"""
Tests for blockchain/smart_contracts/cvss_risk.py

Validates:
  - score_to_risk() returns correct ContractFindingRisk for all CVSS bands
  - score_from_swc() returns expected scores for known SWC IDs
  - enrich_finding() correctly populates CvssEnrichedFinding fields
  - effective_risk returns the higher of checklist vs CVSS risk
  - batch_enrich() sorts by effective risk descending
  - to_dict() contains all required keys
  - Edge cases: score 0.0, score 10.0, unknown SWC ID, score overrides
"""
from __future__ import annotations

import pytest

from blockchain.smart_contracts.cvss_risk import (
    CvssEnrichedFinding,
    SWC_CVSS_TABLE,
    batch_enrich,
    enrich_finding,
    score_from_swc,
    score_to_risk,
)
from blockchain.smart_contracts.review_checklist import (
    ContractFinding,
    ContractFindingRisk,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    swc_id: str = "SWC-107",
    risk: ContractFindingRisk = ContractFindingRisk.CRITICAL,
) -> ContractFinding:
    return ContractFinding(
        swc_id=swc_id,
        swc_title=f"Test {swc_id}",
        risk_level=risk,
        description="Test description",
        line_number=1,
        evidence="test evidence",
        recommendation="Test recommendation",
        requires_manual_review=True,
    )


# ---------------------------------------------------------------------------
# score_to_risk
# ---------------------------------------------------------------------------

class TestScoreToRisk:

    def test_zero_is_informational(self):
        assert score_to_risk(0.0) == ContractFindingRisk.INFORMATIONAL

    def test_low_band(self):
        assert score_to_risk(0.1) == ContractFindingRisk.LOW
        assert score_to_risk(2.0) == ContractFindingRisk.LOW
        assert score_to_risk(3.9) == ContractFindingRisk.LOW

    def test_medium_band(self):
        assert score_to_risk(4.0) == ContractFindingRisk.MEDIUM
        assert score_to_risk(5.5) == ContractFindingRisk.MEDIUM
        assert score_to_risk(6.9) == ContractFindingRisk.MEDIUM

    def test_high_band(self):
        assert score_to_risk(7.0) == ContractFindingRisk.HIGH
        assert score_to_risk(8.0) == ContractFindingRisk.HIGH
        assert score_to_risk(8.9) == ContractFindingRisk.HIGH

    def test_critical_band(self):
        assert score_to_risk(9.0) == ContractFindingRisk.CRITICAL
        assert score_to_risk(9.8) == ContractFindingRisk.CRITICAL
        assert score_to_risk(10.0) == ContractFindingRisk.CRITICAL

    def test_out_of_range_raises(self):
        with pytest.raises(ValueError):
            score_to_risk(-0.1)

    def test_above_10_raises(self):
        with pytest.raises(ValueError):
            score_to_risk(10.1)


# ---------------------------------------------------------------------------
# score_from_swc
# ---------------------------------------------------------------------------

class TestScoreFromSwc:

    def test_known_swc_ids_return_float(self):
        for swc_id in SWC_CVSS_TABLE:
            result = score_from_swc(swc_id)
            assert isinstance(result, float), f"{swc_id} should return float"

    def test_swc107_is_critical_score(self):
        score = score_from_swc("SWC-107")
        assert score is not None
        assert score >= 9.0

    def test_swc103_is_medium_score(self):
        score = score_from_swc("SWC-103")
        assert score is not None
        assert 4.0 <= score <= 6.9

    def test_unknown_swc_returns_none(self):
        assert score_from_swc("SWC-999") is None

    def test_all_table_scores_in_valid_range(self):
        for swc_id, score in SWC_CVSS_TABLE.items():
            assert 0.0 <= score <= 10.0, f"{swc_id} score {score} out of range"


# ---------------------------------------------------------------------------
# enrich_finding
# ---------------------------------------------------------------------------

class TestEnrichFinding:

    def test_uses_swc_table_by_default(self):
        f = _finding("SWC-107")
        enriched = enrich_finding(f)
        assert enriched.cvss_source == "swc_table"
        assert enriched.cvss_score == SWC_CVSS_TABLE["SWC-107"]

    def test_provided_score_overrides_table(self):
        f = _finding("SWC-107")
        enriched = enrich_finding(f, cvss_score=6.0)
        assert enriched.cvss_source == "provided"
        assert enriched.cvss_score == 6.0

    def test_unknown_swc_no_score(self):
        f = _finding("SWC-999")
        enriched = enrich_finding(f)
        assert enriched.cvss_score is None
        assert enriched.cvss_risk is None
        assert enriched.cvss_source is None

    def test_enriched_risk_matches_score_band(self):
        f = _finding("SWC-107")
        enriched = enrich_finding(f)
        expected_risk = score_to_risk(SWC_CVSS_TABLE["SWC-107"])
        assert enriched.cvss_risk == expected_risk

    def test_provided_score_out_of_range_raises(self):
        f = _finding("SWC-107")
        with pytest.raises(ValueError):
            enrich_finding(f, cvss_score=11.0)

    def test_score_note_is_nonempty(self):
        enriched = enrich_finding(_finding("SWC-107"))
        assert len(enriched.score_note) > 0

    def test_finding_reference_preserved(self):
        f = _finding("SWC-115", risk=ContractFindingRisk.HIGH)
        enriched = enrich_finding(f)
        assert enriched.finding is f


# ---------------------------------------------------------------------------
# effective_risk
# ---------------------------------------------------------------------------

class TestEffectiveRisk:

    def test_effective_risk_uses_higher_of_checklist_and_cvss(self):
        """If CVSS score yields CRITICAL but checklist says HIGH, effective = CRITICAL."""
        f = _finding("SWC-999", risk=ContractFindingRisk.HIGH)  # checklist = HIGH
        enriched = CvssEnrichedFinding(
            finding=f,
            cvss_score=9.5,
            cvss_risk=ContractFindingRisk.CRITICAL,  # CVSS says CRITICAL
            cvss_source="provided",
        )
        assert enriched.effective_risk == ContractFindingRisk.CRITICAL

    def test_effective_risk_uses_checklist_when_higher(self):
        """If checklist says CRITICAL but CVSS yields MEDIUM, effective = CRITICAL."""
        f = _finding("SWC-107", risk=ContractFindingRisk.CRITICAL)
        enriched = CvssEnrichedFinding(
            finding=f,
            cvss_score=5.0,
            cvss_risk=ContractFindingRisk.MEDIUM,
            cvss_source="provided",
        )
        assert enriched.effective_risk == ContractFindingRisk.CRITICAL

    def test_effective_risk_falls_back_to_checklist_when_no_cvss(self):
        f = _finding("SWC-999", risk=ContractFindingRisk.HIGH)
        enriched = CvssEnrichedFinding(finding=f, cvss_score=None, cvss_risk=None)
        assert enriched.effective_risk == ContractFindingRisk.HIGH

    def test_effective_risk_equal_levels(self):
        f = _finding("SWC-999", risk=ContractFindingRisk.HIGH)
        enriched = CvssEnrichedFinding(
            finding=f,
            cvss_score=7.5,
            cvss_risk=ContractFindingRisk.HIGH,
            cvss_source="provided",
        )
        assert enriched.effective_risk == ContractFindingRisk.HIGH


# ---------------------------------------------------------------------------
# to_dict
# ---------------------------------------------------------------------------

class TestToDict:

    def test_to_dict_has_required_keys(self):
        enriched = enrich_finding(_finding("SWC-107"))
        d = enriched.to_dict()
        for key in ["swc_id", "swc_title", "checklist_risk", "cvss_score",
                    "cvss_risk", "effective_risk", "cvss_source", "score_note",
                    "line_number", "evidence", "recommendation",
                    "requires_manual_review"]:
            assert key in d, f"Missing key: {key}"

    def test_to_dict_swc_id_matches(self):
        enriched = enrich_finding(_finding("SWC-115"))
        assert enriched.to_dict()["swc_id"] == "SWC-115"

    def test_to_dict_no_cvss_has_none_values(self):
        enriched = enrich_finding(_finding("SWC-999"))
        d = enriched.to_dict()
        assert d["cvss_score"] is None
        assert d["cvss_risk"] is None
        assert d["cvss_source"] is None


# ---------------------------------------------------------------------------
# batch_enrich
# ---------------------------------------------------------------------------

class TestBatchEnrich:

    def test_returns_same_count_as_input(self):
        findings = [_finding("SWC-107"), _finding("SWC-103"), _finding("SWC-115")]
        enriched = batch_enrich(findings)
        assert len(enriched) == 3

    def test_sorted_critical_first(self):
        """batch_enrich result must be sorted by effective_risk descending."""
        findings = [
            _finding("SWC-103", risk=ContractFindingRisk.MEDIUM),  # CVSS 5.3 → MEDIUM
            _finding("SWC-107", risk=ContractFindingRisk.CRITICAL), # CVSS 9.8 → CRITICAL
            _finding("SWC-115", risk=ContractFindingRisk.HIGH),     # CVSS 7.3 → HIGH
        ]
        enriched = batch_enrich(findings)
        risk_values = [e.effective_risk for e in enriched]
        _order = {
            ContractFindingRisk.CRITICAL: 4,
            ContractFindingRisk.HIGH: 3,
            ContractFindingRisk.MEDIUM: 2,
            ContractFindingRisk.LOW: 1,
            ContractFindingRisk.INFORMATIONAL: 0,
        }
        ranks = [_order[r] for r in risk_values]
        assert ranks == sorted(ranks, reverse=True)

    def test_score_overrides_applied(self):
        """Caller-provided overrides should take precedence over the table."""
        findings = [_finding("SWC-107")]
        enriched = batch_enrich(findings, score_overrides={"SWC-107": 3.0})
        assert enriched[0].cvss_score == 3.0
        assert enriched[0].cvss_source == "provided"

    def test_empty_list_returns_empty(self):
        assert batch_enrich([]) == []

    def test_unknown_swc_still_included(self):
        findings = [_finding("SWC-999")]
        enriched = batch_enrich(findings)
        assert len(enriched) == 1
        assert enriched[0].cvss_score is None

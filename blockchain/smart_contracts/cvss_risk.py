"""
CVSS-to-Risk Scoring Integration for Smart Contract Findings
=============================================================
Maps CVSS v3.1 base scores to ContractFindingRisk levels and enriches
ContractFinding objects with CVSS context when a score is known.

This module provides:
  - CVSS v3.1 severity band classification (score → LOW / MEDIUM / HIGH / CRITICAL)
  - A CvssEnrichedFinding dataclass that pairs a ContractFinding with CVSS metadata
  - enrich_finding() — attach CVSS data to an existing ContractFinding
  - score_from_swc() — look up the recommended base score for a well-known SWC ID
  - batch_enrich() — enrich a list of findings using the built-in SWC → CVSS table

Reference: NVD CVSS v3.1 severity ratings
  None       0.0
  Low        0.1–3.9
  Medium     4.0–6.9
  High       7.0–8.9
  Critical   9.0–10.0

IMPORTANT: The CVSS scores in the built-in SWC table are representative baseline
scores for each vulnerability class. Actual scores for a specific finding depend on
environmental and temporal factors that require a qualified auditor to assess.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from blockchain.smart_contracts.review_checklist import ContractFinding, ContractFindingRisk


# ---------------------------------------------------------------------------
# CVSS v3.1 severity bands
# ---------------------------------------------------------------------------

#: Mapping from ContractFindingRisk to the (min, max) CVSS v3.1 score range (inclusive).
CVSS_BANDS: dict[ContractFindingRisk, tuple[float, float]] = {
    ContractFindingRisk.INFORMATIONAL: (0.0, 0.0),
    ContractFindingRisk.LOW:           (0.1, 3.9),
    ContractFindingRisk.MEDIUM:        (4.0, 6.9),
    ContractFindingRisk.HIGH:          (7.0, 8.9),
    ContractFindingRisk.CRITICAL:      (9.0, 10.0),
}


def score_to_risk(cvss_score: float) -> ContractFindingRisk:
    """
    Classify a CVSS v3.1 base score into a ContractFindingRisk level.

    Args:
        cvss_score: Float in range [0.0, 10.0].

    Returns:
        ContractFindingRisk corresponding to the NVD severity band.

    Raises:
        ValueError: If the score is outside [0.0, 10.0].
    """
    if not 0.0 <= cvss_score <= 10.0:
        raise ValueError(f"CVSS score must be in [0.0, 10.0], got {cvss_score}")

    if cvss_score == 0.0:
        return ContractFindingRisk.INFORMATIONAL
    elif cvss_score <= 3.9:
        return ContractFindingRisk.LOW
    elif cvss_score <= 6.9:
        return ContractFindingRisk.MEDIUM
    elif cvss_score <= 8.9:
        return ContractFindingRisk.HIGH
    else:
        return ContractFindingRisk.CRITICAL


# ---------------------------------------------------------------------------
# Representative CVSS base scores for SWC vulnerability classes
# ---------------------------------------------------------------------------

#: Representative CVSS v3.1 base scores for known SWC IDs.
#: Scores are conservative baselines — real scores depend on context.
#:
#: Sources/rationale:
#:   SWC-107 (Reentrancy)       — CVSS 9.8: remote exploitability, full Ether drain (e.g. The DAO)
#:   SWC-105 (Unprotected Withdraw) — CVSS 9.1: no auth required, direct fund theft
#:   SWC-106 (Unprotected selfdestruct) — CVSS 9.1: contract destruction, irrecoverable
#:   SWC-101 (Integer Overflow) — CVSS 7.5: silent arithmetic, balance manipulation
#:   SWC-113 (DoS Failed Call)  — CVSS 7.5: availability, fund lock-up
#:   SWC-128 (DoS Block Gas)    — CVSS 7.5: availability, function permanently uncallable
#:   SWC-115 (tx.origin auth)   — CVSS 7.3: phishing relay attack, access control bypass
#:   SWC-120 (Weak Randomness)  — CVSS 6.5: miner-exploitable, affects fairness
#:   SWC-103 (Floating Pragma)  — CVSS 5.3: informational / configuration risk
#:   SWC-111 (Deprecated Funcs) — CVSS 5.3: code quality, potential undefined behavior
#:   SWC-100 (Default Visibility) — CVSS 5.3: function exposed unexpectedly
SWC_CVSS_TABLE: dict[str, float] = {
    "SWC-107": 9.8,
    "SWC-105": 9.1,
    "SWC-106": 9.1,
    "SWC-101": 7.5,
    "SWC-113": 7.5,
    "SWC-128": 7.5,
    "SWC-115": 7.3,
    "SWC-120": 6.5,
    "SWC-103": 5.3,
    "SWC-111": 5.3,
    "SWC-100": 5.3,
}


def score_from_swc(swc_id: str) -> Optional[float]:
    """
    Return the representative CVSS v3.1 base score for a given SWC ID.

    Args:
        swc_id: SWC identifier string (e.g., "SWC-107").

    Returns:
        Float CVSS score if the SWC ID is in the built-in table, else None.
    """
    return SWC_CVSS_TABLE.get(swc_id)


# ---------------------------------------------------------------------------
# Enriched finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class CvssEnrichedFinding:
    """
    A ContractFinding enriched with CVSS v3.1 scoring context.

    Attributes:
        finding:        The original ContractFinding from the checklist runner.
        cvss_score:     CVSS v3.1 base score (None if unknown/not applicable).
        cvss_risk:      Risk level derived from the CVSS score (may differ from
                        the checklist heuristic risk level).
        cvss_source:    How the score was obtained: "swc_table", "provided", or None.
        score_note:     Human-readable note about score origin / limitations.
    """
    finding:     ContractFinding
    cvss_score:  Optional[float]       = None
    cvss_risk:   Optional[ContractFindingRisk] = None
    cvss_source: Optional[str]         = None
    score_note:  str                   = field(default="")

    @property
    def effective_risk(self) -> ContractFindingRisk:
        """
        Return the higher of the checklist risk level and the CVSS-derived risk level.

        When both signals are available we surface the more severe level to avoid
        under-reporting. If CVSS is not available, the checklist risk level is used.
        """
        if self.cvss_risk is None:
            return self.finding.risk_level

        # Risk level ordering for comparison
        _order: dict[ContractFindingRisk, int] = {
            ContractFindingRisk.INFORMATIONAL: 0,
            ContractFindingRisk.LOW:           1,
            ContractFindingRisk.MEDIUM:        2,
            ContractFindingRisk.HIGH:          3,
            ContractFindingRisk.CRITICAL:      4,
        }
        checklist_rank = _order[self.finding.risk_level]
        cvss_rank      = _order[self.cvss_risk]
        return self.finding.risk_level if checklist_rank >= cvss_rank else self.cvss_risk

    def to_dict(self) -> dict:
        """Serialize to a plain dict suitable for JSON output."""
        return {
            "swc_id":           self.finding.swc_id,
            "swc_title":        self.finding.swc_title,
            "checklist_risk":   self.finding.risk_level.value,
            "cvss_score":       self.cvss_score,
            "cvss_risk":        self.cvss_risk.value if self.cvss_risk else None,
            "effective_risk":   self.effective_risk.value,
            "cvss_source":      self.cvss_source,
            "score_note":       self.score_note,
            "line_number":      self.finding.line_number,
            "evidence":         self.finding.evidence,
            "recommendation":   self.finding.recommendation,
            "requires_manual_review": self.finding.requires_manual_review,
        }


# ---------------------------------------------------------------------------
# Enrichment functions
# ---------------------------------------------------------------------------

_SWC_TABLE_NOTE = (
    "Representative CVSS v3.1 base score from the k1N-Cryptologik SWC baseline table. "
    "This score reflects the typical worst-case impact for this vulnerability class. "
    "Actual score requires context-specific assessment by a qualified auditor."
)

_NO_SCORE_NOTE = (
    "No CVSS score available for this SWC ID in the built-in table. "
    "A qualified auditor should assess and assign a context-specific CVSS score."
)


def enrich_finding(
    finding: ContractFinding,
    cvss_score: Optional[float] = None,
) -> CvssEnrichedFinding:
    """
    Enrich a ContractFinding with CVSS context.

    If a cvss_score is explicitly provided, it is used directly (source: "provided").
    Otherwise, the SWC ID is looked up in the built-in SWC_CVSS_TABLE.
    If no score is available, cvss_score and cvss_risk are set to None.

    Args:
        finding:    ContractFinding from the checklist runner.
        cvss_score: Optional override score. If None, uses built-in table.

    Returns:
        CvssEnrichedFinding with CVSS context attached.
    """
    if cvss_score is not None:
        # Caller provided an explicit score (e.g., from a real CVE or audit report)
        if not 0.0 <= cvss_score <= 10.0:
            raise ValueError(f"CVSS score must be in [0.0, 10.0], got {cvss_score}")
        return CvssEnrichedFinding(
            finding=finding,
            cvss_score=cvss_score,
            cvss_risk=score_to_risk(cvss_score),
            cvss_source="provided",
            score_note=(
                f"Caller-provided CVSS v3.1 base score of {cvss_score:.1f}. "
                "Verify against the specific deployment context."
            ),
        )

    # Look up built-in SWC table
    table_score = score_from_swc(finding.swc_id)
    if table_score is not None:
        return CvssEnrichedFinding(
            finding=finding,
            cvss_score=table_score,
            cvss_risk=score_to_risk(table_score),
            cvss_source="swc_table",
            score_note=_SWC_TABLE_NOTE,
        )

    # No score available
    return CvssEnrichedFinding(
        finding=finding,
        cvss_score=None,
        cvss_risk=None,
        cvss_source=None,
        score_note=_NO_SCORE_NOTE,
    )


def batch_enrich(
    findings: list[ContractFinding],
    score_overrides: Optional[dict[str, float]] = None,
) -> list[CvssEnrichedFinding]:
    """
    Enrich a list of ContractFindings with CVSS context in bulk.

    Args:
        findings:        List of ContractFinding objects from a checklist runner.
        score_overrides: Optional dict mapping SWC ID → CVSS score for custom
                         scores that override the built-in table.

    Returns:
        List of CvssEnrichedFinding objects, one per input finding.
        Sorted by effective risk (CRITICAL first) then CVSS score descending.
    """
    overrides = score_overrides or {}

    enriched: list[CvssEnrichedFinding] = []
    for f in findings:
        override_score = overrides.get(f.swc_id)
        enriched.append(enrich_finding(f, cvss_score=override_score))

    # Sort: highest effective_risk first, then highest CVSS score
    _order: dict[ContractFindingRisk, int] = {
        ContractFindingRisk.CRITICAL:      4,
        ContractFindingRisk.HIGH:          3,
        ContractFindingRisk.MEDIUM:        2,
        ContractFindingRisk.LOW:           1,
        ContractFindingRisk.INFORMATIONAL: 0,
    }
    enriched.sort(
        key=lambda e: (_order[e.effective_risk], e.cvss_score or 0.0),
        reverse=True,
    )
    return enriched

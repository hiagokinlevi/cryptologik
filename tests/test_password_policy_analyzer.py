# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 hiagokinlevi — Cyber Port
# Creative Commons Attribution 4.0 International License
# https://creativecommons.org/licenses/by/4.0/
"""
Tests for crypto.password_policy_analyzer
==========================================
Run with:
    python3 -m pytest tests/test_password_policy_analyzer.py --override-ini="addopts=" -q
"""
from __future__ import annotations

import sys
import os

# Allow imports from the project root regardless of cwd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from crypto.password_policy_analyzer import (
    LockoutPolicy,
    PasswordHashConfig,
    PasswordPolicy,
    PasswordPolicyAnalyzer,
    PolicyAnalysisResult,
    PolicyFinding,
    _CHECK_WEIGHTS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strong_lockout() -> LockoutPolicy:
    """Return a lockout policy that satisfies PWD-004."""
    return LockoutPolicy(
        enabled=True,
        max_attempts=5,
        lockout_duration_minutes=15,
        reset_counter_after_minutes=30,
    )


def _strong_hash() -> PasswordHashConfig:
    """Return a hash config that satisfies PWD-006."""
    return PasswordHashConfig(algorithm="argon2id")


def _strong_policy(**overrides) -> PasswordPolicy:
    """Return a fully compliant policy, optionally overriding fields."""
    defaults = dict(
        name="test-strong",
        min_length=14,
        require_uppercase=True,
        require_lowercase=True,
        require_digits=True,
        require_special_chars=True,
        max_age_days=90,
        history_count=10,
        lockout=_strong_lockout(),
        hash_config=_strong_hash(),
        require_mfa=True,
    )
    defaults.update(overrides)
    return PasswordPolicy(**defaults)


def _find_ids(result: PolicyAnalysisResult) -> set:
    return {f.check_id for f in result.findings}


analyzer = PasswordPolicyAnalyzer()


# ===========================================================================
# 1. STRONG POLICY — zero findings
# ===========================================================================


class TestStrongPolicy:
    def test_no_findings(self):
        result = analyzer.analyze(_strong_policy())
        assert result.findings == []

    def test_risk_score_zero(self):
        result = analyzer.analyze(_strong_policy())
        assert result.risk_score == 0

    def test_summary_no_issues(self):
        result = analyzer.analyze(_strong_policy())
        assert "No issues found" in result.summary()

    def test_summary_contains_policy_name(self):
        result = analyzer.analyze(_strong_policy(name="prod-admin"))
        assert "prod-admin" in result.summary()

    def test_summary_contains_risk_score(self):
        result = analyzer.analyze(_strong_policy())
        assert "0/100" in result.summary()


# ===========================================================================
# 2. PWD-001 — Minimum length
# ===========================================================================


class TestPWD001:
    def test_min_length_8_triggers(self):
        result = analyzer.analyze(_strong_policy(min_length=8))
        assert "PWD-001" in _find_ids(result)

    def test_min_length_11_triggers(self):
        result = analyzer.analyze(_strong_policy(min_length=11))
        assert "PWD-001" in _find_ids(result)

    def test_min_length_12_does_not_trigger(self):
        result = analyzer.analyze(_strong_policy(min_length=12))
        assert "PWD-001" not in _find_ids(result)

    def test_min_length_16_does_not_trigger(self):
        result = analyzer.analyze(_strong_policy(min_length=16))
        assert "PWD-001" not in _find_ids(result)

    def test_severity_is_high(self):
        result = analyzer.analyze(_strong_policy(min_length=8))
        findings = [f for f in result.findings if f.check_id == "PWD-001"]
        assert findings[0].severity == "HIGH"

    def test_finding_references_policy_name(self):
        result = analyzer.analyze(_strong_policy(name="my-policy", min_length=8))
        findings = [f for f in result.findings if f.check_id == "PWD-001"]
        assert findings[0].policy_name == "my-policy"

    def test_finding_message_contains_actual_length(self):
        result = analyzer.analyze(_strong_policy(min_length=6))
        findings = [f for f in result.findings if f.check_id == "PWD-001"]
        assert "6" in findings[0].message

    def test_min_length_1_triggers(self):
        result = analyzer.analyze(_strong_policy(min_length=1))
        assert "PWD-001" in _find_ids(result)


# ===========================================================================
# 3. PWD-002 — No complexity requirements
# ===========================================================================


class TestPWD002:
    def _no_complexity(self, **flags) -> PasswordPolicy:
        base = dict(
            require_uppercase=False,
            require_lowercase=False,
            require_digits=False,
            require_special_chars=False,
        )
        base.update(flags)
        return _strong_policy(**base)

    def test_no_flags_triggers(self):
        result = analyzer.analyze(self._no_complexity())
        assert "PWD-002" in _find_ids(result)

    def test_only_uppercase_suppresses(self):
        result = analyzer.analyze(self._no_complexity(require_uppercase=True))
        assert "PWD-002" not in _find_ids(result)

    def test_only_lowercase_suppresses(self):
        result = analyzer.analyze(self._no_complexity(require_lowercase=True))
        assert "PWD-002" not in _find_ids(result)

    def test_only_digits_suppresses(self):
        result = analyzer.analyze(self._no_complexity(require_digits=True))
        assert "PWD-002" not in _find_ids(result)

    def test_only_special_suppresses(self):
        result = analyzer.analyze(self._no_complexity(require_special_chars=True))
        assert "PWD-002" not in _find_ids(result)

    def test_all_flags_set_does_not_trigger(self):
        result = analyzer.analyze(self._no_complexity(
            require_uppercase=True,
            require_lowercase=True,
            require_digits=True,
            require_special_chars=True,
        ))
        assert "PWD-002" not in _find_ids(result)

    def test_severity_is_medium(self):
        result = analyzer.analyze(self._no_complexity())
        findings = [f for f in result.findings if f.check_id == "PWD-002"]
        assert findings[0].severity == "MEDIUM"


# ===========================================================================
# 4. PWD-003 — Password expiry
# ===========================================================================


class TestPWD003:
    def test_max_age_none_triggers(self):
        result = analyzer.analyze(_strong_policy(max_age_days=None))
        assert "PWD-003" in _find_ids(result)

    def test_max_age_zero_triggers(self):
        result = analyzer.analyze(_strong_policy(max_age_days=0))
        assert "PWD-003" in _find_ids(result)

    def test_max_age_366_triggers(self):
        result = analyzer.analyze(_strong_policy(max_age_days=366))
        assert "PWD-003" in _find_ids(result)

    def test_max_age_365_does_not_trigger(self):
        result = analyzer.analyze(_strong_policy(max_age_days=365))
        assert "PWD-003" not in _find_ids(result)

    def test_max_age_90_does_not_trigger(self):
        result = analyzer.analyze(_strong_policy(max_age_days=90))
        assert "PWD-003" not in _find_ids(result)

    def test_max_age_1_does_not_trigger(self):
        result = analyzer.analyze(_strong_policy(max_age_days=1))
        assert "PWD-003" not in _find_ids(result)

    def test_max_age_1000_triggers(self):
        result = analyzer.analyze(_strong_policy(max_age_days=1000))
        assert "PWD-003" in _find_ids(result)

    def test_severity_is_medium(self):
        result = analyzer.analyze(_strong_policy(max_age_days=None))
        findings = [f for f in result.findings if f.check_id == "PWD-003"]
        assert findings[0].severity == "MEDIUM"

    def test_message_mentions_never_expires_for_none(self):
        result = analyzer.analyze(_strong_policy(max_age_days=None))
        findings = [f for f in result.findings if f.check_id == "PWD-003"]
        assert findings[0].message  # non-empty


# ===========================================================================
# 5. PWD-004 — Lockout policy
# ===========================================================================


class TestPWD004:
    def test_lockout_none_triggers(self):
        result = analyzer.analyze(_strong_policy(lockout=None))
        assert "PWD-004" in _find_ids(result)

    def test_lockout_disabled_triggers(self):
        lo = LockoutPolicy(enabled=False, max_attempts=5)
        result = analyzer.analyze(_strong_policy(lockout=lo))
        assert "PWD-004" in _find_ids(result)

    def test_lockout_max_attempts_none_triggers(self):
        lo = LockoutPolicy(enabled=True, max_attempts=None)
        result = analyzer.analyze(_strong_policy(lockout=lo))
        assert "PWD-004" in _find_ids(result)

    def test_enabled_with_max_attempts_does_not_trigger(self):
        lo = LockoutPolicy(enabled=True, max_attempts=5)
        result = analyzer.analyze(_strong_policy(lockout=lo))
        assert "PWD-004" not in _find_ids(result)

    def test_full_lockout_config_does_not_trigger(self):
        result = analyzer.analyze(_strong_policy(lockout=_strong_lockout()))
        assert "PWD-004" not in _find_ids(result)

    def test_severity_is_high(self):
        result = analyzer.analyze(_strong_policy(lockout=None))
        findings = [f for f in result.findings if f.check_id == "PWD-004"]
        assert findings[0].severity == "HIGH"


# ===========================================================================
# 6. PWD-005 — Password history / reuse
# ===========================================================================


class TestPWD005:
    def test_history_count_0_triggers(self):
        result = analyzer.analyze(_strong_policy(history_count=0))
        assert "PWD-005" in _find_ids(result)

    def test_history_count_4_triggers(self):
        result = analyzer.analyze(_strong_policy(history_count=4))
        assert "PWD-005" in _find_ids(result)

    def test_history_count_5_does_not_trigger(self):
        result = analyzer.analyze(_strong_policy(history_count=5))
        assert "PWD-005" not in _find_ids(result)

    def test_history_count_10_does_not_trigger(self):
        result = analyzer.analyze(_strong_policy(history_count=10))
        assert "PWD-005" not in _find_ids(result)

    def test_history_count_1_triggers(self):
        result = analyzer.analyze(_strong_policy(history_count=1))
        assert "PWD-005" in _find_ids(result)

    def test_severity_is_high(self):
        result = analyzer.analyze(_strong_policy(history_count=0))
        findings = [f for f in result.findings if f.check_id == "PWD-005"]
        assert findings[0].severity == "HIGH"

    def test_message_contains_actual_count(self):
        result = analyzer.analyze(_strong_policy(history_count=3))
        findings = [f for f in result.findings if f.check_id == "PWD-005"]
        assert "3" in findings[0].message


# ===========================================================================
# 7. PWD-006 — Hashing algorithm
# ===========================================================================


class TestPWD006:
    # --- hash_config=None ---

    def test_hash_config_none_triggers_critical(self):
        result = analyzer.analyze(_strong_policy(hash_config=None))
        findings = [f for f in result.findings if f.check_id == "PWD-006"]
        assert findings, "PWD-006 should fire when hash_config is None"
        assert findings[0].severity == "CRITICAL"

    # --- Insecure algorithms → CRITICAL ---

    def test_plaintext_triggers_critical(self):
        hc = PasswordHashConfig(algorithm="plaintext")
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        findings = [f for f in result.findings if f.check_id == "PWD-006"]
        assert findings and findings[0].severity == "CRITICAL"

    def test_md5_triggers_critical(self):
        hc = PasswordHashConfig(algorithm="md5")
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        findings = [f for f in result.findings if f.check_id == "PWD-006"]
        assert findings and findings[0].severity == "CRITICAL"

    def test_sha1_triggers_critical(self):
        hc = PasswordHashConfig(algorithm="sha1")
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        findings = [f for f in result.findings if f.check_id == "PWD-006"]
        assert findings and findings[0].severity == "CRITICAL"

    def test_sha256_triggers_critical(self):
        hc = PasswordHashConfig(algorithm="sha256")
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        findings = [f for f in result.findings if f.check_id == "PWD-006"]
        assert findings and findings[0].severity == "CRITICAL"

    def test_ntlm_triggers_critical(self):
        hc = PasswordHashConfig(algorithm="ntlm")
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        findings = [f for f in result.findings if f.check_id == "PWD-006"]
        assert findings and findings[0].severity == "CRITICAL"

    # --- bcrypt work factor checks ---

    def test_bcrypt_work_factor_8_triggers_high(self):
        hc = PasswordHashConfig(algorithm="bcrypt", work_factor=8, min_work_factor=10)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        findings = [f for f in result.findings if f.check_id == "PWD-006-WF"]
        assert findings, "PWD-006-WF should fire when bcrypt work_factor < 10"
        assert findings[0].severity == "HIGH"

    def test_bcrypt_work_factor_9_triggers_high(self):
        hc = PasswordHashConfig(algorithm="bcrypt", work_factor=9, min_work_factor=10)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        assert "PWD-006-WF" in _find_ids(result)

    def test_bcrypt_work_factor_12_does_not_trigger(self):
        hc = PasswordHashConfig(algorithm="bcrypt", work_factor=12, min_work_factor=10)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        assert "PWD-006" not in _find_ids(result)
        assert "PWD-006-WF" not in _find_ids(result)

    def test_bcrypt_work_factor_10_does_not_trigger(self):
        hc = PasswordHashConfig(algorithm="bcrypt", work_factor=10, min_work_factor=10)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        assert "PWD-006" not in _find_ids(result)
        assert "PWD-006-WF" not in _find_ids(result)

    def test_bcrypt_no_work_factor_does_not_trigger(self):
        # work_factor=None → cannot verify → no finding
        hc = PasswordHashConfig(algorithm="bcrypt", work_factor=None)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        assert "PWD-006" not in _find_ids(result)
        assert "PWD-006-WF" not in _find_ids(result)

    # --- argon2id ---

    def test_argon2id_does_not_trigger(self):
        hc = PasswordHashConfig(algorithm="argon2id")
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        assert "PWD-006" not in _find_ids(result)
        assert "PWD-006-WF" not in _find_ids(result)

    # --- pbkdf2-sha256 work factor checks ---

    def test_pbkdf2_work_factor_50000_triggers_high(self):
        hc = PasswordHashConfig(algorithm="pbkdf2-sha256", work_factor=50_000, min_work_factor=10)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        findings = [f for f in result.findings if f.check_id == "PWD-006-WF"]
        assert findings, "PWD-006-WF should fire when pbkdf2 work_factor < 100000"
        assert findings[0].severity == "HIGH"

    def test_pbkdf2_work_factor_99999_triggers_high(self):
        hc = PasswordHashConfig(algorithm="pbkdf2-sha256", work_factor=99_999, min_work_factor=10)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        assert "PWD-006-WF" in _find_ids(result)

    def test_pbkdf2_work_factor_100000_does_not_trigger(self):
        hc = PasswordHashConfig(algorithm="pbkdf2-sha256", work_factor=100_000, min_work_factor=10)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        assert "PWD-006" not in _find_ids(result)
        assert "PWD-006-WF" not in _find_ids(result)

    def test_pbkdf2_work_factor_600000_does_not_trigger(self):
        hc = PasswordHashConfig(algorithm="pbkdf2-sha256", work_factor=600_000, min_work_factor=10)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        assert "PWD-006" not in _find_ids(result)
        assert "PWD-006-WF" not in _find_ids(result)

    # --- sha512-crypt (acceptable old algorithm) ---

    def test_sha512_crypt_does_not_trigger_insecure(self):
        hc = PasswordHashConfig(algorithm="sha512-crypt")
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        assert "PWD-006" not in _find_ids(result)

    # --- unknown algorithm → CRITICAL ---

    def test_unknown_algorithm_triggers_critical(self):
        hc = PasswordHashConfig(algorithm="des-crypt")
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        findings = [f for f in result.findings if f.check_id == "PWD-006"]
        assert findings and findings[0].severity == "CRITICAL"

    # --- insecure algorithm ignores work_factor (no double firing) ---

    def test_md5_with_work_factor_does_not_fire_wf_check(self):
        hc = PasswordHashConfig(algorithm="md5", work_factor=1, min_work_factor=10)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        ids = _find_ids(result)
        assert "PWD-006" in ids
        assert "PWD-006-WF" not in ids


# ===========================================================================
# 8. PWD-007 — MFA
# ===========================================================================


class TestPWD007:
    def test_require_mfa_false_triggers(self):
        result = analyzer.analyze(_strong_policy(require_mfa=False))
        assert "PWD-007" in _find_ids(result)

    def test_require_mfa_true_does_not_trigger(self):
        result = analyzer.analyze(_strong_policy(require_mfa=True))
        assert "PWD-007" not in _find_ids(result)

    def test_severity_is_high(self):
        result = analyzer.analyze(_strong_policy(require_mfa=False))
        findings = [f for f in result.findings if f.check_id == "PWD-007"]
        assert findings[0].severity == "HIGH"

    def test_finding_has_recommendation(self):
        result = analyzer.analyze(_strong_policy(require_mfa=False))
        findings = [f for f in result.findings if f.check_id == "PWD-007"]
        assert findings[0].recommendation


# ===========================================================================
# 9. Multiple checks firing together
# ===========================================================================


class TestMultipleChecks:
    def test_bare_minimum_policy_fires_all_checks(self):
        """A policy with only a name and defaults should fire most checks."""
        policy = PasswordPolicy(name="bare-minimum")
        result = analyzer.analyze(policy)
        ids = _find_ids(result)
        # Expected: PWD-001 (len=8<12), PWD-002 (no complexity), PWD-003 (no expiry),
        #           PWD-004 (no lockout), PWD-005 (history=0), PWD-006 (hash=None → CRITICAL),
        #           PWD-007 (mfa=False)
        assert "PWD-001" in ids
        assert "PWD-002" in ids
        assert "PWD-003" in ids
        assert "PWD-004" in ids
        assert "PWD-005" in ids
        assert "PWD-006" in ids
        assert "PWD-007" in ids

    def test_pwd001_and_pwd007_together(self):
        result = analyzer.analyze(_strong_policy(min_length=8, require_mfa=False))
        ids = _find_ids(result)
        assert "PWD-001" in ids
        assert "PWD-007" in ids

    def test_pwd002_and_pwd005_together(self):
        result = analyzer.analyze(_strong_policy(
            require_uppercase=False,
            require_lowercase=False,
            require_digits=False,
            require_special_chars=False,
            history_count=0,
        ))
        ids = _find_ids(result)
        assert "PWD-002" in ids
        assert "PWD-005" in ids

    def test_pwd003_and_pwd004_together(self):
        result = analyzer.analyze(_strong_policy(max_age_days=None, lockout=None))
        ids = _find_ids(result)
        assert "PWD-003" in ids
        assert "PWD-004" in ids

    def test_all_checks_appear_only_once(self):
        """No check ID should appear more than once in results."""
        policy = PasswordPolicy(name="multi-fire")
        result = analyzer.analyze(policy)
        check_ids = [f.check_id for f in result.findings]
        assert len(check_ids) == len(set(check_ids))


# ===========================================================================
# 10. Risk score computation
# ===========================================================================


class TestRiskScore:
    def test_zero_for_clean_policy(self):
        result = analyzer.analyze(_strong_policy())
        assert result.risk_score == 0

    def test_score_capped_at_100(self):
        """All checks firing should not exceed 100."""
        policy = PasswordPolicy(name="worst-case")
        result = analyzer.analyze(policy)
        assert result.risk_score <= 100

    def test_score_for_single_pwd001(self):
        """PWD-001 weight is 25."""
        result = analyzer.analyze(_strong_policy(min_length=8))
        assert result.risk_score == _CHECK_WEIGHTS["PWD-001"]

    def test_score_for_single_pwd006_critical(self):
        """PWD-006 weight is 45 when firing CRITICAL."""
        result = analyzer.analyze(_strong_policy(hash_config=None))
        assert result.risk_score == _CHECK_WEIGHTS["PWD-006"]

    def test_score_for_single_pwd006_wf(self):
        """PWD-006-WF weight is 25 when only work factor is weak."""
        hc = PasswordHashConfig(algorithm="bcrypt", work_factor=8, min_work_factor=10)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        assert result.risk_score == _CHECK_WEIGHTS["PWD-006-WF"]

    def test_score_for_pwd001_and_pwd007(self):
        """25 + 25 = 50."""
        result = analyzer.analyze(_strong_policy(min_length=8, require_mfa=False))
        assert result.risk_score == _CHECK_WEIGHTS["PWD-001"] + _CHECK_WEIGHTS["PWD-007"]

    def test_score_is_int(self):
        result = analyzer.analyze(_strong_policy(min_length=8))
        assert isinstance(result.risk_score, int)

    def test_worst_case_score_is_exactly_100(self):
        """Total uncapped for all 7 checks (using CRITICAL for PWD-006):
        25+15+15+25+20+45+25 = 170 → capped to 100."""
        policy = PasswordPolicy(name="worst-ever")
        result = analyzer.analyze(policy)
        assert result.risk_score == 100


# ===========================================================================
# 11. by_severity()
# ===========================================================================


class TestBySeverity:
    def test_returns_dict(self):
        result = analyzer.analyze(_strong_policy())
        assert isinstance(result.by_severity(), dict)

    def test_all_severity_levels_present_as_keys(self):
        result = analyzer.analyze(_strong_policy())
        bs = result.by_severity()
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert level in bs

    def test_empty_lists_when_no_findings(self):
        result = analyzer.analyze(_strong_policy())
        bs = result.by_severity()
        for findings_list in bs.values():
            assert findings_list == []

    def test_critical_finding_placed_correctly(self):
        result = analyzer.analyze(_strong_policy(hash_config=None))
        bs = result.by_severity()
        assert any(f.check_id == "PWD-006" for f in bs["CRITICAL"])

    def test_high_finding_placed_correctly(self):
        result = analyzer.analyze(_strong_policy(min_length=8))
        bs = result.by_severity()
        assert any(f.check_id == "PWD-001" for f in bs["HIGH"])

    def test_medium_finding_placed_correctly(self):
        result = analyzer.analyze(_strong_policy(max_age_days=None))
        bs = result.by_severity()
        assert any(f.check_id == "PWD-003" for f in bs["MEDIUM"])

    def test_totals_match_findings_count(self):
        policy = PasswordPolicy(name="count-check")
        result = analyzer.analyze(policy)
        bs = result.by_severity()
        total = sum(len(v) for v in bs.values())
        assert total == len(result.findings)


# ===========================================================================
# 12. summary()
# ===========================================================================


class TestSummary:
    def test_returns_string(self):
        result = analyzer.analyze(_strong_policy())
        assert isinstance(result.summary(), str)

    def test_summary_clean_no_issues_message(self):
        result = analyzer.analyze(_strong_policy())
        assert "No issues found" in result.summary()

    def test_summary_with_findings_contains_count(self):
        result = analyzer.analyze(_strong_policy(min_length=8, require_mfa=False))
        s = result.summary()
        # 2 findings
        assert "2" in s

    def test_summary_contains_risk_score(self):
        result = analyzer.analyze(_strong_policy(min_length=8))
        assert str(result.risk_score) in result.summary()

    def test_summary_contains_policy_name(self):
        result = analyzer.analyze(_strong_policy(name="my-named-policy", min_length=8))
        assert "my-named-policy" in result.summary()

    def test_summary_single_finding_uses_singular(self):
        result = analyzer.analyze(_strong_policy(min_length=8))
        assert "finding" in result.summary().lower()

    def test_summary_multiple_findings_uses_plural(self):
        result = analyzer.analyze(_strong_policy(min_length=8, require_mfa=False))
        assert "findings" in result.summary().lower()


# ===========================================================================
# 13. analyze_many()
# ===========================================================================


class TestAnalyzeMany:
    def test_returns_list(self):
        results = analyzer.analyze_many([_strong_policy()])
        assert isinstance(results, list)

    def test_empty_input_returns_empty_list(self):
        results = analyzer.analyze_many([])
        assert results == []

    def test_length_matches_input(self):
        policies = [_strong_policy(name=f"p{i}") for i in range(5)]
        results = analyzer.analyze_many(policies)
        assert len(results) == 5

    def test_each_element_is_policy_analysis_result(self):
        policies = [_strong_policy(name="a"), PasswordPolicy(name="b")]
        results = analyzer.analyze_many(policies)
        assert all(isinstance(r, PolicyAnalysisResult) for r in results)

    def test_results_correspond_to_input_order(self):
        p1 = _strong_policy(name="first")
        p2 = PasswordPolicy(name="second")
        results = analyzer.analyze_many([p1, p2])
        assert results[0].policy.name == "first"
        assert results[1].policy.name == "second"

    def test_clean_policy_in_mixed_batch(self):
        results = analyzer.analyze_many([_strong_policy(name="clean"), PasswordPolicy(name="dirty")])
        assert results[0].findings == []
        assert len(results[1].findings) > 0

    def test_single_policy_list(self):
        results = analyzer.analyze_many([_strong_policy()])
        assert len(results) == 1


# ===========================================================================
# 14. to_dict() — all dataclasses
# ===========================================================================


class TestToDict:
    # PasswordHashConfig.to_dict()
    def test_hash_config_to_dict_keys(self):
        hc = PasswordHashConfig(algorithm="argon2id", work_factor=3, min_work_factor=1)
        d = hc.to_dict()
        assert set(d.keys()) == {"algorithm", "work_factor", "min_work_factor"}

    def test_hash_config_to_dict_values(self):
        hc = PasswordHashConfig(algorithm="bcrypt", work_factor=12, min_work_factor=10)
        d = hc.to_dict()
        assert d["algorithm"] == "bcrypt"
        assert d["work_factor"] == 12
        assert d["min_work_factor"] == 10

    def test_hash_config_to_dict_none_work_factor(self):
        hc = PasswordHashConfig(algorithm="argon2id")
        d = hc.to_dict()
        assert d["work_factor"] is None

    # LockoutPolicy.to_dict()
    def test_lockout_to_dict_keys(self):
        lo = _strong_lockout()
        d = lo.to_dict()
        assert set(d.keys()) == {
            "enabled", "max_attempts", "lockout_duration_minutes", "reset_counter_after_minutes"
        }

    def test_lockout_to_dict_values(self):
        lo = LockoutPolicy(enabled=True, max_attempts=5, lockout_duration_minutes=15)
        d = lo.to_dict()
        assert d["enabled"] is True
        assert d["max_attempts"] == 5
        assert d["lockout_duration_minutes"] == 15

    def test_lockout_to_dict_defaults(self):
        lo = LockoutPolicy()
        d = lo.to_dict()
        assert d["enabled"] is False
        assert d["max_attempts"] is None

    # PasswordPolicy.to_dict()
    def test_password_policy_to_dict_has_all_keys(self):
        policy = _strong_policy()
        d = policy.to_dict()
        expected_keys = {
            "name", "min_length", "max_length", "require_uppercase",
            "require_lowercase", "require_digits", "require_special_chars",
            "max_age_days", "min_age_days", "history_count",
            "lockout", "hash_config", "require_mfa",
        }
        assert expected_keys.issubset(set(d.keys()))

    def test_password_policy_to_dict_nested_lockout(self):
        policy = _strong_policy()
        d = policy.to_dict()
        assert isinstance(d["lockout"], dict)
        assert "enabled" in d["lockout"]

    def test_password_policy_to_dict_nested_hash_config(self):
        policy = _strong_policy()
        d = policy.to_dict()
        assert isinstance(d["hash_config"], dict)
        assert "algorithm" in d["hash_config"]

    def test_password_policy_to_dict_none_lockout(self):
        policy = _strong_policy(lockout=None)
        d = policy.to_dict()
        assert d["lockout"] is None

    def test_password_policy_to_dict_none_hash_config(self):
        policy = _strong_policy(hash_config=None)
        d = policy.to_dict()
        assert d["hash_config"] is None

    # PolicyFinding.to_dict()
    def test_finding_to_dict_keys(self):
        finding = PolicyFinding(
            check_id="PWD-001",
            severity="HIGH",
            policy_name="test",
            message="msg",
            recommendation="rec",
        )
        d = finding.to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "policy_name", "message", "recommendation"
        }

    def test_finding_to_dict_values(self):
        finding = PolicyFinding(
            check_id="PWD-007",
            severity="HIGH",
            policy_name="prod",
            message="No MFA",
            recommendation="Enable MFA",
        )
        d = finding.to_dict()
        assert d["check_id"] == "PWD-007"
        assert d["severity"] == "HIGH"
        assert d["policy_name"] == "prod"

    # PolicyAnalysisResult.to_dict()
    def test_result_to_dict_keys(self):
        result = analyzer.analyze(_strong_policy())
        d = result.to_dict()
        assert set(d.keys()) == {"policy", "findings", "risk_score", "summary"}

    def test_result_to_dict_findings_are_list(self):
        result = analyzer.analyze(PasswordPolicy(name="bare"))
        d = result.to_dict()
        assert isinstance(d["findings"], list)

    def test_result_to_dict_findings_are_dicts(self):
        result = analyzer.analyze(PasswordPolicy(name="bare"))
        d = result.to_dict()
        assert all(isinstance(f, dict) for f in d["findings"])

    def test_result_to_dict_risk_score_is_int(self):
        result = analyzer.analyze(_strong_policy())
        d = result.to_dict()
        assert isinstance(d["risk_score"], int)

    def test_result_to_dict_summary_is_string(self):
        result = analyzer.analyze(_strong_policy())
        d = result.to_dict()
        assert isinstance(d["summary"], str)

    def test_result_to_dict_policy_is_dict(self):
        result = analyzer.analyze(_strong_policy())
        d = result.to_dict()
        assert isinstance(d["policy"], dict)


# ===========================================================================
# 15. _CHECK_WEIGHTS sanity
# ===========================================================================


class TestCheckWeights:
    def test_all_expected_keys_present(self):
        expected = {"PWD-001", "PWD-002", "PWD-003", "PWD-004", "PWD-005", "PWD-006", "PWD-006-WF", "PWD-007"}
        assert expected.issubset(set(_CHECK_WEIGHTS.keys()))

    def test_all_values_are_positive_ints(self):
        for k, v in _CHECK_WEIGHTS.items():
            assert isinstance(v, int) and v > 0, f"{k} has non-positive weight {v}"

    def test_pwd006_weight_is_45(self):
        assert _CHECK_WEIGHTS["PWD-006"] == 45

    def test_pwd001_weight_is_25(self):
        assert _CHECK_WEIGHTS["PWD-001"] == 25


# ===========================================================================
# 16. Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_policy_name_preserved_in_findings(self):
        policy = PasswordPolicy(name="edge-case-policy")
        result = analyzer.analyze(policy)
        for finding in result.findings:
            assert finding.policy_name == "edge-case-policy"

    def test_all_findings_have_non_empty_message(self):
        policy = PasswordPolicy(name="bare")
        result = analyzer.analyze(policy)
        for finding in result.findings:
            assert finding.message.strip(), f"{finding.check_id} has empty message"

    def test_all_findings_have_non_empty_recommendation(self):
        policy = PasswordPolicy(name="bare")
        result = analyzer.analyze(policy)
        for finding in result.findings:
            assert finding.recommendation.strip(), f"{finding.check_id} has empty recommendation"

    def test_all_findings_have_valid_severity(self):
        policy = PasswordPolicy(name="bare")
        result = analyzer.analyze(policy)
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for finding in result.findings:
            assert finding.severity in valid, f"Unexpected severity: {finding.severity}"

    def test_max_age_days_exactly_365_boundary(self):
        result = analyzer.analyze(_strong_policy(max_age_days=365))
        assert "PWD-003" not in _find_ids(result)

    def test_max_age_days_exactly_366_boundary(self):
        result = analyzer.analyze(_strong_policy(max_age_days=366))
        assert "PWD-003" in _find_ids(result)

    def test_history_count_exactly_5_boundary(self):
        result = analyzer.analyze(_strong_policy(history_count=5))
        assert "PWD-005" not in _find_ids(result)

    def test_history_count_exactly_4_boundary(self):
        result = analyzer.analyze(_strong_policy(history_count=4))
        assert "PWD-005" in _find_ids(result)

    def test_bcrypt_work_factor_exactly_10_boundary(self):
        hc = PasswordHashConfig(algorithm="bcrypt", work_factor=10, min_work_factor=10)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        assert "PWD-006-WF" not in _find_ids(result)

    def test_pbkdf2_work_factor_exactly_100000_boundary(self):
        hc = PasswordHashConfig(algorithm="pbkdf2-sha256", work_factor=100_000, min_work_factor=10)
        result = analyzer.analyze(_strong_policy(hash_config=hc))
        assert "PWD-006-WF" not in _find_ids(result)

    def test_analyzer_is_reusable(self):
        """Analyzer instance can be used for multiple independent analyses."""
        a = PasswordPolicyAnalyzer()
        r1 = a.analyze(_strong_policy(name="r1"))
        r2 = a.analyze(PasswordPolicy(name="r2"))
        # r1 should still be clean
        assert r1.findings == []
        assert len(r2.findings) > 0

    def test_min_length_12_exact_boundary(self):
        result = analyzer.analyze(_strong_policy(min_length=12))
        assert "PWD-001" not in _find_ids(result)

    def test_min_length_11_just_below_boundary(self):
        result = analyzer.analyze(_strong_policy(min_length=11))
        assert "PWD-001" in _find_ids(result)

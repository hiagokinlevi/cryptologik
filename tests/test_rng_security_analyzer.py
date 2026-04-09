# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Cyber Port — hiagokinlevi
#
# Test suite for rng_security_analyzer.py
# Run: python3 -m pytest tests/test_rng_security_analyzer.py --override-ini="addopts=" -q

from __future__ import annotations

import sys
import os

# Allow imports from the project root without an installed package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from crypto.rng_security_analyzer import (
    RNGAnalysisResult,
    RNGFinding,
    RNGSample,
    RNGSecurityAnalyzer,
    RNGUsage,
    _CHECK_WEIGHTS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_usage(
    rng_type: str = "os.urandom",
    seed_value=None,
    seed_type=None,
    purpose: str = "key_generation",
    key_size_bits=None,
    context: str = "test",
) -> RNGUsage:
    return RNGUsage(
        rng_type=rng_type,
        seed_value=seed_value,
        seed_type=seed_type,
        purpose=purpose,
        key_size_bits=key_size_bits,
        context=context,
    )


def make_sample(
    values,
    bit_length: int = 32,
    sample_size: int = 0,
    rng_type: str = "unknown",
    context: str = "test",
) -> RNGSample:
    return RNGSample(
        values=values,
        bit_length=bit_length,
        sample_size=sample_size or len(values),
        rng_type=rng_type,
        context=context,
    )


def check_ids(result: RNGAnalysisResult):
    """Return the set of check IDs present in a result's findings."""
    return {f.check_id for f in result.findings}


ANALYZER = RNGSecurityAnalyzer()


# ===========================================================================
# 1. Secure usage baseline — no findings expected
# ===========================================================================


class TestSecureUsageBaseline:
    def test_os_urandom_key_generation_no_seed_no_findings(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="os.urandom", purpose="key_generation"))
        assert result.findings == []
        assert result.risk_score == 0

    def test_secrets_session_token_no_findings(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="secrets", purpose="session_token"))
        assert result.findings == []

    def test_os_urandom_iv_generation_no_findings(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="os.urandom", purpose="iv_generation"))
        assert result.findings == []

    def test_secrets_password_reset_token_no_findings(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="secrets", purpose="password_reset_token"))
        assert result.findings == []

    def test_urandom_csrf_no_findings(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="urandom", purpose="csrf_token"))
        assert result.findings == []

    def test_secure_rng_sufficient_key_size_no_findings(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="key_generation", key_size_bits=256)
        )
        assert result.findings == []


# ===========================================================================
# 2. RNG-001 — Insecure PRNG for cryptographic purpose
# ===========================================================================


class TestRNG001:
    def test_random_for_key_generation_fires(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="key_generation"))
        assert "RNG-001" in check_ids(result)

    def test_random_for_session_token_fires(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="session_token"))
        assert "RNG-001" in check_ids(result)

    def test_random_for_iv_generation_fires(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="iv_generation"))
        assert "RNG-001" in check_ids(result)

    def test_random_for_nonce_generation_fires(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="nonce_generation"))
        assert "RNG-001" in check_ids(result)

    def test_random_for_password_reset_token_fires(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="password_reset_token"))
        assert "RNG-001" in check_ids(result)

    def test_random_for_csrf_token_fires(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="csrf_token"))
        assert "RNG-001" in check_ids(result)

    def test_mt19937_for_key_generation_fires(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="mt19937", purpose="key_generation"))
        assert "RNG-001" in check_ids(result)

    def test_numpy_random_for_session_token_fires(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="numpy.random", purpose="session_token"))
        assert "RNG-001" in check_ids(result)

    def test_java_util_random_for_key_generation_fires(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="java.util.Random", purpose="key_generation"))
        assert "RNG-001" in check_ids(result)

    def test_math_random_for_csrf_fires(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="Math.random", purpose="csrf_token"))
        assert "RNG-001" in check_ids(result)

    def test_rand_for_nonce_fires(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="rand", purpose="nonce_generation"))
        assert "RNG-001" in check_ids(result)

    def test_random_for_general_does_not_fire_001(self):
        # "general" is not a crypto purpose — RNG-001 must NOT fire
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="general"))
        assert "RNG-001" not in check_ids(result)

    def test_os_urandom_for_key_generation_does_not_fire(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="os.urandom", purpose="key_generation"))
        assert "RNG-001" not in check_ids(result)

    def test_secrets_for_session_token_does_not_fire(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="secrets", purpose="session_token"))
        assert "RNG-001" not in check_ids(result)

    def test_rng001_severity_is_critical(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="key_generation"))
        finding = next(f for f in result.findings if f.check_id == "RNG-001")
        assert finding.severity == "CRITICAL"

    def test_rng001_weight_contributes_to_score(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="key_generation", seed_type=None)
        )
        assert result.risk_score >= _CHECK_WEIGHTS["RNG-001"]


# ===========================================================================
# 3. RNG-002 — Hardcoded seed value
# ===========================================================================


class TestRNG002:
    def test_seed_type_hardcoded_fires(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_type="hardcoded")
        )
        assert "RNG-002" in check_ids(result)

    def test_seed_value_42_and_hardcoded_type_fires(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_value=42, seed_type="hardcoded")
        )
        assert "RNG-002" in check_ids(result)

    def test_seed_value_set_with_non_os_entropy_type_fires(self):
        # seed_value is not None AND seed_type is "timestamp" → fires
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_value=1234, seed_type="timestamp")
        )
        assert "RNG-002" in check_ids(result)

    def test_seed_value_set_with_pid_type_fires(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_value=9999, seed_type="pid")
        )
        assert "RNG-002" in check_ids(result)

    def test_seed_type_os_entropy_does_not_fire(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_value=None, seed_type="os_entropy")
        )
        assert "RNG-002" not in check_ids(result)

    def test_seed_type_none_does_not_fire(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="key_generation", seed_type=None)
        )
        assert "RNG-002" not in check_ids(result)

    def test_seed_value_none_and_no_type_does_not_fire(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="secrets", purpose="key_generation", seed_value=None, seed_type=None)
        )
        assert "RNG-002" not in check_ids(result)

    def test_rng002_severity_is_critical(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_type="hardcoded")
        )
        finding = next(f for f in result.findings if f.check_id == "RNG-002")
        assert finding.severity == "CRITICAL"

    def test_seed_value_with_os_entropy_type_does_not_fire_002(self):
        # seed_value set but seed_type = "os_entropy" → condition explicitly excluded
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_value=777, seed_type="os_entropy")
        )
        assert "RNG-002" not in check_ids(result)


# ===========================================================================
# 4. RNG-003 — Weak seed source
# ===========================================================================


class TestRNG003:
    def test_seed_type_timestamp_fires(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_type="timestamp")
        )
        assert "RNG-003" in check_ids(result)

    def test_seed_type_pid_fires(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_type="pid")
        )
        assert "RNG-003" in check_ids(result)

    def test_seed_type_os_entropy_does_not_fire(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_type="os_entropy")
        )
        assert "RNG-003" not in check_ids(result)

    def test_seed_type_none_does_not_fire(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_type=None)
        )
        assert "RNG-003" not in check_ids(result)

    def test_seed_type_hardcoded_does_not_fire_003(self):
        # "hardcoded" triggers RNG-002, not RNG-003
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_type="hardcoded")
        )
        assert "RNG-003" not in check_ids(result)

    def test_rng003_severity_is_high(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_type="timestamp")
        )
        finding = next(f for f in result.findings if f.check_id == "RNG-003")
        assert finding.severity == "HIGH"

    def test_os_urandom_with_timestamp_seed_fires_003(self):
        # Even a "secure" RNG type is flagged if seeded with a weak source
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="key_generation", seed_type="timestamp")
        )
        assert "RNG-003" in check_ids(result)


# ===========================================================================
# 5. RNG-004 — Insufficient key/output size
# ===========================================================================


class TestRNG004:
    def test_key_generation_64_bits_fires(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="key_generation", key_size_bits=64)
        )
        assert "RNG-004" in check_ids(result)

    def test_iv_generation_64_bits_fires(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="iv_generation", key_size_bits=64)
        )
        assert "RNG-004" in check_ids(result)

    def test_nonce_generation_64_bits_fires(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="nonce_generation", key_size_bits=64)
        )
        assert "RNG-004" in check_ids(result)

    def test_key_size_127_bits_fires(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="key_generation", key_size_bits=127)
        )
        assert "RNG-004" in check_ids(result)

    def test_key_size_128_does_not_fire(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="key_generation", key_size_bits=128)
        )
        assert "RNG-004" not in check_ids(result)

    def test_key_size_256_does_not_fire(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="key_generation", key_size_bits=256)
        )
        assert "RNG-004" not in check_ids(result)

    def test_key_size_none_does_not_fire(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="key_generation", key_size_bits=None)
        )
        assert "RNG-004" not in check_ids(result)

    def test_general_purpose_small_size_does_not_trigger_004(self):
        # "general" is not in the crypto-size purposes set — must NOT fire RNG-004
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="general", key_size_bits=64)
        )
        assert "RNG-004" not in check_ids(result)

    def test_session_token_small_size_does_not_trigger_004(self):
        # session_token is NOT in the size-check set (key/iv/nonce only)
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="session_token", key_size_bits=64)
        )
        assert "RNG-004" not in check_ids(result)

    def test_rng004_severity_is_high(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="key_generation", key_size_bits=64)
        )
        finding = next(f for f in result.findings if f.check_id == "RNG-004")
        assert finding.severity == "HIGH"


# ===========================================================================
# 6. RNG-005 — Insecure RNG for any sensitive purpose (dedup with RNG-001)
# ===========================================================================


class TestRNG005:
    def test_random_for_general_fires_005(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="general"))
        assert "RNG-005" in check_ids(result)

    def test_random_for_general_rng001_does_not_fire(self):
        # General is not a crypto purpose — RNG-001 must stay silent
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="general"))
        assert "RNG-001" not in check_ids(result)

    def test_mt19937_for_general_fires_005(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="mt19937", purpose="general"))
        assert "RNG-005" in check_ids(result)

    def test_numpy_random_for_general_fires_005(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="numpy.random", purpose="general"))
        assert "RNG-005" in check_ids(result)

    def test_rand_for_general_fires_005(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="rand", purpose="general"))
        assert "RNG-005" in check_ids(result)

    def test_os_urandom_for_general_does_not_fire_005(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="os.urandom", purpose="general"))
        assert "RNG-005" not in check_ids(result)

    def test_secrets_for_general_does_not_fire_005(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="secrets", purpose="general"))
        assert "RNG-005" not in check_ids(result)

    def test_random_for_key_generation_fires_001_not_005(self):
        # Crypto purpose → RNG-001, NOT RNG-005 (dedup rule)
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="key_generation"))
        ids = check_ids(result)
        assert "RNG-001" in ids
        assert "RNG-005" not in ids

    def test_rng005_severity_is_medium(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="general"))
        finding = next(f for f in result.findings if f.check_id == "RNG-005")
        assert finding.severity == "MEDIUM"

    def test_java_util_random_for_general_fires_005(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="java.util.Random", purpose="general"))
        assert "RNG-005" in check_ids(result)


# ===========================================================================
# 7. RNG-006 — Sequential / low-entropy sample
# ===========================================================================


class TestRNG006:
    def test_sequential_ascending_values_fires(self):
        values = list(range(20))  # [0,1,2,...,19] — all pairs diff by 1
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-006" in check_ids(result)

    def test_all_same_values_fires(self):
        values = [42] * 15
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-006" in check_ids(result)

    def test_all_zeros_fires(self):
        values = [0] * 20
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-006" in check_ids(result)

    def test_random_looking_sample_does_not_fire(self):
        # Large spread between values — clearly not sequential
        values = [
            0x7F3A2B1C, 0x00FA3D21, 0xABCDE012, 0x12345678,
            0xDEADBEEF, 0xCAFEBABE, 0x0FF1CE00, 0xBAADF00D,
            0xFACEFEED, 0x1BADC0DE,
        ]
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-006" not in check_ids(result)

    def test_single_element_sample_no_006(self):
        # Only one value — no consecutive pairs, cannot fire
        result = ANALYZER.analyze_sample(make_sample([99]))
        assert "RNG-006" not in check_ids(result)

    def test_empty_sample_no_006(self):
        result = ANALYZER.analyze_sample(make_sample([]))
        assert "RNG-006" not in check_ids(result)

    def test_two_element_same_fires(self):
        # Pair with diff=0 → 1/1 = 100% > 50%
        result = ANALYZER.analyze_sample(make_sample([5, 5]))
        assert "RNG-006" in check_ids(result)

    def test_two_element_large_diff_no_006(self):
        # diff = 1000000 > 2 → 0/1 = 0% ≤ 50%
        result = ANALYZER.analyze_sample(make_sample([0, 1000000]))
        assert "RNG-006" not in check_ids(result)

    def test_exactly_50_percent_boundary_does_not_fire(self):
        # Exactly 50% sequential pairs → NOT > 50% → should NOT fire
        # 4 pairs, 2 sequential (diff<=2), 2 non-sequential
        values = [0, 1, 1000000, 2000000, 2000001, 9000000]
        # pairs: (0,1)diff=1 ✓, (1,1000000)diff=999999 ✗, (1000000,2000000)diff=1000000 ✗,
        #        (2000000,2000001)diff=1 ✓, (2000001,9000000)diff=6999999 ✗
        # 2 sequential out of 5 pairs = 0.4 ≤ 0.5 → no fire
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-006" not in check_ids(result)

    def test_rng006_severity_is_high(self):
        values = list(range(10))
        result = ANALYZER.analyze_sample(make_sample(values))
        finding = next(f for f in result.findings if f.check_id == "RNG-006")
        assert finding.severity == "HIGH"

    def test_descending_sequential_fires(self):
        values = list(range(20, 0, -1))  # 20,19,18,... — all diffs = 1
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-006" in check_ids(result)


# ===========================================================================
# 8. RNG-007 — Statistical frequency imbalance
# ===========================================================================


class TestRNG007:
    def test_repeated_value_above_threshold_fires(self):
        # n=20, threshold=max(3,20//10)=3. Value 7 appears 10 times > 3
        values = [7] * 10 + list(range(10))  # 10 sevens + 10 other distinct
        sample = make_sample(values)
        result = ANALYZER.analyze_sample(sample)
        assert "RNG-007" in check_ids(result)

    def test_uniform_sample_does_not_fire(self):
        # All distinct values — max freq = 1, threshold = max(3, 100//10) = 10
        values = list(range(100))
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-007" not in check_ids(result)

    def test_sample_size_below_10_does_not_fire(self):
        # sample_size < 10 → check skipped entirely
        values = [0, 0, 0, 0, 0, 0, 0, 1, 2]  # only 9 values
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-007" not in check_ids(result)

    def test_exactly_10_items_with_imbalance_fires(self):
        # n=10, threshold=max(3,1)=3. Value 5 appears 5 times > 3
        values = [5, 5, 5, 5, 5, 1, 2, 3, 4, 6]
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-007" in check_ids(result)

    def test_at_threshold_boundary_does_not_fire(self):
        # n=30, threshold=max(3,3)=3. A value appearing exactly 3 times should NOT fire
        values = list(range(10)) * 3  # each value appears exactly 3 times
        sample = make_sample(values)
        result = ANALYZER.analyze_sample(sample)
        assert "RNG-007" not in check_ids(result)

    def test_one_above_threshold_fires(self):
        # n=30, threshold=3. One value appears 4 times (> 3) → fires
        values = list(range(10)) * 3  # each appears 3 times
        values[0] = values[1]  # make one value appear 4 times by duplication
        # values now: [1,1,2,3,4,5,6,7,8,9, 0,1,2,3,...] → value 1 appears 4 times
        sample = make_sample(values)
        result = ANALYZER.analyze_sample(sample)
        assert "RNG-007" in check_ids(result)

    def test_rng007_severity_is_medium(self):
        values = [99] * 10 + list(range(10))
        result = ANALYZER.analyze_sample(make_sample(values))
        finding = next(f for f in result.findings if f.check_id == "RNG-007")
        assert finding.severity == "MEDIUM"

    def test_sample_size_9_does_not_fire_007(self):
        values = [1] * 9
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-007" not in check_ids(result)


# ===========================================================================
# 9. analyze_sample uses RNG-006/007 only — not usage checks
# ===========================================================================


class TestAnalyzeSampleChecksOnly:
    def test_analyze_sample_never_fires_rng001(self):
        values = list(range(50))
        result = ANALYZER.analyze_sample(make_sample(values, rng_type="random"))
        assert "RNG-001" not in check_ids(result)

    def test_analyze_sample_never_fires_rng002(self):
        values = list(range(50))
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-002" not in check_ids(result)

    def test_analyze_sample_never_fires_rng003(self):
        values = list(range(50))
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-003" not in check_ids(result)

    def test_analyze_sample_never_fires_rng004(self):
        values = list(range(50))
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-004" not in check_ids(result)

    def test_analyze_sample_never_fires_rng005(self):
        values = list(range(50))
        result = ANALYZER.analyze_sample(make_sample(values, rng_type="random"))
        assert "RNG-005" not in check_ids(result)

    def test_analyze_sample_can_fire_rng006(self):
        result = ANALYZER.analyze_sample(make_sample(list(range(20))))
        assert "RNG-006" in check_ids(result)

    def test_analyze_sample_can_fire_rng007(self):
        values = [0] * 15 + list(range(15))  # 0 appears 15 times; threshold = max(3,3)=3
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-007" in check_ids(result)


# ===========================================================================
# 10. analyze_usage uses RNG-001/002/003/004/005 only — not sample checks
# ===========================================================================


class TestAnalyzeUsageChecksOnly:
    def test_analyze_usage_never_fires_rng006(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="key_generation")
        )
        assert "RNG-006" not in check_ids(result)

    def test_analyze_usage_never_fires_rng007(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="key_generation")
        )
        assert "RNG-007" not in check_ids(result)


# ===========================================================================
# 11. analyze_many_usages
# ===========================================================================


class TestAnalyzeManyUsages:
    def test_returns_list_same_length(self):
        usages = [
            make_usage(rng_type="os.urandom", purpose="key_generation"),
            make_usage(rng_type="random", purpose="key_generation"),
            make_usage(rng_type="secrets", purpose="session_token"),
        ]
        results = ANALYZER.analyze_many_usages(usages)
        assert isinstance(results, list)
        assert len(results) == 3

    def test_each_element_is_rng_analysis_result(self):
        usages = [make_usage(rng_type="random", purpose="general")] * 5
        results = ANALYZER.analyze_many_usages(usages)
        assert all(isinstance(r, RNGAnalysisResult) for r in results)

    def test_empty_list_returns_empty_list(self):
        results = ANALYZER.analyze_many_usages([])
        assert results == []

    def test_results_are_independent(self):
        usages = [
            make_usage(rng_type="os.urandom", purpose="key_generation"),
            make_usage(rng_type="random", purpose="key_generation"),
        ]
        results = ANALYZER.analyze_many_usages(usages)
        assert results[0].findings == []
        assert "RNG-001" in check_ids(results[1])

    def test_many_usages_preserves_order(self):
        rng_types = ["os.urandom", "random", "secrets", "mt19937"]
        usages = [make_usage(rng_type=rt, purpose="general") for rt in rng_types]
        results = ANALYZER.analyze_many_usages(usages)
        # Index 1 (random) and 3 (mt19937) should have RNG-005; 0 and 2 should not
        assert "RNG-005" not in check_ids(results[0])
        assert "RNG-005" in check_ids(results[1])
        assert "RNG-005" not in check_ids(results[2])
        assert "RNG-005" in check_ids(results[3])


# ===========================================================================
# 12. Risk score calculation and cap
# ===========================================================================


class TestRiskScore:
    def test_no_findings_risk_score_zero(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="os.urandom", purpose="key_generation"))
        assert result.risk_score == 0

    def test_rng001_alone_score_is_45(self):
        # Only RNG-001 fires (secure rng size, no seed)
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="key_generation", seed_type=None, key_size_bits=None)
        )
        # RNG-001 fires (45). RNG-005 does NOT (dedup). No other checks.
        assert "RNG-001" in check_ids(result)
        assert "RNG-005" not in check_ids(result)
        assert result.risk_score == 45

    def test_rng002_alone_score_is_45(self):
        # Secure rng type but hardcoded seed → only RNG-002
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="key_generation", seed_type="hardcoded")
        )
        assert check_ids(result) == {"RNG-002"}
        assert result.risk_score == 45

    def test_rng003_alone_score_is_25(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="general", seed_type="timestamp")
        )
        assert check_ids(result) == {"RNG-003"}
        assert result.risk_score == 25

    def test_rng005_alone_score_is_15(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="general", seed_type=None)
        )
        assert check_ids(result) == {"RNG-005"}
        assert result.risk_score == 15

    def test_risk_score_capped_at_100(self):
        # Fire RNG-001 (45) + RNG-002 (45) + RNG-003 (25) = 115 → capped at 100
        result = ANALYZER.analyze_usage(
            make_usage(
                rng_type="random",
                purpose="key_generation",
                seed_value=42,
                seed_type="timestamp",  # fires RNG-002 (value set + non-os-entropy type) AND RNG-003
            )
        )
        assert result.risk_score == 100

    def test_risk_score_multiple_checks_accumulate(self):
        # RNG-001 (45) + RNG-004 (25) = 70
        result = ANALYZER.analyze_usage(
            make_usage(
                rng_type="random",
                purpose="key_generation",
                key_size_bits=64,
                seed_type=None,
            )
        )
        assert "RNG-001" in check_ids(result)
        assert "RNG-004" in check_ids(result)
        assert result.risk_score == 70

    def test_rng006_sample_score_is_25(self):
        values = list(range(20))
        result = ANALYZER.analyze_sample(make_sample(values))
        # Only RNG-006 fires
        assert result.risk_score == 25

    def test_rng007_sample_score_is_15(self):
        # Create a sample where RNG-007 fires but NOT RNG-006
        # Use widely spread values so no sequential pattern,
        # but one value repeated > n//10 times
        base = [i * 10000 for i in range(1, 21)]  # 20 widely spaced values
        heavy = [999999] * 5  # 999999 appears 5 times; threshold=max(3,2)=3 → fires
        values = base + heavy  # total n=25, threshold=max(3,2)=3
        result = ANALYZER.analyze_sample(make_sample(values))
        assert "RNG-007" in check_ids(result)
        assert result.risk_score >= _CHECK_WEIGHTS["RNG-007"]


# ===========================================================================
# 13. by_severity() structure
# ===========================================================================


class TestBySeverity:
    def test_no_findings_returns_empty_dict(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="os.urandom", purpose="key_generation"))
        assert result.by_severity() == {}

    def test_critical_findings_in_correct_bucket(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="key_generation"))
        bs = result.by_severity()
        assert "CRITICAL" in bs
        assert any(f.check_id == "RNG-001" for f in bs["CRITICAL"])

    def test_high_findings_in_correct_bucket(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="os.urandom", purpose="key_generation", key_size_bits=64)
        )
        bs = result.by_severity()
        assert "HIGH" in bs
        assert any(f.check_id == "RNG-004" for f in bs["HIGH"])

    def test_medium_findings_in_correct_bucket(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="general"))
        bs = result.by_severity()
        assert "MEDIUM" in bs
        assert any(f.check_id == "RNG-005" for f in bs["MEDIUM"])

    def test_by_severity_values_are_lists_of_findings(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="key_generation", seed_type="hardcoded")
        )
        bs = result.by_severity()
        for sev, findings in bs.items():
            assert isinstance(findings, list)
            assert all(isinstance(f, RNGFinding) for f in findings)

    def test_by_severity_all_findings_present(self):
        result = ANALYZER.analyze_usage(
            make_usage(rng_type="random", purpose="key_generation", seed_type="hardcoded")
        )
        total_in_buckets = sum(len(v) for v in result.by_severity().values())
        assert total_in_buckets == len(result.findings)


# ===========================================================================
# 14. summary() format
# ===========================================================================


class TestSummary:
    def test_no_findings_summary_contains_no_findings(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="os.urandom", purpose="key_generation"))
        s = result.summary()
        assert "No findings" in s or "no findings" in s.lower()

    def test_summary_contains_risk_score(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="key_generation"))
        s = result.summary()
        assert str(result.risk_score) in s

    def test_summary_contains_finding_count(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="key_generation"))
        s = result.summary()
        assert str(len(result.findings)) in s

    def test_summary_is_string(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="general"))
        assert isinstance(result.summary(), str)

    def test_summary_secure_risk_score_zero(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="os.urandom", purpose="key_generation"))
        assert "0" in result.summary()


# ===========================================================================
# 15. to_dict() all dataclasses
# ===========================================================================


class TestToDict:
    def test_rng_usage_to_dict_keys(self):
        u = make_usage(rng_type="random", purpose="key_generation", seed_value=1, seed_type="hardcoded", key_size_bits=64)
        d = u.to_dict()
        assert set(d.keys()) == {"rng_type", "seed_value", "seed_type", "purpose", "key_size_bits", "context"}

    def test_rng_usage_to_dict_values(self):
        u = make_usage(rng_type="random", purpose="key_generation", seed_value=99, seed_type="hardcoded", key_size_bits=128)
        d = u.to_dict()
        assert d["rng_type"] == "random"
        assert d["seed_value"] == 99
        assert d["seed_type"] == "hardcoded"
        assert d["key_size_bits"] == 128

    def test_rng_sample_to_dict_keys(self):
        s = make_sample([1, 2, 3], bit_length=32, rng_type="random", context="unit_test")
        d = s.to_dict()
        assert set(d.keys()) == {"values", "bit_length", "sample_size", "rng_type", "context"}

    def test_rng_sample_to_dict_values(self):
        s = make_sample([10, 20, 30], bit_length=16, rng_type="mt19937", context="test_ctx")
        d = s.to_dict()
        assert d["values"] == [10, 20, 30]
        assert d["bit_length"] == 16
        assert d["rng_type"] == "mt19937"
        assert d["context"] == "test_ctx"

    def test_rng_finding_to_dict_keys(self):
        f = RNGFinding(
            check_id="RNG-001",
            severity="CRITICAL",
            rng_type="random",
            context="test",
            message="Test message",
            recommendation="Test rec",
        )
        d = f.to_dict()
        assert set(d.keys()) == {"check_id", "severity", "rng_type", "context", "message", "recommendation"}

    def test_rng_finding_to_dict_values(self):
        f = RNGFinding(
            check_id="RNG-002",
            severity="CRITICAL",
            rng_type="mt19937",
            context="auth",
            message="msg",
            recommendation="rec",
        )
        d = f.to_dict()
        assert d["check_id"] == "RNG-002"
        assert d["severity"] == "CRITICAL"
        assert d["rng_type"] == "mt19937"

    def test_rng_analysis_result_to_dict_keys(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="key_generation"))
        d = result.to_dict()
        assert "risk_score" in d
        assert "findings" in d
        assert "summary" in d
        assert "by_severity" in d

    def test_rng_analysis_result_to_dict_findings_are_dicts(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="key_generation"))
        d = result.to_dict()
        for item in d["findings"]:
            assert isinstance(item, dict)
            assert "check_id" in item

    def test_rng_analysis_result_to_dict_risk_score(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="key_generation"))
        d = result.to_dict()
        assert d["risk_score"] == result.risk_score

    def test_rng_analysis_result_to_dict_summary_is_string(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="key_generation"))
        d = result.to_dict()
        assert isinstance(d["summary"], str)

    def test_rng_analysis_result_to_dict_by_severity_is_dict(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="key_generation"))
        d = result.to_dict()
        assert isinstance(d["by_severity"], dict)

    def test_to_dict_no_findings_case(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="os.urandom", purpose="key_generation"))
        d = result.to_dict()
        assert d["findings"] == []
        assert d["risk_score"] == 0
        assert d["by_severity"] == {}


# ===========================================================================
# 16. _CHECK_WEIGHTS registry
# ===========================================================================


class TestCheckWeights:
    def test_all_check_ids_present(self):
        for cid in ("RNG-001", "RNG-002", "RNG-003", "RNG-004", "RNG-005", "RNG-006", "RNG-007"):
            assert cid in _CHECK_WEIGHTS

    def test_critical_weights(self):
        assert _CHECK_WEIGHTS["RNG-001"] == 45
        assert _CHECK_WEIGHTS["RNG-002"] == 45

    def test_high_weights(self):
        assert _CHECK_WEIGHTS["RNG-003"] == 25
        assert _CHECK_WEIGHTS["RNG-004"] == 25
        assert _CHECK_WEIGHTS["RNG-006"] == 25

    def test_medium_weights(self):
        assert _CHECK_WEIGHTS["RNG-005"] == 15
        assert _CHECK_WEIGHTS["RNG-007"] == 15


# ===========================================================================
# 17. Context and rng_type propagation in findings
# ===========================================================================


class TestContextPropagation:
    def test_rng_type_in_finding_matches_usage_rng_type(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="mt19937", purpose="key_generation", context="auth_service"))
        for f in result.findings:
            assert f.rng_type == "mt19937"

    def test_context_in_finding_matches_usage_context(self):
        result = ANALYZER.analyze_usage(make_usage(rng_type="random", purpose="key_generation", context="login_module"))
        for f in result.findings:
            assert f.context == "login_module"

    def test_rng_type_in_sample_finding_matches(self):
        sample = make_sample(list(range(20)), rng_type="bad_prng", context="crypto_lib")
        result = ANALYZER.analyze_sample(sample)
        for f in result.findings:
            assert f.rng_type == "bad_prng"
            assert f.context == "crypto_lib"


# ===========================================================================
# 18. RNGSample __post_init__ auto-populates sample_size
# ===========================================================================


class TestRNGSamplePostInit:
    def test_sample_size_auto_populated(self):
        s = RNGSample(values=[1, 2, 3, 4, 5], bit_length=32)
        assert s.sample_size == 5

    def test_sample_size_explicit_override(self):
        s = RNGSample(values=[1, 2, 3], bit_length=32, sample_size=3)
        assert s.sample_size == 3

    def test_empty_values_sample_size_zero(self):
        s = RNGSample(values=[], bit_length=32)
        assert s.sample_size == 0

# test_asymmetric_key_analyzer.py — Cyber Port / cryptologik
# Tests for asymmetric_key_analyzer.py — 115+ tests covering all 7 checks.
#
# Copyright (c) 2026 hiagokinlevi — Licensed under CC BY 4.0
# https://creativecommons.org/licenses/by/4.0/
#
# Run with:  python -m pytest tests/test_asymmetric_key_analyzer.py -q

from __future__ import annotations

import sys
import os

# Allow imports from the repo root regardless of how pytest is invoked
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import date
from typing import List

from crypto.asymmetric_key_analyzer import (
    ASYFinding,
    ASYResult,
    AsymmetricKey,
    analyze,
    analyze_many,
    _CHECK_WEIGHTS,
    _WEAK_CURVES,
    _P256_CURVES,
)

# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------

REFERENCE_DATE = date(2026, 4, 6)

# Expiry dates relative to REFERENCE_DATE
EXPIRY_WITHIN_2Y = date(2027, 4, 6)        # exactly 365 days — fine
EXPIRY_EXACTLY_730 = date(2028, 4, 5)      # 730 days — boundary (not triggered)
EXPIRY_EXACTLY_731 = date(2028, 4, 6)      # 731 days — triggers ASY-007
EXPIRY_FAR_FUTURE = date(2030, 1, 1)       # well beyond 2 years


def _rsa(
    key_id: str = "rsa-key",
    key_size_bits: int = 4096,
    rsa_public_exponent: int = 65537,
    expiry_date: date = EXPIRY_WITHIN_2Y,
) -> AsymmetricKey:
    """Factory: RSA key with sensible defaults (STRONG baseline)."""
    return AsymmetricKey(
        key_id=key_id,
        algorithm="RSA",
        key_size_bits=key_size_bits,
        curve_name=None,
        rsa_public_exponent=rsa_public_exponent,
        created_date=REFERENCE_DATE,
        expiry_date=expiry_date,
        purpose="signing",
    )


def _dsa(
    key_id: str = "dsa-key",
    key_size_bits: int = 2048,
    expiry_date: date = EXPIRY_WITHIN_2Y,
) -> AsymmetricKey:
    """Factory: DSA key."""
    return AsymmetricKey(
        key_id=key_id,
        algorithm="DSA",
        key_size_bits=key_size_bits,
        curve_name=None,
        rsa_public_exponent=None,
        created_date=REFERENCE_DATE,
        expiry_date=expiry_date,
        purpose="signing",
    )


def _ec(
    key_id: str = "ec-key",
    algorithm: str = "EC",
    curve_name: str = "secp384r1",
    expiry_date: date = EXPIRY_WITHIN_2Y,
) -> AsymmetricKey:
    """Factory: EC key with sensible defaults (strong curve baseline)."""
    return AsymmetricKey(
        key_id=key_id,
        algorithm=algorithm,
        key_size_bits=None,
        curve_name=curve_name,
        rsa_public_exponent=None,
        created_date=REFERENCE_DATE,
        expiry_date=expiry_date,
        purpose="signing",
    )


def _ed25519(
    key_id: str = "ed25519-key",
    expiry_date: date = EXPIRY_WITHIN_2Y,
) -> AsymmetricKey:
    """Factory: Ed25519 key."""
    return AsymmetricKey(
        key_id=key_id,
        algorithm="Ed25519",
        key_size_bits=None,
        curve_name=None,
        rsa_public_exponent=None,
        created_date=REFERENCE_DATE,
        expiry_date=expiry_date,
        purpose="signing",
    )


def _find(result: ASYResult, check_id: str) -> List[ASYFinding]:
    """Return all findings with the given check_id from a result."""
    return [f for f in result.findings if f.check_id == check_id]


def _has(result: ASYResult, check_id: str) -> bool:
    return bool(_find(result, check_id))


# ===========================================================================
# ASY-001 — RSA key size below 2048 bits (CRITICAL)
# ===========================================================================

# --- fires ---

def test_asy001_fires_for_512_bit_rsa():
    r = analyze(_rsa(key_size_bits=512), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-001")


def test_asy001_fires_for_1024_bit_rsa():
    r = analyze(_rsa(key_size_bits=1024), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-001")


def test_asy001_fires_for_2047_bit_rsa():
    r = analyze(_rsa(key_size_bits=2047), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-001")


def test_asy001_severity_is_critical():
    r = analyze(_rsa(key_size_bits=1024), reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-001")[0]
    assert f.severity == "CRITICAL"


def test_asy001_weight_is_45():
    r = analyze(_rsa(key_size_bits=1024), reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-001")[0]
    assert f.weight == 45


def test_asy001_detail_contains_key_id():
    key = _rsa(key_id="my-rsa-key", key_size_bits=1024)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert "my-rsa-key" in _find(r, "ASY-001")[0].detail


def test_asy001_fires_for_1_bit_rsa():
    r = analyze(_rsa(key_size_bits=1), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-001")


# --- does not fire ---

def test_asy001_does_not_fire_for_2048_bit_rsa():
    r = analyze(_rsa(key_size_bits=2048), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-001")


def test_asy001_does_not_fire_for_3072_bit_rsa():
    r = analyze(_rsa(key_size_bits=3072), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-001")


def test_asy001_does_not_fire_for_4096_bit_rsa():
    r = analyze(_rsa(key_size_bits=4096), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-001")


def test_asy001_does_not_fire_when_key_size_is_none():
    key = _rsa(key_size_bits=4096)
    key.key_size_bits = None
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-001")


def test_asy001_does_not_fire_for_dsa():
    r = analyze(_dsa(key_size_bits=1024), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-001")


def test_asy001_does_not_fire_for_ec():
    r = analyze(_ec(), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-001")


# ===========================================================================
# ASY-002 — RSA key between 2048 and 3071 bits (MEDIUM)
# ===========================================================================

# --- fires ---

def test_asy002_fires_for_2048_bit_rsa():
    r = analyze(_rsa(key_size_bits=2048), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-002")


def test_asy002_fires_for_2560_bit_rsa():
    r = analyze(_rsa(key_size_bits=2560), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-002")


def test_asy002_fires_for_3071_bit_rsa():
    r = analyze(_rsa(key_size_bits=3071), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-002")


def test_asy002_severity_is_medium():
    r = analyze(_rsa(key_size_bits=2048), reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-002")[0]
    assert f.severity == "MEDIUM"


def test_asy002_weight_is_15():
    r = analyze(_rsa(key_size_bits=2048), reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-002")[0]
    assert f.weight == 15


def test_asy002_detail_contains_key_id():
    key = _rsa(key_id="medium-rsa", key_size_bits=2048)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert "medium-rsa" in _find(r, "ASY-002")[0].detail


# --- suppressed by ASY-001 ---

def test_asy002_suppressed_when_asy001_fires_1024():
    r = analyze(_rsa(key_size_bits=1024), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-001")
    assert not _has(r, "ASY-002")


def test_asy002_suppressed_when_asy001_fires_512():
    r = analyze(_rsa(key_size_bits=512), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-002")


def test_asy002_suppressed_when_asy001_fires_2047():
    r = analyze(_rsa(key_size_bits=2047), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-001")
    assert not _has(r, "ASY-002")


# --- does not fire ---

def test_asy002_does_not_fire_for_3072_bit_rsa():
    r = analyze(_rsa(key_size_bits=3072), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-002")


def test_asy002_does_not_fire_for_4096_bit_rsa():
    r = analyze(_rsa(key_size_bits=4096), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-002")


def test_asy002_does_not_fire_for_dsa():
    r = analyze(_dsa(key_size_bits=2048), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-002")


def test_asy002_does_not_fire_for_ec():
    r = analyze(_ec(), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-002")


def test_asy002_does_not_fire_when_key_size_none():
    key = _rsa()
    key.key_size_bits = None
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-002")


# ===========================================================================
# ASY-003 — DSA deprecated (HIGH)
# ===========================================================================

# --- fires ---

def test_asy003_fires_for_dsa_1024():
    r = analyze(_dsa(key_size_bits=1024), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-003")


def test_asy003_fires_for_dsa_2048():
    r = analyze(_dsa(key_size_bits=2048), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-003")


def test_asy003_fires_for_dsa_3072():
    r = analyze(_dsa(key_size_bits=3072), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-003")


def test_asy003_severity_is_high():
    r = analyze(_dsa(), reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-003")[0]
    assert f.severity == "HIGH"


def test_asy003_weight_is_25():
    r = analyze(_dsa(), reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-003")[0]
    assert f.weight == 25


def test_asy003_detail_contains_key_id():
    key = _dsa(key_id="my-dsa-key")
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert "my-dsa-key" in _find(r, "ASY-003")[0].detail


# --- does not fire ---

def test_asy003_does_not_fire_for_rsa():
    r = analyze(_rsa(), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-003")


def test_asy003_does_not_fire_for_ec():
    r = analyze(_ec(), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-003")


def test_asy003_does_not_fire_for_ed25519():
    r = analyze(_ed25519(), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-003")


# ===========================================================================
# ASY-004 — EC weak curve (HIGH)
# ===========================================================================

# --- fires ---

def test_asy004_fires_secp192r1():
    r = analyze(_ec(curve_name="secp192r1"), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-004")


def test_asy004_fires_prime192v1():
    r = analyze(_ec(curve_name="prime192v1"), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-004")


def test_asy004_fires_sect163k1():
    r = analyze(_ec(curve_name="sect163k1"), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-004")


def test_asy004_fires_sect163r2():
    r = analyze(_ec(curve_name="sect163r2"), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-004")


def test_asy004_fires_brainpoolP160r1():
    r = analyze(_ec(curve_name="brainpoolP160r1"), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-004")


def test_asy004_fires_case_insensitive_upper():
    r = analyze(_ec(curve_name="SECP192R1"), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-004")


def test_asy004_fires_case_insensitive_mixed():
    r = analyze(_ec(curve_name="Sect163K1"), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-004")


def test_asy004_severity_is_high():
    r = analyze(_ec(curve_name="secp192r1"), reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-004")[0]
    assert f.severity == "HIGH"


def test_asy004_weight_is_25():
    r = analyze(_ec(curve_name="secp192r1"), reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-004")[0]
    assert f.weight == 25


def test_asy004_detail_contains_key_id():
    key = _ec(key_id="weak-ec-key", curve_name="secp192r1")
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert "weak-ec-key" in _find(r, "ASY-004")[0].detail


def test_asy004_fires_for_ecdsa_algorithm():
    r = analyze(_ec(algorithm="ECDSA", curve_name="secp192r1"), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-004")


def test_asy004_fires_for_ecdh_algorithm():
    r = analyze(_ec(algorithm="ECDH", curve_name="secp192r1"), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-004")


# --- does not fire ---

def test_asy004_does_not_fire_secp256r1():
    r = analyze(_ec(curve_name="secp256r1"), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-004")


def test_asy004_does_not_fire_secp384r1():
    r = analyze(_ec(curve_name="secp384r1"), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-004")


def test_asy004_does_not_fire_secp521r1():
    r = analyze(_ec(curve_name="secp521r1"), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-004")


def test_asy004_does_not_fire_when_curve_name_none():
    key = _ec()
    key.curve_name = None
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-004")


def test_asy004_does_not_fire_for_rsa():
    r = analyze(_rsa(), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-004")


def test_asy004_does_not_fire_for_ed25519():
    r = analyze(_ed25519(), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-004")


# ===========================================================================
# ASY-005 — EC P-256 insufficient when min_security_bits >= 256 (MEDIUM)
# ===========================================================================

# --- fires (min_security_bits=256) ---

def test_asy005_fires_secp256r1_min256():
    r = analyze(_ec(curve_name="secp256r1"), min_security_bits=256, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-005")


def test_asy005_fires_prime256v1_min256():
    r = analyze(_ec(curve_name="prime256v1"), min_security_bits=256, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-005")


def test_asy005_fires_P256_hyphen_min256():
    r = analyze(_ec(curve_name="P-256"), min_security_bits=256, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-005")


def test_asy005_fires_P256_no_hyphen_min256():
    r = analyze(_ec(curve_name="P256"), min_security_bits=256, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-005")


def test_asy005_fires_p256_lowercase_min256():
    r = analyze(_ec(curve_name="p-256"), min_security_bits=256, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-005")


def test_asy005_severity_is_medium():
    r = analyze(_ec(curve_name="secp256r1"), min_security_bits=256, reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-005")[0]
    assert f.severity == "MEDIUM"


def test_asy005_weight_is_15():
    r = analyze(_ec(curve_name="secp256r1"), min_security_bits=256, reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-005")[0]
    assert f.weight == 15


def test_asy005_detail_contains_key_id():
    key = _ec(key_id="p256-key", curve_name="secp256r1")
    r = analyze(key, min_security_bits=256, reference_date=REFERENCE_DATE)
    assert "p256-key" in _find(r, "ASY-005")[0].detail


# --- does not fire (min_security_bits=128) ---

def test_asy005_does_not_fire_secp256r1_min128():
    r = analyze(_ec(curve_name="secp256r1"), min_security_bits=128, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-005")


def test_asy005_does_not_fire_prime256v1_min128():
    r = analyze(_ec(curve_name="prime256v1"), min_security_bits=128, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-005")


# --- does not fire (strong curve regardless of min_security_bits) ---

def test_asy005_does_not_fire_secp384r1_min256():
    r = analyze(_ec(curve_name="secp384r1"), min_security_bits=256, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-005")


def test_asy005_does_not_fire_secp521r1_min256():
    r = analyze(_ec(curve_name="secp521r1"), min_security_bits=256, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-005")


def test_asy005_does_not_fire_for_rsa():
    r = analyze(_rsa(), min_security_bits=256, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-005")


def test_asy005_does_not_fire_for_ed25519():
    r = analyze(_ed25519(), min_security_bits=256, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-005")


# ===========================================================================
# ASY-006 — RSA public exponent e=3 (CRITICAL)
# ===========================================================================

# --- fires ---

def test_asy006_fires_for_e3():
    r = analyze(_rsa(rsa_public_exponent=3), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-006")


def test_asy006_severity_is_critical():
    r = analyze(_rsa(rsa_public_exponent=3), reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-006")[0]
    assert f.severity == "CRITICAL"


def test_asy006_weight_is_45():
    r = analyze(_rsa(rsa_public_exponent=3), reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-006")[0]
    assert f.weight == 45


def test_asy006_detail_contains_key_id():
    key = _rsa(key_id="bad-exponent-key", rsa_public_exponent=3)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert "bad-exponent-key" in _find(r, "ASY-006")[0].detail


def test_asy006_fires_for_e3_with_small_key():
    # Both ASY-001 and ASY-006 should fire independently
    r = analyze(_rsa(key_size_bits=1024, rsa_public_exponent=3), reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-001")
    assert _has(r, "ASY-006")


# --- does not fire ---

def test_asy006_does_not_fire_for_e17():
    r = analyze(_rsa(rsa_public_exponent=17), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-006")


def test_asy006_does_not_fire_for_e65537():
    r = analyze(_rsa(rsa_public_exponent=65537), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-006")


def test_asy006_does_not_fire_when_exponent_is_none():
    key = _rsa()
    key.rsa_public_exponent = None
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-006")


def test_asy006_does_not_fire_for_dsa():
    r = analyze(_dsa(), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-006")


def test_asy006_does_not_fire_for_ec():
    r = analyze(_ec(), reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-006")


# ===========================================================================
# ASY-007 — Missing expiry or expiry > 2 years (MEDIUM)
# ===========================================================================

# --- fires (no expiry) ---

def test_asy007_fires_when_expiry_is_none_rsa():
    key = _rsa(expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-007")


def test_asy007_fires_when_expiry_is_none_dsa():
    key = _dsa(expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-007")


def test_asy007_fires_when_expiry_is_none_ec():
    key = _ec(expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-007")


def test_asy007_fires_when_expiry_is_none_ed25519():
    key = _ed25519(expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-007")


# --- fires (expiry > 730 days) ---

def test_asy007_fires_when_expiry_731_days_out():
    key = _rsa(expiry_date=EXPIRY_EXACTLY_731)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-007")


def test_asy007_fires_when_expiry_far_future():
    key = _rsa(expiry_date=EXPIRY_FAR_FUTURE)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-007")


def test_asy007_fires_when_expiry_1000_days_out():
    key = _rsa(expiry_date=date(2029, 1, 1))
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-007")


def test_asy007_severity_is_medium():
    key = _rsa(expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-007")[0]
    assert f.severity == "MEDIUM"


def test_asy007_weight_is_15():
    key = _rsa(expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    f = _find(r, "ASY-007")[0]
    assert f.weight == 15


def test_asy007_detail_contains_key_id():
    key = _rsa(key_id="expiry-key", expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert "expiry-key" in _find(r, "ASY-007")[0].detail


# --- does not fire ---

def test_asy007_does_not_fire_when_expiry_exactly_730_days():
    key = _rsa(expiry_date=EXPIRY_EXACTLY_730)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-007")


def test_asy007_does_not_fire_when_expiry_365_days():
    key = _rsa(expiry_date=EXPIRY_WITHIN_2Y)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-007")


def test_asy007_does_not_fire_when_expiry_1_day():
    key = _rsa(expiry_date=date(2026, 4, 7))
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-007")


def test_asy007_does_not_fire_when_expiry_same_day():
    key = _rsa(expiry_date=REFERENCE_DATE)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-007")


def test_asy007_applies_to_ed25519():
    key = _ed25519(expiry_date=EXPIRY_FAR_FUTURE)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-007")


def test_asy007_applies_to_ed448():
    key = AsymmetricKey(
        key_id="ed448-key",
        algorithm="Ed448",
        key_size_bits=None,
        curve_name=None,
        rsa_public_exponent=None,
        created_date=REFERENCE_DATE,
        expiry_date=None,
        purpose="signing",
    )
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-007")


# ===========================================================================
# Risk score and security level tests
# ===========================================================================

def test_risk_score_zero_for_strong_rsa():
    r = analyze(_rsa(key_size_bits=4096), reference_date=REFERENCE_DATE)
    assert r.risk_score == 0
    assert r.security_level == "STRONG"


def test_risk_score_15_single_asy002():
    # 2048-bit RSA with good expiry and e=65537 → only ASY-002 fires (weight=15)
    r = analyze(_rsa(key_size_bits=2048), reference_date=REFERENCE_DATE)
    assert r.risk_score == 15
    assert r.security_level == "ADEQUATE"


def test_risk_score_30_asy002_and_asy007():
    # 2048-bit RSA, no expiry → ASY-002 (15) + ASY-007 (15) = 30
    key = _rsa(key_size_bits=2048, expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert r.risk_score == 30
    assert r.security_level == "WEAK"


def test_risk_score_45_single_asy001():
    # RSA 1024 + good expiry + e=65537 → ASY-001 (45) only
    r = analyze(_rsa(key_size_bits=1024), reference_date=REFERENCE_DATE)
    assert r.risk_score == 45
    assert r.security_level == "WEAK"


def test_risk_score_60_asy001_and_asy006():
    # RSA 1024 + e=3 → ASY-001 (45) + ASY-006 (45) = 90 → capped to 90
    r = analyze(_rsa(key_size_bits=1024, rsa_public_exponent=3), reference_date=REFERENCE_DATE)
    assert r.risk_score == 90
    assert r.security_level == "BROKEN"


def test_risk_score_capped_at_100():
    # RSA 512 + e=3 + no expiry → 45+45+15 = 105 → capped to 100
    key = _rsa(key_size_bits=512, rsa_public_exponent=3, expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert r.risk_score == 100
    assert r.security_level == "BROKEN"


def test_risk_score_25_dsa_only():
    # DSA with good expiry → ASY-003 (25) only
    r = analyze(_dsa(), reference_date=REFERENCE_DATE)
    assert r.risk_score == 25
    assert r.security_level == "WEAK"


def test_risk_score_40_dsa_and_asy007():
    # DSA + no expiry → ASY-003 (25) + ASY-007 (15) = 40
    key = _dsa(expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert r.risk_score == 40
    assert r.security_level == "WEAK"


def test_risk_score_25_ec_weak_curve():
    r = analyze(_ec(curve_name="secp192r1"), reference_date=REFERENCE_DATE)
    assert r.risk_score == 25
    assert r.security_level == "WEAK"


def test_risk_score_0_ed25519_with_valid_expiry():
    r = analyze(_ed25519(), reference_date=REFERENCE_DATE)
    assert r.risk_score == 0
    assert r.security_level == "STRONG"


def test_security_level_adequate_boundary():
    # Risk score 20 should map to ADEQUATE
    key = _rsa(key_size_bits=2048, expiry_date=EXPIRY_WITHIN_2Y)
    r = analyze(key, reference_date=REFERENCE_DATE)
    # ASY-002=15 only; that's ADEQUATE
    assert r.risk_score == 15
    assert r.security_level == "ADEQUATE"


def test_security_level_weak_boundary_21():
    # We need a score of 21-50 for WEAK; DSA (25) with good expiry = 25
    r = analyze(_dsa(), reference_date=REFERENCE_DATE)
    assert 21 <= r.risk_score <= 50
    assert r.security_level == "WEAK"


# ===========================================================================
# ASYResult helper method tests
# ===========================================================================

def test_to_dict_contains_required_keys():
    r = analyze(_rsa(key_size_bits=1024), reference_date=REFERENCE_DATE)
    d = r.to_dict()
    assert "key_id" in d
    assert "algorithm" in d
    assert "risk_score" in d
    assert "security_level" in d
    assert "findings" in d
    assert isinstance(d["findings"], list)


def test_to_dict_findings_have_required_keys():
    r = analyze(_rsa(key_size_bits=1024), reference_date=REFERENCE_DATE)
    d = r.to_dict()
    for finding_dict in d["findings"]:
        assert "check_id" in finding_dict
        assert "severity" in finding_dict
        assert "title" in finding_dict
        assert "detail" in finding_dict
        assert "weight" in finding_dict


def test_summary_contains_key_id():
    r = analyze(_rsa(key_id="test-key", key_size_bits=4096), reference_date=REFERENCE_DATE)
    assert "test-key" in r.summary()


def test_summary_contains_security_level():
    r = analyze(_rsa(key_size_bits=4096), reference_date=REFERENCE_DATE)
    assert "STRONG" in r.summary()


def test_summary_contains_score():
    r = analyze(_rsa(key_size_bits=4096), reference_date=REFERENCE_DATE)
    assert "0" in r.summary()


def test_by_severity_groups_correctly():
    # RSA 1024 + no expiry → CRITICAL(ASY-001) + MEDIUM(ASY-007)
    key = _rsa(key_size_bits=1024, expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    groups = r.by_severity()
    assert "CRITICAL" in groups
    assert "MEDIUM" in groups
    assert all(f.severity == "CRITICAL" for f in groups["CRITICAL"])
    assert all(f.severity == "MEDIUM" for f in groups["MEDIUM"])


def test_by_severity_empty_when_no_findings():
    r = analyze(_rsa(key_size_bits=4096), reference_date=REFERENCE_DATE)
    groups = r.by_severity()
    assert groups == {}


# ===========================================================================
# analyze_many tests
# ===========================================================================

def test_analyze_many_returns_list():
    keys = [_rsa(), _dsa(), _ec()]
    results = analyze_many(keys, reference_date=REFERENCE_DATE)
    assert isinstance(results, list)
    assert len(results) == 3


def test_analyze_many_preserves_order():
    keys = [_rsa(key_id="k1"), _dsa(key_id="k2"), _ec(key_id="k3")]
    results = analyze_many(keys, reference_date=REFERENCE_DATE)
    assert [r.key_id for r in results] == ["k1", "k2", "k3"]


def test_analyze_many_empty_list():
    results = analyze_many([], reference_date=REFERENCE_DATE)
    assert results == []


def test_analyze_many_min_security_bits_propagated():
    keys = [_ec(curve_name="secp256r1")]
    results = analyze_many(keys, min_security_bits=256, reference_date=REFERENCE_DATE)
    assert _has(results[0], "ASY-005")


def test_analyze_many_single_key():
    results = analyze_many([_rsa(key_size_bits=4096)], reference_date=REFERENCE_DATE)
    assert len(results) == 1
    assert results[0].risk_score == 0


# ===========================================================================
# Ed25519 / Ed448 / X25519 / X448 exempt algorithm tests
# ===========================================================================

def test_ed25519_only_asy007_can_fire():
    key = _ed25519(expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    ids = {f.check_id for f in r.findings}
    assert ids == {"ASY-007"}


def test_ed448_only_asy007_can_fire():
    key = AsymmetricKey(
        key_id="ed448",
        algorithm="Ed448",
        key_size_bits=None,
        curve_name=None,
        rsa_public_exponent=None,
        created_date=REFERENCE_DATE,
        expiry_date=EXPIRY_FAR_FUTURE,
        purpose="signing",
    )
    r = analyze(key, reference_date=REFERENCE_DATE)
    ids = {f.check_id for f in r.findings}
    assert ids == {"ASY-007"}


def test_x25519_no_findings_with_good_expiry():
    key = AsymmetricKey(
        key_id="x25519",
        algorithm="X25519",
        key_size_bits=None,
        curve_name=None,
        rsa_public_exponent=None,
        created_date=REFERENCE_DATE,
        expiry_date=EXPIRY_WITHIN_2Y,
        purpose="key_agreement",
    )
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert r.findings == []
    assert r.risk_score == 0


def test_x448_no_findings_with_good_expiry():
    key = AsymmetricKey(
        key_id="x448",
        algorithm="X448",
        key_size_bits=None,
        curve_name=None,
        rsa_public_exponent=None,
        created_date=REFERENCE_DATE,
        expiry_date=EXPIRY_WITHIN_2Y,
        purpose="key_agreement",
    )
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert r.findings == []
    assert r.risk_score == 0


def test_ed25519_min_security_256_does_not_trigger_asy005():
    r = analyze(_ed25519(), min_security_bits=256, reference_date=REFERENCE_DATE)
    assert not _has(r, "ASY-005")


# ===========================================================================
# Miscellaneous / integration tests
# ===========================================================================

def test_clean_rsa_4096_has_zero_findings():
    r = analyze(_rsa(key_size_bits=4096), reference_date=REFERENCE_DATE)
    assert r.findings == []


def test_clean_ec_p384_has_zero_findings():
    r = analyze(_ec(curve_name="secp384r1"), reference_date=REFERENCE_DATE)
    assert r.findings == []


def test_check_weights_registry_has_all_ids():
    expected = {"ASY-001", "ASY-002", "ASY-003", "ASY-004", "ASY-005", "ASY-006", "ASY-007"}
    assert set(_CHECK_WEIGHTS.keys()) == expected


def test_default_reference_date_does_not_raise():
    # reference_date defaults to date.today(); should not raise
    key = _rsa(key_size_bits=4096)
    r = analyze(key)
    assert isinstance(r, ASYResult)


def test_result_algorithm_matches_input():
    r = analyze(_rsa(), reference_date=REFERENCE_DATE)
    assert r.algorithm == "RSA"
    r2 = analyze(_dsa(), reference_date=REFERENCE_DATE)
    assert r2.algorithm == "DSA"
    r3 = analyze(_ec(), reference_date=REFERENCE_DATE)
    assert r3.algorithm == "EC"


def test_result_key_id_matches_input():
    key = _rsa(key_id="unique-id-xyz")
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert r.key_id == "unique-id-xyz"


def test_ecdsa_algorithm_label_accepted():
    # ECDSA variant label should run EC checks
    r = analyze(_ec(algorithm="ECDSA", curve_name="secp384r1"), reference_date=REFERENCE_DATE)
    assert r.algorithm == "ECDSA"
    assert r.risk_score == 0


def test_ecdh_algorithm_label_accepted():
    r = analyze(_ec(algorithm="ECDH", curve_name="secp384r1"), reference_date=REFERENCE_DATE)
    assert r.algorithm == "ECDH"
    assert r.risk_score == 0


def test_multiple_findings_accumulate_correctly():
    # DSA + no expiry + far-future expiry (using no expiry) = ASY-003 + ASY-007
    key = _dsa(expiry_date=None)
    r = analyze(key, reference_date=REFERENCE_DATE)
    check_ids = {f.check_id for f in r.findings}
    assert "ASY-003" in check_ids
    assert "ASY-007" in check_ids
    assert r.risk_score == 40  # 25 + 15


def test_asy005_and_asy007_coexist():
    key = _ec(curve_name="secp256r1", expiry_date=None)
    r = analyze(key, min_security_bits=256, reference_date=REFERENCE_DATE)
    assert _has(r, "ASY-005")
    assert _has(r, "ASY-007")
    assert r.risk_score == 30  # 15 + 15


def test_to_dict_round_trip_key_id():
    key = _rsa(key_id="rt-key")
    r = analyze(key, reference_date=REFERENCE_DATE)
    assert r.to_dict()["key_id"] == "rt-key"


def test_analyze_many_all_strong():
    keys = [
        _rsa(key_id="k1", key_size_bits=4096),
        _ed25519(key_id="k2"),
        _ec(key_id="k3", curve_name="secp521r1"),
    ]
    results = analyze_many(keys, reference_date=REFERENCE_DATE)
    assert all(r.risk_score == 0 for r in results)
    assert all(r.security_level == "STRONG" for r in results)

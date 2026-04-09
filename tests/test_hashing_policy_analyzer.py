# test_hashing_policy_analyzer.py — Cyber Port / CryptoLogik
#
# Copyright (c) 2026 hiagokinlevi (github.com/hiagokinlevi)
# Licensed under CC BY 4.0  https://creativecommons.org/licenses/by/4.0/
#
# pytest-compatible test suite for hashing_policy_analyzer.
# Run with:  python -m pytest tests/test_hashing_policy_analyzer.py -q
#
# No mocking — all tests use pure data inputs.

import sys
import os

# Allow import from the crypto package without installing the project.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto.hashing_policy_analyzer import (
    HashingConfig,
    HASHFinding,
    HASHResult,
    analyze,
    analyze_many,
    _CHECK_WEIGHTS,
    _BROKEN_ALGORITHMS,
    _FAST_ALGORITHMS,
    _PASSWORD_KDFS,
    _SECURITY_PURPOSES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_config(
    config_id: str = "cfg-test",
    algorithm: str = "sha256",
    purpose: str = "integrity",
    output_bits=None,
    salt_length_bytes=None,
    iterations=None,
    description: str = "test config",
) -> HashingConfig:
    """Convenience factory for HashingConfig instances."""
    return HashingConfig(
        config_id=config_id,
        algorithm=algorithm,
        purpose=purpose,
        output_bits=output_bits,
        salt_length_bytes=salt_length_bytes,
        iterations=iterations,
        description=description,
    )


def finding_ids(result: HASHResult):
    """Return sorted list of check IDs from a result's findings."""
    return sorted(f.check_id for f in result.findings)


# ===========================================================================
# Module constants sanity checks
# ===========================================================================


class TestConstants:
    def test_check_weights_has_all_seven_checks(self):
        expected = {"HASH-001", "HASH-002", "HASH-003", "HASH-004",
                    "HASH-005", "HASH-006", "HASH-007"}
        assert set(_CHECK_WEIGHTS.keys()) == expected

    def test_hash001_weight_is_45(self):
        assert _CHECK_WEIGHTS["HASH-001"] == 45

    def test_hash002_weight_is_25(self):
        assert _CHECK_WEIGHTS["HASH-002"] == 25

    def test_hash003_weight_is_25(self):
        assert _CHECK_WEIGHTS["HASH-003"] == 25

    def test_hash004_weight_is_45(self):
        assert _CHECK_WEIGHTS["HASH-004"] == 45

    def test_hash005_weight_is_25(self):
        assert _CHECK_WEIGHTS["HASH-005"] == 25

    def test_hash006_weight_is_25(self):
        assert _CHECK_WEIGHTS["HASH-006"] == 25

    def test_hash007_weight_is_15(self):
        assert _CHECK_WEIGHTS["HASH-007"] == 15

    def test_broken_algorithms_contains_md5(self):
        assert "md5" in _BROKEN_ALGORITHMS

    def test_broken_algorithms_contains_sha1(self):
        assert "sha1" in _BROKEN_ALGORITHMS

    def test_password_kdfs_contains_bcrypt(self):
        assert "bcrypt" in _PASSWORD_KDFS

    def test_password_kdfs_contains_argon2id(self):
        assert "argon2id" in _PASSWORD_KDFS

    def test_security_purposes_contains_password(self):
        assert "password" in _SECURITY_PURPOSES

    def test_security_purposes_contains_signing(self):
        assert "signing" in _SECURITY_PURPOSES


# ===========================================================================
# HASH-001: MD5 / MD4 / MD2 for security-relevant purpose
# ===========================================================================


class TestHash001:
    # --- should fire ---

    def test_md5_password_fires(self):
        cfg = make_config(algorithm="md5", purpose="password")
        result = analyze(cfg)
        assert "HASH-001" in finding_ids(result)

    def test_md5_integrity_fires(self):
        cfg = make_config(algorithm="md5", purpose="integrity")
        result = analyze(cfg)
        assert "HASH-001" in finding_ids(result)

    def test_md5_signing_fires(self):
        cfg = make_config(algorithm="md5", purpose="signing")
        result = analyze(cfg)
        assert "HASH-001" in finding_ids(result)

    def test_md5_token_fires(self):
        cfg = make_config(algorithm="md5", purpose="token")
        result = analyze(cfg)
        assert "HASH-001" in finding_ids(result)

    def test_md5_hmac_fires(self):
        cfg = make_config(algorithm="md5", purpose="hmac")
        result = analyze(cfg)
        assert "HASH-001" in finding_ids(result)

    def test_md4_integrity_fires(self):
        cfg = make_config(algorithm="md4", purpose="integrity")
        result = analyze(cfg)
        assert "HASH-001" in finding_ids(result)

    def test_md2_integrity_fires(self):
        cfg = make_config(algorithm="md2", purpose="integrity")
        result = analyze(cfg)
        assert "HASH-001" in finding_ids(result)

    def test_md5_uppercase_normalised_fires(self):
        cfg = make_config(algorithm="MD5", purpose="integrity")
        result = analyze(cfg)
        assert "HASH-001" in finding_ids(result)

    def test_md5_mixed_case_normalised_fires(self):
        cfg = make_config(algorithm="Md5", purpose="signing")
        result = analyze(cfg)
        assert "HASH-001" in finding_ids(result)

    def test_hash001_finding_is_critical(self):
        cfg = make_config(algorithm="md5", purpose="integrity")
        result = analyze(cfg)
        h1 = next(f for f in result.findings if f.check_id == "HASH-001")
        assert h1.severity == "CRITICAL"

    def test_hash001_weight_on_finding(self):
        cfg = make_config(algorithm="md5", purpose="integrity")
        result = analyze(cfg)
        h1 = next(f for f in result.findings if f.check_id == "HASH-001")
        assert h1.weight == 45

    # --- should NOT fire ---

    def test_md5_general_does_not_fire(self):
        # "general" is not a security-relevant purpose for HASH-001.
        cfg = make_config(algorithm="md5", purpose="general")
        result = analyze(cfg)
        assert "HASH-001" not in finding_ids(result)

    def test_sha256_integrity_no_hash001(self):
        cfg = make_config(algorithm="sha256", purpose="integrity")
        result = analyze(cfg)
        assert "HASH-001" not in finding_ids(result)

    def test_bcrypt_password_no_hash001(self):
        cfg = make_config(algorithm="bcrypt", purpose="password", salt_length_bytes=None)
        result = analyze(cfg)
        assert "HASH-001" not in finding_ids(result)


# ===========================================================================
# HASH-002: SHA-1 for signing / integrity / token / hmac
# ===========================================================================


class TestHash002:
    # --- should fire ---

    def test_sha1_signing_fires(self):
        cfg = make_config(algorithm="sha1", purpose="signing")
        result = analyze(cfg)
        assert "HASH-002" in finding_ids(result)

    def test_sha1_integrity_fires(self):
        cfg = make_config(algorithm="sha1", purpose="integrity")
        result = analyze(cfg)
        assert "HASH-002" in finding_ids(result)

    def test_sha1_token_fires(self):
        cfg = make_config(algorithm="sha1", purpose="token")
        result = analyze(cfg)
        assert "HASH-002" in finding_ids(result)

    def test_sha1_hmac_fires(self):
        cfg = make_config(algorithm="sha1", purpose="hmac")
        result = analyze(cfg)
        assert "HASH-002" in finding_ids(result)

    def test_sha_1_hyphen_signing_fires(self):
        cfg = make_config(algorithm="sha-1", purpose="signing")
        result = analyze(cfg)
        assert "HASH-002" in finding_ids(result)

    def test_sha1_uppercase_normalised_fires(self):
        cfg = make_config(algorithm="SHA1", purpose="integrity")
        result = analyze(cfg)
        assert "HASH-002" in finding_ids(result)

    def test_hash002_finding_is_high(self):
        cfg = make_config(algorithm="sha1", purpose="signing")
        result = analyze(cfg)
        h2 = next(f for f in result.findings if f.check_id == "HASH-002")
        assert h2.severity == "HIGH"

    # --- should NOT fire ---

    def test_sha1_password_no_hash002(self):
        # SHA-1 for passwords is caught by HASH-006 (wrong KDF), not HASH-002.
        cfg = make_config(
            algorithm="sha1",
            purpose="password",
            salt_length_bytes=16,
        )
        result = analyze(cfg)
        assert "HASH-002" not in finding_ids(result)

    def test_sha1_general_no_hash002(self):
        cfg = make_config(algorithm="sha1", purpose="general")
        result = analyze(cfg)
        assert "HASH-002" not in finding_ids(result)

    def test_sha256_signing_no_hash002(self):
        cfg = make_config(algorithm="sha256", purpose="signing")
        result = analyze(cfg)
        assert "HASH-002" not in finding_ids(result)

    def test_sha512_integrity_no_hash002(self):
        cfg = make_config(algorithm="sha512", purpose="integrity")
        result = analyze(cfg)
        assert "HASH-002" not in finding_ids(result)


# ===========================================================================
# HASH-003: Truncated hash output (< 128 effective bits)
# ===========================================================================


class TestHash003:
    # --- should fire ---

    def test_64_bit_output_fires(self):
        cfg = make_config(output_bits=64)
        result = analyze(cfg)
        assert "HASH-003" in finding_ids(result)

    def test_127_bit_output_fires(self):
        cfg = make_config(output_bits=127)
        result = analyze(cfg)
        assert "HASH-003" in finding_ids(result)

    def test_32_bit_output_fires(self):
        cfg = make_config(output_bits=32)
        result = analyze(cfg)
        assert "HASH-003" in finding_ids(result)

    def test_1_bit_output_fires(self):
        cfg = make_config(output_bits=1)
        result = analyze(cfg)
        assert "HASH-003" in finding_ids(result)

    def test_truncated_sha256_to_64_bits_fires(self):
        # First 8 hex chars of SHA-256 = 32 bits; also test 64 bits.
        cfg = make_config(algorithm="sha256", purpose="integrity", output_bits=64)
        result = analyze(cfg)
        assert "HASH-003" in finding_ids(result)

    def test_hash003_finding_is_high(self):
        cfg = make_config(output_bits=64)
        result = analyze(cfg)
        h3 = next(f for f in result.findings if f.check_id == "HASH-003")
        assert h3.severity == "HIGH"

    # --- should NOT fire ---

    def test_128_bit_output_no_fire(self):
        cfg = make_config(output_bits=128)
        result = analyze(cfg)
        assert "HASH-003" not in finding_ids(result)

    def test_256_bit_output_no_fire(self):
        cfg = make_config(output_bits=256)
        result = analyze(cfg)
        assert "HASH-003" not in finding_ids(result)

    def test_none_output_bits_no_fire(self):
        cfg = make_config(output_bits=None)
        result = analyze(cfg)
        assert "HASH-003" not in finding_ids(result)

    def test_512_bit_output_no_fire(self):
        cfg = make_config(algorithm="sha512", purpose="integrity", output_bits=512)
        result = analyze(cfg)
        assert "HASH-003" not in finding_ids(result)


# ===========================================================================
# HASH-004: Password hash stored without salt
# ===========================================================================


class TestHash004:
    # --- should fire ---

    def test_password_salt_none_fires(self):
        cfg = make_config(
            algorithm="pbkdf2",
            purpose="password",
            salt_length_bytes=None,
            iterations=100000,
        )
        result = analyze(cfg)
        assert "HASH-004" in finding_ids(result)

    def test_password_salt_zero_fires(self):
        cfg = make_config(
            algorithm="pbkdf2",
            purpose="password",
            salt_length_bytes=0,
            iterations=100000,
        )
        result = analyze(cfg)
        assert "HASH-004" in finding_ids(result)

    def test_argon2_no_salt_fires(self):
        # argon2 (non-bcrypt KDF) without salt should still fire.
        cfg = make_config(
            algorithm="argon2id",
            purpose="password",
            salt_length_bytes=0,
            iterations=3,
        )
        result = analyze(cfg)
        assert "HASH-004" in finding_ids(result)

    def test_scrypt_salt_none_fires(self):
        cfg = make_config(
            algorithm="scrypt",
            purpose="password",
            salt_length_bytes=None,
        )
        result = analyze(cfg)
        assert "HASH-004" in finding_ids(result)

    def test_hash004_finding_is_critical(self):
        cfg = make_config(
            algorithm="pbkdf2",
            purpose="password",
            salt_length_bytes=0,
        )
        result = analyze(cfg)
        h4 = next(f for f in result.findings if f.check_id == "HASH-004")
        assert h4.severity == "CRITICAL"

    # --- should NOT fire ---

    def test_bcrypt_password_no_salt_no_hash004(self):
        # bcrypt manages salt internally; HASH-004 must not fire.
        cfg = make_config(
            algorithm="bcrypt",
            purpose="password",
            salt_length_bytes=None,
        )
        result = analyze(cfg)
        assert "HASH-004" not in finding_ids(result)

    def test_bcrypt_salt_zero_no_hash004(self):
        # Even if caller passes salt_length_bytes=0 for bcrypt, skip HASH-004.
        cfg = make_config(
            algorithm="bcrypt",
            purpose="password",
            salt_length_bytes=0,
        )
        result = analyze(cfg)
        assert "HASH-004" not in finding_ids(result)

    def test_integrity_no_salt_no_hash004(self):
        # HASH-004 is only for password purpose.
        cfg = make_config(algorithm="sha256", purpose="integrity", salt_length_bytes=None)
        result = analyze(cfg)
        assert "HASH-004" not in finding_ids(result)

    def test_password_with_adequate_salt_no_hash004(self):
        cfg = make_config(
            algorithm="pbkdf2",
            purpose="password",
            salt_length_bytes=16,
            iterations=100000,
        )
        result = analyze(cfg)
        assert "HASH-004" not in finding_ids(result)


# ===========================================================================
# HASH-005: Password salt present but < 16 bytes
# ===========================================================================


class TestHash005:
    # --- should fire ---

    def test_salt_8_bytes_fires(self):
        cfg = make_config(
            algorithm="pbkdf2",
            purpose="password",
            salt_length_bytes=8,
            iterations=100000,
        )
        result = analyze(cfg)
        assert "HASH-005" in finding_ids(result)

    def test_salt_1_byte_fires(self):
        cfg = make_config(
            algorithm="pbkdf2",
            purpose="password",
            salt_length_bytes=1,
        )
        result = analyze(cfg)
        assert "HASH-005" in finding_ids(result)

    def test_salt_15_bytes_fires(self):
        cfg = make_config(
            algorithm="argon2id",
            purpose="password",
            salt_length_bytes=15,
        )
        result = analyze(cfg)
        assert "HASH-005" in finding_ids(result)

    def test_hash005_finding_is_high(self):
        cfg = make_config(
            algorithm="pbkdf2",
            purpose="password",
            salt_length_bytes=8,
        )
        result = analyze(cfg)
        h5 = next(f for f in result.findings if f.check_id == "HASH-005")
        assert h5.severity == "HIGH"

    # --- should NOT fire ---

    def test_salt_exactly_16_bytes_no_fire(self):
        cfg = make_config(
            algorithm="pbkdf2",
            purpose="password",
            salt_length_bytes=16,
        )
        result = analyze(cfg)
        assert "HASH-005" not in finding_ids(result)

    def test_salt_32_bytes_no_fire(self):
        cfg = make_config(
            algorithm="argon2id",
            purpose="password",
            salt_length_bytes=32,
        )
        result = analyze(cfg)
        assert "HASH-005" not in finding_ids(result)

    def test_bcrypt_short_salt_no_hash005(self):
        # bcrypt manages salt internally; HASH-005 must not fire.
        cfg = make_config(
            algorithm="bcrypt",
            purpose="password",
            salt_length_bytes=4,
        )
        result = analyze(cfg)
        assert "HASH-005" not in finding_ids(result)

    def test_bcrypt_no_salt_no_hash005(self):
        cfg = make_config(
            algorithm="bcrypt",
            purpose="password",
            salt_length_bytes=None,
        )
        result = analyze(cfg)
        assert "HASH-005" not in finding_ids(result)

    def test_integrity_short_salt_no_hash005(self):
        # HASH-005 only applies to password purpose.
        cfg = make_config(algorithm="sha256", purpose="integrity", salt_length_bytes=4)
        result = analyze(cfg)
        assert "HASH-005" not in finding_ids(result)

    def test_salt_zero_no_hash005_hash004_instead(self):
        # salt_length_bytes=0 triggers HASH-004, not HASH-005.
        cfg = make_config(
            algorithm="pbkdf2",
            purpose="password",
            salt_length_bytes=0,
        )
        result = analyze(cfg)
        assert "HASH-004" in finding_ids(result)
        assert "HASH-005" not in finding_ids(result)


# ===========================================================================
# HASH-006: General-purpose hash used for password storage
# ===========================================================================


class TestHash006:
    # --- should fire ---

    def test_sha256_password_fires(self):
        cfg = make_config(
            algorithm="sha256",
            purpose="password",
            salt_length_bytes=16,
        )
        result = analyze(cfg)
        assert "HASH-006" in finding_ids(result)

    def test_sha512_password_fires(self):
        cfg = make_config(
            algorithm="sha512",
            purpose="password",
            salt_length_bytes=16,
        )
        result = analyze(cfg)
        assert "HASH-006" in finding_ids(result)

    def test_sha1_password_fires(self):
        cfg = make_config(
            algorithm="sha1",
            purpose="password",
            salt_length_bytes=16,
        )
        result = analyze(cfg)
        assert "HASH-006" in finding_ids(result)

    def test_md5_password_fires_hash006(self):
        # md5 for passwords fires both HASH-001 and HASH-006.
        cfg = make_config(
            algorithm="md5",
            purpose="password",
            salt_length_bytes=16,
        )
        result = analyze(cfg)
        assert "HASH-006" in finding_ids(result)

    def test_blake2b_password_fires(self):
        cfg = make_config(
            algorithm="blake2b",
            purpose="password",
            salt_length_bytes=16,
        )
        result = analyze(cfg)
        assert "HASH-006" in finding_ids(result)

    def test_sha3_256_password_fires(self):
        cfg = make_config(
            algorithm="sha3-256",
            purpose="password",
            salt_length_bytes=16,
        )
        result = analyze(cfg)
        assert "HASH-006" in finding_ids(result)

    def test_hash006_finding_is_high(self):
        cfg = make_config(
            algorithm="sha256",
            purpose="password",
            salt_length_bytes=16,
        )
        result = analyze(cfg)
        h6 = next(f for f in result.findings if f.check_id == "HASH-006")
        assert h6.severity == "HIGH"

    # --- should NOT fire ---

    def test_bcrypt_password_no_hash006(self):
        cfg = make_config(
            algorithm="bcrypt",
            purpose="password",
            salt_length_bytes=None,
        )
        result = analyze(cfg)
        assert "HASH-006" not in finding_ids(result)

    def test_argon2id_password_no_hash006(self):
        cfg = make_config(
            algorithm="argon2id",
            purpose="password",
            salt_length_bytes=16,
            iterations=3,
        )
        result = analyze(cfg)
        assert "HASH-006" not in finding_ids(result)

    def test_scrypt_password_no_hash006(self):
        cfg = make_config(
            algorithm="scrypt",
            purpose="password",
            salt_length_bytes=16,
        )
        result = analyze(cfg)
        assert "HASH-006" not in finding_ids(result)

    def test_pbkdf2_password_no_hash006(self):
        cfg = make_config(
            algorithm="pbkdf2",
            purpose="password",
            salt_length_bytes=16,
            iterations=100000,
        )
        result = analyze(cfg)
        assert "HASH-006" not in finding_ids(result)

    def test_sha256_integrity_no_hash006(self):
        # SHA-256 for integrity is fine — HASH-006 only targets password purpose.
        cfg = make_config(algorithm="sha256", purpose="integrity")
        result = analyze(cfg)
        assert "HASH-006" not in finding_ids(result)

    def test_sha512_signing_no_hash006(self):
        cfg = make_config(algorithm="sha512", purpose="signing")
        result = analyze(cfg)
        assert "HASH-006" not in finding_ids(result)


# ===========================================================================
# HASH-007: Algorithm reuse across security contexts
# ===========================================================================


class TestHash007:
    def _two_configs(
        self,
        algo1: str = "sha256",
        purpose1: str = "integrity",
        output_bits1=None,
        iterations1=None,
        algo2: str = "sha256",
        purpose2: str = "password",
        output_bits2=None,
        iterations2=None,
    ):
        c1 = make_config("cfg-A", algo1, purpose1, output_bits1, None, iterations1)
        c2 = make_config("cfg-B", algo2, purpose2, output_bits2, 16, iterations2)
        return c1, c2

    # --- should fire ---

    def test_sha256_integrity_vs_password_fires(self):
        c1, c2 = self._two_configs(
            algo1="sha256", purpose1="integrity",
            algo2="sha256", purpose2="password",
        )
        results = analyze_many([c1, c2])
        assert "HASH-007" in finding_ids(results[0]) or "HASH-007" in finding_ids(results[1])

    def test_hmac_sha256_vs_token_sha256_fires(self):
        c1 = make_config("cfg-A", "sha256", "hmac", None, None, None)
        c2 = make_config("cfg-B", "sha256", "token", None, None, None)
        results = analyze_many([c1, c2])
        all_ids = finding_ids(results[0]) + finding_ids(results[1])
        assert "HASH-007" in all_ids

    def test_hash007_finding_is_medium(self):
        c1 = make_config("cfg-A", "sha256", "integrity", None, None, None)
        c2 = make_config("cfg-B", "sha256", "signing", None, None, None)
        results = analyze_many([c1, c2])
        combined = results[0].findings + results[1].findings
        h7_findings = [f for f in combined if f.check_id == "HASH-007"]
        assert h7_findings
        assert all(f.severity == "MEDIUM" for f in h7_findings)

    def test_hash007_weight_is_15(self):
        c1 = make_config("cfg-A", "sha256", "integrity", None, None, None)
        c2 = make_config("cfg-B", "sha256", "signing", None, None, None)
        results = analyze_many([c1, c2])
        combined = results[0].findings + results[1].findings
        h7 = next(f for f in combined if f.check_id == "HASH-007")
        assert h7.weight == 15

    # --- should NOT fire ---

    def test_different_algorithms_no_hash007(self):
        c1 = make_config("cfg-A", "sha256", "integrity")
        c2 = make_config("cfg-B", "sha512", "password", salt_length_bytes=16)
        results = analyze_many([c1, c2])
        assert "HASH-007" not in finding_ids(results[0])
        assert "HASH-007" not in finding_ids(results[1])

    def test_same_algorithm_same_purpose_no_hash007(self):
        c1 = make_config("cfg-A", "sha256", "integrity")
        c2 = make_config("cfg-B", "sha256", "integrity")
        results = analyze_many([c1, c2])
        assert "HASH-007" not in finding_ids(results[0])
        assert "HASH-007" not in finding_ids(results[1])

    def test_same_algorithm_different_output_bits_no_hash007(self):
        # Different output_bits means different effective configuration — no reuse.
        c1 = make_config("cfg-A", "sha256", "integrity", output_bits=256)
        c2 = make_config("cfg-B", "sha256", "signing", output_bits=128)
        results = analyze_many([c1, c2])
        assert "HASH-007" not in finding_ids(results[0])
        assert "HASH-007" not in finding_ids(results[1])

    def test_same_algorithm_different_iterations_no_hash007(self):
        c1 = make_config("cfg-A", "pbkdf2", "password", None, 16, 100000)
        c2 = make_config("cfg-B", "pbkdf2", "token",    None, None, 50000)
        results = analyze_many([c1, c2])
        assert "HASH-007" not in finding_ids(results[0])
        assert "HASH-007" not in finding_ids(results[1])

    def test_no_all_configs_no_hash007(self):
        cfg = make_config("cfg-A", "sha256", "integrity")
        result = analyze(cfg, all_configs=None)
        assert "HASH-007" not in finding_ids(result)

    def test_single_config_list_no_hash007(self):
        cfg = make_config("cfg-A", "sha256", "integrity")
        results = analyze_many([cfg])
        assert "HASH-007" not in finding_ids(results[0])


# ===========================================================================
# Risk score and compliance logic
# ===========================================================================


class TestRiskScore:
    def test_compliant_config_score_zero(self):
        cfg = make_config(
            algorithm="argon2id",
            purpose="password",
            output_bits=None,
            salt_length_bytes=16,
            iterations=3,
        )
        result = analyze(cfg)
        assert result.risk_score == 0
        assert result.compliant is True

    def test_md5_integrity_score_is_45(self):
        cfg = make_config(algorithm="md5", purpose="integrity")
        result = analyze(cfg)
        # Only HASH-001 fires (weight 45).
        assert result.risk_score == 45

    def test_sha1_signing_score_is_25(self):
        # HASH-002 only (weight 25).
        cfg = make_config(algorithm="sha1", purpose="signing")
        result = analyze(cfg)
        assert result.risk_score == 25

    def test_risk_score_capped_at_100(self):
        # Fire HASH-001 (45) + HASH-004 (45) + HASH-006 (25) = 115 → capped at 100.
        cfg = make_config(
            algorithm="md5",
            purpose="password",
            salt_length_bytes=0,
        )
        result = analyze(cfg)
        assert result.risk_score == 100

    def test_unique_check_ids_not_double_counted(self):
        # Ensure the same check ID weight is only counted once.
        cfg = make_config(algorithm="md5", purpose="integrity")
        result = analyze(cfg)
        fired = [f.check_id for f in result.findings]
        assert len(fired) == len(set(fired)), "Duplicate check IDs found"

    def test_non_compliant_flag(self):
        cfg = make_config(algorithm="sha1", purpose="integrity")
        result = analyze(cfg)
        assert result.compliant is False

    def test_bcrypt_with_good_config_compliant(self):
        cfg = make_config(
            algorithm="bcrypt",
            purpose="password",
            salt_length_bytes=None,
            iterations=12,
        )
        result = analyze(cfg)
        assert result.compliant is True
        assert result.risk_score == 0


# ===========================================================================
# HASHResult helper methods
# ===========================================================================


class TestHASHResultHelpers:
    def test_to_dict_keys_present(self):
        cfg = make_config(algorithm="md5", purpose="integrity")
        result = analyze(cfg)
        d = result.to_dict()
        assert "config_id" in d
        assert "algorithm" in d
        assert "purpose" in d
        assert "risk_score" in d
        assert "compliant" in d
        assert "findings" in d

    def test_to_dict_findings_is_list(self):
        cfg = make_config(algorithm="md5", purpose="integrity")
        result = analyze(cfg)
        d = result.to_dict()
        assert isinstance(d["findings"], list)

    def test_to_dict_finding_keys(self):
        cfg = make_config(algorithm="md5", purpose="integrity")
        result = analyze(cfg)
        d = result.to_dict()
        finding = d["findings"][0]
        assert "check_id" in finding
        assert "severity" in finding
        assert "title" in finding
        assert "detail" in finding
        assert "weight" in finding

    def test_summary_no_findings(self):
        cfg = make_config(
            algorithm="argon2id",
            purpose="password",
            salt_length_bytes=16,
            iterations=3,
        )
        result = analyze(cfg)
        s = result.summary()
        assert "no findings" in s.lower()

    def test_summary_contains_config_id(self):
        cfg = make_config(config_id="my-special-cfg", algorithm="md5", purpose="integrity")
        result = analyze(cfg)
        assert "my-special-cfg" in result.summary()

    def test_summary_contains_check_id(self):
        cfg = make_config(algorithm="md5", purpose="integrity")
        result = analyze(cfg)
        assert "HASH-001" in result.summary()

    def test_by_severity_groups_correctly(self):
        # sha1 for integrity → HASH-002 HIGH
        cfg = make_config(algorithm="sha1", purpose="integrity")
        result = analyze(cfg)
        groups = result.by_severity()
        assert "HIGH" in groups
        assert all(f.severity == "HIGH" for f in groups["HIGH"])

    def test_by_severity_critical_bucket(self):
        cfg = make_config(algorithm="md5", purpose="integrity")
        result = analyze(cfg)
        groups = result.by_severity()
        assert "CRITICAL" in groups

    def test_by_severity_empty_when_compliant(self):
        cfg = make_config(
            algorithm="argon2id",
            purpose="password",
            salt_length_bytes=16,
            iterations=3,
        )
        result = analyze(cfg)
        groups = result.by_severity()
        assert groups == {}


# ===========================================================================
# analyze_many integration
# ===========================================================================


class TestAnalyzeMany:
    def test_returns_list_same_length(self):
        configs = [
            make_config("c1", "sha256", "integrity"),
            make_config("c2", "argon2id", "password", salt_length_bytes=16, iterations=3),
            make_config("c3", "bcrypt", "password"),
        ]
        results = analyze_many(configs)
        assert len(results) == 3

    def test_order_preserved(self):
        configs = [
            make_config("alpha", "sha256", "integrity"),
            make_config("beta", "md5", "password", salt_length_bytes=0),
        ]
        results = analyze_many(configs)
        assert results[0].config_id == "alpha"
        assert results[1].config_id == "beta"

    def test_empty_list_returns_empty(self):
        results = analyze_many([])
        assert results == []

    def test_all_compliant_with_good_configs(self):
        configs = [
            make_config("c1", "sha256", "integrity"),
            make_config("c2", "argon2id", "password", salt_length_bytes=16, iterations=3),
        ]
        results = analyze_many(configs)
        # c1: SHA-256 for integrity — no findings
        assert results[0].compliant is True
        # c2: argon2id with good salt — no findings
        assert results[1].compliant is True

    def test_hash007_detected_across_configs(self):
        configs = [
            make_config("c1", "sha256", "integrity"),
            make_config("c2", "sha256", "signing"),
        ]
        results = analyze_many(configs)
        all_ids = finding_ids(results[0]) + finding_ids(results[1])
        assert "HASH-007" in all_ids


# ===========================================================================
# Edge cases and combined / multi-check scenarios
# ===========================================================================


class TestEdgeCases:
    def test_md5_password_no_salt_multiple_checks(self):
        # MD5 + password + no salt should fire HASH-001, HASH-004, HASH-006.
        cfg = make_config(
            algorithm="md5",
            purpose="password",
            salt_length_bytes=0,
        )
        result = analyze(cfg)
        ids = finding_ids(result)
        assert "HASH-001" in ids
        assert "HASH-004" in ids
        assert "HASH-006" in ids

    def test_sha256_password_short_salt_fires_005_and_006(self):
        cfg = make_config(
            algorithm="sha256",
            purpose="password",
            salt_length_bytes=8,
        )
        result = analyze(cfg)
        ids = finding_ids(result)
        assert "HASH-005" in ids
        assert "HASH-006" in ids

    def test_sha1_password_fires_006_not_002(self):
        cfg = make_config(
            algorithm="sha1",
            purpose="password",
            salt_length_bytes=16,
        )
        result = analyze(cfg)
        ids = finding_ids(result)
        assert "HASH-006" in ids
        assert "HASH-002" not in ids

    def test_bcrypt_password_completely_clean(self):
        cfg = make_config(
            algorithm="bcrypt",
            purpose="password",
            salt_length_bytes=None,
            iterations=12,
        )
        result = analyze(cfg)
        assert result.findings == []
        assert result.compliant is True
        assert result.risk_score == 0

    def test_argon2_password_no_salt_fires_hash004_not_hash005(self):
        # salt_length_bytes=None means not provided — fires HASH-004 only.
        cfg = make_config(
            algorithm="argon2id",
            purpose="password",
            salt_length_bytes=None,
            iterations=3,
        )
        result = analyze(cfg)
        ids = finding_ids(result)
        assert "HASH-004" in ids
        assert "HASH-005" not in ids

    def test_sha256_for_integrity_is_clean(self):
        # SHA-256 for integrity should have no findings.
        cfg = make_config(algorithm="sha256", purpose="integrity")
        result = analyze(cfg)
        assert result.compliant is True
        assert result.risk_score == 0

    def test_pbkdf2_good_config_is_clean(self):
        cfg = make_config(
            algorithm="pbkdf2",
            purpose="password",
            salt_length_bytes=32,
            iterations=260000,
        )
        result = analyze(cfg)
        assert result.compliant is True

    def test_general_purpose_sha256_no_findings(self):
        # "general" is not a security purpose; no checks should fire.
        cfg = make_config(algorithm="sha256", purpose="general")
        result = analyze(cfg)
        assert result.compliant is True

    def test_md5_general_purpose_no_findings(self):
        # MD5 for a non-security purpose should not fire HASH-001.
        cfg = make_config(algorithm="md5", purpose="general")
        result = analyze(cfg)
        assert "HASH-001" not in finding_ids(result)

    def test_truncated_hash_combined_with_sha1_integrity(self):
        # SHA-1 for integrity + truncated output → HASH-002 + HASH-003.
        cfg = make_config(algorithm="sha1", purpose="integrity", output_bits=80)
        result = analyze(cfg)
        ids = finding_ids(result)
        assert "HASH-002" in ids
        assert "HASH-003" in ids

    def test_result_algorithm_preserves_original_case(self):
        # The result should store the original algorithm string, not the normalised one.
        cfg = make_config(algorithm="SHA256", purpose="integrity")
        result = analyze(cfg)
        assert result.algorithm == "SHA256"

    def test_result_purpose_preserved(self):
        cfg = make_config(algorithm="sha256", purpose="integrity")
        result = analyze(cfg)
        assert result.purpose == "integrity"

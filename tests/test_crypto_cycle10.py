"""
Tests for Cycle 10 cryptologik additions:
  - crypto/key_management/rotation_advisor.py
  - crypto/validators/jwt_checker.py
"""
from __future__ import annotations

import base64
import json
import sys
import time
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from crypto.key_management.rotation_advisor import (
    KeyDescriptor,
    RotationAdvisor,
    RotationFinding,
    RotationReport,
    _MAX_AGE_DAYS,
    _age_days,
    _parse_date,
    _today,
    advise_rotation,
)
from crypto.validators.jwt_checker import (
    JwtConfig,
    JwtFinding,
    JwtSecurityReport,
    _b64_decode_part,
    _decode_jwt_parts,
    check_jwt_config,
    check_jwt_token,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _past(days: int) -> str:
    """Return an ISO date string `days` ago."""
    return (date.today() - timedelta(days=days)).isoformat()


def _future(days: int) -> str:
    """Return an ISO date string `days` from now."""
    return (date.today() + timedelta(days=days)).isoformat()


def _jwt_encode(header: dict, payload: dict) -> str:
    """Build a JWT string without signature (for testing structural checks)."""
    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64(header)}.{b64(payload)}."


# ===========================================================================
# KeyDescriptor
# ===========================================================================

class TestKeyDescriptor:
    def test_normalized_type_rsa_with_size(self):
        k = KeyDescriptor(key_id="k", key_type="RSA", key_size=2048)
        assert k.normalized_type() == "rsa-2048"

    def test_normalized_type_lowercase(self):
        k = KeyDescriptor(key_id="k", key_type="AES", key_size=256)
        assert k.normalized_type() == "aes-256"

    def test_max_age_rsa2048(self):
        k = KeyDescriptor(key_id="k", key_type="RSA", key_size=2048)
        assert k.max_age_days() == _MAX_AGE_DAYS["rsa-2048"]

    def test_max_age_api_key(self):
        k = KeyDescriptor(key_id="k", key_type="api_key")
        assert k.max_age_days() == 90

    def test_max_age_none_for_unknown(self):
        k = KeyDescriptor(key_id="k", key_type="QUANTUM-KEY-9000")
        assert k.max_age_days() is None


# ===========================================================================
# ROT-001: Hard expiry
# ===========================================================================

class TestRot001HardExpiry:
    def test_expired_key_flagged(self):
        key = KeyDescriptor(
            key_id="old-key", key_type="RSA", key_size=2048,
            expiry_date=_past(5),
        )
        report = advise_rotation([key])
        findings = [f for f in report.findings if f.rule_id == "ROT-001"]
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_future_expiry_not_flagged_by_rot001(self):
        key = KeyDescriptor(
            key_id="valid-key", key_type="RSA", key_size=2048,
            expiry_date=_future(90),
        )
        report = advise_rotation([key])
        rot001 = [f for f in report.findings if f.rule_id == "ROT-001"]
        assert len(rot001) == 0

    def test_no_expiry_not_flagged(self):
        key = KeyDescriptor(key_id="k", key_type="RSA", key_size=2048)
        report = advise_rotation([key])
        rot001 = [f for f in report.findings if f.rule_id == "ROT-001"]
        assert len(rot001) == 0


# ===========================================================================
# ROT-002: Max age
# ===========================================================================

class TestRot002MaxAge:
    def test_old_api_key_flagged(self):
        # api_key max = 90 days, this one is 200 days old
        key = KeyDescriptor(
            key_id="old-api", key_type="api_key",
            created_date=_past(200),
        )
        report = advise_rotation([key])
        rot002 = [f for f in report.findings if f.rule_id == "ROT-002"]
        assert len(rot002) == 1
        assert rot002[0].severity == "high"

    def test_fresh_key_not_flagged(self):
        key = KeyDescriptor(
            key_id="fresh", key_type="api_key",
            created_date=_past(10),
        )
        report = advise_rotation([key])
        rot002 = [f for f in report.findings if f.rule_id == "ROT-002"]
        assert len(rot002) == 0

    def test_unknown_type_not_flagged_for_age(self):
        # Unknown type → no max_age → no ROT-002
        key = KeyDescriptor(
            key_id="k", key_type="QUANTUM-KEY-9000",
            created_date=_past(9999),
        )
        report = advise_rotation([key])
        rot002 = [f for f in report.findings if f.rule_id == "ROT-002"]
        assert len(rot002) == 0


# ===========================================================================
# ROT-003: Cert expiry warning
# ===========================================================================

class TestRot003CertExpiry:
    def test_expiry_in_7_days_is_critical(self):
        key = KeyDescriptor(
            key_id="cert", key_type="tls",
            expiry_date=_future(5),
        )
        report = advise_rotation([key])
        rot003 = [f for f in report.findings if f.rule_id == "ROT-003"]
        assert len(rot003) == 1
        assert rot003[0].severity == "critical"

    def test_expiry_in_20_days_is_high(self):
        key = KeyDescriptor(
            key_id="cert", key_type="tls",
            expiry_date=_future(20),
        )
        report = advise_rotation([key])
        rot003 = [f for f in report.findings if f.rule_id == "ROT-003"]
        assert len(rot003) == 1
        assert rot003[0].severity == "high"

    def test_expiry_in_60_days_not_flagged_by_rot003(self):
        key = KeyDescriptor(
            key_id="cert", key_type="tls",
            expiry_date=_future(60),
        )
        report = advise_rotation([key])
        rot003 = [f for f in report.findings if f.rule_id == "ROT-003"]
        assert len(rot003) == 0


# ===========================================================================
# ROT-004: Warning window
# ===========================================================================

class TestRot004WarningWindow:
    def test_key_in_warning_window_flagged(self):
        # api_key max = 90 days, key is 85 days old → 5 days until max
        key = KeyDescriptor(
            key_id="near-max", key_type="api_key",
            created_date=_past(85),
        )
        report = advise_rotation([key])
        rot004 = [f for f in report.findings if f.rule_id == "ROT-004"]
        assert len(rot004) == 1
        assert rot004[0].severity == "medium"

    def test_key_well_before_max_not_flagged(self):
        key = KeyDescriptor(
            key_id="fresh", key_type="api_key",
            created_date=_past(30),
        )
        report = advise_rotation([key])
        rot004 = [f for f in report.findings if f.rule_id == "ROT-004"]
        assert len(rot004) == 0


# ===========================================================================
# ROT-005: No rotation policy
# ===========================================================================

class TestRot005NoPolicy:
    def test_no_policy_flagged(self):
        key = KeyDescriptor(key_id="k", key_type="AES", key_size=256)
        report = advise_rotation([key])
        rot005 = [f for f in report.findings if f.rule_id == "ROT-005"]
        assert len(rot005) == 1
        assert rot005[0].severity == "medium"

    def test_with_policy_not_flagged(self):
        key = KeyDescriptor(key_id="k", key_type="AES", key_size=256, rotation_policy=365)
        report = advise_rotation([key])
        rot005 = [f for f in report.findings if f.rule_id == "ROT-005"]
        assert len(rot005) == 0


# ===========================================================================
# ROT-006: Unknown created date
# ===========================================================================

class TestRot006UnknownCreated:
    def test_missing_created_date_flagged(self):
        key = KeyDescriptor(key_id="k", key_type="RSA", key_size=2048)
        report = advise_rotation([key])
        rot006 = [f for f in report.findings if f.rule_id == "ROT-006"]
        assert len(rot006) == 1
        assert rot006[0].severity == "low"

    def test_with_created_date_not_flagged(self):
        key = KeyDescriptor(
            key_id="k", key_type="RSA", key_size=2048,
            created_date=_past(10),
        )
        report = advise_rotation([key])
        rot006 = [f for f in report.findings if f.rule_id == "ROT-006"]
        assert len(rot006) == 0


# ===========================================================================
# RotationReport
# ===========================================================================

class TestRotationReport:
    def test_passed_when_no_critical_high(self):
        report = RotationReport()
        report.findings = [RotationFinding("ROT-005", "medium", "k", "AES", "msg", "rem")]
        assert report.passed

    def test_failed_when_high(self):
        report = RotationReport()
        report.findings = [RotationFinding("ROT-002", "high", "k", "AES", "msg", "rem")]
        assert not report.passed

    def test_summary_contains_pass_or_fail(self):
        report = RotationReport(keys_analyzed=2)
        s = report.summary()
        assert "PASS" in s or "FAIL" in s
        assert "2" in s

    def test_findings_for_key(self):
        report = RotationReport()
        report.findings = [
            RotationFinding("ROT-005", "medium", "key-a", "RSA", "m", "r"),
            RotationFinding("ROT-006", "low", "key-b", "RSA", "m", "r"),
        ]
        assert len(report.findings_for_key("key-a")) == 1
        assert len(report.findings_for_key("key-b")) == 1
        assert len(report.findings_for_key("key-c")) == 0

    def test_severity_counts(self):
        report = RotationReport()
        report.findings = [
            RotationFinding("ROT-001", "critical", "k", "AES", "m", "r"),
            RotationFinding("ROT-002", "high", "k", "AES", "m", "r"),
            RotationFinding("ROT-005", "medium", "k", "AES", "m", "r"),
            RotationFinding("ROT-006", "low", "k", "AES", "m", "r"),
        ]
        assert report.critical_count == 1
        assert report.high_count == 1
        assert report.medium_count == 1
        assert report.low_count == 1


# ===========================================================================
# RotationAdvisor
# ===========================================================================

class TestRotationAdvisor:
    def test_add_key_and_advise(self):
        advisor = RotationAdvisor()
        advisor.add_key(KeyDescriptor(key_id="k", key_type="api_key", created_date=_past(200)))
        report = advisor.advise()
        assert report.keys_analyzed == 1

    def test_add_keys_batch(self):
        advisor = RotationAdvisor()
        keys = [
            KeyDescriptor(key_id="k1", key_type="api_key"),
            KeyDescriptor(key_id="k2", key_type="AES", key_size=256),
        ]
        advisor.add_keys(keys)
        report = advisor.advise()
        assert report.keys_analyzed == 2

    def test_clear_removes_keys(self):
        advisor = RotationAdvisor()
        advisor.add_key(KeyDescriptor(key_id="k", key_type="api_key"))
        advisor.clear()
        report = advisor.advise()
        assert report.keys_analyzed == 0


# ===========================================================================
# JwtConfig check
# ===========================================================================

class TestJwtConfigAlgNone:
    def test_alg_none_flagged(self):
        cfg = JwtConfig(algorithm="none", expiry_seconds=3600, service_name="test")
        report = check_jwt_config(cfg)
        jwt001 = report.findings_by_rule("JWT-001")
        assert len(jwt001) == 1
        assert jwt001[0].severity == "critical"

    def test_normal_algorithm_not_flagged(self):
        cfg = JwtConfig(algorithm="RS256", expiry_seconds=3600, secret_length_bits=2048)
        report = check_jwt_config(cfg)
        jwt001 = report.findings_by_rule("JWT-001")
        assert len(jwt001) == 0


class TestJwtConfigHmacSecret:
    def test_short_hmac_secret_flagged(self):
        cfg = JwtConfig(algorithm="HS256", secret_length_bits=128, expiry_seconds=3600)
        report = check_jwt_config(cfg)
        jwt002 = report.findings_by_rule("JWT-002")
        assert len(jwt002) == 1
        assert jwt002[0].severity == "critical"

    def test_adequate_hmac_secret_not_flagged(self):
        cfg = JwtConfig(algorithm="HS256", secret_length_bits=256, expiry_seconds=3600)
        report = check_jwt_config(cfg)
        jwt002 = report.findings_by_rule("JWT-002")
        assert len(jwt002) == 0

    def test_rsa_does_not_trigger_hmac_check(self):
        cfg = JwtConfig(algorithm="RS256", secret_length_bits=128, expiry_seconds=3600)
        report = check_jwt_config(cfg)
        jwt002 = report.findings_by_rule("JWT-002")
        assert len(jwt002) == 0


class TestJwtConfigWeakRsa:
    def test_rsa_1024_flagged(self):
        cfg = JwtConfig(algorithm="RS256", secret_length_bits=1024, expiry_seconds=3600)
        report = check_jwt_config(cfg)
        jwt003 = report.findings_by_rule("JWT-003")
        assert len(jwt003) == 1
        assert jwt003[0].severity == "high"

    def test_rsa_2048_not_flagged(self):
        cfg = JwtConfig(algorithm="RS256", secret_length_bits=2048, expiry_seconds=3600)
        report = check_jwt_config(cfg)
        jwt003 = report.findings_by_rule("JWT-003")
        assert len(jwt003) == 0


class TestJwtConfigMissingExp:
    def test_missing_exp_flagged(self):
        cfg = JwtConfig(algorithm="RS256", secret_length_bits=2048, expiry_seconds=None)
        report = check_jwt_config(cfg)
        jwt004 = report.findings_by_rule("JWT-004")
        assert len(jwt004) == 1
        assert jwt004[0].severity == "high"

    def test_with_expiry_not_flagged(self):
        cfg = JwtConfig(algorithm="RS256", secret_length_bits=2048, expiry_seconds=3600)
        report = check_jwt_config(cfg)
        jwt004 = report.findings_by_rule("JWT-004")
        assert len(jwt004) == 0


class TestJwtConfigMissingTemporalClaims:
    def test_no_nbf_no_iat_flagged(self):
        cfg = JwtConfig(
            algorithm="RS256", expiry_seconds=3600, secret_length_bits=2048,
            require_nbf=False, require_iat=False,
        )
        report = check_jwt_config(cfg)
        jwt005 = report.findings_by_rule("JWT-005")
        assert len(jwt005) == 1

    def test_with_iat_not_flagged(self):
        cfg = JwtConfig(
            algorithm="RS256", expiry_seconds=3600, secret_length_bits=2048,
            require_iat=True,
        )
        report = check_jwt_config(cfg)
        jwt005 = report.findings_by_rule("JWT-005")
        assert len(jwt005) == 0


class TestJwtConfigLongExpiry:
    def test_48h_expiry_flagged(self):
        cfg = JwtConfig(
            algorithm="RS256", expiry_seconds=172800, secret_length_bits=2048,
        )
        report = check_jwt_config(cfg)
        jwt006 = report.findings_by_rule("JWT-006")
        assert len(jwt006) == 1
        assert jwt006[0].severity == "medium"

    def test_1h_expiry_not_flagged(self):
        cfg = JwtConfig(
            algorithm="RS256", expiry_seconds=3600, secret_length_bits=2048,
        )
        report = check_jwt_config(cfg)
        jwt006 = report.findings_by_rule("JWT-006")
        assert len(jwt006) == 0


class TestJwtConfigIssAud:
    def test_no_iss_validation_flagged(self):
        cfg = JwtConfig(algorithm="RS256", expiry_seconds=3600, secret_length_bits=2048,
                        validate_issuer=False)
        report = check_jwt_config(cfg)
        jwt007 = report.findings_by_rule("JWT-007")
        assert len(jwt007) == 1

    def test_no_aud_validation_flagged(self):
        cfg = JwtConfig(algorithm="RS256", expiry_seconds=3600, secret_length_bits=2048,
                        validate_audience=False)
        report = check_jwt_config(cfg)
        jwt008 = report.findings_by_rule("JWT-008")
        assert len(jwt008) == 1


class TestJwtConfigJti:
    def test_no_jti_flagged(self):
        cfg = JwtConfig(algorithm="RS256", expiry_seconds=3600, secret_length_bits=2048,
                        require_jti=False)
        report = check_jwt_config(cfg)
        jwt009 = report.findings_by_rule("JWT-009")
        assert len(jwt009) == 1
        assert jwt009[0].severity == "low"

    def test_jti_required_not_flagged(self):
        cfg = JwtConfig(algorithm="RS256", expiry_seconds=3600, secret_length_bits=2048,
                        require_jti=True)
        report = check_jwt_config(cfg)
        jwt009 = report.findings_by_rule("JWT-009")
        assert len(jwt009) == 0


class TestJwtConfigPassedProperty:
    def test_passed_when_no_critical_high(self):
        cfg = JwtConfig(
            algorithm="RS256", secret_length_bits=2048, expiry_seconds=3600,
            require_iat=True, validate_issuer=True, validate_audience=True,
        )
        report = check_jwt_config(cfg)
        # Only medium/low findings expected
        assert report.passed

    def test_failed_when_critical(self):
        cfg = JwtConfig(algorithm="none")
        report = check_jwt_config(cfg)
        assert not report.passed


# ===========================================================================
# JWT token string checks
# ===========================================================================

class TestB64DecodePart:
    def test_decodes_standard_header(self):
        encoded = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
        result = _b64_decode_part(encoded)
        assert result == {"alg": "RS256"}

    def test_returns_none_for_invalid(self):
        result = _b64_decode_part("!!!invalid!!!")
        assert result is None


class TestDecodeJwtParts:
    def test_decodes_valid_token(self):
        token = _jwt_encode({"alg": "RS256", "typ": "JWT"}, {"sub": "123", "exp": 9999999999})
        header, payload, sig = _decode_jwt_parts(token)
        assert header["alg"] == "RS256"
        assert payload["sub"] == "123"

    def test_returns_none_for_malformed(self):
        header, payload, sig = _decode_jwt_parts("not-a-jwt")
        assert header is None


class TestCheckJwtTokenAlgNone:
    def test_alg_none_token_flagged(self):
        token = _jwt_encode({"alg": "none"}, {"sub": "123"})
        report = check_jwt_token(token)
        jwt001 = report.findings_by_rule("JWT-001")
        assert len(jwt001) == 1
        assert jwt001[0].severity == "critical"


class TestCheckJwtTokenMissingClaims:
    def test_missing_exp_flagged(self):
        token = _jwt_encode({"alg": "RS256"}, {"sub": "123", "iss": "example.com", "aud": "api"})
        report = check_jwt_token(token)
        jwt004 = report.findings_by_rule("JWT-004")
        assert any(f.severity in ("high", "critical") for f in jwt004)

    def test_missing_iat_flagged(self):
        token = _jwt_encode({"alg": "RS256"}, {"sub": "123", "exp": 9999999999})
        report = check_jwt_token(token)
        jwt005 = report.findings_by_rule("JWT-005")
        assert len(jwt005) == 1

    def test_missing_iss_flagged(self):
        token = _jwt_encode({"alg": "RS256"}, {"sub": "123", "exp": 9999999999, "iat": 1000})
        report = check_jwt_token(token)
        jwt007 = report.findings_by_rule("JWT-007")
        assert len(jwt007) == 1

    def test_missing_aud_flagged(self):
        token = _jwt_encode(
            {"alg": "RS256"},
            {"sub": "123", "exp": 9999999999, "iat": 1000, "iss": "example.com"},
        )
        report = check_jwt_token(token)
        jwt008 = report.findings_by_rule("JWT-008")
        assert len(jwt008) == 1


class TestCheckJwtTokenExpired:
    def test_expired_token_flagged(self):
        past_exp = int(time.time()) - 3600  # 1 hour ago
        token = _jwt_encode(
            {"alg": "RS256"},
            {"sub": "u", "exp": past_exp, "iat": past_exp - 60, "iss": "x", "aud": "y"},
        )
        report = check_jwt_token(token)
        jwt004 = report.findings_by_rule("JWT-004")
        # One from missing exp check passes (exp is present), one from expired check
        expired = [f for f in jwt004 if "EXPIRED" in f.message or "expired" in f.message.lower()]
        assert len(expired) == 1
        assert expired[0].severity == "critical"

    def test_valid_token_not_expired(self):
        future_exp = int(time.time()) + 3600
        token = _jwt_encode(
            {"alg": "RS256"},
            {"sub": "u", "exp": future_exp, "iat": int(time.time()), "iss": "x", "aud": "y"},
        )
        report = check_jwt_token(token)
        expired = [
            f for f in report.findings_by_rule("JWT-004")
            if "EXPIRED" in f.message or "expired" in f.message.lower()
        ]
        assert len(expired) == 0


class TestCheckJwtTokenMalformed:
    def test_malformed_token_produces_warning(self):
        report = check_jwt_token("this-is-not-a-jwt")
        assert report.warnings

    def test_summary_contains_status(self):
        token = _jwt_encode({"alg": "RS256"}, {"sub": "123", "exp": 9999999999,
                                                 "iat": 1000, "iss": "x", "aud": "y"})
        report = check_jwt_token(token)
        s = report.summary()
        assert "PASS" in s or "FAIL" in s


class TestJwtSecurityReport:
    def test_summary_source_is_token(self):
        report = JwtSecurityReport(source="token")
        assert "token" in report.summary()

    def test_summary_source_is_config(self):
        report = JwtSecurityReport(source="config")
        assert "config" in report.summary()

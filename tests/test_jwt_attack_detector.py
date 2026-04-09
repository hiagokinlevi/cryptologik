"""
Tests for crypto.jwt_attack_detector
=====================================
Comprehensive pytest suite covering all seven check rules (JWT-ATK-001 through
JWT-ATK-007), malformed tokens, batch helpers, risk-score arithmetic,
JWTAnalysisResult structure, and edge cases.

Approximately 55 test functions organised by logical section.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict

import pytest

from crypto.jwt_attack_detector import (
    JWTAnalysisResult,
    JWTAttackDetector,
    JWTAttackFinding,
    JWTSeverity,
    _CHECK_WEIGHTS,
    _decode_segment,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def b64url(obj: Any) -> str:
    """JSON-encode *obj*, then base64url-encode it without padding."""
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_token(
    header: Dict,
    claims: Dict,
    signature: str = "",
) -> str:
    """Assemble a JWT-shaped string from plain dicts (no real signature)."""
    return f"{b64url(header)}.{b64url(claims)}.{signature}"


# Convenience token factories used across multiple tests
def _none_alg_token() -> str:
    return make_token({"alg": "none", "typ": "JWT"}, {"sub": "1234"})


def _valid_hs256_token() -> str:
    """Small HS256 token whose payload segment is short (<= 200 chars)."""
    return make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "user1", "iat": 1700000000})


def _large_payload_hs256_token() -> str:
    """HS256 token with a large enough payload to trip ATK-001 heuristic."""
    # Build a claims dict whose base64url encoding exceeds 200 chars
    claims = {
        "sub": "user1",
        "iat": 1700000000,
        "extra": "A" * 300,  # padding to inflate payload size
    }
    return make_token({"alg": "HS256", "typ": "JWT"}, claims)


def _rs256_token() -> str:
    """Simulated RS256 token with a small payload (no ATK-001 trip)."""
    return make_token({"alg": "RS256", "typ": "JWT"}, {"sub": "user2"})


# ---------------------------------------------------------------------------
# Section 1 — _decode_segment helper
# ---------------------------------------------------------------------------

class TestDecodeSegment:
    def test_decodes_valid_segment(self):
        obj = {"alg": "HS256", "typ": "JWT"}
        segment = b64url(obj)
        assert _decode_segment(segment) == obj

    def test_returns_empty_dict_on_invalid_base64(self):
        assert _decode_segment("!!!invalid!!!") == {}

    def test_returns_empty_dict_on_non_json_payload(self):
        raw = base64.urlsafe_b64encode(b"not-json").rstrip(b"=").decode()
        assert _decode_segment(raw) == {}

    def test_returns_empty_dict_on_empty_string(self):
        assert _decode_segment("") == {}

    def test_handles_missing_padding_gracefully(self):
        """JWT segments deliberately omit '=' padding — helper must add it."""
        obj = {"k": "v"}
        segment = b64url(obj)
        # Ensure no trailing '=' was left by our helper
        assert "=" not in segment
        assert _decode_segment(segment) == obj


# ---------------------------------------------------------------------------
# Section 2 — JWTAttackFinding dataclass
# ---------------------------------------------------------------------------

class TestJWTAttackFinding:
    def _make_finding(self) -> JWTAttackFinding:
        return JWTAttackFinding(
            check_id="JWT-ATK-002",
            severity=JWTSeverity.CRITICAL,
            title="None algorithm attack",
            detail="alg=none bypasses signature verification.",
            evidence="alg='none'",
            remediation="Reject tokens with alg=none.",
        )

    def test_to_dict_contains_all_keys(self):
        d = self._make_finding().to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "title", "detail", "evidence", "remediation"
        }

    def test_to_dict_severity_is_string(self):
        d = self._make_finding().to_dict()
        assert d["severity"] == "CRITICAL"

    def test_summary_format(self):
        s = self._make_finding().summary()
        assert "JWT-ATK-002" in s
        assert "CRITICAL" in s
        assert "None algorithm attack" in s

    def test_default_evidence_and_remediation_are_empty(self):
        f = JWTAttackFinding(
            check_id="JWT-ATK-005",
            severity=JWTSeverity.MEDIUM,
            title="Long token",
            detail="Too long.",
        )
        assert f.evidence == ""
        assert f.remediation == ""


# ---------------------------------------------------------------------------
# Section 3 — JWTAnalysisResult dataclass
# ---------------------------------------------------------------------------

class TestJWTAnalysisResult:
    def _make_result(self) -> JWTAnalysisResult:
        f1 = JWTAttackFinding("JWT-ATK-002", JWTSeverity.CRITICAL, "T1", "D1")
        f2 = JWTAttackFinding("JWT-ATK-007", JWTSeverity.MEDIUM, "T2", "D2")
        return JWTAnalysisResult(
            token_preview="eyJhbGciOi...",
            header={"alg": "none"},
            claims={"sub": "x"},
            findings=[f1, f2],
            risk_score=70,
            is_attack=True,
            generated_at=1700000000.0,
        )

    def test_total_findings(self):
        assert self._make_result().total_findings == 2

    def test_critical_findings_filters_correctly(self):
        result = self._make_result()
        crits = result.critical_findings
        assert len(crits) == 1
        assert crits[0].severity == JWTSeverity.CRITICAL

    def test_to_dict_keys(self):
        d = self._make_result().to_dict()
        assert "token_preview" in d
        assert "header" in d
        assert "claims" in d
        assert "findings" in d
        assert "risk_score" in d
        assert "is_attack" in d
        assert "generated_at" in d
        assert "total_findings" in d

    def test_to_dict_findings_are_dicts(self):
        d = self._make_result().to_dict()
        assert isinstance(d["findings"][0], dict)

    def test_summary_format(self):
        s = self._make_result().summary()
        assert "risk=70" in s
        assert "findings=2" in s

    def test_empty_findings_defaults(self):
        r = JWTAnalysisResult(
            token_preview="abc...",
            header={},
            claims={},
        )
        assert r.total_findings == 0
        assert r.critical_findings == []
        assert r.risk_score == 0
        assert r.is_attack is False


# ---------------------------------------------------------------------------
# Section 4 — Malformed tokens
# ---------------------------------------------------------------------------

class TestMalformedTokens:
    def setup_method(self):
        self.det = JWTAttackDetector()

    def test_single_segment_token_returns_malformed_finding(self):
        result = self.det.analyze("onlyonesegment")
        check_ids = [f.check_id for f in result.findings]
        assert "JWT-ATK-000" in check_ids

    def test_empty_string_returns_malformed_finding(self):
        result = self.det.analyze("")
        check_ids = [f.check_id for f in result.findings]
        assert "JWT-ATK-000" in check_ids

    def test_malformed_token_risk_score_is_zero(self):
        """JWT-ATK-000 has no weight in _CHECK_WEIGHTS, so score stays 0."""
        result = self.det.analyze("bad")
        assert result.risk_score == 0

    def test_malformed_token_header_and_claims_are_empty(self):
        result = self.det.analyze("bad")
        assert result.header == {}
        assert result.claims == {}

    def test_two_segment_token_does_not_raise(self):
        """Two segments (header.payload, no signature) should be handled."""
        header = b64url({"alg": "HS256"})
        payload = b64url({"sub": "x"})
        result = self.det.analyze(f"{header}.{payload}")
        # No malformed finding expected
        check_ids = [f.check_id for f in result.findings]
        assert "JWT-ATK-000" not in check_ids


# ---------------------------------------------------------------------------
# Section 5 — JWT-ATK-001: Algorithm confusion
# ---------------------------------------------------------------------------

class TestATK001AlgorithmConfusion:
    def setup_method(self):
        self.det = JWTAttackDetector()
        self.now = time.time()

    def test_x5c_in_header_fires_atk001(self):
        token = make_token({"alg": "HS256", "typ": "JWT", "x5c": ["CERT"]}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        check_ids = [f.check_id for f in result.findings]
        assert "JWT-ATK-001" in check_ids

    def test_x5u_in_header_fires_atk001(self):
        token = make_token({"alg": "RS256", "typ": "JWT", "x5u": "https://evil.com/cert"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        check_ids = [f.check_id for f in result.findings]
        assert "JWT-ATK-001" in check_ids

    def test_large_hs256_payload_fires_atk001(self):
        token = _large_payload_hs256_token()
        # Verify our helper actually produces a long enough payload segment
        payload_segment = token.split(".")[1]
        assert len(payload_segment) > 200, "test pre-condition: payload must be > 200 chars"
        result = self.det.analyze(token, _now=self.now)
        check_ids = [f.check_id for f in result.findings]
        assert "JWT-ATK-001" in check_ids

    def test_small_hs256_payload_does_not_fire_atk001(self):
        token = _valid_hs256_token()
        payload_segment = token.split(".")[1]
        assert len(payload_segment) <= 200, "test pre-condition: payload must be <= 200 chars"
        result = self.det.analyze(token, _now=self.now)
        check_ids = [f.check_id for f in result.findings]
        assert "JWT-ATK-001" not in check_ids

    def test_atk001_severity_is_critical(self):
        token = make_token({"alg": "HS256", "x5c": ["C"]}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        for f in result.findings:
            if f.check_id == "JWT-ATK-001":
                assert f.severity == JWTSeverity.CRITICAL
                return
        pytest.fail("JWT-ATK-001 not found")

    def test_rs256_without_x5c_does_not_fire_atk001(self):
        token = _rs256_token()
        result = self.det.analyze(token, _now=self.now)
        check_ids = [f.check_id for f in result.findings]
        assert "JWT-ATK-001" not in check_ids


# ---------------------------------------------------------------------------
# Section 6 — JWT-ATK-002: None algorithm
# ---------------------------------------------------------------------------

class TestATK002NoneAlg:
    def setup_method(self):
        self.det = JWTAttackDetector()
        self.now = time.time()

    def test_alg_none_lowercase_fires(self):
        token = make_token({"alg": "none"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-002" for f in result.findings)

    def test_alg_None_mixed_case_fires(self):
        token = make_token({"alg": "None"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-002" for f in result.findings)

    def test_alg_NONE_uppercase_fires(self):
        token = make_token({"alg": "NONE"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-002" for f in result.findings)

    def test_alg_null_fires(self):
        token = make_token({"alg": "null"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-002" for f in result.findings)

    def test_alg_empty_string_fires(self):
        token = make_token({"alg": ""}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-002" for f in result.findings)

    def test_atk002_severity_is_critical(self):
        token = _none_alg_token()
        result = self.det.analyze(token, _now=self.now)
        for f in result.findings:
            if f.check_id == "JWT-ATK-002":
                assert f.severity == JWTSeverity.CRITICAL
                return
        pytest.fail("JWT-ATK-002 not found")

    def test_hs256_does_not_fire_atk002(self):
        token = _valid_hs256_token()
        result = self.det.analyze(token, _now=self.now)
        assert not any(f.check_id == "JWT-ATK-002" for f in result.findings)


# ---------------------------------------------------------------------------
# Section 7 — JWT-ATK-003: Embedded JWK / JKU
# ---------------------------------------------------------------------------

class TestATK003EmbeddedJWK:
    def setup_method(self):
        self.det = JWTAttackDetector()
        self.now = time.time()

    def test_jwk_in_header_fires(self):
        token = make_token(
            {"alg": "RS256", "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}},
            {"sub": "u"},
        )
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-003" for f in result.findings)

    def test_jku_in_header_fires(self):
        token = make_token(
            {"alg": "RS256", "jku": "https://attacker.com/keys"},
            {"sub": "u"},
        )
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-003" for f in result.findings)

    def test_atk003_severity_is_high(self):
        token = make_token({"alg": "RS256", "jku": "https://evil.com"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        for f in result.findings:
            if f.check_id == "JWT-ATK-003":
                assert f.severity == JWTSeverity.HIGH
                return
        pytest.fail("JWT-ATK-003 not found")

    def test_clean_header_does_not_fire_atk003(self):
        token = _valid_hs256_token()
        result = self.det.analyze(token, _now=self.now)
        assert not any(f.check_id == "JWT-ATK-003" for f in result.findings)


# ---------------------------------------------------------------------------
# Section 8 — JWT-ATK-004: KID injection
# ---------------------------------------------------------------------------

class TestATK004KIDInjection:
    def setup_method(self):
        self.det = JWTAttackDetector()
        self.now = time.time()

    def test_sql_select_in_kid_fires(self):
        token = make_token({"alg": "HS256", "kid": "1 UNION SELECT 1,2,3--"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-004" for f in result.findings)

    def test_sql_drop_in_kid_fires(self):
        token = make_token({"alg": "HS256", "kid": "'; DROP TABLE keys; --"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-004" for f in result.findings)

    def test_path_traversal_etc_in_kid_fires(self):
        token = make_token({"alg": "HS256", "kid": "/etc/passwd"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-004" for f in result.findings)

    def test_path_traversal_dotdot_in_kid_fires(self):
        token = make_token({"alg": "HS256", "kid": "../../secret"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-004" for f in result.findings)

    def test_windows_path_traversal_in_kid_fires(self):
        token = make_token({"alg": "HS256", "kid": "..\\..\\secret"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-004" for f in result.findings)

    def test_clean_kid_does_not_fire_atk004(self):
        token = make_token({"alg": "HS256", "kid": "key-2024-primary"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        assert not any(f.check_id == "JWT-ATK-004" for f in result.findings)

    def test_no_kid_does_not_fire_atk004(self):
        token = _valid_hs256_token()
        result = self.det.analyze(token, _now=self.now)
        assert not any(f.check_id == "JWT-ATK-004" for f in result.findings)

    def test_atk004_severity_is_critical(self):
        token = make_token({"alg": "HS256", "kid": "' OR '1'='1"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        for f in result.findings:
            if f.check_id == "JWT-ATK-004":
                assert f.severity == JWTSeverity.CRITICAL
                return
        pytest.fail("JWT-ATK-004 not found")


# ---------------------------------------------------------------------------
# Section 9 — JWT-ATK-005: Abnormally long token
# ---------------------------------------------------------------------------

class TestATK005LongToken:
    def test_token_over_limit_fires(self):
        det = JWTAttackDetector(max_token_length=50)
        token = make_token({"alg": "HS256"}, {"sub": "u", "pad": "X" * 100})
        assert len(token) > 50
        result = det.analyze(token)
        assert any(f.check_id == "JWT-ATK-005" for f in result.findings)

    def test_token_at_exact_limit_does_not_fire(self):
        det = JWTAttackDetector(max_token_length=10000)
        token = _valid_hs256_token()
        assert len(token) <= 10000
        result = det.analyze(token)
        assert not any(f.check_id == "JWT-ATK-005" for f in result.findings)

    def test_default_limit_4096_fires_on_huge_token(self):
        det = JWTAttackDetector()
        token = make_token({"alg": "HS256"}, {"sub": "u", "junk": "B" * 5000})
        result = det.analyze(token)
        assert any(f.check_id == "JWT-ATK-005" for f in result.findings)

    def test_atk005_severity_is_medium(self):
        det = JWTAttackDetector(max_token_length=10)
        token = make_token({"alg": "HS256"}, {"sub": "u"})
        result = det.analyze(token)
        for f in result.findings:
            if f.check_id == "JWT-ATK-005":
                assert f.severity == JWTSeverity.MEDIUM
                return
        pytest.fail("JWT-ATK-005 not found")


# ---------------------------------------------------------------------------
# Section 10 — JWT-ATK-006: Timing anomalies
# ---------------------------------------------------------------------------

class TestATK006Timing:
    def setup_method(self):
        self.det = JWTAttackDetector(
            future_nbf_tolerance_seconds=300,
            past_exp_tolerance_seconds=3600,
        )

    def test_nbf_far_future_fires_high(self):
        now = time.time()
        nbf = now + 1000  # 1000s ahead, beyond 300s tolerance
        token = make_token({"alg": "HS256"}, {"sub": "u", "nbf": nbf})
        result = self.det.analyze(token, _now=now)
        findings_006 = [f for f in result.findings if f.check_id == "JWT-ATK-006"]
        assert any(f.severity == JWTSeverity.HIGH for f in findings_006)

    def test_nbf_within_tolerance_does_not_fire(self):
        now = time.time()
        nbf = now + 100  # within 300s tolerance
        token = make_token({"alg": "HS256"}, {"sub": "u", "nbf": nbf})
        result = self.det.analyze(token, _now=now)
        assert not any(f.check_id == "JWT-ATK-006" for f in result.findings)

    def test_exp_far_past_fires_medium(self):
        now = time.time()
        exp = now - 7200  # 2 hours in the past, beyond 3600s tolerance
        token = make_token({"alg": "HS256"}, {"sub": "u", "exp": exp})
        result = self.det.analyze(token, _now=now)
        findings_006 = [f for f in result.findings if f.check_id == "JWT-ATK-006"]
        assert any(f.severity == JWTSeverity.MEDIUM for f in findings_006)

    def test_exp_recently_expired_does_not_fire_atk006(self):
        now = time.time()
        exp = now - 60  # just 1 minute expired — within 3600s tolerance
        token = make_token({"alg": "HS256"}, {"sub": "u", "exp": exp})
        result = self.det.analyze(token, _now=now)
        assert not any(f.check_id == "JWT-ATK-006" for f in result.findings)

    def test_both_nbf_and_exp_anomalies_can_fire(self):
        now = time.time()
        token = make_token(
            {"alg": "HS256"},
            {"sub": "u", "nbf": now + 1000, "exp": now - 7200},
        )
        result = self.det.analyze(token, _now=now)
        severities_006 = {f.severity for f in result.findings if f.check_id == "JWT-ATK-006"}
        assert JWTSeverity.HIGH in severities_006
        assert JWTSeverity.MEDIUM in severities_006

    def test_non_numeric_nbf_does_not_raise(self):
        now = time.time()
        token = make_token({"alg": "HS256"}, {"sub": "u", "nbf": "not-a-number"})
        # Should not raise; just silently skip the check
        result = self.det.analyze(token, _now=now)
        assert result is not None


# ---------------------------------------------------------------------------
# Section 11 — JWT-ATK-007: Suspicious issuer
# ---------------------------------------------------------------------------

class TestATK007SuspiciousIssuer:
    def setup_method(self):
        self.det = JWTAttackDetector()
        self.now = time.time()

    def test_http_issuer_fires(self):
        token = make_token({"alg": "HS256"}, {"sub": "u", "iss": "http://evil.com"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-007" for f in result.findings)

    def test_https_issuer_fires(self):
        token = make_token({"alg": "HS256"}, {"sub": "u", "iss": "https://attacker.io/auth"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-007" for f in result.findings)

    def test_localhost_issuer_fires(self):
        token = make_token({"alg": "HS256"}, {"sub": "u", "iss": "localhost"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-007" for f in result.findings)

    def test_127_0_0_1_issuer_fires(self):
        token = make_token({"alg": "HS256"}, {"sub": "u", "iss": "127.0.0.1"})
        result = self.det.analyze(token, _now=self.now)
        assert any(f.check_id == "JWT-ATK-007" for f in result.findings)

    def test_clean_issuer_does_not_fire(self):
        token = make_token({"alg": "HS256"}, {"sub": "u", "iss": "my-auth-service"})
        result = self.det.analyze(token, _now=self.now)
        assert not any(f.check_id == "JWT-ATK-007" for f in result.findings)

    def test_no_iss_does_not_fire(self):
        token = make_token({"alg": "HS256"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        assert not any(f.check_id == "JWT-ATK-007" for f in result.findings)

    def test_atk007_severity_is_medium(self):
        token = make_token({"alg": "HS256"}, {"sub": "u", "iss": "localhost"})
        result = self.det.analyze(token, _now=self.now)
        for f in result.findings:
            if f.check_id == "JWT-ATK-007":
                assert f.severity == JWTSeverity.MEDIUM
                return
        pytest.fail("JWT-ATK-007 not found")


# ---------------------------------------------------------------------------
# Section 12 — Risk score arithmetic
# ---------------------------------------------------------------------------

class TestRiskScore:
    def setup_method(self):
        self.det = JWTAttackDetector()
        self.now = time.time()

    def test_no_findings_risk_score_is_zero(self):
        token = _valid_hs256_token()
        result = self.det.analyze(token, _now=self.now)
        # Valid token should have no findings → risk 0
        assert result.risk_score == 0

    def test_atk002_alone_has_weight_50(self):
        token = make_token({"alg": "none"}, {"sub": "u"})
        result = self.det.analyze(token, _now=self.now)
        # JWT-ATK-002 weight = 50
        assert result.risk_score >= _CHECK_WEIGHTS["JWT-ATK-002"]

    def test_risk_score_capped_at_100(self):
        """Firing multiple high-weight checks must not exceed 100."""
        # Fire ATK-002 (50) + ATK-003 (45) + ATK-004 (40) = 135 → capped 100
        token = make_token(
            {
                "alg": "none",
                "jwk": {"kty": "RSA"},
                "kid": "' OR '1'='1",
            },
            {"sub": "u"},
        )
        result = self.det.analyze(token, _now=self.now)
        assert result.risk_score <= 100

    def test_same_check_fired_twice_counted_once(self):
        """Both nbf-future and exp-past trigger JWT-ATK-006; weight added once."""
        now = time.time()
        token = make_token(
            {"alg": "HS256"},
            {"sub": "u", "nbf": now + 1000, "exp": now - 7200},
        )
        result = self.det.analyze(token, _now=now)
        # Weight for JWT-ATK-006 is 25; if counted twice it would be 50
        assert result.risk_score == _CHECK_WEIGHTS["JWT-ATK-006"]

    def test_check_weights_dict_contains_all_seven_ids(self):
        expected = {
            "JWT-ATK-001", "JWT-ATK-002", "JWT-ATK-003",
            "JWT-ATK-004", "JWT-ATK-005", "JWT-ATK-006", "JWT-ATK-007",
        }
        assert set(_CHECK_WEIGHTS.keys()) == expected


# ---------------------------------------------------------------------------
# Section 13 — is_attack flag and attack_threshold
# ---------------------------------------------------------------------------

class TestIsAttack:
    def test_default_threshold_zero_any_finding_is_attack(self):
        det = JWTAttackDetector(attack_threshold=0)
        token = make_token({"alg": "none"}, {"sub": "u"})
        result = det.analyze(token)
        assert result.is_attack is True

    def test_high_threshold_suppresses_is_attack(self):
        det = JWTAttackDetector(attack_threshold=99)
        token = make_token({"alg": "none"}, {"sub": "u"})
        # ATK-002 weight = 50 < threshold 99 → not flagged as attack
        result = det.analyze(token)
        assert result.is_attack is False

    def test_clean_token_is_not_attack(self):
        det = JWTAttackDetector()
        token = _valid_hs256_token()
        result = det.analyze(token)
        assert result.is_attack is False


# ---------------------------------------------------------------------------
# Section 14 — analyze_many and filter_attacks
# ---------------------------------------------------------------------------

class TestBatchHelpers:
    def setup_method(self):
        self.det = JWTAttackDetector()
        self.now = time.time()

    def test_analyze_many_returns_same_count(self):
        tokens = [_none_alg_token(), _valid_hs256_token(), _rs256_token()]
        results = self.det.analyze_many(tokens)
        assert len(results) == len(tokens)

    def test_analyze_many_preserves_order(self):
        tokens = [_none_alg_token(), _valid_hs256_token()]
        results = self.det.analyze_many(tokens)
        # First result should flag ATK-002; second should not
        assert any(f.check_id == "JWT-ATK-002" for f in results[0].findings)
        assert not any(f.check_id == "JWT-ATK-002" for f in results[1].findings)

    def test_analyze_many_empty_list(self):
        assert self.det.analyze_many([]) == []

    def test_filter_attacks_returns_only_attacks(self):
        tokens = [_none_alg_token(), _valid_hs256_token(), _rs256_token()]
        attacks = self.det.filter_attacks(tokens)
        assert all(r.is_attack for r in attacks)

    def test_filter_attacks_excludes_clean_tokens(self):
        clean_tokens = [_valid_hs256_token(), _rs256_token()]
        attacks = self.det.filter_attacks(clean_tokens)
        assert len(attacks) == 0

    def test_filter_attacks_empty_list(self):
        assert self.det.filter_attacks([]) == []

    def test_filter_attacks_mixed_batch(self):
        attack_token = make_token({"alg": "none"}, {"sub": "u"})
        clean_token = _valid_hs256_token()
        attacks = self.det.filter_attacks([attack_token, clean_token, attack_token])
        assert len(attacks) == 2


# ---------------------------------------------------------------------------
# Section 15 — token_preview and result metadata
# ---------------------------------------------------------------------------

class TestTokenPreview:
    def test_long_token_preview_ends_with_ellipsis(self):
        det = JWTAttackDetector()
        token = _none_alg_token()
        assert len(token) > 30
        result = det.analyze(token)
        assert result.token_preview.endswith("...")
        assert len(result.token_preview) == 33  # 30 chars + "..."

    def test_short_token_preview_no_ellipsis(self):
        det = JWTAttackDetector()
        short_token = "abc.def"
        result = det.analyze(short_token)
        # Token <= 30 chars → preview equals token itself (malformed, but preview is set)
        assert result.token_preview == short_token

    def test_generated_at_is_recent(self):
        det = JWTAttackDetector()
        before = time.time()
        result = det.analyze(_valid_hs256_token())
        after = time.time()
        assert before <= result.generated_at <= after

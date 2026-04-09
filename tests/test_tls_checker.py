"""Tests for TLS posture checker (unit tests without network calls)."""
from datetime import datetime, timedelta, timezone
from crypto.tls.posture_checker import TlsPostureResult, TlsFinding, TlsRisk


def _make_result(**kwargs) -> TlsPostureResult:
    return TlsPostureResult(
        host="example.com",
        port=443,
        checked_at=datetime.now(timezone.utc),
        **kwargs,
    )


def test_expired_cert_detected():
    past = datetime.now(timezone.utc) - timedelta(days=1)
    result = _make_result(cert_expiry=past)
    assert result.expired is True
    assert result.days_until_expiry < 0


def test_valid_cert_not_expired():
    future = datetime.now(timezone.utc) + timedelta(days=90)
    result = _make_result(cert_expiry=future)
    assert result.expired is False
    assert result.days_until_expiry > 0


def test_expiring_soon():
    soon = datetime.now(timezone.utc) + timedelta(days=15)
    result = _make_result(cert_expiry=soon)
    assert result.days_until_expiry < 30


def test_finding_structure():
    f = TlsFinding(
        rule_id="TLS002",
        risk=TlsRisk.HIGH,
        message="Deprecated TLS 1.0",
        remediation="Disable TLS 1.0",
    )
    assert f.risk == TlsRisk.HIGH
    assert f.rule_id == "TLS002"

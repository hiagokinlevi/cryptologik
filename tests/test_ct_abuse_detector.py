"""
Tests for crypto/ct_abuse_detector.py
"""
from __future__ import annotations

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from crypto.ct_abuse_detector import (
    CTAbuseDetector,
    CTAbuseFinding,
    CTAbuseReport,
    CTSeverity,
    CertEntry,
    _is_trusted_issuer,
    _parse_iso,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _entry(
    domain: str = "example.com",
    sans: list | None = None,
    issuer_cn: str = "Let's Encrypt Authority X3",
    not_before: str = "2026-01-01T00:00:00",
    not_after: str = "2026-04-09T00:00:00",  # ~98 days
    serial: str = "abc123",
    registered_at: str = "",
    is_wildcard: bool = False,
) -> CertEntry:
    return CertEntry(
        domain=domain,
        sans=sans or [],
        issuer_cn=issuer_cn,
        not_before=not_before,
        not_after=not_after,
        serial_number=serial,
        domain_registered_at=registered_at,
        is_wildcard=is_wildcard,
    )


def _detector(**kwargs) -> CTAbuseDetector:
    return CTAbuseDetector(**kwargs)


def _check_ids(report: CTAbuseReport) -> set[str]:
    return {f.check_id for f in report.findings}


# ===========================================================================
# _parse_iso
# ===========================================================================

class TestParseIso:
    def test_standard_iso(self):
        dt = _parse_iso("2026-01-01T00:00:00")
        assert dt is not None
        assert dt.year == 2026

    def test_with_z_suffix(self):
        dt = _parse_iso("2026-01-01T00:00:00Z")
        assert dt is not None

    def test_empty_string(self):
        assert _parse_iso("") is None

    def test_invalid_string(self):
        assert _parse_iso("not-a-date") is None

    def test_adds_utc_if_no_tz(self):
        dt = _parse_iso("2026-01-01T00:00:00")
        assert dt.tzinfo is not None


# ===========================================================================
# _is_trusted_issuer
# ===========================================================================

class TestIsTrustedIssuer:
    def test_letsencrypt_trusted(self):
        assert _is_trusted_issuer("Let's Encrypt Authority X3")

    def test_digicert_trusted(self):
        assert _is_trusted_issuer("DigiCert Global Root CA")

    def test_unknown_not_trusted(self):
        assert not _is_trusted_issuer("Rogue CA v1")

    def test_empty_not_trusted(self):
        assert not _is_trusted_issuer("")

    def test_case_insensitive(self):
        assert _is_trusted_issuer("LETSENCRYPT R3")


# ===========================================================================
# CertEntry
# ===========================================================================

class TestCertEntry:
    def test_wildcard_auto_detected(self):
        e = CertEntry(domain="*.evil.tk", sans=[], issuer_cn="")
        assert e.is_wildcard

    def test_wildcard_from_san(self):
        e = CertEntry(domain="evil.tk", sans=["*.evil.tk"], issuer_cn="")
        assert e.is_wildcard

    def test_non_wildcard(self):
        e = CertEntry(domain="example.com", sans=["www.example.com"], issuer_cn="")
        assert not e.is_wildcard

    def test_tld(self):
        assert _entry("evil.tk").tld() == "tk"

    def test_sld(self):
        assert _entry("www.example.com").sld() == "example"

    def test_validity_days(self):
        e = _entry(not_before="2026-01-01T00:00:00", not_after="2027-01-01T00:00:00")
        assert e.validity_days() == 365

    def test_validity_days_unparseable(self):
        e = _entry(not_before="invalid", not_after="invalid")
        assert e.validity_days() is None


# ===========================================================================
# CTAbuseFinding
# ===========================================================================

class TestCTAbuseFinding:
    def _f(self) -> CTAbuseFinding:
        return CTAbuseFinding(
            check_id="CT-ABU-004",
            severity=CTSeverity.CRITICAL,
            title="Brand keyword in SAN",
            detail="Detail",
            domain="mybank-login.tk",
            evidence="brand='mybank'",
        )

    def test_summary_contains_check_id(self):
        assert "CT-ABU-004" in self._f().summary()

    def test_to_dict_keys(self):
        d = self._f().to_dict()
        for k in ("check_id", "severity", "title", "detail", "domain", "evidence"):
            assert k in d

    def test_severity_serialized_as_string(self):
        assert self._f().to_dict()["severity"] == "CRITICAL"


# ===========================================================================
# CTAbuseReport
# ===========================================================================

class TestCTAbuseReport:
    def _report(self) -> CTAbuseReport:
        f1 = CTAbuseFinding("CT-ABU-004", CTSeverity.CRITICAL, "t", "d", "a.tk")
        f2 = CTAbuseFinding("CT-ABU-002", CTSeverity.HIGH,     "t", "d", "b.tk")
        return CTAbuseReport(
            findings=[f1, f2],
            analyzed_count=5,
            risk_score=55,
            suspicious_domains={"a.tk", "b.tk"},
        )

    def test_total_findings(self):
        assert self._report().total_findings == 2

    def test_critical_findings(self):
        assert len(self._report().critical_findings) == 1

    def test_findings_by_check(self):
        assert len(self._report().findings_by_check("CT-ABU-004")) == 1

    def test_summary_contains_count(self):
        s = self._report().summary()
        assert "5" in s  # analyzed_count

    def test_empty_report(self):
        r = CTAbuseReport()
        assert r.total_findings == 0


# ===========================================================================
# CT-ABU-001: Mass issuance
# ===========================================================================

class TestCTAbu001:
    def test_fires_for_mass_issuance(self):
        det = _detector(mass_issuance_threshold=3)
        # 3 certs for same SLD within 1 hour
        entries = [
            _entry("sub1.evil.com", not_before="2026-01-01T00:00:00"),
            _entry("sub2.evil.com", not_before="2026-01-01T00:30:00"),
            _entry("sub3.evil.com", not_before="2026-01-01T01:00:00"),
        ]
        report = det.analyze(entries)
        assert "CT-ABU-001" in _check_ids(report)

    def test_not_fired_below_threshold(self):
        det = _detector(mass_issuance_threshold=5)
        entries = [
            _entry("sub1.safe.com", not_before="2026-01-01T00:00:00"),
            _entry("sub2.safe.com", not_before="2026-01-01T01:00:00"),
        ]
        report = det.analyze(entries)
        assert "CT-ABU-001" not in _check_ids(report)

    def test_not_fired_when_spread_across_days(self):
        det = _detector(mass_issuance_threshold=2)
        entries = [
            _entry("sub1.evil.com", not_before="2026-01-01T00:00:00"),
            _entry("sub2.evil.com", not_before="2026-01-05T00:00:00"),
        ]
        report = det.analyze(entries)
        assert "CT-ABU-001" not in _check_ids(report)

    def test_ct_abu_001_is_high(self):
        det = _detector(mass_issuance_threshold=2)
        entries = [
            _entry("sub1.x.com", not_before="2026-01-01T00:00:00"),
            _entry("sub2.x.com", not_before="2026-01-01T01:00:00"),
        ]
        report = det.analyze(entries)
        f = next(f for f in report.findings if f.check_id == "CT-ABU-001")
        assert f.severity == CTSeverity.HIGH


# ===========================================================================
# CT-ABU-002: Wildcard on suspicious TLD
# ===========================================================================

class TestCTAbu002:
    def test_fires_for_wildcard_on_tk(self):
        det = _detector()
        e = _entry("*.phishing.tk")
        report = det.analyze([e])
        assert "CT-ABU-002" in _check_ids(report)

    def test_fires_for_wildcard_on_xyz(self):
        det = _detector()
        e = _entry("*.evil.xyz")
        report = det.analyze([e])
        assert "CT-ABU-002" in _check_ids(report)

    def test_not_fired_for_wildcard_on_com(self):
        det = _detector()
        e = _entry("*.example.com")
        report = det.analyze([e])
        assert "CT-ABU-002" not in _check_ids(report)

    def test_not_fired_for_non_wildcard_on_tk(self):
        det = _detector()
        e = _entry("evil.tk")
        report = det.analyze([e])
        assert "CT-ABU-002" not in _check_ids(report)

    def test_ct_abu_002_is_high(self):
        det = _detector()
        e = _entry("*.p.tk")
        report = det.analyze([e])
        f = next(f for f in report.findings if f.check_id == "CT-ABU-002")
        assert f.severity == CTSeverity.HIGH


# ===========================================================================
# CT-ABU-003: High SAN count
# ===========================================================================

class TestCTAbu003:
    def test_fires_when_san_count_exceeds_threshold(self):
        det = _detector(high_san_threshold=5)
        sans = [f"sub{i}.evil.com" for i in range(6)]
        e = _entry("evil.com", sans=sans)
        report = det.analyze([e])
        assert "CT-ABU-003" in _check_ids(report)

    def test_not_fired_at_threshold(self):
        det = _detector(high_san_threshold=5)
        sans = [f"sub{i}.example.com" for i in range(5)]
        e = _entry("example.com", sans=sans)
        report = det.analyze([e])
        assert "CT-ABU-003" not in _check_ids(report)

    def test_ct_abu_003_is_medium(self):
        det = _detector(high_san_threshold=2)
        e = _entry("x.com", sans=["a.x.com", "b.x.com", "c.x.com"])
        report = det.analyze([e])
        f = next(f for f in report.findings if f.check_id == "CT-ABU-003")
        assert f.severity == CTSeverity.MEDIUM


# ===========================================================================
# CT-ABU-004: Brand keyword in SAN
# ===========================================================================

class TestCTAbu004:
    def test_fires_when_brand_in_domain(self):
        det = _detector(brand_keywords=["mybank"])
        e = _entry("mybank-secure-login.tk")
        report = det.analyze([e])
        assert "CT-ABU-004" in _check_ids(report)

    def test_fires_when_brand_in_san(self):
        det = _detector(brand_keywords=["paypal"])
        e = _entry("evil.com", sans=["paypal-login.evil.com"])
        report = det.analyze([e])
        assert "CT-ABU-004" in _check_ids(report)

    def test_not_fired_without_brand_keywords(self):
        det = _detector(brand_keywords=[])
        e = _entry("mybank.com")
        report = det.analyze([e])
        assert "CT-ABU-004" not in _check_ids(report)

    def test_not_fired_when_brand_absent(self):
        det = _detector(brand_keywords=["mybank"])
        e = _entry("legitimate-site.com", sans=["www.legitimate-site.com"])
        report = det.analyze([e])
        assert "CT-ABU-004" not in _check_ids(report)

    def test_ct_abu_004_is_critical(self):
        det = _detector(brand_keywords=["amazon"])
        e = _entry("amazon-deals.tk")
        report = det.analyze([e])
        f = next(f for f in report.findings if f.check_id == "CT-ABU-004")
        assert f.severity == CTSeverity.CRITICAL

    def test_case_insensitive_brand_match(self):
        det = _detector(brand_keywords=["amazon"])
        e = _entry("AMAZON-login.com")
        report = det.analyze([e])
        assert "CT-ABU-004" in _check_ids(report)


# ===========================================================================
# CT-ABU-005: Excessive validity
# ===========================================================================

class TestCTAbu005:
    def test_fires_for_long_validity(self):
        det = _detector(max_validity_days=398)
        e = _entry(
            not_before="2026-01-01T00:00:00",
            not_after="2027-03-01T00:00:00",   # ~424 days
        )
        report = det.analyze([e])
        assert "CT-ABU-005" in _check_ids(report)

    def test_not_fired_within_limit(self):
        det = _detector(max_validity_days=398)
        e = _entry(
            not_before="2026-01-01T00:00:00",
            not_after="2026-04-09T00:00:00",   # ~98 days
        )
        report = det.analyze([e])
        assert "CT-ABU-005" not in _check_ids(report)

    def test_not_fired_when_dates_unparseable(self):
        det = _detector(max_validity_days=398)
        e = _entry(not_before="invalid", not_after="invalid")
        report = det.analyze([e])
        assert "CT-ABU-005" not in _check_ids(report)

    def test_ct_abu_005_is_medium(self):
        det = _detector(max_validity_days=30)
        e = _entry(
            not_before="2026-01-01T00:00:00",
            not_after="2026-04-01T00:00:00",
        )
        report = det.analyze([e])
        f = next(f for f in report.findings if f.check_id == "CT-ABU-005")
        assert f.severity == CTSeverity.MEDIUM


# ===========================================================================
# CT-ABU-006: Untrusted issuer
# ===========================================================================

class TestCTAbu006:
    def test_fires_for_unknown_ca(self):
        det = _detector()
        e = _entry(issuer_cn="Rogue Certificate Authority v1")
        report = det.analyze([e])
        assert "CT-ABU-006" in _check_ids(report)

    def test_not_fired_for_letsencrypt(self):
        det = _detector()
        e = _entry(issuer_cn="Let's Encrypt Authority X3")
        report = det.analyze([e])
        assert "CT-ABU-006" not in _check_ids(report)

    def test_not_fired_for_empty_issuer(self):
        det = _detector()
        e = _entry(issuer_cn="")
        report = det.analyze([e])
        assert "CT-ABU-006" not in _check_ids(report)

    def test_ct_abu_006_is_high(self):
        det = _detector()
        e = _entry(issuer_cn="Evil CA")
        report = det.analyze([e])
        f = next(f for f in report.findings if f.check_id == "CT-ABU-006")
        assert f.severity == CTSeverity.HIGH


# ===========================================================================
# CT-ABU-007: Newly registered domain
# ===========================================================================

class TestCTAbu007:
    def test_fires_for_new_domain(self):
        det = _detector(new_domain_days=30)
        e = _entry(
            domain="fresh-phish.tk",
            not_before="2026-01-10T00:00:00",
            registered_at="2026-01-05T00:00:00",  # 5 days before cert
        )
        report = det.analyze([e])
        assert "CT-ABU-007" in _check_ids(report)

    def test_not_fired_for_old_domain(self):
        det = _detector(new_domain_days=30)
        e = _entry(
            domain="old-site.com",
            not_before="2026-01-10T00:00:00",
            registered_at="2020-01-01T00:00:00",  # 6 years old
        )
        report = det.analyze([e])
        assert "CT-ABU-007" not in _check_ids(report)

    def test_not_fired_when_no_registered_at(self):
        det = _detector(new_domain_days=30)
        e = _entry(domain="unknown-age.com")
        report = det.analyze([e])
        assert "CT-ABU-007" not in _check_ids(report)

    def test_ct_abu_007_is_high(self):
        det = _detector(new_domain_days=30)
        e = _entry(
            domain="fresh.tk",
            not_before="2026-01-10T00:00:00",
            registered_at="2026-01-08T00:00:00",
        )
        report = det.analyze([e])
        f = next(f for f in report.findings if f.check_id == "CT-ABU-007")
        assert f.severity == CTSeverity.HIGH


# ===========================================================================
# Risk score
# ===========================================================================

class TestRiskScore:
    def test_clean_entry_zero_risk(self):
        det = _detector(brand_keywords=["brand"])
        e = _entry(
            domain="example.com",
            sans=["www.example.com"],
            issuer_cn="Let's Encrypt Authority X3",
            not_before="2026-01-01T00:00:00",
            not_after="2026-04-09T00:00:00",
        )
        report = det.analyze([e])
        assert report.risk_score == 0

    def test_risk_capped_at_100(self):
        det = _detector(
            brand_keywords=["bank"],
            mass_issuance_threshold=1,
            high_san_threshold=1,
            max_validity_days=1,
            new_domain_days=3650,
        )
        sans = ["bank-login.tk", "bank-secure.tk"]
        e = _entry(
            domain="*.bank-phish.tk",
            sans=sans,
            issuer_cn="Evil CA",
            not_before="2026-01-01T00:00:00",
            not_after="2031-01-01T00:00:00",
            registered_at="2025-12-31T00:00:00",
        )
        report = det.analyze([e, e])
        assert report.risk_score <= 100

    def test_brand_keyword_alone_35(self):
        det = _detector(brand_keywords=["mybank"])
        e = _entry(
            domain="mybank-login.com",
            issuer_cn="Let's Encrypt",
            not_before="2026-01-01T00:00:00",
            not_after="2026-04-09T00:00:00",
        )
        report = det.analyze([e])
        assert report.risk_score == 35


# ===========================================================================
# suspicious_domains tracking
# ===========================================================================

class TestSuspiciousDomains:
    def test_suspicious_domain_added(self):
        det = _detector(brand_keywords=["mybank"])
        e = _entry("mybank-login.com")
        report = det.analyze([e])
        assert "mybank-login.com" in report.suspicious_domains

    def test_clean_domain_not_in_suspicious(self):
        det = _detector(brand_keywords=["mybank"])
        e = _entry(
            "wikipedia.org",
            sans=["www.wikipedia.org"],
            issuer_cn="DigiCert Global Root CA",
        )
        report = det.analyze([e])
        assert "wikipedia.org" not in report.suspicious_domains


# ===========================================================================
# Empty input
# ===========================================================================

class TestEmptyInput:
    def test_empty_entries(self):
        det = _detector()
        report = det.analyze([])
        assert report.total_findings == 0
        assert report.analyzed_count == 0
        assert report.risk_score == 0

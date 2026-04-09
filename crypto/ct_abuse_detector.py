"""
Certificate Transparency Abuse Detector
==========================================
Analyzes Certificate Transparency (CT) log entries to identify patterns
that may indicate certificate abuse — mass issuance campaigns, wildcard
abuse, suspicious Subject Alternative Names (SANs), and newly registered
domains being used in phishing infrastructure.

Detection Rules
----------------
CT-ABU-001  Mass issuance burst
            An organization issued N or more certificates within a short
            time window. Sudden bursts often indicate an attacker automating
            free TLS certificate issuance (Let's Encrypt, ZeroSSL) to build
            phishing infrastructure at scale.

CT-ABU-002  Wildcard certificate on suspicious TLD
            A wildcard certificate (*.domain.tld) was issued for a TLD
            commonly abused in phishing campaigns (e.g. .tk, .ml, .xyz).
            Wildcards on free/cheap TLDs maximize attacker utility.

CT-ABU-003  High SAN count per certificate
            A single certificate contains many Subject Alternative Names
            (> N). Legitimate certs rarely need more than 5–10 SANs;
            mass-SAN certs may be used to cover entire phishing campaigns
            under a single TLS certificate.

CT-ABU-004  SAN contains brand / keyword match
            One or more SANs in the certificate contain a brand keyword
            (configurable list). Certificates impersonating brands are a
            common phishing enabler.

CT-ABU-005  Certificate validity exceeds maximum
            The certificate is valid for longer than the recommended maximum
            (398 days for publicly trusted CAs). Extended validity
            certificates may indicate misconfigured automation or
            intentional evasion of revocation.

CT-ABU-006  Self-signed or untrusted issuer
            The certificate was issued by an untrusted/unknown CA rather
            than a publicly trusted root. May indicate rogue CA usage or
            mTLS abuse.

CT-ABU-007  Newly registered domain with immediate TLS cert
            The domain appears to have been registered very recently
            (within 30 days) and already has a TLS certificate.  This
            pattern is common in phishing kit deployment.

Usage::

    from crypto.ct_abuse_detector import (
        CTAbuseDetector,
        CTAbuseReport,
        CertEntry,
    )

    detector = CTAbuseDetector(brand_keywords=["mybank", "paypal", "amazon"])
    entries = [
        CertEntry(
            domain="mybank-login.tk",
            sans=["mybank-login.tk", "www.mybank-login.tk"],
            issuer_cn="Let's Encrypt",
            not_before="2026-01-01T00:00:00",
            not_after="2026-04-01T00:00:00",
        )
    ]
    report = detector.analyze(entries)
    print(report.summary())
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class CTSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "click", "link",
    "online", "site", "live", "stream",
    "pw", "cc", "zip", "mov",
})

# Trusted CA CN fragments — not exhaustive but covers major roots
_TRUSTED_CA_FRAGMENTS: frozenset[str] = frozenset({
    "let's encrypt", "letsencrypt",
    "digicert", "comodo", "sectigo",
    "globalsign", "entrust",
    "godaddy", "network solutions",
    "amazon", "aws",
    "google", "microsoft",
    "zerossl", "buypass",
    "usertrust",
    "root ca",
})

_MAX_RECOMMENDED_VALIDITY_DAYS = 398
_MASS_ISSUANCE_WINDOW_HOURS    = 24
_NEW_DOMAIN_THRESHOLD_DAYS     = 30
_DEFAULT_HIGH_SAN_THRESHOLD    = 10

_CHECK_META: dict[str, tuple[CTSeverity, str]] = {
    "CT-ABU-001": (CTSeverity.HIGH,     "Mass certificate issuance burst"),
    "CT-ABU-002": (CTSeverity.HIGH,     "Wildcard cert on suspicious TLD"),
    "CT-ABU-003": (CTSeverity.MEDIUM,   "Excessive SAN count per certificate"),
    "CT-ABU-004": (CTSeverity.CRITICAL, "Certificate SAN contains brand keyword"),
    "CT-ABU-005": (CTSeverity.MEDIUM,   "Certificate validity exceeds 398 days"),
    "CT-ABU-006": (CTSeverity.HIGH,     "Self-signed or untrusted issuer"),
    "CT-ABU-007": (CTSeverity.HIGH,     "Newly registered domain with immediate TLS"),
}

_CHECK_WEIGHTS: dict[str, int] = {
    "CT-ABU-001": 20,
    "CT-ABU-002": 20,
    "CT-ABU-003": 10,
    "CT-ABU-004": 35,
    "CT-ABU-005": 10,
    "CT-ABU-006": 20,
    "CT-ABU-007": 20,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CertEntry:
    """
    A parsed Certificate Transparency log entry.

    Attributes:
        domain:          Primary domain (CN or first SAN).
        sans:            Subject Alternative Names list.
        issuer_cn:       Issuer Common Name string.
        not_before:      ISO-8601 certificate start date (UTC assumed).
        not_after:       ISO-8601 certificate end date (UTC assumed).
        serial_number:   Certificate serial (optional, used for dedup).
        domain_registered_at: ISO-8601 date when domain was registered
                         (optional, for CT-ABU-007).
        is_wildcard:     Whether the primary domain or any SAN is a wildcard.
    """
    domain:               str
    sans:                 list[str] = field(default_factory=list)
    issuer_cn:            str = ""
    not_before:           str = ""
    not_after:            str = ""
    serial_number:        str = ""
    domain_registered_at: str = ""
    is_wildcard:          bool = False

    def __post_init__(self) -> None:
        # Auto-detect wildcard from domain or SANs
        if not self.is_wildcard:
            all_names = [self.domain] + self.sans
            self.is_wildcard = any(n.startswith("*.") for n in all_names)

    def validity_days(self) -> Optional[int]:
        """Return certificate validity period in days, or None if unparseable."""
        try:
            nb = _parse_iso(self.not_before)
            na = _parse_iso(self.not_after)
            if nb and na:
                return (na - nb).days
        except Exception:
            pass
        return None

    def tld(self) -> str:
        """Return TLD of the primary domain."""
        parts = self.domain.lstrip("*.").rsplit(".", 1)
        return parts[-1].lower() if len(parts) >= 1 else ""

    def sld(self) -> str:
        """Return second-level domain."""
        stripped = self.domain.lstrip("*.")
        parts = stripped.rsplit(".", 2)
        return parts[-2].lower() if len(parts) >= 2 else stripped.lower()


@dataclass
class CTAbuseFinding:
    """
    A single CT abuse finding.

    Attributes:
        check_id:    Rule identifier (CT-ABU-001 … CT-ABU-007).
        severity:    Finding severity.
        title:       Short description.
        detail:      Detailed explanation.
        domain:      The domain or certificate affected.
        evidence:    Supporting evidence string.
    """
    check_id:  str
    severity:  CTSeverity
    title:     str
    detail:    str
    domain:    str = ""
    evidence:  str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id":  self.check_id,
            "severity":  self.severity.value,
            "title":     self.title,
            "detail":    self.detail,
            "domain":    self.domain,
            "evidence":  self.evidence,
        }

    def summary(self) -> str:
        return f"[{self.severity.value}] {self.check_id}: {self.title} ({self.domain})"


@dataclass
class CTAbuseReport:
    """
    Aggregated CT abuse analysis report.

    Attributes:
        findings:           All findings.
        analyzed_count:     Number of certificate entries analyzed.
        risk_score:         Aggregate 0–100 risk score.
        suspicious_domains: Domains with at least one finding.
    """
    findings:           list[CTAbuseFinding] = field(default_factory=list)
    analyzed_count:     int = 0
    risk_score:         int = 0
    suspicious_domains: set[str] = field(default_factory=set)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> list[CTAbuseFinding]:
        return [f for f in self.findings if f.severity == CTSeverity.CRITICAL]

    def findings_by_check(self, check_id: str) -> list[CTAbuseFinding]:
        return [f for f in self.findings if f.check_id == check_id]

    def summary(self) -> str:
        return (
            f"CTAbuseReport: {self.analyzed_count} cert(s) | "
            f"risk={self.risk_score} | "
            f"{self.total_findings} finding(s) "
            f"[CRITICAL={len(self.critical_findings)}] | "
            f"{len(self.suspicious_domains)} suspicious domain(s)"
        )


# ---------------------------------------------------------------------------
# CTAbuseDetector
# ---------------------------------------------------------------------------

class CTAbuseDetector:
    """
    Detects certificate abuse patterns in CT log entries.

    Args:
        brand_keywords:         List of brand keywords to match against SANs
                                for CT-ABU-004.
        mass_issuance_threshold: Number of certs from the same domain within
                                 24 hours to trigger CT-ABU-001 (default 5).
        high_san_threshold:     SAN count threshold for CT-ABU-003 (default 10).
        max_validity_days:      Maximum allowed validity for CT-ABU-005 (default 398).
        new_domain_days:        Days threshold for "new domain" in CT-ABU-007 (default 30).
    """

    def __init__(
        self,
        brand_keywords: Optional[list[str]] = None,
        mass_issuance_threshold: int = 5,
        high_san_threshold: int = _DEFAULT_HIGH_SAN_THRESHOLD,
        max_validity_days: int = _MAX_RECOMMENDED_VALIDITY_DAYS,
        new_domain_days: int = _NEW_DOMAIN_THRESHOLD_DAYS,
    ) -> None:
        self._brands    = [k.lower() for k in (brand_keywords or [])]
        self._mass_threshold  = mass_issuance_threshold
        self._san_threshold   = high_san_threshold
        self._max_validity    = max_validity_days
        self._new_domain_days = new_domain_days

    def analyze(self, entries: list[CertEntry]) -> CTAbuseReport:
        """
        Analyze a list of CertEntry objects for abuse patterns.

        Returns a CTAbuseReport.
        """
        findings: list[CTAbuseFinding] = []
        suspicious_domains: set[str] = set()
        fired_checks: set[str] = set()

        # Group by SLD for mass issuance detection
        sld_entries: dict[str, list[CertEntry]] = {}
        for entry in entries:
            sld_key = entry.sld()
            sld_entries.setdefault(sld_key, []).append(entry)

        # CT-ABU-001: Mass issuance burst (per SLD within window)
        for sld, sld_group in sld_entries.items():
            if len(sld_group) >= self._mass_threshold:
                # Check if all are within 24-hour window
                timestamps = []
                for e in sld_group:
                    ts = _parse_iso(e.not_before)
                    if ts:
                        timestamps.append(ts)
                if len(timestamps) >= self._mass_threshold:
                    timestamps.sort()
                    span = timestamps[-1] - timestamps[0]
                    if span <= timedelta(hours=_MASS_ISSUANCE_WINDOW_HOURS):
                        f = self._make_finding(
                            "CT-ABU-001", sld,
                            detail=(
                                f"{len(sld_group)} certificates issued for SLD "
                                f"'{sld}' within {span.total_seconds()/3600:.1f} hours. "
                                "Rapid mass issuance is a strong indicator of automated "
                                "phishing infrastructure deployment."
                            ),
                            evidence=f"{len(sld_group)} certs in {span}",
                        )
                        findings.append(f)
                        suspicious_domains.add(sld)
                        fired_checks.add("CT-ABU-001")

        # Per-certificate checks
        for entry in entries:
            cert_findings = self._check_cert(entry)
            for cf in cert_findings:
                findings.append(cf)
                suspicious_domains.add(entry.domain)
                fired_checks.add(cf.check_id)

        # Aggregate risk score from unique check IDs that fired
        risk_score = min(100, sum(
            _CHECK_WEIGHTS.get(cid, 5) for cid in fired_checks
        ))

        return CTAbuseReport(
            findings=findings,
            analyzed_count=len(entries),
            risk_score=risk_score,
            suspicious_domains=suspicious_domains,
        )

    def _check_cert(self, entry: CertEntry) -> list[CTAbuseFinding]:
        findings: list[CTAbuseFinding] = []

        tld = entry.tld()
        all_names = [entry.domain] + entry.sans

        # CT-ABU-002: Wildcard on suspicious TLD
        if entry.is_wildcard and tld in _SUSPICIOUS_TLDS:
            findings.append(self._make_finding(
                "CT-ABU-002", entry.domain,
                detail=(
                    f"Wildcard certificate issued for '{entry.domain}' on the "
                    f"suspicious TLD '.{tld}'. Wildcards on free/cheap TLDs are "
                    "commonly used to cover large numbers of phishing subdomains."
                ),
                evidence=f"*.{tld}",
            ))

        # CT-ABU-003: High SAN count
        total_sans = len(entry.sans)
        if total_sans > self._san_threshold:
            findings.append(self._make_finding(
                "CT-ABU-003", entry.domain,
                detail=(
                    f"Certificate for '{entry.domain}' contains {total_sans} "
                    f"SANs — exceeding the threshold of {self._san_threshold}. "
                    "Legitimate certificates rarely require more than a handful "
                    "of SANs."
                ),
                evidence=f"{total_sans} SANs",
            ))

        # CT-ABU-004: SAN contains brand keyword
        if self._brands:
            for name in all_names:
                name_lower = name.lower()
                for brand in self._brands:
                    if brand in name_lower:
                        findings.append(self._make_finding(
                            "CT-ABU-004", entry.domain,
                            detail=(
                                f"SAN or domain '{name}' contains the brand keyword "
                                f"'{brand}'. TLS certificates impersonating known "
                                "brands are a strong phishing indicator."
                            ),
                            evidence=f"brand='{brand}' in '{name}'",
                        ))
                        break  # one finding per cert
                else:
                    continue
                break

        # CT-ABU-005: Excessive validity
        validity = entry.validity_days()
        if validity is not None and validity > self._max_validity:
            findings.append(self._make_finding(
                "CT-ABU-005", entry.domain,
                detail=(
                    f"Certificate for '{entry.domain}' is valid for {validity} days, "
                    f"exceeding the recommended maximum of {self._max_validity} days. "
                    "Long-lived certs are not revocable within short incident "
                    "response windows."
                ),
                evidence=f"validity={validity} days",
            ))

        # CT-ABU-006: Self-signed / untrusted issuer
        if entry.issuer_cn and not _is_trusted_issuer(entry.issuer_cn):
            findings.append(self._make_finding(
                "CT-ABU-006", entry.domain,
                detail=(
                    f"Certificate for '{entry.domain}' was issued by "
                    f"'{entry.issuer_cn}', which does not match any known "
                    "publicly trusted CA. This may indicate a rogue CA or "
                    "self-signed certificate being used for TLS abuse."
                ),
                evidence=f"issuer='{entry.issuer_cn}'",
            ))

        # CT-ABU-007: Newly registered domain
        if entry.domain_registered_at:
            reg_date = _parse_iso(entry.domain_registered_at)
            not_before = _parse_iso(entry.not_before)
            if reg_date and not_before:
                age_days = (not_before - reg_date).days
                if 0 <= age_days <= self._new_domain_days:
                    findings.append(self._make_finding(
                        "CT-ABU-007", entry.domain,
                        detail=(
                            f"Domain '{entry.domain}' was registered {age_days} day(s) "
                            "before its first TLS certificate was issued. "
                            "Rapid domain-to-cert patterns are a hallmark of "
                            "automated phishing kit deployment."
                        ),
                        evidence=f"domain_age={age_days} days at cert issuance",
                    ))

        return findings

    @staticmethod
    def _make_finding(
        check_id: str,
        domain: str,
        detail: str,
        evidence: str = "",
    ) -> CTAbuseFinding:
        severity, title = _CHECK_META[check_id]
        return CTAbuseFinding(
            check_id=check_id,
            severity=severity,
            title=title,
            detail=detail,
            domain=domain,
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_iso(s: str) -> Optional[datetime]:
    """Parse ISO-8601 datetime string. Returns None on failure."""
    if not s:
        return None
    try:
        # Strip trailing Z, handle space separator
        clean = s.rstrip("Z").replace(" ", "T")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _is_trusted_issuer(issuer_cn: str) -> bool:
    """Return True if issuer_cn contains a known trusted CA fragment."""
    lower = issuer_cn.lower()
    return any(frag in lower for frag in _TRUSTED_CA_FRAGMENTS)

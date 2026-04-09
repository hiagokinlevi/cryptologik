"""
Key Rotation Advisor
====================
Analyzes cryptographic key and certificate metadata to detect stale keys
and recommend rotation schedules based on key type, algorithm, and usage.

The advisor works with key/certificate descriptors (plain dicts or
KeyDescriptor dataclasses) rather than live key stores, making it suitable
for static analysis pipelines, CI checks, and posture reports.

Checks performed:
  - ROT-001 CRITICAL: Key past hard-expiry date
  - ROT-002 HIGH:     Key older than maximum age for its type/algorithm
  - ROT-003 HIGH:     Certificate within 30 days of expiry (or already expired)
  - ROT-004 MEDIUM:   Key in rotation warning window (approaching max age)
  - ROT-005 MEDIUM:   No rotation policy defined for key
  - ROT-006 LOW:      Key created date unknown (cannot assess age)

Maximum recommended key ages (days) by type:
  - RSA-2048:       730  (2 years)
  - RSA-4096:      1095  (3 years)
  - ECDSA-256:      730  (2 years)
  - ECDSA-384:     1095  (3 years)
  - ED25519:        730  (2 years)
  - AES-128:        365  (1 year)
  - AES-256:        730  (2 years)
  - HMAC-SHA256:    180  (6 months — short-lived by default)
  - API key:         90  (3 months — rotate frequently)
  - Service account key: 90 (3 months)
  - TLS certificate:  depends on validity period (cert-specific)

Usage:
    from crypto.key_management.rotation_advisor import (
        KeyDescriptor,
        advise_rotation,
        RotationAdvisor,
    )

    keys = [
        KeyDescriptor(
            key_id="prod-api-signing",
            key_type="RSA",
            key_size=2048,
            created_date="2023-01-01",
            usage="signing",
            owner="payments-service",
        ),
    ]
    report = advise_rotation(keys)
    for f in report.findings:
        print(f"[{f.severity.upper()}] {f.rule_id}: {f.message}")
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Key age limits (days) per normalized key type string
# ---------------------------------------------------------------------------

_MAX_AGE_DAYS: dict[str, int] = {
    "rsa-2048":           730,
    "rsa-4096":          1095,
    "rsa-1024":           180,   # legacy — flag immediately
    "rsa-512":             30,   # critically weak
    "ecdsa-256":          730,
    "ecdsa-384":         1095,
    "ecdsa-521":         1095,
    "ed25519":            730,
    "aes-128":            365,
    "aes-256":            730,
    "aes-192":            365,
    "hmac-sha256":        180,
    "hmac-sha512":        365,
    "api_key":             90,
    "api-key":             90,
    "service_account_key": 90,
    "service-account-key": 90,
    "ssh":                730,
    "gpg":               1095,
    "tls":                398,   # CA/Browser Forum max for publicly-trusted certs
}

_WARNING_WINDOW_DAYS = 30   # alert when within this many days of max age


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class KeyDescriptor:
    """
    Descriptor for a single cryptographic key or certificate.

    Attributes:
        key_id:          Unique identifier (e.g. "prod-api-signing").
        key_type:        Type string (e.g. "RSA", "ECDSA", "AES", "api_key", "tls").
        key_size:        Key size in bits (e.g. 2048 for RSA, 256 for ECDSA).
        created_date:    ISO 8601 date string "YYYY-MM-DD", or None if unknown.
        expiry_date:     ISO 8601 date string "YYYY-MM-DD", or None if no explicit expiry.
        rotation_policy: Max rotation interval in days, or None if unset.
        usage:           What the key is used for (e.g. "signing", "encryption", "tls").
        owner:           Service or team responsible for the key.
        environment:     "production", "staging", "development", etc.
        notes:           Free-text notes.
    """
    key_id:           str
    key_type:         str
    key_size:         Optional[int] = None
    created_date:     Optional[str] = None
    expiry_date:      Optional[str] = None
    rotation_policy:  Optional[int] = None    # days
    usage:            str = "unknown"
    owner:            str = "unknown"
    environment:      str = "production"
    notes:            str = ""

    def normalized_type(self) -> str:
        """Return a lowercase normalized type key for age-limit lookup."""
        base = self.key_type.lower().replace(" ", "-")
        if self.key_size:
            candidate = f"{base}-{self.key_size}"
            if candidate in _MAX_AGE_DAYS:
                return candidate
        return base

    def max_age_days(self) -> Optional[int]:
        """Return the recommended maximum age in days for this key type."""
        nt = self.normalized_type()
        if nt in _MAX_AGE_DAYS:
            return _MAX_AGE_DAYS[nt]
        # Try base type without size
        base = re.sub(r"-\d+$", "", nt)
        return _MAX_AGE_DAYS.get(base)


@dataclass
class RotationFinding:
    """A single key rotation recommendation or alert."""
    rule_id:     str
    severity:    str          # "critical", "high", "medium", "low"
    key_id:      str
    key_type:    str
    message:     str
    remediation: str
    age_days:    Optional[int] = None   # current age in days, if known
    days_until_expiry: Optional[int] = None


@dataclass
class RotationReport:
    """Aggregate report for a list of key descriptors."""
    findings:         list[RotationFinding] = field(default_factory=list)
    keys_analyzed:    int = 0
    rotation_due:     int = 0     # count of keys needing immediate rotation
    rotation_warning: int = 0     # count of keys in warning window

    @property
    def passed(self) -> bool:
        return not any(f.severity in ("critical", "high") for f in self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")

    def findings_for_key(self, key_id: str) -> list[RotationFinding]:
        return [f for f in self.findings if f.key_id == key_id]

    def summary(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return (
            f"[{status}] Key rotation: {self.keys_analyzed} keys analyzed | "
            f"CRITICAL={self.critical_count} HIGH={self.high_count} "
            f"MEDIUM={self.medium_count} LOW={self.low_count} | "
            f"rotation_due={self.rotation_due}, warning={self.rotation_warning}"
        )


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

def _today() -> date:
    return datetime.now(tz=timezone.utc).date()


def _parse_date(s: str) -> Optional[date]:
    """Parse ISO 8601 date string, returning None on failure."""
    try:
        return date.fromisoformat(s.strip())
    except (ValueError, AttributeError):
        return None


def _age_days(created: date) -> int:
    return (_today() - created).days


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_rot001_hard_expiry(key: KeyDescriptor, report: RotationReport) -> None:
    """ROT-001: Key past its explicit expiry_date."""
    if not key.expiry_date:
        return
    expiry = _parse_date(key.expiry_date)
    if expiry is None:
        return
    if expiry < _today():
        days_over = (_today() - expiry).days
        report.findings.append(RotationFinding(
            rule_id="ROT-001",
            severity="critical",
            key_id=key.key_id,
            key_type=key.key_type,
            message=(
                f"Key '{key.key_id}' ({key.key_type}) has PASSED its expiry date "
                f"({key.expiry_date}) by {days_over} day(s). "
                f"This key should be considered compromised or invalid."
            ),
            remediation=(
                "Rotate this key immediately. Generate a new key, update all consumers, "
                "and revoke the expired key. Do not use expired cryptographic material."
            ),
            days_until_expiry=-days_over,
        ))
        report.rotation_due += 1


def _check_rot002_max_age(key: KeyDescriptor, report: RotationReport) -> None:
    """ROT-002: Key older than recommended maximum age for its type."""
    if not key.created_date:
        return
    created = _parse_date(key.created_date)
    if created is None:
        return
    max_age = key.max_age_days()
    if max_age is None:
        return

    age = _age_days(created)
    if age > max_age:
        days_over = age - max_age
        report.findings.append(RotationFinding(
            rule_id="ROT-002",
            severity="high",
            key_id=key.key_id,
            key_type=key.key_type,
            message=(
                f"Key '{key.key_id}' ({key.key_type}) is {age} day(s) old, "
                f"exceeding the recommended maximum of {max_age} day(s) "
                f"by {days_over} day(s)."
            ),
            remediation=(
                f"Rotate '{key.key_id}' now. The recommended maximum age for "
                f"{key.key_type} keys is {max_age} days ({max_age // 30} months). "
                "Schedule regular rotation and automate where possible."
            ),
            age_days=age,
        ))
        report.rotation_due += 1


def _check_rot003_cert_expiry(key: KeyDescriptor, report: RotationReport) -> None:
    """ROT-003: TLS certificate within expiry warning window."""
    if not key.expiry_date:
        return
    expiry = _parse_date(key.expiry_date)
    if expiry is None:
        return
    days_left = (expiry - _today()).days
    if days_left <= 30 and days_left >= 0:
        severity = "critical" if days_left <= 7 else "high"
        report.findings.append(RotationFinding(
            rule_id="ROT-003",
            severity=severity,
            key_id=key.key_id,
            key_type=key.key_type,
            message=(
                f"Key/certificate '{key.key_id}' expires in {days_left} day(s) "
                f"(on {key.expiry_date}). Automated renewal or manual rotation "
                "is urgently required."
            ),
            remediation=(
                "Renew or replace this certificate/key before it expires. "
                "For TLS certificates: use Let's Encrypt ACME automation or "
                "set up ACM auto-renewal. Alert when < 30 days remain."
            ),
            days_until_expiry=days_left,
        ))
        report.rotation_due += 1


def _check_rot004_warning_window(key: KeyDescriptor, report: RotationReport) -> None:
    """ROT-004: Key approaching max age (within warning window)."""
    if not key.created_date:
        return
    created = _parse_date(key.created_date)
    if created is None:
        return
    max_age = key.max_age_days()
    if max_age is None:
        return

    age = _age_days(created)
    days_until_max = max_age - age
    # Only fire if not already past max (ROT-002 handles that)
    if 0 < days_until_max <= _WARNING_WINDOW_DAYS:
        report.findings.append(RotationFinding(
            rule_id="ROT-004",
            severity="medium",
            key_id=key.key_id,
            key_type=key.key_type,
            message=(
                f"Key '{key.key_id}' ({key.key_type}) will reach its recommended "
                f"maximum age in {days_until_max} day(s). Schedule rotation now."
            ),
            remediation=(
                "Plan rotation within the next week. Prepare the new key, "
                "update references, and decommission the old key within "
                f"{days_until_max} days."
            ),
            age_days=age,
            days_until_expiry=days_until_max,
        ))
        report.rotation_warning += 1


def _check_rot005_no_policy(key: KeyDescriptor, report: RotationReport) -> None:
    """ROT-005: No rotation policy defined for the key."""
    if key.rotation_policy is None:
        report.findings.append(RotationFinding(
            rule_id="ROT-005",
            severity="medium",
            key_id=key.key_id,
            key_type=key.key_type,
            message=(
                f"Key '{key.key_id}' ({key.key_type}) has no rotation policy defined. "
                "Without a policy, rotation may be forgotten or performed inconsistently."
            ),
            remediation=(
                "Define a rotation policy (maximum age in days) for this key. "
                f"For {key.key_type} keys, the recommended maximum age is "
                f"{key.max_age_days() or 'N/A'} days. "
                "Store the policy in your secrets manager or key management system."
            ),
        ))


def _check_rot006_unknown_created(key: KeyDescriptor, report: RotationReport) -> None:
    """ROT-006: Created date unknown — cannot assess age."""
    if not key.created_date:
        report.findings.append(RotationFinding(
            rule_id="ROT-006",
            severity="low",
            key_id=key.key_id,
            key_type=key.key_type,
            message=(
                f"Key '{key.key_id}' ({key.key_type}) has no creation date recorded. "
                "Key age cannot be assessed. The key may be very old."
            ),
            remediation=(
                "Record the creation date in your key inventory. "
                "If the creation date is unknown, treat the key as potentially "
                "overdue for rotation and schedule a proactive rotation."
            ),
        ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_CHECKS = [
    _check_rot001_hard_expiry,
    _check_rot002_max_age,
    _check_rot003_cert_expiry,
    _check_rot004_warning_window,
    _check_rot005_no_policy,
    _check_rot006_unknown_created,
]


class RotationAdvisor:
    """
    Stateful key rotation advisor that accumulates key descriptors and
    produces a consolidated RotationReport.

    Usage:
        advisor = RotationAdvisor()
        advisor.add_key(KeyDescriptor(key_id="db-enc", key_type="AES", key_size=256,
                                      created_date="2022-01-01"))
        report = advisor.advise()
    """

    def __init__(self) -> None:
        self._keys: list[KeyDescriptor] = []

    def add_key(self, key: KeyDescriptor) -> None:
        """Add a key descriptor to the advisor."""
        self._keys.append(key)

    def add_keys(self, keys: list[KeyDescriptor]) -> None:
        """Add multiple key descriptors."""
        self._keys.extend(keys)

    def advise(self) -> RotationReport:
        """Run all checks on all registered keys and return a RotationReport."""
        return advise_rotation(self._keys)

    def clear(self) -> None:
        """Remove all registered keys."""
        self._keys.clear()


def advise_rotation(keys: list[KeyDescriptor]) -> RotationReport:
    """
    Run rotation checks on a list of KeyDescriptor objects.

    Args:
        keys: List of KeyDescriptor objects to analyze.

    Returns:
        RotationReport with all findings and aggregate counts.
    """
    report = RotationReport(keys_analyzed=len(keys))
    for key in keys:
        for check in _CHECKS:
            check(key, report)
    return report

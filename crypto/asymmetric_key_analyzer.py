# asymmetric_key_analyzer.py — Cyber Port / cryptologik
# Analyze asymmetric cryptographic key configurations for security weaknesses.
#
# Copyright (c) 2026 hiagokinlevi — Licensed under CC BY 4.0
# https://creativecommons.org/licenses/by/4.0/
#
# Supported algorithms : RSA, DSA, EC (ECDSA / ECDH), Ed25519, Ed448,
#                        X25519, X448
# Python 3.9 compatible — uses typing.Optional / List / Dict, not X | Y

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check weights registry
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "ASY-001": 45,  # RSA key below 2048 bits — CRITICAL
    "ASY-002": 15,  # RSA key below 3072 bits (2048–3071) — MEDIUM
    "ASY-003": 25,  # DSA algorithm deprecated — HIGH
    "ASY-004": 25,  # EC weak / deprecated curve — HIGH
    "ASY-005": 15,  # EC P-256 insufficient when >= 256-bit security required — MEDIUM
    "ASY-006": 45,  # RSA public exponent e = 3 (low-exponent attack) — CRITICAL
    "ASY-007": 15,  # No expiry date, or expiry more than 2 years away — MEDIUM
}

# ---------------------------------------------------------------------------
# Curve sets (all lower-case for case-insensitive comparison)
# ---------------------------------------------------------------------------

# Curves considered weak or deprecated
_WEAK_CURVES: frozenset = frozenset({
    "secp192r1",
    "prime192v1",
    "sect163k1",
    "sect163r2",
    "brainpoolp160r1",  # lower-cased form of brainpoolP160r1
})

# P-256 equivalent names — insufficient when 256-bit security is required
_P256_CURVES: frozenset = frozenset({
    "secp256r1",
    "prime256v1",
    "p-256",
    "p256",
})

# Algorithm families that support EC-specific checks
_EC_ALGORITHMS: frozenset = frozenset({"EC", "ECDSA", "ECDH"})

# Algorithms that are exempt from all algorithm-specific checks (only ASY-007 applies)
_EXEMPT_ALGORITHMS: frozenset = frozenset({"Ed25519", "Ed448", "X25519", "X448"})

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class AsymmetricKey:
    """Represents an asymmetric cryptographic key and its metadata."""

    key_id: str
    algorithm: str          # "RSA" | "DSA" | "EC" | "Ed25519" | "Ed448" | "X25519" | "X448"
    key_size_bits: Optional[int]        # RSA / DSA bit length; None for curve-based keys
    curve_name: Optional[str]           # EC curve name; None for RSA / DSA
    rsa_public_exponent: Optional[int]  # RSA only; None for all other algorithms
    created_date: Optional[date]
    expiry_date: Optional[date]
    purpose: str            # "signing" | "encryption" | "key_agreement" | "general"


@dataclass
class ASYFinding:
    """A single security finding produced by one check against an AsymmetricKey."""

    check_id: str
    severity: str    # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    detail: str
    weight: int


@dataclass
class ASYResult:
    """Aggregated analysis result for a single AsymmetricKey."""

    key_id: str
    algorithm: str
    findings: List[ASYFinding]
    risk_score: int       # min(100, sum of weights for unique fired check IDs)
    security_level: str   # STRONG | ADEQUATE | WEAK | BROKEN

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain-dict representation suitable for JSON serialization."""
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "risk_score": self.risk_score,
            "security_level": self.security_level,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """One-line human-readable summary of the analysis result."""
        count = len(self.findings)
        noun = "finding" if count == 1 else "findings"
        return (
            f"[{self.security_level}] key={self.key_id!r} alg={self.algorithm} "
            f"score={self.risk_score} — {count} {noun}"
        )

    def by_severity(self) -> Dict[str, List[ASYFinding]]:
        """Group findings by severity label."""
        groups: Dict[str, List[ASYFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Security level mapping
# ---------------------------------------------------------------------------

def _security_level(risk_score: int) -> str:
    """Map a numeric risk score to a named security level."""
    if risk_score == 0:
        return "STRONG"
    if risk_score <= 20:
        return "ADEQUATE"
    if risk_score <= 50:
        return "WEAK"
    return "BROKEN"


# ---------------------------------------------------------------------------
# Individual check helpers
# ---------------------------------------------------------------------------

def _check_asy001(key: AsymmetricKey) -> Optional[ASYFinding]:
    """ASY-001 — RSA key size below 2048 bits (CRITICAL)."""
    if key.key_size_bits is not None and key.key_size_bits < 2048:
        return ASYFinding(
            check_id="ASY-001",
            severity="CRITICAL",
            title="RSA key size is critically small (< 2048 bits)",
            detail=(
                f"Key '{key.key_id}' uses only {key.key_size_bits} bits. "
                "RSA keys below 2048 bits are considered broken and must be "
                "replaced immediately."
            ),
            weight=_CHECK_WEIGHTS["ASY-001"],
        )
    return None


def _check_asy002(key: AsymmetricKey, asy001_fired: bool) -> Optional[ASYFinding]:
    """ASY-002 — RSA key size below 3072 bits (2048–3071 range) (MEDIUM).

    Suppressed when ASY-001 already fired for this key.
    """
    if asy001_fired:
        return None
    if key.key_size_bits is not None and 2048 <= key.key_size_bits < 3072:
        return ASYFinding(
            check_id="ASY-002",
            severity="MEDIUM",
            title="RSA key size below recommended 3072 bits",
            detail=(
                f"Key '{key.key_id}' has {key.key_size_bits} bits. "
                "NIST recommends RSA keys of at least 3072 bits for security "
                "beyond 2030."
            ),
            weight=_CHECK_WEIGHTS["ASY-002"],
        )
    return None


def _check_asy003(key: AsymmetricKey) -> Optional[ASYFinding]:
    """ASY-003 — DSA algorithm is deprecated (HIGH)."""
    return ASYFinding(
        check_id="ASY-003",
        severity="HIGH",
        title="DSA algorithm is deprecated",
        detail=(
            f"Key '{key.key_id}' uses DSA, which has been deprecated by NIST "
            "(FIPS 186-5). Migrate to ECDSA or EdDSA."
        ),
        weight=_CHECK_WEIGHTS["ASY-003"],
    )


def _check_asy004(key: AsymmetricKey) -> Optional[ASYFinding]:
    """ASY-004 — EC weak or deprecated curve (HIGH)."""
    if key.curve_name is None:
        return None
    normalized = key.curve_name.lower()
    if normalized in _WEAK_CURVES:
        return ASYFinding(
            check_id="ASY-004",
            severity="HIGH",
            title="EC key uses a weak or deprecated curve",
            detail=(
                f"Key '{key.key_id}' uses curve '{key.curve_name}', which provides "
                "insufficient security. Replace with a NIST P-256 or stronger curve."
            ),
            weight=_CHECK_WEIGHTS["ASY-004"],
        )
    return None


def _check_asy005(key: AsymmetricKey, min_security_bits: int) -> Optional[ASYFinding]:
    """ASY-005 — P-256 curve insufficient when >= 256-bit security level is required (MEDIUM)."""
    if min_security_bits < 256:
        return None
    if key.curve_name is None:
        return None
    normalized = key.curve_name.lower().replace("-", "").replace("_", "")
    # Canonical P-256 names after stripping dashes/underscores
    p256_normalized = {"secp256r1", "prime256v1", "p256"}
    if normalized in p256_normalized:
        return ASYFinding(
            check_id="ASY-005",
            severity="MEDIUM",
            title="EC P-256 curve does not meet the required 256-bit security level",
            detail=(
                f"Key '{key.key_id}' uses curve '{key.curve_name}' (P-256), which "
                "provides approximately 128 bits of security. For a 256-bit security "
                "requirement use P-384 or P-521."
            ),
            weight=_CHECK_WEIGHTS["ASY-005"],
        )
    return None


def _check_asy006(key: AsymmetricKey) -> Optional[ASYFinding]:
    """ASY-006 — RSA public exponent e = 3 (low-exponent attack) (CRITICAL)."""
    if key.rsa_public_exponent is not None and key.rsa_public_exponent == 3:
        return ASYFinding(
            check_id="ASY-006",
            severity="CRITICAL",
            title="RSA public exponent e = 3 (vulnerable to low-exponent attacks)",
            detail=(
                f"Key '{key.key_id}' has public exponent e=3. This is vulnerable to "
                "Coppersmith-style and cube-root attacks when messages are not properly "
                "padded. Use e=65537 (0x10001) instead."
            ),
            weight=_CHECK_WEIGHTS["ASY-006"],
        )
    return None


def _check_asy007(key: AsymmetricKey, reference_date: date) -> Optional[ASYFinding]:
    """ASY-007 — No expiry date set, or expiry more than 2 years from reference_date (MEDIUM)."""
    if key.expiry_date is None:
        return ASYFinding(
            check_id="ASY-007",
            severity="MEDIUM",
            title="Key has no expiry date configured",
            detail=(
                f"Key '{key.key_id}' does not have an expiry date. Keys without "
                "expiry dates may remain in use indefinitely, increasing exposure "
                "risk."
            ),
            weight=_CHECK_WEIGHTS["ASY-007"],
        )
    days_until_expiry = (key.expiry_date - reference_date).days
    if days_until_expiry > 730:
        return ASYFinding(
            check_id="ASY-007",
            severity="MEDIUM",
            title="Key expiry is more than 2 years away",
            detail=(
                f"Key '{key.key_id}' expires on {key.expiry_date} "
                f"({days_until_expiry} days from {reference_date}). "
                "Key lifetimes should not exceed 2 years."
            ),
            weight=_CHECK_WEIGHTS["ASY-007"],
        )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(
    key: AsymmetricKey,
    min_security_bits: int = 128,
    reference_date: Optional[date] = None,
) -> ASYResult:
    """Analyze an asymmetric key for security weaknesses.

    Parameters
    ----------
    key:
        The key configuration to evaluate.
    min_security_bits:
        Minimum required security level in bits (typically 128 or 256).
        Affects ASY-005 (P-256 curve adequacy check).
    reference_date:
        The date to use as "today" for expiry calculations. Defaults to
        ``date.today()`` when not supplied.

    Returns
    -------
    ASYResult
        Aggregated findings, risk score, and security level for the key.
    """
    if reference_date is None:
        reference_date = date.today()

    findings: List[ASYFinding] = []

    alg = key.algorithm  # keep original casing for display; use it directly

    if alg not in _EXEMPT_ALGORITHMS:
        # -- RSA checks -------------------------------------------------------
        if alg == "RSA":
            f001 = _check_asy001(key)
            if f001 is not None:
                findings.append(f001)

            f002 = _check_asy002(key, asy001_fired=(f001 is not None))
            if f002 is not None:
                findings.append(f002)

            f006 = _check_asy006(key)
            if f006 is not None:
                findings.append(f006)

        # -- DSA check --------------------------------------------------------
        elif alg == "DSA":
            f003 = _check_asy003(key)
            if f003 is not None:
                findings.append(f003)

        # -- EC checks --------------------------------------------------------
        elif alg in _EC_ALGORITHMS:
            f004 = _check_asy004(key)
            if f004 is not None:
                findings.append(f004)

            f005 = _check_asy005(key, min_security_bits)
            if f005 is not None:
                findings.append(f005)

    # ASY-007 applies to every algorithm
    f007 = _check_asy007(key, reference_date)
    if f007 is not None:
        findings.append(f007)

    # Deduplicate by check_id before summing weights (each check fires at most
    # once per key, but guard against future logic changes)
    seen_ids: set = set()
    unique_weight_sum = 0
    for f in findings:
        if f.check_id not in seen_ids:
            unique_weight_sum += f.weight
            seen_ids.add(f.check_id)

    score = min(100, unique_weight_sum)
    level = _security_level(score)

    return ASYResult(
        key_id=key.key_id,
        algorithm=alg,
        findings=findings,
        risk_score=score,
        security_level=level,
    )


def analyze_many(
    keys: List[AsymmetricKey],
    min_security_bits: int = 128,
    reference_date: Optional[date] = None,
) -> List[ASYResult]:
    """Run ``analyze`` over a collection of keys and return all results.

    Parameters
    ----------
    keys:
        Iterable of AsymmetricKey instances to evaluate.
    min_security_bits:
        Forwarded to every ``analyze`` call.
    reference_date:
        Forwarded to every ``analyze`` call (resolved once to ``date.today()``
        if not provided, so all keys share the same reference date).
    """
    # Resolve reference_date once so all keys are compared against the same day
    resolved_ref = reference_date if reference_date is not None else date.today()
    return [analyze(key, min_security_bits=min_security_bits, reference_date=resolved_ref) for key in keys]

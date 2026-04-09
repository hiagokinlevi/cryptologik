# cipher_suite_analyzer.py — Cyber Port / CryptoLogik module
#
# Copyright (c) 2026 hiagokinlevi (github.com/hiagokinlevi)
# Licensed under CC BY 4.0  https://creativecommons.org/licenses/by/4.0/
#
# Analyze TLS/SSL cipher suite configurations for cryptographic weaknesses:
# broken ciphers, deprecated protocols, missing forward secrecy, and lack of
# AEAD modes.  Pure stdlib — no external dependencies required.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check metadata
# ---------------------------------------------------------------------------

# Maps check ID → (severity, title, weight)
_CHECK_META: Dict[str, tuple] = {
    "CS-001": ("CRITICAL", "NULL or anonymous cipher suite present", 45),
    "CS-002": ("CRITICAL", "RC4 cipher present in cipher suite list", 45),
    "CS-003": ("CRITICAL", "DES or 3DES (TDEA) cipher present in cipher suite list", 40),
    "CS-004": ("CRITICAL", "Export-grade cipher present in cipher suite list", 45),
    "CS-005": ("HIGH",     "No AEAD cipher suite present (GCM/CCM/ChaCha20)", 25),
    "CS-006": ("HIGH",     "Deprecated TLS/SSL protocol version allowed", 25),
    "CS-007": ("HIGH",     "No forward-secrecy cipher suite present (DHE/ECDHE)", 25),
}

# Public constant requested in the spec — weight lookup by check ID.
_CHECK_WEIGHTS: Dict[str, int] = {cid: meta[2] for cid, meta in _CHECK_META.items()}

# Deprecated protocol names accepted case-insensitively.
_DEPRECATED_VERSIONS = {
    "sslv2", "sslv3",
    "tlsv1", "tlsv1.0", "tlsv1.1",
    "ssl2",  "ssl3",
    "tls1",  "tls1.0",  "tls1.1",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CipherSuiteConfig:
    """Input configuration: a list of TLS cipher suites and allowed protocol versions."""
    config_id: str
    cipher_suites: List[str]     # e.g. ["TLS_AES_256_GCM_SHA384", ...]
    tls_versions: List[str]      # e.g. ["TLSv1.2", "TLSv1.3"]
    description: str             # e.g. "nginx server config", "ALB listener"


@dataclass
class CSFinding:
    """A single security finding for a given check."""
    check_id: str
    severity: str                # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int
    offending_suites: List[str]  # cipher suite names (or version strings) that triggered the finding


@dataclass
class CSResult:
    """Aggregated analysis result for one CipherSuiteConfig."""
    config_id: str
    findings: List[CSFinding]
    risk_score: int              # min(100, sum of weights for unique fired check IDs)
    grade: str                   # "A" / "B" / "C" / "D" / "F"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain-dict representation suitable for JSON serialisation."""
        return {
            "config_id": self.config_id,
            "risk_score": self.risk_score,
            "grade": self.grade,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                    "offending_suites": f.offending_suites,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """One-line human-readable summary."""
        if not self.findings:
            return (
                f"[{self.config_id}] Grade {self.grade} — "
                f"risk score {self.risk_score}/100 — no findings"
            )
        ids = ", ".join(f.check_id for f in self.findings)
        return (
            f"[{self.config_id}] Grade {self.grade} — "
            f"risk score {self.risk_score}/100 — "
            f"{len(self.findings)} finding(s): {ids}"
        )

    def by_severity(self) -> Dict[str, List[CSFinding]]:
        """Group findings by severity string."""
        result: Dict[str, List[CSFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.severity, []).append(finding)
        return result


# ---------------------------------------------------------------------------
# Internal detection helpers
# ---------------------------------------------------------------------------

def _upper(s: str) -> str:
    """Uppercase helper — avoids repeated .upper() calls inline."""
    return s.upper()


def _check_cs001(suites: List[str]) -> Optional[List[str]]:
    """CS-001: NULL or anonymous cipher suite.

    Triggers on suite names containing:
      _NULL_  |  _ANON_  |  TLS_NULL_  |  TLS_ANON_  |  _WITH_NULL_
    or starting with:
      NULL-  |  ADH-  |  AECDH-
    """
    offending: List[str] = []
    for suite in suites:
        u = _upper(suite)
        if (
            "_NULL_" in u
            or "_ANON_" in u
            or "TLS_NULL_" in u
            or "TLS_ANON_" in u
            or "_WITH_NULL_" in u
            or u.startswith("NULL-")
            or u.startswith("ADH-")
            or u.startswith("AECDH-")
        ):
            offending.append(suite)
    return offending if offending else None


def _check_cs002(suites: List[str]) -> Optional[List[str]]:
    """CS-002: RC4 cipher present."""
    offending = [s for s in suites if "RC4" in _upper(s) or "ARCFOUR" in _upper(s)]
    return offending if offending else None


def _check_cs003(suites: List[str]) -> Optional[List[str]]:
    """CS-003: DES or 3DES (TDEA) cipher present."""
    offending: List[str] = []
    for suite in suites:
        u = _upper(suite)
        if (
            "DES-" in u
            or "-DES-" in u
            or "_DES_" in u
            or "3DES" in u
            or "DES3" in u
            or "TDEA" in u
            or "_DES_EDE_" in u
            or "_3DES_EDE_" in u
        ):
            offending.append(suite)
    return offending if offending else None


def _check_cs004(suites: List[str]) -> Optional[List[str]]:
    """CS-004: Export-grade cipher present."""
    offending: List[str] = []
    for suite in suites:
        u = _upper(suite)
        if (
            "EXPORT" in u
            or "EXP-" in u
            or "EXP_" in u
            or "_40_" in u
            or "RC4_40" in u
            or "RC2_40" in u
            or "DES_40" in u
            or "DH_512" in u
        ):
            offending.append(suite)
    return offending if offending else None


def _check_cs005(suites: List[str]) -> bool:
    """CS-005: No AEAD cipher suite present. Returns True if finding fires."""
    for suite in suites:
        u = _upper(suite)
        if "GCM" in u or "CCM" in u or "CHACHA20" in u:
            return False  # at least one AEAD suite found — no finding
    return True  # no AEAD suite at all


def _check_cs006(versions: List[str]) -> Optional[List[str]]:
    """CS-006: Deprecated TLS/SSL protocol included."""
    offending = [v for v in versions if v.lower() in _DEPRECATED_VERSIONS]
    return offending if offending else None


def _check_cs007(suites: List[str]) -> bool:
    """CS-007: No forward-secrecy cipher suite present.

    Forward secrecy indicators (underscore-delimited, TLS-style):
      DHE_  _DHE_  ECDHE_  _ECDHE_  TLS_ECDHE  TLS_DHE
    Hyphen-delimited (OpenSSL-style):
      ECDHE-  DHE-  EDH-  EECDH-

    Special case: if *any* suite in the list is a TLS 1.3-style suite
    (starts with TLS_AES_ or TLS_CHACHA20_), those inherently provide
    forward secrecy via ephemeral key exchange — do NOT fire CS-007.

    Returns True if the finding fires (no FS found).
    """
    if not suites:
        # Empty list — no suite at all; fire the finding.
        return True

    # If any suite is a TLS 1.3 suite, FS is guaranteed by the protocol.
    has_tls13 = any(
        _upper(s).startswith("TLS_AES_") or _upper(s).startswith("TLS_CHACHA20_")
        for s in suites
    )
    if has_tls13:
        return False  # no finding

    for suite in suites:
        u = _upper(suite)
        if (
            "DHE_" in u
            or "_DHE_" in u
            or "ECDHE_" in u
            or "_ECDHE_" in u
            or u.startswith("TLS_ECDHE")
            or u.startswith("TLS_DHE")
            or "EDH-" in u
            or "EECDH-" in u
            or u.startswith("ECDHE-")
            or u.startswith("DHE-")
        ):
            return False  # found a FS suite — no finding
    return True  # no FS suite found


# ---------------------------------------------------------------------------
# Grade mapping
# ---------------------------------------------------------------------------

def _score_to_grade(score: int) -> str:
    """Convert a numeric risk score (0-100) to a letter grade."""
    if score == 0:
        return "A"
    if score <= 20:
        return "B"
    if score <= 45:
        return "C"
    if score <= 70:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(config: CipherSuiteConfig) -> CSResult:
    """Analyze a TLS cipher suite configuration for security weaknesses.

    Runs all seven checks (CS-001 through CS-007) against the supplied
    CipherSuiteConfig and returns a CSResult with findings, risk score,
    and letter grade.
    """
    findings: List[CSFinding] = []
    fired_weights: List[int] = []

    suites = config.cipher_suites
    versions = config.tls_versions

    # --- CS-001 -----------------------------------------------------------
    offenders = _check_cs001(suites)
    if offenders is not None:
        cid = "CS-001"
        sev, title, weight = _CHECK_META[cid]
        findings.append(CSFinding(
            check_id=cid,
            severity=sev,
            title=title,
            detail=(
                "One or more cipher suites provide no encryption (NULL) or no "
                "authentication (ANON/ADH/AECDH).  An attacker can trivially "
                "decrypt or impersonate the server."
            ),
            weight=weight,
            offending_suites=offenders,
        ))
        fired_weights.append(weight)

    # --- CS-002 -----------------------------------------------------------
    offenders = _check_cs002(suites)
    if offenders is not None:
        cid = "CS-002"
        sev, title, weight = _CHECK_META[cid]
        findings.append(CSFinding(
            check_id=cid,
            severity=sev,
            title=title,
            detail=(
                "RC4 (ARCFOUR) is a broken stream cipher with multiple known "
                "statistical biases and practical plaintext-recovery attacks "
                "(e.g., BEAST, RC4 biases).  RFC 7465 prohibits its use in TLS."
            ),
            weight=weight,
            offending_suites=offenders,
        ))
        fired_weights.append(weight)

    # --- CS-003 -----------------------------------------------------------
    offenders = _check_cs003(suites)
    if offenders is not None:
        cid = "CS-003"
        sev, title, weight = _CHECK_META[cid]
        findings.append(CSFinding(
            check_id=cid,
            severity=sev,
            title=title,
            detail=(
                "DES (56-bit key) and 3DES/TDEA (112-bit effective key) are "
                "considered cryptographically weak.  3DES is vulnerable to the "
                "SWEET32 birthday attack at ~2^32 blocks.  NIST deprecated 3DES "
                "for new applications in 2017 and disallowed it from 2023."
            ),
            weight=weight,
            offending_suites=offenders,
        ))
        fired_weights.append(weight)

    # --- CS-004 -----------------------------------------------------------
    offenders = _check_cs004(suites)
    if offenders is not None:
        cid = "CS-004"
        sev, title, weight = _CHECK_META[cid]
        findings.append(CSFinding(
            check_id=cid,
            severity=sev,
            title=title,
            detail=(
                "Export-grade ciphers were intentionally weakened (40-56 bit "
                "keys) for historical US export regulations.  They are trivially "
                "bruteforceable and exploited by FREAK and Logjam attacks."
            ),
            weight=weight,
            offending_suites=offenders,
        ))
        fired_weights.append(weight)

    # --- CS-005 -----------------------------------------------------------
    if _check_cs005(suites):
        cid = "CS-005"
        sev, title, weight = _CHECK_META[cid]
        findings.append(CSFinding(
            check_id=cid,
            severity=sev,
            title=title,
            detail=(
                "None of the configured cipher suites use an Authenticated "
                "Encryption with Associated Data (AEAD) mode (GCM, CCM, or "
                "ChaCha20-Poly1305).  AEAD provides both confidentiality and "
                "integrity in a single pass, defending against padding-oracle "
                "attacks such as POODLE and Lucky13."
            ),
            weight=weight,
            offending_suites=[],   # list-wide finding — no individual suite is the cause
        ))
        fired_weights.append(weight)

    # --- CS-006 -----------------------------------------------------------
    offenders = _check_cs006(versions)
    if offenders is not None:
        cid = "CS-006"
        sev, title, weight = _CHECK_META[cid]
        findings.append(CSFinding(
            check_id=cid,
            severity=sev,
            title=title,
            detail=(
                f"Deprecated protocol version(s) {offenders} are allowed.  "
                "SSLv2/SSLv3 and TLS 1.0/1.1 have known protocol-level "
                "vulnerabilities (POODLE, BEAST, DROWN) and should be disabled "
                "in favour of TLS 1.2 at a minimum."
            ),
            weight=weight,
            offending_suites=offenders,  # version strings stored here for traceability
        ))
        fired_weights.append(weight)

    # --- CS-007 -----------------------------------------------------------
    if _check_cs007(suites):
        cid = "CS-007"
        sev, title, weight = _CHECK_META[cid]
        findings.append(CSFinding(
            check_id=cid,
            severity=sev,
            title=title,
            detail=(
                "No cipher suite providing forward secrecy (Perfect Forward "
                "Secrecy, PFS) was found.  Without DHE or ECDHE key exchange, a "
                "compromised server private key allows decryption of all past "
                "recorded sessions."
            ),
            weight=weight,
            offending_suites=[],  # list-wide finding — no individual suite is the cause
        ))
        fired_weights.append(weight)

    # --- Score & grade ----------------------------------------------------
    risk_score = min(100, sum(fired_weights))
    grade = _score_to_grade(risk_score)

    return CSResult(
        config_id=config.config_id,
        findings=findings,
        risk_score=risk_score,
        grade=grade,
    )


def analyze_many(configs: List[CipherSuiteConfig]) -> List[CSResult]:
    """Analyze multiple TLS cipher suite configurations in sequence.

    Returns one CSResult per input config in the same order.
    """
    return [analyze(cfg) for cfg in configs]

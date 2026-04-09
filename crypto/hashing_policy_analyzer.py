# hashing_policy_analyzer.py — Cyber Port / CryptoLogik module
#
# Copyright (c) 2026 hiagokinlevi (github.com/hiagokinlevi)
# Licensed under CC BY 4.0  https://creativecommons.org/licenses/by/4.0/
#
# Analyze hashing algorithm configurations for security compliance:
# broken algorithms, unsalted password hashes, inadequate salt sizes,
# inappropriate KDF usage, and hash algorithm reuse across security contexts.
# Pure stdlib — no external dependencies required.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check metadata — maps check ID → (severity, title, weight)
# ---------------------------------------------------------------------------

_CHECK_META: Dict[str, tuple] = {
    "HASH-001": ("CRITICAL", "Broken hash algorithm (MD5/MD4/MD2) used for security-relevant purpose", 45),
    "HASH-002": ("HIGH",     "SHA-1 used for security-relevant purpose (signing/integrity/token/hmac)", 25),
    "HASH-003": ("HIGH",     "Truncated hash output below 128 effective bits", 25),
    "HASH-004": ("CRITICAL", "Password hash stored without salt", 45),
    "HASH-005": ("HIGH",     "Password salt too short (< 16 bytes)", 25),
    "HASH-006": ("HIGH",     "General-purpose hash used for password storage instead of a KDF", 25),
    "HASH-007": ("MEDIUM",   "Hash algorithm reused across different security contexts", 15),
}

# Public constant: weight lookup by check ID.
_CHECK_WEIGHTS: Dict[str, int] = {cid: meta[2] for cid, meta in _CHECK_META.items()}

# ---------------------------------------------------------------------------
# Algorithm classification sets (all lowercase)
# ---------------------------------------------------------------------------

# Algorithms considered cryptographically broken for any security purpose.
_BROKEN_ALGORITHMS = {"md5", "md4", "md2", "sha1", "sha-1", "rc4", "des"}

# Fast / general-purpose hash functions that are NOT suitable as password KDFs.
_FAST_ALGORITHMS = {
    "md5", "md4", "sha1", "sha-1",
    "sha256", "sha-256", "sha512", "sha-512",
    "sha2", "sha3", "sha3-256", "sha3-512",
    "blake2b", "blake2s",
    "ripemd160", "ripemd-160",
}

# Password-specific key-derivation functions.
_PASSWORD_KDFS = {
    "bcrypt",
    "argon2", "argon2id", "argon2i", "argon2d",
    "scrypt",
    "pbkdf2", "pbkdf2_hmac", "pbkdf2-hmac", "pbkdf2_sha256", "pbkdf2_sha512",
}

# Purposes that are security-relevant for HASH-001 / HASH-002.
_SECURITY_PURPOSES = {"password", "integrity", "signing", "token", "hmac"}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class HashingConfig:
    """Input descriptor for a single hashing configuration in the system."""

    config_id: str
    algorithm: str          # e.g. "md5", "sha256", "bcrypt", "argon2"
    purpose: str            # "password", "integrity", "signing", "token", "general", "hmac"
    output_bits: Optional[int]          # effective output bits; None = algorithm default
    salt_length_bytes: Optional[int]    # 0 = explicitly unsalted; None = not applicable
    iterations: Optional[int]           # for KDFs; None if not applicable
    description: str        # human-readable context for the configuration


@dataclass
class HASHFinding:
    """A single security finding produced by one check rule."""

    check_id: str
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int


@dataclass
class HASHResult:
    """Aggregated analysis result for one HashingConfig."""

    config_id: str
    algorithm: str
    purpose: str
    findings: List[HASHFinding]
    risk_score: int     # min(100, sum of weights for unique fired check IDs)
    compliant: bool     # True only when risk_score == 0

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain-dict representation suitable for JSON serialisation."""
        return {
            "config_id": self.config_id,
            "algorithm": self.algorithm,
            "purpose": self.purpose,
            "risk_score": self.risk_score,
            "compliant": self.compliant,
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
        """One-line human-readable summary."""
        status = "COMPLIANT" if self.compliant else "NON-COMPLIANT"
        if not self.findings:
            return (
                f"[{self.config_id}] {status} — "
                f"algorithm={self.algorithm} purpose={self.purpose} — "
                f"risk score {self.risk_score}/100 — no findings"
            )
        ids = ", ".join(f.check_id for f in self.findings)
        return (
            f"[{self.config_id}] {status} — "
            f"algorithm={self.algorithm} purpose={self.purpose} — "
            f"risk score {self.risk_score}/100 — "
            f"{len(self.findings)} finding(s): {ids}"
        )

    def by_severity(self) -> Dict[str, List[HASHFinding]]:
        """Group findings by severity string."""
        result: Dict[str, List[HASHFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.severity, []).append(finding)
        return result


# ---------------------------------------------------------------------------
# Internal check helpers
# ---------------------------------------------------------------------------


def _check_hash001(algo: str, purpose: str) -> Optional[HASHFinding]:
    """HASH-001: MD5/MD4/MD2 used for a security-relevant purpose."""
    if algo in {"md5", "md4", "md2"} and purpose in _SECURITY_PURPOSES:
        meta = _CHECK_META["HASH-001"]
        return HASHFinding(
            check_id="HASH-001",
            severity=meta[0],
            title=meta[1],
            detail=(
                f"Algorithm '{algo}' is cryptographically broken and must not be used "
                f"for security-relevant purpose '{purpose}'. "
                "Replace with SHA-256 or stronger for integrity/signing/token, "
                "or with a password KDF (argon2, bcrypt, scrypt, pbkdf2) for passwords."
            ),
            weight=meta[2],
        )
    return None


def _check_hash002(algo: str, purpose: str) -> Optional[HASHFinding]:
    """HASH-002: SHA-1 used for signing, integrity, token, or hmac purposes.

    Note: SHA-1 for passwords is covered by HASH-006 (wrong KDF), not here.
    """
    sha1_names = {"sha1", "sha-1", "sha160"}
    if algo in sha1_names and purpose in {"signing", "integrity", "token", "hmac"}:
        meta = _CHECK_META["HASH-002"]
        return HASHFinding(
            check_id="HASH-002",
            severity=meta[0],
            title=meta[1],
            detail=(
                f"SHA-1 is deprecated for '{purpose}' use. "
                "SHA-1 is vulnerable to collision attacks (SHAttered) and is prohibited "
                "by NIST SP 800-131A Rev 2 for digital signatures and integrity checks. "
                "Migrate to SHA-256 or SHA-3."
            ),
            weight=meta[2],
        )
    return None


def _check_hash003(output_bits: Optional[int]) -> Optional[HASHFinding]:
    """HASH-003: Effective output bits below 128 (truncated hash)."""
    if output_bits is not None and output_bits < 128:
        meta = _CHECK_META["HASH-003"]
        return HASHFinding(
            check_id="HASH-003",
            severity=meta[0],
            title=meta[1],
            detail=(
                f"Hash output is truncated to {output_bits} bits, which is below the "
                "128-bit minimum for collision resistance. "
                "Use the full output of your chosen algorithm or select a stronger algorithm."
            ),
            weight=meta[2],
        )
    return None


def _check_hash004(algo: str, purpose: str, salt_length_bytes: Optional[int]) -> Optional[HASHFinding]:
    """HASH-004: Password hash stored without salt.

    bcrypt manages its own internal salt; skip the check for bcrypt.
    """
    if purpose != "password":
        return None
    if algo == "bcrypt":
        # bcrypt always embeds a salt internally; the check does not apply.
        return None
    if salt_length_bytes is None or salt_length_bytes == 0:
        meta = _CHECK_META["HASH-004"]
        return HASHFinding(
            check_id="HASH-004",
            severity=meta[0],
            title=meta[1],
            detail=(
                f"Password hash with algorithm '{algo}' has no salt "
                f"(salt_length_bytes={salt_length_bytes!r}). "
                "Unsalted password hashes are trivially reversible with precomputed "
                "rainbow tables. Provide a random salt of at least 16 bytes."
            ),
            weight=meta[2],
        )
    return None


def _check_hash005(algo: str, purpose: str, salt_length_bytes: Optional[int]) -> Optional[HASHFinding]:
    """HASH-005: Password salt present but shorter than 16 bytes.

    bcrypt manages its own internal 16-byte salt; skip the check for bcrypt.
    """
    if purpose != "password":
        return None
    if algo == "bcrypt":
        # bcrypt's internal salt is always 128 bits; no need to check.
        return None
    if (
        salt_length_bytes is not None
        and salt_length_bytes > 0
        and salt_length_bytes < 16
    ):
        meta = _CHECK_META["HASH-005"]
        return HASHFinding(
            check_id="HASH-005",
            severity=meta[0],
            title=meta[1],
            detail=(
                f"Password hash salt is only {salt_length_bytes} byte(s) for algorithm '{algo}'. "
                "NIST SP 800-63B requires at least 32 bits; OWASP recommends ≥ 16 bytes (128 bits). "
                "Increase salt size to at least 16 bytes to prevent precomputation attacks."
            ),
            weight=meta[2],
        )
    return None


def _check_hash006(algo: str, purpose: str) -> Optional[HASHFinding]:
    """HASH-006: General-purpose hash (non-KDF) used for password storage."""
    if purpose != "password":
        return None
    if algo in _FAST_ALGORITHMS:
        meta = _CHECK_META["HASH-006"]
        return HASHFinding(
            check_id="HASH-006",
            severity=meta[0],
            title=meta[1],
            detail=(
                f"Algorithm '{algo}' is a fast general-purpose hash and is not suitable "
                "for password storage. Fast hashes allow high-speed brute-force attacks. "
                "Use a dedicated password KDF: argon2id (preferred), bcrypt, scrypt, or pbkdf2."
            ),
            weight=meta[2],
        )
    return None


def _check_hash007(
    config: HashingConfig,
    algo: str,
    all_configs: List[HashingConfig],
) -> Optional[HASHFinding]:
    """HASH-007: Same algorithm + parameters reused across different security contexts.

    Fires if any other config shares the same algorithm (normalised), the same
    output_bits value, AND the same iterations value, but has a different purpose —
    indicating the algorithm is not scoped to a single security context.
    """
    for other in all_configs:
        # Skip self-comparison.
        if other.config_id == config.config_id:
            continue
        other_algo = other.algorithm.lower().strip()
        # Different algorithm — not a reuse issue.
        if other_algo != algo:
            continue
        # Same algorithm but different purpose — check parameter overlap.
        if other.purpose == config.purpose:
            continue
        # Check that output_bits and iterations also match (same effective config).
        if other.output_bits != config.output_bits:
            continue
        if other.iterations != config.iterations:
            continue
        # Reuse detected: same algorithm + parameters across different purposes.
        meta = _CHECK_META["HASH-007"]
        return HASHFinding(
            check_id="HASH-007",
            severity=meta[0],
            title=meta[1],
            detail=(
                f"Algorithm '{algo}' with the same parameters is used for both "
                f"'{config.purpose}' (config '{config.config_id}') and "
                f"'{other.purpose}' (config '{other.config_id}'). "
                "Sharing hash configurations across security contexts (e.g., password storage "
                "and token generation) reduces isolation. Use distinct algorithms or "
                "parameterisations per context."
            ),
            weight=meta[2],
        )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze(
    config: HashingConfig,
    all_configs: Optional[List[HashingConfig]] = None,
) -> HASHResult:
    """Analyze a hashing configuration for security policy violations.

    Parameters
    ----------
    config:
        The HashingConfig to evaluate.
    all_configs:
        All hashing configs present in the system.  Required for HASH-007
        (cross-context algorithm reuse detection).  Pass None to skip HASH-007.

    Returns
    -------
    HASHResult with per-check findings and an aggregated risk score.
    """
    # Normalise algorithm name once; used by every check.
    algo = config.algorithm.lower().strip()

    findings: List[HASHFinding] = []

    # --- HASH-001: broken algorithm for security purpose ---
    f001 = _check_hash001(algo, config.purpose)
    if f001:
        findings.append(f001)

    # --- HASH-002: SHA-1 for signing / integrity / token / hmac ---
    f002 = _check_hash002(algo, config.purpose)
    if f002:
        findings.append(f002)

    # --- HASH-003: truncated output ---
    f003 = _check_hash003(config.output_bits)
    if f003:
        findings.append(f003)

    # --- HASH-004: password hash without salt ---
    f004 = _check_hash004(algo, config.purpose, config.salt_length_bytes)
    if f004:
        findings.append(f004)

    # --- HASH-005: password salt too short ---
    f005 = _check_hash005(algo, config.purpose, config.salt_length_bytes)
    if f005:
        findings.append(f005)

    # --- HASH-006: fast/general-purpose hash used for passwords ---
    f006 = _check_hash006(algo, config.purpose)
    if f006:
        findings.append(f006)

    # --- HASH-007: algorithm reuse across security contexts ---
    if all_configs is not None:
        f007 = _check_hash007(config, algo, all_configs)
        if f007:
            findings.append(f007)

    # Risk score: sum of weights for unique check IDs, capped at 100.
    fired_ids = {f.check_id for f in findings}
    risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_ids))

    return HASHResult(
        config_id=config.config_id,
        algorithm=config.algorithm,
        purpose=config.purpose,
        findings=findings,
        risk_score=risk_score,
        compliant=(risk_score == 0),
    )


def analyze_many(configs: List[HashingConfig]) -> List[HASHResult]:
    """Analyze a list of HashingConfigs, enabling cross-config HASH-007 checks.

    Each config is analysed with the full list supplied as ``all_configs`` so
    that algorithm reuse across different security contexts is detected.

    Parameters
    ----------
    configs:
        All HashingConfig instances to evaluate together.

    Returns
    -------
    List of HASHResult, one per input config, in the same order.
    """
    return [analyze(cfg, all_configs=configs) for cfg in configs]

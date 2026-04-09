# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Cyber Port — hiagokinlevi
#
# This file is part of the cyber-port portfolio, published under the
# Creative Commons Attribution 4.0 International License (CC BY 4.0).
# You may use, share, and adapt this material for any purpose, provided you
# give appropriate credit. Full license: https://creativecommons.org/licenses/by/4.0/

"""
rng_security_analyzer.py
========================
Cryptographic random number generator (RNG) security analyzer.

Analyzes RNG usage metadata and output samples for security weaknesses
entirely offline — no network calls, no file I/O beyond what the caller
supplies as in-memory objects.

Supported checks
----------------
  RNG-001  Insecure PRNG for cryptographic purpose         CRITICAL  wt 45
  RNG-002  Hardcoded seed value                            CRITICAL  wt 45
  RNG-003  Weak seed source (timestamp / PID)             HIGH      wt 25
  RNG-004  Insufficient key / output size                 HIGH      wt 25
  RNG-005  Insecure RNG for any sensitive purpose         MEDIUM    wt 15
  RNG-006  Sequential / low-entropy sample                HIGH      wt 25
  RNG-007  Statistical frequency imbalance in sample      MEDIUM    wt 15
"""

from __future__ import annotations

import math          # noqa: F401 — available for future statistical helpers
import re            # noqa: F401 — available for pattern matching extensions
import statistics    # noqa: F401 — available for sample statistics extensions
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Check weight registry
# ---------------------------------------------------------------------------

# Maps check ID → integer weight used for risk_score accumulation.
# Only unique fired IDs are summed; duplicates are ignored.
_CHECK_WEIGHTS: Dict[str, int] = {
    "RNG-001": 45,  # Insecure PRNG for cryptographic purpose  (CRITICAL)
    "RNG-002": 45,  # Hardcoded seed value                     (CRITICAL)
    "RNG-003": 25,  # Weak seed source                         (HIGH)
    "RNG-004": 25,  # Insufficient key/output size             (HIGH)
    "RNG-005": 15,  # Insecure RNG for sensitive purpose       (MEDIUM)
    "RNG-006": 25,  # Sequential / low-entropy sample          (HIGH)
    "RNG-007": 15,  # Statistical frequency imbalance          (MEDIUM)
}

# Severity label for each check ID (used when building findings)
_CHECK_SEVERITY: Dict[str, str] = {
    "RNG-001": "CRITICAL",
    "RNG-002": "CRITICAL",
    "RNG-003": "HIGH",
    "RNG-004": "HIGH",
    "RNG-005": "MEDIUM",
    "RNG-006": "HIGH",
    "RNG-007": "MEDIUM",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class RNGUsage:
    """Describes how a random number generator is used in a codebase."""

    # Identifies the PRNG/CSPRNG implementation being used
    rng_type: str  # e.g. "os.urandom", "secrets", "random", "mt19937", …

    # Seeding metadata — None means no explicit seed was found
    seed_value: Optional[int]  # The literal seed value if hardcoded
    seed_type: Optional[str]   # "hardcoded" | "timestamp" | "pid" | "env_var" | "os_entropy" | None

    # How the output is consumed
    purpose: str  # "key_generation" | "iv_generation" | "nonce_generation" |
    #               "session_token" | "password_reset_token" | "csrf_token" | "general"

    key_size_bits: Optional[int]  # Cryptographic output size in bits (None if unknown/NA)
    context: str = "unknown"      # Freeform label of the code location / module


    def to_dict(self) -> Dict:
        """Return a plain-dict representation of this usage record."""
        return {
            "rng_type": self.rng_type,
            "seed_value": self.seed_value,
            "seed_type": self.seed_type,
            "purpose": self.purpose,
            "key_size_bits": self.key_size_bits,
            "context": self.context,
        }


@dataclass
class RNGSample:
    """A batch of raw integer values produced by a single RNG instance."""

    values: List[int]            # The sampled random integers
    bit_length: int = 32         # Declared bit-width of each value (e.g. 32 or 64)
    sample_size: int = 0         # Should equal len(values); set by caller or __post_init__
    rng_type: str = "unknown"    # RNG that produced the sample (if known)
    context: str = "unknown"     # Code location / description

    def __post_init__(self) -> None:
        # Auto-populate sample_size when the caller leaves it at 0
        if self.sample_size == 0:
            self.sample_size = len(self.values)

    def to_dict(self) -> Dict:
        """Return a plain-dict representation of this sample record."""
        return {
            "values": list(self.values),
            "bit_length": self.bit_length,
            "sample_size": self.sample_size,
            "rng_type": self.rng_type,
            "context": self.context,
        }


@dataclass
class RNGFinding:
    """A single security finding produced by a check."""

    check_id: str       # e.g. "RNG-001"
    severity: str       # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    rng_type: str       # Inherited from the analyzed RNGUsage / RNGSample
    context: str        # Location label for the finding
    message: str        # Human-readable description of the problem
    recommendation: str # Actionable remediation guidance

    def to_dict(self) -> Dict:
        """Return a plain-dict representation of this finding."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "rng_type": self.rng_type,
            "context": self.context,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class RNGAnalysisResult:
    """Aggregated result produced by analyzing one RNGUsage or RNGSample."""

    findings: List[RNGFinding] = field(default_factory=list)  # All findings raised
    risk_score: int = 0  # 0–100 composite risk score

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a one-line human-readable summary of the analysis result."""
        if not self.findings:
            return f"Risk score {self.risk_score}/100 — No findings. RNG usage appears secure."
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        parts = [f"{cnt} {sev}" for sev, cnt in sorted(severity_counts.items())]
        return (
            f"Risk score {self.risk_score}/100 — "
            f"{len(self.findings)} finding(s): {', '.join(parts)}."
        )

    def by_severity(self) -> Dict[str, List[RNGFinding]]:
        """Group findings into a dict keyed by severity label."""
        groups: Dict[str, List[RNGFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups

    def to_dict(self) -> Dict:
        """Return a fully serializable dict of this result."""
        return {
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary(),
            "by_severity": {
                sev: [f.to_dict() for f in findings]
                for sev, findings in self.by_severity().items()
            },
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class RNGSecurityAnalyzer:
    """
    Analyzes RNG usage metadata and output samples for security weaknesses.

    All analysis is purely offline — the analyzer never reads from disk or
    the network. Callers supply pre-constructed ``RNGUsage`` or ``RNGSample``
    objects.

    Risk score calculation
    ~~~~~~~~~~~~~~~~~~~~~~
    ``risk_score = min(100, sum(_CHECK_WEIGHTS[id] for id in unique_fired_ids))``
    Each check ID is counted at most once, regardless of how many findings it
    produces.  The score is capped at 100.
    """

    # These RNG types are statistical PRNGs — not suitable for crypto use
    _INSECURE_RNG_TYPES = frozenset(
        {"random", "numpy.random", "java.util.Random", "Math.random", "rand", "mt19937"}
    )

    # Purposes that require a cryptographically secure RNG
    _CRYPTO_PURPOSES = frozenset(
        {"key_generation", "iv_generation", "nonce_generation",
         "session_token", "password_reset_token", "csrf_token"}
    )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_usage(self, usage: RNGUsage) -> RNGAnalysisResult:
        """
        Run all usage-level checks (RNG-001 through RNG-005) against a single
        ``RNGUsage`` record and return a consolidated ``RNGAnalysisResult``.
        """
        findings: List[RNGFinding] = []
        fired_ids: set = set()  # Track which check IDs fired for score dedup

        # ---- RNG-001: Insecure PRNG for cryptographic purpose ----------------
        rng001_fired = False
        if (usage.rng_type in self._INSECURE_RNG_TYPES
                and usage.purpose in self._CRYPTO_PURPOSES):
            findings.append(RNGFinding(
                check_id="RNG-001",
                severity="CRITICAL",
                rng_type=usage.rng_type,
                context=usage.context,
                message=(
                    f"Insecure PRNG '{usage.rng_type}' used for cryptographic "
                    f"purpose '{usage.purpose}'. This generator is not "
                    "cryptographically secure — its output is predictable."
                ),
                recommendation=(
                    "Replace with a CSPRNG such as 'os.urandom' or the 'secrets' "
                    "module (Python), 'SecureRandom' (Java), or 'crypto.randomBytes' "
                    "(Node.js) for all cryptographic operations."
                ),
            ))
            fired_ids.add("RNG-001")
            rng001_fired = True

        # ---- RNG-002: Hardcoded seed value -----------------------------------
        hardcoded = (
            usage.seed_type == "hardcoded"
            or (usage.seed_value is not None
                and usage.seed_type not in ("os_entropy", None))
        )
        if hardcoded:
            seed_display = (
                str(usage.seed_value) if usage.seed_value is not None else "<unknown>"
            )
            findings.append(RNGFinding(
                check_id="RNG-002",
                severity="CRITICAL",
                rng_type=usage.rng_type,
                context=usage.context,
                message=(
                    f"RNG '{usage.rng_type}' seeded with a fixed / predictable "
                    f"value (seed={seed_display}, seed_type='{usage.seed_type}'). "
                    "A constant seed produces an identical, fully deterministic "
                    "output sequence across all executions."
                ),
                recommendation=(
                    "Remove explicit seeding entirely and rely on OS-provided "
                    "entropy (seed_type='os_entropy'). Never seed a PRNG with a "
                    "hardcoded literal, timestamp, or PID in a security context."
                ),
            ))
            fired_ids.add("RNG-002")

        # ---- RNG-003: Weak seed source (timestamp / PID) --------------------
        if usage.seed_type in ("timestamp", "pid"):
            findings.append(RNGFinding(
                check_id="RNG-003",
                severity="HIGH",
                rng_type=usage.rng_type,
                context=usage.context,
                message=(
                    f"RNG '{usage.rng_type}' seeded from a low-entropy source "
                    f"(seed_type='{usage.seed_type}'). Timestamps and PIDs are "
                    "highly guessable and can be brute-forced in seconds."
                ),
                recommendation=(
                    "Seed the RNG from OS-collected entropy "
                    "(e.g., '/dev/urandom', 'os.urandom', or 'secrets') rather "
                    "than from predictable values like the current time or process ID."
                ),
            ))
            fired_ids.add("RNG-003")

        # ---- RNG-004: Insufficient key / output size -------------------------
        crypto_size_purposes = {"key_generation", "iv_generation", "nonce_generation"}
        if (usage.purpose in crypto_size_purposes
                and usage.key_size_bits is not None
                and usage.key_size_bits < 128):
            findings.append(RNGFinding(
                check_id="RNG-004",
                severity="HIGH",
                rng_type=usage.rng_type,
                context=usage.context,
                message=(
                    f"Cryptographic output size of {usage.key_size_bits} bits for "
                    f"purpose '{usage.purpose}' is below the 128-bit security "
                    "minimum. Such small outputs are vulnerable to brute-force attack."
                ),
                recommendation=(
                    "Use at least 128 bits (16 bytes) for IVs and nonces, and at "
                    "least 256 bits (32 bytes) for symmetric encryption keys. "
                    "Prefer 256-bit outputs for all new designs."
                ),
            ))
            fired_ids.add("RNG-004")

        # ---- RNG-005: Insecure RNG for any sensitive purpose -----------------
        # Only fires when RNG-001 has NOT already fired (dedup) and the RNG
        # is in the insecure set regardless of purpose.
        if (not rng001_fired
                and usage.rng_type in self._INSECURE_RNG_TYPES):
            findings.append(RNGFinding(
                check_id="RNG-005",
                severity="MEDIUM",
                rng_type=usage.rng_type,
                context=usage.context,
                message=(
                    f"Insecure statistical PRNG '{usage.rng_type}' detected for "
                    f"purpose '{usage.purpose}'. Even for non-critical uses, "
                    "unpredictability may be assumed by surrounding code."
                ),
                recommendation=(
                    "Prefer 'secrets' or 'os.urandom' for any security-adjacent "
                    "usage. Reserve statistical PRNGs (e.g., 'random', 'numpy.random') "
                    "for non-security purposes such as simulations or shuffling "
                    "non-sensitive data."
                ),
            ))
            fired_ids.add("RNG-005")

        risk_score = self._compute_risk_score(fired_ids)
        return RNGAnalysisResult(findings=findings, risk_score=risk_score)

    def analyze_sample(self, sample: RNGSample) -> RNGAnalysisResult:
        """
        Run all sample-level checks (RNG-006 and RNG-007) against a
        ``RNGSample`` and return a consolidated ``RNGAnalysisResult``.
        """
        findings: List[RNGFinding] = []
        fired_ids: set = set()
        values = sample.values

        # ---- RNG-006: Sequential / low-entropy sample -----------------------
        if len(values) >= 2:
            # Count consecutive pairs whose absolute difference is <= 2
            sequential_count = sum(
                1 for a, b in zip(values, values[1:]) if abs(b - a) <= 2
            )
            pair_count = len(values) - 1  # total number of consecutive pairs
            all_same = len(set(values)) == 1  # degenerate zero-entropy case

            if all_same or (sequential_count / max(1, pair_count) > 0.5):
                reason = (
                    "all values are identical (zero entropy)"
                    if all_same
                    else (
                        f"{sequential_count}/{pair_count} consecutive pairs "
                        "differ by ≤ 2 (> 50% sequential pattern)"
                    )
                )
                findings.append(RNGFinding(
                    check_id="RNG-006",
                    severity="HIGH",
                    rng_type=sample.rng_type,
                    context=sample.context,
                    message=(
                        f"Sample from '{sample.rng_type}' exhibits a sequential or "
                        f"low-entropy pattern: {reason}. This strongly suggests a "
                        "non-random, predictable generator."
                    ),
                    recommendation=(
                        "Replace the generator with a CSPRNG. Run additional "
                        "statistical tests (NIST SP 800-22 or Dieharder) to "
                        "confirm entropy quality before relying on this source."
                    ),
                ))
                fired_ids.add("RNG-006")

        # ---- RNG-007: Statistical frequency imbalance in sample -------------
        if sample.sample_size >= 10:
            # Count occurrences of each value in the sample
            freq: Dict[int, int] = {}
            for v in values:
                freq[v] = freq.get(v, 0) + 1

            n = sample.sample_size
            threshold = max(3, n // 10)  # fire if any single value repeats > threshold
            most_common_count = max(freq.values()) if freq else 0

            if most_common_count > threshold:
                most_common_val = max(freq, key=freq.__getitem__)
                findings.append(RNGFinding(
                    check_id="RNG-007",
                    severity="MEDIUM",
                    rng_type=sample.rng_type,
                    context=sample.context,
                    message=(
                        f"Sample from '{sample.rng_type}' has a highly skewed "
                        f"frequency distribution: value {most_common_val} appears "
                        f"{most_common_count} time(s) in a sample of {n} "
                        f"(threshold={threshold}). This suggests a biased generator."
                    ),
                    recommendation=(
                        "Investigate the RNG implementation for modulo bias or "
                        "truncation artifacts. Use a well-audited CSPRNG and verify "
                        "output distribution with the NIST SP 800-22 test suite."
                    ),
                ))
                fired_ids.add("RNG-007")

        risk_score = self._compute_risk_score(fired_ids)
        return RNGAnalysisResult(findings=findings, risk_score=risk_score)

    def analyze_many_usages(self, usages: List[RNGUsage]) -> List[RNGAnalysisResult]:
        """
        Analyze a list of ``RNGUsage`` records, returning one
        ``RNGAnalysisResult`` per input in the same order.
        """
        return [self.analyze_usage(u) for u in usages]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_score(fired_ids: set) -> int:
        """
        Sum weights for each unique fired check ID and cap the result at 100.
        Each ID is counted at most once even if the same check fires multiple
        times (which the current implementation prevents, but the scoring
        logic is ID-set–based for correctness regardless).
        """
        raw = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids)
        return min(100, raw)  # cap at 100 per spec

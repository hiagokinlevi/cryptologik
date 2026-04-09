# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 hiagokinlevi — Cyber Port
# Creative Commons Attribution 4.0 International License
# https://creativecommons.org/licenses/by/4.0/
"""
Password Policy Security Analyzer
==================================
Evaluates password policy configurations for security weaknesses.

No live authentication calls are made — this module operates entirely on
policy configuration objects, making it safe to run in CI pipelines and
automated audits without access to production systems.

Checks performed
-----------------
PWD-001   Minimum length below recommended (NIST SP 800-63B: >= 12 chars)
PWD-002   No complexity requirements configured at all
PWD-003   Password expiry too long or completely disabled
PWD-004   No account lockout policy (or lockout disabled / unlimited attempts)
PWD-005   Password reuse not restricted (fewer than 5 previous passwords blocked)
PWD-006   Insecure or weak hashing algorithm (fast hashes, plaintext, or unknown)
PWD-007   MFA not required

Usage::

    from crypto.password_policy_analyzer import (
        PasswordPolicy,
        PasswordHashConfig,
        LockoutPolicy,
        PasswordPolicyAnalyzer,
    )

    policy = PasswordPolicy(
        name="prod-users",
        min_length=14,
        require_uppercase=True,
        require_lowercase=True,
        require_digits=True,
        require_special_chars=True,
        max_age_days=90,
        history_count=10,
        lockout=LockoutPolicy(enabled=True, max_attempts=5, lockout_duration_minutes=15),
        hash_config=PasswordHashConfig(algorithm="argon2id"),
        require_mfa=True,
    )

    analyzer = PasswordPolicyAnalyzer()
    result = analyzer.analyze(policy)
    print(result.summary())
    for finding in result.findings:
        print(finding.to_dict())
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# ---------------------------------------------------------------------------
# Weight table — maps check ID to the score contribution when fired.
# risk_score = min(100, sum of unique fired check weights).
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "PWD-001": 25,  # Minimum length below 12
    "PWD-002": 15,  # No complexity requirements
    "PWD-003": 15,  # Expiry too long or disabled
    "PWD-004": 25,  # No lockout policy
    "PWD-005": 20,  # Password reuse not restricted
    "PWD-006": 45,  # Insecure hashing (CRITICAL variant)
    "PWD-006-WF": 25,  # Weak work factor only (HIGH variant, separate weight key)
    "PWD-007": 25,  # MFA not required
}

# Algorithms considered fast/unsuitable for password storage (CRITICAL)
_INSECURE_ALGORITHMS = frozenset(["plaintext", "md5", "sha1", "sha256", "ntlm"])

# Algorithms that are acceptable for password storage
_ACCEPTABLE_ALGORITHMS = frozenset(["bcrypt", "argon2id", "pbkdf2-sha256", "sha512-crypt"])


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class PasswordHashConfig:
    """Describes how passwords are hashed at rest."""

    # Hashing algorithm in use.  Well-known values:
    #   "bcrypt", "argon2id", "pbkdf2-sha256", "sha512-crypt"  — acceptable
    #   "sha256", "sha1", "md5", "plaintext", "ntlm"           — insecure
    algorithm: str

    # Cost/iteration parameter (bcrypt cost, argon2 iterations, pbkdf2 iterations).
    # None means the value is unknown or not applicable.
    work_factor: Optional[int] = None

    # Minimum acceptable work factor for this algorithm.
    # Default of 10 covers bcrypt (cost >= 10).  Override per-config as needed.
    min_work_factor: int = 10

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary."""
        return {
            "algorithm": self.algorithm,
            "work_factor": self.work_factor,
            "min_work_factor": self.min_work_factor,
        }


@dataclass
class LockoutPolicy:
    """Account lockout configuration."""

    # Whether lockout is active.  False = lockout exists in config but is off.
    enabled: bool = False

    # Maximum consecutive failures before lockout.  None = unlimited.
    max_attempts: Optional[int] = None

    # How long (minutes) the account remains locked after triggering lockout.
    lockout_duration_minutes: Optional[int] = None

    # How long (minutes) before the failure counter resets automatically.
    reset_counter_after_minutes: Optional[int] = None

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary."""
        return {
            "enabled": self.enabled,
            "max_attempts": self.max_attempts,
            "lockout_duration_minutes": self.lockout_duration_minutes,
            "reset_counter_after_minutes": self.reset_counter_after_minutes,
        }


@dataclass
class PasswordPolicy:
    """Complete password policy configuration for a single context."""

    # Human-readable name or identifier for this policy (e.g., "prod-users").
    name: str

    # Minimum required password length.  NIST SP 800-63B recommends >= 12.
    min_length: int = 8

    # Maximum allowed password length.  None = no upper bound enforced.
    max_length: Optional[int] = None

    # Complexity character-class requirements.
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_digits: bool = False
    require_special_chars: bool = False

    # Days until a password must be changed.  None or 0 = never expires.
    max_age_days: Optional[int] = None

    # Minimum days a password must be kept before changing.
    min_age_days: int = 0

    # How many previous passwords are blocked from reuse.  0 = no restriction.
    history_count: int = 0

    # Lockout configuration.  None = no lockout policy at all.
    lockout: Optional[LockoutPolicy] = None

    # Hashing algorithm configuration.  None = unknown/not configured.
    hash_config: Optional[PasswordHashConfig] = None

    # Whether multi-factor authentication is required.
    require_mfa: bool = False

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary (nested objects also serialized)."""
        return {
            "name": self.name,
            "min_length": self.min_length,
            "max_length": self.max_length,
            "require_uppercase": self.require_uppercase,
            "require_lowercase": self.require_lowercase,
            "require_digits": self.require_digits,
            "require_special_chars": self.require_special_chars,
            "max_age_days": self.max_age_days,
            "min_age_days": self.min_age_days,
            "history_count": self.history_count,
            "lockout": self.lockout.to_dict() if self.lockout is not None else None,
            "hash_config": self.hash_config.to_dict() if self.hash_config is not None else None,
            "require_mfa": self.require_mfa,
        }


@dataclass
class PolicyFinding:
    """A single security weakness identified in a password policy."""

    # Check identifier (e.g., "PWD-001").
    check_id: str

    # CRITICAL / HIGH / MEDIUM / LOW / INFO
    severity: str

    # Name of the policy that triggered this finding.
    policy_name: str

    # Human-readable description of the weakness found.
    message: str

    # Actionable guidance to remediate the finding.
    recommendation: str

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "policy_name": self.policy_name,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class PolicyAnalysisResult:
    """Aggregated result of analyzing a single PasswordPolicy."""

    # The policy that was analyzed.
    policy: PasswordPolicy

    # All findings raised by the analysis (may be empty for a clean policy).
    findings: List[PolicyFinding] = field(default_factory=list)

    # Composite risk score 0–100.
    # Computed as min(100, sum of _CHECK_WEIGHTS for each unique fired check ID).
    risk_score: int = 0

    def summary(self) -> str:
        """Return a one-line human-readable summary of the analysis result."""
        if not self.findings:
            return (
                f"Policy '{self.policy.name}': No issues found. "
                f"Risk score: {self.risk_score}/100."
            )
        finding_word = "finding" if len(self.findings) == 1 else "findings"
        severities = [f.severity for f in self.findings]
        sev_counts: Dict[str, int] = {}
        for s in severities:
            sev_counts[s] = sev_counts.get(s, 0) + 1
        sev_summary = ", ".join(
            f"{count} {sev}" for sev, count in sorted(sev_counts.items())
        )
        return (
            f"Policy '{self.policy.name}': {len(self.findings)} {finding_word} "
            f"({sev_summary}). Risk score: {self.risk_score}/100."
        )

    def by_severity(self) -> Dict[str, List[PolicyFinding]]:
        """Return findings grouped by severity level.

        All five severity levels are always present as keys (empty lists when
        no findings at that level exist), so callers can rely on key existence.
        """
        grouped: Dict[str, List[PolicyFinding]] = {
            SEVERITY_CRITICAL: [],
            SEVERITY_HIGH: [],
            SEVERITY_MEDIUM: [],
            SEVERITY_LOW: [],
            SEVERITY_INFO: [],
        }
        for finding in self.findings:
            # Guard against unexpected severity strings by defaulting to INFO.
            bucket = finding.severity if finding.severity in grouped else SEVERITY_INFO
            grouped[bucket].append(finding)
        return grouped

    def to_dict(self) -> Dict:
        """Serialize the full result to a plain dictionary."""
        return {
            "policy": self.policy.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "summary": self.summary(),
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class PasswordPolicyAnalyzer:
    """Stateless analyzer that evaluates PasswordPolicy objects for weaknesses.

    No external calls are made — all analysis is performed on the in-memory
    policy objects passed to :py:meth:`analyze` or :py:meth:`analyze_many`.

    Example::

        analyzer = PasswordPolicyAnalyzer()
        result = analyzer.analyze(my_policy)
        print(result.summary())
    """

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def analyze(self, policy: PasswordPolicy) -> PolicyAnalysisResult:
        """Analyze a single PasswordPolicy and return a PolicyAnalysisResult.

        Args:
            policy: The password policy configuration to evaluate.

        Returns:
            A :class:`PolicyAnalysisResult` containing all findings and the
            computed risk score.
        """
        findings: List[PolicyFinding] = []

        # Run each check in a deterministic order.
        self._check_pwd001(policy, findings)
        self._check_pwd002(policy, findings)
        self._check_pwd003(policy, findings)
        self._check_pwd004(policy, findings)
        self._check_pwd005(policy, findings)
        self._check_pwd006(policy, findings)
        self._check_pwd007(policy, findings)

        risk_score = self._compute_risk_score(findings)
        return PolicyAnalysisResult(policy=policy, findings=findings, risk_score=risk_score)

    def analyze_many(self, policies: List[PasswordPolicy]) -> List[PolicyAnalysisResult]:
        """Analyze multiple PasswordPolicy objects.

        Args:
            policies: Iterable of policy configurations to evaluate.

        Returns:
            A list of :class:`PolicyAnalysisResult` objects in the same order
            as the input policies.
        """
        return [self.analyze(p) for p in policies]

    # ------------------------------------------------------------------
    # Risk score computation
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_score(findings: List[PolicyFinding]) -> int:
        """Sum weights for every unique check ID present in findings.

        PWD-006 has two weight variants:
        - "PWD-006"    (CRITICAL) — used when the algorithm itself is insecure
        - "PWD-006-WF" (HIGH)     — used internally for weak work-factor only

        The weight key stored on the finding's check_id determines which
        bucket is used.  Duplicate check IDs only count once.
        """
        seen_ids: set = set()
        total = 0
        for finding in findings:
            cid = finding.check_id
            if cid not in seen_ids:
                seen_ids.add(cid)
                total += _CHECK_WEIGHTS.get(cid, 0)
        return min(100, total)

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_pwd001(policy: PasswordPolicy, findings: List[PolicyFinding]) -> None:
        """PWD-001 — Minimum length below recommended (< 12 characters)."""
        if policy.min_length < 12:
            findings.append(PolicyFinding(
                check_id="PWD-001",
                severity=SEVERITY_HIGH,
                policy_name=policy.name,
                message=(
                    f"Minimum password length is {policy.min_length}, "
                    f"which is below the recommended minimum of 12 characters."
                ),
                recommendation=(
                    "Set min_length to at least 12 characters per NIST SP 800-63B guidance. "
                    "Consider 16 or more for privileged accounts."
                ),
            ))

    @staticmethod
    def _check_pwd002(policy: PasswordPolicy, findings: List[PolicyFinding]) -> None:
        """PWD-002 — No complexity requirements configured at all."""
        if (
            not policy.require_uppercase
            and not policy.require_lowercase
            and not policy.require_digits
            and not policy.require_special_chars
        ):
            findings.append(PolicyFinding(
                check_id="PWD-002",
                severity=SEVERITY_MEDIUM,
                policy_name=policy.name,
                message="No character-class complexity requirements are enforced.",
                recommendation=(
                    "Enable at least two of: uppercase, lowercase, digit, or special-character "
                    "requirements. Combined with a strong minimum length, this significantly "
                    "increases password entropy."
                ),
            ))

    @staticmethod
    def _check_pwd003(policy: PasswordPolicy, findings: List[PolicyFinding]) -> None:
        """PWD-003 — Password expiry too long or completely disabled.

        NIST recommends avoiding forced rotation unless compromise is suspected,
        so this is MEDIUM rather than HIGH.  However, many organizations still
        set upper bounds, and excessively long or disabled expiry is flagged.
        """
        fire = False
        if policy.max_age_days is None or policy.max_age_days == 0:
            # Passwords never expire
            fire = True
            detail = "Passwords are configured to never expire."
        elif policy.max_age_days > 365:
            fire = True
            detail = (
                f"Password expiry is set to {policy.max_age_days} days, "
                f"which exceeds the recommended maximum of 365 days."
            )
        else:
            detail = ""

        if fire:
            findings.append(PolicyFinding(
                check_id="PWD-003",
                severity=SEVERITY_MEDIUM,
                policy_name=policy.name,
                message=detail,
                recommendation=(
                    "Consider setting max_age_days to 365 or fewer. "
                    "While NIST SP 800-63B discourages arbitrary rotation, "
                    "setting a reasonable upper bound limits exposure from undetected compromise."
                ),
            ))

    @staticmethod
    def _check_pwd004(policy: PasswordPolicy, findings: List[PolicyFinding]) -> None:
        """PWD-004 — No effective account lockout policy configured."""
        fire = False
        if policy.lockout is None:
            fire = True
            detail = "No lockout policy is configured."
        elif not policy.lockout.enabled:
            fire = True
            detail = "A lockout policy exists but is disabled."
        elif policy.lockout.max_attempts is None:
            fire = True
            detail = (
                "Lockout is enabled but max_attempts is None (unlimited), "
                "which does not prevent brute-force attacks."
            )

        if fire:
            findings.append(PolicyFinding(
                check_id="PWD-004",
                severity=SEVERITY_HIGH,
                policy_name=policy.name,
                message=detail,
                recommendation=(
                    "Enable lockout with a max_attempts of 5–10 and set a "
                    "lockout_duration_minutes >= 15. "
                    "Consider progressive delays before full account lockout."
                ),
            ))

    @staticmethod
    def _check_pwd005(policy: PasswordPolicy, findings: List[PolicyFinding]) -> None:
        """PWD-005 — Password reuse not restricted (fewer than 5 previous passwords blocked)."""
        if policy.history_count < 5:
            findings.append(PolicyFinding(
                check_id="PWD-005",
                severity=SEVERITY_HIGH,
                policy_name=policy.name,
                message=(
                    f"Password history count is {policy.history_count}. "
                    f"At least the last 5 passwords should be blocked from reuse."
                ),
                recommendation=(
                    "Set history_count to at least 5. "
                    "This prevents users from cycling through a small set of familiar passwords, "
                    "which defeats forced-rotation policies."
                ),
            ))

    @staticmethod
    def _check_pwd006(policy: PasswordPolicy, findings: List[PolicyFinding]) -> None:
        """PWD-006 — Insecure or weak hashing algorithm.

        Two sub-cases:
        1. Algorithm is known-insecure (fast hash, plaintext, or unknown) → CRITICAL
        2. Algorithm is acceptable but work_factor is below minimum → HIGH
        """
        if policy.hash_config is None:
            # No hash config — assume unknown/potentially insecure
            findings.append(PolicyFinding(
                check_id="PWD-006",
                severity=SEVERITY_CRITICAL,
                policy_name=policy.name,
                message=(
                    "No hashing configuration is specified. "
                    "The password storage mechanism is unknown and potentially insecure."
                ),
                recommendation=(
                    "Configure hash_config with a memory-hard algorithm such as "
                    "argon2id (recommended), bcrypt (cost >= 12), or "
                    "pbkdf2-sha256 (iterations >= 600000 per OWASP 2023)."
                ),
            ))
            return

        algo = policy.hash_config.algorithm.lower()

        if algo in _INSECURE_ALGORITHMS:
            # Fast hash or plaintext — always CRITICAL regardless of work factor
            findings.append(PolicyFinding(
                check_id="PWD-006",
                severity=SEVERITY_CRITICAL,
                policy_name=policy.name,
                message=(
                    f"Password hashing algorithm '{policy.hash_config.algorithm}' is "
                    f"cryptographically unsuitable for password storage. "
                    f"Fast hashes and plaintext storage are trivially reversible."
                ),
                recommendation=(
                    "Replace with argon2id, bcrypt (cost >= 12), or "
                    "pbkdf2-sha256 (iterations >= 600000). "
                    "Migrate existing hashes at next login opportunity."
                ),
            ))
            return  # Work-factor check is not applicable for insecure algorithms

        if algo not in _ACCEPTABLE_ALGORITHMS:
            # Unknown algorithm — treat as potentially insecure (CRITICAL)
            findings.append(PolicyFinding(
                check_id="PWD-006",
                severity=SEVERITY_CRITICAL,
                policy_name=policy.name,
                message=(
                    f"Password hashing algorithm '{policy.hash_config.algorithm}' is not "
                    f"recognized as a safe password hashing scheme."
                ),
                recommendation=(
                    "Use a well-known password hashing algorithm: "
                    "argon2id (recommended), bcrypt, or pbkdf2-sha256."
                ),
            ))
            return

        # Algorithm is acceptable — check work factor for algorithms that have one
        work_factor = policy.hash_config.work_factor
        if work_factor is None:
            # Cannot verify work factor — no finding raised (benefit of doubt)
            return

        # Determine per-algorithm minimum work factor
        if algo == "pbkdf2-sha256":
            # OWASP recommends 600,000 iterations; the spec uses a configurable
            # min_work_factor, but we enforce at least 100,000 as our floor.
            effective_min = max(policy.hash_config.min_work_factor, 100_000)
        else:
            # bcrypt, argon2id, sha512-crypt — use the configured min_work_factor
            effective_min = policy.hash_config.min_work_factor

        if work_factor < effective_min:
            findings.append(PolicyFinding(
                check_id="PWD-006-WF",
                severity=SEVERITY_HIGH,
                policy_name=policy.name,
                message=(
                    f"Work factor {work_factor} for '{policy.hash_config.algorithm}' is below "
                    f"the minimum recommended value of {effective_min}."
                ),
                recommendation=(
                    f"Increase the work factor to at least {effective_min}. "
                    f"For bcrypt, a cost of 12 or higher is recommended. "
                    f"For pbkdf2-sha256, use at least 600,000 iterations per OWASP 2023."
                ),
            ))

    @staticmethod
    def _check_pwd007(policy: PasswordPolicy, findings: List[PolicyFinding]) -> None:
        """PWD-007 — MFA not required."""
        if not policy.require_mfa:
            findings.append(PolicyFinding(
                check_id="PWD-007",
                severity=SEVERITY_HIGH,
                policy_name=policy.name,
                message="Multi-factor authentication (MFA) is not required.",
                recommendation=(
                    "Require MFA for all users. Password-only authentication is susceptible "
                    "to phishing, credential stuffing, and brute-force attacks. "
                    "TOTP, hardware keys (FIDO2/WebAuthn), or push-based MFA are all acceptable."
                ),
            ))

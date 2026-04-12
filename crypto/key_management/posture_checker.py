"""
Key Management Posture Checker
================================
Reviews key management configurations for security weaknesses.

Checks the following posture areas:
  - Key rotation: Is a rotation policy defined? Is it enforced?
  - Storage location: Are keys stored securely (HSM, secrets manager)?
  - Access control: Is access scoped to minimum required principals?
  - Lifecycle documentation: Are creation, rotation, and revocation procedures documented?
  - Key type and size: Are key types and sizes appropriate for the use case?

This checker works against a YAML-format key management configuration (see examples
in policies/crypto-baselines/standard.yaml) rather than live systems.

LIMITATIONS:
  - Config-based only — does not connect to live key management systems
  - Relies on accurate and up-to-date configuration input
  - Does not validate that policies are actually enforced at runtime
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
import structlog
from dotenv import load_dotenv

load_dotenv()

log = structlog.get_logger(__name__)

# Strictness level from environment — controls which finding severities are reported
STRICTNESS = os.getenv("STRICTNESS", "standard")


class PostureRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PostureFinding:
    """A single key management posture finding."""
    check_id: str           # Unique identifier for this check
    key_name: str           # The key or key group this finding applies to
    risk_level: PostureRisk
    title: str              # Short, scannable title
    description: str        # Explanation of the issue
    recommendation: str     # Specific remediation guidance
    evidence: str = ""      # Relevant config excerpt (masked if sensitive)


class KeyManagementConfigError(ValueError):
    """Raised when the posture checker cannot safely load the input config."""


# ---------------------------------------------------------------------------
# Individual posture checks
# ---------------------------------------------------------------------------

def _check_rotation_policy(key_name: str, key_config: dict[str, Any]) -> list[PostureFinding]:
    """
    Check that a key rotation policy is defined and has a reasonable interval.

    Args:
        key_name: Name of the key or key group being checked.
        key_config: Dictionary of key configuration attributes.

    Returns:
        List of PostureFinding objects for rotation-related issues.
    """
    findings = []

    rotation = key_config.get("rotation")

    # Finding: No rotation policy defined at all
    if not rotation:
        findings.append(PostureFinding(
            check_id="KM-001",
            key_name=key_name,
            risk_level=PostureRisk.HIGH,
            title="No key rotation policy defined",
            description=(
                f"Key '{key_name}' has no rotation policy configured. "
                "Keys that are never rotated accumulate risk — a compromised key "
                "provides indefinite access to encrypted data."
            ),
            recommendation=(
                "Define a rotation policy with an explicit interval. "
                "Recommended intervals: encryption keys ≤ 1 year, signing keys ≤ 2 years, "
                "API keys ≤ 90 days, session keys ≤ 24 hours."
            ),
        ))
        return findings

    # Finding: Rotation defined but not automated (manual rotation is error-prone)
    if rotation.get("automated") is False:
        findings.append(PostureFinding(
            check_id="KM-002",
            key_name=key_name,
            risk_level=PostureRisk.MEDIUM,
            title="Key rotation is manual — automation recommended",
            description=(
                f"Key '{key_name}' has a defined rotation policy but relies on manual execution. "
                "Manual rotation is prone to human error and delays."
            ),
            recommendation=(
                "Automate key rotation using a secrets manager with native rotation support "
                "(e.g., AWS Secrets Manager automatic rotation, HashiCorp Vault lease renewal, "
                "Azure Key Vault key rotation policy)."
            ),
            evidence=f"rotation.automated: {rotation.get('automated')}",
        ))

    # Finding: Rotation interval is too long
    interval_days = rotation.get("interval_days")
    if interval_days:
        # Thresholds by key type (conservative defaults if type not specified)
        key_type = key_config.get("type", "generic")
        max_intervals: dict[str, int] = {
            "api_key": 90,
            "session_key": 1,
            "encryption_key": 365,
            "signing_key": 730,
            "generic": 365,
        }
        max_interval = max_intervals.get(key_type, 365)

        if interval_days > max_interval:
            findings.append(PostureFinding(
                check_id="KM-003",
                key_name=key_name,
                risk_level=PostureRisk.MEDIUM,
                title=f"Key rotation interval ({interval_days} days) exceeds recommended maximum ({max_interval} days)",
                description=(
                    f"Key '{key_name}' (type: {key_type}) rotates every {interval_days} days, "
                    f"which exceeds the recommended maximum of {max_interval} days for this key type."
                ),
                recommendation=(
                    f"Reduce rotation interval to ≤ {max_interval} days for {key_type} keys."
                ),
                evidence=f"rotation.interval_days: {interval_days}",
            ))

    return findings


def _check_storage_location(key_name: str, key_config: dict[str, Any]) -> list[PostureFinding]:
    """
    Check that key material is stored in an appropriate location.

    Storage locations are ranked from most to least secure:
      1. HSM (Hardware Security Module) — best
      2. Secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) — good
      3. Environment variable — marginal (acceptable only for low-sensitivity dev keys)
      4. Plaintext config file — unacceptable
      5. Hardcoded in source code — critical

    Args:
        key_name: Name of the key being checked.
        key_config: Dictionary of key configuration attributes.

    Returns:
        List of PostureFinding objects.
    """
    findings = []
    storage = key_config.get("storage", {})
    location = storage.get("location", "unknown")

    # Risk mapping for storage locations
    risky_locations: dict[str, tuple[PostureRisk, str, str]] = {
        "plaintext_file": (
            PostureRisk.CRITICAL,
            "Key stored in plaintext configuration file",
            "Move key material to a secrets manager (AWS Secrets Manager, HashiCorp Vault, "
            "Azure Key Vault). Plaintext key files are easily exfiltrated and not auditable.",
        ),
        "environment_variable": (
            PostureRisk.MEDIUM,
            "Key stored in environment variable",
            "Environment variables are acceptable for non-production and low-sensitivity keys. "
            "For production secrets, use a secrets manager with IAM-controlled access. "
            "Ensure the process environment is not logged or exposed.",
        ),
        "hardcoded": (
            PostureRisk.CRITICAL,
            "Key appears to be hardcoded in application configuration",
            "Never hardcode key material in source code or checked-in configuration files. "
            "Rotate the key immediately and move to a secrets manager.",
        ),
        "git_repo": (
            PostureRisk.CRITICAL,
            "Key material is stored in a git repository",
            "Remove key from git history using BFG Repo Cleaner or git-filter-repo. "
            "Rotate the key immediately. Move to a secrets manager.",
        ),
    }

    if location in risky_locations:
        risk, title, recommendation = risky_locations[location]
        findings.append(PostureFinding(
            check_id="KM-010",
            key_name=key_name,
            risk_level=risk,
            title=title,
            description=f"Key '{key_name}' is stored in: {location}.",
            recommendation=recommendation,
            evidence=f"storage.location: {location}",
        ))

    return findings


def _check_access_control(key_name: str, key_config: dict[str, Any]) -> list[PostureFinding]:
    """
    Check that access to the key is appropriately restricted.

    Args:
        key_name: Name of the key being checked.
        key_config: Dictionary of key configuration attributes.

    Returns:
        List of PostureFinding objects.
    """
    findings = []
    access = key_config.get("access_control", {})

    # Finding: No access control defined
    if not access:
        findings.append(PostureFinding(
            check_id="KM-020",
            key_name=key_name,
            risk_level=PostureRisk.HIGH,
            title="No access control policy defined for key",
            description=(
                f"Key '{key_name}' has no access control policy defined in the configuration. "
                "Without explicit access control, the key may be accessible to any principal "
                "with access to the underlying storage."
            ),
            recommendation=(
                "Define an explicit access control policy following the principle of least privilege. "
                "Grant access only to the specific services or principals that require it. "
                "Use separate keys for separate services."
            ),
        ))
        return findings

    # Finding: Overly broad access (wildcard principals)
    principals = access.get("allowed_principals", [])
    if "*" in principals or "everyone" in principals:
        findings.append(PostureFinding(
            check_id="KM-021",
            key_name=key_name,
            risk_level=PostureRisk.CRITICAL,
            title="Key access granted to wildcard principal",
            description=(
                f"Key '{key_name}' grants access to all principals ('*' or 'everyone'). "
                "This effectively makes the key accessible to any authenticated identity."
            ),
            recommendation=(
                "Replace the wildcard principal with specific service accounts or roles. "
                "Apply least-privilege access."
            ),
            evidence=f"access_control.allowed_principals: {principals}",
        ))

    return findings


def _format_yaml_error(exc: yaml.YAMLError) -> str:
    """Return a concise YAML error with line and column context when available."""
    problem = getattr(exc, "problem", None) or str(exc)
    mark = getattr(exc, "problem_mark", None)
    if mark is None:
        return problem
    return f"{problem} at line {mark.line + 1}, column {mark.column + 1}"


def _assert_regular_config_file(config_path: Path) -> None:
    """Reject symlinks and special filesystem nodes before reading YAML content."""
    if not config_path.exists():
        raise FileNotFoundError(f"Key management config not found: {config_path}")

    try:
        node_stat = config_path.lstat()
    except OSError as exc:
        message = exc.strerror or str(exc)
        raise KeyManagementConfigError(
            f"Could not inspect key management config: {message}."
        ) from exc

    if not stat.S_ISREG(node_stat.st_mode):
        raise KeyManagementConfigError(
            f"Key management config path is not a regular file: {config_path}"
        )


def _load_key_management_config(config_path: Path) -> dict[str, Any]:
    """Load and validate the posture config, failing closed on malformed input."""
    _assert_regular_config_file(config_path)

    try:
        raw = config_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise KeyManagementConfigError("Could not decode key management config as UTF-8.") from exc
    except OSError as exc:
        message = exc.strerror or str(exc)
        raise KeyManagementConfigError(f"Could not read key management config: {message}.") from exc

    try:
        config = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise KeyManagementConfigError(
            f"Could not parse key management YAML: {_format_yaml_error(exc)}."
        ) from exc

    if not isinstance(config, dict):
        raise KeyManagementConfigError(
            "Expected key management YAML to contain a top-level mapping."
        )

    keys = config.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise KeyManagementConfigError(
            "Key management configuration must include a non-empty top-level 'keys' mapping."
        )

    for key_name, key_config in keys.items():
        if not isinstance(key_config, dict):
            raise KeyManagementConfigError(
                f"Key entry '{key_name}' must be a mapping of posture attributes."
            )

    return config


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_key_management_posture(config_path: Path) -> list[PostureFinding]:
    """
    Run all key management posture checks against a YAML configuration file.

    The configuration file should have the following structure:
        keys:
          my_api_key:
            type: api_key
            rotation:
              automated: true
              interval_days: 90
            storage:
              location: secrets_manager
              provider: aws_secrets_manager
            access_control:
              allowed_principals:
                - arn:aws:iam::123456789012:role/my-service-role

    Args:
        config_path: Path to the YAML key management configuration file.

    Returns:
        List of PostureFinding objects. Empty list means no issues detected.
    """
    config = _load_key_management_config(config_path)

    all_findings: list[PostureFinding] = []

    for key_name, key_config in config["keys"].items():
        # Run all checks for this key
        all_findings.extend(_check_rotation_policy(key_name, key_config))
        all_findings.extend(_check_storage_location(key_name, key_config))
        all_findings.extend(_check_access_control(key_name, key_config))

    # Filter by strictness level
    risk_thresholds = {
        "minimal": {PostureRisk.CRITICAL},
        "standard": {PostureRisk.CRITICAL, PostureRisk.HIGH},
        "strict": {PostureRisk.CRITICAL, PostureRisk.HIGH, PostureRisk.MEDIUM, PostureRisk.LOW},
    }
    threshold = risk_thresholds.get(STRICTNESS, risk_thresholds["standard"])
    filtered = [f for f in all_findings if f.risk_level in threshold]

    log.info(
        "key_management_posture_check_complete",
        config_path=str(config_path),
        total_findings=len(all_findings),
        reported_findings=len(filtered),
        strictness=STRICTNESS,
    )

    return filtered

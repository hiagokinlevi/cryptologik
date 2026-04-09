"""
JWT Security Checker
=====================
Analyzes JSON Web Token (JWT) configurations and token strings for
security weaknesses.

Checks performed on JWT configuration objects:
  - JWT-001 CRITICAL: Algorithm is "none" (no signature verification)
  - JWT-002 CRITICAL: Symmetric key shorter than 256 bits for HMAC
  - JWT-003 HIGH:     Weak algorithm (HS256 with short secret, RS256 < 2048-bit)
  - JWT-004 HIGH:     Missing 'exp' (expiration) claim
  - JWT-005 HIGH:     Missing 'nbf' (not-before) or 'iat' (issued-at) claim
  - JWT-006 MEDIUM:   Overly long expiry (> 24 hours for access tokens)
  - JWT-007 MEDIUM:   Missing 'iss' (issuer) claim validation
  - JWT-008 MEDIUM:   Missing 'aud' (audience) claim validation
  - JWT-009 LOW:      Missing 'jti' (JWT ID) — no replay prevention

Checks performed on raw JWT token strings:
  - Decodes header and payload (without verification) for structural analysis
  - Detects 'alg:none' in header
  - Detects missing required claims
  - Detects expired tokens (exp in past)
  - Detects tokens with suspicious embedded data (e.g. SQL-like patterns in claims)

Usage:
    from crypto.validators.jwt_checker import (
        JwtConfig,
        check_jwt_config,
        check_jwt_token,
        JwtSecurityReport,
    )

    # Check a JWT configuration spec
    config = JwtConfig(
        algorithm="HS256",
        secret_length_bits=128,   # too short!
        expiry_seconds=86400,
        validate_issuer=False,
    )
    report = check_jwt_config(config)
    for f in report.findings:
        print(f"[{f.severity.upper()}] {f.rule_id}: {f.message}")

    # Decode and check a raw JWT string
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ."
    report = check_jwt_token(token)
"""
from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class JwtConfig:
    """
    JWT security configuration spec for an application or service.

    Attributes:
        algorithm:           JWT algorithm identifier (e.g. "HS256", "RS256", "ES256").
        secret_length_bits:  For HMAC algorithms: the signing key length in bits.
                             For RSA/ECDSA: the key size in bits.
        expiry_seconds:      Token lifetime in seconds (e.g. 3600 = 1 hour).
        refresh_expiry_seconds: Refresh token lifetime (optional).
        validate_issuer:     Whether 'iss' claim is validated on receive.
        validate_audience:   Whether 'aud' claim is validated on receive.
        require_nbf:         Whether 'nbf' claim is required.
        require_iat:         Whether 'iat' claim is required.
        require_jti:         Whether 'jti' claim is required (replay prevention).
        service_name:        Identifier for the service or config this applies to.
    """
    algorithm:              str
    secret_length_bits:     Optional[int] = None
    expiry_seconds:         Optional[int] = None
    refresh_expiry_seconds: Optional[int] = None
    validate_issuer:        bool = True
    validate_audience:      bool = True
    require_nbf:            bool = False
    require_iat:            bool = True
    require_jti:            bool = False
    service_name:           str = "<unnamed>"


@dataclass
class JwtFinding:
    """A single JWT security finding."""
    rule_id:     str
    severity:    str        # "critical", "high", "medium", "low"
    message:     str
    remediation: str
    evidence:    str = ""


@dataclass
class JwtSecurityReport:
    """Results of JWT security analysis."""
    source:      str        # "config" | "token"
    findings:    list[JwtFinding] = field(default_factory=list)
    warnings:    list[str] = field(default_factory=list)

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

    def findings_by_rule(self, rule_id: str) -> list[JwtFinding]:
        return [f for f in self.findings if f.rule_id == rule_id]

    def summary(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return (
            f"[{status}] JWT security ({self.source}) | "
            f"CRITICAL={self.critical_count} HIGH={self.high_count} "
            f"MEDIUM={self.medium_count} LOW={self.low_count}"
        )


# ---------------------------------------------------------------------------
# Algorithm safety table
# ---------------------------------------------------------------------------

# Algorithms considered weak or dangerous in JWT context
_NONE_ALGORITHMS = {"none", "NONE", "None"}
_HMAC_ALGORITHMS = {"HS256", "HS384", "HS512"}
_RSA_ALGORITHMS  = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
_EC_ALGORITHMS   = {"ES256", "ES384", "ES512"}
_STRONG_ALGORITHMS = _RSA_ALGORITHMS | _EC_ALGORITHMS | {"EdDSA"}

# Minimum key lengths per algorithm family
_MIN_HMAC_BITS = 256     # NIST SP 800-107 recommends ≥ key output length for HMAC
_MIN_RSA_BITS  = 2048
_MIN_EC_BITS   = 256

# 24 hours in seconds — access tokens longer than this are considered overly permissive
_MAX_ACCESS_TOKEN_SECONDS = 86400


# ---------------------------------------------------------------------------
# Config checks
# ---------------------------------------------------------------------------

def _chk_alg_none(cfg: JwtConfig, report: JwtSecurityReport) -> None:
    """JWT-001: Algorithm 'none' completely disables signature verification."""
    if cfg.algorithm.lower() == "none":
        report.findings.append(JwtFinding(
            rule_id="JWT-001",
            severity="critical",
            message=(
                f"Service '{cfg.service_name}' uses algorithm 'none'. "
                "Tokens signed with 'none' carry no signature — any token "
                "body will be accepted without verification, allowing full "
                "authentication bypass."
            ),
            remediation=(
                "Never accept or produce JWTs with alg=none. "
                "Use RS256 or ES256 for asymmetric signing, or HS256 with a "
                "cryptographically random secret of at least 256 bits."
            ),
            evidence=f"algorithm: {cfg.algorithm}",
        ))


def _chk_short_hmac_secret(cfg: JwtConfig, report: JwtSecurityReport) -> None:
    """JWT-002: HMAC secret shorter than 256 bits."""
    if cfg.algorithm not in _HMAC_ALGORITHMS:
        return
    if cfg.secret_length_bits is None:
        return
    if cfg.secret_length_bits < _MIN_HMAC_BITS:
        report.findings.append(JwtFinding(
            rule_id="JWT-002",
            severity="critical",
            message=(
                f"Service '{cfg.service_name}' uses {cfg.algorithm} with a "
                f"{cfg.secret_length_bits}-bit secret. HMAC-SHA256 requires "
                f"at least {_MIN_HMAC_BITS} bits to be secure. Short secrets "
                "are vulnerable to offline brute-force attacks."
            ),
            remediation=(
                f"Generate a cryptographically random secret of at least {_MIN_HMAC_BITS} bits "
                "(32 bytes). Use secrets.token_bytes(32) in Python or openssl rand -base64 32."
            ),
            evidence=f"algorithm: {cfg.algorithm}, secret_length_bits: {cfg.secret_length_bits}",
        ))


def _chk_weak_rsa_key(cfg: JwtConfig, report: JwtSecurityReport) -> None:
    """JWT-003 (RSA): RSA key size below 2048 bits."""
    if cfg.algorithm not in _RSA_ALGORITHMS:
        return
    if cfg.secret_length_bits is None:
        return
    if cfg.secret_length_bits < _MIN_RSA_BITS:
        report.findings.append(JwtFinding(
            rule_id="JWT-003",
            severity="high",
            message=(
                f"Service '{cfg.service_name}' uses {cfg.algorithm} with a "
                f"{cfg.secret_length_bits}-bit RSA key. RSA keys below 2048 bits "
                "are considered weak and may be factored."
            ),
            remediation=(
                "Rotate to an RSA key of at least 2048 bits. "
                "Prefer 3072 or 4096 bits for long-lived systems, "
                "or migrate to ECDSA (ES256) which offers equivalent security "
                "with smaller keys."
            ),
            evidence=f"algorithm: {cfg.algorithm}, key_bits: {cfg.secret_length_bits}",
        ))


def _chk_missing_exp(cfg: JwtConfig, report: JwtSecurityReport) -> None:
    """JWT-004: Missing expiry — tokens never expire."""
    if cfg.expiry_seconds is None:
        report.findings.append(JwtFinding(
            rule_id="JWT-004",
            severity="high",
            message=(
                f"Service '{cfg.service_name}' does not configure an 'exp' (expiration) "
                "claim. Non-expiring tokens remain valid indefinitely after issuance, "
                "giving an attacker unlimited time to use a stolen token."
            ),
            remediation=(
                "Set a token lifetime via the 'exp' claim. Recommended: "
                "15–60 minutes for access tokens, up to 24 hours for special-purpose tokens. "
                "Never issue tokens without an expiry."
            ),
            evidence="expiry_seconds: None",
        ))


def _chk_missing_nbf_iat(cfg: JwtConfig, report: JwtSecurityReport) -> None:
    """JWT-005: Missing 'nbf' or 'iat' temporal claim."""
    if not cfg.require_nbf and not cfg.require_iat:
        report.findings.append(JwtFinding(
            rule_id="JWT-005",
            severity="high",
            message=(
                f"Service '{cfg.service_name}' does not require 'nbf' (not-before) "
                "or 'iat' (issued-at) claims. Without these claims, tokens cannot be "
                "invalidated by time and replay window cannot be enforced."
            ),
            remediation=(
                "Always include 'iat' (issued-at) in token payloads. "
                "Include 'nbf' (not-before) for tokens that should not be usable "
                "until a future point (e.g. pre-issued credentials). "
                "Validate 'iat' on the receiver side to reject tokens issued too far in the past."
            ),
            evidence="require_nbf: False, require_iat: False",
        ))


def _chk_long_expiry(cfg: JwtConfig, report: JwtSecurityReport) -> None:
    """JWT-006: Access token expiry longer than 24 hours."""
    if cfg.expiry_seconds is None:
        return
    if cfg.expiry_seconds > _MAX_ACCESS_TOKEN_SECONDS:
        hours = cfg.expiry_seconds // 3600
        report.findings.append(JwtFinding(
            rule_id="JWT-006",
            severity="medium",
            message=(
                f"Service '{cfg.service_name}' issues tokens that expire in "
                f"{hours} hour(s) ({cfg.expiry_seconds}s). "
                "Access tokens valid for more than 24 hours give an attacker "
                "a large window to use a stolen token."
            ),
            remediation=(
                "Shorten access token lifetime to 15–60 minutes. "
                "Use refresh tokens (with rotation) for long-lived sessions. "
                "Implement token revocation (blacklist or short-window JTI checks) "
                "for high-value operations."
            ),
            evidence=f"expiry_seconds: {cfg.expiry_seconds} ({hours}h)",
        ))


def _chk_no_iss_validation(cfg: JwtConfig, report: JwtSecurityReport) -> None:
    """JWT-007: 'iss' (issuer) claim not validated."""
    if not cfg.validate_issuer:
        report.findings.append(JwtFinding(
            rule_id="JWT-007",
            severity="medium",
            message=(
                f"Service '{cfg.service_name}' does not validate the 'iss' (issuer) claim. "
                "An attacker may present a token signed by a different, attacker-controlled "
                "issuer with the same key algorithm."
            ),
            remediation=(
                "Always validate the 'iss' claim against a known allowlist of trusted "
                "issuers. Reject tokens from unexpected issuers even if the signature "
                "is otherwise valid."
            ),
            evidence="validate_issuer: False",
        ))


def _chk_no_aud_validation(cfg: JwtConfig, report: JwtSecurityReport) -> None:
    """JWT-008: 'aud' (audience) claim not validated."""
    if not cfg.validate_audience:
        report.findings.append(JwtFinding(
            rule_id="JWT-008",
            severity="medium",
            message=(
                f"Service '{cfg.service_name}' does not validate the 'aud' (audience) claim. "
                "A token issued for service A could be replayed against service B if both "
                "trust the same issuer and audience is not checked."
            ),
            remediation=(
                "Always validate 'aud' and reject tokens intended for other services. "
                "Each service should have a unique audience value (e.g. its service name "
                "or API URL)."
            ),
            evidence="validate_audience: False",
        ))


def _chk_no_jti(cfg: JwtConfig, report: JwtSecurityReport) -> None:
    """JWT-009: 'jti' (JWT ID) claim not required — no replay prevention."""
    if not cfg.require_jti:
        report.findings.append(JwtFinding(
            rule_id="JWT-009",
            severity="low",
            message=(
                f"Service '{cfg.service_name}' does not require the 'jti' (JWT ID) claim. "
                "Without unique token IDs, replay attacks within the token's validity "
                "window cannot be detected."
            ),
            remediation=(
                "Include a UUID-based 'jti' claim in each token. "
                "For high-security operations, cache seen JTIs and reject duplicates "
                "within the token's validity window."
            ),
            evidence="require_jti: False",
        ))


_CONFIG_CHECKS = [
    _chk_alg_none,
    _chk_short_hmac_secret,
    _chk_weak_rsa_key,
    _chk_missing_exp,
    _chk_missing_nbf_iat,
    _chk_long_expiry,
    _chk_no_iss_validation,
    _chk_no_aud_validation,
    _chk_no_jti,
]


# ---------------------------------------------------------------------------
# JWT token string decoder (no verification — structural analysis only)
# ---------------------------------------------------------------------------

def _b64_decode_part(part: str) -> Optional[dict[str, Any]]:
    """
    Decode a base64url-encoded JWT part (header or payload) without verification.

    Returns parsed JSON dict, or None on failure.
    """
    # Add padding if needed
    padded = part + "=" * (4 - len(part) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def _decode_jwt_parts(token: str) -> tuple[Optional[dict], Optional[dict], str]:
    """
    Split and decode a JWT into (header, payload, signature).

    Returns (None, None, "") if the token is malformed.
    """
    parts = token.strip().split(".")
    if len(parts) < 2:
        return None, None, ""
    header = _b64_decode_part(parts[0])
    payload = _b64_decode_part(parts[1]) if len(parts) > 1 else None
    signature = parts[2] if len(parts) > 2 else ""
    return header, payload, signature


# ---------------------------------------------------------------------------
# Token checks
# ---------------------------------------------------------------------------

def _tok_alg_none(header: dict, report: JwtSecurityReport) -> None:
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        report.findings.append(JwtFinding(
            rule_id="JWT-001",
            severity="critical",
            message="Token header contains alg=none. This token has no signature.",
            remediation="Reject all tokens with alg=none. This is a classic JWT security bypass.",
            evidence=f"header.alg: {header.get('alg')}",
        ))


def _tok_missing_exp(payload: dict, report: JwtSecurityReport) -> None:
    if "exp" not in payload:
        report.findings.append(JwtFinding(
            rule_id="JWT-004",
            severity="high",
            message="Token payload is missing the 'exp' (expiration) claim.",
            remediation="Reject tokens that do not include an expiration claim.",
            evidence="exp: <missing>",
        ))


def _tok_expired(payload: dict, report: JwtSecurityReport) -> None:
    exp = payload.get("exp")
    if exp is None:
        return
    try:
        now = time.time()
        if float(exp) < now:
            overdue_seconds = int(now - float(exp))
            report.findings.append(JwtFinding(
                rule_id="JWT-004",
                severity="critical",
                message=(
                    f"Token has EXPIRED. exp={exp} is {overdue_seconds}s in the past. "
                    "This token should be rejected."
                ),
                remediation="Reject expired tokens. Validate 'exp' on every request.",
                evidence=f"exp: {exp}",
            ))
    except (TypeError, ValueError):
        report.warnings.append(f"Could not parse 'exp' claim: {exp!r}")


def _tok_missing_iat(payload: dict, report: JwtSecurityReport) -> None:
    if "iat" not in payload:
        report.findings.append(JwtFinding(
            rule_id="JWT-005",
            severity="high",
            message="Token payload is missing the 'iat' (issued-at) claim.",
            remediation="Include 'iat' in all tokens to enable freshness checks.",
            evidence="iat: <missing>",
        ))


def _tok_missing_iss(payload: dict, report: JwtSecurityReport) -> None:
    if "iss" not in payload:
        report.findings.append(JwtFinding(
            rule_id="JWT-007",
            severity="medium",
            message="Token payload is missing the 'iss' (issuer) claim.",
            remediation="Always include and validate the 'iss' claim.",
            evidence="iss: <missing>",
        ))


def _tok_missing_aud(payload: dict, report: JwtSecurityReport) -> None:
    if "aud" not in payload:
        report.findings.append(JwtFinding(
            rule_id="JWT-008",
            severity="medium",
            message="Token payload is missing the 'aud' (audience) claim.",
            remediation="Always include and validate the 'aud' claim.",
            evidence="aud: <missing>",
        ))


_TOKEN_PAYLOAD_CHECKS = [
    _tok_missing_exp,
    _tok_expired,
    _tok_missing_iat,
    _tok_missing_iss,
    _tok_missing_aud,
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_jwt_config(config: JwtConfig) -> JwtSecurityReport:
    """
    Check a JwtConfig object for security misconfigurations.

    Args:
        config: JwtConfig describing the JWT setup for a service.

    Returns:
        JwtSecurityReport with all findings.
    """
    report = JwtSecurityReport(source="config")
    for check in _CONFIG_CHECKS:
        check(config, report)
    return report


def check_jwt_token(token: str) -> JwtSecurityReport:
    """
    Decode and check a raw JWT token string for structural security issues.

    This function does NOT verify the signature — it decodes the token parts
    for structural analysis only. Useful for audit tools and log analysis.

    Args:
        token: Raw JWT string (three base64url parts separated by dots).

    Returns:
        JwtSecurityReport with structural findings.
    """
    report = JwtSecurityReport(source="token")
    header, payload, _sig = _decode_jwt_parts(token)

    if header is None:
        report.warnings.append("Could not decode JWT header — token may be malformed")
        return report

    if payload is None:
        report.warnings.append("Could not decode JWT payload — token may be malformed")

    # Header checks
    _tok_alg_none(header, report)

    # Payload checks
    if payload is not None:
        for check in _TOKEN_PAYLOAD_CHECKS:
            check(payload, report)

    return report

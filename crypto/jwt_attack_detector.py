"""
JWT Attack Pattern Detector
==============================
Detects JWT-specific attack patterns in tokens submitted to services:
algorithm confusion attacks, key confusion, token replay indicators,
and suspicious claim patterns that suggest tampering.

Analyzes raw JWT strings without requiring the signing key — focuses
on structural and claim-based attack patterns.

Check IDs
----------
JWT-ATK-001   Algorithm confusion attack (RS256 token submitted with HS256 hint)
JWT-ATK-002   None algorithm attack (alg=none or alg=None)
JWT-ATK-003   Embedded JWK key in header (self-signed token attack)
JWT-ATK-004   KID parameter injection (SQL/path traversal in kid claim)
JWT-ATK-005   Abnormally long token (> max_token_length bytes)
JWT-ATK-006   Claims timing anomaly (nbf in far future or exp in far past)
JWT-ATK-007   Suspicious issuer (iss claim contains URL or localhost)

Usage::

    from crypto.jwt_attack_detector import JWTAttackDetector, JWTAnalysisResult

    raw_token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0."
    detector = JWTAttackDetector()
    result = detector.analyze(raw_token)
    for finding in result.findings:
        print(finding.to_dict())
"""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity enumeration
# ---------------------------------------------------------------------------

class JWTSeverity(Enum):
    """Risk severity levels for JWT attack findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ---------------------------------------------------------------------------
# Finding and result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class JWTAttackFinding:
    """Single attack-pattern finding from JWT analysis.

    Attributes:
        check_id:     Unique identifier for the check rule (e.g. JWT-ATK-001).
        severity:     Risk level assigned to the finding.
        title:        Short human-readable name for the attack pattern.
        detail:       Extended description of what was detected and why it matters.
        evidence:     Raw token fragment or claim value that triggered the finding.
        remediation:  Recommended action for the service owner.
    """

    check_id: str
    severity: JWTSeverity
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict:
        """Return a JSON-serialisable representation of this finding."""
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }

    def summary(self) -> str:
        """One-line summary: check_id + severity + title."""
        return f"[{self.check_id}] {self.severity.value}: {self.title}"


@dataclass
class JWTAnalysisResult:
    """Aggregated output of analyzing a single JWT token.

    Attributes:
        token_preview:  First 30 characters of the raw token followed by '...'.
        header:         Decoded JWT header as a plain dict.
        claims:         Decoded JWT claims/payload as a plain dict.
        findings:       Ordered list of detected attack findings.
        risk_score:     Aggregate numeric risk (0–100); higher is worse.
        is_attack:      True when risk_score exceeds the detector threshold.
        generated_at:   Unix timestamp when analysis was performed.
    """

    token_preview: str
    header: Dict
    claims: Dict
    findings: List[JWTAttackFinding] = field(default_factory=list)
    risk_score: int = 0
    is_attack: bool = False
    generated_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def total_findings(self) -> int:
        """Total number of findings regardless of severity."""
        return len(self.findings)

    @property
    def critical_findings(self) -> List[JWTAttackFinding]:
        """Subset of findings with CRITICAL severity."""
        return [f for f in self.findings if f.severity == JWTSeverity.CRITICAL]

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        """Return a fully JSON-serialisable representation."""
        return {
            "token_preview": self.token_preview,
            "header": self.header,
            "claims": self.claims,
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "is_attack": self.is_attack,
            "generated_at": self.generated_at,
            "total_findings": self.total_findings,
        }

    def summary(self) -> str:
        """Compact one-line summary suitable for logging."""
        return f"{self.token_preview} risk={self.risk_score} findings={self.total_findings}"


# ---------------------------------------------------------------------------
# Per-check risk weights
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "JWT-ATK-001": 45,
    "JWT-ATK-002": 50,
    "JWT-ATK-003": 45,
    "JWT-ATK-004": 40,
    "JWT-ATK-005": 20,
    "JWT-ATK-006": 25,
    "JWT-ATK-007": 20,
}


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _decode_segment(segment: str) -> Dict:
    """Base64url-decode a single JWT segment and JSON-parse it.

    Adds the required '=' padding before decoding so callers do not need to
    manage padding themselves.  Returns an empty dict on any failure so that
    downstream checks can safely treat a missing key as absent.

    Args:
        segment: Raw base64url-encoded JWT segment (header or payload).

    Returns:
        Decoded JSON object as a Python dict, or {} on any error.
    """
    try:
        # Restore standard base64 padding (JWT strips trailing '=')
        padded = segment + "=" * (4 - len(segment) % 4)
        raw_bytes = base64.urlsafe_b64decode(padded)
        return json.loads(raw_bytes.decode("utf-8"))
    except Exception:  # noqa: BLE001 — intentionally broad for robustness
        return {}


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class JWTAttackDetector:
    """Stateless detector that inspects JWT tokens for known attack patterns.

    The detector does **not** verify cryptographic signatures; it focuses
    exclusively on structural and semantic indicators of attack attempts.

    Args:
        max_token_length:            Tokens exceeding this byte count trigger
                                     JWT-ATK-005.  Default: 4096.
        future_nbf_tolerance_seconds: Allow clocks to be at most this many
                                     seconds ahead before flagging nbf as
                                     suspicious.  Default: 300 (5 min).
        past_exp_tolerance_seconds:  Allow exp to be this many seconds in the
                                     past before flagging as a replay token.
                                     Default: 3600 (1 hour).
        attack_threshold:            Minimum risk_score required for
                                     is_attack=True.  Default: 0, so any
                                     finding marks the token as an attack.
    """

    def __init__(
        self,
        max_token_length: int = 4096,
        future_nbf_tolerance_seconds: int = 300,
        past_exp_tolerance_seconds: int = 3600,
        attack_threshold: int = 0,
    ) -> None:
        self.max_token_length = max_token_length
        self.future_nbf_tolerance_seconds = future_nbf_tolerance_seconds
        self.past_exp_tolerance_seconds = past_exp_tolerance_seconds
        self.attack_threshold = attack_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, token: str, _now: Optional[float] = None) -> JWTAnalysisResult:
        """Analyze a single raw JWT string for attack patterns.

        Args:
            token: Raw JWT string (may include or omit trailing signature).
            _now:  Override current Unix time (used in tests; not part of the
                   public interface).

        Returns:
            JWTAnalysisResult populated with all triggered findings.
        """
        now: float = _now if _now is not None else time.time()
        token_preview = token[:30] + "..." if len(token) > 30 else token
        findings: List[JWTAttackFinding] = []

        # Split into parts -----------------------------------------------
        parts = token.split(".")

        if len(parts) < 2:
            # Malformed — cannot proceed with header/claim checks
            findings.append(
                JWTAttackFinding(
                    check_id="JWT-ATK-000",
                    severity=JWTSeverity.HIGH,
                    title="Malformed JWT token",
                    detail=(
                        "The submitted token does not contain the minimum two "
                        "base64url segments separated by '.' required by RFC 7519."
                    ),
                    evidence=token_preview,
                    remediation=(
                        "Reject the token immediately; do not attempt to process it."
                    ),
                )
            )
            result = JWTAnalysisResult(
                token_preview=token_preview,
                header={},
                claims={},
                findings=findings,
                generated_at=now,
            )
            result.risk_score = 0
            result.is_attack = False
            return result

        # Decode header and claims ----------------------------------------
        header: Dict = _decode_segment(parts[0])
        claims: Dict = _decode_segment(parts[1]) if len(parts) >= 2 else {}

        # ------------------------------------------------------------------
        # JWT-ATK-001 — Algorithm confusion attack
        # ------------------------------------------------------------------
        # Heuristic A: both "alg" and "x5c" present in the header
        # (attacker embeds an X.509 cert to confuse an RS256 verifier into
        # treating the cert's public key as an HMAC secret).
        # Heuristic B: an HS-family algorithm is declared but the payload
        # segment is large (>200 base64 chars), which is consistent with an
        # RSA-key-sized HMAC secret being used.
        alg: str = str(header.get("alg", ""))
        alg_upper = alg.upper()
        payload_b64_len = len(parts[1]) if len(parts) >= 2 else 0

        atk001_fired = False
        atk001_evidence = ""
        if "x5c" in header or "x5u" in header:
            # Certificate reference alongside any alg is suspicious
            atk001_fired = True
            atk001_evidence = f"alg={alg!r}, x5c/x5u present in header"
        elif (
            alg_upper.startswith("HS")
            and payload_b64_len > 200
        ):
            # HS-family alg with unusually large payload — possible key
            # confusion where an RSA public key is used as the HMAC secret.
            atk001_fired = True
            atk001_evidence = (
                f"alg={alg!r}, payload segment length={payload_b64_len} chars"
            )

        if atk001_fired:
            findings.append(
                JWTAttackFinding(
                    check_id="JWT-ATK-001",
                    severity=JWTSeverity.CRITICAL,
                    title="Algorithm confusion / key confusion attack",
                    detail=(
                        "The token exhibits indicators of an algorithm confusion "
                        "attack: either a certificate reference (x5c/x5u) is "
                        "embedded alongside an HMAC algorithm, or an HS-family "
                        "algorithm is paired with an unusually large payload "
                        "consistent with an RSA public key being used as the "
                        "HMAC secret."
                    ),
                    evidence=atk001_evidence,
                    remediation=(
                        "Enforce a strict allow-list of accepted algorithms "
                        "server-side.  Never allow the token header to dictate "
                        "the algorithm used for verification."
                    ),
                )
            )

        # ------------------------------------------------------------------
        # JWT-ATK-002 — None algorithm attack
        # ------------------------------------------------------------------
        alg_lower = alg.lower().strip()
        if alg_lower in ("none", "null", ""):
            findings.append(
                JWTAttackFinding(
                    check_id="JWT-ATK-002",
                    severity=JWTSeverity.CRITICAL,
                    title="None algorithm attack",
                    detail=(
                        f"The token declares alg={alg!r}.  The 'none' algorithm "
                        "instructs JWT libraries to skip signature verification "
                        "entirely, allowing an attacker to forge arbitrary claims."
                    ),
                    evidence=f"alg={alg!r}",
                    remediation=(
                        "Explicitly reject any token whose 'alg' header is "
                        "'none', 'null', or an empty string.  Never allow the "
                        "token to specify its own algorithm."
                    ),
                )
            )

        # ------------------------------------------------------------------
        # JWT-ATK-003 — Embedded JWK / JKU key injection
        # ------------------------------------------------------------------
        if "jwk" in header or "jku" in header:
            key_ref = "jwk" if "jwk" in header else "jku"
            findings.append(
                JWTAttackFinding(
                    check_id="JWT-ATK-003",
                    severity=JWTSeverity.HIGH,
                    title="Embedded JWK / JKU self-signed key attack",
                    detail=(
                        f"The token header contains a '{key_ref}' parameter. "
                        "An attacker can embed a self-controlled key and trick "
                        "vulnerable verifiers into fetching or trusting it, "
                        "allowing signature forgery."
                    ),
                    evidence=f"header['{key_ref}'] is present",
                    remediation=(
                        "Reject any token containing 'jwk' or 'jku' header "
                        "parameters unless your implementation explicitly pins "
                        "and validates the key origin against a trust store."
                    ),
                )
            )

        # ------------------------------------------------------------------
        # JWT-ATK-004 — KID parameter injection
        # ------------------------------------------------------------------
        kid_value: Optional[str] = header.get("kid")
        if kid_value is not None:
            kid_str = str(kid_value)
            kid_lower = kid_str.lower()

            # SQL injection keywords
            sql_patterns = ["select", "union", "drop", "--", "'"]
            # Path traversal patterns
            path_patterns = ["../", "..\\", "/etc/", "/dev/"]

            matched_indicators: List[str] = []
            for kw in sql_patterns:
                if kw in kid_lower:
                    matched_indicators.append(f"SQL keyword {kw!r}")
            for pt in path_patterns:
                if pt in kid_str:  # path traversal is case-sensitive
                    matched_indicators.append(f"path traversal {pt!r}")

            if matched_indicators:
                findings.append(
                    JWTAttackFinding(
                        check_id="JWT-ATK-004",
                        severity=JWTSeverity.CRITICAL,
                        title="KID parameter injection (SQL / path traversal)",
                        detail=(
                            "The 'kid' header parameter contains characters or "
                            "keywords associated with SQL injection or path "
                            "traversal attacks.  If the verifier uses 'kid' to "
                            "look up keys in a database or filesystem, this could "
                            "lead to unauthorized key substitution or data "
                            "exfiltration."
                        ),
                        evidence=(
                            f"kid={kid_str!r}; matched: "
                            + ", ".join(matched_indicators)
                        ),
                        remediation=(
                            "Validate 'kid' against a strict allow-list of "
                            "known key identifiers.  Never interpolate the raw "
                            "'kid' value into SQL queries or filesystem paths."
                        ),
                    )
                )

        # ------------------------------------------------------------------
        # JWT-ATK-005 — Abnormally long token
        # ------------------------------------------------------------------
        token_len = len(token)
        if token_len > self.max_token_length:
            findings.append(
                JWTAttackFinding(
                    check_id="JWT-ATK-005",
                    severity=JWTSeverity.MEDIUM,
                    title="Abnormally long JWT token",
                    detail=(
                        f"Token length is {token_len} bytes, which exceeds the "
                        f"configured limit of {self.max_token_length} bytes.  "
                        "Oversized tokens may indicate payload-stuffing, DoS "
                        "attempts, or attempts to overflow log buffers."
                    ),
                    evidence=f"token length={token_len}",
                    remediation=(
                        "Enforce a maximum token size at the API gateway or "
                        "middleware layer before any decoding occurs."
                    ),
                )
            )

        # ------------------------------------------------------------------
        # JWT-ATK-006 — Claims timing anomaly
        # ------------------------------------------------------------------
        nbf = claims.get("nbf")
        exp = claims.get("exp")

        if nbf is not None:
            try:
                nbf_float = float(nbf)
                if nbf_float > now + self.future_nbf_tolerance_seconds:
                    findings.append(
                        JWTAttackFinding(
                            check_id="JWT-ATK-006",
                            severity=JWTSeverity.HIGH,
                            title="Claims timing anomaly: nbf far in the future",
                            detail=(
                                f"The 'nbf' (not-before) claim is set to "
                                f"{nbf_float}, which is "
                                f"{nbf_float - now:.0f} seconds in the future "
                                f"(tolerance: {self.future_nbf_tolerance_seconds}s). "
                                "This may indicate clock manipulation or a crafted "
                                "token intended to bypass time-based access controls."
                            ),
                            evidence=f"nbf={nbf_float}, now={now:.0f}",
                            remediation=(
                                "Reject tokens whose 'nbf' exceeds the current "
                                "server time plus an acceptable clock-skew margin."
                            ),
                        )
                    )
            except (TypeError, ValueError):
                pass  # Non-numeric nbf — not flagged here; treat as absent

        if exp is not None:
            try:
                exp_float = float(exp)
                if exp_float < now - self.past_exp_tolerance_seconds:
                    findings.append(
                        JWTAttackFinding(
                            check_id="JWT-ATK-006",
                            severity=JWTSeverity.MEDIUM,
                            title="Claims timing anomaly: exp far in the past (replay)",
                            detail=(
                                f"The 'exp' (expiry) claim is {exp_float}, which "
                                f"expired {now - exp_float:.0f} seconds ago "
                                f"(tolerance: {self.past_exp_tolerance_seconds}s). "
                                "A token this old being submitted is a strong "
                                "indicator of a token-replay attack."
                            ),
                            evidence=f"exp={exp_float}, now={now:.0f}",
                            remediation=(
                                "Reject expired tokens and consider implementing "
                                "short-lived tokens with refresh-token rotation "
                                "to minimise the replay window."
                            ),
                        )
                    )
            except (TypeError, ValueError):
                pass  # Non-numeric exp — not flagged here; treat as absent

        # ------------------------------------------------------------------
        # JWT-ATK-007 — Suspicious issuer
        # ------------------------------------------------------------------
        iss = claims.get("iss")
        if iss is not None:
            iss_str = str(iss)
            iss_lower = iss_str.lower()
            if (
                "http" in iss_lower
                or "localhost" in iss_lower
                or "127.0.0.1" in iss_str
            ):
                findings.append(
                    JWTAttackFinding(
                        check_id="JWT-ATK-007",
                        severity=JWTSeverity.MEDIUM,
                        title="Suspicious issuer claim",
                        detail=(
                            f"The 'iss' claim is {iss_str!r}, which contains a "
                            "URL or localhost reference.  Attackers may craft "
                            "tokens that appear to originate from a locally "
                            "hosted or attacker-controlled issuer to confuse "
                            "audience validation logic."
                        ),
                        evidence=f"iss={iss_str!r}",
                        remediation=(
                            "Validate the 'iss' claim against a strict allow-list "
                            "of trusted issuer identifiers.  Reject tokens whose "
                            "issuer is a URL, IP address, or localhost variant."
                        ),
                    )
                )

        # ------------------------------------------------------------------
        # Compute risk_score (sum unique check weights, cap at 100)
        # ------------------------------------------------------------------
        fired_ids = {f.check_id for f in findings}
        raw_score = sum(
            _CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids
        )
        risk_score = min(raw_score, 100)

        result = JWTAnalysisResult(
            token_preview=token_preview,
            header=header,
            claims=claims,
            findings=findings,
            risk_score=risk_score,
            is_attack=risk_score > self.attack_threshold,
            generated_at=now,
        )
        return result

    def analyze_many(self, tokens: List[str]) -> List[JWTAnalysisResult]:
        """Analyze a batch of JWT tokens.

        Args:
            tokens: Sequence of raw JWT strings to inspect.

        Returns:
            List of JWTAnalysisResult in the same order as the input.
        """
        return [self.analyze(t) for t in tokens]

    def filter_attacks(self, tokens: List[str]) -> List[JWTAnalysisResult]:
        """Return only the results flagged as attacks.

        Args:
            tokens: Sequence of raw JWT strings to inspect.

        Returns:
            Subset of analysis results where is_attack=True.
        """
        return [r for r in self.analyze_many(tokens) if r.is_attack]

"""
TLS Certificate Chain Validator
=================================
Validates TLS certificate chain properties from structured certificate data.
Checks for chain completeness, signature algorithm safety, validity periods,
SAN/CN correctness, and known-weak configurations.

Operates on structured `CertInfo` dicts — no live TLS connections needed.
Feed it parsed certificate metadata (from OpenSSL, cryptography lib, etc.).

Check IDs
----------
TLS-CV-001   Certificate uses weak signature algorithm (MD5, SHA-1)
TLS-CV-002   Certificate is expired or not yet valid
TLS-CV-003   Certificate expires within warning_days
TLS-CV-004   Self-signed certificate in chain (except explicit trust anchors)
TLS-CV-005   Certificate chain is incomplete (missing intermediate)
TLS-CV-006   Subject CN does not match any SAN entry (mismatch)
TLS-CV-007   Wildcard certificate at root level (*.example.com vs *.sub.example.com)
TLS-CV-008   Certificate key too short (RSA < 2048, EC < 256)

Usage::

    from crypto.tls_chain_validator import TLSChainValidator, CertInfo

    chain = [
        CertInfo(
            subject_cn="example.com",
            issuer_cn="Let's Encrypt R3",
            sans=["example.com", "www.example.com"],
            not_before=1700000000.0,
            not_after=1730000000.0,
            sig_algorithm="sha256WithRSAEncryption",
            key_type="RSA",
            key_bits=2048,
            is_ca=False,
            serial="abc123",
        )
    ]
    validator = TLSChainValidator()
    report = validator.validate(chain)
    for finding in report.findings:
        print(finding.to_dict())
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ChainSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ---------------------------------------------------------------------------
# CertInfo — input model
# ---------------------------------------------------------------------------

@dataclass
class CertInfo:
    """
    Structured information about one certificate in a TLS chain.

    Attributes:
        subject_cn:     Subject Common Name.
        issuer_cn:      Issuer Common Name.
        sans:           Subject Alternative Names (DNS names).
        not_before:     Unix timestamp of notBefore.
        not_after:      Unix timestamp of notAfter.
        sig_algorithm:  Signature algorithm string (e.g. "sha256WithRSAEncryption").
        key_type:       Key type: "RSA", "EC", "DSA", or "unknown".
        key_bits:       Key size in bits (0 if unknown).
        is_ca:          True if this is a CA certificate (basicConstraints CA:TRUE).
        serial:         Serial number string.
        chain_index:    0 = leaf, 1 = first intermediate, last = root.
    """
    subject_cn:    str
    issuer_cn:     str         = ""
    sans:          List[str]   = field(default_factory=list)
    not_before:    float       = 0.0
    not_after:     float       = 0.0
    sig_algorithm: str         = "sha256WithRSAEncryption"
    key_type:      str         = "RSA"
    key_bits:      int         = 2048
    is_ca:         bool        = False
    serial:        str         = ""
    chain_index:   int         = 0


# ---------------------------------------------------------------------------
# ChainFinding
# ---------------------------------------------------------------------------

@dataclass
class ChainFinding:
    """
    A single TLS chain validation finding.

    Attributes:
        check_id:   TLS-CV-XXX identifier.
        severity:   Severity level.
        cert_cn:    Subject CN of the certificate that triggered the finding.
        chain_idx:  Index of the certificate in the chain.
        title:      Short description.
        detail:     Detailed explanation.
        remediation: Recommended fix.
    """
    check_id:    str
    severity:    ChainSeverity
    cert_cn:     str
    chain_idx:   int
    title:       str
    detail:      str
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id":    self.check_id,
            "severity":    self.severity.value,
            "cert_cn":     self.cert_cn,
            "chain_idx":   self.chain_idx,
            "title":       self.title,
            "detail":      self.detail,
            "remediation": self.remediation,
        }

    def summary(self) -> str:
        return f"[{self.check_id}] {self.severity.value}: {self.title} ({self.cert_cn})"


# ---------------------------------------------------------------------------
# ChainValidationReport
# ---------------------------------------------------------------------------

@dataclass
class ChainValidationReport:
    """
    Aggregated TLS chain validation report.

    Attributes:
        findings:     All chain findings.
        risk_score:   0–100 aggregate risk score.
        chain_length: Number of certificates analyzed.
        generated_at: Unix timestamp.
    """
    findings:     List[ChainFinding] = field(default_factory=list)
    risk_score:   int                = 0
    chain_length: int                = 0
    generated_at: float              = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> List[ChainFinding]:
        return [f for f in self.findings if f.severity == ChainSeverity.CRITICAL]

    @property
    def high_findings(self) -> List[ChainFinding]:
        return [f for f in self.findings if f.severity == ChainSeverity.HIGH]

    def findings_by_check(self, check_id: str) -> List[ChainFinding]:
        return [f for f in self.findings if f.check_id == check_id]

    def summary(self) -> str:
        return (
            f"Chain Validation: {self.total_findings} findings, "
            f"risk_score={self.risk_score}, "
            f"chain_length={self.chain_length}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "risk_score":     self.risk_score,
            "chain_length":   self.chain_length,
            "critical":       len(self.critical_findings),
            "high":           len(self.high_findings),
            "generated_at":   self.generated_at,
            "findings":       [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WEAK_SIG_ALGORITHMS = frozenset({
    "md5withrsa",
    "md5withrsa encryption",
    "md5withrsaencryption",
    "sha1withrsa",
    "sha1withrsaencryption",
    "sha1withecdsa",
    "sha1withdsa",
    "md2withrsa",
    "md4withrsa",
})

_CHECK_WEIGHTS: Dict[str, int] = {
    "TLS-CV-001": 40,
    "TLS-CV-002": 50,
    "TLS-CV-003": 20,
    "TLS-CV-004": 35,
    "TLS-CV-005": 30,
    "TLS-CV-006": 35,
    "TLS-CV-007": 20,
    "TLS-CV-008": 35,
}


# ---------------------------------------------------------------------------
# TLSChainValidator
# ---------------------------------------------------------------------------

class TLSChainValidator:
    """
    Validate a TLS certificate chain.

    Args:
        warning_days:      Days before expiry to flag TLS-CV-003 (default 30).
        reference_time:    Unix timestamp to use as "now" (default: time.time()).
        allow_self_signed: If True, skip TLS-CV-004 for single-cert chains
                           (useful for testing scenarios). Default False.
    """

    def __init__(
        self,
        warning_days: int = 30,
        reference_time: Optional[float] = None,
        allow_self_signed: bool = False,
    ) -> None:
        self._warning_days     = warning_days
        self._ref_time         = reference_time
        self._allow_self_signed = allow_self_signed

    def validate(self, chain: List[CertInfo]) -> ChainValidationReport:
        """
        Validate a certificate chain.

        Args:
            chain: List of CertInfo objects. Index 0 = leaf certificate.

        Returns:
            ChainValidationReport with all findings and risk score.
        """
        now = self._ref_time if self._ref_time is not None else time.time()
        findings: List[ChainFinding] = []

        for idx, cert in enumerate(chain):
            # Use chain_index from cert if set, otherwise use list index
            ci = cert.chain_index if cert.chain_index != 0 or idx == 0 else idx
            findings.extend(self._check_sig_algorithm(cert, ci))
            findings.extend(self._check_validity(cert, ci, now))
            findings.extend(self._check_self_signed(cert, ci, len(chain)))
            findings.extend(self._check_key_size(cert, ci))
            # Leaf-only checks
            if idx == 0:
                findings.extend(self._check_san_cn(cert, ci))
                findings.extend(self._check_wildcard(cert, ci))

        # Chain-level check
        findings.extend(self._check_chain_completeness(chain))

        fired = {f.check_id for f in findings}
        score = min(100, sum(_CHECK_WEIGHTS.get(c, 10) for c in fired))

        return ChainValidationReport(
            findings=findings,
            risk_score=score,
            chain_length=len(chain),
        )

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_sig_algorithm(self, cert: CertInfo, idx: int) -> List[ChainFinding]:
        algo_lower = cert.sig_algorithm.lower().replace(" ", "")
        if algo_lower in _WEAK_SIG_ALGORITHMS:
            return [ChainFinding(
                check_id="TLS-CV-001",
                severity=ChainSeverity.HIGH,
                cert_cn=cert.subject_cn,
                chain_idx=idx,
                title=f"Weak signature algorithm: {cert.sig_algorithm}",
                detail=(
                    f"Certificate '{cert.subject_cn}' uses weak signature "
                    f"algorithm '{cert.sig_algorithm}'. This is vulnerable "
                    f"to collision attacks."
                ),
                remediation=(
                    "Reissue certificate with SHA-256 or stronger. "
                    "Migrate to sha256WithRSAEncryption or ecdsa-with-SHA256."
                ),
            )]
        return []

    def _check_validity(
        self, cert: CertInfo, idx: int, now: float
    ) -> List[ChainFinding]:
        findings: List[ChainFinding] = []
        warn_ts = now + self._warning_days * 86400

        if cert.not_after > 0 and cert.not_after < now:
            findings.append(ChainFinding(
                check_id="TLS-CV-002",
                severity=ChainSeverity.CRITICAL,
                cert_cn=cert.subject_cn,
                chain_idx=idx,
                title="Certificate is expired",
                detail=(
                    f"Certificate '{cert.subject_cn}' expired "
                    f"{int((now - cert.not_after) / 86400)} days ago."
                ),
                remediation="Renew or replace the certificate immediately.",
            ))
        elif cert.not_before > 0 and cert.not_before > now:
            findings.append(ChainFinding(
                check_id="TLS-CV-002",
                severity=ChainSeverity.HIGH,
                cert_cn=cert.subject_cn,
                chain_idx=idx,
                title="Certificate is not yet valid",
                detail=(
                    f"Certificate '{cert.subject_cn}' is not valid until "
                    f"{int((cert.not_before - now) / 86400)} days from now."
                ),
                remediation=(
                    "Check certificate issuance time and system clock accuracy."
                ),
            ))
        elif cert.not_after > 0 and cert.not_after < warn_ts:
            days_left = int((cert.not_after - now) / 86400)
            findings.append(ChainFinding(
                check_id="TLS-CV-003",
                severity=ChainSeverity.MEDIUM,
                cert_cn=cert.subject_cn,
                chain_idx=idx,
                title=f"Certificate expires in {days_left} days",
                detail=(
                    f"Certificate '{cert.subject_cn}' expires in {days_left} days. "
                    f"Plan renewal before expiry."
                ),
                remediation="Renew the certificate before it expires.",
            ))

        return findings

    def _check_self_signed(
        self, cert: CertInfo, idx: int, chain_len: int
    ) -> List[ChainFinding]:
        if self._allow_self_signed:
            return []
        is_self_signed = (
            cert.subject_cn == cert.issuer_cn
            and bool(cert.issuer_cn)
        )
        # Allow root CA (last in chain) to be self-signed
        if is_self_signed and idx < chain_len - 1:
            return [ChainFinding(
                check_id="TLS-CV-004",
                severity=ChainSeverity.HIGH,
                cert_cn=cert.subject_cn,
                chain_idx=idx,
                title="Self-signed certificate in non-root position",
                detail=(
                    f"Certificate '{cert.subject_cn}' is self-signed but "
                    f"appears at chain position {idx} (not the root)."
                ),
                remediation=(
                    "Replace with a certificate signed by a trusted CA. "
                    "Self-signed certs in the leaf or intermediate position "
                    "cause browser/client trust errors."
                ),
            )]
        return []

    def _check_key_size(self, cert: CertInfo, idx: int) -> List[ChainFinding]:
        key_type = cert.key_type.upper()
        bits = cert.key_bits
        if bits <= 0:
            return []
        if key_type == "RSA" and bits < 2048:
            return [ChainFinding(
                check_id="TLS-CV-008",
                severity=ChainSeverity.HIGH,
                cert_cn=cert.subject_cn,
                chain_idx=idx,
                title=f"RSA key too short: {bits} bits",
                detail=(
                    f"Certificate '{cert.subject_cn}' uses a {bits}-bit RSA key. "
                    f"Minimum recommended is 2048 bits."
                ),
                remediation="Reissue with RSA-2048 or higher, or switch to EC P-256.",
            )]
        if key_type == "EC" and bits < 256:
            return [ChainFinding(
                check_id="TLS-CV-008",
                severity=ChainSeverity.HIGH,
                cert_cn=cert.subject_cn,
                chain_idx=idx,
                title=f"EC key too short: {bits} bits",
                detail=(
                    f"Certificate '{cert.subject_cn}' uses a {bits}-bit EC key. "
                    f"Minimum recommended is 256 bits (P-256)."
                ),
                remediation="Reissue with EC P-256 or higher.",
            )]
        return []

    def _check_san_cn(self, cert: CertInfo, idx: int) -> List[ChainFinding]:
        """TLS-CV-006: CN not in SANs (modern clients ignore CN when SANs present)."""
        if not cert.sans:
            return []  # no SANs to compare
        cn = cert.subject_cn.lower()
        sans_lower = [s.lower() for s in cert.sans]
        # Check exact or wildcard match
        if cn in sans_lower:
            return []
        # Check wildcard SAN covers CN
        for san in sans_lower:
            if san.startswith("*."):
                suffix = san[1:]  # e.g. ".example.com"
                if cn.endswith(suffix) and "." not in cn[: -len(suffix)]:
                    return []
        return [ChainFinding(
            check_id="TLS-CV-006",
            severity=ChainSeverity.MEDIUM,
            cert_cn=cert.subject_cn,
            chain_idx=idx,
            title="Subject CN not listed in SANs",
            detail=(
                f"Certificate CN '{cert.subject_cn}' is not present in the "
                f"Subject Alternative Names: {cert.sans}. "
                f"Modern clients validate against SANs only."
            ),
            remediation=(
                "Reissue the certificate with the CN included in the SAN extension."
            ),
        )]

    def _check_wildcard(self, cert: CertInfo, idx: int) -> List[ChainFinding]:
        """TLS-CV-007: Wildcard at root/TLD level (*.com, *.example, *.co.uk)."""
        all_names = [cert.subject_cn] + list(cert.sans)
        for name in all_names:
            if not name.startswith("*."):
                continue
            base = name[2:]  # strip "*."
            parts = base.split(".")
            # Root-level wildcard: *.example.com covers *.com[1 part] or *.example [1 part]
            # Dangerous: < 2 dots total, meaning base is just one label
            if len(parts) < 2:
                return [ChainFinding(
                    check_id="TLS-CV-007",
                    severity=ChainSeverity.MEDIUM,
                    cert_cn=cert.subject_cn,
                    chain_idx=idx,
                    title=f"Overly broad wildcard certificate: {name}",
                    detail=(
                        f"Certificate wildcard '{name}' covers a very broad "
                        f"scope (root-level or single-label domain)."
                    ),
                    remediation=(
                        "Use wildcards only for subdomains of your registered "
                        "domain (e.g. *.example.com, not *.com)."
                    ),
                )]
        return []

    def _check_chain_completeness(
        self, chain: List[CertInfo]
    ) -> List[ChainFinding]:
        """TLS-CV-005: Chain has only one cert and it's not self-signed (missing intermediates)."""
        if len(chain) < 2:
            if chain and chain[0].subject_cn != chain[0].issuer_cn:
                return [ChainFinding(
                    check_id="TLS-CV-005",
                    severity=ChainSeverity.HIGH,
                    cert_cn=chain[0].subject_cn,
                    chain_idx=0,
                    title="Certificate chain appears incomplete",
                    detail=(
                        f"Only one certificate in chain for '{chain[0].subject_cn}' "
                        f"and it is not self-signed. Intermediate CA certificates "
                        f"are likely missing."
                    ),
                    remediation=(
                        "Provide the full certificate chain including all "
                        "intermediate CA certificates."
                    ),
                )]
        return []

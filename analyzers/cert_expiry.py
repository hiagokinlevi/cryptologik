from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization


@dataclass
class CertExpiryFinding:
    file: str
    severity: str
    message: str
    status: str = "finding"
    expires_in_days: int | None = None


@dataclass
class CertExpiryResult:
    findings: list[CertExpiryFinding]


def _load_certificate_from_pem_bytes(pem_data: bytes) -> x509.Certificate:
    """Load a certificate from PEM bytes.

    Raises exceptions from cryptography for malformed/non-certificate PEM blocks.
    """
    return x509.load_pem_x509_certificate(pem_data)


def _is_encrypted_private_key_pem(pem_data: bytes) -> bool:
    marker = b"ENCRYPTED PRIVATE KEY"
    legacy_marker = b"Proc-Type: 4,ENCRYPTED"
    return marker in pem_data or legacy_marker in pem_data


def _scan_single_file(path: Path, warn_days: int) -> list[CertExpiryFinding]:
    findings: list[CertExpiryFinding] = []
    try:
        raw = path.read_bytes()
    except Exception as exc:
        findings.append(
            CertExpiryFinding(
                file=str(path),
                severity="low",
                status="skipped",
                message=f"Skipped file: unreadable PEM/certificate input ({exc.__class__.__name__})",
            )
        )
        return findings

    if _is_encrypted_private_key_pem(raw):
        findings.append(
            CertExpiryFinding(
                file=str(path),
                severity="low",
                status="skipped",
                message="Skipped file: appears to contain an encrypted private key PEM, not a certificate",
            )
        )
        return findings

    try:
        cert = _load_certificate_from_pem_bytes(raw)
    except (ValueError, TypeError) as exc:
        findings.append(
            CertExpiryFinding(
                file=str(path),
                severity="low",
                status="skipped",
                message=f"Skipped file: unreadable or non-certificate PEM content ({exc.__class__.__name__})",
            )
        )
        return findings

    now = datetime.now(timezone.utc)
    expires_in_days = (cert.not_valid_after_utc - now).days
    if expires_in_days <= warn_days:
        sev = "high" if expires_in_days < 0 else "medium"
        findings.append(
            CertExpiryFinding(
                file=str(path),
                severity=sev,
                status="finding",
                message="Certificate expiry within warning threshold",
                expires_in_days=expires_in_days,
            )
        )
    return findings


def scan_cert_expiry(cert: str, warn_days: int = 30) -> CertExpiryResult:
    p = Path(cert)
    files: list[Path]
    if p.is_dir():
        files = [*p.rglob("*.pem"), *p.rglob("*.crt")]
    else:
        files = [p]

    findings: list[CertExpiryFinding] = []
    for f in files:
        findings.extend(_scan_single_file(f, warn_days))

    return CertExpiryResult(findings=findings)


def result_to_json_dict(result: CertExpiryResult) -> dict[str, Any]:
    return {
        "findings": [
            {
                "file": f.file,
                "severity": f.severity,
                "status": f.status,
                "message": f.message,
                **({"expires_in_days": f.expires_in_days} if f.expires_in_days is not None else {}),
            }
            for f in result.findings
        ]
    }

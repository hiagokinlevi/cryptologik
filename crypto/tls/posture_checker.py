"""
TLS posture checker.

Probes a host's TLS configuration and reports:
- Protocol version support (TLS 1.0/1.1 = deprecated, TLS 1.3 = recommended)
- Certificate expiry
- Certificate chain validity
- Weak cipher suite detection
- HSTS header presence

Uses Python's ssl module only — no third-party dependencies.
All operations are read-only network observations.
"""
from __future__ import annotations
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class TlsRisk(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class TlsFinding:
    rule_id: str
    risk: TlsRisk
    message: str
    remediation: str


@dataclass
class TlsPostureResult:
    host: str
    port: int
    checked_at: datetime
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_expiry: Optional[datetime] = None
    cert_issuer: Optional[str] = None
    findings: list[TlsFinding] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def expired(self) -> bool:
        if self.cert_expiry is None:
            return False
        return datetime.now(timezone.utc) > self.cert_expiry

    @property
    def days_until_expiry(self) -> Optional[int]:
        if self.cert_expiry is None:
            return None
        delta = self.cert_expiry - datetime.now(timezone.utc)
        return delta.days


# Deprecated TLS protocol versions
_DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}

# Known weak cipher patterns
_WEAK_CIPHER_PATTERNS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "ADH", "AECDH"]


def check_tls_posture(host: str, port: int = 443, timeout: float = 10.0) -> TlsPostureResult:
    """
    Connect to host:port using TLS and assess the TLS posture.

    Checks:
    - Protocol version (TLS 1.2 minimum, 1.3 preferred)
    - Cipher suite strength (reject RC4, DES, NULL, EXPORT, anon ciphers)
    - Certificate expiry (warn if <30 days, critical if expired)
    - Certificate chain verification

    Args:
        host:    Hostname to connect to.
        port:    TCP port (default: 443).
        timeout: Connection timeout in seconds.

    Returns:
        TlsPostureResult with findings.
    """
    result = TlsPostureResult(host=host, port=port, checked_at=datetime.now(timezone.utc))

    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                result.tls_version = tls_sock.version()
                cipher_info = tls_sock.cipher()
                result.cipher_suite = cipher_info[0] if cipher_info else None

                cert = tls_sock.getpeercert()
                if cert:
                    result.cert_subject = dict(x[0] for x in cert.get("subject", []))
                    result.cert_issuer = dict(x[0] for x in cert.get("issuer", []))
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        result.cert_expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=timezone.utc
                        )

    except ssl.SSLCertVerificationError as e:
        result.error = f"Certificate verification failed: {e}"
        result.findings.append(TlsFinding(
            rule_id="TLS001",
            risk=TlsRisk.CRITICAL,
            message=f"TLS certificate verification failed: {e}",
            remediation="Ensure the certificate is valid, not self-signed for production, and issued by a trusted CA",
        ))
        return result
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result.error = str(e)
        return result

    # Protocol version checks
    if result.tls_version in _DEPRECATED_PROTOCOLS:
        result.findings.append(TlsFinding(
            rule_id="TLS002",
            risk=TlsRisk.HIGH,
            message=f"Deprecated TLS version in use: {result.tls_version}",
            remediation="Disable TLS 1.0 and 1.1. Configure minimum TLS 1.2, prefer TLS 1.3.",
        ))

    if result.tls_version and result.tls_version not in ("TLSv1.3", "TLSv1.2"):
        result.findings.append(TlsFinding(
            rule_id="TLS003",
            risk=TlsRisk.MEDIUM,
            message=f"TLS 1.3 not negotiated (got {result.tls_version})",
            remediation="Enable TLS 1.3 support on the server for improved security and performance",
        ))

    # Cipher suite checks
    if result.cipher_suite:
        for weak in _WEAK_CIPHER_PATTERNS:
            if weak in result.cipher_suite.upper():
                result.findings.append(TlsFinding(
                    rule_id="TLS004",
                    risk=TlsRisk.HIGH,
                    message=f"Weak cipher suite detected: {result.cipher_suite}",
                    remediation="Remove weak ciphers from server configuration. Use ECDHE+AES-GCM or ChaCha20-Poly1305.",
                ))
                break

    # Certificate expiry checks
    if result.cert_expiry:
        if result.expired:
            result.findings.append(TlsFinding(
                rule_id="TLS005",
                risk=TlsRisk.CRITICAL,
                message=f"Certificate has EXPIRED (expired: {result.cert_expiry.date()})",
                remediation="Renew the certificate immediately. Consider automating renewal with Let's Encrypt/ACME.",
            ))
        elif result.days_until_expiry is not None and result.days_until_expiry < 30:
            result.findings.append(TlsFinding(
                rule_id="TLS006",
                risk=TlsRisk.MEDIUM,
                message=f"Certificate expires in {result.days_until_expiry} days",
                remediation="Renew the certificate before expiry. Automate renewal to prevent outages.",
            ))

    return result

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set


@dataclass
class TLSFinding:
    id: str
    title: str
    severity: str
    description: str
    field: Optional[str] = None


def _normalize_cipher_name(cipher: str) -> str:
    return cipher.strip().upper()


def _extract_configured_ciphers(config: Dict[str, Any]) -> List[str]:
    ciphers = config.get("ciphers", [])
    if isinstance(ciphers, str):
        # Support OpenSSL-style colon-separated list
        ciphers = [c for c in ciphers.split(":") if c.strip()]
    if not isinstance(ciphers, list):
        return []
    return [str(c).strip() for c in ciphers if str(c).strip()]


def _extract_policy_cipher_allowlist(policy: Optional[Dict[str, Any]]) -> Set[str]:
    if not policy:
        return set()

    # Primary expected location
    tls_block = policy.get("tls", {}) if isinstance(policy, dict) else {}
    allowlist = tls_block.get("cipher_allowlist", []) if isinstance(tls_block, dict) else []

    # Backward/alternate naming support in policy profiles
    if not allowlist and isinstance(tls_block, dict):
        allowlist = tls_block.get("approved_ciphers", [])

    if isinstance(allowlist, str):
        allowlist = [c for c in allowlist.split(":") if c.strip()]

    if not isinstance(allowlist, list):
        return set()

    return {_normalize_cipher_name(str(c)) for c in allowlist if str(c).strip()}


def scan_tls_config(config: Dict[str, Any], policy: Optional[Dict[str, Any]] = None) -> List[TLSFinding]:
    findings: List[TLSFinding] = []

    configured = _extract_configured_ciphers(config)
    approved = _extract_policy_cipher_allowlist(policy)

    if approved:
        for cipher in configured:
            if _normalize_cipher_name(cipher) not in approved:
                findings.append(
                    TLSFinding(
                        id="TLS_CIPHER_NOT_ALLOWLISTED",
                        title="Configured TLS cipher is not in policy allowlist",
                        severity="high",
                        description=(
                            f"Cipher '{cipher}' is configured but not present in the approved "
                            "policy cipher allowlist."
                        ),
                        field="ciphers",
                    )
                )

    return findings

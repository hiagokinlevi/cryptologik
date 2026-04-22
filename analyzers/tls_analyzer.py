from __future__ import annotations

from typing import Any, Dict, List


LEGACY_TLS_VERSIONS = {
    "sslv3",
    "sslv3.0",
    "tls1",
    "tls1.0",
    "tlsv1",
    "tlsv1.0",
    "tls1_0",
    "tlsv1_0",
    "tls1.1",
    "tlsv1.1",
    "tls1_1",
    "tlsv1_1",
}


def _norm(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower().replace("-", "").replace(" ", "")


def _is_legacy(version: Any) -> bool:
    return _norm(version) in LEGACY_TLS_VERSIONS


def _finding(path: str, observed: str) -> Dict[str, Any]:
    return {
        "rule_id": "tls.minimum_version",
        "title": "TLS minimum version allows legacy protocols",
        "severity": "high",
        "path": path,
        "observed": observed,
        "description": "Listener configuration allows SSLv3/TLS 1.0/TLS 1.1, which are deprecated and insecure.",
        "remediation": "Set the minimum TLS version to TLS 1.2 or TLS 1.3 and disable SSLv3/TLS 1.0/TLS 1.1 on all listeners.",
    }


def check_tls_minimum_version(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    listeners = config.get("listeners", [])
    if not isinstance(listeners, list):
        listeners = []

    for idx, listener in enumerate(listeners):
        if not isinstance(listener, dict):
            continue

        base = f"listeners[{idx}]"

        min_version = listener.get("min_version") or listener.get("minimum_version")
        if _is_legacy(min_version):
            findings.append(_finding(f"{base}.min_version", str(min_version)))

        enabled_versions = listener.get("enabled_versions") or listener.get("protocols")
        if isinstance(enabled_versions, list):
            for v in enabled_versions:
                if _is_legacy(v):
                    findings.append(_finding(f"{base}.enabled_versions", str(v)))

    return findings

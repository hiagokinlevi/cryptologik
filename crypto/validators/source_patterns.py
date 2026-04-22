import re
from typing import Dict, List, Any


_KEY_VAR_RE = re.compile(
    r"\b(?:key|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|password|passwd)\b",
    re.IGNORECASE,
)

# Quoted literal assignment in Python/JS style forms.
_ASSIGNMENT_RE = re.compile(
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|:|=>)\s*(?P<quote>['\"])(?P<value>[^'\"]+)(?P=quote)",
)

_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{32,}$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]{40,}$")


def _looks_like_key_material(value: str) -> bool:
    v = value.strip()
    if len(v) < 32:
        return False
    if _HEX_RE.match(v):
        return True
    if _B64_RE.match(v):
        # avoid common long text false positives by requiring at least one base64-ish marker
        return ("=" in v) or ("+" in v) or ("/" in v) or ("-" in v) or ("_" in v)
    return False


def detect_hardcoded_keys(content: str, file_path: str) -> List[Dict[str, Any]]:
    lower = file_path.lower()
    if not (lower.endswith(".py") or lower.endswith(".js") or lower.endswith(".mjs") or lower.endswith(".cjs")):
        return []

    findings: List[Dict[str, Any]] = []
    for i, line in enumerate(content.splitlines(), start=1):
        m = _ASSIGNMENT_RE.search(line)
        if not m:
            continue

        var = m.group("var")
        value = m.group("value")

        if not _KEY_VAR_RE.search(var):
            continue
        if not _looks_like_key_material(value):
            continue

        findings.append(
            {
                "rule_id": "CRYPTO-HARDCODED-KEY",
                "severity": "high",
                "title": "Potential hardcoded cryptographic key material",
                "description": "Detected long literal assigned to key/secret-like variable.",
                "file": file_path,
                "line": i,
                "confidence": "medium",
                "category": "key_management",
                "metadata": {
                    "variable": var,
                    "pattern": "hex_or_base64_literal",
                },
            }
        )

    return findings

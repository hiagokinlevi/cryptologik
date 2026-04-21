from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ContractAnalysisResult:
    path: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    solidity_pragma: Optional[str] = None
    solidity_min_version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "findings": self.findings,
            "solidity_pragma": self.solidity_pragma,
            "solidity_min_version": self.solidity_min_version,
        }


_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _parse_version_tuple(text: str) -> Optional[Tuple[int, int, int]]:
    m = _VERSION_RE.search(text)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def extract_solidity_pragma_and_min_version(source: str) -> Tuple[Optional[str], Optional[Tuple[int, int, int]]]:
    m = _PRAGMA_RE.search(source)
    if not m:
        return None, None

    raw = m.group(1).strip()

    # Common forms:
    # ^0.8.0
    # >=0.7.0 <0.9.0
    # 0.8.19
    # >0.7.1 <=0.8.20
    candidates: List[Tuple[int, int, int]] = []
    for token in raw.split():
        if token.startswith((">=", ">", "^", "~")):
            v = _parse_version_tuple(token[1:] if token[0] in {"^", "~"} else token[2:] if token.startswith(">=") else token[1:])
            if v:
                candidates.append(v)
        elif token.startswith(("<=", "<")):
            continue
        else:
            v = _parse_version_tuple(token)
            if v:
                candidates.append(v)

    min_v = min(candidates) if candidates else _parse_version_tuple(raw)
    return raw, min_v


def analyze_contract(path: str) -> ContractAnalysisResult:
    p = Path(path)
    source = p.read_text(encoding="utf-8", errors="ignore")

    result = ContractAnalysisResult(path=str(p))
    pragma_raw, min_v = extract_solidity_pragma_and_min_version(source)

    result.solidity_pragma = pragma_raw
    if min_v:
        result.solidity_min_version = f"{min_v[0]}.{min_v[1]}.{min_v[2]}"

    if min_v and min_v < (0, 8, 0):
        result.findings.append(
            {
                "id": "SOLIDITY_LEGACY_COMPILER",
                "severity": "medium",
                "title": "Legacy Solidity compiler range detected (<0.8.0)",
                "description": "Detected Solidity minimum version below 0.8.0. Older compiler defaults may allow unchecked arithmetic overflow/underflow and miss newer safety behaviors.",
                "recommendation": "Upgrade pragma to Solidity 0.8.x or newer and re-test contract behavior.",
            }
        )

    return result

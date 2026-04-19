from __future__ import annotations

from pathlib import Path
import re
from typing import Dict, List, Sequence


UNSAFE_SOLIDITY_PATTERNS: Dict[str, re.Pattern[str]] = {
    "tx.origin": re.compile(r"\btx\.origin\b"),
    "call.value": re.compile(r"\.call\.value\s*\("),
    "delegatecall": re.compile(r"\bdelegatecall\s*\("),
}


def scan_solidity_unsafe_patterns(paths: Sequence[str | Path]) -> List[dict]:
    """Scan Solidity files for selected unsafe patterns.

    Returns a list of findings with file path, line number, pattern key,
    and the matching line content.
    """
    findings: List[dict] = []

    for input_path in paths:
        path = Path(input_path)

        if path.is_dir():
            solidity_files = sorted(path.rglob("*.sol"))
        elif path.is_file() and path.suffix == ".sol":
            solidity_files = [path]
        else:
            continue

        for sol_file in solidity_files:
            try:
                lines = sol_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue

            for line_no, line in enumerate(lines, start=1):
                for pattern_name, pattern in UNSAFE_SOLIDITY_PATTERNS.items():
                    if pattern.search(line):
                        findings.append(
                            {
                                "file": str(sol_file),
                                "line": line_no,
                                "pattern": pattern_name,
                                "content": line.strip(),
                            }
                        )

    return findings

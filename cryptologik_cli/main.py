from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Iterable


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _normalize_severity(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text if text in SEVERITY_ORDER else None


def finding_meets_threshold(finding_severity: Any, threshold: str | None) -> bool:
    normalized_threshold = _normalize_severity(threshold)
    if normalized_threshold is None:
        return False
    normalized_finding = _normalize_severity(finding_severity)
    if normalized_finding is None:
        return False
    return SEVERITY_ORDER[normalized_finding] >= SEVERITY_ORDER[normalized_threshold]


def any_finding_meets_threshold(findings: Iterable[dict[str, Any]], threshold: str | None) -> bool:
    return any(finding_meets_threshold(f.get("severity"), threshold) for f in findings)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptologik")
    parser.add_argument("--input", help="Path to findings JSON")
    parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        help="Exit with non-zero status if any finding meets or exceeds this severity",
    )
    return parser


def _load_findings(path: str) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [f for f in data["findings"] if isinstance(f, dict)]
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    findings: list[dict[str, Any]] = []
    if args.input:
        findings = _load_findings(args.input)

    # Existing behavior is preserved unless --fail-on is supplied.
    if args.fail_on and any_finding_meets_threshold(findings, args.fail_on):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

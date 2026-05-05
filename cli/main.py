from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from blockchain.contract_scan import scan_contract


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _finding_severity(finding: dict[str, Any]) -> str:
    sev = str(finding.get("severity", "")).strip().lower()
    return sev if sev in SEVERITY_ORDER else "low"


def _meets_fail_threshold(findings: list[dict[str, Any]], fail_on: str | None) -> bool:
    if not fail_on:
        return False
    threshold = SEVERITY_ORDER[fail_on]
    for f in findings:
        if SEVERITY_ORDER.get(_finding_severity(f), 0) >= threshold:
            return True
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptologik")
    sub = parser.add_subparsers(dest="command")

    contract = sub.add_parser("contract-scan", help="Scan Solidity smart contracts")
    contract.add_argument("--path", required=True, help="Path to Solidity file")
    contract.add_argument("--format", choices=["text", "json"], default="text")
    contract.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Return non-zero when any finding meets or exceeds this severity",
    )

    return parser


def _print_text(result: dict[str, Any]) -> None:
    findings = result.get("findings", [])
    if not findings:
        print("No findings.")
        return
    for idx, f in enumerate(findings, 1):
        sev = str(f.get("severity", "unknown")).upper()
        title = f.get("title", "Untitled finding")
        print(f"{idx}. [{sev}] {title}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "contract-scan":
        result = scan_contract(Path(args.path))
        if args.format == "json":
            print(json.dumps(result, indent=2))
        else:
            _print_text(result)

        findings = result.get("findings", []) if isinstance(result, dict) else []
        if _meets_fail_threshold(findings, args.fail_on):
            return 2
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
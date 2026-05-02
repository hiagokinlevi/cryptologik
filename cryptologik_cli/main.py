from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptologik.contract_scan import run_contract_scan
from cryptologik.reports.sarif import contract_scan_to_sarif


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptologik")
    subparsers = parser.add_subparsers(dest="command")

    contract = subparsers.add_parser("contract-scan", help="Scan smart contracts for common issues")
    contract.add_argument("--path", required=True, help="Path to contract file or directory")
    contract.add_argument("--json", action="store_true", help="Emit JSON output")
    contract.add_argument(
        "--format",
        choices=["text", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    contract.add_argument(
        "--output",
        help="Write structured output to a file (supported with --json or --format sarif)",
    )

    return parser


def _write_output_file(path: str, payload: str) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(payload, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "contract-scan":
        result: dict[str, Any] = run_contract_scan(args.path)

        if args.format == "sarif":
            rendered = json.dumps(contract_scan_to_sarif(result), indent=2)
            if args.output:
                try:
                    _write_output_file(args.output, rendered + "\n")
                except OSError as exc:
                    print(f"error: failed to write SARIF report to '{args.output}': {exc}", file=sys.stderr)
                    return 2
            else:
                print(rendered)
            return 0

        if args.json:
            rendered = json.dumps(result, indent=2)
            if args.output:
                try:
                    _write_output_file(args.output, rendered + "\n")
                except OSError as exc:
                    print(f"error: failed to write JSON report to '{args.output}': {exc}", file=sys.stderr)
                    return 2
            else:
                print(rendered)
            return 0

        # text mode remains stdout only; --output intentionally ignored unless structured format selected
        print(result.get("summary", "contract scan complete"))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

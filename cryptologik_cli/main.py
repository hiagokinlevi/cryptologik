from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from cryptologik.contract_scan import scan_contract
from cryptologik.reporters import render_text_report, render_json_report, render_sarif_report


ALLOWED_CONTRACT_SCAN_FORMATS = {"text", "json", "sarif"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptologik")
    subparsers = parser.add_subparsers(dest="command")

    contract_scan = subparsers.add_parser("contract-scan", help="Scan smart contracts for security issues")
    contract_scan.add_argument("--path", required=True, help="Path to contract source")
    contract_scan.add_argument(
        "--format",
        default="text",
        help="Output format for findings: text|json|sarif (default: text)",
    )
    # Backward-compatible legacy flags
    contract_scan.add_argument("--json", action="store_true", dest="legacy_json", help=argparse.SUPPRESS)
    contract_scan.add_argument("--sarif", action="store_true", dest="legacy_sarif", help=argparse.SUPPRESS)

    return parser


def _resolve_contract_scan_format(args: argparse.Namespace) -> str:
    fmt = (args.format or "text").lower()

    # Backward compatibility: legacy mode-specific flags still work.
    # Explicit --format takes precedence if provided.
    if "--format" not in sys.argv:
        if getattr(args, "legacy_sarif", False):
            fmt = "sarif"
        elif getattr(args, "legacy_json", False):
            fmt = "json"

    if fmt not in ALLOWED_CONTRACT_SCAN_FORMATS:
        raise ValueError("Invalid --format value. Allowed values: sarif, json, text")

    return fmt


def _run_contract_scan(args: argparse.Namespace) -> int:
    findings: list[dict[str, Any]] = scan_contract(args.path)
    fmt = _resolve_contract_scan_format(args)

    if fmt == "json":
        print(render_json_report(findings))
    elif fmt == "sarif":
        print(render_sarif_report(findings))
    else:
        print(render_text_report(findings))

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "contract-scan":
        try:
            return _run_contract_scan(args)
        except ValueError as exc:
            parser.error(str(exc))

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

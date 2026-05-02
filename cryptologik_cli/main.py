from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from analyzers.tls import analyze_tls_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptologik")
    subparsers = parser.add_subparsers(dest="command")

    tls_parser = subparsers.add_parser("tls-check", help="Analyze TLS configuration")
    tls_parser.add_argument("--input", required=True, help="Path to TLS config file")
    tls_parser.add_argument("--json", action="store_true", help="Emit JSON output")
    tls_parser.add_argument(
        "--output",
        help="Write JSON findings to this file (requires --json)",
    )

    return parser


def _render_tls_json(result: Any) -> str:
    return json.dumps(result, indent=2, sort_keys=True)


def _handle_tls_check(args: argparse.Namespace) -> int:
    findings = analyze_tls_config(args.input)

    if args.output and not args.json:
        raise SystemExit("--output is only supported with --json")

    if args.json:
        payload = _render_tls_json(findings)
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(payload + "\n", encoding="utf-8")
        else:
            print(payload)
        return 0

    # existing non-JSON behavior retained
    if isinstance(findings, list):
        for item in findings:
            print(item)
    else:
        print(findings)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "tls-check":
        return _handle_tls_check(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

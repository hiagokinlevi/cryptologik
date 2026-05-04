import argparse
import json
import os
import sys
import tempfile
from typing import Any

from cryptologik.contract_scan import scan_contract


def _print_output(result: Any, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(result, indent=2))
    elif output_format == "sarif":
        # Existing SARIF formatter path is preserved by scan_contract return contract
        print(json.dumps(result, indent=2))
    else:
        # text
        if isinstance(result, str):
            print(result)
        else:
            print(json.dumps(result, indent=2))


def _handle_contract_scan(args: argparse.Namespace) -> int:
    if args.stdin:
        data = sys.stdin.read()
        if not data.strip():
            print("No Solidity source provided on stdin", file=sys.stderr)
            return 2
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False, encoding="utf-8") as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            result = scan_contract(path=tmp_path, output_format=args.format)
            _print_output(result, args.format)
            return 0
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if not args.path:
        print("Either --path or --stdin is required", file=sys.stderr)
        return 2

    result = scan_contract(path=args.path, output_format=args.format)
    _print_output(result, args.format)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptologik")
    subparsers = parser.add_subparsers(dest="command")

    contract = subparsers.add_parser("contract-scan", help="Scan Solidity contracts")
    contract.add_argument("--path", help="Path to Solidity file")
    contract.add_argument("--stdin", action="store_true", help="Read Solidity source from stdin")
    contract.add_argument("--format", choices=["text", "json", "sarif"], default="text")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "contract-scan":
        return _handle_contract_scan(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

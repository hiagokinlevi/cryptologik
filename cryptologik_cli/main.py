import argparse
import json
import sys
from pathlib import Path

from cryptologik.contract_scan import scan_contract_source, scan_contract_file


ALLOWED_CONTRACT_LANGUAGES = ("solidity",)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptologik")
    subparsers = parser.add_subparsers(dest="command", required=True)

    contract_scan = subparsers.add_parser(
        "contract-scan",
        help="Scan smart contract source for security issues",
    )
    contract_scan.add_argument("--path", help="Path to smart contract source file")
    contract_scan.add_argument(
        "--stdin",
        action="store_true",
        help="Read smart contract source from stdin",
    )
    contract_scan.add_argument(
        "--language",
        default="solidity",
        choices=ALLOWED_CONTRACT_LANGUAGES,
        help="Language for --stdin source input (default: solidity)",
    )

    return parser


def _run_contract_scan(args: argparse.Namespace) -> int:
    if args.stdin:
        source = sys.stdin.read()
        result = scan_contract_source(source=source, language=args.language)
    else:
        if not args.path:
            raise SystemExit("contract-scan requires --path when --stdin is not used")
        result = scan_contract_file(Path(args.path))

    print(json.dumps(result, indent=2))
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "contract-scan":
        return _run_contract_scan(args)

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cryptologik.contracts.scan import scan_contract


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2))


def _scan_single(path: str) -> dict[str, Any]:
    return scan_contract(path)


def _scan_from_input_list(input_file: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned_paths: list[str] = []

    for raw in Path(input_file).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        scanned_paths.append(line)
        try:
            result = _scan_single(line)
            if isinstance(result, dict) and isinstance(result.get("findings"), list):
                findings.extend(result["findings"])
            else:
                findings.append(
                    {
                        "rule_id": "CONTRACT_SCAN_INVALID_PAYLOAD",
                        "severity": "medium",
                        "message": "Scan result did not include a findings list.",
                        "path": line,
                    }
                )
        except Exception as exc:  # pragma: no cover - defensive normalization
            findings.append(
                {
                    "rule_id": "CONTRACT_SCAN_PATH_ERROR",
                    "severity": "high",
                    "message": str(exc),
                    "path": line,
                }
            )

    return {
        "mode": "multi-path",
        "input": input_file,
        "paths": scanned_paths,
        "findings": findings,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptologik")
    sub = parser.add_subparsers(dest="command")

    contract = sub.add_parser("contract-scan")
    contract.add_argument("--path", help="Path to Solidity file")
    contract.add_argument(
        "--input",
        help="Path to text file containing one Solidity file path per line",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "contract-scan":
        if args.input:
            _emit(_scan_from_input_list(args.input))
            return 0
        if args.path:
            _emit(_scan_single(args.path))
            return 0
        parser.error("contract-scan requires --path or --input")

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

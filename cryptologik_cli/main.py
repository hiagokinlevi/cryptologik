import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from cryptologik.tls import run_tls_check
from cryptologik.contracts import run_contract_scan

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _max_finding_severity(findings: List[Dict[str, Any]]) -> Optional[str]:
    max_level = 0
    max_name: Optional[str] = None
    for finding in findings or []:
        sev = str(finding.get("severity", "")).lower()
        level = SEVERITY_ORDER.get(sev, 0)
        if level > max_level:
            max_level = level
            max_name = sev
    return max_name


def _should_fail_on_threshold(findings: List[Dict[str, Any]], fail_on: Optional[str]) -> bool:
    if not fail_on:
        return False
    threshold = SEVERITY_ORDER[fail_on]
    for finding in findings or []:
        sev = str(finding.get("severity", "")).lower()
        if SEVERITY_ORDER.get(sev, 0) >= threshold:
            return True
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptologik")
    sub = parser.add_subparsers(dest="command")

    tls = sub.add_parser("tls-check")
    tls.add_argument("--input", required=True)
    tls.add_argument("--config", required=False)
    tls.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], required=False)

    contract = sub.add_parser("contract-scan")
    contract.add_argument("--path", required=True)
    contract.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], required=False)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "tls-check":
        result = run_tls_check(input_path=args.input, config_path=args.config)
        print(json.dumps(result))
        findings = result.get("findings", []) if isinstance(result, dict) else []
        if _should_fail_on_threshold(findings, args.fail_on):
            return 1
        return 0

    if args.command == "contract-scan":
        result = run_contract_scan(path=args.path)
        print(json.dumps(result))
        findings = result.get("findings", []) if isinstance(result, dict) else []
        if _should_fail_on_threshold(findings, args.fail_on):
            return 1
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

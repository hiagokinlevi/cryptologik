import argparse
import json
import sys
from typing import Any, Dict, List

from analyzers.tls import scan_tls_config


def _normalize_tls_finding(finding: Dict[str, Any], target: str) -> Dict[str, Any]:
    return {
        "rule_id": finding.get("rule_id") or finding.get("id") or "TLS_UNKNOWN",
        "title": finding.get("title") or finding.get("message") or "TLS finding",
        "severity": str(finding.get("severity") or "info").lower(),
        "target": finding.get("target") or target,
        "evidence": finding.get("evidence") or finding.get("details") or finding.get("message") or "",
    }


def _build_tls_json_output(target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    normalized = [_normalize_tls_finding(f, target) for f in findings]
    sev_counts: Dict[str, int] = {}
    for f in normalized:
        sev = f["severity"]
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    return {
        "summary": {
            "target": target,
            "total_findings": len(normalized),
            "severity_counts": sev_counts,
        },
        "findings": normalized,
    }


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(prog="cryptologik")
    subparsers = parser.add_subparsers(dest="command")

    tls_parser = subparsers.add_parser("tls-check", help="Run TLS configuration posture checks")
    tls_parser.add_argument("--input", required=True, help="Path to TLS config input file")
    tls_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON findings with summary",
    )

    args = parser.parse_args(argv)

    if args.command == "tls-check":
        results = scan_tls_config(args.input)
        findings = results.get("findings", []) if isinstance(results, dict) else []

        if args.json:
            payload = _build_tls_json_output(args.input, findings)
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1 if payload["summary"]["total_findings"] > 0 else 0

        # existing human-readable output behavior
        for f in findings:
            sev = f.get("severity", "info").upper()
            title = f.get("title") or f.get("message") or "TLS finding"
            print(f"[{sev}] {title}")
        return 1 if len(findings) > 0 else 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

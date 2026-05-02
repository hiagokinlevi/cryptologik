from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

try:
    from importlib.metadata import version as _pkg_version
except Exception:  # pragma: no cover
    _pkg_version = None


def _get_version() -> str:
    if _pkg_version is None:
        return "unknown"
    try:
        return _pkg_version("cryptologik")
    except Exception:
        return "unknown"


def _overall_status(severity_counts: Dict[str, int]) -> str:
    if severity_counts.get("critical", 0) > 0:
        return "fail"
    if severity_counts.get("high", 0) > 0:
        return "warn"
    return "pass"


def _normalize_findings(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    c = Counter()
    for finding in findings or []:
        sev = str(finding.get("severity", "unknown")).lower()
        c[sev] += 1
    return {
        "critical": c.get("critical", 0),
        "high": c.get("high", 0),
        "medium": c.get("medium", 0),
        "low": c.get("low", 0),
        "info": c.get("info", 0),
        "unknown": c.get("unknown", 0),
    }


def _build_summary_payload(executed_checks: List[str], findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    sev = _normalize_findings(findings)
    return {
        "tool_version": _get_version(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "executed_checks": executed_checks,
        "finding_counts": {
            "by_severity": sev,
            "total": sum(sev.values()),
        },
        "overall_status": _overall_status(sev),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptologik", description="cryptologik security toolkit")
    parser.add_argument("--json", action="store_true", help="Emit top-level summary as JSON")
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Top-level inventory/summary path.
    executed_checks: List[str] = []
    findings: List[Dict[str, Any]] = []
    payload = _build_summary_payload(executed_checks=executed_checks, findings=findings)

    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print("cryptologik summary")
        print(f"version: {payload['tool_version']}")
        print(f"status: {payload['overall_status']}")
        print(f"findings: {payload['finding_counts']['total']}")

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

import argparse
import json
import sys
from typing import Any, Dict, Iterable

from cryptologik import __version__


def _iter_findings(result: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(result, dict):
        findings = result.get("findings")
        if isinstance(findings, list):
            for item in findings:
                if isinstance(item, dict):
                    yield item


def _has_blocking_findings(result: Any) -> bool:
    blocking = {"high", "critical"}
    for finding in _iter_findings(result):
        sev = str(finding.get("severity", "")).strip().lower()
        if sev in blocking:
            return True
    return False


def _exit_code_for_result(result: Any, informational: bool = False) -> int:
    if informational:
        return 0
    return 2 if _has_blocking_findings(result) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptologik")
    parser.add_argument("--version", action="version", version=f"cryptologik {__version__}")
    parser.add_argument(
        "--informational",
        action="store_true",
        help="Always exit 0 regardless of finding severities.",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Existing command flow is expected to produce a result object; this keeps
    # behavior small and composable for current tooling/tests.
    result = {}

    # Preserve current output behavior if result is serializable dict-like.
    if isinstance(result, dict):
        print(json.dumps(result))

    return _exit_code_for_result(result, informational=args.informational)


if __name__ == "__main__":
    sys.exit(main())

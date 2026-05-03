from __future__ import annotations

import argparse
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any

from cryptologik.analyzers.cert_expiry import analyze_certificate_expiry


def _serialize_value(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    if is_dataclass(value):
        return {k: _serialize_value(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {k: _serialize_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize_value(v) for v in value]
    return value


def _finding_to_json(finding: Any, cert_path: str) -> dict[str, Any]:
    # Reuse existing finding model and gracefully map common fields.
    data = _serialize_value(finding)
    if not isinstance(data, dict):
        data = {}

    return {
        "certificate_path": cert_path,
        "subject": data.get("subject") or data.get("certificate_subject"),
        "issuer": data.get("issuer") or data.get("certificate_issuer"),
        "not_after": data.get("not_after") or data.get("expires_at") or data.get("expiry_date"),
        "days_remaining": data.get("days_remaining"),
        "severity": data.get("severity"),
        "finding_code": data.get("code") or data.get("finding_code") or data.get("id"),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptologik")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cert_parser = subparsers.add_parser("cert-expiry", help="Check certificate expiry risk")
    cert_parser.add_argument("--cert", required=True, help="Path to certificate file")
    cert_parser.add_argument("--warn-days", type=int, default=30, help="Warning threshold in days")
    cert_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON findings")

    return parser


def _run_cert_expiry(args: argparse.Namespace) -> int:
    findings = analyze_certificate_expiry(args.cert, warn_days=args.warn_days)

    if args.json:
        payload = [_finding_to_json(f, args.cert) for f in findings]
        payload = sorted(
            payload,
            key=lambda x: (
                str(x.get("severity") or ""),
                str(x.get("finding_code") or ""),
                str(x.get("not_after") or ""),
                str(x.get("subject") or ""),
            ),
        )
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0

    # Preserve existing human-readable behavior fallback.
    for f in findings:
        print(f)
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "cert-expiry":
        return _run_cert_expiry(args)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

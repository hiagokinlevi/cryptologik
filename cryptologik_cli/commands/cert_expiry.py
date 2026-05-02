from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List

from cryptologik.analyzers.cert_expiry import analyze_certificate_expiry


def _read_cert_paths_from_input_file(input_file: str) -> List[str]:
    p = Path(input_file)
    lines = p.read_text(encoding="utf-8").splitlines()
    certs: List[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        certs.append(line)
    return certs


def register_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("cert-expiry", help="Check certificate expiry")
    parser.add_argument("--cert", action="append", default=[], help="Certificate path (repeatable)")
    parser.add_argument("--input", help="UTF-8 file with one certificate path per line (supports blank lines and # comments)")
    parser.add_argument("--warn-days", type=int, default=30, help="Warning threshold in days")
    parser.add_argument("--fail-on", choices=["warn", "critical"], help="Exit non-zero on threshold")
    parser.set_defaults(func=run)


def _iter_all_cert_paths(args: argparse.Namespace) -> Iterable[str]:
    for c in getattr(args, "cert", []) or []:
        yield c
    input_file = getattr(args, "input", None)
    if input_file:
        for c in _read_cert_paths_from_input_file(input_file):
            yield c


def run(args: argparse.Namespace):
    findings = []
    for cert_path in _iter_all_cert_paths(args):
        findings.extend(analyze_certificate_expiry(cert_path, warn_days=args.warn_days))

    # Keep existing output/fail pipeline behavior by returning aggregated findings
    return findings

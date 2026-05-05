import argparse
import json
import sys
from pathlib import Path

import yaml

from cryptologik.tls import analyze_tls_config


def _load_tls_input(input_value: str):
    if input_value == "-":
        raw = sys.stdin.read()
        if not raw or not raw.strip():
            raise ValueError("No TLS configuration provided on STDIN")
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML from STDIN: {exc}") from exc
        if data is None:
            raise ValueError("No TLS configuration provided on STDIN")
        return data

    input_path = Path(input_value)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_value}")

    with input_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data is None:
        raise ValueError(f"Input file is empty or invalid YAML: {input_value}")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cryptologik")
    subparsers = parser.add_subparsers(dest="command")

    tls_parser = subparsers.add_parser("tls-check", help="Analyze TLS configuration")
    tls_parser.add_argument("--input", required=True, help="Path to TLS YAML config, or '-' for STDIN")
    tls_parser.add_argument("--format", choices=["json", "text"], default="text")

    args = parser.parse_args(argv)

    if args.command == "tls-check":
        try:
            config = _load_tls_input(args.input)
            result = analyze_tls_config(config)
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

        if args.format == "json":
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("TLS check completed")
            if isinstance(result, dict):
                findings = result.get("findings", [])
                print(f"Findings: {len(findings)}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from cryptologik.contract_scan import scan_contract


@click.group()
def cli() -> None:
    """cryptologik CLI."""


@cli.command("contract-scan")
@click.option("--path", "contract_path", required=True, help="Path to smart contract source file")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", show_default=True, help="Output format")
@click.option("--output", "output_path", required=False, help="Write JSON findings to a file (supported with --format json)")
def contract_scan_cmd(contract_path: str, output_format: str, output_path: str | None) -> None:
    findings = scan_contract(contract_path)

    if output_format.lower() == "json":
        payload = {"findings": findings}
        rendered = json.dumps(payload, indent=2)

        if output_path:
            out = Path(output_path)
            try:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(rendered + "\n", encoding="utf-8")
            except OSError as exc:
                click.echo(f"Error: failed to write JSON findings to '{output_path}': {exc}", err=True)
                raise SystemExit(2)
        else:
            click.echo(rendered)
        return

    # text mode (existing behavior)
    for item in findings:
        click.echo(f"[{item.get('severity', 'unknown').upper()}] {item.get('title', 'Untitled')}")


if __name__ == "__main__":
    cli()

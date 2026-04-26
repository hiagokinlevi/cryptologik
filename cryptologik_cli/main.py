from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from cryptologik.contract_scan import scan_contract


SEVERITY_ORDER = {
    "none": -1,
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def _max_finding_severity(findings: list[dict[str, Any]]) -> str:
    max_sev = "none"
    max_rank = SEVERITY_ORDER[max_sev]
    for finding in findings:
        sev = str(finding.get("severity", "")).lower()
        rank = SEVERITY_ORDER.get(sev, -1)
        if rank > max_rank:
            max_rank = rank
            max_sev = sev
    return max_sev


@click.group()
def cli() -> None:
    """cryptologik command line interface."""


@cli.command("contract-scan")
@click.option("--path", "path_", required=True, type=click.Path(exists=True, path_type=Path), help="Path to smart contract source file")
@click.option("--json-output", is_flag=True, default=False, help="Emit scan output as JSON")
@click.option(
    "--fail-on",
    type=click.Choice(["none", "low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Fail with non-zero exit code when highest finding severity meets/exceeds threshold",
)
def contract_scan_cmd(path_: Path, json_output: bool, fail_on: str | None) -> None:
    """Scan a smart contract for security findings."""
    result = scan_contract(str(path_))
    findings = result.get("findings", []) if isinstance(result, dict) else []

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"Scanned: {path_}")
        for f in findings:
            click.echo(f"- [{f.get('severity', 'unknown')}] {f.get('title', 'finding')}")

    # Default behavior unchanged when --fail-on is omitted
    if fail_on is None:
        return

    threshold = fail_on.lower()
    highest = _max_finding_severity(findings)
    if SEVERITY_ORDER.get(highest, -1) >= SEVERITY_ORDER[threshold] and threshold != "none":
        raise SystemExit(1)

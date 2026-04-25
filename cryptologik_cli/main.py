import json
from collections import Counter
from pathlib import Path

import click

from blockchain.contract_scanner import scan_contract


@click.group()
def cli():
    pass


@cli.command("contract-scan")
@click.option("--path", "contract_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit machine-readable JSON output")
def contract_scan(contract_path: str, as_json: bool):
    findings = scan_contract(contract_path)

    if as_json:
        normalized = []
        for f in findings:
            normalized.append(
                {
                    "rule_id": f.get("rule_id"),
                    "severity": f.get("severity"),
                    "file": f.get("file", str(Path(contract_path))),
                    "line": f.get("line"),
                    "message": f.get("message"),
                    "recommendation": f.get("recommendation"),
                }
            )

        severity_counts = Counter((item.get("severity") or "unknown").lower() for item in normalized)
        payload = {
            "findings": normalized,
            "summary": {
                "total": len(normalized),
                "by_severity": dict(severity_counts),
            },
        }
        click.echo(json.dumps(payload, indent=2))
        return

    if not findings:
        click.echo("No findings.")
        return

    click.echo(f"Found {len(findings)} finding(s):")
    for f in findings:
        click.echo(
            f"- [{f.get('severity', 'UNKNOWN')}] {f.get('rule_id', 'N/A')} "
            f"{f.get('file', contract_path)}:{f.get('line', '?')} - {f.get('message', '')}"
        )
        rec = f.get("recommendation")
        if rec:
            click.echo(f"  Recommendation: {rec}")


if __name__ == "__main__":
    cli()

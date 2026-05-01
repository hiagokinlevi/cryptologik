from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from analyzers.cert_expiry import analyze_certificate_expiry
from analyzers.contract_scan import analyze_contract
from analyzers.tls_check import analyze_tls_config

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@click.group()
def cli() -> None:
    """cryptologik CLI."""


def _load_yaml_or_json(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".json"}:
        return json.loads(text)
    try:
        import yaml  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise click.ClickException("PyYAML is required for YAML inputs") from exc
    data = yaml.safe_load(text)
    return data or {}


def _max_finding_severity(findings: list[dict[str, Any]]) -> str | None:
    max_level = 0
    max_name: str | None = None
    for finding in findings:
        sev = str(finding.get("severity", "")).lower()
        level = SEVERITY_ORDER.get(sev, 0)
        if level > max_level:
            max_level = level
            max_name = sev
    return max_name


def _should_fail(findings: list[dict[str, Any]], fail_on: str | None) -> bool:
    if not fail_on:
        return False
    threshold = SEVERITY_ORDER[fail_on]
    for finding in findings:
        sev = str(finding.get("severity", "")).lower()
        if SEVERITY_ORDER.get(sev, 0) >= threshold:
            return True
    return False


@cli.command("tls-check")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text")
@click.option("--fail-on", type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False), default=None)
def tls_check(input_path: Path, output_format: str, fail_on: str | None) -> None:
    data = _load_yaml_or_json(input_path)
    result = analyze_tls_config(data)
    findings = result.get("findings", [])

    if output_format.lower() == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"TLS findings: {len(findings)}")
        for f in findings:
            click.echo(f"- [{f.get('severity', 'unknown')}] {f.get('id', 'TLS-ISSUE')}: {f.get('message', '')}")

    if _should_fail(findings, fail_on.lower() if fail_on else None):
        raise SystemExit(1)


@cli.command("cert-expiry")
@click.option("--cert", "cert_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--warn-days", default=30, type=int)
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text")
def cert_expiry(cert_path: Path, warn_days: int, output_format: str) -> None:
    result = analyze_certificate_expiry(cert_path, warn_days=warn_days)
    if output_format.lower() == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(result.get("summary", "Certificate expiry analysis complete"))


@cli.command("contract-scan")
@click.option("--path", "source_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text")
def contract_scan(source_path: Path, output_format: str) -> None:
    result = analyze_contract(source_path)
    if output_format.lower() == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        findings = result.get("findings", [])
        click.echo(f"Contract findings: {len(findings)}")


if __name__ == "__main__":
    cli()

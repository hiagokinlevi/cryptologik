import json
from datetime import datetime, timezone
from pathlib import Path

import click

from cryptologik.crypto.cert_expiry import analyze_certificate_expiry


def _iso8601(dt):
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


@click.group()
def cli():
    """cryptologik CLI."""
    pass


@cli.command("cert-expiry")
@click.option("--cert", "cert_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--warn-days", default=30, show_default=True, type=int)
@click.option("--critical-days", default=7, show_default=True, type=int)
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON output")
def cert_expiry(cert_path: Path, warn_days: int, critical_days: int, json_output: bool):
    result = analyze_certificate_expiry(str(cert_path), warn_days=warn_days, critical_days=critical_days)

    severity = (result.get("severity") or result.get("status") or "ok").lower()

    if json_output:
        payload = {
            "cert_path": str(cert_path),
            "subject": result.get("subject"),
            "issuer": result.get("issuer"),
            "not_before": _iso8601(result.get("not_before")),
            "not_after": _iso8601(result.get("not_after")),
            "days_remaining": result.get("days_remaining"),
            "severity": severity,
            "status": result.get("status", severity),
        }
        click.echo(json.dumps(payload))
    else:
        # Preserve existing default human-readable output shape.
        click.echo(f"Certificate: {cert_path}")
        click.echo(f"Subject: {result.get('subject')}")
        click.echo(f"Issuer: {result.get('issuer')}")
        click.echo(f"Not Before: {result.get('not_before')}")
        click.echo(f"Not After: {result.get('not_after')}")
        click.echo(f"Days Remaining: {result.get('days_remaining')}")
        click.echo(f"Severity: {severity}")

    if severity == "critical":
        raise SystemExit(2)
    if severity == "warning":
        raise SystemExit(1)

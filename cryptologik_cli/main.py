from __future__ import annotations

import json
from pathlib import Path
from typing import List

import typer

from cryptologik.certificates.expiry import check_certificate_expiry

app = typer.Typer(help="cryptologik CLI")


@app.command("cert-expiry")
def cert_expiry(
    cert: str = typer.Option(..., "--cert", help="Path to certificate file or directory"),
    warn_days: int = typer.Option(30, "--warn-days", help="Warn threshold in days"),
    report_format: str = typer.Option("json", "--format", help="Output format"),
):
    path = Path(cert)

    if not path.exists():
        typer.echo(json.dumps({"error": f"Path not found: {cert}"}))
        raise typer.Exit(code=2)

    cert_files: List[Path] = []
    if path.is_file():
        cert_files = [path]
    else:
        cert_files = sorted(
            [p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in {".pem", ".crt"}]
        )

    findings = []
    should_fail = False

    for cert_file in cert_files:
        result = check_certificate_expiry(str(cert_file), warn_days=warn_days)

        # Keep existing JSON/report-compatible shape; only enrich with source path when scanning dirs.
        if isinstance(result, dict):
            if path.is_dir():
                result = {**result, "cert": str(cert_file)}
            findings.append(result)
            if bool(result.get("breach") or result.get("expired") or result.get("within_warn_threshold")):
                should_fail = True

    payload = findings[0] if path.is_file() and len(findings) == 1 else {"findings": findings}

    if report_format.lower() == "json":
        typer.echo(json.dumps(payload))
    else:
        typer.echo(json.dumps(payload))

    if should_fail:
        raise typer.Exit(code=1)

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from cryptologik.contracts.scanner import scan_contract_path
from cryptologik.contracts.severity import should_fail_for_threshold
from cryptologik.contracts.text import render_findings_text
from cryptologik.contracts.sarif import findings_to_sarif

app = typer.Typer(help="Scan smart contracts for common security issues.")


def _write_output(content: str, output_path: Optional[Path]) -> None:
    if output_path is None:
        typer.echo(content)
        return

    if output_path.exists():
        raise typer.BadParameter(
            f"Refusing to overwrite existing file: {output_path}",
            param_hint="--output",
        )

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise typer.BadParameter(
            f"Failed to write output file '{output_path}': {exc}",
            param_hint="--output",
        ) from exc


@app.command("contract-scan")
def contract_scan(
    path: Path = typer.Option(..., "--path", help="Path to Solidity file or directory."),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        help="Fail when findings meet/exceed severity: none|low|medium|high|critical",
    ),
    format: str = typer.Option(
        "text",
        "--format",
        help="Output format: text|json|sarif",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Write scan output to a file. For text format, this writes the human-readable findings.",
    ),
) -> None:
    findings = scan_contract_path(path)

    fmt = format.lower()
    if fmt == "json":
        rendered = json.dumps([f.model_dump() for f in findings], indent=2)
    elif fmt == "sarif":
        rendered = json.dumps(findings_to_sarif(findings, str(path)), indent=2)
    else:
        rendered = render_findings_text(findings)

    _write_output(rendered, output)

    if should_fail_for_threshold(findings, fail_on):
        raise typer.Exit(code=1)

"""
Shim de compatibilidade para o ponto de entrada historico da CLI.

Este arquivo preserva importacoes legadas baseadas em ``cli.main`` sem manter
uma segunda copia da implementacao. A fonte canonica da CLI vive em
``cryptologik_cli.main``.
"""

from cryptologik_cli.main import cli


if __name__ == "__main__":
    cli()

@cli.command("review-key-posture")
@click.option(
    "--config", required=True,
    type=click.Path(exists=True),
    help="Path to the YAML key management configuration file.",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Write findings to this file as JSON (optional).",
)
def review_key_posture(config: str, output: Optional[str]) -> None:
    """Review key management posture from a YAML configuration file."""
    from crypto.key_management.posture_checker import check_key_management_posture

    console.print(Panel.fit(
        f"[bold]Config:[/bold] {config}\n"
        f"[bold]Strictness:[/bold] {STRICTNESS}",
        title="[bold cyan]cryptologik — Key Management Posture Review[/bold cyan]",
    ))

    findings = check_key_management_posture(Path(config))

    if not findings:
        console.print("[green]No key management posture issues detected.[/green]")
        return

    table = Table(title=f"Key Management Findings ({len(findings)})", show_lines=True)
    table.add_column("ID", width=8)
    table.add_column("Key", width=25)
    table.add_column("Risk", width=10)
    table.add_column("Title", width=50)

    risk_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}

    for f in findings:
        color = risk_colors.get(f.risk_level.value, "white")
        table.add_row(
            f.check_id,
            f.key_name,
            f"[{color}]{f.risk_level.value.upper()}[/{color}]",
            f.title[:70],
        )

    console.print(table)

    if output:
        findings_json = [
            {
                "check_id": f.check_id,
                "key_name": f.key_name,
                "risk_level": f.risk_level.value,
                "title": f.title,
                "recommendation": f.recommendation,
            }
            for f in findings
        ]
        Path(output).write_text(json.dumps(findings_json, indent=2), encoding="utf-8")
        console.print(f"[dim]Findings written to: {output}[/dim]")


# ---------------------------------------------------------------------------
# review-contract-checklist
# ---------------------------------------------------------------------------

@cli.command("review-contract-checklist")
@click.option(
    "--contract", required=True,
    type=click.Path(exists=True),
    help="Path to the Solidity contract file to review.",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Write findings to this file as JSON (optional).",
)
def review_contract_checklist(contract: str, output: Optional[str]) -> None:
    """Run the smart contract security checklist against a Solidity file."""
    from blockchain.smart_contracts.review_checklist import SmartContractReviewRunner

    console.print(Panel.fit(
        f"[bold]Contract:[/bold] {contract}\n"
        f"[bold]Framework:[/bold] SWC",
        title="[bold cyan]cryptologik — Smart Contract Review[/bold cyan]",
    ))

    runner = SmartContractReviewRunner()
    findings = runner.review(Path(contract))

    if not findings:
        console.print("[green]No checklist items triggered.[/green]")
        console.print("[dim]Manual review is still recommended for all contracts.[/dim]")
        return

    table = Table(title=f"Contract Findings ({len(findings)})", show_lines=True)
    table.add_column("SWC", width=10)
    table.add_column("Title", width=35)
    table.add_column("Risk", width=10)
    table.add_column("Line", width=6)

    risk_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}

    for f in findings:
        color = risk_colors.get(f.risk_level.value, "white")
        table.add_row(
            f.swc_id,
            f.swc_title,
            f"[{color}]{f.risk_level.value.upper()}[/{color}]",
            str(f.line_number or "-"),
        )

    console.print(table)
    console.print("\n[yellow]All contract findings require manual verification.[/yellow]")

    if output:
        findings_json = [
            {
                "swc_id": f.swc_id,
                "swc_title": f.swc_title,
                "risk_level": f.risk_level.value,
                "line_number": f.line_number,
                "recommendation": f.recommendation,
            }
            for f in findings
        ]
        Path(output).write_text(json.dumps(findings_json, indent=2), encoding="utf-8")
        console.print(f"[dim]Findings written to: {output}[/dim]")


# ---------------------------------------------------------------------------
# generate-report
# ---------------------------------------------------------------------------

@cli.command("generate-report")
@click.option(
    "--findings-json", required=True,
    type=click.Path(exists=True),
    help="Path to findings JSON file (output of any review command with --output).",
)
@click.option(
    "--format", "report_format",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    show_default=True,
)
@click.option(
    "--verbosity",
    type=click.Choice(["minimal", "standard", "verbose"]),
    default=os.getenv("REPORT_VERBOSITY", "standard"),
    show_default=True,
)
@click.option(
    "--target", default="Assessment Target",
    help="Description of what was assessed.",
)
@click.option("--output", "-o", default=None, type=click.Path(), help="Write report to this file.")
def generate_report(
    findings_json: str,
    report_format: str,
    verbosity: str,
    target: str,
    output: Optional[str],
) -> None:
    """Generate a security report from a findings JSON file."""
    from schemas.crypto_finding import AssessmentSummary, CryptoConfigFinding, RiskLevel, FindingCategory, FindingStatus
    from reports.report_generator import generate_markdown_report

    raw = json.loads(Path(findings_json).read_text())

    # Convert raw dicts to CryptoConfigFinding objects (simplified)
    findings = []
    for item in raw:
        try:
            f = CryptoConfigFinding(
                check_name=item.get("check_name", "unknown"),
                risk_level=RiskLevel(item.get("risk_level", "medium")),
                file_path=item.get("file_path", "unknown"),
                line_number=item.get("line_number", 1),
                title=item.get("description", "Finding")[:100],
                description=item.get("description", ""),
                recommendation=item.get("recommendation", ""),
            )
            findings.append(f)
        except Exception:
            continue

    summary = AssessmentSummary.from_findings(
        findings,
        target_description=target,
        assessment_profile=STRICTNESS,
    )

    if report_format == "markdown":
        report = generate_markdown_report(summary, verbosity=verbosity)
    else:
        report = summary.model_dump_json(indent=2)

    if output:
        Path(output).write_text(report, encoding="utf-8")
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        console.print(report)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()

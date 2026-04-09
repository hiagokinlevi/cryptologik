"""
cryptologik CLI
====================
Command-line interface for cryptologik.

Commands:
    review-crypto-config        Scan source files for cryptographic anti-patterns
    review-key-posture          Review key management posture from a YAML config
    review-contract-checklist   Run smart contract security checklist
    generate-report             Generate a Markdown security report

Usage:
    cryptologik review-crypto-config --path ./src
    cryptologik review-key-posture --config key-management.yaml
    cryptologik review-contract-checklist --contract ./contracts/MyToken.sol
    cryptologik generate-report --assessment-id ASSESS-ABC123 --format markdown
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

load_dotenv()

console = Console()

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./output"))
STRICTNESS = os.getenv("STRICTNESS", "standard")


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version="1.0.0", prog_name="cryptologik")
def cli() -> None:
    """cryptologik — Cryptographic and blockchain security review toolkit."""
    pass


# ---------------------------------------------------------------------------
# review-crypto-config
# ---------------------------------------------------------------------------

@cli.command("review-crypto-config")
@click.option(
    "--path", "-p", required=True,
    type=click.Path(exists=True),
    help="File or directory to scan for cryptographic anti-patterns.",
)
@click.option(
    "--ext",
    default="py,js,ts,java,go,rb,php,cs",
    help="Comma-separated list of file extensions to scan.",
    show_default=True,
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Write findings to this file as JSON (optional).",
)
@click.option(
    "--strictness",
    type=click.Choice(["minimal", "standard", "strict"]),
    default=STRICTNESS,
    help="Finding threshold.",
    show_default=True,
)
def review_crypto_config(path: str, ext: str, output: Optional[str], strictness: str) -> None:
    """Scan source files for cryptographic configuration anti-patterns."""
    from crypto.validators.config_validator import validate_crypto_config, CryptoRisk

    scan_path = Path(path)
    extensions = {f".{e.strip().lstrip('.')}" for e in ext.split(",")}

    # Collect files to scan
    if scan_path.is_file():
        files = [scan_path]
    else:
        files = [f for f in scan_path.rglob("*") if f.suffix in extensions and f.is_file()]

    console.print(Panel.fit(
        f"[bold]Scanning:[/bold] {scan_path}\n"
        f"[bold]Extensions:[/bold] {', '.join(sorted(extensions))}\n"
        f"[bold]Files:[/bold] {len(files)}\n"
        f"[bold]Strictness:[/bold] {strictness}",
        title="[bold cyan]cryptologik — Crypto Config Review[/bold cyan]",
    ))

    all_findings = []
    for file in files:
        findings = validate_crypto_config(file)
        all_findings.extend(findings)

    if not all_findings:
        console.print("[green]No cryptographic anti-patterns detected.[/green]")
        console.print("[dim]Note: This scan does not guarantee absence of cryptographic weaknesses.[/dim]")
        return

    # Build findings table
    table = Table(title=f"Findings ({len(all_findings)})", show_lines=True)
    table.add_column("Risk", style="bold", width=10)
    table.add_column("File", width=35)
    table.add_column("Line", width=6)
    table.add_column("Description", width=50)

    risk_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }

    for f in all_findings:
        color = risk_colors.get(f.risk_level.value, "white")
        table.add_row(
            f"[{color}]{f.risk_level.value.upper()}[/{color}]",
            str(Path(f.file_path).name),
            str(f.line_number),
            f.description[:80],
        )

    console.print(table)

    # Summary counts
    critical = sum(1 for f in all_findings if f.risk_level.value == "critical")
    high = sum(1 for f in all_findings if f.risk_level.value == "high")
    console.print(f"\n[bold]Total:[/bold] {len(all_findings)} findings "
                  f"([red]{critical} critical[/red], [yellow]{high} high[/yellow])")

    if output:
        findings_json = [
            {
                "check_name": f.check_name,
                "risk_level": f.risk_level.value,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in all_findings
        ]
        Path(output).write_text(json.dumps(findings_json, indent=2), encoding="utf-8")
        console.print(f"[dim]Findings written to: {output}[/dim]")


# ---------------------------------------------------------------------------
# review-key-posture
# ---------------------------------------------------------------------------

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

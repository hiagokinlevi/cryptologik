"""
cryptologik CLI
====================
Command-line interface for cryptologik.

Commands:
    review-crypto-config        Scan source files for cryptographic anti-patterns
    review-tls-config           Review TLS cipher suite and protocol configuration
    review-key-posture          Review key management posture from a YAML config
    review-contract-checklist   Run smart contract security checklist
    assess-crypto-agility       Evaluate migration flexibility and algorithm coupling
    assess-pqc-readiness        Evaluate post-quantum readiness and confidentiality risk
    generate-migration-plan     Build a wave-based hybrid migration plan
    generate-report             Generate Markdown, JSON, or SARIF security reports

Usage:
    cryptologik review-crypto-config --path ./src
    cryptologik review-tls-config --config tls-config.json
    cryptologik review-key-posture --config key-management.yaml
    cryptologik review-contract-checklist --contract ./contracts/MyToken.sol
    cryptologik generate-report --findings-json findings.json --format markdown
"""

import json
import os
import stat
import sys
from pathlib import Path
from typing import Optional

import click
import yaml
from pydantic import ValidationError

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:  # pragma: no cover - fallback simples para ambientes minimos
    def load_dotenv() -> bool:
        """Mantem a CLI operacional quando python-dotenv nao esta instalado."""

        return False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ModuleNotFoundError:  # pragma: no cover - fallback simples para ambientes minimos
    class Console:
        """Fallback minimo para ambientes sem rich."""

        def print(self, *objects: object, **_: object) -> None:
            print(*objects)

    class Panel:
        """Representacao textual simples para substituir rich.panel.Panel."""

        def __init__(self, renderable: object, title: str | None = None) -> None:
            self.renderable = renderable
            self.title = title

        @classmethod
        def fit(cls, renderable: object, title: str | None = None) -> "Panel":
            return cls(renderable, title=title)

        def __str__(self) -> str:
            return f"{self.title or 'Panel'}\n{self.renderable}"

    class Table:
        """Tabela textual simples para ambientes sem rich."""

        def __init__(self, title: str = "", show_lines: bool = False) -> None:
            self.title = title
            self.show_lines = show_lines
            self.columns: list[str] = []
            self.rows: list[tuple[str, ...]] = []

        def add_column(self, header: str, **_: object) -> None:
            self.columns.append(header)

        def add_row(self, *values: object) -> None:
            self.rows.append(tuple(str(value) for value in values))

        def __str__(self) -> str:
            lines = [self.title] if self.title else []
            if self.columns:
                lines.append(" | ".join(self.columns))
            lines.extend(" | ".join(row) for row in self.rows)
            return "\n".join(lines)

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


def _read_utf8_text(path: str, label: str) -> str:
    """Read a UTF-8 text file and raise a stable CLI error on failure."""
    file_path = Path(path)

    try:
        file_mode = file_path.lstat().st_mode
    except OSError as exc:
        message = exc.strerror or str(exc)
        raise click.ClickException(f"Could not read {label}: {message}.") from exc

    if stat.S_ISLNK(file_mode):
        raise click.ClickException(
            f"Could not read {label}: symlinked files are not allowed."
        )
    if not stat.S_ISREG(file_mode):
        raise click.ClickException(
            f"Could not read {label}: path must be a regular file."
        )

    try:
        return file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise click.ClickException(f"Could not decode {label} as UTF-8.") from exc
    except OSError as exc:
        message = exc.strerror or str(exc)
        raise click.ClickException(f"Could not read {label}: {message}.") from exc


def _write_utf8_text(path: str, contents: str, label: str) -> None:
    """Write a UTF-8 text file while rejecting symlinked or special destinations."""
    file_path = Path(path)

    for candidate in (file_path, *file_path.parents):
        if not candidate.exists():
            continue
        try:
            candidate_mode = candidate.lstat().st_mode
        except OSError as exc:
            message = exc.strerror or str(exc)
            raise click.ClickException(f"Could not write {label}: {message}.") from exc

        if stat.S_ISLNK(candidate_mode):
            path_kind = "file" if candidate == file_path else "directory"
            path_label = f"{path_kind}s" if path_kind == "file" else "directories"
            raise click.ClickException(
                f"Could not write {label}: symlinked {path_label} are not allowed."
            )
        if candidate == file_path:
            if not stat.S_ISREG(candidate_mode):
                raise click.ClickException(
                    f"Could not write {label}: path must be a regular file."
                )
            continue
        if not stat.S_ISDIR(candidate_mode):
            raise click.ClickException(
                f"Could not write {label}: parent path must be a directory."
            )

    try:
        file_path.write_text(contents, encoding="utf-8")
    except OSError as exc:
        message = exc.strerror or str(exc)
        raise click.ClickException(f"Could not write {label}: {message}.") from exc


def _load_json_document(path: str, label: str):
    """Load a JSON document and convert parse errors into ClickException."""
    try:
        return json.loads(_read_utf8_text(path, label))
    except json.JSONDecodeError as exc:
        raise click.ClickException(
            f"Could not parse {label}: {exc.msg} at line {exc.lineno}, column {exc.colno}."
        ) from exc


def _format_yaml_error(exc: yaml.YAMLError) -> str:
    """Return a concise YAML parse error with line/column context when available."""
    problem = getattr(exc, "problem", None) or str(exc)
    mark = getattr(exc, "problem_mark", None)
    if mark is None:
        return problem
    return f"{problem} at line {mark.line + 1}, column {mark.column + 1}"


def _load_structured_document(path: str) -> dict:
    """Carrega um documento JSON ou YAML para os fluxos de analise offline."""
    file_path = Path(path)
    raw = _read_utf8_text(path, "configuration file")
    if file_path.suffix.lower() in {".yaml", ".yml"}:
        try:
            loaded = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise click.ClickException(
                f"Could not parse YAML configuration: {_format_yaml_error(exc)}."
            ) from exc
    else:
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise click.ClickException(
                "Could not parse JSON configuration: "
                f"{exc.msg} at line {exc.lineno}, column {exc.colno}."
            ) from exc
    if not isinstance(loaded, dict):
        raise click.ClickException("Expected a JSON/YAML object with metadata and an assets list.")
    return loaded


def _load_asset_profiles(path: str) -> tuple[str, list]:
    """Converte um inventario estruturado em perfis validados de ativos."""
    from schemas.advanced_assessment import CryptoAssetProfile

    loaded = _load_structured_document(path)
    assets_raw = loaded.get("assets", [])
    if not isinstance(assets_raw, list) or not assets_raw:
        raise click.ClickException("Configuration must include a non-empty 'assets' list.")
    target_name = str(loaded.get("program_name") or loaded.get("target_name") or Path(path).stem)
    assets: list[CryptoAssetProfile] = []
    seen_asset_ids: dict[str, int] = {}
    for index, item in enumerate(assets_raw, start=1):
        if not isinstance(item, dict):
            raise click.ClickException(
                f"Asset entry #{index} must be an object with CryptoAssetProfile fields."
            )
        try:
            asset = CryptoAssetProfile(**item)
        except ValidationError as exc:
            details = "; ".join(
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in exc.errors()
            )
            raise click.ClickException(
                f"Asset entry #{index} is invalid: {details}"
            ) from exc
        previous_index = seen_asset_ids.get(asset.asset_id)
        if previous_index is not None:
            raise click.ClickException(
                f"Asset entry #{index} duplicates asset_id '{asset.asset_id}' from entry #{previous_index}."
            )
        seen_asset_ids[asset.asset_id] = index
        assets.append(asset)
    return target_name, assets


def _load_report_payload(path: str) -> list[dict]:
    """Load the report input file and reject malformed top-level payloads."""
    raw = _load_json_document(path, "findings JSON")

    if not isinstance(raw, list):
        raise click.ClickException(
            "Expected findings JSON to contain a top-level list of finding objects."
        )

    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise click.ClickException(f"Finding entry #{index} must be a JSON object.")

    return raw


def _require_string_list(value: object, *, field_name: str, entry_index: int) -> list[str]:
    """Validate that a TLS config field is a JSON array of strings."""
    if not isinstance(value, list):
        raise click.ClickException(
            f"TLS config entry #{entry_index} field '{field_name}' must be a JSON array of strings."
        )

    for item_index, item in enumerate(value, start=1):
        if not isinstance(item, str):
            raise click.ClickException(
                f"TLS config entry #{entry_index} field '{field_name}' item #{item_index} "
                "must be a string."
            )

    return value


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
    from crypto.validators.config_validator import CryptoConfigScanError, validate_crypto_config

    scan_path = Path(path)
    extensions = {f".{e.strip().lstrip('.')}" for e in ext.split(",")}
    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    strictness_threshold = {"strict": 1, "standard": 2, "minimal": 3}

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
        try:
            findings = validate_crypto_config(file)
        except CryptoConfigScanError as exc:
            raise click.ClickException(str(exc)) from exc
        all_findings.extend(findings)
    all_findings = [
        finding
        for finding in all_findings
        if severity_rank[finding.risk_level.value] >= strictness_threshold[strictness]
    ]
    all_findings.sort(
        key=lambda finding: (
            -severity_rank[finding.risk_level.value],
            finding.file_path,
            finding.line_number,
            finding.check_name,
        )
    )

    if not all_findings:
        console.print("[green]No cryptographic anti-patterns detected.[/green]")
        console.print(
            "[dim]Note: This scan does not guarantee absence of cryptographic weaknesses.[/dim]"
        )
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
        _write_utf8_text(output, json.dumps(findings_json, indent=2), "findings output")
        console.print(f"[dim]Findings written to: {output}[/dim]")


# ---------------------------------------------------------------------------
# review-tls-config
# ---------------------------------------------------------------------------

@cli.command("review-tls-config")
@click.option(
    "--config",
    required=True,
    type=click.Path(exists=True),
    help=(
        "JSON file containing one TLS config object or a list of objects with "
        "config_id, cipher_suites, tls_versions, and optional description."
    ),
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Write analysis results to this file as JSON (optional).",
)
@click.option(
    "--fail-on",
    type=click.Choice(["none", "critical", "high"]),
    default="none",
    show_default=True,
    help="Exit non-zero when findings at or above this severity are present.",
)
def review_tls_config(config: str, output: Optional[str], fail_on: str) -> None:
    """Review offline TLS cipher suite and protocol configuration."""
    from crypto.cipher_suite_analyzer import CipherSuiteConfig, analyze_many

    raw = _load_json_document(config, "TLS configuration JSON")
    if not isinstance(raw, (dict, list)):
        raise click.ClickException(
            "Expected TLS configuration JSON to contain an object or list of objects."
        )
    items = raw if isinstance(raw, list) else [raw]
    configs = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise click.ClickException(f"TLS config entry #{index} must be a JSON object.")
        try:
            configs.append(
                CipherSuiteConfig(
                    config_id=item["config_id"],
                    cipher_suites=_require_string_list(
                        item.get("cipher_suites", []),
                        field_name="cipher_suites",
                        entry_index=index,
                    ),
                    tls_versions=_require_string_list(
                        item.get("tls_versions", []),
                        field_name="tls_versions",
                        entry_index=index,
                    ),
                    description=item.get("description", item["config_id"]),
                )
            )
        except KeyError as exc:
            raise click.ClickException(
                f"TLS config entry #{index} is missing required field: {exc.args[0]}."
            ) from exc
        except TypeError as exc:
            raise click.ClickException(
                f"TLS config entry #{index} is invalid: {exc}."
            ) from exc
    results = analyze_many(configs)

    table = Table(title=f"TLS Config Results ({len(results)})", show_lines=True)
    table.add_column("Config", width=24)
    table.add_column("Grade", width=8)
    table.add_column("Score", width=8)
    table.add_column("Findings", width=48)

    for result in results:
        finding_ids = ", ".join(f.check_id for f in result.findings) or "none"
        table.add_row(
            result.config_id,
            result.grade,
            str(result.risk_score),
            finding_ids,
        )

    console.print(table)

    result_dicts = [result.to_dict() for result in results]
    if output:
        _write_utf8_text(output, json.dumps(result_dicts, indent=2), "TLS analysis output")
        console.print(f"[dim]TLS analysis written to: {output}[/dim]")

    severity_rank = {"CRITICAL": 3, "HIGH": 2}
    threshold = severity_rank.get(fail_on.upper(), 0)
    if threshold:
        has_blocking = any(
            severity_rank.get(finding.severity, 0) >= threshold
            for result in results
            for finding in result.findings
        )
        if has_blocking:
            raise click.ClickException(
                f"TLS configuration findings met --fail-on={fail_on} threshold"
            )


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
    from crypto.key_management.posture_checker import (
        KeyManagementConfigError,
        check_key_management_posture,
    )

    console.print(Panel.fit(
        f"[bold]Config:[/bold] {config}\n"
        f"[bold]Strictness:[/bold] {STRICTNESS}",
        title="[bold cyan]cryptologik — Key Management Posture Review[/bold cyan]",
    ))

    try:
        findings = check_key_management_posture(Path(config))
    except KeyManagementConfigError as exc:
        raise click.ClickException(str(exc)) from exc

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
        _write_utf8_text(output, json.dumps(findings_json, indent=2), "findings output")
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
    from blockchain.smart_contracts.review_checklist import (
        ContractSourceError,
        SmartContractReviewRunner,
    )

    console.print(Panel.fit(
        f"[bold]Contract:[/bold] {contract}\n"
        f"[bold]Framework:[/bold] SWC",
        title="[bold cyan]cryptologik — Smart Contract Review[/bold cyan]",
    ))

    runner = SmartContractReviewRunner()
    try:
        findings = runner.review(Path(contract))
    except ContractSourceError as exc:
        raise click.ClickException(str(exc)) from exc

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
        _write_utf8_text(output, json.dumps(findings_json, indent=2), "findings output")
        console.print(f"[dim]Findings written to: {output}[/dim]")


# ---------------------------------------------------------------------------
# assess-crypto-agility
# ---------------------------------------------------------------------------

@cli.command("assess-crypto-agility")
@click.option(
    "--config",
    required=True,
    type=click.Path(exists=True),
    help="JSON or YAML inventory describing cryptographic assets and migration controls.",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Write the assessment result to this file as JSON (optional).",
)
def assess_crypto_agility_command(config: str, output: Optional[str]) -> None:
    """Evaluate crypto agility posture from an offline asset inventory."""
    from analyzers.risk_modeling.crypto_agility_assessor import assess_crypto_agility

    target_name, assets = _load_asset_profiles(config)
    result = assess_crypto_agility(assets, target_name=target_name)

    console.print(Panel.fit(
        f"[bold]Target:[/bold] {result.target_name}\n"
        f"[bold]Assets:[/bold] {result.assessed_assets}\n"
        f"[bold]Agility score:[/bold] {result.crypto_agility_score}/100\n"
        f"[bold]Migration complexity:[/bold] {result.migration_complexity_score}/100\n"
        f"[bold]Coupling index:[/bold] {result.algorithm_coupling_index}/100\n"
        f"[bold]Risk:[/bold] {result.risk_level.value}",
        title="[bold cyan]cryptologik — Crypto Agility Assessment[/bold cyan]",
    ))

    actions = Table(title="Priority Actions", show_lines=True)
    actions.add_column("#", width=4)
    actions.add_column("Action", width=90)
    for index, action in enumerate(result.recommended_actions, start=1):
        actions.add_row(str(index), action)
    console.print(actions)

    if output:
        _write_utf8_text(output, result.model_dump_json(indent=2), "assessment output")
        console.print(f"[dim]Assessment written to: {output}[/dim]")


# ---------------------------------------------------------------------------
# assess-pqc-readiness
# ---------------------------------------------------------------------------

@cli.command("assess-pqc-readiness")
@click.option(
    "--config",
    required=True,
    type=click.Path(exists=True),
    help="JSON or YAML inventory describing assets, retention, hybrid readiness, and blockers.",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Write the readiness result to this file as JSON (optional).",
)
def assess_pqc_readiness_command(config: str, output: Optional[str]) -> None:
    """Evaluate post-quantum readiness and long-term confidentiality exposure."""
    from analyzers.pqc_readiness.readiness_assessor import assess_pqc_readiness

    target_name, assets = _load_asset_profiles(config)
    result = assess_pqc_readiness(assets, target_name=target_name)

    console.print(Panel.fit(
        f"[bold]Target:[/bold] {result.target_name}\n"
        f"[bold]Assets:[/bold] {result.assessed_assets}\n"
        f"[bold]PQC readiness:[/bold] {result.post_quantum_readiness_score}/100\n"
        f"[bold]Future exposure:[/bold] {result.future_exposure_risk.value}\n"
        f"[bold]Long-term confidentiality:[/bold] {result.long_term_confidentiality_risk.value}\n"
        f"[bold]Hybrid priority:[/bold] {result.hybrid_transition_priority}\n"
        f"[bold]Suggested wave:[/bold] {result.migration_wave}\n"
        f"[bold]Status:[/bold] {result.quantum_transition_status}",
        title="[bold cyan]cryptologik — Post-Quantum Readiness[/bold cyan]",
    ))

    actions = Table(title="Priority Actions", show_lines=True)
    actions.add_column("#", width=4)
    actions.add_column("Action", width=90)
    for index, action in enumerate(result.recommended_actions, start=1):
        actions.add_row(str(index), action)
    console.print(actions)

    if output:
        _write_utf8_text(output, result.model_dump_json(indent=2), "readiness output")
        console.print(f"[dim]Readiness result written to: {output}[/dim]")


# ---------------------------------------------------------------------------
# generate-migration-plan
# ---------------------------------------------------------------------------

@cli.command("generate-migration-plan")
@click.option(
    "--config",
    required=True,
    type=click.Path(exists=True),
    help="JSON or YAML inventory describing assets and migration blockers.",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Write the migration plan to this file as JSON (optional).",
)
def generate_migration_plan_command(config: str, output: Optional[str]) -> None:
    """Generate a wave-based hybrid migration plan for the supplied inventory."""
    from analyzers.migration_prioritization.planner import generate_migration_plan

    _, assets = _load_asset_profiles(config)
    plan = generate_migration_plan(assets)

    table = Table(title=f"Migration Plan ({len(plan)} assets)", show_lines=True)
    table.add_column("Asset", width=28)
    table.add_column("Wave", width=6)
    table.add_column("Priority", width=10)
    table.add_column("Hybrid", width=8)
    table.add_column("Confidentiality", width=16)

    for item in plan:
        table.add_row(
            item.asset_name,
            str(item.migration_wave),
            str(item.migration_priority),
            "yes" if item.hybrid_mode_required else "no",
            item.long_term_confidentiality_risk.value,
        )

    console.print(table)

    if output:
        serialized = [item.model_dump(mode="json") for item in plan]
        _write_utf8_text(output, json.dumps(serialized, indent=2), "migration plan output")
        console.print(f"[dim]Migration plan written to: {output}[/dim]")


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
    type=click.Choice(["markdown", "json", "sarif"]),
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
    from reports.report_generator import generate_markdown_report, generate_sarif_report

    raw = _load_report_payload(findings_json)

    findings = []
    for index, item in enumerate(raw, start=1):
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
        except ValidationError as exc:
            details = "; ".join(
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in exc.errors()
            )
            raise click.ClickException(
                f"Finding entry #{index} is invalid: {details}"
            ) from exc
        except ValueError as exc:
            raise click.ClickException(
                f"Finding entry #{index} is invalid: {exc}"
            ) from exc

    summary = AssessmentSummary.from_findings(
        findings,
        target_description=target,
        assessment_profile=STRICTNESS,
    )

    if report_format == "markdown":
        report = generate_markdown_report(summary, verbosity=verbosity)
    elif report_format == "sarif":
        report = generate_sarif_report(summary)
    else:
        report = summary.model_dump_json(indent=2)

    if output:
        _write_utf8_text(output, report, "report output")
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        console.print(report)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()

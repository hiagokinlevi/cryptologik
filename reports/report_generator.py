"""
Cryptographic and Blockchain Security Report Generator
========================================================
Generates Markdown and SARIF security assessment reports from AssessmentSummary objects.

Produces:
  - A structured Markdown report with executive summary, findings table, and recommendations
  - SARIF 2.1.0 output for CI/CD and IDE ingestion
  - Optional per-finding detail sections
  - Risk heat map (text-based) for visual severity distribution

Usage:
    from schemas.crypto_finding import AssessmentSummary
    from reports.report_generator import generate_markdown_report, generate_sarif_report

    summary = AssessmentSummary.from_findings(findings, target_description="MyProject")
    report_md = generate_markdown_report(summary, verbosity="standard")
    Path("report.md").write_text(report_md)
    Path("report.sarif").write_text(generate_sarif_report(summary))

Design notes:
  - Report content is purely derived from the AssessmentSummary — no external calls
  - Evidence fields are included only in verbose mode to minimize sensitive data in reports
  - All timestamps are in UTC ISO 8601 format
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Union

import structlog
from dotenv import load_dotenv

try:
    from jinja2 import BaseLoader, Environment
except ModuleNotFoundError:  # pragma: no cover - optional dependency fallback
    BaseLoader = None
    Environment = None

from schemas.crypto_finding import (
    AssessmentSummary,
    BaseFinding,
    CryptoConfigFinding,
    KeyManagementFinding,
    RiskLevel,
    SmartContractFinding,
)

load_dotenv()
log = structlog.get_logger(__name__)

# Default verbosity from environment
DEFAULT_VERBOSITY = os.getenv("REPORT_VERBOSITY", "standard")

# Risk level display mapping for Markdown
RISK_BADGES = {
    RiskLevel.CRITICAL: "**CRITICAL**",
    RiskLevel.HIGH: "**HIGH**",
    RiskLevel.MEDIUM: "Medium",
    RiskLevel.LOW: "Low",
    RiskLevel.INFORMATIONAL: "_Informational_",
}

# Jinja2 template for the full report
_REPORT_TEMPLATE = """# Cryptographic Security Assessment Report

**Target:** {{ summary.target_description | md_inline }}
**Assessment ID:** {{ summary.assessment_id | md_inline }}
**Conducted At:** {{ summary.conducted_at.strftime('%Y-%m-%d %H:%M UTC') }}
**Conducted By:** {{ (summary.conducted_by or 'cryptologik automated scan') | md_inline }}
**Profile:** {{ summary.assessment_profile | md_inline }}
**Generated At:** {{ generated_at | md_inline }}

---

## Executive Summary

This report presents the findings of a cryptographic security assessment of **{{ summary.target_description | md_inline }}**.

**Overall Risk Rating: {{ overall_risk }}**

| Risk Level | Count |
|---|---|
| Critical | {{ summary.critical_count }} |
| High | {{ summary.high_count }} |
| Medium | {{ summary.medium_count }} |
| Low | {{ summary.low_count }} |
| Informational | {{ summary.informational_count }} |
| **Total** | **{{ summary.total_findings }}** |

{% if summary.critical_count > 0 or summary.high_count > 0 %}
> **Action Required:** This assessment identified {{ summary.critical_count }} critical and {{ summary.high_count }} high-severity findings that should be remediated before the next production release or deployment.
{% else %}
> No critical or high-severity findings were identified in this assessment.
{% endif %}

---

## Findings Overview

{% if all_findings %}
| # | ID | Risk | Category | Title |{% if verbosity == 'verbose' %} File/Location |{% endif %}
|---|---|---|---|---|{% if verbosity == 'verbose' %}---|{% endif %}
{% for finding in all_findings %}
| {{ loop.index }} | {{ finding.finding_id | md_cell }} | {{ risk_badge(finding.risk_level) }} | {{ finding.category.value | md_cell }} | {{ finding.title | md_cell }} |{% if verbosity == 'verbose' %}{{ get_location(finding) }} |{% endif %}
{% endfor %}
{% else %}
No findings were identified.
{% endif %}

---

## Detailed Findings

{% for finding in all_findings %}
### {{ loop.index }}. {{ finding.title | md_heading }}

| Field | Value |
|---|---|
| **Finding ID** | {{ finding.finding_id | md_inline }} |
| **Risk Level** | {{ risk_badge(finding.risk_level) }} |
| **Category** | {{ finding.category.value | md_inline }} |
| **Status** | {{ finding.status.value | md_inline }} |
{% if finding is crypto_finding %}
| **File** | `{{ finding.file_path | md_code }}` |
| **Line** | {{ finding.line_number }} |
| **Check** | {{ finding.check_name | md_inline }} |
{% elif finding is contract_finding %}
| **SWC** | {{ finding.swc_id | md_inline }} — {{ finding.swc_title | md_inline }} |
{% if finding.contract_path %}| **Contract** | `{{ finding.contract_path | md_code }}` |{% endif %}
{% if finding.line_number %}| **Line** | {{ finding.line_number }} |{% endif %}
{% elif finding is km_finding %}
| **Check ID** | {{ finding.check_id | md_inline }} |
| **Key** | {{ finding.key_name | md_inline }} |
{% endif %}

**Description:**

{{ finding.description | md_block }}

**Recommendation:**

{{ finding.recommendation | md_block }}

{% if finding.false_positive_note %}
**False Positive Note:**

_{{ finding.false_positive_note }}_
{% endif %}

{% if finding.requires_manual_review %}
> **Manual Review Required:** This finding was produced by automated static analysis. Confirm whether it represents a real vulnerability before remediation.
{% endif %}

{% if verbosity == 'verbose' and finding.evidence %}
**Evidence (truncated):**

{{ finding.evidence | md_indent_code }}
{% endif %}

---
{% endfor %}

## Recommendations Summary

{% if summary.critical_count > 0 %}
### Immediate Actions (Critical)

{% for finding in all_findings if finding.risk_level.value == 'critical' %}
- **{{ finding.title | md_inline }}:** {{ finding.recommendation[:200] | md_inline }}...
{% endfor %}
{% endif %}

{% if summary.high_count > 0 %}
### Priority Remediations (High)

{% for finding in all_findings if finding.risk_level.value == 'high' %}
- **{{ finding.title | md_inline }}:** {{ finding.recommendation[:200] | md_inline }}...
{% endfor %}
{% endif %}

---

## Disclaimer

This report was generated by cryptologik automated static analysis. All findings require manual verification before acting. Automated analysis cannot detect all cryptographic weaknesses — this report does not substitute for a professional security assessment or penetration test.

_Report generated by cryptologik v1.0.0_
"""


def _risk_badge(risk: RiskLevel) -> str:
    """Return a Markdown-formatted risk badge for the given level."""
    return RISK_BADGES.get(risk, risk.value)


_MD_WHITESPACE_RE = re.compile(r"\s+")


def _strip_control_chars(value: str, *, allow_newlines: bool) -> str:
    normalized: list[str] = []
    for ch in value:
        codepoint = ord(ch)
        if ch == "\n" and allow_newlines:
            normalized.append(ch)
            continue
        if ch == "\n" and not allow_newlines:
            normalized.append(" ")
            continue
        if ch in {"\r", "\t"}:
            normalized.append(" ")
            continue
        if codepoint < 32 or codepoint == 127:
            continue
        normalized.append(ch)
    return "".join(normalized)


def _md_inline(value: Any) -> str:
    """
    Sanitize untrusted values for inline Markdown contexts.

    - strips ASCII control characters
    - collapses whitespace
    """
    if value is None:
        return ""
    text = _strip_control_chars(str(value), allow_newlines=False)
    return _MD_WHITESPACE_RE.sub(" ", text).strip()


def _md_table_cell(value: Any) -> str:
    """Escape `|` for Markdown tables and keep cells single-line."""
    text = _md_inline(value)
    return text.replace("|", r"\|")


def _md_heading(value: Any) -> str:
    """Keep headings single-line to avoid Markdown injection via newlines."""
    return _md_inline(value)


def _md_code(value: Any) -> str:
    """
    Sanitize content for Markdown code spans.

    Backticks are replaced to prevent breaking out of inline code.
    """
    text = _md_inline(value)
    return text.replace("`", "'")


def _md_block(value: Any) -> str:
    """Sanitize untrusted values for Markdown block contexts."""
    if value is None:
        return ""
    return _strip_control_chars(str(value), allow_newlines=True).rstrip()


def _md_indent_code(value: Any) -> str:
    """Render a Markdown indented code block to avoid fence breakouts."""
    text = _md_block(value)
    if not text:
        return ""
    return "\n".join(f"    {line}" for line in text.splitlines())


def _get_location(finding: BaseFinding) -> str:
    """Extract a location string from a finding for the overview table."""
    if isinstance(finding, (CryptoConfigFinding,)):
        return f"`{_md_code(f'{finding.file_path}:{finding.line_number}')}`"
    if isinstance(finding, SmartContractFinding):
        loc = finding.contract_path or "unknown"
        if finding.line_number:
            return f"`{_md_code(f'{loc}:{finding.line_number}')}`"
        return f"`{_md_code(loc)}`"
    if isinstance(finding, KeyManagementFinding):
        return f"Key: `{_md_code(finding.key_name)}`"
    return ""


def _collect_findings(summary: AssessmentSummary) -> list[BaseFinding]:
    """Return all findings in deterministic severity order."""
    all_findings: list[BaseFinding] = [
        *summary.crypto_config_findings,
        *summary.smart_contract_findings,
        *summary.key_management_findings,
    ]
    risk_order = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 3,
        RiskLevel.INFORMATIONAL: 4,
    }
    all_findings.sort(key=lambda finding: risk_order.get(finding.risk_level, 99))
    return all_findings


def _render_markdown_fallback(
    summary: AssessmentSummary,
    all_findings: list[BaseFinding],
    verbosity: str,
    generated_at: str,
) -> str:
    """Render a minimal Markdown report when Jinja2 is unavailable."""
    lines = [
        "# Cryptographic Security Assessment Report",
        "",
        f"**Target:** {_md_inline(summary.target_description)}",
        f"**Assessment ID:** {_md_inline(summary.assessment_id)}",
        f"**Conducted At:** {summary.conducted_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Conducted By:** {_md_inline(summary.conducted_by or 'cryptologik automated scan')}",
        f"**Profile:** {_md_inline(summary.assessment_profile)}",
        f"**Generated At:** {_md_inline(generated_at)}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"**Overall Risk Rating: {_risk_badge(summary.overall_risk)}**",
        "",
        "| Risk Level | Count |",
        "|---|---|",
        f"| Critical | {summary.critical_count} |",
        f"| High | {summary.high_count} |",
        f"| Medium | {summary.medium_count} |",
        f"| Low | {summary.low_count} |",
        f"| Informational | {summary.informational_count} |",
        f"| **Total** | **{summary.total_findings}** |",
        "",
        "---",
        "",
        "## Findings Overview",
        "",
    ]

    if not all_findings:
        lines.append("No findings were identified.")
        return "\n".join(lines)

    header = "| # | ID | Risk | Category | Title |"
    separator = "|---|---|---|---|---|"
    if verbosity == "verbose":
        header = "| # | ID | Risk | Category | Title | File/Location |"
        separator = "|---|---|---|---|---|---|"
    lines.extend([header, separator])

    for index, finding in enumerate(all_findings, start=1):
        row = (
            f"| {index} | {_md_table_cell(finding.finding_id)} | {_risk_badge(finding.risk_level)} | "
            f"{_md_table_cell(finding.category.value)} | {_md_table_cell(finding.title)} |"
        )
        if verbosity == "verbose":
            row = row[:-1] + f" {_get_location(finding)} |"
        lines.append(row)

    lines.extend(["", "---", "", "## Detailed Findings", ""])
    for index, finding in enumerate(all_findings, start=1):
        finding_title = _md_heading(finding.title)
        lines.extend(
            [
                f"### {index}. {finding_title}",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| **Finding ID** | {_md_inline(finding.finding_id)} |",
                f"| **Risk Level** | {_risk_badge(finding.risk_level)} |",
                f"| **Category** | {_md_inline(finding.category.value)} |",
                f"| **Status** | {_md_inline(finding.status.value)} |",
            ]
        )
        if isinstance(finding, CryptoConfigFinding):
            lines.extend(
                [
                    f"| **File** | `{_md_code(finding.file_path)}` |",
                    f"| **Line** | {finding.line_number} |",
                    f"| **Check** | {_md_inline(finding.check_name)} |",
                ]
            )
        elif isinstance(finding, SmartContractFinding):
            lines.append(
                f"| **SWC** | {_md_inline(finding.swc_id)} — {_md_inline(finding.swc_title)} |"
            )
            if finding.contract_path:
                lines.append(f"| **Contract** | `{_md_code(finding.contract_path)}` |")
            if finding.line_number:
                lines.append(f"| **Line** | {finding.line_number} |")
        elif isinstance(finding, KeyManagementFinding):
            lines.extend(
                [
                    f"| **Check ID** | {_md_inline(finding.check_id)} |",
                    f"| **Key** | {_md_inline(finding.key_name)} |",
                ]
            )

        lines.extend(
            [
                "",
                "**Description:**",
                "",
                _md_block(finding.description),
                "",
                "**Recommendation:**",
                "",
                _md_block(finding.recommendation),
                "",
            ]
        )
        if finding.false_positive_note:
            lines.extend(
                ["**False Positive Note:**", "", f"_{_md_block(finding.false_positive_note)}_", ""]
            )
        if finding.requires_manual_review:
            lines.append(
                "> **Manual Review Required:** This finding was produced by automated static analysis. Confirm whether it represents a real vulnerability before remediation."
            )
            lines.append("")
        if verbosity == "verbose" and finding.evidence:
            lines.extend(["**Evidence (truncated):**", "", _md_indent_code(finding.evidence), ""])
        lines.extend(["---", ""])

    return "\n".join(lines).rstrip() + "\n"


def _sarif_level(risk: RiskLevel) -> str:
    """Map internal severities to SARIF levels."""
    if risk in {RiskLevel.CRITICAL, RiskLevel.HIGH}:
        return "error"
    if risk == RiskLevel.MEDIUM:
        return "warning"
    return "note"


def _sarif_rule_id(finding: BaseFinding) -> str:
    """Pick a stable per-finding-type SARIF rule identifier."""
    if isinstance(finding, CryptoConfigFinding):
        return finding.check_name
    if isinstance(finding, SmartContractFinding):
        return finding.swc_id
    if isinstance(finding, KeyManagementFinding):
        return finding.check_id
    return finding.finding_id


def _sarif_help_markdown(finding: BaseFinding) -> str:
    """Build SARIF remediation guidance from finding details."""
    lines = [finding.description.strip()]
    if finding.recommendation.strip():
        lines.extend(["", f"Recommendation: {finding.recommendation.strip()}"])
    if finding.false_positive_note.strip():
        lines.extend(["", f"False positive note: {finding.false_positive_note.strip()}"])
    return "\n".join(lines)


def _sarif_rule_descriptor(finding: BaseFinding) -> dict[str, Any]:
    """Create a SARIF rule descriptor for a finding."""
    return {
        "id": _sarif_rule_id(finding),
        "name": _sarif_rule_id(finding),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "help": {"text": finding.recommendation or finding.description},
        "helpUri": "https://github.com/hiagokinlevi/cryptologik",
        "properties": {
            "category": finding.category.value,
            "tags": list(finding.tags),
            "defaultConfiguration": {"level": _sarif_level(finding.risk_level)},
        },
    }


def _sarif_locations(finding: BaseFinding) -> list[dict[str, Any]]:
    """Translate finding locations into SARIF physical locations."""
    path: str | None = None
    line_number: int | None = None
    if isinstance(finding, CryptoConfigFinding):
        path = finding.file_path
        line_number = finding.line_number
    elif isinstance(finding, SmartContractFinding) and finding.contract_path:
        path = finding.contract_path
        line_number = finding.line_number

    if not path:
        return []

    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
        }
    }
    if line_number:
        location["physicalLocation"]["region"] = {"startLine": line_number}
    return [location]


def generate_sarif_report(summary: AssessmentSummary) -> str:
    """Generate SARIF 2.1.0 output from an assessment summary."""
    all_findings = _collect_findings(summary)
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in all_findings:
        rule_id = _sarif_rule_id(finding)
        rules_by_id.setdefault(rule_id, _sarif_rule_descriptor(finding))

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(finding.risk_level),
            "message": {"text": finding.title},
            "help": {"markdown": _sarif_help_markdown(finding)},
            "properties": {
                "findingId": finding.finding_id,
                "riskLevel": finding.risk_level.value,
                "category": finding.category.value,
                "status": finding.status.value,
                "requiresManualReview": finding.requires_manual_review,
                "recommendation": finding.recommendation,
                "tags": list(finding.tags),
            },
        }
        if finding.false_positive_note:
            result["properties"]["falsePositiveNote"] = finding.false_positive_note
        if finding.evidence:
            result["partialFingerprints"] = {"evidenceSnippet": finding.evidence}

        locations = _sarif_locations(finding)
        if locations:
            result["locations"] = locations

        results.append(result)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cryptologik",
                        "informationUri": "https://github.com/hiagokinlevi/cryptologik",
                        "semanticVersion": "1.0.0",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "automationDetails": {"id": summary.assessment_id},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "targetDescription": summary.target_description,
                            "assessmentProfile": summary.assessment_profile,
                            "generatedAt": datetime.now(timezone.utc).isoformat(),
                        },
                    }
                ],
                "results": results,
            }
        ],
    }

    log.info(
        "sarif_report_generated",
        assessment_id=summary.assessment_id,
        total_findings=summary.total_findings,
        overall_risk=summary.overall_risk.value,
    )
    return json.dumps(payload, indent=2)


def generate_markdown_report(
    summary: AssessmentSummary,
    verbosity: str = DEFAULT_VERBOSITY,
) -> str:
    """
    Generate a Markdown assessment report from an AssessmentSummary.

    Args:
        summary: The completed AssessmentSummary containing all findings.
        verbosity: Detail level — 'minimal', 'standard', or 'verbose'.

    Returns:
        Markdown string containing the full report.
    """
    all_findings = _collect_findings(summary)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if Environment is None or BaseLoader is None:
        report = _render_markdown_fallback(summary, all_findings, verbosity, generated_at)
    else:
        env = Environment(loader=BaseLoader(), autoescape=False)
        env.tests["crypto_finding"] = lambda f: isinstance(f, CryptoConfigFinding)
        env.tests["contract_finding"] = lambda f: isinstance(f, SmartContractFinding)
        env.tests["km_finding"] = lambda f: isinstance(f, KeyManagementFinding)
        env.filters["md_inline"] = _md_inline
        env.filters["md_cell"] = _md_table_cell
        env.filters["md_heading"] = _md_heading
        env.filters["md_code"] = _md_code
        env.filters["md_block"] = _md_block
        env.filters["md_indent_code"] = _md_indent_code

        template = env.from_string(_REPORT_TEMPLATE)
        report = template.render(
            summary=summary,
            all_findings=all_findings,
            verbosity=verbosity,
            generated_at=generated_at,
            overall_risk=_risk_badge(summary.overall_risk),
            risk_badge=_risk_badge,
            get_location=_get_location,
        )

    log.info(
        "report_generated",
        assessment_id=summary.assessment_id,
        total_findings=summary.total_findings,
        overall_risk=summary.overall_risk.value,
        verbosity=verbosity,
    )

    return report


def write_report(
    summary: AssessmentSummary,
    output_path: Path,
    verbosity: str = DEFAULT_VERBOSITY,
) -> None:
    """
    Generate and write a Markdown report to a file.

    Args:
        summary: The AssessmentSummary to report on.
        output_path: File path to write the report to. Parent directory must exist.
        verbosity: Report detail level.
    """
    report = generate_markdown_report(summary, verbosity=verbosity)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    log.info("report_written", path=str(output_path))

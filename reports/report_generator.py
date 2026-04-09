"""
Cryptographic and Blockchain Security Report Generator
========================================================
Generates Markdown security assessment reports from AssessmentSummary objects.

Produces:
  - A structured Markdown report with executive summary, findings table, and recommendations
  - Optional per-finding detail sections
  - Risk heat map (text-based) for visual severity distribution

Usage:
    from schemas.crypto_finding import AssessmentSummary
    from reports.report_generator import generate_markdown_report

    summary = AssessmentSummary.from_findings(findings, target_description="MyProject")
    report_md = generate_markdown_report(summary, verbosity="standard")
    Path("report.md").write_text(report_md)

Design notes:
  - Report content is purely derived from the AssessmentSummary — no external calls
  - Evidence fields are included only in verbose mode to minimize sensitive data in reports
  - All timestamps are in UTC ISO 8601 format
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Union

import structlog
from dotenv import load_dotenv
from jinja2 import Environment, BaseLoader

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

**Target:** {{ summary.target_description }}
**Assessment ID:** {{ summary.assessment_id }}
**Conducted At:** {{ summary.conducted_at.strftime('%Y-%m-%d %H:%M UTC') }}
**Conducted By:** {{ summary.conducted_by or 'cryptologik automated scan' }}
**Profile:** {{ summary.assessment_profile }}
**Generated At:** {{ generated_at }}

---

## Executive Summary

This report presents the findings of a cryptographic security assessment of **{{ summary.target_description }}**.

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
| {{ loop.index }} | {{ finding.finding_id }} | {{ risk_badge(finding.risk_level) }} | {{ finding.category.value }} | {{ finding.title }} |{% if verbosity == 'verbose' %}{{ get_location(finding) }} |{% endif %}
{% endfor %}
{% else %}
No findings were identified.
{% endif %}

---

## Detailed Findings

{% for finding in all_findings %}
### {{ loop.index }}. {{ finding.title }}

| Field | Value |
|---|---|
| **Finding ID** | {{ finding.finding_id }} |
| **Risk Level** | {{ risk_badge(finding.risk_level) }} |
| **Category** | {{ finding.category.value }} |
| **Status** | {{ finding.status.value }} |
{% if finding is crypto_finding %}
| **File** | `{{ finding.file_path }}` |
| **Line** | {{ finding.line_number }} |
| **Check** | {{ finding.check_name }} |
{% elif finding is contract_finding %}
| **SWC** | {{ finding.swc_id }} — {{ finding.swc_title }} |
{% if finding.contract_path %}| **Contract** | `{{ finding.contract_path }}` |{% endif %}
{% if finding.line_number %}| **Line** | {{ finding.line_number }} |{% endif %}
{% elif finding is km_finding %}
| **Check ID** | {{ finding.check_id }} |
| **Key** | {{ finding.key_name }} |
{% endif %}

**Description:**

{{ finding.description }}

**Recommendation:**

{{ finding.recommendation }}

{% if finding.false_positive_note %}
**False Positive Note:**

_{{ finding.false_positive_note }}_
{% endif %}

{% if finding.requires_manual_review %}
> **Manual Review Required:** This finding was produced by automated static analysis. Confirm whether it represents a real vulnerability before remediation.
{% endif %}

{% if verbosity == 'verbose' and finding.evidence %}
**Evidence (truncated):**

```
{{ finding.evidence }}
```
{% endif %}

---
{% endfor %}

## Recommendations Summary

{% if summary.critical_count > 0 %}
### Immediate Actions (Critical)

{% for finding in all_findings if finding.risk_level.value == 'critical' %}
- **{{ finding.title }}:** {{ finding.recommendation[:200] }}...
{% endfor %}
{% endif %}

{% if summary.high_count > 0 %}
### Priority Remediations (High)

{% for finding in all_findings if finding.risk_level.value == 'high' %}
- **{{ finding.title }}:** {{ finding.recommendation[:200] }}...
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


def _get_location(finding: BaseFinding) -> str:
    """Extract a location string from a finding for the overview table."""
    if isinstance(finding, (CryptoConfigFinding,)):
        return f"`{finding.file_path}:{finding.line_number}`"
    if isinstance(finding, SmartContractFinding):
        loc = finding.contract_path or "unknown"
        if finding.line_number:
            return f"`{loc}:{finding.line_number}`"
        return f"`{loc}`"
    if isinstance(finding, KeyManagementFinding):
        return f"Key: `{finding.key_name}`"
    return ""


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
    all_findings: list[BaseFinding] = [
        *summary.crypto_config_findings,
        *summary.smart_contract_findings,
        *summary.key_management_findings,
    ]

    # Sort findings by risk level (critical first)
    risk_order = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 3,
        RiskLevel.INFORMATIONAL: 4,
    }
    all_findings.sort(key=lambda f: risk_order.get(f.risk_level, 99))

    # Build Jinja2 environment with custom tests
    env = Environment(loader=BaseLoader(), autoescape=False)
    env.tests["crypto_finding"] = lambda f: isinstance(f, CryptoConfigFinding)
    env.tests["contract_finding"] = lambda f: isinstance(f, SmartContractFinding)
    env.tests["km_finding"] = lambda f: isinstance(f, KeyManagementFinding)

    template = env.from_string(_REPORT_TEMPLATE)

    report = template.render(
        summary=summary,
        all_findings=all_findings,
        verbosity=verbosity,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
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

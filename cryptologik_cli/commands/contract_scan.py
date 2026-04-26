import json
from typing import Any, Dict, List, Optional

import click


def _severity_to_level(severity: Optional[str]) -> str:
    s = (severity or "").strip().lower()
    if s in {"critical", "high", "error"}:
        return "error"
    if s in {"medium", "warning", "warn"}:
        return "warning"
    return "note"


def _format_contract_findings_as_sarif(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    rules_index: Dict[str, Dict[str, Any]] = {}

    for f in findings:
      rule_id = str(f.get("rule_id") or f.get("id") or "CONTRACT-FINDING")
      message = str(f.get("message") or f.get("description") or "Contract finding")
      severity = f.get("severity")
      level = _severity_to_level(severity)

      if rule_id not in rules_index:
          rules_index[rule_id] = {
              "id": rule_id,
              "shortDescription": {"text": rule_id},
          }

      result: Dict[str, Any] = {
          "ruleId": rule_id,
          "level": level,
          "message": {"text": message},
      }

      file_path = f.get("file") or f.get("path")
      line = f.get("line")
      if file_path:
          region: Dict[str, Any] = {}
          if isinstance(line, int) and line > 0:
              region["startLine"] = line
          result["locations"] = [
              {
                  "physicalLocation": {
                      "artifactLocation": {"uri": str(file_path)},
                      **({"region": region} if region else {}),
                  }
              }
          ]

      results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cryptologik-contract-scan",
                        "informationUri": "https://sarifweb.azurewebsites.net/",
                        "rules": list(rules_index.values()),
                    }
                },
                "results": results,
            }
        ],
    }


@click.command("contract-scan")
@click.option("--path", "path_", required=True, type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["text", "json", "sarif"]), default="text", show_default=True)
def contract_scan(path_: str, output_format: str) -> None:
    """Scan a Solidity smart contract for security findings."""
    # Local import to keep command startup fast and preserve existing architecture.
    from cryptologik.blockchain.contract_scanner import scan_contract

    findings = scan_contract(path_)

    if output_format == "json":
        click.echo(json.dumps(findings, indent=2))
        return

    if output_format == "sarif":
        click.echo(json.dumps(_format_contract_findings_as_sarif(findings), indent=2))
        return

    if not findings:
        click.echo("No contract findings.")
        return

    for f in findings:
        rid = f.get("rule_id") or f.get("id") or "CONTRACT-FINDING"
        sev = (f.get("severity") or "unknown").upper()
        msg = f.get("message") or f.get("description") or "Contract finding"
        loc_file = f.get("file") or f.get("path")
        loc_line = f.get("line")
        loc = ""
        if loc_file:
            loc = f" ({loc_file}{':' + str(loc_line) if isinstance(loc_line, int) else ''})"
        click.echo(f"[{sev}] {rid}: {msg}{loc}")

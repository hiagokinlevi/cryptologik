import json

from click.testing import CliRunner

from cryptologik_cli.commands.contract_scan import contract_scan


def test_contract_scan_outputs_valid_minimal_sarif(monkeypatch, tmp_path):
    contract = tmp_path / "Sample.sol"
    contract.write_text("pragma solidity ^0.8.0; contract Sample {}")

    def _fake_scan_contract(_):
        return [
            {
                "rule_id": "SWC-107",
                "message": "Potential reentrancy issue",
                "severity": "high",
                "file": "Sample.sol",
                "line": 12,
            }
        ]

    import cryptologik.blockchain.contract_scanner as scanner

    monkeypatch.setattr(scanner, "scan_contract", _fake_scan_contract)

    runner = CliRunner()
    result = runner.invoke(contract_scan, ["--path", str(contract), "--format", "sarif"])

    assert result.exit_code == 0, result.output
    sarif = json.loads(result.output)

    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif and len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "cryptologik-contract-scan"
    assert len(run["results"]) == 1

    finding = run["results"][0]
    assert finding["ruleId"] == "SWC-107"
    assert finding["level"] == "error"
    assert finding["message"]["text"] == "Potential reentrancy issue"
    assert finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "Sample.sol"
    assert finding["locations"][0]["physicalLocation"]["region"]["startLine"] == 12

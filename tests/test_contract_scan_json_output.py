import json
from pathlib import Path

from click.testing import CliRunner

from cryptologik_cli.main import cli


def test_contract_scan_json_output_shape_and_non_empty():
    runner = CliRunner()
    sample = Path("examples/contracts/SimpleVault.sol")

    result = runner.invoke(cli, ["contract-scan", "--path", str(sample), "--json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    assert "findings" in data
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) > 0

    first = data["findings"][0]
    for key in ["rule_id", "severity", "file", "line", "message", "recommendation"]:
        assert key in first

    assert "summary" in data
    assert data["summary"]["total"] == len(data["findings"])
    assert isinstance(data["summary"].get("by_severity"), dict)

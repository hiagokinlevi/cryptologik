import json
from pathlib import Path

from click.testing import CliRunner

from cryptologik_cli.main import cli


def test_contract_scan_json_writes_output_file(tmp_path: Path, monkeypatch) -> None:
    contract_file = tmp_path / "Simple.sol"
    contract_file.write_text("contract Simple {}", encoding="utf-8")

    findings = [
        {"id": "SWC-000", "title": "Sample finding", "severity": "low"},
    ]

    def _fake_scan_contract(_path: str):
        return findings

    monkeypatch.setattr("cryptologik_cli.main.scan_contract", _fake_scan_contract)

    output_file = tmp_path / "nested" / "results" / "scan.json"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "contract-scan",
            "--path",
            str(contract_file),
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0, result.output
    assert output_file.exists()

    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert data == {"findings": findings}

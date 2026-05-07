from pathlib import Path

from typer.testing import CliRunner

from cryptologik_cli.main import app


def test_contract_scan_writes_text_findings_to_output_file(tmp_path: Path) -> None:
    runner = CliRunner()
    out_file = tmp_path / "findings.txt"

    result = runner.invoke(
        app,
        [
            "contract-scan",
            "--path",
            "examples/contracts/SimpleVault.sol",
            "--output",
            str(out_file),
        ],
    )

    assert result.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert content.strip() != ""
    assert "SimpleVault.sol" in content or "SWC" in content or "severity" in content.lower()

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from cryptologik_cli.main import cli


def _write_contract(tmp_path: Path) -> Path:
    p = tmp_path / "Test.sol"
    p.write_text("contract Test { function f() public {} }", encoding="utf-8")
    return p


def test_contract_scan_default_behavior_unchanged(monkeypatch, tmp_path):
    contract = _write_contract(tmp_path)

    def fake_scan_contract(_path: str):
        return {
            "findings": [
                {"severity": "high", "title": "Reentrancy risk"},
            ]
        }

    monkeypatch.setattr("cryptologik_cli.main.scan_contract", fake_scan_contract)

    runner = CliRunner()
    result = runner.invoke(cli, ["contract-scan", "--path", str(contract)])
    assert result.exit_code == 0


def test_contract_scan_fail_on_threshold_triggers(monkeypatch, tmp_path):
    contract = _write_contract(tmp_path)

    def fake_scan_contract(_path: str):
        return {
            "findings": [
                {"severity": "medium", "title": "Unchecked return"},
            ]
        }

    monkeypatch.setattr("cryptologik_cli.main.scan_contract", fake_scan_contract)

    runner = CliRunner()
    result = runner.invoke(cli, ["contract-scan", "--path", str(contract), "--fail-on", "medium"])
    assert result.exit_code != 0


def test_contract_scan_fail_on_threshold_passes(monkeypatch, tmp_path):
    contract = _write_contract(tmp_path)

    def fake_scan_contract(_path: str):
        return {
            "findings": [
                {"severity": "low", "title": "Style issue"},
            ]
        }

    monkeypatch.setattr("cryptologik_cli.main.scan_contract", fake_scan_contract)

    runner = CliRunner()
    result = runner.invoke(cli, ["contract-scan", "--path", str(contract), "--fail-on", "high"])
    assert result.exit_code == 0

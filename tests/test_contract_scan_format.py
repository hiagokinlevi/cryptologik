from __future__ import annotations

import pytest

from cryptologik_cli.main import main


def test_contract_scan_format_paths_and_invalid(monkeypatch, capsys):
    monkeypatch.setattr("cryptologik_cli.main.scan_contract", lambda _p: [{"id": "X", "severity": "high"}])
    monkeypatch.setattr("cryptologik_cli.main.render_text_report", lambda _f: "TEXT")
    monkeypatch.setattr("cryptologik_cli.main.render_json_report", lambda _f: "{\"ok\":true}")
    monkeypatch.setattr("cryptologik_cli.main.render_sarif_report", lambda _f: "SARIF")

    assert main(["contract-scan", "--path", "a.sol", "--format", "text"]) == 0
    assert capsys.readouterr().out.strip() == "TEXT"

    assert main(["contract-scan", "--path", "a.sol", "--format", "json"]) == 0
    assert capsys.readouterr().out.strip() == '{"ok":true}'

    assert main(["contract-scan", "--path", "a.sol", "--format", "sarif"]) == 0
    assert capsys.readouterr().out.strip() == "SARIF"

    with pytest.raises(SystemExit):
        main(["contract-scan", "--path", "a.sol", "--format", "xml"])
    err = capsys.readouterr().err
    assert "Invalid --format value" in err

import json

from cryptologik_cli.main import main


def test_contract_scan_input_list_ingests_multiple_paths_and_shapes_output(tmp_path, capsys, monkeypatch):
    input_file = tmp_path / "contracts.txt"
    input_file.write_text(
        "\n# list of contracts\ncontracts/A.sol\n\ncontracts/B.sol\ncontracts/missing.sol\n",
        encoding="utf-8",
    )

    def fake_scan(path: str):
        if path.endswith("missing.sol"):
            raise FileNotFoundError("not found")
        return {"findings": [{"rule_id": "X", "severity": "low", "path": path}]}

    monkeypatch.setattr("cryptologik_cli.main.scan_contract", fake_scan)

    rc = main(["contract-scan", "--input", str(input_file)])
    assert rc == 0

    out = capsys.readouterr().out
    payload = json.loads(out)

    assert payload["mode"] == "multi-path"
    assert payload["input"] == str(input_file)
    assert payload["paths"] == ["contracts/A.sol", "contracts/B.sol", "contracts/missing.sol"]
    assert isinstance(payload["findings"], list)
    assert len(payload["findings"]) == 3
    assert any(f.get("path") == "contracts/A.sol" for f in payload["findings"])
    assert any(f.get("path") == "contracts/B.sol" for f in payload["findings"])
    assert any(f.get("rule_id") == "CONTRACT_SCAN_PATH_ERROR" and f.get("path") == "contracts/missing.sol" for f in payload["findings"])

import io

from cryptologik_cli.main import main


def test_contract_scan_stdin_success(monkeypatch, capsys):
    solidity = """
pragma solidity ^0.8.0;
contract A { function f() public {} }
"""

    def fake_scan_contract(path, output_format):
        assert path.endswith(".sol")
        assert output_format == "json"
        return {"findings": []}

    monkeypatch.setattr("cryptologik_cli.main.scan_contract", fake_scan_contract)
    monkeypatch.setattr("sys.stdin", io.StringIO(solidity))

    rc = main(["contract-scan", "--stdin", "--format", "json"])
    out = capsys.readouterr().out

    assert rc == 0
    assert '"findings": []' in out

import io

import pytest

from cryptologik_cli.main import build_parser, main


def test_contract_scan_stdin_language_valid_and_invalid(monkeypatch, capsys):
    # valid language for stdin mode
    monkeypatch.setattr("sys.stdin", io.StringIO("contract C {}"))
    with pytest.raises(SystemExit) as no_exit:
        # ensure main does not raise SystemExit unexpectedly
        raise SystemExit(main(["contract-scan", "--stdin", "--language", "solidity"]))
    assert no_exit.value.code == 0

    # invalid language should fail during argument parsing (early validation)
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["contract-scan", "--stdin", "--language", "vyper"])
    assert exc.value.code == 2

    err = capsys.readouterr().err
    assert "invalid choice" in err

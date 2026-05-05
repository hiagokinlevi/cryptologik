import io

import pytest

from cryptologik_cli.main import main


def test_tls_check_reads_valid_yaml_from_stdin(monkeypatch, capsys):
    yaml_in = """
protocols:
  - TLS1.2
cipher_suites:
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
"""
    monkeypatch.setattr("sys.stdin", io.StringIO(yaml_in))

    code = main(["tls-check", "--input", "-", "--format", "json"])

    assert code == 0
    out = capsys.readouterr().out
    assert out.strip().startswith("{")


def test_tls_check_stdin_empty_or_invalid_returns_error(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("   \n"))
    code = main(["tls-check", "--input", "-"])
    assert code == 2
    err = capsys.readouterr().err
    assert "STDIN" in err or "Error:" in err

    monkeypatch.setattr("sys.stdin", io.StringIO(":::not yaml:::\n"))
    code = main(["tls-check", "--input", "-"])
    assert code == 2
    err = capsys.readouterr().err
    assert "Invalid YAML" in err or "Error:" in err

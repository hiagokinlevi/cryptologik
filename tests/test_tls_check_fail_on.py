from cryptologik_cli.main import main


def test_tls_check_fail_on_threshold_triggers_exit_non_zero(monkeypatch):
    def _fake_run_tls_check(input_path, config_path=None):
        return {
            "findings": [
                {"id": "TLS-001", "severity": "medium", "message": "weak protocol"},
                {"id": "TLS-002", "severity": "high", "message": "weak cipher"},
            ]
        }

    monkeypatch.setattr("cryptologik_cli.main.run_tls_check", _fake_run_tls_check)

    rc = main(["tls-check", "--input", "examples/tls/server.yaml", "--fail-on", "high"])
    assert rc == 1


def test_tls_check_fail_on_threshold_not_met_returns_zero(monkeypatch):
    def _fake_run_tls_check(input_path, config_path=None):
        return {
            "findings": [
                {"id": "TLS-001", "severity": "low", "message": "minor issue"},
            ]
        }

    monkeypatch.setattr("cryptologik_cli.main.run_tls_check", _fake_run_tls_check)

    rc = main(["tls-check", "--input", "examples/tls/server.yaml", "--fail-on", "medium"])
    assert rc == 0

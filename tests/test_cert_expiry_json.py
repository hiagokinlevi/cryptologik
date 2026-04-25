import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

from cryptologik_cli.main import cli


def test_cert_expiry_json_output_and_exit_code_compat(monkeypatch, tmp_path):
    cert_file = tmp_path / "cert.pem"
    cert_file.write_text("dummy")

    fake_not_before = datetime.now(timezone.utc) - timedelta(days=10)
    fake_not_after = datetime.now(timezone.utc) + timedelta(days=3)

    def fake_analyze_certificate_expiry(path, warn_days=30, critical_days=7):
        return {
            "subject": "CN=example.test",
            "issuer": "CN=Example CA",
            "not_before": fake_not_before,
            "not_after": fake_not_after,
            "days_remaining": 3,
            "severity": "critical",
            "status": "critical",
        }

    monkeypatch.setattr("cryptologik_cli.main.analyze_certificate_expiry", fake_analyze_certificate_expiry)

    runner = CliRunner()
    result = runner.invoke(cli, ["cert-expiry", "--cert", str(cert_file), "--json"])

    assert result.exit_code == 2
    payload = json.loads(result.output)

    assert payload["cert_path"] == str(cert_file)
    assert payload["subject"] == "CN=example.test"
    assert payload["issuer"] == "CN=Example CA"
    assert payload["not_before"] == fake_not_before.isoformat()
    assert payload["not_after"] == fake_not_after.isoformat()
    assert payload["days_remaining"] == 3
    assert payload["severity"] == "critical"
    assert payload["status"] == "critical"

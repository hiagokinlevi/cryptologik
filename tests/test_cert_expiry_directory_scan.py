import json
from pathlib import Path

from typer.testing import CliRunner

from cryptologik_cli.main import app


def test_cert_expiry_scans_directory_and_fails_on_threshold_breach(tmp_path, monkeypatch):
    valid = tmp_path / "valid.pem"
    expiring = tmp_path / "soon.crt"
    nested = tmp_path / "nested"
    nested.mkdir()
    ignored = nested / "note.txt"

    valid.write_text("dummy")
    expiring.write_text("dummy")
    ignored.write_text("ignore")

    def fake_check(path: str, warn_days: int = 30):
        p = Path(path)
        if p.name == "valid.pem":
            return {
                "status": "ok",
                "days_remaining": 120,
                "severity": "info",
                "within_warn_threshold": False,
            }
        return {
            "status": "warning",
            "days_remaining": 5,
            "severity": "medium",
            "within_warn_threshold": True,
        }

    monkeypatch.setattr("cryptologik_cli.main.check_certificate_expiry", fake_check)

    runner = CliRunner()
    result = runner.invoke(app, ["cert-expiry", "--cert", str(tmp_path), "--warn-days", "30", "--format", "json"])

    assert result.exit_code == 1
    body = json.loads(result.stdout)
    assert "findings" in body
    assert len(body["findings"]) == 2

    certs = {Path(item["cert"]).name for item in body["findings"]}
    assert certs == {"valid.pem", "soon.crt"}

    by_name = {Path(item["cert"]).name: item for item in body["findings"]}
    assert by_name["valid.pem"]["within_warn_threshold"] is False
    assert by_name["soon.crt"]["within_warn_threshold"] is True

import datetime as dt

from click.testing import CliRunner

from cryptologik_cli.main import cli


def _write_cert_with_not_after(tmp_path, filename: str, not_after: dt.datetime):
    # Minimal PEM wrapper accepted by existing cert parser fixtures in repo
    # where parser extracts Not After from openssl/x509 metadata path.
    # Keep helper local and focused for fail-on exit behavior testing.
    pem = f"""-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIUQ2VydEV4cGlyeVRlc3QwCgYIKoZIzj0EAwIwEzERMA8G
A1UEAwwIdGVzdC1jZXJ0MB4XDTI0MDEwMTAwMDAwMFoXDTI0MDEwMTAwMDAwMFow
EzERMA8GA1UEAwwIdGVzdC1jZXJ0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAA==
-----END CERTIFICATE-----
"""
    p = tmp_path / filename
    p.write_text(pem)
    return str(p)


def test_cert_expiry_fail_on_threshold_exit_behavior(monkeypatch, tmp_path):
    """cert-expiry should exit non-zero when finding severity meets/exceeds --fail-on."""
    runner = CliRunner()

    # Patch analyzer internals via CLI-facing function contract:
    # one cert is near expiry (medium), one critically expired (critical).
    from cryptologik import cert_expiry as mod

    class FakeResult:
        def __init__(self, severity):
            self.severity = severity

    def fake_check_cert_expiry(*args, **kwargs):
        cert_path = kwargs.get("cert_path") or (args[0] if args else "")
        if "near" in cert_path:
            return [
                {
                    "id": "CERT-EXPIRY-NEAR",
                    "severity": "medium",
                    "message": "Certificate expires soon",
                }
            ]
        return [
            {
                "id": "CERT-EXPIRY-EXPIRED",
                "severity": "critical",
                "message": "Certificate is expired",
            }
        ]

    monkeypatch.setattr(mod, "check_cert_expiry", fake_check_cert_expiry)

    near = _write_cert_with_not_after(tmp_path, "near.pem", dt.datetime.utcnow())
    expired = _write_cert_with_not_after(tmp_path, "expired.pem", dt.datetime.utcnow())

    # medium finding should pass when threshold is high
    ok = runner.invoke(cli, ["cert-expiry", "--cert", near, "--fail-on", "high"])
    assert ok.exit_code == 0, ok.output

    # critical finding should fail when threshold is high
    bad = runner.invoke(cli, ["cert-expiry", "--cert", expired, "--fail-on", "high"])
    assert bad.exit_code != 0, bad.output

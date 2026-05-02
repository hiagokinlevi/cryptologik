from __future__ import annotations

from argparse import Namespace

from cryptologik_cli.commands import cert_expiry


def test_cert_expiry_input_file_mixed_paths_and_comments(tmp_path, monkeypatch):
    cert_a = tmp_path / "a.pem"
    cert_a.write_text("dummy", encoding="utf-8")

    input_file = tmp_path / "certs.txt"
    input_file.write_text(
        "\n# comment line\n"
        f"{cert_a}\n"
        "\n"
        f"{tmp_path / 'missing.pem'}\n"
        "   # indented comment\n",
        encoding="utf-8",
    )

    calls = []

    def fake_analyze(path, warn_days):
        calls.append((path, warn_days))
        if path.endswith("missing.pem"):
            return [{"path": path, "status": "error"}]
        return [{"path": path, "status": "ok"}]

    monkeypatch.setattr(cert_expiry, "analyze_certificate_expiry", fake_analyze)

    args = Namespace(cert=[], input=str(input_file), warn_days=30, fail_on=None)
    findings = cert_expiry.run(args)

    assert [c[0] for c in calls] == [str(cert_a), str(tmp_path / "missing.pem")]
    assert findings == [
        {"path": str(cert_a), "status": "ok"},
        {"path": str(tmp_path / "missing.pem"), "status": "error"},
    ]

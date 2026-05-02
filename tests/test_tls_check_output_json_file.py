import json

from cryptologik_cli.main import main


def test_tls_check_json_output_file(tmp_path, monkeypatch):
    in_file = tmp_path / "tls.yaml"
    in_file.write_text("host: example.com\n", encoding="utf-8")

    out_file = tmp_path / "findings.json"

    def _fake_analyze(_path):
        return {
            "target": "example.com",
            "findings": [{"id": "TLS001", "severity": "low"}],
        }

    monkeypatch.setattr("cryptologik_cli.main.analyze_tls_config", _fake_analyze)

    rc = main([
        "tls-check",
        "--input",
        str(in_file),
        "--json",
        "--output",
        str(out_file),
    ])

    assert rc == 0
    assert out_file.exists()

    parsed = json.loads(out_file.read_text(encoding="utf-8"))
    assert parsed["target"] == "example.com"
    assert parsed["findings"][0]["id"] == "TLS001"

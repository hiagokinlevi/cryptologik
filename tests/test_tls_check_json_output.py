import json

from cryptologik_cli.main import main


def test_tls_check_json_output_shape_and_nonzero_findings(monkeypatch, capsys):
    def fake_scan_tls_config(_path):
        return {
            "findings": [
                {
                    "rule_id": "TLS001",
                    "title": "TLS 1.0 enabled",
                    "severity": "high",
                    "evidence": "supported_protocols includes TLS1.0",
                }
            ]
        }

    monkeypatch.setattr("cryptologik_cli.main.scan_tls_config", fake_scan_tls_config)

    code = main(["tls-check", "--input", "examples/tls/server.yaml", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert code == 1
    assert "summary" in payload
    assert "findings" in payload
    assert payload["summary"]["total_findings"] == 1
    assert isinstance(payload["findings"], list)

    finding = payload["findings"][0]
    assert set(["rule_id", "title", "severity", "target", "evidence"]).issubset(finding.keys())
    assert finding["rule_id"] == "TLS001"
    assert finding["severity"] == "high"
    assert finding["target"] == "examples/tls/server.yaml"

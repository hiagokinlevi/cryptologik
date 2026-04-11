import json

from click.testing import CliRunner

from cryptologik_cli.main import cli


def test_generate_report_writes_sarif_output(tmp_path):
    findings_path = tmp_path / "findings.json"
    output_path = tmp_path / "findings.sarif"
    findings_path.write_text(
        json.dumps(
            [
                {
                    "check_name": "go_tls_legacy_min_version",
                    "risk_level": "high",
                    "file_path": "src/server.go",
                    "line_number": 19,
                    "description": "TLS 1.0 remains enabled for a listener.",
                    "recommendation": "Raise the minimum TLS version to 1.2 or newer.",
                }
            ]
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        [
            "generate-report",
            "--findings-json",
            str(findings_path),
            "--format",
            "sarif",
            "--output",
            str(output_path),
            "--target",
            "server-go",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    run = payload["runs"][0]
    assert run["automationDetails"]["id"].startswith("ASSESS-")
    assert run["results"][0]["ruleId"] == "go_tls_legacy_min_version"
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "src/server.go"
    )

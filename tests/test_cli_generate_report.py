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


def test_generate_report_rejects_non_list_payload(tmp_path):
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        json.dumps({"check_name": "not-a-list"}),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        [
            "generate-report",
            "--findings-json",
            str(findings_path),
        ],
    )

    assert result.exit_code != 0
    assert "top-level list of finding objects" in result.output


def test_generate_report_rejects_non_object_entry(tmp_path):
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        json.dumps(["not-an-object"]),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        [
            "generate-report",
            "--findings-json",
            str(findings_path),
        ],
    )

    assert result.exit_code != 0
    assert "Finding entry #1 must be a JSON object." in result.output


def test_generate_report_rejects_invalid_entry_values(tmp_path):
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        json.dumps(
            [
                {
                    "check_name": "go_tls_legacy_min_version",
                    "risk_level": "severe",
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
        ],
    )

    assert result.exit_code != 0
    assert "Finding entry #1 is invalid" in result.output
    assert "severe" in result.output

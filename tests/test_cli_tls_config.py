import json

from click.testing import CliRunner

from cryptologik_cli.main import cli


def test_review_tls_config_writes_json_results(tmp_path):
    config_path = tmp_path / "tls-config.json"
    output_path = tmp_path / "tls-results.json"
    config_path.write_text(
        json.dumps(
            {
                "config_id": "legacy-listener",
                "cipher_suites": ["TLS_RSA_WITH_RC4_128_SHA"],
                "tls_versions": ["TLSv1.0", "TLSv1.2"],
                "description": "legacy ingress listener",
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        [
            "review-tls-config",
            "--config",
            str(config_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload[0]["config_id"] == "legacy-listener"
    finding_ids = {finding["check_id"] for finding in payload[0]["findings"]}
    assert {"CS-002", "CS-006"}.issubset(finding_ids)


def test_review_tls_config_fail_on_high_returns_nonzero(tmp_path):
    config_path = tmp_path / "tls-config.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "config_id": "modern",
                    "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
                    "tls_versions": ["TLSv1.3"],
                    "description": "modern listener",
                },
                {
                    "config_id": "legacy",
                    "cipher_suites": ["TLS_RSA_WITH_AES_128_CBC_SHA"],
                    "tls_versions": ["TLSv1.0"],
                    "description": "legacy listener",
                },
            ]
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["review-tls-config", "--config", str(config_path), "--fail-on", "high"],
    )

    assert result.exit_code != 0
    assert "fail-on=high" in result.output


def test_review_tls_config_rejects_non_object_entries(tmp_path):
    config_path = tmp_path / "tls-config.json"
    config_path.write_text(json.dumps(["legacy"]), encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["review-tls-config", "--config", str(config_path)],
    )

    assert result.exit_code != 0
    assert "TLS config entry #1 must be a JSON object." in result.output


def test_review_tls_config_rejects_string_cipher_suite_field(tmp_path):
    config_path = tmp_path / "tls-config.json"
    config_path.write_text(
        json.dumps(
            {
                "config_id": "bad",
                "cipher_suites": "TLS_AES_256_GCM_SHA384",
                "tls_versions": ["TLSv1.3"],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["review-tls-config", "--config", str(config_path)],
    )

    assert result.exit_code != 0
    assert "field 'cipher_suites' must be a JSON array of strings." in result.output


def test_review_tls_config_rejects_non_string_tls_version_items(tmp_path):
    config_path = tmp_path / "tls-config.json"
    config_path.write_text(
        json.dumps(
            {
                "config_id": "bad",
                "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
                "tls_versions": ["TLSv1.3", 1.2],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["review-tls-config", "--config", str(config_path)],
    )

    assert result.exit_code != 0
    assert "field 'tls_versions' item #2 must be a string." in result.output

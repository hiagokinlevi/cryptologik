import os

import yaml

from click.testing import CliRunner

from cryptologik_cli.main import cli


def test_review_key_posture_reports_findings_for_valid_config(tmp_path):
    config_path = tmp_path / "keys.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "keys": {
                    "payments-api": {
                        "type": "api_key",
                        "storage": {"location": "environment_variable"},
                        "access_control": {"allowed_principals": ["payments-service"]},
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["review-key-posture", "--config", str(config_path)],
    )

    assert result.exit_code == 0
    assert "No key rotation policy defined" in result.output


def test_review_key_posture_rejects_malformed_yaml(tmp_path):
    config_path = tmp_path / "bad-keys.yaml"
    config_path.write_text("keys:\n  payments-api:\n    storage:\n      location: hsm\n    :", encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["review-key-posture", "--config", str(config_path)],
    )

    assert result.exit_code != 0
    assert "Could not parse key management YAML" in result.output


def test_review_key_posture_rejects_missing_keys_mapping(tmp_path):
    config_path = tmp_path / "bad-keys.yaml"
    config_path.write_text(
        yaml.safe_dump({"services": {"payments-api": {}}}, sort_keys=False),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["review-key-posture", "--config", str(config_path)],
    )

    assert result.exit_code != 0
    assert "non-empty top-level 'keys' mapping" in result.output


def test_review_key_posture_rejects_non_mapping_key_entry(tmp_path):
    config_path = tmp_path / "bad-keys.yaml"
    config_path.write_text(
        yaml.safe_dump({"keys": {"payments-api": "use vault"}}, sort_keys=False),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["review-key-posture", "--config", str(config_path)],
    )

    assert result.exit_code != 0
    assert "payments-api" in result.output


def test_review_key_posture_rejects_symlinked_config(tmp_path):
    target_path = tmp_path / "keys.yaml"
    target_path.write_text(
        yaml.safe_dump(
            {"keys": {"payments-api": {"storage": {"location": "hsm"}}}},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    link_path = tmp_path / "linked-keys.yaml"
    link_path.symlink_to(target_path)

    result = CliRunner().invoke(
        cli,
        ["review-key-posture", "--config", str(link_path)],
    )

    assert result.exit_code != 0
    assert "not a regular file" in result.output


def test_review_key_posture_rejects_fifo_config(tmp_path):
    if not hasattr(os, "mkfifo"):
        return

    fifo_path = tmp_path / "keys.yaml"
    os.mkfifo(fifo_path)

    result = CliRunner().invoke(
        cli,
        ["review-key-posture", "--config", str(fifo_path)],
    )

    assert result.exit_code != 0
    assert "not a regular file" in result.output

import json

import yaml
from click.testing import CliRunner

from cryptologik_cli.main import cli


def _write_program(path):
    payload = {
        "program_name": "advanced-demo",
        "assets": [
            {
                "asset_id": "archive",
                "asset_name": "archive",
                "asset_type": "archive",
                "business_criticality": "high",
                "algorithm_abstraction": True,
                "versioned_policies": True,
                "dual_stack_support": False,
                "hybrid_ready": False,
                "pq_inventory_complete": False,
                "migration_runbook": False,
                "key_lifecycle_automation": False,
                "classical_public_key_dependency": True,
                "long_term_confidentiality": True,
                "data_retention_years": 12,
                "third_party_dependencies": ["backup-provider"],
                "migration_blockers": ["interop"],
            },
            {
                "asset_id": "signing-stage",
                "asset_name": "signing-stage",
                "asset_type": "service",
                "business_criticality": "medium",
                "algorithm_abstraction": True,
                "versioned_policies": True,
                "dual_stack_support": True,
                "hybrid_ready": True,
                "pq_inventory_complete": True,
                "migration_runbook": True,
                "key_lifecycle_automation": True,
                "classical_public_key_dependency": True,
                "long_term_confidentiality": False,
                "data_retention_years": 2,
            },
        ],
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def test_assess_crypto_agility_cli_writes_json(tmp_path):
    config = tmp_path / "program.yaml"
    output = tmp_path / "agility.json"
    _write_program(config)

    result = CliRunner().invoke(
        cli,
        ["assess-crypto-agility", "--config", str(config), "--output", str(output)],
    )

    assert result.exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["target_name"] == "advanced-demo"
    assert "crypto_agility_score" in payload


def test_assess_pqc_readiness_cli_writes_json(tmp_path):
    config = tmp_path / "program.yaml"
    output = tmp_path / "pqc.json"
    _write_program(config)

    result = CliRunner().invoke(
        cli,
        ["assess-pqc-readiness", "--config", str(config), "--output", str(output)],
    )

    assert result.exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["target_name"] == "advanced-demo"
    assert payload["migration_wave"] == 1


def test_generate_migration_plan_cli_writes_sorted_plan(tmp_path):
    config = tmp_path / "program.yaml"
    output = tmp_path / "plan.json"
    _write_program(config)

    result = CliRunner().invoke(
        cli,
        ["generate-migration-plan", "--config", str(config), "--output", str(output)],
    )

    assert result.exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload[0]["asset_id"] == "archive"
    assert payload[0]["migration_wave"] == 1


def test_assess_crypto_agility_cli_rejects_non_mapping_assets(tmp_path):
    config = tmp_path / "bad-program.yaml"
    config.write_text(
        yaml.safe_dump({"program_name": "bad-demo", "assets": ["oops"]}, sort_keys=False),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["assess-crypto-agility", "--config", str(config)],
    )

    assert result.exit_code == 1
    assert "Asset entry #1 must be an object" in result.output

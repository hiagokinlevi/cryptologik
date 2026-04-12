from click.testing import CliRunner

from cryptologik_cli.main import cli


def test_review_contract_checklist_rejects_invalid_utf8(tmp_path):
    contract_path = tmp_path / "bad.sol"
    contract_path.write_bytes(b"\xff\xfepragma solidity ^0.8.0;")

    result = CliRunner().invoke(
        cli,
        ["review-contract-checklist", "--contract", str(contract_path)],
    )

    assert result.exit_code != 0
    assert "Contract source is not valid UTF-8" in result.output


def test_review_contract_checklist_rejects_directory_path(tmp_path):
    result = CliRunner().invoke(
        cli,
        ["review-contract-checklist", "--contract", str(tmp_path)],
    )

    assert result.exit_code != 0
    assert "Contract path is not a regular file" in result.output

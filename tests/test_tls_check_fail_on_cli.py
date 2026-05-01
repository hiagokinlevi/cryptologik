from __future__ import annotations

import json

from click.testing import CliRunner

from cryptologik_cli.main import cli


def test_tls_check_fail_on_threshold_pass_and_fail(tmp_path):
    runner = CliRunner()

    tls_doc = {
        "host": "example.com",
        "port": 443,
        "protocols": ["TLSv1.2"],
        "ciphers": ["TLS_RSA_WITH_AES_128_CBC_SHA"],
    }
    input_file = tmp_path / "tls.json"
    input_file.write_text(json.dumps(tls_doc), encoding="utf-8")

    pass_result = runner.invoke(
        cli,
        ["tls-check", "--input", str(input_file), "--fail-on", "critical", "--format", "json"],
    )
    assert pass_result.exit_code == 0, pass_result.output

    fail_result = runner.invoke(
        cli,
        ["tls-check", "--input", str(input_file), "--fail-on", "low", "--format", "json"],
    )
    assert fail_result.exit_code != 0, fail_result.output

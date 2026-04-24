import json

from cryptologik_cli.main import main


def test_fail_on_threshold_triggers_nonzero_exit(tmp_path):
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(
        json.dumps(
            {
                "findings": [
                    {"id": "f-1", "severity": "low"},
                    {"id": "f-2", "severity": "high"},
                ]
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(["--input", str(findings_file), "--fail-on", "medium"])

    assert exit_code == 1

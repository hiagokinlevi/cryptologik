import json

from cryptologik_cli.main import main


def test_top_level_summary_json_shape(capsys):
    rc = main(["--json"])
    assert rc == 0

    out = capsys.readouterr().out.strip()
    data = json.loads(out)

    assert isinstance(data, dict)
    assert set(data.keys()) == {
        "tool_version",
        "timestamp",
        "executed_checks",
        "finding_counts",
        "overall_status",
    }

    assert isinstance(data["tool_version"], str)
    assert isinstance(data["timestamp"], str)
    assert isinstance(data["executed_checks"], list)

    fc = data["finding_counts"]
    assert set(fc.keys()) == {"by_severity", "total"}
    assert isinstance(fc["total"], int)

    bs = fc["by_severity"]
    assert set(bs.keys()) == {"critical", "high", "medium", "low", "info", "unknown"}
    assert all(isinstance(v, int) for v in bs.values())

    assert data["overall_status"] in {"pass", "warn", "fail"}

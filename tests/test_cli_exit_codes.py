from cryptologik_cli import _exit_code_for_result


def test_exit_code_clean_results_zero():
    result = {"findings": []}
    assert _exit_code_for_result(result) == 0


def test_exit_code_medium_only_zero():
    result = {
        "findings": [
            {"id": "X1", "severity": "medium"},
            {"id": "X2", "severity": "low"},
        ]
    }
    assert _exit_code_for_result(result) == 0


def test_exit_code_high_nonzero():
    result = {
        "findings": [
            {"id": "H1", "severity": "high"},
            {"id": "M1", "severity": "medium"},
        ]
    }
    assert _exit_code_for_result(result) != 0


def test_exit_code_override_informational_zero():
    result = {"findings": [{"id": "C1", "severity": "critical"}]}
    assert _exit_code_for_result(result, informational=True) == 0

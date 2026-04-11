import json

from reports.report_generator import generate_markdown_report, generate_sarif_report
from schemas.crypto_finding import (
    AssessmentSummary,
    CryptoConfigFinding,
    KeyManagementFinding,
    RiskLevel,
    SmartContractFinding,
)


def _sample_summary() -> AssessmentSummary:
    findings = [
        CryptoConfigFinding(
            check_name="java_jca_md5",
            risk_level=RiskLevel.HIGH,
            file_path="src/Example.java",
            line_number=7,
            title="MD5 used for cryptographic digest",
            description="MD5 appears in a security-sensitive digest path.",
            recommendation="Replace MD5 with SHA-256 or stronger.",
            evidence='MessageDigest.getInstance("MD5")',
            tags=["java", "hashing"],
        ),
        SmartContractFinding(
            swc_id="SWC-107",
            swc_title="Reentrancy",
            risk_level=RiskLevel.CRITICAL,
            contract_path="contracts/Vault.sol",
            line_number=42,
            title="External call before state update",
            description="The contract performs an external call before state is updated.",
            recommendation="Apply checks-effects-interactions and/or a reentrancy guard.",
            evidence='msg.sender.call{value: amount}("")',
            tags=["solidity"],
        ),
        KeyManagementFinding(
            check_id="KM-001",
            key_name="payments-master-key",
            risk_level=RiskLevel.MEDIUM,
            title="Rotation policy missing",
            description="The key does not define a formal rotation cadence.",
            recommendation="Define a rotation schedule and enforce it operationally.",
            tags=["kms"],
        ),
    ]
    return AssessmentSummary.from_findings(findings, target_description="sample-target")


def test_generate_markdown_report_includes_sorted_findings():
    report = generate_markdown_report(_sample_summary(), verbosity="standard")

    assert "Cryptographic Security Assessment Report" in report
    assert report.index("External call before state update") < report.index(
        "MD5 used for cryptographic digest"
    )


def test_generate_sarif_report_emits_rules_results_and_locations():
    payload = json.loads(generate_sarif_report(_sample_summary()))

    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "cryptologik"

    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert {"SWC-107", "java_jca_md5", "KM-001"} == set(rules)

    results = {result["ruleId"]: result for result in run["results"]}
    assert results["SWC-107"]["level"] == "error"
    assert (
        results["java_jca_md5"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "src/Example.java"
    )
    assert (
        results["java_jca_md5"]["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    )
    assert "locations" not in results["KM-001"]
    assert "Recommendation:" in results["KM-001"]["help"]["markdown"]

"""
Tests for blockchain/smart_contracts/swc_extended.py

Validates:
  - Each new SWC (103, 106, 111, 113, 128) fires on matching Solidity source
  - Extended checklist contains all 10 expected SWC IDs
  - ExtendedSmartContractRunner.review() works end-to-end
  - ExtendedSmartContractRunner.review_with_summary() returns correct dict shape
  - Clean contracts produce no CRITICAL/HIGH findings from extended checks
  - requires_manual_review constraint (SWC-111 is the only non-manual item)
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from blockchain.smart_contracts.swc_extended import (
    EXTENDED_CHECKLIST,
    EXTENDED_CHECKS,
    ExtendedSmartContractRunner,
)
from blockchain.smart_contracts.review_checklist import (
    ContractFindingRisk,
    SMART_CONTRACT_CHECKLIST,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_sol(source: str) -> Path:
    """Write Solidity source to a temp .sol file and return its path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".sol", delete=False, encoding="utf-8"
    ) as f:
        f.write(source)
        return Path(f.name)


# ---------------------------------------------------------------------------
# Checklist completeness
# ---------------------------------------------------------------------------

class TestExtendedChecklistCompleteness:

    def test_extended_checklist_has_ten_items(self):
        """Base (6) + extended (5) = 11 items total (SWC-100 is part of base)."""
        # Base has 6 items; extended adds 5 → 11 total
        assert len(EXTENDED_CHECKLIST) == len(SMART_CONTRACT_CHECKLIST) + len(EXTENDED_CHECKS)

    def test_extended_checklist_contains_all_base_swcs(self):
        """All base SWC IDs must still be present in the extended checklist."""
        base_ids = {item.swc_id for item in SMART_CONTRACT_CHECKLIST}
        extended_ids = {item.swc_id for item in EXTENDED_CHECKLIST}
        assert base_ids.issubset(extended_ids)

    def test_extended_checks_adds_five_new_swcs(self):
        """EXTENDED_CHECKS must add exactly SWC-103, 106, 111, 113, 128."""
        new_ids = {item.swc_id for item in EXTENDED_CHECKS}
        assert new_ids == {"SWC-103", "SWC-106", "SWC-111", "SWC-113", "SWC-128"}

    def test_all_extended_items_have_patterns(self):
        for item in EXTENDED_CHECKS:
            assert len(item.patterns) >= 1, f"{item.swc_id} has no patterns"

    def test_all_extended_items_have_recommendations(self):
        for item in EXTENDED_CHECKS:
            assert item.recommendation, f"{item.swc_id} has no recommendation"

    def test_swc111_does_not_require_manual_review(self):
        """SWC-111 (deprecated functions) is a direct fix — no manual review needed."""
        swc111 = next(i for i in EXTENDED_CHECKS if i.swc_id == "SWC-111")
        assert swc111.requires_manual_review is False

    def test_other_extended_checks_require_manual_review(self):
        """All extended checks except SWC-111 require manual review."""
        for item in EXTENDED_CHECKS:
            if item.swc_id != "SWC-111":
                assert item.requires_manual_review is True, (
                    f"{item.swc_id} should require manual review"
                )


# ---------------------------------------------------------------------------
# SWC-103 Floating Pragma
# ---------------------------------------------------------------------------

class TestSWC103FloatingPragma:

    def setup_method(self):
        self.runner = ExtendedSmartContractRunner()

    def test_detects_caret_pragma(self):
        """^0.8.0 should trigger SWC-103."""
        path = write_sol("pragma solidity ^0.8.0;\ncontract C {}")
        findings = self.runner.review(path)
        ids = [f.swc_id for f in findings]
        assert "SWC-103" in ids

    def test_detects_gte_pragma(self):
        """>=0.8.0 should trigger SWC-103."""
        path = write_sol("pragma solidity >=0.8.0;\ncontract C {}")
        findings = self.runner.review(path)
        ids = [f.swc_id for f in findings]
        assert "SWC-103" in ids

    def test_pinned_pragma_no_swc103(self):
        """Exact pinned pragma should NOT trigger SWC-103."""
        path = write_sol("pragma solidity 0.8.19;\ncontract C {}")
        findings = self.runner.review(path)
        swc103 = [f for f in findings if f.swc_id == "SWC-103"]
        assert len(swc103) == 0

    def test_swc103_is_medium_risk(self):
        path = write_sol("pragma solidity ^0.8.0;\ncontract C {}")
        findings = self.runner.review(path)
        swc103 = [f for f in findings if f.swc_id == "SWC-103"]
        assert all(f.risk_level == ContractFindingRisk.MEDIUM for f in swc103)


# ---------------------------------------------------------------------------
# SWC-106 Unprotected Self-Destruct
# ---------------------------------------------------------------------------

class TestSWC106SelfDestruct:

    def setup_method(self):
        self.runner = ExtendedSmartContractRunner()

    def test_detects_selfdestruct(self):
        """selfdestruct() call should trigger SWC-106."""
        path = write_sol(
            "pragma solidity 0.8.19;\n"
            "contract Bomb {\n"
            "    function kill() public { selfdestruct(payable(msg.sender)); }\n"
            "}"
        )
        findings = self.runner.review(path)
        ids = [f.swc_id for f in findings]
        assert "SWC-106" in ids

    def test_detects_legacy_suicide(self):
        """Legacy suicide() should trigger SWC-106."""
        path = write_sol(
            "pragma solidity 0.4.0;\n"
            "contract Legacy {\n"
            "    function kill() { suicide(msg.sender); }\n"
            "}"
        )
        findings = self.runner.review(path)
        ids = [f.swc_id for f in findings]
        assert "SWC-106" in ids

    def test_swc106_is_critical_risk(self):
        path = write_sol(
            "pragma solidity 0.8.19;\n"
            "contract C { function d() public { selfdestruct(payable(msg.sender)); } }"
        )
        findings = self.runner.review(path)
        swc106 = [f for f in findings if f.swc_id == "SWC-106"]
        assert all(f.risk_level == ContractFindingRisk.CRITICAL for f in swc106)

    def test_no_selfdestruct_no_swc106(self):
        path = write_sol(
            "pragma solidity 0.8.19;\n"
            "contract Safe { function go() public {} }"
        )
        findings = self.runner.review(path)
        swc106 = [f for f in findings if f.swc_id == "SWC-106"]
        assert len(swc106) == 0


# ---------------------------------------------------------------------------
# SWC-111 Deprecated Functions
# ---------------------------------------------------------------------------

class TestSWC111DeprecatedFunctions:

    def setup_method(self):
        self.runner = ExtendedSmartContractRunner()

    def test_detects_throw(self):
        """'throw' keyword should trigger SWC-111."""
        path = write_sol(
            "pragma solidity 0.4.0;\n"
            "contract Old {\n"
            "    function check(bool ok) { if (!ok) throw; }\n"
            "}"
        )
        findings = self.runner.review(path)
        ids = [f.swc_id for f in findings]
        assert "SWC-111" in ids

    def test_detects_sha3(self):
        """sha3() call should trigger SWC-111."""
        path = write_sol(
            "pragma solidity 0.4.0;\n"
            "contract Hashing {\n"
            "    function h(bytes memory data) public returns (bytes32) {\n"
            "        return sha3(data);\n"
            "    }\n"
            "}"
        )
        findings = self.runner.review(path)
        ids = [f.swc_id for f in findings]
        assert "SWC-111" in ids

    def test_detects_callcode(self):
        """callcode() should trigger SWC-111."""
        path = write_sol(
            "pragma solidity 0.4.0;\n"
            "contract Delegator {\n"
            "    function delegate(address target) public {\n"
            "        target.callcode(msg.data);\n"
            "    }\n"
            "}"
        )
        findings = self.runner.review(path)
        ids = [f.swc_id for f in findings]
        assert "SWC-111" in ids

    def test_swc111_is_medium_risk(self):
        path = write_sol(
            "pragma solidity 0.4.0;\n"
            "contract Old { function go() { throw; } }"
        )
        findings = self.runner.review(path)
        swc111 = [f for f in findings if f.swc_id == "SWC-111"]
        assert all(f.risk_level == ContractFindingRisk.MEDIUM for f in swc111)

    def test_modern_solidity_no_swc111(self):
        """Modern Solidity without deprecated constructs should not trigger SWC-111."""
        path = write_sol(
            "pragma solidity 0.8.19;\n"
            "contract Modern {\n"
            "    function check(bool ok) public pure {\n"
            "        require(ok, 'not ok');\n"
            "    }\n"
            "    function h(bytes memory data) public pure returns (bytes32) {\n"
            "        return keccak256(data);\n"
            "    }\n"
            "}"
        )
        findings = self.runner.review(path)
        swc111 = [f for f in findings if f.swc_id == "SWC-111"]
        assert len(swc111) == 0


# ---------------------------------------------------------------------------
# SWC-113 DoS with Failed Call
# ---------------------------------------------------------------------------

class TestSWC113DoSFailedCall:

    def setup_method(self):
        self.runner = ExtendedSmartContractRunner()

    def test_detects_transfer_in_loop(self):
        """transfer() call should trigger SWC-113 (heuristic fires on any .transfer)."""
        path = write_sol(
            "pragma solidity 0.8.19;\n"
            "contract Payout {\n"
            "    address[] public recipients;\n"
            "    function distribute() public {\n"
            "        for (uint i = 0; i < recipients.length; i++) {\n"
            "            payable(recipients[i]).transfer(1 ether);\n"
            "        }\n"
            "    }\n"
            "}"
        )
        findings = self.runner.review(path)
        ids = [f.swc_id for f in findings]
        assert "SWC-113" in ids

    def test_swc113_is_high_risk(self):
        path = write_sol(
            "pragma solidity 0.8.19;\n"
            "contract C { function pay(address payable a) public { a.transfer(1); } }"
        )
        findings = self.runner.review(path)
        swc113 = [f for f in findings if f.swc_id == "SWC-113"]
        assert all(f.risk_level == ContractFindingRisk.HIGH for f in swc113)


# ---------------------------------------------------------------------------
# SWC-128 DoS with Block Gas Limit
# ---------------------------------------------------------------------------

class TestSWC128GasLimit:

    def setup_method(self):
        self.runner = ExtendedSmartContractRunner()

    def test_detects_for_loop(self):
        """for loop should trigger SWC-128."""
        path = write_sol(
            "pragma solidity 0.8.19;\n"
            "contract C {\n"
            "    uint[] public data;\n"
            "    function process() public {\n"
            "        for (uint i = 0; i < data.length; i++) { data[i] += 1; }\n"
            "    }\n"
            "}"
        )
        findings = self.runner.review(path)
        ids = [f.swc_id for f in findings]
        assert "SWC-128" in ids

    def test_detects_while_loop(self):
        """while loop should trigger SWC-128."""
        path = write_sol(
            "pragma solidity 0.8.19;\n"
            "contract C {\n"
            "    function run(uint n) public {\n"
            "        uint i = 0;\n"
            "        while (i < n) { i++; }\n"
            "    }\n"
            "}"
        )
        findings = self.runner.review(path)
        ids = [f.swc_id for f in findings]
        assert "SWC-128" in ids

    def test_swc128_is_high_risk(self):
        path = write_sol(
            "pragma solidity 0.8.19;\n"
            "contract C { function f() public { for (uint i; i < 10; i++) {} } }"
        )
        findings = self.runner.review(path)
        swc128 = [f for f in findings if f.swc_id == "SWC-128"]
        assert all(f.risk_level == ContractFindingRisk.HIGH for f in swc128)


# ---------------------------------------------------------------------------
# ExtendedSmartContractRunner
# ---------------------------------------------------------------------------

class TestExtendedRunner:

    def setup_method(self):
        self.runner = ExtendedSmartContractRunner()

    def test_review_returns_findings_list(self):
        path = write_sol("pragma solidity ^0.8.0;\ncontract C {}")
        result = self.runner.review(path)
        assert isinstance(result, list)

    def test_review_with_summary_structure(self):
        path = write_sol(
            "pragma solidity ^0.7.0;\n"
            "contract V {\n"
            "    function kill() public { selfdestruct(payable(msg.sender)); }\n"
            "    function f() public { throw; }\n"
            "}"
        )
        summary = self.runner.review_with_summary(path)

        # Required top-level keys
        for key in ["contract_path", "total_findings", "by_risk_level",
                    "requires_immediate_attention", "findings"]:
            assert key in summary, f"Missing key: {key}"

    def test_review_with_summary_by_risk_level_keys(self):
        path = write_sol("pragma solidity ^0.8.0;\ncontract C {}")
        summary = self.runner.review_with_summary(path)
        # by_risk_level must have all ContractFindingRisk values
        for risk in ContractFindingRisk:
            assert risk.value in summary["by_risk_level"]

    def test_review_with_summary_requires_immediate_attention_true_on_critical(self):
        """CRITICAL finding (selfdestruct) should set requires_immediate_attention=True."""
        path = write_sol(
            "pragma solidity 0.8.19;\n"
            "contract Bomb { function kill() public { selfdestruct(payable(msg.sender)); } }"
        )
        summary = self.runner.review_with_summary(path)
        assert summary["requires_immediate_attention"] is True

    def test_review_with_summary_no_immediate_attention_on_medium_only(self):
        """Only MEDIUM findings should not set requires_immediate_attention."""
        path = write_sol(
            "pragma solidity ^0.8.0;\n"  # SWC-103 MEDIUM
            "contract C { function go() external {} }"
        )
        summary = self.runner.review_with_summary(path)
        # SWC-103 only → no CRITICAL
        assert summary["requires_immediate_attention"] is False

    def test_review_with_summary_total_findings_matches_findings_list(self):
        path = write_sol(
            "pragma solidity ^0.7.0;\n"
            "contract V {\n"
            "    function kill() public { selfdestruct(payable(msg.sender)); }\n"
            "}"
        )
        summary = self.runner.review_with_summary(path)
        assert summary["total_findings"] == len(summary["findings"])

    def test_per_finding_dict_has_required_fields(self):
        path = write_sol(
            "pragma solidity ^0.7.0;\n"
            "contract V { function kill() public { selfdestruct(payable(msg.sender)); } }"
        )
        summary = self.runner.review_with_summary(path)
        for f in summary["findings"]:
            for key in ["swc_id", "swc_title", "risk_level", "line_number",
                        "evidence", "recommendation", "requires_manual_review"]:
                assert key in f, f"Finding dict missing key: {key}"

    def test_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            self.runner.review(Path("/tmp/no_such_file_swc_ext.sol"))

    def test_empty_file_no_findings(self):
        path = write_sol("")
        findings = self.runner.review(path)
        assert findings == []


# ---------------------------------------------------------------------------
# Full vulnerability scenario
# ---------------------------------------------------------------------------

class TestFullVulnerableContract:

    def test_highly_vulnerable_contract_triggers_extended_checks(self):
        """A contract with multiple anti-patterns triggers multiple SWC IDs."""
        contract = """
pragma solidity ^0.7.0;
contract VulnerableAll {
    address[] public users;

    function kill() public {
        selfdestruct(payable(msg.sender));
    }

    function legacy(bytes memory data) public returns (bytes32) {
        return sha3(data);
    }

    function pay() public {
        for (uint i = 0; i < users.length; i++) {
            payable(users[i]).transfer(1 ether);
        }
    }
}
"""
        runner = ExtendedSmartContractRunner()
        path = write_sol(contract)
        findings = runner.review(path)
        swc_ids = {f.swc_id for f in findings}

        # Must fire at least: SWC-103 (^pragma), SWC-106 (selfdestruct),
        # SWC-111 (sha3), SWC-113 (transfer), SWC-128 (for loop)
        assert "SWC-103" in swc_ids
        assert "SWC-106" in swc_ids
        assert "SWC-111" in swc_ids
        assert "SWC-113" in swc_ids
        assert "SWC-128" in swc_ids

    def test_clean_modern_contract_no_critical_high_from_extended(self):
        """A clean, pinned-pragma contract should not trigger critical/high from extended checks."""
        contract = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract SafeVault {
    mapping(address => uint256) private balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "Transfer failed");
    }

    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}
"""
        runner = ExtendedSmartContractRunner()
        path = write_sol(contract)
        findings = runner.review(path)

        # Only extended high/critical checks: SWC-106, SWC-113, SWC-128
        # This contract has no selfdestruct, no .transfer(), and no for/while loops
        extended_critical_high = [
            f for f in findings
            if f.swc_id in ("SWC-106", "SWC-113", "SWC-128")
            and f.risk_level in (ContractFindingRisk.CRITICAL, ContractFindingRisk.HIGH)
        ]
        # SWC-113 pattern matches .transfer() — not present in this contract
        # SWC-128 pattern matches for/while — not present
        # SWC-106 pattern matches selfdestruct — not present
        assert len(extended_critical_high) == 0

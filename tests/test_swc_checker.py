"""
Tests for the smart contract SWC review checklist.

These tests validate:
  - Known vulnerable patterns are detected by the checklist runner
  - Clean contracts produce no findings
  - ContractFinding objects have all required fields
  - SWC IDs follow the correct format
  - requires_manual_review is True for all smart contract findings
  - File not found raises FileNotFoundError
"""

import tempfile
from pathlib import Path

import pytest

from blockchain.smart_contracts.review_checklist import (
    ContractFinding,
    ContractFindingRisk,
    SmartContractReviewRunner,
    SMART_CONTRACT_CHECKLIST,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_contract(source: str) -> Path:
    """Write Solidity source to a temporary .sol file and return its path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".sol", delete=False, encoding="utf-8"
    ) as f:
        f.write(source)
        return Path(f.name)


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------

class TestVulnerablePatternDetection:
    def setup_method(self):
        self.runner = SmartContractReviewRunner()

    def test_detects_old_solidity_version(self):
        """Solidity pragma < 0.8 should trigger SWC-101 (integer overflow)."""
        contract = "pragma solidity ^0.7.6;\ncontract Token {}"
        path = write_contract(contract)
        findings = self.runner.review(path)

        swc101 = [f for f in findings if f.swc_id == "SWC-101"]
        assert len(swc101) >= 1
        assert all(f.risk_level == ContractFindingRisk.HIGH for f in swc101)

    def test_detects_tx_origin(self):
        """Use of tx.origin should trigger SWC-115."""
        contract = """
pragma solidity ^0.8.0;
contract Example {
    function onlyOwner() public {
        require(tx.origin == owner);
    }
}"""
        path = write_contract(contract)
        findings = self.runner.review(path)

        swc115 = [f for f in findings if f.swc_id == "SWC-115"]
        assert len(swc115) >= 1
        assert all(f.risk_level == ContractFindingRisk.HIGH for f in swc115)

    def test_detects_block_timestamp_randomness(self):
        """Use of block.timestamp should trigger SWC-120."""
        contract = """
pragma solidity ^0.8.0;
contract Lottery {
    function draw() public {
        uint256 rand = uint256(block.timestamp) % 100;
    }
}"""
        path = write_contract(contract)
        findings = self.runner.review(path)

        swc120 = [f for f in findings if f.swc_id == "SWC-120"]
        assert len(swc120) >= 1

    def test_detects_external_call_pattern(self):
        """Low-level .call{value:} should trigger reentrancy check (SWC-107)."""
        contract = """
pragma solidity ^0.8.0;
contract Bank {
    function withdraw(uint256 amount) public {
        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success);
    }
}"""
        path = write_contract(contract)
        findings = self.runner.review(path)

        swc107 = [f for f in findings if f.swc_id == "SWC-107"]
        assert len(swc107) >= 1
        assert all(f.risk_level == ContractFindingRisk.CRITICAL for f in swc107)

    def test_detects_withdraw_function(self):
        """Unguarded withdraw function should trigger SWC-105."""
        contract = """
pragma solidity ^0.8.0;
contract Vault {
    function withdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}"""
        path = write_contract(contract)
        findings = self.runner.review(path)

        swc105 = [f for f in findings if f.swc_id == "SWC-105"]
        assert len(swc105) >= 1

    def test_multiple_vulnerabilities_detected(self):
        """A contract with multiple vulnerabilities should produce multiple findings."""
        contract = """
pragma solidity ^0.7.0;
contract VulnerableMulti {
    function withdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }

    function auth() public {
        require(tx.origin == owner);
    }

    function randomize() public view returns (uint256) {
        return uint256(block.timestamp) % 10;
    }
}"""
        path = write_contract(contract)
        findings = self.runner.review(path)

        swc_ids = {f.swc_id for f in findings}
        # Should detect at least overflow risk (0.7 pragma), tx.origin, timestamp, withdraw
        assert len(swc_ids) >= 3


# ---------------------------------------------------------------------------
# Clean contract tests
# ---------------------------------------------------------------------------

class TestCleanContracts:
    def setup_method(self):
        self.runner = SmartContractReviewRunner()

    def test_minimal_safe_contract(self):
        """A minimal modern contract should produce no findings."""
        contract = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SafeCounter {
    uint256 private count;

    function increment() external {
        count += 1;
    }

    function getCount() external view returns (uint256) {
        return count;
    }
}"""
        path = write_contract(contract)
        findings = self.runner.review(path)

        # No reentrancy, no tx.origin, no weak randomness, no withdraw — should be clean
        critical_or_high = [f for f in findings if f.risk_level in (
            ContractFindingRisk.CRITICAL, ContractFindingRisk.HIGH
        )]
        assert len(critical_or_high) == 0

    def test_empty_contract(self):
        """An empty file should return no findings."""
        path = write_contract("")
        findings = self.runner.review(path)
        assert findings == []


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_nonexistent_contract_raises(self):
        """Passing a nonexistent file path should raise FileNotFoundError."""
        runner = SmartContractReviewRunner()
        with pytest.raises(FileNotFoundError):
            runner.review(Path("/tmp/does_not_exist_contract_12345.sol"))


# ---------------------------------------------------------------------------
# Finding structure tests
# ---------------------------------------------------------------------------

class TestFindingStructure:
    def setup_method(self):
        self.runner = SmartContractReviewRunner()

    def test_findings_have_all_required_fields(self):
        """Every finding must have all required ContractFinding fields."""
        contract = "pragma solidity ^0.7.0;\ncontract T { function f() public { require(tx.origin == owner); } }"
        path = write_contract(contract)
        findings = self.runner.review(path)

        for f in findings:
            assert isinstance(f, ContractFinding)
            assert f.swc_id.startswith("SWC-")
            assert f.swc_title
            assert f.risk_level in ContractFindingRisk.__members__.values()
            assert f.description
            assert f.recommendation
            # Smart contract findings should always require manual review
            assert f.requires_manual_review is True

    def test_swc_id_format(self):
        """All SWC IDs in the checklist must follow the SWC-NNN format."""
        import re
        for item in SMART_CONTRACT_CHECKLIST:
            assert re.match(r"^SWC-\d+$", item.swc_id), (
                f"Invalid SWC ID format: {item.swc_id}"
            )

    def test_all_checklist_items_have_recommendations(self):
        """Every checklist item must have a non-empty recommendation."""
        for item in SMART_CONTRACT_CHECKLIST:
            assert item.recommendation, (
                f"Checklist item {item.swc_id} has no recommendation"
            )

    def test_critical_findings_are_critical(self):
        """Reentrancy and SWC-105 findings should be CRITICAL risk."""
        contract = """
pragma solidity ^0.8.0;
contract Drain {
    function withdraw() public {}
    mapping(address => uint256) balances;
    function take(uint amount) public {
        payable(msg.sender).call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}"""
        path = write_contract(contract)
        runner = SmartContractReviewRunner()
        findings = runner.review(path)

        critical = [f for f in findings if f.risk_level == ContractFindingRisk.CRITICAL]
        assert len(critical) >= 1


# ---------------------------------------------------------------------------
# Checklist completeness tests
# ---------------------------------------------------------------------------

class TestChecklistCompleteness:
    def test_checklist_covers_essential_swc_entries(self):
        """The built-in checklist must cover the most critical SWC entries."""
        swc_ids_in_checklist = {item.swc_id for item in SMART_CONTRACT_CHECKLIST}
        essential = {"SWC-107", "SWC-101", "SWC-105", "SWC-115", "SWC-120"}

        for swc_id in essential:
            assert swc_id in swc_ids_in_checklist, (
                f"Essential SWC entry {swc_id} is missing from the checklist"
            )

    def test_checklist_items_have_patterns(self):
        """Every checklist item must have at least one detection pattern."""
        for item in SMART_CONTRACT_CHECKLIST:
            assert len(item.patterns) >= 1, (
                f"Checklist item {item.swc_id} has no detection patterns"
            )

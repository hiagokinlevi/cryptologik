from pathlib import Path

from blockchain.smart_contracts.unsafe_patterns import scan_solidity_unsafe_patterns


def test_scan_solidity_unsafe_patterns_reports_file_and_line(tmp_path: Path) -> None:
    contract = tmp_path / "Unsafe.sol"
    contract.write_text(
        """
pragma solidity ^0.8.0;

contract Unsafe {
    function a() public view returns (address) {
        return tx.origin;
    }

    function b(address target, bytes memory data) public payable {
        target.call.value(msg.value)(data);
    }

    function c(address target, bytes memory data) public {
        target.delegatecall(data);
    }
}
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_solidity_unsafe_patterns([tmp_path])

    assert len(findings) == 3

    by_pattern = {f["pattern"]: f for f in findings}

    assert by_pattern["tx.origin"]["file"].endswith("Unsafe.sol")
    assert by_pattern["tx.origin"]["line"] == 5

    assert by_pattern["call.value"]["file"].endswith("Unsafe.sol")
    assert by_pattern["call.value"]["line"] == 9

    assert by_pattern["delegatecall"]["file"].endswith("Unsafe.sol")
    assert by_pattern["delegatecall"]["line"] == 13

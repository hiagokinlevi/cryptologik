"""
Extended Smart Contract SWC Checklist
========================================
Extends the base SMART_CONTRACT_CHECKLIST with 5 additional SWC entries
to provide Top-10 SWC coverage for common Solidity vulnerability patterns.

New checks added (SWC-103, SWC-106, SWC-111, SWC-113, SWC-128):
  - SWC-103 MEDIUM:  Floating Pragma — imprecise version lock risks
  - SWC-106 CRITICAL: Unprotected Self-Destruct — selfdestruct without access control
  - SWC-111 MEDIUM:  Use of Deprecated Functions (suicide, throw, sha3, callcode)
  - SWC-113 HIGH:    DoS via Unexpected Revert — unbounded loops or revert in sub-calls
  - SWC-128 HIGH:    DoS with Block Gas Limit — unbounded gas loops

Together with the base checklist (SWC-107, SWC-101, SWC-105, SWC-115, SWC-120,
SWC-100), this provides a 10-item SWC review covering the most impactful
and commonly exploited Solidity vulnerability classes.

Usage:
    from blockchain.smart_contracts.swc_extended import (
        EXTENDED_CHECKLIST,
        ExtendedSmartContractRunner,
    )
    from pathlib import Path

    runner = ExtendedSmartContractRunner()
    findings = runner.review(Path("MyToken.sol"))
    for f in findings:
        print(f"[{f.risk_level.value.upper()}] {f.swc_id}: {f.swc_title} (line {f.line_number})")
"""
from __future__ import annotations

from pathlib import Path

from blockchain.smart_contracts.review_checklist import (
    ChecklistItem,
    ContractFinding,
    ContractFindingRisk,
    SMART_CONTRACT_CHECKLIST,
    SmartContractReviewRunner,
)


# ---------------------------------------------------------------------------
# Extended checklist entries (SWC-103, SWC-106, SWC-111, SWC-113, SWC-128)
# ---------------------------------------------------------------------------

EXTENDED_CHECKS: list[ChecklistItem] = [
    ChecklistItem(
        swc_id="SWC-103",
        swc_title="Floating Pragma",
        risk_level=ContractFindingRisk.MEDIUM,
        patterns=[
            # Pragma with ^ (floating) or >= (range) — not pinned to exact version
            r"pragma solidity\s+[\^>]",
            r"pragma solidity\s+>=",
        ],
        description=(
            "Contract uses a floating pragma directive (e.g., ^0.8.0 or >=0.8.0). "
            "Floating pragmas allow the contract to be compiled with any compatible "
            "compiler version, including future versions that may introduce breaking changes "
            "or subtle behavioral differences. The version actually used in testing may differ "
            "from the version used in production deployment."
        ),
        recommendation=(
            "Pin the pragma to a specific, well-tested compiler version: "
            "'pragma solidity 0.8.19;' (without ^ or >=). "
            "Choose a version that has been in production for ≥3 months (lower unknown risk). "
            "Avoid the most recently released version for production contracts. "
            "Audit with the exact version you will deploy with."
        ),
        requires_manual_review=True,
        false_positive_note=(
            "Low false positive rate for the detection. Medium risk severity — floating pragma "
            "is bad practice but does not directly cause exploitable vulnerabilities."
        ),
    ),

    ChecklistItem(
        swc_id="SWC-106",
        swc_title="Unprotected Self-Destruct",
        risk_level=ContractFindingRisk.CRITICAL,
        patterns=[
            r"\bselfdestruct\s*\(",  # Modern Solidity
            r"\bsuicide\s*\(",       # Legacy Solidity (deprecated, but still detectable)
        ],
        description=(
            "selfdestruct() call detected. If this function can be reached without "
            "proper access control, any caller could permanently destroy the contract "
            "and send its Ether balance to an arbitrary address. "
            "This heuristic detects the presence of selfdestruct — not confirmed vulnerability. "
            "Manual review is required to verify that access controls are correctly enforced."
        ),
        recommendation=(
            "Restrict access to any function containing selfdestruct() with the strictest "
            "possible access control (e.g., onlyOwner with a multi-signature requirement, "
            "or a time-locked governance mechanism). "
            "Consider whether selfdestruct is necessary at all — most modern contract "
            "patterns use upgrade proxies instead. "
            "Note: EIP-6049 (EIP-4758) deprecated selfdestruct in Dencun upgrade."
        ),
        requires_manual_review=True,
        false_positive_note=(
            "Low false positive rate. selfdestruct is rare in well-designed contracts. "
            "If present, always verify it requires multi-sig or equivalent protection."
        ),
    ),

    ChecklistItem(
        swc_id="SWC-111",
        swc_title="Use of Deprecated Solidity Functions",
        risk_level=ContractFindingRisk.MEDIUM,
        patterns=[
            r"\bsuicide\s*\(",        # Deprecated: replaced by selfdestruct
            r"\bthrow\b",             # Deprecated: replaced by revert()/require()
            r"\bsha3\s*\(",           # Deprecated: replaced by keccak256()
            r"\.callcode\s*\(",       # Deprecated: replaced by delegatecall
        ],
        description=(
            "Use of deprecated Solidity language construct detected. "
            "Deprecated functions/keywords have been removed or renamed in recent "
            "compiler versions and may have different or unsafe semantics. "
            "'throw' and 'suicide' are deprecated aliases. "
            "'sha3' was renamed to 'keccak256'. "
            "'callcode' was deprecated in favour of 'delegatecall' and has been removed."
        ),
        recommendation=(
            "Replace all deprecated constructs: "
            "- suicide → selfdestruct "
            "- throw → revert() or require() "
            "- sha3() → keccak256() "
            "- callcode → delegatecall "
            "Compile with Solidity >= 0.8.0 to catch most deprecated usage at compile time."
        ),
        requires_manual_review=False,  # Deprecated usage is almost always a direct fix
        false_positive_note=(
            "Very low false positive rate. Deprecated keyword use is generally unambiguous."
        ),
    ),

    ChecklistItem(
        swc_id="SWC-113",
        swc_title="DoS with Failed Call",
        risk_level=ContractFindingRisk.HIGH,
        patterns=[
            # transfer() reverts on failure — if used in a loop, one failure blocks all
            r"\.transfer\s*\(",
            # Require/assert in a loop body — a failing condition blocks the whole loop
            r"for\s*\([^)]*\)[^{]*\{[^}]*require\s*\(",
        ],
        description=(
            "Potential Denial of Service via failed call detected. "
            "If .transfer() is called inside a loop, a single recipient reverting "
            "(e.g., a contract with a fallback that reverts) will block the entire loop, "
            "preventing all other participants from receiving their funds. "
            "This is a common vector in payment distribution contracts."
        ),
        recommendation=(
            "Use a pull-payment pattern instead of push payments: "
            "store each user's balance in a mapping and let them withdraw individually. "
            "If push payments are required, use .call{value:}() with a success check "
            "and continue the loop on failure (with appropriate event logging). "
            "Never use .transfer() in loops — its 2300 gas stipend also fails with modern contracts."
        ),
        requires_manual_review=True,
        false_positive_note=(
            "Medium false positive rate. .transfer() alone is not a DoS risk — only "
            "when used inside a loop iterating over external addresses."
        ),
    ),

    ChecklistItem(
        swc_id="SWC-128",
        swc_title="DoS with Block Gas Limit",
        risk_level=ContractFindingRisk.HIGH,
        patterns=[
            # for/while loops that may be unbounded
            r"\bfor\s*\(",
            r"\bwhile\s*\(",
        ],
        description=(
            "Loop construct detected that may be unbounded. "
            "If a loop iterates over a dynamically-sized data structure (e.g., an array "
            "that users can append to), it can exceed the block gas limit for large inputs, "
            "making the function permanently uncallable. "
            "This is a Denial of Service vulnerability via block gas exhaustion."
        ),
        recommendation=(
            "Avoid unbounded loops over user-controlled data structures. "
            "Strategies: "
            "1) Use pull-payment patterns to avoid distributing to many addresses at once. "
            "2) Process arrays in batches with an index parameter. "
            "3) Cap the maximum array size at write time. "
            "4) Use mappings instead of arrays where possible. "
            "Always test with realistic data sizes at the maximum expected scale."
        ),
        requires_manual_review=True,
        false_positive_note=(
            "High false positive rate. Loops are common and most are not unbounded. "
            "Focus review on loops over dynamic arrays that users can grow."
        ),
    ),
]

# Combined checklist: 5 base + 5 extended = 10 SWC checks
EXTENDED_CHECKLIST: list[ChecklistItem] = SMART_CONTRACT_CHECKLIST + EXTENDED_CHECKS


# ---------------------------------------------------------------------------
# Extended runner
# ---------------------------------------------------------------------------

class ExtendedSmartContractRunner(SmartContractReviewRunner):
    """
    SmartContractReviewRunner pre-loaded with the full extended checklist
    (10 SWC checks: SWC-100, 101, 103, 105, 106, 107, 111, 113, 115, 120, 128).
    """

    def __init__(self) -> None:
        super().__init__(checklist=EXTENDED_CHECKLIST)

    def review_with_summary(self, contract_path: Path) -> dict:
        """
        Run the full extended checklist and return a structured summary dict.

        Returns:
            dict with keys:
              - contract_path: str
              - total_findings: int
              - by_risk_level: dict[str, int]
              - findings: list of finding dicts
              - requires_immediate_attention: bool (any CRITICAL findings)
        """
        findings = self.review(contract_path)

        by_risk: dict[str, int] = {r.value: 0 for r in ContractFindingRisk}
        for f in findings:
            by_risk[f.risk_level.value] += 1

        return {
            "contract_path":             str(contract_path),
            "total_findings":            len(findings),
            "by_risk_level":             by_risk,
            "requires_immediate_attention": any(
                f.risk_level == ContractFindingRisk.CRITICAL for f in findings
            ),
            "findings": [
                {
                    "swc_id":       f.swc_id,
                    "swc_title":    f.swc_title,
                    "risk_level":   f.risk_level.value,
                    "line_number":  f.line_number,
                    "evidence":     f.evidence,
                    "recommendation": f.recommendation,
                    "requires_manual_review": f.requires_manual_review,
                }
                for f in findings
            ],
        }

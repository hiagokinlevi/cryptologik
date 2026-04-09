"""
Smart Contract Security Review Checklist
==========================================
A structured, SWC-mapped checklist tool for reviewing Solidity smart contract security.

This module provides:
  - A curated set of review checklist items covering critical SWC entries
  - A ChecklistRunner that evaluates a smart contract source file against the checklist
  - Pattern-based heuristics for common vulnerabilities (static analysis only)

IMPORTANT LIMITATIONS:
  - This tool provides heuristic pattern matching, NOT a formal security audit
  - Static analysis cannot detect all smart contract vulnerabilities
  - A thorough smart contract audit requires manual review by a qualified auditor
  - Some vulnerabilities (e.g., reentrancy via indirect calls) require control flow analysis
    that regex patterns cannot reliably detect
  - Always use this checklist as a SUPPLEMENT to, not a replacement for, professional audit

For production deployments:
  - Engage a professional smart contract audit firm
  - Use formal verification tools (Certora, Echidna, Slither) in CI/CD
  - Consider bug bounty programs for economic validation of security
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ContractFindingRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    INFORMATIONAL = "informational"


@dataclass
class ContractFinding:
    """A finding from the smart contract security review checklist."""
    swc_id: str                     # SWC identifier (e.g., "SWC-107")
    swc_title: str                   # SWC title
    risk_level: ContractFindingRisk
    description: str                 # Description of the specific issue found
    line_number: int | None = None   # Line number where the pattern was found
    evidence: str = ""               # Code excerpt (truncated for safety)
    recommendation: str = ""         # Remediation guidance
    requires_manual_review: bool = True  # Almost all contract findings need manual verification


@dataclass
class ChecklistItem:
    """
    A single checklist item representing a smart contract security check.

    Each item maps to one or more SWC entries and contains a detection heuristic
    (regex pattern) along with metadata for finding reporting.
    """
    swc_id: str
    swc_title: str
    risk_level: ContractFindingRisk
    patterns: list[str]              # Regex patterns that suggest this vulnerability
    description: str
    recommendation: str
    requires_manual_review: bool = True
    false_positive_note: str = ""


# ---------------------------------------------------------------------------
# Checklist — critical SWC entries
# ---------------------------------------------------------------------------

SMART_CONTRACT_CHECKLIST: list[ChecklistItem] = [
    ChecklistItem(
        swc_id="SWC-107",
        swc_title="Reentrancy",
        risk_level=ContractFindingRisk.CRITICAL,
        patterns=[
            # Detects .call{value:...}() pattern followed by state changes — classic reentrancy setup
            r"\.call\{value\s*:",
            # External call before state update (heuristic — requires manual verification)
            r"\.transfer\(",
            r"\.send\(",
        ],
        description=(
            "Potential reentrancy: the contract makes an external call that could allow "
            "a malicious contract to re-enter and manipulate state. "
            "This heuristic detects the presence of external calls — not confirmed reentrancy. "
            "Manual review is required to determine if state changes follow the external call."
        ),
        recommendation=(
            "Apply the checks-effects-interactions pattern: "
            "1) Check conditions, 2) Update state, 3) Make external calls. "
            "Use OpenZeppelin ReentrancyGuard on functions that make external calls. "
            "Prefer pull-payment patterns over push payments."
        ),
        requires_manual_review=True,
        false_positive_note=(
            "High false positive rate. External calls are common and not inherently unsafe. "
            "Only flagging as reentrancy if state changes occur AFTER the call — "
            "this requires manual code flow review."
        ),
    ),

    ChecklistItem(
        swc_id="SWC-101",
        swc_title="Integer Overflow and Underflow",
        risk_level=ContractFindingRisk.HIGH,
        patterns=[
            # Solidity pragma below 0.8 requires SafeMath
            r"pragma solidity\s+\^?0\.[0-7]\.",
        ],
        description=(
            "Contract uses Solidity < 0.8.x, which does not have built-in overflow protection. "
            "Integer arithmetic can silently overflow or underflow, leading to unexpected behavior "
            "(e.g., token balance wrapping to a very large number)."
        ),
        recommendation=(
            "Upgrade to Solidity >= 0.8.0 where overflow/underflow is handled automatically. "
            "If upgrading is not feasible, use OpenZeppelin SafeMath for all arithmetic. "
            "Add explicit overflow checks on all arithmetic operations."
        ),
        requires_manual_review=True,
        false_positive_note=(
            "Low false positive rate for the pragma check. "
            "Solidity version alone does not confirm a vulnerable arithmetic operation exists — "
            "manual review required to identify specific at-risk calculations."
        ),
    ),

    ChecklistItem(
        swc_id="SWC-105",
        swc_title="Unprotected Ether Withdrawal",
        risk_level=ContractFindingRisk.CRITICAL,
        patterns=[
            # Withdraw functions without visible access modifier
            r"function\s+withdraw\s*\(",
            r"function\s+withdrawEther\s*\(",
            r"function\s+drain\s*\(",
        ],
        description=(
            "Withdrawal function detected without confirmed access control. "
            "If this function lacks proper authorization checks (onlyOwner, role-based access), "
            "any caller could drain Ether from the contract."
        ),
        recommendation=(
            "Ensure all withdrawal functions have explicit access control modifiers. "
            "Use OpenZeppelin's Ownable or AccessControl for standardized access management. "
            "Require multi-signature approval for large withdrawals in DeFi contexts."
        ),
        requires_manual_review=True,
        false_positive_note=(
            "High false positive rate — most legitimate contracts have properly protected "
            "withdrawal functions. Manual review required to confirm access controls are present "
            "and correct."
        ),
    ),

    ChecklistItem(
        swc_id="SWC-115",
        swc_title="Authorization Through tx.origin",
        risk_level=ContractFindingRisk.HIGH,
        patterns=[
            r"tx\.origin",  # Any use of tx.origin — very low FP rate
        ],
        description=(
            "tx.origin used for authorization. "
            "tx.origin returns the original externally-owned account that initiated the transaction, "
            "not the immediate caller. A malicious intermediate contract can trick a victim into "
            "initiating a transaction, then forward it while tx.origin still points to the victim."
        ),
        recommendation=(
            "Replace all authorization checks using tx.origin with msg.sender. "
            "tx.origin is appropriate only for the specific use case of blocking relay attacks "
            "(checking that no intermediate contract was involved) — not for access control."
        ),
        requires_manual_review=True,
        false_positive_note=(
            "Low false positive rate. tx.origin in authorization context is almost always a vulnerability. "
            "Exception: legitimate use to require no intermediate contract (e.g., anti-relay patterns)."
        ),
    ),

    ChecklistItem(
        swc_id="SWC-120",
        swc_title="Weak Sources of Randomness from Chain Attributes",
        risk_level=ContractFindingRisk.HIGH,
        patterns=[
            r"block\.timestamp",
            r"block\.number",
            r"blockhash\(",
            r"block\.difficulty",
            r"block\.prevrandao",
        ],
        description=(
            "Block attribute used as source of randomness. "
            "block.timestamp, blockhash, block.difficulty, and related values can be "
            "manipulated or predicted by miners/validators, making them unsuitable for "
            "randomness in any security-sensitive context (lotteries, NFT reveals, game outcomes)."
        ),
        recommendation=(
            "Use Chainlink VRF (Verifiable Random Function) for secure on-chain randomness. "
            "Alternatively, implement a commit-reveal scheme. "
            "Block attributes are acceptable for non-security-sensitive timing (e.g., rate limiting, "
            "time windows) but must not be the sole source of randomness."
        ),
        requires_manual_review=True,
        false_positive_note=(
            "Medium false positive rate. Block attributes are legitimately used for timing (timestamps, "
            "vesting schedules) and are not inherently unsafe. Context determines risk."
        ),
    ),

    ChecklistItem(
        swc_id="SWC-100",
        swc_title="Function Default Visibility",
        risk_level=ContractFindingRisk.MEDIUM,
        patterns=[
            # Function declaration without explicit visibility (Solidity < 0.5)
            r"function\s+\w+\s*\([^)]*\)\s*(?:returns\s*\([^)]*\)\s*)?{",
        ],
        description=(
            "Function may lack an explicit visibility modifier. "
            "In Solidity < 0.5, functions default to public visibility if no modifier is specified. "
            "This can expose internal functions to external callers."
        ),
        recommendation=(
            "Add explicit visibility modifiers (public, external, internal, private) to all functions. "
            "Use external for functions only called from outside the contract (lower gas cost). "
            "This is enforced by the compiler in Solidity >= 0.5."
        ),
        requires_manual_review=True,
        false_positive_note=(
            "High false positive rate. This pattern matches all function declarations. "
            "Only relevant for Solidity < 0.5 — check the pragma first."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Checklist runner
# ---------------------------------------------------------------------------

class SmartContractReviewRunner:
    """
    Runs the smart contract security checklist against a Solidity source file.

    Args:
        checklist: List of ChecklistItem objects to run. Defaults to the built-in checklist.
    """

    def __init__(self, checklist: list[ChecklistItem] | None = None) -> None:
        self.checklist = checklist or SMART_CONTRACT_CHECKLIST

    def review(self, contract_path: Path) -> list[ContractFinding]:
        """
        Review a Solidity contract file against the security checklist.

        Args:
            contract_path: Path to the .sol Solidity source file.

        Returns:
            List of ContractFinding objects. Findings require manual verification
            before being reported as confirmed vulnerabilities.

        Raises:
            FileNotFoundError: If the contract file does not exist.
        """
        if not contract_path.exists():
            raise FileNotFoundError(f"Contract not found: {contract_path}")

        try:
            source = contract_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        findings: list[ContractFinding] = []
        lines = source.splitlines()

        for item in self.checklist:
            for pattern in item.patterns:
                for line_no, line in enumerate(lines, start=1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # Truncate evidence to avoid exposing sensitive contract logic
                        evidence = line.strip()[:120]
                        findings.append(ContractFinding(
                            swc_id=item.swc_id,
                            swc_title=item.swc_title,
                            risk_level=item.risk_level,
                            description=item.description,
                            line_number=line_no,
                            evidence=evidence,
                            recommendation=item.recommendation,
                            requires_manual_review=item.requires_manual_review,
                        ))
                        break  # Only report each check once per file, not per line

        return findings

    def print_summary(self, findings: list[ContractFinding]) -> None:
        """Print a human-readable summary of findings to stdout."""
        if not findings:
            print("No checklist items triggered. Manual review is still recommended.")
            return

        from tabulate import tabulate  # Import here to avoid hard dependency in tests

        rows = [
            [f.swc_id, f.swc_title, f.risk_level.upper(), f.line_number or "-"]
            for f in findings
        ]
        print(tabulate(rows, headers=["SWC", "Title", "Risk", "Line"], tablefmt="github"))
        print(f"\nTotal findings: {len(findings)}")
        print("\nNOTE: All findings require manual verification before being treated as confirmed vulnerabilities.")

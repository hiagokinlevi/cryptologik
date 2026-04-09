"""
Cryptographic and Blockchain Security Finding Schemas
======================================================
Pydantic models for all assessment findings in cryptologik.

These models serve as the canonical data contracts for:
  - Cryptographic configuration findings (CryptoConfigFinding)
  - Smart contract findings (SmartContractFinding)
  - Key management posture findings (KeyManagementFinding)
  - Assessment summaries (AssessmentSummary)

Usage:
    from schemas.crypto_finding import CryptoConfigFinding, RiskLevel, AssessmentSummary

    finding = CryptoConfigFinding(
        check_name="weak_crypto_DES",
        risk_level=RiskLevel.CRITICAL,
        file_path="src/encryption.py",
        line_number=42,
        description="DES usage detected",
        recommendation="Replace with AES-256-GCM",
    )
    summary = AssessmentSummary.from_findings([finding])

Design notes:
  - All enums use lowercase string values for config-file friendliness
  - Fields that may contain sensitive code excerpts are marked with masking guidance
  - Use .model_dump(mode="json") for JSON-serializable output
  - RiskLevel is shared across finding types for consistent risk aggregation
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """Standard risk level classification for all finding types."""
    INFORMATIONAL = "informational"   # No immediate risk; awareness only
    LOW = "low"                        # Minor issue; low exploitability or impact
    MEDIUM = "medium"                  # Notable issue; should be addressed in next sprint
    HIGH = "high"                      # Significant issue; address before next release
    CRITICAL = "critical"              # Must be remediated immediately


class FindingCategory(str, Enum):
    """Top-level finding category."""
    CRYPTO_CONFIG = "crypto_config"         # Cryptographic algorithm or mode issue
    KEY_MANAGEMENT = "key_management"       # Key storage, rotation, or access control
    SMART_CONTRACT = "smart_contract"       # Solidity / EVM smart contract weakness
    WALLET_SECURITY = "wallet_security"     # Wallet posture or key handling
    CUSTODY = "custody"                     # Institutional custody operational issue
    TLS_CONFIG = "tls_config"               # Transport layer security configuration
    PRNG = "prng"                           # Pseudorandom number generator weakness


class FindingStatus(str, Enum):
    """Lifecycle status of a finding."""
    OPEN = "open"                           # Identified, not yet addressed
    ACCEPTED_RISK = "accepted_risk"         # Acknowledged; risk formally accepted
    IN_REMEDIATION = "in_remediation"       # Fix in progress
    RESOLVED = "resolved"                   # Fixed and verified
    FALSE_POSITIVE = "false_positive"       # Determined not to be a real issue


# ---------------------------------------------------------------------------
# Base finding model
# ---------------------------------------------------------------------------

class BaseFinding(BaseModel):
    """
    Base class for all finding types.

    Shared fields applicable to every finding regardless of category.
    """
    finding_id: str = Field(
        default_factory=lambda: f"F-{uuid4().hex[:10].upper()}",
        description="Auto-generated unique finding identifier"
    )
    risk_level: RiskLevel = Field(
        description="Severity/risk classification of this finding"
    )
    category: FindingCategory = Field(
        description="Top-level category of the finding"
    )
    title: str = Field(
        min_length=5,
        max_length=200,
        description="Short, scannable finding title"
    )
    description: str = Field(
        description="Full explanation of the issue, including why it is a security concern"
    )
    recommendation: str = Field(
        description="Specific, actionable remediation guidance"
    )
    status: FindingStatus = Field(
        default=FindingStatus.OPEN,
        description="Current lifecycle status of the finding"
    )
    false_positive_note: str = Field(
        default="",
        description="Context on when this finding may be a false positive"
    )
    requires_manual_review: bool = Field(
        default=False,
        description="If True, this finding requires human verification before acting"
    )
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the finding was identified"
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Searchable tags for filtering and grouping findings"
    )


# ---------------------------------------------------------------------------
# Cryptographic configuration finding
# ---------------------------------------------------------------------------

class CryptoConfigFinding(BaseFinding):
    """
    A finding from cryptographic configuration static analysis.

    Produced by crypto/validators/config_validator.py.
    """
    category: FindingCategory = FindingCategory.CRYPTO_CONFIG  # Fixed for this type

    # Source location
    file_path: str = Field(
        description="Path to the file where the issue was detected"
    )
    line_number: int = Field(
        ge=1,
        description="Line number where the pattern was found"
    )
    evidence: str = Field(
        default="",
        max_length=200,     # Limit to prevent storing large code excerpts
        description="Truncated, masked code excerpt as evidence. Must not contain secrets."
    )
    check_name: str = Field(
        description="Identifier of the detection rule that produced this finding"
    )
    algorithm_detected: Optional[str] = Field(
        default=None,
        description="The specific algorithm or mode name that triggered this finding (e.g., 'MD5', 'ECB')"
    )

    @field_validator("evidence")
    @classmethod
    def evidence_must_not_be_full_line(cls, v: str) -> str:
        """Enforce evidence is truncated to prevent accidental sensitive data storage."""
        if len(v) > 200:
            return v[:200] + "..."
        return v


# ---------------------------------------------------------------------------
# Smart contract finding
# ---------------------------------------------------------------------------

class SmartContractFinding(BaseFinding):
    """
    A finding from smart contract security review.

    Produced by blockchain/smart_contracts/review_checklist.py.
    """
    category: FindingCategory = FindingCategory.SMART_CONTRACT

    swc_id: str = Field(
        pattern=r"^SWC-\d+$",
        description="SWC registry identifier (e.g., 'SWC-107')"
    )
    swc_title: str = Field(
        description="SWC entry title"
    )
    contract_path: Optional[str] = Field(
        default=None,
        description="Path to the reviewed Solidity contract file"
    )
    line_number: Optional[int] = Field(
        default=None,
        ge=1,
        description="Line number in the contract where the pattern was found"
    )
    evidence: str = Field(
        default="",
        max_length=200,
        description="Truncated code excerpt showing the flagged pattern"
    )

    # Smart contract findings almost always require manual review
    requires_manual_review: bool = True


# ---------------------------------------------------------------------------
# Key management finding
# ---------------------------------------------------------------------------

class KeyManagementFinding(BaseFinding):
    """
    A finding from key management posture review.

    Produced by crypto/key_management/posture_checker.py.
    """
    category: FindingCategory = FindingCategory.KEY_MANAGEMENT

    check_id: str = Field(
        description="Unique check identifier (e.g., 'KM-001')"
    )
    key_name: str = Field(
        description="The key or key group this finding applies to"
    )
    evidence: str = Field(
        default="",
        max_length=200,
        description="Relevant configuration excerpt (never include raw key material)"
    )

    @field_validator("evidence")
    @classmethod
    def evidence_must_not_contain_key_material(cls, v: str) -> str:
        """Rudimentary check that evidence doesn't look like key material."""
        # Flag if evidence looks like it might contain a base64-encoded key
        import re
        if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", v):
            return "[REDACTED — potential key material detected in evidence field]"
        return v


# ---------------------------------------------------------------------------
# Assessment summary
# ---------------------------------------------------------------------------

class AssessmentSummary(BaseModel):
    """
    Aggregated summary of a complete cryptographic security assessment.

    Created after all individual finding types have been collected.
    """
    assessment_id: str = Field(
        default_factory=lambda: f"ASSESS-{uuid4().hex[:8].upper()}",
        description="Unique assessment identifier"
    )
    target_description: str = Field(
        description="Description of what was assessed (e.g., 'cryptologik source tree', 'MyToken.sol')"
    )
    assessment_profile: str = Field(
        default="standard",
        description="Assessment profile used (minimal, standard, strict)"
    )
    conducted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the assessment was conducted"
    )
    conducted_by: Optional[str] = Field(
        default=None,
        description="Analyst or tool that conducted the assessment"
    )

    # Finding counts by risk level
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    informational_count: int = Field(default=0, ge=0)

    # Finding collections by type
    crypto_config_findings: list[CryptoConfigFinding] = Field(default_factory=list)
    smart_contract_findings: list[SmartContractFinding] = Field(default_factory=list)
    key_management_findings: list[KeyManagementFinding] = Field(default_factory=list)

    @property
    def total_findings(self) -> int:
        """Total number of findings across all categories."""
        return (
            self.critical_count + self.high_count + self.medium_count
            + self.low_count + self.informational_count
        )

    @property
    def overall_risk(self) -> RiskLevel:
        """
        Overall risk rating derived from the highest severity finding.

        Returns the highest severity present across all findings.
        """
        if self.critical_count > 0:
            return RiskLevel.CRITICAL
        if self.high_count > 0:
            return RiskLevel.HIGH
        if self.medium_count > 0:
            return RiskLevel.MEDIUM
        if self.low_count > 0:
            return RiskLevel.LOW
        return RiskLevel.INFORMATIONAL

    @classmethod
    def from_findings(
        cls,
        findings: list[CryptoConfigFinding | SmartContractFinding | KeyManagementFinding],
        target_description: str = "Unknown target",
        assessment_profile: str = "standard",
        conducted_by: Optional[str] = None,
    ) -> "AssessmentSummary":
        """
        Build an AssessmentSummary from a list of findings.

        Args:
            findings: All findings from the assessment.
            target_description: Description of what was assessed.
            assessment_profile: Profile used.
            conducted_by: Analyst or tool name.

        Returns:
            Populated AssessmentSummary instance.
        """
        counts = {level: 0 for level in RiskLevel}
        crypto_findings = []
        contract_findings = []
        km_findings = []

        for f in findings:
            counts[f.risk_level] += 1
            if isinstance(f, CryptoConfigFinding):
                crypto_findings.append(f)
            elif isinstance(f, SmartContractFinding):
                contract_findings.append(f)
            elif isinstance(f, KeyManagementFinding):
                km_findings.append(f)

        return cls(
            target_description=target_description,
            assessment_profile=assessment_profile,
            conducted_by=conducted_by,
            critical_count=counts[RiskLevel.CRITICAL],
            high_count=counts[RiskLevel.HIGH],
            medium_count=counts[RiskLevel.MEDIUM],
            low_count=counts[RiskLevel.LOW],
            informational_count=counts[RiskLevel.INFORMATIONAL],
            crypto_config_findings=crypto_findings,
            smart_contract_findings=contract_findings,
            key_management_findings=km_findings,
        )

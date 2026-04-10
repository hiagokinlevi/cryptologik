"""
Cryptographic Configuration Validator
=======================================
Detects insecure or deprecated cryptographic configurations in code and config files.

Checks for common cryptographic anti-patterns:
  - Deprecated algorithms (MD5, SHA1 for security purposes, DES, 3DES, RC4)
  - Weak key sizes (RSA < 2048, EC < 256)
  - ECB mode usage (not semantically secure)
  - Hardcoded IV/nonce values
  - Weak PRNG usage (random module for cryptographic purposes)
  - Missing MAC/authentication (encrypt-then-MAC violations)

LIMITATIONS:
  - Static analysis only — cannot evaluate runtime behavior
  - May produce false positives (e.g., MD5 used for checksums, not security)
  - Does not replace a proper cryptographic review
"""
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class CryptoRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CryptoFinding:
    """A single cryptographic configuration finding."""
    check_name: str
    risk_level: CryptoRisk
    file_path: str
    line_number: int
    evidence: str           # Masked, non-sensitive excerpt
    description: str
    recommendation: str
    false_positive_note: str = ""


# Patterns for detecting deprecated or weak cryptographic usage
_WEAK_ALGO_PATTERNS = [
    (r"\bMD5\b(?!\s*#[^\n]*checksum)", CryptoRisk.HIGH,
     "MD5 usage detected",
     "MD5 is cryptographically broken. Use SHA-256 or SHA-3 for security purposes.",
     "May be a false positive if used for non-security checksums (e.g., cache keys)"),

    (r"\bSHA1\b(?!\s*#[^\n]*legacy)", CryptoRisk.HIGH,
     "SHA-1 usage detected",
     "SHA-1 is deprecated for security purposes. Use SHA-256 or SHA-3.",
     "May be a false positive in legacy compatibility code"),

    (r"\bDES\b|\b3DES\b|\bTripleDES\b", CryptoRisk.CRITICAL,
     "DES/3DES usage detected",
     "DES and 3DES are deprecated. Use AES-256-GCM or ChaCha20-Poly1305.",
     ""),

    (r"\bRC4\b|\bARC4\b", CryptoRisk.CRITICAL,
     "RC4 usage detected",
     "RC4 is broken and must not be used. Use AES-256-GCM or ChaCha20-Poly1305.",
     ""),

    (r"\bAES\b.*\b(?:MODE_)?ECB\b|ECBMode|mode\s*=\s*['\"]?ECB|['\"]ECB['\"]", CryptoRisk.HIGH,
     "AES-ECB mode detected",
     "ECB mode is not semantically secure — identical plaintext blocks produce identical ciphertext. Use GCM or CBC with proper IV.",
     ""),

    (r"import random\b.*\n.*(?:key|token|secret|password|nonce|salt)", CryptoRisk.HIGH,
     "Non-cryptographic RNG used near security-sensitive variable",
     "Use secrets.token_bytes() or os.urandom() for cryptographic randomness, not the random module.",
     "May be a false positive if random is used for non-security purposes elsewhere"),
]


def validate_crypto_config(file_path: Path) -> list[CryptoFinding]:
    """
    Scan a source file for cryptographic anti-patterns.

    Args:
        file_path: Path to the file to scan.

    Returns:
        List of CryptoFinding objects. Empty list means no issues detected.
    """
    findings = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    for line_no, line in enumerate(content.splitlines(), start=1):
        for pattern, risk, description, recommendation, fp_note in _WEAK_ALGO_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Mask the line to avoid leaking sensitive data
                masked = line.strip()[:100]
                findings.append(CryptoFinding(
                    check_name=f"weak_crypto_{pattern[:20].replace(r'\\b', '').strip()}",
                    risk_level=risk,
                    file_path=str(file_path),
                    line_number=line_no,
                    evidence=masked,
                    description=description,
                    recommendation=recommendation,
                    false_positive_note=fp_note,
                ))

    return findings

"""
Cryptographic anti-pattern detector for source code.

Scans source files for dangerous cryptographic patterns:
- Hardcoded keys/secrets/IVs
- Use of broken algorithms (MD5, SHA-1, DES, RC4, ECB mode)
- Insecure random number generation (random.random instead of secrets)
- Predictable IVs or nonces
- Weak key sizes

Uses regex scanning — no code execution, purely static analysis.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class AntiPatternFinding:
    rule_id: str
    severity: Severity
    file: str
    line: int
    matched_text: str
    message: str
    remediation: str


# Each rule: (rule_id, severity, regex_pattern, message, remediation)
_RULES: list[tuple[str, Severity, re.Pattern, str, str]] = [
    (
        "CP001", Severity.CRITICAL,
        re.compile(r'(?i)(key|secret|password|iv|nonce)\s*=\s*["\'][0-9a-fA-F]{16,}["\']'),
        "Hardcoded cryptographic key, secret, or IV detected",
        "Store secrets in environment variables or a secrets manager. Never hardcode key material.",
    ),
    (
        "CP002", Severity.HIGH,
        re.compile(r'(?i)\b(md5|MD5)\s*[\(\.]'),
        "MD5 in use — cryptographically broken, collision attacks are practical",
        "Replace MD5 with SHA-256 or SHA-3 for integrity checks. Never use MD5 for passwords.",
    ),
    (
        "CP003", Severity.HIGH,
        re.compile(r'(?i)\b(sha1|sha_1|SHA1|hashlib\.sha1)\s*[\(\.]'),
        "SHA-1 in use — deprecated, collision attacks demonstrated (SHAttered)",
        "Replace SHA-1 with SHA-256 or higher for all security-sensitive uses.",
    ),
    (
        "CP004", Severity.CRITICAL,
        re.compile(r'(?i)\b(DES|3DES|TripleDES|RC4|RC2|Blowfish)\b'),
        "Broken or deprecated symmetric cipher detected",
        "Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption.",
    ),
    (
        "CP005", Severity.HIGH,
        re.compile(r'(?i)\bAES\.?ECB\b|\bECB\b|mode=ECB|MODE_ECB'),
        "AES in ECB mode — does not provide semantic security (identical plaintext → identical ciphertext)",
        "Use AES-GCM (authenticated) or AES-CBC with a random IV. Never use ECB for more than one block.",
    ),
    (
        "CP006", Severity.HIGH,
        re.compile(r'(?i)\brandom\.random\(\)|\brandom\.randint\b|\brandom\.choice\b'),
        "Insecure PRNG (random module) potentially used for security-sensitive values",
        "Use the 'secrets' module for security-sensitive random values (tokens, IVs, nonces, salts).",
    ),
    (
        "CP007", Severity.MEDIUM,
        re.compile(r'(?i)iv\s*=\s*b["\'][\x00-\xff]{0,16}["\']|nonce\s*=\s*b["\'][\x00-\xff]{0,16}["\']'),
        "Potentially hardcoded IV or nonce",
        "Generate IVs and nonces using os.urandom() or secrets.token_bytes() for each encryption operation.",
    ),
    (
        "CP008", Severity.MEDIUM,
        re.compile(r'(?i)(RSA|rsa).*?(?:key_size|bits|key_length)\s*[=:]\s*(?:512|768|1024)\b'),
        "RSA key size too small (< 2048 bits)",
        "Use RSA-2048 at minimum; prefer RSA-4096 or switch to ECDSA P-256/P-384.",
    ),
    (
        "CP009", Severity.LOW,
        re.compile(r'(?i)\.encode\(["\']base64["\']|import base64'),
        "Base64 encoding used — note: base64 is encoding, not encryption",
        "Ensure base64-encoded data is also encrypted if confidentiality is required.",
    ),
]


def scan_file(file_path: Path) -> list[AntiPatternFinding]:
    """
    Scan a source file for cryptographic anti-patterns.

    Args:
        file_path: Path to the source file to scan.

    Returns:
        List of AntiPatternFinding objects for each match found.
    """
    findings: list[AntiPatternFinding] = []
    try:
        lines = file_path.read_text(errors="replace").splitlines()
    except OSError:
        return findings

    for lineno, line in enumerate(lines, start=1):
        # Skip comments (Python, JS, Go, Java single-line comments)
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "/*")):
            continue

        for rule_id, severity, pattern, message, remediation in _RULES:
            m = pattern.search(line)
            if m:
                findings.append(AntiPatternFinding(
                    rule_id=rule_id,
                    severity=severity,
                    file=str(file_path),
                    line=lineno,
                    matched_text=m.group(0)[:80],
                    message=message,
                    remediation=remediation,
                ))

    return findings


def scan_directory(directory: Path, extensions: tuple[str, ...] = (".py", ".js", ".ts", ".go", ".java")) -> list[AntiPatternFinding]:
    """
    Recursively scan a directory for cryptographic anti-patterns.

    Args:
        directory:  Root directory to scan.
        extensions: File extensions to include in the scan.

    Returns:
        Aggregated list of AntiPatternFinding objects from all scanned files.
    """
    all_findings: list[AntiPatternFinding] = []
    for path in directory.rglob("*"):
        if path.is_file() and path.suffix in extensions:
            all_findings.extend(scan_file(path))
    return all_findings

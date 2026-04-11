"""
Validador estatico de configuracao criptografica.

Este modulo faz uma revisao defensiva de arquivos de codigo e configuracao para
identificar anti-patterns criptograficos conhecidos. A cobertura atual combina
regras genericas com regras especificas para Python, Java, Go e
JavaScript/TypeScript.

Limitacoes:
  - A analise e estatica e baseada em padroes; nao substitui revisao manual.
  - Algumas regras podem gerar falso positivo em codigo de compatibilidade ou
    exemplos laboratoriais.
  - O modulo nao executa codigo nem estabelece conexoes externas.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class CryptoRisk(str, Enum):
    """Niveis de risco suportados pelo validador."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class CryptoFinding:
    """Representa um achado individual do validador."""

    check_name: str
    risk_level: CryptoRisk
    file_path: str
    line_number: int
    evidence: str
    description: str
    recommendation: str
    false_positive_note: str = ""


@dataclass(frozen=True)
class PatternSpec:
    """Define uma regra de deteccao baseada em regex."""

    check_name: str
    family: str
    pattern: re.Pattern[str]
    risk_level: CryptoRisk
    description: str
    recommendation: str
    false_positive_note: str = ""
    extensions: tuple[str, ...] = ()
    specificity: int = 1


def _compile(pattern: str) -> re.Pattern[str]:
    """Compila uma regex no modo case-insensitive."""

    return re.compile(pattern, re.IGNORECASE)


_GENERIC_PATTERNS = [
    PatternSpec(
        check_name="weak_crypto_md5",
        family="md5",
        pattern=_compile(r"\b(?:MD5|md5)\b(?![^#\n]*checksum)"),
        risk_level=CryptoRisk.HIGH,
        description="MD5 usage detected",
        recommendation="Replace MD5 with SHA-256, SHA-3, Argon2id, or bcrypt depending on the use case.",
        false_positive_note="May be acceptable only for clearly documented non-security checksums.",
    ),
    PatternSpec(
        check_name="weak_crypto_sha1",
        family="sha1",
        pattern=_compile(r"\b(?:SHA-?1|sha1)\b(?![^#\n]*legacy)"),
        risk_level=CryptoRisk.HIGH,
        description="SHA-1 usage detected",
        recommendation="Replace SHA-1 with SHA-256 or SHA-3 for integrity and signature workflows.",
        false_positive_note="Legacy interoperability code may need manual review.",
    ),
    PatternSpec(
        check_name="weak_crypto_des_3des",
        family="legacy_block_cipher",
        pattern=_compile(r"\b(?:DES|3DES|TripleDES|DESede)\b"),
        risk_level=CryptoRisk.CRITICAL,
        description="DES or 3DES usage detected",
        recommendation="Remove DES and 3DES. Use AES-256-GCM or ChaCha20-Poly1305.",
    ),
    PatternSpec(
        check_name="weak_crypto_rc4",
        family="rc4",
        pattern=_compile(r"\b(?:RC4|ARC4)\b"),
        risk_level=CryptoRisk.CRITICAL,
        description="RC4 usage detected",
        recommendation="Remove RC4. Use AES-256-GCM or ChaCha20-Poly1305.",
    ),
    PatternSpec(
        check_name="weak_crypto_ecb",
        family="ecb",
        pattern=_compile(
            r"\bAES\b.*\b(?:MODE_)?ECB\b|"
            r"ECBMode|"
            r"mode\s*=\s*['\"]?ECB\b|"
            r"['\"](?:AES/ECB(?:/NoPadding|/PKCS5Padding)?|aes-[^'\"]*-ecb)['\"]"
        ),
        risk_level=CryptoRisk.HIGH,
        description="AES-ECB mode detected",
        recommendation="Replace ECB with an authenticated mode such as AES-GCM or ChaCha20-Poly1305.",
    ),
    PatternSpec(
        check_name="weak_crypto_python_random_secret",
        family="weak_prng",
        pattern=_compile(
            r"(?=.*\brandom\.(?:random|randbytes|randint|randrange|choice|choices)\()"
            r"(?=.*\b(?:key|token|secret|password|nonce|salt)\b)"
        ),
        risk_level=CryptoRisk.HIGH,
        description="Non-cryptographic Python random() usage near a security-sensitive value",
        recommendation="Use secrets.token_bytes(), secrets.token_hex(), or os.urandom() for security-sensitive randomness.",
        false_positive_note="Review context if random() is not actually used for credential, secret, or nonce generation.",
        extensions=(".py",),
    ),
]

_LANGUAGE_PATTERNS = [
    PatternSpec(
        check_name="java_jca_md5",
        family="md5",
        pattern=_compile(r'MessageDigest\.getInstance\(\s*"MD5"\s*\)'),
        risk_level=CryptoRisk.HIGH,
        description="Java JCA MD5 digest usage detected",
        recommendation="Replace MessageDigest MD5 with SHA-256 or stronger primitives.",
        extensions=(".java",),
        specificity=2,
    ),
    PatternSpec(
        check_name="java_jca_sha1",
        family="sha1",
        pattern=_compile(r'MessageDigest\.getInstance\(\s*"SHA-?1"\s*\)'),
        risk_level=CryptoRisk.HIGH,
        description="Java JCA SHA-1 digest usage detected",
        recommendation="Replace SHA-1 with SHA-256 or SHA-3 in Java digest workflows.",
        extensions=(".java",),
        specificity=2,
    ),
    PatternSpec(
        check_name="java_jce_sha1prng",
        family="weak_prng",
        pattern=_compile(r'SecureRandom\.getInstance\(\s*"SHA1PRNG"\s*\)'),
        risk_level=CryptoRisk.HIGH,
        description="Java SecureRandom SHA1PRNG usage detected",
        recommendation="Use the default SecureRandom provider or a modern approved DRBG instead of SHA1PRNG.",
        false_positive_note="Some older runtimes expose SHA1PRNG by default, so manual review is recommended before remediation.",
        extensions=(".java",),
        specificity=2,
    ),
    PatternSpec(
        check_name="java_signature_sha1withrsa",
        family="sha1_signature",
        pattern=_compile(r'Signature\.getInstance\(\s*"SHA1withRSA(?:Encryption)?"\s*\)'),
        risk_level=CryptoRisk.HIGH,
        description="Java SHA1withRSA signature usage detected",
        recommendation="Replace SHA1withRSA with SHA256withRSA or stronger signature algorithms.",
        extensions=(".java",),
        specificity=2,
    ),
    PatternSpec(
        check_name="java_pbe_md5_des",
        family="legacy_pbe",
        pattern=_compile(r'PBEWithMD5AndDES'),
        risk_level=CryptoRisk.CRITICAL,
        description="Java password-based encryption with MD5 and DES detected",
        recommendation="Replace legacy PBEWithMD5AndDES with Argon2id, scrypt, or PBKDF2-HMAC-SHA-256 with strong iteration counts and AES-GCM.",
        extensions=(".java",),
        specificity=2,
    ),
    PatternSpec(
        check_name="go_tls_insecure_skip_verify",
        family="tls_verification",
        pattern=_compile(r'InsecureSkipVerify\s*:\s*true'),
        risk_level=CryptoRisk.CRITICAL,
        description="Go crypto/tls InsecureSkipVerify=true detected",
        recommendation="Enable certificate verification and trust pinning instead of disabling TLS verification.",
        extensions=(".go",),
        specificity=2,
    ),
    PatternSpec(
        check_name="go_tls_legacy_min_version",
        family="tls_min_version",
        pattern=_compile(r'MinVersion\s*:\s*(?:0|tls\.VersionSSL30|tls\.VersionTLS10|tls\.VersionTLS11)'),
        risk_level=CryptoRisk.HIGH,
        description="Go TLS minimum version allows deprecated protocols",
        recommendation="Set MinVersion to tls.VersionTLS12 or tls.VersionTLS13.",
        extensions=(".go",),
        specificity=2,
    ),
    PatternSpec(
        check_name="go_tls_curvep224",
        family="tls_curve",
        pattern=_compile(r'CurvePreferences\s*:\s*\[\]tls\.CurveID\{[^}]*CurveP224'),
        risk_level=CryptoRisk.MEDIUM,
        description="Go TLS configuration includes the deprecated CurveP224",
        recommendation="Prefer X25519, P-256, or stronger supported curves and remove CurveP224.",
        extensions=(".go",),
        specificity=2,
    ),
    PatternSpec(
        check_name="go_crypto_md5",
        family="md5",
        pattern=_compile(r'\bmd5\.New\('),
        risk_level=CryptoRisk.HIGH,
        description="Go md5.New() usage detected",
        recommendation="Replace md5.New() with sha256.New() or a stronger construction appropriate to the workflow.",
        extensions=(".go",),
        specificity=2,
    ),
    PatternSpec(
        check_name="go_crypto_sha1",
        family="sha1",
        pattern=_compile(r'\bsha1\.New\('),
        risk_level=CryptoRisk.HIGH,
        description="Go sha1.New() usage detected",
        recommendation="Replace sha1.New() with sha256.New() or a stronger digest.",
        extensions=(".go",),
        specificity=2,
    ),
    PatternSpec(
        check_name="go_crypto_des",
        family="legacy_block_cipher",
        pattern=_compile(r'\bdes\.(?:NewCipher|NewTripleDESCipher)\('),
        risk_level=CryptoRisk.CRITICAL,
        description="Go DES or 3DES cipher usage detected",
        recommendation="Replace DES and 3DES with AES-GCM or ChaCha20-Poly1305.",
        extensions=(".go",),
        specificity=2,
    ),
    PatternSpec(
        check_name="go_crypto_rc4",
        family="rc4",
        pattern=_compile(r'\brc4\.NewCipher\('),
        risk_level=CryptoRisk.CRITICAL,
        description="Go RC4 cipher usage detected",
        recommendation="Remove RC4 and migrate to modern authenticated encryption.",
        extensions=(".go",),
        specificity=2,
    ),
    PatternSpec(
        check_name="js_crypto_md5",
        family="md5",
        pattern=_compile(r'(?:\bcrypto\.)?createHash\(\s*[\'"]md5[\'"]'),
        risk_level=CryptoRisk.HIGH,
        description="Node.js createHash('md5') usage detected",
        recommendation="Replace MD5 with SHA-256 or stronger primitives in node:crypto workflows.",
        extensions=(".js", ".ts", ".mjs", ".cjs"),
        specificity=2,
    ),
    PatternSpec(
        check_name="js_crypto_sha1",
        family="sha1",
        pattern=_compile(r'(?:\bcrypto\.)?createHash\(\s*[\'"]sha1[\'"]'),
        risk_level=CryptoRisk.HIGH,
        description="Node.js createHash('sha1') usage detected",
        recommendation="Replace SHA-1 with SHA-256 or stronger algorithms in node:crypto workflows.",
        extensions=(".js", ".ts", ".mjs", ".cjs"),
        specificity=2,
    ),
    PatternSpec(
        check_name="js_crypto_create_cipher",
        family="legacy_cipher_api",
        pattern=_compile(r'(?:\bcrypto\.)?createCipher\('),
        risk_level=CryptoRisk.CRITICAL,
        description="Node.js createCipher() usage detected",
        recommendation="Replace deprecated createCipher() with createCipheriv() and an authenticated cipher such as aes-256-gcm.",
        extensions=(".js", ".ts", ".mjs", ".cjs"),
        specificity=2,
    ),
    PatternSpec(
        check_name="js_crypto_create_decipher",
        family="legacy_cipher_api",
        pattern=_compile(r'(?:\bcrypto\.)?createDecipher\('),
        risk_level=CryptoRisk.CRITICAL,
        description="Node.js createDecipher() usage detected",
        recommendation="Replace deprecated createDecipher() with createDecipheriv() and authenticated decryption patterns.",
        extensions=(".js", ".ts", ".mjs", ".cjs"),
        specificity=2,
    ),
    PatternSpec(
        check_name="js_crypto_ecb_cipheriv",
        family="ecb",
        pattern=_compile(r'(?:\bcrypto\.)?createCipheriv\(\s*[\'"][^\'"]*ecb[\'"]'),
        risk_level=CryptoRisk.HIGH,
        description="Node.js createCipheriv() uses an ECB cipher suite",
        recommendation="Replace ECB ciphers with AES-GCM or ChaCha20-Poly1305 and a unique nonce/IV strategy.",
        extensions=(".js", ".ts", ".mjs", ".cjs"),
        specificity=2,
    ),
    PatternSpec(
        check_name="js_crypto_math_random_secret",
        family="weak_prng",
        pattern=_compile(
            r"(?=.*\bMath\.random\(\))(?=.*\b(?:key|token|secret|password|nonce|salt)\b)"
        ),
        risk_level=CryptoRisk.HIGH,
        description="Math.random() is used near a security-sensitive value",
        recommendation="Replace Math.random() with crypto.randomBytes(), randomUUID(), or Web Crypto secure randomness APIs.",
        false_positive_note="Review context if the value is not actually used for secret generation.",
        extensions=(".js", ".ts", ".mjs", ".cjs"),
        specificity=2,
    ),
    PatternSpec(
        check_name="js_crypto_pbkdf2_low_iterations",
        family="weak_kdf_parameters",
        pattern=_compile(r'\bpbkdf2(?:Sync)?\([^,\n]+,[^,\n]+,\s*(?:[1-9]\d{0,4})\s*,'),
        risk_level=CryptoRisk.HIGH,
        description="Node.js PBKDF2 usage with a low iteration count detected",
        recommendation="Increase PBKDF2 iterations to a modern baseline or migrate password hashing to Argon2id or scrypt.",
        false_positive_note="Iteration guidance depends on hardware and latency budget; review the intended threat model.",
        extensions=(".js", ".ts", ".mjs", ".cjs"),
        specificity=2,
    ),
    PatternSpec(
        check_name="js_crypto_sha1_signature",
        family="sha1_signature",
        pattern=_compile(r'(?:\bcrypto\.)?create(?:Sign|Verify)\(\s*[\'"]RSA-SHA1[\'"]'),
        risk_level=CryptoRisk.HIGH,
        description="Node.js RSA-SHA1 signature usage detected",
        recommendation="Replace RSA-SHA1 with SHA-256 based signature algorithms or stronger approved schemes.",
        extensions=(".js", ".ts", ".mjs", ".cjs"),
        specificity=2,
    ),
]

_ALL_PATTERNS = tuple(_GENERIC_PATTERNS + _LANGUAGE_PATTERNS)


def _matches_extension(pattern: PatternSpec, suffix: str) -> bool:
    """Retorna True quando a regra se aplica ao tipo de arquivo atual."""

    return not pattern.extensions or suffix in pattern.extensions


def _mask_evidence(line: str) -> str:
    """Reduz a evidencia a um trecho curto e nao sensivel."""

    return line.strip()[:100]


def validate_crypto_config(file_path: Path) -> list[CryptoFinding]:
    """Escaneia um arquivo de codigo em busca de anti-patterns criptograficos."""

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    suffix = file_path.suffix.lower()
    findings: list[CryptoFinding] = []
    selected_matches: dict[tuple[int, str], tuple[int, int]] = {}

    for line_number, line in enumerate(content.splitlines(), start=1):
        for pattern in _ALL_PATTERNS:
            if not _matches_extension(pattern, suffix):
                continue
            if not pattern.pattern.search(line):
                continue

            finding = CryptoFinding(
                check_name=pattern.check_name,
                risk_level=pattern.risk_level,
                file_path=str(file_path),
                line_number=line_number,
                evidence=_mask_evidence(line),
                description=pattern.description,
                recommendation=pattern.recommendation,
                false_positive_note=pattern.false_positive_note,
            )
            dedup_key = (line_number, pattern.family)
            existing = selected_matches.get(dedup_key)

            if existing and existing[0] >= pattern.specificity:
                continue
            if existing:
                findings[existing[1]] = finding
                selected_matches[dedup_key] = (pattern.specificity, existing[1])
                continue

            findings.append(finding)
            selected_matches[dedup_key] = (pattern.specificity, len(findings) - 1)

    return findings

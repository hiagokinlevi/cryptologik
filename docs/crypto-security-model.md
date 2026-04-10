# Cryptographic Security Model

## Threat Model

This tool is designed to detect weaknesses in the following threat categories:

### 1. Algorithm-Level Weaknesses
Using cryptographic algorithms that have been broken or deprecated by the research community and standards bodies (NIST, IETF).

**Examples:**
- MD5 and SHA-1 are collision-resistant but broken for security-critical uses (digital signatures, certificates)
- DES has a 56-bit key space that is trivially brute-forced
- RC4 has multiple known biases and must not be used in any new system

**Detection approach:** Static pattern matching for known weak algorithm names in source code and configuration.

### 2. Implementation-Level Weaknesses
Using correct algorithms incorrectly in ways that eliminate their security properties.

**Examples:**
- AES-ECB mode: identical plaintext blocks produce identical ciphertext — reveals patterns
- Static/hardcoded IV: reusing the same IV with the same key in stream cipher modes allows key recovery
- Weak PRNG: using `random.random()` or `Math.random()` for cryptographic key material

**Detection approach:** Pattern matching for mode strings, IV assignment patterns, and PRNG imports near sensitive variable names.

### 3. Key Management Weaknesses
Correct algorithms implemented correctly, but with poor key management that undermines the security model.

**Examples:**
- Keys that never rotate: a compromised key provides indefinite access
- Keys stored in plaintext files: accessible to anyone with file system access
- Overly broad key access: violates least-privilege, increases blast radius

**Detection approach:** Structured review of key management YAML configurations.

### 4. Transport Layer Weaknesses
Cryptographic weaknesses in TLS/SSL configurations.

**Examples:**
- TLS 1.0/1.1: deprecated due to protocol-level weaknesses (BEAST, POODLE)
- RC4 cipher suites: stream cipher weaknesses
- NULL cipher suites: no encryption at all
- Long-lived public TLS leaf certificates: delayed rotation and larger exposure windows after key or issuance mistakes

**Detection approach:** Offline listener configuration review with cipher-suite and protocol-version checks. The TLS scanner flags NULL or anonymous ciphers, RC4, DES/3DES, export-grade suites, missing AEAD, deprecated protocol versions, and missing forward secrecy. Certificate-chain review also checks expiry, SAN/CN alignment, weak signature algorithms, incomplete chains, weak key sizes, and long-lived public leaf certificate windows.

---

## Cryptographic Algorithm Guidance

### Symmetric Encryption

| Algorithm | Status | Notes |
|---|---|---|
| AES-256-GCM | **Recommended** | AEAD — provides confidentiality and integrity |
| AES-128-GCM | Acceptable | 128-bit security margin is sufficient for most use cases |
| ChaCha20-Poly1305 | **Recommended** | Excellent for software implementations; no hardware requirement |
| AES-CBC | Use with caution | Requires random IV and separate MAC (encrypt-then-MAC) |
| AES-ECB | **Prohibited** | Not semantically secure |
| 3DES | **Prohibited** | NIST deprecated 2023 |
| DES | **Prohibited** | Broken |
| RC4 | **Prohibited** | Multiple known breaks |

### Asymmetric Encryption

| Algorithm | Minimum Key Size | Notes |
|---|---|---|
| RSA | 2048 bits | 3072+ recommended for long-term (2030+) |
| ECDH/ECDSA with NIST curves | P-256 | P-384 for higher security margin |
| X25519/Ed25519 | N/A (fixed curve) | **Recommended** — safer curve, faster |
| RSA-1024 | **Prohibited** | Broken in research |

### Hashing

| Algorithm | Security Use | Non-Security Use | Notes |
|---|---|---|---|
| SHA-256 | Yes | Yes | Recommended for most uses |
| SHA-512 | Yes | Yes | Higher security margin |
| SHA3-256 / SHA3-512 | Yes | Yes | Different design family from SHA-2 |
| BLAKE2b / BLAKE3 | Yes | Yes | High performance; good for checksums |
| SHA-1 | **No** | Acceptable | Do not use for signatures, MACs, or commitments |
| MD5 | **No** | Acceptable | Do not use for any security purpose |

### Password Hashing

**Never use** general-purpose hash functions (SHA-256, MD5) for passwords.

| Algorithm | Status | Minimum Parameters |
|---|---|---|
| Argon2id | **Recommended** | 64MB memory, 3 iterations, 4 parallelism |
| bcrypt | Acceptable | Work factor ≥ 12 |
| scrypt | Acceptable | N=131072, r=8, p=1 |
| PBKDF2-SHA256 | Acceptable | 600,000 iterations (NIST 2023) |

---

## Cryptographic Principles

### Principle 1: Use Established Algorithms
Never design your own cryptographic algorithms or protocols. Use well-studied, peer-reviewed constructions.

### Principle 2: Authenticated Encryption
Prefer Authenticated Encryption with Associated Data (AEAD) schemes (AES-GCM, ChaCha20-Poly1305) over plain encryption. These provide both confidentiality and integrity in a single primitive.

### Principle 3: Random IV/Nonce
Never reuse an IV or nonce with the same key. For GCM specifically, IV/nonce reuse with the same key allows key recovery.

### Principle 4: Cryptographic Randomness
Use only OS-level CSPRNGs (cryptographically secure pseudorandom number generators) for key material and nonces. In Python: `secrets` module or `os.urandom()`.

### Principle 5: Key Rotation
Define and enforce rotation policies. Even with strong algorithms, long-lived keys accumulate risk.

For public TLS, keep leaf certificates short-lived and automate renewal. The chain validator flags leaf certificates with validity windows above 398 days so teams can identify stale issuance patterns before browser trust or incident-response deadlines make renewal urgent.

### Principle 6: Defense in Depth
Cryptography alone is not sufficient security. Access controls, key management, secure coding practices, and operational security all contribute to the overall security model.

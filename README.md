# cryptologik

**Cryptographic security validation, key management posture review, smart contract analysis, and blockchain security baselines.**

---

## Overview

`cryptologik` is a defensive security toolkit for cryptographic and blockchain system reviews. It provides:

- **Cryptographic configuration validation** — static analysis for deprecated algorithms, weak key sizes, ECB mode, and insecure PRNGs
- **TLS configuration review** — offline cipher suite and protocol version analysis for listener configs
- **Key management posture review** — checks for rotation policies, storage hygiene, and access controls
- **TLS certificate chain validation** — offline review for weak signatures, incomplete chains, hostname/SAN drift, weak keys, expiry risk, and long-lived leaf certificates
- **Smart contract review tooling** — SWC-mapped checklists for Solidity security review
- **Blockchain security baselines** — wallet security checklists and custody operational guides
- **Policy baselines** — YAML-defined cryptographic baseline policies for org-wide enforcement
- **Pydantic schemas** — machine-readable finding models for SIEM and reporting integration
- **CLI tooling** — review, assess, and report from the terminal

This tool is for **defensive use** — it helps security engineers, auditors, and developers identify and remediate cryptographic weaknesses.

---

## Repository Structure

```
cryptologik/
├── crypto/
│   ├── validators/         # Cryptographic config static analysis
│   └── key_management/     # Key management posture checks
├── blockchain/
│   ├── smart_contracts/    # Smart contract review checklists
│   ├── swc_mappings/       # SWC registry reference (YAML)
│   ├── wallets/            # Wallet security checklists
│   └── custody/            # Custody security guides
├── policies/
│   └── crypto-baselines/   # Cryptographic baseline policy files
├── schemas/                # Pydantic finding models
├── reports/                # Report generator
├── cli/                    # Click CLI entrypoint
├── docs/                   # Architecture and model documentation
├── training/               # Tutorials and hands-on labs
└── tests/                  # Unit tests
```

---

## Quickstart

### Prerequisites

- Python 3.11+

### Installation

```bash
git clone https://github.com/hiagokinlevi/cryptologik.git
cd cryptologik

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -e .

cp .env.example .env
```

### Run a Cryptographic Config Review

```bash
# Scan a source directory for cryptographic anti-patterns
cryptologik review-crypto-config --path ./src --output report.md

# Review offline TLS listener configuration
cryptologik review-tls-config --config tls-config.json --output tls-results.json

# Review key management posture from a config file
cryptologik review-key-posture --config key-management-policy.yaml

# Run a smart contract review checklist
cryptologik review-contract-checklist --contract ./contracts/MyToken.sol

# Generate a combined report
cryptologik generate-report --assessment-dir ./output --format markdown
```

---

## Key Capabilities

### Cryptographic Configuration Validation

Detects common cryptographic anti-patterns in source code:

| Finding | Risk | Example |
|---------|------|---------|
| MD5 usage | High | `hashlib.md5(data)` in security context |
| SHA-1 usage | High | `SHA1` in certificate or signature code |
| DES / 3DES | Critical | Any use |
| RC4 | Critical | Any use |
| AES-ECB mode | High | `AES.new(key, AES.MODE_ECB)` |
| Weak PRNG | High | `random.token_hex()` instead of `secrets` |

### TLS Configuration Review

Reviews JSON exports of listener TLS settings without making network calls:

```json
{
  "config_id": "prod-ingress",
  "cipher_suites": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
  "tls_versions": ["TLSv1.3"],
  "description": "production ingress listener"
}
```

The `review-tls-config` command grades each config and flags NULL/anonymous suites, RC4, DES/3DES, export-grade ciphers, missing AEAD, deprecated SSL/TLS protocol versions, and missing forward secrecy. Use `--fail-on high` or `--fail-on critical` for CI gates.

### Smart Contract Review (SWC-aligned)

Covers the most critical SWC entries:

- SWC-107: Reentrancy
- SWC-101: Integer Overflow/Underflow
- SWC-105: Unprotected Ether Withdrawal
- SWC-115: Authorization via tx.origin
- SWC-120: Weak Randomness from Chain Attributes
- And more (see `blockchain/swc_mappings/swc_reference.yaml`)

### Key Management Posture

Reviews key management configurations for:
- Rotation policy (is rotation defined and enforced?)
- Storage location (secrets manager vs. plaintext file vs. environment variable)
- Access control (principle of least privilege on key access)
- Lifecycle documentation (creation, rotation, revocation procedures)

### TLS Certificate Chain Validation

Reviews structured certificate metadata without making live network connections:

| Check | Risk | Description |
|-------|------|-------------|
| TLS-CV-001 | High | Weak certificate signature algorithms such as MD5 or SHA-1 |
| TLS-CV-002 | Critical/High | Expired or not-yet-valid certificates |
| TLS-CV-005 | High | Missing intermediate certificates in a presented chain |
| TLS-CV-008 | High | RSA keys below 2048 bits or EC keys below 256 bits |
| TLS-CV-009 | Medium | Leaf certificates with validity periods above 398 days |

---

## Configuration

Runtime behavior is controlled via `.env` (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `ASSESSMENT_PROFILE` | `standard` | Assessment depth profile |
| `TARGET_CATEGORY` | `crypto_config` | What to assess |
| `FRAMEWORK_MODE` | `swc` | Smart contract framework (swc, scsvs, both) |
| `STRICTNESS` | `standard` | Finding threshold (minimal/standard/strict) |
| `OUTPUT_DIR` | `./output` | Output directory for reports |

---

## Security

Please report vulnerabilities via the process described in [SECURITY.md](SECURITY.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

CC BY 4.0 — see [LICENSE](LICENSE). Free to use, share, and adapt with attribution to **Hiago Kin Levi**.

# cryptologik

**Cryptographic security validation, key management posture review, smart contract analysis, and blockchain security baselines.**

---

## Overview

`cryptologik` is a defensive security toolkit for cryptographic and blockchain system reviews. It provides:

- **Cryptographic configuration validation** — static analysis for deprecated algorithms, weak key sizes, ECB mode, and insecure PRNGs
- **Key management posture review** — checks for rotation policies, storage hygiene, and access controls
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

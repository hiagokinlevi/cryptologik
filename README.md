# cryptologik

**Cryptographic security validation, protocol and key-lifecycle review, blockchain security governance, crypto agility assessment, and post-quantum readiness planning.**

---

## Overview

`cryptologik` is a defensive security toolkit for cryptographic and blockchain system reviews. It provides:

- **Cryptographic configuration validation** — static analysis for deprecated algorithms, weak key sizes, ECB mode, insecure PRNGs, and language-specific anti-patterns in Python, Java, Go, and JavaScript/TypeScript
- **TLS configuration review** — offline cipher suite and protocol version analysis for listener configs
- **Key management posture review** — checks for rotation policies, storage hygiene, and access controls
- **TLS certificate chain validation** — offline review for weak signatures, incomplete chains, hostname/SAN drift, weak keys, expiry risk, and long-lived leaf certificates
- **Smart contract review tooling** — SWC-mapped checklists for Solidity security review
- **Blockchain security baselines** — wallet security checklists and custody operational guides
- **Crypto agility assessment** — evaluates algorithm coupling, migration complexity, and policy readiness for future transitions
- **Post-quantum readiness assessment** — scores inventory maturity, hybrid readiness, long-term confidentiality exposure, and migration urgency
- **Hybrid migration planning** — builds wave-based migration plans for assets with classical dependencies and future confidentiality requirements
- **Policy baselines** — YAML-defined cryptographic baseline policies for org-wide enforcement
- **Pydantic schemas** — machine-readable finding models for findings, crypto agility, post-quantum readiness, and migration plans
- **CLI tooling** — review, assess, and report from the terminal, including SARIF export for CI and IDE pipelines

This tool is for **defensive use** — it helps security engineers, auditors, and developers identify and remediate cryptographic weaknesses.

---

## Repository Structure

```
cryptologik/
├── crypto/
│   ├── validators/         # Cryptographic config static analysis
│   └── key_management/     # Key management posture checks
├── analyzers/
│   ├── risk_modeling/      # Crypto agility and prioritization logic
│   ├── pqc_readiness/      # Post-quantum readiness scoring
│   └── migration_prioritization/  # Wave-based migration planning
├── blockchain/
│   ├── smart_contracts/    # Smart contract review checklists
│   ├── swc_mappings/       # SWC registry reference (YAML)
│   ├── wallets/            # Wallet security checklists
│   └── custody/            # Custody security guides
├── policies/
│   ├── crypto-baselines/   # Cryptographic baseline policy files
│   ├── crypto-agility/     # Agility scoring profiles
│   └── post-quantum-migration/  # PQC readiness and transition profiles
├── schemas/                # Pydantic finding models
├── reports/                # Report generator
├── cli/                    # Click CLI entrypoint
├── docs/                   # Architecture and model documentation
├── examples/               # Synthetic inventories and migration inputs
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
cryptologik review-crypto-config --path ./src --strictness standard --output crypto-findings.json

# Review offline TLS listener configuration
cryptologik review-tls-config --config tls-config.json --output tls-results.json

# Review key management posture from a config file
cryptologik review-key-posture --config key-management-policy.yaml

# Run a smart contract review checklist
cryptologik review-contract-checklist --contract ./contracts/MyToken.sol

# Evaluate crypto agility and algorithm coupling
cryptologik assess-crypto-agility --config examples/sample-configs/advanced-crypto-program.yaml

# Evaluate post-quantum readiness and long-term confidentiality exposure
cryptologik assess-pqc-readiness --config examples/sample-configs/advanced-crypto-program.yaml

# Generate a migration wave plan
cryptologik generate-migration-plan --config examples/sample-configs/advanced-crypto-program.yaml

# Generate a combined report
cryptologik generate-report --findings-json ./output/findings.json --format markdown

# Export SARIF for GitHub code scanning or IDE ingestion
cryptologik generate-report --findings-json ./output/findings.json --format sarif --output cryptologik.sarif
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
| Weak PRNG | High | `random` or `Math.random()` near key/token/secret generation |
| Java JCA/JCE misuse | High | `MessageDigest.getInstance("MD5")`, `SHA1PRNG`, `SHA1withRSA` |
| Go crypto/tls misconfig | High/Critical | `MinVersion: tls.VersionTLS10`, `InsecureSkipVerify: true` |
| Node.js crypto anti-patterns | High/Critical | `createCipher()`, `createHash("md5")`, weak PBKDF2 iterations |

The `review-crypto-config` command supports `--strictness minimal|standard|strict` so teams can use the same scanner for local review, CI baselines, or broader audit passes.

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

### Crypto Agility and Post-Quantum Readiness

The advanced assessment layer uses an offline inventory of cryptographic assets
to answer planning questions that static code analysis cannot:

| Output | Purpose |
|--------|---------|
| `crypto_agility_score` | How flexibly the environment can replace algorithms, policies, and dependencies |
| `migration_complexity_score` | How much coordination and operational effort migration will require |
| `algorithm_coupling_index` | How tightly algorithm choice is embedded in code, workflows, or suppliers |
| `post_quantum_readiness_score` | How prepared the target is for quantum-safe transition planning |
| `long_term_confidentiality_risk` | Whether archived or long-lived data requires earlier transition treatment |
| `migration_wave` | Suggested rollout wave for hybrid or post-quantum migration |

The sample profile in [examples/sample-configs/advanced-crypto-program.yaml](examples/sample-configs/advanced-crypto-program.yaml)
demonstrates how to inventory dependencies, long-term confidentiality needs,
supplier blockers, and hybrid support readiness.

### TLS Certificate Chain Validation

Reviews structured certificate metadata without making live network connections:

| Check | Risk | Description |
|-------|------|-------------|
| TLS-CV-001 | High | Weak certificate signature algorithms such as MD5 or SHA-1 |
| TLS-CV-002 | Critical/High | Expired or not-yet-valid certificates |
| TLS-CV-005 | High | Missing intermediate certificates in a presented chain |
| TLS-CV-008 | High | RSA keys below 2048 bits or EC keys below 256 bits |
| TLS-CV-009 | Medium | Leaf certificates with validity periods above 398 days |

### Reporting and CI Export

`generate-report` can transform scanner findings into:

- Markdown for human-readable reviews and remediation tracking
- JSON for machine-readable post-processing
- SARIF 2.1.0 for GitHub code scanning, IDE diagnostics, and CI/CD security pipelines

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
| `MIGRATION_PROFILE` | `foundation` | Migration or readiness baseline profile |

---

## Advanced Models

- [Crypto Agility Model](docs/crypto-agility-model.md)
- [Post-Quantum Model](docs/post-quantum-model.md)

---

## Security

Please report vulnerabilities via the process described in [SECURITY.md](SECURITY.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

CC BY 4.0 — see [LICENSE](LICENSE). Free to use, share, and adapt with attribution to **Hiago Kin Levi**.

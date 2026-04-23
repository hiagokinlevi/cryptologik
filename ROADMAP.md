# Roadmap

---

## v1.1 — Expanded Static Analysis

- [x] Language-specific validators for Java (JCA/JCE misuse), Go (crypto/tls misconfigs), JavaScript (node:crypto anti-patterns)
- [x] TLS configuration scanner (cipher suite analysis, protocol version checks)
- [x] Certificate chain validation tooling with weak signature, incomplete chain, hostname/SAN, weak key, expiry, and long-lived leaf-certificate checks
- [ ] PKCS#11 / HSM integration posture checks

## v1.2 — Smart Contract Coverage

- [ ] Full SWC registry coverage (all 37 entries)
- [ ] SCSVS (Smart Contract Security Verification Standard) mapping
- [ ] Solidity version detection and upgrade recommendations
- [ ] ERC-20 / ERC-721 standard compliance checks
- [ ] Gas optimization notes alongside security findings

## v1.3 — Key Management Automation

- [ ] AWS KMS policy posture checker
- [ ] Azure Key Vault access policy auditor
- [ ] HashiCorp Vault audit log analyzer
- [ ] Key rotation age checker with alerting

## v1.4 — Reporting Enhancements

- [ ] HTML report generation with risk heat maps
- [ ] PDF export
- [x] SARIF output format for IDE and CI/CD integration
- [ ] CycloneDX cryptographic bill of materials (CBOM) output

## v1.5 — Agility and PQC Foundations

- [x] Crypto agility assessment with `crypto_agility_score`, `migration_complexity_score`, and `algorithm_coupling_index`
- [x] Post-quantum readiness assessment with `post_quantum_readiness_score`, `future_exposure_risk`, and `long_term_confidentiality_risk`
- [x] Wave-based hybrid migration planner for inventory-driven roadmaps
- [x] YAML policy profiles for crypto agility and post-quantum migration
- [x] Synthetic advanced inventory example and training tutorial

## v1.6 — Protocol and Long-Term Risk

- [ ] Protocol security review engine for

## Automated Completions
- [x] Ship a default crypto baseline policy file for CI usage (cycle 28)

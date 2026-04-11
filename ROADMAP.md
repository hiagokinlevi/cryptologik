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

- [ ] Protocol security review engine for handshake, downgrade, and trust-boundary analysis
- [ ] Long-term confidentiality report generator with retention-aware prioritization
- [ ] Quantum-safe executive summary report template
- [ ] Environment-aware migration baselines (dev, staging, production, regulated)

## v2.0 — Continuous Monitoring

- [ ] GitHub Actions integration for PR-level crypto review
- [ ] Pre-commit hook for developer-time crypto scanning
- [ ] Policy-as-code enforcement (fail CI if critical findings exceed threshold)
- [ ] Trend dashboard (finding counts over time per codebase)

---

## Completed

- [x] Cryptographic configuration validator (MD5, SHA-1, DES, RC4, ECB, weak PRNG)
- [x] Language-aware crypto validator coverage for Java, Go, and JavaScript/TypeScript
- [x] Key management posture checker
- [x] Smart contract review checklist with SWC mappings
- [x] SWC reference YAML (selected critical entries)
- [x] Wallet security checklist
- [x] Custody security guide
- [x] Standard cryptographic baseline policy
- [x] Pydantic finding schemas
- [x] Markdown report generator
- [x] Click CLI (review-crypto-config, review-key-posture, review-contract-checklist, generate-report)
- [x] Offline TLS configuration scanner with CI fail thresholds
- [x] Advanced CLI workflows for crypto agility, post-quantum readiness, and migration planning

---

Community suggestions are welcome via GitHub Discussions.

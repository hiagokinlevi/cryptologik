# Roadmap

---

## v1.1 — Expanded Static Analysis

- [ ] Language-specific validators for Java (JCA/JCE misuse), Go (crypto/tls misconfigs), JavaScript (node:crypto anti-patterns)
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
- [ ] SARIF output format for IDE and CI/CD integration
- [ ] CycloneDX cryptographic bill of materials (CBOM) output

## v2.0 — Continuous Monitoring

- [ ] GitHub Actions integration for PR-level crypto review
- [ ] Pre-commit hook for developer-time crypto scanning
- [ ] Policy-as-code enforcement (fail CI if critical findings exceed threshold)
- [ ] Trend dashboard (finding counts over time per codebase)

---

## Completed

- [x] Cryptographic configuration validator (MD5, SHA-1, DES, RC4, ECB, weak PRNG)
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

---

Community suggestions are welcome via GitHub Discussions.

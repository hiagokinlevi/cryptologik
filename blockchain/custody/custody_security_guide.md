# Custody Security Operations Guide

**Audience:** Operations teams and security engineers managing institutional cryptocurrency custody
**Scope:** Operational security controls for self-custody and qualified custodian environments

---

## Overview

Custody security refers to the policies, processes, and controls that govern how private key material is stored, protected, and used to authorize transactions. Poor custody security is among the most common causes of large cryptocurrency losses — including exchange hacks, DeFi exploits, and internal theft.

This guide covers defensive controls for institutional custody environments. It does not substitute for a professional custody security assessment.

---

## 1. Cold Storage Controls

### Definition
Cold storage refers to private keys that are never exposed to internet-connected systems. Cold storage is the highest security tier for long-term holdings.

### Required Controls

**Key generation:**
- Generate private keys on air-gapped hardware (never networked)
- Use cryptographically verified random number generation (hardware RNG or audited software)
- Document the generation ceremony: date, participants, hardware used, entropy source

**Key storage:**
- Store seed backups in physical form (paper + steel plate for disaster recovery)
- Use geographically distributed backups (minimum 2 locations, ideally 3)
- Store in access-controlled physical security (safe, vault, safe deposit box with multi-person access)
- Consider Shamir's Secret Sharing (SSS) to split seed among multiple parties — no single party holds the full secret

**Key access:**
- Access to cold storage should require multiple authorized individuals (dual control principle)
- Log every access event: who, when, purpose, witness
- Access should be documented in a secure ledger

**Signing ceremonies:**
- Conduct signing ceremonies on air-gapped hardware in a secure physical environment
- Require a quorum of authorized signers for any cold storage transaction
- Verify transaction details on secure hardware (not on a networked display)
- Document all signing ceremonies

---

## 2. Warm / Operational Wallet Controls

### Definition
Warm wallets are used for operational liquidity — transactions that must be processed within hours rather than days. They accept higher security risk in exchange for operational efficiency.

### Required Controls

- Store only the minimum operational balance needed (e.g., 1–7 days of operational flow)
- Use hardware security modules (HSMs) for private key storage — never store in plaintext
- Implement transaction approval workflows: large transfers above a threshold require multiple approvals
- Use multi-signature wallets (M-of-N) where the hot wallet infrastructure signs as one of N required signers
- Monitor wallet balances and transactions with real-time alerting
- Define balance thresholds that trigger automatic refill from cold storage (with human approval)

---

## 3. HSM (Hardware Security Module) Requirements

HSMs provide tamper-resistant key storage and cryptographic operations without exposing key material.

**Selection criteria:**
- FIPS 140-2 Level 3 or higher for custody-grade key protection
- Certified by a recognized lab (not self-certified)
- Supports key ceremony documentation (quorum-based initialization)
- Audit log capability — all key operations logged to tamper-evident storage

**Operational requirements:**
- HSMs should be initialized with a quorum of key custodians present
- Backup key shares should be distributed to separate custodians
- HSM firmware must be on the latest vendor-released version
- Physical access to HSM hardware must be logged and restricted

---

## 4. Multi-Party Authorization (MPA / MPC)

### Multi-Signature Wallets

Multi-signature wallets require M-of-N key holders to authorize a transaction. Example: 3-of-5 means any 3 of 5 designated signers must sign.

**Configuration guidance:**
- Production custody: minimum 2-of-3 for daily operations; 3-of-5 or higher for cold storage
- Never configure 1-of-N (single point of failure) for organizational funds above a low operational threshold
- Distribute key holders across roles (not all in the same team) and locations
- Ensure the N is survivable: if 2 signers are unavailable simultaneously, can you still operate?

### Multi-Party Computation (MPC)

MPC custody splits the private key into shares that are never assembled in one location. Threshold signatures allow transaction signing without ever reconstructing the full key.

**Advantages over traditional multi-sig:**
- No on-chain exposure of multi-sig structure (chain privacy)
- More flexible threshold configurations
- Compatible with chains that don't natively support multi-sig

**Considerations:**
- MPC implementations vary in security maturity — audit the specific implementation
- Key share refresh should be performed regularly to mitigate long-term accumulation of share exposure

---

## 5. Transaction Authorization Policy

Define and document the following:

| Transaction Size | Required Authorization |
|---|---|
| < $10,000 | Single authorized operator |
| $10,000 – $100,000 | 2-of-N approval required |
| > $100,000 | 3-of-N approval + management notification |
| > $1,000,000 | Board or executive approval + compliance review |

- Allowlist known destination addresses — unauthorized destinations require elevated approval
- Implement mandatory time delays on large outbound transactions (e.g., 24h delay on transfers > $500K)
- Notify all authorized parties via out-of-band channel (not just in-app) for large transactions

---

## 6. Incident Response for Custody Events

### Suspected Compromise

If a custody key may be compromised:

1. **Immediately sweep funds** from the potentially compromised wallet to a freshly generated, clean wallet
2. **Do not use the suspect key** for any further operations
3. **Preserve forensic evidence** of how the key may have been accessed
4. **Notify appropriate parties**: legal, compliance, affected customers
5. **Conduct a full key ceremony** to generate and enroll replacement keys

### Lost Key Share (for MPC or multi-sig)

1. Convene remaining key holders
2. Conduct a key share refresh or new key generation ceremony with a quorum
3. Re-enroll replacement shares to new custodians
4. Document the recovery and update key holder registry

---

## 7. Compliance and Audit Controls

- Maintain an immutable transaction ledger for all custody wallet activity
- Conduct annual third-party security audits of custody processes and infrastructure
- Implement SOC 2 Type II controls for institutional custody operations
- Ensure custody operations comply with applicable regulations (e.g., NYDFS BitLicense, MiCA, SEC guidance)
- Retain transaction and signing ceremony records per legal hold requirements

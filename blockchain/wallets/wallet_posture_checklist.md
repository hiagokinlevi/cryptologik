# Wallet Security Posture Checklist

**Audience:** Security engineers, blockchain developers, and operations teams managing cryptocurrency wallets
**Purpose:** Defensive review of wallet security posture for organizational or high-value individual wallets

---

## Seed Phrase / Mnemonic Security

- [ ] **Offline generation:** Was the seed phrase generated on an air-gapped, never-networked device?
- [ ] **No digital copy:** Is the seed phrase stored ONLY in physical form (paper, steel)? Not in any digital format.
- [ ] **Physical security:** Is the physical seed backup stored in a secure, access-controlled location (safe, safe deposit box)?
- [ ] **Redundancy:** Are there at least two physically separate copies of the seed backup (to protect against loss)?
- [ ] **No photographs:** Was the seed phrase ever photographed? (If yes, consider this seed compromised)
- [ ] **No typed in browser:** Was the seed phrase ever entered on a web page, extension popup, or any form? (If yes, consider compromised)
- [ ] **Single-purpose device:** Was the seed ever generated or entered on a device used for general internet browsing? (High risk if yes)

---

## Hardware Wallet Controls

- [ ] **Hardware wallet used:** Is a hardware wallet (Ledger, Trezor, Coldcard) used for significant holdings?
- [ ] **Firmware up to date:** Is the hardware wallet firmware on the latest verified release?
- [ ] **Purchased from official source:** Was the device purchased directly from the manufacturer (not third-party reseller)? Check for tampering.
- [ ] **PIN protection enabled:** Is a strong PIN (not 1234, 0000) set on the hardware wallet?
- [ ] **Passphrase (25th word):** For high-value wallets, is an additional BIP39 passphrase (25th word) used and stored separately from the seed?
- [ ] **Recovery tested:** Has the wallet recovery been tested end-to-end with the seed backup? (Verify before storing significant funds)

---

## Hot Wallet and Software Wallet Controls

- [ ] **Minimal funds in hot wallet:** Are hot wallets holding only operational minimum (not long-term storage)?
- [ ] **Dedicated device:** Is the hot wallet running on a dedicated device not used for general browsing or email?
- [ ] **OS hardened:** Is the operating system hardened, patched, and running endpoint security?
- [ ] **No browser extensions with wallet permissions:** Are browser extensions audited? Malicious extensions are a leading cause of hot wallet theft.
- [ ] **Private keys encrypted at rest:** Are private key files stored with strong encryption (not plaintext)?

---

## Multi-Signature Controls

- [ ] **Multi-sig for organizational funds:** Are organizational funds protected by multi-signature wallet (M-of-N)?
- [ ] **Key distribution:** Are signing keys distributed across different individuals and/or geographic locations?
- [ ] **Key holder documentation:** Are all key holders documented in a secure registry?
- [ ] **Recovery procedure documented:** Is there a documented recovery procedure if one key holder is unavailable?
- [ ] **Regular quorum test:** Is the ability to sign transactions tested regularly (at least annually)?

---

## Transaction Security

- [ ] **Verify on-device:** For hardware wallet transactions, is the destination address always verified on the hardware wallet screen (not just the computer)?
- [ ] **Address poisoning awareness:** Are team members trained to verify full addresses (not just first/last characters)? Clipboard hijacking and address poisoning are common attacks.
- [ ] **Allowlist trusted addresses:** For operational wallets, are destination addresses verified against a pre-approved allowlist where possible?
- [ ] **Test transaction first:** For large transfers to new addresses, is a small test transaction sent and confirmed first?

---

## Access and Authentication

- [ ] **Access restricted:** Is wallet access restricted to the minimum required individuals?
- [ ] **Access review:** Is wallet access reviewed quarterly (or when personnel change)?
- [ ] **Activity monitoring:** Are wallet transactions monitored for anomalous activity (unexpected sends, large transfers)?
- [ ] **Incident response:** Is there a documented procedure for responding to suspected wallet compromise?

---

## Key Lifecycle

- [ ] **Creation documented:** Is the creation date, generation method, and responsible party documented for each wallet?
- [ ] **Succession planning:** If a key holder leaves the organization, is there a process to rotate to a new key?
- [ ] **Decommission procedure:** Is there a procedure for safely decommissioning a wallet (sweeping funds, destroying seed)?

---

## Scoring

Count checked items per section. Priority areas:

| Section | Risk if Incomplete |
|---|---|
| Seed Phrase / Mnemonic | Critical — fund loss risk |
| Hardware Wallet Controls | High |
| Multi-Signature Controls | High for organizational wallets |
| Transaction Security | High — direct theft vector |
| Hot Wallet Controls | Medium (depends on fund value) |
| Access and Authentication | Medium |
| Key Lifecycle | Low-Medium |

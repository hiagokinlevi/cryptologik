# Blockchain Security Model

## Overview

Blockchain and smart contract security differs from traditional application security in several important ways:

1. **Immutability:** Deployed smart contracts cannot be updated without a proxy pattern or full redeployment. Bugs are permanent unless upgrade paths are designed in advance.
2. **Public code:** Most smart contracts are verified and publicly readable on-chain. Attackers can study the code before attacking.
3. **Adversarial economic incentives:** DeFi contracts control real monetary value, creating strong financial motivation for attackers.
4. **Irreversibility:** On-chain transactions are final. There is no "undo" for a successful exploit.
5. **Composability risk:** DeFi protocols interact with each other. A vulnerability in one protocol can cascade to others.

---

## Smart Contract Security Layers

### Layer 1: Code Correctness

Does the contract code do what it is intended to do?

Key checks:
- Integer arithmetic correctness (overflow/underflow — SWC-101)
- Access control on all privileged functions (SWC-105)
- Correct reentrancy guards (SWC-107)
- Safe use of external calls

### Layer 2: Cryptographic and Randomness Security

Does the contract use secure sources of randomness and cryptographic constructs?

Key checks:
- No reliance on block attributes for randomness (SWC-120)
- Correct use of signatures and verification
- Replay protection in signature schemes (domain separation, nonces)

### Layer 3: Authorization and Access Control

Are privileged operations correctly restricted?

Key checks:
- No tx.origin authorization (SWC-115)
- Role-based access control correctly implemented
- Multi-sig or timelock on admin functions in high-value contracts
- Emergency pause mechanisms appropriately protected

### Layer 4: Economic Security

Are there economic attack vectors even if the code is correct?

Key checks:
- Flash loan attack surface: can an attacker manipulate prices or state with a flash loan?
- Oracle manipulation: are price feeds from decentralized oracles (TWAP, Chainlink)?
- MEV (Miner Extractable Value) exposure: can transactions be front-run?
- Governance attack: can a large token holder pass malicious governance proposals?

---

## SWC Registry Overview

The Smart Contract Weakness Classification (SWC) is the standard weakness taxonomy for Ethereum smart contracts. Key entries covered by this tool:

| SWC ID | Title | Severity |
|---|---|---|
| SWC-100 | Function Default Visibility | Medium |
| SWC-101 | Integer Overflow and Underflow | High |
| SWC-103 | Floating Pragma | Low |
| SWC-104 | Unchecked Call Return Value | Medium |
| SWC-105 | Unprotected Ether Withdrawal | Critical |
| SWC-106 | Unprotected SELFDESTRUCT | Critical |
| SWC-107 | Reentrancy | Critical |
| SWC-110 | Assert Violation | Medium |
| SWC-115 | Authorization Through tx.origin | High |
| SWC-119 | Shadowing State Variables | Medium |
| SWC-120 | Weak Randomness | High |
| SWC-124 | Write to Arbitrary Storage | Critical |
| SWC-125 | Incorrect Inheritance Order | Medium |
| SWC-127 | Arbitrary Jump | Critical |

Full registry: https://swcregistry.io/

---

## Wallet Security Threat Model

### Threat: Seed Phrase Exposure
**Attack vectors:** Phishing, malware (keyloggers, clipboard hijacking), social engineering, insecure backup
**Defensive controls:** Offline generation, air-gapped device, physical-only backup, hardware wallet

### Threat: Hot Wallet Compromise
**Attack vectors:** Malware on the signing device, malicious browser extensions, supply chain attacks on wallet software
**Defensive controls:** Dedicated signing device, minimal funds in hot wallet, transaction allowlisting

### Threat: Transaction Manipulation
**Attack vectors:** Clipboard hijacking (malware substitutes destination address), address poisoning (similar-looking attacker address)
**Defensive controls:** On-device address verification (hardware wallet), test transactions, address allowlisting

### Threat: Insider Threat (Organizational Wallets)
**Attack vectors:** Malicious insider with key access, social engineering of key holders
**Defensive controls:** Multi-signature (M-of-N), key distribution across multiple individuals, dual control for signing ceremonies

### Threat: Custodian Compromise
**Attack vectors:** Custodian infrastructure breach, rogue custodian employee
**Defensive controls:** Multi-party computation (MPC), distributed key shares, independent audit

---

## Blockchain Security Review Process

For a comprehensive blockchain security review, combine this tool's automated checks with:

1. **Manual code review** by a qualified smart contract auditor
2. **Formal verification** (Certora Prover, Echidna, Foundry invariant testing)
3. **Economic/protocol design review** for DeFi protocols
4. **Dependency audit** of all imported libraries (OpenZeppelin version, forks)
5. **Integration testing** against mainnet forks
6. **Bug bounty program** for economic validation

No automated tool, including cryptologik, can substitute for manual audit by qualified smart contract security researchers.

# cryptologik — Architecture Overview

## Purpose

`cryptologik` is a defensive security toolkit for reviewing cryptographic configurations, key management posture, and blockchain security. It is designed for security engineers, auditors, and developers who need to systematically identify and remediate cryptographic weaknesses.

## Design Principles

**1. Defensive-only:** All content and tooling is oriented toward finding and fixing weaknesses. This tool does not assist in exploitation.

**2. Accurate risk calibration:** Finding severities are calibrated against real-world exploitability. Every detection pattern documents its false positive risk so reviewers can make informed decisions.

**3. Composable:** Components work independently. Run only the validators you need without requiring the full tool.

**4. Transparent limitations:** Static analysis has fundamental limits. Every output includes disclaimer language about what the tool cannot detect.

## Component Map

```
┌────────────────────────────────────────────────────────────┐
│                       CLI (click)                          │
│  review-crypto-config  review-key-posture                  │
│  review-contract-checklist  generate-report                │
└──────────────────────┬─────────────────────────────────────┘
                       │
       ┌───────────────┼──────────────────┐
       ▼               ▼                  ▼
┌────────────┐  ┌────────────┐   ┌─────────────────┐
│   crypto/  │  │blockchain/ │   │    schemas/     │
│ validators │  │  smart_    │   │ crypto_finding  │
│ key_mgmt   │  │  contracts │   │ AssessmentSum   │
└────────────┘  │  swc_maps  │   └─────────────────┘
                │  wallets   │          │
                │  custody   │          ▼
                └────────────┘   ┌─────────────┐
                                 │   reports/  │
                                 │  generator  │
                                 └─────────────┘
       │
       ▼
┌────────────────────────────────────────────────────────────┐
│                     policies/                              │
│              crypto-baselines/standard.yaml                │
└────────────────────────────────────────────────────────────┘
```

## Data Flow

1. The user runs a CLI review command against a target (source files, YAML config, Solidity contract).
2. The appropriate validator or checker produces a list of finding objects (dataclasses or Pydantic models).
3. Findings are optionally written to JSON for downstream processing.
4. The report generator consumes an `AssessmentSummary` to produce a structured Markdown report.

## Scope of Analysis

| Capability | Method | Limitations |
|---|---|---|
| Crypto config validation | Regex pattern matching | Static only; cannot detect runtime behavior |
| Key management posture | YAML config review | Config-based; does not connect to live systems |
| Smart contract review | Regex + checklist | Heuristic; formal verification not included |
| Wallet security | Checklist (manual) | Requires operator input |
| Custody security | Guidance (manual) | Process-level; no automated checks |

## Security Considerations

- This tool processes source code and configuration files. Handle tool output with the same access controls as the scanned code.
- Evidence fields in findings are truncated to avoid storing sensitive code excerpts at length.
- Reports should be distributed only to authorized personnel.
- The tool never connects to live systems (no AWS, Azure, or blockchain RPC calls) unless explicitly extended.

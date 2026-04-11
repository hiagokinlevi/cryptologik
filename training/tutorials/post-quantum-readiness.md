# Post-Quantum Readiness Tutorial

This tutorial introduces the defensive workflow now available in `cryptologik` for post-quantum planning.

## Goal

Build a first migration view without touching live systems:

1. inventory representative assets;
2. identify classical public-key dependencies;
3. mark systems with long-term confidentiality requirements;
4. note blockers, suppliers, and missing runbooks;
5. generate readiness and migration outputs from the CLI.

## Suggested flow

```bash
cryptologik assess-crypto-agility --config examples/sample-configs/advanced-crypto-program.yaml
cryptologik assess-pqc-readiness --config examples/sample-configs/advanced-crypto-program.yaml
cryptologik generate-migration-plan --config examples/sample-configs/advanced-crypto-program.yaml
```

## What to look for

- low agility with high coupling means architecture work should start before algorithm migration;
- high long-term confidentiality risk usually deserves an earlier migration wave;
- third-party dependency blockers should be treated as program risks, not only technical notes.

## Operational caution

The sample inventory is synthetic. Keep real identifiers, trust boundaries, and supplier constraints masked or abstracted before sharing results outside authorized teams.

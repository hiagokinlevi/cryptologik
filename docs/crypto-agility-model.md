# Crypto Agility Model

`cryptologik` treats crypto agility as an engineering and governance property, not just a future architecture concern.

The model used in this repository reviews:

- algorithm abstraction and policy decoupling;
- versioned cryptographic baselines;
- dual-stack or hybrid support for staged transitions;
- lifecycle automation for keys and certificates;
- migration runbooks and rollback criteria;
- third-party dependencies that constrain algorithm changes;
- blockers that increase migration complexity.

The current implementation is intentionally offline and inventory-driven. It is meant to support design reviews, roadmap planning, and maturity conversations before runtime validation is introduced.

## Current outputs

The initial advanced cycle produces:

- `crypto_agility_score`
- `migration_complexity_score`
- `algorithm_coupling_index`
- `legacy_algorithm_dependency`
- prioritized recommended actions

## Interpretation

- High agility score: the environment can change algorithms and policies with limited disruption.
- High migration complexity: the target can probably improve, but the transition needs careful sequencing.
- High coupling index: algorithm choices are too embedded in code paths, dependencies, or operational workflows.

## Safe-use note

These outputs are advisory and defensive. They do not validate runtime interoperability or certify post-quantum safety by themselves.

# Post-Quantum Model

The post-quantum model in `cryptologik` is a readiness and prioritization layer. It does not implement or benchmark quantum-safe cryptography. Instead, it helps teams answer the operational questions that usually block transition planning:

- what depends on classical public-key trust today;
- which assets need confidentiality for many years;
- where hybrid transition will likely be required;
- which systems lack inventory, runbooks, or supplier readiness;
- how to group migration into defensible waves.

## Current outputs

The initial readiness workflow produces:

- `post_quantum_readiness_score`
- `future_exposure_risk`
- `long_term_confidentiality_risk`
- `hybrid_transition_priority`
- `migration_wave`
- `quantum_transition_status`

## Priority model

- Wave 1: urgent preparation, usually tied to high criticality or long-lived confidentiality.
- Wave 2: planning required, with blockers or missing hybrid support.
- Wave 3: baseline-ready but still requiring periodic reassessment.
- Wave 4: monitor and refine while supplier and interoperability assumptions mature.

## Scope boundary

This model is purposely governance-first. It supports safe planning, documentation, and prioritization without turning the repository into an offensive or experimental cryptography lab.

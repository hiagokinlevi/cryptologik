from analyzers.pqc_readiness.readiness_assessor import assess_pqc_readiness
from schemas.advanced_assessment import CryptoAssetProfile


def test_assess_pqc_readiness_prioritizes_long_term_confidentiality():
    assets = [
        CryptoAssetProfile(
            asset_id="archive",
            asset_name="archive",
            asset_type="archive",
            business_criticality="high",
            algorithm_abstraction=True,
            versioned_policies=True,
            dual_stack_support=False,
            hybrid_ready=False,
            pq_inventory_complete=False,
            migration_runbook=False,
            key_lifecycle_automation=False,
            classical_public_key_dependency=True,
            long_term_confidentiality=True,
            data_retention_years=12,
        )
    ]

    result = assess_pqc_readiness(assets, target_name="demo")

    assert result.post_quantum_readiness_score < 60
    assert result.long_term_confidentiality_risk in {"high", "critical"} or result.long_term_confidentiality_risk.value in {"high", "critical"}
    assert result.hybrid_transition_priority == "high"
    assert result.migration_wave == 1


def test_assess_pqc_readiness_marks_ready_profiles_more_favorably():
    assets = [
        CryptoAssetProfile(
            asset_id="gateway",
            asset_name="gateway",
            asset_type="gateway",
            business_criticality="medium",
            algorithm_abstraction=True,
            versioned_policies=True,
            dual_stack_support=True,
            hybrid_ready=True,
            pq_inventory_complete=True,
            migration_runbook=True,
            key_lifecycle_automation=True,
            classical_public_key_dependency=True,
            long_term_confidentiality=False,
            data_retention_years=2,
        )
    ]

    result = assess_pqc_readiness(assets, target_name="demo")

    assert result.post_quantum_readiness_score >= 75
    assert result.migration_wave >= 3

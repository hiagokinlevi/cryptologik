from analyzers.risk_modeling.crypto_agility_assessor import assess_crypto_agility
from schemas.advanced_assessment import CryptoAssetProfile


def test_assess_crypto_agility_flags_low_agility_for_coupled_assets():
    assets = [
        CryptoAssetProfile(
            asset_id="edge-api",
            asset_name="edge-api",
            asset_type="api",
            business_criticality="critical",
            hardcoded_algorithm_dependencies=["RSA-2048", "SHA-1"],
            algorithm_abstraction=False,
            versioned_policies=False,
            dual_stack_support=False,
            hybrid_ready=False,
            pq_inventory_complete=False,
            migration_runbook=False,
            key_lifecycle_automation=False,
            classical_public_key_dependency=True,
            third_party_dependencies=["legacy-hsm"],
            migration_blockers=["interop"],
        )
    ]

    result = assess_crypto_agility(assets, target_name="demo")

    assert result.target_name == "demo"
    assert result.crypto_agility_score < 50
    assert result.algorithm_coupling_index >= 70
    assert result.legacy_algorithm_dependency is True
    assert result.recommended_actions


def test_assess_crypto_agility_rewards_structured_programs():
    assets = [
        CryptoAssetProfile(
            asset_id="signing-stage",
            asset_name="signing-stage",
            asset_type="service",
            business_criticality="medium",
            algorithm_abstraction=True,
            versioned_policies=True,
            dual_stack_support=True,
            hybrid_ready=True,
            pq_inventory_complete=True,
            migration_runbook=True,
            key_lifecycle_automation=True,
            classical_public_key_dependency=True,
        )
    ]

    result = assess_crypto_agility(assets, target_name="demo")

    assert result.crypto_agility_score >= 80
    assert result.algorithm_coupling_index <= 20
    assert result.migration_complexity_score < 40

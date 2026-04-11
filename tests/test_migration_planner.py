from analyzers.migration_prioritization.planner import (
    generate_migration_plan,
    summarize_long_term_confidentiality,
)
from schemas.advanced_assessment import CryptoAssetProfile


def test_generate_migration_plan_orders_assets_by_priority():
    assets = [
        CryptoAssetProfile(
            asset_id="archive",
            asset_name="archive",
            asset_type="archive",
            business_criticality="high",
            hybrid_ready=False,
            pq_inventory_complete=False,
            migration_runbook=False,
            classical_public_key_dependency=True,
            long_term_confidentiality=True,
            data_retention_years=12,
        ),
        CryptoAssetProfile(
            asset_id="stage",
            asset_name="stage",
            asset_type="service",
            business_criticality="medium",
            hybrid_ready=True,
            pq_inventory_complete=True,
            migration_runbook=True,
            classical_public_key_dependency=True,
            long_term_confidentiality=False,
            data_retention_years=1,
        ),
    ]

    plan = generate_migration_plan(assets)

    assert plan[0].asset_id == "archive"
    assert plan[0].migration_wave == 1
    assert plan[0].hybrid_mode_required is True


def test_summarize_long_term_confidentiality_filters_low_risk_assets():
    assets = [
        CryptoAssetProfile(
            asset_id="archive",
            asset_name="archive",
            asset_type="archive",
            business_criticality="high",
            hybrid_ready=False,
            classical_public_key_dependency=True,
            long_term_confidentiality=True,
            data_retention_years=10,
        ),
        CryptoAssetProfile(
            asset_id="stage",
            asset_name="stage",
            asset_type="service",
            business_criticality="low",
            hybrid_ready=True,
            classical_public_key_dependency=False,
            long_term_confidentiality=False,
            data_retention_years=1,
        ),
    ]

    findings = summarize_long_term_confidentiality(assets)

    assert len(findings) == 1
    assert findings[0].asset_id == "archive"

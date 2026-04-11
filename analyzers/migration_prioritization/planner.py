"""
Planejador de migracao criptografica e quantum-safe.

Gera uma lista priorizada de ativos para migracao em ondas, considerando
criticidade, risco de confidencialidade de longo prazo, preparo hibrido e
bloqueadores operacionais.
"""

from __future__ import annotations

from schemas.advanced_assessment import (
    CryptoAssetProfile,
    LongTermConfidentialityFinding,
    MigrationPlanningItem,
)
from schemas.crypto_finding import RiskLevel


_CRITICALITY_POINTS = {
    "low": 10,
    "medium": 20,
    "high": 30,
    "critical": 40,
}


def _risk_from_points(points: int) -> RiskLevel:
    """Mapeia pontos para uma classificacao simples de risco."""
    if points >= 75:
        return RiskLevel.CRITICAL
    if points >= 55:
        return RiskLevel.HIGH
    if points >= 30:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def generate_migration_plan(assets: list[CryptoAssetProfile]) -> list[MigrationPlanningItem]:
    """
    Gera um plano de migracao por ativo.

    A prioridade sobe quando o ativo e critico, tem requisito de
    confidencialidade de longo prazo, depende fortemente de PKI classica ou
    ainda nao suporta modo hibrido.
    """
    items: list[MigrationPlanningItem] = []

    for asset in assets:
        priority = _CRITICALITY_POINTS[asset.business_criticality.value]
        if asset.long_term_confidentiality:
            priority += 25
        if asset.classical_public_key_dependency:
            priority += 15
        if not asset.hybrid_ready:
            priority += 15
        if not asset.pq_inventory_complete:
            priority += 10
        priority += min(10, len(asset.migration_blockers) * 2)
        priority = min(priority, 100)

        if priority >= 80:
            wave = 1
        elif priority >= 60:
            wave = 2
        elif priority >= 40:
            wave = 3
        else:
            wave = 4

        confidentiality_risk = _risk_from_points(
            (40 if asset.long_term_confidentiality else 0)
            + (20 if asset.data_retention_years >= 7 else 0)
            + (15 if asset.classical_public_key_dependency else 0)
        )

        actions = []
        if not asset.pq_inventory_complete:
            actions.append("Complete PQC dependency inventory for this asset.")
        if not asset.hybrid_ready:
            actions.append("Design a hybrid classical plus post-quantum transition path.")
        if not asset.migration_runbook:
            actions.append("Create and approve a migration runbook with rollback checkpoints.")
        if asset.third_party_dependencies:
            actions.append("Validate supplier roadmap and interoperability constraints.")
        if asset.long_term_confidentiality:
            actions.append("Move this asset into an early confidentiality-protection wave.")
        if not actions:
            actions.append("Keep this asset under periodic reassessment and compatibility testing.")

        items.append(
            MigrationPlanningItem(
                asset_id=asset.asset_id,
                asset_name=asset.asset_name,
                environment=asset.environment,
                business_criticality=asset.business_criticality,
                migration_priority=priority,
                migration_wave=wave,
                hybrid_mode_required=asset.long_term_confidentiality or asset.classical_public_key_dependency,
                long_term_confidentiality_risk=confidentiality_risk,
                blockers=list(asset.migration_blockers),
                recommended_actions=actions,
            )
        )

    items.sort(key=lambda item: (-item.migration_priority, item.asset_name.lower()))
    return items


def summarize_long_term_confidentiality(
    assets: list[CryptoAssetProfile],
) -> list[LongTermConfidentialityFinding]:
    """Resume achados de confidencialidade futura para relatórios executivos."""
    findings: list[LongTermConfidentialityFinding] = []

    for asset in assets:
        points = (
            (40 if asset.long_term_confidentiality else 0)
            + (20 if asset.data_retention_years >= 7 else 0)
            + (15 if asset.classical_public_key_dependency else 0)
            + (15 if not asset.hybrid_ready else 0)
        )
        risk = _risk_from_points(points)
        if risk == RiskLevel.LOW:
            continue

        findings.append(
            LongTermConfidentialityFinding(
                asset_id=asset.asset_id,
                asset_name=asset.asset_name,
                risk_level=risk,
                evidence_summary=(
                    f"Retention={asset.data_retention_years}y, "
                    f"long_term_confidentiality={asset.long_term_confidentiality}, "
                    f"hybrid_ready={asset.hybrid_ready}"
                ),
                recommended_fix=(
                    "Reclassify the asset into a migration wave and validate hybrid controls "
                    "for long-lived confidentiality requirements."
                ),
            )
        )

    return findings

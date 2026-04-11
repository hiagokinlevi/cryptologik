"""
Avaliador de readiness pos-quantica.

Este modulo transforma um inventario sintetico de ativos em uma leitura
defensiva de prontidao para transicao quantum-safe. O foco e governanca,
visibilidade, prioridade e risco de confidencialidade futura.
"""

from __future__ import annotations

from collections import Counter

from schemas.advanced_assessment import CryptoAssetProfile, PostQuantumReadinessResult
from schemas.crypto_finding import RiskLevel


_CRITICALITY_WEIGHT = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _weighted_average(values: list[tuple[int, int]]) -> int:
    """Calcula media ponderada com protecao para inventarios vazios."""
    if not values:
        return 0
    numerator = sum(value * weight for value, weight in values)
    denominator = sum(weight for _, weight in values) or 1
    return round(numerator / denominator)


def _risk_from_exposure(points: int) -> RiskLevel:
    """Traduz pontos de exposicao em nivel de risco."""
    if points >= 70:
        return RiskLevel.CRITICAL
    if points >= 50:
        return RiskLevel.HIGH
    if points >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def assess_pqc_readiness(
    assets: list[CryptoAssetProfile],
    target_name: str = "crypto-program",
) -> PostQuantumReadinessResult:
    """
    Avalia readiness pos-quantica de um conjunto de ativos.

    O score final combina cobertura de inventario, suporte hibrido, risco de
    confidencialidade de longo prazo e dependencias classicas.
    """
    weighted_scores: list[tuple[int, int]] = []
    exposure_points: list[int] = []
    confidentiality_points: list[int] = []
    notes: list[str] = []
    missing_controls: Counter[str] = Counter()

    for asset in assets:
        weight = _CRITICALITY_WEIGHT[asset.business_criticality.value]
        penalty = 0
        asset_exposure = 0
        confidentiality = 0

        if not asset.pq_inventory_complete:
            penalty += 15
            asset_exposure += 15
            missing_controls["Complete a post-quantum inventory of cryptographic dependencies."] += weight

        if asset.classical_public_key_dependency:
            penalty += 15
            asset_exposure += 15
            missing_controls["Map classical public-key dependencies and trust anchors."] += weight

        if not asset.hybrid_ready:
            penalty += 20
            asset_exposure += 20
            missing_controls["Prepare hybrid classical plus post-quantum deployment paths."] += weight

        if asset.third_party_dependencies:
            dependency_penalty = min(10, len(asset.third_party_dependencies) * 3)
            penalty += dependency_penalty
            asset_exposure += dependency_penalty
            missing_controls["Review supplier readiness for quantum-safe transition."] += weight

        if not asset.migration_runbook:
            penalty += 10
            asset_exposure += 10
            missing_controls["Create a migration runbook with rollback and interoperability checkpoints."] += weight

        if asset.long_term_confidentiality:
            penalty += 15
            asset_exposure += 15
            confidentiality += 40
            missing_controls["Prioritize systems with long-term confidentiality requirements into early migration waves."] += weight

        if asset.data_retention_years >= 7:
            penalty += 10
            asset_exposure += 10
            confidentiality += 20

        if asset.migration_blockers:
            blocker_penalty = min(15, len(asset.migration_blockers) * 5)
            penalty += blocker_penalty
            asset_exposure += blocker_penalty
            missing_controls["Track PQC blockers explicitly and assign accountable owners."] += weight

        score = max(0, 100 - penalty)
        weighted_scores.append((score, weight))
        exposure_points.append(asset_exposure)
        confidentiality_points.append(confidentiality)

        if asset.long_term_confidentiality and not asset.hybrid_ready:
            notes.append(
                f"{asset.asset_name} combines long-term confidentiality with no hybrid-ready path."
            )

    readiness_score = _weighted_average(weighted_scores)
    future_exposure_risk = _risk_from_exposure(max(exposure_points, default=0))
    long_term_confidentiality_risk = _risk_from_exposure(max(confidentiality_points, default=0))

    if readiness_score < 50:
        transition_status = "urgent_preparation"
        hybrid_priority = "high"
        migration_wave = 1
    elif readiness_score < 70:
        transition_status = "planning_needed"
        hybrid_priority = "medium"
        migration_wave = 2
    elif readiness_score < 85:
        transition_status = "baseline_ready"
        hybrid_priority = "medium"
        migration_wave = 3
    else:
        transition_status = "monitor_and_refine"
        hybrid_priority = "low"
        migration_wave = 4

    recommendations = [action for action, _ in missing_controls.most_common(5)]
    if not recommendations:
        recommendations.append(
            "Maintain periodic post-quantum readiness reviews and refresh supplier assumptions annually."
        )

    return PostQuantumReadinessResult(
        target_name=target_name,
        assessed_assets=len(assets),
        post_quantum_readiness_score=readiness_score,
        future_exposure_risk=future_exposure_risk,
        long_term_confidentiality_risk=long_term_confidentiality_risk,
        hybrid_transition_priority=hybrid_priority,
        migration_wave=migration_wave,
        quantum_transition_status=transition_status,
        recommended_actions=recommendations,
        analysis_notes=notes,
    )

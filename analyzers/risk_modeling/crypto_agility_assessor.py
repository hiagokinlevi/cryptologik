"""
Avaliador de crypto agility para o CryptoLogik.

Este modulo estima a capacidade de um conjunto de ativos trocar algoritmos,
politicas, bibliotecas e modos de operacao sem ruptura excessiva.

O objetivo e defensivo: identificar acoplamento, dependencias legadas,
fragilidade de migracao e prioridades de desacoplamento.
"""

from __future__ import annotations

from collections import Counter

from schemas.advanced_assessment import CryptoAgilityAssessment, CryptoAssetProfile
from schemas.crypto_finding import RiskLevel


_CRITICALITY_WEIGHT = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _weighted_average(values: list[tuple[int, int]]) -> int:
    """Calcula media ponderada inteira com protecao para listas vazias."""
    if not values:
        return 0
    numerator = sum(value * weight for value, weight in values)
    denominator = sum(weight for _, weight in values) or 1
    return round(numerator / denominator)


def _risk_from_score(score: int) -> RiskLevel:
    """Converte score agregado em nivel de risco legivel."""
    if score >= 85:
        return RiskLevel.LOW
    if score >= 70:
        return RiskLevel.MEDIUM
    if score >= 50:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def assess_crypto_agility(
    assets: list[CryptoAssetProfile],
    target_name: str = "crypto-program",
) -> CryptoAgilityAssessment:
    """
    Avalia a maturidade de crypto agility de um inventario de ativos.

    Entradas:
      - lista de perfis sinteticos de ativos.

    Saidas:
      - score agregado de crypto agility;
      - score de complexidade de migracao;
      - indice de acoplamento algoritmico;
      - notas e acoes priorizadas.
    """
    weighted_agility: list[tuple[int, int]] = []
    weighted_complexity: list[tuple[int, int]] = []
    weighted_coupling: list[tuple[int, int]] = []
    missing_controls: Counter[str] = Counter()
    legacy_dependency = False
    notes: list[str] = []

    for asset in assets:
        weight = _CRITICALITY_WEIGHT[asset.business_criticality.value]
        agility_penalty = 0
        complexity = 5
        coupling = 0

        if not asset.algorithm_abstraction:
            agility_penalty += 20
            coupling += 25
            missing_controls["Introduce an explicit cryptographic abstraction layer."] += weight

        if asset.hardcoded_algorithm_dependencies:
            legacy_dependency = True
            dependency_penalty = min(24, len(asset.hardcoded_algorithm_dependencies) * 8)
            agility_penalty += dependency_penalty
            coupling += min(30, len(asset.hardcoded_algorithm_dependencies) * 10)
            missing_controls["Reduce hardcoded algorithm dependencies and externalize policy versioning."] += weight

        if not asset.versioned_policies:
            agility_penalty += 10
            coupling += 15
            missing_controls["Adopt versioned cryptographic policies per environment."] += weight

        if not asset.dual_stack_support:
            agility_penalty += 15
            complexity += 20
            coupling += 10
            missing_controls["Prepare dual-stack or hybrid cryptographic support for staged transitions."] += weight

        if not asset.key_lifecycle_automation:
            agility_penalty += 10
            complexity += 15
            missing_controls["Automate key lifecycle controls to reduce migration friction."] += weight

        if not asset.migration_runbook:
            agility_penalty += 10
            complexity += 20
            missing_controls["Document a tested migration runbook with rollback criteria."] += weight

        if asset.third_party_dependencies:
            agility_penalty += min(15, len(asset.third_party_dependencies) * 5)
            complexity += min(15, len(asset.third_party_dependencies) * 5)
            missing_controls["Map third-party cryptographic dependencies and supplier constraints."] += weight

        if asset.migration_blockers:
            blocker_penalty = min(20, len(asset.migration_blockers) * 5)
            agility_penalty += blocker_penalty
            complexity += blocker_penalty
            missing_controls["Track migration blockers with owners and target dates."] += weight

        if asset.classical_public_key_dependency and not asset.hybrid_ready:
            agility_penalty += 10
            complexity += 10
            coupling += 10
            missing_controls["Plan hybrid classical plus post-quantum operation for critical services."] += weight

        agility_score = max(0, 100 - agility_penalty)
        complexity_score = min(100, complexity)
        coupling_index = min(100, coupling)

        weighted_agility.append((agility_score, weight))
        weighted_complexity.append((complexity_score, weight))
        weighted_coupling.append((coupling_index, weight))

        if agility_score < 60:
            notes.append(
                f"{asset.asset_name} shows material agility debt in {asset.environment} "
                f"(score {agility_score}/100)."
            )

    agility_score = _weighted_average(weighted_agility)
    complexity_score = _weighted_average(weighted_complexity)
    coupling_index = _weighted_average(weighted_coupling)
    risk_level = _risk_from_score(agility_score)

    recommendations = [action for action, _ in missing_controls.most_common(5)]
    if not recommendations:
        recommendations.append(
            "Maintain periodic crypto agility reviews and validate migration assumptions with tabletop exercises."
        )

    return CryptoAgilityAssessment(
        target_name=target_name,
        assessed_assets=len(assets),
        crypto_agility_score=agility_score,
        migration_complexity_score=complexity_score,
        algorithm_coupling_index=coupling_index,
        legacy_algorithm_dependency=legacy_dependency,
        risk_level=risk_level,
        recommended_actions=recommendations,
        analysis_notes=notes,
    )

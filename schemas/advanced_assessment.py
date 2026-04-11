"""
Schemas avancados para avaliacoes de crypto agility e readiness pos-quantica.

Este arquivo concentra contratos de dados reutilizaveis para:
  - inventario de ativos criptograficos;
  - avaliacao de crypto agility;
  - avaliacao de readiness pos-quantica;
  - planejamento de migracao hibrida;
  - risco de confidencialidade de longo prazo.

As estruturas foram desenhadas para uso defensivo, offline e orientado a
governanca. Nenhum campo deve conter segredos reais, chaves privadas ou
material sensivel nao mascarado.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from schemas.crypto_finding import RiskLevel


class BusinessCriticality(str, Enum):
    """Classificacao simples de criticidade para ponderar risco e prioridade."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CryptoAssetProfile(BaseModel):
    """
    Perfil sintetico de um ativo para avaliacoes avancadas.

    Entradas:
      - metadados do ativo e do ambiente;
      - sinais de acoplamento criptografico;
      - sinais de prontidao para migracao;
      - riscos de confidencialidade de longo prazo.

    Limitacoes:
      - depende de inventario fiel e atualizado;
      - nao valida enforce em runtime;
      - nao substitui revisao arquitetural humana.
    """

    asset_id: str = Field(..., min_length=2)
    asset_name: str = Field(..., min_length=3)
    asset_type: str = Field(..., min_length=2)
    environment: str = Field(default="production")
    business_criticality: BusinessCriticality = Field(default=BusinessCriticality.MEDIUM)
    owner_hint: Optional[str] = Field(default=None)

    current_primitives: list[str] = Field(default_factory=list)
    hardcoded_algorithm_dependencies: list[str] = Field(default_factory=list)
    third_party_dependencies: list[str] = Field(default_factory=list)
    migration_blockers: list[str] = Field(default_factory=list)

    algorithm_abstraction: bool = Field(default=False)
    versioned_policies: bool = Field(default=False)
    dual_stack_support: bool = Field(default=False)
    hybrid_ready: bool = Field(default=False)
    pq_inventory_complete: bool = Field(default=False)
    migration_runbook: bool = Field(default=False)
    key_lifecycle_automation: bool = Field(default=False)

    classical_public_key_dependency: bool = Field(default=True)
    long_term_confidentiality: bool = Field(default=False)
    data_retention_years: int = Field(default=0, ge=0)

    @field_validator("current_primitives", "hardcoded_algorithm_dependencies")
    @classmethod
    def normaliza_primitivas(cls, value: list[str]) -> list[str]:
        """Normaliza listas tecnicas para reduzir duplicidade e ruido."""
        return [item.strip() for item in value if item and item.strip()]


class CryptoAgilityAssessment(BaseModel):
    """Resultado agregado da avaliacao de crypto agility."""

    target_name: str
    assessed_assets: int = Field(ge=0)
    crypto_agility_score: int = Field(ge=0, le=100)
    migration_complexity_score: int = Field(ge=0, le=100)
    algorithm_coupling_index: int = Field(ge=0, le=100)
    legacy_algorithm_dependency: bool = Field(default=False)
    risk_level: RiskLevel
    recommended_actions: list[str] = Field(default_factory=list)
    analysis_notes: list[str] = Field(default_factory=list)


class PostQuantumReadinessResult(BaseModel):
    """Resultado agregado da avaliacao de readiness pos-quantica."""

    target_name: str
    assessed_assets: int = Field(ge=0)
    post_quantum_readiness_score: int = Field(ge=0, le=100)
    future_exposure_risk: RiskLevel
    long_term_confidentiality_risk: RiskLevel
    hybrid_transition_priority: str
    migration_wave: int = Field(ge=1, le=4)
    quantum_transition_status: str
    recommended_actions: list[str] = Field(default_factory=list)
    analysis_notes: list[str] = Field(default_factory=list)


class MigrationPlanningItem(BaseModel):
    """Item priorizado para uma onda de migracao criptografica."""

    asset_id: str
    asset_name: str
    environment: str
    business_criticality: BusinessCriticality
    migration_priority: int = Field(ge=0, le=100)
    migration_wave: int = Field(ge=1, le=4)
    hybrid_mode_required: bool = Field(default=False)
    long_term_confidentiality_risk: RiskLevel
    blockers: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class LongTermConfidentialityFinding(BaseModel):
    """Achado resumido para exposicao de confidencialidade de longo prazo."""

    asset_id: str
    asset_name: str
    risk_level: RiskLevel
    evidence_summary: str
    recommended_fix: str

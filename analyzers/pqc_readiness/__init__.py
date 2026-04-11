"""
Analisadores de readiness pos-quantica.

Reune a avaliacao agregada de exposicao futura e risco de
confidencialidade de longo prazo para inventarios sinteticos.
"""

from .readiness_assessor import assess_pqc_readiness

__all__ = ["assess_pqc_readiness"]

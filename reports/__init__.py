"""
Geradores de relatorio do CryptoLogik.

Mantem o namespace local explicito para evitar ambiguidade de import
quando o toolkit esta instalado em modo editavel ao lado de outros
repositorios do portfolio.
"""

from .report_generator import generate_markdown_report

__all__ = ["generate_markdown_report"]

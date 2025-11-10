"""
Reporter modules - Módulos auxiliares do Security Reporter
"""

from .sanitizer import DataSanitizer, sanitize_report
from .html_generator import generate_html, save_html, save_basic_html

__all__ = [
    'DataSanitizer',
    'sanitize_report',
    'generate_html',
    'save_html',
    'save_basic_html',  # Mantido para compatibilidade retroativa
]

"""
HTML Builder Package
Componentes modulares para geração de relatórios HTML
"""

from .formatters import format_markdown_to_html, load_asset
from .header import generate_header
from .footer import generate_footer, generate_json_modal
from .sections import (
    generate_status_badge,
    generate_score_section,
    generate_analysis_sections,
    generate_analysis_card,
    generate_disclaimer
)
from .ai_sections import (
    generate_ai_section,
    generate_critical_alerts_section,
    generate_attack_vectors_section,
    generate_recommendations_section,
    generate_compliance_section,
    generate_next_steps_timeline
)

__all__ = [
    # Formatters
    'format_markdown_to_html',
    'load_asset',
    # Header/Footer
    'generate_header',
    'generate_footer',
    'generate_json_modal',
    # Sections
    'generate_status_badge',
    'generate_score_section',
    'generate_analysis_sections',
    'generate_analysis_card',
    'generate_disclaimer',
    # AI Sections
    'generate_ai_section',
    'generate_critical_alerts_section',
    'generate_attack_vectors_section',
    'generate_recommendations_section',
    'generate_compliance_section',
    'generate_next_steps_timeline',
]

"""
Security Analyzers - Módulos de Análise Condicional
Cada analyzer é responsável por gerar insights inteligentes sobre uma área específica
"""

from .base_analyzer import BaseAnalyzer
from .score_analyzer import ScoreAnalyzer
from .ports_analyzer import PortsAnalyzer
from .auth_analyzer import AuthAnalyzer
from .firewall_analyzer import FirewallAnalyzer
from .vulnerabilities_analyzer import VulnerabilitiesAnalyzer
from .network_analyzer import NetworkAnalyzer
from .permissions_analyzer import PermissionsAnalyzer

__all__ = [
    'BaseAnalyzer',
    'ScoreAnalyzer',
    'PortsAnalyzer',
    'AuthAnalyzer',
    'FirewallAnalyzer',
    'VulnerabilitiesAnalyzer',
    'NetworkAnalyzer',
    'PermissionsAnalyzer',
]

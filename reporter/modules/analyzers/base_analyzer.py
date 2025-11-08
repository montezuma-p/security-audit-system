#!/usr/bin/env python3
"""
Base Analyzer - Classe base para todos os analyzers
Define a interface comum e métodos utilitários
"""

from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod


class BaseAnalyzer(ABC):
    """
    Classe abstrata base para analyzers de segurança
    
    Cada analyzer deve implementar o método analyze() que retorna
    um dicionário com insights sobre a área analisada.
    """
    
    def __init__(self, data: Dict[str, Any]):
        """
        Inicializa o analyzer com os dados do relatório
        
        Args:
            data: Dados completos do relatório de segurança
        """
        self.data = data
        self.metrics = data.get('metrics', {})
        self.summary = data.get('summary', {})
        self.alerts = data.get('alerts', [])
        self.security_score = data.get('security_score', {})
    
    @abstractmethod
    def analyze(self) -> Dict[str, Any]:
        """
        Analisa os dados e retorna insights
        
        Returns:
            Dict com:
                - status: 'good', 'warning', 'critical', 'unknown'
                - message: Texto didático explicativo
                - details: Lista de detalhes adicionais
                - recommendations: Lista de recomendações
                - severity: 'low', 'medium', 'high', 'critical'
                - metrics: Métricas específicas da análise
        """
        pass
    
    def _get_status_from_severity(self, critical: int, warning: int, good: int) -> str:
        """
        Determina status geral baseado em contadores
        
        Args:
            critical: Número de itens críticos
            warning: Número de avisos
            good: Número de itens bons
            
        Returns:
            Status: 'critical', 'warning', 'good'
        """
        if critical > 0:
            return 'critical'
        elif warning > 0:
            return 'warning'
        else:
            return 'good'
    
    def _count_alerts_by_priority(self, priority: int) -> int:
        """
        Conta alertas de uma prioridade específica
        
        Args:
            priority: Prioridade a contar (1-5)
            
        Returns:
            Número de alertas
        """
        return len([a for a in self.alerts if a.get('priority') == priority])
    
    def _has_metric(self, *keys) -> bool:
        """
        Verifica se uma métrica existe nos dados
        
        Args:
            *keys: Caminho para a métrica (ex: 'ports', 'listening_ports')
            
        Returns:
            True se existe, False caso contrário
        """
        current = self.metrics
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                return False
            current = current[key]
        return True
    
    def _get_metric(self, *keys, default=None) -> Any:
        """
        Obtém valor de uma métrica com fallback
        
        Args:
            *keys: Caminho para a métrica
            default: Valor padrão se não encontrar
            
        Returns:
            Valor da métrica ou default
        """
        current = self.metrics
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                return default
            current = current[key]
        return current
    
    def _format_list(self, items: List[str], max_items: int = 5) -> str:
        """
        Formata lista para exibição com limite
        
        Args:
            items: Lista de itens
            max_items: Máximo de itens a exibir
            
        Returns:
            String formatada
        """
        if not items:
            return "Nenhum"
        
        if len(items) <= max_items:
            return ", ".join(str(i) for i in items)
        else:
            shown = ", ".join(str(i) for i in items[:max_items])
            return f"{shown} e mais {len(items) - max_items}"
    
    def _pluralize(self, count: int, singular: str, plural: str = None) -> str:
        """
        Helper para pluralização
        
        Args:
            count: Número de itens
            singular: Forma singular
            plural: Forma plural (padrão: singular + 's')
            
        Returns:
            Texto com forma correta
        """
        if plural is None:
            plural = singular + 's'
        
        return f"{count} {singular if count == 1 else plural}"

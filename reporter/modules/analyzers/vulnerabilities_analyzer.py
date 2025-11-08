#!/usr/bin/env python3
"""
Vulnerabilities Analyzer - Analisa pacotes desatualizados e CVEs
"""

from typing import Dict, Any
from .base_analyzer import BaseAnalyzer


class VulnerabilitiesAnalyzer(BaseAnalyzer):
    """Analisa vulnerabilidades e atualizações pendentes"""
    
    def analyze(self) -> Dict[str, Any]:
        """Analisa vulnerabilidades do sistema"""
        
        vuln_data = self._get_metric('vulnerabilities', default={})
        
        # Garantir que são números (pode vir como dict ou lista)
        updates_available = vuln_data.get('updates_available', 0)
        if isinstance(updates_available, (dict, list)):
            updates_available = len(updates_available) if isinstance(updates_available, list) else 0
        
        security_updates = vuln_data.get('security_updates', 0)
        if isinstance(security_updates, (dict, list)):
            security_updates = len(security_updates) if isinstance(security_updates, list) else 0
        
        auto_update = vuln_data.get('auto_update_status', {})
        if not isinstance(auto_update, dict):
            auto_update = {}
        auto_enabled = auto_update.get('enabled', False)
        
        # Status
        if security_updates > 0:
            status = 'critical'
            status_text = f'🚨 {security_updates} ATUALIZAÇÕES DE SEGURANÇA PENDENTES'
            severity = 'critical'
        elif updates_available > 50:
            status = 'warning'
            status_text = f'⚠️ {updates_available} PACOTES DESATUALIZADOS'
            severity = 'high'
        elif updates_available > 0:
            status = 'warning'
            status_text = f'⚠️ {updates_available} ATUALIZAÇÕES DISPONÍVEIS'
            severity = 'medium'
        else:
            status = 'good'
            status_text = '✅ SISTEMA ATUALIZADO'
            severity = 'low'
        
        message = self._generate_message(updates_available, security_updates, auto_enabled)
        
        details = [
            f"Pacotes desatualizados: {updates_available}",
            f"Atualizações de segurança: {security_updates}",
            f"Auto-update: {'✅ Ativo' if auto_enabled else '❌ Inativo'}"
        ]
        
        recommendations = self._generate_recommendations(updates_available, security_updates, auto_enabled)
        
        return {
            'status': status,
            'status_text': status_text,
            'message': message,
            'details': details,
            'recommendations': recommendations,
            'severity': severity,
            'metrics': {
                'updates_available': updates_available,
                'security_updates': security_updates,
                'auto_update_enabled': auto_enabled
            }
        }
    
    def _generate_message(self, total: int, security: int, auto: bool) -> str:
        """Gera mensagem sobre vulnerabilidades"""
        
        if security > 0:
            msg = f"🚨 **CRÍTICO**: Existem **{security} atualizações de segurança** pendentes! "
            msg += "Essas atualizações corrigem vulnerabilidades conhecidas que podem ser exploradas por atacantes. "
            msg += "Aplique essas atualizações **IMEDIATAMENTE** para proteger o sistema.\n\n"
            
            if total > security:
                msg += f"Além disso, há {total - security} outras atualizações gerais que também devem ser aplicadas."
        
        elif total > 50:
            msg = f"⚠️ O sistema possui **{total} pacotes desatualizados**. "
            msg += "Embora não sejam classificados como atualizações de segurança críticas, "
            msg += "pacotes desatualizados frequentemente contêm correções de bugs e melhorias de segurança secundárias. "
            msg += "Sistemas muito desatualizados têm maior risco de exploração."
        
        elif total > 0:
            msg = f"Existem **{total} atualizações disponíveis**. "
            msg += "Manter o sistema atualizado é uma das práticas de segurança mais importantes e eficazes. "
            msg += "Agende a aplicação dessas atualizações em breve."
        
        else:
            msg = "✅ **Perfeito!** O sistema está completamente atualizado. "
            msg += "Não há pacotes desatualizados ou atualizações de segurança pendentes. "
            msg += "Continue mantendo este padrão de atualização regular."
        
        # Auto-update
        if not auto and total > 0:
            msg += "\n\n⚠️ **Atenção**: O serviço de atualizações automáticas está **desativado**. "
            msg += "Isso significa que o sistema depende de atualizações manuais, o que aumenta o risco de "
            msg += "esquecer de aplicar patches importantes."
        elif auto:
            msg += "\n\n✅ O serviço de atualizações automáticas está ativo, ajudando a manter o sistema protegido."
        
        return msg
    
    def _generate_recommendations(self, total: int, security: int, auto: bool) -> list:
        """Gera recomendações"""
        recommendations = []
        
        if security > 0:
            recommendations.append({
                'title': 'Aplicar Atualizações de Segurança AGORA',
                'description': f'Aplique as {security} atualizações de segurança críticas imediatamente.',
                'priority': 'critical',
                'command': 'sudo dnf update -y'
            })
        elif total > 0:
            recommendations.append({
                'title': 'Atualizar Sistema',
                'description': f'Aplique as {total} atualizações disponíveis.',
                'priority': 'high' if total > 50 else 'medium',
                'command': 'sudo dnf update -y'
            })
        
        if not auto:
            recommendations.append({
                'title': 'Habilitar Atualizações Automáticas',
                'description': 'Configure dnf-automatic para aplicar atualizações automaticamente.',
                'priority': 'high',
                'command': 'sudo systemctl enable --now dnf-automatic.timer'
            })
        
        return recommendations

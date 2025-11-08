#!/usr/bin/env python3
"""
Firewall Analyzer - Analisa configuração de firewall e SELinux
"""

from typing import Dict, Any
from .base_analyzer import BaseAnalyzer


class FirewallAnalyzer(BaseAnalyzer):
    """Analisa firewall e SELinux"""
    
    def analyze(self) -> Dict[str, Any]:
        """Analisa configuração de firewall e SELinux"""
        
        firewall_data = self._get_metric('firewall', default={})
        
        # Buscar firewall_active do summary ou do status
        summary = firewall_data.get('summary', {})
        status_data = firewall_data.get('status', {})
        firewall_active = summary.get('firewall_active', status_data.get('running', False))
        
        # Buscar SELinux
        selinux_data = firewall_data.get('selinux', {})
        selinux_mode = selinux_data.get('mode', 'unknown').lower()
        
        zones = firewall_data.get('zones', [])
        
        # Determinar status
        if not firewall_active:
            status = 'critical'
            status_text = '🚨 FIREWALL DESATIVADO'
            severity = 'critical'
        elif selinux_mode == 'disabled':
            status = 'critical'
            status_text = '🚨 SELINUX DESATIVADO'
            severity = 'critical'
        elif selinux_mode == 'permissive':
            status = 'warning'
            status_text = '⚠️ SELINUX EM MODO PERMISSIVO'
            severity = 'high'
        elif selinux_mode == 'enforcing':
            status = 'good'
            status_text = '✅ FIREWALL E SELINUX ATIVOS'
            severity = 'low'
        else:
            status = 'warning'
            status_text = '⚠️ CONFIGURAÇÃO PARCIAL'
            severity = 'medium'
        
        # Mensagem
        message = self._generate_message(firewall_active, selinux_mode, zones)
        
        # Detalhes
        details = []
        if firewall_active:
            details.append(f"Firewall: firewalld ativo")
        if selinux_mode:
            details.append(f"SELinux: {selinux_mode}")
        if zones:
            details.append(f"Zonas configuradas: {len(zones)}")
        
        # Recomendações
        recommendations = self._generate_recommendations(firewall_active, selinux_mode)
        
        return {
            'status': status,
            'status_text': status_text,
            'message': message,
            'details': details,
            'recommendations': recommendations,
            'severity': severity,
            'metrics': {
                'firewall_active': firewall_active,
                'selinux_mode': selinux_mode,
                'zones_count': len(zones)
            }
        }
    
    def _generate_message(self, firewall: bool, selinux: str, zones: list) -> str:
        """Gera mensagem sobre firewall"""
        
        if not firewall and selinux == 'disabled':
            msg = "🚨 **SITUAÇÃO CRÍTICA**: O sistema está **completamente desprotegido**! "
            msg += "Tanto o firewall quanto o SELinux estão desativados, deixando o sistema vulnerável a qualquer tipo de ataque de rede. "
            msg += "**Ative imediatamente** ambos os sistemas de proteção."
        
        elif not firewall:
            msg = "🚨 **ALERTA CRÍTICO**: O **firewall está desativado**! "
            msg += "Sem firewall, todas as portas abertas no sistema estão expostas à rede, permitindo conexões diretas não filtradas. "
            msg += "Mesmo com SELinux ativo, a ausência de firewall é uma falha grave de segurança."
        
        elif selinux == 'disabled':
            msg = "🚨 **ALERTA CRÍTICO**: O **SELinux está desativado**! "
            msg += "O SELinux (Security-Enhanced Linux) é uma camada de segurança essencial que controla o que processos podem fazer. "
            msg += "Sem ele, se um atacante comprometer um serviço, terá muito mais liberdade para explorar o sistema."
        
        elif selinux == 'permissive':
            msg = "⚠️ O SELinux está em **modo permissivo**, o que significa que ele apenas registra violações mas não as bloqueia. "
            msg += "Este modo é útil para debug, mas não oferece proteção real. "
            msg += "Para segurança completa, altere para modo 'enforcing'."
        
        elif selinux == 'enforcing' and firewall:
            msg = "✅ **Excelente configuração de segurança!** O firewall (firewalld) está ativo E o SELinux está em modo 'enforcing'. "
            msg += "Isso significa que você tem **duas camadas robustas de proteção**: "
            msg += "o firewall filtra conexões de rede não autorizadas, "
            msg += "e o SELinux bloqueia ações suspeitas de processos mesmo que sejam comprometidos. "
            
            if zones:
                default_zone = next((z.get('name') for z in zones if z.get('default')), 'unknown')
                msg += f"\n\nA zona padrão '{default_zone}' está configurada, aplicando regras de firewall consistentes."
        
        else:
            msg = "⚠️ A configuração de segurança está parcialmente implementada. Revise as configurações de firewall e SELinux."
        
        return msg
    
    def _generate_recommendations(self, firewall: bool, selinux: str) -> list:
        """Gera recomendações"""
        recommendations = []
        
        if not firewall:
            recommendations.append({
                'title': 'Ativar Firewall Imediatamente',
                'description': 'Habilite e inicie o firewalld para proteção de rede.',
                'priority': 'critical',
                'command': 'sudo systemctl enable --now firewalld'
            })
        
        if selinux == 'disabled':
            recommendations.append({
                'title': 'Ativar SELinux',
                'description': 'Edite /etc/selinux/config e defina SELINUX=enforcing, depois reinicie o sistema.',
                'priority': 'critical',
                'command': 'sudo sed -i "s/SELINUX=disabled/SELINUX=enforcing/" /etc/selinux/config'
            })
        
        elif selinux == 'permissive':
            recommendations.append({
                'title': 'Mudar SELinux para Enforcing',
                'description': 'Altere o SELinux para modo enforcing para proteção ativa.',
                'priority': 'high',
                'command': 'sudo setenforce 1 && sudo sed -i "s/SELINUX=permissive/SELINUX=enforcing/" /etc/selinux/config'
            })
        
        return recommendations

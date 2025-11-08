#!/usr/bin/env python3
"""
Network Analyzer - Analisa configuração de rede
"""

from typing import Dict, Any
from .base_analyzer import BaseAnalyzer


class NetworkAnalyzer(BaseAnalyzer):
    """Analisa configuração e status de rede"""
    
    def analyze(self) -> Dict[str, Any]:
        """Analisa rede do sistema"""
        
        network_data = self._get_metric('network', default={})
        
        interfaces = network_data.get('interfaces', [])
        dns_servers = network_data.get('dns_servers', [])
        routing = network_data.get('routing', {})
        ip_forward = routing.get('ip_forwarding_enabled', False)
        
        # Status
        if ip_forward:
            status = 'warning'
            status_text = '⚠️ IP FORWARDING ATIVADO'
            severity = 'medium'
        elif not interfaces:
            status = 'warning'
            status_text = '⚠️ SEM INTERFACES DE REDE'
            severity = 'low'
        else:
            status = 'good'
            status_text = '✅ CONFIGURAÇÃO NORMAL'
            severity = 'low'
        
        message = self._generate_message(interfaces, dns_servers, ip_forward)
        
        details = [
            f"Interfaces ativas: {len(interfaces)}",
            f"Servidores DNS: {len(dns_servers)}",
            f"IP Forwarding: {'❌ Ativo' if ip_forward else '✅ Inativo'}"
        ]
        
        recommendations = self._generate_recommendations(ip_forward, interfaces)
        
        return {
            'status': status,
            'status_text': status_text,
            'message': message,
            'details': details,
            'recommendations': recommendations,
            'severity': severity,
            'metrics': {
                'interfaces_count': len(interfaces),
                'dns_count': len(dns_servers),
                'ip_forwarding': ip_forward
            }
        }
    
    def _generate_message(self, interfaces: list, dns: list, ip_forward: bool) -> str:
        """Gera mensagem sobre rede"""
        
        if ip_forward:
            msg = "⚠️ **Atenção**: O **IP forwarding está ativado** no sistema. "
            msg += "Esta configuração permite que o sistema encaminhe pacotes entre diferentes interfaces de rede, "
            msg += "efetivamente transformando-o em um roteador. "
            msg += "Para um workstation comum, isso é desnecessário e pode ser explorado por atacantes "
            msg += "para usar sua máquina como pivô em ataques à rede interna."
        
        elif not interfaces:
            msg = "⚠️ Nenhuma interface de rede ativa foi detectada. "
            msg += "Isso pode indicar um problema de configuração ou que o sistema está isolado da rede."
        
        else:
            msg = f"✅ A configuração de rede está **normal** para um workstation. "
            msg += f"O sistema possui {len(interfaces)} interface(s) de rede ativa(s). "
            
            if dns:
                msg += f"A resolução DNS está configurada com {len(dns)} servidor(es). "
                msg += "A conectividade com a internet está funcional."
            
            msg += "\n\nNão foram identificadas configurações de rede perigosas como IP forwarding ativado."
        
        return msg
    
    def _generate_recommendations(self, ip_forward: bool, interfaces: list) -> list:
        """Gera recomendações"""
        recommendations = []
        
        if ip_forward:
            recommendations.append({
                'title': 'Desativar IP Forwarding',
                'description': 'Desative o IP forwarding se não for necessário para sua configuração.',
                'priority': 'medium',
                'command': 'sudo sysctl -w net.ipv4.ip_forward=0 && echo "net.ipv4.ip_forward=0" | sudo tee -a /etc/sysctl.conf'
            })
        
        if interfaces:
            recommendations.append({
                'title': 'Revisar Interfaces de Rede',
                'description': 'Verifique se todas as interfaces ativas são conhecidas e necessárias.',
                'priority': 'low',
                'command': 'ip addr show'
            })
        
        return recommendations

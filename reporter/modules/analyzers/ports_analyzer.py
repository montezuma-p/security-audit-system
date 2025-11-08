#!/usr/bin/env python3
"""
Ports Analyzer - Analisa portas abertas e conexões de rede
"""

from typing import Dict, Any
from .base_analyzer import BaseAnalyzer


class PortsAnalyzer(BaseAnalyzer):
    """Analisa portas abertas, conexões estabelecidas e serviços de rede"""
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analisa configuração de portas e rede
        
        Returns:
            Insights sobre portas e serviços
        """
        ports_data = self._get_metric('ports', default={})
        
        listening_ports = ports_data.get('listening_ports', [])
        suspicious_ports = ports_data.get('suspicious_ports', [])
        connections = ports_data.get('established_connections', {})
        network_services = ports_data.get('network_services', [])
        
        total_listening = len(listening_ports)
        total_suspicious = len(suspicious_ports)
        total_connections = connections.get('total', 0)
        
        # Determinar status
        if total_suspicious > 0:
            status = 'critical'
            status_text = '🚨 PORTAS SUSPEITAS DETECTADAS'
            severity = 'critical'
        elif total_listening > 10:
            status = 'warning'
            status_text = '⚠️ MUITAS PORTAS ABERTAS'
            severity = 'medium'
        elif total_listening == 0:
            status = 'good'
            status_text = '✅ NENHUMA PORTA EXPOSTA'
            severity = 'low'
        else:
            status = 'good'
            status_text = '✅ CONFIGURAÇÃO SEGURA'
            severity = 'low'
        
        # Gerar mensagem
        message = self._generate_message(listening_ports, suspicious_ports, connections, network_services)
        
        # Detalhes
        details = self._generate_details(listening_ports, connections)
        
        # Recomendações
        recommendations = self._generate_recommendations(listening_ports, suspicious_ports, network_services)
        
        return {
            'status': status,
            'status_text': status_text,
            'message': message,
            'details': details,
            'recommendations': recommendations,
            'severity': severity,
            'metrics': {
                'total_listening': total_listening,
                'total_suspicious': total_suspicious,
                'total_connections': total_connections,
                'has_firewall': any(s.get('name') == 'firewalld' and s.get('status') == 'active' 
                                   for s in network_services)
            }
        }
    
    def _generate_message(self, listening: list, suspicious: list, connections: dict, services: list) -> str:
        """Gera análise didática sobre portas"""
        
        total_listening = len(listening)
        total_suspicious = len(suspicious)
        
        if total_suspicious > 0:
            msg = f"⚠️ **ALERTA**: Foram detectadas **{total_suspicious} portas suspeitas** abertas no sistema. "
            msg += "Portas suspeitas podem indicar serviços não autorizados, malware ou backdoors. "
            
            # Listar portas suspeitas
            susp_ports = [f"{p.get('port')}/{p.get('protocol')}" for p in suspicious[:3]]
            msg += f"Portas identificadas: {', '.join(susp_ports)}. "
            
            msg += "**Investigue imediatamente** quais processos estão utilizando essas portas."
        
        elif total_listening == 0:
            msg = "✅ **Excelente!** Nenhuma porta está escutando para conexões externas. "
            msg += "Isso minimiza a superfície de ataque do sistema, dificultando acesso não autorizado."
        
        elif total_listening <= 5:
            msg = f"✅ O sistema possui **{total_listening} portas abertas**, o que é um número seguro e gerenciável. "
            
            # Identificar portas comuns
            common_ports = self._identify_common_ports(listening)
            if common_ports:
                msg += f"As portas abertas são de serviços conhecidos: {', '.join(common_ports)}. "
            
            # Verificar se tem firewall
            has_firewall = any(s.get('name') == 'firewalld' and s.get('status') == 'active' for s in services)
            if has_firewall:
                msg += "O firewall está ativo, fornecendo uma camada adicional de proteção contra acessos não autorizados."
            else:
                msg += "⚠️ No entanto, **não foi detectado firewall ativo**, deixando essas portas potencialmente expostas."
        
        else:
            msg = f"⚠️ O sistema possui **{total_listening} portas abertas**, o que pode representar uma superfície de ataque maior. "
            msg += "Cada porta aberta é um potencial ponto de entrada para atacantes. "
            msg += "Revise se todos esses serviços são realmente necessários e considere desabilitar os que não são essenciais."
        
        # Adicionar informação sobre conexões ativas
        total_conn = connections.get('total', 0)
        if total_conn > 0:
            msg += f"\n\nAtualmente existem **{total_conn} conexões estabelecidas**. "
            
            by_process = connections.get('by_process', {})
            if by_process:
                top_process = max(by_process.items(), key=lambda x: x[1])
                msg += f"O processo '{top_process[0]}' possui {top_process[1]} conexões ativas."
        
        return msg
    
    def _identify_common_ports(self, listening: list) -> list:
        """Identifica portas comuns conhecidas"""
        known_services = {
            22: 'SSH',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            5355: 'mDNS',
            631: 'CUPS (Impressão)',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        services = []
        for port_info in listening[:5]:  # Limitar a 5
            port = port_info.get('port')
            if port in known_services:
                services.append(f"{known_services[port]} ({port})")
        
        return services
    
    def _generate_details(self, listening: list, connections: dict) -> list:
        """Gera detalhes adicionais"""
        details = []
        
        # Agrupar por protocolo
        tcp_count = len([p for p in listening if p.get('protocol') == 'tcp'])
        udp_count = len([p for p in listening if p.get('protocol') == 'udp'])
        
        if tcp_count > 0:
            details.append(f"Portas TCP abertas: {tcp_count}")
        if udp_count > 0:
            details.append(f"Portas UDP abertas: {udp_count}")
        
        # IPs remotos únicos
        remote_ips = connections.get('top_remote_ips', [])
        if remote_ips:
            details.append(f"Conexões com {len(remote_ips)} endereços IP diferentes")
        
        return details
    
    def _generate_recommendations(self, listening: list, suspicious: list, services: list) -> list:
        """Gera recomendações específicas"""
        recommendations = []
        
        if suspicious:
            recommendations.append({
                'title': 'Investigar Portas Suspeitas',
                'description': f'Use "ss -tulpn" ou "netstat -tulpn" para identificar quais processos estão usando as {len(suspicious)} portas suspeitas detectadas.',
                'priority': 'critical',
                'command': 'sudo ss -tulpn | grep -E "' + '|'.join(str(p.get('port')) for p in suspicious) + '"'
            })
        
        if len(listening) > 10:
            recommendations.append({
                'title': 'Reduzir Superfície de Ataque',
                'description': 'Desabilite serviços desnecessários para reduzir o número de portas abertas.',
                'priority': 'medium'
            })
        
        # Verificar firewall
        has_firewall = any(s.get('name') == 'firewalld' and s.get('status') == 'active' for s in services)
        if not has_firewall:
            recommendations.append({
                'title': 'Ativar Firewall',
                'description': 'Habilite e configure o firewalld para filtrar conexões de entrada.',
                'priority': 'high',
                'command': 'sudo systemctl enable --now firewalld'
            })
        
        return recommendations

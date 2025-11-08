#!/usr/bin/env python3
"""
Auth Analyzer - Analisa autenticação, logins e uso de sudo
"""

from typing import Dict, Any
from .base_analyzer import BaseAnalyzer


class AuthAnalyzer(BaseAnalyzer):
    """Analisa tentativas de login, brute force e uso de sudo"""
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analisa aspectos de autenticação
        
        Returns:
            Insights sobre autenticação e acessos
        """
        auth_data = self._get_metric('authentication', default={})
        
        failed_logins = auth_data.get('failed_logins', [])
        brute_force = auth_data.get('brute_force_analysis', {})
        successful_logins = auth_data.get('successful_logins', [])
        sudo_usage = auth_data.get('sudo_usage', [])
        
        brute_force_detected = brute_force.get('brute_force_detected', False)
        suspicious_ips = brute_force.get('suspicious_ips', [])
        
        # Determinar status
        if brute_force_detected:
            status = 'critical'
            status_text = '🚨 ATAQUE DE FORÇA BRUTA DETECTADO'
            severity = 'critical'
        elif len(failed_logins) > 20:
            status = 'warning'
            status_text = '⚠️ MUITAS TENTATIVAS DE LOGIN FALHADAS'
            severity = 'high'
        elif len(failed_logins) > 0:
            status = 'warning'
            status_text = '⚠️ TENTATIVAS DE LOGIN FALHADAS DETECTADAS'
            severity = 'medium'
        else:
            status = 'good'
            status_text = '✅ NENHUMA TENTATIVA DE ACESSO SUSPEITA'
            severity = 'low'
        
        # Gerar mensagem
        message = self._generate_message(failed_logins, brute_force, sudo_usage)
        
        # Detalhes
        details = self._generate_details(failed_logins, successful_logins, sudo_usage)
        
        # Recomendações
        recommendations = self._generate_recommendations(brute_force_detected, failed_logins, suspicious_ips)
        
        return {
            'status': status,
            'status_text': status_text,
            'message': message,
            'details': details,
            'recommendations': recommendations,
            'severity': severity,
            'metrics': {
                'failed_logins': len(failed_logins),
                'brute_force_detected': brute_force_detected,
                'suspicious_ips': len(suspicious_ips),
                'successful_logins': len(successful_logins),
                'sudo_commands': len(sudo_usage)
            }
        }
    
    def _generate_message(self, failed: list, brute_force: dict, sudo: list) -> str:
        """Gera análise sobre autenticação"""
        
        brute_force_detected = brute_force.get('brute_force_detected', False)
        suspicious_ips = brute_force.get('suspicious_ips', [])
        
        if brute_force_detected:
            msg = f"🚨 **ATENÇÃO CRÍTICA**: Foi detectado um **ataque de força bruta** contra o sistema! "
            msg += f"Foram identificados **{len(suspicious_ips)} endereços IP** realizando múltiplas tentativas de login falhadas. "
            msg += "Este é um padrão típico de ataque automatizado tentando adivinhar credenciais. "
            
            if suspicious_ips:
                msg += f"\n\nIPs mais agressivos: {', '.join(suspicious_ips[:3])}. "
            
            msg += "\n\n**Ação Imediata Necessária**: Bloqueie esses IPs no firewall e considere implementar fail2ban "
            msg += "para proteção automática contra ataques de força bruta."
        
        elif len(failed) > 20:
            msg = f"⚠️ Foram detectadas **{len(failed)} tentativas de login falhadas**. "
            msg += "Embora não configure um ataque de força bruta clássico, este número é preocupante e merece investigação. "
            msg += "Pode indicar tentativas de acesso não autorizado ou problemas de configuração."
        
        elif len(failed) > 0:
            msg = f"Foram registradas **{len(failed)} tentativas de login falhadas**. "
            msg += "Um pequeno número de falhas é normal (erros de digitação, senhas expiradas), "
            msg += "mas é importante monitorar para detectar padrões suspeitos."
        
        else:
            msg = "✅ **Excelente!** Não foram detectadas tentativas de login falhadas recentes. "
            msg += "Isso indica que não há atividade suspeita de tentativa de acesso não autorizado ao sistema."
        
        # Análise de sudo
        if sudo:
            msg += f"\n\n**Uso de Sudo**: Foram registrados **{len(sudo)} comandos executados com privilégios elevados**. "
            
            # Analisar padrões
            users = set(cmd.get('user', 'unknown') for cmd in sudo)
            if 'root' in users:
                msg += "Alguns comandos foram executados diretamente como root. "
            
            # Verificar comandos suspeitos
            suspicious_cmds = ['rm -rf', 'chmod 777', 'chown', '/etc/passwd', '/etc/shadow']
            has_suspicious = any(any(susp in cmd.get('command', '') for susp in suspicious_cmds) for cmd in sudo)
            
            if has_suspicious:
                msg += "⚠️ **Atenção**: Foram detectados comandos potencialmente perigosos executados com sudo. Revise o histórico."
            else:
                msg += "Os comandos executados parecem ser operações legítimas de sistema e manutenção."
        
        return msg
    
    def _generate_details(self, failed: list, successful: list, sudo: list) -> list:
        """Gera detalhes adicionais"""
        details = []
        
        if failed:
            # Usuários mais tentados
            failed_users = {}
            for fail in failed:
                user = fail.get('user', 'unknown')
                failed_users[user] = failed_users.get(user, 0) + 1
            
            if failed_users:
                top_user = max(failed_users.items(), key=lambda x: x[1])
                details.append(f"Usuário mais visado: {top_user[0]} ({top_user[1]} tentativas)")
        
        if successful:
            details.append(f"Logins bem-sucedidos: {len(successful)}")
        
        if sudo:
            # Comandos mais comuns
            commands = {}
            for cmd in sudo:
                command = cmd.get('command', '').split()[0]  # Pegar só o comando base
                commands[command] = commands.get(command, 0) + 1
            
            if commands:
                top_cmd = max(commands.items(), key=lambda x: x[1])
                details.append(f"Comando sudo mais usado: {top_cmd[0]} ({top_cmd[1]}x)")
        
        return details
    
    def _generate_recommendations(self, brute_force: bool, failed: list, suspicious_ips: list) -> list:
        """Gera recomendações de segurança"""
        recommendations = []
        
        if brute_force:
            recommendations.append({
                'title': 'Instalar e Configurar fail2ban',
                'description': 'fail2ban bloqueia automaticamente IPs que fazem múltiplas tentativas de login falhadas.',
                'priority': 'critical',
                'command': 'sudo dnf install -y fail2ban && sudo systemctl enable --now fail2ban'
            })
            
            if suspicious_ips:
                ips_str = ' '.join(suspicious_ips[:5])
                recommendations.append({
                    'title': 'Bloquear IPs Atacantes no Firewall',
                    'description': f'Bloqueie imediatamente os IPs suspeitos identificados.',
                    'priority': 'critical',
                    'command': f'sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address={suspicious_ips[0]} reject"'
                })
        
        if len(failed) > 0:
            recommendations.append({
                'title': 'Revisar Logs de Autenticação',
                'description': 'Analise os logs detalhados para identificar padrões e origens das tentativas falhadas.',
                'priority': 'medium',
                'command': 'sudo journalctl -u sshd -n 100 | grep "Failed"'
            })
        
        if not brute_force and len(failed) == 0:
            recommendations.append({
                'title': 'Manter Boas Práticas',
                'description': 'Continue usando senhas fortes e considere autenticação por chave SSH ao invés de senha.',
                'priority': 'low'
            })
        
        return recommendations

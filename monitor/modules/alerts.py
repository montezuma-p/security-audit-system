"""
Módulo de geração de alertas de segurança
"""
from typing import Dict, List, Any


def generate_alerts(metrics: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Gera alertas baseados nas métricas coletadas"""
    alerts = []
    
    # Alertas de portas
    if "ports" in metrics:
        alerts.extend(_check_ports_alerts(metrics["ports"], config))
    
    # Alertas de autenticação
    if "authentication" in metrics:
        alerts.extend(_check_auth_alerts(metrics["authentication"], config))
    
    # Alertas de firewall
    if "firewall" in metrics:
        alerts.extend(_check_firewall_alerts(metrics["firewall"], config))
    
    # Alertas de vulnerabilidades
    if "vulnerabilities" in metrics:
        alerts.extend(_check_vulnerability_alerts(metrics["vulnerabilities"], config))
    
    # Alertas de rede
    if "network" in metrics:
        alerts.extend(_check_network_alerts(metrics["network"], config))
    
    # Alertas de permissões
    if "permissions" in metrics:
        alerts.extend(_check_permissions_alerts(metrics["permissions"], config))
    
    return alerts


def _check_ports_alerts(ports_data: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Verifica alertas relacionados a portas"""
    alerts = []
    
    # Portas suspeitas
    suspicious = ports_data.get("suspicious_ports", [])
    for port in suspicious:
        if isinstance(port, dict) and "error" not in port:
            severity = port.get("severity", "warning")
            if severity == "critical":
                alerts.append({
                    "category": "ports",
                    "severity": "critical",
                    "message": f"Porta {port.get('port')} exposta publicamente: {port.get('description')}",
                    "details": port
                })
            elif severity == "warning":
                alerts.append({
                    "category": "ports",
                    "severity": "warning",
                    "message": f"Porta suspeita aberta: {port.get('port')} - {port.get('description')}",
                    "details": port
                })
    
    # Muitas portas abertas
    summary = ports_data.get("summary", {})
    listening_count = summary.get("total_listening_ports", 0)
    if listening_count > 20:
        alerts.append({
            "category": "ports",
            "severity": "info",
            "message": f"Muitas portas abertas ({listening_count}). Revisar necessidade de cada uma.",
            "details": {"count": listening_count}
        })
    
    return alerts


def _check_auth_alerts(auth_data: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Verifica alertas relacionados a autenticação"""
    alerts = []
    
    # Força bruta detectada
    brute_force = auth_data.get("brute_force_analysis", {})
    if brute_force.get("brute_force_detected", False):
        suspicious_ips = brute_force.get("suspicious_ips", [])
        
        for ip_info in suspicious_ips[:5]:  # Top 5
            if ip_info.get("severity") == "critical":
                alerts.append({
                    "category": "authentication",
                    "severity": "critical",
                    "message": f"Ataque de força bruta detectado do IP {ip_info.get('ip')} ({ip_info.get('attempts')} tentativas)",
                    "details": ip_info,
                    "recommendation": "Considere bloquear este IP no firewall"
                })
    
    # Configuração SSH insegura
    ssh_config = auth_data.get("ssh_config", {})
    checks = ssh_config.get("checks", [])
    
    for check in checks:
        if isinstance(check, dict) and check.get("severity") == "warning":
            if not check.get("is_secure", True):
                alerts.append({
                    "category": "authentication",
                    "severity": "warning",
                    "message": f"Configuração SSH insegura: {check.get('setting')}",
                    "details": {
                        "current": check.get("current"),
                        "recommended": check.get("recommended")
                    },
                    "recommendation": f"Altere para: {check.get('recommended')}"
                })
    
    # Muitas tentativas de login falhas
    summary = auth_data.get("summary", {})
    failed_count = summary.get("failed_login_attempts", 0)
    
    if failed_count > 50:
        alerts.append({
            "category": "authentication",
            "severity": "warning",
            "message": f"Alto número de tentativas de login falhas ({failed_count} nas últimas 24h)",
            "details": {"count": failed_count}
        })
    
    return alerts


def _check_firewall_alerts(firewall_data: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Verifica alertas relacionados ao firewall"""
    alerts = []
    
    summary = firewall_data.get("summary", {})
    
    # Firewall desativado
    if not summary.get("firewall_active", False):
        alerts.append({
            "category": "firewall",
            "severity": "critical",
            "message": "Firewall não está ativo!",
            "recommendation": "Ative o firewalld: sudo systemctl start firewalld"
        })
    
    # Firewall não habilitado para iniciar automaticamente
    if not summary.get("firewall_enabled", False):
        alerts.append({
            "category": "firewall",
            "severity": "warning",
            "message": "Firewall não está habilitado para iniciar automaticamente",
            "recommendation": "Habilite: sudo systemctl enable firewalld"
        })
    
    # SELinux não está em modo enforcing
    if not summary.get("selinux_enforcing", False):
        selinux = firewall_data.get("selinux", {})
        mode = selinux.get("mode", "unknown")
        
        if mode == "Permissive":
            alerts.append({
                "category": "firewall",
                "severity": "warning",
                "message": "SELinux está em modo Permissive (não está aplicando políticas)",
                "recommendation": "Considere mudar para Enforcing para maior segurança"
            })
        elif mode == "Disabled":
            alerts.append({
                "category": "firewall",
                "severity": "critical",
                "message": "SELinux está desabilitado!",
                "recommendation": "Habilite SELinux para maior segurança do sistema"
            })
    
    # Avisos de configuração de firewall
    warnings = firewall_data.get("security_warnings", [])
    for warning in warnings:
        if isinstance(warning, dict) and "error" not in warning:
            alerts.append({
                "category": "firewall",
                "severity": warning.get("severity", "info"),
                "message": f"Firewall - {warning.get('zone', 'unknown')}: {warning.get('issue', 'unknown')}",
                "details": warning
            })
    
    return alerts


def _check_vulnerability_alerts(vuln_data: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Verifica alertas relacionados a vulnerabilidades"""
    alerts = []
    
    summary = vuln_data.get("summary", {})
    
    # Atualizações de segurança disponíveis
    security_count = summary.get("security_updates_available", 0)
    if security_count > 0:
        severity = "critical" if security_count > 10 else "warning"
        alerts.append({
            "category": "vulnerabilities",
            "severity": severity,
            "message": f"{security_count} atualização(ões) de segurança disponível(is)",
            "recommendation": "Execute: sudo dnf update --security",
            "details": {"count": security_count}
        })
    
    # Reinicialização necessária (kernel atualizado)
    if summary.get("reboot_required", False):
        alerts.append({
            "category": "vulnerabilities",
            "severity": "warning",
            "message": "Reinicialização necessária (kernel atualizado)",
            "recommendation": "Reinicie o sistema para aplicar a atualização do kernel"
        })
    
    # Atualizações automáticas não configuradas
    if not summary.get("automatic_updates_enabled", False):
        alerts.append({
            "category": "vulnerabilities",
            "severity": "info",
            "message": "Atualizações automáticas não estão configuradas",
            "recommendation": "Considere configurar dnf-automatic para atualizações de segurança automáticas"
        })
    
    # Muitas atualizações pendentes em geral
    total_updates = summary.get("total_updates_available", 0)
    if total_updates > 50:
        alerts.append({
            "category": "vulnerabilities",
            "severity": "info",
            "message": f"Sistema desatualizado: {total_updates} pacotes com atualizações disponíveis",
            "recommendation": "Execute: sudo dnf update"
        })
    
    return alerts


def _check_network_alerts(network_data: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Verifica alertas relacionados à rede"""
    alerts = []
    
    summary = network_data.get("summary", {})
    
    # Sem conectividade
    if not summary.get("connectivity_ok", True):
        alerts.append({
            "category": "network",
            "severity": "critical",
            "message": "Problemas de conectividade de rede detectados",
            "details": network_data.get("connectivity", [])
        })
    
    # DNS não funcionando
    if not summary.get("dns_working", True):
        alerts.append({
            "category": "network",
            "severity": "critical",
            "message": "Resolução DNS não está funcionando",
            "recommendation": "Verifique /etc/resolv.conf e conectividade com servidores DNS"
        })
    
    # Gateway inacessível
    if not summary.get("gateway_reachable", True):
        alerts.append({
            "category": "network",
            "severity": "critical",
            "message": "Gateway padrão não está acessível",
            "details": network_data.get("gateway", {})
        })
    
    # Sem acesso à Internet
    if not summary.get("internet_access", True):
        alerts.append({
            "category": "network",
            "severity": "warning",
            "message": "Sem acesso à Internet",
            "recommendation": "Verifique conectividade de rede e configurações de gateway"
        })
    
    # Problemas de segurança de rede
    security_issues = network_data.get("security_checks", [])
    for issue in security_issues:
        if isinstance(issue, dict) and issue.get("severity") == "warning":
            alerts.append({
                "category": "network",
                "severity": "warning",
                "message": f"Configuração de rede insegura: {issue.get('check')}",
                "details": issue
            })
    
    # Erros em interfaces de rede
    interfaces = network_data.get("interfaces", [])
    for interface in interfaces:
        if isinstance(interface, dict) and "statistics" in interface:
            stats = interface["statistics"]
            errors_total = stats.get("errors_in", 0) + stats.get("errors_out", 0)
            drops_total = stats.get("drops_in", 0) + stats.get("drops_out", 0)
            
            if errors_total > 100:
                alerts.append({
                    "category": "network",
                    "severity": "warning",
                    "message": f"Interface {interface.get('name')} com muitos erros ({errors_total})",
                    "details": stats
                })
            
            if drops_total > 100:
                alerts.append({
                    "category": "network",
                    "severity": "info",
                    "message": f"Interface {interface.get('name')} com pacotes descartados ({drops_total})",
                    "details": stats
                })
    
    return alerts


def _check_permissions_alerts(perms_data: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Verifica alertas relacionados a permissões"""
    alerts = []
    
    summary = perms_data.get("summary", {})
    
    # Problemas críticos de permissão
    if summary.get("has_critical_issues", False):
        critical_count = summary.get("critical_permission_issues", 0)
        alerts.append({
            "category": "permissions",
            "severity": "critical",
            "message": f"{critical_count} problema(s) crítico(s) de permissão encontrado(s)",
            "recommendation": "Verifique permissões de arquivos críticos do sistema",
            "details": perms_data.get("critical_file_permissions", [])
        })
    
    # Arquivos world-writable
    writable_count = summary.get("world_writable_found", 0)
    if writable_count > 0:
        alerts.append({
            "category": "permissions",
            "severity": "warning",
            "message": f"{writable_count} arquivo(s) world-writable encontrado(s) em diretórios críticos",
            "recommendation": "Revise e corrija permissões destes arquivos",
            "details": perms_data.get("world_writable_files", [])[:5]
        })
    
    # Problemas com chaves SSH
    ssh_issues = summary.get("ssh_key_issues", 0)
    if ssh_issues > 0:
        ssh_perms = perms_data.get("ssh_key_permissions", [])
        for issue in ssh_perms:
            if isinstance(issue, dict) and issue.get("severity") == "critical":
                alerts.append({
                    "category": "permissions",
                    "severity": "critical",
                    "message": f"Chave SSH com permissões incorretas: {issue.get('path')}",
                    "details": issue,
                    "recommendation": f"Execute: chmod {issue.get('expected_permissions')} {issue.get('path')}"
                })
    
    # Muitos arquivos SUID
    suid_count = summary.get("suid_files_found", 0)
    if suid_count > 100:
        alerts.append({
            "category": "permissions",
            "severity": "info",
            "message": f"Muitos arquivos SUID encontrados ({suid_count})",
            "recommendation": "Revise arquivos SUID e remova bits desnecessários"
        })
    
    return alerts

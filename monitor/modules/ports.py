"""
Módulo de monitoramento de portas e serviços
"""
import subprocess
import psutil
import socket
from typing import Dict, List, Any


def get_listening_ports() -> List[Dict[str, Any]]:
    """Obtém todas as portas em estado LISTEN"""
    listening_ports = []
    
    try:
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            if conn.status == 'LISTEN':
                # Obter informações do processo
                process_info = "unknown"
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        process_info = {
                            "pid": conn.pid,
                            "name": proc.name(),
                            "cmdline": " ".join(proc.cmdline()[:3])  # Limitar tamanho
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_info = {"pid": conn.pid, "name": "unknown"}
                
                port_info = {
                    "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                    "local_address": conn.laddr.ip if conn.laddr else "0.0.0.0",
                    "port": conn.laddr.port if conn.laddr else 0,
                    "process": process_info
                }
                
                listening_ports.append(port_info)
                
    except (psutil.AccessDenied, PermissionError):
        return [{"error": "Permissão negada. Execute com sudo para ver todas as portas."}]
    
    # Ordenar por porta
    listening_ports.sort(key=lambda x: x.get('port', 0))
    
    return listening_ports


def get_established_connections() -> Dict[str, Any]:
    """Obtém conexões estabelecidas e estatísticas"""
    connections_data = {
        "total": 0,
        "by_remote_ip": {},
        "by_process": {},
        "top_remote_ips": []
    }
    
    try:
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                connections_data["total"] += 1
                
                remote_ip = conn.raddr.ip
                
                # Contar por IP remoto
                if remote_ip not in connections_data["by_remote_ip"]:
                    connections_data["by_remote_ip"][remote_ip] = 0
                connections_data["by_remote_ip"][remote_ip] += 1
                
                # Contar por processo
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                        if proc_name not in connections_data["by_process"]:
                            connections_data["by_process"][proc_name] = 0
                        connections_data["by_process"][proc_name] += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        
        # Top IPs remotos
        sorted_ips = sorted(
            connections_data["by_remote_ip"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        connections_data["top_remote_ips"] = [
            {"ip": ip, "connections": count}
            for ip, count in sorted_ips
        ]
        
        # Remover dicionário completo para economizar espaço
        del connections_data["by_remote_ip"]
        
    except (psutil.AccessDenied, PermissionError):
        connections_data["error"] = "Permissão negada"
    
    return connections_data


def check_suspicious_ports() -> List[Dict[str, Any]]:
    """Verifica portas comumente usadas em ataques"""
    suspicious_ports = {
        22: "SSH - Alvo comum de ataques de força bruta",
        23: "Telnet - Protocolo inseguro (não criptografado)",
        3306: "MySQL - Não deve estar exposto publicamente",
        5432: "PostgreSQL - Não deve estar exposto publicamente",
        6379: "Redis - Não deve estar exposto publicamente",
        27017: "MongoDB - Não deve estar exposto publicamente",
        3389: "RDP - Alvo de ataques",
        445: "SMB - Vulnerável a ataques",
        1433: "MS SQL Server - Não deve estar exposto",
        5900: "VNC - Não deve estar exposto"
    }
    
    alerts = []
    
    try:
        connections = psutil.net_connections(kind='inet')
        listening_ports = set()
        
        for conn in connections:
            if conn.status == 'LISTEN' and conn.laddr:
                listening_ports.add(conn.laddr.port)
        
        for port, description in suspicious_ports.items():
            if port in listening_ports:
                # Verificar se está escutando em todas as interfaces (0.0.0.0)
                for conn in connections:
                    if (conn.status == 'LISTEN' and 
                        conn.laddr and 
                        conn.laddr.port == port):
                        
                        is_public = conn.laddr.ip in ['0.0.0.0', '::']
                        
                        alerts.append({
                            "port": port,
                            "description": description,
                            "listening_on": conn.laddr.ip,
                            "is_public": is_public,
                            "severity": "critical" if is_public else "warning"
                        })
                        break
    except Exception as e:
        alerts.append({"error": str(e)})
    
    return alerts


def get_network_services() -> List[Dict[str, Any]]:
    """Lista serviços de rede ativos via systemctl"""
    services = []
    
    network_services = [
        'sshd',
        'httpd',
        'nginx',
        'apache2',
        'mysqld',
        'postgresql',
        'redis',
        'mongod',
        'docker',
        'firewalld',
        'NetworkManager',
        'smb',
        'nmb',
        'vsftpd'
    ]
    
    for service in network_services:
        try:
            # Verificar se o serviço está ativo
            result = subprocess.run(
                ['systemctl', 'is-active', service],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.stdout.strip() == 'active':
                # Obter informações adicionais
                status_result = subprocess.run(
                    ['systemctl', 'status', service, '--no-pager', '-l'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                services.append({
                    "name": service,
                    "status": "active",
                    "enabled": _is_service_enabled(service)
                })
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
    
    return services


def _is_service_enabled(service: str) -> bool:
    """Verifica se um serviço está habilitado"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-enabled', service],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip() == 'enabled'
    except Exception:
        return False


def collect_ports_metrics(config: Dict[str, Any]) -> Dict[str, Any]:
    """Coleta todas as métricas de portas e serviços"""
    metrics = {}
    
    if config.get("monitoring", {}).get("check_listening_ports", True):
        metrics["listening_ports"] = get_listening_ports()
    
    if config.get("monitoring", {}).get("check_connections", True):
        metrics["established_connections"] = get_established_connections()
    
    if config.get("monitoring", {}).get("check_suspicious_ports", True):
        metrics["suspicious_ports"] = check_suspicious_ports()
    
    if config.get("monitoring", {}).get("check_network_services", True):
        metrics["network_services"] = get_network_services()
    
    # Estatísticas gerais
    listening_count = len([p for p in metrics.get("listening_ports", []) if "error" not in p])
    metrics["summary"] = {
        "total_listening_ports": listening_count,
        "total_connections": metrics.get("established_connections", {}).get("total", 0),
        "suspicious_ports_found": len(metrics.get("suspicious_ports", [])),
        "active_network_services": len(metrics.get("network_services", []))
    }
    
    return metrics

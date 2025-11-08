"""
Módulo de monitoramento de autenticação e acessos
"""
import subprocess
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any


def get_failed_login_attempts(hours: int = 24) -> List[Dict[str, Any]]:
    """Obtém tentativas de login falhas do journalctl"""
    failed_logins = []
    
    try:
        since_time = datetime.now() - timedelta(hours=hours)
        since_str = since_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Buscar por falhas de autenticação SSH
        result = subprocess.run(
            ['journalctl', '-u', 'sshd', '--since', since_str, '--no-pager'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                # Padrões comuns de falha de SSH
                if 'Failed password' in line or 'Invalid user' in line:
                    # Extrair IP se possível
                    ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                    user_match = re.search(r'for\s+(\w+)', line)
                    
                    failed_logins.append({
                        "timestamp": line.split()[0:3],  # Data/hora aproximada
                        "type": "ssh",
                        "user": user_match.group(1) if user_match else "unknown",
                        "source_ip": ip_match.group(1) if ip_match else "unknown",
                        "message": line.strip()[:200]
                    })
    except subprocess.TimeoutExpired:
        failed_logins.append({"error": "Timeout ao buscar logs SSH"})
    except FileNotFoundError:
        failed_logins.append({"error": "journalctl não encontrado"})
    except Exception as e:
        failed_logins.append({"error": str(e)})
    
    # Limitar a 100 entradas mais recentes
    return failed_logins[-100:]


def get_successful_logins(hours: int = 24) -> List[Dict[str, Any]]:
    """Obtém logins bem-sucedidos recentes"""
    successful_logins = []
    
    try:
        since_time = datetime.now() - timedelta(hours=hours)
        since_str = since_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Buscar logins bem-sucedidos via SSH
        result = subprocess.run(
            ['journalctl', '-u', 'sshd', '--since', since_str, '--no-pager'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Accepted password' in line or 'Accepted publickey' in line:
                    ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                    user_match = re.search(r'for\s+(\w+)', line)
                    
                    auth_type = "password" if "password" in line else "publickey"
                    
                    successful_logins.append({
                        "timestamp": " ".join(line.split()[0:3]),
                        "type": "ssh",
                        "auth_method": auth_type,
                        "user": user_match.group(1) if user_match else "unknown",
                        "source_ip": ip_match.group(1) if ip_match else "unknown"
                    })
    except Exception as e:
        successful_logins.append({"error": str(e)})
    
    return successful_logins[-50:]  # Últimos 50


def get_sudo_usage(hours: int = 24) -> List[Dict[str, Any]]:
    """Obtém uso de sudo recente"""
    sudo_commands = []
    
    try:
        since_time = datetime.now() - timedelta(hours=hours)
        since_str = since_time.strftime('%Y-%m-%d %H:%M:%S')
        
        result = subprocess.run(
            ['journalctl', '_COMM=sudo', '--since', since_str, '--no-pager'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                # Extrair comandos sudo
                if 'COMMAND=' in line:
                    user_match = re.search(r'USER=(\w+)', line)
                    cmd_match = re.search(r'COMMAND=(.+)$', line)
                    
                    sudo_commands.append({
                        "timestamp": " ".join(line.split()[0:3]),
                        "user": user_match.group(1) if user_match else "unknown",
                        "command": cmd_match.group(1) if cmd_match else "unknown"
                    })
    except Exception as e:
        sudo_commands.append({"error": str(e)})
    
    return sudo_commands[-50:]


def analyze_brute_force_attempts(failed_logins: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analisa tentativas de força bruta baseado em IPs"""
    ip_attempts = {}
    
    for login in failed_logins:
        if isinstance(login, dict) and 'source_ip' in login:
            ip = login['source_ip']
            if ip != 'unknown' and 'error' not in login:
                if ip not in ip_attempts:
                    ip_attempts[ip] = {
                        'count': 0,
                        'users_attempted': set()
                    }
                ip_attempts[ip]['count'] += 1
                if 'user' in login:
                    ip_attempts[ip]['users_attempted'].add(login['user'])
    
    # Identificar IPs suspeitos (mais de 5 tentativas)
    suspicious_ips = []
    for ip, data in ip_attempts.items():
        if data['count'] >= 5:
            suspicious_ips.append({
                "ip": ip,
                "attempts": data['count'],
                "users_attempted": list(data['users_attempted']),
                "severity": "critical" if data['count'] > 20 else "warning"
            })
    
    # Ordenar por número de tentativas
    suspicious_ips.sort(key=lambda x: x['attempts'], reverse=True)
    
    return {
        "total_unique_ips": len(ip_attempts),
        "suspicious_ips": suspicious_ips[:20],  # Top 20
        "brute_force_detected": len(suspicious_ips) > 0
    }


def get_active_sessions() -> List[Dict[str, Any]]:
    """Obtém sessões de usuários ativas"""
    sessions = []
    
    try:
        # Usando 'w' para listar usuários logados
        result = subprocess.run(
            ['w', '-h'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        sessions.append({
                            "user": parts[0],
                            "tty": parts[1],
                            "from": parts[2] if len(parts) > 2 else "local",
                            "login_time": parts[3] if len(parts) > 3 else "unknown"
                        })
    except Exception as e:
        sessions.append({"error": str(e)})
    
    return sessions


def check_ssh_config_security() -> Dict[str, Any]:
    """Verifica configurações de segurança do SSH"""
    config_checks = {
        "config_file": "/etc/ssh/sshd_config",
        "checks": []
    }
    
    try:
        with open('/etc/ssh/sshd_config', 'r') as f:
            config_content = f.read()
        
        # Verificações de segurança
        checks = {
            "PermitRootLogin": {
                "secure_value": "no",
                "check": lambda x: "PermitRootLogin" in x and "no" in x.lower()
            },
            "PasswordAuthentication": {
                "secure_value": "no (use keys)",
                "check": lambda x: "PasswordAuthentication" in x and "no" in x.lower()
            },
            "PermitEmptyPasswords": {
                "secure_value": "no",
                "check": lambda x: "PermitEmptyPasswords" in x and "no" in x.lower()
            },
            "Protocol": {
                "secure_value": "2",
                "check": lambda x: "Protocol" in x and "2" in x
            }
        }
        
        for setting, info in checks.items():
            lines = [line for line in config_content.split('\n') if setting in line and not line.strip().startswith('#')]
            
            is_secure = False
            current_value = "not set"
            
            if lines:
                current_value = lines[0].strip()
                is_secure = info["check"](current_value)
            
            config_checks["checks"].append({
                "setting": setting,
                "current": current_value,
                "recommended": info["secure_value"],
                "is_secure": is_secure,
                "severity": "warning" if not is_secure else "ok"
            })
            
    except FileNotFoundError:
        config_checks["error"] = "Arquivo sshd_config não encontrado"
    except PermissionError:
        config_checks["error"] = "Permissão negada para ler sshd_config"
    except Exception as e:
        config_checks["error"] = str(e)
    
    return config_checks


def collect_auth_metrics(config: Dict[str, Any]) -> Dict[str, Any]:
    """Coleta todas as métricas de autenticação"""
    metrics = {}
    
    hours = config.get("monitoring", {}).get("auth_check_hours", 24)
    
    if config.get("monitoring", {}).get("check_failed_logins", True):
        failed_logins = get_failed_login_attempts(hours)
        metrics["failed_logins"] = failed_logins
        metrics["brute_force_analysis"] = analyze_brute_force_attempts(failed_logins)
    
    if config.get("monitoring", {}).get("check_successful_logins", True):
        metrics["successful_logins"] = get_successful_logins(hours)
    
    if config.get("monitoring", {}).get("check_sudo_usage", True):
        metrics["sudo_usage"] = get_sudo_usage(hours)
    
    if config.get("monitoring", {}).get("check_active_sessions", True):
        metrics["active_sessions"] = get_active_sessions()
    
    if config.get("monitoring", {}).get("check_ssh_config", True):
        metrics["ssh_config"] = check_ssh_config_security()
    
    # Resumo
    metrics["summary"] = {
        "failed_login_attempts": len([l for l in metrics.get("failed_logins", []) if "error" not in l]),
        "successful_logins": len([l for l in metrics.get("successful_logins", []) if "error" not in l]),
        "brute_force_detected": metrics.get("brute_force_analysis", {}).get("brute_force_detected", False),
        "suspicious_ips_count": len(metrics.get("brute_force_analysis", {}).get("suspicious_ips", [])),
        "active_sessions": len([s for s in metrics.get("active_sessions", []) if "error" not in s])
    }
    
    return metrics

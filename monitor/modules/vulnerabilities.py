"""
Módulo de verificação de vulnerabilidades e atualizações de segurança
"""
import subprocess
import re
from typing import Dict, List, Any


def get_security_updates() -> Dict[str, Any]:
    """Obtém atualizações de segurança disponíveis"""
    security_updates = {
        "available": [],
        "count": 0
    }
    
    try:
        # Verificar atualizações de segurança via DNF
        result = subprocess.run(
            ['dnf', 'updateinfo', 'list', 'security', '--available'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                # Formato típico: FEDORA-2024-xxxxx Important/Sec. package-version
                if line.strip() and not line.startswith('Last metadata') and 'UpdateInfo' not in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        security_updates["available"].append({
                            "advisory": parts[0] if len(parts) > 0 else "unknown",
                            "severity": parts[1] if len(parts) > 1 else "unknown",
                            "package": " ".join(parts[2:]) if len(parts) > 2 else "unknown"
                        })
            
            security_updates["count"] = len(security_updates["available"])
            
    except subprocess.TimeoutExpired:
        security_updates["error"] = "Timeout ao verificar atualizações"
    except FileNotFoundError:
        security_updates["error"] = "DNF não encontrado"
    except Exception as e:
        security_updates["error"] = str(e)
    
    return security_updates


def get_all_updates() -> Dict[str, Any]:
    """Obtém todas as atualizações disponíveis"""
    updates = {
        "total_packages": 0,
        "packages": []
    }
    
    try:
        result = subprocess.run(
            ['dnf', 'check-update', '--quiet'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # check-update retorna 100 quando há atualizações disponíveis
        if result.returncode == 100 or result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                if line.strip() and not line.startswith('Last metadata'):
                    parts = line.split()
                    if len(parts) >= 2:
                        updates["packages"].append({
                            "name": parts[0],
                            "version": parts[1] if len(parts) > 1 else "unknown",
                            "repo": parts[2] if len(parts) > 2 else "unknown"
                        })
            
            updates["total_packages"] = len(updates["packages"])
            
    except subprocess.TimeoutExpired:
        updates["error"] = "Timeout ao verificar atualizações"
    except Exception as e:
        updates["error"] = str(e)
    
    return updates


def check_kernel_version() -> Dict[str, Any]:
    """Verifica se o kernel está atualizado"""
    kernel_info = {
        "running": "",
        "latest_installed": "",
        "reboot_required": False
    }
    
    try:
        # Kernel em execução
        result = subprocess.run(
            ['uname', '-r'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            kernel_info["running"] = result.stdout.strip()
        
        # Último kernel instalado
        result = subprocess.run(
            ['rpm', '-q', '--last', 'kernel'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if lines:
                # Primeira linha é o mais recente
                latest = lines[0].split()[0]
                kernel_info["latest_installed"] = latest.replace('kernel-', '')
                
                # Verificar se precisa reiniciar
                if kernel_info["running"] not in kernel_info["latest_installed"]:
                    kernel_info["reboot_required"] = True
                    
    except Exception as e:
        kernel_info["error"] = str(e)
    
    return kernel_info


def check_vulnerable_packages() -> List[Dict[str, Any]]:
    """Verifica pacotes com vulnerabilidades conhecidas"""
    vulnerable = []
    
    try:
        # Usar dnf updateinfo para listar CVEs
        result = subprocess.run(
            ['dnf', 'updateinfo', 'list', 'sec', '--available'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                if 'CVE' in line or 'FEDORA' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        vulnerable.append({
                            "advisory": parts[0],
                            "type": parts[1],
                            "packages": " ".join(parts[2:]) if len(parts) > 2 else "unknown"
                        })
                        
    except Exception as e:
        vulnerable.append({"error": str(e)})
    
    return vulnerable[:50]  # Limitar a 50


def get_system_age() -> Dict[str, Any]:
    """Calcula há quanto tempo o sistema não é atualizado"""
    from datetime import datetime
    
    age_info = {
        "last_update": None,
        "days_since_update": None
    }
    
    try:
        # Verificar timestamp do último update do DNF
        result = subprocess.run(
            ['dnf', 'history', '--reverse', '|', 'head', '-n', '1'],
            capture_output=True,
            text=True,
            shell=True,
            timeout=15
        )
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            # Procurar por linhas com data
            for line in lines:
                if '|' in line and any(char.isdigit() for char in line):
                    parts = line.split('|')
                    if len(parts) >= 3:
                        date_str = parts[2].strip()
                        age_info["last_update"] = date_str
                        break
    except Exception as e:
        age_info["error"] = str(e)
    
    return age_info


def check_automatic_updates() -> Dict[str, Any]:
    """Verifica se atualizações automáticas estão configuradas"""
    auto_update = {
        "configured": False,
        "service": "dnf-automatic"
    }
    
    try:
        # Verificar se dnf-automatic está ativo
        result = subprocess.run(
            ['systemctl', 'is-active', 'dnf-automatic.timer'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        auto_update["active"] = result.stdout.strip() == 'active'
        
        # Verificar se está habilitado
        result = subprocess.run(
            ['systemctl', 'is-enabled', 'dnf-automatic.timer'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        auto_update["enabled"] = result.stdout.strip() == 'enabled'
        auto_update["configured"] = auto_update.get("active", False) or auto_update.get("enabled", False)
        
    except FileNotFoundError:
        auto_update["error"] = "systemctl não encontrado"
    except Exception as e:
        auto_update["error"] = str(e)
    
    return auto_update


def collect_vulnerability_metrics(config: Dict[str, Any]) -> Dict[str, Any]:
    """Coleta todas as métricas de vulnerabilidades"""
    metrics = {}
    
    if config.get("monitoring", {}).get("check_security_updates", True):
        metrics["security_updates"] = get_security_updates()
    
    if config.get("monitoring", {}).get("check_all_updates", True):
        metrics["all_updates"] = get_all_updates()
    
    if config.get("monitoring", {}).get("check_kernel", True):
        metrics["kernel"] = check_kernel_version()
    
    if config.get("monitoring", {}).get("check_vulnerable_packages", True):
        metrics["vulnerable_packages"] = check_vulnerable_packages()
    
    if config.get("monitoring", {}).get("check_automatic_updates", True):
        metrics["automatic_updates"] = check_automatic_updates()
    
    # Resumo
    metrics["summary"] = {
        "security_updates_available": metrics.get("security_updates", {}).get("count", 0),
        "total_updates_available": metrics.get("all_updates", {}).get("total_packages", 0),
        "reboot_required": metrics.get("kernel", {}).get("reboot_required", False),
        "automatic_updates_enabled": metrics.get("automatic_updates", {}).get("configured", False),
        "has_critical_vulnerabilities": metrics.get("security_updates", {}).get("count", 0) > 0
    }
    
    return metrics

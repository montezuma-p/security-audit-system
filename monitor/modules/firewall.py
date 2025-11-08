"""
Módulo de monitoramento de firewall
"""
import subprocess
import re
from typing import Dict, List, Any


def get_firewalld_status() -> Dict[str, Any]:
    """Obtém status do firewalld"""
    status = {
        "service": "firewalld",
        "running": False,
        "enabled": False
    }
    
    try:
        # Verificar se está ativo
        result = subprocess.run(
            ['systemctl', 'is-active', 'firewalld'],
            capture_output=True,
            text=True,
            timeout=5
        )
        status["running"] = result.stdout.strip() == 'active'
        
        # Verificar se está habilitado
        result = subprocess.run(
            ['systemctl', 'is-enabled', 'firewalld'],
            capture_output=True,
            text=True,
            timeout=5
        )
        status["enabled"] = result.stdout.strip() == 'enabled'
        
    except FileNotFoundError:
        status["error"] = "systemctl não encontrado"
    except Exception as e:
        status["error"] = str(e)
    
    return status


def get_firewall_zones() -> List[Dict[str, Any]]:
    """Obtém zonas do firewall e suas configurações"""
    zones = []
    
    try:
        # Listar zonas ativas
        result = subprocess.run(
            ['firewall-cmd', '--get-active-zones'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            current_zone = None
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('interfaces:') and not line.startswith('sources:'):
                    current_zone = line
                elif current_zone:
                    # Obter detalhes da zona
                    zone_info = get_zone_details(current_zone)
                    if zone_info:
                        zones.append(zone_info)
                    current_zone = None
                    
    except FileNotFoundError:
        zones.append({"error": "firewall-cmd não encontrado"})
    except Exception as e:
        zones.append({"error": str(e)})
    
    return zones


def get_zone_details(zone_name: str) -> Dict[str, Any]:
    """Obtém detalhes de uma zona específica"""
    zone_info = {
        "name": zone_name,
        "services": [],
        "ports": [],
        "interfaces": [],
        "target": "default"
    }
    
    try:
        # Listar serviços
        result = subprocess.run(
            ['firewall-cmd', f'--zone={zone_name}', '--list-services'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            zone_info["services"] = result.stdout.strip().split()
        
        # Listar portas
        result = subprocess.run(
            ['firewall-cmd', f'--zone={zone_name}', '--list-ports'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            zone_info["ports"] = result.stdout.strip().split()
        
        # Listar interfaces
        result = subprocess.run(
            ['firewall-cmd', f'--zone={zone_name}', '--list-interfaces'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            zone_info["interfaces"] = result.stdout.strip().split()
        
        # Obter target
        result = subprocess.run(
            ['firewall-cmd', f'--zone={zone_name}', '--get-target'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            zone_info["target"] = result.stdout.strip()
            
    except Exception as e:
        zone_info["error"] = str(e)
    
    return zone_info


def get_default_zone() -> str:
    """Obtém a zona padrão"""
    try:
        result = subprocess.run(
            ['firewall-cmd', '--get-default-zone'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    
    return "unknown"


def check_firewall_rules() -> List[Dict[str, Any]]:
    """Verifica regras potencialmente inseguras"""
    warnings = []
    
    try:
        # Obter zonas
        zones_result = subprocess.run(
            ['firewall-cmd', '--get-active-zones'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if zones_result.returncode == 0:
            zones = [line.strip() for line in zones_result.stdout.split('\n') 
                    if line.strip() and not line.startswith('interfaces:') and not line.startswith('sources:')]
            
            for zone in zones:
                # Verificar se a zona tem target ACCEPT (muito permissivo)
                target_result = subprocess.run(
                    ['firewall-cmd', f'--zone={zone}', '--get-target'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if target_result.returncode == 0 and 'ACCEPT' in target_result.stdout:
                    warnings.append({
                        "zone": zone,
                        "issue": "Target set to ACCEPT (muito permissivo)",
                        "severity": "warning",
                        "recommendation": "Configurar regras específicas ao invés de ACCEPT geral"
                    })
                
                # Verificar se há muitas portas abertas
                ports_result = subprocess.run(
                    ['firewall-cmd', f'--zone={zone}', '--list-ports'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if ports_result.returncode == 0:
                    ports = ports_result.stdout.strip().split()
                    if len(ports) > 10:
                        warnings.append({
                            "zone": zone,
                            "issue": f"Muitas portas abertas ({len(ports)})",
                            "severity": "info",
                            "ports": ports[:10]  # Mostrar apenas as primeiras 10
                        })
                        
    except Exception as e:
        warnings.append({"error": str(e)})
    
    return warnings


def get_rich_rules() -> List[str]:
    """Obtém regras ricas (rich rules) configuradas"""
    rich_rules = []
    
    try:
        zones = get_firewall_zones()
        
        for zone in zones:
            if isinstance(zone, dict) and 'name' in zone:
                result = subprocess.run(
                    ['firewall-cmd', f'--zone={zone["name"]}', '--list-rich-rules'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    for rule in result.stdout.strip().split('\n'):
                        rich_rules.append({
                            "zone": zone["name"],
                            "rule": rule
                        })
    except Exception as e:
        rich_rules.append({"error": str(e)})
    
    return rich_rules


def check_selinux_status() -> Dict[str, Any]:
    """Verifica status do SELinux"""
    selinux = {
        "enabled": False,
        "mode": "unknown",
        "policy": "unknown"
    }
    
    try:
        result = subprocess.run(
            ['getenforce'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            mode = result.stdout.strip()
            selinux["mode"] = mode
            selinux["enabled"] = mode != "Disabled"
            
            # Se estiver habilitado, verificar política
            if selinux["enabled"]:
                status_result = subprocess.run(
                    ['sestatus'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if status_result.returncode == 0:
                    for line in status_result.stdout.split('\n'):
                        if 'Policy' in line:
                            selinux["policy"] = line.split(':')[1].strip()
                            break
    except FileNotFoundError:
        selinux["error"] = "SELinux não instalado ou getenforce não encontrado"
    except Exception as e:
        selinux["error"] = str(e)
    
    return selinux


def collect_firewall_metrics(config: Dict[str, Any]) -> Dict[str, Any]:
    """Coleta todas as métricas de firewall"""
    metrics = {}
    
    if config.get("monitoring", {}).get("check_firewall", True):
        metrics["status"] = get_firewalld_status()
        
        if metrics["status"].get("running"):
            metrics["default_zone"] = get_default_zone()
            metrics["zones"] = get_firewall_zones()
            metrics["security_warnings"] = check_firewall_rules()
            metrics["rich_rules"] = get_rich_rules()
    
    if config.get("monitoring", {}).get("check_selinux", True):
        metrics["selinux"] = check_selinux_status()
    
    # Resumo
    metrics["summary"] = {
        "firewall_active": metrics.get("status", {}).get("running", False),
        "firewall_enabled": metrics.get("status", {}).get("enabled", False),
        "selinux_enforcing": metrics.get("selinux", {}).get("mode") == "Enforcing",
        "total_zones": len([z for z in metrics.get("zones", []) if isinstance(z, dict) and "error" not in z]),
        "security_warnings": len(metrics.get("security_warnings", []))
    }
    
    return metrics

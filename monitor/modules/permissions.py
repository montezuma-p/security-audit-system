"""
Módulo de verificação de permissões e arquivos suspeitos
"""
import subprocess
import os
from pathlib import Path
from typing import Dict, List, Any


def find_suid_files() -> List[Dict[str, Any]]:
    """Encontra arquivos com SUID bit setado"""
    suid_files = []
    
    try:
        # Procurar arquivos SUID em diretórios críticos
        search_paths = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin']
        
        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue
                
            result = subprocess.run(
                ['find', search_path, '-type', 'f', '-perm', '-4000', '-ls'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 11:
                        filepath = " ".join(parts[10:])
                        suid_files.append({
                            "path": filepath,
                            "permissions": parts[2],
                            "owner": parts[4],
                            "size": parts[6]
                        })
    except subprocess.TimeoutExpired:
        suid_files.append({"error": "Timeout ao procurar arquivos SUID"})
    except Exception as e:
        suid_files.append({"error": str(e)})
    
    return suid_files[:100]  # Limitar a 100


def find_sgid_files() -> List[Dict[str, Any]]:
    """Encontra arquivos com SGID bit setado"""
    sgid_files = []
    
    try:
        search_paths = ['/bin', '/sbin', '/usr/bin', '/usr/sbin']
        
        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue
                
            result = subprocess.run(
                ['find', search_path, '-type', 'f', '-perm', '-2000', '-ls'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 11:
                        filepath = " ".join(parts[10:])
                        sgid_files.append({
                            "path": filepath,
                            "permissions": parts[2],
                            "group": parts[5]
                        })
    except Exception as e:
        sgid_files.append({"error": str(e)})
    
    return sgid_files[:50]


def find_world_writable_files() -> List[Dict[str, Any]]:
    """Encontra arquivos world-writable em diretórios críticos"""
    writable_files = []
    
    try:
        # Procurar em diretórios críticos
        search_paths = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin']
        
        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue
                
            result = subprocess.run(
                ['find', search_path, '-type', 'f', '-perm', '-002', '!', '-type', 'l', '-ls'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n')[:20]:  # Limitar durante busca
                    parts = line.split()
                    if len(parts) >= 11:
                        filepath = " ".join(parts[10:])
                        writable_files.append({
                            "path": filepath,
                            "permissions": parts[2],
                            "severity": "warning"
                        })
    except Exception as e:
        writable_files.append({"error": str(e)})
    
    return writable_files[:30]


def check_critical_file_permissions() -> List[Dict[str, Any]]:
    """Verifica permissões de arquivos críticos do sistema"""
    critical_files = {
        "/etc/passwd": {"expected": "644", "description": "User database"},
        "/etc/shadow": {"expected": "000", "description": "Password hashes"},
        "/etc/group": {"expected": "644", "description": "Group database"},
        "/etc/gshadow": {"expected": "000", "description": "Group passwords"},
        "/etc/ssh/sshd_config": {"expected": "600", "description": "SSH daemon config"},
        "/root": {"expected": "700", "description": "Root home directory"},
        "/boot/grub2/grub.cfg": {"expected": "600", "description": "GRUB config"}
    }
    
    checks = []
    
    for filepath, info in critical_files.items():
        if not os.path.exists(filepath):
            continue
        
        try:
            stat_info = os.stat(filepath)
            current_perms = oct(stat_info.st_mode)[-3:]
            
            is_secure = current_perms == info["expected"] or (
                info["expected"] == "000" and current_perms in ["000", "400", "440"]
            )
            
            checks.append({
                "file": filepath,
                "description": info["description"],
                "current_permissions": current_perms,
                "expected_permissions": info["expected"],
                "is_secure": is_secure,
                "severity": "critical" if not is_secure else "ok"
            })
        except Exception as e:
            checks.append({
                "file": filepath,
                "error": str(e)
            })
    
    return checks


def check_home_directory_permissions() -> List[Dict[str, Any]]:
    """Verifica permissões de diretórios home dos usuários"""
    issues = []
    
    try:
        # Listar usuários do sistema
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 6:
                    username = parts[0]
                    home_dir = parts[5]
                    uid = int(parts[2])
                    
                    # Verificar apenas usuários normais (UID >= 1000) e root
                    if uid < 1000 and uid != 0:
                        continue
                    
                    if not os.path.exists(home_dir):
                        continue
                    
                    try:
                        stat_info = os.stat(home_dir)
                        perms = oct(stat_info.st_mode)[-3:]
                        
                        # Home directories devem ser 700 ou 755
                        if perms not in ['700', '750', '755']:
                            issues.append({
                                "user": username,
                                "home_dir": home_dir,
                                "permissions": perms,
                                "recommended": "700 or 755",
                                "severity": "warning"
                            })
                    except Exception:
                        pass
    except Exception as e:
        issues.append({"error": str(e)})
    
    return issues[:20]


def find_unowned_files() -> List[Dict[str, Any]]:
    """Encontra arquivos sem dono (podem indicar problemas)"""
    unowned = []
    
    try:
        # Procurar arquivos sem dono em /home
        result = subprocess.run(
            ['find', '/home', '-nouser', '-o', '-nogroup', '-ls'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split('\n')[:30]:
                parts = line.split()
                if len(parts) >= 11:
                    filepath = " ".join(parts[10:])
                    unowned.append({
                        "path": filepath,
                        "permissions": parts[2],
                        "severity": "info"
                    })
    except subprocess.TimeoutExpired:
        unowned.append({"error": "Timeout"})
    except Exception as e:
        unowned.append({"error": str(e)})
    
    return unowned


def check_ssh_key_permissions() -> List[Dict[str, Any]]:
    """Verifica permissões de chaves SSH"""
    issues = []
    
    try:
        home_dir = Path.home()
        ssh_dir = home_dir / '.ssh'
        
        if ssh_dir.exists():
            # Verificar diretório .ssh
            ssh_dir_perms = oct(os.stat(ssh_dir).st_mode)[-3:]
            if ssh_dir_perms != '700':
                issues.append({
                    "path": str(ssh_dir),
                    "type": "directory",
                    "current_permissions": ssh_dir_perms,
                    "expected_permissions": "700",
                    "severity": "warning"
                })
            
            # Verificar chaves privadas
            for key_file in ssh_dir.glob('id_*'):
                if not key_file.name.endswith('.pub'):
                    key_perms = oct(os.stat(key_file).st_mode)[-3:]
                    if key_perms not in ['600', '400']:
                        issues.append({
                            "path": str(key_file),
                            "type": "private_key",
                            "current_permissions": key_perms,
                            "expected_permissions": "600",
                            "severity": "critical"
                        })
    except Exception as e:
        issues.append({"error": str(e)})
    
    return issues


def collect_permissions_metrics(config: Dict[str, Any]) -> Dict[str, Any]:
    """Coleta todas as métricas de permissões"""
    metrics = {}
    
    if config.get("monitoring", {}).get("check_suid_files", True):
        metrics["suid_files"] = find_suid_files()
    
    if config.get("monitoring", {}).get("check_sgid_files", True):
        metrics["sgid_files"] = find_sgid_files()
    
    if config.get("monitoring", {}).get("check_world_writable", True):
        metrics["world_writable_files"] = find_world_writable_files()
    
    if config.get("monitoring", {}).get("check_critical_files", True):
        metrics["critical_file_permissions"] = check_critical_file_permissions()
    
    if config.get("monitoring", {}).get("check_home_permissions", True):
        metrics["home_directory_issues"] = check_home_directory_permissions()
    
    if config.get("monitoring", {}).get("check_ssh_keys", True):
        metrics["ssh_key_permissions"] = check_ssh_key_permissions()
    
    if config.get("monitoring", {}).get("check_unowned_files", False):  # Desabilitado por padrão (lento)
        metrics["unowned_files"] = find_unowned_files()
    
    # Resumo
    critical_issues = len([c for c in metrics.get("critical_file_permissions", []) 
                          if isinstance(c, dict) and c.get("severity") == "critical"])
    
    metrics["summary"] = {
        "suid_files_found": len([f for f in metrics.get("suid_files", []) if isinstance(f, dict) and "error" not in f]),
        "world_writable_found": len([f for f in metrics.get("world_writable_files", []) if isinstance(f, dict)]),
        "critical_permission_issues": critical_issues,
        "ssh_key_issues": len(metrics.get("ssh_key_permissions", [])),
        "has_critical_issues": critical_issues > 0
    }
    
    return metrics

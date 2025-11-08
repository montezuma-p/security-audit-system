"""
Módulo de análise e diagnóstico de rede
"""
import subprocess
import socket
import time
import psutil
from typing import Dict, List, Any
import re


def get_network_interfaces_detailed() -> List[Dict[str, Any]]:
    """Obtém informações detalhadas sobre interfaces de rede"""
    interfaces = []
    
    try:
        net_io = psutil.net_io_counters(pernic=True)
        net_addrs = psutil.net_if_addrs()
        net_stats = psutil.net_if_stats()
        
        for interface_name, stats in net_stats.items():
            interface_info = {
                "name": interface_name,
                "is_up": stats.isup,
                "speed_mbps": stats.speed,
                "mtu": stats.mtu,
                "duplex": str(stats.duplex) if hasattr(stats, 'duplex') else "unknown"
            }
            
            # Endereços IP
            if interface_name in net_addrs:
                addresses = []
                for addr in net_addrs[interface_name]:
                    if addr.family == socket.AF_INET:  # IPv4
                        addresses.append({
                            "family": "IPv4",
                            "address": addr.address,
                            "netmask": addr.netmask
                        })
                    elif addr.family == socket.AF_INET6:  # IPv6
                        addresses.append({
                            "family": "IPv6",
                            "address": addr.address,
                            "netmask": addr.netmask
                        })
                interface_info["addresses"] = addresses
            
            # Estatísticas de tráfego
            if interface_name in net_io:
                io = net_io[interface_name]
                interface_info["statistics"] = {
                    "bytes_sent_mb": round(io.bytes_sent / (1024**2), 2),
                    "bytes_recv_mb": round(io.bytes_recv / (1024**2), 2),
                    "packets_sent": io.packets_sent,
                    "packets_recv": io.packets_recv,
                    "errors_in": io.errin,
                    "errors_out": io.errout,
                    "drops_in": io.dropin,
                    "drops_out": io.dropout
                }
            
            interfaces.append(interface_info)
    except Exception as e:
        interfaces.append({"error": str(e)})
    
    return interfaces


def test_connectivity(hosts: List[str] = None) -> List[Dict[str, Any]]:
    """Testa conectividade com hosts específicos"""
    if hosts is None:
        hosts = ["8.8.8.8", "1.1.1.1", "google.com"]
    
    results = []
    
    for host in hosts:
        result = {
            "host": host,
            "reachable": False,
            "latency_ms": None,
            "packet_loss": 0
        }
        
        try:
            # Ping com 3 pacotes
            ping_result = subprocess.run(
                ['ping', '-c', '3', '-W', '2', host],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if ping_result.returncode == 0:
                result["reachable"] = True
                
                # Extrair latência média
                for line in ping_result.stdout.split('\n'):
                    if 'avg' in line or 'rtt' in line:
                        # Formato: rtt min/avg/max/mdev = X/Y/Z/W ms
                        match = re.search(r'= [\d.]+/([\d.]+)/', line)
                        if match:
                            result["latency_ms"] = float(match.group(1))
                        break
                
                # Extrair packet loss
                loss_match = re.search(r'(\d+)% packet loss', ping_result.stdout)
                if loss_match:
                    result["packet_loss"] = int(loss_match.group(1))
            else:
                result["error"] = "Host unreachable"
                
        except subprocess.TimeoutExpired:
            result["error"] = "Timeout"
        except Exception as e:
            result["error"] = str(e)
        
        results.append(result)
    
    return results


def test_dns_resolution() -> Dict[str, Any]:
    """Testa resolução DNS"""
    dns_info = {
        "working": False,
        "servers": [],
        "resolution_tests": []
    }
    
    # Obter servidores DNS configurados
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.strip().startswith('nameserver'):
                    dns_server = line.split()[1]
                    dns_info["servers"].append(dns_server)
    except Exception as e:
        dns_info["error_reading_config"] = str(e)
    
    # Testar resolução de alguns domínios
    test_domains = ["google.com", "github.com", "fedoraproject.org"]
    
    for domain in test_domains:
        test_result = {
            "domain": domain,
            "resolved": False,
            "ip_addresses": [],
            "time_ms": None
        }
        
        try:
            start_time = time.time()
            addr_info = socket.getaddrinfo(domain, None)
            elapsed = (time.time() - start_time) * 1000
            
            test_result["resolved"] = True
            test_result["time_ms"] = round(elapsed, 2)
            test_result["ip_addresses"] = list(set([addr[4][0] for addr in addr_info]))[:3]
            
        except socket.gaierror as e:
            test_result["error"] = f"DNS resolution failed: {str(e)}"
        except Exception as e:
            test_result["error"] = str(e)
        
        dns_info["resolution_tests"].append(test_result)
    
    # Verificar se pelo menos um teste passou
    dns_info["working"] = any(t.get("resolved", False) for t in dns_info["resolution_tests"])
    
    return dns_info


def check_gateway() -> Dict[str, Any]:
    """Verifica o gateway padrão"""
    gateway_info = {
        "gateway": None,
        "reachable": False,
        "latency_ms": None
    }
    
    try:
        # Obter gateway via ip route
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            # Formato: default via X.X.X.X dev ethX
            match = re.search(r'via\s+([\d.]+)', result.stdout)
            if match:
                gateway_ip = match.group(1)
                gateway_info["gateway"] = gateway_ip
                
                # Testar conectividade com gateway
                ping_result = subprocess.run(
                    ['ping', '-c', '3', '-W', '2', gateway_ip],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if ping_result.returncode == 0:
                    gateway_info["reachable"] = True
                    
                    # Extrair latência
                    for line in ping_result.stdout.split('\n'):
                        if 'avg' in line:
                            match = re.search(r'= [\d.]+/([\d.]+)/', line)
                            if match:
                                gateway_info["latency_ms"] = float(match.group(1))
                            break
    except Exception as e:
        gateway_info["error"] = str(e)
    
    return gateway_info


def check_internet_access() -> Dict[str, Any]:
    """Verifica acesso à Internet"""
    internet = {
        "has_access": False,
        "test_method": "http"
    }
    
    try:
        # Tentar resolver e conectar a um serviço conhecido
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # Testar conexão com DNS público do Google (porta 53)
        result = sock.connect_ex(('8.8.8.8', 53))
        
        if result == 0:
            internet["has_access"] = True
        
        sock.close()
        
    except Exception as e:
        internet["error"] = str(e)
    
    return internet


def get_bandwidth_stats() -> Dict[str, Any]:
    """Obtém estatísticas de uso de banda (simplificado)"""
    bandwidth = {
        "total_sent_mb": 0,
        "total_recv_mb": 0
    }
    
    try:
        net_io = psutil.net_io_counters()
        
        bandwidth["total_sent_mb"] = round(net_io.bytes_sent / (1024**2), 2)
        bandwidth["total_recv_mb"] = round(net_io.bytes_recv / (1024**2), 2)
        bandwidth["packets_sent"] = net_io.packets_sent
        bandwidth["packets_recv"] = net_io.packets_recv
        bandwidth["errors_in"] = net_io.errin
        bandwidth["errors_out"] = net_io.errout
        
    except Exception as e:
        bandwidth["error"] = str(e)
    
    return bandwidth


def check_network_security() -> List[Dict[str, Any]]:
    """Verifica configurações de segurança de rede"""
    security_checks = []
    
    # Verificar IP forwarding (pode ser risco de segurança se não for roteador)
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            ip_forward = f.read().strip()
            
            if ip_forward == '1':
                security_checks.append({
                    "check": "IP Forwarding",
                    "status": "enabled",
                    "severity": "warning",
                    "description": "IP forwarding está habilitado. Verifique se isso é intencional.",
                    "file": "/proc/sys/net/ipv4/ip_forward"
                })
    except Exception:
        pass
    
    # Verificar se ICMP redirect está desabilitado
    try:
        with open('/proc/sys/net/ipv4/conf/all/accept_redirects', 'r') as f:
            accept_redirects = f.read().strip()
            
            if accept_redirects == '1':
                security_checks.append({
                    "check": "ICMP Redirects",
                    "status": "enabled",
                    "severity": "info",
                    "description": "Sistema aceita ICMP redirects. Considere desabilitar para maior segurança.",
                    "file": "/proc/sys/net/ipv4/conf/all/accept_redirects"
                })
    except Exception:
        pass
    
    # Verificar SYN cookies (proteção contra SYN flood)
    try:
        with open('/proc/sys/net/ipv4/tcp_syncookies', 'r') as f:
            syncookies = f.read().strip()
            
            if syncookies == '0':
                security_checks.append({
                    "check": "TCP SYN Cookies",
                    "status": "disabled",
                    "severity": "warning",
                    "description": "SYN cookies desabilitados. Recomenda-se habilitar para proteção contra SYN flood.",
                    "file": "/proc/sys/net/ipv4/tcp_syncookies"
                })
    except Exception:
        pass
    
    return security_checks


def collect_network_metrics(config: Dict[str, Any]) -> Dict[str, Any]:
    """Coleta todas as métricas de rede"""
    metrics = {}
    
    if config.get("monitoring", {}).get("check_network_interfaces", True):
        metrics["interfaces"] = get_network_interfaces_detailed()
    
    if config.get("monitoring", {}).get("check_connectivity", True):
        test_hosts = config.get("monitoring", {}).get("connectivity_test_hosts", 
                                                       ["8.8.8.8", "1.1.1.1", "google.com"])
        metrics["connectivity"] = test_connectivity(test_hosts)
    
    if config.get("monitoring", {}).get("check_dns", True):
        metrics["dns"] = test_dns_resolution()
    
    if config.get("monitoring", {}).get("check_gateway", True):
        metrics["gateway"] = check_gateway()
    
    if config.get("monitoring", {}).get("check_internet", True):
        metrics["internet"] = check_internet_access()
    
    if config.get("monitoring", {}).get("check_bandwidth", True):
        metrics["bandwidth"] = get_bandwidth_stats()
    
    if config.get("monitoring", {}).get("check_network_security", True):
        metrics["security_checks"] = check_network_security()
    
    # Resumo
    connectivity_ok = all(c.get("reachable", False) for c in metrics.get("connectivity", []) if isinstance(c, dict))
    
    metrics["summary"] = {
        "total_interfaces": len([i for i in metrics.get("interfaces", []) if isinstance(i, dict) and "error" not in i]),
        "interfaces_up": len([i for i in metrics.get("interfaces", []) if isinstance(i, dict) and i.get("is_up", False)]),
        "connectivity_ok": connectivity_ok,
        "dns_working": metrics.get("dns", {}).get("working", False),
        "gateway_reachable": metrics.get("gateway", {}).get("reachable", False),
        "internet_access": metrics.get("internet", {}).get("has_access", False),
        "network_security_issues": len(metrics.get("security_checks", []))
    }
    
    return metrics

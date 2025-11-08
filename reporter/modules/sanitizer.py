#!/usr/bin/env python3
"""
Data Sanitizer - Sanitização de dados sensíveis para envio seguro à IA
Remove/anonimiza informações sensíveis mantendo utilidade para análise
"""

import re
import json
from typing import Dict, Any, List
from copy import deepcopy


class DataSanitizer:
    """Sanitiza dados de segurança antes de envio para APIs externas"""
    
    def __init__(self, level: str = "moderate"):
        """
        Inicializa sanitizador com nível de sanitização
        
        Args:
            level: "none" | "light" | "moderate" | "strict"
        """
        self.level = level
        self.username_map = {}  # Mapeamento username real -> anonimizado
        self.ip_map = {}  # Mapeamento IP real -> anonimizado
        self.hostname_original = None
        
    def sanitize(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitiza relatório de segurança completo
        
        Args:
            data: Relatório de segurança original
            
        Returns:
            Relatório sanitizado
        """
        if self.level == "none":
            return data
        
        # Deep copy para não modificar original
        sanitized = deepcopy(data)
        
        # Sanitizar hostname
        if self.level in ["moderate", "strict"]:
            sanitized["hostname"] = self._sanitize_hostname(sanitized.get("hostname", "unknown"))
        
        # Sanitizar métricas
        if "metrics" in sanitized:
            sanitized["metrics"] = self._sanitize_metrics(sanitized["metrics"])
        
        # Sanitizar alertas
        if "alerts" in sanitized:
            sanitized["alerts"] = self._sanitize_alerts(sanitized["alerts"])
        
        return sanitized
    
    def _sanitize_hostname(self, hostname: str) -> str:
        """Anonimiza hostname"""
        self.hostname_original = hostname
        return "workstation-001"
    
    def _sanitize_metrics(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitiza todas as métricas"""
        sanitized = {}
        
        for key, value in metrics.items():
            if key == "ports":
                sanitized[key] = self._sanitize_ports(value)
            elif key == "authentication":
                sanitized[key] = self._sanitize_authentication(value)
            elif key == "network":
                sanitized[key] = self._sanitize_network(value)
            elif key == "permissions":
                sanitized[key] = self._sanitize_permissions(value)
            else:
                # Outras métricas (firewall, vulnerabilities) geralmente OK
                sanitized[key] = value
        
        return sanitized
    
    def _sanitize_ports(self, ports_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitiza dados de portas"""
        if not isinstance(ports_data, dict):
            return ports_data
        
        sanitized = deepcopy(ports_data)
        
        # Sanitizar listening_ports
        if "listening_ports" in sanitized:
            for port in sanitized["listening_ports"]:
                if isinstance(port, dict) and "local_address" in port:
                    port["local_address"] = self._anonymize_ip(
                        port["local_address"], 
                        is_local=True
                    )
        
        # Sanitizar connections
        if "connections" in sanitized:
            conn = sanitized["connections"]
            if isinstance(conn, dict):
                # Sanitizar top_remote_ips
                if "top_remote_ips" in conn:
                    for item in conn["top_remote_ips"]:
                        if isinstance(item, dict) and "ip" in item:
                            item["ip"] = self._anonymize_ip(item["ip"], is_local=False)
        
        return sanitized
    
    def _sanitize_authentication(self, auth_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitiza dados de autenticação (usernames e IPs)"""
        if not isinstance(auth_data, dict):
            return auth_data
        
        sanitized = deepcopy(auth_data)
        
        # Sanitizar failed_logins
        if "failed_logins" in sanitized:
            for login in sanitized["failed_logins"]:
                if isinstance(login, dict):
                    if "user" in login:
                        login["user"] = self._anonymize_username(login["user"])
                    if "source_ip" in login:
                        login["source_ip"] = self._anonymize_ip(login["source_ip"], is_local=False)
        
        # Sanitizar successful_logins
        if "successful_logins" in sanitized:
            for login in sanitized["successful_logins"]:
                if isinstance(login, dict):
                    if "user" in login:
                        login["user"] = self._anonymize_username(login["user"])
                    if "source_ip" in login:
                        login["source_ip"] = self._anonymize_ip(login["source_ip"], is_local=False)
        
        # Sanitizar sudo_usage
        if "sudo_usage" in sanitized:
            for sudo in sanitized["sudo_usage"]:
                if isinstance(sudo, dict) and "user" in sudo:
                    sudo["user"] = self._anonymize_username(sudo["user"])
        
        # Sanitizar active_sessions
        if "active_sessions" in sanitized:
            for session in sanitized["active_sessions"]:
                if isinstance(session, dict):
                    if "user" in session:
                        session["user"] = self._anonymize_username(session["user"])
                    if "from" in session and session["from"] not in ["local", "-"]:
                        session["from"] = self._anonymize_ip(session["from"], is_local=False)
        
        # Sanitizar brute_force_analysis
        if "brute_force_analysis" in sanitized:
            bf = sanitized["brute_force_analysis"]
            if isinstance(bf, dict) and "suspicious_ips" in bf:
                for ip_data in bf["suspicious_ips"]:
                    if isinstance(ip_data, dict):
                        if "ip" in ip_data:
                            ip_data["ip"] = self._anonymize_ip(ip_data["ip"], is_local=False)
                        if "users_attempted" in ip_data:
                            ip_data["users_attempted"] = [
                                self._anonymize_username(u) for u in ip_data["users_attempted"]
                            ]
        
        return sanitized
    
    def _sanitize_network(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitiza dados de rede"""
        if not isinstance(network_data, dict):
            return network_data
        
        sanitized = deepcopy(network_data)
        
        # Sanitizar interfaces
        if "interfaces" in sanitized:
            for interface in sanitized["interfaces"]:
                if isinstance(interface, dict) and "addresses" in interface:
                    for addr in interface["addresses"]:
                        if isinstance(addr, dict) and "address" in addr:
                            addr["address"] = self._anonymize_ip(addr["address"], is_local=True)
                            if "netmask" in addr:
                                addr["netmask"] = "255.255.X.X"
        
        # Sanitizar gateway
        if "gateway" in sanitized and isinstance(sanitized["gateway"], dict):
            if "gateway" in sanitized["gateway"]:
                sanitized["gateway"]["gateway"] = self._anonymize_ip(
                    sanitized["gateway"]["gateway"], 
                    is_local=True
                )
        
        # Sanitizar DNS
        if "dns" in sanitized and isinstance(sanitized["dns"], dict):
            if "servers" in sanitized["dns"]:
                sanitized["dns"]["servers"] = [
                    self._anonymize_ip(ip, is_local=False) 
                    for ip in sanitized["dns"]["servers"]
                ]
        
        return sanitized
    
    def _sanitize_permissions(self, perm_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitiza dados de permissões (principalmente paths com usernames)"""
        if not isinstance(perm_data, dict):
            return perm_data
        
        sanitized = deepcopy(perm_data)
        
        # Sanitizar listas de arquivos (SUID, SGID, world-writable)
        for key in ["suid_files", "sgid_files", "world_writable_files"]:
            if key in sanitized and isinstance(sanitized[key], list):
                sanitized_list = []
                for item in sanitized[key]:
                    # Se for string, sanitiza o path
                    if isinstance(item, str):
                        sanitized_list.append(self._sanitize_path(item))
                    # Se for dict, sanitiza recursivamente
                    elif isinstance(item, dict):
                        sanitized_item = {}
                        for k, v in item.items():
                            if isinstance(v, str):
                                sanitized_item[k] = self._sanitize_path(v)
                            else:
                                sanitized_item[k] = v
                        sanitized_list.append(sanitized_item)
                    else:
                        sanitized_list.append(item)
                sanitized[key] = sanitized_list
        
        return sanitized
    
    def _sanitize_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sanitiza alertas de segurança"""
        if not isinstance(alerts, list):
            return alerts
        
        sanitized = []
        for alert in alerts:
            if isinstance(alert, dict):
                sanitized_alert = deepcopy(alert)
                
                # Sanitizar mensagem e recomendação
                if "message" in sanitized_alert:
                    sanitized_alert["message"] = self._sanitize_text(sanitized_alert["message"])
                if "recommendation" in sanitized_alert:
                    sanitized_alert["recommendation"] = self._sanitize_text(sanitized_alert["recommendation"])
                
                sanitized.append(sanitized_alert)
            else:
                sanitized.append(alert)
        
        return sanitized
    
    def _anonymize_ip(self, ip: str, is_local: bool = False) -> str:
        """
        Anonimiza endereço IP
        
        Args:
            ip: Endereço IP original
            is_local: Se é IP da rede local (RFC1918)
        """
        if not ip or ip in ["unknown", "-", "0.0.0.0", "::", "localhost", "127.0.0.1"]:
            return ip
        
        # Já anonimizado?
        if ip in self.ip_map:
            return self.ip_map[ip]
        
        # IPs locais (RFC1918)
        is_private = (
            ip.startswith("10.") or
            ip.startswith("192.168.") or
            ip.startswith("172.16.") or
            ip.startswith("172.17.") or
            ip.startswith("172.18.") or
            ip.startswith("172.19.") or
            ip.startswith("172.2") or
            ip.startswith("172.30.") or
            ip.startswith("172.31.")
        )
        
        if self.level == "light" and is_private:
            # Light: Anonimizar apenas último octeto de IPs privados
            parts = ip.split(".")
            if len(parts) == 4:
                anonymized = f"{parts[0]}.{parts[1]}.{parts[2]}.X"
            else:
                anonymized = ip
        
        elif self.level == "moderate":
            if is_private or is_local:
                # Moderate: Anonimizar 2 últimos octetos de IPs privados
                parts = ip.split(".")
                if len(parts) == 4:
                    anonymized = f"{parts[0]}.{parts[1]}.X.X"
                else:
                    anonymized = ip
            else:
                # IPs públicos: manter (podem ser IPs de atacantes - úteis)
                anonymized = ip
        
        elif self.level == "strict":
            # Strict: Anonimizar tudo parcialmente
            parts = ip.split(".")
            if len(parts) == 4:
                if is_private or is_local:
                    anonymized = f"{parts[0]}.X.X.X"
                else:
                    # IP público: manter primeiros 2 octetos (região)
                    anonymized = f"{parts[0]}.{parts[1]}.XXX.XXX"
            else:
                anonymized = ip
        
        else:
            anonymized = ip
        
        self.ip_map[ip] = anonymized
        return anonymized
    
    def _anonymize_username(self, username: str) -> str:
        """Anonimiza username do sistema"""
        if not username or username in ["unknown", "root"]:
            return username  # Manter root e unknown
        
        # Já anonimizado?
        if username in self.username_map:
            return self.username_map[username]
        
        if self.level in ["moderate", "strict"]:
            # Criar username genérico
            user_num = len(self.username_map) + 1
            anonymized = f"user{user_num}"
            self.username_map[username] = anonymized
            return anonymized
        
        return username
    
    def _sanitize_path(self, path: str) -> str:
        """Sanitiza paths de arquivos (remove usernames)"""
        if not path:
            return path
        
        # Substituir /home/username/ por /home/$USER/
        path = re.sub(r'/home/[^/]+/', '/home/$USER/', path)
        
        # Substituir usernames conhecidos
        for real_user, anon_user in self.username_map.items():
            path = path.replace(real_user, anon_user)
        
        return path
    
    def _sanitize_text(self, text: str) -> str:
        """Sanitiza texto livre (mensagens, recomendações)"""
        if not text:
            return text
        
        sanitized = text
        
        # Substituir IPs
        for real_ip, anon_ip in self.ip_map.items():
            sanitized = sanitized.replace(real_ip, anon_ip)
        
        # Substituir usernames
        for real_user, anon_user in self.username_map.items():
            # Evitar substituir dentro de palavras
            sanitized = re.sub(r'\b' + re.escape(real_user) + r'\b', anon_user, sanitized)
        
        # Substituir hostname
        if self.hostname_original:
            sanitized = sanitized.replace(self.hostname_original, "workstation-001")
        
        # Substituir paths
        sanitized = re.sub(r'/home/[^/\s]+/', '/home/$USER/', sanitized)
        
        return sanitized
    
    def get_sanitization_summary(self) -> Dict[str, Any]:
        """Retorna resumo do que foi sanitizado"""
        return {
            "level": self.level,
            "ips_anonymized": len(self.ip_map),
            "usernames_anonymized": len(self.username_map),
            "hostname_changed": self.hostname_original is not None,
            "mappings": {
                "sample_ips": dict(list(self.ip_map.items())[:3]) if self.ip_map else {},
                "sample_users": dict(list(self.username_map.items())[:3]) if self.username_map else {}
            }
        }


def sanitize_report(report: Dict[str, Any], level: str = "moderate") -> tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Função helper para sanitizar relatório
    
    Args:
        report: Relatório original
        level: Nível de sanitização
        
    Returns:
        Tupla (relatório_sanitizado, resumo_sanitização)
    """
    sanitizer = DataSanitizer(level=level)
    sanitized = sanitizer.sanitize(report)
    summary = sanitizer.get_sanitization_summary()
    return sanitized, summary


if __name__ == "__main__":
    # Teste básico
    import sys
    
    if len(sys.argv) > 1:
        # Ler JSON de arquivo
        with open(sys.argv[1], 'r') as f:
            data = json.load(f)
        
        level = sys.argv[2] if len(sys.argv) > 2 else "moderate"
        
        sanitized, summary = sanitize_report(data, level)
        
        print("🔒 Sanitização aplicada:")
        print(json.dumps(summary, indent=2))
        print("\n📄 Dados sanitizados salvos em: sanitized_output.json")
        
        with open("sanitized_output.json", 'w') as f:
            json.dump(sanitized, f, indent=2)
    else:
        print("Uso: python sanitizer.py <arquivo.json> [level]")
        print("Levels: none, light, moderate, strict")

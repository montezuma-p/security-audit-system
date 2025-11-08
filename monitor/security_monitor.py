#!/usr/bin/env python3
"""
Security Monitor - Sistema de monitoramento de segurança para Fedora Workstation
Realiza auditoria de segurança abrangente incluindo análise de rede
"""

import json
import os
import sys
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Adicionar o diretório modules ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import ports, auth, firewall, vulnerabilities, network, permissions, alerts


def get_default_output_dir() -> str:
    """Retorna diretório padrão para relatórios (XDG-compliant)"""
    # Padrão: ~/.bin/data/scripts-data/reports/security/raw
    home = Path.home()
    return str(home / ".bin/data/scripts-data/reports/security/raw")


def load_config(config_path: str = "config.json") -> Dict[str, Any]:
    """Carrega arquivo de configuração"""
    script_dir = Path(__file__).parent
    config_file = script_dir / config_path
    
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"⚠️  Arquivo de configuração não encontrado: {config_file}")
        print("💡 Dica: Copie config.json.example para config.json e customize")
        print("Usando configuração padrão...")
        return {
            "output_dir": get_default_output_dir(),
            "monitoring": {}
        }
    except json.JSONDecodeError as e:
        print(f"❌ Erro ao ler arquivo de configuração: {e}")
        sys.exit(1)


def collect_all_metrics(config: Dict[str, Any]) -> Dict[str, Any]:
    """Coleta todas as métricas de segurança"""
    print("🔒 Coletando métricas de segurança...")
    
    metrics = {}
    
    # Coletar métricas de portas e serviços
    print("  🔌 Portas e serviços...")
    try:
        metrics["ports"] = ports.collect_ports_metrics(config)
    except Exception as e:
        print(f"    ⚠️  Erro: {e}")
        metrics["ports"] = {"error": str(e)}
    
    # Coletar métricas de autenticação
    print("  🔐 Autenticação...")
    try:
        metrics["authentication"] = auth.collect_auth_metrics(config)
    except Exception as e:
        print(f"    ⚠️  Erro: {e}")
        metrics["authentication"] = {"error": str(e)}
    
    # Coletar métricas de firewall
    print("  🛡️  Firewall e SELinux...")
    try:
        metrics["firewall"] = firewall.collect_firewall_metrics(config)
    except Exception as e:
        print(f"    ⚠️  Erro: {e}")
        metrics["firewall"] = {"error": str(e)}
    
    # Coletar métricas de vulnerabilidades
    print("  ⚠️  Vulnerabilidades...")
    try:
        metrics["vulnerabilities"] = vulnerabilities.collect_vulnerability_metrics(config)
    except Exception as e:
        print(f"    ⚠️  Erro: {e}")
        metrics["vulnerabilities"] = {"error": str(e)}
    
    # Coletar métricas de rede
    print("  🌐 Rede e conectividade...")
    try:
        metrics["network"] = network.collect_network_metrics(config)
    except Exception as e:
        print(f"    ⚠️  Erro: {e}")
        metrics["network"] = {"error": str(e)}
    
    # Coletar métricas de permissões
    print("  📁 Permissões de arquivos...")
    try:
        metrics["permissions"] = permissions.collect_permissions_metrics(config)
    except Exception as e:
        print(f"    ⚠️  Erro: {e}")
        metrics["permissions"] = {"error": str(e)}
    
    return metrics


def generate_report(config: Dict[str, Any]) -> Dict[str, Any]:
    """Gera relatório completo de segurança"""
    # Timestamp do relatório
    timestamp = datetime.now()
    
    # Coletar métricas
    metrics = collect_all_metrics(config)
    
    # Gerar alertas
    print("🚨 Gerando alertas de segurança...")
    security_alerts = alerts.generate_alerts(metrics, config)
    
    # Calcular score de segurança
    security_score = calculate_security_score(metrics, security_alerts)
    
    # Montar relatório completo
    report = {
        "timestamp": timestamp.isoformat(),
        "timestamp_unix": int(timestamp.timestamp()),
        "hostname": _get_hostname(),
        "metrics": metrics,
        "alerts": security_alerts,
        "security_score": security_score,
        "summary": {
            "total_alerts": len(security_alerts),
            "critical_alerts": sum(1 for a in security_alerts if a.get("severity") == "critical"),
            "warning_alerts": sum(1 for a in security_alerts if a.get("severity") == "warning"),
            "info_alerts": sum(1 for a in security_alerts if a.get("severity") == "info"),
            "security_status": _determine_security_status(security_alerts, security_score)
        }
    }
    
    return report


def calculate_security_score(metrics: Dict[str, Any], security_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calcula score de segurança (0-100)"""
    score = 100
    deductions = []
    
    # Deduzir pontos por alertas críticos
    critical_count = sum(1 for a in security_alerts if a.get("severity") == "critical")
    if critical_count > 0:
        deduction = min(critical_count * 10, 50)
        score -= deduction
        deductions.append(f"-{deduction} pontos: {critical_count} alerta(s) crítico(s)")
    
    # Deduzir pontos por alertas de warning
    warning_count = sum(1 for a in security_alerts if a.get("severity") == "warning")
    if warning_count > 0:
        deduction = min(warning_count * 3, 30)
        score -= deduction
        deductions.append(f"-{deduction} pontos: {warning_count} alerta(s) de aviso")
    
    # Bônus por configurações boas
    bonus = []
    
    # Firewall ativo
    if metrics.get("firewall", {}).get("summary", {}).get("firewall_active", False):
        bonus.append("+5 pontos: Firewall ativo")
    
    # SELinux enforcing
    if metrics.get("firewall", {}).get("summary", {}).get("selinux_enforcing", False):
        bonus.append("+5 pontos: SELinux em modo Enforcing")
    
    # Sistema atualizado
    if metrics.get("vulnerabilities", {}).get("summary", {}).get("security_updates_available", 0) == 0:
        bonus.append("+10 pontos: Sem atualizações de segurança pendentes")
    
    score = max(0, min(100, score))  # Garantir que está entre 0 e 100
    
    return {
        "score": score,
        "grade": _score_to_grade(score),
        "deductions": deductions,
        "bonus": bonus
    }


def _score_to_grade(score: int) -> str:
    """Converte score numérico em nota"""
    if score >= 90:
        return "A (Excelente)"
    elif score >= 80:
        return "B (Bom)"
    elif score >= 70:
        return "C (Aceitável)"
    elif score >= 60:
        return "D (Precisa melhorar)"
    else:
        return "F (Crítico)"


def _determine_security_status(security_alerts: List[Dict[str, Any]], security_score: Dict[str, Any]) -> str:
    """Determina status geral de segurança"""
    critical_count = sum(1 for a in security_alerts if a.get("severity") == "critical")
    score = security_score.get("score", 0)
    
    if critical_count > 0 or score < 60:
        return "critical"
    elif score < 80:
        return "warning"
    else:
        return "good"


def _get_hostname() -> str:
    """Obtém hostname do sistema"""
    try:
        import platform
        return platform.node()
    except Exception:
        return "unknown"


def save_report(report: Dict[str, Any], config: Dict[str, Any]) -> str:
    """Salva relatório em arquivo JSON"""
    # Prioridade: ENV > config.json > default
    output_dir_str = os.getenv(
        'SECURITY_MONITOR_OUTPUT',
        config.get('output_dir', get_default_output_dir())
    )
    
    # Expandir ~ se presente
    output_dir = Path(output_dir_str).expanduser()
    
    # Criar diretório se não existir
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Nome do arquivo com timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_{timestamp}.json"
    filepath = output_dir / filename
    
    # Salvar JSON
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    return str(filepath)


def print_summary(report: Dict[str, Any]):
    """Imprime resumo do relatório"""
    print("\n" + "="*70)
    print("🔒 RESUMO DA AUDITORIA DE SEGURANÇA")
    print("="*70)
    
    summary = report.get("summary", {})
    security_status = summary.get("security_status", "unknown")
    security_score = report.get("security_score", {})
    
    # Status geral
    status_icon = {
        "good": "✅",
        "warning": "⚠️",
        "critical": "❌"
    }.get(security_status, "❓")
    
    print(f"\n{status_icon} Status de Segurança: {security_status.upper()}")
    print(f"🎯 Score de Segurança: {security_score.get('score', 0)}/100 - {security_score.get('grade', 'N/A')}")
    print(f"🕐 Timestamp: {report.get('timestamp', 'N/A')}")
    print(f"🖥️  Hostname: {report.get('hostname', 'N/A')}")
    
    # Alertas
    print(f"\n🚨 Alertas:")
    print(f"   Total: {summary.get('total_alerts', 0)}")
    print(f"   ❌ Críticos: {summary.get('critical_alerts', 0)}")
    print(f"   ⚠️  Avisos: {summary.get('warning_alerts', 0)}")
    print(f"   ℹ️  Informativos: {summary.get('info_alerts', 0)}")
    
    # Listar alertas críticos
    critical_alerts = [a for a in report.get("alerts", []) if a.get("severity") == "critical"]
    if critical_alerts:
        print(f"\n❌ ALERTAS CRÍTICOS:")
        for i, alert in enumerate(critical_alerts[:10], 1):
            print(f"   {i}. [{alert.get('category', 'unknown')}] {alert.get('message', 'N/A')}")
            if alert.get("recommendation"):
                print(f"      💡 {alert.get('recommendation')}")
    
    # Estatísticas por categoria
    print(f"\n📊 Estatísticas:")
    
    metrics = report.get("metrics", {})
    
    # Portas
    if "ports" in metrics:
        ports_summary = metrics["ports"].get("summary", {})
        print(f"   🔌 Portas abertas: {ports_summary.get('total_listening_ports', 0)}")
        print(f"   ⚠️  Portas suspeitas: {ports_summary.get('suspicious_ports_found', 0)}")
    
    # Autenticação
    if "authentication" in metrics:
        auth_summary = metrics["authentication"].get("summary", {})
        print(f"   🔐 Logins falhos (24h): {auth_summary.get('failed_login_attempts', 0)}")
        if auth_summary.get("brute_force_detected", False):
            print(f"   ⚠️  Ataque de força bruta detectado!")
    
    # Vulnerabilidades
    if "vulnerabilities" in metrics:
        vuln_summary = metrics["vulnerabilities"].get("summary", {})
        security_updates = vuln_summary.get("security_updates_available", 0)
        if security_updates > 0:
            print(f"   ⚠️  Atualizações de segurança: {security_updates}")
    
    # Rede
    if "network" in metrics:
        net_summary = metrics["network"].get("summary", {})
        internet_icon = "✅" if net_summary.get("internet_access", False) else "❌"
        print(f"   {internet_icon} Internet: {'OK' if net_summary.get('internet_access', False) else 'SEM ACESSO'}")
    
    # Firewall
    if "firewall" in metrics:
        fw_summary = metrics["firewall"].get("summary", {})
        fw_icon = "✅" if fw_summary.get("firewall_active", False) else "❌"
        selinux_icon = "✅" if fw_summary.get("selinux_enforcing", False) else "⚠️"
        print(f"   {fw_icon} Firewall: {'Ativo' if fw_summary.get('firewall_active', False) else 'Inativo'}")
        print(f"   {selinux_icon} SELinux: {metrics['firewall'].get('selinux', {}).get('mode', 'unknown')}")
    
    print("\n" + "="*70)


def main():
    """Função principal"""
    # Parser de argumentos
    parser = argparse.ArgumentParser(
        description='Security Monitor - Auditoria de segurança do sistema'
    )
    parser.add_argument(
        '--session',
        type=str,
        help='Session ID para integração com orchestrator (habilita modo sessão)',
        default=None
    )
    
    args = parser.parse_args()
    
    print("🔒 Security Monitor - Iniciando auditoria de segurança...")
    if args.session:
        print(f"   🔗 Modo sessão: {args.session}")
    print()
    
    # Carregar configuração
    config = load_config()
    
    try:
        # Gerar relatório
        report = generate_report(config)
        
        # Adicionar session_id ao relatório se fornecido
        if args.session:
            report['session_id'] = args.session
        
        # Salvar relatório
        print("\n💾 Salvando relatório...")
        filepath = save_report(report, config)
        print(f"✅ Relatório salvo em: {filepath}")
        
        # Se modo sessão, integrar com database
        if args.session:
            try:
                # Importa database_manager (apenas em modo sessão)
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'orchestrador'))
                from database_manager.db_manager import DatabaseManager
                
                db = DatabaseManager()
                db.insert_security_metrics(args.session, report)
                print(f"   ✅ Métricas gravadas no histórico (sessão: {args.session})")
                
                # Inserir alertas críticos no banco
                for alert in report.get('alerts', []):
                    if alert.get('severity') in ['critical', 'warning']:
                        db.insert_alert(
                            args.session,
                            'security',
                            alert.get('severity'),
                            alert.get('message', 'Alerta sem título'),
                            alert.get('recommendation', '')
                        )
            except Exception as e:
                print(f"   ⚠️  Erro ao gravar no banco: {e}")
        
        # Imprimir resumo
        print_summary(report)
        
        # Status de saída baseado no status de segurança
        security_status = report.get("summary", {}).get("security_status", "unknown")
        if security_status == "critical":
            sys.exit(2)
        elif security_status == "warning":
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Auditoria interrompida pelo usuário")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Erro fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

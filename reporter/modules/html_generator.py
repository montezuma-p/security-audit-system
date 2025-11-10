#!/usr/bin/env python3
"""
HTML Generator - Gerador de Relatórios HTML (Orquestrador)
Suporta geração com IA ou análise local
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

# Import analyzers locais
from .analyzers import (
    ScoreAnalyzer,
    PortsAnalyzer,
    AuthAnalyzer,
    FirewallAnalyzer,
    VulnerabilitiesAnalyzer,
    NetworkAnalyzer,
    PermissionsAnalyzer
)

# Import componentes de geração HTML
from .html_builder import (
    load_asset,
    generate_header,
    generate_footer,
    generate_json_modal,
    generate_status_badge,
    generate_score_section,
    generate_analysis_sections,
    generate_disclaimer
)


def generate_html(data: Dict[str, Any], ai_analysis: Optional[Dict[str, Any]] = None) -> str:
    """
    Gera HTML completo - com IA ou análise local
    
    Args:
        data: Dados completos do relatório de segurança
        ai_analysis: Análise da IA (opcional). Se None, usa analyzers locais
        
    Returns:
        HTML completo como string standalone
    """
    # Determinar modo e gerar insights
    if ai_analysis:
        insights = convert_ai_to_insights(ai_analysis, data)
        mode = 'ai'
    else:
        insights = run_analyzers(data)
        mode = 'local'
    
    # Carregar assets (CSS e JS inline)
    css = load_asset('styles.css')
    js = load_asset('report.js')
    
    # Extrair informações básicas
    hostname = data.get('hostname', 'Unknown')
    timestamp = data.get('timestamp', datetime.now().isoformat())
    security_score = data.get('security_score', {})
    
    # Construir HTML completo
    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Segurança - {hostname}</title>
    <style>
{css}
    </style>
</head>
<body>
    <div class="container">
        {generate_header(hostname, timestamp, mode)}
        
        <div class="content">
            {generate_status_badge(insights['score'])}
            {generate_score_section(insights['score'], security_score)}
            {generate_analysis_sections(insights, data)}
            {generate_disclaimer(mode)}
        </div>
        
        {generate_footer(mode)}
    </div>
    
    {generate_json_modal()}
    
    <script>
{js}
        
        // Initialize with raw data
        initReport({json.dumps({
            'full': data,
            'metrics': data.get('metrics', {}),
            'ports': data.get('metrics', {}).get('ports', {}),
            'authentication': data.get('metrics', {}).get('authentication', {}),
            'firewall': data.get('metrics', {}).get('firewall', {}),
            'vulnerabilities': data.get('metrics', {}).get('vulnerabilities', {}),
            'network': data.get('metrics', {}).get('network', {}),
            'permissions': data.get('metrics', {}).get('permissions', {}),
            'alerts': data.get('alerts', [])
        })});
    </script>
</body>
</html>"""
    
    return html


def convert_ai_to_insights(ai_analysis: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Converte análise da IA para formato de insights compatível com analyzers
    
    Args:
        ai_analysis: Análise retornada pela IA
        data: Dados originais do relatório
        
    Returns:
        Dict com insights no mesmo formato dos analyzers
    """
    security_score = data.get('security_score', {})
    score_value = security_score.get('score', 0)
    
    insights = {
        'score': {
            'status': 'critical' if score_value < 50 else 'warning' if score_value < 75 else 'good',
            'status_text': ai_analysis.get('status_text', 'Análise de Segurança'),
            'message': ai_analysis.get('security_score_analise', 'Análise de score não disponível'),
            'severity': 'high' if score_value < 50 else 'medium' if score_value < 75 else 'low',
            'metrics': {
                'score': score_value,
                'grade': security_score.get('grade', 'N/A'),
                'total_alerts': data.get('summary', {}).get('total_alerts', 0),
                'critical_alerts': data.get('summary', {}).get('critical_alerts', 0)
            },
            'ai_content': ai_analysis  # Guardar análise completa da IA
        },
        'ports': {
            'status': 'info',
            'status_text': '🔌 Análise de Portas',
            'message': ai_analysis.get('analise_portas', 'Análise não disponível'),
            'details': [],
            'recommendations': [],
            'severity': 'medium'
        },
        'auth': {
            'status': 'info',
            'status_text': '🔐 Análise de Autenticação',
            'message': ai_analysis.get('analise_autenticacao', 'Análise não disponível'),
            'details': [],
            'recommendations': [],
            'severity': 'medium'
        },
        'firewall': {
            'status': 'info',
            'status_text': '🛡️ Firewall e SELinux',
            'message': ai_analysis.get('analise_firewall', 'Análise não disponível'),
            'details': [],
            'recommendations': [],
            'severity': 'medium'
        },
        'vulnerabilities': {
            'status': 'info',
            'status_text': '⚠️ Vulnerabilidades',
            'message': ai_analysis.get('analise_vulnerabilidades', 'Análise não disponível'),
            'details': [],
            'recommendations': [],
            'severity': 'medium'
        },
        'network': {
            'status': 'info',
            'status_text': '🌐 Configuração de Rede',
            'message': ai_analysis.get('analise_rede', 'Análise não disponível'),
            'details': [],
            'recommendations': [],
            'severity': 'low'
        },
        'permissions': {
            'status': 'info',
            'status_text': '📁 Permissões de Arquivos',
            'message': ai_analysis.get('analise_permissoes', 'Análise não disponível'),
            'details': [],
            'recommendations': [],
            'severity': 'low'
        }
    }
    
    return insights


def run_analyzers(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Executa todos os analyzers locais e retorna insights
    
    Args:
        data: Dados do relatório
        
    Returns:
        Dict com insights de cada analyzer
    """
    analyzers = {
        'score': ScoreAnalyzer(data),
        'ports': PortsAnalyzer(data),
        'auth': AuthAnalyzer(data),
        'firewall': FirewallAnalyzer(data),
        'vulnerabilities': VulnerabilitiesAnalyzer(data),
        'network': NetworkAnalyzer(data),
        'permissions': PermissionsAnalyzer(data)
    }
    
    insights = {}
    for name, analyzer in analyzers.items():
        try:
            insights[name] = analyzer.analyze()
        except Exception as e:
            print(f"⚠️ Erro ao analisar {name}: {e}")
            insights[name] = {
                'status': 'unknown',
                'status_text': '⚠️ ERRO NA ANÁLISE',
                'message': f'Não foi possível analisar esta seção: {str(e)}',
                'details': [],
                'recommendations': [],
                'severity': 'low',
                'metrics': {}
            }
    
    return insights


def save_html(data: Dict[str, Any], output_dir: str, ai_analysis: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Gera e salva relatório HTML
    
    Args:
        data: Dados do relatório
        output_dir: Diretório de saída
        ai_analysis: Análise da IA (opcional)
        
    Returns:
        Caminho do arquivo gerado ou None em caso de erro
    """
    try:
        # Gerar HTML
        html = generate_html(data, ai_analysis)
        
        # Criar nome do arquivo
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = data.get('hostname', 'unknown')
        mode_suffix = 'ai' if ai_analysis else 'local'
        filename = f"security_report_{mode_suffix}_{hostname}_{timestamp}.html"
        
        # Criar diretório se não existir
        os.makedirs(output_dir, exist_ok=True)
        
        # Caminho completo
        filepath = os.path.join(output_dir, filename)
        
        # Salvar arquivo
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filepath
    
    except Exception as e:
        print(f"❌ Erro ao gerar HTML: {e}")
        import traceback
        traceback.print_exc()
        return None


# Manter compatibilidade com código antigo
def save_basic_html(data: Dict[str, Any], output_dir: str) -> Optional[str]:
    """
    Alias para save_html() sem IA (compatibilidade retroativa)
    """
    return save_html(data, output_dir, ai_analysis=None)


if __name__ == "__main__":
    print("HTML Generator v2.0 - Modo Unificado")
    print("Use através do security_reporter.py")

#!/usr/bin/env python3
"""
Smart HTML Generator - Gerador de HTML Inteligente sem IA
Usa analyzers condicionais para gerar relatórios didáticos e interativos
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# Import analyzers
from .analyzers import (
    ScoreAnalyzer,
    PortsAnalyzer,
    AuthAnalyzer,
    FirewallAnalyzer,
    VulnerabilitiesAnalyzer,
    NetworkAnalyzer,
    PermissionsAnalyzer
)


def generate_basic_html(data: Dict[str, Any]) -> str:
    """
    Gera HTML inteligente com análises condicionais
    
    Args:
        data: Dados completos do relatório de segurança
        
    Returns:
        HTML completo como string standalone
    """
    # Executar todos os analyzers
    insights = run_analyzers(data)
    
    # Carregar assets (CSS e JS)
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
        {generate_header(hostname, timestamp)}
        
        <div class="content">
            {generate_status_badge(insights['score'])}
            {generate_score_section(insights['score'], security_score)}
            {generate_analysis_sections(insights, data)}
            {generate_disclaimer()}
        </div>
        
        {generate_footer()}
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


def run_analyzers(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Executa todos os analyzers e retorna insights
    
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


def load_asset(filename: str) -> str:
    """
    Carrega arquivo de asset (CSS ou JS)
    
    Args:
        filename: Nome do arquivo em templates/assets/
        
    Returns:
        Conteúdo do arquivo como string
    """
    current_dir = Path(__file__).parent
    asset_path = current_dir.parent / 'templates' / 'assets' / filename
    
    try:
        with open(asset_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"⚠️ Arquivo de asset não encontrado: {asset_path}")
        return f"/* Asset {filename} not found */"


def generate_header(hostname: str, timestamp: str) -> str:
    """Gera cabeçalho do relatório"""
    return f"""
        <div class="header">
            <h1>🔒 Security Reporter - Modo Local</h1>
            <div class="subtitle">Análise Automatizada de Segurança</div>
            <div class="mode-badge">🏠 100% Local - Sem IA - Nenhum Dado Enviado</div>
            <div class="timestamp">⏰ {timestamp}</div>
            <div class="timestamp">🖥️ {hostname}</div>
        </div>
    """


def generate_status_badge(score_insight: Dict[str, Any]) -> str:
    """Gera badge de status geral"""
    status = score_insight.get('status', 'warning')
    status_text = score_insight.get('status_text', 'Status Desconhecido')
    
    return f'<div class="status-badge status-{status}">{status_text}</div>'


def generate_score_section(insight: Dict[str, Any], score_data: Dict[str, Any]) -> str:
    """Gera seção de score"""
    metrics = insight.get('metrics', {})
    score = metrics.get('score', 0)
    grade = metrics.get('grade', 'N/A')
    
    deductions = score_data.get('deductions', [])
    bonus = score_data.get('bonus', [])
    
    deductions_html = ''.join(f'<li>{d}</li>' for d in deductions) if deductions else '<li>Nenhuma dedução</li>'
    bonus_html = ''.join(f'<li>{b}</li>' for b in bonus) if bonus else '<li>Nenhum bônus</li>'
    
    return f"""
        <div class="section" id="score-section">
            <h2 class="section-title">📊 Score de Segurança</h2>
            
            <div class="score-container">
                <div class="score-circle">
                    <div class="score-value">{score}</div>
                    <div class="score-label">/ 100</div>
                </div>
                <div class="score-details">
                    <div class="score-grade">Nota: {grade}</div>
                    <p style="opacity: 0.9;">Total de Alertas: {metrics.get('total_alerts', 0)} | Críticos: {metrics.get('critical_alerts', 0)}</p>
                </div>
            </div>
            
            <div class="card card-{insight.get('status', 'warning')}">
                <div class="card-header">
                    <h3>📈 Análise do Score</h3>
                    <span class="severity-badge severity-{insight.get('severity', 'low')}">{insight.get('severity', 'low')}</span>
                </div>
                <div class="analysis-text">
                    {format_markdown_to_html(insight.get('message', 'Análise não disponível'))}
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
                    <div>
                        <h4>Deduções:</h4>
                        <ul class="details-list">{deductions_html}</ul>
                    </div>
                    <div>
                        <h4>Bônus:</h4>
                        <ul class="details-list">{bonus_html}</ul>
                    </div>
                </div>
                
                <button class="json-toggle-btn" onclick="showJSON('full')">📄 Ver JSON Completo</button>
            </div>
        </div>
    """


def generate_analysis_sections(insights: Dict[str, Dict], data: Dict[str, Any]) -> str:
    """Gera todas as seções de análise"""
    sections = []
    
    # Mapeamento de seções
    section_configs = [
        ('ports', '🔌 Análise de Portas e Serviços', 'ports'),
        ('auth', '🔐 Análise de Autenticação', 'authentication'),
        ('firewall', '🛡️ Firewall e SELinux', 'firewall'),
        ('vulnerabilities', '⚠️ Vulnerabilidades e Atualizações', 'vulnerabilities'),
        ('network', '🌐 Configuração de Rede', 'network'),
        ('permissions', '📁 Permissões de Arquivos', 'permissions')
    ]
    
    for key, title, json_key in section_configs:
        insight = insights.get(key, {})
        sections.append(generate_analysis_card(key, title, insight, json_key))
    
    return '\n'.join(sections)


def generate_analysis_card(section_id: str, title: str, insight: Dict[str, Any], json_key: str) -> str:
    """Gera card de análise individual"""
    status = insight.get('status', 'warning')
    severity = insight.get('severity', 'low')
    message = insight.get('message', 'Análise não disponível')
    details = insight.get('details', [])
    recommendations = insight.get('recommendations', [])
    
    # Detalhes
    details_html = ''
    if details:
        details_items = ''.join(f'<li>{d}</li>' for d in details)
        details_html = f'<ul class="details-list">{details_items}</ul>'
    
    # Recomendações
    recommendations_html = ''
    if recommendations:
        recs = []
        for rec in recommendations:
            priority = rec.get('priority', 'medium')
            rec_title = rec.get('title', 'Recomendação')
            rec_desc = rec.get('description', '')
            rec_cmd = rec.get('command', '')
            
            cmd_html = ''
            if rec_cmd:
                cmd_html = f'<div class="command-box"><code>{rec_cmd}</code></div>'
            
            recs.append(f"""
                <div class="recommendation priority-{priority}">
                    <div class="rec-title">{rec_title}</div>
                    <div class="rec-description">{rec_desc}</div>
                    {cmd_html}
                </div>
            """)
        
        recommendations_html = f"""
            <div style="margin-top: 20px;">
                <h4>💡 Recomendações:</h4>
                {''.join(recs)}
            </div>
        """
    
    return f"""
        <div class="section" id="{section_id}-section">
            <h2 class="section-title">{title}</h2>
            
            <div class="card card-{status}">
                <div class="card-header">
                    <h3>{insight.get('status_text', 'Status')}</h3>
                    <span class="severity-badge severity-{severity}">{severity}</span>
                </div>
                
                <div class="analysis-text">
                    {format_markdown_to_html(message)}
                </div>
                
                {details_html}
                {recommendations_html}
                
                <div class="disclaimer" style="margin-top: 20px;">
                    <div class="disclaimer-title">ℹ️ Sobre esta Análise</div>
                    <p>Esta análise foi gerada automaticamente com base em regras condicionais. 
                    Ela pode não capturar nuances específicas do seu ambiente. 
                    Para uma análise mais profunda, consulte os dados brutos abaixo.</p>
                </div>
                
                <button class="json-toggle-btn" onclick="showJSON('{json_key}')">
                    📄 Ver Dados Brutos (JSON)
                </button>
            </div>
        </div>
    """


def generate_disclaimer() -> str:
    """Gera disclaimer sobre o modo local"""
    return """
        <div class="section">
            <div class="disclaimer">
                <div class="disclaimer-title">🏠 Modo Local - Sem IA</div>
                <p><strong>Este relatório foi gerado completamente offline usando análise baseada em regras.</strong></p>
                <p>Diferente do modo com IA (Google Gemini), este relatório:</p>
                <ul class="details-list">
                    <li>✅ Não envia nenhum dado para servidores externos</li>
                    <li>✅ Processa tudo localmente em sua máquina</li>
                    <li>✅ Mantém 100% de privacidade</li>
                    <li>⚠️ Possui análises mais genéricas (sem contexto específico da IA)</li>
                    <li>⚠️ Pode não detectar padrões complexos que a IA identificaria</li>
                </ul>
                <p style="margin-top: 15px;"><strong>💡 Dica:</strong> Use o modo com IA (<code>--full</code>) se precisar de análises mais profundas e contextuais, 
                mas lembre-se que isso enviará dados para a API do Google Gemini.</p>
            </div>
        </div>
    """


def generate_footer() -> str:
    """Gera rodapé"""
    return """
        <div class="footer">
            <p><strong>Security Reporter - Modo Local v1.0</strong></p>
            <p class="footer-note">Gerado localmente sem uso de IA | 100% Privado | Open Source</p>
            <p class="footer-note" style="margin-top: 10px;">
                <button onclick="printReport()" style="padding: 8px 16px; margin: 5px; cursor: pointer; border: none; background: #667eea; color: white; border-radius: 5px;">
                    🖨️ Imprimir
                </button>
                <button onclick="showJSON('full')" style="padding: 8px 16px; margin: 5px; cursor: pointer; border: none; background: #2d2d2d; color: white; border-radius: 5px;">
                    📄 Exportar JSON
                </button>
            </p>
        </div>
    """


def generate_json_modal() -> str:
    """Gera modal para exibição de JSON"""
    return """
        <div id="json-modal" class="json-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 id="json-title">Dados Brutos</h3>
                    <div>
                        <button class="copy-btn" onclick="copyJSON()">📋 Copiar</button>
                        <button class="modal-close" onclick="closeJSON()">×</button>
                    </div>
                </div>
                <pre id="json-content" class="json-viewer"></pre>
            </div>
        </div>
    """


def format_markdown_to_html(text: str) -> str:
    """
    Converte markdown básico para HTML
    
    Args:
        text: Texto com markdown simples
        
    Returns:
        HTML formatado
    """
    import re
    
    # Bold
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    
    # Italic
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
    
    # Code inline
    text = re.sub(r'`(.+?)`', r'<code style="background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-family: monospace;">\1</code>', text)
    
    # Line breaks
    text = text.replace('\n\n', '</p><p>')
    
    # Wrap in paragraph if not already
    if not text.startswith('<p>'):
        text = f'<p>{text}</p>'
    
    return text


def save_basic_html(data: Dict[str, Any], output_dir: str) -> str:
    """
    Gera e salva relatório HTML
    
    Args:
        data: Dados do relatório
        output_dir: Diretório de saída
        
    Returns:
        Caminho do arquivo gerado ou None em caso de erro
    """
    try:
        # Gerar HTML
        html = generate_basic_html(data)
        
        # Criar nome do arquivo
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = data.get('hostname', 'unknown')
        filename = f"security_report_local_{hostname}_{timestamp}.html"
        
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


if __name__ == "__main__":
    print("HTML Generator - Modo Local")
    print("Use através do security_reporter.py")

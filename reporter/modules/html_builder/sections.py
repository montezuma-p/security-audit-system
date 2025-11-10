"""
Sections - Geração de seções de análise técnica
"""

from typing import Dict, Any, List
from .formatters import format_markdown_to_html


def generate_status_badge(score_insight: Dict[str, Any]) -> str:
    """
    Gera badge de status geral
    
    Args:
        score_insight: Insight do score
        
    Returns:
        HTML do badge
    """
    status = score_insight.get('status', 'warning')
    status_text = score_insight.get('status_text', 'Status Desconhecido')
    
    return f'<div class="status-badge status-{status}">{status_text}</div>'


def generate_score_section(insight: Dict[str, Any], score_data: Dict[str, Any]) -> str:
    """
    Gera seção de score de segurança
    
    Args:
        insight: Insights do analyzer de score
        score_data: Dados brutos do score
        
    Returns:
        HTML da seção
    """
    metrics = insight.get('metrics', {})
    score = metrics.get('score', 0)
    grade = metrics.get('grade', 'N/A')
    
    # Verificar se tem conteúdo da IA
    ai_content = insight.get('ai_content', {})
    
    # Métricas cards (se vier da IA)
    metricas_cards_html = ''
    if ai_content and 'metricas_cards' in ai_content:
        metricas_cards_html = '<div class="metrics-grid">'
        for card in ai_content.get('metricas_cards', []):
            status_class = f"metric-{card.get('status', 'warning')}"
            metricas_cards_html += f'''
            <div class="metric-card {status_class}">
                <div class="metric-icon">{card.get('icon', '📊')}</div>
                <div class="metric-content">
                    <div class="metric-label">{card.get('label', 'N/A')}</div>
                    <div class="metric-value">{card.get('value', 'N/A')}</div>
                    <div class="metric-subtext">{card.get('subtext', '')}</div>
                </div>
            </div>
            '''
        metricas_cards_html += '</div>'
    
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
            
            {metricas_cards_html}
            
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
    """
    Gera todas as seções de análise
    
    Args:
        insights: Insights de todos os analyzers
        data: Dados brutos do relatório
        
    Returns:
        HTML de todas as seções
    """
    from .ai_sections import (
        generate_ai_section,
        generate_critical_alerts_section,
        generate_attack_vectors_section,
        generate_recommendations_section,
        generate_compliance_section,
        generate_next_steps_timeline
    )
    
    sections = []
    
    # Verificar se tem conteúdo da IA no score insight
    ai_content = insights.get('score', {}).get('ai_content', {})
    is_local_mode = not bool(ai_content)  # Se não tem IA, é modo local
    
    # Se tem IA, adicionar seções extras antes das análises técnicas
    if ai_content:
        # Resumo Executivo
        if ai_content.get('resumo_executivo'):
            sections.append(generate_ai_section(
                'resumo-executivo',
                '🎯 Resumo Executivo',
                ai_content.get('resumo_executivo'),
                'info'
            ))
        
        # Alertas Críticos
        if ai_content.get('alertas_criticos'):
            sections.append(generate_critical_alerts_section(ai_content.get('alertas_criticos')))
    
    # Mapeamento de seções técnicas
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
        sections.append(generate_analysis_card(key, title, insight, json_key, is_local_mode))
    
    # Se tem IA, adicionar seções extras no final
    if ai_content:
        # Vetores de Ataque
        if ai_content.get('vetores_ataque'):
            sections.append(generate_attack_vectors_section(ai_content.get('vetores_ataque')))
        
        # Recomendações de Hardening
        if ai_content.get('recomendacoes_hardening'):
            sections.append(generate_recommendations_section(ai_content.get('recomendacoes_hardening')))
        
        # Compliance Checklist
        if ai_content.get('compliance_checklist'):
            sections.append(generate_compliance_section(ai_content.get('compliance_checklist')))
        
        # Próximos Passos
        if ai_content.get('proximos_passos'):
            sections.append(generate_next_steps_timeline(ai_content.get('proximos_passos')))
        
        # Conclusão
        if ai_content.get('conclusao'):
            sections.append(generate_ai_section(
                'conclusao',
                '🎯 Conclusão',
                ai_content.get('conclusao'),
                'good'
            ))
    
    return '\n'.join(sections)


def generate_analysis_card(section_id: str, title: str, insight: Dict[str, Any], json_key: str, is_local: bool = True) -> str:
    """
    Gera card de análise individual
    
    Args:
        section_id: ID da seção
        title: Título da seção
        insight: Insights do analyzer
        json_key: Chave para os dados JSON
        is_local: Se True, mostra disclaimer de análise local
        
    Returns:
        HTML do card
    """
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
    
    # Disclaimer apenas para modo local
    disclaimer_html = ''
    if is_local:
        disclaimer_html = """
                <div class="disclaimer" style="margin-top: 20px;">
                    <div class="disclaimer-title">ℹ️ Sobre esta Análise</div>
                    <p>Esta análise foi gerada automaticamente com base em regras condicionais. 
                    Ela pode não capturar nuances específicas do seu ambiente. 
                    Para uma análise mais profunda, consulte os dados brutos abaixo ou use o modo com IA.</p>
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
                {disclaimer_html}
                
                <button class="json-toggle-btn" onclick="showJSON('{json_key}')">
                    📄 Ver Dados Brutos (JSON)
                </button>
            </div>
        </div>
    """


def generate_disclaimer(mode: str = 'local') -> str:
    """
    Gera disclaimer sobre o modo de geração
    
    Args:
        mode: 'ai' ou 'local'
        
    Returns:
        HTML do disclaimer
    """
    if mode == 'ai':
        return """
        <div class="section">
            <div class="disclaimer">
                <div class="disclaimer-title">🤖 Relatório Gerado com IA</div>
                <p><strong>Este relatório foi gerado usando Google Gemini 2.0 Flash Experimental.</strong></p>
                <p>A análise com IA oferece:</p>
                <ul class="details-list">
                    <li>✅ Análise contextual profunda dos dados</li>
                    <li>✅ Identificação de padrões complexos</li>
                    <li>✅ Recomendações personalizadas</li>
                    <li>✅ Correlação entre diferentes métricas</li>
                    <li>⚠️ Requer envio de dados sanitizados para API externa</li>
                </ul>
                <p style="margin-top: 15px;"><strong>🔒 Privacidade:</strong> Os dados foram sanitizados antes do envio, 
                removendo informações sensíveis como IPs privados, usernames e paths completos.</p>
            </div>
        </div>
        """
    else:
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
                <p style="margin-top: 15px;"><strong>💡 Dica:</strong> Use o modo com IA (<code>--mode=full</code>) se precisar de análises mais profundas e contextuais, 
                mas lembre-se que isso enviará dados sanitizados para a API do Google Gemini.</p>
            </div>
        </div>
        """

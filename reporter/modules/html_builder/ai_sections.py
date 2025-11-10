"""
AI Sections - Seções específicas para análise com IA
"""

from typing import Dict, List, Any


def generate_ai_section(section_id: str, title: str, content: str, status: str = 'info') -> str:
    """
    Gera seção genérica com conteúdo da IA
    
    Args:
        section_id: ID da seção
        title: Título da seção
        content: Conteúdo HTML ou markdown
        status: Status da seção (good, warning, critical, info)
        
    Returns:
        HTML da seção
    """
    from .formatters import format_markdown_to_html
    
    return f"""
        <div class="section" id="{section_id}">
            <h2 class="section-title">{title}</h2>
            <div class="card card-{status}">
                <div class="analysis-text">
                    {format_markdown_to_html(content)}
                </div>
            </div>
        </div>
    """


def generate_critical_alerts_section(alerts: List[Dict]) -> str:
    """
    Gera seção de alertas críticos da IA
    
    Args:
        alerts: Lista de alertas críticos
        
    Returns:
        HTML da seção
    """
    alerts_html = ''
    for alerta in alerts:
        alerts_html += f'''
        <div class="alert-critical">
            <div class="alert-header">
                <strong>🚨 {alerta.get('titulo', 'Alerta')}</strong>
                <span class="priority-badge priority-{alerta.get('prioridade', 3)}">
                    Prioridade {alerta.get('prioridade', 3)}
                </span>
            </div>
            <div class="alert-body">
                <p><strong>Problema:</strong> {alerta.get('descricao', '')}</p>
                <p><strong>Risco:</strong> {alerta.get('risco', '')}</p>
                <div class="solution-box">
                    <strong>✅ Solução Imediata:</strong>
                    <pre>{alerta.get('solucao_imediata', '')}</pre>
                </div>
            </div>
        </div>
        '''
    
    return f"""
        <div class="section" id="alertas-criticos">
            <h2 class="section-title">🚨 Alertas Críticos</h2>
            {alerts_html if alerts_html else '<p>Nenhum alerta crítico identificado.</p>'}
        </div>
    """


def generate_attack_vectors_section(vectors: List[Dict]) -> str:
    """
    Gera seção de vetores de ataque da IA
    
    Args:
        vectors: Lista de vetores de ataque
        
    Returns:
        HTML da seção
    """
    vectors_html = ''
    for vetor in vectors:
        risco = vetor.get('risco', 'medio').lower()
        risco_class = f"risk-{risco}"
        
        # Ícones baseado no risco
        risco_icon = {
            'alto': '🔴',
            'medio': '🟡',
            'baixo': '🟢'
        }.get(risco, '⚪')
        
        vectors_html += f'''
        <div class="attack-vector {risco_class}">
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                <span style="font-size: 1.5em;">{risco_icon}</span>
                <h4 style="margin: 0;">🎯 {vetor.get('vetor', 'Vetor Desconhecido')}</h4>
                <span class="severity-badge severity-{risco}" style="margin-left: auto;">{risco.upper()}</span>
            </div>
            
            <div style="background: rgba(255,255,255,0.5); padding: 15px; border-radius: 8px; margin-bottom: 10px;">
                <strong style="display: block; margin-bottom: 8px; color: #333;">📋 Descrição:</strong>
                <p style="margin: 0; line-height: 1.6;">{vetor.get('descricao', '')}</p>
            </div>
            
            <div style="background: rgba(40, 167, 69, 0.1); padding: 15px; border-radius: 8px; border-left: 4px solid #28a745;">
                <strong style="display: block; margin-bottom: 8px; color: #155724;">🛡️ Mitigação:</strong>
                <p style="margin: 0; line-height: 1.6;">{vetor.get('mitigacao', '')}</p>
            </div>
        </div>
        '''
    
    return f"""
        <div class="section" id="vetores-ataque">
            <h2 class="section-title">🎯 Vetores de Ataque Identificados</h2>
            {vectors_html if vectors_html else '<p>Nenhum vetor de ataque identificado.</p>'}
        </div>
    """


def generate_recommendations_section(recommendations: List[Dict]) -> str:
    """
    Gera seção de recomendações da IA como gavetas expansíveis
    
    Args:
        recommendations: Lista de recomendações de hardening
        
    Returns:
        HTML da seção
    """
    recs_html = ''
    for idx, rec in enumerate(recommendations, 1):
        prioridade = rec.get('prioridade', 'media').lower()
        priority_class = f"priority-{prioridade}"
        
        # Ícones baseado na prioridade
        priority_icon = {
            'urgente': '🚨',
            'alta': '⚠️',
            'media': '📌',
            'baixa': '💡'
        }.get(prioridade, '📋')
        
        comandos_html = ''
        if rec.get('comandos'):
            comandos_html = f'''
            <div style="margin-top: 15px;">
                <strong style="display: block; margin-bottom: 8px;">💻 Comandos:</strong>
                <div class="command-box"><pre>{chr(10).join(rec['comandos'])}</pre></div>
            </div>
            '''
        
        recs_html += f'''
        <div class="accordion-item {priority_class}" style="margin-bottom: 15px; border-radius: 8px; overflow: hidden; border: 2px solid #e0e0e0;">
            <div class="accordion-header" onclick="toggleAccordion('rec-{idx}')" style="cursor: pointer; padding: 20px; background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); display: flex; align-items: center; gap: 15px; transition: all 0.3s;">
                <span style="font-size: 1.5em;">{priority_icon}</span>
                <div style="flex: 1;">
                    <span class="rec-category" style="background: rgba(102, 126, 234, 0.7); color: white; padding: 3px 10px; border-radius: 12px; font-size: 0.75em; font-weight: 600;">[{rec.get('categoria', 'geral')}]</span>
                    <strong style="font-size: 1.15em; display: block; margin-top: 8px; color: #2d3748;">{rec.get('titulo', 'Recomendação')}</strong>
                </div>
                <span class="severity-badge severity-{prioridade}" style="font-size: 0.85em; padding: 6px 14px;">{prioridade.upper()}</span>
                <span class="accordion-arrow" style="font-size: 1.5em; transition: transform 0.3s;">▼</span>
            </div>
            
            <div id="rec-{idx}" class="accordion-content" style="display: none; padding: 0 20px; max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out;">
                <div style="padding: 20px 0;">
                    <div style="background: rgba(255,255,255,0.6); padding: 15px; border-radius: 8px; margin-bottom: 15px; border-left: 4px solid #667eea;">
                        <p style="margin: 0; line-height: 1.8; color: #4a5568;">{rec.get('descricao', '')}</p>
                    </div>
                    
                    {comandos_html}
                    
                    <div style="margin-top: 15px; padding: 12px; background: rgba(102, 126, 234, 0.1); border-radius: 6px; border-left: 4px solid #667eea;">
                        <p style="margin: 0;"><strong>📊 Impacto:</strong> <em style="color: #4a5568;">{rec.get('impacto', '')}</em></p>
                    </div>
                </div>
            </div>
        </div>
        '''
    
    return f"""
        <div class="section" id="recomendacoes">
            <h2 class="section-title">🔧 Recomendações de Hardening</h2>
            <p style="margin-bottom: 20px; color: #666; font-style: italic;">💡 Clique em cada recomendação para expandir e ver os detalhes</p>
            {recs_html if recs_html else '<p>Nenhuma recomendação adicional.</p>'}
        </div>
        
        <script>
        function toggleAccordion(id) {{
            const content = document.getElementById(id);
            const header = content.previousElementSibling;
            const arrow = header.querySelector('.accordion-arrow');
            
            if (content.style.display === 'none' || content.style.display === '') {{
                content.style.display = 'block';
                content.style.maxHeight = content.scrollHeight + 'px';
                arrow.style.transform = 'rotate(180deg)';
                header.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
                header.style.color = 'white';
            }} else {{
                content.style.maxHeight = '0';
                setTimeout(() => {{
                    content.style.display = 'none';
                }}, 300);
                arrow.style.transform = 'rotate(0deg)';
                header.style.background = 'linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%)';
                header.style.color = '#2d3748';
            }}
        }}
        </script>
    """


def generate_compliance_section(items: List[Dict]) -> str:
    """
    Gera seção de compliance com cards organizados
    
    Args:
        items: Lista de itens de compliance
        
    Returns:
        HTML da seção
    """
    # Separar por status
    passed = [item for item in items if item.get('status') == 'pass']
    failed = [item for item in items if item.get('status') == 'fail']
    warnings = [item for item in items if item.get('status') == 'warning']
    
    # Estatísticas
    total = len(items)
    pass_count = len(passed)
    fail_count = len(failed)
    warn_count = len(warnings)
    pass_percentage = (pass_count / total * 100) if total > 0 else 0
    
    # Cards HTML
    compliance_html = ''
    
    # Agrupar todos os itens
    all_items = [
        ('fail', '❌', 'Não Conforme', failed, '#dc3545'),
        ('warning', '⚠️', 'Atenção Necessária', warnings, '#ffc107'),
        ('pass', '✅', 'Conforme', passed, '#28a745')
    ]
    
    for status, icon, label, item_list, color in all_items:
        if not item_list:
            continue
            
        for item in item_list:
            compliance_html += f'''
            <div class="compliance-card compliance-{status}" style="background: white; border-radius: 12px; padding: 20px; margin-bottom: 15px; border-left: 6px solid {color}; box-shadow: 0 2px 8px rgba(0,0,0,0.1); transition: transform 0.2s, box-shadow 0.2s;" onmouseover="this.style.transform='translateY(-4px)'; this.style.boxShadow='0 4px 16px rgba(0,0,0,0.15)'" onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 2px 8px rgba(0,0,0,0.1)'">
                <div style="display: flex; align-items: flex-start; gap: 15px;">
                    <div style="font-size: 2em; line-height: 1;">{icon}</div>
                    <div style="flex: 1;">
                        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                            <h4 style="margin: 0; color: #2d3748; font-size: 1.1em;">{item.get('item', 'Check')}</h4>
                            <span style="background: {color}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.75em; font-weight: 600;">{label.upper()}</span>
                        </div>
                        <p style="margin: 0; color: #4a5568; line-height: 1.6;">{item.get('descricao', '')}</p>
                    </div>
                </div>
            </div>
            '''
    
    # Painel de estatísticas
    stats_panel = f'''
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 12px; padding: 25px; margin-bottom: 30px; color: white; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; text-align: center;">
            <div>
                <div style="font-size: 2.5em; font-weight: 700;">{total}</div>
                <div style="opacity: 0.9; margin-top: 5px;">Total de Checks</div>
            </div>
            <div>
                <div style="font-size: 2.5em; font-weight: 700; color: #d4edda;">✅ {pass_count}</div>
                <div style="opacity: 0.9; margin-top: 5px;">Conformes</div>
            </div>
            <div>
                <div style="font-size: 2.5em; font-weight: 700; color: #fff3cd;">⚠️ {warn_count}</div>
                <div style="opacity: 0.9; margin-top: 5px;">Atenção</div>
            </div>
            <div>
                <div style="font-size: 2.5em; font-weight: 700; color: #f8d7da;">❌ {fail_count}</div>
                <div style="opacity: 0.9; margin-top: 5px;">Não Conformes</div>
            </div>
            <div>
                <div style="font-size: 2.5em; font-weight: 700;">{pass_percentage:.1f}%</div>
                <div style="opacity: 0.9; margin-top: 5px;">Taxa de Conformidade</div>
            </div>
        </div>
    </div>
    '''
    
    return f"""
        <div class="section" id="compliance">
            <h2 class="section-title">✅ Compliance</h2>
            {stats_panel}
            {compliance_html if compliance_html else '<p>Nenhum item de compliance verificado.</p>'}
        </div>
    """


def generate_next_steps_timeline(content) -> str:
    """
    Gera seção de Próximos Passos como linha do tempo
    
    Args:
        content: Pode ser string (texto) ou lista (array de objetos)
        
    Returns:
        HTML da linha do tempo
    """
    from .formatters import format_markdown_to_html
    import re
    
    steps = []
    
    # Caso 1: Content é uma lista de dicts (formato novo da IA)
    if isinstance(content, list):
        for idx, item in enumerate(content, 1):
            if isinstance(item, dict):
                steps.append({
                    'number': str(idx),
                    'title': item.get('titulo', f'Passo {idx}'),
                    'description': item.get('descricao', ''),
                    'prazo': item.get('prazo', '')
                })
            else:
                # Fallback se item não for dict
                steps.append({
                    'number': str(idx),
                    'title': f'Etapa {idx}',
                    'description': str(item)
                })
    
    # Caso 2: Content é string (formato antigo - tentar parsear)
    elif isinstance(content, str):
        # Tentar extrair passos numerados do texto
        lines = content.split('\n')
        current_step = None
        
        for line in lines:
            # Detectar início de novo passo
            match = re.match(r'^(?:Passo\s+)?(\d+)[\.:)\s]+(.+)', line.strip(), re.IGNORECASE)
            if match:
                if current_step:
                    steps.append(current_step)
                current_step = {
                    'number': match.group(1),
                    'title': match.group(2).strip(),
                    'description': ''
                }
            elif current_step and line.strip():
                current_step['description'] += line.strip() + ' '
        
        if current_step:
            steps.append(current_step)
        
        # Se não encontrou passos estruturados, criar passos genéricos
        if not steps:
            # Dividir por parágrafos
            paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]
            steps = [{'number': str(i+1), 'title': f'Etapa {i+1}', 'description': p} for i, p in enumerate(paragraphs[:5])]
    
    # Se ainda não temos steps, criar um genérico
    if not steps:
        steps = [{
            'number': '1',
            'title': 'Revisar Recomendações',
            'description': 'Analise as recomendações de segurança apresentadas neste relatório e priorize as ações necessárias.'
        }]
    
    # Gerar HTML da timeline
    timeline_html = ''
    total_steps = len(steps)
    
    for idx, step in enumerate(steps, 1):
        is_last = (idx == total_steps)
        
        # Cores alternadas
        colors = ['#667eea', '#f093fb', '#4facfe', '#43e97b', '#fa709a']
        color = colors[(idx - 1) % len(colors)]
        
        # Badge de prazo (se houver)
        prazo_badge = ''
        if step.get('prazo'):
            prazo_badge = f'<span style="background: rgba(255,255,255,0.3); padding: 4px 10px; border-radius: 12px; font-size: 0.75em; margin-left: 10px;">⏱️ {step["prazo"]}</span>'
        
        timeline_html += f'''
        <div class="timeline-item" style="display: flex; gap: 20px; margin-bottom: 40px; position: relative;">
            <div style="flex-shrink: 0; display: flex; flex-direction: column; align-items: center;">
                <div style="width: 60px; height: 60px; border-radius: 50%; background: linear-gradient(135deg, {color} 0%, {color}aa 100%); display: flex; align-items: center; justify-content: center; color: white; font-size: 1.5em; font-weight: 700; box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 2;">
                    {idx}
                </div>
                {'' if is_last else '<div style="width: 4px; height: 100%; background: linear-gradient(180deg, ' + color + ' 0%, ' + color + '66 100%); margin-top: -10px; padding-bottom: 10px;"></div>'}
            </div>
            
            <div style="flex: 1; background: white; border-radius: 12px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-left: 4px solid {color}; transition: transform 0.2s, box-shadow 0.2s;" onmouseover="this.style.transform='translateX(8px)'; this.style.boxShadow='0 4px 16px rgba(0,0,0,0.15)'" onmouseout="this.style.transform='translateX(0)'; this.style.boxShadow='0 2px 8px rgba(0,0,0,0.1)'">
                <h4 style="margin: 0 0 12px 0; color: #2d3748; font-size: 1.2em; display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                    <span style="background: {color}; color: white; padding: 4px 12px; border-radius: 12px; font-size: 0.7em;">PASSO {idx}</span>
                    {step.get('title', f'Etapa {idx}')}
                    {prazo_badge}
                </h4>
                <p style="margin: 0; color: #4a5568; line-height: 1.7;">{step.get('description', '').strip()}</p>
            </div>
        </div>
        '''
    
    return f"""
        <div class="section" id="proximos-passos">
            <h2 class="section-title">📋 Próximos Passos</h2>
            <p style="margin-bottom: 30px; color: #666; font-style: italic;">🎯 Siga esta linha do tempo para implementar as melhorias de segurança</p>
            <div class="timeline-container" style="padding: 20px 0;">
                {timeline_html}
            </div>
        </div>
    """

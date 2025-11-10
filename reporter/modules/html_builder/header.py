"""
Header - Geração de cabeçalhos do relatório
"""


def generate_header(hostname: str, timestamp: str, mode: str = 'local') -> str:
    """
    Gera cabeçalho do relatório
    
    Args:
        hostname: Nome do host
        timestamp: Data/hora da geração
        mode: 'ai' ou 'local'
        
    Returns:
        HTML do cabeçalho
    """
    if mode == 'ai':
        subtitle = "Análise Avançada com IA (Google Gemini)"
        mode_badge = '<div class="mode-badge ai-mode">🤖 Análise com IA - Google Gemini 2.0</div>'
    else:
        subtitle = "Análise Automatizada de Segurança"
        mode_badge = '<div class="mode-badge">🏠 100% Local - Sem IA - Nenhum Dado Enviado</div>'
    
    return f"""
        <div class="header">
            <h1>🔒 Security Reporter</h1>
            <div class="subtitle">{subtitle}</div>
            {mode_badge}
            <div class="timestamp">⏰ {timestamp}</div>
            <div class="timestamp">🖥️ {hostname}</div>
        </div>
    """

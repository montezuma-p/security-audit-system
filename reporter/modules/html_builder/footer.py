"""
Footer - Geração de rodapé e modais
"""


def generate_footer(mode: str = 'local') -> str:
    """
    Gera rodapé do relatório
    
    Args:
        mode: 'ai' ou 'local'
        
    Returns:
        HTML do rodapé
    """
    if mode == 'ai':
        tech_line = "Gerado com Google Gemini 2.0 Flash | Análise com IA"
    else:
        tech_line = "Gerado localmente sem uso de IA | 100% Privado | Open Source"
    
    return f"""
        <div class="footer">
            <p><strong>Security Reporter v2.0</strong></p>
            <p class="footer-note">{tech_line}</p>
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
    """
    Gera modal para exibição de JSON
    
    Returns:
        HTML do modal
    """
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

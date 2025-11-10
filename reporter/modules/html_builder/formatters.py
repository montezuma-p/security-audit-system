"""
Formatters - Funções de formatação e carregamento de assets
"""

import re
from pathlib import Path
from typing import Dict, Any


def format_markdown_to_html(text: str) -> str:
    """
    Converte markdown básico para HTML
    
    Args:
        text: Texto com markdown simples
        
    Returns:
        HTML formatado
    """
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


def load_asset(filename: str) -> str:
    """
    Carrega arquivo de asset (CSS ou JS)
    
    Args:
        filename: Nome do arquivo em templates/assets/
        
    Returns:
        Conteúdo do arquivo como string
    """
    current_dir = Path(__file__).parent.parent
    asset_path = current_dir.parent / 'templates' / 'assets' / filename
    
    try:
        with open(asset_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"⚠️ Arquivo de asset não encontrado: {asset_path}")
        return f"/* Asset {filename} not found */"

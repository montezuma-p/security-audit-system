#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI Security Reporter - Gerador de Relatórios de Segurança usando Gemini
Analisa JSONs do security_monitor e gera relatórios HTML humanizados


  █████████████████████████████████████████
  █                                       █
  █   ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░     █
  █   ░   B Y   M O N T E Z U M A   ░     █
  █   ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░     █
  █                                       █
  █████████████████████████████████████████

"""

import os
import sys
import json
import glob
import argparse
from pathlib import Path
from datetime import datetime

# Importar módulos locais
from modules.sanitizer import sanitize_report
from modules.html_generator import save_html

# Imports condicionais para Google Gemini (só necessário para modo full)
try:
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    genai = None
    types = None

# Imports condicionais para Google Gemini (só necessário para modo full)
try:
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    genai = None
    types = None


def get_default_reports_dir() -> Path:
    """Retorna diretório padrão de input (JSONs)"""
    return Path.home() / ".bin/data/scripts-data/reports/security/raw"


def get_default_output_dir() -> Path:
    """Retorna diretório padrão de output (HTMLs)"""
    return Path.home() / ".bin/data/scripts-data/reports/security/html"


# Obter API key (opcional - só necessária para modo full)
api_key = os.getenv('GEMINI_API_KEY')

# Inicializar cliente Gemini (só se módulo disponível E API key configurada)
client = None
model = "gemini-2.5-flash"

if GEMINI_AVAILABLE and api_key:
    client = genai.Client(api_key=api_key)

# Configurar caminhos (prioridade: ENV > default)
REPORTS_DIR = Path(os.getenv(
    'SECURITY_MONITOR_OUTPUT',
    str(get_default_reports_dir())
)).expanduser()

OUTPUT_DIR = Path(os.getenv(
    'SECURITY_REPORTER_OUTPUT',
    str(get_default_output_dir())
)).expanduser()


def confirmar_envio_ia(sanitize_level: str = "moderate") -> bool:
    """Confirma com o usuário antes de enviar dados para IA"""
    print("\n" + "="*70)
    print("⚠️  ATENÇÃO: PRIVACIDADE E SEGURANÇA")
    print("="*70)
    print("\n📤 Os dados de segurança serão enviados para Google Gemini API")
    print(f"🔐 Nível de sanitização: {sanitize_level.upper()}")
    
    # Mostrar o que será enviado baseado no nível
    print("\n🔍 Informações que SERÃO compartilhadas:")
    
    if sanitize_level == "none":
        print("\n   ⚠️  NENHUMA SANITIZAÇÃO - DADOS ORIGINAIS:")
        print("   • ⚠️ IPs REAIS (locais e remotos)")
        print("   • ⚠️ Usernames REAIS do sistema")
        print("   • ⚠️ Hostname REAL da máquina")
        print("   • ⚠️ Paths completos com seu username")
        print("   • ⚠️ Portas abertas e serviços")
        print("   • ⚠️ Vulnerabilidades conhecidas (CVEs)")
        print("   • ⚠️ Configurações de segurança")
        print("   • ⚠️ Logs de autenticação")
        print("\n   🚨 ATENÇÃO: Seus dados pessoais serão enviados sem anonimização!")
        
    elif sanitize_level == "light":
        print("\n   📊 SANITIZAÇÃO LEVE:")
        print("   • ✅ IPs privados: último octeto anonimizado (192.168.1.X)")
        print("   • ❌ IPs públicos/atacantes: mantidos (útil para análise)")
        print("   • ❌ Usernames: mantidos")
        print("   • ❌ Hostname: mantido")
        print("   • ✅ Portas abertas e serviços")
        print("   • ✅ Vulnerabilidades conhecidas (CVEs)")
        print("   • ✅ Configurações de segurança")
        print("   • ✅ Logs de autenticação")
        
    elif sanitize_level == "moderate":
        print("\n   � SANITIZAÇÃO MODERADA (Recomendada):")
        print("   • ✅ IPs privados: 2 últimos octetos anonimizados (192.168.X.X)")
        print("   • ⚠️  IPs públicos/atacantes: mantidos (para identificar ameaças)")
        print("   • ✅ Usernames: anonimizados (user1, user2, etc)")
        print("   • ✅ Hostname: anonimizado (workstation-001)")
        print("   • ✅ Paths: username removido (/home/$USER/)")
        print("   • ✅ Portas abertas e serviços")
        print("   • ✅ Vulnerabilidades conhecidas (CVEs)")
        print("   • ✅ Configurações de segurança")
        print("   • ✅ Logs de autenticação (com dados anonimizados)")
        
    elif sanitize_level == "strict":
        print("\n   🔒 SANITIZAÇÃO ESTRITA (Máxima Privacidade):")
        print("   • ✅ IPs privados: 3 últimos octetos anonimizados (192.X.X.X)")
        print("   • ✅ IPs públicos: parcialmente anonimizados (203.0.XXX.XXX)")
        print("   • ✅ IPs atacantes: região mantida (45.132.XXX.XXX)")
        print("   • ✅ Usernames: todos anonimizados (user1, user2)")
        print("   • ✅ Hostname: anonimizado (workstation-001)")
        print("   • ✅ Paths: username removido (/home/$USER/)")
        print("   • ✅ Portas abertas e serviços")
        print("   • ✅ Vulnerabilidades conhecidas (CVEs)")
        print("   • ✅ Configurações de segurança")
        print("   • ✅ Logs de autenticação (totalmente anonimizados)")
    
    print("\n📋 Dados estruturais (sempre enviados):")
    print("   • Métricas numéricas (quantidade de portas, alertas, etc)")
    print("   • Status de serviços (ativo/inativo)")
    print("   • Configurações de segurança (firewall, SELinux)")
    print("   • Nomes de pacotes vulneráveis e CVEs")
    
    print("\n💡 Alternativas mais privadas:")
    print("   • --local-html : Análise local sem IA (sem envio de dados)")
    print("   • --no-ai      : Apenas JSON local (sem envio de dados)")
    
    print("\n" + "="*70)
    
    while True:
        resposta = input("\n🔐 Confirma o envio destes dados para análise de IA? (yes/no): ").strip().lower()
        if resposta in ['yes', 'y', 'sim', 's']:
            print("\n✅ Confirmado. Prosseguindo com análise...\n")
            return True
        elif resposta in ['no', 'n', 'não', 'nao']:
            print("\n❌ Operação cancelada pelo usuário.")
            print("💡 Dica: Use --local-html para análise sem IA ou --no-ai para apenas JSON\n")
            return False
        else:
            print("⚠️  Digite 'yes' para confirmar ou 'no' para cancelar")


def obter_ultimo_json():
    """Obtém o arquivo JSON mais recente do diretório de relatórios"""
    json_files = glob.glob(str(REPORTS_DIR / "security_*.json"))
    
    if not json_files:
        print(f"❌ Nenhum relatório encontrado em {REPORTS_DIR}")
        return None
    
    # Pegar o arquivo mais recente
    latest_file = max(json_files, key=os.path.getctime)
    return Path(latest_file)


def ler_json(filepath):
    """Lê e retorna o conteúdo do arquivo JSON"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Erro ao ler arquivo {filepath}: {e}")
        return None


def criar_prompt_analise(dados_json):
    """Cria o prompt para a IA analisar o relatório de segurança"""
    
    prompt = f"""Você é um especialista em segurança de sistemas Linux com certificações CISSP e CEH, 15 anos de experiência em hardening de servidores Fedora/RHEL.

Analise este relatório de auditoria de segurança e crie uma análise INTERPRETATIVA e ACIONÁVEL em formato JSON.

DADOS DA AUDITORIA:
```json
{json.dumps(dados_json, indent=2, ensure_ascii=False)}
```

IMPORTANTE: Retorne um JSON estruturado que será usado para preencher um template HTML.

ESTRUTURA DO JSON A RETORNAR:

{{
    "resumo_executivo": "2-3 parágrafos explicando o NÍVEL DE RISCO GERAL do sistema. Seja direto: o sistema está seguro? Quais são os maiores riscos? Precisa de ação imediata?",
    
    "security_score_analise": "Análise do score de segurança. Explique o que o score significa, por que está nesse nível, se é aceitável para um workstation.",
    
    "metricas_cards": [
        {{
            "icon": "🔒 ou 🔓 ou ⚠️",
            "label": "Nome da métrica",
            "value": "Valor principal",
            "subtext": "Status (Seguro/Risco/Crítico)",
            "status": "good, warning ou critical"
        }}
    ],
    
    "alertas_criticos": [
        {{
            "titulo": "Título do alerta crítico",
            "descricao": "O que está exposto/vulnerável",
            "risco": "Qual é o risco REAL (em termos de o que um atacante poderia fazer)",
            "solucao_imediata": "Comandos ou passos EXATOS para corrigir AGORA",
            "prioridade": 1-5 (1=urgentíssimo, 5=quando puder)"
        }}
    ],
    
    "analise_portas": "Análise das portas abertas. Quais são legítimas? Quais são suspeitas? Há serviços expostos desnecessariamente? Contextualize cada porta suspeita.",
    
    "analise_autenticacao": "Análise de autenticação. Há tentativas de invasão? Força bruta detectada? SSH está configurado de forma segura? Logins suspeitos?",
    
    "analise_firewall": "Análise do firewall e SELinux. Estão ativos? Configuração adequada? Zonas corretas? SELinux protegendo?",
    
    "analise_vulnerabilidades": "Análise de vulnerabilidades. Quantas atualizações de segurança? Há CVEs críticos? Sistema desatualizado? Kernel precisa reboot?",
    
    "analise_rede": "Análise da rede. Conectividade ok? DNS seguro? Configurações de rede têm problemas de segurança (IP forwarding, etc)?",
    
    "analise_permissoes": "Análise de permissões. Arquivos críticos protegidos? Chaves SSH seguras? SUID suspeitos? World-writable files?",
    
    "vetores_ataque": [
        {{
            "vetor": "Nome do vetor (ex: SSH Brute Force)",
            "risco": "alto, medio ou baixo",
            "descricao": "Como um atacante exploraria isso",
            "mitigacao": "Como bloquear esse vetor"
        }}
    ],
    
    "recomendacoes_hardening": [
        {{
            "prioridade": "urgente, alta, media ou baixa",
            "categoria": "firewall, ssh, updates, permissoes, etc",
            "titulo": "Título da recomendação",
            "descricao": "Por que fazer isso",
            "comandos": ["comando1", "comando2"] ou null,
            "impacto": "O que melhora fazendo isso"
        }}
    ],
    
    "compliance_checklist": [
        {{
            "item": "Nome do check (ex: Firewall Ativo)",
            "status": "pass, fail ou warning",
            "descricao": "Status atual"
        }}
    ],
    
    "proximos_passos": [
        {{
            "titulo": "Primeiras 24 horas",
            "descricao": "Ações urgentes que devem ser tomadas imediatamente",
            "prazo": "24h"
        }},
        {{
            "titulo": "Próxima semana",
            "descricao": "Melhorias importantes a implementar",
            "prazo": "7d"
        }},
        {{
            "titulo": "Próximo mês",
            "descricao": "Hardening adicional e otimizações",
            "prazo": "30d"
        }}
    ],
    
    "conclusao": "1-2 parágrafos: o sistema é seguro o suficiente? Principais vulnerabilidades? Ação mais urgente?"
}}

REGRAS CRÍTICAS:

🔴 SEJA DIRETO sobre riscos - não suavize problemas críticos
🔴 CONTEXTUALIZE ameaças - explique o que um atacante REALMENTE poderia fazer
🔴 DÊ COMANDOS EXATOS - copiar/colar deve funcionar
🔴 PRIORIZE - deixe claro o que é urgente vs o que pode esperar
🔴 EDUQUE - explique POR QUE cada coisa é um risco

EXEMPLOS DO TOM:

❌ ERRADO: "Porta 3306 está aberta"
✅ CORRETO: "🚨 CRÍTICO: MySQL (porta 3306) está exposta para a Internet! Qualquer pessoa pode tentar acessar seu banco de dados. Isso é equivalente a deixar a porta da sua casa aberta."

❌ ERRADO: "127 tentativas de login SSH falharam"
✅ CORRETO: "⚠️ ATAQUE EM ANDAMENTO: O IP 1.2.3.4 fez 127 tentativas de login SSH nas últimas 24h (ataque de força bruta). Este é um bot tentando adivinhar suas senhas."

❌ ERRADO: "SELinux está em modo Permissive"
✅ CORRETO: "⚠️ PROTEÇÃO REDUZIDA: SELinux está em modo Permissive, o que significa que ele MONITORA mas NÃO BLOQUEIA ataques. É como ter um alarme que apita mas não chama a polícia."

❌ ERRADO: "5 atualizações de segurança disponíveis"
✅ CORRETO: "🔴 VULNERABILIDADES CONHECIDAS: Há 5 patches de segurança não instalados. Atacantes conhecem essas falhas e têm exploits prontos. Instalar updates é como trancar a porta que você deixou aberta."

FOQUE EM RISCO REAL:
- Um workstation pessoal pode ter requisitos diferentes de um servidor
- Explique se cada alerta é crítico para o contexto de workstation
- Priorize o que REALMENTE importa vs checklist de compliance

Retorne APENAS o JSON válido, sem markdown, sem explicações extras.
"""
    
    return prompt


def tentar_recuperar_json(texto: str) -> dict:
    """
    Tenta recuperar/completar um JSON incompleto ou mal formatado
    
    Args:
        texto: Texto potencialmente com JSON incompleto
        
    Returns:
        Dict com JSON parseado ou None
    """
    import re
    
    # Remover possíveis marcadores de código
    texto = texto.strip()
    if texto.startswith('```json'):
        texto = texto[7:]
    if texto.startswith('```'):
        texto = texto[3:]
    if texto.endswith('```'):
        texto = texto[:-3]
    texto = texto.strip()
    
    # Tentar parsear diretamente primeiro
    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        pass
    
    # Tentar encontrar o JSON no meio do texto
    match = re.search(r'\{.*\}', texto, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    
    # Tentar completar JSON incompleto
    # Contar chaves abertas vs fechadas
    open_braces = texto.count('{')
    close_braces = texto.count('}')
    open_brackets = texto.count('[')
    close_brackets = texto.count(']')
    
    # Remover aspas não fechadas no final
    if texto.rstrip().endswith('...'):
        texto = texto.rstrip()[:-3].rstrip()
        if texto.endswith(','):
            texto = texto[:-1]
    
    # Fechar strings não fechadas
    if texto.count('"') % 2 != 0:
        # Última aspas não fechada
        last_quote = texto.rfind('"')
        # Verificar se está no meio de um valor
        if last_quote > 0 and texto[last_quote-1] != '\\':
            # Adicionar fechamento de string
            texto = texto[:last_quote] + texto[last_quote:].replace('\n', '').rstrip() + '"'
    
    # Fechar arrays
    for _ in range(open_brackets - close_brackets):
        texto += ']'
    
    # Fechar objetos
    for _ in range(open_braces - close_braces):
        texto += '}'
    
    # Tentar parsear novamente
    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        return None


def chamar_ia_gemini(prompt):
    """Chama a API do Gemini e retorna a resposta"""
    try:
        print("🤖 Enviando dados para Gemini AI...")
        
        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.3,
                max_output_tokens=8000,
            )
        )
        
        # Extrair o texto da resposta
        resposta_texto = response.text
        
        print("📥 Resposta recebida. Processando...")
        
        # Tentar recuperar JSON
        analise = tentar_recuperar_json(resposta_texto)
        
        if analise:
            print("✅ Análise recebida da IA")
            return analise
        else:
            print("❌ Não foi possível parsear JSON da resposta da IA")
            print(f"📄 Primeiros 500 caracteres: {resposta_texto[:500]}...")
            
            # Salvar resposta completa para debug
            debug_file = OUTPUT_DIR / f"gemini_response_error_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            try:
                debug_file.parent.mkdir(parents=True, exist_ok=True)
                with open(debug_file, 'w', encoding='utf-8') as f:
                    f.write(resposta_texto)
                print(f"💾 Resposta completa salva em: {debug_file}")
            except:
                pass
            
            return None
        
    except Exception as e:
        print(f"❌ Erro ao chamar API Gemini: {e}")
        import traceback
        traceback.print_exc()
        return None


def abrir_no_navegador(filepath):
    """Abre o relatório HTML no navegador padrão"""
    try:
        os.system(f"xdg-open '{filepath}'")
        return True
    except Exception as e:
        print(f"⚠️ Não foi possível abrir automaticamente: {e}")
        return False


def main():
    """Função principal"""
    
    # Verificar disponibilidade do Google Gemini ANTES de fazer argparse
    if not GEMINI_AVAILABLE:
        print("="*70)
        print("⚠️  MÓDULO GOOGLE GEMINI NÃO ENCONTRADO")
        print("="*70)
        print()
        print("❌ O módulo 'google-genai' não está instalado/disponível.")
        print()
        print("Possíveis causas:")
        print("  • A venv não está ativada")
        print("  • O módulo não foi instalado: pip install google-genai")
        print()
        print("🔒 MODO DISPONÍVEL: Apenas --mode=basic (HTML local sem IA)")
        print()
        print("="*70)
        print()
    
    # Configurar argparse
    parser = argparse.ArgumentParser(
        description='🔒 AI Security Reporter - Análise Inteligente de Segurança',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemplos de uso:
  %(prog)s --mode=basic                       # HTML local sem IA (sempre disponível)
  %(prog)s --mode=basic --sanitize=none       # HTML local com dados reais
''' + ('''
  %(prog)s                                    # Modo padrão (AI com sanitização moderada)
  %(prog)s --sanitize=strict                  # Máxima anonimização antes de enviar para IA
  %(prog)s --sanitize=none                    # Enviar dados brutos (NÃO RECOMENDADO)
''' if GEMINI_AVAILABLE else '''
  ⚠️  Modos com IA não disponíveis (módulo google-genai não encontrado)
  💡 Ative a venv ou instale: pip install google-genai
''') + '''
Níveis de sanitização:
  none      - Nenhuma sanitização (dados brutos)
  light     - Sanitiza apenas IPs locais (192.168.x.x, 127.0.0.1)
  moderate  - Sanitiza IPs locais + usernames do sistema (padrão)
  strict    - Máxima anonimização (IPs, usernames, CVEs, logs)

Modos de operação:
''' + ('''  full      - Análise com Google Gemini AI (padrão)
''' if GEMINI_AVAILABLE else '''  full      - [INDISPONÍVEL] Requer google-genai
''') + '''  basic     - HTML básico sem IA (100%% local)
        '''
    )
    
    parser.add_argument(
        '--sanitize',
        choices=['none', 'light', 'moderate', 'strict'],
        default='moderate',
        help='Nível de sanitização dos dados (padrão: moderate)'
    )
    
    parser.add_argument(
        '--mode',
        choices=['basic', 'full'],
        default='basic' if not GEMINI_AVAILABLE else 'full',
        help='Modo de geração do relatório' + 
             (' (padrão: basic - IA não disponível)' if not GEMINI_AVAILABLE else ' (padrão: full)')
    )
    
    parser.add_argument(
        '--no-browser',
        action='store_true',
        help='Não abrir automaticamente o navegador'
    )
    
    args = parser.parse_args()
    
    # Verificar se modo full foi solicitado mas Gemini não está disponível
    if args.mode == 'full' and not GEMINI_AVAILABLE:
        print()
        print("="*70)
        print("❌ ERRO: Modo 'full' requer o módulo google-genai")
        print("="*70)
        print()
        print("O modo com IA não está disponível no momento.")
        print()
        print("Soluções:")
        print("  1. Ative a venv: source venv/bin/activate")
        print("  2. Ou instale o módulo: pip install google-genai")
        print("  3. Ou use o modo básico: --mode=basic")
        print()
        print("="*70)
        
        try:
            input("\n⏎ Pressione ENTER para ver o help e refazer o comando...")
            print()
            parser.print_help()
            print()
        except KeyboardInterrupt:
            print("\n")
        
        sys.exit(1)
    
    # Cabeçalho diferente para cada modo
    if args.mode == 'basic':
        print("🔒 Security Reporter - Modo Local (sem IA)")
        print("📄 Relatório HTML Básico (100% Local)")
        print()
        print("Feito por: Montezuma")
        print()
        print(f"📋 Modo: Básico (sem IA)")
        print(f"🔐 Sanitização: {args.sanitize}")
        print(f"🔒 Privacidade: 100% local - nenhum dado enviado externamente")
        print()
    else:
        print("� AI Security Reporter - Análise Inteligente de Segurança")
        print("🤖 Powered by Google Gemini")
        print()
        print("Feito por: Montezuma")
        print()
        print(f"📋 Modo: Completo (com IA)")
        print(f"🔐 Sanitização: {args.sanitize}")
        print()
    
    try:
        # 1. Obter último JSON
        print("📂 Procurando relatórios de segurança...")
        json_path = obter_ultimo_json()
        
        if not json_path:
            print("💡 Execute primeiro o security_monitor.py para gerar um relatório!")
            sys.exit(1)
        
        print(f"✅ Relatório encontrado: {json_path.name}")
        
        # 2. Ler JSON
        print("📖 Lendo dados do relatório...")
        dados = ler_json(json_path)
        if not dados:
            sys.exit(1)
        
        # 3. Sanitizar dados se necessário
        dados_processados = dados
        if args.sanitize != 'none':
            print(f"🧹 Sanitizando dados (nível: {args.sanitize})...")
            dados_processados, sanitization_summary = sanitize_report(dados, level=args.sanitize)
            print(f"✅ Dados sanitizados")
        
        # 4. Processar de acordo com o modo
        filepath = None
        
        if args.mode == 'basic':
            # Modo básico: HTML sem IA
            print("🎨 Gerando relatório HTML local (sem IA)...")
            filepath = save_html(dados_processados, str(OUTPUT_DIR), ai_analysis=None)
            if not filepath:
                print("❌ Erro ao gerar HTML")
                sys.exit(1)
        
        else:
            # Modo full: com IA
            
            # Verificar API key
            if not api_key:
                print("❌ ERRO: Variável GEMINI_API_KEY não encontrada!")
                print("Configure com: export GEMINI_API_KEY='sua_chave_aqui'")
                print("\n💡 Ou use --mode=basic para gerar relatório sem IA")
                sys.exit(1)
            
            # Confirmar envio para IA (passar nível de sanitização)
            if not confirmar_envio_ia(sanitize_level=args.sanitize):
                print("\n💡 Dica: Use --mode=basic para gerar relatório local sem IA")
                sys.exit(0)
            
            # Criar prompt e chamar IA
            prompt = criar_prompt_analise(dados_processados)
            analise = chamar_ia_gemini(prompt)
            
            # FALLBACK: Se IA falhou, gerar relatório local
            if not analise:
                print("\n" + "="*70)
                print("⚠️  FALLBACK AUTOMÁTICO: IA Indisponível")
                print("="*70)
                print()
                print("❌ A análise com IA falhou (JSON inválido ou erro de API)")
                print("🔄 Gerando automaticamente relatório local em vez disso...")
                print()
                print("✨ Você ainda terá um relatório completo, mas sem análise da IA")
                print("="*70)
                print()
                
                # Gerar HTML local (sem IA)
                print("🎨 Gerando relatório HTML local (modo fallback)...")
                filepath = save_html(dados_processados, str(OUTPUT_DIR), ai_analysis=None)
                
                if not filepath:
                    print("❌ Erro ao gerar HTML (mesmo no fallback)")
                    sys.exit(1)
                
                # Marcar que foi fallback
                args.mode = 'basic'  # Ajustar para mensagens corretas depois
            else:
                # Gerar HTML com análise da IA
                print("🎨 Gerando relatório HTML com IA...")
                filepath = save_html(dados, str(OUTPUT_DIR), ai_analysis=analise)
                if not filepath:
                    sys.exit(1)
        
        # 5. Sucesso!
        print("\n" + "="*60)
        if args.mode == 'basic':
            print("✨ RELATÓRIO HTML LOCAL GERADO COM SUCESSO!")
            print("="*60)
            print("\n🔒 100% Local - Nenhum dado foi enviado externamente")
        else:
            print("✨ RELATÓRIO DE SEGURANÇA GERADO COM SUCESSO!")
            print("="*60)
        
        # 6. Abrir no navegador (se não --no-browser)
        if not args.no_browser:
            while True:
                abrir = input("\n🌐 Abrir relatório no navegador? (s/n): ").strip().lower()
                if abrir in ['s', 'sim', 'y', 'yes']:
                    if abrir_no_navegador(filepath):
                        print("✅ Relatório aberto no navegador!")
                    else:
                        print(f"\n💡 Abra manualmente: {filepath}")
                    break
                elif abrir in ['n', 'nao', 'não', 'no']:
                    print(f"\n💡 Você pode abrir depois: {filepath}")
                    break
                else:
                    print("Digite 's' para sim ou 'n' para não")
        else:
            print(f"\n📄 Relatório salvo em: {filepath}")
        
        if args.mode == 'basic':
            print("\n✅ Análise local concluída! Até mais!")
        else:
            print("\n👋 Análise concluída! Até mais!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Programa interrompido pelo usuário!")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Erro fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

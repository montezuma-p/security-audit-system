#!/bin/bash
#
# Security Audit - Wrapper script
# Permite executar auditoria completa (com IA) ou apenas coleta local
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONITOR="${SCRIPT_DIR}/monitor/security_monitor.py"
REPORTER="${SCRIPT_DIR}/reporter/security_reporter.py"

# Função para verificar se módulo google-genai está disponível
check_gemini_available() {
    python3 -c "from google import genai" 2>/dev/null
    return $?
}

# Função para verificar se módulo psutil está disponível
check_psutil_available() {
    python3 -c "import psutil" 2>/dev/null
    return $?
}

# Verificar disponibilidade dos módulos
GEMINI_AVAILABLE=false
PSUTIL_AVAILABLE=false

if check_gemini_available; then
    GEMINI_AVAILABLE=true
fi

if check_psutil_available; then
    PSUTIL_AVAILABLE=true
fi

show_usage() {
    # Mostrar avisos se módulos não disponíveis
    local has_warnings=false
    
    if [ "$PSUTIL_AVAILABLE" = false ]; then
        has_warnings=true
        cat << EOF
======================================================================
❌ ERRO CRÍTICO: MÓDULO PSUTIL NÃO ENCONTRADO
======================================================================

O módulo 'psutil' é OBRIGATÓRIO para o monitor de segurança funcionar.

❌ Sem psutil, NENHUM modo funcionará (--no-ai, --local-html, --full)

Soluções:
  1. Ative a venv: source venv/bin/activate
  2. Ou instale: pip install psutil
  3. Ou instale tudo: pip install -r requirements.txt

======================================================================

EOF
    fi
    
    if [ "$GEMINI_AVAILABLE" = false ] && [ "$PSUTIL_AVAILABLE" = true ]; then
        has_warnings=true
        cat << EOF
======================================================================
⚠️  MÓDULO GOOGLE GEMINI NÃO ENCONTRADO
======================================================================

❌ O módulo 'google-genai' não está instalado/disponível.

Possíveis causas:
  • A venv não está ativada
  • O módulo não foi instalado

Soluções:
  1. Ative a venv: source venv/bin/activate
  2. Ou instale: pip install google-genai
  3. Ou instale tudo: pip install -r requirements.txt

🔒 MODOS DISPONÍVEIS SEM IA:
  --no-ai          Apenas JSON local (sempre disponível) ✅
  --local-html     HTML básico local sem IA (sempre disponível) ✅

⚠️  MODO INDISPONÍVEL:
  --full           Requer google-genai (instale primeiro) ❌

======================================================================

EOF
    fi
    
    cat << EOF
🔒 Security Audit - Sistema de Auditoria de Segurança

Uso: $0 [OPÇÃO] [FLAGS]

OPÇÕES PRINCIPAIS:
EOF

    if [ "$GEMINI_AVAILABLE" = true ]; then
        cat << EOF
    --full, --with-ai       Auditoria completa com análise de IA ✅
                           (coleta dados + envia para Google Gemini)
EOF
    else
        cat << EOF
    --full, --with-ai       [INDISPONÍVEL] Requer google-genai ❌
                           (instale: pip install google-genai)
EOF
    fi

    cat << EOF
    
    --no-ai, --local-only   Apenas coleta de dados local ✅
                           (não envia nada para APIs externas)
    
    --local-html            Gera HTML básico local (sem IA) ✅
                           (coleta dados + HTML simples, 100% local)

FLAGS ADICIONAIS (apenas com --full ou --local-html):
    --sanitize=LEVEL        Nível de sanitização dos dados
                           Valores: none, light, moderate, strict
                           Padrão: moderate
    
    --no-browser            Não abrir automaticamente o navegador
    
    -h, --help              Mostra esta mensagem

EXEMPLOS:
EOF

    if [ "$GEMINI_AVAILABLE" = true ]; then
        cat << EOF
    $0 --full                          # Auditoria completa + IA (sanitização moderada)
    $0 --full --sanitize=strict        # Máxima anonimização antes de enviar para IA
    $0 --full --sanitize=none          # Enviar dados brutos (NÃO RECOMENDADO)
    
EOF
    fi

    cat << EOF
    $0 --local-html                    # HTML básico sem IA (100% local)
    $0 --local-html --sanitize=none    # HTML local com dados reais
    
    $0 --no-ai                         # Apenas JSON local (sem HTML, sem IA)

NÍVEIS DE SANITIZAÇÃO:
    none        Nenhuma sanitização (dados brutos - use apenas se confiar 100% na IA)
    light       Sanitiza apenas IPs locais (192.168.x.x, 127.0.0.1)
    moderate    Sanitiza IPs locais + usernames do sistema (PADRÃO - recomendado)
    strict      Máxima anonimização (IPs, usernames, CVEs, logs)

MODOS DE OPERAÇÃO:
    --no-ai         → Só monitor (JSON local)
    --local-html    → Monitor + HTML básico (sem enviar para IA)
    --full          → Monitor + IA + HTML completo (requer API key)

PRIVACIDADE:
    --no-ai:        Nenhum dado sai da máquina. Seguro para ambientes sensíveis.
    --local-html:   HTML gerado localmente, sem APIs externas.
    --full:         Dados enviados para Google Gemini (com sanitização configurável).

VARIÁVEIS DE AMBIENTE:
    SECURITY_MONITOR_OUTPUT    Diretório para relatórios JSON
    SECURITY_REPORTER_OUTPUT   Diretório para relatórios HTML
    GEMINI_API_KEY            Chave API do Google Gemini (necessário apenas para --full)

DEPENDÊNCIAS:
EOF

    if [ "$PSUTIL_AVAILABLE" = true ]; then
        echo "    psutil         ✅ Instalado - OBRIGATÓRIO (todos os modos)"
    else
        echo "    psutil         ❌ NÃO INSTALADO - OBRIGATÓRIO (todos os modos)"
    fi
    
    if [ "$GEMINI_AVAILABLE" = true ]; then
        echo "    google-genai   ✅ Instalado - Opcional (apenas --full)"
    else
        echo "    google-genai   ❌ Não instalado - Opcional (apenas --full)"
    fi
    
    echo ""
}

run_monitor_only() {
    echo "🔍 Executando auditoria de segurança (modo local - sem IA)..."
    echo ""
    
    # Verificar se psutil está disponível
    if [ "$PSUTIL_AVAILABLE" = false ]; then
        echo "======================================================================="
        echo "❌ ERRO: Monitor requer o módulo psutil"
        echo "======================================================================="
        echo ""
        echo "O módulo 'psutil' é OBRIGATÓRIO para coletar métricas do sistema."
        echo ""
        echo "❌ Módulo 'psutil' não encontrado"
        echo ""
        echo "Soluções:"
        echo "  1. Ative a venv:"
        echo "     source venv/bin/activate"
        echo ""
        echo "  2. Ou instale o módulo:"
        echo "     pip install psutil"
        echo ""
        echo "  3. Ou instale todas as dependências:"
        echo "     pip install -r requirements.txt"
        echo ""
        echo "======================================================================="
        exit 1
    fi
    
    if [[ ! -x "$MONITOR" ]]; then
        chmod +x "$MONITOR"
    fi
    
    "$MONITOR"
    
    echo ""
    echo "✅ Auditoria concluída!"
    echo "📄 Relatório JSON gerado (sem análise de IA)"
    echo "💡 Para análise com IA, execute: $0 --full"
}

run_full_audit() {
    local sanitize_level="${1:-moderate}"
    local no_browser="$2"
    
    echo "🔍 Executando auditoria de segurança completa (com IA)..."
    echo ""
    
    # Verificar se psutil está disponível
    if [ "$PSUTIL_AVAILABLE" = false ]; then
        echo "======================================================================="
        echo "❌ ERRO: Monitor requer o módulo psutil"
        echo "======================================================================="
        echo ""
        echo "O módulo 'psutil' é OBRIGATÓRIO para coletar métricas do sistema."
        echo ""
        echo "Ative venv ou instale o módulo:"
        echo "  source venv/bin/activate"
        echo ""
        echo "Instale com:"
        echo "  pip install psutil"
        echo "  ou"
        echo "  pip install -r requirements.txt"
        echo ""
        echo "======================================================================="
        exit 1
    fi
    
    # Verificar se google-genai está disponível
    if [ "$GEMINI_AVAILABLE" = false ]; then
        echo "======================================================================="
        echo "❌ ERRO: Modo --full requer o módulo google-genai"
        echo "======================================================================="
        echo ""
        echo "O modo com IA não está disponível no momento."
        echo ""
        echo "❌ Módulo 'google-genai' não encontrado"
        echo ""
        echo "Possíveis causas:"
        echo "  • A venv não está ativada"
        echo "  • O módulo não foi instalado"
        echo ""
        echo "Soluções:"
        echo "  1. Ative a venv:"
        echo "     source venv/bin/activate"
        echo ""
        echo "  2. Ou instale o módulo:"
        echo "     pip install google-genai"
        echo ""
        echo "  3. Ou use modos sem IA:"
        echo "     $0 --local-html    # HTML básico local"
        echo "     $0 --no-ai         # Apenas JSON"
        echo ""
        echo "======================================================================="
        
        read -p "⏎ Pressione ENTER para ver o help..." 
        echo ""
        show_usage
        exit 1
    fi
    
    # Verificar se GEMINI_API_KEY está configurada
    if [[ -z "$GEMINI_API_KEY" ]]; then
        echo "❌ ERRO: Variável GEMINI_API_KEY não encontrada!"
        echo ""
        echo "Configure sua chave da API Gemini:"
        echo "  export GEMINI_API_KEY='sua_chave_aqui'"
        echo ""
        echo "Obtenha uma chave em: https://aistudio.google.com/app/apikey"
        echo ""
        echo "💡 Ou use: $0 --local-html (HTML sem IA)"
        exit 1
    fi
    
    # Tornar scripts executáveis se necessário
    if [[ ! -x "$MONITOR" ]]; then
        chmod +x "$MONITOR"
    fi
    if [[ ! -x "$REPORTER" ]]; then
        chmod +x "$REPORTER"
    fi
    
    # 1. Executar monitor
    echo "📊 Passo 1/2: Coletando dados de segurança..."
    "$MONITOR"
    
    if [[ $? -ne 0 ]]; then
        echo "❌ Erro ao executar monitor. Abortando."
        exit 1
    fi
    
    echo ""
    echo "📊 Passo 2/2: Gerando análise com IA..."
    echo ""
    
    # 2. Executar reporter (com confirmação interativa)
    local reporter_args="--mode=full --sanitize=$sanitize_level"
    if [[ "$no_browser" == "true" ]]; then
        reporter_args="$reporter_args --no-browser"
    fi
    
    "$REPORTER" $reporter_args
    
    if [[ $? -eq 0 ]]; then
        echo ""
        echo "✅ Auditoria completa concluída!"
    else
        echo ""
        echo "⚠️  Reporter foi cancelado ou falhou."
        echo "💡 JSON local ainda foi gerado com sucesso"
    fi
}

run_local_html() {
    local sanitize_level="${1:-none}"
    local no_browser="$2"
    
    echo "🔍 Executando auditoria de segurança (modo HTML local - sem IA)..."
    echo ""
    
    # Verificar se psutil está disponível
    if [ "$PSUTIL_AVAILABLE" = false ]; then
        echo "======================================================================="
        echo "❌ ERRO: Monitor requer o módulo psutil"
        echo "======================================================================="
        echo ""
        echo "O módulo 'psutil' é OBRIGATÓRIO para coletar métricas do sistema."
        echo ""
        echo "Ative venv ou instale o módulo:"
        echo "  source venv/bin/activate"
        echo ""
        echo "Instale com:"
        echo "  pip install psutil"
        echo "  ou"
        echo "  pip install -r requirements.txt"
        echo ""
        echo "======================================================================="
        exit 1
    fi
    
    # Tornar scripts executáveis se necessário
    if [[ ! -x "$MONITOR" ]]; then
        chmod +x "$MONITOR"
    fi
    if [[ ! -x "$REPORTER" ]]; then
        chmod +x "$REPORTER"
    fi
    
    # 1. Executar monitor
    echo "📊 Passo 1/2: Coletando dados de segurança..."
    "$MONITOR"
    
    if [[ $? -ne 0 ]]; then
        echo "❌ Erro ao executar monitor. Abortando."
        exit 1
    fi
    
    echo ""
    echo "📊 Passo 2/2: Gerando HTML básico (sem IA)..."
    echo ""
    
    # 2. Executar reporter em modo básico
    local reporter_args="--mode=basic --sanitize=$sanitize_level"
    if [[ "$no_browser" == "true" ]]; then
        reporter_args="$reporter_args --no-browser"
    fi
    
    "$REPORTER" $reporter_args
    
    if [[ $? -eq 0 ]]; then
        echo ""
        echo "✅ Relatório HTML local gerado com sucesso!"
    else
        echo ""
        echo "⚠️  Erro ao gerar HTML."
    fi
}

# Parse argumentos
MODE=""
SANITIZE_LEVEL=""
NO_BROWSER="false"

# Processar argumentos
while [[ $# -gt 0 ]]; do
    case "$1" in
        --full|--with-ai)
            MODE="full"
            shift
            ;;
        --no-ai|--local-only)
            MODE="no-ai"
            shift
            ;;
        --local-html)
            MODE="local-html"
            shift
            ;;
        --sanitize=*)
            SANITIZE_LEVEL="${1#*=}"
            shift
            ;;
        --no-browser)
            NO_BROWSER="true"
            shift
            ;;
        -h|--help|help)
            show_usage
            exit 0
            ;;
        *)
            echo "❌ Erro: Opção inválida: $1"
            echo ""
            show_usage
            exit 1
            ;;
    esac
done

# Verificar se modo foi especificado
if [[ -z "$MODE" ]]; then
    echo "❌ Erro: Nenhuma opção especificada"
    echo ""
    show_usage
    exit 1
fi

# Validar nível de sanitização se especificado
if [[ -n "$SANITIZE_LEVEL" ]]; then
    case "$SANITIZE_LEVEL" in
        none|light|moderate|strict)
            # Válido
            ;;
        *)
            echo "❌ Erro: Nível de sanitização inválido: $SANITIZE_LEVEL"
            echo "Valores válidos: none, light, moderate, strict"
            exit 1
            ;;
    esac
fi

# Executar modo selecionado
case "$MODE" in
    full)
        # Padrão para modo full: moderate
        SANITIZE_LEVEL="${SANITIZE_LEVEL:-moderate}"
        run_full_audit "$SANITIZE_LEVEL" "$NO_BROWSER"
        ;;
    local-html)
        # Padrão para local-html: none (dados locais completos)
        SANITIZE_LEVEL="${SANITIZE_LEVEL:-none}"
        run_local_html "$SANITIZE_LEVEL" "$NO_BROWSER"
        ;;
    no-ai)
        run_monitor_only
        ;;
esac

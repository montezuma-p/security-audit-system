# 🏗️ Arquitetura do Sistema

<div align="center">

**Documentação técnica da arquitetura do Security Audit System**

*Priorizando compreensão através de texto e diagramas visuais*

</div>

---

## 📋 índice

- [Visão Geral](#-visão-geral)
- [Arquitetura de Alto Nível](#-arquitetura-de-alto-nível)
- [Componentes Principais](#-componentes-principais)
- [Fluxo de Dados](#-fluxo-de-dados)
- [Estrutura de Módulos](#-estrutura-de-módulos)
- [Decisões de Design](#-decisões-de-design)
- [Padrões Arquiteturais](#-padrões-arquiteturais)
- [Extensibilidade](#-extensibilidade)

---

## 🎯 visão geral

O **Security Audit System** é uma ferramenta modular de auditoria de segurança composta por três camadas principais que trabalham em conjunto para coletar, processar e apresentar informações de segurança de forma inteligente e humanizada.

### Filosofia de Design

A arquitetura foi projetada seguindo três princípios fundamentais:

1. **Modularidade**: Cada componente tem uma responsabilidade clara e bem definida
2. **Privacidade**: Dados sensíveis podem ser sanitizados antes de processamento externo
3. **Flexibilidade**: Sistema funciona em múltiplos modos (com ou sem IA, local ou completo)

---

## 🏛️ arquitetura de alto nível

```
┌─────────────────────────────────────────────────────────────────┐
│                      SECURITY AUDIT SYSTEM                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────┐     ┌──────────────────┐     ┌───────────────┐
│                 │     │                  │     │               │
│   ORCHESTRATOR  │────▶│   DATA LAYER     │────▶│  PRESENTATION │
│   (Wrapper)     │     │   (Processing)   │     │    (Output)   │
│                 │     │                  │     │               │
└─────────────────┘     └──────────────────┘     └───────────────┘
        │                       │                        │
        │                       │                        │
        ▼                       ▼                        ▼
        
security_audit.sh       monitor/             reporter/
- Validações           - Coleta              - Análise
- Orquestração         - Métricas            - Geração HTML
- Confirmações         - Alertas             - Sanitização


┌────────────────────────────────────────────────────────────────┐
│                       CAMADA DE SISTEMA                        │
│  Linux | journalctl | firewalld | SELinux | systemd | psutil  │
└────────────────────────────────────────────────────────────────┘
```

### Fluxo de Execução

```
Usuário executa
     │
     ▼
security_audit.sh (Orchestrator)
     │
     ├─── Modo: --no-ai
     │    └──▶ monitor ──▶ JSON local ──▶ FIM
     │
     ├─── Modo: --local-html
     │    └──▶ monitor ──▶ JSON ──▶ reporter (sem IA) ──▶ HTML ──▶ FIM
     │
     └─── Modo: --full
          └──▶ monitor ──▶ JSON ──▶ reporter (com IA) ──▶ HTML ──▶ FIM
                                          │
                                          ▼
                                   Google Gemini API
```

---

## 🔧 componentes principais

### 1. Orchestrator (security_audit.sh)

**Responsabilidade**: Coordenar a execução e validar pré-requisitos

**Funções Principais**:

```
┌─────────────────────────────────────┐
│    security_audit.sh (Bash)         │
├─────────────────────────────────────┤
│ • Validar dependências (psutil)     │
│ • Detectar disponibilidade Gemini   │
│ • Parsear argumentos CLI            │
│ • Exibir avisos de privacidade      │
│ • Orquestrar monitor → reporter     │
│ • Calcular exit codes apropriados   │
└─────────────────────────────────────┘
```

**Decisões Tomadas**:
- Verifica se `psutil` está disponível (obrigatório)
- Verifica se `google-genai` está disponível (opcional)
- Mostra ajuda contextual baseado em módulos disponíveis
- Garante que usuário confirme envio de dados para IA (a menos que `--skip-confirm`)

### 2. Monitor (Data Collection Layer)

**Responsabilidade**: Coletar métricas brutas do sistema

```
┌──────────────────────────────────────────────────────────────┐
│              monitor/security_monitor.py (Core)               │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │   ports    │  │    auth    │  │  firewall  │            │
│  │            │  │            │  │            │            │
│  │ • Listening│  │ • Failed   │  │ • firewalld│            │
│  │ • Estab.   │  │ • Success  │  │ • SELinux  │            │
│  │ • Suspeitos│  │ • Sudo     │  │ • Zones    │            │
│  └────────────┘  └────────────┘  └────────────┘            │
│                                                               │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │vulnerabili │  │  network   │  │permissions │            │
│  │   ties     │  │            │  │            │            │
│  │ • CVEs     │  │ • Interfaces│ │ • SUID     │            │
│  │ • Updates  │  │ • Gateway  │  │ • SGID     │            │
│  │ • Kernel   │  │ • DNS      │  │ • Writable │            │
│  └────────────┘  └────────────┘  └────────────┘            │
│                                                               │
│  ┌────────────────────────────────────┐                      │
│  │         alerts.py (Engine)         │                      │
│  │ Gera alertas baseado em métricas   │                      │
│  └────────────────────────────────────┘                      │
│                                                               │
│                         OUTPUT                                │
│              JSON com métricas + alertas                      │
└──────────────────────────────────────────────────────────────┘
```

**Características**:
- **Independente**: Não depende de IA ou internet
- **Configurável**: `config.json` controla quais checks executar
- **Resiliente**: Falhas em um módulo não afetam outros
- **Performático**: Coleta paralela poderia ser implementada futuramente

**Output Structure**:

```
security_YYYYMMDD_HHMMSS.json
├── timestamp
├── hostname
├── metrics
│   ├── ports
│   ├── authentication
│   ├── firewall
│   ├── vulnerabilities
│   ├── network
│   └── permissions
├── alerts [...]
├── security_score
│   ├── score (0-100)
│   ├── grade (A-F)
│   ├── deductions [...]
│   └── bonus [...]
└── summary
    ├── total_alerts
    ├── critical_alerts
    ├── warning_alerts
    └── security_status
```

### 3. Reporter (Analysis & Presentation Layer)

**Responsabilidade**: Transformar dados brutos em insights humanizados

**🆕 ATUALIZAÇÃO (Nov 2025)**: A arquitetura do Reporter foi completamente refatorada para ser modular e unificada.

```
┌──────────────────────────────────────────────────────────────┐
│           reporter/security_reporter.py (Core)                │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  STAGE 1: Sanitização (Opcional)                             │
│  ┌────────────────────────────────────┐                      │
│  │   sanitizer.py (DataSanitizer)     │                      │
│  │                                     │                      │
│  │  ┌──────────┐  ┌──────────┐       │                      │
│  │  │Anonimizar│  │Anonimizar│       │                      │
│  │  │   IPs    │  │Usernames │       │                      │
│  │  └──────────┘  └──────────┘       │                      │
│  │                                     │                      │
│  │  Níveis: none | light | moderate | strict                │
│  └────────────────────────────────────┘                      │
│                     │                                         │
│                     ▼                                         │
│  STAGE 2: Análise (Modo Full com IA)                         │
│  ┌────────────────────────────────────┐                      │
│  │   Google Gemini 2.0 Flash Client   │                      │
│  │                                     │                      │
│  │  Envia: JSON sanitizado + prompt   │                      │
│  │  Recebe: JSON estruturado com:     │                      │
│  │    • resumo_executivo              │                      │
│  │    • metricas_cards                │                      │
│  │    • alertas_criticos              │                      │
│  │    • vetores_ataque                │                      │
│  │    • recomendacoes_hardening       │                      │
│  │    • compliance_checklist          │                      │
│  │    • proximos_passos               │                      │
│  │    • etc.                           │                      │
│  │                                     │                      │
│  │  🔄 FALLBACK: Se API falhar →      │                      │
│  │     Gera relatório local           │                      │
│  │     automaticamente                │                      │
│  │                                     │                      │
│  │  🛠️ RECUPERAÇÃO: JSON truncado →   │                      │
│  │     tentar_recuperar_json()        │                      │
│  │     (fecha chaves, arrays, etc)    │                      │
│  └────────────────────────────────────┘                      │
│                     │                                         │
│          OU (Modo --local-html)                              │
│                     │                                         │
│                     ▼                                         │
│  STAGE 2B: Analyzers Locais (sem IA)                         │
│  ┌────────────────────────────────────┐                      │
│  │         analyzers/                 │                      │
│  │                                     │                      │
│  │  • base_analyzer (Abstract)        │                      │
│  │  • score_analyzer                  │                      │
│  │  • ports_analyzer                  │                      │
│  │  • auth_analyzer                   │                      │
│  │  • firewall_analyzer               │                      │
│  │  • network_analyzer                │                      │
│  │  • permissions_analyzer            │                      │
│  │  • vulnerabilities_analyzer        │                      │
│  │                                     │                      │
│  │  Cada um analisa sua área          │                      │
│  │  e retorna insights estruturados   │                      │
│  │  (mais básicos que a IA)           │                      │
│  └────────────────────────────────────┘                      │
│                     │                                         │
│                     ▼                                         │
│  STAGE 3: Geração HTML (Arquitetura Modular 🆕)              │
│  ┌────────────────────────────────────┐                      │
│  │  html_generator.py (Orquestrador)  │                      │
│  │  ┌──────────────────────────┐     │                      │
│  │  │ generate_html(data,       │     │                      │
│  │  │   ai_analysis=None)       │     │                      │
│  │  │                           │     │                      │
│  │  │ Se ai_analysis:           │     │                      │
│  │  │   → convert_ai_to_insights│     │                      │
│  │  │ Senão:                    │     │                      │
│  │  │   → run_analyzers()       │     │                      │
│  │  └──────────────────────────┘     │                      │
│  │            │                        │                      │
│  │            ▼                        │                      │
│  │  ┌──────────────────────────┐     │                      │
│  │  │   html_builder/ package   │     │                      │
│  │  │                           │     │                      │
│  │  │  📁 formatters.py         │     │                      │
│  │  │    • format_markdown      │     │                      │
│  │  │    • load_asset (CSS/JS)  │     │                      │
│  │  │                           │     │                      │
│  │  │  📁 header.py             │     │                      │
│  │  │    • generate_header()    │     │                      │
│  │  │      (modo IA ou local)   │     │                      │
│  │  │                           │     │                      │
│  │  │  📁 sections.py           │     │                      │
│  │  │    • generate_score       │     │                      │
│  │  │    • generate_analysis    │     │                      │
│  │  │    • generate_disclaimer  │     │                      │
│  │  │      (condicional)        │     │                      │
│  │  │                           │     │                      │
│  │  │  📁 ai_sections.py        │     │                      │
│  │  │    • accordion (recs) 🎪  │     │                      │
│  │  │    • cards (compliance) 📊│     │                      │
│  │  │    • timeline (steps) ⏳  │     │                      │
│  │  │    • attack_vectors 🎯    │     │                      │
│  │  │                           │     │                      │
│  │  │  📁 footer.py             │     │                      │
│  │  │    • generate_footer()    │     │                      │
│  │  │    • generate_json_modal()│     │                      │
│  │  └──────────────────────────┘     │                      │
│  │                                     │                      │
│  │  Resultado: HTML completo          │                      │
│  │  • Inline CSS e JS                 │                      │
│  │  • Standalone (sem deps)           │                      │
│  │  • Responsivo                      │                      │
│  └────────────────────────────────────┘                      │
│                                                               │
│                    OUTPUT                                     │
│   security_report_{ai|local}_TIMESTAMP.html                  │
└──────────────────────────────────────────────────────────────┘
```

---

## 🔄 fluxo de dados

### Fluxo Completo (Modo --full)

```
┌──────────┐
│  Início  │
└────┬─────┘
     │
     ▼
┌─────────────────────────────────────┐
│ security_audit.sh                   │
│ • Parse args (--full, --sanitize)   │
│ • Valida Gemini disponível          │
│ • Exibe aviso de privacidade        │
│ • Pede confirmação usuário          │
└────┬────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────┐
│ monitor/security_monitor.py         │
│                                     │
│ Para cada módulo habilitado:        │
│ ┌─────────────────────────────┐   │
│ │ ports.collect_ports_metrics()│   │
│ └─────────────────────────────┘   │
│ ┌─────────────────────────────┐   │
│ │ auth.collect_auth_metrics() │   │
│ └─────────────────────────────┘   │
│ ... (outros módulos)                │
│                                     │
│ alerts.generate_alerts(metrics)     │
│ calculate_security_score()          │
└────┬────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────┐
│ Salva JSON                          │
│ ~/.bin/.../security_TIMESTAMP.json  │
└────┬────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────┐
│ reporter/security_reporter.py       │
│                                     │
│ STAGE 1: Sanitização                │
│ ┌─────────────────────────────┐   │
│ │ sanitizer.sanitize(data)     │   │
│ │ • Anonimiza IPs               │   │
│ │ • Anonimiza usernames         │   │
│ │ • Remove hostname real        │   │
│ └─────────────────────────────┘   │
└────┬────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────┐
│ STAGE 2: Análise IA                 │
│ ┌─────────────────────────────┐   │
│ │ Envia JSON sanitizado para   │   │
│ │ Google Gemini API            │   │
│ │                               │   │
│ │ Prompt:                       │   │
│ │ "Analise este relatório e    │   │
│ │  retorne JSON estruturado"   │   │
│ │                               │   │
│ │ Recebe: JSON com análises    │   │
│ │ {                             │   │
│ │   resumo_executivo: "...",   │   │
│ │   metricas_cards: [...],     │   │
│ │   alertas_criticos: [...],   │   │
│ │   analise_portas: "...",     │   │
│ │   recomendacoes: [...]       │   │
│ │ }                             │   │
│ └─────────────────────────────┘   │
└────┬────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────┐
│ STAGE 3: Geração HTML               │
│ ┌─────────────────────────────┐   │
│ │ gerar_html()                 │   │
│ │                               │   │
│ │ 1. Carrega template.html     │   │
│ │ 2. Substitui placeholders:   │   │
│ │    {{HOSTNAME}}              │   │
│ │    {{TIMESTAMP}}             │   │
│ │    {{SCORE}}                 │   │
│ │    {{RESUMO_EXECUTIVO}}      │   │
│ │    {{ANALISE_PORTAS}}        │   │
│ │    {{ALERTAS_CRITICOS}}      │   │
│ │    etc.                       │   │
│ │                               │   │
│ │ 3. Gera HTML dinâmico        │   │
│ │    (cards, alertas, listas)  │   │
│ │ 4. Salva HTML final          │   │
│ └─────────────────────────────┘   │
└────┬────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────┐
│ Output HTML                         │
│ ~/.bin/.../security_report_TIME.html│
└────┬────────────────────────────────┘
     │
     ▼
┌──────────┐
│   FIM    │
│ (Abre no │
│ browser) │
└──────────┘
```

### Fluxo Simplificado (Modo --no-ai)

```
Início → security_audit.sh → monitor → JSON → FIM
```

### Fluxo Intermediário (Modo --local-html)

```
Início → security_audit.sh → monitor → JSON 
                                        ↓
                                   reporter (sem Gemini)
                                        ↓
                                   analyzers locais
                                   (score, ports, auth, etc)
                                        ↓
                                   gera insights estruturados
                                        ↓
                                    HTML básico
                                        ↓
                                      FIM
```

**Nota**: No modo `--local-html`, os **analyzers locais** (classes Python) fazem a análise ao invés do Gemini. São análises mais básicas, mas totalmente offline.

---

## 📦 estrutura de módulos

### Monitor Modules (monitor/modules/)

Cada módulo segue o mesmo padrão de design:

```
Módulo: ports.py

┌────────────────────────────────────┐
│  FUNÇÕES INTERNAS                  │
├────────────────────────────────────┤
│  • get_listening_ports()           │
│    └─▶ Usa psutil para listar      │
│                                     │
│  • get_established_connections()   │
│    └─▶ Analisa conexões ativas     │
│                                     │
│  • check_suspicious_ports()        │
│    └─▶ Detecta portas incomuns     │
│                                     │
│  • get_network_services()          │
│    └─▶ Lista serviços systemd      │
└────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────┐
│  FUNÇÃO PÚBLICA (Entry Point)      │
├────────────────────────────────────┤
│  collect_ports_metrics(config)     │
│                                     │
│  1. Lê config (checks habilitados) │
│  2. Executa funções internas        │
│  3. Monta estrutura de retorno:    │
│     {                               │
│       "listening_ports": [...],    │
│       "connections": {...},        │
│       "suspicious": [...],         │
│       "services": [...],           │
│       "summary": {                 │
│         "total_ports": N,          │
│         "suspicious_found": M      │
│       }                             │
│     }                               │
│  4. Retorna dict                    │
└────────────────────────────────────┘
```

**Todos os módulos seguem este contrato**:
- Input: `config: Dict[str, Any]`
- Output: `Dict[str, Any]` com métricas + summary
- Isolamento: Não dependem uns dos outros
- Robustez: Try/except para não quebrar todo o sistema

### Reporter Analyzers (reporter/modules/analyzers/)

Padrão de herança e polimorfismo:

```
┌────────────────────────────────────┐
│     BaseAnalyzer (Abstract)        │
├────────────────────────────────────┤
│  + __init__(data)                  │
│  + analyze() → Dict  [ABSTRACT]    │
│  # _get_status_from_severity()     │
│  # _count_alerts_by_priority()     │
│  # _has_metric()                   │
│  # _get_metric()                   │
└────────────────────────────────────┘
         △
         │ (herda)
         │
    ┌────┴─────┬───────┬────────┬─────────┐
    │          │       │        │         │
    ▼          ▼       ▼        ▼         ▼
┌────────┐ ┌─────┐ ┌─────┐ ┌────────┐ ┌─────┐
│Score   │ │Ports│ │Auth │ │Firewall│ │...  │
│Analyzer│ │Analyz│ │Analyz│ │Analyzer│ │     │
└────────┘ └─────┘ └─────┘ └────────┘ └─────┘

Cada analyzer concreto:
• Implementa analyze()
• Retorna estrutura padronizada:
  {
    "status": "good|warning|critical",
    "message": "Texto didático",
    "details": ["item1", "item2"],
    "recommendations": ["rec1", "rec2"],
    "severity": "low|medium|high|critical",
    "metrics": {...}
  }
```

**Vantagens desta arquitetura**:
- ✅ Fácil adicionar novos analyzers (extends BaseAnalyzer)
- ✅ Código reutilizável (métodos helper na base)
- ✅ Interface consistente (todos retornam mesma estrutura)
- ✅ Testável (mock data no `__init__`)

---

## 🎨 decisões de design

### 1. Por que Bash + Python?

**Decisão**: Orchestrator em Bash, lógica em Python

**Razões**:
- 🐚 **Bash**: Ideal para orquestração, validação de ambiente, chamadas de sistema
- 🐍 **Python**: Melhor para lógica complexa, estruturas de dados, APIs
- 🔀 **Separação**: Cada linguagem no que faz melhor

**Alternativa considerada**: Tudo em Python
- ❌ Menos natural para scripts de sistema Linux
- ❌ Perderia a simplicidade do shell scripting

### 2. JSON como formato intermediário

**Decisão**: Monitor salva JSON, Reporter lê JSON

**Razões**:
- 📁 **Persistência**: Dados podem ser re-analisados sem re-coletar
- 🔄 **Desacoplamento**: Monitor e Reporter independentes
- 🐛 **Debug**: Fácil inspecionar dados intermediários
- 📊 **Histórico**: JSONs antigos = histórico de auditorias

**Alternativa considerada**: Pipe direto (monitor | reporter)
- ❌ Perde histórico
- ❌ Impossível re-analisar sem re-coletar

### 3. Múltiplos modos de operação

**Decisão**: `--no-ai`, `--local-html`, `--full`

**Razões**:
- 🔐 **Privacidade**: Nem todos querem enviar dados para nuvem
- 🌐 **Offline**: Funciona sem internet
- 💰 **Gratuito**: `--no-ai` não precisa de API key
- 🎯 **Flexibilidade**: Usuário escolhe trade-off privacidade vs insights

### 4. Sanitização multi-nível

**Decisão**: 4 níveis (none, light, moderate, strict)

**Razões**:
- ⚖️ **Balance**: Trade-off entre utilidade e privacidade
- 🎯 **Escolha**: Usuário decide o nível apropriado
- 🏢 **Compliance**: Corporações podem exigir strict
- 🏠 **Home users**: Podem usar moderate ou light

### 5. Analyzers como classes separadas

**Decisão**: Um analyzer por área (ports, auth, etc.)

**Razões**:
- 🧩 **Modularidade**: Cada analyzer foca em uma área
- 🧪 **Testabilidade**: Fácil testar isoladamente
- 📈 **Escalabilidade**: Fácil adicionar novos analyzers
- 👥 **Manutenção**: Diferentes pessoas podem trabalhar em diferentes analyzers

**Alternativa considerada**: Uma função gigante
- ❌ Difícil manter
- ❌ Difícil testar
- ❌ Difícil escalar

### 6. Config via JSON + ENV vars

**Decisão**: `config.json` para defaults, ENV vars para override

**Razões**:
- 📝 **Documentação**: JSON é auto-documentado
- 🐳 **Containers**: ENV vars ideais para Docker
- 🔧 **CI/CD**: Fácil customizar via ENV em pipelines
- 💾 **Persistência**: JSON persiste entre execuções

### 7. 🆕 Arquitetura Modular do HTML Generator (Nov 2025)

**Decisão**: Refatorar de template.html para geração programática modular

**Razões**:
- 📦 **Modularidade**: 751 linhas → 285 linhas (62% redução) + 6 módulos especializados
- 🔄 **Unificação**: Um único gerador para IA e local (antes eram separados)
- 🧪 **Testabilidade**: Cada módulo pode ser testado isoladamente
- 🎨 **Flexibilidade**: Fácil adicionar novos componentes (accordion, cards, timeline)
- 🔧 **Manutenção**: Mudanças em seções específicas não afetam outras
- 📊 **Reusabilidade**: Componentes podem ser reutilizados (e.g., formatters)

**Estrutura**:
```
html_builder/
├── __init__.py          # Exports centralizados
├── formatters.py        # Markdown, asset loading
├── header.py            # Cabeçalhos (detecta modo)
├── footer.py            # Rodapé e modais
├── sections.py          # Seções técnicas (score, analysis)
└── ai_sections.py       # Seções específicas IA (accordion, cards, timeline)
```

**Alternativa anterior**: template.html com placeholders
- ❌ Difícil manter HTML grande
- ❌ Lógica condicional complexa no template
- ❌ Duplicação entre modo IA e local

### 8. 🆕 Fallback Automático (Nov 2025)

**Decisão**: Se API Gemini falhar, gerar automaticamente relatório local

**Razões**:
- 🛡️ **Confiabilidade**: Usuário SEMPRE recebe relatório
- 📡 **Resiliência**: Funciona mesmo com problemas de rede
- 🔧 **UX**: Não perde dados coletados por falha da IA
- 💾 **Debug**: Salva respostas problemáticas para análise

**Implementação**:
```python
analise = chamar_ia_gemini(prompt)
if not analise:
    # FALLBACK: gerar HTML local automaticamente
    filepath = save_html(data, output_dir, ai_analysis=None)
    # Usuário ainda tem relatório completo
```

**Alternativa anterior**: Falha completa se IA não responder
- ❌ Usuário perde tudo
- ❌ Precisa re-executar monitor
- ❌ Frustrante em ambientes com internet instável

### 9. 🆕 Recuperação Inteligente de JSON (Nov 2025)

**Decisão**: Tentar recuperar JSONs truncados/malformados da IA

**Razões**:
- 🤖 **IA não é perfeita**: Gemini pode truncar respostas (token limit)
- 🔧 **Recuperação**: Melhor tentar recuperar que falhar imediatamente
- 📊 **Dados parciais**: Mesmo JSON incompleto pode ter dados úteis
- 🐛 **Debug**: Salva resposta original para análise

**Estratégias de recuperação**:
1. Remover marcadores de código (```json, ```)
2. Buscar JSON no meio do texto com regex
3. Completar chaves/arrays não fechados (`}`, `]`)
4. Remover `...` de truncamento
5. Fechar strings não finalizadas

**Alternativa anterior**: json.loads() direto
- ❌ Falha em qualquer erro
- ❌ Perde dados mesmo que 90% do JSON esteja OK

---

## 🎯 padrões arquiteturais

### 1. Plugin Architecture (Modules)

Cada módulo de monitoramento é um plugin:

```
Interface comum: collect_<area>_metrics(config) → Dict

Permite:
• Adicionar novos módulos sem modificar core
• Desabilitar módulos via config
• Módulos independentes (falha em um não afeta outros)
```

### 2. Strategy Pattern (Sanitization)

Diferentes estratégias de sanitização:

```
DataSanitizer(level="moderate")
  ├─ none: Nenhuma sanitização
  ├─ light: Sanitização leve
  ├─ moderate: Sanitização balanceada
  └─ strict: Máxima sanitização

Permite trocar estratégia em runtime
```

### 3. Template Method (Analyzers)

BaseAnalyzer define esqueleto, subclasses implementam detalhes:

```
BaseAnalyzer (Abstract)
  │
  └─ analyze() [implementado pela subclasse]
  │
  └─ Métodos helper [herdados]
     • _get_status_from_severity()
     • _count_alerts_by_priority()
     • etc.
```

### 4. Factory Pattern (Alert Generation)

```
alerts.generate_alerts(metrics) cria alertas baseado em métricas

Para cada condição:
  • Porta suspeita → Cria alert de porta
  • Login falho → Cria alert de autenticação
  • Etc.

Centraliza lógica de criação de alertas
```

---

## 🚀 extensibilidade

### Como adicionar um novo módulo de monitoramento

1. **Criar arquivo** `monitor/modules/novo_modulo.py`

2. **Implementar função**:
```python
def collect_novo_metrics(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Coleta métricas da nova área
    
    Returns:
        {
            "dados": [...],
            "summary": {
                "total": N,
                "issues": M
            }
        }
    """
    # Implementação...
    return metrics
```

3. **Importar** em `monitor/security_monitor.py`:
```python
from modules import novo_modulo

# Em collect_all_metrics():
metrics["novo"] = novo_modulo.collect_novo_metrics(config)
```

4. **Adicionar configs** em `config.json.example`:
```json
{
  "monitoring": {
    "check_novo_feature": true
  }
}
```

5. **Criar analyzer** (opcional) `reporter/modules/analyzers/novo_analyzer.py`

### Como adicionar novo analyzer

1. **Criar classe** herdando de `BaseAnalyzer`
2. **Implementar** `analyze()` retornando estrutura padronizada
3. **Importar** em `security_reporter.py`
4. **Usar** no fluxo de geração de relatório

### Como customizar HTML template

1. **Editar** `reporter/templates/template.html`
2. **Adicionar placeholders** `{{NOVO_DADO}}`
3. **Modificar** `html_generator.py` para substituir placeholder
4. **CSS** em `reporter/templates/assets/styles.css`
5. **JS** em `reporter/templates/assets/report.js`

---

## 🔍 considerações de performance

### Otimizações Implementadas

1. **Lazy loading**: Só importa Gemini se modo `--full`
2. **Conditional execution**: Checks desabilitados via config não executam
3. **Error isolation**: Falha em um módulo não paralisa sistema

### Oportunidades Futuras

1. **Paralelização**: Executar módulos de coleta em paralelo
2. **Caching**: Cache de resultados lentos (ex: find SUID)
3. **Incremental**: Só coletar o que mudou desde última execução
4. **Profiling**: Identificar gargalos e otimizar

---

## 🔐 considerações de segurança

### Dados Sensíveis

O sistema coleta dados sensíveis que exigem cuidado:

- **IPs**: Locais e remotos (atacantes)
- **Usernames**: Do sistema operacional
- **Paths**: Podem conter usernames
- **Logs**: Podem conter informações privadas

### Mitigações

1. **Sanitização**: Sistema de sanitização multi-nível
2. **Confirmação**: Pede confirmação antes de enviar para IA
3. **Local-first**: Modos sem IA disponíveis
4. **Transparência**: Documentação clara sobre o que é enviado

---

<div align="center">

## 📚 próximos passos

Entendeu a arquitetura? Veja também:

- 🔐 [SECURITY.md](SECURITY.md) - Detalhes sobre sanitização
- 🤝 [CONTRIBUTING.md](CONTRIBUTING.md) - Como contribuir
- 📋 [TODO.md](TODO.md) - Features planejadas

---

**Dúvidas sobre a arquitetura?**

Abra uma [Discussion](https://github.com/montezuma-p/security-audit-system/discussions)

*Documentação mantida pela comunidade*

</div>

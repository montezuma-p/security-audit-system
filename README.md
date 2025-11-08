# 🔒 Security Audit System

<div align="center">

![Security](https://img.shields.io/badge/Security-Audit-c31432?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Fedora-51A2DA?style=for-the-badge&logo=fedora&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-00FF41?style=for-the-badge)

**Sistema completo de auditoria de segurança para Fedora Workstation**

*Monitora, analisa e gera relatórios detalhados sobre a postura de segurança do seu sistema*

[Features](#-features) • [Instalação](#-instalação) • [Uso](#-uso) • [Documentação](#-documentação) • [Contribuir](#-como-contribuir)


<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExbWthajU2OHZuemYzanNtc2dlY3hqcW1xejg4eDF6N3puNzJiZGx0bCZlcD12MV9naWZzX3NlYXJjaCZjdD1n/077i6AULCXc0FKTj9s/giphy.gif" width="400" alt="security"/>

</div>

---

## 🫥 o que é isso? 🫥

Sistema profissional de auditoria de segurança que monitora 7 áreas críticas do seu sistema Linux, detecta vulnerabilidades, gera alertas inteligentes e produz relatórios HTML bonitos com análise humanizada via Google Gemini AI.

_Porque ficar olhando logs crus é coisa de 2010._

---

## 🔥 features 🔥

### 🔍 **7 Módulos de Monitoramento**

| Módulo | O que faz |
|--------|-----------|
| 🔌 **Portas & Serviços** | Detecta portas abertas, conexões suspeitas, serviços vulneráveis |
| 🔐 **Autenticação** | Analisa logins falhos, sessões ativas, uso de sudo, ataques de força bruta |
| 🛡️ **Firewall & SELinux** | Verifica configuração de firewall, zonas, regras e status do SELinux |
| ⚠️ **Vulnerabilidades** | Detecta CVEs conhecidos, atualizações pendentes, kernel vulnerável |
| 🌐 **Rede** | Testa conectividade, DNS, gateway, largura de banda, interfaces |
| 📁 **Permissões** | Encontra arquivos SUID/SGID, world-writable, permissões incorretas |
| 🚨 **Sistema de Alertas** | Gera alertas inteligentes priorizados por severidade (crítico/aviso/info) |

### 🎨 **3 Modos de Operação**

```bash
# 1️⃣ Coleta Local (sem IA)
./security_audit.sh --no-ai
# Gera JSON local, zero envio de dados

# 2️⃣ Relatório HTML Local (sem IA)  
./security_audit.sh --local-html
# HTML básico sem análise de IA, privacidade total

# 3️⃣ Relatório Completo com IA
./security_audit.sh --full
# Análise humanizada via Gemini, insights profundos
```

### 🔐 **Sanitização Inteligente de Dados**

Antes de enviar dados para a IA, o sistema oferece **4 níveis de sanitização**:

- **none**: Dados originais (use apenas em ambiente de teste)
- **light**: Anonimiza último octeto de IPs privados
- **moderate**: ⭐ Recomendado - Anonimiza IPs, usernames, hostname
- **strict**: Máxima privacidade - Anonimiza tudo possível

```bash
# Escolher nível de sanitização
./security_audit.sh --full --sanitize-level moderate
```

📖 **Leia mais:** [docs/SECURITY.md](docs/SECURITY.md) para detalhes sobre sanitização

### 📊 **Score de Segurança**

Sistema de pontuação 0-100 com:
- ✅ Deduções por vulnerabilidades encontradas
- 🎯 Bônus por boas práticas implementadas
- 📈 Nota final (A-F) baseada no score
- 💡 Recomendações priorizadas

### 🎨 **Relatórios HTML Lindos**

Relatórios visuais responsivos com:
- 🌈 Gradientes modernos
- 📊 Cards organizados por categoria
- 🎯 Score visual destacado
- 💬 Análise humanizada da IA

---

## 🛠️ instalação 🛠️

### Requisitos

- **SO**: Fedora Workstation (ou qualquer Linux com systemd)
- **Python**: 3.8+
- **Permissões**: sudo para algumas verificações

### Setup Rápido

```bash
# 1️⃣ Clone o repositório
git clone https://github.com/montezuma-p/security-audit-system.git
cd security-audit-system

# 2️⃣ Crie virtual environment
python3 -m venv venv
source venv/bin/activate

# 3️⃣ Instale dependências
pip install -r requirements.txt

# 4️⃣ Configure (opcional)
cp config.json.example config.json
# Edite config.json para customizar

# 5️⃣ (Apenas para modo --full) Configure API Key do Gemini
export GEMINI_API_KEY="sua-api-key-aqui"
# Ou adicione ao ~/.bashrc para permanente
```

### Obtendo API Key do Google Gemini

Para usar o modo `--full` com análise de IA:

1. Acesse [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Crie uma API Key gratuita
3. Export como variável de ambiente:

```bash
echo 'export GEMINI_API_KEY="sua-api-key"' >> ~/.bashrc
source ~/.bashrc
```

---

## 🚀 uso 🚀

### Modo Simples (Coleta Local)

```bash
# Ativar venv
source venv/bin/activate

# Executar auditoria
./security_audit.sh --no-ai

# Resultado: JSON salvo em ~/.bin/data/scripts-data/reports/security/raw/
```

### Modo HTML Local (Sem IA)

```bash
./security_audit.sh --local-html

# Resultado: HTML básico em ~/.bin/data/scripts-data/reports/security/html/
```

### Modo Completo (Com IA)

```bash
# Com confirmação de privacidade
./security_audit.sh --full

# Pular confirmação (use com cuidado!)
./security_audit.sh --full --skip-confirm

# Escolher nível de sanitização
./security_audit.sh --full --sanitize-level strict
```

### Executando Componentes Separadamente

```bash
# Apenas coletar dados (sem gerar HTML)
./monitor/security_monitor.py

# Apenas gerar HTML de JSONs existentes
./reporter/security_reporter.py --input ~/.bin/data/scripts-data/reports/security/raw/security_20231108_143000.json
```

### Opções Avançadas

```bash
# Ver todas as opções
./security_audit.sh --help

# Executar apenas monitor específico (edite config.json)
# Defina checks específicos como false para desabilitar

# Customizar diretórios de output via ENV
export SECURITY_MONITOR_OUTPUT="/seu/diretorio/json"
export SECURITY_REPORTER_OUTPUT="/seu/diretorio/html"
./security_audit.sh --full
```

---

## 📂 estrutura do projeto 📂

```
.
├── config.json.example
├── docs
│   ├── ARCHITECTURE.md
│   ├── CONTRIBUTING.md
│   ├── SECURITY.md
│   └── TODO.md
├── LICENSE
├── monitor
│   ├── modules
│   │   ├── alerts.py
│   │   ├── auth.py
│   │   ├── firewall.py
│   │   ├── __init__.py
│   │   ├── network.py
│   │   ├── permissions.py
│   │   ├── ports.py
│   │   └── vulnerabilities.py
│   └── security_monitor.py
├── README.md
├── reporter
│   ├── modules
│   │   ├── analyzers
│   │   │   ├── auth_analyzer.py
│   │   │   ├── base_analyzer.py
│   │   │   ├── firewall_analyzer.py
│   │   │   ├── __init__.py
│   │   │   ├── network_analyzer.py
│   │   │   ├── permissions_analyzer.py
│   │   │   ├── ports_analyzer.py
│   │   │   ├── score_analyzer.py
│   │   │   └── vulnerabilities_analyzer.py
│   │   ├── html_generator.py
│   │   ├── __init__.py
│   │   └── sanitizer.py
│   ├── security_reporter.py
│   └── templates
│       └── assets
│           ├── report.js
│           └── styles.css
├── requirements.txt
└── security_audit.sh

9 directories, 33 files

```

---

## 📊 exemplo de saída 📊

### Terminal Output

```
🔒 Security Monitor - Iniciando auditoria de segurança...

🔒 Coletando métricas de segurança...
  🔌 Portas e serviços...
  🔐 Autenticação...
  🛡️  Firewall e SELinux...
  ⚠️  Vulnerabilidades...
  🌐 Rede e conectividade...
  📁 Permissões de arquivos...
🚨 Gerando alertas de segurança...

💾 Salvando relatório...
✅ Relatório salvo em: ~/.bin/data/scripts-data/reports/security/raw/security_20231108_143522.json

======================================================================
🔒 RESUMO DA AUDITORIA DE SEGURANÇA
======================================================================

✅ Status de Segurança: GOOD
🎯 Score de Segurança: 87/100 - B (Bom)
🕐 Timestamp: 2023-11-08T14:35:22
🖥️  Hostname: workstation-montezuma

🚨 Alertas:
   Total: 3
   ❌ Críticos: 0
   ⚠️  Avisos: 2
   ℹ️  Informativos: 1

📊 Estatísticas:
   🔌 Portas abertas: 12
   ⚠️  Portas suspeitas: 0
   🔐 Logins falhos (24h): 0
   ✅ Internet: OK
   ✅ Firewall: Ativo
   ✅ SELinux: enforcing
======================================================================
```

### Relatório HTML

O relatório HTML gerado inclui:
- 🎨 Header visual com gradiente
- 📊 Score de segurança destacado
- 💬 Análise humanizada da IA
- 📋 Seções detalhadas para cada módulo
- 💡 Recomendações priorizadas
- 📱 Design responsivo

---

## 🎯 por que usar? 🎯

### ✅ Antes vs Depois

| Antes | Depois |
|-------|--------|
| 😰 Logs confusos em 10 lugares diferentes | ✨ Um único relatório bonito |
| 🤯 Não sabe o que é crítico e o que não é | 🎯 Alertas priorizados automaticamente |
| 📝 Escrever análise manual leva horas | ⚡ IA faz em segundos |
| 🔓 Não tem certeza se está seguro | 📊 Score objetivo 0-100 |
| 😨 Privacidade? Que privacidade? | 🔐 Sanitização multi-nível |

### 🚀 Casos de Uso

- **🏢 Sysadmins**: Auditoria periódica de servidores
- **👨‍💻 DevOps**: Verificação de segurança pré-deploy
- **🔐 Security Teams**: Compliance e análise de postura
- **🎓 Estudantes**: Aprender segurança Linux na prática
- **🏠 Entusiastas**: Manter workstation pessoal segura

---

## 🧪 tecnologias usadas 🧪

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Google Gemini](https://img.shields.io/badge/Google_Gemini-4285F4?style=flat&logo=google&logoColor=white)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black)

- **Python 3.8+**: Core do sistema
- **psutil**: Coleta de métricas do sistema
- **Google Gemini API**: Análise humanizada via IA
- **systemd/journalctl**: Análise de logs
- **firewalld**: Verificação de firewall
- **SELinux**: Análise de políticas de segurança

---

## 📚 documentação 📚

Documentação completa disponível em:

- 📋 **[TODO.md](docs/TODO.md)** - Roadmap e tarefas futuras
- 🤝 **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** - Como contribuir
- 🏗️ **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Arquitetura do sistema
- 🔐 **[SECURITY.md](docs/SECURITY.md)** - Alertas e sanitização

---

## 🤝 como contribuir 🤝

Contribuições são muito bem-vindas! 🚀

1. Fork o projeto
2. Crie sua feature branch (`git checkout -b feature/MinhaFeature`)
3. Commit suas mudanças (`git commit -m 'Add: minha feature dahora'`)
4. Push para a branch (`git push origin feature/MinhaFeature`)
5. Abra um Pull Request

Leia [CONTRIBUTING.md](docs/CONTRIBUTING.md) para detalhes sobre nosso código de conduta e processo de PR.

---

## 📝 licença 📝

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

## 🙏 agradecimentos 🙏

- Google Gemini API pela análise inteligente
- Comunidade Python pela excelente tooling
- Fedora Project pelo sistema operacional incrível
- Todos os contribuidores que tornaram este projeto possível

---

## 📫 contato 📫

**Pedro Lucas Montezuma Loureiro**

[![GitHub](https://img.shields.io/badge/GitHub-montezuma--p-181717?style=flat&logo=github)](https://github.com/montezuma-p)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-montezuma--p-0A66C2?style=flat&logo=linkedin)](https://www.linkedin.com/in/montezuma-p/)
[![Reddit](https://img.shields.io/badge/Reddit-montezuma--p-FF4500?style=flat&logo=reddit&logoColor=white)](https://www.reddit.com/u/montezuma-p/s/J0TNbbzZaC)

---

<div align="center">

### 🚀 bora construir sistemas mais seguros juntos! 🚀

**Feito com ❤️ e ☕ por [Montezuma](https://github.com/montezuma-p)**

⭐ Se este projeto te ajudou, considere dar uma estrela!

</div>

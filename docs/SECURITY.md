# 🔐 Segurança e Privacidade

<div align="center">

**Guia completo sobre sistema de alertas e sanitização de dados**

*Porque sua privacidade importa tanto quanto sua segurança*

</div>

---

## 📋 índice

- [Sistema de Alertas](#-sistema-de-alertas)
- [Níveis de Sanitização](#-níveis-de-sanitização)
- [Dados Coletados](#-dados-coletados)
- [O que é Enviado para a IA](#-o-que-é-enviado-para-a-ia)
- [Exemplos Práticos](#-exemplos-práticos)
- [Boas Práticas](#-boas-práticas)
- [FAQ](#-faq)

---

## 🚨 sistema de alertas

O Security Audit System gera alertas inteligentes baseados nas métricas coletadas. Cada alerta é classificado por **severidade** e **categoria** para facilitar a priorização.

### Severidades de Alertas

```
┌─────────────────────────────────────────────────────────────┐
│                    NÍVEIS DE SEVERIDADE                     │
└─────────────────────────────────────────────────────────────┘

🔴 CRITICAL (Crítico)
├─ Requer ação IMEDIATA
├─ Pode comprometer segurança do sistema
├─ Exemplos:
│  • Firewall desabilitado
│  • SELinux em modo disabled
│  • Portas de administração expostas publicamente
│  • Ataque de força bruta detectado
│  • Vulnerabilidades críticas não corrigidas
└─ Score: -10 pontos cada

⚠️  WARNING (Aviso)
├─ Requer atenção em breve
├─ Pode se tornar crítico se não tratado
├─ Exemplos:
│  • Atualizações de segurança pendentes
│  • Portas incomuns abertas
│  • Múltiplos logins falhos
│  • Arquivos SUID suspeitos
│  • SELinux em modo permissive
└─ Score: -3 pontos cada

ℹ️  INFO (Informativo)
├─ Informação útil, não é problema
├─ Boas práticas ou contexto
├─ Exemplos:
│  • Sistema atualizado
│  • Firewall ativo e configurado
│  • Sem tentativas de login suspeitas
│  • Configurações recomendadas ativas
└─ Score: sem impacto
```

### Categorias de Alertas

Os alertas são organizados por área de segurança:

| Categoria | Foco | Exemplos |
|-----------|------|----------|
| 🔌 **Ports** | Portas e serviços | Portas abertas, serviços vulneráveis |
| 🔐 **Authentication** | Autenticação | Logins falhos, sessões suspeitas, sudo |
| 🛡️ **Firewall** | Firewall e SELinux | Status, zonas, políticas |
| ⚠️ **Vulnerabilities** | CVEs e updates | Pacotes vulneráveis, kernel desatualizado |
| 🌐 **Network** | Rede | Conectividade, DNS, interfaces |
| 📁 **Permissions** | Permissões | SUID/SGID, world-writable |

### Estrutura de um Alerta

```json
{
  "severity": "critical",
  "category": "firewall",
  "priority": 1,
  "message": "Firewall está desabilitado",
  "recommendation": "Execute 'sudo systemctl start firewalld' para ativar o firewall",
  "details": {
    "service": "firewalld",
    "status": "inactive"
  }
}
```

### Priorização de Alertas

O sistema usa um sistema de **prioridade numérica**:

```
Prioridade 1: 🔴 CRÍTICO + Alta Urgência
├─ Firewall desabilitado
├─ Ataque em andamento
└─ Sistema comprometido

Prioridade 2: 🔴 CRÍTICO + Média Urgência
├─ Vulnerabilidades críticas
└─ Configurações perigosas

Prioridade 3: ⚠️  WARNING + Alta Urgência
├─ Múltiplas tentativas de login
└─ Portas suspeitas

Prioridade 4: ⚠️  WARNING + Média Urgência
├─ Updates pendentes
└─ Configurações sub-ótimas

Prioridade 5: ℹ️  INFO
└─ Informações gerais
```

### Exemplos de Alertas Reais

#### 🔴 Alerta Crítico: Firewall Desabilitado

```
Severidade: CRITICAL
Categoria: firewall
Mensagem: "Firewall está desabilitado no sistema"

Explicação:
O firewalld não está ativo, deixando todas as portas expostas sem 
filtragem. Isso significa que qualquer serviço rodando no sistema 
pode ser acessado livremente da rede, aumentando drasticamente a 
superfície de ataque.

Recomendação:
1. Ative o firewall: sudo systemctl start firewalld
2. Habilite na inicialização: sudo systemctl enable firewalld
3. Configure zonas apropriadas: sudo firewall-cmd --set-default-zone=public

Impacto no Score: -10 pontos
```

#### ⚠️ Alerta de Aviso: Atualizações Pendentes

```
Severidade: WARNING
Categoria: vulnerabilities
Mensagem: "5 atualizações de segurança disponíveis"

Explicação:
Foram identificadas 5 atualizações de segurança que corrigem 
vulnerabilidades conhecidas (CVEs). Manter o sistema desatualizado 
expõe você a exploits públicos.

Pacotes afetados:
• kernel (CVE-2023-12345)
• openssl (CVE-2023-67890)
• systemd (CVE-2023-11111)

Recomendação:
Execute: sudo dnf update --security

Impacto no Score: -3 pontos
```

#### ℹ️ Alerta Informativo: Sistema Seguro

```
Severidade: INFO
Categoria: general
Mensagem: "Sistema está bem configurado"

Explicação:
Todas as verificações de segurança passaram com sucesso:
✅ Firewall ativo e configurado
✅ SELinux em modo enforcing
✅ Sistema atualizado
✅ Sem tentativas de login suspeitas
✅ Permissões de arquivos corretas

Continue monitorando regularmente para manter este nível.

Impacto no Score: +0 pontos (bônus já aplicados)
```

---

## 🔐 níveis de sanitização

Antes de enviar dados para a IA (modo `--full`), o sistema pode **sanitizar** informações sensíveis. Você escolhe o nível de acordo com suas necessidades de privacidade.

### Visão Geral

```
┌─────────────────────────────────────────────────────────────┐
│              NÍVEIS DE SANITIZAÇÃO                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  none      light      moderate      strict                  │
│   │          │           │             │                     
│   │          │           │             │                    │
│   ▼          ▼           ▼             ▼                     
│                                                             │
│  Dados    Anonimiza   Anonimiza    Máxima                   │
│ originais  último     IPs/users   privacidade               │
│           octeto       completo                             │
│                                                             │
├─────────────────────────────────────────────────────────────┤

```

### Nível: NONE

**Quando usar**: Apenas para testes ou ambientes de laboratório

**O que faz**: NENHUMA sanitização

**Dados enviados**:
- ✅ IPs reais (público e privados)
- ✅ Usernames reais
- ✅ Hostname real
- ✅ Paths completos com usernames
- ✅ Todas as informações originais

**Exemplo**:

```json
{
  "hostname": "workstation-montezuma",
  "metrics": {
    "authentication": {
      "failed_logins": [
        {
          "user": "montezuma",
          "source_ip": "192.168.1.105",
          "count": 3
        }
      ]
    },
    "network": {
      "interfaces": [
        {
          "name": "eth0",
          "ip": "192.168.1.100"
        }
      ]
    }
  }
}
```

⚠️ **ATENÇÃO**: Use apenas se você confia 100% no destino dos dados!

---

### Nível: LIGHT

**Quando usar**: Redes domésticas, dados pouco sensíveis

**O que faz**: Sanitização mínima de IPs privados

**Transformações**:

| Tipo | Original | Sanitizado | Regra |
|------|----------|------------|-------|
| IP Privado | `192.168.1.100` | `192.168.1.X` | Último octeto → X |
| IP Privado | `10.0.5.42` | `10.0.5.X` | Último octeto → X |
| IP Público | `203.0.113.5` | `203.0.113.5` | ✅ Mantido (útil para identificar atacantes) |
| Username | `montezuma` | `montezuma` | ✅ Mantido |
| Hostname | `workstation-pedro` | `workstation-pedro` | ✅ Mantido |

**Exemplo**:

```json
{
  "hostname": "workstation-montezuma",
  "metrics": {
    "authentication": {
      "failed_logins": [
        {
          "user": "montezuma",
          "source_ip": "192.168.1.X",  // ← Sanitizado
          "count": 3
        }
      ]
    },
    "network": {
      "interfaces": [
        {
          "name": "eth0",
          "ip": "192.168.1.X"  // ← Sanitizado
        }
      ]
    }
  }
}
```

**Privacidade**: ⭐⭐☆☆☆  
**Utilidade**: ⭐⭐⭐⭐⭐

---

### Nível: MODERATE (Recomendado) ⭐

**Quando usar**: Maioria dos casos, balance ideal

**O que faz**: Anonimiza IPs, usernames e hostname

**Transformações**:

| Tipo | Original | Sanitizado | Regra |
|------|----------|------------|-------|
| IP Privado | `192.168.1.100` | `192.168.X.X` | Dois últimos octetos → X |
| IP Privado | `10.0.5.42` | `10.0.X.X` | Dois últimos octetos → X |
| IP Público | `203.0.113.5` | `203.0.113.5` | ✅ Mantido (atacantes) |
| IP Atacante | `45.132.227.90` | `45.132.227.90` | ✅ Mantido (útil!) |
| Username | `montezuma` | `user1` | Mapeado consistentemente |
| Username | `root` | `root` | ✅ Mantido (comum) |
| Hostname | `workstation-pedro` | `workstation-001` | Anonimizado |
| Path | `/home/montezuma/` | `/home/$USER/` | Username removido |

**Exemplo**:

```json
{
  "hostname": "workstation-001",  // ← Sanitizado
  "metrics": {
    "authentication": {
      "failed_logins": [
        {
          "user": "user1",  // ← Sanitizado
          "source_ip": "192.168.X.X",  // ← Sanitizado
          "count": 3
        }
      ],
      "brute_force_analysis": {
        "suspicious_ips": [
          {
            "ip": "45.132.227.90",  // ← IP atacante mantido
            "attempts": 127,
            "users_attempted": ["user1", "user2"]  // ← Sanitizados
          }
        ]
      }
    },
    "permissions": {
      "ssh_keys": [
        "/home/$USER/.ssh/id_rsa"  // ← Path sanitizado
      ]
    }
  }
}
```

**Privacidade**: ⭐⭐⭐⭐☆  
**Utilidade**: ⭐⭐⭐⭐☆

**✅ RECOMENDADO**: Melhor balance entre privacidade e utilidade da análise

---

### Nível: STRICT

**Quando usar**: Ambientes corporativos, compliance, máxima privacidade

**O que faz**: Sanitiza TUDO, incluindo IPs públicos

**Transformações**:

| Tipo | Original | Sanitizado | Regra |
|------|----------|------------|-------|
| IP Privado | `192.168.1.100` | `192.X.X.X` | Três últimos octetos → X |
| IP Privado | `10.0.5.42` | `10.X.X.X` | Três últimos octetos → X |
| IP Público | `203.0.113.5` | `203.0.XXX.XXX` | ⚠️ Parcialmente sanitizado |
| IP Atacante | `45.132.227.90` | `45.132.XXX.XXX` | ⚠️ Mantém apenas região |
| Username | `montezuma` | `user1` | Mapeado |
| Username | `root` | `root` | ✅ Mantido (comum) |
| Hostname | `workstation-pedro` | `workstation-001` | Anonimizado |
| Path | `/home/montezuma/` | `/home/$USER/` | Username removido |

**Exemplo**:

```json
{
  "hostname": "workstation-001",
  "metrics": {
    "authentication": {
      "failed_logins": [
        {
          "user": "user1",
          "source_ip": "192.X.X.X",  // ← Máxima sanitização
          "count": 3
        }
      ],
      "brute_force_analysis": {
        "suspicious_ips": [
          {
            "ip": "45.132.XXX.XXX",  // ← Até atacantes sanitizados
            "attempts": 127,
            "users_attempted": ["user1", "user2"]
          }
        ]
      }
    },
    "network": {
      "gateway": "192.X.X.X"  // ← Gateway sanitizado
    }
  }
}
```

**Privacidade**: ⭐⭐⭐⭐⭐  
**Utilidade**: ⭐⭐⭐☆☆

⚠️ **Nota**: Sanitização excessiva pode reduzir qualidade da análise da IA

---

## 📊 comparação de níveis

### Tabela Resumida

| Feature | none | light | moderate ⭐ | strict |
|---------|------|-------|------------|--------|
| IPs Privados | Original | 192.168.1.X | 192.168.X.X | 192.X.X.X |
| IPs Públicos | Original | Original | Original | 203.0.XXX.XXX |
| Usernames | Original | Original | user1, user2 | user1, user2 |
| Hostname | Original | Original | workstation-001 | workstation-001 |
| Paths | Original | Original | /home/$USER/ | /home/$USER/ |
| **Privacidade** | 🔴 Nenhuma | 🟡 Baixa | 🟢 Alta | 🟢 Máxima |
| **Utilidade IA** | 🟢 Máxima | 🟢 Alta | 🟢 Alta | 🟡 Boa |
| **Recomendado para** | Labs | Casa | 🌟 Geral | Empresa |

---

## 📋 dados coletados

O sistema coleta as seguintes informações do seu sistema:

### ✅ Sempre Coletado (todos os modos)

- **Sistema**
  - Hostname
  - Timestamp da auditoria
  - Distribuição Linux e versão

- **Portas e Serviços**
  - Portas TCP/UDP abertas (listening)
  - Endereço IP local das portas
  - Conexões estabelecidas (local IP, remote IP, porta)
  - Serviços systemd ativos
  - Status dos serviços (ativo/inativo)

- **Autenticação**
  - Logs de login falho (últimas 24h por padrão)
    - Username tentado
    - IP de origem
    - Timestamp
  - Logins bem-sucedidos (últimas 24h)
  - Uso de sudo
  - Sessões ativas (who)
  - Configuração SSH (`/etc/ssh/sshd_config`)

- **Firewall e SELinux**
  - Status do firewalld (ativo/inativo)
  - Zonas configuradas
  - Portas liberadas por zona
  - Serviços permitidos
  - Status do SELinux (enforcing/permissive/disabled)
  - Políticas SELinux

- **Vulnerabilidades**
  - Pacotes com atualizações de segurança disponíveis
  - Versão do kernel
  - CVEs conhecidos dos pacotes instalados

- **Rede**
  - Interfaces de rede e status
  - Endereços IP de cada interface
  - Gateway padrão
  - Servidores DNS configurados
  - Teste de conectividade (ping para hosts configurados)
  - Velocidade estimada de rede

- **Permissões**
  - Arquivos com bit SUID
  - Arquivos com bit SGID
  - Arquivos world-writable em diretórios críticos
  - Permissões de arquivos críticos (`/etc/passwd`, `/etc/shadow`, etc.)
  - Permissões de diretórios home
  - Permissões de chaves SSH

### 🔒 NUNCA Coletado

- ❌ Conteúdo de arquivos
- ❌ Senhas ou hashes de senha
- ❌ Chaves SSH privadas
- ❌ Variáveis de ambiente
- ❌ Histórico de comandos
- ❌ Cookies ou sessões web
- ❌ Dados de navegador
- ❌ Emails ou mensagens
- ❌ Conteúdo de databases

---

## ☁️ o que é enviado para a ia

### Modo `--no-ai`

**NADA é enviado**. Tudo fica local em JSON.

### Modo `--local-html`

**NADA é enviado**. Análise básica local, sem Gemini.

### Modo `--full`

**JSON sanitizado** (de acordo com nível escolhido) + prompt é enviado para Google Gemini API.

**Conteúdo do prompt**:

```
Você é um especialista em segurança de sistemas Linux.

Analise o seguinte relatório de auditoria de segurança e forneça:

1. Resumo executivo da postura de segurança
2. Análise detalhada de cada área (portas, autenticação, firewall, etc.)
3. Explicação didática dos alertas encontrados
4. Recomendações priorizadas de correção
5. Contexto e educação sobre cada problema

Seja didático, use analogias quando apropriado, e priorize clareza.

[JSON SANITIZADO ANEXADO AQUI]
```

**O que o Gemini recebe**:
- ✅ Estrutura de dados (quais checks foram feitos)
- ✅ Métricas numéricas (quantidades)
- ✅ Alertas gerados
- ✅ Dados sanitizados conforme nível escolhido

**O que o Gemini NÃO recebe** (se sanitização moderate/strict):
- ❌ Seu IP real
- ❌ Seu username real
- ❌ Seu hostname real
- ❌ Paths com seu username

---

## 💡 exemplos práticos

### Exemplo 1: Ataque de Força Bruta

**Dados originais**:
```json
{
  "authentication": {
    "brute_force_analysis": {
      "detected": true,
      "suspicious_ips": [
        {
          "ip": "45.132.227.90",
          "attempts": 127,
          "users_attempted": ["root", "admin", "montezuma"],
          "time_window": "2h"
        }
      ]
    }
  }
}
```

**Após sanitização MODERATE**:
```json
{
  "authentication": {
    "brute_force_analysis": {
      "detected": true,
      "suspicious_ips": [
        {
          "ip": "45.132.227.90",  // Mantido (atacante externo)
          "attempts": 127,
          "users_attempted": ["root", "admin", "user1"],  // user1 = montezuma
          "time_window": "2h"
        }
      ]
    }
  }
}
```

**Análise da IA** (recebe dados sanitizados):
> 🚨 **CRÍTICO**: Ataque de força bruta detectado!
>
> Um endereço IP (45.132.227.90) fez 127 tentativas de login em 2 horas,
> tentando múltiplos usernames incluindo "root" e "admin". Isso é um
> padrão clássico de ataque automatizado.
>
> **O que fazer AGORA**:
> 1. Bloqueie o IP: `sudo firewall-cmd --add-rich-rule='rule family=ipv4 source address=45.132.227.90 reject'`
> 2. Instale fail2ban: `sudo dnf install fail2ban`
> 3. Desabilite login SSH como root em `/etc/ssh/sshd_config`

**Note**: A IA recebeu o IP do atacante (útil!), mas não seu username real.

---

### Exemplo 2: Porta Suspeita Aberta

**Dados originais**:
```json
{
  "ports": {
    "suspicious_ports": [
      {
        "port": 3389,
        "protocol": "tcp",
        "local_address": "192.168.1.100",
        "process": "xrdp",
        "reason": "RDP port (common in Windows attacks)"
      }
    ]
  }
}
```

**Após sanitização MODERATE**:
```json
{
  "ports": {
    "suspicious_ports": [
      {
        "port": 3389,
        "protocol": "tcp",
        "local_address": "192.168.X.X",  // Sanitizado
        "process": "xrdp",
        "reason": "RDP port (common in Windows attacks)"
      }
    ]
  }
}
```

**Análise da IA**:
> ⚠️ **AVISO**: Porta 3389 (RDP) exposta
>
> A porta 3389 é usada pelo Remote Desktop Protocol, frequentemente
> alvo de ataques. Se você não precisa de acesso remoto via RDP,
> considere desabilitar o serviço xrdp.
>
> **Se você precisa**:
> - Configure firewall para aceitar apenas IPs confiáveis
> - Use autenticação forte (chave SSH, não senha)
> - Considere túnel SSH ao invés de RDP direto

**Note**: A IA não sabe seu IP exato, mas conseguiu analisar o problema.

---

## ✅ boas práticas

### Escolhendo o Nível de Sanitização

```
┌─────────────────────────────────────────────────────────┐
│          DECISÃO: QUAL NÍVEL USAR?                      │
└─────────────────────────────────────────────────────────┘

Você está em ambiente...

┌─ Corporativo / Empresa?
│  └─▶ Use: STRICT
│      • Compliance pode exigir
│      • Dados sensíveis de clientes
│      • Melhor prevenir

┌─ Servidor de Produção?
│  └─▶ Use: MODERATE ou STRICT
│      • Dados podem vazar em logs da API
│      • Prefira --local-html

┌─ Workstation Pessoal?
│  └─▶ Use: MODERATE (recomendado)
│      • Balance ideal
│      • Protege identidade
│      • IA ainda útil

┌─ Laboratório / Testes?
│  └─▶ Use: LIGHT ou NONE
│      • Ambiente controlado
│      • Máxima utilidade da análise
```

### Comandos Recomendados

```bash
# ✅ RECOMENDADO: Uso geral
./security_audit.sh --full --sanitize-level moderate

# ✅ BOM: Máxima privacidade
./security_audit.sh --full --sanitize-level strict

# ⚠️ CUIDADO: Apenas para labs
./security_audit.sh --full --sanitize-level none --skip-confirm

# ✅ SEGURO: Sem envio de dados
./security_audit.sh --local-html
```

### Auditoria Regular

```bash
# Agendar auditoria semanal (sem IA, apenas local)
# Adicionar ao crontab:
0 2 * * 1 /caminho/security_audit.sh --no-ai

# Ou mensal com análise IA:
0 2 1 * * /caminho/security_audit.sh --full --sanitize-level moderate
```

---

## ❓ faq

### "Por que o sistema pede confirmação?"

Para garantir que você está **ciente** de que dados serão enviados para Google Gemini API. Transparência é fundamental para privacidade.

### "Posso confiar na sanitização?"

A sanitização é **best-effort**. Ela remove os dados mais óbvios, mas:
- ⚠️ Pode haver edge cases não cobertos
- ⚠️ Padrões nos dados podem ainda identificar você
- ✅ Para máxima privacidade, use `--local-html` (sem IA)

### "O Google vai ter meus dados?"

Se você usar `--full`:
- ✅ Google Gemini processa o JSON sanitizado
- ⚠️ Google pode logar requests (políticas deles)
- ✅ Não enviamos nada além do JSON + prompt
- ✅ Não rastreamos você

Se você usar `--no-ai` ou `--local-html`:
- ✅ NADA é enviado para lugar nenhum
- ✅ Tudo fica local

### "Posso auditar o código?"

✅ **SIM!** O projeto é 100% open-source:
- `reporter/modules/sanitizer.py` - Lógica de sanitização
- `reporter/security_reporter.py` - Envio para Gemini
- `monitor/` - Coleta de dados

Leia o código, audite, sugira melhorias!

### "E se eu não quiser usar IA nunca?"

Perfeito! Use apenas:
```bash
./security_audit.sh --no-ai
# ou
./security_audit.sh --local-html
```

Você ainda terá:
- ✅ Coleta completa de métricas
- ✅ Sistema de alertas
- ✅ Score de segurança
- ✅ Relatório HTML básico (--local-html)

### "Qual a diferença entre --no-ai e --local-html?"

```
--no-ai
├─ Coleta métricas
├─ Gera alertas
├─ Salva JSON
└─ FIM (sem HTML)

--local-html
├─ Coleta métricas
├─ Gera alertas
├─ Salva JSON
├─ Gera HTML básico (analyzers locais)
└─ Abre no browser
    (SEM análise do Gemini)
```

### "Posso contribuir melhorando a sanitização?"

**SIM POR FAVOR!** 🙏

Abra um PR melhorando `reporter/modules/sanitizer.py`. Ideias:
- Detectar mais padrões sensíveis
- Sanitizar campos adicionais
- Novo nível de sanitização
- Melhor documentação

---

## 🔒 compromisso de privacidade

Como mantenedor deste projeto, me comprometo a:

1. ✅ **Transparência total** sobre dados coletados
2. ✅ **Nunca adicionar** telemetria ou tracking
3. ✅ **Nunca enviar dados** sem consentimento explícito
4. ✅ **Documentar claramente** o que vai para onde
5. ✅ **Aceitar** PRs que melhorem privacidade
6. ✅ **Manter** opções totalmente locais (--no-ai, --local-html)

**Este projeto é para VOCÊ auditar SUA segurança, não para EU coletar seus dados.**

---

## 📞 reportar problemas de privacidade

Encontrou um vazamento de dados ou problema de privacidade?

**Reporte IMEDIATAMENTE**:

- 🔒 [Abra uma issue](https://github.com/montezuma-p/security-audit-system/issues/new) com tag `security`
- 📧 Ou email direto para: [LinkedIn](https://www.linkedin.com/in/montezuma-p/)

Problemas de privacidade são tratados com **MÁXIMA PRIORIDADE**.

---

<div align="center">

## 🙏 sua privacidade importa

Este guia será constantemente atualizado conforme o projeto evolui.

**Dúvidas?** [Abra uma Discussion](https://github.com/montezuma-p/security-audit-system/discussions)

**Sugestões?** [Abra uma Issue](https://github.com/montezuma-p/security-audit-system/issues)

---

*Feito com ❤️ e respeito pela sua privacidade*

**by [Montezuma](https://github.com/montezuma-p)**

</div>

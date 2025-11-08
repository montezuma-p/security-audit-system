# 📋 TODO - Roadmap do Projeto

<div align="center">

**Lista de tarefas futuras e melhorias planejadas**

*Última atualização: 8 de novembro de 2025*

</div>

---

## 🎯 tarefas prioritárias 🎯

### 🧪 1. Implementar Testes Automatizados

**Status**: 📝 Planejado

**Descrição**:
Criar suite completa de testes para garantir a qualidade e confiabilidade do sistema.

**O que precisa ser feito**:

- [ ] **Testes Unitários**
  - [ ] Testar módulos de coleta individualmente (`ports.py`, `auth.py`, etc.)
  - [ ] Testar analyzers (`score_analyzer.py`, `auth_analyzer.py`, etc.)
  - [ ] Testar sistema de sanitização em todos os níveis
  - [ ] Testar geração de alertas
  - [ ] Testar cálculo de score de segurança

- [ ] **Testes de Integração**
  - [ ] Testar fluxo completo: monitor → reporter → HTML
  - [ ] Testar diferentes níveis de sanitização end-to-end
  - [ ] Testar com e sem API do Gemini
  - [ ] Testar modos: `--no-ai`, `--local-html`, `--full`

- [ ] **Testes de Configuração**
  - [ ] Testar carregamento de `config.json`
  - [ ] Testar fallback para valores default
  - [ ] Testar ENV vars (`SECURITY_MONITOR_OUTPUT`, etc.)
  - [ ] Testar desabilitação seletiva de checks

- [ ] **Mocks e Fixtures**
  - [ ] Criar dados mock para testes sem acesso root
  - [ ] Criar JSONs de exemplo para cada módulo
  - [ ] Mockar chamadas de sistema (journalctl, firewall-cmd, etc.)
  - [ ] Mockar API do Gemini

- [ ] **Testes de Edge Cases**
  - [ ] Sistema sem internet
  - [ ] Firewall desabilitado
  - [ ] SELinux em modo permissive/disabled
  - [ ] Usuário sem privilégios sudo
  - [ ] Diretórios inexistentes

**Ferramentas a usar**:
- `pytest` - Framework de testes
- `pytest-cov` - Coverage reporting
- `unittest.mock` - Mocking de system calls
- `pytest-xdist` - Testes paralelos

**Meta de Coverage**: 80%+

**Prioridade**: 🔥 ALTA

---

### 🐳 2. Criar Imagem Docker

**Status**: 📝 Planejado

**Descrição**:
Containerizar o sistema para facilitar deployment e garantir ambiente consistente.

**O que precisa ser feito**:

- [ ] **Dockerfile Base**
  - [ ] Criar Dockerfile otimizado (multi-stage build)
  - [ ] Usar imagem base Fedora (manter compatibilidade)
  - [ ] Instalar dependências Python (`requirements.txt`)
  - [ ] Configurar usuário não-root para execução
  - [ ] Configurar entrypoint apropriado

- [ ] **Volumes e Configuração**
  - [ ] Volume para configuração (`config.json`)
  - [ ] Volume para output de relatórios JSON
  - [ ] Volume para output de relatórios HTML
  - [ ] ENV vars para customização

- [ ] **Docker Compose**
  - [ ] Criar `docker-compose.yml`
  - [ ] Configurar volumes
  - [ ] Configurar variáveis de ambiente
  - [ ] Exemplo de uso com cron para execução periódica

- [ ] **Variantes de Imagem**
  - [ ] Imagem slim (apenas monitor, sem IA)
  - [ ] Imagem full (com suporte a Gemini)
  - [ ] Imagem com healthcheck

- [ ] **Documentação Docker**
  - [ ] Atualizar README com instruções Docker
  - [ ] Criar `docs/DOCKER.md` com detalhes
  - [ ] Exemplos de uso
  - [ ] Troubleshooting comum

- [ ] **CI/CD**
  - [ ] GitHub Actions para build automático
  - [ ] Publicar no Docker Hub
  - [ ] Versionamento de tags
  - [ ] Multi-arch build (amd64, arm64)

**Exemplo de uso previsto**:

```bash
# Build
docker build -t montezuma-p/security-audit:latest .

# Run modo no-ai
docker run -v ./config.json:/app/config.json \
           -v ./reports:/reports \
           montezuma-p/security-audit:latest --no-ai

# Run modo full
docker run -e GEMINI_API_KEY="sua-key" \
           -v ./config.json:/app/config.json \
           -v ./reports:/reports \
           montezuma-p/security-audit:latest --full

# Docker Compose
docker-compose up
```

**Prioridade**: 🔥 ALTA

---

## 📊 status geral 📊

| Tarefa | Status | Prioridade | Estimativa |
|--------|--------|------------|------------|
| Testes Automatizados | 📝 Planejado | 🔥 Alta | 2-3 semanas |
| Imagem Docker | 📝 Planejado | 🔥 Alta | 1 semana |

---

## 💡 ideias futuras (backlog) 💡

Estas são ideias para o futuro, sem prazo definido:

### Funcionalidades

- [ ] Dashboard web interativo para visualizar histórico
- [ ] Notificações (email, Slack, Discord) para alertas críticos
- [ ] Agendamento automático (systemd timer)
- [ ] Comparação entre múltiplas auditorias (trending)
- [ ] Export para PDF
- [ ] Modo headless para servidores sem GUI
- [ ] Suporte a outras distros (Ubuntu, Debian, Arch)

### Melhorias Técnicas

- [ ] Cache de resultados para módulos lentos
- [ ] Paralelização de coleta de métricas
- [ ] Compressão de JSONs antigos
- [ ] Rotação automática de relatórios (manter apenas N últimos)
- [ ] Modo incremental (só coletar o que mudou)

### Integrações

- [ ] Integração com Prometheus/Grafana
- [ ] API REST para acesso programático
- [ ] Webhooks para eventos críticos
- [ ] Integração com SIEM tools

---

## 🎯 como contribuir com estas tarefas? 🎯

Interessado em trabalhar em alguma destas tarefas?

1. **Verifique** se já existe uma issue aberta
2. **Comente** na issue manifestando interesse
3. **Fork** o projeto
4. **Desenvolva** a solução
5. **Teste** bem
6. **Abra** um Pull Request

Veja [CONTRIBUTING.md](CONTRIBUTING.md) para mais detalhes.

---

## 📝 notas 📝

- Esta lista é viva e será atualizada conforme o projeto evolui
- Prioridades podem mudar baseado em feedback da comunidade
- Sugestões de novas tarefas são bem-vindas (abra uma issue!)

---

<div align="center">

**Quer sugerir uma nova tarefa?**

[Abra uma issue](https://github.com/montezuma-p/security-audit-system/issues/new) com a tag `enhancement`

</div>

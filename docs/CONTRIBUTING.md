# 🤝 Guia de Contribuição

<div align="center">

**Obrigado por considerar contribuir com o Security Audit System!**

*Toda ajuda é bem-vinda, desde correção de typos até novas features* 🚀

</div>

---

## 📋 índice

- [Código de Conduta](#-código-de-conduta)
- [Como Posso Contribuir?](#-como-posso-contribuir)
- [Reportando Bugs](#-reportando-bugs)
- [Sugerindo Features](#-sugerindo-features)
- [Desenvolvimento](#-desenvolvimento)
- [Padrões de Código](#-padrões-de-código)
- [Processo de Pull Request](#-processo-de-pull-request)
- [Estilo de Commits](#-estilo-de-commits)

---

## 📜 código de conduta

Este projeto adota um código de conduta baseado em respeito mútuo:

### Esperamos que você:

✅ Seja respeitoso e inclusivo  
✅ Aceite críticas construtivas  
✅ Foque no que é melhor para a comunidade  
✅ Mostre empatia com outros membros  

### Não toleramos:

❌ Linguagem ou imagens sexualizadas  
❌ Trolling, insultos ou comentários depreciativos  
❌ Assédio público ou privado  
❌ Publicar informações privadas de terceiros sem permissão  
❌ Qualquer conduta considerada inapropriada em ambiente profissional  

---

## 💡 como posso contribuir?

Há várias formas de contribuir:

### 1. 🐛 Reportar Bugs
Encontrou um problema? Reporte! (veja seção abaixo)

### 2. 💡 Sugerir Features
Tem uma ideia legal? Compartilhe! (veja seção abaixo)

### 3. 📝 Melhorar Documentação
- Corrigir typos
- Adicionar exemplos
- Traduzir documentos
- Escrever tutoriais

### 4. 💻 Contribuir com Código
- Implementar features da [TODO list](TODO.md)
- Corrigir bugs reportados
- Melhorar performance
- Adicionar testes

### 5. 🎨 Melhorar UI/UX
- Templates HTML mais bonitos
- CSS responsivo
- JavaScript para interatividade
- Novos temas/estilos

### 6. 🧪 Testar
- Testar em diferentes ambientes
- Reportar edge cases
- Validar correções de bugs

---

## 🐛 reportando bugs

Antes de reportar um bug:

1. **Verifique** se já não existe uma issue aberta sobre o problema
2. **Atualize** para a versão mais recente
3. **Teste** em ambiente limpo (venv nova)

### Como reportar:

Abra uma [nova issue](https://github.com/montezuma-p/security-audit-system/issues/new) incluindo:

**Template de Bug Report**:

```markdown
## Descrição do Bug
[Descrição clara e concisa do problema]

## Como Reproduzir
1. Execute '...'
2. Com configuração '...'
3. Veja o erro '...'

## Comportamento Esperado
[O que deveria acontecer]

## Comportamento Atual
[O que realmente acontece]

## Screenshots/Logs
[Se aplicável, adicione screenshots ou logs]

## Ambiente
- SO: [ex: Fedora 38]
- Python: [ex: 3.11.2]
- Versão do projeto: [ex: commit hash ou tag]
- Modo de execução: [ex: --full, --no-ai]

## Contexto Adicional
[Qualquer outra informação relevante]
```

**Exemplo Bom**:

> **Bug**: Script falha ao coletar métricas de rede sem internet
>
> **Como Reproduzir**:
> 1. Desconectar internet
> 2. Executar `./security_audit.sh --no-ai`
> 3. Erro: `ModuleNotFoundError: No module named 'network'`
>
> **Ambiente**: Fedora 38, Python 3.11
>
> **Logs**: (anexar arquivo ou paste)

---

## 💡 sugerindo features

Quer propor uma nova funcionalidade?

### Antes de sugerir:

1. **Verifique** a [TODO list](TODO.md) - pode já estar planejado
2. **Procure** issues existentes com tag `enhancement`
3. **Considere** se a feature beneficia a maioria dos usuários

### Como sugerir:

Abra uma [nova issue](https://github.com/montezuma-p/security-audit-system/issues/new) com tag `enhancement`:

**Template de Feature Request**:

```markdown
## Descrição da Feature
[Descrição clara e concisa da funcionalidade desejada]

## Problema que Resolve
[Qual problema esta feature resolve? Por que é útil?]

## Solução Proposta
[Como você imagina que funcione?]

## Alternativas Consideradas
[Outras formas de resolver o problema]

## Exemplos de Uso
```bash
# Como seria usar a feature
./security_audit.sh --nova-flag
```

## Impacto
- [ ] Melhora performance
- [ ] Adiciona funcionalidade nova
- [ ] Melhora usabilidade
- [ ] Melhora segurança
```

**Exemplo Bom**:

> **Feature**: Suporte a notificações por email
>
> **Problema**: Preciso ser notificado quando há alertas críticos, mas nem sempre vejo o relatório
>
> **Solução**: Adicionar opção `--email` que envia relatório por SMTP
>
> **Uso**:
> ```bash
> ./security_audit.sh --full --email admin@example.com
> ```

---

## 💻 desenvolvimento

### Setup do Ambiente de Dev

```bash
# 1. Fork o repositório no GitHub

# 2. Clone seu fork
git clone https://github.com/SEU-USUARIO/security-audit-system.git
cd security-audit-system

# 3. Adicione o upstream
git remote add upstream https://github.com/montezuma-p/security-audit-system.git

# 4. Crie venv
python3 -m venv venv
source venv/bin/activate

# 5. Instale dependências + dev tools
pip install -r requirements.txt
pip install pytest pytest-cov pylint black

# 6. Crie branch para sua feature
git checkout -b feature/minha-feature
```

### Estrutura de Branches

- `main` - Código estável de produção
- `develop` - Desenvolvimento ativo
- `feature/*` - Novas features
- `bugfix/*` - Correções de bugs
- `hotfix/*` - Correções urgentes

### Testando Suas Mudanças

```bash
# Testes unitários (quando disponíveis)
pytest tests/

# Teste manual
./security_audit.sh --no-ai
./security_audit.sh --local-html

# Lint
pylint monitor/security_monitor.py
pylint reporter/security_reporter.py

# Formatação
black monitor/ reporter/
```

---

## 📏 padrões de código

### Python

Seguimos PEP 8 com algumas exceções:

```python
# ✅ BOM
def collect_metrics(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Coleta métricas de segurança do sistema
    
    Args:
        config: Dicionário de configuração
        
    Returns:
        Dicionário com métricas coletadas
    """
    metrics = {}
    # Implementação...
    return metrics

# ❌ RUIM
def get_stuff(x):
    # Sem docstring, sem type hints
    y = {}
    # ...
    return y
```

**Regras**:

- ✅ **Docstrings** em todas as funções/classes públicas
- ✅ **Type hints** em assinaturas de funções
- ✅ **Nomes descritivos** (sem `x`, `y`, `tmp`, `data2`)
- ✅ **Constantes** em UPPER_CASE
- ✅ **4 espaços** de indentação (não tabs)
- ✅ **Máximo 100 caracteres** por linha (flexível)
- ✅ **Imports** organizados: stdlib → third-party → local

### Shell Script

```bash
# ✅ BOM
check_dependencies() {
    local dependency=$1
    if ! command -v "$dependency" &> /dev/null; then
        echo "❌ Erro: $dependency não encontrado"
        return 1
    fi
    return 0
}

# ❌ RUIM
check() {
    if ! command -v $1 &> /dev/null; then
        echo "erro"
        return 1
    fi
}
```

**Regras**:

- ✅ `set -e` no início
- ✅ Variáveis entre aspas `"$var"`
- ✅ `local` para variáveis de função
- ✅ Comentários explicativos
- ✅ Tratamento de erros

### HTML/CSS/JavaScript

- ✅ **Indentação** consistente (2 espaços)
- ✅ **Classes semânticas** (`security-score`, não `box1`)
- ✅ **Mobile-first** design
- ✅ **Acessibilidade** (alt tags, ARIA labels)
- ✅ **Comentários** em seções complexas

---

## 🔀 processo de pull request

### Checklist Antes de Abrir PR

- [ ] Código segue os padrões do projeto
- [ ] Testes passam (quando disponíveis)
- [ ] Documentação atualizada (se necessário)
- [ ] CHANGELOG.md atualizado (para mudanças significativas)
- [ ] Commits bem formatados (veja próxima seção)
- [ ] Branch atualizada com `main`/`develop`

### Como Abrir PR

1. **Push** sua branch
```bash
git push origin feature/minha-feature
```

2. **Abra PR** no GitHub:
   - Base: `develop` (ou `main` para hotfixes)
   - Compare: `feature/minha-feature`
   
3. **Preencha** o template:

```markdown
## Descrição
[Descrição clara das mudanças]

## Tipo de Mudança
- [ ] Bug fix (mudança que corrige um problema)
- [ ] Nova feature (mudança que adiciona funcionalidade)
- [ ] Breaking change (correção ou feature que quebraria funcionalidade existente)
- [ ] Documentação

## Como Testar
1. ...
2. ...

## Checklist
- [ ] Código segue padrões do projeto
- [ ] Comentários adicionados em código complexo
- [ ] Documentação atualizada
- [ ] Sem warnings de lint
- [ ] Testes passam

## Screenshots (se aplicável)
[Adicione screenshots de mudanças visuais]
```

4. **Aguarde** review

### Processo de Review

- Mantenedor(es) revisarão seu PR
- Podem pedir mudanças
- Seja paciente e receptivo a feedback
- Uma vez aprovado, será mergeado

---

## 📝 estilo de commits

Usamos **Conventional Commits**:

### Formato

```
<tipo>: <descrição curta>

[corpo opcional]

[footer opcional]
```

### Tipos

- `feat:` Nova feature
- `fix:` Correção de bug
- `docs:` Mudanças em documentação
- `style:` Formatação (sem mudança de código)
- `refactor:` Refatoração de código
- `perf:` Melhoria de performance
- `test:` Adição/correção de testes
- `chore:` Tarefas de build, configs, etc.

### Exemplos

**Bons commits**:

```bash
feat: adicionar suporte a notificações por email

Implementa envio de relatórios via SMTP quando flag --email é usada.
Configuração via config.json ou ENV vars.

Closes #42

---

fix: corrigir parsing de logs do journalctl

Regex estava falhando com usernames contendo números.
Adicionado tratamento de edge case.

---

docs: atualizar README com instruções Docker

---

refactor: simplificar lógica de sanitização de IPs

Reduz complexidade ciclomática de 15 para 8.
```

**Commits ruins**:

```bash
# ❌ Muito vago
fix stuff

# ❌ Múltiplas mudanças não relacionadas  
feat: adicionar email, corrigir bug de rede, atualizar docs

# ❌ Sem contexto
update file
```

### Dicas

- Use imperativos: "adicionar" não "adicionado"
- Primeira linha com max 72 caracteres
- Corpo com max 100 caracteres por linha
- Separe assunto do corpo com linha em branco
- Referencie issues quando aplicável: `Closes #123`

---

## 🎯 áreas que precisam de ajuda

Estas são áreas onde contribuições são especialmente bem-vindas:

### Alta Prioridade 🔥

- [ ] **Testes**: Criar suite de testes (pytest)
- [ ] **Docker**: Containerização do sistema
- [ ] **Docs**: Tradução para inglês
- [ ] **Performance**: Otimizar coleta de métricas

### Média Prioridade ⚠️

- [ ] **Features**: Dashboard web
- [ ] **Integrações**: Slack, Discord notifications
- [ ] **Suporte**: Outras distros Linux
- [ ] **UI/UX**: Melhorar templates HTML

### Baixa Prioridade 💡

- [ ] **Extras**: Modo dark para HTML
- [ ] **Docs**: Mais exemplos de uso
- [ ] **Refactoring**: Simplificar código legado

---

## 🙏 reconhecimento

Todos os contribuidores serão:

- ✨ Listados no README.md
- 🎉 Mencionados no CHANGELOG.md
- 💖 Eternamente gratos pela comunidade

---

## 📞 precisa de ajuda?

Não hesite em perguntar:

- 💬 Abra uma [Discussion](https://github.com/montezuma-p/security-audit-system/discussions)
- 🐛 Comente na issue relacionada
- 📧 Entre em contato: [LinkedIn](https://www.linkedin.com/in/montezuma-p/)

---

<div align="center">

### 🚀 obrigado por contribuir! 🚀

**Juntos construímos sistemas mais seguros** 🔒

*Feito com ❤️ pela comunidade*

</div>

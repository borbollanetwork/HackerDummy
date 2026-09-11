# Lab 20 — GraphForge — Resultados

GraphQL avançado — além do reconhecimento básico do Lab 07 (GraphVault), na
superfície de ataque de execução de query: amplificação de custo por aliases (DoS),
uma mutation privilegiada sem autenticação (BFLA), CSRF de GraphQL por GET / POST
form-encoded e introspecção habilitada em produção.

## Resultado: 100% na PRIMEIRA passada — uma confirmação limpa de cobertura

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base | **5/5 (100%)** | 83% | sem correção necessária — todo achado classificou certo de saída |

O especialista de GraphQL às cegas achou tudo: despejou o schema por introspecção
(notando o campo sensível `User.ssn` e a mutation `promoteToAdmin`), disparou a
mutation `promoteToAdmin` sem autenticação (escalada de privilégio, sem credenciais),
provou que a mesma mutation funciona por **GET** e por **POST form-encoded** (CSRF,
sem token / sem exigir JSON) e amplificou uma query `report` com aliases a ~1 MB sem
limite de custo.

Notavelmente, todos os cinco classificaram certo **sem mudança no classificador**:
- o achado de amplificação por aliases → `dos`,
- a mutation sem autenticação → `bfla`,
- a mutation de GraphQL por GET → `csrf` — a classe adicionada no Lab 17 (OAuthForge)
  **generalizou de forma limpa** para o CSRF de GraphQL,
- introspecção → `graphql`,
- cabeçalhos ausentes → `headers`.

Este é o valor de um benchmark mesmo quando nada quebra: o Lab 20 confirma que o
plugin lida com a superfície avançada de GraphQL — e que a classe `csrf`
recém-adicionada não é específica de OAuth, mas cobre requisições que mudam estado
entre sites em geral.

## Nota do laboratório

Um executor de GraphQL deliberadamente simplificado (substring/regex), fiel o
bastante para demonstrar cada problema. Nada executa código; só dados de brincadeira.

## Rodar

```bash
python labs/20-graphforge/app.py       # -> http://127.0.0.1:18821  (/graphql)
```

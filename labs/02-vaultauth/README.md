# Lab 02 — VaultAuth

> ⚠️ **VULNERÁVEL DE PROPÓSITO — TREINO SOMENTE EM LOCALHOST.**
> Falhas de autenticação reais e exploráveis de propósito. Escuta em `127.0.0.1`.
> Nunca a exponha; nunca reaproveite as credenciais de semente.

## O que é

O **VaultAuth** é uma **API de identidade e autenticação** baseada em JWT, falsa,
para praticar testes de autenticação, JWT e gestão de sessão. Arquivo Python
único e autocontido, **só com a biblioteca padrão** (`http.server` + `sqlite3` +
`hmac`/`hashlib`/`base64`). Os JWTs são montados e verificados **na mão** (sem
PyJWT), então cada falha fica explícita no código-fonte. SQLite em memória,
populado do zero na inicialização — reinicie para redefinir o estado.

## Como rodar

```bash
python app.py        # -> http://127.0.0.1:18802
```

Sem argumentos, sem dependências. Exige Python 3.8 ou superior. A raiz `/`
devolve a lista de endpoints.

### Fluxo

`POST /register` → `POST /login` (devolve a dica do OTP 😬) → `POST /verify-otp`
(devolve um **JWT**) → `GET /me` / `GET /admin` com `Authorization: Bearer <jwt>`.
Recuperação de conta: `POST /reset-request` → `POST /reset`.

## Usuários de semente

| username | password          | role  | otp    |
|----------|-------------------|-------|--------|
| admin    | `S3cr3tAdminP@ss` | admin | 000000 |
| alice    | `alice123`        | user  | 111111 |
| bob      | `bobpassword`     | user  | 222222 |

(O objetivo é forjar acesso **sem** elas.)

## Vulnerabilidades plantadas

Gabarito: [`gabarito.json`](gabarito.json). 12 vulnerabilidades, 1 ponto cada.

| ID  | Classe          | Sev      | Rota             | Como explorar |
|-----|-----------------|----------|------------------|----------------|
| J1  | jwt             | critical | `/me`,`/admin`   | Forje um token com cabeçalho `{"alg":"none"}` e assinatura vazia → o servidor pula a verificação. Defina `role:admin` → admin total. |
| J2  | jwt             | critical | `/me`            | O segredo HS256 é `secret` — quebre offline (`hashcat -m 16500`) e reassine qualquer token. |
| J3  | jwt             | high     | `/me`            | O `exp` nunca é validado → tokens capturados repetem para sempre. |
| A1  | user-enum       | medium   | `/login`         | `no such user` (404) vs `incorrect password` (401); `/register` 409 em usuário existente → enumere contas. |
| A2  | no-rate-limit   | medium   | `/login`         | Sem bloqueio ou limitação em `/login` ou `/verify-otp` → força bruta de senhas e do OTP de 6 dígitos. |
| A3  | auth            | high     | `/reset-request` | O token de redefinição é um **inteiro sequencial** *e* devolvido no corpo da resposta → redefina a senha de qualquer um. |
| A4  | 2fa-bypass      | high     | `/verify-otp`    | O OTP é ecoado na resposta do `/login` (`otp_hint`); o código mestre `000000` é aceito; sem limite de taxa. |
| A5  | mass-assignment | high     | `/register`      | `POST /register {"role":"admin"}` → conta admin instantânea. |
| A6  | weak-crypto     | high     | `/debug`,`/admin`| Senhas armazenadas como **MD5 sem sal**, vazadas sem autenticação em `/debug`. |
| A7  | idor            | high     | `/api/user/<id>` | `GET /api/user/1..N` → registro de qualquer usuário, sem autenticação. |
| S2  | session         | medium   | `/logout`        | JWT sem estado + sem lista de negação → token ainda válido depois do `/logout`. |
| S3  | session         | medium   | `/login`         | Cookie `remember` = `base64(username)` → forje para se passar por qualquer um. |

## Roteiro sugerido de ataque

1. **Reconhecimento:** `GET /` para endpoints, `GET /debug` → hashes MD5 (quebre `admin`).
2. **Forjar admin (sem credenciais):** monte um token `alg:none` com `role:admin`
   → `GET /admin` despeja todos os hashes (J1). Ou quebre o HMAC `secret` e
   reassine (J2).
3. **Tomada de conta:** `POST /reset-request {admin}` → token no corpo →
   `POST /reset` (A3). Ou `register role=admin` (A5).
4. **A 2FA é teatro:** o OTP é vazado e `000000` sempre funciona (A4).
5. **Persistência:** o token sobrevive ao logout (S2); forje o cookie `remember` (S3).

## Notas / projeto

- O verificador de JWT, de propósito, (a) aceita `alg:none`, (b) usa o segredo
  fraco `secret`, (c) nunca confere o `exp`.
- O banco em memória é redefinido no reinício — repovoe após os testes de tomada de conta.
- Este laboratório é focado em autenticação de propósito; os bugs clássicos de
  injeção web ficam no [Lab 01 — VulnShop](../01-vulnshop/).

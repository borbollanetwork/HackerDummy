# TrustEdge

> **VULNERÁVEL DE PROPÓSITO - somente localhost.** O TrustEdge é uma aplicação
> de treino quebrada de propósito. Todo bug é explorável por projeto. O bind é
> fixo em `127.0.0.1:18808`. Nunca a exponha a uma rede, nunca a rode numa
> máquina de que você goste, e nunca reaproveite nenhum dos seus códigos.

O TrustEdge é um pequeno "portal de conta" escrito como um **arquivo Python
único, só com a biblioteca padrão** (`http.server`, sem dependências). Todo o
tema dele é **confiar em cabeçalhos e parâmetros de requisição controlados pelo
atacante**: reflexão do `Origin` de CORS, injeção do cabeçalho `Host` /
`X-Forwarded-Host`, CRLF / divisão de resposta HTTP e uma primitiva de
envenenamento de cache web por cabeçalho fora da chave.

A aplicação finge um usuário logado (`victim`) - assume que há um cookie de
sessão presente e **não faz autenticação real**. Isso é intencional: o ponto do
laboratório são os bugs de fronteira de confiança, não o login.

## Rodar

```bash
python app.py
# -> TrustEdge escutando em http://127.0.0.1:18808/  (GET /)
```

Depois navegue / faça curl em `http://127.0.0.1:18808`. A página inicial aponta
para todo endpoint (`/profile`, `/api/account`, `/api/data`, `/reset`,
`/redirect`), então a superfície de ataque é descobrível.

## Vulnerabilidades plantadas (T1..T7)

| ID | Nome | Rota | Entrada confiada | Confirmar com curl | Impacto |
|----|------|------|------------------|--------------------|--------|
| **T1** | CORS reflete o Origin + credenciais | `GET /api/account` | Cabeçalho `Origin` (refletido literalmente) | `curl -s -i -H 'Origin: https://evil.example' http://127.0.0.1:18808/api/account` -> `Access-Control-Allow-Origin: https://evil.example` **+** `Access-Control-Allow-Credentials: true` | Qualquer site lê o JSON de conta autenticado da vítima (chave de API, ssn, saldo) entre origens, com os cookies da vítima. |
| **T2** | CORS permite a origem `null` | `GET /api/data` | Cabeçalho `Origin` (inclusive `null`) | `curl -s -i -H 'Origin: null' http://127.0.0.1:18808/api/data` -> `Access-Control-Allow-Origin: null` **+** credenciais | `Origin: null` (iframe em sandbox, documento `data:`/`file:`) contorna a verificação de origem e lê dados de negócio autenticados. Outras origens também são refletidas. |
| **T3** | Injeção de cabeçalho Host na redefinição de senha | `POST /reset` | Cabeçalho `Host` | `curl -s -H 'Host: evil.example' -d 'user=victim' http://127.0.0.1:18808/reset` -> `"link":"http://evil.example/reset-confirm?token=..."` | O atacante envenena o link de redefinição enviado à vítima; a vítima clica, o token vaza para o host do atacante -> **tomada de conta**. |
| **T4** | `X-Forwarded-Host` confiado para URLs absolutas | `GET /`, `GET /profile` | Cabeçalho `X-Forwarded-Host` (senão `Host`) | `curl -s -H 'X-Forwarded-Host: evil.example' http://127.0.0.1:18808/` -> `<link rel="canonical" href="http://evil.example/">` e os links de asset/início apontam para evil.example | Links canônicos/absolutos (SEO, carregamento de assets, fluxos estilo redefinição de senha) são redirecionados para um domínio do atacante. |
| **T5** | Injeção de CRLF / divisão de resposta HTTP | `GET /redirect?next=` | Parâmetro `next` (CR/LF não removidos) | `curl -s -i 'http://127.0.0.1:18808/redirect?next=/x%0d%0aSet-Cookie:admin=1'` -> a resposta contém o cabeçalho injetado `Set-Cookie: admin=1` | Injete cabeçalhos de resposta arbitrários (`Set-Cookie`, diretivas de cache) / divida a resposta -> fixação de sessão, XSS pelo corpo injetado, envenenamento de cache. |
| **T6** | Envenenamento de cache web por cabeçalho fora da chave | `GET /` | `X-Forwarded-Host` (fora da chave) refletido num corpo **cacheável** | `curl -s -i -H 'X-Forwarded-Host: evil.example' http://127.0.0.1:18808/` -> `evil.example` no corpo HTML **+** `Cache-Control: public, max-age=300` | A resposta é cacheável e reflete um cabeçalho fora da chave, controlado pelo atacante, em `<link canonical>` / `<script src>`; uma entrada de cache envenenada serve o host/asset do atacante a **todos** os usuários. |
| **T7** | Cabeçalhos de segurança ausentes | toda resposta | n/a (omissão) | `curl -s -I http://127.0.0.1:18808/` -> sem `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security` | Sem defesa em profundidade: clickjacking, MIME sniffing, downgrade e ataques de conteúdo refletido ficam sem mitigação. |

### Notas sobre confirmar o T5

O `http.client` / `BaseHTTPRequestHandler.send_header` pode rejeitar ou remover
CR/LF. Por isso o handler de `/redirect` escreve a linha de status e os
cabeçalhos **na mão** no socket, então um CRLF injetado em `next` divide de fato
a resposta. Na saída bruta você verá o `Set-Cookie: admin=1` do atacante como uma
linha de cabeçalho real, não como parte do valor do `Location`.

## Endpoints

| Rota | Método | Propósito |
|------|--------|-----------|
| `/` | GET | Página inicial; reflete `X-Forwarded-Host`, cacheável (T4, T6, T7). |
| `/profile` | GET | Página de perfil; links absolutos de `X-Forwarded-Host` (T4). |
| `/api/account` | GET | JSON de conta; CORS reflexivo + credenciais (T1). |
| `/api/data` | GET | JSON de negócio; CORS reflexivo inclusive `null` (T2). |
| `/reset` | GET/POST | Redefinição de senha; link montado a partir do cabeçalho `Host` (T3). |
| `/redirect` | GET | Redirecionador `next=` com injeção de CRLF (T5). |

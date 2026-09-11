# Lab 04 — ShopAPI — Resultados

Pontuação da esteira contra as 9 vulnerabilidades de API plantadas no ShopAPI
(OWASP API Top 10). O agente de exploração rodou **às cegas** — recebeu apenas uma
credencial de teste de usuário comum (`alice`/`alicepass`) e a lista de endpoints,
nunca o gabarito.

## Nota

| Passada     | Recall        | Precisão | Notas |
|-------------|---------------|----------|-------|
| Linha de base | **6/9 (67%)** | 71%     | idor/mass-assignment/no-rate-limit/ssrf/jwt classificados |
| Após correção | **9/9 (100%)**| 100%    | +2 classes de API; erro verboso modelado para toda a aplicação |

O agente às cegas confirmou **11 achados** (dividiu o JWT em alg:none +
segredo-fraco e achou um bônus de exposição de config interna) — escalando para
admin **por três caminhos independentes** (promoção BFLA, atribuição em massa,
forja de JWT) e quebrando o segredo HS256 `apisecret` no primeiro acerto da
wordlist. Zero falso positivo.

## A lacuna que este laboratório revelou

O motor tinha `idor` (cobre BOLA), `mass-assignment`, `no-rate-limit`, `ssrf`,
`jwt`, `info-disc` — mas nenhum vocabulário para duas classes centrais
específicas de API:

| Classe | CWE | Pega |
|--------|-----|------|
| `bfla` | 285 | Broken Function Level Authorization — função privilegiada chamável por usuário comum |
| `excessive-data` | 213 | Excessive Data Exposure — a API devolve campos sensíveis (hash de senha, ssn, notas internas) que um cliente nunca deveria ver |

Sem `excessive-data`, o vazamento de `/users` era pego errado por `weak-crypto`
(menciona um hash MD5). Ambas adicionadas com CVSS + ≥3 referências OWASP-API/CWE.

## Uma nuance de cobertura (erros verbosos)

O erro verboso plantado (B9) reproduz em **todo** endpoint (`/orders`, `/avatar`,
…) — é uma má configuração `DEBUG=on` de toda a aplicação, não específica de rota.
O agente às cegas o disparou em `/avatar` (não fuzzou `/orders` com corpo ruim,
embora `/orders` também dê traceback). Como a má configuração é de todo o
servidor, o gabarito modela o B9 como de nível de host (`route: "*"`) — o plugin
de fato detectou a classe. Lição registrada: fuzzar **todo** endpoint de escrita
com entrada malformada revela mais instâncias da mesma má configuração.

## Regressão

Após as adições: Lab 01 **15/15**, Lab 02 **12/12**, Lab 03 **7/7** — todos
inalterados. As novas classes são aditivas (classificação por título primeiro).

## Pontos fortes confirmados

- O ofício de controle de acesso do agente de API às cegas foi completo: BOLA em
  dois tipos de objeto, BFLA na função admin, atribuição em massa e três caminhos
  separados de escalada de privilégio — todos com prova concreta de acesso entre
  usuários / escalada.
- Ele descartou pistas falsas corretamente (assinatura de JWT adulterada
  rejeitada, `file://` bloqueado no SSRF do avatar) — zero falso positivo.

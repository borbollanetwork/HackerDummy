# Lab 08 — TrustEdge — Resultados

Pontuação do agente de referência contra 7 vulnerabilidades de **fronteira de
confiança** plantadas — bugs que vêm de confiar em cabeçalhos/parâmetros de
requisição controlados pelo atacante (CORS, Host, X-Forwarded-Host, CRLF). Rodou
**às cegas**.

## Nota

| Passada     | Recall        | Precisão | Notas |
|-------------|---------------|----------|-------|
| Linha de base | **1/7 (14%)** | 17%     | só `headers` tinha classe |
| Após correção | **7/7 (100%)**| 100%    | +4 classes de fronteira de confiança |

O agente às cegas confirmou todos os 7 com evidência bruta de cabeçalho (CORS
refletindo tanto `evil.example` quanto `Origin: null` com credenciais,
envenenamento de redefinição por cabeçalho Host, X-Forwarded-Host refletido +
cacheável e uma divisão de resposta por CRLF real injetando `Set-Cookie:
admin=1`). Zero falso positivo.

## A lacuna que este laboratório revelou

Estes são problemas clássicos, mas facilmente perdidos, de **confiança em
cabeçalho**, e o motor não tinha vocabulário para nenhum deles — os achados se
espalharam para `auth` (o envenenamento de redefinição, por "password reset"),
`creds` (CORS, por "credentials"), `session` e `other`. Adicionadas:

| Classe | CWE | Pega |
|--------|-----|------|
| `cors-misconfig` | 942 | `Access-Control-Allow-Origin` refletido/`null`/curinga (+ credenciais) |
| `host-header-injection` | 644 | Host / X-Forwarded-Host confiado em links/redirecionamentos (envenenamento de redefinição, tomada de conta) |
| `crlf` | 113 | CRLF num valor de cabeçalho → divisão de resposta HTTP / injeção de cabeçalho |
| `cache-poisoning` | 349 | cabeçalho fora da chave refletido numa resposta cacheável |

A ordem importou: `cors-misconfig` teve de ficar **antes** de `creds` (o título
diz "credentials") e `host-header-injection` **antes** de `auth` (o título diz
"password reset"), para a classe específica vencer. Tanto o `finding_model` do
plugin quanto o `harness/classify.py` autônomo do benchmark foram atualizados em
sincronia.

Repontuação: **7/7, 100%**. Regressão: labs 01-07 todos inalterados.

## Pontos fortes confirmados

- O agente às cegas leu os cabeçalhos de resposta com cuidado (esses bugs são
  invisíveis no corpo) e provou a divisão por CRLF no nível dos bytes brutos —
  exatamente o rigor que esses problemas sutis exigem.
- Ele separou corretamente os dois impactos do X-Forwarded-Host (confiança no
  cabeçalho Host vs a variante cacheável de envenenamento de cache) em achados
  distintos.

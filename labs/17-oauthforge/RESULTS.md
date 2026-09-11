# Lab 17 — OAuthForge — Resultados

O primeiro lab de **OAuth 2.0 / OIDC** — autenticação federada moderna, distinta do
SAML (Lab 16). Um servidor de autorização em Python só com a biblioteca padrão com os
erros clássicos de OAuth: um endpoint de autorização que não valida o `redirect_uri`
(roubo de código de autorização), um fluxo sem vínculo de `state` (CSRF de OAuth) e um
endpoint de token que reusa códigos, pula a autenticação do cliente e aceita um código
sem o verificador de PKCE (downgrade de PKCE).

## Método

Esteira completa; o agente de exploração rodou **às cegas**. Ele leu
`/.well-known/openid-configuration`, reconheceu o fluxo OAuth e trabalhou a checklist
de OAuth contra o servidor ao vivo: enviou um `redirect_uri` de atacante (o código foi
302 para ele), rodou o fluxo sem `state`, trocou um código sem `client_secret`,
repetiu o mesmo código por vários tokens e resgatou um código com challenge de PKCE
sem o verificador.

## Nota

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base | **2/5 (40%)** | 40% | state ausente → `other` (sem classe CSRF); falhas de token → `other`; erro verboso não disparado |
| Após correção | **5/5 (100%)** | 80% | os extras (injeção de scheme no redirect, response_type) são bônus reais, zero falso positivo |

O agente às cegas **achou toda falha de OAuth** (e extras — `redirect_uri`
`javascript:`/`data:`, response_type não validado). As lacunas foram todas de
classificação, mais uma correção de descobribilidade do laboratório.

## As lacunas que este laboratório revelou

**1. Nova classe: `csrf` (CWE-352).** O achado de `state` ausente / CSRF de OAuth não
tinha classe. Adicionada `csrf` (cross-site request forgery / token anti-CSRF ausente
/ `state` de OAuth sem validação / SameSite ausente) aos dois classificadores +
`TAXONOMY.md`. Ela é colocada **antes de `auth`**: um achado de "state ausente → CSRF
de OAuth / injeção de código de autorização" é primariamente CSRF, mas o vocabulário
de autenticação de OAuth (abaixo) de outro modo pegaria "code injection".
csrf-antes-de-auth mantém achados de CSRF como CSRF enquanto as falhas do endpoint de
token ainda caem em `auth`.

**2. `auth` agora reconhece falhas do endpoint de token OAuth.** "Authorization Code
Reuse", "PKCE Not Enforced" e "Client Authentication Not Enforced" classificavam todos
como `other`. Adicionado vocabulário de OAuth a `auth`: `pkce | code_challenge/verifier
| authorization code reuse/replay | code reuse | client authentication not enforced |
oauth downgrade/reuse/replay`. (Um desvio de assinatura SAML ainda → `auth`; o JWT do
Lab 02 fica `jwt`.)

**3. Descobribilidade do laboratório (info-disc).** O gatilho de erro verboso (um JSON
de `claims` do OIDC malformado) era ao mesmo tempo indescobrível (não anunciado) e
travado atrás de um código de autorização válido — então um fuzzer de erro sempre
batia no `invalid_grant` gracioso e concluía "debug desligado". Laboratório corrigido:
o documento de descoberta agora anuncia `claims_parameter_supported`, e o JSON de
`claims` é interpretado *antes* da validação do grant, então fuzzar o parâmetro
documentado revela o traceback de forma confiável. (Uma correção fiel — um servidor
OIDC real anuncia suporte a `claims` — não uma entrega de resposta.)

Repontuação: **5/5**, todos os 17 labs ainda 100%.

## Nota do laboratório

Em memória; nada real está em jogo. As strings de token/segredo são marcadores sem
função. Cliente registrado: `webapp`, redirect_uri `http://127.0.0.1:18817/callback`.

## Rodar

```bash
python labs/17-oauthforge/app.py        # -> http://127.0.0.1:18817
# GET /.well-known/openid-configuration ; GET /authorize ; POST /token
```

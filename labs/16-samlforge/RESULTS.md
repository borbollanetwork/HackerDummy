# Lab 16 — SamlForge — Resultados

O primeiro lab de **SSO / SAML** — autenticação federada corporativa, uma superfície
que nenhum dos 15 labs anteriores tocou. Uma imitação em Python só com a biblioteca
padrão de um Service Provider SAML 2.0 que reproduz a clássica cadeia de ataque a
SAML: um ACS que nunca verifica a assinatura da asserção (desvio de autenticação), um
parser XML com entidades externas habilitadas (XXE via o SAMLResponse) e um
RelayState sem validação (redirecionamento aberto).

## Método

O plugin rodou a esteira completa; o agente de exploração rodou **às cegas** com um
prompt guiado por metodologia (sem dica de quais ataques a SAML estavam presentes).
Ele enumerou os endpoints de SSO, puxou um SAMLResponse de exemplo de `/sso/login`,
reconheceu o fluxo SAML e trabalhou a checklist de SAML: adulterou o NameID/papel
para `admin` (aceito — `signature_verified:false`), removeu o `<ds:Signature>` por
completo (ainda aceito), injetou uma entidade externa por DOCTYPE no NameID para ler
um arquivo do servidor (XXE) e apontou o RelayState para uma URL externa (302
redirecionamento aberto). Exatamente como um SP SAML é testado.

## Nota

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base | **4/5 (80%)** | 57% | o desvio de assinatura SAML mal classificado (`jwt` / `other`) |
| Após correção | **5/5 (100%)** | 83% | os extras (asserção dupla XSW, clickjacking) são bônus reais, zero falso positivo |

O agente às cegas **achou os cinco** (mais XSW). A única lacuna foi de classificação.

## A lacuna que este laboratório revelou

**Vocabulário de desvio de autenticação SAML — e uma regex de `jwt` gulosa demais.**
O desvio de assinatura SAML ("SAML Signature Bypass — Tampered Assertion")
classificava como `jwt`, e "Signature Stripping" / "XSW" caíam em `other`. Duas
correções:

1. A classe `jwt` tinha uma alternativa `signature.*bypass` pura que pegava
   *qualquer* desvio de assinatura — inclusive SAML. Foi estreitada para
   `(jwt|token).*signature.*bypass` (problemas reais de assinatura de JWT seguem
   cobertos por `jwt.*(secret|signature|forge)`).
2. Adicionado vocabulário de SAML / assinatura XML à classe canônica `auth`:
   `saml signature/assertion bypass | signature bypass/strip/exclusion/wrapping |
   XSW | assertion forge/inject/tamper/strip | unsigned assertion`. Um desvio de
   assinatura SAML é, canonicamente, um desvio de autenticação.

Verificado: desvio/stripping/XSW de SAML → `auth`; JWT `alg:none` / HMAC fraco ainda
→ `jwt`; Lab 02 (JWT) fica em 12/12; todos os 16 labs 100%.

## Uma correção de integridade do laboratório que a execução revelou

O traceback de erro verboso (e uma leitura de código-fonte por XXE) expôs os
comentários inline do próprio laboratório — que carregavam os IDs do gabarito (`# G2:
parsed with XXE enabled`). Isso vaza o gabarito para qualquer um que fuzze o SP. Os
rótulos `Gn` foram removidos do código-fonte servido; os comentários descritivos
permanecem (um pentester os deduziria de qualquer forma).

## Nota do laboratório

A "validação" de assinatura é um no-op de propósito (só lógica de autenticação). O
XXE é genuíno, mas somente leitura. As strings com cara de segredo são marcadores sem
função.

## Rodar

```bash
python labs/16-samlforge/app.py        # -> http://127.0.0.1:18816
# GET /sso/login para um SAMLResponse de exemplo para adulterar e reenviar ao /sso/acs
```

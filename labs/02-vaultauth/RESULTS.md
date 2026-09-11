# Lab 02 — VaultAuth — Resultados

Pontuação da esteira automática de pentest contra as 12 vulnerabilidades de
autenticação / JWT / sessão plantadas no VaultAuth. O agente de exploração rodou
**às cegas** (recebeu apenas a lista de endpoints da raiz, nunca o gabarito).

## Método

Um agente de pentest de autenticação às cegas decodificou um JWT real, atacou a
assinatura (`alg:none`, quebra offline do segredo, `exp`), sondou
login/register/reset em busca de enumeração e limite de taxa, testou OTP/2FA,
atribuição em massa, armazenamento de credenciais, IDOR e comportamento de
sessão/logout — confirmando cada um com requisições ao vivo — e então o
`harness/score_lab.py` casou os achados contra o `gabarito.json` por classe + rota.

## Nota

| Passada         | Recall           | Precisão | Notas |
|-----------------|------------------|----------|-------|
| Linha de base   | **1/12 (8%)**    | 33%      | o agente achou todos os 13, o motor só sabia classificar IDOR |
| Após correção   | **12/12 (100%)** | **100%** | 8 novas classes de autenticação adicionadas |

O agente **confirmou todas as 12 plantadas** na primeira passada (ele até quebrou
o segredo HS256 `secret`, forjou `alg:none` *e* reassinou tokens de admin, tomou
contas via tokens de redefinição sequenciais e usou o código mestre de OTP
`000000`). A nota da linha de base foi 8% **não** porque a detecção falhou, mas
porque o motor de relatório **não tinha vocabulário para bugs de autenticação** —
11 dos 13 achados colapsaram em baldes genéricos `creds`/`other` e foram
deduplicados.

## A lacuna que este laboratório revelou

O `finding_model.py` classificava achados em classes de injeção web e de
exposição, mas tinha **zero classes de autenticação/JWT/sessão**. Todo achado de
autenticação caía em `other` (e se fundia num único balde), então a esteira
*achava* os bugs mas não conseguia *nomeá-los* nem *reportá-los* distintamente.

### Correção — 8 novas classes adicionadas ao motor compartilhado

| Classe | CWE | Pega |
|--------|-----|------|
| `jwt` | 347 | alg:none, segredo de assinatura fraco, validação ausente de `exp`/claim |
| `2fa-bypass` | 287 | OTP/MFA vazado, códigos mestre, segundo fator não exigido |
| `user-enum` | 204 | discrepâncias de resposta que revelam contas válidas |
| `no-rate-limit` | 307 | proteção ausente contra força bruta / credential stuffing |
| `mass-assignment` | 915 | atributos inesperados (por exemplo `role`) → escalada de privilégio |
| `weak-crypto` | 916 | armazenamento de senha em MD5/SHA1 sem sal/texto plano |
| `session` | 384 | fixação de sessão, sem invalidação no logout, tokens previsíveis |
| `auth` | 640 | recuperação de senha fraca / tomada por token de redefinição, autenticação quebrada |

Cada uma traz o próprio vetor CVSS e **≥3 referências de remediação
direcionadas** (cheat sheets da OWASP + WSTG + CWE). Repontuação: **12/12 de
recall, 100% de precisão**.

### Regressão

Repontuado o **Lab 01 — VulnShop** com o motor atualizado: ainda **15/15**, sem
regressão. As novas classes são aditivas (casadas pelo título do especialista via
o classificador por título primeiro do Lab 01).

## Pontos fortes confirmados

- O ofício do agente às cegas com JWT foi completo: decodificar → forjar
  `alg:none` → quebrar o segredo offline → reassinar → repetir com `exp`, tudo
  confirmado contra o servidor ao vivo com zero falso positivo.
- Ele encadeou primitivas corretamente (MD5 vazado → senha de admin quebrada;
  token de redefinição → tomada de conta; atribuição em massa → JWT de admin).

## Acompanhamento (registrado, ainda não feito)

- **Detecção automática.** Esses bugs são achados por teste *ativo*, então a
  correção fica na camada de classificação (feito). Uma melhoria complementar:
  fazer o reconhecimento emitir um sinal `jwt_alg` quando um Bearer/JWT é
  observado, para acionar automaticamente o `specialist-jwt-attack` existente
  (registro WEB-023). Vale ligar em seguida.
- **Cobertura da metodologia.** Confirmar que a fase de exploração do
  `droidagent-web` pede explicitamente confusão de algoritmo em JWT, desvio de
  OTP, atribuição em massa e análise de token de redefinição, para um engajamento
  real alcançar isso sem um prompt escrito à mão.

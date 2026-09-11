# Lab 10 — UploadForge — Resultados

Pontuação do plugin DroidAgent contra as 7 vulnerabilidades plantadas do
UploadForge. O plugin rodou a **esteira completa** (engage-init → passive_audit +
content_discovery → specialist_dispatcher → especialistas da Fase 4), com os
agentes de exploração **às cegas** — só alvo ao vivo + a base de conhecimento do
próprio plugin, nunca o gabarito.

## Método

Quatro especialistas da Fase 4 às cegas rodaram em paralelo (caçador de RCE,
caçador de tomada de conta/autenticação, IDOR/BFLA, injeção/lado do cliente). O
caçador de RCE — que a metodologia web manda sempre perseguir upload→webshell→RCE —
entrou com o padrão `operator:operator`, enviou um template `{{exec:…}}` (a falta
de validação o aceitou) e o renderizou para execução de comando ao vivo
(`whoami`→`eep0x10`, `id`→uid…). Todas as 7 plantadas foram confirmadas com
requisições ao vivo, mais 6 bônus genuínos (BFLA em `/render`, tokens de sessão
sequenciais previsíveis, sem limite de taxa, cookies inseguros, vazamento de token
interno, clickjacking). O `score_lab.py` casou por classe+rota.

## Nota

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base | **6/7 (86%)** | 43% | upload→RCE detectado mas **classificado `rce`**, não `upload`; um bônus caiu em `other` |
| Após correção | **7/7 (100%)** | 54% | classe upload restaurada; os bônus ganham classes canônicas. Precisão <100% = 6 bônus reais, **zero falso positivo** |

O plugin **detectou tudo na primeira passada — inclusive a cadeia completa
upload→webshell→RCE.** A lacuna foi, mais uma vez, **classificação**, não detecção.

## As lacunas que este laboratório revelou (3 correções reais no `finding_model`)

1. **`upload` precisa vencer `rce`.** O achado joia da coroa — "Unrestricted File
   Upload leading to Remote Code Execution (webshell)" — batia na regex genérica de
   `rce` (`remote code`) primeiro, porque `rce` precedia `upload` na lista de
   classes. Então a prioridade #1 de RCE do plugin era *achada mas mal
   categorizada* (e pontuada como falha). Correção: `upload` movido **antes** de
   `rce` e a regex dele ampliada para manter a classe canônica `upload` mesmo
   quando o título cita o *impacto* de RCE. Um RCE de injeção de comando puro ("OS
   Command Injection") não tem palavras de upload e ainda classifica como `rce`
   (Lab 03 inalterado). *Mesma regra de específico-antes-de-genérico que
   nosqli-antes-de-sqli.*

2. **Vocabulário de controle de acesso quebrado.** Um bônus ("Unauthenticated
   Access to Uploaded Files", "Missing Object-Level Authorization") não casava com
   classe nenhuma → `other`. Adicionada uma captura **tardia** (depois das classes
   específicas de controle de acesso e de serviço exposto, para não roubar o Lab
   06) roteando restos de missing-auth / unauthenticated-access /
   broken-access-control para o balde de acesso a objeto `idor`.

3. **Vocabulário de sessão estreito demais.** "Session Tokens **Without Expiry**
   and **No Logout** Endpoint" exigia que a regex dissesse "never expir"/"not
   invalidated" → caía em `other`. `session` ampliada para também pegar "without
   expiry / no expiry / no logout endpoint". (Cuidado tomado: não ampliar demais
   `predictable.*token`, que roubaria o "predictable password reset token" do Lab
   02 — um achado `auth` — verificado por regressão.)

Repontuação: **7/7, nenhum achado no balde `other` e sem regressão** — todos os 10
labs seguem com 100% de recall (Lab 02 de volta a 12/12 depois de a regex de
sessão ser apertada).

## A lacuna de reconhecimento/despacho que este laboratório revelou (notada, ainda não fechada)

O front-end determinístico **não** apontou para o vetor de upload sozinho: o
`content_discovery` levantou apenas os alcançáveis por GET `/myfiles` + `/render`
(os só-POST `/upload`, `/login` foram filtrados), e **não há tipo de sinal** para
"endpoint de upload de arquivo" ou "formulário de login" — então o dispatcher
emitiu apenas os especialistas passivos de clickjacking/cabeçalhos. A cadeia
upload→RCE foi carregada inteiramente pelo caçador de RCE às cegas descobrindo o
`/upload` pelo índice `/`, exatamente como a metodologia web manda. Funcionou aqui,
mas uma esteira mais robusta emitiria um sinal `file-upload-detected` /
`auth-endpoint-detected` e despacharia um especialista automaticamente em vez de
depender do especialista LLM achar o vetor. Registrado como a principal melhoria de
acompanhamento.

## Pontos fortes confirmados

- O ofício dos agentes às cegas foi completo e **encadeado**: credenciais padrão →
  autenticação → upload irrestrito → renderização no servidor → RCE, provado ao vivo.
- A segurança por projeto se manteve: a webshell executou apenas a lista de
  permissão de canários somente leitura; comandos fora do canário foram confirmados
  como capazes de RCE sem rodar.
- Entrega além do pedido, não ruído: todo achado "extra" foi uma fraqueza adicional
  real (BFLA, sessões previsíveis, sem limite de taxa, cookies inseguros, vazamento
  de token, clickjacking) — zero falso positivo.

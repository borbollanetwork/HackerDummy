# Lab 12 — CloudPivot — Resultados

O primeiro lab de **encadeamento**. Todo outro lab planta bugs independentes; aqui
os achados de alto valor são alcançáveis *apenas* explorando o passo anterior, então
o recall mede diretamente quão fundo o agente encadeou. Ele testa a metodologia em
largura do plugin, "uma primitiva é um pivô, não um endpoint" (a matriz de
tomada-de-conta/RCE da SKILL promete explicitamente SSRF→IMDS→role→RCE — nunca
medida até aqui).

```
(K1) SSRF /fetch?url=   --lista de bloqueio fraca, 169.254.169.254 passa-->
   (K2) pivô para o IMDS da nuvem -> rouba credenciais da role da instância (AccessKey/Token) -->
      (K3) reusa o Token vazado como Bearer em /internal/admin -> injeção de comando do sistema -> RCE
```

O plugin rodou a **esteira completa**, com os agentes de exploração **às cegas** — e
os prompts deliberadamente **não** revelaram a cadeia (sem menção ao IMDS, ao token
ou à junção com o RCE). A base de conhecimento teve de conduzir os pivôs.

## Resultado: o plugin encadeou o caminho inteiro

Dois especialistas independentes às cegas (SSRF e controle de acesso/RCE)
**completaram cada um os três saltos** — desvio da lista de bloqueio do SSRF → roubo
de credencial no IMDS `169.254.169.254` → Token de sessão do IMDS reusado como
Bearer → RCE por injeção de comando como o usuário do host. Este é o resultado de
destaque: a metodologia em largura conduziu a cadeia até o fim sem nenhuma dica do
gabarito. (Seguro para lab: só um canário somente leitura roda de fato; as
credenciais do IMDS são marcadores sem função.)

## Nota

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base | **3/5 (60%)** | 60% | cadeia completa, mas o roubo de credencial do IMDS classificado como `ssrf` (deduplicado em K1); o traceback de porta malformada nunca foi fuzzado |
| Após correção | **5/5 (100%)** | 71% | os extras (clickjacking, versão) são bônus reais, zero falso positivo |

## As lacunas que este laboratório revelou

**1. Roubo de credencial de nuvem não tinha classe própria (correção no
finding_model).** Os especialistas roubaram as credenciais da role da instância do
IMDS, mas todo achado desses era intitulado "SSRF → IMDS Credential Theft", então
todos classificavam como `ssrf` e eram deduplicados no achado da porta de entrada —
K2 (`creds`) não tinha casamento. Adicionada uma entrada de credencial de nuvem
**antes** de `ssrf`: títulos que mencionam IMDS / instance metadata /
metadata-credential / `169.254.169.254` / security-credentials / credential
theft|exfil classificam como `creds` (a divulgação de credencial é o resultado mais
específico e de maior impacto). Achados de SSRF puro ("blocklist bypass", "scheme
validation") não têm linguagem de credencial e ainda classificam como `ssrf` (K1).
Mesma regra de causa-raiz-vs-impacto do upload-antes-de-rce. Sem regressão.

**2. O fuzzing de erro nunca tentou estrutura de URL malformada (correção de
conhecimento — uma lacuna de DETECÇÃO, não de classificação).** Esta é a primeira
falha da campanha que não foi problema de nomear: o especialista de má configuração
fuzzou `file://` / `://broken` / sem-scheme mas nunca uma *porta* malformada, então
perdeu o traceback verboso (K4). Reforçado o
`knowledge/web/03-Access-Control/Info Disclosure.md`: quando um parâmetro vira uma
URL no servidor (SSRF/fetch/webhook/preview), fuzze a **estrutura** da URL — porta
ruim (`host:notaport`), porta fora do intervalo, colchete de IPv6 não fechado, host
vazio, scheme ruim — para levar o parser a um stack trace. Rerrodado o especialista
às cegas: ele leu o conhecimento atualizado, fuzzou `?url=http://host:notaport/` e
recuperou o traceback completo → K4 achado, **5/5**.

## Por que o projeto da cadeia mede o encadeamento

K2 e K3 são inalcançáveis sem explorar K1 (e K2): o IMDS não é diretamente
alcançável pelo atacante, e `/internal/admin` devolve 401 sem o Token que só o pivô
SSRF→IMDS produz. Um scanner que trata endpoints de forma independente enxerga só o
SSRF e para em recall 1/5. Alcançar K3 (RCE) é em si a prova de que o agente
encadeou SSRF→IMDS→RCE.

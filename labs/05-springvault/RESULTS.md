# Lab 05 — SpringVault — Resultados

Pontuação da esteira contra um alvo **Java/Spring Boot** (uma stack não Python) —
7 problemas de actuator/interface de gerenciamento plantados. Este laboratório
exercita especificamente **detecção de stack → emissão de sinal → mineração de
segredos**, não só a classificação.

## O que este laboratório validou (esteira de reconhecimento)

Rodando o `content_discovery.py` real contra a imitação:
- **Detecção de stack:** `stack=java` inferido corretamente pelo corpo da
  Whitelabel Error Page (sem JVM, sem entrega pelo cabeçalho de servidor).
- **Descoberta de caminhos:** todos os endpoints `/actuator/*` + `/jolokia` +
  `/h2-console` achados pelos STACK_PATHS de java.
- **Emissão de sinal:** **11 sinais** dispararam — `actuator-env-exposed`,
  `actuator-heapdump-exposed`, `jolokia-exposed`, `h2-console-exposed`,
  `spring-actuator-exposed` — que roteiam para `specialist-actuator-mine` /
  `specialist-jolokia-rce` / `specialist-h2-rce` no registro.

Então a cadeia **detectar → sinalizar → despachar** para uma stack Java/Spring
funciona de ponta a ponta. Essa parte não precisou de correção.

## Nota

| Passada     | Recall        | Precisão | Notas |
|-------------|---------------|----------|-------|
| Linha de base | **5/7 (71%)** | 75%     | actuator/creds/info-disc classificados |
| Após correção | **7/7 (100%)**| 100%    | classe actuator ampliada + repriorizada |

O agente às cegas minerou tudo (segredos do env, heapdump → **token de sessão
Bearer de admin ao vivo** + flag, superfícies de RCE por jolokia/h2 confirmadas).
Zero falso positivo.

## A lacuna que este laboratório revelou

Os dois achados de superfície de RCE — Jolokia e console H2 — foram intitulados
"…(RCE surface)" pelo agente e classificados como **`rce`** genérico em vez da
classe de interface de gerenciamento, porque: (1) a regex de `actuator` exigia as
formas com barra `/jolokia` / `/h2-console`, e (2) `rce` era checado *antes* de
`actuator`, então a palavra "RCE" no título vencia.

Correção (motor):
- **`actuator` ampliado** para casar `jolokia`, `h2[-/espaço]console`, `jmx` e
  `heapdump` como palavras soltas (não só caminhos com barra), e rerrotulado como
  "Java/Spring management interface (Actuator/Jolokia/H2)".
- **`actuator` reordenado** *acima* de `rce` no classificador, para a classe
  **específica** de interface de gerenciamento vencer a classe genérica de RCE
  nesses achados (o RCE é o *impacto*; a interface exposta é a *classe*).

Repontuação: **7/7, 100% de precisão**. Regressão: labs 01-04 todos inalterados
(15/15, 12/12, 7/7, 9/9) — `rce` ainda classifica "OS Command Injection" puro.

## Pontos fortes confirmados

- Stack Java/Spring tratada sem suposições específicas de Python: detecção de
  impressão digital, descoberta de caminhos do actuator, emissão de sinal e
  mineração de segredos no heap dump, tudo funcionou.
- O agente recuperou um token de sessão de admin ao vivo do heap dump — o butim
  de maior impacto — e escopou corretamente o RCE por jolokia/h2 como
  *exposição confirmada, não detonada* (disciplina de zero falso positivo).

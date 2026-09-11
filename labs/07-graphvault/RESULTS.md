# Lab 07 — GraphVault — Resultados

Pontuação da esteira contra uma API GraphQL com 8 vulnerabilidades plantadas. O
agente rodou **às cegas** — recebeu apenas o endpoint `/graphql` (que o
reconhecimento minerou do índice JSON), nunca o gabarito.

## Nota

| Passada     | Recall        | Precisão | Notas |
|-------------|---------------|----------|-------|
| Linha de base | **6/8 (75%)** | 86%     | idor/excessive-data/bfla/no-rate-limit/sqli/info-disc classificados |
| Após correção | **8/8 (100%)**| 100%    | +2 classes (graphql, dos) |

O agente às cegas confirmou todos os 8 (dump do schema por introspecção, BOLA,
exposição excessiva da tabela inteira, `makeAdmin` por BFLA, força bruta por alias
em batch, query com profundidade 16 → resposta de 3,6 MB, SQLi pelo argumento
`filter` do `search`, vazamento por sugestão de campo). Zero falso positivo.

## A lacuna que este laboratório revelou

O motor já cobria os bugs *agnósticos de transporte* que aparecem em GraphQL
(BOLA→`idor`, BFLA→`bfla`, exposição excessiva→`excessive-data`, batching→
`no-rate-limit`, argumento→`sqli`, erros verbosos→`info-disc`). Os dois problemas
**com formato de GraphQL** não tinham lar:

| Classe | CWE | Pega |
|--------|-----|------|
| `graphql` | 200 | introspecção habilitada, exposição de schema, má configuração específica de GraphQL |
| `dos` | 400 | consumo descontrolado de recursos — profundidade/complexidade de query, amplificação, limites ausentes |

Ambas mantidas de propósito **estreitas** para não roubar as vizinhas: a regex de
`graphql` casa só introspecção/`__schema` (não "batching", então o achado de
força bruta em batch fica `no-rate-limit`), e nenhuma toca no achado de sugestão
de campo (fica `info-disc`). Repontuação: **8/8, 100%**.

## Uma regressão que o harness pegou antes de publicar

A primeira tentativa da classe `dos` referenciava o prefixo de URL de nível de
módulo `_CS` **dentro da lista CLASSES** — mas `_CS` é definido mais adiante no
arquivo, então importar o `finding_model` levantava `NameError` e o
`build_findings` caía em silêncio no parser legado. A varredura de regressão da
campanha inteira sinalizou na hora: **os sete labs caíram para 0%** numa única
execução. Corrigido (URL literal na referência inline) e reverificado. Um motor de
classificação quebrado teria degradado *todo engajamento real* — o ciclo do
gabarito o pegou em segundos. Essa rede de segurança é grande parte do motivo de
esta campanha existir.

## Regressão

Após a correção: labs 01-06 todos inalterados (15/15, 12/12, 7/7, 9/9, 7/7, 8/8).

## Pontos fortes confirmados

- O reconhecimento minerou o `/graphql` do índice JSON (sem precisar de acerto de wordlist).
- O agente às cegas demonstrou ofício real de GraphQL: mapeamento de schema
  guiado por introspecção, batching por alias, amplificação exponencial por
  profundidade e injeção por um argumento tipado.

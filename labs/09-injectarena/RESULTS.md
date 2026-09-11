# Lab 09 — InjectArena — Resultados

Pontuação do plugin DroidAgent contra as 5 vulnerabilidades de injeção além de SQL
do InjectArena. Os agentes de exploração rodaram **às cegas** (alvo ao vivo + base
de conhecimento do plugin, nunca o gabarito).

## Método

Especialistas de injeção às cegas testaram cada endpoint e confirmaram todos os
cinco com payloads ao vivo: injeção de operador NoSQL (desvio de autenticação por
`$ne`) em `/login`, injeção de LDAP em `/directory`, injeção de XPath em
`/employee`, injeção de SSI em `/greet` e injeção de CSV / fórmula em `/export`. O
`score_lab.py` casou por classe + rota.

## Nota

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base | **0/5 (0%)** | — | o plugin **detectou todos os cinco** mas não tinha classe para nomeá-los → todos caíram em `sqli`/`other` |
| Após correção | **5/5 (100%)** | — | cinco classes de injeção dedicadas adicionadas |

## A lacuna que este laboratório revelou

O plugin *conhecia* essas técnicas (a base de conhecimento documenta injeção de
NoSQL/LDAP/XPath/SSI/CSV) mas o motor de relatório **não tinha classe canônica**
para nenhuma delas, então não conseguia nomear o que achava. Adicionadas 5 classes
ao `finding_model.py` **e** ao `classify.py` do benchmark:

| Classe | CWE | Nota |
|--------|-----|------|
| `nosqli` | 943 | **precisa preceder `sqli`** — "NoSQL Injection" contém "sql inj" |
| `ldap-injection` | 90 | |
| `xpath-injection` | 643 | |
| `ssi-injection` | 97 | server-side includes / ESI |
| `csv-injection` | 1236 | injeção de fórmula / planilha |

A ordem importa: `nosqli` é colocada **antes** de `sqli` para a classe mais
específica vencer. Repontuação: **5/5**, sem regressão nos outros labs. Mesmo
padrão de todo outro laboratório — **a detecção foi completa; a lacuna foi
vocabulário de classificação.**

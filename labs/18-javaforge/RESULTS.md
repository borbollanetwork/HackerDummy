# Lab 18 — JavaForge — Resultados

Uma aplicação Java / Apache Tomcat (imitação em Python só com a biblioteca padrão)
centrada em **desserialização nativa do Java** — a aplicação devolve e aceita um
objeto serializado em base64 `rO0AB...` no cookie `JSESSIONOBJ` e no `/api/restore`,
então uma cadeia de gadgets do ysoserial alcança RCE. Mais credenciais padrão do
Tomcat-manager, stack traces Java verbosos e um banner de Tomcat/Java em fim de vida.

## Nota

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base | **3/5 (60%)** | 43% | achado de credenciais padrão do Tomcat classificado `rce`; achado de versão/fim de vida classificado `eol` (o gabarito dizia `version`) |
| Após correção | **5/5 (100%)** | — | os extras são bônus reais, zero falso positivo |

O especialista Java às cegas achou tudo: reconheceu o cookie de sessão `rO0AB` como um
objeto serializado do Java, enviou um gadget CommonsCollections6 tanto para
`/api/whoami` (cookie) quanto para `/api/restore` (corpo) confirmando a capacidade de
RCE, usou as credenciais padrão do Tomcat-manager, disparou o stack trace Java e
sinalizou o Tomcat 7.0.42 / Java 1.8 em fim de vida com as CVEs de desserialização
dele.

## A lacuna que este laboratório revelou

**`rce` precisa ser a ÚLTIMA classe de impacto (a generalização concluída).** O achado
"Tomcat Default Credentials → WAR deploy → RCE" era roubado por `rce` porque o título
menciona RCE — mas a causa raiz dele é `default-creds`. É a mesma regra de
causa-raiz-vs-impacto do upload/lfi/deser antes de rce; o AspNetVault (Lab 13) moveu
`rce` para depois das classes de *injeção*, mas as classes de acesso/configuração
(default-creds, exposed-service, actuator, admin-panel) ainda estavam abaixo dele.
`rce` movido para ser a **última classe de impacto** (depois de toda causa raiz
específica que pode levar a RCE). Agora "Tomcat default creds → RCE" → `default-creds`,
"exposed Redis → RCE" → `exposed-service`, "actuator → RCE" → `actuator`, enquanto "OS
Command Injection" ainda → `rce`. Sem regressão nos 18 labs.

Também: a classe do gabarito de M4 foi corrigida de `version` → `eol` — o achado é
fundamentalmente sobre uma stack Tomcat/Java em fim de vida (o banner é como se
detecta).

## Nota do laboratório

Isto é uma imitação em Python da superfície Java. Nada de Java é
desserializado/executado — o endpoint reconhece o magic do stream `AC ED 00 05` e uma
cadeia de gadgets do ysoserial e reporta como capaz de RCE sem rodar nada. As strings
com cara de segredo são marcadores sem função.

## Rodar

```bash
python labs/18-javaforge/app.py        # -> http://127.0.0.1:18818
```

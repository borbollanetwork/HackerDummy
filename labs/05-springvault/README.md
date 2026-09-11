# Lab 05 — SpringVault

> ⚠️ **VULNERÁVEL DE PROPÓSITO — TREINO SOMENTE EM LOCALHOST.** Escuta em `127.0.0.1`.

## O que é

O **SpringVault** é uma **imitação fiel, só com a biblioteca padrão, de uma
aplicação Java/Spring Boot** com os endpoints do **Actuator** expostos — a
clássica má configuração do mundo real
(`management.endpoints.web.exposure.include=*`). Não precisa de JVM: reproduz as
impressões digitais do Spring (a Whitelabel Error Page, o cabeçalho
`X-Application-Context`, os stack traces Java) e os endpoints de gerenciamento
perigosos, então uma esteira de **detecção de stack → emissão de sinal do
actuator → mineração de segredos** pode ser exercitada de ponta a ponta contra
uma stack "não Python". Roda em `127.0.0.1:18805`.

## Como rodar

```bash
python app.py        # -> http://127.0.0.1:18805
```

`GET /` devolve uma Whitelabel Error Page do Spring (a impressão digital).
`GET /actuator` lista os endpoints de gerenciamento expostos.

## Vulnerabilidades plantadas

Gabarito: [`gabarito.json`](gabarito.json). 7 problemas, 1 ponto cada.

| ID  | Classe    | Sev      | Rota                 | O quê |
|-----|-----------|----------|----------------------|------|
| SP1 | actuator  | high     | `/actuator`          | Listagem de endpoints de gerenciamento exposta, sem autenticação. |
| SP2 | actuator  | critical | `/actuator/env`      | Segredos de configuração em texto claro: senha do datasource, segredo do JWT, chaves Stripe/AWS. |
| SP3 | actuator  | critical | `/actuator/heapdump` | `.hprof` baixável → minere a memória em busca de segredos de runtime (senha do banco, JWT, **token de sessão Bearer do admin**). |
| SP4 | actuator  | critical | `/jolokia`           | JMX sobre HTTP exposto → leitura/invocação de MBean (logback `reloadByURL` → superfície de RCE por JNDI/deser). |
| SP5 | actuator  | high     | `/h2-console`        | Console web do H2 alcançável → URL JDBC controlável → RCE por `CREATE ALIAS`/`RUNSCRIPT`. |
| SP6 | creds     | critical | `/actuator/env`      | O butim de fato: credenciais de produção reaproveitáveis em outros lugares. |
| SP7 | info-disc | medium   | `*`                  | A página Whitelabel + os stack traces Java vazam o Spring Boot **2.6.6** e pacotes internos. |

## Roteiro sugerido de ataque

1. **Impressão digital:** `GET /` → "Whitelabel Error Page" + "Spring Boot 2.6.6" ⇒ Java/Spring.
2. **Enumerar gerenciamento:** `GET /actuator` → env, heapdump, mappings, …
3. **Roubar configuração:** `GET /actuator/env` → senha do banco, segredo do JWT, chaves de API.
4. **Minerar memória:** `GET /actuator/heapdump` → grep nos bytes → token de sessão do admin.
5. **Superfícies de RCE:** `/jolokia` (JMX→reloadByURL) e `/h2-console` (URL JDBC).

## Notas / projeto

- Esta imitação existe para testar **detecção de stack + mineração de actuator**
  numa stack não Python sem uma JVM. A esteira detecta `stack=java` pelo corpo da
  Whitelabel e sonda automaticamente os caminhos `/actuator/*` + `/jolokia`.
- Valores com cara de segredo (Stripe/AWS) são marcadores sem função de propósito.

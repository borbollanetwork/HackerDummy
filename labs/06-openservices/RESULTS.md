# Lab 06 — OpenServices — Resultados

Pontuação da esteira contra um host que expõe 8 serviços de rede mal configurados
(infraestrutura, não web). O agente rodou **às cegas**, restrito às 8 portas do
laboratório no escopo (o SMB/445 real do host ficou explicitamente fora de escopo
e intocado).

## O que este laboratório validou (reconhecimento de infraestrutura)

O `service_scan.py` contra `127.0.0.1` conectou nas portas de serviço padrão e
emitiu os sinais certos por serviço — `redis-exposed`, `elastic-exposed`,
`mongodb-exposed`, `couchdb-exposed`, `docker-exposed`, `memcached-exposed`,
`mysql-exposed`, `http-alt-port` (e corretamente também sinalizou o
`smb-exposed` real do host na 445, que mantivemos fora de escopo). A etapa de
varredura de portas de infraestrutura + banner + sinal funciona.

## Nota

| Passada     | Recall        | Precisão | Notas |
|-------------|---------------|----------|-------|
| Linha de base | **0/8 (0%)**  | 0%      | NENHUM vocabulário de infraestrutura |
| Após correção | **8/8 (100%)**| 100%    | +2 classes de infraestrutura |

O agente às cegas confirmou todos os 8 (Redis 2.8.0 sem autenticação,
Elasticsearch 1.4.2 sem autenticação, MongoDB sem autenticação, CouchDB admin
party, Docker API 19.03.5 sem TLS, Memcached 1.4.15, MySQL 5.5.62 em fim de vida e
o `admin/admin` do painel admin). Zero falso positivo, todos os vetores de RCE
documentados como teóricos (não detonados).

## A lacuna que este laboratório revelou — a maior até aqui

O recall da linha de base foi **0%**. O motor **não tinha classe para serviço de
rede exposto nem para credenciais padrão**, então os oito achados se espalharam
para os baldes errados — "Exposed Redis" → `rce` (o corpo menciona RCE por cron),
"Exposed MySQL" → `sqli`/`other`, "Default credentials" → `creds`. A detecção foi
perfeita; a classificação, ausente.

Correção (motor):

| Classe | CWE | Pega |
|--------|-----|------|
| `exposed-service` | 306 | Redis/Elastic/Mongo/CouchDB/Docker/Memcached/MySQL/… alcançável sem autenticação (autenticação ausente numa função crítica) |
| `default-creds` | 1392 | credenciais padrão/nunca trocadas (`admin/admin`, root sem senha, …) |

`default-creds` foi colocada **antes** de `creds` no classificador, porque
"Default **credential**s" seria de outro modo pega pela classe genérica de
exposição de credencial. Ambas trazem CVSS + ≥3 referências de endurecimento
(OWASP/CIS/CWE).

Repontuação: **8/8, 100% de precisão**. Regressão: labs 01-05 todos inalterados.

## Pontos fortes confirmados

- O subsistema de infraestrutura (`service_scan`) fez a impressão digital de todo
  serviço e emitiu sinais corretos num host multiserviço.
- O agente às cegas pegou toda versão, confirmou toda condição de sem
  autenticação/credencial padrão e respeitou o escopo (nunca tocou no serviço SMB
  real) — uma demonstração limpa de teste de infraestrutura autorizado e escopado.

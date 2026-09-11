# Lab 06 — OpenServices

> ⚠️ **VULNERÁVEL DE PROPÓSITO — SOMENTE LOCALHOST.** Todo listener escuta em
> `127.0.0.1`. Nunca exponha isto numa interface real.

## O que é

O **OpenServices** é um host único que expõe descuidadamente uma frota de
serviços de dados e infraestrutura nas suas **portas padrão**, cada um **sem
autenticação** (ou com **credenciais padrão** triviais) — a clássica má
configuração do "serviço interno deixado aberto à rede", que transforma um ponto
de apoio em comprometimento total.

É um **arquivo Python único, só com a biblioteca padrão** (`app.py`): nenhum
Redis, Mongo, Elasticsearch, Docker etc. é instalado. Cada serviço é um pequeno
listener multithread que fala o suficiente do próprio protocolo para um
**capturador de banner** e um **cliente curioso** confirmarem a exposição —
`PING`→`+PONG`, strings de versão, enquadramento RESP/texto, um handshake de
MySQL cuja parte legível carrega a versão em fim de vida, JSON com cara real para
as APIs HTTP etc.

Serviços expostos (todos sem autenticação, salvo indicação):

- **Redis** 2.8.0 — sem autenticação
- **Elasticsearch** 1.4.2 — sem autenticação, em fim de vida/desatualizado (era do RCE por Groovy)
- **MongoDB** — sem autenticação
- **CouchDB** 1.6.0 — "admin party" (admins vazios → todo mundo é admin)
- **Docker Engine API** 19.03.5 — sem TLS, sem autenticação
- **Memcached** 1.4.15 — sem autenticação
- **MySQL** 5.5.62 — em fim de vida, alcançável na rede
- **Painel admin HTTP** — aceita as credenciais padrão `admin:admin`

## Como rodar

```bash
python app.py
```

Cada listener primeiro checa que a porta está livre, define `SO_REUSEADDR` e roda
na própria thread daemon. Uma **falha de bind imprime um aviso e é pulada** (o
laboratório nunca trava). Na inicialização imprime um resumo de quais portas
subiram, por exemplo:

```
=== Startup summary ===
  [BOUND ] I1  6379   Redis (no auth)
  [BOUND ] I2  9200   Elasticsearch 1.4.2 (no auth)
  ...
8/8 services listening. Ctrl+C to stop.
```

Se uma porta já estiver ocupada na sua máquina (por exemplo, você realmente roda
Redis), aquela linha mostra `[SKIP ]` e o resto sobe mesmo assim.

## Serviços expostos

Gabarito: [`gabarito.json`](gabarito.json). 8 problemas, 1 ponto cada.

| ID  | Porta | Serviço | Por que é perigoso | Como confirmar |
|-----|-------|---------|--------------------|----------------|
| I1  | 6379  | **Redis** (sem autenticação) | Leitura/escrita sem autenticação de todas as chaves; RCE gravando cron jobs, módulos ou um `authorized_keys` de SSH via `CONFIG SET dir` + `SAVE`. | `redis-cli -h 127.0.0.1 PING` → `PONG`; `INFO` → `redis_version:2.8.0` **sem exigir AUTH**. Cru: `printf 'PING\r\n' \| nc 127.0.0.1 6379` → `+PONG`. |
| I2  | 9200  | **Elasticsearch** 1.4.2 (sem autenticação) | Dump completo do índice sem autenticação; a linha 1.4.x é a era do RCE por bypass de sandbox do Groovy (**CVE-2015-1427**). | `curl 127.0.0.1:9200/` → `"number":"1.4.2"`; `curl 127.0.0.1:9200/_cat/indices` lista um índice **`secrets`**. |
| I3  | 27017 | **MongoDB** (sem autenticação) | Banco sem autenticação — despeje/modifique toda coleção. | `mongo 127.0.0.1:27017` → `show dbs`. Lab: ao conectar imprime `MongoDB server (no auth)`, então a porta aberta é inconfundível. |
| I4  | 5984  | **CouchDB** 1.6.0 (admin party) | Config de `admins` vazia → **toda requisição é admin**; crie um admin / priv-esc **CVE-2017-12635** → RCE. | `curl 127.0.0.1:5984/` → `"couchdb":"Welcome"`; `curl 127.0.0.1:5984/_all_dbs` → `["_users","_replicator","secrets"]`. |
| I5  | 2375  | **Docker Engine API** (sem TLS) | Socket do daemon sem autenticação sobre TCP = **RCE trivial no host**: rode um container que faz bind-mount da raiz do host (`-v /:/host`). | `curl 127.0.0.1:2375/version` → `"Version":"19.03.5"`; `curl 127.0.0.1:2375/info` → `prod-docker-01`. |
| I6  | 11211 | **Memcached** 1.4.15 (sem autenticação) | Leia segredos em cache (tokens de sessão, resultados de query); historicamente abusado para reflexão/amplificação por UDP. | `printf 'stats\r\n' \| nc 127.0.0.1 11211` → `STAT version 1.4.15`; `printf 'version\r\n'` → `VERSION 1.4.15`. |
| I7  | 3306  | **MySQL** 5.5.62 (fim de vida) | Banco alcançável na rede numa versão em **fim de vida** → força bruta de `root`, webshell por `INTO OUTFILE`, CVEs conhecidas. | Captura de banner: `recv(160)` na conexão contém `5.5.62`; `mysql -h 127.0.0.1 -u root`. |
| I8  | 8080  | **Painel admin** (credenciais padrão) | Dashboard admin HTTP protegido só por **credenciais padrão** `admin:admin`. | `curl 127.0.0.1:8080/admin` → `401` + `WWW-Authenticate: Basic`; `curl -u admin:admin ...` → `200` dashboard admin. Cabeçalho Server `Apache/2.2.15` (antigo). |

## Roteiro sugerido de ataque

1. **Varredura / captura de banner** do host → oito portas de serviço padrão respondem.
2. **Redis (I1):** `INFO`, `CONFIG GET dir`, `KEYS *` sem AUTH → dump de chaves,
   depois o clássico RCE por primitiva de escrita.
3. **Elasticsearch (I2):** `_cat/indices` → `secrets`; `_search` despeja dados; a
   versão 1.4.2 é a janela do RCE por Groovy.
4. **MongoDB (I3) / CouchDB (I4):** banco aberto / admin party → despeje ou crie admin.
5. **Docker (I5):** a joia da coroa — `2375` sobre HTTP puro é **RCE no host**.
6. **Memcached (I6):** `stats`/`get` → tokens em cache.
7. **MySQL (I7):** banner em fim de vida `5.5.62` → força bruta / `INTO OUTFILE`.
8. **Painel admin (I8):** tente `admin:admin` → dentro.

## Notas / projeto

- Esta imitação existe para exercitar a **detecção de serviço de infraestrutura +
  emissão de sinal de serviço exposto / credencial padrão** sem instalar nenhum
  dos daemons reais.
- O listener do MongoDB emite um banner legível de laboratório em vez do
  protocolo binário real, de propósito, para a porta aberta ser trivialmente
  identificável.
- Valores com cara de segredo (senhas, `flag{...}`) são marcadores falsos de
  propósito, só para treino.

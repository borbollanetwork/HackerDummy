# Lab 03 — RelayKit

> ⚠️ **VULNERÁVEL DE PROPÓSITO — TREINO SOMENTE EM LOCALHOST.**
> Bugs reais de exploração no lado do servidor, de propósito. Escuta em `127.0.0.1`.

## O que é

O **RelayKit** é um "gateway de integração" interno falso para praticar
**exploração no lado do servidor**: SSRF, XXE, desserialização insegura, injeção
de comando do sistema, travessia de caminho/LFI e SSTI. Arquivo Python único e
autocontido, só com a biblioteca padrão. Roda em `127.0.0.1:18803`.

### Segurança por projeto

Para o laboratório não danificar o host e ainda ser fiel, as duas primitivas mais
perigosas são confirmáveis mas neutralizadas:

- **`/restore` (desserialização)** resolve o gadget malicioso do pickle —
  comprovando o bug — mas **se recusa a executá-lo** (reporta `resolved_gadget` no lugar).
- **`/ping` (injeção de comando)** executa apenas uma **lista de permissão de
  canários somente leitura** (`whoami`/`hostname`/`id`/`ver`/`echo`); qualquer
  outra coisa é interceptada.
- **`/render` (SSTI)** vaza dados por injeção de format-string; não executa.

As primitivas de SSRF, XXE e LFI são genuínas (divulgação somente leitura).

## Como rodar

```bash
python app.py        # -> http://127.0.0.1:18803
```

Sem dependências. `GET /` lista os endpoints. Há um endpoint só de servidor
`/internal/secrets` (recusa chamadores fora do loopback) que os bugs de SSRF/XXE
devem alcançar.

## Vulnerabilidades plantadas

Gabarito: [`gabarito.json`](gabarito.json). 7 vulnerabilidades, 1 ponto cada.

| ID  | Classe          | Sev      | Rota           | Como explorar |
|-----|-----------------|----------|----------------|----------------|
| SS1 | ssrf            | high     | `/fetch?url=`  | O servidor busca qualquer URL → alcança `/internal/secrets` (senha do banco, chave AWS, token). Também aceita `file://` → leitura de arquivo local. |
| SS2 | ssrf            | high     | `/preview?url=`| O mesmo, mas atrás de uma lista de bloqueio de `127.0.0.1`/`localhost` **sensível a maiúsculas** → contorne com `http://LocalHost:18803/internal/secrets`. |
| XX1 | xxe             | high     | `/import-xml`  | XML interpretado com entidades externas habilitadas → `<!ENTITY x SYSTEM "file:///…/secret.txt">` lê arquivos locais (e SSRF via entidades SYSTEM `http`). |
| DS1 | deserialization | critical | `/restore`     | base64 → `pickle.loads` da entrada do atacante. Um gadget `__reduce__`→`os.system` é resolvido (RCE num deploy real; execução bloqueada aqui por segurança). |
| RC1 | rce             | critical | `/ping?host=`  | `host` concatenado num comando de shell → `?host=x;whoami` roda o canário e devolve a saída. |
| LF1 | lfi             | high     | `/download?file=` | Caminho unido a `files/` sem normalização → `?file=../secret.txt` (ou `../../…`) lê arquivos arbitrários. |
| ST1 | ssti            | high     | `/render?name=`| `name` concatenado num template `.format()` → `?name={config[SECRET_KEY]}` vaza o segredo da aplicação. |

## Roteiro sugerido de ataque

1. **Mapear o interno:** SSRF em `/fetch` → `/internal/secrets` despeja banco/AWS/token.
2. **Vencer o filtro:** `/preview` bloqueia `127.0.0.1`; envie `LocalHost`
   (maiúscula) para alcançar o mesmo endpoint interno.
3. **Ler o disco:** XXE em `/import-xml` e travessia em `/download` leem ambos o
   `secret.txt`; `/fetch?url=file://…` faz o mesmo via SSRF.
4. **Execução de código:** injeção de comando em `/ping`; desserialização
   insegura em `/restore` (gadget resolvido).
5. **Vazar configuração:** SSTI em `/render` imprime `SECRET_KEY`.

## Notas / projeto

- O `/internal/secrets` impõe uma verificação de loopback para o SSRF fazer
  sentido (um atacante externo não o alcança diretamente — só *através* do gateway).
- Arquivos do laboratório (`secret.txt`, `files/report.txt`) são criados no
  primeiro início.
- Injeção web clássica fica no [Lab 01](../01-vulnshop/); autenticação/JWT no
  [Lab 02](../02-vaultauth/).

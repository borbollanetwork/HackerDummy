# Lab 11 — LegacyPortal (PHP) — Resultados

Pontuação do plugin DroidAgent contra as 6 vulnerabilidades plantadas do
LegacyPortal. O plugin rodou a **esteira completa** (engage-init → passive_audit +
content_discovery → specialist_dispatcher → especialistas da Fase 4), com os
agentes de exploração **às cegas** — só alvo ao vivo + a base de conhecimento do
próprio plugin, nunca o gabarito. É o primeiro lab PHP; exercita a maquinaria de
wrappers de LFI (php://filter, travessia, poliglota upload→LFI→RCE) que o plugin
documenta mas que nenhum lab tinha medido.

## Método

Quatro especialistas da Fase 4 às cegas (LFI/RCE, upload, autenticação, info-disc).
Eles confirmaram toda plantada com requisições ao vivo: divulgação do código-fonte
de `config.php` por php://filter (credenciais do banco + flag), travessia com `../`
lendo arquivos do host, um upload poliglota GIF89a/MIME incluído via LFI para
executar PHP arbitrário (`php_uname()`, `7*7=49` — RCE; a execução do sistema é
neutralizada pelo `disable_functions` do motor, então o host está seguro),
exposição de phpinfo, desvio de autenticação por type juggling do PHP (`key=0e1` /
`key=0`), divulgação de caminho por erro verboso e cabeçalhos ausentes.

## Nota

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base | **4/6 (67%)** | 40% | LFI achado mas com rota incompatível; type-juggling roubado por `admin-panel` |
| Após correção | **6/6 (100%)** | 60% | precisão <100% = bônus reais (cadeia de RCE, risco de SSRF por allow_url_fopen, versão, clickjacking), zero falso positivo |

O plugin **detectou tudo às cegas na primeira passada** — inclusive a cadeia
completa upload→LFI→RCE. A lacuna foi, de novo, **classificação + encanamento do
reconhecimento**, não detecção.

## As lacunas que este laboratório revelou

**1. `auth` não tinha vocabulário para desvio de autenticação / type juggling
(correção no finding_model).** O achado de type-juggling foi intitulado "PHP Type
Juggling Authentication Bypass — Admin Panel", então foi roubado pela classe
`admin-panel` (o título contém literalmente "Admin Panel"). A classe `auth` só sabia
das formas de redefinição/recuperação de senha. Adicionado `authentication bypass |
auth bypass | login bypass | type juggling | magic hash | loose comparison` a `auth`
(que precede `admin-panel`), para o desvio ser classificado como `auth`. Verificado
por regressão: "SQL injection authentication bypass" ainda → `sqli`, "Admin panel
exposed" ainda → `admin-panel`, "predictable password reset token" ainda → `auth`.

**2. Sem sinal `php-page-controller-lfi` para o parâmetro LFI `?page=` (correção no
reconhecimento).** O `content_discovery` sinalizou o formulário de upload mas não o
LFI óbvio `?page=` — a estrela de severidade crítica deste lab. Adicionado um
detector conservador de parâmetro de LFI: ele emite `php-page-controller-lfi` (→
`specialist-lfi-php-page-controller`, P0) quando um parâmetro com cara de inclusão
de arquivo (`page/file/include/template/path/...`) carrega um valor de
arquivo/caminho/wrapper, e fica em silêncio em paginação (`?page=2`, `?page=next`).
O dispatcher agora gera automaticamente o especialista de LFI (0 sem mapeamento) — o
vetor de LFI não depende mais de o LLM notar o parâmetro.

**3. A rota do gabarito era estrita demais.** A rota de P1 era `/index.php`, mas o
front controller do LFI é igualmente alcançável em `/?page=` (o plugin reportou essa
forma). A rota de P1 foi relaxada para a raiz do front controller `/`.

Repontuação: **6/6**, e **sem regressão** — todos os 11 labs seguem com 100% de recall.

## Segurança do laboratório

O LegacyPortal é genuinamente vulnerável (um `include()` sem sanitização real,
execução de PHP arbitrário real via a cadeia upload→LFI), mas o servidor é iniciado
com `disable_functions` cobrindo a execução do sistema (`system`/`exec`/…) e as
operações de arquivo destrutivas (`unlink`/`file_put_contents`/…). Então uma
webshell incluída **executa PHP** (comprovando o RCE e lendo o código-fonte) mas não
pode rodar comandos de shell nem danificar o host. Um script roteador também faz o
servidor embutido devolver 404s reais (senão o servidor CLI do PHP recai no
index.php para todo caminho, o que faria qualquer varredura de conteúdo achar que a
wordlist inteira existe).

## Rodar

```bash
# precisa do PHP no PATH (ou o php do scoop)
./serve.sh        # ou:  pwsh ./serve.ps1     ->  http://127.0.0.1:18811
```

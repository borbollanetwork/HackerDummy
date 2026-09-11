# Lab 19 — SmuggleForge — Resultados

O primeiro lab de **contrabando de requisições HTTP** — e uma dessincronização
front-end/back-end *genuína*, não uma imitação. Duas camadas de socket bruto, só com a
biblioteca padrão, que deliberadamente discordam sobre o enquadramento do corpo: o
front-end (alvo, :18819) delimita por `Content-Length` e bloqueia `/admin`; o back-end
(:18820, interno) respeita `Transfer-Encoding: chunked` e serve `/admin`. Um payload
CL.TE contrabandeia uma requisição ao `/admin` interno passando pelo bloqueio do
front-end.

## Resultado: o plugin executou um ataque de dessincronização real

Dado um prompt guiado por metodologia (sem exploit entregue), o especialista de
contrabando às cegas leu os banners de `Server`, inferiu a arquitetura de duas
camadas, diagnosticou **CL.TE**, escreveu uma requisição de socket bruto exata em
bytes (Content-Length cobrindo um `GET /admin` contrabandeado após o terminador de
chunk `0\r\n\r\n`) e **recuperou o segredo do admin interno** que uma requisição
direta a `/admin` devolve como 403. Este é o ataque de protocolo mais profundo da
suíte — dessincronização HTTP genuína, feita às cegas.

## Nota

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base | **2/3 (67%)** | 50% | o achado de contrabando não tinha classe (caiu em `other`/`ssrf`) |
| Após correção | **3/3 (100%)** | — | banner + cabeçalhos ausentes são os outros dois; zero falso positivo |

## A lacuna que este laboratório revelou

**Nova classe: `smuggling` (CWE-444).** O agente confirmou a dessincronização CL.TE
mas nenhum classificador tinha uma classe de contrabando de requisições, então caiu.
Adicionada `smuggling` (request/response smuggling, CL.TE / TE.CL / TE.TE, HTTP
desync, conflito chunked-vs-CL) aos dois classificadores + `TAXONOMY.md`, colocada ao
lado de `crlf` (e verificado que NÃO colide com CRLF/divisão de resposta). Os outros
dois achados plantados (banner de `version`, `headers` ausentes) classificaram certo
de saída.

## Nota do laboratório

A dessincronização é real (dois servidores de socket bruto com lógica de enquadramento
de corpo genuinamente diferente), então reproduz só com requisições exatas em bytes —
exatamente como o bug real. O único "segredo" é uma flag de laboratório; nada executa
código. O back-end devolve 404 em caminhos desconhecidos para uma varredura de
conteúdo não ver a wordlist inteira como 200.

## Rodar

```bash
python labs/19-smuggleforge/app.py     # front-end (alvo) -> http://127.0.0.1:18819
#                                        (o back-end roda internamente na 18820)
```

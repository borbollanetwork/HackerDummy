# Lab 13 — AspNetVault — Resultados

O primeiro lab **.NET / IIS** — uma *imitação* fiel, em Python só com a biblioteca
padrão, de um site ASP.NET Web Forms legado, exercitando classes e reconhecimento
que os 12 labs anteriores nunca tocaram: um **web.config** exposto (connectionStrings
+ `<machineKey>`), **desserialização de ViewState**, o **visualizador de trace** do
ASP.NET e banners de versão do ASP.NET. Ele finalmente conduz a wordlist inteira de
.NET (web.config, trace.axd, elmah.axd, Default.aspx) que já vivia no motor de
reconhecimento.

## Método

O plugin rodou a esteira completa; os agentes de exploração **às cegas**. O
reconhecimento foi o melhor da campanha: o `content_discovery` detectou
`stack=aspnet` e emitiu `web-config-exposed` (→ specialist-config-secrets P0),
`trace-axd-enabled` (→ specialist-aspnet-trace), `aspnet-version-disclosure`,
`iis-legacy`, `elmah-exposed` e `login-form-detected` — 9 especialistas, 0 sem
mapeamento. O especialista .NET às cegas então extraiu tudo do web.config, provou que
o MAC do ViewState não era exigido (`__VIEWSTATE` adulterado aceito), raciocinou o
caminho machineKey→forja de ViewState / RCE por ObjectStateFormatter do ysoserial.net
e leu as variáveis de servidor do trace.axd (caminhos físicos, conta de serviço
`PORTAL\svc_web`).

## Nota

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base | **3/5 (60%)** | 38% | deser de ViewState classificada `rce`; trace.axd classificado pela `aspnet-leak` de nicho |
| Após correção | **5/5 (100%)** | 62% | os extras (elmah, eol, clickjacking) são bônus reais, zero falso positivo |

O plugin **detectou toda a superfície .NET às cegas**. As duas falhas foram de
classificação, e uma delas forçou uma correção estrutural adiada havia tempo.

## As lacunas que este laboratório revelou

**1. `rce` precisa ser a ÚLTIMA entre as classes de execução de código (a grande).**
O achado de ViewState era intitulado "ViewState Deserialization → RCE", então batia
na classe genérica `rce` antes de `deserialization`. É o mesmo padrão de
causa-raiz-vs-impacto do upload-antes-de-rce — mas estava latente desde o Lab 11
(cujo achado de LFI simplesmente não dizia "RCE" no título). O AspNetVault forçou.
Correção: `rce` movido para **depois** de upload/lfi/ssrf/xxe/deserialization/ssti,
para um achado intitulado "`<X>` → RCE" manter a causa raiz e só um achado de injeção
de comando puro cair em `rce`. Verificado: "OS Command Injection" → `rce`, "ViewState
Deserialization → RCE" → `deserialization`, "LFI → RCE" → `lfi`, "Upload → RCE" →
`upload`, "SSTI → RCE" → `ssti`. Sem regressão nos 13 labs (e a precisão do Lab 11
melhorou — o achado LFI→RCE dele agora é `lfi`, não um `rce` extra perdido).

**2. As taxonomias do plugin e do benchmark tinham divergido (`aspnet-leak`).** A
divulgação por trace.axd era classificada por uma classe `aspnet-leak` só do plugin,
que a taxonomia do benchmark (`classify.py`) não tinha. A classe canônica, agnóstica
de fornecedor, para isso é `info-disc`. A chave da classe de diagnóstico de ASP.NET
foi reapontada para `info-disc` (mantendo o rótulo descritivo) e o `classify.py`
aprendeu a mapear `trace.axd` / `asp.net trace` / `elmah` → `info-disc`, restaurando
a sincronia finding_model ↔ classify.py.

Repontuação: **5/5**, todos os 13 labs ainda 100%.

## Nota do laboratório

Isto é uma *imitação* (Python só com a biblioteca padrão, sem runtime .NET) que
reproduz a **superfície** de ataque do ASP.NET/IIS para o reconhecimento + o
conhecimento .NET de um agente serem medidos. As primitivas de exploração são
travadas por segurança: um `__VIEWSTATE` adulterado/gadget é reconhecido e reportado
como capaz de RCE (MAC não exigido) mas nunca desserializado/executado; a machineKey
e a senha do SQL são marcadores sem função.

## Rodar

```bash
python labs/13-aspnetvault/app.py        # -> http://127.0.0.1:18813
```

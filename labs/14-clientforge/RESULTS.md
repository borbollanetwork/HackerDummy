# Lab 14 — ClientForge — Resultados

O primeiro lab de **lado do cliente** — toda a superfície de ataque no navegador que
os 13 labs anteriores (focados no servidor) nunca tocaram. Todo bug vive no HTML/JS
que o servidor entrega e que executa no navegador da vítima, então é achado por
**análise fonte → sink do código servido**, exatamente como XSS de DOM, poluição de
protótipo, redirecionamento aberto no DOM e segredos no JS são descobertos num
engajamento real.

## Método

O plugin rodou a esteira completa; o agente de exploração rodou **às cegas** e (como
essas vulnerabilidades não aparecem nas respostas HTTP puras) as achou buscando toda
página + `<script>` e traçando estaticamente o fluxo de dados. Ele leu
`/search.html`, `/profile.html`, `/go.html` e `/static/app.js` e identificou cada
fonte→sink.

## Nota

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base | **3/5 (60%)** | 50% | XSS de DOM classificado `other`; poluição de protótipo sem classe (caiu em `2fa-bypass` pelo texto do corpo) |
| Após correção | **5/5 (100%)** | 83% | o extra (clickjacking) é bônus real, zero falso positivo |

O agente às cegas **detectou os cinco bugs de lado do cliente** lendo o JS. As duas
falhas foram de classificação — inclusive uma classe totalmente nova.

## As lacunas que este laboratório revelou

**1. Nova classe: `prototype-pollution` (CWE-1321).** O agente achou o `merge()`
recursivo sem proteção e o fluxo `?prefs={"__proto__":...}`, mas nem o
`finding_model.py` nem o `classify.py` do benchmark tinham uma classe de poluição de
protótipo, então caiu em `other` e depois em `2fa-bypass` (o texto de impacto
mencionava "2FA bypass" via o gadget, e o fallback pelo corpo casou). Classe
adicionada aos dois, com CWE-1321 + referências OWASP/PortSwigger.

**2. `xss` não reconhecia XSS de DOM (divergência finding_model ↔ classify.py).** A
regex de `xss` do `finding_model` era `reflect.*xss | cross-site script |
reflected.*script` — **não tinha `\bxss\b` nem vocabulário de DOM**, então "DOM-Based
XSS" classificava como `other` (enquanto o `classify.py` do benchmark já o casava por
`\bxss\b`). Adicionado `dom.?based.?xss | dom.?xss` ao `finding_model`.

**Uma armadilha evitada:** a correção óbvia (adicionar `\bxss\b` puro) *regredia* o
achado de redirecionamento aberto — o título dele era "DOM-Based Open Redirect
(escalation to **XSS** via `javascript:`)", e um `\bxss\b` guloso o roubava para o
balde `xss`. Então o casamento de XSS é de propósito restrito a qualificadores
DOM/refletido/cross-site, nunca um substring "XSS" puro — o redirecionamento aberto
(causa raiz) mantém a classe enquanto o achado de XSS de DOM ainda casa. Verificado
nos 14 labs; sem regressão.

## Nota do laboratório

HTML/JS estático, servido por Python só com a biblioteca padrão. Os bugs são sinks
reais de lado do cliente (`location.hash`→`innerHTML`, `merge()` sem proteção de
`?prefs=`, `location.href`←`?next=`, chave embutida em `app.js`); executam num
navegador, por isso a detecção é por revisão de código-fonte. As strings com cara de
segredo são marcadores sem função.

## Rodar

```bash
python labs/14-clientforge/app.py        # -> http://127.0.0.1:18814
```

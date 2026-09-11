# Lab 15 — RaceVault — Resultados

O primeiro lab de **lógica de negócio**. Ele testa uma *capacidade*, não uma
superfície: o agente consegue achar uma falha invisível ao teste de uma requisição
por vez? A joia da coroa é uma **condição de corrida** genuína — o endpoint de
resgate tem uma janela real de check-then-act (TOCTOU) sem bloqueio, então só um
agente que dispara requisições **concorrentes** a acha. A SKILL lista um
especialista de lógica de negócio (condições de corrida / pular etapa de fluxo);
nenhum lab anterior tinha medido isso.

## Resultado: o plugin enviou requisições concorrentes e venceu

Dado um prompt guiado por metodologia (sem dica de que havia uma corrida), o
especialista de lógica de negócio às cegas capturou o estado inicial, disparou ~30
`POST /redeem` **paralelos** de um voucher de uso único e observou a carteira
creditada a mais (BONUS25 valia 25 → saldo +75 = resgatado 3×). Ele diagnosticou
corretamente a falta de bloqueio entre a verificação de `used` e o crédito. Este é o
destaque: a metodologia em largura de lógica de negócio exercita concorrência de
verdade, não só sondagens sequenciais.

## Nota

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base | **4/5 (80%)** | 67% | a corrida foi detectada mas não tinha classe (`other`) |
| Após correção | **5/5 (100%)** | 83% | o extra (clickjacking) é bônus real, zero falso positivo |

## A lacuna que este laboratório revelou

**Nova classe: `race-condition` (CWE-362).** O agente confirmou o gasto duplo por
TOCTOU, mas nem o `finding_model.py` nem o `classify.py` do benchmark tinham classe
para isso, então caiu em `other`. Classe adicionada aos dois (+ `TAXONOMY.md`),
casando as formas `race condition | TOCTOU | check-then-act | double-spend |
concurrent <ação>`, com CWE-362 + referências OWASP/PortSwigger. Os outros quatro
bugs plantados classificaram certo de saída (idor, mass-assignment, no-rate-limit,
headers).

## Um bug que a execução às cegas achou no próprio laboratório

Na primeira passada o especialista reportou um **desvio de autenticação por
comparação nula** que eu tinha escrito por acidente: `USERS.get(u) == p` devolve
`None == None` para um usuário inexistente com `"password": null`, cunhando uma
sessão para qualquer nome (mais um DoS por `KeyError` no usuário fantasma
resultante). Isso é um bug real de confusão de tipo — mas não intencional, e
trivializava a autenticação da aplicação e bloqueava o teste limpo do caminho de
atribuição em massa. Laboratório corrigido para `u in USERS and p is not None and
USERS[u] == p` e rerrodado. (Uma boa demonstração de que o harness pega também os
erros do autor do laboratório.)

## Nota do laboratório

Dinheiro de brincadeira em memória; nada real está em jogo. A corrida é genuína — um
servidor multithread com uma janela real (pequena) de TOCTOU — então reproduz só sob
concorrência, exatamente como a classe de bug real.

## Rodar

```bash
python labs/15-racevault/app.py        # -> http://127.0.0.1:18815
# contas de teste: alice/alicepw, bob/bobpw
```

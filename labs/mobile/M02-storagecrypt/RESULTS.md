# M02 — StorageCrypt — Resultados

Degrau 2: armazenamento local inseguro + criptografia quebrada. O especialista
estático às cegas leu a árvore `app/` (manifesto, duas classes smali,
`assets/db_schema.sql`) e produziu **10 achados** — cobrindo as quatro classes
plantadas mais bônus (chave AES embutida no código, IV estático, PIN em MD5).
Notavelmente ele **corretamente NÃO levantou um achado de rede em texto claro**
(targetSdk 31 desabilita cleartext por padrão e não há network-security-config
permissivo) — boa disciplina de falso positivo.

## Nota

| Passada | Recall | Notas |
|---------|--------|-------|
| Após taxonomia | 3/4 (75%) | o achado de `allowBackup` foi roubado por `insecure-storage` (ele nomeia as prefs/DB que expõe) |
| Após reordenação | **4/4 (100%)** | `backup-allowed` movido antes de `insecure-storage`; precisão 40% (o resto = bônus) |

## As lacunas que este laboratório revelou

**Duas novas classes + uma extensão** (sincronizadas em `classify.py` e
`finding_model.py`, documentadas em `TAXONOMY.md`):

| classe | CWE | sinal |
|--------|-----|-------|
| `insecure-storage` | 312 | SharedPreferences legível por todos/em texto plano, SQLite/PII sem criptografia |
| `sensitive-log` | 532 | token/PII/PAN escrito no logcat (`Log.d`/`Log.v`) |
| `weak-crypto` (estendida) | 327 | + AES-ECB, IV estático/zerado, chave de criptografia embutida no código (mantidos MD5/SHA1/sem sal) |

**Três correções de ordem/regressão** que a varredura forçou:

1. **`backup-allowed` antes de `insecure-storage`** — um achado real de `allowBackup`
   descreve os dados que expõe ("...extrair as SharedPreferences e o `wallet.db` em
   texto plano..."), então a classe de armazenamento o roubava. A classe de causa raiz
   vence.
2. **`insecure-storage` antes de `weak-crypto`** — para "token em texto plano nas
   SharedPreferences" ser um achado de armazenamento, enquanto "hash MD5" fica cripto.
3. **`sqli` → `\bsqli\b`** — o literal puro casava "**SQLi**te", classificando errado
   qualquer achado de "unencrypted SQLite database" como injeção de SQL. A fronteira de
   palavra mantém a abreviação `SQLi` enquanto libera `SQLite`.

`sensitive-log` é ancorada em formas reais de log (`logcat`, `Log.d/v`, "written to
log") para **não** roubar achados web como "login **token** in the URL".

## Rodar

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M02-storagecrypt/gabarito.json \
  --findings achados_do_seu_agente.json
```

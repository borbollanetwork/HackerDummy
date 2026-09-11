# M02 — StorageCrypt (Android)

Degrau 2 da escada móvel: **armazenamento local inseguro + criptografia quebrada**
— a camada de dados em repouso de um aplicativo de carteira móvel feita errado.

## Artefato

**Árvore do apktool** decompilada em [`app/`](app/). Veja
[`../MOBILE.md`](../MOBILE.md).

```
app/
  AndroidManifest.xml                       # allowBackup=true
  res/values/strings.xml
  assets/db_schema.sql                      # SQLite em texto plano: CPF, nome, PAN completo, PIN em MD5
  smali/com/storagecrypt/app/
    CryptoUtils.smali                        # AES/ECB + chave embutida no código + IV zerado + MD5
    StorageManager.smali                     # prefs em texto plano legíveis por todos + vazamento por Log.d
```

> Vulnerável de propósito, só para treino. Os valores de semente (CPF/PAN de
> teste) são marcadores sem função.

## Vulnerabilidades plantadas (4)

| id | classe | severidade | evidência |
|----|--------|:----------:|-----------|
| S1 | `insecure-storage` | high | prefs em texto plano `MODE_WORLD_READABLE` (token, PAN) + PII em SQLite sem criptografia |
| S2 | `weak-crypto` | high | `AES/ECB/NoPadding` + chave embutida no código + IV estático só de zeros + MD5 sem sal |
| S3 | `sensitive-log` | medium | `Log.d` vaza o token de sessão e o PAN completo do cartão |
| S4 | `backup-allowed` | medium | `android:allowBackup="true"` → exfiltração por `adb backup` |

Detalhes em [`gabarito.json`](gabarito.json).

## Analisar e pontuar

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M02-storagecrypt/gabarito.json \
  --findings achados_do_seu_agente.json
```

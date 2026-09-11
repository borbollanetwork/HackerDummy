# M01 — LeakyVault (Android)

O **piso** da escada móvel: um aplicativo Android escancarado, sem ofuscação e
sem proteções em tempo de execução. Fruta pura de análise estática — os achados
que um pentester móvel lê direto do manifesto, dos recursos e do dex
decompilados.

## Artefato

Uma **árvore do apktool** decompilada em [`app/`](app/) — analise-a do jeito que
a fase estática do `droidagent-mobile` faz (flags do manifesto, grep de segredos,
revisão de exportação de componentes). Veja [`../MOBILE.md`](../MOBILE.md) para o
formato.

```
app/
  AndroidManifest.xml                  # debuggable, allowBackup, componentes exportados, cleartext
  apktool.yml
  res/values/strings.xml               # chave de API + segredo HMAC embutidos no código
  res/xml/network_security_config.xml  # cleartextTrafficPermitted + trust-anchors do usuário
  assets/config.json                   # base_url sobre http:// + os mesmos segredos
  smali/com/leakyvault/app/ApiClient.smali   # segredos compilados no dex; loga o token
```

> Vulnerável de propósito, só para treino. Sem backend real; toda string com cara
> de segredo (`lv_live_…`, `lv_sign_…`) é um marcador sem função.

## Vulnerabilidades plantadas (5)

| id | classe | severidade | evidência |
|----|--------|:----------:|-----------|
| L1 | `debuggable` | medium | `android:debuggable="true"` no manifesto |
| L2 | `backup-allowed` | medium | `android:allowBackup="true"` → roubo de dados por `adb backup` |
| L3 | `exported-component` | high | `AdminActivity` / `SyncReceiver` / `NotesProvider` exportados, sem permissão |
| L4 | `cleartext-traffic` | high | `usesCleartextTraffic="true"` + `network_security_config` permite cleartext e ACs do usuário |
| L5 | `creds` | high | chave de API + segredo HMAC embutidos em `strings.xml`, `assets/config.json` e no dex |

Detalhes completos e notas de exploração em [`gabarito.json`](gabarito.json).

## Analisar e pontuar

```bash
# aponte o seu agente de análise estática móvel para app/ (ÀS CEGAS — não mostre o gabarito),
# recolha os achados em JSON, depois:
python harness/score_lab.py \
  --gabarito labs/mobile/M01-leakyvault/gabarito.json \
  --findings achados_do_seu_agente.json
```

O casamento é por **classe** (a localização é `*` / de toda a aplicação aqui). Um
APK real pode ser produzido com `apktool b labs/mobile/M01-leakyvault/app` quando
o conjunto de recursos estiver completo; a análise estática precisa apenas da
árvore como entregue.

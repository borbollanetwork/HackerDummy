# M01 — LeakyVault — Resultados

O primeiro lab **móvel (Android)** — e o primeiro degrau da escada móvel. Um
aplicativo decompilado escancarado: sem ofuscação, sem RASP, fruta pura de análise
estática.

## Resultado: 5/5 (100% de recall) — a lacuna foi vocabulário, não detecção

| Passada | Recall | Precisão | Notas |
|---------|--------|----------|-------|
| Linha de base (sem classes móveis) | — | — | o agente às cegas achou tudo; o classificador não tinha vocabulário móvel, então os achados caíram em `other` |
| Após taxonomia | **5/5 (100%)** | 28% | precisão <100% = bônus (o agente reporta instâncias por arquivo; a deduplicação as colapsa) |

O especialista estático às cegas analisou a árvore `app/` (manifesto, `res/`,
`assets/`, `smali/`) **sem o gabarito** e produziu **18 achados** — toda classe
plantada mais bônus genuíno: pegou os três componentes exportados individualmente,
sinalizou o **trust-anchor de AC do usuário** no network-security-config, o **token
Bearer vazado para `Log.d`**, o segredo duplicado nos três caminhos de extração, a
`WRITE_EXTERNAL_STORAGE` ampla demais e o `targetSdkVersion 22` desatualizado.

Igual à campanha web: **o agente detecta quase tudo às cegas; a lacuna é o motor de
relatório nomeá-lo.**

## A lacuna que este laboratório revelou

O classificador tinha **zero vocabulário Android**. Adicionadas quatro classes móveis
(tanto ao `harness/classify.py` quanto ao `finding_model.py` do plugin, mantidos em
sincronia, mais `TAXONOMY.md`):

| classe | CWE | sinal |
|--------|-----|-------|
| `debuggable` | 489 | `android:debuggable="true"` |
| `backup-allowed` | 530 | `android:allowBackup="true"` |
| `exported-component` | 926 | Activity/Service/Receiver/Provider exportado, sem permissão |
| `cleartext-traffic` | 319 | `usesCleartextTraffic` / cleartext no network-security-config |

Elas são colocadas **antes** das classes web `backup` / `admin-panel` / `headers`
para a classe móvel específica vencer as colisões naturais (por exemplo "adb **backup
file**", "exported **Admin**Activity"). Duas correções saíram da checagem de
regressão:

- a regex de `cleartext-traffic` originalmente começava com um `cleartext` puro, que
  roubaria achados web como "**cleartext** credentials" → apertada para só as formas
  de cleartext-traffic do Android;
- `creds` não reconhecia a forma de **segredo embutido no APK** (chave de api /
  segredo de assinatura em `strings.xml` / `smali` / `assets`) e estava fora de
  sincronia entre os dois classificadores → unificada e ampliada nos dois.

## Achados bônus → a escada à frente

Os achados extras do agente antecipam degraus posteriores: o **trust-anchor de AC do
usuário** é a classe `improper-tls` que o M03 introduz; o **vazamento de token por
`Log.d`** é `sensitive-log` no M02. Construído como projetado.

## Rodar

```bash
# análise estática às cegas da árvore, depois:
python harness/score_lab.py \
  --gabarito labs/mobile/M01-leakyvault/gabarito.json \
  --findings achados_do_seu_agente.json
```

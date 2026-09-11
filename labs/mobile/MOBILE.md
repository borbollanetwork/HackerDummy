# HackerDummy — Laboratórios móveis (Android)

Uma trilha paralela que estende o benchmark da *exploração web ao vivo* para a
**avaliação de aplicativos Android** — a metodologia que um pentester móvel
aplica a um APK decompilado e às proteções em tempo de execução dele.

## Por que um artefato diferente

Os laboratórios web são servidores HTTP que você ataca ao vivo. Um alvo móvel é
um **APK**: você o *decompila* (jadx / apktool) e raciocina sobre o resultado —
`AndroidManifest.xml`, `smali`/Java, recursos, assets, bibliotecas nativas — e
depois, dinamicamente, vence as proteções dele (detecção de root e de emulador,
anti-Frida, pinning de certificado, ofuscação).

Então cada laboratório móvel vem como uma **árvore de projeto de APK decompilado**
— exatamente a forma que `apktool d app.apk` / `jadx` produzem:

```
labs/mobile/MNN-nome/
  app/
    AndroidManifest.xml         # manifesto em texto (forma do apktool)
    apktool.yml                 # para `apktool b app/` reconstruir um APK real
    smali/.../*.smali           # classes que carregam os sinais plantados
    res/values/strings.xml      # recursos / strings embutidas no código
    assets/                     # arquivos empacotados (configs, chaves, JS)
    lib/<abi>/                  # marcadores de .so nativo (degraus posteriores)
  gabarito.json                 # gabarito (mesmo esquema dos labs web)
  README.md                     # o que é, a tabela de vulnerabilidades plantadas
  RESULTS.md                    # a nota da execução de referência
```

Este artefato único é:
- **pesquisável hoje** — um agente de análise estática roda a própria metodologia
  real (flags do manifesto, grep de segredos, padrões de storage/crypto/IPC/WebView/TLS) sobre ele;
- **construível** — `apktool b labs/mobile/MNN-nome/app` gera um APK real e
  decompilável quando você quiser instalar/instrumentar.

> Nada aqui executa código ou fala com um backend real. Todos os endpoints são
> marcadores `example`/`127.0.0.1`; todas as strings com cara de segredo são sem função.

## Pontuação

Contrato idêntico ao dos laboratórios web — o `harness/score_lab.py` casa um
achado por **classe + localização**. Para o móvel, `route` no gabarito é a
*localização da evidência*: um caminho de arquivo (`AndroidManifest.xml`,
`res/values/strings.xml`, uma classe smali) ou `*` para toda a aplicação. Rode no
modo genérico:

```bash
python harness/score_lab.py \
  --gabarito labs/mobile/M01-leakyvault/gabarito.json \
  --findings achados_do_seu_agente.json
```

As classes de vulnerabilidade móvel vivem na mesma taxonomia
([`harness/classify.py`](../../harness/classify.py) / [`TAXONOMY.md`](../../TAXONOMY.md)) —
por exemplo `exported-component`, `cleartext-traffic`, `debuggable`,
`backup-allowed`, `insecure-storage`, `improper-tls`, `webview`, `deeplink`,
`weak-anti-tampering` (mais as reaproveitadas `creds`, `weak-crypto`, `lfi`,
`info-disc`).

## A escada (simples → endurecido)

Modelada para subir de um aplicativo escancarado a um endurecido como um alvo real
de banco móvel (do tipo que traz RASP estilo AllowMe, pinning nativo, SDKs de
liveness/atestação e ofuscação pesada):

| Degrau | Lab | Tema | Classes principais |
|--------|-----|------|--------------------|
| M01 | LeakyVault | Fruta estática | debuggable, backup-allowed, exported-component, cleartext-traffic, creds |
| M02 | StorageCrypt | Armazenamento e criptografia inseguros | insecure-storage, weak-crypto, sensitive-log |
| M03 | NetForge | Confiança de rede e WebView | improper-tls, webview |
| M04 | DeepLinkForge | IPC / deep links | deeplink, exported-component, lfi (travessia em provider) |
| M05 | RootLite | Entrada em RASP (contornável) | weak-anti-tampering |
| M06 | Hardened | Proteções nível bancário guardando uma falha real | weak-anti-tampering + a falha por trás dela |

Cada laboratório planta **classes distintas** (para a deduplicação por
`(host, class)` nunca colapsar dois achados) e é construído/pontuado/corrigido até
100% de recall antes do degrau seguinte — o mesmo ciclo da campanha web.

## Ferramental

`jadx` e `apktool` (ambos instaláveis via scoop / pelos releases deles) para
decompilar e reconstruir. O agente de referência é a skill `droidagent-mobile` do
DroidAgent, rodada **às cegas** (nunca vê o gabarito), lendo a própria base de
conhecimento móvel.

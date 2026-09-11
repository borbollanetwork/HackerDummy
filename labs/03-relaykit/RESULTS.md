# Lab 03 — RelayKit — Resultados

Pontuação da esteira contra as 7 vulnerabilidades de lado do servidor plantadas
no RelayKit. O agente de exploração rodou **às cegas** (só a lista de endpoints do
reconhecimento, nunca o gabarito).

## Método

Reconhecimento: o `content_discovery.py` aprimorado **minerou do código-fonte** a
lista de endpoints direto da página inicial em JSON (nenhuma das rotas do RelayKit
está em wordlist) — inclusive o `/internal/secrets`, só de servidor. Depois um
agente de lado do servidor às cegas testou SSRF (inclusive desvio de filtro), XXE,
desserialização insegura, injeção de comando do sistema, travessia de caminho e
SSTI, confirmando cada um com requisições ao vivo. O `score_lab.py` casou por
classe + rota.

## Nota

| Passada     | Recall        | Precisão | Notas |
|-------------|---------------|----------|-------|
| Linha de base | **4/7 (57%)** | 100%    | ssrf/rce/lfi classificados; xxe/deser/ssti sem classe |
| Após correção | **7/7 (100%)**| 100%    | +3 classes de lado do servidor |

O agente confirmou todos os 7 na primeira passada (bônus: notou que `/fetch`
também aceita `file://`, e que o desvio por credencial embutida do `/preview` é
corretamente bloqueado enquanto a variação de maiúsculas funciona). As 3 falhas
foram, de novo, **classes ausentes** — o motor não sabia nomear XXE,
desserialização ou SSTI.

## A lacuna que este laboratório revelou

O `finding_model.py` tinha `ssrf`, `rce` e `lfi`, mas nenhum vocabulário para as
outras três classes centrais de lado do servidor. Adicionadas:

| Classe | CWE | Pega |
|--------|-----|------|
| `xxe` | 611 | entidades externas de XML → leitura de arquivo / SSRF |
| `deserialization` | 502 | pickle/unserialize/yaml.load inseguro → gadgets de RCE |
| `ssti` | 1336 | injeção de template / linguagem de expressão no servidor |

Cada uma com CVSS + ≥3 referências de remediação (OWASP/PortSwigger/CWE).
Repontuação: **7/7, 100% de precisão**, e **sem regressão** (Lab 01 ainda 15/15,
Lab 02 ainda 12/12).

## Vitória no reconhecimento (o aprimoramento do crawling)

Este laboratório serviu também de teste da melhoria de crawling de diretórios. A
página inicial do RelayKit é JSON, e os endpoints dele (`/fetch`, `/render`,
`/internal/secrets`, …) não aparecem em **nenhuma** wordlist. Antes do
aprimoramento, o `content_discovery` não achava nada; depois de adicionar
**mineração de referências no código-fonte** (strings de caminho em HTML +
JS/JSON `fetch`/`axios`/XHR) e **seguir redirecionamentos**, ele levantou os
endpoints ao vivo — inclusive o alvo do SSRF `/internal/secrets` — direto do
código-fonte. É a regra "enxergar 100% da superfície" em ação: reconhecimento só
por wordlist teria perdido a aplicação inteira.

## Pontos fortes confirmados

- O ofício de lado do servidor do agente às cegas foi completo e encadeou bem
  (SSRF → segredos internos, raciocínio de desvio de filtro, XXE+LFI+SSRF por
  arquivo todos alcançando o mesmo arquivo, prova de resolução de gadget na
  desserialização).
- A segurança por projeto se manteve: injeção de comando e desserialização foram
  confirmadas sem nenhuma execução real de código no host.

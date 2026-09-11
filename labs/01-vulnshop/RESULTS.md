# Lab 01 — VulnShop — Resultados

Pontuação da esteira automática de pentest contra as 15 vulnerabilidades
plantadas no VulnShop. A esteira rodou **às cegas**: o agente de exploração
recebeu apenas os endpoints descobertos no reconhecimento, nunca o gabarito.

## Método

1. **Reconhecimento (scripts determinísticos)** — `passive_audit.py` (cabeçalhos
   de segurança, cookies, banners) + `content_discovery.py` (descoberta de
   caminhos/arquivos + emissão de sinal) contra `http://127.0.0.1:18801`.
2. **Exploração (agente às cegas)** — um agente de pentest web testou ativamente
   cada endpoint/parâmetro descoberto em busca de injeção, controle de acesso,
   redirecionamento/SSRF e divulgação de informação, confirmando cada um com uma
   requisição ao vivo (disciplina de zero falso positivo) e escrevendo um achado
   por vulnerabilidade confirmada.
3. **Pontuação** — o `harness/score_lab.py` casou os achados contra o
   `gabarito.json` por classe + rota.

## Nota

| Passada         | Recall        | Precisão            | Notas |
|-----------------|---------------|---------------------|-------|
| Primeira execução | 12/15 (80%)   | 85%                 | 3 falhas — todas bugs de **classificação**, não de detecção |
| Após correções  | **15/15 (100%)** | **93% (1 bônus, 0 FP)** | todas as plantadas casadas + 1 bônus |

O único achado "extra" é **clickjacking** — um problema real que a esteira
levantou além do gabarito (bônus, não falso positivo). A precisão efetiva é 100%.

## O que a primeira passada deixou passar — e por quê

O agente às cegas de fato **achou todas as 15 vulnerabilidades** e escreveu
achados para elas. As três "falhas" foram o motor de relatório **classificando
errado** achados corretos, que é justamente o tipo de lacuna que esta campanha
existe para revelar:

| Plantada | Causa raiz | Correção |
|----------|-----------|----------|
| **V03 backup** (`/backup.sql`) | A evidência do achado (um dump SQL) continha `password`, e o `classify()` lia título **+ evidência**; a regex de `creds` precede `backup`, então foi rerrotulado `creds` e fundido no achado do `.env`. | **Classificação por título primeiro**: classifica pelo título do especialista primeiro, recorrendo ao corpo só quando o título é genérico. |
| **V07 info-disc** (`/product?id=abc`) | A evidência do achado de erro verboso mostrava um erro de SQL, então a classificação por texto completo bateu em `sqli` e o fundiu. O título sozinho batia em `aspnet-leak` (regex gulosa demais: casava "verbose error" / "stack trace" genéricos). | Classificar por título primeiro **+** apertar `aspnet-leak` para marcadores específicos de ASP.NET **+** ampliar `info-disc` para pegar `verbose error` / `traceback` / `stack trace`. |
| **V14 open-redirect** (`/redirect?url=`) | **Não havia classe open-redirect** nenhuma — caía em `other`. | Adicionada uma classe `open-redirect` (CWE-601) com o próprio vetor CVSS e ≥3 referências de remediação. |

Todas as correções entraram no motor compartilhado `finding_model.py`
(`tools/templates/deliverable/dashboard/`) — então beneficiam todo engajamento
futuro, não só este laboratório.

## Observações secundárias (registradas, sem afetar o recall)

- **A checagem passiva de cookie é só na raiz.** O `passive_audit.py` sinaliza
  cookies inseguros na resposta inicial, mas o VulnShop só define o cookie de
  sessão num `POST /login` bem-sucedido. O agente de exploração pegou o V06
  (inspecionou o `Set-Cookie` depois de autenticar), então o recall não foi
  afetado — mas o reconhecimento passivo sozinho perderia cookies definidos só em
  respostas autenticadas.
- **Engajamentos congelam o motor.** O andaime do engajamento copia o motor do
  dashboard (`finding_model.py`, `generate_manifest.py`) para a pasta do
  engajamento por reprodutibilidade, então correções do motor precisam ser
  ressincronizadas num engajamento em andamento antes de repontuar.

## Pontos fortes confirmados

- O reconhecimento levantou de forma confiável toda exposição de arquivo/caminho
  (`.git`, `.env`, `backup.sql`, listagem de diretório, painel admin) e emitiu os
  sinais certos.
- O agente de exploração às cegas confirmou bugs de injeção, controle de acesso,
  redirecionamento/SSRF e divulgação de informação com evidência ao vivo e **sem
  falsos positivos** — ele até descartou corretamente SQLi em `/search` (só
  reflexão) e notou que o valor do cookie de sessão era *previsível/forjável*
  (`user-<id>-<role>`), uma profundidade extra além do bug plantado.
- A calibração de severidade + as referências de remediação por classe foram
  renderizadas corretamente para todas as classes, inclusive a recém-adicionada
  `open-redirect`.

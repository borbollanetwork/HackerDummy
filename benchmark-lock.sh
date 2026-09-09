#!/usr/bin/env bash
#
# benchmark-lock.sh — Cofre de integridade para o benchmark HackerDummy.
#
# Move gabarito.json e RESULTS.md de cada lab para um cofre com permissao 700 e
# registra o sha256 de cada arquivo. Enquanto travado, os arquivos NAO existem no
# path original: o agente de IA nao consegue ler, listar ou grepar o gabarito
# durante o pentest as cegas. O unlock restaura tudo e verifica os hashes,
# detectando qualquer adulteracao ocorrida enquanto travado.
#
# Uso:
#   ./benchmark-lock.sh lock      # antes do Prompt 1 (pentest as cegas)
#   ./benchmark-lock.sh unlock    # so na etapa de Comparacao do Prompt 1
#   ./benchmark-lock.sh status    # ver estado atual
#
# Variavel de ambiente:
#   HACKERDUMMY_ROOT  raiz do projeto (default: $HOME/tools/HackerDummy)

set -euo pipefail

ROOT="${HACKERDUMMY_ROOT:-$HOME/tools/HackerDummy}"
LABS_DIR="$ROOT/labs"
VAULT="$ROOT/.gabarito-vault"
MANIFEST="$VAULT/manifest.tsv"
LOCKFILE="$VAULT/LOCKED"

# Arquivos protegidos por lab.
PROTECTED=(gabarito.json RESULTS.md)

sha() { sha256sum "$1" | awk '{print $1}'; }

die() { echo "ERRO: $*" >&2; exit 1; }

[ -d "$LABS_DIR" ] || die "labs/ nao encontrado em '$ROOT'. Ajuste HACKERDUMMY_ROOT."

cmd_lock() {
  [ -f "$LOCKFILE" ] && die "Ja esta travado. Rode 'unlock' antes de travar de novo."
  mkdir -p "$VAULT"
  chmod 700 "$VAULT"
  : > "$MANIFEST"
  local moved=0
  # Varre recursivamente: pega gabarito/RESULTS dos labs web (labs/<lab>/) e
  # também dos labs mobile (labs/mobile/<lab>/).
  local find_args=()
  local i
  for i in "${!PROTECTED[@]}"; do
    [ "$i" -gt 0 ] && find_args+=(-o)
    find_args+=(-name "${PROTECTED[$i]}")
  done
  while IFS= read -r src; do
    [ -n "$src" ] || continue
    local rel="${src#"$LABS_DIR"/}"
    local h; h="$(sha "$src")"
    local dst="$VAULT/$rel"
    mkdir -p "$(dirname "$dst")"
    mv "$src" "$dst"
    printf '%s\t%s\n' "$rel" "$h" >> "$MANIFEST"
    moved=$((moved + 1))
  done < <(find "$LABS_DIR" -type f \( "${find_args[@]}" \) | sort)
  [ "$moved" -gt 0 ] || die "Nada para travar (nenhum gabarito/RESULTS encontrado)."
  date -u +"%Y-%m-%dT%H:%M:%SZ" > "$LOCKFILE"
  # Restringe acesso ao cofre sem marcar os arquivos como executáveis:
  # diretórios 700 (dono navega), arquivos 600 (dono lê/escreve).
  find "$VAULT" -type d -exec chmod 700 {} +
  find "$VAULT" -type f -exec chmod 600 {} +
  echo "TRAVADO: $moved arquivo(s) movido(s) para o cofre. Gabarito/RESULTS agora inacessiveis."
  echo "Rode './benchmark-lock.sh unlock' apenas na etapa de Comparacao."
}

cmd_unlock() {
  [ -f "$LOCKFILE" ] || die "Nao esta travado (LOCKED ausente)."
  [ -f "$MANIFEST" ] || die "Manifesto ausente — cofre corrompido."
  local restored=0 mismatch=0
  while IFS=$'\t' read -r rel h_orig; do
    [ -n "$rel" ] || continue
    local vfile="$VAULT/$rel"
    local dst="$LABS_DIR/$rel"
    [ -f "$vfile" ] || die "Arquivo sumiu do cofre: $rel"
    local h_now; h_now="$(sha "$vfile")"
    if [ "$h_now" != "$h_orig" ]; then
      echo "AVISO: hash divergente em $rel (adulterado enquanto travado)." >&2
      mismatch=$((mismatch + 1))
    fi
    mkdir -p "$(dirname "$dst")"
    mv "$vfile" "$dst"
    chmod 644 "$dst"   # arquivos de dados nunca devem ficar executáveis
    restored=$((restored + 1))
  done < "$MANIFEST"
  rm -f "$LOCKFILE" "$MANIFEST"
  # Remove diretorios vazios do cofre.
  find "$VAULT" -type d -empty -delete 2>/dev/null || true
  rmdir "$VAULT" 2>/dev/null || true
  echo "DESTRAVADO: $restored arquivo(s) restaurado(s)."
  if [ "$mismatch" -gt 0 ]; then
    echo "INTEGRIDADE: $mismatch arquivo(s) com hash divergente — verifique manualmente." >&2
    exit 2
  fi
  echo "INTEGRIDADE: OK (todos os hashes conferem)."
}

cmd_status() {
  if [ -f "$LOCKFILE" ]; then
    local n; n="$(wc -l < "$MANIFEST" 2>/dev/null || echo 0)"
    echo "Estado: TRAVADO desde $(cat "$LOCKFILE")"
    echo "Arquivos no cofre: $n"
  else
    echo "Estado: DESTRAVADO (gabarito/RESULTS acessiveis)."
  fi
}

case "${1:-}" in
  lock)   cmd_lock ;;
  unlock) cmd_unlock ;;
  status) cmd_status ;;
  *) echo "Uso: $0 {lock|unlock|status}" >&2; exit 1 ;;
esac

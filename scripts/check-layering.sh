#!/usr/bin/env bash
# Enforces the crate layering of ADR 0014 and AGENTS.md.
#
# - format, crypto and reader must not depend on a network client, an OAuth
#   crate or an async runtime.
# - format, crypto, reader, recover and wasm (the reader side) must not depend
#   on the writer or on anything above it.
#
# Only normal and build dependencies count; dev-dependencies are not shipped.
# Run from anywhere in the repository: scripts/check-layering.sh

set -euo pipefail
cd "$(dirname "$0")/.."

# Crates that must stay free of network, OAuth and async-runtime dependencies.
no_io_crates=(nilperit-format nilperit-crypto nilperit-reader)
# Crates that must never reach the writer side.
reader_side_crates=(nilperit-format nilperit-crypto nilperit-reader nilperit-recover nilperit-wasm)

forbidden_upward='^nilperit-(writer|node|cli|connector-.*|target-.*)$'
forbidden_io='^(tokio|async-std|smol|reqwest|hyper|ureq|isahc|surf|curl|oauth2|openidconnect|yup-oauth2)$'

workspace_packages=$(cargo metadata --format-version 1 --no-deps --locked |
  grep -o '"name":"nilperit-[a-z-]*"' | cut -d'"' -f4 | sort -u)

has_package() { grep -qx "$1" <<<"$workspace_packages"; }

deps_of() {
  cargo tree --locked -p "$1" --edges normal,build --prefix none --format '{p}' |
    awk '{print $1}' | sort -u | grep -vx "$1" || true
}

status=0
check() { # crate, pattern, reason
  local hits
  hits=$(deps_of "$1" | grep -E "$2" || true)
  if [ -n "$hits" ]; then
    echo "::error::$1 must not depend on ($3):"
    echo "$hits" | sed 's/^/  - /'
    status=1
  fi
}

for crate in "${reader_side_crates[@]}"; do
  has_package "$crate" && check "$crate" "$forbidden_upward" "writer side"
done
for crate in "${no_io_crates[@]}"; do
  has_package "$crate" && check "$crate" "$forbidden_io" "network, OAuth or async runtime"
done

[ "$status" -eq 0 ] && echo "Layering OK"
exit "$status"

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PREVIEW="$ROOT/builder/welcome/preview.html"

[[ -f "$PREVIEW" && ! -L "$PREVIEW" ]] || {
  printf 'SteamOS with NVIDIA drivers graphical preview is missing or unsafe: %s\n' "$PREVIEW" >&2
  exit 1
}

if [[ "${OPEMOS_GRAPHICAL_TEST_PRINT_ONLY:-0}" == 1 ]]; then
  printf '%s\n' "$PREVIEW"
  exit 0
fi

if [[ "$(uname -s)" != Darwin ]]; then
  printf 'test_welcome_macos.sh supports macOS only.\n' >&2
  exit 2
fi
command -v open >/dev/null 2>&1 || {
  printf 'macOS open(1) is unavailable.\n' >&2
  exit 2
}

printf 'Opening the safe SteamOS with NVIDIA drivers graphical simulation.\n'
printf 'No disks, privileges, QEMU processes, or installers are used.\n'
open "$PREVIEW"

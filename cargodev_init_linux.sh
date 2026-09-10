#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
MODE="${1:-run}"
[[ "$MODE" == run || "$MODE" == --check || "$MODE" == --print-only ]] || { printf 'Usage: %s [--check|--print-only]\n' "$0" >&2; exit 2; }
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || { printf 'cargodev_init_linux.sh supports x86_64 Linux only.\n' >&2; exit 2; }
[[ -f "$ROOT/package-lock.json" ]] || { printf 'Run this script from an OPEMOS.EXE checkout.\n' >&2; exit 2; }
if [[ "$MODE" == --print-only ]]; then
  printf 'npm ci\nOPEMOS_EXPERIMENTAL_LINUX=1 OPEMOS_LINUX_ACCEL=tcg npm run dev:linux-test\n'
  exit 0
fi
required=(node npm cargo rustc python3 git curl ssh scp qemu-system-x86_64 qemu-img gpgv 7z)
missing=()
for tool in "${required[@]}"; do command -v "$tool" >/dev/null 2>&1 || missing+=("$tool"); done
if ((${#missing[@]})); then
  printf 'Missing Linux prerequisites: %s\n' "${missing[*]}" >&2
  printf 'Install Node.js, Rust, Python 3, Git, curl, OpenSSH, QEMU, GnuPG, 7-Zip, and the Tauri/WebKitGTK build packages for your distribution.\n' >&2
  exit 2
fi
printf 'Linux development prerequisites are available. This host path is experimental.\n'
[[ "$MODE" == --check ]] && exit 0
cd "$ROOT"
npm ci
export OPEMOS_EXPERIMENTAL_LINUX=1
[[ "${OPEMOS_LINUX_ACCEL:-}" == kvm || "${OPEMOS_LINUX_ACCEL:-}" == tcg ]] || { printf 'Set OPEMOS_LINUX_ACCEL=kvm or tcg explicitly.\n' >&2; exit 2; }
exec npm run dev:linux-test

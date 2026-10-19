#!/usr/bin/env bash
set -euo pipefail
# This is the explicit hosted-M1 software lane. It never acquires dependencies.
if [[ $# -ne 5 || $1 != --runtime-root || $3 != --appliance-root || $5 != --diagnostic-x86-tcg ]]; then
  echo "usage: ./bundle_macos.sh --runtime-root PATH --appliance-root PATH --diagnostic-x86-tcg" >&2
  exit 2
fi
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || {
  echo "The diagnostic package requires native Apple Silicon macOS." >&2; exit 2;
}
root=$(cd -- "$2" && pwd -P)
appliance=$(cd -- "$4" && pwd -P)
source_commit=$(git rev-parse HEAD)
manifest_hash=$(shasum -a 256 "$root/runtime-manifest.json" | cut -d' ' -f1)
OPEMOS_RUNTIME_MANIFEST_SHA256=$manifest_hash OPEMOS_MACOS_X86_TCG=1 OPEMOS_EXE_SOURCE_COMMIT=$source_commit \
  npm run build:app -- --target aarch64-apple-darwin
apps=(src-tauri/target/aarch64-apple-darwin/release/bundle/macos/*.app)
[[ ${#apps[@]} -eq 1 && -d ${apps[0]} ]] || { echo "Expected one complete native .app." >&2; exit 1; }
python3 scripts/stage_macos_app.py --runtime-root "$root" --appliance-root "$appliance" \
  --output dist/macos --source-commit "$source_commit" --application "${apps[0]}"

#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 || $1 != --runtime-root ]]; then
  echo "usage: ./bundle_macos.sh --runtime-root PATH" >&2
  exit 2
fi
root=$(cd -- "$2" && pwd -P)
source_commit=$(git rev-parse HEAD)
manifest_hash=$(shasum -a 256 "$root/runtime-manifest.json" | cut -d' ' -f1)
OPEMOS_RUNTIME_MANIFEST_SHA256=$manifest_hash npm run build:app
apps=(src-tauri/target/release/bundle/macos/*.app/Contents/MacOS/steamos-nvidia-image-builder)
if [[ ${#apps[@]} -ne 1 ]]; then
  echo "Expected exactly one macOS application executable." >&2
  exit 1
fi
python3 scripts/stage_runtime_bundle.py --platform macos --runtime-root "$root" \
  --output dist/macos --source-commit "$source_commit" --application "${apps[0]}"

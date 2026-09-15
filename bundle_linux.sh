#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 || $1 != --runtime-root ]]; then
  echo "usage: ./bundle_linux.sh --runtime-root PATH" >&2
  exit 2
fi
root=$(cd -- "$2" && pwd -P)
source_commit=$(git rev-parse HEAD)
manifest_hash=$(sha256sum "$root/runtime-manifest.json" | cut -d' ' -f1)
OPEMOS_RUNTIME_MANIFEST_SHA256=$manifest_hash npm run build:linux-test
shopt -s nullglob
deb=(src-tauri/target/debug/bundle/deb/*.deb)
appimage=(src-tauri/target/debug/bundle/appimage/*.AppImage)
if [[ ${#deb[@]} -ne 1 || ${#appimage[@]} -ne 1 ]]; then
  echo "Expected exactly one Debian package and one AppImage." >&2
  exit 1
fi
python3 scripts/stage_runtime_bundle.py --platform linux --runtime-root "$root" \
  --output dist/linux --source-commit "$source_commit" \
  --application "${deb[0]}" --application "${appimage[0]}"

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
UI_ROOT="$ROOT/builder/welcome"
SERVER="$UI_ROOT/welcome_server.py"

[[ -x "$SERVER" && ! -L "$SERVER" && -f "$UI_ROOT/index.html" ]] || {
  printf 'SteamOS with NVIDIA drivers graphical test bundle is missing or unsafe.\n' >&2
  exit 1
}

if [[ "${OPEMOS_GRAPHICAL_TEST_PRINT_ONLY:-0}" == 1 ]]; then
  printf '%s --mock --ui-root %s\n' "$SERVER" "$UI_ROOT"
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

RUNTIME=$(mktemp -d /tmp/opemos-welcome-macos.XXXXXX)
SERVER_PID=
BROWSER_PID=
cleanup() {
  [[ -z "${BROWSER_PID:-}" ]] || kill -TERM "$BROWSER_PID" >/dev/null 2>&1 || true
  [[ -z "${SERVER_PID:-}" ]] || kill -TERM "$SERVER_PID" >/dev/null 2>&1 || true
  [[ -z "${SERVER_PID:-}" ]] || wait "$SERVER_PID" >/dev/null 2>&1 || true
  rm -rf "$RUNTIME"
}
trap cleanup EXIT INT TERM
python3 "$SERVER" --mock --ui-root "$UI_ROOT" --runtime "$RUNTIME" &
SERVER_PID=$!
for _ in {1..100}; do
  [[ -s "$RUNTIME/port" ]] && break
  kill -0 "$SERVER_PID" 2>/dev/null || exit 1
  sleep 0.05
done
[[ -s "$RUNTIME/port" ]] || { printf 'The graphical simulation did not start.\n' >&2; exit 1; }
PORT=$(tr -d '[:space:]' <"$RUNTIME/port")
URL="http://127.0.0.1:$PORT/"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
printf 'Opening the safe SteamOS with NVIDIA drivers graphical simulation.\n'
printf 'No disks, privileges, QEMU processes, or installers are used.\n'
if [[ -x "$CHROME" ]]; then
  "$CHROME" --user-data-dir="$RUNTIME/chrome" --app="$URL" --start-fullscreen --no-first-run &
  BROWSER_PID=$!
  printf '%s\n' "$BROWSER_PID" >"$RUNTIME/browser.pid"
else
  open "$URL"
fi
wait "$SERVER_PID"
SERVER_PID=

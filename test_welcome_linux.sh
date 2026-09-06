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

if [[ "$(uname -s)" != Linux ]]; then
  printf 'test_welcome_linux.sh supports Linux only.\n' >&2
  exit 2
fi
if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
  printf 'A Linux X11 or Wayland graphical session is required.\n' >&2
  exit 2
fi
command -v python3 >/dev/null 2>&1 || {
  printf 'python3 is required for the safe mock controller.\n' >&2
  exit 2
}

BROWSER=
for candidate in google-chrome-stable google-chrome chromium chromium-browser; do
  resolved=$(command -v "$candidate" 2>/dev/null || true)
  if [[ -n "$resolved" && -f "$resolved" && -x "$resolved" ]]; then
    BROWSER="$resolved"
    break
  fi
done
[[ -n "$BROWSER" ]] || {
  printf 'Install Google Chrome or Chromium to run the Linux graphical preview.\n' >&2
  exit 2
}

RUNTIME=$(mktemp -d "${TMPDIR:-/tmp}/opemos-welcome-linux.XXXXXX")
SERVER_PID=
BROWSER_PID=
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  [[ -z "${BROWSER_PID:-}" ]] || kill -TERM "$BROWSER_PID" >/dev/null 2>&1 || true
  [[ -z "${SERVER_PID:-}" ]] || kill -TERM "$SERVER_PID" >/dev/null 2>&1 || true
  [[ -z "${BROWSER_PID:-}" ]] || wait "$BROWSER_PID" >/dev/null 2>&1 || true
  [[ -z "${SERVER_PID:-}" ]] || wait "$SERVER_PID" >/dev/null 2>&1 || true
  rm -rf -- "$RUNTIME"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

python3 "$SERVER" --mock --ui-root "$UI_ROOT" --runtime "$RUNTIME" &
SERVER_PID=$!
for _ in {1..100}; do
  [[ -s "$RUNTIME/port" ]] && break
  kill -0 "$SERVER_PID" 2>/dev/null || { wait "$SERVER_PID"; exit 1; }
  sleep 0.05
done
[[ -s "$RUNTIME/port" ]] || { printf 'The graphical simulation did not start.\n' >&2; exit 1; }
PORT=$(tr -d '[:space:]' <"$RUNTIME/port")
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 1 && "$PORT" -le 65535 ]] || {
  printf 'The graphical simulation returned an invalid loopback port.\n' >&2
  exit 1
}
URL="http://127.0.0.1:$PORT/"
printf 'Opening the safe SteamOS with NVIDIA drivers graphical simulation.\n'
printf 'No disks, privileges, QEMU processes, or installers are used.\n'
env \
  HOME="$RUNTIME/home" \
  XDG_CONFIG_HOME="$RUNTIME/config" \
  XDG_CACHE_HOME="$RUNTIME/cache" \
  "$BROWSER" \
  --user-data-dir="$RUNTIME/browser" \
  --app="$URL" \
  --start-fullscreen \
  --no-first-run \
  --disable-default-apps \
  --disable-sync \
  --disable-background-networking &
BROWSER_PID=$!
printf '%s\n' "$BROWSER_PID" >"$RUNTIME/browser.pid"

while kill -0 "$SERVER_PID" 2>/dev/null; do
  if ! kill -0 "$BROWSER_PID" 2>/dev/null; then
    status=0
    wait "$BROWSER_PID" || status=$?
    BROWSER_PID=
    kill -TERM "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
    SERVER_PID=
    exit "${status:-1}"
  fi
  sleep 0.1
done
wait "$SERVER_PID"
SERVER_PID=

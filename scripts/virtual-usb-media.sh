#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/tests/virtual-usb/work"
MEDIA="$ROOT/virtual-usb-32g.raw"
STATE="$ROOT/virtual-usb-32g.state"
BYTES=34359738368
regular_exact() { [[ "$1" == "$ROOT"/* && ! -L "$1" && -f "$1" && "$(readlink -f -- "$1")" == "$1" ]]; }
regular_source() { [[ ! -L "$1" && -f "$1" && "$(readlink -f -- "$1")" == "$1" ]]; }
source_identity() { stat -c '%d:%i:%s' -- "$1"; }
create() {
  [[ -d "$ROOT" && ! -L "$ROOT" ]] || { echo 'unsafe or missing harness-owned root' >&2; exit 2; }
  [[ ! -e "$MEDIA" ]] || { echo 'stale virtual media exists' >&2; exit 2; }
  ( umask 077; : > "$MEDIA" ); truncate -s "$BYTES" "$MEDIA"
  regular_exact "$MEDIA" && [[ "$(stat -c %s "$MEDIA")" = "$BYTES" ]] || exit 1
}
write_verify() {
  local source="$1" before source_hash readback
  [[ ! -L "$source" && -f "$source" ]] || { echo "source must be a real regular file inside the harness root" >&2; exit 2; }
  source="$(readlink -f -- "$source")"
  regular_source "$source" || { echo 'source must be a real regular file inside the harness root' >&2; exit 2; }
  regular_exact "$MEDIA" && [[ "$(stat -c %s "$MEDIA")" = "$BYTES" ]] || { echo 'media is not the exact owned 32 GiB file' >&2; exit 2; }
  before="$(source_identity "$source")"; [[ "${before##*:}" -gt 0 && "${before##*:}" -le "$BYTES" ]] || exit 2
  source_hash="$(sha256sum "$source" | awk '{print $1}')"
  if [[ "${OPEMOS_VIRTUAL_USB_CANCEL_BEFORE_WRITE:-0}" = 1 ]]; then echo "virtual-media write cancelled" >&2; exit 130; fi
  dd if="$source" of="$MEDIA" bs=8M conv=notrunc,fsync status=none
  readback="$(head -c "${before##*:}" "$MEDIA" | sha256sum | awk '{print $1}')"
  [[ "$readback" = "$source_hash" && "$(source_identity "$source")" = "$before" ]] || { echo 'read-back or source identity verification failed' >&2; exit 1; }
  ( umask 077; printf 'schema=1\nmediaBytes=%s\nsource=%s\nsourceIdentity=%s\nsourceSha256=%s\n' "$BYTES" "$source" "$before" "$source_hash" > "$STATE.tmp" )
  mv -f -- "$STATE.tmp" "$STATE"
}
reset() {
  for path in "$MEDIA" "$STATE"; do
    [[ ! -e "$path" ]] && continue
    regular_exact "$path" || { echo 'refusing linked or drifted reset target' >&2; exit 2; }
    rm -- "$path"
  done
}
case "${1:-}" in create) [[ $# = 1 ]] || exit 2; create;; write) [[ $# = 2 ]] || exit 2; write_verify "$2";; reset) [[ $# = 1 ]] || exit 2; reset;; *) echo 'usage: virtual-usb-media.sh create|write SOURCE|reset' >&2; exit 2;; esac

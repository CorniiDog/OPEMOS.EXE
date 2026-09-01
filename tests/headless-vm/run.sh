#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPOSITORY_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"
BASE_IMAGE="${STEAMOS_HEADLESS_VM_BASE:-$REPOSITORY_ROOT/builder/appliance/fedora-builder-x86_64.qcow2}"
STATE_ROOT="${STEAMOS_HEADLESS_VM_STATE_ROOT:-$SCRIPT_DIR}"
WORK_ROOT="$STATE_ROOT/work"
RESULT_ROOT="$STATE_ROOT/results"
RESULT_PATH="$RESULT_ROOT/latest.json"
TIMEOUT_SECONDS="${STEAMOS_HEADLESS_VM_TIMEOUT_SECONDS:-180}"
SYNTHETIC_BYTES=$((64 * 1024 * 1024))

if ! command -v node >/dev/null 2>&1; then
    printf 'Headless VM harness requires node for machine-readable result validation.\n' >&2
    exit 2
fi
if [[ "$STATE_ROOT" != /* || ! -d "$STATE_ROOT" || -L "$STATE_ROOT" ]]; then
    printf 'Headless VM harness state root must be an existing absolute non-symlink directory.\n' >&2
    exit 2
fi
for state_directory in "$WORK_ROOT" "$RESULT_ROOT"; do
    if [[ -L "$state_directory" || ( -e "$state_directory" && ! -d "$state_directory" ) ]]; then
        printf 'Headless VM harness refuses unsafe runtime/result state: %s\n' "$state_directory" >&2
        exit 2
    fi
    if [[ ! -d "$state_directory" ]]; then
        mkdir -m 0700 -- "$state_directory"
    fi
done
if [[ ! "$TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || (( TIMEOUT_SECONDS < 30 || TIMEOUT_SECONDS > 900 )); then
    printf 'STEAMOS_HEADLESS_VM_TIMEOUT_SECONDS must be an integer from 30 through 900.\n' >&2
    exit 2
fi

atomic_result()
{
    local status="$1"
    local reason="$2"
    local staged_result
    staged_result="$(mktemp "$RESULT_ROOT/.latest.XXXXXX")"
    node -e '
const fs = require("fs");
const [path, status, reason] = process.argv.slice(1);
fs.writeFileSync(path, `${JSON.stringify({schemaVersion: 1, status, reason})}\n`, {mode: 0o600});
' "$staged_result" "$status" "$reason"
    chmod 0600 "$staged_result"
    mv -f -- "$staged_result" "$RESULT_PATH"
}

if [[ "${STEAMOS_HEADLESS_VM_STATE_CHECK_ONLY:-0}" == 1 ]]; then
    atomic_result passed "runtime and result state boundaries are safe"
    exit 0
fi

RUNTIME="$(mktemp -d "$WORK_ROOT/run.XXXXXX")"
QEMU_PID=""
RUN_COMPLETE=0

cleanup()
{
    local exit_status=$?
    if [[ -n "$QEMU_PID" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    rm -rf -- "$RUNTIME"
    if (( RUN_COMPLETE == 0 )); then
        atomic_result failed "headless VM harness aborted before a final guest result" || true
    fi
    return "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

write_result()
{
    atomic_result "$1" "$2"
    RUN_COMPLETE=1
}

for command in qemu-img qemu-system-x86_64; do
    if ! command -v "$command" >/dev/null 2>&1; then
        write_result "skipped" "missing dependency: $command"
        printf 'Headless VM harness skipped: missing %s\n' "$command" >&2
        exit 2
    fi
done
if [[ ! -f "$BASE_IMAGE" || -L "$BASE_IMAGE" ]]; then
    write_result "skipped" "immutable x86_64 Fedora base image is unavailable"
    printf 'Set STEAMOS_HEADLESS_VM_BASE to a regular x86_64 Fedora qcow2 image.\n' >&2
    exit 2
fi

SEED_DIR="$RUNTIME/seed"
SEED_ISO="$RUNTIME/seed.iso"
OVERLAY="$RUNTIME/system-overlay.qcow2"
SYNTHETIC_DISK="$RUNTIME/synthetic-test-disk.raw"
UNEXPECTED_DISK="$RUNTIME/unexpected-test-disk.raw"
SERIAL_LOG="$RUNTIME/serial.log"
UEFI_VARS="$RUNTIME/uefi-vars.fd"
mkdir -p "$SEED_DIR"
cp "$SCRIPT_DIR/user-data" "$SEED_DIR/user-data"
cp "$SCRIPT_DIR/meta-data" "$SEED_DIR/meta-data"

if command -v xorriso >/dev/null 2>&1; then
    xorriso -as mkisofs -quiet -output "$SEED_ISO" -volid cidata -joliet -rock "$SEED_DIR"
elif command -v genisoimage >/dev/null 2>&1; then
    genisoimage -quiet -output "$SEED_ISO" -volid cidata -joliet -rock "$SEED_DIR"
elif command -v hdiutil >/dev/null 2>&1; then
    hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata -o "$SEED_ISO" "$SEED_DIR"
    if [[ ! -f "$SEED_ISO" && -f "$SEED_ISO.iso" ]]; then
        mv "$SEED_ISO.iso" "$SEED_ISO"
    fi
else
    write_result "skipped" "no supported NoCloud seed-media creator"
    exit 2
fi
if [[ ! -f "$SEED_ISO" ]]; then
    write_result "failed" "NoCloud seed-media creation produced no image"
    exit 1
fi

if [[ -n "${STEAMOS_HEADLESS_VM_FIRMWARE_DIR:-}" ]]; then
    FIRMWARE_DIR="$STEAMOS_HEADLESS_VM_FIRMWARE_DIR"
elif command -v brew >/dev/null 2>&1; then
    FIRMWARE_DIR="$(brew --prefix qemu)/share/qemu"
else
    write_result "skipped" "x86_64 UEFI firmware directory is unavailable"
    exit 2
fi
UEFI_CODE="$FIRMWARE_DIR/edk2-x86_64-code.fd"
UEFI_VARS_TEMPLATE="$FIRMWARE_DIR/edk2-i386-vars.fd"
if [[ ! -f "$UEFI_CODE" || ! -f "$UEFI_VARS_TEMPLATE" ]]; then
    write_result "skipped" "required x86_64 UEFI firmware files are unavailable"
    exit 2
fi
cp "$UEFI_VARS_TEMPLATE" "$UEFI_VARS"

qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OVERLAY"
qemu-img create -q -f raw "$SYNTHETIC_DISK" "$SYNTHETIC_BYTES"
qemu-img create -q -f raw "$UNEXPECTED_DISK" "$SYNTHETIC_BYTES"

qemu-system-x86_64 \
    -machine q35,accel=tcg \
    -cpu max \
    -smp 2 \
    -m 2048 \
    -display none \
    -monitor none \
    -serial "file:$SERIAL_LOG" \
    -nic none \
    -no-reboot \
    -drive "if=pflash,format=raw,readonly=on,file=$UEFI_CODE" \
    -drive "if=pflash,format=raw,readonly=off,file=$UEFI_VARS" \
    -drive "if=virtio,format=qcow2,readonly=off,file=$OVERLAY" \
    -drive "if=none,id=synthetic,format=raw,readonly=off,file=$SYNTHETIC_DISK" \
    -device "virtio-blk-pci,drive=synthetic,serial=STEAMOS_SYNTH_V1" \
    -drive "if=none,id=unexpected,format=raw,readonly=off,file=$UNEXPECTED_DISK" \
    -device "virtio-blk-pci,drive=unexpected,serial=STEAMOS_WRONG_V1" \
    -drive "if=virtio,media=cdrom,format=raw,readonly=on,file=$SEED_ISO" &
QEMU_PID="$!"

deadline=$((SECONDS + TIMEOUT_SECONDS))
while kill -0 "$QEMU_PID" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
        write_result "failed" "guest timed out before emitting a result"
        exit 1
    fi
    sleep 1
done
wait "$QEMU_PID" || true
QEMU_PID=""

RESULT_LINE="$(grep -ao 'STEAMOS_HEADLESS_RESULT {[^}]*}' "$SERIAL_LOG" | tail -n 1 || true)"
if [[ -z "$RESULT_LINE" ]]; then
    write_result "failed" "guest emitted no machine-readable result"
    exit 1
fi
GUEST_RESULT="$RUNTIME/guest-result.json"
printf '%s\n' "${RESULT_LINE#STEAMOS_HEADLESS_RESULT }" > "$GUEST_RESULT"
grep -ao 'STEAMOS_HEADLESS_PROGRESS {[^}]*}' "$SERIAL_LOG" | sed 's/^STEAMOS_HEADLESS_PROGRESS //' > "$RUNTIME/progress.jsonl"
node "$SCRIPT_DIR/validate-result.mjs" "$GUEST_RESULT" "$RUNTIME/progress.jsonl"
STAGED_RESULT="$(mktemp "$RESULT_ROOT/.latest.XXXXXX")"
cp "$GUEST_RESULT" "$STAGED_RESULT"
chmod 0600 "$STAGED_RESULT"
mv -f -- "$STAGED_RESULT" "$RESULT_PATH"
RUN_COMPLETE=1
printf 'Headless VM harness passed; result: %s\n' "$RESULT_PATH"

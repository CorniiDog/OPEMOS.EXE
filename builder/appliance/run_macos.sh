#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="steamos-nvidia-image-builder"

SCRIPT_DIR="$(
    cd "$(dirname "${BASH_SOURCE[0]}")"
    pwd
)"

CLOUD_INIT_DIR="${SCRIPT_DIR}/cloud-init"
USER_DATA="${CLOUD_INIT_DIR}/user-data"
META_DATA="${CLOUD_INIT_DIR}/meta-data"
SSH_PORT="2222"
REQUESTED_ARCH="native"
RESOLVE_ONLY=0

log()
{
    printf '[%s] %s\n' "$PROJECT_NAME" "$*"
}

die()
{
    printf '[%s] ERROR: %s\n' "$PROJECT_NAME" "$*" >&2
    exit 1
}

usage()
{
    cat <<EOF
Usage: ./builder/appliance/run_macos.sh [options]

Options:
      --architecture ARCH  native, aarch64, or x86_64 (default: native)
      --ssh-port PORT       Host SSH forwarding port (default: 2222)
      --resolve-only        Print the resolved launch plan without starting QEMU
  -h, --help               Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --architecture)
            [[ $# -ge 2 ]] || die "$1 requires a value."
            REQUESTED_ARCH="$2"
            shift 2
            ;;
        --ssh-port)
            [[ $# -ge 2 ]] || die "$1 requires a value."
            SSH_PORT="$2"
            shift 2
            ;;
        --resolve-only)
            RESOLVE_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown argument: $1"
            ;;
    esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
    die "This launcher currently supports macOS only."
fi

[[ "$SSH_PORT" =~ ^[0-9]+$ ]] && (( SSH_PORT >= 1 && SSH_PORT <= 65535 )) ||
    die "--ssh-port must be between 1 and 65535."

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    arm64) NATIVE_GUEST_ARCH="aarch64" ;;
    x86_64) NATIVE_GUEST_ARCH="x86_64" ;;
    *) die "Unsupported macOS architecture: ${HOST_ARCH}" ;;
esac

case "$REQUESTED_ARCH" in
    native)
        GUEST_ARCH="$NATIVE_GUEST_ARCH"
        APPLIANCE_IMAGE="${SCRIPT_DIR}/fedora-builder.qcow2"
        RUNTIME_DIR="${SCRIPT_DIR}/runtime"
        ;;
    aarch64|x86_64)
        GUEST_ARCH="$REQUESTED_ARCH"
        APPLIANCE_IMAGE="${SCRIPT_DIR}/fedora-builder-${GUEST_ARCH}.qcow2"
        RUNTIME_DIR="${SCRIPT_DIR}/runtime-${GUEST_ARCH}"
        ;;
    *)
        die "--architecture must be native, aarch64, or x86_64."
        ;;
esac

if [[ "$GUEST_ARCH" == "$NATIVE_GUEST_ARCH" ]]; then
    ACCELERATOR="hvf"
    CPU_MODEL="host"
else
    ACCELERATOR="tcg"
    CPU_MODEL="max"
fi

case "$GUEST_ARCH" in
    aarch64)
        QEMU_BINARY="qemu-system-aarch64"
        MACHINE="virt,accel=${ACCELERATOR}"
        UEFI_CODE_NAME="edk2-aarch64-code.fd"
        UEFI_VARS_NAME="edk2-arm-vars.fd"
        ;;
    x86_64)
        QEMU_BINARY="qemu-system-x86_64"
        MACHINE="q35,accel=${ACCELERATOR}"
        UEFI_CODE_NAME="edk2-x86_64-code.fd"
        UEFI_VARS_NAME="edk2-i386-vars.fd"
        ;;
esac

if [[ "$RESOLVE_ONLY" == "1" ]]; then
    python3 - "$HOST_ARCH" "$GUEST_ARCH" "$QEMU_BINARY" "$MACHINE" \
        "$CPU_MODEL" "$APPLIANCE_IMAGE" "$RUNTIME_DIR" "$SSH_PORT" <<'PY'
import json
import sys

keys = (
    "hostArchitecture",
    "guestArchitecture",
    "qemuBinary",
    "machine",
    "cpuModel",
    "appliancePath",
    "runtimePath",
    "sshPort",
)
print(json.dumps(
    {"schemaVersion": 1, "status": "ready", "launch": dict(zip(keys, sys.argv[1:]))},
    sort_keys=True,
    separators=(",", ":"),
))
PY
    exit 0
fi

RUNTIME_CLOUD_INIT_DIR="${RUNTIME_DIR}/cloud-init"
RUNTIME_USER_DATA="${RUNTIME_CLOUD_INIT_DIR}/user-data"
RUNTIME_META_DATA="${RUNTIME_CLOUD_INIT_DIR}/meta-data"
SSH_PRIVATE_KEY="${RUNTIME_DIR}/builder_key"
SSH_PUBLIC_KEY="${RUNTIME_DIR}/builder_key.pub"

SEED_IMAGE="${RUNTIME_DIR}/seed.iso"
VARS_IMAGE="${RUNTIME_DIR}/uefi-vars.fd"
RUNTIME_DISK="${RUNTIME_DIR}/session.qcow2"

[[ -f "$APPLIANCE_IMAGE" ]] ||
    die "Builder appliance not found: ${APPLIANCE_IMAGE}"

[[ -f "$USER_DATA" ]] ||
    die "Cloud-init user-data not found."

[[ -f "$META_DATA" ]] ||
    die "Cloud-init meta-data not found."

command -v brew >/dev/null 2>&1 ||
    die "Homebrew is required."

command -v qemu-img >/dev/null 2>&1 ||
    die "qemu-img is required."

mkdir -p "$RUNTIME_DIR"
mkdir -p "$RUNTIME_CLOUD_INIT_DIR"

#
# Generate runtime SSH identity.
#

if [[ ! -f "$SSH_PRIVATE_KEY" ]]; then
    log "Generating builder SSH identity..."

    ssh-keygen         -q         -t ed25519         -N ""         -f "$SSH_PRIVATE_KEY"
fi

BUILDER_PUBLIC_KEY="$(cat "$SSH_PUBLIC_KEY")"

#
# Build runtime cloud-init configuration.
#

cp "$META_DATA" "$RUNTIME_META_DATA"

python3 -c 'from pathlib import Path; import sys; source=Path(sys.argv[1]).read_text(); key=sys.argv[3]; marker="    lock_passwd: true\n"; assert marker in source; source=source.replace(marker, marker+"    ssh_authorized_keys:\n      - "+key+"\n", 1); Path(sys.argv[2]).write_text(source)'     "$USER_DATA"     "$RUNTIME_USER_DATA"     "$BUILDER_PUBLIC_KEY"

#
# Create a disposable writable overlay.
#

log "Creating disposable appliance overlay..."

rm -f "$RUNTIME_DISK"

qemu-img create     -f qcow2     -F qcow2     -b "$APPLIANCE_IMAGE"     "$RUNTIME_DISK"


#
# Create cloud-init NoCloud seed image.
#

log "Creating cloud-init seed image..."

rm -f "$SEED_IMAGE"

hdiutil makehybrid \
    -quiet \
    -iso \
    -joliet \
    -default-volume-name cidata \
    -o "$SEED_IMAGE" \
    "$RUNTIME_CLOUD_INIT_DIR"

#
# hdiutil may append .iso automatically depending on macOS behavior.
#

if [[ ! -f "$SEED_IMAGE" ]] &&
   [[ -f "${SEED_IMAGE}.iso" ]]; then
    mv "${SEED_IMAGE}.iso" "$SEED_IMAGE"
fi

[[ -f "$SEED_IMAGE" ]] ||
    die "Cloud-init seed image was not created."

#
# Determine QEMU firmware.
#

QEMU_SHARE="$(brew --prefix qemu)/share/qemu"
UEFI_CODE="${QEMU_SHARE}/${UEFI_CODE_NAME}"
UEFI_VARS_TEMPLATE="${QEMU_SHARE}/${UEFI_VARS_NAME}"

command -v "$QEMU_BINARY" >/dev/null 2>&1 ||
    die "${QEMU_BINARY} is not available."

[[ -f "$UEFI_CODE" ]] ||
    die "UEFI firmware not found: ${UEFI_CODE}"

[[ -f "$UEFI_VARS_TEMPLATE" ]] ||
    die "UEFI variables template not found: ${UEFI_VARS_TEMPLATE}"

#
# Each VM run gets its own writable UEFI variable store.
#

cp "$UEFI_VARS_TEMPLATE" "$VARS_IMAGE"

log "QEMU: $("$QEMU_BINARY" --version | head -n 1)"
log "Appliance: ${APPLIANCE_IMAGE}"
log "Guest architecture: ${GUEST_ARCH} (${ACCELERATOR})"
log "SSH: localhost:${SSH_PORT}"
log ""
log "Fedora login:"
log "  user: builder"
log "  authentication: per-session SSH key only"
log ""
log "Starting Fedora builder appliance..."
log "Press Ctrl+A, then X to exit QEMU."
log ""

#
# Launch
#

if [[ "$GUEST_ARCH" == "aarch64" ]]; then
    exec "$QEMU_BINARY" \
        -name "SteamOS NVIDIA Builder" \
        -machine "$MACHINE" \
        -cpu "$CPU_MODEL" \
        -smp 4 \
        -m 4096 \
        -drive "file=${UEFI_CODE},if=pflash,format=raw,readonly=on" \
        -drive "file=${VARS_IMAGE},if=pflash,format=raw" \
        -drive "file=${RUNTIME_DISK},if=virtio,format=qcow2" \
        -drive "file=${SEED_IMAGE},if=virtio,format=raw,readonly=on" \
        -device virtio-rng-pci \
        -device virtio-net-pci,netdev=net0 \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
        -display none \
        -monitor none \
        -serial mon:stdio
else
    exec "$QEMU_BINARY" \
        -name "SteamOS NVIDIA Builder" \
        -machine "$MACHINE" \
        -cpu "$CPU_MODEL" \
        -smp 4 \
        -m 4096 \
        -drive "file=${UEFI_CODE},if=pflash,format=raw,readonly=on" \
        -drive "file=${VARS_IMAGE},if=pflash,format=raw" \
        -drive "file=${RUNTIME_DISK},if=virtio,format=qcow2" \
        -drive "file=${SEED_IMAGE},if=virtio,format=raw,readonly=on" \
        -device virtio-rng-pci \
        -device virtio-net-pci,netdev=net0 \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
        -display none \
        -monitor none \
        -serial mon:stdio
fi

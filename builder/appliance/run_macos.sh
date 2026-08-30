#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="steamos-nvidia-image-builder"

SCRIPT_DIR="$(
    cd "$(dirname "${BASH_SOURCE[0]}")"
    pwd
)"

APPLIANCE_IMAGE="${SCRIPT_DIR}/fedora-builder.qcow2"

CLOUD_INIT_DIR="${SCRIPT_DIR}/cloud-init"
USER_DATA="${CLOUD_INIT_DIR}/user-data"
META_DATA="${CLOUD_INIT_DIR}/meta-data"

RUNTIME_DIR="${SCRIPT_DIR}/runtime"
SEED_IMAGE="${RUNTIME_DIR}/seed.iso"
VARS_IMAGE="${RUNTIME_DIR}/uefi-vars.fd"

SSH_PORT="2222"

log()
{
    printf '[%s] %s\n' "$PROJECT_NAME" "$*"
}

die()
{
    printf '[%s] ERROR: %s\n' "$PROJECT_NAME" "$*" >&2
    exit 1
}

if [[ "$(uname -s)" != "Darwin" ]]; then
    die "This launcher currently supports macOS only."
fi

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
    "$CLOUD_INIT_DIR"

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
# Determine architecture and QEMU firmware.
#

case "$(uname -m)" in
    arm64)
        QEMU_BINARY="qemu-system-aarch64"

        QEMU_SHARE="$(
            brew --prefix qemu
        )/share/qemu"

        UEFI_CODE="${QEMU_SHARE}/edk2-aarch64-code.fd"
        UEFI_VARS_TEMPLATE="${QEMU_SHARE}/edk2-arm-vars.fd"

        ;;

    x86_64)
        QEMU_BINARY="qemu-system-x86_64"

        QEMU_SHARE="$(
            brew --prefix qemu
        )/share/qemu"

        UEFI_CODE="${QEMU_SHARE}/edk2-x86_64-code.fd"
        UEFI_VARS_TEMPLATE="${QEMU_SHARE}/edk2-i386-vars.fd"

        ;;

    *)
        die "Unsupported macOS architecture: $(uname -m)"
        ;;
esac

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
log "SSH: localhost:${SSH_PORT}"
log ""
log "Fedora login:"
log "  user: builder"
log "  password: builder"
log ""
log "Starting Fedora builder appliance..."
log "Press Ctrl+A, then X to exit QEMU."
log ""

#
# Launch
#

if [[ "$(uname -m)" == "arm64" ]]; then
    exec "$QEMU_BINARY" \
        -name "SteamOS NVIDIA Builder" \
        -machine virt,accel=hvf \
        -cpu host \
        -smp 4 \
        -m 4096 \
        -drive "file=${UEFI_CODE},if=pflash,format=raw,readonly=on" \
        -drive "file=${VARS_IMAGE},if=pflash,format=raw" \
        -drive "file=${APPLIANCE_IMAGE},if=virtio,format=qcow2" \
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
        -machine q35,accel=hvf \
        -cpu host \
        -smp 4 \
        -m 4096 \
        -drive "file=${UEFI_CODE},if=pflash,format=raw,readonly=on" \
        -drive "file=${VARS_IMAGE},if=pflash,format=raw" \
        -drive "file=${APPLIANCE_IMAGE},if=virtio,format=qcow2" \
        -drive "file=${SEED_IMAGE},if=virtio,format=raw,readonly=on" \
        -device virtio-rng-pci \
        -device virtio-net-pci,netdev=net0 \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
        -display none \
        -monitor none \
        -serial mon:stdio
fi
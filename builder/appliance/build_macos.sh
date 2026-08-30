#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="steamos-nvidia-image-builder"

SCRIPT_DIR="$(
    cd "$(dirname "${BASH_SOURCE[0]}")"
    pwd
)"

WORK_DIR="${SCRIPT_DIR}/work"
OUTPUT_IMAGE="${SCRIPT_DIR}/fedora-builder.qcow2"

FEDORA_RELEASE="44"
FEDORA_COMPOSE="1.7"

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
    die "This appliance builder currently supports macOS only."
fi

case "$(uname -m)" in
    arm64)
        FEDORA_ARCH="aarch64"
        IMAGE_NAME="Fedora-Cloud-Base-Generic-${FEDORA_RELEASE}-${FEDORA_COMPOSE}.aarch64.qcow2"
        CHECKSUM_NAME="Fedora-Cloud-${FEDORA_RELEASE}-${FEDORA_COMPOSE}-aarch64-CHECKSUM"
        ;;

    x86_64)
        FEDORA_ARCH="x86_64"
        IMAGE_NAME="Fedora-Cloud-Base-Generic-${FEDORA_RELEASE}-${FEDORA_COMPOSE}.x86_64.qcow2"
        CHECKSUM_NAME="Fedora-Cloud-${FEDORA_RELEASE}-${FEDORA_COMPOSE}-x86_64-CHECKSUM"
        ;;

    *)
        die "Unsupported macOS architecture: $(uname -m)"
        ;;
esac

BASE_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/${FEDORA_RELEASE}/Cloud/${FEDORA_ARCH}/images"

IMAGE_URL="${BASE_URL}/${IMAGE_NAME}"
CHECKSUM_URL="${BASE_URL}/${CHECKSUM_NAME}"
FEDORA_GPG_URL="https://fedoraproject.org/fedora.gpg"

mkdir -p "$WORK_DIR"

IMAGE_PATH="${WORK_DIR}/${IMAGE_NAME}"
CHECKSUM_PATH="${WORK_DIR}/${CHECKSUM_NAME}"
GPG_PATH="${WORK_DIR}/fedora.gpg"

log "Fedora release: ${FEDORA_RELEASE}"
log "Architecture: ${FEDORA_ARCH}"

if [[ ! -f "$IMAGE_PATH" ]]; then
    log "Downloading Fedora Cloud image..."

    curl \
        --fail \
        --location \
        --progress-bar \
        --output "$IMAGE_PATH" \
        "$IMAGE_URL"
else
    log "Fedora Cloud image already downloaded."
fi

log "Downloading Fedora checksum..."

curl \
    --fail \
    --location \
    --silent \
    --show-error \
    --output "$CHECKSUM_PATH" \
    "$CHECKSUM_URL"

log "Downloading Fedora signing keys..."

curl \
    --fail \
    --location \
    --silent \
    --show-error \
    --output "$GPG_PATH" \
    "$FEDORA_GPG_URL"

if command -v gpgv >/dev/null 2>&1; then
    log "Verifying Fedora checksum signature..."

    VERIFIED_CHECKSUM="${WORK_DIR}/verified-checksum.txt"

    gpgv \
        --keyring "$GPG_PATH" \
        --output "$VERIFIED_CHECKSUM" \
        "$CHECKSUM_PATH"

    log "Verifying image SHA256..."

    (
        cd "$WORK_DIR"

        grep "$IMAGE_NAME" "$VERIFIED_CHECKSUM" |
            shasum -a 256 -c -
    )
else
    log "gpgv not found."
    log "Falling back to checksum verification without signature validation."

    (
        cd "$WORK_DIR"

        grep "$IMAGE_NAME" "$CHECKSUM_PATH" |
            shasum -a 256 -c -
    )
fi

log "Preparing builder appliance..."

rm -f "$OUTPUT_IMAGE"

cp "$IMAGE_PATH" "$OUTPUT_IMAGE"

log "Validating qcow2 image..."

qemu-img check "$OUTPUT_IMAGE"

log "Builder appliance created:"
log "$OUTPUT_IMAGE"
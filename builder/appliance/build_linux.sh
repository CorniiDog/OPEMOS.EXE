#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="steamos-nvidia-image-builder"

SCRIPT_DIR="$(
    cd "$(dirname "${BASH_SOURCE[0]}")"
    pwd
)"

WORK_DIR="${SCRIPT_DIR}/work"

FEDORA_RELEASE="44"
FEDORA_COMPOSE="1.7"
REQUESTED_ARCH="native"
OUTPUT_IMAGE=""
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
Usage: ./builder/appliance/build_linux.sh [options]

Download and verify a Fedora Cloud base appliance.

Options:
      --architecture ARCH  native, aarch64, or x86_64 (default: native)
      --output FILE        Override the output qcow2 path
      --resolve-only       Print the resolved appliance plan without downloads
  -h, --help               Show this help

An explicit non-native architecture uses a separately named appliance so it
cannot replace the fast native appliance by accident.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --architecture)
            [[ $# -ge 2 ]] || die "$1 requires a value."
            REQUESTED_ARCH="$2"
            shift 2
            ;;
        --output)
            [[ $# -ge 2 ]] || die "$1 requires a file."
            OUTPUT_IMAGE="$2"
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

if [[ "$(uname -s)" != "Linux" ]]; then
    die "This appliance builder supports Linux only."
fi

HOST_ARCH="$(uname -m)"

case "$HOST_ARCH" in
    arm64)
        NATIVE_FEDORA_ARCH="aarch64"
        ;;

    x86_64)
        NATIVE_FEDORA_ARCH="x86_64"
        ;;

    *)
        die "Unsupported Linux architecture: ${HOST_ARCH}"
        ;;
esac

case "$REQUESTED_ARCH" in
    native)
        FEDORA_ARCH="$NATIVE_FEDORA_ARCH"
        DEFAULT_OUTPUT_IMAGE="${SCRIPT_DIR}/fedora-builder.qcow2"
        ;;
    aarch64|x86_64)
        FEDORA_ARCH="$REQUESTED_ARCH"
        DEFAULT_OUTPUT_IMAGE="${SCRIPT_DIR}/fedora-builder-${FEDORA_ARCH}.qcow2"
        ;;
    *)
        die "--architecture must be native, aarch64, or x86_64."
        ;;
esac

if [[ -z "$OUTPUT_IMAGE" ]]; then
    OUTPUT_IMAGE="$DEFAULT_OUTPUT_IMAGE"
fi

IMAGE_NAME="Fedora-Cloud-Base-Generic-${FEDORA_RELEASE}-${FEDORA_COMPOSE}.${FEDORA_ARCH}.qcow2"
CHECKSUM_NAME="Fedora-Cloud-${FEDORA_RELEASE}-${FEDORA_COMPOSE}-${FEDORA_ARCH}-CHECKSUM"

BASE_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/${FEDORA_RELEASE}/Cloud/${FEDORA_ARCH}/images"

IMAGE_URL="${BASE_URL}/${IMAGE_NAME}"
CHECKSUM_URL="${BASE_URL}/${CHECKSUM_NAME}"
FEDORA_GPG_URL="https://fedoraproject.org/fedora.gpg"

IMAGE_PATH="${WORK_DIR}/${IMAGE_NAME}"
CHECKSUM_PATH="${WORK_DIR}/${CHECKSUM_NAME}"
GPG_PATH="${WORK_DIR}/fedora.gpg"

if [[ "$RESOLVE_ONLY" == "1" ]]; then
    python3 - "$HOST_ARCH" "$FEDORA_ARCH" "$FEDORA_RELEASE" "$FEDORA_COMPOSE" \
        "$IMAGE_NAME" "$CHECKSUM_NAME" "$OUTPUT_IMAGE" "$IMAGE_URL" "$CHECKSUM_URL" <<'PY'
import json
import sys

keys = (
    "hostArchitecture",
    "applianceArchitecture",
    "fedoraRelease",
    "fedoraCompose",
    "imageName",
    "checksumName",
    "outputPath",
    "imageUrl",
    "checksumUrl",
)
print(json.dumps(
    {"schemaVersion": 1, "status": "ready", "appliance": dict(zip(keys, sys.argv[1:]))},
    sort_keys=True,
    separators=(",", ":"),
))
PY
    exit 0
fi

for tool in curl gpgv qemu-img sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || die "Required tool not found: $tool"
done

mkdir -p "$WORK_DIR"

log "Fedora release: ${FEDORA_RELEASE}"
log "Host architecture: ${HOST_ARCH}"
log "Architecture: ${FEDORA_ARCH}"
log "Output: ${OUTPUT_IMAGE}"

mkdir -p "$(dirname "$OUTPUT_IMAGE")"

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

SIGNATURE_VERIFIED=0
log "Verifying Fedora checksum signature..."

VERIFIED_CHECKSUM="${WORK_DIR}/verified-checksum-${FEDORA_ARCH}.txt"

gpgv \
    --keyring "$GPG_PATH" \
    --output "$VERIFIED_CHECKSUM" \
    "$CHECKSUM_PATH"
SIGNATURE_VERIFIED=1

CHECKSUM_LINE_PREFIX="SHA256 (${IMAGE_NAME}) = "
mapfile -t IMAGE_CHECKSUM_LINES < <(grep -F "$CHECKSUM_LINE_PREFIX" "$VERIFIED_CHECKSUM")
[[ "${#IMAGE_CHECKSUM_LINES[@]}" == "1" ]] || \
    die "Signed checksum did not contain exactly one entry for ${IMAGE_NAME}."
EXPECTED_IMAGE_SHA256="${IMAGE_CHECKSUM_LINES[0]#"$CHECKSUM_LINE_PREFIX"}"
[[ "$EXPECTED_IMAGE_SHA256" =~ ^[0-9a-f]{64}$ ]] || \
    die "Signed checksum contained an invalid SHA-256 for ${IMAGE_NAME}."

verify_image()
{
    local candidate="$1"
    local actual_sha256
    actual_sha256="$(sha256sum "$candidate" | awk '{ print $1 }')"
    [[ "$actual_sha256" == "$EXPECTED_IMAGE_SHA256" ]]
}

DOWNLOAD_TEMP="${IMAGE_PATH}.download.partial"
cleanup_download()
{
    rm -f "$DOWNLOAD_TEMP"
}
trap cleanup_download EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cleanup_download

if [[ -f "$IMAGE_PATH" ]] && verify_image "$IMAGE_PATH"; then
    log "Authenticated Fedora Cloud image cache is valid."
else
    if [[ -f "$IMAGE_PATH" ]]; then
        log "Cached Fedora Cloud image is invalid; downloading an authenticated replacement."
    else
        log "Downloading Fedora Cloud image..."
    fi
    curl \
        --fail \
        --location \
        --progress-bar \
        --output "$DOWNLOAD_TEMP" \
        "$IMAGE_URL"
    verify_image "$DOWNLOAD_TEMP" || \
        die "Downloaded Fedora Cloud image did not match the signed checksum."
    mv "$DOWNLOAD_TEMP" "$IMAGE_PATH"
fi
trap - EXIT INT TERM

log "Verifying image SHA256..."
verify_image "$IMAGE_PATH" || die "Fedora Cloud image did not match the signed checksum."

log "Preparing builder appliance..."

OUTPUT_TEMP="${OUTPUT_IMAGE}.partial"
METADATA_PATH="${OUTPUT_IMAGE}.metadata.json"
METADATA_TEMP="${METADATA_PATH}.partial"
cleanup_partial_outputs()
{
    rm -f "$OUTPUT_TEMP" "$METADATA_TEMP"
}
trap cleanup_partial_outputs EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cleanup_partial_outputs

cp "$IMAGE_PATH" "$OUTPUT_TEMP"

log "Validating qcow2 image..."

qemu-img check "$OUTPUT_TEMP"

IMAGE_SHA256="$(sha256sum "$IMAGE_PATH" | awk '{ print $1 }')"
CHECKSUM_SHA256="$(sha256sum "$CHECKSUM_PATH" | awk '{ print $1 }')"
KEYRING_SHA256="$(sha256sum "$GPG_PATH" | awk '{ print $1 }')"
python3 - "$METADATA_TEMP" "$FEDORA_RELEASE" "$FEDORA_COMPOSE" "$FEDORA_ARCH" \
    "$IMAGE_NAME" "$IMAGE_URL" "$IMAGE_SHA256" "$CHECKSUM_NAME" "$CHECKSUM_URL" \
    "$CHECKSUM_SHA256" "$FEDORA_GPG_URL" "$KEYRING_SHA256" "$SIGNATURE_VERIFIED" <<'PY'
import json
import os
import sys

(
    output,
    release,
    compose,
    architecture,
    image_name,
    image_url,
    image_sha256,
    checksum_name,
    checksum_url,
    checksum_sha256,
    key_url,
    keyring_sha256,
    signature_verified,
) = sys.argv[1:]
document = {
    "schemaVersion": 1,
    "applianceProtocolVersion": 1,
    "fedora": {
        "release": release,
        "compose": compose,
        "architecture": architecture,
        "imageName": image_name,
        "imageUrl": image_url,
        "imageSha256": image_sha256,
        "checksumName": checksum_name,
        "checksumUrl": checksum_url,
        "checksumSha256": checksum_sha256,
        "signingKeyUrl": key_url,
        "signingKeyringSha256": keyring_sha256,
        "checksumSignatureVerified": signature_verified == "1",
    },
}
with open(output, "x", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
PY
mv "$OUTPUT_TEMP" "$OUTPUT_IMAGE"
mv "$METADATA_TEMP" "$METADATA_PATH"
trap - EXIT INT TERM

log "Builder appliance created:"
log "$OUTPUT_IMAGE"
log "Provenance metadata:"
log "$METADATA_PATH"

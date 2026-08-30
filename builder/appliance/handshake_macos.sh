#!/usr/bin/env bash
set -euo pipefail

SSH_PORT="2222"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_KEY="${SCRIPT_DIR}/runtime/builder_key"
EXPECTED="SteamOS NVIDIA Image Builder appliance
READY"

OUTPUT="$(
    ssh         -p "$SSH_PORT"         -i "$SSH_KEY"         -o IdentitiesOnly=yes         -o BatchMode=yes         -o ConnectTimeout=2         -o StrictHostKeyChecking=no         -o UserKnownHostsFile=/dev/null         builder@127.0.0.1         "cat /etc/steamos-builder-ready"         2>/dev/null
)" || {
    echo "Builder handshake failed."
    exit 1
}

if [[ "$OUTPUT" != "$EXPECTED" ]]; then
    echo "Builder handshake returned unexpected response:"
    printf "%s\n" "$OUTPUT"
    exit 1
fi

echo "STEAMOS_BUILDER_READY"

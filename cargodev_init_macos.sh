#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="steamos-nvidia-image-builder"

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
    die "This setup script currently supports macOS only."
fi

[[ -f package.json ]] ||
    die "Run this script from the ${PROJECT_NAME} repository root."

log "Checking macOS development environment..."

if ! xcode-select -p >/dev/null 2>&1; then
    log "Xcode Command Line Tools are required."
    log "Opening Apple's installer..."

    xcode-select --install || true

    echo
    log "Finish installing the Xcode Command Line Tools, then run this script again."
    exit 0
fi

log "Xcode Command Line Tools found."

if ! command -v rustup >/dev/null 2>&1; then
    log "Rust is not installed."
    log "Installing Rust using rustup..."

    curl --proto '=https' \
        --tlsv1.2 \
        -sSf \
        https://sh.rustup.rs |
        sh -s -- -y
fi

if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
fi

command -v cargo >/dev/null 2>&1 ||
    die "Cargo was installed but is not available in PATH."

command -v rustc >/dev/null 2>&1 ||
    die "rustc was installed but is not available in PATH."

command -v node >/dev/null 2>&1 ||
    die "Node.js is required. Install Node.js, then run this script again."

command -v npm >/dev/null 2>&1 ||
    die "npm is required. Install Node.js/npm, then run this script again."

log "Rust: $(rustc --version)"
log "Cargo: $(cargo --version)"
log "Node: $(node --version)"
log "npm:  $(npm --version)"

if [[ ! -d node_modules ]]; then
    log "Installing JavaScript dependencies..."

    if [[ -f package-lock.json ]]; then
        npm ci
    else
        npm install
    fi
else
    log "JavaScript dependencies already present."
fi

log "Starting Tauri development mode..."
exec npm run dev
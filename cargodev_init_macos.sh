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

#
# Xcode Command Line Tools
#

if ! xcode-select -p >/dev/null 2>&1; then
    log "Xcode Command Line Tools are required."
    log "Opening Apple's installer..."

    xcode-select --install || true

    echo
    log "Finish installing the Xcode Command Line Tools, then run this script again."
    exit 0
fi

log "Xcode Command Line Tools found."

#
# Homebrew
#

if ! command -v brew >/dev/null 2>&1; then
    log "Homebrew is not installed."
    log "Installing Homebrew..."

    NONINTERACTIVE=1 /bin/bash -c \
        "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

#
# Homebrew may have just been installed, so load its environment.
#

if [[ -x /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
elif [[ -x /usr/local/bin/brew ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
fi

command -v brew >/dev/null 2>&1 ||
    die "Homebrew was installed but is not available in PATH."

log "Homebrew: $(brew --version | head -n 1)"

#
# Node.js / npm
#

if ! command -v node >/dev/null 2>&1 ||
   ! command -v npm >/dev/null 2>&1; then

    log "Node.js/npm are not installed."
    log "Installing Node.js..."

    brew install node
fi

command -v node >/dev/null 2>&1 ||
    die "Node.js was installed but is not available in PATH."

command -v npm >/dev/null 2>&1 ||
    die "npm was installed but is not available in PATH."

#
# Rust / Cargo
#

if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
fi

if ! command -v rustup >/dev/null 2>&1; then
    log "Rust is not installed."
    log "Installing Rust using rustup..."

    curl --proto '=https' \
        --tlsv1.2 \
        -sSf \
        https://sh.rustup.rs |
        sh -s -- -y

    if [[ -f "${HOME}/.cargo/env" ]]; then
        # shellcheck disable=SC1091
        source "${HOME}/.cargo/env"
    fi
fi

command -v cargo >/dev/null 2>&1 ||
    die "Cargo was installed but is not available in PATH."

command -v rustc >/dev/null 2>&1 ||
    die "rustc was installed but is not available in PATH."
    
#
# QEMU
#

case "$(uname -m)" in
    arm64)
        QEMU_BINARY="qemu-system-aarch64"
        ;;
    x86_64)
        QEMU_BINARY="qemu-system-x86_64"
        ;;
    *)
        die "Unsupported macOS architecture: $(uname -m)"
        ;;
esac

if ! command -v "$QEMU_BINARY" >/dev/null 2>&1; then
    log "QEMU is not installed."
    log "Installing QEMU..."

    brew install qemu
fi

command -v "$QEMU_BINARY" >/dev/null 2>&1 ||
    die "QEMU was installed but ${QEMU_BINARY} is not available in PATH."

#
# Environment summary
#

log "Rust: $(rustc --version)"
log "Cargo: $(cargo --version)"
log "Node: $(node --version)"
log "npm:  $(npm --version)"
log "QEMU: $("$QEMU_BINARY" --version | head -n 1)"

#
# JavaScript dependencies
#

if [[ ! -d node_modules ]]; then
    log "Installing project JavaScript dependencies..."

    if [[ -f package-lock.json ]]; then
        npm ci
    else
        npm install
    fi
else
    log "JavaScript dependencies already present."
fi

#
# Launch
#

#
# Stop stale development instance
#

if pgrep -f "target/debug/${PROJECT_NAME}" >/dev/null 2>&1 ||
   pgrep -f "tauri dev" >/dev/null 2>&1; then

    log "Stopping existing development instance..."

    pkill -f "target/debug/${PROJECT_NAME}" 2>/dev/null || true
    pkill -f "tauri dev" 2>/dev/null || true

    sleep 1
fi

log "Starting Tauri development mode..."

exec npm run dev

#
# Stop stale development instance
#

if pgrep -f "target/debug/${PROJECT_NAME}" >/dev/null 2>&1 ||
   pgrep -f "tauri dev" >/dev/null 2>&1; then

    log "Stopping existing development instance..."

    pkill -f "target/debug/${PROJECT_NAME}" 2>/dev/null || true
    pkill -f "tauri dev" 2>/dev/null || true

    sleep 1
fi

#
# Launch
#

log "Starting Tauri development mode..."

exec npm run dev
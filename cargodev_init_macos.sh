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

version_pair()
{
    printf '%s\n' "$1" |
        sed -E 's/^[^0-9]*([0-9]+)(\.([0-9]+))?.*/\1 \3/' |
        awk '{ print $1, ($2 == "" ? 0 : $2) }'
}

require_minimum_version()
{
    local label="$1"
    local actual="$2"
    local minimum_major="$3"
    local minimum_minor="$4"
    local remediation="$5"
    local parsed actual_major actual_minor

    parsed="$(version_pair "$actual")"
    read -r actual_major actual_minor <<<"$parsed"
    [[ "$actual_major" =~ ^[0-9]+$ && "$actual_minor" =~ ^[0-9]+$ ]] ||
        die "Could not parse ${label} version from: ${actual}. ${remediation}"
    if (( actual_major < minimum_major ||
          (actual_major == minimum_major && actual_minor < minimum_minor) )); then
        die "${label} ${minimum_major}.${minimum_minor}+ is required; found ${actual}. ${remediation}"
    fi
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

CLT_VERSION="$(pkgutil --pkg-info=com.apple.pkg.CLTools_Executables 2>/dev/null |
    awk '/^version:/ { print $2; exit }')"
[[ -n "$CLT_VERSION" ]] ||
    die "Xcode Command Line Tools are present but their package version is unavailable. Run 'xcode-select --install' again."
log "Xcode Command Line Tools: $CLT_VERSION"

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

HOMEBREW_VERSION="$(brew --version | head -n 1)"
require_minimum_version "Homebrew" "$HOMEBREW_VERSION" 4 0 "Run 'brew update'."
log "Homebrew: $HOMEBREW_VERSION"

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
# Fast, multithreaded SteamOS image decompression
#

if ! command -v 7zz >/dev/null 2>&1; then
    log "7-Zip is not installed."
    log "Installing sevenzip..."

    brew install sevenzip
fi

command -v 7zz >/dev/null 2>&1 ||
    die "sevenzip was installed but 7zz is not available in PATH."

#
# Signature verification and helper tools
#

if ! command -v gpgv >/dev/null 2>&1; then
    log "GnuPG/gpgv is not installed."
    log "Installing GnuPG for authenticated appliance verification..."

    brew install gnupg
fi

command -v gpgv >/dev/null 2>&1 ||
    die "GnuPG was installed but gpgv is not available in PATH. Run 'brew reinstall gnupg'."

if ! command -v python3 >/dev/null 2>&1; then
    log "Python 3 is not installed."
    log "Installing Python 3 for appliance-plan and validation helpers..."

    brew install python
fi

for required_command in python3 git curl ssh scp qemu-img; do
    command -v "$required_command" >/dev/null 2>&1 ||
        die "Required command '${required_command}' is unavailable. Reinstall Xcode Command Line Tools and the Homebrew dependencies, then retry."
done

#
# Environment summary
#

RUST_VERSION="$(rustc --version)"
CARGO_VERSION="$(cargo --version)"
NODE_VERSION="$(node --version)"
NPM_VERSION="$(npm --version)"
QEMU_VERSION="$("$QEMU_BINARY" --version | head -n 1)"
QEMU_IMG_VERSION="$(qemu-img --version | head -n 1)"
SEVENZIP_VERSION="$(7zz | sed -n '2p' | sed -E 's/^7-Zip \(z\) //')"
GPGV_VERSION="$(gpgv --version | head -n 1)"
PYTHON_VERSION="$(python3 --version 2>&1)"
GIT_VERSION="$(git --version)"
CURL_VERSION="$(curl --version | head -n 1)"
SSH_VERSION="$(ssh -V 2>&1)"

require_minimum_version "Rust" "$RUST_VERSION" 1 77 "Run 'rustup update stable'."
require_minimum_version "Cargo" "$CARGO_VERSION" 1 77 "Run 'rustup update stable'."
require_minimum_version "Node.js" "$NODE_VERSION" 18 0 "Run 'brew upgrade node'."
require_minimum_version "npm" "$NPM_VERSION" 9 0 "Run 'brew upgrade node'."
require_minimum_version "QEMU" "$QEMU_VERSION" 8 0 "Run 'brew upgrade qemu'."
require_minimum_version "qemu-img" "$QEMU_IMG_VERSION" 8 0 "Run 'brew upgrade qemu'."
require_minimum_version "7-Zip" "$SEVENZIP_VERSION" 23 0 "Run 'brew upgrade sevenzip'."
require_minimum_version "gpgv" "$GPGV_VERSION" 2 2 "Run 'brew upgrade gnupg'."
require_minimum_version "Python" "$PYTHON_VERSION" 3 9 "Run 'brew upgrade python'."
require_minimum_version "Git" "$GIT_VERSION" 2 30 "Run 'brew upgrade git'."
require_minimum_version "curl" "$CURL_VERSION" 7 79 "Update macOS or install a current curl with Homebrew."

log "Rust: $RUST_VERSION"
log "Cargo: $CARGO_VERSION"
log "Node: $NODE_VERSION"
log "npm:  $NPM_VERSION"
log "QEMU: $QEMU_VERSION"
log "qemu-img: $QEMU_IMG_VERSION"
log "7-Zip: $SEVENZIP_VERSION"
log "gpgv: $GPGV_VERSION"
log "Python: $PYTHON_VERSION"
log "Git: $GIT_VERSION"
log "curl: $CURL_VERSION"
log "SSH: $SSH_VERSION"

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

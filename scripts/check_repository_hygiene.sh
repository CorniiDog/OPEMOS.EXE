#!/usr/bin/env bash
set -euo pipefail

MAX_TRACKED_BYTES=$((25 * 1024 * 1024))
FAILED=0

report()
{
    printf '[repository-hygiene] ERROR: %s\n' "$*" >&2
    FAILED=1
}

file_size()
{
    if stat -f '%z' "$1" >/dev/null 2>&1; then
        stat -f '%z' "$1"
    else
        stat -c '%s' "$1"
    fi
}

while IFS= read -r -d '' path; do
    [[ -f "$path" ]] || continue
    size="$(file_size "$path")"
    if (( size > MAX_TRACKED_BYTES )); then
        report "$path is $size bytes; source-controlled files are limited to $MAX_TRACKED_BYTES bytes."
    fi

    lower_path="$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')"
    case "$lower_path" in
        *.qcow2|*.raw|*.iso|*.img|*.img.bz2|*.img.gz|*.img.xz)
            report "$path looks like a generated appliance or recovery image."
            ;;
        *.log)
            case "$lower_path" in
                tests/fixtures/*.sanitized.log) ;;
                *) report "$path is a build/runtime log without the required tests/fixtures/*.sanitized.log boundary." ;;
            esac
            ;;
    esac

    basename="$(basename "$lower_path")"
    case "$basename" in
        id_rsa|id_dsa|id_ecdsa|id_ed25519|*.key|*.pem|*.p12|*.pfx)
            report "$path looks like private key material."
            ;;
    esac
    if LC_ALL=C grep -aEq -- '-----BEGIN (OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----' "$path"; then
        report "$path contains a private-key PEM marker."
    fi
done < <(git ls-files --cached --others --exclude-standard -z)

if (( FAILED )); then
    exit 1
fi

python3 tests/boundary_policy.py

printf '[repository-hygiene] Repository file checks passed.\n'

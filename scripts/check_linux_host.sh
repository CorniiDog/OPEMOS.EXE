#!/usr/bin/env bash
# Read-only diagnostics. Overrides below are for isolated doctor tests only;
# they do not configure or authorize the application runtime.
set -eu
failures=0
problem() { printf 'MISSING: %s\n' "$1"; failures=$((failures + 1)); }
printf '%s\n' 'Experimental Linux host prerequisite inventory; this does not establish runtime readiness or production trust.'
os_release=${OPEMOS_DOCTOR_OS_RELEASE:-/etc/os-release}
host_arch=${OPEMOS_DOCTOR_ARCH:-$(uname -m)}
distribution=
version=
# Never source os-release. Use the system Python parser, not an executable
# discovered through PATH, and read only a bounded regular-file snapshot.
if parsed=$(/usr/bin/python3 - "$os_release" <<'PYTHON'
import os
import stat
import sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("os-release must be a regular file")
        data = source.read(65537)
    if len(data) > 65536:
        raise ValueError("os-release exceeds 65536 bytes")
    document = data.decode("utf-8", errors="strict")
    if "\x00" in document:
        raise ValueError("os-release contains a NUL byte")
    distribution = ""
    version = ""
    seen_id = False
    for line in document.splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            continue
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            value = value[1:-1]
        if key == "ID":
            if seen_id:
                raise ValueError("os-release contains duplicate ID entries")
            seen_id = True
            distribution = value
        elif key == "VERSION_ID":
            version = value
    print(distribution)
    print(version)
except (OSError, ValueError) as error:
    print("Invalid os-release: " + str(error), file=sys.stderr)
    sys.exit(1)
PYTHON
); then
    distribution=${parsed%%$'\n'*}
    if [[ "$parsed" == *$'\n'* ]]; then version=${parsed#*$'\n'}; fi
else
    problem 'A bounded UTF-8 os-release with one ID entry is required.'
fi
printf 'Host: %s %s / %s\n' "${distribution:-unknown}" "${version:-unknown}" "$host_arch"
case "$distribution:$host_arch" in
    ubuntu:x86_64|debian:x86_64) ;;
    *) problem 'Only Ubuntu/Debian x86_64 is in this experimental host scope.' ;;
esac
[[ ${OPEMOS_EXPERIMENTAL_LINUX:-} == 1 ]] || problem 'Set OPEMOS_EXPERIMENTAL_LINUX=1 to opt in explicitly.'
for binary in qemu-system-x86_64 qemu-img genisoimage ssh ssh-keygen python3; do
    if location=$(command -v "$binary") && [[ -f "$location" && -x "$location" ]]; then
        printf 'FOUND: %s: %s\n' "$binary" "$location"
    else
        problem "$binary"
    fi
done
firmware_root=${OPEMOS_DOCTOR_FIRMWARE_ROOT:-/usr/share/OVMF}
firmware_found=0
for suffix in _4M ''; do
    code="$firmware_root/OVMF_CODE${suffix}.fd"
    vars="$firmware_root/OVMF_VARS${suffix}.fd"
    if [[ -f "$code" && -r "$code" && -s "$code" && -f "$vars" && -r "$vars" && -s "$vars" ]]; then
        printf 'FOUND: matched firmware pair: %s ; %s\n' "$code" "$vars"
        firmware_found=1
        break
    fi
done
[[ $firmware_found == 1 ]] || problem 'A readable nonempty matched OVMF CODE/VARS pair (4M or legacy) is required.'
case ${OPEMOS_LINUX_ACCEL:-kvm} in
    kvm)
        if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
            printf '%s\n' 'KVM: /dev/kvm is accessible; usability is NOT verified. The runtime must pass its KVM ioctl probe.'
        else
            problem 'KVM device access unavailable; explicitly select OPEMOS_LINUX_ACCEL=tcg for software testing.'
        fi
        ;;
    tcg) printf '%s\n' 'TCG: explicitly selected software testing; KVM access is not required.' ;;
    *) problem 'OPEMOS_LINUX_ACCEL must be kvm or tcg; no automatic fallback.' ;;
esac
printf '%s\n' 'Physical USB writing is unsupported. This inventory does not authenticate appliances, Core results, or output images.'
if (( failures )); then
    printf 'Inventory: %s prerequisite issue(s).\n' "$failures"
    exit 1
fi
printf '%s\n' 'Inventory complete; application runtime checks and independent image verification remain required.'

#!/usr/bin/env bash

set -euo pipefail

die() {
  printf 'OPEMOS installation-target VM gate: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 5 ]] || die "usage: $0 HELPER DEVICE EXPECTED_BYTES SOURCE_COMMIT RESULT_JSON"
[[ ${EUID:-$(id -u)} -eq 0 ]] || die "the guest gate must run as root"

helper=$(readlink -f -- "$1")
device=$(readlink -f -- "$2")
expected_bytes=$3
source_commit=$4
result=$(readlink -m -- "$5")
expected_inventory_disks=${OPEMOS_EXPECTED_INVENTORY_DISKS:-1}

[[ -f "$helper" && ! -L "$helper" ]] || die "the staged production helper is missing or unsafe"
[[ "$expected_bytes" =~ ^[0-9]+$ ]] || die "the expected disk size is malformed"
[[ "$expected_inventory_disks" =~ ^[1-9][0-9]*$ ]] || die "the expected inventory count is malformed"
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || die "the source commit is malformed"
[[ "$device" == /dev/sd? ]] || die "the disposable target must be one whole Hyper-V SCSI disk"
[[ -b "$device" && "$(lsblk -dnro TYPE "$device")" == disk ]] || die "the target is not a whole disk"

for tool in blockdev findmnt lsblk mkfs.ext4 mount partprobe python3 readlink sfdisk sha256sum udevadm umount wipefs; do
  command -v "$tool" >/dev/null 2>&1 || die "required guest tool is missing: $tool"
done

actual_bytes=$(blockdev --getsize64 "$device")
[[ "$actual_bytes" == "$expected_bytes" ]] || die "the guarded target has an unexpected capacity"
[[ "$(lsblk -dnro RO "$device" | tr -d '[:space:]')" == 0 ]] || die "the guarded target is read-only"

root_source=$(findmnt -nro SOURCE -T /)
root_disk=$(lsblk -snrpo PATH,TYPE "$root_source" | awk '$2 == "disk" { print $1; exit }')
[[ -n "$root_disk" && "$device" != "$root_disk" ]] || die "the guarded target overlaps the guest system disk"
[[ "$(lsblk -nrpo TYPE "$device" | awk '$1 == "part" { count++ } END { print count+0 }')" == 0 ]] ||
  die "the disposable target was not initially unallocated"
[[ -z "$(wipefs -n "$device" 2>/dev/null)" ]] || die "the disposable target contains an unexpected signature"

helper_size=$(stat -Lc '%s' "$helper")
helper_sha256=$(sha256sum "$helper" | awk '{print $1}')
model=$(lsblk -dnro MODEL "$device" | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//')
serial=$(lsblk -dnro SERIAL "$device" | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//')

# Exercise the installed command boundary before sourcing helper functions. This
# catches discovery regressions caused by install-only prerequisites that are
# absent from an otherwise valid recovery environment.
unallocated_inventory=$("$helper" inventory) ||
  die "the production helper command could not inspect the unallocated virtual disk"
inventory_count=$(awk -F '\t' '$1 ~ /^\/dev\// && $7 == "fresh" { count++ } END { print count+0 }' \
  <<<"$unallocated_inventory")
[[ "$inventory_count" == "$expected_inventory_disks" ]] ||
  die "the production helper listed $inventory_count fresh target(s), expected $expected_inventory_disks"
awk -F '\t' -v wanted="$device" '$1 == wanted && $7 == "fresh" { found++ } END { exit found != 1 }' \
  <<<"$unallocated_inventory" || die "inventory did not list the unallocated virtual disk exactly once"

# shellcheck source=/dev/null
source "$helper"

unallocated_status=$(disk_status "$device")
[[ "$unallocated_status" == eligible ]] || die "the unallocated virtual disk was not eligible"

printf 'label: gpt\n,14G,L\n' | sfdisk --wipe always "$device" >/dev/null
partprobe "$device"
udevadm settle
partition=$(lsblk -nrpo PATH,TYPE "$device" | awk '$2 == "part" { print $1 }')
[[ -b "$partition" && "$(printf '%s\n' "$partition" | wc -l)" == 1 ]] ||
  die "the disposable target did not produce exactly one test partition"
mkfs.ext4 -q -F -L OPEMOS_VM_TARGET "$partition"

mount_root=$(mktemp -d /run/opemos-install-target-vm.XXXXXX)
cleanup() {
  if findmnt -rn -S "$partition" >/dev/null 2>&1; then
    umount "$partition" || true
  fi
  rmdir "$mount_root" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
mount "$partition" "$mount_root"
[[ "$(findmnt -nro SOURCE -T "$mount_root")" == "$partition" ]] || die "the test filesystem was not mounted"

identity_before=$(disk_identity "$device")
mounted_status=$(disk_status "$device")
[[ "$mounted_status" == eligible ]] || die "a mounted filesystem incorrectly hid the whole target disk"
mounted_inventory=$(inventory)
awk -F '\t' -v wanted="$device" '$1 == wanted && $7 == "fresh" { found++ } END { exit found != 1 }' \
  <<<"$mounted_inventory" || die "inventory did not list the mounted virtual disk exactly once"

unmount_target_children "$device" || die "the bounded target unmount failed"
mounted_child "$device" && die "a target child remained mounted"
identity_after=$(disk_identity "$device")
[[ "$identity_after" == "$identity_before" ]] || die "the disk identity changed during bounded unmount"
trap - EXIT INT TERM
rmdir "$mount_root"

RESULT_PATH="$result" SOURCE_COMMIT="$source_commit" HELPER_SIZE="$helper_size" \
HELPER_SHA256="$helper_sha256" DEVICE="$device" MODEL="$model" SERIAL="$serial" \
EXPECTED_BYTES="$expected_bytes" IDENTITY_BEFORE="$identity_before" \
IDENTITY_AFTER="$identity_after" python3 - <<'PY'
import json
import os
from pathlib import Path

payload = {
    "schemaVersion": 1,
    "test": "install-media-target-vm-guest",
    "sourceCommit": os.environ["SOURCE_COMMIT"],
    "helper": {"size": int(os.environ["HELPER_SIZE"]), "sha256": os.environ["HELPER_SHA256"]},
    "target": {
        "device": os.environ["DEVICE"], "model": os.environ["MODEL"],
        "serial": os.environ["SERIAL"], "bytes": int(os.environ["EXPECTED_BYTES"]),
        "initialPartitionCount": 0,
    },
    "unallocated": {"status": "eligible", "listedExactlyOnce": True, "layout": "fresh"},
    "mounted": {"status": "eligible", "listedExactlyOnce": True, "layout": "fresh"},
    "release": {
        "boundedUnmountSucceeded": True, "childMountsRemaining": 0,
        "identityBefore": os.environ["IDENTITY_BEFORE"], "identityAfter": os.environ["IDENTITY_AFTER"],
    },
}
path = Path(os.environ["RESULT_PATH"])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
path.chmod(0o600)
PY

printf 'Installation-target VM guest gate passed for %s.\n' "$device"

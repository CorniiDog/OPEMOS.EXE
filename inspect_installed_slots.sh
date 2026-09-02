#!/usr/bin/env bash

# Read-only recovery helper for locating an OPEMOS NVIDIA installation across
# machines with more than one SteamOS-style A/B disk layout.

set -u

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this helper with sudo:"
  echo "  sudo ./inspect_installed_slots.sh"
  exit 2
fi

if ! command -v lsblk >/dev/null 2>&1 || ! command -v mount >/dev/null 2>&1; then
  echo "This helper must be run from the Linux recovery environment."
  exit 2
fi

work_dir=$(mktemp -d /tmp/opemos-slot-inspection.XXXXXX) || exit 1
mounted_path=""

cleanup() {
  if [[ -n "$mounted_path" ]]; then
    umount "$mounted_path" >/dev/null 2>&1 || true
  fi
  rmdir "$work_dir" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

printf 'OPEMOS read-only A/B slot inspection\n'
printf 'No disks, partitions, or boot entries will be changed.\n\n'

found=0
while read -r device partlabel parttype; do
  [[ "$parttype" == "part" ]] || continue
  case "$partlabel" in
    rootfs-A|rootfs-B) ;;
    *) continue ;;
  esac

  found=1
  parent=$(lsblk -ndo PKNAME "$device" 2>/dev/null | head -n 1)
  model=$(lsblk -ndo MODEL "/dev/$parent" 2>/dev/null | sed 's/[[:space:]]*$//')
  esp_partuuid=$(lsblk -rno PARTLABEL,PARTUUID "/dev/$parent" 2>/dev/null \
    | awk '$1 == "esp" { print $2; exit }')
  filesystem=$(lsblk -ndo FSTYPE "$device" 2>/dev/null | head -n 1)

  printf '%s  %s  [%s]\n' "$device" "$partlabel" "${model:-unknown disk}"
  printf '  ESP PARTUUID: %s\n' "${esp_partuuid:-unknown}"

  mount_options="ro"
  case "$filesystem" in
    ext2|ext3|ext4) mount_options="ro,noload" ;;
    btrfs) mount_options="ro,norecovery" ;;
  esac

  mount_point="$work_dir/slot"
  mkdir -p "$mount_point"
  if ! mount -o "$mount_options" "$device" "$mount_point" 2>/dev/null; then
    printf '  Result: could not mount read-only (filesystem: %s)\n\n' "${filesystem:-unknown}"
    rmdir "$mount_point" >/dev/null 2>&1 || true
    continue
  fi
  mounted_path="$mount_point"

  version="unknown"
  if [[ -r "$mount_point/etc/os-release" ]]; then
    version=$(sed -n 's/^VERSION_ID=//p' "$mount_point/etc/os-release" \
      | head -n 1 | tr -d '"')
  fi
  kernels=$(find "$mount_point/usr/lib/modules" -mindepth 1 -maxdepth 1 -type d \
    -printf '%f ' 2>/dev/null | sed 's/[[:space:]]*$//')
  receipt="$mount_point/usr/lib/open-gpu-kernel-modules-steamos-support/offline-install/receipt.json"

  printf '  SteamOS: %s\n' "$version"
  printf '  Kernels: %s\n' "${kernels:-none found}"
  if [[ -r "$receipt" ]]; then
    printf '  OPEMOS receipt: FOUND\n'
    grep -E '"(receiptId|receipt_id|nvidiaVersion|nvidia_version|kernelVersion|kernel_version)"' "$receipt" \
      | head -n 8 | sed 's/^/    /' || true
  else
    printf '  OPEMOS receipt: not found\n'
  fi

  umount "$mount_point"
  mounted_path=""
  rmdir "$mount_point"
  printf '\n'
done < <(lsblk -rno PATH,PARTLABEL,TYPE)

if [[ $found -eq 0 ]]; then
  echo "No rootfs-A or rootfs-B partitions were found."
  exit 1
fi

echo "Inspection complete. All inspected slots were unmounted."

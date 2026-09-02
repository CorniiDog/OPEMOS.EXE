---
layout: page
title: Hardware and update recovery
description: Diagnose Wi-Fi and graphics failures, and understand the planned fail-safe SteamOS update workflow.
---

# Hardware and update recovery

OPEMOS targets hardware outside Valve's currently validated Steam Deck set.
Ethernet, Wi-Fi, hybrid graphics, suspend, display routing, and firmware must
therefore be verified for each hardware profile. A successful image build does
not certify every device in a PC.

## If an update leaves a black screen

Do not reinstall or wipe the system immediately. A black display does not by
itself prove that the update failed: the graphical session may have failed
while the machine, another virtual terminal, and networking remain alive.

Try `Ctrl`+`Alt`+`F3`. If a login prompt appears, sign in and collect the
following without changing the boot configuration:

```bash
uname -r
cat /etc/os-release
cat /proc/cmdline
steamos-bootconf this-image 2>&1
modinfo -F version nvidia 2>&1
modinfo -F vermagic nvidia 2>&1
modinfo nvidia 2>&1 | sed -n '1,30p'
lsmod | grep -E 'nvidia|nouveau'
journalctl -b -p warning..alert --no-pager
journalctl -b | grep -iE 'nvidia|nouveau|gamescope|drm|firmware'
```

If SSH was already enabled, the same read-only collection can be run over
Ethernet. Preserve `/var/log/steamos-nvidia-repatch.log` if the legacy
installer's self-heal path is present. Do not disable signature checking,
install a nearest-version module, or edit the inactive-slot boot files until
the running kernel, active slot, NVIDIA module vermagic, userspace version,
firmware, and failure log have been compared.

As a temporary diagnostic route, the legacy installer documents
`steamos-session-select plasma` from a TTY. That may recover a desktop when
Gaming Mode alone failed, but it does not repair a mismatched kernel module.

## Why a SteamOS update can invalidate NVIDIA

SteamOS stages operating-system updates into an inactive A/B root slot. NVIDIA
contains a kernel-specific interface layer, so a module built for the old
kernel must not be treated as compatible with the new slot. The matching
userspace libraries and GSP firmware must agree with the module release too.

The legacy `steamos-nvidia-installer` demonstrates a useful transaction shape:
after Valve stages the inactive slot, it builds the driver for that slot and
marks the slot invalid if preparation fails. OPEMOS must not copy its fallback
that retries package installation with `SigLevel = Never`. HTTPS transport is
not a replacement for the reviewed signatures, hashes, locks, and provenance
required by the OPEMOS support contract.

## Planned OPEMOS update guardian

The installed-system updater should use a persistent, machine-readable state
transaction:

1. Detect the exact staged SteamOS version, kernel, slot, partition identities,
   and selected NVIDIA source policy.
2. Resolve or build only the exact compatible NVIDIA artifact and complete
   authenticated userspace closure.
3. Apply it to the inactive slot and verify modules, vermagic, userspace,
   firmware, initramfs, boot arguments, and package database independently.
4. Permit the boot-slot switch only after every verification succeeds.
5. On failure or cancellation, mark the candidate slot invalid, keep the
   current slot selected, retain bounded diagnostics, and offer retry.
6. On first boot, count attempts and automatically return to the last verified
   slot if the graphical health check does not complete.

The graphical updater should show `Downloading update`, `Preparing NVIDIA for
the new kernel`, `Validating next boot`, and `Ready to restart`. Because a
graphics update can terminate the compositor, the same status must also be
written to a persistent log and shown through a console-safe fallback. A
progress window alone is not a recovery mechanism.

OPEMOS should additionally install an explicit recovery entry that can reach a
text/rescue environment without starting Gaming Mode. The exact SteamOS boot
entry and rollback edits remain hardware-test gates; they must not be inferred
from generic systemd behavior or applied to an unrecognized Valve layout.

## Wi-Fi diagnosis on non-Deck hardware

Start by identifying the controller and its current kernel binding. Run:

```bash
lspci -nnk | grep -A3 -iE 'network|wireless'
lsusb
rfkill list
nmcli radio
nmcli device status
nmcli -f GENERAL.DEVICE,GENERAL.TYPE,GENERAL.DRIVER,GENERAL.DRIVER-VERSION,GENERAL.FIRMWARE-VERSION,GENERAL.FIRMWARE-MISSING,GENERAL.STATE,GENERAL.REASON device show
journalctl -b -u NetworkManager --no-pager
dmesg | grep -iE 'firmware|wifi|wlan|iwlwifi|ath|rtw|brcm|mt76'
```

These results separate common causes:

| Evidence | Likely class of problem |
| --- | --- |
| No PCI/USB device | Firmware/UEFI setting, hardware, or bus enumeration |
| Device exists but no kernel driver | Unsupported or omitted kernel module |
| `FIRMWARE-MISSING: yes` or firmware load errors | Required firmware blob absent |
| Hardware/software blocked in `rfkill` or `nmcli radio` | Radio-kill state |
| Driver and firmware load, but activation fails | Credentials, security mode, regulatory domain, DHCP, or NetworkManager policy |

Do not include passwords or full connection profiles in a diagnostic report.
The PCI/USB vendor and device IDs, driver name, firmware filename/version,
NetworkManager state reason, and bounded kernel errors are sufficient for the
hardware compatibility record.

## Hardware-profile policy

Future image builds should accept a detected or user-selected target hardware
profile, then verify before export that every required in-kernel module and
firmware file exists for the image's exact kernel. Profiles may add reviewed
Wi-Fi firmware or modules, but must never fetch an arbitrary out-of-tree driver
at first boot. Both A/B slots and the update guardian must preserve the same
profile, and unsupported devices must remain clearly labeled rather than being
silently treated as compatible.

## References

- [Current `steamos-nvidia-installer` implementation](https://github.com/CorniiDog/steamos-nvidia-installer/blob/main/steamos-nvidia-installer.sh)
- [NVIDIA open kernel-module build and matching-component requirements](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/main/README.md)
- [NetworkManager `nmcli` reference](https://networkmanager.dev/docs/api/latest/nmcli.html)
- [NetworkManager device state and missing-firmware properties](https://www.networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Device.html)
- [Linux kernel firmware-request documentation](https://docs.kernel.org/next/driver-api/firmware/request_firmware.html)
- [systemd rescue and emergency boot guidance](https://wiki.freedesktop.org/www/Software/systemd/Debugging/)

# Open OPEMOS installation-media welcome app

This directory owns the welcome/installer experience that runs after booting a
newly generated OPEMOS recovery image. It is separate from the persistent
installed-system Desktop application owned by the support repository.

The current frontend uses Zenity because Valve's inspected SteamOS 3.8.14
recovery image already requires and ships it. `open-opemos-welcome` is an
unprivileged presentation layer. It may be replaced by the native frosted-glass
frontend without changing the helper protocol.

`opemos-install-helper` is installed root-owned at
`/usr/lib/opemos-install-media/`. It exposes only:

- `inventory`
- `identity DEVICE`
- `install all DEVICE IDENTITY --confirm "ERASE NAME"`
- `install system DEVICE IDENTITY --confirm "REINSTALL NAME"`

Before installation it excludes the recovery medium, pseudo devices, mounted
or swap-backed disks, read-only disks, and disks smaller than 12 GiB. Reinstall
also requires the standard labels at exact partition indices 1 through 8. The
device identity and eligibility are checked again under a per-device lock.

`patch_repair_device.py` runs only while the output image is being assembled.
It rejects unknown Valve installer structure and creates a root-owned delegate
that requires an explicit target disk, supports NVMe/non-NVMe partition names,
does not hang forever after an error, does not reboot behind the UI, and skips
Steam Deck-specific firmware operations on generic hardware. It does not edit
installer source when the welcome app runs.

The fresh-install path is destructive and deliberately has no mid-write cancel
button. Interruption cannot be rolled back once Valve has rewritten the target
partition table. The UI keeps the original media usable, preserves a diagnostic
log, and clearly treats a failed target as incomplete.

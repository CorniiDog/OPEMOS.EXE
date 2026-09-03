# SteamOS with NVIDIA drivers installation-media welcome app

This directory owns the welcome/installer experience that runs after booting a
newly generated SteamOS image with NVIDIA drivers. The experience is maintained
by OPEMOS and is separate from the persistent installed-system Desktop
application owned by the support repository.

The current frontend uses Zenity because Valve's inspected SteamOS 3.8.14
recovery image already requires and ships it. `open-opemos-welcome` is an
unprivileged presentation layer. It may be replaced by the native frosted-glass
frontend without changing the helper protocol. A bundled GTK stylesheet gives
this guaranteed-runtime fallback the OPEMOS-maintained blue/green glass language with an
opaque fallback when compositor transparency is unavailable.

Only one welcome instance can run in a recovery session. Its diagnostics view
shows the pinned NVIDIA/support identity and currently eligible disks. Complete
installation output is retained under the recovery user's private state
directory and remains viewable after closing and reopening the window.

`opemos-install-helper` is installed root-owned at
`/usr/lib/opemos-install-media/`. It exposes only:

- `inventory`
- `inventory-report`
- `media-info`
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

After Valve's operation returns, the helper installs the immutable support
snapshot into both target root slots and independently verifies the persistent
recovery scripts, services, symlinks, support revision, and NVIDIA version in
each slot before reporting success.
Successful installation ends with an explicit Shut Down, Restart, or Stay Here
choice. Shut Down is recommended; restart copy explains when to remove the USB
or use the firmware boot menu so the machine does not loop back into recovery.

## Safe macOS graphical preview

Run `./test_welcome_macos.sh` from the repository root to open the interactive
browser-based welcome simulation. It uses only fixed synthetic disks and mock
progress. The launcher cannot inspect or write a disk, elevate privileges,
start QEMU, access the network, or invoke either installation helper. This is a
visual/interaction test; the generated SteamOS media continues to use the
audited Zenity frontend above.

The preview follows the centered-choice and installation-slideshow principles
used by modern graphical installers. Its original illustrations explain target
selection, gaming graphics, and A/B recovery without presenting OPEMOS as the
operating system or borrowing another distribution's branding.

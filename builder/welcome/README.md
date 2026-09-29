# SteamOS with NVIDIA drivers installation-media welcome app

This directory owns the welcome/installer experience that runs after booting a
newly generated SteamOS image with NVIDIA drivers. The experience is maintained
by OPEMOS and is separate from the persistent installed-system Desktop
application owned by the support repository.

The normal frontend is the same full-screen frosted-glass HTML/CSS/JavaScript
bundle used by the macOS simulation. `open-opemos-welcome` starts a random-port,
loopback-only Python controller and opens the Qt 6 WebEngine runtime already
present in Valve's recovery image. Installed browsers remain secondary runtimes.
A per-session secret plus exact-Origin checks protect every API
call. Zenity remains a guaranteed-runtime fallback only when neither a supported
graphical runtime nor Python is available; its bundled GTK stylesheet retains the same
blue/green language with an opaque compositor fallback.

Only one welcome instance can run in a recovery session. Its diagnostics view
shows the pinned NVIDIA/support identity and currently eligible disks. Complete
installation output is retained under the recovery user's private state
directory and remains viewable after closing and reopening the window.
Launcher diagnostics are retained in `welcome-startup.log` in that same private
state directory. A second launch reports where to find the existing instance,
and a browser that exits before presenting a stable window advances to the next
installed supported browser. The existing Zenity recovery interface opens only
after every available full-screen runtime fails.

The Qt 6 runtime records its selected renderer policy plus bounded Qt WebEngine
and scene-graph backend diagnostics in that startup log. On Intel-display plus
NVIDIA-render hybrid systems it keeps Qt Quick and Chromium on the default DRI
device and the same OpenGL path instead of
allowing Chromium's NVIDIA-specific Vulkan override to diverge from Qt. Other
systems retain Qt's automatic accelerated selection. If the accelerated runtime
exits or cannot report a ready UI within 20 seconds, the launcher retries Qt
Quick and Chromium together in software mode before trying installed browsers
and the existing Zenity fallback.

The visible Desktop launcher is installed as a deck-owned executable desktop
entry so KDE treats it as trusted before the recovery session appears. The
matching autostart entry remains non-executable because it is configuration,
not a second application.

`opemos-install-helper` is installed root-owned at
`/usr/lib/opemos-install-media/`. It exposes only:

- `inventory`
- `inventory-report`
- `media-info`
- `identity DEVICE`
- `install all DEVICE IDENTITY --confirm "ERASE NAME"`
- `install system DEVICE IDENTITY --confirm "REINSTALL NAME"`

Before installation it excludes the recovery medium, pseudo devices,
swap-active disks, read-only disks, and disks smaller than 12 GiB. Mounted
filesystems do not hide an otherwise eligible whole disk: only after the user
selects that disk, types its exact erase or reinstall phrase, and the helper
revalidates its identity under a per-device lock does the helper unmount that
target's child filesystems. It then revalidates identity again before invoking
Valve's installer. Reinstall also requires the standard labels at exact
partition indices 1 through 8.

Disk discovery performs only its own read-only tool preflight; install-only
requirements such as Btrfs and `steamos-chroot` are checked only after the user
selects and confirms a target. Helper failures remain visible instead of being
reported as an empty eligible-disk list.

Changes to installation-target discovery or target filesystem release must
also pass the disposable installation-target VM gate. The gate sources the
exact production helper inside the headless `OPEMOS-KVM-B` Hyper-V guest and
attaches one newly created dynamic VHDX. It proves the whole disk is listed
while both unallocated and mounted, then proves the helper releases only that
confirmed target's child filesystem without changing disk identity. The VHDX
and guest staging are removed after the run. Evidence is checked by
`scripts/install-media-target-vm-evidence.mjs`.

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
browser-based welcome simulation. It serves the exact shipped frontend and API
schema through the controller's explicit `--mock` mode, using only one fixed
synthetic disk and mock progress. The mock controller cannot inspect or write a
disk, elevate privileges, start QEMU, access the network, or invoke either
installation helper.

The preview follows the centered-choice and installation-slideshow principles
used by modern graphical installers. Its original illustrations explain target
selection, gaming graphics, and A/B recovery without presenting OPEMOS as the
operating system or borrowing another distribution's branding.

---
layout: page
title: Build workflow
description: Stage-by-stage behavior, progress, trust, outputs, and cancellation.
---

## End-to-end flow

```text
official Valve image (read-only)
        |
        v
signature detection, normalization, hashing, host-space preflight
        |
        v
native Fedora inspection ---> exact SteamOS/kernel/layout/architecture
        |
        v
OPEMOS resolver -----------> exact published artifact or safe no-match
        |
        v
authenticated modules + userspace + disposable qcow2 overlay
        |
        v
managed x86_64 Fedora ---> validate-only ---> mutation ---> verification
        |
        v
fresh native inspection ---> atomic image/manifest finalization
        |
        +-- optional revalidated USB write and read-back verification
```

## Progress stages

The upper half of the glass progress pill shows overall workflow progress. The
lower half reports real progress inside the active stage. Guest heartbeats are
liveness evidence only; they never fabricate percentages.

Long phases include source integrity verification, image transfer, managed
x86_64 boot, authenticated package validation, pacman installation, module
verification, `depmod`, GRUB policy, `mkinitcpio`, final inspection, export, and
optional USB verification.

## Published versus local artifacts

A published artifact is still accepted according to its authenticated
provenance. Publication alone does not promote it to certified. When no exact
artifact exists, maintainers may approve a long local x86_64 build against the
exact Valve header package and pinned project source.

No closest-kernel headers, modules, userspace packages, or signers are used.

## Output identity and reuse

New NVIDIA outputs include the resolved driver version in their human-readable
name, for example `steamdeck-repair-nvidia-575.64.05.img`. The adjacent JSON
manifest remains authoritative: it binds the exact NVIDIA, SteamOS, kernel,
source policy, trust classification, and image hash. Renaming the image does
not change its identity.

Dropping a completed image back into the application verifies both files and
skips installation when the manifest matches. If an explicitly selected
NVIDIA version differs, the completed image is not silently reused or upgraded
in place; select the original Valve recovery image to build that version.

## Bootable-media welcome flow

Newly generated images stage **Open OPEMOS** in the recovery desktop and launch
it automatically. The first implementation intentionally uses the recovery
image's known Zenity runtime while the frosted-glass native surface is built.
The safety contract does not depend on that presentation layer.

The welcome flow offers separate actions for a fresh installation, a SteamOS
system reinstall that preserves the recognized home partition, and A/B
rollback. It never silently picks the first or smallest disk. Only whole,
writable, unmounted physical disks of sufficient capacity are offered, and the
booted installation medium is excluded. The selected disk is bound to its
device path, capacity, kernel major/minor and sequence values, and available
hardware identifiers. The protected helper rechecks all of them after the
typed confirmation and immediately before Valve's installer starts.

The frontend runs as `deck`. The only privileged installation code is stored
root-owned in the recovery root filesystem, accepts the fixed `all` or `system`
mode, and delegates to a structurally verified copy of the image's own Valve
installer. OPEMOS does not interpolate UI text into shell source or rewrite the
installer at runtime.

After Valve finishes cloning the recovery system, the protected helper enters
each installed A/B slot and runs the pinned support repository's offline-root
guardian installer. The shared target home receives the persistent recovery
snapshot, while both root slots receive the matching systemd, NetworkManager,
and atomic-update integration. This post-install step is required because a
fresh Valve installation formats the target home rather than copying the
installation USB's home partition.

## Cancellation

Cancellation can occur during normalization, download, validation, package
mutation, initramfs generation, export, or USB writing. The intended terminal
state is always:

- original image unchanged;
- disposable overlay discarded;
- partial final image absent;
- target and runtime mounts released;
- native and x86_64 QEMU children stopped;
- no trusted partial result; and
- bounded diagnostics retained.

## Diagnostic logs

The progress window preserves selectable ANSI-colored output. **Copy Diagnostic
Log** produces a bounded summary that removes routine VM/compiler noise and
repeated lines, redacts usernames and common credential forms, and retains the
authoritative failure plus relevant milestones. Human log text never decides
whether an image is trusted.

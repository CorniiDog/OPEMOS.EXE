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

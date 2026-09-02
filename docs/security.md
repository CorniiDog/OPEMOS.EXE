---
layout: page
title: Security
description: Source-image safety, artifact authentication, target execution, USB authorization, and remaining trust gaps.
---

## Trust boundary

OPEMOS.EXE treats exact compatibility and authentication as separate
requirements. An accepted NVIDIA result binds:

- SteamOS version, exact kernel release, architecture, and NVIDIA version;
- archive, checksum, external and embedded provenance;
- five installed module hashes, ELF architecture, version, and vermagic;
- four explicitly required early-boot initramfs modules and rootfs-only
  `nvidia-peermem`;
- signed userspace closure, package-specific signer policy, reviewed lock, and
  minimal keyring;
- immutable OPEMOS installer and source commits; and
- structured mutation plus independent final-image inspection.

## Source and output isolation

The source image is attached read-only. All SteamOS changes occur in a
disposable qcow2 overlay. A failure or cancellation cannot finalize the hidden
partial output. The source is rehashed after guest work, and final acceptance
occurs through a fresh read-only inspection session.

## Target-owned execution

SteamOS package hooks and `mkinitcpio` are code from the selected image. OPEMOS
snapshots and validates their confined paths, ownership, permissions,
interpreters, and hashes before executing them. The snapshot must remain
unchanged between validate-only and mutation.

## Repository and artifact identity

Live support operations use the canonical
[`CorniiDog/OPEMOS`](https://github.com/CorniiDog/OPEMOS) identity. Historical
artifact provenance may retain the former repository name; it remains valid
only when its exact support commit and all artifact hashes pass independent
checks.

## USB authorization

On macOS, the GUI does not become root and no persistent privileged daemon is
installed. The app asks Apple's protected authorization mechanism to open only
the exact revalidated raw device, receives that descriptor, verifies it, and
keeps copy, progress, cancellation, read-back hashing, and ejection in bounded
Rust code.

Windows requires a separately signed UAC helper implementing the same protocol
and remains unavailable until that helper exists.

## Installation-media authorization

The bootable-media welcome application does not inherit broad shell or root
authority. Its helper accepts only inventory, identity, and the fixed fresh or
reinstall operation. It excludes the physical disk backing the running recovery
home/root, rejects mounted/read-only/undersized targets, uses a per-device
exclusive lock, and requires a matching identity digest plus a device-specific
typed phrase immediately before mutation.

The compatible Valve installer is patched once while the image is built, using
guarded exact structural anchors, and installed root-owned in the immutable
recovery root. The desktop user cannot replace the program executed by `sudo`.
Generic-PC installation skips Steam Deck-specific BIOS/controller updates and
firmware secure erase; the selected disk is still repartitioned and its target
filesystems are recreated by Valve's install path.

## Remaining certification gates

- Physical NVIDIA GPU boot and rendering coverage
- Fresh Valve recovery installation and change propagation
- SteamOS A/B slot switching and update behavior
- Secure Boot and module-signing policy
- Hardware certification attestations bound to exact artifacts
- Authenticated offline mirrors for upstream outages

Until those pass, the UI must state the narrow verified result rather than
claiming broader certification.

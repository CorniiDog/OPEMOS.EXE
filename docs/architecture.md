---
layout: page
title: Architecture
description: Host, appliance, image, support-repository, and trust boundaries.
---

# Architecture and trust boundaries

SteamOS NVIDIA Image Builder is a local desktop workflow. The user supplies an
official Valve recovery image; the application creates disposable working
storage and exports a separate result. It does not upload or redistribute the
Valve image.

## Responsibility boundaries

The read-only governance authority is
[`BOUNDARIES.md`](https://github.com/CorniiDog/OPEMOS.EXE/blob/main/BOUNDARIES.md).
The table below is only an implementation summary.

| Component | Owns | Must not own |
| --- | --- | --- |
| Main/progress UI | Image selection, explicit user choices, status, cancellation, and diagnostics | Compatibility decisions, shell commands, credentials, or filesystem mutation |
| Rust host backend | State machines, safe paths, downloads, hashes, QEMU lifecycle, immutable pins, handoffs, result validation, and export | Trusting human log text or silently selecting compatibility fallbacks |
| Native Fedora appliance | Fast read-only image inspection, disposable overlay creation, marker mutation, and independent output inspection | NVIDIA compatibility policy or access to unrelated host directories |
| Managed x86_64 Fedora appliance | Exact-kernel NVIDIA compilation and offline SteamOS-root validation/mutation | Selecting arbitrary headers, packages, signers, roots, or A/B slots |
| NVIDIA support repository | Resolver/build/install contracts, reviewed keys and userspace locks, artifact formats, and canonical publishing | Choosing a user image or host output path |
| NVIDIA source repository | Versioned project patches and exact source commits | Image mutation, release authorization, or runtime credentials |
| Gamescope repository | Gamescope-specific source/artifact policy | NVIDIA kernel-module fallback policy |

## Host backend module layout

The Tauri crate root intentionally contains only shared policy constants,
module wiring, and the public application entry point. Backend responsibilities
are separated as follows:

| Rust module | Responsibility |
| --- | --- |
| `app.rs` | Tauri construction, fixed command registration, and application shutdown events |
| `appliance.rs` | QEMU/QMP/SSH processes, disposable runtimes, host preparation, health, and workflow command orchestration |
| `contracts.rs` | Versioned support/build/install/manifest data and pinned support-file identities |
| `image.rs` | Input validation, layout inspection, working-copy mutation, space checks, export, and independent verification |
| `nvidia.rs` | NVIDIA/source resolution, authenticated downloads, reviewed userspace closure, exact builds, and publication |
| `installer.rs` | Offline-root handoff, structured support-result validation, storage policy, and target mutation |
| `settings.rs` | Versioned preferences and GitHub maintainer authentication/authorization |
| `windows.rs` | Native progress and maintainer child-window construction |
| `tests.rs` | Default and explicitly ignored live integration tests |

The frontend follows the same boundary: diagnostic compaction lives in
`log-diagnostics.js`, while ANSI/control parsing and safe DOM rendering live in
`terminal-renderer.js`. Compatibility and command construction remain in Rust.

## Data flow

    user recovery image (read-only)
              |
              v
    Rust signature detection + hashing
              |
              v
    normalized raw runtime storage -----> native Fedora inspection
              |                                  |
              |                                  v
              |                           disposable qcow2 overlay
              |                                  |
              +--------------------------> x86_64 Fedora
                                                 |
                               pinned modules + reviewed userspace lock
                                                 |
                                                 v
                                   validate-only, then mutation
                                                 |
                                                 v
    Rust export to a create-only partial file
              |
              v
    fresh native Fedora independent inspection
              |
              v
    atomic image + manifest finalization

The original image is never attached writable. The working overlay is the only
SteamOS block device mutated, and it is discarded after failures. The x86_64
worker is separate because an Apple Silicon appliance cannot execute SteamOS's
x86_64 pacman and mkinitcpio tools correctly.

## Protocol and lifecycle

Rust launches QEMU directly and allocates loopback-only SSH and QMP ports.
Cloud-init writes a fixed readiness marker. After SSH becomes available, Rust
requires protocol version 1, the expected guest architecture, sufficient guest
space, and the complete required-tool inventory. Process exit, marker mismatch,
health failure, and timeout are distinct lifecycle failures.

Each runtime directory contains ephemeral QEMU state, cloud-init media, SSH
keys, logs, normalized storage, overlays, and staged artifacts. Runtime
directories and appliance images are ignored by Git. Normal completion removes
ephemeral workers; diagnostic logs are archived without embedding host paths in
the generated image manifest.

## Supply-chain boundary

Normal NVIDIA installation accepts only:

- an immutable support commit whose required files match embedded sizes and
  SHA-256 hashes;
- an exact SteamOS/kernel/NVIDIA identity;
- an authenticated module archive with matching provenance and vermagic;
- an exact reviewed userspace lock and minimal keyring;
- package and detached-signature bytes matching that lock; and
- a structured installer result independently revalidated by Rust.
- a rootfs-resident payload receipt binding the validated module, userspace,
  firmware, and initramfs evidence so later Valve-installer propagation can be
  checked by exact `receiptId`.

Logs are diagnostic only. A missing lock, changed signer, unavailable historical
input, ambiguous kernel/root/EFI/var partition, or mismatched result fails
closed and becomes a maintainer compatibility issue.

The support-owned bounded result/progress validator runs inside the x86_64
appliance after both validation-only and mutation attempts. Rust separately
requires and cross-checks the mandatory success proofs; neither an installer
exit code nor a receipt by itself can promote an image.

## macOS development bootstrap

Run:

    ./cargodev_init_macos.sh

The script supports Apple Silicon and Intel macOS, installs missing Homebrew
dependencies, reports every required tool version, enforces minimum supported
versions, and launches Tauri development mode. The native appliance can be
built with:

    ./builder/appliance/build_macos.sh

On Apple Silicon, prepare the separate software-emulated installer/build worker
with:

    ./builder/appliance/build_macos.sh --architecture x86_64

Generated qcow2 images, appliance work directories, runtime directories, logs,
keys, and output images must remain untracked.

## Current compatibility and limitations

- macOS is the implemented host platform; Apple Silicon is the primary tested
  host and Intel macOS follows the native x86_64 QEMU path.
- SteamOS 3.8.14 with NVIDIA 575.64.05 is the first reviewed userspace-lock
  target. Other pairs require their own reviewed lock.
- NVIDIA mutation can be structurally validated, but the result is not yet
  classified as install-ready. Valve installer propagation, Gamescope changes,
  A/B update behavior, and NVIDIA hardware boot remain separate gates.
- The application has a fail-closed macOS USB writer and independently tested
  raw-device copy/read-back engine. It accepts only a manifest-bound,
  sector-aligned raw output and a repeatedly validated whole external physical
  removable disk, then requires a short-lived one-use token and explicit final
  confirmation. Normal packaged physical writes remain unavailable until a
  signed least-privilege helper is installed; running the GUI as root is not a
  supported workaround.

## Troubleshooting boundary

Users should resolve only ordinary input, disk-space, and transient-network
problems. Missing exact artifacts, headers, reviewed locks, signer changes,
compiler failures, and compatibility mismatches are maintainer issues. Preserve
the smart diagnostic-log summary when reporting those failures; do not source
alternate packages or keys manually.

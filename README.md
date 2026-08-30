# SteamOS NVIDIA Image Builder

A desktop application that takes an official Valve SteamOS recovery image and prepares a locally generated NVIDIA-oriented SteamOS image.

## Current milestone

The first target is macOS. The desktop shell provides drag-and-drop, file picker fallback, Valve download-page access, and one image-driven build action. A separate progress window automatically manages the builder appliance, displays live logs and status, supports cancellation, and reveals the prototype result in Finder.

The Rust backend now prepares a disposable Fedora session, launches QEMU in the background, polls the guest's SSH readiness marker, reports lifecycle states, and performs graceful shutdown with a forced-stop fallback. Prototype output is still **not** bootable SteamOS.

## Architecture

The Tauri frontend invokes a fixed set of Rust commands; it does not pass arbitrary shell commands to the host or guest. Rust owns the QEMU child process and creates a unique runtime directory containing an ephemeral SSH identity, cloud-init seed, qcow2 overlay, writable UEFI variables, and `qemu.log`. The pristine Fedora appliance remains unchanged.

Closing the progress window cancels the active prototype build. Closing the main application gracefully powers off the managed guest, falls back to terminating QEMU after a bounded wait, archives `qemu.log`, and removes the disposable overlay and SSH credentials. Abandoned inactive session directories are cleaned on the next launch.

Rust detects input format from file signatures rather than extensions. Raw images pass through unchanged; `.bz2`, `.gz`, and `.xz` streams are decompressed into raw storage inside the disposable session with live hashing and compressed-byte progress. QEMU receives only that raw image as a read-only virtio block device, while the original compressed or raw source remains outside the guest. Fedora inventories the disk, partitions, filesystems, labels, UUIDs, sizes, and offsets without mounting it. Rust verifies hashes for both the original source and attached raw image before and after the session. NVIDIA build/install logic will come from `open-gpu-kernel-modules-steamos-support`, patched NVIDIA source from `open-gpu-kernel-modules-steamos`, and the compositor payload from `gamescope-nvidia`.

The current guest protocol exposes only fixed Rust-owned operations. Protocol version `1` provides a health check for guest identity, architecture, free space, and required tools; a deterministic host→guest→host transfer probe verified byte-for-byte; synthetic inspection and mutation fixtures; and structured read-only inspection of the selected raw image. The synthetic mutation test clones the read-only source, mounts only the working copy writable, adds a deterministic marker, unmounts and locks the copy read-only, then verifies the source hash is unchanged and the output hash differs. The frontend cannot submit arbitrary guest shell commands.

## Development

```bash
npm install
npm run dev
```

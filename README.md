# SteamOS NVIDIA Image Builder

A desktop application that takes an official Valve SteamOS recovery image and prepares a locally generated NVIDIA-oriented SteamOS image.

## Current milestone

The first target is macOS. The desktop shell provides drag-and-drop, file picker fallback, Valve download-page access, builder-appliance controls, prototype progress, and automatic Finder reveal.

The Rust backend now prepares a disposable Fedora session, launches QEMU in the background, polls the guest's SSH readiness marker, reports lifecycle states, and performs graceful shutdown with a forced-stop fallback. Prototype output is still **not** bootable SteamOS.

## Architecture

The Tauri frontend invokes a fixed set of Rust commands; it does not pass arbitrary shell commands to the host or guest. Rust owns the QEMU child process and creates a unique runtime directory containing an ephemeral SSH identity, cloud-init seed, qcow2 overlay, writable UEFI variables, and `qemu.log`. The pristine Fedora appliance remains unchanged.

Once the guest reports the exact readiness marker, later milestones will pass a copy of the user-selected Valve image into the guest for controlled image operations. NVIDIA build/install logic will come from `open-gpu-kernel-modules-steamos-support`, patched NVIDIA source from `open-gpu-kernel-modules-steamos`, and the compositor payload from `gamescope-nvidia`.

## Development

```bash
npm install
npm run dev
```

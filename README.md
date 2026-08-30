# SteamOS NVIDIA Image Builder

A desktop application that takes an official Valve SteamOS recovery image and prepares a locally generated NVIDIA-oriented SteamOS image.

## Current milestone

The first target is macOS. The initial shell provides drag-and-drop, file picker fallback, Valve download-page access, a guide area, prototype progress, and automatic Finder reveal.

The Fedora/QEMU backend is intentionally not implemented yet. Prototype output is **not** bootable SteamOS.

## Development

```bash
npm install
npm run dev
```

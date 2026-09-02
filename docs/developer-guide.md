---
layout: page
title: Developer guide
description: Set up the project, run validation, build appliances, and publish documentation.
---

## Repository setup

```bash
git clone https://github.com/CorniiDog/OPEMOS.EXE.git
cd OPEMOS.EXE
npm ci
./cargodev_init_macos.sh
```

The bootstrap reports Xcode tools, Homebrew, Rust, Node, npm, QEMU,
compression, GPG, Python, Git, curl, and SSH versions before starting Tauri.

## Appliance preparation

```bash
./builder/appliance/build_macos.sh
./builder/appliance/build_macos.sh --architecture x86_64
```

The second command prepares the software-emulated NVIDIA build and offline-root
installation worker used on Apple Silicon. Generated qcow2 images, runtime
directories, logs, keys, normalized images, and outputs must remain untracked.

## Local validation

```bash
npm run test:all
```

This runs frontend contracts, documentation validation, repository hygiene, and
the default Rust suite. Separately scoped commands include:

```bash
npm run test:vm-headless
npm run test:vm-lifecycle
npm run test:package-headless
```

Ignored Rust tests perform live GitHub, Arch, Valve, QEMU, recovery-image,
macOS authorization, or virtual-media work and must be selected deliberately.

## Backend boundaries

| Module | Responsibility |
| --- | --- |
| `app.rs` | Tauri construction, fixed command registration, shutdown events |
| `appliance.rs` | QEMU/QMP/SSH lifecycle and runtime state |
| `contracts.rs` | Versioned data and immutable support-file pins |
| `image.rs` | Image inspection, mutation, space policy, export, final verification |
| `nvidia.rs` | Resolution, downloads, source selection, builds, publication |
| `installer.rs` | x86 handoff and structured OPEMOS install-result validation |
| `settings.rs` | Preferences and GitHub maintainer authorization |
| `windows.rs` | Native window construction and coupling |

The frontend never submits arbitrary host or guest shell commands.

## Documentation

Documentation follows the OPEMOS GitHub Pages structure and lives in `docs/`.
Validate it locally with:

```bash
npm run test:docs
```

After merging the Pages workflow, select **Settings → Pages → Build and
deployment → GitHub Actions** once. Pull requests build without deploying;
documentation changes on `main` deploy automatically.

Screenshot capture instructions live in the
[screenshot asset guide](assets/screenshots/README.md).

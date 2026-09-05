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

## Experimental Ubuntu/Debian validation

The Linux host-testing backend is under development. See the
[experimental Linux guide](linux-testing.md) for explicit opt-in, dependency
discovery, accelerator selection, and resource limits. The current validation
baseline exercises shared contracts, caches, disposable handoffs, export
transactions, and process cleanup on Ubuntu 24.04.4 x86_64. It does not establish
Debian, macOS, real QEMU appliance, physical-media, or SteamOS/NVIDIA hardware
validation. Linux physical-device writing remains unavailable.

Use Node.js 22 and stable Rust with `clippy` and `rustfmt`. Both `cargo` and
`rustc` must be on PATH because verifier lifecycle tests compile small fixture
programs. Install the same Linux build dependencies as CI:

```bash
sudo -n apt-get install --yes build-essential curl file \
  libayatana-appindicator3-dev librsvg2-dev libssl-dev \
  libwebkit2gtk-4.1-dev patchelf pkg-config
. "$HOME/.cargo/env"
npm ci
```

Obtain Core inputs from the canonical GitHub repository at the exact commit.
Do not point these variables at a sibling development checkout. For the current
lineage integration pin:

```bash
git clone --depth 56 --branch main \
  https://github.com/CorniiDog/open-gpu-kernel-modules-steamos-support \
  /absolute/path/to/github-core-cache
test "$(git -C /absolute/path/to/github-core-cache rev-parse HEAD)" = \
  adf372b857cd348b6a18680b45ffcea790f04d4b
export OPEMOS_CORE_CONTRACT_ROOT=/absolute/path/to/github-core-cache
export OPEMOS_CORE_EXPECTED_COMMIT=adf372b857cd348b6a18680b45ffcea790f04d4b
```

The test guard also requires that cache's `origin` URL is the canonical HTTPS
GitHub repository and resolves every older fixture pin to its exact commit before
reading bytes with `git show`.

On the coordinated development host, run all compilation and large suites through
the `heavy.sh` wrapper required by `AGENTS.md`; for example, with
`OPEMOS_HEAVY` set to that wrapper's absolute path:

```bash
"$OPEMOS_HEAVY" npm run test:all
```

The wrapper supplies serial test execution and the shared CPU/memory budget.
Exit 75 means the slot is busy, not a test failure; wait for the scheduler rather
than bypassing the wrapper. Production generation trust and activation remain
blocked by the publication inputs in [TODO.md](../TODO.md).

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

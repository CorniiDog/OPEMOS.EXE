<p align="center">
  <img src="docs/assets/images/opemos-pill.svg" alt="OPEMOS gradient pill" width="112">
</p>

<h1 align="center">OPEMOS.EXE</h1>

<p align="center"><strong>Desktop image building for exact-kernel NVIDIA on SteamOS.</strong></p>

[![Checks](https://github.com/CorniiDog/OPEMOS.EXE/actions/workflows/checks.yml/badge.svg)](https://github.com/CorniiDog/OPEMOS.EXE/actions/workflows/checks.yml)
[![Documentation](https://github.com/CorniiDog/OPEMOS.EXE/actions/workflows/pages.yml/badge.svg)](https://github.com/CorniiDog/OPEMOS.EXE/actions/workflows/pages.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

OPEMOS.EXE is the desktop SteamOS NVIDIA Image Builder. It takes an official
Valve recovery image, performs exact-kernel NVIDIA resolution and installation
inside managed Fedora appliances, independently validates the result, and
exports a separate image, a removable USB target, or both.

The original recovery image is opened read-only and is never redistributed by
this project.

> OPEMOS.EXE is active development software. NVIDIA image mutation has passed
> structural validation, but Valve installer propagation, A/B update behavior,
> and physical NVIDIA hardware boot are still separate certification gates.

## Screenshots

| Main workflow | Build progress |
| --- | --- |
| _Screenshot reserved: main image and USB workflow_ | _Screenshot reserved: live validation and installation progress_ |

The documentation site contains additional prepared screenshot slots and the
exact filenames to use when captures are ready.

## Start here

- [Documentation home](https://corniidog.github.io/OPEMOS.EXE/)
- [Getting started](docs/getting-started.md)
- [Build workflow](docs/workflow.md)
- [Developer guide](docs/developer-guide.md)
- [Architecture and trust boundaries](docs/architecture.md)
- [Security model](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Roadmap](TODO.md)

## Current host support

| Host | Status |
| --- | --- |
| Apple Silicon macOS | Primary development and tested host |
| Intel macOS | Supported architecture path; needs broader hardware testing |
| Windows | Planned; signed least-privilege USB helper not yet implemented |
| Linux | Not yet a supported desktop host |

The first reviewed target is SteamOS 3.8.14, kernel
`6.16.12-valve24.4-1-neptune-616-gfe145653a794`, and NVIDIA `575.64.05`.
No closest-kernel substitution is permitted.

## Develop on macOS

```bash
git clone https://github.com/CorniiDog/OPEMOS.EXE.git
cd OPEMOS.EXE
./cargodev_init_macos.sh
```

The bootstrap checks or installs the required Homebrew tools and launches Tauri
development mode. Prepare the managed x86_64 worker on Apple Silicon with:

```bash
./builder/appliance/build_macos.sh --architecture x86_64
```

Run the local validation suite:

```bash
npm ci
npm run test:all
```

Live appliance, network, packaging, and raw-device tests remain explicitly
ignored or separately named because they require local images, downloads,
virtual media, or macOS authorization.

## Repository boundaries

| Repository | Responsibility |
| --- | --- |
| [`OPEMOS.EXE`](https://github.com/CorniiDog/OPEMOS.EXE) | Desktop UI, recovery-image inspection, QEMU lifecycle, safe export, USB workflow, and independent final-image validation |
| [`OPEMOS`](https://github.com/CorniiDog/OPEMOS) | Exact NVIDIA artifact resolution, builds, userspace locks, offline installation, provenance, and publication |
| [`open-gpu-kernel-modules-steamos`](https://github.com/CorniiDog/open-gpu-kernel-modules-steamos) | Versioned project NVIDIA source branches and SteamOS-specific patches |

## Safety summary

- The selected recovery image is attached read-only.
- Mutation occurs only in a disposable qcow2 overlay.
- NVIDIA artifacts require exact kernel, architecture, vermagic, hashes, and
  authenticated provenance.
- Userspace packages require reviewed locks, detached signatures, and an exact
  dependency closure.
- Failed or cancelled overlays are discarded and never receive the final
  NVIDIA image name.
- The GUI never runs as root. macOS USB writing uses a narrowly authorized raw
  device descriptor and revalidates the target immediately before destruction.
- Human-readable logs are diagnostic only; machine-readable contracts decide
  success.

## Licensing and trademarks

Project source is available under the [MIT License](LICENSE). Third-party
runtime components retain their own licenses and distribution terms.

SteamOS, Steam Deck, and Steam are trademarks of Valve Corporation. NVIDIA and
related marks are trademarks of NVIDIA Corporation. This unofficial community
project is not affiliated with, endorsed by, or supported by Valve or NVIDIA.

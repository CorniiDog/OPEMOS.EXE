---
layout: page
title: Getting started
description: Prepare macOS, choose an official Valve image, build, and understand the output.
---

## Before you begin

OPEMOS.EXE currently targets macOS. Apple Silicon is the primary development
host; Intel macOS follows the native x86_64 appliance path but has less physical
coverage.

You need enough free space for the source image, disposable overlay, final raw
image, and runtime reserve; QEMU and the managed Fedora appliance; an official
Valve SteamOS recovery image; and network access for exact OPEMOS artifacts and
authenticated userspace inputs.

The application reports exact required and available storage before expensive
mutation. It does not resize SteamOS partitions automatically.

## Development launch

```bash
git clone https://github.com/CorniiDog/OPEMOS.EXE.git
cd OPEMOS.EXE
./cargodev_init_macos.sh
```

On Apple Silicon, prepare the x86_64 appliance once:

```bash
./builder/appliance/build_macos.sh --architecture x86_64
```

## Build an image

1. Download the official SteamOS recovery image from Valve.
2. Drag the `.img`, `.img.bz2`, `.img.gz`, or `.img.xz` into OPEMOS.EXE.
3. Review the detected SteamOS version, kernel, architecture, and output.
4. Leave NVIDIA source on **Automatic (Recommended)** unless deliberately
   testing a pinned project branch.
5. Choose whether to retain the image, write a selected removable drive, or do
   both.
6. Click **Build NVIDIA Image**.
7. Keep the progress window open while the managed appliances validate and
   mutate the disposable overlay.

Automatic mode never chooses an experimental upstream NVIDIA tag. It accepts
only an exact kernel and a bounded same-series publication policy defined by
OPEMOS.

## Read the result

| Result | Meaning |
| --- | --- |
| `locally-built-verified` | Exact local build passed structural and provenance checks; hardware certification is separate |
| `nvidia-mutation-valid` | Offline mutation and independent image inspection passed |
| `development-unverified` | Build completed but a production trust property was not established |
| Marker-only image | NVIDIA installation was not accepted; useful only as an earlier development milestone |
| Failed | Disposable output is rejected and the original remains unchanged |

Successful output includes a versioned manifest sidecar. It records basenames,
hashes, target identity, tool/appliance identity, trust, and verification state
without embedding full host paths.

## Export to USB

USB export accepts only a whole external physical removable device. Immediately
before writing, OPEMOS.EXE revalidates identity and capacity, requires the exact
`ERASE diskN` phrase, asks for final confirmation, writes through a narrowly
authorized raw-device descriptor, reads the written range back, verifies its
SHA-256, and ejects it.

The GUI must not run as root. Virtual and internal disks remain ineligible even
though the copy engine is tested against disposable virtual media.

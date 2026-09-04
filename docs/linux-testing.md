---
layout: page
title: Experimental Linux host testing
description: Ubuntu and Debian host prerequisites, explicit testing controls, and remaining validation gates.
---

# Experimental Ubuntu/Debian host testing

This is an experimental **x86_64 EXE host** path alongside macOS. It does not
install Ubuntu/Debian into the target image or certify SteamOS/NVIDIA hardware.
Ownership remains defined by [BOUNDARIES.md](../BOUNDARIES.md). Core supplies
compatibility policy and authenticated contracts; EXE owns host adapters and
managed disposable appliances.

Ubuntu **24.04.4** is the only host version used for this implementation's local
testing. Debian is an intended testing platform, not a validated distribution.
An actual Linux application launch and managed-appliance boot have not yet been
validated.
These host checks do not establish a successful appliance boot, complete image
build, packaged application launch, or physical-hardware result. Consult TODO
for the exact validation evidence and remaining gates.

## Install development prerequisites

Use Rust with Cargo and Node.js **22**, including npm. For Ubuntu 24.04 or a
Debian environment providing WebKitGTK 4.1, the package prerequisites are:

```bash
OPEMOS_HEAVY="/home/connor/Documents/ChatGPT/Handoff troubleshooting/opemos-scheduler/heavy.sh"
"$OPEMOS_HEAVY" sudo -n apt-get update
"$OPEMOS_HEAVY" sudo -n apt-get install --yes --no-install-recommends \
  build-essential pkg-config curl wget file libssl-dev liblzma-dev \
  libwebkit2gtk-4.1-dev libxdo-dev librsvg2-dev \
  libayatana-appindicator3-dev patchelf \
  qemu-system-x86 qemu-utils ovmf genisoimage openssh-client python3
```

These are explicit host installation commands; the doctor below never installs
packages, changes permissions, joins groups, or changes network configuration.
Run them only when host package installation is authorized. A missing package
on another distribution version is a setup blocker, not evidence of support.
Keep builds as your ordinary user.

The runtime needs a matched OVMF pair under `/usr/share/OVMF`: either
`OVMF_CODE_4M.fd` plus `OVMF_VARS_4M.fd`, or the legacy `OVMF_CODE.fd` plus
`OVMF_VARS.fd`. Do not mix pairs or substitute secure-boot variants. The writable
variable store belongs to the disposable appliance session; never modify the
installed template.

## Inspect and launch

From the repository root, select one explicit acceleration mode:

```bash
export OPEMOS_EXPERIMENTAL_LINUX=1
export OPEMOS_LINUX_ACCEL=kvm
bash scripts/check_linux_host.sh
```

KVM needs read/write access to `/dev/kvm`. Access alone does **not** prove KVM
usability: the application must pass its runtime ioctl probe. The doctor only
inventories prerequisites and returns a nonzero status for missing entries.
It cannot authenticate appliances, authorize Core actions, or establish output
trust. There is no automatic software fallback after a failed KVM launch.

For explicitly slower software-only testing:

```bash
export OPEMOS_EXPERIMENTAL_LINUX=1
export OPEMOS_LINUX_ACCEL=tcg
bash scripts/check_linux_host.sh
```

The `OPEMOS_DOCTOR_*` environment overrides are solely for isolated script
tests; they neither configure nor authorize the application's runtime backend.

On this coordinated development host, **all compilation, large tests,
packaging, compression, and QEMU work must use the shared scheduler wrapper**:

```bash
OPEMOS_HEAVY="/home/connor/Documents/ChatGPT/Handoff troubleshooting/opemos-scheduler/heavy.sh"
"$OPEMOS_HEAVY" npm ci
"$OPEMOS_HEAVY" npm run dev:linux-test
```

Launch from a graphical desktop session. Exit **75** means the shared resource
slot is occupied: wait for scheduler coordination or do light work. Do not
retry-loop, bypass the wrapper, increase its limits, or run builds as root.
Appliance operations require an already provisioned, appropriately authenticated
Fedora appliance; installing QEMU does not provision or authenticate it.
Missing appliance state must remain unavailable rather than trigger an
unreviewed image download.

The Linux entry point requires both explicit environment choices above, an
x86_64 Linux host, and a graphical session for development launch. Runtime
Ubuntu/Debian discovery and all appliance/Core checks still apply. Unsupported
extra CLI arguments are rejected. The separate test configuration uses an opaque
main window and its own application identifier; macOS defaults remain unchanged.

Create a local **debug Debian package** without installing it:

```bash
"$OPEMOS_HEAVY" npm run build:linux-test
"$OPEMOS_HEAVY" npm run test:package-linux
```

The package check extracts only this locally generated archive into a temporary
directory. It checks metadata, amd64 ELF identity, the exact Tauri bundle-marker
patch, shared-library resolution, archive permissions, the desktop entry, and absence of maintainer
scripts. It does not install the package or launch its GUI.

The package is written under `src-tauri/target/debug/bundle/deb/`. This command
needs no graphical session. It deliberately uses a debug build and the `deb`
bundle target, with no signing, publication, or system installation. This test
package requires glibc **2.39 or newer**, matching the Ubuntu 24.04 build
baseline; the Ubuntu-built binary is not a Debian 12 package. OpenSSL 3 and
liblzma runtime dependencies are declared alongside Tauri's GTK/WebKit
dependencies. Debian packaging still requires its own build and validation.
The test
application identifier does not provide isolation for user-selected images or
shared host tools: use disposable inputs. To test the compiled application from
a graphical desktop, preserving the same explicit environment and resource cap:

```bash
"$OPEMOS_HEAVY" src-tauri/target/debug/steamos-nvidia-image-builder
```

The existing `build:app` and default release bundle targets remain macOS paths.
A package build alone does not validate graphical launch, installed-package
integration, Debian compatibility, managed guest boot, or hardware.

## Validation and limits

Managed-appliance planning uses the smaller of physical RAM and all inherited
cgroup-v2 `memory.max` limits. Its existing minimum is 6 GiB; the shared 2 GiB
scheduler budget therefore leaves managed-appliance readiness unavailable.
Do not lift that cap. The disposable tool smoke below uses only a 64 MiB paused
QEMU machine, with no host disks or networking, and does not establish Fedora
boot or image-build readiness.

After installing prerequisites, explicitly exercise seed-ISO creation,
qcow2 backing-file preservation, and TCG startup/cleanup:

```bash
"$OPEMOS_HEAVY" env OPEMOS_EXPERIMENTAL_LINUX=1 OPEMOS_LINUX_ACCEL=tcg \
  cargo test --manifest-path src-tauri/Cargo.toml live_linux_disposable_host_tools -- --ignored --nocapture
```


The focused doctor tests use disposable directories and fake executable paths:

```bash
"$OPEMOS_HEAVY" node --test tests/linux-host-doctor.test.mjs
```

For the applicable repository gates:

```bash
"$OPEMOS_HEAVY" cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
"$OPEMOS_HEAVY" cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
"$OPEMOS_HEAVY" cargo test --manifest-path src-tauri/Cargo.toml
"$OPEMOS_HEAVY" npm run test:frontend
```

Use only disposable image files and managed appliances for initial Linux
integration work. Preserve source images, retain cancellation/process cleanup,
and independently verify exported images. Storage admission checks available
bytes and finite inode capacity; passing admission is not a reservation against
other host writers or proof that later writes cannot fail.

**Physical USB writing is unsupported on Linux.** Do not expose macOS diskutil
assumptions or bypass that refusal. Real removable-device support needs its own
verified Linux implementation and safety tests.

## Inspect Core compatibility without activation

Open **Settings → Inspect Core compatibility…** in either the macOS application
or the experimental Linux application. Paste a Core resolver schema-2 JSON
result and choose **Inspect pasted result**. The existing Rust Core consumer
checks the same document structure and 1 MiB byte limit used by its resolver
adapter. Structural validity does not authenticate a pasted result: the dialog
always identifies it as **Unverified pasted document**.

Debug builds also offer **Compatible fixture** and **No-artifact fixture** from
the existing repository conformance fixtures. Their results are always labeled
**Development fixture — non-production**; release builds reject fixture requests.
A reported exact-target action is shown as text and cannot be executed here.
The inspector offers no build, download, trust, or generation-activation action.
It needs no credentials, network requests, image files, guest, or cache changes.

The dialog displays Core's status, target, reason, publication, artifact trust,
and next action without inventing another decision. Editing, clearing, or
closing invalidates pending preview responses; closing also clears pasted text.
Long fields are explicitly truncated for display. Keyboard focus stays within
the native dialog, and main-window file drops are ignored while it is open.
Frontend behavior and Rust adapter tests are automated; visual rendering and
native keyboard/focus behavior still require a graphical desktop validation.

This host opt-in does not install production keys, select publication policy,
authorize source fallback, or activate a generation. Existing production trust and activation gates remain
intact. macOS regression validation, Debian validation, managed-appliance smoke
tests, final-image equivalence, and real SteamOS/NVIDIA certification require
their own recorded evidence.

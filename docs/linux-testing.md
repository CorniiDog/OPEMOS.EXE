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
A development binary and the extracted debug-package binary have launched and
closed in an Ubuntu 24.04.4 Wayland session, with no remaining launcher or EXE
processes. The package was not installed. GNOME denied noninteractive screenshot
access, so pixel rendering, delivered key-event traversal, companion windows,
desktop integration, and interactive close remain unvalidated. AT-SPI has
validated the main native frame, WebKit Settings/compatibility controls, exact
Settings and compatibility-dialog focus order, debug generation row names and
values, scoped dialog close, and main-document survival on Ubuntu Wayland.
These host checks do not establish a
successful appliance boot, complete image build, installed package, or
physical-hardware result. Consult TODO
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
The launcher snapshots the exact pre-launch bytes and modes of `Cargo.toml` and
the Linux capability schema path. After normal exit, signal handling, or child
failure, it waits for the isolated process group to disappear, restores
preexisting files, and removes only a schema proven absent before launch. A
launcher SIGKILL can still bypass this in-process restoration.

Create a local **debug Debian package** without installing it:

```bash
"$OPEMOS_HEAVY" npm run build:linux-test
"$OPEMOS_HEAVY" npm run test:package-linux
```

The package check extracts only this locally generated archive into a temporary
directory. It checks metadata, amd64 ELF identity, the exact Tauri bundle-marker
patch, shared-library resolution, archive permissions, the desktop entry, and absence of maintainer
scripts. It does not install the package or launch its GUI.

From a graphical desktop, extract the package to a disposable directory and run
the bounded accessibility smoke against its exact binary path:

```bash
dpkg-deb -x 'src-tauri/target/debug/bundle/deb/OPEMOS EXE Linux Test_0.1.0_amd64.deb' /tmp/opemos-exe-package
"$OPEMOS_HEAVY" env OPEMOS_EXPERIMENTAL_LINUX=1 \
  npm run test:package-linux-gui -- \
  --expect-host-unavailable \
  --executable /tmp/opemos-exe-package/usr/bin/steamos-nvidia-image-builder
```

The smoke inherits the graphical session environment, including its AT-SPI bus
and accessibility bridge setting. Because the shared scheduler caps this command
at 2 GiB while managed appliances require 6 GiB, `--expect-host-unavailable`
requires the experimental window, readiness section, and unavailable heading and
the exact ordered explanation that KVM is unavailable, TCG requires explicit
selection, and automatic fallback is disabled. The unavailable surface must
expose exactly Settings, image selection, and Valve's download page as buttons;
build and USB-writing actions must remain absent. It rejects any Linux-ready or
normal-ready heading, altered fallback policy, extra button, or unexpected
initial button focus. The smoke also opens the native recovery-image chooser,
requires its SteamOS recovery-image filter without an all-files option, requires
Open to remain disabled before selection and Cancel to remain enabled, cancels
without selecting a file, requires both chooser accessibility nodes to disappear,
and requires focus to return to Choose Image. Omit the unavailable
assertion only when
running outside this scheduler with a deliberately different resource budget.
It accepts only the accessibility application
whose process ID matches the process it launched, then opens Settings and the
read-only Core compatibility inspector. In the tested unauthenticated package
session, the Settings landmark must expose exactly Close, the two enabled update
preferences, Connect GitHub, and the compatibility inspector in that focus order.
Opening Settings must focus its Close control, and closing Settings must restore
focus to its opener. CUDA omission, maintainer workspace access, and automated
release must each remain present for explanation but disabled and unfocusable in
the unauthenticated package session. The compatibility dialog must expose exact
warnings that its structural preview is unauthenticated and non-authorizing,
fixtures are debug-only and non-production, and local inputs are cleared without
credentials, downloads, cache changes, or guest operations. The smoke also
verifies the ordered compatibility controls, initial Close focus, all four
development-fixture generation rows, and focus
restoration to the Settings opener after closing the dialog. It exercises both
fixture branches. The compatible branch must expose Core's exact publication,
artifact, pending-verification, and target fields. The no-artifact branch must
expose Core's exact status, reason, message, bounded exact-target build action,
architecture, and kernel policy in order. Clear must remove the result heading,
Core fields, next action, and all generation rows from the accessibility tree
while retaining focus on Clear. Reloading Compatible after Clear must reproduce
only its exact rows and retain focus on the fixture control. Closing and reopening
the populated dialog must expose no prior result fields and must restore the
native Close-first focus order. These remain non-production fixture data and
grant no authorization. It then
stops the
isolated application process group. It has
a 20-second default deadline (configurable from 1 through 60 seconds), reports
early application exit immediately with its status, refuses symlink or
non-executable inputs, pins the accepted regular executable to a no-follow file
descriptor before launch, and sends SIGKILL after a bounded SIGTERM grace
period. It takes bounded before/after `/proc` snapshots keyed by PID, kernel
start time, and process name, so PID reuse cannot hide a new `qemu-system-*`
process. It does not install the archive, use
production compatibility inputs, or start QEMU.

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

## Launcher cancellation

The experimental launcher forwards SIGINT and SIGTERM to its isolated Tauri
process group. It allows five seconds for shutdown, then sends SIGKILL if the
leader remains alive. When the leader exits, it stops any remaining group
members and preserves the command's exit status or reports termination.
Disposable subprocess tests cover graceful and stubborn children and leftover
children after leader exit. They do not establish native GUI launch/close or
managed-appliance lifecycle validation. SIGKILL of the launcher itself and
children that deliberately leave the group require separate supervision.

## Inspect Core compatibility without activation

Open **Settings → Inspect Core compatibility…** in either the macOS application
or the experimental Linux application. Select a local Core resolver schema-2
JSON file, or paste its contents and choose **Inspect pasted result**. Local
files must contain UTF-8 text and be nonempty and no larger than 1 MiB. The
existing Rust Core consumer checks the same document structure and 1 MiB byte limit used by its resolver
adapter. Structural validity does not authenticate a supplied result: the dialog
always identifies it as **Unverified document**. Filenames and file extensions
do not establish trust; only the selected contents are passed to the parser.

Debug builds also offer **Compatible fixture** and **No-artifact fixture** from
the existing repository conformance fixtures. Their results are always labeled
**Development fixture — non-production**; release builds reject fixture requests.
A reported exact-target action is shown as text and cannot be executed here.
The inspector offers no build, download, trust, or generation-activation action.
It needs no credentials, network requests, image files, guest, or cache changes.

The dialog displays Core's status, target, reason, publication, artifact trust,
and next action without inventing another decision. Editing, clearing, or
closing invalidates pending file reads and preview responses; closing also
clears pasted text and the file selection. Cancelling the file picker preserves
the current preview. Selecting the same file again performs a fresh read.
Long fields are explicitly truncated for display. Keyboard focus stays within
the native dialog, and main-window file drops are ignored while it is open.
Frontend behavior and Rust adapter tests are automated; visual rendering and
native keyboard/focus behavior still require a graphical desktop validation.

This host opt-in does not install production keys, select publication policy,
authorize source fallback, or activate a generation. Existing production trust and activation gates remain
intact. macOS regression validation, Debian validation, managed-appliance smoke
tests, final-image equivalence, and real SteamOS/NVIDIA certification require
their own recorded evidence.

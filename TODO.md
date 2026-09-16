# OPEMOS.EXE — Product Checklist

## Foundation and change policy

Commit `e0502833282ffd9055ecf46f75df82f71a9ee20f` is the current tested
foundation. It includes the macOS image workflow, managed Fedora appliances,
authenticated NVIDIA installation, USB export, installation-media welcome app,
and the first OPEMOS Core contract adapters.

Changes above this foundation must remain behaviorally close to it. Do not
remove a working path, safety check, validation step, or user-visible recovery
route until its replacement passes equivalent unit, integration, cancellation,
and failure tests. Any deliberate behavior change must be called out in the
commit that introduces it.

Required dependency direction:

```text
OPEMOS Core contracts
├── CLI
├── SteamOS Desktop Companion
├── SteamOS DRM/KMS interstitial
└── OPEMOS.EXE
```

Frontends are siblings and must never depend on one another. OPEMOS.EXE may
install an authenticated SteamOS frontend as target payload, but must not bundle
or invoke it as part of the macOS application runtime.

## Ownership boundary

Authority: [`BOUNDARIES.md`](BOUNDARIES.md). This checklist summarizes the
contract but must not redefine it.

OPEMOS.EXE owns:

- macOS windows, menus, accessibility, progress weighting, and diagnostics.
- Host QEMU and appliance lifecycle, cancellation, and cleanup.
- Recovery-image selection, normalization, overlays, partitions, and export.
- Authenticated host-to-guest transfer and USB writing.
- Independent final-image and output-manifest validation.
- The installation-media welcome UI and its narrowly scoped installer bridge.

OPEMOS Core owns:

- SteamOS/NVIDIA compatibility and release-selection policy.
- Reviewed userspace locks, trust policy, installation, verification, receipts,
  recovery, and structured progress/results.
- The installed SteamOS Desktop Companion, DRM/KMS interstitial, CLI, update
  guardian, and their backend/update contracts.
- Support build, test, packaging, publication, and device-deployment entry
  points.

The NVIDIA source repository owns NVIDIA source branches and patches. Valve
recovery images are user inputs and must never be committed or redistributed by
this repository.

## Current validated baseline

- [x] Build and run the Tauri application on macOS Apple Silicon.
- [x] Select, normalize, and inspect supported Valve recovery images without
  mutating the original.
- [x] Start disposable native and x86_64 Fedora appliances with bounded
  lifecycle control.
- [x] Resolve or locally build an exact-kernel NVIDIA artifact and verify its
  provenance, modules, userspace, firmware, and initramfs contract.
- [x] Stage normal-build packages only from the reviewed userspace lock; normal
  operation does not select newer packages from an Arch index.
- [x] Export a separately validated image and optionally write and byte-verify
  a selected whole removable USB device.
- [x] Reopen a manifest-bound existing NVIDIA image without rebuilding it.
- [x] Install the fullscreen welcome application and guarded target-disk picker
  into generated recovery media.
- [x] Provide Linux parity for the safe mock welcome preview. The root launcher
  serves only the real welcome frontend through its loopback mock controller,
  discovers Google Chrome/Chromium in fixed order, isolates browser and XDG state,
  refuses absent graphical sessions, and reaps both processes plus runtime state
  after normal server exit, browser close, or signals. Print-only mode retains the
  non-GUI contract; no disks, privileges, QEMU processes, or installers are reachable.
  PR #13 passed Debian package, frontend/docs, Linux integration, and Rust in both
  initial GitHub runs; build also passed.
- [x] Preserve an opaque fallback behind the cross-platform frosted-glass UI.
- [x] Provide bounded, color-aware logs, smart diagnostic copying, monotonic
  progress, keyboard navigation, and coupled companion windows.
- [x] Add fixture-tested schema-compatible consumers for Core resolver schema 2
  and installer validation, result, progress, module-verification, and
  userspace-verification, initramfs-workspace, initramfs-verification, and
  payload-receipt and gaming-payload schema 1.

Current outputs remain `nvidia-mutation-valid`. Do not call them
`install-ready`, hardware-certified, or update-safe until the gates below pass.

## Immediate work

### Experimental Ubuntu/Debian host testing (current user priority)

This authorizes an EXE host-testing path alongside macOS, not Ubuntu/Debian
installation targets, production activation, or hardware certification.

- [x] Finish the preserved appliance-handoff test change before extending the
  host backend. On Ubuntu 24.04.4 x86_64, scheduler-limited formatting and
  warnings-as-errors Clippy pass; the complete Rust suite passes 302 tests
  (25 ignored live/helper entries), and all 74 frontend tests plus documentation,
  hygiene, and boundary integrity checks pass. Core fixtures use immutable CI
  commit `3e49323fce266af8686039fb6487918ef5a64fd9`. Fix Linux dash watchdog
  signaling, bound process-group IDs, directly signal isolated Git-runner groups,
  and stop descendant-held pipes after leader exit. Real subprocess matrices
  now work with serial test-harness output. Debian, macOS, live QEMU, physical
  media, and hardware certification are not established by this host run.
- [x] Add explicit experimental Ubuntu/Debian x86_64 host capability/dependency
  reporting and UI labels. Wire bounded RAM/cgroup readers, matched OVMF pairs,
  genisoimage seed creation, and host-aware QEMU plans into both appliance paths;
  reuse existing Unix storage, descriptor, overlay, cleanup, and export code.
  The read-only prerequisite doctor rejects missing/non-executable tools,
  mixed firmware pairs, malformed/oversized OS metadata, and unsupported hosts.
- [x] Require explicit Linux opt-in plus an accessible KVM API and a successful
  selected-accelerator QEMU smoke, or explicitly selected TCG testing. Never
  silently fall back. Keep physical-device writing unavailable. macOS HVF/native
  and Apple-Silicon-to-x86 TCG plans retain their existing behavior in tests.
- [x] On Ubuntu 24.04.4 x86_64, run the real 64 MiB paused TCG smoke with no
  networking/host disks, create a seed ISO and disposable qcow2 overlay using
  paths with spaces, and verify the raw source hash is unchanged. Through the
  shared scheduler, formatting and Clippy pass, 308 Rust tests pass (27 ignored
  live/helper entries), the explicit Linux smoke passes, and 86 frontend tests
  plus documentation/hygiene checks pass against the same immutable Core CI pin.
- [x] Harden experimental Linux cgroup budget discovery: require an existing
  directory root and distinguish genuinely absent root memory.max from lookup
  errors or dangling links. Unreadable limits must stop readiness rather than
  silently fall back to physical RAM. Disposable filesystem tests cover nested
  child/ancestor/root minima, unlimited children, the physical-memory ceiling,
  malformed/duplicate memberships, traversal, missing groups/root, malformed
  ancestor limits, dangling links, directory-valued limits, and zero RAM.
  On Ubuntu 24.04.4 through the shared scheduler, formatting and Clippy pass,
  319 Rust tests pass (27 ignored), and all 98 frontend tests plus documentation,
  hygiene, and boundary integrity pass against the unchanged Core fixture pin.
  This does not change the scheduler cap or establish managed-appliance boot.
- [x] Validate a real Debian 12 headless host/package path in CI. The exact
  official Debian 12.15 slim amd64 platform manifest is pinned at
  `sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867`.
  A disposable local instance passed the real Debian 12 `/etc/os-release`
  prerequisite inventory with QEMU, OVMF, SSH, Python, and explicitly selected
  TCG under the shared 2 GiB/one-CPU wrapper. The separate debug-package
  configuration preserves the Linux test window and app identity while declaring
  Debian's glibc 2.36 and `libssl3` baseline. PR #10 built and inspected
  that package successfully in two GitHub runs; both Debian jobs, frontend/docs,
  Linux integration, Rust, and build passed. A successor disposable-container-only
  smoke installs the exact locally built package, verifies package-manager state,
  installed binary bytes, desktop-entry identity, and the complete installed-file
  inventory, then purges it on success, partial installation, or verification failure.
  It refuses missing opt-in, non-container/Debian 12 contexts, symlink packages,
  wrong package identity, and preinstalled packages. PR #12 passed the Debian package,
  frontend/docs, Linux integration, and Rust checks in both repaired GitHub runs;
  build also passed. PR #14 extends this disposable job with an isolated Xvfb,
  D-Bus, AT-SPI, and child-process subreaper session. It launches the installed
  debug package, verifies the unavailable-host, chooser, Settings, compatibility,
  focus, process-group, and no-new-QEMU contracts, then purges it; both final
  Debian runs pass. This establishes virtual-X11 graphical launch, not a physical
  Debian desktop, KVM, managed-appliance boot, publication, or hardware support.
- [ ] Validate managed Fedora appliance boot and image equivalence. The
  user-authorized scheduler cap is now 6 GiB, matching the existing host-budget
  minimum while retaining one-CPU serialization and no swap. A Linux-specific
  Fedora 44 appliance builder now resolves the pinned compose, requires Fedora's
  signed checksum plus exact image SHA-256, validates qcow2 structure, and
  atomically installs the image and provenance sidecar; resolve-only, malformed
  option, mandatory-signature, and atomic-publication tests pass. The authenticated
  x86_64 download verified Fedora key DBFCF71C6D9F90A6, signed image SHA-256
  28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f, and
  qcow2 structure. A one-vCPU TCG boot entered emergency mode after its 45-second
  guest device deadlines expired before slow udev coldplug exposed the image UUIDs;
  extending the host handshake wait to ten minutes did not change that result and
  was reverted. The separately authorized guest-only remediation preserved as source
  commits bddb0b80dcaf1e659cf25a227bcd2d37de01a9ed and
  827f15fe0121b6eed274715f06ba1b645d9f246a in PR
  https://github.com/CorniiDog/OPEMOS.EXE/pull/63 and squash-merged as
  da945cae6d6c9ea6e4c1fa1b5bfdc0d59f0c4a93 after exact Core approval and all
  nine non-deploy checks passed. It passes two exact systemd unit drop-ins through
  QEMU credentials only for the pinned
  root and EFI UUIDs under TCG, fixes the value at a bounded five minutes, leaves the
  host handshake unchanged, and refuses unexpected or missing in-guest values before
  reporting ready. The systemd-boot SMBIOS command-line prototype was rejected by
  live evidence because Fedora GRUB did not propagate it. Focused bound, scope,
  missing-device, wrong-timeout, extra-data, slow-SSH, cancellation, and cleanup
  tests pass. The final one-vCPU TCG lifecycle passed in 534.94 seconds, including
  exact in-guest timeout verification, health, clean shutdown, runtime removal, log
  archival, and authenticated base-image SHA-256 immutability. Managed boot now
  passes; broader image equivalence, Debian, macOS runtime, and SteamOS hardware
  remain unvalidated.
- [x] Provide exact Ubuntu/Debian setup and experimental launch/package commands
  with tested-version limits. Add `dev:linux-test`, debug-only `build:linux-test`,
  and `test:package-linux`, a separate opaque Linux main-window configuration,
  and an independent test app identifier while retaining macOS bundle defaults.
  On Ubuntu 24.04.4, the local amd64 Debian package builds under the scheduler;
  it declares the observed glibc 2.39, OpenSSL 3, and liblzma requirements.
  Archive checks verify metadata, ELF architecture, staged binary hash, exactly
  Tauri's UNK-to-DEB marker transformation, shared-library resolution, normal
  archive permissions, desktop entry, and absence of maintainer scripts. Four
  marker tests cover chunk boundaries, truncation, additional changes, missing
  markers, and malformed transformations. Four launcher tests cover opt-in,
  unsupported hosts, acceleration, argument overrides, and missing displays.
  Formatting, Clippy, 308 Rust tests (27 ignored), 90 frontend tests,
  documentation, hygiene, and boundary integrity pass against the unchanged
  immutable Core CI pin. No package installation or publication occurred.
- [x] Add first-class repository-root development and safe welcome entry points for all three host families. Linux and Windows setup scripts must support non-mutating prerequisite/command inspection, fail closed on unsupported hosts and missing tools, and preserve argument boundaries. The Windows welcome preview must use only the loopback mock controller, an isolated browser profile, exact process-tree cleanup, and no disk or QEMU operation. README must carry the real Linux debug/package commands and outputs, the exact locked Windows test/release-build commands and unsigned executable path, the sealed-base/disposable-overlay rule, and current limitations; automated assertions bind those commands and files to the repository workflows. Local Bash syntax, dependency-free print-only output, and missing-tool refusal pass. This host lacks Node and PowerShell, so remote-only JavaScript and native Windows validation require a normal fast-forward push of source commit `098c5db847e8eeba254b1616c97b5ffa066dc83f` to `https://github.com/CorniiDog/steamos-nvidia-image-builder.git`, branch `work/exe-platform-entrypoints`; no release or asset publication is authorized. All observed non-deploy checks passed, Core approved exact base `778d5f843d97d1df43726b33c59850d9afc0a459` and head `3ab7209c0f1ad276bfd4b98d5a3c4d1edf42d834`, and source PR [#74](https://github.com/CorniiDog/OPEMOS.EXE/pull/74) squash-merged to protected main as `ab853c42717b7b6add2ea734eae2bf6aaea05148`; GitHub deleted the exact remote topic branch and retained detailed pre-squash history.
- [ ] Deliver consistent Windows, Linux, and macOS self-contained bundle entry points. The first slice added compiled manifest-SHA binding, bundle-relative command resolution without packaged `PATH` fallback, closed schema-1 staging/consumer validation, and consistent entry points. Native Linux and Windows clean-environment startup and representative bundled-command execution passed with exact payload/application/provenance identities. Core approved exact PR #96 base `d21410a21ba9db84b99c4c45118d5a77484bb99c` and head `47fe5b5dea25fffca355beb7666b2057d9915365` after all required checks passed; protected main squash-merged it as `b3dbc965626cf4d1818de69791afc3cc73e8ea4c`. The active acquisition follow-up pins the 78-archive Ubuntu 24.04 x86_64 closure by version, size, SHA-256, and archive-derived license, verifies or safely replaces cache entries, stages through a same-parent temporary directory, retains optional `--runtime-root` offline input, and acquires automatically when omitted. After Core identified that the initial acquisition merely recorded authenticated archives while copying mutable host bytes, remediation constructs every selected command/library/license byte from verified archive extraction, includes the required archive-derived Python standard library, Git helpers/templates, QEMU data/firmware, and CA roots, resolves those data roots bundle-relatively without host fallback, and binds existing-output reuse to the exact current source lock. Focused Python passes 14/14; Python and Bash syntax and diff hygiene pass. Native archive-derived construction validates exact manifest SHA-256 `5a5096a1ad7aa663f5ff390db6e904802e8fc7af5046a6493250b9a95986d956` (226,667 bytes) and all 78 locked archives. With an otherwise empty environment, bundled Python executes canonical GitHub Core `lib/release_operation.py` from exact commit `f66c374cf224b8e01c723304ad8ee2d5354f69d4` and script SHA-256 `6da8509e14431f2a97f3d0b80ec23791b8ed43f72e96e6519d5139ae79006db6`, bundled Git initializes and inspects an isolated repository through its bundled helpers/templates, then overrides deliberately invalid incoming host-CA variables with its archive-derived CA bundle and resolves that exact canonical Core commit from GitHub HTTPS; bundled QEMU completes a PC-machine firmware/data QMP startup/quit with no surviving process. A post-operation validation proves bytecode cannot mutate the runtime and exact lock-bound reuse still passes; transactional cleanup, host-byte divergence refusal, and stale-output refusal also pass. The Windows follow-up now pins the exact six-archive x86_64 source closure proven by PR 96, replaces tampered cache entries transactionally, derives the complete base runtime only from verified archives, records the closed source lock, injects the exact Core zstd dependency, builds the manifest-bound unsigned EXE, and changes native Windows CI to smoke and retain the complete dist/windows bundle instead of the unusable bare executable. Focused acquisition and packaging tests pass 18/18 with the exact Core-backed zstd case skipped only because no canonical Core checkout was supplied locally; Python compilation and diff hygiene pass. Native acquisition, bundle build/startup/maintainer proof, broader checks, exact-head Core review, PR, and merge remain pending.
- [x] Enforce explicit machine-readable Windows imaging modes before adding VM execution. The network-free contract distinguishes `short` bounded feedback, `partial` official-SteamOS plus immutable compiled-driver-only bundle construction/export/write/flush/readback, and `full` source-evidence plus boot/install/reinstall/no-orphan publication gating. It requires sealed-base disposable overlays, exact executable and bundle identities, every mode-specific evidence bit, rejects shorter substitution and combined NVIDIA-plus-SteamOS assets, and never treats validation as publication authority. Core rejected PR #75 head `d369689043a9d472ead98bf0edda2da425a24381` because the result could select its own required mode, omitted negative declarations passed, shorter modes could carry contradictory boot/install claims, and non-short bundle evidence was not fully bound. Remediation commit `d13a0654c04e22d5a433c9a92fbf59f0a908acdb` requires an independent mode and immutable bundle requirement, explicit false reinstall/combined-asset/publication declarations, mode-correct boot/install claims, and canonical bundle schema, Release, ordered asset byte/hash, Core/source, target/compatibility, provenance, and build-source identities. Focused omission, alteration, contradiction, base/overlay, and publication regressions passed in both frontend/docs jobs; documentation, Windows portable, both Rust, both Linux integration, and both Debian checks also passed. Core approved exact base `ab853c42717b7b6add2ea734eae2bf6aaea05148` and remediated head `d13a0654c04e22d5a433c9a92fbf59f0a908acdb`; source PR [#75](https://github.com/CorniiDog/OPEMOS.EXE/pull/75) squash-merged to protected main as `6a4f3db8ce319074eb50aa3cfce3e1c179c882c3`, and GitHub deleted only the exact merged topic branch while retaining pre-squash commits `e58b8f8`, `d369689`, and `d13a065`. No release, asset, image, VM, trust, production, hardware, boundary, or governance action occurred.
- [x] Add the executable network-free Windows `short` runner. It must run the bounded unit/contract/UI, USB enumeration, physical-disk refusal, immutable driver-bundle manifest, and small-writer checks under one absolute deadline, always run owned cancellation cleanup, require independently pinned exact executable identity, and emit only the validated non-E2E short result. Core rejected PR #77 head `f421dfd0ab1289b8738123961cd6d266dfbd8ec4` because identity was self-reported, mid-action cancellation was not raced, timed-out work could survive or overlap cleanup, and cleanup extended the deadline. The first remediation uses a runner-owned linked abort signal, requires each active action to expose cancellation-and-settlement, reserves teardown within one total deadline, and settles active work before cleanup. Core then rejected remediated head `31a710b36a12647643264a28f648213ee84f163d` because the external abort relay ended before cleanup and timed-out cleanup lacked owned settlement proof. The second remediation keeps cancellation linked through final settlement, makes cleanup an owned operation with a work/settlement split inside the same total deadline, and adds mid-cleanup abort plus real child-process cleanup-timeout/no-survivor tests alongside the earlier missing/unowned/false actions, active cancellation, cleanup failure, deadline, and pin-mismatch cases. Core approved exact base `8bdc9adf8e19da94b587637c70e84e1a84e6061f` and final head `57cabc8bc7ae6abf3b881ae91ed679dc9fdd605b` after Windows portable, both frontend/docs, both Rust, both Linux integration, and both Debian checks passed. Source PR [#77](https://github.com/CorniiDog/OPEMOS.EXE/pull/77) squash-merged to protected main as `72ab0d6bab1e9342b02c87c0cf22d6453057f760`; GitHub deleted only the merged topic branch and retained pre-squash commits `f421dfd`, `c23a99c`, `31a710b`, `41e62c5`, and `57cabc8`. No VM, image, media, release, publication, trust, production, hardware, boundary, or governance action occurred.
- [ ] Complete the first contained Windows installation needed by the authorized partial-mode run. The retained 64 GiB qcow2 is structurally clean and still entirely unallocated after the earlier headless attempt; its QEMU log contains only TCG feature warnings, and the reviewed answer file lacked a `windowsPE` Setup pass. The staged remediation confines unattended partitioning and installation to disk 0, creates exact EFI/MSR/Windows partitions, shows Setup UI on error, and retains the existing one-login authenticated SSH provisioning. Generator-level validation requires exactly one disk 0, the unique ordered EFI 100 MiB/MSR 16 MiB/remaining primary structure, exactly three matching create actions, exactly two matching modify actions, and the sole install target at partition 3; six mutations cover extra/duplicate, reordered, mismatched, and wrong-target layouts. PR #81 passed ten applicable checks, received exact-head Core approval, and squash-merged as `b5e329487762cc610997ffb9e121a3b71576fe09`. Fresh private answer media SHA-256 `7dea196c6ca641fb189f929b5f2b094a3e8c1ed99773740ad6bc620d7c5a5bfd` booted the official Windows ISO after explicit UEFI selection. Under the authorized two-vCPU TCG profile, Windows PE remained black and CPU-bound for 24 minutes 33 seconds without allocating the qcow2 or exposing SSH. Private-QMP shutdown reported `host-qmp-quit`; no process or socket survived, wrapped `qemu-img check` found no errors, and the disk remains 1/1048576 clusters allocated. First install, seal, and partial execution remain blocked by the unchanged no-KVM host constraint.
- [ ] Retain one current-source Linux x86_64 package set after the existing Debian 12 package, AppImage resolver, installed virtual-X11, cleanup, and no-QEMU checks pass. The bounded staging tool requires exactly one regular Debian archive and one executable x86_64 ELF AppImage, refuses an existing output, binds both byte sizes and SHA-256 values to the exact 40-character source commit, and uploads only the resulting packages, checksum file, and schema-1 provenance through the pinned artifact action. Focused staging regressions pass 3/3 locally through `heavy.sh`; remote package construction, validation, artifact retention, and PR evidence remain pending. This is a private CI artifact, not a release, publication, signing, trust, production, or physical-media action.
- [x] Add the network-free Windows `partial` orchestration harness. It must reject mismatched independent executable, official SteamOS, immutable driver-only bundle, and exact harness-owned 32 GiB virtual-USB identities before action work; run owned construct/export/enumerate/write/flush/readback phases and cleanup under one total deadline; and emit only validated construction/write/readback evidence with explicit no-install and no-publication claims. Focused independent-identity, malformed action, false result, mid-write cancellation ordering, cleanup-deadline settlement, and validated partial-result tests passed in both frontend/docs jobs; Windows portable, both Rust, both Linux integration, and both Debian checks also passed. Core approved exact base `554f0a927e988b15c2b08567ef305787ea8d8d65` and head `990621abf9aaf73a3f04113bc3f1be549a684a5a`. Source PR [#79](https://github.com/CorniiDog/OPEMOS.EXE/pull/79) squash-merged to protected main as `f0f610fcaace8e9f51ba14014e0eb33705a50c1b`; GitHub deleted only the merged topic branch and retains pre-squash commit `990621a`. This bounded source work performed no download, VM launch, image construction, media write, install, release, publication, trust, production, hardware, boundary, or governance action.
- [x] Replace the experimental Linux launcher's synchronous child wait with
  an isolated process group, SIGINT/SIGTERM forwarding, a five-second forced
  shutdown bound, and cleanup of children left behind by an exited leader.
  Real disposable subprocess tests cover graceful and stubborn signal handlers,
  leader exit status, surviving child cleanup, spawn failure, invalid grace
  bounds, and signal-handler removal. SIGKILL of the launcher and descendants
  leaving the group remain outside this guarantee; no GUI or VM was launched.
  On Ubuntu 24.04.4 through the shared scheduler, formatting and Clippy pass,
  319 Rust tests pass (27 ignored), and all 105 frontend tests plus documentation,
  hygiene, and boundary integrity pass against the unchanged Core fixture pin.
- [x] Exercise the experimental development launcher in a real Ubuntu 24.04.4
  Wayland/GNOME user session. The binary started twice and bounded SIGINT closure
  left no launcher or EXE processes. The run exposed Tauri rewriting Cargo.toml
  formatting and leaving a generated Linux capability schema; the launcher now
  snapshots and restores exact preexisting bytes/modes and removes only a schema
  proven absent before launch, including child-failure paths. Two new tests cover
  absent/preexisting files, modes, parent cleanup, thrown actions, and symlink
  rejection; all nine focused launcher tests pass. The launcher now waits for
  process-group quiescence before restoration; a repeat package build leaves no
  schema, Cargo rewrite, or descendant. The validated package was extracted
  without installation, launched under Wayland, and closed by SIGTERM with no
  orphan. GNOME denied noninteractive screenshot access, so visual content,
  focus, companion windows, Debian, and SIGKILL-of-launcher restoration remain
  open. Formatting,
  Clippy, 330 Rust tests (27 ignored), and 107 frontend tests plus documentation,
  hygiene, and boundary integrity pass through the shared scheduler.
- [ ] Validate graphical development and packaged application launch/close on
  Ubuntu and Debian, including companion windows and orphan-process checks.
  Ubuntu 24.04.4 Wayland now covers the development main window and the extracted
  debug-package main window. A bounded opt-in AT-SPI smoke starts the exact
  regular executable, verifies the scheduler-capped package exposes the exact
  experimental frame/readiness/unavailable surface, its ordered KVM-unavailable
  explanation with explicit TCG opt-in and no automatic fallback, no ready
  heading, and exactly the Settings, image chooser, and Valve-page buttons with
  no build or USB-writing action exposed. It opens the native recovery-image
  chooser, requires the SteamOS recovery-image filter with no all-files option,
  proves Open remains disabled before selection while Cancel is enabled, cancels
  without selecting input, proves the chooser is gone, and restores focus to its
  opener, then
  verifies the unauthenticated Settings landmark's exact
  five-control focus order plus initial and restored focus, and proves CUDA
  omission, maintainer workspace, and automated-release controls remain disabled
  and unfocusable. It then opens the read-only
  compatibility dialog, opens its native resolver JSON chooser, requires the
  JSON-only filter with no all-files option, disabled empty-selection Open and
  enabled Cancel, cancels without reading a file, proves the chooser is gone,
  and restores focus to its opener. It verifies the exact accessible warnings that preview
  structure is unauthenticated and non-authorizing, fixtures are debug-only and
  non-production, and local inputs are cleared without credentials or guest work.
  The dynamic status now mirrors its bounded text into an accessibility label;
  the live fixture result exposes `Development fixture — non-production` as a
  status bar and `Unverified Core result` as a landmark,
  then verifies the dialog's exact native focusable order, initial Close focus,
  and initial empty status. Inspecting an empty document must expose the bounded
  `Choose or paste` error as
  exactly one status bar without a result landmark; Clear must restore the exact
  empty status before fixture use. It then verifies Core's exact compatible
  publication, artifact, pending-verification,
  and target fields plus all four development-fixture generation rows. Every
  compatible, no-artifact, and compatible-after-clear fixture result must expose
  exactly the non-production status and unverified-result landmark with no stale
  empty/error status. It switches to the no-artifact fixture and verifies Core's
  exact status/reason/message plus its
  bounded exact-target action fields in order. Clear then removes every result,
  action, generation, and fixture-origin sentinel from the accessibility tree,
  requires exactly one `No result loaded.` status, and retains Clear focus, then
  reloading Compatible must restore only its exact rows and
  focus its fixture control. Closing and reopening the populated dialog must
  remove every prior result and origin sentinel, restore exactly one empty
  status, and restore native Close-first focus. It
  closes only the dialog,
  restores focus to its Settings opener, preserves the main document, stops the
  complete process group, and proves no
  new `qemu-system-*` process remains. Unit tests
  reject missing opt-in/display, symlink and non-executable inputs, invalid
  deadlines, missing/duplicate controls, oversized trees, failed actions,
  malformed or symlinked process data, a stubborn process group, exact timeout,
  immediate failure when the packaged process exits before UI readiness, and
  executable pathname replacement after a no-follow descriptor is pinned, and
  stale, missing, invalid, or duplicate AT-SPI application process identities,
  reordered or extra Settings controls, missing or duplicate Settings/dialog
  restored focus, PID reuse, and malformed
  or mismatched bounded `/proc` stat identities. The QEMU snapshot keys PID plus
  kernel start time; the live tree reports the spawned package PID exactly. Package
  archive validation passes with SHA-256
  `28fd817d490c06b76d35190ac4bcf63816f8478d910d9e9620a345cde7213ad5`; no
  package was installed. Twenty-five focused harness tests reject false-ready or
  ambiguous unavailable surfaces, altered unavailable explanations or fallback
  policy, extra unavailable-mode actions, unexpected initial button focus,
  missing or broadened chooser filters, unsafe empty-selection Open/Cancel
  state, a stale native chooser, missing or duplicate chooser focus restoration,
  enabled, focusable, missing, or duplicate unavailable Settings controls,
  altered, missing, or extra compatibility safety warnings, inaccessible fixture
  origin or unverified-result landmark, reordered or extra
  or ambiguously bounded rows, stale cleared fields or result headings, wrong
  Clear focus, altered or duplicate empty-document errors, a result exposed for
  empty input, stale or duplicate empty-status labels, stale, missing, or
  duplicate fixture origins/result landmarks after transitions, stale next actions after
  recovery, and altered compatible trust text, stale close/reopen state, and wrong
  reopened focus; the live package
  smoke passes. A debug-only, Linux-only opt-in now opens the idle native build-progress
  companion without submitting a build. On Ubuntu 24.04.4 Wayland, the live
  AT-SPI smoke verifies the exact main and progress frames, initial progress
  headings/status, disabled idle cancellation, main-window policy controls scoped
  away from companion actions, complete process-group shutdown, and no new QEMU
  process; 27 focused harness tests cover duplicate frames, incorrectly enabled
  cancellation, and cross-window action contamination. The authenticated
  maintainer gate was then exercised against the existing `CorniiDog/OPEMOS`
  permission and approved-source inventory: the live smoke waits for enabled
  `Open Workspace…`, opens the exact native maintainer frame, verifies
  `Maintainer verified`, Refresh, and its read-only Core inspector, performs no
  plan/worktree/commit/push/build/release action, stops the complete process
  group, and leaves no new QEMU process. Twenty-eight focused harness tests also
  reject disabled maintainer entry and denied or ambiguous companion state.
  Debian, delivered key-event/editable-text traversal, and pixel rendering remain open; GNOME Wayland accepted an exploratory AT-SPI Escape
  synthesis request without delivering it to the WebKit dialog. WebKit exposes
  the resolver text field as an entry without an AT-SPI EditableText interface.
  The former HTML file control also accepted `press` without opening a chooser;
  replacing it with the native Tauri dialog closed that blocker in the packaged
  smoke while retaining local-only, unverified parsing. The renderer test proves the accessible status label
  follows loading, result, error, and clear without retaining stale text.
  Scheduler-limited
  formatting and
  Clippy pass, 331 Rust
  tests pass (27 ignored), and all 111 frontend tests plus documentation, hygiene,
  package, focused smoke, and boundary integrity checks pass against unchanged
  Core fixture commit `3e49323fce266af8686039fb6487918ef5a64fd9`.
  PR #14 adds the corresponding installed Debian 12 virtual-X11 smoke. Both final
  Debian jobs pass the full main-window/Settings/compatibility AT-SPI flow, strict
  process-group and QEMU-orphan checks, and unconditional package purge. A child
  subreaper handles WebKit descendants without weakening the cleanup assertion;
  locale options remain exact within their owning Settings landmark while an
  external native popup mirror is allowed. Thirty-eight focused lifecycle and
  accessibility tests and 171 frontend tests pass. Physical Debian graphics
  remain open. The independent Debian follow-up enables the existing debug-only
  idle build-progress companion in the installed-package virtual-X11 smoke and
  requires its exact harness argument plus all three opt-in environment values.
  Thirty-eight focused lifecycle/smoke tests passed locally; all nine non-deploy
  checks passed, including both installed Debian 12 package smokes. Core approved
  exact base `15b68924ccea08094e07001a6d8c3e5e94d4f5d8`, unchanged head
  `4337d9928f1eebff36474a5e169fd024ac8dc362`, three-file scope, and required-check
  set through the authenticated same-author fallback. PR
  https://github.com/CorniiDog/OPEMOS.EXE/pull/82 squash-merged as
  `f373cad797b95101a5d0ba397f9d93cc0ce1a5f5`; protected `main` resolved to that
  commit and only the merged topic branch was deleted. Managed-appliance
  lifecycle and
  image equivalence remain separately blocked by the unchanged resource minimum
  above. The Ubuntu glibc-2.39 package is not a validated Debian 12 artifact.
- [x] Add Settings → Inspect Core compatibility: a read-only host dialog for
  pasted resolver results and the existing compatible/no-artifact development
  fixtures. Reuse the same Rust Core schema-2 parser and 1 MiB byte bound;
  distinguish unverified pasted documents from non-production debug fixtures.
  Display Core status, targets, publication, pending artifact trust, reasons,
  and next actions as text without policy selection, network/guest/cache work,
  or build/activation controls. Closing, clearing, editing, and newer requests
  invalidate stale responses; native file drops cannot select images while
  the dialog is open. Three Rust tests cover exact result preservation, origin
  and fixture gating, strict request shapes, duplicate/malformed documents,
  unknown schemas, trust-field tampering, Unicode overflow, and the size edge.
  Eight frontend tests cover presentation, bounded errors/text, races, clearing,
  hostile-looking text, keyboard-event isolation, and byte limits. On Ubuntu
  24.04.4, scheduler-limited formatting, Clippy, 311 Rust tests (27 ignored),
  98 frontend tests, documentation, hygiene, and boundary integrity pass against
  unchanged Core CI commit `3e49323fce266af8686039fb6487918ef5a64fd9`.
  Native dialog rendering/focus remains part of the graphical validation gate;
  this session has no graphical display or enabled browser surface.

- [x] Extend the read-only compatibility inspector with local resolver JSON
  selection, now through a native Tauri file dialog and bounded EXE-owned reader. Enforce nonempty files, the same
  1 MiB byte bound, strict UTF-8, and unchanged document IPC/Rust validation;
  label file and pasted results Unverified document. Four new frontend tests
  cover exact size, BOM preservation, bad sizes/encoding, read failure, changed
  length, cancelled picker, repeated selection, close, and stale read success
  or failure after clear or a newer request. A Rust regression additionally
  rejects relative paths, empty/oversized/nonregular files, and symlinks. Paths
  enter only the EXE-local preview command and never establish trust. The rebuilt
  Ubuntu package now passes the native chooser accessibility smoke; pixel
  rendering remains gated. No production activation is added. The earlier HTML
  input implementation passed 319 Rust tests (27 ignored) and 102 frontend tests.
  On 2026-09-04, the native chooser follow-up passes formatting and Clippy, 331
  Rust tests (27 ignored), all 111 frontend tests, 25 focused smoke-harness tests,
  live extracted-package AT-SPI smoke, package validation, documentation, hygiene,
  and boundary integrity against the unchanged Core fixture pin.

- [x] Reuse the read-only Core compatibility inspector in the maintainer
  workspace as well as normal Settings. Both windows accept the same bounded
  pasted/local resolver documents and debug-only non-production fixtures, show
  Core fields verbatim, and expose no source selection, generation mutation,
  network, cache, guest, build, or activation action. Cross-window concurrency
  tests prove independent revision state: a stale or closed maintainer request
  cannot replace the main result and vice versa. Static wiring tests require the
  shared controller, stylesheet, bounded inputs, and explicit no-authorization
  notice in the maintainer surface. The broader available/selected/active/LKG
  generation UI remains gated and open. On Ubuntu 24.04.4 through the shared
  scheduler, formatting and Clippy pass, 330 Rust tests pass (27 ignored), and
  all 109 frontend tests plus documentation, hygiene, and boundary integrity
  pass against the unchanged Core fixture pin. Native maintainer-dialog visual
  and focus validation remains blocked by GNOME screenshot policy.

- [x] Validate the normal Settings compatibility inspector through the live
  Ubuntu 24.04.4 Wayland accessibility tree. AT-SPI found the native frame,
  WebKit document, Settings panel, dialog, fixture controls, and all four debug
  generation rows; it invoked the fixture, verified selected/active identity
  values, closed the dialog without closing the main document, and launcher
  shutdown left no process. This exposed empty native names for generated
  description terms and values. The renderer now assigns exact text-only ARIA
  labels, with a hostile-looking value regression proving labels remain data,
  not markup. Formatting and Clippy pass, 330 Rust tests pass (27 ignored), and
  all 110 frontend tests plus documentation, hygiene, and boundary integrity
  pass through the shared scheduler. Pixel rendering, focus order, maintainer
  companion launch, packaged accessibility, and Debian remain open.

- [x] Split Tauri permissions into exact main, build-progress, and maintainer
  window capabilities. Main retains native dialog, URL opener, focus, and drag;
  maintainer retains native dialog, hide, and drag; build progress retains only
  hide and drag beyond core IPC. No window receives an unused show permission,
  build progress receives neither dialog nor opener, and maintainer receives no
  opener. An exact regression rejects changed window membership, permission
  order, permission additions, duplicate coverage, or scope collapse. On
  2026-09-04, Tauri/Cargo capability validation, all 111 frontend tests,
  documentation, hygiene, 25 Linux GUI harness tests, package validation, and
  live extracted-package AT-SPI smoke pass; main Settings, native image and JSON
  choosers, focus restoration, process cleanup, and the no-QEMU
  invariant remain functional. Package SHA-256 is
  `f7a43e115e234ed977ad91d7daa8a7660f0453cad3a6cf73bd692849048dfc76`.
  At this commit, the restrictive production CSP and further `core:default`
  review remained open; the follow-up below closes both.

- [x] Enable a restrictive packaged-webview CSP and replace every broad Tauri
  permission default with the exact frontend calls. The CSP admits only bundled
  scripts, images, fonts, and styles plus Tauri's documented IPC endpoints;
  runtime progress/log rendering retains the required inline-style allowance.
  Objects, forms, frames, base-URL changes, and every other source are denied.
  `core:default`, `dialog:default`, and `opener:default` are absent. Main receives
  only listen/unlisten/emit, window inventory/focus/drag, dialog open, and URL
  open; build progress and maintainer receive only listen/unlisten/emit-to,
  hide/drag, plus dialog open for maintainer. The exact regression rejects any
  directive, permission, order, or membership drift. On 2026-09-04, focused
  frontend and Cargo checks plus a rebuilt extracted-package AT-SPI smoke pass;
  Settings, both native choosers, compatibility IPC, focus restoration, clean
  process-group shutdown, and the no-QEMU invariant remain functional. Package
  SHA-256 is
  `2fa3e4036e793ecbaaf149979740f9c46aafb3ac0f291e83c0faf1243bb8f883`.
  This does not grant webview networking or alter production trust/activation.

- [x] Add shared reduced-motion and forced-color behavior to main, build-progress,
  maintainer, and compatibility controls. Reduced motion bounds every animation
  to one effectively instantaneous iteration, removes transition delay, and
  disables pressed-button displacement while retaining final progress/status
  state. Forced colors use system button, canvas, highlight, and disabled colors
  for borders, custom checkbox marks, focus outlines, and unavailable controls;
  disabled controls remain visibly distinct without opacity loss. An exact
  regression covers repetition, transition, focus, checkbox, status, and disabled
  boundaries across the shared stylesheet. On 2026-09-04, the focused five-case
  theme suite and all 112 frontend tests plus documentation, hygiene, and boundary
  integrity pass. Pixel-level forced-color/reduced-motion rendering, zoom, long
  localization, and display scaling remain in the broader graphical gate.

- [x] Add the first inactive maintainer-facing release review surface. It displays
  exact Core commit, bundle identity and SHA-256, and release identity together
  with package, build, signature, checksum, and provenance states. The model
  rejects mutable/malformed identities and unknown states, freezes accepted
  plans, and enables explicit authorization only when all five evidence gates
  pass. No publisher, signer, network request, release execution, production
  trust, or activation path is connected. On 2026-09-06, 7 focused and all 197
  frontend tests pass with documentation, hygiene, and boundary integrity.

- [x] Bind the inactive maintainer release review to Core's canonical closed
  release-operation schema from authenticated GitHub commit
  `8ebaccac5f0969da4955931d094f3cb47a587ef5`. The exact schema bytes have
  SHA-256 `84cbb630e69cbd3d1bbee351ab65123a5afb8567700a15a2a963887a6bfc0609`.
  Render repository, tag, target commit, operation ID, attempt, lifecycle,
  decision, message, and every asset identity/state. Explicit authorization is
  available only for a closed `planned/create` inventory or a missing-only
  `reconciling/retry-missing` inventory; already-complete, conflict, cancelled,
  malformed, additive, duplicate, and oversized inputs remain closed. This
  fixture consumer does not invoke Core, publish, sign, use credentials, access
  the network at runtime, or activate production. On 2026-09-06, 8 focused and
  all 198 frontend tests pass with documentation, hygiene, and boundary integrity.

- [x] Add an inactive explicit-authorization session around the exact Core
  release operation. Authorization is bound to operation ID, attempt, and
  decision, is idempotent for the same reviewed request, and is invalidated by
  any new attempt or operation. The UI explains exact completion, conflict, and
  cancellation without claiming success or enabling action; accepted local
  authorization states that no executor is connected. This does not invoke Core,
  publish, sign, use credentials, or activate production. On 2026-09-06, 10
  focused and all 200 frontend tests pass with documentation, hygiene, and
  boundary integrity.

- [x] Add inactive host-side release status/reconciliation admission. A newer
  result must preserve operation ID, repository, tag, target commit, and every
  ordered asset name/hash/size; stale attempts, changed same-attempt results,
  and identity substitutions are rejected without replacing the reviewed state.
  A newer accepted attempt clears prior authorization, exact repeated results
  are idempotent, and succeeded/failed/cancelled terminal results cannot be
  replaced. No Core process, remote inventory, publisher, credentials, or
  production path is connected. On 2026-09-06, 8 focused and all 202 frontend
  tests pass with documentation, hygiene, and boundary integrity.

- [x] Consume Core's durable closed release-session boundary from authenticated
  canonical GitHub commit `fe0080afecb7784083d56d36dc22d3aecdf8058d`
  (Core PR #25, preserved source `78b96ed`). The updated exact
  release-operation schema bytes have SHA-256
  `59c6e25d3121e307d60e91612694fff0edf5b86bf754eb4c0ad603932451a2ed`;
  the session implementation and closed fixture hashes are
  `df2e815e03eb5d429b3d6e6ff13df9d126d9befd066a8efe14fe37bdf4975330`
  and `e8c95599e4f296db85b5e328a2679b8d4540ad8a45db9abd346f0bdbce78716f`.
  EXE now validates and renders exact bounded progress and exposes an injectable
  inactive controller for Core's stable execute/status/reconcile/cancel commands.
  Start and missing-only retry require the exact local authorization; concurrent,
  stale, malformed, substituted-identity, inconsistent-progress, and
  post-terminal results fail closed. The maintainer surface includes disabled
  start/resume, verify, retry, cancel, and progress controls until an
  authenticated host adapter is supplied. No publisher, signer, credentials,
  network transport, production trust, or activation path is connected. On
  2026-09-06, 14 focused and all 204 frontend tests pass with documentation, hygiene, and boundary integrity. EXE lead pushed source commit `e90343dea4c92fdc88d8a3c38ae4eec89b597e21` on branch `work/exe-release-session-controls` to configured remote `https://github.com/CorniiDog/steamos-nvidia-image-builder.git` (redirected by GitHub to OPEMOS.EXE) because PR review and remote CI are required; PR https://github.com/CorniiDog/OPEMOS.EXE/pull/42 passed all duplicated checks and squash-merged as `b9cdb8de5b2d1d8a49626110109df1abed12860f`; preserved branch head `61e87bff824e7b09898fadf4478da1ad6c77a938`.

- [x] Add bounded restart-safe observation for the inactive release session.
  The UI checks durable status immediately after resume and then schedules at
  most one poll at a time, stops on every terminal lifecycle, and fails closed
  at a configurable finite poll bound. Stopping or cancelling invalidates an
  in-flight result through the shared overflow-safe request gate, so late status
  cannot replace the current operation; overlapping poll owners are rejected.
  Successful inactive start/retry commands enter this observer, while cancel
  invalidates it before invoking Core's closed command adapter. No runtime host
  adapter, network transport, publisher, credentials, production trust,
  activation, KVM, or hardware path is connected. On 2026-09-06, 13 focused and all 207 frontend tests pass with
  documentation, hygiene, and boundary integrity. EXE lead pushed source commit `e0d287a644b9690266d35d2341805d9e7f27ab11` on branch `work/exe-release-status-polling` to configured remote `https://github.com/CorniiDog/steamos-nvidia-image-builder.git` (redirected by GitHub to OPEMOS.EXE) because PR review and remote CI are required; PR https://github.com/CorniiDog/OPEMOS.EXE/pull/43 passed all duplicated checks and squash-merged as `7e6ef197292e066f0a4a363f75b2091cb1110114`; preserved branch head `e265713a7149d5ffa60d03690948223218e106ad`.


- [x] Add a closed non-production maintainer UI fixture for the exact release
  session lifecycle. It exercises explicit authorization, start, immediate
  durable observation, a missing-only retry, final verification, and
  cancellation through the injected Core command boundary while retaining one
  immutable operation and ordered asset identity. Starting, retrying, or
  cancelling invalidates the prior polling owner before transferring lifecycle
  ownership, so a scheduled stale observation cannot overwrite the new command.
  Cancellation remains terminal and cannot claim success. No authenticated
  runtime adapter, publisher, signer, credentials, network transport,
  production activation, KVM, or hardware path is connected. Focused validation passes 15/15 and all 209 frontend tests pass with
  documentation, hygiene, and boundary integrity. EXE lead pushed source commit
  `bb58ad9` on branch `work/exe-release-session-ui-fixture` to configured remote
  `https://github.com/CorniiDog/steamos-nvidia-image-builder.git` (redirected by
  GitHub to OPEMOS.EXE) because PR review and remote CI are required; PR
  https://github.com/CorniiDog/OPEMOS.EXE/pull/44 is open. Squash evidence
  follows.

### 1. Complete the OPEMOS Core migration

Production generation activation is intentionally blocked until the maintainer
supplies all five independent publication inputs below. Existing schema-1
filenames, no-redirect behavior, exact-target selection, and replay rules are
already Core contracts and are not open-ended product choices.

- [ ] Approve one production OpenPGP primary fingerprint and the exact keyring
  bytes/digest installed independently with OPEMOS.EXE.
- [ ] Approve one canonical HTTPS origin/channel and immutable release
  namespace; no mirror, redirect, or mutable-ref fallback is implied.
- [ ] Approve the first signed discovery/manifest identity and its minimum
  sequence as the independently installed bootstrap checkpoint.
- [ ] Name the authorized generation publisher/signing process and the
  immutable release evidence required before discovery advances.
- [ ] Define the separately authenticated binary/config procedure for signer
  rotation or emergency state-loss recovery. Routine data generations may
  neither rotate authority nor lower a consumer's durable high-water mark.

- [ ] Have Core publish an immutable generation through its canonical
  authenticated release channel. OPEMOS.EXE must never generate the production
  manifest, lock, signer policy, or target policy.
- [ ] Define and consume one bounded generation descriptor binding the channel
  and trust-root version, Core commit, manifest and bundle identities, supported
  contract schemas, reviewed lock identities, target matrix, and publication
  evidence.
- [ ] Discover generations with bounded retries; authenticate the descriptor and
  manifest independently, then verify every listed path, role, size, SHA-256,
  and executable mode before staging anything.
- [ ] Install each verified generation into a create-only cache directory, rehash
  it before appliance transfer, retain the last-known-good generation, and make
  activation atomic and rollback-safe across cancellation, ENOSPC, crash, replay,
  and downgrade attempts.
- [x] Add an inactive Unix host-cache substrate with private create-only
  candidates, closed-tree durability, cross-process serialization, canonical
  bounded state, revision/operation compare-and-swap, pending health approval,
  independently reverified last-known-good rollback, and cleanup of partial,
  cancelled, ENOSPC, or late-verification candidates. Hold an identity-bound,
  size-reserved cross-process lease throughout candidate population and commit.
  Require durable host-owned completion evidence before activation so an
  interrupted publication cannot be trusted. Reconcile abandoned candidates,
  orphaned evidence, and exact stale temporaries under the cache lock; preserve
  active, pending, and last-known-good identities while pruning the oldest
  unprotected generations to bounded count and byte budgets. Keep this
  disconnected from production until a compatible generation is published
  through an authenticated trust root and bootstrap checkpoint.
- [x] Add inactive test-only host acquisition using one sealed two-phase
  verifier capability. Authenticate discovery before deriving the exact
  manifest request; bind policy, keyring, authority, target, documents, and
  signatures; then stream only sealed request-plan payloads into an
  identity-pinned candidate. Freshly verify the exact disk inventory inside
  atomic cache commit without changing active state. This has no production
  transport, trust root, command, or UI entry point.
- [x] Bind inactive bootstrap activation to the host cache using only sealed
  generation/checkpoint capabilities. Authorize durable state under the cache
  lock, verify exact inventory through the pinned directory descriptor, and
  publish only pending state across replay, lineage, race, and cancellation
  tests. Production still requires root-confined installed trust; fixtures are
  never authority.
- [x] Consume Core's closed userspace-lock discovery and generation-manifest
  schema-1 models plus all 74 inactive compatibility cases and additive
  consumer handoff metadata preserved at exact local successor commit
  `f2030ab5277c18ae4320747d8e1c4f8120efd0bb`. Also consume its separate
  16-case bounded OpenPGP status matrix. Bind durable cache identity
  to `{sequence, manifestSha256}`, retain a monotonic high-water sequence, and
  keep rollback on the previously healthy generation. Provide fixture-tested,
  root-confined snapshot readers for future staged documents. This is contract
  testing, not a production trust or release pin.
- [x] Consume Core's closed bootstrap policy/checkpoint contract and exact
  49-case compatibility matrix from local commit
  `0c16ccd7ba68095ea8a6655b0d2bb8b6e97d32f3`. This adds no production key,
  keyring, endpoint, checkpoint, networking, activation, command, or UI path.
- [x] Consume Core's unchanged generation request-plan wire contract, exact
  35-case planner matrix, and sealed verifier-evidence capability with its exact
  28-case audit-record matrix from local commit
  `1fde359025031a99055763dca76e0d709486ffac`. Planning derives payload request
  identities from the authenticated manifest; downloaded-byte equality remains
  an acquisition/cache responsibility. No production path is wired.
- [ ] Show the available, selected, active, and last-known-good Core generations
  plus exact-target support in normal and maintainer UI. Preserve explicit source
  intent; never substitute a nearby target, lock, or generation.
- [x] Exercise that generation-status presentation in both shared inspector
  surfaces using a closed debug-only host fixture. The fixture provides two
  synthetic identities and distinct selected, active, and last-known-good state;
  production and unverified-document responses cannot supply generation state.
  The frontend requires the exact four-field shape, one to four unique available
  identities, positive safe sequences, bounded IDs, lowercase SHA-256 values,
  no extra fields, and membership of every selected/active/LKG identity in the
  available set. It displays Core's exact-target support field verbatim and
  labels every generation row “development fixture.” Tests cover absent state,
  missing/extra fields, empty/oversized/duplicate inventories, malformed hashes,
  invalid sequences, unavailable selections, and origin substitution. This adds
  no cache reader, production discovery, source selection, or activation; the
  parent production UI item stays open. On Ubuntu 24.04.4 through the shared
  scheduler, formatting and Clippy pass, 330 Rust tests pass (27 ignored), and
  all 110 frontend tests plus documentation, hygiene, and boundary integrity
  pass against the unchanged Core fixture pin.
- [x] Add an inactive descriptor-bound host-cache-to-appliance staging bridge.
  It requires the exact pending identity, operation, target, lineage, installed
  trust, and committed inventory; publishes a canonical non-executable handoff
  create-only under a destination lock; and supports exact reuse and explicit
  retirement without exposing a raw path or descriptor. It retains a canonical,
  descriptor-bound lease through handoff lifetime and synthetically reconciles
  crashes at intent, copy, seal, publication, completion, and retirement
  boundaries. Exact durable file receipts preserve ambiguous or replaced
  entries detected before the final descriptor-relative cleanup boundary.
- [x] Exercise one immutable, explicitly non-production Core generation from
  local Core commit `7f90e45c4c154fdfda81ff594611cf533e4fb894` through EXE
  acquisition, installed-trust authentication, pending activation, canonical
  appliance staging, Core guest consumption, handoff retirement, and healthy
  activation. The integration found and fixed the evidence filename and
  canonical handoff-JSON mismatches. The cross-repository test is explicitly
  opt-in until that Core commit is published, and does not activate production
  trust or the normal path.
- [x] Prefer the independently pinned 55-file canonical Core bundle for normal
  installer staging. A verified manifest is rechecked against its independent
  digest, bundle identity, commit, file set, hashes, sizes, roles, and modes;
  any authenticated integrity failure stops. The legacy 50-file inventory
  remains only as an explicit temporary availability fallback until the
  immutable Core release exists and passes live acquisition plus equivalent
  install-media and final-image tests.
- [ ] Wire staged generations into managed appliances only after Core publishes
  the guest-consumption contract and EXE passes a real subprocess/SIGKILL,
  restart, cancellation, cleanup, and ENOSPC handoff matrix. A routine compatible
  lock addition must require neither a new EXE binary nor a reimage; unknown
  schema or trust-policy versions must stop safely.
  - [x] Core handoff requested 2026-09-05: complete the smallest inactive
    guest-consumption gap by defining and implementing non-empty lineage
    handling for schema-1 `opemos-core-appliance-generation-handoff`. The
    current development consumer at `7f90e45c4c154fdfda81ff594611cf533e4fb894`
    accepts the bounded field structurally but rejects every non-empty
    `lineageManifestSha256`, while EXE staging already preserves zero to 64
    unique manifest hashes in order. Core must authenticate the permitted
    predecessor chain under its installed bootstrap/generation policy and fail
    closed on missing, duplicate, reordered, unrelated, downgraded, malformed,
    or unsupported lineage before preparing installer inputs. Preserve the
    exact operation ID, generation identity, target, authenticated inventory,
    create-only output, and structured prepared/error behavior already covered
    by the Core development consumer matrix. Deliver an immutable Core commit,
    canonical schema/fixture bytes, and focused positive single-/multi-
    predecessor plus negative lineage conformance evidence. This request adds
    no production key, endpoint, publication, activation, host transport, or
    boundary change. After that handoff, EXE can repin and extend its existing
    ignored end-to-end generation test to a non-empty successor lineage before
    normal managed-appliance wiring. Core completed the bounded consumer at exact
    local commit `adf372b857cd348b6a18680b45ffcea790f04d4b`; its focused lineage
    suite passed under the shared scheduler. EXE can consume that commit directly
    from the sibling object database without remote publication: on 2026-09-05,
    the repinned ignored Rust integration passed the complete existing zero-lineage
    acquisition, installed-trust, pending-activation, appliance-staging, guest-
    consumption, retirement, and acknowledgment path. Non-empty lineage staging
    and its process-death/failure matrix remain EXE-owned work; no additional Core
    contract gap is established by this baseline.
  - [x] Reject a pending generation that cites itself as authenticated lineage
    before appliance handoff publication. The staging bridge returns the exact
    bootstrap-checkpoint mismatch, leaves the destination without a handoff, and
    preserves cache state. On 2026-09-05, the focused Rust regression and
    formatting pass. A positive authenticated successor lineage plus process-
    death, cancellation, cleanup, and storage-failure coverage remain open.
  - [x] Reject non-empty lineage authenticated under a different installed-trust
    snapshot before staging begins. The bridge returns the exact mixed-trust
    diagnostic, publishes no handoff, and leaves the pending cache state unchanged.
    On 2026-09-05, the focused Rust regression and formatting pass. The positive
    same-trust successor fixture and broader failure matrix remain open.
  - [x] Derive the bounded predecessor transfer inventory from authenticated
    capabilities, admitting only each generation manifest and its detached
    signature with exact sizes and hashes. Duplicate and case-folded filename
    collisions now fail during staging admission before locks or destination
    mutation. On 2026-09-05, the focused Rust exact-inventory/collision regression
    passes. Multi-source cache pinning, copying, receipts, capacity accounting,
    restart recovery, and final revalidation remain open before positive staging.
  - [x] Reject collisions across the current-generation and predecessor transfer
    inventories, including case-only aliases, after installed-trust validation
    and before cache or destination paths are opened. This deliberately moves
    self-lineage failure earlier from the recorded bootstrap-checkpoint mismatch
    to the exact transfer filename-collision diagnostic; mixed-trust lineage still
    fails first at its trust boundary. On 2026-09-05, the focused collision,
    self-lineage, and mixed-trust Rust regressions pass. Multi-source pinning,
    copying, receipts, recovery, and final revalidation remain open.
  - [x] Require every authenticated predecessor to have exact durable cache
    commit evidence and a unique sequence, then retain a pinned generation-
    directory capability after verifying its complete authenticated inventory
    and path identity. Missing commit evidence fails before destination access.
    On 2026-09-05, the focused Rust committed/missing-predecessor regression and
    formatting pass. Multi-source selective copying, receipts, restart recovery,
    and final revalidation remain open.
  - [x] Copy only each pinned predecessor manifest and detached signature into
    the combined handoff inventory using descriptor-relative create-only writes.
    The complete predecessor cache inventory and pinned directory identity are
    rechecked before copying, before atomic publication, and after publication;
    combined records, receipts, and published-directory verification include the
    transferred lineage files. On 2026-09-05, warnings-as-errors Clippy plus the
    focused selective-copy and existing zero-lineage staging/reuse regressions
    pass. A positive same-trust successor integration, restart recovery, and
    injected cancellation/storage faults remain open.
  - [x] Include predecessor manifest/signature bytes and file nodes in checked
    handoff storage admission before destination work. Combined current-plus-
    lineage totals reject integer overflow and directory entry-limit excess,
    preventing lineage catch-up from bypassing byte or inode reservations. On
    2026-09-05, both focused Rust accounting/inventory regressions and formatting
    pass. Multi-source pinning, copying, receipts, recovery, and final
    revalidation remain open.
  - [x] Stage a positive authenticated successor across an active sequence 1,
    committed sequence-2 predecessor, and pending sequence-3 generation under
    one installed trust snapshot. The integration verifies the unchanged cache
    state, ordered predecessor hash, exact selectively copied manifest/signature
    bytes and combined receipt inventory, excludes the predecessor discovery
    document, revalidates the published handoff, and retires it cleanly. On
    2026-09-05, the focused Rust integration passes. Restart recovery and
    injected cancellation/storage faults remain open.
  - [x] Exercise cancellation and an injected ENOSPC-equivalent failure after
    the complete current-generation plus predecessor copy. Both paths remove
    every receipted private payload, stage, and lease while retaining only the
    destination lock and preserving the active/pending cache state exactly. On
    2026-09-05, the focused two-path lineage fault regression, the refactored
    positive lineage integration, formatting, and warnings-as-errors Clippy pass.
    Lineage-aware process-death restart recovery remains open.
  - [x] Kill a real staging subprocess after the combined lineage copy and
    after atomic handoff rename, then start a fresh executable which reloads the
    installed trust snapshot, reconstructs the authenticated sequence-2/3 chain,
    reconciles the durable lease, revalidates the ordered predecessor receipt,
    and retires the handoff. Both boundaries preserve cache/trust bytes, inode
    identities, and active/pending state exactly. On 2026-09-05, the focused
    two-boundary SIGKILL/restart regression, formatting, warnings-as-errors
    Clippy, repository hygiene, and boundary integrity pass. This closes the
    currently identified lineage staging restart/fault matrix; normal managed-
    appliance wiring remains gated by its broader lifecycle and production inputs.
- [x] Exercise the inactive appliance handoff in real subprocesses killed at
  all 38 existing staging, partial-file-receipt, and retirement hook boundaries.
  Fresh-process restart reauthenticates installed trust, reacquires locks,
  preserves cache/trust bytes and inode identities, and either validates and
  retires the handoff or preserves ambiguous stage bytes with the stable
  recovery-required result. Only the exact unfinished lease-record temporary
  is reconciled in partial-receipt cases. This supplements synthetic fault
  tests; production wiring, durable quarantine, real storage-failure coverage,
  and macOS validation remain separate gates.
- [ ] Add an explicit authenticated maintenance action for a preserved
  `appliance-handoff-recovery-required` pre-receipt stage. Never auto-delete
  ambiguous same-UID residue after the create-to-receipt crash gap.
  Awaiting user ownership clarification: does “authenticated maintenance”
  require a Core-owned authorization contract, or an explicit EXE host-local
  maintenance approval? EXE owns transfer cleanup; Core owns signer/keyring
  policy and authorization contracts. The existing recovery path preserves a
  stage without a durable file receipt and supplies no deletion authority.
  Stop this action until the user identifies the intended authority; do not
  infer it from scheduler continuation, mutable lease records, or same-UID
  ownership. Review at `08d2e9a` found no implementation changes to validate;
  existing production gates and preserved stages remain unchanged.
  Decision recorded 2026-09-04: the user approved Core's canonical creator-owned
  cleanup boundary from commit `3a6f0652f4118936820871f8201f7c5e1250acbf`.
  Core owns cleanup of Core-created artifacts it can safely identify; EXE may
  consume a bounded provenance-preserving Core flag only after revalidating exact
  artifact identity and provenance. Missing, stale, malformed, mismatched,
  conflicting, or ambiguous evidence still preserves the artifact. This resolves
  the ownership question but does not implement or activate maintenance cleanup.
- [x] Mirror the explicitly authorized artifact-cleanup ownership boundary from
  canonical Core commit `3a6f0652f4118936820871f8201f7c5e1250acbf` without
  rewording. EXE integrity pins now require Git blob
  `68fd9553bb8fee79cee803a38f980a94b2d80e57` and SHA-256
  `136d3572effa90c1b84bcf51002d7f9641c367132de20d54dd7173f68f13c6a8`,
  verify the pinned Core counterpart bytes when the sibling checkout exists, and
  assert the creator-ownership, exact revalidation, fail-safe ambiguity, and
  no-blanket-deletion rules. The dated decision handoff is
  `docs/decisions/2026-09-04-artifact-cleanup-ownership.md`; prior TODO and Git
  history remain preserved. Core completed the reverse counterpart pin at
  `a7011dca932f5a89426a07005bc52418651b94b5`, targeting exact EXE mirror commit
  `064d1d54c7ef2eda3d56e80c67e9f8e78a554725`. Both repositories' default and
  local focused boundary validation passes.
- [ ] Mirror the explicitly authorized cross-repository pull-request governance
  from canonical Core squash commit
  `73e8d15c07671f3174f1a948d525e18db1084e5a` without rewording the authority.
  Canonical Git blob `2f8424a1df29fce2859126f7c42fd1885db8a425` and SHA-256
  `8c882b9a25e3d53fc200d82fff0807a8746dc826410271563d37342542c01df0`
  were fetched from authenticated GitHub and verified before mirroring. EXE
  integrity now pins that immutable Core squash and asserts owning-primary,
  exact-identity approval, same-author authenticated fallback, invalidation,
  and exact merged-topic deletion limits. The staged decision record is
  `docs/decisions/2026-09-06-cross-lead-merge-governance.md`. Core review of the
  exact final EXE base, head, scope, and required-check set remains required
  before squash merge; the final Core counterpart repin follows the verified
  EXE squash commit. Focused boundary integrity, repository hygiene, Python
  compilation, canonical SHA-256/Git-blob, and diff checks pass locally.
  Pre-squash implementation commit
  `c4662ae085667dd6c1b340bb548ee30fa9dd9924` was necessarily pushed to
  `https://github.com/CorniiDog/OPEMOS.EXE.git` on branch
  `work/exe-cross-lead-governance` for PR
  https://github.com/CorniiDog/OPEMOS.EXE/pull/53, remote CI, and exact Core
  review. On that head, Pages build and both copies of frontend/docs, Rust,
  Linux integration, and Debian package checks passed; Pages deploy skipped.
- [x] Mirror the explicitly authorized product-first review tiers from canonical
  Core squash commit `e36e9052b982893b5fc89f6df0fa1c8671b7cad1` without
  rewording the authority. Authenticated GitHub bytes match Git blob
  `9b379788b1deadbb2088887eb10be325008254ac` and SHA-256
  `c44a987b4931f413ee72cc6d94ff3797f746bbdba4bcf51c7d7aed9406ffd9f2`.
  EXE integrity enforcement now distinguishes routine non-destructive work from
  imaging-sensitive and release work, retains exact counterpart review for the
  stronger tiers, and rejects standalone evidence-only PR practice. The staged
  decision record is `docs/decisions/2026-09-11-product-first-review-tiers.md`;
  Core's final counterpart repin follows the verified EXE squash identity.
- [ ] Mirror the explicitly authorized blocked-lead Resolver escalation from
  canonical Core protected-main squash commit
  `aeec707b8cb3dc6f592cedd7164c58c75a50aa8b` without rewording the authority.
  Authenticated canonical GitHub bytes match Git blob
  `b4d4711321590d39756b2850a3b25c26e8117d3e` and SHA-256
  `80cc89afcc2dfd467d3a52c492c246cfc4e1a03b7fd73219172ed0bbfa9d6dfb`.
  EXE guidance and integrity enforcement require immediate Resolver dispatch
  for fresh blocked/resource/approval reports while preserving every authority,
  review, queue, helper, pause, ownership, and branch-protection guard. The
  staged decision record is
  `docs/decisions/2026-09-13-blocked-lead-resolver-escalation.md`. Canonical
  byte comparison, SHA-256 and Git-blob verification, focused boundary integrity,
  Python compilation, documentation contracts, repository hygiene, and diff
  checks pass locally. Core exact-identity review, EXE squash merge, merged-
  branch deletion, and Core's final counterpart repin remain pending.
- [ ] Before production wiring, replace final name-based cleanup with a durable
  quarantine/retirement protocol: fsync intent, same-parent create-only rename,
  fsync parent, recheck the receipt, then delete. Preserve mismatches and test
  non-locking same-UID swaps at final file and directory retirement boundaries.
- [ ] Keep EXE binary updates and Core data-generation updates as distinct
  channels. A data-only lock update must not replace application code, broaden
  trust, or bypass the generation compatibility contract.
- [x] Consume Core resolver schema 2, `nextAction=build_exact_target`, installer
  validation/result/progress, module, userspace, initramfs, workspace, receipt,
  and gaming-payload fixtures with bounded fail-closed Rust adapters.
- [x] Consume Core source-intent and source-authorization schema 1 plus its exact
  21-case matrix from the same non-production development generation at
  `7f90e45c4c154fdfda81ff594611cf533e4fb894`. Bind every authorization to the
  canonical intent hash, exact target, action kind, resolver result/build plan,
  and reviewed project or acknowledged upstream source. Malformed, unsupported,
  substituted, and unreviewed inputs remain rejected without a build fallback.
- [ ] Route the normal source-selection path through an authenticated Core
  authorization and finish old/new behavioral equivalence; then remove only
  duplicated Core-owned release/source-selection policy. Retain Rust parsing,
  bounds, session binding, diagnostics, orchestration, and independent final-
  image verification.
  - [x] Add the first EXE-owned packaged resolver entrypoint without activating
    production discovery. `resolve-core-driver` accepts only resolver schema-2
    documents whose bytes match an explicit lowercase SHA-256, binds exact
    SteamOS/kernel-ABI/architecture and supported capability metadata, rejects
    conflicting or multiple different compatible decisions, and accepts one
    unique Core decision regardless of candidate order. Closed fixtures cover
    ordering and identical duplicates, exact-ABI mismatch,
    unsupported optional-CUDA capability, conflicting metadata, and hash mismatch.
    Canonical Core resolver source at immutable commit `a1c03c9658c5ed885f094b5f8e0896d818fee785`
    was fetched from authenticated GitHub and hashed as
    `d7fe29e02df03abd84f1558311a448adeb198fe50549a74ec9077482e68c70bc`.
    The real packaged binary command emitted the selected closed fixture without
    network or mutation. Focused Rust tests pass 3/3, JavaScript passes 209/209,
    documentation, hygiene/boundary, formatting, and warnings-as-errors Clippy
    pass. The full Rust run passed 343 tests with 28 ignored and one unrelated
    failure from the mutable sibling Core installer-result fixture, which is not
    an authorized Core input and was not retried. Production discovery, trust
    roots, downloads, and activation remain gated. PR
    https://github.com/CorniiDog/OPEMOS.EXE/pull/45 preserves pre-squash commit
    `58f79d7` plus evidence commit `62af319`; all required duplicated checks
    passed and the PR squash-merged as
    `437d55f65b8d56d4b0039e63cd61279d6a00a920`.
  - [x] Package the same experimental debug application as a portable x86_64
    AppImage alongside the Debian archive. Both Ubuntu and pinned Debian 12
    build plans request the exact `deb,appimage` target pair. CI requires one
    regular executable x86_64 ELF AppImage, runs it in extract-and-run mode,
    invokes only the packaged `resolve-core-driver`, hash-binds the closed local
    schema-2 fixture, and verifies the exact selected artifact and target.
    The local scheduler-limited Debian 12 build produced both bundles; the
    AppImage check passed with SHA-256
    `a72f60844ac3516032c1b74b95d20d447cadda928673856aa8dcd677eeaa9cf7`,
    and the companion Debian archive inspection passed with SHA-256
    `62d19731b83d156678157f0488c034a2092800a4ff2d175c90c41f153d373dc7`.
    No package was installed, no graphical application opened, and no network
    request, driver download, publication, production activation, KVM, or
    hardware operation occurred. A follow-up portable-package gate also proves
    the packaged command rejects a wrong authenticated digest, an exact-kernel
    mismatch, and two different compatible decisions; its temporary hostile
    candidate is removed automatically. The focused AppImage check passes with
    no GUI, network, download, or activation. The follow-up source commit is
    `319c929` on `work/exe-appimage-resolver-failures`; remote CI and review
    require publishing that bounded branch. The original package slice required publishing branch
    `work/exe-linux-appimage-package` to configured origin
    `https://github.com/CorniiDog/steamos-nvidia-image-builder.git`; source commit
    `c03a1d6` contains only this bounded slice. PR and squash evidence follow.
  - [x] Establish the repository-local Windows packaging VM containment before
    obtaining installation media or creating a guest. The gitignored
    `local-inputs/windows-vm/` tree has an exact private seven-directory layout,
    a create-only OPEMOS.EXE identity marker, current-user ownership and strict
    `0700`/`0600` modes. Inspection rejects links, special files, foreign root
    entries, changed identity, excessive traversal, and storage-limit breaches;
    sparse logical and allocated bytes are accounted separately under the
    recorded 8 GiB source, 12 GiB overlay, 40 GiB soft-total, and 55 GiB
    hard-total bounds. The real empty root reports 74 logical bytes and 4096
    allocated bytes. Focused validation passes 5/5. This slice downloads no ISO,
    creates no disk or credential, starts no VM, accesses no network, and does
    not alter production discovery, trust, activation, KVM, or hardware gates.
    Remote CI and review require publishing source commit `6211884` on branch
    `work/exe-windows-vm-containment` to configured origin
    `https://github.com/CorniiDog/steamos-nvidia-image-builder.git`; PR and
    squash evidence follow.
  - [x] Add the local Windows evaluation-media identity boundary before download
    or unattended installation. It accepts only one exact schema-1 Windows 11
    Enterprise Evaluation x86_64 identity from canonical Microsoft HTTPS,
    bounded to an 8 GiB ISO with explicit filename, release, size, and lowercase
    SHA-256. Verification requires a current-user-owned regular source file in
    the contained tree with immutable mode `0400`, then streams and matches the
    exact bytes. Closed tests reject HTTP and deceptive hosts, unknown fields,
    unsupported architecture, oversize input, mutable permissions, wrong size,
    and wrong digest. Focused Windows validation passes 7/7. This slice performs
    no download, ISO derivation, unattended generation, disk creation, network
    access, VM launch, production discovery/trust/activation, KVM, or hardware
    operation. The complete JavaScript suite passes 216/216 with documentation,
    hygiene, and diff checks. Remote CI and review require publishing source
    commit `e54a82c` on branch `work/exe-windows-media-plan` to configured origin
    `https://github.com/CorniiDog/steamos-nvidia-image-builder.git`; PR and squash
    evidence follow.
  - [x] Add reviewed secret-free Windows unattended templates and a private
    create-only generator. Committed XML and PowerShell contain placeholders,
    while a mode-`0600` ignored runtime document supplies one bounded test
    account, one-time password, and SSH public key. Generated answer/provisioning
    files remain mode `0600`; unknown fields, unsafe accounts, weak/control-byte
    passwords, malformed keys, permissive inputs, template drift, and existing
    outputs fail closed. Pair publication preserves a conflicting second file
    and removes only the first output created by that attempt. The answer file
    permits one setup autologon. The idempotent provisioning script installs the
    Microsoft OpenSSH capability, starts it automatically, preserves the
    firewall, installs the public key with restricted ACLs, disables SSH password
    authentication, and records completion without disabling Defender, Update,
    WebView2, accessibility, recovery, or device services. Focused Windows tests
    pass 11/11. No real credential was generated, ISO derived, disk created,
    network accessed, VM launched, or production trust/activation/hardware path
    enabled. The complete JavaScript suite passes 220/220 with documentation,
    hygiene, and diff checks. Remote CI and review require publishing source
    commit `4c05e6d` on branch `work/exe-windows-unattend-plan` to configured
    origin `https://github.com/CorniiDog/steamos-nvidia-image-builder.git`; PR
    and squash evidence follow.
  - [x] Acquire and authenticate the official Microsoft Windows 11 Enterprise
    Evaluation 25H2 EN-US x64 ISO as an immutable ignored local input. Microsoft
    Evaluation Center identified version 25H2 and linked the x64 ISO and hash
    PDF. The resolved ISO is build `26200.6584`, exactly `7092807680` bytes, with
    Microsoft-published SHA-256
    `a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9`.
    The downloaded Microsoft hash PDF has SHA-256
    `0d44bc561af90844c0a0da5ddc420f5fa84459872c02a1def6240fcfe1aac2c7`.
    The serialized download published only after size/hash success, the ISO is
    mode `0400`, and the strengthened local identity binds the canonical
    Microsoft ISO URL, hash-PDF URL/digest, EN-US locale, product, edition,
    architecture, release, size, and ISO digest. Independent streamed
    reverification passed; containment allocation is `7092822016` bytes. The ISO
    and manifest remain gitignored and will not be redistributed. No derived
    installer, credential, disk, VM, production trust/activation, KVM, or
    hardware operation occurred. Focused media validation passes 2/2 and the
    complete JavaScript suite passes 220/220 with documentation, hygiene, and
    diff checks. Remote CI and review require publishing source commit `91b2147`
    on branch `work/exe-windows-evaluation-source` to configured origin
    `https://github.com/CorniiDog/steamos-nvidia-image-builder.git`; PR and squash
    evidence follow.
  - [x] Build one private answer ISO without modifying or duplicating the
    official Windows ISO. The answer file now locates `opemos-provision.ps1` on
    attached filesystems and fails with code 31 when absent. A confined
    create-only builder validates the mode-`0600` generated pair and reviewed
    markers, grafts only `autounattend.xml` and `opemos-provision.ps1` through
    `genisoimage`, bounds stderr/output size, and removes only its failed output.
    Closed tests reject permissive or changed inputs, collision, and failed
    creation while preserving the source pair. Focused Windows tests pass 15/15.
    One unique ignored ED25519 key and one-time password generated without being
    printed or passed as process arguments. The 374784-byte answer ISO has
    SHA-256 `7c4feeccb81b890fa50b999e2af60af63e37f5b43100d0fc5dd945ad103543ae`;
    Joliet and Rock Ridge inventories contain exactly the two intended names.
    Public-key fingerprint is
    `SHA256:yE5d5TQXr4G63Hd5dPlMs4HJiQ5kENP3j5BqRL29O1o`; total containment allocation
    is `7093252096` bytes. No system disk or VM was created/launched, and no
    production trust/activation, KVM, or hardware path was enabled. PR and
    squash evidence follow.
  - [x] Remediate the post-PR-#52 elevated provisioning lookup so the answer
    file selects exactly one `OPEMOS_ANSWER` volume, constructs only its rooted
    `opemos-provision.ps1` path, and verifies the generated script's embedded
    lowercase SHA-256 before execution. Missing labels, duplicate labeled media,
    missing scripts, and digest mismatches fail closed; no first-match filesystem
    search remains. The confined builder rejects a changed script/answer pair
    before launching and tests the exact `genisoimage` command, ordered flags,
    output, graft names, inputs, and stdio. Focused Windows tests pass 8/8; the
    complete JavaScript suite passes 223/224 with only the intentionally skipped
    absent-Core fixture, plus documentation, repository hygiene, boundary, and
    diff checks. No secret, private media, VM launch, production activation,
    trust change, KVM, or hardware action is included. The lead verified remote
    `https://github.com/CorniiDog/steamos-nvidia-image-builder.git` redirects to
    canonical `CorniiDog/OPEMOS.EXE`, then normally fast-forward pushed branch
    `work/exe-windows-answer-binding` at pre-review commit
    `63d8d04b86cd77b420c3eec32b2d60b9f5379ae1`. PR
    https://github.com/CorniiDog/OPEMOS.EXE/pull/54 has exact base
    `507e23cf848cde3c74390f7e6c41ba09f9084a15`. All duplicated remote checks
    passed, with deploy skipped as designed. Core approved exact final head
    `82b716cd9f25a8e2358f94f67e24f550eeedf961` and its unchanged scope/check set
    through the authenticated handoff. The PR preserves pre-squash commits
    `63d8d04b86cd77b420c3eec32b2d60b9f5379ae1` and
    `82b716cd9f25a8e2358f94f67e24f550eeedf961`; it squash-merged to protected
    `main` as `0a3a76bb247ea824a7e9cd393a2b36e79369df5e` on 2026-09-08. The remote topic
    ref was absent after merge, and the lead removed only its clean local topic
    worktree and branch after verifying the squash.
  - [x] Make private answer-media permissions deterministic before contained VM
    installation. A normal `022` caller umask caused `genisoimage` to create the
    otherwise valid remediated ISO as mode `0644`; the fail-closed post-check
    correctly removed it, but creation then required an undocumented private
    umask. The builder now forces its tool-created output to mode `0600` before
    validation and removes it if permission hardening fails. A regression models
    mode-`0644` tool output and requires the published file to be mode `0600`.
    Focused Windows tests pass 10/10 and the complete JavaScript suite passes
    225/226 with only the intentionally skipped absent-Core fixture; documentation,
    repository hygiene, boundary integrity, and diff checks pass. PR, exact Core
    review, and squash evidence follow. No VM launch, network access, release,
    signing/trust, production,
    physical hardware, boundary, or sibling-repository change is included. The
    lead verified configured remote
    `https://github.com/CorniiDog/steamos-nvidia-image-builder.git` redirects to
    canonical `CorniiDog/OPEMOS.EXE`, then normally fast-forward pushed branch
    `work/exe-windows-vm-installer` at pre-review commit `a422afc`. PR
    https://github.com/CorniiDog/OPEMOS.EXE/pull/56 targets exact base
    `0a06f9598bcbc795526a47cf2bb018c1ff0a1486`; remote checks, exact Core
    review, final pre-squash history, and squash evidence follow. Core approved
    exact head `09e47daa7233939bf5ac96224eaea67818eda5de` and its four-file
    scope after all duplicated checks passed. PR #56 squash-merged to protected
    `main` as `ca787ce4c3f90e1116928892fff6368183a63721`; its remote topic
    ref was absent and only the verified clean local topic was removed.
  - [x] Build and test one unsigned portable Windows executable on GitHub's
    `windows-latest` runner because local KVM is unavailable. The workflow pins
    every action to an immutable commit, Rust `1.98.1`, Node `22.23.2`, locked
    JavaScript and Rust dependencies, and authenticated Core contracts at exact
    commit `3e49323fce266af8686039fb6487918ef5a64fd9`, which it verifies after
    checkout. It compiles the complete Rust test binary, runs Windows-specific
    cases, builds the release executable, rejects any Authenticode-signed output,
    and records exact source/Core/toolchain provenance, byte size, and SHA-256.
    Pull-request builds check out and verify the exact head rather than GitHub's
    temporary merge ref. Only a private one-day GitHub workflow artifact is
    uploaded; no release, signing/trust, production activation, local VM deletion,
    physical hardware, boundary, or sibling-repository change is included.

    PR https://github.com/CorniiDog/OPEMOS.EXE/pull/57 preserved pre-squash
    commits `2c93c0d5bfbbd826da50519b86b1def6714a0f40`,
    `663f29e10d88b06d2eb9c85d0d024dd1bb7d7df5`,
    `223860919d1b510f4c515bc656d0aa5f2c12945f`,
    `17f0e697d742b7f3b4f74eee3bf8c25ef2caef2e`,
    `266aad7f88ff6bf8d6b3c29d92615fe6e9db1f0f`,
    `0bf90abe829254cbe8580762b721ebf00132dd21`, and
    `5ddbf28b115115e7cef1f86ede32c6d204c858b5`. Core approved exact base
    `ca787ce4c3f90e1116928892fff6368183a63721`, final head
    `5ddbf28b115115e7cef1f86ede32c6d204c858b5`, eight-file scope, and all
    nine passing checks. Workflow run `34284706417` produced private artifact
    `10079324601`, bound to that EXE head and the pinned Core commit. The
    unsigned portable executable is 15,904,256 bytes with SHA-256
    `cb96feeba744d1b6ef420aad80f7b1e75ffce063a353d9ea386c29d9470e80d8`;
    independently downloaded bytes matched both `SHA256SUMS.txt` and
    `provenance.txt`. The PR squash-merged through protected `main` as
    `ac37cfc601b3031f96686b3363ca2fafa645714f`. GitHub removed the remote
    topic ref, and the lead removed only its verified clean local worktree and
    exact merged topic branch.
- [x] Require the unsigned portable Windows executable to show its real native
  main window before artifact staging. The hosted smoke now refreshes the launched
  process under a 30-second deadline, fails if no nonzero main-window handle
  appears or if its title is not exactly `SteamOS NVIDIA Builder`, and always
  terminates and waits for the owned process. Thirteen focused workflow-policy
  tests pass through `heavy.sh`, including removal of the visible-window, title,
  and unconditional-cleanup gates. The first native run reached a nonzero window
  handle before Windows had populated its title, so it failed with an empty title;
  the corrected poll now waits for both the handle and exact title within the same
  deadline. Corrected-head native Windows execution, PR checks, and squash evidence follow; this changes no imaging, Core, trust, publication,
  production, hardware, boundary, or governance behavior.
- [x] Consume the Core-owned exact-target maintainer workflow at canonical Core
  commit `b02ff79265e20bd7ef4fa4e16835c3c343afdee2`. The Windows maintainer
  menu now shows the exact SteamOS 3.8.14, kernel
  6.16.12-valve24.4-1-neptune-616-gfe145653a794, NVIDIA 575.64.05 target,
  immutable driver source, six ordered plan/build/package/bundle/validate/
  release-dry-run phases, and the dry-run-only publication boundary. A closed
  consumer rejects target, phase, ordering, remote-mutation, combined-image,
  and additive drift. Linux and Windows CI fetch the canonical GitHub Core
  commit and compare the bundled plan with the Core generator before building.
  The authenticated GitHub tar archive for canonical squash-merged Core main
  `https://api.github.com/repos/CorniiDog/OPEMOS/tarball/b02ff79265e20bd7ef4fa4e16835c3c343afdee2`
  has SHA-256 `8de9981ea2e63c3395f259ca928a0e1f3ab34d0c92834a4ddcf3cecb84e94696`.
  This is distinct from the authenticated review archive for pre-squash Core PR
  #37 head `https://api.github.com/repos/CorniiDog/OPEMOS/tarball/b4496b2b5234a69948cc48f85d89f8955cee145a`,
  whose SHA-256 is `1ba85212a526fd0161178bcd1eff8f43ac728700856417f3f52a69dbcdb89f51`;
  the exact parity check, 22 focused cases, all 284 applicable JavaScript cases,
  documentation, and repository hygiene pass through `heavy.sh`. This exposes
  a usable preparation plan and does not execute builds or authorize
  publication. The first repinned Rust CI run then exposed Core's added
  `cancelled-terminal` fixture; EXE now accepts only that exact terminal status
  and verifies its cancelled phase/reason, completed cleanup, and absence of
  validation or mutation evidence. The exact focused Core fixture consumer passes.
- [x] Replace the first portable Windows artifact after a user-reported release
  blocker: its backend rejected Windows as an unsupported host and the UI reported
  `Builder unavailable`. PR https://github.com/CorniiDog/OPEMOS.EXE/pull/59
  preserved source commit `bd44cf126060d30ee777f89731d41eadb36efcd7`
  and added the x86_64 WHPX plan with no software fallback, Windows
  PATH/PATHEXT executable discovery that preserves paths with spaces, native RAM
  and process-liveness detection, QEMU-distribution firmware, cdrtools seed
  creation, complete prerequisite gating, Windows-specific host status, and an
  exact release-executable startup smoke test. All ten non-deploy checks passed.
  Core approved exact base `ba7c9ace36003a13a8cad3f55280afff824e5d84`,
  unchanged head `bd44cf126060d30ee777f89731d41eadb36efcd7`, ten-file
  scope, clean merge state, check set, and private artifact evidence through the
  authenticated same-account-review fallback. Windows workflow run `34306251759`
  produced private one-day artifact `10086975917`; the unsigned portable EXE is
  16,253,440 bytes with SHA-256
  `6e72f87dbe7ed5f0cefa4f2110f6af969533101dbf7ca876360eed2e5745c728`,
  and its manifests bind that EXE head, Core
  `3e49323fce266af8686039fb6487918ef5a64fd9`, Rust `1.98.1`, Node
  `22.23.2`, and runner image `win25-vs2026` version `20260824.214.3`.
  PR #59 squash-merged through protected `main` as
  `fbb9bf6e6ee4c146ff3f3ec2f8557a815f9590e4`; GitHub removed the
  remote topic and EXE removed only its verified clean local topic/worktree.
  No release publication, signing/trust, production activation, physical USB
  write, boundary change, or sibling-repository mutation occurred.
- [x] Fix the Windows live-test follow-up on a fresh EXE PR: apply settings
  checkbox intent immediately without a WebView restart; enumerate eligible USB
  physical drives read-only with explicit empty, error, refresh, and replug
  behavior while keeping Windows writes disabled; hide verbatim `\\?\` path
  prefixes only in displayed text; and group NVIDIA source and output controls
  in accessible workflow order. Focused parser, path, state, layout, Windows
  build, and exact executable startup-smoke evidence follows. No USB write,
  release, signing/trust, production, Core, boundary, or hardware action is
  authorized by this item. PR #61 preserves pre-squash commits
  `aac932b96e5ca5cb50ed82e2a6bcb53e8baefdb3`,
  `31cd21245bd36d9a2f7fad826f7a0577ab52eed1`, and
  `70fd2554e876509a551da93953304c355e30ec09`. Core rejected the first head
  because it compared a one-leading-backslash physical-drive path, then
  approved exact base `2205afc7993eba328a277c1d253a3fae3a5af6c3` and final
  head `70fd2554e876509a551da93953304c355e30ec09` after the candidate changed
  to canonical `\\.\PHYSICALDRIVE<N>` and a literal PowerShell
  `ConvertTo-Json` wire fixture covered decoding, the exact four-byte prefix,
  and mismatch rejection. Local focused Windows inventory tests pass 2/2;
  formatting and full warnings-as-errors Clippy pass. All ten non-deploy PR
  checks pass, including both Rust, Linux integration, Debian 12 package, and
  frontend/documentation jobs plus the Windows build. Private artifact
  `10089283135` from run `34312989388` independently verifies as an unsigned
  portable executable of 16,225,280 bytes with SHA-256
  `151f13abffc7244633d67fa115a150c83a0028596f732dd730fcb36f7dcb4c7e`;
  its manifest binds the exact final EXE head, immutable Core commit
  `3e49323fce266af8686039fb6487918ef5a64fd9`, Rust `1.98.1`, Node
  `22.23.2`, and runner `win25-vs2026` version `20260824.214.3`, and the
  workflow startup smoke passed. PR #61 squash-merged through protected
  `main` as `8a04649d75dc9808340e927c1e61e7ba1a6f389c`; GitHub removed the remote
  topic. No USB write, release publication, signing/trust, production
  activation, Core or boundary change, or hardware action occurred.
- [x] Run the published Core compatibility baseline in CI from immutable commit
  `8224169`; never test against mutable Core `main`.
- [x] After Core published `1fde359025031a99055763dca76e0d709486ffac`,
  repin CI so the 74 generation, 16 OpenPGP, 49 bootstrap, 28 verifier-evidence,
  and 35 request-plan cases run remotely. A contract-fixture pin does not
  activate a candidate bundle.
- [x] Repin the immutable CI checkout to published lifecycle successor
  `3e49323fce266af8686039fb6487918ef5a64fd9` after confirming its shared
  schemas and compatibility fixtures are byte-identical to the validated
  `dfa83a01ad7d8cb915466de86229741f725c83b8` baseline. This records the
  complete published Core lifecycle without activating production trust.
- [x] Add an inactive Unix verifier-child lifecycle substrate with an exact
  executable digest, bounded output, deterministic cancellation/timeout,
  process-group descendant reaping, and descriptor-confined cleanup tests.
- [x] Add an inactive Unix installed-trust adapter that pins an exact private
  three-file policy/keyring/checkpoint inventory to independent hashes, retains
  descriptor-bound guards through sealed two-phase verification and pending
  activation, and rejects replacement, mixed lineage, cancellation, and unsafe
  filesystem inputs under adversarial tests.
- [ ] Before production wiring, provide the reviewed install/config channel that
  creates those independent pins, reject macOS ACL grants in addition to Unix
  modes, and choose a reviewed signed/platform verifier launch path. Current
  trust and pathname adapters remain test-only and cannot activate production.
- [ ] Repin or activate a generation only after Core’s complete Fedora suite and
  this repository’s unit, integration, cancellation, cleanup, malformed-input,
  lifecycle, ENOSPC, replay/downgrade, and final-image tests pass against the
  same immutable publication.

The Core-to-EXE handoff is data, never policy code: Core publishes the signed
generation descriptor, canonical manifest, reviewed locks, target decisions,
schemas, fixtures, and evidence. OPEMOS.EXE authenticates, caches, selects,
transports, and independently verifies that generation in its host cache.
Installed Core/CLI independently discovers and activates the same authenticated
generation identity in a separate device cache for install, update, and repair.
The consumers share identities, schemas, and fixtures—not updater code, physical
caches, activation state, credentials, or health state. Unknown authority or
schema, replay/downgrade, target mismatch, partial download, ENOSPC, or failed
health validation must leave each consumer's last-known-good generation active.

Core commits `510e843c9ef7fea3e1f9b0c9a3f0c8480ddc596d`,
`e3cbcd1ffaea68f2cb0a5fc737a93a831f397f4d`, and
`eff994cfa52224bfb5dd1ce1c84ad295a05831f5` add, fixture-test, and harden
restart reconciliation for the separate inactive installed-device lifecycle.
Core commit `78cf5e8ee5b4a48782afffa43b5812f7e3cf801b` additionally confines abandoned
device-cache cleanup and applies bounded retention and storage admission. Core
commit `c07de7cf5b40e1a52b1db83126436fda2fe611d4` adds a durable activation-intent
journal and restart recovery around device-side state publication. Core commit
`34ee1d22a519fadaccfd12657d56c478316c74d5` adds a development-only injected
acquisition path into a separate authenticated device download cache without
changing active state; Core commit
`22b2beb5d9e2aabe517fabf0b1e9947ed06ba408` contains transport descendants
across owner termination through a bundled watchdog. Production networking
remains inactive. Core commit
`fda5de265c685b95c3e61daeb084ed7188998f96` clarifies the shared consumer
handoff without changing schema-1 wire documents: discovery is authenticated by
canonical external OpenPGP evidence, generation payloads are non-executable
data, storage accounting includes bounded control artifacts, and persisted
discovery names are canonical. Device acquisition, health, persistence,
activation, and physical cache implementation remain Core-owned; OPEMOS.EXE
must not copy that frontend or updater.
Core commit `f2030ab5277c18ae4320747d8e1c4f8120efd0bb` preserves those wire
documents and adds the separate canonical bounded OpenPGP verifier-status
contract. It is compatibility evidence, not a production key or endpoint.
Core commit `0c16ccd7ba68095ea8a6655b0d2bb8b6e97d32f3` defines and hardens the closed
inactive bootstrap policy and checkpoint compatibility contract, including
portable immutable namespace identities. It ships no production trust material
or service location. Core commit `1fde359025031a99055763dca76e0d709486ffac`
adds the closed inactive request-plan and verifier-capability contracts without
shipping a production verifier, transport, or endpoint. Published successor
`dfa83a01ad7d8cb915466de86229741f725c83b8` preserves those shared contracts
while hardening Core-owned device acquisition staging.
Newer unpublished Core health/receipt hardening changes no shared EXE schema;
keep it inactive until Core publishes it and cross-repository tests pass.

Compatibility fixture only—never use this as a permanent global trust root:

```text
Core commit: a1c03c9658c5ed885f094b5f8e0896d818fee785
Manifest SHA-256: 34fa1dfa0351f3bfede0451632063b496ca41da3544d07296a5e4a42a9756cd1
Bundle ID: 225a5c08ebfb77b3e2ba61aa92c678ba59a13321185f3b6766194e97bf8318fa
```

### 2. Prove the generated media end to end

- [ ] Build from a fresh official recovery image and independently verify the
  final rootfs, EFI, home payloads, Holo database, modules, userspace, firmware,
  initramfs, boot arguments, welcome assets, and embedded receipt.
- [ ] Install from the generated USB onto the intended physical disk and verify
  the installed receipt matches the image-build receipt before accepting
  payload propagation.
- [ ] Boot without the recovery USB and verify Desktop Mode, Gaming Mode,
  `nvidia-smi`, module vermagic, Vulkan/GLX/EGL, games through Proton, external
  display, suspend/resume, and absence of NVIDIA Xid faults.
- [ ] Test without first-boot internet access when all required payloads are
  embedded.
- [ ] Test a SteamOS A/B update and prove Core’s guardian either installs the
  exact new-kernel driver before slot activation or retains/returns to the last
  verified slot.
- [ ] Verify recovery remains reachable when NVIDIA graphics initialization,
  networking, artifact resolution, package authentication, initramfs creation,
  or first graphical boot fails.
- [ ] Only after those checks pass, promote output classification from
  `nvidia-mutation-valid` to `install-ready`.

### 3. Idempotency and upgrades

- [ ] Inspect selected media by authenticated state and receipt—not filename—to
  distinguish stock, already-current, upgradeable, partial, and contradictory
  images.
- [ ] For an identical verified SteamOS/kernel/NVIDIA state, skip downloads,
  build, package mutation, and initramfs regeneration while still running
  independent validation.
- [ ] Treat a different valid kernel or NVIDIA version as an explicit upgrade;
  reject partial or unverifiable installations instead of overwriting them.
- [ ] Prove repeat runs leave identical media byte-for-byte unchanged and
  upgrades never modify the original source image.
- [x] Reject overlapping image/adjacent-manifest reservations before inactive
  staging. A regression reproduced two live reservations sharing one output
  path. Acquire both paths in image-then-manifest lexical order using the same
  output-lock namespace, including on reopen; verify both guards through
  record creation, staging, and recovery. Tests cover both acquisition orders,
  partial-acquisition lock release, reopen contention, cross-process overlap,
  manifest-lock replacement before staging, and restrictive umask. Source
  bytes and output paths remain unchanged after rejected reservations. The
  SIGKILL inventory allows four locks and ten total private entries, accounting
  for exactly one additional empty manifest lock. Production remains inactive.
  On Ubuntu 24.04.4 through the shared scheduler, formatting and Clippy pass,
  323 Rust tests pass (27 ignored), and all 105 frontend tests plus documentation,
  hygiene, and boundary integrity pass against the unchanged Core fixture pin.
- [ ] Test output-name and adjacent-manifest collisions, interrupted two-file
  finalization, stale manifests, and concurrent builds selecting the same
  source or destination.
  - [x] Cover a stale adjacent manifest at the first version-pinned NVIDIA
    output name. Naming advances to the create-only `-2.img` pair without
    creating the blocked image or changing the stale manifest bytes. On
    2026-09-05, the focused Rust naming regression passes. Interrupted
    two-file finalization and broader concurrent-build cases remain open.
  - [x] Extend the version-pinned collision regression across mixed pair
    occupancy: after the stale base manifest forces `-2.img`, a foreign image
    at that second candidate forces `-3.img`. Both blocking artifacts retain
    their exact bytes. On 2026-09-05, the focused Rust naming regression passes.
    Interrupted finalization and cross-process build concurrency remain open.
  - [x] Race two fresh subprocess reservations from different source images
    against the same image/adjacent-manifest destination pair behind one start
    barrier. Exactly one process acquires both locks while the other receives
    `RESERVATION_ALREADY_HELD`; after release, both source bytes are unchanged
    and neither destination exists. On 2026-09-05, the focused Rust subprocess
    regression and formatting pass. Full build-level concurrency and
    interrupted two-file finalization remain open.
  - [x] Extend the real subprocess SIGKILL/reopen matrix through both
    pre-rename boundaries. Termination immediately before image publication and
    in the image-visible/manifest-hidden window both remain uncommitted, release
    process locks, preserve source and foreign bytes, and resume through the
    durable receipt chain to the exact verified image/manifest pair. On
    2026-09-05, the focused 12-boundary Rust subprocess matrix and formatting
    pass. Full build-level concurrency remains open.

### 4. Lifecycle and failure hardening

- [ ] Give every build, appliance, handoff, USB operation, and async worker a
  generation ID so stale completions cannot overwrite newer state.
  - [x] Gate overlapping GitHub maintainer-status refreshes and login-poll
    responses with one bounded latest-request generation. Older successes and
    errors cannot replace a newer authentication/authorization result; polling
    additionally retains its existing login-attempt identity. Independent gate,
    invalid-candidate, stale-success/error wiring, and mutable-counter exposure
    regressions cover the slice. On 2026-09-05, the focused 18-case async/layout
    suite and all 144 frontend tests plus documentation, hygiene, and boundary
    integrity pass. Other async workers remain under the parent lifecycle item.
  - [x] Bind the initial GitHub maintainer-connect response to the same
    latest-status generation and its existing login-attempt identity. A newer
    refresh can supersede a delayed connect success without preventing the
    current login poll from starting; a superseded connect error clears pending
    login state without replacing the newer status message. On 2026-09-05, the
    focused 18-case async/layout suite and all 144 frontend tests pass, along
    with documentation, repository hygiene, and boundary integrity checks.
    Other async workers remain under the parent lifecycle item.
  - [x] Reject stale GitHub login-poll errors using both the login-attempt
    identity and latest-status generation before changing the visible message.
    A refresh or reconnect that supersedes an in-flight rejected poll now keeps
    its newer state. On 2026-09-05, the focused 18-case async/layout suite and
    all 144 frontend tests pass, along with documentation, repository hygiene,
    and boundary integrity checks. Other async workers remain under the parent
    lifecycle item.
  - [x] Give the native image chooser its own latest-request generation and
    capture the active image-selection generation before opening the dialog.
    An older overlapping chooser and a chooser superseded by drag-and-drop can
    no longer start validation or replace the newer selection. On 2026-09-05,
    the focused 41-case workflow/layout suite and all 145 frontend tests pass,
    along with documentation, repository hygiene, and boundary integrity
    checks. Other async workers remain under the parent lifecycle item.
  - [x] Give the native output-folder chooser its own latest-request generation
    and capture both output and image-selection revisions before opening the
    dialog. Older overlapping dialogs, resets, and image replacements can no
    longer apply a stale directory. On 2026-09-05, the focused 42-case
    workflow/layout suite and all 146 frontend tests pass, along with
    documentation, repository hygiene, and boundary integrity checks. Other
    async workers remain under the parent lifecycle item.
  - [x] Gate settings loading, ordinary saves, and automated-release saves with
    one latest-request generation, and freeze each update payload before its
    first await. A delayed startup read, stale success or error, and stale
    pending-state cleanup can no longer overwrite a newer user operation; an
    older request cannot send a payload mutated by a later edit. On 2026-09-05,
    the focused 21-case async/layout suite and all 147 frontend tests pass,
    along with documentation, repository hygiene, and boundary integrity
    checks. Other async workers remain under the parent lifecycle item.
  - [x] Gate overlapping maintainer workspace source refreshes with the shared
    overflow-safe latest-request generation. An older source-list success or
    error can no longer replace a newer inventory, permission result, message,
    loading state, or enabled-control state; stale finalizers leave the newer
    request in control. The focused request-gate/maintainer suite passes 4/4,
    and all 172 frontend tests plus documentation, hygiene, and boundary
    integrity pass on 2026-09-06. Other async workers remain under the parent
    lifecycle item.
  - [x] Gate overlapping maintainer workspace plan verifications with a
    dedicated latest-request generation, invalidated by source or plan resets.
    Older same-source successes, errors, and finalizers cannot replace or clear
    a newer verified plan, message, loading state, or enabled-control state.
    The focused request-gate/maintainer suite passes 5/5 and all 173 frontend
    tests plus documentation, hygiene, and boundary integrity pass on
    2026-09-06. Other async workers remain under the parent lifecycle item.
  - [x] Give maintainer staged-commit review requests a dedicated generation,
    invalidated by message edits, workspace resets, and worktree replacement.
    An older same-context snapshot success, error, or finalizer can no longer
    replace the newer reviewed tree or alter its controls. The focused
    request-gate/maintainer suite passes 6/6 and all 174 frontend tests plus
    documentation, hygiene, and boundary integrity pass on 2026-09-06. Other
    async workers remain under the parent lifecycle item.
  - [x] Gate overlapping maintainer local-branch list requests with a dedicated
    generation invalidated by plan resets and worktree replacement. Older
    same-worktree lists, errors, and finalizers cannot replace a newer branch
    inventory, checkout controls, status, or loading-button state. The focused
    request-gate/maintainer suite passes 7/7 and all 175 frontend tests plus
    documentation, hygiene, and boundary integrity pass on 2026-09-06. Other
    async workers remain under the parent lifecycle item.
  - [x] Give maintainer checkout-review requests a dedicated generation,
    invalidated by branch-list refresh, branch selection, plan reset, and
    worktree replacement. Awaited review data stays request-local until the
    exact branch/worktree context passes, so older successes, errors, and
    finalizers cannot replace the newer review or its controls. The focused
    request-gate/maintainer suite passes 8/8 and all 176 frontend tests plus
    documentation, hygiene, and boundary integrity pass on 2026-09-06. Other
    async workers remain under the parent lifecycle item.
  - [x] Gate overlapping recent-worktree refreshes with a dedicated generation
    invalidated by plan reset and worktree replacement. Older same-workspace
    lists and errors cannot replace a newer recent-folder inventory, status, or
    control state, and both paths revalidate the exact planned repository. The
    focused request-gate/maintainer suite passes 9/9 and all 177 frontend tests
    plus documentation, hygiene, and boundary integrity pass on 2026-09-06.
    Other async workers remain under the parent lifecycle item.
  - [x] Gate overlapping native worktree chooser dialogs and their subsequent
    inspections with a dedicated generation invalidated by plan reset or any
    independently rendered worktree. Older dialog choices, inspection successes,
    errors, and finalizers cannot replace a newer worktree or clear its pending
    state; every accepted path also revalidates the exact planned repository.
    The focused request-gate/maintainer suite passes 10/10 and all 178 frontend
    tests plus documentation, hygiene, and boundary integrity pass on 2026-09-06.
    Other async workers remain under the parent lifecycle item.
  - [x] Extend the native chooser generation into one shared worktree-selection
    gate covering recent-folder selection and inspection. A newer selection,
    empty selection, plan reset, or independently rendered worktree invalidates
    the older request; stale successes, errors, and finalizers cannot replace
    the current worktree or clear its pending state. The focused request-gate/
    maintainer suite passes 11/11 and all 179 frontend tests plus documentation,
    hygiene, and boundary integrity pass on 2026-09-06. Other async workers
    remain under the parent lifecycle item.
  - [x] Extend the shared worktree-selection generation through managed
    worktree creation/reopen and bind the request to the exact planned source.
    A newer selection, plan reset, source change, or independently rendered
    worktree invalidates older creation successes, errors, and finalizers before
    they can replace the current worktree or clear its pending state. The focused
    request-gate/maintainer suite passes 12/12 and all 180 frontend tests plus
    documentation, hygiene, and boundary integrity pass on 2026-09-06. Other
    async workers remain under the parent lifecycle item.
  - [x] Give VS Code open/revalidation requests a dedicated generation,
    invalidated by plan reset and worktree replacement. Older same-worktree
    successes and errors cannot replace the current worktree, status, or controls;
    every accepted result still revalidates the exact generation, path, and
    repository. The focused request-gate/maintainer suite passes 13/13 and all
    181 frontend tests plus documentation, hygiene, and boundary integrity pass
    on 2026-09-06. No VS Code process was launched during validation. Other
    async workers remain under the parent lifecycle item.
  - [x] Gate maintainer local-commit and follow-up worktree-refresh requests
    with a dedicated generation bound to the exact reviewed inputs and workspace.
    Plan reset, worktree replacement, message edits, or a newer review/request
    invalidates older successes, errors, refreshes, and finalizers before they can
    replace newer status or controls. The focused request-gate/maintainer suite
    passes 14/14 and all 182 frontend tests plus documentation, hygiene, and
    boundary integrity pass on 2026-09-06. No Git mutation ran during validation.
    Other async workers remain under the parent lifecycle item.
  - [x] Gate maintainer checkout execution and its follow-up worktree refresh
    with a dedicated generation bound to the exact reviewed branch identities and
    workspace. Plan reset, worktree replacement, branch changes, or newer review,
    list, or execution requests invalidate older successes, errors, refreshes,
    and finalizers. The focused request-gate/maintainer suite passes 15/15 and
    all 183 frontend tests plus documentation, hygiene, and boundary integrity
    pass on 2026-09-06. No checkout or Git mutation ran during validation. Other
    async workers remain under the parent lifecycle item.
  - [x] Gate overlapping host-environment checks with a dedicated latest-request
    generation. Older successes and errors cannot replace newer `hostReady`,
    readiness presentation, or build-button state; host policy and native probe
    behavior remain unchanged. The focused async/layout suite passes 22/22 and
    all 184 frontend tests plus documentation, hygiene, and boundary integrity
    pass on 2026-09-06. No host probe ran during validation. Other async workers
    remain under the parent lifecycle item.
  - [x] Replace the NVIDIA source-branch refresh's exposed mutable generation
    counter with the shared overflow-safe latest-request gate while preserving
    the workflow admission contract and stale success, error, and finalizer
    behavior. The focused generation/layout/workflow suite passes 46/46 and all
    184 frontend tests plus documentation, hygiene, and boundary integrity pass
    on 2026-09-06. No network source refresh ran during validation. Other async
    workers remain under the parent lifecycle item.
  - [x] Replace the compatibility-preview controller's exposed mutable revision
    counter with the shared overflow-safe latest-request gate. Existing clear,
    close, explicit-failure, pending-file-read, and native-preview invalidation
    semantics remain intact. The focused compatibility/generation suite passes
    21/21 and all 185 frontend tests plus documentation, hygiene, and boundary
    integrity pass on 2026-09-06. Other async workers remain under the parent
    lifecycle item.
  - [x] Replace the native image chooser's exposed mutable request counter with
    the shared overflow-safe latest-request gate while retaining the separate
    image-selection revision that invalidates stale dialogs after drag-and-drop
    or another selection. The focused async/layout suite passes 22/22 and all
    185 frontend tests plus documentation, hygiene, and boundary integrity pass
    on 2026-09-06. No native chooser opened during validation. Other async
    workers remain under the parent lifecycle item.
  - [x] Replace the native output-folder chooser's exposed mutable request
    counter with the shared overflow-safe latest-request gate while retaining
    the separate output- and image-selection revisions that reject stale
    dialogs after resets or image replacement. The focused async/layout suite
    passes 22/22 and all 185 frontend tests plus documentation, hygiene, and
    boundary integrity pass on 2026-09-06. No native chooser opened during
    validation. Other async workers remain under the parent lifecycle item.
  - [x] Replace the GitHub maintainer login poll's exposed mutable request
    counter with a dedicated shared overflow-safe latest-request gate while
    retaining the independent status gate and stale connect, poll, error, and
    timeout rejection. The focused async/layout suite and complete frontend,
    documentation, hygiene, and boundary checks pass on 2026-09-06. No login,
    network request, or authorization change ran during validation. Other async
    workers remain under the parent lifecycle item.
- [x] Add the inactive descriptor-bound source/output reservation foundation:
  pinned source and parent descriptors, exclusive immutable locks, strict
  basenames, and a closed durable record that preserves torn or stale state.
- [x] Close renamed-source contention in the inactive output reservation.
  A regression reproduced two reservations accepting the same inode after a
  rename. Retain the existing pathname lock and add a device/inode lock before
  hashing, acquired in pathname → inode → output order; verify both source
  locks throughout consumption. Same-parent and cross-parent rename tests
  preserve exclusivity, failed inode acquisition releases its pathname lock,
  lock replacement revokes the guard, and a real subprocess holds exclusivity
  across rename until exit. The source and foreign bytes remain unchanged.
  This is an inactive host reservation change, not production export wiring;
  working-image/USB locks and broader lifecycle lock-order proof remain open.
  The bounded SIGKILL inventory now permits exactly one additional empty lock
  (at most three locks and nine total private entries). On Ubuntu 24.04.4 under
  the shared scheduler, formatting and Clippy pass, 321 Rust tests pass
  (27 ignored), and all 105 frontend tests plus documentation, hygiene, and
  boundary integrity pass against the unchanged Core fixture pin.
- [x] Bind inactive publication to the exact source guard recorded by its
  reservation. A regression reached staging with a valid guard for a different
  source. Guard verification now rejects identity or hash mismatch before any
  publication step. Six reserved/staged/complete cases cover distinct sources
  with different or identical bytes, repeated rejection without file/receipt
  changes, and successful retry after reacquiring the original guard. A further
  case rejects substitution after the original source changes, including a new
  guard for that changed inode. Production wiring and cleanup gates stay open.
  On Ubuntu 24.04.4 through the shared scheduler, formatting and Clippy pass,
  325 Rust tests pass (27 ignored), and all 105 frontend tests plus documentation,
  hygiene, and boundary integrity pass against the unchanged Core fixture pin.
- [x] Require inactive source/output reservations to share the same pinned
  private lock-directory identity. A regression accepted an output reservation
  in a second root, creating an independent lock namespace for the same source.
  Reject this before output lock/record creation, recheck acquired lock roots,
  and reject equal-byte/equal-inode source guards from another root during
  publication and completion recovery. Tests cover empty-root preservation,
  repeated rejection, correct-root retry, and alternate spelling of the same
  directory. Choosing the fixed installed application root remains gated;
  this change does not configure production storage or trust. On Ubuntu
  24.04.4 through the shared scheduler, formatting and Clippy pass, 327 Rust
  tests pass (27 ignored), and all 105 frontend tests plus documentation, hygiene,
  and boundary integrity pass against the unchanged Core fixture pin.
- [ ] Add a cross-process exclusive lock for each source image, working image,
  output reservation, and USB target. Before activation, use one fixed private
  app-owned root, retain the source guard through descriptor-bound consumption,
  close lock-inode/verify-to-action races, and hold every lock through cleanup.
- [x] Add an inactive image-first/manifest-last publication prototype with an
  unpredictable operation identity, create-only per-file receipt chain,
  exclusive no-replace renames, descriptor-bound exact-byte resume, and
  fail-closed preservation of unreceipted or mismatched residue.
- [ ] Independently review and activate output publication only after real
  subprocess/SIGKILL, ENOSPC/EDQUOT/fsync, replacement-race, and platform
  no-replace tests pass. Add explicit recovery UI and durable quarantine before
  any restart-time deletion; never infer deletion authority from a mutable
  reservation record.
- [x] Exercise the inactive paired publication transaction in real subprocesses
  killed at every stage receipt, image rename/directory-sync/published receipt,
  and manifest rename/directory-sync/published receipt boundary. Restart tests
  prove only exact receipted states resume, incomplete pairs remain untrusted,
  source and foreign files remain unchanged, locks release, and residue stays
  bounded. Injected published-artifact/output-directory storage faults are
  covered below; real filesystem exhaustion and production activation remain
  gated.
- [x] Add test-only, thread-local storage fault injection at the inactive EXE
  image/manifest staging write and file-sync calls. Eighteen cases cover
  ENOSPC, EDQUOT, and EIO before the first byte, after a real partial write
  (including a completed image chunk), and at file sync. Failed staging removes
  only its exact unreceipted inode, never publishes the output pair, preserves
  prior image receipts, and resumes to verified exact bytes after releasing and
  reacquiring source/output locks. Two further cases swap in same-size,
  same-mode foreign stages before partial-write failure: cleanup and retry
  preserve both foreign bytes and the moved original descriptor's partial bytes.
  Source bytes/metadata and unrelated files stay unchanged. This is deterministic
  fault injection, not a real full-filesystem or power-loss test; production
  publication remains inactive. On Ubuntu 24.04.4 through the shared scheduler,
  formatting and Clippy pass, 313 Rust tests pass (27 ignored), and all 98
  frontend tests plus documentation, hygiene, and boundary integrity pass.
- [x] Require the exact validated receipt chain to be synced before inactive
  output-publication completion, including recovery of apparently complete
  pairs. A regression first reproduced recovery returning Complete after a
  failed receipt sync without retrying that sync. The final acceptance path
  now verifies each receipt's descriptor identity and bytes before and after
  syncing its file and pinned parent; it then repeats guards and final-pair
  verification. Thirty-six receipt create/zero-byte/partial-write failures
  preserve ambiguous evidence or reconstruct only a missing published receipt
  from the exact intact staged chain. Twenty-four repeated ENOSPC/EDQUOT/EIO
  file/parent-sync cases stay failed after lock reacquisition until persistence
  succeeds; an identical-byte replacement inode is rejected. All four receipt
  phases are covered. These are injected errors, not power-loss certification;
  receipt bytes/schemas and production activation remain unchanged. On Ubuntu
  24.04.4 under the shared scheduler, formatting and Clippy pass, 316 Rust tests
  pass (27 ignored), and all 98 frontend tests plus documentation, hygiene, and
  boundary integrity pass against the unchanged Core fixture pin.
- [x] Exercise inactive publication artifact and output-directory sync failures
  with test-only thread-local injection. Twelve image/manifest ENOSPC/EDQUOT/EIO
  cases fail again after lock reacquisition, retry the sync without renaming the
  exact existing final inode, and complete only after persistence succeeds.
  Eight further cases reject same-inode content changes and identical-byte
  replacement inodes after failed sync, preserving foreign files and original
  evidence across repeated retries. No premature published receipt is created;
  source bytes/metadata and staged receipts remain unchanged. These injected
  failures do not certify real filesystem exhaustion, power loss, or macOS
  runtime behavior; production publication remains inactive. On Ubuntu 24.04.4
  under the shared scheduler, formatting and Clippy pass, 318 Rust tests pass
  (27 ignored), and all 98 frontend tests plus documentation, hygiene, and
  boundary integrity pass against the unchanged Core fixture pin.
- [ ] Extend storage-failure coverage to durable quarantine/retirement and real
  filesystem failures before activation; never auto-delete ambiguous residue.
- [ ] Formalize lock ordering and prove status polling, cancellation, close,
  and worker completion cannot deadlock.
- [ ] Route normal cancellation, window close, process failure, and next-launch
  abandoned-session recovery through one idempotent cleanup contract.
- [ ] Replace user-facing string errors incrementally with stable bounded error
  codes, responsibility, retryability, and safe diagnostic detail.
- [x] Add cooperative cancellation to inactive source reservation acquisition
  and verification, checking before acquisition and around each 1 MiB hash
  read (including completion). Eight acquisition and six verification cases
  cover early, mid-read, and final-read cancellation. Cancelled acquisition
  releases both locks for retry without changing source bytes/metadata;
  cancelled verification retains ownership and never caches acceptance of
  later-mutated bytes. Pre-cancelled missing input performs no root mutation.
  Existing non-cancellable entry points retain their behavior. Runtime UI
  cancellation wiring and interruption of a blocked filesystem syscall remain
  separate gates; production output publication stays inactive. On Ubuntu
  24.04.4 through the shared scheduler, formatting and Clippy pass, 329 Rust
  tests pass (27 ignored), and all 105 frontend tests plus documentation, hygiene,
  and boundary integrity pass against the unchanged Core fixture pin.
- [x] Add cooperative cancellation to the inactive output publication
  transaction. Check before mutation and after each staged image/manifest chunk,
  file sync, durable receipt, rename, and publication sync boundary. Seven early,
  multi-chunk, receipted, and finalization cancellation cases retain both source
  and output reservations, preserve exact source bytes and metadata, never expose
  a manifest without its image, and resume through the same descriptor-bound
  transaction to an exact verified pair. This does not wire runtime UI
  cancellation, delete recovery evidence, or activate production publication.
  On Ubuntu 24.04.4 through the shared scheduler, formatting and Clippy pass,
  330 Rust tests pass (27 ignored), and all 105 frontend tests plus documentation
  and hygiene checks pass against the unchanged Core fixture pin.
- [ ] Test cancellation and injected failure during download, decompression,
  transfer, QEMU boot, Core validation, package mutation, initramfs, export, USB
  writing, USB verification, and finalization.
  - [x] Cover Linux Fedora cache replacement download interruption with a real
    child process and process-group SIGTERM. Once partial bytes exist, termination
    returns nonzero, preserves the exact prior cache bytes, and removes the
    temporary download. A separate injected download exit after writing partial
    bytes also preserves the cache and removes the partial file. The focused
    builder suite passes 7/7. Signed-checksum trust-failure coverage also rejects
    duplicate and malformed entries before any cache or output replacement. The
    focused builder suite passes 8/8. Other listed cancellation and injected-
    failure phases remain open.
- [ ] On every terminal path prove: original unchanged, partial output absent,
  mounts released, guests stopped, locks released, secrets removed, and no
  partial result accepted as trusted.

### 5. Trust and release readiness

- [ ] Make Fedora image signature verification mandatory for packaged release
  builds and pin the expected Fedora signing identity.
- [ ] Version and authenticate native/x86 appliance releases independently from
  the desktop application; verify their hashes before launch.
- [ ] Complete compiler/toolchain provenance or adopt and document a reviewed
  compiler-mismatch policy for certified NVIDIA artifacts.
- [ ] Record the exact OPEMOS.EXE source commit, Core bundle identity, appliance
  identity, input image hash, selected policy, and artifact provenance in the
  output manifest without private host paths.
- [x] Enable a restrictive production CSP and reduce Tauri dialog/opener/global
  capabilities to the minimum required per window. Completed above with exact
  per-window permissions and packaged Linux runtime evidence.
- [ ] Audit licenses and redistribution obligations for bundled QEMU, firmware,
  Fedora components, NVIDIA artifacts, and other third-party material.
- [ ] Sign and notarize the macOS application, publish checksums and release
  notes, and test clean install plus upgrade on a non-development Mac.

## Focused quality work

### Application and UI

- [ ] Model the main workflow as an explicit state machine rather than scattered
  DOM state; test every allowed transition and reject impossible ones.
  - [x] Centralize build admission as the first bounded state-machine slice.
    A pure snapshot reducer names empty, selected, building, complete, and
    USB-writing phases; derives every build blocker; accepts all three output
    modes and acknowledged upstream intent; and rejects malformed snapshots,
    concurrent build/write activity, and build-after-completion. The main
    renderer now consumes this single result instead of repeating admission
    predicates. On 2026-09-04, the focused 17-case workflow/layout suite and
    all 119 frontend tests plus documentation, hygiene, and boundary integrity
    pass.
  - [x] Route the build-click event boundary through that same admission
    snapshot, eliminating a second predicate list that could drift from the
    rendered disabled state. Programmatic starts now reject missing inputs,
    unavailable hosts, absent outputs, unacknowledged upstream intent, completed
    outputs, active USB writes, and impossible concurrent activity through the
    same fail-closed reducer. On 2026-09-04, the focused 18-case workflow/layout
    suite and all 120 frontend tests plus documentation, hygiene, and boundary
    integrity pass.
  - [x] Route image-selection admission through the same reducer. Empty,
    selected, and completed phases can select or replace an image; active build
    and USB-write phases return their exact blocker, and impossible concurrent
    mutation still throws before UI state is cleared. On 2026-09-05, the focused
    19-case workflow/layout suite and all 121 frontend tests plus documentation,
    hygiene, and boundary integrity pass.
  - [x] Centralize USB-write admission without changing its destructive
    confirmation or native revalidation. The event boundary now requires the
    completed-image phase and a live preflight capability; missing, malformed,
    stale-phase, build-active, and already-writing inputs fail closed before the
    confirmation dialog. On 2026-09-05, the focused 20-case workflow/layout
    suite and all 122 frontend tests plus documentation, hygiene, and boundary
    integrity pass.
  - [x] Route output-folder selection through the reducer. Only the selected,
    non-mutating phase may preview or adopt a destination; empty, completed,
    building, USB-writing, malformed, and impossible concurrent states return
    stable blockers before any native preview call. On 2026-09-05, the focused
    21-case workflow/layout suite and all 123 frontend tests plus documentation,
    hygiene, and boundary integrity pass.
  - [x] Centralize USB preflight admission and require the typed destructive
    confirmation at the event boundary as well as in native validation. Only a
    completed image with no pending arm, an exact target identity, and matching
    ERASE-device text can invoke preflight; malformed capability shapes and all
    partial combinations fail closed. Native revalidation remains unchanged.
    On 2026-09-05, the focused 22-case workflow/layout suite and all 124
    frontend tests plus documentation, hygiene, and boundary integrity pass.
    The broader workflow transition model remains open.
  - [x] Route USB preflight cancellation through the reducer. Cancellation now
    requires the completed-image phase, one live session, and no cancellation
    already pending; missing and malformed capabilities or stale workflow phases
    fail closed before native cancellation while existing operation-context race
    checks remain authoritative. On 2026-09-05, the focused 23-case
    workflow/layout suite and all 125 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Route USB target selection through the reducer. Target changes now
    require a stable selected-image or completed-image phase; empty, building,
    USB-writing, malformed, and impossible concurrent states fail closed before
    clearing a live preflight session or changing target context. Native target
    identity inspection and destructive confirmation remain unchanged. On
    2026-09-05, the focused 24-case workflow/layout suite and all 126 frontend
    tests plus documentation, hygiene, and boundary integrity pass. The broader
    workflow transition model remains open.
  - [x] Route USB target clearing through the reducer before DOM mutation. Clear
    requests now require a selected target and a stable selected-image or
    completed-image phase; missing targets, malformed capabilities, active
    builds, USB writes, and impossible concurrent states fail closed without
    discarding the visible selection or live preflight context. Native target
    inspection and destructive confirmation remain unchanged. On 2026-09-05,
    the focused 25-case workflow/layout suite and all 127 frontend tests plus
    documentation, hygiene, and boundary integrity pass. The broader workflow
    transition model remains open.
  - [x] Route USB review opening through the reducer. Review now requires the
    completed-image phase and a selected target; selected-only, empty, building,
    USB-writing, missing-target, malformed, and impossible concurrent states
    fail closed before the destructive-review dialog opens. Native preflight,
    identity revalidation, and final confirmation remain unchanged. On
    2026-09-05, the focused 26-case workflow/layout suite and all 128 frontend
    tests plus documentation, hygiene, and boundary integrity pass. The broader
    workflow transition model remains open.
  - [x] Route USB review dismissal through the reducer. Dismissal remains
    available through empty, selected, completed, and asynchronous build-refresh
    phases, but fails closed once destructive USB writing starts or workflow
    mutation becomes impossible. Session cancellation and generation invalidation
    behavior remain unchanged. On 2026-09-05, the focused 27-case
    workflow/layout suite and all 129 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Route image export-mode changes through the reducer. The checkbox stays
    editable in empty and selected phases; completed, building, USB-writing, and
    impossible concurrent states reject synthetic mutations and restore the
    authoritative completed or active-build destination before rerendering. USB
    target selection remains independently gated. On 2026-09-05, the focused
    28-case workflow/layout suite and all 130 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Route destructive USB confirmation editing through the reducer. Text
    entry now requires an idle completed-image phase, selected target, no pending
    preflight, and no live session; rejected synthetic edits are cleared and
    cannot enable preflight. Missing and malformed capabilities, active writes,
    and impossible concurrent states fail closed. On 2026-09-05, the focused
    29-case workflow/layout suite and all 131 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Apply image-selection admission before opening the native picker.
    Programmatic picker clicks now reject building, USB-writing, malformed, and
    impossible concurrent states before native UI appears; the existing inner
    reducer guard remains authoritative for drag/drop, delayed picker results,
    and selection replacement. On 2026-09-05, the focused 29-case
    workflow/layout suite and all 131 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Apply output-directory admission before opening the native folder
    picker. Programmatic clicks now reject empty, completed, building,
    USB-writing, malformed, and impossible concurrent states before native UI
    appears; the existing inner reducer guard remains authoritative for delayed
    picker results and explicit destination reset. On 2026-09-05, the focused
    29-case workflow/layout suite and all 131 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Route manual USB target refresh through the reducer. User-triggered
    refresh now requires a stable selected-image or completed-image phase; empty,
    building, USB-writing, malformed, and impossible concurrent states fail
    closed before session cancellation or native disk inspection. The internal
    build-completion refresh remains separately protected by exact operation and
    target identity checks. On 2026-09-05, the focused 30-case workflow/layout
    suite and all 132 frontend tests plus documentation, hygiene, and boundary
    integrity pass. The broader workflow transition model remains open.
  - [x] Apply output-directory admission before explicit destination reset.
    Rejected synthetic reset clicks now leave the output-selection revision and
    current destination untouched in empty, completed, building, USB-writing,
    malformed, and impossible concurrent states; the existing inner guard still
    protects delayed calls. On 2026-09-05, the focused 30-case workflow/layout
    suite and all 132 frontend tests plus documentation, hygiene, and boundary
    integrity pass. The broader workflow transition model remains open.
  - [x] Apply image-selection admission to drag-over and drop events. Invalid
    building, USB-writing, malformed, and impossible states no longer advertise
    an active drop target or enter selection; non-over events still clear stale
    highlighting, and the inner selection guard continues to protect delayed
    work. On 2026-09-05, the focused 30-case workflow/layout suite and all 132
    frontend tests plus documentation, hygiene, and boundary integrity pass. The
    broader workflow transition model remains open.
  - [x] Bind NVIDIA source selection and upstream approval into the accepted
    build context before asynchronous preview/window setup. Build requests now
    emit only those immutable values, source controls stay locked through the
    active build, and both failure and completion restore them. Late DOM changes
    can no longer alter an admitted request. On 2026-09-05, the focused 30-case
    workflow/layout suite and all 132 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Bind the selected input path/name, output mode, and output directory to
    the accepted build context before asynchronous preview and window setup.
    Preview and build dispatch now use only that immutable request snapshot, so
    delayed UI or internal state changes cannot redirect an admitted build to a
    different source or destination. On 2026-09-05, the focused 30-case
    workflow/layout suite and all 132 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Restore build controls from the actual asynchronous terminal phase.
    Failed build completions now re-enable source and output configuration,
    while verified completed outputs keep those immutable controls locked and
    still allow selecting a different image. On 2026-09-05, the focused 30-case
    workflow/layout suite and all 132 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Route NVIDIA source intent and explicit upstream approval changes
    through the reducer. Empty and selected-image phases accept changes;
    completed, building, USB-writing, malformed, and impossible states restore
    the last accepted source and approval instead of honoring synthetic events.
    Source controls also remain locked when a delayed branch refresh ends in a
    non-editable phase. On 2026-09-05, the focused 31-case workflow/layout suite
    and all 133 frontend tests plus documentation, hygiene, and boundary
    integrity pass. The broader workflow transition model remains open.
  - [x] Make NVIDIA branch-list refresh transactional. Results now replace the
    source options only when they belong to the latest positive-safe-integer
    request generation and the workflow is still empty or selected; stale,
    completed, building, USB-writing, malformed, and impossible states preserve
    the accepted options and source intent. On 2026-09-05, the focused 32-case
    workflow/layout suite and all 134 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Guard NVIDIA branch refresh before native IPC and gate late errors with
    the same transactional admission. Requests that begin in completed,
    building, USB-writing, malformed, or impossible states do no work, and a
    request that becomes stale or non-editable cannot overwrite the current
    workflow message with an obsolete fetch failure. On 2026-09-05, the focused
    32-case workflow/layout suite and all 134 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Reject impossible completed-output relationships in the reducer. A
    completed output now requires its selected source image, and USB-writing
    state requires that completed output; all ordinary USB-writing fixtures
    model the retained completed image explicitly. On 2026-09-05, the focused
    32-case workflow/layout suite passes after correcting the newly exposed
    invalid fixture, and all 134 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Reject detached upstream-approval state. The reducer now requires an
    upstream source whenever explicit upstream approval is set; switching back
    to a trusted source validates a normalized proposed snapshot before clearing
    approval, while synthetic approval events on trusted sources restore the
    safe unchecked state. On 2026-09-05, the focused 32-case workflow/layout
    suite and all 134 frontend tests plus documentation, hygiene, and boundary
    integrity pass. The broader workflow transition model remains open.
  - [x] Reject active-build state without its selected source image. Build
    admission binds the image before entering mutation and image replacement is
    already blocked throughout that phase, so a missing image now fails closed
    instead of being classified as an ordinary build. On 2026-09-05, the focused
    32-case workflow/layout suite and all 134 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Reject completed-output state without a retained output mode. Imported
    and newly built completions both select image retention before rendering the
    completed phase, so a null output mode now fails closed instead of presenting
    an internally contradictory completion. On 2026-09-05, the focused 32-case
    workflow/layout suite and all 134 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Reject USB-writing state without a USB-bearing output mode. Destructive
    writing now requires `usb` or `both`, and all ordinary writing fixtures model
    the retained completed image plus selected USB destination explicitly. On
    2026-09-05, the focused 32-case workflow/layout suite passes after correcting
    the newly exposed invalid fixtures; all 134 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Reject active-build state without its admitted output mode. Build
    admission requires a non-null output destination before mutation and output
    controls remain locked for that phase, so losing the mode now fails closed.
    On 2026-09-05, the focused 32-case workflow/layout suite and all 134 frontend
    tests plus documentation, hygiene, and boundary integrity pass. The broader
    workflow transition model remains open.
  - [x] Reject active upstream builds without retained explicit approval.
    Upstream admission requires consent before mutation and source controls stay
    locked throughout the build, so a missing approval now fails closed instead
    of becoming an ordinary active-build snapshot. On 2026-09-05, the focused
    32-case workflow/layout suite and all 134 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Reject empty workflows with a USB-bearing output mode. USB target
    selection requires a selected image, and image replacement clears the target
    before its temporary empty phase, so `usb` and `both` now fail closed without
    an image. On 2026-09-05, the focused 32-case workflow/layout suite and all 134
    frontend tests plus documentation, hygiene, and boundary integrity pass. The
    broader workflow transition model remains open.
  - [x] Route terminal build completion through reducer phase admission. A
    completion may now mutate workflow state only while the reducer still names
    an active build; empty, selected, completed, USB-writing, malformed, and
    impossible concurrent snapshots fail closed before completion rendering.
    Exact request identity, selected-image generation, output inspection, and
    later operation-context checks remain authoritative. On 2026-09-05, the
    focused 33-case workflow/layout suite and all 135 frontend tests plus
    documentation, hygiene, and boundary integrity pass. The broader workflow
    transition model remains open.
  - [x] Route USB write progress through reducer admission. Progress renders
    only during the destructive write phase and only for the bounded native
    phase vocabulary, positive safe total, in-range monotonic byte counts,
    stable total, forward phase movement, and a bounded nonempty message.
    Verification may reset its phase-local byte count, while stale, malformed,
    backward, and regressing events leave the visible status untouched. On
    2026-09-05, the focused 34-case workflow/layout suite and all 136 frontend
    tests plus documentation, hygiene, and boundary integrity pass. Physical
    removable-media validation remains a separate release gate, and the broader
    workflow transition model remains open.
  - [x] Validate USB write completion before rendering verified success. The
    admitted preflight session now binds the image, session, whole-device
    identifier, and raw device node before native IPC. A resolved result must
    retain that exact device identity, report a positive safe byte count,
    `verified` status, matching hexadecimal image/readback SHA-256 values, a
    boolean eject outcome, and a bounded nonempty message. Malformed, mismatched,
    stale-phase, or false-success results enter the existing safe error UI. On
    2026-09-05, the focused 35-case workflow/layout suite and all 137 frontend
    tests plus documentation, hygiene, and boundary integrity pass. Physical
    removable-media validation remains a separate release gate, and the broader
    workflow transition model remains open.
  - [x] Bind USB completion verification to the preflight image digest and
    distinguish automatic-eject failure. A terminal result whose internally
    matching hashes differ from the preflight-authenticated image now fails
    closed. A byte-verified result with `ejected: false` remains an accepted
    completed write, preserves the native manual-eject instruction, and uses
    error attention styling rather than presenting an entirely successful
    finish. On 2026-09-05, the focused 36-case workflow/layout suite and all 138
    frontend tests plus documentation, hygiene, and boundary integrity pass.
    Physical removable-media validation remains a separate release gate, and
    the broader workflow transition model remains open.
  - [x] Require the complete admitted USB write context at terminal result
    validation. Empty, oversized, missing, or malformed session tokens, image
    paths, whole-device identifiers, raw device nodes, and preflight image
    digests now fail closed even when a result otherwise appears verified. The
    renderer already dispatches and validates against the same immutable context.
    On 2026-09-05, all 36 focused workflow/layout tests, including the new context
    boundary cases, and all 138 frontend tests plus documentation, hygiene, and
    boundary integrity pass. Physical removable-media validation remains a
    separate release gate, and the broader workflow transition model remains
    open.
- [ ] Split oversized frontend workflow/log rendering code only where behavior
  can be covered by focused tests.
  - [x] Extract the pure USB write start, progress, and completion reducer
    slice from the general workflow module. The new module retains the same
    snapshot authority and keeps UI orchestration in the main window while
    isolating its bounded phase vocabulary, context/result validation, and
    monotonic progress rules. A new regression rejects malformed retained
    progress history as well as malformed incoming events. On 2026-09-05, the
    focused 37-case workflow/layout suite and all 139 frontend tests plus
    documentation, hygiene, and boundary integrity pass. Further splitting
    remains limited to behavior with equivalent focused coverage.
  - [x] Extract the pure USB target, review, confirmation, and preflight
    admission slice from the general workflow module. The dedicated module
    continues to consume the same authoritative phase reducer while keeping
    destructive-review capability checks separate from unrelated build/source
    transitions. A new combined-invalid-input regression proves blocker
    precedence remains preflight pending, target identity, identity token, then
    exact destructive confirmation. On 2026-09-05, the focused 38-case
    workflow/layout suite and all 140 frontend tests plus documentation, hygiene,
    and boundary integrity pass. Further splitting remains limited to behavior
    with equivalent focused coverage.
  - [x] Extract build-source selection and asynchronous branch-refresh admission
    from the general workflow reducer. The dedicated module still derives its phase
    from the authoritative workflow snapshot, accepts changes only in empty/selected
    phases, and rejects stale refresh generations before they can update the source
    menu. A new combined stale-and-building regression preserves the stronger active-
    mutation blocker, and static wiring requires the separate reducer import. On
    2026-09-05, the focused 38-case workflow/layout suite and all 140 frontend tests
    plus documentation, hygiene, and boundary integrity pass. Further splitting
    remains limited to behavior with equivalent focused coverage.
  - [x] Extract image export-mode and output-directory admission from the general
    workflow reducer. The dedicated output-state module still derives every phase
    from the authoritative workflow snapshot; directory changes remain limited to
    selected images, while export-mode changes remain limited to empty or selected
    phases. A combined completed-output and unavailable-host regression proves the
    completed phase remains authoritative and cannot reopen output controls. On
    2026-09-05, the focused 38-case workflow/layout suite and all 140 frontend tests
    plus documentation, hygiene, and boundary integrity pass. Further splitting
    remains limited to behavior with equivalent focused coverage.
  - [x] Extract build-start and terminal-completion admission from the general
    workflow reducer. The dedicated lifecycle module still derives its decision
    from the authoritative snapshot: starts require every readiness input, while
    completion remains admitted for an already-running build even if host readiness
    drops afterward, allowing bounded terminal cleanup and result handling. Static
    wiring requires the separate lifecycle import. On 2026-09-05, the focused
    38-case workflow/layout suite and all 140 frontend tests plus documentation,
    hygiene, and boundary integrity pass. Further splitting remains limited to
    behavior with equivalent focused coverage.
- [x] Add a user-selectable image output folder and safe non-overwriting name.
  The main workflow now uses a native directory chooser, supports an explicit
  return to the source folder, invalidates stale chooser results when image
  selection changes, and disables destination changes during builds or for
  completed images. Preview, host-space admission, appliance session state, and
  final export share the same canonical directory. Existing create-only image
  and adjacent-manifest collision scanning remains authoritative, including
  manifest-only reservations and versioned NVIDIA names. Missing paths and
  regular files are rejected as output directories. On 2026-09-04, the focused
  13-case layout suite and Rust collision/directory test pass; formatting and
  warnings-as-errors Clippy pass; all 113 frontend tests plus documentation,
  hygiene, and boundary integrity pass. The complete Rust suite reached 330
  passes with 27 ignored before one unrelated live sibling Core
  installer-result fixture conformance case failed while Core was busy changing
  its local fixtures; that unchanged external failure was not retried or treated
  as EXE feature validation.
- [x] Keep advanced diagnostics accessible without exposing them by default.
  Build logs now start behind an explicit keyboard-accessible disclosure with
  synchronized `aria-expanded`, panel visibility, and expanded layout state.
  Copy-diagnostic and live-follow controls remain inside the revealed panel;
  every new build collapses stale diagnostic output again. On 2026-09-04, the
  focused 11-case diagnostics suite and all 112 frontend tests plus
  documentation, hygiene, and boundary integrity pass.
- [x] Add a narrow-effective-width/high-zoom reflow contract for the main
  workflow. At 760 CSS pixels or below in either dimension, the shell becomes
  vertically scrollable, two-column readiness/build/download layouts collapse
  to one column, output actions wrap, and long source/output paths wrap at any
  character inside bounded scroll regions instead of forcing horizontal
  clipping. On 2026-09-04, the focused 14-case layout suite and all 114
  frontend tests plus documentation, hygiene, and boundary integrity pass.
  This is structural coverage; pixel rendering, translated-string fixtures, and
  real display scaling remain in the broader graphical gate.
- [x] Extend the narrow-effective-width/high-zoom reflow contract to the build
  progress and compatibility-management windows. At 760 CSS pixels or below in
  either dimension, fixed desktop minimums no longer force clipping; progress
  content can scroll, status/actions wrap, expanded diagnostics retain a usable
  viewport, compatibility grids collapse to one column, and long identities,
  paths, and patch previews wrap within their cards. On 2026-09-04, the focused
  build-diagnostics and maintainer-layout regressions pass; all 116 frontend
  tests plus documentation, hygiene, and boundary integrity pass. Real pixel
  rendering, translated-string fixtures, and display scaling remain in the
  broader gate.
- [ ] Test compact and expanded layouts, long localized text, zoom, reduced
  motion, high contrast, keyboard-only use, and display scaling.
  - [x] Keep the shared main/maintainer compatibility inspector inside the
    viewport when long localized headings, notices, labels, actions, and field
    names meet high zoom. Text-bearing controls now permit character-level wrap
    without intrinsic-width overflow; at 480 effective pixels in either
    dimension the dialog uses an eight-pixel viewport inset, reduced padding,
    bounded scrolling, and a shorter editable input. On 2026-09-05, the focused
    17-case compatibility suite, all 148 frontend tests, documentation, hygiene,
    and boundary integrity pass. Pixel rendering, delivered translations,
    keyboard-only traversal, and real display scaling remain open.
  - [x] Make compatibility-inspector modal focus deterministic for keyboard use.
    Opening either shared inspector focuses its close control, while every close
    path, including native Escape dismissal, clears private input/result state and
    restores focus to the invoking button. On 2026-09-05, all 17 focused
    compatibility-preview tests pass. Full keyboard traversal and real display
    scaling remain open.
  - [x] Bind both shared compatibility-inspector pages to reduced-motion and
    forced-color coverage. The focused regression requires each page to load the
    shared control and inspector styles, suppresses inherited motion, preserves
    system-adjusted controls and Highlight focus outlines, and keeps the dialog
    boundary visible with CanvasText. On 2026-09-05, all 18 focused compatibility-
    preview tests pass. Real OS high-contrast rendering remains open.
  - [x] Make the experimental Linux launcher and packaged GUI smoke select the
    capture-compatible WebKitGTK renderer. On Ubuntu 24.04.4 GNOME Wayland with
    NVIDIA graphics, the unguarded debug package exposed the complete expected
    AT-SPI document while its foregrounded web surface remained blank after a
    three-second repaint delay. With `WEBKIT_DISABLE_DMABUF_RENDERER=1`, the same
    bounded smoke rendered the full unavailable-host interface in a non-black
    1280x720 RGB capture (SHA-256
    `68666c08125e3b3b94d75aedadc123ceabad0a065b4aaaaca0bb667ff716635e`),
    stopped its process group, left no new QEMU process, and released the in-memory
    capture lease to zero viewers. Focused launcher and harness tests cover absent,
    empty, conflicting, and unexpected inherited values without mutating caller
    environments. On Ubuntu 24.04.4 GNOME Wayland, the debug-only idle
    build-progress companion then passed an OPEMOS-window-only, memory-only pixel
    validation: the 541x599 main crop had RGB variances 805.4/733.2/740.3 and
    extrema 0..255/1..255/0..255; the 488x519 progress crop had variances
    947.7/842.9/864.9 with the same extrema. The frame and both crops were
    discarded immediately after assertions, the short-lived viewer lease returned
    to zero, the application process group stopped, and no new QEMU remained.
    An isolated per-process Ubuntu GNOME Wayland matrix also rendered main and
    progress surfaces under `GTK_THEME=HighContrast` at `GDK_SCALE=1` /
    `GDK_DPI_SCALE=1` and `GDK_SCALE=2` / `GDK_DPI_SCALE=0.5`; both combinations
    produced distinct non-flat RGB rasters from the default baseline while
    preserving usable 541x599 and 488x519 frame bounds. The authenticated
    maintainer surface rendered at 634x546 under HighContrast with RGB variances
    2754.3/2915.4/3206.7. Every case discarded frame/crop bytes in memory,
    released its viewer lease, stopped its process group, and left no new QEMU.
    A shared bounded page-zoom adapter now gives main, progress, and maintainer
    webviews standard primary-modifier `+`, `-`, and `0` controls from 80% through
    200%, with per-window state and polite accessibility announcements. Focused
    tests cover both platform modifiers, editable-field compatibility, malformed
    modifier/repeat/composition rejection, intermediate-value recovery, limits,
    reset, and exact installation in all three entry points. On Ubuntu GNOME
    Wayland, the main-window control grew from 148x41 to 163x45 after one delivered
    zoom step; the viewer lease returned to zero, the process group stopped, and
    no new QEMU remained. Automated portal focus could not be transferred to the
    separately foregrounded companion windows, so their live shortcut geometry
    remains unclaimed despite sharing the tested adapter. All 154 frontend cases
    pass; two headless-harness cases initially lacked `node` in the escalated child
    `PATH` and passed when rerun with the installed Node directory. Documentation,
    hygiene, and boundary integrity pass. Delivered translations, browser/OS
    forced-colors behavior, and real monitor scaling remain open.
  - [x] Exercise application forced-colors CSS in a real browser. Google Chrome
    152.0.7977.82, under the shared resource wrapper, used fresh disposable
    headless profiles and a synthetic document containing the actual main,
    build-progress, maintainer, shared-control, and compatibility CSS. Normal
    mode reported inactive; forced high contrast reported active and preserved
    exact body/card, control/status, focus, disabled, checkbox, and dialog
    computed-style invariants. Three parser/state edge tests reject absent,
    repeated, malformed, scalar, inactive, hidden-focus, faded-disabled,
    shadowed, borderless, and mismatched-dialog results. No screenshot, desktop
    capture, app launch, or network input occurred. The live browser check stays
    local because GitHub runners cannot use the mandated host `heavy.sh`
    wrapper; remote frontend CI covers the regression tests.
  - [x] Deliver a bounded local compatibility-interface catalog with `en-US` as
    source/fallback and initial `de-DE`, `ja-JP`, and `ar` translations. Settings
    follows the first supported system locale or a persisted explicit choice;
    already-open windows observe explicit changes. Arabic sets RTL page direction,
    resolver JSON remains LTR, and verbatim Core values use automatic bidi
    isolation. Catalog admission rejects missing, extra, empty, non-string, and
    markup-bearing entries; unsupported locales and keys fall back safely without
    a network translation service. Focused locale, compatibility, and layout tests
    pass 43/43, and all 160 frontend tests pass under the serialized heavy wrapper.
    Documentation and repository integrity validation are recorded with the PR.
  - [x] Extend the packaged Ubuntu AT-SPI smoke over the delivered locale selector
    and capture translated compatibility surfaces. The smoke now requires the exact
    System default, English, German, Japanese, and Arabic plain-text options, rejects
    missing, duplicate, or unexpected-role options, and keeps the existing complete
    English compatibility flow. On Ubuntu 24.04.4 GNOME Wayland, explicit choices
    rendered OPEMOS-only inspector crops for `de-DE` at 453x481 (RGB variance
    423.1/334.9/290.1), `ja-JP` at 453x440 (441.7/348.3/298.0), and RTL `ar` at
    453x473 (432.1/491.8/500.6); all were non-flat with broad channel extrema.
    Frame and crop bytes were discarded in memory, the exact test lease was
    released, application processes stopped, and no new QEMU remained. An explicit
    desktop-only smoke option now synthesizes a bounded seven-Tab keyboard cycle from
    the initially focused Close control through every declared inspector control and
    back to Close; every step requires the expected control to be the only focused
    control, so skipped, reordered, duplicate/stale, non-wrapping, or refused focus
    transitions fail. Two disposable Debian Xvfb runs proved that neither symbolic nor
    hardware AT-SPI Tab synthesis reaches the webview without an active desktop input
    route, so headless CI retains exact structural focus-order checks without claiming
    live keyboard traversal. Thirty-four focused smoke-harness cases pass locally;
    real-desktop execution and PR evidence remain pending on this branch.
- [x] Keep unknown Core phases indeterminate; never infer percentages from
  heartbeats or free-form log text. Unknown structured phases now retain only
  their bounded label and current validation/installation context: even a
  syntactically determinate future record exposes no inherited overall progress,
  completed/total values, unit, or step fraction. The focused progress parser
  regression covers unknown phases before and after known determinate progress;
  existing strict parsing continues to reject malformed, regressing, oversized,
  and contradictory records. On 2026-09-04, the focused 11-case diagnostics
  suite and all 112 frontend tests plus documentation, hygiene, and boundary
  integrity pass.

### Host and appliance

- [x] Verify host bytes and finite inode capacity before normalization,
  overlays, package and handoff staging, export, and retained-image-plus-USB
  workflows. Measure compressed output through a cancellable bounded pass,
  aggregate shared APFS allocation pools conservatively, recheck before later
  phases, and preserve a stable no-space/quota reason on write failures.
- [ ] Detect corrupt cached appliances and recover only through an authenticated
  replacement.
  - [x] The Linux Fedora builder now authenticates the signed checksum before
    trusting cached image bytes. A corrupt cache entry is replaced only after a
    temporary download matches that authenticated SHA-256; download or hash
    failure removes only the temporary file and preserves the prior cache. Five
    focused builder tests cover valid resolution, malformed options, mandatory
    signatures, successful corrupt-cache replacement, and failed-replacement
    preservation. Packaged/native appliance cache recovery remains open.
- [ ] Move large generated guest scripts into versioned templates when doing so
  improves reviewability without weakening fixed-operation boundaries.
- [ ] Measure decompression, transfer, VM boot, mutation, export, and USB speed;
  optimize only after correctness measurements identify the bottleneck.
- [ ] Test Apple Silicon and Intel macOS separately. A nested VM is useful for
  compatibility testing but is not a substitute for final hardware validation.

### USB safety

- [ ] Complete the authorized contained virtual-USB lifecycle. The host boundary now creates only an exact 32 GiB sparse regular file beneath the ignored `tests/virtual-usb/work/` root, refuses symlinks, path drift, wrong sizes, and stale creation, preserves source identity across write and SHA-256 read-back, and resets only exact harness-owned files. The remaining live phase must consume a real authenticated NVIDIA-built image, retain the verified medium through install and reinstall into disposable targets, and prove both boots before completion. The PR #90 partial construction run archived session-1789301815477-2687651.log after the authenticated Fedora appliance reached cloud-init-local but missed the exact 600-second harness deadline; cleanup left no QEMU and no retained output. The user authorized one changed-code retry with an exact harness-only 900-second readiness deadline while preserving the 120-second production default, absolute late-ready refusal, and a 60-second outer cleanup margin. That retry passed readiness and reached recovery-image inspection, then exhausted the existing absolute 60-second exit-255-only SSH retry with a banner-exchange timeout. Cleanup archived session-1789310020147-2757553.log, left no QEMU, and retained output remained empty; the unchanged run must not repeat. Resolver authorized a changed-code harness-only retry that extends only the pre-mutation read-only inspection exit-255 retry to an absolute 180 seconds; marker preflight and mutation remain at 60 seconds, and production behavior remains unchanged. The authorized retry then varied earlier: cloud-init completed near guest second 886, but the ready marker did not arrive before the exact 900-second host deadline. Cleanup archived session-1789311898343-2782891.log, left no QEMU, and retained output remained empty; no unchanged retry is permitted. Resolver authorized one changed-code retry with an exact 1200-second Fedora TCG readiness deadline and 1260-second outer guard, preserving every other timeout and safety boundary. That run passed readiness but the pre-mutation read-only inspection exhausted its exact 180-second exit-255 retry with a banner-exchange timeout. Cleanup archived session-1789313516340-2811732.log, left no QEMU, and retained output remained empty; no unchanged retry is permitted. Resolver then authorized a different bounded inspection strategy: one exact 30-second post-readiness quiescence followed by serial exit-255-only inspection attempts at fixed five-second intervals within the existing absolute 180-second retry window. Commit `ea2d7f0bd79eeb8c66542dcb34624cc2d76bfe90` implements that harness-only behavior; focused timing, semantic-refusal, expiry, and existing transport-boundary tests pass through `heavy.sh`. The one authorized partial did not reach the changed inspection path: cloud-init-network completed near guest minute 12:34, but cloud-config remained active and the appliance missed the exact 1200-second readiness deadline. Cleanup archived `session-1789315888820-2861942.log`, left no QEMU, and retained output remained empty; no unchanged retry is permitted. Core rejected initial PR #65 head `316edfc5ca17522df944bd4f28623d591ca3b1ce`: it accepted outside-root regular sources and did not reject a pre-existing predictable state-temp symlink. The remediation requires a canonical root descendant, preserves rejected outside inputs, rejects the temp symlink before a noclobber create, and passes eight focused heavy-wrapper tests. Source PR [#65](https://github.com/CorniiDog/OPEMOS.EXE/pull/65) preserves commits `316edfc5ca17522df944bd4f28623d591ca3b1ce` and `d0e82b93a8e0fa4503bfcb178770fae6542cee1a`; after exact corrected-head Core approval and nine passing non-deploy checks, protected main squash-merged it as `7cad351b552f3e7c3e482be34ac3ba9e4325d6b3`. The ignored headless live runner reuses the production authenticated resolution/build, signed-userspace, pinned-installer, validation, install, export, and completed-image inspection commands; it refuses linked recovery inputs and any output path outside the exact ignored harness root, then retains the image and manifest for the later virtual-media stages. Two path-boundary tests and the concrete-runtime smoke pass through `heavy.sh`; the full live run remains pending merge and an empty retained-output root. Source PR [#67](https://github.com/CorniiDog/OPEMOS.EXE/pull/67) preserves initial commit `295fcd53ffb5ef51ea51f7f1b7f3c11617e3564b`, the first Windows runtime-entry-point check failure, Linux-only remediation `3520d657ae9329656d954c5d1621c17803f117c8`, repeated focused `heavy.sh` validation, exact Core approval, all nine passing checks, and protected-main squash `b1c05574b54b74de403e6e42598404ffdbd3bcb9`. A contained one-vCPU TCG run then proved UEFI had selected the bootable SteamOS attachment instead of Fedora; the explicit Fedora `bootindex=1` remediation boots Fedora and reaches root-device discovery and switch-root, but the unchanged 120-second host handshake expires before userspace readiness. The lifecycle remains blocked pending explicit host-handshake authority; no deadline was changed or bypassed. Source PR [#69](https://github.com/CorniiDog/OPEMOS.EXE/pull/69) preserves source commit `8cfc58380cdba4f26bc81b1ff73ff0b45acf22cc`, the corrected immutable-identity Core approval, the exact three-file scope, all nine passing non-deploy checks, and protected-main squash `b2e80d14194aea9db2505c33d965cedb0eced37c`. The separately authorized host-readiness work preserves the 120-second production default and permits exactly one absolute, non-resetting 600-second deadline only through the Linux TCG test harness; malformed values fail before preparation, expiry wins over a late ready marker, and a panic-safe guard cleans the owned appliance runtime. Focused deadline and harness tests pass through `heavy.sh`. A captured live run also found the harness outer guard was only 360 seconds and left its failed runtime; the corrected 660-second outer guard and panic cleanup are committed. Its preserved QEMU log proves the native Fedora inspection appliance enters emergency mode when its root/EFI device units time out around 190 seconds. The previously approved 300-second guest-device override is wired only to the separate NVIDIA build appliance, so completing this lifecycle now requires explicit authority to apply that same exact TCG-only guest-device override to the native inspection appliance; it has not been broadened. Source PR [#71](https://github.com/CorniiDog/OPEMOS.EXE/pull/71) preserves commits `33887a1`, `3c98e84`, and `861e472bd0c4e004a3c3aabc0e31e7d5f5fb3ed1`; after exact unchanged-head Core approval and all nine passing non-deploy checks, protected main squash-merged it as `f1bd8bcc7dbe0e3fdee360437b74cd7aec24561f`. The delegated native-inspection approval is implemented by composing the existing exact 300-second TCG-only root/EFI QEMU credentials into the native Fedora appliance arguments; KVM receives the prior byte-for-byte root arguments. Focused tests verify exact pinned units and credential bytes, comma-safe paths, timeout bounds, missing/wrong/extra guest-report refusal, the absolute 600-second readiness deadline, 660-second harness guard, cancellation, and owned-runtime cleanup. The authenticated Fedora appliance cache reverified SHA-256 `28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f` and clean qcow2 structure before the live lifecycle rerun. That run reached cloud-init readiness at 376.7 seconds, proving the guest timeout remediation, but abrupt harness parent-group termination killed the lifecycle watchdog before it could stop QEMU. The watchdog now runs in its own process group so keepalive closure survives parent-group death and stops only its exact QEMU group; native session shutdown first requests bounded private-QMP `quit`, then retains the existing SSH and force-kill fallbacks. Focused protocol and parent-exit regressions prove the exact QMP handshake/command and no surviving target. A durable captured rerun then reached readiness at 438.96 seconds, completed read-only image inspection and working-overlay verification, and failed before source detachment or mutation when the next SSH preflight timed out during banner exchange. The ignored TCG lifecycle now retries only exit-255 transport failures for that fixed-content marker operation under a new absolute 60-second bound; non-transport failures and expiry remain immediate errors. A changed-code captured rerun passed the transport retry but failed closed with guest exit status 1 in the same preflight; cleanup removed all owned runtime/process state, retained output stayed empty, and the authenticated appliance remained at SHA-256 `28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f`. Because the five existing shell assertions supplied no stderr, each now retains its refusal while naming the exact unavailable-device, access-mode, or mounted-state condition for the next diagnostic run. The diagnostic run failed earlier during initial read-only inspection with the same exit-255 SSH banner timeout and again left no QEMU, test process, or retained output. The existing exit-255-only helper now also bounds that inspection to one absolute 60-second retry window; semantic inspection failures remain immediate. The next run passed that retry and identified the marker preflight failure precisely: the read-only source by-id device was temporarily unavailable even though no detach had yet been requested. Only that exact pre-mutation disappearance joins exit-255 transport errors under the existing absolute 60-second bound; working-device, access-mode, mount-state, semantic, and post-detach failures remain immediate. The exhausted retry proved the apparent disappearance was the second invocation after a first attempt had already passed preflight, detached the source via QMP, and then lost SSH during mutation. The harness now retries only the separately exposed preflight before detachment and invokes the detach/mutation phase exactly once; a focused regression forces a post-detach exit-255 error and proves neither phase repeats. Run 6 confirmed that boundary and then failed on the single new SSH banner exchange after successful preflight and source detach. The mutation SSH process is now established once before QMP removal; its existing script waits for source disappearance before touching the overlay, and a failed detach terminates and reaps the waiting process. No mutation retry or fallback is introduced. Run 7 stopped before mutation because the initial `spawn` refactor inherited stdout and stderr instead of preserving `Command::output` capture semantics, so the READY marker reached the harness log while the parser received an empty value. The prestarted process now uses null stdin and piped stdout/stderr; focused success and failure fixtures prove exact stdout parsing and stderr-first exit diagnostics. Run 8 then proved process creation can precede completion of the SSH banner exchange, so QMP still detached before a usable channel existed. The guest script now emits one exact readiness sentinel on the already-captured channel before waiting for source disappearance; only after the host reads that sentinel does it request QMP removal, and it consumes the remaining mutation report from the same process. Missing/wrong sentinel, command EOF/failure, and detach failure remain bounded refusals without mutation retry. Run 9 passed native inspection and marker mutation, then stopped before NVIDIA build because the recreated ignored worktree lacked the separately named x86_64 appliance; it did not substitute the native path. The repository Linux builder subsequently authenticated Fedora 44 compose 1.7 x86_64 through the signed checksum and pinned keyring, produced `fedora-builder-x86_64.qcow2` with SHA-256 `28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f`, and passed `qemu-img check` while leaving the separately named native appliance intact. Run 10 then passed native inspection, marker mutation, exact NVIDIA resolution and build, signed userspace staging, and pinned installer preparation. It failed closed before installation because the result validator compared the guest result’s intentionally canonical module filenames with the original builder artifact basenames. Cleanup left no QEMU or test process, retained output remained empty, and both authenticated appliances retained SHA-256 `28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f`. The validator now requires the exact `nvidia-modules.tar.gz` and `nvidia-modules.provenance.json` names that the handoff explicitly copies into the guest, while package identities remain derived from the reviewed handoff. A focused regression uses deliberately different host artifact basenames, accepts only those canonical guest identities, and preserves rejection of a different archive name. Run 11 passed that identity gate, then failed closed before installation because the validation object emitted by the pinned Core installer bundle at commit `a1c03c9658c5ed885f094b5f8e0896d818fee785` omitted mandatory `inputSource` and `gamingPayload` verified-input metadata. The captured result otherwise records the exact archive, provenance, userspace packages, target, trust, storage, compression, module hashes, dependency closure, keyring, and userspace lock. EXE must not synthesize or weaken Core-owned machine-readable result evidence. This lifecycle item now depends on a canonical GitHub Core commit whose offline installer emits both required fields for this exact validation-only direct-input/no-gaming-payload invocation, with Core contract tests and immutable commit evidence; EXE will then repin and consume that exact remote commit only after separate authorization for the governance-pin change. PR #73’s first Windows portable check then found two Linux-only test symbols compiled without matching target guards: the outer TCG timeout assertions and live retry helpers. The assertions now compile only on Linux and both live helpers carry the same Linux guard as their callers; the focused readiness test passes through `heavy.sh`. Core rejected exact PR #73 head `671bbf7f39dcf4e121e738a53f278b35920bc805` after green CI because the prestarted mutation channel could deadlock on an undrained stderr pipe and its readiness read had no host deadline. The corrected implementation starts a concurrent complete stderr drain before reading stdout, limits the readiness marker to 64 bytes and 30 seconds, and launches the SSH command in an owned process group so timeout, malformed-marker, and reader failures terminate and reap the shell plus descendants before returning. Focused regressions prove a 1 MiB stderr stream cannot block readiness, a silent descendant is bounded and leaves no child, an excessive marker is refused and reaped, and successful/failing output capture remains intact; both focused tests and all-target Clippy pass through `heavy.sh`. Remote-only CI and exact counterpart rereview required a normal fast-forward push of remediation commit `e0576e2582dca0754c7f204c1f7ee544fee6af47` to `https://github.com/CorniiDog/steamos-nvidia-image-builder.git`, branch `work/exe-native-tcg-device-timeout`, for existing PR #73. The first remote Rust job on head `ff985fdbddc1e1b681ae411042667d0075f5699d` failed only its formatting gate before compilation; the exact `cargo fmt` correction, formatter check, and all-target Clippy pass through `heavy.sh`, while the prior focused results remain unchanged. After Core approved exact corrected head `410d925df9cb8f35256086b1af3c443ed01e7ec3` with all nine checks passing, source PR [#73](https://github.com/CorniiDog/OPEMOS.EXE/pull/73) squash-merged to protected main as `778d5f843d97d1df43726b33c59850d9afc0a459`; the exact merged topic branch was deleted and detailed pre-squash commits remain in the PR record.

- [ ] Exercise the contained file-backed 32 GiB virtual USB on native Windows. The staged Windows-only harness adapter creates only `virtual-usb-32g.raw` directly beneath a canonical caller-owned root with create-new semantics, marks it sparse before setting the exact 34,359,738,368-byte logical length, verifies the sparse attribute and capacity through the open handle, and reuses the existing production copy/flush/readback engine. Cleanup accepts only the exact non-linked 32 GiB regular file and preserves the source. The native test covers exact construction, stale-create refusal, write, flush, readback hash, logical-size preservation, mid-write cancellation, cleanup after success and cancellation, source preservation, and cleanup path drift. Initial native Windows execution passed the construction/write/flush/readback/cleanup path in run 34727881131. Head `dc5f62e27627519284040ec74cd8b59d97ba9d87` added and passed mid-write cancellation in retained Windows run 34728803736 plus all required Checks in 34728803727. A newly available sealed Hyper-V base exposed that these operations were test-only, so the coherent batch now adds a Windows-only `contained-virtual-usb` executable entrypoint that accepts only a caller-owned root and source image, uses the same production copy/flush/readback engine, cleans its exact sparse target on success or failure, rehashes the preserved source, and emits machine-readable non-physical evidence. Fresh exact-head Windows execution, the required imaging `partial`, counterpart review, and merge remain pending. Exact head `a7d747ac6804214a930124207f83ce5bf29f8659` passed required Checks run 34736329649 and Windows build/startup/provenance run 34736329622, producing unsigned executable SHA-256 `5c64425be580636be85e5e3732b8775c0360d1b8adf789fc80345eb57bcb31da`. Focused execution on the sealed-base disposable Windows guest then failed before imaging with status `0xC0000135`; PE imports and guest inspection showed the purported portable artifact depended on absent `VCRUNTIME140.dll` and `VCRUNTIME140_1.dll`. The coherent batch now statically links the MSVC runtime and records that property in checked artifact provenance; changed-head Windows execution and the required imaging `partial` remain pending. Exact static-runtime head `add0be9d42884874535fb1445a420fddae39f750` passed Checks run `34737088844` and Windows run `34737088829`, producing unsigned executable SHA-256 `1dba4fa3ff657fde0dbf6b3fe277640faa209c145b72b3467cdd5eda8c49c933`; its PE imports omit both VCRUNTIME DLLs. The focused guest rerun then started successfully but failed before writing with Windows stack-overflow status `0xC00000FD`; source SHA-256 remained unchanged and the target remained absent. The existing SHA-256 helper now allocates its 1 MiB buffer on the heap so the pre-Tauri executable path does not exhaust the Windows main-thread stack; changed-head Windows execution and the required imaging `partial` remain pending. The first WHPX recovery attempt exposed that the Cargo test executable lacked the Common Controls v6 activation manifest and failed before QEMU with `0xC0000139`; a static-CRT library-only build with an explicit v6 manifest resolved that loader failure. The correctly selected live test then failed before QEMU because Windows canonicalization adds its extended path prefix, while the harness compared the canonical output root with a lexical repository path. The harness now compares canonical output and repository roots while retaining exact path-drift and final-component link refusal. The fully qualified focused boundary regression passes locally through `heavy.sh`. Changed-head WHPX run `PR90-WHPX-3924ebc-V1` then reached the intended test but failed before QEMU because `usable_host_executable` rejected every Windows path under its unconditional non-Unix branch; its atomic exit was 101 and durable log SHA-256 was `a46849de87b2f7bfe6e7b34f97828e7c3f083c2d565a8af9533a1a3f324b52a2`, with no surviving Cargo, Rust, or QEMU process. Windows now accepts only an existing regular tool file while Unix retains its executable-bit check. The focused Unix regression and exact-head Windows regression both pass through `heavy.sh`; the latter records atomic exit 0 at `C:\OPEMOS\PR90-Windows-Regression-e804291\status.json`. A bounded search then confirmed that the sealed guest had no `mkisofs.exe` in its configured PATH or standard installed-tool locations. Resolver authorized minimum provisioning; cdrtools `3.02a09` was obtained from the versioned SourceForge HTTPS artifact, enforced archive SHA-256 `0b83f199ebf72cc5a1b60bcb4aa915a420c33b8886b00496e21467e5845aa135`, extracted only `win32/mkisofs.exe`, and verified executable SHA-256 `d0f4b4b1cb1f9feefb41683cc6160a68b8fa8cdac986809fb0e0529d8c2eb5c8` plus its version identity. WHPX V2 accepted that prerequisite and booted Fedora to login near guest second 20, then remained blocked for more than 30 minutes in the exact readiness child `ssh.exe ... cat /etc/steamos-builder-ready`: `ConnectTimeout=2` bounded connection setup but no execution deadline controlled the established SSH command. The exact test-owned process tree was terminated, the wrapper atomically recorded exit 1, no Cargo, Rust, QEMU, or SSH orphan remained, and preserved log/status SHA-256 values are `682c043f1618a8419f29578d0595d49ee13e19fc66c717e9770d7cec07f2e4a7` and `54c488946fb4368bb619a2abd63911e7b42e9a7c2a90dff41d310429ad5a37c7`. The readiness handshake now gives each child a fixed five-second execution deadline, captures at most 64 KiB from each output stream concurrently, terminates and reaps the owned process tree on expiry, and returns that expiry as a transport attempt under the existing single non-resetting overall readiness deadline; wrong marker output remains an immediate semantic failure. Focused timeout/reap/output-limit and late-marker deadline regressions pass through `heavy.sh`. Exact Windows execution at `069b7d0d2b0543322313127881deaf920685c5ab` proved readiness advanced and QEMU exited, then exposed the same missing post-connect deadline in the cleanup SSH child running `sudo systemctl poweroff`; Resolver terminated and reaped only that verified test-owned child, the run ended with exit 101, no owned process survived, and preserved partial-log SHA-256 is `378edba5f72d22209ed943f23fb734f90305d27f900aeca6304323193c91b5d6`. Both existing appliance shutdown paths now run that command with a fixed five-second post-connect deadline, concurrent 64-KiB-bounded output capture, and deterministic owned-tree termination/reaping. The focused local regression passes, and exact Windows head `a0afb894b60b5d46b60cdf5de1f3551b0bc2d88b` records atomic exit 0 at `C:\\OPEMOS\\PR90-Windows-Shutdown-a0afb89\\status.json`; the changed-head partial remains pending. The bounded WHPX transport-only diagnostic at source `3e073cd158a608eb0f8d91154d786f6acadd84e9` then proved TCP connection and a second authenticated raw SSH command were healthy: it returned `SECOND_OK` plus the guest `SSH_CONNECTION` in 233 ms. The otherwise identical framed command timed out at 30 seconds without its terminal marker, isolating Windows OpenSSH multiline argument delivery; atomic exit was 101, with test-log SHA-256 `94f7c485c7de0486cc773ea6afab941cdd4e8c8c991bc00bc108c09e72ee6671` and status SHA-256 `301838eae970dc1899f98eb4d939126aabda6081889f7d629085391bd2d0bd60`. The structured runner now base64-encodes the guest script into one transport line, decodes it inside the existing Fedora guest, preserves the bounded marker/status collector, and assigns the initial read-only attachment check an explicit ten-second deadline. The focused regression executes a multiline script through that exact one-line transport and passes through `heavy.sh`; the required changed-head imaging partial remains pending. The `ba7032e01bde0085163a151da2bbc7f51560ac66` partial passed Fedora readiness and then failed cleanly at the new ten-second initial read-only-property bound; partial log SHA-256 is `7fbbbf73001c7746d977aa707ba231529ad58a1cc46fb62bf438859a51c6cdea`, atomic status SHA-256 is `59f06911d967918c79892157ad82f07d9b75e65e229b15774cdd3b6606072213`, and archived QEMU log SHA-256 is `66f2edd8978651c0c3e3b1731e88a5b57485d48c8cc14e344070d99aec3be65d`; cleanup left no owned process or retained virtual-USB output. The bounded attachment diagnostic at `9bbab90bbad371c4bfd3d786fce828dc9bef3e09` proved the expected by-id device appears within 6 ms while only `sudo blockdev --getro` failed to return a terminal marker within 30 seconds; its log/status SHA-256 values are `98a00f9ab233b92c82856f21e6aee44877891f5ae8811fb09530826667ce0f41` and `9d1034913d0ca37e5e392f41c602e724fc820eda5fda45fb039929851643a5e8`. The two pre-mutation phases now read the kernel's unprivileged sysfs read-only property for the exact resolved block device, accept only one exact `0` or `1`, require source=`1` and working=`0`, and preserve every device, mount-state, and later-phase guard. Focused exact-value acceptance and malformed/multiple-value refusal pass through `heavy.sh`; the failed bounded diagnostic stage and then the required changed-head partial remain pending. Swapped-order WHPX diagnostic head `030c3c5dee020a435a91f3549d61263c8514e35f` proved both framed-first and raw-second commands authenticated, executed remotely, and received EOF, exit status, end-of-write, and channel close, while Win32 OpenSSH alone remained alive past each fixed ten-second bound; atomic exit was 101, with partial-log SHA-256 `d2e4808077143697a6bb7e74cb01ed3579da0290736ed3fa9af9046003254166` and status SHA-256 `4b85cacaa55415bc36f08e511fe7055f79444f175f68b99bfc34f37a6fc4d322`, and no owned process survived. Windows guest SSH children now receive an anonymous stdin pipe whose parent handle is closed immediately instead of mapping stdin to NUL, avoiding the demonstrated Win32 OpenSSH redirected-NUL hang while other hosts retain null stdin; the focused structured-command framing, timeout, and reap regression passes through `heavy.sh`. Windows external SSH remained defective after bounded mode diagnostics, so commits `8b0473b`, `8032624`, `e61824c`, and `045350b` add and prove the Windows-only in-process russh command and exact gated mutation transports while Unix remains unchanged. Exact WHPX focused head `045350b20ada0d066baed1011d0ae1c8a6f53054` passed split marker, callback-once/failure, nonzero, overflow, timeout, and cleanup cases. The next partial exposed NTFS alternate-stream interpretation of reviewed Arch epoch filenames such as `egl-wayland-4:1.1.19-1-x86_64.pkg.tar.zst`; head `7fe3d97e8da07048057bcb7dbaa1e53164a9189b` maps only Windows host staging names to deterministic SHA-256 basenames while preserving canonical lock and guest names, and its native Windows regression passes. Its WHPX partial advanced through mutation and reviewed signed userspace, then failed at offline handoff validation because the existing x86 appliance was not attached to the expected working image. Atomic log/status SHA-256 values are `3a29690c5652326ece94990565f6c484f486ecc8d93136acd0b6f8c16ab8d117` and `001e7f9a0c658f0069951bf50313aedddaf08600b80927992be79d086682f946e`; cleanup left no test-owned survivor. Resolver diagnosis is pending and the unchanged partial must not repeat. Commit `ad8215986d735f9d35503729ec3df70053cbdbd6` routes the remaining Windows logged installer command through the existing bounded in-process russh transport while preserving the Unix process path. Its exact source archive has SHA-256 `2fbea99cba515139dc4fb89bc26dfab3e4873b9e061fa0e270872b4c91461a34`; the focused host compile and exact sealed-Windows WHPX regression pass, including incremental combined stdout/stderr, exact nonzero status, mid-operation cancellation, a clean follow-up SSH session, total deadline, output bound, readiness, and cleanup. The earlier partial independently remains stopped at the delivered Core contract request for a canonical immutable commit whose final validation object propagates `inputSource`; no Core pin changed and no unchanged partial was repeated.

- [ ] Test sacrificial removable media covering unformatted disks, multiple
  partitions, busy volumes, identical devices, device renumbering, unplug and
  replug, sleep/wake, cancellation, short writes, verification errors, eject
  failure, and insufficient capacity.
- [ ] Revalidate the whole physical device, capacity, identity token, selected
  image, and destructive phrase immediately before opening it for writing.
- [x] Keep a conspicuous “do not disconnect” warning visible throughout write,
  verification, flush, and eject. The alert is exposed before native destructive
  work begins, remains present across every admitted progress update, and clears
  only from the terminal cleanup path after the native operation resolves or
  fails. Its visible text explicitly covers writing, read-back verification,
  flushing, and safe ejection. On 2026-09-05, the focused 15-case main-layout
  suite and all 141 frontend tests plus documentation, hygiene, and boundary
  integrity pass. Linux physical-device writing remains unavailable.
- [x] Never expose internal/system disks or accept a partition when a whole
  removable device is required. macOS discovery requires an exact numeric whole-
  disk identifier and canonical `/dev/diskN` node, explicit external physical,
  writable, removable-or-ejectable metadata, a bounded capacity, supported block
  size and image alignment, plus nonempty device-tree provenance; final preflight
  reruns the same eligibility parser and binds its identity token. The expanded
  fail-closed matrix covers every required field missing or malformed, internal,
  partition, virtual, non-writable, non-removable, deceptive raw-node, oversized,
  unsupported-block, and unaligned cases. On 2026-09-05, formatting, warnings-as-
  errors Clippy, and the focused native safety test pass. The full Rust suite
  reached 330 passes with 27 ignored; its sole failure was the already-recorded
  mutable sibling-Core installer-result fixture mismatch while Core was busy,
  which was not retried or counted as USB validation. Linux physical-device
  discovery and writing remain unavailable.

## CI and test commands

Every normal code change must pass:

```bash
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
npm run test:frontend
```

Before release, also run the ignored network, QEMU, recovery-image, package,
USB, cancellation, and real x86_64 Fedora tests explicitly. Skipped live tests
must be reported; a default-suite pass does not imply hardware certification.

- [x] Add CI coverage for formatting, warnings-as-errors, Rust tests,
  frontend tests, documentation, and repository hygiene.
- [x] Add an x86_64 Ubuntu 24.04 integration job for the immutable Core
  resolver contract, authenticated guest handoff/activation consumer, and the
  disposable TCG headless image-tool smoke. The job checks out exact Core commit
  `adf372b857cd348b6a18680b45ffcea790f04d4b` without credentials, explicitly
  opts into TCG, and exposes no publication or physical-device operation. Core
  `main` now resolves to that exact commit after the bounded necessary-CI
  fast-forward. On 2026-09-05, YAML parsing, exact workflow documentation
  assertions, the local ignored resolver and consumer integrations, repository
  hygiene, and boundary integrity pass. To execute that remote-only CI, EXE lead
  normally fast-forwarded configured remote
  `https://github.com/CorniiDog/steamos-nvidia-image-builder.git`, branch `main`,
  from `14d510787380fc444eb57d2888677c2239ab0b9f` through CI commit
  `7a911834d9625c7cd6fd3f428eaba0b48ad55211`; GitHub redirected the repository
  to `CorniiDog/OPEMOS.EXE` without changing the configured remote. Checks run
  33980895429 was queued for the exact commit. That run exposed a bounded
  shallow-checkout failure: `adf372b` was present but pinned ancestor `7f90e45`
  was not an available object. The integration checkout now fetches exactly 56
  commits, covering the 55-commit fast-forward plus its pinned baseline without
  requesting unrelated history. The follow-up online-Core migration removes the
  sibling-checkout fallback from both CI integration consumers, requires a
  canonical GitHub `origin`, exact fetched `HEAD`, and exact immutable fixture
  object before `git show`, and documents the verified cache workflow. A fresh
  depth-56 canonical clone resolved `HEAD` to `adf372b857cd348b6a18680b45ffcea790f04d4b`
  and the pinned boundary object to `7f90e45c4c154fdfda81ff594611cf533e4fb894`;
  both ignored Core-backed integrations pass against that cache. Transition PR
  #1 then exposed that the regular Rust job still fetched only one commit at
  fixture head `3e49323fce266af8686039fb6487918ef5a64fd9`; nine existing conformance
  tests could not resolve immutable ancestors. Canonical GitHub history proves
  the oldest required pin is ten commits behind that head, so the job now fetches
  initially fetched 11 commits. The next PR run passed those nine cases and
  exposed two older compatibility-generator consumers pinned to
  `a1c03c9658c5ed885f094b5f8e0896d818fee785`, 45 commits behind the checkout.
  Canonical GitHub provides both expected files at that exact object, so the
  final checkout and documentation guard fetch exactly 46 commits. Debian and
  managed Fedora appliance boot remain separate.
- [ ] Add bounded release-package smoke tests which start and close the packaged
  application and confirm no orphan QEMU processes remain. The experimental
  Ubuntu debug package now has the equivalent bounded AT-SPI launch/close and
  before/after QEMU inventory coverage. The unsigned Windows portable artifact
  now snapshots QEMU process identities before startup, closes the exact app,
  and refuses any newly surviving QEMU identity after a bounded five-second
  settlement window. Native Windows CI evidence remains pending; the signed
  release-package path remains gated and unclaimed.

## Release gates

- [ ] Complete the explicitly authorized maintainer Git delivery controls without
  granting merge or release-publication authority. The active bounded batch
  reviews a clean named non-main topic branch against its exact repository,
  local HEAD, and observed remote HEAD; permits only a normal same-name
  fast-forward push after a freshly typed identity phrase; creates only an exact
  reviewed pull request against the observed `origin/main`; and implements
  rollback only as a new inverse commit for a reviewed single-parent HEAD.
  Changed identities refuse and require a fresh review. Force push, tag/ref
  deletion, main-branch push/rollback, reset, merge, release, and history rewrite
  remain unavailable. The authenticated post-create check additionally accepts
  only the reviewed repository's canonical PR URL and verifies its repository,
  immutable head, base branch/commit, title, and body SHA-256; a race or wrong
  result reports the created URL and observed identities without closing,
  deleting, merging, or otherwise mutating it. Focused Rust validation and
  remote-race cases (2/2) plus warnings-denied all-target Clippy pass through
  `heavy.sh`; local frontend execution is pending
  because this host has no Node runtime, so required CI must exercise the
  frontend review/confirmation regression before merge. No real remote action or
  release publication has occurred.

- [ ] Connect the maintainer release-plan review to Core's schema-1 release
  session without granting publication authority. The bounded adapter pins
  canonical Core `f66c374cf224b8e01c723304ad8ee2d5354f69d4`, stages the exact
  `release_operation.py` and Windows-compatible
  `release_operation_session.py`, prepares the existing publisher's dry-run
  plan, and binds prepare/status/cancel/create-only execution to the exact
  operation identity and attempt. Focused Rust contract/identity tests, 48
  frontend workflow/session tests, documentation validation, host Cargo check,
  warnings-as-errors Clippy, and diff hygiene pass. Exact committed source
  `500ac56` also built as an unsigned static-CRT Windows executable (SHA-256
  `27f96abbcb2904b9ea6128e7de3cc85d5d0a7ee48cecceefb3f1206cd33b8980`,
  19,805,184 bytes), remained live for the bounded eight-second startup smoke,
  closed without a new QEMU survivor, and invoked no release action. Required
  pull-request checks, Core counterpart review, and the separately required
  maintainer-menu create-only demonstration remain pending. No release or
  publication has occurred.
  A reproduced post-merge gap showed that the menu could not consume a fresh
  authenticated Core product outside the current in-memory build session. The
  active follow-up adds one folder picker and an adapter-owned import path that
  accepts exactly four regular publisher inputs, rejects links, duplicates and
  extras, canonicalizes paths, verifies the archive hash and pinned Core dry-run
  plan, isolates durable state by archive SHA-256, and repeats dry-run plus
  maintainer authorization immediately before create-only publication. Host
  Cargo check, formatting, Clippy with warnings denied, exact operation-binding
  and pinned-publisher tests, the closed-world regular-file importer regression,
  native Windows frontend adapter validation, and diff hygiene pass. Exact
  implementation commit `1e20d91f23a4f939011fca3a11df253032bc24ba`
  also built as an unsigned static-CRT Windows executable (SHA-256
  `d4b29a7f710b860910283b2ac060b4dcb4e47eddcfb3afbb68842993e158dde1`,
  19,860,992 bytes), remained live for the bounded eight-second startup smoke,
  closed cleanly, and left zero new QEMU processes. Pull-request checks and
  Core review remain pending; no product release or beta publication occurred.

- [ ] Make the immutable Core publisher executable from the bundled Windows
  maintainer runtime without modifying Core-owned bytes or weakening its
  validation. Exact native proof with EXE SHA-256
  `5ea0f696e24a1a02cbc41222157fd0e4da2d0a47bfd9f2ab8f03c9e4d000ddf1`
  and authenticated r2 archive
  `cc4b30e5ba65dd61b1c0cf8089531f6393fae1372025af5fe96697b9d6937c3b`
  reached the pinned publisher and failed first because Windows bundles
  `python.exe` while Core invokes `python3`. The bounded Windows-only command
  adapter now defines `python3` as the already resolved bundled `python` only
  inside the Bash process that sources the exact immutable publisher; Unix
  execution and publisher bytes remain unchanged. Host formatting, focused
  library compilation, and warnings-denied all-target Clippy pass through the
  shared heavy wrapper. The same native dry-run then advanced to Core's next
  exact dependency and failed because `validate_publish_inputs.py` invokes an
  unavailable external `zstd`; a concrete Core-owned dependency request is
  recorded. Native Windows runs `35005730804`, `35006747321`, and `35007612060`
  all exited the temporary publisher process before its marker with empty stderr,
  even after removing the Python invocation, isolating the instability to running
  a temporary Windows path through CI Git Bash. The contained guest proof
  independently showed the bridge reaching bundled Python and advancing to
  `zstd`. The focused Windows regression now verifies the exact constructed Bash
  command, injected function, delegation body, publisher position, and four
  closed-world input flags without executing an ambient runner tool. PR #99 passed its changed-head native Windows build, startup, artifact, and regression gates plus exact Core review, then squash-merged through protection as EXE main `2090dbc8111ee3230f5a6ae8a147dd58be882612`. Core subsequently supplied the exact Windows zstd dependency at canonical squash commit `f6871104ea83d8afa620b133b362a0578ff4a6a8`. The active consumption batch advances the ordinary Core pin to that commit, verifies the closed contract and retained ZIP/license bytes, extracts only exact `zstd.exe` into the existing closed runtime, records its license and command identity in the hash-bound manifest, and leaves Core publisher bytes unchanged. Focused Python runtime validation passes 15/15 against the canonical GitHub cache. Native Windows run `35012965074` proved the new exact zstd consumer passed, then failed only because the newly broad workflow invocation also executed an unrelated Unix-wrapper fixture as a Win32 program; the workflow now invokes only the platform-relevant exact-zstd regression. Replacement native Windows run `35013164238` passes exact zstd consumption, all Windows tests, unsigned build, startup, provenance, and artifact upload. Both Rust jobs then showed the advanced Core head is 168 commits after retained compatibility commit `a1c03c9`, so the exact shallow checkout depth advances from 167 to 169; Linux and Debian jobs pass. Required CI, unchanged-head Core review, merge, and the resumed create-only proof remain pending.

  Exact-head Core approval and every required replacement check then passed; PR
  #100 squash-merged through protected main as
  `740bc61d5212445160feff3dc72bd960e1610b05`. The resumed exact
  imported-product dry-run proved Core accepts the r2 bytes and emits the
  expected plan, but the Windows wrapper fails earlier while EXE discarded its
  stderr behind a generic rejection. The bounded follow-up retains a nonempty
  publisher diagnostic only within the existing 1 MiB result limit, preserves
  the generic empty-stderr refusal, and reports oversized stderr without echoing
  it. Formatting, the focused Windows-line-ending/empty/oversized diagnostic
  regression, and warnings-denied all-target Clippy pass through `heavy.sh`.
  Changed-head native Windows build/startup validation, required CI, exact Core
  review, merge, and the resumed create-only proof remain pending.

### Alpha

- [ ] One fresh official image builds, writes to USB, installs to the intended
  disk, and boots to usable NVIDIA Desktop and Gaming Mode.
- [ ] The original image remains unchanged and all independent validations pass.
- [ ] Failure leaves a usable recovery route and bounded diagnostics.

### Beta

- [ ] Repeat build, already-current, upgrade, cancellation, and cleanup paths
  pass on real media.
- [ ] SteamOS A/B update and rollback are proven on hardware.
- [ ] At least one NVIDIA laptop and one desktop GPU configuration pass the
  published compatibility matrix.
- [ ] Packaged macOS installation works without developer tools.

### Stable

- [ ] Normal operation requires no shell knowledge or manual driver repair.
- [ ] Supported SteamOS/kernel/NVIDIA/GPU combinations are explicitly certified.
- [ ] Application, Core bundle, appliances, dependencies, and outputs have
  auditable provenance and authenticated update paths.
- [ ] Documentation matches the shipped behavior and known limitations.

## Deferred until after alpha

These are not current OPEMOS.EXE implementation work:

- Production Windows and Linux application ports, including a signed Windows USB
  writer. The explicitly authorized experimental Ubuntu/Debian host-testing
  path above is current work.
- Raspberry Pi Imager-style password and Wi-Fi provisioning.
- Automatic official-image download assistance.
- Multiple certified NVIDIA profiles and the optional no-CUDA profile beyond
  Core’s reviewed/hardware-tested contract.
- The persistent SteamOS storage manager, installed-system recovery UI, update
  guardian, backend hot-update system, and device-side Wi-Fi support. Those
  belong to Core and the SteamOS Desktop Companion.
- Support pipeline internals, sanitizers, build recipes, release publication,
  and device deployment. Core owns the entry points; a later OPEMOS.EXE
  maintainer UI/CLI may schedule them and present authenticated results.
- Automated pushing, publishing, rebooting, or destructive deployment. These
  always require separately implemented authorization and fresh confirmation.

Deferred items should return here only when an accepted milestone makes them
current and their repository ownership is unambiguous.

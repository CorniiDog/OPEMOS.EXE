Below is the consolidated project checklist based on the current repository state and the latest successful local appliance tests. Where local validation is newer than older prototype documentation, the latest validated behavior is treated as authoritative.

# SteamOS NVIDIA Image Builder — Master Checklist

## Current project phase

**Status: development / backend bring-up**

The desktop shell, macOS development bootstrap, Fedora appliance bootstrap, disposable Rust-managed QEMU runtime, cloud-init provisioning, fixed guest operations, synthetic mutation proof, and raw user-image inspection path are working.

The current transition is from a proven disposable image-mutation pipeline to a
fully verified NVIDIA recovery image. Real SteamOS 3.8.14 inspection,
normalization, exact-kernel artifact resolution/building, authenticated
userspace closure validation, and module mutation now work. The latest real run
reached target `mkinitcpio` and failed closed because the recovery target could
not create its `/var/tmp` workspace; no output image was accepted.

The project is not yet producing a bootable modified SteamOS image.

### Milestone ladder

* [x] **Prototype shell:** desktop UI can select supported SteamOS image files and produce a harmless prototype output.
* [x] **Host readiness:** detect QEMU, determine host architecture, validate QEMU can launch, and locate the Fedora builder appliance.
* [x] **Appliance bring-up:** build and boot a Fedora Cloud appliance under QEMU on macOS.
* [x] **Disposable runtime:** boot through a writable qcow2 overlay so the Fedora base remains pristine.
* [x] **Guest handshake:** provision the guest with cloud-init and verify readiness through non-interactive SSH.
* [x] **Backend integration:** Rust owns appliance startup, readiness polling, fixed guest operations, shutdown, and cleanup.
* [x] **Harmless image mutation:** pass a user-selected Valve recovery image to the guest, create a working copy, mount it safely, write a deterministic marker, unmount it, and return a validated modified image.
* [ ] **NVIDIA integration prototype:** inject the project’s NVIDIA kernel-module/userspace support into a SteamOS recovery image without requiring manual post-install repair.
* [ ] **Bootable alpha image:** generated image boots/install-recovery media successfully on at least one NVIDIA test machine.
* [ ] **Beta:** repeatable builds, clean-image tests, rollback/error handling, and multiple NVIDIA hardware configurations.
* [ ] **Release candidate:** cross-platform packaged application with reproducible builder runtime and documented compatibility matrix.
* [ ] **Stable:** reliable end-user workflow from official Valve image to validated NVIDIA-capable output with no shell knowledge required.

### Current priority queue

1. [x] Move the successful `STEAMOS_BUILDER_READY` handshake into the Rust backend.
2. [x] Make Rust launch the Fedora appliance in the background without an interactive terminal.
3. [x] Add bounded readiness polling and distinguish booting, ready, failed, timed out, and stopped states.
4. [x] Add controlled guest command execution from Rust.
5. [x] Add graceful guest shutdown and reliable forced cleanup fallback.
6. [x] Keep each appliance session disposable and verify no state leaks between builds.
7. [x] Pass a harmless host file into the guest, return it, and verify identical bytes.
8. [x] Pass a user-selected raw SteamOS image to the guest as a host-level read-only block device without booting it.
9. [x] Detect compression/container format and prepare a disposable writable qcow2 working layer.
10. [x] Inspect a selected raw image read-only without mounting and return structured partition/filesystem metadata. (Real Valve-image validation remains in the immediate sequence.)
11. [x] Implement the first deterministic marker-only mutation on the selected image's disposable working overlay.
12. [x] Integrate NVIDIA support from `OPEMOS` (formerly `open-gpu-kernel-modules-steamos-support`) only after the generic image-mutation path is proven.

---

# 1. Core project architecture

* [x] Keep the desktop image-builder application in:

  * `CorniiDog/OPEMOS.EXE`
* [x] Keep SteamOS NVIDIA support/build/install logic in:

  * `CorniiDog/OPEMOS`
* [x] Keep NVIDIA source history and project patch branches in:

  * `CorniiDog/open-gpu-kernel-modules-steamos`
* [x] Treat the user-provided Valve recovery image as input data, never as project source content.
* [x] Do not redistribute Valve recovery images from this repository.
* [x] Modify a working copy rather than mutating the user’s original image in place.
* [x] Keep final output separate from the original input.
* [x] Avoid direct USB flashing in the initial application scope.
* [x] Use Tauri 2 for the desktop shell.
* [x] Use Rust for privileged/sensitive orchestration and filesystem/process control.
* [x] Use a standardized Fedora guest as the Linux image-manipulation environment.
* [x] Use QEMU as the virtualization boundary.
* [x] Allow Apple Silicon to run an aarch64 Fedora guest while manipulating x86_64 SteamOS images as data.
* [x] Establish a versioned fixed-operation host↔guest protocol without arbitrary UI-originated shell strings.
* [x] Define explicit responsibility boundaries among UI, Rust host backend, Fedora appliance, and NVIDIA support repo.
* [x] Document the architecture and link it from the main README.
* [x] Add an architecture/data-flow diagram.

---

## Backend decomposition and maintainability audit

The audit began with roughly 14,800 lines in one `lib.rs`, including about
3,000 lines of inline tests. The first behavior-preserving decomposition is now
complete: `lib.rs` is a small crate root, while application lifecycle,
appliance/workflow orchestration, contracts, image work, NVIDIA resolution and
publication, offline installation, settings, native windows, and tests have
separate files. Continue subdividing only where the resulting review or test
boundary is useful; do not split files merely to chase a line-count target.

* [ ] Replace source-text tests that `include_str!("lib.rs")` with behavioral
  tests or tests against the extracted module/template they actually govern, so
  moving code cannot silently weaken coverage.
* [x] Extract shared types and versioned external contracts into `contracts.rs`
  with crate-confined visibility, preserving strict serde contracts and every
  pinned support-file record. Subdivide this file by schema family later only
  when shared fixtures or independent ownership justify it.
* [ ] Extract host/platform functionality into focused modules such as
  `host/{paths,process,resources,hashing,network}.rs` and
  `platform/{macos,windows,linux}.rs`; keep platform-specific command discovery
  and GUI launching behind explicit traits or narrow functions.
* [x] Extract appliance/process/workflow orchestration into `appliance.rs`, with
  one module owning child processes, watchdogs, credentials, ports, QMP/SSH,
  abandoned-session cleanup, and the fixed-operation command bridge. Further
  submodules remain optional maintainability work.
* [x] Extract image inspection, mutation, output naming, space checks, export,
  and independent verification into `image.rs`, keeping source immutability and
  finalization invariants separate from NVIDIA resolution.
* [x] Extract NVIDIA release resolution, authenticated artifact/userspace
  acquisition, source preflight/building, support-bundle preparation, and
  publication into `nvidia.rs`; keep offline-root result validation and mutation
  orchestration separately in `installer.rs`.
* [x] Extract settings/GitHub authorization, native window construction, and
  application bootstrap/lifecycle into `settings.rs`, `windows.rs`, and
  `app.rs`. Reduce `lib.rs` to imports, module wiring, shared policy constants,
  the public `run` re-export, and the test include.
* [ ] Move large generated guest shell programs out of Rust function bodies
  into versioned template/assets or small typed command builders. Validate every
  substitution, preserve fixed-operation semantics, and add argument-injection
  and exact-rendering tests.
* [x] Remove the 2,900-line inline test body from `lib.rs` into `tests.rs` while
  retaining all existing default/ignored behavior. A later cleanup may move
  pure tests beside modules and live multi-component tests under `tests/`.
* [ ] After the module split is stable, evaluate a small Cargo workspace with a
  pure `builder-core` crate and a Tauri application crate. Do this only if it
  materially improves compile isolation, contract testing, or reuse; Rust
  modules alone improve ownership but do not guarantee much lower total compile
  time.
* [x] Remove the superseded, repository-unreferenced
  `src-tauri/src/{main.js,style.css}` prototype files; the active frontend
  remains under top-level `src/`.

## State, concurrency, and error-model audit

* [ ] Replace stringly typed appliance/build states and ad-hoc status tokens
  with enums plus one validated transition layer. Reject impossible transitions
  such as `ready` directly to `exported` or a stale worker completing a newer
  session.
* [ ] Give every build, image session, x86 worker, handoff, and async command a
  generation/session identifier. Require it before committing worker results to
  shared state so cancellation/restart cannot let an old task overwrite a new
  build.
* [ ] Define and enforce one lock-order policy for image and x86 managers; avoid
  holding either mutex across process I/O, network I/O, guest commands, or
  waits. Add a concurrency test that exercises cancellation, status polling,
  and close handling together.
* [ ] Add a cross-process exclusive lock for each selected source image,
  working qcow2, output reservation, and target handoff. Hold the working-image
  lock across native-to-x86-to-validation handoffs and release it only after
  QEMU, mounts, and partial-output cleanup finish.
* [x] Consolidate the duplicated main-window-close and `ExitRequested` worker
  cleanup into one shutdown coordinator in `app.rs`.
* [ ] Route cancellation, panic/failure recovery, and the next-launch
  abandoned-runtime audit through the same idempotent bounded cleanup contract.
* [ ] Replace backend `Result<T, String>` boundaries incrementally with a
  versioned `BuilderError` containing a stable code, operation/phase, safe user
  message, bounded maintainer detail, responsibility, retryability, and source
  chain. Serialize it only at the Tauri boundary.
* [x] Make settings writes durable and concurrency-safe: use unique confined
  temporary files, restrictive permissions, flush/sync plus atomic replacement,
  and a bounded OS advisory lock spanning each load/migrate/update/write
  transaction. Real subprocess regressions cover independent concurrent updates,
  contention timeout, killed-writer lock release, complete JSON, mode 0600,
  symlink refusal, recovery, and temporary-file cleanup.

## Support-installer boundary audit

* [ ] Repin the support installer only after its immutable-input snapshot,
  lifecycle lock, target `/var/tmp` scratch mount, mount-identity checks, and
  mandatory post-install verification contracts pass its complete Fedora suite.
* [ ] Create one private content-addressed handoff snapshot containing every
  support helper, module archive/checksum/provenance file, userspace package and
  signature, keyring, lock, and optional profile. Rehash the same snapshot
  before transfer, `--validate-only`, mutation, and final result acceptance.
* [ ] Record the working disk GUID, partition GUID/PARTUUID, filesystem UUID,
  Btrfs subvolume identity, EFI identity, expected read/write policy, and qcow2
  backing identity. Revalidate them at every appliance handoff and before and
  after each destructive phase.
* [ ] Extend the Rust support-result contracts with mandatory
  `moduleVerification`, `userspaceVerification`, and `initramfsVerification`.
  Reject a successful support result when any record is absent, malformed,
  inconsistent with validated inputs, or not independently verified.
* [ ] Cross-check all three support verification records against the builder's
  independent final-image module, package, firmware, pacman-database, and
  `lsinitcpio` inspection; never treat support self-reporting as a replacement
  for final-image verification.
* [ ] Independently validate the final Holo pacman database's exact package
  records, ownership, dependencies/providers, database consistency, and
  agreement with the support userspace-verification result.
* [ ] Consume support-owned schema fixtures covering valid schema 1, absent
  mandatory fields, safe additive fields, unsupported future major versions,
  malformed records, oversized inputs, and contradictory success/failure data.
* [ ] Require an exact validated-snapshot/document identity across the separate
  validation and mutation calls; a merely equivalent freshly resolved package
  set is not the same authorization.
* [ ] Consume bounded pacman/mkinitcpio heartbeats as indeterminate liveness,
  retain unknown-phase forward compatibility, and detect a stale guest with a
  conservative phase-specific timeout without inventing percentage progress.
* [ ] Run a real x86 phase/fault matrix for pacman hooks, userspace verification,
  module extraction/compression/copy/verification, GRUB, depmod, mkinitcpio,
  state writing, compression restoration, and recursive cleanup. At every
  failure/cancellation point require source immutability, overlay rejection,
  stopped workers, released locks/mounts, and no trusted partial result.
* [ ] Define recovery-image authenticity honestly. A builder-generated layout
  report is an inspection attestation, not proof of an official Valve image;
  cryptographic `official` status requires Valve-signed metadata or a reviewed
  exact-image manifest. Bind any target executable/hook allowlist to that trust
  root and otherwise retain an explicit unverified classification.
* [ ] Consume a machine-readable hardware-certification attestation before
  accepting `certified-published`; bind it to exact artifact hashes, GPU IDs,
  SteamOS/kernel versions, test date/result, and maintainer identity, and
  preserve it in the output manifest and UI explanation.

---

# 2. Desktop shell and basic UX

* [x] Create Tauri application shell.
* [x] Add primary heading and builder status area.
* [x] Add drag-and-drop image selection.
* [x] Add native file-picker fallback.
* [x] Add Valve recovery-image download-page access.
* [x] Add selected-image summary card.
* [x] Show immediate image-validation feedback and bring the selected image/build action into view.
* [x] Order the main workflow as download, image selection, readiness, and build action.
* [x] Add build button and prototype progress state.
* [x] Move build status, live logs, and cancellation into a dedicated progress window.
* [x] Create the progress window on demand as a native child so it stays above the main window without appearing at startup.
* [x] Prevent document scrolling and macOS overscroll exposure in both application windows.
* [x] Keep progress controls fixed while the log viewport absorbs window resizing.
* [x] Keep the main workflow window compact and fixed-size while allowing the progress log window to expand from its minimum size.
* [x] Start and stop the builder appliance automatically as part of the build workflow.
* [x] Reveal the validated raw marker image in Finder on macOS.
* [x] Accept:

  * `.img`
  * `.img.bz2`
  * `.img.gz`
  * `.img.xz`
* [x] Reject unsupported file extensions early.
* [x] Add project icon/assets.
* [x] Replace prototype text-output wording with marker-image export wording.
* [x] Show distinct host, appliance, guest-handshake, input-image, export, validation, and output states.
* [x] Add a clear pre-build summary of exactly what will happen.
* [x] Add a per-build NVIDIA source selector beside the build action with Automatic, Latest, and versioned project branches; pin the resolved branch commit before compilation.
* [x] Display original image path and planned non-overwriting output location separately.
* [ ] Add user-selectable output path/name.
* [x] Add cancel control for the current appliance/prototype workflow.
* [ ] Keep advanced diagnostics hidden by default but accessible.
* [x] Ensure normal users never need Fedora, QEMU, SSH, cloud-init, or partitioning terminology to complete the current workflow.
* [ ] Split `build.js` into testable progress-state/workflow, terminal-rendering,
  diagnostics, and window-lifecycle modules; split `main.js` into image
  selection, settings/maintainer state, and build-launch modules without adding
  a framework solely for file organization.
* [x] Extract ANSI/control normalization and safe terminal rendering from
  `build.js` into `terminal-renderer.js`, with deterministic Node coverage for
  control filtering, state isolation, and ANSI 256-color boundaries.
* [ ] Model frontend workflow state explicitly and render from state rather than
  allowing event handlers to independently mutate related controls. Add Node
  tests for build/cancel/retry, stale events, window close, and support progress.

---

# 3. macOS development bootstrap

* [x] Add canonical macOS developer launcher:

  * `./cargodev_init_macos.sh`
* [x] Detect macOS host.
* [x] Check Xcode Command Line Tools.
* [x] Install/load Homebrew when necessary for development.
* [x] Install/check Node and npm.
* [x] Source `$HOME/.cargo/env` before checking Rust tooling.
* [x] Install/check rustup, `rustc`, and Cargo.
* [x] Detect host architecture.
* [x] Select `qemu-system-aarch64` on Apple Silicon.
* [x] Select `qemu-system-x86_64` on Intel macOS.
* [x] Install/check QEMU through Homebrew for development.
* [x] Run npm dependency installation when needed.
* [x] Launch Tauri development mode.
* [x] Handle stale Tauri/Cargo development processes that can hold the build-directory lock.
* [x] Add `gpgv` to the development bootstrap so direct appliance builds can authenticate Fedora metadata instead of silently relying on the checksum-only fallback.
* [x] Add explicit version reporting for every required development dependency.
* [x] Add minimum-supported version checks rather than presence-only checks.
* [x] Make bootstrap failures actionable with exact remediation messages.
* [x] Keep developer bootstrap separate from end-user runtime dependency strategy; packaged-runtime acquisition remains an independent release milestone.

---

# 4. Host QEMU readiness detection

* [x] Determine expected QEMU binary from Rust host architecture.
* [x] Search `PATH`.
* [x] Check common Homebrew paths.
* [x] Read QEMU version.
* [x] Run a minimal QEMU startup smoke test.
* [x] Report QEMU launch-test status to the frontend.
* [x] Detect missing Fedora appliance.
* [x] Expose host OS and architecture.
* [ ] Support Windows QEMU discovery.
* [ ] Support Linux QEMU discovery.
* [x] Detect virtualization acceleration availability separately from QEMU binary availability.
* [x] Report the selected HVF/TCG acceleration mode clearly for the current macOS paths.
* [x] Use bounded TCG fallback for the managed x86_64 appliance on Apple Silicon when native acceleration is unavailable.
* [ ] Verify required QEMU machine/device features before starting a build.

---

# 5. Fedora builder appliance acquisition

* [x] Pin a Fedora Cloud release/compose for the current development appliance.
* [x] Select architecture-appropriate Fedora Cloud image.
* [x] Download Fedora Cloud qcow2.
* [x] Download Fedora checksum metadata.
* [x] Download Fedora signing keys.
* [x] Verify image SHA256 against Fedora checksum metadata.
* [x] Validate resulting qcow2 with `qemu-img check`.
* [x] Replace an existing appliance atomically only after the new qcow2 passes validation.
* [x] Preserve downloaded base image in appliance work cache.
* [x] Produce `fedora-builder.qcow2` as the base appliance image.
* [x] Keep generated appliance images out of Git.
* [ ] Make signature verification mandatory for release builds.
* [ ] Test `gpgv` verification path rather than relying on checksum-only fallback.
* [ ] Pin or verify the exact Fedora signing key material expected for the selected release.
* [ ] Decide appliance update cadence.
* [x] Record Fedora release/compose/architecture, protocol version, source URLs, image/checksum/keyring hashes, and checksum-signature status in a machine-readable appliance metadata sidecar.
* [x] Require the guest health response's exact supported builder protocol version.
* [x] Fail clearly if the desktop app and appliance protocol versions differ.

---

# 6. Disposable Fedora runtime

* [x] Keep the downloaded/prepared Fedora qcow2 as a pristine base.
* [x] Create a writable qcow2 backing overlay for each run.
* [x] Boot QEMU from the runtime overlay rather than the base image.
* [x] Verify guest-created files disappear between appliance runs.
* [x] Keep runtime overlay data out of Git.
* [x] Keep runtime UEFI variables separate from the base appliance.
* [x] Generate collision-safe per-session runtime directories rather than one global mutable runtime directory.
* [x] Prevent concurrent builds through one Rust-managed session and one active progress workflow.
* [x] Remove abandoned inactive overlays after crashes on the next launch.
* [x] Track runtime disk lifecycle from Rust.
* [x] Remove partially prepared runtime state automatically when startup fails before QEMU launches.
* [x] Verify the base qcow2 remains byte-for-byte unchanged across a complete live session.
* [ ] Add a corruption/recovery path if the base appliance fails `qemu-img check`.

---

# 7. UEFI and QEMU machine configuration

* [x] Locate Homebrew-provided EDK2 firmware on macOS.
* [x] Use a writable UEFI variable store per runtime.
* [x] Boot Apple Silicon guest with `virt` + HVF.
* [x] Configure CPU, memory, virtio block, RNG, and networking.
* [x] Forward localhost TCP port 2222 to guest SSH port 22 during development.
* [x] Run the guest headlessly.
* [x] Move QEMU away from interactive `-serial mon:stdio` for application-managed sessions.
* [x] Capture serial/QEMU logs to a runtime log file or Rust pipe.
* [x] Implement predictable graceful shutdown.
* [x] Implement forced termination fallback.
* [x] Allocate dynamic localhost ports or another transport for parallel-safe operation.

---

# 8. cloud-init guest provisioning

* [x] Use NoCloud seed data.
* [x] Set appliance hostname.
* [x] Create `builder` guest account.
* [x] Grant passwordless sudo to the development builder account.
* [x] Enable SSH service.
* [x] Create `/etc/steamos-builder-ready` marker.
* [x] Emit `STEAMOS_BUILDER_READY` during successful cloud-init completion.
* [x] Generate runtime SSH identity on the host.
* [x] Inject the runtime public key into cloud-init data.
* [x] Verify the authorized key appears in `/home/builder/.ssh/authorized_keys` on a pristine first boot.
* [x] Keep private SSH key in ignored runtime state.
* [x] Remove development password authentication from the appliance workflow; cloud-init disables SSH password authentication.
* [x] Set `lock_passwd: true` and inject only a per-session SSH public key.
* [x] Generate an ephemeral host SSH identity inside each disposable runtime rather than reusing a long-lived project key.
* [x] Version the initial guest control contract as protocol `1`.
* [ ] Provision required image-manipulation tools explicitly instead of relying on Fedora defaults.
* [x] Add a Rust-owned guest health/self-test operation.
* [x] Add a repository-local one-command headless VM harness using a disposable qcow2 overlay, exact synthetic virtio disk, NoCloud seed control, serial JSON result, no network/GUI/SSH, and nested ignored runtime state.
* [x] Extend the headless VM harness with unambiguous synthetic `rootfs-A`/`rootfs-B` discovery, isolated B mutation, backup restoration, and byte-hash rollback verification.
* [x] Exercise synthetic USB identity/capacity authorization, progress, mid-copy cancellation cleanup, full-device readback, and explicit root/wrong-identity refusal entirely inside the isolated headless VM.
* [x] Harden the headless VM harness against symlinked state, stale/non-atomic results, unbounded timeout input, malformed progress, and first/middle/final-block cancellation or off-by-one capacity regressions.
* [x] Add a bounded headless macOS packaging smoke path that separates `.app` build failures from command-line `hdiutil` create/verify failures without Finder, AppleScript, mounts, or host disks.

---

# 9. Host↔guest readiness handshake

* [x] Add macOS handshake helper.
* [x] Use non-interactive SSH.
* [x] Use dedicated runtime private key.
* [x] Disable dependency on persistent `known_hosts` state for disposable guests.
* [x] Read `/etc/steamos-builder-ready`.
* [x] Require exact expected marker content.
* [x] Return:

  * `STEAMOS_BUILDER_READY`
* [x] Validate the complete handshake successfully against a fresh pristine-base appliance session.
* [x] Implement the same handshake directly in Rust.
* [x] Poll readiness while QEMU is booting.
* [x] Add timeout.
* [ ] Distinguish connection refused, guest boot failure, SSH authentication failure, marker mismatch, and timeout. (Process exit, marker mismatch, and timeout are distinct; SSH connection/authentication errors still need separate codes.)
* [x] Surface a concise user message plus detailed diagnostic reason.
* [x] Keep the shell handshake helper development-only; the production workflow uses the Rust-owned protocol.

---

# 10. Rust appliance lifecycle integration

* [x] Add an appliance lifecycle manager to `src-tauri`.
* [x] Generate or prepare runtime files from Rust.
* [x] Create qcow2 session overlay from Rust or a controlled helper.
* [x] Generate cloud-init seed from Rust or a controlled helper.
* [x] Locate firmware from Rust.
* [x] Spawn QEMU detached from the terminal.
* [x] Store QEMU child/process handle.
* [x] Stream or capture QEMU stderr/serial diagnostics.
* [x] Poll SSH/guest readiness.
* [x] Expose appliance states to frontend:

  * unavailable
  * preparing
  * starting
  * booting
  * ready
  * busy
  * stopping
  * stopped
  * failed
* [x] Add fixed guest health and transfer-proof APIs.
* [x] Avoid allowing arbitrary frontend command strings to be passed directly to a privileged guest shell.
* [x] Add structured results for supported operations.
* [x] Add graceful shutdown command.
* [x] Add timeout and kill fallback.
* [x] Guarantee managed-session shutdown and runtime cleanup on normal application exit.
* [x] Clean inactive abandoned session state on the next startup after a crash.
* [x] Ensure stale QEMU instances do not interfere with a new build through exact-child watchdogs, startup cleanup, and development-launcher cleanup.

---

# 11. Builder environment status model

* [x] Report host OS.
* [x] Report host architecture.
* [x] Report QEMU path/version.
* [x] Report QEMU smoke-test result.
* [x] Report appliance presence/path.
* [ ] Add appliance integrity status.
* [x] Add runtime preparation status.
* [x] Add guest boot status.
* [x] Add guest handshake status.
* [x] Add guest toolchain/self-test status to the prototype build flow.
* [x] Require the selected image and relevant environment state before enabling a real build.
* [ ] Add machine-readable error codes instead of relying only on human strings.
* [x] Keep user-facing messages simple while preserving detailed developer diagnostics and a bounded shareable summary.

---

# 12. Input image validation

* [x] Require selected path to exist and be a file.
* [x] Canonicalize selected path.
* [x] Accept supported image/compression extensions.
* [x] Inspect actual magic bytes instead of trusting extension alone.
* [x] Detect raw, bzip2, gzip, and xz content independently of filename.
* [x] Prefer multithreaded host 7-Zip for bzip2, then `pbzip2` and embedded Rust fallbacks, avoiding guest decompressor dependency.
* [x] Reject directories, device nodes, sockets, FIFOs, and unexpected special files before image preparation.
* [x] Determine source and normalized image sizes before QEMU launch.
* [ ] Verify sufficient host free space for decompression, working copy, overlays, and final output.
* [ ] Detect obvious non-SteamOS images before destructive or expensive processing.
* [x] Recognize the observed Valve recovery A-layout conservatively from GPT type GUIDs, labels, and filesystems.
* [x] Identify the SteamOS recovery image version/build from bounded target-root `os-release` data.
* [x] Record input SHA256 before and after read-only inspection and fail if it changes.
* [ ] Optionally verify known official Valve image hashes when trustworthy metadata is available.
* [x] Never treat an unknown image hash as the compatibility decision; use inspected layout and exact target identity instead.

---

# 13. Input decompression and normalization

* [x] Support raw `.img` input without unnecessary recompression for read-only inspection.
* [x] Decompress `.img.bz2`.
* [x] Decompress `.img.gz`.
* [x] Decompress `.img.xz`.
* [x] Stream decompression rather than loading the image into memory.
* [x] Use multithreaded bzip2 decompression on macOS while reserving one logical CPU for responsiveness.
* [x] Show live source-hashing, compressed-byte, and normalized-image hashing progress.
* [x] Keep post-inspection integrity hashing off the UI thread without blocking log/status IPC.
* [x] Bound normalized raw images to 64 GiB during embedded decompression, monitor external decompressor output, and reject empty/oversized normalized images before QEMU attachment.
* [x] Compute and verify the normalized raw-image checksum.
* [x] Keep original compressed input untouched and verify its checksum after the session.
* [x] Clean incomplete normalized images with the disposable-runtime guard after failure/cancellation.
* [x] Keep normalized raw storage in the host-side disposable runtime and expose only its block device to the guest.

---

# 14. Host-to-guest image transport

* [x] Use direct QEMU virtio block attachment for large recovery images rather than copying them through SSH.
* [x] Attach the selected raw host image directly as a QEMU block device for inspection.
* [x] Prove direct QEMU virtio block attachment with an isolated sparse synthetic image.
* [x] Avoid copying multi-gigabyte images over SSH.
* [x] Attach the user image read-only at the host/QEMU boundary for initial inspection; never mount it.
* [x] Attach a distinct writable qcow2 working layer for mutation.
* [x] Expose only explicitly validated image/appliance files as QEMU block devices; do not share unrelated host directories.
* [x] Canonicalize and validate the selected path before exposing it to QEMU.
* [x] Pass host paths as process arguments rather than shell fragments and cover spaces/Unicode in deterministic output naming.
* [x] Verify read-only block transport and structured inspection on Apple Silicon macOS first.
* [ ] Design transport abstraction that can be implemented on Windows and Linux.

---

# 15. SteamOS recovery-image discovery

* [x] Inventory partition table without mounting anything writable.
* [x] Record GPT/partition GUIDs, labels, filesystem types, offsets, and sizes.
* [x] Determine the labeled `rootfs-A`, `var-A`, and `efi-A` partitions relevant to mutation and installation.
* [x] Identify the observed ESP and `efi-A` partitions without relying on partition numbers.
* [x] Identify the observed Btrfs `rootfs-A` filesystem layout.
* [x] Identify root-owned `/usr` and `/etc`, separate `var-A`, and the recovery `home` installer assets without relying on fixed partition numbers.
* [ ] Determine whether Valve image layout varies by release.
* [x] Build layout detection around labels/metadata rather than hard-coded partition numbers where possible.
* [x] Keep unknown or ambiguous layouts non-actionable.
* [x] Produce a structured inspection report before first real NVIDIA modification.
* [x] Preserve a deterministic non-Valve DOS-partition fixture for the opt-in live inspection test.
* [x] Confirm bounded ELF architecture and `/usr/lib/modules` discovery against the current full-size Valve image (`x86_64`, kernel `6.16.12-valve24.4-1-neptune-616-gfe145653a794`).
* [x] Confirm SteamOS `VERSION_ID` discovery from a safe regular recovery-root `/etc/os-release` before `/usr/lib/os-release`; never infer certification from the host path or filename.

---

# 16. Safe image mutation framework

* [x] Always operate on a disposable qcow2 working layer.
* [x] Mount filesystems read-only during discovery and validation.
* [x] Escalate to writable mounts only for the explicit mutation phase.
* [x] Track every attached block device and guest mount.
* [x] Use cleanup guards/traps so mounts are released after failures.
* [x] Sync filesystems before detaching and export.
* [ ] Validate filesystem consistency after mutation where appropriate.
* [x] Preserve original partition offsets and sizes; the builder does not resize or repartition automatically.
* [x] Avoid repartitioning unless a future explicitly reviewed design requires it.
* [x] Record the bounded modified-path set in the output manifest.
* [x] Add deterministic marker-only mutation as the first synthetic integration test.
* [x] Verify the marker on the synthetic working copy and prove the source hash is unchanged.
* [ ] Verify second run does not accidentally modify the first input.
* [x] Verify the read-only source remains hash-identical after cancellation/failure paths.

---

# 17. First harmless image-mutation milestone

* [x] Copy/prepare selected SteamOS image into build workspace.
* [x] Attach it to Fedora guest as data.
* [x] Detect expected partition/filesystem.
* [x] Mount target filesystem on the disposable working layer only.
* [x] Write a project marker such as:

  * `/etc/steamos-nvidia-image-builder-test`
* [x] Include deterministic marker content with protocol/milestone data and no host-private information.
* [x] Unmount cleanly.
* [x] Stop the mutation VM before flattening its qcow2 working layer so conversion never races an open QEMU writer.
* [x] Return a separately named raw output image beside the selected input.
* [x] Verify input checksum remains unchanged after working-layer mutation.
* [x] Hot-unplug the guest-visible source before Btrfs mutation so duplicate filesystem UUIDs cannot redirect the mount.
* [x] Restore Valve's Btrfs read-only subvolume/seeding state after modifying only the disposable overlay.
* [x] Verify output checksum differs from the normalized unmodified source.
* [x] Re-open the candidate output through a fresh appliance, rediscover its layout, and verify the marker read-only before finalizing its name.
* [x] Make the UI report successful image mutation only after export validation succeeds.
* [x] Name prototype outputs `-marker.img`; never apply the `-nvidia.img` label before the complete NVIDIA payload has been installed and independently validated.

---

# 18. NVIDIA support integration strategy

Support-repository readiness (tracked here because it gates image-builder integration):

* [x] Add an offline-target build command that accepts explicit SteamOS, kernel, NVIDIA, architecture, and output parameters without using the appliance's running kernel as the target.
* [x] Add a non-mutating, machine-readable `--resolve-only` build plan.
* [x] Derive the exact Valve Neptune headers package and require the exact `/usr/lib/modules/<full-target-kernel>/build` tree.
* [x] Validate the headers archive paths and `.PKGINFO` package name, version, and `x86_64` architecture before extraction/use.
* [x] Require prepared target headers, `include/generated/autoconf.h`, and `Module.symvers`.
* [x] Validate the exact five-module NVIDIA set, x86_64 ELF architecture, and exact target-kernel vermagic before packaging.
* [x] Emit the archive, checksum, and build metadata format already accepted by the support installer.
* [x] Make the shared module validator and local contract checks compatible with macOS Bash 3.2; skip and clearly retain Fedora-only transaction coverage where modern Bash/Linux behavior is required.
* [x] Add non-network architecture-plan modes and separate macOS acquisition/launch paths for a development x86_64 Fedora appliance without replacing or colliding with the native appliance.
* [x] Add an isolated Rust-owned x86_64 build-appliance manager with disposable overlay/credentials, dynamic SSH forwarding, architecture health enforcement, bounded boot status, log access, graceful shutdown, forced-stop fallback, and abandoned-runtime cleanup.
* [x] Run abandoned-runtime reclamation on every direct appliance preparation path, not only Tauri application setup, so hard-aborted development tests are recovered by the next worker start.
* [x] Add an opt-in live lifecycle test that verifies x86_64 guest identity, runtime cleanup, log preservation, and base-appliance immutability.
* [x] Validate the isolated x86_64 lifecycle on Apple Silicon under TCG (`57.40s` in the first successful local run).
* [x] Add a controlled development build command that transfers an explicit support-repository checkout, streams the fixed offline-target build into managed logs, supports cancellation, and retrieves artifacts without exposing arbitrary guest commands.
* [x] Make progress-window cancellation and failure cleanup stop both the image appliance and the isolated x86 NVIDIA worker.
* [x] Validate returned development artifacts on the host for SHA-256, safe/exact archive membership, matching internal/external build metadata, requested target identity, and explicit unverified-header trust state.
* [x] Consume the support repository's versioned final build-result JSON for stable success/failure reasons, target/trust validation, artifact identity/hash checks, and preserved diagnostics; do not branch on human log text.
* [x] Preserve and validate the support repository's schema-1 provenance sidecar, require byte-identical embedded `PROVENANCE.json`, verify target/trust/pinned-signer/module metadata, and hash every archived module against its provenance record.
* [x] Gate NVIDIA artifact resolution on a valid SteamOS identity/version, x86_64 target architecture, and exactly one unique safe kernel release; zero or multiple discovered kernels remain non-actionable instead of selecting the first directory (`177.59s` real-image test passed for SteamOS 3.8.14 build `20260707.10`).
* [x] Run a real offline-target build inside an x86_64 Fedora environment (`30m15s` in the first successful Apple Silicon TCG run; `34m18s` for the initial result contract; `53m25s` for current support HEAD with pinned header signature, comprehensive module validation, and structured provenance).
* [x] Confirm Valve still serves the exact historical headers package for the observed SteamOS 3.8.14 `valve24.4` kernel (SHA-256 `dd532330d2bb34d4ab6b00ffb249d245ec882841a37694ae703548dab6d09f17`; package signature verification remains pending).
* [x] Confirm NVIDIA 575.64.05 produces all five modules with exact target vermagic.
* [x] Run the complete transaction/installer suite under Fedora with modern Bash; the managed x86_64 Fedora run passed all local contracts and fake-root transactions.
* [x] Exercise the support repository's offline-root installer with real recursive `/dev`, `/proc`, and `/sys` bind trees, real Arch package signatures/keyring preparation, and real process-group cancellation during validation and initramfs mutation; all mounts, children, and temporary validation files were released.
* [x] Consume the offline-root installer's fail-closed requirements: exact explicit root/kernel, archive/checksum/provenance, independently released matching userspace packages, detached signatures, reviewed binary keyring, GSP firmware, target-root pacman, depmod, and target mkinitcpio.
* [x] Consume the support repository's reviewed, hash-pinned Valve keyring manifest, require the exact header package's detached signature during development builds, and reject metadata that does not confirm pinned-keyring verification. Certification still requires the remaining compiler, provenance, and hardware gates.
* [x] Exercise an official NVIDIA upstream tag end to end through a lightweight managed x86_64 Fedora preflight: matching userspace indexes, exact tag commit, pinned support commit, source-repository URL propagation, and exact schema-1 target plan all agree before a long build is allowed (`148.57s`, NVIDIA `575.64.05`, SteamOS `3.8.14`).
* [ ] Reproduce Valve's GCC 15.1.1 kernel compiler for certified builds, or define and validate a documented compiler-mismatch policy; Fedora 44 currently supplies GCC 16.2.1 and the real development builds emit NVIDIA's mismatch warning. Support commit `e5d183e` fixes the tab-separated Valve compiler parser and its focused local contract test passes; confirm the corrected `15.1.1`/major-mismatch provenance on the next full build.
* [ ] Complete provenance identity across the appliance boundary. The support repo now emits and the image builder preserves/validates the structured provenance sidecar, but the image builder safely excludes `.git` from guest transfers, so the support commit/dirty fields remain `unknown`; add explicit, validated provenance inputs rather than copying Git credentials/hooks. Builder-appliance version/hash also remains to be recorded.

* [x] Consume the support repository's versioned schema-2 published-artifact contract in the image builder, including exact-kernel matching, bounded non-forward SteamOS-series fallback, required checksum/provenance assets, and pending trust until provenance verification. Keep contract tests synchronized until the support project provides a directly linkable Rust library or signed release index.
* [x] Define and consume a versioned machine-readable target-build result interface from the support repo; certified target resolution and offline-root installation remain separate contracts.
* [x] Resolve SteamOS version/kernel compatibility from the image contents rather than the host.
* [x] Resolve the appropriate published NVIDIA release for the target SteamOS image without promoting its provenance trust classification.
* [x] Preserve development/upstream modes as explicit advanced workflows rather than default end-user behavior.
* [x] Consume published release artifacts in the normal path; retain the support-repository Fedora build as an explicit future development fallback when no compatible publication exists.
* [x] Prefer published, provenance-bearing artifacts for normal users.
* [x] Before allowing future injection, verify GitHub asset digests, the archive checksum, byte-identical embedded/external provenance, pinned Valve header-signature identity, exact module hashes, architecture, version, and vermagic.
* [x] Resolve exact signed `nvidia-utils` and `lib32-nvidia-utils` inputs from the Arch Linux Archive without requiring their package releases to match; stage them through bounded cancellable downloads and keep signature trust pending until x86 appliance validation.
* [x] Immutably pin the support repository's offline installer, reviewed userspace lock, and minimal signer keyring for the normal workflow: exact support commit, nineteen required paths, byte counts, SHA-256 hashes, safe staging, cancellation cleanup, and a versioned bundle manifest are enforced without accepting a user-selected checkout or moving branch.
* [x] Transfer the verified module/userspace inputs into the managed x86_64 appliance, consume the pinned minimal reviewed binary keyring and lock, and validate the installer's structured result. Package-specific signer fingerprints, package versions/hashes, target identity, artifact trust/hash, mount cleanup, and schema/status are revalidated by Rust.
* [x] Stop the native mutation appliance without deleting its working qcow2, attach that working layer only to the x86_64 installer appliance, and mount the uniquely recognized `rootfs-A`, matching `var-A` at `<root>/var`, and matching `efi-A` at `<root>/efi` while leaving rootfs `<root>/boot` visible; validation mounts all three read-only, never guesses an A/B slot, and releases them before mutation or export.
* [x] Prevent the handed-off SteamOS disk from participating in x86 firmware boot selection: boot Fedora alone, then QMP-hotplug the working qcow2 through a dedicated PCIe root port after readiness.
* [x] Invoke the same pinned installer without `--validate-only` against the disposable overlay, require its structured `success/install_complete` result, verify NVIDIA-bearing initramfs contents, and discard the overlay after every failure or cancellation.
* [x] Run the newly integrated mutation path against the real SteamOS 3.8.14 recovery image and preserve the complete success/failure diagnostics. The exact build and canonical publication succeeded, while mutation failed closed in `userspace_install` because pacman could not read `<root>/var/lib/pacman`; no NVIDIA-labelled output was accepted.
* [x] Inspect the real recovery image's package/root semantics read-only: neither the mounted Btrfs root nor `var-A` contains `/var/lib/pacman`; `var-A` contains only `lib/overlays`, recovery `fstab` comments out `/var`, and SteamOS's actual package database is `/usr/lib/holo/pacmandb/local` with 1,158 package records (`43.62s` asserted live appliance test).
* [x] Require the recovery root's Holo pacman database before dependency setup and reject a pinned support installer before mutation unless its structured validation internally owns and reports the exact `/usr/lib/holo/pacmandb` selection; never initialize an empty database or expose a redundant caller override.
* [x] Pin reviewed support commit `8c11111787e064fc24d8c21652a8ffbfb08c9e5a` after its Holo database and EFI boot-policy changes; require exact byte/hash pins for every helper and require structured results to report `/usr/lib/holo/pacmandb`, a bounded nonzero package count, and the exact boot contract.
* [x] Mount `var-A` during independent output verification so installer state is read from the partition where mutation wrote it; verify exact Holo package versions, module version/vermagic, and the installed provenance hash instead of accepting filename patterns or mere file presence.
* [x] Inspect recovery boot storage read-only: rootfs `/boot` contains the Neptune kernel and both initramfs images, while `efi-A` contains `EFI/steamos/grub.cfg` and the EFI loader (`39.93s` asserted live appliance test).
* [x] Mount `efi-A` at `<root>/efi` across validation, mutation, and independent output verification; never hide rootfs `/boot` with the EFI filesystem before target `mkinitcpio` runs.
* [x] Update the pinned support installer to require the recovery EFI partition at `<root>/efi` while leaving rootfs `/boot` visible; add the required NVIDIA kernel command-line policy to `EFI/steamos/grub.cfg` without duplicating arguments on repeat runs, reject any structured-result policy drift, and independently verify every exported Linux entry contains each exact argument once.
* [x] Pin support commit `af36f43b2b1571d8c5c9a0d0379b094de7954715` after its validator and updater learned Valve's observed `steamenv_boot linux ...` GRUB entries, preserved that prefix on repeat runs, and adopted bounded limits compatible with the observed 632.5 MB project artifact.
* [x] Repin support commit `11a3cd914cb5a05829f667214b27e4dd8e2e206d` and consume its authoritative non-mutating storage contract: authenticated package installed sizes/dependency closure, replacement credit, module/initramfs requirements, root/var/EFI availability, Btrfs compression context, and stable `target_space_insufficient` failure.
* [x] Repin support commit `236b926c4cf29bdefbadad2b6fea85ef46c904dd` after real Holo database validation allowed unrelated records without `%ISIZE%`, retained exact size requirements for replaced packages, and added `packageRecord`/`invalidFields` diagnostics.
* [x] Rerun real SteamOS 3.8.14 `--validate-only` with the tolerant Holo parser; database validation passed and exposed the next fail-closed gate: signed `nvidia-utils` requires `egl-wayland`, which is absent from both the incoming two-package set and installed Holo providers, so no authoritative storage result was emitted.
* [x] Extend the support resolver/installer contract to return and accept the complete missing signed Arch dependency package set (beginning with `egl-wayland`), including exact filenames, versions, hashes, paired signatures, authenticated signer identities, declared installed sizes, and recursive dependency/provides metadata.
* [x] Generalize the Rust userspace handoff and result validation from exactly two NVIDIA packages to two required NVIDIA packages plus the resolver-owned dependency set; transfer every package/signature explicitly, require the same validated manifest at mutation, and never let target pacman fetch an unpinned dependency from the network.
* [x] Repin support commit `82a761622f682db62f58721e00bf329749ffb4a8`, verify all eight immutable installer files live, and exercise a bounded live host download of signed `egl-wayland` plus its detached signature.
* [x] Percent-decode safe Arch Archive path components before dependency version selection so epoch-bearing releases such as `egl-wayland` `4:1.1.21-1` outrank obsolete non-epoch packages and retain their matching reviewed signatures.
* [x] Replace incremental latest-package dependency discovery with the first versioned, support-repository-owned userspace lock (SteamOS 3.8.14/NVIDIA 575.64.05): resolve the complete transitive closure before an end-user build, pin exact filenames/versions/hashes/signatures/package-specific signer fingerprints, authenticate every signer against reviewed Arch key material, and require maintainer review rather than expanding trust at runtime. Additional supported target/version pairs require their own reviewed lock.
* [x] Make normal validation consume the complete locked dependency set in one bounded handoff; report a missing lock or any unknown/changed package, hash, signature, keyring, or signer as a maintainer compatibility gate instead of making users repeat builds one dependency at a time.
* [x] Preserve every reviewed package and detached-signature filename across the x86 guest handoff so the support validator can compare the incoming set exactly to the userspace lock; reject unsafe guest filename characters instead of substituting generic dependency names.
* [x] Repin support commit `bf2a6568755766e6af527c9b2cbb831e33d206b9` and surface its bounded aggregate lock diagnostics: every missing, unexpected, duplicate, and mismatched package is listed in one failure, with all mismatched field names and expected/actual values retained in structured logs.
* [x] Include every newly installed dependency and replacement in `validation.storage` and rerun real SteamOS 3.8.14 validation. The exact authenticated closure passed, then failed closed before mutation with authoritative accounting: rootfs-A requires 1,450,249,413 bytes, has 908,500,992, and is short by 541,748,421 bytes; var-A and efi-A are sufficient.
* [x] Repin support commit `fc3cdc54a5256470da50b81f9b38aca150afcc42`, request its validation-only `btrfs-zstd3` profile, and strictly consume the exact provenance hash, reviewed-lock identity, complete package records, dependency closure, and measured physical-allocation contract. Keep mutation blocked while the pinned result reports `mutationProfileImplemented=false`.
* [x] Rerun the real SteamOS 3.8.14 overlay through the pinned measured-compression validator and independently consume its measured payload, required-byte, reserve, and projected-margin contract.
* [x] Repin support commit `7c07018149dea6a7e14548ceb12c3b1ea0fe88b9`, require its fail-closed `compress-force=zstd:3` mutation profile, validate per-package/module allocation and exact-payload no-op credits, and independently require restoration of the caller's original root mount compression option.
* [x] Run the large scratch-Btrfs measurement under disk-backed appliance `/var/tmp` instead of sharing the 2 GiB RAM-backed `/tmp` with the authenticated packages and module archive.
* [x] Repin support commit `78e9ae8a65c001a97dd6594ab6837589dc8042a8`, consume its bounded structured measurement failure phase, approved command identity, exit status, and safe stderr summary, require cleanup to report both released mounts and restored compression policy, and pin its independent installed-payload verifiers plus reviewed gaming/no-CUDA policy contract.
* [x] Repin support commit `2a6d97ec08d8767d738b815d15e5b6660d89f02f`, stage its symlink-safe atomic-output helper, and consume bounded file-backed measurement/publication validation so large artifacts are never retained wholly in memory and partial result files fail closed.
* [x] Apply and validate every pinned support file's executable/data mode before packaging, then enforce the exact modes again inside Fedora after extraction so direct helper execution works independently of macOS/Windows host archive semantics.
* [x] Repin support commit `f8c569c72fc6c1ecfba3d1a87235886f09baaa63`, whose validator launches the measurement helper through its exact Python interpreter and preserves a bounded, path-sanitized `OSError` when process creation itself fails.
* [x] Repin support commit `6d02c3167f115044b72bc8feb81724574d6be3c1`, stage its confined pacman-config helper, and require the authenticated measured-space result to authorize the scoped `CheckSpace` exception while every conservative or insufficient-space path preserves it.
* [x] Repin support commit `d6cb08d3508361e1b1804e37a67a2b3c07116b1e`, including recursive runtime-mount cleanup, canonical compressed-module installation, aggregate installed-module verification, preserved structured results, and real mutation progress.
* [x] Repin support commit `420688d1ea8c1b0e7a7d16d9a9361d0f3788bf1d`, including authenticated input snapshots, target lifecycle/mount guards, private initramfs workspaces, bounded package transactions, structured userspace verification, and the disposable headless Linux harness.
* [x] Repin support commit `e93bd5b91f8b645d27090fb5963edfd6613bbe68`, adding exact runtime bind-mount topology verification and its newly required pinned verifier without changing unrelated bundle files.
* [x] Repin support commit `ee8ce07b628a8b9943773657389034943fea66e4`, adding bounded target-owned pacman-hook and initramfs-input snapshots plus immediate pre-execution revalidation.
* [x] Repin support commit `9f3f1918846dea4fc3068d651451133207653fe5`, adding bounded generated-initramfs content verification and requiring its structured successful-result evidence.
* [x] Repin support commit `099192ecdf8e1853529d4d02cb9a27becc621a09`; pin and execute its bounded result/progress contract validator, require its exact module/userspace/initramfs success proofs, preserve its rootfs-resident payload receipt, and reject missing or inconsistent `receiptId` evidence before export.
* [x] Repin support commit `6aecdc28a169cdd3723683551a5e997e5f0bf838` after real-image validation exposed repeated per-file hashing sequences; require one fixed-total, monotonic aggregate over every authenticated installer input and retain strict regression rejection in both the support and UI consumers.
* [x] Repin support commit `0b09b55998eaca30f705ef8fe5ea56314607dfc8`, pin all fourteen recovery-guardian additions by exact size/hash/mode, and include the exact snapshot in generated installation media for offline target staging.
* [x] Repin support commit `2f6f133485f68ed09abf58b8a49ad67b985dd2e6`, including its crash-safe Desktop companion generation manager, fail-closed launcher, and intentionally unconfigured release-signer policy. Preserve the trust gate instead of inventing a caller override.
* [x] Repin support commit `305f1199f5745136902de1c88655a9192fb91de3` after its desktop generation manager bound launch to a revalidated, write-sealed Linux `memfd`, authenticated stored trust metadata on every lifecycle operation, and returned stable bounded failure reasons. Keep the release-signer policy fail-closed.
* [ ] After a real Valve `repair_device.sh` installation, verify the installed rootfs receipt with the pinned support helper and require the exact image-build `receiptId` before independently checking the installed payload. A matching receipt proves propagation only—not graphical boot, rollback, or hardware certification.
* [x] Repin offline-installer commit `bf4863910fb58c80ed920fdea1768b5dcf466023`, including authenticated offline bundles/cache hardening, deterministic reviewed gaming-payload support, and confined SteamOS execution-symlink handling; pin the newly mandatory repacker import and verify every file from the public commit.
* [x] Repin offline-installer commit `93285dc176f65964daa6d0c0c01f01e53ab7506e`, consume its bounded dynamic-inode probe evidence, distinguish the four-module early-boot initramfs contract from rootfs-only `nvidia-peermem`, and stop treating Btrfs's all-zero inode counters as exhaustion while still requiring allocation-and-cleanup proof before mutation.
* [x] Advance only the installer snapshot to `b443727ec6a3dd854374e4f4ea997403992353fa`, pin its two authenticated-bundle runtime helpers plus the two changed production files, and retain typed source-mode/cache-ID provenance without moving unrelated build or publisher pins.
* [x] Compare reviewed and validated package dependency/provider relations as bounded canonical sets: accept order-only normalization, reject duplicates, unsafe syntax, or membership drift, and report every differing package field in one builder error.
* [ ] Run the compressed mutation against the real SteamOS 3.8.14 overlay, then independently verify final package contents, modules, initramfs, Btrfs policy, cancellation cleanup, repeat execution, and the remaining free-space margin before exporting.
* [x] Normalize the verified archive checksum sidecar to the builder's fixed guest archive basename before handoff, while retaining the Rust-owned digest and requiring the pinned support validator to independently rehash the transferred bytes.
* [x] Harden the support installer against hostile/corrupt target-root symlinks for every mutation destination (`usr/lib/modules`, firmware, `/etc` policy, Holo database, `/boot`, and persistent state), and require the `/efi` mount to be a distinct expected FAT filesystem before mutation.
* [x] Bound decompressed module/member sizes and reject every noncanonical extra archive member during support publication, builder ingestion, and installation; keep the builder aligned with the pinned support contract (1 GiB/member, 2 GiB total) so an accepted canonical artifact is not rejected by a stale lower limit.
* [x] Carry verified compressed/expanded archive sizes into the x86 handoff, reject post-validation size changes, and preflight conservative appliance staging space before transfer.
* [x] Replace the builder's heuristic target multiplier with the support installer's authenticated dependency closure, package/replacement/module/initramfs totals, and structured partition-specific storage result; do not mutate or automatically resize after an authoritative failure.
* [x] Validate real Holo package-record contents (including known SteamOS base records), not only a nonzero count of confined regular `desc` files.
* [ ] Add a read-only repeat-build preflight that mounts both the selected rootfs and `var-A`, validates the offline install state (`kernel-version`, `nvidia-version`, `BUILD-INFO.txt`, and `PROVENANCE.json`), and never infers installed state from an `-nvidia` filename.
* [ ] Treat a fully verified identical SteamOS/kernel/NVIDIA/artifact state as `already_current`: skip download, compilation, publication, package installation, module replacement, and initramfs regeneration, while still independently validating the selected image.
* [ ] Treat a valid but different NVIDIA version or exact target kernel as an explicit upgrade; treat partial, malformed, mismatched, or unverifiable state as a fail-closed repair/error path rather than silently overwriting it.
* [ ] Add real-image repeat-run tests proving identical input is byte-for-byte unchanged and upgrade tests proving the original image remains untouched while only the disposable output changes.
* [x] Record selected NVIDIA driver version in the NVIDIA-mutation build manifest.
* [x] Record selected SteamOS/kernel target and artifact trust classification in the NVIDIA-mutation build manifest.
* [x] Fail closed when no compatible published release exists; the normal workflow never silently enters development build mode.
* [x] Treat “no compatible published artifact” as a normal, non-destructive resolution result with a clear UI/log status; do not create an NVIDIA-labeled output or classify it as an application failure.
* [x] Require exact target-kernel identity/vermagic for NVIDIA artifacts; never reuse the SteamOS 3.8.16 `valve24.5` modules for the observed 3.8.14 `valve24.4` kernel.
* [x] Connect the Rust-managed x86_64 Fedora build-appliance commands to the normal build workflow and progress UI on Apple Silicon, including boot, stable compiler subphases, elapsed-time guidance, live logs, cancellation, artifact retrieval, validation, and installation handoff.
* [x] Use the separately managed, disposable emulated x86_64 Fedora appliance on Apple Silicon; do not depend on a remote build worker.

---

# 19. NVIDIA kernel-module injection

* [x] Determine target kernel(s) contained in the recovery image through safe module-directory inventory.
* [x] Place all required open NVIDIA modules in the correct target module tree through the pinned support installer.
* [x] Support compressed `.ko.zst` modules where SteamOS expects them.
* [x] Preserve exact kernel vermagic compatibility through provenance validation before mutation.
* [x] Run target-image `depmod` appropriately.
* [x] Require the generated initramfs to contain `nvidia`, `nvidia-modeset`, `nvidia-uvm`, and `nvidia-drm` before export.
* [x] Add the four required NVIDIA modules to the target mkinitcpio configuration.
* [x] Configure `nvidia-drm` modeset/fbdev through the pinned project modprobe policy.
* [x] Replace the project-owned target module directory rather than leaving stale project module versions.
* [x] Verify all five target image module paths independently after export.
* [x] Preserve structured provenance, kernel, and NVIDIA version state for debugging even though output image mutation remains disposable until finalization.

---

# 20. NVIDIA userspace injection

* [x] Install matching authenticated NVIDIA userspace libraries into the target image through target-root pacman semantics.
* [x] Install authenticated 32-bit userspace libraries where Steam/games require them.
* [x] Keep userspace and kernel-module NVIDIA versions matched through preflight and final result validation.
* [ ] Verify EGL/GLX/Vulkan loader integration.
* [ ] Verify Vulkan ICD files.
* [ ] Verify NVIDIA GBM/EGL loader paths.
* [ ] Avoid overwriting unrelated Mesa/AMD/Intel userspace unnecessarily.
* [ ] Preserve the ability for the resulting SteamOS image to run on the intended NVIDIA system without requiring network access during first boot.
* [ ] Document whether the generated image remains multi-GPU-capable.
* [ ] Detect the target machine's GPU topology and display-owner relationship before enabling a hardware profile; distinguish discrete-only, muxed, muxless/hybrid, and iGPU-driven boot displays without assuming that the NVIDIA device owns the internal panel.

---

# 22. SteamOS boot and first-boot integration

* [ ] Determine which image-time changes survive the Valve installer/recovery process.
* [ ] Verify NVIDIA files injected into recovery media are copied into installed SteamOS as intended.
* [ ] Treat the recovery image as a multi-part install contract: place the NVIDIA/userspace payload and persistent configuration in `rootfs-A`, bootloader changes in `efi-A`, and installer tools/desktop launchers in the `home` partition.
* [x] Locate Valve's `/home/deck/tools/repair_device.sh` through the inspected `home` filesystem role rather than a fixed partition number, leave the stock file unchanged, and reject incompatible structure instead of applying a partial installer patch.
* [x] Stage the double-click installer under `/home/deck/tools` and `/home/deck/Desktop` with the required modes and `deck` ownership; independently validate every staged path before declaring the output install-ready.
* [x] Ensure the desktop action invokes a fixed project-owned frontend which delegates only bounded operations to a root-owned protected Valve installer copy; never expose arbitrary guest or host commands through the launcher.
* [ ] Verify that Valve's clone-based install propagates the patched running recovery root into the installed SteamOS system, rather than assuming a successful recovery-image mutation guarantees an installed-system change.
* [x] Modify the protected recovery installer copy only where required, with minimal auditable guarded patches and an explicit fail-closed structure check for the supported Valve recovery build.
* [x] Avoid brittle assumptions about target install disk names.
* [ ] Confirm the generated recovery image does not reproduce the earlier wrong-disk/Optane selection problem without clear user control.
* [x] Confirm from the real SteamOS 3.8.14 media that Valve's installer hard-codes `/dev/nvme0n1` plus the `p` partition suffix, then replace those assumptions only in the protected OPEMOS delegate.
* [x] Require a target-disk picker, exclude the booted recovery medium, validate the selected block device, and show a final destructive confirmation before a fresh install.
* [x] Keep fresh-install and system-upgrade modes distinct; require upgrade mode to recognize an existing SteamOS layout and invoke Valve's `system` path, which preserves the target `home` partition.
* [x] Pass the selected target disk explicitly to a protected installer delegate without hard-coding NVMe naming, including correct partition suffix handling for NVMe and non-NVMe devices.
* [x] Bundle an **Open OPEMOS** welcome application in newly generated installation media and start it automatically in the recovery desktop. Offer fresh install, reinstall-with-home-preserved, and rollback as distinct actions.
* [x] Enumerate only eligible whole physical disks in the installation-media welcome flow, exclude the booted recovery medium, reject mounted/read-only/undersized targets, bind the choice to a hardware identity digest, revalidate it immediately before mutation, and require a typed device-specific confirmation.
* [x] Keep the installation-media frontend unprivileged and delegate only a fixed `all` or `system` operation to a root-owned guarded copy of Valve's compatible `repair_device.sh`. Never execute a desktop-user-owned privileged helper or rewrite installer text at runtime.
* [x] Skip Steam Deck-specific BIOS/controller firmware operations and firmware secure erase on generic OPEMOS installs. Continue with explicit repartition/filesystem creation, preserve an install log, prevent the stock infinite error wait, and return completion control to the welcome application.
* [ ] Replace the guaranteed-runtime Zenity welcome surface with the full OPEMOS frosted-glass native UI while retaining the same helper protocol and an opaque/terminal-safe fallback.
  * [x] Apply a bundled OPEMOS glass GTK theme to the guaranteed Zenity fallback, prevent duplicate welcome instances, retain private installation logs across window restarts, and expose media/disk diagnostics without adding privileged UI code.
  * [x] Exercise the exact installation-media helper inside the isolated x86_64 headless VM against a sparse eligible virtio target, an LVM-backed recovery root, and undersized decoys; require one stable target identity without writing the eligible fixture.
  * [x] Add `test_welcome_macos.sh`, an interactive no-privilege graphical simulation with fixed synthetic disks, typed-confirmation behavior, mocked installation/A/B progress, recovery, and diagnostics screens.
  * [x] End successful installation with explicit Shut Down, Restart, and Stay Here choices; recommend shutdown and explain how to avoid rebooting into the installation USB again.
* [x] Add a generated-media manifest receipt and fresh read-only verification for the welcome application, protected helper/delegate, desktop launcher, icon, and autostart entry. Reject completed images created before that receipt exists instead of silently treating them as current install-ready output.
* [ ] Exercise fresh install and reinstall against sacrificial NVMe, SATA, virtio, USB, 4K-logical-sector, multiple-identical-disk, hot-unplug, mounted-child, and device-renumbering scenarios before calling arbitrary-hardware installation production-ready.
* [ ] Design and stage a project-owned SteamOS Storage Manager desktop launcher with the generated media, then verify that Valve installation propagates it to the installed system rather than leaving it available only in recovery mode.
* [ ] Integrate the support repository's separate persistent **Open OPEMOS Desktop** application into the installed target through its canonical one-line installer. It—not the installation-media welcome app—owns exact slot/kernel/NVIDIA health, fallback state, connectivity, release discovery, rebuild/install/verification progress, rollback, and post-install storage actions through the support-owned machine-readable contract.
* [ ] Keep the persistent Open OPEMOS Desktop frontend unprivileged. Pass only bounded, enumerated actions and revalidated device/slot identity documents to the privileged support helper; never regex-rewrite a device name, slot, command, or user input into a shell script.
* [ ] Reuse the OPEMOS frosted-glass component language in the persistent installed application with an opaque dark fallback where compositor transparency is unavailable. Keep console/TTY status usable when Desktop Mode or graphics cannot start.
* [ ] Give the Storage Manager a bounded graphical drive picker for mount, unmount, format, and wipe operations; identify whole devices and partitions clearly, exclude the running system and recovery media, and never construct arbitrary shell commands from UI text.
* [ ] Support deliberate multi-drive selection for bulk mount or wipe only after every device identity is independently revalidated. Require a conspicuous destructive summary and explicit confirmation that names every affected physical drive.
* [ ] Add opt-in persistent automount by filesystem UUID with an explicit mount policy that survives reboot and works in both Desktop and Gaming Mode. Missing/replaced drives must fail safely without delaying or breaking boot.
* [ ] Keep one-time mounting separate from persistent automount, preserve existing user data unless format/wipe is explicitly chosen, and add hardware tests for USB disks, SD-card readers, multiple identical devices, sleep/wake, unplug/replug, and partial bulk-operation failure.
* [ ] Ensure NVIDIA setup occurs before first Gaming Mode launch.
* [ ] Verify first boot without manual TTY intervention.
* [ ] Verify first boot without network access if all required artifacts are embedded.
* [ ] After installing from generated media, boot without the recovery USB and verify NVIDIA modules, boot arguments, updater integration, desktop account state, and A/B update behavior on the installed disk.
* [ ] Verify rollback/recovery path if NVIDIA initialization fails.
  * [x] After Valve installation completes through Open OPEMOS, install the pinned support recovery guardian into both target A/B slots and their shared home, bound to the exact support commit and NVIDIA version.
  * [x] Independently reopen generated media read-only and verify every embedded guardian snapshot file, mode, owner, support revision, and NVIDIA version before accepting the output manifest.
  * [ ] Hardware-test guardian propagation, offline wait, delayed connectivity, exact-release repair, cancellation, failed graphical boot, and A/B rollback on the installed target.
* [ ] Add a fail-closed installed-system update guardian: bind the staged inactive A/B slot and exact kernel identity, resolve/build the selected NVIDIA policy, run the reviewed support installer, independently verify modules/userspace/firmware/initramfs/boot policy, and permit the slot switch only after success.
* [ ] Persist update-guardian state and bounded diagnostics outside the replaceable root slot. Resume or roll back interrupted download/build/install/verification transactions without trusting a partial result.
* [ ] Preserve the last verified boot slot and use a bounded first-boot graphical health check plus boot-attempt accounting to fall back automatically when NVIDIA, DRM, the display manager, or Gamescope does not reach the required state.
* [ ] Provide an explicit NVIDIA recovery boot entry that reaches a console-safe rescue environment without Gaming Mode; validate its exact Valve boot configuration and never infer edits for an unknown layout.
* [ ] Implement recovery graphics as tested tiers: prefer an Intel/AMD iGPU when it can own a display, otherwise retain a firmware-framebuffer console, and enable Nouveau only for an explicitly validated GPU/kernel/Mesa/GSP profile. Treat every tier as recovery-only rather than gaming certification.
* [ ] Give a Nouveau recovery entry a separately validated initramfs and command line that disables all NVIDIA modules and omits the normal Nouveau blacklist; prove the two drivers cannot bind the same GPU or contaminate the normal boot configuration.
* [ ] Add a non-destructive “Roll back last SteamOS update” action to the generated recovery USB. Revalidate installed-disk and A/B identities, show the active and previous versions, and change only the recognized boot selection—never reinstall or wipe user data as part of rollback.
  * [x] Bundle a terminal-backed recovery launcher into the generated media's persistent home partition; require explicit disk and eligible-slot selection, exact confirmation, and Valve's disk-scoped boot-selection tools.
  * [x] Independently re-open the generated image and verify the recovery script/launcher hashes, modes, regular-file identities, and released home mount before export succeeds.
  * [ ] Replace the terminal selector with the bounded graphical recovery surface, record current/selected bootconf state in a structured result, and pass sacrificial-disk A/B rollback plus cancellation testing before describing the action as production-ready.
* [ ] Show honest installed-update phases before reboot and mirror them to a persistent log/console-safe status path because the compositor may disappear during graphics work. Never represent heartbeats as percentage completion.
* [ ] Keep the update guardian fail-closed under network loss, missing exact headers/artifacts, signer/lock drift, insufficient storage, cancellation, power loss, and unsupported future result schemas; never copy the legacy installer's unsigned `SigLevel = Never` fallback.
* [ ] Make update policy honor the image manifest: Automatic may select only a certified compatible profile, while a pinned NVIDIA source/version remains pinned and pauses the update when its exact new-kernel artifact cannot be produced.
* [ ] Add an installed-system diagnostics/export UI that remains reachable from Desktop Mode or a TTY and reports active/candidate slot, running/candidate kernel, module vermagic, userspace/GSP versions, last update transaction, and stable failure reason without secrets.
* [ ] Inventory target Wi-Fi by PCI/USB identity, bound kernel module, requested firmware filenames, rfkill state, and NetworkManager state reason; classify missing device, missing driver, missing firmware, blocked radio, authentication, and IP failures separately.
* [ ] Define reviewed non-Deck hardware profiles for required in-tree Wi-Fi modules and authenticated firmware. Verify the exact kernel/initramfs contains them, preserve the profile across both A/B slots and updates, and reject arbitrary first-boot/out-of-tree driver downloads.

---

# 23. Output-image construction

* [x] Produce a distinct, non-overwriting output filename.
* [x] Preserve raw `.img` output as the canonical first format.
* [ ] Decide whether to offer optional `.xz`, `.gz`, or `.bz2` compression.
* [x] Compute final SHA256.
* [x] Write a versioned marker/NVIDIA-mutation sidecar build manifest atomically beside the output.
* [ ] Distinguish `mutation-valid` output from `install-ready` output; require verified `rootfs-A`, `efi-A`, and `home` installer assets before using the latter status.
* [x] Include input hash, app version, appliance identity/hashes, SteamOS/kernel identity, NVIDIA version/trust, support commit, packages/signers, and modification summary.
* [x] Never embed the user’s full host path or username into the output image or sidecar manifest.
* [x] Verify the candidate raw image's GPT/filesystem roles before atomic finalization.
* [ ] Verify output can be opened by standard flashing tools.
* [x] Reveal output in Finder on the current macOS target.

---

# 24. Output validation before success

* [x] Re-open the candidate final image read-only through a fresh validation appliance.
* [x] Re-run conservative Valve partition discovery.
* [x] Verify all five required NVIDIA kernel modules exist in the independently attached candidate.
* [x] Verify matching userspace package records and exact-version GSP firmware exist in the independently attached candidate.
* [x] Verify NVIDIA-bearing initramfs contents before export and independently verify the persisted mkinitcpio configuration plus nonempty initramfs output afterward.
* [x] Verify all installer, Btrfs-top-level, root, EFI, and independent-validation mounts are released.
* [ ] Verify no runtime SSH keys or Fedora guest secrets leaked into SteamOS output.
* [ ] Verify no Fedora appliance files were copied into SteamOS accidentally.
* [ ] Verify filesystem health.
* [x] Emit the marker/NVIDIA-mutation validation report as a versioned sidecar manifest.
* [x] Do not show completion unless candidate layout, marker, size, hashes, source immutability, and—when selected—the NVIDIA payload validation pass.

---

# 25. Boot validation automation

* [ ] Determine what portions of the x86 SteamOS output can be boot-tested under QEMU on x86 hosts.
* [x] Add independent structural output validation on Apple Silicon without claiming it is a hardware boot test.
* [ ] Consider CI boot smoke tests on x86_64 Linux runners with virtualization access.
* [x] Detect the expected EFI loader/GRUB configuration during inspected recovery-layout validation.
* [x] Detect the target kernel and require a nonempty NVIDIA-bearing initramfs before export.
* [ ] Verify generated image reaches an expected recovery/install stage where feasible.
* [ ] Keep VM boot validation distinct from real NVIDIA hardware validation.

---

# 26. Real hardware validation

## Primary NVIDIA laptop baseline

* [ ] Test generated recovery image on HP Omen 15 / RTX 2060-class hardware.
* [ ] Verify recovery UI is usable.
* [ ] Verify installer targets the intended primary NVMe device.
* [ ] Verify installation completes.
* [ ] Verify reboot reaches SteamOS.
* [ ] Verify `nvidia-smi`.
* [ ] Verify `modinfo`.
* [ ] Verify `/proc/driver/nvidia/version`.
* [ ] Verify Gaming Mode uses the NVIDIA GPU.
* [ ] Verify Xwayland/Steam use NVIDIA GPU.
* [ ] Verify Gaming Mode.
* [ ] Verify Desktop Mode.
* [ ] Verify game launch through Proton.
* [ ] Verify suspend/resume.
* [ ] Verify HDMI/external display if applicable.
* [ ] Verify no NVIDIA Xid faults during basic test cycle.

## Additional hardware

* [ ] Test another Turing NVIDIA GPU.
* [ ] Test Ampere GPU such as RTX 3080.
* [ ] Test laptop hybrid-graphics system.
* [ ] Test desktop discrete-NVIDIA-only system.
* [ ] Test Wi-Fi on representative Intel, Realtek, Qualcomm/Atheros, Broadcom, and MediaTek controllers only after recording exact PCI/USB IDs, in-tree driver, firmware identity, NetworkManager result, suspend/resume, and A/B-update survival.
* [ ] Inject an update with an unavailable exact NVIDIA artifact, failed signature, failed module build, failed initramfs verification, power loss, and failed first graphical boot; each case must retain or automatically return to the last verified slot.
* [ ] Track unsupported generations explicitly.
* [ ] Build compatibility matrix by SteamOS release, kernel, NVIDIA release, and GPU generation.

---

# 27. Build reproducibility

* [ ] Pin Fedora appliance source sufficiently for release reproducibility.
* [x] Pin downloaded project support code and selected release artifacts to immutable commit/asset identities.
* [x] Record and verify checksums for every build-critical downloaded artifact currently consumed by the NVIDIA path.
* [ ] Avoid resolving “latest” silently during reproducible build mode.
* [x] Version the builder protocol.
* [x] Version the modification manifest schema.
* [ ] Make two builds from identical input/configuration structurally reproducible where timestamps/UUIDs allow.
* [ ] Identify unavoidable nondeterministic fields.
* [ ] Normalize timestamps where safe and appropriate.
* [ ] Add reproducibility test comparing repeated outputs.

---

# 28. Supply-chain and download security

* [x] Verify Fedora image checksum.
* [ ] Require Fedora signature verification for production.
* [x] Use HTTPS for all current production-path downloads.
* [x] Verify GitHub release artifact hashes, checksum sidecars, and provenance before mutation.
* [x] Pin the expected repository, owner, commit, and asset identity for project artifacts.
* [x] Bound downloads and reject unexpected HTTP/content/archive results rather than trusting filenames.
* [x] Never shell-pipe unverified downloaded code in the application workflow; stage and verify pinned support files before execution.
* [x] Verify downloaded archive/file structure, sizes, hashes, signatures, and target metadata before use.
* [ ] Keep network retrieval logic centralized and auditable.
* [x] Record artifact, package, signer, appliance, and support provenance in the build manifest.
* [ ] Add an offline mode once required artifacts can be pre-cached safely.
* [x] Preserve reviewed signer policy, exact hashes, keyring provenance, and userspace locks as pinned project trust material; require reviewed updates rather than runtime trust expansion.
* [ ] Add a content-addressed project backup for authenticated upstream inputs that may disappear (Arch packages/signatures/repository databases and Valve headers/signatures), using GitHub release assets or separate object storage rather than committing large binaries to Git; mirror only when redistribution terms permit.
* [ ] Treat a project mirror only as an availability fallback, never as a new trust root: every restored byte must still match the Git-pinned hash, detached signature, exact package identity, and reviewed signer policy, with no closest-version substitution.
* [ ] Add a maintainer command that exports/imports a complete audited offline bundle and inventory so reviewed locks remain reproducible if an upstream archive is temporarily unavailable.

---

# 29. Security boundaries

* [x] Keep image manipulation inside a Linux guest rather than granting broad host root privileges.
* [x] Bind guest SSH to localhost only during development.
* [x] Use dedicated guest account.
* [x] Remove guest password authentication from the application workflow.
* [x] Restrict the guest command API to backend-owned fixed operations.
* [x] Avoid exposing arbitrary host filesystem paths to the guest.
* [x] Canonicalize and validate every host path passed to QEMU.
* [x] Treat the selected recovery image and all target-root metadata as untrusted input.
* [x] Mount untrusted filesystems read-only for discovery/validation and use confined explicit mutation mounts.
* [x] Avoid executing target-image binaries except for the explicit architecture-correct offline transaction/initramfs contract in the isolated x86_64 appliance.
* [ ] Keep QEMU networking disabled unless the guest actually needs network access for a stage.
* [ ] Prefer host-mediated verified downloads over unrestricted guest downloads for release builds.
* [ ] Audit temp-file permissions.
* [x] Create runtime SSH private keys with confined permissions and test their ephemeral lifecycle.
* [x] Remove runtime credentials with disposable session cleanup and exclude them from shareable diagnostics/manifests.
* [ ] Enable a restrictive production Content Security Policy for the local
  frontend and test all three windows under it; `csp: null` must not ship.
* [ ] Replace broad `dialog:default` and `opener:default` grants with the minimum
  per-window permissions and URL/path scopes. Prefer fixed backend-owned actions
  for the Valve download page and output reveal operation.
* [ ] Give the normal, progress, and maintainer windows separate Tauri
  capabilities. Explicitly include the dynamically created maintainer window,
  but expose maintainer operations only there and continue reauthorizing every
  remote mutation in Rust.
* [ ] Evaluate removing `withGlobalTauri` after frontend modules are organized;
  use explicit API imports/build tooling if the security and packaging benefit
  justifies the change.

---

# 30. Large-file and disk-space management

* [ ] Estimate required disk space before the entire build. (The NVIDIA x86 handoff and authoritative target-root validation now have bounded preflights; host image normalization/export remain.)
* [ ] Account for compressed input size.
* [x] Account for decompressed image size after normalization and before guest startup.
* [x] Account conservatively for worst-case qcow2 working-overlay growth.
* [x] Account for the final raw output image.
* [ ] Add safety reserves to every large-file phase. (NVIDIA appliance handoff and target-root mutation are covered.)
* [ ] Choose workspace filesystem deliberately.
* [x] Avoid duplicating multi-gigabyte image data unnecessarily by attaching the source directly and mutating a qcow2 overlay.
* [x] Use sparse/qcow2 copy-on-write storage for disposable image and appliance work.
* [x] Report conservative host disk-space failure before guest startup and target-space failure before mutation.
* [x] Clean partial runtime/output artifacts after failure or cancellation.
* [x] Preserve atomically finalized output when later runtime cleanup succeeds.

---

# 31. Progress reporting

* [x] Define structured prototype build stages in the progress UI.
* [x] Report current backend stage to the frontend.
* [x] Add stage/substep percentages where meaningful.
* [x] Use indeterminate progress for operations with unknown duration instead of fake linear percentages.
* [x] Show real byte progress during hashing, decompression, transfer, and export where available.
* [x] Show appliance startup separately from prototype output creation.
* [x] Show NVIDIA build, validation, mutation, and independent output-validation stages separately.
* [x] Preserve and display the current session's QEMU/serial log through completion.
* [x] Auto-follow live logs only while the viewer remains at the bottom; preserve manual scroll position otherwise.
* [x] Freeze visual log updates while the user scrolls through active output, then catch up once when live following resumes.
* [x] Append only new ANSI log output instead of reparsing and replacing the complete terminal buffer.
* [x] Run SSH, disk, handshake, and log-reading commands on blocking workers instead of the Tauri UI thread.
* [x] Reserve host CPU capacity and throttle decompression progress updates so the windows remain interactive.
* [x] Keep synthetic working-copy mutation retry-safe when the guest kernel temporarily reports a busy partition-table reread.
* [x] Skip unchanged log redraws and keep progress-status geometry stable across message changes.
* [x] Render ANSI SGR colors safely while normalizing unsupported terminal cursor/control sequences.
* [x] Preserve overlap across bursty Fedora/compiler output with a bounded 256 KiB-per-source live window instead of dropping output at the former 32 KiB boundary.
* [x] Use an honest indeterminate progress bar, stable log-derived subphases, elapsed time, and delayed long-build guidance for x86_64 compilation rather than inventing a linear ETA.
* [x] Add a “Copy Diagnostic Log” action with bounded noise removal and secret/path redaction.
* [x] Keep normal prototype success UX concise.

---

# 32. Error handling and recovery

* [ ] Define typed errors for host dependency failure.
* [ ] Define typed errors for appliance boot failure.
* [ ] Define typed errors for guest handshake failure.
* [ ] Define typed errors for invalid image layout.
* [ ] Define typed errors for insufficient disk space.
* [ ] Define typed errors for mount/filesystem failure.
* [ ] Define typed errors for incompatible NVIDIA release.
* [ ] Define typed errors for download verification failure.
* [ ] Define typed errors for final output validation failure.
* [x] Require reverse-order guest mount cleanup in structured failure/cancellation results.
* [x] Always stop QEMU after the current prototype build fails.
* [x] Preserve useful appliance logs after current-session cleanup.
* [x] Never delete or mutate the original user image.
* [x] Never show completion until export and independent validation succeed.

---

# 33. Cancellation

* [x] Support cancellation during bounded artifact/package downloads.
* [x] Support cancellation while hashing/copying/decompressing.
* [x] Support cancellation while the guest is booting.
* [x] Support process-group cancellation during image mutation with cleanup verification.
* [ ] Support cancellation during compression/finalization.
* [x] Make image-preparation cancellation cooperative with an atomic worker signal.
* [x] Add bounded forced termination fallback.
* [x] Unmount/detach filesystems on cancellation and reject the disposable overlay if cleanup is incomplete.
* [x] Delete incomplete candidate output by default; only atomically finalized images receive their final name.
* [x] Never modify the original image during the current cancellable prototype workflow.

---

# 34. Logging and diagnostics

* [x] Create a unique per-build runtime/diagnostic directory.
* [x] Record the application version in the output manifest. (Source commit remains a separate provenance task.)
* [x] Record host OS/architecture without including private host paths.
* [x] Record the basename and version of every QEMU executable used by the build.
* [ ] Record appliance version. (Exact appliance filename, size, and SHA-256 are recorded; a separately versioned appliance protocol/release identity remains.)
* [x] Record the input filename without its full private host path in the output manifest.
* [x] Record input and normalized-image checksums.
* [x] Record the recognized SteamOS layout and target-system discovery result.
* [x] Record selected NVIDIA trust/certification and exact target identity.
* [ ] Capture guest command exit statuses.
* [x] Capture QEMU stderr/serial logs.
* [x] Redact private keys, credentials, usernames, and sensitive host paths from user-shareable diagnostic summaries while retaining the full local log.

---

# 35. Automated testing

## Rust/unit tests

* [x] Test supported-image detection.
* [x] Test extension/magic mismatch handling in both directions; content signatures control normalization for compressed bytes named `.img` and raw bytes carrying a compressed suffix.
* [x] Test QEMU/appliance architecture and acceleration selection.
* [ ] Test environment status state machine.
* [x] Test bounded backend-owned command/argument construction for support handoff and maintainer plans.
* [x] Test build-manifest serialization, versioning, and host-path exclusion.
* [ ] Test error mapping.
* [ ] Add pure contract tests that do not initialize Tauri for every support
  build/install/progress schema and every stable `BuilderError` mapping.
* [ ] Add state-transition and stale-generation tests for overlapping status,
  cancellation, shutdown, retry, and worker-completion events.
* [ ] Add tests for the source/working/output cross-process lock, including a
  second application instance and abandoned-lock recovery without PID reuse
  mistakes.
* [ ] Add CSP and per-window capability smoke tests proving the main, progress,
  and maintainer windows have only their intended access.

## Appliance tests

* [x] Manually verify disposable overlay behavior.
* [x] Manually verify cloud-init first boot.
* [x] Manually verify SSH authorized-key injection.
* [x] Manually verify readiness marker handshake.
* [x] Automate disposable-overlay persistence/base-immutability testing as an opt-in live appliance test.
* [x] Automate guest health/self-test and byte-for-byte transfer verification in the live appliance test.
* [ ] Test damaged base qcow2 detection.
* [ ] Test missing firmware.
* [ ] Test boot timeout.

## Image tests

* [x] Create a deterministic sparse synthetic disk fixture with a DOS partition table and ext4 filesystem.
* [x] Test conservative GPT/layout discovery.
* [x] Test expected FAT/ext4/Btrfs partition-role discovery against synthetic and inspected layouts.
* [x] Test marker mutation without requiring a Valve image.
* [ ] Test cleanup after forced mutation failure.
* [x] Test input checksum preservation in the opt-in live appliance test.
* [x] Test independent marker/NVIDIA output-validation contracts.

## Cross-workflow corner and edge-case matrix

Exercise these first with pure fixtures or disposable virtual media. Tests that
need a real recovery image, network archive, privileged raw device, or physical
NVIDIA system must remain explicitly opt-in and must not run destructively in
ordinary CI. A VM result validates orchestration and image structure, not
physical NVIDIA boot compatibility.

### Output naming, metadata, and version reuse

* [ ] Test final versioned names for raw, `.bz2`, `.gz`, and `.xz` inputs,
  including spaces, Unicode, mixed-case extensions, very long names, an empty
  stem, and exhausted/non-writable destination directories.
* [ ] Test collision numbering when the image exists, only its manifest exists,
  both exist, a partial output exists, or a previous versioned NVIDIA output is
  selected. Never overwrite or pair an image with the wrong manifest.
* [ ] Keep legacy unversioned `-nvidia.img` outputs importable when their
  adjacent manifest passes every current identity and content check.
* [ ] Prove filenames are hints only: harmless renaming must require a matching
  manifest update/revalidation, while a version-looking filename without a
  valid manifest must never skip a build.
* [ ] Reject contradictory manifest identity: output filename/size/hash,
  SteamOS version, kernel, NVIDIA version, source selection/origin/reference,
  trust class, result class, and installation verification must agree.
* [ ] Test completed-output reuse for Automatic and an exact matching pinned
  version. Test an explicitly different version, project/upstream origin
  mismatch, and missing version metadata; none may silently reuse or mutate the
  completed image.
* [ ] Test that `Latest` is resolved and pinned at build start rather than
  inferred from a filename or changed by a later catalog refresh.
* [ ] Test source-selector changes during image inspection and immediately
  before build dispatch so a stale inspection cannot authorize a different
  requested driver.
* [ ] Test current-schema safe additive fields, missing mandatory identity,
  malformed/oversized JSON, duplicate keys where the parser permits detection,
  unsupported future schema versions, and legacy migrations.
* [ ] Add a future explicit upgrade-mode test before allowing a completed
  NVIDIA image to be rebuilt. It must verify installed state, removal/replacement
  ownership, rollback, free space, initramfs, and repeat execution; until then,
  require the original Valve recovery image for a different driver version.

### Idempotency, restart, and concurrent ownership

* [ ] Build the same clean source and exact NVIDIA selection twice. Verify the
  source remains identical, outputs do not overwrite each other, both manifests
  bind the correct bytes, and no first-run cache/runtime state is trusted by the
  second run without revalidation.
* [ ] Reopen a completed output repeatedly for image-only and USB-only export;
  verify no installer, compiler, mutation appliance, or new output image starts.
* [ ] Rapidly select image A then image B while hashing, inspecting, resolving,
  refreshing USB devices, and receiving completion events. Only the newest
  generation may alter visible or backend state.
* [ ] Start a second application instance against the same source, qcow2,
  handoff, output name, and USB target. Verify exclusive locks fail safely and
  abandoned locks are recovered only after exact owner/process validation.
* [ ] Exercise cancel followed immediately by restart during decompression,
  source hashing, native-appliance boot, x86 boot, download, compilation,
  validation, mutation, initramfs, export, and USB verification.
* [ ] Close the progress window, main window, Dock/taskbar application, and OS
  session during every long phase. Require bounded cleanup, no orphaned QEMU or
  helper process, no trusted partial output, and an actionable next-launch
  recovery report.
* [ ] Test host sleep/wake, clock movement, network loss/recovery, and removable
  volume disappearance without treating elapsed-time estimates or stale
  heartbeats as proof of failure or success.

### Filesystem, capacity, and hostile local paths

* [ ] Test exact-fit, one-byte-short, inode-exhausted, sparse-file, quota-limited,
  read-only, case-insensitive collision, and free-space-changing-during-export
  destinations. Partial files and manifests must be removed or quarantined.
* [ ] Test source/output/runtime paths containing newlines, tabs, combining
  Unicode, shell metacharacters, leading dashes, invalid UTF-8 at the Rust
  boundary, symlink swaps, hard links, aliases, and parent-directory replacement.
* [ ] Test interrupted atomic finalization between image rename, manifest rename,
  directory sync, and Finder reveal. Never leave a final-looking image with an
  absent, stale, or mismatched manifest.
* [ ] Test damaged/truncated qcow2 layers, unexpected backing-file changes,
  full appliance filesystems, guest inode exhaustion, and host write/read errors
  while preserving the original source and bounded diagnostics.

### USB discovery, authorization, and physical-media behavior

* [ ] Test macOS discovery of previously flashed multi-partition Linux/Arch
  media where Finder mounts only the EFI volume; select the external whole disk,
  never an individual visible partition.
* [ ] Test `diskutil` empty/invalid plist, missing optional keys, internal disks,
  external USB SSDs with unusual removable/ejectable flags, SD-card readers,
  disk images, Thunderbolt storage, multiple identical models, and devices with
  no readable serial number.
* [ ] Test drive renumbering, unplug/replug, same-capacity replacement, identity
  token drift, new volumes auto-mounting, and device disappearance before and
  after authorization. Revalidate the whole disk immediately before the first
  write and again before reporting success.
* [ ] Test exact-capacity and off-by-one rejection at logical/physical block-size
  boundaries, short writes, zero-byte writes, partial final blocks, readback
  mismatch at first/middle/last block, and media becoming read-only.
* [ ] Test busy-volume unmount refusal, user cancellation of the macOS privilege
  prompt, denied authorization, descriptor substitution, descriptor leakage,
  helper crash, cancellation during write/readback, eject refusal, and power
  loss. Never reuse a consumed or expired intent session.
* [ ] Test Image, USB, and Both behavior when the USB is selected before a long
  build but changes afterward. The completed staging image must remain available
  whenever USB writing fails or is cancelled.

### UI, diagnostics, and accessibility regressions

* [ ] Add screenshot/layout tests for every window at minimum size, expanded
  size, macOS display scaling, long paths, long translated errors, empty logs,
  maximum bounded logs, settings expansion, and USB-device lists. Controls and
  explanatory footer text must never clip or shift between progress events.
* [ ] Test keyboard-only image selection, source selection, settings, log text
  selection/copy, paused-scroll return-to-latest, USB review, confirmation, and
  cancellation with visible focus and correct disabled/inert states.
* [ ] Test rapid ANSI output, partial escape sequences, carriage-return compiler
  progress, invalid UTF-8, very long lines, repeated diagnostics, and copy-smart
  redaction without freezing scrolling or hiding the authoritative error.
* [ ] Test companion-window stacking/focus and native close behavior across
  main, progress, settings, USB review, and maintainer windows, including app
  switching and another process between their z-order.

### Platform and release-package coverage

* [ ] Run the complete non-destructive suite on Apple Silicon and Intel macOS;
  distinguish native x86 acceleration from Apple Silicon TCG behavior and do
  not infer physical-host support solely from a nested VM.
* [ ] Repeat output identity, completed-image reuse, path, cancellation, and USB
  helper protocol tests on Windows before enabling that platform. Include UAC
  denial, `PhysicalDrive` renumbering, drive-letter-only visibility, antivirus
  interference, sleep/wake, and signed-helper upgrade/rollback.
* [ ] Test a packaged application with no Homebrew, developer checkout, Cargo,
  Node, host Python, GitHub CLI, or pre-populated cache. Every required runtime
  must be bundled or acquired through an authenticated, recoverable path.

---

# 36. CI

* [ ] Add formatting checks for Rust.
* [ ] Add `cargo check`.
* [ ] Add Rust tests.
* [ ] Add shell syntax checks.
* [ ] Add JavaScript lint/check strategy if needed.
* [ ] Add macOS build job.
* [ ] Add Linux build job when Linux support begins.
* [ ] Add Windows build job when Windows support begins.
* [x] Add an opt-in live synthetic appliance/image integration test for local virtualization.
* [ ] Do not require proprietary/Valve recovery images in public CI.
* [ ] Cache safe dependencies without caching mutable secret/runtime state.

---

# 37. macOS end-user runtime

* [x] Use Homebrew dependencies for development bring-up.
* [ ] Do not require end users to understand or manually install Homebrew as the final product model.
* [ ] Decide whether QEMU is bundled, downloaded/managed by the app, or supplied through another distributable runtime.
* [ ] Bundle or manage UEFI firmware consistently.
* [ ] Bundle or manage Fedora appliance consistently.
* [x] Verify the current Apple Silicon development workflow, including native inspection and emulated x86_64 NVIDIA work.
* [ ] Verify Intel macOS support if retained.
* [ ] Handle Gatekeeper/notarization requirements.
* [ ] Sign application.
* [ ] Notarize releases.
* [ ] Verify application sandbox/entitlement requirements if applicable.
* [ ] Test clean-machine installation with no developer tools present.

---

# 38. Windows support

* [ ] Build Tauri application on Windows.
* [ ] Select appropriate QEMU Windows distribution strategy.
* [ ] Detect WHPX acceleration.
* [ ] Provide TCG fallback policy if desired.
* [ ] Locate/manage UEFI firmware.
* [ ] Implement Windows-safe runtime paths.
* [ ] Implement host-to-guest large-image transport.
* [ ] Implement guest-control transport.
* [ ] Test NTFS path/permissions behavior.
* [ ] Test paths containing spaces and Unicode.
* [ ] Package without requiring WSL unless explicitly chosen as architecture.
* [ ] Sign Windows binaries.
* [ ] Test on clean Windows installation.

---

# 39. Linux support

* [ ] Build Tauri application on Linux.
* [ ] Detect `qemu-system-*`.
* [ ] Detect KVM access.
* [ ] Handle distro-specific QEMU/firmware locations.
* [ ] Decide bundled vs system QEMU policy.
* [ ] Implement host-to-guest image transport.
* [ ] Test Wayland/X11 desktop integration.
* [ ] Package AppImage/Flatpak/deb/rpm strategy as appropriate.
* [ ] Avoid requiring root for ordinary image builds where possible.
* [ ] Test on at least one mainstream distro.

---

# 40. Cross-platform abstraction

* [ ] Separate host-independent build plan from platform-specific runtime code.
* [ ] Define host abstraction for:

  * QEMU discovery
  * firmware discovery
  * runtime directory creation
  * appliance startup
  * guest transport
  * output reveal
  * process cleanup
* [ ] Keep guest-side image mutation identical across macOS, Windows, and Linux wherever possible.
* [ ] Ensure platform-specific code does not leak into NVIDIA compatibility logic.
* [ ] Add platform capability reporting.

---

# 41. Appliance toolchain provisioning

* [x] Inventory and health-check required guest tools.
* [x] Include partition inspection tools.
* [x] Include required filesystem tools.
* [x] Include compression tools.
* [ ] Include `qemu-img`/guest utilities where needed.
* [x] Include checksum/signature verification tools used by the appliance contracts.
* [x] Include Git/curl for the explicitly isolated build/download stages that still require them.
* [ ] Pin package versions or appliance image version sufficiently for reproducibility.
* [ ] Build appliance once for release rather than installing packages during every user build.
* [x] Add appliance health/self-tests for architecture, free space, and required binaries/features.

---

# 42. Builder protocol design

* [x] Define initial protocol version `1`.
* [x] Define the fixed health operation and structured host result.
* [x] Define the general user-image inspection command and structured Rust result.
* [ ] Define prepare-working-image command.
* [x] Define the fixed structured working-image marker operation.
* [x] Define the fixed NVIDIA resolution/build/validation/mutation operations.
* [ ] Define validate-output command.
* [x] Return structured JSON for compatibility, validation, mutation, storage, and lifecycle results; logs remain diagnostic-only.
* [x] Include strict machine-readable schema-1 progress events for installer validation and mutation.
* [ ] Include stable error codes.
* [ ] Keep protocol backward-compatible across minor app updates where practical.
* [x] Reject incompatible health protocol versions clearly.

---

# 43. Build manifest

* [x] Define marker-manifest schema version 1 with an explicit `mutation-valid` result class.
* [ ] Include application version/commit. (Application version included; source commit pending.)
* [ ] Include appliance version/hash. (Exact native and x86 appliance hashes are included; independently versioned appliance release identity remains.)
* [x] Include input and normalized-image SHA256 values.
* [x] Include the safely detected SteamOS version and exact kernel in NVIDIA output manifests.
* [x] Include detected target kernel(s) in the manifest.
* [x] Include NVIDIA version, trust, support commit, and automatic-versus-pinned source policy.
* [x] Include NVIDIA archive, provenance, keyring, and package checksums through the structured installation result.
* [x] Include all modified target paths for the marker milestone.
* [x] Include final image SHA256.
* [ ] Include build timestamp only where nondeterminism is acceptable.
* [x] Save manifest beside output image without host directory paths or usernames.
* [ ] Optionally place a copy inside generated SteamOS image for later diagnostics.

---

# 44. Compatibility policy

* [ ] Define what SteamOS versions are supported.
* [x] Require exact target-kernel matches for all installed NVIDIA modules.
* [x] Reuse the support project's bounded, non-forward SteamOS-series certification fallback while retaining exact kernel identity.
* [x] Never silently inject modules for an incompatible target kernel.
* [ ] Define supported NVIDIA GPU generations.
* [ ] Define unsupported legacy/proprietary-driver-only cases.
* [ ] Define behavior for newer unknown Valve images.
* [x] Resolve and display the target/driver compatibility result before installation mutation.

---

# 45. Development modes

* [x] Prefer certified published NVIDIA support for normal users and require explicit approval before a local exact-target build fallback.
* [x] Add explicit project-branch and upstream NVIDIA development selections outside the normal automatic path.
* [x] Add explicit pristine-upstream control mode for image-level testing, kept off by default and guarded by a per-build warning acknowledgement.
* [x] Keep development/upstream results visibly labeled with their non-certified trust classification.
* [x] Embed exact development source repository/reference/commit policy in the manifest.
* [x] Reject upstream-local/development artifacts from the canonical automated publisher.
* [ ] Allow advanced users to retain Fedora runtime/logs for debugging.

---

# 46. User safety

* [x] Do not directly flash USB drives in initial scope.
* [x] Do not modify original input image.
* [x] Never enumerate or write physical disks during the normal image-builder flow.
* [ ] If flashing is ever added, make it a separate explicitly dangerous workflow.
* [ ] Require unmistakable device identification before any future flashing operation.
* [x] Canonicalize the output parent and reject any output path resolving to the input file.
* [x] Reject block/character device output paths and any destination that appears before atomic finalization.
* [x] Verify conservative host space before guest startup and authoritative target space before mutation.
* [x] Preserve bounded runtime diagnostics and a shareable failure summary.
* [x] Make experimental upstream NVIDIA selection/status explicit and acknowledgement-gated.

---

# 47. Valve recovery-image legal/distribution boundary

* [x] Require users to obtain the official Valve recovery image themselves.
* [x] Provide a link/button to Valve’s download page rather than bundling Valve image content.
* [x] Keep generated Valve image files out of source control.
* [x] Document that the app modifies a user-provided image locally and exports a separate result.
* [ ] Review Valve/SteamOS redistribution terms before distributing any derivative image artifact from project infrastructure.
* [ ] Do not publish premodified Valve recovery images as GitHub release assets without clear legal permission.
* [x] Document the distribution boundary: project code, recipes, patches, manifests, and permitted appliance assets—not Valve filesystem content.
* [x] State that the project is not affiliated with or endorsed by Valve.

---

# 48. Project licensing

* [x] Confirm the repository's MIT license and link it from the README without implying that it relicenses third-party components.
* [ ] Audit third-party licenses for bundled QEMU/firmware/Fedora components.
* [ ] Audit licenses for any redistributed NVIDIA-related artifacts.
* [ ] Include required notices in packaged application.
* [x] Keep Valve image content outside the project distribution boundary.

---

# 49. Documentation

* [x] Keep the README aligned with the implemented Fedora/QEMU backend.
* [x] Document current working appliance architecture.
* [x] Document developer bootstrap.
* [x] Document appliance build process.
* [x] Document disposable-overlay behavior.
* [x] Document handshake design.
* [x] Document generated runtime files and why they are ignored.
* [x] Document input/output safety guarantees.
* [x] Document supported input formats.
* [x] Document current compatibility status.
* [x] Document known limitations.
* [x] Add a troubleshooting responsibility guide.
* [x] Add architecture diagram.
* [ ] Add contributor workflow.
* [ ] Add release process.
* [x] Reconcile this TODO against implemented milestones and current project scope.

---

# 50. Repository hygiene

* [x] Ignore generated Fedora qcow2 images.
* [x] Ignore appliance work directory.
* [x] Ignore runtime directory.
* [x] Keep private runtime SSH key out of Git.
* [x] Keep generated cloud-init runtime copy out of Git.
* [x] Add a repository check rejecting files over 25 MiB and generated image/appliance extensions.
* [x] Add a repository check rejecting private-key filenames and PEM markers.
* [x] Keep generated SteamOS output images out of Git through global image-extension ignores and the repository check.
* [x] Keep build logs/diagnostics out of Git unless they use the explicit sanitized test-fixture convention.
* [x] Remove the stale, repository-unreferenced
  `src-tauri/src/{main.js,style.css}` prototype frontend after confirming the
  active application uses top-level `src/`.

---

# 51. Performance

* [ ] Measure Fedora guest boot time.
* [ ] Measure image decompression time.
* [ ] Measure host↔guest large-file transport throughput.
* [ ] Measure image copy/mutation time.
* [ ] Measure final compression time.
* [ ] Avoid repeated appliance startup when multiple safe stages can share one session.
* [ ] Avoid keeping appliance alive indefinitely while idle.
* [x] Tune vCPU and guest memory allocation within separate native-inspection and x86-build bounds based on host resources.
* [x] Reject hosts below the 6 GiB RAM floor and retain host CPU/memory headroom.
* [x] Use HVF hardware acceleration for the native Apple Silicon appliance.
* [x] Keep bounded TCG functional for the required x86_64 appliance on Apple Silicon.

---

# 52. Resource policy

* [x] Detect host RAM through macOS sysctl.
* [x] Choose bounded 2-4 GiB native and 4-6 GiB x86 build-worker memory plans.
* [x] Detect host logical CPU count.
* [x] Choose 1-4 native or 1-6 build-worker vCPUs while leaving host CPU headroom.
* [x] Run CPU/blocking image preparation, inspection verification, and shutdown outside the UI thread.
* [x] Detect low disk space before guest startup, without double-counting capacity across separate runtime and output volumes.
* [x] Record schema-1 host/guest resource plans in each disposable runtime's `resources.json` diagnostics.

---

# 53. Application lifecycle

* [x] Make main-window quit equivalent to safe appliance cancellation for the current prototype workflow.
* [x] Stop the managed QEMU child when application state is dropped on exit.
* [x] Give every Unix-hosted QEMU process an exact-PID keepalive watchdog so Dock Quit, `pkill`, crashes, and force-quit cannot leave an orphaned native or x86 appliance.
* [ ] Before enabling Windows builds, place every QEMU process in a kill-on-close Windows Job Object equivalent to the Unix watchdog.
* [x] Clean the session overlay and ephemeral SSH credentials on app exit.
* [x] Detect inactive stale runtime state on next launch.
* [x] Automatically clean abandoned inactive workspace data while archiving QEMU logs.
* [x] Atomically finalize completed output and its manifest before revealing success, independently of later runtime cleanup.
* [ ] Keep state machine recoverable after frontend reload.

## Stable graphical shell and independently updateable backend

Treat the persistent installed-system application as two products with one
versioned protocol. The graphical shell should become intentionally boring and
stable; compatibility, recovery, resolver, and transaction fixes should ship as
smaller backend generations without closing, replacing, or visually resetting
the open window.

* [x] Embed the pinned support repository's signed, content-addressed A/B
  desktop-generation manager, atomic activation marker, startup-health deadline,
  last-known-good rollback, lifecycle lock, and fail-closed signer policy as the
  initial update foundation.
* [ ] Split the persistent Open OPEMOS Desktop into an unprivileged graphical
  shell and a separately launched backend process. Do not load downloaded code
  into the GUI process or grant the backend unrestricted shell execution.
* [ ] Define a strict, bounded schema-1 shell/backend protocol with capability
  discovery, request IDs, cancellation, heartbeats, structured errors, maximum
  message sizes, and explicit minimum/maximum compatible protocol versions.
* [ ] Version the shell and backend independently. A backend release manifest
  must bind its exact version, protocol range, OS/architecture, executable hash,
  support revision, required guardian schema, release channel, and signer.
* [ ] Let a compatible backend generation stage while the current backend keeps
  serving the visible shell. Start the candidate separately, require a bounded
  ready/health handshake, switch new requests atomically, drain or cancel old
  requests safely, and only then acknowledge the candidate as healthy.
* [ ] Keep the graphical window resident through backend download, activation,
  crash, timeout, and rollback. Show a small truthful status such as
  `Updating services`, `Checking update`, or `Restored previous service`; do not
  blank, reload, resize, or replace the window merely because the backend moved.
* [ ] If the candidate crashes, misses its health deadline, loses its channel,
  or returns an incompatible schema, reconnect the shell to the last-known-good
  backend and retain bounded diagnostics. Never strand the UI on a dead socket.
* [ ] Require a conventional full-application update when a backend's protocol
  is outside the installed shell's compatible range or when a security fix must
  change the UI boundary. Never force a nominally backend-only update across an
  incompatible shell.
* [ ] Add signed release-channel metadata that distinguishes `stable`, `beta`,
  and explicit maintainer/development generations. Automatic mode may consume
  only a reviewed production signer and may never downgrade or cross channels.
* [ ] Check for backend updates only after connectivity is available, with
  bounded exponential backoff and jitter. Offline or delayed networking must
  continue using the last-known-good generation without blocking the desktop,
  boot, recovery, or local diagnostics.
* [ ] Download into a private content-addressed staging directory, enforce disk
  and byte limits, rehash before every trust boundary, verify the detached
  signature and reviewed signer before activation, and retain no trusted state
  for a partial or cancelled download.
* [ ] Make update checks and downloads cancellable, but never interrupt an
  active image/slot mutation at an unsafe point. Defer activation until the
  backend reports an idle or explicitly resumable transaction boundary.
* [ ] Keep one verified previous generation plus the active generation, bound
  cache growth, and prune only generations that are neither active, pending,
  last-known-good, nor referenced by a recoverable transaction.
* [ ] Support signed key rotation and emergency revocation without allowing
  release metadata, GitHub availability, TLS alone, or a backend generation to
  expand its own trust policy.
* [ ] Persist only non-secret update state outside replaceable SteamOS root
  slots. Reconcile interrupted staging/activation after power loss and expose
  the same state through the graphical shell and console-safe diagnostics.
* [ ] Test backend hot-swap with active requests, slow and disconnected clients,
  offline startup, delayed internet, corrupt/truncated downloads, disk
  exhaustion, signature failure, incompatible protocol ranges, crash loops,
  power loss at every durable-write boundary, and rollback while the GUI remains
  usable.
* [ ] Hardware-test backend-only updates across SteamOS A/B updates and prove
  that the stable shell can reconnect to the correct last-known-good backend
  from either slot before enabling automatic production updates.

---

# 54. Release packaging

* [ ] Define application semantic versioning.
* [ ] Define builder-appliance versioning.
* [ ] Produce macOS application bundle.
* [ ] Include/manage required runtime components.
* [ ] Publish checksums.
* [ ] Sign releases.
* [ ] Add release notes with compatibility matrix.
* [ ] Add upgrade behavior for cached appliance/runtime.
* [ ] Avoid breaking old cached state silently.
* [ ] Test clean installation and upgrade installation separately.

---

# 55. GitHub Releases and artifact strategy

* [x] Keep generated qcow2 images ignored and out of the source repository.
* [ ] Version appliance separately from desktop app if necessary.
* [x] Restrict automated publication to project-owned/generated NVIDIA artifacts and permitted runtime metadata.
* [x] Explicitly reject Valve recovery/generated SteamOS images from automated GitHub publication.
* [ ] Define cache invalidation when a new appliance release is required.

---

# 56. Alpha acceptance gate

Before calling the project **alpha**, verify all of the following:

* [x] Rust launches and controls Fedora without manual terminal commands.
* [x] Guest readiness handshake is automatic.
* [x] User can select an official Valve recovery image.
* [x] Original image remains unchanged through the disposable workflow.
* [x] App produces a separate modified output image.
* [ ] Output modification is deterministic and validated.
* [ ] NVIDIA kernel modules/userspace are integrated through the intended support-repo path.
* [ ] Generated image installs/boots on the primary RTX 2060 test system.
* [ ] Gaming Mode reaches a usable graphical state.
* [x] Build failure never writes to the read-only original input image.
* [x] End user does not need to manually use QEMU, Fedora, SSH, mount, or chroot commands.

---

# 57. Beta acceptance gate

Before calling the project **beta**, verify:

* [ ] Repeated builds from clean input succeed.
* [ ] Cancellation works across major stages.
* [ ] Failure cleanup is reliable.
* [ ] Multiple Valve recovery-image versions are handled or rejected clearly.
* [ ] Multiple NVIDIA GPU generations are tested.
* [ ] SteamOS update behavior after installation is understood.
* [ ] Rebuild workflow after SteamOS/kernel updates is documented.
* [ ] Compatibility matrix is published.
* [ ] Supply-chain verification is production-grade.
* [ ] macOS clean-machine installation works without developer setup.
* [ ] Windows and/or Linux support status is explicit, even if still unsupported.

---

# 58. Release-candidate acceptance gate

* [ ] No manual shell steps in normal workflow.
* [ ] Packaged runtime is self-contained or automatically managed.
* [ ] Application signing/notarization complete where required.
* [ ] Builder appliance is versioned and verified.
* [ ] NVIDIA artifacts are verified.
* [ ] Diagnostics are exportable.
* [ ] Major failure modes have actionable user messages.
* [ ] Output validation is automatic.
* [ ] At least one desktop NVIDIA system and one NVIDIA laptop are validated.
* [ ] Clean install and application upgrade tests pass.

---

# 59. Stable acceptance gate

* [ ] Image generation is repeatable and predictable.
* [ ] Supported SteamOS/NVIDIA combinations are explicitly certified.
* [ ] Generated images boot/install reliably on supported hardware.
* [ ] Gaming Mode is stable enough for normal use on supported configurations.
* [ ] SteamOS update/recovery behavior is documented and tested.
* [ ] The project can recover cleanly from interrupted builds.
* [ ] No known workflow can overwrite the user’s original recovery image.
* [ ] No normal workflow requires users to understand the Fedora/QEMU implementation.
* [ ] Release artifacts and dependency provenance are auditable.
* [ ] Documentation matches actual behavior.

---

# 60. Explicitly deferred / non-goals for initial release

* [x] Do not make direct USB flashing part of the first functional milestone.
* [x] Do not redistribute Valve recovery images from the source repository.
* [x] Do not make NVIDIA source patch development a prerequisite for proving generic image mutation.
* [x] Do not boot x86 SteamOS inside the Apple Silicon Fedora guest merely to manipulate its filesystem.
* [x] Keep advanced upstream/development NVIDIA controls separate and explicitly experimental while certified-image generation is being proven.
* [x] Defer automated physical-disk installation targeting until the generated recovery image itself is proven.
* [x] Defer VR/Valve Index-specific SteamOS work to a separate compatibility effort unless it becomes directly relevant to image construction.
* [x] Defer non-NVIDIA GPU customization; the project’s initial purpose is NVIDIA-oriented SteamOS image construction.

---

# 61. Long-term possibilities

* [ ] Optional direct USB flashing with extremely strong device-selection safeguards.
* [x] Add a read-only macOS USB preflight that accepts only a manifest-bound raw output and discovers whole, physical, external, removable/ejectable disks large enough for the image without opening a raw device.
* [x] Add a short-lived, cancellation-safe USB intent session that rehashes the image, immediately revalidates exact device identity/capacity, and requires typing `ERASE diskN` before authorization.
* [x] Make the USB image/manifest and destructive-intent boundaries independently fixture-testable without Disk Arbitration; cover content/manifest drift, phrase, exact node, capacity, and identity-token mismatch.
* [x] Expose truthful read-only USB intent-session status with exact-token active/expired/stale/not-armed states and remaining lifetime; never imply cancellation succeeded when no matching session existed.
* [x] Bind USB intent status to the exact device identifier, device identity token, and image SHA-256; reveal that identity only to the matching session token so stale tokens cannot observe a replacement session.
* [x] Require an exact valid session token for public USB intent cancellation; keep tokenless cancellation backend-only so a stale UI cannot cancel an unrelated replacement session.
* [x] Bind asynchronous USB arm/status/cancel and VS Code-open completions to their initiating UI context so stale responses cannot overwrite or resurrect replacement state.
* [x] Add a pre-build Image / USB / Both destination selector and allow read-only removable-target selection before the long build; require final manifest identity and capacity revalidation afterward.
* [x] Reopen a manifest-bound, independently validated `nvidia-mutation-valid` output directly for USB export without rerunning NVIDIA installation; reject suffix-only, marker-only, incomplete, or byte-drifted inputs.
* [x] Add a one-use USB writer state transition with 4 MiB bounded writes, live byte progress, safe-boundary cancellation, full written-range SHA-256 read-back, and best-effort eject on success or failure.
* [x] Exercise the same writer against regular-file fixtures and an opt-in 16 MiB macOS virtual raw disk while continuing to reject virtual disks from real target discovery.
* [x] Keep the physical writer command fail-closed before unmount/open until the exact revalidated identity can be bound to an independently authorized raw-device handle; enable macOS only through the protected `authopen` descriptor path.
* [x] Define and hostile-test the bounded external-helper protocol for exact image, intent, process, device, progress, outcome, cancellation, readback, and cleanup binding; retain it for platforms such as Windows that require a separately signed elevated helper.
* [x] Use Apple's SIP-protected `authopen` as the least-privilege macOS authorization boundary: request only the exact revalidated raw-device path, receive one descriptor through `SCM_RIGHTS`, require close-on-exec plus exact device/read-write identity, revalidate after authorization, and never run the Tauri GUI as root or install a persistent daemon.
* [ ] Add a signed Windows UAC writer helper implementing the same bounded request, identity, progress, cancellation, verification, and cleanup protocol against an exact `\\.\PhysicalDriveN` target.
* [ ] Validate the complete workflow against a sacrificial physical USB device, including unplug/replug identity drift, busy volumes, cancellation during write and verification, read errors, eject failure, sleep/wake, and power loss.
* [ ] Define a recoverable post-verification cleanup action for USB-only mode; until then retain the validated staging image rather than automatically deleting multi-gigabyte user output.
* [ ] Automatic detection/download assistance for current official Valve recovery image without redistributing it.
* [ ] Local artifact cache manager.
* [ ] Offline build mode.
* [ ] Multiple certified NVIDIA profiles.
* [x] Expose explicit project-branch and upstream NVIDIA development profiles separately from Automatic.
* [x] Add an off-by-default experimental NVIDIA-upstream source catalog with separate grouping, exact tag/commit resolution, matching-userspace preflight, and transient per-build acknowledgement.
* [x] Keep experimental upstream builds local-only and reject them from the canonical automated publisher until source-origin-aware release identities exist.
* [x] Record automatic-versus-pinned NVIDIA source policy in generated image manifests.
* [ ] Automated compatibility report upload with explicit user consent.
* [ ] Rebuild/update workflow for an already-installed SteamOS system.
* [ ] Make the future updater honor manifest source policy: rebuild a pinned NVIDIA version for each exact new kernel or pause for an explicit switch to Automatic/another version.
* [ ] Recovery-image comparison/diff tooling.
* [x] Provide an expandable live diagnostics/log viewer with smart-copy support.
* [x] Add a one-click diagnostic-log copy that keeps important build/failure context, removes routine repeated output, bounds clipboard size, and redacts host paths and common credentials without changing the full displayed log.
* [x] Reweight progress around real workflow cost and advance the long NVIDIA compile/validation/install ranges from normalized diagnostic milestones without allowing backward movement.
* [x] Split one shared rounded progress track into an overall upper half and per-step lower half: byte-counted work reports a real substep ratio, while validation and other unmeasurable phases use a restrained indeterminate animation.
* [x] Define and consume strict schema-1 `STEAMOS_NVIDIA_PROGRESS` JSON lines for detailed offline-root validation phases, real byte/item ratios, bounded attempts, readable phase logs, and app-owned status wording; the pinned support validator now emits this contract.
* [x] Consume the same strict progress contract for offline-root mutation, including pacman policy, runtime mounts, authenticated userspace installation/verification, all five modules, GRUB, depmod, initramfs, state recording, and cleanup.

## Deferred settings, profiles, and maintainer automation

* [x] Add a hamburger/settings menu for infrequent build and maintenance options without crowding the primary image workflow.
* [x] Define the first versioned, automatically saved JSON settings schema that can be reopened and validated safely. (Migration/reset UI remains.)
* [x] Remember only non-secret preferences in the JSON profile, including driver-update and verified NVIDIA release prompts.
* [x] Add the off-by-default “Omit optional CUDA to save storage” setting surface, but keep it visibly disabled until a reviewed support-repository payload profile exists.
* [ ] Enable the support repository's versioned, reviewed, package-owned `gaming-no-cuda-v1` payload profile only after it has an audited record for the selected SteamOS/NVIDIA target. Preserve graphics, Vulkan, GLVND/EGL, NVENC/NVDEC, GSP firmware, required 32-bit gaming libraries, recovery rendering, provenance, and pacman consistency; never implement it as builder-owned filename deletion.
* [ ] Integrate the support repository's deterministic raw-module-to-`.ko.zst` repack command into the maintainer workflow: authenticate the original archive/checksum/provenance, validate its dry-run contract, regenerate representation hashes and provenance, and publish a create-only revision tag/assets without overwriting the original release.
* [x] Never store a plaintext SteamOS user password, reusable password hash, GitHub token, SSH key, or other credential in the profile JSON.
* [ ] Add Raspberry Pi Imager-style optional first-boot provisioning for the SteamOS user password and Wi-Fi network so a generated image can avoid a manual `passwd`/network setup step while keeping both settings disabled/unchanged by default.
* [ ] Keep password input masked and transient; use the operating-system credential store when persistence is explicitly requested, otherwise prompt for each build.
* [ ] Generate the target Linux password representation inside the trusted Rust/backend path and prevent it from appearing in logs or manifests.
* [ ] Treat a blank password or blank Wi-Fi selection as “do not modify this setting,” never as an empty password, open network, credential deletion, or request to overwrite an existing target configuration.
* [ ] Allow Wi-Fi selection from a scanned list plus a manually entered/hidden SSID, record the intended security type, and validate that the selected SteamOS provisioning mechanism survives Valve installation rather than configuring only the recovery environment.
* [ ] Keep Wi-Fi passphrases masked and transient; store them only in the host operating-system credential store when explicitly requested, and exclude all provisioning secrets from settings JSON, logs, manifests, command lines, cloud-init output, and build artifacts not strictly required for provisioning.
* [ ] Confirm the target account and show a secret-free provisioning summary before building; verify the generated image contains only the intended password/Wi-Fi state and that cancellation removes every temporary secret-bearing file.
* [x] Add an opt-in “track SteamOS driver compatibility updates” preference; compatibility automation remains fail-closed until implemented.
* [x] Never silently replace a certified driver with an unverified latest release solely because a newer SteamOS version is detected.
* [x] Add a maintainer-gated workflow that can build and offer publication of an exact-target NVIDIA artifact when no compatible release exists.
* [ ] Add an off-by-default, maintainer-permission-gated “Audit unreviewed Arch signers” setting after the support repository exposes the non-mutating full-closure audit contract; require a fresh per-run warning/confirmation and never describe cryptographically authenticated but project-unreviewed package signers as trusted production inputs.
* [ ] In signer-audit mode, allow continuation only when every package signature validates against the pinned authenticated full Arch keyring; collect all package-specific mappings missing from project review in one candidate report, but never bypass an invalid signature, missing authoritative key, unsafe package, unresolved dependency, or hash mismatch.
* [ ] Mark every signer-audit result and any optional development image `development-unverified`, disable automated release/certified cache insertion, record the candidate lock hash and unreviewed signer set in its manifest, and keep normal builds fail-closed regardless of the saved checkbox state.
* [x] Add a dedicated maintainer window opened from the hamburger menu; keep it permission-gated and visually separate from the normal recovery-image workflow.
* [x] In the maintainer window, select the project NVIDIA repository or approved upstream repository and an exact available version/branch/commit before creating a workspace; re-resolve the selection and derive a schema-1 immutable plan identity in the backend.
* [ ] Start an isolated architecture-correct development environment for that selection, expose only an ephemeral authenticated SSH endpoint, and offer an “Open in VS Code” action using VS Code Remote SSH with the selected checkout as its workspace.
* [x] Add a local VS Code handoff that requires the user to select a Git worktree root, revalidates its GitHub origin against the exact planned repository, and reports its HEAD, branch, and bounded change count before opening it in a reused VS Code window.
* [x] Add a “Make For Me” local-worktree action that reauthorizes and re-resolves the exact planned source, fetches only its verified reference into a private atomic app-data checkout, creates a named local branch, and reuses an existing managed checkout without fetching, resetting, deleting edits, or changing its remote.
* [x] Remember at most ten previously validated maintainer worktree roots in owner-only settings and offer only recent entries that still exist and revalidate as an exact Git root with the planned GitHub origin; revalidate again on selection and never trust a saved path directly.
* [ ] Never reuse the image-mutation appliance as a general-purpose development host; use a disposable maintainer environment with explicit retention/destruction controls and no image/user credentials copied into it.
* [ ] Detect repository changes inside the maintainer environment and enable reviewed Commit and Push actions only when the checkout, branch, remote, diff, maintainer authorization, and commit message pass backend validation.
* [x] Add an explicitly local-only staged commit flow: require a named branch and matching approved origin, reject unsafe paths/messages, bind review to exact HEAD/index tree, atomically update only the unchanged local branch, and never stage or push.
* [x] Show the exact bounded staged patch before local commit, disable external diff/text conversion, reject control data and common credential/private-key markers, and bind execution to the reviewed patch SHA-256 as well as HEAD/tree.
* [x] Screen credential/private-key markers only in added patch lines so removing an exposed value or editing safe context remains possible without weakening added-secret rejection.
* [x] Add a guarded local branch context flow: enumerate existing safe local branches only, require a completely clean named-branch worktree, bind review to current/target commits, revalidate immediately, disable checkout hooks, and never fetch/reset/force/discard/push.
* [ ] Add a scrollable **Local Pipeline** area to the maintainer window, modeled after a compact local GitLab runner view: show bounded queued/running/completed stages, live logs, elapsed time, cancellation state, exact source/target identity, and retained artifact links without making the normal image-builder window taller.
* [ ] Implement the local pipeline as a backend-owned, persisted job state machine rather than a browser-only task list. Give every run an immutable ID bound to repository, worktree HEAD, reviewed diff/tree, target architecture, toolchain/appliance identity, and pipeline definition; reconcile or safely fail interrupted jobs when the app restarts.
* [ ] Split local-pipeline ownership at the repository boundary instead of duplicating support logic. The support repository should own versioned entry points and schemas for NVIDIA compatibility resolution, build, validation, tests/sanitizers, packaging, provenance, release dry-run, and deployment validation. OPEMOS.EXE should pin and validate those entry points while owning job scheduling, isolation, persistence, cancellation/supersession, UI/CLI presentation, artifact retention, desktop/device permissions, and final human authorization.
* [ ] Ask the support pipeline to expose a stable noninteractive contract comparable to `pipeline/run.sh --pipeline <name> --source <workspace> --target <document> --result <document> --events <jsonl> --artifacts <directory>`. Require bounded/versioned inputs, JSONL progress and heartbeats, a terminal structured result, hash-bound artifact manifests, redacted diagnostics, stable failure reasons, safe process-group cancellation, and explicit supported-tool/platform records.
* [ ] Keep the support pipeline incapable of granting its own external authority: support stages may prepare and validate a release or deployment, but they must not interpret pipeline success as permission to push, publish, write a device, reboot a target, or alter remotes. OPEMOS.EXE must independently revalidate the pinned support identity and outputs and obtain the required fresh confirmation or short-lived review token.
* [ ] Expose that same pipeline engine through a packaged `opemos pipeline` CLI usable from a VS Code terminal; the GUI and CLI must be clients of one backend/state store, never separate executors. Provide at least `run`, `list`, `status`, `follow`, `cancel`, `retry`, `artifacts`, and `diagnose` operations, with exact job IDs and unambiguous nonzero exit codes.
* [ ] Give the pipeline CLI versioned, bounded `--json` result documents and JSON Lines event streaming in addition to readable terminal output. Preserve stage, source, target, timestamps, cancellation/supersession, command exit, skipped-tool reasons, artifact hashes, and diagnostic identities so scripts and debugging assistants never need fuzzy log scraping.
* [ ] Make `opemos pipeline follow <job-id>` reconnectable and able to display retained output from its last acknowledged event before following live events. Detect truncated history explicitly, keep ANSI/color opt-in, and ensure a slow or disconnected terminal cannot block the underlying job.
* [ ] Add a redacted `opemos pipeline diagnose <job-id>` bundle/summary intended for maintainer and LLM-assisted debugging: include the immutable pipeline plan, failed-stage context, bounded relevant logs, tool versions, test reports, sanitizer findings, and artifact manifest while excluding credentials, host-private paths, raw images, device contents, and unrestricted environment variables.
* [ ] Require CLI callers to operate only on jobs/worktrees already authorized by the maintainer workflow, revalidate local ownership and immutable job identity for every mutation, and require an interactive confirmation or separately issued short-lived review token for push, release, deployment, device write, or reboot. `--json`, automation, or an LLM caller must never bypass those boundaries.
* [ ] Run pipeline commands only inside the architecture-correct disposable maintainer environment using repository-owned, reviewed allowlisted entry points. Bound runtime, output, CPU, memory, disk, process count, and network policy; terminate and reap complete process groups on cancellation or app exit.
* [ ] Give compile, test, package, release-dry-run, and device-deploy jobs explicit dependencies. A new deployment request for the same exact device/target should cancel or supersede older queued work and request safe-boundary cancellation of an older running deployment, while unrelated targets continue and stale completions can never publish, deploy, or replace newer results.
* [ ] Preserve bounded, content-addressed local pipeline artifacts and reports with exact job/source/toolchain provenance, hashes, retention limits, and manual reveal/export controls. Exclude credentials, recovery images, generated SteamOS images, raw device contents, and unreviewed secret-bearing files; never treat an artifact as trusted merely because its job exited successfully.
* [ ] Add optional maintainer diagnostics stages for memory leaks, undefined behavior, concurrency/thread safety, resource leaks, and process cleanup using platform-appropriate tools (for example sanitizers, Miri, Valgrind, Clippy, and stress/repetition tests). Record skipped/unsupported tooling explicitly and never report a clean platform-independent result from a tool that could not run.
* [ ] Gate local pipeline release and deployment actions on all required jobs, immutable artifact verification, fresh maintainer authorization, and a final human review. Automatic supersession may cancel obsolete work but must never itself authorize a push, release, destructive device write, reboot, or deployment.
* [ ] Show a reviewable status/diff summary before commit or push, prevent generated artifacts and credentials from being committed accidentally, and require explicit confirmation before every remote mutation.
* [ ] Add a Release action which performs the repository-owned clean build/test/compile/package/provenance pipeline, validates the resulting exact-version artifacts, presents a dry-run release manifest, and invokes the existing canonical publisher only after explicit confirmation.
* [ ] Keep release publication fail-closed: never release a dirty, untested, mismatched, unverified, upstream-local-only, or ambiguously versioned build, and never reinterpret “release” as permission to upload Valve recovery images.
* [ ] Offer an optional maintainer deployment workflow for a Steam Deck/SteamOS device over authenticated SSH: discover or manually enter the device, pin/confirm its host key, inspect exact OS/kernel/GPU compatibility, preview changes, and deploy only matching verified artifacts.
* [ ] Make Deck deployment recoverable and auditable: preserve diagnostics, define rollback/reinstall behavior, avoid modifying inactive A/B slots accidentally, and require a fresh confirmation naming the target device before mutation or reboot.
* [x] Authenticate through GitHub CLI's visible browser/Terminal flow without blocking the app, poll for completion, and verify effective repository role/maintainer access before enabling any upload or automated-release control. (Bundle the CLI for packaged releases; development currently discovers it on the host.)
* [x] Re-check GitHub authorization in the backend immediately before every build upload, tag, release, or other remote mutation; do not trust the UI checkbox alone.
* [x] Keep Valve recovery images and generated SteamOS images out of GitHub uploads; publish only project-owned NVIDIA artifacts, manifests, checksums, and permitted sources.
* [x] Present an explicit yes/no confirmation before every automated NVIDIA release, defaulting to “No” and naming the repository, tag, support commit, trust, and artifact hash.
* [x] Delegate NVIDIA release formatting and upload semantics to the hash-pinned canonical support publisher; cross-check its dry-run plan and invoke only create-only mode.
* [ ] Prefer draft releases plus a reviewable dry-run manifest before allowing a maintainer to publish automatically.
* [x] Record maintainer automation actions and artifact provenance without logging credentials or private host paths.
* [x] Begin the settings/maintainer surface after durable image export, independent output validation, and exact-kernel artifact validation were established.
* [ ] Bundle and verify a platform-appropriate GitHub CLI binary for packaged macOS, Windows, and Linux applications.
* [ ] Bundle the shell/Python runtime required by the canonical support publisher, or add a reviewed native launcher that preserves its exact validation and release-format contract, so packaged apps never depend on host-installed tools.

---

# 62. Immediate next implementation sequence

1. [x] Add Rust-owned appliance process manager.
2. [x] Reproduce current shell handshake from Rust.
3. [x] Report real guest-ready state to frontend.
4. [x] Add graceful shutdown/cleanup.
5. [x] Add one structured guest command such as `health`.
6. [x] Add a tiny host↔guest file-transfer or block-attachment proof.
7. [x] Attach a synthetic disk image, lock it read-only, and inspect it without mounting.
8. [x] Implement deterministic marker mutation on a synthetic working copy and prove source immutability.
9. [x] Run the implemented read-only inspection path against a real user-supplied Valve recovery image and record its `valve-recovery-a` GPT/Btrfs layout.
10. [x] Produce first modified Valve-image working copy containing only a harmless marker.
11. [x] Validate durable output and input immutability automatically against a full-size Valve recovery image.
12. [x] Begin NVIDIA support-repo integration with target SteamOS identity, architecture, and kernel discovery.
13. [x] Validate the support repository's offline-target build end to end in x86_64 Fedora for the observed SteamOS 3.8.14 kernel.
14. [x] Connect the managed x86_64 build path to the workflow and expose appliance boot, build subphases, elapsed time, live logs, download, validation, and cancellation through the existing progress window.
15. [ ] Invoke the support repository's machine-readable resolver/build contract from Rust without duplicating its compatibility policy.
16. [ ] Complete installation of the resulting artifact into only the disposable
    SteamOS working image. The real path now passes authenticated userspace and
    five-module installation/verification but remains blocked on support-owned
    target `/var/tmp` scratch handling for `mkinitcpio`; after repinning, verify
    initramfs, metadata, source immutability, cleanup, repeat execution, and the
    output manifest before export.

---

# 63. Definition of the intended end-user experience

The stable target workflow should eventually be approximately:

1. User downloads an official Valve SteamOS recovery image.
2. User opens SteamOS NVIDIA Image Builder.
3. User selects or drops the recovery image.
4. App validates the image and compatibility.
5. App prepares its managed Fedora/QEMU builder environment automatically.
6. App creates a separate working copy.
7. App injects the certified NVIDIA support required for that SteamOS image.
8. App validates the modified filesystem and image structure.
9. App writes a separate output image and manifest.
10. App reveals the output file.
11. User flashes the output with the disk-imaging tool of their choice.

No normal step should require the user to manually operate QEMU, SSH into Fedora, mount partitions, select kernel-module releases, edit SteamOS files, or understand the internal appliance architecture.

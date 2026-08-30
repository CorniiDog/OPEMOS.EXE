Below is the consolidated project checklist based on the current repository state and the latest successful local appliance tests. Where local validation is newer than older prototype documentation, the latest validated behavior is treated as authoritative.

# SteamOS NVIDIA Image Builder — Master Checklist

## Current project phase

**Status: development / backend bring-up**

The desktop shell, macOS development bootstrap, Fedora appliance bootstrap, disposable QEMU runtime, cloud-init provisioning, and non-interactive host-to-guest readiness handshake are now working as separate pieces.

The next major transition is to move appliance lifecycle management into the Rust/Tauri backend, then begin harmless mutation of a user-supplied official Valve SteamOS recovery image inside the Fedora guest.

The project is not yet producing a bootable modified SteamOS image.

### Milestone ladder

* [x] **Prototype shell:** desktop UI can select supported SteamOS image files and produce a harmless prototype output.
* [x] **Host readiness:** detect QEMU, determine host architecture, validate QEMU can launch, and locate the Fedora builder appliance.
* [x] **Appliance bring-up:** build and boot a Fedora Cloud appliance under QEMU on macOS.
* [x] **Disposable runtime:** boot through a writable qcow2 overlay so the Fedora base remains pristine.
* [x] **Guest handshake:** provision the guest with cloud-init and verify readiness through non-interactive SSH.
* [ ] **Backend integration:** Rust owns appliance startup, readiness polling, shutdown, and cleanup; structured guest command execution remains.
* [ ] **Harmless image mutation:** pass a user-selected Valve recovery image to the guest, create a working copy, mount it safely, write a deterministic marker, unmount it, and return a modified image.
* [ ] **NVIDIA integration prototype:** inject the project’s NVIDIA kernel-module/userspace support into a SteamOS recovery image without requiring manual post-install repair.
* [ ] **Bootable alpha image:** generated image boots/install-recovery media successfully on at least one NVIDIA test machine.
* [ ] **Beta:** repeatable builds, clean-image tests, rollback/error handling, and multiple NVIDIA hardware configurations.
* [ ] **Release candidate:** cross-platform packaged application with reproducible builder runtime and documented compatibility matrix.
* [ ] **Stable:** reliable end-user workflow from official Valve image to validated NVIDIA-capable output with no shell knowledge required.

### Current priority queue

1. [x] Move the successful `STEAMOS_BUILDER_READY` handshake into the Rust backend.
2. [x] Make Rust launch the Fedora appliance in the background without an interactive terminal.
3. [x] Add bounded readiness polling and distinguish booting, ready, failed, timed out, and stopped states.
4. [ ] Add controlled guest command execution from Rust.
5. [x] Add graceful guest shutdown and reliable forced cleanup fallback.
6. [ ] Keep each appliance session disposable and verify no state leaks between builds.
7. [ ] Pass a harmless host file into the guest and return a harmless output file.
8. [ ] Pass a user-selected SteamOS recovery image to the guest as data without booting it.
9. [ ] Detect compression/container format and prepare a writable working image.
10. [ ] Mount or inspect the SteamOS image read-only first and inventory its partition/filesystem layout.
11. [ ] Implement the first deterministic marker-only image mutation.
12. [ ] Integrate NVIDIA support from `open-gpu-kernel-modules-steamos-support` only after the generic image-mutation path is proven.

---

# 1. Core project architecture

* [x] Keep the desktop image-builder application in:

  * `CorniiDog/steamos-nvidia-image-builder`
* [x] Keep SteamOS NVIDIA support/build/install logic in:

  * `CorniiDog/open-gpu-kernel-modules-steamos-support`
* [x] Keep NVIDIA source history and project patch branches in:

  * `CorniiDog/open-gpu-kernel-modules-steamos`
* [x] Keep Gamescope NVIDIA work in:

  * `CorniiDog/gamescope-nvidia`
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
* [ ] Define a stable host↔guest protocol rather than allowing arbitrary UI-originated shell strings.
* [ ] Define explicit responsibility boundaries among UI, Rust host backend, Fedora appliance, NVIDIA support repo, and Gamescope repo.
* [ ] Document the architecture in the main README.
* [ ] Add an architecture/data-flow diagram.

---

# 2. Desktop shell and basic UX

* [x] Create Tauri application shell.
* [x] Add primary heading and builder status area.
* [x] Add drag-and-drop image selection.
* [x] Add native file-picker fallback.
* [x] Add Valve recovery-image download-page access.
* [x] Add selected-image summary card.
* [x] Add build button and prototype progress state.
* [x] Move build status, live logs, and cancellation into a dedicated progress window.
* [x] Start and stop the builder appliance automatically as part of the build workflow.
* [x] Reveal prototype output in Finder on macOS.
* [x] Accept:

  * `.img`
  * `.img.bz2`
  * `.img.gz`
  * `.img.xz`
* [x] Reject unsupported file extensions early.
* [x] Add project icon/assets.
* [ ] Replace prototype build wording once the real backend path exists.
* [x] Show distinct host, appliance, guest-handshake, input-image, and prototype-output states.
* [ ] Add a clear pre-build summary of exactly what will happen.
* [ ] Display original image path and chosen output location separately.
* [ ] Add user-selectable output path/name.
* [ ] Warn before overwriting an existing output.
* [x] Add cancel control for the current appliance/prototype workflow.
* [ ] Keep advanced diagnostics hidden by default but accessible.
* [x] Ensure normal users never need Fedora, QEMU, SSH, cloud-init, or partitioning terminology to complete the current workflow.

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
* [ ] Add `gpgv` or another verified signature-validation path to the development bootstrap.
* [ ] Add explicit version reporting for every required dependency.
* [ ] Add minimum-supported version checks rather than presence-only checks.
* [ ] Make bootstrap failures actionable with exact remediation messages.
* [ ] Keep developer bootstrap separate from end-user runtime dependency strategy.

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
* [ ] Detect virtualization acceleration availability separately from QEMU binary availability.
* [ ] Report HVF/KVM/WHPX/TCG capability clearly.
* [ ] Decide fallback policy when hardware acceleration is unavailable.
* [ ] Verify required QEMU machine/device features before starting a build.
* [ ] Stop treating “QEMU exists + qcow2 exists” as sufficient for `ready=true` once integrated guest handshake is available.

---

# 5. Fedora builder appliance acquisition

* [x] Pin a Fedora Cloud release/compose for the current development appliance.
* [x] Select architecture-appropriate Fedora Cloud image.
* [x] Download Fedora Cloud qcow2.
* [x] Download Fedora checksum metadata.
* [x] Download Fedora signing keys.
* [x] Verify image SHA256 against Fedora checksum metadata.
* [x] Validate resulting qcow2 with `qemu-img check`.
* [x] Preserve downloaded base image in appliance work cache.
* [x] Produce `fedora-builder.qcow2` as the base appliance image.
* [x] Keep generated appliance images out of Git.
* [ ] Make signature verification mandatory for release builds.
* [ ] Test `gpgv` verification path rather than relying on checksum-only fallback.
* [ ] Pin or verify the exact Fedora signing key material expected for the selected release.
* [ ] Decide appliance update cadence.
* [ ] Record appliance provenance/version in machine-readable metadata.
* [ ] Add builder-appliance schema/version compatibility with the desktop application.
* [ ] Fail clearly if desktop app and appliance protocol versions differ.

---

# 6. Disposable Fedora runtime

* [x] Keep the downloaded/prepared Fedora qcow2 as a pristine base.
* [x] Create a writable qcow2 backing overlay for each run.
* [x] Boot QEMU from the runtime overlay rather than the base image.
* [x] Verify guest-created files disappear between appliance runs.
* [x] Keep runtime overlay data out of Git.
* [x] Keep runtime UEFI variables separate from the base appliance.
* [x] Generate collision-safe per-session runtime directories rather than one global mutable runtime directory.
* [ ] Support concurrent-build prevention or explicit multi-session isolation.
* [ ] Remove abandoned overlays after crashes.
* [ ] Track runtime disk lifecycle from Rust.
* [ ] Verify the base qcow2 remains byte-for-byte unchanged across normal sessions.
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
* [ ] Add QMP or another structured lifecycle/control channel if useful.
* [x] Implement predictable graceful shutdown.
* [x] Implement forced termination fallback.
* [ ] Detect accidental port collision before QEMU startup.
* [x] Allocate dynamic localhost ports or another transport for parallel-safe operation.
* [ ] Evaluate QEMU vsock for host↔guest control once cross-platform behavior is understood.

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
* [ ] Remove development password authentication from the final appliance workflow.
* [ ] Set `lock_passwd: true` once key-only control is complete.
* [ ] Avoid long-lived reusable host private keys in release builds if ephemeral per-session keys are practical.
* [ ] Version the guest control contract.
* [ ] Provision required image-manipulation tools explicitly instead of relying on Fedora defaults.
* [ ] Add guest-side health/self-test command.

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
* [ ] Surface a concise user message plus detailed diagnostic reason.
* [ ] Remove the shell handshake helper from the production path once Rust owns the protocol.

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
* [ ] Expose appliance states to frontend:

  * unavailable
  * preparing
  * starting
  * booting
  * ready
  * busy
  * stopping
  * stopped
  * failed
* [ ] Add guest command execution API.
* [ ] Avoid allowing arbitrary frontend command strings to be passed directly to a privileged guest shell.
* [ ] Add structured commands/arguments for supported operations.
* [x] Add graceful shutdown command.
* [x] Add timeout and kill fallback.
* [ ] Guarantee cleanup on normal application exit.
* [ ] Attempt cleanup after panic/crash on the next startup.
* [ ] Ensure stale QEMU instances do not interfere with a new build.

---

# 11. Builder environment status model

* [x] Report host OS.
* [x] Report host architecture.
* [x] Report QEMU path/version.
* [x] Report QEMU smoke-test result.
* [x] Report appliance presence/path.
* [ ] Add appliance integrity status.
* [ ] Add runtime preparation status.
* [ ] Add guest boot status.
* [ ] Add guest handshake status.
* [ ] Add guest toolchain/self-test status.
* [ ] Require all relevant statuses before enabling a real build.
* [ ] Add machine-readable error codes instead of relying only on human strings.
* [ ] Keep user-facing messages simple while preserving developer diagnostics.

---

# 12. Input image validation

* [x] Require selected path to exist and be a file.
* [x] Canonicalize selected path.
* [x] Accept supported image/compression extensions.
* [ ] Inspect actual magic bytes instead of trusting extension alone.
* [ ] Detect compression type independently of filename.
* [ ] Verify decompressor availability in guest.
* [ ] Reject directories, device nodes, sockets, FIFOs, and unexpected special files.
* [ ] Determine source image size before build.
* [ ] Verify sufficient host free space for decompression, working copy, overlays, and final output.
* [ ] Detect obvious non-SteamOS images before destructive or expensive processing.
* [ ] Identify SteamOS recovery image version/build if possible.
* [ ] Record input SHA256 for diagnostics/reproducibility.
* [ ] Optionally verify known official Valve image hashes when trustworthy metadata is available.
* [ ] Never reject a legitimate newer Valve image solely because its hash is unknown without a clear compatibility reason.

---

# 13. Input decompression and normalization

* [ ] Support raw `.img` input without unnecessary recompression.
* [ ] Decompress `.img.bz2`.
* [ ] Decompress `.img.gz`.
* [ ] Decompress `.img.xz`.
* [ ] Stream decompression when practical rather than loading whole image into memory.
* [ ] Show decompression progress.
* [ ] Verify decompressed output size is sane.
* [ ] Compute checksum of normalized working image.
* [ ] Keep original compressed input untouched.
* [ ] Clean incomplete normalized images after cancellation/failure.
* [ ] Decide whether normalized working image belongs on host filesystem or inside guest-accessible storage.

---

# 14. Host-to-guest image transport

* [ ] Choose a safe high-performance transport for large recovery images.
* [ ] Evaluate attaching the host working image directly as a QEMU block device.
* [ ] Evaluate virtiofs/shared-folder approaches where supported.
* [ ] Avoid copying multi-gigabyte images over SSH unless there is a compelling reason.
* [ ] Mount/attach user image as read-only for initial inspection.
* [ ] Attach a distinct writable working copy for mutation.
* [ ] Prevent guest from seeing unrelated host directories.
* [ ] Validate paths before exposing them to QEMU.
* [ ] Handle spaces and Unicode in host paths safely.
* [ ] Verify transport on Apple Silicon macOS first.
* [ ] Design transport abstraction that can be implemented on Windows and Linux.

---

# 15. SteamOS recovery-image discovery

* [ ] Inventory partition table without mounting anything writable.
* [ ] Record GPT/partition GUIDs, labels, filesystem types, offsets, and sizes.
* [ ] Determine which partition contains the recovery/root payload relevant to installation.
* [ ] Identify boot/EFI partition.
* [ ] Identify root filesystem layout.
* [ ] Identify `/usr`, `/etc`, `/var`, `/home`, and recovery/install scripts as represented in the image.
* [ ] Determine whether Valve image layout varies by release.
* [ ] Build layout detection around labels/metadata rather than hard-coded partition numbers where possible.
* [ ] Fail safely on unknown layouts.
* [ ] Produce an inspection report before first real NVIDIA modification.
* [ ] Preserve an anonymized layout fixture or synthetic test image for automated tests.

---

# 16. Safe image mutation framework

* [ ] Always operate on a working copy.
* [ ] Mount filesystems read-only during discovery.
* [ ] Escalate to writable mount only for explicitly planned mutation phase.
* [ ] Track every mounted filesystem and loop/NBD device.
* [ ] Use cleanup guards/traps so mounts are released after failures.
* [ ] Sync filesystems before detaching.
* [ ] Validate filesystem consistency after mutation where appropriate.
* [ ] Preserve original partition offsets and sizes unless resize is explicitly required.
* [ ] Avoid repartitioning until proven necessary.
* [ ] Create a transaction manifest listing every modified path.
* [ ] Add deterministic marker-only mutation as the first integration test.
* [ ] Verify marker is present in output and absent from input.
* [ ] Verify second run does not accidentally modify the first input.
* [ ] Verify cancellation cannot modify original image.

---

# 17. First harmless image-mutation milestone

* [ ] Copy/prepare selected SteamOS image into build workspace.
* [ ] Attach it to Fedora guest as data.
* [ ] Detect expected partition/filesystem.
* [ ] Mount target filesystem.
* [ ] Write a project marker such as:

  * `/etc/steamos-nvidia-image-builder-test`
* [ ] Include deterministic marker content with builder version and no host-private information.
* [ ] Unmount cleanly.
* [ ] Detach image.
* [ ] Return output image to host.
* [ ] Verify input checksum remains unchanged.
* [ ] Verify output checksum differs.
* [ ] Re-open output read-only and verify marker.
* [ ] Make the UI report successful image mutation before beginning NVIDIA integration.

---

# 18. NVIDIA support integration strategy

* [ ] Consume supported/certified logic from `open-gpu-kernel-modules-steamos-support` rather than duplicating compatibility rules in the image builder.
* [ ] Define a machine-readable integration interface from the support repo.
* [ ] Resolve SteamOS version/kernel compatibility from the image contents rather than the host.
* [ ] Resolve the appropriate certified NVIDIA release for the target SteamOS image.
* [ ] Preserve development/upstream modes as explicit advanced workflows rather than default end-user behavior.
* [ ] Decide whether the image builder should consume published release artifacts or invoke support-repo build logic inside the Fedora appliance.
* [ ] Prefer reproducible published/certified artifacts for normal users.
* [ ] Verify release checksums/signatures before injection.
* [ ] Record selected NVIDIA driver version in build manifest.
* [ ] Record selected SteamOS/kernel certification in build manifest.
* [ ] Fail closed when no compatible certified release exists unless the user explicitly selects development mode.

---

# 19. NVIDIA kernel-module injection

* [ ] Determine target kernel(s) contained in the recovery image.
* [ ] Place all required open NVIDIA modules in the correct target module tree.
* [ ] Support compressed `.ko.zst` modules where SteamOS expects them.
* [ ] Preserve exact kernel vermagic compatibility.
* [ ] Run target-image `depmod` appropriately.
* [ ] Ensure initramfs contains required NVIDIA modules when necessary.
* [ ] Ensure early modesetting requirements are satisfied.
* [ ] Configure `nvidia-drm.modeset=1` where required by project support policy.
* [ ] Avoid leaving stale conflicting module versions.
* [ ] Verify target image module paths after injection.
* [ ] Add rollback/removal metadata for debugging even though output image is disposable.

---

# 20. NVIDIA userspace injection

* [ ] Install matching NVIDIA userspace libraries into the target image.
* [ ] Install 32-bit userspace libraries where Steam/games require them.
* [ ] Keep userspace and kernel-module NVIDIA versions matched.
* [ ] Verify EGL/GLX/Vulkan loader integration.
* [ ] Verify Vulkan ICD files.
* [ ] Verify GBM/EGL paths used by Gamescope.
* [ ] Avoid overwriting unrelated Mesa/AMD/Intel userspace unnecessarily.
* [ ] Preserve the ability for the resulting SteamOS image to run on the intended NVIDIA system without requiring network access during first boot.
* [ ] Document whether the generated image remains multi-GPU-capable.

---

# 21. Gamescope NVIDIA integration

* [ ] Define how `gamescope-nvidia` artifacts are selected for a target SteamOS release.
* [ ] Keep Gamescope patch selection separate from NVIDIA kernel-module selection.
* [ ] Record Gamescope source/release identifier in build manifest.
* [ ] Apply only the patches required for NVIDIA compatibility.
* [ ] Preserve a path to pristine Valve Gamescope for control testing.
* [ ] Verify Gamescope launches on NVIDIA after generated-image install.
* [ ] Verify Xwayland launches and renders correctly.
* [ ] Verify Steam Gaming Mode renders without severe corruption/artifacts.
* [ ] Test compositor startup, resolution changes, refresh-rate changes, suspend/resume, and game launch/exit.
* [ ] Track known 580-series graphical issues independently of generic image-builder correctness.

---

# 22. SteamOS boot and first-boot integration

* [ ] Determine which image-time changes survive the Valve installer/recovery process.
* [ ] Verify NVIDIA files injected into recovery media are copied into installed SteamOS as intended.
* [ ] If needed, modify recovery/install scripts in a minimal and auditable way.
* [ ] Avoid brittle assumptions about target install disk names.
* [ ] Confirm the generated recovery image does not reproduce the earlier wrong-disk/Optane selection problem without clear user control.
* [ ] Investigate how Valve recovery media chooses installation target.
* [ ] Add target-disk safeguards if the project ever modifies installer disk-selection behavior.
* [ ] Ensure NVIDIA setup occurs before first Gaming Mode launch.
* [ ] Verify first boot without manual TTY intervention.
* [ ] Verify first boot without network access if all required artifacts are embedded.
* [ ] Verify rollback/recovery path if NVIDIA initialization fails.

---

# 23. Output-image construction

* [ ] Produce a distinct output filename.
* [ ] Preserve raw `.img` output as the canonical first format.
* [ ] Decide whether to offer optional `.xz`, `.gz`, or `.bz2` compression.
* [ ] Compute final SHA256.
* [ ] Write sidecar build manifest.
* [ ] Include input hash, app version, appliance version, SteamOS version, NVIDIA version, Gamescope version, and modification summary.
* [ ] Never embed the user’s full host path or username into the output image unless explicitly needed.
* [ ] Verify resulting GPT/filesystems after finalization.
* [ ] Verify output can be opened by standard flashing tools.
* [ ] Reveal output in Finder/Explorer/file manager.

---

# 24. Output validation before success

* [ ] Re-open final image read-only.
* [ ] Re-run partition discovery.
* [ ] Verify required NVIDIA kernel modules exist.
* [ ] Verify expected NVIDIA userspace files exist.
* [ ] Verify Gamescope modification exists when selected.
* [ ] Verify initramfs contents/configuration where applicable.
* [ ] Verify no temporary mount artifacts remain.
* [ ] Verify no runtime SSH keys or Fedora guest secrets leaked into SteamOS output.
* [ ] Verify no Fedora appliance files were copied into SteamOS accidentally.
* [ ] Verify filesystem health.
* [ ] Emit a final validation report.
* [ ] Do not show “Build complete” unless validation passes.

---

# 25. Boot validation automation

* [ ] Determine what portions of the x86 SteamOS output can be boot-tested under QEMU on x86 hosts.
* [ ] Add structural validation for Apple Silicon even when full SteamOS boot emulation is impractical.
* [ ] Consider CI boot smoke tests on x86_64 Linux runners with virtualization access.
* [ ] Detect bootloader presence.
* [ ] Detect kernel/initramfs presence.
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
* [ ] Verify Gamescope uses NVIDIA GPU.
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
* [ ] Track unsupported generations explicitly.
* [ ] Build compatibility matrix by SteamOS release, kernel, NVIDIA release, and GPU generation.

---

# 27. Build reproducibility

* [ ] Pin Fedora appliance source sufficiently for release reproducibility.
* [ ] Pin all downloaded project release artifacts.
* [ ] Record checksums for every external artifact.
* [ ] Avoid resolving “latest” silently during reproducible build mode.
* [ ] Version builder protocol.
* [ ] Version modification manifest schema.
* [ ] Make two builds from identical input/configuration structurally reproducible where timestamps/UUIDs allow.
* [ ] Identify unavoidable nondeterministic fields.
* [ ] Normalize timestamps where safe and appropriate.
* [ ] Add reproducibility test comparing repeated outputs.

---

# 28. Supply-chain and download security

* [x] Verify Fedora image checksum.
* [ ] Require Fedora signature verification for production.
* [ ] Use HTTPS for all downloads.
* [ ] Verify GitHub release artifact hashes where available.
* [ ] Pin expected repository/owner for project artifacts.
* [ ] Defend against malicious redirects or unexpected content types.
* [ ] Avoid shell-piping unverified downloaded code.
* [ ] Verify downloaded executable/archive format before use.
* [ ] Keep network retrieval logic centralized and auditable.
* [ ] Record provenance in build manifest.
* [ ] Add an offline mode once required artifacts can be pre-cached safely.

---

# 29. Security boundaries

* [x] Keep image manipulation inside a Linux guest rather than granting broad host root privileges.
* [x] Bind guest SSH to localhost only during development.
* [x] Use dedicated guest account.
* [ ] Remove guest password authentication from release path.
* [ ] Restrict guest command API.
* [ ] Avoid exposing arbitrary host filesystem paths.
* [ ] Validate every path passed to QEMU.
* [ ] Treat selected recovery image as untrusted input.
* [ ] Mount untrusted filesystems with conservative options where practical.
* [ ] Avoid automatically executing binaries from the SteamOS image.
* [ ] Keep QEMU networking disabled unless the guest actually needs network access for a stage.
* [ ] Prefer host-mediated verified downloads over unrestricted guest downloads for release builds.
* [ ] Audit temp-file permissions.
* [ ] Audit SSH key permissions.
* [ ] Audit runtime cleanup for secret leakage.

---

# 30. Large-file and disk-space management

* [ ] Estimate required disk space before build.
* [ ] Account for compressed input size.
* [ ] Account for decompressed image size.
* [ ] Account for working copy.
* [ ] Account for qcow2 runtime overlay.
* [ ] Account for final output.
* [ ] Add safety reserve.
* [ ] Choose workspace filesystem deliberately.
* [ ] Avoid duplicating multi-gigabyte image data unnecessarily.
* [ ] Use sparse/reflink/copy-on-write techniques where reliable.
* [ ] Report disk-space failure before beginning expensive work.
* [ ] Clean partial artifacts after failure/cancel.
* [ ] Preserve final output when cleanup succeeds.

---

# 31. Progress reporting

* [x] Define structured prototype build stages in the progress UI.
* [ ] Report current stage from Rust to frontend.
* [ ] Add stage percentages where meaningful.
* [ ] Avoid fake linear percentages for operations with unknown duration.
* [ ] Show bytes processed during copy/decompression/compression.
* [x] Show appliance startup separately from prototype output creation.
* [ ] Show NVIDIA/Gamescope integration steps separately.
* [x] Preserve and display the current session's QEMU/serial log through completion.
* [ ] Add a “Copy diagnostics” action.
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
* [ ] Always clean guest mounts after errors.
* [x] Always stop QEMU after the current prototype build fails.
* [x] Preserve useful appliance logs after current-session cleanup.
* [ ] Never delete the original user image.
* [ ] Never leave the UI claiming success after a partial failure.

---

# 33. Cancellation

* [ ] Support cancellation while downloading.
* [ ] Support cancellation while copying/decompressing.
* [x] Support cancellation while the guest is booting.
* [ ] Support cancellation during image mutation.
* [ ] Support cancellation during compression/finalization.
* [ ] Make cancellation cooperative first.
* [x] Add bounded forced termination fallback.
* [ ] Unmount/detach filesystems on cancellation.
* [ ] Delete incomplete output by default or clearly mark it incomplete.
* [x] Never modify the original image during the current cancellable prototype workflow.

---

# 34. Logging and diagnostics

* [x] Create a unique per-build runtime/diagnostic directory.
* [ ] Record app version.
* [ ] Record host OS/architecture.
* [ ] Record QEMU version.
* [ ] Record appliance version.
* [ ] Record input filename without requiring full private path in exported reports.
* [ ] Record input checksum.
* [ ] Record SteamOS layout detection result.
* [ ] Record selected NVIDIA certification.
* [ ] Record selected Gamescope build/patch identifier.
* [ ] Capture guest command exit statuses.
* [x] Capture QEMU stderr/serial logs.
* [ ] Redact private keys and sensitive host paths from user-shareable diagnostics.
* [ ] Add one-click diagnostics export.

---

# 35. Automated testing

## Rust/unit tests

* [x] Test supported-image detection.
* [ ] Test extension/magic mismatch handling.
* [ ] Test QEMU binary selection by architecture.
* [ ] Test environment status state machine.
* [ ] Test command argument construction.
* [ ] Test build-manifest serialization.
* [ ] Test error mapping.

## Appliance tests

* [x] Manually verify disposable overlay behavior.
* [x] Manually verify cloud-init first boot.
* [x] Manually verify SSH authorized-key injection.
* [x] Manually verify readiness marker handshake.
* [ ] Automate disposable-overlay persistence test.
* [ ] Automate guest health/self-test.
* [ ] Test damaged base qcow2 detection.
* [ ] Test missing firmware.
* [ ] Test occupied SSH/control port.
* [ ] Test boot timeout.

## Image tests

* [ ] Create small synthetic disk-image fixtures.
* [ ] Test GPT discovery.
* [ ] Test ext4/btrfs/etc. filesystem discovery as needed.
* [ ] Test marker mutation without using Valve images in CI.
* [ ] Test cleanup after forced mutation failure.
* [ ] Test input checksum preservation.
* [ ] Test output validation.

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
* [ ] Add synthetic appliance/image integration tests where CI virtualization permits.
* [ ] Do not require proprietary/Valve recovery images in public CI.
* [ ] Cache safe dependencies without caching mutable secret/runtime state.

---

# 37. macOS end-user runtime

* [x] Use Homebrew dependencies for development bring-up.
* [ ] Do not require end users to understand or manually install Homebrew as the final product model.
* [ ] Decide whether QEMU is bundled, downloaded/managed by the app, or supplied through another distributable runtime.
* [ ] Bundle or manage UEFI firmware consistently.
* [ ] Bundle or manage Fedora appliance consistently.
* [ ] Verify Apple Silicon support.
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

* [ ] Inventory required guest tools.
* [ ] Include partition inspection tools.
* [ ] Include filesystem tools.
* [ ] Include compression tools.
* [ ] Include `qemu-img`/guest utilities where needed.
* [ ] Include checksum/signature verification tools.
* [ ] Include Git/curl only if guest-side source retrieval remains part of design.
* [ ] Pin package versions or appliance image version sufficiently for reproducibility.
* [ ] Build appliance once for release rather than installing packages during every user build.
* [ ] Add appliance self-test for required binaries/features.

---

# 42. Builder protocol design

* [ ] Define protocol version.
* [ ] Define health command.
* [ ] Define inspect-image command.
* [ ] Define prepare-working-image command.
* [ ] Define mutate-marker command.
* [ ] Define integrate-NVIDIA command.
* [ ] Define integrate-Gamescope command.
* [ ] Define validate-output command.
* [ ] Return structured JSON instead of parsing human shell output.
* [ ] Include machine-readable progress events.
* [ ] Include stable error codes.
* [ ] Keep protocol backward-compatible across minor app updates where practical.
* [ ] Reject incompatible protocol versions clearly.

---

# 43. Build manifest

* [ ] Define manifest schema.
* [ ] Include application version/commit.
* [ ] Include appliance version/hash.
* [ ] Include input SHA256.
* [ ] Include detected SteamOS version.
* [ ] Include detected target kernel(s).
* [ ] Include NVIDIA version/release source.
* [ ] Include NVIDIA artifact checksums.
* [ ] Include Gamescope version/artifact checksums.
* [ ] Include all modified target paths.
* [ ] Include final image SHA256.
* [ ] Include build timestamp only where nondeterminism is acceptable.
* [ ] Save manifest beside output image.
* [ ] Optionally place a copy inside generated SteamOS image for later diagnostics.

---

# 44. Compatibility policy

* [ ] Define what SteamOS versions are supported.
* [ ] Define whether only exact certified kernel matches are supported by default.
* [ ] Reuse bounded certified fallback policy from the NVIDIA support project where appropriate.
* [ ] Never silently inject modules for an incompatible target kernel.
* [ ] Define supported NVIDIA GPU generations.
* [ ] Define unsupported legacy/proprietary-driver-only cases.
* [ ] Define behavior for newer unknown Valve images.
* [ ] Define behavior when no Gamescope patch is available.
* [ ] Display compatibility result before starting expensive mutation.

---

# 45. Development modes

* [ ] Default normal users to certified NVIDIA support only.
* [ ] Add explicit advanced development mode for project-patched NVIDIA source/artifacts.
* [ ] Add explicit pristine-upstream control mode if useful for image-level testing.
* [ ] Keep development outputs visibly labeled as non-certified.
* [ ] Embed development source identifiers in manifest.
* [ ] Prevent accidental publication of a development image as a stable build.
* [ ] Allow advanced users to retain Fedora runtime/logs for debugging.

---

# 46. User safety

* [x] Do not directly flash USB drives in initial scope.
* [x] Do not modify original input image.
* [ ] Never enumerate and write arbitrary physical disks during normal build flow.
* [ ] If flashing is ever added, make it a separate explicitly dangerous workflow.
* [ ] Require unmistakable device identification before any future flashing operation.
* [ ] Prevent output path from resolving to the input file.
* [ ] Prevent output path from resolving to a block device.
* [ ] Verify sufficient space before starting.
* [ ] Preserve recoverable logs after failure.
* [ ] Make experimental NVIDIA/Gamescope status visible before user flashes an image.

---

# 47. Valve recovery-image legal/distribution boundary

* [x] Require users to obtain the official Valve recovery image themselves.
* [x] Provide a link/button to Valve’s download page rather than bundling Valve image content.
* [x] Keep generated Valve image files out of source control.
* [ ] Document that the app modifies a user-provided image locally.
* [ ] Review Valve/SteamOS redistribution terms before distributing any derivative image artifact from project infrastructure.
* [ ] Do not publish premodified Valve recovery images as GitHub release assets without clear legal permission.
* [ ] Prefer distributing code, recipes, patches, manifests, and builder appliance—not Valve filesystem content.
* [ ] Clearly distinguish Valve trademarks/assets from project branding.

---

# 48. Project licensing

* [ ] Add or confirm repository license.
* [ ] Audit third-party licenses for bundled QEMU/firmware/Fedora components.
* [ ] Audit licenses for any redistributed NVIDIA-related artifacts.
* [ ] Audit Gamescope patch/build redistribution requirements.
* [ ] Include required notices in packaged application.
* [ ] Keep Valve image content outside project distribution boundary.

---

# 49. Documentation

* [ ] Update README because current text still describes the Fedora/QEMU backend as unimplemented.
* [ ] Document current working appliance architecture.
* [ ] Document developer bootstrap.
* [ ] Document appliance build process.
* [ ] Document disposable-overlay behavior.
* [ ] Document handshake design.
* [ ] Document generated runtime files and why they are ignored.
* [ ] Document input/output safety guarantees.
* [ ] Document supported input formats.
* [ ] Document current compatibility status.
* [ ] Document known limitations.
* [ ] Add troubleshooting guide.
* [ ] Add architecture diagram.
* [ ] Add contributor workflow.
* [ ] Add release process.
* [ ] Keep this TODO synchronized as milestones are completed.

---

# 50. Repository hygiene

* [x] Ignore generated Fedora qcow2 images.
* [x] Ignore appliance work directory.
* [x] Ignore runtime directory.
* [x] Keep private runtime SSH key out of Git.
* [x] Keep generated cloud-init runtime copy out of Git.
* [ ] Add checks to prevent accidental commit of multi-gigabyte image files.
* [ ] Add checks to prevent accidental commit of private keys.
* [ ] Keep generated SteamOS output images out of Git.
* [ ] Keep build logs/diagnostics out of Git unless sanitized fixtures.
* [ ] Remove stale prototype assets/code when real implementation supersedes them.

---

# 51. Performance

* [ ] Measure Fedora guest boot time.
* [ ] Measure image decompression time.
* [ ] Measure host↔guest large-file transport throughput.
* [ ] Measure image copy/mutation time.
* [ ] Measure final compression time.
* [ ] Avoid repeated appliance startup when multiple safe stages can share one session.
* [ ] Avoid keeping appliance alive indefinitely while idle.
* [ ] Tune vCPU and guest memory allocation based on host resources.
* [ ] Prevent application from exhausting low-memory hosts.
* [ ] Use hardware acceleration where available.
* [ ] Keep TCG functional enough for compatibility/testing if retained.

---

# 52. Resource policy

* [ ] Detect host RAM.
* [ ] Choose sane guest memory default.
* [ ] Detect host CPU count.
* [ ] Choose sane guest vCPU default.
* [ ] Keep enough resources for host UI responsiveness.
* [ ] Detect low disk space before guest startup.
* [ ] Allow advanced resource override only if needed.
* [ ] Record effective resource configuration in diagnostics.

---

# 53. Application lifecycle

* [ ] Prevent accidental app quit during irreversible/finalization stages or make quit equivalent to safe cancellation.
* [x] Stop the managed QEMU child when application state is dropped on exit.
* [ ] Clean session overlay on app exit when safe.
* [ ] Detect stale runtime state on next launch.
* [ ] Offer cleanup of abandoned workspace data.
* [ ] Preserve completed output even if app crashes immediately afterward.
* [ ] Keep state machine recoverable after frontend reload.

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

* [ ] Keep source repository free of generated qcow2 binaries.
* [ ] Decide whether a compressed Fedora builder appliance should be distributed as a GitHub Release asset.
* [ ] If distributed, publish its checksum and provenance.
* [ ] Version appliance separately from desktop app if necessary.
* [ ] Publish only project-owned/generated runtime assets that are legally distributable.
* [ ] Do not publish Valve recovery images.
* [ ] Define cache invalidation when a new appliance release is required.

---

# 56. Alpha acceptance gate

Before calling the project **alpha**, verify all of the following:

* [ ] Rust launches and controls Fedora without manual terminal commands.
* [ ] Guest readiness handshake is automatic.
* [ ] User can select an official Valve recovery image.
* [ ] Original image remains unchanged.
* [ ] App produces a separate modified output image.
* [ ] Output modification is deterministic and validated.
* [ ] NVIDIA kernel modules/userspace are integrated through the intended support-repo path.
* [ ] Required Gamescope NVIDIA changes are integrated or explicitly not required for the tested configuration.
* [ ] Generated image installs/boots on the primary RTX 2060 test system.
* [ ] Gaming Mode reaches a usable graphical state.
* [ ] Build failure never damages input image.
* [ ] End user does not need to manually use QEMU, Fedora, SSH, mount, or chroot commands.

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
* [ ] NVIDIA/Gamescope artifacts are verified.
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
* [ ] Defer GUI controls for advanced upstream/development NVIDIA modes until certified-image generation works.
* [ ] Defer automated physical-disk installation targeting until the generated recovery image itself is proven.
* [ ] Defer VR/Valve Index-specific SteamOS work to a separate compatibility effort unless it becomes directly relevant to image construction.
* [ ] Defer non-NVIDIA GPU customization; the project’s initial purpose is NVIDIA-oriented SteamOS image construction.

---

# 61. Long-term possibilities

* [ ] Optional direct USB flashing with extremely strong device-selection safeguards.
* [ ] Automatic detection/download assistance for current official Valve recovery image without redistributing it.
* [ ] Local artifact cache manager.
* [ ] Offline build mode.
* [ ] Multiple certified NVIDIA profiles.
* [ ] Experimental driver/Gamescope profiles.
* [ ] Automated compatibility report upload with explicit user consent.
* [ ] Rebuild/update workflow for an already-installed SteamOS system.
* [ ] Recovery-image comparison/diff tooling.
* [ ] GUI diagnostics viewer.
* [ ] Advanced custom package injection framework only if it does not dilute the NVIDIA-focused safety model.

---

# 62. Immediate next implementation sequence

1. [x] Add Rust-owned appliance process manager.
2. [x] Reproduce current shell handshake from Rust.
3. [x] Report real guest-ready state to frontend.
4. [x] Add graceful shutdown/cleanup.
5. [ ] Add one structured guest command such as `health`.
6. [ ] Add a tiny host↔guest file-transfer or block-attachment proof.
7. [ ] Attach a synthetic disk image and inspect it read-only.
8. [ ] Implement deterministic marker mutation on synthetic image.
9. [ ] Run the same inspection path against a user-supplied Valve recovery image.
10. [ ] Produce first modified Valve-image working copy containing only a harmless marker.
11. [ ] Validate output and input immutability automatically.
12. [ ] Only then begin NVIDIA support-repo integration.

---

# 63. Definition of the intended end-user experience

The stable target workflow should eventually be approximately:

1. User downloads an official Valve SteamOS recovery image.
2. User opens SteamOS NVIDIA Image Builder.
3. User selects or drops the recovery image.
4. App validates the image and compatibility.
5. App prepares its managed Fedora/QEMU builder environment automatically.
6. App creates a separate working copy.
7. App injects the certified NVIDIA/Gamescope support required for that SteamOS image.
8. App validates the modified filesystem and image structure.
9. App writes a separate output image and manifest.
10. App reveals the output file.
11. User flashes the output with the disk-imaging tool of their choice.

No normal step should require the user to manually operate QEMU, SSH into Fedora, mount partitions, select kernel-module releases, edit SteamOS files, or understand the internal appliance architecture.

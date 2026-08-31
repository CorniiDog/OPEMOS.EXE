# SteamOS NVIDIA Image Builder

The main window includes a compact settings panel for durable, non-secret preferences. Settings use a versioned `settings.json`; GitHub credentials are never stored there. On macOS, maintainer connection opens the GitHub CLI browser flow in a visible Terminal window while the responsive settings panel polls for completion. Maintainer release controls require a live permission check against `CorniiDog/open-gpu-kernel-modules-steamos-support` and a second backend permission check immediately before publication.

When an exact-kernel NVIDIA artifact is built locally and reaches `locally-built-verified`, maintainers who opted in receive a release confirmation naming the repository, tag, pinned support commit, trust classification, and archive hash. “No, keep local” is focused by default. Publication uses the support repository's hash-pinned canonical publisher: Rust cross-checks its dry-run JSON and then invokes only its create-only mode. It refuses to overwrite an existing release and uploads only the NVIDIA archive, checksum, external build-info, and provenance sidecar—never the recovery image or generated SteamOS image.

The main build card also exposes a per-build NVIDIA source selector. `Automatic` remains the default and follows the nearest compatible same-series release; `Latest` explicitly selects the newest available project branch; individual `nvidia/<version>` branches can be selected for controlled testing. An off-by-default setting can additionally expose numeric tags from NVIDIA's official `NVIDIA/open-gpu-kernel-modules` repository in a separate experimental group. Upstream selections require a transient per-build acknowledgement, are re-resolved to an exact tag commit, must have matching Arch Archive userspace inputs before the long build begins, and are never offered to the automated publisher. Every source choice is pinned to an exact commit before the x86_64 build begins.

A desktop application that takes an official Valve SteamOS recovery image and prepares a locally generated NVIDIA-oriented SteamOS image.

## Current milestone

The first target is macOS. The desktop shell provides drag-and-drop, file picker fallback, Valve download-page access, and one image-driven build action. A separate progress window automatically manages the builder appliance, displays live logs and status, supports cancellation, and reveals the generated raw image in Finder.

The Rust backend prepares a disposable Fedora session, launches QEMU in the background, polls the guest's SSH readiness marker, reports lifecycle states, and performs graceful shutdown with a forced-stop fallback. When no exact published NVIDIA artifact exists, the resolver can now offer a long on-demand x86_64 build using the exact image kernel and a same-series publication only as the NVIDIA-version baseline. Declining that build still exports the harmless `-marker.img`; no mismatched published modules are reused. A compatible published or locally-built-verified target proceeds through authenticated userspace installation and reserves `-nvidia.img` for a successful structured install plus independent read-only output inspection. A versioned `.img.manifest.json` sidecar records filenames (never full host paths), formats, sizes, hashes, layout, modified paths, NVIDIA target/trust metadata, validation status, and the automatic-versus-pinned source policy. Automatic builds may follow a newer compatible verified profile later; an explicit project or upstream selection remains pinned to that NVIDIA version and requires an exact-kernel rebuild after a SteamOS kernel change. Gamescope and recovery-media installer integration are still separate gates, so an NVIDIA-mutated output is not yet classified as install-ready.

On Apple Silicon, the normal inspection/mutation appliance remains native
aarch64 with HVF acceleration. Development tooling can acquire and launch a
separate x86_64 Fedora appliance under TCG software emulation for exact-kernel
NVIDIA compilation and offline-root installation. The Rust backend owns an
isolated lifecycle for that worker, including its disposable overlay and
credentials, dynamic SSH port, architecture health check, logs, ten-minute
emulated-boot timeout, and shutdown cleanup. The support repository's complete
Fedora suite, real recursive bind-mount cleanup, real signed-package validation,
and validation/mutation cancellation paths have passed in that managed x86_64
appliance. For a compatible published artifact, the normal frontend now stops
the native guest while preserving its working qcow2, boots the x86 worker from
Fedora alone, then hot-plugs that layer through a dedicated PCIe port only after
Fedora is ready. It performs read-only installer validation and then invokes the
same pinned installer in mutation mode. The first real recovery-image run of
this newly integrated mutation path remains the immediate test gate.

An opt-in development command can copy an explicitly selected support-repository
checkout into the managed x86 worker and execute its fixed offline-target build
contract. Output is streamed to the worker log rather than buffered on the UI
thread. Control flow uses the support repository's versioned final-result JSON,
including its stable failure reason, target identity, trust classification,
artifact filenames, and hash; human logs remain diagnostic only. Returned
archives are accepted only after independent host-side checksum, archive
membership, metadata, and target-identity validation. The result JSON is
preserved beside successful artifacts and in archived failure diagnostics. The
worker also prepares the support repository's reviewed, hash-pinned Valve
keyring and requires the exact historical header package's detached signature;
the host rejects returned metadata that does not confirm that verification. The
host also requires the schema-1 provenance sidecar to exactly match the embedded
`PROVENANCE.json`, validates its target/trust/signer and five-module metadata,
and hashes every archived module against it. The normal build button does not
invoke this command yet.

The complete exact-target path has been exercised locally on Apple Silicon.
The current support HEAD completed in 53 minutes 25 seconds: the emulated
x86_64 Fedora worker authenticated the historical SteamOS 3.8.14 headers,
built and structurally validated all five NVIDIA 575.64.05 modules with exact
target vermagic, produced structured provenance, and passed every independent
host check. The result remains `development-unverified`: Fedora 44's GCC 16.2.1
differs from the GCC 15.1.1 reported by the kernel build, and the safe checkout
transfer does not expose `.git` provenance to the guest. The full run used
support commit `d6a43f5`; the following `e5d183e` compiler-parser fix passes its
focused local contract test but has not repeated the hour-long compilation.
An additional 148-second managed-appliance preflight now covers experimental
upstream selection without compiling modules: it resolves matching userspace,
checks out NVIDIA's `575.64.05` tag at the exact API-resolved commit, checks out
the pinned support commit, verifies the support repository's upstream source
URL contract, and accepts only the exact schema-1 SteamOS 3.8.14 target plan.

The normal progress flow now assesses the discovered offline target and consumes
the support repository's schema-2 published-release policy. It permits NVIDIA
resolution only for a valid SteamOS version, x86_64 userspace, and exactly one
safe kernel release. The host queries GitHub through its bundled Rust HTTPS
client, applies the bounded non-forward SteamOS-series policy while still
requiring the exact kernel, and treats a missing compatible publication as a
normal marker-only result. It never substitutes the published SteamOS 3.8.16
`valve24.5` modules for the observed SteamOS 3.8.14 `valve24.4` kernel.

For a compatible publication, the host downloads the checksum, provenance, and
archive into disposable session storage. Acceptance requires GitHub SHA-256
digests, the archive checksum, safe and exact archive membership, byte-identical
external and embedded provenance, the pinned Valve header signer, x86_64 module
identity, exact target vermagic, and all five per-module hashes. Trust remains
the provenance value (`locally-built-verified` for the current release) rather
than being promoted merely because an artifact was published. A live Rust test
has downloaded and passed the current SteamOS 3.8.16/NVIDIA 575.64.05 release.
Injection is enabled only after the complete input set passes the pinned support
installer's structured `--validate-only` contract in x86_64 Fedora. Mutation
must then return `success/install_complete`, release every mount, and pass an
initramfs-content check before Rust will allow an NVIDIA-named export.

After accepting a compatible module publication, the backend now queries the
official Arch Linux Archive for exact-version `nvidia-utils` and
`lib32-nvidia-utils` packages. It independently selects the highest signed
package release for each name, so a valid `575.64.05-2`/`575.64.05-1` pairing is
not rejected. Packages and detached signatures are downloaded through bounded,
cancellable streams, hashed while transferring, and retained only in backend
session state. Their trust remains explicitly `pending-x86-validation`; the UI
cannot provide alternate paths or promote them before the managed x86 installer
checks the reviewed signer policy, package contents, and exact GSP firmware.

The backend also stages the offline-root installer from immutable support commit
`af36f43b2b1571d8c5c9a0d0379b094de7954715`. Its eight required scripts,
helpers, and signer-policy files have embedded byte counts and SHA-256 pins;
every file must match before a versioned bundle manifest is recorded. The
normal workflow therefore does not accept a user-selected support checkout or
follow a moving branch. Failed or cancelled downloads remove the entire partial
bundle, and repeated preparation revalidates and reuses the session-owned copy.
The handoff transfers that bundle plus the verified module archive, checksum,
provenance, exact userspace packages, and detached signatures into the x86
worker. Because the guest uses a fixed archive basename, Rust derives its guest
checksum sidecar from the already verified archive digest with that exact fixed
name; the pinned support validator then independently rehashes the transferred
archive. It prepares a minimal keyring from Fedora's trusted Arch key material,
mounts uniquely identified `rootfs-A`, `var-A`, and `efi-A` read-only, and accepts only a
schema-1 `validated/validation_complete` result whose target, trust, hashes,
package-specific signers, Holo database, EFI boot policy, and released-mount
status all match Rust-owned state.
Mutation mounts the Btrfs top level explicitly, identifies the current default
root subvolume, temporarily clears only that subvolume's read-only property,
mounts the matching `var-A` at `/var` and `efi-A` at `/efi` without hiding
rootfs `/boot`, and restores both Btrfs read-only and seed-device state
afterward. The resulting raw candidate is reopened through a
fresh appliance and checked for all five modules, matching package records and
GSP firmware, configuration, provenance state, initramfs output, exact
nonduplicated GRUB kernel arguments, layout, and source immutability before
finalization.

The same immutable support commit supplies the canonical NVIDIA release
publisher and its input validator under independent size and SHA-256 pins. The
app first requires a schema-1 dry-run plan whose repository, tag, target commit,
trust, archive hash, and ordered asset paths exactly match Rust-owned state. It
then rechecks maintainer permission and invokes `--create-only`; the app never
uses the publisher's release-edit or asset-clobber path.

The older `steamos-nvidia-installer` project remains a useful reference for the
later recovery-media contract: an install-ready result also needs the `home`
partition's desktop launcher and tools, a safely preserved and patched Valve
`repair_device.sh`, and verification that rootfs, EFI, and home changes survive
installation. Those responsibilities are tracked separately and are not implied
by this NVIDIA root/EFI mutation milestone.

Marker-only exports use an explicit `-marker.img` suffix. A structured successful
installation plus independent payload inspection uses `-nvidia.img`. Existing
trailing `-marker`/`-nvidia` suffixes are normalized first so repeated builds do
not produce names such as `-nvidia-nvidia-marker.img`.

That filename normalization is not yet full NVIDIA-install idempotency. A future
repeat-build preflight must mount the selected rootfs and `var-A` read-only and
validate the installer's recorded kernel, NVIDIA version, build information,
and provenance. An exact verified match should be reported as already current
without rebuilding or mutating it; a different requested NVIDIA version or
target kernel is an explicit upgrade; incomplete or inconsistent state must
fail closed instead of being guessed from the filename.

The observed Valve SteamOS 3.8.14 recovery image has no pacman database at
`/var/lib/pacman`, either in the selected Btrfs root or `var-A`; the latter
contains only `lib/overlays`, and its recovery `fstab` leaves `/var` commented
out. SteamOS instead keeps its package database under
`/usr/lib/holo/pacmandb`. The builder now verifies that database exists and
requires the pinned support installer to own and report that internal database
selection; no second CLI override exists. The builder independently rechecks
the reported path and package count, then validates the exact installed package
records from the Holo database in the exported image.

The recovery root also owns a populated `/boot` containing the Neptune kernel
and initramfs images; `efi-A` separately contains `EFI/steamos/grub.cfg` and the
EFI loader. The builder mounts `efi-A` at `<root>/efi`, never over `<root>/boot`,
so target `mkinitcpio` updates the real rootfs initramfs. Independent output
verification mounts both `var-A` and `efi-A` read-only, checks exact module
version/vermagic and Holo package versions, and requires the installed
provenance file to retain its validated SHA-256.

## Architecture

The Tauri frontend invokes a fixed set of Rust commands; it does not pass arbitrary shell commands to the host or guest. Rust owns the QEMU child process and creates a unique runtime directory containing an ephemeral SSH identity, cloud-init seed, qcow2 overlay, writable UEFI variables, and `qemu.log`. The pristine Fedora appliance remains unchanged.

Closing the progress window cancels the active image build. Closing the main application gracefully powers off the managed guest, falls back to terminating QEMU after a bounded wait, archives `qemu.log`, and removes the disposable overlay and SSH credentials. Partial exports use hidden temporary names beside the requested output and are removed after cancellation or failure. Abandoned inactive session directories are cleaned on the next launch.

Rust detects input format from file signatures rather than extensions. Raw images pass through unchanged; `.bz2`, `.gz`, and `.xz` streams are decompressed by a cancellable background worker into raw storage inside the disposable session. Bzip2 prefers 7-Zip's multithreaded decoder, falls back to `pbzip2` when available, and retains an embedded decoder as the dependency-free fallback; gzip and xz use embedded streaming decoders. Live byte counters and phase-specific activity rings keep the window responsive during source hashing, decompression, transfer, and normalized-image verification. QEMU receives that raw image as a read-only virtio block device plus a distinct writable qcow2 overlay backed by it. Fedora verifies that neither device is mounted, the source is read-only, the working layer is writable, and both expose the same size and partition-table type. The current conservative layout detector recognizes Valve's observed GPT `esp`, `efi-A`, `rootfs-A`, `var-A`, and `home` roles only when their labels, filesystem types, and partition-type GUIDs match unambiguously; unknown layouts remain non-actionable. Rust verifies hashes for both the original source and attached raw image before and after inspection. NVIDIA build/install logic will come from `open-gpu-kernel-modules-steamos-support`, patched NVIDIA source from `open-gpu-kernel-modules-steamos`, and the compositor payload from `gamescope-nvidia`.

The current guest protocol exposes only fixed Rust-owned operations. Protocol version `1` provides a health check for guest identity, architecture, free space, and required tools; a deterministic host→guest→host transfer probe verified byte-for-byte; synthetic inspection and mutation fixtures; structured read-only inspection of the selected raw image; and marker mutation on the selected image's disposable qcow2 working layer. Before real-image mutation, QEMU hot-unplugs the separately attached read-only source to prevent duplicate Btrfs filesystem identity resolution. The working `rootfs-A` is mounted explicitly, Valve's Btrfs read-only state is cleared only on the overlay and restored after verification, all mounts are released, and the original host input is re-hashed. While that root is mounted, the backend reads bounded values from regular `os-release` files, inspects an ELF header for target architecture, and inventories regular `/usr/lib/modules` directories without executing target-image content or following image-controlled top-level symlinks. This metadata is logged and recorded in the sidecar manifest as the input to future certified NVIDIA artifact resolution. The frontend cannot submit arbitrary guest shell commands.

## Development

```bash
npm install
npm run dev
```

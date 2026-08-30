# SteamOS NVIDIA Image Builder

A desktop application that takes an official Valve SteamOS recovery image and prepares a locally generated NVIDIA-oriented SteamOS image.

## Current milestone

The first target is macOS. The desktop shell provides drag-and-drop, file picker fallback, Valve download-page access, and one image-driven build action. A separate progress window automatically manages the builder appliance, displays live logs and status, supports cancellation, and reveals the generated raw image in Finder.

The Rust backend prepares a disposable Fedora session, launches QEMU in the background, polls the guest's SSH readiness marker, reports lifecycle states, and performs graceful shutdown with a forced-stop fallback. The current marker milestone exports the modified qcow2 working state as a separate raw `.img`, then attaches that candidate read-only to a fresh validation appliance, rediscovers the supported Valve layout, verifies the marker, rechecks the original input hash, and only then gives the output its final name. A versioned `.img.manifest.json` sidecar records filenames (never full host paths), formats, sizes, hashes, layout, modified paths, and validation status. This marker-only output does **not** yet contain NVIDIA or Gamescope integration and is not an install-ready project release.

On Apple Silicon, the normal inspection/mutation appliance remains native
aarch64 with HVF acceleration. Development tooling can acquire and launch a
separate x86_64 Fedora appliance under TCG software emulation for exact-kernel
NVIDIA compilation and offline-root installation. The Rust backend owns an
isolated lifecycle for that worker, including its disposable overlay and
credentials, dynamic SSH port, architecture health check, logs, ten-minute
emulated-boot timeout, and shutdown cleanup. The support repository's complete
Fedora suite, real recursive bind-mount cleanup, real signed-package validation,
and validation/mutation cancellation paths have passed in that managed x86_64
appliance. The normal frontend does not move or mutate the working image through
the x86 worker yet.

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
Injection is intentionally not enabled yet: the verified download is removed
with the disposable session and the exported output remains clearly
marker-only.

After accepting a compatible module publication, the backend now queries the
official Arch Linux Archive for exact-version `nvidia-utils` and
`lib32-nvidia-utils` packages. It independently selects the highest signed
package release for each name, so a valid `575.64.05-2`/`575.64.05-1` pairing is
not rejected. Packages and detached signatures are downloaded through bounded,
cancellable streams, hashed while transferring, and retained only in backend
session state. Their trust remains explicitly `pending-x86-validation`; the UI
cannot provide alternate paths or promote them before the managed x86 installer
checks the reviewed signer policy, package contents, and exact GSP firmware.

Marker-only exports use an explicit `-marker.img` suffix. The builder reserves
the `-nvidia.img` label for a future output that has successfully installed and
independently validated the complete NVIDIA payload.

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

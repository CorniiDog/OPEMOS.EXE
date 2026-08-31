# Fedora Builder Appliance

This directory contains the development tooling for the isolated Fedora
environment used by SteamOS NVIDIA Image Builder.

The generated appliance is:

```text
fedora-builder.qcow2
```

By default, `build_macos.sh` downloads the Fedora architecture matching the
Mac. This remains the fast appliance used for image inspection and mutation.

On Apple Silicon, prepare the separate x86_64 appliance required by native
x86_64 NVIDIA module compilation with:

```bash
./builder/appliance/build_macos.sh --architecture x86_64
```

That command writes `fedora-builder-x86_64.qcow2`; it never replaces the
native `fedora-builder.qcow2`. Inspect the resolved URLs and output path without
downloading anything with:

```bash
./builder/appliance/build_macos.sh --architecture x86_64 --resolve-only
```

A successful build also writes `<appliance>.metadata.json`. The sidecar records
the Fedora release, compose, architecture, source URLs, source/checksum/keyring
hashes, appliance protocol version, and whether the checksum signature was
verified. Appliance replacement is atomic: a failed download, copy, or
`qemu-img check` leaves the last valid qcow2 in place.

The x86_64 guest must use software emulation on Apple Silicon and will be much
slower than the native aarch64 appliance. It is intended only for exact-kernel
NVIDIA artifact compilation when no certified published artifact exists.

After creating it, inspect or launch the separate development VM with:

```bash
./builder/appliance/run_macos.sh --architecture x86_64 --resolve-only
./builder/appliance/run_macos.sh --architecture x86_64
```

The launch plan uses `qemu-system-x86_64` with TCG software emulation when the
host is Apple Silicon. Its runtime directory is also separate, so it cannot
overwrite or collide with the native appliance runtime.

Every launch creates a new SSH identity in the ignored runtime directory and
injects only its public key with cloud-init. The `builder` account is locked and
SSH password authentication is disabled; there is no reusable appliance
password.

The Tauri backend also exposes an isolated managed lifecycle for this x86_64
worker. After the separate appliance has been prepared, its opt-in lifecycle
test is:

```bash
cargo test --manifest-path src-tauri/Cargo.toml \
  live_nvidia_build_appliance_reaches_ready_marker -- --ignored --nocapture
```

The test can take several minutes under Apple Silicon software emulation. It
verifies the guest architecture, clean shutdown, disposable-runtime removal,
log archival, and base-appliance immutability. It does not compile NVIDIA yet.

After that lifecycle test passes, run the opt-in exact-kernel compilation test
with explicit host inputs:

```bash
NVIDIA_SUPPORT_REPO=/Users/connor/Desktop/open-gpu-kernel-modules-steamos-support \
NVIDIA_TARGET_ARTIFACT_DIR=/Users/connor/Downloads/nvidia-target-test \
cargo test --manifest-path src-tauri/Cargo.toml \
  live_nvidia_offline_target_build -- --ignored --nocapture
```

This installs Fedora build dependencies into the disposable overlay, searches
for the exact historical Valve headers, downloads the NVIDIA source branch,
and performs a full compilation under emulated x86_64. It may take substantially
longer than the lifecycle test. The host validates and preserves the returned
archive, checksum, and build-info file in `NVIDIA_TARGET_ARTIFACT_DIR`; it never
treats this result as certified while header signatures remain unverified.
The controller also requests and validates the support repository's schema-1
build-result JSON, preserves it beside successful artifacts, and uses its typed
reason/message for failures instead of parsing the human build log.
It prepares the support checkout's reviewed, hash-pinned Valve keyring inside
the disposable guest, requires the manifest's single approved signer for the
headers package, and accepts the returned metadata only when detached-signature
verification is recorded.
The controller also preserves the schema-1 provenance sidecar, requires it to
match the archive's embedded `PROVENANCE.json`, validates its target, trust,
signer and exact five-module metadata, and verifies each archived module hash.

The current support HEAD completed the full Apple Silicon path in 53 minutes 25
seconds for SteamOS 3.8.14, kernel
`6.16.12-valve24.4-1-neptune-616-gfe145653a794`, and NVIDIA 575.64.05. It
authenticated the exact headers, produced all five modules with exact vermagic,
emitted provenance, and passed host validation. Fedora 44 used GCC 16.2.1 while
the Valve kernel build reports GCC 15.1.1, so the successful result remains
compiler-mismatch-unverified until the support policy reproduces or explicitly
validates that toolchain difference.

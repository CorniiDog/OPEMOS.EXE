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

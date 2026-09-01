# Headless VM harness

Run `npm run test:vm-headless` from the repository root. The harness boots the existing immutable x86_64 Fedora appliance through QEMU TCG, creates a disposable qcow2 system overlay and a 64 MiB synthetic raw disk, and controls the guest only through NoCloud seed media and the serial console.

The VM has no emulated network device, GUI, monitor, SSH workflow, host-disk passthrough, secrets, or persistent host permission. Guest code refuses to write unless the target is the uniquely serialed synthetic virtio disk, differs from the guest root device, and has the exact expected capacity. It then creates unambiguous synthetic `rootfs-A` and `rootfs-B` partitions, mutates only B, restores B from a disposable backup, and verifies the rollback hash. Every runtime artifact is created beneath the nested ignored `work/` directory and removed on exit.

The final machine-readable record is written to `tests/headless-vm/results/latest.json`. Missing QEMU, seed-media tooling, or the base image produces a `skipped` record and exit status 2; test failures produce a `failed` record and exit status 1.

Set `STEAMOS_HEADLESS_VM_BASE` only when the immutable appliance lives outside `builder/appliance/fedora-builder-x86_64.qcow2`. The value must name a regular, non-symlink qcow2 file. Homebrew's QEMU UEFI firmware is discovered automatically; a non-Homebrew installation can set `STEAMOS_HEADLESS_VM_FIRMWARE_DIR` to the directory containing `edk2-x86_64-code.fd` and `edk2-i386-vars.fd`. `STEAMOS_HEADLESS_VM_TIMEOUT_SECONDS` may reduce or extend the default 180-second deadline.

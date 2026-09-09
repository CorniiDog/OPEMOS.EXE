# Retained virtual USB lifecycle

The live harness reuses the same authenticated resolution, signed userspace,
pinned Core installer, offline validation, installation, export, and completed
image inspection functions as the desktop workflow. It retains the completed
image and adjacent manifest beneath this directory's ignored `work/` root.

Set `STEAMOS_RECOVERY_IMAGE` to a non-symlink regular Valve recovery image,
enable the reviewed experimental Linux TCG path, and run the exact ignored test
through the shared heavy-work wrapper:

```bash
OPEMOS_EXPERIMENTAL_LINUX=1 OPEMOS_LINUX_ACCEL=tcg \
  STEAMOS_RECOVERY_IMAGE=/absolute/path/to/steamdeck-repair.img \
  "/home/connor/Documents/ChatGPT/Handoff troubleshooting/opemos-scheduler/heavy.sh" \
  cargo test --manifest-path src-tauri/Cargo.toml \
  tests::live_authenticated_nvidia_image_is_retained_for_virtual_usb -- \
  --ignored --exact --nocapture
```

The test refuses output path drift and linked inputs or output roots. Existing
output collisions fail closed. A successful run prints the completed-image
record and leaves the image and manifest in `tests/virtual-usb/work/` for the
separate exact 32 GiB write, install, and reinstall lifecycle. It does not
publish artifacts, activate production trust, or access physical disks.

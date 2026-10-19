"""Create exact same-job Mac runtime, companion and read-only chooser input.

Only existing official Homebrew/Fedora/Valve and immutable GitHub inputs. No
formula installation, private endpoint, credential enrollment or original write.
"""
import bz2
import json
import os
from pathlib import Path
import urllib.request

from acquire_appliance_windows import acquire, load_lock, stage
from acquire_runtime_macos import construct
from stage_runtime_bundle import digest

RECOVERY_URL = "https://steamdeck-images.steamos.cloud/recovery/steamdeck-oobe-repair-20260707.10-3.8.14.img.bz2"
RECOVERY_BYTES = 8120172544
RECOVERY_SHA256 = "f9aa0fa2dd618febf28a5e2a583d1e2b5a8ca3f1205be965da584602ac962f40"


def prepare(root, evidence):
    output = root / "admitted-macos"
    output.mkdir(exist_ok=False)
    # Both exact firmware pins are already present in the locked Homebrew QEMU
    # bottle. The producer verifies them after acquisition; no Actions artifact
    # download, mutable lookup or firmware fallback is necessary.
    construct(root / "runtime/macos-arm64.sources.json", output / "runtime", evidence)
    lock = load_lock(root / "runtime/windows-fedora-appliance.json")
    image = acquire(lock, output / "fedora-cache", deadline_seconds=1800)
    stage(lock, image, root / "builder/appliance/cloud-init", output / "appliance")
    documents = Path.home() / "Documents"
    documents.mkdir(exist_ok=True)
    recovery = documents / "opemos-pinned-recovery.img"
    if recovery.exists() or recovery.is_symlink():
        raise ValueError("Chooser original must be create-only")
    partial = documents / ".opemos-pinned-recovery.img.partial"
    decoder = bz2.BZ2Decompressor()
    received = 0
    with urllib.request.urlopen(RECOVERY_URL, timeout=60) as response, partial.open("xb") as target:
        while not decoder.eof:
            block = response.read(1024 * 1024)
            if not block:
                raise ValueError("Truncated official recovery")
            received += len(block)
            if received > 5 * 1024**3:
                raise ValueError("Recovery compressed size exceeds bound")
            raw = decoder.decompress(block, max_length=min(1024**2, RECOVERY_BYTES + 1 - target.tell()))
            target.write(raw)
            while not decoder.needs_input and not decoder.eof:
                if target.tell() >= RECOVERY_BYTES:
                    raise ValueError("Recovery expanded size exceeds bound")
                target.write(decoder.decompress(b"", max_length=min(1024**2, RECOVERY_BYTES + 1 - target.tell())))
            if target.tell() > RECOVERY_BYTES:
                raise ValueError("Recovery expanded size exceeds bound")
        if decoder.unused_data or response.read(1):
            raise ValueError("Trailing recovery archive data")
        target.flush()
        os.fsync(target.fileno())
    if partial.stat().st_size != RECOVERY_BYTES or digest(partial) != RECOVERY_SHA256:
        raise ValueError("Exact original recovery identity mismatch")
    partial.chmod(0o444)
    partial.rename(recovery)
    (evidence / "macos-input-producer.json").write_text(json.dumps({
        "firmwareSource": "locked-qemu-bottle-exact-existing-pair",
        "recovery": {"url": RECOVERY_URL, "path": str(recovery), "bytes": RECOVERY_BYTES, "sha256": digest(recovery)},
        "applianceSHA256": lock["sha256"], "complete": True}, indent=2) + "\n")


if __name__ == "__main__":
    import sys
    prepare(Path(__file__).resolve().parents[1], Path(sys.argv[1]))

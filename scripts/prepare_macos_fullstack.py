"""Create exact same-job Mac runtime, companion and read-only chooser input.

Only existing official Homebrew/Fedora/Valve and immutable GitHub inputs. No
formula installation, private endpoint, credential enrollment or original write.
"""
import bz2
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import zipfile

from acquire_appliance_windows import acquire, load_lock, stage
from acquire_runtime_macos import construct
from stage_macos_app import FIRMWARE
from stage_runtime_bundle import digest

ARTIFACT = 12187147443
ARTIFACT_BYTES = 2237313105
ARTIFACT_SHA256 = "4009e7a432b7f757542c38e7698577aff8b9f461ad8606f84bea1243305c66e5"
RECOVERY_URL = "https://steamdeck-images.steamos.cloud/recovery/steamdeck-oobe-repair-20260707.10-3.8.14.img.bz2"
RECOVERY_BYTES = 8120172544
RECOVERY_SHA256 = "f9aa0fa2dd618febf28a5e2a583d1e2b5a8ca3f1205be965da584602ac962f40"


def prepare(root, evidence):
    output = root / "admitted-macos"
    output.mkdir(exist_ok=False)
    firmware = output / "firmware"
    firmware.mkdir()
    archive = output / "existing-windows-firmware-artifact.zip"
    # gh uses only the existing readonly Actions token and never prints it.
    metadata = json.loads(subprocess.check_output([
        "gh", "api", f"repos/CorniiDog/OPEMOS.EXE/actions/artifacts/{ARTIFACT}"], text=True, timeout=30))
    if (metadata["id"], metadata["size_in_bytes"], metadata["workflow_run"]["head_sha"]) != (
            ARTIFACT, ARTIFACT_BYTES, "c439b20243bb053706769bac60b3921941a32cb6"):
        raise ValueError("Immutable firmware artifact identity changed")
    with archive.open("xb") as stream:
        subprocess.run(["gh", "api", f"repos/CorniiDog/OPEMOS.EXE/actions/artifacts/{ARTIFACT}/zip"],
                       stdout=stream, check=True, timeout=1200)
    if archive.stat().st_size != ARTIFACT_BYTES or digest(archive) != ARTIFACT_SHA256:
        raise ValueError("Immutable firmware artifact archive hash mismatch")
    with zipfile.ZipFile(archive) as source:
        for relative, (size, sha256) in FIRMWARE.items():
            name = Path(relative).name
            matches = [i for i in source.infolist() if i.filename.endswith("/qemu/share/" + name)]
            if len(matches) != 1 or matches[0].file_size != size:
                raise ValueError("Ambiguous firmware artifact member")
            target = firmware / name
            with target.open("xb") as stream:
                stream.write(source.read(matches[0]))
            if digest(target) != sha256:
                raise ValueError("Original firmware bytes changed")
    construct(root / "runtime/macos-arm64.sources.json", output / "runtime", evidence, firmware)
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
        "firmwareArtifact": ARTIFACT, "archiveSHA256": digest(archive),
        "recovery": {"url": RECOVERY_URL, "path": str(recovery), "bytes": RECOVERY_BYTES, "sha256": digest(recovery)},
        "applianceSHA256": lock["sha256"], "complete": True}, indent=2) + "\n")


if __name__ == "__main__":
    import sys
    prepare(Path(__file__).resolve().parents[1], Path(sys.argv[1]))

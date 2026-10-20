"""Create exact same-job Mac runtime, companion and read-only chooser input.

Only existing official Homebrew/Fedora/Valve and immutable GitHub inputs. No
formula installation, private endpoint, credential enrollment or original write.
"""
import bz2
import json
import os
from pathlib import Path
import tempfile
import shutil
import subprocess
import urllib.request

from acquire_appliance_windows import acquire, load_lock, stage
from acquire_runtime_macos import construct, load_lock as load_runtime_lock, probe_runtime, verify_firmware_pair
from stage_runtime_bundle import digest, validate_runtime

RETAINED_ARCHIVE_BYTES = 1102515341
RETAINED_ARCHIVE_SHA256 = "c2748a0ee1dfd149945f48fa48e8809f0eb3fcdd4c02e1ae788795006421e2f9"
RETAINED_MANIFEST_SHA256 = "eab631c9b4e277d9050c1d28fe448ac3c002be30fba025f56bc3beb274d7e9d5"


def reuse_retained(root, output, evidence, archive):
    """Only the fully hashed 5dc package's unchanged runtime, not its app binary."""
    from stage_macos_app import verify_companion
    if (archive.is_symlink() or not archive.is_file()
            or archive.stat().st_size != RETAINED_ARCHIVE_BYTES
            or digest(archive) != RETAINED_ARCHIVE_SHA256):
        raise ValueError("Retained complete runtime archive identity mismatch")
    scratch = Path(tempfile.mkdtemp(prefix="opemos-retained-runtime-")).resolve()
    subprocess.run(["ditto", "-x", "-k", str(archive), str(scratch)], check=True, timeout=120)
    app = scratch / "SteamOS NVIDIA Builder.app"
    resources = app / "Contents/Resources"
    runtime = resources / "runtime"
    _, _, manifest_hash = validate_runtime(runtime, "macos")
    if (manifest_hash != RETAINED_MANIFEST_SHA256
            or json.loads((runtime / "source-provenance.json").read_bytes())
                != load_runtime_lock(root / "runtime/macos-arm64.sources.json")
            or digest(runtime / "licenses/OPEMOS-LICENSE") != digest(root / "LICENSE")
            or digest(runtime / "licenses/source-notices.json")
                != digest(root / "runtime/macos-licenses/source-notices.json")):
        raise ValueError("Retained runtime/source/license contract changed")
    verify_companion(resources / "appliance")
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], check=True, timeout=60)
    shutil.copytree(runtime, output / "runtime", symlinks=False)
    shutil.copytree(resources / "appliance", output / "appliance", symlinks=False)
    verify_firmware_pair(output / "runtime/share/qemu")
    probe_runtime(output / "runtime")
    if validate_runtime(output / "runtime", "macos")[2] != RETAINED_MANIFEST_SHA256:
        raise ValueError("Reused runtime manifest changed during native probes")
    verify_companion(output / "appliance")
    if digest(archive) != RETAINED_ARCHIVE_SHA256:
        raise ValueError("Retained original archive changed")
    (evidence / "darwin-runtime-producer.json").write_text(json.dumps({
        "mode": "reuse-exact-previously-measured-derivative", "complete": True,
        "originalProducerHead": "5dc31f3c2afd2894818b4e94792a30afdfd322dc",
        "archiveSHA256": RETAINED_ARCHIVE_SHA256, "runtimeManifestSHA256": manifest_hash,
        "sourceLockSHA256": digest(root / "runtime/macos-arm64.sources.json"),
        "bottleAcquisitionOrRelocationExecuted": False, "currentNativeProbesPassed": True,
    }, indent=2) + "\n")
    # Only this producer's exact fresh extraction, never the retained archive.
    shutil.rmtree(scratch)

RECOVERY_URL = "https://steamdeck-images.steamos.cloud/recovery/steamdeck-oobe-repair-20260707.10-3.8.14.img.bz2"
RECOVERY_BYTES = 8120172544
RECOVERY_SHA256 = "f9aa0fa2dd618febf28a5e2a583d1e2b5a8ca3f1205be965da584602ac962f40"


def consume_input_receipt(path, source_root, recovery):
    """Bind private generated-directory custody; payload verification follows."""
    from stage_macos_app import FEDORA
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError("Producer receipt must be a bounded regular file")
    inputs = json.loads(path.read_bytes())
    if (not isinstance(inputs, dict) or set(inputs) != {"inputRoot", "identity", "complete",
            "firmwareSource", "recovery", "applianceSHA256"} or inputs["complete"] is not True
            or inputs["firmwareSource"] != "locked-qemu-bottle-exact-existing-pair"
            or inputs["applianceSHA256"] != FEDORA[2]
            or inputs["recovery"] != {"url": RECOVERY_URL, "path": str(recovery),
                                      "bytes": RECOVERY_BYTES, "sha256": RECOVERY_SHA256}):
        raise ValueError("Input receipt schema or immutable identity changed")
    root = Path(inputs["inputRoot"])
    if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
            or root.resolve(strict=True) != root or source_root.resolve() in root.parents
            or root.parent != Path(tempfile.gettempdir()).resolve(strict=True)
            or not root.name.startswith("opemos-macos-inputs-")):
        raise ValueError("Unrecognized generated input custody")
    metadata = root.stat()
    if (inputs["identity"] != {"device": metadata.st_dev, "inode": metadata.st_ino,
            "uid": os.getuid(), "mode": 0o700} or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o777 != 0o700):
        raise ValueError("Generated input UID/directory identity changed")
    return inputs, root


def prepare(root, evidence):
    # Private generated payload must not become untracked repository source.
    # mkdtemp is create-only with actual current-UID custody, outside Git.
    output = Path(tempfile.mkdtemp(prefix="opemos-macos-inputs-")).resolve(strict=True)
    if root.resolve() == output or root.resolve() in output.parents:
        raise ValueError("Generated input root must be outside the source repository")
    metadata = output.stat()
    identity = {"device": metadata.st_dev, "inode": metadata.st_ino,
                "uid": metadata.st_uid, "mode": metadata.st_mode & 0o777}
    receipt = {"inputRoot": str(output), "identity": identity, "complete": False}
    (evidence / "macos-input-producer.json").write_text(json.dumps(receipt, indent=2) + "\n")
    # Both exact firmware pins are already present in the locked Homebrew QEMU
    # bottle. The producer verifies them after acquisition; no Actions artifact
    # download, mutable lookup or firmware fallback is necessary.
    lock = load_lock(root / "runtime/windows-fedora-appliance.json")
    retained = os.environ.get("OPEMOS_RETAINED_MAC_APP_ARCHIVE")
    if retained:
        reuse_retained(root, output, evidence, Path(retained))
    else:
        construct(root / "runtime/macos-arm64.sources.json", output / "runtime", evidence)
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
    receipt.update({
        "firmwareSource": "locked-qemu-bottle-exact-existing-pair",
        "recovery": {"url": RECOVERY_URL, "path": str(recovery), "bytes": RECOVERY_BYTES, "sha256": digest(recovery)},
        "applianceSHA256": lock["sha256"], "complete": True})
    (evidence / "macos-input-producer.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    import sys
    prepare(Path(__file__).resolve().parents[1], Path(sys.argv[1]))

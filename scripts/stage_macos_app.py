"""Stage a relocatable native Mac app with the existing exact x86 companion.

Consumes an already acquired, source-pinned Darwin runtime. Never downloads
packages, signing keys, images, or credentials. No release signing/publication.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import tempfile

from stage_runtime_bundle import digest, validate_runtime

FEDORA = ("fedora-builder.qcow2", 583729152,
          "28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f")
CLOUD_INIT = [
    ("cloud-init/meta-data", 75, "8c5c072b26bd904148b4b1fe1699fe7bf4701d3f8661549aa332ba611d0001ac"),
    ("cloud-init/user-data", 474, "78b1be42378b2409724a2a673a8fb0ffe55c67fb053edfaf760b402b47e5d5ce"),
]
# Platform-independent EDK2 pair already pinned in the existing x86 runtime
# transaction; do not replace it with a newly downloaded/unreviewed firmware.
FIRMWARE = {
    "share/qemu/edk2-x86_64-code.fd": (3653632, "33090cc07675baa5190d9f1e84bf5176b33bcbfa9bacac522961150cdb6dbb2a"),
    "share/qemu/edk2-i386-vars.fd": (540672, "5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e"),
}


def verify_files(root, expected):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Companion root must be a real directory")
    for entry in root.rglob("*"):
        if entry.is_symlink() or not (entry.is_file() or entry.is_dir()):
            raise ValueError("Companion contains a symlink or special file")
    for relative, size, sha256 in expected:
        path = root / relative
        if any(parent.is_symlink() for parent in [path, *path.parents]
               if parent == root or root in parent.parents):
            raise ValueError("Companion symlink is forbidden")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != size or digest(path) != sha256:
            raise ValueError("Companion identity changed: " + relative)
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    if actual != {x[0] for x in expected} | {"appliance-manifest.json"}:
        raise ValueError("Companion inventory is not closed")


def verify_companion(root):
    expected = [FEDORA, *CLOUD_INIT]
    manifest_path = root / "appliance-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > 65536:
        raise ValueError("Invalid companion manifest")
    manifest = json.loads(manifest_path.read_bytes())
    fields = {"schema_version", "appliance_protocol_version", "fedora_release", "fedora_compose",
              "architecture", "source_url", "files"}
    if set(manifest) != fields or any(manifest.get(k) != v for k, v in {
        "schema_version": 1, "appliance_protocol_version": 1, "fedora_release": "44",
        "fedora_compose": "1.7", "architecture": "x86_64",
        "source_url": "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2",
    }.items()) or sorted(manifest["files"], key=lambda f: f["path"]) != sorted([
        {"path": p, "size": n, "sha256": h} for p, n, h in expected], key=lambda f: f["path"]):
        raise ValueError("Companion must match existing exact x86 Fedora contract")
    verify_files(root, expected)


def stage(app, runtime, appliance, output, source_commit):
    if len(source_commit) != 40 or any(c not in "0123456789abcdef" for c in source_commit):
        raise ValueError("Exact source commit required")
    runtime, raw, manifest_hash = validate_runtime(runtime, "macos")
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in runtime.rglob("*")):
        raise ValueError("Mac runtime may not follow undeclared symlinks or special files")
    manifest = json.loads(raw)
    declared = {f["path"]: (f["size"], f["sha256"]) for f in manifest["files"]}
    if any(declared.get(path) != identity for path, identity in FIRMWARE.items()):
        raise ValueError("Declared existing exact pinned x86 firmware pair is required")
    app, appliance = Path(app), Path(appliance)
    if app.is_symlink() or not app.is_dir() or app.suffix != ".app":
        raise ValueError("A complete real .app is required")
    if any(p.is_symlink() for p in app.rglob("*")):
        raise ValueError("App may not depend on external symlinks")
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    name = info.get("CFBundleExecutable", "")
    if info.get("CFBundleIdentifier") != "dev.cornidog.steamos-nvidia-image-builder" or not name or Path(name).name != name:
        raise ValueError("Wrong app identity")
    binary = app / "Contents/MacOS" / name
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("App executable missing")
    for destination in [app / "Contents/Resources/runtime", app / "Contents/Resources/appliance"]:
        if destination.exists():
            raise ValueError("Source app already contains a companion; refuse stale overlay")
    verify_companion(appliance)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="." + output.name + ".", dir=output.parent))
    try:
        staged_app = staging / app.name
        shutil.copytree(app, staged_app, symlinks=False)
        macos = staged_app / "Contents/MacOS"
        resources = staged_app / "Contents/Resources"
        resources.mkdir(exist_ok=True)
        shutil.copytree(runtime, resources / "runtime", symlinks=False)
        shutil.copytree(appliance, resources / "appliance", symlinks=False)
        validate_runtime(resources / "runtime", "macos")
        verify_companion(resources / "appliance")
        if digest(macos / name) != digest(binary):
            raise ValueError("App bytes changed during staging")
        # Strict native startup contract, inside the archive and resource seal.
        # Final executable digest belongs to independent outer evidence/cache,
        # not inside its own signed resources (which would be self-referential).
        (resources / "bundle-provenance.json").write_text(json.dumps({
            "schema_version": 1, "platform": "macos", "source_commit": source_commit,
            "runtime_manifest_sha256": manifest_hash, "executable_name": name,
        }, indent=2) + "\n")
        # Existing ad-hoc test identity only: no certificate, entitlement or release.
        subprocess.run(["codesign", "--force", "--sign", "-", str(staged_app)], check=True, timeout=60)
        subprocess.run(["codesign", "--verify", "--deep", "--strict", str(staged_app)], check=True, timeout=60)
        # Signing the outer app may change only its main executable/seal. The
        # accepted runtime and companion bytes must still match their contracts.
        validate_runtime(resources / "runtime", "macos")
        verify_companion(resources / "appliance")
        (staging / "bundle-provenance.json").write_text(json.dumps({
            "schema_version": 1, "platform": "macos", "mode": "explicit-x86_64-tcg-diagnostic",
            "source_commit": source_commit, "runtime_manifest_sha256": manifest_hash,
            "application": {"path": app.name, "executable": name, "sha256": digest(macos / name), "pre_seal_sha256": digest(binary)},
            "appliance": {"architecture": "x86_64", "sha256": FEDORA[2]},
            "release_signed": False,
        }, indent=2) + "\n")
        if output.exists():
            raise ValueError("Output appeared during staging")
        os.rename(staging, output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return output / app.name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["application", "runtime-root", "appliance-root", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    print(stage(args.application, args.runtime_root, args.appliance_root, args.output, args.source_commit))


if __name__ == "__main__":
    main()

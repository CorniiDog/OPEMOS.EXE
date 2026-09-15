#!/usr/bin/env python3
"""Validate and stage one exact, self-contained OPEMOS runtime payload."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile


REQUIRED = {
    "windows": {"git", "python", "qemu-img", "qemu-system-x86_64", "mkisofs", "ssh", "scp", "ssh-keygen", "gh", "bash", "tar"},
    "linux": {"git", "python3", "qemu-img", "qemu-system-x86_64", "genisoimage", "ssh", "scp", "ssh-keygen", "gh", "bash", "tar"},
    "macos": {"git", "python3", "qemu-img", "qemu-system-aarch64", "ssh", "scp", "ssh-keygen", "gh", "bash", "tar"},
}


def fail(message):
    raise SystemExit(message)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def relative(value):
    path = Path(value)
    return bool(value) and "\\" not in value and not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts)


def validate_runtime(root, platform):
    supplied = root
    supplied_metadata = supplied.lstat()
    if supplied.is_symlink() or not stat.S_ISDIR(supplied_metadata.st_mode):
        fail("Runtime root must be a real directory")
    root = root.resolve(strict=True)
    manifest_path = root / "runtime-manifest.json"
    metadata = manifest_path.lstat()
    if manifest_path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
        fail("Runtime manifest must be a bounded regular file")
    raw = manifest_path.read_bytes()
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Runtime manifest is invalid: {error}")
    if set(manifest) != {"schema_version", "platform", "commands", "files", "components"}:
        fail("Runtime manifest fields are not closed")
    if manifest["schema_version"] != 1 or manifest["platform"] != platform:
        fail("Runtime manifest platform or schema is wrong")
    commands = manifest["commands"]
    if not isinstance(commands, dict) or set(commands) != REQUIRED[platform]:
        fail("Runtime command inventory is incomplete or contains extras")
    files = manifest["files"]
    if not isinstance(files, list) or not files:
        fail("Runtime file inventory is empty")
    declared = set()
    for item in files:
        if set(item) != {"path", "sha256", "size"} or not relative(item["path"]):
            fail("Runtime file identity is invalid")
        if item["path"] in declared:
            fail("Runtime file identity is duplicated")
        declared.add(item["path"])
        path = root / item["path"]
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size != item["size"] or item["size"] <= 0:
            fail(f"Runtime file changed: {item['path']}")
        if digest(path) != item["sha256"]:
            fail(f"Runtime file hash changed: {item['path']}")
    for name, path in commands.items():
        if not name or "/" in name or "\\" in name or path not in declared:
            fail("Runtime command mapping is invalid")
    components = manifest["components"]
    if not isinstance(components, list) or not components:
        fail("Runtime component inventory is empty")
    for component in components:
        if set(component) != {"name", "version", "license_files"} or not component["name"] or not component["version"]:
            fail("Runtime component identity is invalid")
        licenses = component["license_files"]
        if not isinstance(licenses, list) or not licenses or any(path not in declared for path in licenses):
            fail("Every runtime component requires a declared license file")
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "runtime-manifest.json"
    }
    if actual != declared:
        fail("Runtime directory contains undeclared or missing files")
    return root, raw, hashlib.sha256(raw).hexdigest()


def stage(runtime_root, output, platform, source_commit, applications):
    if len(source_commit) != 40 or any(character not in "0123456789abcdef" for character in source_commit):
        fail("Source commit must be one lowercase 40-character Git commit")
    runtime_root, _manifest, manifest_hash = validate_runtime(runtime_root, platform)
    if output.exists():
        fail("Bundle output must not already exist")
    resolved_applications = []
    for application in applications:
        supplied_metadata = application.lstat()
        if application.is_symlink() or not stat.S_ISREG(supplied_metadata.st_mode):
            fail("Application artifact must be a regular file")
        source = application.resolve(strict=True)
        resolved_applications.append(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    staged = []
    try:
        shutil.copytree(runtime_root, staging / "runtime", symlinks=False)
        for source in resolved_applications:
            target = staging / source.name
            shutil.copy2(source, target)
            staged.append({"filename": target.name, "size": target.stat().st_size, "sha256": digest(target)})
        (staging / "bundle-provenance.json").write_text(json.dumps({
            "schema_version": 1,
            "platform": platform,
            "source_commit": source_commit,
            "runtime_manifest_sha256": manifest_hash,
            "applications": staged,
        }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        if output.exists():
            fail("Bundle output appeared during staging")
        os.rename(staging, output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return manifest_hash


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=sorted(REQUIRED), required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--application", type=Path, action="append", required=True)
    args = parser.parse_args()
    print(stage(args.runtime_root, args.output, args.platform, args.source_commit, args.application))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Acquire the pinned Ubuntu runtime used by the Linux application bundle."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile

try:
    from stage_runtime_bundle import REQUIRED, validate_runtime
except ModuleNotFoundError:  # Imported as scripts.acquire_runtime_linux by tests.
    from scripts.stage_runtime_bundle import REQUIRED, validate_runtime


def fail(message):
    raise SystemExit(message)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def exact_file(path, item):
    if path.is_symlink() or not path.exists():
        return False
    metadata = path.stat()
    return stat.S_ISREG(metadata.st_mode) and metadata.st_size == item["size"] and digest(path) == item["sha256"]


def load_lock(path):
    raw = json.loads(path.read_text(encoding="utf-8"))
    if set(raw) != {"schema_version", "distribution", "archives"} or raw["schema_version"] != 1 or raw["distribution"] != "Ubuntu 24.04":
        fail("Linux runtime source lock is invalid")
    archives = raw["archives"]
    if not isinstance(archives, list) or len(archives) != 63:
        fail("Linux runtime source lock must contain the exact archive closure")
    names = set()
    for item in archives:
        if (set(item) != {"package", "version", "file", "sha256", "size"}
                or not all(isinstance(item[key], str) and item[key] for key in ("package", "version", "file", "sha256"))
                or not isinstance(item["size"], int) or item["size"] <= 0
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or Path(item["file"]).name != item["file"] or item["file"] in names):
            fail("Linux runtime source lock contains an invalid archive")
        names.add(item["file"])
    return raw


def acquire_archive(item, cache, runner=subprocess.run):
    target = cache / item["file"]
    if exact_file(target, item):
        return target
    if target.exists() or target.is_symlink():
        target.unlink()
    cache.mkdir(parents=True, exist_ok=True)
    before = set(cache.iterdir())
    runner(["apt-get", "download", f'{item["package"]}={item["version"]}'], cwd=cache, check=True)
    created = set(cache.iterdir()) - before
    if target not in created or not exact_file(target, item):
        for path in created:
            if path.is_file():
                path.unlink()
        fail(f'Pinned archive identity mismatch: {item["package"]}')
    return target


COMMAND_PATHS = {
    "bash": "usr/bin/bash",
    "genisoimage": "usr/bin/genisoimage",
    "gh": "usr/bin/gh",
    "git": "usr/bin/git",
    "python3": "usr/bin/python3.12",
    "qemu-img": "usr/bin/qemu-img",
    "qemu-system-x86_64": "usr/bin/qemu-system-x86_64",
    "scp": "usr/bin/scp",
    "ssh": "usr/bin/ssh",
    "ssh-keygen": "usr/bin/ssh-keygen",
    "tar": "usr/bin/tar",
}


def extracted_file(path, extraction):
    if path.is_symlink():
        target = Path(os.readlink(path))
        path = extraction / target.relative_to("/") if target.is_absolute() else path.parent / target
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(extraction.resolve(strict=True))
    except ValueError:
        fail("Archive link escapes the verified extraction root")
    if not resolved.is_file():
        fail("Archive runtime entry is not a regular file")
    return resolved


def current_lock_matches(root, lock):
    provenance = root / "source-provenance.json"
    if provenance.is_symlink() or not provenance.is_file():
        return False
    expected = json.dumps(lock, sort_keys=True, separators=(",", ":")) + "\n"
    return provenance.read_text(encoding="utf-8") == expected


def construct(output, cache, lock_path):
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        fail("Pinned Linux runtime acquisition requires Ubuntu x86_64")
    lock = load_lock(lock_path)
    if output.exists():
        validate_runtime(output, "linux")
        if current_lock_matches(output, lock):
            return output
        fail("Existing Linux runtime does not match the current source lock")
    for item in lock["archives"]:
        acquire_archive(item, cache)

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    try:
        for name in ("bin", "lib", "licenses", "sources"):
            (staging / name).mkdir()
        extraction = staging / ".archive-extraction"
        extraction.mkdir()
        for item in lock["archives"]:
            subprocess.run(["dpkg-deb", "--extract", str(cache / item["file"]), str(extraction)], check=True)

        commands = {}
        for name in sorted(REQUIRED["linux"]):
            source = extracted_file(extraction / COMMAND_PATHS[name], extraction)
            target = staging / "bin" / name
            shutil.copy2(source, target)
            target.chmod(target.stat().st_mode | 0o111)
            commands[name] = target.relative_to(staging).as_posix()

        for archived in sorted(extraction.rglob("*.so*")):
            if not (archived.is_file() or archived.is_symlink()):
                continue
            source = extracted_file(archived, extraction)
            destination = staging / "lib" / archived.name
            if destination.exists() and digest(destination) != digest(source):
                fail(f"Runtime library basename collision: {archived.name}")
            if not destination.exists():
                shutil.copy2(source, destination)

        components = []
        for item in sorted(lock["archives"], key=lambda entry: entry["package"]):
            package = item["package"]
            notice = extracted_file(extraction / "usr/share/doc" / package / "copyright", extraction)
            license_target = staging / "licenses" / f"{package}.txt"
            shutil.copy2(notice, license_target)
            shutil.copy2(cache / item["file"], staging / "sources" / item["file"])
            components.append({"name": package, "version": item["version"], "license_files": [license_target.relative_to(staging).as_posix()]})

        (staging / "source-provenance.json").write_text(json.dumps(lock, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        shutil.rmtree(extraction)
        files = []
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                files.append({"path": path.relative_to(staging).as_posix(), "sha256": digest(path), "size": path.stat().st_size})
        manifest = {"schema_version": 1, "platform": "linux", "commands": commands, "files": files, "components": components}
        (staging / "runtime-manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        validate_runtime(staging, "linux")
        if output.exists():
            fail("Linux runtime output appeared during acquisition")
        os.rename(staging, output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return output


def main():
    repository = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=repository / "build/runtime/linux")
    parser.add_argument("--cache", type=Path, default=repository / "build/runtime-cache/linux")
    parser.add_argument("--lock", type=Path, default=repository / "runtime/linux-ubuntu-24.04-amd64.sources.json")
    args = parser.parse_args()
    print(construct(args.output, args.cache, args.lock))


if __name__ == "__main__":
    main()

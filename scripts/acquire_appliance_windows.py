#!/usr/bin/env python3
"""Acquire and stage the exact Windows Fedora builder appliance."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
import urllib.request


LOCK_FIELDS = {
    "schema_version", "filename", "size", "sha256", "url",
    "fedora_release", "fedora_compose", "architecture",
}
CLOUD_INIT = {
    "cloud-init/meta-data": (75, "8c5c072b26bd904148b4b1fe1699fe7bf4701d3f8661549aa332ba611d0001ac"),
    "cloud-init/user-data": (474, "78b1be42378b2409724a2a673a8fb0ffe55c67fb053edfaf760b402b47e5d5ce"),
}
DOWNLOAD_CHUNK_SIZE = 1024 * 1024
DOWNLOAD_PROGRESS_INTERVAL = 64 * 1024 * 1024
DOWNLOAD_SOCKET_TIMEOUT_SECONDS = 120
DEFAULT_DOWNLOAD_DEADLINE_SECONDS = 4500


def fail(message):
    raise SystemExit(message)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def exact_file(path, size, sha256):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (not path.is_symlink() and stat.S_ISREG(metadata.st_mode)
            and metadata.st_size == size and digest(path) == sha256)


def canonical_text(path, size, sha256):
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        fail(f"Bundled Fedora appliance support path is not a regular file: {path}")
    content = path.read_bytes().replace(b"\r\n", b"\n")
    if b"\r" in content or len(content) != size or hashlib.sha256(content).hexdigest() != sha256:
        fail(f"Bundled Fedora appliance support file changed: {path.relative_to(path.parents[1]).as_posix()}")
    return content


def load_lock(path):
    document = json.loads(path.read_text(encoding="utf-8"))
    if (set(document) != LOCK_FIELDS or document["schema_version"] != 1
            or document["filename"] != "fedora-builder.qcow2"
            or document["architecture"] != "x86_64"
            or not isinstance(document["size"], int) or document["size"] <= 0
            or not isinstance(document["sha256"], str) or len(document["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in document["sha256"])
            or not document["url"].startswith("https://download.fedoraproject.org/")):
        fail("Windows Fedora appliance lock is invalid")
    return document


def download_locked(url, destination, expected_size, deadline_seconds,
                    opener=urllib.request.urlopen, clock=time.monotonic, output=print):
    if deadline_seconds <= 0:
        fail("Fedora appliance download deadline must be positive")
    deadline = clock() + deadline_seconds
    downloaded = 0
    next_progress = DOWNLOAD_PROGRESS_INTERVAL
    output(f"Downloading locked Fedora appliance: 0/{expected_size} bytes")
    with opener(url, timeout=min(DOWNLOAD_SOCKET_TIMEOUT_SECONDS, deadline_seconds)) as response:
        with destination.open("xb") as stream:
            while True:
                if clock() >= deadline:
                    fail(f"Fedora appliance download exceeded {deadline_seconds} seconds")
                block = response.read(DOWNLOAD_CHUNK_SIZE)
                if not block:
                    break
                stream.write(block)
                downloaded += len(block)
                if downloaded > expected_size:
                    fail("Downloaded Fedora appliance exceeds its exact locked size")
                if downloaded >= next_progress or downloaded == expected_size:
                    output(f"Downloading locked Fedora appliance: {downloaded}/{expected_size} bytes")
                    while next_progress <= downloaded:
                        next_progress += DOWNLOAD_PROGRESS_INTERVAL


def acquire(lock, cache, downloader=None, deadline_seconds=DEFAULT_DOWNLOAD_DEADLINE_SECONDS):
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / lock["filename"]
    if exact_file(target, lock["size"], lock["sha256"]):
        return target
    partial = cache / f'.{lock["filename"]}.download.partial'
    if target.exists() or target.is_symlink():
        target.unlink()
    if partial.exists() or partial.is_symlink():
        partial.unlink()
    try:
        if downloader is None:
            download_locked(lock["url"], partial, lock["size"], deadline_seconds)
        else:
            downloader(lock["url"], partial)
        if not exact_file(partial, lock["size"], lock["sha256"]):
            fail("Downloaded Fedora appliance does not match its exact locked identity")
        os.replace(partial, target)
    finally:
        if partial.exists() or partial.is_symlink():
            partial.unlink()
    return target


def stage(lock, image, cloud_init, output):
    if output.exists() or output.is_symlink():
        fail("Windows appliance output already exists")
    files = [{"path": lock["filename"], "size": lock["size"], "sha256": lock["sha256"]}]
    support = {}
    for relative, (size, sha256) in CLOUD_INIT.items():
        source = cloud_init.parent / relative
        support[relative] = canonical_text(source, size, sha256)
        files.append({"path": relative, "size": size, "sha256": sha256})
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    try:
        shutil.copy2(image, staging / lock["filename"])
        for relative, _identity in CLOUD_INIT.items():
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(support[relative])
        manifest = {"schema_version": 1, "appliance_protocol_version": 1,
                    "fedora_release": lock["fedora_release"],
                    "fedora_compose": lock["fedora_compose"],
                    "architecture": lock["architecture"], "source_url": lock["url"],
                    "files": files}
        (staging / "appliance-manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        os.rename(staging, output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=Path("runtime/windows-fedora-appliance.json"))
    parser.add_argument("--cache", type=Path, default=Path("build/cache/windows-appliance"))
    parser.add_argument("--cloud-init", type=Path, default=Path("builder/appliance/cloud-init"))
    parser.add_argument("--output", type=Path, default=Path("build/appliance/windows"))
    parser.add_argument("--deadline-seconds", type=int, default=DEFAULT_DOWNLOAD_DEADLINE_SECONDS)
    args = parser.parse_args()
    lock = load_lock(args.lock)
    stage(lock, acquire(lock, args.cache, deadline_seconds=args.deadline_seconds), args.cloud_init, args.output)


if __name__ == "__main__":
    main()

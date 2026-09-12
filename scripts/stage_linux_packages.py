#!/usr/bin/env python3
"""Stage exactly one Debian package and AppImage for CI artifact retention."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat


def fail(message):
    raise SystemExit(message)


def one_regular(directory, pattern, label):
    matches = list(directory.glob(pattern))
    if len(matches) != 1:
        fail(f"Expected exactly one {label}, found {len(matches)}")
    item = matches[0]
    metadata = item.lstat()
    if item.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a regular file, not a link or special file")
    return item, metadata


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def stage(root, output, source_commit):
    if not source_commit or len(source_commit) != 40 or any(c not in "0123456789abcdef" for c in source_commit):
        fail("Source commit must be one lowercase 40-character Git commit")
    if output.exists():
        fail("Linux package artifact output must not already exist")

    deb, _ = one_regular(root / "src-tauri/target/debug/bundle/deb", "*.deb", "Debian package")
    appimage, app_metadata = one_regular(
        root / "src-tauri/target/debug/bundle/appimage", "*.AppImage", "AppImage"
    )
    if app_metadata.st_mode & 0o111 == 0:
        fail("AppImage must be executable")
    with deb.open("rb") as stream:
        deb_header = stream.read(8)
    if deb_header != b"!<arch>\n":
        fail("Debian package does not have an ar archive header")
    with appimage.open("rb") as stream:
        header = stream.read(20)
    if header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != 62:
        fail("AppImage is not an x86_64 ELF executable")

    output.mkdir(mode=0o755)
    staged = []
    for source in (deb, appimage):
        target = output / source.name
        shutil.copyfile(source, target)
        os.chmod(target, stat.S_IMODE(source.stat().st_mode))
        staged.append((target, digest(target)))
    (output / "SHA256SUMS.txt").write_text(
        "".join(f"{value}  {path.name}\n" for path, value in staged), encoding="utf-8"
    )
    provenance = {
        "schemaVersion": 1,
        "kind": "opemos-exe-linux-packages",
        "sourceCommit": source_commit,
        "packages": [
            {"filename": path.name, "sha256": value, "size": path.stat().st_size}
            for path, value in staged
        ],
    }
    (output / "provenance.json").write_text(
        json.dumps(provenance, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return provenance


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path, default=Path("linux-package-artifact"))
    parser.add_argument("--source-commit", default=os.environ.get("GITHUB_SHA", ""))
    args = parser.parse_args()
    print(json.dumps(stage(args.root.resolve(), args.output.resolve(), args.source_commit), indent=2))


if __name__ == "__main__":
    main()

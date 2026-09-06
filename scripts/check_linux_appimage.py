#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

root = Path(__file__).resolve().parent.parent
bundle_root = root / "src-tauri/target/debug/bundle/appimage"
fixture = root / "tests/fixtures/opemos-core/resolver-compatible-v2.json"


def main():
    images = list(bundle_root.glob("*.AppImage"))
    if len(images) != 1:
        raise SystemExit(f"Expected exactly one AppImage, found {len(images)}")
    image = images[0]
    mode = stat.S_IMODE(image.stat().st_mode)
    if not image.is_file() or image.is_symlink() or mode & 0o111 == 0:
        raise SystemExit("AppImage is not one executable regular file")
    with image.open("rb") as stream:
        header = stream.read(20)
    if header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != 62:
        raise SystemExit("AppImage is not an x86_64 ELF executable")
    fixture_hash = hashlib.sha256(fixture.read_bytes()).hexdigest()
    environment = dict(os.environ)
    environment["APPIMAGE_EXTRACT_AND_RUN"] = "1"
    result = subprocess.run([
        str(image), "resolve-core-driver", "--steamos", "3.8.14",
        "--kernel", "fixture", "--architecture", "x86_64",
        "--candidate-sha256", fixture_hash, str(fixture),
    ], cwd=root, env=environment, text=True, capture_output=True, timeout=60)
    if result.returncode != 0:
        raise SystemExit(f"Portable resolver failed: {result.stderr.strip()}")
    selected = json.loads(result.stdout)
    expected = json.loads(fixture.read_text())
    if selected["artifact"] != expected["artifact"] or selected["target"] != expected["target"]:
        raise SystemExit("Portable resolver changed the selected artifact or exact target")
    print(f"PASS: {image.name} is executable x86_64 ELF and its closed resolver path matches the fixture")
    print("AppImage SHA-256:", hashlib.sha256(image.read_bytes()).hexdigest())
    print("No graphical application, network request, download, or activation occurred.")


if __name__ == "__main__":
    main()

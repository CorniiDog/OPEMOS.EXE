#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
bundle_root = root / "src-tauri/target/debug/bundle/appimage"
fixture = root / "tests/fixtures/opemos-core/resolver-compatible-v2.json"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(image, kernel, candidates):
    arguments = [
        str(image), "resolve-core-driver", "--steamos", "3.8.14",
        "--kernel", kernel, "--architecture", "x86_64",
    ]
    for candidate_hash, path in candidates:
        arguments.extend(["--candidate-sha256", candidate_hash, str(path)])
    environment = dict(os.environ)
    environment["APPIMAGE_EXTRACT_AND_RUN"] = "1"
    return subprocess.run(
        arguments, cwd=root, env=environment, text=True,
        capture_output=True, timeout=60, check=False,
    )


def require_failure(result, message):
    if result.returncode == 0 or message not in result.stderr:
        raise SystemExit(
            f"Portable resolver did not fail closed with {message!r}: "
            f"exit={result.returncode}, stdout={result.stdout.strip()!r}, "
            f"stderr={result.stderr.strip()!r}"
        )


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

    fixture_hash = digest(fixture)
    result = invoke(image, "fixture", [(fixture_hash, fixture)])
    if result.returncode != 0:
        raise SystemExit(f"Portable resolver failed: {result.stderr.strip()}")
    selected = json.loads(result.stdout)
    expected = json.loads(fixture.read_text())
    if selected["artifact"] != expected["artifact"] or selected["target"] != expected["target"]:
        raise SystemExit("Portable resolver changed the selected artifact or exact target")

    require_failure(
        invoke(image, "fixture", [("0" * 64, fixture)]),
        "does not match its authenticated SHA-256",
    )
    require_failure(
        invoke(image, "different-kernel", [(fixture_hash, fixture)]),
        "No compatible OPEMOS Core driver artifact matches the exact target",
    )
    with tempfile.TemporaryDirectory(prefix="opemos-appimage-resolver-") as temporary:
        conflicting = json.loads(fixture.read_text())
        conflicting["artifact"]["name"] = "different-authenticated-driver.tar.gz"
        conflict_path = Path(temporary) / "conflicting.json"
        conflict_path.write_text(
            json.dumps(conflicting, sort_keys=True, separators=(",", ":")) + "\n"
        )
        require_failure(
            invoke(
                image,
                "fixture",
                [(fixture_hash, fixture), (digest(conflict_path), conflict_path)],
            ),
            "Multiple different compatible OPEMOS Core driver decisions are ambiguous",
        )

    print(
        f"PASS: {image.name} is executable x86_64 ELF; its closed resolver "
        "accepts one exact fixture and rejects bad hash, target, and ambiguity"
    )
    print("AppImage SHA-256:", digest(image))
    print("No graphical application, network request, download, or activation occurred.")


if __name__ == "__main__":
    main()

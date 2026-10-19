"""Record actual producer bytes after upload; no image/SteamOS acceptance claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from omen_ci_executables import PRODUCERS, SHA, NUMBER, COMMIT

FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def held(path, cap, keep=False):
    path = Path(path).absolute()
    before = path.lstat()
    require(path.resolve() == path and stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
            not getattr(before, "st_file_attributes", 0) & 0x400 and 0 < before.st_size <= cap,
            "Actual non-reparse single-link producer file required")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        ident = lambda x: tuple(getattr(x, k) for k in FIELDS)
        require(ident(before) == ident(os.fstat(fd)), "Producer path changed before held descriptor")
        digest, total, raw = hashlib.sha256(), 0, bytearray()
        while block := os.read(fd, 1024**2):
            total += len(block)
            require(total <= cap, "Producer file overflow")
            digest.update(block)
            if keep:
                raw.extend(block)
        require(total == before.st_size and ident(before) == ident(os.fstat(fd)) == ident(path.lstat()),
                "Producer full9 descriptor/path byte identity changed")
        return {"name": path.name, "bytes": total, "sha256": digest.hexdigest()}, bytes(raw)
    finally:
        os.close(fd)


def record(platform, source, artifact_id, artifact_name, artifact_sha, output):
    require(platform in PRODUCERS and COMMIT.fullmatch(source) and NUMBER.fullmatch(artifact_id) and SHA.fullmatch(artifact_sha),
            "Exact producer platform/source/upload identity missing")
    env = os.environ
    require(env.get("GITHUB_REPOSITORY") == "CorniiDog/OPEMOS.EXE" and
            all(NUMBER.fullmatch(env.get(k, "")) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")) and
            env.get("GITHUB_WORKFLOW_REF", "").startswith("CorniiDog/OPEMOS.EXE/" + PRODUCERS[platform]["workflow"] + "@"),
            "Actual canonical producer workflow/run/attempt context missing")
    root = Path.cwd().resolve()
    if platform == "windows":
        executable = package = root / "dist/windows/OPEMOS.EXE-windows-x86_64-unsigned.exe"
    elif platform == "ubuntu":
        packages = list((root / "linux-package-artifact").glob("*.AppImage"))
        require(len(packages) == 1, "Exactly one actual Ubuntu AppImage is required")
        executable = package = packages[0]
    else:
        _, raw = held(root / "build/macos-arm64-evidence/receipt.json", 1024**2, keep=True)
        receipt = json.loads(raw)
        require(receipt.get("exe_source_commit") == source and receipt.get("artifact", {}).get("architectures") == "arm64",
                "Actual same-source native Mac executable receipt missing")
        executable = Path(receipt["artifact"]["executable"])
        require(executable.is_relative_to(root), "Mac executable escapes exact producer root")
        package = root / "build/macos-arm64-evidence/SteamOS-NVIDIA-Builder-arm64.app.zip"
    packaged, _ = held(package, 60_000_000_000)
    binary, _ = held(executable, 1024**3)
    value = {"schema": 1, "repository": env["GITHUB_REPOSITORY"], "source_commit": source,
             "platform": platform, "workflow": PRODUCERS[platform]["workflow"], "producer_run_id": env["GITHUB_RUN_ID"],
             "producer_attempt": env["GITHUB_RUN_ATTEMPT"], "event": env["GITHUB_EVENT_NAME"], "ref": env["GITHUB_REF"],
             "artifact_id": artifact_id, "artifact_name": artifact_name, "artifact_archive_sha256": artifact_sha,
             "package_name": packaged["name"], "package_sha256": packaged["sha256"], "package_bytes": packaged["bytes"],
             "executable_name": binary["name"], "executable_sha256": binary["sha256"], "executable_bytes": binary["bytes"]}
    # PR builds may retain provenance. The acceptance consumer rejects their
    # event/ref, so recording a diagnostic does not admit PR code to SSH.
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    with (output / "executable-producer.json").open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    return value


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("platform", "source", "artifact-id", "artifact-name", "artifact-sha", "output"):
        parser.add_argument("--" + name, required=True)
    args = vars(parser.parse_args())
    record(args["platform"], args["source"], args["artifact_id"], args["artifact_name"], args["artifact_sha"], args["output"])

#!/usr/bin/env python3
"""Prevent accidental edits or drift from the Core ownership contract."""

import hashlib
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "32ac0c28109ceee40bbaa356003755d5acf33646"
EXPECTED_GIT_BLOB = "a8123b2134a3b6ed536353ab16ed9496ba263c01"
EXPECTED_SHA256 = "3d995e054dbad65f871dfbf20234d5be7977a54eba765b10635d09a954d01bbb"


def git_blob_id(payload):
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def verify_source_commit(payload):
    sibling = ROOT.parent / "open-gpu-kernel-modules-steamos-support"
    if not (sibling / ".git").exists():
        return
    result = subprocess.run(
        ["git", "-C", str(sibling), "show", f"{SOURCE_COMMIT}:BOUNDARIES.md"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, "pinned Core boundary commit is unavailable"
    assert result.stdout == payload, "local boundary differs from the pinned Core commit"
    assert hashlib.sha256(result.stdout).hexdigest() == EXPECTED_SHA256


def main():
    authority = ROOT / "BOUNDARIES.md"
    payload = authority.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == EXPECTED_SHA256, (
        "BOUNDARIES.md changed without an explicit cross-project governance update"
    )
    assert git_blob_id(payload) == EXPECTED_GIT_BLOB, (
        "BOUNDARIES.md is not the exact blob from the pinned Core commit"
    )
    verify_source_commit(payload)

    text = payload.decode("utf-8")
    for required in (
        "READ-ONLY GOVERNANCE CONTRACT",
        "## Networking boundary",
        "## Source intent and Core authorization",
        "Automatic is itself explicit user intent",
        "## A/B ownership",
        "## Sole UI exception",
        "authenticated OPEMOS-owned\ninterstitial target payload",
        "Core-owned installed-device supervisor may launch and\nmonitor",
        "This ownership is cross-platform",
    ):
        assert required in text, f"boundary authority omitted required rule: {required}"

    for relative in ("README.md", "TODO.md", "docs/architecture.md"):
        summary = (ROOT / relative).read_text(encoding="utf-8")
        assert "BOUNDARIES.md" in summary, f"{relative} does not link to the authority"


if __name__ == "__main__":
    main()

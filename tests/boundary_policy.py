#!/usr/bin/env python3
"""Prevent accidental edits or drift from the Core ownership contract."""

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "e36e9052b982893b5fc89f6df0fa1c8671b7cad1"
EXPECTED_GIT_BLOB = "9b379788b1deadbb2088887eb10be325008254ac"
EXPECTED_SHA256 = "c44a987b4931f413ee72cc6d94ff3797f746bbdba4bcf51c7d7aed9406ffd9f2"


def git_blob_id(payload):
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def main():
    authority = ROOT / "BOUNDARIES.md"
    payload = authority.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == EXPECTED_SHA256, (
        "BOUNDARIES.md changed without an explicit cross-project governance update"
    )
    assert git_blob_id(payload) == EXPECTED_GIT_BLOB, (
        "BOUNDARIES.md is not the exact blob from the pinned Core commit"
    )
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
        "## Artifact cleanup ownership",
        "Artifact cleanup follows creator ownership",
        "Neither component gains authority to remove artifacts created by the other",
        "Missing, stale, malformed, mismatched,\nconflicting, or ambiguous evidence fails safely without cleanup",
        "The flag grants\nno blanket deletion authority and does not transfer ownership to OPEMOS.EXE",
        "## Cross-repository pull-request merge governance",
        "Only the owning repository primary lead may squash-merge",
        "Routine pull requests may merge without counterpart-primary approval",
        "cannot reach disks,\nimages, VM or process lifecycle, production trust, release publication, physical\nhardware, or cross-repository contracts",
        "Imaging-sensitive pull requests still require the other repository's primary\nlead to explicitly approve",
        "the counterpart primary may instead record approval\nthrough the authenticated scheduler/handoff channel",
        "Any new head commit, changed base commit, material scope change",
        "Do not open a standalone evidence-only pull request",
        "its absence never blocks product development",
        "may delete only that exact merged topic branch",
        "This ownership is cross-platform",
    ):
        assert required in text, f"boundary authority omitted required rule: {required}"

    for relative in ("README.md", "TODO.md", "docs/architecture.md"):
        summary = (ROOT / relative).read_text(encoding="utf-8")
        assert "BOUNDARIES.md" in summary, f"{relative} does not link to the authority"


if __name__ == "__main__":
    main()

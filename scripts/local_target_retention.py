#!/usr/bin/env python3
"""Fail-closed cleanup of stale, creator-owned Rust worktree output.

This component is deliberately not scheduled here.  The shared retention owner
supplies cadence and invokes it only after separate deployment review.
"""
import argparse
import fcntl
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import uuid

STALE_SECONDS = 24 * 60 * 60
MARKERS = {".opemos-retain", ".keep", "RETENTION.md", ".frozen-input", ".required-artifact"}
ACTIVE_MARKERS = {".opemos-active-job", ".opemos-consumer-lease"}
MAX_ENTRIES = 200000


def fail(message):
    raise RuntimeError(message)


def held_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        os.close(fd); fail(f"not directory: {path}")
    return fd, (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_ctime_ns, info.st_mtime_ns)


def unchanged(fd, identity, label):
    now = os.fstat(fd)
    current = (now.st_dev, now.st_ino, now.st_uid, now.st_gid, now.st_ctime_ns, now.st_mtime_ns)
    if current != identity:
        fail(f"{label} changed while held")


def mount_inventory():
    rows = []
    with open("/proc/self/mountinfo", encoding="utf-8") as source:
        for line in source:
            left = line.split(" - ", 1)[0].split()
            if len(left) < 5: fail("malformed mountinfo")
            rows.append((left[0], left[4].replace("\\040", " ").replace("\\011", "\t")))
    return rows


def require_no_mount_boundary(target):
    target = os.path.realpath(target)
    seen = [(ident, point) for ident, point in mount_inventory()
            if point == target or point.startswith(target + os.sep)]
    if seen: fail("target contains mount boundary: " + repr(seen))


def git(worktree, *args):
    return subprocess.run(("git", "-C", str(worktree), *args), text=True, capture_output=True, check=False)


def require_git_clean(worktree):
    if git(worktree, "rev-parse", "--is-inside-work-tree").stdout.strip() != "true": fail("Git identity unavailable")
    status = git(worktree, "status", "--porcelain=v1")
    if status.returncode or status.stdout: fail("worktree has dirty or untracked source")
    if git(worktree, "check-ignore", "-q", "src-tauri/target").returncode: fail("target is not ignored")
    tracked = git(worktree, "ls-files", "--", "src-tauri/target")
    if tracked.returncode or tracked.stdout: fail("tracked target content")


def process_references(target_fd, target):
    target_stat = os.fstat(target_fd)
    prefix = os.path.realpath(target) + os.sep
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit(): continue
        probes = [entry / "cwd", entry / "root", entry / "maps"]
        try: probes.append(entry / "fd")
        except OSError: fail("process probe construction failed")
        for probe in probes:
            try:
                if probe.name == "fd": values = list(probe.iterdir())
                elif probe.name == "maps": values = [probe]
                else: values = [probe]
            except FileNotFoundError: continue
            except PermissionError: fail(f"unknown process visibility: {entry.name}/{probe.name}")
            for value in values:
                try:
                    text = value.read_text(errors="replace") if value.name == "maps" else os.readlink(value)
                except FileNotFoundError: continue
                except (PermissionError, OSError) as error: fail(f"unknown process reference: {entry.name}/{value.name}: {error}")
                if target == text or text.startswith(prefix) or prefix in text:
                    fail(f"live process path reference: {entry.name}/{value.name}")
                if value.name != "maps":
                    try:
                        held = os.stat(value, follow_symlinks=True)
                    except FileNotFoundError: continue
                    except (PermissionError, OSError) as error: fail(f"unknown process identity: {entry.name}/{value.name}: {error}")
                    if (held.st_dev, held.st_ino) == (target_stat.st_dev, target_stat.st_ino):
                        fail(f"live process inode reference: {entry.name}/{value.name}")


def tree_inventory(target_fd, uid, now):
    total = 0; newest = 0; names = []
    count = 0
    root_stat = os.fstat(target_fd)
    newest = max(root_stat.st_mtime_ns, root_stat.st_ctime_ns)
    for base, dirs, files, parent_fd in os.fwalk('.', topdown=True, follow_symlinks=False, dir_fd=target_fd):
        for name in dirs + files:
            count += 1
            if count > MAX_ENTRIES: fail("target inventory exceeds bound")
            try: info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError: fail("tree changed during inventory")
            if stat.S_ISLNK(info.st_mode): fail("symlink in target tree")
            if info.st_uid != uid: fail("foreign-owned target entry")
            if info.st_mtime_ns > newest or info.st_ctime_ns > newest: newest = max(info.st_mtime_ns, info.st_ctime_ns)
            if name in MARKERS: fail("retention marker in target tree: " + os.path.join(base, name))
            total += info.st_blocks * 512; names.append((info.st_dev, info.st_ino, base, name))
    if now - newest / 1_000_000_000 < STALE_SECONDS: fail("recent target descendant")
    return total, tuple(sorted(names))


def durable_json(directory, stem, value):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = directory / f"{stem}-{time.time_ns()}-{uuid.uuid4().hex}.json"
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write((json.dumps(value, sort_keys=True) + "\n").encode()); out.flush(); os.fsync(out.fileno())
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); os.fsync(parent); os.close(parent)
    return name


def remove_held_tree(target_fd, parent_fd, target_name):
    """Descriptor-relative removal; callers retain typed partial-effect evidence."""
    removed = 0
    for base, dirs, files, directory_fd in os.fwalk('.', topdown=False, follow_symlinks=False, dir_fd=target_fd):
        for entry in files:
            info = os.stat(entry, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode): fail("late symlink")
            os.unlink(entry, dir_fd=directory_fd); removed += 1
        for entry in dirs:
            os.rmdir(entry, dir_fd=directory_fd); removed += 1
    os.rmdir(target_name, dir_fd=parent_fd); return removed


def evaluate(repository, receipts, execute):
    if os.path.commonpath((os.path.realpath(repository), os.path.realpath(receipts))) == os.path.realpath(repository):
        fail("receipt directory must be outside repository")
    repo_fd, repo_id = held_dir(repository); roots_fd, roots_id = held_dir(repository / ".worktrees")
    outcome = {"kind": "EXE_LOCAL_TARGET_RETENTION", "execute": execute, "candidates": [], "refused": [], "deleted": [], "bytesReclaimed": 0}
    try:
        for name in sorted(os.listdir(repository / ".worktrees")):
            worktree = repository / ".worktrees" / name; target = worktree / "src-tauri" / "target"
            if not os.path.lexists(target): continue
            try:
                wf, wi = held_dir(worktree); sf, si = held_dir(worktree / "src-tauri"); tf, ti = held_dir(target)
                try:
                    try: fcntl.flock(tf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError: fail("target consumer lease is held")
                    if os.path.realpath(worktree.parent) != os.path.realpath(repository / ".worktrees"): fail("worktree parent drift")
                    if any((worktree / marker).exists() for marker in ACTIVE_MARKERS): fail("active worktree job marker")
                    require_no_mount_boundary(target); require_git_clean(worktree); process_references(tf, str(target))
                    bytes_before, entries = tree_inventory(tf, os.getuid(), time.time())
                    row = {"path": str(target), "allocatedBytes": bytes_before, "entries": len(entries)}
                    outcome["candidates"].append(row)
                    if execute:
                        intent = durable_json(receipts, "target-retention-intent", {"target": str(target), "identity": ti, "bytes": bytes_before})
                        for fd, ident, label in ((repo_fd, repo_id, "repository"), (roots_fd, roots_id, "worktrees"), (wf, wi, "worktree"), (sf, si, "src-tauri"), (tf, ti, "target")): unchanged(fd, ident, label)
                        require_no_mount_boundary(target); require_git_clean(worktree); process_references(tf, str(target))
                        if tree_inventory(tf, os.getuid(), time.time()) != (bytes_before, entries): fail("target changed before deletion")
                        parent_fd = os.open(worktree / "src-tauri", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                        try: removed = remove_held_tree(tf, parent_fd, "target")
                        except OSError as error:
                            outcome["partialDeletion"] = {"path": str(target), "removedEntries": removed if "removed" in locals() else 0, "error": repr(error)}; raise
                        finally: os.close(parent_fd)
                        outcome["deleted"].append(dict(row, intent=str(intent), removedEntries=removed)); outcome["bytesReclaimed"] += bytes_before
                finally:
                    for fd in (tf, sf, wf): os.close(fd)
            except (RuntimeError, OSError) as error: outcome["refused"].append({"path": str(target), "reason": str(error)})
    finally:
        os.close(roots_fd); os.close(repo_fd)
    outcome["receipt"] = str(durable_json(receipts, "target-retention-result", outcome)); return outcome


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--repository", type=Path, required=True); parser.add_argument("--receipts", type=Path, required=True); parser.add_argument("--execute", action="store_true")
    print(json.dumps(evaluate(parser.parse_args().repository, parser.parse_args().receipts, parser.parse_args().execute), sort_keys=True))

if __name__ == "__main__": main()

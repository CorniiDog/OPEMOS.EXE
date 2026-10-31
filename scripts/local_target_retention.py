#!/usr/bin/env python3
"""Fail-closed cleanup of stale, creator-owned Rust worktree output.

This component is deliberately not scheduled here.  The shared retention owner
supplies cadence and invokes it only after separate deployment review.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import uuid

STALE_SECONDS = 24 * 60 * 60
MARKERS = {".opemos-retain", ".keep", "RETENTION.md", ".frozen-input", ".required-artifact"}
ACTIVE_MARKERS = {".opemos-active-job", ".opemos-consumer-lease", ".opemos-producer-lease"}
ARTIFACT_SUFFIXES = (".appimage", ".deb", ".img", ".qcow2")
MAX_ENTRIES = 200000
MAX_DEPTH = 64
INVENTORY_SECONDS = 10
CUSTODY_NAME = ".opemos-target-custody.json"


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


def require_custody(worktree, worktree_identity, source_identity, target_identity):
    """Require the producer's exact, released stale-output custody record."""
    custody = worktree / "src-tauri" / CUSTODY_NAME
    try:
        raw = custody.read_bytes()
        info = custody.stat(follow_symlinks=False)
        record = json.loads(raw)
    except (OSError, ValueError, UnicodeDecodeError) as error:
        fail(f"missing or malformed producer custody: {error}")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        fail("invalid producer custody file")
    expected = {
        "version": 1,
        "creatorUid": os.getuid(),
        "worktree": list(worktree_identity[:2]),
        "source": list(source_identity[:2]),
        "target": list(target_identity[:2]),
        "jobState": "complete",
        "producerLease": "released",
        "requiredArtifact": None,
        "latestArtifact": None,
    }
    if not isinstance(record, dict) or any(record.get(key) != value for key, value in expected.items()):
        fail("producer custody contract mismatch")
    if not isinstance(record.get("jobId"), str) or not record["jobId"].strip():
        fail("producer custody job is missing")


def process_pid_references(pid, target_stat, target, prefix, own_target_fd=None):
    """Reject one process holding the target, except this scan's exact FD.

    The exception is intentionally descriptor-scoped.  A duplicate descriptor,
    cwd, map, or any other process reference remains a consumer and blocks
    cleanup, including when it belongs to this process.
    """
    entry = Path("/proc") / str(pid)
    probes = [entry / "cwd", entry / "root", entry / "maps", entry / "fd"]
    for probe in probes:
        try:
            values = list(probe.iterdir()) if probe.name == "fd" else [probe]
        except FileNotFoundError:
            continue
        except PermissionError:
            fail(f"unknown process visibility: {entry.name}/{probe.name}")
        for value in values:
            if pid == os.getpid() and value.name == str(own_target_fd):
                continue
            try:
                text = value.read_text(errors="replace") if value.name == "maps" else os.readlink(value)
            except FileNotFoundError:
                continue
            except (PermissionError, OSError) as error:
                fail(f"unknown process reference: {entry.name}/{value.name}: {error}")
            if target == text or text.startswith(prefix) or prefix in text:
                fail(f"live process path reference: {entry.name}/{value.name}")
            if value.name != "maps":
                try:
                    held = os.stat(value, follow_symlinks=True)
                except FileNotFoundError:
                    continue
                except (PermissionError, OSError) as error:
                    fail(f"unknown process identity: {entry.name}/{value.name}: {error}")
                if (held.st_dev, held.st_ino) == (target_stat.st_dev, target_stat.st_ino):
                    fail(f"live process inode reference: {entry.name}/{value.name}")


def process_references(target_fd, target, own_target_fd):
    target_stat = os.fstat(target_fd)
    prefix = os.path.realpath(target) + os.sep
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        process_pid_references(int(entry.name), target_stat, target, prefix, own_target_fd)


def tree_inventory(target_fd, uid, now):
    total = 0; newest = 0; entries = []
    count = 0; started = time.monotonic()
    root_stat = os.fstat(target_fd)
    if root_stat.st_uid != uid or not stat.S_ISDIR(root_stat.st_mode): fail("invalid target root")
    newest = max(root_stat.st_mtime_ns, root_stat.st_ctime_ns)
    root_dev = root_stat.st_dev
    def walk_error(error): fail(f"target traversal error: {error}")
    for base, dirs, files, parent_fd in os.fwalk('.', topdown=True, follow_symlinks=False, dir_fd=target_fd, onerror=walk_error):
        if time.monotonic() - started > INVENTORY_SECONDS: fail("target inventory exceeded time bound")
        depth = 0 if base == '.' else len(Path(base).parts)
        if depth > MAX_DEPTH: fail("target inventory exceeded depth bound")
        for name in dirs + files:
            count += 1
            if count > MAX_ENTRIES: fail("target inventory exceeds bound")
            try: info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as error: fail(f"tree changed during inventory: {error}")
            if stat.S_ISLNK(info.st_mode): fail("symlink in target tree")
            if info.st_uid != uid or info.st_dev != root_dev: fail("foreign-owned or cross-device target entry")
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)): fail("unsupported target entry type")
            if info.st_mtime_ns > newest or info.st_ctime_ns > newest: newest = max(info.st_mtime_ns, info.st_ctime_ns)
            if name in MARKERS or name in ACTIVE_MARKERS or name.lower().endswith(ARTIFACT_SUFFIXES): fail("retained marker, producer lease, or artifact in target tree: " + os.path.join(base, name))
            total += info.st_blocks * 512
            entries.append((info.st_dev, info.st_ino, base, name, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_ctime_ns, info.st_mtime_ns))
    if now - newest / 1_000_000_000 < STALE_SECONDS: fail("recent target descendant")
    root = (root_stat.st_dev, root_stat.st_ino, root_stat.st_mode, root_stat.st_uid, root_stat.st_gid, root_stat.st_nlink, root_stat.st_size, root_stat.st_ctime_ns, root_stat.st_mtime_ns)
    return total, root, tuple(sorted(entries))


def durable_json(directory, stem, value):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = directory / f"{stem}-{time.time_ns()}-{uuid.uuid4().hex}.json"
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write((json.dumps(value, sort_keys=True) + "\n").encode()); out.flush(); os.fsync(out.fileno())
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); os.fsync(parent); os.close(parent)
    return name


class PartialDeleteError(RuntimeError):
    def __init__(self, removed, error):
        super().__init__(str(error))
        self.removed = removed
        self.original = error


def remove_held_contents(target_fd):
    """Descriptor-relative removal; callers retain typed partial-effect evidence."""
    removed = 0
    try:
        for base, dirs, files, directory_fd in os.fwalk('.', topdown=False, follow_symlinks=False, dir_fd=target_fd):
            for entry in files:
                info = os.stat(entry, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode): fail("late symlink")
                os.unlink(entry, dir_fd=directory_fd); removed += 1
            for entry in dirs:
                os.rmdir(entry, dir_fd=directory_fd); removed += 1
    except Exception as error:
        raise PartialDeleteError(removed, error) from error
    return removed


def evaluate(repository, receipts, execute):
    if os.path.commonpath((os.path.realpath(repository), os.path.realpath(receipts))) == os.path.realpath(repository):
        fail("receipt directory must be outside repository")
    outcome = {"kind": "EXE_LOCAL_TARGET_RETENTION", "execute": execute, "candidates": [], "refused": [], "deleted": [], "bytesReclaimed": 0}
    repo_fd = roots_fd = -1
    try:
        repo_fd, repo_id = held_dir(repository); roots_fd, roots_id = held_dir(repository / ".worktrees")
        for name in sorted(os.listdir(repository / ".worktrees")):
            worktree = repository / ".worktrees" / name; target = worktree / "src-tauri" / "target"
            if not os.path.lexists(target): continue
            wf = sf = tf = -1; row = None; intent = None
            try:
                wf, wi = held_dir(worktree)
                sf, si = held_dir(worktree / "src-tauri")
                tf, ti = held_dir(target)
                try:
                    if any(identity[2] != os.getuid() for identity in (wi, si, ti)): fail("creator ownership contract failed")
                    try: fcntl.flock(tf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError: fail("target consumer lease is held")
                    if os.path.realpath(worktree.parent) != os.path.realpath(repository / ".worktrees"): fail("worktree parent drift")
                    if any((worktree / marker).exists() for marker in ACTIVE_MARKERS): fail("active worktree job marker")
                    require_no_mount_boundary(target); require_git_clean(worktree); require_custody(worktree, wi, si, ti); process_references(tf, str(target), tf)
                    bytes_before, root_cut, entries = tree_inventory(tf, os.getuid(), time.time())
                    row = {"path": str(target), "allocatedBytes": bytes_before, "entries": len(entries), "identity": ti[:2]}
                    outcome["candidates"].append(row)
                    if execute:
                        intent = durable_json(receipts, "target-retention-intent", {"target": str(target), "identity": ti, "bytes": bytes_before})
                        for fd, ident, label in ((repo_fd, repo_id, "repository"), (roots_fd, roots_id, "worktrees"), (wf, wi, "worktree"), (sf, si, "src-tauri"), (tf, ti, "target")): unchanged(fd, ident, label)
                        require_no_mount_boundary(target); require_git_clean(worktree); require_custody(worktree, wi, si, ti); process_references(tf, str(target), tf)
                        if tree_inventory(tf, os.getuid(), time.time()) != (bytes_before, root_cut, entries): fail("target changed before deletion")
                        bound = os.stat("target", dir_fd=sf, follow_symlinks=False)
                        if (bound.st_dev, bound.st_ino) != ti[:2]: fail("target name no longer bound to held target")
                        removed = 0
                        try:
                            removed = remove_held_contents(tf)
                            bound = os.stat("target", dir_fd=sf, follow_symlinks=False)
                            if (bound.st_dev, bound.st_ino) != ti[:2]: fail("target replaced before final removal")
                            os.rmdir("target", dir_fd=sf)
                            outcome["deleted"].append(dict(row, intent=str(intent), removedEntries=removed)); outcome["bytesReclaimed"] += bytes_before
                        except PartialDeleteError as error:
                            outcome["partialDeletion"] = {"path": str(target), "intent": str(intent), "removedEntries": error.removed, "error": repr(error.original), "kind": "delete-operation"}; raise
                        except Exception as error:
                            outcome["partialDeletion"] = {"path": str(target), "intent": str(intent), "removedEntries": removed, "error": repr(error), "kind": "final-removal-or-fd"}; raise
                finally:
                    for fd in (tf, sf, wf):
                        if fd >= 0:
                            try: os.close(fd)
                            except OSError as error: outcome.setdefault("closeErrors", []).append({"path": str(target), "error": repr(error)})
            except Exception as error:
                refusal = {"path": str(target), "reason": str(error)}
                if intent is not None: refusal["intent"] = str(intent)
                outcome["refused"].append(refusal)
    finally:
        for fd, label in ((roots_fd, "worktrees"), (repo_fd, "repository")):
            if fd >= 0:
                try: os.close(fd)
                except OSError as error: outcome.setdefault("closeErrors", []).append({"path": label, "error": repr(error)})
    outcome["receipt"] = str(durable_json(receipts, "target-retention-result", outcome)); return outcome


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--repository", type=Path, required=True); parser.add_argument("--receipts", type=Path, required=True); parser.add_argument("--execute", action="store_true")
    print(json.dumps(evaluate(parser.parse_args().repository, parser.parse_args().receipts, parser.parse_args().execute), sort_keys=True))

if __name__ == "__main__": main()

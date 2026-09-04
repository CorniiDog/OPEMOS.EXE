#!/usr/bin/env python3
"""Bounded AT-SPI smoke test for an extracted experimental Linux package."""
from __future__ import annotations
import argparse, os, signal, stat, subprocess, sys, time
from pathlib import Path

EXPECTED_ROWS = {
    "Available generations — development fixture": "#41",
    "Selected generation — development fixture": "#42",
    "Active generation — development fixture": "#41",
    "Last-known-good generation — development fixture": "#41",
}

def validate_launch(executable: Path, timeout: float, env: dict[str, str]) -> Path:
    if sys.platform != "linux" or os.uname().machine not in {"x86_64", "amd64"}:
        raise ValueError("Packaged GUI smoke requires an x86_64 Linux host.")
    if env.get("OPEMOS_EXPERIMENTAL_LINUX") != "1":
        raise ValueError("Set OPEMOS_EXPERIMENTAL_LINUX=1 explicitly.")
    if not env.get("DISPLAY", "").strip() and not env.get("WAYLAND_DISPLAY", "").strip():
        raise ValueError("Run packaged GUI smoke from an X11 or Wayland session.")
    if not (1 <= timeout <= 60):
        raise ValueError("Timeout must be between 1 and 60 seconds.")
    try:
        metadata = executable.lstat()
    except FileNotFoundError as error:
        raise ValueError(f"Packaged executable does not exist: {executable}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Packaged executable must be a regular file, not a symlink: {executable}")
    if not os.access(executable, os.X_OK):
        raise ValueError(f"Packaged executable is not executable: {executable}")
    return executable.resolve(strict=True)

def descendants(root, *, max_nodes: int = 4096, max_depth: int = 32):
    pending, seen = [(root, 0)], 0
    while pending:
        node, depth = pending.pop()
        seen += 1
        if seen > max_nodes:
            raise RuntimeError(f"Accessibility tree exceeded the {max_nodes}-node smoke bound.")
        yield node
        if depth >= max_depth:
            continue
        for index in range(node.get_child_count() - 1, -1, -1):
            child = node.get_child_at_index(index)
            if child is not None:
                pending.append((child, depth + 1))

def named(root, label: str):
    return [node for node in descendants(root) if (node.get_name() or "") == label]

def exactly_one(root, label: str):
    matches = named(root, label)
    if len(matches) != 1:
        raise RuntimeError(f"Expected one accessible {label!r}, found {len(matches)}.")
    return matches[0]

def exactly_one_action(root, label: str, roles=None):
    matches = []
    for node in named(root, label):
        actions = node.get_action_iface()
        role = node.get_role_name() if roles is not None else None
        if actions is not None and actions.get_n_actions() > 0 and (roles is None or role in roles):
            matches.append(node)
    if len(matches) != 1:
        details = [node.get_role_name() for node in named(root, label)]
        raise RuntimeError(f"Expected one actionable {label!r}, found {len(matches)}; roles={details!r}.")
    return matches[0]

def exactly_one_role(root, label: str, role: str):
    matches = [node for node in named(root, label) if node.get_role_name() == role]
    if len(matches) != 1:
        roles = [node.get_role_name() for node in named(root, label)]
        raise RuntimeError(f"Expected one {role} named {label!r}, found roles={roles!r}.")
    return matches[0]

def first_action(root, label: str, roles):
    for node in named(root, label):
        actions = node.get_action_iface()
        if node.get_role_name() in roles and actions is not None and actions.get_n_actions() > 0:
            return node
    raise RuntimeError(f"Expected an actionable {label!r} control.")

def invoke(node):
    actions = node.get_action_iface()
    if actions is None or actions.get_n_actions() < 1 or not actions.do_action(0):
        raise RuntimeError(f"Accessible control {node.get_name()!r} did not accept its action.")

def wait_for(find, deadline: float, description: str):
    last_error = None
    while time.monotonic() < deadline:
        try:
            return find()
        except RuntimeError as error:
            last_error = error
        time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for {description}: {last_error}")

def exercise_accessibility(desktop, deadline: float):
    def application():
        candidates = [desktop.get_child_at_index(index)
                      for index in range(desktop.get_child_count())
                      if desktop.get_child_at_index(index) is not None
                      and named(desktop.get_child_at_index(index), "Open settings")]
        if len(candidates) != 1:
            raise RuntimeError(f"Expected one OPEMOS app with Settings, found {len(candidates)}.")
        return candidates[0]
    app = wait_for(application, deadline, "the packaged OPEMOS accessibility tree")
    invoke(exactly_one_action(app, "Open settings"))
    inspector = wait_for(lambda: exactly_one_action(app, "Inspect Core compatibility…"), deadline,
                         "the Settings compatibility action")
    invoke(inspector)
    dialog = wait_for(lambda: exactly_one_role(app, "Core compatibility inspector", "dialog"),
                      deadline, "the compatibility inspector")
    invoke(exactly_one_action(dialog, "Compatible fixture"))
    for label, prefix in EXPECTED_ROWS.items():
        term = wait_for(lambda label=label: exactly_one(dialog, label), deadline, label)
        values = [node.get_name() or "" for node in descendants(dialog)]
        if not any(value.startswith(prefix) for value in values):
            raise RuntimeError(f"{label!r} did not expose a value beginning with {prefix!r}.")
        if term.get_name() != label:
            raise RuntimeError(f"Accessibility label changed while reading {label!r}.")
    invoke(first_action(dialog, "Close", {"push button", "button"}))
    wait_for(lambda: exactly_one_action(app, "Open settings"), deadline, "the main document after dialog close")

def qemu_processes(proc_root: Path = Path("/proc")) -> set[tuple[int, str]]:
    metadata = proc_root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"Process root must be a directory, not a symlink: {proc_root}")
    processes = set()
    numeric_entries = 0
    for entry in proc_root.iterdir():
        if not entry.name.isascii() or not entry.name.isdigit():
            continue
        numeric_entries += 1
        if numeric_entries > 1_000_000:
            raise RuntimeError("Process inventory exceeded its entry bound.")
        try:
            entry_metadata = entry.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(entry_metadata.st_mode) or not stat.S_ISDIR(entry_metadata.st_mode):
            raise RuntimeError(f"Process entry must be a directory, not a symlink: {entry}")
        try:
            with (entry / "comm").open("rb") as stream:
                raw = stream.read(65)
        except FileNotFoundError:
            continue
        if len(raw) > 64 or not raw.endswith(b"\n"):
            raise RuntimeError(f"Process {entry.name} has an invalid bounded name.")
        try:
            name = raw[:-1].decode("ascii")
        except UnicodeDecodeError as error:
            raise RuntimeError(f"Process {entry.name} has a non-ASCII name.") from error
        if name.startswith("qemu-system-"):
            processes.add((int(entry.name), name))
    return processes

def process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False

def stop_process_group(process: subprocess.Popen, grace: float = 2.0):
    pgid = process.pid
    if process_group_exists(pgid):
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + grace
    while process_group_exists(pgid) and time.monotonic() < deadline:
        if process.poll() is None:
            try: process.wait(timeout=0.05)
            except subprocess.TimeoutExpired: pass
        else:
            time.sleep(0.05)
    if process_group_exists(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.wait(timeout=grace)
    deadline = time.monotonic() + grace
    while process_group_exists(pgid) and time.monotonic() < deadline:
        time.sleep(0.05)
    if process_group_exists(pgid):
        raise RuntimeError("Packaged application process group did not stop.")

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=20)
    args = parser.parse_args(argv)
    executable = validate_launch(args.executable, args.timeout, os.environ)
    try:
        import gi
        gi.require_version("Atspi", "2.0")
        from gi.repository import Atspi
    except (ImportError, ValueError) as error:
        raise RuntimeError("Install the Python GI AT-SPI bindings before GUI smoke testing.") from error
    Atspi.init()
    qemu_before = qemu_processes()
    process = subprocess.Popen([str(executable)], start_new_session=True)
    try:
        exercise_accessibility(Atspi.get_desktop(0), time.monotonic() + args.timeout)
    finally:
        stop_process_group(process)
    new_qemu = qemu_processes() - qemu_before
    if new_qemu:
        raise RuntimeError(f"Packaged application left new QEMU processes: {sorted(new_qemu)!r}.")
    if process.returncode not in {0, -signal.SIGTERM, -signal.SIGKILL}:
        raise RuntimeError(f"Packaged application exited unexpectedly with {process.returncode}.")
    print("Packaged Linux accessibility smoke passed; process group stopped; no new QEMU process remained.")

if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)

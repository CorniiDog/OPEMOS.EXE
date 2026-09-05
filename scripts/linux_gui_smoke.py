#!/usr/bin/env python3
"""Bounded AT-SPI smoke test for an extracted experimental Linux package."""
from __future__ import annotations
import argparse, os, signal, stat, subprocess, sys, time
from pathlib import Path

RESULT_SENTINEL_LABELS = [
    "Unverified Core result",
    "Core status",
    "Next action reported by Core",
    "Available generations — development fixture",
    "Selected generation — development fixture",
    "Active generation — development fixture",
    "Last-known-good generation — development fixture",
]

EXPECTED_COMPATIBLE_ROWS = [
    ("Core status", "compatible"),
    ("SteamOS target", "3.8.14"),
    ("Kernel target", "fixture"),
    ("Architecture", "x86_64"),
    ("Exact-target support reported by Core", "exact"),
    ("Reason", "Not provided"),
    ("Message", "Not provided"),
    ("Publication tag", "fixture"),
    ("Published SteamOS", "3.8.14"),
    ("Published kernel", "fixture"),
    ("Published NVIDIA", "575.64.05"),
    (
        "Artifact name",
        "nvidia-open-steamos-3.8.14-nvidia-575.64.05-kfixture-x86_64.tar.gz",
    ),
    ("Artifact trust reported by Core", "pending-provenance-verification"),
    ("Required verification", "external-and-embedded-provenance-byte-match"),
]

EXPECTED_NO_ARTIFACT_ROWS = [
    ("Core status", "no_compatible_artifact"),
    ("SteamOS target", "3.8.14"),
    ("Kernel target", "fixture"),
    ("Architecture", "x86_64"),
    ("Exact-target support reported by Core", "Not provided"),
    ("Reason", "no_compatible_release"),
    (
        "Message",
        "No published release matches the exact target kernel within the permitted "
        "SteamOS compatibility range.",
    ),
    ("Next action reported by Core", "build_exact_target"),
    ("Action architecture", "x86_64"),
    ("Kernel policy", "exact"),
]

EXPECTED_ROWS = {
    "Available generations — development fixture": "#41",
    "Selected generation — development fixture": "#42",
    "Active generation — development fixture": "#41",
    "Last-known-good generation — development fixture": "#41",
}

EXPECTED_SETTINGS_FOCUS_ORDER = [
    ("Close settings", "push button"),
    (
        "Track SteamOS driver updates Check for a compatible NVIDIA profile when "
        "SteamOS changes. Never selects an unverified closest kernel.",
        "check box",
    ),
    (
        "Show experimental upstream NVIDIA releases Add NVIDIA's unpatched open-module "
        "tags to the per-build selector. Automatic mode never selects them.",
        "check box",
    ),
    ("Connect GitHub", "push button"),
    ("Inspect Core compatibility…", "combo box"),
]

EXPECTED_FOCUS_ORDER = [
    ("Close", "push button"),
    ("Open a local resolver JSON file (up to 1 MiB)", "push button"),
    ("Core resolver JSON (up to 1 MiB)", "entry"),
    ("Inspect pasted result", "push button"),
    ("Clear", "push button"),
    ("Compatible fixture", "push button"),
    ("No-artifact fixture", "push button"),
]

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

def open_pinned_executable(executable: Path) -> int:
    flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(executable, flags)
    except OSError as error:
        raise ValueError(f"Cannot pin packaged executable: {executable}: {error.strerror}") from error
    metadata = os.fstat(descriptor)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ValueError(f"Pinned packaged executable must be a regular file: {executable}")
    if metadata.st_mode & 0o111 == 0:
        os.close(descriptor)
        raise ValueError(f"Pinned packaged executable has no execute mode: {executable}")
    return descriptor

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

def validate_named_rows(root, expected_rows, end_label: str):
    names = [node.get_name() or "" for node in descendants(root)]
    starts = [index for index, name in enumerate(names) if name == expected_rows[0][0]]
    ends = [index for index, name in enumerate(names) if name == end_label]
    if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0]:
        raise RuntimeError("Compatibility result row boundaries changed.")
    expected = [value for row in expected_rows for value in row]
    actual = [name for name in names[starts[0]:ends[0]] if name]
    if actual != expected:
        raise RuntimeError(f"Compatibility result rows changed: {actual!r}.")

def require_absent(root, labels):
    for label in labels:
        matches = named(root, label)
        if matches:
            raise RuntimeError(f"Expected no accessible {label!r}, found {len(matches)}.")

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

def exactly_one_focused_action(root, label: str, focused_state):
    matches = []
    for node in named(root, label):
        actions = node.get_action_iface()
        if (actions is not None and actions.get_n_actions() > 0
                and node.get_state_set().contains(focused_state)):
            matches.append(node)
    if len(matches) != 1:
        raise RuntimeError(f"Expected one focused action {label!r}, found {len(matches)}.")
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

def controls_with_state(root, state):
    controls = []
    for node in descendants(root):
        if node is root or not node.get_state_set().contains(state):
            continue
        controls.append((node.get_name() or "", node.get_role_name()))
    return controls

def validate_settings_focus(settings, focusable_state, focused_state):
    focusable = controls_with_state(settings, focusable_state)
    if focusable != EXPECTED_SETTINGS_FOCUS_ORDER:
        raise RuntimeError(f"Settings focus order changed: {focusable!r}.")
    focused = controls_with_state(settings, focused_state)
    if focused != [("Close settings", "push button")]:
        raise RuntimeError(f"Settings initial focus changed: {focused!r}.")

def validate_cleared_result(dialog, focused_state):
    require_absent(dialog, RESULT_SENTINEL_LABELS)
    exactly_one_focused_action(dialog, "Clear", focused_state)

def validate_dialog_focus(dialog, focusable_state, focused_state):
    focusable = controls_with_state(dialog, focusable_state)
    if focusable != EXPECTED_FOCUS_ORDER:
        raise RuntimeError(f"Compatibility dialog focus order changed: {focusable!r}.")
    focused = controls_with_state(dialog, focused_state)
    if focused != [("Close", "push button")]:
        raise RuntimeError(f"Compatibility dialog initial focus changed: {focused!r}.")

def validate_reopened_dialog(dialog, focusable_state, focused_state):
    validate_dialog_focus(dialog, focusable_state, focused_state)
    require_absent(dialog, RESULT_SENTINEL_LABELS)

def application_for_pid(desktop, expected_pid: int):
    if not isinstance(expected_pid, int) or isinstance(expected_pid, bool) or expected_pid <= 1:
        raise RuntimeError("Packaged application PID is invalid.")
    candidates = []
    for index in range(desktop.get_child_count()):
        app = desktop.get_child_at_index(index)
        if app is not None and app.get_process_id() == expected_pid and named(app, "Open settings"):
            candidates.append(app)
    if len(candidates) != 1:
        raise RuntimeError(
            f"Expected one OPEMOS accessibility app for PID {expected_pid}, found {len(candidates)}."
        )
    return candidates[0]

def wait_for(find, deadline: float, description: str, process_poll=None):
    last_error = None
    while time.monotonic() < deadline:
        if process_poll is not None:
            returncode = process_poll()
            if returncode is not None:
                raise RuntimeError(
                    f"Packaged application exited with {returncode} while waiting for {description}."
                )
        try:
            return find()
        except RuntimeError as error:
            last_error = error
        time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for {description}: {last_error}")

def exercise_accessibility(desktop, deadline: float, expected_pid: int,
                           focusable_state, focused_state, process_poll=None):
    wait = lambda find, description: wait_for(
        find, deadline, description, process_poll=process_poll
    )
    app = wait(lambda: application_for_pid(desktop, expected_pid),
               "the packaged OPEMOS accessibility tree")
    invoke(exactly_one_action(app, "Open settings"))
    settings = wait(lambda: exactly_one_role(app, "Builder settings", "landmark"),
                    "the Settings landmark")
    validate_settings_focus(settings, focusable_state, focused_state)
    close_settings = exactly_one_focused_action(settings, "Close settings", focused_state)
    inspector = wait(lambda: exactly_one_action(app, "Inspect Core compatibility…"),
                     "the Settings compatibility action")
    invoke(inspector)
    dialog = wait(lambda: exactly_one_role(app, "Core compatibility inspector", "dialog"),
                  "the compatibility inspector")
    validate_dialog_focus(dialog, focusable_state, focused_state)
    invoke(exactly_one_action(dialog, "Compatible fixture"))
    wait(lambda: exactly_one(dialog, "compatible"), "the compatible Core status")
    validate_named_rows(
        dialog,
        EXPECTED_COMPATIBLE_ROWS,
        "Available generations — development fixture",
    )
    for label, prefix in EXPECTED_ROWS.items():
        term = wait(lambda label=label: exactly_one(dialog, label), label)
        values = [node.get_name() or "" for node in descendants(dialog)]
        if not any(value.startswith(prefix) for value in values):
            raise RuntimeError(f"{label!r} did not expose a value beginning with {prefix!r}.")
        if term.get_name() != label:
            raise RuntimeError(f"Accessibility label changed while reading {label!r}.")
    invoke(exactly_one_action(dialog, "No-artifact fixture"))
    wait(lambda: exactly_one(dialog, "no_compatible_artifact"),
         "the no-artifact Core status")
    validate_named_rows(
        dialog,
        EXPECTED_NO_ARTIFACT_ROWS,
        "Available generations — development fixture",
    )
    invoke(exactly_one_action(dialog, "Clear"))
    wait(lambda: validate_cleared_result(dialog, focused_state),
         "cleared compatibility result")
    invoke(exactly_one_action(dialog, "Compatible fixture"))
    wait(lambda: exactly_one(dialog, "compatible"),
         "the compatible Core status after Clear")
    validate_named_rows(
        dialog,
        EXPECTED_COMPATIBLE_ROWS,
        "Available generations — development fixture",
    )
    exactly_one_focused_action(dialog, "Compatible fixture", focused_state)
    invoke(first_action(dialog, "Close", {"push button", "button"}))
    wait(lambda: exactly_one_focused_action(
        app, "Inspect Core compatibility…", focused_state
    ), "focus restoration after dialog close")
    invoke(exactly_one_action(app, "Inspect Core compatibility…"))
    dialog = wait(lambda: exactly_one_role(app, "Core compatibility inspector", "dialog"),
                  "the reopened compatibility inspector")
    validate_reopened_dialog(dialog, focusable_state, focused_state)
    invoke(first_action(dialog, "Close", {"push button", "button"}))
    wait(lambda: exactly_one_focused_action(
        app, "Inspect Core compatibility…", focused_state
    ), "focus restoration after empty dialog close")
    invoke(close_settings)
    wait(lambda: exactly_one_focused_action(app, "Open settings", focused_state),
         "focus restoration after Settings close")

def process_start_time(entry: Path, expected_pid: int) -> int:
    try:
        with (entry / "stat").open("rb") as stream:
            raw = stream.read(4097)
    except FileNotFoundError:
        raise
    if len(raw) > 4096 or not raw.endswith(b"\n"):
        raise RuntimeError(f"Process {expected_pid} has an invalid bounded stat record.")
    closing = raw.rfind(b") ")
    opening = raw.find(b" (")
    if opening < 1 or closing <= opening:
        raise RuntimeError(f"Process {expected_pid} has a malformed stat record.")
    try:
        recorded_pid = int(raw[:opening].decode("ascii"))
        fields = raw[closing + 2:-1].split()
        start_time = int(fields[19].decode("ascii"))
    except (UnicodeDecodeError, ValueError, IndexError) as error:
        raise RuntimeError(f"Process {expected_pid} has a malformed stat identity.") from error
    if recorded_pid != expected_pid or start_time <= 0:
        raise RuntimeError(f"Process {expected_pid} has a mismatched stat identity.")
    return start_time

def qemu_processes(proc_root: Path = Path("/proc")) -> set[tuple[int, int, str]]:
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
            pid = int(entry.name)
            try:
                start_time = process_start_time(entry, pid)
            except FileNotFoundError:
                continue
            processes.add((pid, start_time, name))
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
    descriptor = open_pinned_executable(executable)
    try:
        process = subprocess.Popen(
            [f"/proc/self/fd/{descriptor}"],
            pass_fds=(descriptor,),
            start_new_session=True,
        )
    finally:
        os.close(descriptor)
    try:
        exercise_accessibility(Atspi.get_desktop(0), time.monotonic() + args.timeout,
                               expected_pid=process.pid,
                               focusable_state=Atspi.StateType.FOCUSABLE,
                               focused_state=Atspi.StateType.FOCUSED,
                               process_poll=process.poll)
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

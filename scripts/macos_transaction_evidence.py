"""Actual normal Mac session inventory and GUI phase reconciliation. No effects."""
import json
import os
from pathlib import Path
import stat
import subprocess
import time


def native_session_snapshot(root, anchor):
    root, anchor = Path(root), Path(anchor)
    relative = root.relative_to(anchor)
    observed = []
    current = anchor
    missing = None
    for name in [None, *relative.parts]:
        if name is not None:
            current = current / name
        try:
            entry = current.lstat()
        except FileNotFoundError:
            missing = str(current)
            break
        if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.getuid() or entry.st_mode & 0o022:
            raise ValueError("Unsafe native session ancestor: " + str(current))
        observed.append({"path": str(current), "dev": entry.st_dev, "ino": entry.st_ino, "uid": entry.st_uid})
    entries = []
    if missing is None:
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in sorted(dirs + files):
                path = Path(directory) / name
                entry = path.lstat()
                if (entry.st_uid != os.getuid() or stat.S_ISLNK(entry.st_mode) or
                        not (stat.S_ISREG(entry.st_mode) or stat.S_ISDIR(entry.st_mode))):
                    raise ValueError("Unsafe native session inventory entry")
                entries.append({"path": str(path.relative_to(root)), "dev": entry.st_dev,
                                "ino": entry.st_ino, "mode": entry.st_mode, "size": entry.st_size,
                                "mtime_ns": entry.st_mtime_ns, "ctime_ns": entry.st_ctime_ns})
                if len(entries) > 256:
                    raise ValueError("Native inventory bound exceeded")
    qemu = subprocess.run(["/usr/bin/pgrep", "-f", "qemu-system-"], capture_output=True, text=True, timeout=10)
    if qemu.returncode not in (0, 1):
        raise ValueError("QEMU inventory failed: " + qemu.stderr[:1024])
    return {"wall_ns": time.time_ns(), "monotonic_ns": time.monotonic_ns(), "uid": os.getuid(),
            "root": str(root), "ancestors": observed, "missingAt": missing, "entries": entries,
            "qemuProbe": {"exit": qemu.returncode, "stdout": qemu.stdout[:4096]},
            "qemuAbsent": qemu.returncode == 1 and not qemu.stdout.strip()}


def reconcile_gui(events_path, before, after, expected_executable):
    events = json.loads(Path(events_path).read_text())
    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
        raise ValueError("Invalid actual GUI event stream")
    intents = [e for e in events if e.get("kind") == "build-request-intent"]
    clicks = [e for e in events if e.get("kind") == "pointer-click" and e.get("label") == "build-pinned-image"]
    failures = [e for e in events if e.get("kind") == "failure"]
    prebuild = [e for e in events if e.get("kind") == "gui-pre-build-checkpoint"]
    apps = [e for e in events if e.get("kind") == "app"]
    bound = (len(apps) == 1 and len(prebuild) == 1 and
             type(apps[0].get("pid")) is int and apps[0]["pid"] > 0 and
             prebuild[0].get("pid") == apps[0]["pid"] and
             apps[0].get("executable") == str(expected_executable) and
             isinstance(apps[0].get("launchDate"), (int, float)) and
             before["wall_ns"] / 1e9 <= apps[0]["launchDate"] <= after["wall_ns"] / 1e9 and
             all(isinstance(e.get("time"), (int, float)) and
                 before["wall_ns"] / 1e9 <= e["time"] <= after["wall_ns"] / 1e9
                 for e in [apps[0], prebuild[0], *failures]))
    # No trace absence is interpreted as successful VM closure. This is a
    # distinct observed NOT STARTED phase using real OS/disk and event evidence.
    no_session = (bound and bool(failures) and not intents and not clicks and
                  before["uid"] == after["uid"] == os.getuid() and before["root"] == after["root"] and
                  before["qemuAbsent"] and after["qemuAbsent"] and
                  before["entries"] == after["entries"] == [] and
                  before["monotonic_ns"] <= after["monotonic_ns"])
    return {"firstGUIFailure": failures[0] if failures else None,
            "BuildIntent": bool(intents), "BuildClicked": bool(clicks),
            "sessionState": "not-launched-observed" if no_session else "launched-or-ambiguous",
            "VMClosurePassed": False, "eventCount": len(events), "eventFile": str(events_path)}

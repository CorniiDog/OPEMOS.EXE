"""Actual normal Mac session inventory and GUI phase reconciliation. No effects."""
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import time


def reconcile_pointer_input(events_path):
    """Strict consumer of actual pair attempts, including failed/partial clicks.

    Fixture validation is not OS proof. Native neutral is a source-state
    observation, never window delivery acknowledgement or product acceptance.
    """
    path = Path(events_path)
    raw = path.read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Native pointer ledger overflow")
    events = json.loads(raw)
    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
        raise ValueError("Invalid native pointer ledger")
    final = [e for e in events if e.get("kind") == "pointer-input-final"]
    if (len(final) != 1 or events[-1] != final[0] or final[0].get("pendingPairIDs") != [] or
            final[0].get("evidenceWriteFailed") is not False):
        raise ValueError("Missing/ambiguous/unpersisted final native input custody")
    def neutral(e):
        state = e.get("state", {})
        return (state.get("neutral") is True and state.get("combinedDown") is False and
                state.get("hardwareDown") is False and state.get("deliveryAcknowledged") is False and
                state.get("api") == "CGEventSource.buttonState")
    if not neutral(final[0]):
        raise ValueError("Final native input state not observed neutral")
    starts = [e for e in events if e.get("kind") == "pointer-pair-start"]
    ids = [e.get("pairID") for e in starts]
    if any(type(i) is not int or i < 1 for i in ids) or len(set(ids)) != len(ids):
        raise ValueError("Invalid/duplicate native pair epoch")
    helpers = [e for e in events if e.get("kind") == "helper-native-birth"]
    if starts and (len(helpers) != 1 or helpers[0].get("probeExit") != 0 or
                   helpers[0].get("uid") != os.getuid() or type(helpers[0].get("probePID")) is not int):
        raise ValueError("Native helper birth probe unavailable")
    pair_events = [e for e in events if e.get("kind", "").startswith("pointer-") and
                   e.get("kind") not in ("pointer-click", "pointer-scroll", "pointer-input-final")]
    if any(e.get("pairID") not in ids for e in pair_events):
        raise ValueError("Orphan native pair event")
    invariant = ("pairID", "label", "clickIndex", "helperPID", "helperBirth", "recipientPID", "recipientBirth",
                 "executable", "bundle", "x", "y", "eventNumber", "sourceState", "deadline")
    summaries = []
    succeeded = set()
    for start in starts:
        pid = start["pairID"]
        rows = [e for e in pair_events if e["pairID"] == pid]
        if not neutral(start) or any(any(e.get(k) != start.get(k) for k in invariant) for e in rows):
            raise ValueError("Native pair recipient/source/point/number or baseline mismatch")
        if (any(type(start.get(k)) is not int or start[k] <= 0 for k in ("helperPID", "recipientPID")) or
                not all(isinstance(start.get(k), str) and start[k] for k in ("helperBirth", "executable", "bundle")) or
                not isinstance(start.get("recipientBirth"), (int, float)) or not math.isfinite(start["recipientBirth"])):
            raise ValueError("Native pair actor epoch unavailable")
        if (start["helperPID"] != helpers[0].get("pid") or start["helperBirth"] != helpers[0].get("birth") or
                start["helperPID"] != final[0].get("helperPID") or start["helperBirth"] != final[0].get("helperBirth") or
                any(not isinstance(start.get(k), (int, float)) or not math.isfinite(start[k]) for k in ("x", "y", "deadline"))):
            raise ValueError("Native pair helper/final identity or numeric custody invalid")
        if (any(type(e.get("uptimeNs")) is not int or e["uptimeNs"] < 0 or
                not isinstance(e.get("time"), (int, float)) or not math.isfinite(e["time"]) or
                e.get("deliveryAcknowledged") is not False for e in rows) or
                [e["uptimeNs"] for e in rows] != sorted(e["uptimeNs"] for e in rows)):
            raise ValueError("Native pair clock/delivery evidence invalid")
        kinds = [e["kind"] for e in rows]
        if "pointer-pair-not-posted" in kinds and "pointer-down-return" not in kinds:
            summaries.append({"pairID": pid, "state": "not-posted-observed", "label": start["label"]})
            continue
        ordered = ("pointer-pair-start", "pointer-down-attempt", "pointer-down-return", "pointer-release-custody",
                   "pointer-up-attempt", "pointer-up-return", "pointer-pair-neutral", "pointer-pair-end")
        if any(kinds.count(k) != 1 for k in ordered) or [kinds.index(k) for k in ordered] != sorted(kinds.index(k) for k in ordered):
            raise ValueError("Issued Down lacks one exact matching Up/neutral disposition")
        custody = rows[kinds.index("pointer-release-custody")]
        if custody.get("hitStatus") != 0 or custody.get("hitPID") != start["recipientPID"] or custody.get("exactHeldWindowAncestor") is not True:
            raise ValueError("Native release lacked original actor/window/point custody")
        if not neutral(rows[kinds.index("pointer-pair-neutral")]):
            raise ValueError("Native pair neutral not observed")
        up = rows[kinds.index("pointer-up-attempt")]
        down = rows[kinds.index("pointer-down-attempt")]
        if down.get("nativeEventType") != 1 or up.get("nativeEventType") != 2:
            raise ValueError("Native Down/Up event types unavailable")
        if not isinstance(start.get("deadline"), (int, float)) or not math.isfinite(start["deadline"]) or up["time"] >= start["deadline"]:
            raise ValueError("Native release outside original deadline")
        complete = rows[kinds.index("pointer-pair-end")].get("succeeded") is True
        if complete:
            succeeded.add(pid)
        summaries.append({"pairID": pid, "label": start["label"], "state": "observed-neutral",
                          "clickSucceeded": complete, "deliveryAcknowledged": False})
    claimed = []
    for click in [e for e in events if e.get("kind") == "pointer-click"]:
        pairs = click.get("pairIDs")
        if (not isinstance(pairs, list) or len(pairs) not in (1, 2) or
                any(i not in succeeded for i in pairs) or
                any(next(s for s in starts if s["pairID"] == i)["label"] != click.get("label") for i in pairs)):
            raise ValueError("Completed click lacks exact successful native pairs")
        claimed.extend(pairs)
    if len(set(claimed)) != len(claimed):
        raise ValueError("Native pair reused by another click")
    return {"observedNeutral": True, "deliveryAcknowledged": False, "pairs": summaries,
            "actualNativeStateAPI": "CGEventSource.buttonState", "eventFile": str(path),
            "productAcceptance": False}


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

#!/usr/bin/env python3
"""Installed OMEN adapter for five typed reviewed queue cases and 4-hour CI copies.

No VM command is accepted on stdin. Original packages, images, case directories
and queue history are never expired. Only copies under this adapter's dedicated
marked CI root can be removed, with current queue and active-run guards.
"""
import base64
import fcntl
import gc
import io
import tempfile
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import zipfile

TTL = 4 * 60 * 60
CASES = ("windows-full-stack", "ubuntu-full-stack", "macos-full-stack", "steamos-autoheal", "nested-ubuntu-linux")
ROOT = Path("/media/connor/Games/OPEMOS/CI-artifacts")
MARKER = ".opemos-ci-artifacts.json"
SHA = re.compile(r"[0-9a-f]{64}\Z")
RUN = re.compile(r"run-[1-9][0-9]{0,19}-[1-9][0-9]{0,19}-[0-9a-f]{32}\Z")
# Match the installed normal queue's closed states. Its `unknown` is terminal
# for scheduling, but never proves lifecycle closure or authorizes expiration.
TERMINAL = {"passed", "failed", "blocked", "timed_out", "output_limit"}
BUILD_CHECKS = {"graphical_chooser", "graphical_build", "cold_readiness", "output_verified",
                "virtual_usb_write", "virtual_usb_flush", "virtual_usb_readback", "steamos_boot",
                "normal_recovery", "abrupt_power_recovery", "wrong_readiness_rejected", "closure"}
HEAL_CHECKS = {"kernel_update", "driver_rebuild_old_kernel", "driver_rebuild_new_kernel",
               "driver_receipt_verified", "graphical_display", "normal_recovery",
               "abrupt_power_recovery", "nvidia_loaded", "nvidia_rendered", "gpu_restored", "closure"}
EVIDENCE_KINDS = {
    "graphical_chooser": {"screenshot", "pointer-action"}, "graphical_build": {"screenshot", "log", "pointer-action"},
    "cold_readiness": {"log"}, "output_verified": {"output-image", "output-manifest"},
    "virtual_usb_write": {"log", "pointer-action"}, "virtual_usb_flush": {"log"},
    "virtual_usb_readback": {"usb-readback"}, "steamos_boot": {"boot-log", "screenshot"},
    "normal_recovery": {"recovery-receipt"},
    "abrupt_power_recovery": {"recovery-receipt", "boot-log"}, "closure": {"queue-closure"},
    "kernel_update": {"log"}, "driver_rebuild_old_kernel": {"log"},
    "driver_rebuild_new_kernel": {"log"}, "driver_receipt_verified": {"output-manifest"},
    "graphical_display": {"screenshot"},
    "wrong_readiness_rejected": {"fault-log", "queue-closure"},
    "nvidia_loaded": {"nvidia-loaded"}, "nvidia_rendered": {"nvidia-render", "screenshot"},
    "gpu_restored": {"gpu-lease", "gpu-restoration", "queue-closure"},
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def identity(s):
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def real_dir(path):
    path = Path(path)
    require(path.is_absolute() and str(path.resolve()) == str(path), "Directory has symlink/relative path")
    s = path.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and not s.st_mode & 0o077,
            "Private owned directory required")
    return s



# Exact pinned copy of the existing canonical operational descriptor reader.
# Bootstrap consumes one bounded held FD; all later code/JSON uses its returned
# bytes. No source is hashed and then reopened for parse or execution.
_READER_SHA = "6b2d97a373001e8835400d5be22cef8c06004dab5c228bc1efbe7078dfe464df"
_FULL9 = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
          "st_size", "st_mtime_ns", "st_ctime_ns")

def _bind_reader():
    import types
    path = Path(__file__).with_name("omen_ci_reader.py")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                before.st_nlink == 1 and not before.st_mode & 0o022 and 0 < before.st_size <= 65536,
                "Canonical reader source type/owner/cap")
        raw = bytearray()
        while True:
            block = os.read(fd, min(65536, 65537 - len(raw)))
            if not block:
                break
            raw.extend(block)
            require(len(raw) <= 65536, "Canonical reader overflow")
        original = tuple(getattr(before, key) for key in _FULL9)
        require(original == tuple(getattr(os.fstat(fd), key) for key in _FULL9) ==
                tuple(getattr(os.lstat(path), key) for key in _FULL9) and len(raw) == before.st_size and
                hashlib.sha256(raw).hexdigest() == _READER_SHA, "Canonical reader full9/hash/path drift")
    finally:
        os.close(fd)
    module = types.ModuleType("opemos_ci_canonical_reader")
    exec(compile(bytes(raw), str(path), "exec"), module.__dict__)
    return module, bytes(raw)

_READER, _READER_RAW = _bind_reader()

_INVENTORY_SHA = "e8873930651d4e1022fd3851b9bc35400ff54310e1d904f5d01c0f7dd903119e"
_inventory_path = Path(__file__).with_name("omen_ci_inventory.py")
_inventory_pin, _inventory_raw = _READER.read_verified(_inventory_path, 1024**2, expected_sha=_INVENTORY_SHA, uid=os.getuid())
_INVENTORY = _READER.verified_namespace(_inventory_raw, _inventory_path, "opemos_ci_inventory")

_EXECUTABLES_SHA = "435aa0901a39981fc26d2b5a87f283aa918985318fcd28213c86da918c4c5b1f"
_executables_path = Path(__file__).with_name("omen_ci_executables.py")
_executable_pin, _executable_raw = _READER.read_verified(_executables_path, 1024**2,
    expected_sha=_EXECUTABLES_SHA, uid=os.getuid())
_EXECUTABLES = _READER.verified_namespace(_executable_raw, _executables_path, "opemos_ci_executables")
_RESULT_SHA = "5baa682b9bd7b625d817b857befa7b180edf025bf1b8ab60e7de0a77fd456f85"
_result_path=Path(__file__).with_name("omen_ci_result.py")
_result_pin,_result_raw=_READER.read_verified(_result_path,1024**2,expected_sha=_RESULT_SHA,uid=os.getuid())
_RESULT=_READER.verified_namespace(_result_raw,_result_path,"opemos_ci_result")





def pinned(item, limit=8 * 1024**2):
    path = Path(item["path"])
    require(path.is_absolute() and str(path.resolve()) == str(path), "File has symlink/relative path")
    uid = item.get("uid", os.getuid())
    require(uid in (0, os.getuid()), "Only current-principal or existing protected Root inputs admitted")
    pin, raw = _READER.read_verified(path, limit, expected_sha=item["sha256"],
                                     expected_size=item.get("size"), uid=uid)
    require(not pin["identity"]["st_mode"] & 0o022, "Pinned input is group/world writable")
    return raw


def load_pinned(item):
    return strict_json(pinned(item, 1024**2))


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON field")
            result[key] = value
        return result
    def invalid(value):
        raise ValueError("Nonfinite JSON value: " + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def load_result(path, limit=1024**2):
    """Parse only bytes returned by the canonical full9 held-FD reader."""
    path = Path(path)
    require(path.is_absolute() and str(path.resolve()) == str(path), "Result path guard")
    pin, raw = _READER.read_verified(path, limit, uid=os.getuid())
    require(not pin["identity"]["st_mode"] & 0o022, "Result is group/world writable")
    return strict_json(raw), pin["sha256"]


def sealed_manifest(raw):
    """Freeze verified JSON bytes for the unchanged normal queue reader."""
    fd = os.memfd_create("opemos-ci-reviewed-manifest", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(fd, 0o400)
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            require(n > 0, "Complete sealed manifest write")
            view = view[n:]
        os.lseek(fd, 0, os.SEEK_SET)
        flags = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, flags)
        require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) == flags and os.pread(fd, len(raw) + 1, 0) == raw,
                "Sealed exact manifest readback")
        return fd
    except BaseException:
        os.close(fd)
        raise


def absolute_manifest(manifest):
    require(manifest.get("version") == 1 and isinstance(manifest.get("jobs"), list), "Normal version1 manifest required")
    for job in manifest["jobs"]:
        require(Path(job.get("cwd", "")).is_absolute() and job.get("command") and
                Path(job["command"][0]).is_absolute() and
                all(Path(x).is_absolute() for x in job.get("files", [])) and
                Path(job.get("approval", {}).get("path", "")).is_absolute(),
                "Relative manifest operands cannot preserve original-base normalization")
        if "libvirt_domain" in job:
            require(Path(job["libvirt_domain"].get("observer", "")).is_absolute(), "Absolute libvirt observer required")
    return manifest


class MetadataCapture(io.TextIOBase):
    """Complete byte-bounded status stream; anonymous held FD, strict UTF8 at EOF.

    A partial write or overflow is failure, never accepted truncated metadata.
    Unknown rows/fields are retained unchanged by strict_json.
    """
    def __init__(self, cap, scratch):
        super().__init__()
        require(type(cap) is int and 0 < cap <= 512 * 1024**2, "Finite reviewed metadata cap required")
        self.cap, self.total, self.received, self.digest = cap, 0, 0, hashlib.sha256()
        self.stream = tempfile.TemporaryFile(mode="w+b", prefix="opemos-ci-metadata-", dir=scratch)
        self.last = None
        owner = self
        class Binary:
            def write(self, block):
                return owner.write_bytes(block)
            def flush(self):
                owner.flush()
        self.buffer = Binary()

    @property
    def encoding(self):
        return "utf-8"

    def write(self, text):
        require(isinstance(text, str), "Canonical text output must be text")
        self.write_bytes(text.encode("utf-8", errors="strict"))
        return len(text)

    def write_bytes(self, block):
        require(not self.closed and isinstance(block, (bytes, bytearray)), "Open byte capture required")
        self.received += len(block)
        require(self.total + len(block) <= self.cap, "Complete canonical metadata exceeds measured/reviewed byte envelope; no truncation/retry")
        view = memoryview(block)
        while view:
            count = self.stream.write(view)
            require(type(count) is int and 0 < count <= len(view), "Partial metadata spool write failed")
            self.digest.update(view[:count])
            self.total += count
            view = view[count:]
        return len(block)

    def flush(self):
        stream = getattr(self, "stream", None)
        if not self.closed and stream is not None and not stream.closed:
            stream.flush()

    def payload(self):
        self.flush()
        before = os.fstat(self.stream.fileno())
        require(before.st_size == self.total and stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid(),
                "Held metadata spool identity/size mismatch")
        self.stream.seek(0)
        raw = self.stream.read(self.cap + 1)
        require(len(raw) == self.total and hashlib.sha256(raw).hexdigest() == self.digest.hexdigest()
                and _READER.identity(before) == _READER.identity(os.fstat(self.stream.fileno())),
                "Complete metadata FD byte/hash/full9 mismatch")
        # Decoding once at EOF correctly handles byte writes split inside UTF8;
        # malformed/incomplete UTF8 is rejected rather than replaced/ignored.
        value = strict_json(raw.decode("utf-8", errors="strict"))
        self.last = {"bytes": self.total, "sha256": self.digest.hexdigest(), "complete": True,
                     "utf8Strict": True, "anonymousHeldFD": True}
        return value

    def close(self):
        errors = []
        if not self.closed:
            try: self.flush()
            except BaseException as error: errors.append(error)
            try:
                stream = getattr(self, "stream", None)
                if stream is not None: stream.close()
            except BaseException as error: errors.append(error)
            try: super().close()
            except BaseException as error: errors.append(error)
        if errors:
            raise ValueError("Owned metadata capture close failed: " + repr(errors)) from errors[0]


def metadata_envelope(config):
    policy = config.get("queue_metadata", {})
    cap, reserve = policy.get("max_bytes"), policy.get("free_reserve_bytes")
    require(type(cap) is int and 8 * 1024**2 <= cap <= 512 * 1024**2 and
            type(reserve) is int and reserve >= 0, "Reviewed complete metadata maximum/reserve missing")
    scratch = Path(policy.get("scratch_dir", ""))
    real_dir(scratch)
    queue = Path(config["queue_dir"])
    real_dir(queue)
    volume, files = 0, []
    for suffix in ("", "-wal", "-shm"):
        path = queue / ("queue.sqlite3" + suffix)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            require(suffix != "", "Existing normal queue database required")
            continue
        try:
            before = os.fstat(fd)
            after, named = os.fstat(fd), os.lstat(path)
            core = lambda item: tuple(getattr(item, key) for key in
                                      ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink"))
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                    and core(before) == core(after) == core(named),
                    "Existing mutable queue storage core FD/path identity differs")
            # The queue is live, not an immutable code input. Observe legitimate
            # size/time growth under the same core identity without freezing a
            # busy owner's writes. This is an envelope estimate, not DB parsing.
            measured_size = max(before.st_size, after.st_size, named.st_size)
            volume += measured_size
            files.append({"path": str(path), "before": _READER.identity(before),
                          "after": _READER.identity(after), "path_after": _READER.identity(named),
                          "measured_bytes": measured_size})
        finally:
            os.close(fd)
    # Serialized JSON may expand escaped DB values. Reserve eight times current
    # DB+WAL+SHM plus8MiB, capped by explicit reviewed hard maximum. Fresh storage
    # and volume-free checks occur on every status call, not a32MB fixture pin.
    measured = min(cap, max(8 * 1024**2, volume * 8 + 8 * 1024**2))
    space = os.statvfs(scratch)
    require(space.f_bavail * space.f_frsize >= measured + reserve, "Actual metadata spool volume lacks measured envelope+reserve")
    return {"cap_bytes": measured, "reviewed_max_bytes": cap, "storage_bytes": volume,
            "storage": files, "scratch": str(scratch), "free_bytes": space.f_bavail * space.f_frsize,
            "reserve_bytes": reserve, "growth_strategy": "fresh(DB+WAL+SHM)*8+8MiB; bounded by reviewed maximum; overflow fails all20, no row dropping or DB pruning"}


def descriptor_observation(fd):
    """Actual bounded self-FD evidence; never inspect or close another process."""
    try:
        before = os.fstat(fd)
    except OSError as error:
        if error.errno == 9: return {"fd":fd, "open":False}
        raise
    target = os.readlink("/proc/self/fd/" + str(fd))
    after = os.fstat(fd)
    require(_READER.identity(before) == _READER.identity(after)
            and os.readlink("/proc/self/fd/" + str(fd)) == target, "Self descriptor changed during observation")
    return {"fd":fd, "open":True, "target":target, "identity":_READER.identity(before)}


def queue_descriptor_snapshot(config):
    directory = config["queue_dir"].rstrip("/")
    entries = list(Path("/proc/self/fd").iterdir())
    require(len(entries) <= 4096, "Bounded self-descriptor scan")
    observed = []
    for entry in entries:
        try:
            target = os.readlink(entry)
            if target == directory or target.startswith(directory + "/"):
                row = descriptor_observation(int(entry.name))
                require(row["open"] and row["target"] == target, "Queue descriptor changed during snapshot")
                observed.append(row)
        except FileNotFoundError:
            continue
    return sorted(observed, key=lambda x:x["fd"])


def descriptor_keys(snapshot):
    # Queue DB/WAL/SHM may legitimately grow under the same identity. Retain
    # full9 observations but compare descriptor ownership/core identity, not
    # mutable storage size/timestamps. No anonymous FD or queue path is excluded.
    return {(row["fd"],row["target"],*(row["identity"][k] for k in
            ("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink"))) for row in snapshot}


def queue_descriptors(config):
    return {(row["fd"],row["target"]) for row in queue_descriptor_snapshot(config)}


class MetadataConsumerFailure(ValueError):
    def __init__(self, receipt):
        self.metadata_receipt = receipt
        first = receipt["first_failure"]
        super().__init__(first["type"] + ": " + first["reason"])


def queue_call(config, action, manifests=(), capture_receipt=None):
    """Complete unchanged normal producer, consume, close, then prove closure.

    Only current verified source/dependencies and sealed absolute manifests are
    consumed. Caller-owned spool/manifest FDs close before comparing actual queue
    descriptor snapshots; all genuine queue/anonymous leaks still fail.
    """
    import contextlib
    import types
    require(action in ("status", "submit"), "CI never starts/replaces a queue worker")
    modules = {}
    for item in config["queue_modules"]:
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item["module"]), "Declared module name required")
        require(item["module"] not in modules and item["module"] not in sys.stdlib_module_names,
                "Local dependencies cannot replace standard-library modules")
        try: raw = pinned(item)
        except _READER.SourceReadFailure as error:
            error.nonsecret_source_evidence=error.evidence
            raise
        namespace = _READER.verified_namespace(raw, item["path"], item["module"], dependencies=modules)
        module = types.ModuleType(item["module"])
        module.__dict__.update(namespace)
        modules[item["module"]] = module
    entry = config["queue_entry"]
    try: raw = pinned(entry)
    except _READER.SourceReadFailure as error:
        error.nonsecret_source_evidence=error.evidence
        raise
    namespace = _READER.verified_namespace(raw, entry["path"], "opemos_ci_normal_queue", dependencies=modules)
    require(callable(namespace.get("main")), "Installed normal queue main is unavailable")
    before_envelope = metadata_envelope(config)
    gc.collect()
    before_fds = queue_descriptor_snapshot(config)
    receipt = capture_receipt if capture_receipt is not None else {}
    receipt.update(version=2, action=action, producer_source_sha256=hashlib.sha256(raw).hexdigest(),
        before=before_envelope, queue_fds_before=before_fds, owned_descriptors=[], complete=False,
        capture_fd_closed=False, sealed_manifest_fds_closed=False, normal_queue_descriptors_closed=False)
    output, payload, primary, code = None, None, None, None
    owned, close_errors = [], []
    try:
        require(not before_fds,"Standalone CI adapter inherited queue descriptors; refuse shared lifecycle before capture")
        output = MetadataCapture(before_envelope["cap_bytes"], before_envelope["scratch"])
        capture = {"role":"metadata-capture", "allocated":descriptor_observation(output.stream.fileno())}
        receipt["owned_descriptors"].append(capture)
        owned.append((output.stream.fileno(), capture))
        paths = []
        for item in manifests:
            body = pinned(item, 1024**2)
            absolute_manifest(strict_json(body))
            fd = sealed_manifest(body)
            record = {"role":"sealed-manifest", "allocated":descriptor_observation(fd)}
            receipt["owned_descriptors"].append(record);owned.append((fd,record))
            paths.append("/proc/self/fd/" + str(fd))
        argv = ["--queue", config["queue_dir"], action, *paths]
        with contextlib.redirect_stdout(output): code = namespace["main"](argv)
        receipt["producer_exit"] = code
        require(type(code) is int and code == 0, "Normal queue metadata consumer failed")
        payload = output.payload()
        receipt.update(output.last)
        after_envelope = metadata_envelope(config)
        receipt["after"] = after_envelope
        require(output.total <= after_envelope["cap_bytes"], "Queue storage changed beyond complete metadata envelope")
    except BaseException as error:
        primary = error
    finally:
        # Ownership proof comes before each exact close; close cannot target a
        # replaced/reused descriptor. Capture's full9 may grow during writes.
        for fd, record in reversed(owned):
            try:
                if record["role"] == "metadata-capture":
                    record["before_flush"] = descriptor_observation(fd)
                    allocated = record["allocated"]
                    before_flush = record["before_flush"]
                    require(before_flush["open"] and before_flush["target"] == allocated["target"] and
                        all(before_flush["identity"][k] == allocated["identity"][k] for k in
                            ("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink")),
                        "Owned capture identity changed; refusing foreign flush")
                    try: output.flush()
                    except BaseException as error:
                        record["flush_error"]={"type":type(error).__name__,"reason":str(error)}
                        close_errors.append(record["flush_error"])
                observed = descriptor_observation(fd);record["before_close"] = observed
                allocated = record["allocated"]
                require(observed["open"] and observed["target"] == allocated["target"] and
                    all(observed["identity"][k] == allocated["identity"][k] for k in
                        ("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink")),
                    "Owned metadata descriptor identity changed; refusing foreign close")
                if record["role"] == "metadata-capture": output.close()
                else: os.close(fd)
            except BaseException as error:
                record["close_error"] = {"type":type(error).__name__, "reason":str(error)}
                close_errors.append(record["close_error"])
            try:
                record["after_close"] = descriptor_observation(fd)
                if record["after_close"]["open"]:
                    close_errors.append({"type":"ValueError", "reason":"Owned metadata descriptor still open after close"})
            except BaseException as error:
                record["after_close_error"] = {"type":type(error).__name__, "reason":str(error)}
                close_errors.append(record["after_close_error"])
        receipt.update(captured_bytes=output.total if output else 0, observed_bytes=output.received if output else 0,
            captured_prefix_sha256=output.digest.hexdigest() if output else hashlib.sha256(b"").hexdigest(),
            capture_fd_closed=bool(output is not None and output.closed and owned and
                owned[0][1].get("after_close",{}).get("open") is False),
            sealed_manifest_fds_closed=all(record.get("after_close",{}).get("open") is False
                for _,record in owned if record["role"] == "sealed-manifest"))
        try:
            gc.collect()  # normal sqlite cycles close after producer returns
            after_fds = queue_descriptor_snapshot(config)
            receipt["queue_fds_after_owned_close"] = after_fds
            receipt["normal_queue_descriptors_closed"] = descriptor_keys(after_fds) == descriptor_keys(before_fds)
            require(receipt["normal_queue_descriptors_closed"], "Normal metadata producer left queue descriptors; closure unknown")
        except BaseException as error:
            close_errors.append({"type":type(error).__name__, "reason":str(error)})
        if close_errors: receipt["close_failures"] = close_errors
        if primary is not None or close_errors:
            receipt["complete"] = False
            receipt["first_failure"] = ({"type":type(primary).__name__, "reason":str(primary)} if primary is not None else close_errors[0])
    if primary is not None or close_errors:
        raise MetadataConsumerFailure(receipt) from primary
    receipt["complete"] = True
    return payload


def create_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def owned_lock(path):
    """Open the existing generated lock through one held nofollow descriptor."""
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                before.st_nlink == 1 and not before.st_mode & 0o077 and
                _READER.identity(before) == _READER.identity(os.lstat(path)),
                "Run lock full9/type/owner/path guard")
        return os.fdopen(fd, "r+")
    except BaseException:
        os.close(fd)
        raise


def root_guard(root=ROOT):
    real_dir(root)
    marker, _ = load_result(root / MARKER)
    require(marker == {"schema": 1, "uid": os.getuid(), "purpose": "OPEMOS CI copies only"},
            "Dedicated CI root marker mismatch")
    real_dir(root / ".receipts")


def queue_status(config, diagnostic=None):
    queue = Path(config["queue_dir"])
    real_dir(queue)
    database = (queue / "queue.sqlite3").lstat()
    require(stat.S_ISREG(database.st_mode) and database.st_uid == os.getuid() and database.st_nlink == 1,
            "Existing queue database required; this adapter never initializes a queue")
    payload = queue_call(config, "status", capture_receipt=diagnostic)
    pool_sha = hashlib.sha256(json.dumps(payload["pool"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    require(pool_sha == config["pool_sha256"], "Installed shared-pool configuration differs from reviewed admission")
    jobs = payload["jobs"]
    require(isinstance(jobs, list) and len({x["id"] for x in jobs}) == len(jobs), "Ambiguous queue rows")
    if diagnostic is not None:
        diagnostic.update(job_rows=len(jobs), pool_sha256=pool_sha, all_rows_retained=True,
                          top_level_keys=sorted(payload), mutation="normal status only; no submit/run/dispatch/expire")
    return {row["id"]: row for row in jobs}


def closed_jobs(job_ids, rows):
    return all(job in rows and rows[job].get("state") in TERMINAL
               and not ((rows[job].get("result") or {}).get("reason", "").startswith("Unit evidence missing"))
               for job in job_ids)


def process_identity(value):
    return (isinstance(value, dict) and set(value) == {"pid", "start"} and
            all(type(x) is int and x > 0 for x in value.values()))


def validate_roles(receipt, case, plan, operand):
    """Keep outer host, inner appliance, USB and SteamOS target distinct."""
    roles = receipt.get("roles", {})
    allowed = {"imaging_host", "fedora_appliance", "virtual_usb", "steamos_target"}
    require(isinstance(roles, dict) and set(roles) <= allowed and
            (case == "steamos-autoheal" or set(roles) == allowed), "Exact normal graph roles required")
    declared_ids = [value["inventory_vm_id"] for value in roles.values()
                    if isinstance(value, dict) and value.get("inventory_vm_id")]
    require(all(isinstance(x, str) for x in declared_ids) and len(declared_ids) == len(set(declared_ids)), "One canonical VM cannot impersonate two graph roles")
    target = roles.get("steamos_target", {})
    require(target.get("platform") == "steamos" and target.get("architecture") == "x86_64" and
            target.get("kind") == "vm" and target.get("owned") is True and target.get("id") and
            target.get("disk_identity"), "Actual owned x86 SteamOS target identity missing")
    boots = [target.get(key) for key in ("baseline_boot_id", "normal_boot_id", "abrupt_boot_id")]
    require(all(isinstance(x, str) and x for x in boots) and len(set(boots)) == 3 and
            receipt.get("recovery_target_id") == target["id"] and
            receipt.get("recovery_target_disk_identity") == target["disk_identity"],
            "Recovery must power-cycle the same actual SteamOS target/disk")
    role = operand.get("subject_role")
    require(_INVENTORY["subject_contract"](operand["inventory_vm_id"], case, role) and receipt.get("subject_role") == role,
            "Each inventory VM must declare its own actual graph subject role")
    require(case != "steamos-autoheal" or role == "steamos_target", "Autoheal inventory subject must be actual SteamOS target")
    subject = roles.get(role, {})
    original=operand.get("original_source",{})
    require(SHA.fullmatch(original.get("sha256","") or "") and type(original.get("size"))is int and original["size"]>0
            and isinstance(original.get("identity"),dict)and set(original["identity"])==set(_FULL9)
            and subject.get("original_source")==original,"Actual runtime subject original/source lineage missing or changed")
    require(subject.get("inventory_vm_id") == operand["inventory_vm_id"] and
            subject.get("id") == operand["runtime_instance_id"] and subject.get("owned") is True and
            (subject.get("id") not in _INVENTORY["IDS"] or subject.get("id") == operand["inventory_vm_id"]) and
            subject.get("original_inventory_id") == operand["inventory_vm_id"] and
            subject.get("runtime_relationship") in ("existing", "owned-disposable-copy"),
            "Inventory VM and separately admitted actual runtime instance/provenance differ")
    if case == "steamos-autoheal":
        require(target.get("location") == "omen-vm", "Same admitted OMEN SteamOS guest required")
        return roles
    host, appliance, usb = (roles.get(key, {}) for key in ("imaging_host", "fedora_appliance", "virtual_usb"))
    expected = {"windows-full-stack": ("windows", "x86_64"), "ubuntu-full-stack": ("linux", "x86_64"),
                "macos-full-stack": ("darwin", "arm64")}[case]
    require((host.get("platform"), host.get("architecture")) == expected and host.get("kind") == "vm" and
            host.get("disk_identity") and process_identity(host.get("app_process")) and host.get("app_window_id"),
            "Actual graphical outer imaging host/app process/window identity missing")
    require(appliance.get("platform") == "fedora" and appliance.get("architecture") == "x86_64" and
            appliance.get("id") and appliance.get("kind") == "vm" and appliance.get("disk_identity") and appliance.get("owned") is True and
            appliance.get("host_instance_id") == host["id"] and process_identity(appliance.get("qemu_process")),
            "Actual inner Fedora appliance and outer-host child birth missing")
    require(len({host["id"], appliance["id"], target["id"]}) == 3,
            "Outer imaging host, Fedora appliance and SteamOS target cannot impersonate each other")
    output = receipt.get("output", {})
    require(SHA.fullmatch(output.get("sha256", "")) and SHA.fullmatch(output.get("manifest_sha256", "")) and
            all(output.get(k) == v for k, v in {"source_commit": plan["source_commit"], "nonce": plan["nonce"],
                "package_sha256": operand["package_sha256"], "input_sha256": operand["input_sha256"]}.items()),
            "Input/source/package to actual output image/manifest custody missing")
    require(usb.get("kind") == "virtual" and usb.get("owned") is True and usb.get("id") and
            usb.get("source_output_sha256") == output["sha256"] == usb.get("readback_sha256") and
            type(usb.get("bytes")) is int and usb["bytes"] > 0 and target.get("boot_medium_id") == usb["id"] and
            target.get("image_sha256") == output["sha256"],
            "Actual output to owned USB readback to x86 SteamOS target custody missing")
    files = receipt.get("files", {})
    require(any(f.get("kind") == "output-image" and f.get("sha256") == output["sha256"] for f in files.values()) and
            any(f.get("kind") == "output-manifest" and f.get("sha256") == output["manifest_sha256"] for f in files.values()),
            "Graph output hashes do not reference actual typed retained artifacts")
    return roles


def validate_wrong_marker(receipt, plan, operand):
    fault = receipt.get("readiness_fault", {})
    guest = receipt["roles"]["imaging_host"]
    required = {"consumer_guest_id": guest["id"], "disk_identity": guest["disk_identity"],
                "package_sha256": operand["package_sha256"], "source_commit": plan["source_commit"],
                "nonce": plan["nonce"], "transport_exit": 0, "consumer_outcome": "rejected",
                "continued_build": False, "source_unchanged": True, "appliance_processes_gone": True,
                "queue_released": True}
    require(all(fault.get(k) == v for k, v in required.items()),
            "Actual same-guest successful-but-wrong readiness consumer rejection/closure missing")
    require(fault.get("continued_build") is False and all(fault.get(k) is True for k in
            ("source_unchanged", "appliance_processes_gone", "queue_released")),
            "Wrong-marker consumer fault needs explicit boolean outcome/closure")
    require(type(fault.get("transport_exit")) is int and fault.get("closure_job_ids") == operand["job_ids"],
            "Actual numeric successful transport and same fault queue closure required")
    expected, observed = fault.get("expected_marker"), fault.get("observed_marker")
    require(all(isinstance(x, str) and 0 < len(x) <= 256 for x in (expected, observed)) and expected != observed,
            "Wrong-marker fault must retain distinct expected and successful observed marker")
    birth = fault.get("consumer_process", {})
    require(set(birth) == {"pid", "start"} and all(type(x) is int and x > 0 for x in birth.values()) and
            fault.get("appliance_instance"), "Exact fault consumer/appliance process identity missing")


def validate_gpu(receipt, operand):
    """Require measured existing-GPU acceptance; this grants no GPU authority."""
    require(operand.get("hardware_scope") == "existing-independently-admitted-gpu" and receipt.get("gpu_claim") is True,
            "SteamOS autoheal unavailable without existing independently admitted shared-GPU scope")
    gpu = receipt.get("gpu", {})
    guest = receipt["roles"]["steamos_target"]
    admission = operand.get("gpu_admission", {})
    require(SHA.fullmatch(admission.get("sha256", "")) and gpu.get("admission_sha256") == admission["sha256"] and
            gpu.get("group") == "omen-iommu-group-1" and gpu.get("lease_nonce") == operand.get("lease_nonce") and
            re.fullmatch(r"[0-9a-f]{32}", gpu.get("lease_nonce", "")), "Existing exact shared-GPU admission/lease identity missing")
    require(gpu.get("guest_id") == guest["id"] and gpu.get("driver_version") == operand["driver_version"] and
            isinstance(gpu.get("gpu_uuid"), str) and gpu["gpu_uuid"], "Same guest/NVIDIA driver/GPU UUID missing")
    samples = gpu.get("samples", [])
    required_boots = {guest[k] for k in ("baseline_boot_id", "normal_boot_id", "abrupt_boot_id")}
    require(isinstance(samples, list) and {x.get("boot_id") for x in samples} == required_boots and
            len(samples) == 3 and [x.get("boot_id") for x in samples] ==
            [guest[k] for k in ("baseline_boot_id", "normal_boot_id", "abrupt_boot_id")],
            "NVIDIA loaded/render proof required before update and across normal/abrupt recovery")
    files = receipt.get("files", {})
    require(all(len({sample.get(key) for sample in samples}) == 3 for key in
                ("screenshot", "query_evidence", "render_evidence")),
            "Distinct actual NVIDIA query/render/display captures are required across boots")
    for sample in samples:
        require(sample.get("guest_id") == guest["id"] and sample.get("gpu_uuid") == gpu["gpu_uuid"] and
                sample.get("driver_version") == operand["driver_version"] and sample.get("module_loaded") is True and
                type(sample.get("driver_query_exit")) is int and sample.get("driver_query_exit") == 0 and
                type(sample.get("render_exit")) is int and sample.get("render_exit") == 0 and
                sample.get("render_vendor") == "NVIDIA Corporation" and isinstance(sample.get("renderer"), str) and
                sample["renderer"] and not any(x in sample["renderer"].lower() for x in ("llvmpipe", "softpipe", "software")),
                "Actual NVIDIA module/driver/render evidence is missing or software-only")
        require(files.get(sample.get("screenshot"), {}).get("kind") == "screenshot" and
                files.get(sample.get("query_evidence"), {}).get("kind") == "nvidia-loaded" and
                files.get(sample.get("render_evidence"), {}).get("kind") == "nvidia-render",
                "Same-boot NVIDIA loaded/render/display artifact references missing")
    require([x["kernel"] for x in samples][0] == operand["kernels"][0] and
            all(x["kernel"] == operand["kernels"][-1] for x in samples[1:]), "Old/new recovery kernel identities differ")
    restored = gpu.get("four_function_restoration", {})
    functions = {"0000:01:00.0", "0000:01:00.1", "0000:01:00.2", "0000:01:00.3"}
    require(set(restored) == functions and all(v.get("restored") is True and v.get("before_driver") and
            v.get("after_driver") == v.get("before_driver") for v in restored.values()) and
            gpu.get("lease_closed") is True and gpu.get("domain_closed") is True and gpu.get("qmp_closed") is True,
            "Verified four-function original-driver restoration/domain/QMP/lease closure missing")


def validate_nested_actual(actual, queue, serial, vm_id, source_pins):
    """Consume the existing actual A/B receipt shape without relabeling its role.

    Historic receipts can qualify retained role evidence; current pipeline
    success additionally requires its fresh source/run/nonce wrapper below.
    """
    require(vm_id in {"OPEMOS-Ubuntu-KVM-A", "OPEMOS-Ubuntu-KVM-B"}, "Exact nested Ubuntu inventory role required")
    letter = "A" if vm_id.endswith("-A") else "B"
    prefix = "OPEMOS_" if letter == "A" else "OPEMOS_B_"
    require(actual.get("kind", "").startswith("CORE_KVM_" + letter + "_ACTUAL_NESTED_LINUX_COLD_BOOT_R")
            and actual.get("status") == "PASS_NESTED_LINUX_AND_CLOSURE"
            and type(actual.get("exit")) is int and actual["exit"] == 0
            and actual.get("childExited") is True and actual.get("sourceStable") is True
            and actual.get("networkWaitObserved") is False and type(actual.get("pid")) is int and actual["pid"] > 0,
            "Actual nested Linux numeric exit/source/child closure proof missing")
    markers = [prefix + value for value in ("OUTER_BOOT_BEGIN", "PAYLOAD_MOUNT_EXIT=0", "PAYLOAD_HASH_EXIT=0",
               "INNER_LINUX_BOOT_OK", "INNER_POWEROFF_BEGIN", "INNER_QEMU_EXIT=0", "OUTER_BOOT_END")]
    require(set(actual.get("markers", {})) == set(markers) and all(actual["markers"][x] is True for x in markers)
            and all(x.encode() in serial for x in markers)
            and actual.get("serialBytes") == len(serial)
            and actual.get("serialSHA256") == hashlib.sha256(serial).hexdigest(), "Exact typed outer/inner actual serial custody differs")
    positions = [serial.index(x.encode()) for x in markers]
    require(positions == sorted(positions) and serial.count(b"Linux version ") >= 2,
            "Actual ordered outer/inner Linux boots and payload verification missing")
    pins = actual.get("sourcePins", {})
    require(pins == source_pins and isinstance(pins, dict) and len(pins) >= 5
            and all(Path(k).is_absolute() and SHA.fullmatch(v) for k, v in pins.items())
            and all(any(Path(path).name == name and vm_id in path for path in pins)
                    for name in ("base.qcow2", "active.qcow2")), "Exact original/base/seed/payload source custody missing")
    argv = actual.get("command", [])
    require(isinstance(argv, list) and argv[:5] == ["/usr/bin/qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host"]
            and "-virtfs" in argv and "none" == argv[argv.index("-nic") + 1], "Actual nested KVM readonly payload graph missing")
    require(queue.get("state") == "passed" and queue.get("id", "").startswith("core-ubuntu-kvm-" + letter.lower() + "-nested-")
            and queue.get("started") <= actual.get("started") <= actual.get("finished") <= queue.get("finished"),
            "Exact nested queue invocation/timing differs")
    lifecycle = queue.get("result", {}).get("terminalLifecycle", {})
    closed = lifecycle.get("postStopCgroupProof", {})
    pool = lifecycle.get("postStopPoolProof", {})
    require(lifecycle.get("phase") == "CLOSED" and closed.get("completeTraversal") is True
            and closed.get("includesUID0") is True and closed.get("empty") is True and closed.get("processes") == []
            and pool.get("admitted") is True and pool.get("allOwnedDescriptorsClosed") is True,
            "Actual nested canonical cgroup/pool descriptor closure missing")
    return {"role": "nested_linux", "platform": "ubuntu", "outer_qemu_pid": actual["pid"],
            "outer_process_birth": "UNKNOWN_NOT_RECORDED_BY_HISTORICAL_PRODUCER",
            "queue_job_id": queue["id"], "queue_unit": queue["unit"], "numeric_qemu_exit": actual["exit"],
            "source_pins": pins, "serial_sha256": actual["serialSHA256"], "nested_linux_boot": True,
            "executable_acceptance": False, "fedora_appliance_claim": False, "gpu_claim": False,
            "fullstack_claim": False, "unknown_historical_fields_preserved": True}


def validate_nested_receipt(receipt, plan, operand):
    require(all(isinstance(plan.get(k), str) and re.fullmatch(r"[1-9][0-9]{0,19}", plan[k])
                for k in ("run_id", "attempt")), "Current nested source/run/attempt plan binding missing")
    for key, expected in {"case": "nested-ubuntu-linux", "source_commit": plan["source_commit"],
                          "nonce": plan["nonce"], "run_id": plan["run_id"], "attempt": plan["attempt"],
                          "inventory_vm_id": operand["inventory_vm_id"],
                          "runtime_instance_id": operand["runtime_instance_id"], "subject_role": "nested_linux",
                          "queue_job_ids": operand["job_ids"], "input_sha256": operand["input_sha256"]}.items():
        require(receipt.get(key) == expected, "Nested current-run " + key + " identity differs")
    require(receipt.get("status") == "passed" and receipt.get("gpu_claim") is False
            and receipt.get("physical_usb_written") is False and receipt.get("fullstack_claim") is False
            and operand.get("hardware_scope") == "virtual-only"
            and _INVENTORY["subject_contract"](operand["inventory_vm_id"], "nested-ubuntu-linux", "nested_linux"),
            "Nested role cannot impersonate fullstack/GPU/physical acceptance")
    files = receipt.get("files", {})
    require(isinstance(files, dict) and set(files) >= {"nested_actual", "nested_queue", "nested_serial", "payload_manifest"}
            and len(files) <= 128, "Actual nested typed artifacts missing")
    raw = {}
    for key, kind, cap in (("nested_actual", "nested-linux-result", 1024**2),
                           ("nested_queue", "queue-closure", 8 * 1024**2),
                           ("nested_serial", "boot-log", 8 * 1024**2),
                           ("payload_manifest", "payload-manifest", 1024**2)):
        require(files[key].get("kind") == kind, "Nested retained artifact kind differs")
        raw[key] = pinned(files[key], cap)
    actual, queue = strict_json(raw["nested_actual"]), strict_json(raw["nested_queue"])
    validated = validate_nested_actual(actual, queue, raw["nested_serial"], operand["inventory_vm_id"], operand["source_pins"])
    require(operand["job_ids"] == [queue["id"]] and operand["input_sha256"] in actual["sourcePins"].values()
            and hashlib.sha256(raw["payload_manifest"]).hexdigest() in actual["sourcePins"].values(),
            "Current nested queue/input/payload manifest custody differs")
    require(receipt.get("roles") == {"nested_linux": {**validated, "id": operand["runtime_instance_id"],
            "inventory_vm_id": operand["inventory_vm_id"], "original_inventory_id": operand["inventory_vm_id"],
            "runtime_relationship": "owned-disposable-copy", "original_source":operand["original_source"], "owned": True}}, "Exact nested observed role/custody differs")
    require(receipt.get("closure") == {"processes_gone": True, "pool_released": True, "queue_released": True},
            "Nested current case closure missing")
    return files


POINTER_ACTIONS=("chooser-open","chooser-confirm-exact-input","Build","virtualUSB-select-and-review","virtualUSB-Write-confirmation")
POINTER_TRANSITIONS={"chooser-open":("main","chooser"),"chooser-confirm-exact-input":("chooser","input-selected"),
    "Build":("input-selected","build-started"),"virtualUSB-select-and-review":("output-ready","usb-reviewed"),
    "virtualUSB-Write-confirmation":("usb-reviewed","write-started")}


def pointer_file(files,ref,kind,operand,cap=1024**2):
    require(isinstance(ref,str)and ref in files and files[ref].get("kind")==kind,"Actual typed pointer file reference missing")
    item=files[ref];path=Path(item["path"])
    roots=operand.get("evidence_roots")or[operand.get("evidence_root","")]
    require(roots and all(Path(x).is_absolute()for x in roots)and any(path.is_relative_to(Path(x))for x in roots),
            "Pointer evidence escaped independently reviewed normal operation roots")
    pin,raw=_READER.read_verified(path,cap,expected_sha=item["sha256"],expected_size=item["size"],uid=os.getuid())
    require(not pin["identity"]["st_mode"]&0o022,"Pointer evidence writable by another principal")
    previous=item.get("_gui_validated_identity")
    require(previous is None or previous==pin["identity"],"Pointer original descriptor changed between normal consumers")
    item["_gui_validated_identity"]=pin["identity"]
    return pin,raw


def pointer_json(files,ref,kind,operand):
    pin,raw=pointer_file(files,ref,kind,operand)
    value=strict_json(raw);require(isinstance(value,dict),"Pointer record must be actual JSON object")
    return value,pin


def windows_frame_pixels(ppm,png,display):
    """Exact existing QMP PPM to deterministic copied RGB PNG, bounded pixels."""
    import struct,zlib
    require(ppm.startswith(b"P6"),"Windows original QMP PPM missing")
    index=2;tokens=[]
    while len(tokens)<3:
        while index<len(ppm)and ppm[index:index+1]in b" \t\r\n":index+=1
        require(index<len(ppm),"Truncated PPM header")
        if ppm[index:index+1]==b"#":
            end=ppm.find(b"\n",index);require(end>=0,"Truncated PPM comment");index=end+1;continue
        end=index
        while end<len(ppm)and ppm[end:end+1]not in b" \t\r\n":end+=1
        require(end<len(ppm)and end>index,"Truncated PPM dimensions")
        tokens.append(int(ppm[index:end]));index=end
    require(index<len(ppm)and ppm[index:index+1]in b" \t\r\n","PPM delimiter missing")
    index+=2 if ppm[index:index+2]==b"\r\n"else 1
    width,height,maximum=tokens;pixels=ppm[index:]
    require((width,height)==(display["width"],display["height"])and maximum==255 and len(pixels)==width*height*3<=16*1024**2,"Original PPM dimensions/pixels differ")
    require(png[:8]==b"\x89PNG\r\n\x1a\n","Converted PNG missing")
    offset=8;data=[];header=False;ended=False
    while offset<len(png):
        require(offset+12<=len(png),"Truncated PNG chunk")
        length=struct.unpack(">I",png[offset:offset+4])[0];kind=png[offset+4:offset+8];end=offset+8+length
        require(end+4<=len(png),"Truncated PNG bytes")
        body=png[offset+8:end];require(zlib.crc32(kind+body)&0xffffffff==struct.unpack(">I",png[end:end+4])[0],"PNG conversion CRC differs")
        if kind==b"IHDR":
            require(not header and body==struct.pack(">IIBBBBB",width,height,8,2,0,0,0),"Converted RGB PNG header differs");header=True
        elif kind==b"IDAT":require(header and not ended,"PNG chunk ordering differs");data.append(body)
        elif kind==b"IEND":require(length==0 and end+4==len(png),"PNG trailing bytes");ended=True
        offset=end+4
    require(header and ended and data,"Incomplete PNG conversion")
    limit=len(pixels)+height;decoder=zlib.decompressobj();decoded=decoder.decompress(b"".join(data),limit+1)
    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and len(decoded)==limit,"Bounded PNG RGB decode differs")
    require(decoded==b"".join(b"\0"+pixels[y*width*3:(y+1)*width*3]for y in range(height)),"PPM/PNG exact RGB bytes differ")


def gui_frame(files,frame,operand,session,used):
    import struct
    require(isinstance(frame,dict)and re.fullmatch(r"[0-9a-f]{32}",frame.get("capture_id","")or"")
            and frame["capture_id"]not in used and type(frame.get("tick"))is int and frame["tick"]>=0,
            "Distinct actual frame acquisition identity/clock tick missing or reused")
    used.add(frame["capture_id"])
    pin,raw=pointer_file(files,frame.get("ref"),"screenshot",operand,16*1024**2)
    require(raw[:8]==b"\x89PNG\r\n\x1a\n"and len(raw)>=24 and raw[12:16]==b"IHDR","Actual captured PNG header missing")
    require(struct.unpack(">II",raw[16:24])==(session["display"]["width"],session["display"]["height"]),"Frame/display geometry mismatch")
    capture,cp=pointer_json(files,frame.get("capture_ref"),"frame-capture",operand)
    require(capture.get("capture_id")==frame["capture_id"]and capture.get("clock")==frame["clock"]
        and capture.get("tick")==frame["tick"]and capture.get("frame_ref")==frame["ref"]
        and capture.get("frame_sha256")==pin["sha256"]and capture.get("session")==session
        and capture.get("acquired")is True,"Actual frame acquisition metadata/bytes/session mismatch")
    if session["platform"]=="windows":
        original,source=pointer_file(files,frame.get("original_ref"),"screenshot-original-ppm",operand,16*1024**2)
        require(source.startswith(b"P6")and original["sha256"]==capture.get("original_sha256"),"Windows original QMP PPM absent")
        conversion,_=pointer_json(files,frame.get("conversion_ref"),"frame-conversion",operand)
        require(conversion.get("capture_id")==frame["capture_id"]and conversion.get("original_ref")==frame["original_ref"]
            and conversion.get("original_sha256")==original["sha256"]and conversion.get("derived_ref")==frame["ref"]
            and conversion.get("derived_sha256")==pin["sha256"]and type(conversion.get("numeric_exit"))is int
            and conversion["numeric_exit"]==0 and conversion.get("pixel_bytes_preserved")is True
            and conversion.get("converter_source_sha256")==operand.get("gui_converter",{}).get("sha256"),
            "Original PPM/derived PNG exact conversion custody missing")
        pinned(operand["gui_converter"])
        windows_frame_pixels(source,raw,session["display"])
    return {"capture_id":frame["capture_id"],"frame_sha256":pin["sha256"],"capture_receipt_sha256":cp["sha256"],"identity":pin["identity"]}


def gui_number(value):
    import math
    return type(value)in(int,float)and math.isfinite(value)


def gui_rect(rect,display):
    return (isinstance(rect,dict)and set(rect)=={"x","y","width","height"}and
        all(gui_number(v)for v in rect.values())and rect["width"]>0 and rect["height"]>0
        and display["origin_x"]<=rect["x"]<rect["x"]+rect["width"]<=display["origin_x"]+display["coordinate_width"]
        and display["origin_y"]<=rect["y"]<rect["y"]+rect["height"]<=display["origin_y"]+display["coordinate_height"])


def validate_pointer_destination(row,identity,session,app,clock,files,operand):
    observed=row.get('actual_destination',{})
    admission,pin=pointer_json(files,observed.get('admission_ref'),'pointer-destination-admission',operand)
    expected=operand.get('gui_destination_admission',{})
    raw=pinned(expected)
    require(pin['sha256']==expected.get('sha256')and pin['bytes']==expected.get('size')and strict_json(raw)==admission,
            'Destination mapping is not the independently pinned current admission')
    actual=observed.get('observed',{})
    require(admission.get('schema')==1 and admission.get('kind')=='OPEMOS_ADMITTED_POINTER_DESTINATION'and admission.get('admitted')is True
        and admission.get('identity')==identity and admission.get('session')==session and admission.get('clock')==clock
        and admission.get('app')=={key:app[key]for key in('process','executable_sha256','root_window_id')}
        and actual==admission.get('qmp')and observed.get('admission_sha256')==pin['sha256'],
        'Actual QMP destination/app/runtime/current-source mapping differs')
    require(process_identity(actual.get('qemu_process'))and actual.get('host_boot_id')==clock['id']and actual.get('qmp_name')
        and Path(actual.get('socket_path','')).is_absolute()and Path(actual.get('disk',{}).get('path','')).is_absolute()
        and actual.get('disk',{}).get('read_only')is False and SHA.fullmatch(actual.get('argv_sha256','')or''),
        'Actual QMP birth/socket/disk/argv observation missing')
    peer=actual.get('peer',{});socket_identity=actual.get('socket_identity',{})
    require(peer=={'pid':actual['qemu_process']['pid'],'uid':os.getuid(),'gid':os.getgid()}
        and isinstance(socket_identity,dict),
        'Actual destination peer/socket identity missing')
    import stat
    require(all(type(socket_identity.get(key))is int for key in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        and stat.S_ISSOCK(socket_identity['st_mode'])and socket_identity['st_uid']==os.getuid(), 'Actual owned QMP socket full identity missing')
    context=row['source_context']
    require(context.get('destination_admission_path')==expected['path']and context.get('destination_admission_sha256')==pin['sha256'],
            'Sender consumed another destination admission')
    return pin


def validate_pointer_raw(row,life,life_pin,action_pin,files,operand,session):
    context=row['source_context'];raw_pins={}
    for label in('stdout','stderr'):
        ref=context.get('sender_'+label+'_ref')
        require(life.get('raw_refs',{}).get(label)==ref,'Actual sender raw reference missing')
        pin,raw=pointer_file(files,ref,'pointer-sender-'+label,operand,24*1024**2 if label=='stdout'and session['platform']=='linux'else 1024**2)
        observed=life.get('raw',{}).get(label,{})
        require(observed.get('path')==pin['path']and observed.get('size')==len(raw)and observed.get('sha256')==pin['sha256']
            and observed.get('identity')==pin['identity']and observed.get('custody')=='verified-prefix'
            and observed.get('full9_unchanged')is True,'Actual complete raw sender bytes/full identity differ')
        require(context.get('sender_'+label+'_path')==pin['path']and life.get('raw_complete',{}).get(label)is True
            and life.get('stream_read_bytes',{}).get(label)==len(raw),'Sender raw output path/complete EOF custody differs')
        raw_pins[label]=pin
    # Exact pre-effect reservations bind created inodes; final size/times may
    # change only through the retained owned descriptors.
    expected={'action_result_path':action_pin,'sender_lifecycle_path':life_pin,
        'sender_stdout_path':raw_pins['stdout'],'sender_stderr_path':raw_pins['stderr']}
    reserved=row.get('output_reservations',{})
    require(set(reserved)==set(expected)and len({pin['path']for pin in expected.values()})==4,'All required distinct pre-effect outputs missing')
    for key,pin in expected.items():
        item=reserved[key];created=item.get('created_identity',{})
        require(item.get('path')==context.get(key)==pin['path']and type(item.get('cap'))is int and item['cap']>=pin['bytes']
            and all(created.get(k)==pin['identity'].get(k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')),
            'Required output was not the exact pre-effect reserved owned inode')
    return raw_pins


def pointer_evidence_size(item):
    return type(item.get('size'))is int and(item['size']>0 or(item['size']==0 and item.get('kind')in('pointer-sender-stdout','pointer-sender-stderr')
        and item.get('sha256')==hashlib.sha256(b'').hexdigest()))


def validate_gui_pointer(receipt,plan,operand,expected_executable=None):
    """Consume actual sender bytes/observations, never pointer labels plus PNG."""
    files=receipt["files"];host=receipt["roles"]["imaging_host"]
    refs=receipt.get("pointer_actions")
    require(isinstance(refs,dict)and set(refs)==set(POINTER_ACTIONS),"All five required actual pointer action files missing")
    require(all(isinstance(ref,str)for ref in refs.values())and len(set(refs.values()))==5,"Pointer action files reused")
    session=operand.get("gui_session",{})
    require(session==host.get("gui_session")and session.get("runtime_instance_id")==host["id"]and
        session.get("platform")==host["platform"]and session.get("architecture")==host["architecture"]
        and isinstance(session.get("boot_id"),str)and session["boot_id"]and isinstance(session.get("id"),str)and session["id"],"Actual current graphical boot/session identity missing")
    display=session.get("display",{})
    require(display.get("id")and all(type(display.get(k))is int and 0<display[k]<=8192 for k in ("width","height"))
            and gui_number(display.get("scale"))and 0<display["scale"]<=4
            and all(gui_number(display.get(k))for k in("coordinate_width","coordinate_height","origin_x","origin_y"))
            and display["coordinate_width"]>0 and display["coordinate_height"]>0
            and display["width"]==round(display["coordinate_width"]*display["scale"])
            and display["height"]==round(display["coordinate_height"]*display["scale"]),"Measured actual display pixel/coordinate geometry/scale missing")
    require(display.get("coordinate_space")==("logical-points"if session["platform"]=="darwin"else"physical-pixels")
        and(session["platform"]=="darwin"or(display["scale"]==1 and display["origin_x"]==display["origin_y"]==0)),"Actual native coordinate space differs")
    sender=operand.get("gui_sender",{});sender_bytes=pinned(sender)
    observer=operand.get("gui_observer",{});observer_bytes=pinned(observer)
    retained_sender,_=pointer_file(files,receipt.get("gui_sender_ref"),"pointer-sender-source",operand,8*1024**2)
    retained_observer,_=pointer_file(files,receipt.get("gui_observer_ref"),"gui-observer-source",operand,8*1024**2)
    require(retained_sender["sha256"]==sender["sha256"]and retained_sender["bytes"]==len(sender_bytes)
        and retained_observer["sha256"]==observer["sha256"]and retained_observer["bytes"]==len(observer_bytes),"Actual sender/observer source bytes not retained")
    if session["platform"]=="windows":
        converter_bytes=pinned(operand["gui_converter"])
        retained_converter,_=pointer_file(files,receipt.get("gui_converter_ref"),"gui-converter-source",operand,8*1024**2)
        require(retained_converter["sha256"]==operand["gui_converter"]["sha256"]and retained_converter["bytes"]==len(converter_bytes),"Actual converter source not retained")
    executable=expected_executable or operand.get("gui_executable")
    _EXECUTABLES["descriptor"](executable,plan["source_commit"])
    require(executable["package_sha256"]==operand["package_sha256"]and executable["platform"]=={"windows":"windows","linux":"ubuntu","darwin":"macos"}[session["platform"]],"Pointer executable descriptor/package/platform differs")
    controls=operand.get("gui_controls",{})
    require(isinstance(controls,dict)and set(controls)==set(POINTER_ACTIONS),"Exact current-source native control map missing")
    identity={"source_commit":plan["source_commit"],"run_id":plan.get("run_id"),"attempt":plan.get("attempt"),
        "operation_nonce":plan["nonce"],"inventory_vm_id":operand["inventory_vm_id"],"runtime_instance_id":operand["runtime_instance_id"],
        "queue_job_ids":operand["job_ids"],"original_source":operand["original_source"],"executable":executable}
    require(all(isinstance(identity.get(k),str)and identity[k]for k in ("run_id","attempt")),"Current pointer run/attempt missing")
    used=set();seen_ids=set();clock=None;last_tick=-1;actions=[]
    for sequence,action in enumerate(POINTER_ACTIONS,1):
        row,pin=pointer_json(files,refs[action],"pointer-action",operand)
        require(type(row.get("schema"))is int and row.get("schema")==1 and row.get("kind")=="OPEMOS_NATIVE_POINTER_ACTION"and row.get("action")==action
            and type(row.get("sequence"))is int and row.get("sequence")==sequence and row.get("identity")==identity and row.get("session")==session,
            "Actual action/source/run/attempt/nonce/package/session identity differs")
        require(row.get("button")=="left"and type(row.get("click_count"))is int and row["click_count"]==1,"Actual single left-click count missing")
        context=row.get("source_context",{})
        require(isinstance(context,dict)and all(context.get(k)==row.get(k)for k in
            ("action","action_id","sequence","identity","session","app","target","point","clock","before","transition_ref","sender_lifecycle_ref","target_observation_ref")),
            "Actual complete source context missing/mismatched; unknown context fields must remain retained")
        action_id=row.get("action_id","");require(re.fullmatch(r"[0-9a-f]{32}",action_id or"")and action_id not in seen_ids,"Replayed/unknown actual action ID")
        seen_ids.add(action_id)
        ownclock=row.get("clock",{})
        require(set(ownclock)=={"domain","id"}and ownclock.get("domain")=="monotonic-ns"and ownclock.get("id"),"Declared sender clock domain missing")
        if clock is None:clock=ownclock
        require(ownclock==clock==operand.get("gui_clock"),"No cross-clock ordering assumption or unadmitted clock ID permitted")
        app=row.get("app",{});target=row.get("target",{});point=row.get("point",{})
        require(app.get("process")==host["app_process"]and app.get("executable_sha256")==executable["executable_sha256"]
            and app.get("root_window_id")==host["app_window_id"]and app.get("window_id")and app.get("window_title")
            and gui_rect(app.get("window_rect"),display),"Actual app birth/executable/root/target window differs")
        require(target.get("control_id")==controls[action].get("control_id")and target.get("role")==controls[action].get("role")and bool(target.get("role")),"Pointer aimed at another current-source control")
        require(target.get("app_process")==app["process"]and target.get("window_id")==app["window_id"]
            and target.get("visible")is True and target.get("enabled")is True and target.get("control_id")
            and gui_rect(target.get("rect"),display)and gui_number(point.get("x"))and gui_number(point.get("y"))
            and(session["platform"]=="darwin"or(type(point["x"])is int and type(point["y"])is int)),
            "Actual enabled/visible same-app/window control geometry missing")
        target_observation,obp=pointer_json(files,row.get("target_observation_ref"),"gui-observation",operand)
        require(target_observation.get("schema")==1 and target_observation.get("identity")==identity
            and target_observation.get("session")==session and target_observation.get("app")==app and target_observation.get("target")==target
            and target_observation.get("observer_source_sha256")==observer["sha256"]
            and target_observation.get("app_birth_rechecked")is True and target_observation.get("before_frame_ref")==row.get("before",{}).get("ref")
            and target_observation.get("capture_id")==row.get("before",{}).get("capture_id")
            and target_observation.get("delivery_clock")==ownclock and type(target_observation.get("delivered_tick"))is int
            and target_observation.get("method")in("native-readonly","frame-review+native-process-birth"),"Actual measured target/app/frame observer bytes missing")
        rect=target["rect"];window=app["window_rect"]
        require(window["x"]<=rect["x"]and window["y"]<=rect["y"]and rect["x"]+rect["width"]<=window["x"]+window["width"]
            and rect["y"]+rect["height"]<=window["y"]+window["height"],"Control outside actual owned window")
        require(rect["x"]<=point["x"]<rect["x"]+rect["width"]and rect["y"]<=point["y"]<rect["y"]+rect["height"],"Pointer outside actual control")
        require(target.get("hit_observation")in("native-same-control-unoccluded","same-console-frame-review")
            and(session["platform"]!="darwin"or target["hit_observation"]=="native-same-control-unoccluded"),"Native hit/occlusion observation missing")
        life,life_pin=pointer_json(files,row.get("sender_lifecycle_ref"),"pointer-sender-lifecycle",operand)
        sender_birth=row.get("sender",{})
        require(sender_birth.get("source_sha256")==sender["sha256"]and process_identity(sender_birth.get("process"))
            and sender_birth.get("host_boot_id")==ownclock["id"]and life.get("sender")==sender_birth
            and life.get("action_id")==action_id and type(life.get("numeric_exit"))is int and life["numeric_exit"]==0
            and life.get("deadline_expired")is False and all(life.get(k)is True for k in("waited","stdout_EOF","stderr_EOF","pipes_closed","original_gone")),"Actual sender birth/numeric/EOF/closure missing")
        if session['platform']in('windows','linux'):
            validate_pointer_destination(row,identity,session,app,ownclock,files,operand)
            validate_pointer_raw(row,life,life_pin,pin,files,operand,session)
        before=row.get("before",{});require(before.get("clock")==clock and type(before.get("tick"))is int and before["tick"]>last_tick,"Stale/cross-action before capture")
        first=gui_frame(files,before,operand,session,used)
        if session['platform']in('windows','linux'):
            require(context.get('before_path')==files[before['ref']]['path']and context.get('before_sha256')==files[before['ref']]['sha256']
                and context.get('before_capture_path')==files[before['capture_ref']]['path']and context.get('before_capture_sha256')==files[before['capture_ref']]['sha256'],
                'Actual operation/context before acquisition and bytes differ')
        phases=row.get("phases",[]);require(isinstance(phases,list)and len(phases)==3 and [x.get("phase")for x in phases]==["move","down","up"],"Actual move/down/up phases missing/out of order")
        require(before["tick"]<=target_observation["delivered_tick"]<=phases[0].get("sent_tick",-1),"Stale actual target observation delivery")
        previous=before["tick"]
        for phase in phases:
            require(phase.get("clock")==clock and type(phase.get("sent_tick"))is int and type(phase.get("returned_tick"))is int
                and previous<=phase["sent_tick"]<=phase["returned_tick"],"Actual phase sender ordering/clock differs")
            previous=phase["returned_tick"]
        if session["platform"]in("windows","linux"):
            require(row.get("backend")=="QMP","Required QMP native sender missing")
            ids=set();last_id=0
            for index,phase in enumerate(phases):
                request,response=phase.get("request",{}),phase.get("response",{})
                require(type(request.get("id"))is int and request["id"]>0 and request["id"]not in ids and request["id"]>last_id and type(response.get("id"))is int and response.get("id")==request["id"]
                    and response.get("return")=={} and"error"not in response and request.get("execute")=="input-send-event","Actual matching successful QMP request/reply missing")
                ids.add(request["id"]);last_id=request["id"]
                events=request.get("arguments",{}).get("events")
                expected=([{"type":"abs","data":{"axis":"x","value":round(point["x"]*32767/(display["width"]-1))}},
                           {"type":"abs","data":{"axis":"y","value":round(point["y"]*32767/(display["height"]-1))}}]if index==0 else
                          [{"type":"btn","data":{"button":"left","down":index==1}}])
                require(events==expected,"Keyboard/AX/DOM/wrong pointer bytes cannot satisfy required click")
                require(all(type(event["data"]["value"])is int for event in events)if index==0 else type(events[0]["data"]["down"])is bool,
                    "Actual QMP pointer numeric/button JSON types differ")
        else:
            require(row.get("backend")=="CGEvent"and row.get("delivery_ack")=="UNAVAILABLE:CGEvent.post",
                    "CGEvent has no delivery ACK; do not fabricate one")
            for index,phase in enumerate(phases):
                require(phase.get("event_type")==("mouseMoved","leftMouseDown","leftMouseUp")[index]
                    and phase.get("posted")is True and phase.get("button")=="left"and phase.get("click_count")==1,
                    "Actual CGEvent post phases missing")
            require(row.get("observed_pointer")==point,"Actual macOS pointer movement observation missing")
        transition,tp=pointer_json(files,row.get("transition_ref"),"pointer-transition",operand)
        require(not life.get("first_failure")and not life.get("secondary_errors")and row.get("status")=="sent"and transition.get("status")=="observed"and transition.get("action_id")==action_id
            and transition.get("identity")==identity and transition.get("session")==session
            and transition.get("app_process")==app["process"],"Failed/UNKNOWN action or foreign observed transition")
        after=transition.get("after",{});require(after.get("clock")==clock and type(after.get("tick"))is int and after["tick"]>=previous,"Missing actual ordered after acquisition")
        second=gui_frame(files,after,operand,session,used)
        require(transition.get("delivery_clock")==clock and type(transition.get("delivered_tick"))is int
            and transition["delivered_tick"]>=after["tick"],"Actual after observation delivery clock/order missing")
        last_tick=transition["delivered_tick"]
        observation=transition.get("observation",{})
        require((observation.get("before_state"),observation.get("after_state"))==POINTER_TRANSITIONS[action]
            and observation.get("before_frame_ref")==before["ref"]and observation.get("after_frame_ref")==after["ref"]
            and observation.get("window_owner_process")==app["process"]and observation.get("actual_observation")is True,
            "Action-specific native/console observed state transition missing")
        if action in("chooser-confirm-exact-input","Build"):
            require(observation.get("input_sha256")==operand["input_sha256"]and observation.get("input_path")==operand.get("gui_input_path")
                and isinstance(observation.get("input_path"),str)and observation["input_path"],"Exact selected original input pin/path missing")
        if action=="Build":require(observation.get("planned_output")==operand.get("gui_output_path")and bool(observation.get("planned_output")),"Actual planned output differs")
        if action.startswith("virtualUSB"):
            usb=receipt["roles"]["virtual_usb"]
            require(all(observation.get(k)==usb.get(v)and observation.get(k)for k,v in
                (("usb_id","id"),("usb_backing_identity","backing_identity"),("usb_device_identity","device_identity")))
                and observation.get("output_image_sha256")==receipt["output"]["sha256"],"Actual GUI selected/reviewed Write source/backing/device differs")
        actions.append({"action":action,"action_id":action_id,"record_sha256":pin["sha256"],"transition_sha256":tp["sha256"],
            "sender_lifecycle_sha256":life_pin["sha256"],"target_observation_sha256":obp["sha256"],"before":first,"after":second})
    proof={"schema":1,"verified":True,**identity,"sender_sha256":sender["sha256"],"actions":actions}
    proof["proof_sha256"]=_EXECUTABLES["digest"](proof)
    return proof


def validate_receipt(receipt, case, plan, operand):
    if case == "nested-ubuntu-linux":
        return validate_nested_receipt(receipt, plan, operand)
    require(receipt.get("status") == "passed", "Case did not pass")
    for key, value in {"case": case, "source_commit": plan["source_commit"], "nonce": plan["nonce"],
                       "package_sha256": operand["package_sha256"], "input_sha256": operand["input_sha256"],
                       "queue_job_ids": operand["job_ids"]}.items():
        require(receipt.get(key) == value, f"Case {key} identity mismatch")
    require(receipt.get("physical_usb_written") is False, "No physical USB action is admitted by this pipeline")
    if case != "steamos-autoheal":
        require(receipt.get("gpu_claim") is False and operand.get("hardware_scope") == "virtual-only",
                "Host imaging case must remain virtual-only")
    require(set(receipt.get("closure", {})) == {"processes_gone", "pool_released", "queue_released"} and
            all(value is True for value in receipt["closure"].values()),
            "Case closure is absent/unknown")
    require(receipt.get("inventory_vm_id") == operand["inventory_vm_id"] and
            receipt.get("runtime_instance_id") == operand["runtime_instance_id"], "Exact inventory/runtime instance mismatch")
    roles = validate_roles(receipt, case, plan, operand)
    if case == "macos-full-stack":
        host = roles["imaging_host"]
        require(host.get("apple_hardware") is True and receipt.get("apple_admission_sha256") == operand.get("apple_admission_sha256")
                and SHA.fullmatch(receipt.get("apple_admission_sha256", "")), "Actual admitted Apple Silicon imaging host missing")
    elif case != "steamos-autoheal":
        require(roles["imaging_host"].get("location") == "omen-vm", "Windows/Ubuntu imaging hosts must be OMEN VMs")
    else:
        kernels = operand.get("kernels", [])
        require(len(kernels) >= 2 and len(set(kernels)) == len(kernels) and receipt.get("kernels") == kernels and
                receipt.get("driver_version") == operand.get("driver_version") and bool(operand.get("driver_version")),
                "Exact same-SteamOS-target old/new kernel and driver identities missing")
    if case == "steamos-autoheal":
        validate_gpu(receipt, operand)
    else:
        validate_wrong_marker(receipt, plan, operand)
    required = HEAL_CHECKS if case == "steamos-autoheal" else BUILD_CHECKS
    files = receipt.get("files", {})
    checks = receipt.get("checks", {})
    require(isinstance(files, dict) and 1 <= len(files) <= 128, "Actual bounded case evidence files missing")
    for item in files.values():
        require(isinstance(item, dict) and SHA.fullmatch(item.get("sha256", "")) and
                pointer_evidence_size(item) and
                Path(item.get("path", "")).is_absolute(), "Evidence file identity/size missing")
    for name in required:
        check = checks.get(name, {})
        refs = check.get("evidence", [])
        require(check.get("passed") is True and refs and all(r in files for r in refs), f"Missing/failed actual check: {name}")
        require(EVIDENCE_KINDS[name] <= {files[r].get("kind") for r in refs},
                f"Actual evidence kind missing for {name}")
    require(receipt.get("gui_input_method") == "pointer" and receipt.get("display_session") in
            {"real-guest-console", "apple-silicon-session"}, "Real graphical pointer/session evidence required")
    require(any(f.get("kind") == "screenshot" for f in files.values()), "Real graphical screenshots missing")
    require(checks["abrupt_power_recovery"].get("method") == "vm-power-off-and-restart", "Abrupt VM power recovery was not performed")
    if case!="steamos-autoheal":
        proof=validate_gui_pointer(receipt,plan,operand)
        groups={"graphical_chooser":POINTER_ACTIONS[:2],"graphical_build":("Build",),"virtual_usb_write":POINTER_ACTIONS[3:]}
        for check,actions in groups.items():
            require(all(receipt["pointer_actions"][action]in checks[check]["evidence"]for action in actions),"Actual check is not bound to its exact pointer actions")
    return files


def verify_uploaded_package(item, executable):
    """Same held archive FD supplies SHA and actual packaged member bytes."""
    path = Path(item["path"])
    require(path.is_absolute() and str(path.resolve()) == str(path) and
            item.get("sha256") == executable["artifact_archive_sha256"] and type(item.get("size")) is int
            and 0 < item["size"] <= 60_000_000_000, "Exact producer archive input missing")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                and before.st_size == item["size"], "Producer archive descriptor differs")
        digest = hashlib.sha256()
        while block := os.read(fd, 1024**2): digest.update(block)
        require(digest.hexdigest() == item["sha256"], "Actual downloaded producer archive SHA differs")
        os.lseek(fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(fd), "rb") as stream, zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
            require(len(members) <= 100000, "Bounded executable archive metadata required")
            found = [x for x in members if x.filename == executable["package_name"]]
            require(len(found) == 1 and found[0].file_size == executable["package_bytes"]
                    and not stat.S_ISLNK(found[0].external_attr >> 16) and not found[0].flag_bits & 1,
                    "Actual uploaded package entry missing/aliased/encrypted")
            digest, count = hashlib.sha256(), 0
            with archive.open(found[0]) as package:
                while block := package.read(1024**2):
                    count += len(block)
                    require(count <= executable["package_bytes"], "Packaged member overflow")
                    digest.update(block)
            require(count == executable["package_bytes"] and digest.hexdigest() == executable["package_sha256"],
                    "Producer archive contains a different executable package")
        require(_READER.identity(before) == _READER.identity(os.fstat(fd)) == _READER.identity(os.lstat(path)),
                "Held producer archive changed during member verification")
    finally:
        os.close(fd)


def verify_macos_binary(item, executable):
    if executable["platform"] != "macos":
        require(executable["package_sha256"] == executable["executable_sha256"] and
                executable["package_bytes"] == executable["executable_bytes"], "Windows/AppImage package must be the exact application executable")
        return
    fd = os.open(item["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                and before.st_size == executable["package_bytes"], "Native Mac package descriptor differs")
        digest = hashlib.sha256()
        while block := os.read(fd, 1024**2):digest.update(block)
        require(digest.hexdigest() == executable["package_sha256"], "Native app package SHA differs")
        os.lseek(fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(fd), "rb") as stream, zipfile.ZipFile(stream) as package:
            members = package.infolist()
            require(len(members) <= 100000, "Bounded native Mac app metadata required")
            matches = [x for x in members if x.filename.endswith(".app/Contents/MacOS/" + executable["executable_name"])]
            require(len(matches) == 1 and matches[0].file_size == executable["executable_bytes"]
                    and not stat.S_ISLNK(matches[0].external_attr >> 16) and not matches[0].flag_bits & 1,
                    "Exact native application executable is missing/aliased/encrypted")
            digest = hashlib.sha256()
            with package.open(matches[0]) as stream:
                count = 0
                while block := stream.read(1024**2):
                    count += len(block);require(count <= executable["executable_bytes"], "Mac executable member overflow")
                    digest.update(block)
            require(count == executable["executable_bytes"] and digest.hexdigest() == executable["executable_sha256"], "Native executable differs from producer SHA")
        require(_READER.identity(before) == _READER.identity(os.fstat(fd)) == _READER.identity(os.lstat(item["path"])),
                "Native package full9 descriptor/path drift")
    finally:os.close(fd)


def validate_executable_output(build, expected, context=None):
    output, files, usb = build["output"], build["files"], build["roles"]["virtual_usb"]
    images = [x for x in files.values() if x.get("kind") == "output-image" and x.get("sha256") == output["sha256"]]
    manifests = [x for x in files.values() if x.get("kind") == "output-manifest" and x.get("sha256") == output["manifest_sha256"]]
    require(len(images) == len(manifests) == 1 and type(images[0].get("size")) is int and images[0]["size"] > 0,
            "One actual completed image and adjacent build manifest required")
    if "imageArtifactRange" in images[0]:
        observed = artifact_read(images[0], 60_000_000_000, context=context)
        require(observed["originalManifest"] == manifests[0], "Range must retain the exact original raw manifest pin")
        original, raw = _READER.read_verified(manifests[0]["path"], 8 * 1024**2,
            expected_sha=manifests[0]["sha256"], expected_size=manifests[0]["size"], uid=manifests[0].get("uid", os.getuid()))
        require(original["identity"] == manifests[0]["identity"], "Original raw manifest full9 differs")
        require(raw == observed["originalManifestRaw"], "Parsed/reserialized manifest is not original guest bytes")
        manifest = strict_json(raw)
    else:
        manifest = strict_json(pinned(manifests[0], 8 * 1024**2))
    require(manifest.get("schemaVersion") == 1 and manifest.get("resultClass") == "nvidia-mutation-valid"
            and manifest.get("input", {}).get("sourceSha256") == output["input_sha256"]
            and manifest.get("output", {}).get("format") == "raw"
            and manifest.get("output", {}).get("sha256") == output["sha256"]
            and manifest.get("output", {}).get("bytes") == images[0]["size"]
            and manifest.get("steamos", {}).get("architecture") == "x86_64"
            and manifest.get("steamos", {}).get("layoutScheme") == "valve-recovery-a"
            and manifest.get("integration", {}).get("milestone") == "nvidia-offline-installed",
            "Actual normal producer image manifest/output/source identity differs")
    nvidia, validation = manifest["integration"].get("nvidia", {}), manifest.get("validation", {})
    require(all(nvidia.get(k) == v for k,v in {"status":"success", "phase":"complete", "reason":"install_complete",
                "mountsReleased":True, "compressionPolicyRestored":True}.items())
            and all(validation.get(k) is True for k in ("passed", "sourceUnchanged", "candidateAttachedReadOnly", "layoutRecognized",
                "markerVerified", "nvidiaPayloadVerified", "recoveryRollbackVerified", "installationMediaWelcomeVerified",
                "installedRecoveryGuardianPayloadVerified")), "Marker-only/incomplete image is not SteamOS output acceptance")
    inspected = build.get("completed_image_inspection", {})
    require(inspected.get("normal_command") == "inspect_completed_nvidia_image" and inspected.get("passed") is True
            and inspected.get("package_sha256") == expected["package_sha256"]
            and inspected.get("image_sha256") == output["sha256"] and inspected.get("manifest_sha256") == output["manifest_sha256"]
            and inspected.get("welcome_revision") == validation.get("installationMediaWelcomeRevision")
            and isinstance(inspected.get("welcome_revision"), str) and inspected["welcome_revision"]
            and files.get(inspected.get("evidence"), {}).get("kind") == "completed-image-inspection",
            "Existing normal app completed-image consumer/current welcome revision proof missing")
    size = images[0]["size"]
    require(usb.get("bytes") == size and usb.get("written_bytes") == size and usb.get("readback_bytes") == size
            and type(usb.get("capacity_bytes")) is int and usb["capacity_bytes"] >= size
            and usb.get("flushed") is True and usb.get("full_readback") is True,
            "Every executable needs full image bytes written, flushed and read back from its owned virtual USB")


def executable_protected_jobs(plan):
    """Retention protects all declared ordinary operations, even failed receipt checks."""
    result = []
    entries = plan.get("executable_acceptance", {})
    require(isinstance(entries, dict) and len(entries) <= 16, "Bounded executable operation set required")
    for entry in entries.values():
        if entry is None: continue
        require(isinstance(entry, dict), "Invalid executable acceptance operand")
        for role in ("build_operand", "heal_operand"):
            operand = entry.get(role, {})
            ids = operand.get("job_ids", [])
            require(isinstance(ids, list) and len(ids) <= 16 and all(isinstance(j, str) and
                    re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", j) for j in ids), "Exact bounded ordinary job IDs needed for retention")
            result.extend(ids)
    require(len(result) == len(set(result)), "One ordinary job cannot cover two executable operations")
    return result


def executable_job_origin(operand, rows, proofs, started):
    """Join only exact ordinary admitted current-run owner jobs; never launch."""
    admission = load_pinned(operand["runtime_admission"])
    require(isinstance(admission, dict), "Existing normal runtime admission missing")
    manifest = absolute_manifest(load_pinned(operand["manifest"]))
    require([job["id"] for job in manifest["jobs"]] == operand["job_ids"] and len(operand["job_ids"]) <= 16,
            "Exact ordinary executable operation manifest/job IDs differ")
    require(set(proofs) == set(operand["job_ids"]), "Exact ordinary queue proof pins required")
    for job in manifest["jobs"]:
        require(all(job.get("approval", {}).get(k) == operand["runtime_admission"].get(k) for k in ("path", "sha256")),
                "Executable operation approval differs from its normal manifest")
        proof = load_pinned(proofs[job["id"]])
        live = rows.get(job["id"], {})
        require(proof.get("id") == job["id"] and proof.get("state") == live.get("state") == "passed"
                and proof.get("unit") == live.get("unit") and proof.get("result", {}).get("InvocationID")
                == live.get("result", {}).get("InvocationID") and proof.get("result", {}).get("InvocationID")
                and type(proof.get("started")) in (int, float) and started <= proof["started"]
                <= proof.get("finished", -1) <= time.time(), "Old/foreign/nonterminal ordinary job cannot cover an executable")
        lifecycle = proof.get("result", {}).get("terminalLifecycle", {})
        closure, pool = lifecycle.get("postStopCgroupProof", {}), lifecycle.get("postStopPoolProof", {})
        require(lifecycle.get("phase") == "CLOSED" and closure.get("completeTraversal") is True
                and closure.get("includesUID0") is True and closure.get("empty") is True
                and closure.get("processes") == [] and pool.get("admitted") is True
                and pool.get("allOwnedDescriptorsClosed") is True, "Executable operation normal job closure unknown")
    return manifest


def verify_original_operand(operand,cap,context=None):
    original=operand.get("original_source",{})
    require(_INVENTORY["original_source_valid"](original),"Exact retained original source pin required")
    for item in operand.get("inputs",[]):
        if "imageArtifactRange" in item:
            observed = artifact_read(item, cap, context=context)
            if observed["backing"] == original:return
        if item.get("sha256")==original["sha256"]and item.get("size")==original["size"]:
            observed=artifact_read(item,cap)
            if {k:observed[k]for k in ("sha256","size","identity")}==original:return
    raise ValueError("Retained original source pin has no matching actual full9 input")


def validate_executable_transaction(value, expected, entry, plan, request, rows):
    _EXECUTABLES["descriptor"](expected, request["source_commit"])
    nonce = entry.get("operation_nonce")
    require(re.fullmatch(r"[0-9a-f]{32}", nonce or "") and value.get("operation_nonce") == nonce
            and value.get("executable") == expected and value.get("source_commit") == request["source_commit"]
            and value.get("run_id") == request["run_id"] and value.get("attempt") == request["attempt"],
            "Exact executable/source/current acceptance run/attempt/operation identity differs")
    build_operand, heal_operand = entry["build_operand"], entry["heal_operand"]
    range_context = image_range_context(request, nonce, expected, build_operand["job_ids"] + heal_operand["job_ids"])
    verify_original_operand(build_operand,60_000_000_000,range_context)
    verify_original_operand(heal_operand,60_000_000_000,range_context)
    require(build_operand.get("package_sha256") == expected["package_sha256"]
            and build_operand.get("subject_role") == "imaging_host"
            and heal_operand.get("subject_role") == "steamos_target", "Exact artifact must be consumed by its genuine platform imaging host")
    build_jobs, heal_jobs = build_operand["job_ids"], heal_operand["job_ids"]
    require(build_jobs and heal_jobs and not set(build_jobs) & set(heal_jobs), "Build and NVIDIA/recovery need distinct ordinary jobs")
    executable_job_origin(build_operand, rows, value["build_queue_proofs"], request["consumer_started_epoch"])
    heal_manifest = executable_job_origin(heal_operand, rows, value["heal_queue_proofs"], request["consumer_started_epoch"])
    load_pinned(heal_operand["gpu_admission"])
    gpu_jobs = [job for job in heal_manifest["jobs"] if "libvirt_domain" in job and "omen-iommu-group-1" in job.get("resources", [])]
    require(len(gpu_jobs) == 1 and gpu_jobs[0]["libvirt_domain"]["leaseNonce"] == heal_operand.get("lease_nonce")
            and all(gpu_jobs[0].get("approval", {}).get(k) == heal_operand["gpu_admission"].get(k) for k in ("path", "sha256")),
            "Existing independently admitted exact NVIDIA lease required for this executable target")
    local_plan = {**plan, "nonce": nonce, "run_id": request["run_id"], "attempt": request["attempt"]}
    build = load_pinned(value["build_receipt"])
    heal = load_pinned(value["heal_receipt"])
    require(all(receipt.get(k) == request[k] for receipt in (build, heal) for k in ("run_id", "attempt")),
            "Build/NVIDIA receipt belongs to an old consumer run or attempt")
    build_operand={**build_operand,"gui_executable":expected,"evidence_roots":entry["evidence_roots"]}
    build_files = validate_receipt(build, _EXECUTABLES["PRODUCERS"][expected["platform"]]["case"], local_plan, build_operand)
    require(heal_operand.get("input_sha256") == build["output"]["sha256"], "NVIDIA/recovery input must be this exact actual GUI image output")
    heal_files = validate_receipt(heal, "steamos-autoheal", local_plan, heal_operand)
    pointer_proof=validate_gui_pointer(build,local_plan,build_operand,expected)
    validate_executable_output(build, expected, range_context)
    target, healed = build["roles"]["steamos_target"], heal["roles"]["steamos_target"]
    require(all(target.get(k) == healed.get(k) for k in ("id", "disk_identity", "baseline_boot_id", "normal_boot_id", "abrupt_boot_id"))
            and target["id"] != build["roles"]["imaging_host"]["id"] and target["id"] != build["roles"]["fedora_appliance"]["id"],
            "Each executable needs the same actual separately installed SteamOS target through NVIDIA recovery")
    install = load_pinned(value["install_receipt"])
    required = {"kind": "OPEMOS_VIRTUAL_STEAMOS_INSTALL_V1", "source_commit": request["source_commit"],
        "run_id": request["run_id"], "attempt": request["attempt"], "operation_nonce": nonce,
        "executable_package_sha256": expected["package_sha256"], "output_image_sha256": build["output"]["sha256"],
        "virtual_usb_id": build["roles"]["virtual_usb"]["id"], "usb_readback_sha256": build["output"]["sha256"],
        "target_id": target["id"], "target_disk_identity": target["disk_identity"], "baseline_boot_id": target["baseline_boot_id"],
        "architecture": "x86_64", "platform": "steamos", "physical_media": False, "source_preserved": True,
        "installed_image_verified": True, "install_exit": 0, "method": "installation-media-welcome"}
    require(all(install.get(k) == v for k, v in required.items()) and type(install.get("install_exit")) is int
            and all(install.get(k) is True for k in ("source_preserved", "installed_image_verified"))
            and install.get("physical_media") is False and install.get("installed_root_uuid") and install.get("installed_efi_uuid")
            and all(isinstance(install.get(k), str) and 0 < len(install[k]) <= 256 for k in
                    ("target_generation", "output_identity", "installed_root_uuid", "installed_efi_uuid")),
            "Actual virtual SteamOS install/boot/output/disk generation proof missing for this executable")
    install_files = install.get("files", {})
    require({"install-log", "boot-log", "screenshot"} <= {x.get("kind") for x in install_files.values()},
            "Real install log, graphical boot and screenshot evidence required")
    archive, package, binary = value["archive_pin"], value["package_pin"], value["executable_pin"]
    verify_uploaded_package(archive, expected)
    require(package.get("sha256") == expected["package_sha256"] and package.get("size") == expected["package_bytes"]
            and binary.get("sha256") == expected["executable_sha256"] and binary.get("size") == expected["executable_bytes"],
            "Installed executable/package byte identities differ from actual producer")
    verify_macos_binary(package, expected)
    files = {"producer-archive": archive, "producer-package": package, "producer-executable": binary}
    for prefix, group in (("build", build_files), ("heal", heal_files), ("install", install_files)):
        for name, item in group.items():
            require(SHA.fullmatch(item.get("sha256", "")) and pointer_evidence_size(item)
                    and Path(item.get("path", "")).is_absolute(), "Actual executable transaction evidence pin missing")
            files[prefix + ":" + name] = item
    return {"status": "passed", "executable": expected, "source_commit": request["source_commit"],
            "run_id": request["run_id"], "attempt": request["attempt"], "operation_nonce": nonce,
            "actual_receipt_verified": True, "active": False, "job_ids": build_jobs + heal_jobs,
            "pointer_acceptance":pointer_proof,
            "build_receipt_sha256": value["build_receipt"]["sha256"], "heal_receipt_sha256": value["heal_receipt"]["sha256"],
            "install_receipt_sha256": value["install_receipt"]["sha256"], "output_identity": str(install["output_identity"]),
            "target_generation": str(install["target_generation"]), "image_sha256": build["output"]["sha256"],
            "image_manifest_sha256": build["output"]["manifest_sha256"], "usb_readback_sha256": build["roles"]["virtual_usb"]["readback_sha256"],
            "target_id": target["id"], "target_disk_identity": target["disk_identity"], "baseline_boot_id":target["baseline_boot_id"],
            "installed_root_uuid":install["installed_root_uuid"], "installed_efi_uuid":install["installed_efi_uuid"],
            "imaging_host_id":build["roles"]["imaging_host"]["id"],
            "reason": "Distinct actual GUI image/manifest, complete virtualUSB, installed SteamOS target and same-target NVIDIA/kernel/recovery proof"}, files


def executable_outcomes(config, request, plan, rows, artifacts, budget):
    expected = _EXECUTABLES["validate_expected"](plan.get("expected_executables"), request["source_commit"])
    require(_EXECUTABLES["digest"](expected) == request["executables_sha256"], "Expected producer artifact set changed")
    entries = plan.get("executable_acceptance", {})
    require(isinstance(entries, dict) and set(entries) <= set(expected), "Unknown/aliased executable acceptance plan entry")
    result, owned_jobs = {}, set()
    for name, executable in expected.items():
        entry = entries.get(name)
        try:
            require(isinstance(entry, dict), "Missing exact independently admitted executable image/USB/install/NVIDIA transaction")
            value, receipt_sha = load_result(entry["receipt_path"])
            outcome, files = validate_executable_transaction(value, executable, entry, plan, request, rows)
            require(not owned_jobs & set(outcome["job_ids"]), "One old/shared job cannot cover another executable artifact")
            owned_jobs.update(outcome["job_ids"])
            roots = [Path(x) for x in entry["evidence_roots"]]
            require(roots and all(x.is_absolute() for x in roots), "Exact ordinary executable evidence roots required")
            for evidence_root in roots: real_dir(evidence_root)
            for item in files.values():
                require(any(Path(item["path"]).is_relative_to(root) for root in roots), "Executable evidence escaped reviewed operation roots")
                if item.get("kind") == "screenshot":
                    require(artifact_read(item, config["max_run_bytes"])["prefix"] == b"\x89PNG\r\n\x1a\n", "Actual graphical PNG proof missing")
                target = artifacts / item["sha256"]
                range_context = image_range_context(request, entry["operation_nonce"], executable, outcome["job_ids"])
                charged,observed=retain_pin(item,target,budget,config["max_run_bytes"],context=range_context)
                budget-=charged
                if item.get("kind") == "output-image":
                    actual_output_identity = _EXECUTABLES["digest"]({"imaging_host_id":outcome["imaging_host_id"],
                        "descriptor_identity":observed["identity"]})
                    require(outcome["output_identity"] == actual_output_identity,
                            "Install output identity differs from the exact held image descriptor")
            actual_generation = _EXECUTABLES["digest"]({k:outcome[k] for k in
                ("target_id", "target_disk_identity", "baseline_boot_id", "installed_root_uuid", "installed_efi_uuid", "image_sha256")})
            require(outcome["target_generation"] == actual_generation,
                    "Install target generation differs from actual disk/boot/installed UUID/image identities")
            outcome["receipt_sha256"] = receipt_sha
            result[name] = outcome
        except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile) as error:
            result[name] = {"status":"failed", "executable":executable, "reason":str(error)}
    return _EXECUTABLES["report"](expected, result, request["source_commit"], request["run_id"], request["attempt"]), budget


def image_range_context(request, nonce, executable, job_ids):
    return {"source_commit": request["source_commit"], "run_id": request["run_id"],
            "attempt": request["attempt"], "operation_nonce": nonce,
            "executable": executable, "consumer_job_ids": list(job_ids)}


def operand_image_range_context(operand, plan, request, expected):
    matches = [(name, entry) for name, entry in plan.get("executable_acceptance", {}).items()
               if name in expected and isinstance(entry, dict)
               and operand in (entry.get("build_operand"), entry.get("heal_operand"))]
    require(len(matches) == 1, "Range input must be the exact registered executable operation operand")
    name, entry = matches[0]
    return image_range_context(request, entry["operation_nonce"], expected[name],
        entry["build_operand"]["job_ids"] + entry["heal_operand"]["job_ids"])


def protected_image_range_receipt(item):
    """Only the existing Root-owned /run publication domain may attest a range."""
    path = Path(item["path"])
    require(path.is_absolute() and path.is_relative_to("/run") and ".." not in path.parts
            and len(path.parts) <= 32, "Range authority must be an exact bounded Root /run receipt")
    mounts = [line for line in Path("/proc/self/mountinfo").read_text().splitlines()
              if line.split()[4] == "/run"]
    require(len(mounts) == 1 and " - tmpfs " in mounts[0], "Actual Root /run tmpfs required")
    fds = []
    try:
        fds.append(os.open("/run", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
        for part in path.parts[2:-1]:
            parent = os.fstat(fds[-1])
            require(parent.st_uid == parent.st_gid == 0 and not parent.st_mode & 0o022,
                    "Range authority writable/foreign ancestry")
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fds[-1]))
        parent = os.fstat(fds[-1])
        require(parent.st_uid == parent.st_gid == 0 and not parent.st_mode & 0o022,
                "Range authority parent custody")
        observed, raw = _READER.read_verified(path, 1024**2, expected_sha=item["sha256"],
                                              expected_size=item["size"], uid=0)
        identity = observed["identity"]
        require(all(type(v) is int for v in item["identity"].values())
                and identity == item["identity"] and identity["st_gid"] == 0
                and stat.S_IMODE(identity["st_mode"]) == 0o444
                and identity == _READER.identity(os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)),
                "Exact protected Root range receipt full9/mode")
        return strict_json(raw)
    finally:
        first = sys.exc_info()[1];errors = []
        for fd in reversed(fds):
            try:os.close(fd)
            except BaseException as error:errors.append(repr(error))
        if errors:
            if first is not None:first.add_note("Independent range authority descriptor closure UNKNOWN: " + repr(errors))
            else:raise ValueError("Range authority descriptor closure UNKNOWN: " + repr(errors))


def artifact_image_range(item, cap, context):
    """Read one attested stopped virtual-USB prefix AND its entire backing.

    Not an arbitrary offset broker. The backing remains one immutable media
    inode, never relabeled as an image-sized whole file or copied implicitly.
    """
    require(context is not None and item.get("kind") == "output-image",
            "Range requires the current executable operation context")
    extent = item["imageArtifactRange"]
    require(set(extent) == {"backingFile", "offset", "bytes", "sha256", "tailBytes", "root_final"},
            "Exact stopped virtual-USB extent schema")
    backing = extent["backingFile"]
    require(set(backing) == {"path", "size", "sha256", "identity", "allocatedBytes"}
            and type(cap) is int and cap > 0 and type(item["size"]) is int
            and type(backing["size"]) is int and 0 < item["size"] < backing["size"] <= cap
            and type(extent["offset"]) is int and extent["offset"] == 0 and type(extent["bytes"]) is int
            and extent["bytes"] == item["size"] and extent["sha256"] == item["sha256"]
            and type(extent["tailBytes"]) is int and extent["tailBytes"] == backing["size"] - item["size"]
            and type(backing["allocatedBytes"]) is int and backing["allocatedBytes"] >= 0
            and all(type(v) is int for v in backing["identity"].values())
            and item["path"] == backing["path"]
            and SHA.fullmatch(item["sha256"]) and SHA.fullmatch(backing["sha256"]),
            "Exact prefix/image/backing/tail identities required")
    root = protected_image_range_receipt(extent["root_final"])
    declared = {k:v for k,v in extent.items() if k != "root_final"}
    require(root.get("kind") == "ROOT_VERIFIED_STOPPED_WINDOWS_IMAGE_RANGE_V1"
            and root.get("identity") == context and context["executable"]["platform"] == "windows"
            and root.get("imageArtifactRange") == declared
            and root.get("normalWindowsImageAndVirtualUSB") is True
            and root.get("stoppedFullReadback") is True and root.get("tailZero") is True
            and root.get("retainedForConsumerJobIds") == context["consumer_job_ids"]
            and root.get("completedImagePreserved") is True
            and root.get("originalGuestManifestSHA256") == root.get("originalManifest", {}).get("sha256")
            and SHA.fullmatch(root.get("originalGuestManifestSHA256", "")),
            "Current Root final/readback/retention authority missing")
    encoded = root.get("originalManifestRawBase64")
    require(isinstance(encoded, str) and 0 < len(encoded) <= 87384, "Bounded original raw manifest transfer required")
    manifest_raw = base64.b64decode(encoded, validate=True)
    require(0 < len(manifest_raw) <= 65536 and len(manifest_raw) == root["originalManifest"]["size"]
            and hashlib.sha256(manifest_raw).hexdigest() == root["originalGuestManifestSHA256"],
            "Original manifest raw bytes/guest pin mismatch")
    path = Path(backing["path"])
    require(path.is_absolute() and str(path.resolve()) == str(path), "Range backing canonical path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd);identity = _READER.identity(before)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                and not before.st_mode & 0o022 and identity == backing["identity"]
                and before.st_size == backing["size"]
                and before.st_blocks * 512 == backing["allocatedBytes"], "Range backing FD/full9/allocation guard")
        whole, image, total, prefix = hashlib.sha256(), hashlib.sha256(), 0, b""
        while block := os.read(fd, min(1024**2, backing["size"] + 1 - total)):
            start = total;total += len(block);require(total <= backing["size"], "Range backing overflow")
            whole.update(block);image_part = block[:max(0, min(len(block), item["size"] - start))]
            image.update(image_part);prefix = (prefix + image_part)[:8]
            require(not any(block[len(image_part):]), "Stopped virtual USB nonzero tail")
        require(total == backing["size"] and image.hexdigest() == item["sha256"]
                and whole.hexdigest() == backing["sha256"]
                and identity == _READER.identity(os.fstat(fd)) == _READER.identity(os.lstat(path))
                and before.st_blocks == os.fstat(fd).st_blocks == os.lstat(path).st_blocks,
                "Complete range/backing EOF/hash/full9/allocation drift")
    finally:
        first = sys.exc_info()[1]
        try:os.close(fd)
        except BaseException as error:
            if first is not None:first.add_note("Range backing descriptor closure UNKNOWN: " + repr(error))
            else:raise
    # Recheck protected authority after the complete potentially long read.
    require(protected_image_range_receipt(extent["root_final"]) == root, "Range authority drift")
    typed = {"representation": "root-stopped-virtual-usb-prefix-v1",
             "backing_identity": identity, "backing_sha256": backing["sha256"],
             "offset": 0, "size": item["size"], "sha256": item["sha256"],
             "root_final_sha256": extent["root_final"]["sha256"]}
    return {"size": item["size"], "sha256": image.hexdigest(), "prefix": prefix,
            "identity": typed, "backing": {"size": backing["size"], "sha256": whole.hexdigest(),
                                          "identity": identity},
            "originalManifest": root["originalManifest"], "originalManifestRaw": manifest_raw}

def artifact_read(item, cap, target=None, context=None):
    """Streaming equivalent of canonical full9 custody for large artifacts.

    One source FD supplies hashing/copying. A bounded prefix is retained only
    for typed PNG checks; full code/JSON uses the canonical reader directly.
    """
    if "imageArtifactRange" in item:
        require(target is None, "No implicit large range export; separate whole-budget admission required")
        return artifact_image_range(item, cap, context)
    path = Path(item["path"])
    require(path.is_absolute() and str(path.resolve()) == str(path), "Artifact path guard")
    require(isinstance(item.get("sha256"), str) and SHA.fullmatch(item["sha256"]),
            "Artifact digest must be an exact lowercase SHA256")
    require(type(cap) is int and cap > 0 and pointer_evidence_size(item) and item["size"] <= cap,
            "Explicit artifact cap/size required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    writer = None
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1 and
                not before.st_mode & 0o022 and before.st_size == item["size"], "Artifact FD type/owner/size guard")
        if item.get("_gui_validated_identity")is not None:
            require(_READER.identity(before)==item["_gui_validated_identity"],"Pointer/frame original descriptor differs from validated action bytes")
        if target is not None:
            target = Path(target)
            require(target.is_absolute() and target.name == item["sha256"] and
                    str(target.parent.resolve()) == str(target.parent), "Dedicated digest-named artifact target required")
            real_dir(target.parent)
            writer = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        digest, total, prefix = hashlib.sha256(), 0, b""
        while True:
            block = os.read(fd, min(1024**2, cap + 1 - total))
            if not block:
                break
            total += len(block)
            require(total <= cap, "Artifact overflow sentinel")
            digest.update(block)
            prefix = (prefix + block)[:8]
            if writer is not None:
                view = memoryview(block)
                while view:
                    count = os.write(writer, view)
                    require(count > 0, "Complete artifact copy")
                    view = view[count:]
        require(total == before.st_size and digest.hexdigest() == item["sha256"] and
                _READER.identity(before) == _READER.identity(os.fstat(fd)) == _READER.identity(os.lstat(path)),
                "Artifact full9/path/hash drift")
        if writer is not None:
            os.fsync(writer)
            os.close(writer)
            writer = None
            artifact_read({"path": str(target), "sha256": item["sha256"], "size": total,"kind":item.get("kind")}, cap)
        require(_READER.identity(before) == _READER.identity(os.fstat(fd)) == _READER.identity(os.lstat(path)),
                "Original artifact changed during readback")
        return {"size": total, "sha256": digest.hexdigest(), "prefix": prefix, "identity": _READER.identity(before)}
    finally:
        if writer is not None:
            os.close(writer)
        os.close(fd)


def retain_pin(item,target,remaining,cap,context=None):
    # Deduplication saves storage only. Every declared source and every existing
    # cached object independently prove complete full9/size/hash custody.
    if "imageArtifactRange" in item:
        observed=artifact_read(item,cap,context=context)
        # The protected Root receipt retains the actual media for all consumer
        # jobs. Do not invent an additional image inode under the staging cap.
        if target.exists():
            artifact_read({"path":str(target),"sha256":item["sha256"],"size":item["size"],"kind":item.get("kind")},cap)
        return 0,observed
    if target.exists():
        observed=artifact_read(item,cap)
        artifact_read({"path":str(target),"sha256":item["sha256"],"size":item["size"],"kind":item.get("kind")},cap)
        return 0,observed
    observed=artifact_read(item,min(remaining,cap),target)
    return observed["size"],observed


def copy_pin(item, target, remaining):
    return artifact_read(item, remaining, target)["size"]


def tree_guard(path):
    for parent, dirs, files in os.walk(path, followlinks=False):
        real_dir(Path(parent))
        for name in dirs:
            real_dir(Path(parent) / name)
        for name in files:
            s = (Path(parent) / name).lstat()
            require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1,
                    "Unsafe CI tree entry; retain entire run")


def expire(config, rows, now=None, root=ROOT):
    now = int(time.time()) if now is None else now
    root_guard(root)
    removed = []
    for run in root.iterdir():
        if not RUN.fullmatch(run.name):
            continue  # Unknown/non-CI entries are preserved, never swept.
        run_identity = _READER.identity(real_dir(run))
        lock_path = run / ".lock"
        with owned_lock(lock_path) as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue
            meta, _ = load_result(run / ".owned.json")
            require(meta.get("schema") == 1 and meta.get("name") == run.name and meta.get("uid") == os.getuid()
                    and type(meta.get("created")) is int and meta.get("expires") == meta["created"] + TTL,
                    "CI run marker/TTL guard")
            if now < meta["created"] or now < meta["expires"]:
                continue
            # Absent closure or interrupted controller is retained indefinitely
            # until the ordinary owner reconciles exact current disposition.
            receipt_path = run / "receipt.json"
            if not receipt_path.exists():
                continue
            receipt_limit=meta.get("result_max_bytes",_RESULT["FALLBACK_MAX"])
            require(type(receipt_limit)is int and _RESULT["FALLBACK_MAX"]<=receipt_limit<=_RESULT["HARD_MAX"],"Owned receipt contract bound invalid")
            if "result_max_bytes"in meta:require(receipt_limit<=_RESULT["policy"](config["result_contract"])["max_bytes"],"Owned receipt contract exceeds configured consumer")
            receipt, _ = load_result(receipt_path,receipt_limit)
            if receipt.get("active") is not False or not closed_jobs(meta["job_ids"], rows):
                continue
            require(receipt.get("run_name") == run.name, "CI receipt run identity mismatch")
            tree_guard(run)
            # Small immutable receipt survives big-artifact expiry. No logs,
            # source disks or originals outside this dedicated run are removed.
            saved = root / ".receipts" / (run.name + ".json")
            if saved.exists():
                saved_value, _ = load_result(saved,receipt_limit)
                require(saved_value == receipt, "Retained receipt conflict")
            else:
                _RESULT["write_full"](saved,receipt,receipt_limit)
            require(shutil.rmtree.avoids_symlink_attacks, "Platform lacks symlink-safe tree removal")
            require(run_identity == _READER.identity(run.lstat()), "CI run directory changed during expiry guards")
            shutil.rmtree(run)
            removed.append(run.name)
    return removed


QUALIFICATION_FILES = {"scripts/omen_ci_stage.py", "scripts/omen_ci_reader.py", "scripts/omen_ci_inventory.py",
                       "scripts/omen_ci_executables.py", "scripts/omen_ci_result.py", "tests/verify_omen_ci_canonical.py"}
CANONICAL_QUEUE_SHA = "ba577d32e0ad4d582a2908521695056256f0d81c71f715486b83ff2648c379de"


def validate_canonical_qualification(value, expected_pins, source, stage_sha):
    require(isinstance(expected_pins, dict) and set(expected_pins) == QUALIFICATION_FILES
            and all(SHA.fullmatch(x or "") for x in expected_pins.values())
            and expected_pins["scripts/omen_ci_stage.py"] == stage_sha,
            "Exact executing stage/current-source canonical qualification pins required")
    require(value.get("kind") == "OPEMOS_REQUIRED_CANONICAL_METADATA_VM_QUALIFICATION_V1"
            and value.get("status") == "passed" and value.get("source_commit") == source
            and type(value.get("uid")) is int and value["uid"] == 1000
            and type(value.get("numeric_exit")) is int and value["numeric_exit"] == 0
            and value.get("canonical_fixture_sha256") == CANONICAL_QUEUE_SHA
            and value.get("canonical_fixture_bytes") == 388189 and value.get("source_pins") == expected_pins
            and value.get("public_safety_batch_substitute") is False and value.get("genuine_vm_receipt") is True,
            "REQUIRED actual UID1000 OMEN canonical fixture qualification absent/failed/stale; public tests cannot substitute")
    cases = value.get("cases", [])
    require(isinstance(cases, list) and len(cases) == 3 and {x.get("scratch_relation") for x in cases} == {"same","nested","separate"},
            "Actual canonical same/nested/separate scratch verification required")
    for case in cases:
        proof = case.get("metadata_custody", {})
        owned = proof.get("owned_descriptors", [])
        require(case.get("status") == "passed" and case.get("job_rows") == 77 and case.get("unknown_fields_preserved") is True
                and type(case.get("normal_producer_exit")) is int and case["normal_producer_exit"] == 0
                and type(proof.get("bytes")) is int and proof["bytes"] > 32 * 1024**2
                and proof.get("producer_source_sha256") == CANONICAL_QUEUE_SHA
                and proof.get("job_rows") == 77 and proof.get("all_rows_retained") is True
                and all(proof.get(k) is True for k in ("complete","capture_fd_closed","sealed_manifest_fds_closed","normal_queue_descriptors_closed"))
                and not proof.get("first_failure") and not proof.get("close_failures")
                and proof.get("queue_fds_before") == proof.get("queue_fds_after_owned_close")
                and len(owned) == 1 and owned[0].get("role") == "metadata-capture"
                and owned[0].get("allocated",{}).get("open") is True
                and owned[0].get("before_close",{}).get("open") is True
                and owned[0].get("after_close",{}).get("open") is False,
                "Actual complete canonical capture/consume/owned-close/queue-close proof incomplete")
    for case in cases:
        probe=case.get("result_transport_retention",{})
        require(probe.get("status")=="passed"and type(probe.get("full_bytes"))is int and probe["full_bytes"]>32*1024**2
                and probe.get("wire_bytes")==probe["full_bytes"]and SHA.fullmatch(probe.get("wire_sha256","")or"")
                and type(probe.get("local_numeric_exit"))is int and probe["local_numeric_exit"]==0
                and all(probe.get(k)is True for k in ("wire_EOF","transport_complete","local_reaped","all_unknown_rows_equal",
                    "guarded_expiry_removed_only_new_owned_probe","retained_full_receipt_equal"))
                and probe.get("actual_SSH_claim")is False,"Required actual full canonical result/pipe/retention composition missing")
        proof=case["metadata_custody"];owned=proof["owned_descriptors"][0]
        allocated,before,after=(owned[k] for k in ("allocated","before_close","after_close"))
        require(type(allocated.get("fd")) is int and allocated["fd"]>=0 and allocated["fd"]==before.get("fd")==after.get("fd")
                and isinstance(allocated.get("target"),str) and before.get("target")==allocated["target"]
                and set(allocated.get("identity",{}))==set(_FULL9) and set(before.get("identity",{}))==set(_FULL9)
                and all(type(x) is int for record in (allocated,before) for x in record["identity"].values())
                and stat.S_ISREG(allocated["identity"]["st_mode"]) and allocated["identity"]["st_uid"]==1000
                and allocated["identity"]["st_nlink"]==0
                and all(allocated["identity"][k]==before["identity"][k] for k in
                    ("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink"))
                and before["identity"]["st_size"]==proof["bytes"]
                and type(proof.get("producer_exit")) is int and proof["producer_exit"]==0,
                "Required actual owned capture full9/birth/byte count/closed FD evidence missing")
    return value


def require_canonical_qualification(config, request, rows):
    item = config.get("required_canonical_qualification", {})
    value = load_pinned(item["receipt"])
    validate_canonical_qualification(value, item["source_pins"], request["source_commit"], request["stage_sha256"])
    guest=value.get("guest",{})
    require(isinstance(item.get("runtime_instance_id"),str) and item["runtime_instance_id"]
            and guest.get("runtime_instance_id")==item["runtime_instance_id"]
            and guest.get("detection_command")==["/usr/bin/systemd-detect-virt","--vm"]
            and type(guest.get("detection_exit")) is int and guest["detection_exit"]==0
            and guest.get("detected_virtualization") in ("kvm","qemu"),
            "Required actual admitted OMEN guest detection/instance does not match qualification")
    # The qualification is an existing independently reviewed ordinary VM job,
    # never a workflow flag, public synthetic fixture or new runtime admission.
    load_pinned(item["runtime_admission"])
    manifest = absolute_manifest(load_pinned(item["manifest"]))
    job_id = item["producer_job_id"]
    jobs = [job for job in manifest["jobs"] if job.get("id") == job_id]
    require(len(jobs) == 1 and all(jobs[0].get("approval",{}).get(k) == item["runtime_admission"].get(k)
                                 for k in ("path","sha256")), "Required canonical VM job exact normal admission differs")
    proof = load_pinned(item["owner_queue_proof"])
    current = rows.get(job_id,{})
    lifecycle = proof.get("result",{}).get("terminalLifecycle",{})
    closure,pool = lifecycle.get("postStopCgroupProof",{}),lifecycle.get("postStopPoolProof",{})
    require(proof.get("id") == job_id and proof.get("state") == current.get("state") == "passed"
            and proof.get("unit") == current.get("unit") and proof.get("result",{}).get("InvocationID")
            == current.get("result",{}).get("InvocationID") and proof.get("result",{}).get("InvocationID")
            and lifecycle.get("phase") == "CLOSED" and closure.get("completeTraversal") is True
            and closure.get("includesUID0") is True and closure.get("empty") is True and closure.get("processes") == []
            and pool.get("admitted") is True and pool.get("allOwnedDescriptorsClosed") is True,
            "Required canonical VM qualification normal queue/pool/cgroup closure unknown")
    return {"receipt_sha256":item["receipt"]["sha256"], "producer_job_id":job_id,
            "source_pins":item["source_pins"], "status":"passed", "uid":1000, "normal_queue_closed":True}


def dispatch(config, request, plan, root=ROOT):
    started = time.monotonic()
    require(set(request) == {"version", "action", "repository", "run_id", "attempt", "source_commit", "plan_sha256", "config_sha256", "executables_sha256", "consumer_started_epoch", "stage_sha256", "result_contract"},
            "Unknown request fields")
    require(request["repository"] == "CorniiDog/OPEMOS.EXE" and re.fullmatch(r"[0-9a-f]{40}", request["source_commit"]), "Canonical source missing")
    require(plan.get("version") == 1 and plan.get("source_commit") == request["source_commit"] and
            re.fullmatch(r"[0-9a-f]{32}", plan.get("nonce", "")), "Reviewed source/nonce plan mismatch")
    require(set(plan.get("cases", {})) == set(CASES) and set(plan.get("vms", {})) == _INVENTORY["IDS"],
            "All20 exact VM IDs and five truthful role cases must be declared, including null operands")
    require(all(isinstance(ids, list) and all(isinstance(x, str) for x in ids) for ids in plan["cases"].values()),
            "Per-role case mapping must be explicit VM ID lists")
    mapping = {vm_id: case for case, ids in plan["cases"].items() for vm_id in ids}
    mapped_ids = [vm_id for ids in plan["cases"].values() for vm_id in ids]
    require(len(mapped_ids) == len(set(mapped_ids)) and set(mapped_ids) <= _INVENTORY["IDS"],
            "Ambiguous, duplicated or unknown per-role VM mapping")
    admitted = plan.get("admitted_vm_ids", [])
    require(isinstance(admitted, list) and len(admitted) == len(set(admitted)) and set(admitted) <= _INVENTORY["IDS"] and
            type(config.get("max_vm_submissions")) is int and 1 <= config["max_vm_submissions"] <= 20 and
            len(admitted) <= config["max_vm_submissions"], "Explicit finite owner-admitted VM set required; no mass discovery launch")
    require(config.get("vm_admission_limits") == {"max_vm_bytes": 60_000_000_000, "max_cpu": 10,
            "max_memory_bytes": 32 * 1024**3}, "Existing full VM accounting/pool limits must remain exact")
    for key in ("run_id", "attempt"):
        require(re.fullmatch(r"[1-9][0-9]{0,19}", request[key]), "GitHub run identity invalid")
    expected = _EXECUTABLES["validate_expected"](plan.get("expected_executables"), request["source_commit"])
    require(_EXECUTABLES["digest"](expected) == request["executables_sha256"] and type(request.get("consumer_started_epoch")) is int
            and 0 < request["consumer_started_epoch"] <= time.time(), "Exact current producer expectations/consumer start required")
    bindings = {vm_id:operand.get("runtime_instance_id") for vm_id,operand in plan["vms"].items() if isinstance(operand,dict) and vm_id in admitted}
    require(not _INVENTORY["runtime_conflicts"](bindings), "Conflicting original/runtime lineage in admitted plan; no effects")
    sources={}
    for vm_id in admitted:
        operand=plan["vms"][vm_id]
        require(isinstance(operand,dict) and isinstance(operand.get("original_source"),dict),"Admitted original source lineage missing")
        original=operand["original_source"]
        require(_INVENTORY["original_source_valid"](original),"Exact original source full9/size/SHA required")
        sources[vm_id]=_EXECUTABLES["digest"](original["identity"])
    require(not _INVENTORY["runtime_conflicts"](sources),"Two catalog originals alias one retained source backing identity; no effects")
    runtime_original={runtime:original for original,runtime in bindings.items()}
    source_original={fingerprint:original for original,fingerprint in sources.items()}
    for entry in plan.get("executable_acceptance",{}).values():
        if not isinstance(entry,dict):continue
        for key in ("build_operand","heal_operand"):
            operand=entry.get(key,{})
            original,runtime=operand.get("inventory_vm_id"),operand.get("runtime_instance_id")
            require(original in _INVENTORY["IDS"]and isinstance(runtime,str)and runtime,"Exact artifact operation original/runtime subject missing")
            require(runtime not in runtime_original or runtime_original[runtime]==original,"Artifact operation runtime aliases another original")
            runtime_original[runtime]=original
            require(_INVENTORY["original_source_valid"](operand.get("original_source")),"Artifact operation original source lineage missing")
            fingerprint=_EXECUTABLES["digest"](operand["original_source"]["identity"])
            require(fingerprint not in source_original or source_original[fingerprint]==original,"Artifact operation source backing aliases another original")
            source_original[fingerprint]=original
    contract=_RESULT["policy"](config["result_contract"])
    require(contract==request["result_contract"],"Controller/stage result contract mismatch")
    composition=_RESULT["composition"](config,plan)
    root_guard(root)
    initial_metadata = {}
    rows = queue_status(config, diagnostic=initial_metadata)
    try:
        canonical_qualification = require_canonical_qualification(config, request, rows)
    except (ValueError,KeyError,TypeError,OSError) as error:
        error.metadata_receipt=initial_metadata
        raise
    expire(config, rows, root=root)
    name = "run-" + request["run_id"] + "-" + request["attempt"] + "-" + plan["nonce"]
    require(RUN.fullmatch(name), "Run path invalid")
    # Nonce is one-use across attempts/runs, including already-expired receipts.
    require(not any(p.name.endswith(plan["nonce"]) or p.name.endswith(plan["nonce"] + ".json")
                    for folder in (root, root / ".receipts") for p in folder.iterdir()), "Reviewed run nonce already consumed")
    path = root / name
    path.mkdir(mode=0o700)
    artifacts = path / "artifacts"
    artifacts.mkdir(mode=0o700)
    create_json(path / ".lock", {})
    lock = owned_lock(path / ".lock")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    now = int(time.time())
    result = {"version": 1, "run_name": name, "run_id": request["run_id"], "attempt": request["attempt"],
              "source_commit": request["source_commit"], "nonce": plan["nonce"], "active": True,
              "created": now, "expires": now + TTL, "vms": _INVENTORY["default_rows"]("Missing reviewed exact VM operand"), "staged_files": []}
    result["observed_vm_ids"], result["coverage_verified"] = [], False
    result["metadata_producer_custody"] = {"initial":initial_metadata}
    result["required_canonical_qualification"] = canonical_qualification
    result["result_contract"] = contract
    result["result_composition"] = composition
    manifests, job_ids = [], []
    protected_jobs = executable_protected_jobs(plan)
    budget = config["max_run_bytes"]
    require(type(budget) is int and 0 < budget <= 60_000_000_000, "Reviewed dedicated CI staging budget missing")
    require(type(config["wait_seconds"]) is int and 1 <= config["wait_seconds"] <= 3 * 3600,
            "Reviewed finite controller wait must be 1..10800 seconds")
    require(type(config["free_reserve_bytes"]) is int and config["free_reserve_bytes"] >= 0,
            "Reviewed staging free-space reserve missing")
    require(shutil.disk_usage(root).free >= budget + 2*contract["max_bytes"] + config["free_reserve_bytes"], "CI staging free-space reserve unavailable")
    for vm_id, row in result["vms"].items():
        operand = plan["vms"][vm_id]
        case = mapping.get(vm_id)
        row["case"] = case
        try:
            require(operand is not None and vm_id in admitted and case in CASES,
                    f"Missing explicit admitted exact {vm_id} ordinary case/manifest/package/input/runtime operand")
            require(operand.get("inventory_vm_id") == vm_id and operand.get("case") == case and
                    isinstance(operand.get("runtime_instance_id"), str) and
                    re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", operand["runtime_instance_id"]),
                    "Exact inventory/case and distinct admitted runtime identity required")
            row["planned_runtime_instance_id"] = operand["runtime_instance_id"]
            require(_INVENTORY["subject_contract"](vm_id, case, operand.get("subject_role")), "Missing/wrong exact per-VM graph role/case")
            row["subject_role"] = operand["subject_role"]
            load_pinned(operand["runtime_admission"])
            if case == "steamos-autoheal":
                require(operand.get("hardware_scope") == "existing-independently-admitted-gpu",
                        "SteamOS case unavailable: no existing independently admitted shared-GPU lease")
                load_pinned(operand["gpu_admission"])
            else:
                require(operand.get("hardware_scope") == "virtual-only", "Host imaging must remain virtual-only")
            require(SHA.fullmatch(operand["input_sha256"]) and
                    (case == "nested-ubuntu-linux" and SHA.fullmatch(operand.get("payload_sha256", ""))
                     or case != "nested-ubuntu-linux" and SHA.fullmatch(operand["package_sha256"])),
                    "Actual input and role-specific package/payload identity missing")
            manifest = absolute_manifest(load_pinned(operand["manifest"]))
            require(manifest.get("version") == 1 and [j["id"] for j in manifest["jobs"]] == operand["job_ids"], "Queue manifest job identity mismatch")
            require(all(all(j.get("approval", {}).get(key) == operand["runtime_admission"].get(key) for key in ("path", "sha256"))
                        for j in manifest["jobs"]), "Normal job approval differs from exact runtime admission")
            require(1 <= len(operand["job_ids"]) <= 16 and not any(j in rows or j in job_ids for j in operand["job_ids"]), "Queue job already exists or conflicts")
            if case == "steamos-autoheal":
                gpu_jobs = [j for j in manifest["jobs"] if "libvirt_domain" in j and
                            "omen-iommu-group-1" in j.get("resources", [])]
                require(len(gpu_jobs) == 1 and gpu_jobs[0]["libvirt_domain"]["leaseNonce"] == operand.get("lease_nonce"),
                        "Exact existing normal libvirt/shared-GPU lease manifest is missing")
                approval = gpu_jobs[0].get("approval", {})
                require(all(approval.get(key) == operand["gpu_admission"].get(key) for key in ("path", "sha256")),
                        "GPU admission must be the exact independently reviewed normal job approval")
            require(operand["input_sha256"] in {p["sha256"] for p in operand["inputs"]}, "Exact original input pin absent")
            # Package/source-byte copies are streamed under the controller's
            # mandatory heavy entry; queue.sh separately accounts guest work.
            source_proven=False
            for item in operand["inputs"]:
                context = operand_image_range_context(operand,plan,request,expected) if "imageArtifactRange" in item else None
                observed=artifact_read(item,config["max_input_bytes"],context=context)
                original = observed["backing"] if "imageArtifactRange" in item else {k:observed[k]for k in ("sha256","size","identity")}
                if original==operand["original_source"]:source_proven=True
            require(source_proven,"Original source pin was not an actually verified ordinary input")
            for pin in operand["artifacts"]:
                require(isinstance(pin.get("sha256"), str) and SHA.fullmatch(pin["sha256"]),
                        "Artifact digest/path identity invalid")
                target = artifacts / pin["sha256"]
                context = operand_image_range_context(operand,plan,request,expected) if "imageArtifactRange" in pin else None
                charged,_=retain_pin(pin,target,budget,config["max_run_bytes"],context=context)
                budget-=charged
                result["staged_files"].append({"sha256": pin["sha256"], "size": pin["size"]})
            require(operand["payload_sha256"] if case == "nested-ubuntu-linux" else operand["package_sha256"], "Role-specific artifact missing")
            require((operand["payload_sha256"] if case == "nested-ubuntu-linux" else operand["package_sha256"])
                    in {p["sha256"] for p in operand["artifacts"]}, "Exact role-specific package/payload not staged on OMEN")
            manifests.append(operand["manifest"])
            job_ids.extend(operand["job_ids"])
            row["status"] = "pending"
        except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError) as exc:
            row.update(status="failed", reason=str(exc))
    require(not set(job_ids) & set(protected_jobs), "Inventory and per-executable ordinary jobs must not alias")
    protected_jobs = job_ids + protected_jobs
    create_json(path / ".owned.json", {"schema": 1, "name": name, "uid": os.getuid(), "created": now,
                 "expires": now + TTL, "result_max_bytes":contract["max_bytes"], "job_ids": protected_jobs, "source_commit": request["source_commit"], "nonce": plan["nonce"]})
    if manifests:
        require(config.get("dispatcher_mode") == "join-existing", "Only the existing admitted queue worker may run")
        # Submission uses exact verified bytes/sealed FDs; never path-hash then
        # reopen a queue executable or manifest. Do not start a replacement worker.
        submit_metadata = {}
        submitted = queue_call(config, "submit", manifests, capture_receipt=submit_metadata)
        create_json(path / "queue-submitted.json", {"normal_result":submitted,"metadata_custody":submit_metadata})
        result["metadata_producer_custody"]["submit"] = submit_metadata
    if protected_jobs:
        deadline = started + config["wait_seconds"]
        while time.monotonic() < deadline:
            wait_metadata = {}
            rows = queue_status(config, diagnostic=wait_metadata)
            result["metadata_producer_custody"]["last_wait"] = wait_metadata
            if closed_jobs(protected_jobs, rows):
                break
            time.sleep(10)
    final_metadata = {}
    rows = queue_status(config, diagnostic=final_metadata)
    result["metadata_producer_custody"]["final"] = final_metadata
    result["active"] = not closed_jobs(protected_jobs, rows)
    for vm_id, row in result["vms"].items():
        if row["status"] != "pending":
            continue
        operand, case = plan["vms"][vm_id], mapping[vm_id]
        try:
            require(closed_jobs(operand["job_ids"], rows), "Queue case still active/closure unknown; artifacts protected")
            require(all(rows[j]["state"] == "passed" for j in operand["job_ids"]), "Actual queue case failed; no acceptance claim")
            receipt, receipt_sha = load_result(operand["receipt_path"])
            files = validate_receipt(receipt, case, {**plan, "run_id": request["run_id"], "attempt": request["attempt"]}, operand)
            evidence_root = Path(operand["evidence_root"])
            real_dir(evidence_root)
            for item in files.values():
                source = Path(item["path"])
                require(source.is_relative_to(evidence_root), "Case evidence escapes its reviewed operation root")
                if item.get("kind") == "screenshot":
                    require(artifact_read(item, config["max_run_bytes"])["prefix"] == b"\x89PNG\r\n\x1a\n", "Screenshot is not actual PNG evidence")
                target = artifacts / item["sha256"]
                charged,_=retain_pin(item,target,budget,config["max_run_bytes"])
                budget-=charged
                result["staged_files"].append({"sha256": item["sha256"], "size": item["size"]})
            row.update(status="passed", runtime_instance_id=receipt["runtime_instance_id"], receipt_sha256=receipt_sha, queue_job_ids=operand["job_ids"],
                       roles=receipt["roles"], original_source=operand["original_source"], actual_receipt_verified=True, active=False,
                       source_commit=request["source_commit"], run_id=request["run_id"], attempt=request["attempt"], nonce=plan["nonce"],
                       reason=("Exact independently validated nested Ubuntu Linux boot/closure only; no executable/Fedora/GPU/fullstack claim"
                               if case == "nested-ubuntu-linux" else "Exact independently validated actual graphical/boot/recovery receipt and closure"))
        except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError) as exc:
            row.update(status="failed", reason=str(exc))
    try:
        observation, observation_sha = load_result(config["inventory_observation"]["path"])
        observed, producer = observation["vm_ids"], config["inventory_observation"]["producer_job_id"]
        finished = int(time.time())
        require(producer in job_ids and rows[producer]["state"] == "passed" and
                observation.get("producer_job_id") == producer and observation.get("closure_verified") is True and
                observation.get("source_commit") == request["source_commit"] and observation.get("nonce") == plan["nonce"] and
                type(observation.get("observed_at")) is int and finished - 300 <= observation["observed_at"] <= finished and
                isinstance(observed, list) and all(isinstance(x, str) for x in observed) and len(observed) == len(set(observed)),
                "Fresh final canonical VM discovery must be output of the exact passed ordinary producer job")
        result["observed_vm_ids"], result["inventory_observation_sha256"] = observed, observation_sha
        result["coverage_verified"] = set(observed) == _INVENTORY["IDS"]
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError) as exc:
        result["coverage_error"] = str(exc)
    result["executable_acceptance"], budget = executable_outcomes(config, request, plan, rows, artifacts, budget)
    result["expected_executables"] = expected
    result["queue_rows"] = {j: rows.get(j) for j in protected_jobs}
    result = _INVENTORY["normalize"](result)
    _RESULT["write_full"](path/"receipt.json",result,contract["max_bytes"])
    if result["active"] is False:
        _RESULT["write_full"](root/".receipts"/(name+".json"),result,contract["max_bytes"])
    lock.close()
    return result


def main():
    try:
        require(len(sys.argv) in (2, 3), "Installed config path required")
        if len(sys.argv) == 3:
            require(sys.argv[2] == "expire", "Only dedicated artifact expiry can run without SSH input")
            request = {"version": 1, "action": "expire", "config_sha256": os.environ.get("OPEMOS_OMEN_CONFIG_SHA256", "")}
        else:
            raw = sys.stdin.buffer.read(1024**2 + 1)
            require(len(raw) <= 1024**2, "Request stream cap")
            request = strict_json(raw)
        require(request.get("version") == 1, "Request schema mismatch")
        config = load_pinned({"path": sys.argv[1], "sha256": request["config_sha256"]})
        require(config.get("version") == 1 and config.get("enabled") is True and config.get("artifact_root") == str(ROOT),
                "Installed OMEN route is disabled or root differs")
        if request.get("action") == "expire":
            expiry_metadata = {}
            rows = queue_status(config, diagnostic=expiry_metadata)
            result = {"expired":expire(config,rows),"metadata_producer_custody":expiry_metadata}
        else:
            require(request.get("action") == "dispatch", "Unsupported action")
            require(config["plan"]["sha256"] == request["plan_sha256"], "Reviewed installed plan differs")
            plan = load_pinned(config["plan"])
            result = dispatch(config, request, plan)
        _RESULT["emit"](result,sys.stdout.buffer,_RESULT["policy"](config["result_contract"])["max_bytes"],config["queue_metadata"]["scratch_dir"])
        return 0 if "vms" not in result or (result["aggregate"]["status"] == "passed"
            and result.get("executable_acceptance", {}).get("aggregate", {}).get("status") == "passed") else 1
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError, subprocess.SubprocessError) as exc:
        failure = {"status": "failed", "error": str(exc), "active": "unknown"}
        if hasattr(exc, "metadata_receipt"): failure["metadata_producer_custody"] = exc.metadata_receipt
        if hasattr(exc,"nonsecret_source_evidence"):failure["nonsecret_source_read"]=exc.nonsecret_source_evidence
        if isinstance(locals().get("request"), dict):
            for key in ("source_commit", "run_id", "attempt"):
                failure[key] = request.get(key)
        expected = locals().get("plan", {}).get("expected_executables") if isinstance(locals().get("plan"), dict) else None
        failure["executable_acceptance"] = _EXECUTABLES["missing_report"](failure.get("source_commit"), failure.get("run_id"),
            failure.get("attempt"), str(exc), expected if isinstance(expected, dict) else None)
        failure=_INVENTORY["normalize"](failure,reason=str(exc))
        limit=locals().get("config",{}).get("result_contract",{}).get("max_bytes",_RESULT["FALLBACK_MAX"])
        if type(limit)is not int or not _RESULT["FALLBACK_MAX"]<=limit<=_RESULT["HARD_MAX"]:limit=_RESULT["FALLBACK_MAX"]
        _RESULT["emit"](failure,sys.stdout.buffer,limit,"/tmp")
        return 1


if __name__ == "__main__":
    sys.exit(main())

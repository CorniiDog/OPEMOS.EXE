#!/usr/bin/python3
"""Fixed source-owner integration ABI for OPEMOSRobot keywords.

Install in the reviewed EXE source only through its owning lead. This client
does not execute plans or inspect VM/source files inside the confined runner.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import time

REPO = "CorniiDog/OPEMOS.EXE"
SOCKET = "/run/opemos-ci/control/control.sock"
EXCHANGE = "/home/connor/.local/share/opemos-ci/github-runner/robot-private/reports"
MAX_REPLY = 1048576
MAX_PUBLIC = 16 * 1024 * 1024
MAX_PUBLIC_TOTAL = 256 * 1024 * 1024


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate broker JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, "nonfinite broker JSON"))


def require(ok, why):
    if not ok:
        raise ValueError(why)


def _read_public(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        require(stat.S_ISREG(meta.st_mode) and meta.st_size <= MAX_PUBLIC and
                meta.st_nlink == 1 and meta.st_uid == os.getuid() and
                not meta.st_mode & 0o222, "bounded read-only public report")
        digest = hashlib.sha256()
        data = bytearray()
        while block := os.read(fd, min(65536, MAX_PUBLIC + 1 - len(data))):
            data.extend(block)
            digest.update(block)
            require(len(data) <= MAX_PUBLIC, "public report cap")
        after = os.fstat(fd)
        require(len(data) == meta.st_size and
                (meta.st_dev, meta.st_ino, meta.st_mtime_ns, meta.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns) and
                digest.hexdigest() == expected, "public report custody/hash")
        return bytes(data)
    finally:
        os.close(fd)


def _require_host_broker_peer(peer):
    """Validate kernel credentials; PID zero means peer outside our PID namespace."""
    credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                  struct.calcsize("3i"))
    require(type(credentials) is bytes and len(credentials) == struct.calcsize("3i"),
            "complete fixed host broker credentials")
    pid, uid, gid = struct.unpack("3i", credentials)
    require(pid >= 0 and uid == os.getuid() and gid == os.getgid(),
            "fixed host broker peer UID/GID")
    return pid, uid, gid


class Engine:
    def __init__(self, output):
        env = os.environ
        require(env.get("GITHUB_REPOSITORY") == REPO and
                env.get("OPEMOS_ROBOT_CONTROL_SOCKET") == SOCKET,
                "fixed authenticated Robot route")
        self.identity = {"repository": REPO,
                         "source_commit": env["OPEMOS_SOURCE_SHA"],
                         "run_id": env["GITHUB_RUN_ID"],
                         "attempt": env["GITHUB_RUN_ATTEMPT"]}
        require(re.fullmatch(r"[0-9a-f]{40}", self.identity["source_commit"]) and
                all(re.fullmatch(r"[1-9][0-9]{0,19}", self.identity[key])
                    for key in ("run_id", "attempt")),
                "exact current GitHub/source identity")
        self.output = Path(output)
        require(self.output.is_absolute() and self.output.resolve() == self.output,
                "absolute unlinked private client state")
        self.reports = Path(env["OPEMOS_ROBOT_REPORT_DIR"])
        require(env.get("OPEMOS_ROBOT_REPORT_EXCHANGE") == EXCHANGE,
                "fixed read-only public report exchange")
        self.exchange = Path(EXCHANGE)
        self.output.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.reports.mkdir(mode=0o700, parents=True, exist_ok=True)
        private = self.output.lstat()
        require(stat.S_ISDIR(private.st_mode) and private.st_uid == os.getuid() and
                private.st_mode & 0o077 == 0, "private current-run client state")
        inventory = json.loads((Path(__file__).parents[1] / "ci/required-vms.json").read_bytes())
        rows = inventory["required_vms"]
        require(len(rows) == len({row["id"] for row in rows}) == 20,
                "all20 visible inventory")
        self.results = {row["id"]: {"status": "unavailable", "name": row["name"]}
                        for row in rows}
        self.artifacts = {p: {"status": "unavailable"}
                          for p in ("windows", "ubuntu", "macos")}

    def _request(self, action, subject):
        request = dict(self.identity, version=2, action=action, subject=subject,
                       nonce=secrets.token_hex(16),
                       consumer_started_epoch=int(time.time()))
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(21600)
            peer.connect(SOCKET)
            _require_host_broker_peer(peer)
            peer.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
            raw = bytearray()
            while len(raw) <= MAX_REPLY and not raw.endswith(b"\n"):
                part = peer.recv(min(8192, MAX_REPLY + 1 - len(raw)))
                require(part, "host broker reply EOF")
                raw.extend(part)
        require(len(raw) <= MAX_REPLY and raw.endswith(b"\n"),
                "bounded complete host broker reply")
        reply = strict_json(raw)
        require(reply.get("identity") == {k: request[k] for k in
                ("repository", "source_commit", "run_id", "attempt", "nonce")},
                "current broker reply identity")
        require(reply.get("action") == action and reply.get("subject") == subject,
                "broker action/subject identity")
        self._copy_public(reply.get("public_evidence", []))
        # A retained-package connection proof cannot promote the independently
        # required current-source VM/platform cases, even via a malformed reply.
        if action == "connection-proof":
            return reply
        for key, status in reply.get("vms", {}).items():
            require(key in self.results and status in
                    ("unavailable", "failed", "passed"), "exact VM result")
            self.results[key]["status"] = status
        for key, status in reply.get("platforms", {}).items():
            require(key in self.artifacts and status in
                    ("unavailable", "failed", "passed"), "exact platform result")
            self.artifacts[key]["status"] = status
        return reply

    def _copy_public(self, rows):
        require(type(rows) is list and len(rows) <= 64, "public evidence count")
        total = 0
        for row in rows:
            name = row["name"]
            require(type(name) is str and name == Path(name).name and
                    name.startswith(self.identity["run_id"] + "-" +
                                    self.identity["attempt"] + "-"),
                    "current report basename")
            require(type(row["bytes"]) is int and 0 <= row["bytes"] <= MAX_PUBLIC and
                    type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]),
                    "bounded exact public descriptor")
            total += row["bytes"]
            require(total <= MAX_PUBLIC_TOTAL, "public operation total cap")
            data = _read_public(self.exchange / name, row["sha256"])
            require(len(data) == row["bytes"], "public report size")
            target = self.reports / name
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(fd)

    def vm(self, vm_id):
        require(vm_id in self.results, "unknown required VM")
        reply = self._request("execute-vm", vm_id)
        require(reply["status"] == "passed", "actual VM case failed; retained host evidence")
        return {"exports": [{"path": str(self.reports / item["name"]),
                              "kind": item["kind"], "sha256": item["sha256"]}
                             for item in reply["public_evidence"]]}

    def platform(self, platform):
        require(platform in self.artifacts, "unknown platform")
        reply = self._request("execute-platform", platform)
        require(reply["status"] == "passed", "actual platform artifacts failed")
        return {"exports": [{"path": str(self.reports / item["name"]),
                              "kind": item["kind"], "sha256": item["sha256"]}
                             for item in reply["public_evidence"]]}

    def connection(self):
        """Separately scoped real pointer/native-chooser proof, never fullstack."""
        reply = self._request("connection-proof", "ubuntu_native_chooser_connection")
        require(reply["status"] == "passed", "actual scoped connection proof failed")
        require(reply.get("scope") == "CONNECTION_ONLY_OLD_ARTIFACT_NO_FULLSTACK_ACCEPTANCE",
                "connection proof scope missing")
        return {"exports": [{"path": str(self.reports / item["name"]),
                              "kind": item["kind"], "sha256": item["sha256"]}
                             for item in reply["public_evidence"]]}

    def persist(self):
        reply = self._request("persist", "all")
        path = self.reports / ("summary-" + self.identity["run_id"] + "-" +
                               self.identity["attempt"] + "-" + str(time.monotonic_ns()) + ".json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(reply, stream, sort_keys=True, indent=2)
            stream.write("\n")
        return reply

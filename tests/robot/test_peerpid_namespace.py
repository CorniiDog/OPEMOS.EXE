#!/usr/bin/python3
"""Native Linux SO_PEERCRED regression for the EXE-owned client source.

Run as the actual nonroot host-test user with --source pointing at that
checkout's scripts/robot_client.py and --sha256 its reviewed exact bytes.
The listener stays in the host PID namespace; the child uses the existing
sudo-n/bwrap/setpriv route and makes no Robot request or queue/VM change.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import types


def source_helper(path, expected):
    path = Path(path)
    assert path.is_absolute() and path.name == "robot_client.py" and path.parent.name == "scripts"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 131072
        data = bytearray()
        while part := os.read(fd, 65536):
            data.extend(part)
            assert len(data) <= 131072
        after = os.fstat(fd)
        named = path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        assert all(getattr(before, k) == getattr(after, k) == getattr(named, k) for k in fields)
        assert len(data) == before.st_size and hashlib.sha256(data).hexdigest() == expected
    finally:
        os.close(fd)
    module = types.ModuleType("reviewed_robot_client")
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module._require_host_broker_peer


class FakePeer:
    def __init__(self, raw):
        self.raw = raw

    def getsockopt(self, level, option, length):
        assert (level, option, length) == (socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        return self.raw


def denied(check, raw):
    try:
        check(FakePeer(raw))
    except ValueError:
        return
    raise AssertionError("invalid credentials accepted")


def pg_members(pgid):
    members = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            raw = (entry / "stat").read_text()
        except FileNotFoundError:
            continue
        fields = raw[raw.rfind(")") + 2:].split()
        assert len(fields) > 2, "process-group custody UNKNOWN"
        if int(fields[2]) == pgid:
            members.append(int(entry.name))
    return sorted(members)


def child_mode(check, path, uid, gid):
    assert os.getuid() == uid and os.getgid() == gid
    with socket.socket(socket.AF_UNIX) as peer:
        peer.connect(path)
        pid, peer_uid, peer_gid = check(peer)
        assert pid == 0 and (peer_uid, peer_gid) == (uid, gid)
        peer.sendall(b"accepted-peer-pid-zero\n")
    print(json.dumps({"peerPID": pid, "peerUID": peer_uid, "peerGID": peer_gid,
                      "pidNamespace": os.readlink("/proc/self/ns/pid")}), flush=True)


def outer_mode(check, source, digest, uid, gid):
    assert uid > 0 and os.geteuid() == uid and os.getuid() == uid and os.getgid() == gid
    left, right = socket.socketpair()
    try:
        visible_pid, peer_uid, peer_gid = check(left)
        assert visible_pid > 0 and (peer_uid, peer_gid) == (uid, gid)
    finally:
        left.close()
        right.close()
    for row in [(-1, uid, gid), (0, uid + 1, gid), (0, uid, gid + 1),
                (1, uid + 1, gid), (1, uid, gid + 1)]:
        denied(check, struct.pack("3i", *row))
    denied(check, b"\x00" * 11)
    with tempfile.TemporaryDirectory(prefix="opemos-peerpid-test-") as tmp:
        path = str(Path(tmp) / "control.sock")
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(path)
            listener.listen(1)
            listener.settimeout(20)
            command = ["/usr/bin/sudo", "-n", "/usr/bin/bwrap", "--unshare-pid",
                       "--die-with-parent", "--ro-bind", "/usr", "/usr",
                       "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib",
                       "--ro-bind", "/lib64", "/lib64", "--proc", "/proc",
                       "--dev", "/dev", "--dir", "/tmp", "--bind", tmp, tmp,
                       "--dir", "/source", "--dir", "/source/scripts",
                       "--ro-bind", str(source), "/source/scripts/robot_client.py",
                       "--dir", "/test", "--ro-bind", str(Path(__file__).resolve()),
                       "/test/test_peerpid_namespace.py", "--",
                       "/usr/bin/setpriv", f"--reuid={uid}", f"--regid={gid}",
                       "--clear-groups", sys.executable, "-B",
                       "/test/test_peerpid_namespace.py", "--source",
                       "/source/scripts/robot_client.py", "--sha256", digest,
                       "--inner", path, str(uid), str(gid)]
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True)
            first = None
            out = err = b""
            try:
                assert os.getpgid(child.pid) == child.pid, "owned native group identity"
                with listener.accept()[0] as peer:
                    peer.settimeout(20)
                    assert peer.recv(128) == b"accepted-peer-pid-zero\n"
                out, err = child.communicate(timeout=20)
                assert len(out) <= 1048576 and len(err) <= 1048576
                assert child.returncode == 0, (child.returncode, err.decode(errors="replace"))
                result = json.loads(out)
                assert result["peerPID"] == 0 and (result["peerUID"], result["peerGID"]) == (uid, gid)
            except BaseException as exc:
                first = exc
            finally:
                try:
                    members = pg_members(child.pid)
                    if child.poll() is None and members:
                        os.killpg(child.pid, signal.SIGTERM)
                except BaseException as cleanup_error:
                    first = RuntimeError("native group cleanup UNKNOWN: " + repr(cleanup_error))
                try:
                    tail_out, tail_err = child.communicate(timeout=5)
                    out += tail_out
                    err += tail_err
                except subprocess.TimeoutExpired:
                    first = RuntimeError("native test child timeout; root descendant closure UNKNOWN")
                try:
                    remaining = pg_members(child.pid)
                except BaseException as closure_error:
                    first = RuntimeError("native group closure UNKNOWN: " + repr(closure_error))
                    remaining = "UNKNOWN"
                closure = {"numeric": child.poll(), "stdoutBytes": len(out),
                           "stdoutSHA256": hashlib.sha256(out).hexdigest(),
                           "stderrBytes": len(err), "stderrSHA256": hashlib.sha256(err).hexdigest(),
                           "pipesClosed": bool(child.stdout and child.stdout.closed and
                                               child.stderr and child.stderr.closed),
                           "processGroupMembers": remaining}
                if first is not None or closure["processGroupMembers"] or not closure["pipesClosed"]:
                    raise AssertionError({"first": repr(first), "closure": closure})
            print(json.dumps({"sameNamespacePeerPID": visible_pid, "confinedPeerPID": 0,
                              "uid": uid, "gid": gid, "negativeCases": 6,
                              "nativeClosure": closure}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--inner", nargs=3, metavar=("SOCKET", "UID", "GID"))
    args = parser.parse_args()
    assert len(args.sha256) == 64 and all(c in "0123456789abcdef" for c in args.sha256)
    check = source_helper(args.source, args.sha256)
    if args.inner:
        child_mode(check, args.inner[0], int(args.inner[1]), int(args.inner[2]))
    else:
        outer_mode(check, Path(args.source), args.sha256, os.getuid(), os.getgid())

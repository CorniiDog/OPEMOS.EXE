#!/usr/bin/python3
"""Fixed local Robot handoff. The queue owns this process and its cgroup."""
import json
import hashlib
import os
import signal
import socket
import stat
import struct
import sys
import re
import time
import select
import urllib.request
import urllib.error
from pathlib import Path
from host_engine import HostEngine, held_bytes

REPO = "CorniiDog/OPEMOS.EXE"
MAX_REQUEST = 65536
MAX_REPLY = 1048576
PRODUCER_PATHS = {
    "01 Windows EXE": ".github/workflows/windows-portable.yml",
    "02 Ubuntu AppImage": ".github/workflows/ubuntu-executable.yml",
    "03 macOS Executable": ".github/workflows/macos-arm64.yml",
}


def need(ok, why):
    if not ok:
        raise ValueError(why)


PUBLIC_FAILURES = {'ACTIONS_TOKEN_REQUIRED': 'Existing ephemeral attested Actions token required', 'LEGACY_SCOPE_REFUSED': 'Legacy connection proof is not authorized by this control-only lease', 'TOKEN_BINDING_REQUIRED': 'A post-hook job-token binding is required before a produced-platform operation', 'HOST_OPERATION_FAILED': 'Host operation failed; retained private stage evidence remains authoritative'}
SAFE_FAILURE_CODES = {
    "existing ephemeral attested Actions token required": "ACTIONS_TOKEN_REQUIRED",
    "Legacy connection proof is not authorized by this control-only lease": "LEGACY_SCOPE_REFUSED",
    "post-hook job-token binding required": "TOKEN_BINDING_REQUIRED",
}


def failure_value(error):
    # Only literal known messages are disclosed. Unknown exceptions are typed,
    # not stringified: third-party/network error text may contain a secret.
    code = SAFE_FAILURE_CODES.get(str(error), "HOST_OPERATION_FAILED") if type(error) is ValueError else "HOST_OPERATION_FAILED"
    name = type(error).__name__
    if name not in {"ValueError", "RuntimeError", "TimeoutError", "HTTPError", "URLError", "FileNotFoundError", "PermissionError", "TypeError", "KeyError", "AssertionError", "OSError", "EOFError", "ConnectionError"}:
        name = "Exception"
    return {"kind": "OPEMOS_BROKER_FAILURE_V1", "code": code,
            "reason": PUBLIC_FAILURES[code], "error_type": name,
            "private_recorded": False, "secondary": []}


def private_failure(lease, failure):
    """Persist ONLY classified nonsecret fields, never raw exception/request."""
    path = Path(lease["host_private_root"]) / "broker-failures.jsonl"
    row = {"epoch": int(time.time()), **failure}
    raw = json.dumps(row, separators=(",", ":")).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
             stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
             before.st_size + len(raw) <= 8 * 1024 * 1024,
             "bounded private broker failure log")
        remaining = memoryview(raw)
        while remaining:
            count = os.write(fd, remaining)
            need(count > 0, "private failure short write")
            remaining = remaining[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def record_failure(lease, error):
    value = failure_value(error)
    try:
        private_failure(lease, dict(value, private_recorded=True))
        value["private_recorded"] = True
    except Exception:
        # Preserve the first cause even if its private receipt cannot persist.
        value["secondary"] = ["PRIVATE_FAILURE_PERSISTENCE_FAILED"]
    return value


def peer_context(pid):
    """Kernel peer namespaces/cgroup; retain values, no namespace/proc FD lease."""
    fd = os.open("/proc/" + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    owned = []
    try:
        proc_meta = os.fstat(fd)
        pfd = os.pidfd_open(pid, 0); owned.append(pfd)
        def read(name):
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            owned.append(child)
            raw = bytearray()
            while True:
                block = os.read(child, min(4096, 65537-len(raw)))
                if not block: break
                raw.extend(block)
                need(len(raw) <= 65536, "bounded peer process metadata")
            return raw.decode()
        first = read("stat"); tail = first[first.rfind(")")+2:].split()
        birth = [pid, int(tail[19]), int(tail[1])]
        status = read("status")
        uids = next([int(x) for x in l.split()[1:]] for l in status.splitlines() if l.startswith("Uid:"))
        gids = next([int(x) for x in l.split()[1:]] for l in status.splitlines() if l.startswith("Gid:"))
        need(uids == gids == [1000]*4, "ordinary job peer role")
        cg = read("cgroup")
        need(cg == Path("/proc/self/cgroup").read_text(), "same admitted control queue cgroup")
        result = {"cgroup": cg}
        for name in ("mnt", "pid"):
            nfd = os.open("ns/"+name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=fd)
            owned.append(nfd)
            meta = os.fstat(nfd)
            local = os.stat("/proc/self/ns/"+name)
            need((meta.st_dev, meta.st_ino) != (local.st_dev, local.st_ino), "confined job namespace required")
            result[name] = [meta.st_dev, meta.st_ino]
        last = read("stat"); tail = last[last.rfind(")")+2:].split()
        named = os.stat("/proc/"+str(pid), follow_symlinks=False)
        poll = select.poll(); poll.register(pfd, select.POLLIN)
        need(birth == [pid, int(tail[19]), int(tail[1])] and not poll.poll(0) and
             (proc_meta.st_dev, proc_meta.st_ino) == (named.st_dev, named.st_ino), "held live peer birth")
        return {"namespace": result, "actor": birth}
    finally:
        for child in reversed(owned): os.close(child)
        os.close(fd)


def structured_failure(request, failure):
    reply = {"identity": {k: request[k] for k in
                         ("repository", "source_commit", "run_id", "attempt", "nonce")},
            "action": request["action"], "subject": request["subject"],
            "status": "failed", "all20_passed": False, "all_platforms_passed": False,
            "vms": {}, "platforms": {}, "public_evidence": [],
            "acceptance": "SOURCE_AND_ACTUAL_CASE_ONLY; NO_INFERRED_FULLSTACK_PASS",
            "failure": failure}
    need(len(json.dumps(reply, separators=(",", ":")).encode()) + 1 <= 4096, "small typed broker failure")
    return reply


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "duplicate JSON field")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, "nonfinite JSON"))


class NoGitHubRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward an Authorization header to a redirect destination.
        return None


def github(path, token=None):
    need(not path.startswith("/") and ".." not in path, "fixed GitHub path")
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "OPEMOS-fixed-control"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request("https://api.github.com/" + path,
                                     headers=headers)
    try:
        with urllib.request.build_opener(NoGitHubRedirect()).open(request, timeout=15) as response:
            raw = response.read(MAX_REPLY + 1)
    except urllib.error.HTTPError as refused:
        refused.close()
        raise

    need(len(raw) <= MAX_REPLY, "GitHub response cap")
    return json.loads(raw)


def job_window_valid(not_before,expires_at,now):
    """The real first-hook four-hour job plus cleanup/backoff predicate."""
    return (type(not_before) is int and type(expires_at) is int and
            type(now) is int and not_before<=now and expires_at-now>19000)

def remaining_job_window(lease, peer, now):
    """First hook attestation only; the token binding retains its birth epoch.

    This runs in the existing outside-namespace broker. The confined Runner
    receives only accepted/refused through its existing Unix socket.
    """
    pin = lease.get("connection_fixed_policy")
    need(type(pin) is dict and set(pin)=={"path", "sha256"} and
         re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]),
         "exact Root fixed policy pointer")
    target = Path(pin["path"])
    tx = target.parent.name
    need(re.fullmatch(r"[0-9a-f]{32}", tx) and
         target == Path("/var/lib/opemos-robot-control-r1/releases") / tx /
                   "fixed-policy.json",
         "same installed release fixed policy path")
    raw = held_bytes(target, 65536, pin["sha256"], require_root=True)
    policy = json.loads(raw)
    need(policy.get("kind") == "ROOT_FIXED_SCOPED_CONNECTION_POLICY_V1" and
         policy.get("sourceCommit") == lease["engine_source_commit"] and
         policy.get("queueSourceSHA256") == lease["connection_queue_sha256"] and
         job_window_valid(policy.get("notBefore"),policy.get("expiresAt"),now),
         "finite 240-minute job plus cleanup/poll/backoff admission window")
    group = peer["namespace"]["cgroup"]
    units = re.findall(r"opemos-testq-[0-9a-f-]+\.service", group)
    need(len(units) == 1 and peer["namespace"]["cgroup"] ==
         Path("/proc/self/cgroup").read_text(),
         "same exact host-owned canonical control cgroup")
    return {"policy_sha256": hashlib.sha256(raw).hexdigest(),
            "unit": units[0], "expiresAt": policy["expiresAt"]}


def attest(request, states, peer, pid, lease):
    fields = {"kind", "repository", "source_commit", "workflow_commit", "run_id", "attempt", "mode",
              "producer", "consumer_started_epoch"}
    binding = request.get("kind") == "OPEMOS_ROBOT_JOB_API_TOKEN"
    need(type(request) is dict and
         set(request) == (fields | {"github_token"} if binding else fields) and
         request["kind"] in ("OPEMOS_ROBOT_JOB_ATTESTATION", "OPEMOS_ROBOT_JOB_API_TOKEN"),
         "exact attestation")
    token = request.get("github_token")
    need((not binding and token is None) or (binding and type(token) is str and
         (token.startswith("ghs_") or token.startswith("ghr_")) and
         20 <= len(token) <= 4096), "ephemeral Actions token only; no PAT")
    need(request["repository"] == REPO and
         type(request["source_commit"]) is str and
         re.fullmatch(r"[0-9a-f]{40}", request["source_commit"]) and
         request["source_commit"] == states["_lease_source_commit"] and
         type(request["workflow_commit"]) is str and
         re.fullmatch(r"[0-9a-f]{40}", request["workflow_commit"]) and
         all(type(request[k]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", request[k])
             for k in ("run_id", "attempt")), "attestation identity")
    need(request["mode"] in ("normal", "report_only") and
         type(request["consumer_started_epoch"]) is int and
         0 <= time.time() - request["consumer_started_epoch"] <= 30,
         "current attestation birth/mode")
    key = (request["run_id"], request["attempt"])
    if binding:
        need(key in states and states[key]["api_token"] is None and
             states[key]["used"] == states[key]["subjects"] == set() and
             states[key]["source_commit"] == request["source_commit"] and
             states[key]["workflow_commit"] == request["workflow_commit"] and
             states[key]["mode"] == request["mode"] and
             states[key]["producer"] == request["producer"] and
             states[key]["peer"] == peer["namespace"] and
             states[key]["attested_epoch"] <= request["consumer_started_epoch"] <=
             states[key]["attested_epoch"] + 21600,
             "one token binding to existing unused hook attestation")
    else:
        need(key not in states and len(states) < 1024, "single current attestation per job")
        remaining_job_window(lease, peer, int(time.time()))
    consumer = github(f"repos/{REPO}/actions/runs/{key[0]}/attempts/{key[1]}", token)
    branch = github(f"repos/{REPO}/branches/main", token)
    workflow = github(f"repos/{REPO}/actions/workflows/omen-robot.yml", token)
    need(consumer.get("id") == int(key[0]) and
         consumer.get("run_attempt") == int(key[1]) and
         consumer.get("workflow_id") == workflow.get("id") and
         workflow.get("path") == consumer.get("path") == ".github/workflows/omen-robot.yml" and
         consumer.get("head_repository", {}).get("full_name") == REPO and
         consumer.get("head_branch") == "main" and
         consumer.get("head_sha") == request["workflow_commit"] and
         branch.get("protected") is True and
         consumer.get("status") == "in_progress" and
         consumer.get("conclusion") is None and
         consumer.get("event") in ("workflow_run", "workflow_dispatch"),
         "fresh canonical consumer API identity")
    producer = request["producer"]
    if consumer["event"] == "workflow_run":
        need(type(producer) is dict and set(producer) ==
             {"id", "attempt", "workflow_id", "conclusion"}, "exact producer attestation")
        observed = github(f"repos/{REPO}/actions/runs/{producer['id']}/attempts/{producer['attempt']}", token)
        need(observed.get("name") in PRODUCER_PATHS and
             observed.get("path") == PRODUCER_PATHS[observed["name"]],
             "known producer workflow path/name")
        fixed_producer = github(f"repos/{REPO}/actions/workflows/{observed['path'].rsplit('/', 1)[1]}", token)
        need(observed.get("id") == producer["id"] and
             observed.get("run_attempt") == producer["attempt"] and
             observed.get("workflow_id") == producer["workflow_id"] == fixed_producer.get("id") and
             fixed_producer.get("path") == observed["path"] and
             fixed_producer.get("state") == "active" and
             observed.get("head_repository", {}).get("full_name") == REPO and
             type(observed.get("head_branch")) is str and bool(observed["head_branch"]) and
             re.fullmatch(r"[0-9a-f]{40}", observed.get("head_sha", "")) and
             observed.get("status") == "completed" and
             observed.get("conclusion") == producer["conclusion"] and
             request["mode"] == ("normal" if producer["conclusion"] == "success" else "report_only"),
             "exact producer API conclusion")
    else:
        need(producer is None and request["mode"] == "normal", "dispatch has no producer")
    need(peer_context(pid) == peer, "same live peer after attestation API")
    if binding:
        # Preserve the ORIGINAL hook epoch; token binding never renews a lease.
        states[key]["api_token"] = token
        return
    states[key] = {"source_commit": request["source_commit"],
                   "workflow_commit": request["workflow_commit"],
                   "mode": request["mode"], "attested_epoch": request["consumer_started_epoch"],
                   "used": set(), "subjects": set(), "producer": producer,
                   "api_token": None, "peer": peer["namespace"]}


def validate_request(request, states, peer):
    need(type(request) is dict and set(request) ==
         {"version", "action", "subject", "repository", "source_commit",
          "run_id", "attempt", "nonce", "consumer_started_epoch"}, "exact request schema")
    need(request["version"] == 2 and request["action"] in
         ("execute-vm", "execute-platform", "execute-produced-platform", "persist", "connection-proof"),
         "fixed host Engine action")
    subject = request["subject"]
    if request["action"] == "execute-vm":
        need(type(subject) is str and subject in states["_vm_ids"], "exact VM subject")
    elif request["action"] == "execute-platform":
        need(subject in ("windows", "ubuntu", "macos"), "exact platform subject")
    elif request["action"] == "execute-produced-platform":
        need(type(subject) is dict and set(subject) ==
             {"platform", "producer_run_id", "producer_attempt", "artifact_id", "descriptor_sha256"},
             "exact producer selection")
        need(subject["platform"] in ("ubuntu", "windows") and
             all(type(subject[k]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", subject[k])
                 for k in ("producer_run_id", "producer_attempt", "artifact_id")) and
             type(subject["descriptor_sha256"]) is str and
             re.fullmatch(r"[0-9a-f]{64}", subject["descriptor_sha256"]),
             "typed producer selection; no argv/path/authority")
    elif request["action"] == "connection-proof":
        need(subject == "ubuntu_native_chooser_connection", "exact scoped connection case")
    else:
        need(subject == "all", "exact summary subject")
    key = (request["run_id"], request["attempt"])
    need(request["repository"] == REPO and key in states and
         request["source_commit"] == states[key]["source_commit"] and
         type(request["nonce"]) is str and re.fullmatch(r"[0-9a-f]{32}", request["nonce"]),
         "attested job/nonce identity")
    need(states[key]["peer"] == peer["namespace"], "same attested job namespace/cgroup")
    if request["action"] in ("connection-proof", "execute-produced-platform"):
        need(states[key]["mode"] == "normal", "failed producer cannot request scoped VM effect")
    need(type(request["consumer_started_epoch"]) is int and
         states[key]["attested_epoch"] <= request["consumer_started_epoch"] <=
         states[key]["attested_epoch"] + 21600 and
         request["consumer_started_epoch"] <= time.time() + 30,
         "consumer birth after fixed hook")
    need(request["nonce"] not in states[key]["used"], "reused operation nonce")
    need(time.time() <= states[key]["attested_epoch"] + 21600,
         "expired GitHub job attestation")
    subject_key = (request["action"], json.dumps(subject, sort_keys=True, separators=(",", ":"))
                   if request["action"] == "execute-produced-platform" else subject)
    if request["action"] != "persist":
        need(subject_key not in states[key]["subjects"],
             "current job may attempt each subject only once")
        states[key]["subjects"].add(subject_key)
    # A failed trigger is diagnostic, not a global stop. The fixed host Engine's
    # planner must qualify the relevant source artifact for each actual case.
    states[key]["used"].add(request["nonce"])
    return key


def serve_once(conn, lease, states, engines):
    pid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(uid == 1000 and gid == 1000 and pid > 0, "runner peer identity")
    conn.settimeout(15)
    raw = bytearray()
    while len(raw) <= MAX_REQUEST and not raw.endswith(b"\n"):
        block = conn.recv(min(8192, MAX_REQUEST + 1 - len(raw)))
        need(block, "request EOF")
        raw.extend(block)
    need(len(raw) <= MAX_REQUEST and raw.endswith(b"\n"), "bounded complete request")
    request = strict(raw)
    need(type(request) is dict, "request object")
    peer = peer_context(pid)
    if request.get("kind") in ("OPEMOS_ROBOT_JOB_ATTESTATION", "OPEMOS_ROBOT_JOB_API_TOKEN"):
        attest(request, states, peer, pid, lease)
        conn.sendall(b'{"accepted":true}\n')
        return
    key = validate_request(request, states, peer)
    try:
        need(request.get("action") != "connection-proof" or
             lease.get("connection_proof_authorized") is True,
             "Legacy connection proof is not authorized by this control-only lease")
        # Each host engine is constructed only for its own fixed action. The
        # scoped connection does not inherit a full20/profile pass.
        conn.settimeout(21600)
        if request["action"] == "connection-proof":
            if "connection" not in engines:
                from connection_host import ConnectionHost
                engines["connection"] = ConnectionHost(lease)
            proof = engines["connection"].execute(request)
            public = []
            exchange = Path(lease["report_exchange"])
            need(str(exchange) == "/home/connor/.local/share/opemos-ci/github-runner/robot-private/reports",
                 "fixed public report exchange")
            meta = exchange.lstat()
            need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid() and
                 stat.S_IMODE(meta.st_mode) == 0o700 and not exchange.is_symlink(),
                 "exact private reports exchange custody")
            kinds = {"observer-rule-provision.json": "robot-output",
                     "job-result.json": "robot-output",
                     "connection-result.json": "robot-output",
                     "before-click.png": "screenshot", "after-click.png": "screenshot",
                     "proof-junit.xml": "robot-xunit", "proof.html": "robot-report",
                     "queue-terminal-summary.json": "queue-closure"}
            for name, data, sha in proof.pop("public"):
                need(name in kinds and len(data) <= 16 * 1024 * 1024,
                     "only bounded scoped public artifact")
                target_name = request["run_id"] + "-" + request["attempt"] + "-" + request["nonce"] + "-" + name
                target = exchange / target_name
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.fchmod(fd, 0o400)
                finally:
                    os.close(fd)
                public.append({"name": target_name, "sha256": sha,
                               "kind": kinds[name], "artifact": name,
                               "bytes": len(data)})
            response = {"identity": {k: request[k] for k in
                        ("repository", "source_commit", "run_id", "attempt", "nonce")},
                        "action": request["action"], "subject": request["subject"],
                        "scope": "CONNECTION_ONLY_OLD_ARTIFACT_NO_FULLSTACK_ACCEPTANCE",
                        "status": "passed" if proof["accepted"] else "failed", "scoped_connection": {
                            k: v for k, v in proof.items() if k != "public"},
                        "all20_passed": False, "all_platforms_passed": False,
                        "vms": {}, "platforms": {}, "public_evidence": public}
        else:
            if request["action"] == "execute-produced-platform":
                need(states[key]["api_token"] is not None, "post-hook job-token binding required")
            if "engine" not in engines:
                engines["engine"] = HostEngine(lease)
            response = engines["engine"].execute(request, github_token=states[(request["run_id"], request["attempt"])]["api_token"])
    except Exception as error:
        response = structured_failure(request, record_failure(lease, error))
    finally:
        if request["action"] == "persist":
            states[key]["api_token"] = None
    need(peer_context(pid) == peer, "same live peer before response")
    identity = response.get("identity", {})
    for key in ("repository", "source_commit", "run_id", "attempt", "nonce"):
        need(identity.get(key) == request[key], "host Engine response identity")
    encoded = json.dumps(response, separators=(",", ":"), allow_nan=False).encode()
    need(len(encoded) <= MAX_REPLY, "bounded host Engine response")
    conn.sendall(encoded + b"\n")


def main():
    need(os.getuid() == os.geteuid() == 1000, "queue owner")
    lease = json.loads(Path(sys.argv[1]).read_bytes())
    need(lease["kind"] == "OPEMOS_ROBOT_FIXED_CONTROL_LEASE" and
         lease["repository"] == REPO and lease["runtimeAuthorized"] is True,
         "exact fixed control lease")
    need(type(lease.get("engine_source_commit")) is str and
         re.fullmatch(r"[0-9a-f]{40}", lease["engine_source_commit"]),
         "pinned current source commit")
    engines = {}
    inventory_raw = held_bytes(Path(lease["engine_bundle"])/"ci/required-vms.json", 1048576,
                               lease["engine_pins"]["ci/required-vms.json"], require_root=True)
    vm_rows = strict(inventory_raw)["required_vms"]
    vm_ids = {row["id"] for row in vm_rows}
    need(len(vm_ids) == len(vm_rows) == 20, "pinned complete VM subjects")
    states = {"_lease_source_commit": lease["engine_source_commit"], "_vm_ids": vm_ids}
    root = Path(sys.argv[2])
    need(root.is_dir() and not root.is_symlink() and root.stat().st_uid == 1000 and
         root.stat().st_mode & 0o077 == 0, "private socket directory")
    path = root / "control.sock"
    need(not path.exists() and not path.is_symlink(), "fresh socket only")
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(path))
    os.chmod(path, 0o600)
    sock.listen(4)
    sock.settimeout(1)
    def stop(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    print(json.dumps({"stage": "FIXED_CONTROL_LISTENING", "socket": str(path)}), flush=True)
    try:
        while True:
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            with conn:
                try:
                    serve_once(conn, lease, states, engines)
                except Exception as error:
                    failure = record_failure(lease, error)
                    # No private host paths, inputs, credentials or source
                    # diagnostics cross back to the untrusted job.
                    try:
                        conn.sendall(json.dumps({"available": False,
                                                 "reason": "Fixed host operation refused or failed",
                                                 "failure": failure}).encode() + b"\n")
                    except OSError:
                        pass
    except KeyboardInterrupt:
        pass
    finally:
        for key, state in states.items():
            if isinstance(key, tuple): state["api_token"] = None
        sock.close()
        path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()

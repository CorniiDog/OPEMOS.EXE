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


PUBLIC_FAILURES = {'ACTIONS_TOKEN_REQUIRED': 'Existing ephemeral attested Actions token required', 'LEGACY_SCOPE_REFUSED': 'Legacy connection proof is not authorized by this control-only lease', 'TOKEN_BINDING_REQUIRED': 'A post-hook job-token binding is required before a produced-platform operation', 'HOST_OPERATION_FAILED': 'Host operation failed; retained private stage evidence remains authoritative'}

def public_failure_value(f):
    require(type(f) is dict and set(f) == {"kind", "code", "reason", "error_type", "private_recorded", "secondary"} and
            f["kind"] == "OPEMOS_BROKER_FAILURE_V1" and f["code"] in PUBLIC_FAILURES and
            f["reason"] == PUBLIC_FAILURES[f["code"]] and
            type(f["error_type"]) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", f["error_type"]) and
            type(f["private_recorded"]) is bool and
            f["secondary"] in ([], ["PRIVATE_FAILURE_PERSISTENCE_FAILED"]),
            "strict nonsecret failed broker cause")
    return f


def broker_failure(reply):
    if "failure" not in reply: return None
    require(set(reply) == {"identity", "action", "subject", "status", "all20_passed",
                          "all_platforms_passed", "vms", "platforms", "public_evidence",
                          "acceptance", "failure"} and
            reply["status"] == "failed" and reply["all20_passed"] is False and
            reply["all_platforms_passed"] is False and reply["vms"] == reply["platforms"] == {} and
            reply["public_evidence"] == [] and
            reply["acceptance"] == "SOURCE_AND_ACTUAL_CASE_ONLY; NO_INFERRED_FULLSTACK_PASS",
            "exact failed broker envelope")
    return public_failure_value(reply["failure"])


def outcome_reason(reply, fallback):
    failure = broker_failure(reply)
    return fallback if failure is None else "Root broker " + failure["code"] + ": " + failure["reason"]


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
        failure = broker_failure(reply)
        if failure is not None:
            try:
                # Authenticated nonsecret failure only; create once per operation.
                path = self.reports / ("broker-failure-" + request["nonce"] + ".json")
                raw = json.dumps(reply, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                require(len(raw) <= 4096, "small failed broker record")
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                fd = os.open(self.reports, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(fd)
                finally: os.close(fd)
            except Exception:
                raise ValueError(outcome_reason(reply, "host operation failed") +
                                 "; public failure receipt persistence failed") from None
        self._copy_public(reply.get("public_evidence", []), source=action=='execute-source-workload')
        # A retained-package connection proof cannot promote the independently
        # required current-source VM/platform cases, even via a malformed reply.
        if action in ("connection-proof",'execute-source-workload'):
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

    def _copy_public(self, rows, source=False):
        require(type(rows) is list and len(rows) <= (512 if source else 64), "public evidence count")
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
            require(total <= (5*1024**3 if source else MAX_PUBLIC_TOTAL), "public operation total cap")
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
        require(reply["status"] == "passed", outcome_reason(reply, "actual VM case failed; retained host evidence"))
        return {"exports": [{"path": str(self.reports / item["name"]),
                              "kind": item["kind"], "sha256": item["sha256"]}
                             for item in reply["public_evidence"]]}

    def platform(self, platform):
        require(platform in self.artifacts, "unknown platform")
        reply = self._request("execute-platform", platform)
        require(reply["status"] == "passed", outcome_reason(reply, "actual platform artifacts failed"))
        return {"exports": [{"path": str(self.reports / item["name"]),
                              "kind": item["kind"], "sha256": item["sha256"]}
                             for item in reply["public_evidence"]]}

    def produced_platform(self):
        """Exact producer target from hosted guard; host broker revalidates it."""
        target = strict_json(os.environ['OPEMOS_REQUIRED_PRODUCER'])
        keys={'platform','producer_run_id','producer_attempt','artifact_id','descriptor_sha256'}
        require(type(target)is dict and set(target)in(keys,keys|{'source_roles'}), 'exact finite producer target')
        if 'source_roles'in target:
            roles=target['source_roles']
            require(type(roles)is dict and set(roles)=={'repository','controller_commit','candidate_commit',
                    'pull_request','base_commit','repository_id','head_repository_id'}and
                    roles['repository']==REPO and roles['controller_commit']==roles['base_commit']==self.identity['source_commit']and
                    type(roles['candidate_commit'])is str and re.fullmatch('[0-9a-f]{40}',roles['candidate_commit'])and
                    roles['candidate_commit']!=roles['controller_commit']and
                    type(roles['pull_request'])is int and 0<roles['pull_request']<2**31 and
                    all(type(roles[k])is int and roles[k]>0 for k in('repository_id','head_repository_id'))and
                    roles['repository_id']==roles['head_repository_id'],'finite same-repository A/B target only')
        reply = self._request('execute-produced-platform', target)
        # Persist actual complete reply BEFORE a failure assertion. It contains
        # only public descriptors/typed outcome, never a host plan or disk bytes.
        path = self.reports / 'broker-required.json'
        raw = json.dumps(reply, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        require(len(raw) <= MAX_REPLY, 'finite exact broker required outcome')
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        except Exception:
            if broker_failure(reply) is not None:
                raise ValueError(outcome_reason(reply, "host operation failed") +
                                 "; required failure receipt persistence failed") from None
            raise
        require(reply['status'] == 'passed', outcome_reason(reply, 'exact current artifact GUI/SteamOS transaction failed or unavailable'))
        require(type(reply.get('required_acceptance')) is dict, 'current complete Root acceptance missing')
        if 'source_roles'in target:
            acceptance=reply['required_acceptance'];executable=acceptance.get('executable')
            require(acceptance.get('source_roles')==roles and
                    acceptance.get('controller_source_commit')==self.identity['source_commit']and
                    acceptance.get('source_commit')==roles['candidate_commit']and
                    type(executable)is dict and executable.get('source_commit')==roles['candidate_commit']and
                    executable.get('platform')==target['platform']and
                    all(executable.get(k)==target[k]for k in('producer_run_id','producer_attempt','artifact_id'))and
                    hashlib.sha256(json.dumps(executable,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()==target['descriptor_sha256'],
                    'Root acceptance belongs to another controller/candidate/package')
        return {'exports': [{'path': str(self.reports / item['name']), 'kind': item['kind'], 'sha256': item['sha256']} for item in reply['public_evidence']]}

    def connection(self):
        """Separately scoped real pointer/native-chooser proof, never fullstack."""
        reply = self._request("connection-proof", "ubuntu_native_chooser_connection")
        require(reply["status"] == "passed", outcome_reason(reply, "actual scoped connection proof failed"))
        require(reply.get("scope") == "CONNECTION_ONLY_OLD_ARTIFACT_NO_FULLSTACK_ACCEPTANCE",
                "connection proof scope missing")
        return {"exports": [{"path": str(self.reports / item["name"]),
                              "kind": item["kind"], "sha256": item["sha256"]}
                             for item in reply["public_evidence"]]}

    def source_workload(self, spec):
        from omen_source_workloads import selection, subject, verify_result
        selection(spec,self.identity['source_commit'])
        reply=self._request('execute-source-workload',spec)
        # Persist the complete actual response before asserting success. A
        # failed compiler is useful evidence, never GUI or package acceptance.
        target=self.reports/('source-workload-'+spec['workload']+'.json')
        raw=json.dumps(reply,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
        require(len(raw)<=MAX_REPLY,'bounded complete source reply')
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        require(reply['status']=='passed',outcome_reason(reply,'Actual OMEN source job failed/unavailable'))
        bound=subject(reply['source_subject'],self.identity['source_commit'])
        require(all(bound[k]==v for k,v in spec.items()),'Root substituted candidate/workload')
        verify_result(reply['source_result'],reply['identity'],bound)
        require(reply['source_closure']['unknown']==[] and all(reply['source_closure'].get(k)is True for k in
            ('domainAbsent','originalPIDStartAbsent','cgroupEmpty','ownedFDsClosed','hostUnchanged',
             'observerClosed','controlClosed','mediaUnchanged','originalBaseUnchanged')),
            'actual source VM closure incomplete')
        return reply

    def persist(self):
        reply = self._request("persist", "all")
        path = self.reports / ("summary-" + self.identity["run_id"] + "-" +
                               self.identity["attempt"] + "-" + str(time.monotonic_ns()) + ".json")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(reply, stream, sort_keys=True, indent=2)
                stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        except Exception:
            if broker_failure(reply) is not None:
                raise ValueError(outcome_reason(reply, "host persistence failed") +
                                 "; summary failure receipt persistence failed") from None
            raise
        require(reply["status"] == "recorded", outcome_reason(reply, "host outcome persistence failed"))
        return reply

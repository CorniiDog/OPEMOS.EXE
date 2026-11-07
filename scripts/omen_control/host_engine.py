#!/usr/bin/python3
"""Run the pinned, unmodified Robot Engine on the queue-charged host broker.

No request can select source, configuration, paths, commands or VM operands.
The Engine and its existing planner retain normal queue/source/VM admission.
"""
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import zipfile
import types
from pathlib import Path

REPO = "CorniiDog/OPEMOS.EXE"
EXCHANGE = "/media/connor/Games/OPEMOS/CI-artifacts/robot-runtime/reports"
KINDS = {"screenshot", "log", "boot-log", "pointer-action",
         "pointer-sender-lifecycle", "nvidia-loaded", "nvidia-render",
         "gpu-restoration", "queue-closure", "robot-output", "robot-log",
         "robot-report", "robot-xunit", "argv"}
MAX_PUBLIC = 16 * 1024 * 1024
MAX_PUBLIC_TOTAL = 256 * 1024 * 1024


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def held_bytes(path, cap, expected=None, require_root=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and a.st_size <= cap and
             not a.st_mode & 0o022 and (not require_root or a.st_uid == 0),
             "fixed bounded regular file custody")
        data = bytearray()
        while chunk := os.read(fd, min(65536, cap + 1 - len(data))):
            data.extend(chunk)
            need(len(data) <= cap, "fixed file cap")
        b = os.fstat(fd)
        need((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) ==
             (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns) and
             len(data) == a.st_size, "fixed file changed during read")
        if expected is not None:
            need(hashlib.sha256(data).hexdigest() == expected, "fixed source SHA")
        return bytes(data)
    finally:
        os.close(fd)


def verified_source_workflow(lease, read, commit):
    """Reuse the authenticated hook's verifier; no second compatibility table."""
    path = Path('/var/lib/opemos-robot-control-r1/guard/job_guard.py')
    source = held_bytes(path,262144,lease['guard_pins']['job_guard.py'],require_root=True)
    module = types.ModuleType('exact_source_producer_guard'); module.__file__ = str(path)
    exec(compile(source,str(path),'exec'),module.__dict__)
    pin = lease.get('producer_workflow_policy')
    need(type(pin) is dict and set(pin) == {'path','sha256'} and
         pin['path'] == str(path.with_name('ubuntu-producer-workflow.json')) and
         re.fullmatch('[0-9a-f]{64}',pin['sha256']),
         'current lease must independently grant the reviewed source-build workflow')
    return module.verify_source_workflow(read,commit,pin['sha256'])



class HostEngine:
    def __init__(self, lease):
        self.lease = lease
        self.bundle = Path(lease["engine_bundle"])
        self.pins = lease["engine_pins"]
        self.private_root = Path(lease["host_private_root"])
        self.exchange = Path(lease["report_exchange"])
        need(str(self.exchange) == EXCHANGE, "fixed shared report exchange")
        self.instances = {}
        self.required_modules = {}
        self.verify_bundle()
        for directory in (self.private_root, self.exchange):
            need(directory.is_dir() and not directory.is_symlink() and
                 directory.stat().st_uid == os.getuid() and
                 directory.stat().st_mode & 0o077 == 0,
                 "exact existing private host/report directory")

    def verify_bundle(self):
        need(self.bundle.is_dir() and not self.bundle.is_symlink() and
             self.bundle.stat().st_uid == 0 and
             not self.bundle.stat().st_mode & 0o022,
             "root-owned fixed Engine bundle")
        need(type(self.pins) is dict, "complete fixed Engine graph")
        required = {"scripts/omen_robot.py", "scripts/omen_ci_reader.py",
                    "scripts/omen_ci_stage.py", "scripts/omen_ci_inventory.py",
                    "scripts/omen_ci_executables.py", "scripts/omen_ci_result.py",
                    "scripts/OPEMOSPointer.py", "scripts/OPEMOSGuest.py",
                    "scripts/run_omen_robot_guest.py", "ci/required-vms.json",
                    "tests/robot/guest.robot", "tests/robot/role.robot",
                    "tests/robot/inventory.robot", "scripts/required_omen.py",
                    "scripts/check_full_stack_acceptance.py"}
        need(set(self.pins) == required, "fixed complete Engine graph")
        for relative, sha in self.pins.items():
            need(type(sha) is str and len(sha) == 64 and
                 not (self.bundle / relative).is_symlink(), "fixed source pin")
            held_bytes(self.bundle / relative, 8 * 1024 * 1024, sha, require_root=True)
        items = json.loads(held_bytes(self.bundle / "ci/required-vms.json", 1024 * 1024,
                                      self.pins["ci/required-vms.json"], require_root=True))
        self.vm_ids = {row["id"] for row in items["required_vms"]}
        need(len(items["required_vms"]) == len(self.vm_ids) and self.vm_ids,
             "unique configured VM identifiers")
        planner = Path(self.lease["planner_path"])
        profile = Path(self.lease["profile_path"])
        self.planner_bytes = held_bytes(planner, 8 * 1024 * 1024,
                                        self.lease["planner_sha256"], require_root=True)
        self.profile_bytes = held_bytes(profile, 1024 * 1024,
                                        self.lease["profile_sha256"], require_root=True)
        settings = json.loads(self.profile_bytes)
        need(settings.get("schema") == 1 and settings.get("enabled") is True and
             settings.get("hook", {}).get("path") == str(planner) and
             settings["hook"].get("sha256") == self.lease["planner_sha256"] and
             settings.get("stage", {}).get("sha256") ==
             self.pins["scripts/omen_ci_stage.py"],
             "exact enabled root-owned planner/profile pairing")

    def _load(self, staged):
        # Engine.modules() itself requires files owned by its effective UID.
        # Stage only the independently pinned bytes in a host-private directory;
        # the confined runner cannot traverse it. Read the executing module from
        # the verified descriptor bytes instead of reopening a mutable path.
        file = staged / "scripts/omen_robot.py"
        raw = held_bytes(file, 8 * 1024 * 1024,
                         self.pins["scripts/omen_robot.py"])
        spec = importlib.util.spec_from_file_location("opemos_fixed_host_engine", file)
        module = importlib.util.module_from_spec(spec)
        module.__file__ = str(file)
        exec(compile(raw, str(file), "exec"), module.__dict__)
        # Relocate only the independently pinned planner/profile bytes into
        # the Engine's private UID-owned runtime. Its installed(), hook(),
        # queue and VM methods execute unchanged and still verify SHA/custody.
        module.HOOK = str(staged / "fixed-planner.py")
        module.CONFIG = staged / "robot.json"
        return module

    def _run_directories(self, run, attempt):
        name = f"run-{run}-attempt-{attempt}"
        private = self.private_root / name
        reports = self.private_root / (name + "-reports")
        for directory in (private, reports):
            directory.mkdir(mode=0o700, exist_ok=True)
            s = directory.lstat()
            need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and
                 s.st_mode & 0o077 == 0, "private current-run directory")
        staged = private / "source"
        staged.mkdir(mode=0o700, exist_ok=True)
        for relative, sha in self.pins.items():
            source = self.bundle / relative
            target = staged / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            raw = held_bytes(source, 8 * 1024 * 1024, sha, require_root=True)
            if target.exists():
                need(held_bytes(target, 8 * 1024 * 1024, sha) == raw,
                     "private staged source drift")
            else:
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.fchmod(fd, 0o400)
                finally:
                    os.close(fd)
        planner = staged / "fixed-planner.py"
        if planner.exists():
            need(held_bytes(planner, 8 * 1024 * 1024,
                            self.lease["planner_sha256"]) == self.planner_bytes,
                 "private fixed planner drift")
        else:
            self._create_private(planner, self.planner_bytes)
        profile = json.loads(self.profile_bytes)
        profile["hook"]["path"] = str(planner)
        profile_bytes = (json.dumps(profile, sort_keys=True, separators=(",", ":")) + "\n").encode()
        installed_profile = staged / "robot.json"
        if installed_profile.exists():
            need(held_bytes(installed_profile, 1024 * 1024) == profile_bytes,
                 "private fixed profile drift")
        else:
            self._create_private(installed_profile, profile_bytes)
        return private, reports, staged

    @staticmethod
    def _create_private(path, raw):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.fchmod(fd, 0o400)
        finally:
            os.close(fd)

    def _engine(self, request):
        key = (request["run_id"], request["attempt"])
        if key not in self.instances:
            self.verify_bundle()
            private, reports, staged = self._run_directories(*key)
            os.environ.update(GITHUB_REPOSITORY=REPO,
                              GITHUB_RUN_ID=key[0], GITHUB_RUN_ATTEMPT=key[1],
                              OPEMOS_SOURCE_SHA=request["source_commit"],
                              OPEMOS_CONSUMER_STARTED_EPOCH=str(request["consumer_started_epoch"]),
                              OPEMOS_ROBOT_REPORT_DIR=str(reports))
            self.instances[key] = (self._load(staged).Engine(private), reports)
        return self.instances[key]

    def _required_module(self, request):
        """Load actual staged pinned dependencies, never confined runner source."""
        key = (request["run_id"], request["attempt"])
        if key not in self.required_modules:
            staged = self.private_root / f"run-{key[0]}-attempt-{key[1]}" / "source" / "scripts"
            previous = {name: sys.modules.get(name) for name in
                        ("check_full_stack_acceptance", "omen_ci_executables")}
            try:
                for name in ("check_full_stack_acceptance", "omen_ci_executables", "required_omen"):
                    relative = "scripts/" + name + ".py"
                    file = staged / (name + ".py")
                    raw = held_bytes(file, 8 * 1024 * 1024, self.pins[relative])
                    spec = importlib.util.spec_from_file_location("opemos_fixed_" + name, file)
                    module = importlib.util.module_from_spec(spec)
                    module.__file__ = str(file)
                    exec(compile(raw, str(file), "exec"), module.__dict__)
                    if name == "required_omen":
                        self.required_modules[key] = module
                    else:
                        sys.modules[name] = module
            finally:
                for name, original in previous.items():
                    if original is None:
                        sys.modules.pop(name, None)
                    else:
                        sys.modules[name] = original
        return self.required_modules[key]

    def _publish(self, exports, reports, request, inner_nonce):
        public = []
        total = 0
        need(type(exports) is list and len(exports) <= 64, "bounded public exports")
        need(type(inner_nonce) is str and re.fullmatch(r"[0-9a-f]{32}", inner_nonce),
             "actual Engine operation nonce")
        for item in exports:
            need(type(item) is dict and item.get("kind") in KINDS and
                 type(item.get("sha256")) is str and len(item["sha256"]) == 64,
                 "public evidence kind/hash")
            source = Path(item["path"])
            need(source.parent == reports and source.name.startswith(inner_nonce + "-"),
                 "only current operation public reports")
            data = held_bytes(source, MAX_PUBLIC, item["sha256"])
            total += len(data)
            need(total <= MAX_PUBLIC_TOTAL, "total current public evidence cap")
            name = request["run_id"] + "-" + request["attempt"] + "-" + source.name
            target = self.exchange / name
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fchmod(fd, 0o400)
            finally:
                os.close(fd)
            public.append({"name": name, "sha256": item["sha256"],
                           "kind": item["kind"], "bytes": len(data)})
        return public

    def _publish_source_packages(self,result,request):
        """Readback/export only; never execute/extract an AppImage on host."""
        package=result['package'];proof=result['guest_build'];expected=result['source_input']
        need(proof['source_commit']==expected['source_commit'] and
             proof['source_input_sha256']==expected['input']['archive_sha256'],
             'actual guest compiler/input provenance')
        provenance=proof['packaging_provenance'];native=provenance['nativeExecutable']
        need(provenance['sourceCommit']==expected['source_commit'] and
             native['method']=='actual-built-AppImage-extraction', 'guest packaging/native extraction proof')
        members=proof['packages']
        need(type(members)is list and 1<=len(members)<=4096 and
             len({m['name']for m in members})==len(members) and
             sum(m['bytes']for m in members)<=2147483648,'finite actual package member inventory')
        source=Path(package['path']);fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        identity=lambda value:{k:getattr(value,k)for k in fields}
        directory_name=request['run_id']+'-'+request['attempt']+'-'+result['identity']['nonce']+'-packages'
        directory=self.exchange/directory_name
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode)and before.st_uid==1000 and before.st_nlink==1 and
                 stat.S_IMODE(before.st_mode)==0o400 and before.st_size==package['bytes']<=2147483648 and
                 identity(before)==package['identity']==identity(source.lstat()),'closed generated package custody')
            digest=hashlib.sha256()
            while block:=os.read(fd,1048576):digest.update(block)
            need(digest.hexdigest()==package['sha256'],'actual exported guest ZIP full hash')
            os.lseek(fd,0,os.SEEK_SET);directory.mkdir(mode=0o700);os.chmod(directory,0o700)
            with os.fdopen(fd,'rb',closefd=False)as stream,zipfile.ZipFile(stream)as archive:
                need(set(archive.namelist())=={m['name']for m in members}and
                     len(archive.infolist())==len(members),'actual package ZIP matches guest output inventory')
                for expected_file in members:
                    name=expected_file['name'];path=Path(name);item=archive.getinfo(name)
                    need(not path.is_absolute()and path.parts and '..'not in path.parts and
                         '\\'not in name and '\x00'not in name and not item.flag_bits&1 and
                         item.file_size==expected_file['bytes']and
                         stat.S_IFMT(item.external_attr>>16)in(0,stat.S_IFREG),
                         'regular bounded package member, no links/escape/encryption')
                    target=directory/path;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                    out=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                    try:
                        actual=hashlib.sha256();size=0
                        with archive.open(item)as data:
                            while block:=data.read(1048576):
                                size+=len(block);need(size<=item.file_size,'package member expanded')
                                actual.update(block);view=memoryview(block)
                                while view:
                                    n=os.write(out,view);need(n>0,'package export write stalled');view=view[n:]
                        need(size==expected_file['bytes']and actual.hexdigest()==expected_file['sha256'],
                             'actual guest-to-host package byte readback')
                        os.fchmod(out,0o400);os.fsync(out)
                    finally:os.close(out)
            need(identity(before)==identity(os.fstat(fd))==identity(source.lstat()),
                 'retained guest package ZIP changed during export')
        finally:os.close(fd)
        built=[m for m in members if m['name']==native['packageName']]
        executable=[m for m in members if m['name']==native['name']]
        need(len(built)==len(executable)==1 and built[0]['sha256']==native['packageSHA256']and
             all(executable[0][k]==native[k]for k in('name','bytes','sha256')),
             'same actual AppImage/native outputs exported without rebuild')
        public={'kind':'OMEN_GUEST_PACKAGE_EXPORT_V1','candidate_source_commit':expected['source_commit'],
            'controller_source_commit':request['source_commit'],'queue_job_id':result['queue_job_id'],
            'source_input':expected,'guest_build':proof,'qemu':result['qemu'],'files':members,
            'package_zip_sha256':package['sha256'],'directory':directory_name,
            'package':built[0],'executable':executable[0],'GUIOrSteamOSAcceptance':False}
        raw=(json.dumps(public,sort_keys=True,indent=2)+'\n').encode()
        need(len(raw)<=1048576,'bounded actual guest compiler/export receipt')
        target=directory/'omen-guest-build.json'
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400)
        try:
            view=memoryview(raw)
            while view:
                n=os.write(fd,view);need(n>0,'source export receipt write stalled');view=view[n:]
            os.fchmod(fd,0o400);os.fsync(fd)
        finally:os.close(fd)
        return public

    def execute(self, request, github_token=None):
        self.verify_bundle()
        engine, reports = self._engine(request)
        # The source Engine sees the authenticated current operation, not a
        # caller-selected command, plan, source path or historical receipt.
        os.environ["OPEMOS_CONSUMER_STARTED_EPOCH"] = str(request["consumer_started_epoch"])
        action, subject = request["action"], request["subject"]
        if action == 'build-source-platform':
            helper=self._required_module(request)
            need(type(github_token)is str and github_token.startswith(('ghs_','ghr_')),
                 'attested ephemeral source-build job token')
            phase='authenticate source-input download job'
            try:
                read=helper.root_api_reader(github_token)
                expected=helper.source_input_ready(subject['producer_run_id'],subject['producer_attempt'],read,
                    lambda path:helper.metadata_download(path,token=github_token))
                phase='stage authenticated source input as opaque guest data'
                archive=engine.stage_source_input(expected,
                    lambda value,stream,cap:helper.download_bound_archive(value,stream,cap,github_token))
                phase='normal admitted Ubuntu guest compile/package and closure'
                result=engine.build_source(expected,archive)
                phase='actual package full-byte readback/export'
                exported=self._publish_source_packages(result,request)
                return {'identity':{k:request[k]for k in('repository','source_commit','run_id','attempt','nonce')},
                        'action':action,'subject':subject,'status':'passed','source_build':exported,
                        'all20_passed':False,'all_platforms_passed':False,'GUIOrSteamOSAcceptance':False}
            except Exception as first:
                failure={'phase':phase,'type':type(first).__name__}
                self._create_private(engine.output/'source-build-FIRST.json',
                    (json.dumps(dict(failure,reason=str(first)[:4000]),sort_keys=True)+'\n').encode())
                # Original detailed errors stay private; current typed stage is
                # returned promptly rather than leaving an indefinite busy wait.
                return {'identity':{k:request[k]for k in('repository','source_commit','run_id','attempt','nonce')},
                        'action':action,'subject':subject,'status':'failed','first_error':failure,
                        'all20_passed':False,'all_platforms_passed':False,'GUIOrSteamOSAcceptance':False,
                        'actual_source_failure':getattr(engine,'source_failure',{})}
        if action == "execute-produced-platform":
            helper = self._required_module(request)
            need(type(github_token) is str and
                 github_token.startswith(("ghs_", "ghr_")) and
                 20 <= len(github_token) <= 4096,
                 "existing ephemeral attested Actions token required")
            read = helper.root_api_reader(github_token)
            if subject['platform']=='ubuntu' and self.lease.get('producer_workflow_policy')is not None:
                producer=read(f"actions/runs/{subject['producer_run_id']}/attempts/{subject['producer_attempt']}")
                guard_path=Path('/var/lib/opemos-robot-control-r1/guard/job_guard.py')
                guard_raw=held_bytes(guard_path,262144,self.lease['guard_pins']['job_guard.py'],require_root=True)
                guard=types.ModuleType('fixed_producer_API');guard.__file__=str(guard_path)
                exec(compile(guard_raw,str(guard_path),'exec'),guard.__dict__)
                verified_source_workflow(self.lease,lambda path:guard.api(path,github_token),producer['head_sha'])
                native=[job for job in helper.items(read,f"actions/runs/{subject['producer_run_id']}/attempts/{subject['producer_attempt']}/jobs",'jobs')if job['name']=='appimage-package']
                need(len(native)==1 and native[0].get('runner_id')==21,
                     'Ubuntu package must actually be produced by the admitted OMEN guest workflow')
            result = helper.broker_execute_produced(
                engine, request, read,
                lambda path: helper.metadata_download(path, token=github_token),
                lambda expected, stream, cap: helper.download_candidate(
                    expected, stream, cap, github_token))
            public = []
            exports = result.get("exports", [])
            # Exact repeated public pins carry no additional evidence. Preserve
            # every distinct pin, reject conflicting kinds/hashes at one path.
            need(type(exports) is list, "actual public export list")
            unique = {}
            for item in exports:
                need(type(item) is dict and set(item) == {"path", "sha256", "kind"},
                     "exact current public export")
                path = item["path"]
                need(path not in unique or unique[path] == item,
                     "conflicting public export identity")
                unique[path] = item
            exports = list(unique.values())
            if exports:
                need(engine.current is not None, "actual operation required for exported evidence")
                inner = engine.current[0]["nonce"]
                public = self._publish(exports, reports, request, inner)
            actual_summary = self.summary(request, engine, public, result["status"])
            return helper.required_broker_reply(request, result, actual_summary, public)
        if action == "execute-vm":
            need(type(subject) is str and subject in self.vm_ids, "exact VM ID")
            operation_error = False
            try:
                engine.vm(subject)
            except Exception:
                operation_error = True  # Genuine failure/secondary evidence remain on host.
            row = engine.results[subject]
        elif action == "execute-platform":
            need(subject in ("windows", "ubuntu", "macos"), "exact platform")
            operation_error = False
            try:
                engine.platform(subject)
            except Exception:
                operation_error = True  # Independent artifact outcomes remain on host.
            row = engine.artifacts[subject]
        elif action == "persist":
            need(subject == "all", "exact summary subject")
            engine.persist()
            row = {"status": "recorded"}
        else:
            raise ValueError("fixed Engine action")
        if action == "persist":
            return self.summary(request, engine, [], "recorded")
        public = []
        if action == "execute-vm":
            inner = row.get("identity", {}).get("nonce")
            if inner is None and engine.current is not None:
                inner = engine.current[0]["nonce"]
            if row.get("exports"):
                public = self._publish(row["exports"], reports, request, inner)
            failure = row.get("failure_exports", {})
            if failure.get("exports"):
                public += self._publish(failure["exports"], reports, request, inner)
        else:
            for artifact in row.get("artifacts", {}).values():
                if artifact.get("exports"):
                    inner = artifact.get("identity", {}).get("nonce")
                    public += self._publish(artifact["exports"], reports, request, inner)
                failed = artifact.get("failure_exports", {}).get("exports", [])
                if failed:
                    nonces = {Path(item["path"]).name.split("-", 1)[0]
                              for item in failed}
                    need(len(nonces) == 1, "one actual failed artifact nonce")
                    public += self._publish(failed, reports, request, nonces.pop())
        need(sum(item["bytes"] for item in public) <= MAX_PUBLIC_TOTAL,
             "total operation public evidence cap")
        public = list({item["name"]: item for item in public}.values())
        status = "failed" if operation_error else row["status"]
        return self.summary(request, engine, public, status)

    def summary(self, request, engine, public, status):
        # Host-local diagnostics stay in the private Engine output. This is the
        # only response published to the sandbox/GitHub job.
        vms = {k: row["status"] for k, row in engine.results.items()}
        platforms = {k: row["status"] for k, row in engine.artifacts.items()}
        if status == "failed" and request["action"] == "execute-vm":
            vms[request["subject"]] = "failed"
        if status == "failed" and request["action"] == "execute-platform":
            platforms[request["subject"]] = "failed"
        all20 = all(row["status"] == "passed" for row in engine.results.values())
        all_platforms = all(row["status"] == "passed" for row in engine.artifacts.values())
        if status == "failed":
            all20 = False
            all_platforms = False
        return {"identity": {k: request[k] for k in
                             ("repository", "source_commit", "run_id", "attempt", "nonce")},
                "action": request["action"], "subject": request["subject"],
                "status": status, "all20_passed": all20,
                "all_platforms_passed": all_platforms,
                "vms": vms,
                "platforms": platforms,
                "public_evidence": public,
                "acceptance": "SOURCE_AND_ACTUAL_CASE_ONLY; NO_INFERRED_FULLSTACK_PASS"}

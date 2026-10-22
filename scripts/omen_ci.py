#!/usr/bin/env python3
"""Manual protected-main controller. SSH authority stays on its installed host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
from datetime import datetime
import urllib.error
import urllib.request

REPOSITORY = "CorniiDog/OPEMOS.EXE"
CONFIG = Path("/home/connor/.config/opemos-ci/controller.json")
CASES = ("windows-full-stack", "ubuntu-full-stack", "macos-full-stack", "steamos-autoheal", "nested-ubuntu-linux")
SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_RESULT_LIMIT=1024**2


def require(ok, message):
    if not ok:
        raise ValueError(message)


def strict_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "Duplicate JSON field")
            value[key] = item
        return value
    def invalid(value):
        raise ValueError("Nonfinite JSON value: " + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def trusted_event(env):
    require(env.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "Only manual workflow_dispatch is admitted")
    require(env.get("GITHUB_REPOSITORY") == REPOSITORY, "Canonical repository required")
    require(env.get("GITHUB_REF") == "refs/heads/main" and env.get("GITHUB_REF_PROTECTED") == "true",
            "Protected main dispatch required; PR/fork code is not admitted")
    require(COMMIT.fullmatch(env.get("GITHUB_SHA", "")), "Exact source commit missing")



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





def pinned(path, expected):
    path = Path(path)
    require(path.is_absolute() and str(path.resolve()) == str(path), "Pinned path must be absolute without symlink parents")
    pin, raw = _READER.read_verified(path, 8 * 1024**2, expected_sha=expected, uid=os.getuid())
    require(not pin["identity"]["st_mode"] & 0o022, "Pinned file is group/world writable")
    return raw


def sealed_bytes(raw, name, mode=0o600):
    """A generated sealed descriptor; no mutable path is consumed afterward."""
    import fcntl
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, "Complete sealed descriptor write")
            view = view[count:]
        os.lseek(fd, 0, os.SEEK_SET)
        flags = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, flags)
        require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) == flags, "Complete immutable descriptor seal")
        require(os.pread(fd, len(raw) + 1, 0) == raw, "Sealed descriptor readback")
        return fd
    except BaseException as primary:
        try:os.close(fd)
        except BaseException as close:
            raise ValueError("Sealed descriptor preparation failed; primary="+repr(primary)+"; close="+repr(close))from primary
        raise


def ssh_run(config, remote, request):
    """Consume one reviewed effective route; original config is audit input only.

    All config/Include/known-host bytes are descriptor-bound. The approved route
    is a closed effective snapshot of those sources, avoiding OpenSSH reopening
    mutable config dependencies. The existing private key stays local, sealed in
    an anonymous descriptor for this exact SSH invocation only.
    """
    pins = [config["ssh_config"], *config["ssh_dependencies"]]
    for item in pins:
        pinned(item["path"], item["sha256"])
    route = config["route"]
    closure = hashlib.sha256(json.dumps(pins, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    require(route["source_pins_sha256"] == closure, "Reviewed effective SSH route/source closure mismatch")
    require(route["hostname"] == "100.119.12.93" and route["user"] == "connor" and route["port"] == 22,
            "Only the existing approved outbound OMEN route is admitted")
    known = pinned(route["known_hosts"]["path"], route["known_hosts"]["sha256"])
    key_pin, key = _READER.read_verified(route["private_key_path"], 65536, uid=os.getuid())
    require(key_pin["identity"]["st_mode"] & 0o077 == 0, "Existing private key is not private")
    import types
    import uuid
    fds=[];primary=None;receipt=None;closed=[]
    directory=Path.cwd()/('ci-transport-'+uuid.uuid4().hex)
    directory.mkdir(mode=0o700)
    try:
        fds.append(sealed_bytes(known,"opemos-ci-known-hosts"))
        fds.append(sealed_bytes(key,"opemos-ci-existing-key"))
        proc="/proc/"+str(os.getpid())+"/fd/"
        command=["/usr/bin/ssh","-F","/dev/null","-oBatchMode=yes","-oStrictHostKeyChecking=yes",
                 "-oIdentitiesOnly=yes","-oGlobalKnownHostsFile=/dev/null","-oConnectTimeout=10","-oServerAliveInterval=15",
                 "-oServerAliveCountMax=2","-oUserKnownHostsFile="+proc+str(fds[0]),"-i",proc+str(fds[1]),
                 "-l",route["user"],"-p","22",route["hostname"],remote]
        receipt=_RESULT["capture"](command,request,config["result_contract"],directory/"process",3*3600+120)
    except BaseException as error:
        primary=error
        if hasattr(error,"transport_receipt"):receipt=error.transport_receipt
    finally:
        for index,fd in reversed(list(enumerate(fds))):
            row={"fd":fd,"role":"known-hosts"if index==0 else"private-key","closed":False}
            try:os.close(fd);row["closed"]=True
            except BaseException as error:row["close_failure"]=_RESULT["safe_error"](error,"Owned sealed descriptor close")
            closed.append(row)
    if receipt is None:
        receipt={"complete":False,"remote_closure":"UNKNOWN","local_reaped":False,"local_process_started":False,
                 "first_failure":_RESULT["safe_error"](primary or ValueError(),"SSH preparation")}
    try:identity=strict_json(request)
    except (ValueError,UnicodeError):identity={}
    receipt["request_identity"]={k:identity.get(k)for k in ("repository","run_id","attempt","source_commit","plan_sha256","stage_sha256")}
    receipt["sealed_descriptors"]=closed
    if primary is not None or any(not x["closed"]for x in closed):
        receipt["complete"]=False
        receipt.setdefault("first_failure",{"reason":"Owned sealed SSH descriptor closure UNKNOWN"})
    _RESULT["persist_transport"](directory/'sealed-closure.json',receipt)
    # A private small index points to complete immutable stdout/stderr capture.
    # Never include keys, original route/config contents or command arguments.
    _RESULT["persist_transport"]('ci-transport-index.json',receipt)
    if not receipt.get("complete"):raise _RESULT["TransportFailure"](receipt)from primary
    row=receipt["streams"]["stdout"]
    pin,raw=_READER.read_verified(row["path"],_RESULT["policy"](config["result_contract"])["max_bytes"],
        expected_sha=row["sha256"],expected_size=row["bytes"],uid=os.getuid())
    require(pin["identity"]==row["identity"],"Stored transport stdout full9 identity differs")
    return types.SimpleNamespace(stdout=raw,returncode=receipt["numeric_exit"],transport_receipt=receipt)


def installed_result_contract(env,optional=False):
    """Only verified installed configuration can enlarge the small hosted cap."""
    digest=env.get("OPEMOS_CONTROLLER_CONFIG_SHA256","")
    if optional and not digest:return None
    require(SHA.fullmatch(digest or ""),"Installed result configuration pin missing")
    config=strict_json(pinned(CONFIG,digest))
    return config,_RESULT["policy"](config["result_contract"])


def current_source_pin():
    return _READER.read_verified(Path(__file__).absolute(),8*1024**2,uid=os.getuid())[0]


def bound_pin(path,cap):
    pin,raw=_READER.read_verified(path,cap,uid=os.getuid())
    return {"path":str(Path(path).absolute()),"sha256":pin["sha256"],"bytes":pin["bytes"],"identity":pin["identity"]},strict_json(raw)


def verify_bound(item,cap):
    pin,raw=_READER.read_verified(item["path"],cap,expected_sha=item["sha256"],expected_size=item["bytes"],uid=os.getuid())
    require(pin["identity"]==item["identity"],"Control-bound full9 identity drift")
    return strict_json(raw)


def run_identity(env):
    return {"source_commit":env.get("GITHUB_SHA"),"run_id":env.get("GITHUB_RUN_ID"),"attempt":env.get("GITHUB_RUN_ATTEMPT")}


def zero_exit(value):
    return type(value)is int and value==0


def transport_closed(receipt):
    return (isinstance(receipt,dict)and receipt.get("complete")is True and receipt.get("local_process_started")is True
            and receipt.get("local_reaped")is True and zero_exit(receipt.get("numeric_exit"))
            and not receipt.get("close_failures")and not receipt.get("persistence_failures")
            and len(receipt.get("streams",{}))==2
            and all(row.get("EOF")is True and row.get("complete")is True and row.get("observation_verified")is True
                    and row.get("FD_closed")is True for row in receipt["streams"].values())
            and len(receipt.get("sealed_descriptors",[]))==2 and all(row.get("closed")is True for row in receipt["sealed_descriptors"]))


def record_dispatch_verdict(env,completed,result):
    summary,_=bound_pin("ci-summary.json",_RESULT_LIMIT)
    transport,receipt=bound_pin("ci-transport-index.json",1024**2)
    identity=run_identity(env)
    accepted=(all(result.get(k)==v for k,v in identity.items())and set(result.get("cases",{}))==set(CASES)
        and zero_exit(completed.returncode) and receipt==completed.transport_receipt and transport_closed(receipt)
        and result.get("aggregate",{}).get("status")=="passed"
        and result.get("executable_acceptance",{}).get("aggregate",{}).get("status")=="passed")
    value={"version":1,**identity,"controller_source":current_source_pin(),"summary":summary,"transport":transport,
           "dispatch_numeric_exit":0 if accepted else 1,"ssh_numeric_exit":completed.returncode,
           "accepted":bool(accepted),"remote_closure":"Only independently validated runtime receipts; local SSH does not establish it"}
    _RESULT["write_full"]("ci-dispatch-verdict.json",value,1024**2)
    return value


def record_control_verdict(env,code):
    """Actual parent wait outcome joins retained result before either publisher."""
    identity=run_identity(env);value={"version":1,**identity,"controller_source":current_source_pin(),
        "parent_numeric_exit":code,"accepted":False}
    try:
        summary,result=bound_pin("ci-summary.json",_RESULT_LIMIT)
        dispatch,d=bound_pin("ci-dispatch-verdict.json",1024**2)
        heavy,h=bound_pin("ci-heavy-control.json",1024**2)
        value.update(summary=summary,dispatch=dispatch,heavy=heavy)
        value["accepted"]=(zero_exit(code) and all(result.get(k)==v and d.get(k)==v and h.get(k)==v for k,v in identity.items())
            and d.get("summary")==summary and d.get("accepted")is True and zero_exit(d.get("dispatch_numeric_exit"))
            and zero_exit(h.get("numeric_exit")) and h.get("local_reaped")is True and h.get("local_process_started")is True
            and d.get("controller_source")==value["controller_source"]and h.get("controller_source")==value["controller_source"])
    except (ValueError,KeyError,TypeError,OSError)as error:
        value["first_failure"]=_RESULT["safe_error"](error,"Control acceptance evidence")
    _RESULT["write_full"]("ci-control-verdict.json",value,1024**2)
    return value


def publication_verdict(run_id,attempt,run,result):
    """Retained passing JSON alone never grants publication acceptance."""
    try:
        config,contract=installed_result_contract(os.environ)
        own=current_source_pin()
        require(own["sha256"]==config["controller_program_sha256"],"Installed controller source pin differs")
        _,control=bound_pin("ci-control-verdict.json",1024**2)
        require(control.get("accepted")is True and zero_exit(control.get("parent_numeric_exit")),
                "Actual parent control exit/closure refused or unknown")
        identity={"source_commit":run["head_sha"],"run_id":run_id,"attempt":attempt}
        require(all(control.get(k)==v for k,v in identity.items())and control.get("controller_source")==own,"Control source/run/attempt mismatch")
        stored=verify_bound(control["summary"],contract["max_bytes"])
        dispatch=verify_bound(control["dispatch"],1024**2);heavy=verify_bound(control["heavy"],1024**2)
        require(all(dispatch.get(k)==v and heavy.get(k)==v and stored.get(k)==v for k,v in identity.items()),"Child identity mismatch")
        require(dispatch.get("summary")==control["summary"]and dispatch.get("accepted")is True and zero_exit(dispatch.get("dispatch_numeric_exit"))
                and zero_exit(dispatch.get("ssh_numeric_exit")) and dispatch.get("controller_source")==own,"Dispatch verdict unverified")
        require(heavy.get("local_reaped")is True and heavy.get("local_process_started")is True and zero_exit(heavy.get("numeric_exit"))
                and heavy.get("controller_source")==own,"Actual heavy-child closure unverified")
        receipt=verify_bound(dispatch["transport"],1024**2)
        require(transport_closed(receipt),"Actual transport numeric/stream/descriptor closure refused")
        expected_identity={**identity,"repository":REPOSITORY}
        require(all(receipt.get("request_identity",{}).get(k)==v for k,v in expected_identity.items()),"Transport request identity mismatch")
        a=_INVENTORY["normalize"](stored,source=run["head_sha"],run_id=run_id,attempt=attempt)
        b=_INVENTORY["normalize"](result,source=run["head_sha"],run_id=run_id,attempt=attempt)
        require(all(a.get(k)==b.get(k)for k in ("vms","nonce","executable_acceptance")),"Publisher facts differ from exact bound summary")
        return {"accepted":True,"reason":"Actual zero parent/dispatch/SSH and closed custody bound to exact summary/source/run/attempt"}
    except (ValueError,KeyError,TypeError,AttributeError,OSError)as error:
        return {"accepted":False,"reason":"Control acceptance unavailable: "+type(error).__name__}


def write_summary(value):
    value = _INVENTORY["normalize"](value, source=value.get("source_commit") or os.environ.get("GITHUB_SHA"),
                                     run_id=value.get("run_id") or os.environ.get("GITHUB_RUN_ID"),
                                     attempt=value.get("attempt") or os.environ.get("GITHUB_RUN_ATTEMPT"),
                                     reason=value.get("error", "No actual current-run exact VM receipt"))
    _RESULT["write_full"]("ci-summary.json",value,_RESULT_LIMIT)
    return value


def inventory_report(env):
    """Always render20 rows; a formatting success is never acceptance."""
    try:
        global _RESULT_LIMIT
        installed=installed_result_contract(env,optional=True)
        _RESULT_LIMIT=installed[1]["max_bytes"]if installed else 1024**2
        if os.path.lexists("ci-summary.json"):
            _, raw = _READER.read_verified("ci-summary.json", _RESULT_LIMIT, uid=os.getuid())
            result = strict_json(raw)
            require(isinstance(result, dict), "Summary is not an object")
        else:
            result = {"error": "No controller result: preflight/tests/SSH/config unavailable"}
            write_summary(result)
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError) as exc:
        result = {"error": "Malformed/unavailable retained summary: " + str(exc)}
    result = _INVENTORY["normalize"](result, source=env.get("GITHUB_SHA") or result.get("source_commit"),
             run_id=env.get("GITHUB_RUN_ID") or result.get("run_id"), attempt=env.get("GITHUB_RUN_ATTEMPT") or result.get("attempt"))
    text = _INVENTORY["markdown"](result)
    summary = env.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(text)
    # Preserve every previous/corrupt file; the current hosted summary is still
    # rendered before any exclusive artifact creation can refuse an old path.
    if not os.path.lexists("ci-vms.md"):
        fd = os.open("ci-vms.md", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
    _RESULT["write_full"]("ci-inventory-report.json",result,_RESULT_LIMIT)


def runner_labels(payload, expected):
    require(expected and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", expected), "Exact controller runner name is not configured")
    matches = [r for r in payload.get("runners", []) if r.get("name") == expected]
    require(len(matches) == 1, "Exact controller runner is not registered")
    runner = matches[0]
    labels = {x["name"].lower() for x in runner.get("labels", [])}
    require(runner.get("status") == "online" and runner.get("busy") is False,
            "Exact controller runner is offline or busy; no job was queued")
    require({"self-hosted", "linux", "opemos-controller"} <= labels, "Controller runner labels missing")
    # A unique name-specific label prevents an unrelated runner receiving SSH work.
    require(expected.lower() in labels, "Controller requires its unique name label")
    return ["self-hosted", "linux", "opemos-controller", expected]


def preflight(env):
    trusted_event(env)
    require(env.get("OPEMOS_CI_ENABLED") == "true", "OMEN CI route is disabled/unconfigured; zero VM work queued")
    require(SHA.fullmatch(env.get("OPEMOS_CONTROLLER_CONFIG_SHA256", "")), "Installed controller configuration pin is missing")
    token = env.get("OPEMOS_RUNNER_READ_TOKEN")
    require(token, "Missing existing approved runner-metadata credential (Administration read); no SSH credential is requested")
    # Paginate rather than mistaking a first-page absence for zero runners.
    runners = []
    for page in range(1, 11):
        url = f"https://api.github.com/repos/{REPOSITORY}/actions/runners?per_page=100&page={page}"
        request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
                    "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                body = response.read(4 * 1024**2 + 1)
            require(len(body) <= 4 * 1024**2, "Runner metadata response cap")
            payload = strict_json(body)
        except urllib.error.HTTPError as exc:
            raise ValueError(f"Runner readiness API HTTP{exc.code}; route not admitted") from None
        runners.extend(payload.get("runners", []))
        if len(payload.get("runners", [])) < 100:
            break
    else:
        raise ValueError("Runner inventory exceeds bounded pagination")
    labels = runner_labels({"runners": runners}, env.get("OPEMOS_CONTROLLER_RUNNER"))
    with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write("runner=" + json.dumps(labels) + "\n")


def dispatch(env):
    trusted_event(env)
    config = strict_json(pinned(CONFIG, env.get("OPEMOS_CONTROLLER_CONFIG_SHA256")))
    require(config.get("version") == 1 and config.get("enabled") is True, "Installed controller route disabled")
    require(config.get("host") == "opemos-ubuntu-host", "Only existing reviewed OMEN host alias is admitted")
    program = config["remote_program"]
    require(Path(program["path"]).is_absolute() and SHA.fullmatch(program["sha256"]), "Remote installed-program pin missing")
    require(SHA.fullmatch(config["remote_config_sha256"]), "Remote configuration pin missing")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(re.fullmatch(r"[1-9][0-9]{0,19}", env.get(key, "")), "Exact GitHub run identity missing")
    request = {"version": 1, "action": "dispatch", "repository": REPOSITORY,
               "run_id": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"],
               "source_commit": env["GITHUB_SHA"], "plan_sha256": config["plan_sha256"],
               "config_sha256": config["remote_config_sha256"],
               "executables_sha256": env.get("OPEMOS_EXPECTED_EXECUTABLES_SHA256"),
               "consumer_started_epoch": int(env.get("OPEMOS_CONSUMER_STARTED_EPOCH", "0")),
               "stage_sha256":program["sha256"],"result_contract":_RESULT["policy"](config["result_contract"])}
    require(SHA.fullmatch(request["executables_sha256"] or "") and request["consumer_started_epoch"] > 0,
            "04 SteamOS exact independently verified executable expectation set required")
    global _RESULT_LIMIT
    _RESULT_LIMIT=request["result_contract"]["max_bytes"]
    # Execute verified installed bytes in memory: no check/exec path race and no
    # command, endpoint, VM operand, or script supplied by a PR or dispatch input.
    verifier = _READER_RAW.decode() + "\nimport sys\npin, raw = read_verified(sys.argv[1], 8*1024**2, expected_sha=sys.argv[2], uid=os.getuid())\nverified_namespace(raw, sys.argv[1], '__main__')\n"
    # Preserve installed config argument while the script executes its verified
    # bytes. Its canonical reader dependency is separately pinned and bound.
    verifier = verifier.replace("verified_namespace(raw, sys.argv[1], '__main__')", "path=sys.argv[1]; sys.argv=[path,sys.argv[3]]; verified_namespace(raw,path,'__main__')")
    remote = shlex.join(["/usr/bin/python3", "-I", "-c", verifier, program["path"], program["sha256"], config["remote_config"]])
    completed = ssh_run(config, remote, json.dumps(request).encode())
    require(len(completed.stdout) <= _RESULT_LIMIT, "Controller reply exceeded metadata bound")
    try:
        result = strict_json(completed.stdout)
    except (ValueError, UnicodeError):
        error=ValueError(f"OMEN reply absent/malformed; SSH exit{completed.returncode}; active work remains unknown")
        error.transport_receipt=completed.transport_receipt
        raise error from None
    require(isinstance(result, dict), "OMEN reply must be an object")
    local_pin,_=_READER.read_verified("ci-transport-index.json",1024**2,uid=os.getuid())
    result["local_transport_index"]={"path":str(Path("ci-transport-index.json").absolute()),"sha256":local_pin["sha256"],"bytes":local_pin["bytes"]}
    result = write_summary(result)
    record_dispatch_verdict(env,completed,result)
    require(result.get("source_commit") == request["source_commit"] and
            result.get("run_id") == request["run_id"] and result.get("attempt") == request["attempt"],
            "OMEN reply identity mismatch")
    require(set(result.get("cases", {})) == set(CASES), "OMEN omitted required case")
    require(completed.returncode == 0 and result["aggregate"]["status"] == "passed" and
            result.get("executable_acceptance", {}).get("aggregate", {}).get("status") == "passed",
            "One or more actual cases failed/unavailable; inspect ci-summary.json")


def enter_heavy(env):
    """Consume verified existing heavy source and exact controller bytes."""
    config = strict_json(pinned(CONFIG, env.get("OPEMOS_CONTROLLER_CONFIG_SHA256")))
    global _RESULT_LIMIT
    _RESULT_LIMIT=_RESULT["policy"](config["result_contract"])["max_bytes"]
    heavy = config["heavy_sh"]
    require(heavy["path"] == "/home/connor/Documents/ChatGPT/Handoff troubleshooting/opemos-scheduler/heavy.sh",
            "Existing heavy route required")
    heavy_body = pinned(heavy["path"], heavy["sha256"]).decode()
    source = str(Path(__file__).resolve())
    pinned(source, config["controller_program_sha256"])
    bootstrap = _READER_RAW.decode() + "\nimport sys\np=sys.argv[1]; h=sys.argv[2]; pin,raw=read_verified(p,8*1024**2,expected_sha=h,uid=os.getuid());sys.argv=[p,'dispatch'];verified_namespace(raw,p,'__main__')\n"
    child_env = dict(env, OPEMOS_CI_HEAVY_ENTRY="1")
    # bash -c consumes returned verified bytes; $0 retains the normal installed
    # script identity. No mutable heavy/controller source path is executed.
    receipt={"version":1,**run_identity(env),"controller_source":current_source_pin(),"local_process_started":False,"local_reaped":False}
    try:
        child=subprocess.Popen(["/bin/bash", "-c", heavy_body, heavy["path"], "/usr/bin/python3", "-I", "-c",
                               bootstrap, source, config["controller_program_sha256"]],env=child_env)
        receipt.update(local_process_started=True,local_pid=child.pid)
        try:
            raw=Path('/proc/'+str(child.pid)+'/stat').read_text();receipt["local_start"]=int(raw[raw.rindex(')')+2:].split()[19])
        except (OSError,ValueError):receipt["local_start"]="UNKNOWN"
        receipt["numeric_exit"]=child.wait();receipt["local_reaped"]=True
    except BaseException as error:
        receipt["first_failure"]=_RESULT["safe_error"](error,"Owned heavy-child lifecycle",receipt=receipt)
        _RESULT["persist_transport"]("ci-heavy-control.json",receipt)
        raise _RESULT["TransportFailure"](receipt)from error
    _RESULT["persist_transport"]("ci-heavy-control.json",receipt)
    return receipt["numeric_exit"]


def gh_api(endpoint, value=None):
    """Existing approved local gh session only; no token creation or upload."""
    require(endpoint.startswith("repos/" + REPOSITORY + "/"), "Canonical existing GitHub endpoint only")
    command = ["/usr/bin/gh", "api", endpoint]
    data = None
    if value is not None:
        command += ["--method", "POST", "--input", "-"]
        data = json.dumps(value).encode()
    response = subprocess.run(command, input=data, capture_output=True, timeout=30,
                              env=dict(os.environ, GH_HOST="github.com", GH_DEBUG=""))
    require(response.returncode == 0 and len(response.stdout) <= 4 * 1024**2,
            f"Existing gh session API operation failed (exit{response.returncode}); no new credential requested")
    return strict_json(response.stdout)


def status_context(run_id, attempt, case):
    return f"opemos/full-stack/{run_id}-{attempt}/{case}"


def current_gh_run(env):
    run_id = env.get("OPEMOS_GITHUB_RUN_ID", env.get("GITHUB_RUN_ID", ""))
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id), "Exact requested GitHub run ID required")
    run = gh_api(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    branch = gh_api(f"repos/{REPOSITORY}/branches/main")
    require(run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main" and
            run.get("path") == ".github/workflows/steamos.yml" and
            run.get("status") == "in_progress" and run.get("conclusion") is None and branch.get("protected") is True,
            "Only the live protected-main existing-controller request is admitted")
    attempt = str(run["run_attempt"])
    require(re.fullmatch(r"[1-9][0-9]{0,19}", attempt) and COMMIT.fullmatch(run.get("head_sha", "")), "GitHub request identity invalid")
    return run_id, attempt, run


def publish_vm_statuses(run_id, attempt, run, result):
    verdict=publication_verdict(run_id,attempt,run,result)
    result = _INVENTORY["normalize"](result, source=run["head_sha"], run_id=run_id, attempt=attempt)
    result["control_acceptance"]=verdict
    if not verdict["accepted"]:
        for row in result["vms"].values():row.update(status="failed",reason=verdict["reason"])
        result["aggregate"]["status"]="failed";result["cases"]=_INVENTORY["case_rollup"](result["vms"])
    url = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    for row in result["vms"].values():
        try:
            description = _INVENTORY["binding"](run_id, attempt, result.get("nonce"), row.get("runtime_instance_id"), row.get("case"), row.get("subject_role"))
        except ValueError:
            row["status"] = "failed"
            result["aggregate"]["status"] = "failed"
            result["cases"] = _INVENTORY["case_rollup"](result["vms"])
            description = _INVENTORY["binding"](run_id, attempt, result.get("nonce"), case=row.get("case"), role=row.get("subject_role"))
        gh_api(f"repos/{REPOSITORY}/statuses/{run['head_sha']}", {
            "state": "success" if row["status"] == "passed" else "failure", "context": row["github_context"],
            "description": description, "target_url": url})
    gh_api(f"repos/{REPOSITORY}/statuses/{run['head_sha']}", {
        "state": "success" if result["aggregate"]["status"] == "passed" else "failure",
        "context": _INVENTORY["AGGREGATE_CONTEXT"], "description": _INVENTORY["binding"](run_id, attempt, result.get("nonce")), "target_url": url})
    for case, row in result["cases"].items():
        gh_api(f"repos/{REPOSITORY}/statuses/{run['head_sha']}", {
            "state": "success" if row["status"] == "passed" else "failure", "context": status_context(run_id, attempt, case),
            "description": _INVENTORY["binding"](run_id, attempt, result.get("nonce")), "target_url": url})
    return result


def publish_existing(env):
    run_id, attempt, run = current_gh_run(env)
    global _RESULT_LIMIT
    _RESULT_LIMIT=_RESULT["policy"](strict_json(pinned(CONFIG,env.get("OPEMOS_CONTROLLER_CONFIG_SHA256")))["result_contract"])["max_bytes"]
    if os.path.lexists("ci-summary.json"):
        _, raw = _READER.read_verified("ci-summary.json", _RESULT_LIMIT, uid=os.getuid())
        result = strict_json(raw)
    else:
        result = {"error": "No actual current-run result; all exact VMs failed"}
    result = publish_vm_statuses(run_id, attempt, run, result)
    expected = consumer_expectations(run_id, attempt, run)
    artifacts = publish_executable_statuses(run_id, attempt, run, result, expected)
    require(result["aggregate"]["status"] == "passed" and artifacts["aggregate"]["status"] == "passed",
            "All20 exact VM rows, roles and every executable SteamOS output must pass")


def existing_gh(env):
    """Join one live protected manual request using existing local gh/SSH."""
    run_id, attempt, run = current_gh_run(env)
    code = 1
    expected = None
    child=dict(env,GITHUB_SHA=run["head_sha"],GITHUB_RUN_ID=run_id,GITHUB_RUN_ATTEMPT=attempt)
    try:
        expected = consumer_expectations(run_id, attempt, run)
        child = dict(env, GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REPOSITORY=REPOSITORY,
                     GITHUB_REF="refs/heads/main", GITHUB_REF_PROTECTED="true", GITHUB_SHA=run["head_sha"],
                     GITHUB_RUN_ID=run_id, GITHUB_RUN_ATTEMPT=attempt,
                     OPEMOS_EXPECTED_EXECUTABLES_SHA256=_EXECUTABLES["digest"](expected),
                     OPEMOS_CONSUMER_STARTED_EPOCH=str(int(datetime.fromisoformat(run["run_started_at"].replace("Z", "+00:00")).timestamp())))
        code = enter_heavy(child)
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError, subprocess.SubprocessError) as exc:
        if not os.path.lexists("ci-summary.json"):
            write_summary({"error": _RESULT["safe_error"](exc,"Existing control route")["reason"], "source_commit": run["head_sha"], "run_id": run_id, "attempt": attempt})
    if not os.path.lexists("ci-summary.json"):
        write_summary({"source_commit": run["head_sha"], "run_id": run_id, "attempt": attempt, "active": "unknown",
                       "error": f"Existing heavy/transport route exit{code}; no actual current-run VM result"})
    _, raw = _READER.read_verified("ci-summary.json", _RESULT_LIMIT, uid=os.getuid())
    record_control_verdict(child,code)
    result = publish_vm_statuses(run_id, attempt, run, strict_json(raw))
    artifacts = publish_executable_statuses(run_id, attempt, run, result, expected)
    require(code == 0 and result["aggregate"]["status"] == "passed" and artifacts["aggregate"]["status"] == "passed",
            "One or more exact required VMs or per-executable SteamOS output transactions failed/unavailable")


def wait_existing(env):
    trusted_event(env)
    require(env.get("OPEMOS_EXISTING_CONTROLLER_ENABLED") == "true", "Existing gh/outbound SSH controller is unconfigured; no VM work queued")
    token = env.get("GITHUB_TOKEN")
    require(token, "Built-in read-only GitHub workflow token missing")
    run_id, attempt = env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", "")
    require(all(re.fullmatch(r"[1-9][0-9]{0,19}", x) for x in (run_id, attempt)), "Exact workflow run identity missing")
    expected = read_expected_envelope(env)["expected_executables"]
    import time
    deadline = time.monotonic() + 3 * 3600
    latest = {}
    while time.monotonic() < deadline:
        for page in range(1, 11):
            url = f"https://api.github.com/repos/{REPOSITORY}/commits/{env['GITHUB_SHA']}/statuses?per_page=100&page={page}"
            req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=15) as response:
                body = response.read(4*1024**2 + 1)
            require(len(body) <= 4*1024**2, "GitHub status response cap")
            statuses = strict_json(body)
            for row in statuses:
                context = row.get("context")
                if context not in latest or row["id"] > latest[context]["id"]:
                    latest[context] = row
            if len(statuses) < 100:
                break
        rows, nonces = _INVENTORY["default_rows"]("No actual result for this run/attempt"), set()
        complete = True
        url = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
        for vm_id, row in rows.items():
            status = latest.get(row["github_context"], {})
            match = _INVENTORY["BINDING"].fullmatch(status.get("description", ""))
            bound = match and match.group(1) == run_id and match.group(2) == attempt and status.get("target_url") == url
            if not bound or status.get("state") not in ("success", "failure", "error"):
                complete = False
                continue
            row.update(status="passed" if status["state"] == "success" else "failed", runtime_instance_id=match.group(4),
                       status_id=status["id"], reason="Existing controller published exact stable VM context", nonce=match.group(3),
                       source_commit=env["GITHUB_SHA"], run_id=run_id, attempt=attempt, active=False,
                       case=_INVENTORY["CASE_CODES"].get(match.group(5)), subject_role=_INVENTORY["ROLE_CODES"].get(match.group(6)), bridge_status_verified=True)
            nonces.add(match.group(3))
        aggregate = latest.get(_INVENTORY["AGGREGATE_CONTEXT"], {})
        binding = _INVENTORY["BINDING"].fullmatch(aggregate.get("description", ""))
        aggregate_bound = (binding and binding.group(1) == run_id and binding.group(2) == attempt and aggregate.get("target_url") == url)
        case_rows = {c: latest.get(status_context(run_id, attempt, c), {}) for c in CASES}
        executable_view = _EXECUTABLES["status_view"](expected, latest, env["GITHUB_SHA"], run_id, attempt, url)
        if complete and aggregate_bound and aggregate.get("state") in ("success", "failure", "error") and executable_view["complete"]:
            passed = (len(nonces) == 1 and "unavailable" not in nonces and aggregate["state"] == "success" and
                      all(row["status"] == "passed" for row in rows.values()) and
                      all(row.get("state") == "success" and row.get("description") == aggregate.get("description")
                          and row.get("target_url") == url for row in case_rows.values()))
            vm_passed = passed
            passed = vm_passed and executable_view["aggregate"]["status"] == "passed"
            write_executable_report(executable_view)
            # Status-derived view is a report of the independently validated
            # bridge, not a new VM execution or local runtime-receipt validation.
            summary = {"source_commit": env["GITHUB_SHA"], "run_id": run_id, "attempt": attempt,
                       "nonce": next(iter(nonces)) if len(nonces) == 1 else None, "vms": rows,
                       "status_bridge_view": True, "coverage_verified": vm_passed, "observed_vm_ids": list(rows),
                       "executable_acceptance": executable_view,
                       "aggregate": {"status": "passed" if vm_passed else "failed", "required": 20},
                       "cases": {c: {"status": "passed" if row.get("state") == "success" else "failed"} for c, row in case_rows.items()}}
            # Keep exact per-VM status evidence in a separate metadata report;
            # normalizer cannot promote it into actual receipt verification.
            fd = os.open("ci-status-view.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as stream: json.dump(summary, stream)
            write_summary(summary)
            require(passed, "Existing controller reported failed/unavailable VM, case or aggregate")
            return
        time.sleep(15)
    write_executable_report(_EXECUTABLES["missing_report"](env["GITHUB_SHA"], run_id, attempt, "Exact VM/executable status bridge wait expired; active remote work retained", expected))
    write_summary({"source_commit": env["GITHUB_SHA"], "run_id": run_id, "attempt": attempt,
                   "cases": {c: {"status": "failed", "reason": "No complete actual case status from existing controller within bounded wait"} for c in CASES}})
    raise ValueError("Existing-controller wait expired; active remote work is retained, never cancelled")


def gh_bytes(endpoint, cap=256 * 1024):
    require(endpoint.startswith("repos/" + REPOSITORY + "/actions/artifacts/"), "Existing canonical artifact API only")
    # gh follows GitHub's short-lived artifact redirect; no new endpoint or key is configured.
    response = subprocess.run(["/usr/bin/gh", "api", endpoint], capture_output=True, timeout=30,
        env=dict(os.environ, GH_HOST="github.com", GH_DEBUG=""))
    require(response.returncode == 0 and len(response.stdout) <= cap, "Exact bounded metadata artifact download failed")
    return response.stdout


def write_executable_report(value):
    for name, raw in (("ci-executables-result.json", json.dumps(value, sort_keys=True).encode()),
                      ("ci-executables.md", _EXECUTABLES["markdown"](value).encode())):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream: stream.write(raw)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream: stream.write(_EXECUTABLES["markdown"](value))


def read_expected_envelope(env):
    _, raw = _READER.read_verified("ci-executables-expected.json", 1024**2, uid=os.getuid())
    value = strict_json(raw)
    require(value.get("source_commit") == env["GITHUB_SHA"] and value.get("run_id") == env["GITHUB_RUN_ID"]
            and value.get("attempt") == env["GITHUB_RUN_ATTEMPT"], "Expected executable envelope is from another consumer")
    _EXECUTABLES["validate_expected"](value.get("expected_executables"), env["GITHUB_SHA"])
    require(value.get("expected_sha256") == _EXECUTABLES["digest"](value["expected_executables"]), "Expected executable set changed")
    return value


def prepare_executables(env):
    trusted_event(env)
    selections = {p: env.get("OPEMOS_" + p.upper() + "_PRODUCER", "") for p in _EXECUTABLES["PRODUCERS"]}
    try:
        expected = _EXECUTABLES["expectations"](env["GITHUB_SHA"], selections, gh_api, gh_bytes)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        write_executable_report(_EXECUTABLES["missing_report"](env["GITHUB_SHA"], env["GITHUB_RUN_ID"],
            env["GITHUB_RUN_ATTEMPT"], _RESULT["safe_error"](error,"Producer metadata prerequisite")["reason"], getattr(error, "partial", None)))
        raise
    envelope = {"source_commit":env["GITHUB_SHA"], "run_id":env["GITHUB_RUN_ID"], "attempt":env["GITHUB_RUN_ATTEMPT"],
                "producer_selections":selections, "expected_executables":expected, "expected_sha256":_EXECUTABLES["digest"](expected)}
    fd = os.open("ci-executables-expected.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream: stream.write(_EXECUTABLES["canonical"](envelope))


def consumer_expectations(run_id, attempt, run):
    require(run.get("path") == ".github/workflows/steamos.yml", "Use 04 SteamOS with exact producer run:attempt inputs")
    expected_name = f"steamos-expectations-{run_id}-{attempt}"
    response = gh_api(f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100")
    require(response.get("total_count", 101) <= 100, "Consumer metadata enumeration overflow; no partial inventory accepted")
    matches = [x for x in response.get("artifacts", []) if x.get("name") == expected_name and x.get("expired") is False]
    require(len(matches) == 1, "Exact current 04 SteamOS expectation artifact unavailable; no VM launch")
    artifact = matches[0]
    value = _EXECUTABLES["archive_json"](gh_bytes(f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip"), artifact,
                                       "ci-executables-expected.json")
    require(value.get("source_commit") == run["head_sha"] and value.get("run_id") == run_id and value.get("attempt") == attempt,
            "Consumer expectation artifact belongs to another source/run/attempt")
    expected = _EXECUTABLES["expectations"](run["head_sha"], value["producer_selections"], gh_api, gh_bytes)
    require(value.get("expected_executables") == expected and value.get("expected_sha256") == _EXECUTABLES["digest"](expected),
            "Independently read producer metadata differs from hosted expectation artifact")
    return expected


def publish_executable_statuses(run_id, attempt, run, result, expected):
    verdict=publication_verdict(run_id,attempt,run,result)
    url = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    if expected is None:
        value = _EXECUTABLES["missing_report"](run["head_sha"], run_id, attempt, "Exact producer expectation set unavailable")
    else:
        value = _EXECUTABLES["report"](expected, result.get("executable_acceptance", {}).get("artifacts", {}), run["head_sha"], run_id, attempt)
        if not verdict["accepted"]:
            for row in value["artifacts"].values():row.update(status="failed",reason=verdict["reason"])
            value["aggregate"]["status"]="failed"
        value["control_acceptance"]=verdict
        for row in value["artifacts"].values():
            nonce = row.get("operation_nonce")
            if not re.fullmatch(r"[0-9a-f]{32}", nonce or ""): nonce = "unavailable"
            description = (_EXECUTABLES["binding"](run_id, attempt, row["executable"], nonce)
                           if nonce != "unavailable" else f"r:{run_id}/{attempt};e:{_EXECUTABLES['digest'](row['executable'])};n:unavailable")
            gh_api(f"repos/{REPOSITORY}/statuses/{run['head_sha']}", {"state":"success" if row["status"] == "passed" else "failure",
                "context":row["github_context"], "description":description, "target_url":url})
    gh_api(f"repos/{REPOSITORY}/statuses/{run['head_sha']}", {"state":"success" if value["aggregate"]["status"] == "passed" else "failure",
        "context":"opemos/steamos/all-executables", "description":f"r:{run_id}/{attempt};e:{_EXECUTABLES['digest'](expected) if expected else 'unavailable'}", "target_url":url})
    if not os.path.lexists("ci-executables-result.json"): write_executable_report(value)
    return value


def executable_report(env):
    if not os.path.lexists("ci-executables-result.json"):
        partial = None
        try: partial = read_expected_envelope(env)["expected_executables"]
        except (ValueError, KeyError, TypeError, OSError): pass
        write_executable_report(_EXECUTABLES["missing_report"](env.get("GITHUB_SHA"), env.get("GITHUB_RUN_ID"),
            env.get("GITHUB_RUN_ATTEMPT"), "No completed exact per-executable SteamOS acceptance result", partial))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "dispatch", "existing-gh", "wait-existing", "publish-existing", "inventory-report", "executables-prepare", "executables-report"))
    args = parser.parse_args()
    try:
        if args.action == "executables-prepare":
            prepare_executables(os.environ)
            return 0
        if args.action == "executables-report":
            executable_report(os.environ)
            return 0
        if args.action == "inventory-report":
            inventory_report(os.environ)
            return 0
        if args.action == "publish-existing":
            publish_existing(os.environ)
            return 0
        require(not os.path.lexists("ci-summary.json"), "Existing summary must be retained; use a fresh workflow checkout")
        if args.action == "preflight":
            preflight(os.environ)
        elif args.action == "wait-existing":
            wait_existing(os.environ)
        elif args.action == "existing-gh":
            existing_gh(os.environ)
        elif os.environ.get("OPEMOS_CI_HEAVY_ENTRY") != "1":
            code = enter_heavy(os.environ)
            record_control_verdict(os.environ,code)
            if code != 0 and not os.path.lexists("ci-summary.json"):
                write_summary({"status": "failed", "error": f"Existing heavy entry refused/failed exit{code}",
                               "cases": {c: {"status": "failed", "reason": "No admitted actual case result"} for c in CASES}})
            return code
        else:
            dispatch(os.environ)
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError, subprocess.SubprocessError) as exc:
        result = {"status": "failed", "error": _RESULT["safe_error"](exc,"Controller action")["reason"], "cases": {
            name: {"status": "failed", "reason": "Controller/route prerequisite unavailable; no acceptance claim"} for name in CASES}}
        if hasattr(exc,"transport_receipt"):result["transport_custody"]=exc.transport_receipt
        # Preserve the remote per-case causes instead of replacing them with a
        # generic failure after a legitimate negative result.
        summary = Path("ci-summary.json")
        if not os.path.lexists(summary):
            try:write_summary(result)
            except (ValueError,OSError)as secondary:
                # Preserve the complete failed partial separately; never retry
                # writing over it or replace the actual primary failure.
                _RESULT["write_full"]("ci-controller-failure.json",{"first_failure":_RESULT["safe_error"](exc,"Controller action"),
                    "summary_failure":_RESULT["safe_error"](secondary,"Controller summary persistence"),
                    "partial_summary_retained":True,"remote_closure":"UNKNOWN"},_RESULT["FALLBACK_MAX"])
        print(_RESULT["safe_error"](exc,"Controller action")["reason"], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())


#!/usr/bin/python3
"""Candidate queue-charged confined listener; Root installs after review."""
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from host_engine import held_bytes

RUNNER = Path("/home/connor/.local/share/opemos-ci/github-runner")
GUARD = Path("/var/lib/opemos-robot-control-r1/guard")


def need(ok, why):
    if not ok:
        raise RuntimeError(why)


def control_policy_bytes(lease):
    """Authenticate the listener's finite source grant independently of VM scope."""
    pin = lease['connection_fixed_policy']
    need(type(pin) is dict and set(pin) == {'path', 'sha256'} and
         type(pin['sha256']) is str and len(pin['sha256']) == 64 and
         all(c in '0123456789abcdef' for c in pin['sha256']), 'fixed control policy pin')
    raw = held_bytes(Path(pin['path']), 16384, pin['sha256'], require_root=True)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, 'duplicate control policy field')
            value[key] = item
        return value
    policy = json.loads(raw, object_pairs_hook=unique)
    need(type(policy) is dict and policy.get('repository') == lease['repository'] == 'CorniiDog/OPEMOS.EXE'
         and type(policy.get('sourceCommit')) is str and len(policy['sourceCommit']) == 40
         and all(c in '0123456789abcdef' for c in policy['sourceCommit'])
         and policy.get('sourceCommit') == lease['engine_source_commit']
         and policy.get('runtimeAuthorized') is True
         and type(policy.get('notBefore')) is int and type(policy.get('expiresAt')) is int
         and policy['notBefore'] <= time.time() < policy['expiresAt']
         and 0 < policy['expiresAt'] - policy['notBefore'] <= 7 * 86400,
         'Root control policy source/authority/finite lease')
    return raw, policy, pin['sha256']


def control_source_environment(lease):
    """Job-start hooks inherit process env, not workflow/job-level env."""
    _, policy, _ = control_policy_bytes(lease)
    return ['--setenv', 'OPEMOS_SOURCE_SHA', policy['sourceCommit']]


def main():
    need(os.getuid() == os.geteuid() == 1000, "ordinary owner")
    cg = Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]
    need(cg.startswith("/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/opemos-testq-")
         and cg.endswith(".service"), "ordinary queue unit required")
    cgroup = Path("/sys/fs/cgroup") / cg.lstrip("/")
    need((cgroup / "memory.max").read_text().strip() == "1073741824" and
         (cgroup / "memory.swap.max").read_text().strip() == "0" and
         (cgroup / "cpu.max").read_text().split() == ["100000", "100000"],
         "exact 1CPU/1GiB/no-swap reservation")
    lease = json.loads(Path(sys.argv[1]).read_bytes())
    need(lease["kind"] == "OPEMOS_ROBOT_FIXED_CONTROL_LEASE" and
         lease["runtimeAuthorized"] is True and
         lease["repository"] == "CorniiDog/OPEMOS.EXE", "fixed lease")
    source_environment = control_source_environment(lease)
    profile_path = Path('/home/connor/.config/opemos-ci/robot.json')
    registry_path = Path('/home/connor/.config/opemos-ci/robot-jobs.json')
    planner_path = Path('/var/lib/opemos-robot-control-r1/opemos-robot-job-plan')
    need(lease['profile_path'] == str(profile_path) and
         lease['planner_path'] == str(planner_path),
         'exact installed profile/planner route')
    profile = json.loads(held_bytes(profile_path, 1024 * 1024,
                                    lease['profile_sha256'], require_root=True))
    held_bytes(planner_path, 8 * 1024 * 1024,
               lease['planner_sha256'], require_root=True)
    need(profile.get('enabled') is True and
         profile.get('hook', {}).get('path') == str(planner_path) and
         profile['hook'].get('sha256') == lease['planner_sha256'] and
         profile.get('fixed_registry', {}).get('path') == str(registry_path),
         'fixed enabled planner/profile/registry join')
    registry = json.loads(held_bytes(registry_path, 4 * 1024 * 1024,
                                     profile['fixed_registry']['sha256']))
    need(registry.get('source_commit') == lease['engine_source_commit'] and
         type(registry.get('cases')) is dict and len(registry['cases']) == 20,
         'current Main exact20 registry join')
    need(RUNNER.is_dir() and GUARD.is_dir(), "installed dependencies")
    exchange = Path('/media/connor/Games/OPEMOS/CI-artifacts/robot-runtime/reports')
    need(exchange.is_dir() and not exchange.is_symlink() and
         exchange.stat().st_uid == 1000 and exchange.stat().st_mode & 0o077 == 0,
         "fixed private reports exchange missing")
    manifest = Path(lease["manifest"]["path"])
    raw = manifest.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == lease["manifest"]["sha256"],
         "installed program manifest pin")
    items = json.loads(raw)
    need(type(items) is list and len(items) <= 100000, "bounded manifest")
    for item in items:
        relative = Path(item["path"])
        need(not relative.is_absolute() and ".." not in relative.parts,
             "installed program path")
        path = RUNNER / relative
        if "symlink" in item:
            need(path.is_symlink() and os.readlink(path) == item["symlink"] and
                 path.resolve().is_relative_to(RUNNER), "runner program link")
        else:
            s = path.lstat()
            need(stat.S_ISREG(s.st_mode) and s.st_size == item["bytes"],
                 "runner program file")
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1048576), b""):
                    digest.update(block)
            need(digest.hexdigest() == item["sha256"], "runner program bytes")
    runner = json.loads((RUNNER / ".runner").read_text(encoding="utf-8-sig"))
    need(runner["agentName"] == "opemos-omen-robot" and
         runner["agentId"] == lease["runnerId"], "registered runner identity")
    for name in (".credentials", ".credentials_rsaparams"):
        s = (RUNNER / name).lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 1000 and not s.st_mode & 0o077,
             "private registered runner credential")
    required_env = {
        "ACTIONS_RUNNER_HOOK_JOB_STARTED=/var/lib/opemos-robot-control-r1/guard/job-started.sh",
        "PYTHONPATH=/home/connor/.local/share/opemos-ci/github-runner/robot-python",
        "OPEMOS_ROBOT_PYTHON=/usr/bin/python3",
        "OPEMOS_ROBOT_PRIVATE_RESULTS=/home/connor/.local/share/opemos-ci/robot-private",
    }
    env_raw = held_bytes(RUNNER / '.env', 65536, lease['runner_env_sha256'])
    env_meta = (RUNNER / '.env').lstat()
    need(env_meta.st_uid == 1000 and stat.S_IMODE(env_meta.st_mode) == 0o600 and
         required_env.issubset(set(env_raw.decode().splitlines())),
         "fixed runner hook/runtime environment")
    for name in ("_work", "_diag"):
        item = RUNNER / name
        need(item.is_dir() and not item.is_symlink() and item.stat().st_uid == 1000,
             "exact isolated writable runner directory")
    for name in ("job_guard.py", "job-started.sh"):
        p = GUARD / name
        s = p.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
             "root-owned external fixed guard")
        need(hashlib.sha256(p.read_bytes()).hexdigest() == lease["guard_pins"][name],
             "exact guard pin")
    socket_dir = Path(sys.argv[2])
    need(socket_dir.parent == Path('/run/user/1000') and
         socket_dir.name.startswith('opemos-robot-control-') and
         len(socket_dir.name) == len('opemos-robot-control-') + 32 and
         all(c in '0123456789abcdef' for c in socket_dir.name[-32:]) and
         not os.path.lexists(socket_dir), 'fresh exact private socket directory')
    parent = socket_dir.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 1000 and
         stat.S_IMODE(parent.st_mode) == 0o700,
         'owner runtime parent custody')
    socket_dir.mkdir(mode=0o700)
    parent_fd = os.open(socket_dir.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(parent_fd)
    finally: os.close(parent_fd)
    controller = subprocess.Popen(["/usr/bin/python3", str(Path(__file__).with_name("control.py")),
                                   sys.argv[1], sys.argv[2]], stdin=subprocess.DEVNULL,
                                  start_new_session=True)
    # No host home, SSH, originals, user config or host /run is mounted.
    # The official runner and its _work are the only writable host tree.
    argv = ["/usr/bin/sudo", "-n", "/usr/bin/bwrap",
            "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
            "--die-with-parent",
            "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64",
            "--dir", "/etc", "--ro-bind", "/etc/ssl", "/etc/ssl", "--ro-bind", "/etc/passwd", "/etc/passwd",
            "--ro-bind", "/etc/group", "/etc/group",
            "--ro-bind", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
            "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf",
            "--ro-bind", "/etc/hosts", "/etc/hosts", "--proc", "/proc",
            "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home",
            "--dir", "/home/connor", "--dir", "/home/connor/.local",
            "--dir", "/home/connor/.local/share", "--dir", "/home/connor/.local/share/opemos-ci",
            "--ro-bind", str(RUNNER), str(RUNNER),
            "--bind", str(RUNNER / "_work"), str(RUNNER / "_work"),
            "--bind", str(RUNNER / "_diag"), str(RUNNER / "_diag"),
            "--bind", "/home/connor/.local/share/opemos-ci/robot-private", "/home/connor/.local/share/opemos-ci/robot-private",
            "--dir", "/media", "--dir", "/media/connor", "--dir", "/media/connor/Games",
            "--dir", "/media/connor/Games/OPEMOS", "--dir", "/media/connor/Games/OPEMOS/CI-artifacts",
            "--dir", "/media/connor/Games/OPEMOS/CI-artifacts/robot-runtime",
            "--ro-bind", "/media/connor/Games/OPEMOS/CI-artifacts/robot-runtime/reports", "/media/connor/Games/OPEMOS/CI-artifacts/robot-runtime/reports",
            # Keep old04's read-only report spelling as an alias of the new
            # separate-partition data. No original report directory is moved.
            "--ro-bind", str(exchange), "/home/connor/.local/share/opemos-ci/github-runner/robot-private/reports",
            "--dir", "/var", "--dir", "/var/lib",
            "--dir", "/var/lib/opemos-robot-control-r1",
            "--ro-bind", "/var/lib/opemos-robot-control-r1/opemos-robot-job-plan", "/var/lib/opemos-robot-control-r1/opemos-robot-job-plan",
            "--dir", "/home/connor/.config", "--dir", "/home/connor/.config/opemos-ci",
            "--ro-bind", "/home/connor/.config/opemos-ci/robot.json", "/home/connor/.config/opemos-ci/robot.json",
            "--ro-bind", "/home/connor/.config/opemos-ci/robot-jobs.json", "/home/connor/.config/opemos-ci/robot-jobs.json",
            "--ro-bind", str(GUARD), str(GUARD),
            "--dir", "/run", "--dir", "/run/opemos-ci",
            "--bind", str(socket_dir), "/run/opemos-ci/control",
            "--ro-bind", lease["engine_bundle"], "/run/opemos-ci/engine",
            "--chdir", str(RUNNER), "--setenv", "HOME", "/home/connor",
            *source_environment,
            "--setenv", "OPEMOS_ROBOT_CONTROL_SOCKET", "/run/opemos-ci/control/control.sock",
            "--setenv", "ACTIONS_RUNNER_HOOK_JOB_STARTED", str(GUARD / "job-started.sh"),
            "--setenv", "PYTHONPATH", str(RUNNER / "robot-python"),
            "--setenv", "OPEMOS_ROBOT_PYTHON", "/usr/bin/python3",
            "--setenv", "OPEMOS_ROBOT_PRIVATE_RESULTS", "/home/connor/.local/share/opemos-ci/robot-private",
            "--setenv", "OPEMOS_ROBOT_REPORT_EXCHANGE", "/media/connor/Games/OPEMOS/CI-artifacts/robot-runtime/reports",
            "--", "/usr/bin/setpriv", "--reuid=1000", "--regid=1000",
            "--clear-groups", "--no-new-privs", str(RUNNER / "bin/Runner.Listener"), "run", "--startuptype", "service"]
    print(json.dumps({"stage": "CONFINED_LISTENER_START", "cgroup": cg,
                      "memoryBytes": 1073741824, "cores": 1,
                      "vmAdmission": False}), flush=True)
    reason = None
    code = None
    try:
        for _ in range(50):
            if (socket_dir / "control.sock").is_socket():
                break
            need(controller.poll() is None, "fixed controller exited")
            time.sleep(.1)
        need((socket_dir / "control.sock").is_socket(), "control socket not ready")
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            code = child.wait(timeout=21500)
        except subprocess.TimeoutExpired:
            reason = "finite queue lease approaching expiry"
            os.killpg(child.pid, signal.SIGTERM)
            try:
                code = child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                code = child.wait(timeout=10)
    finally:
        if controller.poll() is None:
            os.killpg(controller.pid, signal.SIGTERM)
        try:
            controller.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(controller.pid, signal.SIGKILL)
            controller.wait(timeout=5)
        try:
            socket_dir.rmdir()  # control.py removed its exact owned socket.
            parent_fd = os.open(socket_dir.parent,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: os.fsync(parent_fd)
            finally: os.close(parent_fd)
        except OSError as error:
            reason = reason or ('private socket closure: ' + str(error))
    print(json.dumps({"stage": "LISTENER_CLOSED", "numeric": code,
                      "listenerReaped": True, "controllerReaped": True,
                      "firstFailure": reason,
                      "wholeUnitClosure": "ordinary queue verifies cgroup"}), flush=True)
    return code if code not in (None, 0) else (1 if reason else 0)


if __name__ == "__main__":
    raise SystemExit(main())

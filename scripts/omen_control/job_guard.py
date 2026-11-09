#!/usr/bin/python3
"""Fixed GitHub pre-job hook; authentication only, never VM admission."""
import json
import base64
import hashlib
import os
import re
import socket
import stat
import struct
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

REPO = "CorniiDog/OPEMOS.EXE"
# The existing hook and token-binding shell both have a 45-second whole limit.
# Leave time to report/exit; API reads and the broker share this one budget.
GUARD_SECONDS = 40
WORKFLOW_PATH = ".github/workflows/omen-robot.yml"
PRODUCER_PATHS = {
    "01 Windows EXE": ".github/workflows/windows-portable.yml",
    "02 Ubuntu AppImage": ".github/workflows/ubuntu-executable.yml",
    "03 macOS Executable": ".github/workflows/macos-arm64.yml",
}


def need(value, why):
    if not value:
        raise ValueError(why)


class GuardTimeout(TimeoutError):
    """Only a fixed nonsecret classification crosses the job boundary."""


def remaining(deadline, limit=None):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise GuardTimeout("original fixed guard budget exhausted")
    return seconds if limit is None else min(limit, seconds)


def number(value):
    need(type(value) is int and value > 0, "positive numeric identity required")
    return value


def bounded_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= 1048576,
             "bounded regular event required")
        raw = os.read(fd, 1048577)
        after = os.fstat(fd)
        need(len(raw) <= 1048576 and
             all(getattr(before, key) == getattr(after, key) for key in
                 ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")),
             "event mutated or oversized")
        return json.loads(raw)
    finally:
        os.close(fd)


class NoGitHubRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api(path, token=None, *, deadline=None):
    need(not path.startswith("/") and ".." not in path, "fixed API path")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "OPEMOS-fixed-job-guard"}
    if token is not None: headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request("https://api.github.com/" + path, headers=headers)
    if deadline is None:
        deadline = time.monotonic() + GUARD_SECONDS
    try:
        with urllib.request.build_opener(NoGitHubRedirect()).open(request, timeout=remaining(deadline, 15)) as response:
            raw = response.read(1048577)
        remaining(deadline)
    except TimeoutError:
        raise GuardTimeout("original fixed guard API budget exhausted") from None
    except urllib.error.HTTPError as refused:
        refused.close()
        raise

    need(len(raw) <= 1048576, "API response oversized")
    return json.loads(raw)


def broker_attestation(control_path, attestation, deadline):
    """The broker authenticates through GitHub before replying, not in five seconds."""
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(remaining(deadline))
            connection.connect(control_path)
            peer_pid, peer_uid, peer_gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            # Keep the actual outside-namespace broker requirement unchanged.
            need(peer_pid == 0 and peer_uid == peer_gid == 1000, "fixed outside-namespace broker peer")
            connection.settimeout(remaining(deadline))
            connection.sendall(json.dumps(attestation, separators=(",", ":")).encode() + b"\n")
            raw = bytearray()
            while len(raw) <= 4096 and not raw.endswith(b"\n"):
                connection.settimeout(remaining(deadline))
                part = connection.recv(min(4096, 4097 - len(raw)))
                need(part, "host control attestation EOF")
                raw.extend(part)
            remaining(deadline)
            need(len(raw) <= 4096 and raw.endswith(b"\n"), "bounded attestation reply")
            return json.loads(raw)
    except TimeoutError:
        raise GuardTimeout("original fixed guard broker budget exhausted") from None


def source_workflow_policy(expected_sha=None):
    path = Path(__file__).with_name('ubuntu-producer-workflow.json')
    fd = os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
             stat.S_IMODE(before.st_mode) == 0o444 and before.st_nlink == 1 and
             before.st_size <= 65536,'Root-owned source-producer workflow selection')
        raw = os.read(fd,65537)
        fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                  'st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw) == before.st_size and all(getattr(before,k) ==
             getattr(os.fstat(fd),k) == getattr(path.lstat(),k) for k in fields),
             'source workflow policy changed')
        need(expected_sha is None or hashlib.sha256(raw).hexdigest() == expected_sha,
             'source workflow policy differs from current controller lease')
    finally: os.close(fd)
    value = json.loads(raw)
    need(set(value) == {'kind','repository','workflow','bodySHA256','inputPrograms'} and
         value['kind'] == 'REVIEWED_UBUNTU_SOURCE_PRODUCER_WORKFLOW_V1' and
         value['repository'] == REPO and
         value['workflow'] == '.github/workflows/ubuntu-executable.yml' and
         re.fullmatch('[0-9a-f]{64}',value['bodySHA256']) and
         set(value['inputPrograms']) == {'scripts/prepare_ubuntu_source_inputs.py',
                                          'scripts/acquire_appliance_windows.py'},
         'exact source-producer role, not arbitrary candidate host execution')
    return value


def verify_source_workflow(read, workflow_commit, expected_policy_sha=None):
    policy = source_workflow_policy(expected_policy_sha)
    need(re.fullmatch('[0-9a-f]{40}',workflow_commit),'actual workflow source commit')
    for path,digest in {policy['workflow']:policy['bodySHA256'],**policy['inputPrograms']}.items():
        need(re.fullmatch('[0-9a-f]{64}',digest),'reviewed producer code body hash')
        item = read(f'repos/{REPO}/contents/{path}?ref={workflow_commit}')
        need(item.get('encoding') == 'base64' and item.get('path') == path and
             type(item.get('size')) is int and 0<item['size']<=262144,
             'actual bounded source workflow/input-helper body')
        raw = base64.b64decode(item['content'].encode(),validate=False)
        need(len(raw) == item['size'] and hashlib.sha256(raw).hexdigest() == digest,
             'unreviewed producer workflow or hosted input-preparation code')
    return policy


def main():
    deadline = time.monotonic() + GUARD_SECONDS
    need(sys.argv[1:] in ([], ["--bind-job-token"]), "fixed guard invocation")
    bind_token = sys.argv[1:] == ["--bind-job-token"]
    env = os.environ
    need(os.getuid() == 1000 and os.geteuid() == 1000, "runner UID")
    need(env.get("GITHUB_REPOSITORY") == REPO, "canonical repository only")
    ref = env.get('GITHUB_REF','')
    source_producer = env.get('GITHUB_WORKFLOW_REF') == (
        f'{REPO}/.github/workflows/ubuntu-executable.yml@'+ref)
    if source_producer:
        need(ref.startswith('refs/heads/') and len(ref)>11 and
             env.get('GITHUB_EVENT_NAME') in ('push','workflow_dispatch') and
             env.get('GITHUB_JOB') == 'appimage-package',
             'same-repository automatic source-build job; no candidate checkout on host')
    else:
        need(ref == 'refs/heads/main' and env.get('GITHUB_WORKFLOW_REF') ==
             f'{REPO}/{WORKFLOW_PATH}@refs/heads/main', 'canonical consumer workflow only')
    event_name = env.get('GITHUB_EVENT_NAME')
    need(event_name in (('push','workflow_dispatch') if source_producer else
                       ('workflow_dispatch','workflow_run')), 'event refused')
    workflow_sha = env.get("GITHUB_SHA", "")
    sha = env.get("OPEMOS_SOURCE_SHA", "")
    need(re.fullmatch("[0-9a-f]{40}", sha) and
         re.fullmatch("[0-9a-f]{40}", workflow_sha),
         "installed controller and workflow source SHA")
    run_id = env.get("GITHUB_RUN_ID", "")
    attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    need(re.fullmatch("[1-9][0-9]*", run_id or "") and
         re.fullmatch("[1-9][0-9]*", attempt or ""), "consumer run/attempt")
    event = bounded_file(Path(env["GITHUB_EVENT_PATH"]))
    need(event.get("repository", {}).get("full_name") == REPO, "event repository")
    token = None
    if bind_token:
        # Existing Actions step env only; never file/argv/registration/PAT.
        token = env.pop("GITHUB_TOKEN", None)
        need(type(token) is str and token.startswith(("ghs_", "ghr_")) and
             20 <= len(token) <= 4096, "existing ephemeral Actions token required")
    read = lambda path: api(path, token, deadline=deadline)
    if source_producer:
        verify_source_workflow(read, workflow_sha)
    else:
        branch = read(f"repos/{REPO}/branches/main")
        need(branch.get("protected") is True, "protected controller workflow branch")
    workflow_path = '.github/workflows/ubuntu-executable.yml' if source_producer else WORKFLOW_PATH
    workflow = read(f"repos/{REPO}/actions/workflows/{workflow_path.rsplit('/', 1)[1]}")
    need(workflow.get("path") == workflow_path and workflow.get("state") == "active",
         "current consumer workflow path/state")
    consumer = read(f"repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}")
    need(consumer.get("id") == int(run_id) and
         consumer.get("run_attempt") == int(attempt) and
         consumer.get("workflow_id") == workflow.get("id") and
         consumer.get("path") == workflow_path and
         consumer.get("head_repository", {}).get("full_name") == REPO and
         consumer.get("head_branch") == (ref[len("refs/heads/"):] if source_producer else "main") and
         consumer.get("head_sha") == workflow_sha and
         consumer.get("event") == event_name,
         "consumer API identity/path/attempt")
    mode = "source_build" if source_producer else "normal"
    producer_identity = None
    if event_name == "workflow_run":
        producer = event.get("workflow_run", {})
        name = producer.get("name")
        need(name in PRODUCER_PATHS, "unknown producer")
        expected_path = PRODUCER_PATHS[name]
        producer_workflow = read(f"repos/{REPO}/actions/workflows/{expected_path.rsplit('/', 1)[1]}")
        need(producer_workflow.get("path") == expected_path and
             producer_workflow.get("state") == "active", "producer workflow path/state")
        pid = number(producer.get("id"))
        pattempt = number(producer.get("run_attempt"))
        observed = read(f"repos/{REPO}/actions/runs/{pid}/attempts/{pattempt}")
        need(producer.get("workflow_id") == producer_workflow.get("id") and
             observed.get("id") == pid and observed.get("run_attempt") == pattempt and
             observed.get("workflow_id") == producer_workflow.get("id") and
             observed.get("path") == expected_path and observed.get("name") == name and
             producer.get("head_repository", {}).get("full_name") == REPO and
             observed.get("head_repository", {}).get("full_name") == REPO and
             type(observed.get("head_branch")) is str and bool(observed["head_branch"]) and
             producer.get("head_branch") == observed.get("head_branch") and
             re.fullmatch(r"[0-9a-f]{40}", observed.get("head_sha", "")) and
             producer.get("head_sha") == observed.get("head_sha") and
             producer.get("status") == observed.get("status") == "completed" and
             producer.get("conclusion") == observed.get("conclusion"),
             "producer exact API/event mismatch")
        need(observed.get("conclusion") in
             ("success", "failure", "cancelled", "timed_out", "action_required", "neutral", "skipped"),
             "producer terminal conclusion")
        if observed["conclusion"] != "success":
            mode = "report_only"
        producer_identity = {"id": pid, "attempt": pattempt,
                             "workflow_id": producer_workflow["id"],
                             "conclusion": observed["conclusion"]}
    accepted = {"guard": "accepted", "mode": mode, "repository": REPO,
                "source_commit": sha, "run_id": run_id,
                "attempt": attempt, "producer": producer_identity,
                "vm_admission": False}
    control_path = env.get("OPEMOS_ROBOT_CONTROL_SOCKET")
    need(control_path == "/run/opemos-ci/control/control.sock", "fixed control socket")
    attestation = {"kind": "OPEMOS_ROBOT_JOB_ATTESTATION",
                   "repository": REPO, "source_commit": sha,
                   "workflow_commit": workflow_sha,
                   "run_id": run_id, "attempt": attempt, "mode": mode,
                   "producer": producer_identity, "consumer_started_epoch": int(time.time())}
    if bind_token:
        attestation["kind"] = "OPEMOS_ROBOT_JOB_API_TOKEN"
        attestation["github_token"] = token
    try:
        reply = broker_attestation(control_path, attestation, deadline)
    finally:
        # Deleting references is not secure erasure of Python strings.
        attestation.pop("github_token", None)
        token = None
    need(reply == {"accepted": True}, "host control attestation refused")
    accepted["job_token_bound"] = bind_token
    print(json.dumps(accepted, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never log arbitrary exception text while a credential may be in memory.
        code = "GUARD_REFUSED"
        if isinstance(error, GuardTimeout):
            code = "GUARD_ORIGINAL_BUDGET_EXHAUSTED"
        elif isinstance(error, urllib.error.HTTPError):
            code = "GITHUB_API_HTTP_" + str(error.code)
        elif isinstance(error, urllib.error.URLError):
            code = "GITHUB_API_UNAVAILABLE"
        elif type(error) is ValueError and str(error) == "existing ephemeral Actions token required":
            code = "ACTIONS_JOB_TOKEN_UNAVAILABLE"
        elif type(error) is ValueError and str(error) == "host control attestation refused":
            code = "ATTESTATION_REFUSED"
        print("OMEN Robot job refused: " + code, file=sys.stderr)
        raise SystemExit(1)

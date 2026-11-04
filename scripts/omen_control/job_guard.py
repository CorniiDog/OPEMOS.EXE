#!/usr/bin/python3
"""Fixed GitHub pre-job hook; authentication only, never VM admission."""
import json
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
WORKFLOW_PATH = ".github/workflows/omen-robot.yml"
PRODUCER_PATHS = {
    "01 Windows EXE": ".github/workflows/windows-portable.yml",
    "02 Ubuntu AppImage": ".github/workflows/ubuntu-executable.yml",
    "03 macOS Executable": ".github/workflows/macos-arm64.yml",
}


def need(value, why):
    if not value:
        raise ValueError(why)


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


def api(path, token=None):
    need(not path.startswith("/") and ".." not in path, "fixed API path")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "OPEMOS-fixed-job-guard"}
    if token is not None: headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request("https://api.github.com/" + path, headers=headers)
    try:
        with urllib.request.build_opener(NoGitHubRedirect()).open(request, timeout=15) as response:
            raw = response.read(1048577)
    except urllib.error.HTTPError as refused:
        refused.close()
        raise

    need(len(raw) <= 1048576, "API response oversized")
    return json.loads(raw)


def main():
    need(sys.argv[1:] in ([], ["--bind-job-token"]), "fixed guard invocation")
    bind_token = sys.argv[1:] == ["--bind-job-token"]
    env = os.environ
    need(os.getuid() == 1000 and os.geteuid() == 1000, "runner UID")
    need(env.get("GITHUB_REPOSITORY") == REPO and env.get("GITHUB_REF") == "refs/heads/main",
         "canonical protected main only")
    need(env.get("GITHUB_WORKFLOW_REF") == f"{REPO}/{WORKFLOW_PATH}@refs/heads/main",
         "canonical consumer workflow only")
    event_name = env.get("GITHUB_EVENT_NAME")
    need(event_name in ("workflow_dispatch", "workflow_run"), "event refused")
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
    read = lambda path: api(path, token)
    branch = read(f"repos/{REPO}/branches/main")
    need(branch.get("protected") is True, "protected controller workflow branch")
    workflow = read(f"repos/{REPO}/actions/workflows/{WORKFLOW_PATH.rsplit('/', 1)[1]}")
    need(workflow.get("path") == WORKFLOW_PATH and workflow.get("state") == "active",
         "current consumer workflow path/state")
    consumer = read(f"repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}")
    need(consumer.get("id") == int(run_id) and
         consumer.get("run_attempt") == int(attempt) and
         consumer.get("workflow_id") == workflow.get("id") and
         consumer.get("path") == WORKFLOW_PATH and
         consumer.get("head_repository", {}).get("full_name") == REPO and
         consumer.get("head_branch") == "main" and
         consumer.get("head_sha") == workflow_sha and
         consumer.get("event") == event_name,
         "consumer API identity/path/attempt")
    mode = "normal"
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
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(control_path)
        peer_pid, peer_uid, peer_gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        # The host broker is outside this fixed private PID namespace. A job
        # process can share UID1000 but must never impersonate that broker.
        need(peer_pid == 0 and peer_uid == peer_gid == 1000, "fixed outside-namespace broker peer")
        connection.sendall(json.dumps(attestation, separators=(",", ":")).encode() + b"\n")
        raw = bytearray()
        while len(raw) <= 4096 and not raw.endswith(b"\n"):
            part = connection.recv(min(4096, 4097 - len(raw)))
            need(part, "host control attestation EOF")
            raw.extend(part)
        need(len(raw) <= 4096 and raw.endswith(b"\n"), "bounded attestation reply")
        reply = json.loads(raw)
    # Deleting references is not a claim of secure erasure of Python strings.
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
        if type(error) is ValueError and str(error) == "existing ephemeral Actions token required":
            code = "ACTIONS_JOB_TOKEN_UNAVAILABLE"
        elif type(error) is ValueError and str(error) == "host control attestation refused":
            code = "ATTESTATION_REFUSED"
        print("OMEN Robot job refused: " + code, file=sys.stderr)
        raise SystemExit(1)

"""Read-only overall acceptance gate. Packaging success cannot satisfy it.

The trusted 04 SteamOS job owns validation of every VM and each executable's
image, virtual USB, install, boot and recovery evidence. This check requires its
latest completed successful attempt for this exact main commit. It never starts
a controller, guest, SSH session, image writer or retry.
"""
from datetime import datetime
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import sys
from urllib import error, request

REPOSITORY = "CorniiDog/OPEMOS.EXE"
WORKFLOW = ".github/workflows/steamos.yml"
JOB = "every-executable-steamos-output"
PROOF_STEPS = {
    "Bind all three exact protected-main executable producers",
    "Await every exact VM and each executable's actual SteamOS output",
}
MAX_RESPONSE = 2 * 1024 * 1024


class Refusal(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def parse_response(raw):
    require(len(raw) <= MAX_RESPONSE, "GitHub acceptance metadata exceeds its finite bound")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate GitHub metadata field")
            result[key] = value
        return result

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refusal("Nonfinite GitHub metadata")))


def close_refused_response(response, reason):
    try:
        response.close()
    except Exception as exc:
        reason += "; response close failed: " + type(exc).__name__
    raise Refusal(reason) from None


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        close_refused_response(fp, "GitHub acceptance API redirected; no alternate endpoint is authorized")


def api_reader(token):
    opener = request.build_opener(NoRedirect)

    def read(path):
        req = request.Request("https://api.github.com/repos/" + REPOSITORY + "/" + path,
                              headers={"Accept": "application/vnd.github+json",
                                       "Authorization": "Bearer " + token,
                                       "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with opener.open(req, timeout=20) as response:
                return parse_response(response.read(MAX_RESPONSE + 1))
        except error.HTTPError as exc:
            if exc.code == 404 and path.startswith("actions/workflows/steamos.yml/runs?"):
                reason = "04 SteamOS is not installed; full-stack acceptance is missing (HTTP 404)"
            else:
                reason = "GitHub acceptance API refused HTTP " + str(exc.code)
            close_refused_response(exc, reason)
        except HTTPException as exc:
            # Never serialize partial response bytes, headers or credentials.
            raise Refusal("GitHub acceptance transport failed: " + type(exc).__name__) from None
    return read


def run_inventory(read, sha):
    payload = read("actions/workflows/steamos.yml/runs?head_sha=" + sha + "&per_page=100")
    runs = payload["workflow_runs"]
    require(type(payload["total_count"]) is int and isinstance(runs, list)
            and payload["total_count"] == len(runs) <= 100,
            "SteamOS run inventory is incomplete; no previous success may be substituted")
    require(runs, "No 04 SteamOS run exists for this exact main commit")
    require(all(type(run.get("id")) is int and run["id"] > 0 and run.get("head_sha") == sha
                for run in runs), "SteamOS run inventory contains another source identity")
    require(len({run["id"] for run in runs}) == len(runs), "Duplicate SteamOS run identity")
    # A rerun keeps its original ID. Order current attempts by actual start,
    # refusing unknown or ambiguous ordering instead of using creation IDs.
    def started(run):
        value = run.get("run_started_at")
        require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value),
                "SteamOS attempt start is missing or malformed")
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise Refusal("SteamOS attempt start is not a valid UTC date") from None
    ordered = sorted(runs, key=started)
    require(len(ordered) == 1 or started(ordered[-2]) < started(ordered[-1]),
            "Latest SteamOS attempt ordering is ambiguous")
    # Fence all returned attempts, including a lower-ID rerun changing while
    # the selected job/artifact is inspected. Immutable tuples avoid aliasing.
    fields = ("id", "run_attempt", "status", "conclusion", "head_sha", "head_branch",
              "path", "name", "event", "run_started_at")
    fingerprint = tuple(tuple(run.get(key) for key in fields) +
                        (run.get("repository", {}).get("full_name"),
                         run.get("head_repository", {}).get("full_name"))
                        for run in sorted(runs, key=lambda row: row["id"]))
    return ordered[-1], fingerprint


def identity(run, sha):
    require(run.get("head_sha") == sha and run.get("head_branch") == "main"
            and run.get("repository", {}).get("full_name") == REPOSITORY
            and run.get("head_repository", {}).get("full_name") == REPOSITORY,
            "SteamOS acceptance must come from this canonical main commit")
    require(run.get("path") in {WORKFLOW, WORKFLOW + "@main", WORKFLOW + "@refs/heads/main"}
            and run.get("name") == "04 SteamOS"
            and run.get("event") in {"workflow_dispatch", "push", "workflow_run"},
            "SteamOS result is not the trusted main acceptance workflow")
    require(type(run.get("run_attempt")) is int and run["run_attempt"] > 0,
            "SteamOS attempt identity is missing")
    require(run.get("status") == "completed" and run.get("conclusion") == "success",
            "Latest 04 SteamOS attempt has not passed; build/package checks do not satisfy acceptance")
    return run["id"], run["run_attempt"]


def evaluate(read, sha):
    require(re.fullmatch(r"[0-9a-f]{40}", sha or ""), "Exact acceptance commit is missing")
    run, inventory = run_inventory(read, sha)
    run_id, attempt = identity(run, sha)
    jobs = read(f"actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    require(type(jobs["total_count"]) is int and jobs["total_count"] == len(jobs["jobs"]) <= 100,
            "SteamOS attempt job inventory is incomplete")
    required = [job for job in jobs["jobs"] if job.get("name") == JOB]
    require(len(required) == 1, "Required all-VM and per-executable SteamOS job is missing or ambiguous")
    job = required[0]
    require(job.get("run_id") == run_id and job.get("head_sha") == sha
            and job.get("status") == "completed" and job.get("conclusion") == "success",
            "Required SteamOS acceptance job failed, was skipped or belongs to another commit")
    for name in PROOF_STEPS:
        steps = [step for step in job.get("steps", []) if step.get("name") == name]
        require(len(steps) == 1 and steps[0].get("status") == "completed"
                and steps[0].get("conclusion") == "success",
                "Required executable/VM acceptance step is absent, failed or skipped: " + name)
    artifacts = read(f"actions/runs/{run_id}/artifacts?per_page=100")
    require(type(artifacts["total_count"]) is int
            and artifacts["total_count"] == len(artifacts["artifacts"]) <= 100,
            "SteamOS acceptance artifact inventory is incomplete")
    proof = [item for item in artifacts["artifacts"]
             if item.get("name") == f"steamos-acceptance-{run_id}-{attempt}"]
    require(len(proof) == 1 and proof[0].get("expired") is False
            and type(proof[0].get("size_in_bytes")) is int and 0 < proof[0]["size_in_bytes"] <= 16 * 1024**2
            and re.fullmatch(r"sha256:[0-9a-f]{64}", proof[0].get("digest", "")),
            "This SteamOS attempt has no retained exact acceptance metadata")
    # A retry/newer failure appearing during inspection invalidates this sample.
    final, final_inventory = run_inventory(read, sha)
    require(inventory == final_inventory and identity(final, sha) == (run_id, attempt),
            "SteamOS attempt inventory changed during acceptance review")
    return {"status": "passed", "source_commit": sha, "steamOS_run": run_id,
            "steamOS_attempt": attempt, "steamOS_attempt_started_at": run["run_started_at"],
            "acceptance_artifact_sha256": proof[0]["digest"],
            "url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
            "reason": "Exact main 04 SteamOS all-VM and every-executable acceptance job passed"}


def event_target(env):
    require(env.get("GITHUB_REPOSITORY") == REPOSITORY and env.get("GITHUB_REF") == "refs/heads/main",
            "Overall acceptance evaluates canonical main only; no PR or fork controller route")
    require(env.get("GITHUB_EVENT_NAME") in {"push", "workflow_dispatch", "workflow_run"},
            "Unsupported overall acceptance event")
    sha = env.get("GITHUB_SHA", "")
    if env["GITHUB_EVENT_NAME"] == "workflow_run":
        require(env.get("OPEMOS_UPSTREAM_SHA") == sha
                and env.get("OPEMOS_UPSTREAM_REPOSITORY") == REPOSITORY,
                "Completed SteamOS event is stale or foreign to this check's main commit")
        require(env.get("OPEMOS_UPSTREAM_ACTION") == "completed",
                "04 SteamOS has a requested or running attempt; acceptance must be rechecked after completion")
    return sha


def main():
    result = {"status": "failed", "source_commit": os.environ.get("GITHUB_SHA"),
              "scope": "Overall full-stack acceptance; packaging is reported separately"}
    try:
        sha = event_target(os.environ)
        token = os.environ.get("GITHUB_TOKEN", "")
        require(token, "Read-only GitHub token is unavailable; acceptance cannot be established")
        result.update(evaluate(api_reader(token), sha))
    except (Refusal, KeyError, TypeError, AttributeError, UnicodeError, OSError, ValueError) as exc:
        result["reason"] = str(exc)
    with Path("full-stack-acceptance.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    message = "Full-stack acceptance: " + result["status"].upper() + ". " + result["reason"]
    print(message)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
            stream.write(message + "\n\nRequires Windows, Ubuntu and macOS artifact image creation, virtual USB write/readback, "
                         "SteamOS installation/boot and the all-VM recovery checks in 04 SteamOS.\n")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())

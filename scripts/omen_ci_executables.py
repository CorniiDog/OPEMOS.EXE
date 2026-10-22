"""Per-executable SteamOS acceptance identity/report contract, no runtime authority."""
import hashlib
import io
import json
import re
import zipfile
from datetime import datetime

REPOSITORY = "CorniiDog/OPEMOS.EXE"
PRODUCERS = {
    "windows": {"workflow": ".github/workflows/windows-portable.yml", "label": "01 Windows EXE", "case": "windows-full-stack"},
    "ubuntu": {"workflow": ".github/workflows/ubuntu-executable.yml", "label": "02 Ubuntu AppImage", "case": "ubuntu-full-stack"},
    "macos": {"workflow": ".github/workflows/macos-arm64.yml", "label": "03 macOS Executable", "case": "macos-full-stack"},
}
SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
NUMBER = re.compile(r"[1-9][0-9]{0,19}\Z")
FIELDS = {"schema", "repository", "source_commit", "platform", "workflow", "producer_run_id", "producer_attempt",
          "event", "ref", "artifact_id", "artifact_name", "artifact_archive_sha256", "package_name", "package_sha256",
          "package_bytes", "executable_name", "executable_sha256", "executable_bytes"}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate executable JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda x: (_ for _ in ()).throw(ValueError("Nonfinite executable JSON")))


def descriptor(value, source=None):
    require(isinstance(value, dict) and set(value) == FIELDS and value["schema"] == 1 and
            value["repository"] == REPOSITORY and COMMIT.fullmatch(value["source_commit"]) and
            (source is None or source == value["source_commit"]), "Exact executable producer descriptor/source required")
    require(value["platform"] in PRODUCERS and value["workflow"] == PRODUCERS[value["platform"]]["workflow"] and
            value["event"] in ("push", "workflow_dispatch") and value["ref"] == "refs/heads/main",
            "Only reviewed protected-main executable producer workflows are accepted; PR/fork artifacts refused")
    for key in ("producer_run_id", "producer_attempt", "artifact_id"):
        require(isinstance(value[key], str) and NUMBER.fullmatch(value[key]), "Exact producer numeric identity missing")
    for key in ("artifact_archive_sha256", "package_sha256", "executable_sha256"):
        require(isinstance(value[key], str) and SHA.fullmatch(value[key]), "Exact executable/package/archive SHA missing")
    for key in ("package_bytes", "executable_bytes"):
        require(type(value[key]) is int and 0 < value[key] <= 60_000_000_000, "Actual executable/package size missing")
    for key in ("artifact_name", "package_name", "executable_name"):
        require(isinstance(value[key], str) and 0 < len(value[key]) <= 180 and
                not any(c in value[key] for c in ("/", "\\", "\n", "\r", "\0")), "Only non-private relative producer names allowed")
    return value


def key(value):
    return value["platform"] + "-" + value["artifact_id"]


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def validate_expected(values, source):
    require(isinstance(values, dict) and 3 <= len(values) <= 16, "Every expected executable must be declared distinctly")
    seen = set()
    for name, value in values.items():
        descriptor(value, source)
        require(name == key(value) and value["artifact_id"] not in seen, "Duplicate/aliased producer artifact identity")
        seen.add(value["artifact_id"])
    require({value["platform"] for value in values.values()} == set(PRODUCERS), "Windows, Ubuntu and macOS executable artifacts are all required")
    return values


def archive_json(raw, artifact, filename):
    require(isinstance(raw, bytes) and len(raw) <= 256 * 1024 and
            artifact.get("digest") == "sha256:" + hashlib.sha256(raw).hexdigest(), "Small producer metadata archive digest differs")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(archive.namelist() == [filename], "Exact one-file producer metadata archive required")
        member = archive.infolist()[0]
        require(member.file_size <= 65536 and member.compress_size <= 65536 and not member.flag_bits & 1,
                "Bounded unencrypted producer metadata required")
        return strict_json(archive.read(member))


class ExpectationFailure(ValueError):
    def __init__(self, partial, errors):
        self.partial, self.errors = partial, errors
        super().__init__("; ".join(platform + ": " + reason for platform, reason in errors.items()))


def expectations(source, selections, api, download):
    """Read-only GitHub metadata; never fetch package code or invoke an artifact."""
    require(COMMIT.fullmatch(source) and isinstance(selections, dict) and set(selections) == set(PRODUCERS),
            "Exact current-source three-platform producer selection required")
    expected, errors = {}, {}
    for platform, selected in selections.items():
        try:
            match = re.fullmatch(r"([1-9][0-9]{0,19}):([1-9][0-9]{0,19})", selected or "")
            require(match, platform + ": exact producer run:attempt is missing")
            run_id, attempt = match.groups()
            run = api(f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}")
            require(str(run.get("id")) == run_id and str(run.get("run_attempt")) == attempt and
                    run.get("head_sha") == source and run.get("head_branch") == "main" and
                    run.get("path") == PRODUCERS[platform]["workflow"] and run.get("event") in ("push", "workflow_dispatch") and
                    run.get("status") == "completed" and run.get("conclusion") == "success" and
                    run.get("repository", {}).get("full_name") == REPOSITORY and
                    run.get("head_repository", {}).get("id") == run.get("repository", {}).get("id"),
                    platform + ": producer workflow/run/attempt/source/main repository did not pass")
            artifacts = []
            for page in range(1, 11):
                response = api(f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100&page={page}")
                rows = response.get("artifacts")
                require(isinstance(rows, list), "Actual producer artifact enumeration missing")
                artifacts.extend(rows)
                if len(rows) < 100:
                    break
            else:
                raise ValueError("Producer artifact enumeration exceeded finite bound; no omission")
            require(len({x["id"] for x in artifacts}) == len(artifacts), "Ambiguous producer artifact IDs")
            attestation_name = f"executable-producer-{platform}-{run_id}-{attempt}"
            matches = [x for x in artifacts if x.get("name") == attestation_name and x.get("expired") is False]
            require(len(matches) == 1, platform + ": exact producer descriptor artifact unavailable")
            metadata = matches[0]
            value = archive_json(download(f"repos/{REPOSITORY}/actions/artifacts/{metadata['id']}/zip"), metadata, "executable-producer.json")
            descriptor(value, source)
            require(value["platform"] == platform and value["producer_run_id"] == run_id and value["producer_attempt"] == attempt,
                    "Downloaded producer descriptor belongs to another platform/run/attempt")
            selected_artifacts = [x for x in artifacts if str(x.get("id")) == value["artifact_id"]]
            require(len(selected_artifacts) == 1, "Descriptor references a foreign/unlisted artifact")
            actual = selected_artifacts[0]
            require(actual.get("expired") is False and actual.get("name") == value["artifact_name"] and
                    actual.get("digest") == "sha256:" + value["artifact_archive_sha256"] and
                    actual.get("workflow_run", {}).get("id") == int(run_id) and
                    actual.get("workflow_run", {}).get("head_sha") == source and
                    actual.get("workflow_run", {}).get("repository_id") == run["repository"]["id"] and
                    actual.get("workflow_run", {}).get("head_repository_id") == run["repository"]["id"],
                    "Producer artifact archive/source/run/repository identity differs")
            start = datetime.fromisoformat(run["run_started_at"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(run["updated_at"].replace("Z", "+00:00"))
            for entry in (actual, metadata):
                created = datetime.fromisoformat(entry["created_at"].replace("Z", "+00:00"))
                require(start <= created <= end, "Artifact predates/escapes the exact producer attempt")
            expected[key(value)] = value
        except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile) as error:
            errors[platform] = str(error)
    if errors:
        raise ExpectationFailure(expected, errors)
    return validate_expected(expected, source)


def binding(run_id, attempt, value, nonce):
    require(NUMBER.fullmatch(str(run_id)) and NUMBER.fullmatch(str(attempt)) and
            re.fullmatch(r"[0-9a-f]{32}", nonce or ""), "Current executable acceptance run/attempt/operation nonce missing")
    value = f"r:{run_id}/{attempt};e:{digest(value)};n:{nonce}"
    require(len(value) <= 140, "Executable status binding exceeds GitHub description bound")
    return value


def context(value):
    return "opemos/steamos/" + key(value)


POINTER_ACTIONS=("chooser-open","chooser-confirm-exact-input","Build","virtualUSB-select-and-review","virtualUSB-Write-confirmation")


def pointer_proof_valid(proof,value,row,source,run_id,attempt):
    if not isinstance(proof,dict):return False
    expected={"schema":1,"verified":True,"source_commit":source,"run_id":run_id,"attempt":attempt,
        "operation_nonce":row.get("operation_nonce"),"executable":value}
    if not all(proof.get(k)==v for k,v in expected.items())or proof.get("verified")is not True or type(proof.get("schema"))is not int:return False
    if proof.get("proof_sha256")!=digest({k:v for k,v in proof.items()if k!="proof_sha256"}):return False
    if not SHA.fullmatch(proof.get("sender_sha256","")or""):return False
    actions=proof.get("actions",[])
    if not isinstance(actions,list)or len(actions)!=5 or not all(isinstance(x,dict)for x in actions)or[x.get("action")for x in actions]!=list(POINTER_ACTIONS):return False
    ids=[];captures=[]
    for action in actions:
        name=action.get("action_id","")
        if not re.fullmatch(r"[0-9a-f]{32}",name or""):return False
        ids.append(name)
        if not all(SHA.fullmatch(action.get(k,"")or"")for k in("record_sha256","transition_sha256","sender_lifecycle_sha256","target_observation_sha256")):return False
        for phase in("before","after"):
            frame=action.get(phase,{})
            if not isinstance(frame,dict):return False
            if not re.fullmatch(r"[0-9a-f]{32}",frame.get("capture_id","")or"")or not all(SHA.fullmatch(frame.get(k,"")or"")for k in("frame_sha256","capture_receipt_sha256")):return False
            captures.append(frame["capture_id"])
    return len(ids)==len(set(ids))and len(captures)==len(set(captures))


def report(expected, outcomes, source, run_id, attempt):
    """One exact outcome per expected artifact; missing rows remain failures."""
    validate_expected(expected, source)
    rows, fingerprints = {}, set()
    outcomes = outcomes if isinstance(outcomes, dict) else {}
    for name, value in expected.items():
        row = outcomes.get(name, {})
        valid = (isinstance(row, dict) and row.get("status") == "passed" and row.get("executable") == value and
                 row.get("source_commit") == source and row.get("run_id") == run_id and row.get("attempt") == attempt and
                 row.get("active") is False and row.get("actual_receipt_verified") is True and
                 re.fullmatch(r"[0-9a-f]{32}", row.get("operation_nonce", "")))
        valid=valid and pointer_proof_valid(row.get("pointer_acceptance"),value,row,source,run_id,attempt)
        footprint = tuple(row.get(key) for key in ("operation_nonce", "build_receipt_sha256", "heal_receipt_sha256", "install_receipt_sha256", "output_identity", "target_generation"))
        valid = valid and all(isinstance(x, str) and x for x in footprint) and footprint not in fingerprints
        if valid:
            fingerprints.add(footprint)
        rows[name] = {**row, "executable": value, "status": "passed" if valid else "failed",
                      "reason": row.get("reason", "No distinct verified GUI/image/USB/install/NVIDIA/recovery transaction for this exact executable"),
                      "github_context": context(value)}
    # A duplicate individual operation/output/receipt/target generation cannot
    # cover two expected artifacts, even when their binary/image SHA is equal.
    for field in ("operation_nonce", "build_receipt_sha256", "heal_receipt_sha256", "install_receipt_sha256", "output_identity", "target_generation"):
        values = [row.get(field) for row in rows.values() if row["status"] == "passed"]
        if len(values) != len(set(values)):
            for row in rows.values():
                row.update(status="failed", reason="An operation/output/target/receipt was reused across executable artifacts")
    # A frame acquisition or actual action belongs to one executable operation.
    # Pixel SHA equality is allowed; acquisition/action identity reuse is not.
    seen_actions=set();seen_captures=set()
    for row in rows.values():
        if row["status"]!="passed":continue
        proof=row["pointer_acceptance"]
        action_ids={x["action_id"]for x in proof["actions"]}
        capture_ids={x[p]["capture_id"]for x in proof["actions"]for p in("before","after")}
        if seen_actions&action_ids or seen_captures&capture_ids:
            for invalid in rows.values():invalid.update(status="failed",reason="A pointer action/frame acquisition was replayed across executable artifacts")
            break
        seen_actions|=action_ids;seen_captures|=capture_ids
    extra = sorted(set(outcomes) - set(expected))
    return {"source_commit": source, "run_id": run_id, "attempt": attempt, "expected_sha256": digest(expected),
            "artifacts": rows, "unexpected_artifacts": extra,
            "aggregate": {"status": "passed" if not extra and all(x["status"] == "passed" for x in rows.values()) else "failed",
                          "expected": len(expected), "passed": sum(x["status"] == "passed" for x in rows.values())}}


def markdown(value):
    rows = value.get("artifacts", {})
    lines = ["### SteamOS output acceptance per executable", "", "| Executable | Producer run/attempt | Artifact | Package SHA256 | Result |", "| --- | --- | --- | --- | --- |"]
    for row in rows.values():
        x = row["executable"]
        lines.append(f"| {PRODUCERS[x['platform']]['label']} | {x['producer_run_id']}/{x['producer_attempt']} | {x['artifact_id']} | {x['package_sha256']} | {row['status']} |")
    return "\n".join(lines) + "\n\nPackaging, inventory and one platform's result cannot pass another executable's SteamOS output.\n"


def missing_report(source, run_id, attempt, reason, partial=None):
    rows = {name: {"executable": value, "status": "failed", "reason": reason}
            for name, value in (partial or {}).items()}
    represented = {row["executable"]["platform"] for row in rows.values()}
    for platform, producer in PRODUCERS.items():
        if platform not in represented:
            rows["unavailable-" + platform] = {"executable": {"platform": platform,
                "producer_run_id": "unavailable", "producer_attempt": "unavailable", "artifact_id": "unavailable",
                "package_sha256": "unavailable"}, "status": "failed", "reason": reason}
    return {"source_commit": source, "run_id": run_id, "attempt": attempt, "artifacts": rows,
            "aggregate": {"status": "failed", "expected": len(rows), "passed": 0}, "expected_set_verified": False}


def status_view(expected, latest, source, run_id, attempt, url):
    """A current exact status bridge report, never local runtime verification."""
    validate_expected(expected, source)
    rows, complete, nonces = {}, True, []
    for name, executable in expected.items():
        status = latest.get(context(executable), {})
        match = re.fullmatch(r"r:([1-9][0-9]*)/([1-9][0-9]*);e:([0-9a-f]{64});n:([0-9a-f]{32}|unavailable)", status.get("description", ""))
        bound = (match and match.group(1) == run_id and match.group(2) == attempt and
                 match.group(3) == digest(executable) and status.get("target_url") == url and
                 status.get("state") in ("success", "failure", "error"))
        complete = bool(complete and bound)
        passed = bool(bound and status["state"] == "success" and match.group(4) != "unavailable")
        if passed: nonces.append(match.group(4))
        rows[name] = {"executable":executable, "status":"passed" if passed else "failed",
                      "github_context":context(executable), "status_id":status.get("id"),
                      "operation_nonce":match.group(4) if bound else None,
                      "bridge_status_verified":bool(bound), "actual_receipt_verified":False,
                      "reason":"Exact current acceptance-run status bridge; no local runtime receipt validation"}
    aggregate = latest.get("opemos/steamos/all-executables", {})
    unavailable = (aggregate.get("description") == f"r:{run_id}/{attempt};e:unavailable" and
                   aggregate.get("target_url") == url and aggregate.get("state") in ("failure", "error"))
    if unavailable:
        for row in rows.values(): row.update(status="failed", reason="Current controller expectation preflight failed; no actual artifact acceptance")
        return {"source_commit":source, "run_id":run_id, "attempt":attempt, "expected_sha256":digest(expected),
                "artifacts":rows, "complete":True, "status_bridge_view":True,
                "aggregate":{"status":"failed", "expected":len(rows), "passed":0}}
    aggregate_bound = (aggregate.get("description") == f"r:{run_id}/{attempt};e:{digest(expected)}" and
                       aggregate.get("target_url") == url and aggregate.get("state") in ("success", "failure", "error"))
    complete = bool(complete and aggregate_bound)
    passed = (complete and aggregate["state"] == "success" and len(nonces) == len(rows) == len(set(nonces))
              and all(row["status"] == "passed" for row in rows.values()))
    return {"source_commit":source, "run_id":run_id, "attempt":attempt, "expected_sha256":digest(expected),
            "artifacts":rows, "complete":complete, "status_bridge_view":True,
            "aggregate":{"status":"passed" if passed else "failed", "expected":len(rows),
                         "passed":sum(row["status"] == "passed" for row in rows.values())}}

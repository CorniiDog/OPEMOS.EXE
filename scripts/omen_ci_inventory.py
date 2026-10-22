"""Fixed all-VM visibility/identity contract; no runtime or launch authority."""
import copy
import json
import stat
import re

# Exact independently reviewed required-vms.json records are embedded so every
# failure path can render all rows without installed config or SSH access.
REQUIRED = [{'id': '81688cb8-c3a5-41c3-b7a3-75a9f6ba0e25',
  'name': 'OPEMOS-Agent-Boot',
  'family': 'transferred-hyperv',
  'required': True,
  'owner': 'exe',
  'initial_state': 'format-readable-runtime-unverified',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Agent-Boot'},
 {'id': 'c54ddf9a-6060-44d7-9cd2-3476e8b4d996',
  'name': 'OPEMOS-Agent-Boot-B',
  'family': 'transferred-hyperv',
  'required': True,
  'owner': 'exe',
  'initial_state': 'format-open-failed-before-boot',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Agent-Boot-B'},
 {'id': '9dc1d978-a83a-4699-aeb9-32c10fe22be3',
  'name': 'OPEMOS-Agent-UI',
  'family': 'transferred-hyperv',
  'required': True,
  'owner': 'exe',
  'initial_state': 'format-open-failed-before-boot',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Agent-UI'},
 {'id': 'd058543e-5b8c-4742-93a4-5bd2427621d8',
  'name': 'OPEMOS-Agent-UI-B',
  'family': 'transferred-hyperv',
  'required': True,
  'owner': 'exe',
  'initial_state': 'format-open-failed-before-boot',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Agent-UI-B'},
 {'id': '97ad3a89-299d-44e6-92bc-880e197d2f89',
  'name': 'OPEMOS-KVM-A',
  'family': 'transferred-hyperv',
  'required': True,
  'owner': 'exe',
  'initial_state': 'format-open-failed-before-boot',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-KVM-A'},
 {'id': '130f2dc3-24b4-403f-8e28-7f1776251a15',
  'name': 'OPEMOS-KVM-B',
  'family': 'transferred-hyperv',
  'required': True,
  'owner': 'exe',
  'initial_state': 'format-open-failed-before-boot',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-KVM-B'},
 {'id': 'd6011de4-0376-4109-a569-31ad00418f5d',
  'name': 'OPEMOS-Windows-Test',
  'family': 'transferred-hyperv',
  'required': True,
  'owner': 'exe',
  'initial_state': 'format-open-failed-before-boot',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Windows-Test'},
 {'id': '9f63f6d9-a223-492d-8f68-49ef3948838d',
  'name': 'OPEMOS-Windows-Test-B',
  'family': 'transferred-hyperv',
  'required': True,
  'owner': 'exe',
  'initial_state': 'format-open-failed-before-boot',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Windows-Test-B'},
 {'id': 'OPEMOS-Ubuntu-Test',
  'name': 'OPEMOS-Ubuntu-Test',
  'family': 'ubuntu-counterpart',
  'required': True,
  'owner': 'core',
  'initial_state': 'files-present-not-workflow-verified',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Ubuntu-Test'},
 {'id': 'OPEMOS-Ubuntu-Test-B',
  'name': 'OPEMOS-Ubuntu-Test-B',
  'family': 'ubuntu-counterpart',
  'required': True,
  'owner': 'core',
  'initial_state': 'files-present-not-workflow-verified',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Ubuntu-Test-B'},
 {'id': 'OPEMOS-Ubuntu-Agent-Boot',
  'name': 'OPEMOS-Ubuntu-Agent-Boot',
  'family': 'ubuntu-counterpart',
  'required': True,
  'owner': 'core',
  'initial_state': 'files-present-not-workflow-verified',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Ubuntu-Agent-Boot'},
 {'id': 'OPEMOS-Ubuntu-Agent-Boot-B',
  'name': 'OPEMOS-Ubuntu-Agent-Boot-B',
  'family': 'ubuntu-counterpart',
  'required': True,
  'owner': 'core',
  'initial_state': 'files-present-not-workflow-verified',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Ubuntu-Agent-Boot-B'},
 {'id': 'OPEMOS-Ubuntu-Agent-UI',
  'name': 'OPEMOS-Ubuntu-Agent-UI',
  'family': 'ubuntu-counterpart',
  'required': True,
  'owner': 'core',
  'initial_state': 'files-present-not-workflow-verified',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Ubuntu-Agent-UI'},
 {'id': 'OPEMOS-Ubuntu-Agent-UI-B',
  'name': 'OPEMOS-Ubuntu-Agent-UI-B',
  'family': 'ubuntu-counterpart',
  'required': True,
  'owner': 'core',
  'initial_state': 'files-present-not-workflow-verified',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Ubuntu-Agent-UI-B'},
 {'id': 'OPEMOS-Ubuntu-KVM-A',
  'name': 'OPEMOS-Ubuntu-KVM-A',
  'family': 'ubuntu-counterpart',
  'required': True,
  'owner': 'core',
  'initial_state': 'files-present-not-workflow-verified',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Ubuntu-KVM-A',
  'required_case': 'nested-ubuntu-linux',
  'subject_role': 'nested_linux',
  'retained_evidence_scope': 'Nested Ubuntu Linux boot and exact closure only; historical receipt '
                             'is not a current source/run/nonce result or '
                             'executable/Fedora/GPU/fullstack acceptance.'},
 {'id': 'OPEMOS-Ubuntu-KVM-B',
  'name': 'OPEMOS-Ubuntu-KVM-B',
  'family': 'ubuntu-counterpart',
  'required': True,
  'owner': 'core',
  'initial_state': 'files-present-not-workflow-verified',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Ubuntu-KVM-B',
  'required_case': 'nested-ubuntu-linux',
  'subject_role': 'nested_linux',
  'retained_evidence_scope': 'Nested Ubuntu Linux boot and exact closure only; historical receipt '
                             'is not a current source/run/nonce result or '
                             'executable/Fedora/GPU/fullstack acceptance.'},
 {'id': 'macos-apple-silicon-fullstack',
  'name': 'Admitted Apple Silicon macOS graphical lane',
  'family': 'macos',
  'required': True,
  'owner': 'exe',
  'initial_state': 'complete-fullstack-unverified',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/Admitted-Apple-Silicon-macOS-graphical-lane'},
 {'id': 'steamos-same-guest-gpu-autoheal',
  'name': 'Same SteamOS guest kernel update/NVIDIA/render/power recovery',
  'family': 'steamos',
  'required': True,
  'owner': 'steamos/core',
  'initial_state': 'capacity/admission unresolved',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/Same-SteamOS-guest-kernel-update-NVIDIA-render-power-recovery'},
 {'id': 'opemos-windows-debloat-20261019-r3b',
  'name': 'opemos-windows-debloat-20261019-r3b',
  'family': 'fresh-windows-install',
  'required': True,
  'owner': 'windows',
  'initial_state': 'running-unverified',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/opemos-windows-debloat-20261019-r3b'},
 {'id': 'OPEMOS-Ubuntu-FullStack-PR189-20261019-r1',
  'name': 'OPEMOS-Ubuntu-FullStack-PR189-20261019-r1',
  'family': 'ubuntu-graphical-fullstack',
  'required': True,
  'owner': 'ubuntu',
  'initial_state': 'running-unverified',
  'case_operand': 'unconfigured',
  'replacement_for': None,
  'github_context': 'opemos/vm/OPEMOS-Ubuntu-FullStack-PR189-20261019-r1'}]
CASES = ("windows-full-stack", "ubuntu-full-stack", "macos-full-stack", "steamos-autoheal", "nested-ubuntu-linux")
CASE_CODES = {"w": CASES[0], "u": CASES[1], "m": CASES[2], "s": CASES[3], "n": CASES[4]}
ROLE_CODES = {"h": "imaging_host", "a": "fedora_appliance", "t": "steamos_target", "n": "nested_linux"}
AGGREGATE_CONTEXT = "opemos/vm/all-required"
IDS = {row["id"] for row in REQUIRED}
BY_ID = {row["id"]: row for row in REQUIRED}
BINDING = re.compile(r"r:([1-9][0-9]{0,19})/([1-9][0-9]{0,19});n:([0-9a-f]{32}|unavailable);i:([A-Za-z0-9_.:-]{1,80}|unavailable);c:([wumsn-]);t:([hatn-])\Z")


def subject_contract(vm_id, case, role):
    fixed = {"macos": ("macos-full-stack", "imaging_host"),
             "steamos": ("steamos-autoheal", "steamos_target"),
             "fresh-windows-install": ("windows-full-stack", "imaging_host"),
             "ubuntu-graphical-fullstack": ("ubuntu-full-stack", "imaging_host")}
    if vm_id in {"OPEMOS-Ubuntu-KVM-A", "OPEMOS-Ubuntu-KVM-B"}:
        return case == "nested-ubuntu-linux" and role == "nested_linux"
    if case == "nested-ubuntu-linux" or role == "nested_linux":
        return False
    expected = fixed.get(BY_ID.get(vm_id, {}).get("family"))
    return (case in CASES and role in ROLE_CODES.values() and (expected is None or expected == (case, role)) and
            (case != "steamos-autoheal" or role == "steamos_target"))


def platform_section(row):
    return {"macos": "macOS", "steamos": "SteamOS recovery",
            "fresh-windows-install": "Windows", "ubuntu-graphical-fullstack": "Ubuntu",
            "ubuntu-counterpart": "Ubuntu", "transferred-hyperv": "Transferred original VMs"}[row["family"]]


def default_rows(reason):
    return {row["id"]: {"id": row["id"], "name": row["name"], "family": row["family"],
                        "github_context": row["github_context"], "initial_state": row["initial_state"],
                        "platform_section": platform_section(row),
                        "status": "failed", "reason": reason, "runtime_instance_id": None,
                        "case": None, "subject_role": None, "planned_runtime_instance_id": None} for row in REQUIRED}


def binding(run_id, attempt, nonce=None, instance=None, case=None, role=None):
    nonce = nonce if isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{32}", nonce) else "unavailable"
    instance = instance if isinstance(instance, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", instance) else "unavailable"
    code = next((key for key, value in CASE_CODES.items() if value == case), "-")
    role_code = next((key for key, value in ROLE_CODES.items() if value == role), "-")
    value = f"r:{run_id}/{attempt};n:{nonce};i:{instance};c:{code};t:{role_code}"
    if not BINDING.fullmatch(value) or len(value) > 140:
        raise ValueError("Exact run/nonce/instance identity cannot fit GitHub status description")
    return value


def case_rollup(vms):
    result = {}
    complete_mapping = all(row.get("case") in CASES for row in vms.values())
    for case in CASES:
        members = [row for row in vms.values() if row.get("case") == case]
        result[case] = {"status": "passed" if complete_mapping and members and all(row.get("status") == "passed" for row in members) else "failed",
                        "vm_ids": [row["id"] for row in members],
                        "reason": "All exact mapped VM rows must pass; missing/unknown role stays failed"}
    return result


def original_source_valid(value):
    fields={"st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns"}
    return (isinstance(value,dict)and set(value)=={"sha256","size","identity"}and
            isinstance(value.get("sha256"),str)and re.fullmatch(r"[0-9a-f]{64}",value["sha256"])and
            type(value.get("size"))is int and value["size"]>0 and isinstance(value.get("identity"),dict)and
            set(value["identity"])==fields and all(type(x)is int for x in value["identity"].values())and
            stat.S_ISREG(value["identity"]["st_mode"])and value["identity"]["st_nlink"]==1 and value["identity"]["st_size"]==value["size"])


def runtime_conflicts(bindings):
    groups = {}
    for original,runtime in bindings.items():
        if runtime and runtime != "unavailable": groups.setdefault(runtime,[]).append(original)
    return {original for originals in groups.values() if len(originals)>1 for original in originals}


def normalize(result, source=None, run_id=None, attempt=None, reason="No actual current-run VM result"):
    """Display all required IDs even after missing/invalid remote output.

    Existing rows are accepted only with exact source/run/attempt/nonce, context,
    runtime instance, VM identity, observed discovery coverage and closure. This
    is aggregation of independently validated actual receipts, never acceptance
    of mere inventory/format qualification.
    """
    result = result if isinstance(result, dict) else {}
    source = source or result.get("source_commit")
    run_id, attempt = run_id or result.get("run_id"), attempt or result.get("attempt")
    reason = reason if isinstance(reason, str) else "Malformed/absent actual result"
    rows = default_rows(reason)
    supplied = result.get("vms", {})
    nonce = result.get("nonce")
    matches = (isinstance(source, str) and re.fullmatch(r"[0-9a-f]{40}", source) and
               result.get("source_commit") == source and result.get("run_id") == run_id and
               result.get("attempt") == attempt and isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{32}", nonce))
    observed = result.get("observed_vm_ids")
    coverage = (isinstance(observed, list) and all(isinstance(x, str) for x in observed) and len(observed) == len(set(observed)) and set(observed) == IDS
                and isinstance(supplied, dict) and set(supplied) == IDS and result.get("coverage_verified") is True)
    for vm_id, original in rows.items():
        row = supplied.get(vm_id, {}) if isinstance(supplied, dict) else {}
        row = row if isinstance(row, dict) else {}
        if row.get("case") in CASES:
            original["case"] = row["case"]
        if row.get("subject_role") in ROLE_CODES.values():
            original["subject_role"] = row["subject_role"]
        instance = row.get("runtime_instance_id")
        if isinstance(instance, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", instance):
            original["runtime_instance_id"] = instance
        valid = (matches and row.get("id") == vm_id and row.get("github_context") == original["github_context"] and
                 row.get("source_commit") == source and row.get("run_id") == run_id and row.get("attempt") == attempt and
                 row.get("nonce") == nonce and subject_contract(vm_id, original["case"], original["subject_role"]) and original["runtime_instance_id"] and original["runtime_instance_id"] != "unavailable" and
                 (original["runtime_instance_id"] not in IDS or original["runtime_instance_id"] == vm_id) and
                 ((row.get("actual_receipt_verified") is True and original_source_valid(row.get("original_source"))) or (result.get("status_bridge_view") is True and
                  row.get("bridge_status_verified") is True and type(row.get("status_id")) is int and row["status_id"] > 0)) and
                 row.get("active") is False)
        original["status"] = "passed" if valid and row.get("status") == "passed" else "failed"
        original["actual_receipt_verified"] = bool(valid and row.get("actual_receipt_verified") is True)
        original["bridge_status_verified"] = bool(valid and row.get("bridge_status_verified") is True)
        original["active"] = False if valid else row.get("active", "unknown")
        original["reported_status"] = row.get("status", "unavailable")
        original["reason"] = row.get("reason", reason) if isinstance(row.get("reason", reason), str) else reason
        planned = row.get("planned_runtime_instance_id")
        if isinstance(planned, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", planned):
            original["planned_runtime_instance_id"] = planned
        if not valid:
            original["reported_runtime_instance_id"] = original["runtime_instance_id"]
            original["runtime_instance_id"] = None
            if row.get("status") == "passed":
                original["reported_reason"] = original["reason"]
                original["reason"] = "Current source/run/attempt/nonce/VM/role/receipt/closure identity is unverified"
        original.update({"source_commit": source, "run_id": run_id, "attempt": attempt, "nonce": nonce})
        if valid:
            for key in ("receipt_sha256", "queue_job_ids", "roles", "status_id", "original_source"):
                if key in row: original[key] = copy.deepcopy(row[key])
    conflicts=runtime_conflicts({vm_id:row.get("runtime_instance_id") for vm_id,row in rows.items()})
    lineage={vm_id:json.dumps(row.get("original_source",{}).get("identity"),sort_keys=True)for vm_id,row in rows.items()
             if row.get("actual_receipt_verified")and isinstance(row.get("original_source"),dict)}
    conflicts|=runtime_conflicts(lineage)
    for vm_id in conflicts:
        rows[vm_id].update(status="failed",actual_receipt_verified=False,bridge_status_verified=False,
            reason="Runtime subject aliases another catalog original; original lineage unverified")
    result = {**result, "source_commit": source, "run_id": run_id, "attempt": attempt, "nonce": nonce,
              "vms": rows, "coverage_verified": bool(coverage),
              "unknown_vm_ids": sorted(set(observed or []) - IDS) if isinstance(observed, list) and all(isinstance(x, str) for x in observed) else [],
              "cases": case_rollup(rows)}
    result["aggregate"] = {"status": "passed" if coverage and all(r["status"] == "passed" for r in rows.values()) and
                           all(r["status"] == "passed" for r in result["cases"].values()) else "failed",
                           "github_context": AGGREGATE_CONTEXT, "required": len(REQUIRED),
                           "passed": sum(row["status"] == "passed" for row in rows.values())}
    return result


def markdown(result):
    def clean(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")[:240]
    lines = []
    for section in ("Windows", "Ubuntu", "macOS", "SteamOS recovery", "Transferred original VMs"):
        lines.extend(["\n### " + section, "", "| Required VM | Exact inventory ID | Actual runtime instance | Subject role | Result | Reason |",
                      "| --- | --- | --- | --- | --- | --- |"])
        for row in result["vms"].values():
            if row.get("platform_section") == section:
                lines.append("| " + " | ".join(clean(row.get(k) or "unavailable") for k in
                             ("name", "id", "runtime_instance_id", "subject_role", "status", "reason")) + " |")
    lines.append("\nAggregate: " + result["aggregate"]["status"] + "; inventory visibility is not runtime acceptance.\n")
    if result.get("unknown_vm_ids"):
        lines.append("Unreviewed canonical VM IDs; coverage failed: " + ", ".join(clean(x) for x in result["unknown_vm_ids"]))
    return "\n".join(lines)

"""Controller safety tests; execute in GitHub CI or an admitted test VM."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


def module(name):
    path = Path(__file__).resolve().parents[1] / "scripts" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


controller = module("omen_ci")
stage = module("omen_ci_stage")


class ControllerAdmission(unittest.TestCase):
    def test_existing_controller_disabled_fails_without_network(self):
        env = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": controller.REPOSITORY,
               "GITHUB_REF": "refs/heads/main", "GITHUB_REF_PROTECTED": "true", "GITHUB_SHA": "a" * 40}
        with mock.patch.object(controller.urllib.request, "urlopen") as network:
            with self.assertRaisesRegex(ValueError, "unconfigured"):
                controller.wait_existing(env)
            network.assert_not_called()

    def test_existing_controller_is_exact_live_run_and_attempt_bound(self):
        with mock.patch.object(controller, "gh_api") as api, mock.patch.object(controller, "enter_heavy") as heavy:
            with self.assertRaises(ValueError):
                controller.existing_gh({"OPEMOS_GITHUB_RUN_ID": "../invalid"})
            api.assert_not_called()
            api.side_effect = [{"event": "pull_request", "head_branch": "main"}, {"protected": True}]
            with self.assertRaisesRegex(ValueError, "live protected-main"):
                controller.existing_gh({"OPEMOS_GITHUB_RUN_ID": "12"})
            heavy.assert_not_called()
        self.assertNotEqual(controller.status_context("12", "1", "windows-full-stack"),
                            controller.status_context("12", "2", "windows-full-stack"))

    def test_unconfigured_route_fails_before_network_or_queue(self):
        env = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": controller.REPOSITORY,
               "GITHUB_REF": "refs/heads/main", "GITHUB_REF_PROTECTED": "true", "GITHUB_SHA": "a" * 40}
        with mock.patch.object(controller.urllib.request, "urlopen") as network:
            with self.assertRaisesRegex(ValueError, "disabled/unconfigured"):
                controller.preflight(env)
            network.assert_not_called()

    def test_fork_or_pull_request_cannot_reach_controller(self):
        for event in ("pull_request", "pull_request_target", "workflow_run"):
            with self.assertRaises(ValueError):
                controller.trusted_event({"GITHUB_EVENT_NAME": event})

    def test_runner_must_exist_be_online_idle_and_uniquely_labelled(self):
        runner = {"name": "controller-a", "status": "online", "busy": False,
                  "labels": [{"name": n} for n in ["self-hosted", "linux", "opemos-controller", "controller-a"]]}
        self.assertEqual(controller.runner_labels({"runners": [runner]}, "controller-a")[-1], "controller-a")
        for delta in ({"status": "offline"}, {"busy": True}, {"labels": []}):
            with self.assertRaises(ValueError):
                controller.runner_labels({"runners": [{**runner, **delta}]}, "controller-a")
        with self.assertRaises(ValueError):
            controller.runner_labels({"runners": []}, "controller-a")


class ArtifactExpiry(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        (self.root / ".receipts").mkdir(mode=0o700)
        stage.create_json(self.root / stage.MARKER,
                          {"schema": 1, "uid": os.getuid(), "purpose": "OPEMOS CI copies only"})
        self.name = "run-12-1-" + "a" * 32
        self.run = self.root / self.name
        self.run.mkdir(mode=0o700)
        (self.run / "artifacts").mkdir(mode=0o700)
        stage.create_json(self.run / ".lock", {})
        stage.create_json(self.run / ".owned.json", {"schema": 1, "name": self.name, "uid": os.getuid(),
                          "created": 100, "expires": 100 + stage.TTL, "job_ids": ["case-1"]})
        stage.create_json(self.run / "receipt.json", {"run_name": self.name, "active": False})
        self.rows = {"case-1": {"state": "passed", "result": {}}}

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_four_hour_boundary_and_small_receipt_retention(self):
        original = self.root / "original-disk-preserved"
        original.write_bytes(b"original")
        self.assertEqual(stage.expire({}, self.rows, 100 + stage.TTL - 1, self.root), [])
        self.assertEqual(stage.expire({}, self.rows, 100 + stage.TTL, self.root), [self.name])
        self.assertFalse(self.run.exists())
        self.assertEqual(original.read_bytes(), b"original")
        self.assertTrue((self.root / ".receipts" / (self.name + ".json")).is_file())

    def test_active_unknown_or_locked_run_is_never_expired(self):
        for state in ("running", "pending", "unknown", "terminal_cleanup", "timeout", "cancelled"):
            rows = {"case-1": {"state": state}}
            self.assertEqual(stage.expire({}, rows, 999999, self.root), [])
        self.assertEqual(stage.expire({}, {}, 999999, self.root), [])
        with (self.run / ".lock").open("r+") as lock:
            stage.fcntl.flock(lock, stage.fcntl.LOCK_EX | stage.fcntl.LOCK_NB)
            self.assertEqual(stage.expire({}, self.rows, 999999, self.root), [])
        receipt = self.run / "receipt.json"
        receipt.unlink()
        stage.create_json(receipt, {"run_name": self.name, "active": True})
        self.assertEqual(stage.expire({}, self.rows, 999999, self.root), [])

    def test_symlink_or_hardlink_tree_refuses_all_deletion(self):
        target = self.root / "original"
        target.write_bytes(b"do not delete")
        link = self.run / "artifacts" / "unsafe"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            stage.expire({}, self.rows, 999999, self.root)
        self.assertTrue(self.run.exists())
        self.assertEqual(target.read_bytes(), b"do not delete")
        link.unlink()
        os.link(target, link)
        with self.assertRaises(ValueError):
            stage.expire({}, self.rows, 999999, self.root)

    def test_unmarked_wrong_root_or_ttl_is_not_collected(self):
        marker = self.run / ".owned.json"
        value = json.loads(marker.read_text())
        value["expires"] += 1
        marker.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "TTL"):
            stage.expire({}, self.rows, 999999, self.root)
        self.assertTrue(self.run.exists())

    def test_exact_normal_timed_out_closure_and_symlink_lock_guard(self):
        self.assertTrue(stage.closed_jobs(["case-1"], {"case-1": {"state": "timed_out", "result": {}}}))
        self.assertFalse(stage.closed_jobs(["case-1"], {"case-1": {"state": "unknown", "result": {}}}))
        lock = self.run / ".lock"
        lock.unlink()
        target = self.root / "unrelated-lock"
        target.write_bytes(b"original")
        lock.symlink_to(target)
        with self.assertRaises((ValueError, OSError)):
            stage.expire({}, self.rows, 999999, self.root)
        self.assertTrue(self.run.exists())
        self.assertEqual(target.read_bytes(), b"original")


class EvidenceAdmission(unittest.TestCase):
    def setUp(self):
        self.plan = {"source_commit": "a" * 40, "nonce": "b" * 32}
        self.operand = {"package_sha256": "c" * 64, "input_sha256": "d" * 64, "job_ids": ["job-1"], "hardware_scope": "virtual-only",
                        "inventory_vm_id": stage._INVENTORY["REQUIRED"][0]["id"], "runtime_instance_id": "guest-1", "subject_role": "imaging_host"}
        self.receipt = {"status": "passed", "case": "windows-full-stack", **self.plan,
                        **{k: self.operand[k] for k in ["package_sha256", "input_sha256"]},
                        "queue_job_ids": ["job-1"], "physical_usb_written": False, "gpu_claim": False,
                        "closure": {"processes_gone": True, "pool_released": True, "queue_released": True},
                        "guest": {"kind": "vm", "id": "guest-1", "disk_identity": "disk-1", "baseline_boot_id": "boot-a",
                                  "normal_boot_id": "boot-b", "abrupt_boot_id": "boot-c", "location": "omen-vm"},
                        "recovery_guest_id": "guest-1", "recovery_disk_identity": "disk-1",
                        "gui_input_method": "pointer", "display_session": "real-guest-console",
                        "files": {}, "checks": {}}
        for kind in set().union(*stage.EVIDENCE_KINDS.values()):
            self.receipt["files"][kind] = {"kind": kind, "path": "/reviewed/" + kind,
                                           "sha256": "e" * 64, "size": 1}
        for key in stage.BUILD_CHECKS:
            self.receipt["checks"][key] = {"passed": True, "evidence": sorted(stage.EVIDENCE_KINDS[key])}
        self.receipt["checks"]["abrupt_power_recovery"]["method"] = "vm-power-off-and-restart"
        host = self.receipt.pop("guest")
        for key in ("baseline_boot_id", "normal_boot_id", "abrupt_boot_id"):
            host.pop(key)
        host.update(platform="windows", architecture="x86_64", inventory_vm_id=self.operand["inventory_vm_id"],
                    original_inventory_id=self.operand["inventory_vm_id"], owned=True, runtime_relationship="owned-disposable-copy",
                    app_process={"pid": 10, "start": 11}, app_window_id="actual-app-window")
        target = {"kind": "vm", "id": "target-1", "owned": True, "platform": "steamos", "architecture": "x86_64",
                  "disk_identity": "target-disk", "location": "omen-vm", "boot_medium_id": "owned-usb-1", "image_sha256": "e" * 64,
                  "baseline_boot_id": "boot-a", "normal_boot_id": "boot-b", "abrupt_boot_id": "boot-c"}
        self.receipt["roles"] = {"imaging_host": host,
            "fedora_appliance": {"id": "fedora-1", "kind": "vm", "disk_identity": "fedora-disk", "owned": True, "platform": "fedora", "architecture": "x86_64",
                                 "host_instance_id": "guest-1", "qemu_process": {"pid": 20, "start": 21}},
            "virtual_usb": {"id": "owned-usb-1", "owned": True, "kind": "virtual", "bytes": 123,
                            "source_output_sha256": "e" * 64, "readback_sha256": "e" * 64}, "steamos_target": target}
        self.receipt["output"] = {**self.plan, "package_sha256": "c" * 64, "input_sha256": "d" * 64,
                                  "sha256": "e" * 64, "manifest_sha256": "e" * 64}
        self.receipt.update(inventory_vm_id=self.operand["inventory_vm_id"], runtime_instance_id="guest-1", subject_role="imaging_host",
                            recovery_target_id="target-1", recovery_target_disk_identity="target-disk")
        self.receipt.pop("recovery_guest_id")
        self.receipt.pop("recovery_disk_identity")

        self.receipt["readiness_fault"] = {
            "consumer_guest_id": "guest-1", "disk_identity": "disk-1", **self.plan,
            "package_sha256": "c" * 64, "transport_exit": 0, "consumer_outcome": "rejected",
            "continued_build": False, "source_unchanged": True, "appliance_processes_gone": True,
            "queue_released": True, "expected_marker": "expected", "observed_marker": "wrong",
            "closure_job_ids": ["job-1"],
            "consumer_process": {"pid": 12, "start": 34}, "appliance_instance": "actual-disposable-1"}

        identity={k:0 for k in stage._FULL9};identity.update(st_dev=1,st_ino=2,st_size=123,st_uid=1000,st_gid=1000,st_nlink=1,st_mode=0o100600)
        self.operand["original_source"]={"sha256":"9"*64,"size":123,"identity":identity}
        for subject in self.receipt["roles"].values():subject["original_source"]=copy.deepcopy(self.operand["original_source"])
        self.pointer_temp=tempfile.TemporaryDirectory();self.addCleanup(self.pointer_temp.cleanup)
        fixture_path=Path(__file__).with_name('omen_ci_pointer_fixture.py')
        spec=importlib.util.spec_from_file_location('generated_pointer_policy_fixture',fixture_path)
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        fixture.attach(stage,self.receipt,self.plan,self.operand,Path(self.pointer_temp.name))


    def test_full_identity_and_actual_graphical_graph_required(self):
        stage.validate_receipt(self.receipt, "windows-full-stack", self.plan, self.operand)
        changes = [{"status": "skipped"}, {"nonce": "0" * 32}, {"gui_input_method": "keyboard"},
                   {"display_session": "xvfb"}, {"physical_usb_written": True}, {"closure": {}},
                   {"checks": {"graphical_build": {"passed": True, "evidence": ["screenshot"]}}}]
        for delta in changes:
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                stage.validate_receipt({**self.receipt, **delta}, "windows-full-stack", self.plan, self.operand)

    def test_recovery_must_power_cycle_same_guest_and_disk(self):
        for delta in [{"recovery_target_id": "replacement"}, {"recovery_target_disk_identity": "replacement"}]:
            with self.assertRaises(ValueError):
                stage.validate_receipt({**self.receipt, **delta}, "windows-full-stack", self.plan, self.operand)
        wrong = copy.deepcopy(self.receipt)
        wrong["checks"]["abrupt_power_recovery"]["method"] = "process-crash"
        with self.assertRaises(ValueError):
            stage.validate_receipt(wrong, "windows-full-stack", self.plan, self.operand)

    def test_mac_requires_real_apple_admission(self):
        mac = {**self.receipt, "case": "macos-full-stack"}
        with self.assertRaises(ValueError):
            stage.validate_receipt(mac, "macos-full-stack", self.plan, self.operand)

    def test_successful_wrong_marker_cannot_be_omitted_or_replaced_by_transport_failure(self):
        for change in ("omit_fault", "omit_check", "transport_failure", "same_marker", "different_guest", "unknown_closure"):
            value = copy.deepcopy(self.receipt)
            if change == "omit_fault": value.pop("readiness_fault")
            elif change == "omit_check": value["checks"].pop("wrong_readiness_rejected")
            elif change == "transport_failure": value["readiness_fault"]["transport_exit"] = 255
            elif change == "same_marker": value["readiness_fault"]["observed_marker"] = "expected"
            elif change == "different_guest": value["readiness_fault"]["consumer_guest_id"] = "replacement"
            elif change == "unknown_closure": value["readiness_fault"]["appliance_processes_gone"] = None
            with self.subTest(change=change), self.assertRaises(ValueError):
                stage.validate_receipt(value, "windows-full-stack", self.plan, self.operand)

    def test_autoheal_cannot_pass_without_admitted_loaded_rendered_gpu_and_restoration(self):
        operand = {**self.operand, "hardware_scope": "existing-independently-admitted-gpu",
                   "gpu_admission": {"sha256": "1" * 64}, "lease_nonce": "2" * 32,
                   "kernels": ["old-exact-release", "new-exact-release"], "driver_version": "575.64.05"}
        receipt = copy.deepcopy(self.receipt)
        operand.update(inventory_vm_id="steamos-same-guest-gpu-autoheal", runtime_instance_id="target-1", subject_role="steamos_target")
        receipt.update(case="steamos-autoheal", gpu_claim=True, kernels=operand["kernels"], driver_version=operand["driver_version"],
                       inventory_vm_id=operand["inventory_vm_id"], runtime_instance_id="target-1", subject_role="steamos_target")
        receipt["roles"]["steamos_target"].update(inventory_vm_id=operand["inventory_vm_id"],
            original_inventory_id=operand["inventory_vm_id"], runtime_relationship="owned-disposable-copy", original_source=copy.deepcopy(operand["original_source"]))
        receipt["checks"] = {key: {"passed": True, "evidence": sorted(stage.EVIDENCE_KINDS[key])} for key in stage.HEAL_CHECKS}
        receipt["checks"]["abrupt_power_recovery"]["method"] = "vm-power-off-and-restart"
        samples = [{"guest_id": "target-1", "gpu_uuid": "GPU-exact", "driver_version": "575.64.05",
                    "boot_id": boot, "kernel": kernel, "module_loaded": True, "driver_query_exit": 0,
                    "render_exit": 0, "render_vendor": "NVIDIA Corporation", "renderer": "NVIDIA RTX2060"}
                   for boot, kernel in [("boot-a", "old-exact-release"), ("boot-b", "new-exact-release"), ("boot-c", "new-exact-release")]]
        for sample in samples:
            name = "capture-" + sample["boot_id"]
            receipt["files"][name] = {"kind": "screenshot", "path": "/reviewed/" + name, "sha256": "e" * 64, "size": 1}
            for key, kind in (("query_evidence", "nvidia-loaded"), ("render_evidence", "nvidia-render")):
                ref = kind + "-" + sample["boot_id"]
                receipt["files"][ref] = {"kind": kind, "path": "/reviewed/" + ref, "sha256": "e" * 64, "size": 1}
                sample[key] = ref
            sample["screenshot"] = name
        receipt["gpu"] = {"admission_sha256": "1" * 64, "group": "omen-iommu-group-1", "lease_nonce": "2" * 32,
                          "guest_id": "target-1", "driver_version": "575.64.05", "gpu_uuid": "GPU-exact", "samples": samples,
                          "four_function_restoration": {"0000:01:00." + str(i): {"restored": True, "before_driver": "original-" + str(i), "after_driver": "original-" + str(i)} for i in range(4)},
                          "lease_closed": True, "domain_closed": True, "qmp_closed": True}
        stage.validate_receipt(receipt, "steamos-autoheal", self.plan, operand)
        for change in ("virtual", "no_gpu", "not_loaded", "software", "wrong_kernel", "missing_restore", "unknown_qmp", "reused_query"):
            value, op = copy.deepcopy(receipt), copy.deepcopy(operand)
            if change == "virtual": op["hardware_scope"] = "virtual-only"
            elif change == "no_gpu": value["gpu_claim"] = False
            elif change == "not_loaded": value["gpu"]["samples"][1]["module_loaded"] = False
            elif change == "software": value["gpu"]["samples"][2]["renderer"] = "llvmpipe"
            elif change == "wrong_kernel": value["gpu"]["samples"][1]["kernel"] = "old-exact-release"
            elif change == "missing_restore": value["gpu"]["four_function_restoration"].pop("0000:01:00.3")
            elif change == "unknown_qmp": value["gpu"]["qmp_closed"] = None
            elif change == "reused_query": value["gpu"]["samples"][1]["query_evidence"] = value["gpu"]["samples"][0]["query_evidence"]
            with self.subTest(change=change), self.assertRaises(ValueError):
                stage.validate_receipt(value, "steamos-autoheal", self.plan, op)

    def test_transferred_fedora_vm_can_be_its_actual_appliance_role_without_impersonating_host(self):
        value, operand = copy.deepcopy(self.receipt), copy.deepcopy(self.operand)
        operand.update(runtime_instance_id="fedora-1", subject_role="fedora_appliance")
        value.update(runtime_instance_id="fedora-1", subject_role="fedora_appliance")
        value["roles"]["imaging_host"].update(inventory_vm_id="different-actual-host", original_inventory_id="different-actual-host")
        value["roles"]["fedora_appliance"].update(inventory_vm_id=operand["inventory_vm_id"],
            original_inventory_id=operand["inventory_vm_id"], runtime_relationship="owned-disposable-copy", original_source=copy.deepcopy(operand["original_source"]))
        # The subject is now the Fedora appliance, while the actual graphical
        # imaging host remains distinct. Regenerate the COMPLETE synthetic
        # pointer/destination graph for this role before its positive check.
        fixture_path=Path(__file__).with_name('omen_ci_pointer_fixture.py')
        spec=importlib.util.spec_from_file_location('generated_fedora_pointer_fixture',fixture_path)
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        fixture.attach(stage,value,self.plan,operand,Path(self.pointer_temp.name)/'synthetic-fedora-role')
        stage.validate_receipt(value, "windows-full-stack", self.plan, operand)
        bad = copy.deepcopy(value)
        bad["roles"]["imaging_host"]["inventory_vm_id"] = operand["inventory_vm_id"]
        with self.assertRaises(ValueError):
            stage.validate_receipt(bad, "windows-full-stack", self.plan, operand)

    def test_darwin_host_is_distinct_from_actual_x86_steamos_recovery_target(self):
        value, operand = copy.deepcopy(self.receipt), copy.deepcopy(self.operand)
        operand.update(inventory_vm_id="macos-apple-silicon-fullstack", apple_admission_sha256="1" * 64)
        value.update(case="macos-full-stack", inventory_vm_id=operand["inventory_vm_id"],
                     apple_admission_sha256="1" * 64, display_session="apple-silicon-session")
        value["roles"]["imaging_host"].update(platform="darwin", architecture="arm64", apple_hardware=True,
            inventory_vm_id=operand["inventory_vm_id"], original_inventory_id=operand["inventory_vm_id"])
        spec=importlib.util.spec_from_file_location('generated_mac_pointer_fixture',Path(__file__).with_name('omen_ci_pointer_fixture.py'))
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        fixture.attach(stage,value,self.plan,operand,Path(self.pointer_temp.name)/'synthetic-mac','darwin')
        stage.validate_receipt(value, "macos-full-stack", self.plan, operand)
        for change in ("host_as_target", "target_arm64", "different_recovery_target", "usb_hash", "target_image", "inner_not_fedora"):
            bad = copy.deepcopy(value)
            if change == "host_as_target": bad["roles"]["steamos_target"] = bad["roles"]["imaging_host"]
            elif change == "target_arm64": bad["roles"]["steamos_target"]["architecture"] = "arm64"
            elif change == "different_recovery_target": bad["recovery_target_id"] = "other-target"
            elif change == "usb_hash": bad["roles"]["virtual_usb"]["readback_sha256"] = "2" * 64
            elif change == "target_image": bad["roles"]["steamos_target"]["image_sha256"] = "2" * 64
            else: bad["roles"]["fedora_appliance"]["platform"] = "darwin"
            with self.subTest(change=change), self.assertRaises(ValueError):
                stage.validate_receipt(bad, "macos-full-stack", self.plan, operand)


class AllVMVisibility(unittest.TestCase):
    def setUp(self):
        self.inventory = stage._INVENTORY
        self.source, self.run, self.attempt, self.nonce = "a" * 40, "12", "3", "b" * 32
        rows = self.inventory["default_rows"]("fixture only")
        for index, (vm_id, row) in enumerate(rows.items()):
            fixed = {"macos": "macos-full-stack", "steamos": "steamos-autoheal",
                     "fresh-windows-install": "windows-full-stack", "ubuntu-graphical-fullstack": "ubuntu-full-stack"}
            case = "nested-ubuntu-linux" if vm_id in {"OPEMOS-Ubuntu-KVM-A", "OPEMOS-Ubuntu-KVM-B"} else fixed.get(row["family"], stage.CASES[index % 3])
            row.update(status="passed", case=case, source_commit=self.source, run_id=self.run,
                       attempt=self.attempt, nonce=self.nonce, runtime_instance_id="owned-instance-" + str(index),
                       actual_receipt_verified=True, active=False, subject_role="nested_linux" if case == "nested-ubuntu-linux" else "steamos_target" if case == "steamos-autoheal" else "imaging_host")
        for index,row in enumerate(rows.values()):
            identity={k:0 for k in stage._FULL9};identity.update(st_dev=1,st_ino=index+1,st_size=123,st_uid=1000,st_gid=1000,st_nlink=1,st_mode=0o100600)
            row["original_source"]={"sha256":"9"*64,"size":123,"identity":identity}
        self.result = {"source_commit": self.source, "run_id": self.run, "attempt": self.attempt, "nonce": self.nonce,
                       "observed_vm_ids": list(rows), "coverage_verified": True, "vms": rows}

    def test_always_reporter_renders_all20_and_preserves_corrupt_prior_result(self):
        with tempfile.TemporaryDirectory() as temp:
            previous = Path.cwd()
            try:
                os.chdir(temp)
                old = Path("ci-summary.json")
                old.write_bytes(b"corrupt original")
                old.chmod(0o600)
                env = {"GITHUB_SHA": self.source, "GITHUB_RUN_ID": self.run, "GITHUB_RUN_ATTEMPT": self.attempt,
                       "GITHUB_STEP_SUMMARY": str(Path(temp) / "hosted-summary.md")}
                controller.inventory_report(env)
                self.assertEqual(old.read_bytes(), b"corrupt original")
                report = json.loads(Path("ci-inventory-report.json").read_text())
                self.assertEqual(len(report["vms"]), 20)
                self.assertEqual(report["aggregate"]["status"], "failed")
                self.assertEqual(Path("hosted-summary.md").read_text().count("| failed |"), 20)
            finally:
                os.chdir(previous)

    def test_missing_or_broken_controller_still_displays_all20_exact_ids_and_contexts(self):
        for failure in ({}, {"error": "SSH timed out"}, {"vms": None}, {"vms": {"bad": None}, "observed_vm_ids": [{}]}):
            result = self.inventory["normalize"](failure, source=self.source, run_id=self.run, attempt=self.attempt)
            self.assertEqual(len(result["vms"]), 20)
            self.assertEqual(set(result["vms"]), self.inventory["IDS"])
            self.assertEqual({row["github_context"] for row in result["vms"].values()},
                             {row["github_context"] for row in self.inventory["REQUIRED"]})
            self.assertEqual(result["aggregate"]["status"], "failed")
            self.assertTrue(all(row["status"] == "failed" for row in result["vms"].values()))
            self.assertEqual(self.inventory["markdown"](result).count("| failed |"), 20)

    def test_no_missing_row_extra_discovery_stale_nonce_or_counterpart_substitution_can_pass(self):
        good = self.inventory["normalize"](self.result)
        self.assertEqual(good["aggregate"]["status"], "passed")
        vm_id = next(iter(self.result["vms"]))
        for change in ("omit", "extra_vm", "stale_nonce", "wrong_source", "wrong_attempt", "replacement", "fresh_instance_substitution", "inventory_only"):
            value = copy.deepcopy(self.result)
            if change == "omit": value["vms"].pop(vm_id)
            elif change == "extra_vm": value["observed_vm_ids"].append("new-unreviewed-canonical-vm")
            elif change == "stale_nonce": value["vms"][vm_id]["nonce"] = "0" * 32
            elif change == "wrong_source": value["vms"][vm_id]["source_commit"] = "0" * 40
            elif change == "wrong_attempt": value["vms"][vm_id]["attempt"] = "2"
            elif change == "replacement": value["vms"][vm_id]["id"] = "opemos-windows-debloat-20261019-r3b"
            elif change == "fresh_instance_substitution": value["vms"][vm_id]["runtime_instance_id"] = "opemos-windows-debloat-20261019-r3b"
            else: value["vms"][vm_id]["actual_receipt_verified"] = False
            with self.subTest(change=change):
                result = self.inventory["normalize"](value)
                self.assertEqual(len(result["vms"]), 20)
                self.assertEqual(result["aggregate"]["status"], "failed")
        self.assertEqual(len({row["id"] for row in good["vms"].values() if row["family"] == "ubuntu-counterpart"}), 8)

    def test_planned_runtime_is_not_reported_as_actual_and_new_discovery_preserves_known_passes(self):
        value = {"source_commit": self.source, "run_id": self.run, "attempt": self.attempt, "nonce": self.nonce,
                 "vms": self.inventory["default_rows"]("not executed")}
        first = next(iter(value["vms"]))
        value["vms"][first]["planned_runtime_instance_id"] = "prepared-only"
        result = self.inventory["normalize"](value)
        self.assertIsNone(result["vms"][first]["runtime_instance_id"])
        self.assertEqual(result["vms"][first]["planned_runtime_instance_id"], "prepared-only")
        actual = copy.deepcopy(self.result)
        actual["observed_vm_ids"].append("new-canonical-unreviewed-vm")
        result = self.inventory["normalize"](actual)
        self.assertEqual(result["aggregate"]["status"], "failed")
        self.assertEqual(result["aggregate"]["passed"], 20)
        self.assertIn("new-canonical-unreviewed-vm", self.inventory["markdown"](result))

    def test_status_bridge_view_does_not_claim_local_runtime_receipt_validation(self):
        value = copy.deepcopy(self.result)
        value["status_bridge_view"] = True
        for index, row in enumerate(value["vms"].values()):
            row.update(actual_receipt_verified=False, bridge_status_verified=True, status_id=100 + index)
        result = self.inventory["normalize"](value)
        self.assertEqual(result["aggregate"]["status"], "passed")
        self.assertTrue(all(row["bridge_status_verified"] and not row["actual_receipt_verified"] for row in result["vms"].values()))
        first = next(iter(value["vms"]))
        value["vms"][first]["nonce"] = "0" * 32
        self.assertEqual(self.inventory["normalize"](value)["aggregate"]["status"], "failed")

    def test_exact_existing_context_binding_does_not_accept_a_prior_run(self):
        row = next(iter(self.result["vms"].values()))
        text = self.inventory["binding"](self.run, self.attempt, self.nonce, row["runtime_instance_id"], row["case"], row["subject_role"])
        match = self.inventory["BINDING"].fullmatch(text)
        self.assertEqual(match.group(1), self.run)
        self.assertEqual(match.group(2), self.attempt)
        self.assertEqual(match.group(3), self.nonce)
        self.assertEqual(match.group(4), row["runtime_instance_id"])
        self.assertEqual(self.inventory["CASE_CODES"][match.group(5)], row["case"])
        self.assertNotEqual(text, self.inventory["binding"]("11", self.attempt, self.nonce, row["runtime_instance_id"], row["case"], row["subject_role"]))

    def test_same_stable_contexts_are_published_for_all20_after_configuration_failure(self):
        run = {"head_sha": self.source}
        with mock.patch.object(controller, "gh_api") as api:
            controller.publish_vm_statuses(self.run, self.attempt, run, {"error": "bad installed config"})
        calls = [call.args[1] for call in api.call_args_list]
        vm_calls = [value for value in calls if value["context"] in {r["github_context"] for r in self.inventory["REQUIRED"]}]
        self.assertEqual(len(vm_calls), 20)
        self.assertTrue(all(value["state"] == "failure" for value in vm_calls))
        self.assertTrue(all(self.inventory["BINDING"].fullmatch(value["description"]) for value in vm_calls))


class DescriptorCustody(unittest.TestCase):
    def test_duplicate_or_nonfinite_json_is_refused_in_both_consumers(self):
        for consumer in (stage.strict_json, controller.strict_json):
            for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
                with self.assertRaises(ValueError):
                    consumer(raw)

    def test_artifact_digest_cannot_become_a_path_operand(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "original"
            source.write_bytes(b"original")
            bad = {"path": str(source), "size": 8, "sha256": "../outside"}
            with self.assertRaisesRegex(ValueError, "digest"):
                stage.artifact_read(bad, 1024, root / bad["sha256"])
            self.assertEqual(source.read_bytes(), b"original")

    def test_canonical_reader_cap_link_and_replacement_faults(self):
        reader = stage._READER
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source.json"
            path.write_bytes(b'{"value":1}')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(reader.SourceReadFailure):
                reader.read_verified(path, 2, expected_sha=digest, uid=os.getuid())
            alias = Path(temp) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(reader.SourceReadFailure):
                reader.read_verified(alias, 1024, expected_sha=digest, uid=os.getuid())
            alias.unlink()
            os.link(path, alias)
            with self.assertRaises(reader.SourceReadFailure):
                reader.read_verified(path, 1024, expected_sha=digest, uid=os.getuid())
            alias.unlink()
            actual_read = os.read
            replaced = False
            def replace_after_read(fd, size):
                nonlocal replaced
                value = actual_read(fd, size)
                if value and not replaced:
                    replaced = True
                    other = Path(temp) / "replacement"
                    other.write_bytes(b'{"value":2}')
                    other.replace(path)
                return value
            with mock.patch.object(reader.os, "read", replace_after_read):
                with self.assertRaises(reader.SourceReadFailure):
                    reader.read_verified(path, 1024, expected_sha=digest, uid=os.getuid())

    def test_verified_bytes_are_consumed_without_parse_or_exec_reopening(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source.py"
            raw = b'VALUE = "verified"\n'
            path.write_bytes(raw)
            pin, captured = stage._READER.read_verified(path, 1024, expected_sha=hashlib.sha256(raw).hexdigest(), uid=os.getuid())
            path.write_bytes(b'raise RuntimeError("must not execute replacement")\n')
            namespace = stage._READER.verified_namespace(captured, path, "verified_fixture")
            self.assertEqual(namespace["VALUE"], "verified")
            self.assertEqual(pin["sha256"], hashlib.sha256(raw).hexdigest())

    def test_sealed_normal_manifest_consumer_and_absolute_base_equivalence(self):
        manifest = {"version": 1, "jobs": [{"cwd": "/reviewed/control", "command": ["/usr/bin/python3", "/reviewed/control/worker.py"],
                    "files": ["/reviewed/control/worker.py"], "approval": {"path": "/reviewed/control/approval.json"}}]}
        stage.absolute_manifest(manifest)
        raw = json.dumps(manifest).encode()
        fd = stage.sealed_manifest(raw)
        try:
            # This is the unchanged normal queue's actual path.read_text JSON
            # consumption shape, operating on sealed bytes rather than a mock.
            self.assertEqual(json.loads(Path("/proc/self/fd/" + str(fd)).read_text()), manifest)
            with self.assertRaises(OSError): os.write(fd, b"changed")
        finally:
            os.close(fd)
        for value in (manifest["jobs"][0]["cwd"], *manifest["jobs"][0]["files"], manifest["jobs"][0]["approval"]["path"]):
            self.assertEqual(Path("/original/base") / value, Path("/proc/self/fd") / value)
        for key in ("cwd", "files", "approval"):
            value = copy.deepcopy(manifest)
            if key == "cwd": value["jobs"][0][key] = "relative"
            elif key == "files": value["jobs"][0][key] = ["relative"]
            else: value["jobs"][0][key]["path"] = "relative"
            with self.assertRaises(ValueError): stage.absolute_manifest(value)


class CompleteMetadataAndNestedRoles(unittest.TestCase):
    def test_complete_metadata_preserves_actual_size_unknown_rows_unicode_and_partial_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            capture = stage.MetadataCapture(96 * 1024**2, temp)
            # Different sizes beyond the actual32MB observation,73+unknown rows,
            # non-ASCII and splits inside UTF8 ensure a byte-aware growth case.
            value = {"pool": {"cpu_ids": list(range(10))}, "jobs": [
                {"id": "old-" + str(i), "unknown_historical": "x" * (512 * 1024)} for i in range(79)],
                     "unknown_future": "🧪é"}
            raw = json.dumps(value, ensure_ascii=False).encode()
            for start in range(0, len(raw), 7919): capture.buffer.write(raw[start:start + 7919])
            self.assertEqual(capture.payload(), value)
            self.assertEqual(capture.last["bytes"], len(raw))
            self.assertEqual(capture.last["sha256"], hashlib.sha256(raw).hexdigest())
            capture.close()
            self.assertTrue(capture.closed)
            self.assertTrue(capture.stream.closed)

    def test_complete_capture_handles_short_spool_writes_and_refuses_zero_write(self):
        with tempfile.TemporaryDirectory() as temp:
            capture = stage.MetadataCapture(4096, temp)
            underlying = capture.stream
            class ShortWriter:
                def __getattr__(self, key): return getattr(underlying, key)
                def write(self, block): return underlying.write(block[:3])
            capture.stream = ShortWriter()
            capture.write('{"payload":"actual short writes"}')
            self.assertEqual(capture.payload(), {"payload": "actual short writes"})
            capture.close();self.assertTrue(underlying.closed)
            capture = stage.MetadataCapture(4096, temp)
            underlying = capture.stream
            class ZeroWriter:
                def __getattr__(self, key): return getattr(underlying, key)
                def write(self, block): return 0
            capture.stream = ZeroWriter()
            try:
                with self.assertRaisesRegex(ValueError, "Partial"):capture.write('{}')
            finally:capture.close()
            self.assertTrue(underlying.closed)

    def test_metadata_exact_byte_boundary_overflow_incomplete_utf8_and_failure_close(self):
        with tempfile.TemporaryDirectory() as temp:
            raw = '{"v":"é"}'.encode()
            for cap in [len(raw), len(raw) - 1]:
                capture = stage.MetadataCapture(cap, temp)
                try:
                    if cap == len(raw):
                        self.assertEqual(capture.write(raw.decode()), len(raw.decode()))
                        self.assertEqual(capture.payload(), {"v": "é"})
                    else:
                        with self.assertRaises(ValueError): capture.write(raw.decode())
                        self.assertEqual(capture.total, 0)
                finally: capture.close()
                self.assertTrue(capture.stream.closed)
            capture = stage.MetadataCapture(1024, temp)
            try:
                capture.buffer.write(b'{"v":"\xc3')
                with self.assertRaises(UnicodeDecodeError): capture.payload()
            finally: capture.close()
            self.assertTrue(capture.closed)

    def test_measured_metadata_growth_and_real_scratch_volume_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            database = root / "queue.sqlite3";database.write_bytes(b"small actual storage")
            config = {"queue_dir": str(root), "queue_metadata": {"scratch_dir": str(root),
                       "max_bytes": 128 * 1024**2, "free_reserve_bytes": 0}}
            first = stage.metadata_envelope(config)
            with database.open("wb") as stream: stream.truncate(9 * 1024**2)
            second = stage.metadata_envelope(config)
            self.assertGreater(second["cap_bytes"], first["cap_bytes"])
            self.assertLessEqual(second["cap_bytes"], config["queue_metadata"]["max_bytes"])
            self.assertEqual(second["storage_bytes"], 9 * 1024**2)
            config["queue_metadata"]["free_reserve_bytes"] = second["free_bytes"] + 1
            with self.assertRaisesRegex(ValueError, "volume"): stage.metadata_envelope(config)

    def test_sanitized_historical_nested_a_b_examples_and_faults_keep_truthful_scope(self):
        fixture = Path(__file__).with_name("fixtures") / "omen-ci-nested"
        for label in ("a", "b"):
            actual = json.loads((fixture / (label + "-result.json")).read_bytes())
            queue = json.loads((fixture / (label + "-queue-result.json")).read_bytes())
            serial = (fixture / (label + "-outer-serial.log")).read_bytes()
            vm = "OPEMOS-Ubuntu-KVM-" + label.upper()
            role = stage.validate_nested_actual(actual, queue, serial, vm, actual["sourcePins"])
            self.assertEqual(role["role"], "nested_linux")
            self.assertFalse(role["fullstack_claim"])
            self.assertFalse(role["fedora_appliance_claim"])
            self.assertTrue(stage._INVENTORY["subject_contract"](vm, "nested-ubuntu-linux", "nested_linux"))
            self.assertFalse(stage._INVENTORY["subject_contract"](vm, "ubuntu-full-stack", "fedora_appliance"))
            for fault in ("sourceStable", "childExited", "exit", "serialSHA256"):
                bad = copy.deepcopy(actual);bad[fault] = "UNKNOWN"
                with self.assertRaises((ValueError, TypeError)): stage.validate_nested_actual(bad, queue, serial, vm, actual["sourcePins"])
            bad = copy.deepcopy(queue);bad["result"]["terminalLifecycle"]["postStopCgroupProof"]["completeTraversal"] = False
            with self.assertRaises(ValueError): stage.validate_nested_actual(actual, bad, serial, vm, actual["sourcePins"])
            with self.assertRaises(ValueError): stage.validate_nested_actual(actual, queue, serial[:-20], vm, actual["sourcePins"])
            self.assertFalse(stage._INVENTORY["subject_contract"]("OPEMOS-Ubuntu-Test", "nested-ubuntu-linux", "nested_linux"))

    def test_historical_nested_result_cannot_become_current_pipeline_wrapper(self):
        vm = "OPEMOS-Ubuntu-KVM-A"
        actual = json.loads((Path(__file__).with_name("fixtures") / "omen-ci-nested/a-result.json").read_bytes())
        with self.assertRaises(ValueError):
            stage.validate_receipt(actual, "nested-ubuntu-linux", {"source_commit": "a" * 40, "nonce": "b" * 32},
                {"inventory_vm_id": vm, "runtime_instance_id": "owned-new", "job_ids": ["new"], "input_sha256": "c" * 64})
        value = {"source_commit": "a" * 40, "run_id": "12", "attempt": "1", "nonce": "b" * 32,
                 "vms": stage._INVENTORY["default_rows"]("unavailable")}
        self.assertEqual(stage._INVENTORY["normalize"](value)["aggregate"]["status"], "failed")
        rendered = stage._INVENTORY["markdown"](stage._INVENTORY["normalize"](value))
        for platform in ("Windows", "Ubuntu", "macOS", "Transferred original VMs"):
            self.assertIn("### " + platform, rendered)


if __name__ == "__main__":
    unittest.main()

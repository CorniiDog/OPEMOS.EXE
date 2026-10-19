"""Focused receipt fault tests; synthetic examples never constitute VM acceptance.

Execute only in admitted GitHub CI or a VM. No SSH, queue or hardware is used.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile


def module(name):
    path = Path(__file__).resolve().parents[1] / "scripts" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


stage = module("omen_ci_stage")
E = stage._EXECUTABLES
SOURCE = "a" * 40


def descriptor(platform, index):
    return {"schema":1, "repository":"CorniiDog/OPEMOS.EXE", "source_commit":SOURCE, "platform":platform,
            "workflow":E["PRODUCERS"][platform]["workflow"], "producer_run_id":str(100 + index), "producer_attempt":"2",
            "event":"push", "ref":"refs/heads/main", "artifact_id":str(200 + index), "artifact_name":"package-" + platform,
            "artifact_archive_sha256":"b" * 64, "package_name":"package-" + platform + ".zip", "package_sha256":"c" * 64,
            "package_bytes":1024, "executable_name":"executable-" + platform, "executable_sha256":"d" * 64, "executable_bytes":512}


def expected():
    return {E["key"](value):value for index, platform in enumerate(E["PRODUCERS"], 1) for value in [descriptor(platform, index)]}


def outcomes(values):
    rows = {name:{"status":"passed", "executable":value, "source_commit":SOURCE, "run_id":"900", "attempt":"3",
                  "operation_nonce":format(index, "032x"), "active":False, "actual_receipt_verified":True,
                  "build_receipt_sha256":hashlib.sha256((name+"build").encode()).hexdigest(),
                  "heal_receipt_sha256":hashlib.sha256((name+"heal").encode()).hexdigest(),
                  "install_receipt_sha256":hashlib.sha256((name+"install").encode()).hexdigest(),
                  "output_identity":"output-" + name, "target_generation":"target-" + name}
            for index, (name,value) in enumerate(values.items(), 1)}
    path=Path(__file__).with_name('omen_ci_pointer_fixture.py')
    spec=importlib.util.spec_from_file_location('generated_executable_pointer_fixture',path)
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    for name,row in rows.items():row['pointer_acceptance']=fixture.synthetic_proof(E,row['executable'],row['operation_nonce'],name)
    return rows



class PerExecutableIdentity(unittest.TestCase):
    def test_every_platform_and_distinct_artifact_are_required(self):
        values = expected()
        self.assertEqual(E["validate_expected"](values, SOURCE), values)
        for name in values:
            partial = {key:value for key,value in values.items() if key != name}
            with self.assertRaises(ValueError):E["validate_expected"](partial, SOURCE)
        alias = copy.deepcopy(values);name = next(iter(alias));alias["alias"] = alias.pop(name)
        with self.assertRaises(ValueError):E["validate_expected"](alias, SOURCE)

    def test_pr_foreign_source_wrong_workflow_or_attempt_cannot_be_expected(self):
        value = descriptor("windows", 1)
        for field, wrong in (("source_commit","e"*40),("event","pull_request"),("ref","refs/pull/1/merge"),
                             ("workflow", E["PRODUCERS"]["ubuntu"]["workflow"]),("producer_attempt","0")):
            changed = dict(value, **{field:wrong})
            with self.assertRaises(ValueError):E["descriptor"](changed, SOURCE)

    def test_missing_one_outcome_or_old_run_attempt_stays_failed(self):
        values = expected();rows = outcomes(values)
        self.assertEqual(E["report"](values, rows, SOURCE,"900","3")["aggregate"]["status"],"passed")
        for field, wrong in (("run_id","899"),("attempt","2"),("source_commit","f"*40),("active",True),
                             ("actual_receipt_verified",False)):
            changed = copy.deepcopy(rows);changed[next(iter(changed))][field] = wrong
            self.assertEqual(E["report"](values,changed,SOURCE,"900","3")["aggregate"]["status"],"failed")
        rows.pop(next(iter(rows)))
        report = E["report"](values,rows,SOURCE,"900","3")
        self.assertEqual(len(report["artifacts"]),3);self.assertEqual(report["aggregate"]["status"],"failed")

    def test_one_output_job_generation_or_receipt_cannot_cover_another_executable(self):
        values = expected();original = outcomes(values);names = list(original)
        for field in ("operation_nonce","build_receipt_sha256","heal_receipt_sha256","install_receipt_sha256","output_identity","target_generation"):
            rows = copy.deepcopy(original);rows[names[1]][field] = rows[names[0]][field]
            self.assertEqual(E["report"](values,rows,SOURCE,"900","3")["aggregate"]["status"],"failed",field)
        rows = copy.deepcopy(original);rows[names[1]]["executable"] = values[names[0]]
        self.assertEqual(E["report"](values,rows,SOURCE,"900","3")["aggregate"]["status"],"failed")

    def test_equal_image_hash_does_not_hide_distinct_output_and_target_requirement(self):
        values = expected();rows = outcomes(values)
        for row in rows.values():row["image_sha256"] = "f"*64
        self.assertEqual(E["report"](values,rows,SOURCE,"900","3")["aggregate"]["status"],"passed")
        rows["foreign"] = copy.deepcopy(next(iter(rows.values())))
        self.assertEqual(E["report"](values,rows,SOURCE,"900","3")["aggregate"]["status"],"failed")

    def test_missing_producers_always_display_all_three_platforms_as_failed(self):
        view = E["missing_report"](SOURCE,"900","3","No genuine runtime operands")
        self.assertEqual({x["executable"]["platform"] for x in view["artifacts"].values()},set(E["PRODUCERS"]))
        self.assertEqual(view["aggregate"]["passed"],0)

    def test_descriptor_zip_digest_and_complete_member_boundary(self):
        raw_json = E["canonical"](descriptor("windows",1));buffer = io.BytesIO()
        with zipfile.ZipFile(buffer,"w") as archive:archive.writestr("executable-producer.json",raw_json)
        raw=buffer.getvalue();metadata={"digest":"sha256:"+hashlib.sha256(raw).hexdigest()}
        self.assertEqual(E["archive_json"](raw,metadata,"executable-producer.json"),json.loads(raw_json))
        with self.assertRaises(ValueError):E["archive_json"](raw,dict(metadata,digest="sha256:"+"0"*64),"executable-producer.json")
        with self.assertRaises(ValueError):E["archive_json"](raw,metadata,"foreign.json")

    def test_absent_producer_attempt_preserves_explicit_three_platform_failures(self):
        def forbidden(*args):self.fail("Missing run:attempt must fail before metadata request")
        with self.assertRaises(ValueError) as caught:E["expectations"](SOURCE,{p:"" for p in E["PRODUCERS"]},forbidden,forbidden)
        self.assertEqual(set(caught.exception.errors),set(E["PRODUCERS"]))
        self.assertEqual(caught.exception.partial,{})

    def test_bridge_is_exact_and_cannot_claim_local_actual_receipt_validation(self):
        values=expected();url="https://github.com/CorniiDog/OPEMOS.EXE/actions/runs/900";statuses={}
        for index,value in enumerate(values.values(),1):
            statuses[E["context"](value)]={"id":index,"state":"success","description":E["binding"]("900","3",value,format(index,"032x")),"target_url":url}
        statuses["opemos/steamos/all-executables"]={"state":"success","description":"r:900/3;e:"+E["digest"](values),"target_url":url}
        view=E["status_view"](values,statuses,SOURCE,"900","3",url)
        self.assertEqual(view["aggregate"]["status"],"passed")
        self.assertTrue(view["status_bridge_view"])
        self.assertTrue(all(row["actual_receipt_verified"] is False for row in view["artifacts"].values()))
        changed=copy.deepcopy(statuses);changed[next(iter(changed))]["description"] = E["binding"]("899","3",next(iter(values.values())),"1"*32)
        self.assertFalse(E["status_view"](values,changed,SOURCE,"900","3",url)["complete"])
        changed=copy.deepcopy(statuses);changed.pop(next(iter(changed)))
        self.assertFalse(E["status_view"](values,changed,SOURCE,"900","3",url)["complete"])

    def test_bridge_refuses_duplicate_operation_nonce_and_foreign_aggregate(self):
        values=expected();url="https://github.com/CorniiDog/OPEMOS.EXE/actions/runs/900"
        rows={E["context"](v):{"state":"success","description":E["binding"]("900","3",v,"1"*32),"target_url":url}for v in values.values()}
        rows["opemos/steamos/all-executables"]={"state":"success","description":"r:900/3;e:"+E["digest"](values),"target_url":url}
        self.assertEqual(E["status_view"](values,rows,SOURCE,"900","3",url)["aggregate"]["status"],"failed")
        rows["opemos/steamos/all-executables"]["description"]="r:899/3;e:"+E["digest"](values)
        self.assertFalse(E["status_view"](values,rows,SOURCE,"900","3",url)["complete"])

    def test_current_controller_preflight_failure_completes_failed_without_old_or_fake_artifact_passes(self):
        values=expected();url="https://github.com/CorniiDog/OPEMOS.EXE/actions/runs/900"
        statuses={"opemos/steamos/all-executables":{"state":"failure","description":"r:900/3;e:unavailable","target_url":url}}
        view=E["status_view"](values,statuses,SOURCE,"900","3",url)
        self.assertTrue(view["complete"]);self.assertEqual(view["aggregate"]["passed"],0)
        self.assertTrue(all(row["status"] == "failed" for row in view["artifacts"].values()))
        statuses["opemos/steamos/all-executables"]["description"]="r:899/3;e:unavailable"
        self.assertFalse(E["status_view"](values,statuses,SOURCE,"900","3",url)["complete"])

    def test_missing_unknown_or_duplicated_join_jobs_never_escape_retention(self):
        plan={"executable_acceptance":{"windows-201":{"build_operand":{"job_ids":["build-a"]},"heal_operand":{"job_ids":["heal-a"]}}}}
        self.assertEqual(stage.executable_protected_jobs(plan),["build-a","heal-a"])
        changed=copy.deepcopy(plan);changed["executable_acceptance"]["windows-201"]["heal_operand"]["job_ids"]=["build-a"]
        with self.assertRaises(ValueError):stage.executable_protected_jobs(changed)
        self.assertFalse(stage.closed_jobs(stage.executable_protected_jobs(plan),{}))


class CompletedImageAndFullUSB(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.exe=descriptor("windows",1)
        self.manifest={"schemaVersion":1,"resultClass":"nvidia-mutation-valid","input":{"sourceSha256":"1"*64},
            "output":{"format":"raw","bytes":4096,"sha256":"2"*64},"steamos":{"architecture":"x86_64","layoutScheme":"valve-recovery-a"},
            "integration":{"milestone":"nvidia-offline-installed","nvidia":{"status":"success","phase":"complete","reason":"install_complete",
                "mountsReleased":True,"compressionPolicyRestored":True}},
            "validation":{k:True for k in ("passed","sourceUnchanged","candidateAttachedReadOnly","layoutRecognized","markerVerified","nvidiaPayloadVerified",
                "recoveryRollbackVerified","installationMediaWelcomeVerified","installedRecoveryGuardianPayloadVerified")}}
        self.manifest["validation"]["installationMediaWelcomeRevision"]="synthetic-test-revision"
        self.build={"output":{"input_sha256":"1"*64,"sha256":"2"*64},"files":{"image":{"kind":"output-image","sha256":"2"*64,"size":4096},
            "inspection":{"kind":"completed-image-inspection"}},"roles":{"virtual_usb":{"bytes":4096,"written_bytes":4096,"readback_bytes":4096,
            "capacity_bytes":8192,"flushed":True,"full_readback":True}},"completed_image_inspection":{"normal_command":"inspect_completed_nvidia_image",
            "passed":True,"package_sha256":self.exe["package_sha256"],"image_sha256":"2"*64,"welcome_revision":"synthetic-test-revision","evidence":"inspection"}}
        self.counter=0;self.seal()

    def seal(self):
        self.counter+=1;p=self.root/("manifest-"+str(self.counter)+".json");raw=json.dumps(self.manifest).encode();p.write_bytes(raw);p.chmod(0o600)
        sha=hashlib.sha256(raw).hexdigest();self.build["files"]["manifest"]={"path":str(p),"kind":"output-manifest","size":len(raw),"sha256":sha}
        self.build["output"]["manifest_sha256"]=sha;self.build["completed_image_inspection"]["manifest_sha256"]=sha

    def test_real_completed_manifest_and_full_byte_usb_shape(self):
        stage.validate_executable_output(self.build,self.exe)
        for key,value in (("written_bytes",4095),("readback_bytes",4095),("flushed",False),("full_readback",False),("capacity_bytes",4095)):
            changed=copy.deepcopy(self.build);changed["roles"]["virtual_usb"][key]=value
            with self.assertRaisesRegex(ValueError,"full image bytes"):stage.validate_executable_output(changed,self.exe)

    def test_marker_only_or_wrong_image_source_manifest_is_rejected(self):
        for field,value in (("resultClass","marker-only"),("schemaVersion",2)):
            old=self.manifest[field];self.manifest[field]=value;self.seal()
            with self.assertRaises(ValueError):stage.validate_executable_output(self.build,self.exe)
            self.manifest[field]=old
        self.manifest["output"]["bytes"]=4095;self.seal()
        with self.assertRaises(ValueError):stage.validate_executable_output(self.build,self.exe)

    def test_existing_app_completed_image_consumer_cannot_be_omitted_or_replaced(self):
        for key,value in (("passed",False),("normal_command","test-override"),("package_sha256","9"*64),("welcome_revision","old-revision")):
            changed=copy.deepcopy(self.build);changed["completed_image_inspection"][key]=value
            with self.assertRaisesRegex(ValueError,"normal app"):stage.validate_executable_output(changed,self.exe)

    def test_readonly_manifest_bytes_custody_detects_replacement(self):
        item=self.build["files"]["manifest"];Path(item["path"]).write_bytes(b"{}")
        with self.assertRaises(ValueError):stage.validate_executable_output(self.build,self.exe)


if __name__ == "__main__":
    unittest.main()

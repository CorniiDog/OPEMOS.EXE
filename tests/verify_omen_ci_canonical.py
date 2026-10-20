"""REQUIRED actual canonical producer verification inside admitted OMEN UID1000.

Not a public synthetic safety batch; absence of the exact private fixture fails.
Run explicitly, retaining stderr/stdout and this create-only JSON result.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import tempfile
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("canonical_qualification_stage", ROOT / "scripts/omen_ci_stage.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
FIXTURE_SHA = "ba577d32e0ad4d582a2908521695056256f0d81c71f715486b83ff2648c379de"
RESULTS = []


class RequiredCanonicalProducer(unittest.TestCase):
    def test_unchanged_actual_canonical77rows_same_nested_separate_scratch(self):
        self.assertEqual(os.getuid(),1000,"Required OMEN qualification runs UID1000")
        fixture=os.environ.get("OPEMOS_CI_CANONICAL_QUEUE_FIXTURE_PATH")
        self.assertTrue(fixture,"Missing REQUIRED absolute private canonical queue fixture; no skip/pass")
        source=Path(fixture)
        self.assertTrue(source.is_absolute() and source.resolve()==source,"Exact absolute fixture required")
        pin,raw=stage._READER.read_verified(source,1024**2,expected_sha=FIXTURE_SHA,expected_size=388189,uid=1000)
        normal=stage._READER.verified_namespace(raw,source,"actual_canonical_status_verification")
        for relation in ("same","nested","separate"):
            with self.subTest(scratch=relation), tempfile.TemporaryDirectory() as temp:
                work=Path(temp);work.chmod(0o700);root=work/"queue";root.mkdir(mode=0o700)
                scratch=root if relation=="same" else root/"scratch" if relation=="nested" else work/"scratch"
                if scratch!=root:scratch.mkdir(mode=0o700)
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(normal["main"](["--queue",str(root),"init"]),0)
                _,database=normal["connect"](root);pool=normal["config"](database)
                for index in range(77):
                    database.execute("INSERT INTO jobs(id,spec,state,result) VALUES(?,?,?,?)",(
                        "retained-"+str(index),json.dumps({"platform":"linux"}),"unknown"if index==76 else"passed",
                        json.dumps({"unknown_historical":"escaped\n"*70000,"future":{"unknown":True}})))
                database.commit();database.close()
                config={"queue_dir":str(root),"queue_entry":{"path":str(source),"sha256":pin["sha256"]},"queue_modules":[],
                    "pool_sha256":hashlib.sha256(json.dumps(pool,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
                    "queue_metadata":{"scratch_dir":str(scratch),"max_bytes":192*1024**2,"free_reserve_bytes":0}}
                report={};record={"scratch_relation":relation,"metadata_custody":report,"status":"failed"};RESULTS.append(record)
                rows=stage.queue_status(config,diagnostic=report)
                self.assertEqual(len(rows),77);self.assertGreater(report["bytes"],32*1024**2)
                self.assertEqual(rows["retained-76"]["state"],"unknown")
                self.assertEqual(rows["retained-0"]["result"]["future"],{"unknown":True})
                self.assertTrue(report["capture_fd_closed"]);self.assertTrue(report["normal_queue_descriptors_closed"])
                self.assertTrue(report["sealed_manifest_fds_closed"]);self.assertTrue(report["all_rows_retained"])
                self.assertEqual(report["queue_fds_before"],report["queue_fds_after_owned_close"])
                self.assertEqual(report["producer_exit"],0);self.assertTrue(report["complete"])
                owned=report["owned_descriptors"];self.assertEqual(len(owned),1)
                self.assertEqual(owned[0]["role"],"metadata-capture");self.assertTrue(owned[0]["before_close"]["open"])
                self.assertFalse(owned[0]["after_close"]["open"])
                # This full result contains ACTUAL canonical metadata; it is a
                # metadata/pipe/retention probe, never all20/fullstack acceptance.
                contract={"max_bytes":512*1024**2,"stderr_max_bytes":1024**2,"free_reserve_bytes":0}
                stage._RESULT["composition"]({**config,"result_contract":contract},{"admitted_vm_ids":[],"expected_executables":{}})
                ci=work/"owned-ci";ci.mkdir(mode=0o700);(ci/".receipts").mkdir(mode=0o700)
                stage.create_json(ci/stage.MARKER,{"schema":1,"uid":1000,"purpose":"OPEMOS CI copies only"})
                name="run-12-1-"+"a"*32;run=ci/name;run.mkdir(mode=0o700);(run/"artifacts").mkdir(mode=0o700)
                stage.create_json(run/".lock",{})
                stage.create_json(run/".owned.json",{"schema":1,"name":name,"uid":1000,"created":100,"expires":100+stage.TTL,
                    "job_ids":["unit-metadata-retention-only"],"result_max_bytes":contract["max_bytes"]})
                full={"kind":"ACTUAL_CANONICAL_METADATA_RESULT_PIPE_RETENTION_PROBE_ONLY","run_name":name,"active":False,
                      "queue_rows":rows,"metadata_custody":report,"fullstack_acceptance":False}
                count=stage._RESULT["write_full"](run/"receipt.json",full,contract["max_bytes"])
                self.assertGreater(count,32*1024**2)
                child="import pathlib,sys;f=pathlib.Path(sys.argv[1]).open('rb');import shutil;shutil.copyfileobj(f,sys.stdout.buffer);f.close()"
                transport=stage._RESULT["capture"]([sys.executable,"-I","-c",child,str(run/"receipt.json")],b"",contract,work/"transport",60)
                streamed=transport["streams"]["stdout"]
                _,wire=stage._READER.read_verified(streamed["path"],contract["max_bytes"],expected_sha=streamed["sha256"],expected_size=streamed["bytes"],uid=1000)
                self.assertEqual(stage.strict_json(wire),full)
                removed=stage.expire({"result_contract":contract},{"unit-metadata-retention-only":{"state":"passed","result":{}}},100+stage.TTL,ci)
                self.assertEqual(removed,[name]);retained,_=stage.load_result(ci/".receipts"/(name+".json"),contract["max_bytes"])
                self.assertEqual(retained,full)
                record["result_transport_retention"]={"status":"passed","full_bytes":count,"wire_bytes":streamed["bytes"],
                    "wire_sha256":streamed["sha256"],"wire_EOF":streamed["EOF"],"transport_complete":transport["complete"],
                    "local_numeric_exit":transport["numeric_exit"],"local_reaped":transport["local_reaped"],
                    "all_unknown_rows_equal":True,"guarded_expiry_removed_only_new_owned_probe":True,
                    "retained_full_receipt_equal":True,"actual_SSH_claim":False,"fullstack_acceptance":False}
                record.update(status="passed",job_rows=len(rows),unknown_fields_preserved=True,normal_producer_exit=0)


def main():
    source=os.environ.get("OPEMOS_CI_SOURCE_COMMIT","")
    output=os.environ.get("OPEMOS_CI_CANONICAL_QUALIFICATION_RESULT","")
    if not re.fullmatch(r"[0-9a-f]{40}",source) or not Path(output).is_absolute():
        raise ValueError("REQUIRED exact source commit and absolute create-only qualification result path missing")
    instance=os.environ.get("OPEMOS_CI_VM_INSTANCE_ID","")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}",instance) or os.getuid()!=1000:
        raise ValueError("Required actual admitted VM instance identity and UID1000 missing")
    virt=subprocess.run(["/usr/bin/systemd-detect-virt","--vm"],capture_output=True,timeout=10)
    if virt.returncode!=0 or virt.stdout.strip() not in (b"kvm",b"qemu"):
        raise ValueError("Required actual OMEN QEMU/KVM guest detection failed; host/container is not qualification")
    guest={"runtime_instance_id":instance,"detection_command":["/usr/bin/systemd-detect-virt","--vm"],
           "detection_exit":virt.returncode,"detected_virtualization":virt.stdout.decode().strip()}
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(RequiredCanonicalProducer)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
    pins={}
    for name in ("scripts/omen_ci_stage.py","scripts/omen_ci_reader.py","scripts/omen_ci_inventory.py","scripts/omen_ci_executables.py",
                 "scripts/omen_ci_result.py","tests/verify_omen_ci_canonical.py"):
        pin,_=stage._READER.read_verified(ROOT/name,8*1024**2,uid=1000);pins[name]=pin["sha256"]
    value={"kind":"OPEMOS_REQUIRED_CANONICAL_METADATA_VM_QUALIFICATION_V1","status":"passed"if outcome.wasSuccessful()else"failed",
        "source_commit":source,"uid":os.getuid(),"numeric_exit":0 if outcome.wasSuccessful()else 1,
        "guest":guest,"canonical_fixture_sha256":FIXTURE_SHA,"canonical_fixture_bytes":388189,"source_pins":pins,"cases":RESULTS,
        "public_safety_batch_substitute":False,"genuine_vm_receipt":True,"fullstack_acceptance":False}
    stage.create_json(Path(output),value)
    return value["numeric_exit"]


if __name__=="__main__":
    raise SystemExit(main())

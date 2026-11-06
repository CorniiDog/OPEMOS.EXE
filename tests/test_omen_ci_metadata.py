"""Public synthetic FD/failure safety tests; not actual canonical qualification.

The mini producers below are explicit unit operands, never VM acceptance. Run
these project tests only in admitted CI/VM; the private real producer is a
separate REQUIRED command and receipt gate.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

path=Path(__file__).resolve().parents[1]/"scripts/omen_ci_stage.py"
spec=importlib.util.spec_from_file_location("metadata_safety_stage",path)
stage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class MetadataOwnedClosure(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.queue=self.root/"queue";self.queue.mkdir(mode=0o700)
        (self.queue/"queue.sqlite3").write_bytes(b"unit opaque volume, no canonical-source claim")
        self.counter=0

    def config(self,body,relation="same"):
        self.counter+=1;source=self.root/("synthetic-producer-"+str(self.counter)+".py")
        raw=("import json,os,sys\ndef main(argv):\n"+"\n".join("    "+line for line in body.splitlines())+"\n").encode()
        source.write_bytes(raw);source.chmod(0o600)
        scratch=self.queue if relation=="same" else self.queue/"scratch"if relation=="nested"else self.root/"scratch"
        scratch.mkdir(mode=0o700,exist_ok=True)
        return {"queue_dir":str(self.queue),"queue_entry":{"path":str(source),"sha256":hashlib.sha256(raw).hexdigest()},
                "queue_modules":[],"queue_metadata":{"scratch_dir":str(scratch),"max_bytes":128*1024**2,"free_reserve_bytes":0}}

    def assert_closed(self,proof,complete):
        self.assertEqual(proof["complete"],complete)
        self.assertTrue(proof["capture_fd_closed"])
        self.assertTrue(proof["sealed_manifest_fds_closed"])
        self.assertTrue(proof["normal_queue_descriptors_closed"])
        self.assertEqual(stage.descriptor_keys(proof["queue_fds_before"]),stage.descriptor_keys(proof["queue_fds_after_owned_close"]))
        self.assertTrue(proof["owned_descriptors"][0]["allocated"]["open"])
        self.assertTrue(proof["owned_descriptors"][0]["before_close"]["open"])
        self.assertFalse(proof["owned_descriptors"][0]["after_close"]["open"])

    def test_actual_owned_spool_closes_before_real_scan_same_nested_and_separate(self):
        for relation in ("same","nested","separate"):
            with self.subTest(relation=relation):
                proof={};value=stage.queue_call(self.config('print(json.dumps({"unit_only":True,"unknown":[1,2,3]}))\nreturn 0',relation),"status",capture_receipt=proof)
                self.assertEqual(value,{"unit_only":True,"unknown":[1,2,3]})
                self.assert_closed(proof,True);self.assertEqual(proof["producer_exit"],0)

    def cleanup_leaks(self,proof):
        before={row["fd"]for row in proof["queue_fds_before"]}
        for row in proof.get("queue_fds_after_owned_close",[]):
            if row["fd"]not in before and row["target"].startswith(str(self.queue)+"/unit-leak"):
                actual=stage.descriptor_observation(row["fd"])
                self.assertEqual(actual,row)
                os.close(row["fd"])

    def test_genuine_named_and_unlinked_anonymous_queue_fd_leaks_still_refused(self):
        for anonymous in (False,True):
            body='p=os.path.join(argv[1],"unit-leak")\nfd=os.open(p,os.O_CREAT|os.O_RDWR,0o600)\n'
            if anonymous:body+='os.unlink(p)\n'
            body+='print(json.dumps({"unit_only":True}))\nreturn 0'
            proof={}
            try:
                with self.assertRaises(stage.MetadataConsumerFailure)as caught:stage.queue_call(self.config(body),"status",capture_receipt=proof)
                self.assertIs(caught.exception.metadata_receipt,proof)
                self.assertFalse(proof["normal_queue_descriptors_closed"]);self.assertFalse(proof["complete"])
                self.assertTrue(proof["capture_fd_closed"])
                self.assertIn("left queue descriptors",str(caught.exception))
                self.assertTrue(any("unit-leak"in row["target"]for row in proof["queue_fds_after_owned_close"]))
                if anonymous:self.assertTrue(any(row["target"].endswith(" (deleted)")for row in proof["queue_fds_after_owned_close"]))
            finally:self.cleanup_leaks(proof)

    def test_producer_failure_retains_numeric_exit_and_complete_actual_fd_cleanup(self):
        proof={}
        with self.assertRaises(stage.MetadataConsumerFailure)as caught:
            stage.queue_call(self.config('print("partial producer output")\nreturn 7'),"status",capture_receipt=proof)
        self.assert_closed(proof,False);self.assertEqual(proof["producer_exit"],7)
        self.assertIn("consumer failed",caught.exception.metadata_receipt["first_failure"]["reason"])

    def test_overflow_failure_retains_byte_observations_without_truncation_or_fd_leak(self):
        proof={}
        with self.assertRaises(stage.MetadataConsumerFailure):
            stage.queue_call(self.config('print("x"*(9*1024**2))\nreturn 0'),"status",capture_receipt=proof)
        self.assert_closed(proof,False)
        self.assertGreater(proof["observed_bytes"],proof["before"]["cap_bytes"])
        self.assertFalse(proof["complete"]);self.assertIn("no truncation",proof["first_failure"]["reason"])

    def test_parse_and_partial_utf8_failures_still_close_owned_spool_before_scan(self):
        for producer in ('print("{malformed")\nreturn 0','sys.stdout.buffer.write(b"\\xc3")\nreturn 0'):
            proof={}
            with self.assertRaises(stage.MetadataConsumerFailure):stage.queue_call(self.config(producer),"status",capture_receipt=proof)
            self.assert_closed(proof,False);self.assertEqual(proof["producer_exit"],0)
            self.assertIn(proof["first_failure"]["type"],("JSONDecodeError","UnicodeDecodeError"))

    def test_close_fault_is_not_promoted_to_success_even_after_actual_fd_closes(self):
        original=stage.MetadataCapture.close
        def fail_after_close(value):
            already_closed=value.closed
            original(value)
            if not already_closed:raise ValueError("unit close verification fault after actual owned close")
        proof={}
        with mock.patch.object(stage.MetadataCapture,"close",fail_after_close):
            with self.assertRaises(stage.MetadataConsumerFailure):
                stage.queue_call(self.config('print("{}")\nreturn 0'),"status",capture_receipt=proof)
        self.assert_closed(proof,False);self.assertTrue(proof["close_failures"])
        self.assertIn("verification fault",proof["first_failure"]["reason"])

    def test_real_leak_is_retained_alongside_original_producer_failure(self):
        proof={};body='os.open(os.path.join(argv[1],"unit-leak"),os.O_CREAT|os.O_RDWR,0o600)\nprint("partial")\nreturn 9'
        try:
            with self.assertRaises(stage.MetadataConsumerFailure):stage.queue_call(self.config(body),"status",capture_receipt=proof)
            self.assertEqual(proof["producer_exit"],9);self.assertIn("consumer failed",proof["first_failure"]["reason"])
            self.assertTrue(proof["capture_fd_closed"]);self.assertFalse(proof["normal_queue_descriptors_closed"])
            self.assertTrue(any("left queue descriptors"in x["reason"]for x in proof["close_failures"]))
        finally:self.cleanup_leaks(proof)

    def test_sealed_manifest_descriptor_has_own_exact_before_after_close_custody(self):
        manifest={"version":1,"jobs":[{"id":"unit-only","cwd":"/unit","command":["/usr/bin/true"],"files":[],"approval":{"path":"/unit/admission.json"}}]}
        path=self.root/"manifest.json";raw=json.dumps(manifest).encode();path.write_bytes(raw);path.chmod(0o600)
        pin={"path":str(path),"sha256":hashlib.sha256(raw).hexdigest()}
        body='value=json.loads(open(argv[3]).read())\nprint(json.dumps({"unit_manifest":value["version"]}))\nreturn 0'
        proof={};value=stage.queue_call(self.config(body),"submit",[pin],capture_receipt=proof)
        self.assertEqual(value,{"unit_manifest":1});self.assert_closed(proof,True)
        self.assertEqual([x["role"]for x in proof["owned_descriptors"]],["metadata-capture","sealed-manifest"])
        self.assertTrue(all(x["after_close"]["open"]is False for x in proof["owned_descriptors"]))
        # Permission refusal is a required negative, independent of guest umask.
        with self.subTest(mode="0664-manifest-refused"):
            path.chmod(0o664)
            try:
                rejected={}
                with self.assertRaisesRegex(stage.MetadataConsumerFailure,"group/world writable"):
                    stage.queue_call(self.config(body),"submit",[pin],capture_receipt=rejected)
                self.assertEqual(path.read_bytes(),raw)
            finally:path.chmod(0o600)


class OwnedReadonlyPartitionReadiness(unittest.TestCase):
    """Real source FD custody; modeled NBD/proc and clock, not VM acceptance."""
    def fixture(self):
        import sys
        import types
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        root=Path(directory.name);source=Path(__file__).resolve().parents[1]/'scripts/omen_control'
        job_spec=importlib.util.spec_from_file_location('readiness_actual_job',source/'job.py')
        job=importlib.util.module_from_spec(job_spec)
        mask=os.umask(0o077)
        try:job_spec.loader.exec_module(job)
        finally:os.umask(mask)
        spec=importlib.util.spec_from_file_location('readiness_actual_helper',source/'provision_observer_rule.py')
        helper=importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules,{'job':job}):spec.loader.exec_module(helper)
        cow=root/'owned-cow';cow.write_bytes(b'opaque private source fixture')
        proc=root/'proc/42';proc.mkdir(parents=True)
        fields=['0']*20;fields[19]='123'
        (proc/'stat').write_text('42 (modeled-nbd) '+' '.join(fields))
        owner={'pid':42,'start_ticks':'123','offset':1128267776,'read_only':True,
               'argv':['/usr/bin/qemu-nbd','--read-only','--format=qcow2',
                       '--offset=1128267776','--connect=/dev/nbd0',str(cow)]}
        (proc/'cmdline').write_bytes(b'\0'.join(x.encode()for x in owner['argv'])+b'\0')
        sysfs=root/'sys';sysfs.mkdir();(sysfs/'pid').write_text('42\n')
        (sysfs/'ro').write_text('1\n');(sysfs/'holders').mkdir()
        helper.SYS=sysfs;helper.Path=lambda p:root/'proc'if p=='/proc'else Path(p)
        clock=types.SimpleNamespace(now=0)
        clock.monotonic=lambda:clock.now
        clock.sleep=lambda seconds:setattr(clock,'now',clock.now+seconds)
        helper.time=clock
        return helper,cow,owner,job.sig(cow.lstat()),clock,proc

    @staticmethod
    def positive():
        return {'numeric':0,'stdout':'DEVNAME=/dev/nbd0\nTYPE=ext4\nUSAGE=filesystem\n'
                'FSBLOCKSIZE=4096\nFSSIZE=38869663744\n','stderr':''}

    def test_initial_empty_two_then_strict_export_preserves_both_actual_frames(self):
        p,cow,owner,identity,clock,_=self.fixture();frames=[]
        initial={'numeric':2,'stdout':'','stderr':''};positive=self.positive()
        with mock.patch.object(p,'cmd',side_effect=[initial,positive])as command:
            result=p.readonly_partition_probe(cow,owner,owner['offset'],identity,frames)
        self.assertEqual(frames,[initial,positive]);self.assertIs(result,positive)
        self.assertEqual(command.call_count,2);self.assertEqual(clock.now,.25)
        self.assertTrue(all(0<x.kwargs['timeout']<=2 for x in command.call_args_list))
        p.exact_partition_export(result,38869663744)
        wrong=dict(positive,stdout=positive['stdout'].replace('TYPE=ext4','TYPE=xfs'))
        with self.assertRaisesRegex(RuntimeError,'not exact ext4'):
            p.exact_partition_export(wrong,38869663744)

    def test_other_cli_failure_or_output_never_retried_or_promoted(self):
        for frame in({'numeric':1,'stdout':'','stderr':''},
                      {'numeric':2,'stdout':'partial','stderr':''},
                      {'numeric':2,'stdout':'','stderr':'I/O error'},
                      dict(self.positive(),stdout='DEVNAME=/dev/nbd0\nTYPE=xfs\n')):
            with self.subTest(frame=frame):
                p,cow,owner,identity,_,_=self.fixture();frames=[]
                with mock.patch.object(p,'cmd',return_value=frame)as command:
                    result=p.readonly_partition_probe(cow,owner,owner['offset'],identity,frames)
                command.assert_called_once();self.assertEqual(frames,[frame])
                with self.assertRaises(RuntimeError):p.exact_partition_export(result,38869663744)

    def test_fixed_deadline_exhaustion_and_late_positive_still_refuse(self):
        p,cow,owner,identity,clock,_=self.fixture();frames=[]
        with mock.patch.object(p,'cmd',return_value={'numeric':2,'stdout':'','stderr':''})as command:
            result=p.readonly_partition_probe(cow,owner,owner['offset'],identity,frames)
        self.assertLessEqual(command.call_count,9);self.assertLess(clock.now,2)
        with self.assertRaises(RuntimeError):p.exact_partition_export(result,38869663744)
        p,cow,owner,identity,clock,_=self.fixture();frames=[]
        def late(*args,**kwargs):clock.now=2.01;return self.positive()
        with mock.patch.object(p,'cmd',side_effect=late):
            with self.assertRaisesRegex(RuntimeError,'late readonly'):
                p.readonly_partition_probe(cow,owner,owner['offset'],identity,frames)
        self.assertEqual(frames,[self.positive()])  # late evidence retained, not accepted
        p,cow,owner,identity,clock,_=self.fixture()
        clock.monotonic=mock.Mock(side_effect=[0,3])
        with mock.patch.object(p,'cmd')as command:
            with self.assertRaisesRegex(RuntimeError,'deadline expired'):
                p.readonly_partition_probe(cow,owner,owner['offset'],identity,[])
        command.assert_not_called()

    def test_changed_identity_or_association_refuses_before_next_probe(self):
        mutations=[lambda p,c,o,r:(p.SYS/'pid').write_text('99'),
                   lambda p,c,o,r:(p.SYS/'ro').write_text('0'),
                   lambda p,c,o,r:(p.SYS/'holders/foreign').write_text(''),
                   lambda p,c,o,r:(r/'cmdline').write_bytes(b'foreign\0'),
                   lambda p,c,o,r:(r/'stat').write_text('42 (other) '+' '.join(['0']*20)),
                   lambda p,c,o,r:c.write_bytes(b'changed-source'),
                   lambda p,c,o,r:o.update(read_only=False),
                   lambda p,c,o,r:o.update(offset=0)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                p,cow,owner,identity,clock,proc=self.fixture();frames=[]
                def first(*args,**kwargs):
                    mutate(p,cow,owner,proc)
                    return {'numeric':2,'stdout':'','stderr':''}
                before=set(os.listdir('/proc/self/fd'))
                with mock.patch.object(p,'cmd',side_effect=first)as command:
                    with self.assertRaises(RuntimeError):
                        p.readonly_partition_probe(cow,owner,1128267776,identity,frames)
                command.assert_called_once();self.assertEqual(len(frames),1)
                self.assertEqual(set(os.listdir('/proc/self/fd')),before)


class RequiredCanonicalAdmission(unittest.TestCase):
    def test_public_safety_or_old_source_cannot_substitute_for_required_actual_omen_fixture(self):
        pins={name:"a"*64 for name in stage.QUALIFICATION_FILES}
        for value in ({},{"status":"passed","uid":1000,"numeric_exit":0,"public_safety_batch_substitute":True},
                      {"kind":"OPEMOS_REQUIRED_CANONICAL_METADATA_VM_QUALIFICATION_V1","status":"passed","source_commit":"b"*40}):
            with self.assertRaises(ValueError):stage.validate_canonical_qualification(value,pins,"c"*40,"a"*64)
        with self.assertRaises(ValueError):stage.validate_canonical_qualification({},pins,"c"*40,"e"*64)

    def test_qualified_source_needs_all_three_actual_closed_captures_and_preserved_unknown_rows(self):
        import stat
        pins={name:"a"*64 for name in stage.QUALIFICATION_FILES}
        cases=[]
        for relation in ("same","nested","separate"):
            identity={key:0 for key in stage._FULL9};identity.update(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o600,st_uid=1000,st_gid=1000)
            allocated={"fd":9,"open":True,"target":"/unit/anonymous (deleted)","identity":identity}
            before=copy.deepcopy(allocated);before["identity"]["st_size"]=33*1024**2
            proof={"bytes":33*1024**2,"producer_source_sha256":stage.CANONICAL_QUEUE_SHA,"job_rows":77,"producer_exit":0,
                   "all_rows_retained":True,"complete":True,"capture_fd_closed":True,"sealed_manifest_fds_closed":True,
                   "normal_queue_descriptors_closed":True,"queue_fds_before":[],"queue_fds_after_owned_close":[],
                   "owned_descriptors":[{"role":"metadata-capture","allocated":allocated,"before_close":before,"after_close":{"fd":9,"open":False}}]}
            probe={"status":"passed","full_bytes":33*1024**2,"wire_bytes":33*1024**2,"wire_sha256":"b"*64,
                   "local_numeric_exit":0,"actual_SSH_claim":False,**{k:True for k in ("wire_EOF","transport_complete","local_reaped",
                   "all_unknown_rows_equal","guarded_expiry_removed_only_new_owned_probe","retained_full_receipt_equal")}}
            cases.append({"scratch_relation":relation,"status":"passed","job_rows":77,"unknown_fields_preserved":True,
                          "normal_producer_exit":0,"metadata_custody":proof,"result_transport_retention":probe})
        value={"kind":"OPEMOS_REQUIRED_CANONICAL_METADATA_VM_QUALIFICATION_V1","status":"passed","source_commit":"c"*40,
               "uid":1000,"numeric_exit":0,"canonical_fixture_sha256":stage.CANONICAL_QUEUE_SHA,"canonical_fixture_bytes":388189,
               "source_pins":pins,"public_safety_batch_substitute":False,"genuine_vm_receipt":True,"cases":cases}
        stage.validate_canonical_qualification(value,pins,"c"*40,"a"*64)
        for field in ("complete","capture_fd_closed","normal_queue_descriptors_closed","all_rows_retained"):
            changed=copy.deepcopy(value);changed["cases"][0]["metadata_custody"][field]=False
            with self.assertRaises(ValueError):stage.validate_canonical_qualification(changed,pins,"c"*40,"a"*64)
        changed=copy.deepcopy(value);changed["cases"][0]["metadata_custody"]["owned_descriptors"][0]["after_close"]["open"]=True
        with self.assertRaises(ValueError):stage.validate_canonical_qualification(changed,pins,"c"*40,"a"*64)
        changed=copy.deepcopy(value);changed["cases"].pop()
        with self.assertRaises(ValueError):stage.validate_canonical_qualification(changed,pins,"c"*40,"a"*64)


if __name__=="__main__":
    unittest.main()

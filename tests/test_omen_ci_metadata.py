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


class OrdinaryDispatcherStartup(unittest.TestCase):
    """Real queue/SQL/locks and normal close API; clock only is modeled."""
    def setUp(self):
        import contextlib,io,gc
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        source=path.parent/'omen_control/test_queue.py'
        spec=importlib.util.spec_from_file_location('startup_actual_queue',source)
        self.q=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.q)
        self.state=self.root/'state'
        with contextlib.redirect_stdout(io.StringIO()):self.q.main(['--queue',str(self.state),'init'])
        gc.collect()
        lock=self.state/'worker.lock';lock.write_bytes(b'');lock.chmod(0o664)
        marker=self.root/'admission.json';marker.write_text('{"fixtureOnly":true}');marker.chmod(0o600)
        self.job={'id':'correlated-unstarted-ubuntu','owner':'exe','platform':'ubuntu',
                  'command':['/usr/bin/true'],'cwd':str(self.root),'files':[str(marker)],
                  'cores':1,'memory':'1GiB','timeout_seconds':30,'resources':['fixture-only'],
                  'approval':{'path':str(marker),'sha256':hashlib.sha256(marker.read_bytes()).hexdigest()}}
        self.manifest=self.root/'manifest.json';self.manifest.write_text(json.dumps({'version':1,'jobs':[self.job]}));self.manifest.chmod(0o600)
        self.pin={'path':str(self.manifest),'sha256':hashlib.sha256(self.manifest.read_bytes()).hexdigest()}
        cfg={'cpu_ids':self.q.DEFAULT_CPUS,'memory_bytes':self.q.DEFAULT_RAM,
             'slice':'opemos-vm-pool.slice','manager':'system'}
        self.config={'queue_dir':str(self.state),'queue_entry':{'path':str(source),
                     'sha256':hashlib.sha256(source.read_bytes()).hexdigest()},'queue_modules':[],
                     'queue_metadata':{'scratch_dir':str(self.state),'max_bytes':128*1024**2,'free_reserve_bytes':0},
                     'pool_sha256':hashlib.sha256(json.dumps(cfg,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
        stage.queue_call(self.config,'submit',[self.pin])

    def test_absent_dispatcher_fails_correlated_job_promptly_without_late_launch(self):
        clock=[100.0];evidence={}
        def sleep(seconds):clock[0]+=seconds
        with mock.patch.object(stage.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(stage.time,'sleep',side_effect=sleep):
            with self.assertRaisesRegex(ValueError,'Ordinary dispatcher unavailable'):
                stage.wait_jobs(self.config,[self.job['id']],[self.pin],10000,evidence)
        self.assertLessEqual(clock[0],135)
        self.assertEqual(evidence['closure'],'CLOSED')
        self.assertEqual(evidence['normal_pending_closure']['closed_unstarted'],[self.job['id']])
        row=stage.queue_status(self.config)[self.job['id']]
        self.assertEqual(row['state'],'failed');self.assertIsNone(row['unit'])
        self.assertIs(row['result']['launched'],False)
        self.assertIs(row['result']['reservationRetained'],False)
        # The normal scheduler cannot start this closed request later.
        result=stage.queue_call(self.config,'status')
        self.assertEqual(result['runnable_now'],[])

    def test_live_worker_and_changed_manifest_refuse_pending_closure(self):
        import subprocess,sys
        body='import fcntl,sys;f=open(sys.argv[1]);fcntl.flock(f,fcntl.LOCK_EX);print("held",flush=True);sys.stdin.read(1)'
        worker=subprocess.Popen([sys.executable,'-I','-c',body,str(self.state/'worker.lock')],
                                stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(worker.stdout.readline().strip(),'held')
            with self.assertRaises(stage.MetadataConsumerFailure):
                stage.queue_call(self.config,'fail-unstarted',[self.pin])
            cut={};stage.queue_status(self.config,diagnostic=cut)
            self.assertIs(cut['worker_lock_free'],False)
        finally:
            worker.stdin.close();worker.wait(timeout=5);worker.stdout.close()
        wrong=dict(self.job,command=['/usr/bin/false'])
        self.manifest.write_text(json.dumps({'version':1,'jobs':[wrong]}))
        wrong_pin=dict(self.pin,sha256=hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        with self.assertRaises(stage.MetadataConsumerFailure):stage.queue_call(self.config,'fail-unstarted',[wrong_pin])
        row=stage.queue_status(self.config)[self.job['id']]
        self.assertEqual(row['state'],'pending');self.assertIsNone(row['unit'])

    def test_native_empty_worker_lock_accepts_0664_but_refuses_executable_otherwrite_or_content(self):
        lock=self.state/'worker.lock'
        cut={};stage.queue_status(self.config,diagnostic=cut)
        self.assertIs(cut['worker_lock_free'],True)
        for mode,content in((0o764,b''),(0o666,b''),(0o664,b'not an empty native lock')):
            with self.subTest(mode=oct(mode),content=bool(content)):
                lock.write_bytes(content);lock.chmod(mode)
                with self.assertRaisesRegex(ValueError,'worker lock custody'):
                    stage.queue_status(self.config,diagnostic={})
                with self.assertRaises(stage.MetadataConsumerFailure):
                    stage.queue_call(self.config,'fail-unstarted',[self.pin])
                self.assertEqual(stage.queue_status(self.config)[self.job['id']]['state'],'pending')
        lock.write_bytes(b'');lock.chmod(0o664)
        result=stage.queue_call(self.config,'fail-unstarted',[self.pin])
        self.assertEqual(result['closed_unstarted'],[self.job['id']])


    def test_absent_worker_with_started_or_unknown_work_fails_without_release(self):
        import sqlite3
        for state in('running','unknown'):
            with self.subTest(state=state):
                # Canonical/kernel execution is modeled; SQL/lock/wait are real.
                with sqlite3.connect(self.state/'queue.sqlite3')as db:
                    retained=json.dumps({'reason':'Unit evidence missing; original reservation retained'})if state=='unknown'else None
                    db.execute('UPDATE jobs SET state=?,unit=?,started=?,cpus=?,result=? WHERE id=?',
                               (state,'fixture-started-unit.service',1,'[0]',retained,self.job['id']))
                db.close()  # sqlite's context commits; it does not close the FD
                clock=[100.0];evidence={}
                with mock.patch.object(stage.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(stage.time,'sleep',side_effect=lambda n:clock.__setitem__(0,clock[0]+n)):
                    with self.assertRaisesRegex(ValueError,'Ordinary dispatcher unavailable'):
                        stage.wait_jobs(self.config,[self.job['id']],[self.pin],10000,evidence)
                self.assertEqual(evidence['closure'],'UNKNOWN')
                self.assertIs(evidence['reservationRetained'],True)
                self.assertNotIn('normal_pending_closure',evidence)
                row=stage.queue_status(self.config)[self.job['id']]
                self.assertEqual((row['state'],row['unit']),(state,'fixture-started-unit.service'))
                with self.assertRaises(stage.MetadataConsumerFailure):stage.queue_call(self.config,'fail-unstarted',[self.pin])

    def test_late_status_cannot_extend_original_wait_deadline(self):
        clock=[1.0];called=[]
        def status(config,diagnostic):clock[0]=11.0;return {self.job['id']:{'state':'passed'}}
        with mock.patch.object(stage.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(stage,'queue_status',side_effect=status):
            with self.assertRaisesRegex(ValueError,'deadline after status'):
                stage.wait_jobs(self.config,[self.job['id']],[self.pin],10,{})

    @unittest.skipUnless(os.getuid()==1000 and Path('/run/user/1000/bus').exists(),
                         'actual ordinary user manager unavailable')
    def test_real_existing_manager_reenters_error_two_once_but_not_normal_failure_one(self):
        """Benign finite source fixture only; no listener, queue or VM effect."""
        import subprocess,sys,time,uuid
        source=path.parent/'omen_control/normal_cycle.py'
        spec=importlib.util.spec_from_file_location('actual_dispatcher_properties',source)
        cycle=importlib.util.module_from_spec(spec);spec.loader.exec_module(cycle)
        env=dict(os.environ,XDG_RUNTIME_DIR='/run/user/1000',DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/1000/bus')
        for code,expected in((2,2),(1,1)):
            unit='opemos-source-fixture-reentry-'+uuid.uuid4().hex+'.service'
            counter=self.root/('counter-'+str(code))
            body='import os,sys;f=open(sys.argv[1],"a");f.write("attempt\\n");f.flush();os.fsync(f.fileno());f.close();sys.exit(int(sys.argv[2]))'
            def call(args):return subprocess.run(args,env=env,capture_output=True,text=True,timeout=10)
            try:
                launch=call(['/usr/bin/systemd-run','--user','--unit='+unit,
                    '--property=RuntimeMaxSec=10','--property=MemoryMax=67108864',
                    '--property=MemorySwapMax=0','--property=AllowedCPUs=1',
                    *cycle.DISPATCHER_REENTRY_PROPERTIES,sys.executable,'-I','-c',body,str(counter),str(code)])
                self.assertEqual(launch.returncode,0,launch.stderr)
                end=time.monotonic()+12
                while True:
                    props=call(['/usr/bin/systemctl','--user','show',unit,'-p','ActiveState','-p','MainPID','-p','ControlGroup'])
                    self.assertEqual(props.returncode,0,props.stderr)
                    m=dict(z.split('=',1)for z in props.stdout.splitlines()if'='in z)
                    if m.get('ActiveState')=='failed'and m.get('MainPID')=='0'and m.get('ControlGroup')=='':break
                    self.assertLess(time.monotonic(),end,props.stdout);time.sleep(.1)
                self.assertEqual(counter.read_text().splitlines(),['attempt']*expected)
            finally:
                call(['/usr/bin/systemctl','--user','stop',unit])
                call(['/usr/bin/systemctl','--user','reset-failed',unit])


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

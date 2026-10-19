"""New Robot adapter safety/dispatch regressions. Run only in admitted VM/CI.

Synthetic unit cases are not mouse, graphical, GPU or full-stack acceptance.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
M=load('omen_robot');G=load('omen_robot_gate')

class DescriptorSafety(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def file(self,data=b'actual bounded source'):
        p=self.root/'source';p.write_bytes(data);p.chmod(0o600);return p
    def test_exact_bytes_consumed(self):
        p=self.file();self.assertEqual(M.raw_file(p,128,hashlib.sha256(p.read_bytes()).hexdigest(),os.getuid()),b'actual bounded source')
    def test_symlink_is_refused(self):
        p=self.file();q=self.root/'alias';q.symlink_to(p)
        with self.assertRaises(OSError):M.raw_file(q)
    def test_wrong_hash_is_refused(self):
        with self.assertRaises(ValueError):M.raw_file(self.file(),expected='0'*64)
    def test_group_writable_source_is_refused(self):
        p=self.file();p.chmod(0o664)
        with self.assertRaises(ValueError):M.raw_file(p)
    def test_oversized_source_is_refused(self):
        with self.assertRaises(ValueError):M.raw_file(self.file(),cap=4)
    def test_duplicate_json_is_refused(self):
        with self.assertRaises(ValueError):M.strict(b'{"nonce":1,"nonce":2}')
    def test_all20_inventory_and_both_nested_roles_visible(self):
        rows=M.inventory();self.assertEqual(len({x['id']for x in rows}),20)
        for name in ('OPEMOS-Ubuntu-KVM-A','OPEMOS-Ubuntu-KVM-B'):
            self.assertEqual(next(x for x in rows if x['id']==name)['subject_role'],'nested_linux')

class IndependentOutcomes(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.env=patch.dict(os.environ,{'GITHUB_REPOSITORY':M.REPO,'GITHUB_RUN_ID':'101','GITHUB_RUN_ATTEMPT':'2','OPEMOS_SOURCE_SHA':'a'*40,'OPEMOS_ROBOT_REPORT_DIR':str(self.root/'public')})
        self.env.start();self.engine=M.Engine(self.root/'private')
    def tearDown(self):self.env.stop();self.temp.cleanup()
    def test_one_missing_vm_does_not_suppress_next(self):
        ids=list(self.engine.results);calls=[]
        def transaction(kind,subject):
            calls.append(subject)
            if subject==ids[0]:raise ValueError('missing exact first operand')
            return {'status':'passed','synthetic_unit_only':True}
        with patch.object(self.engine,'transaction',side_effect=transaction):
            with self.assertRaises(ValueError):self.engine.vm(ids[0])
            self.engine.vm(ids[1])
        self.assertEqual(calls,ids[:2]);self.assertEqual(self.engine.results[ids[0]]['status'],'failed');self.assertEqual(len(self.engine.results),20)
    def test_absent_profile_leaves_twenty_explicit_outcomes(self):
        with patch.object(self.engine,'request',side_effect=FileNotFoundError('exact installed profile missing')):
            with self.assertRaises(FileNotFoundError):self.engine.vm(next(iter(self.engine.results)))
        rows=json.loads(sorted((self.root/'public').glob('summary-*.json'))[-1].read_text())['vms']
        self.assertEqual(len(rows),20);self.assertFalse(all(x['status']=='passed'for x in rows.values()))
    def test_failed_mac_does_not_prevent_windows_invocation(self):
        called=[]
        def request(kind,subject):
            called.append(subject);raise FileNotFoundError(subject+' exact producer missing')
        with patch.object(self.engine,'request',side_effect=request):
            for platform in ('macos','windows'):
                with self.assertRaises(FileNotFoundError):self.engine.platform(platform)
        self.assertEqual(called,['macos','windows'])

class HostedRunnerGuard(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.previous=Path.cwd();os.chdir(self.root)
        (self.root/'ci').mkdir();(self.root/'ci/required-vms.json').write_bytes((ROOT/'ci/required-vms.json').read_bytes())
        self.event=self.root/'event.json';self.event.write_text('{}')
        self.state={'version':1,'repository':M.REPO,'source_commit':'a'*40,'checked_at':1000,'expires_at':1180,'ready':True,'runner_id':1,'runner_name':'opemos-omen-robot','labels':G.LABELS,'reason':'online'}
        self.environ={'GITHUB_REPOSITORY':M.REPO,'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_EVENT_PATH':str(self.event),'GITHUB_REF':'refs/heads/main','GITHUB_REF_PROTECTED':'true','GITHUB_SHA':'a'*40,'GITHUB_TOKEN':'synthetic-unit-token','GITHUB_OUTPUT':str(self.root/'output'),'GITHUB_STEP_SUMMARY':str(self.root/'summary')}
    def tearDown(self):os.chdir(self.previous);self.temp.cleanup()
    def run_gate(self,now=1001):
        class Reply:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,cap):return json.dumps({'protected':True,'commit':{'sha':'a'*40}}).encode()
        with patch.dict(os.environ,dict(self.environ,OPEMOS_OMEN_ROBOT_RUNNER_STATE=json.dumps(self.state))),patch.object(G.time,'time',return_value=now),patch.object(G.urllib.request,'urlopen',return_value=Reply()):
            return G.main()
    def test_fresh_route_is_not_a_vm_pass(self):
        self.assertEqual(self.run_gate(),0);value=json.loads(Path('robot-preflight/all20.json').read_text())
        self.assertTrue(all(r['status']=='unavailable'for r in value['vms'].values()))
    def test_stale_heartbeat_fails_before_self_hosted_queue(self):
        self.assertEqual(self.run_gate(now=1180),1)
        self.assertIn('ready=false',(self.root/'output').read_text())
    def test_other_source_fails(self):
        self.state['source_commit']='b'*40;self.assertEqual(self.run_gate(),1)
    def test_other_labels_fail(self):
        self.state['labels']=['self-hosted'];self.assertEqual(self.run_gate(),1)
    def test_other_repository_fails(self):
        self.state['repository']='other/repository';self.assertEqual(self.run_gate(),1)
    def test_absent_runner_fails_with_all20(self):
        self.state['runner_id']=None;self.state['ready']=False;self.assertEqual(self.run_gate(),1)
        self.assertEqual(len(json.loads(Path('robot-preflight/all20.json').read_text())['vms']),20)

class PointerKeywordCustody(unittest.TestCase):
    """Synthetic fault-only keyword wiring; never actual mouse acceptance."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.env=patch.dict(os.environ,{'GITHUB_REPOSITORY':M.REPO,'GITHUB_RUN_ID':'101','GITHUB_RUN_ATTEMPT':'2','OPEMOS_SOURCE_SHA':'a'*40,'OPEMOS_TRANSACTION_NONCE':'b'*32})
        self.env.start();self.P=load('OPEMOSPointer');self.pointer=self.P.OPEMOSPointer();self.fd=None;self.saved=[]
        self.driver=self.root/'driver.py';self.driver.write_text('# synthetic unit driver, no QMP/native effects\n');self.driver.chmod(0o600)
        context={'identity':{'source_commit':'a'*40,'run_id':'101','attempt':'2','nonce':'b'*32,'runtime_instance_id':'synthetic-only'},'action_id':'fresh-unit-action','point':{'x':1,'y':1},'clock':{'id':'unit-clock'},'sender_stdout_ref':'stdout','sender_stderr_ref':'stderr'}
        self.operation={'pointer_context':context,'driver':{'path':str(self.driver),'sha256':hashlib.sha256(self.driver.read_bytes()).hexdigest()},'platform':'windows','observed_result_path':str(self.root/'new-observer.json'),'observer_source_sha256':'c'*64}
    def tearDown(self):self.env.stop();self.temp.cleanup()
    def operand(self):
        payload=json.dumps(self.operation,sort_keys=True,separators=(',',':')).encode();digest=hashlib.sha256(payload).hexdigest()
        admission={'kind':'OPEMOS_ROBOT_POINTER_ADMISSION','identity':self.operation['pointer_context']['identity'],'driver_sha256':self.operation['driver']['sha256'],'operation_sha256':digest,'admitted':True}
        p=self.root/'admission';p.write_text(json.dumps(admission));p.chmod(0o600)
        value=dict(self.operation,operation_payload_sha256=digest,admission={'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
        q=self.root/'operation';q.write_text(json.dumps(value));q.chmod(0o600)
        return str(q),hashlib.sha256(q.read_bytes()).hexdigest()
    def namespace(self,exit_code=0,close_error=False):
        def child(argv,records,**kwargs):
            self.fd=kwargs['pass_fds'][0]
            return {'numeric_exit':exit_code,'waited':True,'stdout_EOF':True,'stderr_EOF':True,'pipes_closed':True,'original_gone':True,'first_failure':None if exit_code==0 else {'type':'SyntheticChildNonzero'},'secondary_errors':[],'child_identity':{'pid':1,'start':2}},b'{"status":"sent"}',b''
        return {'ci10_reserve':lambda *a:{'sender_lifecycle_path':{'fd':0}},'ci10_inputs':lambda *a:[],'ci10_pending':lambda *a:None,'ci10_run_child':child,'ci10_json_finish':lambda *a:self.saved.append(a[1]),'ci10_close_outputs':lambda *a:[{'type':'SyntheticCloseFailure'}]if close_error else []}
    def test_sealed_source_fd_closed_after_normal_keyword(self):
        from types import SimpleNamespace
        ns=self.namespace()
        with patch.object(self.P,'modules',return_value={'_READER':SimpleNamespace(verified_namespace=lambda *a:ns)}):self.pointer.click(*self.operand())
        self.assertEqual(self.pointer.actual_pointer_calls,1)
        with self.assertRaises(OSError):os.fstat(self.fd)
        self.assertEqual(self.saved[0]['numeric_exit'],0)
    def test_failed_sender_and_secondary_close_do_not_become_a_click(self):
        from types import SimpleNamespace
        ns=self.namespace(exit_code=9,close_error=True)
        with patch.object(self.P,'modules',return_value={'_READER':SimpleNamespace(verified_namespace=lambda *a:ns)}):
            with self.assertRaisesRegex(ValueError,'Actual sender failure'):self.pointer.click(*self.operand())
        self.assertEqual(self.pointer.actual_pointer_calls,0);self.assertEqual(self.saved[0]['numeric_exit'],9)
        with self.assertRaises(OSError):os.fstat(self.fd)
    def test_prior_observation_refused_before_output_reservation(self):
        from types import SimpleNamespace
        (self.root/'new-observer.json').write_text('old unit receipt')
        def no_reservation(*a):raise AssertionError('must not reserve or input')
        ns={'ci10_reserve':no_reservation}
        with patch.object(self.P,'modules',return_value={'_READER':SimpleNamespace(verified_namespace=lambda *a:ns)}):
            with self.assertRaisesRegex(ValueError,'Old observed result refused'):self.pointer.click(*self.operand())
        self.assertEqual(self.pointer.actual_pointer_calls,0)

if __name__=='__main__':unittest.main()

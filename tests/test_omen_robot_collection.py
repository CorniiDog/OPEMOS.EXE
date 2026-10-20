"""Real subprocess/file handoff through current consumers, not guest/queue proof."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('collection_owner',ROOT/'scripts/omen_robot.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


class PublishedCollection(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.request=dict(repository=M.REPO,source_commit='a'*40,run_id='123',attempt='1',
                          nonce='b'*32,version=1,action='prepare',kind='inventory',
                          subject='OPEMOS-Ubuntu-KVM-A',consumer_started_epoch=100)
        self.operand={'receipt':str(self.root/'receipt.json'),'subject_role':'nested_linux',
                      'inventory_vm_id':self.request['subject']}
        self.robot={'job_id':'fresh-A','result_path':str(self.root/'guest.json')}
        self.proof={'identity':self.request,'boot_id':'11111111-1111-1111-1111-111111111111',
                    'inventory_vm_id':self.request['subject'],'execution_location':'inner_QEMU_guest',
                    'process_reaped':True,'channel_eof':True}
        # Models are explicitly not a guest success. The actual process uses
        # current dump(), current UID and real create-only/fsync file operations.
        code="import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from omen_robot import dump;dump(Path(sys.argv[2]),json.loads(sys.argv[4]));dump(Path(sys.argv[3]),json.loads(sys.argv[5]))"
        child=subprocess.run([sys.executable,'-B','-c',code,str(ROOT/'scripts'),
                              self.operand['receipt'],self.robot['result_path'],
                              json.dumps({'synthetic_case_only':True}),json.dumps(self.proof)],
                             capture_output=True,timeout=10)
        self.assertEqual(child.returncode,0,child.stderr)
        self.assertEqual(child.stdout,b'')
        self.collected={'identity':{k:self.request[k] for k in ('repository','source_commit','run_id','attempt','nonce')},
                        'effect':'READ_ONLY_CURRENT_OPERATION','job_ids':['fresh-A'],
                        'queue_job_id':'fresh-A','queue_state':'passed','queue_lifecycle_closed':True,
                        'receipt_path':self.operand['receipt'],'robot_result_path':self.robot['result_path'],
                        'receipt_sha256':self.sha(self.operand['receipt']),
                        'robot_result_sha256':self.sha(self.robot['result_path']),
                        'guest_boot_id':self.proof['boot_id'],
                        'host_boot_id':'22222222-2222-2222-2222-222222222222'}
        self.stage=M.modules()
    def tearDown(self):self.temp.cleanup()
    def sha(self,p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    def consume(self,c=None,jobs=None):
        return M.consume_collection(self.stage,self.collected if c is None else c,self.request,
                                    ['fresh-A'] if jobs is None else jobs,self.robot,self.operand,65536)
    def test_current_process_to_held_consumer(self):
        receipt,sha,proof=self.consume()
        self.assertEqual(proof['identity'],self.request)
        self.assertEqual(sha,self.collected['receipt_sha256'])
        self.assertTrue(receipt['synthetic_case_only'])
        self.assertEqual(Path(self.robot['result_path']).stat().st_uid,os.getuid())
    def test_identity_effect_jobs_and_terminal_faults(self):
        for key,value in [('effect','RUN_ANOTHER_JOB'),('job_ids',['collector-job']),
                          ('queue_job_id','old-A'),('queue_state','running'),
                          ('queue_lifecycle_closed',False),('receipt_path','/unrelated'),
                          ('robot_result_sha256','0'*64),('host_boot_id',self.proof['boot_id']),
                          ('guest_boot_id','3'*36)]:
            c=copy.deepcopy(self.collected);c[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.consume(c)
        c=copy.deepcopy(self.collected);c['identity']['nonce']='c'*32
        with self.assertRaises(ValueError):self.consume(c)
    def test_complete_multijob_artifact_set_not_selected_subset(self):
        c=copy.deepcopy(self.collected);c['job_ids']=['fresh-A','fresh-heal']
        self.consume(c,['fresh-A','fresh-heal'])
        with self.assertRaises(ValueError):self.consume(c,['fresh-A'])
        with self.assertRaises(ValueError):self.consume(c,['fresh-A','fresh-A'])
    def test_full_request_not_collect_subset(self):
        p=Path(self.robot['result_path']);v=json.loads(p.read_bytes())
        v['identity']=self.collected['identity'];p.write_text(json.dumps(v))
        self.collected['robot_result_sha256']=self.sha(p)
        with self.assertRaisesRegex(ValueError,'full original'):self.consume()
    def test_real_file_tamper_permissions_link_and_size(self):
        p=Path(self.operand['receipt']);p.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.consume()
        self.collected['receipt_sha256']=self.sha(p);p.chmod(0o666)
        with self.assertRaises(ValueError):self.consume()
        p.chmod(0o600);p.unlink();p.symlink_to(self.robot['result_path'])
        with self.assertRaises((ValueError,OSError)):self.consume()


if __name__=='__main__':unittest.main()

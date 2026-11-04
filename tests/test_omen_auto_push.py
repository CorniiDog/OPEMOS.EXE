"""Automatic candidate data path; run in admitted Linux CI/VM only.

Real metadata, held files, opaque archive transport, planner and final identity
consumers run here. GitHub HTTP data and native VM facts are modeled. These
tests are not evidence of an OMEN domain, installer, GPU or lifecycle closure.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
sys.path.insert(0,str(Path(__file__).parents[1]/'scripts/omen_control'))
import required_omen as gate
from test_omen_required import Metadata, encoded_zip

def load(name):
    path=Path(__file__).parents[1]/'scripts/omen_control'/(name+'.py')
    spec=importlib.util.spec_from_file_location('automatic_'+name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

P=load('planner');H=load('normal_heartbeat');N=load('normal_probe');C=load('control')

class AutomaticCandidateData(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.m=Metadata();self.m.run.update(head_branch='work/development',status='completed',conclusion='failure')
        self.m.value['ref']='refs/heads/work/development'
        self.archive=b'opaque candidate archive; never executed on controller'
        self.m.value['artifact_archive_sha256']=hashlib.sha256(self.archive).hexdigest()
        self.m.artifacts[0]['digest']='sha256:'+self.m.value['artifact_archive_sha256']
        self.m.raw=encoded_zip('executable-producer.json',self.m.value)
        self.m.artifacts[1]['digest']='sha256:'+hashlib.sha256(self.m.raw).hexdigest()
        self.expected=gate.producer_ready(None,'ubuntu','10','2',self.m.read,self.m.download)
        self.package=self.root/'candidate.zip';self.package.write_bytes(self.archive);self.package.chmod(0o400)
        self.r={'version':1,'action':'prepare','kind':'artifact','subject':{'platform':'ubuntu','artifact_id':'30'},
                'repository':gate.REPO,'source_commit':'e'*40,'run_id':'50','attempt':'1','nonce':'f'*32,'consumer_started_epoch':1,
                'candidate':{'descriptor':self.expected,'archive':{'path':str(self.package),
                    'sha256':hashlib.sha256(self.archive).hexdigest(),'bytes':len(self.archive)}}}
        self.recipe={'schema':1,'documents':[
            {'name':'identity.json','value':{'$request':'prepare'}},
            {'name':'candidate.json','value':{'controller':{'$run':'source_commit'},'executable':{'$candidate':'*'},
                                           'archive':{'$archive':'path'},'queue_job':{'$job':'steamos'}}}],
            'prepare':{'expected':{'$candidate':'*'},'config':{'$document':'candidate.json'},
                'operand':{'runtime_instance_id':{'$job':'disposable'}},
                'plan':{'source_commit':{'$run':'source_commit'},'nonce':{'$run':'nonce'}},
                'staging_path':{'$path':'staging'},'robot_job':{},'executable_entry':{},
                'additional_operations':[],'executable_transaction_path':{'$path':'actual-result.json'}},
            'collect':{'effect':'READ_ONLY_CURRENT_OPERATION','receipt':{'$result':'actual-result.json'}}}
        self.recipe_path=self.root/'installed-operation.json'
    def tearDown(self):self.temp.cleanup()
    def pin(self):
        raw=json.dumps(self.recipe).encode()
        if self.recipe_path.exists():self.assertEqual(self.recipe_path.read_bytes(),raw)
        else:self.recipe_path.write_bytes(raw);self.recipe_path.chmod(0o400)
        return {'path':str(self.recipe_path),'sha256':hashlib.sha256(raw).hexdigest()}
    def prepare(self):return P.automatic_operation(self.pin(),self.r,str(self.root))
    def test_real_non_main_producer_to_planner_and_final_identity_consumer(self):
        prepared=self.prepare()
        self.assertEqual(prepared['expected'],self.expected)
        self.assertNotEqual(self.expected['source_commit'],prepared['plan']['source_commit'])
        raw=P.held(prepared['config']['path'],1048576,prepared['config']['sha256'])
        data=gate.strict(raw)
        gate.descriptor(data['executable'],self.expected['source_commit'])
        context={'repository':gate.REPO,'source_commit':data['controller'],'workflow_source_commit':'d'*40,
                 'candidate_source_commit':self.expected['source_commit'],'target':gate.target(self.expected),'nonce':'f'*32}
        self.assertEqual(gate.candidate_context(context,self.expected,'f'*32,'d'*40),context)
        self.assertEqual(self.package.read_bytes(),self.archive)
        self.assertEqual(data['queue_job'],'steamos-'+'f'*32)
    def test_collect_reads_only_actual_same_operation_bytes(self):
        prepared=self.prepare();target=Path(prepared['executable_transaction_path'])
        # A real file stands in for external native output; no passed/closure
        # claim is manufactured by the planner. The real Engine validates it.
        target.write_bytes(b'{"status":"failed","native_model":true}');target.chmod(0o400)
        collected=P.automatic_operation(self.pin(),dict(self.r,action='collect'),str(self.root))
        self.assertEqual(P.held(collected['receipt']['path'],1024,collected['receipt']['sha256']),target.read_bytes())
    def test_same_head_new_attempt_has_fresh_identity_and_no_rearm(self):
        first=self.prepare()
        with self.assertRaises(FileExistsError):P.automatic_operation(self.pin(),self.r,str(self.root))
        newer=copy.deepcopy(self.r);newer.update(attempt='2',nonce='a'*32)
        second=P.automatic_operation(self.pin(),newer,str(self.root))
        self.assertNotEqual(first['config']['path'],second['config']['path'])
        self.assertEqual(second['expected'],first['expected'])
    def test_candidate_hash_or_custody_drift_refused(self):
        self.package.chmod(0o600);self.package.write_bytes(b'changed package');self.package.chmod(0o400)
        with self.assertRaises(ValueError):self.prepare()
    def test_symlink_or_executable_document_refused(self):
        self.recipe['documents'][0]['name']='controller.py'
        with self.assertRaisesRegex(ValueError,'JSON operand'):self.prepare()
    def test_template_cannot_relabel_identity_or_result_as_available(self):
        self.recipe['prepare']['identity']={'source_commit':'0'*40}
        with self.assertRaisesRegex(ValueError,'identity'):self.prepare()
    def test_wrong_candidate_or_controller_context_refused(self):
        context={'repository':gate.REPO,'source_commit':'e'*40,'workflow_source_commit':'d'*40,
                 'candidate_source_commit':'0'*40,'target':gate.target(self.expected),'nonce':'f'*32}
        with self.assertRaises(gate.Refusal):gate.candidate_context(context,self.expected,'f'*32,'d'*40)
    def test_actual_download_stream_hash_and_no_credential_redirect(self):
        requests=[]
        class Response(io.BytesIO):
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        class Opener:
            def open(_,req,timeout):
                requests.append(req)
                return Response(self.archive)
        target=io.BytesIO()
        with patch.object(gate.request,'build_opener',return_value=Opener()):
            count=gate.download_candidate(self.expected,target,1024,'synthetic-token')
        self.assertEqual(count,len(self.archive));self.assertEqual(target.getvalue(),self.archive)
        self.assertEqual(requests[0].full_url,'https://api.github.com/repos/'+gate.REPO+'/actions/artifacts/30/zip')
        self.assertNotIn('synthetic-token',requests[0].full_url)
    @unittest.skipUnless(sys.platform=='linux','Linux kernel connection-denial proof')
    def test_production_data_consumer_with_kernel_connect_denied(self):
        # All sockets, including a potential Codex/Control connection, return
        # EPERM in this child. The actual held data producer and reader run.
        self.pin();request=self.root/'request.json';request.write_text(json.dumps(self.r))
        code=r'''
import ctypes,errno,importlib.util,json,os,sys
class Filter(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):_fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
# x86_64 Linux connect=42; this admitted CI job is x64.
filters=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,42),Filter(0x06,0,0,0x00050000|errno.EPERM),Filter(0x06,0,0,0x7fff0000))
libc=ctypes.CDLL(None,use_errno=True)
assert libc.prctl(38,1,0,0,0)==0
assert libc.prctl(22,2,ctypes.byref(Program(4,filters)),0,0)==0
spec=importlib.util.spec_from_file_location('normal_planner',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
from pathlib import Path
r=json.loads(Path(sys.argv[2]).read_bytes());p=Path(sys.argv[3]);import hashlib
v=m.automatic_operation({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()},r,sys.argv[4])
assert json.loads(m.held(v['config']['path'],1048576,v['config']['sha256']))['executable']==r['candidate']['descriptor']
print('normal candidate producer/consumer succeeded with connect denied; native VM unverified')
'''
        result=subprocess.run([sys.executable,'-I','-B','-c',code,P.__file__,str(request),str(self.recipe_path),str(self.root)],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode());self.assertIn(b'connect denied',result.stdout)

class RouteHeartbeat(unittest.TestCase):
    def state(self):
        policy={'mainCommit':'e'*40,'queueSourceSHA256':'c'*64,'controlBrokerSHA256':'b'*64}
        probe={'networkReachable':True,'protectedMain':True,'mainCommit':'d'*40,'runnerOnline':True,
            'runnerBusy':True,'actionsInProgress':4,'controlBrokerSHA256':'b'*64,'sourceOwnerBusy':True,'sourceWritersBusy':False,
            'unknownReservations':[],'unclassifiedRuntimeActors':[],'otherActiveJobs':True,'guestActive':True,'gpuLeaseActive':True,
            'control':{'state':'running','sourceCommit':'e'*40,'queueSourceSHA256':'c'*64,
                'listenerAlive':True,'controllerAlive':True,'workerAlive':True,'ownUnitBound':True,'leaseExpiresUnix':22000}}
        return probe,policy
    def test_busy_real_runner_and_gpu_are_queueing_facts_not_route_vetoes(self):
        probe,policy=self.state();result=H.state_from_current(probe,policy,1000,'f'*32)
        self.assertEqual(result['source_commit'],'e'*40);self.assertEqual(result['expires_at'],1180)
        self.assertNotIn('gpu_admitted',result)
    def test_actual_source_worker_or_expiry_fault_still_refuses(self):
        for key,value in [('listenerAlive',False),('workerAlive',False),('sourceCommit','a'*40),('leaseExpiresUnix',20000)]:
            probe,policy=self.state();probe['control'][key]=value
            with self.assertRaises(RuntimeError):H.state_from_current(probe,policy,1000,'f'*32)
    def test_source_writer_still_refuses_busy_route(self):
        probe,policy=self.state();probe['sourceWritersBusy']=True
        with self.assertRaises(RuntimeError):H.state_from_current(probe,policy,1000,'f'*32)
    def test_actual_probe_busy_actor_classification_to_heartbeat(self):
        own='opemos-testq-'+('a'*12)+'-'+('b'*32)+'.service'
        vm='opemos-testq-'+('a'*12)+'-'+('c'*32)+'.service'
        rows=[{'id':'controller','state':'running','unit':own},{'id':'admitted-vm','state':'running','unit':vm}]
        bindings=[{'job_id':r['id'],'value':json.dumps({'unit':r['unit'],'invocation':str(i)*32})}for i,r in enumerate(rows,1)]
        pool={'admitted':True,'unknownReservationsRetained':[],'knownInvocations':{own:'1'*32,vm:'2'*32}}
        actors=[{'pid':100,'start':123,'uid':1000,'argv':['/installed/queue_job.py'],'cgroup':'0::/opemos.slice/'+vm}]
        probe,policy=self.state()
        probe['unclassifiedRuntimeActors']=N.unclassified_route_actors(actors,own,rows,bindings,pool)
        self.assertTrue(H.state_from_current(probe,policy,1000,'f'*32)['ready'])
        actors[0]['cgroup']='0::/unbound-foreign.service'
        probe['unclassifiedRuntimeActors']=N.unclassified_route_actors(actors,own,rows,bindings,pool)
        with self.assertRaises(RuntimeError):H.state_from_current(probe,policy,1000,'f'*32)
        pool['knownInvocations'][vm]='3'*32
        with self.assertRaises(RuntimeError):N.unclassified_route_actors(actors,own,rows,bindings,pool)
    def test_heartbeat_and_actual_first_hook_clock_predicate_agree(self):
        for expiry in (1300,20000,20001,22000):
            probe,policy=self.state();probe['control']['leaseExpiresUnix']=expiry
            expected=C.job_window_valid(0,expiry,1000)
            if expected:self.assertTrue(H.state_from_current(probe,policy,1000,'f'*32)['ready'])
            else:
                with self.assertRaises(RuntimeError):H.state_from_current(probe,policy,1000,'f'*32)
        # A queued delay never renews the original lease or waives first-hook
        # revalidation. Existing normal idle-only renewal supplies a new owner.
        self.assertFalse(C.job_window_valid(0,22000,4000))
        probe,policy=self.state()
        with self.assertRaises(RuntimeError):H.state_from_current(probe,policy,4000,'f'*32)
    def test_real_route_metadata_uses_runner21_not_repository_job_frontier(self):
        calls=[]
        def github(path,timeout=10):
            calls.append(path)
            if path.endswith('/branches/main'):return {'protected':True,'commit':{'sha':'d'*40}}
            if path.endswith('/actions/runners/21'):
                return {'id':21,'name':'opemos-omen-robot','labels':[{'name':'opemos-omen-robot'}], 'status':'online','busy':True}
            if '/actions/variables/' in path:raise RuntimeError('old heartbeat unavailable')
            raise AssertionError('unrelated repository job inventory must not be requested: '+path)
        with patch.object(N,'gh_json',side_effect=github):
            value=N.current_github({'mainCommit':'e'*40,'queueSourceSHA256':'c'*64},route_only=True)
        self.assertTrue(value['runnerOnline']);self.assertTrue(value['runnerBusy'])
        self.assertEqual(value['mainCommit'],'d'*40);self.assertIsNone(value['actionsInProgress'])
        self.assertFalse(any('/actions/runs?' in p for p in calls))

if __name__=='__main__':unittest.main()

"""Required producer contract cases. Run only in admitted source-test guest/CI.

Synthetic metadata/engine doubles verify gate decisions, never VM or GUI proof.
Actual pipeline qualification is separately required after owning-source review.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
import required_omen as gate

SOURCE='a'*40

def encoded_zip(name,value):
 stream=io.BytesIO()
 with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED)as archive:archive.writestr(name,json.dumps(value))
 return stream.getvalue()

class Metadata:
 def __init__(self,platform='ubuntu'):
  self.value={'schema':1,'repository':gate.REPO,'source_commit':SOURCE,'platform':platform,'workflow':gate.PRODUCER_PATH[platform],'producer_run_id':'10','producer_attempt':'2','event':'push','ref':'refs/heads/main','artifact_id':'30','artifact_name':'package-'+platform,'artifact_archive_sha256':'b'*64,'package_name':'package.zip','package_sha256':'c'*64,'package_bytes':100,'executable_name':'app','executable_sha256':'d'*64,'executable_bytes':80}
  self.raw=encoded_zip('executable-producer.json',self.value)
  self.run={'id':10,'run_attempt':2,'head_sha':SOURCE,'head_branch':'main','path':gate.PRODUCER_PATH[platform],'event':'push','repository':{'full_name':gate.REPO,'id':1},'head_repository':{'id':1},'status':'in_progress','conclusion':None,'run_started_at':'2026-10-20T00:00:00Z'}
  self.jobs=[{'id':20,'run_id':10,'head_sha':SOURCE,'name':gate.NATIVE[platform][0],'status':'completed','conclusion':'success','completed_at':'2026-10-20T00:01:00Z','steps':[{'name':x,'status':'completed','conclusion':'success'}for x in('Bind exact executable and package to this producer artifact','Retain small producer identity for separate SteamOS acceptance')]},{'id':21,'name':'Required OMEN GUI image + SteamOS','status':'in_progress','steps':[]}]
  workflow={'id':10,'head_sha':SOURCE,'repository_id':1,'head_repository_id':1}
  self.artifacts=[{'id':30,'expired':False,'name':self.value['artifact_name'],'digest':'sha256:'+'b'*64,'workflow_run':workflow,'created_at':'2026-10-20T00:00:40Z'},{'id':31,'expired':False,'name':f'executable-producer-{platform}-10-2','digest':'sha256:'+hashlib.sha256(self.raw).hexdigest(),'workflow_run':workflow,'created_at':'2026-10-20T00:00:50Z'}]
  self.calls=[];self.live_attempt=2
 def read(self,path):
  self.calls.append(path)
  if path=='branches/main':return{'protected':True,'commit':{'sha':SOURCE}}
  if path=='actions/runs/10':return dict(copy.deepcopy(self.run),run_attempt=self.live_attempt)
  if path=='actions/runs/10/attempts/2':return copy.deepcopy(self.run)
  if path.startswith('actions/runs/10/attempts/2/jobs?'):return{'total_count':len(self.jobs),'jobs':copy.deepcopy(self.jobs)}
  if path.startswith('actions/runs/10/artifacts?'):return{'total_count':len(self.artifacts),'artifacts':copy.deepcopy(self.artifacts)}
  raise AssertionError(path)
 def download(self,path):
  assert path=='actions/artifacts/31/zip'
  return self.raw
 def verify(self):return gate.producer_ready(SOURCE,self.value['platform'],'10','2',self.read,self.download)

class RequiredProducerTests(unittest.TestCase):
 def test_dispatch_write_token_is_only_in_main_job_and_pr_diagnostics_are_read_only(self):
  root=Path(__file__).parents[1]
  for name in('ubuntu-executable.yml','windows-portable.yml'):
   workflow=(root/'.github/workflows'/name).read_text()
   main,untrusted=workflow.split('\n  omen-required:\n',1)[1].split('\n  omen-required-untrusted:\n',1)
   self.assertIn("github.ref == 'refs/heads/main' && github.ref_protected",main)
   self.assertIn('actions: write',main)
   self.assertIn('ref: ${{ github.sha }}',main)
   self.assertIn('actions: read',untrusted)
   self.assertNotIn('actions: write',untrusted)
   self.assertNotIn('dispatch-and-wait',untrusted)
   self.assertIn(' diagnostics --directory required-omen-results ',untrusted)
   self.assertIn('exit 1',untrusted)
 def test_in_progress_parent_with_passed_package_is_eligible(self):
  m=Metadata();self.assertEqual(m.verify(),m.value)
 def test_windows_independent_of_ubuntu_mac_readiness(self):
  m=Metadata('windows');self.assertEqual(m.verify()['platform'],'windows');self.assertTrue(all('/10/'in p or p=='actions/runs/10'for p in m.calls))
 def test_running_package_refuses(self):
  m=Metadata();m.jobs[0]['status']='in_progress'
  with self.assertRaises(gate.Refusal):m.verify()
 def test_failed_package_refuses(self):
  m=Metadata();m.jobs[0]['conclusion']='failure'
  with self.assertRaises(gate.Refusal):m.verify()
 def test_skipped_binding_step_refuses(self):
  m=Metadata();m.jobs[0]['steps'][0]['conclusion']='skipped'
  with self.assertRaises(gate.Refusal):m.verify()
 def test_fork_producer_refuses(self):
  m=Metadata();m.run['head_repository']['id']=2
  with self.assertRaises(gate.Refusal):m.verify()
 def test_pull_request_refuses(self):
  m=Metadata();m.run['event']='pull_request'
  with self.assertRaises(gate.Refusal):m.verify()
 def test_wrong_source_refuses(self):
  m=Metadata();m.run['head_sha']='e'*40
  with self.assertRaises(gate.Refusal):m.verify()
 def test_previous_attempt_refuses(self):
  m=Metadata();m.live_attempt=3
  with self.assertRaises(gate.Refusal):m.verify()
 def test_duplicate_native_job_refuses(self):
  m=Metadata();m.jobs.append(copy.deepcopy(m.jobs[0]))
  with self.assertRaises(gate.Refusal):m.verify()
 def test_expired_metadata_refuses(self):
  m=Metadata();m.artifacts[1]['expired']=True
  with self.assertRaises(gate.Refusal):m.verify()
 def test_changed_archive_refuses(self):
  m=Metadata();m.raw+=b'x'
  with self.assertRaises(ValueError):m.verify()
 def test_foreign_artifact_repository_refuses(self):
  m=Metadata();m.artifacts[0]['workflow_run']['head_repository_id']=2
  with self.assertRaises(gate.Refusal):m.verify()
 def test_artifact_before_attempt_refuses(self):
  m=Metadata();m.artifacts[1]['created_at']='2026-10-19T23:59:59Z'
  with self.assertRaises(gate.Refusal):m.verify()
 def test_artifact_after_package_job_refuses(self):
  m=Metadata();m.artifacts[1]['created_at']='2026-10-20T00:01:01Z'
  with self.assertRaises(gate.Refusal):m.verify()
 def test_rerun_during_inventory_refuses(self):
  m=Metadata();original=m.read;calls=0
  def read(path):
   nonlocal calls
   if path=='actions/runs/10':
    calls+=1
    if calls==2:m.live_attempt=3
   return original(path)
  with self.assertRaises(gate.Refusal):gate.producer_ready(SOURCE,'ubuntu','10','2',read,m.download)
 def test_native_job_inventory_drift_refuses(self):
  m=Metadata();original=m.read;calls=0
  def read(path):
   nonlocal calls
   if '/jobs?'in path:
    calls+=1
    if calls==2:m.jobs[0]['steps'][0]['conclusion']='failure'
   return original(path)
  with self.assertRaises(gate.Refusal):gate.producer_ready(SOURCE,'ubuntu','10','2',read,m.download)
 def test_own_waiting_gate_progress_does_not_invalidate_closed_package(self):
  m=Metadata();original=m.read;calls=0
  def read(path):
   nonlocal calls
   if '/jobs?'in path:
    calls+=1
    if calls==2:m.jobs[1]['steps']=[{'name':'waiting','status':'in_progress'}]
   return original(path)
  self.assertEqual(gate.producer_ready(SOURCE,'ubuntu','10','2',read,m.download),m.value)
 def test_duplicate_json_refuses(self):
  with self.assertRaises(gate.Refusal):gate.strict(b'{"a":1,"a":2}')
 def test_nonfinite_json_refuses(self):
  with self.assertRaises(gate.Refusal):gate.strict(b'{"a":NaN}')
 def test_public_hash_tampering_refuses(self):
  with tempfile.TemporaryDirectory()as temp:
   prior=os.getcwd();os.chdir(temp)
   try:
    Path('robot-results').mkdir();name='10-2-proof.txt';Path('robot-results',name).write_bytes(b'changed')
    reply={'identity':{'run_id':'10','attempt':'2'},'public_evidence':[{'name':name,'kind':'argv','bytes':7,'sha256':'a'*64}]}
    with self.assertRaises(gate.Refusal):gate.public_reports(reply)
   finally:os.chdir(prior)
 def test_public_foreign_run_name_refuses(self):
  reply={'identity':{'run_id':'10','attempt':'2'},'public_evidence':[{'name':'11-2-proof','kind':'argv','bytes':1,'sha256':'a'*64}]}
  with self.assertRaises(gate.Refusal):gate.public_reports(reply)
 def test_public_wrong_type_size_refuses(self):
  reply={'identity':{'run_id':'10','attempt':'2'},'public_evidence':[{'name':'10-2-proof','kind':'argv','bytes':True,'sha256':'a'*64}]}
  with self.assertRaises(gate.Refusal):gate.public_reports(reply)
 def test_fallback_always_failed_no_fabricated_frame(self):
  with tempfile.TemporaryDirectory()as temp:
   gate.emit_diagnostics(temp,'Unavailable fixture; no actual operation')
   value=json.loads(Path(temp,'diagnostic.json').read_bytes());self.assertTrue(value['diagnostic_only']);self.assertEqual(len(value['vms']),20);self.assertFalse(value['actualGUIExecuted']);self.assertEqual(list(Path(temp).glob('*.png')),[])
   for name in('output.xml','report.html','log.html','xunit.xml','diagnostic.log'):self.assertTrue(Path(temp,name).is_file())
 def test_fallback_preserves_existing_real_output(self):
  with tempfile.TemporaryDirectory()as temp:
   Path(temp,'output.xml').write_bytes(b'original-failed-Robot-output')
   gate.emit_diagnostics(temp,'Missing other reports')
   self.assertEqual(Path(temp,'output.xml').read_bytes(),b'original-failed-Robot-output')
   for name in('report.html','log.html','xunit.xml'):self.assertTrue(Path(temp,name).is_file())
 def test_ordinary_prepared_producer_mismatch_guard_precedes_effect(self):
  # Inspect production statement order, not an alternate transaction method.
  import ast
  tree=ast.parse(Path(gate.__file__).with_name('omen_robot.py').read_bytes());fn=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='transaction');text=ast.get_source_segment(Path(gate.__file__).with_name('omen_robot.py').read_text(),fn)
  self.assertLess(text.index("prepared.get('expected')==expected_producer"),text.index('stage_path.mkdir'))
  self.assertLess(text.index("prepared.get('expected')==expected_producer"),text.index("self.stage['queue_call']"))
 def test_root_failure_retains_first_and_secondary(self):
  m=Metadata();req=dict(version=2,action='execute-produced-platform',subject=gate.target(m.value),repository=gate.REPO,source_commit=SOURCE,run_id='50',attempt='1',nonce='f'*32,consumer_started_epoch=1)
  class Engine:
   context={k:req[k]for k in('repository','source_commit','run_id','attempt')};artifacts={'ubuntu':{'status':'unavailable'}};current=None
   def transaction(self,*args,**kw):raise gate.Refusal('first actual transaction failure')
   def failure_exports(self):return{'status':'failed','closure':'UNKNOWN','exports':[],'secondary_collection_error':{'type':'FixtureCaptureFailure'}}
   def persist(self):raise OSError('secondary persistence')
  value=gate.broker_execute_produced(Engine(),req,m.read,m.download)
  self.assertEqual(value['status'],'failed');self.assertEqual(value['first_error']['reason'],'first actual transaction failure');self.assertEqual(value['closure'],'UNKNOWN');self.assertIn('secondary_collection_error',value['failure_collection']);self.assertEqual(value['secondary_errors'][0]['phase'],'persist')
 def test_root_normal_uses_exact_expected_and_real_result_consumer(self):
  m=Metadata();req=dict(version=2,action='execute-produced-platform',subject=gate.target(m.value),repository=gate.REPO,source_commit=SOURCE,run_id='50',attempt='1',nonce='f'*32,consumer_started_epoch=1);calls=[]
  # Schema fixture ONLY, never native proof. Exercise the REAL verifier rather
  # than replacing it to manufacture a successful caller result.
  acceptance={'status':'passed','executable':m.value,'source_commit':SOURCE,'run_id':'50','attempt':'1',
   'actual_receipt_verified':True,'active':False,'operation_nonce':'e'*32}
  for field in('build_receipt_sha256','heal_receipt_sha256','install_receipt_sha256','image_sha256','image_manifest_sha256','usb_readback_sha256'):
   acceptance[field]='a'*64
  for field in('output_identity','target_generation','target_id','target_disk_identity','baseline_boot_id','installed_root_uuid','installed_efi_uuid','imaging_host_id'):
   acceptance[field]='synthetic-schema-not-native-'+field
  proof={'schema':1,'verified':True,'source_commit':SOURCE,'run_id':'50','attempt':'1','operation_nonce':'e'*32,
         'executable':m.value,'sender_sha256':'b'*64,'actions':[]}
  for i,name in enumerate(('chooser-open','chooser-confirm-exact-input','Build','virtualUSB-select-and-review','virtualUSB-Write-confirmation'),1):
   action={'action':name,'action_id':format(i,'032x')}
   for field in('record_sha256','transition_sha256','sender_lifecycle_sha256','target_observation_sha256'):action[field]='c'*64
   for side,j in(('before',i*2),('after',i*2+1)):
    action[side]={'capture_id':format(j,'032x'),'frame_sha256':'d'*64,'capture_receipt_sha256':'a'*64}
   proof['actions'].append(action)
  proof['proof_sha256']=gate.digest(proof);acceptance['pointer_acceptance']=proof
  class Engine:
   context={k:req[k]for k in('repository','source_commit','run_id','attempt')};artifacts={'ubuntu':{'status':'unavailable'}};current=None
   def transaction(self,kind,subject,expected_producer=None):
    calls.append((kind,subject,expected_producer));return{'status':'passed','expected':m.value,'active':False,'closure_verified':True,'steam_os_transaction':acceptance,'exports':[]}
   def persist(self):calls.append('persist')
   def failure_exports(self):return{'exports':[]}
  value=gate.broker_execute_produced(Engine(),req,m.read,m.download)
  self.assertEqual(value['status'],'passed');self.assertEqual(calls[0],('artifact',{'platform':'ubuntu','artifact_id':'30'},m.value))
  self.assertEqual(value['required_acceptance'],acceptance)
  changed=copy.deepcopy(acceptance);changed['image_sha256']='b'*64
  with self.assertRaises(gate.Refusal):gate.verify_acceptance(changed,m.value,req)

if __name__=='__main__':unittest.main()

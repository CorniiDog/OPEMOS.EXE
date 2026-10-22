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
from unittest.mock import patch
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
 def parent_failed_result(self, temp, stale=False, collision=False):
  m=Metadata();state={}
  failure={'kind':'OPEMOS_BROKER_FAILURE_V1','code':'ACTIONS_TOKEN_REQUIRED','reason':gate.PUBLIC_FAILURES['ACTIONS_TOKEN_REQUIRED'],'error_type':'ValueError','private_recorded':True,'secondary':[]}
  class Response:
   status=204
   def __enter__(self):return self
   def __exit__(self,*args):pass
   def read(self,n):return b''
  class Opener:
   def open(self,req,timeout):
    inputs=json.loads(req.data)['inputs'];nonce=inputs['correlation_nonce']
    state['title']='04 SteamOS required ubuntu 10/2 '+nonce
    context={'repository':gate.REPO,'source_commit':SOURCE,'target':gate.target(m.value),'nonce':nonce}
    if stale:context['nonce']='0'*32
    value={'kind':'OMEN_REQUIRED_PRODUCER_RESULT_V1','status':'failed','diagnostic_only':True,'actualGUIAccepted':False,'context':context,'producer':m.value,'consumer':{'run_id':'50','attempt':'1'},'broker_failure':failure}
    state['raw']=encoded_zip('required-result.json',value)
    return Response()
  def read(path):
   if path.startswith('actions/workflows/omen-robot.yml/runs?'):
    return {'total_count':1,'workflow_runs':[{'id':50,'run_attempt':1,'display_title':state['title'],'head_sha':SOURCE,'head_branch':'main','event':'workflow_dispatch','repository':{'full_name':gate.REPO},'status':'completed'}]}
   if path.startswith('actions/runs/50/attempts/1/jobs?'):
    return {'total_count':2,'jobs':[{'name':n,'status':'completed','conclusion':'failure'}for n in ('required-platform-robot','required-platform-result')]}
   if path.startswith('actions/runs/50/artifacts?'):
    return {'total_count':1,'artifacts':[{'id':60,'name':'omen-required-result-50-1','expired':False,'digest':'sha256:'+hashlib.sha256(state['raw']).hexdigest()}]}
   return m.read(path)
  def download(path):return state['raw'] if path=='actions/artifacts/60/zip'else m.download(path)
  env={'GITHUB_REPOSITORY':gate.REPO,'GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/main','GITHUB_REF_PROTECTED':'true','GITHUB_SHA':SOURCE,'GITHUB_TOKEN':'synthetic-not-a-token','GITHUB_RUN_ID':'10','GITHUB_RUN_ATTEMPT':'2'}
  prior=os.getcwd();os.chdir(temp)
  try:
   if collision:
    Path('required-omen-results/required-result-failed.json').mkdir(parents=True)
    Path('required-omen-results/failed-result-readback-secondary.json').mkdir()
   # Only external API/HTTP adapters supply synthetic provider metadata. The
   # dispatch, producer verifier, failed ZIP/schema/identity consumer and actual
   # create-only filesystem persistence functions are never replaced.
   with patch.dict(os.environ,env),patch.object(gate,'api_reader',return_value=read),patch.object(gate,'metadata_download',side_effect=download),patch.object(gate.request,'build_opener',return_value=Opener()):
    self.assertEqual(gate.main_dispatch('ubuntu'),1)
   result=json.loads(Path('required-omen-results/required-failure.json').read_bytes())
   self.assertFalse(result['oldResultAdopted'])
   self.assertEqual('ACTIONS_TOKEN_REQUIRED'in result['reason'],not stale)
   if collision:self.assertTrue(Path('required-omen-results/required-result-failed.json').is_dir())
  finally:os.chdir(prior)
 def test_parent_normal_failed_artifact_retains_authenticated_cause(self):
  with tempfile.TemporaryDirectory()as temp:self.parent_failed_result(temp)
 def test_parent_stale_failed_artifact_never_adopted(self):
  with tempfile.TemporaryDirectory()as temp:self.parent_failed_result(temp,stale=True)
 def test_parent_two_real_persistence_collisions_do_not_mask_first_cause(self):
  with tempfile.TemporaryDirectory()as temp:self.parent_failed_result(temp,collision=True)
 def test_token_bind_precedes_both_real_operations_without_token_argv(self):
  workflow=(Path(__file__).parents[1]/'.github/workflows/omen-robot.yml').read_text()
  self.assertEqual(workflow.count('job_guard.py --bind-job-token'),2)
  for name,next_name in [('actual-robot-transactions','required-platform-robot'),('required-platform-robot','required-platform-result')]:
   section=workflow.split('\n  '+name+':\n')[1].split('\n  '+next_name+':\n')[0]
   self.assertLess(section.index('persist-credentials: false'),section.index('job_guard.py --bind-job-token'))
   self.assertLess(section.index('job_guard.py --bind-job-token'),section.index(' -m robot '))
   self.assertIn('GITHUB_TOKEN: ${{ github.token }}',section)
   self.assertNotIn('--bind-job-token $',section)
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
   self.assertEqual(value['workflow_identity']['run_id'],os.environ.get('GITHUB_RUN_ID'))
   self.assertEqual(value['workflow_identity']['attempt'],os.environ.get('GITHUB_RUN_ATTEMPT'))
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

class CandidateMetadata(Metadata):
 """Finite API fixtures only: never OS, VM, job or pointer acceptance."""
 def __init__(self):
  super().__init__()
  self.selection={'repository':gate.REPO,'controller_commit':'e'*40,
   'candidate_commit':SOURCE,'pull_request':210,'base_commit':'e'*40,
   'repository_id':1,'head_repository_id':1}
  repo={'id':1,'full_name':gate.REPO,'fork':False}
  self.pr={'number':210,'state':'open','merged_at':None,
   'base':{'ref':'main','sha':'e'*40,'repo':copy.deepcopy(repo)},
   'head':{'ref':'topic','sha':SOURCE,'repo':copy.deepcopy(repo)}}
  self.run.update(head_branch='topic',event='pull_request',
   repository=copy.deepcopy(repo),head_repository=copy.deepcopy(repo),
   pull_requests=[{'number':210,'head':{'sha':SOURCE},'base':{'sha':'e'*40}}])
  self.value.update(event='pull_request',ref='refs/pull/210/merge')
  self.reseal()
 def reseal(self):
  self.raw=encoded_zip('executable-producer.json',self.value)
  self.artifacts[1]['digest']='sha256:'+hashlib.sha256(self.raw).hexdigest()
 def read(self,path):
  if path=='branches/main':return{'protected':True,'commit':{'sha':'e'*40}}
  if path=='pulls/210':return copy.deepcopy(self.pr)
  return super().read(path)
 def verify_candidate(self):
  # This clock substitution exercises metadata decisions only, not OS clocks.
  with patch.object(gate.time,'time',return_value=1792454520):
   return gate.candidate_producer_ready(self.selection,'ubuntu','10','2',self.read,self.download)

class CandidateProducerTests(unittest.TestCase):
 def test_descriptor_requires_explicit_roles_and_refuses_role_swap(self):
  m=CandidateMetadata()
  with self.assertRaises(ValueError):gate.descriptor(m.value,SOURCE)
  self.assertEqual(gate.descriptor(m.value,SOURCE,m.selection),m.value)
  swapped=dict(m.selection,controller_commit=SOURCE,base_commit=SOURCE,candidate_commit='e'*40)
  with self.assertRaises(ValueError):gate.descriptor(m.value,SOURCE,swapped)
  with self.assertRaises(ValueError):gate.descriptor(m.value,'e'*40,m.selection)
 def test_candidate_target_carries_roles_without_changing_original_descriptor(self):
  m=CandidateMetadata();original=copy.deepcopy(m.value)
  value=gate.target(m.value,m.selection)
  self.assertEqual(value['source_roles'],m.selection)
  self.assertEqual(value['descriptor_sha256'],gate.digest(original))
  self.assertEqual(m.value,original)
 def test_candidate_workflow_never_checks_out_guest_b_on_privileged_runner(self):
  workflow=(Path(__file__).parents[1]/'.github/workflows/omen-robot.yml').read_text()
  section=workflow.split('\n  required-platform-robot:\n')[1].split('\n  required-platform-result:\n')[0]
  self.assertIn('ref: ${{ needs.trusted-runner-route.outputs.source }}',section)
  self.assertNotIn('ref: ${{ inputs.candidate_sha }}',workflow)
  self.assertNotIn('pull_request_target:',workflow)
  self.assertNotIn('candidate_sha }}',section)
  self.assertIn('job_guard.py --bind-job-token',section)
  self.assertIn('actions: read',workflow)
 def test_passed_native_job_does_not_erase_failed_parent_diagnostic(self):
  m=CandidateMetadata();m.run.update(status='completed',conclusion='failure')
  value=m.verify_candidate()
  self.assertEqual(value['parent_outcome'],{'status':'completed','conclusion':'failure'})
  self.assertNotIn('runtime_admitted',value)
  self.assertNotIn('checks_passed',value)
 def test_original_b_provenance_and_separate_a_retained(self):
  m=CandidateMetadata();value=m.verify_candidate()
  self.assertEqual(value['source_roles'],m.selection)
  self.assertEqual(value['producer'],m.value)
  self.assertEqual(value['producer']['event'],'pull_request')
  self.assertNotEqual(value['producer']['source_commit'],value['source_roles']['controller_commit'])
  self.assertEqual(value['native_job_id'],'20')
  # The original production route remains strict, not a PR fallback.
  with self.assertRaises(gate.Refusal):m.verify()
 def test_foreign_fork_stale_rebased_or_closed_pr_refused(self):
  for mutate in (
   lambda m:m.pr['head']['repo'].update(fork=True),
   lambda m:m.pr['head']['repo'].update(id=2),
   lambda m:m.pr['head'].update(sha='f'*40),
   lambda m:m.pr['base'].update(sha='f'*40),
   lambda m:m.pr.update(state='closed'),
   lambda m:m.selection.update(controller_commit='f'*40),
   lambda m:m.selection.update(head_repository_id=2),
   lambda m:m.selection.update(pull_request=True),
   lambda m:m.selection.update(command=['arbitrary'])):
   with self.subTest(mutate=mutate):
    m=CandidateMetadata();mutate(m)
    with self.assertRaises(gate.Refusal):m.verify_candidate()
 def test_wrong_native_attempt_step_artifact_or_pr_association_refused(self):
  for mutate in (
   lambda m:setattr(m,'live_attempt',3),
   lambda m:m.jobs[0].update(status='in_progress'),
   lambda m:m.jobs[0]['steps'][0].update(conclusion='skipped'),
   lambda m:m.run['pull_requests'][0].update(number=211),
   lambda m:m.artifacts[0].update(expired=True),
   lambda m:m.artifacts[0].update(digest='sha256:'+'0'*64),
   lambda m:m.artifacts[0]['workflow_run'].update(head_repository_id=2),
   lambda m:m.artifacts[0].update(created_at='2026-10-19T00:00:40Z')):
   with self.subTest(mutate=mutate):
    m=CandidateMetadata();mutate(m)
    with self.assertRaises(gate.Refusal):m.verify_candidate()
 def test_descriptor_cannot_normalize_b_to_main_or_smuggle_paths(self):
  for change in ({'event':'push','ref':'refs/heads/main'},
                 {'source_commit':'e'*40},{'package_name':'../app'},
                 {'package_bytes':True},{'executable_sha256':'bad'},
                 {'ref':'refs/pull/211/merge'},{'host_command':['bad']}):
   with self.subTest(change=change):
    m=CandidateMetadata();m.value.update(change);m.reseal()
    with self.assertRaises(gate.Refusal):m.verify_candidate()
 def test_pr_changed_after_descriptor_download_is_not_adopted(self):
  m=CandidateMetadata();download=m.download
  def changed(path):
   result=download(path);m.pr['head']['sha']='f'*40;return result
  with patch.object(gate.time,'time',return_value=1792454520):
   with self.assertRaises(gate.Refusal):
    gate.candidate_producer_ready(m.selection,'ubuntu','10','2',m.read,changed)

if __name__=='__main__':unittest.main()

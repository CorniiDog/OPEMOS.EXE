"""Exact Ubuntu/Windows producer -> trusted 04 -> existing Root Robot gate.

Metadata only on hosted runners. The existing Root broker is the sole runtime
admission/queue owner. A missing route always fails with diagnostic artifacts.
"""
import argparse
import hashlib
import html
import io
import json
import os
from pathlib import Path
import stat
from datetime import datetime
import re
import secrets
import sys
import time
from urllib import request,error,parse
import xml.etree.ElementTree as ET
import zipfile
from check_full_stack_acceptance import api_reader,NoRedirect,Refusal
from omen_ci_executables import descriptor,canonical,digest,archive_json,pointer_proof_valid,source_roles
from omen_robot_gate import controller_selection

REPO='CorniiDog/OPEMOS.EXE'
ROUTE='.github/workflows/omen-robot.yml'
NATIVE={'ubuntu':('appimage-package','02 Ubuntu AppImage'),'windows':('build','01 Windows EXE'),'macos':('native-app','03 macOS Executable')}
PRODUCER_PATH={'ubuntu':'.github/workflows/ubuntu-executable.yml','windows':'.github/workflows/windows-portable.yml','macos':'.github/workflows/macos-arm64.yml'}
CAP=2*1024**2
def require(value,reason):
 if not value:raise Refusal(reason)
def reviewed_controller(read,env=None):
 try:return controller_selection(read,env)
 except ValueError as error:raise Refusal('Controller qualification: '+str(error))from None
def strict(raw):
 def unique(rows):
  result={}
  for k,v in rows:require(k not in result,'duplicate metadata field');result[k]=v
  return result
 require(len(raw)<=CAP,'finite metadata bound')
 return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False,'nonfinite metadata'))
def save(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 raw=canonical(value)+b'\n';require(len(raw)<=CAP,'finite result')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
def token_headers(token=None):return{'Accept':'application/vnd.github+json','Authorization':'Bearer '+(os.environ['GITHUB_TOKEN']if token is None else token),'X-GitHub-Api-Version':'2022-11-28'}
class NoArtifactRedirect(request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):return None

def metadata_download(path,token=None):
 """Only small GitHub metadata ZIP, never the executable/package itself."""
 require(re.fullmatch(r'actions/artifacts/[1-9][0-9]*/zip',path),'exact artifact endpoint')
 opener=request.build_opener(NoArtifactRedirect)
 try:
  with opener.open(request.Request('https://api.github.com/repos/'+REPO+'/'+path,headers=token_headers(token)),timeout=20)as response:
   raw=response.read(262145);require(len(raw)<=262144,'small metadata archive');return raw
 except error.HTTPError as response:
  try:
   require(response.code==302,'artifact API refusal HTTP '+str(response.code));location=response.headers.get('Location','')
  finally:response.close()
 # No Authorization header crosses this signed download redirect.
 url=parse.urlsplit(location)
 require(url.scheme=='https'and not url.username and not url.password and url.port in(None,443)and
         (url.hostname or '').endswith(('.blob.core.windows.net','.actions.githubusercontent.com','.githubusercontent.com')),'GitHub signed artifact host required')
 try:
  with opener.open(request.Request(location),timeout=20)as response:
   raw=response.read(262145);require(len(raw)<=262144,'small metadata archive');return raw
 except error.HTTPError as refused:
  try:raise Refusal('signed metadata archive refused HTTP '+str(refused.code))from None
  finally:refused.close()
def root_api_reader(token):
 """Same existing GitHub API trust, finite original 1MiB Root metadata bound."""
 opener=request.build_opener(NoRedirect)
 def read(path):
  require(path in('','branches/main')or re.fullmatch(r'contents/\.github/workflows/omen-robot.yml\?ref=[0-9a-f]{40}',path)or re.fullmatch(r'commits/[0-9a-f]{40}',path)or re.fullmatch(r'git/ref/heads/[A-Za-z0-9_][A-Za-z0-9_./-]{0,239}',path)or re.fullmatch(r'pulls/[1-9][0-9]{0,9}',path)or re.fullmatch(r'actions/runs/[1-9][0-9]{0,19}(?:/attempts/[1-9][0-9]{0,19}(?:/jobs)?|/artifacts)?(?:\?per_page=100)?',path),'fixed Root producer metadata endpoint')
  try:
   with opener.open(request.Request('https://api.github.com/repos/'+REPO+'/'+path,headers=token_headers(token)),timeout=15)as response:
    raw=response.read(1048577);require(len(raw)<=1048576,'original Root API metadata bound');return strict(raw)
  except error.HTTPError as refused:
   try:raise Refusal('Root producer API refused HTTP '+str(refused.code))from None
   finally:refused.close()
 return read
def items(read,path,key):
 value=read(path+('&'if'?'in path else'?')+'per_page=100')
 require(type(value['total_count'])is int and value['total_count']==len(value[key])<=100,'complete finite '+key+' inventory')
 return value[key]

def candidate_identity(selection, read):
 """Revalidate the two source roles using official metadata, not PR code.

 This is deliberately not a runtime admission or a replacement for
 producer_ready. The existing Main-only route stays closed to candidates until
 the complete broker/planner/guest/finalizer joins this exact contract. No
 caller-supplied ref, command, path, token or script belongs in selection.
 """
 if type(selection)is dict and selection.get('source_kind')=='branch':
  source_roles(selection)
  main=read('branches/main');repo=read('');ref=read('git/ref/'+selection['source_ref'][5:])
  require(main['protected']is True and main['commit']['sha']==selection['controller_commit']==selection['base_commit']and
          repo['id']==selection['repository_id']==selection['head_repository_id']and repo['full_name']==REPO and
          repo['fork']is False and ref['ref']==selection['source_ref']and ref['object']['type']=='commit'and
          ref['object']['sha']==selection['candidate_commit'],'live unchanged same-repository branch and controller required')
  return selection.copy()
 require(type(selection)is dict and set(selection)=={
  'repository','controller_commit','candidate_commit','pull_request','base_commit',
  'repository_id','head_repository_id'},'finite exact controller A / candidate B selection')
 require(selection['repository']==REPO,'canonical candidate repository')
 for field in('controller_commit','candidate_commit','base_commit'):
  require(type(selection[field])is str and re.fullmatch('[0-9a-f]{40}',selection[field]),'exact '+field)
 require(type(selection['pull_request'])is int and 0<selection['pull_request']<2**31,
         'exact pull request number')
 require(all(type(selection[k])is int and selection[k]>0 for k in
         ('repository_id','head_repository_id'))and
         selection['repository_id']==selection['head_repository_id'],'same repository candidate only')
 # A changing Main invalidates both the controller and the selected base. Do
 # not silently rebase, replace B by A, or reuse an old counterpart approval.
 branch=read('branches/main')
 require(branch['protected']is True and branch['commit']['sha']==selection['controller_commit']==selection['base_commit'],
         'current protected controller and exact candidate base required')
 pr=read('pulls/'+str(selection['pull_request']))
 require(pr['number']==selection['pull_request']and pr['state']=='open'and
         pr['merged_at']is None and pr['base']['ref']=='main'and
         pr['base']['sha']==selection['base_commit']and
         pr['head']['sha']==selection['candidate_commit'],
         'open exact current PR head/base required')
 for side in('base','head'):
  repo=pr[side]['repo']
  require(repo is not None and repo['id']==selection['repository_id']and
          repo['full_name']==REPO and repo['fork']is False,'foreign/fork candidate refused')
 require(pr['head']['ref']!='main'and
         selection['candidate_commit']!=selection['controller_commit'],
         'candidate B must not masquerade as controller A')
 return selection.copy()

def candidate_producer_ready(selection,platform,run_id,attempt,read,download):
 """Authenticate B's completed native job without ever executing its bytes.

 Metadata-only half of Core109. Returned roles must survive the subsequent
 trusted A broker, guest B and final receipt unchanged. This function grants no
 host execution and does not make the old one-source dispatch PR-capable.
 """
 started=time.time();before=candidate_identity(selection,read)
 require(platform in NATIVE and all(type(x)is str and re.fullmatch('[1-9][0-9]{0,19}',x)
         for x in(run_id,attempt)),'exact candidate platform/run/attempt')
 path=f'actions/runs/{run_id}/attempts/{attempt}'
 run=read(path);latest=read(f'actions/runs/{run_id}')
 require(run['id']==int(run_id)and run['run_attempt']==int(attempt)and
         latest['run_attempt']==int(attempt)and run['head_sha']==latest['head_sha']==before['candidate_commit']and
         run['path']==PRODUCER_PATH[platform]and
         (run['event']in('push','workflow_dispatch')if before.get('source_kind')=='branch'else run['event']=='pull_request')and
         run['repository']['id']==run['head_repository']['id']==before['repository_id']and
         run['repository']['full_name']==run['head_repository']['full_name']==REPO,
         'exact same-repository PR native producer required')
 # The package JOB, not the parent workflow, produces the executable. Current
 # PR workflows deliberately fail their separate operational diagnostic. Keep
 # that failure visible; do not mislabel it success or discard the passed native
 # package. Required-check approval is a separate unchanged runtime/merge gate.
 require((run['status']=='in_progress'and run['conclusion']is None)or
         (run['status']=='completed'and run['conclusion']in('success','failure')),
         'candidate producer cancelled/timed out/unavailable')
 if before.get('source_kind')=='branch':
  require(run['head_branch']==before['source_ref'][11:],'producer branch differs from exact selected ref')
 else:
  prs=run['pull_requests']
  require(type(prs)is list and len(prs)==1 and prs[0]['number']==before['pull_request']and
          prs[0]['head']['sha']==before['candidate_commit']and
          prs[0]['base']['sha']==before['base_commit'], 'producer PR association differs')
 jobs=items(read,path+'/jobs','jobs')
 native=[j for j in jobs if j['name']==NATIVE[platform][0]]
 require(len(native)==1,'exact candidate native job')
 job=native[0]
 require(job['run_id']==int(run_id)and job['head_sha']==before['candidate_commit']and
         job['status']=='completed'and job['conclusion']=='success','candidate native JOB must pass')
 for name in('Bind exact executable and package to this producer artifact',
             'Retain small producer identity for separate SteamOS acceptance'):
  steps=[s for s in job['steps']if s['name']==name]
  require(len(steps)==1 and steps[0]['status']=='completed'and steps[0]['conclusion']=='success',
          'candidate native binding step failed/missing')
 artifacts=items(read,f'actions/runs/{run_id}/artifacts','artifacts')
 att=[a for a in artifacts if a['name']==f'executable-producer-{platform}-{run_id}-{attempt}'and a['expired']is False]
 require(len(att)==1,'candidate small descriptor missing/expired')
 value=archive_json(download(f"actions/artifacts/{att[0]['id']}/zip"),att[0],'executable-producer.json')
 # Validate the original PR descriptor as PR data. Never call the Main-only
 # validator with rewritten event/ref fields, even for a shape check.
 try:descriptor(value,before['candidate_commit'],before)
 except (ValueError,KeyError,TypeError) as error:raise Refusal('candidate descriptor must retain exact original PR provenance/content')from error
 if before.get('source_kind')=='branch':
  require(value.get('workflow_commit')==before['candidate_commit'],'exact branch workflow definition SHA required')
 elif 'workflow_commit'in value:
  require(read('pulls/'+str(before['pull_request']))['merge_commit_sha']==value['workflow_commit'],
          'original PR workflow merge SHA moved or differs; never rewrite it to source head B')
 require(value['platform']==platform and value['producer_run_id']==run_id and value['producer_attempt']==attempt,
         'candidate descriptor producer identity differs')
 selected=[a for a in artifacts if str(a['id'])==value['artifact_id']]
 require(len(selected)==1,'candidate package artifact absent/ambiguous')
 package=selected[0]
 for artifact in(package,att[0]):
  workflow=artifact['workflow_run']
  require(artifact['expired']is False and workflow['id']==int(run_id)and
          workflow['head_sha']==before['candidate_commit']and
          workflow['repository_id']==workflow['head_repository_id']==before['repository_id'],
          'candidate artifact producer/source identity differs')
  created=datetime.fromisoformat(artifact['created_at'].replace('Z','+00:00'))
  require(0<=started-created.timestamp()<=10800,'candidate artifact outside current three-hour retention window')
  require(datetime.fromisoformat(run['run_started_at'].replace('Z','+00:00'))<=created<=
          datetime.fromisoformat(job['completed_at'].replace('Z','+00:00')),
          'candidate artifact outside actual native job')
 require(package['name']==value['artifact_name']and
         package['digest']=='sha256:'+value['artifact_archive_sha256'],
         'candidate package archive identity differs')
 finished=time.time()
 require(finished>=started and all(0<=finished-datetime.fromisoformat(a['created_at'].replace('Z','+00:00')).timestamp()<=10800
         for a in(package,att[0])),'candidate clock regressed or artifact expired during verification')
 require(read(path)==run and read(f'actions/runs/{run_id}')==latest and
         items(read,path+'/jobs','jobs')==jobs and
         items(read,f'actions/runs/{run_id}/artifacts','artifacts')==artifacts and
         candidate_identity(before,read)==before,'candidate producer/current PR raced; no retry/adoption')
 return {'kind':'OPEMOS_EXACT_CONTROLLER_A_CANDIDATE_B_V1','source_roles':before,
         'producer':value,'native_job_id':str(job['id']),
         'parent_outcome':{'status':run['status'],'conclusion':run['conclusion']},
         'descriptor_artifact_id':str(att[0]['id']),
         'descriptor_archive_sha256':att[0]['digest'].removeprefix('sha256:')}
def producer_ready(source,platform,run_id,attempt,read,download):
 require(platform in NATIVE and re.fullmatch('[0-9a-f]{40}',source or '')and all(re.fullmatch('[1-9][0-9]{0,19}',x or '')for x in(run_id,attempt)),'exact platform/source/producer identity')
 path=f'actions/runs/{run_id}/attempts/{attempt}';run=read(path)
 current=read(f'actions/runs/{run_id}');require(str(current['run_attempt'])==attempt and current['head_sha']==source,'latest producer attempt required')
 require(str(run['id'])==run_id and str(run['run_attempt'])==attempt and run['head_sha']==source and run['head_branch']=='main'and run['path']==PRODUCER_PATH[platform]and run['event']in('push','workflow_dispatch')and run['repository']['full_name']==REPO and run['head_repository']['id']==run['repository']['id'],'protected canonical producer identity')
 require(run['status']=='in_progress'or run['status']=='completed'and run['conclusion']=='success','producer not current/in-progress or successful')
 jobs=items(read,path+'/jobs','jobs');matches=[j for j in jobs if j['name']==NATIVE[platform][0]]
 require(len(matches)==1,'exact native package job')
 job=matches[0];require(job['run_id']==int(run_id)and job['head_sha']==source and job['status']=='completed'and job['conclusion']=='success','native package JOB must actually pass before GUI dispatch')
 for name in('Bind exact executable and package to this producer artifact','Retain small producer identity for separate SteamOS acceptance'):
  steps=[s for s in job['steps']if s['name']==name];require(len(steps)==1 and steps[0]['status']=='completed'and steps[0]['conclusion']=='success','producer binding step missing/failed')
 artifacts=items(read,f'actions/runs/{run_id}/artifacts','artifacts')
 att=[a for a in artifacts if a['name']==f'executable-producer-{platform}-{run_id}-{attempt}'and a['expired']is False]
 require(len(att)==1,'exact producer metadata artifact unavailable')
 value=archive_json(download(f"actions/artifacts/{att[0]['id']}/zip"),att[0],'executable-producer.json');descriptor(value,source)
 if 'workflow_commit'in value:require(value['workflow_commit']==source,'Main workflow definition/source mismatch')
 require(value['platform']==platform and value['producer_run_id']==run_id and value['producer_attempt']==attempt,'downloaded producer descriptor identity')
 selected=[a for a in artifacts if str(a['id'])==value['artifact_id']];require(len(selected)==1,'exact package artifact')
 actual=selected[0];require(actual['expired']is False and actual['name']==value['artifact_name']and actual['digest']=='sha256:'+value['artifact_archive_sha256']and actual['workflow_run']['id']==int(run_id)and actual['workflow_run']['head_sha']==source and actual['workflow_run']['repository_id']==run['repository']['id']and actual['workflow_run']['head_repository_id']==run['repository']['id'],'artifact/source/archive identity')
 start=datetime.fromisoformat(run['run_started_at'].replace('Z','+00:00'));native_end=datetime.fromisoformat(job['completed_at'].replace('Z','+00:00'))
 for item in(actual,att[0]):require(start<=datetime.fromisoformat(item['created_at'].replace('Z','+00:00'))<=native_end,'artifact outside actual native package attempt')
 # No inference from a prior successful attempt or stale artifact listing.
 run_after=read(path);current_after=read(f'actions/runs/{run_id}');require(str(current_after['run_attempt'])==attempt and current_after['head_sha']==source,'producer rerun invalidated attempt');jobs_after=items(read,path+'/jobs','jobs');artifacts_after=items(read,f'actions/runs/{run_id}/artifacts','artifacts')
 identity_keys=('id','run_attempt','head_sha','head_branch','path','event','status','conclusion')
 require(all(run_after[k]==run[k]for k in identity_keys)and {j['id']for j in jobs_after}=={j['id']for j in jobs}and [j for j in jobs_after if j['name']==NATIVE[platform][0]]==[job]and sorted(artifacts_after,key=lambda x:x['id'])==sorted(artifacts,key=lambda x:x['id']),'producer package identity/inventory raced')
 return value
def target(value,roles=None):
 selected={k:value[k]for k in('platform','producer_run_id','producer_attempt','artifact_id')}|{'descriptor_sha256':digest(value)}
 if roles is not None:selected['source_roles']=source_roles(roles,candidate=value['source_commit'])
 return selected
def verify_acceptance(value,expected,consumer,roles=None):
 require(type(value)is dict and value['status']=='passed'and value['executable']==expected and value['source_commit']==expected['source_commit']and value['run_id']==consumer['run_id']and value['attempt']==consumer['attempt']and value['actual_receipt_verified']is True and value['active']is False,'exact current actual Root artifact transaction')
 if roles is not None:
  source_roles(roles,controller=consumer['source_commit'],candidate=expected['source_commit'])
  require(value.get('controller_source_commit')==roles['controller_commit']and value.get('source_roles')==roles,'final A/B source roles differ')
 else:require('source_roles'not in value and 'controller_source_commit'not in value,'unexpected candidate role in Main-only acceptance')
 require(pointer_proof_valid(value['pointer_acceptance'],expected,value,expected['source_commit'],consumer['run_id'],consumer['attempt'],roles),'all five actual chooser/Build/USB pointer transitions required')
 for field in('build_receipt_sha256','heal_receipt_sha256','install_receipt_sha256','image_sha256','image_manifest_sha256','usb_readback_sha256'):
  require(re.fullmatch('[0-9a-f]{64}',value.get(field,'')or''),'missing exact '+field)
 require(value['image_sha256']==value['usb_readback_sha256'],'full USB readback differs from actual GUI output')
 for field in('output_identity','target_generation','target_id','target_disk_identity','baseline_boot_id','installed_root_uuid','installed_efi_uuid','imaging_host_id'):
  require(bool(value.get(field)),'actual SteamOS/image generation field missing: '+field)
 return value

def broker_execute_produced(engine,req,read,download):
 """Root route only after unchanged peer, prior-job, Main, one-use checks.

 Root supplies its authenticated API/download adapters. Client supplies only
 finite selection; never argv/path/profile/admission or a fabricated receipt.
 Existing planner still must return genuine current normal operands. Missing
 prepared operands is a FAILED visible outcome, never a successful shortcut.
 """
 require(set(req)=={'version','action','subject','repository','source_commit','run_id','attempt','nonce','consumer_started_epoch'},'exact protocol2 fields')
 require(req['version']==2 and req['action']=='execute-produced-platform'and req['repository']==REPO,'exact existing broker route/action')
 selected=req['subject'];keys={'platform','producer_run_id','producer_attempt','artifact_id','descriptor_sha256'}
 require(type(selected)is dict and set(selected)in(keys,keys|{'source_roles'}),'finite producer selection')
 roles=selected.get('source_roles')
 if roles is not None:source_roles(roles,controller=req['source_commit'])
 require(all(engine.context[k]==req[k]for k in('repository','source_commit','run_id','attempt')),'Root Engine current job/source identity')
 platform=selected['platform'];require(platform in NATIVE,'exact supported producer')
 engine.current=None;phase='current protected Main metadata'
 try:
  branch=read('branches/main');require(branch['protected']is True and branch['commit']['sha']==req['source_commit'],'actual current protected Main before normal operation')
  phase='exact current producer package/job/artifact'
  def current_producer():
   if roles is None:return producer_ready(req['source_commit'],platform,selected['producer_run_id'],selected['producer_attempt'],read,download)
   return candidate_producer_ready(roles,platform,selected['producer_run_id'],selected['producer_attempt'],read,download)['producer']
  expected=current_producer();require(target(expected,roles)==selected,'producer target changed')
  phase='normal admitted prepare/stage/queue transaction'
  options={'expected_producer':expected}
  if roles is not None:options['source_roles']=roles
  result=engine.transaction('artifact',{'platform':platform,'artifact_id':expected['artifact_id']},**options)
  require(result['expected']==expected and result['status']=='passed'and result['active']is False and result['closure_verified']is True,'normal canonical transaction not closed')
  phase='actual image/USB/SteamOS and pointer proof'
  verified=verify_acceptance(result['steam_os_transaction'],expected,req,roles)
  phase='post-transaction producer and Main recheck'
  require(current_producer()==expected,'producer changed during runtime')
  branch_after=read('branches/main');require(branch_after==branch,'current Main changed during operation')
  engine.artifacts[platform]={'status':'passed','artifacts':{expected['artifact_id']:result}}
  value={'status':'passed','required_acceptance':verified,'exports':result['exports']}
 except Exception as first:
  try:failure=engine.failure_exports() # existing read-only same-operation capture
  except Exception as secondary:failure={'closure':'UNKNOWN','exports':[],'secondary_collection_error':{'type':type(secondary).__name__}}
  value={'status':'failed','first_error':{'phase':phase,'type':type(first).__name__,'reason':str(first)[:1000]if isinstance(first,Refusal)else'normal operation failed; original protected Root evidence retained'},'closure':failure.get('closure','UNKNOWN'),'exports':failure.get('exports',[]),'failure_collection':failure}
  # Match the existing Engine.platform private first-cause retention. Never
  # publish arbitrary exception text/private paths via the public summary.
  engine.artifacts[platform]={'status':'failed','reason':str(first),'error_type':type(first).__name__,
      'phase':phase,'closure':value['closure'],'failure_exports':failure}
 try:engine.persist()
 except Exception as secondary:
  value.setdefault('secondary_errors',[]).append({'phase':'persist','type':type(secondary).__name__})
  value['status']='failed';value.pop('required_acceptance',None)
 return value

def required_broker_reply(req,result,summary,published):
 """Fixed Root router joins actual summary and _publish output, not caller data.

 The owning Root source must call this after its original auth+nonce fence and
 actual _publish(result.exports). No private path or requested proof is public.
 """
 require(type(summary)is dict and all(k in summary for k in('all20_passed','all_platforms_passed','vms','platforms','acceptance')),'actual existing Engine summary required')
 require(type(published)is list and len(published)<=64,'bounded actual public publisher result')
 total=0
 for row in published:
  require(set(row)=={'name','sha256','kind','bytes'}and row['name']==Path(row['name']).name and row['name'].startswith(req['run_id']+'-'+req['attempt']+'-')and re.fullmatch('[0-9a-f]{64}',row['sha256']or'')and type(row['bytes'])is int and 0<=row['bytes']<=16*1024**2,'exact actual publisher descriptor')
  total+=row['bytes'];require(total<=256*1024**2,'existing public operation bound')
 reply={k:summary[k]for k in('all20_passed','all_platforms_passed','vms','platforms')}
 reply.update(identity={k:req[k]for k in('repository','source_commit','run_id','attempt','nonce')},action=req['action'],subject=req['subject'],status=result['status'],public_evidence=published,acceptance=summary['acceptance'])
 if result['status']=='passed':reply['required_acceptance']=result['required_acceptance']
 else:
  require(result['status']=='failed','no skipped/unavailable success');reply.update(first_error=result.get('first_error'),secondary_errors=result.get('secondary_errors',[]),closure=result.get('closure','UNKNOWN'))
 require(len(canonical(reply))+1<=1048576,'unchanged broker reply bound')
 return reply

def emit_diagnostics(directory,reason,context=None):
 directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
 inventory=json.loads((Path(__file__).parents[1]/'ci/required-vms.json').read_bytes())['required_vms']
 rows=[{'id':r['id'],'name':r['name'],'status':'unavailable','reason':reason}for r in inventory]
 require(len(rows)==20 and len({r['id']for r in rows})==20,'all20 diagnostic inventory')
 workflow_identity={k:os.environ.get(v)for k,v in {'repository':'GITHUB_REPOSITORY','run_id':'GITHUB_RUN_ID','attempt':'GITHUB_RUN_ATTEMPT','github_sha':'GITHUB_SHA','ref':'GITHUB_REF'}.items()}
 workflow_identity['candidate_source_commit']=os.environ.get('OPEMOS_SOURCE_SHA',os.environ.get('OPEMOS_EXE_COMMIT'))
 value={'kind':'OMEN_REQUIRED_FAILURE_DIAGNOSTIC_V1','status':'failed','diagnostic_only':True,'actualGUIExecuted':False,'reason':reason,'context':context,'workflow_identity':workflow_identity,'vms':rows,'SteamOS':'unavailable; requires actual installed target/NVIDIA/render/recovery receipts','missingScreenshotIsNotAFrame':True}
 # Create-only checkpoint and report names; never overwrite actual RF output.
 for name,data in [('diagnostic.json',value),('screenshot-unavailable.json',{'status':'unavailable','reason':reason,'fabricatedPNG':False})]:
  if not(directory/name).exists():save(directory/name,data)
 if not(directory/'output.xml').exists():
  robot=ET.Element('robot',{'generator':'OPEMOS unavailable diagnostic ONLY; not guest Robot execution','schemaversion':'5'});suite=ET.SubElement(robot,'suite',{'name':'Required unavailable OMEN cases','id':'s1'})
  testsuite=ET.Element('testsuite',{'name':'Required OMEN unavailable','tests':str(len(rows)),'failures':str(len(rows)),'skipped':'0'})
  for i,row in enumerate(rows,1):
   case=ET.SubElement(suite,'test',{'name':row['name'],'id':'s1-t'+str(i)});ET.SubElement(case,'status',{'status':'FAIL'}).text=reason
   junit=ET.SubElement(testsuite,'testcase',{'name':row['name']});ET.SubElement(junit,'failure',{'type':'Unavailable'}).text=reason
  (directory/'output.xml').write_bytes(ET.tostring(robot,encoding='utf-8',xml_declaration=True))
  page='<html><head><meta charset="utf-8"></head><body><h1>OMEN unavailable: FAILED</h1><p>Diagnostic only. No guest/GUI/SteamOS/NVIDIA pass.</p><pre>'+html.escape(reason)+'</pre><ul>'+''.join('<li>'+html.escape(r['name'])+': FAILED / unavailable</li>'for r in rows)+'</ul></body></html>'
  for name in('report.html','log.html'):
   if not(directory/name).exists():(directory/name).write_text(page)
 if not(directory/'xunit.xml').exists():
  failed=ET.Element('testsuite',{'name':'Missing actual OMEN report: diagnostic only','tests':'1','failures':'1','skipped':'0'});case=ET.SubElement(failed,'testcase',{'name':'Required actual evidence unavailable'});ET.SubElement(case,'failure',{'type':'Unavailable'}).text=reason;(directory/'xunit.xml').write_bytes(ET.tostring(failed,encoding='utf-8',xml_declaration=True))
 for name in('report.html','log.html'):
  if not(directory/name).exists():(directory/name).write_text('<html><body><h1>FAILED diagnostic only; missing actual report</h1><pre>'+html.escape(reason)+'</pre></body></html>')
 if not(directory/'diagnostic.log').exists():(directory/'diagnostic.log').write_text(reason+'\n')
 annotation=reason.replace('%','%25').replace('\r','%0D').replace('\n','%0A')[:1500];print('::error title=Required actual OMEN GUI/SteamOS gate::'+annotation)
 if os.environ.get('GITHUB_STEP_SUMMARY'):
  with open(os.environ['GITHUB_STEP_SUMMARY'],'a')as out:out.write('\nRequired actual OMEN GUI/SteamOS gate: **FAILED**\n\n'+reason.replace('|','/')+'\n\n| Required VM | Outcome |\n|---|---|\n'+''.join('| '+r['name']+' | failed / unavailable |\n'for r in rows))

def consume_completed_result(source,expected,context,selected,read,download,directory=Path('required-omen-results')):
 """Independent read-only consumer of an ALREADY completed controller result.

 Retains the original failed-artifact/first-cause/create-only reader, without
 dispatching or waiting inside a producer. API/download are external metadata
 adapters; all producer/result/schema/persistence methods below are real.
 """
 platform=expected['platform'];directory=Path(directory)
 try:
  roles=context['target'].get('source_roles')
  checkpoint=read('branches/main');require(checkpoint['protected']is True and checkpoint['commit']['sha']==source,
                                          'current control checkpoint before completed-result read')
  def current_producer():
   return (producer_ready(source,platform,expected['producer_run_id'],expected['producer_attempt'],read,download)if roles is None else
           candidate_producer_ready(roles,platform,expected['producer_run_id'],expected['producer_attempt'],read,download)['producer'])
  require(current_producer()==expected and context['target']==target(expected,roles),'exact unchanged producer/context before readback')
  actual=read('actions/runs/'+str(selected['id']))
  code=context.get('controller_execution',{}).get('implementation_commit',source)
  require(actual['id']==selected['id']and actual['run_attempt']==selected['run_attempt']and
          actual['head_sha']==code and actual['status']=='completed'and actual['repository']['full_name']==REPO and
          actual['path']==ROUTE and actual['event']in('workflow_dispatch','workflow_run'),
          'actual completed controller/latest attempt/implementation, not a pending producer wait')
  execution=reviewed_controller(read,{'GITHUB_REPOSITORY':REPO,'GITHUB_SHA':code,'GITHUB_WORKFLOW_SHA':code,
      'GITHUB_REF':'refs/heads/'+actual['head_branch'],'GITHUB_REF_PROTECTED':'true'if actual['head_branch']=='main'else'false',
      'GITHUB_WORKFLOW_REF':REPO+'/'+ROUTE+'@refs/heads/'+actual['head_branch'],
      'OPEMOS_OMEN_ROBOT_RUNNER_STATE':os.environ.get('OPEMOS_OMEN_ROBOT_RUNNER_STATE','')})
  require(context.get('controller_execution',execution if execution['qualification']is None else None)==execution,
          'actual independently qualified controller, not caller-supplied code provenance')
  rid=str(selected['id']);attempt=str(selected['run_attempt']);jobs=items(read,f'actions/runs/{rid}/attempts/{attempt}/jobs','jobs')
  bad_jobs=[]
  for name in('required-platform-robot','required-platform-result'):
   rows=[j for j in jobs if j['name']==name]
   if not(len(rows)==1 and rows[0]['status']=='completed'and rows[0]['conclusion']=='success'):bad_jobs.append(name)
  if bad_jobs:
   broker_reason=None
   try:
    artifacts=items(read,f'actions/runs/{rid}/artifacts','artifacts');rows=[a for a in artifacts if a['name']==f'omen-required-result-{rid}-{attempt}'and a['expired']is False];require(len(rows)==1,'exact failed-result artifact missing')
    failed=archive_json(download(f"actions/artifacts/{rows[0]['id']}/zip"),rows[0],'required-result.json')
    require(failed['kind']=='OMEN_REQUIRED_PRODUCER_RESULT_V1'and failed['status']=='failed'and failed['diagnostic_only']is True and failed['actualGUIAccepted']is False and failed['context']==context and failed['producer']==expected and failed['consumer']=={'run_id':rid,'attempt':attempt},'failed diagnostic exact current identities')
    value=failed['broker_failure'];require(type(value)is dict,'typed failed broker cause missing')
    public_failure_value(value)
    broker_reason='Root broker '+value['code']+': '+value['reason']
    save(directory/'required-result-failed.json',failed)
   except Exception as secondary:
    print('Secondary failed-result readback/persistence failed: '+type(secondary).__name__,file=sys.stderr)
    try:save(directory/'failed-result-readback-secondary.json',{'status':'failed','firstCause':broker_reason or 'required actual job missing/failed/skipped: '+bad_jobs[0],'secondaryType':type(secondary).__name__,'oldResultAdopted':False})
    except Exception as persistence:print('Secondary readback receipt persistence failed: '+type(persistence).__name__,file=sys.stderr)
   raise Refusal(broker_reason or 'required actual job missing/failed/skipped: '+bad_jobs[0])
  artifacts=items(read,f'actions/runs/{rid}/artifacts','artifacts');rows=[a for a in artifacts if a['name']==f'omen-required-result-{rid}-{attempt}'and a['expired']is False];require(len(rows)==1,'exact current result artifact missing')
  raw=download(f"actions/artifacts/{rows[0]['id']}/zip");result=archive_json(raw,rows[0],'required-result.json')
  require(result['kind']=='OMEN_REQUIRED_PRODUCER_RESULT_V1'and result['context']==context and result['producer']==expected and result['consumer']=={'run_id':rid,'attempt':attempt}and result['status']=='passed'and result['diagnostic_only']is False,'strict current required result identity/status')
  verify_acceptance(result['required_acceptance'],expected,dict(result['consumer'],source_commit=source),roles)
  # Re-read immutable identities/current attempt; stale/re-run receipts fail.
  current=read(f'actions/runs/{rid}');require(current['run_attempt']==int(attempt)and current['status']=='completed'and current['conclusion']=='success','consumer attempt changed')
  require(current_producer()==expected,'producer changed after result')
  require(read('branches/main')==checkpoint,'control checkpoint changed during completed-result read')
  save(directory/'required-result.json',result);return 0
 except Exception as exc:
  reason='Required current OMEN GUI/SteamOS acceptance failed: '+type(exc).__name__+(': '+str(exc)[:1000]if isinstance(exc,Refusal)else'')
  print(reason,file=sys.stderr)
  try:emit_diagnostics(directory,reason,context)
  except Exception as secondary:print('Secondary diagnostic persistence failed: '+type(secondary).__name__,file=sys.stderr)
  try:save(directory/'required-failure.json',{'status':'failed','reason':reason,'context':context,'oldResultAdopted':False,'consumer':None if selected is None else {'run_id':selected['id'],'attempt':selected['run_attempt'],'url':'https://github.com/'+REPO+'/actions/runs/'+str(selected['id'])}})
  except Exception as secondary:print('Secondary failure-receipt persistence failed: '+type(secondary).__name__,file=sys.stderr)
  return 1

def main_dispatch(platform):
 """Compatibility metadata handoff, NEVER dispatch/wait inside its producer.

 The actual controller is a separate completed workflow_run (or authenticated
 controller workflow_dispatch). Returning metadata success does not create a
 required-result.json, an acceptance status or an OMEN operation.
 """
 directory=Path('required-omen-results')
 try:
  require(os.environ['GITHUB_REPOSITORY']==REPO,'canonical producer repository')
  source=os.environ['GITHUB_SHA'];read=api_reader(os.environ['GITHUB_TOKEN'])
  main=read('branches/main');controller=main['commit']['sha'];require(main['protected']is True,'current reviewed controller checkpoint')
  run_id=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT']
  run=read('actions/runs/'+run_id+'/attempts/'+attempt);roles=None
  if run['event']=='pull_request':
   prs=run['pull_requests'];require(len(prs)==1,'one exact original PR association')
   roles={'repository':REPO,'controller_commit':controller,'candidate_commit':run['head_sha'],
          'pull_request':prs[0]['number'],'base_commit':prs[0]['base']['sha'],
          'repository_id':run['repository']['id'],'head_repository_id':run['head_repository']['id']}
  elif run['head_branch']!='main':
   roles={'repository':REPO,'controller_commit':controller,'candidate_commit':run['head_sha'],'pull_request':0,
          'base_commit':controller,'repository_id':run['repository']['id'],'head_repository_id':run['head_repository']['id'],
          'source_kind':'branch','source_ref':'refs/heads/'+run['head_branch']}
  expected=(producer_ready(controller,platform,run_id,attempt,read,metadata_download)if roles is None else
            candidate_producer_ready(roles,platform,run_id,attempt,read,metadata_download)['producer'])
  save(directory/'producer-handoff.json',{'kind':'OMEN_PRODUCER_HANDOFF_V1','status':'pending-reviewed-controller',
       'producer':expected,'source_roles':roles,'controller_checkpoint':controller,'actualGUIAccepted':False,
       'completionProtocol':'Producer must complete before separate authenticated controller outcome; no wait or dispatch token here'})
  return 0
 except Exception as error:
  emit_diagnostics(directory,'Producer metadata handoff failed: '+type(error).__name__)
  return 1

def scope_guard():
 event=strict(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes());inputs=event.get('inputs',{});platform=inputs.get('required_platform','')
 name=os.environ['GITHUB_EVENT_NAME'];roles=None
 require(name in('workflow_dispatch','workflow_run'),'exact reviewed controller event')
 read=api_reader(os.environ['GITHUB_TOKEN']);execution=reviewed_controller(read);source=execution['control_commit']
 branch=read('branches/main');require(branch['protected']is True and branch['commit']['sha']==source,'current protected controller A')
 if name=='workflow_run':
  run=event['workflow_run'];matches=[p for p,path in PRODUCER_PATH.items()if path==run['path']]
  require(len(matches)==1 and run['status']=='completed'and run['event']in('push','workflow_dispatch','pull_request'),'exact completed supported producer event')
  platform=matches[0];run_id=str(run['id']);attempt=str(run['run_attempt']);nonce=secrets.token_hex(16)
 else:
  require(platform in NATIVE and inputs['source_sha']==source and re.fullmatch('[0-9a-f]{32}',inputs['correlation_nonce']or''),'exact current controller/correlation')
  run_id=inputs['producer_run'];attempt=inputs['producer_attempt'];nonce=inputs['correlation_nonce']
  require(all(re.fullmatch('[1-9][0-9]{0,19}',x or'')for x in(run_id,attempt)),'exact manual producer identity')
  run=read('actions/runs/'+run_id+'/attempts/'+attempt)
 require(run['repository']['full_name']==run['head_repository']['full_name']==REPO and
         run['repository']['id']==run['head_repository']['id']and run['head_repository'].get('fork')is False,
         'fork/foreign source needs separate authenticated guest isolation; no inherited host privilege')
 if run['event']=='pull_request':
  prs=run['pull_requests'];require(type(prs)is list and len(prs)==1,'one original PR association')
  roles={'repository':REPO,'controller_commit':source,'candidate_commit':run['head_sha'],
   'pull_request':prs[0]['number'],'base_commit':prs[0]['base']['sha'],
   'repository_id':run['repository']['id'],'head_repository_id':run['head_repository']['id']}
 elif run['head_branch']!='main':
  roles={'repository':REPO,'controller_commit':source,'candidate_commit':run['head_sha'],
   'pull_request':0,'base_commit':source,'repository_id':run['repository']['id'],
   'head_repository_id':run['head_repository']['id'],'source_kind':'branch','source_ref':'refs/heads/'+run['head_branch']}
 else:require(run['head_sha']==source,'stale Main producer')
 if name=='workflow_dispatch':
  selected_ref=inputs.get('candidate_ref','');selected_pr=inputs.get('candidate_pr','')
  if roles is None:require(not any(inputs.get(k,'')for k in('candidate_ref','candidate_pr','candidate_sha','candidate_base')),'unexpected candidate selection on Main')
  else:
   require(inputs.get('candidate_sha')==roles['candidate_commit']and inputs.get('candidate_base')==roles['base_commit'],'manual exact candidate SHA/current control checkpoint')
   if roles.get('source_kind')=='branch':require(selected_ref==roles['source_ref']and not selected_pr,'manual branch must not invent a PR')
   else:require(selected_pr==str(roles['pull_request'])and not selected_ref,'manual exact PR selection')
 if roles is not None:candidate_identity(roles,read)
 save('robot-preflight/quality-source.json',{'kind':'OMEN_BUILD_VM_QUALITY_SOURCE_V1',
      'platform':platform,'producer_run':run_id,'producer_attempt':attempt,
      'source_commit':run['head_sha'],'source_roles':roles,'control_commit':source})
 value=(producer_ready(source,platform,run_id,attempt,read,metadata_download)if roles is None else
        candidate_producer_ready(roles,platform,run_id,attempt,read,metadata_download)['producer'])
 if name=='workflow_dispatch':require(value['artifact_id']==inputs['artifact_id'],'exact dispatch artifact')
 context={'repository':REPO,'source_commit':source,'target':target(value,roles),'nonce':nonce,
          'controller_execution':execution}
 save('robot-preflight/required-context.json',{'context':context,'producer':value})
 with open(os.environ['GITHUB_OUTPUT'],'a')as out:out.write('producer='+canonical(target(value,roles)).decode()+'\nplatform='+platform+'\n')

def read_report(path,cap):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=cap,'bounded regular current report')
  raw=bytearray()
  while block:=os.read(fd,min(65536,cap+1-len(raw))):raw.extend(block);require(len(raw)<=cap,'report overflow')
  fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');sig=lambda x:tuple(getattr(x,k)for k in fields)
  require(len(raw)==before.st_size and sig(before)==sig(os.fstat(fd))==sig(Path(path).lstat()),'report held/named changed')
  return bytes(raw)
 finally:os.close(fd)
def public_reports(reply):
 rows=reply['public_evidence'];identity=reply['identity'];require(type(rows)is list and 0<len(rows)<=64,'finite actual public reports')
 require(len({r['name']for r in rows})==len(rows),'duplicate public report names');total=0
 for row in rows:
  name=row['name'];require(name==Path(name).name and name.startswith(identity['run_id']+'-'+identity['attempt']+'-'),'current public basename')
  require(type(row['bytes'])is int and 0<row['bytes']<=16*1024**2 and re.fullmatch('[0-9a-f]{64}',row['sha256']or''),'exact public descriptor');total+=row['bytes'];require(total<=256*1024**2,'public operation cap')
  raw=read_report(Path('robot-results')/name,16*1024**2);require(len(raw)==row['bytes']and hashlib.sha256(raw).hexdigest()==row['sha256'],'downloaded public report differs from actual Root publication')
  if row['kind']=='robot-output':
   tree=ET.fromstring(raw);require(tree.tag=='robot'and tree.attrib.get('generator','').startswith('Robot'),'actual guest Robot XML required');cases=tree.findall('.//test');require(cases and all(c.find('status').attrib.get('status')=='PASS'for c in cases),'actual guest Robot result failed/missing')
 return rows
PUBLIC_FAILURES = {'ACTIONS_TOKEN_REQUIRED': 'Existing ephemeral attested Actions token required', 'LEGACY_SCOPE_REFUSED': 'Legacy connection proof is not authorized by this control-only lease', 'TOKEN_BINDING_REQUIRED': 'A post-hook job-token binding is required before a produced-platform operation', 'HOST_OPERATION_FAILED': 'Host operation failed; retained private stage evidence remains authoritative'}

def public_failure_value(f):
    require(type(f) is dict and set(f) == {"kind", "code", "reason", "error_type", "private_recorded", "secondary"} and
            f["kind"] == "OPEMOS_BROKER_FAILURE_V1" and f["code"] in PUBLIC_FAILURES and
            f["reason"] == PUBLIC_FAILURES[f["code"]] and
            type(f["error_type"]) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", f["error_type"]) and
            type(f["private_recorded"]) is bool and
            f["secondary"] in ([], ["PRIVATE_FAILURE_PERSISTENCE_FAILED"]),
            "strict nonsecret failed broker cause")
    return f


def broker_failure(reply):
    if "failure" not in reply: return None
    require(set(reply) == {"identity", "action", "subject", "status", "all20_passed",
                          "all_platforms_passed", "vms", "platforms", "public_evidence",
                          "acceptance", "failure"} and
            reply["status"] == "failed" and reply["all20_passed"] is False and
            reply["all_platforms_passed"] is False and reply["vms"] == reply["platforms"] == {} and
            reply["public_evidence"] == [] and
            reply["acceptance"] == "SOURCE_AND_ACTUAL_CASE_ONLY; NO_INFERRED_FULLSTACK_PASS",
            "exact failed broker envelope")
    return public_failure_value(reply["failure"])


def finalize_scope():
 failure_path=Path('robot-preflight/scope-failure.json')
 if failure_path.exists():
  failure=strict(read_report(failure_path,65536))
  require(failure['kind']=='OMEN_CONTROLLER_PREFLIGHT_FAILURE_V1'and failure['consumer']=={
      'run_id':os.environ['GITHUB_RUN_ID'],'attempt':os.environ['GITHUB_RUN_ATTEMPT'],
      'implementation_commit':os.environ['GITHUB_SHA']}and failure['diagnostic_only']is True and
      failure['actualGUIAccepted']is False,'stale/foreign controller preflight failure')
  error=Refusal(failure['reason']);error.preflight_failure=failure;raise error
 context=strict(Path('robot-preflight/required-context.json').read_bytes());reply=strict(Path('robot-results/broker-required.json').read_bytes());identity=reply['identity'];expected=context['producer']
 roles=context['context']['target'].get('source_roles')
 controller=context['context']['source_commit']
 execution=reviewed_controller(api_reader(os.environ['GITHUB_TOKEN']))
 require(context['context'].get('controller_execution')==execution and identity['repository']==REPO and
         identity['source_commit']==controller==execution['control_commit']and identity['run_id']==os.environ['GITHUB_RUN_ID']and
         identity['attempt']==os.environ['GITHUB_RUN_ATTEMPT']and re.fullmatch('[0-9a-f]{32}',identity['nonce']),
         'actual current broker/control checkpoint AND independent controller implementation identity')
 if roles is not None:source_roles(roles,controller=controller,candidate=expected['source_commit'])
 else:require(controller==expected['source_commit'],'Main-only producer/controller differs')
 require(reply['action']=='execute-produced-platform'and reply['subject']==context['context']['target'],'actual exact broker target')
 failure=broker_failure(reply)
 if failure is not None:
  refusal=Refusal('Root broker '+failure['code']+': '+failure['reason']);refusal.broker_failure=failure;refusal.failed_context=context;raise refusal
 require(reply['status']=='passed','actual exact broker target status')
 verified=verify_acceptance(reply['required_acceptance'],expected,identity,roles)
 read=api_reader(os.environ['GITHUB_TOKEN']);branch=read('branches/main')
 require(branch['protected']is True and branch['commit']['sha']==controller,'controller A changed before final result')
 if roles is not None:
  require(candidate_producer_ready(roles,expected['platform'],expected['producer_run_id'],expected['producer_attempt'],read,metadata_download)['producer']==expected,
          'candidate B changed/rerun/expired before final result')
 public=public_reports(reply);kinds={x['kind']for x in public};require({'robot-output','robot-report','robot-log','robot-xunit','screenshot','argv','pointer-action','nvidia-loaded','nvidia-render','gpu-restoration'}<=kinds,'all actual public reports/frames/native/SteamOS/NVIDIA evidence required')
 outer=[]
 for name in('output.xml','report.html','log.html','xunit.xml'):
  raw=read_report(Path('robot-results')/name,16*1024**2);outer.append({'name':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
 tree=ET.parse('robot-results/output.xml');root=tree.getroot();require(root.tag=='robot'and root.attrib.get('generator','').startswith('Robot'),'actual Robot report, not fallback diagnostics')
 tests=root.findall('.//test');require(tests and all(t.find('status').attrib.get('status')=='PASS'for t in tests),'current actual RF cases failed/missing')
 require(not Path('robot-results/diagnostic.json').exists(),'fallback unavailable diagnostic cannot become pass')
 result={'kind':'OMEN_REQUIRED_PRODUCER_RESULT_V1','context':context['context'],'producer':expected,'consumer':{'run_id':identity['run_id'],'attempt':identity['attempt']},'status':'passed','diagnostic_only':False,'required_acceptance':verified,'public_evidence':public,'outer_reports':outer,'actualReportsArtifact':'robot-actual-'+identity['run_id']+'-'+identity['attempt'],'quality_source':quality_source_record()}
 require(len(canonical(result))+1<=65536,'small result contract; no cap expansion')
 save('required-result/required-result.json',result)

def quality_source_record():
 path=Path('robot-preflight/quality-source.json')
 return strict(read_report(path,65536))if path.exists()else None

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['dispatch-and-wait','scope-guard','finalize-scope','diagnostics']);parser.add_argument('--platform',choices=tuple(NATIVE));parser.add_argument('--directory',default='robot-results');parser.add_argument('--reason',default='Actual OMEN route/result unavailable; no guest pass')
 args=parser.parse_args()
 if args.mode=='dispatch-and-wait':raise SystemExit(main_dispatch(args.platform))
 try:
  if args.mode=='scope-guard':scope_guard()
  elif args.mode=='finalize-scope':finalize_scope()
  else:emit_diagnostics(args.directory,args.reason)
 except Exception as exc:
  reason='Required actual OMEN stage failed: '+type(exc).__name__+(': '+str(exc)[:1000]if isinstance(exc,Refusal)else'')
  print(reason,file=sys.stderr)
  if args.mode=='scope-guard':
   try:
    save('robot-preflight/scope-failure.json',{'kind':'OMEN_CONTROLLER_PREFLIGHT_FAILURE_V1','stage':'producer-scope',
       'reason':reason,'error_type':type(exc).__name__,'consumer':{'run_id':os.environ.get('GITHUB_RUN_ID'),
        'attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),'implementation_commit':os.environ.get('GITHUB_SHA')},
       'actualGUIAccepted':False,'diagnostic_only':True})
   except Exception as secondary:print('Secondary scope failure persistence failed: '+type(secondary).__name__,file=sys.stderr)
  try:emit_diagnostics(args.directory,reason)
  except Exception as secondary:print('Secondary diagnostic persistence failed: '+type(secondary).__name__,file=sys.stderr)
  if args.mode=='finalize-scope':
   try:save('required-result/required-result.json',{'kind':'OMEN_REQUIRED_PRODUCER_RESULT_V1','status':'failed','diagnostic_only':True,'reason':reason,'actualGUIAccepted':False,'source_commit':os.environ.get('GITHUB_SHA'),'consumer':{'run_id':os.environ.get('GITHUB_RUN_ID'),'attempt':os.environ.get('GITHUB_RUN_ATTEMPT')},'broker_failure':getattr(exc,'broker_failure',None),'preflight_failure':getattr(exc,'preflight_failure',None),'context':getattr(exc,'failed_context',{}).get('context'),'producer':getattr(exc,'failed_context',{}).get('producer'),'quality_source':quality_source_record()})
   except Exception as secondary:print('Secondary required-result persistence failed: '+type(secondary).__name__,file=sys.stderr)
  raise SystemExit(1)

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
import time
from urllib import request,error,parse
import xml.etree.ElementTree as ET
import zipfile
from check_full_stack_acceptance import api_reader,NoRedirect,Refusal
from omen_ci_executables import descriptor,canonical,digest,archive_json,pointer_proof_valid

REPO='CorniiDog/OPEMOS.EXE'
ROUTE='.github/workflows/omen-robot.yml'
NATIVE={'ubuntu':('appimage-package','02 Ubuntu AppImage'),'windows':('build','01 Windows EXE')}
PRODUCER_PATH={'ubuntu':'.github/workflows/ubuntu-executable.yml','windows':'.github/workflows/windows-portable.yml'}
CAP=2*1024**2
def require(value,reason):
 if not value:raise Refusal(reason)
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
  require(path=='branches/main'or re.fullmatch(r'actions/runs/[1-9][0-9]{0,19}(?:/attempts/[1-9][0-9]{0,19}(?:/jobs)?|/artifacts)?(?:\?per_page=100)?',path),'fixed Root producer metadata endpoint')
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
def target(value):return{k:value[k]for k in('platform','producer_run_id','producer_attempt','artifact_id')}|{'descriptor_sha256':digest(value)}
def verify_acceptance(value,expected,consumer):
 require(type(value)is dict and value['status']=='passed'and value['executable']==expected and value['source_commit']==expected['source_commit']and value['run_id']==consumer['run_id']and value['attempt']==consumer['attempt']and value['actual_receipt_verified']is True and value['active']is False,'exact current actual Root artifact transaction')
 require(pointer_proof_valid(value['pointer_acceptance'],expected,value,expected['source_commit'],consumer['run_id'],consumer['attempt']),'all five actual chooser/Build/USB pointer transitions required')
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
 selected=req['subject'];require(type(selected)is dict and set(selected)=={'platform','producer_run_id','producer_attempt','artifact_id','descriptor_sha256'},'finite producer selection')
 require(all(engine.context[k]==req[k]for k in('repository','source_commit','run_id','attempt')),'Root Engine current job/source identity')
 platform=selected['platform'];require(platform in NATIVE,'exact supported producer')
 engine.current=None;phase='current protected Main metadata'
 try:
  branch=read('branches/main');require(branch['protected']is True and branch['commit']['sha']==req['source_commit'],'actual current protected Main before normal operation')
  phase='exact current producer package/job/artifact'
  expected=producer_ready(req['source_commit'],platform,selected['producer_run_id'],selected['producer_attempt'],read,download);require(target(expected)==selected,'producer target changed')
  phase='normal admitted prepare/stage/queue transaction'
  result=engine.transaction('artifact',{'platform':platform,'artifact_id':expected['artifact_id']},expected_producer=expected)
  require(result['expected']==expected and result['status']=='passed'and result['active']is False and result['closure_verified']is True,'normal canonical transaction not closed')
  phase='actual image/USB/SteamOS and pointer proof'
  verified=verify_acceptance(result['steam_os_transaction'],expected,req)
  phase='post-transaction producer and Main recheck'
  require(producer_ready(req['source_commit'],platform,selected['producer_run_id'],selected['producer_attempt'],read,download)==expected,'producer changed during runtime')
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
 value={'kind':'OMEN_REQUIRED_FAILURE_DIAGNOSTIC_V1','status':'failed','diagnostic_only':True,'actualGUIExecuted':False,'reason':reason,'context':context,'vms':rows,'SteamOS':'unavailable; requires actual installed target/NVIDIA/render/recovery receipts','missingScreenshotIsNotAFrame':True}
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

def main_dispatch(platform):
 directory=Path('required-omen-results');context=None;selected=None
 try:
  require(os.environ['GITHUB_REPOSITORY']==REPO and os.environ['GITHUB_EVENT_NAME']in('push','workflow_dispatch')and os.environ['GITHUB_REF']=='refs/heads/main'and os.environ['GITHUB_REF_PROTECTED']=='true','PR/fork/unprotected event unavailable: no OMEN dispatch')
  source=os.environ['GITHUB_SHA'];read=api_reader(os.environ['GITHUB_TOKEN']);branch=read('branches/main');require(branch['protected']is True and branch['commit']['sha']==source,'exact live protected Main required')
  expected=producer_ready(source,platform,os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT'],read,metadata_download)
  nonce=secrets.token_hex(16);context={'repository':REPO,'source_commit':source,'target':target(expected),'nonce':nonce};save(directory/'request.json',context)
  inputs={'required_platform':platform,'producer_run':expected['producer_run_id'],'producer_attempt':expected['producer_attempt'],'artifact_id':expected['artifact_id'],'source_sha':source,'correlation_nonce':nonce}
  body=json.dumps({'ref':'main','inputs':inputs}).encode();opener=request.build_opener(NoRedirect)
  try:
   with opener.open(request.Request('https://api.github.com/repos/'+REPO+'/actions/workflows/omen-robot.yml/dispatches',data=body,headers=token_headers(),method='POST'),timeout=20)as response:require(response.status==204 and response.read(1)==b'','one dispatch acknowledgement')
  except error.HTTPError as refused:
   try:raise Refusal('one dispatch refused HTTP '+str(refused.code))from None
   finally:refused.close()
  deadline=time.monotonic()+14400;selected=None
  title=f'04 SteamOS required {platform} {expected["producer_run_id"]}/{expected["producer_attempt"]} {nonce}'
  while time.monotonic()<deadline:
   runs=items(read,'actions/workflows/omen-robot.yml/runs?event=workflow_dispatch&head_sha='+source,'workflow_runs');matches=[r for r in runs if r.get('display_title')==title]
   require(len(matches)<=1,'ambiguous dispatch correlation; no second dispatch')
   if matches:
    selected=matches[0];require(selected['head_sha']==source and selected['head_branch']=='main'and selected['event']=='workflow_dispatch'and selected['repository']['full_name']==REPO,'consumer run identity')
    if selected['status']=='completed':break
   time.sleep(10)
  require(selected is not None and selected['status']=='completed','OMEN result unavailable/timed out; no retry or old receipt')
  rid=str(selected['id']);attempt=str(selected['run_attempt']);jobs=items(read,f'actions/runs/{rid}/attempts/{attempt}/jobs','jobs')
  for name in('required-platform-robot','required-platform-result'):
   rows=[j for j in jobs if j['name']==name];require(len(rows)==1 and rows[0]['status']=='completed'and rows[0]['conclusion']=='success','required actual job missing/failed/skipped: '+name)
  artifacts=items(read,f'actions/runs/{rid}/artifacts','artifacts');rows=[a for a in artifacts if a['name']==f'omen-required-result-{rid}-{attempt}'and a['expired']is False];require(len(rows)==1,'exact current result artifact missing')
  raw=metadata_download(f"actions/artifacts/{rows[0]['id']}/zip");result=archive_json(raw,rows[0],'required-result.json')
  require(result['kind']=='OMEN_REQUIRED_PRODUCER_RESULT_V1'and result['context']==context and result['producer']==expected and result['consumer']=={'run_id':rid,'attempt':attempt}and result['status']=='passed'and result['diagnostic_only']is False,'strict current required result identity/status')
  verify_acceptance(result['required_acceptance'],expected,result['consumer'])
  # Re-read immutable identities/current attempt; stale/re-run receipts fail.
  current=read(f'actions/runs/{rid}');require(current['run_attempt']==int(attempt)and current['status']=='completed'and current['conclusion']=='success','consumer attempt changed')
  require(producer_ready(source,platform,expected['producer_run_id'],expected['producer_attempt'],read,metadata_download)==expected,'producer changed after result')
  save(directory/'required-result.json',result);return 0
 except Exception as exc:
  reason='Required current OMEN GUI/SteamOS acceptance failed: '+type(exc).__name__+(': '+str(exc)[:1000]if isinstance(exc,Refusal)else'')
  emit_diagnostics(directory,reason,context);save(directory/'required-failure.json',{'status':'failed','reason':reason,'context':context,'oldResultAdopted':False,'consumer':None if selected is None else {'run_id':selected['id'],'attempt':selected['run_attempt'],'url':'https://github.com/'+REPO+'/actions/runs/'+str(selected['id'])}});return 1

def scope_guard():
 event=strict(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes());inputs=event.get('inputs',{});platform=inputs.get('required_platform','')
 require(platform in NATIVE and os.environ['GITHUB_EVENT_NAME']=='workflow_dispatch'and os.environ['GITHUB_REF']=='refs/heads/main'and os.environ['GITHUB_REF_PROTECTED']=='true','trusted finite required dispatch')
 source=inputs['source_sha'];require(source==os.environ['GITHUB_SHA']and re.fullmatch('[0-9a-f]{32}',inputs['correlation_nonce']or''),'exact current source/correlation')
 read=api_reader(os.environ['GITHUB_TOKEN']);branch=read('branches/main');require(branch['protected']is True and branch['commit']['sha']==source,'current protected Main')
 value=producer_ready(source,platform,inputs['producer_run'],inputs['producer_attempt'],read,metadata_download);require(value['artifact_id']==inputs['artifact_id'],'exact dispatch artifact')
 context={'repository':REPO,'source_commit':source,'target':target(value),'nonce':inputs['correlation_nonce']}
 save('robot-preflight/required-context.json',{'context':context,'producer':value})
 with open(os.environ['GITHUB_OUTPUT'],'a')as out:out.write('producer='+canonical(target(value)).decode()+'\n')

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
def finalize_scope():
 context=strict(Path('robot-preflight/required-context.json').read_bytes());reply=strict(Path('robot-results/broker-required.json').read_bytes());identity=reply['identity'];expected=context['producer']
 require(identity['repository']==REPO and identity['source_commit']==expected['source_commit']and identity['run_id']==os.environ['GITHUB_RUN_ID']and identity['attempt']==os.environ['GITHUB_RUN_ATTEMPT']and re.fullmatch('[0-9a-f]{32}',identity['nonce']),'actual current broker identity')
 require(reply['action']=='execute-produced-platform'and reply['subject']==context['context']['target']and reply['status']=='passed','actual exact broker target status')
 verified=verify_acceptance(reply['required_acceptance'],expected,identity)
 public=public_reports(reply);kinds={x['kind']for x in public};require({'robot-output','robot-report','robot-log','robot-xunit','screenshot','argv','pointer-action','nvidia-loaded','nvidia-render','gpu-restoration'}<=kinds,'all actual public reports/frames/native/SteamOS/NVIDIA evidence required')
 outer=[]
 for name in('output.xml','report.html','log.html','xunit.xml'):
  raw=read_report(Path('robot-results')/name,16*1024**2);outer.append({'name':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
 tree=ET.parse('robot-results/output.xml');root=tree.getroot();require(root.tag=='robot'and root.attrib.get('generator','').startswith('Robot'),'actual Robot report, not fallback diagnostics')
 tests=root.findall('.//test');require(tests and all(t.find('status').attrib.get('status')=='PASS'for t in tests),'current actual RF cases failed/missing')
 require(not Path('robot-results/diagnostic.json').exists(),'fallback unavailable diagnostic cannot become pass')
 result={'kind':'OMEN_REQUIRED_PRODUCER_RESULT_V1','context':context['context'],'producer':expected,'consumer':{'run_id':identity['run_id'],'attempt':identity['attempt']},'status':'passed','diagnostic_only':False,'required_acceptance':verified,'public_evidence':public,'outer_reports':outer,'actualReportsArtifact':'robot-actual-'+identity['run_id']+'-'+identity['attempt']}
 require(len(canonical(result))+1<=65536,'small result contract; no cap expansion')
 save('required-result/required-result.json',result)

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
  emit_diagnostics(args.directory,reason)
  if args.mode=='finalize-scope':
   save('required-result/required-result.json',{'kind':'OMEN_REQUIRED_PRODUCER_RESULT_V1','status':'failed','diagnostic_only':True,'reason':reason,'actualGUIAccepted':False,'source_commit':os.environ.get('GITHUB_SHA'),'consumer':{'run_id':os.environ.get('GITHUB_RUN_ID'),'attempt':os.environ.get('GITHUB_RUN_ATTEMPT')}})
  raise SystemExit(1)

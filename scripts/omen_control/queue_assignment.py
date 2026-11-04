"""Filesystem-only current canonical worker export -> protected Root assignment.
No SQLite API, DB copy/index or closure inference on this postlaunch path.
"""
import hashlib,json,time,types,sys
import libvirt_peer as p
from libvirt_native import held
from libvirt_preflight import QUEUE_SHA
CONTROL_QUEUE_SHA='16177e18b25de4b5b4a45849f5eddb7f7b58527f7d3425d48849927d5843103e'

def protected_continuation_value(ref,mode=0o400):
 """Same existing RootFiles nofollow/FD/name/full9 contract, no new IO backend."""
 path=__import__('pathlib').Path(ref['path'])
 with p.RootFiles(str(path.parent))as files:
  raw,actual=files.read(path.name,mode,1048576);p.need(actual==ref,'exact protected continuation input full9/SHA/EOF');return json.loads(raw)

def closed_unbooted_prior(c,row,binding,parent,parent_original):
 """Pure full canonical prior generation join; never projects CLOSED from absence."""
 p.need(set(row)=={'id','spec','state','cpus','unit','started','finished','result'}and row['id']==c['jobId']and row['state']=='failed'and type(row['started'])in(int,float)and type(row['finished'])in(int,float)and row['finished']>=row['started'],'exact failed finished eight-column prepared generation')
 spec=json.loads(row['spec']);bound=json.loads(binding['value']);p.need(binding['job_id']==row['id']and bound['job_id']==row['id']and bound['unit']==row['unit']and bound['specSHA256']==hashlib.sha256(p.canon(spec)).hexdigest()and bound['cpus']==json.loads(row['cpus'])and bound['memory']==10737418240,'whole prior spec/keyed binding/unit/cpus/memory equality')
 expected=__import__('copy').deepcopy(parent['normalizedSpecTemplate']);p.need(expected['approval']=='EXACT_PARENT_MINIMAL_PIN'and expected['command'][-1]=='EXACT_PARENT_FULL_PIN_JSON','prior normal two late pin slots');expected['approval']={k:parent_original[k]for k in('path','bytes','sha256')};expected['command'][-1]=p.canon(parent_original).decode()
 p.need(spec==expected and parent['candidate']==c and parent['jobId']==row['id']and parent['nonce']==c['nonce']and parent['bootID']==c['hostBoot']and parent['RootIssued']is True and parent['kind']=='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT'and parent['runtimeAuthorized']is True and parent.get('MODEL_ONLY')is False and parent['noNIC']is True and parent['noInstall']is True and parent['maxBoots']==1,'whole prior normalized spec/Root parent/exact unchanged prepared candidate')
 domain=spec['libvirt_domain'];p.need(domain=={'uuid':c['guestUUID'],'name':c['name'],'leaseNonce':c['nonce'],'observer':{k:parent['sourceRoles']['libvirt_peer'][k]for k in('path','bytes','sha256')}}and spec['id']==c['jobId']and p.GROUP in spec['resources'],'same prior domain/guest/nonce/observer/exclusive resource')
 result=json.loads(row['result']);life=result['terminalLifecycle'];final=result['finalAfterFsyncCgroupProof'];native=final['neverPrepared'];manager=life['managerAfter']
 p.need(life['phase']=='CLOSED'and life['intendedState']=='failed'and life['reservationRetained']is False and result['finalLedgerInvocation']==bound['invocation']and manager['InvocationID']==bound['invocation']and manager['MainPID']=='0'and manager['ControlGroup']==''and manager['ActiveState']==manager['SubState']=='failed','actual canonical CLOSED/nonretained same original invocation; no synthetic close')
 p.need(final['empty']is True and final['queueService']['empty']is True and final['libvirtPartition']['empty']is True and final['libvirtDomain']['phase']=='NOT_PREPARED'and final['libvirtDomain']['lease']is None and final['libvirtDomain']['leader']is None and native['kind']=='FAILED_BEFORE_LIBVIRT_PREPARATION'and native['leaseEverCreated']is False and native['leaseClosureInvented']is False and native['physicalLeaseReadonly']['gpuAvailable']is True,'actual complete canonical never-prepared no-lease/VM terminal proof')
 return bound

def execution_job(c,parent,prior=None):
 """Logical prepared candidate stays exact; one Root-bound unbooted execution differs."""
 p.need(parent['candidate']==c and parent['RootIssued']is True and parent['kind']=='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT'and parent['bootID']==c['hostBoot'],'whole unchanged logical prepared candidate/current Root parent')
 job=parent['jobId'];ref=parent.get('unbootedContinuationPin')
 if ref is None:
  p.need(job==c['jobId'],'distinct job requires protected closed-unbooted continuation');return job
 p.need(__import__('re').fullmatch(__import__('re').escape(c['jobId'])+r'-e[0-9a-f]{16}',job)is not None and len(job)<=80 and job!=c['jobId'],'one exact distinct bounded queue execution ID')
 v=protected_continuation_value(ref);i=ref['identity'];p.need(i['st_uid']==i['st_gid']==0 and __import__('stat').S_IMODE(i['st_mode'])==0o400 and i['st_nlink']==1,'protected Root0400 continuation, no supplied closed boolean')
 fields={'kind','nonce','bootID','preparedCandidate','newJobId','preparedAccessPin','preparedDiskPins','currentPreflightPin','sourceRoles','queuePrograms','observedUnix','prior','nativeCurrentPin'}
 p.need(set(v)==fields and v['kind']=='ROOT_NORMAL_CLOSED_UNBOOTED_PREPARED_CONTINUATION_R1'and v['nonce']==c['nonce']==parent['nonce']and v['bootID']==c['hostBoot']==parent['bootID']and v['preparedCandidate']==c and v['newJobId']==job,'exact typed same-guest/candidate/current-boot execution relation')
 suffix=job.rsplit('-e',1)[1];p.need(ref['path']=='/run/opemos-steamos-placement-'+c['nonce']+'/closed-unbooted-'+suffix+'.json','exact normal placement continuation role')
 p.need(v['preparedAccessPin']==parent['preparedAccessPin']and v['preparedDiskPins']==parent['preparedDiskPins']and v['currentPreflightPin']==parent['prequeuePreflightPin']and v['sourceRoles']==parent['sourceRoles']and v['queuePrograms']==parent['queuePrograms'],'same actual access/disk/preflight/current source+queue producer bindings')
 pre=protected_continuation_value(v['currentPreflightPin']);p.need(pre['kind']=='ACTUAL_LIBVIRT_R4_CURRENT_PREFLIGHT'and pre['preparedAccessPin']==v['preparedAccessPin']and pre['original']==v['preparedDiskPins']['original']and pre['working']==v['preparedDiskPins']['working']and pre['queuePrograms']==v['queuePrograms']and pre['bootID']==v['bootID']and pre['allOwnedFDsClosed']is True and pre['runtimeAuthorized']is False and pre['observedUnix']<=v['observedUnix']<=parent['issuedUnix']<=pre['observedUnix']+30,'fresh real final preflight, never relabel old stage or clocks')
 old=v['prior'];p.need(set(old)=={'row','binding','parent','manifest','issuerFailure'},'complete prior normal metadata and canonical relation')
 history='/run/opemos-libvirt-unbooted-history-'+c['nonce']+'-'+hashlib.sha256(c['jobId'].encode()).hexdigest()[:16]
 def retained(role,newpath,oldpath,mode):
  pair=old[role];p.need(set(pair)=={'originalPin','retainedPin'}and pair['originalPin']['path']==oldpath and pair['retainedPin']['path']==newpath,'exact original/retained metadata roles');a=pair['originalPin'];b=pair['retainedPin'];value=protected_continuation_value(b,mode)
  p.need(a['bytes']==b['bytes']and a['sha256']==b['sha256']and all(a['identity'][k]==b['identity'][k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns'))and a['identity']['st_uid']==a['identity']['st_gid']==0 and __import__('stat').S_IMODE(a['identity']['st_mode'])==mode and a['identity']['st_nlink']==1,'same inode/content/mode retained history; only explicit rename ctime may differ');return value
 op=retained('parent',history+'/parent.json','/run/opemos-libvirt-parent-'+c['nonce']+'.json',0o444);manifest=retained('manifest',history+'/job.json','/run/opemos-libvirt-job-'+c['nonce']+'.json',0o444);issuer=retained('issuerFailure',history+'/issuer-first.json','/run/opemos-libvirt-runtime-'+c['nonce']+'/FIRST-postqueue-issuer.json',0o400)
 bound=closed_unbooted_prior(c,old['row'],old['binding'],op,old['parent']['originalPin']);p.need(manifest['version']==1 and len(manifest['jobs'])==1 and manifest['jobs'][0]['id']==c['jobId']and issuer['grantAccepted']is False and issuer['hardwareEffects']==[]and type(issuer['first'])is dict,'retained actual no-grant issuer failure and consumed manifest')
 if prior is not None:
  raw=p.canon(prior);prior_history=pre['privateHistory'];p.need(len(raw)==prior_history['rawBytes']and hashlib.sha256(raw).hexdigest()==prior_history['rawSHA256']and {k:len(v)for k,v in prior.items()}==prior_history['counts'],'complete current closed prior equals genuine final preflight relation')
  p.need([r for r in prior['rows']if r['id']==c['jobId']]==[old['row']]and dict(prior['bindings']).get(c['jobId'])==old['binding']['value']and job not in{r['id']for r in prior['rows']},'current whole prior history contains exact closed generation; new execution absent')
 nr=v['nativeCurrentPin'];ni=nr['identity'];p.need(ni['st_uid']==ni['st_gid']==0 and __import__('stat').S_IMODE(ni['st_mode'])==0o400 and ni['st_nlink']==1 and nr['path']==history+'/current-native.json','normal protected current-native role');now=protected_continuation_value(nr);p.need(set(now)=={'kind','bootID','observedUnix','unit','domains','QEMU','vfioHolders','unknown','absent'}and now['kind']=='ROOT_NORMAL_UNBOOTED_CURRENT_NATIVE_R1'and now['bootID']==v['bootID']and pre['observedUnix']<=now['observedUnix']<=v['observedUnix'],'fresh actual current native observation, no historic absence inference')
 unit=now['unit'];p.need(unit['Id']==old['row']['unit']and unit['InvocationID']==bound['invocation']and unit['LoadState']=='loaded'and unit['ActiveState']==unit['SubState']=='failed'and unit['MainPID']=='0'and unit['ControlGroup']==''and now['domains']==now['QEMU']==now['vfioHolders']==now['unknown']==[],'exact failed original invocation and current no-domain/holder/unknown proof')
 absent=['/run/opemos-vfio-'+c['nonce'],history+'/runtime/child-grant.json',history+'/runtime/context.json',history+'/runtime/assignment.json'];p.need(now['absent']==[{'path':path,'error':{'errno':2,'type':'FileNotFoundError'}}for path in absent],'exact observed no-lease/no-grant historical runtime paths')
 return job

def capture_execution_job(c,binding):
 ref=binding['parentManifestPin'];p.need(ref['identity']['st_uid']==ref['identity']['st_gid']==0 and __import__('stat').S_IMODE(ref['identity']['st_mode'])==0o444 and ref['identity']['st_nlink']==1,'Root444 capture parent');parent=json.loads(held(ref,1048576));p.need(parent['sourceRoles']==binding['sourceRoles']and parent['queuePrograms']==binding['queuePrograms']and parent['bootID']==binding['bootID']and binding['parentManifestPin']['path']==__import__('source_contract').parent_paths(parent)['parentPath'],'held exact capture parent/source/queue/boot');return execution_job(c,parent)

def from_values(value,prior,c,g,queue,parent=None):
 counts={k:len(v)for k,v in prior.items()};raw=p.canon(prior)
 p.need(set(prior)=={'rows','bindings','config'}and 0<len(prior['rows'])<256 and len(prior['bindings'])<=256 and counts==g['priorHistoryCounts']and len(raw)==g['priorHistoryBytes']and hashlib.sha256(raw).hexdigest()==g['priorHistorySHA256'],'exact full independently pinned current prior history')
 p.need(len({r['id']for r in prior['rows']})==len(prior['rows'])and len(dict(prior['bindings']))==len(prior['bindings']),'unique prior row and keyed binding inventory')
 p.need(set(value)=={'rows','bindings','config'}and len(value['rows'])==len(prior['rows'])+1 and len(value['bindings'])==len(prior['bindings'])+1 and value['rows'][:-1]==prior['rows']and value['config']==prior['config'],'complete prior ordered rows/config unchanged plus one exact append')
 bindings=dict(value['bindings']);p.need(len(bindings)==len(value['bindings'])and all(bindings.get(k)==v for k,v in prior['bindings']),'all unique keyed prior binding bytes exact')
 row=value['rows'][-1];p.need(set(row)=={'id','spec','state','cpus','unit','started','finished','result'}and row['id']==g['jobId']==(c['jobId']if parent is None else execution_job(c,parent,prior))and row['state']=='running'and row['started']is not None and row['finished']is None and row['result']is None and row['id']not in{r['id']for r in prior['rows']}and set(bindings)-set(dict(prior['bindings']))=={row['id']},'actual unique eight-column own running row/new binding before effects')
 spec=json.loads(row['spec']);p.need(hashlib.sha256(queue.canonical(spec).encode()).hexdigest()==g['normalizedSpecSHA256'],'exact Root-bound normalized whole job bytes')
 bound=json.loads(bindings[row['id']]);request=queue.libvirt_request(row,bound);p.validate_request(request)
 p.need(request['domainName']==c['name']and request['domainUUID']==c['guestUUID']and request['leaseNonce']==c['nonce']and request['observer']==g['observerPin'],'same exact domain/lease/source scope')
 return request,{'ownRowSHA256':hashlib.sha256(p.canon(row)).hexdigest(),'ownBindingSHA256':hashlib.sha256(bindings[row['id']].encode()).hexdigest(),'priorRawSHA256':g['priorHistorySHA256'],'priorCounts':counts,'currentRawSHA256':hashlib.sha256(p.canon(value)).hexdigest(),'currentCounts':{k:len(v)for k,v in value.items()}}

def load_queue(ref):
 p.need(ref['sha256']==QUEUE_SHA,'exact reviewed paired live-export queue source');raw=held(ref,1048576);q=types.ModuleType('held_live_export_queue_R6');q.__file__=ref['path'];sys.modules[q.__name__]=q
 try:exec(compile(raw,ref['path'],'exec'),q.__dict__)
 finally:sys.modules.pop(q.__name__,None)
 return q

def produce(c,g,parent,prior,persist,worker_guard,end,metrics=None):
 qref=g['queuePrograms'][0];started=time.monotonic();queue=load_queue(qref);polls=0;observations={'kind':'ROOT_CURRENT_ASSIGNMENT_INTAKE_MEASUREMENTS','originalEndUnix':end,'readinessPolls':0,'workerChecks':0};archive={}
 try:
  while True:
   p.need(time.time()<end,'no current exact canonical export inside original30s entry wait')
   polls+=1
   if queue.libvirt_assignment_ready(parent['queueStateRoot'],g['jobId']):break
   time.sleep(min(.025,max(0,end-time.time())))
  observations.update(readinessPolls=polls,headerWaitSeconds=time.monotonic()-started)
  tick=time.monotonic();before=worker_guard(qref,parent);observations.update(beforeWorkerSeconds=time.monotonic()-tick,workerChecks=1)
  p.need(time.time()<end,'original entry deadline before whole assignment intake');tick=time.monotonic()
  value,evidence=queue.read_libvirt_assignment_export(parent['queueStateRoot'],g['jobId'],before['worker'],qref,parent['bootID'],maximumAge=min(30,max(.001,end-time.time())),metrics=archive)
  observations.update(intakeSeconds=time.monotonic()-tick,archive=archive);p.need(time.time()<end,'original entry deadline after whole assignment intake')
  tick=time.monotonic();after=worker_guard(qref,parent);observations.update(afterWorkerSeconds=time.monotonic()-tick,workerChecks=2)
  p.need(before==after,'same exact live worker PID/start/UID/source/argv/exe/ancestry/held FD and sole FLOCK before and after complete export')
  request,proof=from_values(value,prior,c,g,queue,parent)
  p.need(evidence['request']==request and evidence['producer']==before['worker']and evidence['source']==qref and evidence['RootAuthority']is False and evidence['closureOrLeaseReleaseClaimed']is False,'whole data-only export/request/source equality, no closure projection')
  evidence['independentWorkerProof']=after
  observations.update(totalSeconds=time.monotonic()-started,remainingSeconds=end-time.time());p.need(observations['remainingSeconds']>0,'original whole assignment effect clock remains valid')
  if metrics is not None:metrics.update(observations)
  result={'kind':'ROOT_CANONICAL_QUEUE_LIBVIRT_ASSIGNMENT_R4','request':request,'proof':proof,'queueExport':evidence,'source':'live canonical committed SQL-domain data, Root filesystem-only export resolver','runtimeAuthorized':False}
  if persist is not None:persist('queue-assignment',result)
  return result,value
 except BaseException as error:
  observations.update(readinessPolls=polls,totalSeconds=time.monotonic()-started,remainingSeconds=end-time.time(),archive=archive);error.assignmentIntakeEvidence=observations
  if metrics is not None:metrics.update(observations)
  raise

def revalidate_worker(expected,selected,persist=None):
 """Fresh exact-PID check after independently selecting the sole worker once."""
 need=p.need;process_snapshot=p.process_snapshot;process=p.process
 persist=(lambda *a:None)if persist is None else persist
 need(type(selected)is dict and type(selected.get('pid'))is int,'Previously selected actual worker identity')
 raw=process_snapshot(selected['pid']);actor=process(selected['pid'])
 need(actor==selected and actor['argv']==expected and actor['uid']==1000 and actor['pid']==actor['tgid']and raw['uids']==[1000]*4 and raw['pid']==actor['pid']and raw['start']==actor['start']and raw['ppid']==actor['ppid']and raw['argv']==expected and raw['cgroup']==actor['cgroup']and raw['tgid']==actor['tgid'],'Same fresh worker PID/start/UID/TGID/argv/cgroup/parent; no PID or role reuse')
 need(process_snapshot(actor['pid'])==raw,'Same worker full current identity after targeted check');persist('worker-targeted-revalidation',raw);return actor

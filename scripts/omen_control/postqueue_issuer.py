"""One delegated Root postqueue issuer; no domain/device/ACL effect.

The immutable public parent delegates only this closed binding procedure. No
future queue token, InvocationID or CPU allocation is supplied by the parent.
Live snapshot production is an independently reviewed prerequisite, not a
boolean this issuer can fabricate. Missing evidence times out before a grant.
"""
import copy,hashlib,json,os,stat,time,traceback,types,sys
from pathlib import Path
import libvirt_peer as p
import libvirt_producer as prod
import libvirt_preflight as pre
from libvirt_native import held,NativeTransactionOps
ROLES=__import__('source_contract').RUNTIME_ROLES

def protected(ref,mode=0o400,cap=1048576):
 i=ref['identity'];p.need(i['st_uid']==i['st_gid']==0 and stat.S_IMODE(i['st_mode'])==mode,'exact Root protected input mode')
 from libvirt_access import Held
 with Held(ref['path'])as h:
  p.need(h.check()==i,'protected ancestry/initial full9')
  raw=held(ref,cap);p.need(h.check()==i,'protected ancestry/final full9')
 return json.loads(raw)

def adopted_history(parent):
 """Authenticate every history leaf and the complete prior value before grant."""
 import base64,zlib
 ref=parent['priorHistoryCodecPin'];codec=protected(ref,cap=8388608)['value'];expected=parent['priorHistory']
 p.need(type(expected['bytes'])is int and 0<expected['bytes']<=64*1024**2,'unchanged whole history64MiB')
 if 'data'in codec:  # Immutable historical parents retain their original ABI.
  compressed=base64.b64decode(codec['data'],validate=True)
 else:
  p.need(set(codec)=={'kind','bytes','sha256','chunks'}and codec['kind']=='ROOT_PRIOR_HISTORY_CHUNKS_V1','typed complete history chunks')
  p.need(type(codec['bytes'])is int and 0<codec['bytes']<=expected['bytes']+65536 and type(codec['chunks'])is list and len(codec['chunks'])==(codec['bytes']+524287)//524288,'complete finite compressed history')
  parts=[];offset=0;names=set()
  for chunkref in codec['chunks']:
   path=Path(chunkref['path']);p.need(path.parent==Path(ref['path']).parent and path.name not in names,'same protected history namespace, unique leaves');names.add(path.name)
   part=protected(chunkref);p.need(set(part)=={'offset','data'}and type(part['offset'])is int and part['offset']==offset,'ordered complete history spans')
   data=base64.b64decode(part['data'],validate=True);p.need(len(data)==min(524288,codec['bytes']-offset),'complete history chunk length');parts.append(data);offset+=len(data)
  compressed=b''.join(parts);p.need(offset==codec['bytes']and hashlib.sha256(compressed).hexdigest()==codec['sha256'],'whole compressed history hash')
 decoder=zlib.decompressobj();raw=decoder.decompress(compressed,expected['bytes']+1)
 p.need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and len(raw)==expected['bytes']and hashlib.sha256(raw).hexdigest()==expected['sha256'],'exact full adopted prior history bytes')
 prior=json.loads(raw);p.need({k:len(v)for k,v in prior.items()}==expected['counts'],'exact adopted prior counts');return prior

def load(ref,name,cap):
 raw=held(ref,cap);m=types.ModuleType(name);m.__file__=ref['path'];sys.modules[name]=m
 try:exec(compile(raw,ref['path'],'exec'),m.__dict__)
 finally:sys.modules.pop(name,None)
 return m

def expected_spec(parent,parent_ref):
 # Two exact late slots avoid a parent->own SHA recursion. Every other final
 # normalized field is literal and equality checked; no field projection.
 spec=copy.deepcopy(parent['normalizedSpecTemplate'])
 p.need(spec['approval']=='EXACT_PARENT_MINIMAL_PIN'and spec['command'][-1]=='EXACT_PARENT_FULL_PIN_JSON','only declared late parent-pin slots')
 spec['approval']={k:parent_ref[k]for k in('path','bytes','sha256')}
 spec['command'][-1]=p.canon(parent_ref).decode()
 p.need(spec['command']==['sudo','-n','/usr/bin/python3','-B',parent['sourceRoles']['runtime_entry']['path'],'--parent-pin-json',p.canon(parent_ref).decode()],'one fixed Root entry command')
 p.need(spec['id']==parent['jobId']and spec['cores']==4 and spec['memory']==10737418240 and spec['timeout_seconds']==900 and p.GROUP in spec['resources'],'fixed job/resource scope')
 p.need(spec['libvirt_domain']=={'uuid':parent['candidate']['guestUUID'],'name':parent['candidate']['name'],'leaseNonce':parent['nonce'],'observer':{k:parent['sourceRoles']['libvirt_peer'][k]for k in('path','bytes','sha256')}},'exact domain/observer/lease scope')
 return spec

def submission_manifest(parent,parent_ref,base):
 """Exact raw CLI input from the already bound normalized parent template.

 This emits data only. The existing Root producer must supply the real parent,
 current source custody and admission; no Boolean or output grants hardware.
 """
 expected=expected_spec(parent,parent_ref);qref=parent['queuePrograms'][0];queue_sha=pre.paired_queue_sha(parent)
 p.need(qref['sha256']==queue_sha,'current exact paired queue before submit manifest')
 qraw=held(qref,1048576);p.need(hashlib.sha256(qraw).hexdigest()==queue_sha,'same full paired queue bytes')
 raw=copy.deepcopy(expected);raw['files']=[ref['path']for ref in expected['files']];raw['approval']={k:expected['approval'][k]for k in('path','sha256')};raw['libvirt_domain']['observer']=expected['libvirt_domain']['observer']['path']
 name='held_firstboot_submit_queue';p.need(name not in sys.modules,'no reused submit queue module');q=types.ModuleType(name);q.__file__=qref['path'];sys.modules[name]=q
 try:
  exec(compile(qraw,qref['path'],'exec'),q.__dict__)
  normalized=q.normalize_job(raw,Path(base))
  p.need(normalized==expected,'complete raw submit normalization equals exact parent expected spec; no field projection')
 finally:sys.modules.pop(name,None)
 p.need(held(qref,1048576)==qraw,'held/named paired queue unchanged after normalization')
 return raw

def bind_known_control_worker(known,verified,independent,qref,persist):
 """Join two independently measured full actors, retaining their core wire ABI.

 The export's worker is deliberately only pid/start/uid. Its workerLockProof
 retains the full actor and exact original FD/FLOCK. Never compare those two
 different shapes, or turn a core equality into full actor/source authority.
 Both unchanged producers must already have performed their native custody
 checks; this function does not replace them or authorize a grant/release.
 """
 fields=('jobId','unit','invocation','rowSHA256','worker','workerLockProof')
 record={'kind':'KNOWN_CONTROL_CANONICAL_WORKER_JOIN_BEFORE_PREDICATE_R238',
         'knownControl':{k:known.get(k)for k in fields[:4]}if type(known)is dict else known,
         'verifiedControl':{k:verified.get(k)for k in fields}if type(verified)is dict else verified,
         'independentWorkerProof':independent,'expectedQueueSource':qref}
 persist('known-control-worker-join-before-predicate',record)
 p.need(type(known)is dict and type(verified)is dict and type(independent)is dict and set(independent)=={'worker','argv','cgroup','workerLockProof','sourcePin'},'closed independently measured worker/source proof')
 core=independent['worker'];lock=independent['workerLockProof'];other=verified['workerLockProof']
 p.need(type(core)is dict and set(core)=={'pid','start','uid'}and type(lock)is dict and type(other)is dict,'separate core worker wire and full native lock proofs')
 worker=lock['worker']
 p.need(type(worker)is dict and set(worker)=={'pid','start','uid','tgid','ppid','argv','cgroup'}and core=={k:worker[k]for k in('pid','start','uid')}and worker['uid']==1000 and worker['tgid']==worker['pid'],'exact full actor with exact core projection')
 p.need(independent['argv']==worker['argv']and independent['cgroup']==worker['cgroup']and independent['sourcePin']==qref,'same independently measured argv/cgroup/full source pin')
 p.need(verified['worker']==worker==other['worker']and lock['verified']is True and other['verified']is True,'same two independently measured full worker actors')
 for key in('workerLockPin','workerLockMode','heldLockFDs','kernelFlocks'):
  p.need(lock[key]==other[key],'same original worker lock/full9/FD/FLOCK across native producers '+key)
 p.need(verified['jobId']==known['jobId']and verified['unit']==known['unit']and verified['invocation']==known['invocation']and verified['rowSHA256']==known['rowSHA256'],'same exact known control and independently authenticated canonical worker')
 return worker

class NativeIssueOps:
 MODEL_ONLY=False
 def __init__(self,parent,root):self.parent=parent;self.root=root;self.calls=[]
 def boot(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 def now(self):return time.time()
 def worker_guard(self,qref,parent):
  # Independent current PID/argv/exe/lock facts, never export header authority.
  p.need(qref==parent['queuePrograms'][0],'same adopted installed source pin')
  pre.measured(qref,1048576,False);expected=parent['workerArgv'];p.need(qref['path']in expected and expected[-1]=='run','exact canonical worker command, no inferred producer')
  selected=getattr(self,'_selected_worker',None)
  if selected is None:
   actor=p.select_worker(expected,getattr(self,'persist_worker',None));self._selected_worker=actor;self.worker_global_selections=getattr(self,'worker_global_selections',0)+1
  else:actor=__import__('queue_assignment').revalidate_worker(expected,selected,getattr(self,'persist_worker',None))
  fd=os.open('/proc/'+str(actor['pid'])+'/exe',os.O_RDONLY|os.O_CLOEXEC)
  try:p.need(p.ident(os.fstat(fd))==parent['workerPythonPin']['identity'],'same pinned worker Python executable')
  finally:os.close(fd)
  p.need(parent['workerStatePin']['path']==parent['queueStateRoot']and parent['workerLockPin']['path']==parent['queueStateRoot']+'/worker.lock','closed parent exact lock/state roles')
  proof=p.verify_worker_lock(parent['workerLockPin'],parent['workerStatePin'],parent['workerLockMode'],actor,getattr(self,'persist_worker',None))
  return {'worker':{k:actor[k]for k in('pid','start','uid')},'argv':actor['argv'],'cgroup':actor['cgroup'],'workerLockProof':proof,'sourcePin':qref}

 def assignment_export(self,c,g,parent,prior,end):
  import queue_assignment
  metrics={}
  try:result=queue_assignment.produce(c,g,parent,prior,None,self.worker_guard,end,metrics)
  except BaseException:
   self.assignment_intake_diagnostics=metrics;raise
  metrics['globalWorkerSelections']=getattr(self,'worker_global_selections',0)
  self.assignment_intake_diagnostics=metrics
  # No success-summary callback or report IO is part of intake.
  return result
 def check_prepared_disks(self,c,disks):
  # The retained immutable working role has an authenticated VM UID owner;
  # use its existing current custody/ACL/kernel-mount reader, never relax Held.
  from libvirt_access import held_disk
  for key in('original','working'):
   with held_disk(c,key,disks[key])as h:p.need(h.check()==disks[key]['identity'],'same held original/working post-ACL capture identity')

 def observe(self,parent,parent_ref,request,value,evidence,g):
  c=parent['candidate'];before=set(os.listdir('/proc/self/fd'));old=protected(parent['prequeuePreflightPin']);now=self.now()
  p.need(parent['sudoPin']is not None and parent['nativeTools']is not None,'actual sudo/native tool operands before grant')
  pre.measured(parent['sudoPin'],33554432)
  expected_tools={'/usr/bin/virt-xml-validate','/usr/bin/xmllint','/usr/sbin/losetup','/usr/bin/mount','/usr/bin/umount','/var/lib/opemos-vfio-idle-d3/modprobe','/var/lib/opemos-vfio-idle-d3/rmmod','/var/lib/opemos-vfio-idle-d3/managed_vfio.py'}
  p.need(set(parent['nativeTools'])==expected_tools,'closed exact native tool role set')
  for path,ref in parent['nativeTools'].items():p.need(ref['path']==path,'exact native tool path');pre.measured(ref,33554432)
  g.update(installedSchemaReceiptPin=parent.get('installedSchemaReceiptPin'),sudoPin=parent['sudoPin'],nativeTools=parent['nativeTools'])
  p.need(0<=now-old['observedUnix']<=30 and old['original']==c['original']and old['working']==parent['preparedDiskPins']['working']and old['preparedAccessPin']==parent['preparedAccessPin']and old['splitDiskCapturePins']==parent['splitDiskCapturePins'],'prequeue complete40GiB hashes remain original<=30s, never retimestamped')
  p.need(old['queuePrograms']==parent['queuePrograms']and old.get('abi')==pre.MACHINE_PREFLIGHT_ABI and old['privateHistory']['rawSHA256']==parent['priorHistory']['sha256'],'original prequeue proof/current prior history/machine preflight source')
  for ref in parent['queuePrograms']:pre.measured(ref,1048576,False)
  for ref in parent['sourceRoles'].values():pre.measured(ref,65536)
  self.check_prepared_disks(c,parent['preparedDiskPins'])
  from libvirt_access import verify_prepared
  verify_prepared(c,parent['preparedAccessPin'],parent['preparedDiskPins'])
  queue=load(parent['queuePrograms'][0],'postqueue_pool_queue',1048576)
  rows=[];bindings=dict(value['bindings'])
  for r in value['rows']:
   item=dict(r);item['_poolBinding']=json.loads(bindings[r['id']])if r['id']in bindings else None;rows.append(item)
  cfg=json.loads(value['config'][0][1]);backend=queue.SystemdBackend(Path(parent['queueStateRoot']),cfg)
  # Actual complete canonical pool proof admits just this service before any VM
  # exists. It also calls the unchanged Root readonly libvirt observer.
  pool=backend.validate_pool(rows);p.need(pool['admitted']is True and pool['unknownReservationsRetained']==[],'complete current pool/UID0/known invocation proof')
  expectedInvocations={request['unit']:request['invocation']}
  known=old.get('knownControl')
  if known is not None:
   p.need(known['unit']!=request['unit']and dict(value['bindings']).get(known['jobId'])==known['bindingRaw'],'exact unchanged separate known control keyed binding')
   priorValue={'rows':value['rows'][:-1],'bindings':[b for b in value['bindings']if b[0]!=request['jobId']],'config':value['config']}
   verified=pre.verify_control_live(priorValue,known['knownControlAdmission'],queue,parent['queuePrograms'][0],self.persist_worker,entry={'value':value,'request':request})
   bind_known_control_worker(known,verified,evidence['independentWorkerProof'],parent['queuePrograms'][0],self.persist_worker)
   expectedInvocations[known['unit']]=known['invocation']
  p.need(pool['knownInvocations']==expectedInvocations,'only exact current control plus own VM service reservations')
  qnative=load(parent['nativeReadOnlyPin'],'postqueue_existing_native',65536)
  p.need(parent['nativeReadOnlyPin']['sha256']=='fd1cc2b458394580a82d08cd5673f67ff6e5f026dbe94129b2950e867f1eebc4','exact existing readonly device guard')
  gpu=qnative.Devices().guards();fds=qnative.fd_inventory();p.need(fds['unknown']==fds['holders']==fds['QEMU']==[],'whole native host/VFIO/QEMU holder guard')
  # Derive expected logger/sudo solely from the exact pinned queue's launch
  # implementation, canonical stateRoot and immutable normalized job command.
  spec=json.loads(value['rows'][-1]['spec']);g['controllerArgv']=spec['command'][2:];g['sudoArgv']=spec['command'];g['loggerArgv']=['/usr/bin/python3',str(Path(parent['queuePrograms'][0]['path']).with_name('queue_job.py')),'--logs',str(Path(parent['queueStateRoot'])/'logs'/parent['jobId']),'--limit',str(queue.MAX_LOG),'--',*spec['command']]
  native=NativeTransactionOps(c,self.persist_worker);native.g=g;entry=native.current_entry(request)
  p.verify_historical_lease_set(parent['priorLeases'],value['rows'],value['bindings'],queue,self.boot())
  for path in parent['unusedPaths']:p.need(path not in(c['run'],c['output']),'prepared IO may not be claimed unused');p.need(not os.path.lexists(path),'unused domain/lease lane '+path)
  placement=p.storage_contract(c['nonce']);p.need(placement['outerAvailableBytes']>=72000000000,'literal60GB+20percent actual placement host storage')
  finalWorker=self.worker_guard(parent['queuePrograms'][0],parent)
  p.need(finalWorker==evidence['independentWorkerProof'],'same independently authenticated worker/lock after all native callbacks')
  finalValue,finalExport=queue.read_libvirt_assignment_export(parent['queueStateRoot'],parent['jobId'],finalWorker['worker'],parent['queuePrograms'][0],self.boot(),maximumAge=30)
  p.need(finalValue==value and finalExport=={k:v for k,v in evidence.items()if k!='independentWorkerProof'},'full immutable export reread after all native callbacks')
  p.need(native.current_entry(request)==entry,'final same original Root/logger/manager lineage after all blocking callbacks')
  p.need(before==set(os.listdir('/proc/self/fd')),'postqueue observer owned FDs closed')
  # Preserve original disk clock; current observation has its own distinct time.
  result={**old,'postqueueStoragePlacement':placement,'postqueueObservedUnix':self.now(),'postqueueAssignment':request,'queueAssignmentExport':evidence,'actualPoolProof':pool,'nativeGPUProof':gpu,'FDInventory':fds,'entry':entry,'wholeQueueConflictFree':True,'allOwnedFDsClosed':True}
  return result

def bind_placement(peer,parent,parent_ref,context=None):
 """Bind only the fresh protected same-source/same-scope metadata operand.
 Never changes the frozen peer's nonce, strict geometry or owner predicate.
 """
 nonce=parent['nonce'];roles=parent['sourceRoles'];candidate=parent['candidate']
 if 'operationContext'in candidate:__import__('source_contract').bind_scope(peer,parent)
 peer.need(peer.SOURCE_PLACEMENT_NONCE==nonce and candidate['nonce']==nonce and __import__('queue_assignment').execution_job(candidate,parent)==parent['jobId'],'D23 unused scope only; D22 is consumed')
 peer.need(parent['RootIssued']is True and parent['kind']=='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT'and parent['bootID']==candidate['hostBoot']and parent_ref['path']==__import__('source_contract').parent_paths(parent)['parentPath'],'existing exact Root parent/boot/source scope')
 peer.need(set(roles)==__import__('source_contract').RUNTIME_ROLES,'closed twelve-role binding')
 __import__('source_contract').validate(roles,parent['queuePrograms'],parent['installedSourceContractPin'])
 ref=parent['sourcePlacementPin'];qr=parent['placementQualificationPin'];root=str(__import__('retained_media').placement_for_candidate(candidate))
 peer.need(ref['path']==root+'/storage-contract.json'and qr['path']==root+'/placement-qualified.json','fresh exact placement+qualification names, no historical receipt')
 files=peer.RootFiles(root);primary=None;result=None
 try:
  files.__enter__()
  raw,actual=files.read('storage-contract.json');qualified,qactual=files.read('placement-qualified.json');peer.need(actual==ref and qactual==qr,'fresh placement/qualification exact full9/EOF/SHA')
  value=json.loads(raw);q=json.loads(qualified);b=value['preparationBinding']
  peer.need(value['kind']==('ROOT_EXACT_STEAMOS_INSTALLER_GAMES_PLACEMENT'if candidate.get('installer')is not None else'ROOT_EXACT_STEAMOS_FIXED_GAMES_PLACEMENT')and value['nonce']==nonce and value['boot']==parent['bootID']and value['original']==candidate['original']and value['working']==candidate['working']and value.get('installer')==candidate.get('installer'),'same current prepared working placement, no relabel')
  peer.need(b['sourceRoles']==roles and b['queuePrograms']==parent['queuePrograms']and b['sourceGraphSHA256']==hashlib.sha256(peer.canon(roles)).hexdigest(),'placement producer source12/current queue equality')
  peer.need(q['kind']=='ROOT_VERIFIED_FRESH_STEAMOS_PLACEMENT'and q['qualifiedPlacementPin']==ref and q['nonce']==nonce and q['bootID']==parent['bootID']and q['sourceRoles']==roles and q['queuePrograms']==parent['queuePrograms']and q['runtimeAuthorized']is False and q['RootIssuedRuntimeAuthority']is False,'complete fresh protected metadata qualification, not a runtime grant')
  pre=q['currentPreflight'];prepared=parent['preparedDiskPins'];access_pin=parent['preparedAccessPin']
  peer.need(type(prepared)is dict and set(prepared)=={'original','working'}and prepared['original']==candidate['original']and b['preparedDiskPins']==prepared and access_pin is not None and b['preparedAccessPin']==access_pin==pre['preparedAccessPin']and b['splitDiskCapturePins']==parent['splitDiskCapturePins']==pre['splitDiskCapturePins'],'exact candidate/pending-access/post-ACL prepared captures/final-preflight lineage')
  work=prepared['working'];before_work=candidate['working'];peer.need(work['path']==before_work['path']and work['bytes']==before_work['bytes']and work['sha256']==before_work['sha256']and all(work['identity'][k]==before_work['identity'][k]for k in('st_dev','st_ino','st_uid','st_gid','st_nlink','st_size','st_mtime_ns')),'same content and stable pre/post ACL working object; full9 remains exact within each epoch')
  from libvirt_access import verify_prepared
  verify_prepared(candidate,access_pin,prepared)
  peer.need(q['currentPreflightPin']==parent['prequeuePreflightPin']and pre['bootID']==parent['bootID']and pre['storagePlacement']['receiptPin']==ref and pre['queuePrograms']==parent['queuePrograms']and pre['original']==candidate['original']and pre['kind']=='ACTUAL_LIBVIRT_R4_CURRENT_PREFLIGHT'and pre['working']==prepared['working']and 0<=parent['issuedUnix']-pre['observedUnix']<=30,'existing normal complete current preflight joins placement before parent issuance')
  if context is not None:peer.need(context['parentPin']==parent_ref and context['candidate']==candidate and context['sourceRoles']==roles and context['sourcePlacementPin']==ref and context['placementQualificationPin']==qr,'context/parent/source12/placement equality')
  peer.need(peer.SOURCE_PLACEMENT_PIN is None or peer.SOURCE_PLACEMENT_PIN==ref,'never replace a different bound placement operand')
  again,again_pin=files.read('storage-contract.json');again_q,again_qpin=files.read('placement-qualified.json');peer.need((again,again_pin)==(raw,ref)and(again_q,again_qpin)==(qualified,qr),'original held/named placement and qualification full9/raw-SHA unchanged after prepared verification')
  result={'placementPin':ref,'qualificationPin':qr,'sourceGraphSHA256':b['sourceGraphSHA256'],'runtimeAuthorityIssued':False}
 except BaseException as error:primary=error
 finally:
  try:files.__exit__(None if primary is None else type(primary),primary,None)
  except BaseException as close:
   if primary is None:primary=close
   else:primary.ownedPlacementCloseErrors=getattr(primary,'ownedPlacementCloseErrors',[])+[{'role':'bind-placement-ancestors','type':type(close).__name__,'reason':str(close)}]
 if primary is not None:raise primary
 peer.SOURCE_PLACEMENT_PIN=ref
 return result

def publish_runtime_leaf(files,parent,parent_ref,label,value,end,ops):
 from libvirt_access import publish_runtime
 return publish_runtime(files,parent,parent_ref,label+'.json',value,time.monotonic()+max(0,end-ops.now()))

def persist_issue_first(files,parent,parent_ref,first,secondary,outputs,failed_publication=None):
 from libvirt_access import publish_runtime_first
 return publish_runtime_first(files,parent,parent_ref,{'first':first,'secondary':secondary,'outputs':outputs,'failedPublication':failed_publication,'diagnosticOnly':True,'grantAccepted':False,'hardwareEffects':[],'retainLease':True})

def record_issue_failure(files,parent,parent_ref,error,outputs):
 """Preserve original failure/effects before a diagnostic-only append."""
 for ref in getattr(error,'runtimePublicationEffects',[]):
  if ref not in outputs:outputs.append(ref)
 first={'type':type(error).__name__,'reason':str(error),'traceback':traceback.format_exc(),'evidence':getattr(error,'evidence',None),'publication':getattr(error,'runtimePublication',None)}
 secondary=list(getattr(error,'secondary',[]));receipt=None
 try:
  receipt=persist_issue_first(files,parent,parent_ref,first,secondary,outputs,getattr(error,'runtimePublication',None));outputs.append(receipt)
 except BaseException as close:secondary.append({'type':type(close).__name__,'reason':str(close),'publication':getattr(close,'runtimePublication',None),'effects':getattr(close,'runtimePublicationEffects',[]),'evidence':getattr(close,'evidence',None)})
 if secondary:error.secondary=secondary
 result={'first':first,'secondary':secondary,'outputs':outputs,'FIRSTPin':receipt,'grantAccepted':False,'hardwareEffects':[],'retainLease':True}
 error.postqueueFailureRecord=result
 return result

class PublicationEvidence:
 """Each EX publication is a complete ancestry scope, retained after unlock/close.
 The Root parent supplies a fresh private evidence capability, never runtime or
 grant authority. Original per-scope caps and original clocks stay unchanged.
 """
 def __init__(self,parent,parent_ref):
  self.parent=parent;self.parent_ref=parent_ref;self.root=__import__('source_contract').parent_paths(parent)['runtimeRoot'];self.previous=None
  self.anchor=p.RootFiles(self.root);self.anchor.__enter__();self.closed=False
 def guard_anchor(self,files):
  value={'kind':'ROOT_ORIGINAL_PUBLISHER_FD_LIFETIME_R270','namespace':os.readlink('/proc/self/ns/mnt'),'originalRun':self.anchor.run_row(self.anchor.runFD),'runtimeHeld':p.ident(os.fstat(self.anchor.fd)),'runtimeNamed':p.ident(os.lstat(self.root)),'phaseRuntime':p.ident(os.fstat(files.fd)),'ancestry':[]}
  for path,fd,initial in self.anchor.chain:
   value['ancestry'].append({'path':str(path),'fd':fd,'held':p.ident(os.fstat(fd)),'named':p.ident(os.lstat(path)),'birthCore':initial})
  try:
   p.need(not self.closed and value['runtimeHeld']==value['runtimeNamed']==value['phaseRuntime'],'same original held/named publisher runtime full9')
   birth=self.anchor.runBirth;run=value['originalRun'];p.need(run==dict(birth,identity=run['identity'])and all(run['identity'][k]==birth['identity'][k]for k in p.FIELDS[:5])and value['namespace']==files.runProof['namespace']==self.anchor.runProof['namespace']and files.runBirth['mountID']==birth['mountID']and files.runProof['mountRow']==self.anchor.runProof['mountRow'],'original held run FD/flags/mount/namespace across closed phases')
   for row in value['ancestry']:
    keys=p.FIELDS[:5]if row['path']=='/run'else p.CORE
    p.need(all(row['held'][k]==row['named'][k]==row['birthCore'][k]for k in keys),'original publisher ancestor FD/name/core lifetime')
   return value
  except BaseException as error:error.evidence=value;raise
 def close(self,primary=None,outputs=None):
  try:self.anchor.__exit__(None if primary is None else type(primary),primary,None if primary is None else primary.__traceback__)
  except BaseException as error:
   if primary is None:raise
   primary.secondary=list(getattr(primary,'secondary',[]))+[{'stage':'actual-publisher-FD-close','error':p.error_value(error),'knownClosed':False}]
   if hasattr(primary,'postqueueFailureRecord'):primary.postqueueFailureRecord['secondary']=primary.secondary
  finally:self.closed=True
 def publish(self,name,value,end,ops,diagnostic=False):
  files=p.RootFiles(self.root);result=None
  with files:
   self.guard_anchor(files)
   result=persist_issue_first(files,self.parent,self.parent_ref,value['first'],value['secondary'],value['outputs'],value.get('failedPublication'))if diagnostic else publish_runtime_leaf(files,self.parent,self.parent_ref,name,value,end,ops)
   self.guard_anchor(files)
  if not diagnostic:p.need(ops.now()<end,'original issuer deadline after actual publication and FD closure')
  return result

 def failure(self,error,outputs,end,ops):
  for ref in getattr(error,'runtimePublicationEffects',[]):
   if ref not in outputs:outputs.append(ref)
  first={'type':type(error).__name__,'reason':str(error),'traceback':traceback.format_exc(),'evidence':getattr(error,'evidence',None),'publication':getattr(error,'runtimePublication',None),'phaseRetention':getattr(error,'publicationEvidenceFailure',None)}
  secondary=list(getattr(error,'secondary',[]));receipt=None
  try:receipt=self.publish('FIRST-postqueue-issuer',{'first':first,'secondary':secondary,'outputs':outputs,'failedPublication':getattr(error,'runtimePublication',None)},end,ops,True);outputs.append(receipt)
  except BaseException as close:secondary.append({'type':type(close).__name__,'reason':str(close),'evidence':getattr(close,'evidence',None),'phaseRetention':getattr(close,'publicationEvidenceFailure',None),'effects':getattr(close,'runtimePublicationEffects',[])})
  error.secondary=secondary;error.postqueueFailureRecord={'first':first,'secondary':secondary,'outputs':outputs,'FIRSTPin':receipt,'phaseEvidenceHead':self.previous,'grantAccepted':False,'hardwareEffects':[],'retainLease':True}
  return error.postqueueFailureRecord


def bind_current_preflight(g,parent,parent_ref,observed,proof_pin,assignment_pin,export_evidence,request,row,now,end,model_only):
 """Bind the actual immutable machine observation to the exact queue grant.

 No AI-owner receipt exists in this contract. This data operation cannot create
 a domain, assign a device, mutate a disk or supply source-adoption authority.
 """
 p.need(type(model_only)is bool and not {'ownersPin','ownersObservedUnix','cohort','selfThreadId'}&set(parent) and not {'ownersPin','ownersObservedUnix'}&set(g),'current machine grant has no AI orchestration fields')
 i=proof_pin['identity'];p.need(i['st_uid']==i['st_gid']==0 and stat.S_IMODE(i['st_mode'])==0o400 and i['st_nlink']==1,'protected actual immutable preflight')
 # The producer publishes canonical JSON. Bind every emitted byte before
 # reading its wire representation; native tuple/list distinctions confer no
 # grant authority and must not reject the producer's own complete proof.
 raw=held(proof_pin,1048576)
 p.need(raw==p.canon(observed),'whole emitted canonical preflight bytes equal held proof')
 observed=json.loads(raw)
 pre.require_phase_result(observed,'INSTALLER_BOOT_READY',parent['preparedAccessPin'])
 p.need(observed['bootID']==parent['bootID'] and 0<=now-observed['observedUnix']<=30 and observed['queuePrograms']==parent['queuePrograms'] and observed['splitDiskCapturePins']==parent['splitDiskCapturePins'] and observed['working']==parent['preparedDiskPins']['working'] and observed['original']==parent['preparedDiskPins']['original'],'complete fresh machine proof/parent/queue/disk joins')
 p.need(row['id']==parent['jobId']==request['jobId'] and row['unit']==request['unit'] and row['started']<=now<end<=parent['startBeforeUnix'],'actual original admitted row/request/finite effect clocks')
 g=dict(g)
 g.update(workerLockPin=parent['workerLockPin'],workerStatePin=parent['workerStatePin'],workerLockMode=parent['workerLockMode'],preparedAccessPin=parent['preparedAccessPin'],preparedDiskPins=parent['preparedDiskPins'],splitDiskCapturePins=parent['splitDiskCapturePins'],RootIssued=True,MODEL_ONLY=model_only,runtimeAuthorized=not model_only,parentPin=parent_ref,assignmentPin=assignment_pin,currentPreflightPin=proof_pin,preflightObservedUnix=observed['observedUnix'],preflightABI=pre.MACHINE_PREFLIGHT_ABI,queueAssignmentExport=export_evidence,privateHistory=observed['privateHistory'],queuePrograms=parent['queuePrograms'],issuedUnix=now,startBeforeUnix=min(end,parent['startBeforeUnix']),wholeDeadlineUnix=min(parent['wholeDeadlineUnix'],row['started']+900),cpus=request['cpus'])
 return g



def _issue(parent_ref,ops=None):
 """Runs inside the exact Root queue entry; does not enqueue or touch hardware."""
 parent=protected(parent_ref,0o444);root=__import__('source_contract').parent_paths(parent)['runtimeRoot'];before=set(os.listdir('/proc/self/fd'));first=None;secondary=[];outputs=[]
 p.need(parent['kind']=='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT'and parent['RootIssued']is True and parent['postqueueDelegation']=='ROOT_EXACT_CANONICAL_BINDING_ONLY_R5','separate immutable Root delegation')
 p.need(parent_ref['path']==__import__('source_contract').parent_paths(parent)['parentPath']and parent['contextPath']==root+'/context.json','exact parent/runtime names')
 if 'operationContext'in parent['candidate']:__import__('source_contract').bind_scope(p,parent)
 else:__import__('source_contract').validate(parent['sourceRoles'],parent['queuePrograms'],parent['installedSourceContractPin'])
 __import__('guest_firmware_probe').require_firstboot_only(parent['candidate'])
 p.need(set(parent['sourceRoles'])==ROLES and all(Path(ref['path']).name==role+'.py'for role,ref in parent['sourceRoles'].items()),'closed twelve-role reviewed source graph')
 p.need(parent['noNIC']is True and parent['noInstall']is True and parent['maxBoots']==1 and parent['failureControl']=='LIBVIRT_AUTODESTROY_CONTROLLER_CONNECTION','unchanged narrow scope')
 ops=ops or NativeIssueOps(parent,root);now=ops.now();p.need(os.getuid()==0 and parent['bootID']==ops.boot()and parent['issuedUnix']<=now<parent['startBeforeUnix']<=parent['issuedUnix']+300,'Root same boot finite actual authority')
 p.need(parent.get('MODEL_ONLY')is ops.MODEL_ONLY,'no model-to-live promotion')
 bind_placement(p,parent,parent_ref)
 end=min(now+30,parent['startBeforeUnix']);spec=expected_spec(parent,parent_ref)
 # This issuer and external snapshot writer share a precreated Root0700 capsule;
 # no polling of foreign/unprotected arbitrary paths, no overwrite/rearm.
 publication_owner=PublicationEvidence(parent,parent_ref)
 def save(label,v):
  try:pin=publication_owner.publish(label,v,end,ops)
  except BaseException as error:
   for ref in getattr(error,'runtimePublicationEffects',[]):
    if ref not in outputs:outputs.append(ref)
   raise
  outputs.append(pin);return pin
 worker_events=[]
 def worker_save(label,value):
  # Bounded diagnostics may be omitted; they cannot veto a real worker proof.
  if len(worker_events)<32:worker_events.append({'label':label,'value':value})
 ops.persist_worker=worker_save
 try:
  p.need(not os.path.lexists(root+'/context.json')and not os.path.lexists(root+'/child-grant.json'),'one-use context/grant absent')
  save('issuer-start',{'actor':p.process(os.getpid()),'startedUnix':now,'parentPin':parent_ref,'hardwareEffects':[]})
  # Full immutable accepted prior bytes; counts are data-derived, not37/33.
  expected=parent['priorHistory'];prior=adopted_history(parent)
  import queue_assignment
  queue=queue_assignment.load_queue(parent['queuePrograms'][0],parent);digest=hashlib.sha256(queue.canonical(spec).encode()).hexdigest();g=copy.deepcopy(parent['childGrantTemplate']);c=parent['candidate']
  g.update(installerContract=c.get('installer'),sourcePlacementPin=parent['sourcePlacementPin'],placementQualificationPin=parent['placementQualificationPin'],jobId=parent['jobId'],domainName=c['name'],domainUUID=c['guestUUID'],leaseNonce=c['nonce'],bootID=parent['bootID'],normalizedSpecSHA256=digest,observerPin=spec['libvirt_domain']['observer'],originalPin=c['original'],workingPin=c['working'],guestUUID=c['guestUUID'],firmwareCodePin=c['firmwareCode'],producerPin=parent['sourceRoles']['libvirt_producer'],peerPin=parent['sourceRoles']['libvirt_peer'],accessPin=parent['sourceRoles']['libvirt_access'],nativePin=parent['sourceRoles']['libvirt_native'],historyReaderPin=parent['sourceRoles']['held_history_reader'],queuePrograms=parent['queuePrograms'],priorHistorySHA256=expected['sha256'],priorHistoryBytes=expected['bytes'],priorHistoryCounts=expected['counts'])
  assignment,value=ops.assignment_export(c,g,parent,prior,end);p.need(ops.now()<end,'whole entry30s includes genuine postlaunch export')
  p.need(json.loads(value['rows'][-1]['spec'])==spec,'entire late-parent reconstructed normalized spec equality')
  request=assignment['request'];export_evidence=assignment['queueExport'];row=value['rows'][-1];ap=save('assignment',assignment)
  observed=ops.observe(parent,parent_ref,request,value,export_evidence,g);p.need(ops.now()<end,'entry30s includes all current native checks')
  pp=save('postqueue-preflight',observed);now=ops.now();p.need(0<=now-observed['observedUnix']<=30,'original complete hash clock before grant')
  # Fresh fields only from actual canonical binding/request + observations.
  g=bind_current_preflight(g,parent,parent_ref,observed,pp,ap,export_evidence,request,row,now,end,ops.MODEL_ONLY)
  p.need(g['wholeDeadlineUnix']>now and g['wholeDeadlineUnix']<=row['started']+900,'no job deadline extension')
  prod.require_grant({**g,'runtimeAuthorized':True},request,parent['candidate'],ops.boot())
  gp=save('child-grant',g)
  context={'sourcePlacementPin':parent['sourcePlacementPin'],'placementQualificationPin':parent['placementQualificationPin'],'kind':'ROOT_LIBVIRT_R4_RUNTIME_CONTEXT','runtimeAuthorized':not ops.MODEL_ONLY,'MODEL_ONLY':ops.MODEL_ONLY,'parentPin':parent_ref,'candidate':parent['candidate'],'sourceRoles':parent['sourceRoles'],'grantPin':gp,'assignmentPin':ap,'guestParserPin':parent['sourceRoles']['two_boot_contract'],'guestContract':parent['guestContract']}
  p.need(protected(parent_ref,0o444)==parent,'unchanged authority at final boundary');cp=save('context',context)
  return cp
 except BaseException as e:
  first=e
  evidence={'workerObservations':worker_events,'globalWorkerSelections':getattr(ops,'worker_global_selections',0),'intake':getattr(e,'assignmentIntakeEvidence',getattr(ops,'assignment_intake_diagnostics',None)),'optionalReportError':getattr(ops,'assignment_diagnostic_error',None)}
  old_evidence=getattr(e,'evidence',None);e.evidence={'primaryEvidence':old_evidence,'assignmentIntake':evidence}
  publication_owner.failure(e,outputs,end,ops)
  raise
 finally:
  publication_owner.close(first,outputs)
  if first is None:
   try:p.need(ops.now()<end,'original issuer deadline includes owner-close retention')
   except BaseException as error:
    error.postqueueFailureRecord={'first':p.error_value(error),'secondary':[],'outputs':outputs,'FIRSTPin':None,'phaseEvidenceHead':publication_owner.previous,'grantAccepted':False,'hardwareEffects':[],'retainLease':True};raise


def issue(parent_ref,ops=None):
 before=set(os.listdir('/proc/self/fd'))
 try:return _issue(parent_ref,ops)
 finally:p.need(before==set(os.listdir('/proc/self/fd')),'postqueue issuer all owned FDs closed')

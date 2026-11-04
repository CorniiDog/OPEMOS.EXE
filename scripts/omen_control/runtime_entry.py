"""Exact Root queue entry: disabled until real protected context/grant exists.

No queue enqueue, permission exception, source deployment or binding is issued.
Canonical queue owns the row/unit/invocation and separately supplies the approved
same-host private assignment. Parent runtime orchestrator must bind these pins.
"""
import contextlib,hashlib,json,os,stat,sys,time,traceback
from pathlib import Path
import libvirt_peer as peer
import libvirt_producer as producer
from libvirt_native import held,NativeTransactionOps,bootstrap_event_driver,event_driver_fd_changes,close_event_driver_anchor

def finish_entry_fds(result,initial,driver,persist):
 """Retain transaction primary and exact FD/anchor failures in one terminal."""
 primary=result.get('first');errors=[];final=None;difference=None;anchor=None
 try:
  final=peer.fd_snapshot('Root-entry-transaction-final')
  difference=event_driver_fd_changes(driver,initial,final)
  peer.need(not any(difference['changes'].values()),'all Root entry transaction owned FDs closed')
 except BaseException as error:
  errors.append(peer.error_value(error))
 try:anchor=close_event_driver_anchor(driver,persist)
 except BaseException as error:errors.append(peer.error_value(error))
 value={'before':initial,'after':final,'comparison':difference,'anchorClosure':anchor,'processLifetimeEventDriver':driver,'resultFirst':primary,'FDClosureErrors':errors}
 try:persist('Root-entry-FD-closure',value)
 except BaseException as error:errors.append(peer.error_value(error))
 if errors:
  if primary is None:result['first']=errors[0]
  result['secondary']=list(result.get('secondary',[]))+[{'stage':'Root-entry-FD-closure','primaryPreserved':primary,'errors':errors}]
  result['accepted']=False;result['leaseMustRemainHeld']=True
 result['entryFDClosure']={'known':not errors,'ownedAnchorClosed':bool(anchor and anchor['anchorClosed']),'globalDriverRequiresOriginalRootReap':True,'errors':errors}
 return not errors

def emit_issuer_cap_summary(error,parent_ref,record,detail):
 """Bounded production custody summary; full over-cap record stays unavailable."""
 raw=None;written=0
 try:
  first=record.get('first');publication=first.get('publication')if type(first)is dict else None
  value={'kind':'ROOT_POSTQUEUE_ISSUER_CAP_SUMMARY_R205','stage':'await_root_context/postqueue_issuer/fallback-cap','parentPin':parent_ref,'actor':peer.process(os.getpid()),'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'primary':{'type':type(error).__name__,'reason':str(error)},'primaryPreserved':True,'diagnosticFirstSecondary':record.get('secondary'),'partialOutputs':record.get('outputs'),'failedPublication':publication,'FIRSTPin':record.get('FIRSTPin'),'fullRecordSHA256':detail['fullSHA256'],'fullRecordBytes':detail['expectedBytes'],'completeRecordUnavailable':True,'rawFallbackWrittenBytes':detail['writtenBytes'],'capRefusal':detail,'numericExit':None,'diagnosticOnly':True,'grantAccepted':False,'hardwareEffects':[],'retainLease':True}
  raw=peer.canon(value)+b'\n';peer.need(len(raw)<=1048576,'original1MiB whole cap-summary output bound')
  while written<len(raw):
   n=os.write(2,raw[written:]);peer.need(n>0,'positive cap-summary output write');written+=n
  error.postqueueFallbackSummary={'stream':'stderr','bytes':written,'sha256':hashlib.sha256(raw).hexdigest(),'completeSummary':True,'completeRecordUnavailable':True,'durabilityRequiresNormalQueueCapture':True}
 except(OSError,ValueError,TypeError,peer.Refused)as output:
  secondary={'type':type(output).__name__,'reason':str(output),'writtenBytes':written,'expectedBytes':None if raw is None else len(raw),'fullSHA256':None if raw is None else hashlib.sha256(raw).hexdigest(),'UNKNOWN':True}
  error.secondary=list(getattr(error,'secondary',[]))+[{'stage':'normal-entry-FIRST-cap-summary-output','failure':secondary}]
  error.add_note('Normal-entry FIRST cap summary incomplete/UNKNOWN: '+repr(secondary)[:2048])

def emit_issuer_first_fallback(error,parent_ref,record):
 """Normal queue stderr capture owns durability; no runtime/close authority."""
 raw=None;written=0
 try:
  try:fd={'known':True,'snapshot':peer.fd_snapshot('Root-entry-issuer-FIRST-fallback')}
  except(OSError,ValueError)as capture:fd={'known':False,'first':peer.error_value(capture)}
  value={'kind':'ROOT_POSTQUEUE_ISSUER_FIRST_FALLBACK_R203','stage':'await_root_context/postqueue_issuer','parentPin':parent_ref,'actor':peer.process(os.getpid()),'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'failureRecord':record,'numericExit':None,'numericDisposition':'Original exception still propagating; actual numeric/reap/EOF belongs to queue capture','FDObservation':fd,'diagnosticOnly':True,'grantAccepted':False,'hardwareEffects':[],'retainLease':True}
  raw=peer.canon(value)+b'\n';peer.need(len(raw)<=1048576,'original1MiB whole fallback output bound')
  while written<len(raw):
   n=os.write(2,raw[written:]);peer.need(n>0,'positive fallback output write');written+=n
  error.postqueueFallbackOutput={'stream':'stderr','bytes':written,'sha256':hashlib.sha256(raw).hexdigest(),'complete':True,'durabilityRequiresNormalQueueCapture':True}
 except(OSError,ValueError,TypeError,peer.Refused)as output:
  detail={'type':type(output).__name__,'reason':str(output),'writtenBytes':written,'expectedBytes':None if raw is None else len(raw),'fullSHA256':None if raw is None else hashlib.sha256(raw).hexdigest(),'UNKNOWN':True}
  error.postqueueFallbackOutputError=detail;error.secondary=list(getattr(error,'secondary',[]))+[{'stage':'normal-entry-FIRST-fallback-output','failure':detail}]
  error.add_note('Normal-entry FIRST fallback output incomplete/UNKNOWN: '+repr(detail)[:2048])
  if isinstance(output,peer.Refused)and str(output)=='original1MiB whole fallback output bound'and raw is not None and written==0:
   emit_issuer_cap_summary(error,parent_ref,record,detail)

@contextlib.contextmanager
def issuer_first_fallback_output(parent_ref):
 """Only the exact failed protected-FIRST path; original exception is unaltered."""
 completed=False
 try:
  yield;completed=True
 finally:
  error=None if completed else sys.exception();record=getattr(error,'postqueueFailureRecord',None)
  if type(record)is dict and record.get('FIRSTPin')is None:
   emit_issuer_first_fallback(error,parent_ref,record)

def await_root_context(parent_ref):
 """Prequeue public parent -> postqueue exact Root context, no future hash.

 The independently running Root producer supplies actual assignment/grant after
 canonical enqueue. This entry never issues either one. The finite parent is
 queue approval; the context and child grant are later Root-only measurements.
 """
 from libvirt_access import Held
 # Exact reviewed Root issuer runs in this current queue process, not a future
 # separately timed producer. No context is consumed until the full issue joins.
 parent_header=json.loads(held(parent_ref,1048576))
 if parent_header.get('postqueueDelegation')=='ROOT_EXACT_CANONICAL_BINDING_ONLY_R5':
  import postqueue_issuer
  with issuer_first_fallback_output(parent_ref):
   return postqueue_issuer.issue(parent_ref)
 peer.need(parent_ref['identity']['st_uid']==parent_ref['identity']['st_gid']==0 and stat.S_IMODE(parent_ref['identity']['st_mode'])==0o444,'actual Root public approval parent')
 raw=held(parent_ref,1048576);parent=json.loads(raw)
 peer.need(parent_ref['path']=='/run/opemos-libvirt-parent-'+parent['nonce']+'.json','exact prequeue parent namespace')
 peer.need(parent['kind']=='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT'and parent['RootIssued']is True and parent['MODEL_ONLY']is not True,'separate real Root prequeue parent')
 peer.need(parent['failureControl']=='LIBVIRT_AUTODESTROY_CONTROLLER_CONNECTION'and parent['noInstall']is True and parent['noNIC']is True and parent['maxBoots']==1,'exact no-install two-boot scope')
 peer.need(parent['issuedUnix']<=time.time()<parent['startBeforeUnix']<=parent['issuedUnix']+300,'finite Root parent, no self refresh')
 peer.need(parent['bootID']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'same actual Root parent host boot')
 expected='/run/opemos-libvirt-runtime-'+parent['nonce']+'/context.json';peer.need(parent['contextPath']==expected,'one exact postqueue protected context name')
 end=min(parent['startBeforeUnix'],time.time()+30)
 while time.time()<end:
  peer.need(held(parent_ref,1048576)==raw,'unchanged Root approval while waiting')
  try:
   with Held(expected)as obj:
    st=obj.check();peer.need(stat.S_ISREG(st['st_mode'])and st['st_uid']==st['st_gid']==0 and stat.S_IMODE(st['st_mode'])==0o400 and st['st_nlink']==1 and st['st_size']<=1048576,'protected create-only postqueue context')
    value=os.read(obj.fd,1048577);peer.need(len(value)<=1048576 and not os.read(obj.fd,1)and obj.check()==st,'whole context EOF/full9')
   context=json.loads(value);peer.need(context['parentPin']==parent_ref and context['candidate']['nonce']==parent['nonce']and __import__('queue_assignment').execution_job(context['candidate'],parent)==parent['jobId']and context['candidate']['hostBoot']==parent['bootID']and context['sourceRoles']==parent['sourceRoles'],'Root current context joins actual prequeue authority scope')
   return {'path':expected,'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest(),'identity':st}
  except FileNotFoundError:time.sleep(.05)
 raise peer.Refused('postqueue Root assignment/context not supplied within exact finite window; no GPU/domain effect')

def bind_placement(peer,parent,parent_ref,context=None):
 """Bind only the fresh protected same-source/same-scope metadata operand.
 Never changes the frozen peer's nonce, strict geometry or owner predicate.
 """
 nonce=parent['nonce'];roles=parent['sourceRoles'];candidate=parent['candidate']
 peer.need(nonce=='cd9ef0826364409da287f6f3e3830c95'and peer.SOURCE_PLACEMENT_NONCE==nonce and candidate['nonce']==nonce and __import__('queue_assignment').execution_job(candidate,parent)==parent['jobId'],'D23 unused scope only; D22 is consumed')
 peer.need(parent['RootIssued']is True and parent['kind']=='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT'and parent['bootID']==candidate['hostBoot']and parent_ref['path']=='/run/opemos-libvirt-parent-'+nonce+'.json','existing exact Root parent/boot/source scope')
 __import__('source_contract').validate(roles,parent['queuePrograms'],parent['installedSourceContractPin'])
 ref=parent['sourcePlacementPin'];qr=parent['placementQualificationPin'];root='/run/opemos-steamos-placement-'+nonce
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

def capture_binding(context,parent,g,request):
 c=context['candidate'];roles=context['sourceRoles']
 peer.need(parent['candidate']==c and parent['sourceRoles']==roles and parent['queuePrograms']==g['queuePrograms']and parent['actualInstalledQueueFull9']==g['queuePrograms'][0],'exact existing parent/source12/current queue capture provenance')
 peer.need(c['nonce']==parent['nonce']==request['leaseNonce']and __import__('queue_assignment').execution_job(c,parent)==parent['jobId']==request['jobId']and c['hostBoot']==parent['bootID']and g['normalizedSpecSHA256']==request['specSHA256'],'capture belongs only to exact new canonical job/nonce/boot/spec')
 return {'kind':'ROOT_CONTEXT_BOUND_DAC_FD_CAPTURE','nonce':c['nonce'],'jobId':parent['jobId'],'bootID':c['hostBoot'],'parentManifestPin':context['parentPin'],'sourceRoles':roles,'sourceGraphSHA256':hashlib.sha256(peer.canon(roles)).hexdigest(),'queuePrograms':g['queuePrograms'],'normalizedSpecSHA256':request['specSHA256'],'diagnosticOnly':True}

def operational_complete(result, fds_closed):
    """A closed installer observation can succeed without full installation."""
    closure = result.get('closure', {})
    return bool(
        fds_closed is True
        and result.get('MODEL_ONLY') is False
        and result.get('first') is None
        and result.get('runtimeAuthorized') is True
        and result.get('leaseMustRemainHeld') is False
        and closure.get('known') is True
        and closure.get('FDsClosed') is True
        and closure.get('logicalLeaseClosed') is True
        and (result.get('accepted') is True
             or result.get('installerDiagnosticComplete') is True)
    )

def validate_context_sources(context):
 peer.need(set(context['sourceRoles'])==__import__('source_contract').RUNTIME_ROLES,'complete installed current source graph')
 for name,ref in context['sourceRoles'].items():
  peer.need(ref['path']==str(Path(__file__).parent/(name+'.py')),'exact same staged source bundle path')
  peer.need(ref['identity']['st_uid']==ref['identity']['st_gid']==0 and stat.S_IMODE(ref['identity']['st_mode'])==0o444,'Root immutable source role');compile(held(ref,65536),ref['path'],'exec')
 return context['sourceRoles']

def main(context_ref):
 initial=peer.fd_snapshot('Root-entry-initial');peer.need(os.getuid()==0,'actual Root queue entry')
 peer.need(context_ref['identity']['st_uid']==context_ref['identity']['st_gid']==0 and stat.S_IMODE(context_ref['identity']['st_mode'])==0o400,'exact protected context')
 context=json.loads(held(context_ref,1048576));peer.need(context['kind']=='ROOT_LIBVIRT_R4_RUNTIME_CONTEXT'and context['runtimeAuthorized']is True and context.get('MODEL_ONLY')is not True,'independently issued exact context, never disabled model')
 validate_context_sources(context)
 c=context['candidate'];grant_ref=context['grantPin'];g=json.loads(held(grant_ref,1048576))
 parent=json.loads(held(context['parentPin'],1048576));bind_placement(peer,parent,context['parentPin'],context);peer.need(g['sourcePlacementPin']==context['sourcePlacementPin']and g['placementQualificationPin']==context['placementQualificationPin'],'child grant/context exact fresh placement pins');peer.need(g['parentPin']==context['parentPin']and parent['RootIssued']is True and parent['issuedUnix']<=g['issuedUnix']<g['startBeforeUnix']<=parent['startBeforeUnix']and g['wholeDeadlineUnix']<=parent['wholeDeadlineUnix'],'finite child within exact independently issued parent clocks; no refresh/extension')
 assignment=json.loads(held(context['assignmentPin'],1048576));peer.need(assignment['kind']=='ROOT_CANONICAL_QUEUE_LIBVIRT_ASSIGNMENT_R4'and assignment['proof']['priorCounts']==g['priorHistoryCounts']and assignment['proof']['priorRawSHA256']==g['priorHistorySHA256']and assignment['proof']['currentCounts']=={'rows':g['priorHistoryCounts']['rows']+1,'bindings':g['priorHistoryCounts']['bindings']+1,'config':g['priorHistoryCounts']['config']},'genuine adopted prior plus one own row/binding before GPU')
 request=assignment['request'];peer.validate_request(request);peer.need(g['assignmentPin']==context['assignmentPin']and g['normalizedSpecSHA256']==request['specSHA256'],'complete grant/assignment/spec equality')
 receipt_root='/run/opemos-libvirt-results-'+c['nonce'];peer.need(not os.path.lexists(receipt_root),'unique receipt lane');producer.create_root(receipt_root);sequence=[];observations={}
 def persist(label,value):
  if label in observations or len(observations)<32:observations[label]=value
  return None
 peer.need(peer.fd_equal(initial,peer.fd_snapshot('Root-entry-before-library-bootstrap')),'all prebootstrap entry descriptors unchanged');driver=bootstrap_event_driver(persist);transactionInitial=peer.fd_snapshot('Root-entry-transaction-baseline');ops=NativeTransactionOps(c,persist);ops.captureBinding=capture_binding(context,parent,g,request);persist('source12-capture-binding',ops.captureBinding)
 import importlib.util
 parser_ref=context['guestParserPin'];peer.need(parser_ref==context['sourceRoles']['two_boot_contract'],'exact parser role membership');raw=held(parser_ref,65536);module=__import__('types').ModuleType('held_guest_two_boot_parser');exec(compile(raw,parser_ref['path'],'exec'),module.__dict__)
 persist('entry',{'actor':peer.process(os.getpid()),'contextPin':context_ref,'grantPin':grant_ref,'assignmentPin':context['assignmentPin'],'failureControl':'LIBVIRT_AUTODESTROY_CONTROLLER_CONNECTION'})
 result=producer.Transaction(c,request,g,grant_ref,ops,persist).run(module,context['guestContract'])
 fdsClosed=finish_entry_fds(result,transactionInitial,driver,persist)
 with peer.RootFiles(receipt_root)as f,f.lock(True):terminal=producer.put(f,'terminal-index.json',{'result':result,'orderedRecords':sequence,'allOwnedFDsClosed':fdsClosed,'processLifetimeEventDriver':driver,'processLifetimeClosureRequiresOriginalRootReap':True,'actor':{k:peer.process(os.getpid())[k]for k in('pid','start','uid')},'atUnix':time.time()})
 print(peer.canon({'terminal':terminal,'accepted':result['accepted'],'leaseHeld':result['leaseMustRemainHeld']}).decode(),flush=True);return 0 if operational_complete(result,fdsClosed)else 1

if __name__=='__main__':
 if len(sys.argv)!=3 or sys.argv[1]not in('--context-pin-json','--parent-pin-json'):raise ValueError('exact protected context or independent parent pin argv only')
 ref=json.loads(sys.argv[2]);sys.exit(main(await_root_context(ref)if sys.argv[1]=='--parent-pin-json'else ref))

"""Exact D23 readonly standalone peer/access adapter proposal, never installed.
No deployment, writes, SQL, runtime grant, domain control or sysfs methods.
Queue owner must independently adopt exact bytes and consumer contract.
"""
import contextlib,copy,hashlib,json,os,re,stat,sys,time,traceback,types
from pathlib import Path
ORIGINAL_SOURCE_ROOT='/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r107b'
PEER_SHA='314076a17d300854e942674f4d3dbfb5c5d489ace233c5b4af6f75d49323ce9c'
F=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');CORE=F[:6]
NONCE='cd9ef0826364409da287f6f3e3830c95';CONTRACT='R109_CURRENT_NORMAL_QUEUE_FULL_PHASE_READONLY'
PEER_BYTES=65396
ORIGINAL_PEER_SHA='7e1663f8351247b9643b7c14419119449b0bd0722a46b80ae0f8ea34a9f9816a';ORIGINAL_PEER_BYTES=64727
CLOSED_SUBJECT_PEERS={'9e5516fcdf57624d786a91741066998605045fe145ce60fbe8bde68f5b494bdd':61355,'224aa4a8b06999e318350267195cc681a095aaf2a2b5e407552f8811673a8614':61400}
SOURCE_ROOT=None
SOURCE_CONTRACT_SHA='4cb604515bbb577e6448283a7b785249929c73216e890a06ca5c531e25bd6e5d'
CURRENT_DEFINITION=None
ACCESS_SHA='28867292c15b26f683a8d81d79af23dfb9ef647c10af86ebab01ed7393502285';ACCESS_BYTES=39326
ORIGINAL_ACCESS_SHA='ee32a4e84df796d6932062ded9e1049ce5e82cbbf01315d8c74da96b9e03aa9e';ORIGINAL_ACCESS_BYTES=33928
ROLES={'libvirt_peer','libvirt_access','libvirt_native','libvirt_preflight','libvirt_producer','queue_assignment','runtime_entry','guest_delta','guest_firmware_probe','held_history_reader','two_boot_contract','postqueue_issuer','libvirt_storage','retained_media','source_contract'}
def placement_root(candidate):
 if 'operationContext'in candidate:
  need(CURRENT_DEFINITION is not None,'authenticated shared definition available');return CURRENT_DEFINITION.candidate_paths(candidate)['placementRoot']
 nonce=candidate['nonce'];need(nonce==NONCE,'same placement nonce')
 io=Path(candidate['run']).parent;prefix='opemos-libvirt-io-'+nonce+'-'
 if candidate.get('installer',{}).get('kind')=='AUTHENTICATED_RETAINED_F9AA_READONLY_USB' or io.name.startswith(prefix):
  need(io.parent==Path('/run')and re.fullmatch(re.escape(prefix)+'[0-9a-f]{32}',io.name)and Path(candidate['run'])==io/'run'and Path(candidate['output'])==io/'output'and type(candidate.get('jobId'))is str and candidate['jobId'].endswith('-e'+io.name[len(prefix):][:16]),'protected same attempt IO/job placement')
  return '/run/opemos-steamos-placement-'+nonce+'-'+io.name[len(prefix):]
 return '/run/opemos-steamos-placement-'+nonce
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)
def need(v,m):
 if not v:raise RuntimeError(m)
def ident(s):return{k:getattr(s,k)for k in F}
def decode(raw):
 def unique(pairs):
  value={}
  for key,item in pairs:need(key not in value,'duplicate protected JSON key');value[key]=item
  return value
 value=json.loads(raw,object_pairs_hook=unique);need(canonical(value).encode()==raw,'whole canonical protected metadata, no dropped/trailing fields');return value
def record_run_check(proof,event):
 # All native FD/name/core/mount/namespace predicates run before this call.
 # Keep only the current witness; diagnostic transcript growth is no authority.
 proof['lastCheck']=event

class RootInputs:
 """One readonly bounded held-nofollow /run graph; owns and closes all FDs."""
 def __init__(self,control=None,implementation=None):self.fds=[];self.dirs={};self.currentControl=control;self.implementationPin=implementation;self.implementationRoot=None
 def __enter__(self):
  self.root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.fds.append(self.root)
  try:
   self.run=os.open('run',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.root);self.fds.append(self.run)
   self.dirs={'/':(self.root,ident(os.fstat(self.root)),False),'/run':(self.run,ident(os.fstat(self.run)),False)};self.runBirth=self.run_row(self.run);rows=[x for x in Path('/proc/self/mountinfo').read_text().splitlines()if x.split()[0]==str(self.runBirth['mountID'])];need(len(rows)==1,'exact initial run mount');self.runProof={'kind':'ROOT_BORROWED_RUN_CURRENT_CUSTODY_V1','path':'/run','birth':self.runBirth,'namespace':os.readlink('/proc/self/ns/mnt'),'mountRow':rows[0],'lastCheck':None,'scopeDescriptorsClosed':False,'closeOutcomes':[]};self.check()
   if self.currentControl is not None:self.bind_definition(self.currentControl)
   if self.implementationPin is not None:self.bind_implementation(self.implementationPin)
   return self
  except BaseException:
   self.__exit__(*sys.exc_info());raise
 def run_row(self,fd):
  raw=Path('/proc/self/fdinfo/'+str(fd)).read_text();v={}
  for line in raw.splitlines():
   if line.startswith(('flags:','mnt_id:')):k,x=line.split(':',1);v[k]=x.strip()
  need(set(v)=={'flags','mnt_id'}and v['mnt_id'].isdigit()and re.fullmatch('[0-7]+',v['flags'])is not None,'complete actual run descriptor flags/mount')
  f=__import__('fcntl');return {'fd':fd,'identity':ident(os.fstat(fd)),'target':os.readlink('/proc/self/fd/'+str(fd)),'flags':f.fcntl(fd,f.F_GETFL),'descriptorFlags':f.fcntl(fd,f.F_GETFD),'fdinfoFlags':v['flags'],'mountID':int(v['mnt_id'])}
 def borrowed_run(self):
  initial=self.runBirth;owned=[];primary=None;event={};startns=os.readlink('/proc/self/ns/mnt')
  try:
   event['heldBefore']=self.run_row(self.run)
   for label,path,anchored in(('anchored','run',True),('named','/run',False)):
    fd=os.open(path,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,**({'dir_fd':self.root}if anchored else{}));owned.append(fd);event[label]=self.run_row(fd)
   event['anchoredPath']=ident(os.stat('run',dir_fd=self.root,follow_symlinks=False));event['namedPath']=ident(os.lstat('/run'));event['heldAfter']=self.run_row(self.run);event['anchoredAfter']=self.run_row(owned[0]);event['namedAfter']=self.run_row(owned[1]);event['namespaceBefore']=startns;event['namespaceAfter']=os.readlink('/proc/self/ns/mnt')
   rows=[x for x in Path('/proc/self/mountinfo').read_text().splitlines()if x.split()[0]==str(initial['mountID'])];need(len(rows)==1,'unique current kernel run mount row');event['mountRow']=rows[0]
   stable=F[:5];snapshots=[event[k]['identity']for k in('heldBefore','anchored','named','heldAfter','anchoredAfter','namedAfter')]+[event['anchoredPath'],event['namedPath']]
   need(all(all(x[k]==initial['identity'][k]for k in stable)for x in snapshots)and all(event[k]['target']=='/run'and event[k]['mountID']==initial['mountID']and event[k]['descriptorFlags']==1 for k in('heldBefore','anchored','named','heldAfter','anchoredAfter','namedAfter')),'same held/anchored/named run inode/type/mode/owner/mount')
   need(event['heldBefore']==dict(initial,identity=event['heldBefore']['identity'])and event['heldAfter']==dict(initial,identity=event['heldAfter']['identity'])and startns==event['namespaceAfter']==self.runProof['namespace'],'same borrowed run FD/flags/name/namespace')
   for name in('anchored','named'):
    a=event[name];b=event[name+'After'];need(a==dict(b,identity=a['identity'])and a['flags']==os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,'exact temporary nofollow O_PATH run descriptors')
   row=rows[0].split();i=initial['identity'];need(stat.S_ISDIR(i['st_mode'])and stat.S_IMODE(i['st_mode'])==0o755 and i['st_uid']==i['st_gid']==0 and initial['flags']&os.O_ACCMODE==os.O_RDONLY and not initial['flags']&os.O_PATH and initial['flags']&os.O_DIRECTORY and initial['flags']&os.O_NOFOLLOW and re.fullmatch(r'mnt:\[[0-9]+\]',startns)is not None,'declared borrowed Root0755 readonly run directory');need(row[3:5]==['/','/run']and row[2]==str(os.major(i['st_dev']))+':'+str(os.minor(i['st_dev']))and event['mountRow']==self.runProof['mountRow'],'same kernel mount root/device/path and original run mount')
  except BaseException as error:primary=error;error.evidence={'kind':'BORROWED_RUN_CUSTODY_REFUSAL_R257','birth':initial,'event':event};raise
  finally:
   errors=[]
   for fd in owned[::-1]:
    try:os.close(fd)
    except BaseException as e:errors.append({'fd':fd,'type':type(e).__name__,'reason':str(e)})
   if errors:
    if primary is not None:primary.ownedRootInputClosureErrors=errors
    else:raise RuntimeError(canonical({'ownedRootInputClosureErrors':errors}))
  event['temporaryDescriptorsClosed']=True;record_run_check(self.runProof,event);return event
 def check(self):
  for path,(fd,a,exclusive)in self.dirs.items():
   if path=='/run':self.borrowed_run();continue
   x=ident(os.fstat(fd));named=ident(os.lstat(path))
   if not(x==named and all(x[k]==a[k]for k in(CORE if not exclusive else F))):
    error=RuntimeError('held/named declared directory identity/epoch');error.evidence={'path':path,'role':'exclusive'if exclusive else'shared-ancestor','birth':a,'held':x,'named':named,'monotonic':time.monotonic()};raise error
   need(stat.S_ISDIR(x['st_mode'])and x['st_uid']==x['st_gid']==0,'Root directory nofollow custody')
   need(stat.S_IMODE(x['st_mode'])in((0o755,0o777)if path=='/'else(0o755,)if path=='/run'else(0o555,)if path in(SOURCE_ROOT,self.implementationRoot) else(0o755,)if path.startswith('/run/opemos-steamos-source-')else(0o700,)),'exact role-specific directory mode')
 def bind_definition(self,control):
  global SOURCE_ROOT,NONCE,CURRENT_DEFINITION
  need(type(control)is dict and set(control)=={'definitionPin','parentPin'},'closed protected current control input')
  ref=control['definitionPin'];root=Path(ref['path']).parent
  need(root.parent==Path('/run')and Path(ref['path']).name=='installed-controller.json','direct Root definition leaf')
  SOURCE_ROOT=str(root)
  raw,helper=self.read_path(str(root/'source_contract.py'),0o444,65536)
  need(helper['sha256']==SOURCE_CONTRACT_SHA,'exact reviewed shared definition implementation')
  module=types.ModuleType('scoped_source_definition');module.__file__=str(root/'source_contract.py');exec(compile(raw,module.__file__,'exec'),module.__dict__)
  value=module.read_definition(ref);need(value['sourceRoles']['source_contract']==helper,'same held definition implementation pin')
  need(value['deployment']['paths']['sourceRoot']==SOURCE_ROOT and re.fullmatch('[0-9a-f]{32}',value['guestNonce']),'typed protected deployment/guest lineage')
  self.definition=value;self.definitionPin=ref;NONCE=value['guestNonce'];CURRENT_DEFINITION=module
 def bind_implementation(self,ref):
  need(self.currentControl is not None and CURRENT_DEFINITION is not None,'original authenticated subject definition first')
  root=Path(ref['path']).parent;need(ref['path']==str(root/'installed-controller.json')and root.parent==Path('/run')and re.fullmatch('opemos-media-source-[0-9a-f]{32}',root.name),'separate normal immutable implementation definition')
  self.implementationRoot=str(root)
  raw,actual=self.read_path(ref['path'],0o444,1048576);need(actual==ref,'held separate implementation definition')
  value=CURRENT_DEFINITION.read_definition(ref)
  need(set(value['sourceRoles'])==ROLES and value['deployment']['paths']['sourceRoot']==str(root),'complete typed implementation membership/root')
  helper=value['sourceRoles']['source_contract'];need(helper['sha256']==SOURCE_CONTRACT_SHA and self.read(helper,0o444,65536),'unchanged reviewed shared definition implementation')
  self.implementationDefinition=value
 def directory(self,path):
  allowed={SOURCE_ROOT,ORIGINAL_SOURCE_ROOT,self.implementationRoot,getattr(self,'runtimeRoot','/run/opemos-libvirt-runtime-'+NONCE),getattr(self,'placementRoot','/run/opemos-steamos-placement-'+NONCE)}
  need(path in allowed,'declared finite source/context/placement root only')
  if path not in self.dirs:
   fd=os.open(Path(path).name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.run);self.fds.append(fd);self.dirs[path]=(fd,ident(os.fstat(fd)),True)
  self.check();return self.dirs[path][0]
 def read_path(self,path,mode,cap):
  path=Path(path);need(path.is_absolute()and path.name not in('','.','..'),'absolute confined declared leaf')
  if str(path.parent)=='/run':need(str(path)==(self.currentControl['parentPin']['path']if self.currentControl is not None else'/run/opemos-libvirt-parent-'+NONCE+'.json'),'one bound public parent only');parent=self.run
  else:parent=self.directory(str(path.parent))
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
  try:
   s=os.fstat(fd);a=ident(s);need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode and s.st_nlink==1 and s.st_size<=cap,'exact Root leaf mode/owner/link/size');raw=b''
   while chunk:=os.read(fd,65536):raw+=chunk;need(len(raw)<=cap,'bounded full leaf stream')
   need(a==ident(os.fstat(fd))==ident(os.stat(path.name,dir_fd=parent,follow_symlinks=False))==ident(os.lstat(path))and len(raw)==a['st_size'],'full held/anchored/named identity and EOF');self.check();return raw,{'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':a}
  finally:os.close(fd)
 def read(self,ref,mode,cap):
  raw,actual=self.read_path(ref['path'],mode,cap)
  if actual!=ref:
   error=RuntimeError('exact declared full9/length/SHA pin');error.evidence={'path':ref['path'],'expected':ref,'actual':actual};raise error
  return raw
 def placement_bytes(self,fd,parentfd,ref):
  """Inner FD/hash check; hold_placement applies exact Root role custody.
  It does not change Root policy or convert a user fixture into Root proof.
  """
  value={'path':ref['path'],'expected':ref,'heldBefore':None,'heldAfter':None,'named':None,'heldSHA256':None,'namedSHA256':None,'heldBytes':None,'namedBytes':None}
  def bytesof(f):
   chunks=[];offset=0
   while True:
    b=os.pread(f,65536,offset)
    if not b:break
    offset+=len(b);need(offset<=1048576,'unchanged placement metadata1MiB streaming cap');chunks.append(b)
   return b''.join(chunks)
  try:
   value['heldBefore']=ident(os.fstat(fd));need((__import__('fcntl').fcntl(fd,__import__('fcntl').F_GETFL)&os.O_ACCMODE)==os.O_RDONLY,'owned placement held FD remains O_RDONLY');held=bytesof(fd);value.update(heldBytes=len(held),heldSHA256=hashlib.sha256(held).hexdigest())
   nf=os.open(Path(ref['path']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)
   try:
    value['named']=ident(os.fstat(nf));named=bytesof(nf);value.update(namedBytes=len(named),namedSHA256=hashlib.sha256(named).hexdigest());need(value['named']==ident(os.fstat(nf))==ident(os.stat(Path(ref['path']).name,dir_fd=parentfd,follow_symlinks=False))==ident(os.lstat(ref['path'])),'placement fresh nofollow named FD/path full9')
   finally:
    primary=sys.exc_info()[1]
    try:os.close(nf)
    except BaseException as close:
     if primary is None:raise
     primary.ownedPlacementCloseErrors=getattr(primary,'ownedPlacementCloseErrors',[])+[{'fd':nf,'type':type(close).__name__,'reason':str(close)}]
   value['heldAfter']=ident(os.fstat(fd));need(value['heldBefore']==value['heldAfter']==value['named']==ref['identity']and len(held)==len(named)==ref['bytes']and value['heldSHA256']==value['namedSHA256']==ref['sha256']and held==named,'placement held/named full9/raw bytes/length/SHA equal originally bound operand')
   return held
  except BaseException as error:error.placementCustody=value;raise
 @contextlib.contextmanager
 def hold_placement(self,ref):
  root=getattr(self,'placementRoot','/run/opemos-steamos-placement-'+NONCE);need(ref['path']in(root+'/storage-contract.json',root+'/placement-qualified.json'),'two exact placement metadata leaves only');i=ref['identity'];need(set(ref)=={'path','bytes','sha256','identity'}and 0<ref['bytes']<=1048576 and stat.S_ISREG(i['st_mode'])and stat.S_IMODE(i['st_mode'])==0o400 and i['st_uid']==i['st_gid']==0 and i['st_nlink']==1 and i['st_size']==ref['bytes'],'exact Root0400 placement full pin/custody')
  parentfd=self.directory(root);fd=os.open(Path(ref['path']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)
  try:
   original=self.placement_bytes(fd,parentfd,ref);self.check()
   def recheck():
    self.check();raw=self.placement_bytes(fd,parentfd,ref);need(raw==original,'complete held placement raw bytes identical after observer');self.check();return ref
   yield {'ref':ref,'raw':original,'recheck':recheck}
  finally:
   primary=sys.exc_info()[1]
   try:os.close(fd)
   except BaseException as close:
    if primary is None:raise
    primary.ownedPlacementCloseErrors=getattr(primary,'ownedPlacementCloseErrors',[])+[{'fd':fd,'type':type(close).__name__,'reason':str(close)}]
 def __exit__(self,*a):
  errors=[]
  for fd in self.fds[::-1]:
   try:
    os.close(fd)
    if hasattr(self,'runProof'):self.runProof['closeOutcomes'].append({'fd':fd,'closed':True})
   except OSError as e:errors.append({'fd':fd,'type':type(e).__name__,'reason':str(e)})
  self.fds=[]
  if hasattr(self,'runProof'):self.runProof['scopeDescriptorsClosed']=not errors
  if errors:
   if a[1]is not None:a[1].ownedRootInputClosureErrors=errors
   else:raise RuntimeError(canonical({'ownedRootInputClosureErrors':errors}))

def parent_spec(parent,parent_ref):
 s=copy.deepcopy(parent['normalizedSpecTemplate']);need(s['approval']=='EXACT_PARENT_MINIMAL_PIN'and s['command'][-1]=='EXACT_PARENT_FULL_PIN_JSON','two existing late parent-pin slots only');s['approval']={k:parent_ref[k]for k in('path','bytes','sha256')};s['command'][-1]=canonical(parent_ref)
 need(s['command']==['sudo','-n','/usr/bin/python3','-B',parent['sourceRoles']['runtime_entry']['path'],'--parent-pin-json',canonical(parent_ref)]and s['id']==parent['jobId']and s['cores']==4 and s['memory']==10737418240 and s['timeout_seconds']==900 and 'omen-iommu-group-1'in s['resources'],'exact ordinary entry and10GiB/4CPU/900s spec')
 return s

def verify_inputs(request,io,boot,include_context=True):
 global NONCE
 if io.currentControl is None:need(request['leaseNonce']==NONCE,'exact historical input scope')
 parent_path=io.currentControl['parentPin']['path']if io.currentControl is not None else'/run/opemos-libvirt-parent-'+NONCE+'.json'
 parentRaw,parentRef=io.read_path(parent_path,0o444,1048576);parent=decode(parentRaw)
 if io.currentControl is not None:
  need(parentRef==io.currentControl['parentPin']and request.get('currentControl')==io.currentControl,'whole current parent/request pin')
  if 'operationContext'in parent['candidate']:
   paths=CURRENT_DEFINITION.candidate_paths(parent['candidate']);need(parent['candidate']['operationContext']['deploymentId']==io.definition['deployment']['id']and parent['candidate']['lineageNonce']==io.definition['guestNonce']and parent['installedSourceContractPin']==io.definitionPin and parent_path==paths['parentPath'],'same protected deployment/operation parent');io.runtimeRoot=paths['runtimeRoot'];io.placementRoot=paths['placementRoot']
 NONCE=parent['nonce'];need(request['leaseNonce']==NONCE and request['domainName']=='opemos-libvirt-'+NONCE,'same protected current domain/scope')
 cr=getattr(io,'runtimeRoot','/run/opemos-libvirt-runtime-'+NONCE)+'/context.json'
 contextRaw=contextRef=context=None
 if include_context:
  try:contextRaw,contextRef=io.read_path(cr,0o400,1048576);context=decode(contextRaw)
  except FileNotFoundError:pass
 need(parent['kind']=='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT'and parent['RootIssued']is True and parent['runtimeAuthorized']is True and parent.get('MODEL_ONLY')is False and parent['bootID']==boot and parent['nonce']==NONCE and parent['contextPath']==cr,'existing actual same-boot Root parent; no issuance or clock refresh')
 if context is not None:need(context['parentPin']==parentRef and context['kind']=='ROOT_LIBVIRT_R4_RUNTIME_CONTEXT'and context['runtimeAuthorized']is True and context.get('MODEL_ONLY')is False and context['candidate']==parent['candidate']and context['sourceRoles']==parent['sourceRoles'],'Root context/candidate/source12 equality; no model promotion')
 need(type(parent['candidate'].get('installer'))is dict and parent['candidate']['installer'].get('kind')in('AUTHENTICATED_F9AA_RAW_RECOVERY_USB_FIRSTBOOT','AUTHENTICATED_RETAINED_F9AA_READONLY_USB')and parent['candidate']['installer'].get('noInstallTarget')is True,'this reviewed source branch admits only the retained installer/no target')
 need(parent['issuedUnix']<parent['startBeforeUnix']<=parent['issuedUnix']+300 and parent['wholeDeadlineUnix']<=parent['issuedUnix']+900,'original finite parent scope retained; readonly closed observation does not reissue authority')
 roles=parent['sourceRoles'];need(set(roles)==ROLES,'complete source12 membership');compat=io.implementationPin is not None
 if compat:need(roles['libvirt_peer']['sha256']in(CLOSED_SUBJECT_PEERS|{PEER_SHA:PEER_BYTES})and roles['libvirt_peer']['bytes']==(CLOSED_SUBJECT_PEERS|{PEER_SHA:PEER_BYTES})[roles['libvirt_peer']['sha256']],'exact enrolled original subject peer')
 need((roles['libvirt_peer']['bytes'],roles['libvirt_peer']['sha256'])in(tuple((n,h)for h,n in(CLOSED_SUBJECT_PEERS|{PEER_SHA:PEER_BYTES}).items())if compat else((PEER_BYTES,PEER_SHA),(ORIGINAL_PEER_BYTES,ORIGINAL_PEER_SHA))) and (roles['libvirt_access']['bytes'],roles['libvirt_access']['sha256'])in((ACCESS_BYTES,ACCESS_SHA),(ORIGINAL_ACCESS_BYTES,ORIGINAL_ACCESS_SHA)),'frozen reviewed peer/access implementation')
 need(request['observer']=={k:roles['libvirt_peer'][k]for k in('path','bytes','sha256')}and request['jobId']==parent['jobId'],'exact original request observer/job')
 source={}
 for name,ref in sorted(roles.items()):
  need(ref['path']==str(Path(roles['libvirt_peer']['path']).parent/(name+'.py')) and str(Path(roles['libvirt_peer']['path']).parent)in(SOURCE_ROOT,ORIGINAL_SOURCE_ROOT),'same exact source namespace');source[name]=io.read(ref,0o444,65536)
  if not compat:compile(source[name],ref['path'],'exec')
 spec=parent_spec(parent,parentRef);bound=spec['libvirt_domain'];need(bound=={'leaseNonce':NONCE,'name':request['domainName'],'observer':request['observer'],'uuid':request['domainUUID']}and hashlib.sha256(canonical(spec).encode()).hexdigest()==request['specSHA256'],'complete final normalized spec/hash/domain identity')
 original=roles['libvirt_peer']['sha256']==ORIGINAL_PEER_SHA
 need((roles['libvirt_access']['sha256'],roles['libvirt_access']['bytes'])==((ORIGINAL_ACCESS_SHA,ORIGINAL_ACCESS_BYTES)if original else(ACCESS_SHA,ACCESS_BYTES)),'one coherent original/current peer/access pair')
 need(str(Path(roles['libvirt_peer']['path']).parent)==(ORIGINAL_SOURCE_ROOT if original else SOURCE_ROOT),'same declared original/current source namespace')
 need(not original or context is None,'original R107 input supports no-grant qualification only')
 need(original or roles['libvirt_peer']['path']==SOURCE_ROOT+'/libvirt_peer.py','current request requires exact new source namespace')
 implementationRoot=io.implementationRoot if compat else SOURCE_ROOT
 implRaw,implRef=io.read_path(implementationRoot+'/libvirt_peer.py',0o444,65536)
 need(implRef['sha256']==PEER_SHA and implRef['bytes']==PEER_BYTES,'separate exact current peer implementation')
 accessRaw,accessRef=io.read_path(implementationRoot+'/libvirt_access.py',0o444,65536)
 need(accessRef['sha256']==ACCESS_SHA and accessRef['bytes']==ACCESS_BYTES,'separate exact current access implementation')
 need(compat or original or roles['libvirt_access']==accessRef,'new parent access is exact current implementation')
 implementationSource={}
 if compat:
  for name,ref in io.implementationDefinition['sourceRoles'].items():
   need(ref['path']==io.implementationRoot+'/'+name+'.py','current implementation modules never execute original subject sources')
   implementationSource[name]=io.read(ref,0o444,65536)
 assignmentRef=grantRef=None;assignment=grant=None
 if context is not None:
  assignmentRef=context['assignmentPin'];need(assignmentRef['path']==getattr(io,'runtimeRoot','/run/opemos-libvirt-runtime-'+NONCE)+'/assignment.json'and context['grantPin']['path']==getattr(io,'runtimeRoot','/run/opemos-libvirt-runtime-'+NONCE)+'/child-grant.json','two exact same-scope child control leaves');assignment=decode(io.read(assignmentRef,0o400,1048576));grantRef=context['grantPin'];grant=decode(io.read(grantRef,0o400,1048576))
  need(assignment['kind']=='ROOT_CANONICAL_QUEUE_LIBVIRT_ASSIGNMENT_R4'and assignment['request']==request and grant['assignmentPin']==assignmentRef and grant['parentPin']==parentRef and grant['normalizedSpecSHA256']==request['specSHA256'],'canonical assignment and child grant exact request/spec/parent')
  need(grant['queuePrograms']==parent['queuePrograms']and grant['sourcePlacementPin']==context['sourcePlacementPin']==parent['sourcePlacementPin']and grant['placementQualificationPin']==context['placementQualificationPin']==parent['placementQualificationPin'],'current queue authority and placement pins across child/context/parent')
  need(grant['RootIssued']is True and grant['MODEL_ONLY']is False and grant['runtimeAuthorized']is True and grant['jobId']==request['jobId']and grant['leaseNonce']==NONCE and grant['bootID']==boot and parent['issuedUnix']<=grant['issuedUnix']<grant['startBeforeUnix']<=parent['startBeforeUnix']and grant['wholeDeadlineUnix']<=parent['wholeDeadlineUnix'],'existing finite Root child only, no new runtime grant')
 io.placementRoot=placement_root(parent['candidate'])
 return {'implementationDefinitionPin':io.implementationPin,'implementationSource':implementationSource,'implementationRoles':None if not compat else io.implementationDefinition['sourceRoles'],'implementationAccessRaw':accessRaw,'implementationAccessPin':accessRef,'implementationPeerRaw':implRaw,'implementationPeerPin':implRef,'originalInputOnly':original,'parent':parent,'parentPin':parentRef,'parentRaw':parentRaw,'context':context,'contextPin':contextRef,'contextRaw':contextRaw,'source':source,'assignmentPin':assignmentRef,'assignmentRaw':None if assignment is None else canonical(assignment).encode(),'grantPin':grantRef,'grantRaw':None if grant is None else canonical(grant).encode()}

def _bind_placement(peer,parent,parent_ref,context,verify_access,implementation_definition=None):
 """Bind only the fresh protected same-source/same-scope metadata operand.
 Never changes the frozen peer's nonce, strict geometry or owner predicate.
 """
 nonce=parent['nonce'];roles=parent['sourceRoles'];candidate=parent['candidate']
 if 'operationContext'in candidate:__import__('source_contract').bind_scope(peer,parent)
 peer.need(peer.SOURCE_PLACEMENT_NONCE==nonce and candidate['nonce']==nonce and __import__('queue_assignment').execution_job(candidate,parent)==parent['jobId'],'D23 unused scope only; D22 is consumed')
 peer.need(parent['RootIssued']is True and parent['kind']=='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT'and parent['bootID']==candidate['hostBoot']and parent_ref['path']==__import__('source_contract').parent_paths(parent)['parentPath'],'existing exact Root parent/boot/source scope')
 __import__('source_contract').validate(roles,parent['queuePrograms'],parent['installedSourceContractPin'])
 if implementation_definition is not None:
  definition=__import__('source_contract').read_definition(implementation_definition)
  __import__('source_contract').validate(definition['sourceRoles'],definition['queuePrograms'],implementation_definition)
  peer.need(peer.__file__==definition['sourceRoles']['libvirt_peer']['path']and definition['sourceRoles']['libvirt_peer']['sha256']==PEER_SHA,'actual separately authenticated current placement implementation')
  peer.need(roles['libvirt_peer']['sha256']in(CLOSED_SUBJECT_PEERS|{PEER_SHA:PEER_BYTES})and roles['libvirt_peer']['bytes']==(CLOSED_SUBJECT_PEERS|{PEER_SHA:PEER_BYTES})[roles['libvirt_peer']['sha256']]and (roles['libvirt_access']['sha256'],roles['libvirt_access']['bytes'])==(ACCESS_SHA,ACCESS_BYTES),'enrolled original subject peer/access pair remains data')
 else:peer.need((roles['libvirt_peer']['sha256'],roles['libvirt_peer']['bytes'])in((PEER_SHA,PEER_BYTES),(ORIGINAL_PEER_SHA,ORIGINAL_PEER_BYTES))and (roles['libvirt_access']['sha256'],roles['libvirt_access']['bytes'])in((ACCESS_SHA,ACCESS_BYTES),(ORIGINAL_ACCESS_SHA,ORIGINAL_ACCESS_BYTES)),'frozen exact D23 peer and unchanged access bytes')
 for name,ref in roles.items():peer.need(ref['path']==str(Path(roles['libvirt_peer']['path']).parent/(name+'.py'))and str(Path(roles['libvirt_peer']['path']).parent)in(SOURCE_ROOT,ORIGINAL_SOURCE_ROOT)and ref['identity']['st_uid']==ref['identity']['st_gid']==0 and stat.S_IMODE(ref['identity']['st_mode'])==0o444 and ref['identity']['st_nlink']==1,'same immutable Root source12 namespace')
 ref=parent['sourcePlacementPin'];qr=parent['placementQualificationPin'];root=placement_root(candidate)
 if 'operationContext'in candidate:__import__('source_contract').bind_scope(peer,parent)
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
  verify_access(candidate,access_pin,prepared)
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

def bind_placement(peer,parent,parent_ref,context=None):
 from libvirt_access import verify_prepared
 return _bind_placement(peer,parent,parent_ref,context,verify_prepared)

def bind_observer_placement(peer,parent,parent_ref,context,implementation_definition=None):
 from libvirt_access import prepared_lineage
 return _bind_placement(peer,parent,parent_ref,context,prepared_lineage,implementation_definition)

@contextlib.contextmanager
def load_pair(v):
 names=('libvirt_storage','retained_media','source_contract','libvirt_peer','libvirt_access','guest_firmware_probe','libvirt_native','queue_assignment');missing=object();previous={k:sys.modules.get(k,missing)for k in names}
 try:
  roles=v['implementationRoles']if v['implementationDefinitionPin']is not None else v['parent']['sourceRoles'];modules={}
  for name in names:
   module=types.ModuleType(name);module.__file__=roles[name]['path'];sys.modules[name]=module;modules[name]=module
  for name in names:
   module=modules[name];body=v['implementationSource'][name]if v['implementationDefinitionPin']is not None else v['implementationPeerRaw']if name=='libvirt_peer'else v['implementationAccessRaw']if name=='libvirt_access'else v['source'][name];module.__file__=v['implementationPeerPin']['path']if name=='libvirt_peer'else v['implementationAccessPin']['path']if name=='libvirt_access'else module.__file__;exec(compile(body,module.__file__,'exec'),module.__dict__)
  if v['implementationDefinitionPin']is not None:
   definition=modules['source_contract'].read_definition(v['implementationDefinitionPin']);modules['source_contract'].validate(definition['sourceRoles'],definition['queuePrograms'],v['implementationDefinitionPin'])
  yield modules['libvirt_peer'],modules['libvirt_access']
 finally:
  for name,old in previous.items():
   if old is missing:sys.modules.pop(name,None)
   else:sys.modules[name]=old

def run(request,io,boot):
 v0=verify_inputs(request,io,boot,False)
 with load_pair(v0)as(peer,access):
  with access.runtime_snapshot(v0['parent'],v0['parentPin'],request,time.monotonic()+14,io)as snapshot:
   v=verify_inputs(request,io,boot);need(v['parentPin']==v0['parentPin']and v['source']==v0['source'],'unchanged immutable sources across runtime SH acquisition')
   with contextlib.ExitStack()as custody:
    heldPlacement=custody.enter_context(io.hold_placement(v['parent']['sourcePlacementPin']));heldQualification=custody.enter_context(io.hold_placement(v['parent']['placementQualificationPin']))
    if io.implementationPin is None:peer.validate_request(request)
    binding=bind_observer_placement(peer,v['parent'],v['parentPin'],v['context'],io.implementationPin);need(binding['placementPin']==heldPlacement['ref']and binding['qualificationPin']==heldQualification['ref'],'binding consumes the two retained exact placement pins')
    parent=v['parent'];candidate=parent['candidate']
    def custody(phase,intent,reg,state,files):return access.verify_phase(candidate,parent['preparedAccessPin'],parent['preparedDiskPins'],phase,intent,reg,state,files)
    proof=peer.observe_closed_subject(request,io.implementationPin,custody=custody)if io.implementationPin is not None else peer.observe(request,custody=custody)
    need(not v['originalInputOnly']or proof['phase']=='NOT_PREPARED','old R107 request cannot adopt a current runtime phase')
    need(proof.get('accessCustody',{}).get('phase')==proof['phase'],'actual locked phase access custody required')
    proof['accessCustody']={'kind':'ROOT_PHASE_PREPARED_ACCESS_CUSTODY_R1','phase':proof['phase'],'nonce':NONCE,'bootID':boot,'requestSHA256':hashlib.sha256(peer.canon(request)).hexdigest(),'parentPin':v['parentPin'],'preparedAccessPin':parent['preparedAccessPin'],'preparedDiskPins':parent['preparedDiskPins'],'sourceGraphSHA256':binding['sourceGraphSHA256'],'placementPin':binding['placementPin'],'qualificationPin':binding['qualificationPin'],'stage':access.prepared_lineage(candidate,parent['preparedAccessPin'],parent['preparedDiskPins']),'stageRawBase64':__import__('base64').b64encode(__import__('libvirt_native').held(parent['preparedAccessPin'],1048576)).decode('ascii'),'data':proof['accessCustody']}
    need(v['context']is not None or proof['phase']=='NOT_PREPARED','missing context permits only actual NOT_PREPARED, never ACTIVE/CLOSED')
    need(proof['request']==request and proof['sourceSHA256']==request['observer']['sha256'] and proof['phase']in('NOT_PREPARED','PREPARED','ACTIVE','CLOSED')and proof['allOwnedDescriptorsClosed']is True and proof['effects']==[],'unchanged complete readonly observer proof and closure')
    # Every complete source and protected control is reread after observer use.
    for name,ref in v['parent']['sourceRoles'].items():need(io.read(ref,0o444,65536)==v['source'][name],'post-use exact source12 bytes')
    need(io.read(v['parentPin'],0o444,1048576)==v['parentRaw'],'post-use exact parent bytes')
    if v['context']is not None:
     need(io.read(v['contextPin'],0o400,1048576)==v['contextRaw'],'post-use exact context bytes');io.read(v['assignmentPin'],0o400,1048576);io.read(v['grantPin'],0o400,1048576)
    else:
     try:io.read_path(getattr(io,'runtimeRoot','/run/opemos-libvirt-runtime-'+NONCE)+'/context.json',0o400,1048576)
     except FileNotFoundError:pass
     else:raise RuntimeError('context absence changed during exact NOT_PREPARED observation; no retry')
    heldPlacement['recheck']();heldQualification['recheck']()
    result={'kind':'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION','upstreamObserver':v['parent']['sourceRoles']['libvirt_peer'],'implementation':{'actualAccessImplementation':v['implementationAccessPin'],'actualPeerImplementation':v['implementationPeerPin'],'contract':CONTRACT,'peer':v['parent']['sourceRoles']['libvirt_peer'],'access':v['parent']['sourceRoles']['libvirt_access'],'sourceRoles':v['parent']['sourceRoles'],'parent':v['parentPin'],'context':v['contextPin'],'assignment':v['assignmentPin'],'grant':v['grantPin'],'placementBinding':binding,'runtimePublication':snapshot,'borrowedRunCustody':io.runProof},'proof':proof,'effects':[]}
    if io.implementationPin is not None:result['implementation'].update(contract='CURRENT_NORMAL_CLOSED_SUBJECT_V1',implementationDefinitionPin=io.implementationPin)
    need(io.read(v['implementationPeerPin'],0o444,65536)==v['implementationPeerRaw']and io.read(v['implementationAccessPin'],0o444,65536)==v['implementationAccessRaw'],'held current pair reread after full observation')
    io.check()
 need(snapshot['readLockClosed']is True,'actual runtime read lock closed');need(len(canonical(result).encode())+1<=1048576,'unchanged whole Root1MiB envelope');return result

def main():
 compat=len(sys.argv)==6 and sys.argv[4]=='--implementation-definition-pin-json'and sys.argv[1]in(CLOSED_SUBJECT_PEERS|{PEER_SHA:PEER_BYTES})
 need(os.getuid()==0 and (compat or len(sys.argv)==4 and sys.argv[1]in(PEER_SHA,ORIGINAL_PEER_SHA))and sys.argv[2]=='--queue-libvirt-request-json','exact existing Root standalone queue argv')
 request=json.loads(sys.argv[3]);before=set(os.listdir('/proc/self/fd'))
 with RootInputs(request.get('currentControl'),json.loads(sys.argv[5])if compat else None)as io:result=run(request,io,Path('/proc/sys/kernel/random/boot_id').read_text().strip())
 need(before==set(os.listdir('/proc/self/fd')),'adapter full owned FD closure');print(canonical(result),flush=True)
if __name__=='__main__':
 try:main()
 except BaseException as e:
  print(canonical({'kind':'QUEUE_LIBVIRT_FIRST_REFUSAL','type':type(e).__name__,'reason':str(e),'effects':[],'evidence':getattr(e,'evidence',None),'workingEvidence':getattr(e,'workingEvidence',None),'placementCustody':getattr(e,'placementCustody',None),'runtimePublication':getattr(e,'runtimePublication',None),'rootInputCloseErrors':getattr(e,'ownedRootInputClosureErrors',[]),'rootFilesCloseErrors':getattr(e,'rootFilesCloseErrors',[]),'lockCloseErrors':getattr(e,'lockCloseErrors',[]),'ownedPlacementCloseErrors':getattr(e,'ownedPlacementCloseErrors',[]),'traceback':traceback.format_exc()}),file=sys.stderr,flush=True);sys.exit(1)

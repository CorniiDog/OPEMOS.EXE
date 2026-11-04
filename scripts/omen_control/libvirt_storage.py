import os,json,stat,re,hashlib
from pathlib import Path

def working_geometry(evidence,expected,installer,adopted,persist=None,config=None):
 """Optional observation sink cannot replace the genuine custody predicate."""
 from libvirt_peer import require_working_metadata
 errors=[]
 if persist is not None:
  try:persist('working-inode-geometry-before-predicate',evidence)
  except Exception as error:errors.append({'type':type(error).__name__,'reason':str(error),'diagnosticOnly':True})
 try:
  if adopted:__import__('retained_media').observe(config)
  value=require_working_metadata(evidence,expected,installer,adopted)
 except BaseException as error:
  if errors:error.optionalDiagnosticErrors=errors
  raise
 return value,errors

def storage_contract(nonce,request=None,persist=None):
 """Exact one declared Games regular-file container; no physical-device API."""
 from libvirt_peer import need,SOURCE_PLACEMENT_NONCE,SOURCE_PLACEMENT_PIN,RootFiles,CORE,ident,working_metadata,require_working_metadata,metadata_cohort
 need(nonce==SOURCE_PLACEMENT_NONCE,'same exact source/placement/job scope')
 ref=SOURCE_PLACEMENT_PIN;need(ref is not None,'new-scope protected placement pin UNISSUED; no D22 receipt adoption')
 with RootFiles(Path(ref['path']).parent)as files:
  raw,actual=files.read(Path(ref['path']).name);need(actual==ref,'immutable exact Root placement receipt full9/bytes/SHA')
 v=json.loads(raw);need(type(v)is dict and all(k in v for k in('kind','nonce','boot','original','working')),'complete recorded placement scope/roles');installer=v['kind']=='ROOT_EXACT_STEAMOS_INSTALLER_GAMES_PLACEMENT';need(v['kind']in('ROOT_EXACT_STEAMOS_FIXED_GAMES_PLACEMENT','ROOT_EXACT_STEAMOS_INSTALLER_GAMES_PLACEMENT')and v['nonce']==nonce and v['boot']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Root exact current placement scope/boot')
 config=__import__('guest_firmware_probe').storage_installer_config(v,nonce,v['boot'])if installer else None;graph=__import__('guest_firmware_probe').installer_contract(config)if installer else None
 need(v['wholeGraphUpperBound']==(graph['wholeGraphUpperBound']if installer else 58449672960)and v['wholeGraphUpperBound']<60000000000 and v['hostFloor']==72000000000,'whole60GB graph and unchanged20percent host headroom')
 if installer:__import__('guest_firmware_probe').authenticate_copy_receipt(config,v['boot']);need(v['backing']==v['installer']['backing']and v['retainedPartial']==v['installer']['retainedPartial'],'same entire charged backing and retained partial')
 fds=[];chain=[];diagnosticErrors=[];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd);chain.append(('/',fd));path=Path('/')
 try:
  for name in Path(v['placement']['path']).parts[1:]:
   fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);fds.append(fd);path=path/name;chain.append((str(path),fd))
  need(len(chain)==len(v['ancestry']),'closed exact placement ancestor list');before=[]
  for(path,fd),declared in zip(chain,v['ancestry']):
   a=ident(os.fstat(fd));b=ident(os.lstat(path));need(path==declared['path']and a==b and all(a[k]==declared['identity'][k]for k in CORE),'declared nofollow ancestor core/current FD/name '+path);before.append(a)
  def epoch(f,path):
   for _ in range(4):
    a=ident(os.fstat(f));b=ident(os.lstat(path));c=ident(os.fstat(f))
    if a==b==c:return a
   need(False,'bounded current mutable leaf FD/name epoch unstable '+path)
  partial=v['retainedPartial'];pf=os.open(Path(partial['path']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=chain[-1][1]);fds.append(pf);ps=ident(os.fstat(pf));need(ps==partial['identity']==ident(os.lstat(partial['path']))and ps['st_size']==1048576,'preserved previous partial exact full9');ph=hashlib.sha256();pn=0
  while chunk:=os.read(pf,65536):ph.update(chunk);pn+=len(chunk)
  need(pn==partial['bytes']and ph.hexdigest()==partial['sha256']and ident(os.fstat(pf))==partial['identity'],'preserved partial exact full content/EOF');parentfd=chain[-1][1];s=os.fstat(parentfd);need((s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(2051,93499,1000,1000,0o700),'only approved UID1000 parent boundary')
  expected=['storage-plan.json',Path(v['retainedPartial']['path']).name,Path(v['backing']['path']).name];retained=v.get('retainedPlacementLeaves',[])if installer else [];need(type(retained)is list and len(retained)<=4,'bounded preserved old backing metadata');
  for prior in retained:need(Path(prior['path']).parent==Path(v['placement']['path'])and ident(os.stat(Path(prior['path']).name,dir_fd=parentfd,follow_symlinks=False))==prior['identity'],'retained old backing custody only, no outer-digest authority');expected.append(Path(prior['path']).name)
  need(sorted(os.listdir(parentfd))==sorted(expected),'no foreign placement files/writers');bf=os.open(Path(v['backing']['path']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd);fds.append(bf);back=epoch(bf,v['backing']['path']);need(back==ident(os.lstat(v['backing']['path']))and all(back[k]==v['backing']['identity'][k]for k in CORE)and stat.S_ISREG(back['st_mode'])and back['st_uid']==back['st_gid']==0 and stat.S_IMODE(back['st_mode'])==0o600 and back['st_nlink']==1 and back['st_size']==v['backing']['bytes']and os.fstat(bf).st_blocks*512<=v['backingCharge'],'exact Root0 fixed bounded regular backing/current FD/name')
  loop=Path(v['loop']).name;need(re.fullmatch('loop[0-9]+',loop)is not None,'exact generated loop name');sysloop=Path('/sys/class/block')/loop/'loop';looprow={'backing':(sysloop/'backing_file').read_text().strip(),'offset':int((sysloop/'offset').read_text()),'sizelimit':int((sysloop/'sizelimit').read_text())};need(looprow['backing']==v['backing']['path']and looprow['offset']==0 and looprow['sizelimit']in(0,v['backing']['bytes']),'only generated file loop, no physical source')
  mf=os.open(v['mount']['path'],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(mf);mi=ident(os.fstat(mf));need(mi==ident(os.lstat(v['mount']['path']))and all(mi[k]==v['mount']['identity'][k]for k in('st_dev','st_ino','st_uid','st_gid')),'same exact Root ext4 mounted object')
  import libvirt_access as access;mode=stat.S_IMODE(mi['st_mode']);need(mode in(0o700,0o710),'only private or exact libvirt traversal mount mode')
  if mode==0o710:need(access.ACL().get(mf)==access.expected_acl(0o700,access.UID,'--x')[1],'exact generated mount-parent ACL')
  mid=int(next(x.split()[1]for x in Path('/proc/self/fdinfo',str(mf)).read_text().splitlines()if x.startswith('mnt_id:')));rows=[x for x in Path('/proc/self/mountinfo').read_text().splitlines()if int(x.split()[0])==mid];need(len(rows)==1 and rows[0].split()[4]==v['mount']['path']and' - ext4 '+v['loop']+' 'in rows[0]and rows[0].split()[2]==(Path('/sys/class/block')/loop/'dev').read_text().strip(),'exact current namespace ext4/loop mount relation')
  captureScope={'nonce':nonce,'jobId':None if request is None else request['jobId'],'normalizedSpecSHA256':None if request is None else request['specSHA256'],'placementReceiptPin':ref}
  try:wf=os.open('working.raw',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=mf)
  except BaseException as error:
   evidence=working_metadata(None,mf,v['working']['path'],v['working'],captureScope,'storage-working-before-predicate',error);error.workingEvidence=evidence
   if persist is not None:
    try:persist('working-inode-geometry-before-predicate',evidence)
    except BaseException as secondary:error.capturePersistenceError={'type':type(secondary).__name__,'reason':str(secondary)}
   raise
  fds.append(wf);evidence=working_metadata(wf,mf,v['working']['path'],v['working'],captureScope,'storage-working-before-predicate')
  adopted=installer and __import__('retained_media').is_adopted(config)
  wi,diagnosticErrors=working_geometry(evidence,v['working'],installer,adopted,persist,config);wmode=stat.S_IMODE(wi['st_mode']);need(wmode in((0o600,0o640)if installer else(0o600,0o660)),'only private or exact libvirt working mode')
  if wmode!=0o600 and not adopted:need(access.ACL().get(wf)==access.expected_acl(0o600,access.UID,'r--'if installer else'rw-')[1],'exact generated working ACL')
  inner=os.fstatvfs(mf);outer=os.fstatvfs(parentfd);need(inner.f_blocks*inner.f_frsize<=v['backing']['bytes']and inner.f_bavail*inner.f_frsize>=(134217728 if installer else 3000000000) and os.fstat(wf).st_blocks*512<=v['backing']['bytes'],'hard fixed filesystem/inner allocation plus20percent backing growth separation');need(outer.f_bavail*outer.f_frsize>=72000000000,'actual Games after-allocation72GB headroom')
  need(set(os.listdir(mf)).issubset({'lost+found','working.raw','run','output'}),'only finite declared inner IO roots')
  for(path,fd),old in zip(chain,before):
   now=ident(os.fstat(fd));need(now==ident(os.lstat(path))and all(now[k]==old[k]for k in CORE),'current placement ancestor core/FD/name after check')
  afterBack=epoch(bf,v['backing']['path']);afterWorking=epoch(wf,v['working']['path']);need(all(afterBack[k]==back[k]for k in CORE+('st_size',))and all(afterWorking[k]==wi[k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size')),'same only declared mutable backing/working core after use')
  roots=[str(Path(ref['path']).parent),str(Path(__file__).parent),'/var/lib/opemos-queue-r113-f276aacd8a994f30bfc4097c15cdb945','/run/opemos-closed-e842-r111-runtime','/run/opemos-root-source239-cd9ef0826364409da287f6f3e3830c95-e842cfa1daa5412aba5d454cca9ab58f','/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r110b','/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r109b','/var/lib/opemos-queue-r109-f55b98f9f6e8406086a22a4b58fa502b','/run/opemos-root-source239-cd9ef0826364409da287f6f3e3830c95-6b6443deca894d1e96e326b6f428d491','/var/lib/opemos-queue-r110-21f60c09e156455daab0410c6c374fda','/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r107b','/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r109','/run/opemos-root-source239-cd9ef0826364409da287f6f3e3830c95-34117bbb1f4d4418b4eff9c1190233f2','/run/opemos-closed-34117-r109-runtime','/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r106','/run/opemos-root-source239-cd9ef0826364409da287f6f3e3830c95-96af5ac9637c40309055725bb9df0c17','/run/opemos-closed-e87-96af5ac9637c40309055725bb9df0c17-runtime','/run/opemos-closed-e87-96af5ac9637c40309055725bb9df0c17-lease','/run/opemos-closed-e87-96af5ac9637c40309055725bb9df0c17-results','/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r104','/run/opemos-steamos-source-' + nonce,'/run/opemos-libvirt-runtime-' + nonce,'/run/opemos-libvirt-results-' + nonce,'/run/opemos-vfio-' + nonce,'/run/opemos-steamos-prequeue-' + nonce,'/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r110','/var/lib/opemos-queue-r110-f49013fb03dd4b3db0079c99a7c41dba']
  socket=None
  if adopted:
   io=v['ioScope'];need(set(io)=={'run','output'}and Path(io['run']).parent==Path(io['output']).parent and Path(io['run']).parent.parent==Path('/run')and Path(io['run']).name=='run'and Path(io['output']).name=='output'and Path(io['run']).parent.name.startswith('opemos-libvirt-io-'+nonce+'-'),'declared current writable IO only');roots+=list(io.values());socket=io['run']+'/vnc.sock'
   operation=v['operationRoot'];need(re.fullmatch('/run/opemos-current-media-[0-9a-f]{32}',operation)is not None,'exact owned current preparation root');roots.append(operation)
   queueRoot=v['currentQueueRoot'];need(re.fullmatch('/var/lib/opemos-queue-r120-[0-9a-f]{32}',queueRoot)is not None,'exact installed current queue metadata charge');roots.append(queueRoot)
  if request is not None:roots+=['/run/opemos-libvirt-queue-'+request['jobToken'],'/home/connor/.local/state/opemos-test-queue-r2/state/logs/'+request['jobId']]
  observedExtra,entries,metadataClosure=__import__('guest_firmware_probe').metadata_cohort(roots,allowed_socket=socket);need(observedExtra<=500000000,'all metadata/source/capture/private SQL growth remains in declared500MB reserve')
  return{'receiptPin':ref,'wholeGraphUpperBound':v['wholeGraphUpperBound'],'outerAvailableBytes':outer.f_bavail*outer.f_frsize,'backingCurrent':ident(os.fstat(bf)),'backingCharge':v['backingCharge'],'innerAvailableBytes':inner.f_bavail*inner.f_frsize,'innerAllocatedWorkingBytes':os.fstat(wf).st_blocks*512,'currentMountID':mid,'loop':looprow,'workingCurrent':wi,'workingAfter':afterWorking,'workingObservation':evidence,'extraIOObservedBytes':observedExtra,'extraIOEntries':entries,'metadataFDClosure':metadataClosure,'mutableEpochsOnlyForDeclaredBackingWorkingAndMount':True,'optionalDiagnosticErrors':diagnosticErrors}
 except BaseException as error:
  if diagnosticErrors:error.optionalDiagnosticErrors=diagnosticErrors
  raise
 finally:
  for fd in fds[::-1]:os.close(fd)

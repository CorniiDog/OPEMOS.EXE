"""Proposed supplemental read-only guest EFI measurement, not installed.

Runs before the existing reporter on each boot after a separately reviewed
generated-service delta. Existing reporter/ledger schema and nonce stay intact.
No package/tool install, efivar write, guest input or firmware setting operation.
"""
import base64,hashlib,json,os,re,stat,struct
from pathlib import Path
GUID='8be4df61-93ca-11d2-aa0d-00e098032b8c'
def read(name,root=Path('/sys/firmware/efi/efivars')):
 fd=os.open(root/(name+'-'+GUID),os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  b=os.read(fd,65537)
  if len(b)>65536 or os.read(fd,1):raise ValueError('EFI variable finite EOF')
  return b
 finally:os.close(fd)
def measure(nonce,guest_uuid,reader=read):
 if re.fullmatch('[0-9a-f]{32}',nonce)is None:raise ValueError('scope nonce')
 current=reader('BootCurrent');order=reader('BootOrder')
 if len(current)!=6 or len(order)<6 or len(order)>2048 or len(order[4:])%2:raise ValueError('EFI BootCurrent/Order shape')
 boot=struct.unpack('<H',current[4:])[0];option=reader('Boot%04X'%boot)
 if len(option)<12:raise ValueError('finite EFI load option')
 return {'kind':'ACTUAL_LIBVIRT_GUEST_EFI_ROUTE_V1','nonce':nonce,'guestUUID':guest_uuid,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'BootCurrent':boot,'BootOrder':list(struct.unpack('<'+'H'*(len(order[4:])//2),order[4:])),'variables':[{'name':name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'base64':base64.b64encode(b).decode()}for name,b in [('BootCurrent',current),('BootOrder',order),('Boot%04X'%boot,option)]]}
def frame(value):
 b=json.dumps(value,sort_keys=True,separators=(',',':')).encode();out=b'OPEMOS_LIBVIRT_FIRMWARE_V1 '+value['nonce'].encode()+b' '+hashlib.sha256(b).hexdigest().encode()+b' '+base64.b64encode(b)+b'\n'
 if len(out)>131072:raise ValueError('firmware serial frame cap')
 return out
if __name__=='__main__':
 import sys
 if len(sys.argv)!=3:raise ValueError('exact nonce/UUID operands')
 raw=frame(measure(sys.argv[1],sys.argv[2]));fd=os.open('/dev/ttyS0',os.O_WRONLY|os.O_NOCTTY|os.O_CLOEXEC)
 try:
  if not stat.S_ISCHR(os.fstat(fd).st_mode):raise ValueError('existing serial route character device')
  view=memoryview(raw)
  while view:
   n=os.write(fd,view)
   if n<=0:raise ValueError('serial write progress')
   view=view[n:]
 finally:os.close(fd)


# Carrier and raw boot payload are distinct authenticated roles. No original
# raw file is copied to OMEN in addition to the charged container: its exact
# counterpart receipt supplies the expected raw digest, and this producer reads
# the one bounded member extent directly from the retained charged carrier.
CARRIER_BYTES=8121049088
CARRIER_SHA='2fc5f2b8992f93deccf66e79133c6ceeb9d8ec2acda82c12ac641dc65cf7a193'
RAW_BYTES=8120172544
RAW_SHA='f9aa0fa2dd618febf28a5e2a583d1e2b5a8ca3f1205be965da584602ac962f40'
RAW_OFFSET=567296
RAW_MEMBER='/STEAMOS/steamdeck-repair-latest.img'
INSTALLER_BACKING_BYTES=8400000000
INSTALLER_METADATA_BYTES=500000000
RAW_KIND='AUTHENTICATED_F9AA_RAW_RECOVERY_USB_FIRSTBOOT'

def raw_extent():return {'carrierOffset':RAW_OFFSET,'bytes':RAW_BYTES,'sha256':RAW_SHA,'memberPath':RAW_MEMBER}

def storage_installer_config(value,nonce,boot):
 import libvirt_peer as p
 p.need(all(k in value for k in('nonce','boot','original','working','installer')),'complete recorded storage scope and roles; no omitted-field fallback')
 p.need(nonce==p.SOURCE_PLACEMENT_NONCE and value['nonce']==nonce and value['boot']==boot,'authenticated recorded storage nonce/boot equality; no ambient substitution')
 return {'nonce':value['nonce'],'hostBoot':value['boot'],'original':value['original'],'working':value['working'],'installer':value['installer']}

def installer_contract(c):
 import libvirt_peer as p
 p.need(all(k in c for k in('nonce','hostBoot'))and c['nonce']==p.SOURCE_PLACEMENT_NONCE and type(c['hostBoot'])is str and bool(c['hostBoot']),'complete explicit installer nonce/hostBoot, never defaulted')
 v=c.get('installer')
 if v is None:return None
 adopted=__import__('retained_media').is_adopted(c)
 keys={'kind','carrierSource','rawExtent','bootCopy','backing','retainedR66','retainedPartial','metadataReserve','noInstallTarget','maxBoots','measurement'}|({'currentCustodyPin','currentCustody'}if adopted else{'copyReceiptPin','copyReceipt'})
 p.need(type(v)is dict and set(v)==keys,'closed purpose-bound carrier/raw/current-custody firstboot schema')
 p.need(v['kind']in(RAW_KIND,__import__('retained_media').KIND) and v['noInstallTarget']is True and v['maxBoots']==1 and v['measurement']=='GRAPHICAL_FIRST_RECOVERY_DIAGNOSTIC','raw recovery firstboot only; no install/update/restart')
 p.need(v['bootCopy']==c['working']and v['rawExtent']==raw_extent(),'working is exact f9aa member-derived readonly USB, never outer carrier')
 refs=[c['original'],v['retainedR66'],v['carrierSource'],v['backing'],v['retainedPartial'],v['bootCopy']]
 p.need(all(type(r)is dict and set(r)=={'path','bytes','sha256','identity'}for r in refs),'all full role pins')
 p.need(len({(r['identity']['st_dev'],r['identity']['st_ino'])for r in refs})==6,'distinct charged files; no aliases')
 for r in refs:
  i=r['identity'];p.need(stat.S_ISREG(i['st_mode'])and i['st_nlink']==1 and i['st_size']==r['bytes'],'regular single-link role geometry')
 p.need(c['original']['bytes']==v['retainedR66']['bytes']==21474836480,'original and R66 charges retained')
 p.need(v['carrierSource']['bytes']==CARRIER_BYTES and v['carrierSource']['sha256']==CARRIER_SHA and v['carrierSource']['identity']['st_uid']==v['carrierSource']['identity']['st_gid']==1000,'exact UID1000 outer carrier retained, not booted or relabelled')
 p.need(v['bootCopy']['bytes']==RAW_BYTES and v['bootCopy']['sha256']==RAW_SHA,'actual authenticated raw member bytes, never carrier hash/geometry')
 for r in((v['backing'],)if adopted else(v['bootCopy'],v['backing'])):p.need(r['identity']['st_uid']==r['identity']['st_gid']==0 and stat.S_IMODE(r['identity']['st_mode'])in(0o600,0o640),'generated Root custody and exact read-only libvirt ACL')
 p.need(v['backing']['bytes']==INSTALLER_BACKING_BYTES and v['retainedPartial']['bytes']==1048576 and v['metadataReserve']==INSTALLER_METADATA_BYTES,'full fixed backing/partial/metadata charge')
 if adopted:__import__('retained_media').contract(c)
 else:
  receipt=v['copyReceipt'];ref=v['copyReceiptPin'];encoded=p.canon(receipt);validate_carrier_custody(v['carrierSource'],receipt.get('carrierMountCustody'),c['hostBoot'])
  p.need(receipt['nonce']==c['nonce']and receipt['bootID']==c['hostBoot']and ref['path']=='/run/opemos-steamos-placement-'+c['nonce']+'/raw-recovery-copy.json','same purpose/scope/host raw copy receipt, not historical or foreign')
  p.need(type(ref)is dict and set(ref)=={'path','bytes','sha256','identity'}and stat.S_ISREG(ref['identity']['st_mode'])and ref['identity']['st_size']==len(encoded),'complete regular receipt full pin')
  p.need(ref['bytes']==len(encoded)and ref['sha256']==hashlib.sha256(encoded).hexdigest()and ref['identity']['st_uid']==ref['identity']['st_gid']==0 and stat.S_IMODE(ref['identity']['st_mode'])==0o400 and ref['identity']['st_nlink']==1,'exact complete Root0400 raw-copy receipt binding')
  p.need(receipt['kind']=='ROOT_AUTHENTICATED_CARRIER_TO_RAW_BOOT_COPY'and receipt['runtimeAuthorized']is False and receipt['carrierBefore']==receipt['carrierAfter']==v['carrierSource']and receipt['extent']==raw_extent()and receipt['carrierWholeSHA256']==CARRIER_SHA and receipt['rawBytes']==RAW_BYTES and receipt['rawSHA256']==RAW_SHA,'whole original carrier -> exact raw member proof, no source relabel')
  closure=receipt.get('ownedFDClosure');p.need(type(closure)is dict and closure['allCopyOwnedFDsClosed']is True and closure['FDSetRestored']is True and closure['unknown']is False and closure['secondary']==[],'complete new raw producer closure, no boolean-only or secondary suppression')
  owned=closure['ownedClosure'];p.need(owned['allClosed']is True and owned['unknown']is False and owned['mustRefuse']is False and owned['errors']==[]and owned['eachEntryConsumedOnce']is True and 0<len(owned['rows'])<=64 and all(len(r)==7 and r[5]is True and r[6]is True for r in owned['rows']),'each raw descriptor close attempted once and known; no unknown acceptance')
  target=receipt['target'];p.need(closure['partial']['path']==target['path']and closure['partial']['identity']==target['identity']and any(r[0]=='rawT'and r[2]==[target['identity']['st_dev'],target['identity']['st_ino'],stat.S_IFMT(target['identity']['st_mode'])]for r in owned['rows'])and any(r[0]=='rawA'and r[2]==[v['carrierSource']['identity']['st_dev'],v['carrierSource']['identity']['st_ino'],stat.S_IFMT(v['carrierSource']['identity']['st_mode'])]for r in owned['rows']),'closure records join exact target and held carrier objects')
  p.need(target['path']==v['bootCopy']['path']and target['bytes']==RAW_BYTES and target['sha256']==RAW_SHA and all(target['identity'][k]==v['bootCopy']['identity'][k]for k in('st_dev','st_ino','st_uid','st_gid','st_nlink','st_size'))and receipt['fsynced']is True and receipt['targetRereadEOF']is True and receipt['allOwnedFDsClosed']is True,'same byte target/current postACL inode and producer close proof')
 charged=[{'role':'original','pin':c['original'],'upperBytes':21474836480},{'role':'R66','pin':v['retainedR66'],'upperBytes':21474836480},{'role':'retainedCarrier','pin':v['carrierSource'],'upperBytes':CARRIER_BYTES},{'role':'entireContainerIncludingRawBootCopyAndIO','pin':v['backing'],'upperBytes':INSTALLER_BACKING_BYTES},{'role':'retainedPartial','pin':v['retainedPartial'],'upperBytes':1048576},{'role':'externalSourcePrivateSQLMetadataCapture','pin':None,'upperBytes':INSTALLER_METADATA_BYTES}]
 total=sum(r['upperBytes']for r in charged);p.need(total<=60000000000,'all simultaneous files charged under literal60GB; no extra raw copy')
 return {'kind':v['kind'],'charged':charged,'wholeGraphUpperBound':total,'literalLimit':60000000000,'headroom':60000000000-total,'mutableInstallTarget':False,'rawBootCopyChargedInsideEntireBacking':True,'noSeparateOMENRawOriginalOrScratchCopy':True,'maxBoots':1}

def authenticate_copy_receipt(c,boot):
 from libvirt_native import held
 import libvirt_peer as p
 if __import__('retained_media').is_adopted(c):
  installer_contract(c);p.need(c['hostBoot']==boot,'current custody caller boot');__import__('retained_media').observe(c);return c['installer']['currentCustodyPin']
 installer_contract(c);p.need(c['hostBoot']==boot,'copy receipt caller and recorded host boot equality');v=c['installer'];raw=held(v['copyReceiptPin'],1048576)
 p.need(raw==p.canon(v['copyReceipt'])and v['copyReceipt']['bootID']==boot,'held actual same-host raw-copy receipt, not model or controller identity')
 return v['copyReceiptPin']


# One finite already-authenticated retained carrier on the user-approved Games
# volume. This exception never applies to another path, leaf, filesystem or role.
CARRIER_PATH='/media/connor/Games/OPEMOS/Windows-AppTest-20261019-pr189-r1/input/steamos-original-verified.iso'
CARRIER_GAMES='/media/connor/Games'
CARRIER_BOOT='3b85fc38-1344-4482-9517-be651ca4d9a6'

def _carrier_role(ref):
 import libvirt_peer as p
 p.need(type(ref)is dict and set(ref)=={'path','bytes','sha256','identity'},'closed retained carrier role pin')
 i=ref['identity'];p.need(ref['path']==CARRIER_PATH and ref['bytes']==CARRIER_BYTES and ref['sha256']==CARRIER_SHA and set(i)==set(p.FIELDS),'exact retained authenticated carrier path/bytes/hash')
 p.need([i[k]for k in p.CORE]==[2051,91770,0o100600,1000,1000,1]and i['st_size']==CARRIER_BYTES,'exact retained carrier device/inode/owner/mode/link/geometry')

def validate_carrier_mount_proof(ref,v):
 import libvirt_peer as p
 _carrier_role(ref);p.need(type(v)is dict and set(v)=={'kind','nonce','bootID','sourcePin','GamesPath','GamesIdentity','mount','readOnlyFD','heldNamedEqual','procFDsClosed'},'closed carrier mount custody record')
 p.need(v['kind']=='EXACT_RETAINED_CARRIER_GAMES_MOUNT_V1'and v['nonce']==p.SOURCE_PLACEMENT_NONCE and type(v['bootID'])is str and bool(v['bootID']) and v['sourcePin']==ref and v['GamesPath']==CARRIER_GAMES,'same finite carrier/source scope/host')
 i=v['GamesIdentity'];p.need(set(i)==set(p.FIELDS)and[i[k]for k in p.CORE]==[2051,5,0o40777,1000,1000,1],'only exact approved shared Games root, not a general writable ancestor')
 m=v['mount'];p.need(type(m)is dict and set(m)=={'mountId','parentId','majorMinor','root','target','mountOptions','optional','fsType','source','superOptions'},'closed actual selected mount record')
 p.need(type(m['mountId'])is int and m['mountId']>0 and type(m['parentId'])is int and m['parentId']>0 and m['majorMinor']=='8:3'and m['root']=='/'and m['target']==CARRIER_GAMES and m['fsType']=='ntfs3'and m['source']=='/dev/sda3','exact current device/filesystem/mount target; mount IDs stay process-local observations')
 p.need(len(m['mountOptions'])==4 and set(m['mountOptions'])=={'rw','nosuid','nodev','relatime'}and len(m['superOptions'])==6 and set(m['superOptions'])=={'rw','uid=1000','gid=1000','acl','iocharset=utf8','prealloc'},'exact observed NTFS ownership/ACL/options, no remount or permission weakening')
 p.need(type(m['optional'])is list and len(m['optional'])<=3 and all(type(x)is str and re.fullmatch(r'(shared|master|propagate_from):[1-9][0-9]*',x)for x in m['optional']),'bounded known propagation facts, no unknown optional mount flags')
 p.need(v['readOnlyFD']is True and v['heldNamedEqual']is True and v['procFDsClosed']is True,'actual readonly held/name and kernel metadata closure')
 return v

def _carrier_kernel_text(path,cap):
 import libvirt_peer as p
 owned=[];first=None;out=b'';fd=None
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);own_descriptor(owned,fd,'carrier-proc')
  while b:=os.read(fd,65536):out+=b;p.need(len(out)<=cap,'bounded complete carrier kernel record')
 except BaseException as error:first=error
 finally:
  proof,close=close_owned_descriptors(owned)
  if first is None:first=close
 if first is not None:first.carrierKernelClose=proof;raise first
 return out.decode()

def _carrier_mnt_id(fd):
 import libvirt_peer as p
 rows=[x.split()[1]for x in _carrier_kernel_text('/proc/self/fdinfo/'+str(fd),65536).splitlines()if x.startswith('mnt_id:')];p.need(len(rows)==1 and rows[0].isdigit(),'one actual held FD mount ID');return int(rows[0])

def carrier_shared_ancestor(ref,path,fd,row):
 import libvirt_peer as p,fcntl
 if str(path)!=CARRIER_GAMES or ref.get('path')!=CARRIER_PATH:return None
 _carrier_role(ref);p.need(row==p.ident(os.fstat(fd))==p.ident(os.lstat(CARRIER_GAMES)),'Games full9 held/name epoch equal before use')
 p.need(fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY,'Games anchor held readonly');boot=_carrier_kernel_text('/proc/sys/kernel/random/boot_id',128).strip();mid=_carrier_mnt_id(fd);matches=[]
 for line in _carrier_kernel_text('/proc/self/mountinfo',1048576).splitlines():
  fields=line.split();p.need(len(fields)>=10 and '-'in fields,'complete mountinfo row');cut=fields.index('-')
  if fields[0]==str(mid):matches.append({'mountId':int(fields[0]),'parentId':int(fields[1]),'majorMinor':fields[2],'root':fields[3],'target':fields[4],'mountOptions':fields[5].split(','),'optional':fields[6:cut],'fsType':fields[cut+1],'source':fields[cut+2],'superOptions':fields[cut+3].split(',')})
 p.need(len(matches)==1,'exact one actual FD-selected source mount');v={'kind':'EXACT_RETAINED_CARRIER_GAMES_MOUNT_V1','nonce':p.SOURCE_PLACEMENT_NONCE,'bootID':boot,'sourcePin':ref,'GamesPath':CARRIER_GAMES,'GamesIdentity':row,'mount':matches[0],'readOnlyFD':True,'heldNamedEqual':True,'procFDsClosed':True};return validate_carrier_mount_proof(ref,v)

def finish_carrier_ancestry(ref,guards,leaf_fd):
 import libvirt_peer as p,fcntl
 if ref.get('path')!=CARRIER_PATH:p.need(not guards,'no carrier exception for foreign role');return None
 p.need(len(guards)==1,'one declared carrier shared mount anchor required');fd,before=guards[0];after=carrier_shared_ancestor(ref,CARRIER_GAMES,fd,p.ident(os.fstat(fd)))
 p.need(after==before,'source mount/owner/mode/inode/options/full9 drift during use');p.need(_carrier_mnt_id(leaf_fd)==after['mount']['mountId']and p.ident(os.fstat(leaf_fd))==ref['identity']==p.ident(os.lstat(ref['path']))and fcntl.fcntl(leaf_fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY,'exact readonly leaf on same original mount; no hidden bind/alias/drift')
 return {'before':before,'after':after}

def validate_carrier_custody(ref,custody,boot):
 import libvirt_peer as p
 if ref.get('path')!=CARRIER_PATH:p.need(custody is None,'foreign source cannot claim approved Games custody');return None
 p.need(type(custody)is dict and set(custody)=={'before','after'}and custody['before']==custody['after'],'complete unchanged source mount custody before/after');validate_carrier_mount_proof(ref,custody['before']);p.need(custody['before']['bootID']==boot,'same authenticated source host boot');return custody


def _stream_extent(source,target,offset,count,expected,deadline,tick=lambda:None):
 import time
 import libvirt_peer as p
 h=hashlib.sha256();written=0
 while written<count:
  p.need(time.time()<deadline,'original finite raw-copy clock');tick();b=os.pread(source,min(65536,count-written),offset+written);p.need(bool(b),'full raw member EOF before target completion');h.update(b);view=memoryview(b)
  while view:
   n=os.write(target,view);p.need(n>0,'raw-copy write progress');view=view[n:]
  written+=len(b)
 p.need(written==count and h.hexdigest()==expected,'actual raw member length/SHA, no carrier relabel');os.fsync(target);h=hashlib.sha256();n=0
 while n<count:
  p.need(time.time()<deadline,'original finite raw readback clock');tick();b=os.pread(target,min(65536,count-n),n);p.need(bool(b),'complete raw target reread');h.update(b);n+=len(b)
 p.need(not os.pread(target,1,count)and n==count and h.hexdigest()==expected,'full target SHA and exact EOF after fsync')
 return {'rawBytes':written,'rawSHA256':h.hexdigest(),'fsynced':True,'targetRereadEOF':True}

def own_descriptor(owned,fd,role):
 import fcntl
 row={'fd':fd,'role':role,'core':None,'flags':None,'fdFlags':None};owned.append(row)
 s=os.fstat(fd);row.update(core=[s.st_dev,s.st_ino,stat.S_IFMT(s.st_mode)],flags=fcntl.fcntl(fd,fcntl.F_GETFL),fdFlags=fcntl.fcntl(fd,fcntl.F_GETFD));return fd

def fd_error(error,role,fd,stage):return {'role':role,'fd':fd,'stage':stage,'type':type(error).__name__,'reason':str(error),'errno':getattr(error,'errno',None)}

def close_owned_descriptors(owned):
 """Consume each acquired entry BEFORE one close attempt; never close unknown."""
 import fcntl,errno
 rows=[];errors=[];first=None;unknown=False
 while owned:
  item=owned.pop();fd=item['fd'];role=item['role'];attempted=False;closed=False
  try:
   s=os.fstat(fd);current=[s.st_dev,s.st_ino,stat.S_IFMT(s.st_mode)]
   if item['core']is None or current!=item['core']or fcntl.fcntl(fd,fcntl.F_GETFL)!=item['flags']or fcntl.fcntl(fd,fcntl.F_GETFD)!=item['fdFlags']:raise RuntimeError('owned descriptor object/flags unproved; no unknown close')
   attempted=True
   try:os.close(fd);closed=True
   except BaseException as error:
    errors.append(fd_error(error,role,fd,'close'));first=first or error
    try:os.fstat(fd)
    except OSError as after:
     if after.errno==errno.EBADF:closed=True
     else:errors.append(fd_error(after,role,fd,'after-close-inspection'))
    except BaseException as after:errors.append(fd_error(after,role,fd,'after-close-inspection'))
  except BaseException as error:errors.append(fd_error(error,role,fd,'ownership-inspection'));first=first or error
  unknown=unknown or not closed;rows.append([role,fd,item['core'],item['flags'],item['fdFlags'],attempted,closed])
 proof={'rowSchema':['role','fd','objectCore','openFlags','descriptorFlags','closeAttempted','closedObserved'],'rows':rows,'errors':errors,'unknown':unknown,'allClosed':not unknown,'mustRefuse':bool(errors)or unknown,'eachEntryConsumedOnce':True}
 return proof,first

def finish_raw_copy(owned,target,path,primary,before):
 partial=None;secondary=[];first=primary
 if target is not None:
  try:
   s=os.fstat(target);partial={'path':path,'identity':{k:getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')},'retained':True}
  except BaseException as error:secondary.append(fd_error(error,'rawT',target,'partial-metadata'));first=first or error
 proof,close_error=close_owned_descriptors(owned);first=first or close_error
 try:restored=before==set(os.listdir('/proc/self/fd'))
 except BaseException as error:restored=False;secondary.append(fd_error(error,'raw',None,'final-FD-set'));first=first or error
 evidence={'partial':partial,'ownedClosure':proof,'secondary':secondary,'FDSetRestored':restored,'allCopyOwnedFDsClosed':proof['allClosed']and restored,'unknown':proof['unknown']or not restored,'noCleanupOrSourceWrite':True}
 if first is None and evidence['unknown']:first=RuntimeError('raw copy FD closure unproved; no acceptance')
 if first is not None:first.closeEvidence=evidence;first.rawCopyEvidence=evidence
 return first,evidence

def prepare_raw_boot_copy(expectation_pin,carrier_fd,mount_fd,backing_fd,persist):
 """Existing Root preparation only; never called during source qualification.
 No source/mount/container creation, grant issuance, cleanup or runtime effect.
 """
 import time,fcntl,sys
 import libvirt_peer as p,libvirt_preflight as pre,libvirt_producer as prod
 from libvirt_native import held
 before=set(os.listdir('/proc/self/fd'));target=None;target_path=None;result=None;owned=[];first=None
 try:
  e=json.loads(held(expectation_pin,1048576));now=time.time();p.need(os.getuid()==0 and expectation_pin['identity']['st_uid']==expectation_pin['identity']['st_gid']==0 and stat.S_IMODE(expectation_pin['identity']['st_mode'])==0o400,'existing protected Root preparation expectation')
  p.need(e['kind']=='ROOT_LIBVIRT_R4_PREFLIGHT_EXPECTATION'and e['RootAdopted']is True and e['purpose']=='INSTALLER_BOOT_READY'and e['issuedUnix']<=now<e['startBeforeUnix']<=e['issuedUnix']+300,'same original finite normal preparation only')
  p.need(e['nonce']==p.SOURCE_PLACEMENT_NONCE and e['bootID']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'current boot/fresh source scope')
  v=e['rawMediaPreparation'];source=v['carrier'];back=v['backing'];mount=v['mount'];p.need(len(Path(source['path']).parts)<=32,'bounded raw source ancestry/owned descriptor set');p.need(source['bytes']==CARRIER_BYTES and source['sha256']==CARRIER_SHA and v['extent']==raw_extent(),'exact pre-reviewed carrier/member roles')
  p.need(p.ident(os.fstat(carrier_fd))==source['identity']==p.ident(os.lstat(source['path']))and fcntl.fcntl(carrier_fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY,'actual immutable source held O_RDONLY full9')
  p.need(Path(back['path']).parent==Path('/media/connor/Games/OPEMOS/SteamOS-test-storage-20261027-ae79cd4de452')and back['bytes']==INSTALLER_BACKING_BYTES and stat.S_ISREG(os.fstat(backing_fd).st_mode)and os.fstat(backing_fd).st_size==INSTALLER_BACKING_BYTES and p.ident(os.fstat(backing_fd))==p.ident(os.lstat(back['path']))and all(p.ident(os.fstat(backing_fd))[k]==back['identity'][k]for k in p.CORE),'only exact charged regular backing in approved parent')
  p.need(p.ident(os.fstat(mount_fd))==mount['identity']==p.ident(os.lstat(mount['path']))and stat.S_ISDIR(mount['identity']['st_mode'])and mount['identity']['st_uid']==mount['identity']['st_gid']==0 and stat.S_IMODE(mount['identity']['st_mode'])==0o700,'fresh private held mount directory')
  mid=int(next(x.split()[1]for x in Path('/proc/self/fdinfo',str(mount_fd)).read_text().splitlines()if x.startswith('mnt_id:')));rows=[x for x in Path('/proc/self/mountinfo').read_text().splitlines()if int(x.split()[0])==mid];p.need(len(rows)==1 and rows[0].split()[4]==mount['path']and' - ext4 '+v['loop']+' 'in rows[0],'existing exact ext4 mount, no raw/physical write')
  loop=Path(v['loop']).name;p.need(re.fullmatch('loop[0-9]+',loop)is not None,'generated loop only');lp=Path('/sys/class/block')/loop/'loop';p.need((lp/'backing_file').read_text().strip()==back['path']and int((lp/'offset').read_text())==0 and int((lp/'sizelimit').read_text())in(0,INSTALLER_BACKING_BYTES),'loop is confined exact charged regular backing')
  p.need(v['original']['bytes']==v['retainedR66']['bytes']==21474836480 and v['retainedPartial']['bytes']==1048576 and v['metadataReserve']==INSTALLER_METADATA_BYTES and v['wholeGraphUpperBound']==sum((v['original']['bytes'],v['retainedR66']['bytes'],CARRIER_BYTES,INSTALLER_BACKING_BYTES,1048576,INSTALLER_METADATA_BYTES))<=60000000000,'all simultaneous original/R66/carrier/container/partial/metadata charged before copy; no second raw file')
  outer=os.fstatvfs(backing_fd);p.need(outer.f_bavail*outer.f_frsize>=72000000000,'unchanged actual after-allocation host headroom before copy')
  p.need(set(os.listdir(mount_fd)).issubset({'lost+found','run','output'})and not os.path.lexists(mount['path']+'/working.raw'),'create-only absent raw target, no old carrier-copy overwrite');space=os.fstatvfs(mount_fd);p.need(space.f_blocks*space.f_frsize<=INSTALLER_BACKING_BYTES and space.f_bavail*space.f_frsize>=RAW_BYTES+134217728,'actual complete raw copy plus unchanged inner reserve before write')
  # Held, nofollow source ancestry before the whole carrier hash and copy.
  fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);own_descriptor(owned,fd,'rawA');anc=[('/',fd,p.ident(os.fstat(fd)))];at=Path('/');shared=[]
  for name in Path(source['path']).parts[1:]:
   fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);own_descriptor(owned,fd,'rawA');at=at/name;a=p.ident(os.fstat(fd));admission=carrier_shared_ancestor(source,str(at),fd,a);p.need((a['st_uid']in(0,1000)and not(a['st_mode']&0o022))or admission is not None,'readonly admitted source ancestry');shared.extend([]if admission is None else[(fd,admission)]);anc.append((str(at),fd,a))
  p.need(p.ident(os.fstat(fd))==source['identity'],'source ancestry ends at exact held carrier');h=hashlib.sha256();n=0
  while b:=os.pread(carrier_fd,65536,n):
   p.need(time.time()<e['startBeforeUnix'],'original preparation hash clock');h.update(b);n+=len(b);p.need(n<=CARRIER_BYTES,'no source growth beyond exact carrier read budget')
  p.need((n,h.hexdigest())==(CARRIER_BYTES,CARRIER_SHA),'whole carrier bytes/hash before member copy')
  target_path=mount['path']+'/working.raw';target=os.open('working.raw',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=mount_fd);own_descriptor(owned,target,'rawT');os.fchmod(target,0o600);value=_stream_extent(carrier_fd,target,RAW_OFFSET,RAW_BYTES,RAW_SHA,e['startBeforeUnix']);os.fsync(mount_fd);ts=os.fstat(target);path=mount['path']+'/working.raw';p.need(p.ident(ts)==p.ident(os.stat('working.raw',dir_fd=mount_fd,follow_symlinks=False))and ts.st_uid==ts.st_gid==0 and stat.S_IMODE(ts.st_mode)==0o600 and ts.st_nlink==1 and ts.st_size==RAW_BYTES,'exact Root0600 generated raw target FD/name')
  p.need(p.ident(os.fstat(carrier_fd))==source['identity']==p.ident(os.lstat(source['path'])),'source carrier full9 unchanged after raw copy')
  for name,fd,old in anc:p.need(old==p.ident(os.fstat(fd))==p.ident(os.lstat(name)),'source ancestor/name unchanged after copy')
  mount_custody=finish_carrier_ancestry(source,shared,carrier_fd);result={'carrierMountCustody':mount_custody,'kind':'ROOT_AUTHENTICATED_CARRIER_TO_RAW_BOOT_COPY','bootID':e['bootID'],'nonce':e['nonce'],'expectationPin':expectation_pin,'carrierBefore':source,'carrierAfter':source,'carrierWholeSHA256':h.hexdigest(),'extent':raw_extent(),'target':{'path':path,'bytes':RAW_BYTES,'sha256':RAW_SHA,'identity':p.ident(ts)},'backing':back,'runtimeAuthorized':False,**value}
 except BaseException as error:first=error
 finally:first,closeproof=finish_raw_copy(owned,target,target_path,first,before)
 if first is not None:
  try:persist('FIRST-raw-member-copy',{'type':type(first).__name__,'reason':str(first),'evidence':closeproof})
  except BaseException as secondary:
   closeproof['secondary'].append(fd_error(secondary,'raw',None,'failure-persistence'));first.capturePersistenceError=fd_error(secondary,'raw',None,'failure-persistence')
  raise first
 if result is not None:
  try:
   p.need(before==set(os.listdir('/proc/self/fd')),'all copy-owned FDs close; caller-held FDs unchanged');result['allOwnedFDsClosed']=closeproof['allCopyOwnedFDsClosed'];result['ownedFDClosure']=closeproof;persist('raw-member-copy-before-acceptance',result)
   with p.RootFiles('/run/opemos-steamos-placement-'+e['nonce'])as files,files.lock(True):ref=prod.put(files,'raw-recovery-copy.json',result)
   return {'copyReceiptPin':ref,'copyReceipt':result,'bootCopy':result['target']}
  except BaseException as error:
   error.rawCopyEvidence=closeproof
   if hasattr(error,'closeEvidence'):error.closeEvidence={'prior':error.closeEvidence,'rawCopy':closeproof}
   else:error.closeEvidence=closeproof
   raise

def validate_installer_xml(c,root):
 import libvirt_peer as p
 installer_contract(c);disks=root.findall('devices/disk');p.need(len(disks)==1,'one raw recovery virtualUSB, no install target')
 d=disks[0];p.need(d.get('type')=='file'and d.get('device')=='disk'and d.find('driver').get('type')=='raw'and d.find('source').get('file')==c['working']['path']and d.find('target').get('bus')=='usb'and d.find('target').get('dev')=='sda'and d.find('readonly')is not None and d.find('boot').get('order')=='1','exact authenticated f9aa raw copy readonly USB/order1')
 p.need(not root.findall('os/boot')and not root.findall('devices/interface'),'no old disk/physical/NIC fallback');resolution=root.find('devices/video/model/resolution');p.need(root.find('devices/video/model').get('type')=='virtio'and resolution is not None and resolution.attrib=={'x':'1600','y':'900'},'supported virtio resolution recipe, actual mode still required')
 p.need(root.findtext('os/loader')==c['firmwareCode']['path']and root.findtext('os/nvram')==c['run']+'/OVMF_VARS_4M.fd','same pinned firmware/private vars')

def require_firstboot_only(c):
 import libvirt_peer as p
 p.need('fullFlow'not in c and c.get('installer')is not None,'independent raw recovery firstboot only; no installed/fullflow fallback');return installer_contract(c)

def verify_display_capability(xml):
 import xml.etree.ElementTree as E
 import libvirt_peer as p
 p.need(len(xml.encode())<=1048576,'domain capabilities1MiB');root=E.fromstring(xml);v=root.find('devices/video');p.need(v is not None and v.get('supported')=='yes'and 'virtio'in[x.text for x in v.findall("enum[@name='modelType']/value")],'installed libvirt/QEMU supports virtio video; unsupported refuses')
 return {'virtioSupported':True,'requestedMinimum':[1600,900],'actualFramebufferStillRequired':True}

def verify_unscaled_usable_frame(request,identity,protocol,rgb):
 import libvirt_peer as p
 p.need(identity['domain']['uuid']==request['domainUUID']and identity['domain']['name']==request['domainName']and protocol['serverName']in(request['domainName'],'QEMU ('+request['domainName']+')'),'actual same-domain QEMU/frame identity')
 p.need(protocol['width']==1600 and protocol['height']==900 and protocol['fullRectangle']==[0,0,1600,900]and protocol['encoding']==0 and protocol['completePixelEOF']is True,'actual native1600x900 complete unscaled usable framebuffer; wrong/unsupported mode refuses')
 p.need(protocol['RGBBytes']==len(rgb)==1600*900*3 and protocol['RGBSHA256']==hashlib.sha256(rgb).hexdigest(),'complete original pixel count/hash, no stretch/crop/synthetic pixels')
 return {'kind':'ACTUAL_UNSCALED_SAME_DOMAIN_1600X900_BOUNDS','domainUUID':request['domainUUID'],'domainName':request['domainName'],'width':1600,'height':900,'usableBounds':[0,0,1600,900],'lastUsablePixel':[1599,899],'scale':1,'crop':False,'rawRGBSHA256':protocol['RGBSHA256'],'NVIDIARenderProof':False,'desktopOrPointerAcceptance':False}


def verify_saved_frame_geometry(record,png):
 import libvirt_peer as p
 p.need(len(png)<=4194304 and png[:8]==bytes([137,80,78,71,13,10,26,10])and png[12:16]==b'IHDR','exact retained PNG binary role, unchanged4MiB')
 w,h=struct.unpack('!II',png[16:24]);p.need((w,h)==(record['protocol']['width'],record['protocol']['height']),'saved PNG is original native framebuffer geometry; no stretch/crop')
 accepted=record.get('modeAccepted',False);p.need(type(accepted)is bool,'typed native mode disposition')
 if accepted:p.need((w,h)==(1600,900)and record['usableBounds']['usableBounds']==[0,0,1600,900],'accepted mode joins exact unscaled usable bounds')
 return {'nativeGeometry':[w,h],'modeAccepted':accepted,'diagnosticOnly':not accepted,'NVIDIARenderProof':False}


def metadata_cohort(roots,allowed_socket=None):
 """Nofollow bounded walk; consume every owned descriptor once on all paths."""
 p=__import__('libvirt_peer');need=p.need;ident=p.ident;CORE=p.CORE;Refused=p.Refused;h=__import__('guest_firmware_probe');total=0;entries=0;seen=set();dirs=set();anchors=[];last=None;first=None;rows=[];errors=[];unknown=False;baseline=set(os.listdir('/proc/self/fd'))
 def close(owned,primary=None):
  nonlocal unknown
  proof,error=h.close_owned_descriptors(owned);rows.extend(proof['rows']);errors.extend(proof['errors']);unknown=unknown or proof['unknown']
  if primary is None and error is not None:raise error
 def walk(fd,path,depth):
  nonlocal total,entries,last
  need(depth<=32,'bounded metadata directory depth');s=os.fstat(fd);before=ident(s);need(stat.S_ISDIR(s.st_mode)and before==ident(os.lstat(path)),'held/named metadata directory');key=(s.st_dev,s.st_ino);need(key not in dirs,'no aliased metadata directory');dirs.add(key);total+=max(s.st_size,s.st_blocks*512);need(total<=500000000,'all directory+file allocated metadata in500MB reserve');names=[]
  with os.scandir(fd)as scan:
   for entry in scan:entries+=1;names.append(entry.name)
  for name in sorted(names):
   s=os.stat(name,dir_fd=fd,follow_symlinks=False);last={'path':str(Path(path)/name),'identity':ident(s)};need(not stat.S_ISLNK(s.st_mode),'no file or directory symlink before metadata descent');socket=stat.S_ISSOCK(s.st_mode)and str(Path(path)/name)==allowed_socket and s.st_uid==64055 and s.st_nlink==1;need(stat.S_ISDIR(s.st_mode)or(stat.S_ISREG(s.st_mode)and s.st_nlink==1)or socket,'known directory/single regular or exact current owned VNC socket only');owned=[];primary=None
   try:
    child=os.open(name,(os.O_PATH if socket else os.O_RDONLY)|os.O_NOFOLLOW|os.O_CLOEXEC|(os.O_DIRECTORY if stat.S_ISDIR(s.st_mode)else 0),dir_fd=fd);h.own_descriptor(owned,child,'mdC');need(ident(s)==ident(os.fstat(child))==ident(os.stat(name,dir_fd=fd,follow_symlinks=False)),'stable nofollow named metadata child before descent')
    if stat.S_ISDIR(s.st_mode):walk(child,str(Path(path)/name),depth+1)
    else:
     key=(s.st_dev,s.st_ino);need(key not in seen,'no aliased metadata leaf');seen.add(key);total+=max(s.st_size,s.st_blocks*512);need(total<=500000000,'all directory+file allocated metadata in500MB reserve')
    need(ident(s)==ident(os.fstat(child))==ident(os.stat(name,dir_fd=fd,follow_symlinks=False)),'metadata child unchanged after complete use')
   except BaseException as error:primary=error;raise
   finally:close(owned,primary)
  need(before==ident(os.fstat(fd))==ident(os.lstat(path)),'metadata directory full9/namespace unchanged')
 try:
  need(type(roots)in(list,tuple)and len(roots)>0,'declared metadata roots')
  for root in roots:
   try:os.lstat(root)
   except FileNotFoundError:continue
   entries+=1
   need(Path(root).is_absolute()and '..'not in Path(root).parts and len(Path(root).parts)<=32,'absolute bounded metadata ancestry');fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);h.own_descriptor(anchors,fd,'mdA');chain=[('/',fd,ident(os.fstat(fd)))];at=Path('/')
   for name in Path(root).parts[1:]:
    s=os.stat(name,dir_fd=fd,follow_symlinks=False);need(stat.S_ISDIR(s.st_mode),'nofollow directory ancestry before descent');fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);h.own_descriptor(anchors,fd,'mdA');at=at/name;need(ident(s)==ident(os.fstat(fd)),'same opened metadata ancestor');chain.append((str(at),fd,ident(s)))
   walk(fd,str(root),0)
   for name,fd,old in chain:need(ident(os.fstat(fd))==ident(os.lstat(name))and all(ident(os.fstat(fd))[k]==old[k]for k in CORE),'held metadata ancestry core/name unchanged')
   close(anchors)
 except BaseException as error:first=error
 finally:
  try:close(anchors,first)
  except BaseException as error:first=first or error
 try:restored=baseline==set(os.listdir('/proc/self/fd'))
 except BaseException as error:restored=False;unknown=True;errors.append(h.fd_error(error,'md',None,'final-FD-set'));first=first or error
 proof={'rowSchema':['role','fd','objectCore','openFlags','descriptorFlags','closeAttempted','closedObserved'],'rows':rows,'errors':errors,'unknown':unknown,'allClosed':not unknown,'eachEntryConsumedOnce':True,'FDSetRestored':restored}
 if first is None and(not proof['FDSetRestored']or unknown):first=Refused('metadata FD closure unproved')
 if first is not None:first.metadataEvidence={'lastChild':last,'entries':entries,'chargedBytes':total,'directoryCount':len(dirs),'noSkippedDirectorySymlink':True};first.closeEvidence=proof;raise first
 need(len(p.canon(proof))<=1048576,'unchanged metadata closure evidence1MiB');return total,entries,proof

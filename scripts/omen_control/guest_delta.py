"""Generated-only EFI measurement addition to the retained working derivative.

No original attach/write, copy, package, credentials or guest setting operation.
This source is inert until a separate finite Root preparation grant is consumed.
Only two existing disposable var filesystems may receive a new probe/drop-in.
"""
import hashlib,json,os,stat,time
from pathlib import Path
import libvirt_peer as p
from libvirt_native import held,native_child
from libvirt_preflight import measured

VAR=(('A',11141120000),('B',11409555456))
VAR_SIZE=268435456
def payload(c,probe):
 p.need(len(probe)<=65536,'finite exact EFI producer')
 nonce=c['guestReporterNonce'];directory='lib/opemos-autorecovery-'+nonce
 return {directory+'/efi-probe.py':probe,'lib/overlays/etc/upper/systemd/system/opemos-autorecovery.service.d/10-libvirt-efi.conf':('[Service]\nExecStartPre=/usr/bin/python /var/'+directory+'/efi-probe.py '+nonce+' '+c['guestUUID']+'\n').encode()}

def put_at(root,relative,raw):
 # All names are literal generated payload leaves; parent traversal is nofollow.
 parts=Path(relative).parts;p.need(not Path(relative).is_absolute()and all(x not in('..','.')for x in parts),'confined generated path')
 fds=[];fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd)
 try:
  for i,name in enumerate(parts[:-1]):
   try:new=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
   except FileNotFoundError:
    # Existing preparation owns all parents; only new service.d is allowed.
    p.need(name=='opemos-autorecovery.service.d'and i==len(parts)-2,'only declared new drop-in directory');os.mkdir(name,0o755,dir_fd=fd);os.fsync(fd);new=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);os.fchmod(new,0o755)
   fd=new;fds.append(fd);s=os.fstat(fd);p.need(s.st_uid==s.st_gid==0 and not(s.st_mode&0o022),'Root restrictive generated parent')
  leaf=os.open(parts[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o444,dir_fd=fd)
  try:
   os.fchmod(leaf,0o444);v=memoryview(raw)
   while v:n=os.write(leaf,v);p.need(n>0,'generated delta write progress');v=v[n:]
   os.fsync(leaf)
  finally:os.close(leaf)
  os.fsync(fd);leaf=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
  try:
   s=os.fstat(leaf);got=os.read(leaf,65537);p.need(len(got)<=65536 and not os.read(leaf,1)and got==raw and p.ident(s)==p.ident(os.fstat(leaf))==p.ident(os.stat(parts[-1],dir_fd=fd,follow_symlinks=False))and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o444,'exact generated probe/drop-in reread full9/SHA/EOF')
   return {'relative':relative,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':p.ident(s)}
  finally:os.close(leaf)
 finally:
  for fd in fds[::-1]:os.close(fd)

def apply(c,grant_pin,persist):
 g=json.loads(held(grant_pin,1048576));p.need(os.getuid()==0 and grant_pin['identity']['st_uid']==0 and stat.S_IMODE(grant_pin['identity']['st_mode'])==0o400,'actual protected Root preparation grant')
 p.need(g['kind']=='ROOT_LIBVIRT_R4_GENERATED_EFI_PREPARATION'and g['RootIssued']is True and g['derivativePreparationAuthorized']is True and g['runtimeAuthorized']is False,'separate preparation only grant')
 p.need(g['issuedUnix']<=time.time()<g['startBeforeUnix']<=g['issuedUnix']+300 and g['bootID']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'same boot/finite Root scope')
 p.need(g['candidateNonce']==c['nonce']and g['original']==c['original']and g['working']==c['working']and g['guestUUID']==c['guestUUID']and g['reporterNonce']==c['guestReporterNonce'],'exact prepared source/working/guest scope')
 pre=json.loads(held(g['preflightPin'],1048576));p.need(0<=time.time()-pre['observedUnix']<=30 and pre['original']==c['original']and pre['working']==c['working']and pre['allOwnedFDsClosed']is True,'fresh complete actual readonly preparation preflight')
 probe=held(g['probePin'],65536);expected=payload(c,probe);original=c['original'];working=c['working']
 # The outside-before full read has its own bounded authenticated capture.
 before_capture=json.loads(held(g['outsideBeforeCapturePin'],1048576))
 verify_outside_capture(c['working'],before_capture)
 outsideBefore=before_capture['sha256']
 fd=os.open(c['working']['path'],os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);mounted=[];loops=[];loopMeta={};first=None;secondary=[];records=[]
 def cmd(argv):
  value=native_child(argv,time.time()+30,g['nativeTools'][argv[0]]);persist('guest-delta-native',value);p.need(value['numeric']==0,'generated working-only native helper');return value['stdout']
 def loop_proof(dev,target=None):
  offset=loopMeta[dev][0];info=json.loads(cmd(['/usr/sbin/losetup','--json','--output','NAME,BACK-INO,OFFSET,SIZELIMIT,RO',dev]))['loopdevices'][0];p.need(info['name']==dev and info['back-ino']==working['identity']['st_ino']and info['offset']==offset and info['sizelimit']==VAR_SIZE and info['ro']is False,'fresh exact owned loop before teardown')
  if target is not None:
   rdev=os.stat(dev,follow_symlinks=False).st_rdev;rows=[r.split()for r in Path('/proc/self/mountinfo').read_text().splitlines()if r.split()[4]==str(target)];p.need(len(rows)==1 and rows[0][2]==str(os.major(rdev))+':'+str(os.minor(rdev))and {'rw','nodev','nosuid','noexec'}.issubset(set(rows[0][5].split(','))),'fresh exact owned mounted loop before unmount')
 try:
  p.need(p.ident(os.fstat(fd))==working['identity']==p.ident(os.lstat(working['path'])),'held exact working inode before preparation')
  root=Path(g['mountRoot']);p.need(str(root)=='/run/opemos-libvirt-efi-'+g['nonce']and not root.exists(),'fresh exact preparation mount namespace');root.mkdir(mode=0o700)
  for slot,offset in VAR:
   target=root/slot;target.mkdir(mode=0o700)
   dev=cmd(['/usr/sbin/losetup','--find','--show','--offset',str(offset),'--sizelimit',str(VAR_SIZE),'/proc/'+str(os.getpid())+'/fd/'+str(fd)]).strip();p.need(__import__('re').fullmatch('/dev/loop[0-9]+',dev)is not None,'exact owned loop name');loops.append(dev);loopMeta[dev]=(offset,str(target))
   info=json.loads(cmd(['/usr/sbin/losetup','--json','--output','NAME,BACK-INO,OFFSET,SIZELIMIT,RO',dev]))['loopdevices'][0];p.need(info['back-ino']==working['identity']['st_ino']and info['offset']==offset and info['sizelimit']==VAR_SIZE and info['ro']is False,'exact derivative-only var loop')
   cmd(['/usr/bin/mount','-t','ext4','-o','rw,nodev,nosuid,noexec',dev,str(target)]);mounted.append(target)
   lines=[s.split()for s in Path('/proc/self/mountinfo').read_text().splitlines()if s.split()[4]==str(target)];p.need(len(lines)==1 and 'rw'in lines[0][5].split(','),'actual working-only mountinfo')
   service=target/'lib/overlays/etc/upper/systemd/system/opemos-autorecovery.service';sf=os.open(service,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
   try:
    st=os.fstat(sf);b=os.read(sf,65537);p.need(len(b)<=65536 and not os.read(sf,1)and p.ident(st)==p.ident(os.fstat(sf))==p.ident(service.lstat()),'existing generated service current full9/EOF');p.need({'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid}==g['serviceBefore'][slot],'exact previously prepared service bytes/Root mode unchanged')
   finally:os.close(sf)
   for relative,raw in expected.items():records.append({'slot':slot,**put_at(target,relative,raw)})
   loop_proof(dev,target);cmd(['/usr/bin/umount',str(target)]);mounted.remove(target);loop_proof(dev);cmd(['/usr/sbin/losetup','--detach',dev]);loops.remove(dev);target.rmdir()
  root.rmdir();os.fsync(fd);workingAfterMetadata=p.ident(os.fstat(fd));p.need(workingAfterMetadata==p.ident(os.lstat(working['path'])),'exact working metadata after declared delta/closure')
 except BaseException as error:first={'type':type(error).__name__,'reason':str(error),'traceback':__import__('traceback').format_exc()}
 finally:
  for target in mounted[:][::-1]:
   try:
    dev=next(k for k,v in loopMeta.items()if v[1]==str(target));loop_proof(dev,target);cmd(['/usr/bin/umount',str(target)]);mounted.remove(target)
   except BaseException as e:secondary.append(str(e))
  if not mounted:
   for dev in loops[:][::-1]:
    try:loop_proof(dev);cmd(['/usr/sbin/losetup','--detach',dev]);loops.remove(dev)
    except BaseException as e:secondary.append(str(e))
  os.close(fd);persist('guest-delta-closure',{'first':first,'secondary':secondary,'mounts':list(map(str,mounted)),'loops':loops,'noOriginalWrite':True})
 p.need(first is None and not secondary and not mounted and not loops,'first generated delta failure/unknown closure; retain partial')
 # Full after-original/working/outside reads are separate bounded captures,
 # not hidden inside the short mount/loop mutation transport.
 result={'kind':'LIBVIRT_R7_GENERATED_EFI_PENDING_CAPTURE','original':original,'workingBefore':working,'workingAfterIdentity':workingAfterMetadata,'probePin':g['probePin'],'generatedLeaves':records,'allowedVarRegions':[(slot,offset,VAR_SIZE)for slot,offset in VAR],'outsideBeforeCapturePin':g['outsideBeforeCapturePin'],'outsideSHA256':outsideBefore,'grantPin':grant_pin,'knownMountLoopClosure':True,'contentComplete':False,'runtimeAuthorized':False}
 persist('guest-delta-pending',result);return result


def verify_outside_capture(ref,v):
 p.need(ref['bytes']==21474836480,'exact retained20GiB derivative only')
 p.need(v['kind']=='ROOT_LIBVIRT_R7_OUTSIDE_VAR_CAPTURE'and v['fullIdentity']==ref['identity']and v['path']==ref['path'],'exact full9 outside capture')
 p.need(v['allowedVarRegions']==[[slot,offset,VAR_SIZE]for slot,offset in VAR]and v['bytesRead']==ref['bytes']-len(VAR)*VAR_SIZE,'only two declared regions excluded; exact whole outside byte count')
 p.need(v['readOnly']is True and v['EOF']is True and v['numeric']==0 and v['reaped']is True and v['stdoutEOF']is True and v['stderrEOF']is True and v['FDSetRestored']is True and v['children']==[]and v['originalAbsent']is True,'outside read actual complete capture/closure')
 p.need(v['startedUnix']<=v['finishedUnix']and v['finishedUnix']-v['startedUnix']<=70,'unchanged independently bounded outside read')
 p.need(len(v['sha256'])==64 and all(x in'0123456789abcdef'for x in v['sha256']),'canonical complete outside digest')
 return v


def complete(c,pending_pin,capture_pins,persist):
 from libvirt_preflight import disk_capture
 pending=json.loads(held(pending_pin,1048576));g=json.loads(held(pending['grantPin'],1048576));boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 p.need(os.getuid()==0 and pending_pin['identity']['st_uid']==pending_pin['identity']['st_gid']==0 and stat.S_IMODE(pending_pin['identity']['st_mode'])==0o400,'Root protected pending generated delta')
 p.need(pending['kind']=='LIBVIRT_R7_GENERATED_EFI_PENDING_CAPTURE'and pending['contentComplete']is False and pending['knownMountLoopClosure']is True and pending['original']==c['original']and pending['workingBefore']==c['working'],'exact pending original/working and full mount/loop closure')
 p.need(g['bootID']==boot and g['candidateNonce']==c['nonce']and time.time()<=g['issuedUnix']+300,'completion stays inside original finite preparation300s; no rearm/retimestamp')
 p.need(set(capture_pins)=={'original','working','outside'},'closed three after-capture graph')
 proofs={k:json.loads(held(ref,1048576))for k,ref in capture_pins.items()}
 for ref in capture_pins.values():p.need(ref['identity']['st_uid']==ref['identity']['st_gid']==0 and stat.S_IMODE(ref['identity']['st_mode'])==0o400,'protected actual capture proof')
 original=disk_capture(c['original'],proofs['original'],boot);work=proofs['working']['fullPin'];p.need(work['path']==c['working']['path']and work['identity']==pending['workingAfterIdentity']and work['bytes']==c['working']['bytes'],'same declared working inode/size and exact post-delta full9')
 p.need(all(work['identity'][k]==c['working']['identity'][k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size')),'delta cannot change working object/type/owner/access/cap')
 work=disk_capture(work,proofs['working'],boot);after=verify_outside_capture(work,proofs['outside']);before=verify_outside_capture(c['working'],json.loads(held(pending['outsideBeforeCapturePin'],1048576)))
 p.need(after['sha256']==before['sha256']==pending['outsideSHA256'],'complete outside regions exactly unchanged')
 result={'kind':'LIBVIRT_R4_GENERATED_EFI_DERIVATIVE_PREPARED','original':original,'workingBefore':c['working'],'workingAfter':work,'probePin':pending['probePin'],'generatedLeaves':pending['generatedLeaves'],'allowedVarRegions':pending['allowedVarRegions'],'outsideSHA256':after['sha256'],'knownClosed':True,'runtimeAuthorized':False,'pendingPin':pending_pin,'capturePins':capture_pins,'noTimestampRewrite':True}
 persist('guest-delta-prepared',result);return result


def reporter_payload(c,reporter_pin):
 """Same generated reporter role only; an independently reviewed finite image
 preparation must bind original/working, old A/B leaves and post-use closure.
 This pure producer never changes a disk or relabels old prepared receipts.
 """
 raw=held(reporter_pin,65536);p.need(len(raw)<=65536 and b'class Guest:'in raw,'exact bounded guest reporter source');compile(raw,reporter_pin['path'],'exec');nonce=c['guestReporterNonce'];p.need(len(nonce)==32 and all(x in'0123456789abcdef'for x in nonce),'exact existing reporter scope')
 return {'kind':'DISABLED_GUEST_REPORTER_ONLY_PAYLOAD','runtimeAuthorized':False,'sourcePin':reporter_pin,'relative':'lib/opemos-autorecovery-'+nonce+'/report.py','mode':0o500,'bytes':len(raw),'sha256':__import__('hashlib').sha256(raw).hexdigest(),'raw':raw,'requiresSeparatePreparedReceipt':True,'allowedVarRegions':[[slot,offset,VAR_SIZE]for slot,offset in VAR]}

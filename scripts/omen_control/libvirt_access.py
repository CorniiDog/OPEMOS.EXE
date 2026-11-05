import base64
"""One derivative-only POSIX access ACL transaction; never an original disk.

The caller holds the exact intent/lease EX lock and proves complete host holder
and domain closure before restore. Journal leaves are Root0400 O_EXCL. Kernel
ACL operations address held nofollow descriptors, not a shell/path subprocess.
No ACL operation is performed by importing this module.
"""
import ctypes,ctypes.util,hashlib,json,os,stat,contextlib,time,re,sys
from pathlib import Path
import libvirt_peer as p

UID=64055
CORE=('st_dev','st_ino','st_mode','st_uid','st_gid')
OBJECT=('st_dev','st_ino','st_uid','st_gid')

class ACL:
 def __init__(self):
  name=ctypes.util.find_library('acl');p.need(name is not None,'existing libacl required')
  self.lib=ctypes.CDLL(name,use_errno=True)
  for n,args,result in [('acl_get_fd',[ctypes.c_int],ctypes.c_void_p),('acl_to_any_text',[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_char,ctypes.c_int],ctypes.c_void_p),('acl_to_text',[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ssize_t)],ctypes.c_void_p),('acl_from_text',[ctypes.c_char_p],ctypes.c_void_p),('acl_set_fd',[ctypes.c_int,ctypes.c_void_p],ctypes.c_int),('acl_valid',[ctypes.c_void_p],ctypes.c_int),('acl_free',[ctypes.c_void_p],ctypes.c_int)]:
   f=getattr(self.lib,n);f.argtypes=args;f.restype=result
 def get(self,fd):
  a=self.lib.acl_get_fd(fd);p.need(bool(a),'acl_get_fd errno='+str(ctypes.get_errno()));text=None
  try:
   text=self.lib.acl_to_any_text(a,None,b'\n',0x08);p.need(bool(text),'numeric ACL text result');raw=ctypes.string_at(text);p.need(0<len(raw)<=4096,'bounded actual numeric ACL text');return raw.decode().rstrip('\n')+'\n'
  finally:
   if text:self.lib.acl_free(text)
   self.lib.acl_free(a)
 def set(self,fd,text):
  p.need(len(text.encode())<=4096,'ACL bound');a=self.lib.acl_from_text(text.encode());p.need(bool(a),'valid ACL parse')
  try:p.need(self.lib.acl_valid(a)==0 and self.lib.acl_set_fd(fd,a)==0,'held FD ACL set errno='+str(ctypes.get_errno()));os.fsync(fd)
  finally:self.lib.acl_free(a)

def hashfd(fd):
 os.lseek(fd,0,os.SEEK_SET);h=hashlib.sha256();n=0
 while b:=os.read(fd,65536):h.update(b);n+=len(b)
 return n,h.hexdigest()

class Held:
 def __init__(self,path,active_vars_owner=None):
  self.path=Path(path);p.need(self.path.is_absolute()and '..'not in self.path.parts,'absolute confined ACL path');self.fds=[];self.rows=[];self.active_vars_owner=active_vars_owner
  p.need(active_vars_owner is None or self.path.name=='OVMF_VARS_4M.fd'and type(active_vars_owner)is tuple and len(active_vars_owner)==2 and active_vars_owner[0]==UID and type(active_vars_owner[1])is int and active_vars_owner[1]>=0,'only registered QEMU firmware leaf owner')
  try:
   fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.fds.append(fd);self.rows.append(('/',p.ident(os.fstat(fd))))
   for part in self.path.parts[1:]:
    fd=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);self.fds.append(fd);self.rows.append((str(Path(self.rows[-1][0])/part),p.ident(os.fstat(fd))))
   self.fd=fd;self.check()
  except BaseException:self.close();raise
 def check(self,allow_leaf_epoch=False):
  for i,(name,old)in enumerate(self.rows):
   a=p.ident(os.fstat(self.fds[i]));b=p.ident(os.lstat(name));p.need(a==b,'full9 FD/name identity '+name)
   keys=OBJECT if i==len(self.rows)-1 and allow_leaf_epoch else CORE
   p.need(all(a[k]==old[k]for k in keys),'held same object/Root/mode '+name)
   owner=(a['st_uid'],a['st_gid']);p.need(owner==(0,0)or i==len(self.rows)-1 and self.active_vars_owner is not None and owner==self.active_vars_owner,'Root path custody '+name)
   if i not in (0,len(self.rows)-1) and a['st_mode']&0o022:
    p.need(ACL().get(self.fds[i])==expected_acl(0o700,UID,'rwx')[1],'only exact named libvirt UID private parent ACL '+name)
  return p.ident(os.fstat(self.fd))
 def close(self):
  for fd in self.fds[::-1]:os.close(fd)
  self.fds=[]
 def __enter__(self):return self
 def __exit__(self,*args):self.close()


def held_row(row):
 if 'immutableMediaCustodyPin'in row:return __import__('retained_media').held_row(row)
 return Held(row['path'])

def held_disk(c,key,ref):
 if key=='working'and __import__('retained_media').is_adopted(c):
  __import__('retained_media').observe(c)
  return __import__('retained_media').held_row(__import__('retained_media').access_row(c,ref['path'],ref,'working'))
 return Held(ref['path'])

def expected_acl(mode,uid,rights):
 p.need(uid==UID and mode in(0o700,0o600),'only exact derivative/private output basic modes')
 base='user::'+('rwx'if mode==0o700 else'rw-')+'\ngroup::---\nother::---\n'
 text='user::'+('rwx'if mode==0o700 else'rw-')+'\nuser:'+str(uid)+':'+rights+'\ngroup::---\nmask::'+rights+'\nother::---\n'
 return base,text

def plan(path,ref,role,uid=UID,verified_content=None,readonly_media=False):
 p.need(role in('working-parent','working','vars','runtime-parent','output-parent','serial'),'finite derivative-only roles')
 p.need(not readonly_media or role=='working','readonly media applies only exact working role');rights='--x'if role=='working-parent'else('r--'if readonly_media else('rwx'if role in('runtime-parent','output-parent')else'rw-'))
 mode=0o700 if role.endswith('parent')else 0o600
 with Held(path)as h:
  s=h.check();p.need(s==ref['identity'],'initial exact full9 '+role)
  p.need(stat.S_IMODE(s['st_mode'])==mode and(stat.S_ISDIR(s['st_mode'])if mode==0o700 else stat.S_ISREG(s['st_mode'])and s['st_nlink']==1),'exact initial type/mode/link')
  acl=ACL();before,after=expected_acl(mode,uid,rights);p.need(acl.get(h.fd)==before,'unrecognized prior ACL; do not override')
  if mode==0o600:
   if verified_content is None:p.need(hashfd(h.fd)==(ref['bytes'],ref['sha256']),'same-byte initial leaf')
   else:p.need(role=='working'and verified_content==ref,'only exact Root-qualified working capture may avoid repeated pre-ACL read')
  return {'path':str(path),'role':role,'before':ref,'priorACL':before,'targetACL':after,'uid':uid,'rights':rights}

def apply(row,persist,defer_working_hash=False):
 # A prior journal pin must be durably persisted BEFORE changing any ACL.
 p.need(persist('acl-before-'+row['role'],row)is not None,'durable before-ACL journal pin required')
 with held_row(row)as h:
  p.need(h.check()==row['before']['identity'],'no pre-apply rename/replacement/epoch drift');a=ACL();p.need(a.get(h.fd)==row['priorACL'],'ACL prior unchanged')
  if 'immutableMediaCustodyPin'not in row:a.set(h.fd,row['targetACL'])
  observed=h.check(True);p.need(a.get(h.fd)==row['targetACL'],'exact effective ACL reread')
  p.need(all(observed[k]==row['before']['identity'][k]for k in('st_uid','st_gid')),'no ownership change')
  out={'path':row['path'],'identity':observed,'ACL':a.get(h.fd)}
  if stat.S_ISREG(observed['st_mode'])and not(defer_working_hash and row['role']=='working'):
   n,d=hashfd(h.fd);p.need((n,d)==(row['before']['bytes'],row['before']['sha256']),'ACL metadata only; full same content');out.update(bytes=n,sha256=d)
  persist('acl-applied-'+row['role'],out);return out

def restore(row,closure,persist):
 p.need(closure.get('domainAbsent')is True and closure.get('originalPIDStartAbsent')is True and closure.get('cgroupEmpty')is True and closure.get('VFIOFDsAbsent')is True and closure.get('hostRestored')is True and closure.get('unknown')==[],'no ACL restore with unknown/live domain/holder')
 with held_row(row)as h:
  s=h.check(True);p.need(all(s[k]==row['before']['identity'][k]for k in OBJECT),'exact original ACL object')
  p.need(stat.S_IFMT(s['st_mode'])==stat.S_IFMT(row['before']['identity']['st_mode'])and(stat.S_ISDIR(s['st_mode'])or s['st_nlink']==1),'same ACL type/link')
  acl=ACL();current=acl.get(h.fd);p.need(current in(row['targetACL'],row['priorACL']),'foreign ACL drift refuses')
  if current!=row['priorACL']:
   p.need('immutableMediaCustodyPin'not in row,'immutable media ACL drift; no repair write');acl.set(h.fd,row['priorACL'])
  s=h.check(True);p.need(acl.get(h.fd)==row['priorACL']and s['st_mode']==row['before']['identity']['st_mode'],'exact ACL/mode restored')
  value={'path':row['path'],'identity':s,'ACL':acl.get(h.fd),'restored':True,'contentMayHaveGuestWrites':row['role']=='working'}
  if stat.S_ISREG(s['st_mode']):n,d=hashfd(h.fd);value.update(bytes=n,sha256=d)
  persist('acl-restored-'+row['role'],value);return value

def effective_access(path,writable,directory=False):
 # Called only by an already Root-controlled, original-free diagnostic child.
 p.need(os.geteuid()==UID,'effective libvirt-qemu UID measurement required')
 bits=(os.X_OK|(os.W_OK if writable else 0))if directory else os.R_OK|(os.W_OK if writable else 0)
 return os.access(path,bits,effective_ids=True,follow_symlinks=False)

def probe(paths,original,persist):
 """Actual finite DAC proof, original access is tested only with access(2).

 Child waits for parent PID/start capture before it switches uid. It receives
 no disk, intent, lease, source or other caller descriptors.
 """
 import select,time
 rd,wr=os.pipe();go_r,go_w=os.pipe();pid=os.fork()
 if pid==0:
  try:
   os.close(rd);os.close(go_w)
   for name in os.listdir('/proc/self/fd'):
    n=int(name)
    if n not in(0,1,2,wr,go_r):
     try:os.close(n)
     except OSError:pass
   if os.read(go_r,1)!=b'G':os._exit(2)
   os.close(go_r);os.setgroups([]);os.setgid(993);os.setuid(UID)
   rows=[{'path':x['path'],'role':x['role'],'allowed':effective_access(x['path'],x['role']!='working-parent'and x.get('rights')!='r--',x['role'].endswith('parent'))}for x in paths]
   value={'uid':os.getuid(),'rows':rows,'originalAllowed':os.access(original,os.R_OK,effective_ids=True,follow_symlinks=False)}
   os.write(wr,p.canon(value));os.close(wr);os._exit(0)
  except BaseException:os._exit(3)
 os.close(wr);os.close(go_r);known=False
 try:
  actor=p.process(pid);persist('dac-probe-early',{'actor':actor});os.write(go_w,b'G');os.close(go_w);go_w=None
  raw=b'';end=time.monotonic()+5
  while True:
   p.need(time.monotonic()<end and select.select([rd],[],[],max(0,end-time.monotonic()))[0],'DAC child deadline; unknown child holds')
   b=os.read(rd,65536)
   if not b:break
   raw+=b;p.need(len(raw)<=65536,'bounded DAC child result')
  got,status=os.waitpid(pid,0);known=True;p.need(got==pid and os.waitstatus_to_exitcode(status)==0,'DAC child numeric/EOF/reap')
  v=json.loads(raw)
  if not(v['uid']==UID and all(x['allowed']for x in v['rows'])and not v['originalAllowed']):
   error=p.Refused('effective UID working IO access; immutable original inaccessible');error.evidence={'kind':'EFFECTIVE_UID_ACCESS_REFUSAL','actor':actor,'numeric':0,'EOF':True,'reaped':True,'FDsClosed':True,'value':v};raise error
  persist('dac-probe-terminal',{'actor':actor,'numeric':0,'EOF':True,'reaped':True,'FDsClosed':True,'value':v});return v
 finally:
  os.close(rd)
  if go_w is not None:os.close(go_w)
  p.need(known,'DAC child closure unknown; retain lease and ACL journal')


def metadata_pin(path):
 with Held(path)as h:return {'path':str(path),'identity':h.check()}


def io_ancestor(c,recorded=None):
 """Current shared IO grouping path is traverse-only; leaf ACLs grant access."""
 if 'operationContext'not in c:return None
 path=__import__('source_contract').candidate_paths(c)['ioRoot']
 with Held(path)as h:
  now=h.check();p.need(stat.S_ISDIR(now['st_mode'])and stat.S_IMODE(now['st_mode'])==0o711 and ACL().get(h.fd)=='user::rwx\ngroup::--x\nother::--x\n','exact owned traverse-only IO ancestor')
  if recorded is not None:p.need(recorded['path']==path and all(now[k]==recorded['identity'][k]for k in CORE),'same declared IO ancestor inode/owner/mode')
  return {'path':path,'identity':now}


def stage_io(c,grant_pin,persist):
 """Finite generated-only access preparation, BEFORE runtime clocks begin.

 No queue/partition/domain/lease/GPU operation. The result is PENDING until
 both separate post-ACL full disk captures have been joined by final preflight.
 """
 from libvirt_native import held
 import time
 g=json.loads(held(grant_pin,1048576));now=time.time()
 p.need(os.getuid()==0 and grant_pin['identity']['st_uid']==grant_pin['identity']['st_gid']==0 and stat.S_IMODE(grant_pin['identity']['st_mode'])==0o400,'protected Root stage grant')
 p.need(g['kind']=='ROOT_LIBVIRT_PREGRANT_ACCESS_STAGE_R7'and g['RootIssued']is True and g['runtimeAuthorized']is False and g['stageOnly']is True,'finite stage-only authority')
 p.need(g['issuedUnix']<=now<g['startBeforeUnix']<=g['issuedUnix']+300 and g['bootID']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'original300s scope/boot')
 p.need(g['candidate']==c and g['nonce']==c['nonce'],'exact static candidate, no future canonical IDs')
 pre=json.loads(held(g['currentPreflightPin'],1048576))
 p.need(pre['bootID']==g['bootID']and 0<=now-pre['observedUnix']<=30 and pre['allOwnedFDsClosed']is True and pre['original']==c['original']and pre['working']==c['working']and pre.get('abi')==__import__('libvirt_preflight').MACHINE_PREFLIGHT_ABI,'fresh complete machine stage preflight, not a retimestamped hash')
 p.need(c['original']['path']!=c['working']['path']and str(Path(c['original']['path']).parent)!=str(Path(c['working']['path']).parent),'original parent excluded')
 for key in('original','working'):
  with held_disk(c,key,c[key])as h:p.need(h.check()==c[key]['identity'],'qualified initial disk still exact full9')
 for root in(c['run'],c['output']):
  p.need(not os.path.lexists(root),'unused exact static IO path')
  with Held(str(Path(root).parent))as h:
   os.mkdir(Path(root).name,0o700,dir_fd=h.fd);os.fsync(h.fd)
 template=held(c['firmwareVarsTemplate'],1048576)
 for path,raw in((c['run']+'/OVMF_VARS_4M.fd',template),(c['output']+'/serial.raw',b'')):
  with Held(str(Path(path).parent))as h:
   fd=os.open(Path(path).name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=h.fd)
   try:
    os.fchmod(fd,0o600);view=memoryview(raw)
    while view:n=os.write(fd,view);p.need(n>0,'stage IO write progress');view=view[n:]
    os.fsync(fd)
   finally:os.close(fd)
   os.fsync(h.fd)
 rows=[];after=[]
 leaves=[(str(Path(c['working']['path']).parent),'working-parent'),(c['working']['path'],'working'),(c['run'],'runtime-parent'),(c['run']+'/OVMF_VARS_4M.fd','vars'),(c['output'],'output-parent'),(c['output']+'/serial.raw','serial')]
 for path,role in leaves:
  ref=({'path':path,'identity':__import__('retained_media').observe(c)['parent']['identity']}if role=='working-parent'and __import__('retained_media').is_adopted(c)else(c['working']if role=='working'and __import__('retained_media').is_adopted(c)else metadata_pin(path)))
  if role=='working':
   if c.get('installer')is not None:__import__('guest_firmware_probe').installer_contract(c)
   ref=dict(c['working'])
  elif not role.endswith('parent'):
   with Held(path)as h:n,d=hashfd(h.fd);ref.update(bytes=n,sha256=d)
  row=(__import__('retained_media').access_row(c,path,ref,role)if __import__('retained_media').is_adopted(c)and role in('working','working-parent')else plan(path,ref,role,verified_content=(c['working']if role=='working'else None),readonly_media=(c.get('installer')is not None and role=='working')));rows.append(row);after.append(apply(row,persist,defer_working_hash=True))
 ancestor=io_ancestor(c)
 probe(rows,c['original']['path'],persist)
 result={'kind':'LIBVIRT_R7_ACCESS_STAGE_PENDING_FULL_HASH','nonce':c['nonce'],'bootID':g['bootID'],'candidate':c,'grantPin':grant_pin,'rows':rows,'after':after,'original':c['original'],'workingBefore':c['working'],'pendingFullContentProof':True,'runtimeAuthorized':False}
 if ancestor is not None:result['ioAncestor']=ancestor
 persist('access-stage-pending',result);return result

def prepared_lineage(c,ref,disk_pins):
 """Authenticate the frozen stage and both pre/post-ACL epochs; no live IO acceptance."""
 from libvirt_native import held
 v=json.loads(held(ref,1048576))
 p.need(ref['identity']['st_uid']==ref['identity']['st_gid']==0 and stat.S_IMODE(ref['identity']['st_mode'])==0o400,'Root0400 access stage')
 p.need(v['kind']=='LIBVIRT_R7_ACCESS_STAGE_PENDING_FULL_HASH'and v['nonce']==c['nonce']and v['candidate']==c and v['runtimeAuthorized']is False,'exact stage candidate/full lineage')
 p.need(v['bootID']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'same current stage boot')
 if 'operationContext'in c:p.need(type(v.get('ioAncestor'))is dict,'current stage records actual IO ancestor');io_ancestor(c,v['ioAncestor'])
 p.need(set(disk_pins)=={'original','working'}and disk_pins['original']==c['original'],'complete independent post-ACL original proof')
 work=disk_pins['working'];p.need(work['path']==c['working']['path']and work['bytes']==c['working']['bytes']and work['sha256']==c['working']['sha256'],'post-ACL same complete working bytes')
 p.need(all(work['identity'][k]==c['working']['identity'][k]for k in('st_dev','st_ino','st_uid','st_gid','st_nlink','st_size','st_mtime_ns')),'only declared ACL metadata can change, no content epoch')
 p.need([r['role']for r in v['rows']]==['working-parent','working','runtime-parent','vars','output-parent','serial']and len(v['after'])==6,'closed ordered six-role access graph')
 return v


def verify_prepared(c,ref,disk_pins):
 v=prepared_lineage(c,ref,disk_pins);work=disk_pins['working']
 allowed={'working-parent':str(Path(c['working']['path']).parent),'working':c['working']['path'],'runtime-parent':c['run'],'vars':c['run']+'/OVMF_VARS_4M.fd','output-parent':c['output'],'serial':c['output']+'/serial.raw'}
 for row,a in zip(v['rows'],v['after']):
  p.need(row['path']==allowed[row['role']]==a['path']and row['uid']==UID,'exact access scope')
  if row['role']=='working'and c.get('installer')is not None and not __import__('retained_media').is_adopted(c):p.need(row['rights']=='r--'and row['targetACL']==expected_acl(0o600,UID,'r--')[1],'same-byte installer media readonly DAC, no write permission')
  with held_row(row)as h:
   now=h.check();p.need(now==a['identity']and ACL().get(h.fd)==row['targetACL']==a['ACL'],'frozen effective post-ACL full9/FD/name')
   if row['role']=='working':p.need(now==work['identity']and row['before']==c['working'],'exact pre/post working pin lineage')
   elif not row['role'].endswith('parent'):
    n,d=hashfd(h.fd);p.need((n,d)==(a['bytes'],a['sha256']),'small vars/serial exact bytes')
 for key in('original','working'):
  with held_disk(c,key,disk_pins[key])as h:p.need(h.check()==disk_pins[key]['identity'],'same post-hash disk full9 at use')
 return v


def closed_working_content_epoch(now,restored,disk,receipt,row):
 """Protected restoration producer hashed this exact full9 content epoch."""
 keys={'path','identity','ACL','restored','contentMayHaveGuestWrites','bytes','sha256'};p.need(type(restored)is dict and set(restored)==keys and restored['path']==row['path']==disk['path']and restored['restored']is True and restored['contentMayHaveGuestWrites']is True,'exact old/current working restoration producer record')
 raw=p.canon(restored);i=receipt['identity'];p.need(receipt['path'].endswith('/acl-restored-working.json')and stat.S_ISREG(i['st_mode'])and stat.S_IMODE(i['st_mode'])==0o400 and i['st_uid']==i['st_gid']==0 and i['st_nlink']==1 and receipt['bytes']==i['st_size']==len(raw)<=1048576 and receipt['sha256']==hashlib.sha256(raw).hexdigest(),'entire held protected working restore receipt')
 p.need(now==restored['identity']and stat.S_ISREG(now['st_mode'])and now['st_nlink']==1 and all(now[k]==row['before']['identity'][k]for k in('st_uid','st_gid')) and now['st_mode']==row['before']['identity']['st_mode']and restored['ACL']==row['priorACL']and (restored['bytes'],restored['sha256'])==(disk['bytes'],disk['sha256'])and now['st_size']==restored['bytes'],'same full9 including ctime/ACL/mode/bytes/hash restoration epoch')
 return {'bytes':restored['bytes'],'sha256':restored['sha256']}

def active_firmware_owner(reg):
 """Same registered live QEMU, not a general non-Root path exception."""
 leader=reg['leader'];actor=p.process(leader['pid']);p.need({k:actor[k]for k in('pid','start','uid')}==leader and actor['uid']==UID and actor['tgid']==actor['pid'],'original registered firmware QEMU owner')
 fd=os.open('/proc/'+str(leader['pid']),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 def gids():
  child=os.open('status',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
  try:
   raw=b''
   while block:=os.read(child,4096):raw+=block;p.need(len(raw)<=65536,'bounded QEMU group observation')
   lines=[x.split()[1:]for x in raw.decode().splitlines()if x.startswith('Gid:')];p.need(len(lines)==1,'one actual QEMU GID quartet');values=[int(x)for x in lines[0]];p.need(len(values)==4 and len(set(values))==1 and values[0]>=0,'uniform actual QEMU GID quartet');return values
  finally:os.close(child)
 try:
  values=gids();p.need(p.process(leader['pid'])==actor and gids()==values,'original QEMU PID/start/UID/argv/cgroup/GID stable');return {'leader':leader,'gids':values}
 finally:os.close(fd)

def runtime_socket(directory,run,phase):
 """A declared live socket or its unbound node after proved domain closure."""
 fd=os.open('vnc.sock',os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
 try:
  st=os.fstat(fd);value={'path':run+'/vnc.sock','identity':p.ident(st)};p.need(stat.S_ISSOCK(st.st_mode)and st.st_uid==UID and st.st_nlink==1,'same domain owned VNC socket type/UID/link')
  if phase=='CLOSED':
   with open('/proc/net/unix','rb')as inventory:raw=inventory.read(1048577)
   p.need(len(raw)<=1048576,'bounded current UNIX socket inventory');rows=[line.split()for line in raw.decode().splitlines()[1:]];p.need(all(len(row)>=7 for row in rows),'complete current UNIX socket rows');p.need(not any(row[6]==str(st.st_ino)or len(row)>7 and row[7]==value['path']for row in rows),'closed VNC node has no current kernel socket');value.update(kernelSocketAbsent=True,networkNamespace=os.readlink('/proc/self/ns/net'))
  p.need(p.ident(st)==p.ident(os.stat('vnc.sock',dir_fd=directory,follow_symlinks=False))==p.ident(os.fstat(fd)),'held and named VNC socket epoch');return value
 finally:os.close(fd)

def verify_phase(c,ref,disks,phase,intent,reg,state,files):
 """Called inside the observer's held intent AND lease locks, before rereads.
 Frozen stage is provenance, never a substitute for live phase custody.
 """
 if phase in('NOT_PREPARED','PREPARED'):return {'phase':phase,'stage':verify_prepared(c,ref,disks),'mutable':[]}
 p.need(phase in('ACTIVE','CLOSED')and files is not None,'protected known runtime phase')
 v=prepared_lineage(c,ref,disks);r=intent['request']
 p.need(r['leaseNonce']==c['nonce']and r['domainUUID']==c['guestUUID']and r['domainName']==c['name']and intent['workingPin']==c['working']and intent['originalPin']==c['original']and intent['accessScope']=={'run':c['run'],'output':c['output'],'working':c['working'],'firmwareVarsTemplate':c['firmwareVarsTemplate']},'entire protected phase candidate/access scope')
 if phase=='ACTIVE':p.need(not state['closed']and reg['leader']is not None and reg['scope']is not None,'real registered active lease')
 else:
  details=reg['details'];p.need(state['closed']and state['restored']and state['changed']==[]and state['currentDisposition']==details,'exact outer phase/lease current disposition equality');closed=details
  if 'currentClosure'in details:
   p.need(set(details)=={'first','secondary','currentClosure','historicalQMPClosed','noHistoricalCloseFabrication'}and type(details['first'])is dict and type(details['secondary'])is list and details['historicalQMPClosed']is None and details['noHistoricalCloseFabrication']is True,'exact failed-current-disposition schema, retain first and historical unknown');final=details['currentClosure']
   p.need(final['known']is True and final['FDsClosed']is True and final['leaseHeld']is False,'independent failure closure and exact owned FDs');closed=final['closure'];p.need(closed['ACLRestored']is True and closed['originalFullHashVerified']is True and closed['historicalQMPClosed']is None,'failure original/ACL/native closure, no inferred historical QMP')
  p.need(all(closed.get(k)is True for k in('domainAbsent','originalPIDStartAbsent','cgroupEmpty','VFIOFDsAbsent','hostRestored'))and closed['unknown']==[]and closed['qemuExitStatus']is None and closed['controllerWaitpidClaimed']is False,'exact current closed native disposition, no historical QMP invention')
 allowed={'working-parent':str(Path(c['working']['path']).parent),'working':c['working']['path'],'runtime-parent':c['run'],'vars':c['run']+'/OVMF_VARS_4M.fd','output-parent':c['output'],'serial':c['output']+'/serial.raw'};out=[];journals=[]
 for row,a in zip(v['rows'],v['after']):
  role=row['role'];p.need(row['path']==allowed[role]==a['path']and row['uid']==UID,'exact phase six-role scope')
  raw,jp=files.read('acl-before-'+role+'.json');journals.append(('acl-before-'+role+'.json',raw,jp));p.need(json.loads(raw)==row,'protected original six-role ACL journal')
  owner=active_firmware_owner(reg)if phase=='ACTIVE'and role=='vars'else None
  with (Held(row['path'],(UID,owner['gids'][0]))if owner is not None else held_row(row))as h:
   now=h.check();acl=ACL().get(h.fd);restore_pin=None;restore_raw=None;content=None;expected=a['identity'];keys=('st_dev','st_ino')if owner is not None else OBJECT;p.need(all(now[k]==expected[k]for k in keys)and stat.S_IFMT(now['st_mode'])==stat.S_IFMT(expected['st_mode'])and now['st_nlink']==expected['st_nlink'],'same owned phase inode/type/link')
   if phase=='ACTIVE':
    p.need(now['st_mode']==expected['st_mode']and acl==row['targetACL']==a['ACL'],'exact active effective ACL/mode')
    if role in('working','working-parent'):p.need(now==expected,'immutable readonly working and parent full9 during ACTIVE')
    elif role=='vars':p.need(now['st_size']==a['bytes']and now['st_size']<=1048576,'bounded same-size mutable firmware')
    elif role=='serial':p.need(a['identity']['st_size']<=now['st_size']<=4194304,'bounded append-only serial epoch')
   else:
    rb,rpin=files.read('acl-restored-'+role+'.json');restore_pin=rpin;restore_raw=base64.b64encode(rb).decode('ascii');journals.append(('acl-restored-'+role+'.json',rb,rpin));restored=json.loads(rb)
    p.need(closed_restoration(row,restored,now,acl),'exact protected closed restoration/current custody')
    if not role.endswith('parent'):
     if role=='working':content=closed_working_content_epoch(now,restored,disks['working'],rpin,row)
     else:p.need(hashfd(h.fd)==(restored['bytes'],restored['sha256']),'restored leaf full content pin');content={'bytes':restored['bytes'],'sha256':restored['sha256']}
    if role=='working':p.need((restored['bytes'],restored['sha256'])==(disks['working']['bytes'],disks['working']['sha256']),'closed readonly working full SHA unchanged')
   if role=='working':p.need(row['before']==c['working']and all(now[k]==disks['working']['identity'][k]for k in('st_dev','st_ino','st_uid','st_gid','st_nlink','st_size','st_mtime_ns')),'immutable readonly working content epoch and pre/post lineage')
   children=None;socket_pin=None
   if role in('runtime-parent','output-parent'):
    children=sorted(os.listdir(h.fd));wanted=['OVMF_VARS_4M.fd']if role=='runtime-parent'else['serial.raw']
    if role=='runtime-parent'and(phase=='ACTIVE'or 'vnc.sock'in children):wanted+=['vnc.sock']
    p.need(children==sorted(wanted),'only declared owned runtime/output children')
    if role=='runtime-parent'and 'vnc.sock'in children:socket_pin=runtime_socket(h.fd,c['run'],phase)
   p.need(now==h.check()and ACL().get(h.fd)==acl,'phase held/named object and ACL stable during observation');out.append({'role':role,'identity':now,'ACL':acl,'journalPin':jp,'children':children,'socket':socket_pin,'restorePin':restore_pin,'restoreRawBase64':restore_raw,'content':content})
   if owner is not None:out[-1]['activeFirmwareOwner']=owner
 with Held(disks['original']['path'])as h:p.need(h.check()==disks['original']['identity'],'immutable original full9 after runtime custody')
 for name,raw,jpin in journals:p.need(files.read(name)==(raw,jpin),'same original held-epoch ACL journals full9/raw after custody')
 prepared_lineage(c,ref,disks)
 return {'phase':phase,'stagePin':ref,'rows':out,'nativeDisposition':None if phase=='ACTIVE'else reg['details']}




RUNTIME_KIND='ROOT_DECLARED_RUNTIME_PUBLICATION_R201'
RUNTIME_CONTROLS={'issuer-start.json','assignment.json','postqueue-preflight.json','child-grant.json','context.json','FIRST-postqueue-issuer.json'}
def runtime_name(name):
 return name in RUNTIME_CONTROLS or re.fullmatch(r'[0-9]{2,3}-[A-Za-z0-9_.-]{1,96}[.]json',name)is not None

def runtime_inventory(files,parent,parent_ref):
 """Validate the complete create-only publisher chain; never a grant."""
 names=None;leaves={};pubs=[]
 try:
  root=__import__('source_contract').parent_paths(parent)['runtimeRoot'];p.need(str(files.path)==root,'exact runtime capsule')
  names=sorted(os.listdir(files.fd));p.need(len(names)<=1536,'original finite runtime inventory')
  journals=[n for n in names if re.fullmatch(r'publication-[0-9]{3}[.]json',n)];p.need(len(journals)<=512 and journals==['publication-'+str(i).zfill(3)+'.json'for i in range(len(journals))],'ordered bounded publication chain')
  _,lockpin=files.read('lock',0o600,4096);leaves={};pubs=[];last=None;total=0;request_hash=None;publisher=None
  for index,name in enumerate(journals):
   raw,ref=files.read(name);total+=len(raw);p.need(total<=8388608,'runtime full metadata read budget');v=json.loads(raw)
   keys={'kind','nonce','jobId','bootID','parentPin','publisherPin','ordinal','previousPin','name','leafPin','stateSHA256','requestSHA256','actor','beforeDirectory','afterLeafDirectory'}
   p.need(set(v)==keys and p.canon(v)==raw and v['kind']==RUNTIME_KIND and v['nonce']==parent['nonce']and v['jobId']==parent['jobId']and v['bootID']==parent['bootID']and v['parentPin']==parent_ref and v['publisherPin']==parent['sourceRoles']['postqueue_issuer']and v['ordinal']==index and v['previousPin']==(None if not pubs else pubs[-1]),'same authority/source/ordered runtime publisher')
   actor=v['actor'];p.need(set(actor)=={'pid','start','uid','tgid','ppid','cgroup','argv'}and actor['uid']==0 and actor['pid']==actor['tgid']and actor['pid']>0 and actor['start']>0 and type(actor['argv'])is list and actor['cgroup'].startswith('/'),'actual Root publisher identity')
   if publisher is None:publisher=actor
   p.need(actor==publisher,'same original publisher PID/start/UID/argv/cgroup')
   for field in('beforeDirectory','afterLeafDirectory'):
    i=v[field];p.need(set(i)==set(p.FIELDS)and all(type(x)is int for x in i.values())and all(i[k]==p.ident(os.fstat(files.fd))[k]for k in p.CORE)and stat.S_IMODE(i['st_mode'])==0o700,'same runtime core across exact create')
   leaf=v['name'];p.need(runtime_name(leaf)and leaf not in leaves,'declared create-only publisher leaf');data,actual=files.read(leaf);total+=len(data);p.need(total<=8388608 and actual==v['leafPin'],'whole prior runtime leaf full9/EOF/SHA unchanged');leaves[leaf]=actual
   if leaf=='issuer-start.json':
    start=json.loads(data);p.need(index==0 and start['parentPin']==parent_ref and start['hardwareEffects']==[]and start['actor']==actor,'actual first same-parent publisher start')
   else:p.need('issuer-start.json'in leaves,'publisher must start before dependent leaves')
   if leaf=='assignment.json':
    assignment=json.loads(data);r=assignment['request'];p.need(assignment['kind']=='ROOT_CANONICAL_QUEUE_LIBVIRT_ASSIGNMENT_R4'and r['jobId']==parent['jobId']and r['leaseNonce']==parent['nonce'],'same exact assignment publisher');request_hash=hashlib.sha256(p.canon(r)).hexdigest()
   if leaf=='child-grant.json':
    g=json.loads(data);p.need('postqueue-preflight.json'in leaves and g['parentPin']==parent_ref and g['assignmentPin']==leaves['assignment.json']and g['jobId']==parent['jobId']and g['leaseNonce']==parent['nonce'],'grant only after existing actual assignment/preflight proof')
   if leaf=='context.json':
    c=json.loads(data);p.need(c['parentPin']==parent_ref and c['assignmentPin']==leaves['assignment.json']and c['grantPin']==leaves['child-grant.json'],'complete published context, never partial')
   p.need(v['requestSHA256']==request_hash and v['stateSHA256']==hashlib.sha256(p.canon(leaves)).hexdigest(),'complete runtime leaf set/request chain hash');pubs.append(ref);last=v
  p.need(set(names)=={'lock',*journals,*leaves},'foreign or unjournaled runtime leaf')
  files.check();return {'leaves':leaves,'publications':pubs,'head':last,'lockPin':lockpin,'requestSHA256':request_hash}
 except BaseException as error:
  evidence={'path':str(files.path),'names':names,'contextPresent':None if names is None else'context.json'in names,'leavesRead':leaves,'publicationsRead':pubs,'lastJournalPin':locals().get('ref'),'lastLeafPin':locals().get('actual'),'expectedLeafPin':locals().get('v',{}).get('leafPin'),'held':None,'named':None,'monotonic':time.monotonic()}
  try:evidence.update(held=p.ident(os.fstat(files.fd)),named=p.ident(os.lstat(files.path)))
  except BaseException as secondary:evidence['secondary']={'type':type(secondary).__name__,'reason':str(secondary),'UNKNOWN':True}
  error.runtimeInventory=evidence;raise

def publish_runtime(files,parent,parent_ref,name,value,deadline):
 """One finite EX create. Never retain EX across worker/export/observer calls."""
 p.need(runtime_name(name),'declared runtime producer name');before=None;effects=[]
 try:
  with files.lock(True,deadline)as lock:
   files.check();before=p.ident(os.fstat(files.fd));previous=runtime_inventory(files,parent,parent_ref);p.need(name not in previous['leaves']and len(previous['publications'])<512,'one-use runtime publication')
   if not previous['publications']:p.need(name=='issuer-start.json','issuer-start first publication')
   else:p.need(previous['head']['actor']==p.process(os.getpid()),'same live original Root publisher before create')
   if name=='issuer-start.json':p.need(not previous['publications']and value['parentPin']==parent_ref and value['actor']==p.process(os.getpid()),'one exact issuer start')
   if name=='assignment.json':p.need(value['kind']=='ROOT_CANONICAL_QUEUE_LIBVIRT_ASSIGNMENT_R4'and value['request']['jobId']==parent['jobId']and value['request']['leaseNonce']==parent['nonce'],'same assignment before publication')
   if name=='child-grant.json':p.need('assignment.json'in previous['leaves']and'postqueue-preflight.json'in previous['leaves']and value['parentPin']==parent_ref and value['assignmentPin']==previous['leaves']['assignment.json']and value['jobId']==parent['jobId']and value['leaseNonce']==parent['nonce'],'no grant publication before bound preflight/assignment')
   if name=='context.json':p.need('assignment.json'in previous['leaves']and'child-grant.json'in previous['leaves']and value['parentPin']==parent_ref and value['assignmentPin']==previous['leaves']['assignment.json']and value['grantPin']==previous['leaves']['child-grant.json'],'complete context before publication')
   from libvirt_producer import put
   ref=put(files,name,value);effects.append(ref);leaves=dict(previous['leaves']);leaves[name]=ref;request_hash=previous['requestSHA256']
   if name=='assignment.json':request_hash=hashlib.sha256(p.canon(value['request'])).hexdigest()
   actor=value['actor']if name=='issuer-start.json'else p.process(os.getpid());p.need(actor['uid']==0,'only actual Root publisher')
   record={'kind':RUNTIME_KIND,'nonce':parent['nonce'],'jobId':parent['jobId'],'bootID':parent['bootID'],'parentPin':parent_ref,'publisherPin':parent['sourceRoles']['postqueue_issuer'],'ordinal':len(previous['publications']),'previousPin':None if not previous['publications']else previous['publications'][-1],'name':name,'leafPin':ref,'stateSHA256':hashlib.sha256(p.canon(leaves)).hexdigest(),'requestSHA256':request_hash,'actor':actor,'beforeDirectory':before,'afterLeafDirectory':p.ident(os.fstat(files.fd))}
   journal=put(files,'publication-'+str(record['ordinal']).zfill(3)+'.json',record);effects.append(journal);checked=runtime_inventory(files,parent,parent_ref);p.need(checked['leaves']==leaves,'publisher readback complete same leaf set');p.need(time.monotonic()<deadline,'original publisher deadline after durable write');return ref
 except BaseException as error:error.runtimePublicationEffects=effects;error.runtimePublication={'path':str(files.path),'name':name,'before':before,'held':p.ident(os.fstat(files.fd)),'named':p.ident(os.lstat(files.path)),'effects':effects,'first':getattr(error,'evidence',None)};raise

@contextlib.contextmanager
def runtime_snapshot(parent,parent_ref,request,deadline,io):
 """Birth is sampled AFTER SH. Full9 remains exact throughout one read cut."""
 root=__import__('source_contract').parent_paths(parent)['runtimeRoot'];value={'kind':'ROOT_SHARED_RUNTIME_SNAPSHOT_R201','parentPin':parent_ref,'publisherPin':parent['sourceRoles']['postqueue_issuer'],'jobId':parent['jobId'],'nonce':parent['nonce'],'bootID':parent['bootID'],'startedMonotonic':time.monotonic(),'readLockClosed':False};files=p.RootFiles(root)
 try:
  with files:
   with files.lock(False,deadline)as lock:
    birth=p.ident(os.fstat(files.fd));value.update(directory={'path':root,'identity':birth},lock=lock)
    # RootInputs borrows this FD only while the owning SH context is active.
    p.need(root not in io.dirs,'runtime birth must follow shared lock');io.dirs[root]=(files.fd,birth,True)
    try:
     initial=runtime_inventory(files,parent,parent_ref);value.update(initial);p.need(initial['requestSHA256']in(None,hashlib.sha256(p.canon(request)).hexdigest()),'runtime publication exact requested assignment');yield value
     final=runtime_inventory(files,parent,parent_ref);value.update(directoryAfter=p.ident(os.fstat(files.fd)),completedMonotonic=time.monotonic());p.need(final==initial and birth==value['directoryAfter']==p.ident(os.lstat(root)),'shared runtime complete full9/leaf epoch unchanged')
    finally:io.dirs.pop(root,None)
   value['readLockClosed']=lock['closed']
 except BaseException as error:value.update(errorPath=root,inventoryFailure=getattr(error,'runtimeInventory',None),lockFailure=getattr(error,'evidence',None));error.runtimePublication=value;raise


def publish_runtime_first(files,parent,parent_ref,value):
 """Only a failure receipt, under a new two-second closure budget. No grant."""
 p.need(type(value)is dict and value.get('diagnosticOnly')is True and value.get('grantAccepted')is False and value.get('hardwareEffects')==[]and value.get('retainLease')is True and type(value.get('first'))is dict,'diagnostic-only protected FIRST purpose')
 return publish_runtime(files,parent,parent_ref,'FIRST-postqueue-issuer.json',value,time.monotonic()+2)

def closed_restoration(row,restored,now,acl):
 """Validate a closed ACL record without mistaking VNC unlink timestamps for drift."""
 restoration=(restored['path']==row['path']and restored['restored']is True and restored['ACL']==row['priorACL']==acl and now['st_mode']==row['before']['identity']['st_mode'])
 if row['role']=='runtime-parent':
  # vnc.sock is a declared transient child. Its create/unlink changes only the
  # parent directory timestamps; verify_phase below still requires its exact
  # final child census and the OVMF leaf's protected full content pin.
  stable=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size')
  return restoration and all(now[k]==restored['identity'][k]for k in stable)
 return restoration and restored['identity']==now

"""Readonly queue peer."""
import contextlib,fcntl,hashlib,json,os,re,stat,sys,time,traceback,zlib;import xml.etree.ElementTree as ET
from pathlib import Path;FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
CORE=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink');POOL='/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice'
GROUP='omen-iommu-group-1';NS='urn:opemos:steamos:libvirt:2'
class Refused(RuntimeError):pass
def need(v,m):
 if not v:raise Refused(m)
def canon(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def ident(s):return{k:getattr(s,k)for k in FIELDS}
def core(s):return{k:getattr(s,k)for k in CORE}
def same(ref,raw,st):return len(raw)==ref['bytes'] and hashlib.sha256(raw).hexdigest()==ref['sha256'] and ident(st)==ref['identity']
def process(pid):
 need(type(pid)is int and pid>0,'positive PID');p='/proc/'+str(pid)
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 def read(n,cap=65536):
  f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
  try:
   out=b''
   while b:=os.read(f,4096):out+=b;need(len(out)<=cap,'proc field bound')
   return out
  finally:os.close(f)
 try:
  before=read('stat');parts=before.decode().rsplit(')',1)[1].split();status=read('status').decode();cg=read('cgroup').decode().strip();argv=read('cmdline').split(b'\0');argv=argv[:-1]if argv and argv[-1]==b''else argv
  ids=[x for x in status.splitlines()if x.startswith('Uid:')];tg=[x for x in status.splitlines()if x.startswith('Tgid:')]
  need(len(ids)==len(tg)==1 and len(set(map(int,ids[0].split()[1:])))==1,'stable one UID/TGID');need(cg.startswith('0::/')and '\n'not in cg,'one unified cgroup')
  v={'pid':pid,'start':int(parts[19]),'uid':int(ids[0].split()[1]),'tgid':int(tg[0].split()[1]),'ppid':int(parts[1]),'cgroup':cg[3:],'argv':[os.fsdecode(x)for x in argv]};need(read('stat').decode().rsplit(')',1)[1].split()[19]==str(v['start'])and Path(p).is_dir(),'original proc start remained present')
  return v
 finally:os.close(fd)
def record_run_epoch(proof,event):
 raw=canon(event);last=proof['events'][-1]if proof['events']else None
 if last is not None and last['event']==event:last['count']+=1
 else:proof['events'].append({'event':event,'count':1})
 proof['eventCount']+=1;proof['eventChainSHA256']=hashlib.sha256(bytes.fromhex(proof['eventChainSHA256'])+raw).hexdigest();need(0<proof['eventCount']<=4096 and len(proof['events'])<=256 and len(canon(proof))<=262144,'bounded lossless borrowed run epoch runs')
class RootFiles:
 """Held nofollow ancestry; real FD/name/core and private full9 custody."""
 def __init__(self,path):self.path=Path(path);self.fds=[];self.chain=[];self.fd=None
 def __enter__(self):
  need(str(self.path).startswith('/run/opemos-')and len(self.path.parts)==3,'exact generated /run root');fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.fds.append(fd);self.chain.append((Path('/'),fd,core(os.fstat(fd))))
  try:
   for n in self.path.parts[1:]:
    fd=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);self.fds.append(fd);path=self.chain[-1][0]/n;st=os.fstat(fd)
    need(st.st_uid==st.st_gid==0 and stat.S_ISDIR(st.st_mode),'Root ancestor type/owner');self.chain.append((path,fd,core(st)))
    if path==Path('/run'):
     self.runFD=fd;self.runBirth=self.run_row(fd);rows=[x for x in Path('/proc/self/mountinfo').read_text().splitlines()if x.split()[0]==str(self.runBirth['mountID'])];need(len(rows)==1,'exact initial kernel run mount');self.runProof={'kind':'ROOT_BORROWED_RUN_ANCESTRY_R257','path':'/run','birth':self.runBirth,'namespace':os.readlink('/proc/self/ns/mnt'),'mountRow':rows[0],'events':[],'eventCount':0,'eventChainSHA256':'0'*64,'scopeDescriptorsClosed':False,'closeOutcomes':[]}
   self.fd=fd;st=os.fstat(fd);need(stat.S_IMODE(st.st_mode)==0o700,'private Root0700');self.private=ident(st);self.check();return self
  except BaseException:self.__exit__(*sys.exc_info());raise
 def run_row(self,fd):
   raw=Path('/proc/self/fdinfo/'+str(fd)).read_text();v={}
   for line in raw.splitlines():
    if line.startswith(('flags:','mnt_id:')):k,x=line.split(':',1);v[k]=x.strip()
   need(set(v)=={'flags','mnt_id'}and v['mnt_id'].isdigit()and re.fullmatch('[0-7]+',v['flags'])is not None,'complete actual run descriptor flags/mount')
   f=__import__('fcntl');return {'fd':fd,'identity':ident(os.fstat(fd)),'target':os.readlink('/proc/self/fd/'+str(fd)),'flags':f.fcntl(fd,f.F_GETFL),'descriptorFlags':f.fcntl(fd,f.F_GETFD),'fdinfoFlags':v['flags'],'mountID':int(v['mnt_id'])}
 def borrowed_run(self):
   initial=self.runBirth;owned=[];primary=None;event={};startns=os.readlink('/proc/self/ns/mnt')
   try:
    event['heldBefore']=self.run_row(self.runFD)
    for label,path,anchored in(('anchored','run',True),('named','/run',False)):
     fd=os.open(path,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,**({'dir_fd':self.chain[0][1]}if anchored else{}));owned.append(fd);event[label]=self.run_row(fd)
    event['anchoredPath']=ident(os.stat('run',dir_fd=self.chain[0][1],follow_symlinks=False));event['namedPath']=ident(os.lstat('/run'));event['heldAfter']=self.run_row(self.runFD);event['anchoredAfter']=self.run_row(owned[0]);event['namedAfter']=self.run_row(owned[1]);event['namespaceBefore']=startns;event['namespaceAfter']=os.readlink('/proc/self/ns/mnt')
    rows=[x for x in Path('/proc/self/mountinfo').read_text().splitlines()if x.split()[0]==str(initial['mountID'])];need(len(rows)==1,'unique current kernel run mount row');event['mountRow']=rows[0]
    stable=FIELDS[:5];snapshots=[event[k]['identity']for k in('heldBefore','anchored','named','heldAfter','anchoredAfter','namedAfter')]+[event['anchoredPath'],event['namedPath']]
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
     except BaseException as e:errors.append({'fd':fd,'type':type(e).__name__,'reason':str(e),'closure':'UNKNOWN'})
    if errors:
     if primary is not None:primary.ownedRootInputClosureErrors=errors
     else:
      failure=Refused(canon({'ownedRootInputClosureErrors':errors}).decode());failure.ownedRootInputClosureErrors=errors;failure.evidence={'kind':'BORROWED_RUN_CLOSE_REFUSAL_R258','birth':initial,'event':event,'ownedRootInputClosureErrors':errors};raise failure
   event['temporaryDescriptorsClosed']=True;record_run_epoch(self.runProof,event);return event
 def check(self):
  for p,fd,initial in self.chain:
   if p==Path('/run'):self.borrowed_run();continue
   a=os.fstat(fd);b=os.lstat(p);need(core(a)==core(b)==initial,'ancestor core/FD/name drift')
   if p==Path('/'):need(a.st_uid==a.st_gid==0 and stat.S_IMODE(a.st_mode)in(0o755,0o777),'declared host root boundary')
   elif p==Path('/run'):need(stat.S_IMODE(a.st_mode)==0o755,'shared /run mode')
  need(ident(os.fstat(self.fd))==ident(os.lstat(self.path)),'private FD/name full9')
 def parent_pin(self):
  self.check();i=ident(os.fstat(self.fd));return {'path':str(self.path),'bytes':i['st_size'],'sha256':hashlib.sha256(canon(i)).hexdigest(),'identity':i}
 def read(self,name,mode=0o400,cap=1048576):
  need(re.fullmatch('[A-Za-z0-9_.-]+',name)is not None,'confined leaf');f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.fd)
  try:
   a=os.fstat(f);need(stat.S_ISREG(a.st_mode)and a.st_uid==a.st_gid==0 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==mode and a.st_size<=cap,'Root exact leaf custody/cap');raw=b''
   while b:=os.read(f,65536):raw+=b;need(len(raw)<=cap,'bounded streaming leaf')
   need(ident(a)==ident(os.fstat(f))==ident(os.stat(name,dir_fd=self.fd,follow_symlinks=False))and len(raw)==a.st_size,'leaf full9/EOF drift');self.check()
   return raw,{'path':str(self.path/name),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':ident(a)}
  finally:os.close(f)
 @contextlib.contextmanager
 def lock(self,exclusive=False,deadline=None):
  f=os.open('lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.fd);first=None;value={}
  try:
   s=os.fstat(f);i=ident(s);value={'fd':f,'identity':i,'mode':'EX'if exclusive else'SH','startedMonotonic':time.monotonic(),'closed':False};need(s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and stat.S_ISREG(s.st_mode)and i==ident(os.stat('lock',dir_fd=self.fd,follow_symlinks=False)),'Root lock held/named custody')
   value={'fd':f,'identity':i,'mode':'EX'if exclusive else'SH','startedMonotonic':time.monotonic(),'closed':False}
   if deadline is None:fcntl.flock(f,fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH|fcntl.LOCK_NB)
   else:
    need(type(deadline)in(int,float)and 0<deadline-time.monotonic()<=30,'original finite runtime lock window')
    while True:
     try:fcntl.flock(f,(fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)|fcntl.LOCK_NB);break
     except BlockingIOError:
      if time.monotonic()>=deadline:
       error=Refused('runtime publication lock deadline');error.evidence=value;raise error
      time.sleep(min(.005,max(0,deadline-time.monotonic())))
   need(i==ident(os.fstat(f))==ident(os.stat('lock',dir_fd=self.fd,follow_symlinks=False)),'Root lock identity after acquisition');value['acquiredMonotonic']=time.monotonic();value['fdinfo']=Path('/proc/self/fdinfo/'+str(f)).read_text();yield value
  except BaseException as error:
   first=error
   if getattr(error,'evidence',None)is None:error.evidence={'kind':'ROOT_LOCK_CUSTODY_REFUSAL','path':str(self.path/'lock'),'snapshot':value,'preLockDirectory':self.private}
   raise
  finally:
   try:os.close(f);value['closed']=True
   except BaseException as error:
    if first is None:raise
    first.lockCloseErrors=getattr(first,'lockCloseErrors',[])+[{'fd':f,'type':type(error).__name__,'reason':str(error),'UNKNOWN':True}]
 def __exit__(self,*args):
  first=None
  if hasattr(self,'runProof')and self.fd is not None:
   try:self.privateAfter=ident(os.fstat(self.fd))
   except BaseException as error:first=error
  for fd in self.fds[::-1]:
   try:
    os.close(fd)
    if hasattr(self,'runProof'):self.runProof['closeOutcomes'].append({'fd':fd,'closed':True})
   except BaseException as e:first=first or e
  self.fds=[]
  if hasattr(self,'runProof'):self.runProof['scopeDescriptorsClosed']=first is None
  if first:
   if args[1]is not None:args[1].rootFilesCloseErrors=getattr(args[1],'rootFilesCloseErrors',[])+[{'type':type(first).__name__,'reason':str(first),'UNKNOWN':True}]
   else:raise first
def _complete_historical_libvirt_closed(state):
 closed=state.get('currentDisposition');flat=type(closed)is dict and all(closed.get(k)is True for k in('domainAbsent','originalPIDStartAbsent','cgroupEmpty','VFIOFDsAbsent','hostRestored'))and (type(closed.get('unknown'))is list and closed['unknown']==[])
 if flat:return True
 need(type(closed)is dict and set(closed)=={'currentClosure','first','secondary','historicalQMPClosed','noHistoricalCloseFabrication'}and closed['noHistoricalCloseFabrication']is True and closed['historicalQMPClosed']is None and closed['secondary']==[],'exact genuine nested libvirt diagnostic disposition, historical QMP remains unknown');cc=closed['currentClosure'];need(type(cc)is dict and all(cc.get(k)is True for k in('known','FDsClosed','domainAbsent','hostRestored','preservePrimary','noSignalOrSysfsEffect'))and cc.get('leaseHeld')is False and cc.get('secondary')==[]and cc.get('historicalQMPClosed')is None,'nested complete current domain/FD/host closure')
 actions=cc.get('actions');need(type(actions)is list and 0<len(actions)<=64 and all(type(x)is dict and set(x)=={'role','value'}and type(x['role'])is str for x in actions),'finite typed native closure actions');roles=[x['role']for x in actions];need(len(roles)==len(set(roles)),'unique closure action roles');values={x['role']:x['value']for x in actions}
 proof=values.get('independent-current-domain-host-closure');need(type(proof)is dict and all(proof.get(k)is True for k in('known','ACLRestored','VFIOFDsAbsent','cgroupEmpty','domainAbsent','hostRestored','originalPIDStartAbsent','currentDispositionOnly','originalFullHashVerified'))and proof.get('unknown')==[]and proof.get('historicalQMPClosed')is None and proof.get('controllerWaitpidClaimed')is False and cc.get('closure')==proof,'authenticated complete independent current closure/action equality, no historical QMP fabrication')
 acl=values.get('six-ACL-restoration');need(type(acl)is list and len(acl)==6 and len({x.get('path')for x in acl if type(x)is dict})==6 and all(type(x)is dict and x.get('restored')is True and type(x.get('path'))is str and x['path'].startswith('/')and x.get('identity',{}).get('st_uid')==x.get('identity',{}).get('st_gid')==0 for x in acl),'exact six distinct Root restored ACL paths')
 for role in('control-connection','observer-connection'):
  v=values.get(role);need(type(v)is dict and type(v.get('numeric'))is int and v['numeric']==0,'positive native libvirt connection close')
 change=cc.get('FDComparison',{}).get('changes');need(change=={'added':[],'removed':[],'replaced':[]},'native role FD comparison closed without unknown changes')
 need(state.get('restored')is True and state.get('changed')==[],'nested closed native lease restored unchanged');return True
_hp_z=zlib.decompressobj();_hp_raw=_hp_z.decompress(__import__('base64').b85decode('c-oCv-*4MC5Pr{JLG*<-D%)L$4QM(&v`vNv=+ZV#hXI~p$Pyhfl}Ux9oCZby_kBlFzno;-ODu_Z$GhWq-yKtkEnAn;I&Ea0RqIM*R;+8I_d;bV7n4F7kz@5PG5Xdf8>tGZuGV!XjZJPE(THTDwVNIvv1iYoebD(gQLwx*MkvP$X=`nzlUlLoY?EP86*F6lTyAB~<ZjovY*Pu=Z#X|XVwa_0aHbN5m6>JOQq)j{#p;gjg@H0Qagf3%_}A^{{b5#RwJo(<SlyUh9I;Fltde_(?`n6)N^RYu*1DQwCu!NXQMq?f2??Wy8R64lS;qVWQ`#`s7-f&Tt+I_3a2L)w&H4ng&wqSkVlN9?oU;o-YH)VjR28eGvTWB_$82NvaOenui)|&ZO6Q$KvRsHk+%#Dw-Ccsc9lItSN4`phY+@VTI5<j4n)}2bvF@PKPnj$GbDO?a8os36hq=mjVs69^DW~n__X*cEUhQnZm3qdfN63UICf1pOnKb1K)2PKr^trd~eK%rGLGCh_mlM8xF?*HGwyPgMzr5#(mzu(T3g%oZk#O-n%iS<>b$Ms~LrA#+s5pElN8DX4CImk+Q9&h~s8HeKZ|Tcle(gT}FiS2AzS`o<4D!WD<{s{M@(FL0M4H2)3|yd9iavteB4@dqj36I9B3rFgG(8scK8-i}Chh=)!FH_y+VU32V;6||cUcKLNIUSqrB8|fJFie+6Dl@Vn(Q_y>oj~fA}c1m#NYX~)e4!T=ainIlNEMC^4KUIt#A_(fbTze4ZQG#Z|<D1__bvQ-|;{ocEBLNr`!@6JhDh{8I)Gjd7V)?zz(ekUuX$Q&NCc)IMKiggV1kFU5Od$fsr+MYbhE#isq5c2)U4TnG?g%>?pK4O-YLdry;uJ9)En5rafHaN?vIzfEEDj(lnzbBgow+7V|PwSG1O<%T>a^DSfM0Ft%tF*#nGw<<|@)q!z%ZkXLHasGy8WY`{6lg)bpt)1_e}5Hq=D5!{q+@5i;?oSpF1s*RqI81-=`KY5qq`|`zV$+sX7TgIT;YJ4E&jYC9Dka|lAO87Rz(a?jFJ5j7bKzPRAx^e4D?j*f#!b$UKTi+n5omAPV%HT3sO@PN)-E1oK0kHqI@Dz;b5oy}{@;Ww+5byj7xaIK^l?|!tEig<c{z)o+T-Hf&-@jSBg%ll+6P83w9Q&Vy_x^#v-vv+{5B7X)9Z|Nf9P?1Io)$UIDK0Q%*=JZ(;I#Ph9)3R*p_*nnl|eo(>Rc;l(5zxz$JZhL^N9Zdfhh1O>btd=hC>{UWT>y7d9cw_d!!-I5px^u@JV#4i?&H_0*U)WTDF1E!K~7}?i_wP*fgEQj3C!><0#=d_0<CNL5b2ao<(4h@_gJ`Zo!lCN^bVj5Jua28xnCmiM|A5{|luaf_Y1^#9R!SAZ89V+VXkQ?#70B@H!!dp%Y;9D_<K?&-)M2MipxWownwd2c<sfiJdStMi4MaSMTadIPt(b3-s>yFqkgDQK=s_=F!=8{7OAC8Gx(bWBPiJnWTU-y=?gPRttGWM(IRgavs{q#CL&CZaOc;_aHclS&mB~zT$C6b~1i8IDeAOquiJGZ>WPoB5c({x64VGv7+?Cn^|BxaItg?srEY0h>aFOJtXahCX(?C6f-yT<}eHmL%Gy|6enIj?CstV_4S+3*l!LyJJ^9hFYEMXSQ?l#fu)uP!rPDqWXl2p`$1sIzv28T75w7k$IJEUUvJ)Bu0MZ0{d&6oaQ61kvy031+4<$^`Q`fJC8t!jdNCMMjgM@&?8)JzCkKnxJYa&h0)qIWP4yu$_#vh)4<fCBAu$^cGycorL{pdJh-s+l1pQ<K!qBGZXPWy5gQ|&}(Y(6)@$&xfuw&BMS++)2<N4K>Mc3o|z`bHS)zm(`adeMa4)Kj*8;5pKRDN|>N@+SU8-w+g<3BG$kRAo^K79Ogdcp^5PZSLsh>Q<=xMFkEf*&TjK_af8R10CcrM3pc{>;OrMTIx&)#$ntu4+bHfuKzmr-DK_%pW$5#^WoGWZ15zW6D11ub&|s>y{ozSKi2fVR{R!k9HGoY<+8s$R(-9kbjl;&3ioPCEg0#W*d49&iiBZJ#gOCM4z!X(Fjvn2dKRd^9$mOAN)%lZrB&Y6KXlFC9}7I-{ax|P&)FS<36ejF&Q&(XXHZPK5ih=x4s=KM(%!^pU}A@iA^c-|6bk@?wH_#_+#}#3Zb-cP#Im~MAdUn|IdWskU)3qSwlC=ep+}ievF-pS1j++|G1byBVJ?R)x$dvX)HXt{=+Tf|7j2q^AAu;L9z'),8193)
need(_hp_z.eof and not _hp_z.unused_data and not _hp_z.unconsumed_tail and len(_hp_raw)==4512 and hashlib.sha256(_hp_raw).hexdigest()=='701588e9f9273e7a00372c42d38fd18729bc80f37f83520bb4db607e3f004153','exact immutable historical provenance definition')
exec(compile(_hp_raw,__file__,'exec'));del _hp_z,_hp_raw
def historical_lease_provenance(directory,rows,binding_pairs,queue,boot):
 try:return _historical_lease_provenance(directory,rows,binding_pairs,queue,boot)
 except BaseException as error:
  error.evidence={'historicalLeaseRoot':str(directory),'operation':'locked backend-specific historical provenance','priorEvidence':getattr(error,'evidence',None)};raise
def verify_historical_lease_set(expected,rows,binding_pairs,queue,boot):
 need(type(expected)is list and len(expected)<=64 and len({r['headPin']['path']for r in expected})==len(expected),'finite unique expected historical lease set');observed=[]
 for prior in expected:
  value=historical_lease_provenance(str(Path(prior['headPin']['path']).parent),rows,binding_pairs,queue,boot);need(value==prior,'entire locked historical backend provenance unchanged')
  observed.append(value)
 return observed
def validate_request(r):
 fields={'jobId','jobToken','unit','invocation','specSHA256','domainUUID','domainName','leaseNonce','cpus','controllerMemory','domainMemory','reservationMemory','vmSlice','partition','gpuGroup','observer'};need(type(r)is dict and set(r)==fields,'exact upstream request schema')
 t=r['jobToken'];need(re.fullmatch('[0-9a-f]{32}',t)is not None and r['unit'].endswith('-'+t+'.service'),'exact queue token/unit')
 need(re.fullmatch('[0-9a-f]{32}',r['invocation'])is not None and re.fullmatch('[0-9a-f]{64}',r['specSHA256'])is not None,'queue immutable invocation/spec');need(r['vmSlice']=='opemos-vm-pool-libvirt'+t+'.slice' and r['partition']=='/opemos/vm/pool/libvirt'+t,'derived per-job partition')
 need(r['controllerMemory']==2*1024**3 and r['domainMemory']==8*1024**3 and r['reservationMemory']==10*1024**3,'one10GiB split2+8');need(type(r['cpus'])is list and len(r['cpus'])==len(set(r['cpus']))==4 and all(type(n)is int and 0<=n<10 for n in r['cpus']),'same exact assigned four CPUs')
 need(r['gpuGroup']==GROUP and re.fullmatch('[0-9a-f]{32}',r['leaseNonce'])is not None,'one physical group lease');need(re.fullmatch('opemos-libvirt-[0-9a-f]{32}',r['domainName'])is not None,'exact libvirt domain name')
 import uuid;need(str(uuid.UUID(r['domainUUID']))==r['domainUUID'],'canonical domain UUID')
 need(type(r['observer'])is dict and set(r['observer'])=={'path','bytes','sha256'}and 0<r['observer']['bytes']<=65536 and re.fullmatch('[0-9a-f]{64}',r['observer']['sha256'])is not None,'upstream exact minimal observer pin')
def validate_hostdev_xml(x,intent):
 devices=x.findall('devices/hostdev');need(len(devices)==4,'exact four managed hostdevs')
 observed=[]
 for h in devices:
  need(h.get('type')=='pci'and h.get('mode')=='subsystem'and h.get('managed')=='yes','managed-only PCI control');a=h.find('source/address');need(a is not None,'explicit source BDF');observed.append('%04x:%02x:%02x.%x'%tuple(int(a.get(k),0)for k in('domain','bus','slot','function')))
 need(len(set(observed))==4 and set(observed)=={e['bdf']for e in intent['endpoints']},'exact four distinct original group endpoints')
def read_lease(files,request,boot):
 raw,hp=files.read('head.json');head=json.loads(raw);need(set(head)=={'path','bytes','sha256','identity'}and str(Path(head['path']).parent)==str(files.path)and re.fullmatch('state-(?:[0-9]|[1-5][0-9]|6[0-3])[.]json',Path(head['path']).name)is not None,'canonical confined full native state-pin head')
 b,sp=files.read(Path(head['path']).name);s=json.loads(b);need(sp==head and Path(head['path']).name=='state-'+str(s['revision'])+'.json','lease head/state exact full9/size/SHA/revision')
 need(s['nonce']==request['leaseNonce']and s['jobID']==request['jobId']and s['currentBoot']==boot and s['requestSHA256']==hashlib.sha256(canon(request)).hexdigest(),'same request/job/boot lease');need(type(s['closed'])is bool and type(s['restored'])is bool and type(s['changed'])is list and s['backend']=='libvirt','typed libvirt lease')
 return s,{'group':GROUP,'nonce':s['nonce'],'jobId':s['jobID'],'headPin':hp,'statePin':sp,'closed':s['closed'],'restored':s['restored'],'currentBoot':boot},(raw,b)
def run_anchor(n,r,o):
 p=Path(o['path']);need(p.name=='libvirt_peer.py'and p.parent.parent==Path('/run')and p.parent in (Path('/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r107b'),Path('/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r118')),'run ancestry');fds=[];ns=os.readlink('/proc/self/ns/mnt')
 try:
  d=os.open('/run',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(d);s=os.open(p.parent.name,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=d);fds.append(s);b=ident(os.fstat(s));need(b==ident(os.lstat(p.parent))and b['st_uid']==b['st_gid']==0 and not b['st_mode']&0o022,'run parent');a=ident(os.fstat(d));i=Path('/proc/self/fdinfo/'+str(d)).read_text();epochs={'snapshot':r['identity'],'anchored':a,'named':ident(os.lstat('/run')),'held':ident(os.fstat(n))};need(all(all(v[k]==a[k]for k in FIELDS[:5])for v in epochs.values())and ns==os.readlink('/proc/self/ns/mnt'),'run stable name/FD core');return {'named':a,'info':i,'ns':ns,'observer':o,'parent':b,'epochs':epochs}
 finally:
  for f in fds[::-1]:os.close(f)
def run_pair(a,b,o):
 try:
  x=a['runAncestry'];y=b['runAncestry'];keys={'named','info','ns','observer','parent','epochs'}
  for r,p in((a,x),(b,y)):
   need(set(p)==keys and p['observer']==o and all(p['named'][k]==r['identity'][k]for k in FIELDS[:5])and set(p['epochs'])=={'snapshot','anchored','named','held'}and all(all(e[k]==r['identity'][k]for k in FIELDS[:5])for e in p['epochs'].values())and p['epochs']['snapshot']==r['identity']and r['target']=='/run'and r['identity']['st_mode']==0o40755 and r['identity']['st_uid']==r['identity']['st_gid']==0,'run proof');u=dict(z.split(':',1)for z in r['fdinfo'].splitlines()if ':'in z);v=dict(z.split(':',1)for z in p['info'].splitlines()if ':'in z);need(len(r['fdinfo'].splitlines())==len(p['info'].splitlines())==4 and set(u)==set(v)=={'pos','flags','mnt_id','ino'},'run facts');flags=int(r['flags'],8);need(flags in(0o2700000,0o12600000)and int(v['flags'],8)==0o12600000 and not r['eventfdID']and u['flags'].strip()==r['flags']and u['mnt_id'].strip()==v['mnt_id'].strip()and u['ino'].strip()==v['ino'].strip()==str(r['identity']['st_ino']),'run mount')
  return all(a[k]==b[k]for k in('fd','target','flags','eventfdID','fdinfo'))and all(a['identity'][k]==b['identity'][k]for k in FIELDS[:5])and all(x[k]==y[k]for k in('ns','parent'))
 except(KeyError,TypeError,ValueError,Refused):return False
def fd_snapshot(label,observer=None):
 if observer is None and label in('helper-before','helper-after')and _READONLY_REQUEST_CONTEXT is not None:
  need(_READONLY_REQUEST_CONTEXT['pid']==os.getpid(),'same owned readonly helper context');observer=_READONLY_REQUEST_CONTEXT['observer']
 rows=[];vanished=[];names=os.listdir('/proc/self/fd');need(len(names)<=256,'bounded FD inventory')
 for name in sorted(names,key=int):
  n=int(name)
  try:
   a=ident(os.fstat(n));target=os.readlink('/proc/self/fd/'+name);info=Path('/proc/self/fdinfo/'+name).read_text();need(len(target)<=4096 and len(info)<=8192 and (all(a[k]==ident(os.fstat(n))[k]for k in FIELDS[:5])if observer is not None and target=='/run'else a==ident(os.fstat(n))),'bounded stable FD observation');fields=dict(x.split(':',1)for x in info.splitlines()if ':'in x);r={'fd':n,'identity':a,'target':target,'flags':fields.get('flags','').strip(),'eventfdID':fields.get('eventfd-id','').strip(),'fdinfo':info};rows.append(r)
   if observer is not None and target=='/run':
    try:r['runAncestry']=run_anchor(n,r,observer)
    except(OSError,Refused,KeyError,ValueError)as e:r['runAncestry']={'error':str(e)}
  except FileNotFoundError:vanished.append(n)
  except OSError as error:
   if error.errno==9:vanished.append(n)
   else:raise
 return {'label':label,'actor':{k:process(os.getpid())[k]for k in('pid','start','uid')},'atUnix':time.time(),'rows':rows,'vanishedDuringFDList':vanished,**({'borrowedObserver':observer}if observer is not None else{})}
def fd_key(row):return {k:row[k]for k in('fd','identity','target','flags','eventfdID')}
def fd_changes(before,after):
 aa={r['fd']:r for r in before['rows']};bb={r['fd']:r for r in after['rows']};a={n:fd_key(r)for n,r in aa.items()};b={n:fd_key(r)for n,r in bb.items()};borrowed=(before['label'],after['label'])in(('readonly-observe-before','readonly-observe-after'),('helper-before','helper-after'))and before.get('borrowedObserver')==after.get('borrowedObserver')and before.get('borrowedObserver')is not None
 return {'added':[b[n]for n in sorted(b.keys()-a.keys())],'removed':[a[n]for n in sorted(a.keys()-b.keys())],'replaced':[{'before':a[n],'after':b[n]}for n in sorted(a.keys()&b.keys())if (not run_pair(aa[n],bb[n],before['borrowedObserver'])if borrowed and aa[n]['target']==bb[n]['target']=='/run'else a[n]!=b[n])]}
def fd_equal(before,after):return not any(fd_changes(before,after).values())
def error_value(error):
 if error is None:return None
 return {'type':type(error).__name__,'reason':str(error),'traceback':__import__('traceback').format_exception(type(error),error,error.__traceback__),**{k:getattr(error,k)for k in('workingEvidence','closeEvidence','capturePersistenceError','nativeChildEvidence','observerBudgetEvidence','ownedRootInputClosureErrors')if hasattr(error,k)}}
class NativeOps:
 """Read-only native observation. No daemon/domain/device mutation methods."""
 def __init__(self,close_pump=None,persist=None):self.conn=None;self.domainObjects={};self.close_pump=close_pump;self.persist=persist;self.closeOutcomes=[]
 def boot(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 def actor(self):
  p=process(os.getpid());return {k:p[k]for k in('pid','start','uid')}
 def domains(self):
  import libvirt;self.conn=libvirt.openReadOnly('qemu:///system');need(self.conn is not None and self.conn.getURI()=='qemu:///system','readonly system libvirt')
  ds=self.conn.listAllDomains(0);need(len(ds)<=128,'finite complete domain enumeration');out=[]
  for d in ds:
   x=ET.fromstring(d.XMLDesc(0));u=d.UUIDString();self.domainObjects[u]=d
   out.append({'uuid':u,'name':d.name(),'active':bool(d.isActive()),'persistent':bool(d.isPersistent()),'xml':d.XMLDesc(0),'noNIC':not x.findall('devices/interface')})
  need(len({x['uuid']for x in out})==len(out)and len({x['name']for x in out})==len(out),'unique full domain inventory');return out
 def manager(self,unit):
  args=['/usr/bin/systemctl','show',unit,'-p','LoadState','-p','InvocationID','-p','ControlGroup','-p','MainPID','-p','ActiveState'];x=__import__('libvirt_native').native_child(args,time.time()+5)
  try:
   need(x['numeric']==0 and not x['stderr']and len(x['stdout'].encode())<=65536,'bounded manager read');return dict(y.split('=',1)for y in x['stdout'].splitlines())
  except BaseException as error:
   error.nativeChildEvidence=x;error.evidence=x;raise
 def entry(self,intent,phase):
  r=intent['request'];m=self.manager(r['unit'])
  if phase=='CLOSED'and m.get('LoadState')=='not-found':return
  if phase=='CLOSED'and m.get('LoadState')=='loaded'and m.get('ActiveState')=='failed':
   observed={'unit':r['unit'],'expectedInvocation':r['invocation'],'manager':m,'expectedCgroup':POOL+'/'+r['unit'],'phase':phase}
   if self.persist is not None:self.persist('closed-loaded-failed-manager-before-predicate',observed)
   need(m.get('InvocationID')==r['invocation']and m.get('ControlGroup')==''and m.get('MainPID')=='0','same exact failed invocation with no live manager PID/cgroup');need(not os.path.lexists('/sys/fs/cgroup'+POOL+'/'+r['unit']),'exact failed service cgroup actually absent')
   after=self.manager(r['unit'])
   if self.persist is not None:self.persist('closed-loaded-failed-manager-after',{'before':observed,'after':after})
   need(after==m,'same failed invocation/state remained stable');return
  need(m.get('InvocationID')==r['invocation']and m.get('ControlGroup')==POOL+'/'+r['unit'],'current exact own service invocation/cgroup');need(int(m.get('MainPID','0'))==intent['entry']['managerMainPID'],'same actual logger MainPID')
  if phase!='CLOSED':
   a=process(intent['entry']['pid']);need(all(a[k]==intent['entry'][k]for k in('pid','start','uid'))and a['uid']==0 and a['cgroup'].startswith(POOL+'/'+r['unit']),'current Root queue entry actor')
   need(hashlib.sha256(canon(a['argv'])).hexdigest()==intent['entry']['argvSHA256'],'Root entry exact argv')
 def budget(self,r,phase,scope):
  root=Path('/sys/fs/cgroup'+POOL+'/'+r['vmSlice']);need(root.is_dir()and not root.is_symlink(),'exact existing VM slice')
  fields={n:(root/n).read_text().strip()for n in('cpu.max','memory.max','memory.swap.max','cpuset.cpus.effective','cgroup.events','cgroup.procs')};need(fields['cpu.max']=='400000 100000'and fields['memory.max']==str(8*1024**3)and fields['memory.swap.max']=='0','actual VM slice4CPU8GiBswap0')
  def cpus(text):
   v=set()
   for x in text.split(','):
    if '-'in x:a,b=map(int,x.split('-'));v.update(range(a,b+1))
    elif x:v.add(int(x))
   return v
  need(cpus(fields['cpuset.cpus.effective'])==set(r['cpus']),'actual same four CPUs');pool=Path('/sys/fs/cgroup'+POOL);need((pool/'cpu.max').read_text().strip()=='1000000 100000'and(pool/'memory.max').read_text().strip()==str(32*1024**3)and(pool/'memory.swap.max').read_text().strip()=='0','unchanged whole pool')
  children=[p.name for p in root.iterdir()if p.is_dir()];need(children==([]if scope is None else[scope]),'no foreign scope even empty')
  if phase!='ACTIVE':need(not fields['cgroup.procs']and 'populated 0'in fields['cgroup.events'],'inactive partition actually empty')
  if r['leaseNonce']==SOURCE_PLACEMENT_NONCE:storage_contract(r['leaseNonce'],r,self.persist)
 def leader(self,reg,intent):
  a=process(reg['leader']['pid']);need({k:a[k]for k in('pid','start','uid')}==reg['leader']and a['tgid']==a['pid']and a['uid']==64055,'fresh original QEMU leader PID/start/UID')
  r=intent['request'];prefix=POOL+'/'+r['vmSlice']+'/'+reg['scope'];need(a['cgroup']==prefix or a['cgroup'].startswith(prefix+'/'),'exact domain scope descendant')
  args=a['argv'];need('-uuid'in args and args[args.index('-uuid')+1]==r['domainUUID']and '-name'in args and ('guest='+r['domainName'])in args[args.index('-name')+1].split(','),'exact QEMU UUID/name argv')
  fd=os.open('/proc/'+str(a['pid'])+'/exe',os.O_RDONLY|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);ref=intent['qemuPin'];h=hashlib.sha256();n=0
   while b:=os.read(fd,65536):n+=len(b);need(n<=33554432,'QEMU target32MiB');h.update(b)
   need(ident(st)==ref['identity']and n==ref['bytes']and h.hexdigest()==ref['sha256']and ident(st)==ident(os.fstat(fd)),'exact current QEMU exe FD/full9/hash')
  finally:os.close(fd)
  self.active_devices(a,intent);need(process(a['pid'])==a,'original actor fully revalidated');return reg['leader']
 def active_devices(self,actor,intent):
  for e in intent['endpoints']:
   root=Path('/sys/bus/pci/devices')/e['bdf']
   for field,key in (('vendor','vendor'),('device','device'),('class','class'),('subsystem_vendor','subsystemVendor'),('subsystem_device','subsystemDevice')):need((root/field).read_text().strip()==e[key],'actual managed endpoint full identity')
   need(os.path.basename(os.readlink(root/'iommu_group'))=='1'and os.path.basename(os.readlink(root/'driver'))=='vfio-pci','all four exact endpoints managed into same vfio group')
  found=[];unknown=[];count=0;scanned=0;raw=None;observedFD=None;matched=False
  try:
   for proc in Path('/proc').iterdir():
    if not proc.name.isdigit():continue
    raw=None;observedFD=None;matched=False;scanned+=1;need(scanned<=8192,'bounded managed process inventory')
    try:
     raw=process_snapshot(int(proc.name));fds=list((proc/'fd').iterdir());need(len(fds)<=16384,'bounded managed FD scan')
     for fd in fds:
      count+=1;need(count<=262144,'bounded whole-host FD scan')
      try:target=os.readlink(fd)
      except FileNotFoundError:continue
      if target in('/dev/vfio/1','/dev/vfio/vfio')or target.startswith('/dev/vfio/devices/'):
       matched=True;observedFD={'pid':raw['pid'],'fd':fd.name,'target':target,'raw':raw}
       if self.persist is not None:self.persist('vfio-holder-before-role',observedFD)
       original=process(raw['pid']);need(raw['uids']==[64055]*4 and original['tgid']==original['pid']and all(original[k]==raw[k]for k in('pid','start','ppid','tgid','argv','cgroup')),'matched VFIO holder raw/strict principal identity')
       need(all(original[k]==actor[k]for k in('pid','start','ppid','tgid','uid','argv','cgroup'))and original['uid']==64055,'no foreign VFIO holder');need(process_snapshot(raw['pid'])==raw and process(raw['pid'])==original and os.readlink(fd)==target,'same matched VFIO holder and FD revalidated')
       found.append(observedFD)
     need(process_snapshot(raw['pid'])==raw,'ambient FD-scan raw identity stable')
    except(FileNotFoundError,ProcessLookupError):
     need(not matched,'observed VFIO holder disappearance is unknown; refuse');continue
    except PermissionError:unknown.append(int(proc.name))
   need(not unknown and any(x['target']=='/dev/vfio/1'for x in found),'positive exact QEMU group1 FD and no unknowns; alternate cdev route needs reviewed proof')
   if self.persist is not None:self.persist('vfio-inventory-verified',{'scanned':scanned,'FDs':count,'matched':found,'unknown':unknown})
  except BaseException as error:
   evidence={'stage':'whole-host-VFIO-FD-inventory','first':{'type':type(error).__name__,'reason':str(error)},'currentRawActor':raw,'currentMatchedFD':observedFD,'matched':found,'unknown':unknown,'scanned':scanned,'FDs':count,'selectedQEMU':actor};error.vfioEvidence=evidence
   try:
    if self.persist is not None:self.persist('FIRST-vfio-inventory',evidence)
   except BaseException as secondary:evidence['diagnosticPersistenceError']={'type':type(secondary).__name__,'reason':str(secondary)}
   raise
 def restoration(self,intent):
  for e in intent['endpoints']:
   p=Path('/sys/bus/pci/devices')/e['bdf'];need(p.exists(),'same physical endpoint')
   for field,key in (('vendor','vendor'),('device','device'),('class','class'),('subsystem_vendor','subsystemVendor'),('subsystem_device','subsystemDevice')):need((p/field).read_text().strip()==e[key],'exact physical endpoint identity')
   need(os.path.basename(os.readlink(p/'iommu_group'))=='1','exact IOMMU group1');driver=os.path.basename(os.readlink(p/'driver'))if(p/'driver').exists()else None
   need(driver==e['originalDriver']and(p/'driver_override').read_text()==e['originalOverride'],'all original driver/override states restored')
  root=Path('/dev/vfio');targets={str(root/'1'),str(root/'vfio')};unknown=[];holders=[];count=0
  for proc in Path('/proc').iterdir():
   if not proc.name.isdigit():continue
   try:
    fs=list((proc/'fd').iterdir());need(len(fs)<=16384,'per-process FD bound')
    for f in fs:
     count+=1;need(count<=262144,'whole host FD bound')
     try:t=os.readlink(f)
     except FileNotFoundError:continue
     if t in targets or t.startswith('/dev/vfio/devices/'):holders.append({'pid':int(proc.name),'fd':f.name,'target':t})
   except FileNotFoundError:continue
   except PermissionError:unknown.append(int(proc.name))
  need(not holders and not unknown,'complete current VFIO holder/unknown absence')
 def close(self):
  before=fd_snapshot('readonly-before-close');numeric=None;first=None
  try:
   self.domainObjects.clear()
   if self.conn is not None:
    conn=self.conn;self.conn=None;numeric=conn.close();conn=None;need(numeric==0,'readonly libvirt connection close')
    if self.close_pump is not None:self.close_pump('readonly-connection-close')
  except BaseException as error:first=error
  after=fd_snapshot('readonly-after-close');v={'before':before,'after':after,'numeric':numeric,'primary':error_value(first)};self.closeOutcomes.append(v)
  if self.persist is not None:self.persist('readonly-connection-close',v)
  if first is not None:raise first
_READONLY_REQUEST_CONTEXT=None
def readonly_request_context(fn):
 def call(request,*args,**kwargs):
  global _READONLY_REQUEST_CONTEXT
  validate_request(request);need(_READONLY_REQUEST_CONTEXT is None,'no nested readonly request context');_READONLY_REQUEST_CONTEXT={'observer':request['observer'],'pid':os.getpid()}
  try:return fn(request,*args,**kwargs)
  finally:_READONLY_REQUEST_CONTEXT=None
 return call
@readonly_request_context
def observe(request,ops=None,custody=None):
 validate_request(request);ops=NativeOps()if ops is None else ops;custody=getattr(ops,'custody',None)if custody is None else custody;started=time.monotonic();before=fd_snapshot('readonly-observe-before',request['observer']);proof=None;primary=None;secondary=[]
 try:
  need(os.getuid()==0,'actual Root readonly producer');boot=ops.boot();actor=ops.actor();need(actor['uid']==0,'Root observer actor')
  domains=ops.domains();target=[d for d in domains if d['uuid']==request['domainUUID']or d['name']==request['domainName']]
  need(len(target)<=1,'ambiguous target domain');path='/run/opemos-libvirt-queue-'+request['jobToken']
  proof={'kind':'ROOT_CURRENT_EXACT_QUEUE_LIBVIRT_DOMAIN_R1','request':request,'bootID':boot,'producer':actor,'sourceSHA256':request['observer']['sha256'],'startedMonotonic':started,'completedMonotonic':None,'phase':'NOT_PREPARED','scope':None,'leader':None,'intentPin':None,'intentParentPin':None,'lease':None,'domainUUID':request['domainUUID'],'persistent':False,'noNIC':True,'fullDomainEnumeration':True,'allOwnedDescriptorsClosed':False,'effects':[],'rootAncestorCustody':[]}
  if not os.path.lexists(path):
    need(not target,'no adoption of target domain without intent')
    if custody is not None:proof['accessCustody']=custody('NOT_PREPARED',None,None,None,None);proof['accessCustody']['phasePins']=None
  else:
   with RootFiles(path)as files,files.lock():
    ir,ip=files.read('intent.json');intent=json.loads(ir);need(intent['kind']=='ROOT_EXACT_QUEUE_LIBVIRT_INTENT_R2'and intent['request']==request and intent['bootID']==boot,'entire current Root intent/request/boot')
    hr,hp=files.read('phase-head.json');head=json.loads(hr);need(set(head)=={'record','sha256'}and re.fullmatch('phase-[0-9]{2}.json',head['record'])is not None,'bounded phase head')
    rr,rp=files.read(head['record']);reg=json.loads(rr);need(hashlib.sha256(rr).hexdigest()==head['sha256']and reg['requestSHA256']==hashlib.sha256(canon(request)).hexdigest()and reg['bootID']==boot,'phase head/source/scope hash')
    phase=reg['phase'];need(phase in('PREPARED','ACTIVE','CLOSED'),'known exact phase')
    with RootFiles('/run/opemos-vfio-'+request['leaseNonce'])as leasefiles,leasefiles.lock():
     state,lease,old=read_lease(leasefiles,request,boot);ops.entry(intent,phase)
     scope=None;leader=None
     if phase=='ACTIVE':
      need(len(target)==1 and target[0]['uuid']==request['domainUUID']and target[0]['name']==request['domainName']and target[0]['active']and not target[0]['persistent']and target[0]['noNIC'],'real exact transient noNIC active domain');scope=reg['scope'];need(re.fullmatch(r'machine-[A-Za-z0-9_.\\-]+\.scope',scope)is not None,'actual machine scope name')
      x=ET.fromstring(target[0]['xml']);validate_hostdev_xml(x,intent);m=x.find('metadata/{'+NS+'}binding');need(m is not None and m.get('token')==request['jobToken']and m.get('job')==request['jobId']and m.get('nonce')==request['leaseNonce'],'live immutable domain metadata token')
      need(x.findtext('resource/partition')==request['partition'],'actual domain partition');leader=ops.leader(reg,intent);need(not state['closed'],'active lease open')
     else:
      need(not target,'inactive phase has no target domain; startup/teardown race remains held');need(reg['scope']is None and reg['leader']is None,'no invented inactive identity')
      if phase=='CLOSED':need(state['closed']and state['restored']and not state['changed'],'closed restored exact lease');ops.restoration(intent)
      else:need(not state['closed'],'prepared current lease open')
     ops.budget(request,phase,scope)
     if custody is not None:
      proof['accessCustody']=custody(phase,intent,reg,state,files);proof['accessCustody']['phasePins']={'intentPin':ip,'phaseHeadPin':hp,'phaseRecordPin':rp,'phaseHead':head,'phaseRecord':reg,'leaseHeadPin':lease['headPin'],'leaseStatePin':lease['statePin'],'leaseHead':json.loads(old[0]),'leaseState':state}
     need(files.read('intent.json')==(ir,ip)and files.read('phase-head.json')==(hr,hp)and files.read(head['record'])==(rr,rp),'immutable intent/phase full9 and raw reread');again_state,again_lease,again_old=read_lease(leasefiles,request,boot);need(again_lease==lease and again_old==old,'current lease full9 head/state reread')
     proof.update(phase=phase,scope=scope,leader=leader,intentPin=ip,intentParentPin=files.parent_pin(),lease=lease);proof['rootAncestorCustody']=[{'kind':'ROOT_GENERATED_SCOPE_ANCESTRY_R257','privatePath':str(f.path),'privateBefore':f.private,'privateAfter':None,'run':f.runProof}for f in(files,leasefiles)]
  if proof['rootAncestorCustody']:
   for value,f in zip(proof['rootAncestorCustody'],(files,leasefiles)):value['privateAfter']=f.privateAfter
 except BaseException as e:primary=e
 finally:
  try:ops.close()
  except BaseException as e:
   if primary is None:primary=e
   else:secondary.append(error_value(e))
 after=fd_snapshot('readonly-observe-after',request['observer']);changes=fd_changes(before,after)
 if any(changes.values()):secondary.append({'type':'FDClosureRefusal','reason':'all readonly owned FDs closed','changes':changes})
 evidence={'primary':error_value(primary),'secondary':secondary,'before':before,'after':after,'closeOutcomes':getattr(ops,'closeOutcomes',[])}
 if getattr(ops,'persist',None)is not None:
  try:ops.persist('readonly-observer-closure',evidence)
  except Exception as report_error:evidence['optionalReportError']=error_value(report_error)
  after=fd_snapshot('readonly-observe-after-report',request['observer']);changes=fd_changes(before,after);evidence.update(after=after)
  if any(changes.values())and not secondary:secondary.append({'type':'FDClosureRefusal','reason':'all readonly owned FDs closed','changes':changes})
 if primary is not None:primary.evidence=evidence;raise primary
 if secondary:
  error=Refused('all readonly owned FDs closed');error.evidence=evidence;raise error
 proof['readonlyFDCustody']={'kind':'ROOT_READONLY_FD_LIFETIME_R240','before':before,'after':after,'changes':changes,'closeOutcomes':ops.closeOutcomes};proof['completedMonotonic']=time.monotonic();proof['allOwnedDescriptorsClosed']=True
 size=len(canon(proof))+1;elapsed=proof['completedMonotonic']-started
 if not(size<=1048576 and elapsed<15):
  error=Refused('canonical observer size/deadline');error.observerBudgetEvidence={'kind':'ACTUAL_CANONICAL_OBSERVER_BUDGET_R257','canonicalBytes':size,'elapsedMonotonic':elapsed,'sizeCap':1048576,'timeCap':15,'sizeArm':size<=1048576,'timeArm':elapsed<15,'phase':proof['phase'],'requestSHA256':hashlib.sha256(canon(request)).hexdigest(),'proofSHA256':hashlib.sha256(canon(proof)).hexdigest()};raise error
 return proof
def process_snapshot(pid):
 """Raw stable process metadata; no worker/Root role authorization implied.""";need(type(pid)is int and pid>0,'positive raw PID');root=Path('/proc')/str(pid);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 def read(name):
  f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
  try:
   raw=b''
   while b:=os.read(f,4096):raw+=b;need(len(raw)<=65536,'bounded raw process field')
   return raw
  finally:os.close(f)
 try:
  a=read('stat').decode().rsplit(')',1)[1].split();cmd=read('cmdline');status=read('status').decode();cg=read('cgroup').decode().strip();u=[int(x)for l in status.splitlines()if l.startswith('Uid:')for x in l.split()[1:]];tg=[int(l.split()[1])for l in status.splitlines()if l.startswith('Tgid:')]
  need(len(u)==4 and len(tg)==1 and cg.startswith('0::/')and '\n'not in cg,'raw complete UID quartet/TGID/cgroup');v={'pid':pid,'start':int(a[19]),'ppid':int(a[1]),'uids':u,'tgid':tg[0],'cgroup':cg[3:],'argv':[os.fsdecode(x)for x in cmd.rstrip(b'\0').split(b'\0')]if cmd else[]}
  b=read('stat').decode().rsplit(')',1)[1].split();need((b[19],b[1])==(a[19],a[1])and read('cmdline')==cmd and [int(x)for l in read('status').decode().splitlines()if l.startswith('Uid:')for x in l.split()[1:]]==u and read('cgroup').decode().strip()==cg,'raw PID/start/ppid/cmdline/UID/cgroup stable')
  return v
 finally:os.close(fd)
def select_worker(expected,persist=None):
 persist=(lambda *a:None)if persist is None else persist;matches=[];count=0;observed=None
 try:
  for path in Path('/proc').iterdir():
   if not path.name.isdigit():continue
   count+=1;need(count<=8192,'finite whole PID enumeration')
   try:raw=process_snapshot(int(path.name))
   except(FileNotFoundError,ProcessLookupError):continue
   if raw['argv']!=expected:continue
   observed=raw;persist('worker-candidate-before-role',raw)
   actor=process(raw['pid']);need(actor['start']==raw['start']and actor['ppid']==raw['ppid']and actor['argv']==raw['argv']and actor['cgroup']==raw['cgroup']and raw['uids']==[1000]*4 and actor['uid']==1000 and actor['tgid']==actor['pid']==raw['tgid'],'exact matching canonical worker role UID1000/TGID/argv/start/cgroup')
   need(process_snapshot(raw['pid'])==raw,'matching raw identity after strict role');matches.append(actor)
  persist('worker-candidate-selection',{'scanned':count,'matches':matches});need(len(matches)==1,'exact one canonical live queue worker');return matches[0]
 except BaseException as error:error.evidence={'candidate':observed,'matches':matches,'scanned':count};raise
def verify_worker_lock(lock_pin,state_pin,mode,worker=None,persist=None):
 """Exact retained lock under its pinned private parent; never chmod/chown/write.

 Idle preparation requires no kernel holder and an owned nonblocking EX probe.
 Issuance instead requires one exact original UID1000 worker's kernel FLOCK/FD.
 Every observed field is delivered before the first custody predicate.
 """
 persist=(lambda *a:None)if persist is None else persist;fd=dfd=None;observed={};before=set(os.listdir('/proc/self/fd'))
 def kernel(st):
  rows=[]
  for line in Path('/proc/locks').read_text().splitlines():
   fields=line.split()
   if len(fields)<8 or fields[1]!='FLOCK'or fields[3]!='WRITE':continue
   major,minor,ino=fields[5].split(':')
   if(int(major,16),int(minor,16),int(ino))==(os.major(st.st_dev),os.minor(st.st_dev),st.st_ino):rows.append({'pid':int(fields[4]),'type':fields[1],'access':fields[3]})
  return rows
 try:
  path=Path(state_pin['path']);dfd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);ds=os.fstat(dfd)
  fd=os.open('worker.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dfd);s=os.fstat(fd);raw=os.pread(fd,4097,0)
  actual={'path':str(path/'worker.lock'),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':ident(s)};state_now=ident(ds);children=sorted(os.listdir(dfd));need(len(children)<=128,'bounded canonical state children');observed={'prequeueStatePin':state_pin,'statePin':{'path':str(path),'identity':state_now},'stateChildren':children,'epochChangedBetweenPhases':state_now!=state_pin['identity'],'workerLockPin':actual,'workerLockMode':stat.S_IMODE(s.st_mode),'kernelFlocks':kernel(s),'worker':worker}
  persist('worker-lock-before-predicate',observed);need(str(path/'worker.lock')==lock_pin['path']and state_now==ident(path.lstat())and stat.S_ISDIR(ds.st_mode)and ds.st_uid==ds.st_gid==1000 and stat.S_IMODE(ds.st_mode)==0o700,'exact current held privateUID1000 state0700')
  if worker is None:need(state_now==state_pin['identity'],'idle exact pinned privateUID1000 state0700')
  else:need(all(state_now[k]==state_pin['identity'][k]for k in CORE),'postqueue immutable private state core; only size/mtime/ctime may evolve')
  need(actual==lock_pin and stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and s.st_size==0 and raw==b''and mode==stat.S_IMODE(s.st_mode)and mode in(0o600,0o644,0o664),'exact pinned emptyUID1000 single-link finite worker lock')
  if mode==0o664:need(state_pin['identity']['st_mode']==stat.S_IFDIR|0o700,'0664 only under exact pinned private state0700')
  chain=[];held=[]
  if worker is None:
   need(observed['kernelFlocks']==[],'idle exact lock has no kernel holder');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   try:need(kernel(s)==[{'pid':os.getpid(),'type':'FLOCK','access':'WRITE'}],'idle probe has sole own kernel FLOCK')
   finally:fcntl.flock(fd,fcntl.LOCK_UN)
  else:
   need(worker['uid']==1000 and worker['pid']==worker['tgid']and process(worker['pid'])==worker,'same exact currentUID1000 worker PID/start/argv/cgroup');need(observed['kernelFlocks']==[{'pid':worker['pid'],'type':'FLOCK','access':'WRITE'}],'actual exact worker sole exclusive FLOCK')
   pid=worker['pid']
   for _ in range(32):
    a=process_snapshot(pid);chain.append({k:a[k]for k in('pid','start','uids','ppid','cgroup')})
    if pid==1:break
    need(a['ppid']>0 and a['ppid']!=pid,'finite known worker ancestry');pid=a['ppid']
   need(chain[-1]['pid']==1,'complete bounded current worker ancestry');items=list(Path('/proc/'+str(worker['pid'])+'/fd').iterdir());need(len(items)<=16384,'bounded worker FD enumeration')
   for item in items:
    try:st=item.stat()
    except FileNotFoundError:continue
    if(st.st_dev,st.st_ino)==(s.st_dev,s.st_ino):held.append({'fd':int(item.name),'identity':ident(st)})
   need(len(held)==1 and held[0]['identity']==lock_pin['identity'],'positive one actual original-worker lockFD')
   for old in chain:need({k:process_snapshot(old['pid'])[k]for k in old}==old,'worker ancestry stable before/after')
   need(process(worker['pid'])==worker,'same whole original worker after callbacks')
  need(ident(os.fstat(fd))==ident(os.stat('worker.lock',dir_fd=dfd,follow_symlinks=False))==ident(Path(lock_pin['path']).lstat())==lock_pin['identity']and ident(os.fstat(dfd))==ident(path.lstat())==state_now and sorted(os.listdir(dfd))==children,'final held/path/state/lock full9 unchanged');need(kernel(s)==observed['kernelFlocks'],'kernel FLOCK same after callback')
  result={**observed,'ancestry':chain,'heldLockFDs':held,'verified':True};persist('worker-lock-final',result);return result
 except BaseException as error:
  error.evidence=observed;raise
 finally:
  if fd is not None:os.close(fd)
  if dfd is not None:os.close(dfd)
  need(before==set(os.listdir('/proc/self/fd')),'worker lock owned FD restoration')
SOURCE_PLACEMENT_NONCE='cd9ef0826364409da287f6f3e3830c95';SOURCE_PLACEMENT_PIN=None  # UNISSUED: fresh Root new-scope receipt required; never D22
def working_metadata(fd,parentfd,path,expected,scope,stage,open_error=None):
 value={'kind':'ACTUAL_WORKING_HELD_NAMED_METADATA','stage':stage,'scope':scope,'path':path,'expectedProtectedPin':expected,'contentHashRecomputedHere':False,'fd':fd,'flags':None,'target':None,'fdinfo':None,'attempts':[],'errors':[],'stable':False}
 def failure(label,error):value['errors'].append({'operation':label,'type':type(error).__name__,'errno':getattr(error,'errno',None),'reason':str(error)[:512]})
 def read(label,fn):
  try:return fn()
  except BaseException as error:failure(label,error);return None
 if open_error is not None:failure('open-O_RDONLY-NOFOLLOW',open_error)
 if fd is not None:
  value['flags']=read('F_GETFL',lambda:fcntl.fcntl(fd,fcntl.F_GETFL));value['target']=read('readlink-held-FD',lambda:os.readlink('/proc/self/fd/'+str(fd)))
  def fdinfo():
   f=os.open('/proc/self/fdinfo/'+str(fd),os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
   try:
    raw=os.read(f,4097);need(len(raw)<=4096 and not os.read(f,1),'working fdinfo4096/EOF');return raw.decode('utf-8','strict')
   finally:os.close(f)
  value['fdinfo']=read('fdinfo',fdinfo)
 for ordinal in range(4):
  row={'ordinal':ordinal,'heldBefore':read('fstat-before',lambda:ident(os.fstat(fd)))if fd is not None else None,'anchoredName':read('stat-anchored-NOFOLLOW',lambda:ident(os.stat('working.raw',dir_fd=parentfd,follow_symlinks=False))),'namedPath':read('lstat-path',lambda:ident(os.lstat(path))),'heldAfter':read('fstat-after',lambda:ident(os.fstat(fd)))if fd is not None else None};value['attempts'].append(row)
  if row['heldBefore']is not None and row['heldBefore']==row['anchoredName']==row['namedPath']==row['heldAfter']:value['stable']=True;break
 if value['target']is not None:value['targetBytes']=len(value['target'].encode())
 need(len(canon(value))<=16384,'complete working metadata16KiB, unchanged outer caps');return value
def require_working_metadata(value,expected,installer=False,adopted=False):
 try:
  need(not value['errors']and value['stable']and value.get('targetBytes',0)<=4096,'complete stable working held/anchored/path full9 before geometry');wi=value['attempts'][-1]['heldAfter'];need(value['flags']is not None and(value['flags']&os.O_ACCMODE)==os.O_RDONLY,'working guard held FD remains O_RDONLY')
  need(all(wi[k]==expected['identity'][k]for k in('st_dev','st_ino','st_uid','st_gid','st_nlink','st_size'))and stat.S_ISREG(wi['st_mode'])and ((wi['st_uid'],wi['st_gid'])==(64055,993)if adopted else wi['st_uid']==wi['st_gid']==0) and wi['st_nlink']==1 and wi['st_size']==(8120172544 if installer else 21474836480)and(not installer or expected['sha256']=='f9aa0fa2dd618febf28a5e2a583d1e2b5a8ca3f1205be965da584602ac962f40'),'only exact new working or retained-media inode/geometry, current FD/name epoch');return wi
 except BaseException as error:error.workingEvidence=value;raise
_df_z=zlib.decompressobj();_df_raw=_df_z.decompress(__import__('base64').b85decode('c-o~{-*elz5q{5K!M+q^kCr1}l1rKL!M3EtbBdKZc9V`q!+}Xq!kHpz0<@&N%m3bQ0g|GWq|HoUBm!72_Q$v1u9S$>Nq8KkNtDS{Xt@?{>{sHk7E0qgE~-TN_cBjpzVwymOW`NQn#(-AE^^_=9486a!YsYunNt;+P~jgellM=u(orcy#r$r`<5(!w+sL_=PolR`RwB*ha-|RUilmN>B3M?7h$|(R`C8;8Rn<8e9${7OuwIh!Q6e(UyHzTy^@dl1RNd2cE0HD9N-AAcyQmU8G1~Q}i0+F*M{xmVJSO#Jp|rhKDpf=5%bQ$?#MQe}xJ_t0shmW{+Ce;=W^c|O@W2*f$Zlq{+vsw3eLMbq8(qxqu1C@6{4$!1qRaCSw|6&VcJN+a<guU^<KA<VlsU@;SK``kAH4Qkaerm*iz2x$3&bsQzmAtTh<T}NghFgZTx(h65#B`FTVHy2H7XCTq4->l8uL~N&ILBCj1t=I<Wx~tvA7{Tumvflr^5hQk+&5uS0CS<pS^rVT31}HkobXGaqPH&Sdo8Et2bDQZ6cR2*7c5JSgm;`e;3KeQp9`hoolMM?K81OvK^~@cy?L>D!D#c^Bh&7^l4mIX2V4DG#8r_6&Iy&nozdaGVhu51n`^02kiXv_U?QdO|LHgb#-$aeVX0;dUgG_P5tz0GQPcfKL*51VX?s07vuUams=JPs0XGbJ)gBV1Z^?0O;O>V<#-E6w7`8xN3%yB!JnFEm%uR$e}|Z|z?3ZG$r?aL+Go{llZ#5NWci7s2rCv$c%~p?&|hSks3s%Df;rUvbNv3U)nFN*U5TnHDkJsfnUjD}%!Zrsdy)Czgr|8cvKa8P6nWzQ!4SNP6ZTkO1sRnSe5Rrj-XH=oprj+CJ}+3X6q;*YxuV_i4dbBtQ4XX=(V;gFUJlO|Uyz5isGKzM33ZOlorcQ>Qj4{6iK#$U8{{fQ<RHgLkOlPF#_k;`q6?bYxrR;MR+{mpY8RSUu+Xj$1_w+;SI`}Ux+I2l_ew*VASZ621}Rdm-8At$zjwp_JTvF<oXi5Bh#gxj=B(s;Md0_131J%NIvbczsPgS{61^SYPNtr3EeoNHST2+KgUe3Ag7K*mS$di#r|c(+9U0+~$uf0%*MYrSP#K3D%iy8fslghoj5-`ZzkAH^o+U}UazKxHp`8XWrq&V>XQ;BIQE2XTct%F<oU8yLqndY)t>dmT?MVgoh%BnSUW-b`=a*AhY84Hza6MxaT!P7B8;epq7huh?c?9Ylt{f3qp!U#yQlKD`lga3$iwO`69l-EmO>|I(84y6sY*F+*4SG1R*#+F{S^_~<cyM=jHTtM41eZ#j5Z@iqf;I^N`(3kgpJN~OqtLyG(E~7Y<~9;iedtbHK!kmMKW$+723|C!OTi+8+9c8Q+}hUXNGnZNT7GW@jip};UYl*76?wLEY?eWlcs5~eBLst-HQzb+9epO0PQD2n7a%YaDu$Z_k;g@XI9NL~k-L!d{t*s;9zOr&jGzQh5x$=8;o0k7<pnfaW83P(Nr-m`fSu9kW8-3{F{`v%X~#B%;}%4x{YK;2$}V&`z8$1hu~s&RB=@F`kwSB=q~1-5-T;_z4q;t1qFdj%hR2ZAxg?vIN0hZSWCh)W6hzOn%q2~RBbm48v^O>R(Uisie?=mmB#P%Wk?MhYK=am|xlOxeUJur$g&&_=4oD?9)H8!Y*NIxXTKq^UTKAeVv^hONT29b1nW;pW*3F#9wf2be5=}Qek1^PxCAPBYX|{#m@J-9vjfq{0Q;^2JX8jx}uH;hYJo|7pdJFlcIhram&2SMu_6nT73B$y!V4+Cmyi}_~yPXLL1eKQoj}3%7LA<UDJt^uu8B+xO5BBwGQ9RV8+4789vY1|cocA4B5Tskq<{Ju#$q<r^<($Z)!f5uFuxCWG7eLdohl}vGs?9ZkldyD8V2X9?*4N(H$~3ouJqU#1{MC!+FJCVH_QD{A@MV?EA82Om6g(^lj1K^#YjpXIY2Y@y)JyYKn@@DHCw#@rs;Emw#MX>#A~OkhC@0_)=oC(qS!XhG)|eY`9S0#04pHu44EF;bn>NUNV*0QA@@X*eXk4fgS)u0l6lC-e3BCIH^$S>iU;(bYr*txtXETMARBz@b8&XPQ4{M8`!lB(K41J?rm);wto0*_AEuf*GuAsicQ9#{F<~ErG57&&m^sDFz4Badw#weQ1-NSk{H-Wk6xqIcmidaQ(wXy!21kgC|q~sjtznoz4gPD+diixi@T@ks5f?0Gknq5!-{ik`po=s-c>FkqTT~24?&*RG`MkcJJpbe^<`Y)dU{g+-w=@bdY?kj^?VwJt{(Ca1n8_=THPRFweYcEWxsIpxE6>(N5;im1$<Gjy0y?L0XP-*gOT-*<o_S@e_9D{Bb5#!drrL`kzF1Fg;4pf;*kaED_!F;$FP!*Q$z6Bh-Y^8xWf$7*Z08@=>BPl;dae%V>(u>-WGYH`8?*xkLcqP>9E<nWMwqwW~*U(UP&|(5}2gT#)j`_(Dc(QIT{MX)JO}@`BFW=8b<1p;u!r!a5g^9UZa$`-cbTi3hW(uJ+)5y}8XYT&rG#(Q78nk?u8^h2NAEJV!IxXEEaTZU(F-KHoY&i1W{1YMR-;z$jiBa$kNVY^+@>&V95YERmNdC}3e4zfMQIDzEw%{)R_LupShs2+~Ivc(K7oty}!i@I6q~=!_W+;qg4#)|P)_J_*`BEgq_t@K1#IQ8~2~2{y^YkCh_*`c'),8193)
need(_df_z.eof and not _df_z.unused_data and not _df_z.unconsumed_tail and len(_df_raw)==4754 and hashlib.sha256(_df_raw).hexdigest()=='ab8271cf82eff6f39423d4842dcc7edfe8c1d05270e142b7b7467292ef041888','exact immutable DAC descriptor definition')
exec(compile(_df_raw,__file__,'exec'));del _df_z,_df_raw
def connection_close_evidence(conn,role,persist,binding,domain_present):
 snapshots={};captureErrors=[];capturePrimary=None
 def snapshot(phase):
  nonlocal capturePrimary
  try:snapshots[phase]=fd_snapshot(role+'-API-close-'+phase)
  except BaseException as error:
   snapshots[phase]=None;captureErrors.append({'phase':phase,'type':type(error).__name__,'reason':str(error)[:512]});capturePrimary=capturePrimary or error
 snapshot('before');n=None;primary=None
 try:n=conn.close()
 except BaseException as e:primary=e
 snapshot('after');value={'kind':'ACTUAL_OWNED_LIBVIRT_API_CLOSE','role':role,'binding':binding,'connectionPythonObjectID':id(conn),'ownedDomainArgumentPresent':domain_present,'numeric':n,'first':None if primary is None else{'type':type(primary).__name__,'reason':str(primary)},'before':snapshots['before'],'after':snapshots['after'],'captureErrors':captureErrors,'notHistoricalQMPProof':True}
 try:persist(role+'-API-close-before-predicate',value)
 except BaseException as capture:
  if primary is None:
   if capturePrimary is not None:primary=capturePrimary
   elif n!=0:primary=Refused('exact '+role+' connection close0')
   else:primary=capture
  primary.capturePersistenceError={'type':type(capture).__name__,'reason':str(capture)}
 if primary is None:primary=capturePrimary
 if primary is not None:primary.closeEvidence=value;raise primary
 return n
def metadata_cohort(roots):
 return __import__('guest_firmware_probe').metadata_cohort(roots)
from libvirt_storage import storage_contract
if __name__=='__main__':
 try:
  need(len(sys.argv)==4 and sys.argv[2]=='--queue-libvirt-request-json','exact queue observer argv');request=json.loads(sys.argv[3]);need(sys.argv[1]==request['observer']['sha256'],'exact queue source SHA operand')
  ref=request['observer'];fd=os.open(ref['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);raw=os.read(fd,65537);need(os.read(fd,1)==b'' and len(raw)==ref['bytes']<=65536 and hashlib.sha256(raw).hexdigest()==ref['sha256']and st.st_nlink==1 and ident(st)==ident(os.fstat(fd))==ident(os.lstat(ref['path'])),'upstream minimal pin plus freshly held source full9/EOF/hash')
  finally:os.close(fd)
  print(canon(observe(request)).decode(),flush=True)
 except BaseException as e:
  reason={'kind':'QUEUE_LIBVIRT_FIRST_REFUSAL','type':type(e).__name__,'reason':str(e),'effects':[],'evidence':getattr(e,'evidence',None),'traceback':traceback.format_exc()};raw=canon(reason);sys.stderr.buffer.write(raw[:65535]+b'\n');sys.exit(1)

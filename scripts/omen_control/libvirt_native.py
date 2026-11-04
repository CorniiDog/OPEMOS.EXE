import copy,fcntl,hashlib,json,os,stat,subprocess,time,socket,struct,zlib,binascii
from pathlib import Path
import libvirt_peer as peer
def held(ref,cap):
 fd=os.open(ref['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);raw=b'';peer.need(stat.S_ISREG(st.st_mode)and st.st_nlink==1,'single regular pinned object')
  while b:=os.read(fd,65536):raw+=b;peer.need(len(raw)<=cap,'role-specific object cap')
  peer.need(peer.same(ref,raw,st)and peer.ident(st)==peer.ident(os.fstat(fd))==peer.ident(os.lstat(ref['path'])),'held full9/name/EOF/SHA');return raw
 finally:os.close(fd)
SCHEMA_SCRIPT_SHA='d7eda32d2b6d3b7a612221bfc3c19dcbb660c9ddf0a360b5156652dbaac5cb36'
SCHEMA_INTERPRETER_SHA='86d31f6fb799e91fa21bad341484564510ca287703a16e9e46c53338776f4f42'
def schema_interpreter(argv,tool):
 if argv[0]!='/usr/bin/virt-xml-validate':return None
 peer.need(tool is not None and tool['path']==argv[0]and tool['sha256']==SCHEMA_SCRIPT_SHA and held(tool,33554432).splitlines()[0]==b'#!/bin/sh','exact installed pinned schema script/shebang')
 aliases=[]
 for path,target,resolved in(('/bin','usr/bin','/usr/bin'),('/bin/sh','dash','/usr/bin/dash')):
  a=peer.ident(os.lstat(path));peer.need(stat.S_ISLNK(a['st_mode'])and a['st_uid']==a['st_gid']==0 and a['st_nlink']==1 and os.readlink(path)==target and os.path.realpath(path)==resolved,'finite exact Root schema interpreter alias');aliases.append({'path':path,'identity':a,'target':target,'resolved':resolved})
 path='/usr/bin/dash';a=peer.ident(os.lstat(path));peer.need(stat.S_ISREG(a['st_mode'])and stat.S_IMODE(a['st_mode'])==0o755 and a['st_uid']==a['st_gid']==0 and a['st_nlink']==1 and a['st_size']==129784,'Root installed interpreter role')
 ref={'path':path,'identity':a,'bytes':a['st_size'],'sha256':SCHEMA_INTERPRETER_SHA};held(ref,33554432)
 return {'kind':'EXACT_PINNED_SCHEMA_SCRIPT_INTERPRETER_R257','scriptPin':tool,'interpreterPin':ref,'aliases':aliases,'argv':['/bin/sh',*argv],'mountNamespace':os.readlink('/proc/self/ns/mnt')}
def schema_executable(provenance,pid):
 peer.need(os.readlink('/proc/'+str(pid)+'/ns/mnt')==provenance['mountNamespace']and os.readlink('/proc/'+str(pid)+'/exe')==provenance['interpreterPin']['path'],'actual helper same namespace/pinned executable')
 fd=os.open('/proc/'+str(pid)+'/exe',os.O_RDONLY|os.O_CLOEXEC)
 try:
  a=peer.ident(os.fstat(fd));raw=b''
  while b:=os.read(fd,65536):raw+=b;peer.need(len(raw)<=33554432,'native executable32MiB')
  r=provenance['interpreterPin'];peer.need(a==peer.ident(os.fstat(fd))==peer.ident(os.lstat(r['path']))==r['identity']and len(raw)==r['bytes']and hashlib.sha256(raw).hexdigest()==r['sha256'],'actual kernel executable full9/bytes/SHA/EOF')
 finally:os.close(fd)
 return dict(provenance,actualExecutableVerified=True)
def native_child(argv,deadline,tool_pin=None,input_bytes=None):
 return _native_child(argv,deadline,tool_pin,input_bytes,10)

def native_queue_worker(argv,deadline,tool_pin):
 """Normal worker transport only; does not extend its900s job authority."""
 now=time.time();peer.need(now<deadline<=now+1000,'original bounded normal-worker transport deadline')
 return _native_child(argv,deadline,tool_pin,None,1000)

def _native_child(argv,deadline,tool_pin,input_bytes,transport_seconds):
 import signal,select
 peer.need(argv[0]in('/usr/bin/systemctl','/usr/bin/systemd-run')or(tool_pin is not None and tool_pin['path']==argv[0]),'closed pinned native helper role')
 if tool_pin is not None:
  toolraw=held(tool_pin,33554432);peer.need(not toolraw.startswith(b'#!')or argv[0]=='/usr/bin/virt-xml-validate','only exact pinned schema script helper')
 peer.need(input_bytes is None or len(input_bytes)<=1048576,'finite exact native input')
 p=None;pidfd=None;actor=None;first=None;secondary=[];out=b'';err=b'';eof=False;reaped=False;group=[];script=None;executable=None;before=peer.fd_snapshot('helper-before')
 try:
  script=schema_interpreter(argv,tool_pin)
  peer.need(time.time()<deadline,'native helper original deadline before spawn')
  p=subprocess.Popen(argv,stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,start_new_session=True)
  pidfd=os.pidfd_open(p.pid,0);actor=peer.process(p.pid);peer.need(actor['ppid']==os.getpid()and actor['uid']==os.getuid()and actor['tgid']==p.pid and os.getpgid(p.pid)==p.pid,'exact own helper PID/start/UID/private group')
  if not actor['argv']:
   ready=select.select([pidfd],[],[],max(0,min(10,deadline-time.time())))[0];now=peer.process(p.pid);peer.need(ready and all(now[k]==actor[k]for k in('pid','start','uid','ppid','cgroup')),'empty helper argv requires same original exited pidfd; no inferred exit')
  peer.need(actor['argv']==(script['argv']if script is not None else argv)or not actor['argv'],'exact live helper argv or proved exited own child')
  if script is not None and actor['argv']:executable=schema_executable(script,p.pid)
  out,err=p.communicate(input_bytes,timeout=max(.001,min(transport_seconds,deadline-time.time())));eof=True;p.wait(timeout=2);reaped=True
  peer.need(len(out)+len(err)<=1048576,'native helper output bound')
 except BaseException as error:first=error
 finally:
  if p is not None:
   if p.poll()is None:
    try:
     peer.need(actor is not None and pidfd is not None,'unknown helper ownership refuses signal')
     now=peer.process(p.pid);peer.need(all(now[k]==actor[k]for k in('pid','start','uid','ppid','cgroup'))and os.getpgid(p.pid)==p.pid,'same original owned helper before pidfd signal')
     signal.pidfd_send_signal(pidfd,signal.SIGKILL);out,err=p.communicate(timeout=2);eof=True;p.wait(timeout=2);reaped=True
    except BaseException as error:secondary.append(peer.error_value(error))
   else:
    try:
     if not eof:out,err=p.communicate(timeout=2);eof=True
     p.wait(timeout=2);reaped=True
    except BaseException as error:secondary.append(peer.error_value(error))
   for pipe in(p.stdin,p.stdout,p.stderr):
    if pipe is not None:
     try:pipe.close()
     except BaseException as error:secondary.append(peer.error_value(error))
   try:
    for name in os.listdir('/proc'):
     if not name.isdigit():continue
     try:
      raw=Path('/proc/'+name+'/stat').read_text().rsplit(')',1)[1].split()
      if int(raw[2])==p.pid:group.append({'pid':int(name),'start':int(raw[19])})
     except FileNotFoundError:continue
    peer.need(not group and reaped and eof and p.poll()is not None,'helper numeric/EOF/reap/private-group closure')
   except BaseException as error:secondary.append(peer.error_value(error))
  if pidfd is not None:
   try:os.close(pidfd)
   except BaseException as error:secondary.append(peer.error_value(error))
  if script is not None:
   try:peer.need(schema_interpreter(argv,tool_pin)==script,'same exact schema script/interpreter/aliases after helper')
   except BaseException as error:secondary.append(peer.error_value(error))
  after=peer.fd_snapshot('helper-after');changes=peer.fd_changes(before,after)
  if any(changes.values()):secondary.append({'type':'FDClosureRefusal','reason':'helper owned FD closure','changes':changes})
 value={'actor':actor,'argv':argv,'numeric':None if p is None else p.returncode,'stdout':out.decode(errors='backslashreplace'),'stderr':err.decode(errors='backslashreplace'),'EOF':eof,'reaped':reaped,'pipesClosed':p is not None and all(x is None or x.closed for x in(p.stdin,p.stdout,p.stderr)),'groupRemaining':group,'scriptProvenance':script,'actualExecutable':executable,'before':before,'after':after,'primary':peer.error_value(first),'secondary':secondary,'closure':'KNOWN'if p is not None and reaped and eof and not secondary else'UNKNOWN'}
 if first is not None:first.evidence=value;first.nativeChildEvidence=value;raise first
 if secondary:error=peer.Refused('native helper closure UNKNOWN; retain lease');error.evidence=value;error.nativeChildEvidence=value;raise error
 return value
_PROCESS_EVENT_DRIVER=None
def event_driver_observation(driver,snapshot,anchor=True):
 peer.need(driver is _PROCESS_EVENT_DRIVER and not driver.get('anchorClosed'),'original live event-driver anchor')
 peer.need(snapshot['actor']==driver['owner'],'same original process owns event-driver role')
 rows={r['fd']:peer.fd_key(r)for r in snapshot['rows']};observed=[];drift=[]
 for label,expected in [('driver',driver['descriptor'])]+([('anchor',driver['anchor'])]if anchor else[]):
  row=rows.get(expected['fd']);peer.need(row is not None,'exact '+label+' eventfd remains open')
  peer.need(all(row[k]==expected[k]for k in('fd','target','flags','eventfdID')),'exact '+label+' eventfd slot/target/flags/context')
  peer.need(all(row['identity'][k]==expected['identity'][k]for k in peer.FIELDS if k not in('st_mtime_ns','st_ctime_ns')),'exact '+label+' eventfd inode core')
  peer.need(row['eventfdID']==driver['descriptor']['eventfdID']and row['target']=='anon_inode:[eventfd]'and row['flags']=='02004002','held duplicate same proven eventfd context')
  observed.append({'role':label,'row':row})
  drift.append({'role':label,'fd':row['fd'],'before':{k:expected['identity'][k]for k in('st_mtime_ns','st_ctime_ns')},'observed':{k:row['identity'][k]for k in('st_mtime_ns','st_ctime_ns')}})
 return {'owner':snapshot['actor'],'observed':observed,'timestampEpochs':drift,'anchorHeld':anchor}
def event_driver_fd_changes(driver,before,after):
 a=event_driver_observation(driver,before);b=event_driver_observation(driver,after)
 normalized=copy.deepcopy(after)
 old={r['fd']:r for r in before['rows']}
 for row in normalized['rows']:
  if row['fd']in(driver['descriptor']['fd'],driver['anchor']['fd']):
   for k in('st_mtime_ns','st_ctime_ns'):row['identity'][k]=old[row['fd']]['identity'][k]
 return {'changes':peer.fd_changes(before,normalized),'beforeRole':a,'afterRole':b}
def close_event_driver_anchor(driver,persist):
 before=peer.fd_snapshot('before-owned-event-driver-anchor-close');proof=event_driver_observation(driver,before)
 os.close(driver['anchor']['fd'])
 after=peer.fd_snapshot('after-owned-event-driver-anchor-close');event_driver_observation(driver,after,anchor=False)
 expected=copy.deepcopy(before);expected['rows']=[r for r in expected['rows']if r['fd']!=driver['anchor']['fd']]
 normalized=copy.deepcopy(after)
 for row in normalized['rows']:
  if row['fd']==driver['descriptor']['fd']:
   previous=next(r for r in expected['rows']if r['fd']==row['fd'])
   for k in('st_mtime_ns','st_ctime_ns'):row['identity'][k]=previous['identity'][k]
 changes=peer.fd_changes(expected,normalized)
 driver['anchorClosed']=True
 value={'before':before,'after':after,'proof':proof,'changesExceptExactOwnedAnchorRemoval':changes,'anchorClosed':True,'originalDriverRequiresProcessReap':True}
 persist('event-driver-owned-anchor-close',value);peer.need(not any(changes.values()),'only exact owned anchor closed; all other descriptors unchanged')
 return value
def bootstrap_event_driver(persist):
 global _PROCESS_EVENT_DRIVER
 import libvirt
 if _PROCESS_EVENT_DRIVER is not None:
  now=peer.fd_snapshot('existing-process-event-driver');persist('existing-event-driver-context',event_driver_observation(_PROCESS_EVENT_DRIVER,now));return _PROCESS_EVENT_DRIVER
 before=peer.fd_snapshot('before-default-event-driver');threadsBefore=sorted(os.listdir('/proc/self/task'));timer=None;removed=False;duplicate=None;anchor=None
 try:
  ret=libvirt.virEventRegisterDefaultImpl();registered=peer.fd_snapshot('after-default-event-registration')
  peer.need(ret in(0,None)and not any(peer.fd_changes(before,registered).values()),'exact lazy default-driver registration; no unknown FD producer')
  timer=libvirt.virEventAddTimeout(100,lambda timer,opaque:None,None);armed=peer.fd_snapshot('after-first-default-event-timer');change=peer.fd_changes(before,armed)
  peer.need(type(timer)is int and timer>=0 and len(change['added'])==1 and not change['removed']and not change['replaced'],'one exactly API-attributed eventfd')
  row=change['added'][0];peer.need(row['target']=='anon_inode:[eventfd]'and row['eventfdID'].isdigit()and row['flags']=='02004002'and row['identity']['st_uid']==row['identity']['st_gid']==0,'exact Root CLOEXEC nonblocking eventfd role')
  duplicate=fcntl.fcntl(row['fd'],fcntl.F_DUPFD_CLOEXEC,3);anchored=peer.fd_snapshot('after-owned-event-driver-duplicate');delta=peer.fd_changes(armed,anchored)
  peer.need(len(delta['added'])==1 and delta['added'][0]['fd']==duplicate and not delta['removed'],'only our exact F_DUPFD_CLOEXEC anchor added');anchor=delta['added'][0]
  peer.need(anchor['eventfdID']==row['eventfdID']and anchor['target']==row['target']and anchor['flags']==row['flags'],'private duplicate retains original API eventfd context')
  _PROCESS_EVENT_DRIVER={'kind':'LIBVIRT_DEFAULT_EVENT_DRIVER_PROCESS_LIFETIME','API':'virEventRegisterDefaultImpl+first-virEventAddTimeout','descriptor':row,'anchor':anchor,'anchorClosed':False,'owner':before['actor'],'disposal':'private duplicate explicitly closed; global driver requires original Root EOF/reap'}
  expected=copy.deepcopy(armed);expected['rows'].append(next(r for r in anchored['rows']if r['fd']==duplicate));dupProof=event_driver_fd_changes(_PROCESS_EVENT_DRIVER,expected,anchored)
  peer.need(not any(dupProof['changes'].values()),'no unrelated FD change while creating context anchor')
  removedValue=libvirt.virEventRemoveTimeout(timer);removed=True;after=peer.fd_snapshot('after-bootstrap-timer-removal');threadsAfter=sorted(os.listdir('/proc/self/task'));proof=event_driver_fd_changes(_PROCESS_EVENT_DRIVER,anchored,after)
  peer.need(removedValue in(0,None)and threadsBefore==threadsAfter==[str(os.getpid())]and not any(proof['changes'].values()),'exact single-process timer removal with held context; no unknown FD changes')
  value={'driver':_PROCESS_EVENT_DRIVER,'return':ret,'bootstrapTimer':timer,'bootstrapTimerRemovalReturn':removedValue,'bootstrapThreadsBefore':threadsBefore,'bootstrapThreadsAfter':threadsAfter,'before':before,'afterRegistration':registered,'afterFirstTimer':armed,'afterAnchor':anchored,'after':after,'duplicateProof':dupProof,'timerRemovalProof':proof}
  persist('process-event-driver-bootstrap',value);return _PROCESS_EVENT_DRIVER
 except BaseException as first:
  cleanup={'anchorFD':duplicate,'closed':False,'unknown':duplicate is not None,'timer':timer,'timerRemoved':removed}
  if timer is not None and not removed:
   try:cleanup['timerRemovalReturn']=libvirt.virEventRemoveTimeout(timer);cleanup['timerRemoved']=True
   except BaseException as secondary:cleanup['timerSecondary']={'type':type(secondary).__name__,'reason':str(secondary)}
  if duplicate is not None:
   try:
    current=peer.fd_snapshot('failed-anchor-before-owned-cleanup');now=next((peer.fd_key(r)for r in current['rows']if r['fd']==duplicate),None)
    if anchor is not None and now==anchor:os.close(duplicate);cleanup.update(closed=True,unknown=False)
   except BaseException as secondary:cleanup['FDSecondary']={'type':type(secondary).__name__,'reason':str(secondary)}
  first.evidence={'primary':peer.error_value(first),'anchorCleanup':cleanup,'before':before,'requiresOriginalProcessReap':True}
  try:persist('FIRST-event-driver-anchor',first.evidence)
  except BaseException as secondary:first.evidence['diagnosticPersistenceError']={'type':type(secondary).__name__,'reason':str(secondary)}
  _PROCESS_EVENT_DRIVER=None;raise
def read_vnc_frame(channel,tick,end):
 evidence={'protocol':None,'securityTypes':None,'serverName':None,'width':None,'height':None,'readBytes':0,'sentTypes':[]};wire=hashlib.sha256()
 def read(n):
  peer.need(0<=n<=8388608,'bounded RFB field');out=bytearray()
  while len(out)<n:
   peer.need(time.time()<end,'bounded graphical read deadline');tick()
   try:b=channel.recv(min(65536,n-len(out)))
   except socket.timeout:continue
   peer.need(bool(b),'RFB complete frame EOF');out.extend(b);wire.update(b);evidence['readBytes']+=len(b);peer.need(evidence['readBytes']<=8454144,'bounded complete RFB transcript')
  return bytes(out)
 def send(b,label):channel.sendall(b);evidence['sentTypes'].append(label)
 try:
  version=read(12);evidence['protocol']=version.decode(errors='replace');peer.need(version==b'RFB 003.008\n','exact supported RFB3.8');send(version,'ProtocolVersion')
  count=read(1)[0];peer.need(1<=count<=16,'finite RFB security types');types=list(read(count));evidence['securityTypes']=types;peer.need(1 in types,'Unix-local None security only; no credentials');send(b'\x01','SecurityTypeNone');peer.need(struct.unpack('!I',read(4))[0]==0,'RFB None security accepted');send(b'\x01','ClientInitShared')
  head=read(24);w,h=struct.unpack('!HH',head[:4]);n=struct.unpack('!I',head[20:])[0];evidence.update(width=w,height=h);peer.need(1<=w<=2560 and 1<=h<=1600 and w*h*4<=8388608 and n<=4096,'exact bounded framebuffer geometry/name');name=read(n);evidence['serverName']=name.decode(errors='strict');evidence['initialPixelFormat']=list(head[4:20])
  fmt=struct.pack('!BBBBHHHBBBxxx',32,24,0,1,255,255,255,16,8,0);send(b'\x00\x00\x00\x00'+fmt,'SetPixelFormat32TrueColour');send(struct.pack('!BBHi',2,0,1,0),'SetEncodingsRawOnly');send(struct.pack('!BBHHHH',3,0,0,0,w,h),'FramebufferUpdateRequestFull')
  header=read(4);peer.need(header[0]==0 and header[1]==0 and struct.unpack('!H',header[2:])[0]==1,'one complete full raw framebuffer rectangle');x,y,rw,rh,enc=struct.unpack('!HHHHi',read(12));peer.need((x,y,rw,rh,enc)==(0,0,w,h,0),'no partial/foreign encoding or invented pixels');pixels=read(w*h*4);rgb=bytearray(w*h*3);rgb[0::3]=pixels[2::4];rgb[1::3]=pixels[1::4];rgb[2::3]=pixels[0::4]
  evidence.update(fullRectangle=[x,y,rw,rh],encoding=enc,wireSHA256=wire.hexdigest(),raw32SHA256=hashlib.sha256(pixels).hexdigest(),RGBSHA256=hashlib.sha256(rgb).hexdigest(),RGBBytes=len(rgb),completePixelEOF=True)
  return bytes(rgb),evidence
 except BaseException as error:
  error.evidence={'graphicalProtocol':evidence,'wireSHA256':wire.hexdigest(),'noGuestInput':True};raise
def rgb_png(rgb,width,height):
 peer.need(len(rgb)==width*height*3<=6291456,'complete RGB frame size')
 def chunk(tag,b):return struct.pack('!I',len(b))+tag+b+struct.pack('!I',binascii.crc32(tag+b)&0xffffffff)
 scan=b''.join(b'\0'+rgb[y*width*3:(y+1)*width*3]for y in range(height));out=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!IIBBBBB',width,height,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(scan,6))+chunk(b'IEND',b'');peer.need(len(out)<=4194304,'graphical PNG role4MiB');return out
def graphical_frame_bytes(request,record):
 peer.need(len(request['leaseNonce'])==32 and all(x in'0123456789abcdef'for x in request['leaseNonce']),'exact graphical scope nonce');phase=record['phase'];ref=record['framePin'];peer.need(phase in(1,2)and record['kind']=='ACTUAL_DOMAIN_BOUND_GRAPHICAL_FIRST_FRAME'and record['identity']['phase']==phase,'closed graphical frame role/phase');sample=record.get('frameSample',1);peer.need(type(sample)is int and 1<=sample<=6,'finite exact retained frame sample');expected='/run/opemos-libvirt-results-'+request['leaseNonce']+'/graphical-first-'+str(phase)+(''if sample==1 else'-sample-'+str(sample))+'.png';peer.need(ref['path']==expected and record['identity']['domain']['uuid']==request['domainUUID']and record['identity']['domain']['name']==request['domainName'],'exact same-domain graphical path/UUID/name');a=ref['identity'];peer.need(a['st_uid']==a['st_gid']==0 and stat.S_IMODE(a['st_mode'])==0o400 and a['st_nlink']==1,'protected single Root0400 graphical binary role');
 with peer.RootFiles(str(Path(expected).parent))as files,files.lock():b,actual=files.read(Path(expected).name,cap=4194304);peer.need(actual==ref,'exact held protected PNG full9/EOF/hash/ancestry')
 __import__('guest_firmware_probe').verify_saved_frame_geometry(record,b);return b
class GuestReporterFailure(peer.Refused):pass
class NativeTransactionOps:
 MODEL_ONLY=False
 def __init__(self,c,persist):self.c=c;self.persist=persist;self.conn=None;self.observer=None;self.request=None;self.diskfds=[];self.events=[];self.registered=None;self.offset=0;self.rows=[];self.intent=None;self.eventIndex=0;self.expectedStop=None;self.eventTimer=None;self.callback=None;self.diskfdRecords={};self.initialFD=peer.fd_snapshot('native-transaction-created');self.graphical={};self.observationCalls=0;self.observationActor=None;self.capturedFrames={};self.capturedFrameHistory=[];self.captureBinding=None;self.captureCandidate=None;self.lastDACFDRecordPin=None;self.lastDACFDObservation=None;self.diagnosticObservations={};self.lastDiagnostic=None
 def report(self,label,value):
  self.lastDiagnostic={'label':label,'value':value}
  if label in self.diagnosticObservations or len(self.diagnosticObservations)<32:self.diagnosticObservations[label]=value
 def capture_dac_fd(self,stage,domain=None,candidate=None,required=True):
  value=peer.dac_fd_lifetime(self.c,self.request,self.diskfdRecords,self.captureBinding,stage,domain,candidate);self.lastDACFDObservation=value;self.report('DAC-FD-'+stage,value)
  if required:
   try:peer.need(not value['errors'],'complete exact paused DAC/FD evidence before admission predicate')
   except BaseException as error:error.workingEvidence=value;raise
  return {'pin':self.lastDACFDRecordPin,'errors':value['errors'],'diagnosticOnly':True}
 def boot(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 def readonly(self):
  ops=peer.NativeOps(self.drain_event_closures,self.report);ops.custody=lambda phase,intent,reg,state,files:__import__('libvirt_access').verify_phase(self.c,self.g['preparedAccessPin'],self.g['preparedDiskPins'],phase,intent,reg,state,files);return ops
 def effect_clock(self,role):
  now=time.time();g=self.g;v={'role':role,'nowUnix':now,'issuedUnix':g['issuedUnix'],'startBeforeUnix':g['startBeforeUnix'],'wholeDeadlineUnix':self.deadline,'preflightObservedUnix':g['preflightObservedUnix']};self.report('effect-clock-'+role,v)
  now=time.time();peer.need(g['issuedUnix']<=now<self.deadline<=g['issuedUnix']+900,'original whole deadline at actual effect')
  if role=='create':peer.need(now<g['startBeforeUnix']<=g['issuedUnix']+300 and 0<=now-g['preflightObservedUnix']<=30,'original start/machine-preflight clocks immediately before createXML')
  return min(self.deadline,g['startBeforeUnix'],g['preflightObservedUnix']+30)if role=='create'else self.deadline
 def drain_event_closures(self,reason):
  import libvirt
  peer.need(_PROCESS_EVENT_DRIVER is not None,'exact live process event driver');temporary=self.eventTimer is None;timer=self.eventTimer;out=[];primary=None;removeError=None
  if temporary:timer=libvirt.virEventAddTimeout(100,lambda timer,opaque:None,None);peer.need(type(timer)is int and timer>=0,'finite owned close-drain timer')
  before=peer.fd_snapshot('event-drain-before-'+reason)
  try:
   for number in range(2):
    start=time.monotonic();ret=libvirt.virEventRunDefaultImpl();out.append({'number':number,'return':ret,'seconds':time.monotonic()-start});peer.need(ret in(0,None)and out[-1]['seconds']<.5,'bounded100ms event dispatch')
  except BaseException as error:primary=error
  finally:
   if temporary:
    try:ret=libvirt.virEventRemoveTimeout(timer);peer.need(ret in(0,None),'own temporary close-drain timer removed')
    except BaseException as error:removeError=peer.error_value(error)
   self.report('event-connection-close-drain',{'reason':reason,'before':before,'after':peer.fd_snapshot('event-drain-after-'+reason),'calls':out,'timer':timer,'temporary':temporary,'primary':peer.error_value(primary),'timerRemovalError':removeError})
  if primary is not None:
   primary.evidence={'timerRemovalError':removeError};raise primary
  peer.need(removeError is None,'unknown close-drain timer disposal')
 def verify_grant_and_sources(self,pin,g):
  with peer.RootFiles(str(Path(pin['path']).parent))as f:
   b,r=f.read(Path(pin['path']).name);peer.need(r==pin and json.loads(b)==g and g.get('MODEL_ONLY')is not True,'actual protected Root grant, never a model')
  for key in('producerPin','peerPin','accessPin'):
   ref=g[key];b=held(ref,65536);peer.need(ref['identity']['st_uid']==ref['identity']['st_gid']==0 and ref['identity']['st_mode']&0o777==0o444,'reviewed Root0444 source role');compile(b,ref['path'],'exec')
  peer.need({k:g['peerPin'][k]for k in('path','bytes','sha256')}==g['observerPin'],'full Root source pin joins exact upstream minimal job pin')
  # The exact installed validator checks the actual XML immediately before
  # createXML. A historical qualification report owns no launch authority.
 def full_preflight_and_entry(self,g,r,c):
  self.request=r;self.g=g;self.deadline=g['wholeDeadlineUnix']
  for ref in(g['currentPreflightPin'],):
   with peer.RootFiles(str(Path(ref['path']).parent))as f:
    b,p=f.read(Path(ref['path']).name);peer.need(p==ref,'exact fresh protected proof')
   v=json.loads(b);peer.need(v['bootID']==self.boot()and v['producer']['uid']==0,'fresh same-boot Root proof')
  pre=json.loads(held(g['currentPreflightPin'],1048576));peer.need(pre['observedUnix']==g['preflightObservedUnix']and 0<=time.time()-pre['observedUnix']<=30,'actual receipt clocks equal grant clocks; no refreshed stale pin');self.preflight=pre;peer.need(pre['original']==c['original']and pre['working']==g['preparedDiskPins']['working']and pre['preparedAccessPin']==g['preparedAccessPin']and pre['splitDiskCapturePins']==g['splitDiskCapturePins']and pre['queuePrograms']==g['queuePrograms']and pre['privateHistory']==g['privateHistory']and pre['queueAssignmentExport']==g['queueAssignmentExport']and pre.get('abi')==g.get('preflightABI')==__import__('libvirt_preflight').MACHINE_PREFLIGHT_ABI,'entire exact producer-to-consumer preflight')
  peer.need(pre['pool']=={'cpu.max':'1000000 100000','memory.max':str(32*1024**3),'memory.swap.max':'0'}and pre['holderUnknowns']==[]and pre['GPUGroup']==peer.GROUP and pre['freeBytes']>=72000000000 and pre['wholeQueueConflictFree']is True,'current full pool/holder/storage/queue contract')
  for key in('original','working'):
   ref=(g['preparedDiskPins'][key]);f=os.open(ref['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);self.diskfds.append(f);peer.need(peer.ident(os.fstat(f))==ref['identity']==peer.ident(os.lstat(ref['path'])),'held original/working exact initial full9');self.diskfdRecords[f]={'key':key,'identity':peer.ident(os.fstat(f)),'flags':fcntl.fcntl(f,fcntl.F_GETFL),'target':os.readlink('/proc/self/fd/'+str(f))}
  self.current_entry(r)
 def current_entry(self,r):
  ops=peer.NativeOps();fds=[];observed=[];first=None;stage='manager'
  def record(label,value):
   self.report(label,value)
  def snapshot(pid):
   raw=peer.process_snapshot(pid);fd=os.open('/proc/'+str(pid)+'/exe',os.O_RDONLY|os.O_CLOEXEC);fds.append(fd);st=peer.ident(os.fstat(fd));h=hashlib.sha256();n=0
   while b:=os.read(fd,65536):n+=len(b);peer.need(n<=33554432,'entry executable32MiB');h.update(b)
   ex={'path':os.readlink('/proc/'+str(pid)+'/exe'),'bytes':n,'sha256':h.hexdigest(),'identity':st}
   row={'raw':raw,'exe':ex};observed.append(row)
   record('entry-raw-'+str(len(observed)-1),row)
   peer.need(peer.process_snapshot(pid)==raw and peer.ident(os.fstat(fd))==peer.ident(os.stat('/proc/'+str(pid)+'/exe'))==st,'raw entry PID/start/UID/argv/cgroup/exe stable before role')
   return row
  try:
   props=ops.manager(r['unit']);peer.need(props['InvocationID']==r['invocation']and props['ControlGroup']==peer.POOL+'/'+r['unit'],'current original manager invocation');main=int(props['MainPID'])
   stage='controller';own=snapshot(os.getpid());a=peer.process(os.getpid());peer.need(a['uid']==0 and a['cgroup']==peer.POOL+'/'+r['unit']and a['tgid']==a['pid'],'Root controller exact own unit');peer.need(a['argv']==self.g['controllerArgv'],'exact Root controller argv/source')
   ancestors=[];strict=[a];current=own['raw'];seen={a['pid']};stage='ancestors'
   for index in range(3):
    peer.need(current['pid']!=main and current['ppid']not in seen and current['ppid']>0,'finite noncyclic Root/sudo/logger ancestry');row=snapshot(current['ppid']);q=row['raw'];seen.add(q['pid']);ancestors.append(row)
    if q['pid']==main:
     logger=peer.process(main);strict.append(logger);peer.need(logger['uid']==1000 and logger['tgid']==main and logger['argv']==self.g['loggerArgv']and logger['cgroup']==a['cgroup'],'exact uniformUID1000 original logger argv/cgroup');break
    peer.need(index<2 and q['tgid']==q['pid']and q['argv']==self.g['sudoArgv']and q['cgroup']==a['cgroup'],'only exact bounded pinned sudo transition role')
    peer.need(q['uids']in([0,0,0,0],[1000,1000,1000,1000],[1000,0,0,0]),'exact permitted sudo UID quartet; no foreign UID adoption')
    peer.need(row['exe']==self.g['sudoPin'],'exact sudo executable path/full9/bytes/SHA')
    current=q
   peer.need(2<=len(ancestors)<=3 and ancestors[-1]['raw']['pid']==main,'one or two exact sudo roles reach positive original logger')
   stage='final-revalidation'
   after=[]
   for fd,row in zip(fds,observed):
    q=row['raw'];now=peer.process_snapshot(q['pid']);ex=peer.ident(os.fstat(fd));named=peer.ident(os.stat('/proc/'+str(q['pid'])+'/exe'));peer.need(now==q and ex==named==row['exe']['identity'],'all original raw ancestry PID/start/UID/ppid/argv/cgroup/exe revalidated');after.append({'raw':now,'heldExeIdentity':ex,'namedExeIdentity':named})
   record('entry-revalidated',{'before':observed,'after':after})
   for q in strict:peer.need(peer.process(q['pid'])==q,'strict uniform Root/logger actor revalidated')
   peer.need(ops.manager(r['unit'])==props,'same original manager invocation/MainPID/cgroup after callbacks')
   cg=Path('/sys/fs/cgroup'+a['cgroup']);peer.need((cg/'memory.max').read_text().strip()==str(2*1024**3)and(cg/'memory.swap.max').read_text().strip()=='0'and(cg/'cpu.max').read_text().strip()=='400000 100000','actual controller2GiB4CPUzeroSwap')
   result={'pid':a['pid'],'start':a['start'],'uid':a['uid'],'argvSHA256':hashlib.sha256(peer.canon(a['argv'])).hexdigest(),'managerMainPID':main,'ancestry':[{**{k:row['raw'][k]for k in('pid','start','ppid','uids','cgroup')},'uid':row['raw']['uids'][0],'exePin':row['exe']}for row in ancestors]}
   record('entry-verified',result);return result
  except BaseException as error:
   first=error;value={'stage':stage,'first':{'type':type(error).__name__,'reason':str(error)},'observations':observed,'request':r,'hardwareEffects':[]};error.evidence=value
   try:record('FIRST-entry-lineage',value)
   except BaseException as secondary:value['diagnosticPersistenceError']={'type':type(secondary).__name__,'reason':str(secondary)}
   raise
  finally:
   errors=[]
   for fd in fds[::-1]:
    try:os.close(fd)
    except BaseException as error:errors.append({'fd':fd,'type':type(error).__name__,'reason':str(error)})
   if errors:
    if first is not None:first.evidence['descriptorClosureErrors']=errors
    else:raise peer.Refused('entry executable descriptor closure UNKNOWN; retain lease: '+repr(errors))
 def access_persist(self,label,value):
  from libvirt_producer import put
  with peer.RootFiles('/run/opemos-libvirt-queue-'+self.request['jobToken'])as files,files.lock(True):
   pin=put(files,label+'.json',value)
  self.report(label,{'pin':pin,'value':value});return pin
 def prepare_io(self,intent):
  import libvirt_access as access
  held(intent['accessPin'],65536)
  stage=access.verify_prepared(self.c,self.g['preparedAccessPin'],self.g['preparedDiskPins'])
  self.accessRows=stage['rows']
  for row in self.accessRows:self.access_persist('acl-before-'+row['role'],row)
  access.probe(self.accessRows,self.c['original']['path'],self.persist)
  self.report('IO_ACCESS_READY',{'preparedAccessPin':self.g['preparedAccessPin'],'splitDiskCapturePins':self.g['splitDiskCapturePins'],'noPostGrantDiskHash':True,'rows':self.accessRows})
 def restore_access(self,intent,closure,locked_files=None):
  import libvirt_access as access
  import contextlib
  with (contextlib.nullcontext(locked_files)if locked_files is not None else peer.RootFiles('/run/opemos-libvirt-queue-'+self.request['jobToken']))as files,(contextlib.nullcontext()if locked_files is not None else files.lock(True)):
   stage=access.prepared_lineage(self.c,self.g['preparedAccessPin'],self.g['preparedDiskPins']);expected={row['role']:row for row in stage['rows']}
   roles=('serial','output-parent','vars','runtime-parent','working','working-parent');rows=[]
   for role in roles:
    try:raw,pin=files.read('acl-before-'+role+'.json')
    except FileNotFoundError:
     from libvirt_producer import put
     pin=put(files,'acl-before-'+role+'.json',expected[role]);raw,_=files.read('acl-before-'+role+'.json')
    row=json.loads(raw);peer.need(row==expected[role],'original protected prepared stage exactly joins every restore journal');scope=intent['accessScope'];allowed={'working-parent':str(Path(scope['working']['path']).parent),'working':scope['working']['path'],'runtime-parent':scope['run'],'vars':scope['run']+'/OVMF_VARS_4M.fd','output-parent':scope['output'],'serial':scope['output']+'/serial.raw'}
    peer.need(row['role']==role and row['path']==allowed[role]and row['uid']==64055,'exact immutable journal scope/role binding')
    if role=='working':peer.need(row['before']==scope['working'],'journal original working pin')
    rows.append(row)
   results=[]
   for row in rows:
    def save(label,value):
     from libvirt_producer import put
     try:raw,pin=files.read(label+'.json');old=json.loads(raw);peer.need(old['path']==value['path']and old['restored']is True,'exact prior restore receipt');return pin
     except FileNotFoundError:return put(files,label+'.json',value)
    results.append(access.restore(row,closure,save))
  if hasattr(self,'vfioPolicy'):self.vfioPolicy.restore(self,peer,native_child,closure)
  self.report('ACL_CLOSURE',results);return results
 def configure_partition(self,r):
  for argv in([
   '/usr/bin/systemctl','set-property','--runtime',r['vmSlice'],'CPUQuota=400%','MemoryMax='+str(8*1024**3),'MemorySwapMax=0','AllowedCPUs='+','.join(map(str,r['cpus']))],['/usr/bin/systemctl','start',r['vmSlice']]):
   x=native_child(argv,self.deadline);self.report('partition-helper',x);peer.need(x['numeric']==0,'exact transient VM partition operation')
  peer.NativeOps().budget(r,'PREPARED',None)
 def partition_empty(self,r):peer.NativeOps().budget(r,'PREPARED',None);return True
 def prepare_controller_connection(self,intent):
  import libvirt
  peer.need(self.conn is None and self.observer is None and intent['failureControl']=='LIBVIRT_AUTODESTROY_CONTROLLER_CONNECTION','one exact held controlling connection; no watchdog')
  self.processEventDriver=bootstrap_event_driver(self.persist);self.intent=intent;self.conn=libvirt.open('qemu:///system');self.observer=libvirt.openReadOnly('qemu:///system')
  peer.need(self.conn is not None and self.observer is not None and self.conn.getURI()==self.observer.getURI()=='qemu:///system','actual independent observer/control system URI')
  self.eventTimer=libvirt.virEventAddTimeout(100,lambda timer,opaque:None,None)
  def event(conn,domain,event,detail,opaque):self.events.append({'uuid':domain.UUIDString(),'name':domain.name(),'event':event,'detail':detail,'atUnix':time.time()})
  self.callback=self.observer.domainEventRegisterAny(None,libvirt.VIR_DOMAIN_EVENT_ID_LIFECYCLE,event,None)
  a=peer.process(os.getpid());return {'heldVerified':True,'failureControl':intent['failureControl'],'controllerActor':{k:a[k]for k in('pid','start','uid','cgroup')},'connectionURI':self.conn.getURI(),'observerURI':self.observer.getURI(),'independentHelperBytes':0,'controlConnectionLossProofRequired':True}
 def recheck_before_domain(self,intent,phase):
  peer.need(time.time()<self.deadline,'whole job deadline')
  if phase==1:peer.need(time.time()-self.g['preflightObservedUnix']<=30,'unchanged actual pre-use30s clock after ACL full content re-pin')
  peer.NativeOps().entry(intent,'PREPARED');peer.NativeOps().budget(self.request,'PREPARED',None)
  for fd,key in zip(self.diskfds,('original','working')):
   a=os.fstat(fd);b=os.lstat(self.c[key]['path']);peer.need(peer.ident(a)==peer.ident(b),'held named disk before use')
   if key=='original':peer.need(peer.ident(a)==self.c[key]['identity'],'immutable original full9')
   else:peer.need(a.st_dev==self.c[key]['identity']['st_dev']and a.st_ino==self.c[key]['identity']['st_ino']and a.st_size==self.c[key]['bytes'],'same working inode/size across boots')
  self.offset=Path(self.c['output']+'/serial.raw').stat().st_size if Path(self.c['output']+'/serial.raw').exists()else 0
 def create_paused(self,xml):
  import libvirt
  for path in('/usr/bin/virt-xml-validate','/usr/bin/xmllint'):held(self.g['nativeTools'][path],33554432)
  schema=native_child(['/usr/bin/virt-xml-validate','-','domain'],self.effect_clock('create'),self.g['nativeTools']['/usr/bin/virt-xml-validate'],xml.encode());self.report('exact-installed-XML-before-create',schema);peer.need(schema['numeric']==0,'current exact XML installed schema before domain create')
  peer.need(self.observer is not None,'independent observer must be subscribed before first domain')
  if self.conn is None:self.conn=libvirt.open('qemu:///system')
  peer.need(self.conn is not None and self.conn.getURI()=='qemu:///system','exact controlling connection')
  caps=self.conn.getDomainCapabilities(self.c['qemu']['path'],'x86_64','q35','kvm',0);self.report('actual-virtio-mode-capability-before-create',__import__('guest_firmware_probe').verify_display_capability(caps))
  peer.need(not any(d.UUIDString()==self.request['domainUUID']or d.name()==self.request['domainName']for d in self.conn.listAllDomains(0)),'no existing domain adoption')
  self.effect_clock('create')
  self.capture_dac_fd('before-create')
  self.eventIndex=len(self.events);self.expectedStop=None
  self.effect_clock('create')
  if not hasattr(self,'vfioPolicy'):
   import types
   ref=self.g['nativeTools']['/var/lib/opemos-vfio-idle-d3/managed_vfio.py'];raw=held(ref,65536);self.vfioPolicy=types.ModuleType('managed_vfio');exec(compile(raw,ref['path'],'exec'),self.vfioPolicy.__dict__)
  self.vfioPolicy.prepare(self,peer,native_child)
  self.effect_clock('create')  # fresh immediately after module preparation/scans
  return self.conn.createXML(xml,libvirt.VIR_DOMAIN_START_PAUSED|libvirt.VIR_DOMAIN_START_AUTODESTROY)
 def pump_events(self):
  import libvirt
  peer.need(libvirt.virEventRunDefaultImpl()==0,'bounded libvirt event dispatch')
 def register_actual_domain(self,d,intent):
  import libvirt
  peer.need(d.UUIDString()==self.request['domainUUID']and d.name()==self.request['domainName']and not d.isPersistent()and d.state(0)[0]==libvirt.VIR_DOMAIN_PAUSED,'actual paused transient domain')
  self.capture_dac_fd('after-create-paused',d)
  matches=[];scanned=0;observed=None;scanningPID=None;stage='raw-candidate-selection'
  try:
   for p in Path('/proc').iterdir():
    if not p.name.isdigit():continue
    scanningPID=int(p.name);scanned+=1;peer.need(scanned<=8192,'finite whole domain PID enumeration')
    try:raw=peer.process_snapshot(int(p.name))
    except(FileNotFoundError,ProcessLookupError):continue
    args=raw['argv'];uuidPositions=[i for i,x in enumerate(args)if x=='-uuid'];namePositions=[i for i,x in enumerate(args)if x=='-name']
    uuidMatch=any(i+1<len(args)and args[i+1]==self.request['domainUUID']for i in uuidPositions)
    nameMatch=any(i+1<len(args)and('guest='+self.request['domainName'])in args[i+1].split(',')for i in namePositions)
    if not(uuidMatch or nameMatch):continue
    observed=raw;self.report('domain-candidate-before-role',{'raw':raw,'uuidMatch':uuidMatch,'nameMatch':nameMatch})
    peer.need(uuidMatch and nameMatch and len(uuidPositions)==len(namePositions)==1,'one exact UUID/name pair; conflicting matching candidate refuses')
    stage='selected-QEMU-role';a=peer.process(raw['pid'])
    peer.need(all(a[k]==raw[k]for k in('pid','start','ppid','tgid','argv','cgroup'))and raw['uids']==[64055]*4 and a['uid']==64055 and a['tgid']==a['pid'],'selected actual uniform UID64055/TGID and original raw identity')
    peer.need(peer.process_snapshot(a['pid'])==raw and peer.process(a['pid'])==a,'selected QEMU repeated original identity');matches.append(a);stage='raw-candidate-selection'
   self.report('domain-candidate-selection',{'scanned':scanned,'matches':matches})
   peer.need(len(matches)==1,'one actually observed exact QEMU UUID/name actor');a=matches[0];vmroot=peer.POOL+'/'+self.request['vmSlice']+'/';peer.need(a['cgroup'].startswith(vmroot),'actual scope within own VM partition')
   scope=a['cgroup'][len(vmroot):].split('/')[0];reg={'scope':scope,'leader':{k:a[k]for k in('pid','start','uid')}}
   reader=self.readonly();verificationFailed=False;registrationClosureErrors=[]
   try:
    reader.leader(reg,intent);self.captureCandidate=a;self.capture_dac_fd('paused-before-storage',d,a);reader.budget(self.request,'ACTIVE',scope)
    peer.need(peer.process(a['pid'])==a,'selected QEMU unchanged after executable/cgroup/device verification')
   except BaseException:verificationFailed=True;raise
   finally:
    try:reader.close()
    except BaseException as secondary:
     if not verificationFailed:raise
     registrationClosureErrors=[{'type':type(secondary).__name__,'reason':str(secondary)}]
   x=d.XMLDesc(0);
   if self.c.get('installer')is not None:__import__('guest_firmware_probe').validate_installer_xml(self.c,__import__('xml.etree.ElementTree',fromlist=['ElementTree']).fromstring(x))
   peer.validate_hostdev_xml(__import__('xml.etree.ElementTree',fromlist=['ElementTree']).fromstring(x),intent);peer.need(not __import__('xml.etree.ElementTree',fromlist=['ElementTree']).fromstring(x).findall('devices/interface'),'actual noNIC XML')
   reg.update(uuid=d.UUIDString(),name=d.name(),persistent=False,noNIC=True,XMLSHA256=hashlib.sha256(x.encode()).hexdigest());self.registered=reg;self.observationActor=peer.process_snapshot(a['pid']);peer.need(self.observationActor['uids']==[64055]*4 and all(self.observationActor[k]==a[k]for k in('pid','start','ppid','tgid','argv','cgroup')),'registered full raw observation baseline');self.report('actual-paused-domain',reg);return reg
  except BaseException as error:
   value={'stage':stage,'first':{'type':type(error).__name__,'reason':str(error)},'scanned':scanned,'scanningPID':scanningPID,'candidate':observed,'closureErrors':locals().get('registrationClosureErrors',[]),'vfioEvidence':getattr(error,'vfioEvidence',None),'workingEvidence':getattr(error,'workingEvidence',None),'DACFDRecordPin':None,'DACFDObservation':self.lastDACFDObservation,'matches':matches,'request':self.request,'noGuestResume':True}
   error.evidence=value
   try:self.report('FIRST-domain-candidate',value)
   except BaseException as secondary:value['diagnosticPersistenceError']={'type':type(secondary).__name__,'reason':str(secondary)}
   raise
 def resume_exact(self,d,reg,intent):
  self.effect_clock('resume')
  peer.need(self.registered==reg and d.UUIDString()==intent['request']['domainUUID']and d.name()==intent['request']['domainName'],'exact registered handle');peer.NativeOps().leader(reg,intent);self.effect_clock('resume');peer.need(d.resume()==0,'libvirt resume numeric0')
 def observation_tick(self):
  self.pump_events();self.observationCalls+=1
  peer.need(time.time()<self.deadline,'whole observation deadline')
  peer.need(self.conn is not None and self.observer is not None and self.conn.isAlive()==1 and self.observer.isAlive()==1,'actual controlling/readonly connections remain alive')
  import libvirt
  relevant=self.events[self.eventIndex:];peer.need(not any(e['uuid']==self.request['domainUUID']and e['name']==self.request['domainName']and e['event']in(libvirt.VIR_DOMAIN_EVENT_STOPPED,libvirt.VIR_DOMAIN_EVENT_SHUTDOWN,libvirt.VIR_DOMAIN_EVENT_CRASHED)for e in relevant),'unexpected terminal domain lifecycle during graphical/serial observation')
  raw=peer.process_snapshot(self.registered['leader']['pid']);peer.need(raw['start']==self.registered['leader']['start']and raw['uids']==[64055]*4 and raw['tgid']==raw['pid']and raw==self.observationActor,'original selected QEMU PID/start/UID/argv/ancestry/cgroup stable throughout observation')
 def _capture_graphical_sample(self,phase,sample,intent,end):
  import libvirt_access as access
  peer.need(phase in(1,2)and phase not in self.graphical and type(sample)is int and 1<=sample<=6,'one finite graphical observation per boot');path=self.c['run']+'/vnc.sock';ch=None;primary=None;value=None;parent=None;sockfd=None
  try:
   self.observation_tick();peer.need(self.registered is not None,'exact actual paused-domain registration before graphics')
   row=next(r for r in self.accessRows if r['role']=='runtime-parent')
   with access.Held(self.c['run'])as parent:
    before=parent.check(True);peer.need(all(before[k]==row['before']['identity'][k]for k in('st_dev','st_ino','st_uid','st_gid'))and before['st_uid']==before['st_gid']==0 and access.ACL().get(parent.fd)==row['targetACL'],'held exact generated runtime parent/current ACL')
    sockfd=os.open('vnc.sock',os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent.fd);si=peer.ident(os.fstat(sockfd));peer.need(stat.S_ISSOCK(si['st_mode'])and si==peer.ident(os.stat('vnc.sock',dir_fd=parent.fd,follow_symlinks=False)),'held named VNC socket full9')
    ch=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);ch.settimeout(.1);ch.connect(path);pid,uid,gid=struct.unpack('3i',ch.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));raw=peer.process_snapshot(pid);identity={'path':path,'socketIdentity':si,'peerPID':pid,'peerUID':uid,'peerGID':gid,'rawPeer':raw,'domain':self.registered,'phase':phase};self.report('graphical-peer-before-predicate-'+str(phase)+'-sample-'+str(sample),identity)
    peer.need(pid==self.registered['leader']['pid']and uid==64055 and raw['start']==self.registered['leader']['start']and raw['uids']==[64055]*4,'VNC server is exact original QEMU, never another guest')
    rgb,protocol=read_vnc_frame(ch,self.observation_tick,end);png=rgb_png(rgb,protocol['width'],protocol['height']);peer.need(protocol['serverName']in(self.request['domainName'],'QEMU ('+self.request['domainName']+')'),'RFB name joins exact domain')
    peer.need(si==peer.ident(os.fstat(sockfd))==peer.ident(os.stat('vnc.sock',dir_fd=parent.fd,follow_symlinks=False))and parent.check(True)==before and peer.process_snapshot(pid)==raw,'socket/parent/QEMU full current identity unchanged during frame')
   colours=set(tuple(rgb[i:i+3])for i in range(0,len(rgb),3));content={'distinctRGBColours':len(colours),'nonBlank':len(colours)>=4,'virtualDisplayOnly':True,'NVIDIARenderProof':False,'OSGraphicalSessionAccepted':False}
   root='/run/opemos-libvirt-results-'+self.request['leaseNonce'];name='graphical-first-'+str(phase)+(''if sample==1 else'-sample-'+str(sample))+'.png'
   previous=next((x for x in self.capturedFrameHistory if x['phase']==phase and x['framePin']['sha256']==hashlib.sha256(png).hexdigest()and x['framePin']['bytes']==len(png)),None)
   if previous is not None:
    ref=previous['framePin'];peer.need(held(ref,4194304)==png,'exact retained same-byte frame reused without duplicate image');frameSample=previous.get('frameSample',1)
   else:
    with peer.RootFiles(root)as f,f.lock(True):
     used=sum(x.lstat().st_blocks*512 for x in Path(root).iterdir());peer.need(used+len(png)+3145728<=13421772,'unchanged16MiB receipt reservation/20percent headroom includes every image');fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400,dir_fd=f.fd)
     try:
      os.fchmod(fd,0o400);view=memoryview(png)
      while view:n=os.write(fd,view);peer.need(n>0,'graphical write progress');view=view[n:]
      os.fsync(fd)
     finally:os.close(fd)
     os.fsync(f.fd);a=os.stat(name,dir_fd=f.fd,follow_symlinks=False);ref={'path':root+'/'+name,'bytes':len(png),'sha256':hashlib.sha256(png).hexdigest(),'identity':peer.ident(a)};peer.need(held(ref,4194304)==png,'full protected graphical PNG reread/EOF/hash')
    frameSample=sample
   value={'kind':'ACTUAL_DOMAIN_BOUND_GRAPHICAL_FIRST_FRAME','phase':phase,'sample':sample,'frameSample':frameSample,'identity':identity,'protocol':protocol,'framePin':ref,'displayContent':content,'modeAccepted':False,'beforeAnySerialRead':True,'noGuestInput':True,'observationCalls':self.observationCalls};self.capturedFrames[phase]=value;self.capturedFrameHistory.append(value);self.report('graphical-frame-before-content-predicate-'+str(phase)+'-sample-'+str(sample),value);value['usableBounds']=__import__('guest_firmware_probe').verify_unscaled_usable_frame(self.request,identity,protocol,rgb);value['modeAccepted']=True;return value
  except BaseException as error:primary=error;raise
  finally:
   if ch is not None:ch.close()
   if sockfd is not None:os.close(sockfd)
   self.report('graphical-channel-closure-'+str(phase)+'-sample-'+str(sample),{'first':peer.error_value(primary),'socketClosed':ch is None or ch.fileno()==-1,'pathFDClosed':sockfd is None or not Path('/proc/self/fd/'+str(sockfd)).exists(),'frameRetained':None if value is None else value['framePin'],'noGuestInput':True})
 def capture_graphical_first(self,phase,intent):
  peer.need(phase in(1,2)and phase not in self.graphical,'one graphical-first observation per boot');started=time.time();end=min(self.deadline,started+30);samples=[]
  for sample in range(1,7):
   if time.time()>=end:break
   value=self._capture_graphical_sample(phase,sample,intent,end);samples.append(value)
   if value['displayContent']['nonBlank']:
    self.graphical[phase]=value;self.report('graphical-observation-complete-'+str(phase),{'phase':phase,'startedUnix':started,'endUnix':end,'activeFrame':value['framePin'],'modeAccepted':value['modeAccepted'],'usableBounds':value['usableBounds'],'samples':[{'sample':r['sample'],'pin':r['framePin'],'content':r['displayContent']}for r in samples],'graphicalAccepted':True,'NVIDIARenderAccepted':False,'OSGraphicalSessionAccepted':False,'beforeAnySerialRead':True});return value
   until=min(end,started+sample*5)
   while time.time()<until:self.observation_tick();time.sleep(min(.05,max(0,until-time.time())))
  while time.time()<end:self.observation_tick();time.sleep(min(.05,max(0,end-time.time())))
  peer.need(bool(samples),'actual graphical observation produced no complete frame');value=dict(samples[-1]);value.update(diagnosticOnly=True,graphicalDeadlineReached=True,graphicalAccepted=False);self.graphical[phase]=value;self.report('graphical-observation-inactive-deadline-'+str(phase),{'phase':phase,'startedUnix':started,'endUnix':end,'finishedUnix':time.time(),'samples':[{'sample':r['sample'],'pin':r['framePin'],'content':r['displayContent']}for r in samples],'graphicalAccepted':False,'NVIDIARenderAccepted':False,'OSGraphicalSessionAccepted':False,'serialNextDiagnosticOnly':True,'beforeAnySerialRead':True});return value
 def measure_guest(self,phase,intent):
  peer.need(phase in self.graphical and self.graphical[phase]['beforeAnySerialRead'],'graphical-first frame must precede all serial reads')
  if self.c.get('installer')is not None:
   __import__('guest_firmware_probe').authenticate_copy_receipt(self.c,self.c['hostBoot']);self.observation_tick();p=Path(self.c['output']+'/serial.raw');f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
   try:
    before=peer.ident(os.fstat(f));os.lseek(f,self.offset,os.SEEK_SET);b=os.read(f,4194305);after=peer.ident(os.fstat(f));peer.need(len(b)<=4194304 and all(before[k]==after[k]==peer.ident(p.lstat())[k]for k in peer.CORE)and after['st_size']>=self.offset+len(b),'bounded named serial diagnostic after graphical observation')
   finally:os.close(f)
   self.phaseSerial=b;self.report('installer-secondary-serial',{'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'serialPath':str(p),'graphicalFrame':self.graphical[phase]['framePin'],'diagnosticOnly':True,'graphicalFirst':True});v={'kind':'ACTUAL_RETAINED_INSTALLER_BOOT_DIAGNOSTIC','domainUUID':self.request['domainUUID'],'domainName':self.request['domainName'],'mediaPin':self.c['working'],'actualDomainRegistration':self.registered,'graphicalFrame':self.graphical[phase]['framePin'],'graphicalFirst':True,'serialBytes':len(b),'serialSHA256':hashlib.sha256(b).hexdigest(),'guestOSIdentityAccepted':False,'NVIDIARenderAccepted':False,'installedSystemAccepted':False,'recoveryAccepted':False};return peer.canon(v)
  p=Path(self.c['output']+'/serial.raw');end=min(self.deadline,time.time()+300);primary=None;seen=0;self.phaseSerial=b''
  try:
   while time.time()<end:
    self.observation_tick();fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
     st=os.fstat(fd);peer.need(stat.S_ISREG(st.st_mode)and st.st_nlink==1,'exact serial file');os.lseek(fd,self.offset,os.SEEK_SET);b=os.read(fd,4194305);peer.need(len(b)<=4194304,'phase serial4MiB');after=peer.ident(os.fstat(fd));named=peer.ident(p.lstat());core=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink');peer.need(all(after[k]==named[k]==peer.ident(st)[k]for k in core)and after['st_size']>=self.offset+seen,'same owned serial core and no output truncation')
    finally:os.close(fd)
    seen=len(b);self.phaseSerial=b;complete=b'\n'.join(b.split(b'\n')[:-1])+b'\n'
    if b'OPEMOS_STEAMOS_AB_REPORTER_FAILURE'in [line.rstrip(b'\r')for line in complete.split(b'\n')]:
     error=GuestReporterFailure('actual guest reporter failure');error.evidence={'kind':'ACTUAL_GUEST_REPORTER_FAILURE','phase':phase,'marker':'OPEMOS_STEAMOS_AB_REPORTER_FAILURE','serialBytes':len(b),'serialPrefixSHA256':hashlib.sha256(b).hexdigest(),'serialPath':str(p),'retainedFailureSuffixBase64':__import__('base64').b64encode(b[-8192:]).decode(),'suffixIsBounded':len(b)>8192,'graphicalFirst':True};raise error
    if b'OPEMOS_STEAMOS_AB_V1 'in complete:self.phaseSerial=b;return b
   raise peer.Refused('actual guest serial measurement deadline')
  except BaseException as error:primary=error;raise
  finally:self.report('secondary-serial-observation-'+str(phase),{'graphicalFramePin':self.graphical[phase]['framePin'],'serialBytesObserved':seen,'serialPrefixSHA256':hashlib.sha256(self.phaseSerial).hexdigest(),'serialPath':str(p),'diagnosticOnly':not self.graphical[phase]['displayContent']['nonBlank'],'eventDispatchCalls':self.observationCalls,'first':peer.error_value(primary),'deadlineUnchanged':True,'graphicalFirst':True})
 def prove_firmware_route(self,intent,phase,boot_id):
  import base64,struct
  rows=[];prefix=b'OPEMOS_LIBVIRT_FIRMWARE_V1 '
  for line in self.phaseSerial.split(b'\n')[:-1]:
   if not line.startswith(prefix):continue
   parts=line[len(prefix):].split(b' ');peer.need(len(parts)==3 and parts[0].decode()==self.c['guestReporterNonce'],'exact firmware frame scope')
   raw=base64.b64decode(parts[2],validate=True);peer.need(len(raw)<=262144 and hashlib.sha256(raw).hexdigest().encode()==parts[1],'firmware canonical hash/bound');v=json.loads(raw);peer.need(peer.canon(v)==raw,'firmware canonical JSON');rows.append(v)
  peer.need(len(rows)==1,'one actual EFI route frame per boot');v=rows[0]
  peer.need(v['kind']=='ACTUAL_LIBVIRT_GUEST_EFI_ROUTE_V1'and v['guestUUID']==self.request['domainUUID']and v['bootId']==boot_id,'same actual guest/boot firmware proof')
  variables={x['name']:x for x in v['variables']};peer.need(len(variables)==3,'exact three EFI variables')
  for q in variables.values():
   raw=base64.b64decode(q['base64'],validate=True);peer.need(len(raw)==q['bytes']<=65536 and hashlib.sha256(raw).hexdigest()==q['sha256'],'full EFI raw bytes/hash')
  raw=base64.b64decode(variables['BootCurrent']['base64']);peer.need(len(raw)==6 and struct.unpack('<H',raw[4:])[0]==v['BootCurrent'],'actual BootCurrent binary')
  peer.need('Boot%04X'%v['BootCurrent']in variables,'selected firmware load option retained');self.report('actual-firmware-route-'+str(phase),v)
 def prepare_disconnect(self,d,intent):
  peer.NativeOps().leader(self.registered,intent);peer.need(d.UUIDString()==self.request['domainUUID']and d.name()==self.request['domainName']and self.conn is not None,'exact owned AUTODESTROY connection/domain')
  return dict(self.registered)
 def disconnect_exact(self,registration,intent):
  import libvirt
  peer.need(registration==self.registered and self.conn is not None,'exact prior registered controller-loss target');peer.NativeOps().leader(registration,intent)
  self.expectedStop=(libvirt.VIR_DOMAIN_EVENT_STOPPED,libvirt.VIR_DOMAIN_EVENT_STOPPED_DESTROYED)
  result=self.conn.close();self.conn=None;self.report('controller-connection-loss',{'numeric':result,'domainUUID':self.request['domainUUID'],'registered':self.registered,'acceptanceRequiresIndependentClosure':True});peer.need(result==0,'controller connection close numeric0')
 def wait_guest_shutdown(self,d,intent):
  import libvirt
  self.expectedStop=(libvirt.VIR_DOMAIN_EVENT_STOPPED,libvirt.VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN)
  end=min(self.deadline,time.time()+120)
  while time.time()<end:
   self.pump_events()
   if not any(x.UUIDString()==self.request['domainUUID']or x.name()==self.request['domainName']for x in self.observer.listAllDomains(0)):return
   time.sleep(.1)
  raise peer.Refused('guest ordinary shutdown not observed; hold')
 def prove_domain_closure(self,d,intent):
  import libvirt
  end=min(self.deadline,time.time()+15);relevant=[]
  while time.time()<end:
   self.pump_events()
   relevant=[e for e in self.events[self.eventIndex:]if e['uuid']==self.request['domainUUID']and e['name']==self.request['domainName']]
   stopped=any((e['event'],e['detail'])==self.expectedStop for e in relevant)
   if stopped and not any(x.UUIDString()==self.request['domainUUID']for x in self.observer.listAllDomains(0)):break
   time.sleep(.1)
  absent=not any(x.UUIDString()==self.request['domainUUID']for x in self.observer.listAllDomains(0));peer.need(absent,'transient domain absent')
  peer.need(self.expectedStop is not None and any((e['event'],e['detail'])==self.expectedStop for e in relevant),'actual same-phase daemon STOPPED reason required')
  try:a=peer.process(self.registered['leader']['pid']);peer.need(a['start']!=self.registered['leader']['start'],'original leader still present')
  except(FileNotFoundError,ProcessLookupError):pass
  peer.NativeOps().budget(self.request,'PREPARED',None);peer.NativeOps().restoration(intent)
  return {'domainAbsent':True,'originalPIDStartAbsent':True,'cgroupEmpty':True,'VFIOFDsAbsent':True,'hostRestored':True,'unknown':[],'qemuExitStatus':None,'controllerWaitpidClaimed':False,'lifecycleEvidence':relevant}
 def stopped_readback(self,intent):
  peer.NativeOps().budget(self.request,'CLOSED',None);peer.NativeOps().restoration(intent)
  target=Path(self.c['run'])/'stopped-home';target.mkdir(mode=0o700);dev=None;mounted=False;primary=None;secondary=[];rows=[]
  def tool(argv):
   ref=self.g['nativeTools'][argv[0]];r=native_child(argv,self.deadline,ref);self.report('stopped-native',r);peer.need(r['numeric']==0,'stopped readonly native helper');return r['stdout']
  def loop_proof():
   row=json.loads(tool(['/usr/sbin/losetup','--json','--output','NAME,BACK-INO,OFFSET,SIZELIMIT,RO',dev]))['loopdevices'][0]
   peer.need(row['ro']is True and row['back-ino']==self.c['working']['identity']['st_ino']and row['offset']==11677990912 and row['sizelimit']==9796825088,'exact readonly synthetic-home loop binding')
  try:
   dev=tool(['/usr/sbin/losetup','--find','--show','--read-only','--offset','11677990912','--sizelimit','9796825088','/proc/'+str(os.getpid())+'/fd/'+str(self.diskfds[1])]).strip();peer.need(__import__('re').fullmatch('/dev/loop[0-9]+',dev)is not None,'owned loop path');loop_proof()
   tool(['/usr/bin/mount','-t','ext4','-o','ro,noload,nodev,nosuid,noexec',dev,str(target)]);mounted=True
   mi=[x for x in Path('/proc/self/mountinfo').read_text().splitlines()if x.split()[4]==str(target)];peer.need(len(mi)==1 and 'ro'in mi[0].split()[5].split(','),'actual read-only stopped mountinfo')
   ledger=target/('.opemos-autorecovery-'+self.c['guestReporterNonce']);s=ledger.lstat();peer.need(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700 and set(os.listdir(ledger))=={'boot-1.json','boot-2.json'},'exact stopped shared ledger')
   for phase in(1,2):
    p=ledger/('boot-'+str(phase)+'.json');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
     a=os.fstat(fd);b=os.read(fd,65537);peer.need(stat.S_ISREG(a.st_mode)and a.st_uid==a.st_gid==0 and a.st_nlink==1 and len(b)<=65536 and not os.read(fd,1)and peer.ident(a)==peer.ident(os.fstat(fd))==peer.ident(p.lstat()),'stopped leaf full9/EOF')
     rows.append({'phase':phase,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'value':json.loads(b)})
    finally:os.close(fd)
  except BaseException as e:primary=e
  finally:
   if mounted:
    try:loop_proof();tool(['/usr/bin/umount',str(target)]);mounted=False
    except BaseException as e:secondary.append(str(e))
   if dev is not None and not mounted:
    try:loop_proof();tool(['/usr/sbin/losetup','--detach',dev]);dev=None
    except BaseException as e:secondary.append(str(e))
   self.report('stopped-readback-closure',{'primary':None if primary is None else str(primary),'secondary':secondary,'mountClosed':not mounted,'loopClosed':dev is None,'rows':rows})
  peer.need(primary is None and not secondary and not mounted and dev is None,'stopped readback first/secondary/closure failure');return rows
 def original_unchanged(self,intent):
  ref=self.c['original'];fd=self.diskfds[0];os.lseek(fd,0,os.SEEK_SET);h=hashlib.sha256();n=0
  while b:=os.read(fd,1048576):h.update(b);n+=len(b)
  peer.need(n==ref['bytes']and h.hexdigest()==ref['sha256']and peer.ident(os.fstat(fd))==ref['identity']==peer.ident(os.lstat(ref['path'])),'full immutable original after use')
  if self.c.get('installer')is not None:
   ref=self.c['working'];fd=self.diskfds[1];os.lseek(fd,0,os.SEEK_SET);h=hashlib.sha256();n=0
   while b:=os.read(fd,65536):h.update(b);n+=len(b)
   peer.need(n==ref['bytes']and h.hexdigest()==ref['sha256']and peer.ident(os.fstat(fd))==peer.ident(os.lstat(ref['path']))and all(peer.ident(os.fstat(fd))[k]==ref['identity'][k]for k in('st_dev','st_ino','st_uid','st_gid','st_nlink','st_size','st_mtime_ns')),'same-byte readonly installer virtualUSB after domain closure')
 _fc_z=zlib.decompressobj();_fc_raw=_fc_z.decompress(__import__('base64').b85decode('c-pO4OLN;e628x`;9eHw3?(Ory-34@qsJyyiRH1KY)z?DELa33mMM?{NZZ=f{`dVF4~kTrOe(t<i4UN=(fxJz*UUs7<b~vAx-Ba$LM_TXE@UHQ6KB<d7c!ds5(Gl2O6g?1neuH@RMK41j#i1}s*+;*Agd>tEP1H~)@KmQn?@Y!CM@~ADC67;3L15sJo2&?NiM_4iyQO07BUOJFjbX;P3#_K7Baj3Khac)rd2X9w<JqEZ$;e%Z@3l<a|uxa*VfvJwfSYqzy4Yap~hxOYUG9HIyz~gQ@N9DE7@STbCEp<p2>u~HKwa+ca^w(L1FgEpwLFt#EJdFWYw%-5}Vv9oQjsp#8^Yih4F{gl#0h96LKp;dJ{8e28)fdS}0xU#@=js4e8=dA+tj6;`^#9Ll?eiYJ^K6vQQ?;tC)#rc-<eW#QNZ*IWU@EvCa*!w>=0|Y}o`RTz<S;%@?<KH>*Ey#OGG%Mr3T#R~NIa68frYu2uCY=H}td0_AjK4-GcIoQ;<A(Y?qkB}PU!i%WjE&-kQ&ur%Y_G|xgdT)E{qZ^j#u^cT<k(^$dALW#`cGK!$Oy4ONI3T1cryXoN0#}Fa(k0^`?oC#$B`GHedmiK)7(0^;tL8!@u5<5glC<htD*^3)nZ!I2?XY+2|r96fMxr5jRg$!TCqykPxvIU)XuSszVA!0WWV)OHba2o7&p@2k@jl6*)znjIUb3`s5{GvfZoH^@%#=IAXv%0JQ6Yx7Le-QNpz`Cp%o%RBS{qlg4)_Jt^WpDA&chU3(%$b7;g2r8O7(#E-39l>N*fbcKrK3#Y(8J_0k5cnGb;VkT%#{0)KM1hg1)W7c!rNA<-Yys7lRs^T=v#*JWcLJaPvDXd<=D8rR#gKhh%B(1;cV39<N#D#V+GGpj6~ev&|~@uqu*ZtgDeW3_C+ZI!j4U(%4V;^mP(dK^pRQ>2d<75>rcFBfQGIc*{)+Qf=nls%RU|UAyNt%W;*&kd2R9=@DD$)S=$yF+az9}DS2yV_kaBOZq7Ee7z-soh;J>tGVf?1c?*jjgvkrt{_5)8jBQZeg3s^}>_nE!Dxh*#>~L=+1zD@8VBc4*%-~9sv_Y>bTO_l{9u{EAv^%(s9(tWAjp-iv$;4y&d?>>-Ee>_1nlud=?#H50LW~!sI1mPL&Ei~DhY}_yYu10hiN^E>r3Y5Qed|}7HHp9r$0GVJ?nU-@#6D(Uo9~WEemV+^C6P^mrH0TQb)h9J*mDWQ*dMVP-?!OLG+{pqF`K<#-7e<L*3M~#7rLozv2;jw{_3*NS3E-NS!wrhQvAu5FaUciv`)3;wcb~qaxY=cO5haP1=rMsCa=u#mv9MiqhT&7rVC;r@wFBCzN#MD+B}MkKF=+JK{Dcvuebr=gWEOJ4Oaly-;(bb<JKSys@PFcptIW){bTXrV{rX$eqq)GJ4$f4A<%##FFm}1u38%QXRCYcK!1s%0(`q?UIk>{lE~rP?M_uVC<@!rKl-$Mw_48ia2<j6#srUOhke#cr+kf*><fBXpn3iA;d*Ak!zQ*oeHMpy@mw@e-?Z94^(;uJe*swt&#dGCD0Z3R(N(p1p;2)Qg3JmPr`O2-f`$6RWbURY$gU!pDqQ-iM1ZQsuATl8{IysYfR{NgLpK!kg!+Oj$0KFq{ypk@N&;u~sgZYf<E6_%+hgkXP}>%xjpcqQ=o;0)7VFHBMaXFHdl-?!_^jtd(DZeiG3oBP`8kc`c|+aSDd_}%k57JM%TEwX;`^@iotF&0El>W?#q;QL_I}hWLPHbn3z70I)c{wZV(%5yFPBOuk^af(X^;3@Hw<O^6=^HCdoFif3x_<i&`xh0{PTHjL4;QJqN&uNo~c2($t^O?@@(Ua27R@2KtBf|JSqL5@C}y#MCg3r)(n!m`m*^se@r`J-V4jNEZ=gy{{%vr7cWZwVTTbpQ{sTpDy2s1M+@7(gR;1PEL3CWY<ioVQOUDjtcC=Rs1z}ZKsQBMj(R=NEJpX0iPJE~j~QNWj4dR*Y8xx`+e6E6@PvA6ggFm&mFbzeXOoMyVq*T{GlKr3wAoHMmN8p-ao?TfVsd*<EHxm)<H%{DA97H#Zn(3<3Ox?<EXgxB;ZZ=7-i{lwtrTcco^7Vw(ghlCny}L29KE%{ZloZQM+et6iCD7-abz1J47}O1P0yn|ITKSFF(e_1JaOgg2cXJIG7Aed)(sxg*&Zk+X#OeaAB*Xtkd?h4vTH7O{z8J1KiErM{2Rp5=zv;f>H0&+E{FhKko6aNcENrF88oNz2B6)8k`c_wNJFmkt!&D%`Nh)M-Y(OBF7B4^yM1}dciQmdaPZ*o(7sA9XR{ArjaY4NZ|1A3_kVf}dp=|NrGFbxOafh2&4sn;0>Kd%Mr?54N6($7kZ4;mjxp`We{8X0o_Da!K^AZb*L&%=8(FhA=5vK1B5cCJCLAT{*uxnxNzbTrVSGYa)Ngm)C^gzCUhj$SjB*9%nkH|jc2_mmUs%28q+PAu6=;&?huRoBCbH~r<JZX18Z?{M8hO{a!SefKBlL|R;cP;4Ql~aG%TlvoNV-)7VL2+_Vzs2=x1ij22PYKDSW$`zlg6maVZT~uOA`CmkhvqwGL$(h@*FnEt?)e9Pj#kT+O){C6A#Bs))bFoWCvc`Du&ERaM{)x5%0;i<8r178qy)o_Ddb6*Eg%#;`TOOd|F)HrSqG2pB6XvBSaxVh*0O}u~9N8fT%!J>`w~T%t>UMv7uk!O>h;`Hn8^MSX^pb^8-*|Hw49jW4g%jCw|l@n|Z4thJ5ogUqWp;cHTkj-ByR1t3neW`94W(VO}nhwJ^0(m^d00REC9bYjkv~G%tNJdGXswv~gdN-7(#~Y_)Z_{d_!qi5u2^hY$OmxtmVRUrYm#7H>rfER#I<bU0d=??|4`k&>>d57up>^J(YX8wcxXBSPyZloL9>`p)>n0P@^*;w}IwOB+yl>;>{3?MP-I_RL{|teBnR-ZKQ105peUbZuvWZU+1Ih$X9AGas(h?NR4?0a;znPy65Q{6{ERsRRBhH3E>fsApdhadW`om;e6)Y1q9F'),8193)
 peer.need(_fc_z.eof and not _fc_z.unused_data and not _fc_z.unconsumed_tail and len(_fc_raw)==6323 and hashlib.sha256(_fc_raw).hexdigest()=='96af367c5f3c31f1cc4b23c8f49f0466bfdf3227a49f0265ca51d998bbfa5d24','exact bounded immutable final_close definition')
 exec(compile(_fc_raw,__file__,'exec'));final_close.__qualname__='NativeTransactionOps.final_close'
 del _fc_z,_fc_raw

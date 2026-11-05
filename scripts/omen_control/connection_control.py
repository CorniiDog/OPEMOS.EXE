#!/usr/bin/env python3
"""Native observations and bounded QMP input in an admitted Ubuntu VM.

The ordinary queue job owns QEMU creation and closure. Diagnostic clicks and
normal GUI Build/write observations retain separate results; neither alone
establishes SteamOS boot, installation or NVIDIA acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import time

FULL9=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def need(ok,why):
    if not ok:raise RuntimeError(why)

def held(path,cap):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        first=os.fstat(fd);sig=lambda s:tuple(getattr(s,k)for k in FULL9)
        need(stat.S_ISREG(first.st_mode)and first.st_uid==os.getuid()and
             first.st_nlink==1 and not first.st_mode&0o077 and first.st_size<=cap,
             'private held file custody failed')
        raw=b''
        while chunk:=os.read(fd,min(65536,cap+1-len(raw))):
            raw+=chunk;need(len(raw)<=cap,'bounded held read overflow')
        need(len(raw)==first.st_size and
             sig(first)==sig(os.fstat(fd))==sig(os.lstat(path)),
             'held file/path identity changed')
        return raw
    finally:os.close(fd)

def save(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        need(os.write(fd,raw)==len(raw),'short receipt write');os.fsync(fd)
    finally:os.close(fd)
    return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def process(binding):
    pid=binding['pid'];need(type(pid)is int and pid>1,'exact VM PID missing')
    proc=Path('/proc')/str(pid);raw=(proc/'stat').read_text()
    start=raw[raw.rfind(')')+2:].split()[19]
    need(start==binding['start_ticks'] and
         Path('/proc/sys/kernel/random/boot_id').read_text().strip()==binding['host_boot_id'],
         'QEMU birth identity changed')
    need((proc/'exe').resolve()==Path('/usr/bin/qemu-system-x86_64').resolve(),
         'not the admitted QEMU binary')
    actual=[x.decode()for x in (proc/'cmdline').read_bytes().split(b'\0')if x]
    need(actual==binding['argv'],'QEMU argv changed')
    need((proc/'cgroup').read_text().strip()==binding['queue_cgroup'] and
         binding['queue_unit'] in binding['queue_cgroup'],
         'QEMU escaped exact admitted normal queue cgroup')
    return proc

def connect_owned(path,pid,timeout=35):
    info=os.lstat(path)
    need(stat.S_ISSOCK(info.st_mode)and info.st_uid==os.getuid()and
         not info.st_mode&0o077,'owned private VM socket required')
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(timeout);s.connect(str(path))
    peer=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    need(peer[0]==pid and peer[1]==os.getuid(),'socket peer is not exact QEMU')
    return s

class QMP:
    def __init__(self,s):
        self.s=s;self.f=s.makefile('rwb',buffering=0);self.n=0
        need('QMP'in self.read(),'QMP greeting absent');self.call('qmp_capabilities')
    def read(self):
        raw=self.f.readline(1048577);need(raw and len(raw)<=1048576,'QMP response missing/oversize')
        return json.loads(raw)
    def call(self,command,args=None):
        self.n+=1;packet={'execute':command,'id':self.n}
        if args is not None:packet['arguments']=args
        self.f.write((json.dumps(packet)+'\r\n').encode())
        while True:
            row=self.read()
            if row.get('id')==self.n:
                need('error'not in row,'QMP command error: '+repr(row.get('error')))
                return row['return']
    def close(self):self.f.close();self.s.close()

def frame(q,path):
    need(not os.path.lexists(path),'frame output must be absent')
    q.call('screendump',{'filename':str(path),'format':'png'})
    raw=held(path,16*1024*1024)
    need(raw[:8]==b'\x89PNG\r\n\x1a\n','real PNG frame absent')
    width,height=struct.unpack('>II',raw[16:24])
    need((width,height)==(1280,800),'actual disposable GUI geometry differs')
    return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'width':width,'height':height}

def observer_line(s,cap=65536):
    b=bytearray()
    while not b.endswith(b'\n'):
        part=s.recv(1);need(part,'observer channel EOF before native result')
        b.extend(part);need(len(b)<=cap,'observer line cap exceeded')
    return json.loads(b)

def next_native_event(s,nonce,receipt):
    row=observer_line(s)
    if row.get('kind')=='BOOTSTRAP_REFUSED':
        need(row.get('nonce')==nonce and
             row.get('phase') in ('verified_package','native_app_and_observer') and
             type(row.get('numeric')) is int and row['numeric']>0,
             'malformed or foreign typed guest bootstrap refusal')
        receipt['typed_guest_bootstrap_refusal']=row
        raise RuntimeError('exact guest bootstrap refused at '+row['phase']+
                           ' numeric='+str(row['numeric']))
    return row

def bounded_input(q,args,records,end=None):
    if end is not None:
        remaining=end-time.monotonic();need(remaining>0,'original input deadline before QMP event')
        q.s.settimeout(min(10,remaining))
    event={'request':args,'response':None};records.append(event)
    event['response']=q.call('input-send-event',args)
    if end is not None:need(time.monotonic()<end,'original input deadline after QMP event')


def pointer(q,x,y,w,h,records=None,end=None):
    records=[] if records is None else records
    for axis,value,dimension in (('x',x,w),('y',y,h)):
        args={'events':[{'type':'abs','data':{'axis':axis,'value':round(value*32767/(dimension-1))}}]}
        bounded_input(q,args,records,end)
    for down in (True,False):
        args={'events':[{'type':'btn','data':{'button':'left','down':down}}]}
        bounded_input(q,args,records,end)
    return records

def main():
    need(len(sys.argv)==2,'one exact private queue binding required')
    raw=held(sys.argv[1],1048576);b=json.loads(raw)
    need(b.get('kind')=='ROBOT_DISPOSABLE_UBUNTU_CONNECTION'and
         re.fullmatch(r'[0-9a-f]{32}',b.get('nonce',''))and
         b.get('package_sha256')=='b252781da4a8af77c1439e0197208fc5c607d29bbc7ef18595ed550029ee9580'
         and b.get('artifact_source')=='01ae39dbe07ae3e5a2f45c6e4c4b354f735156b3',
         'fixed scoped package/nonce identity differs')
    root=Path(b['run_directory']);need(root.is_absolute()and
         root.name=='robot-connection-'+b['nonce'] and
         root.parent==Path('/home/connor/.local/state/opemos-runtime') and
         root.is_dir() and root.stat().st_uid==os.getuid() and
         stat.S_IMODE(root.stat().st_mode)==0o700,'fresh private ext4 VM root required')
    process(b)
    q=QMP(connect_owned(b['qmp_socket'],b['pid']))
    obs=connect_owned(b['observer_socket'],b['pid'],200)
    first=None;receipt={'kind':'ACTUAL_SCOPED_OMEN_NATIVE_CHOOSER_CONNECTION',
                        'nonce':b['nonce'],'artifact_source':b['artifact_source'],
                        'package_sha256':b['package_sha256'],
                        'dispatch_origin':b['dispatch_origin'],'full20Acceptance':False,
                        'imageUSBOrGPUAcceptance':False,'qemu_binding_sha256':hashlib.sha256(raw).hexdigest()}
    try:
        need(q.call('query-name')['name']==b['vm_name'] and
             q.call('query-status')['status']=='running','not actual running exact VM')
        ready=next_native_event(obs,b['nonce'],receipt)
        need(ready.get('kind')=='READY'and ready.get('nonce')==b['nonce'] and
             type(ready.get('app'))is dict and ready['app'].get('window_id') and
             ready.get('process',{}).get('pid')==ready['app'].get('pid') and
             ready['process'].get('start_ticks') and
             ready['process'].get('inherited_nonce')==b['nonce'] and
             re.fullmatch(r'[0-9a-f]{64}',ready['process'].get('exe_sha256','')),
             'real guest native app/PID/window birth missing')
        port=ready.get('port_custody',{})
        need(port.get('sysfs_name')=='opemos.robot.observer' and
             port.get('sudo_numeric') in ('0','NOT_NEEDED') and
             port.get('before','').startswith('character special file ') and
             port.get('after','').startswith('character special file 1000 ') and
             ' 600 ' in port.get('after',''),
             'guest exact native observer port custody not verified')
        app=ready['app'];rect=app.get('rect',[])
        need(len(rect)==4 and 700<=rect[2]<=900 and 400<=rect[3]<=1400,
             'reviewed current package window geometry differs')
        # Fixed same-package coordinate from retained actual PR197 GUI frame;
        # the post-click native dialog, not this label/coordinate, is the proof.
        x,y=755,455
        need(rect[0]<=x<rect[0]+rect[2]and rect[1]<=y<rect[1]+rect[3],
             'choose-input pointer point outside native app window')
        obs.sendall((json.dumps({'kind':'ARM','nonce':b['nonce'],
                                'app_window_id':app['window_id']})+'\n').encode())
        armed=next_native_event(obs,b['nonce'],receipt)
        need(armed.get('kind')=='ARMED'and armed.get('nonce')==b['nonce']and
             armed.get('app_window_id')==app['window_id'],
             'independent native observer did not arm')
        before=frame(q,root/'before-click.png')
        action=pointer(q,x,y,before['width'],before['height'])
        observed=next_native_event(obs,b['nonce'],receipt)
        need(observed.get('kind')=='CHOOSER_OBSERVED' and
             observed.get('nonce')==b['nonce'] and observed.get('observed')is True and
             observed.get('native_observer')is True and
             observed.get('process',{}).get('pid')==ready['process']['pid'] and
             observed.get('process',{}).get('start_ticks')==ready['process']['start_ticks'] and
             observed.get('chooser',{}).get('window_id') not in armed['baseline_ids'] and
             observed.get('chooser',{}).get('title') and
             (observed.get('chooser',{}).get('dialog_type')is True or
              observed.get('chooser',{}).get('transient_for')==app['window_id']),
             'new native same-app chooser result not observed')
        after=frame(q,root/'after-click.png')
        process(b)
        receipt.update(observed=True,ready=ready,armed=armed,
                       pointer={'button':'left','x':x,'y':y,'qmp_events':action},
                       chooser=observed,before_frame=before,after_frame=after,
                       actualQMPInput=True,independentNativeDialog=True)
    except BaseException as error:
        first={'type':type(error).__name__,'reason':str(error)}
        receipt.update(observed=False,first_failure=first)
        try:
            # If the port itself cannot open, no guest event is possible. The
            # exact current QMP terminal frame preserves visible diagnostic
            # text, but it is never promoted to an observed chooser result.
            receipt['failure_frame']=frame(q,root/'failure-diagnostic.png')
        except BaseException as frame_error:
            receipt['failure_frame_secondary']={'type':type(frame_error).__name__,
                                                'reason':str(frame_error)}
        raise
    finally:
        try:obs.close()
        finally:q.close()
        save(root/'connection-result.json',receipt)


# Existing Robot CI10 owned sender custody, reused for the normal Ubuntu job.
# Original source: producer-candidates-r10/ubuntu-owned-ui.py. The Root-selected
# operation replaces only the historical fixed directory/destination data.
CI10_OUTPUTS={'action_result_path':1048576,'sender_lifecycle_path':1048576,'sender_stdout_path':1048576,'sender_stderr_path':1048576}
CI10_FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def ci10_root(context):
    ref=context['normal_policy_pin'];path=Path(ref['path'])
    need(path.parent.parent==Path('/var/lib/opemos-robot-control-r1/releases')and
         re.fullmatch('[0-9a-f]{32}',path.parent.name)and path.name=='fixed-policy.json',
         'existing immutable normal pointer policy')
    for parent in(path.parent,*path.parent.parents):
        info=parent.lstat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==info.st_gid==0
                               and not info.st_mode&0o022,'Root normal pointer ancestry')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);raw=bytearray()
        need(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and
             before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o444 and
             0<before.st_size<=1048576,'Root normal pointer policy custody')
        while block:=os.read(fd,65536):raw.extend(block);need(len(raw)<=1048576,'policy cap')
        need(len(raw)==before.st_size and ci10_sig(before)==ci10_sig(os.fstat(fd))==ci10_sig(path.lstat())
             and hashlib.sha256(raw).hexdigest()==ref['sha256'],'held immutable pointer policy epoch')
    finally:os.close(fd)
    policy=ci9_json(raw);need(policy['kind']=='ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1',
                            'current normal pointer operation authority')
    root=Path(context['operation_root']);need(root.parent==Path(policy['operationRoot'])and
         root.name.endswith('-'+context['identity']['operation_nonce'])and
         root.is_absolute()and root.resolve()==root,'same typed normal pointer evidence root')
    own=root.lstat();need(stat.S_ISDIR(own.st_mode)and own.st_uid==os.getuid()and
                         stat.S_IMODE(own.st_mode)==0o700,'private normal pointer root')
    need(policy['programSHA256']['connection_control.py']==context['sender_source_sha256'],
         'Root selected current normal sender bytes')
    return root


def ci9_json(raw):
 def unique(pairs):
  result={}
  for key,value in pairs:
   if key in result:raise ValueError('Duplicate pointer JSON field')
   result[key]=value
  return result
 def invalid(value):raise ValueError('Nonfinite pointer JSON')
 return json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)

def ci9_read(path,expected=None,cap=16777216):
 path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
 try:
  before=os.fstat(fd);assert stat.S_ISREG(before.st_mode)and before.st_uid==os.getuid()and before.st_nlink==1 and before.st_size<=cap
  raw=bytearray()
  while True:
   block=os.read(fd,min(65536,cap+1-len(raw)))
   if not block:break
   raw.extend(block);assert len(raw)<=cap
  assert len(raw)==before.st_size and tuple(getattr(before,k)for k in fields)==tuple(getattr(os.fstat(fd),k)for k in fields)==tuple(getattr(path.lstat(),k)for k in fields)
  assert expected is None or hashlib.sha256(raw).hexdigest()==expected
  return bytes(raw)
 finally:os.close(fd)

def ci10_sig(value):return {key:getattr(value,key)for key in CI10_FIELDS}

def ci10_error(error,phase):return {'type':type(error).__name__,'phase':phase}

def ci10_inputs(value):
 result=[]
 if isinstance(value,dict):
  for key,item in value.items():
   if key not in CI10_OUTPUTS and isinstance(item,str)and(key=='path'or key.endswith('_path')):result.append(item)
   elif key not in CI10_OUTPUTS:result.extend(ci10_inputs(item))
 elif isinstance(value,list):
  for item in value:result.extend(ci10_inputs(item))
 return result

def ci10_reserve_paths(paths,root,inputs=()):
 root=Path(root);assert root.is_absolute()and root.resolve()==root
 targets=[Path(value[0])for value in paths.values()]
 assert len(set(targets))==len(targets)
 forbidden={str(Path(x).absolute())for x in inputs}
 records={}
 # Validate the WHOLE set before creating or effecting anything.
 for key,(name,cap)in paths.items():
  target=Path(name);assert target.is_absolute()and target.is_relative_to(root)and target.parent.resolve()==target.parent
  assert str(target)not in forbidden and not os.path.lexists(target)and type(cap)is int and cap>0
  parent=target.parent
  while True:
   info=parent.lstat();assert stat.S_ISDIR(info.st_mode)and info.st_uid==os.getuid()and not info.st_mode&0o077
   if parent==root:break
   assert parent.is_relative_to(root);parent=parent.parent
 required={}
 for name,cap in paths.values():
  volume=os.stat(Path(name).parent).st_dev;required[volume]=required.get(volume,0)+cap
 for name,_ in paths.values():
  volume=os.stat(Path(name).parent).st_dev;space=os.statvfs(Path(name).parent)
  assert space.f_bavail*space.f_frsize>=required[volume]and(space.f_favail==0 or space.f_favail>=len(paths))
 try:
  for key,(name,cap)in paths.items():
   fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
   record={'fd':fd,'path':str(name),'cap':cap,'confirmed_bytes':0};records[key]=record
   # Reserve actual blocks before input; no optimistic free-space-only promise.
   os.posix_fallocate(fd,0,cap)
   before=os.fstat(fd);assert stat.S_ISREG(before.st_mode)and before.st_uid==os.getuid()and before.st_nlink==1 and not before.st_mode&0o077
   assert ci10_sig(before)==ci10_sig(Path(name).lstat());record['created_identity']=ci10_sig(before)
  return records
 except BaseException:
  ci10_close_outputs(records);raise

def ci10_reserve(context,inputs=(),stdout_cap=1048576):
 assert all(key in context for key in CI10_OUTPUTS)
 assert all(isinstance(context.get(key),str)and context[key]for key in('action_id','sender_lifecycle_ref','sender_stdout_ref','sender_stderr_ref'))
 assert len({context[key]for key in('sender_lifecycle_ref','sender_stdout_ref','sender_stderr_ref')})==3
 caps=dict(CI10_OUTPUTS,sender_stdout_path=stdout_cap)
 return ci10_reserve_paths({key:(context[key],cap)for key,cap in caps.items()},ci10_root(context),tuple(inputs)+tuple(ci10_inputs(context))+(__file__,))

def ci10_check_outputs(context,records):
 assert set(records)==set(CI10_OUTPUTS)
 assert len({record['path']for record in records.values()})==4
 for key,record in records.items():
  assert record['path']==context[key]
  info=os.fstat(record['fd']);actual=ci10_sig(info);created=record['created_identity']
  assert stat.S_ISREG(info.st_mode)and info.st_uid==os.getuid()and info.st_nlink==1 and not info.st_mode&0o077
  assert all(actual[k]==created[k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink'))
  assert actual==ci10_sig(Path(record['path']).lstat())
 return records

def ci10_pending(records,context):
 ci10_checkpoint(records,{'schema':1,'kind':'OPEMOS_NATIVE_POINTER_ACTION','action_id':context['action_id'],'status':'pending','effect':'NOT_ATTEMPTED','phases':[]})

def ci10_append(record,raw):
 assert record['confirmed_bytes']+len(raw)<=record['cap']
 view=memoryview(raw)
 while view:
  n=os.pwrite(record['fd'],view,record['confirmed_bytes']);assert n>0
  record['confirmed_bytes']+=n;view=view[n:]

def ci10_finish(record,raw=None,kind='pointer-action'):
 if raw is not None:
  record['confirmed_bytes']=0;ci10_append(record,raw)
 os.ftruncate(record['fd'],record['confirmed_bytes']);os.fsync(record['fd'])
 before=os.fstat(record['fd']);assert ci10_sig(before)==ci10_sig(Path(record['path']).lstat())
 readback=bytearray();offset=0
 while block:=os.pread(record['fd'],min(65536,record['confirmed_bytes']+1-offset),offset):readback.extend(block);offset+=len(block)
 assert len(readback)==record['confirmed_bytes']and ci10_sig(before)==ci10_sig(os.fstat(record['fd']))==ci10_sig(Path(record['path']).lstat())
 return {'path':record['path'],'size':len(readback),'sha256':hashlib.sha256(readback).hexdigest(),'kind':kind,'identity':ci10_sig(before),'custody':'verified-prefix','full9_unchanged':True}

def ci10_json_finish(record,value,kind):return ci10_finish(record,(json.dumps(value,sort_keys=True,allow_nan=False)+'\n').encode(),kind)

def ci10_close_outputs(records):
 errors=[]
 for key,record in records.items():
  try:os.close(record['fd'])
  except OSError as error:errors.append(ci10_error(error,'close-output:'+key))
 return errors

def ci10_destination(context,actual):
 admission=ci9_json(ci9_read(context['destination_admission_path'],context['destination_admission_sha256'],1048576))
 assert admission['schema']==1 and admission['kind']=='OPEMOS_ADMITTED_POINTER_DESTINATION'
 assert admission['identity']==context['identity']and admission['session']==context['session']and admission['clock']==context['clock']
 assert admission['qmp']==actual and admission['admitted']is True
 assert set(actual)=={'qmp_name','qemu_process','host_boot_id','socket_path','socket_identity','peer','disk','argv_sha256'}
 assert actual['qmp_name']and Path(actual['socket_path']).is_absolute()and Path(actual['disk']['path']).is_absolute()and actual['disk']['read_only']is False
 assert stat.S_ISSOCK(actual['socket_identity']['st_mode'])and actual['socket_identity']['st_uid']==os.getuid()
 assert len(actual['argv_sha256'])==64
 assert admission['app']=={key:context['app'][key]for key in('process','executable_sha256','root_window_id')}
 assert actual['host_boot_id']==context['clock']['id']and actual['peer']=={'pid':actual['qemu_process']['pid'],'uid':os.getuid(),'gid':os.getgid()}
 assert context['identity']['runtime_instance_id']==context['session']['runtime_instance_id']and context['session']['boot_id']
 capture=ci9_json(ci9_read(context['before_capture_path'],context['before_capture_sha256'],1048576))
 assert capture['capture_id']==context['before']['capture_id']and capture['frame_ref']==context['before']['ref']and capture['frame_sha256']==context['before_sha256']
 assert capture['session']==context['session']and capture['clock']==context['before']['clock']and capture['tick']==context['before']['tick']and capture['acquired']is True
 return {'observed':actual,'admission_ref':context['destination_admission_ref'],'admission_sha256':context['destination_admission_sha256']}

def ci10_run_child(argv,records,*,input_data=None,seconds=60,pass_fds=()):
 # One absolute finite budget includes identity read, IO, stop, wait and closure.
 import selectors,signal,subprocess,time
 deadline=time.monotonic()+seconds;work_deadline=deadline-5
 life={'numeric_exit':None,'waited':False,'stdout_EOF':False,'stderr_EOF':False,'pipes_closed':False,'original_gone':'UNKNOWN','child_identity':'UNKNOWN','first_failure':None,'secondary_errors':[]}
 life['stream_read_bytes']={'stdout':0,'stderr':0}
 buffers={'stdout':bytearray(),'stderr':bytearray()};child=None;pidfd=None;selector=selectors.DefaultSelector();written=0
 def fail(error,phase):
  value=ci10_error(error,phase)
  if life['first_failure']is None:life['first_failure']=value
  else:life['secondary_errors'].append(value)
 try:
  child=subprocess.Popen(argv,stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=pass_fds)
  life['pid']=child.pid
  if hasattr(os,'pidfd_open'):pidfd=os.pidfd_open(child.pid)
  raw=(Path('/proc')/str(child.pid)/'stat').read_text();start=int(raw[raw.rfind(')')+2:].split()[19]);life['child_identity']={'pid':child.pid,'start':start}
  for label,stream in [('stdout',child.stdout),('stderr',child.stderr)]:
   os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,label)
  if input_data is not None:
   os.set_blocking(child.stdin.fileno(),False);selector.register(child.stdin,selectors.EVENT_WRITE,'stdin')
  while selector.get_map():
   remaining=work_deadline-time.monotonic()
   if remaining<=0:raise subprocess.TimeoutExpired('owned-pointer-transport',seconds-5)
   for key,_ in selector.select(min(remaining,.1)):
    label=key.data
    if label=='stdin':
     if written<len(input_data):
      try:written+=os.write(key.fd,input_data[written:written+65536])
      except BlockingIOError:continue
     if written==len(input_data):selector.unregister(key.fileobj);key.fileobj.close()
    else:
     try:block=os.read(key.fd,65536)
     except BlockingIOError:continue
     if not block:
      life[label+'_EOF']=True;selector.unregister(key.fileobj);key.fileobj.close();continue
     life['stream_read_bytes'][label]+=len(block)
     record=records['sender_'+label+'_path']
     if len(buffers[label])+len(block)>record['cap']:raise ValueError('bounded actual child stream overflow')
     buffers[label].extend(block);ci10_append(record,block)
  child.wait(timeout=max(.001,work_deadline-time.monotonic()));life['waited']=True
 except BaseException as error:fail(error,'child-lifecycle')
 finally:
  if child is not None:
   if child.poll()is None:
    try:
     if pidfd is not None and hasattr(signal,'pidfd_send_signal'):signal.pidfd_send_signal(pidfd,signal.SIGKILL)
     else:
      assert isinstance(life['child_identity'],dict)
      raw=(Path('/proc')/str(child.pid)/'stat').read_text();assert int(raw[raw.rfind(')')+2:].split()[19])==life['child_identity']['start'];child.kill()
     life['exact_original_stop_requested']=True
    except BaseException as error:fail(error,'exact-child-stop')
   try:child.wait(timeout=max(.001,deadline-time.monotonic()));life['waited']=True
   except BaseException as error:fail(error,'exact-child-wait')
   life['numeric_exit']=child.returncode
   if life['waited']and type(child.returncode)is int:life['original_gone']=True
   if type(child.returncode)is int and child.returncode!=0:
    life['sender_failure']={'numeric_exit':child.returncode,'raw_diagnostics':'retained stdout/stderr; not replaced by generic assertion'}
    if life['first_failure']is None:life['first_failure']={'type':'ChildNonzero','numeric_exit':child.returncode,'phase':'child-wait'}
   # Drain only immediately available bytes within the SAME deadline; never an
   # unbounded communicate/join after killing the exact root.
   for label,stream in [('stdout',child.stdout),('stderr',child.stderr)]:
    if stream is None or stream.closed:continue
    try:
     os.set_blocking(stream.fileno(),False)
     while time.monotonic()<deadline:
      try:block=os.read(stream.fileno(),65536)
      except BlockingIOError:break
      if not block:life[label+'_EOF']=True;break
      life['stream_read_bytes'][label]+=len(block)
      record=records['sender_'+label+'_path'];assert len(buffers[label])+len(block)<=record['cap']
      buffers[label].extend(block);ci10_append(record,block)
    except BaseException as error:fail(error,'drain:'+label)
   streams=[x for x in(child.stdin,child.stdout,child.stderr)if hasattr(x,'close')]
   for stream in streams:
    try:stream.close()
    except BaseException as error:fail(error,'close-pipe')
   life['pipes_closed']=all(x.closed for x in streams)
  try:selector.close()
  except BaseException as error:fail(error,'close-selector')
  if pidfd is not None:
   try:os.close(pidfd)
   except BaseException as error:fail(error,'close-pidfd')
  life['raw']={}
  for label in('stdout','stderr'):
   try:life['raw'][label]=ci10_finish(records['sender_'+label+'_path'],kind='pointer-sender-'+label)
   except BaseException as error:
    fail(error,'persist-raw:'+label);life['raw'][label]={'custody':'UNKNOWN','confirmed_prefix_bytes':records['sender_'+label+'_path']['confirmed_bytes'],'path':records['sender_'+label+'_path']['path']}
  life['raw_complete']={label:life[label+'_EOF']and life['stream_read_bytes'][label]==records['sender_'+label+'_path']['confirmed_bytes']for label in('stdout','stderr')}
  life['stdin_bytes_confirmed']=written;life['deadline_expired']=time.monotonic()>deadline
  if life['deadline_expired']:fail(subprocess.TimeoutExpired('owned-pointer-lifecycle',seconds),'absolute-deadline')
 return life,bytes(buffers['stdout']),bytes(buffers['stderr'])

def ci10_checkpoint(records,action):
 record=records['action_result_path'];raw=(json.dumps(action,sort_keys=True,allow_nan=False)+'\n').encode();assert len(raw)<=record['cap']
 # Whitespace padding preserves the preallocated quota AND valid pending JSON.
 record['confirmed_bytes']=0;ci10_append(record,raw+b' '*(record['cap']-len(raw)));os.fsync(record['fd'])

def ci10_begin_phase(action,records,request,sent):
 row={'phase':('move','down','up')[len(action['phases'])],'clock':action['clock'],'sent_tick':sent,'returned_tick':None,'request':request,'response':{'UNKNOWN':True},'delivery':'UNKNOWN','write_state':'NOT_RETURNED'}
 action['phases'].append(row);action['effect']='ATTEMPT_PREFIX_RETAINED_DELIVERY_UNKNOWN';ci10_checkpoint(records,action)
 return row

def ci10_phase_reply(row,response):
 row.update(response=response,returned_tick=time.monotonic_ns(),delivery='MATCHED_REPLY')

def ci9_prepare(context,x,y,source_sha,actual_destination,records):
 ci10_check_outputs(context,records)
 destination=ci10_destination(context,actual_destination)
 actions=('chooser-open','chooser-confirm-exact-input','Build','virtualUSB-select-and-review','virtualUSB-Write-confirmation')
 assert context['action']in actions and context['sequence']==actions.index(context['action'])+1
 assert len(source_sha)==64 and len(context['action_id'])==32
 boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 assert context['clock']=={'domain':'monotonic-ns','id':boot}
 display=context['session']['display'];rect=context['target']['rect'];app=context['app']
 assert app['process']==context['target']['app_process']and app['window_id']==context['target']['window_id']
 assert context['target']['visible']is True and context['target']['enabled']is True
 assert rect['x']<=x<rect['x']+rect['width']and rect['y']<=y<rect['y']+rect['height']
 assert context['point']=={'x':x,'y':y}and 0<=x<display['width']and 0<=y<display['height']
 # Context metadata is a reference, not a substitute for actual captured bytes.
 raw=ci9_read(context['before_path'],context['before_sha256'])
 assert raw[:8]==b'\x89PNG\r\n\x1a\n'
 import struct
 assert struct.unpack('>II',raw[16:24])==(display['width'],display['height'])
 observed=ci9_json(ci9_read(context['target_observation_path'],context['target_observation_sha256'],1048576))
 assert observed['app']==app and observed['target']==context['target']and observed['identity']==context['identity']and observed['session']==context['session']
 assert observed['app_birth_rechecked']is True and observed['before_frame_ref']==context['before']['ref']
 assert observed['capture_id']==context['before']['capture_id']and observed['delivery_clock']==context['clock']
 assert context['before']['tick']<=observed['delivered_tick']<=time.monotonic_ns()
 assert context['before']['clock']==context['clock']and context['before']['tick']<=time.monotonic_ns()
 process=Path('/proc')/str(os.getpid());raw=(process/'stat').read_text();start=int(raw[raw.rfind(')')+2:].split()[19])
 action={k:context[k]for k in('action','action_id','sequence','identity','session','app','target','point','clock','before','transition_ref','sender_lifecycle_ref','target_observation_ref')}
 action['source_context']=context
 action['actual_destination']=destination
 action['output_reservations']={key:{name:record[name]for name in('path','cap','created_identity')}for key,record in records.items()}
 action.update(schema=1,kind='OPEMOS_NATIVE_POINTER_ACTION',backend='QMP',button='left',click_count=1,sender={'source_sha256':source_sha,'process':{'pid':os.getpid(),'start':start},'host_boot_id':boot},phases=[],status='pending')
 return action

def transact(operation):
    """One actual Robot mouse action in the already admitted normal VM."""
    need(os.getuid()==os.geteuid()==1000 and operation['kind']=='mouse',
         'ordinary normal queued mouse sender only')
    context=operation['pointerContext'];root=ci10_root(context);binding=operation['binding']
    need(Path(binding['run_directory'])==root and binding['nonce']==context['identity']['operation_nonce']
         and binding['artifact_source']==context['identity']['source_commit'],
         'actual current queue VM/source/nonce')
    proc=process(binding);need((proc/'status').read_text().split('Uid:',1)[1].splitlines()[0].split()==['1000']*4,
                               'uniform ordinary QEMU identity')
    need(operation['sender_source_sha256']==context['sender_source_sha256'], 'exact admitted sender')
    end=operation['deadline_monotonic'];need(type(end)in(int,float)and 0<end-time.monotonic()<=7200,
                                           'original normal operation finite clock')
    records=globals().get('CI10_RESERVATIONS');need(records is not None,'actual pre-effect reserved sender outputs')
    q=None;stream=None;action=None;first=None;n=0
    try:
        path=Path(binding['qmp_socket']);socket_before=path.lstat()
        q=connect_owned(str(path),binding['pid'],min(15,end-time.monotonic()))
        stream=q.makefile('rwb',buffering=0)
        def receive():
            remaining=end-time.monotonic();need(remaining>0,'original pointer deadline')
            q.settimeout(min(15,remaining));raw=stream.readline(1048577)
            need(raw and len(raw)<=1048576,'bounded actual QMP reply');return ci9_json(raw)
        def call(command,args=None):
            nonlocal n
            process(binding);need(time.monotonic()<end,'original deadline before QMP event')
            n+=1;packet={'execute':command,'id':n}
            if args is not None:packet['arguments']=args
            sent=time.monotonic_ns();row=ci10_begin_phase(action,records,packet,sent)if action is not None else None
            try:
                remaining=end-time.monotonic();need(remaining>0,'original deadline before QMP write')
                q.settimeout(min(15,remaining));wire=(json.dumps(packet)+'\r\n').encode();written=stream.write(wire)
                if row is not None:row.update(write_state='WRITE_RETURNED',bytes_written=written)
                need(written==len(wire),'complete actual QMP write')
                while True:
                    reply=receive()
                    if reply.get('id')==n:
                        if row is not None:ci10_phase_reply(row,reply)
                        need(time.monotonic()<end and reply.get('return')is not None and 'error'not in reply,
                             'actual successful finite matching QMP reply')
                        return reply['return']
            except BaseException as error:
                if row is not None:row['transport_failure']=ci10_error(error,'actual-qmp-exchange');ci10_checkpoint(records,action)
                raise
        need('QMP'in receive(),'actual QMP greeting');call('qmp_capabilities')
        need(call('query-name')['name']==binding['vm_name']and call('query-status')['status']=='running',
             'same actual running admitted Ubuntu VM')
        blocks=call('query-block');disks=[v for v in blocks if v.get('device')=='osdisk']
        need(len(disks)==1 and disks[0]['inserted']['file']==str(root/'desktop-overlay.qcow2')
             and disks[0]['inserted']['ro']is False,'current owned disposable guest disk')
        actual={'qmp_name':binding['vm_name'],'qemu_process':{'pid':binding['pid'],'start':int(binding['start_ticks'])},
                'host_boot_id':binding['host_boot_id'],'socket_path':str(path),'socket_identity':ci10_sig(socket_before),
                'peer':{'pid':binding['pid'],'uid':os.getuid(),'gid':os.getgid()},
                'disk':{'path':disks[0]['inserted']['file'],'read_only':False},
                'argv_sha256':hashlib.sha256((proc/'cmdline').read_bytes()).hexdigest()}
        need(ci10_sig(socket_before)==ci10_sig(path.lstat()),'same owned QMP socket epoch')
        x,y=context['point']['x'],context['point']['y'];display=context['session']['display']
        action=ci9_prepare(context,x,y,operation['sender_source_sha256'],actual,records)
        ci10_checkpoint(records,action)
        events=[[{'type':'abs','data':{'axis':'x','value':round(x*32767/(display['width']-1))}},
                 {'type':'abs','data':{'axis':'y','value':round(y*32767/(display['height']-1))}}],
                [{'type':'btn','data':{'button':'left','down':True}}],
                [{'type':'btn','data':{'button':'left','down':False}}]]
        for event in events:call('input-send-event',{'events':event})
        action['status']='sent';return action
    except BaseException as error:
        first=error
        if action is not None:action['status']='failed';action['first_failure']=ci10_error(error,'actual-pointer')
        raise
    finally:
        secondary=[]
        if action is not None:
            try:ci10_json_finish(records['action_result_path'],action,'pointer-action')
            except BaseException as error:secondary.append(ci10_error(error,'persist-action'))
        for resource in(stream,q):
            if resource is not None:
                try:resource.close()
                except BaseException as error:secondary.append(ci10_error(error,'close-qmp'))
        if secondary:
            os.write(2,(json.dumps({'secondary_errors':secondary})+'\n').encode())
            if first is None:raise ValueError('Actual pointer output/socket closure failed')


class Pipeline:
    """Actual native observations and QMP input in the same owned Ubuntu VM."""
    def __init__(self,binding,config,q,observer,ready,root):
        self.binding=binding;self.cfg=config;self.q=q;self.observer=observer;self.ready=ready
        self.root=root;self.sequence=0;self.actions=[];self.observations=[];self.observation_bytes=0
        self.end=time.monotonic()+config['whole_seconds'];self.app=ready['app'];self.check=lambda:None
        need(binding['nonce']==config['nonce']==ready['nonce'] and
             binding['artifact_source']==config['source_commit'] and
             binding['package_sha256']==config['package_sha256'] and
             ready['process']['pid']==self.app['pid'] and
             ready['process']['inherited_nonce']==binding['nonce']and
             ready['process'].get('exe_sha256')==config['native_executable_sha256'],
             'same admitted candidate/app birth/normal operation')

    def request(self,kind,**operands):
        self.check()
        remaining=self.end-time.monotonic();need(remaining>0 and self.sequence<256,'original GUI operation clock/request bound')
        process(self.binding);self.sequence+=1;self.observer.settimeout(remaining)
        request={'nonce':self.binding['nonce'],'sequence':self.sequence,'kind':kind,**operands}
        self.observer.sendall((json.dumps(request,separators=(',',':'))+'\n').encode())
        response=observer_line(self.observer,1048576)
        need(time.monotonic()<self.end and response.get('kind')=='NATIVE_OBSERVATION' and
             response.get('nonce')==request['nonce'] and response.get('sequence')==self.sequence and
             response.get('request_kind')==kind and response.get('process')==self.ready['process'],
             'ordered same native app observation within original clock')
        self.observations.append(response)
        self.observation_bytes+=len(json.dumps(response,separators=(',',':')).encode())
        need(self.observation_bytes<=32*1024*1024,'complete bounded native observation history; first crossing retained')
        return response

    def windows(self):return self.request('WINDOWS')['value']['windows']

    def target(self,label,roles,window=None):
        window=self.app if window is None else window
        while True:
            response=self.request('CONTROL',window_id=window['window_id'],label=label,roles=roles,probe=True)
            if response['value'].get('available')is not False:return response
            remaining=self.end-time.monotonic();need(remaining>0,'native control did not become available')
            time.sleep(min(2,remaining))

    def click(self,name,label,roles=('push button',),window=None):
        target=self.target(label,list(roles),window);control=target['value'];point=control['point']
        native=self.app if window is None else window
        need(control['pid']==native['pid']and control['window_id']==native['window_id']and
             control['enabled']is True and control['visible']is True and control['readOnlyObservation']is True,
             'current genuine native control process/window/state')
        before=frame(self.q,self.root/(str(len(self.actions)).zfill(3)+'-'+name+'-before.png'))
        self.check();process(self.binding);need(time.monotonic()<self.end,'original deadline before actual pointer')
        rect=control['rect'];need(rect[0]<=point['x']<rect[0]+rect[2]<=before['width']and
            rect[1]<=point['y']<rect[1]+rect[3]<=before['height'],'actual native target and observed display point')
        record={'action':name,'nativeControl':target,'beforeFrame':before,'actualQMPInput':[],
                'point':point,'sameGuestPID':self.ready['process']}
        self.actions.append(record)
        pointer(self.q,point['x'],point['y'],before['width'],before['height'],record['actualQMPInput'],self.end)
        return record

    def key(self,qcode,modifiers=()):
        need(qcode in ('a','l','ret','tab')or re.fullmatch('[a-z0-9]|spc|dot|minus|slash|underscore',qcode),
             'bounded QMP text key')
        need(set(modifiers)<={'ctrl','shift'},'only declared location/text modifiers')
        process(self.binding)
        record={'kind':'keyboard','qcode':qcode,'modifiers':list(modifiers),'actualQMPInput':[]}
        self.actions.append(record)
        def send(code,down):
            bounded_input(self.q,{'events':[{'type':'key','data':{'down':down,
                'key':{'type':'qcode','data':code}}}]},record['actualQMPInput'],self.end)
        for code in modifiers:send(code,True)
        for down in(True,False):send(qcode,down)
        for code in reversed(modifiers):send(code,False)

    def text(self,value):
        need(type(value)is str and 0<len(value)<=512 and re.fullmatch('[A-Za-z0-9 /_.-]+',value),
             'declared ASCII image/folder/confirmation only')
        self.key('a',('ctrl',))
        for character in value:
            code={' ':'spc','.':'dot','-':'minus','/':'slash','_':'minus'}.get(character,character.lower())
            self.key(code,('shift',)if character.isupper()or character=='_'else())

    def choose(self,action,button,path,confirm):
        self.click(action,button)
        while True:
            dialogs=[w for w in self.windows()if w['window_id']!=self.app['window_id']and
                (w['transient_for']==self.app['window_id']or w['pid']==self.app['pid'])and w['dialog_type']]
            if dialogs:break
            remaining=self.end-time.monotonic();need(remaining>0,'native chooser absent');time.sleep(min(.5,remaining))
        need(len(dialogs)==1,'one actual same-app native chooser')
        self.key('l',('ctrl',));self.text(path)
        self.click(action+'-confirm',confirm,window=dialogs[0])

    def names(self):return self.request('NAMES',window_id=self.app['window_id'])['value']['names']

    def wait_text(self,text):
        while True:
            names=self.names()
            if text in names:return names
            errors=[name for name in names if name.startswith(('Build failed','USB write failed','Error:'))]
            need(not errors,'actual application failure: '+repr(errors))
            remaining=self.end-time.monotonic();need(remaining>0,'actual application completion absent');time.sleep(min(30,remaining))

    def build_write(self):
        labels=self.cfg['labels']
        self.choose('chooser-open',labels['choose_input'],self.cfg['input_path'],labels['open'])
        self.choose('choose-output-directory',labels['choose_output'],self.cfg['output_directory'],labels['select_folder'])
        input_image=self.request('FILE',role='input_path')
        need(input_image['value']['sha256']==self.cfg['input_sha256'],'actual selected original image hash')
        self.click('Build',labels['build'])
        self.wait_text(labels['build_success'])
        output=self.request('FILE',role='output_path')
        usb=self.request('USB')['value']
        need(usb['serial']=='opemos-'+self.binding['nonce']and usb['bytes']==self.cfg['usb_bytes'],
             'actual same-guest emulated USB identity')
        self.click('virtualUSB-select',labels['usb_target'],('combo box','list item'))
        choices=[name for name in self.names()if ' · '+usb['path']+' · 'in name]
        need(len(choices)==1,'one native device option for the actually observed emulated USB')
        self.click('virtualUSB-device',choices[0],('list item','menu item','text'))
        self.click('virtualUSB-select-and-review',labels['review'])
        self.click('virtualUSB-confirmation-entry',labels['confirmation'],('entry',))
        self.text('ERASE')
        self.click('virtualUSB-Write-confirmation',labels['write'])
        self.wait_text(labels['write_success'])
        repeated=self.request('FILE',role='output_path')
        need(repeated['value']==output['value'],'actual built image unchanged through GUI write/readback')
        after=frame(self.q,self.root/'gui-write-complete.png')
        self.request('CLOSE')
        return {'kind':'ACTUAL_UBUNTU_GUI_BUILD_WRITE_OBSERVATIONS','nonce':self.binding['nonce'],
            'source_commit':self.cfg['source_commit'],'package_sha256':self.cfg['package_sha256'],
            'input':input_image,'output':output,'usb':usb,'actions':self.actions,
            'nativeObservations':self.observations,'afterFrame':after,
            'hostReadbackOrSteamOSAcceptance':False}


def pipeline_main(binding_path):
    b=json.loads(held(binding_path,1048576));process(b)
    ref=b['pipelineConfigPin'];raw=held(ref['path'],65536)
    need(hashlib.sha256(raw).hexdigest()==ref['sha256'],'same normal planner pipeline config')
    cfg=json.loads(raw);need(cfg['kind']=='ROOT_ADMITTED_UBUNTU_GUI_BUILD_WRITE_V1' and
        type(cfg['whole_seconds'])is int and 0<cfg['whole_seconds']<=7200 and
        cfg['display']==[1280,800] and re.fullmatch('[0-9a-f]{40}',cfg['source_commit']),
        'finite source-bound normal GUI pipeline')
    root=Path(b['run_directory']);need(root.is_absolute()and root.resolve()==root and
        root.stat().st_uid==os.getuid()and stat.S_IMODE(root.stat().st_mode)==0o700,
        'same owned normal VM directory')
    q=QMP(connect_owned(b['qmp_socket'],b['pid']));obs=connect_owned(b['observer_socket'],b['pid'],200)
    result={'kind':'ACTUAL_UBUNTU_GUI_BUILD_WRITE_OBSERVATIONS','first':None,'accepted':False}
    try:
        need(q.call('query-name')['name']==b['vm_name']and q.call('query-status')['status']=='running','same actual live VM')
        ready=next_native_event(obs,b['nonce'],result)
        need(ready['kind']=='READY'and ready['port_custody']['held_node_stable']is True,'actual native observer READY/custody')
        operation=Pipeline(b,cfg,q,obs,ready,root)
        result=operation.build_write()
    except BaseException as error:
        result['first']={'type':type(error).__name__,'reason':str(error)}
        if 'operation'in locals():result.update(actions=operation.actions,nativeObservations=operation.observations)
        try:result['failureFrame']=frame(q,root/'pipeline-first-failure.png')
        except BaseException as secondary:result['frameFailure']=str(secondary)
        raise
    finally:
        try:obs.close()
        finally:q.close()
        save(root/'gui-build-write-result.json',result)


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--pipeline':pipeline_main(sys.argv[2])
    else:main()


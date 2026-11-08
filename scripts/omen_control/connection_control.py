#!/usr/bin/env python3
"""Native observations and bounded QMP input in an admitted Ubuntu VM.

The ordinary queue job owns QEMU creation and closure. Diagnostic clicks and
normal GUI Build/write observations retain separate results; neither alone
establishes SteamOS boot, installation or NVIDIA acceptance.
"""
import hashlib
import contextlib
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
    path=Path(path);parent=path.parent
    need(path.is_absolute()and parent.resolve()==parent,
         'canonical private VM socket directory required')
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    s=None
    try:
        directory=os.fstat(fd)
        stable=lambda st:(st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid)
        need(stat.S_ISDIR(directory.st_mode)and directory.st_uid==os.getuid()and
             not directory.st_mode&0o077 and stable(directory)==stable(parent.lstat()),
             'owned private VM socket directory required')
        info=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
        need(stat.S_ISSOCK(info.st_mode)and info.st_uid==os.getuid()and
             not info.st_mode&0o077,'owned private VM socket required')
        # Linux resolves this short address through our held parent FD. Keep
        # the logical operation path in every binding/receipt; never truncate it
        # or reuse another operation's socket to fit sockaddr_un.sun_path.
        address=f'/proc/self/fd/{fd}/{path.name}'
        need(len(os.fsencode(address))<108,'finite Linux Unix socket address')
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(timeout);s.connect(address)
        peer=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        need(peer[0]==pid and peer[1]==os.getuid(),'socket peer is not exact QEMU')
        need(tuple(getattr(info,k)for k in FULL9)==tuple(getattr(os.stat(path.name,dir_fd=fd,follow_symlinks=False),k)for k in FULL9)and
             stable(directory)==stable(os.fstat(fd))==stable(parent.lstat()),
             'VM socket/directory identity changed during connect')
        return s
    except BaseException:
        if s is not None:s.close()
        raise
    finally:os.close(fd)

class QMP:
    def __init__(self,s):
        self.s=s;self.f=s.makefile('rwb',buffering=0);self.n=0
        try:
            need('QMP'in self.read(),'QMP greeting absent');self.call('qmp_capabilities')
        except BaseException:
            self.close();raise
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

@contextlib.contextmanager
def owned_qmp(path,pid,timeout=35):
    """Release the single owned QMP client even if READY/bootstrap refuses."""
    with connect_owned(path,pid,timeout) as channel:
        q=QMP(channel)
        try:yield q
        finally:q.close()

def frame(q,path,display=None):
    need(not os.path.lexists(path),'frame output must be absent')
    q.call('screendump',{'filename':str(path),'format':'png'})
    raw=held(path,16*1024*1024)
    need(raw[:8]==b'\x89PNG\r\n\x1a\n','real PNG frame absent')
    width,height=struct.unpack('>II',raw[16:24])
    need(width>0 and height>0 and (display is None or (width,height)==tuple(display)),
         'actual disposable GUI geometry differs from current guest display')
    return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'width':width,'height':height}

def painted_client(value,window):
    """Inspect this captured frame, excluding the native window's border.

    A mapped but uniformly blank client is not ready for a pointer target.
    Colour variation is only a readiness prerequisite, never target authority.
    Use the installed libpng decoder already required by the QEMU host.
    """
    import ctypes as c
    class Image(c.Structure):
        _fields_=[('opaque',c.c_void_p)]+[(name,c.c_uint32)for name in
            ('version','width','height','format','flags','colormap_entries','warning_or_error')]+[
            ('message',c.c_char*64)]
    width,height=value['width'],value['height']
    need(width*height<=4*1024*1024,'bounded actual frame decode')
    rect=window['rect'];need(len(rect)==4 and all(type(n)is int for n in rect),'native client rectangle')
    x,y,w,h=rect
    need(0<=x<x+w<=width and 0<=y<y+h<=height and w>4 and h>4,'native client inside actual frame')
    raw=held(value['path'],16*1024*1024)
    need(len(raw)==value['bytes']and hashlib.sha256(raw).hexdigest()==value['sha256'],
         'same captured PNG for paint observation')
    lib=c.CDLL('libpng16.so.16')
    lib.png_image_begin_read_from_memory.argtypes=[c.POINTER(Image),c.c_void_p,c.c_size_t]
    lib.png_image_begin_read_from_memory.restype=c.c_int
    lib.png_image_finish_read.argtypes=[c.POINTER(Image),c.c_void_p,c.c_void_p,c.c_int32,c.c_void_p]
    lib.png_image_finish_read.restype=c.c_int
    lib.png_image_free.argtypes=[c.POINTER(Image)];lib.png_image_free.restype=None
    image=Image();image.version=1;source=c.create_string_buffer(raw)
    try:
        need(lib.png_image_begin_read_from_memory(c.byref(image),source,len(raw))==1,
             'decode actual PNG header')
        need((image.width,image.height)==(width,height),'same decoded PNG geometry')
        image.format=3 # libpng simplified API: 8-bit RGBA
        pixels=c.create_string_buffer(width*height*4)
        need(lib.png_image_finish_read(c.byref(image),None,pixels,0,None)==1,'decode actual PNG pixels')
        data=pixels.raw;left=x+2;right=x+w-2;top=y+2;bottom=y+h-2
        first=data[(top*width+left)*4:(top*width+left)*4+4]
        blank=first*(right-left)
        return any(data[(row*width+left)*4:(row*width+right)*4]!=blank for row in range(top,bottom))
    finally:lib.png_image_free(c.byref(image))

def observer_line(s,cap=65536,end=None):
    b=bytearray()
    while not b.endswith(b'\n'):
        if end is not None:
            remaining=end-time.monotonic()
            need(remaining>0,'original native observer deadline before receive')
            s.settimeout(remaining)
        part=s.recv(1);need(part,'observer channel EOF before native result')
        if end is not None:
            need(time.monotonic()<end,'original native observer deadline after receive')
        b.extend(part);need(len(b)<=cap,'observer line cap exceeded')
    return json.loads(b)

def next_native_event(s,nonce,receipt,end=None):
    row=observer_line(s,end=end)
    if row.get('kind')=='BOOTSTRAP_REFUSED':
        # Retain the bounded original event even when its binding is invalid;
        # this diagnostic field never supplies a successful native result.
        receipt['received_guest_bootstrap_refusal']=row
        need(row.get('nonce')==nonce and
             row.get('phase') in ('verified_package','guest_display',
                                  'guest_prerequisites','native_app_and_observer') and
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
    root=Path(context['operation_root']);need(root.parent.parent==Path(policy['operationRoot'])and
         root.parent.name.endswith('-'+context['identity']['operation_nonce'])and root.name=='runtime'and
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
         and binding['artifact_source']==context['identity']['executable']['source_commit'],
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
        need(len(disks)==1 and disks[0]['inserted']['file']==str(root.parent/'scratch/desktop-overlay.qcow2')
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


def native_control_bound(control,window,birth):
    """Keep the actual provider PID distinct from its native window/app root."""
    pid=control['pid']
    need(type(pid)is int and pid>1,'positive native control provider PID')
    if pid==window['pid']:
        return {'kind':'SAME_NATIVE_WINDOW_PROCESS','pid':pid}
    proof=control.get('nativeProcessOwner',{});chain=proof.get('chain')
    need(window['pid']==birth['pid']and control.get('window_pid')==window['pid']and
         proof.get('kind')=='ACTUAL_NATIVE_PROVIDER_APP_ANCESTRY'and proof.get('pid')==pid and
         proof.get('app_pid')==birth['pid']and proof.get('app_start_ticks')==birth['start_ticks']and
         proof.get('inherited_nonce')==birth['inherited_nonce']and type(proof.get('uid'))is int and proof['uid']>=0 and
         type(chain)is list and 2<=len(chain)<=32,
         'current genuine native control process/window/state: provider not bound to original app/nonce/birth')
    need(all(type(row)is dict and type(row.get('pid'))is int and row['pid']>1 and
             type(row.get('ppid'))is int and row['ppid']>0 and
             type(row.get('start_ticks'))is str and row['start_ticks'].isdigit()and
             int(row['start_ticks'])>=int(birth['start_ticks'])and
             row.get('uids')==[proof['uid']]*4 for row in chain),
         'complete native provider process birth and uniform UID evidence')
    need(chain[0]['pid']==pid and chain[-1]['pid']==birth['pid']and
         chain[-1]['start_ticks']==birth['start_ticks']and
         len({row['pid']for row in chain})==len(chain)and
         all(row['ppid']==parent['pid']for row,parent in zip(chain,chain[1:])),
         'complete ordered native provider ancestry to original app')
    return proof


ROBOT_RUNTIME_ROOT=Path('/home/connor/.local/share/opemos-ci/github-runner/robot-python')

def fixed_robot_bootstrap(context,entry,entry_sha,cache_prefix):
    """Select only the existing lease-authenticated RF runtime under Python -I."""
    ci10_root(context)  # Same Root policy/sender/operation ancestry as the pointer.
    def read(path,uid,digest=None):
        path=Path(path)
        for parent in path.parents:
            s=parent.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid in(0,os.getuid())
                and not s.st_mode&0o022,'fixed Robot runtime ancestry')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            s=os.fstat(fd);before=ci10_sig(s);raw=b''
            need(stat.S_ISREG(s.st_mode)and s.st_uid==uid and s.st_nlink==1 and
                 not s.st_mode&0o022 and s.st_size<=8388608,'fixed Robot runtime file custody')
            while part:=os.read(fd,65536):raw+=part;need(len(raw)<=8388608,'bounded Robot runtime member')
            need(before==ci10_sig(os.fstat(fd))==ci10_sig(path.lstat())and len(raw)==s.st_size
                 and(digest is None or hashlib.sha256(raw).hexdigest()==digest),'fixed Robot runtime file epoch/hash')
            return raw
        finally:os.close(fd)
    policy_ref=context['normal_policy_pin'];policy_path=Path(policy_ref['path'])
    lease=ci9_json(read(policy_path.parent/'lease.json',0))
    need(lease['kind']=='OPEMOS_ROBOT_FIXED_CONTROL_LEASE'and
         lease['engine_source_commit']==context['identity']['source_commit']and
         lease['connection_fixed_policy']=={'path':str(policy_path),'sha256':policy_ref['sha256']}and
         lease['engine_pins']['scripts/run_omen_robot_guest.py']==entry_sha,
         'same actual Root lease and selected Robot entry')
    profile=ci9_json(read(lease['profile_path'],0,lease['profile_sha256']))
    need(profile['robotframework']=={'version':'7.5','wheel_sha256':
         '5a194db36524604fafa1da89adebc837db9a95adf15ffd746e09ce98251e6c68'},
         'same official pinned RF7.5 runtime')
    manifest=lease['manifest'];items=ci9_json(read(manifest['path'],os.getuid(),manifest['sha256']))
    need(type(items)is list and len(items)<=100000,'existing bounded Runner program manifest')
    selected={}
    for item in items:
        name=Path(item['path'])
        if not name.parts or name.parts[0]!='robot-python':continue
        need(not name.is_absolute()and '..'not in name.parts and len(name.parts)>1 and
             'symlink'not in item and str(name)not in selected,'fixed Robot manifest member')
        raw=read(ROBOT_RUNTIME_ROOT.parent/name,os.getuid(),item['sha256'])
        need(len(raw)==item['bytes'],'fixed Robot manifest member bytes');selected[str(name)]=item
    need(all('robot-python/'+name in selected for name in
        ('robot/__init__.py','robot/version.py','robotframework-7.5.dist-info/METADATA')),
        'complete selected RF7.5 distribution')
    actual=set()
    for directory,dirs,files in os.walk(ROBOT_RUNTIME_ROOT,followlinks=False):
        # The isolated child uses a fresh, unwritten bytecode prefix, so old
        # ambient caches are not executable inputs.
        dirs[:]=[n for n in dirs if n!='__pycache__']
        for name in dirs:
            s=(Path(directory)/name).lstat();need(stat.S_ISDIR(s.st_mode)and
                s.st_uid==os.getuid()and not s.st_mode&0o022,'fixed Robot runtime directory')
        for name in files:actual.add(str((Path(directory)/name).relative_to(ROBOT_RUNTIME_ROOT.parent)))
        need(len(actual)<=len(selected),'unlisted Robot runtime source')
    need(actual==set(selected)and not os.path.lexists(cache_prefix),'exact Robot source set and fresh bytecode prefix')
    raw=held(entry,1048576);need(hashlib.sha256(raw).hexdigest()==entry_sha,'same held selected Robot entry')
    # No ambient PYTHONPATH/site fallback; execute the verified entry bytes.
    return ('import sys\nsys.pycache_prefix='+repr(str(cache_prefix))+
            '\nsys.path.insert(0,'+repr(str(ROBOT_RUNTIME_ROOT))+')\nsys.argv=sys.argv[1:]\n'+
            '__file__='+repr(str(entry))+'\nexec(compile('+repr(raw)+',__file__,"exec"))\n')


class RobotPipeline:
    """The normal job produces observations; the existing Robot child sends input."""
    ACTIONS=('chooser-open','chooser-confirm-exact-input','Build',
             'virtualUSB-select-and-review','virtualUSB-Write-confirmation')
    TRANSITIONS=dict(zip(ACTIONS,(('main','chooser'),('chooser','input-selected'),
        ('input-selected','build-started'),('output-ready','usb-reviewed'),('usb-reviewed','write-started'))))

    def __init__(self,pipeline,config,engine,owned):
        import threading
        self.p=pipeline;self.cfg=config;self.engine=Path(engine);self.owned=owned
        self.files={};self.actions={};self.reports=[];self.controls={};self.threading=threading
        r=pipeline.ready;b=pipeline.binding;d=config['candidate']['descriptor']
        need(r['guest_uid']==1000 and r['guest_architecture']=='x86_64'and
             re.fullmatch('[0-9a-f-]{36}',r['guest_boot_id'])and r['display_connection'],
             'actual native guest boot/session/architecture')
        self.clock={'domain':'monotonic-ns','id':b['host_boot_id']}
        self.identity={'source_commit':config['source_commit'],'run_id':config['run_id'],
            'attempt':config['attempt'],'operation_nonce':b['nonce'],
            'inventory_vm_id':config['inventory_vm_id'],'runtime_instance_id':b['vm_name'],
            'queue_job_ids':[config['queue_job_id']],'original_source':config['original_source'],
            'executable':d}
        # The normal job keeps GUI geometry in guest_operation, which is the
        # Pipeline config already used for native targets and QMP screenshots.
        width,height=pipeline.cfg['display']
        display={'id':r['display_connection'],'width':width,'height':height,'scale':1,
            'coordinate_width':width,'coordinate_height':height,'origin_x':0,'origin_y':0,
            'coordinate_space':'physical-pixels'}
        self.session={'runtime_instance_id':b['vm_name'],'platform':'linux','architecture':'x86_64',
            'boot_id':r['guest_boot_id'],'id':r['display_connection']+':uid1000','display':display}
        birth=r['process'];self.birth={'pid':birth['pid'],'start':int(birth['start_ticks'])}
        self.sender=Path(config['programRoot'])/'connection_control.py'
        self.sender_sha=config['normalPolicy']['programSHA256']['connection_control.py']
        self.observer_sha=config['normalPolicy']['programSHA256']['observer_guest.py']
        self.destination=None

    def retain(self,ref,path,kind):
        raw=held(path,24*1024*1024);info=Path(path).lstat()
        self.files[ref]={'path':str(path),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'identity':{k:getattr(info,k)for k in FULL9},'kind':kind,'public':True}
        return self.files[ref]

    def put(self,ref,value,kind):
        path=self.p.root/(ref+'.json');save(path,value);return self.retain(ref,path,kind)

    def capture(self,prefix,window=None):
        import uuid
        end=min(self.p.end,time.monotonic()+25);attempt=0;total=0
        while True:
            need(time.monotonic()<end,'original deadline waiting for painted native client')
            suffix=''if attempt==0 else '-paint-'+str(attempt).zfill(3)
            tick=time.monotonic_ns()
            value=frame(self.p.q,self.p.root/(prefix+suffix+'.png'),self.p.cfg['display'])
            total+=value['bytes'];need(total<=16*1024*1024,'bounded retained paint frames')
            painted=window is None or painted_client(value,window)
            need(time.monotonic()<end,'original deadline after actual paint observation')
            if painted:break
            attempt+=1
            time.sleep(min(.2,max(0,end-time.monotonic())))
        ref=prefix+'-png';self.retain(ref,value['path'],'screenshot')
        record={'capture_id':uuid.uuid4().hex,'clock':self.clock,'tick':tick,
            'frame_ref':ref,'frame_sha256':value['sha256'],'session':self.session,'acquired':True}
        self.put(prefix+'-capture',record,'frame-capture')
        return {'capture_id':record['capture_id'],'clock':self.clock,'tick':tick,
                'ref':ref,'capture_ref':prefix+'-capture'}

    def destination_admission(self,app):
        b=self.p.binding;process(b);path=Path(b['qmp_socket']);before=path.lstat()
        need(self.p.q.call('query-name')['name']==b['vm_name']and
             self.p.q.call('query-status')['status']=='running','actual same running QMP destination')
        disks=[x for x in self.p.q.call('query-block')if x.get('device')=='osdisk']
        need(len(disks)==1 and disks[0]['inserted']['file']==self.cfg['runtime_storage']['cowPath']
             and disks[0]['inserted']['ro']is False,'actual writable owned guest destination')
        actual={'qmp_name':b['vm_name'],'qemu_process':{'pid':b['pid'],'start':int(b['start_ticks'])},
            'host_boot_id':b['host_boot_id'],'socket_path':str(path),
            'socket_identity':{k:getattr(before,k)for k in FULL9},
            'peer':{'pid':b['pid'],'uid':os.getuid(),'gid':os.getgid()},
            'disk':{'path':disks[0]['inserted']['file'],'read_only':False},
            'argv_sha256':hashlib.sha256((Path('/proc')/str(b['pid'])/'cmdline').read_bytes()).hexdigest()}
        need(ci10_sig(before)==ci10_sig(path.lstat()),'actual destination socket epoch')
        record={'schema':1,'kind':'OPEMOS_ADMITTED_POINTER_DESTINATION','admitted':True,
            'identity':self.identity,'session':self.session,'clock':self.clock,
            'app':{k:app[k]for k in('process','executable_sha256','root_window_id')},'qmp':actual}
        if self.destination is None:self.destination=self.put('pointer-destination',record,'pointer-destination-admission')
        else:need(json.loads(held(self.destination['path'],1048576))==record,'same original destination for every action')
        return self.destination

    def after_state(self,name,before):
        """Read native state after input; a QMP acknowledgement is insufficient."""
        p=self.p;end=min(p.end,time.monotonic()+25)
        while True:
            raw=p.request('UI_STATE');windows=raw['value']['windows']
            names=[n for w in raw['value']['namesByWindow']for n in w['names']]
            dialogs=[w for w in windows if w['dialog_type']and
                (w['transient_for']==p.app['window_id']or w['pid']==p.app['pid'])]
            labels=p.cfg['labels'];ok=False
            if name=='chooser-open':ok=len(dialogs)==1
            elif name=='chooser-confirm-exact-input':
                ok=not dialogs and any(Path(p.cfg['input_path']).name in n for n in names)
            elif name=='Build':
                ok=any(n in names for n in ('Opening build progress…','Build progress is open in a separate window.',
                    'Preparing builder','Starting builder','Normalizing compressed image','Build Progress is open'))
            elif name=='virtualUSB-select-and-review':
                ok=any('Type ERASE exactly to confirm '+p.selected_usb['path'] in n for n in names)
            elif name=='virtualUSB-Write-confirmation':
                ok=any(n.startswith(('Revalidating the exact image and removable drive.',
                    'USB writing','Writing','Verifying'))for n in names)
            need(not any(n.startswith(('Build failed','USB write failed','Error:'))for n in names),
                 'actual native application failure after '+name)
            if ok:return raw
            need(time.monotonic()<end,'actual action-specific native transition absent: '+name)
            time.sleep(min(.2,end-time.monotonic()))

    def click(self,p,name,label,roles,window):
        import uuid
        need(name==self.ACTIONS[len(self.actions)],'five actual canonical actions in order')
        native=p.app if window is None else window;prefix='robot-'+str(len(self.actions)+1)
        before=self.capture(prefix+'-before',native)
        raw=p.target(label,list(roles),window);control=raw['value']
        ownership=native_control_bound(control,native,p.ready['process'])
        need(control['window_id']==native['window_id']and
             control['visible']is True and control['enabled']is True and
             control['hitObservation']=='native-same-control-unoccluded',
             'fresh native unoccluded same app/window target')
        rect=lambda v:dict(zip(('x','y','width','height'),v))
        app={'process':self.birth,'executable_sha256':p.ready['process']['exe_sha256'],
            'root_window_id':p.app['window_id'],'window_id':native['window_id'],
            'window_title':native['title'],'window_rect':rect(native['rect'])}
        cid=control['nativeAccessibleId']or(control['role']+':'+control['label'])
        target={'control_id':cid,'role':control['role'],'app_process':self.birth,
            'window_id':native['window_id'],'visible':True,'enabled':True,'rect':rect(control['rect']),
            'hit_observation':control['hitObservation'],'native_process_owner':ownership}
        self.controls[name]={'control_id':cid,'role':control['role']}
        destination=self.destination_admission(app)
        observation={'schema':1,'identity':self.identity,'session':self.session,'app':app,'target':target,
            'observer_source_sha256':self.observer_sha,'app_birth_rechecked':True,
            'before_frame_ref':before['ref'],'capture_id':before['capture_id'],'delivery_clock':self.clock,
            'delivered_tick':time.monotonic_ns(),'method':'native-readonly','native_observation':raw}
        ob=self.put(prefix+'-target',observation,'gui-observation')
        context={'action':name,'action_id':uuid.uuid4().hex,'sequence':len(self.actions)+1,
            'identity':self.identity,'session':self.session,'app':app,'target':target,'point':control['point'],
            'clock':self.clock,'before':before,'transition_ref':prefix+'-transition',
            'sender_lifecycle_ref':prefix+'-life','target_observation_ref':prefix+'-target',
            'normal_policy_pin':self.cfg['normalPolicyPin'],'operation_root':str(p.root),
            'sender_source_sha256':self.sender_sha,'before_path':self.files[before['ref']]['path'],
            'before_sha256':self.files[before['ref']]['sha256'],
            'before_capture_path':self.files[before['capture_ref']]['path'],
            'before_capture_sha256':self.files[before['capture_ref']]['sha256'],
            'target_observation_path':ob['path'],'target_observation_sha256':ob['sha256'],
            'destination_admission_path':destination['path'],'destination_admission_sha256':destination['sha256'],
            'destination_admission_ref':'pointer-destination'}
        for key,suffix in [('action_result','action'),('sender_lifecycle','life'),('sender_stdout','stdout'),('sender_stderr','stderr')]:
            context[key+'_path']=str(p.root/(prefix+'-'+suffix+'.'+('raw'if suffix in('stdout','stderr')else'json')))
            context[key+'_ref']=prefix+'-'+suffix
        operation={'platform':'ubuntu','driver':{'path':str(self.sender),'sha256':self.sender_sha},
            'pointer_context':context,'sender_operation':{'kind':'mouse','binding':p.binding,
            'deadline_monotonic':p.end},'observed_result_path':str(p.root/(prefix+'-observed.json')),
            'observer_source_sha256':self.observer_sha}
        digest=hashlib.sha256(json.dumps(operation,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        admission=self.put(prefix+'-admission',{'kind':'OPEMOS_ROBOT_POINTER_ADMISSION','admitted':True,
            'identity':self.identity,'driver_sha256':self.sender_sha,'operation_sha256':digest},'pointer-admission')
        operation.update(admission={'path':admission['path'],'sha256':admission['sha256']},operation_payload_sha256=digest)
        op=self.put(prefix+'-operation',operation,'pointer-operation')
        request=self.put(prefix+'-identity',{'source_commit':self.identity['source_commit'],
            'run_id':self.identity['run_id'],'attempt':self.identity['attempt'],'nonce':self.identity['operation_nonce']},'robot-identity')
        env={'GITHUB_REPOSITORY':'CorniiDog/OPEMOS.EXE','GITHUB_RUN_ID':self.identity['run_id'],
            'GITHUB_RUN_ATTEMPT':self.identity['attempt'],'OPEMOS_SOURCE_SHA':self.identity['source_commit'],
            'OPEMOS_TRANSACTION_NONCE':self.identity['operation_nonce'],'OPEMOS_POINTER_OPERATION':op['path'],
            'OPEMOS_POINTER_OPERATION_SHA256':op['sha256']}
        runner=self.engine/'scripts/run_omen_robot_guest.py';suite=self.engine/'tests/robot/guest.robot'
        bootstrap=fixed_robot_bootstrap(context,runner,
            self.cfg['normalPolicy']['engineSHA256']['scripts/run_omen_robot_guest.py'],
            p.root/(prefix+'-unused-pycache'))
        argv=['/usr/bin/env',*[k+'='+v for k,v in env.items()],sys.executable,'-I','-B','-c',bootstrap,str(runner),
            request['path'],request['sha256'],str(suite),str(p.root/(prefix+'-reports'))]
        # QMP admits one client. Release the parent's connection before the
        # already reviewed Robot sender uses it; native observation is separate.
        need(p.end-time.monotonic()>130,'original GUI clock includes Robot child closure reserve')
        p.q.close();outcome={}
        def run():
            try:outcome['native']=self.owned.run_owned_command(argv,None,min(100,p.end-time.monotonic()),
                [p.root/(prefix+'-robot.stdout'),p.root/(prefix+'-robot.stderr')],stream_limit=4194304)
            except BaseException as error:outcome['error']={'type':type(error).__name__,'reason':str(error)}
        thread=self.threading.Thread(target=run);thread.start();first=None
        try:
            end=min(p.end,time.monotonic()+70)
            while True:
                if Path(context['sender_lifecycle_path']).exists():
                    try:life=json.loads(held(context['sender_lifecycle_path'],1048576))
                    except (OSError,ValueError,UnicodeError,RuntimeError):life={}  # owned pending producer; never acceptance
                    if life.get('waited')is True:break
                need(thread.is_alive()and time.monotonic()<end,'Robot sender failed or did not finish before observation')
                time.sleep(.05)
            need(life['numeric_exit']==0 and life['stdout_EOF']is True and life['stderr_EOF']is True
                 and life['pipes_closed']is True and life['original_gone']is True and not life['first_failure'],
                 'actual Robot sender lifecycle failed; full partial evidence retained')
            p.q=QMP(connect_owned(p.binding['qmp_socket'],p.binding['pid']))
            after_native=self.after_state(name,raw);after=self.capture(prefix+'-after')
            observed={'before_state':self.TRANSITIONS[name][0],'after_state':self.TRANSITIONS[name][1],
                'before_frame_ref':before['ref'],'after_frame_ref':after['ref'],
                'window_owner_process':self.birth,'actual_observation':True,'native':after_native}
            if name in('chooser-confirm-exact-input','Build'):
                observed.update(input_sha256=p.cfg['input_sha256'],input_path=p.cfg['input_path'])
            if name=='Build':observed['planned_output_directory']=p.cfg['output_directory']
            if name.startswith('virtualUSB'):
                observed.update(usb_id='opemos-'+p.binding['nonce'],usb_backing_identity=self.cfg['virtualUSBIdentity'],
                    usb_device_identity=p.selected_usb,output_image_sha256=p.built_output['value']['sha256'])
            self.put(prefix+'-transition',{'status':'observed','action_id':context['action_id'],
                'identity':self.identity,'session':self.session,'app_process':self.birth,'after':after,
                'delivery_clock':self.clock,'delivered_tick':time.monotonic_ns(),'observation':observed},'pointer-transition')
            result={'identity':self.identity,'observed':True,'expected_result':True,'native_observer':True,
                'action_id':context['action_id'],'runtime_instance_id':p.binding['vm_name'],
                'frame_sha256':self.files[after['ref']]['sha256'],'window_id':native['window_id'],
                'observer_source_sha256':self.observer_sha}
            # The observed result is published complete; Robot never sees a
            # partially written JSON file or an overwritten previous result.
            temp=p.root/(prefix+'-observed.partial');save(temp,result)
            import ctypes
            libc=ctypes.CDLL(None,use_errno=True)
            numeric=libc.renameat2(-100,os.fsencode(temp),-100,os.fsencode(operation['observed_result_path']),1)
            need(numeric==0,'atomic create-only independent observed result')
        except BaseException as error:first=error;raise
        finally:
            thread.join(max(0,min(110,p.end-time.monotonic())))
            if first is not None:outcome['parentFIRST']={'type':type(first).__name__,'reason':str(first)}
            outcome['originalRobotThreadClosed']=not thread.is_alive()
            self.put(prefix+'-robot-native',outcome,'robot-child-lifecycle')
            if thread.is_alive() and first is None:raise RuntimeError('original Robot owned-child closure remains unknown')
            if p.q.f.closed and not thread.is_alive():p.q=QMP(connect_owned(p.binding['qmp_socket'],p.binding['pid']))
        need('error'not in outcome and outcome['native']['numericExit']==0
             and outcome['native']['lifecycleClosed']is True and not outcome['native']['errors'],
             'real Robot suite or child closure failed')
        actual=json.loads(held(p.root/(prefix+'-reports/result.json'),1048576))
        need(actual['numeric_exit']==0 and actual['tests_failed']==0 and actual['tests_passed']==1
             and actual['actual_pointer_calls']==1,'actual ordinary Robot mouse suite did not pass')
        for key,kind in [('action_result','pointer-action'),('sender_lifecycle','pointer-sender-lifecycle'),
                         ('sender_stdout','pointer-sender-stdout'),('sender_stderr','pointer-sender-stderr')]:
            self.retain(context[key+'_ref'],context[key+'_path'],kind)
        for item in actual['reports']:self.retain(prefix+'-'+Path(item['path']).name,item['path'],item['kind'])
        self.actions[name]=prefix+'-action';self.reports.append(actual)
        record={'action':name,'nativeControl':raw,'robotResult':actual,'beforeFrame':before}
        p.actions.append(record);return record

    def complete(self):
        need(tuple(self.actions)==self.ACTIONS and len(self.reports)==5,'all five actual Robot mouse operations required')
        self.retain('normal-sender-source',self.sender,'pointer-sender-source')
        self.retain('normal-observer-source',Path(self.cfg['programRoot'])/'observer_guest.py','gui-observer-source')
        return {'pointer_actions':self.actions,'files':self.files,'gui_session':self.session,
            'gui_clock':self.clock,'gui_controls':self.controls,'gui_destination_admission':self.destination,
            'identity':self.identity,'app_process':self.birth,'app_window_id':self.p.app['window_id'],
            'gui_sender_ref':'normal-sender-source','gui_observer_ref':'normal-observer-source',
            'robot_reports':self.reports}


class Pipeline:
    """Actual native observations and QMP input in the same owned Ubuntu VM."""
    def __init__(self,binding,config,q,observer,ready,root):
        self.binding=binding;self.cfg=config;self.q=q;self.observer=observer;self.ready=ready
        self.root=root;self.sequence=0;self.actions=[];self.observations=[];self.observation_bytes=0
        self.end=time.monotonic()+config['whole_seconds'];self.app=ready['app'];self.check=lambda:None;self.robot_click=None
        need(binding['nonce']==config['nonce']==ready['nonce'] and
             binding['artifact_source']==config['source_commit'] and
             binding['package_sha256']==config['package_sha256'] and
             ready['process']['pid']==self.app['pid'] and
             ready['process']['inherited_nonce']==binding['nonce']and
             ready['process'].get('exe_sha256')==config['native_executable_sha256'],
             'same admitted candidate/app birth/normal operation')

    def __enter__(self):return self
    def __exit__(self,*failure):
        # Robot releases and replaces this peer between mouse operations.
        # Close the current peer before the normal VM finalizer reconnects.
        self.q.close()

    def request(self,kind,**operands):
        self.check()
        remaining=self.end-time.monotonic();need(remaining>0 and self.sequence<256,'original GUI operation clock/request bound')
        process(self.binding);self.sequence+=1;self.observer.settimeout(remaining)
        request={'nonce':self.binding['nonce'],'sequence':self.sequence,'kind':kind,**operands}
        self.observer.sendall((json.dumps(request,separators=(',',':'))+'\n').encode())
        response=observer_line(self.observer,1048576)
        # Keep the bounded reply even if authentication rejects it. This is
        # diagnostic data and never supplies an accepted native observation.
        self.last_received_native_frame={'response':response,'diagnosticOnly':True,
            'expected':{'nonce':request['nonce'],'sequence':self.sequence,
                        'request_kind':kind,'process':self.ready['process']}}
        need(time.monotonic()<self.end and response.get('kind')=='NATIVE_OBSERVATION' and
             response.get('nonce')==request['nonce'] and response.get('sequence')==self.sequence and
             response.get('request_kind')==kind and response.get('process')==self.ready['process'],
             'ordered same native app observation within original clock')
        path=self.root/('native-observation-'+str(self.sequence).zfill(3)+'.json')
        pin=save(path,response);info=path.lstat()
        self.observations.append(dict(pin,identity={k:getattr(info,k)for k in FULL9},
            kind='native-observation'))
        self.observation_bytes+=pin['bytes']
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
        if self.robot_click is not None and name in ('chooser-open','chooser-confirm-exact-input','Build','virtualUSB-select-and-review','virtualUSB-Write-confirmation'):
            return self.robot_click(self,name,label,roles,window)
        target=self.target(label,list(roles),window);control=target['value'];point=control['point']
        native=self.app if window is None else window
        native_control_bound(control,native,self.ready['process'])
        need(control['window_id']==native['window_id']and
             control['enabled']is True and control['visible']is True and control['readOnlyObservation']is True,
             'current genuine native control process/window/state')
        before=frame(self.q,self.root/(str(len(self.actions)).zfill(3)+'-'+name+'-before.png'),self.cfg['display'])
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
        self.click('chooser-confirm-exact-input'if action=='chooser-open'else action+'-confirm',confirm,window=dialogs[0])

    def names(self):return [name for row in self.request('UI_STATE')['value']['namesByWindow']for name in row['names']]

    def wait_text(self,text,prefix=False):
        while True:
            names=self.names()
            if text in names or(prefix and text=='NVIDIA-mutated image created and retained: '
                                   and any(name.startswith(text)for name in names)):return names
            errors=[name for name in names if name.startswith(('Build failed','Image build failed','USB write failed','Error:'))]
            need(not errors,'actual application failure: '+repr(errors))
            remaining=self.end-time.monotonic();need(remaining>0,'actual application completion absent');time.sleep(min(30,remaining))

    def build_write(self):
        labels=self.cfg['labels']
        self.choose('chooser-open',labels['choose_input'],self.cfg['input_path'],labels['open'])
        self.choose('choose-output-directory',labels['choose_output'],self.cfg['output_directory'],labels['select_folder'])
        input_image=self.request('FILE',role='input_path')
        need(input_image['value']['sha256']==self.cfg['input_sha256'],'actual selected original image hash')
        self.selected_input=input_image
        self.click('Build',labels['build'])
        self.wait_text(labels['build_success'],prefix=True)
        output=self.request('FILE',role='output_path')
        usb=self.request('USB')['value']
        need(usb['serial']=='opemos-'+self.binding['nonce']and usb['bytes']==self.cfg['usb_bytes'],
             'actual same-guest emulated USB identity')
        self.click('virtualUSB-select',labels['usb_target'],('combo box','list item'))
        choices=[name for name in self.names()if ' · '+usb['path']+' · 'in name]
        need(len(choices)==1,'one native device option for the actually observed emulated USB')
        self.click('virtualUSB-device',choices[0],('list item','menu item','text'))
        self.built_output=output;self.selected_usb=usb;self.cfg['output_path']=output['value']['path']
        self.click('virtualUSB-select-and-review',labels['review'])
        self.click('virtualUSB-confirmation-entry',labels['confirmation'],('entry',))
        self.text('ERASE')
        self.click('virtualUSB-Write-confirmation',labels['write'])
        self.wait_text(labels['write_success'])
        repeated=self.request('FILE',role='output_path')
        need(repeated['value']==output['value'],'actual built image unchanged through GUI write/readback')
        after=frame(self.q,self.root/'gui-write-complete.png',self.cfg['display'])
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
        type(cfg['display'])is list and len(cfg['display'])==2 and
        all(type(v)is int and v>0 for v in cfg['display']) and
        re.fullmatch('[0-9a-f]{40}',cfg['source_commit']),
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
        try:result['failureFrame']=frame(q,root/'pipeline-first-failure.png',cfg['display'])
        except BaseException as secondary:result['frameFailure']=str(secondary)
        raise
    finally:
        try:obs.close()
        finally:q.close()
        save(root/'gui-build-write-result.json',result)


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--pipeline':pipeline_main(sys.argv[2])
    else:main()


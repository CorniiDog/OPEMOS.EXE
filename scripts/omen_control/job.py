#!/usr/bin/env python3
"""Existing ordinary-queue Ubuntu GUI Build/write job.

Requires a separately issued exact queue approval and Root-installed broker.
No direct invocation from a GitHub checkout is authorized.
"""
import hashlib
import contextlib
import html
import json
import errno
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import types
import threading

WHOLE_END=None
CLEANUP_END=None
OWNED=None
CHILD_SEQUENCE=0

os.umask(0o077)
QMP_BUFFERS={}

HERE=Path(__file__).resolve().parent
RUNTIME=Path('/home/connor/.local/state/opemos-runtime')
FULL9=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def need(ok,why):
    if not ok:raise RuntimeError(why)

def sig(s):return {k:getattr(s,k) for k in FULL9}

def input_file(pin,cap):
    path=Path(pin['path']);need(path.is_absolute() and path.resolve()==path,
                             'canonical absolute readonly source required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        first=os.fstat(fd)
        need(stat.S_ISREG(first.st_mode)and first.st_uid==os.getuid()and
             first.st_nlink==1 and not first.st_mode&0o022 and
             first.st_size==pin['bytes'] and first.st_size<=cap and
             sig(first)==pin['identity'],'original full9/owner/size differs')
        digest=hashlib.sha256()
        while data:=os.read(fd,4*1024*1024):digest.update(data)
        need(sig(first)==sig(os.fstat(fd))==sig(path.lstat())and
             digest.hexdigest()==pin['sha256'],'original whole SHA/full9 drift')
    finally:os.close(fd)
    return path

def write_json(path,row):
    raw=(json.dumps(row,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    need(len(raw)<=64*1024*1024,'finite complete normal job metadata')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:need(os.write(fd,raw)==len(raw),'short private receipt write');os.fsync(fd)
    finally:os.close(fd)

def write_blob(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:need(os.write(fd,raw)==len(raw),'short bounded report write');os.fsync(fd)
    finally:os.close(fd)

def remaining(seconds):
    deadline=CLEANUP_END if CLEANUP_END is not None else WHOLE_END
    value=seconds if deadline is None else min(seconds,deadline-time.monotonic())
    need(value>0,'original finite job or owned closure deadline')
    return value

def child(argv,cwd,seconds,stdin_bytes=None):
    global CHILD_SEQUENCE
    need(OWNED is not None,'authenticated existing owned transport')
    CHILD_SEQUENCE+=1;root=Path(cwd)
    outpath=root/('owned-child-'+str(CHILD_SEQUENCE).zfill(3)+'.stdout')
    errpath=root/('owned-child-'+str(CHILD_SEQUENCE).zfill(3)+'.stderr')
    old=Path.cwd()
    try:
        os.chdir(root)
        native=OWNED.run_owned_command(argv,stdin_bytes,remaining(seconds),[outpath,errpath],stream_limit=4194304)
    finally:os.chdir(old)
    write_json(root/('owned-child-'+str(CHILD_SEQUENCE).zfill(3)+'.native.json'),native)
    need(native['lifecycleClosed']is True and native['errors']==[],'actual helper EOF/reap/FD/childset closure')
    out=outpath.read_bytes();err=errpath.read_bytes()
    return dict(native,numeric=native['numericExit']),out,err


def qmp_call(q,ident,cmd,args=None):
    budget=remaining(10);q.settimeout(budget)
    req={'execute':cmd,'id':ident}
    if args is not None:req['arguments']=args
    q.sendall((json.dumps(req)+'\r\n').encode())
    buf=QMP_BUFFERS.setdefault(q.fileno(),bytearray())
    while True:
        while b'\n'in buf:
            line,_,rest=buf.partition(b'\n');buf[:]=rest
            row=json.loads(line)
            if row.get('id')==ident:
                need('error'not in row,'QMP error: '+repr(row.get('error')))
                remaining(10)
                return row['return']
        part=q.recv(65536);need(part,'QMP EOF')
        buf.extend(part);need(len(buf)<=1048576,'QMP cap exceeded')

def qmp_connect(path,pid,connect,child=None):
    deadline=time.monotonic()+remaining(20)
    while not os.path.exists(path):
        if child is not None:
            code=child.poll()
            need(code is None,'QEMU exited before QMP startup: numeric '+str(code)+
                 '; original qemu.stdout/qemu.stderr retained')
        need(time.monotonic()<deadline,'QMP startup deadline; original QEMU streams retained')
        time.sleep(min(.05,max(0,deadline-time.monotonic())))
    s=connect(path,pid,remaining(20))
    try:
        intro=bytearray()
        while b'\n' not in intro:
            part=s.recv(65536);need(part,'QMP greeting EOF')
            intro.extend(part);need(len(intro)<=1048576,'QMP greeting cap exceeded')
        greeting,sep,rest=intro.partition(b'\n')
        need(sep and b'QMP' in greeting,'complete QMP greeting missing')
        QMP_BUFFERS[s.fileno()]=bytearray(rest)
        qmp_call(s,1,'qmp_capabilities')
        return s
    except BaseException:
        QMP_BUFFERS.pop(s.fileno(),None);s.close();raise

def readonly_qemu_holders(pid, pins):
    found={str(Path(p['path'])):0 for p in pins}
    bypath={str(Path(p['path'])):p for p in pins}
    procfd=Path('/proc')/str(pid)/'fd'
    for entry in procfd.iterdir():
        try:
            target=entry.resolve(strict=True)
            if str(target) in found:
                flags=int((Path('/proc')/str(pid)/'fdinfo'/entry.name).read_text().split('flags:\t',1)[1].splitlines()[0],8)
                need(flags&os.O_ACCMODE==os.O_RDONLY,'QEMU original holder writable')
                need(sig(entry.stat())==bypath[str(target)]['identity'],
                     'QEMU original holder inode/full9 differs from pinned source')
                found[str(target)]+=1
        except (FileNotFoundError,PermissionError):
            continue
    need(all(found.values()),'missing QEMU original holder')
    return found

def boot_text(q,text):
    # Existing Ubuntu graphical bootstrap primitive. This starts the native
    # observer and packaged app; it is NOT the tested chooser activation.
    need(text=='bash /media/opemosgui/OPROBOT/start.sh\n',
         'exact fixed observer bootstrap command required')
    codes={' ':'spc','.':'dot','-':'minus','/':'slash','\n':'ret'};ident=50
    for c in text:
        upper='A'<=c<='Z'
        key=codes.get(c,c.lower() if upper else c)
        if upper:
            ident+=1
            qmp_call(q,ident,'input-send-event',{'events':[{'type':'key',
                'data':{'down':True,'key':{'type':'qcode','data':'shift'}}}]})
        for down in (True,False):
            ident+=1
            qmp_call(q,ident,'input-send-event',{'events':[{'type':'key',
                'data':{'down':down,'key':{'type':'qcode','data':key}}}]})
            time.sleep(.015)
        if upper:
            ident+=1
            qmp_call(q,ident,'input-send-event',{'events':[{'type':'key',
                'data':{'down':False,'key':{'type':'qcode','data':'shift'}}}]})

def login_guest(q,root):
    # This is the retained credential for the exact Graphical-r1 disposable
    # guest, used only for session bootstrap. Never print or put it in a receipt.
    secret=HERE/'login.private.json'
    fd=os.open(secret,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode)and st.st_uid==os.getuid()and
             st.st_nlink==1 and st.st_mode&0o777==0o600 and st.st_size<=4096,
             'retained exact disposable login input custody differs')
        row=json.loads(os.read(fd,4097))
        need(sig(st)==sig(os.fstat(fd))==sig(secret.lstat()),
             'retained disposable login input changed')
    finally:os.close(fd)
    need(row.get('username')=='opemosgui' and
         row.get('hostname')=='opemos-ubuntu-gui' and
         row.get('publicEvidenceMustNotContainSecret') is True and
         'Graphical-r1 disposable guest' in row.get('scope',''),
         'retained login input is not for this graphical guest')
    password=row.get('password')
    need(type(password)is str and len(password)==32 and
         all(c in 'abcdefghijklmnopqrstuvwxyz0123456789' for c in password),
         'retained login alphabet/length differs')
    for ident,axis,value,dimension in ((210,'x',640,1280),(211,'y',348,800)):
        qmp_call(q,ident,'input-send-event',{'events':[{'type':'abs','data':
            {'axis':axis,'value':round(value*32767/(dimension-1))}}]})
    for ident,down in ((212,True),(213,False)):
        qmp_call(q,ident,'input-send-event',{'events':[{'type':'btn','data':
            {'button':'left','down':down}}]})
    time.sleep(2)
    prompt=capture_bootstrap(q,214,root/'password-prompt.png')
    ident=220
    for c in password:
        for down in (True,False):
            ident+=1
            qmp_call(q,ident,'input-send-event',{'events':[{'type':'key',
                'data':{'down':down,'key':{'type':'qcode','data':c}}}]})
            time.sleep(.015)
    for down in (True,False):
        ident+=1
        qmp_call(q,ident,'input-send-event',{'events':[{'type':'key',
            'data':{'down':down,'key':{'type':'qcode','data':'ret'}}}]})
    del password,row
    time.sleep(15)
    desktop=capture_bootstrap(q,215,root/'post-login.png')
    return {'prompt_frame':prompt,'post_login_frame':desktop,
            'method':'retained-exact-private-guest-input/QMP-session-bootstrap',
            'chooserAcceptance':False}

def capture_bootstrap(q,ident,path):
    need(not os.path.lexists(path),'fresh bootstrap frame required')
    qmp_call(q,ident,'screendump',{'filename':str(path),'format':'png'})
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode)and st.st_uid==os.getuid()and st.st_size<=16*1024*1024,
         'bounded actual bootstrap frame missing')
    raw=path.read_bytes();need(raw.startswith(b'\x89PNG\r\n\x1a\n'),
                              'bootstrap image not PNG')
    return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'width':struct.unpack('>I',raw[16:20])[0],
            'height':struct.unpack('>I',raw[20:24])[0],
            'guiAcceptance':False}



def qemu_output(proc,root):
    """Bound retained bytes while draining both actual QEMU pipes to EOF."""
    records={};threads=[]
    for name,pipe in [('stdout',proc.stdout),('stderr',proc.stderr)]:
        record={'readBytes':0,'retainedBytes':0,'EOF':False,'first':None};records[name]=record
        fd=os.open(root/('qemu.'+name),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        def drain(stream=pipe,output=fd,value=record):
            try:
                while block:=stream.read(65536):
                    value['readBytes']+=len(block);left=max(0,1048576-value['retainedBytes'])
                    raw=memoryview(block[:left])
                    while raw:
                        count=os.write(output,raw);need(count>0,'bounded QEMU capture write');raw=raw[count:];value['retainedBytes']+=count
                    if len(block)>left and value['first']is None:value['first']='actual QEMU stream cap; remaining tail not retained'
                value['EOF']=True;os.fsync(output)
            except BaseException as error:value['first']=value['first']or(type(error).__name__+': '+str(error))
            finally:os.close(output);stream.close()
        thread=threading.Thread(target=drain,daemon=True);thread.start();threads.append(thread)
    return records,threads

def check_qemu_output(records):
    need(all(value['first']is None for value in records.values()),'actual QEMU output failure: '+repr(records))

def held_source(path,uid,mode,digest=None,cap=1048576):
    path=Path(path);need(path.is_absolute()and path.resolve()==path,'canonical source/data path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);raw=bytearray()
        need(stat.S_ISREG(before.st_mode)and before.st_uid==uid and before.st_nlink==1
             and stat.S_IMODE(before.st_mode)==mode and 0<before.st_size<=cap,'source/data owner/mode/size')
        while piece:=os.read(fd,65536):raw.extend(piece);need(len(raw)<=cap,'finite source/data')
        need(len(raw)==before.st_size and sig(before)==sig(os.fstat(fd))==sig(path.lstat())
             and(digest is None or hashlib.sha256(raw).hexdigest()==digest),'held source/data epoch/hash')
        return bytes(raw)
    finally:os.close(fd)

def current_queue_identity(C):
    group=Path('/proc/self/cgroup').read_text().strip()
    units=[x for x in group.removeprefix('0::').split('/')
           if re.fullmatch(r'opemos-testq-[0-9a-f-]+\.service',x)]
    need(len(units)==1 and C['queue_job_id'].endswith('-'+C['nonce']),
         'same actual admitted queue unit/job/operation')
    observed=subprocess.run(['/usr/bin/systemctl','show',units[0],'-p','InvocationID','-p','ActiveState'],
        capture_output=True,text=True,timeout=10)
    need(observed.returncode==0 and observed.stderr=='','actual current system manager observation')
    value=dict(x.split('=',1)for x in observed.stdout.splitlines()if'='in x)
    need(value.get('ActiveState')=='active'and re.fullmatch('[0-9a-f]{32}',value.get('InvocationID','')),
         'actual finite current queue invocation/active state')
    inherited=os.environ.get('INVOCATION_ID')
    need(inherited is None or inherited==value['InvocationID'],'inherited actual queue invocation differs')
    return units[0],value['InvocationID'],group

def authenticated_config(config):
    need(os.getuid()==os.geteuid()==1000 and config.parent==HERE and config.name=='operation.json',
         'same materialized ordinary queue config')
    C=json.loads(held_source(config,1000,0o400))
    ref=C['normalPolicyPin'];path=Path(ref['path'])
    need(path.parent.parent==Path('/var/lib/opemos-robot-control-r1/releases')and
         re.fullmatch('[0-9a-f]{32}',path.parent.name)and path.name=='fixed-policy.json',
         'existing immutable Root deployment policy')
    for parent in(path.parent,*path.parent.parents):
        s=parent.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0
                              and not s.st_mode&0o022,'Root source ancestry')
    policy=json.loads(held_source(path,0,0o444,ref['sha256']))
    need(policy==C['normalPolicy']and policy['kind']=='ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1'
         and policy['network']=='none'and policy['swapBytes']==0
         and type(policy['maxVMBytes'])is int and 0<policy['maxVMBytes']<=59_971_770_624,
         'one actual normal policy graph')
    need(C['kind']=='ROOT_ADMITTED_UBUNTU_GUI_BUILD_WRITE_V1'and re.fullmatch('[0-9a-f]{32}',C['nonce'])
         and re.fullmatch('[0-9a-f]{40}',C['source_commit'])and C['programRoot']==str(HERE)
         and HERE.parent.parent==Path(policy['operationRoot'])
         and HERE.parent.name.endswith('-'+C['nonce'])and
         type(C['whole_seconds'])is int and 0<C['whole_seconds']<=policy['wholeSeconds']<=7200
         and type(C['cores'])is int and 0<C['cores']<=policy['maxCPU']<=10
         and type(C['memoryBytes'])is int and 0<C['memoryBytes']<=policy['maxMemoryBytes']<=34359738368,
         'current normal operation identity/deadline/resource bounds')
    d=C['candidate']['descriptor'];guest=C['guest_operation']
    need(all(C[k]['sha256']==policy['originalSHA256'][k]for k in('base','code','vars_template','image_carrier')),
         'Root-pinned original image/firmware roles')
    need(d['platform']=='ubuntu'and d['repository']=='CorniiDog/OPEMOS.EXE'
         and C['source_commit']==policy['sourceCommit']and d['source_commit']==guest['source_commit']
         and C['candidate']['archive']['sha256']==d['artifact_archive_sha256']
         and guest['package_sha256']==d['package_sha256']and guest['nonce']==C['nonce']
         and d['executable_name']!=d['package_name']and guest['native_executable_sha256']==d['executable_sha256']
         and guest['native_executable_bytes']==d['executable_bytes']
         and guest['usb_serial']=='opemos-'+C['nonce'],'actual producer/archive/guest/USB binding')
    return C

def authenticated_programs(C):
    expected={'run_approved.py','job.py','provision_observer_rule.py','connection_control.py',
              'observer_guest.py','prepare_observer_iso.py','virtual_usb.py','vm_write_ceiling.py','owned_command.py'}
    policy=C['normalPolicy'];need(set(policy['programSHA256'])==expected,'complete current normal program graph')
    root=Path(C['normalPolicyPin']['path']).parent/'proof-sources';sources={}
    # Authenticate the whole graph before any sibling import or interpretation.
    for name in sorted(expected):
        raw=held_source(root/name,0,0o444,policy['programSHA256'][name])
        need(held_source(HERE/name,1000,0o500,policy['programSHA256'][name])==raw,
             'materialized source differs from immutable current program')
        sources[name]=raw
    sys.modules['job']=sys.modules[__name__];values={}
    for name in ['vm_write_ceiling','virtual_usb','owned_command','connection_control','provision_observer_rule']:
        value=types.ModuleType(name);value.__file__=str(HERE/(name+'.py'))
        sys.modules[name]=value;exec(compile(sources[name+'.py'],value.__file__,'exec'),value.__dict__)
        values[name]=value
    return values


def authenticated_engine(C):
    policy=C['normalPolicy'];engine=Path(C['engineRoot'])
    need(engine==HERE/'engine','same actual materialized normal Robot engine')
    root=Path(C['normalPolicyPin']['path']).parent/'engine';sources={}
    for name,digest in policy['engineSHA256'].items():
        need(name.startswith(('scripts/','ci/','tests/robot/'))and '..'not in Path(name).parts,
             'normal fixed engine member')
        raw=held_source(root/name,0,0o444,digest)
        need(held_source(engine/name,1000,0o500,digest)==raw,'same authenticated normal engine bytes')
        sources[name]=raw
    return sources


def main():
    global WHOLE_END,CLEANUP_END,OWNED
    need(len(sys.argv)==3 and sys.argv[1]=='--pipeline','exact installed normal pipeline config')
    config=Path(sys.argv[2]);C=authenticated_config(config)
    RUNTIME=HERE.parent  # the existing one-use normal operation owns all VM/evidence paths
    nonce=C['nonce'];WHOLE_END=C['operation_end_monotonic']
    need(type(WHOLE_END)in(int,float)and C['operation_started_monotonic']<=time.monotonic()<WHOLE_END<=C['operation_started_monotonic']+C['whole_seconds'],'same original whole normal operation clock, including preparation')
    modules=authenticated_programs(C);engine_sources=authenticated_engine(C);OWNED=modules['owned_command']
    USB=modules['virtual_usb'];CONTROL=modules['connection_control']
    cow_limit=C['cow_growth_bytes'];whole_limit=C['maxVMBytes']
    need(type(cow_limit)is int and 4_000_000_000<=cow_limit<=24_000_000_000,
         'finite actual guest COW write ceiling')
    need(type(C['cores'])is int and 0<C['cores']<=10 and
         type(C['memoryBytes'])is int and C['memoryBytes']%1048576==0 and
         0<C['memoryBytes']<=34359738368 and C['swapBytes']==0 and C['network']=='none',
         'same admitted CPU/RAM/no-swap/no-network bounds')
    need(type(C['guest_memory_bytes'])is int and C['guest_memory_bytes']%1048576==0 and
         0<C['guest_memory_bytes']<=C['memoryBytes']-2147483648,
         'guest memory preserves admitted QEMU/observer overhead')
    need(os.getuid()==1000 and stat.S_ISDIR(RUNTIME.stat().st_mode)and
         RUNTIME.stat().st_uid==1000 and RUNTIME.stat().st_dev==C['ext4_dev'] and
         os.statvfs(RUNTIME).f_frsize>0,'exact ext4 OPEMOS runtime root differs')
    fs=subprocess.run(['/usr/bin/findmnt','-n','-o','FSTYPE','-T',str(RUNTIME)],
                      capture_output=True,text=True,timeout=10)
    need(fs.returncode==0 and fs.stdout.strip()=='ext4',
         'fresh disposable COW target must actually be ext4')
    unit,invocation,current_cgroup=current_queue_identity(C)
    base=input_file(C['base'],60_000_000_000)
    code=input_file(C['code'],8*1024*1024)
    vars_original=input_file(C['vars_template'],8*1024*1024)
    package=input_file(C['image_carrier'],16*1024**3)
    observer_iso=C['observer_iso'];observer=input_file(observer_iso,3*1024**3)
    need(observer_iso['nonce']==nonce and observer_iso['source_commit']==C['candidate']['descriptor']['source_commit'],
         'exact produced candidate/observer medium belongs to this operation')
    originals={'base':C['base'],'code':C['code'],'vars_template':C['vars_template'],
               'image_carrier':C['image_carrier'],'observer_iso':observer_iso}
    # Measure every distinct original, including prepared medium and archive
    # retention. The Root normal admission supplies the separately retained union.
    ids=[(v['identity']['st_dev'],v['identity']['st_ino'])for v in originals.values()]
    need(len(ids)==len(set(ids)),'aliased VM original roles')
    storage=C['runtime_storage'];scratch=RUNTIME/'scratch';scratch_info=scratch.lstat()
    need(storage['kind']=='CURRENT_ROOT_PRIVATE_FILE_BACKED_EXT4_V1'and
         storage['mount']==str(scratch)and storage['mountNamespace']==os.readlink('/proc/self/ns/mnt')and
         storage['device']==scratch_info.st_dev and scratch_info.st_uid==1000 and
         storage['cowPath']==str(scratch/'desktop-overlay.qcow2')and
         storage['fixedStorageBytes']==C['normalPolicy']['fixedStorageBytes']and
         storage['usbDirectory']==str(Path(C['normalPolicy']['storageBase'])/nonce/'usb'),
         'actual current Root-provided bounded storage context')
    private_fs=subprocess.run(['/usr/bin/findmnt','-n','-o','FSTYPE','-T',str(scratch)],
                              capture_output=True,text=True,timeout=10)
    need(private_fs.returncode==0 and private_fs.stdout.strip()=='ext4','actual private COW ext4')
    charged=sum(os.stat(v['path']).st_blocks*512 for k,v in originals.items()if k!='observer_iso')
    retained=C['retained_union_bytes'];usb_bytes=C['guest_operation']['usb_bytes']
    need(type(retained)is int and retained>=0 and type(usb_bytes)is int and usb_bytes>0 and
         type(C['maxVMBytes'])is int and whole_limit==C['normalPolicy']['maxVMBytes']<=59_971_770_624 and
         charged+retained+storage['fixedStorageBytes']+usb_bytes+C['vars_template']['bytes']+500_000_000<=whole_limit,
         'complete immutable originals/retention/COW/USB/vars/metadata exceed admitted whole VM bound')
    root=RUNTIME/'runtime'
    need(not os.path.lexists(root),'fresh private VM directory exists')
    statfs=os.statvfs(scratch);free=statfs.f_bavail*statfs.f_frsize
    need(free>=cow_limit+500_000_000 and os.statvfs(RUNTIME).f_bavail*os.statvfs(RUNTIME).f_frsize>=500_000_000,
         'actual inner COW and outer metadata capacity unavailable')
    root.mkdir(mode=0o700)
    def metadata_guard(reserve=0):
        allocated=0;count=0;archive=Path(C['candidate']['archive']['path'])
        for directory,dirs,files in os.walk(RUNTIME,followlinks=False):
            parent=Path(directory)
            if parent==RUNTIME:dirs[:]=[n for n in dirs if n!='scratch']
            for name in files+dirs:
                path=parent/name;s=path.lstat();count+=1
                need(count<=8192 and not stat.S_ISLNK(s.st_mode),'finite owned metadata namespace')
                if path==archive:continue  # independently full-hashed and charged archive role
                allocated+=s.st_blocks*512
        need(allocated+reserve<=500_000_000,'actual whole operation metadata reserve exhausted')
        return allocated
    metadata_guard(192*1024**2)  # QEMU stream caps plus one complete Robot action
    first=None;q=None;qemu_pidfd=None;qemu_streams={};qemu_readers=[];qemu_launch_attempted=False;control=None;socket_pins={};usb_scope=None;usb_fd=None;runtime_fd=None
    result={'kind':'NORMAL_UBUNTU_GUI_BUILD_WRITE_JOB_V1','nonce':nonce,
            'source_commit':C['source_commit'],'candidate_source_commit':C['candidate']['descriptor']['source_commit'],'package_sha256':C['candidate']['descriptor']['package_sha256'],
            'fullStackAccepted':False,'SteamOSOrGPUAcceptance':False,'originals':originals,
            'effects':[],'first_failure':None,'closure':'UNKNOWN'}
    try:
        usb_scope=USB.virtual_usb_backing(storage['usbDirectory'],usb_bytes,
                    charged+retained+storage['fixedStorageBytes']+C['vars_template']['bytes'])
        backing,usb_fd=usb_scope.__enter__()
        result['virtualUSB']=backing;result['effects'].append('new-owned-allocated-regular-file-USB')
        vars_out=root/'OVMF_VARS_4M.fd'
        with open(vars_original,'rb')as src,open(vars_out,'xb')as dst:
            shutil.copyfileobj(src,dst,1048576);dst.flush();os.fsync(dst.fileno())
        need(hashlib.sha256(vars_out.read_bytes()).hexdigest()==C['vars_template']['sha256'],
             'fresh vars copy differs from readonly template')
        result['effects'].append('fresh-private-vars')
        overlay=Path(storage['cowPath'])
        run,out,err=child(['/usr/bin/qemu-img','create','-q','-f','qcow2','-F','qcow2',
                           '-b',str(base),str(overlay)],root,30)
        need(run['numeric']==0 and overlay.is_file() and overlay.stat().st_size<cow_limit,
             'fresh create-only COW failed')
        info_run,info_raw,_=child(['/usr/bin/qemu-img','info','--output=json','--backing-chain',str(overlay)],root,30)
        need(info_run['numeric']==0,'fresh overlay backing-chain inspection failed')
        chain=json.loads(info_raw)
        need(len(chain)==2 and chain[0]['filename']==str(overlay) and
             chain[0]['backing-filename']==str(base) and chain[1]['filename']==str(base) and
             chain[0]['virtual-size']==chain[1]['virtual-size'] and
             chain[0]['virtual-size']==40_000_000_000 and
             chain[0]['format']==chain[1]['format']=='qcow2' and
             chain[1].get('dirty-flag') is False and
             not chain[1].get('backing-filename'),
             'complete original-base/COW virtual geometry or ancestry differs')
        result['overlay_geometry']={'virtual_size':chain[0]['virtual-size'],
                                    'original_base':str(base),'new_cow':str(overlay)}
        result['effects'].append('fresh-private-cow')
        need(WHOLE_END-time.monotonic()>390,'finite preboot rule budget within original whole clock')
        # Execute exact held verified helper bodies through the existing owned
        # child transport. Its 4GB preboot RLIMIT/signal clock never alters the
        # parent graphical job or the later larger guest COW ceiling.
        job_source=held_source(HERE/'job.py',1000,0o500,C['normalPolicy']['programSHA256']['job.py'])
        provision_source=held_source(HERE/'provision_observer_rule.py',1000,0o500,
                                     C['normalPolicy']['programSHA256']['provision_observer_rule.py'])
        carrier=('import sys,types\njob=types.ModuleType("job");job.__file__='+repr(str(HERE/'job.py'))+
                 '\nsys.modules["job"]=job\nexec(compile('+repr(job_source)+',job.__file__,"exec"),job.__dict__)\n'+
                 'p=types.ModuleType("exact_ordinary_cow_provision");p.__file__='+repr(str(HERE/'provision_observer_rule.py'))+
                 '\nexec(compile('+repr(provision_source)+',p.__file__,"exec"),p.__dict__)\n'+
                 'sys.argv=[p.__file__,'+repr(str(config))+'];p.main()\n').encode()
        provision,_,_=child(['/usr/bin/python3','-I','-B','-'],root,390,carrier)
        result['observer_rule_provision_child']=provision
        need(provision['numeric']==0,'exact preboot COW-only rule helper refused')
        rule_receipt=json.loads((root/'observer-rule-provision.json').read_bytes())
        need(rule_receipt.get('accepted') is True and
             rule_receipt.get('nonce')==nonce and
             rule_receipt.get('guest_rule',{}).get('readback') is True and
             rule_receipt.get('base_post_sha256')==C['base']['sha256'] and
             rule_receipt.get('cow_after',{}).get('sha256') and
             rule_receipt.get('post_idle',{}).get('sysfs_pid_absent') is True and
             overlay.stat().st_size<cow_limit,
             'complete offline disposable rule proof missing')
        overlay_hash=hashlib.sha256()
        with overlay.open('rb') as fresh_cow:
            while piece:=fresh_cow.read(4*1024*1024):overlay_hash.update(piece)
        need(overlay_hash.hexdigest()==rule_receipt['cow_after']['sha256'] and
             sig(overlay.lstat())==rule_receipt['cow_after']['identity'],
             'post-provision COW path/whole bytes changed before first boot')
        result['observer_rule_provision']={'path':str(root/'observer-rule-provision.json'),
             'sha256':hashlib.sha256((root/'observer-rule-provision.json').read_bytes()).hexdigest(),
             'cow_after_sha256':rule_receipt['cow_after']['sha256'],
             'rule_sha256':rule_receipt['rule_sha256']}
        result['effects'].append('exact-offline-rule-in-fresh-private-cow-only')
        name='opemos-robot-ubuntu-'+nonce
        runtime_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        runtime_identity=os.fstat(runtime_fd)
        need(stat.S_ISDIR(runtime_identity.st_mode)and runtime_identity.st_uid==os.getuid()and
             not runtime_identity.st_mode&0o077 and
             (runtime_identity.st_dev,runtime_identity.st_ino)==(root.lstat().st_dev,root.lstat().st_ino),
             'held original private VM runtime directory')
        qmp=root/'qmp.sock';vnc=root/'vnc.sock';obs=root/'observer.sock'
        argv=['/usr/bin/qemu-system-x86_64','-name',name,'-machine','q35,accel=kvm',
              '-cpu','host','-smp',str(C['cores']),'-m',str(C['guest_memory_bytes']//1048576),
              '-drive',f'if=pflash,format=raw,unit=0,readonly=on,file={code}',
              '-drive',f'if=pflash,format=raw,unit=1,file={vars_out}',
              '-drive',f'if=none,id=osdisk,format=qcow2,file={overlay}',
              '-device','virtio-blk-pci,drive=osdisk,bootindex=0',
              '-drive',f'if=none,id=package,media=cdrom,format=raw,readonly=on,file={package}',
              '-device','ide-cd,id=package-cd,bus=ide.0,unit=0,drive=package,serial='+C['guest_operation']['input_carrier_serial'],
              '-drive',f'if=none,id=observer,media=cdrom,format=raw,readonly=on,file={observer}',
              '-device','ide-cd,id=observer-cd,bus=ide.1,unit=0,drive=observer',
              '-device','virtio-vga','-device','qemu-xhci,id=xhci',
              '-device','usb-tablet,bus=xhci.0','-device','usb-kbd,bus=xhci.0',
              '-chardev','socket,path=observer.sock,server=on,wait=off,id=obs',
              '-device','virtio-serial-pci',
              '-device','virtserialport,chardev=obs,name=opemos.robot.observer',
              '-nic','none','-display','none','-vnc','unix:vnc.sock',
              '-qmp','unix:qmp.sock,server=on,wait=off',
              '-monitor','none','-serial','none','-parallel','none',
              '-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny','-S']
        argv+=USB.virtual_usb_qemu_arguments(backing,usb_fd,nonce)
        def limit():
            resource.setrlimit(resource.RLIMIT_FSIZE,(cow_limit,cow_limit))
        qemu_launch_attempted=True
        q=subprocess.Popen(argv,cwd=f'/proc/self/fd/{runtime_fd}',stdin=subprocess.DEVNULL,
             stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=limit,start_new_session=True,pass_fds=(usb_fd,runtime_fd))
        qemu_pidfd=os.pidfd_open(q.pid)
        qemu_streams,qemu_readers=qemu_output(q,root)
        raw=(Path('/proc')/str(q.pid)/'stat').read_text();tick=raw[raw.rfind(')')+2:].split()[19]
        binding={'kind':'NORMAL_UBUNTU_GUI_BUILD_WRITE_VM_V1','nonce':nonce,
                 'pid':q.pid,'start_ticks':tick,'host_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                 'dispatch_origin':'ROOT_SCOPED_RUNTIME_PROOF',
                 'queue_unit':unit,'queue_invocation_id':invocation,
                 'queue_cgroup':Path('/proc/self/cgroup').read_text().strip(),
                 'argv':argv,'qmp_socket':str(qmp),'observer_socket':str(obs),
                 'vm_name':name,'run_directory':str(root),'artifact_source':C['candidate']['descriptor']['source_commit'],
                 'package_sha256':C['candidate']['descriptor']['package_sha256']}
        write_json(root/'binding.json',binding)
        control=qmp_connect(qmp,q.pid,CONTROL.connect_owned,q)
        need((Path('/proc')/str(q.pid)/'cgroup').read_text().strip()==binding['queue_cgroup'],
             'new QEMU not in exact admitted queue cgroup')
        socket_identity=sig(os.lstat(qmp))
        socket_pins={str(p):sig(os.lstat(p))for p in (qmp,vnc,obs)}
        need(all(stat.S_ISSOCK(p['st_mode'])and p['st_uid']==os.getuid()
                 for p in socket_pins.values()),'disposable VM socket custody differs')
        need(qmp_call(control,2,'query-name')['name']==name and
             qmp_call(control,3,'query-status')['status'] in ('prelaunch','paused'),
             'exact paused VM not observed')
        blocks={row['device']:row for row in qmp_call(control,4,'query-block')}
        need(blocks['osdisk']['inserted']['file']==str(overlay) and
             blocks['package']['inserted']['file']==str(package) and
             blocks['observer']['inserted']['file']==str(observer) and
             blocks['package']['inserted']['ro'] is True and
             blocks['observer']['inserted']['ro'] is True,
             'paused QEMU original/observer block attachment differs')
        holders=readonly_qemu_holders(q.pid,[C['base'],C['code'],C['image_carrier'],observer_iso])
        need(os.statvfs(scratch).f_bavail*os.statvfs(scratch).f_frsize>=cow_limit+500_000_000,
             'actual bounded COW growth capacity absent before cont')
        write_json(root/'paused-before-cont.json',{'binding':binding,'actual_blocks':blocks,
                   'USB':backing,'COWGrowthBound':cow_limit,
                   'readonly_original_holders':holders,'socket_pins':socket_pins,
                   'originals_readonly_hashes':{k:v['sha256']for k,v in originals.items()}})
        qmp_call(control,5,'cont');result['effects'].append('one-fresh-disposable-VM-boot')
        # The GNOME terminal is initialized through the existing QMP route.
        # Neither this shortcut nor typed script command is the tested chooser
        # activation. The latter is pointer-only in connection_control.py.
        time.sleep(45)
        result['pre_bootstrap_frame']=capture_bootstrap(control,20,root/'pre-bootstrap.png')
        result['guest_session_bootstrap']=login_guest(control,root)
        result['effects'].append('exact-retained-credential-guest-session-bootstrap-only')
        qmp_call(control,6,'input-send-event',{'events':[{'type':'key','data':{'down':True,
                 'key':{'type':'qcode','data':'ctrl'}}},
                 {'type':'key','data':{'down':True,'key':{'type':'qcode','data':'alt'}}},
                 {'type':'key','data':{'down':True,'key':{'type':'qcode','data':'t'}}}]})
        qmp_call(control,7,'input-send-event',{'events':[{'type':'key','data':{'down':False,
                 'key':{'type':'qcode','data':'t'}}},
                 {'type':'key','data':{'down':False,'key':{'type':'qcode','data':'alt'}}},
                 {'type':'key','data':{'down':False,'key':{'type':'qcode','data':'ctrl'}}}]})
        time.sleep(3)
        # The independent observer must own the virtio socket before the
        # bootstrap can fail and emit a typed refusal. It never activates the
        # chooser; its QMP pointer comes only after verified native READY.
        with contextlib.ExitStack() as channels:
            obs_sock=channels.enter_context(CONTROL.connect_owned(str(obs),q.pid,200))
            boot_text(control,'bash /media/opemosgui/OPROBOT/start.sh\n')
            result['post_bootstrap_frame']=capture_bootstrap(control,300,root/'post-bootstrap.png')
            control.close();control=None  # one actual QMP connection at a time
            native_q=channels.enter_context(CONTROL.owned_qmp(str(qmp),q.pid))
            result['effects'].append('guest-terminal-observer-bootstrap-only')
            ready=CONTROL.next_native_event(obs_sock,nonce,result)
            need(ready.get('kind')=='READY'and ready.get('port_custody',{}).get('sudo_numeric')in('0','NOT_NEEDED'),
                 'actual source-bound guest observer READY/port custody')
            guest=dict(C['guest_operation']);guest['input_path']=ready['input_path']
            need(ready['input_carrier']['serial']==C['guest_operation']['input_carrier_serial']==nonce[:20] and
                 ready['input_carrier']['relativePath']==guest['input_relative_path'],
                 'actual original guest carrier/path belongs to this admitted operation')
            pipeline=CONTROL.Pipeline(binding,guest,native_q,obs_sock,ready,root)
            pipeline.end=WHOLE_END  # original job clock; never restart it for the GUI
            def current_output_and_metadata():
                check_qemu_output(qemu_streams);metadata_guard(192*1024**2)
            pipeline.check=current_output_and_metadata
            C['virtualUSBIdentity']=backing['identity']
            robot=CONTROL.RobotPipeline(pipeline,C,C['engineRoot'],OWNED)
            pipeline.robot_click=robot.click
            try:
                result['GUI']=pipeline.build_write()
                result['GUI']['normalRobotEvidence']=robot.complete()
            finally:
                if 'GUI'not in result:
                    result['partialGUIActions']=pipeline.actions
                    result['partialNativeObservations']=pipeline.observations
        need(result['GUI']['output']['value']['bytes']>0,'actual completed guest output required')
        result['effects'].append('actual-visible-GUI-Build-and-virtual-USB-write')
        # The complete owned-VM finalizer below runs on both success and fault.
    except BaseException as error:
        first={'type':type(error).__name__,'reason':str(error)}
        result['first_failure']=first
        raise
    finally:
        CLEANUP_END=time.monotonic()+180
        if control is not None:control.close()
        secondary=[]
        if q is not None and q.poll() is None:
            try:
                raw=(Path('/proc')/str(q.pid)/'stat').read_text()
                need(raw[raw.rfind(')')+2:].split()[19]==tick and
                     Path('/proc/sys/kernel/random/boot_id').read_text().strip()==binding['host_boot_id'] and
                     [x.decode()for x in (Path('/proc')/str(q.pid)/'cmdline').read_bytes().split(b'\0')if x]==argv,
                     'finalizer QEMU birth/argv changed')
                need(sig(os.lstat(qmp))==socket_identity,
                     'owned QMP socket identity changed before finalizer')
                readonly_qemu_holders(q.pid,[C['base'],C['code'],C['image_carrier'],observer_iso])
                control=qmp_connect(qmp,q.pid,CONTROL.connect_owned,q)
                need(qmp_call(control,9,'query-name')['name']==name,
                     'finalizer VM name differs')
                if first is not None:
                    try:result['failure_frame']=capture_bootstrap(control,301,root/'failure.png')
                    except Exception as error:secondary.append('failure screenshot: '+type(error).__name__+': '+str(error))
                try:qmp_call(control,10,'system_powerdown')
                except (BrokenPipeError,ConnectionResetError,EOFError):
                    secondary.append('graceful QMP ACK UNKNOWN; exact process closure still required')
                control.close();control=None
                try:q.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    # Exact disposable VM only; Root's bounded QMP quit scope.
                    result['graceful_shutdown_timeout_first']=True
                    secondary.append('graceful shutdown timed out at 60 seconds before exact QMP quit')
                    raw=(Path('/proc')/str(q.pid)/'stat').read_text()
                    need(raw[raw.rfind(')')+2:].split()[19]==tick and
                         [x.decode()for x in (Path('/proc')/str(q.pid)/'cmdline').read_bytes().split(b'\0')if x]==argv,
                         'bounded quit birth/argv changed')
                    need(sig(os.lstat(qmp))==socket_identity,
                         'owned QMP socket identity changed before bounded quit')
                    readonly_qemu_holders(q.pid,[C['base'],C['code'],C['image_carrier'],observer_iso])
                    control=qmp_connect(qmp,q.pid,CONTROL.connect_owned,q)
                    need(qmp_call(control,11,'query-name')['name']==name,
                         'bounded quit VM name differs')
                    try:qmp_call(control,12,'quit')
                    except (BrokenPipeError,ConnectionResetError,EOFError):
                        secondary.append('QMP quit ACK UNKNOWN; process closure checked separately')
                    control.close();control=None
                    q.wait(timeout=20)
                result['qemu_numeric']=q.returncode
            except BaseException as error:
                secondary.append('owned QEMU finalizer: '+type(error).__name__+': '+str(error))
            finally:
                if control is not None:control.close();control=None
        result['qemu_pid']=q.pid if q is not None else None
        result['qemu_reaped']=q is None or q.poll() is not None
        if q is None and not qemu_launch_attempted:
            # A preboot helper refusal is not a VM closure receipt. Prove
            # exactly what did close: original bytes, owned scratch and NBD.
            # The ordinary queue's later CLOSED result remains independent.
            try:
                need(not any(os.path.lexists(root/name) for name in
                             ('qmp.sock','vnc.sock','observer.sock')),
                     'unexpected QEMU socket before VM launch')
                for pin in originals.values():input_file(pin,60_000_000_000)
                result['originals_unchanged_after']=True
                need(usb_fd is not None and 'vars_out' in locals() and
                     'overlay' in locals() and overlay.exists(),
                     'preboot generated assets incomplete; no complete closure claim')
                need(hashlib.sha256(vars_out.read_bytes()).hexdigest()==C['vars_template']['sha256'] and
                     os.fstat(usb_fd).st_blocks*512>=usb_bytes and
                     overlay.is_file() and not overlay.is_symlink() and
                     overlay.stat().st_uid==os.getuid() and
                     overlay.stat().st_nlink==1 and overlay.stat().st_size<cow_limit,
                     'preboot owned COW/USB allocation changed')
                current_cow=hashlib.sha256()
                with overlay.open('rb') as stream:
                    while block:=stream.read(4*1024*1024):current_cow.update(block)
                result['preboot_cow_after_failure']={'identity':sig(overlay.lstat()),
                                                     'sha256':current_cow.hexdigest()}
                nbd=Path('/sys/block/nbd0')
                need(nbd.is_dir() and
                     (not (nbd/'pid').exists() or not (nbd/'pid').read_text().strip()) and
                     not list((nbd/'holders').iterdir()) and
                     (nbd/'ro').read_text().strip()=='1',
                     'preboot NBD process/holder/read-only closure missing')
                for node in ('/dev/nbd0',*(str(p) for p in Path('/dev').glob('nbd0p*'))):
                    mounted=subprocess.run(['/usr/bin/findmnt','-rn','-S',node,'-o','TARGET'],
                                           capture_output=True,text=True,timeout=10)
                    need(mounted.returncode==1 and not mounted.stdout,
                         'preboot NBD or partition mount remains')
                holder=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/fuser','/dev/nbd0'],
                                      capture_output=True,text=True,timeout=10)
                need(holder.returncode==1 and not holder.stdout,
                     'preboot NBD process FD remains')
                result['preboot_nbd_closed']={'pid_absent':True,'holders_empty':True,
                                              'mounts_empty':True,'fuser_numeric':1}
                result['private_storage_closure_verified']=True
                result['closure']='PREBOOT_NO_QEMU_SOURCE_AND_NBD_CLOSED'
            except BaseException as error:
                secondary.append('preboot source/NBD closure: '+type(error).__name__+': '+str(error))
        if q is not None and q.poll() is not None:
            result['qemu_numeric']=q.returncode
            result['closure']='QEMU_REAPED'
            try:
                for key,pin in originals.items():input_file(pin,60_000_000_000)
                result['originals_unchanged_after']=True
            except BaseException as error:
                secondary.append('original postflight: '+type(error).__name__+': '+str(error))
            try:
                closed=[]
                for path,pin in socket_pins.items():
                    if os.path.lexists(path):
                        need(sig(os.lstat(path))==pin,'VM socket changed before exact cleanup')
                        os.unlink(path)
                    need(not os.path.lexists(path),'VM socket remains after exact cleanup')
                    closed.append(path)
                result['socket_closure']=closed
                need(overlay.stat().st_size<=cow_limit and
                     os.fstat(usb_fd).st_blocks*512>=usb_bytes,
                     'private COW cap/reservation no longer true at closure')
                result['private_storage_closure_verified']=True
            except BaseException as error:
                secondary.append('exact socket/storage postflight: '+type(error).__name__+': '+str(error))
        if q is not None and q.poll() is not None and result.get('GUI') is not None:
            try:
                result['hostUSBReadback']=USB.virtual_usb_readback_observed(backing,usb_fd,
                    result['GUI']['output'],pipeline.ready['process'],nonce,result['GUI']['output']['value']['path'])
            except BaseException as error:
                secondary.append('actual completed USB whole readback: '+type(error).__name__+': '+str(error))
        for reader in qemu_readers:
            reader.join(timeout=max(0,min(5,CLEANUP_END-time.monotonic())))
        result['qemu_streams']=qemu_streams
        if any(reader.is_alive()for reader in qemu_readers)or any(not r['EOF']or r['first']for r in qemu_streams.values()):
            secondary.append('actual bounded QEMU stdout/stderr EOF/capture incomplete')
        if qemu_pidfd is not None:
            try:os.close(qemu_pidfd)
            except OSError as error:secondary.append('QEMU owned pidfd close: '+str(error))
        if runtime_fd is not None:
            try:os.close(runtime_fd)
            except OSError as error:secondary.append('owned VM runtime directory FD closure: '+str(error))
        if usb_scope is not None:
            try:usb_scope.__exit__(None,None,None)
            except BaseException as error:secondary.append('owned USB FD closure: '+str(error))
        if secondary:result['secondary_failures']=secondary
        try:result['operationMetadataAllocatedBytes']=metadata_guard()
        except BaseException as error:secondary.append('metadata whole-reserve postflight: '+str(error));result['secondary_failures']=secondary
        result['GUIBuildWriteReadbackAccepted']=(result.get('first_failure') is None and
            result.get('GUI',{}).get('kind')=='ACTUAL_UBUNTU_GUI_BUILD_WRITE_OBSERVATIONS'and result.get('hostUSBReadback',{}).get('hostFlushCompleted')is True and
            result.get('qemu_reaped') is True and result.get('originals_unchanged_after') is True and
            result.get('private_storage_closure_verified') is True and
            not secondary)
        write_json(root/'job-result.json',result)
        suite=ET.Element('testsuite',name='normal-real-ubuntu-GUI-Build-write-readback',tests='1',
                         failures='0'if result['GUIBuildWriteReadbackAccepted']else'1')
        case=ET.SubElement(suite,'testcase',name='Actual GUI Build/write and independent whole USB readback')
        if not result['GUIBuildWriteReadbackAccepted']:
            failure=ET.SubElement(case,'failure',message='normal GUI Build/write/readback refused')
            failure.text=json.dumps({'first':result.get('first_failure'),
                                      'secondary':result.get('secondary_failures'),
                                      'closure':result.get('closure')},sort_keys=True)
        write_blob(root/'proof-junit.xml',ET.tostring(suite,encoding='utf-8',xml_declaration=True))
        body='<html><body><h1>Normal Ubuntu GUI Build/write/readback</h1><pre>'+html.escape(
             json.dumps(result,sort_keys=True,indent=2))+'</pre></body></html>'
        write_blob(root/'proof.html',body.encode())

if __name__=='__main__':main()

#!/usr/bin/env python3
"""One offline rule in a fresh disposable COW, before its first QEMU boot.

Only /dev/nbd0 is used, with an exclusive local claim and checked empty state.
The original backing image is held and checked read-only throughout. No mount,
fsck, guest account, password, or source image write is part of this operation.
"""
import fcntl
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import time

import job

NODE='/dev/nbd0'
SYS=Path('/sys/block/nbd0')
TARGET='/etc/udev/rules.d/99-opemos-robot-observer.rules'
RULE=b'SUBSYSTEM=="virtio-ports", ATTR{name}=="opemos.robot.observer", OWNER="1000", GROUP="1000", MODE="0600"\n'

def need(ok,reason):
    if not ok:raise RuntimeError(reason)

def cmd(argv,cap=65536,timeout=40):
    p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,timeout=timeout)
    need(len(p.stdout)<=cap and len(p.stderr)<=cap,
         'bounded offline helper output exceeded: stdout='+str(len(p.stdout))+
         ' stderr='+str(len(p.stderr))+' cap='+str(cap))
    return {'argv':argv,'numeric':p.returncode,
            'stdout':p.stdout.decode('utf8','replace'),
            'stderr':p.stderr.decode('utf8','replace')}

def sha(path):
    h=hashlib.sha256()
    with open(path,'rb',buffering=0) as f:
        while b:=f.read(4*1024*1024):h.update(b)
    return h.hexdigest()

def disconnected_sysfs_pid():
    """Only an owned successful disconnect permits a removed kernfs node."""
    try:return (SYS/'pid').read_text().strip()
    except OSError as error:
        if error.errno not in (errno.ENOENT,errno.ENODEV):raise
        return ''


def idle(after_disconnect=False):
    need(SYS.is_dir(),'NBD sysfs node absent')
    ro=(SYS/'ro').read_text().strip()
    need(ro in ('0','1'),'NBD idle read-only indicator malformed')
    absent=not disconnected_sysfs_pid() if after_disconnect else (
        not (SYS/'pid').exists() or not (SYS/'pid').read_text().strip())
    need(absent,
         'NBD already has an attached process')
    need(not list((SYS/'holders').iterdir()),'NBD has foreign holders')
    for dev in (NODE,*(str(x) for x in Path('/dev').glob('nbd0p*'))):
        mounted=cmd(['/usr/bin/findmnt','-rn','-S',dev,'-o','TARGET'])
        need(mounted['numeric']==1 and not mounted['stdout'],
             'NBD or partition already mounted')
    holders=cmd(['/usr/bin/sudo','-n','/usr/bin/fuser',NODE])
    need(holders['numeric']==1 and not holders['stdout'],
         'NBD already opened by another actor')
    return {'sysfs_pid_absent':True,'holders_empty':True,'mounts_empty':True,
            'sysfs_read_only_when_idle':ro,'fuser_numeric':1}

def nbd_process_identity(tid):
    """Bind the kernel NBD client task to its process, without treating a TID as a PIDFD."""
    def task(pid):
        proc=Path('/proc')/str(pid)
        birth=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
        fields={}
        for line in (proc/'status').read_text().splitlines():
            key,sep,value=line.partition(':')
            if sep and key in ('Pid','Tgid','Uid'):
                need(key not in fields,'ambiguous NBD task identity')
                fields[key]=value.split()
        need(set(fields)=={'Pid','Tgid','Uid'} and fields['Pid']==[str(pid)] and
             len(fields['Tgid'])==1 and fields['Tgid'][0].isdecimal() and
             fields['Uid']==['0']*4,'same uniform Root NBD payload task')
        argv=[os.fsdecode(x)for x in(proc/'cmdline').read_bytes().split(b'\0')if x]
        group=(proc/'cgroup').read_text()
        need(birth==(proc/'stat').read_text().rsplit(')',1)[1].split()[19],
             'NBD task birth changed during identity observation')
        return {'pid':pid,'tgid':int(fields['Tgid'][0]),'start_ticks':birth,
                'argv':argv,'cgroup':group}
    client=task(tid);leader=client if client['tgid']==tid else task(client['tgid'])
    need(leader['pid']==leader['tgid'] and client['tgid']==leader['pid'] and
         client['argv']==leader['argv'] and
         client['cgroup']==leader['cgroup']==Path('/proc/self/cgroup').read_text(),
         'NBD client task/process/source/current-unit join differs')
    return {'pid':leader['pid'],'start_ticks':leader['start_ticks'],'argv':leader['argv'],
            'sysfs_pid':tid,'sysfs_start_ticks':client['start_ticks'],
            'cgroup':leader['cgroup']}

def same_nbd_owner(owner):
    need((SYS/'pid').read_text().strip()==str(owner['sysfs_pid']) and
         nbd_process_identity(owner['sysfs_pid'])=={k:owner[k]for k in
             ('pid','start_ticks','argv','sysfs_pid','sysfs_start_ticks','cgroup')},
         'NBD birth/argv changed before exact operation: client task/process binding')

def attach(cow,readonly,offset=None):
    args=['/usr/bin/sudo','-n','/usr/bin/qemu-nbd']
    if readonly:args.append('--read-only')
    args+=['--format=qcow2']
    if offset is not None:args.append('--offset='+str(offset))
    args+=['--connect='+NODE,str(cow)]
    result=cmd(args,timeout=45)
    need(result['numeric']==0,'exact disposable NBD attach refused')
    for _ in range(100):
        if (SYS/'pid').exists() and (SYS/'pid').read_text().strip():break
        time.sleep(.1)
    pid_text=(SYS/'pid').read_text().strip()
    need(pid_text.isdecimal(),'NBD attached PID absent')
    identity=nbd_process_identity(int(pid_text));argv=identity['argv']
    owned=(argv and Path(argv[0]).name=='qemu-nbd' and
           '--connect='+NODE in argv and str(cow) in argv and
           (('--read-only' in argv)==readonly) and
           (offset is None or '--offset='+str(offset) in argv))
    need(owned,'NBD attached process/source/offset is not ours; no detach attempted')
    owner=dict(identity,read_only=readonly,offset=offset)
    same_nbd_owner(owner)
    if (SYS/'ro').read_text().strip()!=('1' if readonly else '0'):
        detach(owner)
        raise RuntimeError('owned NBD read-only mode differs; detached')
    return owner

def detach(owner,record=None):
    if owner is None:return None
    need(not owner.get('disconnect_started'),'owned NBD disconnect already started; never repeat')
    owner['disconnect_started']=True;owner['disconnect_phase']='VALIDATING'
    import select
    pid=owner['pid'];proc=Path('/proc')/str(pid)
    def same_attached_birth():
        same_nbd_owner(owner)
    same_attached_birth();pidfd=os.pidfd_open(pid,0)
    try:
        same_attached_birth()
        exited=select.poll();exited.register(pidfd,select.POLLIN)
        owner['disconnect_attempted']=True;owner['disconnect_phase']='ISSUING'
        if record is not None:record('attempt',owner)
        try:result=cmd(['/usr/bin/sudo','-n','/usr/bin/qemu-nbd','--disconnect',NODE],timeout=40)
        except BaseException as error:
            owner['disconnect_phase']='COMMAND_UNKNOWN'
            owner['disconnect_error']={'type':type(error).__name__,'reason':str(error)}
            if record is not None:record('command-unknown',owner)
            raise
        owner['disconnect_result']=result;owner['disconnect_phase']='RETURNED'
        if record is not None:record('result',owner)
        need(result['numeric']==0,'owned NBD disconnect refused')
        owner['disconnect_phase']='OBSERVING'
        started=time.monotonic();deadline=started+10
        while True:
            need(time.monotonic()<deadline,'owned NBD closure observation deadline expired')
            associated=disconnected_sysfs_pid()
            need(associated in('',str(owner['sysfs_pid'])),
                 'NBD association replaced after owned disconnect')
            try:birth=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
            except (FileNotFoundError,ProcessLookupError):birth=None
            need(birth is None or birth==owner['start_ticks'],'NBD PID reused during exact closure observation')
            try:
                thread_birth=(Path('/proc')/str(owner['sysfs_pid'])/'stat').read_text().rsplit(')',1)[1].split()[19]
            except (FileNotFoundError,ProcessLookupError):thread_birth=None
            need(thread_birth is None or thread_birth==owner['sysfs_start_ticks'],
                 'NBD client task reused during exact closure observation')
            gone=birth is None and thread_birth is None and bool(exited.poll(0))
            need(time.monotonic()<deadline,'late owned NBD closure refused')
            # sysfs may clear BEFORE the same daemon disappears from /proc.
            # Wait for BOTH in the original finite window; never detach again,
            # signal a process or infer native closure from sysfs alone.
            if not associated and gone:break
            remaining=deadline-time.monotonic()
            need(remaining>0,'owned NBD process/association not gone after disconnect')
            time.sleep(min(.1,remaining))
        closed={'disconnect_numeric':0,'pid_absent':True,'client_task_absent':True,
                'original_pidfd_exited':True,
                'closure_wait_seconds':time.monotonic()-started,**idle(after_disconnect=True)}
        owner['disconnect_phase']='CLOSED';owner['disconnect_closure']=closed
        if record is not None:record('closed',owner)
        return closed
    finally:os.close(pidfd)

def debugfs(request,writable=False,cap=65536):
    args=['/usr/bin/sudo','-n','/usr/sbin/debugfs']
    if writable:args.append('-w')
    args+=['-R',request,NODE]
    result=cmd(args,cap)
    need(result['numeric']==0 and
         not re.search(r'(not found|not a directory|file exists|error|invalid|could not)',
                       result['stderr'],re.I),
         'offline ext4 request refused: '+request.split()[0])
    return result

def exact_partition_export(frame,expected_bytes):
    """Consume the actual uncached blkid export without inferring TYPE from magic."""
    values={}
    for line in frame['stdout'].splitlines():
        key,sep,value=line.partition('=')
        need(sep and key not in values and key and value,
             'ambiguous uncached partition export')
        values[key]=value
    need(frame['numeric']==0 and
         values.get('DEVNAME')==NODE and values.get('TYPE')=='ext4' and
         values.get('USAGE')=='filesystem' and
         values.get('FSBLOCKSIZE')=='4096' and
         values.get('FSSIZE')==str(expected_bytes),
         'reviewed guest partition export/geometry is not exact ext4')
    return values

def readonly_partition_probe(cow,owner,offset,identity,frames):
    """Wait at most two seconds for this same owned read-only export.

    NBD can publish its PID/RO state before blkid identifies the new view.
    Only an empty exit-2 result is eligible for another complete probe.
    Every actual result is retained; filesystem acceptance remains separate.
    """
    fd=os.open(cow,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    deadline=time.monotonic()+2
    def same_view():
        need(job.sig(os.fstat(fd))==identity==job.sig(cow.lstat()),
             'readonly partition source epoch changed')
        need(owner['read_only']is True and owner['offset']==offset and
             str(cow)in owner['argv'] and '--read-only'in owner['argv'] and
             '--offset='+str(offset)in owner['argv'] and
             (SYS/'ro').read_text().strip()=='1'and not list((SYS/'holders').iterdir()),
             'readonly partition association changed; no further probe')
        same_nbd_owner(owner)
    try:
        while True:
            same_view();remaining=deadline-time.monotonic()
            need(remaining>0,'original readonly partition probe deadline expired')
            frame=cmd(['/usr/bin/sudo','-n','/usr/sbin/blkid','-p','-o','export',NODE],
                      timeout=min(40,remaining))
            frames.append(frame)
            need(time.monotonic()<deadline,'late readonly partition probe refused')
            same_view()
            if frame['numeric']!=2 or frame['stdout']or frame['stderr']:
                return frame
            remaining=deadline-time.monotonic()
            if remaining<=.25:return frame
            time.sleep(min(.25,remaining))
    finally:os.close(fd)

def source_build_guest_files(config):
    """Nonce-bound files only in this fresh disposable COW, never the host."""
    source_build=config['kind']=='ROOT_ADMITTED_UBUNTU_SOURCE_BUILD_V1'
    if not source_build and 'guest_prerequisites'not in config:return []
    nonce=config['nonce']
    if source_build:
        definition=config['source_input']['descriptor']['input']
        input_path='/media/opemosgui/OPROBOT/ubuntu-source-inputs.tar'
        input_sha=definition['archive_sha256']
    else:
        definition=config['guest_prerequisites']
        input_path='/media/opemosgui/OPROBOT/candidate/'+definition['relative_path']
        input_sha=definition['tar_sha256']
    need(re.fullmatch('[0-9a-f]{32}',nonce),'same source-build guest identity')
    program=job.held_source(Path(config['programRoot'])/'ubuntu_guest_build.py',1000,0o500,
                           config['normalPolicy']['programSHA256']['ubuntu_guest_build.py'])
    stem='/usr/local/bin/opemos-source-build-'+nonce
    guest={'nonce':nonce,'input_archive':input_path,
           'input_sha256':input_sha,'expanded_bytes':definition['expanded_bytes'],
           'packages':definition['packages']}
    sudo=('opemosgui ALL=(root) NOPASSWD: /usr/bin/python3 -I -B '+stem+
          '.py --install-prerequisites\n').encode()
    return [(stem+'.py',program,0o755),
            (stem+'.json',(json.dumps(guest,sort_keys=True)+'\n').encode(),0o600),
            ('/etc/sudoers.d/opemos-source-build-'+nonce,sudo,0o440)]


def write_guest_source_files(config,root):
    files=source_build_guest_files(config);result=[]
    for index,(target,raw,mode)in enumerate(files):
        parent=str(Path(target).parent)
        meta=debugfs('stat '+parent)
        match=re.search(r'Type:\s*directory\s+Mode:\s*([0-7]+)',meta['stdout'])
        need(match and not int(match[1],8)&0o022 and
             re.search(r'User:\s*0\s+Group:\s*0',meta['stdout']),
             'protected guest prerequisite/source helper ancestry')
        absent=cmd(['/usr/bin/sudo','-n','/usr/sbin/debugfs','-R','stat '+target,NODE])
        need(absent['numeric']==0 and 'File not found by ext2_lookup'in absent['stderr'],
             'guest source helper target already exists; no overwrite')
        source=root/('source-build-guest-'+str(index)+'.new')
        fd=os.open(source,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            view=memoryview(raw)
            while view:
                n=os.write(fd,view);need(n>0,'guest source helper write stalled');view=view[n:]
            os.fsync(fd)
        finally:os.close(fd)
        written=debugfs('write '+str(source)+' '+target,True)
        need(re.fullmatch(r'Allocated inode: [0-9]+\n?',written['stdout']),
             'create-only guest source helper allocation')
        for field,value in(('uid','0'),('gid','0'),('mode','0'+format(0o100000|mode,'o'))):
            debugfs('sif '+target+' '+field+' '+value,True)
        readback=debugfs('cat '+target,cap=262144)
        need(readback['stdout'].encode()==raw,'whole guest source helper readback')
        meta=debugfs('stat '+target)
        need(re.search(r'Type:\s*regular\s+Mode:\s*0?'+format(mode,'o')+r'\b',meta['stdout']) and
             re.search(r'User:\s*0\s+Group:\s*0',meta['stdout']) and
             re.search(r'Links:\s*1\b',meta['stdout']), 'guest source helper metadata')
        result.append({'path':target,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                       'uid':0,'gid':0,'mode':oct(mode),'readback':True})
    return result


def mask_guest_update_notifier(config,root):
    """Disable ambient upgrade popups only in this not-yet-booted GUI COW."""
    need(config['kind']=='ROOT_ADMITTED_UBUNTU_GUI_BUILD_WRITE_V1',
         'update notifier mask is only for the disposable GUI guest')
    target='/etc/xdg/autostart/update-notifier.desktop'
    for directory in('/etc','/etc/xdg','/etc/xdg/autostart'):
        meta=debugfs('stat '+directory)['stdout']
        need(re.search(r'Type:\s*directory\s+Mode:\s*0?755\b',meta) and
             re.search(r'User:\s*0\s+Group:\s*0',meta),'protected guest autostart ancestry')
    meta=debugfs('stat '+target)['stdout']
    need(re.search(r'Type:\s*regular\s+Mode:\s*0?644\b',meta) and
         re.search(r'User:\s*0\s+Group:\s*0',meta) and
         re.search(r'Links:\s*1\b',meta),'original guest update notifier custody')
    size=re.search(r'(?m)^User:[^\n]*\bSize:\s*([0-9]+)\b',meta)
    need(size and 0<int(size[1])<=65536,'bounded original guest update notifier size')
    # Translated Ubuntu desktop entries can exceed 8 KiB. Use the existing
    # offline-helper bound and retain the whole authenticated original.
    original=debugfs('cat '+target)['stdout']
    need(len(original.encode())==int(size[1]),'whole original guest update notifier size')
    import configparser
    desktop=configparser.ConfigParser(interpolation=None)
    desktop.read_string(original)
    need(desktop['Desktop Entry'].get('Type')=='Application' and
         desktop['Desktop Entry'].get('Exec') in('update-notifier','/usr/bin/update-notifier'),
         'exact original Ubuntu update notifier, no arbitrary autostart target')
    raw=b'[Desktop Entry]\nType=Application\nName=Update Notifier\nHidden=true\n'
    source=root/'guest-update-notifier-mask.new'
    fd=os.open(source,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:need(os.write(fd,raw)==len(raw),'short guest autostart mask write');os.fsync(fd)
    finally:os.close(fd)
    debugfs('rm '+target,True)
    written=debugfs('write '+str(source)+' '+target,True)
    need(re.fullmatch(r'Allocated inode: [0-9]+\n?',written['stdout']),
         'fresh guest autostart mask allocation')
    for field,value in(('uid','0'),('gid','0'),('mode','0100644')):
        debugfs('sif '+target+' '+field+' '+value,True)
    need(debugfs('cat '+target)['stdout'].encode()==raw,'whole guest autostart mask readback')
    meta=debugfs('stat '+target)['stdout']
    need(re.search(r'Type:\s*regular\s+Mode:\s*0?644\b',meta) and
         re.search(r'User:\s*0\s+Group:\s*0',meta) and
         re.search(r'Links:\s*1\b',meta),'guest autostart mask custody after write')
    return {'path':target,'original':original,'originalSHA256':hashlib.sha256(original.encode()).hexdigest(),
            'maskSHA256':hashlib.sha256(raw).hexdigest(),'readback':True,
            'scope':'fresh disposable GUI COW before first boot; original backing unchanged'}


def main():
    resource.setrlimit(resource.RLIMIT_FSIZE,(4_000_000_000,4_000_000_000))
    def deadline(_signal,_frame):
        raise TimeoutError('bounded exact disposable-COW offline rule deadline')
    signal.signal(signal.SIGALRM,deadline)
    signal.setitimer(signal.ITIMER_REAL,330)
    need(len(sys.argv)==2,'one exact private queue config required')
    config=Path(sys.argv[1]);need(config.resolve()==config and config.parent==job.HERE,
                             'exact admitted fixed-source config required')
    c=job.authenticated_config(config)
    job.authenticated_programs(c);nonce=c.get('nonce','')
    need(re.fullmatch(r'[0-9a-f]{32}',nonce or '')and
         c['kind']in('ROOT_ADMITTED_UBUNTU_GUI_BUILD_WRITE_V1',job.SOURCE_KIND),
         'same actual ordinary queue operation')
    unit,invocation,group=job.current_queue_identity(c)
    root=Path(c['programRoot']).parent/'runtime'
    need(root.is_dir() and root.stat().st_uid==os.getuid() and
         stat.S_IMODE(root.stat().st_mode)==0o700 and
         root.stat().st_dev==c['ext4_dev'],'fresh private COW root differs')
    storage=c['runtime_storage'];cow=Path(storage['cowPath'])
    need(cow==Path(c['programRoot']).parent/'scratch/desktop-overlay.qcow2'and
         storage['mountNamespace']==os.readlink('/proc/self/ns/mnt')and
         cow.parent.stat().st_dev==storage['device'],'same actual private ext4 COW namespace')
    need(cow.is_file() and not cow.is_symlink() and cow.stat().st_uid==os.getuid() and
         cow.stat().st_nlink==1 and cow.stat().st_size<4_000_000_000 and
         not os.path.lexists(root/'observer-rule-provision.json'),
         'exact new capped COW/provision output differs')
    cow_users=cmd(['/usr/bin/sudo','-n','/usr/bin/fuser',str(cow)])
    need(cow_users['numeric']==1 and not cow_users['stdout'],
         'fresh COW has an active holder before offline-only rule write')
    base=job.input_file(c['base'],60_000_000_000)
    need(c['base']['sha256']==c['normalPolicy']['originalSHA256']['base'],'Root-pinned original base hash')
    basefd=os.open(base,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    need(os.fstat(basefd).st_ino==c['base']['identity']['st_ino'],
         'readonly held original base differs')
    need(fcntl.fcntl(basefd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY,
         'held original backing FD is not readonly')
    lockfd=os.open(job.RUNTIME/'robot-observer-nbd0.lock',
                   os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    lockstat=os.fstat(lockfd)
    need(stat.S_ISREG(lockstat.st_mode) and lockstat.st_uid==os.getuid() and
         lockstat.st_nlink==1 and stat.S_IMODE(lockstat.st_mode)==0o600,
         'exclusive NBD claim file custody differs')
    fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    owner=None;out={'kind':'EXACT_DISPOSABLE_COW_OBSERVER_UDEV_RULE',
                    'nonce':nonce,'cow':str(cow),'original':str(base),
                    'rule_sha256':hashlib.sha256(RULE).hexdigest(),
                    'target':TARGET,'accepted':False,'first_failure':None}
    first=None
    disconnect_record_number=0
    def record_disconnect(phase,value):
        nonlocal disconnect_record_number
        disconnect_record_number+=1
        path=root/('observer-disconnect-'+str(disconnect_record_number).zfill(2)+'-'+phase+'.json')
        job.write_json(path,value)
        out.setdefault('disconnect_records',[]).append({'phase':phase,'path':str(path),
            'sha256':sha(path),'identity':job.sig(path.lstat())})
    try:
        out['pre_idle']=idle()
        out['cow_before']={'identity':job.sig(cow.lstat()),'sha256':sha(cow)}
        raw_info=cmd(['/usr/bin/qemu-img','info','--output=json','--backing-chain',str(cow)])
        need(raw_info['numeric']==0,'fresh COW ancestry unavailable')
        chain=json.loads(raw_info['stdout'])
        need(len(chain)==2 and chain[0]['filename']==str(cow) and
             chain[0]['backing-filename']==str(base) and
             chain[1]['filename']==str(base) and
             chain[0]['virtual-size']==chain[1]['virtual-size']==40_000_000_000 and
             not chain[1].get('backing-filename'),
             'exact original readonly COW ancestry differs')
        out['raw_nbd']=attach(cow,True);owner=out['raw_nbd']
        partitions=cmd(['/usr/bin/sudo','-n','/usr/sbin/sfdisk','--json',NODE])
        need(partitions['numeric']==0,'readonly partition proof unavailable')
        table=json.loads(partitions['stdout'])['partitiontable']
        selected=[p for p in table.get('partitions',[]) if
                  str(p.get('type','')).lower()=='0fc63daf-8483-4772-8e79-3d69d8477de4']
        need(table.get('sectorsize')==512 and len(selected)==1 and
             selected[0].get('start')==2203648 and selected[0].get('size')==75917312,
             'reviewed original ext4 partition geometry changed')
        offset=selected[0]['start']*table['sectorsize']
        out['partition']={'offset':offset,'type':selected[0]['type'],
                          'start':selected[0]['start'],'size':selected[0]['size']}
        out['raw_detach']=detach(owner,record_disconnect);owner=None
        out['partition_nbd_ro']=attach(cow,True,offset);owner=out['partition_nbd_ro']
        # The actual RO NBD diagnostic returned empty/2 initially and exact
        # ext4 export later in the same association, without a cache flush.
        # Retain every frame and require the unchanged exact export below;
        # neither read timing nor superblock magic establishes acceptance.
        out['partition_type_probes']=[]
        kind=readonly_partition_probe(cow,owner,offset,
                                     out['cow_before']['identity'],out['partition_type_probes'])
        out['partition_type_probe']=kind
        out['partition_type_values']=exact_partition_export(
             kind,selected[0]['size']*table['sectorsize'])
        for directory in ('/etc','/etc/udev','/etc/udev/rules.d'):
            meta=debugfs('stat '+directory)
            need(re.search(r'Type:\s*directory\s+Mode:\s+0?755',meta['stdout']) and
                 re.search(r'User:\s*0\s+Group:\s*0',meta['stdout']),
                 'guest udev rule ancestor owner/type/mode differs')
        absent=cmd(['/usr/bin/sudo','-n','/usr/sbin/debugfs','-R','stat '+TARGET,NODE])
        need(absent['numeric']==0 and 'File not found by ext2_lookup' in absent['stderr'],
             'exact guest udev rule target already exists or lookup unexpected')
        out['partition_detach']=detach(owner,record_disconnect);owner=None
        out['partition_nbd_rw']=attach(cow,False,offset);owner=out['partition_nbd_rw']
        rule_file=root/'observer-rule.new'
        fd=os.open(rule_file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:need(os.write(fd,RULE)==len(RULE),'short rule source write');os.fsync(fd)
        finally:os.close(fd)
        need(rule_file.read_bytes()==RULE,'source rule bytes differ')
        created=debugfs('write '+str(rule_file)+' '+TARGET,True)
        need(re.fullmatch(r'Allocated inode: [0-9]+\n?',created['stdout']),
             'exact create-only debugfs result missing')
        for field,value in (('uid','0'),('gid','0'),('mode','0100644')):
            debugfs('sif '+TARGET+' '+field+' '+value,True)
        readback=debugfs('cat '+TARGET)
        need(readback['stdout'].encode()==RULE,'offline guest udev rule readback differs')
        metadata=debugfs('stat '+TARGET)
        need(re.search(r'Type:\s*regular\s+Mode:\s+0?644',metadata['stdout']) and
             re.search(r'User:\s*0\s+Group:\s*0',metadata['stdout']) and
             re.search(r'Links:\s*1\b',metadata['stdout']) and
             re.search(r'Size:\s*'+str(len(RULE))+r'\b',metadata['stdout']),
             'offline guest udev rule metadata differs')
        out['guest_rule']={'bytes':len(RULE),'sha256':hashlib.sha256(RULE).hexdigest(),
                           'uid':0,'gid':0,'mode':'0644','readback':True}
        if c['kind']=='ROOT_ADMITTED_UBUNTU_SOURCE_BUILD_V1'or 'guest_prerequisites'in c:
            out['guest_source_build_files']=write_guest_source_files(c,root)
        if c['kind']=='ROOT_ADMITTED_UBUNTU_GUI_BUILD_WRITE_V1':
            out['guest_update_notifier_mask']=mask_guest_update_notifier(c,root)
        out['write_detach']=detach(owner,record_disconnect);owner=None
        out['cow_after']={'identity':job.sig(cow.lstat()),'sha256':sha(cow)}
        before=out['cow_before']['identity'];after=out['cow_after']['identity']
        need(all(before[k]==after[k]for k in
                 ('st_dev','st_ino','st_uid','st_gid','st_nlink','st_mode')) and
             out['cow_after']['sha256']!=out['cow_before']['sha256'] and
             cow.stat().st_size<4_000_000_000,
             'offline fresh COW physical custody/write proof differs')
        out['base_post_sha256']=sha(base)
        need(job.sig(os.fstat(basefd))==c['base']['identity']==job.sig(base.lstat()) and
             out['base_post_sha256']==c['base']['sha256'],
             'held readonly original base changed during offline rule write')
        out['post_idle']=idle();out['accepted']=True
    except BaseException as error:
        first={'type':type(error).__name__,'reason':str(error)}
        out['first_failure']=first
    finally:
        if owner is not None:
            if owner.get('disconnect_started'):
                out['failure_detach']={'not_repeated':True,
                    'command_attempted':owner.get('disconnect_attempted',False),
                    'phase':owner['disconnect_phase'],
                    'closure':owner.get('disconnect_closure','UNKNOWN')}
            else:
                try:out['failure_detach']=detach(owner,record_disconnect)
                except BaseException as error:
                    out['secondary_failure']={'type':type(error).__name__,'reason':str(error)}
        os.close(basefd);os.close(lockfd)
        job.write_json(root/'observer-rule-provision.json',out)
    need(out['accepted'] and not out.get('secondary_failure'),
         'disposable COW udev rule provision refused: '+repr(first))
    signal.setitimer(signal.ITIMER_REAL,0)
    print(json.dumps({'receipt':str(root/'observer-rule-provision.json'),
                      'cow_sha256':out['cow_after']['sha256'],
                      'rule_sha256':out['rule_sha256'],'accepted':True},sort_keys=True))

# Reused normal cold-executor file-backed ext4 API; originals are never targets.
class Storage:
 def __init__(self,c,C,N,W):self.c=c;self.C=C;self.N=N;self.W=W;self.raw=None;self.loop=None;self.mountfd=None;self.loopfd=None;self.rawIdentity=None;self.mounted=False;self.acquired=[]
 def open(self):
  c=self.c;C=self.C;N=self.N
  C.require(os.getresuid()==(0,0,0),'actual Root storage owner');C.require(os.readlink('/proc/self/ns/mnt')!=c['outerMountNamespace'],'new actual private mount namespace')
  C.require(not any(os.path.lexists(c[k])for k in ('fixedBacking','mount')),'absent fresh backing/mount')
  self.raw=os.open(c['fixedBacking'],os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);self.acquired.append('created-backing');os.fchown(self.raw,0,0);os.fchmod(self.raw,0o600);C.require(os.fstat(self.raw).st_uid==os.fstat(self.raw).st_gid==0 and stat.S_IMODE(os.fstat(self.raw).st_mode)==0o600,'actual Root-only generated raw backing');self.rawCreatedIdentity=C.F(os.fstat(self.raw))
  os.posix_fallocate(self.raw,0,c['fixedStorageBytes']);os.fsync(self.raw);a=os.fstat(self.raw);C.require(a.st_size==c['fixedStorageBytes']and a.st_blocks*512<=c['fixedStorageBytes']and Fsame(a,Path(c['fixedBacking']).lstat(),C),'actual fixed backing physical/logical absolute capacity',C.F(a));self.rawIdentity=C.F(a)
  b,_=N.checked(['/usr/sbin/losetup','--find','--show','--nooverlap',c['fixedBacking']],15,'loop-create');self.loop=b.decode().strip();self.acquired.append('returned-loop');C.require(self.loop.startswith('/dev/loop')and self.loop[9:].isdigit(),'actual returned loop association',self.loop)
  self.association('loop-before-format');self.loopfd=os.open(self.loop,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);self.acquired.append('held-own-loop-FD');C.require(stat.S_ISBLK(os.fstat(self.loopfd).st_mode)and os.major(os.fstat(self.loopfd).st_rdev)==7,'exact owned mutable storage loop FD');N.checked(['/usr/sbin/mkfs.ext4','-F','-q','-m','0',self.loop],120,'mkfs');os.mkdir(c['mount'],0o700);self.acquired.append('created-mount-directory')
  N.checked(['/usr/bin/mount','-t','ext4','-o','rw,nosuid,nodev,noexec',self.loop,c['mount']],15,'mount');self.mounted=True;self.acquired.append('mounted')
  self.mountfd=os.open(c['mount'],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  self.mountIdentity=C.F(os.fstat(self.mountfd));self.check('before-mounted-root-permissions')
  C.require(os.fstat(self.mountfd).st_dev==os.fstat(self.loopfd).st_rdev,
            'held mounted root belongs to exact own loop')
  # Mounting hides the 0700 mountpoint with ext4's newly formatted root (0755).
  # Change only that held filesystem root, never a pathname or a prior volume.
  os.fchown(self.mountfd,1000,1000);os.fchmod(self.mountfd,0o700);os.fsync(self.mountfd)
  root=os.fstat(self.mountfd)
  C.require(root.st_uid==root.st_gid==1000 and stat.S_IMODE(root.st_mode)==0o700 and
            Fsame(root,Path(c['mount']).lstat(),C),'actual private ordinary mounted root owner/mode')
  self.mountIdentity=C.F(root);self.check('mounted');return self
 def association(self,stem):
  b,_=self.N.checked(['/usr/sbin/losetup','--json','--list','--output','NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT,RO',self.loop],15,stem)
  rows=json.loads(b)['loopdevices'];self.C.require(len(rows)==1,'one exact owned loop');r=rows[0];self.C.require(r['name']==self.loop and r['back-file']==self.c['fixedBacking']and int(r['back-ino'])==self.rawIdentity['st_ino']and r['back-maj:min']==str(os.major(self.rawIdentity['st_dev']))+':'+str(os.minor(self.rawIdentity['st_dev']))and r['ro']is False and int(r['offset'])==0 and int(r['sizelimit'])in(0,self.c['fixedStorageBytes']),'loop backed by exact generated inode',r);return r
 def check(self,stem):
  C=self.C;a=os.fstat(self.raw);C.require(all(getattr(a,k)==self.rawIdentity[k]for k in C.K if k not in ('st_mtime_ns','st_ctime_ns'))and mutable_same(a,Path(self.c['fixedBacking']).lstat(),C),'held fixed backing immutable identity/size',C.F(a));C.require(a.st_blocks*512<=self.c['fixedStorageBytes'],'hard backing allocated charge')
  if self.mountfd is not None:
   C.require(Fsame(os.fstat(self.mountfd),Path(self.c['mount']).lstat(),C),'same held mount root')
   mi=Path('/proc/self/fdinfo',str(self.mountfd)).read_text();mid=next(x.split()[1]for x in mi.splitlines()if x.startswith('mnt_id:'));entries=[x.split()for x in Path('/proc/self/mountinfo').read_text().splitlines()if x.split()[0]==mid];C.require(len(entries)==1 and entries[0][4]==self.c['mount']and entries[0][entries[0].index('-')+1]=='ext4','FD mount-id exact ext4 membership')
   sv=os.fstatvfs(self.mountfd);C.require(sv.f_blocks*sv.f_frsize<=self.c['fixedStorageBytes'],'absolute inner filesystem capacity');return {'backing':C.F(a),'mountID':mid,'device':os.fstat(self.mountfd).st_dev,'availableBytes':sv.f_bavail*sv.f_frsize,'innerTotal':sv.f_blocks*sv.f_frsize}
 def close(self,quietProof):
  C=self.C;errors=[]
  # Caller must provide fresh independently collected whole-own-unit/FD proof,
  # no terminal.json boolean or direct-child poll is a cleanup authorization.
  C.require(quietProof['kind']=='INDEPENDENT_ROOT_CURRENT_STORAGE_QUIET'and quietProof['jobId']==self.c['jobId']and quietProof['boot']==self.c['boot']and quietProof['unknown']==[]and quietProof['foreignHolders']==[]and quietProof['otherMountNamespaces']==[]and quietProof['allOwnChildrenReaped']is True and (quietProof['original']is None or quietProof['originalAbsent']is True),'independent same-host cleanup proof',quietProof)
  before=self.state()
  if self.raw is not None:
   actual=C.F(os.fstat(self.raw));named=C.F(Path(self.c['fixedBacking']).lstat());expected=self.rawCreatedIdentity
   C.require(actual==named and all(actual[k]==expected[k]for k in C.K if k not in ('st_size','st_mtime_ns','st_ctime_ns'))and actual['st_size']<=self.c['fixedStorageBytes'],'same exact acquired bounded backing before partial/normal cleanup',actual)
  if self.loop is not None:self.association('loop-before-unmount')
  if self.mountfd is not None:os.close(self.mountfd);self.mountfd=None
  if self.mounted:self.N.checked(['/usr/bin/umount',self.c['mount']],15,'umount');self.mounted=False
  if self.loop is not None:
   self.association('own-loop-held-after-unmount')
   self.N.checked(['/usr/sbin/losetup','--detach',self.loop],15,'loop-detach')
   if self.loopfd is not None:os.close(self.loopfd);self.loopfd=None
   current=Path('/sys/block')/Path(self.loop).name/'loop/backing_file'
   C.require(not current.exists()or not current.read_text().strip(),'actual own loop association absent after ordered FD close')
   self.loop=None
  if self.raw is not None:os.fsync(self.raw);os.close(self.raw);self.raw=None
  # Never unlink backing/USB/failed state; retained qualified or partial data.
  return {'unmountedNormally':True,'loopDetachedNormally':True,'backingRetained':bool(self.acquired),'acquired':list(self.acquired),'before':before,'after':self.state(),'errors':errors}
 def state(self):
  return {'rawFDHeld':self.raw is not None,'loop':self.loop,'mounted':self.mounted,'mountFDHeld':self.mountfd is not None,'ownLoopFDHeld':self.loopfd is not None,'acquired':list(self.acquired)}
def Fsame(a,b,C):return C.F(a)==C.F(b)

def mutable_same(a,b,C):
 # Only the exact generated fixed-capacity raw backing is mutable. Preserve full
 # observations; require immutable7/held named identity while QEMU is writing.
 # Original/code/vars/source media and stopped data still use full9+whole hash.
 left=C.F(a);right=C.F(b)
 return all(left[k]==right[k]for k in C.K if k not in('st_mtime_ns','st_ctime_ns'))


if __name__=='__main__':main()

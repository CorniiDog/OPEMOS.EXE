#!/usr/bin/env python3
"""One offline rule in a fresh disposable COW, before its first QEMU boot.

Only /dev/nbd0 is used, with an exclusive local claim and checked empty state.
The original backing image is held and checked read-only throughout. No mount,
fsck, guest account, password, or source image write is part of this operation.
"""
import fcntl
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
    need(len(p.stdout)<=cap and len(p.stderr)<=cap,'bounded offline helper output exceeded')
    return {'argv':argv,'numeric':p.returncode,
            'stdout':p.stdout.decode('utf8','replace'),
            'stderr':p.stderr.decode('utf8','replace')}

def sha(path):
    h=hashlib.sha256()
    with open(path,'rb',buffering=0) as f:
        while b:=f.read(4*1024*1024):h.update(b)
    return h.hexdigest()

def idle():
    need(SYS.is_dir(),'NBD sysfs node absent')
    ro=(SYS/'ro').read_text().strip()
    need(ro in ('0','1'),'NBD idle read-only indicator malformed')
    need(not (SYS/'pid').exists() or not (SYS/'pid').read_text().strip(),
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
    proc=Path('/proc')/pid_text
    argv=[x.decode() for x in (proc/'cmdline').read_bytes().split(b'\0') if x]
    raw=(proc/'stat').read_text()
    tick=raw[raw.rfind(')')+2:].split()[19]
    owned=(argv and Path(argv[0]).name=='qemu-nbd' and
           '--connect='+NODE in argv and str(cow) in argv and
           (('--read-only' in argv)==readonly) and
           (offset is None or '--offset='+str(offset) in argv))
    need(owned,'NBD attached process/source/offset is not ours; no detach attempted')
    owner={'pid':int(pid_text),'start_ticks':tick,'argv':argv,
           'read_only':readonly,'offset':offset}
    if (SYS/'ro').read_text().strip()!=('1' if readonly else '0'):
        detach(owner)
        raise RuntimeError('owned NBD read-only mode differs; detached')
    return owner

def detach(owner):
    if owner is None:return None
    pid=owner['pid'];proc=Path('/proc')/str(pid)
    need(proc.exists() and
         (proc/'stat').read_text().split(')')[-1].split()[19]==owner['start_ticks'] and
         [x.decode() for x in (proc/'cmdline').read_bytes().split(b'\0') if x]==owner['argv'] and
         (SYS/'pid').read_text().strip()==str(pid),
         'NBD birth/argv changed before exact detach')
    result=cmd(['/usr/bin/sudo','-n','/usr/bin/qemu-nbd','--disconnect',NODE],timeout=40)
    need(result['numeric']==0,'owned NBD disconnect refused')
    for _ in range(100):
        if not (SYS/'pid').exists() or not (SYS/'pid').read_text().strip():break
        time.sleep(.1)
    need(not proc.exists(),'owned NBD process not gone after disconnect')
    return {'disconnect_numeric':0,'pid_absent':True,**idle()}

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
    need(re.fullmatch(r'[0-9a-f]{32}',nonce or '') and
         c.get('kind')=='ROOT_ADMITTED_UBUNTU_GUI_BUILD_WRITE_V1' and
         c.get('queue_unit') in Path('/proc/self/cgroup').read_text(),
         'fresh ordinary queue identity missing')
    unit=c['queue_unit'];invocation=c.get('queue_invocation_id')
    need(isinstance(invocation,str) and re.fullmatch(r'[0-9a-f]{32}',invocation),
         'exact admitted queue invocation absent')
    show=cmd(['/usr/bin/systemctl','show',unit,'-p','InvocationID','-p','ActiveState'])
    need(show['numeric']==0 and
         'InvocationID='+invocation in show['stdout'].splitlines() and
         'ActiveState=active' in show['stdout'].splitlines(),
         'current queue InvocationID or active state changed before offline rule')
    root=job.RUNTIME/('robot-ubuntu-'+nonce)
    need(root.is_dir() and root.stat().st_uid==os.getuid() and
         stat.S_IMODE(root.stat().st_mode)==0o700 and
         root.stat().st_dev==c['ext4_dev'],'fresh private COW root differs')
    cow=root/'desktop-overlay.qcow2'
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
        out['raw_detach']=detach(owner);owner=None
        out['partition_nbd_ro']=attach(cow,True,offset);owner=out['partition_nbd_ro']
        # The actual stopped COW gave numeric 2/empty streams for `-o value
        # -s TYPE` although the same uncached probe with `-o export` returned
        # TYPE=ext4 and debugfs read the root inode. Preserve the complete
        # command frame before any refusal; never infer a filesystem from an
        # unrecorded exit or magic alone.
        kind=cmd(['/usr/bin/sudo','-n','/usr/sbin/blkid','-p','-o','export',NODE])
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
        out['partition_detach']=detach(owner);owner=None
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
        out['write_detach']=detach(owner);owner=None
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
            try:out['failure_detach']=detach(owner)
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

if __name__=='__main__':main()

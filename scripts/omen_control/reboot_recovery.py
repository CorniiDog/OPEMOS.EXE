#!/usr/bin/python3
"""Failed-only, normal queue reconciliation after an authenticated host reboot.

The installed Root profile/code and real journal/kernel facts are authority.
Candidate code, AI presence and a previous /run grant are never authority here.
This command cannot dispatch, mount, restore ACLs, control a VM or change PCI.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import uuid

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
PROFILE_ROOT=Path('/var/lib/opemos-reboot-recovery')
POOL=Path('/sys/fs/cgroup/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice')

def need(value,why):
    if not value:raise ValueError(why)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def identity(st):return {k:getattr(st,k)for k in FIELDS}

@contextmanager
def closing(close):
    first=None
    try:yield
    except BaseException as error:first=error;raise
    finally:
        try:close()
        except BaseException as secondary:
            if first is None:raise
            first.add_note('Owned recovery closure also failed: '+repr(secondary))

def stream_original(pin):
    """Bounded-memory whole original-image verification, never image loading."""
    path=Path(pin['path']);need(path.is_absolute()and path.resolve()==path,'real original image')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);end=time.monotonic()+150
    with closing(lambda:os.close(fd)):
        before=os.fstat(fd);need(identity(before)==pin['identity']and before.st_uid==before.st_gid==0 and
             stat.S_ISREG(before.st_mode)and before.st_nlink==1,'exact immutable original custody')
        digest=hashlib.sha256();count=0
        while block:=os.read(fd,1048576):
            count+=len(block);need(count<=pin['bytes']and time.monotonic()<end,'finite original whole hash');digest.update(block)
        need(count==pin['bytes']and digest.hexdigest()==pin['sha256']and
             identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'original bytes/full9 changed')

def read_pin(pin,cap,uid=None,mode=None):
    path=Path(pin['path']);need(path.is_absolute()and path.resolve()==path,'real pinned path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with closing(lambda:os.close(fd)):
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size<=cap,'bounded regular pin')
        need(uid is None or before.st_uid==before.st_gid==uid,'pinned owner')
        need(mode is None or stat.S_IMODE(before.st_mode)==mode,'pinned mode')
        raw=bytearray()
        while block:=os.read(fd,1048576):raw.extend(block);need(len(raw)<=cap,'pin grew')
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'held/name full9 drift')
        need(len(raw)==pin['bytes']and sha(raw)==pin['sha256'],'whole pin bytes/hash')
        if 'identity'in pin:need(identity(before)==pin['identity'],'declared full9 drift')
        return bytes(raw)

def load_profile(path):
    path=Path(path);need(path.parent==PROFILE_ROOT and path.resolve()==path,'installed Root profile only')
    for parent in (PROFILE_ROOT,*PROFILE_ROOT.parents):
        s=parent.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'Root profile ancestry')
    s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_size<=1048576,'bounded installed profile')
    raw=path.read_bytes();pin={'path':str(path),'bytes':len(raw),'sha256':sha(raw),'identity':identity(s)}
    data=json.loads(read_pin(pin,1048576,0,0o444))
    need(set(data)=={'schema','queue_root','queue_code','peer','capture','original','endpoints','recovery_code'},'closed installed recovery profile')
    code=Path(__file__).resolve();s=code.lstat()
    need(code.parent==PROFILE_ROOT and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o444 and s.st_nlink==1,
         'only immutable installed Root recovery code, never candidate or checkout code')
    need(type(data['schema'])is int and data['schema']==1 and data['recovery_code']['path']==str(code),'exact installed recovery source')
    read_pin(data['recovery_code'],8*1048576,0,0o444)
    need({e['bdf']for e in data['endpoints']}=={'0000:01:00.'+str(i)for i in range(4)}and
         len(data['endpoints'])==4 and all(e['vendor']=='0x10de'for e in data['endpoints']),'complete original four-function baseline')
    return data,pin

def module(pin,name):
    need(set(pin)=={'path','bytes','sha256','identity'},'complete installed source full9 pin')
    raw=read_pin(pin,8*1048576,0,0o444)
    spec=importlib.util.spec_from_loader(name,loader=None);value=importlib.util.module_from_spec(spec)
    value.__file__=pin['path'];exec(compile(raw,pin['path'],'exec'),value.__dict__)
    return value

def ledger(db):
    return {'rows':[dict(x)for x in db.execute('SELECT * FROM jobs ORDER BY rowid')],
            'bindings':[dict(x)for x in db.execute('SELECT * FROM pool_unit_bindings ORDER BY rowid')],
            'config':[dict(x)for x in db.execute('SELECT * FROM config ORDER BY rowid')]}

def selected(epoch,job):
    rows=[r for r in epoch['rows']if r['id']==job];bindings=[b for b in epoch['bindings']if b['job_id']==job]
    need(len(rows)==len(bindings)==1,'exact original row/binding')
    row=rows[0];binding=json.loads(bindings[0]['value']);spec=json.loads(row['spec'])
    import re
    need(re.fullmatch(r'opemos-testq-[0-9a-f]{12}-[0-9a-f]{32}\.service',row['unit'])is not None and
         re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',job)is not None,'original normal job/unit names')
    need(row['state']in('running','terminal_cleanup')and row['finished']is None,'original retained reservation only')
    need(spec['id']==binding['job_id']==job and binding['unit']==row['unit']and binding['specSHA256']==sha(canonical(spec).encode()),'original spec/binding equality')
    need(binding['cpus']==json.loads(row['cpus'])and binding['memory']==spec['memory'],'original resource assignment')
    need('libvirt_domain'in spec and 'omen-iommu-group-1'in spec['resources'],'only original admitted libvirt GPU job')
    # Other pending jobs remain pending. The normal heavy/worker locks and
    # whole native pool proof protect actual work; queue length is no veto.
    return row,binding,spec

def validate_observation(proof,epoch,job):
    row,binding,spec=selected(epoch,job)
    need(proof['kind']=='ROOT_HOST_REBOOT_INTERRUPTED_CURRENT_DISPOSITION'and proof['effects']==[],'read-only reboot disposition')
    need(proof['job_id']==job and proof['epochSHA256']==sha(canonical(epoch).encode()),'entire original canonical epoch')
    need(proof['binding']==binding and proof['specSHA256']==binding['specSHA256'],'original full immutable binding/source')
    need(uuid.UUID(proof['oldBoot'])!=uuid.UUID(proof['currentBoot']),'same boot is not reboot closure')
    need(proof['journal']and all(x['_BOOT_ID']==uuid.UUID(proof['oldBoot']).hex and
         x['_SYSTEMD_INVOCATION_ID']==binding['invocation']and x['_SYSTEMD_UNIT']==row['unit']for x in proof['journal']),
         'trusted journal old boot/unit/invocation provenance')
    need(type(row['started'])in(int,float)and math.isfinite(row['started'])and
         type(binding['recordedAtUnix'])in(int,float)and math.isfinite(binding['recordedAtUnix'])and
         binding['recordedAtUnix']>=row['started']and
         all(int(x['__REALTIME_TIMESTAMP'])/1000000>=row['started']for x in proof['journal']),
         'trusted original invocation/start provenance')
    need(proof['domainInventory']==[]and proof['unit']=={'LoadState':'not-found','ActiveState':'inactive','MainPID':'0','ControlGroup':'','InvocationID':''},'current original unit/domain absence')
    need(proof['wholePoolEmpty']is True and proof['allFourBaselineAndVFIOFDsAbsent']is True and
         proof['hostIntel']is True and proof['originalWholeHashVerified']is True and proof['unknown']==[],
         'whole current native/source/original-data custody')
    need(proof['allOwnedDescriptorsClosed']is True,'Root observer descriptor closure')
    return row,binding,spec

def observe(profile,job):
    """Root-only native producer. No original SQL connection or device control."""
    need(os.getuid()==os.geteuid()==0,'Root readonly producer')
    read_pin(profile['queue_code'],8*1048576,0,0o444)
    peer=module(profile['peer'],'installed_reboot_readonly_peer')
    root=Path(profile['queue_root']);payload={};before={}
    for name in ('queue.sqlite3','queue.sqlite3-wal','queue.sqlite3-shm','queue.sqlite3-journal'):
        path=root/name
        if not os.path.lexists(path):before[name]=None;continue
        s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and s.st_size<=64*1048576,'normal queue file custody/cap')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with closing(lambda:os.close(fd)):
            need(identity(os.fstat(fd))==identity(s),'initial queue held identity');raw=bytearray()
            while block:=os.read(fd,1048576):raw.extend(block);need(len(raw)<=64*1048576,'queue file grew')
            need(len(raw)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(path.lstat()),'whole held original queue file')
            pin={'path':str(path),'identity':identity(s),'bytes':len(raw),'sha256':sha(raw)}
            payload[name]=bytes(raw);before[name]=pin
    need('queue.sqlite3'in payload and not before['queue.sqlite3-journal'],'no incomplete original writer')
    with tempfile.TemporaryDirectory(prefix='opemos-reboot-readonly-')as tmp:
        for name,raw in payload.items():(Path(tmp)/name).write_bytes(raw)
        import sqlite3
        db=sqlite3.connect('file:'+tmp+'/queue.sqlite3?mode=ro',uri=True);db.row_factory=sqlite3.Row
        with closing(db.close):db.execute('PRAGMA query_only=ON');db.execute('BEGIN');epoch=ledger(db);need(db.total_changes==0,'private reader only');db.rollback()
    for name,pin in before.items():
        if pin is None:need(not os.path.lexists(root/name),'original queue sidecar appeared')
        else:read_pin(pin,64*1048576,1000)
    row,binding,spec=selected(epoch,job);current=peer.NativeOps().boot()
    need(binding['stateRoot']==str(root)and row['unit'].startswith(binding['prefix']),'original queue root/prefix binding')
    command=['/usr/bin/journalctl','-u',row['unit'],'--no-pager','-o','json',
             '--output-fields=_BOOT_ID,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,_PID,_UID,__REALTIME_TIMESTAMP,__MONOTONIC_TIMESTAMP','-n','32']
    result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
    need(result.returncode==0 and not result.stderr and len(result.stdout)<=131072,'complete trusted journal read')
    journal=[x for x in map(json.loads,result.stdout.splitlines())if x.get('_SYSTEMD_INVOCATION_ID')==binding['invocation']and x.get('_SYSTEMD_UNIT')==row['unit']]
    boots={x['_BOOT_ID']for x in journal};need(len(boots)==1,'unique genuine original boot provenance');old=str(uuid.UUID(next(iter(boots))))
    need(old!=current,'original invocation belongs to current boot; no cleanup')
    stream_original(profile['original'])
    ops=peer.NativeOps();initial=peer.fd_snapshot('helper-before')
    with closing(ops.close):
        ops.restoration({'endpoints':profile['endpoints']});domains=ops.domains()
        need(sorted(x.name for x in Path('/sys/kernel/iommu_groups/1/devices').iterdir())==
             ['0000:00:01.0']+['0000:01:00.'+str(i)for i in range(4)],'current complete IOMMU group1')
        props=subprocess.run(['/usr/bin/systemctl','show',row['unit'],'-p','LoadState','-p','ActiveState','-p','MainPID','-p','ControlGroup','-p','InvocationID'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        need(props.returncode==0 and not props.stderr and len(props.stdout)<=65536,'current original manager read')
        unit=dict(x.split('=',1)for x in props.stdout.decode().splitlines())
        pool={name:(POOL/name).read_text().strip()for name in('cgroup.procs','cgroup.events','memory.max','memory.swap.max','cpu.max','cpuset.cpus.effective')}
        need(pool['memory.max']=='34359738368'and pool['memory.swap.max']=='0'and pool['cpu.max']=='1000000 100000'and pool['cpuset.cpus.effective']=='0-9','unchanged complete pool limits')
        intel=Path('/sys/bus/pci/devices/0000:00:02.0');hostIntel=(intel/'boot_vga').read_text().strip()=='1'and Path(os.readlink(intel/'driver')).name=='i915'
        ops.restoration({'endpoints':profile['endpoints']})
        need(ops.boot()==current,'boot changed during current observation')
    need(peer.fd_equal(initial,peer.fd_snapshot('helper-after')),'readonly observer FD closure')
    for key in('queue_code','peer','capture'):read_pin(profile[key],8*1048576,0,0o444)
    proof={'kind':'ROOT_HOST_REBOOT_INTERRUPTED_CURRENT_DISPOSITION','job_id':job,'epochSHA256':sha(canonical(epoch).encode()),'binding':binding,'specSHA256':binding['specSHA256'],'oldBoot':old,'currentBoot':current,'journal':journal,'domainInventory':domains,'unit':unit,'wholePoolEmpty':pool['cgroup.procs']==''and'populated 0'in pool['cgroup.events'],'allFourBaselineAndVFIOFDsAbsent':True,'hostIntel':hostIntel,'originalWholeHashVerified':True,'unknown':[],'allOwnedDescriptorsClosed':True,'effects':[],'observedMonotonic':time.monotonic(),'observedUnix':time.time()}
    validate_observation(proof,epoch,job)
    return proof

def preserve(path,value):
    raw=(canonical(value)+'\n').encode();fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400)
    with closing(lambda:os.close(fd)):
        stream=os.fdopen(fd,'wb',closefd=False)
        with closing(stream.close):stream.write(raw);stream.flush();os.fsync(fd)
    sync_directory(path.parent)
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw),'identity':identity(path.lstat())}

def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with closing(lambda:os.close(fd)):
        need(identity(os.fstat(fd))==identity(path.lstat()),'held history parent')
        os.fsync(fd)

@contextmanager
def writer(db):
    """The queue's existing SQLite writer lock; never an unlocked SQL script."""
    need(not db.in_transaction,'no nested writer transaction')
    db.execute('BEGIN IMMEDIATE')
    try:yield;db.commit()
    except BaseException as first:
        try:db.rollback()
        except BaseException as secondary:first.add_note('Queue rollback also failed: '+repr(secondary))
        raise

def reconcile(db,job,capture,history):
    """One failed-only normal writer transaction; native capture is external I/O.

    Runtime supplies only the pinned installed Root capture below. Tests model
    that external native boundary; those fixtures are not native acceptance.
    """
    before=ledger(db);row,binding,spec=selected(before,job)
    first=capture(job);validate_observation(first,before,job)
    proof=preserve(history/'before-native.json',first)
    if row['state']=='running':
        old=preserve(history/'original-row.json',row)
        pending={'kind':'HOST_REBOOT_INTERRUPTED','historicalRowPin':old,'originalBinding':binding,'currentBoot':first['currentBoot'],'oldBoot':first['oldBoot'],'beforeNativePin':proof,'historicalQMPClosed':None,'historicalChildExit':None,'historicalLeaseClosed':None,'historicalACLRestored':None,'automaticRetryAuthorized':False,'terminalLifecycle':{'phase':'REBOOT_DISPOSITION_PENDING','intendedState':'failed','reservationRetained':True}}
        with writer(db):
            need(ledger(db)==before,'original whole ledger drift before retained commit')
            db.execute('UPDATE jobs SET state=?,result=? WHERE id=? AND state=? AND finished IS NULL',('terminal_cleanup',canonical(pending),job,'running'))
            need(db.execute('SELECT changes()').fetchone()[0]==1,'one original retained interrupted job')
    else:
        # Only an explicit owning API invocation can continue its own retained
        # commit. Nothing resumes a VM, retries automatically or reopens failure.
        pending=json.loads(row['result'])
        need(set(pending)=={'kind','historicalRowPin','originalBinding','currentBoot','oldBoot','beforeNativePin','historicalQMPClosed','historicalChildExit','historicalLeaseClosed','historicalACLRestored','automaticRetryAuthorized','terminalLifecycle'}and
             pending['kind']=='HOST_REBOOT_INTERRUPTED'and pending['originalBinding']==binding and
             pending['currentBoot']==first['currentBoot']and pending['oldBoot']==first['oldBoot']and
             pending['automaticRetryAuthorized']is False and pending['terminalLifecycle']=={'phase':'REBOOT_DISPOSITION_PENDING','intendedState':'failed','reservationRetained':True}and
             all(pending[k]is None for k in('historicalQMPClosed','historicalChildExit','historicalLeaseClosed','historicalACLRestored')),
             'only exact original retained reboot transaction, no alternate cleanup authority')
        old=json.loads(read_pin(pending['historicalRowPin'],64*1048576))
        need(old['state']=='running'and old['finished']is None and all(old[k]==row[k]for k in row if k not in('state','result')),
             'complete original interrupted row remains exact')
        prior=json.loads(read_pin(pending['beforeNativePin'],1048576))
        need(prior['job_id']==job and prior['binding']==binding and prior['oldBoot']==first['oldBoot']and prior['currentBoot']==first['currentBoot'],
             'original prepared native custody remains bound')
    # Any later failure leaves the durable retained reservation, not a pass.
    current=ledger(db)
    expected=dict(before,rows=[dict(r,state='terminal_cleanup',result=canonical(pending))if r['id']==job else r for r in before['rows']])
    need(current==expected,'whole epoch drift after retained disposition')
    second=capture(job);validate_observation(second,current,job)
    need(second['oldBoot']==first['oldBoot']and second['currentBoot']==first['currentBoot']and second['binding']==binding,'same old/current boot and original binding')
    afterpin=preserve(history/'after-native.json',second)
    need(0<=time.monotonic()-second['observedMonotonic']<=5,'fresh final native boundary')
    final=dict(pending,continuationBeforeNativePin=proof,afterNativePin=afterpin,currentDispositionOnly=True,noHistoricalClosureFabrication=True,
               terminalLifecycle={'phase':'CLOSED','closureDomain':'CURRENT_BOOT_RECONCILIATION','intendedState':'failed','reservationRetained':False,'automaticRetryAuthorized':False})
    with writer(db):
        need(ledger(db)==current,'whole canonical epoch changed before failed disposition')
        need(0<=time.monotonic()-second['observedMonotonic']<=5,'final native boundary expired')
        db.execute('UPDATE jobs SET state=?,finished=?,result=? WHERE id=? AND state=? AND result=?',('failed',time.time(),canonical(final),job,'terminal_cleanup',canonical(pending)))
        need(db.execute('SELECT changes()').fetchone()[0]==1,'one failed-only current resource disposition')
    after=ledger(db)
    need(after['bindings']==before['bindings']and after['config']==before['config']and
         [r for r in after['rows']if r['id']!=job]==[r for r in before['rows']if r['id']!=job], 'other canonical history changed')
    return final

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('observe','reconcile'));parser.add_argument('profile',type=Path);parser.add_argument('job');args=parser.parse_args()
    profile,pin=load_profile(args.profile)
    if args.action=='observe':
        proof=observe(profile,args.job);read_pin(pin,1048576,0,0o444)
        read_pin(profile['recovery_code'],8*1048576,0,0o444)
        print(canonical(proof));return
    need(os.getuid()==os.geteuid()==1000,'normal queue owner only')
    root=Path(profile['queue_root']);need(root.resolve()==root and root.is_dir(),'existing real normal queue root')
    dbst=(root/'queue.sqlite3').lstat();need(stat.S_ISREG(dbst.st_mode)and dbst.st_uid==1000 and dbst.st_nlink==1,'existing normal queue; never initialize')
    queue=module(profile['queue_code'],'installed_normal_queue_reboot_api');root,db=queue.connect(root)
    with closing(db.close):
        worker=os.open(root/'worker.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
        with closing(lambda:os.close(worker)):
            need(stat.S_ISREG(os.fstat(worker).st_mode)and os.fstat(worker).st_uid==1000,'normal worker lock custody')
            fcntl.flock(worker,fcntl.LOCK_EX|fcntl.LOCK_NB)
            need(os.environ.get('OPEMOS_QUEUE_HEAVY_ENTRY')=='1','normal heavy admission entry required')
            heavy=os.open(Path(os.environ.get('XDG_RUNTIME_DIR','/run/user/1000'))/'opemos-heavy.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
            with closing(lambda:os.close(heavy)):
                need(stat.S_ISREG(os.fstat(heavy).st_mode)and os.fstat(heavy).st_uid==1000,'normal heavy lock custody')
                try:fcntl.flock(heavy,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:pass
                else:raise ValueError('heavy owner lock not held')
            history=root/'logs'/args.job/('reboot-reconciliation-'+uuid.uuid4().hex);history.mkdir(mode=0o700);sync_directory(history.parent)
            helper=module(profile['capture'],'installed_owned_capture');index=0
            def capture(job):
                nonlocal index
                index+=1;argv=['sudo','-n','/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'observe',str(args.profile),job]
                output=[history/(str(index)+'-stdout.raw'),history/(str(index)+'-stderr.raw')]
                record=helper.run_owned_command(argv,b'',180,output,stream_limit=1048576)
                ok=(record['numericExit']==0 and record['lifecycleClosed']and record['fd']['restored']and record['childSetRestored']and not record['errors']and not record['signals'])
                try:preserve(history/(str(index)+'-native.json'),record)
                except OSError as diagnostic:
                    print('Optional duplicate native report failed: '+type(diagnostic).__name__,file=sys.stderr)
                need(ok,'complete actual Root readonly capture; original raw failure retained')
                need(not output[1].read_bytes(),'Root readonly failure retained')
                read_pin(pin,1048576,0,0o444)
                return json.loads(output[0].read_bytes())
            print(canonical(reconcile(db,args.job,capture,history)))

if __name__=='__main__':main()

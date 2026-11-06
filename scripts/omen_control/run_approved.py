#!/usr/bin/python3
"""Materialize the installed normal Ubuntu program graph for one admitted job.

Candidate archives remain guest data. Only the Root-installed policy selects
host programs; the ordinary queue supplies fresh operation identifiers/data.
"""
import hashlib
import ctypes
import errno
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
PROGRAMS={'run_approved.py','job.py','provision_observer_rule.py','connection_control.py',
          'observer_guest.py','prepare_observer_iso.py','virtual_usb.py','vm_write_ceiling.py','owned_command.py'}
ENGINE={'scripts/omen_robot.py','scripts/omen_ci_reader.py','scripts/omen_ci_stage.py',
        'scripts/omen_ci_inventory.py','scripts/omen_ci_executables.py','scripts/omen_ci_result.py',
        'scripts/OPEMOSPointer.py','scripts/OPEMOSGuest.py','scripts/run_omen_robot_guest.py',
        'ci/required-vms.json','tests/robot/guest.robot','tests/robot/role.robot',
        'tests/robot/inventory.robot','scripts/required_omen.py','scripts/check_full_stack_acceptance.py'}
TRUSTED=Path('/var/lib/opemos-robot-control-r1/releases')

def need(value,reason):
    if not value:raise ValueError(reason)

def read(path,cap,uid,expected=None,mode=None):
    path=Path(path);need(path.is_absolute()and path.resolve()==path,'canonical normal source/data')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);identity=lambda s:{k:getattr(s,k)for k in FIELDS}
        need(stat.S_ISREG(before.st_mode)and before.st_uid==uid and before.st_nlink==1
             and not before.st_mode&0o022 and 0<before.st_size<=cap
             and(mode is None or stat.S_IMODE(before.st_mode)==mode),'normal source/data custody')
        raw=bytearray()
        while block:=os.read(fd,65536):raw.extend(block);need(len(raw)<=cap,'normal file cap')
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),
             'whole held/named normal file epoch')
        need(expected is None or hashlib.sha256(raw).hexdigest()==expected,'normal exact source/data hash')
        return bytes(raw),{'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                           'identity':identity(before)}
    finally:os.close(fd)

def create(path,raw,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    try:
        os.fchmod(fd,mode);view=memoryview(raw)
        while view:
            count=os.write(fd,view);need(count>0,'materialization write progress');view=view[count:]
        os.fsync(fd)
    finally:os.close(fd)

def storage_generation(base_fd,base,nonce):
    """Create one Root-protected generation with UID1000 traversal only.

    The USB directory is private to its ordinary owner. Its Root parent cannot
    be listed or renamed by that owner, and the raw backing remains Root-only.
    """
    base=Path(base);need(os.getresuid()==(0,0,0)and re.fullmatch('[0-9a-f]{32}',nonce),
                         'Root fresh storage generation identity')
    signature=lambda s:{k:getattr(s,k)for k in FIELDS}
    before=os.fstat(base_fd)
    need(base.is_absolute()and base.resolve()==base and stat.S_ISDIR(before.st_mode)and
         before.st_uid in(0,1000)and not before.st_mode&0o022 and
         signature(before)==signature(base.lstat()),'same trusted owned storage base')
    os.mkdir(nonce,0o700,dir_fd=base_fd)
    fd=os.open(nonce,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=base_fd)
    try:
        os.fchown(fd,0,1000);os.fchmod(fd,0o710)
        os.mkdir('usb',0o700,dir_fd=fd)
        usb=os.open('usb',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        try:
            os.fchown(usb,1000,1000);os.fchmod(usb,0o700)
            info=os.fstat(usb)
            need(info.st_uid==info.st_gid==1000 and stat.S_IMODE(info.st_mode)==0o700 and
                 signature(info)==signature(os.stat('usb',dir_fd=fd,follow_symlinks=False)),
                 'actual ordinary private USB child ownership')
        finally:os.close(usb)
        info=os.fstat(fd)
        need(info.st_uid==0 and info.st_gid==1000 and stat.S_IMODE(info.st_mode)==0o710 and
             signature(info)==signature(os.stat(nonce,dir_fd=base_fd,follow_symlinks=False))==
             signature((base/nonce).lstat()),'actual Root generation, ordinary traversal only')
        os.fsync(fd);os.fsync(base_fd)
        return base/nonce,fd,signature(info)
    except BaseException:
        os.close(fd);raise  # keep partial data; never adopt or overwrite it

def archive_pin(ref):
    path=Path(ref['path']);need(path.is_absolute()and path.resolve()==path,'canonical downloaded candidate')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        first=os.fstat(fd);sig=lambda s:{k:getattr(s,k)for k in FIELDS}
        need(stat.S_ISREG(first.st_mode)and first.st_uid==os.getuid()and first.st_nlink==1
             and stat.S_IMODE(first.st_mode)==0o400 and first.st_size==ref['bytes']<=2147483648,
             'same opaque candidate bytes/owner/bound')
        digest=hashlib.sha256()
        while block:=os.read(fd,1048576):digest.update(block)
        need(digest.hexdigest()==ref['sha256']and sig(first)==sig(os.fstat(fd))==sig(path.lstat()),
             'whole candidate digest/held named source epoch')
        return dict(ref,identity=sig(first))
    finally:os.close(fd)

def definition(config_ref,root=False):
    need(os.getuid()==os.geteuid()==(0 if root else 1000),'exact normal storage or queue owner only')
    raw,_=read(config_ref['path'],1048576,1000,config_ref['sha256'],0o400);cfg=json.loads(raw)
    nonce=cfg['nonce'];need(cfg['kind']=='ROOT_ADMITTED_UBUNTU_GUI_BUILD_WRITE_V1'
        and re.fullmatch('[0-9a-f]{32}',nonce)and re.fullmatch('[0-9a-f]{40}',cfg['source_commit']),
        'same bounded normal Ubuntu operation')
    ref=cfg['normalPolicyPin'];path=Path(ref['path'])
    need(path.parent.parent==TRUSTED and re.fullmatch('[0-9a-f]{32}',path.parent.name)
         and path.name=='fixed-policy.json','existing trusted immutable deployment policy')
    # Verify every Root ancestor and every program before interpreting a sibling.
    for parent in(path.parent,*path.parent.parents):
        info=parent.lstat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==0
            and not info.st_mode&0o022,'Root immutable deployment ancestry')
    policy_raw,_=read(path,1048576,0,ref['sha256'],0o444);policy=json.loads(policy_raw)
    need(policy['kind']=='ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1'and
         set(policy['programSHA256'])==PROGRAMS and set(policy['engineSHA256'])==ENGINE and policy['network']=='none'
         and policy['maxVMBytes']<=59_971_770_624 and policy['maxCPU']<=10
         and policy['maxMemoryBytes']<=34359738368 and policy['swapBytes']==0,
         'reviewed finite normal VM policy, no physical media or new network')
    bundle=path.parent/'proof-sources';programs={};pins={}
    for name in sorted(PROGRAMS):
        programs[name],pins[name]=read(bundle/name,1048576,0,policy['programSHA256'][name],0o444)
    engine={name:read(path.parent/'engine'/name,8388608,0,policy['engineSHA256'][name],0o444)[0]
            for name in sorted(ENGINE)}
    need(sum(map(len,programs.values()))+sum(map(len,engine.values()))<=8388608,'complete finite normal source graph')
    need(Path(__file__).resolve()==bundle/'run_approved.py','actual installed current materializer')
    operation=Path(config_ref['path']).parent;base=Path(policy['operationRoot'])
    need(operation.parent==base and operation.name.endswith('-'+nonce)and
         operation.resolve()==operation and operation.stat().st_uid==1000
         and stat.S_IMODE(operation.stat().st_mode)==0o700,'same existing normal operation namespace')
    need(cfg['network']=='none'and cfg['whole_seconds']<=policy['wholeSeconds']<=7200
         and 0<cfg['cores']<=policy['maxCPU']and 0<cfg['memoryBytes']<=policy['maxMemoryBytes']
         and cfg['maxVMBytes']==policy['maxVMBytes']and cfg['swapBytes']==0,
         'normal operation stays within exact queue policy')
    for role in('base','code','vars_template','image_carrier','loginPin','ext4_dev','retained_union_bytes','original_source'):
        need(cfg[role]==policy['operationOperands'][role],'same immutable deployment operand: '+role)
    expected=cfg['candidate']['descriptor'];need(expected['platform']=='ubuntu'
         and expected['repository']=='CorniiDog/OPEMOS.EXE'and cfg['source_commit']==policy['sourceCommit']
         and re.fullmatch('[0-9a-f]{40}',expected['source_commit'])
         and cfg['candidate']['archive']['sha256']==expected['artifact_archive_sha256'],
         'actual current producer package remains separate data')
    return cfg,policy,programs,pins,engine,operation

def materialize(config_ref):
    cfg,policy,programs,pins,engine,operation=definition(config_ref)
    nonce=cfg['nonce'];expected=cfg['candidate']['descriptor']
    storage=cfg['runtime_storage'];mount=operation/'scratch'
    info=mount.lstat()
    need(storage['kind']=='CURRENT_ROOT_PRIVATE_FILE_BACKED_EXT4_V1'and
         storage['mount']==str(mount)and storage['mountNamespace']==os.readlink('/proc/self/ns/mnt')and
         info.st_dev==storage['device']and info.st_uid==1000 and
         storage['cowPath']==str(mount/'desktop-overlay.qcow2')and
         storage['preparedDirectory']==str(mount/'prepared')and
         storage['fixedStorageBytes']==policy['fixedStorageBytes']and
         not os.path.lexists(mount/'desktop-overlay.qcow2'),'actual Root-created private scratch filesystem')
    target=operation/'programs';target.mkdir(mode=0o700)
    for name,source in programs.items():
        create(target/name,source,0o500)
        read(target/name,1048576,1000,policy['programSHA256'][name],0o500)
    engine_target=target/'engine';engine_target.mkdir(mode=0o700)
    for name,source in engine.items():
        destination=engine_target/name;destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        create(destination,source,0o500)
        read(destination,8388608,1000,policy['engineSHA256'][name],0o500)
    # Reuse the original private login input; never alter or export its bytes.
    secret=cfg['loginPin'];login,actual=read(secret['path'],4096,1000,secret['sha256'],0o600)
    need(actual==secret,'exact retained private login full9')
    create(target/'login.private.json',login,0o600)
    cfg.update(programRoot=str(target),programPins=pins,normalPolicy=policy,engineRoot=str(engine_target))
    need(0<cfg['operation_started_monotonic']<=time.monotonic()<cfg['operation_end_monotonic']<=
         cfg['operation_started_monotonic']+cfg['whole_seconds'],'original operation clock includes storage and preparation')
    cfg['candidate']['archive']=archive_pin(cfg['candidate']['archive'])
    guest=cfg['guest_operation'];guest['input_carrier_serial']=nonce[:20]
    guest['usb_serial']='opemos-'+nonce
    guest['output_directory']='/home/opemosgui/opemos-robot-'+nonce+'/output'
    guest.pop('output_path',None)  # observed completed export, never guessed filename
    prepare={'nonce':nonce,'source_commit':expected['source_commit'],'candidate':cfg['candidate'],
        'prepared_directory':storage['preparedDirectory'],'expanded_limit':2147483648,
        'observer_source':pins['observer_guest.py'],'guest_operation':guest}
    prep_raw=(json.dumps(prepare,sort_keys=True,separators=(',',':'))+'\n').encode()
    create(target/'prepare.json',prep_raw,0o400)
    prep_pin={'path':str(target/'prepare.json'),'sha256':hashlib.sha256(prep_raw).hexdigest()}
    owned=types.ModuleType('normal_owned_transport');owned.__file__=str(target/'owned_command.py')
    exec(compile(programs['owned_command.py'],owned.__file__,'exec'),owned.__dict__)
    native=owned.run_owned_command(['/usr/bin/python3','-I','-B',str(target/'prepare_observer_iso.py'),
        '--pipeline-config-pin-json',json.dumps(prep_pin,sort_keys=True,separators=(',',':'))],None,
        min(600,cfg['operation_end_monotonic']-time.monotonic()),
        [operation/'prepare.stdout',operation/'prepare.stderr'],stream_limit=4194304)
    create(operation/'prepare-native.json',(json.dumps(native,sort_keys=True,indent=2)+'\n').encode(),0o400)
    need(native['numericExit']==0 and native['lifecycleClosed']is True and native['errors']==[],
         'actual existing candidate/observer preparation failed; original raw/native retained')
    result=json.loads(read(operation/'prepare.stdout',4194304,1000)[0]);iso=Path(result['path']);info=iso.lstat()
    cfg['observer_iso']={k:result[k]for k in('path','bytes','sha256','nonce','source_commit')}
    cfg['observer_iso']['identity']={k:getattr(info,k)for k in FIELDS}
    need(iso==mount/'prepared/observer.iso'and stat.S_IMODE(info.st_mode)==0o400,
         'actual generated readonly observer medium path/mode')
    # The fixed backing already charges all inner preparation/COW allocations.
    # The opaque archive is outside that container and charged separately once.
    allocated=Path(cfg['candidate']['archive']['path']).stat().st_blocks*512
    cfg['retained_union_bytes']+=allocated
    config_raw=(json.dumps(cfg,sort_keys=True,separators=(',',':'))+'\n').encode()
    create(target/'operation.json',config_raw,0o400)
    return target/'job.py',target/'operation.json'

def normal_queue_membership_source(queue_path,queue_raw,job_id):
    """Read one full canonical row through the authenticated queue's pool API.

    The public status CLI intentionally exports summary rows without spec.
    This read-only transaction neither initializes nor mutates the queue.
    """
    data=repr((str(queue_path),queue_raw,job_id))
    return ('''import os,stat,json,types
from pathlib import Path
path,source,job_id=DATA
q=types.ModuleType('actual_normal_queue_membership');q.__file__=path
exec(compile(source,path,'exec'),q.__dict__)
root=Path(path).parent/'state';directory=root.lstat()
q.require(stat.S_ISDIR(directory.st_mode)and directory.st_uid==os.getuid(),'actual owned canonical queue directory')
database=root/'queue.sqlite3';fd=os.open(database,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
core=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink)
try:
 before=os.fstat(fd)
 q.require(stat.S_ISREG(before.st_mode)and before.st_uid==os.getuid()and before.st_nlink==1,'actual owned canonical queue database')
 db=q.sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True,timeout=10);db.row_factory=q.sqlite3.Row
 try:
  db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
  rows=q.pool_rows(db,db.execute('SELECT * FROM jobs WHERE id=?',(job_id,)).fetchall())
  q.require(len(rows)==1 and rows[0]['id']==job_id,'one exact canonical normal job')
  q.require(db.total_changes==0,'readonly canonical membership only')
  db.rollback()
 finally:db.close()
 q.require(core(before)==core(os.fstat(fd))==core(database.lstat()),'same held named canonical database')
finally:os.close(fd)
print(json.dumps({'jobs':rows},sort_keys=True))
'''.replace('DATA',data,1)).encode()


def owned_storage(config_ref):
    """Existing file-backed ext4 lifecycle around the ordinary queue child.

    Only immutable installed programs run as Root. Candidate bytes are opaque
    here and execute later inside QEMU. Root retains the loop/mount descriptors
    until the unprivileged job and independent kernel holder observations close.
    """
    cfg,policy,programs,pins,engine,operation=definition(config_ref,root=True)
    nonce=cfg['nonce'];started=time.monotonic();end=started+cfg['whole_seconds']
    fields=FIELDS
    def signature(s):return {k:getattr(s,k)for k in fields}
    def record(name,value):
        path=operation/name;create(path,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode(),0o400)
        os.chown(path,1000,1000)
    def load(name):
        m=types.ModuleType('installed_storage_'+name);m.__file__=str(Path(cfg['normalPolicyPin']['path']).parent/'proof-sources'/(name+'.py'))
        exec(compile(programs[name+'.py'],m.__file__,'exec'),m.__dict__);return m
    owned=load('owned_command');sys.modules['job']=load('job');storage_api=load('provision_observer_rule')
    class Custody:
        K=fields
        F=staticmethod(signature)
        @staticmethod
        def require(ok,reason,evidence=None):need(ok,reason+(' '+repr(evidence)if evidence is not None else''))
    class Commands:
        count=0
        @classmethod
        def checked(cls,argv,seconds,stem):
            cls.count+=1;stem='storage-'+str(cls.count).zfill(3)+'-'+stem
            left=(end+300)-time.monotonic();need(left>0,'original storage/cleanup clock exhausted')
            paths=[operation/(stem+'.stdout'),operation/(stem+'.stderr')]
            value=owned.run_owned_command(argv,None,min(seconds,left),paths,stream_limit=4194304)
            record(stem+'-native.json',value)
            for p in paths:os.chown(p,1000,1000)
            need(value['numericExit']==0 and value['lifecycleClosed']is True and value['errors']==[],
                 'owned storage command refused: '+stem)
            return paths[0].read_bytes(),paths[1].read_bytes()
    # Prove the actual normal queue scope before any allocation or namespace effect.
    cgroup=Path('/proc/self/cgroup').read_text().strip()
    unit_names=[x for x in cgroup.split('/')if re.fullmatch(r'opemos-testq-[A-Za-z0-9_.@-]+\.service',x)]
    need(len(unit_names)==1 and cfg['queue_job_id'].endswith('-'+nonce),'actual admitted normal queue unit/job')
    unit=unit_names[0];boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    raw,_=Commands.checked(['/usr/bin/systemctl','show',unit,'-p','InvocationID','-p','ActiveState','-p','ControlGroup'],10,'queue-owner')
    manager=dict(x.split('=',1)for x in raw.decode().splitlines()if'='in x)
    need(re.fullmatch('[0-9a-f]{32}',manager['InvocationID'])and manager['ActiveState']=='active'and
         cgroup=='0::'+manager['ControlGroup'],'same live normal queue invocation/cgroup')
    # Consume the full selected canonical row as its unprivileged queue owner.
    # Unit names are generated by the queue, not derived from an attempt nonce.
    queue=Path('/home/connor/.local/state/opemos-test-queue-r2')
    queue_raw,_=read(queue/'test_queue.py',1048576,1000,policy['queueSourceSHA256'],0o600)
    code=normal_queue_membership_source(queue/'test_queue.py',queue_raw,cfg['queue_job_id'])
    paths=[operation/'storage-current-queue.stdout',operation/'storage-current-queue.stderr']
    snapshot=owned.run_owned_command(['/usr/sbin/runuser','-u','connor','--','/usr/bin/python3','-I','-B','-'],
        code,min(120,end-time.monotonic()),paths,stream_limit=1048576)
    record('storage-current-queue-native.json',snapshot)
    for p in paths:os.chown(p,1000,1000)
    need(snapshot['numericExit']==0 and snapshot['lifecycleClosed']is True and snapshot['errors']==[],
         'genuine current normal queue status/closure')
    current=json.loads(paths[0].read_bytes());rows=[x for x in current['jobs']if x['id']==cfg['queue_job_id']]
    need(len(rows)==1 and rows[0]['state']=='running'and rows[0]['unit']==unit,
         'actual current canonical job owns this unit')
    spec=rows[0]['spec'];spec=json.loads(spec)if type(spec)is str else spec
    need(spec['id']==cfg['queue_job_id']and spec['owner']=='exe'and spec['platform']=='ubuntu'and
         spec['cores']==cfg['cores']and spec['memory']==cfg['memoryBytes']and
         spec['resources']==['opemos-ubuntu-gui-virtual-usb']and len(spec['command'])==11 and
         spec['command'][:7]==['/usr/bin/env','GITHUB_REPOSITORY=CorniiDog/OPEMOS.EXE',
             'OPEMOS_SOURCE_SHA='+cfg['source_commit'],'GITHUB_RUN_ID='+cfg['run_id'],
             'GITHUB_RUN_ATTEMPT='+cfg['attempt'],'OPEMOS_TRANSACTION_NONCE='+nonce,'/usr/bin/python3']and
         spec['command'][8]=='--normal-ubuntu-job'and json.loads(spec['command'][9])==config_ref and
         spec['approval']['path']==cfg['normalPolicyPin']['path']and spec['approval']['sha256']==cfg['normalPolicyPin']['sha256'],
         'exact normal command/config/Root admission/resource binding')
    read(spec['command'][7],8388608,1000,policy['engineSHA256']['scripts/run_omen_robot_guest.py'])
    base=Path(policy['storageBase'])
    need(base==Path('/media/connor/Games/OPEMOS/Ubuntu-VM-Storage')and base.resolve()==base,
         'existing trusted Games data base, no arbitrary storage root')
    held=[];raw_store=None;native=None;first=None;closure=None
    def actors():
        values={}
        for p in Path('/proc').iterdir():
            if not p.name.isdigit():continue
            try:
                raw=(p/'stat').read_text();start=raw[raw.rfind(')')+2:].split()[19]
                if (p/'cgroup').read_text().strip()==cgroup:values[p.name]=start
            except(FileNotFoundError,ProcessLookupError):pass
        return values
    baseline=actors();outer=os.readlink('/proc/self/ns/mnt')
    try:
        # Hold and compare every writable data ancestor, including the mount.
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);held.append((Path('/'),fd,signature(os.fstat(fd))))
        current=Path('/')
        for part in base.parts[1:]:
            current=current/part;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            s=os.fstat(fd);need(s.st_uid in(0,1000)and not s.st_mode&0o022,'trusted data ancestor owner/mode')
            held.append((current,fd,signature(s)))
        for path,descriptor,s in held:need(signature(path.lstat())==signature(os.fstat(descriptor))==s,'held storage ancestry')
        total=policy['fixedStorageBytes'];usb_bytes=cfg['guest_operation']['usb_bytes']
        need(type(total)is int and total>0 and total%4096==0 and
             total>=cfg['cow_growth_bytes']+5_500_000_000 and
             total+usb_bytes+sum(cfg[k]['bytes']for k in('base','code','vars_template','image_carrier'))+
             cfg['candidate']['archive']['bytes']+cfg['retained_union_bytes']+500_000_000<=cfg['maxVMBytes'],
             'whole original/archive/fixed scratch/USB/retained/metadata charge')
        sv=os.fstatvfs(fd);need(sv.f_bavail*sv.f_frsize>=total+usb_bytes+500_000_000,
                              'actual Games free capacity for all new allocations')
        generation,generation_fd,generation_identity=storage_generation(fd,base,nonce)
        held.append((generation,generation_fd,generation_identity))
        libc=ctypes.CDLL(None,use_errno=True)
        need(libc.unshare(0x00020000)==0,'actual private mount namespace: '+str(ctypes.get_errno()))
        Commands.checked(['/usr/bin/mount','--make-rprivate','/'],10,'private-propagation')
        private=os.readlink('/proc/self/ns/mnt');need(private!=outer,'independent mount namespace required')
        data={'fixedBacking':str(generation/'scratch.ext4.raw'),'mount':str(operation/'scratch'),
              'fixedStorageBytes':total,'outerMountNamespace':outer,'jobId':unit,'boot':boot}
        raw_store=storage_api.Storage(data,Custody,Commands,None);raw_store.open()
        observed=raw_store.check('before-normal-child')
        cfg['runtime_storage']={'kind':'CURRENT_ROOT_PRIVATE_FILE_BACKED_EXT4_V1',**data,
             'mountNamespace':private,'device':observed['device'],'mountID':observed['mountID'],
             'cowPath':str(operation/'scratch/desktop-overlay.qcow2'),
             'preparedDirectory':str(operation/'scratch/prepared'),'usbDirectory':str(generation/'usb')}
        cfg['operation_started_monotonic']=started;cfg['operation_end_monotonic']=end
        target=operation/'storage-operation.json';payload=(json.dumps(cfg,sort_keys=True,separators=(',',':'))+'\n').encode()
        create(target,payload,0o400);os.chown(target,1000,1000)
        ref={'path':str(target),'sha256':hashlib.sha256(payload).hexdigest()}
        need(end>time.monotonic(),'original operation clock expired before ordinary child')
        native=owned.run_owned_command(['/usr/sbin/runuser','-u','connor','--','/usr/bin/python3','-I','-B',
             str(Path(__file__)),'--pipeline-config-pin-json',json.dumps(ref,sort_keys=True,separators=(',',':'))],
             None,end-time.monotonic(),[operation/'ordinary-storage-job.stdout',operation/'ordinary-storage-job.stderr'],
             stream_limit=4194304)
        for p in (operation/'ordinary-storage-job.stdout',operation/'ordinary-storage-job.stderr'):os.chown(p,1000,1000)
        record('ordinary-storage-job-native.json',native)
        need(native['numericExit']==0 and native['lifecycleClosed']is True and native['errors']==[],
             'ordinary Ubuntu job failed; actual FIRST/raw/native retained')
    except BaseException as error:
        first={'type':type(error).__name__,'reason':str(error)}
    finally:
        if raw_store is not None:
            # Current kernel observations are independent of all job result flags.
            unknown=[];holders=[];namespaces=[];now=actors()
            for pid,start in now.items():
                if pid!=str(os.getpid())and baseline.get(pid)!=start:unknown.append({'pid':pid,'start':start,'reason':'new normal-unit actor remains'})
            identities=[]
            for path in (raw_store.c['fixedBacking'],str(operation/'scratch/desktop-overlay.qcow2'),
                         str(base/nonce/'usb/virtual-usb.raw')):
                try:s=os.lstat(path);identities.append((s.st_dev,s.st_ino))
                except FileNotFoundError:pass
            loop_device=os.fstat(raw_store.loopfd).st_rdev if raw_store.loopfd is not None else None
            for p in Path('/proc').iterdir():
                if not p.name.isdigit()or p.name==str(os.getpid()):continue
                try:
                    process_ns=os.readlink(p/'ns/mnt');private_ns=os.readlink('/proc/self/ns/mnt')
                    if process_ns==private_ns:namespaces.append(int(p.name))
                    elif loop_device is not None:
                        device=str(os.major(loop_device))+':'+str(os.minor(loop_device))
                        if any(line.split()[2]==device for line in(p/'mountinfo').read_text().splitlines()):
                            namespaces.append({'pid':int(p.name),'namespace':process_ns,'device':device})
                    for f in(p/'fd').iterdir():
                        try:s=f.stat()
                        except(FileNotFoundError,ProcessLookupError):continue
                        if (s.st_dev,s.st_ino)in identities or(loop_device is not None and stat.S_ISBLK(s.st_mode)and s.st_rdev==loop_device):
                            holders.append({'pid':int(p.name),'fd':f.name})
                except(FileNotFoundError,ProcessLookupError):continue
                except OSError as error:unknown.append({'pid':int(p.name),'reason':str(error)})
            quiet={'kind':'INDEPENDENT_ROOT_CURRENT_STORAGE_QUIET','jobId':unit,'boot':boot,
                   'unknown':unknown,'foreignHolders':holders,'otherMountNamespaces':namespaces,
                   'allOwnChildrenReaped':native is None or native['lifecycleClosed']is True,
                   'original':None,'atMonotonic':time.monotonic()}
            record('storage-current-kernel-quiet.json',quiet)
            try:closure=raw_store.close(quiet)
            except BaseException as error:
                closure={'first':{'type':type(error).__name__,'reason':str(error)},'state':raw_store.state()}
        for path,descriptor,s in reversed(held):os.close(descriptor)
        record('storage-result.json',{'first':first,'closure':closure,'native':native,
                                      'candidateExecutedOnHost':False,'originalsUsedAsStorageTargets':False})
    need(first is None and closure is not None and not closure.get('first'),
         'normal storage/Ubuntu operation failed; retained exact receipts and data')

def main():
    need(len(sys.argv)==3 and sys.argv[1]in('--pipeline-config-pin-json','--owned-storage'),
         'normal pinned operation data only')
    if sys.argv[1]=='--owned-storage':
        return owned_storage(json.loads(sys.argv[2]))
    job,config=materialize(json.loads(sys.argv[2]))
    os.execv('/usr/bin/python3',['/usr/bin/python3','-B',str(job),'--pipeline',str(config)])

if __name__=='__main__':main()

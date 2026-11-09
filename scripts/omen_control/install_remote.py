#!/usr/bin/python3
"""Root-run exact scoped Robot materializer; no queue submit or VM start.

Root passes one reviewed whole-payload SHA. This program stages and verifies every
source/configuration member before replacing any existing installed member.
An install failure invokes exact guarded rollback and preserves the first error.
"""
import fcntl, hashlib, json, os, re, stat, subprocess, sys, time
from pathlib import Path

ROOT = Path('/var/lib/opemos-robot-control-r1')
HOME = Path('/home/connor')
OP = HOME / '.local/share/opemos-ci'
RUNNER = OP / 'github-runner'
CONFIG = HOME / '.config/opemos-ci'
QUEUE = HOME / '.local/state/opemos-test-queue-r2'
PRIVATE = OP / 'robot-private'
EXCHANGE = Path('/media/connor/Games/OPEMOS/CI-artifacts/robot-runtime/reports')
PROGRAMS = ('control.py','connection_host.py','host_engine.py','launch.py')
PROOF_LEGACY = ('run_approved.py','job.py','provision_observer_rule.py',
                'connection_control.py','observer_guest.py','prepare_observer_iso.py')
PROOF = PROOF_LEGACY + ('ubuntu_guest_build.py','virtual_usb.py','vm_write_ceiling.py','owned_command.py')
ENGINE = ('scripts/omen_robot.py','scripts/omen_ci_reader.py',
          'scripts/omen_ci_stage.py','scripts/omen_ci_inventory.py',
          'scripts/omen_ci_executables.py','scripts/omen_ci_result.py',
          'scripts/OPEMOSPointer.py','scripts/OPEMOSGuest.py',
          'scripts/run_omen_robot_guest.py','ci/required-vms.json',
          'tests/robot/guest.robot','tests/robot/role.robot',
          'tests/robot/inventory.robot','scripts/required_omen.py',
          'scripts/check_full_stack_acceptance.py')
SOURCE = PROGRAMS + PROOF + ('planner.py','job_guard.py','job-started.sh',
                             'install_remote.py','rollback_before_submit.py')
OPERATION_DATA = ('ubuntu-operation.json','ubuntu-source-operation.json')
SCOPE='CONNECTION_ONLY_OLD_ARTIFACT_NO_FULLSTACK_ACCEPTANCE'
OLD_SOURCE='01ae39dbe07ae3e5a2f45c6e4c4b354f735156b3'
OLD_APP='b252781da4a8af77c1439e0197208fc5c607d29bbc7ef18595ed550029ee9580'
OLD_PACKAGE='3e63076a297df9015aacef49c32610058216528e4307002bc72a783bbbe6f415'
OLD_BASE='2222268d94712bbd03c0251d619e7cd67ef12d2348b5fe0893b31dde2e40d4ab'
ROOT_SCOPED_PLAN='70426f2e91563950a651974efaab42e74289d22ae179a3eb260974ddac6ce7b0'
HISTORIC_EXCHANGE='/home/connor/.local/share/opemos-ci/github-runner/robot-private/reports'
PRIVATE_RESULTS='/home/connor/.local/share/opemos-ci/robot-private'


def need(ok, why):
    if not ok: raise RuntimeError(why)


def strict(data):
    def pairs(items):
        out={}
        for k,v in items:
            need(k not in out,'duplicate input field')
            out[k]=v
        return out
    return json.loads(data,object_pairs_hook=pairs,
                      parse_constant=lambda _:need(False,'nonfinite input'))


def sha(data): return hashlib.sha256(data).hexdigest()


def enc(data): return (json.dumps(data,sort_keys=True,separators=(',',':'))+'\n').encode()


def read_exact(path, cap):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap,
             'bounded regular input')
        data=bytearray()
        while block:=os.read(fd,min(65536,cap+1-len(data))):
            data.extend(block);need(len(data)<=cap,'bounded input cap')
        b=os.fstat(fd)
        keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
              'st_size','st_mtime_ns','st_ctime_ns','st_blocks')
        identity=lambda s:tuple(getattr(s,k) for k in keys)
        need(identity(a)==identity(b)==identity(os.lstat(path)),
             'input held-FD/named identity changed during read')
        return bytes(data),a
    finally: os.close(fd)


def fsync_parent(path):
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def directory(path,uid,mode):
    if path.exists():
        m=path.lstat()
        need(stat.S_ISDIR(m.st_mode) and not path.is_symlink() and
             m.st_uid==uid and stat.S_IMODE(m.st_mode)==mode,
             'exact directory custody '+str(path))
    else:
        path.mkdir(mode=mode)
        os.chown(path,uid,uid if uid==1000 else 0)
        os.chmod(path,mode)
        fsync_parent(path)


def full(path):
    if not os.path.lexists(path): return {'absent':True}
    m=path.lstat()
    need(stat.S_ISREG(m.st_mode) and m.st_nlink==1 and not path.is_symlink(),
         'prior target not regular one-link '+str(path))
    raw,held=read_exact(path,16*1024*1024)
    keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
          'st_size','st_mtime_ns','st_ctime_ns','st_blocks')
    need(tuple(getattr(m,k) for k in keys)==tuple(getattr(held,k) for k in keys),
         'prior named/held metadata differs')
    return {'absent':False,'dev':m.st_dev,'ino':m.st_ino,
            'mode':stat.S_IMODE(m.st_mode),'uid':m.st_uid,'gid':m.st_gid,
            'nlink':m.st_nlink,'bytes':len(raw),'mtimeNs':m.st_mtime_ns,
            'ctimeNs':m.st_ctime_ns,'allocatedBytes':m.st_blocks*512,
            'sha256':sha(raw)}


def exact_previous(path,expected):
    got=full(path)
    need(got==expected,'prior installed file/absence differs '+str(path))
    return got


def new_file(path,data,uid,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        os.fchown(fd,uid,uid if uid==1000 else 0)
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    fsync_parent(path)
    need(full(path)['sha256']==sha(data),'staged write readback')


def replacement(path,data,uid,mode,expected,tx,backup_path=None):
    exact_previous(path,expected)
    gid=uid if uid==1000 else 0
    if not expected['absent']:
        actual,meta=read_exact(path,16*1024*1024)
        exact_previous(path,expected)
        if (actual==data and meta.st_uid==uid and meta.st_gid==gid and
                stat.S_IMODE(meta.st_mode)==mode):
            need(backup_path is not None and not os.path.lexists(backup_path),
                 'unchanged original must not have a backup alias')
            post=exact_previous(path,expected)
            return post,'unchanged'
    temp=path.parent/('.opemos-install-'+tx+'-'+path.name)
    need(not os.path.lexists(temp),'install temp exists')
    made=False;linked=False;renamed=False;owned=None
    try:
        # Retain a known newly-created inode even if fsync/readback later fails.
        need(not os.path.lexists(temp),'install temp exists')
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
        made=True
        try:
            st=os.fstat(fd);owned=(st.st_dev,st.st_ino)
            os.fchown(fd,uid,gid);os.fchmod(fd,mode)
            with os.fdopen(fd,'wb',closefd=False) as stream:
                stream.write(data);stream.flush();os.fsync(stream.fileno())
        finally:os.close(fd)
        fsync_parent(temp)
        staged=full(temp)
        need(staged['sha256']==sha(data) and staged['uid']==uid and
             staged['gid']==gid and staged['mode']==mode,'new target bytes/metadata')
        exact_previous(path,expected)
        if not expected['absent']:
            need(backup_path is not None and not os.path.lexists(backup_path) and
                 path.stat().st_dev==backup_path.parent.stat().st_dev,
                 'same-device fresh exact original-inode backup required')
            os.link(path,backup_path,follow_symlinks=False);linked=True
            fsync_parent(backup_path)
            held=backup_path.lstat()
            need(held.st_dev==expected['dev'] and held.st_ino==expected['ino'] and
                 held.st_nlink==2,'original inode hardlink custody')
        os.replace(temp,path);renamed=True;fsync_parent(path)
        post=full(path)
        need((post['dev'],post['ino'])==owned and post['sha256']==sha(data) and
             post['uid']==uid and post['gid']==gid and post['mode']==mode,
             'atomic installed result differs')
        return post,('created' if expected['absent'] else 'replaced')
    except BaseException as first:
        errors=[]
        try:
            if renamed:
                now=full(path)
                need((now['dev'],now['ino'])==owned and now['sha256']==sha(data)
                     and now['uid']==uid and now['gid']==gid and now['mode']==mode,
                     'partial replacement lost exact new inode custody')
                if expected['absent']:path.unlink();fsync_parent(path)
                else:
                    original=full(backup_path)
                    need(all(original[k]==expected[k] for k in
                         ('dev','ino','sha256','uid','gid','mode','bytes','mtimeNs')),
                         'partial replacement original backup changed')
                    os.replace(backup_path,path);linked=False;fsync_parent(path)
            elif linked:
                a=path.lstat();b=backup_path.lstat()
                need((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)==
                     (expected['dev'],expected['ino']) and b.st_nlink==2,
                     'partial link original custody')
                backup_path.unlink();linked=False;fsync_parent(backup_path)
        except BaseException as error:errors.append(('replacement-restore',str(error)))
        try:
            if made and os.path.lexists(temp):
                s=temp.lstat()
                need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and
                     (s.st_dev,s.st_ino)==owned,'partial temp inode custody')
                temp.unlink();fsync_parent(temp)
        except BaseException as error:errors.append(('replacement-temp',str(error)))
        first.add_note('independent replacement cleanup: '+repr(errors))
        raise


def original_custody(before,installed,outcomes,txdir,payload=None):
    selected=targets(payload)
    need(set(before)==set(installed)==set(outcomes)==set(selected),
         'complete target outcome membership')
    result={}
    for label,path in selected.items():
        backup=txdir/('backup-'+label);old=before[label]
        need(full(path)==installed[label],'installed target drift '+label)
        outcome=outcomes[label]
        if outcome=='unchanged':
            need(not old['absent'] and installed[label]==old and
                 not os.path.lexists(backup),'unchanged full original custody '+label)
            result[label]={'location':'original-target','pin':old}
        elif outcome=='created':
            need(old['absent'] and not os.path.lexists(backup),
                 'created target had no original '+label)
            result[label]={'location':'absent','pin':old}
        else:
            need(outcome=='replaced' and not old['absent'],
                 'exact replacement outcome '+label)
            pin=full(backup)
            need(all(pin[k]==old[k] for k in
                 ('dev','ino','sha256','uid','gid','mode','bytes','mtimeNs')),
                 'original backup identity/content changed '+label)
            result[label]={'location':'original-backup','pin':pin}
    return result


def require_source(payload):
    need(type(payload) is dict and set(payload)=={'kind','runtimeAuthorized','transaction',
         'mainCommit','runnerId','runnerManifest','sources','engine','profile','registry',
         'policy','queueSourceSHA256','queueLoggerSHA256','login','prior','oldControl',
         'approval','rootAdmissionSHA256'},'exact installer payload schema')
    need(payload['kind']=='ROOT_REVIEWED_ROBOT_CONTROL_MATERIALIZATION_V1' and
         payload['runtimeAuthorized'] is True and
         re.fullmatch(r'[0-9a-f]{32}',payload['transaction']) and
         re.fullmatch(r'[0-9a-f]{40}',payload['mainCommit']) and
         payload['runnerId']==21 and set(payload['sources']) in (set(SOURCE)|set(OPERATION_DATA),set(SOURCE)-set(PROOF[len(PROOF_LEGACY):])) and
         set(payload['engine'])==set(ENGINE),'exact source/transaction graph')
    for name,row in {**payload['sources'],**payload['engine']}.items():
        need(type(row) is dict and set(row)=={'hex','sha256'} and
             len(bytes.fromhex(row['hex']))<=8*1024*1024 and
             sha(bytes.fromhex(row['hex']))==row['sha256'],
             'exact source bytes '+name)
    profile=payload['profile'];registry=payload['registry'];policy=payload['policy']
    need(type(profile) is dict and profile.get('schema')==1 and
         profile.get('enabled') is True and
         profile.get('hook',{}).get('path')==str(ROOT/'opemos-robot-job-plan') and
         profile['hook'].get('sha256')==payload['sources']['planner.py']['sha256'] and
         profile.get('fixed_registry',{}).get('path')==str(CONFIG/'robot-jobs.json') and
         profile['fixed_registry'].get('sha256')==sha(enc(registry)),
         'exact enabled planner/profile/registry join')
    need(type(registry) is dict and len(registry.get('cases',{}))==20 and
         registry.get('source_commit')==payload['mainCommit'],
         'exact 20-case registry required')
    if type(policy)is dict and policy.get('kind')=='ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1':
        need(set(payload['sources'])==set(SOURCE)|set(OPERATION_DATA)and policy.get('runtimeAuthorized')is True
             and policy.get('sourceAccepted')is True and policy.get('sourceCommit')==payload['mainCommit']
             and policy.get('scope')==('NORMAL_UBUNTU_SOURCE_BUILD_AND_GUI_VIRTUAL_USB_ONLY'if policy.get('sourceBuildEnabled')is True else'NORMAL_UBUNTU_GUI_BUILD_WRITE_VIRTUAL_USB_ONLY')
             and policy.get('programSHA256')=={k:payload['sources'][k]['sha256']for k in PROOF}
             and policy.get('engineSHA256')=={k:payload['engine'][k]['sha256']for k in ENGINE}
             and policy.get('queueSourceSHA256')==payload['queueSourceSHA256']
             and policy.get('queueLoggerSHA256')==payload['queueLoggerSHA256'],
             'one exact reviewed normal controller/program/engine/queue definition')
        need(policy.get('operationRoot')==profile.get('operation_root')==str(PRIVATE/'operations')
             and policy.get('runtimeRoot')==policy.get('operationRoot')
             and policy.get('storageBase')=='/media/connor/Games/OPEMOS/Ubuntu-VM-Storage'
             and type(policy.get('fixedStorageBytes'))is int
             and policy['fixedStorageBytes']%4096==0 and 0<policy['fixedStorageBytes']<policy['maxVMBytes']
             and type(policy.get('publicEvidenceMaxBytes'))is int
             and 0<policy['publicEvidenceMaxBytes']<=268435456
             and policy.get('network')=='none'and policy.get('swapBytes')==0
             and type(policy.get('maxVMBytes'))is int and 0<policy['maxVMBytes']<=59_971_770_624
             and type(policy.get('maxCPU'))is int and 0<policy['maxCPU']<=10
             and type(policy.get('maxMemoryBytes'))is int and 0<policy['maxMemoryBytes']<=34359738368
             and type(policy.get('wholeSeconds'))is int and 0<policy['wholeSeconds']<=7200,
             'normal Ubuntu VM stays within existing typed placement/resource/network boundaries')
        originals=policy.get('originalSHA256',{})
        need(set(originals)=={'base','code','vars_template','image_carrier'}and
             all(re.fullmatch('[0-9a-f]{64}',x)for x in originals.values())
             and type(policy.get('maxRuns'))is int and 1<=policy['maxRuns']<=20
             and type(policy.get('notBefore'))is int and type(policy.get('expiresAt'))is int
             and policy['notBefore']<=time.time()<policy['expiresAt']
             and 19000<policy['expiresAt']-policy['notBefore']<=7*86400,
             'Root-selected immutable original roles and finite normal job epoch')
        operands=policy.get('operationOperands',{})
        need(set(operands)=={'base','code','vars_template','image_carrier','loginPin','ext4_dev',
             'retained_union_bytes','pool_sha256','queue_entry','original_source'},
             'one complete existing deployment operand definition')
        for role in originals:
            item=operands[role];info=item.get('identity',{})
            need(item.get('sha256')==originals[role]and item.get('bytes')==item.get('size')==info.get('st_size')and
                 type(item['bytes'])is int and item['bytes']>0 and Path(item['path']).is_absolute()and
                 '..'not in Path(item['path']).parts and stat.S_ISREG(info.get('st_mode',0))and
                 info.get('st_uid')==info.get('st_gid')==1000 and info.get('st_nlink')==1,
                 'complete immutable original data role '+role)
        need(operands['loginPin']==payload['login']and operands['retained_union_bytes']>=0 and
             type(operands['ext4_dev'])is int and operands['ext4_dev']>0 and
             re.fullmatch('[0-9a-f]{64}',operands['pool_sha256'])and
             operands['queue_entry']['path']==str(QUEUE/'test_queue.py')and
             operands['queue_entry']['sha256']==payload['queueSourceSHA256']and
             operands['original_source']=={k:operands['base'][k]for k in('size','sha256','identity')},
             'retained login/queue/pool/original identity joins')
        ubuntu=registry.get('artifacts',{}).get('ubuntu',{})
        need(type(ubuntu.get('automatic_operation'))is dict and
             set(ubuntu['automatic_operation'])=={'path','sha256'}and
             re.fullmatch('[0-9a-f]{64}',ubuntu['automatic_operation']['sha256']),
             'Ubuntu registry must select the complete authenticated ordinary recipe')
        recipe_source=payload['sources']['ubuntu-operation.json']
        need(ubuntu['automatic_operation']=={'path':str(ROOT/'normal-operations'/
             (recipe_source['sha256']+'.json')),'sha256':recipe_source['sha256']},
             'single existing registry recipe pin and trusted immutable data placement')
        if policy.get('sourceBuildEnabled')is True:
            source_recipe=payload['sources']['ubuntu-source-operation.json']
            need(ubuntu.get('native_producer')=={'path':str(ROOT/'normal-operations'/
                 (source_recipe['sha256']+'.json')),'sha256':source_recipe['sha256']}and
                 type(policy.get('sourceBuildInputBytes'))is int and
                 0<policy['sourceBuildInputBytes']<=policy['maxVMBytes']and
                 profile.get('max_source_input_archive_bytes')==policy['sourceBuildInputBytes']and
                 policy.get('guestPrerequisitesRequired')is True,
                 'actual source producer/whole input bound/prerequisites operation joins')
            selected=policy.get('producerWorkflowPolicy')
            need(type(selected)is dict and set(selected)=={'kind','repository','workflow','bodySHA256','inputPrograms'}and
                 selected['kind']=='REVIEWED_UBUNTU_SOURCE_PRODUCER_WORKFLOW_V1'and
                 selected['repository']=='CorniiDog/OPEMOS.EXE'and
                 selected['workflow']=='.github/workflows/ubuntu-executable.yml'and
                 re.fullmatch('[0-9a-f]{64}',selected['bodySHA256'])and
                 set(selected['inputPrograms'])=={'scripts/prepare_ubuntu_source_inputs.py',
                                                 'scripts/acquire_appliance_windows.py'}and
                 all(re.fullmatch('[0-9a-f]{64}',value)for value in selected['inputPrograms'].values()),
                 'exact reviewed producer workflow/input-program grant, never candidate control code')
        recipe=strict(bytes.fromhex(recipe_source['hex']))
        need(type(recipe)is dict and set(recipe)=={'schema','documents','prepare','collect'}
             and recipe['schema']==1 and type(recipe['documents'])is list,
             'existing normal planner recipe schema, no generated executable')
    else:
        need(type(policy) is dict and policy.get('kind')=='ROOT_FIXED_SCOPED_CONNECTION_POLICY_V1' and
             policy.get('runtimeAuthorized') is True and policy.get('sourceCommit')==payload['mainCommit'] and
             policy.get('scope')==SCOPE and policy.get('programSHA256')==
                  {k:payload['sources'][k]['sha256'] for k in PROOF_LEGACY} and
             policy.get('baseApprovalSHA256')==ROOT_SCOPED_PLAN and
             policy.get('oldArtifactSource')==OLD_SOURCE and
             policy.get('oldArtifactSHA256')==OLD_APP and
             policy.get('oldPackageSHA256')==OLD_PACKAGE and
             policy.get('oldBaseSHA256')==OLD_BASE and
             policy.get('queueSourceSHA256')==payload['queueSourceSHA256'] and
             policy.get('queueLoggerSHA256')==payload['queueLoggerSHA256'] and
             policy.get('cores')==1 and policy.get('memoryBytes')==7*1024**3 and
             policy.get('jobTimeoutSeconds')==900 and
             type(policy.get('maxRuns')) is int and 1<=policy['maxRuns']<=20 and
             type(policy.get('notBefore')) is int and type(policy.get('expiresAt')) is int and
             policy['notBefore']<=time.time()<policy['expiresAt'] and
             policy['expiresAt']-policy['notBefore']<=7*86400,
             'exact current fixed scoped policy')
        need(payload['rootAdmissionSHA256']==ROOT_SCOPED_PLAN,
             'exact existing Root scoped admission plan binding')
    approval=payload['approval']
    need(type(approval) is dict and set(approval)==
         {'kind','exactRuntimeAuthorized','owner','repository','runnerId',
          'cores','memoryBytes','swapBytes','wallSeconds','vmAdmission',
          'originalsImmutable','sourceApprovalRequiredForWorkflow'} and
         approval['kind']=='ROOT_CONFINED_GITHUB_RUNNER_ADMISSION' and
         approval['exactRuntimeAuthorized'] is True and approval['owner']=='root' and
         approval['repository']=='CorniiDog/OPEMOS.EXE' and approval['runnerId']==21 and
         approval['cores']==1 and approval['memoryBytes']==1073741824 and
         approval['swapBytes']==0 and type(approval['wallSeconds'])is int and
         100<approval['wallSeconds']<=7*86400 and
         approval['wallSeconds']==policy['expiresAt']-policy['notBefore'] and
         approval['vmAdmission'] is False and
         approval['originalsImmutable'] is True and
         approval['sourceApprovalRequiredForWorkflow'] is True,
         'initial Root control lease admission')
    return {n:bytes.fromhex(row['hex']) for n,row in payload['sources'].items()},\
           {n:bytes.fromhex(payload['engine'][n]['hex']) for n in ENGINE}


def preflight(payload):
    need(os.geteuid()==0,'Root-owned installer only')
    need(ROOT.parent==Path('/var/lib') and ROOT.parent.stat().st_uid==0 and
         stat.S_IMODE(ROOT.parent.stat().st_mode)==0o755,
         'root-anchored /var/lib custody')
    runner=json.loads((RUNNER/'.runner').read_text(encoding='utf-8-sig'))
    need(runner.get('agentId')==payload['runnerId'] and
         runner.get('agentName')=='opemos-omen-robot','exact registered Runner')
    for n in ('.runner','.credentials','.credentials_rsaparams'):
        m=(RUNNER/n).lstat()
        need(stat.S_ISREG(m.st_mode) and m.st_uid==1000 and m.st_nlink==1 and
             not m.st_mode&0o077,'retained Runner registration/credential custody')
    runner_manifest=payload['runnerManifest']
    need(type(runner_manifest) is dict and set(runner_manifest)=={'path','sha256'},
         'reviewed Runner manifest pin')
    raw,_=read_exact(Path(runner_manifest['path']),8*1024*1024)
    need(sha(raw)==runner_manifest['sha256'],'registered Runner program manifest')
    for path,pin in ((QUEUE/'test_queue.py',payload['queueSourceSHA256']),
                     (QUEUE/'queue_job.py',payload['queueLoggerSHA256']),
                     (Path(payload['login']['path']),payload['login']['sha256'])):
        data,m=read_exact(path,8*1024*1024)
        need(sha(data)==pin,'installed queue/logger or retained login drift')
    login=Path(payload['login']['path']).lstat()
    need(login.st_uid==1000 and stat.S_IMODE(login.st_mode)==0o600 and
         login.st_nlink==1,'retained private login identity')
    need(PRIVATE.is_dir() and PRIVATE.lstat().st_uid==1000 and
         stat.S_IMODE(PRIVATE.lstat().st_mode)==0o700 and
         not PRIVATE.is_symlink(),'outside-Runner private results custody')
    old=payload['oldControl'];receipt=bytes.fromhex(old['closedReceiptHex'])
    need(sha(receipt)==old['closedReceiptSHA256'] and len(receipt)<=65536,
         'exact old-control post-stop receipt bytes')
    observed=strict(receipt)
    need(observed.get('currentManager',{}).get('MainPID')=='0' and
         observed.get('currentManager',{}).get('ControlGroup')=='' and
         observed.get('fullUID0Group',{}).get('absent') is True and
         observed.get('oldDispatcherAbsent') is True and
         observed.get('oldListenerAbsent') is True,
         'old-control physical closure receipt')
    need(re.fullmatch(r'opemos-testq-[0-9a-f-]+\.service',old['unit']) and
        old['liveMainPID']==0 and old['liveUID0Absent'] is True,
        'old control closure disposition; no historical invocation equality')
    manager=subprocess.run(['/usr/bin/systemctl','show',old['unit'],
        '-p','LoadState','-p','ActiveState','-p','MainPID','-p','ControlGroup'],
        capture_output=True,timeout=10)
    need(manager.returncode==0 and len(manager.stdout)<=8192 and
         len(manager.stderr)<=8192,'bounded current old-control manager read')
    fields=dict(line.split('=',1) for line in manager.stdout.decode().splitlines() if '=' in line)
    need(fields.get('MainPID')=='0' and fields.get('ControlGroup')=='' and
         fields.get('ActiveState') in ('inactive','failed') and
         fields.get('LoadState') in ('loaded','not-found'),
         'old control currently owns no process/cgroup')
    for label,path in targets(payload).items():
        exact_previous(path,payload['prior'][label])
    return True


def targets(payload=None):
    result={'planner':ROOT/'opemos-robot-job-plan',
      'guardScript':ROOT/'guard/job-started.sh','guardCode':ROOT/'guard/job_guard.py',
      'profile':CONFIG/'robot.json','registry':CONFIG/'robot-jobs.json',
      'runnerEnv':RUNNER/'.env'}
    if payload is not None and payload['policy'].get('sourceBuildEnabled')is True:
        result['producerWorkflow']=ROOT/'guard/ubuntu-producer-workflow.json'
    return result


def configure_env(old):
    text=old.decode('utf-8')
    remove=('ACTIONS_RUNNER_HOOK_JOB_STARTED=','PYTHONPATH=',
            'OPEMOS_ROBOT_PYTHON=','OPEMOS_ROBOT_PRIVATE_RESULTS=',
            'OPEMOS_ROBOT_REPORT_EXCHANGE=')
    lines=[x for x in text.splitlines() if not x.startswith(remove)]
    lines += ['ACTIONS_RUNNER_HOOK_JOB_STARTED='+str(ROOT/'guard/job-started.sh'),
      'PYTHONPATH='+str(RUNNER/'robot-python'),'OPEMOS_ROBOT_PYTHON=/usr/bin/python3',
      'OPEMOS_ROBOT_PRIVATE_RESULTS='+PRIVATE_RESULTS,
      'OPEMOS_ROBOT_REPORT_EXCHANGE='+HISTORIC_EXCHANGE]
    return ('\n'.join(lines)+'\n').encode()


def _install_locked(payload,payload_sha,source,engine):
    preflight(payload)
    tx=payload['transaction'];txdir=ROOT/'transactions'/tx
    need(not os.path.lexists(txdir),'transaction already used')
    directory(ROOT,0,0o755)
    directory(ROOT/'transactions',0,0o700)
    directory(txdir,0,0o700)
    before={label:full(path) for label,path in targets(payload).items()}
    backup={label:(None if item['absent'] else read_exact(targets(payload)[label],16*1024*1024)[0].hex())
            for label,item in before.items()}
    pre={'kind':'ROBOT_INSTALL_PRE_EFFECT_FULL_PRESTATE','transaction':tx,
         'payloadSHA256':payload_sha,'before':before,'backupHex':backup,
         'queueSourceSHA256':payload['queueSourceSHA256'],
         'queueLoggerSHA256':payload['queueLoggerSHA256'],
         'mainCommit':payload['mainCommit'],'oldControl':payload['oldControl']}
    new_file(txdir/'preflight.json',enc(pre),0,0o600)
    installed=[];outcomes={}
    try:
        directory(ROOT/'guard',0,0o755)
        directory(ROOT/'releases',0,0o755)
        release=ROOT/'releases'/tx
        directory(release,0,0o755)
        for n in PROGRAMS:
            new_file(release/n,source[n],0,0o444)
        for n in ('install_remote.py','rollback_before_submit.py'):
            new_file(release/n,source[n],0,0o444)
        proof=release/'proof-sources';directory(proof,0,0o755)
        for n in PROOF:
            if n in source:new_file(proof/n,source[n],0,0o444)
        engine_dir=release/'engine';directory(engine_dir,0,0o755)
        for n in ENGINE:
            target=engine_dir/n
            parent=target.parent
            missing=[]
            while not parent.exists() and parent!=engine_dir:
                missing.append(parent);parent=parent.parent
            for d in reversed(missing):directory(d,0,0o755)
            new_file(target,engine[n],0,0o444)
        new_file(release/'fixed-policy.json',enc(payload['policy']),0,0o444)
        if payload['policy']['kind']=='ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1':
            directory(PRIVATE/'operations',1000,0o700)
            directory(Path(payload['policy']['storageBase']),1000,0o700)
            recipes=ROOT/'normal-operations';directory(recipes,0,0o755)
            for name in OPERATION_DATA:
                recipe=source[name];target=recipes/(sha(recipe)+'.json')
                if os.path.lexists(target):
                    need(full(target)['sha256']==sha(recipe),'immutable normal recipe collision')
                else:new_file(target,recipe,0,0o444)
        new_file(release/'control-approval.json',enc(payload['approval']),0,0o444)
        # Pre-build all user and root replacement bytes before first swap.
        prior_env=bytes.fromhex(backup['runnerEnv'])
        replacements={
            'planner':(source['planner.py'],0,0o555),
            'guardScript':(source['job-started.sh'],0,0o555),
            'guardCode':(source['job_guard.py'],0,0o444),
            'profile':(enc(payload['profile']),0,0o444),
            'registry':(enc(payload['registry']),1000,0o400),
            'runnerEnv':(configure_env(prior_env),1000,0o600),
        }
        if payload['policy'].get('sourceBuildEnabled')is True:
            replacements['producerWorkflow']=(enc(payload['policy']['producerWorkflowPolicy']),0,0o444)
        for label,(data,uid,mode) in replacements.items():
            post,outcome=replacement(targets(payload)[label],data,uid,mode,before[label],tx,
                             txdir/('backup-'+label))
            outcomes[label]=outcome
            if outcome!='unchanged':installed.append((label,post))
        directory(EXCHANGE.parent,1000,0o700)
        directory(EXCHANGE,1000,0o700)
        host_private=OP/('robot-host-private-'+tx)
        directory(host_private,1000,0o700)
        lease={'kind':'OPEMOS_ROBOT_FIXED_CONTROL_LEASE','runtimeAuthorized':True,
          'repository':'CorniiDog/OPEMOS.EXE','runnerId':21,
          'connection_proof_authorized':False,
          'manifest':payload['runnerManifest'],
          'guard_pins':{'job_guard.py':sha(source['job_guard.py']),
                        'job-started.sh':sha(source['job-started.sh'])},
          'engine_source_commit':payload['mainCommit'],'engine_bundle':str(engine_dir),
          'engine_pins':{n:sha(engine[n]) for n in ENGINE},
          'planner_path':str(ROOT/'opemos-robot-job-plan'),
          'planner_sha256':sha(source['planner.py']),
          'profile_path':str(CONFIG/'robot.json'),
          'profile_sha256':sha(enc(payload['profile'])),
          'runner_env_sha256':sha(replacements['runnerEnv'][0]),
          'host_private_root':str(host_private),'report_exchange':str(EXCHANGE),
          'connection_bundle':str(proof),
          'connection_fixed_policy':{'path':str(release/'fixed-policy.json'),
                                      'sha256':sha(enc(payload['policy']))},
          'connection_login':payload['login']['path'],
          'connection_queue_sha256':payload['queueSourceSHA256'],
          'connection_queue_logger_sha256':payload['queueLoggerSHA256']}
        if payload['policy'].get('sourceBuildEnabled')is True:
            lease['producer_workflow_policy']={'path':str(targets(payload)['producerWorkflow']),
                'sha256':sha(replacements['producerWorkflow'][0])}
        lease_dir=OP/('robot-control-'+tx);directory(lease_dir,1000,0o700)
        new_file(release/'lease.json',enc(lease),0,0o444)
        approval_path=release/'control-approval.json'
        job_id='root-github-robot-control-'+tx
        job={'version':1,'jobs':[{'id':job_id,'platform':'controlplane','owner':'root',
          'command':['/usr/bin/python3',str(release/'launch.py'),str(release/'lease.json'),
                     '/run/user/1000/opemos-robot-control-'+tx],
          'cwd':str(release),
          'files':[str(release/n) for n in PROGRAMS]+[str(release/'lease.json')],
          'cores':1,'memory':'1GiB','timeout_seconds':payload['approval']['wallSeconds'],
          'resources':['opemos-robot-controlplane'],'depends_on':[],
          'requires_success':True,
          'approval':{'path':str(approval_path),'sha256':sha(enc(payload['approval']))}}]}
        new_file(lease_dir/'job.json',enc(job),1000,0o600)
        staged_paths={n:release/n for n in PROGRAMS}
        staged_paths.update({'proof/'+n:proof/n for n in PROOF if n in source})
        staged_paths.update({'engine/'+n:engine_dir/n for n in ENGINE})
        staged_paths.update({'installer':release/'install_remote.py',
                             'rollback':release/'rollback_before_submit.py',
                             'policy':release/'fixed-policy.json',
                             'controlApproval':approval_path,
                             'lease':release/'lease.json',
                             'job':lease_dir/'job.json'})
        current={k:full(v) for k,v in targets(payload).items()}
        originals=original_custody(before,current,outcomes,txdir,payload)
        new_file(txdir/'postflight.json',enc({'kind':'ROBOT_INSTALL_VERIFIED_NO_QUEUE_EFFECT',
          'transaction':tx,'installed':current,'targetOutcomes':outcomes,
          'originalCustody':originals,
          'staged':{k:full(v) for k,v in staged_paths.items()},
          'leaseSHA256':sha(enc(lease)),'jobSHA256':sha(enc(job)),
          'rootRelease':str(release),'queueSubmit':False,'vm':False}),0,0o600)
        return {'transaction':tx,'stage':'INSTALLED_NOT_SUBMITTED',
                'lease':str(release/'lease.json'),'job':str(lease_dir/'job.json'),
                'queueSubmitCommand':['/usr/bin/python3',str(QUEUE/'test_queue.py'),
                  '--queue',str(QUEUE/'state'),'submit',str(lease_dir/'job.json')],
                'rollback':{'installationFailure':'automatic exact-inode guarded restore; first error retained',
                            'afterSuccessfulInstall':'UNAVAILABLE: ordinary submit is not excluded by worker.lock; preserve targets, job, lease and backups',
                            'available':False,
                            'reason':'no continuous submit/start exclusion exists in this reviewed graph',
                            'commandTemplate':['/usr/bin/sudo','-n','/usr/bin/python3','-I',
                              str(release/'rollback_before_submit.py'),tx,
                              '<root-owned-fresh-no-job-proof-path>',
                              '<exact-proof-sha256>']}}
    except BaseException as first:
        errors=[]
        for label,outcome in outcomes.items():
            if outcome!='unchanged':continue
            try:exact_previous(targets(payload)[label],before[label])
            except BaseException as error:errors.append((label+'-unchanged',str(error)))
        for label,post in reversed(installed):
            try:
                path=targets(payload)[label];need(full(path)==post,'rollback target drift')
                if before[label]['absent']:
                    path.unlink();fsync_parent(path)
                else:
                    old_path=txdir/('backup-'+label);old=full(old_path);m=before[label]
                    need(old['dev']==m['dev'] and old['ino']==m['ino'] and
                         old['sha256']==m['sha256'] and old['mode']==m['mode'] and
                         old['uid']==m['uid'] and old['gid']==m['gid'] and
                         old['nlink']==1,'original inode backup changed')
                    os.replace(old_path,path);fsync_parent(path)
                    restored=full(path)
                    need(restored['dev']==m['dev'] and restored['ino']==m['ino'] and
                         restored['sha256']==m['sha256'] and
                         restored['mode']==m['mode'] and restored['uid']==m['uid'] and
                         restored['gid']==m['gid'] and
                         restored['mtimeNs']==m['mtimeNs'],
                         'original inode rollback content/mode/mtime differs')
            except BaseException as e:errors.append((label,str(e)))
        # replacement() alone owns cleanup of its made/linked/renamed resources.
        # Never infer ownership for unstarted labels from deterministic names,
        # UID, or an alias: preexisting and raced unknown names remain untouched.
        try:
            new_file(txdir/'failed.json',enc({'firstType':type(first).__name__,
              'first':str(first)[:2000],'firstNotes':getattr(first,'__notes__',[]),
              'rollbackErrors':errors,
              'source':'original preflight and backup retained'}),0,0o600)
        except BaseException as error:errors.append(('failure-persistence',str(error)))
        first.add_note('independent install finalization: '+repr(errors))
        raise


def install(payload,payload_sha):
    source,engine=require_source(payload)
    lock=QUEUE/'state/worker.lock'
    fd=os.open(lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==1000 and st.st_nlink==1,
             'existing ordinary queue worker lock custody')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:raise RuntimeError('ordinary queue worker busy') from e
        return _install_locked(payload,payload_sha,source,engine)
    finally:os.close(fd)


def main():
    need(len(sys.argv)==3 and sys.argv[1]=='install' and
         re.fullmatch(r'[0-9a-f]{64}',sys.argv[2]),
         'exact install mode and reviewed payload SHA')
    raw=sys.stdin.buffer.read(16*1024*1024+1)
    need(len(raw)<=16*1024*1024 and sha(raw)==sys.argv[2],
         'complete exact reviewed payload')
    result=install(strict(raw),sys.argv[2])
    sys.stdout.buffer.write(enc(result))

if __name__=='__main__':main()

#!/usr/bin/python3
"""Current Root/OMEN read-only provider for the finite Runner21 trigger.

No original queue SQLite connection is made. The existing source-verified
queue validator operates on a bounded private DB/WAL copy only. Every error
refuses a cycle; an unreachable GitHub API is a typed offline observation.
"""
import contextlib, fcntl, hashlib, json, os, re, shutil, sqlite3, stat, subprocess, sys, tempfile, time, types
from pathlib import Path

ROOT=Path('/var/lib/opemos-robot-control-r1/auto-recovery')
CONTROL=ROOT.parent
QUEUE=Path('/home/connor/.local/state/opemos-test-queue-r2')
RUNNER=Path('/home/connor/.local/share/opemos-ci/github-runner')
GH=['/usr/sbin/runuser','-u','connor','--','/usr/bin/env',
    'XDG_CONFIG_HOME=/home/connor/.config','/usr/bin/gh','api']
MAX_DB=64*1024*1024
PRIVATE_DIR=Path('/run')

def need(ok,msg):
    if not ok:raise RuntimeError(msg)
def enc(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def full9(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]

def held(path,cap,uid=None,mode=None):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=cap and
             (uid is None or a.st_uid==uid) and
             (mode is None or stat.S_IMODE(a.st_mode)==mode),
             'held current source/data custody '+str(path))
        raw=bytearray()
        while True:
            z=os.read(fd,min(65536,cap+1-len(raw)))
            need(len(raw)+len(z)<=cap,'bounded held input')
            if not z:break
            raw.extend(z)
        need(len(raw)==a.st_size and full9(a)==full9(os.fstat(fd))==
             full9(os.stat(path,follow_symlinks=False)),
             'held/named current full9 changed '+str(path))
        return bytes(raw),full9(a)
    finally:os.close(fd)

def root_policy():
    if 'REMOTE_POLICY' in globals():
        return REMOTE_POLICY
    raw,_=held(ROOT/'policy.json',65536,0,0o400)
    p=json.loads(raw)
    need(p['enabled'] is True and p['sourceAccepted'] is True and
         p['runtimeAuthorized'] is True and p['runnerId']==21 and
         p['repository']=='CorniiDog/OPEMOS.EXE',
         'reviewed current Root policy')
    return p

def pin_source(path,digest,uid=None):
    raw,identity=held(path,8*1024*1024,uid)
    need(sha(raw)==digest,'CURRENT_SOURCE_DRIFT '+str(path))
    return raw,identity

def installed_normal_installer(p):
    """The reviewed installer role may advance without copying an old lease."""
    pin=p.get('normalInstallerSourcePin')
    path=CONTROL/'releases'/p['currentReleaseTx']/'install_remote.py'
    if pin is not None:
        need(type(pin)is dict and set(pin)=={'path','bytes','sha256','identity'}and
             type(pin['path'])is str and re.fullmatch(
             '/var/lib/opemos-robot-control-r1/releases/[0-9a-f]{32}/install_remote\\.py',pin['path'])and
             pin['sha256']==p['normalInstallerSHA256'],'same protected installer source role')
        path=Path(pin['path'])
    raw,identity=pin_source(path,p['normalInstallerSHA256'],0)
    if pin is not None:
        need(identity==pin['identity']and len(raw)==pin['bytes']and
             identity['st_gid']==0 and stat.S_IMODE(identity['st_mode'])==0o444 and
             identity['st_nlink']==1,'actual immutable installer source full9/bytes')
    return raw,identity,path


def local_sources(p):
    tx=p['currentReleaseTx']
    need(type(tx) is str and re.fullmatch(r'[0-9a-f]{32}',tx),
         'exact current installed release transaction')
    release=CONTROL/'releases'/tx
    mappings={
        'queueSourceSHA256':QUEUE/'test_queue.py',
        'queueLoggerSHA256':QUEUE/'queue_job.py',
        'normalQueueEntrySHA256':QUEUE/'queue.sh',
        'heavySHA256':QUEUE/'heavy.sh',
        'jobStartedSHA256':CONTROL/'guard/job-started.sh',
        'jobGuardSHA256':CONTROL/'guard/job_guard.py',
        'privatePeerSHA256':release/'connection_host.py',
    }
    out={};queue_source=None
    for key,path in mappings.items():
        raw,full=pin_source(path,p[key],0 if path.is_relative_to(CONTROL) else 1000)
        out[key]={'sha256':sha(raw),'full9':full}
        if key=='queueSourceSHA256':queue_source=raw
    raw,full,_=installed_normal_installer(p)
    out['normalInstallerSHA256']={'sha256':sha(raw),'full9':full}
    lease_raw,lease_identity=pin_source(release/'lease.json',p['currentReleaseLeaseSHA256'],0)
    out['currentReleaseLease']={'sha256':sha(lease_raw),'full9':lease_identity}
    lease=json.loads(lease_raw)
    need(lease.get('engine_source_commit')==p['mainCommit'] and
         lease.get('manifest',{}).get('sha256')==p['runnerManifestSHA256'],
         'installed release Main/runner manifest')
    manifest_raw,manifest_identity=pin_source(Path(lease['manifest']['path']),
                                              p['runnerManifestSHA256'])
    out['runnerManifest']={'sha256':sha(manifest_raw),'full9':manifest_identity}
    reg,reg_identity=held(RUNNER/'.runner',65536,1000)
    registered=json.loads(reg.decode('utf-8-sig'))
    need(registered.get('agentId')==21 and
         registered.get('agentName')=='opemos-omen-robot',
         'existing registered Runner21 identity')
    out['registration']={'sha256':sha(reg),'full9':reg_identity}
    env,env_identity=held(RUNNER/'.env',65536,1000,0o600)
    need(('ACTIONS_RUNNER_HOOK_JOB_STARTED='+
          str(CONTROL/'guard/job-started.sh')).encode() in env.splitlines(),
         'actual registered Runner uses existing guarded job-started source')
    out['runnerEnv']={'sha256':sha(env),'full9':env_identity}
    return out,lease,queue_source

def gh_json(path,timeout=10):
    r=subprocess.run(GH+[path],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,timeout=timeout,check=False)
    need(r.returncode==0 and len(r.stdout)<=1048576 and len(r.stderr)<=65536,
         'current GitHub API unavailable')
    return json.loads(r.stdout)

def runner21_active_runs(read):
    # Only this reviewed consumer can receive native Runner21 work. Hosted
    # packaging activity is not an assignment frontier for the OMEN owner.
    path='repos/CorniiDog/OPEMOS.EXE/actions/workflows/omen-robot.yml/runs?status=in_progress&per_page=100'
    for attempt in range(3):
        active=read(path)
        total=active.get('total_count')if type(active)is dict else None
        runs=active.get('workflow_runs')if type(active)is dict else None
        # GitHub can return a count from just before the final run completed.
        # Retry only this typed, bounded listing transition, never malformed
        # ownership data or an incomplete job/runner assignment.
        transition=(type(total)is int and 0<=total<=100 and type(runs)is list and
            len(runs)<=100 and len(runs)!=total and
            all(type(r)is dict and type(r.get('id'))is int and r['id']>0 and
                r.get('status')=='in_progress'and type(r.get('path'))is str and
                r['path'].split('@',1)[0]=='.github/workflows/omen-robot.yml'for r in runs)and
            len({r['id']for r in runs})==len(runs))
        if not transition or attempt==2:return active
        time.sleep(.1)


def runner21_assigned_jobs(active, read):
    """Scope active Actions ownership to this registered runner, not the repo.

    Any relevant job with an incomplete runner assignment is UNKNOWN and
    refuses the probe. A bounded run/job frontier avoids silent pagination.
    """
    total=active.get('total_count')
    runs=active.get('workflow_runs')
    complete=(type(total) is int and 0<=total<=100 and type(runs) is list and len(runs)==total)
    if not complete:
        observed={'total_count':total,'returned':len(runs)if type(runs)is list else None,
                  'run_ids':[r.get('id')for r in runs[:100]if type(r)is dict]if type(runs)is list else None}
        raise RuntimeError('bounded complete active workflow-run frontier; observed='+json.dumps(observed,sort_keys=True))
    owned=0
    relevant_runs=0
    for run in runs:
        run_id=run.get('id')
        need(type(run_id) is int and run_id>0 and
             run.get('status')=='in_progress' and
             type(run.get('path')) is str,
             'current active workflow-run identity')
        need(run['path'].split('@',1)[0]=='.github/workflows/omen-robot.yml',
             'only exact reviewed workflow in runner assignment frontier')
        relevant_runs+=1
        need(relevant_runs<=10,'bounded reviewed consumer workflow frontier')
        page=read('repos/CorniiDog/OPEMOS.EXE/actions/runs/'+str(run_id)+
                  '/jobs?per_page=100')
        jobs=page.get('jobs');count=page.get('total_count')
        need(type(count) is int and 0<=count<=100 and type(jobs) is list and
             len(jobs)==count,'bounded complete active job assignment frontier')
        for job in jobs:
            need(type(job) is dict and type(job.get('id')) is int and
                 job.get('run_id')==run_id and
                 job.get('status') in ('queued','in_progress','completed') and
                 type(job.get('labels')) is list,
                 'typed current Actions job ownership')
            labels=job['labels']
            need(all(type(x) is str for x in labels),
                 'complete current job label custody')
            relevant='opemos-omen-robot' in labels
            assigned=job.get('runner_id')
            if job['status']=='in_progress':
                need(assigned!=21 or relevant,
                     'runner21 assignment without reviewed label')
                need(not(relevant and assigned is None),
                     'unknown relevant active job runner assignment')
                if relevant or assigned==21:
                    need(assigned==21,'relevant job assigned foreign runner')
                    owned+=1
    need(owned<=1,'duplicate active Runner21 job assignment')
    return owned

def current_github(p,route_only=False):
    if 'REMOTE_GITHUB' in globals():
        value=dict(REMOTE_GITHUB)
        if route_only:
            value.update(actionsInProgress=None,actionsQueued=None)
            if value['networkReachable']:value['mainCommit']=value['protectedMainCommit']
        return value
    try:
        branch=gh_json('repos/CorniiDog/OPEMOS.EXE/branches/main')
        if route_only:
            runner=gh_json('repos/CorniiDog/OPEMOS.EXE/actions/runners/21')
            runners={'runners':[runner]}
        else:
            runners=gh_json('repos/CorniiDog/OPEMOS.EXE/actions/runners?per_page=100')
            active=runner21_active_runs(gh_json)
            queued=gh_json('repos/CorniiDog/OPEMOS.EXE/actions/runs?status=queued&per_page=1')
    except (OSError,subprocess.TimeoutExpired):
        return {'networkReachable':False,'protectedMain':False,'mainCommit':None,'protectedMainCommit':None,
                'runnerOnline':False,'runnerBusy':False,'actionsInProgress':None,
                'actionsQueued':None,'heartbeatCurrent':False,
                'heartbeatNonce':None}
    need(branch.get('protected') is True and
         type(branch.get('commit',{}).get('sha')) is str and
         re.fullmatch(r'[0-9a-f]{40}',branch['commit']['sha']),
         'protected Main unavailable')
    matches=[r for r in runners.get('runners',[]) if r.get('id')==21]
    need(len(matches)==1 and matches[0].get('name')=='opemos-omen-robot' and
         'opemos-omen-robot' in {x.get('name') for x in matches[0].get('labels',[])},
         'exact registered GitHub runner21')
    runner=matches[0]
    if not route_only:
        need(type(queued.get('total_count')) is int,
             'complete current Actions total counts')
    owned=None if route_only else runner21_assigned_jobs(active,gh_json)
    try:
        heartbeat=gh_json('repos/CorniiDog/OPEMOS.EXE/actions/variables/OPEMOS_OMEN_ROBOT_RUNNER_STATE')
        h=json.loads(heartbeat['value'])
    except (OSError,subprocess.TimeoutExpired,RuntimeError,KeyError,TypeError,ValueError):h={}
    current=(h.get('source_commit')==p['mainCommit'] and
             h.get('queue_source_sha256')==p['queueSourceSHA256'] and
             h.get('runner_id')==21 and
             h.get('ready') is True and h.get('checked_at',0)>=time.time()-180 and
             h.get('expires_at',0)>time.time())
    nonce=h.get('recovery_nonce')
    if type(nonce) is not str or not re.fullmatch(r'[0-9a-f]{32}',nonce):nonce=None
    return {'networkReachable':True,'protectedMain':True,
            'mainCommit':branch['commit']['sha']if route_only else p['mainCommit'],
            'protectedMainCommit':branch['commit']['sha'],
            'runnerOnline':runner.get('status')=='online',
            'runnerBusy':runner.get('busy') is True,
            'actionsInProgress':owned,
            'actionsQueued':None if route_only else queued['total_count'],'heartbeatCurrent':current,
            'heartbeatNonce':nonce}

def health_source(ref,mode=0o444):
    """Authenticate executable bytes before imports, using their real paths."""
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    need(type(ref) is dict and set(ref)=={'path','bytes','sha256','identity'} and
         type(ref['identity']) is dict and set(ref['identity'])==set(fields),
         'complete health implementation pin')
    path=Path(ref['path']);need(path.is_absolute() and '..' not in path.parts,
                               'absolute health implementation path')
    descriptors=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);descriptors.append(fd)
        for part in path.parent.parts[1:]:
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);descriptors.append(fd)
            st=os.fstat(fd)
            need(st.st_uid==st.st_gid==0 and not st.st_mode&0o022,
                 'Root nofollow health implementation ancestry')
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);descriptors.append(fd)
        before=os.fstat(fd);identity=lambda s:{k:getattr(s,k) for k in fields}
        need(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and
             stat.S_IMODE(before.st_mode)==mode and before.st_nlink==1 and
             0<before.st_size<=1048576,'immutable bounded health implementation')
        raw=b''
        while block:=os.read(fd,65536):
            raw+=block;need(len(raw)<=1048576,'health implementation cap')
        need(identity(before)==ref['identity']==identity(os.fstat(fd))==identity(os.lstat(path)) and
             len(raw)==ref['bytes'] and sha(raw)==ref['sha256'],
             'held/named health implementation full9/bytes/hash')
        return raw
    finally:
        for fd in reversed(descriptors):os.close(fd)

@contextlib.contextmanager
def health_queue(source_raw,implementation_pin=None):
    """Installed listener identity and readonly observer implementation differ."""
    if implementation_pin is None:
        q=types.ModuleType('authenticated_installed_queue');q.__file__=str(QUEUE/'test_queue.py')
        exec(compile(source_raw,q.__file__,'exec'),q.__dict__)
        yield q
        return
    definition=json.loads(health_source(implementation_pin))
    root=Path(implementation_pin['path']).parent
    need(root.parent==Path('/run') and re.fullmatch('opemos-media-source-[0-9a-f]{32}',root.name) and
         implementation_pin['path']==str(root/'installed-controller.json'),
         'existing confined health implementation definition')
    roles=definition['sourceRoles']
    names=('libvirt_storage','retained_media','source_contract','libvirt_peer',
           'libvirt_access','guest_firmware_probe','libvirt_native','queue_assignment')
    bodies={}
    for name in names:
        need(roles[name]['path']==str(root/(name+'.py')),'same health implementation source root')
        bodies[name]=health_source(roles[name])
    # The pinned definition is DATA; authenticate every executable in its
    # existing graph before interpreting any member of that graph.
    for ref in [*roles.values(),*definition['preparationRoles'].values()]:
        health_source(ref)
    for ref in definition['queuePrograms']:
        health_source(ref,0o555 if Path(ref['path']).name in ('heavy.sh','queue.sh','queue-files.sh') else 0o444)
    missing=object();previous={name:sys.modules.get(name,missing) for name in names}
    try:
        for name in names:
            m=types.ModuleType(name);m.__file__=roles[name]['path'];sys.modules[name]=m
        for name in names:
            m=sys.modules[name];exec(compile(bodies[name],m.__file__,'exec'),m.__dict__)
        shared=sys.modules['source_contract']
        need(shared.read_definition(implementation_pin)==definition,'same health implementation definition')
        shared.validate(roles,definition['queuePrograms'],implementation_pin)
        q=sys.modules['queue_assignment'].load_queue(definition['queuePrograms'][0],
                                                    implementation_definition=implementation_pin)
        yield q
        shared.validate(roles,definition['queuePrograms'],implementation_pin)
    finally:
        for name,old in previous.items():
            if old is missing:sys.modules.pop(name,None)
            else:sys.modules[name]=old

class QueueSnapshotChanged(RuntimeError):
    """Only a concurrently changing canonical data epoch may be read again."""


def queue_snapshot_file(path,cap,optional=False):
    # SQLite may remove WAL/cache sidecars after any existence check. Open the
    # actual descriptor first; this is data, never executable source custody.
    try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    except FileNotFoundError:
        if optional:return None
        raise
    def custody(s):
        # A successful nofollow open can be unlinked before its first fstat.
        # Zero links permits ONLY a complete recopy, never using those bytes.
        need(stat.S_ISREG(s.st_mode)and s.st_nlink in((0,1)if optional else(1,))and
             s.st_uid==1000 and 0<=s.st_size<=cap,
             'held current queue data custody '+str(path))
    try:
        before=os.fstat(fd);custody(before);raw=bytearray()
        while block:=os.read(fd,min(65536,cap+1-len(raw))):
            raw.extend(block);need(len(raw)<=cap,'bounded held queue data')
        after=os.fstat(fd);custody(after)
        try:named=os.stat(path,follow_symlinks=False)
        except FileNotFoundError:
            if optional:raise QueueSnapshotChanged('queue sidecar disappeared')from None
            raise
        custody(named)
        if any(s.st_nlink==0 for s in(before,after,named)):
            raise QueueSnapshotChanged('optional queue sidecar unlinked while held')
        if len(raw)!=before.st_size or full9(before)!=full9(after)or full9(before)!=full9(named):
            raise QueueSnapshotChanged('queue data epoch changed during held read')
        return bytes(raw),full9(before)
    finally:os.close(fd)


def private_snapshot(validate=None):
    # Recopy the complete epoch on a known SQLite-data race only. All source,
    # owner, native, pool, SQL and UNKNOWN failures keep their original refusal.
    end=time.monotonic()+2
    for attempt in range(3):
        try:return private_snapshot_once(validate)
        except QueueSnapshotChanged:
            if attempt==2 or time.monotonic()>=end:raise
            time.sleep(min(.01,max(0,end-time.monotonic())))
            if time.monotonic()>=end:raise


def private_snapshot_once(validate=None):
    """One held canonical/WAL epoch; SQL is private-only and never writes live state."""
    state=QUEUE/'state'; names=['queue.sqlite3','queue.sqlite3-wal',
                                'queue.sqlite3-shm','queue.sqlite3-journal']
    limits=[MAX_DB,8*1024*1024,1024*1024,8*1024*1024]
    initial={};payload={}
    for name,limit in zip(names,limits):
        path=state/name
        value=queue_snapshot_file(path,limit,optional=name!='queue.sqlite3')
        if value is None:initial[name]=None;continue
        raw,identity=value
        initial[name]={'full9':identity,'sha256':sha(raw)};payload[name]=raw
    need(initial['queue.sqlite3'] is not None and
         initial['queue.sqlite3-journal'] is None,
         'current no-journal private queue snapshot')
    # All byte reads precede private-only SQL. Any concurrent original change
    # invalidates the snapshot, including sidecar appearance/disappearance.
    for name,limit in zip(names,limits):
        path=state/name
        value=queue_snapshot_file(path,limit,optional=name!='queue.sqlite3')
        current=None if value is None else {'full9':value[1],'sha256':sha(value[0])}
        if current!=initial[name]:
            raise QueueSnapshotChanged('queue source changed before private SQL')
    temp=Path(tempfile.mkdtemp(prefix='runner21-probe-',dir=PRIVATE_DIR))
    try:
        os.chmod(temp,0o700)
        for name,raw in payload.items():
            path=temp/name
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                view=memoryview(raw)
                while view:
                    n=os.write(fd,view);need(n>0,'private copy short write');view=view[n:]
                os.fsync(fd)
            finally:os.close(fd)
        db=sqlite3.connect('file:'+str(temp/'queue.sqlite3')+'?mode=ro',uri=True,timeout=2)
        db.row_factory=sqlite3.Row
        try:
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            rows=[dict(x) for x in db.execute('SELECT * FROM jobs ORDER BY rowid')]
            bindings=[dict(x) for x in db.execute('SELECT * FROM pool_unit_bindings ORDER BY rowid')]
            config=[dict(x) for x in db.execute('SELECT * FROM config ORDER BY rowid')]
            need(db.total_changes==0 and len(rows)<=4096 and len(bindings)<=4096 and
                 len(config)==1,'bounded canonical private queue relation')
            if validate is not None:validate(db,rows,bindings,config)
            db.rollback()
        finally:db.close()
    finally:shutil.rmtree(temp)
    for name,limit in zip(names,limits):
        path=state/name
        value=queue_snapshot_file(path,limit,optional=name!='queue.sqlite3')
        current=None if value is None else {'full9':value[1],'sha256':sha(value[0])}
        if current!=initial[name]:
            raise QueueSnapshotChanged('queue source changed after private SQL')
    return rows,bindings,config

def private_queue(source_raw,observer_capture=None,pool_capture=None,implementation_pin=None):
    state=QUEUE/'state'
    if implementation_pin is None:
        implementation_pin=root_policy().get('healthImplementationDefinitionPin')
    def validate(db,rows,bindings,config):
        with health_queue(source_raw,implementation_pin) as q:
            backend=q.SystemdBackend(state,json.loads(config[0]['value']))
            if implementation_pin is not None:backend.terminal_implementation_pin=implementation_pin
            if observer_capture is not None:
                need(type(observer_capture)is list and len(observer_capture)==0,'fresh bounded readonly observer capture buffer')
                backend.observer_captures=observer_capture
            proof=backend.validate_pool(
                q.pool_rows(db,db.execute('SELECT * FROM jobs ORDER BY rowid').fetchall()))
        need(proof.get('admitted') is True and
             type(proof.get('unknownReservationsRetained')) is list and
             proof['unknownReservationsRetained']==[],
             'canonical current whole-pool proof')
        if pool_capture is not None:
            need(type(pool_capture) is list and not pool_capture,'fresh actual pool proof capture')
            pool_capture.append(proof)
    return private_snapshot(validate)

def classify_rows(rows,bindings,p):
    active=[r for r in rows if r['state'] in ('running','terminal_cleanup')]
    unknown=[r['id'] for r in rows if r['state'] not in
             ('pending','running','terminal_cleanup','passed','failed',
              'timed_out','blocked','unknown','output_limit')]
    own=[r for r in rows if r['id'].startswith('root-github-robot-control-')]
    own_active=[r for r in own if r['state'] in ('pending','running','terminal_cleanup')]
    need(len(own_active)<=1,'one current control lineage')
    selected=(own_active[0] if own_active else
              max(own,key=lambda x:(x.get('started') or 0,x.get('finished') or 0,x['id']))
              if own else None)
    foreign=[r['id'] for r in active if selected is None or r['id']!=selected['id']]
    ids={r['id'] for r in rows}
    need(len(ids)==len(rows) and all(b['job_id'] in ids for b in bindings),
         'canonical relation identity')
    return selected,foreign,unknown

def actors():
    out=[]
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():continue
        try:
            raw=(path/'cmdline').read_bytes()[:131073]
            need(len(raw)<=131072,'bounded actor argv')
            if not any(x in raw for x in (b'Runner.Listener',b'Runner.Worker',
                                          b'qemu-system-',b'normal_cycle.py',
                                          b'job-started.sh',b'queue_job.py',
                                          b'/control.py',b'/launch.py')):continue
            statline=(path/'stat').read_text()
            start=int(statline.rsplit(')',1)[1].split()[19])
            uid=int(next(z.split()[1] for z in (path/'status').read_text().splitlines()
                         if z.startswith('Uid:')))
            out.append({'pid':int(path.name),'start':start,'uid':uid,
                        'argv':raw.decode(errors='replace').split('\0')[:32],
                        'cgroup':(path/'cgroup').read_text().strip()})
            need(len(out)<=128,'bounded relevant actors')
        except (FileNotFoundError,ProcessLookupError):continue
    return out

def source_writers(paths):
    pinned={(os.stat(path,follow_symlinks=False).st_dev,
             os.stat(path,follow_symlinks=False).st_ino) for path in paths}
    count=0
    for procpath in Path('/proc').iterdir():
        if not procpath.name.isdecimal():continue
        try:
            for fdpath in (procpath/'fd').iterdir():
                count+=1;need(count<=65536,'bounded all-UID source FD census')
                try:
                    target=os.stat(fdpath)
                    if (target.st_dev,target.st_ino) not in pinned:continue
                    info=(procpath/'fdinfo'/fdpath.name).read_text()
                    flags=int(next(z.split()[1] for z in info.splitlines()
                                   if z.startswith('flags:')),8)
                    if flags&os.O_ACCMODE in (os.O_WRONLY,os.O_RDWR):return True
                except (FileNotFoundError,ProcessLookupError):continue
        except (FileNotFoundError,ProcessLookupError):continue
    return False

def intel_host_graphics():
    intel=False
    for card in Path('/sys/class/drm').glob('card[0-9]*'):
        try:
            vendor=(card/'device/vendor').read_text().strip().lower()
            driver=(card/'device/driver').resolve(strict=True).name
            if vendor=='0x8086' and driver in ('i915','xe'):intel=True
            need(not(vendor=='0x10de' and driver=='nvidia'),
                 'NVIDIA must not be the physical host graphics driver')
        except FileNotFoundError:continue
    need(intel,'actual Intel host graphics binding absent')
    return 'INTEL_HOST_NVIDIA_GUEST_ONLY'

def current_control(row,p):
    result={'jobId':None,'state':'absent','terminalLifecycle':None,
            'reservationRetained':False,'sourceCommit':None,
            'queueSourceSHA256':None,'leaseExpiresUnix':None,
            'listenerAlive':False,'controllerAlive':False,
            'workerAlive':False,'ownUnitBound':False}
    if row is None:return result
    tx=row['id'].removeprefix('root-github-robot-control-')
    need(re.fullmatch(r'[0-9a-f]{32}',tx),'exact normal control job ID')
    release=CONTROL/'releases'/tx
    lease_raw,_=held(release/'lease.json',65536,0)
    lease=json.loads(lease_raw)
    broker_raw,_=held(release/'control.py',1048576,0,0o444)
    broker_sha=sha(broker_raw)
    need(broker_sha in (p['controlBrokerSHA256'],
                         p['priorControlBrokerSHA256']),
         'current exact selected broker source drift')
    policy_raw,_=held(release/'fixed-policy.json',65536,0)
    fixed=json.loads(policy_raw)
    need(lease.get('engine_source_commit') is not None and
         lease.get('connection_queue_sha256') is not None,
         'exact historical or current control source')
    phase=None;retained=False
    if row['result']:
        detail=json.loads(row['result'])
        lifecycle=detail.get('terminalLifecycle')
        if type(lifecycle) is dict:
            phase=lifecycle.get('phase');retained=lifecycle.get('reservationRetained')
    if row['state'] in ('running','pending','terminal_cleanup'):
        retained=True
    result.update(jobId=row['id'],state=row['state'],terminalLifecycle=phase,
                  reservationRetained=retained,
                  sourceCommit=lease['engine_source_commit'],
                  queueSourceSHA256=lease['connection_queue_sha256'],
                  leaseExpiresUnix=fixed.get('expiresAt'))
    result['brokerSHA256']=broker_sha
    return result

def connectivity_native_cut(source_raw,rows,bindings,config,p,relevant):
    """Current control/native membership only; never VM admission or release."""
    selected,_,_=classify_rows(rows,bindings,p)
    need(selected is not None and selected['state']=='running','actual running connection subject')
    with health_queue(source_raw,p.get('healthImplementationDefinitionPin')) as q:
        backend=q.SystemdBackend(QUEUE/'state',json.loads(config[0]['value']))
        need(backend.cfg.get('manager')=='system','actual system manager for connected control')
        native=sys.modules['libvirt_peer'];known={};own=None
        connection_units=set()
        for actor in relevant:
            if any(key in arg for arg in actor['argv']for key in ('Runner.Listener','Runner.Worker','/queue_job.py','/control.py')):
                connection_units.update(re.findall(r'opemos-testq-[0-9a-f-]+\.service',actor['cgroup']))
        for row in rows:
            if row['state']not in('running','terminal_cleanup')or (row['unit']not in connection_units and row['id']!=selected['id']):continue
            matches=[b for b in bindings if b['job_id']==row['id']]
            need(len(matches)==1,'one actual connection-unit canonical binding')
            bound=json.loads(matches[0]['value']);spec=json.loads(row['spec'])
            need(bound['version']==1 and bound['job_id']==row['id']==spec['id']and
                 bound['unit']==row['unit']and bound['stateRoot']==str(QUEUE/'state')and
                 bound['prefix']==backend.prefix and bound['specSHA256']==q.hashlib.sha256(q.canonical(spec).encode()).hexdigest()and
                 bound['cpus']==json.loads(row['cpus'])and bound['memory']==spec['memory'],
                 'exact original connection row/spec/resource/binding')
            props=backend.pool_unit_properties(row['unit'])
            need(props['LoadState']=='loaded'and props['InvocationID']==bound['invocation'],
                 'current connection-unit kernel invocation')
            known[row['unit']]=bound['invocation']
            if row['id']==selected['id']:own=(row,bound,props)
        need(own is not None,'own connected canonical/native unit')
        row,bound,props=own;group=backend.whole_owned_cgroup(row['unit'],props)
        need(props['ActiveState']=='active'and int(props['MainPID'])>0 and
             group['empty']is False and group['includesUID0']is True and group['completeTraversal']is True,
             'actual complete nonempty own connection unit')
        current={pid:native.process_snapshot(pid)for pid in group['processes']}
        main=int(props['MainPID']);need(main in current,'actual manager PID in held native unit')
        release=CONTROL/'releases'/row['id'].removeprefix('root-github-robot-control-')
        # Root-pinned control.py inherits the ordinary launcher's UID. Root
        # source custody and complete native-unit authority are checked above.
        roles={
          'listener':[v for v in current.values()if v['uids']==[1000]*4 and v['argv']==[str(RUNNER/'bin/Runner.Listener'),'run','--startuptype','service']],
          'worker':[v for v in current.values()if v['uids']==[1000]*4 and str(QUEUE/'queue_job.py')in v['argv']],
          'controller':[v for v in current.values()if v['uids']==[1000]*4 and str(release/'control.py')in v['argv']]}
        need(all(len(v)==1 for v in roles.values())and roles['worker'][0]['pid']==main,
             'unique exact current listener/controller/canonical worker roles')
        for role,values in roles.items():
            actor=values[0];need(actor['cgroup']==props['ControlGroup'],'exact role current cgroup')
            chain=set();cursor=actor
            while cursor['pid']!=main:
                need(cursor['pid']not in chain and cursor['ppid']in current,'actual role belongs to original worker ancestry')
                chain.add(cursor['pid']);cursor=current[cursor['ppid']]
        need(backend.pool_unit_properties(row['unit'])==props,'same own manager source/invocation after native observation')
        for actor in current.values():need(native.process_snapshot(actor['pid'])==actor,'actual own PID/start/UID/argv/cgroup changed')
        last=backend.whole_owned_cgroup(row['unit'],props)
        need(last['empty']is False and last['processes']==group['processes']and
             last['derivedPath']==group['derivedPath'],'same complete own native membership after role proof')
        return {'kind':'CONTROL_CONNECTIVITY_NATIVE_UNITS_R1','operationOrReleaseAuthorized':False,
                'knownInvocations':known,'ownJobId':row['id'],'ownUnit':row['unit'],
                'ownInvocation':bound['invocation'],'manager':props,'group':last,
                'roles':{name:values[0]for name,values in roles.items()},
                'VMReadiness':'NOT_OBSERVED','retainedVMJobIds':[r['id']for r in rows
                    if r['id']!=row['id']and r['state']in('running','terminal_cleanup','unknown')]}

def unclassified_route_actors(relevant,own_unit,rows,bindings,pool):
    """Recognize busy actors only through current canonical/kernel unit joins."""
    need(pool.get('kind')=='CONTROL_CONNECTIVITY_NATIVE_UNITS_R1'and pool.get('operationOrReleaseAuthorized')is False,
         'actual native connection membership, never VM admission')
    invocations=pool.get('knownInvocations')
    need(type(invocations) is dict,'actual kernel-validated unit invocations')
    known={}
    for row in rows:
        if row['state'] not in ('running','terminal_cleanup'):continue
        matched=[b for b in bindings if b['job_id']==row['id']]
        need(len(matched)==1,'active admitted owner exact canonical binding')
        value=json.loads(matched[0]['value']);unit=value.get('unit');invocation=value.get('invocation')
        # A retained actorless VM is not part of a live connection role.
        # Unknown live actors still fail below; absence of VM-observation
        # proof cannot erase the independently proved current listener.
        if unit not in invocations:continue
        need(unit==row.get('unit') and type(unit) is str and
             re.fullmatch(r'opemos-testq-[0-9a-f-]+\.service',unit) and
             type(invocation) is str and re.fullmatch(r'[0-9a-f]{32}',invocation) and
             invocations[unit]==invocation,'current row/binding/kernel invocation join')
        known[unit]=row['id']
    unknown=[]
    for actor in relevant:
        if not any(key in arg for arg in actor['argv'] for key in
                   ('Runner.Listener','Runner.Worker','/queue_job.py','/control.py')):continue
        units=re.findall(r'opemos-testq-[0-9a-f-]+\.service',actor['cgroup'])
        if len(units)!=1 or units[0] not in known:
            unknown.append({'pid':actor['pid'],'start':actor['start'],'uid':actor['uid'],'cgroup':actor['cgroup']})
    need(own_unit in known,'own live control in actual canonical/kernel unit set')
    return unknown

def observe(route_only=False):
    need(os.geteuid()==0,'fixed Root readonly probe entry')
    p=root_policy();sources,release,queue_source=local_sources(p)
    github=current_github(p,route_only=route_only)
    pool_capture=[];native_actors=[]
    if route_only:
        def native_validate(db,rows,bindings,config):
            relevant=actors();native_actors.extend(relevant)
            pool_capture.append(connectivity_native_cut(queue_source,rows,bindings,config,p,relevant))
        rows,bindings,config=private_snapshot(native_validate)
    else:
        rows,bindings,config=private_queue(queue_source,implementation_pin=p.get('healthImplementationDefinitionPin'))
    selected,foreign,unknown=classify_rows(rows,bindings,p)
    relevant=native_actors if route_only else actors();ctl=current_control(selected,p)
    broker_sha=ctl.pop('brokerSHA256',None)
    # Only actual running work blocks; pending jobs stay pending for a normal
    # dispatcher. Unknown actors or source writers are left to the normal
    # cycle's fresh admission and must not be inferred idle from this frame.
    unit=selected.get('unit') if selected else None
    own=[a for a in relevant if unit and unit in a['cgroup']]
    ctl['listenerAlive']=len([a for a in own if a['argv'][:1]==
                              ['/home/connor/.local/share/opemos-ci/github-runner/bin/Runner.Listener']])==1
    ctl['workerAlive']=len([a for a in own if any('/queue_job.py' in x
                                                  for x in a['argv'])])==1
    ctl['controllerAlive']=len([a for a in own if any('/control.py' in x
                                                      for x in a['argv'])])==1
    bound=[b for b in bindings if selected and b['job_id']==selected['id']]
    ctl['ownUnitBound']=bool(unit and len(bound)==1 and
         json.loads(bound[0]['value']).get('unit')==unit and
         re.fullmatch(r'[0-9a-f]{32}',
                      json.loads(bound[0]['value']).get('invocation','')))
    lockfd=os.open(QUEUE/'state/worker.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        lock=os.fstat(lockfd)
        need(stat.S_ISREG(lock.st_mode) and lock.st_uid==1000 and lock.st_nlink==1,
             'exact canonical worker lock')
        try:fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB);free=True
        except BlockingIOError:free=False
    finally:os.close(lockfd)
    guest=any(any('qemu-system-' in x for x in a['argv']) for a in relevant)
    # A live affected-source actor or an unclassified actor is a hold. The
    # effect-bearing cycle must reobserve the exact whole actor/owner guard.
    foreign_runtime=any(a not in own and any(
        key in x for x in a['argv'] for key in
        ('Runner.Listener','Runner.Worker','/queue_job.py','/control.py'))
        for a in relevant)
    protected_sources=[QUEUE/'test_queue.py',QUEUE/'queue.sh',
              QUEUE/'queue_job.py',QUEUE/'heavy.sh',
              CONTROL/'guard/job-started.sh',CONTROL/'guard/job_guard.py']
    writers=source_writers(protected_sources) if route_only or not foreign_runtime else False
    source_busy=foreign_runtime or writers
    frame={'kind':('ROOT_RUNNER21_CONNECTIVITY_PROBE_V1'if route_only else 'ROOT_RUNNER21_NORMAL_CURRENT_PROBE_V1'),'atUnix':time.time(),
           'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
           'protectedMain':github['protectedMain'],'mainCommit':github['mainCommit'],
           'protectedMainCommit':github['protectedMainCommit'],
           'runnerId':21,'registeredRunnerId':21,
           **{k:p[k] for k in ('runnerManifestSHA256','queueSourceSHA256',
              'queueLoggerSHA256','jobStartedSHA256','jobGuardSHA256',
              'privatePeerSHA256','normalInstallerSHA256','normalQueueEntrySHA256',
              'heartbeatProducerSHA256')},
           'controlBrokerSHA256':broker_sha,
           'networkReachable':github['networkReachable'],
           'runnerOnline':github['runnerOnline'],
           'runnerBusy':github['runnerBusy'] or any(any('Runner.Worker' in x
                       for x in a['argv']) for a in relevant),
           'heartbeatCurrent':github['heartbeatCurrent'],
           'heartbeatNonce':github['heartbeatNonce'],
           'actionsInProgress':github['actionsInProgress'],
           'actionsQueued':github['actionsQueued'],
           'sourceOwnerBusy':source_busy,'queueKnown':not unknown,
           'workerLockFree':free,'unknownReservations':unknown,
           'otherActiveJobs':foreign,'guestActive':guest,
           'gpuLeaseActive':guest or any('omen-iommu-group-1' in r['spec']
                                         for r in rows if r['state']=='running'),
           'hostGraphics':intel_host_graphics(),
           'control':ctl,'effects':[]}
    if route_only:
        # Queue-owned busy VMs/listeners are not source writers. Keep the
        # effect-bearing recovery probe's original stricter owner predicate;
        # the read-only route exposes actual source writers separately.
        frame['sourceWritersBusy']=writers
        need(len(pool_capture)==1,'one complete actual native connectivity cut')
        frame['connectivityProof']=pool_capture[0]
        proof=pool_capture[0]
        ctl.update(listenerAlive=proof['roles']['listener']['pid']>0,
                   controllerAlive=proof['roles']['controller']['pid']>0,
                   workerAlive=proof['roles']['worker']['pid']>0,
                   ownUnitBound=proof['ownUnit']==unit and proof['ownInvocation']==json.loads(bound[0]['value'])['invocation'])
        frame['unclassifiedRuntimeActors']=unclassified_route_actors(relevant,unit,rows,bindings,pool_capture[0])
    after,_,_=local_sources(p)
    need(after==sources,'all installed current source identities changed during probe')
    return frame

def main():
    need(sys.argv in ([sys.argv[0],'--probe'],[sys.argv[0],'--probe-route']),'fixed Root probe argv')
    print(enc(observe(route_only=sys.argv[1]=='--probe-route')).decode(),end='')

if __name__=='__main__':main()

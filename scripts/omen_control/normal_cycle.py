#!/usr/bin/python3
"""One Root-approved finite Runner21 control cycle through normal queue paths.

This is never a runner service launcher. It reobserves all inputs, uses the
existing reviewed installer and canonical queue submit/worker, and retains
uncertain effects under the parent recovery in-flight nonce.
"""
import hashlib, json, os, re, signal, stat, subprocess, sys, time, types
from pathlib import Path

ROOT=Path('/var/lib/opemos-robot-control-r1/auto-recovery')
CONTROL=ROOT.parent
QUEUE=Path('/home/connor/.local/state/opemos-test-queue-r2')
USER_ENV=['/usr/sbin/runuser','-u','connor','--','/usr/bin/env',
          'XDG_RUNTIME_DIR=/run/user/1000',
          'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus']
ACTIONS={'CREATE','RESUME_PENDING','RECONCILE_CLOSED',
         'GRACEFUL_RENEW','REFRESH_HEARTBEAT'}
# A normal drain returns 1 when retained history contains failures. Reentry
# applies only to the demonstrated unexpected worker-error exit 2, once over
# this unit's lifetime. The queue repeats all source/lock/admission guards.
DISPATCHER_REENTRY_PROPERTIES=['--property=Restart=no','--property=RestartForceExitStatus=2',
    '--property=RestartSec=2','--property=StartLimitIntervalSec=infinity',
    '--property=StartLimitBurst=2']

def need(ok,why):
    if not ok:raise RuntimeError(why)
def enc(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def sha(b):return hashlib.sha256(b).hexdigest()

def module(path,digest):
    if 'REMOTE_MODULES' in globals() and path.name in REMOTE_MODULES:
        raw=bytes.fromhex(REMOTE_MODULES[path.name])
        need(len(raw)<=1048576 and sha(raw)==digest,
             'exact controller-held remote module '+path.name)
        m=types.ModuleType('reviewed_'+path.stem);m.__file__=str(path)
        exec(compile(raw,str(path),'exec'),m.__dict__)
        if path.name=='normal_probe.py':
            m.REMOTE_POLICY=REMOTE_POLICY
            m.REMOTE_GITHUB=REMOTE_GITHUB
        if path.name=='runner21_recovery.py':
            m.read_state=lambda:REMOTE_STATE
            if 'REMOTE_TEMPLATE_HEX' in globals():m.REMOTE_TEMPLATE_HEX=REMOTE_TEMPLATE_HEX
        return m
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and
             a.st_size<=1048576,'reviewed fixed Root module')
        raw=os.read(fd,1048577)
        z=os.fstat(fd);n=os.stat(path,follow_symlinks=False)
        need(len(raw)==a.st_size and sha(raw)==digest and
             all(getattr(a,k)==getattr(z,k)==getattr(n,k) for k in
                 ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                  'st_size','st_mtime_ns','st_ctime_ns')),
             'held reviewed module drift '+str(path))
    finally:os.close(fd)
    m=types.ModuleType('reviewed_'+path.stem);m.__file__=str(path)
    exec(compile(raw,str(path),'exec'),m.__dict__)
    return m

def run(argv,input_bytes=b'',timeout=30,cap=1048576):
    p=subprocess.run(argv,input=input_bytes,stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,timeout=timeout,check=False)
    need(len(p.stdout)<=cap and len(p.stderr)<=65536,
         'bounded ordinary native capture')
    return p

def normal_at_use(action,nonce,policy,probe,trigger):
    now=int(time.time())
    trigger.validate_probe(probe,policy,now)
    # The wrapper fsyncs this exact nonce before it launches us.  A direct
    # invocation or a stale child cannot mint a control job on its own.
    state=trigger.validate_state(trigger.read_state())
    need(state['inflight']==nonce and
         now<state['epochExpiresUnix']<=policy['renewalAuthorizedUntilUnix'] and
         state['completedCycles']<policy['maxCycles'] and
         state['totalCycles']<policy['maxTotalCycles'],
         'current Root one-use in-flight state/epoch')
    local=dict(state);local['inflight']=None
    need(trigger.decision(probe,policy,now,local)==action and
         not probe['sourceOwnerBusy'] and
         probe['networkReachable'] is True and
         probe['protectedMain'] is True and
         not probe['actionsInProgress'] and
         not probe['runnerBusy'] and
         not probe['otherActiveJobs'] and
         not probe['unknownReservations'] and
         not probe['guestActive'] and
         not probe['gpuLeaseActive'],
         'at-use current safe idle differs from trigger')
    return probe

def manager(unit):
    need(type(unit) is str and re.fullmatch(r'opemos-testq-[0-9a-f-]+\.service',unit),
         'exact canonical own queue unit')
    p=run(['/usr/bin/systemctl','show',unit,'-p','LoadState','-p',
           'ActiveState','-p','MainPID','-p','ControlGroup','-p',
           'InvocationID'],timeout=10,cap=8192)
    need(p.returncode==0 and not p.stderr,'current own manager read')
    return dict(x.split('=',1) for x in p.stdout.decode().splitlines() if '=' in x)

def proc(pid):
    root=Path('/proc')/str(pid)
    st=(root/'stat').read_text().rsplit(')',1)[1].split()
    uid=[int(x) for x in next(z.split()[1:] for z in
          (root/'status').read_text().splitlines() if z.startswith('Uid:'))]
    return {'pid':pid,'start':int(st[19]),'uids':uid,
            'argv':(root/'cmdline').read_bytes().split(b'\0')[:-1],
            'cgroup':(root/'cgroup').read_text().strip()}

def retire_listener(row,probe,policy):
    """Signal only the attested idle Runner.Listener; queue closes naturally."""
    need(row['state']=='running' and row['id']==probe['control']['jobId'] and
         not probe['runnerBusy'] and not probe['actionsInProgress'] and
         not probe['guestActive'],
         'only bound idle current listener can retire')
    m=manager(row['unit'])
    need(m.get('ActiveState')=='active' and int(m.get('MainPID','0'))>0 and
         re.fullmatch(r'[0-9a-f]{32}',m.get('InvocationID','')) and
         row['unit'] in m.get('ControlGroup',''),
         'current exact own unit/invocation')
    group=Path('/sys/fs/cgroup')/m['ControlGroup'].lstrip('/')
    need(group.is_dir() and not group.is_symlink(),
         'current exact own queue group')
    pids=[int(x) for x in (group/'cgroup.procs').read_text().splitlines()]
    need(1<=len(pids)<=16 and int(m['MainPID']) in pids,
         'complete bounded own group')
    live=[proc(x) for x in pids]
    listeners=[x for x in live if x['argv'][:1]==
               [b'/home/connor/.local/share/opemos-ci/github-runner/bin/Runner.Listener']]
    need(len(listeners)==1 and listeners[0]['uids']==[1000]*4 and
         listeners[0]['argv']==[listeners[0]['argv'][0],b'run',b'--startuptype',b'service'] and
         all(row['unit'] in x['cgroup'] for x in live) and
         not any(any(b'Runner.Worker' in z or b'qemu-system-' in z
                     for z in x['argv']) for x in live),
         'exact idle listener and no job/guest in own group')
    listener=listeners[0]
    fd=os.pidfd_open(listener['pid'],0)
    try:
        need(proc(listener['pid'])==listener,
             'listener changed at pidfd signal boundary')
        signal.pidfd_send_signal(fd,signal.SIGTERM,None,0)
    finally:os.close(fd)
    return {'pid':listener['pid'],'start':listener['start'],
            'unit':row['unit'],'invocation':m['InvocationID']}

def current_rows(probe_module,policy):
    source,_=probe_module.pin_source(QUEUE/'test_queue.py',policy['queueSourceSHA256'],1000)
    rows,binds,cfg=probe_module.private_queue(source)
    selected,foreign,unknown=probe_module.classify_rows(rows,binds,policy)
    need(not foreign and not unknown,'current whole queue/owner changed')
    return selected,rows,binds,cfg

def completion_dispatch_nonce(nonce):
    """One typed dispatcher identity, distinct from the successor control."""
    need(re.fullmatch(r'[0-9a-f]{32}',nonce),'exact normal cycle nonce')
    value=sha(('normal-predecessor-finalizer:'+nonce).encode())[:32]
    need(value!=nonce,'distinct normal finalizer and successor identities')
    return value

def user_dispatcher(unit):
    need(re.fullmatch('opemos-root-robot-dispatcher-[0-9a-f]{32}\\.service',unit),
         'typed normal dispatcher unit')
    value=run(USER_ENV+['/usr/bin/systemctl','--user','show',unit,'-p','LoadState',
        '-p','ActiveState','-p','MainPID','-p','ControlGroup','-p','InvocationID','-p','ExecStart'],
        timeout=10,cap=8192)
    need(value.returncode==0 and value.stderr==b'','actual normal dispatcher manager')
    return dict(x.split('=',1)for x in value.stdout.decode().splitlines()if'='in x)

def owning_dispatcher(row,policy,state,starting=False):
    old=state['lastOutcome'];tx=old.get('dispatcherNonce')
    if tx is None:tx=row['id'].removeprefix('root-github-robot-control-')
    need(old.get('controlJobId')==row['id']and re.fullmatch('[0-9a-f]{32}',tx),
         'protected normal current dispatcher/control join')
    unit='opemos-root-robot-dispatcher-'+tx+'.service';m=user_dispatcher(unit)
    ref={'kind':'NORMAL_CONTROL_DISPATCHER_IDENTITY_V1','jobId':row['id'],
         'nonce':tx,'unit':unit,'queueSourceSHA256':policy['queueSourceSHA256'],
         'invocation':m.get('InvocationID'),'pid':int(m.get('MainPID','0')),'start':None}
    need(m.get('LoadState')=='loaded'and re.fullmatch('[0-9a-f]{32}',ref['invocation']or'')and
         str(QUEUE/'queue.sh')in m.get('ExecStart',''),'current source-bound normal dispatcher')
    if ref['pid']:
        actor=proc(ref['pid']);need(actor['uids']==[1000]*4 and unit in actor['cgroup']and
             unit in m.get('ControlGroup',''),'actual normal dispatcher leader/source group')
        ref['start']=actor['start']
        children=[int(x)for x in(Path('/proc')/str(ref['pid'])/'task'/str(ref['pid'])/'children').read_text().split()]
        workers=[]
        for pid in children:
            try:
                worker=proc(pid);parent=int((Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[1])
                if(parent==ref['pid']and worker['uids']==[1000]*4 and worker['argv']==
                   [b'/usr/bin/python3',str(QUEUE/'test_queue.py').encode(),b'--queue',str(QUEUE/'state').encode(),b'run']and
                   worker['cgroup'].startswith('0::/user.slice/user-1000.slice/user@1000.service/opemos.slice/opemos-heavy.slice/run-')and
                   worker['cgroup'].endswith('.scope')):workers.append(worker)
            except(FileNotFoundError,ProcessLookupError):continue
        if len(children)==len(workers)==1:ref['worker']={k:workers[0][k]for k in('pid','start','cgroup')}
        else:need(starting,'actual same-parent ordinary heavy worker; no unknown dispatcher helper')
    else:
        need(m.get('ControlGroup')==''and m.get('ActiveState')in('inactive','failed'),
             'quiescent exact old dispatcher identity')
    return ref

def dispatcher_lock_paths():
    return (QUEUE/'state/worker.lock',Path('/run/user/1000/opemos-heavy.lock'))

def admitted_dispatcher_lock_custody(refs):
    """Verify borrowed, already-admitted OFDs without opening another lock OFD."""
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    need(type(refs)is list and len(refs)==2 and
         all(type(r)is dict and set(r)=={'path','fd','identity'}for r in refs),
         'exact two admitted normal lock capabilities')
    need({r['path']for r in refs}=={str(p)for p in dispatcher_lock_paths()}and
         all(type(r['fd'])is int and r['fd']>=0 for r in refs)and
         len({r['fd']for r in refs})==2,'actual distinct fixed normal lock descriptors')
    for ref in refs:
        fd=ref['fd'];path=Path(ref['path']);st=os.fstat(fd)
        identity=lambda s:{k:getattr(s,k)for k in fields}
        need(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==1000 and
             st.st_nlink==1 and st.st_size==0 and not st.st_mode&0o113 and
             identity(st)==ref['identity']==identity(path.lstat()),
             'same admitted held/named native normal lock full9')
        rows=[line.split()for line in Path('/proc/self/fdinfo',str(fd)).read_text().splitlines()
              if line.startswith('lock:')]
        need(len(rows)==1 and len(rows[0])==9 and rows[0][2:5]==['FLOCK','ADVISORY','WRITE']and
             rows[0][5]==str(os.getpid())and rows[0][7:]==['0','EOF'],
             'kernel proves this process already owns the exclusive normal FLOCK')
        device=rows[0][6].split(':')
        need(len(device)==3 and int(device[0],16)==os.major(st.st_dev)and
             int(device[1],16)==os.minor(st.st_dev)and int(device[2])==st.st_ino and
             identity(st)==identity(os.fstat(fd))==identity(path.lstat()),
             'admitted FLOCK inode and final held/named epoch unchanged')
    return True

def dispatcher_closed(ref,admitted_locks=None):
    if admitted_locks is not None:admitted_dispatcher_lock_custody(admitted_locks)
    m=user_dispatcher(ref['unit'])
    need(m.get('LoadState')=='not-found'or m.get('InvocationID')==ref['invocation'],
         'same actual dispatcher invocation, never historical substitution')
    if not(m.get('MainPID')=='0'and m.get('ControlGroup')==''and
           m.get('ActiveState')in('inactive','failed')):return False
    if ref['pid']:
        try:actor=proc(ref['pid'])
        except(FileNotFoundError,ProcessLookupError):actor=None
        need(actor is None or actor['start']!=ref['start'],'original dispatcher leader still exists')
    if ref.get('worker')is not None:
        old=ref['worker']
        try:worker=proc(old['pid'])
        except(FileNotFoundError,ProcessLookupError):worker=None
        if worker is not None and worker['start']==old['start']:return False
        group=Path('/sys/fs/cgroup')/old['cgroup'].removeprefix('0::').lstrip('/')
        if group.exists()and(group/'cgroup.procs').read_text().strip():return False
    elif admitted_locks is None:
        # Legacy/quiescent manager has no retained child PID. Its actual normal
        # worker cannot be declared gone while either existing lock is held.
        fds=[]
        try:
            import fcntl
            for path in dispatcher_lock_paths():
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd);st=os.fstat(fd)
                fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
                before=tuple(getattr(st,k)for k in fields)
                need(stat.S_ISREG(st.st_mode)and st.st_uid==1000 and st.st_nlink==1 and
                     before==tuple(getattr(os.stat(path,follow_symlinks=False),k)for k in fields),'same held/named existing normal lock inode')
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:return False
                need(before==tuple(getattr(os.fstat(fd),k)for k in fields)==
                     tuple(getattr(os.stat(path,follow_symlinks=False),k)for k in fields),'same held/named lock custody after nonblocking admission')
        finally:
            for fd in reversed(fds):os.close(fd)
    for root in Path('/proc').iterdir():
        if not root.name.isdecimal():continue
        try:need(ref['unit']not in(root/'cgroup').read_text(),'actual dispatcher group still has an actor')
        except(FileNotFoundError,ProcessLookupError):continue
    if admitted_locks is not None:admitted_dispatcher_lock_custody(admitted_locks)
    return True

def wait_terminal(probe_module,policy,job_id,deadline,dispatcher_nonce=None,dispatchers=None):
    while time.monotonic()<deadline:
        row,_,_,_=current_rows(probe_module,policy)
        need(row and row['id']==job_id,'same exact canonical control changed')
        if row['state']in('passed','failed','timed_out','blocked','unknown','output_limit'):
            control=probe_module.current_control(row,policy)
            need(control['terminalLifecycle']=='CLOSED'and control['reservationRetained']is False,
                 'canonical current terminal not CLOSED')
            m=manager(row['unit']);need(m.get('MainPID')=='0'and m.get('ControlGroup')==''and
                m.get('ActiveState')in('inactive','failed'),'current own unit still active after terminal')
            if dispatchers is not None:
                if all(dispatcher_closed(ref)for ref in dispatchers):return row,m
            else:
                tx=dispatcher_nonce or job_id.removeprefix('root-github-robot-control-')
                outer=user_dispatcher('opemos-root-robot-dispatcher-'+tx+'.service')
                if outer.get('MainPID')=='0'and outer.get('ControlGroup')==''and outer.get('ActiveState')in('inactive','failed'):return row,m
        time.sleep(2)
    raise RuntimeError('current ordinary canonical/actual dispatcher terminal timeout; retain nonce')

def closed_receipt(row,m,dispatchers=None,admitted_locks=None):
    if admitted_locks is not None:admitted_dispatcher_lock_custody(admitted_locks)
    need(row['unit']and row['state']in('passed','failed','timed_out','blocked','unknown','output_limit'),
         'exact old canonical closed row')
    tx=row['id'].removeprefix('root-github-robot-control-')
    need(re.fullmatch('[0-9a-f]{32}',tx),'exact historical control tx')
    if dispatchers is None:
        unit='opemos-root-robot-dispatcher-'+tx+'.service';d=user_dispatcher(unit)
        need(d.get('MainPID')=='0'and d.get('ControlGroup')==''and
             d.get('ActiveState')in('inactive','failed'),'old dispatcher still active')
        units=[unit]
    else:
        need(dispatchers and len({r['unit']for r in dispatchers})==len(dispatchers)and
             all(r['jobId']==row['id']and r['queueSourceSHA256']==dispatchers[0]['queueSourceSHA256']
                 for r in dispatchers),
             'same exact predecessor/actual dispatcher set')
        for ref in dispatchers:need(dispatcher_closed(ref,admitted_locks=admitted_locks),'actual dispatcher still active')
        units=[ref['unit']for ref in dispatchers]
    for root in Path('/proc').iterdir():
        if not root.name.isdecimal():continue
        try:
            group=(root/'cgroup').read_text()
            need(row['unit']not in group and not any(u in group for u in units),
                 'old exact control/actual dispatcher actor still present')
            argv=(root/'cmdline').read_bytes()[:131073]
            need(len(argv)<=131072 and b'Runner.Listener'not in argv and
                 (b'/releases/'+tx.encode()+b'/control.py')not in argv,
                 'old or orphan listener/controller still present')
        except(FileNotFoundError,ProcessLookupError):continue
    if admitted_locks is not None:admitted_dispatcher_lock_custody(admitted_locks)
    return {'currentManager':m,'oldDispatcherAbsent':True,'oldListenerAbsent':True,
            'fullUID0Group':{'absent':True},'oldRowId':row['id'],'oldRowSHA256':sha(enc(row)),
            'atUnix':int(time.time()),**({'normalDispatchers':dispatchers}if dispatchers is not None else{})}

def closed_source_dispatchers(template,row):
    """Original closed execution identities remain DATA across a code upgrade."""
    if template.get('policy',{}).get('kind')!='ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1':return None
    old=template.get('oldControl',{})
    raw=bytes.fromhex(old.get('closedReceiptHex',''))
    if not raw:return None
    need(len(raw)<=65536 and sha(raw)==old.get('closedReceiptSHA256'),'exact current deployment predecessor receipt')
    proof=json.loads(raw)
    if proof.get('oldRowId')!=row['id']:return None
    life=json.loads(row['result'])['terminalLifecycle']
    need(row['state']in('passed','failed','timed_out','blocked','unknown','output_limit')
         and row['finished']is not None and life['phase']=='CLOSED'and life['reservationRetained']is False
         and proof['oldRowSHA256']==sha(enc(row)),'whole actual closed original row, no active source exception')
    refs=proof['normalDispatchers']
    need(type(refs)is list and refs and len({r['unit']for r in refs})==len(refs)
         and all(r['kind']=='NORMAL_CONTROL_DISPATCHER_IDENTITY_V1'and r['jobId']==row['id']
                 and re.fullmatch('[0-9a-f]{64}',r['queueSourceSHA256'])and dispatcher_closed(r)for r in refs),
         'exact original source identities and fresh actual dispatcher/worker closure')
    return refs

def materialize(policy,probe_module,nonce,old_row,old_manager,dispatchers=None):
    if 'REMOTE_TEMPLATE_HEX' in globals():
        template_raw=bytes.fromhex(REMOTE_TEMPLATE_HEX)
    else:
        template_raw,_=probe_module.held(ROOT/'normal-template.json',16*1024*1024,0,0o400)
    need(sha(template_raw)==policy['normalTemplateSHA256'],
         'exact Root approved current normal payload template')
    template=json.loads(template_raw)
    tx=policy['currentReleaseTx']
    installer_raw,_=probe_module.pin_source(
        CONTROL/'releases'/tx/'install_remote.py',policy['normalInstallerSHA256'],0)
    installer=types.ModuleType('reviewed_normal_installer')
    installer.__file__=str(CONTROL/'releases'/tx/'install_remote.py')
    exec(compile(installer_raw,installer.__file__,'exec'),installer.__dict__)
    if dispatchers is not None and not all(ref['queueSourceSHA256']==policy['queueSourceSHA256']for ref in dispatchers):
        need(dispatchers==closed_source_dispatchers(template,old_row),
             'exact authenticated closed predecessor source, never relabel old execution')
    receipt=closed_receipt(old_row,old_manager,dispatchers)
    data=dict(template)
    need(data.get('kind')=='ROOT_REVIEWED_ROBOT_CONTROL_MATERIALIZATION_V1' and
         data.get('mainCommit')==policy['mainCommit'] and
         data.get('runnerId')==21 and
         data.get('queueSourceSHA256')==policy['queueSourceSHA256'],
         'fixed approved same-source installer template')
    need(data['sources']['control.py']['sha256']==policy['controlBrokerSHA256'] and
         sha(bytes.fromhex(data['sources']['control.py']['hex']))==
             policy['controlBrokerSHA256'] and
         data['sources']['job-started.sh']['sha256']==
             policy['jobStartedSHA256'],
         'new host broker lease fence and unchanged sandbox hook pins')
    data['transaction']=nonce
    data['prior']={name:installer.full(path) for name,path in installer.targets().items()}
    data['oldControl']={'unit':old_row['unit'],'liveMainPID':0,
                        'liveUID0Absent':True,
                        'closedReceiptHex':enc(receipt).hex(),
                        'closedReceiptSHA256':sha(enc(receipt))}
    now=int(time.time())
    fixed=dict(data['policy']);fixed['notBefore']=now;fixed['expiresAt']=now+21600
    data['policy']=fixed
    if fixed.get('kind')=='ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1':
        # One actual immutable policy pin is generated with the new normal
        # release, then the existing registry/profile consume it consistently.
        data['registry']=json.loads(enc(data['registry']))
        data['profile']=json.loads(enc(data['profile']))
        data['registry']['artifacts']['ubuntu']['operation_policy']={
            'path':str(CONTROL/'releases'/nonce/'fixed-policy.json'),'sha256':sha(enc(fixed))}
        data['profile']['fixed_registry']['sha256']=sha(enc(data['registry']))
    need(data['queueLoggerSHA256']==policy['queueLoggerSHA256'] and
         fixed['sourceCommit']==policy['mainCommit'] and
         fixed['queueSourceSHA256']==policy['queueSourceSHA256'] and
         fixed['queueLoggerSHA256']==policy['queueLoggerSHA256'],
         'exact current normal fixed policy/template pins')
    payload=enc(data)
    need(len(payload)<=16*1024*1024,'bounded exact installer payload')
    return payload,installer

def install(payload,installer,policy):
    # The existing installer is the only writer of the six installed targets.
    # Execute its verified held bytes, not a mutable source path.
    result=installer.install(installer.strict(payload),sha(payload))
    need(result['stage']=='INSTALLED_NOT_SUBMITTED' and
         result['queueSubmitCommand'][:2]==
         ['/usr/bin/python3',str(QUEUE/'test_queue.py')],
         'existing reviewed installer result before queue submit')
    return result

def submit(job,policy,probe_module):
    source,_=probe_module.pin_source(QUEUE/'test_queue.py',policy['queueSourceSHA256'],1000)
    # Existing canonical submit is run from the exact held source bytes.
    bootstrap=('import sys\nsys.argv='+repr([str(QUEUE/'test_queue.py'),'--queue',
               str(QUEUE/'state'),'submit',str(job)])+'\n__file__='+
               repr(str(QUEUE/'test_queue.py'))+'\nexec(compile('+repr(source)+',__file__,"exec"))\n').encode()
    p=run(USER_ENV+['/usr/bin/python3','-I','-B','-'],bootstrap,30)
    need(p.returncode==0 and p.stderr==b'' and
         json.loads(p.stdout)=={'queued':['root-github-robot-control-'+job.parent.name.removeprefix('robot-control-')]},
         'canonical one-job normal submit')

def dispatch(tx,policy,probe_module):
    for name,key in (('test_queue.py','queueSourceSHA256'),
                     ('queue_job.py','queueLoggerSHA256'),
                     ('queue.sh','normalQueueEntrySHA256'),
                     ('heavy.sh','heavySHA256')):
        probe_module.pin_source(QUEUE/name,policy[key],1000)
    lockfd=os.open(QUEUE/'state/worker.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        import fcntl
        lock=os.fstat(lockfd)
        need(stat.S_ISREG(lock.st_mode) and lock.st_uid==1000 and lock.st_nlink==1,
             'exact ordinary worker lock')
        fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    finally:os.close(lockfd)
    unit='opemos-root-robot-dispatcher-'+tx+'.service'
    argv=USER_ENV+['/usr/bin/systemd-run','--user','--unit='+unit,
           '--property=RuntimeMaxSec=21700','--property=TimeoutStopSec=40',
           '--property=KillMode=control-group',*DISPATCHER_REENTRY_PROPERTIES,str(QUEUE/'queue.sh'),
           '--queue',str(QUEUE/'state'),'run']
    p=run(argv,timeout=20,cap=65536)
    notice=p.stderr.decode(errors='strict').strip()
    match=re.fullmatch(r'Running as unit: (opemos-root-robot-dispatcher-[0-9a-f]{32}\.service); invocation ID: ([0-9a-f]{32})',notice)
    need(p.returncode==0 and p.stdout==b'' and match and match[1]==unit,
         'exact successful canonical systemd-run notification')
    shown=run(USER_ENV+['/usr/bin/systemctl','--user','show',unit,
                       '-p','LoadState','-p','ActiveState','-p','MainPID',
                       '-p','InvocationID','-p','ControlGroup','-p','ExecStart'],
              timeout=10,cap=8192)
    need(shown.returncode==0 and shown.stderr==b'',
         'canonical dispatcher manager readback')
    manager_fields=dict(z.split('=',1) for z in shown.stdout.decode().splitlines() if '=' in z)
    need(manager_fields.get('LoadState')=='loaded' and
         manager_fields.get('ActiveState') in ('active','activating') and
         int(manager_fields.get('MainPID','0'))>0 and
         manager_fields.get('InvocationID')==match[2] and
         unit in manager_fields.get('ControlGroup','') and
         str(QUEUE/'queue.sh') in manager_fields.get('ExecStart',''),
         'exact new ordinary dispatcher PID/invocation/source')
    return unit

def publish_heartbeat(policy,probe_module,nonce):
    source=module(ROOT/'normal_heartbeat.py',policy['heartbeatProducerSHA256'])
    full=probe_module.observe();connected=probe_module.observe(route_only=True)
    state=source.state_from_current(source.join_current_presence(full,connected),policy,int(time.time()),nonce)
    result=source.publish_once(state)
    need(result['readbackCurrent'] is True,'current heartbeat not read back')
    return result

"""Exact old-control completion join. No effects or generic live exemption."""
import re,time
def need(v,m):
 if not v:raise RuntimeError(m)
def validate_terminal_control(bound,row,manager,state,evidence,empty,queue_sha,expected_sha,job):
 need(row['id']==bound['job_id']==job and re.fullmatch('root-github-robot-control-[0-9a-f]{32}',job) is not None and row['unit']==bound['unit'],'exact original canonical control/binding')
 inv=bound['invocation'];need(re.fullmatch('[0-9a-f]{32}',inv)is not None and manager.get('InvocationID')==evidence.get('InvocationID')==inv,'exact original control invocation at both native cuts')
 need(queue_sha==expected_sha,'original current queue implementation identity')
 need(manager.get('LoadState')=='loaded'and manager.get('MainPID')=='0'and manager.get('ControlGroup')==''and evidence.get('MainPID')=='0'and evidence.get('ControlGroup')=='','actual loaded original Main0/empty unit; no missing/active-owner inference')
 need(state in('passed','failed','timed_out')and empty is True and evidence.get('ExecMainCode')in('1','2','3')and str(evidence.get('ExecMainStatus','')).isdigit(),'real installed backend terminal/numeric/whole-cgroup proof')
 return True

def orphan_finalize(nonce,policy_sha,probe_sha,intent_sha):
    """One ordinary dispatcher for an exact actorless retained predecessor.

    The controller has already persisted a create-only intent independent of
    the consumed control nonce. This path never submits a job or clears SQL.
    It only starts the source-pinned queue.sh run worker after two complete
    current cuts, and returns an accepted dispatcher identity for later
    canonical terminal observation.
    """
    need(os.geteuid()==0 and 'REMOTE_POLICY_RAW' in globals() and
         'ORPHAN_INTENT_HEX' in globals(),'authenticated remote orphan carrier')
    policy_raw=bytes.fromhex(REMOTE_POLICY_RAW)
    need(sha(policy_raw)==policy_sha,'exact Root orphan policy')
    trigger=module(ROOT/'runner21_recovery.py',REMOTE_POLICY['recoverySourceSHA256'])
    policy=trigger.validate_policy(trigger.strict(policy_raw),int(time.time()))
    probe_module=module(ROOT/'normal_probe.py',policy['normalProbeSHA256'])
    state=trigger.validate_state(trigger.read_state())
    intent_raw=bytes.fromhex(ORPHAN_INTENT_HEX)
    need(sha(intent_raw)==intent_sha,'durable exact orphan intent bytes')
    intent=trigger.strict(intent_raw)
    need(intent['kind']=='ROOT_RUNNER21_ORPHAN_FINALIZER_INTENT_V1' and
         intent['nonce']==nonce and intent['queueSourceSHA256']==policy['queueSourceSHA256'] and
         intent['mainCommit']==policy['mainCommit'] and
         intent['priorInflight']==state['inflight'] and
         state['inflight'] is not None and
         state['lastOutcome']['action'] in ('GRACEFUL_RENEW','CREATE') and
         trigger.orphan_job(state)==intent['oldJobId'] and
         time.time()<state['epochExpiresUnix'],'old consumed nonce/epoch retained')
    job=intent['oldJobId'];tx=job.removeprefix('root-github-robot-control-')
    need(re.fullmatch(r'[0-9a-f]{32}',tx) and tx!=nonce,'exact old job and fresh dispatcher nonce')
    oldunit='opemos-root-robot-dispatcher-'+tx+'.service'
    newunit='opemos-root-robot-dispatcher-'+nonce+'.service'
    def outer(unit):
        p=run(USER_ENV+['/usr/bin/systemctl','--user','show',unit,
              '-p','LoadState','-p','ActiveState','-p','MainPID',
              '-p','ControlGroup','-p','InvocationID','-p','ExecStart'],timeout=10,cap=8192)
        need(p.returncode==0 and p.stderr==b'','exact user dispatcher manager')
        return dict(z.split('=',1) for z in p.stdout.decode().splitlines() if '=' in z)
    def no_old_actors_or_fds(row):
        targets=[QUEUE/'test_queue.py',QUEUE/'state'/'queue.sqlite3',
                 QUEUE/'state'/'queue.sqlite3-wal',QUEUE/'state'/'queue.sqlite3-shm',
                 CONTROL/'releases'/tx/'lease.json',
                 CONTROL/'releases'/tx/'fixed-policy.json']
        keys=set()
        for p in targets:
            if os.path.lexists(p):
                s=os.stat(p,follow_symlinks=False)
                need(stat.S_ISREG(s.st_mode),'exact orphan target type')
                keys.add((s.st_dev,s.st_ino))
        need(keys,'orphan target identities missing')
        count=0;matches=[]
        for node in Path('/proc').iterdir():
            if not node.name.isdecimal():continue
            try:
                cg=(node/'cgroup').read_text()
                need(row['unit'] not in cg and oldunit not in cg and newunit not in cg,
                     'old or new dispatcher/control cgroup still populated')
                argv=(node/'cmdline').read_bytes()[:131073]
                need(len(argv)<=131072,'bounded orphan actor argv')
                need(not any(x in argv for x in (b'Runner.Listener',b'Runner.Worker',
                     b'qemu-system-',b'/queue_job.py',b'/control.py',b'/launch.py')),
                     'relevant owner/guest actor still present')
                for fd in (node/'fd').iterdir():
                    count+=1;need(count<=65536,'bounded all-UID orphan FD census')
                    try:
                        s=os.stat(fd)
                        if (s.st_dev,s.st_ino) in keys:matches.append((node.name,fd.name))
                    except (FileNotFoundError,ProcessLookupError):continue
            except (FileNotFoundError,ProcessLookupError):continue
        need(not matches,'old queue/source/lease FD holder '+str(matches[:8]))
        return count
    def cut():
        current=probe_module.observe();trigger.validate_probe(current,policy,int(time.time()))
        need(current['protectedMain'] and current['networkReachable'] and
             current['mainCommit']==policy['mainCommit'] and
             current['queueSourceSHA256']==policy['queueSourceSHA256'] and
             current['workerLockFree'] and not current['runnerOnline'] and
             not any(current[k] for k in ('runnerBusy','actionsInProgress',
               'sourceOwnerBusy','guestActive','gpuLeaseActive','otherActiveJobs',
               'unknownReservations')) and current['queueKnown'] and
             current['hostGraphics']=='INTEL_HOST_NVIDIA_GUEST_ONLY',
             'fresh sole idle Root/OMEN/GitHub orphan scope')
        c=current['control']
        need(c['jobId']==job and c['state']=='running' and c['reservationRetained'] is True and
             c['terminalLifecycle'] is None and c['ownUnitBound'] and
             c['sourceCommit']==policy['mainCommit'] and
             c['queueSourceSHA256']==policy['queueSourceSHA256'] and
             not any(c[k] for k in ('listenerAlive','controllerAlive','workerAlive')),
             'exact actorless reserved current control')
        row,rows,bindings,config=current_rows(probe_module,policy)
        need(row and row['id']==job and row['state']=='running' and
             [r['id'] for r in rows if r['state'] in ('pending','running','terminal_cleanup')]==[job],
             'one and only one open canonical control')
        own=[b for b in bindings if b['job_id']==job]
        need(len(own)==1,'exact current own unit binding')
        bound=json.loads(own[0]['value']);m=manager(row['unit'])
        _,_,qraw=probe_module.local_sources(policy)
        need(sha(qraw)==policy['queueSourceSHA256'],'actual installed queue bytes for terminal observer')
        q=types.ModuleType('actual_normal_control_terminal_queue');q.__file__=str(QUEUE/'test_queue.py')
        exec(compile(qraw,q.__file__,'exec'),q.__dict__)
        backend=q.SystemdBackend(QUEUE/'state',json.loads(config[0]['value']))
        terminal,evidence,empty=backend.inspect(row['unit'])
        validate_terminal_control(bound,row,m,terminal,evidence,empty,sha(qraw),policy['queueSourceSHA256'],job)
        prior=outer(oldunit);future=outer(newunit)
        need(prior.get('ActiveState') in ('inactive','failed') and
             prior.get('MainPID')=='0' and prior.get('ControlGroup')=='' and
             future.get('LoadState')=='not-found' and future.get('MainPID')=='0' and
             future.get('ControlGroup')=='' and
             (prior.get('LoadState')=='not-found' or str(QUEUE/'queue.sh') in prior.get('ExecStart','')),
             'old dispatcher quiescent/new dispatcher absent')
        fd_count=no_old_actors_or_fds(row)
        return {'boot':current['boot'],'control':c,'rowSHA256':sha(enc(row)),
                'otherRowsSHA256':sha(enc([r for r in rows if r['id']!=job])),
                'bindingsSHA256':sha(enc(bindings)),'configSHA256':sha(enc(config)),
                'manager':m,'oldDispatcher':prior,'newDispatcher':future,
                'FDsScanned':fd_count}
    first=cut();need(first['boot']==intent['boot'] and
                     first['control']==intent['control'] and
                     intent['controllerProbeSHA256']==probe_sha,
                     'durable controller-to-OMEN orphan scope changed')
    record=CONTROL/('orphan-finalizer-'+nonce)
    os.mkdir(record,0o700)
    parent=os.open(CONTROL,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent)
    finally:os.close(parent)
    def save(name,value):
        raw=enc(value);need(len(raw)<=1048576,'bounded exact orphan record')
        fd=os.open(record/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400)
        try:
            view=memoryview(raw)
            while view:
                n=os.write(fd,view);need(n>0,'orphan receipt write');view=view[n:]
            os.fsync(fd)
        finally:os.close(fd)
        d=os.open(record,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(d)
        finally:os.close(d)
    save('before.json',{'intentSHA256':intent_sha,'first':first,'effectAttempted':False})
    second=cut()
    need({k:v for k,v in first.items() if k!='FDsScanned'}==
         {k:v for k,v in second.items() if k!='FDsScanned'},
         'two exact stable actor/unit/queue cuts')
    save('effect-intent.json',{'intentSHA256':intent_sha,'first':first,
                              'second':second,'effect':'one source-pinned ordinary dispatcher'})
    unit=dispatch(nonce,policy,probe_module)
    need(unit==newunit,'one exact ordinary dispatcher unit')
    save('dispatched.json',{'dispatcherUnit':unit,'oldJobId':job,'nonce':nonce,
                            'sourceSHA256':policy['queueSourceSHA256'],'canonicalTerminalClaimed':False})
    return {'kind':'ROOT_RUNNER21_ORPHAN_DISPATCH_V1','nonce':nonce,'oldJobId':job,
            'dispatcherUnit':unit,'oldRowSHA256':first['rowSHA256'],
            'before':first,'second':second,'ordinaryQueueEntry':str(QUEUE/'queue.sh'),
            'vmAdmission':False,'canonicalTerminalClaimed':False}

def main():
    need(os.geteuid()==0 and len(sys.argv)==6 and
         sys.argv[1]=='--normal-cycle' and sys.argv[2] in ACTIONS and
         re.fullmatch(r'[0-9a-f]{32}',sys.argv[3]) and
         all(re.fullmatch(r'[0-9a-f]{64}',x) for x in sys.argv[4:]),
         'fixed one-use Root normal-cycle ABI')
    action,nonce,policy_sha,probe_sha=sys.argv[2:]
    if 'REMOTE_POLICY_RAW' in globals():
        raw=bytes.fromhex(REMOTE_POLICY_RAW)
    else:
        policy_fd=os.open(ROOT/'policy.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            first=os.fstat(policy_fd)
            need(stat.S_ISREG(first.st_mode) and first.st_uid==first.st_gid==0 and
                 first.st_nlink==1 and stat.S_IMODE(first.st_mode)==0o400 and
                 0<first.st_size<=65536,'held Root policy identity')
            raw=os.read(policy_fd,65537)
            need(len(raw)==first.st_size and
                 all(getattr(first,k)==getattr(os.fstat(policy_fd),k)==
                     getattr(os.stat(ROOT/'policy.json',follow_symlinks=False),k)
                     for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                               'st_size','st_mtime_ns','st_ctime_ns')),
                 'held Root policy full9/EOF')
        finally:os.close(policy_fd)
    need(sha(raw)==policy_sha,'held current Root policy changed')
    pins=json.loads(raw)
    probe_module=module(ROOT/'normal_probe.py',pins['normalProbeSHA256'])
    trigger=module(ROOT/'runner21_recovery.py',pins['recoverySourceSHA256'])
    policy=trigger.validate_policy(trigger.strict(raw),int(time.time()))
    current=normal_at_use(action,nonce,policy,probe_module.observe(),trigger)
    selected,_,_,_=current_rows(probe_module,policy)
    job_id=current['control']['jobId']
    dispatchers=None;dispatcher_nonce=None
    if action in('GRACEFUL_RENEW','RECONCILE_CLOSED'):
        dispatchers=[owning_dispatcher(selected,policy,trigger.read_state())]
    elif action=='CREATE'and trigger.read_state()['lastOutcome'].get('dispatcherNonce')is not None:
        template=(trigger.current_controller_definition(policy)
                  if policy['mainCommit']!=trigger.REVIEWED_MAIN or policy['queueSourceSHA256']!=trigger.REVIEWED_QUEUE else {})
        dispatchers=closed_source_dispatchers(template,selected)
        if dispatchers is None:dispatchers=[owning_dispatcher(selected,policy,trigger.read_state())]
        selected,_=wait_terminal(probe_module,policy,job_id,time.monotonic()+180,dispatchers=dispatchers)
    if action=='REFRESH_HEARTBEAT':
        need('REMOTE_POLICY_RAW' not in globals(),
             'heartbeat effect only in authenticated controller')
        need(selected and selected['id']==job_id and
             selected['state']=='running','only existing current live control heartbeat')
        publish_heartbeat(policy,probe_module,nonce)
        phase='RUNNING';new_job=job_id
    else:
        if action=='GRACEFUL_RENEW':
            retire_listener(selected,current,policy)
            selected,_=wait_terminal(probe_module,policy,job_id,time.monotonic()+180,dispatchers=dispatchers)
        elif action=='RECONCILE_CLOSED':
            need(selected and selected['id']==job_id and
                 selected['state']=='running' and not current['control']['workerAlive'],
                 'only exact stopped current job may reconcile')
            finalizer=completion_dispatch_nonce(nonce)
            dispatch(finalizer,policy,probe_module)
            context={'lastOutcome':{'controlJobId':job_id,'dispatcherNonce':finalizer}}
            dispatchers.append(owning_dispatcher(selected,policy,context,starting=True))
            selected,_=wait_terminal(probe_module,policy,job_id,time.monotonic()+180,
                                     dispatcher_nonce=finalizer,dispatchers=dispatchers)
        if action in ('CREATE','GRACEFUL_RENEW','RECONCILE_CLOSED'):
            need(selected and selected['state'] in
                 ('passed','failed','timed_out','blocked','unknown','output_limit'),
                 'existing canonical closed predecessor required')
            old_m=manager(selected['unit'])
            payload,installer=materialize(policy,probe_module,nonce,selected,old_m,dispatchers=dispatchers)
            result=install(payload,installer,policy)
            new_job='root-github-robot-control-'+nonce
            need(result['job'].endswith('/robot-control-'+nonce+'/job.json'),
                 'exact installed new job path')
            submit(Path(result['job']),policy,probe_module)
            dispatch(nonce,policy,probe_module);dispatcher_nonce=nonce
        else:
            need(action=='RESUME_PENDING' and selected and
                 selected['id']==job_id and selected['state']=='pending',
                 'same pending job only')
            new_job=job_id
            # Starting the control transport does not admit an Actions job.
            # The broker's first-hook 19000s window and heartbeat producer's
            # same readiness floor stay unchanged. A short live lease can only
            # obtain a native acknowledgement and immediate ordinary renewal.
            need(current['control']['leaseExpiresUnix'] is not None and
                 current['control']['leaseExpiresUnix']>time.time(),
                 'pending control lease expired; never extend or replay it')
            dispatch(nonce,policy,probe_module);dispatcher_nonce=nonce
        if 'REMOTE_POLICY_RAW' in globals():
            phase='SUBMITTED_OR_DISPATCHED_AWAIT_CONTROLLER_GITHUB_READBACK'
        else:
            deadline=time.monotonic()+600
            while time.monotonic()<deadline:
                fresh=probe_module.observe()
                if (fresh['control']['jobId']==new_job and
                    fresh['control']['state']=='running' and fresh['runnerOnline'] and
                    fresh['control']['listenerAlive'] and
                    fresh['control']['controllerAlive'] and
                    fresh['control']['workerAlive']):
                    break
                time.sleep(3)
            else:raise RuntimeError('new normal Runner21 job not live before finite bound')
            if action=='RESUME_PENDING' and fresh['control']['leaseExpiresUnix']<=time.time()+19000:
                need(time.time()<fresh['control']['leaseExpiresUnix'],'resumed control lease expired')
                phase='RUNNING_RENEWAL_DUE'
            else:
                publish_heartbeat(policy,probe_module,nonce)
                phase='RUNNING'
    out={'kind':'ROOT_RUNNER21_REMOTE_ACTION_RESULT_V1' if 'REMOTE_POLICY_RAW' in globals()
         else 'ROOT_RUNNER21_NORMAL_CYCLE_RESULT_V1','nonce':nonce,
         'action':action,'policySHA256':policy_sha,'probeSHA256':probe_sha,
         'queueSourceSHA256':policy['queueSourceSHA256'],
         'mainCommit':policy['mainCommit'],'ordinaryRoute':True,
         'sourceAccepted':True,'runtimeAuthorized':True,'vmAdmission':False,
         'jobStartedGuard':True,
         'heartbeatReadbackCurrent':'REMOTE_POLICY_RAW' not in globals() and phase=='RUNNING',
         'newOrExistingJobRoutable':phase=='RUNNING',
         'noDuplicateControllerListenerWorker':True,
         'jobId':new_job,'phase':phase,
         **({'dispatcherNonce':dispatcher_nonce}if dispatcher_nonce is not None else{})}
    print(enc(out).decode(),end='')

if __name__=='__main__':
    if len(sys.argv)==6 and sys.argv[1]=='--orphan-finalize' and \
       re.fullmatch(r'[0-9a-f]{32}',sys.argv[2]) and \
       all(re.fullmatch(r'[0-9a-f]{64}',x) for x in sys.argv[3:]):
        print(enc(orphan_finalize(*sys.argv[2:])).decode(),end='')
    else:main()

#!/usr/bin/python3
"""Root-owned Runner21 trigger for an independently reviewed normal control cycle.

This program does not install a runner, submit a queue job, or issue a lease by
itself.  It executes only the Root-pinned normal-cycle source through its held
bytes.  That source must use the existing installer, canonical queue, listener
and job-started guard.  A disabled or stale policy always refuses.
"""
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import types
import uuid
from pathlib import Path

ROOT = Path('/var/lib/opemos-robot-control-r1/auto-recovery')
POLICY = ROOT / 'policy.json'
PROBE = ROOT / 'controller_probe.py'
CYCLE = ROOT / 'controller_cycle.py'
LOCK = ROOT / 'recovery.lock'
STATE = ROOT / 'state.json'
RUNNER_ID = 21
REVIEWED_MAIN = 'b4ae93065ca930b32010f94f24b109d4b7bccbae'
REVIEWED_QUEUE = 'd2d29bae09a0fdcea79511f84eb2b9f02d4ad57e72491f066e301d9ea6e4c86a'
SOURCE_SCOPE = 'CONNECTION_ONLY_OLD_ARTIFACT_NO_FULLSTACK_ACCEPTANCE'
MAX_FRAME = 1048576
MAX_PROBE_SECONDS = 30
MAX_CYCLE_SECONDS = 900
# Four-hour Actions job, up to one hour of cleanup/poll/backoff, and fifteen
# minutes of controller/transport margin plus 100s for the shorter Listener wall.
RENEW_LEAD_SECONDS = 19000

def need(ok, why):
    if not ok: raise RuntimeError(why)

def canonical(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()

def strict(raw):
    def pairs(items):
        d = {}
        for k, v in items:
            need(k not in d, 'duplicate JSON field')
            d[k] = v
        return d
    v = json.loads(raw, object_pairs_hook=pairs,
                   parse_constant=lambda _: need(False, 'nonfinite JSON'))
    need(canonical(v) == raw, 'noncanonical or trailing JSON')
    return v

def sha(raw): return hashlib.sha256(raw).hexdigest()

def write_all(fd, raw):
    view=memoryview(raw)
    while view:
        written=os.write(fd,view)
        need(written>0,'short owned source/state write')
        view=view[written:]

def held(path, cap, uid=0, mode=0o400):
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        need(stat.S_ISREG(first.st_mode) and first.st_uid == uid and
             first.st_gid == uid and first.st_nlink == 1 and
             stat.S_IMODE(first.st_mode) == mode and 0 < first.st_size <= cap,
             'exact held Root source/policy custody: '+str(path))
        data = bytearray()
        while True:
            block = os.read(fd, min(65536, cap+1-len(data)))
            need(len(data)+len(block) <= cap, 'held source cap')
            if not block: break
            data.extend(block)
        last = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                  'st_size','st_mtime_ns','st_ctime_ns')
        need(all(getattr(first,k)==getattr(last,k)==getattr(named,k) for k in fields)
             and len(data)==first.st_size, 'held/named full9 or EOF changed')
        return bytes(data)
    finally: os.close(fd)

def check_root_directory():
    for path, mode in ((Path('/var/lib'),0o755),
                       (Path('/var/lib/opemos-robot-control-r1'),0o755),
                       (ROOT,0o700)):
        s = os.lstat(path)
        need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_gid==0 and
             stat.S_IMODE(s.st_mode)==mode and not path.is_symlink(),
             'Root anchored recovery directory '+str(path))

def current_controller_definition(p):
    # Existing normal-template is the single installed deployment definition.
    # Original release/job identities remain immutable data; no copied current
    # revision list or candidate checkout can select privileged implementation.
    raw=(bytes.fromhex(REMOTE_TEMPLATE_HEX) if 'REMOTE_TEMPLATE_HEX' in globals()
         else held(ROOT/'normal-template.json',16*1024*1024,0,0o400))
    need(0<len(raw)<=16*1024*1024,'bounded existing normal deployment definition')
    need(sha(raw)==p['normalTemplateSHA256'],'authenticated current normal deployment definition')
    template=strict(raw)
    need(template.get('kind')=='ROOT_REVIEWED_ROBOT_CONTROL_MATERIALIZATION_V1'
         and template.get('mainCommit')==p['mainCommit']and template.get('runnerId')==21
         and template.get('runtimeAuthorized')is True
         and template.get('queueSourceSHA256')==p['queueSourceSHA256']
         and template.get('queueLoggerSHA256')==p['queueLoggerSHA256'],
         'same reviewed controller/queue/source definition')
    fixed=template.get('policy',{})
    need(fixed.get('kind')=='ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1'
         and fixed.get('sourceAccepted')is True and fixed.get('runtimeAuthorized')is True
         and fixed.get('sourceCommit')==p['mainCommit']
         and fixed.get('queueSourceSHA256')==p['queueSourceSHA256'],
         'explicit current normal operation definition, no expansion of legacy connection grant')
    for name,key in (('control.py','controlBrokerSHA256'),('connection_host.py','privatePeerSHA256'),
                     ('install_remote.py','normalInstallerSHA256'),('job_guard.py','jobGuardSHA256'),
                     ('job-started.sh','jobStartedSHA256')):
        source=template['sources'][name];body=bytes.fromhex(source['hex'])
        need(0<len(body)<=8*1024*1024 and sha(body)==source['sha256']==p[key],
             'current controller definition source role '+name)
    return template

def validate_policy(p, now):
    keys = {'kind','enabled','sourceAccepted','runtimeAuthorized','repository',
            'runnerId','mainCommit','queueSourceSHA256','queueLoggerSHA256',
            'jobStartedSHA256','jobGuardSHA256','runnerManifestSHA256',
            'controlBrokerSHA256','priorControlBrokerSHA256',
            'privatePeerSHA256','normalProbeSHA256','normalCycleSHA256',
            'controllerProbeSHA256','controllerCycleSHA256','sshConfigSHA256',
            'coordinationSourceSHA256',
            'normalInstallerSHA256','normalQueueEntrySHA256','heartbeatProducerSHA256',
            'currentReleaseTx','currentReleaseLeaseSHA256','heavySHA256',
            'normalTemplateSHA256',
            'recoverySourceSHA256','scope',
            'notBeforeUnix','expiresUnix','renewalAuthorizedUntilUnix',
            'maxTotalCycles','maxCycles','renewLeadSeconds',
            'maxBackoffSeconds'}
    need(type(p) is dict and set(p) in (keys,keys|{'healthImplementationDefinitionPin'}) and p['kind']=='ROOT_RUNNER21_AUTO_RECOVERY_V1'
         and p['enabled'] is True and p['sourceAccepted'] is True and
         p['runtimeAuthorized'] is True and p['repository']=='CorniiDog/OPEMOS.EXE'
         and p['runnerId']==RUNNER_ID and p['scope']==SOURCE_SCOPE,
         'exact reviewed and enabled Runner21-only policy')
    need(re.fullmatch(r'[0-9a-f]{40}',p['mainCommit']) and
         re.fullmatch(r'[0-9a-f]{32}',p['currentReleaseTx']) and
         all(re.fullmatch(r'[0-9a-f]{64}',p[k]) for k in keys if k.endswith('SHA256')),
         'exact current Main and complete source pins')
    if not(p['mainCommit']==REVIEWED_MAIN and p['queueSourceSHA256']==REVIEWED_QUEUE):
        current_controller_definition(p)
    need(type(p['notBeforeUnix']) is int and type(p['expiresUnix']) is int and
         p['notBeforeUnix'] <= now < p['renewalAuthorizedUntilUnix'] and
         0 < p['expiresUnix']-p['notBeforeUnix'] <= 7*86400 and
         p['expiresUnix'] <= p['renewalAuthorizedUntilUnix'] <=
             p['notBeforeUnix']+90*86400,
         'finite Root-approved rolling policy horizon')
    need(type(p['maxCycles']) is int and 1 <= p['maxCycles'] <= 64 and
         type(p['maxTotalCycles']) is int and
         p['maxCycles']<=p['maxTotalCycles']<=4096 and
         p['renewLeadSeconds']==RENEW_LEAD_SECONDS and
         p['maxBackoffSeconds']==900, 'bounded fixed cycle/backoff policy')
    return p

def current_closed_predecessor(policy, control):
    """Existing deployment receipt binds historical DATA independently of code."""
    need(control['state'] in ('passed','failed','timed_out','blocked','unknown','output_limit')
         and control['terminalLifecycle']=='CLOSED' and control['reservationRetained'] is False
         and not any(control[k] for k in ('listenerAlive','controllerAlive','workerAlive')),
         'different historical broker must be actually CLOSED and actorless')
    old=current_controller_definition(policy)['oldControl']
    raw=bytes.fromhex(old['closedReceiptHex'])
    need(0<len(raw)<=65536 and sha(raw)==old['closedReceiptSHA256'],
         'authenticated existing predecessor closure receipt')
    receipt=strict(raw)
    need(receipt['oldRowId']==control['jobId'] and
         receipt['currentManager']['MainPID']=='0' and receipt['currentManager']['ControlGroup']==''
         and receipt['fullUID0Group']['absent'] is True and receipt['oldDispatcherAbsent'] is True
         and receipt['oldListenerAbsent'] is True and old['liveMainPID']==0
         and old['liveUID0Absent'] is True,
         'same exact closed predecessor in current deployment definition')
    return True

def validate_probe(v, policy, now):
    keys={'kind','atUnix','boot','protectedMain','mainCommit','protectedMainCommit','runnerId',
          'registeredRunnerId','runnerManifestSHA256','queueSourceSHA256',
          'queueLoggerSHA256','jobStartedSHA256','jobGuardSHA256',
          'privatePeerSHA256','normalInstallerSHA256','normalQueueEntrySHA256',
          'heartbeatProducerSHA256','heartbeatCurrent',
          'heartbeatNonce','controlBrokerSHA256',
          'networkReachable','runnerOnline','runnerBusy','actionsInProgress',
          'actionsQueued',
          'sourceOwnerBusy','queueKnown','workerLockFree','unknownReservations',
          'otherActiveJobs','guestActive','gpuLeaseActive','hostGraphics',
          'control','effects'}
    need(type(v) is dict and set(v)==keys and v['kind']=='ROOT_RUNNER21_NORMAL_CURRENT_PROBE_V1'
         and v['effects']==[] and
         v['runnerId']==v['registeredRunnerId']==RUNNER_ID and
         type(v['boot']) is str and re.fullmatch(r'[0-9a-f-]{36}',v['boot']) and
         type(v['atUnix']) in (int,float) and
         0 <= int(now)-int(v['atUnix']) <= 15,
         'fresh protected Main/runner/boot probe')
    for key in ('runnerManifestSHA256','queueSourceSHA256','queueLoggerSHA256',
                'jobStartedSHA256','jobGuardSHA256','privatePeerSHA256',
                'normalInstallerSHA256','normalQueueEntrySHA256',
                'heartbeatProducerSHA256'):
        need(v[key]==policy[key], 'current pinned source drift: '+key)
    need(v['controlBrokerSHA256'] is None or v['controlBrokerSHA256'] in
         (policy['controlBrokerSHA256'],policy['priorControlBrokerSHA256']),
         'current broker outside reviewed old/new transition')
    need(v['hostGraphics']=='INTEL_HOST_NVIDIA_GUEST_ONLY' and
         type(v['unknownReservations']) is list and
         type(v['otherActiveJobs']) is list and
         type(v['control']) is dict,
         'exact Intel host and current queue/Actions schema')
    for key in ('networkReachable','runnerOnline','runnerBusy','heartbeatCurrent',
                'sourceOwnerBusy',
                'queueKnown','workerLockFree','guestActive','gpuLeaseActive'):
        need(type(v[key]) is bool, 'unknown current guard: '+key)
    need(v['heartbeatNonce'] is None or
         type(v['heartbeatNonce']) is str and
         re.fullmatch(r'[0-9a-f]{32}',v['heartbeatNonce']),
         'bounded current heartbeat nonce')
    if v['networkReachable']:
        need(v['protectedMain'] is True and v['mainCommit']==policy['mainCommit'] and
             type(v['protectedMainCommit']) is str and
             re.fullmatch(r'[0-9a-f]{40}',v['protectedMainCommit']) and
             type(v['actionsInProgress']) is int and v['actionsInProgress']>=0 and
             type(v['actionsQueued']) is int and v['actionsQueued']>=0,
             'fresh protected Main/Actions proof')
    else:
        need(v['protectedMain'] is False and v['mainCommit'] is None and
             v['protectedMainCommit'] is None and
             v['actionsInProgress'] is None and v['actionsQueued'] is None and
             v['runnerOnline'] is False and v['heartbeatCurrent'] is False,
             'offline state never cached as current GitHub proof')
        need(v['heartbeatNonce'] is None,'offline heartbeat nonce cannot be cached')
    c=v['control']
    need(set(c)=={'jobId','state','terminalLifecycle','reservationRetained',
                 'sourceCommit','queueSourceSHA256','leaseExpiresUnix',
                 'listenerAlive','controllerAlive','workerAlive','ownUnitBound'},
         'complete current own control state')
    need(c['state'] in ('absent','pending','running','passed','failed',
                       'timed_out','blocked','unknown','output_limit','terminal_cleanup')
         and (c['jobId'] is None or re.fullmatch(
             r'root-github-robot-control-[0-9a-f]{32}',c['jobId'])) and
         (c['sourceCommit'] is None or re.fullmatch(r'[0-9a-f]{40}',c['sourceCommit'])) and
         (c['queueSourceSHA256'] is None or
          re.fullmatch(r'[0-9a-f]{64}',c['queueSourceSHA256'])),
         'authentic typed own control row')
    for key in ('reservationRetained','listenerAlive','controllerAlive',
                'workerAlive','ownUnitBound'):
        need(type(c[key]) is bool, 'unknown own-control guard: '+key)
    need(c['leaseExpiresUnix'] is None or
         type(c['leaseExpiresUnix']) in (int,float), 'lease expiry type')
    if c['state']=='absent':
        need(v['controlBrokerSHA256'] is None,'absent control has no broker')
    elif v['controlBrokerSHA256']==policy['priorControlBrokerSHA256']:
        if c['jobId']!='root-github-robot-control-'+policy['currentReleaseTx']:
            current_closed_predecessor(policy,c)
        else:
            need(c['state'] in ('running','pending','terminal_cleanup','passed','failed',
                               'timed_out','blocked','unknown','output_limit'),
                 'old broker only with exact historical predecessor')
    else:
        need(v['controlBrokerSHA256']==policy['controlBrokerSHA256'],
             'new current control broker source not authenticated')
        need(c['jobId'] is None or c['jobId']!=
             'root-github-robot-control-'+policy['currentReleaseTx'] or
             c['terminalLifecycle']=='CLOSED',
             'new broker cannot be represented as still-live old control')
    if c['state']=='absent':
        need(c['jobId'] is None and c['terminalLifecycle'] is None and
             not c['reservationRetained'] and not c['listenerAlive'] and
             not c['controllerAlive'] and not c['workerAlive'] and
             not c['ownUnitBound'], 'truly absent current control')
    else:
        need(c['jobId'] is not None and c['sourceCommit'] is not None and
             c['queueSourceSHA256'] is not None,
             'exact bound or historical control row')
    if c['state'] in ('passed','failed','timed_out','blocked','unknown','output_limit'):
        need(c['terminalLifecycle']=='CLOSED' and not c['reservationRetained'],
             'canonical terminal closure, never old lease replay')
    elif c['state']!='absent':
        need(c['sourceCommit']==policy['mainCommit'] and
             c['queueSourceSHA256']==policy['queueSourceSHA256'],
             'live control must bind current source; historical closed source retained')
    return v

def decision(probe, policy, now, state):
    """Pure bounded trigger; the normal-cycle source repeats every guard at use."""
    validate_probe(probe, policy, now)
    if state['inflight'] is not None: return 'HOLD_INFLIGHT'
    if state.get('totalCycles',0)>=policy['maxTotalCycles']: return 'HOLD_TOTAL_CYCLE_CAP'
    if state['completedCycles'] >= policy['maxCycles']: return 'HOLD_CYCLE_CAP'
    if now < state['nextAttemptUnix']: return 'BACKOFF'
    if not probe['networkReachable']: return 'WAIT_NETWORK'
    if probe['sourceOwnerBusy'] or probe['actionsInProgress'] or probe['runnerBusy']:
        return 'WAIT_ACTIVE_ACTION_OR_SOURCE_OWNER'
    if (not probe['queueKnown'] or probe['unknownReservations'] or
        probe['otherActiveJobs'] or probe['guestActive'] or probe['gpuLeaseActive']):
        return 'WAIT_SHARED_OWNER_OR_GPU'
    c=probe['control']
    if c['state']=='pending':
        if probe['runnerOnline']: return 'HOLD_ORPHAN_RUNNER'
        return 'WAIT_EXISTING_WORKER' if c['workerAlive'] or not probe['workerLockFree'] else 'RESUME_PENDING'
    if c['state']=='terminal_cleanup': return 'WAIT_CANONICAL_FINALIZER'
    if c['state']=='running':
        if not c['ownUnitBound'] or c['reservationRetained'] is False:
            return 'HOLD_UNKNOWN_RUNNING'
        if not c['listenerAlive'] or not c['controllerAlive']:
            return 'WAIT_EXISTING_WORKER' if c['workerAlive'] else 'RECONCILE_CLOSED'
        if not c['workerAlive'] or not probe['runnerOnline']:
            return 'HOLD_LIVE_LISTENER_UNKNOWN'
        if c['leaseExpiresUnix'] is None: return 'HOLD_UNKNOWN_EXPIRY'
        if probe['controlBrokerSHA256']==policy['priorControlBrokerSHA256']:
            return 'GRACEFUL_RENEW'
        if c['leaseExpiresUnix']-now <= policy['renewLeadSeconds']:
            return 'GRACEFUL_RENEW'
        # The timer period is 120 seconds while the published readiness TTL is
        # 180 seconds. Publishing only after expiry creates a truthful but
        # avoidable NOT_READY window. A healthy idle tick is the bounded
        # refresh margin; all existing guards above still apply.
        if not probe['heartbeatCurrent']:
            return 'REFRESH_HEARTBEAT'
        return 'REFRESH_HEARTBEAT'
    if c['state']=='absent' or c['terminalLifecycle']=='CLOSED':
        if probe['runnerOnline']: return 'HOLD_ORPHAN_RUNNER'
        return 'CREATE' if probe['workerLockFree'] else 'WAIT_EXISTING_WORKER'
    return 'HOLD_UNKNOWN_CONTROL'

def default_state():
    return {'kind':'RUNNER21_AUTO_RECOVERY_STATE_V1','completedCycles':0,
            'totalCycles':0,'renewals':0,'epochExpiresUnix':None,
            'failureCount':0,'nextAttemptUnix':0,'inflight':None,
            'lastOutcome':None}

def read_state():
    return strict(held(STATE,65536,0,0o600))

def validate_state(s):
    need(type(s) is dict and set(s)==set(default_state()) and
         s['kind']=='RUNNER21_AUTO_RECOVERY_STATE_V1' and
         type(s['completedCycles']) is int and s['completedCycles']>=0 and
         type(s['totalCycles']) is int and s['totalCycles']>=s['completedCycles'] and
         type(s['renewals']) is int and 0<=s['renewals']<=512 and
         (s['epochExpiresUnix'] is None or
          type(s['epochExpiresUnix']) is int and s['epochExpiresUnix']>0) and
         type(s['failureCount']) is int and s['failureCount']>=0 and
         type(s['nextAttemptUnix']) in (int,float) and
         (s['inflight'] is None or re.fullmatch(r'[0-9a-f]{32}',s['inflight'])) and
         (s['lastOutcome'] is None or type(s['lastOutcome']) is dict),
         'exact durable recovery state')
    return s

def renew_epoch(policy,state,probe,now):
    """A Root-approved fixed-source horizon permits bounded idle subleases.

    The original Root policy never changes. A single fsynced state update
    preserves total cycles and advances a finite, <=7-day local epoch only
    while the same current source and all shared-owner guards are proven.
    """
    if state['epochExpiresUnix'] is None:
        need(state['totalCycles']==0 and state['completedCycles']==0 and
             state['renewals']==0,'initial epoch state custody')
        state['epochExpiresUnix']=policy['expiresUnix']
        write_state(state)
    need(state['renewals']>0 or state['epochExpiresUnix']==policy['expiresUnix'],
         'original Root policy epoch state changed')
    need(state['epochExpiresUnix']>=policy['expiresUnix'],
         'Root policy epoch rolled backward')
    need(now<state['epochExpiresUnix'] and
         state['epochExpiresUnix']<=policy['renewalAuthorizedUntilUnix'],
         'Root-approved policy epoch expired; no late automatic extension')
    due=(state['epochExpiresUnix']-now<=policy['renewLeadSeconds'] or
         state['completedCycles']>=policy['maxCycles']-1)
    if not due:return 'CURRENT_EPOCH'
    if (state['inflight'] is not None or state['totalCycles']>=policy['maxTotalCycles'] or
        probe['sourceOwnerBusy'] or probe['runnerBusy'] or probe['actionsInProgress'] or
        not probe['networkReachable'] or not probe['queueKnown'] or
        probe['otherActiveJobs'] or probe['unknownReservations'] or
        probe['guestActive'] or probe['gpuLeaseActive']):
        return 'WAIT_SAFE_IDLE_POLICY_RENEWAL'
    next_end=min(now+7*86400,policy['renewalAuthorizedUntilUnix'])
    need(next_end>state['epochExpiresUnix'] and next_end-now>900,
         'no bounded Root-approved next epoch')
    state['renewals']+=1
    state['epochExpiresUnix']=next_end
    state['completedCycles']=0
    state['lastOutcome']={'decision':'ROOT_APPROVED_SAME_SOURCE_POLICY_EPOCH_RENEWED',
                          'atUnix':now,'renewals':state['renewals'],
                          'expiresUnix':next_end,'totalCycles':state['totalCycles']}
    write_state(state)
    return 'RENEWED_CURRENT_SOURCE_EPOCH'

def write_state(state):
    raw=canonical(state)
    tmp=ROOT/('.state-'+os.urandom(16).hex())
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:write_all(fd,raw);os.fsync(fd)
    finally:os.close(fd)
    os.replace(tmp,STATE)
    d=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(d)
    finally:os.close(d)

def alert(first,now):
    """One durable Root-only alert per exact refusal; journal repeats remain visible."""
    reason=type(first).__name__+':'+str(first)[:512]
    name='alert-'+sha(reason.encode())[:24]+'.json'
    path=ROOT/name
    body=canonical({'kind':'RUNNER21_NORMAL_RECOVERY_REFUSAL_ALERT_V1',
                    'atUnix':now,'first':reason,'noRuntimeClaim':True})
    try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:return
    try:write_all(fd,body);os.fsync(fd)
    finally:os.close(fd)
    d=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(d)
    finally:os.close(d)

def summon_resolver_once(policy, state, result, now):
    """Retired agents are never a runtime recovery dependency or destination."""
    alert(RuntimeError('normal recovery hold: '+str(result.get('decision'))),now)
    return 'LOCAL_DURABLE_ALERT_ONLY_NO_AGENT_DISPATCH'


def load_code(path, expected):
    raw=held(path,1048576,0,0o444)
    need(sha(raw)==expected,'exact reviewed normal route source '+str(path))
    compile(raw,str(path),'exec')
    return raw

def start_held_python(raw, argv):
    fd=os.memfd_create('opemos-runner21-reviewed-source',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        write_all(fd,raw)
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SHRINK|
                    fcntl.F_SEAL_GROW|fcntl.F_SEAL_SEAL)
        p=subprocess.Popen(['/usr/bin/python3','-I','-B',f'/proc/self/fd/{fd}',*argv],
                           stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,pass_fds=(fd,),close_fds=True)
        return p
    finally:os.close(fd)

def capture(child, seconds, abort_readonly=False):
    sel=selectors.DefaultSelector(); caps={'stdout':MAX_FRAME,'stderr':65536}
    counts={'stdout':0,'stderr':0};data={k:bytearray() for k in caps};eof={k:False for k in caps}
    first=None;started=time.monotonic();abort_at=None;kill_at=None
    try:
        for name,pipe in (('stdout',child.stdout),('stderr',child.stderr)):
            os.set_blocking(pipe.fileno(),False);sel.register(pipe,selectors.EVENT_READ,name)
        while sel.get_map():
            current=time.monotonic()
            if current-started>seconds and abort_at is None and kill_at is None:
                if first is None:
                    first=('readonly probe timeout' if abort_readonly else
                           'owned normal route timeout; child retained; no retry')
                if abort_readonly:
                    if child.poll() is None:child.terminate()
                    abort_at=current+5
                else:break
            if abort_at is not None and current>abort_at and kill_at is None:
                if child.poll() is None:child.kill() # exact owned read-only probe
                kill_at=current+5
            if kill_at is not None and current>kill_at:
                if first is None:first='readonly probe descendant EOF unknown'
                break
            for key,_ in sel.select(.1):
                name=key.data;z=os.read(key.fileobj.fileno(),65536)
                if not z:sel.unregister(key.fileobj);key.fileobj.close();eof[name]=True;continue
                remaining=max(0,caps[name]-counts[name]);data[name].extend(z[:remaining]);counts[name]+=len(z)
                if counts[name]>caps[name] and first is None:
                    first='normal route output cap'
                    if abort_readonly:
                        if child.poll() is None:child.terminate()
                        abort_at=time.monotonic()+5
        if first and abort_readonly and child.poll() is None:
            try:child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                try:child.wait(timeout=2)
                except subprocess.TimeoutExpired:pass
        if first and child.poll() is None:
            return {'first':first,'numeric':None,'eof':eof,'reaped':False,
                    'stdout':bytes(data['stdout']),'stderr':bytes(data['stderr'])}
        numeric=child.wait(timeout=2)
        return {'first':first,'numeric':numeric,'eof':eof,'reaped':True,
                'stdout':bytes(data['stdout']),'stderr':bytes(data['stderr'])}
    finally:
        sel.close()
        if child.poll() is not None:
            for pipe in (child.stdout,child.stderr):
                if pipe is not None and not pipe.closed:pipe.close()

def receipt(raw, kind):
    need(len(raw)<=MAX_FRAME and raw.endswith(b'\n') and raw.count(b'\n')==1,
         'single complete normal route frame')
    value=strict(raw)
    need(value.get('kind')==kind,'exact normal route frame kind')
    return value

def orphan_intent_path(job):
    need(type(job) is str and re.fullmatch(
         r'root-github-robot-control-[0-9a-f]{32}',job),
         'exact predecessor for orphan record')
    return ROOT/('orphan-finalizer-'+job.removeprefix(
        'root-github-robot-control-')+'.json')

def orphan_job(state):
    old=state['lastOutcome']
    if old['action']=='CREATE':
        return 'root-github-robot-control-'+state['inflight']
    return old['controlJobId']

def orphan_scope(probe,policy,state):
    """A necessary controller cut. The remote queue cut remains authoritative."""
    old=state['lastOutcome'];c=probe['control']
    return (state['inflight'] is not None and type(old) is dict and
            old.get('action') in ('GRACEFUL_RENEW','CREATE') and
            type(state['epochExpiresUnix']) is int and
            time.time()<state['epochExpiresUnix']<=policy['renewalAuthorizedUntilUnix'] and
            orphan_job(state)==c['jobId'] and
            c['state']=='running' and c['reservationRetained'] is True and
            c['terminalLifecycle'] is None and c['ownUnitBound'] and
            c['sourceCommit']==policy['mainCommit'] and
            c['queueSourceSHA256']==policy['queueSourceSHA256'] and
            not any(c[k] for k in ('listenerAlive','controllerAlive','workerAlive')) and
            probe['workerLockFree'] and probe['queueKnown'] and
            probe['networkReachable'] and probe['protectedMain'] and
            probe['mainCommit']==policy['mainCommit'] and
            probe['queueSourceSHA256']==policy['queueSourceSHA256'] and
            not probe['runnerOnline'] and
            not any(probe[k] for k in ('runnerBusy','actionsInProgress',
                'sourceOwnerBusy','otherActiveJobs','unknownReservations',
                'guestActive','gpuLeaseActive')))

def save_orphan_intent(path,value):
    raw=canonical(value);need(len(raw)<=65536,'bounded orphan intent')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:write_all(fd,raw);os.fsync(fd)
    finally:os.close(fd)
    d=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(d)
    finally:os.close(d)
    return raw

def orphan_cycle(policy,state,probe,probe_raw,now):
    """One use of the ordinary dispatcher; consumed control nonce is untouched."""
    job=orphan_job(state)
    path=orphan_intent_path(job)
    if path.exists():
        prior_raw=held(path,65536,0,0o600);prior=strict(prior_raw)
        need(prior.get('kind')=='ROOT_RUNNER21_ORPHAN_FINALIZER_INTENT_V1' and
             prior.get('oldJobId')==job and
             prior.get('priorInflight')==state['inflight'] and
             prior.get('mainCommit')==policy['mainCommit'] and
             prior.get('queueSourceSHA256')==policy['queueSourceSHA256'],
             'existing orphan finalizer intent collision')
        c=probe['control']
        need(c['jobId']==job and c['state']=='running' and
             c['reservationRetained'] is True and
             c['terminalLifecycle'] is None and
             probe['queueKnown'] and not probe['unknownReservations'] and
             not probe['otherActiveJobs'] and not probe['guestActive'] and
             not probe['gpuLeaseActive'],
             'existing orphan intent changed from exact retained row')
        # A dispatcher may still be closing the same canonical row. Never
        # start a second one even if the original response was lost.
        return {'decision':('WAIT_ORPHAN_FINALIZER' if not probe['workerLockFree']
                            else 'HOLD_ORPHAN_FINALIZER_OUTCOME'),
                'effect':'UNKNOWN','nonce':state['inflight'],
                'orphanNonce':prior['nonce'],
                'orphanIntentSHA256':sha(prior_raw),'oldJobId':job}
    need(orphan_scope(probe,policy,state),'fresh actorless reserved orphan scope')
    nonce=os.urandom(16).hex()
    need(nonce!=state['inflight'] and
         nonce!=job.removeprefix('root-github-robot-control-'),
         'fresh disjoint dispatcher nonce')
    intent={'kind':'ROOT_RUNNER21_ORPHAN_FINALIZER_INTENT_V1',
            'nonce':nonce,'oldJobId':job,'priorInflight':state['inflight'],
            'boot':probe['boot'],'control':probe['control'],
            'mainCommit':policy['mainCommit'],
            'queueSourceSHA256':policy['queueSourceSHA256'],
            'controllerProbeSHA256':sha(probe_raw),
            'ordinaryQueueOnly':True,'vmAdmission':False}
    cycle_raw=load_code(CYCLE,policy['controllerCycleSHA256'])
    raw=save_orphan_intent(path,intent)
    child=start_held_python(cycle_raw,['--orphan-finalize',nonce,
        sha(canonical(policy)),sha(probe_raw),sha(raw)])
    outcome=capture(child,MAX_CYCLE_SECONDS)
    if not(outcome['reaped'] and outcome['numeric']==0 and
           all(outcome['eof'].values()) and outcome['first'] is None and
           outcome['stderr']==b''):
        return {'decision':'HOLD_ORPHAN_FINALIZER_OUTCOME','effect':'UNKNOWN',
                'nonce':state['inflight'],'orphanNonce':nonce,
                'oldJobId':job,'orphanIntentSHA256':sha(raw),
                'numeric':outcome['numeric'],'reaped':outcome['reaped'],
                'first':outcome['first'],
                'stdoutSHA256':sha(outcome['stdout']),
                'stderrSHA256':sha(outcome['stderr'])}
    result=receipt(outcome['stdout'],'ROOT_RUNNER21_ORPHAN_DISPATCH_CONTROLLER_V1')
    need(result.get('nonce')==nonce and result.get('oldJobId')==job and
         result.get('vmAdmission') is False and
         result.get('dispatcherUnit')=='opemos-root-robot-dispatcher-'+nonce+'.service',
         'authenticated ordinary orphan dispatcher identity')
    return {'decision':'DISPATCHED_ORPHAN_FINALIZER',
            'effect':'ORDINARY_QUEUE_RUN_ONLY','nonce':state['inflight'],
            'orphanNonce':nonce,'oldJobId':job,
            'dispatcherUnit':result['dispatcherUnit'],
            'orphanIntentSHA256':sha(raw),
            'resultSHA256':sha(outcome['stdout']),
            'canonicalTerminalClaimed':False}

def reconcile_closed_inflight(policy, state, probe, now, probe_sha):
    old=state.get('lastOutcome') or {}
    if (state.get('inflight') is None or old.get('nonce')!=state['inflight'] or
        old.get('action')!='RECONCILE_CLOSED' or
        type(old.get('controlJobId')) is not str or
        not re.fullmatch(r'root-github-robot-control-[0-9a-f]{32}',old['controlJobId'])):
        return None
    c=probe['control']
    if c['jobId']=='root-github-robot-control-'+state['inflight'] and c['state']=='running':return None
    if not (c['jobId']==old['controlJobId'] and
            c['state'] in ('passed','failed','timed_out','blocked','unknown','output_limit') and
            c['terminalLifecycle']=='CLOSED' and c['reservationRetained'] is False and
            not any(c[k] for k in ('listenerAlive','controllerAlive','workerAlive')) and
            probe['networkReachable'] and probe['queueKnown'] and probe['workerLockFree'] and
            not any(probe[k] for k in ('runnerOnline','runnerBusy','actionsInProgress',
                'sourceOwnerBusy','guestActive','gpuLeaseActive')) and
            not probe['otherActiveJobs'] and not probe['unknownReservations']):
        return {'decision':'HOLD_CLOSED_INFLIGHT_CURRENT_OWNER','effect':False,
                'nonce':state['inflight']}
    # Preserve the complete original state before changing only recovery bookkeeping.
    receipt={'kind':'RUNNER21_CLOSED_PREDECESSOR_DISPOSITION_V1',
             'atUnix':now,'before':state.copy(),'probeSHA256':probe_sha,
             'historicalEffects':'UNKNOWN_EXCEPT_CANONICAL_PREDECESSOR_CLOSED_RELEASED',
             'successorCreated':False,'queueMutation':False,'vmAdmission':False}
    raw=canonical(receipt)
    path=ROOT/('closed-inflight-'+state['inflight']+'-'+sha(raw)[:16]+'.json')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:write_all(fd,raw);os.fsync(fd)
    finally:os.close(fd)
    nonce=state['inflight']
    state['inflight']=None;state['failureCount']=0;state['nextAttemptUnix']=now+1
    state['lastOutcome']={'action':'RECONCILE_CLOSED','nonce':nonce,
        'reconciledBy':'actual selected canonical predecessor CLOSED/released, no successor actors',
        'disposition':str(path),'dispositionSHA256':sha(raw),
        'successorCreated':False,'originalOutcome':old}
    write_state(state)
    return {'decision':'RECONCILED_CLOSED_PREDECESSOR_ONLY',
            'effect':'RECOVERY_BOOKKEEPING_ONLY','nonce':nonce,
            'successorCreated':False,'dispositionSHA256':sha(raw)}

MATERIALIZED_RENEWAL_READONLY = "from pathlib import Path\nimport os,sys,json,hashlib,stat,types,subprocess,time\nx=json.loads(sys.argv[1]);p=x['policy'];nonce=x['nonce'];prior=x['prior'];pending=x.get('pending',False);assert type(pending)is bool;base=Path('/var/lib/opemos-robot-control-r1')\ndef need(v,m):\n if not v:raise RuntimeError(m)\ndef enc(v):return(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\\n').encode()\ndef read(path,expected=None):\n path=Path(path);fds=[];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd)\n try:\n  for name in path.parts[1:]:\n   fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);fds.append(fd);s=os.fstat(fd);need(s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'protected Root normal source/record ancestry')\n  f=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');i={k:getattr(os.fstat(fd),k)for k in f};need(stat.S_ISREG(i['st_mode'])and i['st_nlink']==1,'single Root normal record');raw=b''\n  while b:=os.read(fd,65536):raw+=b;need(len(raw)<=1048576,'normal proof bound')\n  h=hashlib.sha256(raw).hexdigest();need(i=={k:getattr(os.fstat(fd),k)for k in f}=={k:getattr(os.lstat(path),k)for k in f}and(expected is None or h==expected),'full held named Root source/proof');return raw,dict(path=str(path),bytes=len(raw),sha256=h,identity=i)\n finally:\n  for fd in fds[::-1]:os.close(fd)\nraw,source=read(base/'auto-recovery/normal_probe.py',p['normalProbeSHA256']);N=types.ModuleType('reviewed_normal_readonly_proof');N.__file__=source['path'];exec(compile(raw,N.__file__,'exec'),N.__dict__);N.REMOTE_POLICY=p;N.REMOTE_GITHUB=x['github']\n_,_,qraw=N.local_sources(p);rows,bindings,config=N.private_queue(qraw);selected,foreign,unknown=N.classify_rows(rows,bindings,p)\nneed(not foreign and not unknown and selected['id']=='root-github-robot-control-'+nonce,'sole actual successor/no foreign reservation');old=next(z for z in rows if z['id']==prior);current=selected;oldStatus=N.current_control(old,p);newStatus=N.current_control(current,p)\nneed(old['finished'] is not None and oldStatus['terminalLifecycle']=='CLOSED' and oldStatus['reservationRetained'] is False,'actual predecessor canonical CLOSED/released')\nneed(current['state']==('pending'if pending else'running') and newStatus['sourceCommit']==p['mainCommit'] and newStatus['queueSourceSHA256']==p['queueSourceSHA256'],'same normal running successor source')\ndef manager(unit,user=False):\n argv=(['/usr/sbin/runuser','-u','connor','--','/usr/bin/env','XDG_RUNTIME_DIR=/run/user/1000','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus'] if user else [])+['/usr/bin/systemctl']+(['--user'] if user else [])+['show',unit,'-p','ActiveState','-p','MainPID','-p','ControlGroup','-p','InvocationID','-p','LoadState','-p','ExecStart'];v=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10);need(v.returncode==0 and not v.stderr,'actual own manager');return dict(l.split('=',1)for l in v.stdout.decode().splitlines()if'='in l)\npreRaw,prePin=read(base/'transactions'/nonce/'preflight.json');pre=json.loads(preRaw);closed=bytes.fromhex(pre['oldControl']['closedReceiptHex']);need(hashlib.sha256(closed).hexdigest()==pre['oldControl']['closedReceiptSHA256'],'same original closure source');closure=json.loads(closed)\noldWorkers=[]\nrefs=closure.get('normalDispatchers');units=([r['unit']for r in refs]if refs is not None else['opemos-root-robot-dispatcher-'+prior.removeprefix('root-github-robot-control-')+'.service'])\nneed(1<=len(units)<=2 and len(set(units))==len(units),'complete distinct actual predecessor dispatcher set')\noldManager=manager(old['unit']);oldOuters=[manager(u,True)for u in units];oldOuter=oldOuters[0];outer=units[0]\nfor m in[oldManager,*oldOuters]:need(m['MainPID']=='0'and m['ControlGroup']==''and m['ActiveState']in('inactive','failed'),'original normal manager and actual dispatchers fully closed')\nif refs is not None:\n for r,m in zip(refs,oldOuters):\n  need(r['jobId']==prior and r['queueSourceSHA256']==p['queueSourceSHA256']and r['unit']=='opemos-root-robot-dispatcher-'+r['nonce']+'.service'and(m['LoadState']=='not-found'or m['InvocationID']==r['invocation']),'same source-bound actual predecessor dispatcher invocation')\n  if r['pid']:\n   q=Path('/proc')/str(r['pid'])/'stat'\n   try:need(int(q.read_text().rsplit(')',1)[1].split()[19])!=r['start'],'original actual dispatcher leader remains')\n   except(FileNotFoundError,ProcessLookupError):pass\nfor q in Path('/proc').iterdir():\n if not q.name.isdecimal():continue\n try:need(not any(u in(q/'cgroup').read_text()for u in units),'actual old dispatcher group actor remains')\n except(FileNotFoundError,ProcessLookupError):pass\nif refs is not None:\n for r in refs:\n  worker=r.get('worker')\n  if worker is None:continue\n  path=Path('/proc')/str(worker['pid'])/'stat'\n  try:need(int(path.read_text().rsplit(')',1)[1].split()[19])!=worker['start'],'actual old heavy child still exists')\n  except(FileNotFoundError,ProcessLookupError):pass\n  need(worker['cgroup'].startswith('0::/user.slice/user-1000.slice/user@1000.service/opemos.slice/opemos-heavy.slice/run-')and worker['cgroup'].endswith('.scope'),'same actual historical heavy scope')\n  group=Path('/sys/fs/cgroup')/worker['cgroup'].removeprefix('0::').lstrip('/')\n  need(not group.exists()or not(group/'cgroup.procs').read_text().strip(),'actual old worker heavy scope still occupied')\n  oldWorkers.append({'expected':worker,'processAbsent':True,'scopeEmpty':True})\n\nactors=N.actors();need(not any(old['unit']in a['cgroup'] or any(u in a['cgroup']for u in units) or any('/releases/'+prior.removeprefix('root-github-robot-control-')+'/'in z for z in a['argv'])for a in actors),'no old actors')\nb=[json.loads(z['value'])for z in bindings if z['job_id']==current['id']]\ncurrentDispatcher=None;currentFiles=[]\nif pending:\n need(b==[] and current['unit']is None and current['started']is None and current['finished']is None and not current['result'],'genuine never-started pending successor/no binding')\n binding=None;newManager=None;own=[]\n need(not any(any(z in arg for z in('Runner.Listener','Runner.Worker','qemu-system-','/queue_job.py','/control.py','/launch.py'))for a in actors for arg in a['argv']),'actual no control/worker/guest actors before pending bookkeeping')\n currentDispatcher=manager('opemos-root-robot-dispatcher-'+nonce+'.service',True)\n need(currentDispatcher['MainPID']=='0'and currentDispatcher['ControlGroup']==''and currentDispatcher['ActiveState']in('inactive','failed')and(currentDispatcher['LoadState']=='not-found'or str(N.QUEUE/'queue.sh')in currentDispatcher['ExecStart']),'attempted dispatcher absent or quiescent exact normal source')\n spec=json.loads(current['spec']);root=str(base/'releases'/nonce);expected=x['expectedSources']\n need(spec['id']==current['id']and spec['owner']=='root'and spec['platform']=='controlplane'and spec['cores']==1 and spec['memory']==1073741824 and spec['timeout_seconds']==21600 and spec['resources']==['opemos-robot-controlplane']and spec['depends_on']==[]and spec['cwd']==root and spec['command']==['/usr/bin/python3',root+'/launch.py',root+'/lease.json','/run/user/1000/opemos-robot-control-'+nonce],'exact normal pending source/resource/command data')\n need(len(spec['files'])==5 and {f['path']for f in spec['files']}=={root+'/'+name for name in(*expected,'lease.json')},'all five pending source and lease roles')\n for f in spec['files']:\n  data,ref=read(f['path'],f['sha256']);need(ref['bytes']==f['bytes'],'whole generated pending file bytes')\n  name=Path(f['path']).name\n  if name in expected:need({k:ref[k]for k in('bytes','sha256')}==expected[name]and ref['identity']['st_mode']&0o7777==0o444,'same reviewed normal template source role')\n  currentFiles.append(ref)\nelse:\n need(len(b)==1,'one actual successor binding');binding=b[0];newManager=manager(current['unit']);need(newManager['InvocationID']==binding['invocation'] and newManager['ActiveState']=='active'and newManager['MainPID']!='0'and newManager['ControlGroup'],'same actual canonical manager invocation')\n own=[a for a in actors if current['unit']in a['cgroup']];need(any(a['pid']==int(newManager['MainPID'])for a in own)and not any(any('Runner.Worker'in z or'qemu-system-'in z for z in a['argv'])for a in actors),'actual logger and no assigned worker/guest')\npreRaw,prePin=read(base/'transactions'/nonce/'preflight.json');postRaw,postPin=read(base/'transactions'/nonce/'postflight.json');pre=json.loads(preRaw);post=json.loads(postRaw);closed=bytes.fromhex(pre['oldControl']['closedReceiptHex']);need(hashlib.sha256(closed).hexdigest()==pre['oldControl']['closedReceiptSHA256'],'original closure hash');closure=json.loads(closed)\nneed(pre['transaction']==post['transaction']==nonce and pre['mainCommit']==p['mainCommit'] and pre['queueSourceSHA256']==p['queueSourceSHA256'] and closure['oldRowId']==prior and closure['oldRowSHA256']==N.sha(N.enc(old)),'actual predecessor/materialization/whole row/source join')\nneed(pre['oldControl']['unit']==old['unit']and pre['oldControl']['liveMainPID']==0 and pre['oldControl']['liveUID0Absent']is True and closure['oldDispatcherAbsent']is True and closure['oldListenerAbsent']is True and closure['fullUID0Group']['absent']is True,'original whole normal closure proof')\nleaseRaw,leasePin=read(base/'releases'/nonce/'lease.json');fixedRaw,fixedPin=read(base/'releases'/nonce/'fixed-policy.json');lease=json.loads(leaseRaw);fixed=json.loads(fixedRaw);need(post['leaseSHA256']==leasePin['sha256']and post['rootRelease']==str(base/'releases'/nonce)and lease['runtimeAuthorized']is True and lease['runnerId']==21 and lease['engine_source_commit']==p['mainCommit']and lease['connection_queue_sha256']==p['queueSourceSHA256']and fixed['expiresAt']>time.time(),'actual same successor materialization/lease/source/expiry')\nobserved=N.observe();need(observed['control']['jobId']==current['id']and observed['control']['state']==('pending'if pending else'running')and not any(observed[k]for k in('runnerBusy','actionsInProgress','sourceOwnerBusy','guestActive','gpuLeaseActive','otherActiveJobs','unknownReservations')),'full authenticated enriched actual successor status')\nif pending:need(observed['queueKnown']and observed['workerLockFree']and not observed['runnerOnline']and not any(observed['control'][k]for k in('listenerAlive','controllerAlive','workerAlive','ownUnitBound')),'actual pending has no bound runtime/readiness')\nif pending:\n need(manager('opemos-root-robot-dispatcher-'+nonce+'.service',True)==currentDispatcher,'same pending dispatcher after readonly proof')\n rows2,bindings2,config2=N.private_queue(qraw);need(rows2==rows and bindings2==bindings and config2==config,'whole pending canonical snapshot unchanged after proof')\nelse:need(all(observed['control'][k]for k in('listenerAlive','controllerAlive','workerAlive','ownUnitBound'))and manager(current['unit'])==newManager,'same enriched running successor and invocation')\nnewStatus=observed['control'];oldStatus={k:v for k,v in oldStatus.items()if k not in('listenerAlive','controllerAlive','workerAlive','ownUnitBound')}\nresult={'kind':'NORMAL_MATERIALIZED_PENDING_PROVENANCE_V1'if pending else'NORMAL_MATERIALIZED_RENEWAL_PROVENANCE_V1','atUnix':time.time(),'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'nonce':nonce,'prior':prior,'sourcePin':source,'oldRow':old,'oldStatus':oldStatus,'oldManager':oldManager,'oldOuter':oldOuter,'oldOuters':oldOuters,'oldWorkers':oldWorkers,'oldActors':[],'currentRow':current,'currentStatus':newStatus,'currentBinding':binding,'currentManager':newManager,'currentActors':own,'currentDispatcher':currentDispatcher,'currentFiles':currentFiles,'preflight':{'pin':prePin,'transaction':pre['transaction'],'mainCommit':pre['mainCommit'],'queueSourceSHA256':pre['queueSourceSHA256'],'oldControl':pre['oldControl']},'postflight':{'pin':postPin,'transaction':post['transaction'],'rootRelease':post['rootRelease'],'leaseSHA256':post['leaseSHA256']},'closure':closure,'lease':{'pin':leasePin,'value':lease},'fixed':{'pin':fixedPin,'value':fixed},'effects':[]}\nif 'resumeDispatcher'in x:\n cycleRaw=bytes.fromhex(x['normalCycleHex']);need(hashlib.sha256(cycleRaw).hexdigest()==p['normalCycleSHA256'],'same Root-held current normal worker observer source')\n C=types.ModuleType('reviewed_normal_dispatcher_observer');C.__file__=str(base/'auto-recovery/normal_cycle.py');exec(compile(cycleRaw,C.__file__,'exec'),C.__dict__)\n context={'lastOutcome':{'controlJobId':current['id'],'dispatcherNonce':x['resumeDispatcher']}}\n dispatcher=C.owning_dispatcher(current,p,context);dm=manager(dispatcher['unit'],True)\n need(dm['ActiveState']=='active'and int(dm['MainPID'])==dispatcher['pid']and dm['InvocationID']==dispatcher['invocation'],'actual retained resume dispatcher alive')\n N.pin_source(N.QUEUE/'heavy.sh',p['heavySHA256'],1000);N.pin_source(N.QUEUE/'queue.sh',p['normalQueueEntrySHA256'],1000)\n lockpath=N.QUEUE/'state/worker.lock';heavy=Path('/run/user/1000/opemos-heavy.lock');lf=os.open(lockpath,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);hf=os.open(heavy,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n try:\n  fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');identity=lambda st:{k:getattr(st,k)for k in fields}\n  li=identity(os.fstat(lf));hi=identity(os.fstat(hf))\n  for path,i in((lockpath,li),(heavy,hi)):need(stat.S_ISREG(i['st_mode'])and i['st_uid']==i['st_gid']==1000 and i['st_nlink']==1 and i==identity(os.lstat(path)),'same existing owned native lock inode')\n  def actor(pid):\n   value=C.proc(pid);value['ppid']=int((Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[1]);value['argv']=[a.decode()for a in value['argv']];return value\n  def lockfd(pid,number,i):\n   q=Path('/proc')/str(pid);st=os.stat(q/'fd'/str(number));need((st.st_dev,st.st_ino)==(i['st_dev'],i['st_ino']),'actual same inherited lock FD inode')\n   locks=[v for v in(q/'fdinfo'/str(number)).read_text().splitlines()if v.startswith('lock:')and'FLOCK'in v and'WRITE'in v];need(locks,'actual kernel FLOCK custody');return locks\n  custody=None\n  for attempt in range(20):\n   leader=actor(dispatcher['pid']);children=[int(z)for z in(Path('/proc')/str(dispatcher['pid'])/'task'/str(dispatcher['pid'])/'children').read_text().split()]\n   need(leader['uids']==[1000]*4 and leader['start']==dispatcher['start']and dispatcher['unit']in leader['cgroup']and str(N.QUEUE/'heavy.sh')in leader['argv'],'same normal heavy wrapper leader')\n   if len(children)!=1:time.sleep(.1);continue\n   worker=actor(children[0]);need(worker['uids']==[1000]*4 and worker['ppid']==dispatcher['pid']and worker['argv']==['/usr/bin/python3',str(N.QUEUE/'test_queue.py'),'--queue',str(N.QUEUE/'state'),'run']and worker['cgroup'].startswith('0::/user.slice/user-1000.slice/user@1000.service/opemos.slice/opemos-heavy.slice/run-')and worker['cgroup'].endswith('.scope'),'same genuine child queue worker in original heavy scope')\n   if(Path('/proc')/str(worker['pid'])/'task'/str(worker['pid'])/'children').read_text().strip():time.sleep(.1);continue\n   holders=[]\n   for q in(Path('/proc')/str(worker['pid'])/'fd').iterdir():\n    try:\n     st=os.stat(q)\n     if(st.st_dev,st.st_ino)==(li['st_dev'],li['st_ino']):holders.append({'fd':int(q.name),'locks':lockfd(worker['pid'],int(q.name),li)})\n    except(FileNotFoundError,ProcessLookupError):continue\n   need(holders,'actual canonical worker owns its kernel worker lock')\n   parent_locks=lockfd(leader['pid'],9,hi);worker_locks=lockfd(worker['pid'],9,hi);need(parent_locks==worker_locks,'same inherited heavy open-file-description custody')\n   need(actor(leader['pid'])==leader and actor(worker['pid'])==worker and manager(dispatcher['unit'],True)==dm,'same dispatcher/worker PIDstart/parent/source and manager after lock proof')\n   custody={'lockPath':str(lockpath),'lockIdentity':li,'holders':holders,'leader':leader,'worker':worker,'heavyPath':str(heavy),'heavyIdentity':hi,'parentHeavyLocks':parent_locks,'workerHeavyLocks':worker_locks};break\n  need(custody is not None,'bounded helper-free same normal worker/heavy custody cut')\n  need(li==identity(os.fstat(lf))==identity(os.lstat(lockpath))and hi==identity(os.fstat(hf))==identity(os.lstat(heavy)),'same held/named native worker/heavy lock epochs')\n finally:os.close(hf);os.close(lf)\n result['resumedPending']={'operationNonce':x['resumeDispatcher'],'auditSHA256':x['pendingAuditSHA256'],'normalCycleSHA256':p['normalCycleSHA256'],'dispatcher':dispatcher,'manager':dm,'workerCustody':custody}\nprint(enc(result).decode(),end='')\n"

def validate_materialized_renewal(proof,policy,state,probe,now,pending=False,subject=None):
    old=state['lastOutcome'];nonce=state['inflight'];prior=old['controlJobId'];c=probe['control']
    if subject is not None:
        need(not pending and old['action']=='RESUME_PENDING'and old['nonce']==nonce==subject['operationNonce']and
             old['controlJobId']=='root-github-robot-control-'+subject['nonce']and
             set(subject)=={'nonce','prior','operationNonce','auditSHA256'},
             'same retained resume intent; explicit original materialization subject only')
        nonce=subject['nonce'];prior=subject['prior']
    need(proof['kind']==('NORMAL_MATERIALIZED_PENDING_PROVENANCE_V1'if pending else'NORMAL_MATERIALIZED_RENEWAL_PROVENANCE_V1')and proof['effects']==[]and proof['nonce']==nonce and proof['prior']==prior and proof['boot']==probe['boot']and 0<=now-proof['atUnix']<=20,'fresh actual renewal provenance boot/nonce')
    row=proof['oldRow'];status=proof['oldStatus'];closure=proof['closure'];pre=proof['preflight'];post=proof['postflight'];current=proof['currentRow']
    need(row['id']==prior and row['finished']is not None and row['state']in('passed','failed','timed_out','blocked','output_limit')and status['terminalLifecycle']=='CLOSED'and status['reservationRetained']is False,'actual predecessor terminal CLOSED/released')
    need(closure['oldRowId']==prior and closure['oldRowSHA256']==sha(canonical(row))and closure['oldDispatcherAbsent']is True and closure['oldListenerAbsent']is True and closure['fullUID0Group']['absent']is True and sha(bytes.fromhex(pre['oldControl']['closedReceiptHex']))==pre['oldControl']['closedReceiptSHA256']and strict(bytes.fromhex(pre['oldControl']['closedReceiptHex']))==closure,'whole predecessor row and immutable closure receipt')
    for manager in(proof['oldManager'],proof['oldOuter']):need(manager['MainPID']=='0'and manager['ControlGroup']==''and manager['ActiveState']in('inactive','failed'),'fresh full predecessor process closure')
    if 'normalDispatchers'in closure:
        refs=closure['normalDispatchers'];managers=proof['oldOuters']
        need(1<=len(refs)<=2 and len({r['unit']for r in refs})==len(refs)==len(managers)and
             proof['oldOuter']==managers[0],'actual complete distinct predecessor dispatchers')
        for ref,m in zip(refs,managers):
            need(set(ref)in({'kind','jobId','nonce','unit','queueSourceSHA256','invocation','pid','start'},
                 {'kind','jobId','nonce','unit','queueSourceSHA256','invocation','pid','start','worker'})and
                 ref['kind']=='NORMAL_CONTROL_DISPATCHER_IDENTITY_V1'and ref['jobId']==prior and
                 ref['queueSourceSHA256']==policy['queueSourceSHA256']and
                 re.fullmatch('[0-9a-f]{32}',ref['nonce'])and
                 ref['unit']=='opemos-root-robot-dispatcher-'+ref['nonce']+'.service'and
                 re.fullmatch('[0-9a-f]{32}',ref['invocation'])and type(ref['pid'])is int and ref['pid']>=0 and
                 ((ref['pid']==0 and ref['start']is None)or(type(ref['start'])is int and ref['start']>0))and
                 m['MainPID']=='0'and m['ControlGroup']==''and m['ActiveState']in('inactive','failed')and
                 (m['LoadState']=='not-found'or m['InvocationID']==ref['invocation']),
                 'same actual predecessor dispatcher source/identity/native closure')
        workers=[r['worker']for r in refs if r.get('worker')is not None]
        need(len(proof.get('oldWorkers',[]))==len(workers),'complete actual old heavy child closure set')
        for worker,observed in zip(workers,proof.get('oldWorkers',[])):
            need(set(worker)=={'pid','start','cgroup'}and type(worker['pid'])is int and worker['pid']>1 and
                 type(worker['start'])is int and worker['start']>0 and
                 worker['cgroup'].startswith('0::/user.slice/user-1000.slice/user@1000.service/opemos.slice/opemos-heavy.slice/run-')and
                 worker['cgroup'].endswith('.scope')and observed['expected']==worker and
                 observed['processAbsent']is True and observed['scopeEmpty']is True,
                 'same actual old queue worker PIDstart and independent heavy scope closed')
    need(proof['oldActors']==[]and pre['transaction']==post['transaction']==nonce and pre['mainCommit']==policy['mainCommit']and pre['queueSourceSHA256']==policy['queueSourceSHA256'],'normal materialization lineage/source')
    lease=proof['lease'];fixed=proof['fixed'];binding=proof['currentBinding'];manager=proof['currentManager'];source=proof['sourcePin']
    need(source['sha256']==policy['normalProbeSHA256']and source['identity']['st_uid']==source['identity']['st_gid']==0 and current['id']==c['jobId']=='root-github-robot-control-'+nonce and current['state']==('pending'if pending else'running')and proof['currentStatus']['sourceCommit']==policy['mainCommit']and proof['currentStatus']['queueSourceSHA256']==policy['queueSourceSHA256'],'actual sole successor source and row')
    if pending:
        dispatcher=proof['currentDispatcher'];expected=materialized_source_roles(policy);root='/var/lib/opemos-robot-control-r1/releases/'+nonce
        need(binding is None and manager is None and current['unit']is None and current['started']is None and current['finished']is None and not current['result']and proof['currentActors']==[]and not any(proof['currentStatus'][k]for k in('listenerAlive','controllerAlive','workerAlive','ownUnitBound')),'actual pending row has no runtime or binding')
        need(dispatcher['MainPID']=='0'and dispatcher['ControlGroup']==''and dispatcher['ActiveState']in('inactive','failed')and(dispatcher['LoadState']=='not-found'or '/home/connor/.local/state/opemos-test-queue-r2/queue.sh'in dispatcher['ExecStart']),'same quiescent normal dispatcher for pending lineage')
        pins=proof['currentFiles'];need(len(pins)==5 and len({x['path']for x in pins})==5 and {x['path']for x in pins}=={root+'/'+n for n in(*expected,'lease.json')},'complete unique pending source pins')
        for pin in pins:
            need(pin['identity']['st_uid']==pin['identity']['st_gid']==0 and pin['identity']['st_nlink']==1,'Root pending source custody')
            name=Path(pin['path']).name
            if name in expected:need({k:pin[k]for k in('bytes','sha256')}==expected[name]and pin['identity']['st_mode']&0o7777==0o444,'same current normal template source')
            else:need(pin==lease['pin'],'same actual pending lease full9')
    else:
        need(binding['job_id']==current['id']and binding['unit']==current['unit']and manager['InvocationID']==binding['invocation']and manager['ActiveState']=='active'and manager['MainPID']!='0'and manager['ControlGroup']and proof['currentActors']and all(proof['currentStatus'][k]for k in('listenerAlive','controllerAlive','workerAlive','ownUnitBound')),'current exact manager/binding/actors')
    if subject is not None:
        resumed=proof['resumedPending'];d=resumed['dispatcher'];m=resumed['manager'];custody=resumed['workerCustody']
        need(resumed['operationNonce']==subject['operationNonce']and resumed['auditSHA256']==subject['auditSHA256']and
             resumed['normalCycleSHA256']==policy['normalCycleSHA256']and
             d['kind']=='NORMAL_CONTROL_DISPATCHER_IDENTITY_V1'and d['nonce']==subject['operationNonce']and
             d['unit']=='opemos-root-robot-dispatcher-'+d['nonce']+'.service'and
             d['jobId']==current['id']and d['queueSourceSHA256']==policy['queueSourceSHA256']and
             m['LoadState']=='loaded'and m['ActiveState']=='active'and m['MainPID']==str(d['pid'])and
             m['InvocationID']==d['invocation']and d['unit']in m['ControlGroup']and
             '/home/connor/.local/state/opemos-test-queue-r2/queue.sh'in m['ExecStart']and
             type(d['pid'])is int and d['pid']>1 and type(d['start'])is int and d['start']>0,
             'same actual source-bound retained resume dispatcher incarnation')
        li=custody['lockIdentity'];hi=custody['heavyIdentity'];leader=custody['leader'];worker=custody['worker']
        if d.get('worker')is not None:need(d['worker']=={k:worker[k]for k in('pid','start','cgroup')},'same normal observer child and actual lock-holder worker')
        need(custody['lockPath']=='/home/connor/.local/state/opemos-test-queue-r2/state/worker.lock'and
             custody['heavyPath']=='/run/user/1000/opemos-heavy.lock'and all(
                 stat.S_ISREG(i['st_mode'])and i['st_uid']==i['st_gid']==1000 and i['st_nlink']==1 for i in(li,hi))and
             custody['holders']and custody['parentHeavyLocks']==custody['workerHeavyLocks']and custody['parentHeavyLocks'],
             'actual existing worker lock and shared inherited heavy OFD custody')
        need(leader['pid']==d['pid']and leader['start']==d['start']and leader['uids']==worker['uids']==[1000]*4 and
             d['unit']in leader['cgroup']and '/home/connor/.local/state/opemos-test-queue-r2/heavy.sh'in leader['argv']and
             type(worker['pid'])is int and worker['pid']>1 and type(worker['start'])is int and worker['start']>0 and worker['ppid']==leader['pid']and worker['argv']==['/usr/bin/python3','/home/connor/.local/state/opemos-test-queue-r2/test_queue.py','--queue','/home/connor/.local/state/opemos-test-queue-r2/state','run']and
             worker['cgroup'].startswith('0::/user.slice/user-1000.slice/user@1000.service/opemos.slice/opemos-heavy.slice/run-')and
             worker['cgroup'].endswith('.scope'),'actual same-source normal heavy parent and queue child')
        for locks in[custody['parentHeavyLocks'],custody['workerHeavyLocks'],*[h['locks']for h in custody['holders']]]:
            need(locks and all(v.startswith('lock:')and'FLOCK'in v and'WRITE'in v for v in locks),
                 'actual kernel worker/heavy FLOCK records')
    need(post['rootRelease']=='/var/lib/opemos-robot-control-r1/releases/'+nonce and post['leaseSHA256']==lease['pin']['sha256']and lease['value']['runtimeAuthorized']is True and lease['value']['runnerId']==21 and lease['value']['engine_source_commit']==policy['mainCommit']and lease['value']['connection_queue_sha256']==policy['queueSourceSHA256']and fixed['value']['expiresAt']==c['leaseExpiresUnix']and now<c['leaseExpiresUnix'],'same actual normal successor lease and finite expiry')
    return proof

def materialized_source_roles(policy):
    raw=held(ROOT/'normal-template.json',16*1024*1024,0,0o400)
    need(sha(raw)==policy['normalTemplateSHA256'],'same reviewed normal materialization template')
    template=strict(raw);roles={}
    for name in('control.py','connection_host.py','host_engine.py','launch.py'):
        value=template['sources'][name];data=bytes.fromhex(value['hex'])
        need(sha(data)==value['sha256'],'same held template source body')
        roles[name]={'bytes':len(data),'sha256':value['sha256']}
    need(roles['control.py']['sha256']==policy['controlBrokerSHA256']and roles['connection_host.py']['sha256']==policy['privatePeerSHA256'],'same installed normal broker/source')
    return roles

def materialized_renewal_provenance(policy,state,probe,pending=False,subject=None):
    observer=types.ModuleType('existing_reviewed_controller_observer');observer.__file__=str(PROBE)
    exec(compile(load_code(PROBE,policy['controllerProbeSHA256']),str(PROBE),'exec'),observer.__dict__)
    config=observer.held(observer.SSH,65536,1000,0o600);need(sha(config)==policy['sshConfigSHA256'],'same authenticated existing SSH route')
    args={'policy':policy,'nonce':state['inflight'],'prior':state['lastOutcome']['controlJobId'],'github':{k:probe[k]for k in('networkReachable','protectedMain','mainCommit','protectedMainCommit','runnerOnline','runnerBusy','actionsInProgress','actionsQueued','heartbeatCurrent','heartbeatNonce')}}
    if pending:args.update(pending=True,expectedSources=materialized_source_roles(policy))
    if subject is not None:args.update(nonce=subject['nonce'],prior=subject['prior'],resumeDispatcher=subject['operationNonce'],pendingAuditSHA256=subject['auditSHA256'],normalCycleHex=load_code(ROOT/'normal_cycle.py',policy['normalCycleSHA256']).hex())
    import shlex
    remote=shlex.join(['sudo','-n','/usr/bin/python3','-I','-B','-',canonical(args).decode()])
    child=subprocess.run(['/usr/sbin/runuser','-u','connor','--','/usr/bin/ssh','-T','-F',str(observer.SSH),'-o','BatchMode=yes','-o','ConnectTimeout=8','-o','StrictHostKeyChecking=yes','opemos-ubuntu-host',remote],input=MATERIALIZED_RENEWAL_READONLY.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
    need(child.returncode==0 and child.stderr==b''and 0<len(child.stdout)<=1048576,'actual normal readonly renewal proof native result')
    need(observer.held(observer.SSH,65536,1000,0o600)==config,'same held SSH source after proof')
    return validate_materialized_renewal(strict(child.stdout),policy,state,probe,time.time(),pending=pending,subject=subject)

def materialized_control_ready(state, probe):
    """Only acknowledge the same nonce already materialized by a normal cycle.

    run_cycle has authenticated the complete current source/queue/native/API
    probe. A renewal's prior generation stays historical; no finalizer replays.
    """
    old=state.get('lastOutcome');nonce=state.get('inflight');c=probe['control']
    if nonce is None or type(old) is not dict or old.get('nonce')!=nonce or old.get('action') not in ('CREATE','GRACEFUL_RENEW','RECONCILE_CLOSED'):
        return False
    if old['action']in('GRACEFUL_RENEW','RECONCILE_CLOSED') and not (
            type(old.get('controlJobId')) is str and
            re.fullmatch(r'root-github-robot-control-[0-9a-f]{32}',old['controlJobId']) and
            old['controlJobId']!='root-github-robot-control-'+nonce):
        return False
    return (c['jobId']=='root-github-robot-control-'+nonce and
            c['state']=='running' and c['reservationRetained'] is True and
            c['terminalLifecycle'] is None and c['ownUnitBound'] and
            c['listenerAlive'] and c['controllerAlive'] and c['workerAlive'] and
            probe['queueKnown'] and probe['runnerOnline'] and
            not probe['runnerBusy'] and not probe['actionsInProgress'] and
            not probe['otherActiveJobs'] and not probe['unknownReservations'] and
            not probe['guestActive'] and not probe['gpuLeaseActive'] and
            not probe['sourceOwnerBusy'])

def reconcile_materialized_pending(policy,state,probe,now):
    old=state.get('lastOutcome');nonce=state.get('inflight');c=probe['control']
    if nonce is None or type(old)is not dict or old.get('nonce')!=nonce or old.get('action')not in('GRACEFUL_RENEW','RECONCILE_CLOSED')or c['jobId']!='root-github-robot-control-'+nonce or c['state']!='pending':return None
    need(type(old.get('controlJobId'))is str and re.fullmatch(r'root-github-robot-control-[0-9a-f]{32}',old['controlJobId'])and old['controlJobId']!=c['jobId'],'actual distinct predecessor for pending materialization')
    need(probe['networkReachable']and probe['protectedMain']and probe['queueKnown']and probe['workerLockFree']and not any(probe[k]for k in('runnerOnline','runnerBusy','actionsInProgress','sourceOwnerBusy','otherActiveJobs','unknownReservations','guestActive','gpuLeaseActive')),'sole pending normal materialization, no readiness')
    proof=materialized_renewal_provenance(policy,state,probe,pending=True)
    validate_materialized_renewal(proof,policy,state,probe,time.time(),pending=True)
    before=strict(canonical(state));record={'kind':'ROOT_NORMAL_MATERIALIZED_PENDING_RECONCILIATION','before':before,'provenance':proof,'atUnix':now,'queueMutation':False,'successorCreated':False,'heartbeatPublished':False}
    raw=canonical(record);path=ROOT/('materialized-pending-'+nonce+'-'+sha(raw)[:16]+'.json');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:write_all(fd,raw);os.fsync(fd)
    finally:os.close(fd)
    state['inflight']=None;state['completedCycles']+=1;state['totalCycles']+=1;state['failureCount']=0;state['nextAttemptUnix']=now+1
    state['lastOutcome']={'action':old['action'],'nonce':nonce,'originalOutcome':old,'reconciledBy':'authenticated materialized pending successor; ordinary RESUME_PENDING still required','disposition':str(path),'dispositionSHA256':sha(raw),'phase':'PENDING_MATERIALIZED_NOT_READY','heartbeatPublished':False,'successorCreated':False}
    write_state(state)
    return {'decision':'RECONCILED_MATERIALIZED_PENDING','effect':'RECOVERY_BOOKKEEPING_ONLY','nonce':nonce,'jobId':c['jobId'],'heartbeatPublished':False}

def resumed_pending_subject(state,probe):
    nonce=state['inflight'];old=state['lastOutcome'];job=probe['control']['jobId']
    need(old['action']=='RESUME_PENDING'and old['nonce']==nonce and old['controlJobId']==job,
         'exact retained original resume operation/control subject')
    control_nonce=job.removeprefix('root-github-robot-control-');records=[]
    for path in ROOT.glob('materialized-pending-'+control_nonce+'-*.json'):
        raw=held(path,1048576,0,0o600);value=strict(raw)
        need(path.name=='materialized-pending-'+control_nonce+'-'+sha(raw)[:16]+'.json',
             'same create-only normal pending acknowledgement bytes')
        if(value['kind']=='ROOT_NORMAL_MATERIALIZED_PENDING_RECONCILIATION'and
           value['before']['inflight']==control_nonce and value['provenance']['nonce']==control_nonce and
           value['queueMutation']is False and value['successorCreated']is False and value['heartbeatPublished']is False):
            records.append((value,sha(raw)))
    need(len(records)==1,'one authentic original materialized pending acknowledgement; never replay')
    value,digest=records[0];prior=value['before']['lastOutcome']['controlJobId']
    need(value['before']['lastOutcome']['action']in('GRACEFUL_RENEW','RECONCILE_CLOSED')and
         value['provenance']['prior']==prior,'actual canonical predecessor/materialization subject')
    return {'nonce':control_nonce,'prior':prior,'operationNonce':nonce,'auditSHA256':digest}

def reconcile_running_resume(policy,state,probe,now):
    old=state.get('lastOutcome');nonce=state.get('inflight');c=probe['control']
    if nonce is None or type(old)is not dict or old.get('action')!='RESUME_PENDING' or c['state']!='running':return None
    need(old.get('nonce')==nonce and old.get('controlJobId')==c['jobId']and
         c['reservationRetained']is True and c['terminalLifecycle']is None and
         all(c[k]for k in('listenerAlive','controllerAlive','workerAlive','ownUnitBound'))and
         probe['runnerOnline']and probe['networkReachable']and probe['protectedMain']and probe['queueKnown']and
         not any(probe[k]for k in('runnerBusy','actionsInProgress','sourceOwnerBusy','otherActiveJobs',
                                'unknownReservations','guestActive','gpuLeaseActive')),
         'only genuine same running resumed control; no foreign work or readiness waiver')
    subject=resumed_pending_subject(state,probe)
    proof=materialized_renewal_provenance(policy,state,probe,subject=subject)
    probe_raw=load_code(PROBE,policy['controllerProbeSHA256'])
    child=start_held_python(probe_raw,['--probe']);fresh=capture(child,MAX_PROBE_SECONDS,abort_readonly=True)
    need(fresh['reaped']and fresh['numeric']==0 and all(fresh['eof'].values())and
         fresh['first']is None and fresh['stderr']==b'','fresh complete post-lineage resume ownership probe')
    latest=receipt(fresh['stdout'],'ROOT_RUNNER21_NORMAL_CURRENT_PROBE_V1')
    validate_probe(latest,policy,int(time.time()))
    need(latest['control']==c and latest['runnerOnline']and latest['networkReachable']and
         latest['protectedMain']and latest['queueKnown']and not any(latest[k]for k in
         ('runnerBusy','actionsInProgress','sourceOwnerBusy','otherActiveJobs','unknownReservations',
          'guestActive','gpuLeaseActive')),'same current live resume/no work after actual dispatcher proof')
    validate_materialized_renewal(proof,policy,state,latest,time.time(),subject=subject)
    before=strict(canonical(state));record={'kind':'ROOT_EXISTING_RESUME_NATIVE_ACK_NOT_READINESS_V1',
        'before':before,'subject':subject,'proof':proof,'atUnix':time.time(),
        'queueMutation':False,'dispatcherStarted':False,'heartbeatPublished':False}
    raw=canonical(record);path=ROOT/('resumed-existing-'+nonce+'-'+sha(raw)[:16]+'.json')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:write_all(fd,raw);os.fsync(fd)
    finally:os.close(fd)
    state['inflight']=None;state['completedCycles']+=1;state['totalCycles']+=1
    state['failureCount']=0;state['nextAttemptUnix']=int(time.time())+1
    state['lastOutcome']={'action':'RESUME_PENDING','nonce':nonce,'dispatcherNonce':nonce,
        'jobId':c['jobId'],'originalOutcome':old,'nativeAcknowledgement':str(path),
        'nativeAcknowledgementSHA256':sha(raw),'heartbeatPublished':False,
        'phase':'RUNNING_RENEWAL_DUE'if c['leaseExpiresUnix']<=time.time()+policy['renewLeadSeconds']else'RUNNING_NATIVE_ACK_NOT_READY'}
    write_state(state)
    return {'decision':'RECONCILED_RUNNING_RESUME_PENDING','effect':'RECOVERY_BOOKKEEPING_ONLY',
            'nonce':nonce,'jobId':c['jobId'],'heartbeatPublished':False}

def failed_probe(stage, native):
    """Keep a bounded genuine failed child stderr in existing private custody.

    This is diagnostic evidence, never a closure, readiness or retry grant.
    Immutable content names retain the first bytes; at most16 distinct records
    (each under140000 bytes) can be added by this producer. A diagnostic failure cannot
    replace the original refusal.
    """
    error=RuntimeError('full current probe native closure; numeric='+str(native['numeric'])+
                       '; stderrSHA256='+sha(native['stderr']))
    try:
        need(stage in('controller-native','controller-ssh')and
             type(native['stderr'])is bytes and len(native['stderr'])<=65536,
             'finite fixed-stage failed stderr')
        record={'kind':'ROOT_RUNNER21_FAILED_PROBE_NATIVE_V1','stage':stage,
                'numeric':native['numeric'],'first':native.get('first'),
                'reaped':native.get('reaped'),'eof':native.get('eof'),
                'stdoutSHA256':sha(native['stdout']),'stderrSHA256':sha(native['stderr']),
                'stderrHex':native['stderr'].hex()}
        raw=canonical(record);need(len(raw)<=140000,'finite failed native evidence')
        directory=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(directory)
            need(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700,
                 'existing Root private evidence directory')
            name='probe-failure-'+sha(raw)+'.json'
            existing=[n for n in os.listdir(directory)if re.fullmatch(r'probe-failure-[0-9a-f]{64}\.json',n)]
            if name in existing:
                need(held(ROOT/name,140000,0,0o400)==raw,'existing immutable failure differs')
            elif len(existing)<16:
                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400,dir_fd=directory)
                try:write_all(fd,raw);os.fsync(fd)
                finally:os.close(fd)
                os.fsync(directory)
            else:name=None
            if name is not None:error.add_note('actual private failed stderr: '+str(ROOT/name))
        finally:os.close(directory)
    except BaseException as secondary:
        error.add_note('secondary failed-probe evidence: '+type(secondary).__name__+': '+str(secondary)[:200])
    return error


def run_cycle(policy, state, now):
    # A pre-effect failure schedules one future attempt. Read-only timer ticks
    # before that point must not run another fallible probe and slide it away.
    # Inflight outcomes still require their normal fresh reconciliation proof.
    if (state['inflight'] is None and now < state['nextAttemptUnix'] and
            state.get('totalCycles',0) < policy['maxTotalCycles'] and
            state['completedCycles'] < policy['maxCycles']):
        return {'decision':'BACKOFF','effect':False}
    probe_raw=load_code(PROBE,policy['controllerProbeSHA256'])
    probe_child=start_held_python(probe_raw,['--probe'])
    observed=capture(probe_child,MAX_PROBE_SECONDS,abort_readonly=True)
    if not(observed['reaped'] and observed['numeric']==0 and
           all(observed['eof'].values()) and observed['first'] is None and observed['stderr']==b''):
        raise failed_probe('controller-native',observed)
    probe=receipt(observed['stdout'],'ROOT_RUNNER21_NORMAL_CURRENT_PROBE_V1')
    # The authenticated remote timestamp is later than the main entry clock.
    # Sample a fresh local clock only after the complete native probe receipt.
    now=int(time.time())
    validate_probe(probe,policy,now)
    resumed=reconcile_running_resume(policy,state,probe,now)
    if resumed is not None:return resumed
    pending=reconcile_materialized_pending(policy,state,probe,now)
    if pending is not None:return pending
    reconciled=reconcile_closed_inflight(policy,state,probe,now,sha(observed['stdout']))
    if reconciled is not None:return reconciled
    if state['inflight'] is not None and type(state['lastOutcome']) is dict and \
       state['lastOutcome'].get('action') in ('GRACEFUL_RENEW','CREATE'):
        old_job=orphan_job(state)
        if probe['control']['jobId']==old_job and \
           probe['control']['state']=='running' and \
           (orphan_intent_path(old_job).exists() or
            orphan_scope(probe,policy,state)):
            return orphan_cycle(policy,state,probe,observed['stdout'],now)
    if materialized_control_ready(state,probe):
        nonce=state['inflight'];c=probe['control'];old_outcome=dict(state['lastOutcome'])
        lineage=None
        if old_outcome['action']in('GRACEFUL_RENEW','RECONCILE_CLOSED'):
            lineage=materialized_renewal_provenance(policy,state,probe)
            second=start_held_python(probe_raw,['--probe']);fresh=capture(second,MAX_PROBE_SECONDS,abort_readonly=True)
            need(fresh['reaped']and fresh['numeric']==0 and all(fresh['eof'].values())and fresh['first']is None and fresh['stderr']==b'','actual fresh enriched ownership/API probe after lineage')
            probe=receipt(fresh['stdout'],'ROOT_RUNNER21_NORMAL_CURRENT_PROBE_V1');now=int(time.time());validate_probe(probe,policy,now)
            need(materialized_control_ready(state,probe),'same fully enriched live successor before normal heartbeat')
            validate_materialized_renewal(lineage,policy,state,probe,time.time())
            before=canonical(state);record=canonical({'kind':'ROOT_NORMAL_MATERIALIZED_RENEWAL_RECONCILIATION','before':strict(before),'provenance':lineage,'atUnix':now,'queueMutation':False,'successorCreated':False})
            record_path=ROOT/('materialized-renewal-'+nonce+'-'+sha(record)[:16]+'.json')
            fd=os.open(record_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:write_all(fd,record);os.fsync(fd)
            finally:os.close(fd)
        # Materialization acknowledgement is not a readiness grant. A fully
        # proven live renewal may already be due for its next ordinary renewal.
        # Preserve the real heartbeat's whole-job lease horizon; do not advertise
        # ready, invent readback or let that publication veto native bookkeeping.
        renewal_due=(lineage is not None and old_outcome['action']in('GRACEFUL_RENEW','RECONCILE_CLOSED') and
                     probe['control']['leaseExpiresUnix']<=now+policy['renewLeadSeconds'])
        published=None
        if not renewal_due:
            heartbeat_raw=load_code(ROOT/'normal_heartbeat.py',policy['heartbeatProducerSHA256'])
            heartbeat=types.ModuleType('reviewed_materialized_heartbeat')
            exec(compile(heartbeat_raw,str(ROOT/'normal_heartbeat.py'),'exec'),heartbeat.__dict__)
            published=heartbeat.publish_once(heartbeat.state_from_current(probe,policy,now,nonce))
            need(published.get('readbackCurrent') is True and published.get('recoveryNonce')==nonce,'same nonce materialized heartbeat readback')
        result_sha=None if published is None else published['stateSHA256']
        state['inflight']=None;state['completedCycles']+=1;state['totalCycles']+=1;state['failureCount']=0;state['nextAttemptUnix']=now+60
        state['lastOutcome']={'action':old_outcome['action'],'nonce':nonce,'reconciledBy':'materialized canonical renewal; readiness withheld pending ordinary renewal' if renewal_due else 'materialized canonical running job plus same-nonce heartbeat','originalOutcome':old_outcome,'provenanceSHA256':None if lineage is None else sha(canonical(lineage)),'resultSHA256':result_sha,'heartbeatPublished':published is not None,'jobId':probe['control']['jobId'],'phase':'RUNNING_RENEWAL_DUE'if renewal_due else'RUNNING'}
        write_state(state)
        return {'decision':'RECONCILED_MATERIALIZED_'+old_outcome['action'],'effect':'RECOVERY_BOOKKEEPING_ONLY'if renewal_due else'NORMAL_CONTROL_ONLY','nonce':nonce,'jobId':probe['control']['jobId'],'heartbeatPublished':published is not None,'resultSHA256':result_sha}
    if state['inflight'] is not None and type(state['lastOutcome']) is dict and state['lastOutcome'].get('action') in ('GRACEFUL_RENEW','CREATE'):
        old=state['lastOutcome']; prior=old.get('controlJobId'); c=probe['control']
        if (prior==c['jobId'] and c['state'] in ('passed','failed','timed_out','blocked','unknown','output_limit') and c['terminalLifecycle']=='CLOSED' and c['reservationRetained'] is False and not probe['runnerOnline'] and not probe['runnerBusy'] and not probe['actionsInProgress'] and not probe['otherActiveJobs'] and not probe['unknownReservations'] and not probe['guestActive'] and not probe['gpuLeaseActive'] and not probe['sourceOwnerBusy'] and probe['workerLockFree'] and probe['networkReachable'] and probe['protectedMain']):
            nonce=state['inflight']; state['inflight']=None;state['completedCycles']+=1;state['totalCycles']+=1;state['failureCount']=0;state['nextAttemptUnix']=now+1
            state['lastOutcome']={'action':old['action'],'nonce':nonce,'reconciledBy':'closed predecessor/no successor/no runtime actors','originalOutcome':old,'probeSHA256':sha(observed['stdout'])}
            write_state(state)
            return {'decision':'RECONCILED_ABSENT_GRACEFUL_RENEW','effect':'NO_EFFECT_PROVEN','nonce':nonce}
    if state['inflight'] is not None and type(state['lastOutcome']) is dict and \
       state['lastOutcome'].get('action')=='REFRESH_HEARTBEAT':
        nonce=state['inflight']
        if (probe['heartbeatCurrent'] and probe['heartbeatNonce']==nonce and
            probe['mainCommit']==policy['mainCommit'] and
            probe['queueSourceSHA256']==policy['queueSourceSHA256']):
            # Heartbeat publication has no queue/control lifecycle effect.
            state['inflight']=None
            state['failureCount']=0;state['nextAttemptUnix']=now+60
            state['lastOutcome']={'action':'REFRESH_HEARTBEAT','nonce':nonce,
                                  'jobId':probe['control']['jobId'],
                                  'dispatcherNonce':state['lastOutcome'].get('dispatcherNonce'),
                                  'reconciledBy':'exact current GitHub readback'}
            write_state(state)
            return {'decision':'RECONCILED_SAME_NONCE_HEARTBEAT',
                    'effect':'CURRENT_HEARTBEAT_READBACK_ONLY','nonce':nonce}
        # A different *current* heartbeat is an effect conflict. An expired
        # predecessor heartbeat is not: it is the exact condition this same
        # nonce refresh is meant to repair after a pre-effect probe race.
        if (probe['heartbeatNonce'] is not None and
            probe['heartbeatNonce']!=nonce and probe['heartbeatCurrent']):
            return {'decision':'HOLD_HEARTBEAT_ACTION_CHANGED',
                    'effect':'UNKNOWN','nonce':nonce}
        if (not probe['networkReachable'] or probe['heartbeatCurrent'] or
            probe['sourceOwnerBusy'] or probe['runnerBusy'] or
            probe['actionsInProgress'] or probe['otherActiveJobs'] or
            probe['unknownReservations'] or probe['guestActive'] or
            probe['gpuLeaseActive']):
            return {'decision':'HOLD_HEARTBEAT_SAME_NONCE_READBACK',
                    'effect':'UNKNOWN','nonce':nonce}
        candidate=dict(state);candidate['inflight']=None
        if decision(probe,policy,now,candidate)!='REFRESH_HEARTBEAT':
            return {'decision':'HOLD_HEARTBEAT_ACTION_CHANGED',
                    'effect':'UNKNOWN','nonce':nonce}
        cycle_raw=load_code(CYCLE,policy['controllerCycleSHA256'])
        child=start_held_python(cycle_raw,['--normal-cycle','REFRESH_HEARTBEAT',nonce,
                                          sha(canonical(policy)),sha(observed['stdout'])])
        outcome=capture(child,MAX_CYCLE_SECONDS)
        if not(outcome['reaped'] and outcome['numeric']==0 and
               all(outcome['eof'].values()) and outcome['first'] is None and
               outcome['stderr']==b''):
            state['lastOutcome']={'action':'REFRESH_HEARTBEAT','nonce':nonce,
                                  'dispatcherNonce':state['lastOutcome'].get('dispatcherNonce'),
                                  'controlJobId':probe['control']['jobId'],
                                  'first':outcome['first'],'numeric':outcome['numeric'],
                                  'reaped':outcome['reaped'],
                                  'stdoutSHA256':sha(outcome['stdout']),
                                  'stderrSHA256':sha(outcome['stderr'])}
            write_state(state)
            return {'decision':'HOLD_SAME_NONCE_HEARTBEAT_OUTCOME',
                    'effect':'UNKNOWN','nonce':nonce}
        result=receipt(outcome['stdout'],'ROOT_RUNNER21_NORMAL_CYCLE_RESULT_V1')
        need(result.get('nonce')==nonce and result.get('action')=='REFRESH_HEARTBEAT'
             and result.get('heartbeatReadbackCurrent') is True and
             result.get('mainCommit')==policy['mainCommit'] and
             result.get('queueSourceSHA256')==policy['queueSourceSHA256'],
             'same nonce heartbeat reconciliation receipt')
        # Periodic readiness maintenance must not exhaust normal-cycle caps.
        state['inflight']=None
        state['failureCount']=0;state['nextAttemptUnix']=now+60
        state['lastOutcome']={'action':'REFRESH_HEARTBEAT','nonce':nonce,
                              'jobId':probe['control']['jobId'],'dispatcherNonce':result.get('dispatcherNonce'),
                              'reconciledBy':'same nonce GET-before-PATCH/readback',
                              'resultSHA256':sha(outcome['stdout'])}
        write_state(state)
        return {'decision':'RECONCILED_SAME_NONCE_HEARTBEAT',
                'effect':'CURRENT_HEARTBEAT_ONLY','nonce':nonce}
    renewal=renew_epoch(policy,state,probe,now)
    if renewal=='WAIT_SAFE_IDLE_POLICY_RENEWAL':
        return {'decision':renewal,'probeSHA256':sha(observed['stdout']),
                'effect':False}
    action=decision(probe,policy,now,state)
    if action not in ('CREATE','RESUME_PENDING','RECONCILE_CLOSED',
                      'GRACEFUL_RENEW','REFRESH_HEARTBEAT'):
        return {'decision':action,'probeSHA256':sha(observed['stdout']),'effect':False}
    cycle_raw=load_code(CYCLE,policy['controllerCycleSHA256'])
    previous_outcome=strict(canonical(state['lastOutcome']))
    nonce=os.urandom(16).hex()
    state['inflight']=nonce
    dispatcher_nonce=(previous_outcome.get('dispatcherNonce')if type(previous_outcome)is dict and
        previous_outcome.get('jobId',previous_outcome.get('controlJobId'))==probe['control']['jobId']else None)
    state['lastOutcome']={'action':action,'nonce':nonce,
                          'dispatcherNonce':dispatcher_nonce,
                          'controlJobId':probe['control']['jobId'],
                          'stage':'DURABLE_BEFORE_NORMAL_EFFECT'}
    write_state(state) # durable before any effect-bearing child can spawn
    child=start_held_python(cycle_raw,['--normal-cycle',action,nonce,
                                      sha(canonical(policy)),sha(observed['stdout'])])
    outcome=capture(child,MAX_CYCLE_SECONDS)
    if not(outcome['reaped'] and outcome['numeric']==0 and
           all(outcome['eof'].values()) and outcome['first'] is None and
           outcome['stderr']==b''):
        error_path=ROOT/('normal-cycle-'+nonce+'.stderr')
        try:
            fd=os.open(error_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:write_all(fd,outcome['stderr'][:65536]);os.fsync(fd)
            finally:os.close(fd)
        except FileExistsError: pass
        state['lastOutcome']={'action':action,'nonce':nonce,'dispatcherNonce':dispatcher_nonce,
                              'controlJobId':probe['control']['jobId'],
                              'first':outcome['first'],
                              'numeric':outcome['numeric'],'reaped':outcome['reaped'],
                              'stdoutSHA256':sha(outcome['stdout']),
                              'stderrSHA256':sha(outcome['stderr']),'stderrCapture':str(error_path)}
        # An effect may have occurred. The next tick must not replay it.
        write_state(state)
        return {'decision':'HOLD_NORMAL_CYCLE_OUTCOME','effect':'UNKNOWN',
                'nonce':nonce,'outcome':state['lastOutcome']}
    result=receipt(outcome['stdout'],'ROOT_RUNNER21_NORMAL_CYCLE_RESULT_V1')
    need(result.get('nonce')==nonce and result.get('action')==action and
         result.get('policySHA256')==sha(canonical(policy)) and
         result.get('probeSHA256')==sha(observed['stdout']) and
         result.get('queueSourceSHA256')==policy['queueSourceSHA256'] and
         result.get('mainCommit')==policy['mainCommit'] and
         result.get('ordinaryRoute') is True and
         result.get('sourceAccepted') is True and
         result.get('runtimeAuthorized') is True and
         result.get('vmAdmission') is False and
         result.get('jobStartedGuard') is True and
         result.get('noDuplicateControllerListenerWorker') is True,
         'exact successful normal finite control receipt')
    need(result.get('dispatcherNonce')==(nonce if action!='REFRESH_HEARTBEAT'else
         (dispatcher_nonce or probe['control']['jobId'].removeprefix('root-github-robot-control-'))),
         'same actual ordinary dispatcher identity through normal acknowledgement')
    renewal_due=result.get('phase')=='RUNNING_RENEWAL_DUE'
    if renewal_due:
        need(action=='RESUME_PENDING' and result.get('heartbeatReadbackCurrent') is False and
             result.get('newOrExistingJobRoutable') is False and
             result.get('jobId')==probe['control']['jobId'] and
             result.get('leaseExpiresUnix')==probe['control']['leaseExpiresUnix'] and
             time.time()<result['leaseExpiresUnix']<=time.time()+policy['renewLeadSeconds'],
             'only same unexpired pending control may acknowledge renewal without readiness')
        child=start_held_python(probe_raw,['--probe'])
        fresh=capture(child,MAX_PROBE_SECONDS,abort_readonly=True)
        need(fresh['reaped'] and fresh['numeric']==0 and all(fresh['eof'].values()) and
             fresh['first'] is None and fresh['stderr']==b'',
             'fresh native closure after resumed control acknowledgement')
        current=receipt(fresh['stdout'],'ROOT_RUNNER21_NORMAL_CURRENT_PROBE_V1')
        validate_probe(current,policy,int(time.time()));c=current['control']
        need(c['jobId']==result['jobId'] and c['state']=='running' and
             c['leaseExpiresUnix']==result['leaseExpiresUnix'] and time.time()<c['leaseExpiresUnix'] and
             c['terminalLifecycle'] is None and c['reservationRetained'] is True and
             all(c[k] for k in ('listenerAlive','controllerAlive','workerAlive','ownUnitBound')) and
             current['runnerOnline'] and current['networkReachable'] and current['protectedMain'] and
             current['queueKnown'] and not any(current[k] for k in
                 ('runnerBusy','actionsInProgress','sourceOwnerBusy','otherActiveJobs',
                  'unknownReservations','guestActive','gpuLeaseActive')),
             'actual source/process-bound renewed-due control; keep ordinary job admission floor')
        raw=canonical({'kind':'ROOT_RESUMED_CONTROL_NATIVE_ACK_NOT_READINESS_V1',
                       'before':strict(canonical(state)),'result':result,'probe':current,
                       'heartbeatPublished':False,'queueMutation':False,'atUnix':time.time()})
        path=ROOT/('resumed-control-'+nonce+'-'+sha(raw)[:16]+'.json')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:write_all(fd,raw);os.fsync(fd)
        finally:os.close(fd)
    else:
        need(result.get('phase')=='RUNNING' and result.get('heartbeatReadbackCurrent') is True and
             result.get('newOrExistingJobRoutable') is True,
             'normal ready result requires actual heartbeat publication and readback')
    state['inflight']=None
    if action!='REFRESH_HEARTBEAT':
        state['completedCycles']+=1
        state['totalCycles']+=1
    state['failureCount']=0
    state['nextAttemptUnix']=int(time.time())+(1 if renewal_due else 60)
    state['lastOutcome']={'action':action,'nonce':nonce,'resultSHA256':sha(outcome['stdout']),
                          'dispatcherNonce':result['dispatcherNonce'],
                          'jobId':result.get('jobId'),'phase':result.get('phase'),
                          **({'originalOutcome':previous_outcome,'heartbeatPublished':False,
                              'nativeAcknowledgement':str(path),'nativeAcknowledgementSHA256':sha(raw)}
                             if renewal_due else {})}
    write_state(state)
    return {'decision':action,'effect':'NORMAL_CONTROL_ONLY',
            'nonce':nonce,'resultSHA256':sha(outcome['stdout']),
            'jobId':result.get('jobId'),'phase':result.get('phase')}

def main():
    need(os.geteuid()==0 and sys.argv==[sys.argv[0]],'Root fixed timer entry; no caller argv')
    check_root_directory()
    policy=validate_policy(strict(held(POLICY,65536)),int(time.time()))
    need(sha(held(Path(__file__),1048576,0,0o444))==policy['recoverySourceSHA256'],
         'exact reviewed recovery source bytes')
    fd=os.open(LOCK,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and
             s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,
             'exact Root recovery lock')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('normal recovery already active')
        state=validate_state(read_state());now=int(time.time())
        try:
            result=run_cycle(policy,state,now)
        except BaseException as first:
            if state['inflight'] is None:
                state['failureCount']+=1
                state['nextAttemptUnix']=now+min(60*2**min(state['failureCount']-1,4),
                                                policy['maxBackoffSeconds'])
                state['lastOutcome']={'firstType':type(first).__name__,
                                      'first':str(first)[:1000],
                                      'preEffect':True}
                try:write_state(state)
                except BaseException as secondary:
                    first.add_note('secondary state failure: '+
                                   type(secondary).__name__+':'+str(secondary)[:300])
                try:alert(first,now)
                except BaseException as secondary:
                    first.add_note('secondary alert failure: '+
                                   type(secondary).__name__+':'+str(secondary)[:300])
            elif (state['lastOutcome'] or {}).get('action')!='REFRESH_HEARTBEAT':
                failure=type(first).__name__+':'+str(first)[:512]
                state['lastOutcome']['firstType']=type(first).__name__
                state['lastOutcome']['first']=str(first)[:512]
                try:write_state(state)
                except BaseException as secondary:
                    first.add_note('secondary ambiguous state custody: '+
                                   type(secondary).__name__+':'+str(secondary)[:300])
                try:
                    escalation={'decision':'HOLD_NORMAL_CYCLE_EXCEPTION',
                                'failure':failure}
                    old=state['lastOutcome'] or {}
                    if old.get('action') in ('GRACEFUL_RENEW','CREATE'):
                        path=orphan_intent_path(orphan_job(state))
                        if path.exists():
                            prior=strict(held(path,65536,0,0o600))
                            need(prior.get('kind')==
                                 'ROOT_RUNNER21_ORPHAN_FINALIZER_INTENT_V1' and
                                 prior.get('priorInflight')==state['inflight'] and
                                 prior.get('oldJobId')==orphan_job(state),
                                 'exception orphan intent identity')
                            escalation.update(decision='HOLD_ORPHAN_FINALIZER_EXCEPTION',
                                orphanNonce=prior['nonce'],oldJobId=prior['oldJobId'])
                    summon_resolver_once(policy,state,escalation,now)
                except BaseException as secondary:
                    first.add_note('secondary local recovery alert: '+
                                   type(secondary).__name__+':'+str(secondary)[:300])
            raise
        if result['decision']=='WAIT_NETWORK':
            state['failureCount']+=1
            state['nextAttemptUnix']=now+min(60*2**min(state['failureCount']-1,4),
                                            policy['maxBackoffSeconds'])
            state['lastOutcome']={'decision':'WAIT_NETWORK','preEffect':True}
            write_state(state)
        if result['decision'] in ('HOLD_NORMAL_CYCLE_OUTCOME','HOLD_INFLIGHT',
                                  'HOLD_HEARTBEAT_ACTION_CHANGED',
                                  'HOLD_ORPHAN_FINALIZER_OUTCOME'):
            route=summon_resolver_once(policy,state,result,now)
            raise RuntimeError('Ambiguous normal control effect; local alert '+
                               route+'; nonce='+state['inflight'])
        print(canonical({'kind':'ROOT_RUNNER21_RECOVERY_TICK_V1','atUnix':now,
                         'runnerId':RUNNER_ID,'mainCommit':policy['mainCommit'],
                         'queueSourceSHA256':policy['queueSourceSHA256'],
                         'result':result,'fullStackAccepted':False}).decode(),end='')
    finally:os.close(fd)

if __name__=='__main__':
    try:main()
    except BaseException as exc:
        print(canonical({'kind':'ROOT_RUNNER21_RECOVERY_REFUSAL_V1',
                         'type':type(exc).__name__,'first':str(exc)[:1000],
                         'runnerId':RUNNER_ID,'fullStackAccepted':False}).decode(),
              file=sys.stderr,end='')
        raise SystemExit(1)

#!/usr/bin/python3
"""One Root-inflight Runner21 action, controller GitHub and pinned OMEN SSH."""
import hashlib,json,os,re,stat,subprocess,sys,time,types
from pathlib import Path
ROOT=Path('/var/lib/opemos-robot-control-r1/auto-recovery')
SSH=Path('/home/connor/Documents/ChatGPT/Handoff troubleshooting/opemos-scheduler/artifacts/ubuntu-vm-migration/migration-ssh-config')
ACTIONS={'CREATE','RESUME_PENDING','RECONCILE_CLOSED','GRACEFUL_RENEW','REFRESH_HEARTBEAT'}
def need(x,msg):
    if not x:raise RuntimeError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def full9(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def held(path,cap,uid,mode):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_uid==uid and a.st_gid==uid and
             a.st_nlink==1 and stat.S_IMODE(a.st_mode)==mode and 0<a.st_size<=cap,
             'held controller cycle input '+str(path))
        raw=bytearray()
        while b:=os.read(fd,65536):
            raw+=b;need(len(raw)<=cap,'bounded controller cycle input')
        need(len(raw)==a.st_size and full9(a)==full9(os.fstat(fd))==
             full9(os.stat(path,follow_symlinks=False)),
             'held/named controller cycle input drift')
        return bytes(raw)
    finally:os.close(fd)
def module(raw,name):
    m=types.ModuleType(name);m.__file__=name
    exec(compile(raw,name,'exec'),m.__dict__);return m
def require_remote_effect(child):
    ok=(child.returncode==0 and child.stderr==b'' and
        len(child.stdout)<=1048576 and child.stdout.count(b'\n')==1)
    if not ok and child.stderr:
        # Existing wrapper capture retains this stream. Preserve the real
        # remote FIRST instead of leaving only a digest after failed CREATE.
        sys.stderr.buffer.write(child.stderr[-65536:]);sys.stderr.buffer.flush()
    need(ok,'finite remote ordinary effect; numeric='+str(child.returncode)+
         '; stderrSHA='+sha(child.stderr))

def run(action,nonce,policy_sha,probe_sha):
    raw=held(ROOT/'policy.json',65536,0,0o400)
    need(sha(raw)==policy_sha,'same exact Root policy passed by wrapper')
    trigger_raw=held(ROOT/'runner21_recovery.py',1048576,0,0o444)
    trigger=module(trigger_raw,'reviewed_wrapper')
    p=trigger.validate_policy(trigger.strict(raw),int(time.time()))
    need(sha(trigger_raw)==p['recoverySourceSHA256'],'exact held wrapper source')
    state=trigger.validate_state(trigger.strict(held(ROOT/'state.json',65536,0,0o600)))
    need(state['inflight']==nonce and time.time()<state['epochExpiresUnix'],
         'exact durable own nonce/current policy epoch')
    cp_raw=held(ROOT/'controller_probe.py',1048576,0,0o444)
    need(sha(cp_raw)==p['controllerProbeSHA256'],'exact held controller probe')
    cp=module(cp_raw,'reviewed_controller_probe')
    initial=cp.observe()
    trigger.validate_probe(initial,p,int(time.time()))
    # The original frame was delivered by the same Root wrapper. This fresh
    # frame is a separate at-use epoch; an action change always refuses.
    local=dict(state);local['inflight']=None
    need(trigger.decision(initial,p,int(time.time()),local)==action,
         'same action changed between wrapper and current at-use observation')
    heartbeat_raw=held(ROOT/'normal_heartbeat.py',1048576,0,0o444)
    need(sha(heartbeat_raw)==p['heartbeatProducerSHA256'],
         'current controller heartbeat source')
    hb=module(heartbeat_raw,'reviewed_current_heartbeat')
    if action!='REFRESH_HEARTBEAT':
        source=held(ROOT/'normal_cycle.py',1048576,0,0o444)
        probe=held(ROOT/'normal_probe.py',1048576,0,0o444)
        config=held(SSH,65536,1000,0o600)
        template=held(ROOT/'normal-template.json',16*1024*1024,0,0o400)
        need(sha(source)==p['normalCycleSHA256'] and
             sha(probe)==p['normalProbeSHA256'] and
             sha(config)==p['sshConfigSHA256'] and
             sha(template)==p['normalTemplateSHA256'],
             'all current held normal remote source/template/SSH')
        github={k:initial[k] for k in ('networkReachable','protectedMain','mainCommit','protectedMainCommit',
            'runnerOnline','runnerBusy','actionsInProgress','actionsQueued',
            'heartbeatCurrent','heartbeatNonce')}
        prefix=('REMOTE_POLICY_RAW='+repr(raw.hex())+'\n'+
                'REMOTE_POLICY='+repr(p)+'\n'+
                'REMOTE_GITHUB='+repr(github)+'\n'+
                'REMOTE_STATE='+repr(state)+'\n'+
                'REMOTE_TEMPLATE_HEX='+repr(template.hex())+'\n'+
                'REMOTE_MODULES='+repr({'normal_probe.py':probe.hex(),
                    'runner21_recovery.py':trigger_raw.hex()})+'\n'+
                'import sys\nsys.argv=["remote-reviewed-cycle","--normal-cycle",'+repr(action)+','+repr(nonce)+','+repr(policy_sha)+','+repr(probe_sha)+']\n').encode()
        wire=prefix+source
        need(len(wire)<=16*1024*1024,'finite authenticated remote action carrier')
        argv=['/usr/sbin/runuser','-u','connor','--','/usr/bin/ssh','-F',str(SSH),'-o','BatchMode=yes',
              '-o','ConnectTimeout=8','opemos-ubuntu-host',
              'sudo -n /usr/bin/python3 -I -B -']
        child=subprocess.run(argv,input=wire,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=650,check=False)
        require_remote_effect(child)
        remote=trigger.strict(child.stdout)
        need(remote.get('kind')=='ROOT_RUNNER21_REMOTE_ACTION_RESULT_V1' and
             remote.get('nonce')==nonce and remote.get('action')==action and
             remote.get('mainCommit')==p['mainCommit'] and
             remote.get('queueSourceSHA256')==p['queueSourceSHA256'] and
             remote.get('vmAdmission') is False and remote.get('ordinaryRoute') is True,
             'exact current remote action receipt')
        job=remote['jobId']
        dispatcher_nonce=remote.get('dispatcherNonce')
        need(dispatcher_nonce==nonce,'same actual ordinary dispatcher operation nonce')
        deadline=time.monotonic()+180
        status_transitions=[]
        while time.monotonic()<deadline:
            try:latest=cp.observe()
            except (cp.IdleRunnerStatusTransition,cp.AssignedRunnerStatusTransition) as transition:
                status_transitions.append({'before':transition.before,'after':transition.after})
                remaining=deadline-time.monotonic()
                need(remaining>0,'original control-readback deadline after idle transition')
                time.sleep(min(3,remaining));continue
            need(time.monotonic()<deadline,'original control-readback deadline after fresh probe')
            c=latest['control']
            if (c['jobId']==job and c['state']=='running' and
                latest['runnerOnline'] and c['listenerAlive'] and
                c['controllerAlive'] and c['workerAlive']):
                break
            time.sleep(3)
        else:raise RuntimeError('new existing Runner21 control not live within bounded current observation; idleTransitions='+json.dumps(status_transitions,sort_keys=True))
    else:
        latest=initial;job=initial['control']['jobId']
        dispatcher_nonce=state['lastOutcome'].get('dispatcherNonce') or job.removeprefix('root-github-robot-control-')
        need(re.fullmatch('[0-9a-f]{32}',dispatcher_nonce),'current normal dispatcher context')
    now=int(time.time())
    trigger.validate_probe(latest,p,now)
    c=latest['control']
    renewal_due=(action=='RESUME_PENDING' and
                 c['leaseExpiresUnix'] is not None and
                 c['leaseExpiresUnix']<=now+p['renewLeadSeconds'])
    if renewal_due:
        need(c['jobId']==job==initial['control']['jobId'] and
             c['leaseExpiresUnix']==initial['control']['leaseExpiresUnix'] and
             now<c['leaseExpiresUnix'] and c['state']=='running' and
             c['terminalLifecycle'] is None and c['reservationRetained'] is True and
             all(c[k] for k in ('listenerAlive','controllerAlive','workerAlive','ownUnitBound')) and
             latest['runnerOnline'] and latest['queueKnown'] and
             latest['networkReachable'] and latest['protectedMain'] and
             not any(latest[k] for k in ('runnerBusy','actionsInProgress','sourceOwnerBusy',
                 'otherActiveJobs','unknownReservations','guestActive','gpuLeaseActive')),
             'native-only resumed control acknowledgement; no work or heartbeat readiness')
        # Keep the exact old finite lease. The next ordinary tick must renew;
        # no heartbeat publication, job token or VM admission is granted here.
    else:
        connected=cp.observe(route_only=True)
        trigger.validate_probe(connected,p,int(time.time()),route_only=True)
        h=hb.state_from_current(hb.join_current_presence(latest,connected),p,now,nonce)
        published=hb.publish_once(h)
        need(published['readbackCurrent'] is True,
             'same nonce current GitHub heartbeat readback')
    return {'kind':'ROOT_RUNNER21_NORMAL_CYCLE_RESULT_V1','nonce':nonce,
            'action':action,'policySHA256':policy_sha,'probeSHA256':probe_sha,
            'queueSourceSHA256':p['queueSourceSHA256'],'mainCommit':p['mainCommit'],
            'ordinaryRoute':True,'sourceAccepted':True,'runtimeAuthorized':True,
            'vmAdmission':False,'jobStartedGuard':True,
            'heartbeatReadbackCurrent':not renewal_due,'newOrExistingJobRoutable':not renewal_due,
            'noDuplicateControllerListenerWorker':True,'jobId':job,'dispatcherNonce':dispatcher_nonce,
            'phase':'RUNNING_RENEWAL_DUE' if renewal_due else 'RUNNING',
            **({'leaseExpiresUnix':c['leaseExpiresUnix']} if renewal_due else {})}

def run_orphan_finalize(nonce,policy_sha,probe_sha,intent_sha):
    """Authenticated controller transport for one existing ordinary queue run."""
    raw=held(ROOT/'policy.json',65536,0,0o400)
    need(sha(raw)==policy_sha,'same exact Root orphan policy')
    trigger_raw=held(ROOT/'runner21_recovery.py',1048576,0,0o444)
    trigger=module(trigger_raw,'reviewed_orphan_wrapper')
    policy=trigger.validate_policy(trigger.strict(raw),int(time.time()))
    need(sha(trigger_raw)==policy['recoverySourceSHA256'],'current wrapper source')
    state=trigger.validate_state(trigger.strict(held(ROOT/'state.json',65536,0,0o600)))
    need(state['inflight'] is not None and state['lastOutcome']['action'] in
         ('GRACEFUL_RENEW','CREATE'),'one retained old control effect')
    old_job=trigger.orphan_job(state)
    intent_path=trigger.orphan_intent_path(old_job)
    intent_raw=held(intent_path,65536,0,0o600)
    need(sha(intent_raw)==intent_sha,'exact create-only orphan intent')
    intent=trigger.strict(intent_raw)
    need(intent['kind']=='ROOT_RUNNER21_ORPHAN_FINALIZER_INTENT_V1' and
         intent['nonce']==nonce and intent['oldJobId']==old_job and
         intent['priorInflight']==state['inflight'] and
         intent['mainCommit']==policy['mainCommit'] and
         intent['queueSourceSHA256']==policy['queueSourceSHA256'] and
         intent['controllerProbeSHA256']==probe_sha,'original nonce/current source intent')
    cp_raw=held(ROOT/'controller_probe.py',1048576,0,0o444)
    need(sha(cp_raw)==policy['controllerProbeSHA256'],'current controller probe')
    cp=module(cp_raw,'reviewed_orphan_controller_probe')
    current=cp.observe();trigger.validate_probe(current,policy,int(time.time()))
    need(current['control']==intent['control'] and current['boot']==intent['boot'] and
         current['workerLockFree'] and not current['runnerOnline'] and
         not any(current[k] for k in ('runnerBusy','actionsInProgress','sourceOwnerBusy',
                'otherActiveJobs','unknownReservations','guestActive','gpuLeaseActive')) and
         current['queueKnown'] and current['hostGraphics']=='INTEL_HOST_NVIDIA_GUEST_ONLY',
         'fresh authenticated controller orphan scope')
    source=held(ROOT/'normal_cycle.py',1048576,0,0o444)
    probe=held(ROOT/'normal_probe.py',1048576,0,0o444)
    config=held(SSH,65536,1000,0o600)
    need(sha(source)==policy['normalCycleSHA256'] and
         sha(probe)==policy['normalProbeSHA256'] and
         sha(config)==policy['sshConfigSHA256'],'pinned normal source/SSH')
    github={k:current[k] for k in ('networkReachable','protectedMain','mainCommit','protectedMainCommit',
        'runnerOnline','runnerBusy','actionsInProgress','actionsQueued',
        'heartbeatCurrent','heartbeatNonce')}
    prefix=('REMOTE_POLICY_RAW='+repr(raw.hex())+'\nREMOTE_POLICY='+repr(policy)+
            '\nREMOTE_GITHUB='+repr(github)+'\nREMOTE_STATE='+repr(state)+
            '\nREMOTE_MODULES='+repr({'normal_probe.py':probe.hex(),
                'runner21_recovery.py':trigger_raw.hex()})+
            '\nORPHAN_INTENT_HEX='+repr(intent_raw.hex())+
            '\nimport sys\nsys.argv=["remote-reviewed-orphan","--orphan-finalize",'+
            repr(nonce)+','+repr(policy_sha)+','+repr(probe_sha)+','+repr(intent_sha)+']\n').encode()
    carrier=prefix+source
    need(len(carrier)<=16*1024*1024,'finite source-pinned orphan carrier')
    argv=['/usr/sbin/runuser','-u','connor','--','/usr/bin/ssh','-F',str(SSH),
          '-o','BatchMode=yes','-o','ConnectTimeout=8','opemos-ubuntu-host',
          'sudo -n /usr/bin/python3 -I -B -']
    child=subprocess.run(argv,input=carrier,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                         timeout=150,check=False)
    need(child.returncode==0 and child.stderr==b'' and
         len(child.stdout)<=1048576 and child.stdout.count(b'\n')==1,
         'one ordinary orphan dispatcher remote outcome; numeric='+str(child.returncode)+
         '; stderrSHA='+sha(child.stderr))
    result=trigger.strict(child.stdout)
    need(result['kind']=='ROOT_RUNNER21_ORPHAN_DISPATCH_V1' and
         result['nonce']==nonce and result['oldJobId']==intent['oldJobId'] and
         result['vmAdmission'] is False and result['canonicalTerminalClaimed'] is False,
         'one source-pinned ordinary dispatcher receipt')
    return {'kind':'ROOT_RUNNER21_ORPHAN_DISPATCH_CONTROLLER_V1',
            'nonce':nonce,'oldJobId':intent['oldJobId'],
            'dispatcherUnit':result['dispatcherUnit'],
            'remoteSHA256':sha(child.stdout),'remote':result,'vmAdmission':False}
def run_presence(policy_sha):
    """Existing trusted metadata path only; no queue/unit/VM lifecycle calls."""
    raw=held(ROOT/'policy.json',65536,0,0o400)
    need(sha(raw)==policy_sha,'same exact Root presence policy')
    recovery=held(ROOT/'runner21_recovery.py',1048576,0,0o444)
    trigger=module(recovery,'reviewed_presence_policy_validator')
    p=trigger.validate_policy(trigger.strict(raw),int(time.time()))
    need(sha(recovery)==p['recoverySourceSHA256'],'exact Root presence validator')
    cp_raw=held(ROOT/'controller_probe.py',1048576,0,0o444)
    hb_raw=held(ROOT/'normal_heartbeat.py',1048576,0,0o444)
    need(sha(cp_raw)==p['controllerProbeSHA256']and sha(hb_raw)==p['heartbeatProducerSHA256'],
         'exact existing presence producer/transport')
    cp=module(cp_raw,'reviewed_current_presence_probe')
    hb=module(hb_raw,'reviewed_current_presence_publisher')
    current=cp.observe(route_only=True);trigger.validate_probe(current,p,int(time.time()),route_only=True)
    job=current['control']['jobId'];prefix='root-github-robot-control-'
    need(type(job)is str and job.startswith(prefix),'actual existing control identity')
    state=hb.state_from_current(current,p,int(time.time()),job[len(prefix):],presence_only=True)
    published=hb.publish_once(state)
    need(published['readbackCurrent']is True,'actual same connected presence readback')
    return {'kind':'ROOT_RUNNER21_PRESENCE_RESULT_V1','policySHA256':policy_sha,
            'connected':True,'ready':False,'busy':current['runnerBusy'],
            'jobId':job,'vmAdmission':False,'readbackCurrent':True}

if __name__=='__main__':
    normal=(len(sys.argv)==6 and sys.argv[1]=='--normal-cycle' and
            sys.argv[2] in ACTIONS and
            re.fullmatch(r'[0-9a-f]{32}',sys.argv[3]) and
            all(re.fullmatch(r'[0-9a-f]{64}',x) for x in sys.argv[4:]))
    orphan=(len(sys.argv)==6 and sys.argv[1]=='--orphan-finalize' and
            re.fullmatch(r'[0-9a-f]{32}',sys.argv[2]) and
            all(re.fullmatch(r'[0-9a-f]{64}',x) for x in sys.argv[3:]))
    presence=(len(sys.argv)==3 and sys.argv[1]=='--publish-presence'and re.fullmatch('[0-9a-f]{64}',sys.argv[2]))
    need(os.geteuid()==0 and (normal or orphan or presence),
         'fixed Root controller normal-cycle/orphan ABI')
    if presence:print(enc(run_presence(sys.argv[2])).decode(),end='')
    elif sys.argv[1]=='--orphan-finalize':
        print(enc(run_orphan_finalize(*sys.argv[2:])).decode(),end='')
    else:print(enc(run(*sys.argv[2:])).decode(),end='')

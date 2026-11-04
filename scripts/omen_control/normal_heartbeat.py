#!/usr/bin/python3
"""Truthful current Runner21 GitHub variable producer; no VM acceptance."""
import hashlib, json, os, stat, subprocess, sys, time, types
from pathlib import Path

ROOT=Path('/var/lib/opemos-robot-control-r1/auto-recovery')
REPO='CorniiDog/OPEMOS.EXE'
VAR='OPEMOS_OMEN_ROBOT_RUNNER_STATE'
GH=['/usr/sbin/runuser','-u','connor','--','/usr/bin/env',
    'XDG_CONFIG_HOME=/home/connor/.config','/usr/bin/gh','api']
LABELS=['self-hosted','Linux','X64','opemos-omen-robot']

def need(ok,msg):
    if not ok:raise RuntimeError(msg)
def enc(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()

def load_probe():
    policy=json.loads((ROOT/'policy.json').read_bytes())
    path=ROOT/'normal_probe.py'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and
             stat.S_IMODE(a.st_mode)==0o444 and a.st_size<=1048576,
             'held reviewed normal probe')
        raw=os.read(fd,1048577)
        named=os.stat(path,follow_symlinks=False)
        need(len(raw)==a.st_size and hashlib.sha256(raw).hexdigest()==
             policy['normalProbeSHA256'] and
             all(getattr(a,k)==getattr(os.fstat(fd),k)==getattr(named,k)
                 for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                           'st_size','st_mtime_ns','st_ctime_ns')),
             'current probe held byte custody')
    finally:os.close(fd)
    module=types.ModuleType('reviewed_current_probe')
    module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module,policy

def gh(method,path,body=None):
    argv=GH+(['--method',method] if method!='GET' else [])+[path]
    if body is not None:argv+=['--input','-']
    result=subprocess.run(argv,input=body,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,timeout=15,check=False)
    need(len(result.stdout)<=1048576 and len(result.stderr)<=65536,
         'bounded GitHub variable exchange')
    return result

def state_from_current(probe,policy,now,nonce):
    need(type(nonce) is str and len(nonce)==32 and
         all(c in '0123456789abcdef' for c in nonce),
         'exact Root in-flight heartbeat nonce')
    control=probe['control']
    need(probe['networkReachable'] is True and
         probe['protectedMain'] is True and
         probe['runnerOnline'] is True and
         control['state']=='running' and
         control['sourceCommit']==policy['mainCommit'] and
         control['queueSourceSHA256']==policy['queueSourceSHA256'] and
         probe['controlBrokerSHA256']==policy['controlBrokerSHA256'] and
         control['listenerAlive'] is True and
         control['controllerAlive'] is True and
         control['workerAlive'] is True and
         control['ownUnitBound'] is True and
         control['leaseExpiresUnix'] is not None and
         control['leaseExpiresUnix']>now+180 and
         not probe['sourceOwnerBusy'] and
         not probe['unknownReservations'],
         'actual current same-source runner/control/listener not jointly proven')
    return {'version':1,'repository':REPO,
            'source_commit':policy['mainCommit'],'checked_at':now,
            'expires_at':now+180,'ready':True,'runner_id':21,
            'queue_source_sha256':policy['queueSourceSHA256'],
            'recovery_nonce':nonce,
            'runner_name':'opemos-omen-robot','labels':LABELS,
            'reason':'installed reviewed controller/listener bound; busy runner and GPU work queue normally; current per-VM admission remains separate'}

def publish_once(state):
    need(state.get('recovery_nonce') and state.get('queue_source_sha256'),
         'same-nonce current source heartbeat only')
    body=json.dumps({'name':VAR,'value':json.dumps(state,separators=(',',':'))},
                    separators=(',',':')).encode()
    path=f'repos/{REPO}/actions/variables/{VAR}'
    desired=json.dumps(state,separators=(',',':'))
    before=gh('GET',path)
    if before.returncode==0 and json.loads(before.stdout).get('value')==desired:
        return {'kind':'ROOT_RUNNER21_CURRENT_HEARTBEAT_RESULT_V1',
                'stateSHA256':hashlib.sha256(enc(state)).hexdigest(),
                'sourceCommit':state['source_commit'],'runnerId':21,
                'recoveryNonce':state['recovery_nonce'],
                'readbackCurrent':True,'fullStackAccepted':False}
    absent=before.returncode!=0 and b'HTTP 404' in before.stderr
    need(before.returncode==0 or absent,'current heartbeat prior readback unavailable')
    try:
        sent=gh('POST' if absent else 'PATCH',
                f'repos/{REPO}/actions/variables' if absent else path,body)
    except (OSError,subprocess.TimeoutExpired):
        # The reply can be lost after the write. Re-read this SAME nonce.
        sent=None
    back=gh('GET',path)
    need(back.returncode==0 and json.loads(back.stdout)['value']==
         desired,
         'heartbeat current readback mismatch')
    return {'kind':'ROOT_RUNNER21_CURRENT_HEARTBEAT_RESULT_V1',
            'stateSHA256':hashlib.sha256(enc(state)).hexdigest(),
            'sourceCommit':state['source_commit'],'runnerId':21,
            'recoveryNonce':state['recovery_nonce'],
            'readbackCurrent':True,'fullStackAccepted':False}

def main():
    need(os.geteuid()==0 and sys.argv==[sys.argv[0],'--publish-current'],
         'fixed Root heartbeat source entry')
    source,policy=load_probe()
    need(source.root_policy()==policy,'current Root policy changed during heartbeat source load')
    probe=source.observe()
    now=int(time.time())
    control=probe['control']
    prefix='root-github-robot-control-'
    job=control.get('jobId','')
    need(type(job) is str and job.startswith(prefix), 'actual canonical control job')
    # This is a fresh observation, not a replay of the old in-flight recovery
    # packet. Existing normal_probe authenticates canonical row/unit/lease and
    # live listener/controller/worker. The existing recovery service can invoke
    # this fixed entry after its normal cycle; no new timer or registration.
    state=state_from_current(probe,policy,now,job[len(prefix):])
    need(source.root_policy()==policy,'policy changed during current observation')
    print(json.dumps(publish_once(state),sort_keys=True,separators=(',',':')))

if __name__=='__main__':main()

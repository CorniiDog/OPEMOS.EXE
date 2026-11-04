"""Controller-side real Runner21 facts; unrelated repo telemetry is optional."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time
import types


def read(ref):
    fd=os.open(ref['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        i={k:getattr(os.fstat(fd),k)for k in ref['identity']};raw=b''
        if i!=ref['identity']or i['st_uid']!=i['st_gid']or i['st_uid']!=0 or not stat.S_ISREG(i['st_mode'])or i['st_mode']&0o022:
            raise RuntimeError('protected installed probe input')
        while b:=os.read(fd,65536):
            raw+=b
            if len(raw)>1048576:raise RuntimeError('probe input cap')
        if len(raw)!=ref['bytes']or hashlib.sha256(raw).hexdigest()!=ref['sha256']or any(i[k]!=getattr(os.fstat(fd),k)or i[k]!=getattr(os.lstat(ref['path']),k)for k in i):
            raise RuntimeError('probe input full9/EOF/hash')
        return raw
    finally:os.close(fd)


def github(p,m):
    runners=m.gh_json('repos/CorniiDog/OPEMOS.EXE/actions/runners?per_page=100')
    active=m.gh_json('repos/CorniiDog/OPEMOS.EXE/actions/runs?status=in_progress&per_page=100')
    selected=[r for r in runners['runners']if r['id']==21]
    if len(selected)!=1 or selected[0]['name']!='opemos-omen-robot' or 'opemos-omen-robot'not in {x['name']for x in selected[0]['labels']}:
        raise RuntimeError('exact existing registered Runner21')
    runner=selected[0]
    if type(runner['busy'])is not bool or runner['status']not in('online','offline'):raise RuntimeError('known runner work state')
    assigned=m.runner21_assigned_jobs(active,m.gh_json)
    # Default-main observations, repo-wide queue and heartbeat are telemetry.
    # Installed controller code/policy identity is authenticated independently.
    main=None;protected=None;queued=None;h={}
    try:
        branch=m.gh_json('repos/CorniiDog/OPEMOS.EXE/branches/main')
        main=branch['commit']['sha'];protected=branch['protected']
    except (OSError,RuntimeError,KeyError,TypeError,subprocess.TimeoutExpired):pass
    try:
        count=m.gh_json('repos/CorniiDog/OPEMOS.EXE/actions/runs?status=queued&per_page=1')['total_count']
        if type(count)is int and count>=0:queued=count
    except (OSError,RuntimeError,KeyError,TypeError,subprocess.TimeoutExpired):pass
    try:h=json.loads(m.gh_json('repos/CorniiDog/OPEMOS.EXE/actions/variables/OPEMOS_OMEN_ROBOT_RUNNER_STATE')['value'])
    except (OSError,RuntimeError,KeyError,TypeError,ValueError,subprocess.TimeoutExpired):pass
    now=time.time();nonce=h.get('recovery_nonce')
    if type(nonce)is not str or re.fullmatch('[0-9a-f]{32}',nonce)is None:nonce=None
    current=(h.get('source_commit')==p['mainCommit']and h.get('queue_source_sha256')==p['queueSourceSHA256']
             and h.get('runner_id')==21 and h.get('ready')is True
             and type(h.get('checked_at'))is int and type(h.get('expires_at'))is int
             and now-180<=h['checked_at']<=now<h['expires_at'])
    return {'networkReachable':True,'protectedMain':protected,'mainCommit':p['mainCommit'],
            'protectedMainCommit':main,'runnerOnline':runner['status']=='online','runnerBusy':runner['busy'],
            'actionsInProgress':assigned,'actionsQueued':queued,'heartbeatCurrent':current,'heartbeatNonce':nonce}


def observe(inputs):
    p=json.loads(read(inputs['policyPin']));ref=inputs['normalProbePin'];source=read(ref)
    if ref['sha256']!=p['normalProbeSHA256']:raise RuntimeError('exact installed normal source')
    m=types.ModuleType('normal_media_github_client');m.__file__=ref['path'];exec(compile(source,ref['path'],'exec'),m.__dict__)
    before=github(p,m)
    remote=['sudo','-n','/usr/bin/python3','-I','-B',inputs['remoteEntryPin']['path'],
            '--profile-pin-json',json.dumps(inputs['remoteProfilePin'],sort_keys=True,separators=(',',':'))]
    argv=inputs['sshArgv']+[shlex.join(remote)]
    result=subprocess.run(argv,input=json.dumps({'github':before},sort_keys=True,separators=(',',':')).encode(),
                          capture_output=True,timeout=25)
    if result.returncode!=0 or result.stderr or len(result.stdout)>1048576:raise RuntimeError('actual readonly normal peer failure: '+result.stderr.decode(errors='replace')[:2048])
    value=json.loads(result.stdout);after=github(p,m)
    for key in('runnerOnline','runnerBusy','actionsInProgress'):
        if before[key]!=after[key]:raise RuntimeError('actual assigned-work transition during probe')
    if value['kind']!='ROOT_RUNNER21_NORMAL_CURRENT_PROBE_V1'or value['effects']!=[]or not 0<=time.time()-value['atUnix']<=15:
        raise RuntimeError('fresh normal source/native observation')
    for key in('runnerManifestSHA256','queueSourceSHA256','queueLoggerSHA256','jobStartedSHA256','jobGuardSHA256',
               'privatePeerSHA256','normalInstallerSHA256','normalQueueEntrySHA256','heartbeatProducerSHA256'):
        if value[key]!=p[key]:raise RuntimeError('actual installed source drift: '+key)
    for key in('runnerOnline','runnerBusy','actionsInProgress','mainCommit'):
        if value[key]!=before[key]:raise RuntimeError('authenticated carrier equality: '+key)
    return value

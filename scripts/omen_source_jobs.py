"""Finite source-workload extension of the existing broker/planner/queue path.

Only immutable A code runs here. The normal Root registry, not a workflow,
chooses the original base, disposable derivative, native admission and fixed
managed-libvirt entry. Missing/unknown inputs fail before queue submission.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import time

from omen_source_workloads import WORKLOADS, subject, selection, verify_result, verify_diagnostics, need, canonical


def current_stage(profile):
    """Load the already-qualified current-A queue helper, NOT candidate stage B.

    This keeps initial guest source checks independent of merging the new GUI/
    image consumer first. Root owns the actual current-A snapshot/profile pins.
    """
    from omen_ci_reader import read_verified, verified_namespace
    ref=profile['source_workloads']['currentStage']
    need(ref['source_commit']==profile['source_workloads']['controller_commit']and
         Path(ref['path']).name=='omen_ci_stage.py'and ref['owner_uid']==os.getuid(),
         'explicit already-adopted current-A queue stage, never B code')
    _,raw=read_verified(ref['path'],1024**2,expected_sha=ref['sha256'],uid=ref['owner_uid'])
    return verified_namespace(raw,ref['path'],'source_current_A_queue_stage')


def root_leaf(stage, path, cap=1024**2, expected=None):
    path=Path(path)
    need(path.is_absolute()and path.is_relative_to('/run')and '..'not in path.parts,
         'fixed transient Root source-result namespace')
    # Current Main A need not already contain the new range reader. This source
    # namespace has its own same protected Root ancestry/FD closure checks.
    held=[];first=None
    try:
        fd=os.open('/run',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);held.append(fd)
        for part in path.parts[2:-1]:
            s=os.fstat(fd);need(s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'Root publication ancestry')
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);held.append(fd)
        s=os.fstat(fd);need(s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'Root publication parent')
        pin,raw=stage['_READER'].read_verified(path,cap,uid=0)
        need(pin['identity']['st_gid']==0 and pin['identity']['st_mode']&0o777==0o444 and
             pin['identity']==stage['_READER'].identity(os.stat(path.name,dir_fd=fd,follow_symlinks=False)),
             'sealed Root source job full9/name')
        need(expected is None or pin==expected,'Root source-result pin drift')
        return stage['strict_json'](raw),pin
    except BaseException as error:first=error;raise
    finally:
        errors=[]
        for fd in reversed(held):
            try:os.close(fd)
            except BaseException as error:errors.append(repr(error))
        if errors:
            if first is not None:first.add_note('Root source publication FD closure UNKNOWN '+repr(errors))
            else:raise ValueError('Root source publication FD closure UNKNOWN '+repr(errors))


def closure(value, request, spec):
    identity={k:request[k]for k in('repository','source_commit','run_id','attempt','nonce')}
    need(value.get('kind')=='ROOT_VERIFIED_OMEN_SOURCE_JOB_CLOSED_V1'and
         value['identity']==identity and value['subject']==spec and
         value['hostBoot']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()and
         type(value['startedUnix'])in(int,float)and value['startedUnix']>=request['consumer_started_epoch']and
         type(value['finishedUnix'])in(int,float)and value['startedUnix']<=value['finishedUnix']<=time.time()and
         time.time()-value['finishedUnix']<=10800,'same actual operation/boot/source/current interval')
    c=value['closure']
    need(c.get('unknown')==[]and all(c.get(k)is True for k in
        ('domainAbsent','originalPIDStartAbsent','cgroupEmpty','ownedFDsClosed','hostUnchanged',
         'observerClosed','controlClosed','mediaUnchanged','originalBaseUnchanged')),
         'actual source VM/process/input/finalizer closure UNKNOWN')
    budget=value['storage']
    limit=80_000_000_000 if WORKLOADS[spec['workload']][0]=='windows'else 60_000_000_000
    need(budget['limitBytes']==limit and budget['earlyLimitBytes']==limit-1_000_000_000 and
         set(budget['observations'])=={'before','during','after'}and
         all(type(x['chargedBytes'])is int and 0<x['chargedBytes']<=limit and x['unknown']==[]
             for x in budget['observations'].values())and
         value['pool']=={'cpus':10,'memoryBytes':34359738368,'swapBytes':0},
         'actual whole dependency union/pool observations, not disk-size only')
    return identity


def collect(stage, prepared, request):
    job=prepared['source_job'];spec=subject(job['subject'],request['source_commit'])
    need(all(spec[k]==v for k,v in request['subject'].items()),'Root source archive belongs to another requested selection')
    cfg=stage['load_pinned'](prepared['config']);rows=stage['queue_status'](cfg)
    need(stage['closed_jobs'](job['job_ids'],rows),'source job not terminal; no synthetic collection')
    for job_id in job['job_ids']:
        life=(rows[job_id].get('result')or{}).get('terminalLifecycle',{})
        group=life.get('postStopCgroupProof',{});pool=life.get('postStopPoolProof',{})
        need(life.get('phase')=='CLOSED'and group.get('completeTraversal')is True and
             group.get('includesUID0')is True and group.get('empty')is True and group.get('processes')==[]and
             pool.get('admitted')is True and pool.get('allOwnedDescriptorsClosed')is True,
             'actual independent canonical publisher/job UID0-inclusive closure, not terminal state alone')
    root,pin=root_leaf(stage,job['result_path'])
    identity=closure(root,request,spec)
    guest,gpin=root_leaf(stage,root['guestResultPin']['path'],expected=root['guestResultPin'])
    success=all(rows[j]['state']=='passed'for j in job['job_ids'])and root.get('first')is None and root.get('secondary')==[]
    if success:verify_result(guest,identity,spec)
    elif guest.get('kind')=='OMEN_GUEST_SOURCE_WORKLOAD_V1':verify_diagnostics(guest,identity,spec)
    # File data is copied only by the broker's existing public exchange. Large
    # package chunks are explicitly typed/bounded, never executable host paths.
    public=root['publicEvidence'];need(type(public)is list and len(public)<=512,'finite source report/package chunks')
    for row in public:
        need(row.get('public')is True and row.get('kind')in
             ('source-result','source-log','source-package-chunk','robot-output','robot-log','robot-report','robot-xunit'),
             'unreviewed/private source export')
        observed,_=stage['_READER'].read_verified(row['path'],16*1024**2,expected_sha=row['sha256'],expected_size=row['size'],uid=0)
        need(observed['identity']==row['identity']and row['identity']['st_gid']==0 and
             row['identity']['st_mode']&0o777==0o444,'Root-owned sealed source export full9')
    again,_=root_leaf(stage,job['result_path'],expected=pin)
    need(again==root,'Root source publication changed during collection')
    return {'identity':identity,'subject':request['subject'],'source_subject':spec,'available':True,'effect':'READ_ONLY_CURRENT_OPERATION',
            'status':'passed'if success else'failed','job_ids':job['job_ids'],'root_result_pin':pin,
            'guest_result_pin':gpin,'source_result':guest,'source_closure':root['closure'],
            'public_evidence':public,'package':root.get('package'),'first':root.get('first'),
            'secondary':root.get('secondary',[])}


def normal_operation(engine, spec):
    """One ordinary submit/collect; no arbitrary argv, repair, retry or new job."""
    selection(spec,engine.context['source_commit'])
    request,prepared,folder=engine.request('source-workload',spec)
    need(prepared.get('available')is True,prepared.get('reason','source workload not admitted'))
    stage=engine.stage;cfg=stage['load_pinned'](prepared['config']);job=prepared['source_job']
    bound=subject(job['subject'],request['source_commit'])
    need(all(bound[k]==v for k,v in spec.items()) and job['identity']=={k:request[k]for k in
         ('repository','source_commit','run_id','attempt','nonce')}and
         job['backend']=='existing-managed-libvirt'and job['hardware_scope']=='virtual-only'and
         job['noNIC']is True,'finite same-operation guest-only job, no GPU/native host workload')
    rows=stage['queue_status'](cfg)
    stage['require_canonical_qualification'](cfg,dict(request,
        stage_sha256=engine.profile['source_workloads']['currentStage']['sha256']),rows)
    stage['load_pinned'](job['admission'])
    manifest=stage['absolute_manifest'](stage['load_pinned'](job['manifest']))
    need([j['id']for j in manifest['jobs']]==job['job_ids']and len(job['job_ids'])==1 and
         not any(j in rows for j in job['job_ids']),'one fresh original source queue job, never rearm')
    actual=manifest['jobs'][0]
    need(actual['command']==job['fixed_controller_command']and
         actual['files']==job['controller_files']and
         job['entrypoint']in actual['command']and spec['candidate_commit']not in actual['command']and
         all(actual.get('approval',{}).get(k)==job['admission'][k]for k in('path','sha256'))and
         'omen-iommu-group-1'not in actual.get('resources',[]),
         'only Root-selected A command/files/admission; B is readonly media data')
    need(not os.path.lexists(job['result_path']),'pre-existing source result refused')
    if spec['workload']=='windows-build':
        seed,_=root_leaf(stage,job['seedProofPath'])
        seed_spec=subject(seed['subject'],request['source_commit'])
        need(seed_spec['workload']=='seed-runtime-source'and all(seed_spec[k]==v for k,v in bound.items()if k!='workload')and
             all(seed['identity'][k]==request[k]for k in('repository','source_commit','run_id','attempt'))and
             seed['first']is None and seed['secondary']==[]and seed['closure']['unknown']==[],
             'exact same-source/archive/parent/attempt completed guest seed, no old cache relabel')
        seed_guest,_=root_leaf(stage,seed['guestResultPin']['path'],expected=seed['guestResultPin'])
        verify_result(seed_guest,seed['identity'],seed_spec)
        need(seed['package']['kind']=='OMEN_SOURCE_PACKAGE_TAR_V1'and
             job['seed_package_sha256']==seed['package']['sha256'],
             'Windows source medium must bind the actual completed seed package, not an unrelated cache')
    # Root profile pins the entire controller command graph, not workflow argv.
    need(actual['command']==engine.profile['source_workloads']['controllerCommandPrefix']+[job['grant_path']],
         'fixed installed source controller prefix')
    for pin in job['controller_pins']:stage['pinned'](pin)
    stage['queue_call'](cfg,'submit',[job['manifest']])
    deadline=min(engine.deadline,time.monotonic()+WORKLOADS[spec['workload']][1])
    while True:
        rows=stage['queue_status'](cfg)
        if stage['closed_jobs'](job['job_ids'],rows):break
        need(time.monotonic()<deadline,'source queue budget exhausted; active closure UNKNOWN, no retry')
        time.sleep(5)
    # Collection is independent of pass/fail, preserving raw failing compiler
    # and cleanup evidence before asserting any required status.
    result=collect(stage,prepared,request)
    raw=canonical(result)+b'\n';path=folder/'source-collected.json'
    with path.open('xb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    return result

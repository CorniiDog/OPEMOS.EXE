"""Finite A build -> B terminal exact-output VM -> C quality metadata joins.

No project command runs here. Root must independently pin/adopt this metadata
verifier in its existing source-job hook before granting any late guest job.
Read-only GitHub token only; no status/check writes or dispatch/wait cycle.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import time

from required_omen import (REPO,ROUTE,NATIVE,PRODUCER_PATH,items,archive_json,
    metadata_download,api_reader,reviewed_controller,candidate_identity,
    candidate_producer_ready,producer_ready,verify_acceptance,canonical,save,require)

QUALITY=('frontend-and-docs','rust','linux-integration','debian-12-package')


def terminal_context(read,download,run_id,attempt):
    """Authenticate completed B and original A even when B failed ordinarily."""
    run=read('actions/runs/'+run_id)
    require(str(run['run_attempt'])==attempt and run['status']=='completed'and
        run['path']==ROUTE and run['name']=='04 SteamOS'and
        run['repository']['full_name']==run['head_repository']['full_name']==REPO and
        run['repository']['id']==run['head_repository']['id']and
        run['head_repository'].get('fork')is False and
        run['event']in('workflow_run','workflow_dispatch'),'exact terminal canonical B/latest attempt')
    branch=read('branches/main');control=branch['commit']['sha']
    execution=reviewed_controller(read,dict(os.environ,GITHUB_REPOSITORY=REPO,GITHUB_SHA=run['head_sha'],
        GITHUB_WORKFLOW_SHA=run['head_sha'],GITHUB_REF='refs/heads/'+run['head_branch'],
        GITHUB_REF_PROTECTED=str(run['head_branch']=='main'and run['head_sha']==control).lower(),
        GITHUB_WORKFLOW_REF=REPO+'/'+ROUTE+'@refs/heads/'+run['head_branch']))
    rows=items(read,'actions/runs/'+run_id+'/artifacts','artifacts')
    rows=[r for r in rows if r['name']=='omen-required-result-'+run_id+'-'+attempt]
    require(len(rows)==1,'one exact terminal B result artifact, never guessed unavailable success')
    artifact=rows[0]
    require(artifact.get('expired')is False and artifact['workflow_run']['id']==int(run_id)and
        artifact['workflow_run']['head_sha']==run['head_sha']and
        artifact['workflow_run']['repository_id']==artifact['workflow_run']['head_repository_id']==run['repository']['id']and
        0<=time.time()-datetime.fromisoformat(artifact['created_at'].replace('Z','+00:00')).timestamp()<=10800,
        'B artifact stale/foreign/expired; original retention unchanged')
    bj=items(read,'actions/runs/'+run_id+'/attempts/'+attempt+'/jobs','jobs')
    final=[j for j in bj if j['name']=='required-platform-result']
    require(len(final)==1 and final[0]['status']=='completed','actual B finalizer must have terminated before C')
    result=archive_json(download('actions/artifacts/'+str(artifact['id'])+'/zip'),artifact,'required-result.json')
    require(result['kind']=='OMEN_REQUIRED_PRODUCER_RESULT_V1'and result['consumer']=={
        'run_id':run_id,'attempt':attempt}and result['status']in('passed','failed'),'exact B result identity/status')
    origin=result.get('quality_source')
    require(type(origin)is dict and origin.get('kind')=='OMEN_BUILD_VM_QUALITY_SOURCE_V1'and
        origin['control_commit']==execution['control_commit']==control and origin['platform']in NATIVE,
        'B lacks authenticated original A identity; precise unavailable, no fabricated candidate')
    platform=origin['platform'];source=origin['source_commit'];roles=origin['source_roles']
    a=read('actions/runs/'+origin['producer_run'])
    require(str(a['run_attempt'])==origin['producer_attempt']and a['status']=='completed'and
        a['head_sha']==source and a['path']==PRODUCER_PATH[platform]and
        a['repository']['full_name']==a['head_repository']['full_name']==REPO and
        a['repository']['id']==a['head_repository']['id']and a['head_repository'].get('fork')is False,
        'original A moved/rerun/foreign/not complete')
    if roles is not None:
        candidate_identity(roles,read)
        if roles.get('source_kind')=='branch':require(a['event']in('push','workflow_dispatch')and
            roles['source_ref']=='refs/heads/'+a['head_branch'],'original A branch event/ref differs')
        else:require(a['event']=='pull_request'and len(a['pull_requests'])==1 and
            a['pull_requests'][0]['number']==roles['pull_request'],'original A PR association differs')
    else:require(source==control and a['head_branch']=='main'and a['event']in('push','workflow_dispatch'),
        'original Main A event/ref identity')
    require(0<=time.time()-datetime.fromisoformat(a['created_at'].replace('Z','+00:00')).timestamp()<=10800,
        'original A interval expired')
    jobs=items(read,'actions/runs/'+origin['producer_run']+'/attempts/'+origin['producer_attempt']+'/jobs','jobs')
    native=[j for j in jobs if j['name']==NATIVE[platform][0]]
    require(len(native)==1 and native[0]['status']=='completed','actual terminal native build job required')
    built=native[0]['conclusion']=='success';producer=None
    if built:
        producer=(producer_ready(control,platform,origin['producer_run'],origin['producer_attempt'],read,download)
            if roles is None else candidate_producer_ready(roles,platform,origin['producer_run'],
                origin['producer_attempt'],read,download)['producer'])
    vm_passed=result['status']=='passed'
    if vm_passed:
        require(built and result['producer']==producer,'B pass must consume exact successful A output')
        verify_acceptance(result['required_acceptance'],producer,
            {'repository':REPO,'source_commit':control,'run_id':run_id,'attempt':attempt},roles)
    else:require(result.get('diagnostic_only')is True,'failed B must remain explicitly diagnostic')
    after={'kind':'OMEN_TERMINAL_VM_BEFORE_QUALITY_V1','controller_run':run_id,'controller_attempt':attempt,
        'artifact_id':str(artifact['id']),'artifact_sha256':artifact['digest'].removeprefix('sha256:'),
        'producer_run':origin['producer_run'],'producer_attempt':origin['producer_attempt'],
        'platform':platform,'source_commit':source,'build_passed':built,'vm_passed':vm_passed,
        'build_artifact':producer}
    require(read('actions/runs/'+run_id)==run and read('actions/runs/'+origin['producer_run'])==a,
        'A/B latest identity changed during late selection')
    return {'after':after,'roles':roles,'control':control,'source':source,
        'tree':read('commits/'+source)['commit']['tree']['sha'],'B':result,'B_run':run}


def event_context(read,download):
    event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes())
    if os.environ['GITHUB_EVENT_NAME']=='workflow_run':
        b=event['workflow_run'];run_id=str(b['id']);attempt=str(b['run_attempt'])
    else:
        require(os.environ['GITHUB_EVENT_NAME']=='workflow_dispatch','only terminal B or exact manual late selection')
        run_id=event['inputs']['controller_run'];attempt=event['inputs']['controller_attempt']
    return terminal_context(read,download,run_id,attempt)


def scope(read,download,parent_run,parent_attempt,workload):
    ctx=event_context(read,download);run=quality_run(read,parent_run,parent_attempt,ctx)
    return context_selection(ctx,run,parent_run,parent_attempt,workload)


def context_selection(ctx,run,parent_run,parent_attempt,workload):
    from omen_source_workloads import selection
    require(workload in QUALITY or workload==ctx['after']['platform']+'-quality','finite matching late workload')
    origin=ctx['roles']or{'repository':REPO,'controller_commit':ctx['control'],'candidate_commit':ctx['source'],
        'base_commit':ctx['control'],'pull_request':0,'repository_id':run['repository']['id'],
        'head_repository_id':run['repository']['id']}
    spec={**origin,'workload':workload,'candidate_tree':ctx['tree'],'parent_run':parent_run,
        'parent_attempt':parent_attempt,'parent_workflow':run['path'],'quality_after':ctx['after']}
    selection(spec,ctx['control']);return spec


def quality_run(read,parent_run,parent_attempt,ctx):
    run=read('actions/runs/'+parent_run)
    require(run['name']=='Checks'and run['path']=='.github/workflows/checks.yml'and
        str(run['run_attempt'])==parent_attempt and run['event']in('workflow_run','workflow_dispatch')and
        run['repository']['full_name']==run['head_repository']['full_name']==REPO and
        run['repository']['id']==run['head_repository']['id']and run['head_repository'].get('fork')is False,
        'exact late C run, not producer/main SHA relabel')
    require(datetime.fromisoformat(run['created_at'].replace('Z','+00:00'))>=
        datetime.fromisoformat(ctx['B_run']['updated_at'].replace('Z','+00:00')),
        'C cannot precede terminal B; no early quality permission')
    return run


def verify_root_late_scope(spec,read,download):
    """Existing Root job hook calls with its authenticated API, not client flags."""
    a=spec['quality_after'];ctx=terminal_context(read,download,a['controller_run'],a['controller_attempt'])
    run=quality_run(read,spec['parent_run'],spec['parent_attempt'],ctx)
    require(spec==context_selection(ctx,run,spec['parent_run'],spec['parent_attempt'],spec['workload']),
        'Root independently checked full late selection differs from client')
    return {'kind':'ROOT_VERIFIED_LATE_QUALITY_SCOPE_V1','selection':spec,'selection_sha256':hashlib.sha256(canonical(spec)).hexdigest(),
        'quality_after':a,'runtimeAuthorized':False}


def aggregate(read,download,ctx,run_id,attempt):
    """Strict A+B+C, no GITHUB_SHA/candidate confusion or new check-write grant."""
    run=quality_run(read,run_id,attempt,ctx)
    jobs=items(read,'actions/runs/'+run_id+'/attempts/'+attempt+'/jobs','jobs')
    expected=(*QUALITY,ctx['after']['platform']+'-quality');outcomes={}
    artifacts=items(read,'actions/runs/'+run_id+'/artifacts','artifacts')
    for name in expected:
        job=[j for j in jobs if j['name']==name]
        require(len(job)==1 and job[0]['status']=='completed','late required job missing/not terminal: '+name)
        pins=[a for a in artifacts if a['name']=='quality-proof-'+name+'-'+run_id+'-'+attempt]
        require(len(pins)==1,'exact small late outcome artifact missing: '+name)
        pin=pins[0]
        require(pin.get('expired')is False and pin['workflow_run']['id']==int(run_id)and
            pin['workflow_run']['head_sha']==run['head_sha']and
            pin['workflow_run']['repository_id']==pin['workflow_run']['head_repository_id']==run['repository']['id'],
            'late outcome artifact expired/foreign')
        proof=archive_json(download('actions/artifacts/'+str(pin['id'])+'/zip'),pin,'quality-outcome.json')
        require(proof.get('kind')=='OMEN_REQUIRED_SOURCE_JOB_V1'and
            proof.get('selection')==context_selection(ctx,run,run_id,attempt,name)and proof['parent_run']==run_id and
            proof['parent_attempt']==attempt,'late proof belongs to another source/A/B/run')
        if proof['status']=='passed':require(proof['closure']['unknown']==[]and
            re.fullmatch('[0-9a-f]{64}',proof['root_result_pin']['sha256']or''),'late source success lacks actual Root closure/receipt')
        outcomes[name]={'status':proof['status'],'job_conclusion':job[0]['conclusion'],'artifact_id':str(pins[0]['id'])}
    reporting=run['head_sha']==ctx['source']
    passed=ctx['after']['build_passed']and ctx['after']['vm_passed']and reporting and all(
        v['status']=='passed'and v['job_conclusion']=='success'for v in outcomes.values())
    return {'kind':'OMEN_BUILD_VM_QUALITY_AGGREGATE_V1','source_commit':ctx['source'],
        'quality_after':ctx['after'],'quality':outcomes,'status':'passed'if passed else'failed',
        'candidate_required_contexts':'same-source'if reporting else'UNAVAILABLE_existing_candidate_status_admission',
        'reason':'No check/status write permission added; controller Main checks are never candidate passes'if not reporting else
                 'Strict A+B+C; a failure is never hidden by later quality success'}


def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=('route','aggregate'));a=p.parse_args()
    read=api_reader(os.environ['GITHUB_TOKEN']);ctx=event_context(read,metadata_download)
    if a.mode=='route':
        save('quality-preflight/context.json',ctx)
        with open(os.environ['GITHUB_OUTPUT'],'a')as out:out.write('platform='+ctx['after']['platform']+'\n')
    else:
        result=aggregate(read,metadata_download,ctx,os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT'])
        save('quality-final/aggregate.json',result);raise SystemExit(0 if result['status']=='passed'else 1)


if __name__=='__main__':
    try:main()
    except Exception as error:
        directory='quality-final'if 'aggregate'in __import__('sys').argv else'quality-preflight'
        try:save(Path(directory)/'unavailable.json',{'kind':'OMEN_BUILD_VM_QUALITY_UNAVAILABLE_V1',
            'status':'failed','actualGUIAccepted':False,'type':type(error).__name__,'reason':str(error)})
        except Exception as secondary:error.add_note('Unavailable evidence persistence: '+repr(secondary))
        raise

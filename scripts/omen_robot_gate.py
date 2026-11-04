#!/usr/bin/env python3
"""Hosted read-only guard. No OMEN credential, code execution or guest admission."""
import json
import os
from pathlib import Path
import time
import urllib.request

REPO='CorniiDog/OPEMOS.EXE'
LABELS=['self-hosted','Linux','X64','opemos-omen-robot']
PRODUCERS={'.github/workflows/windows-portable.yml','.github/workflows/ubuntu-executable.yml','.github/workflows/macos-arm64.yml'}
# Only these fields authorize routing to the ordinary runner admission path.
# Recovery provenance and optional diagnostics may evolve independently.
RUNNER_STATE_FIELDS={'version','repository','source_commit','checked_at',
                     'expires_at','ready','runner_id','runner_name','labels'}

def main():
    # The route is authorized by authenticated event/runner facts below. A
    # report catalog, directory or optional summary cannot authorize or veto it.
    report=Path('robot-preflight')
    value={'status':'failed','vms':{},'executable_acceptance':{p:{'status':'unavailable','reason':'Fresh transaction not executed'}for p in ('windows','ubuntu','macos')}}
    ready=False;source='';stage='canonical repository'
    try:
        assert os.environ['GITHUB_REPOSITORY']==REPO
        stage='complete event metadata'
        event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        name=os.environ['GITHUB_EVENT_NAME']
        if name=='workflow_dispatch':
            stage='dispatch on protected Main ref'
            assert os.environ['GITHUB_REF']=='refs/heads/main'and os.environ['GITHUB_REF_PROTECTED']=='true'
            workflow_source=os.environ['GITHUB_SHA']
        else:
            stage='completed canonical candidate producer event'
            assert name=='workflow_run'
            run=event['workflow_run']
            assert run['path']in PRODUCERS and run['status']=='completed'
            assert run['repository']['full_name']==REPO and run['head_repository']['id']==run['repository']['id']
            assert len(run['head_sha'])==40 and all(x in '0123456789abcdef'for x in run['head_sha'])
            workflow_source=os.environ['GITHUB_SHA']
        stage='current Main GitHub metadata'
        req=urllib.request.Request('https://api.github.com/repos/'+REPO+'/branches/main',headers={'Authorization':'Bearer '+os.environ['GITHUB_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        with urllib.request.urlopen(req,timeout=20)as response:
            raw=response.read(1024**2+1);assert len(raw)<=1024**2;branch=json.loads(raw)
        stage='protected controller workflow identity'
        assert branch['protected']is True
        assert len(workflow_source)==40 and all(x in '0123456789abcdef'for x in workflow_source)
        stage='runner heartbeat JSON/schema'
        state=json.loads(os.environ.get('OPEMOS_OMEN_ROBOT_RUNNER_STATE',''))
        assert type(state)is dict and RUNNER_STATE_FIELDS<=state.keys()
        stage='runner heartbeat repository/source/version'
        assert type(state['version'])is int and state['version']==1 and state['repository']==REPO
        # Installed controller identity is independently checked against the
        # Root lease/bundle before any host operation. It is never the test
        # candidate and need not change when an unrelated Main commit moves.
        source=state['source_commit']
        assert type(source)is str and len(source)==40 and all(x in '0123456789abcdef'for x in source)
        now=int(time.time())
        stage='runner heartbeat clock/180-second freshness'
        assert type(state['checked_at'])is int and type(state['expires_at'])is int and state['expires_at']==state['checked_at']+180 and state['checked_at']<=now<state['expires_at']
        stage='runner exact labels/name/id'
        assert state['labels']==LABELS and state['runner_name']=='opemos-omen-robot'and type(state['runner_id'])is int and state['runner_id']>0
        stage='runner heartbeat explicitly ready=true'
        assert state['ready']is True
        ready=True;value.update(status='ready-for-ordinary-admission',source_commit=source,runner_id=state['runner_id'])
        for row in value['vms'].values():row['reason']='Runner route online; actual VM case remains unverified'
    except Exception as error:
        value['reason']='Trusted route refused at '+stage+': '+type(error).__name__
        value['failed_check']=stage
        for row in value['vms'].values():row['reason']=value['reason']
        print('::error::'+value['reason'])
    finally:
        try:
            rows=json.loads(Path('ci/required-vms.json').read_text())['required_vms']
            value['vms']={r['id']:{'name':r['name'],'status':'unavailable','reason':value.get('reason','Runner route online; actual VM remains unverified')}for r in rows}
            report.mkdir(exist_ok=True)
            (report/'all20.json').write_text(json.dumps(value,indent=2)+'\n')
        except Exception as error:
            print('::warning::Optional runner report unavailable: '+type(error).__name__)
        # GITHUB_OUTPUT carries the actual route to the next job, not a report.
        with open(os.environ['GITHUB_OUTPUT'],'a')as stream:stream.write('ready='+str(ready).lower()+'\nsource='+source+'\n')
        try:
            with open(os.environ['GITHUB_STEP_SUMMARY'],'a')as stream:
                stream.write('Installed controller: `'+source+'`. Candidate execution remains unverified.\n')
                stream.write('No domain, CPU resume, installer or NVIDIA pass is inferred from runner availability.\n')
        except Exception as error:
            print('::warning::Optional step summary unavailable: '+type(error).__name__)
    return 0 if ready else 1

if __name__=='__main__':raise SystemExit(main())

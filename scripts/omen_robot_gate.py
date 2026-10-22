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

def main():
    report=Path('robot-preflight');report.mkdir(exist_ok=True)
    rows=json.loads(Path('ci/required-vms.json').read_text())['required_vms']
    value={'status':'failed','vms':{r['id']:{'name':r['name'],'status':'unavailable','reason':'Runner/event preflight not verified'}for r in rows},'executable_acceptance':{p:{'status':'unavailable','reason':'Fresh transaction not executed'}for p in ('windows','ubuntu','macos')}}
    ready=False;source='';candidate=False;platform='';stage='canonical repository'
    try:
        assert os.environ['GITHUB_REPOSITORY']==REPO
        stage='complete event metadata'
        event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        name=os.environ['GITHUB_EVENT_NAME']
        if name=='workflow_dispatch':
            stage='dispatch on protected Main ref'
            assert os.environ['GITHUB_REF']=='refs/heads/main'and os.environ['GITHUB_REF_PROTECTED']=='true'
            source=os.environ['GITHUB_SHA']
        else:
            stage='completed canonical producer event; trusted controller remains Main'
            assert name=='workflow_run'
            run=event['workflow_run']
            assert run['path']in PRODUCERS and run['status']=='completed'
            assert run['repository']['full_name']==REPO and run['head_repository']['id']==run['repository']['id']
            if run['event']=='pull_request':
                assert run['path']in('.github/workflows/windows-portable.yml','.github/workflows/ubuntu-executable.yml')
                assert type(run['pull_requests'])is list and len(run['pull_requests'])==1
                assert os.environ['GITHUB_REF']=='refs/heads/main'and os.environ['GITHUB_REF_PROTECTED']=='true'
                source=os.environ['GITHUB_SHA'];candidate=True
                platform='windows'if run['path'].endswith('windows-portable.yml')else'ubuntu'
            else:
                assert run['head_branch']=='main'and run['event']in('push','workflow_dispatch')
                source=run['head_sha']
        stage='current Main GitHub metadata'
        req=urllib.request.Request('https://api.github.com/repos/'+REPO+'/branches/main',headers={'Authorization':'Bearer '+os.environ['GITHUB_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        with urllib.request.urlopen(req,timeout=20)as response:
            raw=response.read(1024**2+1);assert len(raw)<=1024**2;branch=json.loads(raw)
        stage='current protected Main source equality'
        assert branch['protected']is True and branch['commit']['sha']==source
        assert len(source)==40 and all(x in '0123456789abcdef'for x in source)
        stage='runner heartbeat JSON/schema'
        state=json.loads(os.environ.get('OPEMOS_OMEN_ROBOT_RUNNER_STATE',''))
        assert set(state)=={'version','repository','source_commit','checked_at','expires_at','ready','runner_id','runner_name','labels','reason'}
        stage='runner heartbeat repository/source/version'
        assert state['version']==1 and state['repository']==REPO and state['source_commit']==source
        now=int(time.time())
        stage='runner heartbeat clock/180-second freshness'
        assert type(state['checked_at'])is int and state['expires_at']==state['checked_at']+180 and state['checked_at']<=now<state['expires_at']
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
        (report/'all20.json').write_text(json.dumps(value,indent=2)+'\n')
        with open(os.environ['GITHUB_OUTPUT'],'a')as stream:stream.write('ready='+str(ready).lower()+'\nsource='+source+'\ncandidate='+str(candidate).lower()+'\nplatform='+platform+'\n')
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a')as stream:
            stream.write('| Required VM | Result |\n|---|---|\n')
            for row in value['vms'].values():stream.write('| '+row['name']+' | unavailable until actual Robot transaction |\n')
            stream.write('\nNo VM, GUI, SteamOS or NVIDIA pass is inferred from runner availability.\n')
    return 0 if ready else 1

if __name__=='__main__':raise SystemExit(main())

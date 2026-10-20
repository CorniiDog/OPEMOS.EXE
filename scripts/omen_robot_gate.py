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
    ready=False;source=''
    try:
        assert os.environ['GITHUB_REPOSITORY']==REPO
        event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        name=os.environ['GITHUB_EVENT_NAME']
        if name=='workflow_dispatch':
            assert os.environ['GITHUB_REF']=='refs/heads/main'and os.environ['GITHUB_REF_PROTECTED']=='true'
            source=os.environ['GITHUB_SHA']
        else:
            assert name=='workflow_run'
            run=event['workflow_run']
            assert run['path']in PRODUCERS and run['status']=='completed'and run['head_branch']=='main'
            assert run['repository']['full_name']==REPO and run['head_repository']['id']==run['repository']['id']
            source=run['head_sha']
        req=urllib.request.Request('https://api.github.com/repos/'+REPO+'/branches/main',headers={'Authorization':'Bearer '+os.environ['GITHUB_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        with urllib.request.urlopen(req,timeout=20)as response:
            raw=response.read(1024**2+1);assert len(raw)<=1024**2;branch=json.loads(raw)
        assert branch['protected']is True and branch['commit']['sha']==source
        assert len(source)==40 and all(x in '0123456789abcdef'for x in source)
        state=json.loads(os.environ.get('OPEMOS_OMEN_ROBOT_RUNNER_STATE',''))
        assert set(state)=={'version','repository','source_commit','checked_at','expires_at','ready','runner_id','runner_name','labels','reason'}
        assert state['version']==1 and state['repository']==REPO and state['source_commit']==source
        now=int(time.time())
        assert type(state['checked_at'])is int and state['expires_at']==state['checked_at']+180 and state['checked_at']<=now<state['expires_at']
        assert state['labels']==LABELS and state['runner_name']=='opemos-omen-robot'and type(state['runner_id'])is int and state['runner_id']>0 and state['ready']is True
        ready=True;value.update(status='ready-for-ordinary-admission',source_commit=source,runner_id=state['runner_id'])
        for row in value['vms'].values():row['reason']='Runner route online; actual VM case remains unverified'
    except Exception as error:
        value['reason']='Trusted event/current protected Main/fresh runner heartbeat not verified: '+type(error).__name__
        print('::error::'+value['reason'])
    finally:
        (report/'all20.json').write_text(json.dumps(value,indent=2)+'\n')
        with open(os.environ['GITHUB_OUTPUT'],'a')as stream:stream.write('ready='+str(ready).lower()+'\nsource='+source+'\n')
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a')as stream:
            stream.write('| Required VM | Result |\n|---|---|\n')
            for row in value['vms'].values():stream.write('| '+row['name']+' | unavailable until actual Robot transaction |\n')
            stream.write('\nNo VM, GUI, SteamOS or NVIDIA pass is inferred from runner availability.\n')
    return 0 if ready else 1

if __name__=='__main__':raise SystemExit(main())

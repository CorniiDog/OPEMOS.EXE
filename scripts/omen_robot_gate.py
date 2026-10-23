#!/usr/bin/env python3
"""Hosted read-only guard. No OMEN credential, code execution or guest admission."""
import json
import os
from pathlib import Path
import time
import urllib.request
import base64
import hashlib
import re

REPO='CorniiDog/OPEMOS.EXE'
LABELS=['self-hosted','Linux','X64','opemos-omen-robot']
PRODUCERS={'.github/workflows/windows-portable.yml','.github/workflows/ubuntu-executable.yml','.github/workflows/macos-arm64.yml'}


def controller_selection(read,env=None):
    """Metadata scope only; Root's actual kernel/job guard remains mandatory.

    A current control checkpoint is not a claim that new reviewed implementation
    bytes exist in Main. The optional qualification uses the EXISTING Root
    heartbeat/independent review channel, never a candidate-supplied flag.
    """
    env=os.environ if env is None else env
    def need(value,reason):
        if not value:raise ValueError(reason)
    need(env['GITHUB_REPOSITORY']==REPO,'canonical controller repository')
    main=read('branches/main');checkpoint=main['commit']['sha'];code=env['GITHUB_SHA']
    workflow=env.get('GITHUB_WORKFLOW_REF',REPO+'/.github/workflows/omen-robot.yml@refs/heads/main')
    need(main['protected']is True and re.fullmatch('[0-9a-f]{40}',code)and
         env.get('GITHUB_WORKFLOW_SHA',code)==code,'exact controller workflow implementation identity')
    if code==checkpoint and env['GITHUB_REF']=='refs/heads/main'and env['GITHUB_REF_PROTECTED']=='true':
        return {'control_commit':checkpoint,'implementation_commit':code,'workflow_ref':workflow,'qualification':None}
    state=json.loads(env.get('OPEMOS_OMEN_ROBOT_RUNNER_STATE','{}'));q=state.get('controller_qualification',{})
    need(set(q)=={'kind','control_commit','implementation_commit','workflow_ref','workflow_sha256',
                  'source_graph_sha256','review_receipt_sha256'}and q['kind']=='ROOT_REVIEWED_TEST_CONTROLLER_V1'and
         q['control_commit']==state.get('source_commit')==checkpoint and q['implementation_commit']==code and
         q['workflow_ref']==workflow and workflow==REPO+'/.github/workflows/omen-robot.yml@'+env['GITHUB_REF']and
         all(re.fullmatch('[0-9a-f]{64}',q[k]or'')for k in('workflow_sha256','source_graph_sha256','review_receipt_sha256')),
         'exact independent Root-reviewed controller implementation/graph qualification absent; branch name is not authority')
    need(type(state.get('checked_at'))is int and state.get('expires_at')==state['checked_at']+180 and
         state['checked_at']<=time.time()<state['expires_at'],'current original controller qualification interval')
    blob=read('contents/.github/workflows/omen-robot.yml?ref='+code)
    need(blob.get('encoding')=='base64'and blob.get('size',0)<=131072,'finite exact controller workflow blob')
    raw=base64.b64decode(blob['content'],validate=False)
    need(len(raw)==blob['size']and hashlib.sha256(raw).hexdigest()==q['workflow_sha256'],
         'actual workflow bytes differ from Root-reviewed safe implementation')
    return {'control_commit':checkpoint,'implementation_commit':code,'workflow_ref':workflow,'qualification':q}

def main():
    report=Path('robot-preflight');report.mkdir(exist_ok=True)
    rows=json.loads(Path('ci/required-vms.json').read_text())['required_vms']
    value={'status':'failed','vms':{r['id']:{'name':r['name'],'status':'unavailable','reason':'Runner/event preflight not verified'}for r in rows},'executable_acceptance':{p:{'status':'unavailable','reason':'Fresh transaction not executed'}for p in ('windows','ubuntu','macos')}}
    ready=False;source='';candidate=False;platform='';stage='canonical repository';execution={}
    try:
        assert os.environ['GITHUB_REPOSITORY']==REPO
        stage='complete event metadata'
        event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        name=os.environ['GITHUB_EVENT_NAME']
        if name=='workflow_dispatch':
            stage='dispatch on exact independently reviewed controller'
        else:
            stage='completed canonical producer event; trusted controller remains Main'
            assert name=='workflow_run'
            run=event['workflow_run']
            assert run['path']in PRODUCERS and run['status']=='completed'
            platform={'.github/workflows/windows-portable.yml':'windows','.github/workflows/ubuntu-executable.yml':'ubuntu',
                      '.github/workflows/macos-arm64.yml':'macos'}[run['path']]
            assert run['repository']['full_name']==REPO and run['head_repository']['id']==run['repository']['id']
            assert run['event']in('push','workflow_dispatch','pull_request')
            assert run['head_repository']['full_name']==REPO and run['head_repository'].get('fork')is False
            candidate=True
            platform={'.github/workflows/windows-portable.yml':'windows','.github/workflows/ubuntu-executable.yml':'ubuntu',
                      '.github/workflows/macos-arm64.yml':'macos'}[run['path']]
            if run['event']=='pull_request':
                assert type(run['pull_requests'])is list and len(run['pull_requests'])==1
        stage='current Main GitHub metadata'
        req=urllib.request.Request('https://api.github.com/repos/'+REPO+'/branches/main',headers={'Authorization':'Bearer '+os.environ['GITHUB_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args):return None
        opener=urllib.request.build_opener(NoRedirect)
        with opener.open(req,timeout=20)as response:
            raw=response.read(1024**2+1);assert len(raw)<=1024**2;branch=json.loads(raw)
        stage='current protected Main source equality'
        def read_controller(path):
            if path=='branches/main':return branch
            req=urllib.request.Request('https://api.github.com/repos/'+REPO+'/'+path,headers={'Authorization':'Bearer '+os.environ['GITHUB_TOKEN'],'Accept':'application/vnd.github+json'})
            with opener.open(req,timeout=20)as response:
                raw=response.read(1048577);assert len(raw)<=1048576;return json.loads(raw)
        execution=controller_selection(read_controller);source=execution['control_commit']
        assert len(source)==40 and all(x in '0123456789abcdef'for x in source)
        stage='runner heartbeat JSON/schema'
        state=json.loads(os.environ.get('OPEMOS_OMEN_ROBOT_RUNNER_STATE',''))
        fields={'version','repository','source_commit','checked_at','expires_at','ready','runner_id','runner_name','labels','reason'}
        assert set(state)in(fields,fields|{'controller_qualification'})
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
        value['reason']='Trusted route refused at '+stage+': '+type(error).__name__+(
            ': '+str(error)[:512]if isinstance(error,ValueError)else'')
        value['failed_check']=stage
        for row in value['vms'].values():row['reason']=value['reason']
        print('::error::'+value['reason'])
        failure={'kind':'OMEN_CONTROLLER_PREFLIGHT_FAILURE_V1','stage':stage,'reason':value['reason'],
            'error_type':type(error).__name__,'consumer':{'run_id':os.environ.get('GITHUB_RUN_ID'),
                'attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),'implementation_commit':os.environ.get('GITHUB_SHA')},
            'actualGUIAccepted':False,'diagnostic_only':True}
        with (report/'scope-failure.json').open('x')as out:json.dump(failure,out,sort_keys=True)
    finally:
        (report/'all20.json').write_text(json.dumps(value,indent=2)+'\n')
        with open(os.environ['GITHUB_OUTPUT'],'a')as stream:stream.write('ready='+str(ready).lower()+'\nsource='+source+'\nimplementation='+execution.get('implementation_commit','')+'\ncandidate='+str(candidate).lower()+'\nplatform='+platform+'\n')
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a')as stream:
            stream.write('| Required VM | Result |\n|---|---|\n')
            for row in value['vms'].values():stream.write('| '+row['name']+' | unavailable until actual Robot transaction |\n')
            stream.write('\nNo VM, GUI, SteamOS or NVIDIA pass is inferred from runner availability.\n')
    return 0 if ready else 1

if __name__=='__main__':raise SystemExit(main())

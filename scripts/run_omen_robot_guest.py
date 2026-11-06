#!/usr/bin/env python3
"""Installed ordinary queue job step, executed ONLY in its admitted case lane."""
import hashlib
import json
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0,str(Path(__file__).parent))
from omen_robot import raw_file,strict,require,dump,FULL9,identity


def normal_ubuntu_job(config_ref,request_ref):
    """Existing Robot entry also owns the full normal GUI job's result join.

    The job executes this same entry for each actual mouse operation. This
    outer adapter aggregates only those produced reports after native closure.
    """
    import time,types,stat,re
    cfg=strict(raw_file(config_ref['path'],1048576,config_ref['sha256'],os.getuid()))
    request=strict(raw_file(request_ref['path'],1048576,request_ref['sha256'],os.getuid()))
    current={k:request[k]for k in('source_commit','run_id','attempt')}
    require(all(identity()[k]==v for k,v in current.items())and
        request['nonce']==os.environ['OPEMOS_TRANSACTION_NONCE']==cfg['nonce']and
        cfg['source_commit']==request['source_commit'],'actual current normal queue consumer identity')
    ref=cfg['normalPolicyPin'];path=Path(ref['path'])
    require(path.parent.parent==Path('/var/lib/opemos-robot-control-r1/releases')and
        re.fullmatch('[0-9a-f]{32}',path.parent.name)and path.name=='fixed-policy.json',
        'same Root normal deployment policy')
    for parent in(path.parent,*path.parent.parents):
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0
            and not s.st_mode&0o022,'Root normal deployment ancestry')
    policy=strict(raw_file(path,1048576,ref['sha256'],0))
    require(policy['kind']=='ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1'and
        policy['sourceCommit']==cfg['source_commit']and policy['network']=='none'and
        policy['swapBytes']==0 and 0<cfg['whole_seconds']<=policy['wholeSeconds']<=7200,
        'exact explicit normal Ubuntu source/effects boundary')
    bundle=path.parent/'proof-sources';programs={}
    for name,digest in policy['programSHA256'].items():
        require(name.endswith('.py')and Path(name).name==name,'fixed Root normal program member')
        programs[name]=raw_file(bundle/name,1048576,digest,0)
    require(set(programs)=={'run_approved.py','job.py','provision_observer_rule.py','connection_control.py',
        'observer_guest.py','prepare_observer_iso.py','virtual_usb.py','vm_write_ceiling.py','owned_command.py'},
        'complete authenticated normal job source graph')
    source=programs['owned_command.py'];owned=types.ModuleType('actual_normal_owned')
    owned.__file__=str(bundle/'owned_command.py');exec(compile(source,owned.__file__,'exec'),owned.__dict__)
    root=Path(config_ref['path']).parent
    require(root.parent==Path(policy['operationRoot'])and root.name.endswith('-'+cfg['nonce'])and
        root.resolve()==root and root.stat().st_uid==os.getuid()and stat.S_IMODE(root.stat().st_mode)==0o700,
        'same ordinary planned operation root')
    target=root/'robot-result.json';require(not os.path.lexists(target),'old normal Robot result refused before execution')
    first=None;native=None;actual=None
    try:
        native=owned.run_owned_command(['/usr/bin/sudo','-n','/usr/bin/python3','-I','-B',str(bundle/'run_approved.py'),
            '--owned-storage',json.dumps(config_ref,sort_keys=True,separators=(',',':'))],
            None,cfg['whole_seconds']+300,[root/'normal-job.stdout',root/'normal-job.stderr'],stream_limit=4194304)
        dump(root/'normal-job-native.json',native)
        require(native['numericExit']==0 and native['lifecycleClosed']is True and native['errors']==[],
            'actual normal Ubuntu job failed or child closure unknown; raw/native retained')
        runtime=root/'runtime'
        actual=strict(raw_file(runtime/'job-result.json',16*1024**2,owner=os.getuid()))
        storage=strict(raw_file(root/'storage-result.json',16*1024**2,owner=os.getuid()))
        require(storage['first']is None and storage['closure']['unmountedNormally']is True and
            storage['closure']['loopDetachedNormally']is True and storage['closure']['errors']==[],
            'actual independent Root storage/loop/namespace closure required')
        require(actual['nonce']==cfg['nonce']and actual['source_commit']==cfg['source_commit']and
            actual['candidate_source_commit']==cfg['candidate']['descriptor']['source_commit']and
            actual['GUIBuildWriteReadbackAccepted']is True,'actual same normal Build/write/readback and closure required')
        dump(root/'runtime-observed.json',actual)
        gui=actual['GUI']['normalRobotEvidence'];reports=gui['robot_reports']
        require(set(gui['pointer_actions'])=={'chooser-open','chooser-confirm-exact-input','Build',
            'virtualUSB-select-and-review','virtualUSB-Write-confirmation'}and len(reports)==5,
            'complete five real ordinary Robot pointer executions')
        public=[]
        for row in reports:
            require(row['numeric_exit']==0 and row['tests_failed']==0 and row['tests_passed']==1
                and row['actual_pointer_calls']==1 and all(row['identity'][k]==request[k]
                for k in('source_commit','run_id','attempt','nonce')),
                'actual per-action Robot identities/counts/exit differ')
            for report in row['reports']:
                raw=raw_file(report['path'],16*1024**2,report['sha256'],os.getuid());s=Path(report['path']).lstat()
                require(len(raw)==report['size']and {k:getattr(s,k)for k in FULL9}==report['identity'],
                    'actual per-action report full9/hash custody')
                public.append(report)
        suite=Path(__file__).parents[1]/'tests/robot/guest.robot'
        dump(target,{'identity':request,'numeric_exit':0,'tests_failed':0,'tests_passed':5,
            'actual_pointer_calls':5,'reports':public,'suite_sha256':hashlib.sha256(raw_file(suite)).hexdigest(),
            'actual_normal_job_path':str(runtime/'job-result.json'),
            'fullStackAccepted':False,'SteamOSOrNVIDIAAcceptance':False})
        return 0
    except BaseException as error:
        first={'type':type(error).__name__,'reason':str(error)}
        dump(root/'normal-job-FIRST.json',{'first':first,'native':native,'actual':actual,
            'fullStackAccepted':False,'SteamOSOrNVIDIAAcceptance':False})
        raise


def main():
    if len(sys.argv)==4 and sys.argv[1]=='--normal-ubuntu-job':
        return normal_ubuntu_job(strict(sys.argv[2].encode()),strict(sys.argv[3].encode()))
    import robot
    require(len(sys.argv)==5,'Usage: identity.json identity-sha suite output-directory')
    request=strict(raw_file(sys.argv[1],1048576,sys.argv[2],os.getuid()))
    output=Path(sys.argv[4]);require(output.is_absolute()and output.parent.resolve()==output.parent and not os.path.lexists(output),'Fresh exact owned Robot output required')
    output.mkdir(mode=0o700)
    suite=Path(sys.argv[3]);require(suite.name in ('guest.robot','role.robot'),'Only installed reviewed case suites')
    for key,value in request.items():
        if key in ('run_id','attempt'):require(os.environ[{'run_id':'GITHUB_RUN_ID','attempt':'GITHUB_RUN_ATTEMPT'}[key]]==value,'Consumer identity mismatch')
    require(os.environ['OPEMOS_SOURCE_SHA']==request['source_commit']and os.environ['OPEMOS_TRANSACTION_NONCE']==request['nonce'],'Stale guest job source/nonce')
    code=robot.run(str(suite),outputdir=str(output),output='output.xml',report='report.html',log='log.html',xunit='xunit.xml')
    reports=[];raw=raw_file(output/'output.xml',16*1024**2,owner=os.getuid());tree=ET.fromstring(raw)
    statuses=[test.find('status').attrib['status']for test in tree.findall('.//test')]
    clicks=sum(kw.attrib.get('name')=='Click Observed Native Control'and kw.find('status')is not None and kw.find('status').attrib['status']=='PASS'for kw in tree.findall('.//kw'))
    for name,kind in [('output.xml','robot-output'),('report.html','robot-report'),('log.html','robot-log'),('xunit.xml','robot-xunit')]:
        path=output/name;data=raw_file(path,16*1024**2,owner=os.getuid());info=path.lstat()
        reports.append({'path':str(path),'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'identity':{k:getattr(info,k)for k in FULL9},'kind':kind,'public':True})
    dump(output/'result.json',{'identity':request,'numeric_exit':code,'tests_failed':sum(x!='PASS'for x in statuses),'tests_passed':statuses.count('PASS'),'actual_pointer_calls':clicks,'reports':reports,'suite_sha256':hashlib.sha256(raw_file(suite)).hexdigest()})
    return code

if __name__=='__main__':raise SystemExit(main())

"""Fixed Root-installed A source client for ordinary OMEN required jobs.

No candidate checkout or project command on the runner. Root's existing job
hook must authenticate the exact workflow bytes and bind the ephemeral token
before this finite client is usable. That adoption is separate from source.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import xml.etree.ElementTree as ET
from urllib import request
from omen_source_workloads import REPO, WORKLOADS, PARENT_WORKLOADS, selection, need, canonical, diagnostic_binding

ROOT_CLIENT='/var/lib/opemos-robot-control-r1/source/scripts/omen_source_ci.py'
FULL9=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
PARENT_NAMES={'.github/workflows/checks.yml':'Checks','.github/workflows/windows-portable.yml':'01 Windows EXE',
              '.github/workflows/ubuntu-executable.yml':'02 Ubuntu AppImage','.github/workflows/macos-arm64.yml':'03 macOS Executable'}


def held(path,cap,sha=None,owner=0):
    path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        s=os.fstat(fd);sig=lambda m:tuple(getattr(m,k)for k in FULL9)
        need(stat.S_ISREG(s.st_mode)and s.st_uid==owner and s.st_nlink==1 and not s.st_mode&0o022 and s.st_size<=cap,
             'owned sealed fixed A input')
        raw=bytearray()
        while block:=os.read(fd,min(65536,cap+1-len(raw))):
            raw.extend(block);need(len(raw)<=cap,'fixed A input overflow')
        need(len(raw)==s.st_size and sig(s)==sig(os.fstat(fd))==sig(path.lstat())and
             (sha is None or hashlib.sha256(raw).hexdigest()==sha),'held fixed A full9/hash/EOF')
        return bytes(raw)
    finally:os.close(fd)


def strict(raw):
    def pairs(rows):
        obj={}
        for k,v in rows:need(k not in obj,'duplicate source metadata');obj[k]=v
        return obj
    need(len(raw)<=2*1024**2,'finite source metadata')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite metadata'))


def save(path,value):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    raw=canonical(value)+b'\n';need(len(raw)<=1024**2,'complete bounded source proof')
    with path.open('xb')as out:out.write(raw);out.flush();os.fsync(out.fileno())


def api(path):
    need(path in('','branches/main','pulls?state=open&per_page=100')or
         re.fullmatch(r'(?:pulls|commits)/[A-Za-z0-9]+',path)or
         re.fullmatch(r'git/ref/heads/[A-Za-z0-9_][A-Za-z0-9_./-]{0,239}',path)or
         re.fullmatch(r'actions/runs/[1-9][0-9]*(?:/attempts/[1-9][0-9]*(?:/jobs)?|/artifacts)?(?:\?per_page=100)?',path),
         'finite official source metadata path')
    class NoRedirect(request.HTTPRedirectHandler):
        def redirect_request(self,*args):return None
    headers={'Accept':'application/vnd.github+json','Authorization':'Bearer '+os.environ['GITHUB_TOKEN'],
             'X-GitHub-Api-Version':'2022-11-28'}
    with request.build_opener(NoRedirect).open(request.Request(
        'https://api.github.com/repos/'+REPO+('/'+path if path else''),headers=headers),timeout=20)as response:
        return strict(response.read(2*1024**2+1))


def scope(parent_run,parent_attempt,workload):
    run=api('actions/runs/'+parent_run);repo=api('');branch=api('branches/main');main=branch['commit']['sha']
    need(branch['protected']is True and run['repository']['full_name']==REPO and
         run['head_repository']['id']==repo['id']and run['head_repository']['full_name']==REPO and
         run['head_repository'].get('fork')is False and str(run['run_attempt'])==parent_attempt and
         run['path']in PARENT_WORKLOADS and workload in PARENT_WORKLOADS[run['path']]and
         run['name']==PARENT_NAMES[run['path']]and run['event']in('push','pull_request','workflow_dispatch'),
         'actual same-repository original source job/latest attempt; no fork privilege')
    source=run['head_sha'];number=0;extra={}
    if run['event']=='pull_request':
        prs=run['pull_requests'];need(type(prs)is list and len(prs)==1,'one original PR event association')
        pr=api('pulls/'+str(prs[0]['number']));number=pr['number']
        need(pr['state']=='open'and pr['head']['sha']==source and pr['head']['repo']['id']==pr['base']['repo']['id']==repo['id']and
             pr['head']['repo']['full_name']==pr['base']['repo']['full_name']==REPO and
             pr['base']['sha']==main and pr['base']['ref']=='main','unchanged PR head/current base')
    elif run['head_branch']!='main':
        ref='refs/heads/'+run['head_branch'];current=api('git/ref/'+ref[5:])
        need(current['ref']==ref and current['object']['type']=='commit'and current['object']['sha']==source,
             'ordinary exact branch moved/deleted; no guessed PR association')
        extra={'source_kind':'branch','source_ref':ref}
    else:need(source==main,'stale Main source')
    tree=api('commits/'+source)['commit']['tree']['sha']
    workflow=os.environ['GITHUB_WORKFLOW_SHA'];original_ref=os.environ['GITHUB_REF']
    need(os.environ['GITHUB_EVENT_NAME']==run['event']and
         workflow==(pr['merge_commit_sha']if run['event']=='pull_request'else source),
         'original workflow SHA is separate from PR head B; event/ref must not be rewritten')
    spec={'repository':REPO,'controller_commit':main,'candidate_commit':source,'base_commit':main,
          'pull_request':number,'repository_id':repo['id'],'head_repository_id':run['head_repository']['id'],
          'candidate_tree':tree,'workload':workload,'parent_run':parent_run,'parent_attempt':parent_attempt,
          'parent_workflow':run['path'],'producer_event':run['event'],'producer_ref':original_ref,
          'workflow_commit':workflow,**extra}
    selection(spec,main)
    created=datetime.fromisoformat(run['created_at'].replace('Z','+00:00')).timestamp()
    need(0<=time.time()-created<=10800,'original parent interval expired')
    return spec


def installed(spec):
    need(str(Path(__file__).absolute())==ROOT_CLIENT,'only fixed A source client, no branch/PR host script')
    for parent in Path(__file__).absolute().parents:
        s=parent.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,
                             'fixed Root A source ancestry')
    p=strict(held(Path.home()/'.config/opemos-ci/robot.json',1024**2))
    cfg=p['source_workloads']
    need(cfg['enabled']is True and cfg['schema']=='FINITE_VM_ONLY_V1'and
         cfg['controller_commit']==spec['controller_commit']and cfg['no_candidate_host_code']is True,
         'current Root-adopted source vocabulary absent/disabled; no alternate client')
    for relative,pin in cfg['clientSourcePins'].items():
        need(not Path(relative).is_absolute()and '..'not in Path(relative).parts,'fixed A relative source graph')
        held(Path(__file__).parents[1]/relative,8*1024**2,pin)
    need({'scripts/omen_source_ci.py','scripts/omen_source_workloads.py','scripts/robot_client.py',
          'scripts/record_executable_artifact.py','scripts/omen_ci_executables.py','ci/required-vms.json'}<=
          set(cfg['clientSourcePins']),'complete client dependency graph, not just self pin')
    # The installed hook must have already checked the exact workflow blob,
    # caller namespace/UID/birth/cgroup and one-use token. This is a checked
    # supplemental field, never a replacement for kernel/broker authentication.
    need(os.environ.get('OPEMOS_SOURCE_JOB_SCOPE')=='ROOT_ATTESTED_FIXED_A_GUEST_WORKLOAD'and
         os.environ.get('OPEMOS_SOURCE_SHA',spec['controller_commit'])==spec['controller_commit'],
         'source-specific fixed job guard not admitted')
    os.environ['OPEMOS_SOURCE_SHA']=spec['controller_commit']
    return p


def unpack_tar(archive,root,expected_bytes,expected_sha):
    import tarfile
    need(archive.stat().st_size==expected_bytes,'complete immutable guest package tar size')
    h=hashlib.sha256()
    with archive.open('rb')as source:
        while block:=source.read(1024**2):h.update(block)
    need(h.hexdigest()==expected_sha,'complete immutable guest package tar SHA')
    root.mkdir(mode=0o700);seen=set();total=0
    with tarfile.open(archive,mode='r:')as source:
        for entry in source:
            relative=Path(entry.name)
            need(entry.isfile()and not entry.issparse()and not relative.is_absolute()and
                 '..'not in relative.parts and '\\'not in entry.name and entry.name not in seen and
                 len(seen)<65536 and 0<=entry.size<=4*1024**3,'finite regular guest package tree; no links/special files')
            seen.add(entry.name);total+=entry.size;need(total<=4*1024**3,'whole guest package expanded cap')
            path=root/relative;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with source.extractfile(entry)as data,path.open('xb')as output:
                count=0
                while block:=data.read(1024**2):
                    count+=len(block);need(count<=entry.size,'package member overflow');output.write(block)
                need(count==entry.size,'complete actual package member EOF');output.flush();os.fsync(output.fileno())
            path.chmod(0o700 if entry.mode&0o111 else 0o600)
    return len(seen)


def assemble(reply,directory,workload):
    package=reply['package']
    need(package['kind']=='OMEN_SOURCE_PACKAGE_TAR_V1'and package['identity']==reply['identity']and
         package['subject']==reply['source_subject'],'same actual guest package/source identity')
    reports=Path(os.environ['OPEMOS_ROBOT_REPORT_DIR']);rows={r['name']:r for r in reply['public_evidence']}
    archive=Path(directory)/'guest-package.tar';h=hashlib.sha256();count=0
    with archive.open('xb')as output:
        for chunk in package['chunks']:
            name=chunk['public_name'];need(name in rows and rows[name]['kind']=='source-package-chunk'and
                 rows[name]['sha256']==chunk['sha256']and rows[name]['bytes']==chunk['bytes']and
                 chunk['offset']==count,'exact ordered same-operation package chunks')
            raw=(reports/name).read_bytes()
            need(len(raw)==chunk['bytes']<=16*1024**2 and hashlib.sha256(raw).hexdigest()==chunk['sha256'],
                 'whole exact source package chunk')
            count+=len(raw);need(count<=5*1024**3,'package tar total cap');output.write(raw);h.update(raw)
        output.flush();os.fsync(output.fileno())
    need(count==package['bytes']and h.hexdigest()==package['sha256'],'whole source package tar EOF/hash')
    destinations={'windows-build':'dist/windows','appimage-package':'linux-package-artifact',
                  'debian-12-package':'linux-package-artifact','seed-runtime-source':'build/runtime-cache/windows',
                  'macos-build':'build/macos-arm64-evidence'}
    target=Path.cwd()/destinations[workload];target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    need(unpack_tar(archive,target,count,package['sha256'])==package['file_count'],'complete guest package tree count')


def run(workload,directory):
    parent=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT']
    before=scope(parent,attempt,workload);installed(before)
    from robot_client import Engine
    directory=Path(directory).absolute();need(not directory.exists(),'fresh source job workspace required; no old result adoption')
    directory.mkdir(mode=0o700,parents=True)
    fixed={'OPEMOS_ROBOT_REPORT_DIR':str(directory/'reports'),
           'OPEMOS_ROBOT_CONTROL_SOCKET':'/run/opemos-ci/control/control.sock',
           'OPEMOS_ROBOT_REPORT_EXCHANGE':'/home/connor/.local/share/opemos-ci/github-runner/robot-private/reports'}
    for key,value in fixed.items():
        need(os.environ.get(key,value)==value,'fixed source namespace/report/socket differs');os.environ[key]=value
    actual_result=None
    try:
        reply=Engine(directory/'private').source_workload(before)
        actual_result=reply['source_result']
        save(directory/'source-actual-outcome.json',reply)
        reports(directory,actual_result)
        need(scope(parent,attempt,workload)==before,'source/head/base/attempt changed during guest operation')
        need(reply['status']=='passed','Actual OMEN source workload failed; complete command outcomes and raw evidence retained')
        if reply.get('package')is not None:assemble(reply,directory,workload)
        need(workload not in('windows-build','appimage-package','debian-12-package','seed-runtime-source','macos-build')or
             reply.get('package')is not None,'required actual guest package absent')
        value={'kind':'OMEN_REQUIRED_SOURCE_JOB_V1','status':'passed','selection':before,
            'parent_run':parent,'parent_attempt':attempt,'root_result_pin':reply['root_result_pin'],
            'guest_result_sha256':hashlib.sha256(canonical(reply['source_result'])).hexdigest(),
            'closure':reply['source_closure'],'noGUIImageOrGPUAcceptance':True}
        reports(directory,reply['source_result'])
        save(directory/'source-proof.json',value)
    except BaseException as e:
        try:
            save(directory/'source-failed-outcome.json',{'kind':'OMEN_REQUIRED_SOURCE_JOB_V1','status':'failed',
                'selection':before,'parent_run':parent,'parent_attempt':attempt,
                'type':type(e).__name__,'reason':str(e),'noGUIImageOrGPUAcceptance':True})
        except BaseException as secondary:e.add_note('Failed-outcome persistence: '+repr(secondary))
        try:reports(directory,actual_result,str(e))
        except BaseException as secondary:e.add_note('Command report finalizer: '+repr(secondary))
        raise


def reports(directory,result,reason=''):
    """Command JUnit/HTML, explicitly NOT an actual Robot GUI output."""
    import html
    binding=None
    if result is not None and result.get('kind')=='OMEN_GUEST_SOURCE_WORKLOAD_V1':
        binding=diagnostic_binding(result,result['identity'],result['subject'],result['controller_manifest_sha256'])
    rows=[]if result is None else result.get('commands',[])
    if not rows:rows=[{'template_argv':['Actual OMEN source prerequisite unavailable'],
                       'numeric_exit':None,'first':reason or 'No actual command receipt'}]
    passed=lambda r:r.get('status')=='passed'and type(r.get('numeric_exit'))is int and r['numeric_exit']==0 and r.get('first')is None
    blocked=sum(r.get('status')=='blocked'for r in rows)
    failed=sum(not passed(r)and r.get('status')!='blocked'for r in rows)
    suite=ET.Element('testsuite',name='Actual OMEN source commands; not GUI Robot acceptance',
                     tests=str(len(rows)),failures=str(failed),skipped=str(blocked))
    for row in rows:
        case=ET.SubElement(suite,'testcase',name=' '.join(row['template_argv']))
        if row.get('status')=='blocked':
            ET.SubElement(case,'skipped',type='blocked-prerequisite-or-hard-stop').text=json.dumps(
                {'blocked_by':row['blocked_by'],'stop_reason':row['stop_reason'],
                 'hard_stop_sha256':row['hard_stop_sha256']})
        elif not passed(row):
            ET.SubElement(case,'failure').text=json.dumps({'status':row.get('status'),
                'numeric_exit':row.get('numeric_exit'),'capture_first':row.get('first'),
                'capture_secondary':row.get('secondary',[]),'transaction_failure':reason})
    if reason and not failed:
        # A Root/publication/closure failure after successful commands is not
        # allowed to leave an all-green JUnit file. This is not a child receipt.
        suite.set('tests',str(len(rows)+1));suite.set('failures','1')
        ET.SubElement(ET.SubElement(suite,'testcase',name='Source transaction finalization'),'failure').text=reason
    ET.ElementTree(suite).write(Path(directory)/'xunit.xml',encoding='utf-8',xml_declaration=True)
    text='<html><body><h1>OMEN source command results (not GUI/Robot acceptance)</h1><pre>'+html.escape(
        json.dumps({'commands':rows,'first':None if result is None else result.get('first'),
            'hard_stop':None if result is None else result.get('hard_stop'),'diagnostic_binding':binding,
            'secondary':[]if result is None else result.get('secondary',[]),'transaction_failure':reason},indent=2))+'</pre></body></html>'
    (Path(directory)/'report.html').write_text(text);(Path(directory)/'log.html').write_text(text)


def record(platform,artifact_id,artifact_name,artifact_sha,output):
    workload={'windows':'windows-build','ubuntu':'appimage-package','macos':'macos-build'}[platform]
    spec=scope(os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT'],workload);installed(spec)
    proof=strict((Path('source-results')/'source-proof.json').read_bytes())
    need(proof['status']=='passed'and proof['selection']==spec and proof['closure']['unknown']==[],
         'same actual guest source proof required before producer binding')
    # Actual package data came through the same Root proof and complete tar
    # verification. Existing A descriptor writer does no native/build execution.
    from record_executable_artifact import record as write_descriptor
    return write_descriptor(platform,spec['candidate_commit'],artifact_id,artifact_name,artifact_sha,output)


def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=('run-required','record'))
    p.add_argument('--workload',choices=tuple(WORKLOADS));p.add_argument('--directory',default='source-results')
    p.add_argument('--platform',choices=('windows','ubuntu','macos'));p.add_argument('--artifact-id')
    p.add_argument('--artifact-name');p.add_argument('--artifact-sha');p.add_argument('--output')
    a=p.parse_args()
    try:
        if a.mode=='run-required':run(a.workload,a.directory)
        else:record(a.platform,a.artifact_id,a.artifact_name,a.artifact_sha,a.output)
    except BaseException as e:
        directory=Path(a.directory);directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        try:save(directory/'source-failure.json',{'kind':'OMEN_SOURCE_JOB_FAILED_DIAGNOSTIC','status':'failed',
            'workload':a.workload,'type':type(e).__name__,'reason':str(e),'compilerPassed':False})
        except BaseException:pass
        print('::error title=OMEN guest source job::'+type(e).__name__+': '+str(e).replace('\n',' ')[:1000]);raise


if __name__=='__main__':main()

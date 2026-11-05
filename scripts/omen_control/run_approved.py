#!/usr/bin/python3
"""Materialize the installed normal Ubuntu program graph for one admitted job.

Candidate archives remain guest data. Only the Root-installed policy selects
host programs; the ordinary queue supplies fresh operation identifiers/data.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
PROGRAMS={'run_approved.py','job.py','provision_observer_rule.py','connection_control.py',
          'observer_guest.py','prepare_observer_iso.py','virtual_usb.py','vm_write_ceiling.py','owned_command.py'}
ENGINE={'scripts/omen_robot.py','scripts/omen_ci_reader.py','scripts/omen_ci_stage.py',
        'scripts/omen_ci_inventory.py','scripts/omen_ci_executables.py','scripts/omen_ci_result.py',
        'scripts/OPEMOSPointer.py','scripts/OPEMOSGuest.py','scripts/run_omen_robot_guest.py',
        'ci/required-vms.json','tests/robot/guest.robot','tests/robot/role.robot',
        'tests/robot/inventory.robot','scripts/required_omen.py','scripts/check_full_stack_acceptance.py'}
TRUSTED=Path('/var/lib/opemos-robot-control-r1/releases')

def need(value,reason):
    if not value:raise ValueError(reason)

def read(path,cap,uid,expected=None,mode=None):
    path=Path(path);need(path.is_absolute()and path.resolve()==path,'canonical normal source/data')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);identity=lambda s:{k:getattr(s,k)for k in FIELDS}
        need(stat.S_ISREG(before.st_mode)and before.st_uid==uid and before.st_nlink==1
             and not before.st_mode&0o022 and 0<before.st_size<=cap
             and(mode is None or stat.S_IMODE(before.st_mode)==mode),'normal source/data custody')
        raw=bytearray()
        while block:=os.read(fd,65536):raw.extend(block);need(len(raw)<=cap,'normal file cap')
        need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),
             'whole held/named normal file epoch')
        need(expected is None or hashlib.sha256(raw).hexdigest()==expected,'normal exact source/data hash')
        return bytes(raw),{'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                           'identity':identity(before)}
    finally:os.close(fd)

def create(path,raw,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    try:
        os.fchmod(fd,mode);view=memoryview(raw)
        while view:
            count=os.write(fd,view);need(count>0,'materialization write progress');view=view[count:]
        os.fsync(fd)
    finally:os.close(fd)

def materialize(config_ref):
    need(os.getuid()==os.geteuid()==1000,'ordinary admitted queue owner only')
    raw,_=read(config_ref['path'],1048576,1000,config_ref['sha256'],0o400);cfg=json.loads(raw)
    nonce=cfg['nonce'];need(cfg['kind']=='ROOT_ADMITTED_UBUNTU_GUI_BUILD_WRITE_V1'
        and re.fullmatch('[0-9a-f]{32}',nonce)and re.fullmatch('[0-9a-f]{40}',cfg['source_commit']),
        'same bounded normal Ubuntu operation')
    ref=cfg['normalPolicyPin'];path=Path(ref['path'])
    need(path.parent.parent==TRUSTED and re.fullmatch('[0-9a-f]{32}',path.parent.name)
         and path.name=='fixed-policy.json','existing trusted immutable deployment policy')
    # Verify every Root ancestor and every program before interpreting a sibling.
    for parent in(path.parent,*path.parent.parents):
        info=parent.lstat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==0
            and not info.st_mode&0o022,'Root immutable deployment ancestry')
    policy_raw,_=read(path,1048576,0,ref['sha256'],0o444);policy=json.loads(policy_raw)
    need(policy['kind']=='ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1'and
         set(policy['programSHA256'])==PROGRAMS and set(policy['engineSHA256'])==ENGINE and policy['network']=='none'
         and policy['maxVMBytes']<=59_971_770_624 and policy['maxCPU']<=10
         and policy['maxMemoryBytes']<=34359738368 and policy['swapBytes']==0,
         'reviewed finite normal VM policy, no physical media or new network')
    bundle=path.parent/'proof-sources';programs={};pins={}
    for name in sorted(PROGRAMS):
        programs[name],pins[name]=read(bundle/name,1048576,0,policy['programSHA256'][name],0o444)
    engine={name:read(path.parent/'engine'/name,8388608,0,policy['engineSHA256'][name],0o444)[0]
            for name in sorted(ENGINE)}
    need(sum(map(len,programs.values()))+sum(map(len,engine.values()))<=8388608,'complete finite normal source graph')
    need(Path(__file__).resolve()==bundle/'run_approved.py','actual installed current materializer')
    operation=Path(config_ref['path']).parent;base=Path(policy['operationRoot'])
    need(operation.parent==base and operation.name.endswith('-'+nonce)and
         operation.resolve()==operation and operation.stat().st_uid==1000
         and stat.S_IMODE(operation.stat().st_mode)==0o700,'same existing normal operation namespace')
    need(cfg['network']=='none'and cfg['whole_seconds']<=policy['wholeSeconds']<=7200
         and 0<cfg['cores']<=policy['maxCPU']and 0<cfg['memoryBytes']<=policy['maxMemoryBytes']
         and cfg['maxVMBytes']==policy['maxVMBytes']and cfg['swapBytes']==0,
         'normal operation stays within exact queue policy')
    expected=cfg['candidate']['descriptor'];need(expected['platform']=='ubuntu'
         and expected['repository']=='CorniiDog/OPEMOS.EXE'and expected['source_commit']==cfg['source_commit']
         and cfg['candidate']['archive']['sha256']==expected['artifact_archive_sha256'],
         'actual current producer package remains separate data')
    target=operation/'programs';target.mkdir(mode=0o700)
    for name,source in programs.items():
        create(target/name,source,0o500)
        read(target/name,1048576,1000,policy['programSHA256'][name],0o500)
    engine_target=target/'engine';engine_target.mkdir(mode=0o700)
    for name,source in engine.items():
        destination=engine_target/name;destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        create(destination,source,0o500)
        read(destination,8388608,1000,policy['engineSHA256'][name],0o500)
    # Reuse the original private login input; never alter or export its bytes.
    secret=cfg['loginPin'];login,actual=read(secret['path'],4096,1000,secret['sha256'],0o600)
    need(actual==secret,'exact retained private login full9')
    create(target/'login.private.json',login,0o600)
    cfg.update(programRoot=str(target),programPins=pins,normalPolicy=policy,engineRoot=str(engine_target))
    config_raw=(json.dumps(cfg,sort_keys=True,separators=(',',':'))+'\n').encode()
    create(target/'operation.json',config_raw,0o400)
    return target/'job.py',target/'operation.json'

def main():
    need(len(sys.argv)==3 and sys.argv[1]=='--pipeline-config-pin-json','normal pinned operation data only')
    job,config=materialize(json.loads(sys.argv[2]))
    os.execv('/usr/bin/python3',['/usr/bin/python3','-B',str(job),'--pipeline',str(config)])

if __name__=='__main__':main()

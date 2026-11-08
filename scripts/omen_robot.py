#!/usr/bin/env python3
"""Robot orchestration: execute fresh admitted ordinary jobs, never replay receipts."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

REPO = 'CorniiDog/OPEMOS.EXE'
CONFIG = Path.home()/'.config/opemos-ci/robot.json'
HOOK = '/home/connor/.local/libexec/opemos-robot-job-plan'
FULL9 = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
SHA = re.compile(r'[0-9a-f]{64}\Z')
MODULE_PINS={'omen_ci_reader.py': '6b2d97a373001e8835400d5be22cef8c06004dab5c228bc1efbe7078dfe464df', 'omen_ci_executables.py': '0a94a6068019795bbb3698fcacabd60dc632f863b6504fc183791b00aad56440', 'omen_ci_result.py': '5baa682b9bd7b625d817b857befa7b180edf025bf1b8ab60e7de0a77fd456f85', 'omen_ci_stage.py': '851ab2f250c79841646902d21e0e1811d851899c26ce5937d9738a52a739d7f9', 'omen_ci_inventory.py': 'e8873930651d4e1022fd3851b9bc35400ff54310e1d904f5d01c0f7dd903119e'}


def require(value, message):
    if not value:
        raise ValueError(message)


def raw_file(path, cap=8*1024**2, expected=None, owner=None):
    path=Path(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=cap and not before.st_mode&0o022,'Unsafe source/config/evidence file')
        require(owner is None or before.st_uid==owner,'File owner mismatch')
        raw=bytearray()
        while block:=os.read(fd,min(65536,cap+1-len(raw))):
            raw.extend(block);require(len(raw)<=cap,'Bounded read overflow')
        sig=lambda s:tuple(getattr(s,k)for k in FULL9)
        require(len(raw)==before.st_size and sig(before)==sig(os.fstat(fd))==sig(path.lstat()),'Descriptor/path changed')
        require(expected is None or hashlib.sha256(raw).hexdigest()==expected,'Source/evidence SHA mismatch')
        return bytes(raw)
    finally:
        os.close(fd)


def strict(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'Duplicate JSON field');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:require(False,'Nonfinite JSON'))


def dump(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())


def modules():
    root=Path(__file__).parent
    blobs={name:raw_file(root/name,expected=pin,owner=os.getuid())for name,pin in MODULE_PINS.items()}
    namespace={'__name__':'robot_bound_reader','__file__':str(root/'omen_ci_reader.py')}
    exec(compile(blobs['omen_ci_reader.py'],namespace['__file__'],'exec'),namespace)
    return namespace['verified_namespace'](blobs['omen_ci_stage.py'],root/'omen_ci_stage.py','robot_bound_stage')


def identity(env=None):
    env=os.environ if env is None else env
    result={k:env.get(v,'')for k,v in {'source_commit':'OPEMOS_SOURCE_SHA','run_id':'GITHUB_RUN_ID','attempt':'GITHUB_RUN_ATTEMPT'}.items()}
    require(re.fullmatch(r'[0-9a-f]{40}',result['source_commit']),'Exact accepted source missing')
    require(all(re.fullmatch(r'[1-9][0-9]{0,19}',result[k])for k in ('run_id','attempt')),'Exact consumer run/attempt missing')
    require(env.get('GITHUB_REPOSITORY')==REPO,'Canonical repository required')
    result['repository']=REPO
    return result


def inventory():
    value=strict(raw_file(Path(__file__).parents[1]/'ci/required-vms.json',owner=os.getuid()))
    require(value['required_vms'] and len({r['id']for r in value['required_vms']})==len(value['required_vms']),'Unique configured inventory required')
    return value['required_vms']


def installed():
    value=strict(raw_file(CONFIG,1024**2,owner=os.getuid()))
    require(value.get('schema')==1 and value.get('enabled')is True,'Reviewed Robot profile absent/disabled')
    require(value['hook']['path']==HOOK and SHA.fullmatch(value['hook']['sha256']),'Fixed installed plan hook pin missing')
    require(value['robotframework']=={'version':'7.5','wheel_sha256':'5a194db36524604fafa1da89adebc837db9a95adf15ffd746e09ce98251e6c68'},'Official pinned Robot runtime differs')
    require(value['stage']['sha256']==MODULE_PINS['omen_ci_stage.py'],'Installed stage/source graph differs')
    raw_file(HOOK,expected=value['hook']['sha256'],owner=os.getuid())
    return value


def hook(profile,request,out):
    """Run fixed, verified installed planner bytes. No PR argv/shell operation."""
    out=Path(out);out.mkdir(mode=0o700,parents=True,exist_ok=True)
    source=raw_file(HOOK,expected=profile['hook']['sha256'],owner=os.getuid())
    # Use a sealed descriptor instead of re-opening an executable after checking.
    stage=modules()
    command=[sys.executable,'-I','-c',"__file__="+repr(HOOK)+";exec(compile("+repr(source)+","+repr(HOOK)+",'exec'))"]
    receipt=stage['_RESULT']['capture'](command,json.dumps(request).encode(),profile['result_contract'],out/'planner-transport',60)
    require(receipt['numeric_exit']==0 and receipt['complete']is True,'Fixed planner failed; retained exact raw/transport diagnostics')
    row=receipt['streams']['stdout']
    result=strict(raw_file(row['path'],profile['result_contract']['max_bytes'],row['sha256'],os.getuid()))
    require(result.get('identity')=={k:request[k]for k in ('repository','source_commit','run_id','attempt','nonce')},'Planner returned stale run/source/nonce')
    return result



def consume_collection(stage, collected, request, job_ids, robot, operand, limit):
    """Consume same-operation post-terminal publications, never dispatch work."""
    require(collected.get('identity')=={k:request[k]for k in
            ('repository','source_commit','run_id','attempt','nonce')},
            'Post-terminal collector identity differs')
    require(collected.get('effect')=='READ_ONLY_CURRENT_OPERATION' and
            collected.get('job_ids')==job_ids and len(set(job_ids))==len(job_ids) and
            collected.get('queue_job_id')==robot['job_id'] and
            collected.get('queue_state')=='passed' and
            collected.get('queue_lifecycle_closed') is True and
            collected.get('receipt_path')==operand['receipt'] and
            collected.get('robot_result_path')==robot['result_path'] and
            SHA.fullmatch(collected.get('receipt_sha256','')) and
            SHA.fullmatch(collected.get('robot_result_sha256','')),
            'Exact current read-only post-terminal producer missing')
    receipt, receipt_sha=stage['load_result'](operand['receipt'],limit)
    proof, proof_sha=stage['load_result'](robot['result_path'],limit)
    require(receipt_sha==collected['receipt_sha256'] and
            proof_sha==collected['robot_result_sha256'],
            'Post-terminal published bytes changed after collection')
    require(proof.get('identity')==request,'Guest must retain the full original prepare request')
    if operand['subject_role']=='nested_linux':
        guest=proof.get('boot_id');host=collected.get('host_boot_id')
        require(proof.get('execution_location')=='inner_QEMU_guest' and
                isinstance(guest,str) and re.fullmatch(r'[0-9a-f-]{36}',guest) and
                isinstance(host,str) and re.fullmatch(r'[0-9a-f-]{36}',host) and
                guest!=host and collected.get('guest_boot_id')==guest,
                'Observed inner guest boot must differ from collector host')
        require(proof.get('inventory_vm_id')==operand['inventory_vm_id'] and
                proof.get('process_reaped') is True and proof.get('channel_eof') is True,
                'Actual inner guest identity/channel/reap proof missing')
    return receipt, receipt_sha, proof


class Engine:
    """One Robot test owns one current transaction. Failures do not stop peers."""
    def __init__(self,output):
        self.output=Path(output).absolute();self.output.mkdir(parents=True,exist_ok=True,mode=0o700)
        meta=self.output.lstat();require(self.output.resolve()==self.output and stat.S_ISDIR(meta.st_mode)and meta.st_uid==os.getuid()and not meta.st_mode&0o077,'Private current-run output root required')
        self.context=identity();self.profile=None;self.stage=None
        self.results={r['id']:{'status':'unavailable','reason':'Fresh transaction not executed','name':r['name']}for r in inventory()}
        self.artifacts={p:{'status':'unavailable','reason':'Current native candidate producer absent','artifacts':{}}for p in ('windows','ubuntu','macos')}
        self.deadline=time.monotonic()+10800
        self.counter=0;self.current=None;self.runtime_original={};self.source_original={}
        self.reports=Path(os.environ['OPEMOS_ROBOT_REPORT_DIR']).absolute();self.reports.mkdir(parents=True,exist_ok=True,mode=0o700)

    def stage_candidate(self, expected, download):
        """Opaque data custody only; candidates never become controller code."""
        if self.profile is None:self.profile=installed();self.stage=modules()
        self.stage['_EXECUTABLES']['descriptor'](expected)
        return self._stage_archive(expected,download,self.profile['max_candidate_archive_bytes'],'candidate')

    def stage_source_input(self,expected,download):
        if self.profile is None:self.profile=installed();self.stage=modules()
        require(expected['kind']=='UBUNTU_SOURCE_INPUT_ARTIFACT_V1' and
                expected['repository']==self.context['repository'], 'authenticated source-only input')
        return self._stage_archive(expected,download,self.profile['max_source_input_archive_bytes'],'source-input')

    def _stage_archive(self,expected,download,limit,role):
        require(type(limit)is int and 0<limit<=60000000000,'Existing whole-VM candidate bound')
        root=Path(self.profile['candidate_storage_root'])
        require(root==self.stage['ROOT'],'Existing dedicated CI candidate storage required')
        self.stage['root_guard'](root)
        contract=self.stage['_RESULT']['policy'](self.profile['result_contract'])
        # Opaque multi-GB packages belong on existing CI storage. Keep complete
        # result/diagnostic headroom on the separate private control volume too.
        for directory,required in ((root,limit+contract['free_reserve_bytes']),
                (self.output,2*contract['max_bytes']+contract['stderr_max_bytes']+contract['free_reserve_bytes'])):
            space=os.statvfs(directory)
            require(space.f_bavail*space.f_frsize>=required,'Candidate/control volume lacks bounded acquisition/result reserve')
        require(all(re.fullmatch(r'[1-9][0-9]{0,19}',self.context[k])for k in ('run_id','attempt')),
                'Exact current consumer run/attempt required')
        folder=root/(role+'-'+self.context['run_id']+'-'+self.context['attempt']+'-'+
                     expected['artifact_id']+'-'+expected['artifact_archive_sha256'])
        folder.mkdir(mode=0o700)
        os.chmod(folder,0o700);self.stage['real_dir'](folder)
        # This prefix is outside ordinary run expiry. Preserve failed partials
        # with provenance; never classify interrupted acquisition as VM closure.
        dump(folder/'.owned.json',{'schema':1,'uid':os.getuid(),'identity':self.context,
             'descriptor':expected,'max_bytes':limit,'role':'opaque '+role+' acquisition; not controller code'})
        path=folder/'archive.zip'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            with os.fdopen(fd,'wb',closefd=False)as stream:
                size=download(expected,stream,limit);stream.flush();os.fsync(fd)
            os.fchmod(fd,0o400)
        finally:os.close(fd)
        self.stage['artifact_read']({'path':str(path),'sha256':expected['artifact_archive_sha256'],'size':size},limit)
        return {'path':str(path),'sha256':expected['artifact_archive_sha256'],'bytes':size}

    def request(self,kind,subject,candidate=None,source_input=None):
        if self.profile is None:self.profile=installed();self.stage=modules()
        self.counter+=1
        nonce=os.urandom(16).hex()
        folder=self.output/(str(self.counter)+'-'+nonce);folder.mkdir(mode=0o700)
        request=dict(self.context,version=1,action='prepare',kind=kind,subject=subject,nonce=nonce,
                     consumer_started_epoch=int(os.environ['OPEMOS_CONSUMER_STARTED_EPOCH']))
        if candidate is not None:request['candidate']=candidate
        if source_input is not None:request['source_input']=source_input
        dump(folder/'request.json',request)
        return request,hook(self.profile,request,folder),folder

    def build_source(self,expected,archive):
        """One source-build operation through the existing planner/normal queue.

        Compilation is a separately typed stage. It cannot assert a graphical
        Build, USB write, SteamOS boot, NVIDIA or full-stack acceptance.
        """
        request,prepared,folder=self.request('source',{'platform':'ubuntu'},
            source_input={'descriptor':expected,'archive':archive})
        require(prepared.get('available')is True,prepared.get('reason','Source producer unavailable'))
        require(prepared.get('operation_scope')=='NORMAL_UBUNTU_SOURCE_BUILD_ONLY' and
                prepared['expected_source_input']==expected,'exact source-input operation required')
        cfg=self.stage['load_pinned'](prepared['config']);operand=prepared['operand'];plan=prepared['plan']
        self.current=(request,prepared,folder,cfg)
        require(plan['source_commit']==request['source_commit'] and plan['nonce']==request['nonce'] and
                operand['hardware_scope']=='virtual-only' and
                operand['inventory_vm_id']=='OPEMOS-Ubuntu-Agent-UI',
                'actual Ubuntu original/virtual-only source stage')
        require(cfg.get('enabled')is True and cfg['version']==1 and
                cfg['artifact_root']==str(self.stage['ROOT']) and cfg['dispatcher_mode']=='join-existing' and
                cfg['vm_admission_limits']=={'max_vm_bytes':60000000000,'max_cpu':10,'max_memory_bytes':34359738368} and
                type(cfg['wait_seconds'])is int and 1<=cfg['wait_seconds']<=10800,
                'same normal queue/resource/wait contract')
        admission=self.stage['load_pinned'](operand['runtime_admission'])
        require(admission.get('sourceBuildEnabled')is True,'reviewed source-build policy required')
        self.stage['verify_original_operand'](operand,cfg['max_input_bytes'])
        for pin in operand['inputs']:self.stage['artifact_read'](pin,cfg['max_input_bytes'])
        manifest=self.stage['absolute_manifest'](self.stage['load_pinned'](operand['manifest']))
        require(len(manifest['jobs'])==1 and [j['id']for j in manifest['jobs']]==operand['job_ids'],
                'one exact normal compiler job')
        job=manifest['jobs'][0]
        require(job['owner']=='exe' and job['platform']=='ubuntu' and
                job['resources']==['opemos-ubuntu-gui-virtual-usb'] and
                0<job['cores']<=4 and 0<job['memory']<=25769803776 and
                all(job['approval'][k]==operand['runtime_admission'][k]for k in('path','sha256')),
                'unchanged exclusive Ubuntu/resource/source admission')
        rows=self.stage['queue_status'](cfg,job_ids=[job['id']])
        require(job['id']not in rows,'source-build job cannot be replayed')
        staging=Path(prepared['staging_path']);self.stage['root_guard']()
        require(staging.parent==self.stage['ROOT'] and self.stage['RUN'].fullmatch(staging.name) and
                staging.name.endswith(request['nonce']) and not staging.exists(),'fresh source-build stage')
        staging.mkdir(mode=0o700);self.stage['create_json'](staging/'.lock',{})
        lock=self.stage['owned_lock'](staging/'.lock')
        import fcntl
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        self.stage['create_json'](staging/'.owned.json',{'schema':1,'name':staging.name,
            'uid':os.getuid(),'created':int(time.time()),'expires':int(time.time())+14400,
            'result_max_bytes':cfg['result_contract']['max_bytes'],'job_ids':[job['id']],
            'source_commit':request['source_commit'],'nonce':request['nonce']})
        progress={}
        try:
            submitted=self.stage['queue_call'](cfg,'submit',[operand['manifest']])
            self.stage['create_json'](staging/'submitted.json',submitted)
            try:rows=self.stage['wait_jobs'](cfg,[job['id']],[operand['manifest']],
                    min(self.deadline,time.monotonic()+cfg['wait_seconds']),progress)
            finally:self.stage['create_json'](staging/'queue-wait.json',progress)
            row=rows[job['id']]
            lifecycle=(row.get('result')or{}).get('terminalLifecycle',{})
            require(row['state']=='passed' and lifecycle.get('phase')=='CLOSED' and
                    lifecycle.get('reservationRetained')is False,'actual source job must finish normally')
            collected=hook(self.profile,dict(request,action='collect'),folder/'post-terminal')
            raw=raw_file(collected['source_result_path'],cfg['result_contract']['max_bytes'])
            actual=strict(raw)
            require(actual['kind']=='NORMAL_UBUNTU_SOURCE_BUILD_JOB_V1' and
                    actual['nonce']==request['nonce'] and actual['source_commit']==request['source_commit'] and
                    actual['candidate_source_commit']==expected['source_commit'] and
                    actual['first_failure']is None and actual['qemu_reaped']is True and
                    actual['private_storage_closure_verified']is True and
                    actual['originals_unchanged_after']is True and actual['SourceBuildAccepted']is True and
                    not actual.get('secondary_failures'),
                    'actual guest compiler, native closure and original preservation proof')
            binding=strict(raw_file(Path(collected['source_result_path']).with_name('binding.json'),1048576,owner=os.getuid()))
            require(binding['nonce']==request['nonce']and binding['pid']==actual['qemu_pid']and
                    binding['queue_unit']==row['unit']and
                    binding['artifact_source']==expected['source_commit']and
                    binding['vm_name']=='opemos-robot-ubuntu-'+request['nonce'],
                    'actual original admitted QEMU/queue/source identity')
            package=actual['source_package']
            self.stage['artifact_read']({'path':package['path'],'sha256':package['sha256'],
                                         'size':package['bytes']},2147483648)
            return {'status':'passed','identity':request,'source_input':expected,
                    'queue_job_id':job['id'],'canonical':row,'package':package,
                    'guest_build':actual['guest_build'],'normal_job_result':actual,
                    'qemu':{k:binding[k]for k in('pid','start_ticks','host_boot_id','queue_unit','queue_invocation_id','vm_name')},
                    'GUIOrSteamOSAcceptance':False}
        except Exception:
            # Correlated current results only; never substitute a historical
            # success or release an unknown reservation while collecting FIRST.
            self.source_failure={'queue_job_id':job['id'],'closure':'UNKNOWN'}
            try:
                current=hook(self.profile,dict(request,action='collect'),folder/'failed-source-collection')
                observed=strict(raw_file(current['source_result_path'],cfg['result_contract']['max_bytes']))
                if observed.get('nonce')==request['nonce']:
                    self.source_failure.update(first=observed.get('first_failure'),
                        guest_event=observed.get('guest_source_event'),qemu_pid=observed.get('qemu_pid'),
                        qemu_reaped=observed.get('qemu_reaped'),closure=observed.get('closure','UNKNOWN'))
            except Exception as secondary:self.source_failure['collection_error']=type(secondary).__name__
            raise
        finally:
            fcntl.flock(lock,fcntl.LOCK_UN);lock.close()

    def transaction(self,kind,subject,expected_producer=None,candidate_archive=None):
        candidate=None if expected_producer is None else {'descriptor':expected_producer,'archive':candidate_archive}
        request,prepared,folder=self.request(kind,subject,candidate)
        require(prepared.get('available')is True,prepared.get('reason','Missing exact admitted operation'))
        if expected_producer is not None:
            require(kind=='artifact' and prepared.get('expected')==expected_producer,'Exact requested producer differs BEFORE any stage/submit/VM effect')
        cfg=self.stage['load_pinned'](prepared['config'])
        operand=prepared['operand'];plan=prepared['plan'];case=operand['case']
        self.current=(request,prepared,folder,cfg)
        require(plan['source_commit']==request['source_commit'] and plan['nonce']==request['nonce'],'Fresh same-source plan required')
        require(operand['inventory_vm_id']in self.results,'Unknown original inventory identity')
        require(kind!='inventory' or operand['inventory_vm_id']==subject,'Another original substituted')
        require(case in self.stage['CASES'],'Truthful existing role required')
        require(time.monotonic()<self.deadline,'Finite Robot batch deadline; affected case unavailable without dispatch')
        require(cfg.get('enabled')is True and cfg.get('version')==1 and cfg.get('artifact_root')==str(self.stage['ROOT']),'Exact installed normal stage/root configuration required')
        require(type(cfg['wait_seconds'])is int and 1<=cfg['wait_seconds']<=10800 and type(cfg['max_run_bytes'])is int and 0<cfg['max_run_bytes']<=60000000000,'Finite ordinary case/staging bound required')
        require(cfg['dispatcher_mode']=='join-existing' and cfg['vm_admission_limits']=={'max_vm_bytes':60000000000,'max_cpu':10,'max_memory_bytes':34359738368},'Existing pool/full60GB limits changed')
        runtime=operand['runtime_instance_id'];original=operand['inventory_vm_id'];source_id=json.dumps(operand['original_source']['identity'],sort_keys=True)
        require(runtime not in self.runtime_original or self.runtime_original[runtime]==original,'Runtime aliases another catalog original')
        require(source_id not in self.source_original or self.source_original[source_id]==original,'Backing source aliases another catalog original')
        self.runtime_original[runtime]=original;self.source_original[source_id]=original
        rows=self.stage['queue_status'](cfg)
        # Historical fixture/qualification reports belong to deployment review.
        # Current pool, actual source/worker, admission and every operation's
        # original/file/lease/lifecycle guards remain authoritative below.
        self.stage['load_pinned'](operand['runtime_admission'])
        require(self.stage['_INVENTORY']['subject_contract'](operand['inventory_vm_id'],case,operand['subject_role']),'Role relabeling refused')
        self.stage['verify_original_operand'](operand,cfg['max_input_bytes'])
        for item in operand['inputs']:self.stage['artifact_read'](item,cfg['max_input_bytes'])
        for item in operand['artifacts']:self.stage['artifact_read'](item,cfg['max_run_bytes'])
        require(not os.path.lexists(prepared['robot_job']['result_path']),'Old Robot result path refused before submission')
        manifest=self.stage['absolute_manifest'](self.stage['load_pinned'](operand['manifest']))
        require([j['id']for j in manifest['jobs']]==operand['job_ids'] and not any(j in rows for j in operand['job_ids']),'Old/aliased ordinary jobs refused')
        require(all(all(job.get('approval',{}).get(k)==operand['runtime_admission'][k]for k in ('path','sha256'))for job in manifest['jobs']),'Manifest approval mismatch')
        if case=='steamos-autoheal':
            self.stage['load_pinned'](operand['gpu_admission'])
            require(operand['hardware_scope']=='existing-independently-admitted-gpu','No existing GPU lease admission')
            selected=[j for j in manifest['jobs']if j.get('libvirt_domain',{}).get('leaseNonce')==operand['lease_nonce'] and 'omen-iommu-group-1'in j.get('resources',[])]
            require(len(selected)==1 and all(selected[0].get('approval',{}).get(k)==operand['gpu_admission'][k]for k in ('path','sha256')),'Exact shared GPU lease/manifest required')
        else:require(operand['hardware_scope']=='virtual-only','Imaging host physical scope refused')
        # Fixed planner must install current Robot+pointer-driver job steps and
        # exact dependencies; an old manual result or a no-op job is not a click.
        robot=prepared['robot_job']
        gui_required=operand['subject_role']in ('imaging_host','steamos_target')
        require(gui_required or operand['subject_role']in ('nested_linux','fedora_appliance','virtual_usb'),'Unknown real role, no inferred GUI')
        suite='guest.robot'if gui_required else 'role.robot'
        require(robot['library_sha256']==hashlib.sha256(raw_file(Path(__file__).with_name('OPEMOSPointer.py'))).hexdigest(),'Actual job pointer library differs')
        require(robot['source_commit']==request['source_commit']and robot['run_id']==request['run_id']and robot['attempt']==request['attempt']and robot['nonce']==request['nonce'],'Robot job not bound to consumer')
        require(robot['job_id']in operand['job_ids']and robot['suite_sha256']==hashlib.sha256(raw_file(Path(__file__).parents[1]/('tests/robot/'+suite))).hexdigest(),'Fresh actual guest Robot job absent')
        selected_job=next(j for j in manifest['jobs']if j['id']==robot['job_id'])
        require(selected_job['command']==robot['queue_command'],'Normal command differs from fixed reviewed Robot job')
        required_sources={'scripts/OPEMOSPointer.py','scripts/OPEMOSGuest.py','scripts/omen_robot.py','scripts/run_omen_robot_guest.py','tests/robot/'+suite}
        require(required_sources<=set(robot['source_pins']),'Complete Robot execution dependency pins missing')
        for relative in required_sources:
            pin=robot['source_pins'][relative]
            expected_sha=hashlib.sha256(raw_file(Path(__file__).parents[1]/relative)).hexdigest()
            require(pin['sha256']==expected_sha and pin['path']in selected_job['files'],'Normal queue file custody omitted exact Robot source')
            self.stage['pinned'](pin)
        entry=robot['source_pins']['scripts/run_omen_robot_guest.py']['path']
        require(entry in selected_job['command'],'Normal queue command does not actually execute the installed Robot step')

        operations=prepared.get('additional_operations',[])
        require(isinstance(operations,list)and len(operations)<=3,'Finite complete artifact graph required')
        manifests=[operand['manifest']];protected=list(operand['job_ids'])
        for extra in operations:
            require(kind=='artifact'and extra['inventory_vm_id']in self.results,'Only declared exact artifact build/heal operands')
            self.stage['load_pinned'](extra['runtime_admission']);self.stage['verify_original_operand'](extra,cfg['max_input_bytes'])
            require(self.stage['_INVENTORY']['subject_contract'](extra['inventory_vm_id'],extra['case'],extra['subject_role']),'Additional operation role mismatch')
            normal=self.stage['absolute_manifest'](self.stage['load_pinned'](extra['manifest']))
            require([j['id']for j in normal['jobs']]==extra['job_ids']and not(set(extra['job_ids'])&set(protected))and not any(j in rows for j in extra['job_ids']),'Additional actual jobs old/aliased')
            require(all(all(j.get('approval',{}).get(k)==extra['runtime_admission'][k]for k in ('path','sha256'))for j in normal['jobs']),'Additional operation approval mismatch')
            if extra['case']=='steamos-autoheal':
                self.stage['load_pinned'](extra['gpu_admission'])
                selected=[j for j in normal['jobs']if j.get('libvirt_domain',{}).get('leaseNonce')==extra['lease_nonce']and 'omen-iommu-group-1'in j.get('resources',[])]
                require(extra['hardware_scope']=='existing-independently-admitted-gpu'and len(selected)==1 and all(selected[0].get('approval',{}).get(k)==extra['gpu_admission'][k]for k in ('path','sha256')),'Additional heal lacks exact GPU lease')
            else:require(extra['hardware_scope']=='virtual-only','Additional physical scope refused')
            for pin in extra['inputs']:self.stage['artifact_read'](pin,cfg['max_input_bytes'])
            manifests.append(extra['manifest']);protected.extend(extra['job_ids'])
        runtimes={operand['runtime_instance_id']}|{extra['runtime_instance_id']for extra in operations}
        require(type(cfg['max_vm_submissions'])is int and 1<=cfg['max_vm_submissions']<=20 and len(runtimes)<=cfg['max_vm_submissions'],'Exact finite owner admission set exceeded')
        for extra in operations:
            runtime=extra['runtime_instance_id'];original=extra['inventory_vm_id'];source_id=json.dumps(extra['original_source']['identity'],sort_keys=True)
            require(runtime not in self.runtime_original or self.runtime_original[runtime]==original,'Additional runtime aliases another original')
            require(source_id not in self.source_original or self.source_original[source_id]==original,'Additional backing aliases another original')
            self.runtime_original[runtime]=original;self.source_original[source_id]=original
        # Existing stage is sole staging/expiry owner. A fresh root/config/source
        # check and exact owned marker precede submission, not an unguarded copy.
        stage_path=Path(prepared['staging_path']);self.stage['root_guard']()
        require(stage_path.parent==self.stage['ROOT'] and self.stage['RUN'].fullmatch(stage_path.name)and stage_path.name.endswith(request['nonce']) and not stage_path.exists(),'Fresh dedicated CI stage required')
        self.stage['expire'](cfg,rows)
        stage_path.mkdir(mode=0o700);(stage_path/'artifacts').mkdir(mode=0o700)
        self.stage['create_json'](stage_path/'.lock',{})
        lock=self.stage['owned_lock'](stage_path/'.lock')
        import fcntl
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        now=int(time.time());marker={'schema':1,'name':stage_path.name,'uid':os.getuid(),'created':now,'expires':now+14400,'result_max_bytes':cfg['result_contract']['max_bytes'],'job_ids':protected,'source_commit':request['source_commit'],'nonce':request['nonce']}
        self.stage['create_json'](stage_path/'.owned.json',marker)
        try:
            before=stage_path/'before.json';self.stage['create_json'](before,{'request':request,'prepared':prepared})
            submit=self.stage['queue_call'](cfg,'submit',manifests);self.stage['create_json'](stage_path/'submitted.json',submit)
            deadline=min(self.deadline,time.monotonic()+cfg['wait_seconds'])
            progress={}
            try:rows=self.stage['wait_jobs'](cfg,protected,manifests,deadline,progress)
            finally:self.stage['create_json'](stage_path/'queue-wait.json',progress)
            require(all(rows[j]['state']=='passed'for j in protected),'Actual ordinary job failed; original failure retained')
            collected=hook(self.profile,dict(request,action='collect'),folder/'post-terminal')
            if prepared.get('operation_scope')=='NORMAL_UBUNTU_GUI_BUILD_WRITE_VIRTUAL_USB_ONLY':
                require(kind=='artifact'and subject['platform']=='ubuntu'and not operations,
                        'bounded Ubuntu stage cannot replace another full-stack role')
                return self.ubuntu_gui_component(request,prepared,collected,rows,stage_path,folder)
            receipt,receipt_sha,proof=consume_collection(
                self.stage,collected,request,protected,robot,operand,cfg['result_contract']['max_bytes'])
            self.stage['validate_receipt'](receipt,case,plan,operand)
            require(receipt['run_id']==request['run_id'] and receipt['attempt']==request['attempt'],'Old manual receipt is not a new Robot run')
            require(proof['identity']==request and type(proof['numeric_exit'])is int and proof['numeric_exit']==0 and type(proof['tests_failed'])is int and proof['tests_failed']==0 and type(proof['tests_passed'])is int and proof['tests_passed']>0,'Actual same-run Robot result missing or failed')
            if gui_required:require(type(proof['actual_pointer_calls'])is int and proof['actual_pointer_calls']>0,'No actual pointer calls in this execution')
            budget=cfg['max_run_bytes'];files=receipt.get('files',{})
            require(proof['suite_sha256']==robot['suite_sha256'],'Actual Robot suite bytes differ')
            if kind=='artifact':
                expected=prepared['expected'];self.stage['_EXECUTABLES']['descriptor'](expected)
                require(expected['platform']==subject['platform'] and expected['artifact_id']==subject['artifact_id'],'Another platform/artifact cannot cover missing executable')
                transaction,_=self.stage['load_result'](prepared['executable_transaction_path'],cfg['result_contract']['max_bytes'])
                entry=prepared['executable_entry']
                require(set(entry['build_operand']['job_ids']+entry['heal_operand']['job_ids'])==set(protected),'Artifact omitted normal build/heal jobs')
                verified,transaction_files=self.stage['validate_executable_transaction'](transaction,expected,entry,plan,request,rows)
                files=dict(files,**transaction_files)
            exports=[]
            for pin in list(files.values())+proof['reports']:
                # Only explicitly reviewed public evidence; raw credentials and
                # private config/source are never GitHub artifact candidates.
                if pin.get('public')is not True:continue
                require(pin['kind']in {'screenshot','log','boot-log','pointer-action','pointer-sender-lifecycle','nvidia-loaded','nvidia-render','gpu-restoration','queue-closure','robot-output','robot-log','robot-report','robot-xunit','argv'},'Unreviewed/private artifact export refused')
                target=stage_path/'artifacts'/pin['sha256'];charged,_=self.stage['retain_pin'](pin,target,budget,cfg['max_run_bytes']);budget-=charged
                # Reports are copied from exact already verified/staged bytes;
                # original images/disks are never uploaded or expired.
                data=raw_file(target,cfg['max_run_bytes'],pin['sha256'])
                suffix='.png'if pin['kind']=='screenshot'else '.xml'if pin['kind']in ('robot-output','robot-xunit')else '.html'if pin['kind']in ('robot-log','robot-report')else '.txt'
                dest=self.reports/(request['nonce']+'-'+pin['sha256']+suffix)
                if not os.path.lexists(dest):
                    fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(fd,'wb')as stream:stream.write(data)
                else:require(raw_file(dest,cfg['max_run_bytes'],pin['sha256'],os.getuid())==data,'Owned duplicate report drift')
                exports.append({'path':str(dest),'sha256':pin['sha256'],'kind':pin['kind']})
            kinds={p['kind']for p in exports}
            require({'robot-output','robot-report','robot-log','robot-xunit'}<=kinds,'All actual Robot reports must be public and retained')
            if gui_required:require({'screenshot','argv','pointer-action'}<=kinds,'Actual GUI/argv/action evidence not exportable')
            if case=='steamos-autoheal' or kind=='artifact':require({'nvidia-loaded','nvidia-render','gpu-restoration'}<=kinds,'Guest NVIDIA raw graphics/restoration not exportable')
            value={'status':'passed','receipt_sha256':receipt_sha,'runtime_instance_id':receipt['runtime_instance_id'],'case':case,'identity':request,'exports':exports,'stage':str(stage_path),'closure_verified':True,'active':False,'run_name':stage_path.name}
            if kind=='artifact':value.update(artifact_id=expected['artifact_id'],expected=expected,steam_os_transaction=verified)
            self.stage['create_json'](stage_path/'receipt.json',value);dump(folder/'verified.json',value)
            return value
        finally:
            lock.close()

    def ubuntu_gui_component(self,request,prepared,collected,rows,stage_path,folder):
        """Verify the real Ubuntu stage without claiming the later SteamOS stages.

        The same strict pointer/raw/frame consumer validates dynamic native
        observations after this exact normal job closes. GPU/install/update
        acceptance remains unavailable until their own real jobs run.
        """
        stage=self.stage;operand=prepared['operand'];expected=prepared['expected']
        cfg=stage['load_pinned'](prepared['normal_job_config'])
        policy=stage['load_pinned'](cfg['normalPolicyPin'])
        require(policy['kind']=='ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1'and
            policy['scope']=='NORMAL_UBUNTU_GUI_BUILD_WRITE_VIRTUAL_USB_ONLY'and
            policy['sourceCommit']==request['source_commit']==cfg['source_commit']and
            cfg['candidate']['descriptor']==expected and cfg['nonce']==request['nonce']and
            collected['identity']=={k:request[k]for k in('repository','source_commit','run_id','attempt','nonce')}and
            collected['effect']=='READ_ONLY_CURRENT_OPERATION'and collected['job_ids']==operand['job_ids'],
            'exact Root-selected Ubuntu stage, candidate and post-terminal identity')
        root=Path(prepared['normal_job_config']['path']).parent
        require(root.parent==Path(policy['operationRoot'])and root.name.endswith('-'+request['nonce'])and
            collected['job_result_path']==str(root/'runtime/job-result.json')and
            collected['robot_result_path']==str(root/'robot-result.json')and
            collected['storage_result_path']==str(root/'storage-result.json'),
            'same current admitted result paths')
        actual,actual_sha=stage['load_result'](collected['job_result_path'],16*1024**2)
        robot,_=stage['load_result'](collected['robot_result_path'],4*1024**2)
        storage,_=stage['load_result'](collected['storage_result_path'],4*1024**2)
        require(actual['kind']=='NORMAL_UBUNTU_GUI_BUILD_WRITE_JOB_V1'and
            actual['nonce']==request['nonce']and actual['source_commit']==request['source_commit']and
            actual['candidate_source_commit']==expected['source_commit']and actual['package_sha256']==expected['package_sha256']and
            actual['GUIBuildWriteReadbackAccepted']is True and actual['qemu_reaped']is True and
            actual['originals_unchanged_after']is True and actual['private_storage_closure_verified']is True and
            storage['first']is None and storage['closure']['unmountedNormally']is True and
            storage['closure']['loopDetachedNormally']is True and storage['closure']['errors']==[]and
            robot['identity']==request and robot['numeric_exit']==robot['tests_failed']==0 and
            robot['actual_pointer_calls']==robot['tests_passed']==5,
            'actual GUI/normal child/originals/Root storage/Robot closure required')
        for job_id in operand['job_ids']:
            result=rows[job_id]['result'];require(result['terminalLifecycle']['phase']=='CLOSED'and
                not result.get('reservationRetained',False),'actual canonical release required')
        gui=actual['GUI'];evidence=gui['normalRobotEvidence'];files=evidence['files']
        sender=files[evidence['gui_sender_ref']];observer=files[evidence['gui_observer_ref']]
        require(sender['sha256']==policy['programSHA256']['connection_control.py']and
            observer['sha256']==policy['programSHA256']['observer_guest.py'],
            'actual current sender/observer independently bound to Root source')
        image=gui['output']['value'];readback=actual['hostUSBReadback']
        output_dir='/home/opemosgui/opemos-robot-'+request['nonce']+'/output'
        require(Path(image['path']).parent==Path(output_dir)and
            readback['readbackSHA256']==image['sha256']and readback['imageBytes']==image['bytes']and
            readback['bytesRead']==actual['virtualUSB']['capacityBytes']==cfg['guest_operation']['usb_bytes']and
            readback['hostFlushCompleted']is True,'same actual guest output/full virtual USB readback')
        observed=dict(operand,evidence_roots=[str(root)],gui_session=evidence['gui_session'],
            gui_clock=evidence['gui_clock'],gui_controls=evidence['gui_controls'],
            gui_destination_admission=evidence['gui_destination_admission'],
            gui_sender=sender,gui_observer=observer,gui_input_path=gui['input']['value']['path'],
            gui_output_path=image['path'],gui_output_directory=output_dir)
        receipt=dict(evidence,roles={'imaging_host':{'id':operand['runtime_instance_id'],'platform':'linux',
            'architecture':'x86_64','gui_session':evidence['gui_session'],'app_process':evidence['app_process'],
            'app_window_id':evidence['app_window_id']},'virtual_usb':{'id':'opemos-'+request['nonce'],
            'backing_identity':actual['virtualUSB']['identity'],'device_identity':gui['usb']}},output=image)
        pointer=stage['validate_gui_pointer'](receipt,prepared['plan'],observed,expected)
        exports=[];remaining=policy['publicEvidenceMaxBytes']
        for pin in collected['public_evidence']:
            require(pin['public']is True and pin['kind']in{'screenshot','log','pointer-action','pointer-sender-lifecycle',
                'robot-output','robot-report','robot-log','robot-xunit'}and
                Path(pin['path']).is_relative_to(root/'runtime'),'same actual public GUI evidence only')
            actual_pin=stage['artifact_read'](pin,remaining);remaining-=actual_pin['size']
            suffix=Path(pin['path']).suffix;dest=self.reports/(request['nonce']+'-'+pin['sha256']+suffix)
            stage['retain_pin'](pin,stage_path/'artifacts'/pin['sha256'],remaining+actual_pin['size'],policy['publicEvidenceMaxBytes'])
            raw=raw_file(pin['path'],policy['publicEvidenceMaxBytes'],pin['sha256'],os.getuid())
            if not os.path.lexists(dest):
                fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            else:require(raw_file(dest,policy['publicEvidenceMaxBytes'],pin['sha256'],os.getuid())==raw,'same public report bytes')
            exports.append({'path':str(dest),'sha256':pin['sha256'],'kind':pin['kind']})
        require({'screenshot','pointer-action','robot-output','robot-log','robot-report','robot-xunit'}<=
            {x['kind']for x in exports},'actual GUI and all Robot report formats must be retained')
        value={'status':'incomplete','reason':'Ubuntu GUI Build/write/readback verified; SteamOS install/update/NVIDIA/healing not yet verified',
            'component':'ubuntu-gui-build-write-readback','component_accepted':True,'fullStackAccepted':False,
            'SteamOSOrNVIDIAAcceptance':False,'identity':request,'runtime_instance_id':operand['runtime_instance_id'],
            'actual_job_sha256':actual_sha,'pointer_proof':pointer,'virtual_usb':readback,'exports':exports,
            'closure_verified':True,'active':False,'stage':str(stage_path),'run_name':stage_path.name}
        stage['create_json'](stage_path/'receipt.json',value);dump(folder/'verified-ubuntu-stage.json',value)
        return value

    def failure_exports(self):
        if self.current is None:return {'status':'unavailable','reason':'No admitted current operation'}
        request,prepared,folder,cfg=self.current
        result={'status':'failed','closure':'UNKNOWN','exports':[]}
        try:
            collected=hook(self.profile,dict(request,action='collect'),folder/'failure-collection')
            require(collected.get('effect')=='READ_ONLY_CURRENT_OPERATION','Failure collection may not retry/control a guest')
            jobs=list(prepared['operand']['job_ids'])
            for extra in prepared.get('additional_operations',[]):jobs.extend(extra['job_ids'])
            require(len(jobs)==len(set(jobs)) and collected['job_ids']==jobs,
                    'Failure evidence belongs to another complete queue operation')
            for pin in collected.get('public_evidence',[]):
                require(pin.get('public')is True and pin['kind']in {'screenshot','log','boot-log','argv','pointer-action','pointer-sender-lifecycle','nvidia-loaded','nvidia-render','gpu-restoration','queue-closure','robot-output','robot-log','robot-report','robot-xunit'},'Private/unreviewed failure evidence refused')
                require(Path(pin['path']).is_relative_to(Path(prepared['operand']['evidence_root'])),'Failure export escapes exact reviewed evidence root')
                observed=self.stage['artifact_read'](pin,cfg['max_run_bytes'])
                data=raw_file(pin['path'],cfg['max_run_bytes'],observed['sha256'],os.getuid())
                suffix='.png'if pin['kind']=='screenshot'else '.xml'if pin['kind']in ('robot-output','robot-xunit')else '.html'if pin['kind']in ('robot-log','robot-report')else '.txt'
                dest=self.reports/(request['nonce']+'-failure-'+pin['sha256']+suffix)
                fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb')as stream:stream.write(data)
                result['exports'].append({'path':str(dest),'kind':pin['kind'],'sha256':pin['sha256']})
            result['closure']=collected.get('closure','UNKNOWN')
        except Exception as secondary:
            result['secondary_collection_error']={'type':type(secondary).__name__,'reason':str(secondary)}
        return result

    def vm(self,vm_id):
        require(vm_id in self.results,'Unknown VM ID')
        self.current=None
        try:self.results[vm_id]=self.transaction('inventory',vm_id)
        except Exception as error:
            self.results[vm_id].update(status='failed',reason=str(error),error_type=type(error).__name__,failure_exports=self.failure_exports())
            raise
        finally:self.persist()

    def platform(self,platform):
        require(platform in self.artifacts,'Unknown platform')
        errors=[];outcomes={}
        try:
            request,listed,folder=self.request('artifacts',platform)
            require(listed.get('available')is True,listed.get('reason','Current producer absent'))
            descriptors=listed['expected_executables']
            require(isinstance(descriptors,list)and descriptors and len(descriptors)<=16,'Every exact expected artifact must be enumerated')
            require(len({d['artifact_id']for d in descriptors})==len(descriptors),'Duplicate artifact descriptor')
            for expected in descriptors:
                self.stage['_EXECUTABLES']['descriptor'](expected,request['source_commit'])
                require(expected['platform']==platform,'Platform descriptor mismatch')
            for expected in descriptors:
                artifact=expected['artifact_id']
                try:
                    value=self.transaction('artifact',{'platform':platform,'artifact_id':artifact})
                    require(value['expected']==expected,'Enumeration/actual transaction descriptor changed')
                    outcomes[artifact]=value
                except Exception as error:
                    outcomes[artifact]={'status':'failed','reason':str(error),'error_type':type(error).__name__,'expected':expected,'failure_exports':self.failure_exports()}
                    errors.append(artifact+': '+str(error))
            require(not errors,'; '.join(errors))
            self.artifacts[platform]={'status':'passed','artifacts':outcomes}
        except Exception as error:
            self.artifacts[platform]={'status':'failed','reason':str(error),'error_type':type(error).__name__,'artifacts':outcomes}
            raise
        finally:self.persist()

    def persist(self):
        name=self.output/f'summary-{time.monotonic_ns()}.json'
        value=dict(self.context,vms=self.results,executable_acceptance=self.artifacts,all20_passed=all(r['status']=='passed'for r in self.results.values()),all_platforms_passed=all(r['status']=='passed'for r in self.artifacts.values()))
        try:
            dump(name,value)
            dump(self.reports/name.name,value)
        except Exception as error:
            # Actual stage receipts, queue state and public native evidence are
            # authoritative. This convenience summary must not mask FIRST.
            print('Optional outcome summary unavailable: '+type(error).__name__,file=sys.stderr)

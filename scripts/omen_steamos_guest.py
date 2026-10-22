#!/usr/bin/env python3
"""One ordinary, source-A Robot phase inside the real SteamOS output VM.

Uses the existing named observer channel. No network, arbitrary argv, raw Core
activation, production endpoint, or host control. Only authenticated A medium
code executes as controller; B is the guest/application subject. No effects on
import; the Root firmware-bound launcher admits the actual main transaction.
"""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import stat
import sys
import time
import types
import xml.etree.ElementTree as ET

PORT=Path('/dev/virtio-ports/opemos.robot.observer')
CORE=Path('/home/.steamos/open-gpu-kernel-modules-steamos-support/recovery')
PHASES=('installation','baseline','update','recovery')
WHEEL_SHA='5a194db36524604fafa1da89adebc837db9a95adf15ffd746e09ce98251e6c68'
FULL9=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
_ACTIVE=None


def need(value,reason):
    if not value:raise RuntimeError(reason)


def strict(raw):
    def pairs(rows):
        value={}
        for k,v in rows:need(k not in value,'duplicate phase JSON field');value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite phase metadata'))


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def read(path,cap,sha=None,owner=None):
    path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);sig=lambda st:{k:getattr(st,k)for k in FULL9}
        need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and not before.st_mode&0o022 and
             0<=before.st_size<=cap and(owner is None or before.st_uid==owner),'phase source/evidence permission/size')
        raw=bytearray()
        while part:=os.read(fd,min(65536,cap+1-len(raw))):raw.extend(part);need(len(raw)<=cap,'phase source/evidence overflow')
        need(len(raw)==before.st_size and sig(before)==sig(os.fstat(fd))==sig(path.lstat()),'phase held/named identity changed')
        actual=hashlib.sha256(raw).hexdigest();need(sha is None or actual==sha,'phase source/evidence hash differs')
        return bytes(raw),{'path':str(path),'size':len(raw),'sha256':actual,'identity':sig(before)}
    finally:os.close(fd)


def bind(path):
    path=Path(path);need(path.is_absolute()and path.resolve()==path,'actual observer manifest path')
    firmware=Path('/sys/firmware/qemu_fw_cfg/by_name/opt/opemos/observer-manifest-sha256/raw')
    with firmware.open('rb')as stream:expected=stream.read(257).strip().decode('ascii')
    need(re.fullmatch('[0-9a-f]{64}',expected),'Root firmware observer manifest pin absent')
    raw,pin=read(path,1048576,expected,0);manifest=strict(raw)
    need(manifest.get('kind')=='EXE_STEAMOS_PHASE_MEDIA_V1'and manifest.get('guest_uid')==1000 and
         re.fullmatch('[0-9a-f]{32}',manifest.get('nonce',''))and
         re.fullmatch('[0-9a-f]{40}',manifest.get('controller_commit','')),'exact source-A observer manifest')
    need(os.statvfs(path).f_flag&os.ST_RDONLY,'controller medium must actually be read-only')
    expected_names={'omen_steamos_guest.py','omen_steamos_native.py','omen_steamos_probe.py',
                    'omen_ci_result.py','output-install.robot','robotframework-7.5-py3-none-any.whl'}
    need(set(manifest['files'])==expected_names,'complete finite observer dependency graph')
    blobs={}
    for name,ref in manifest['files'].items():
        data,item=read(path.parent/name,16*1024**2,ref['sha256'],0)
        need(len(data)==ref['bytes'],'controller dependency size differs');blobs[name]=data
    actual=Path(__file__).absolute()
    need(actual.parent==path.parent and actual.name=='omen_steamos_guest.py'and
         read(actual,1048576)[0]==blobs[actual.name],'actual guest agent is not the verified A source')
    modules={}
    for name in('omen_steamos_native','omen_ci_result'):
        module=types.ModuleType(name);module.__file__=str(path.parent/(name+'.py'))
        need(name not in sys.modules,'preloaded guest controller module refused')
        exec(compile(blobs[name+'.py'],module.__file__,'exec'),module.__dict__)
        modules[name]=module
    wheel=path.parent/'robotframework-7.5-py3-none-any.whl'
    need(manifest['files'][wheel.name]['sha256']==WHEEL_SHA,'official exact Robot7.5 wheel')
    return manifest,pin,modules,wheel


class Channel:
    def __init__(self,deadline,inherited_fd=None):
        self.deadline=deadline;self.fd=None;self.selector=selectors.DefaultSelector();self.buffer=bytearray()
        try:
            before=PORT.lstat();need(stat.S_ISLNK(before.st_mode),'actual named virtio channel absent')
            node=PORT.resolve(strict=True)
            need(node.parent==Path('/dev')and re.fullmatch(r'vport[0-9]+p[0-9]+',node.name),'exact actual observer vport')
            need((Path('/sys/class/virtio-ports')/node.name/'name').read_text().strip()=='opemos.robot.observer','observer sysfs name differs')
            info=node.lstat();need(stat.S_ISCHR(info.st_mode)and info.st_uid==os.getuid()and
                 stat.S_IMODE(info.st_mode)==0o600,'real private desktop observer channel permission')
            sig=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_rdev)
            if inherited_fd is None:
                self.fd=os.open(node,os.O_RDWR|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
            else:
                need(type(inherited_fd)is int and inherited_fd>=3,'finite explicitly inherited observer FD')
                flags=fcntl.fcntl(inherited_fd,fcntl.F_GETFL)
                need(flags&os.O_ACCMODE==os.O_RDWR and flags&os.O_NONBLOCK,'actual inherited nonblocking RDWR observer FD')
                need(sig(info)==sig(os.fstat(inherited_fd)),'inherited FD does not name the actual owned observer port')
                self.fd=inherited_fd;os.set_inheritable(self.fd,False)
            need(sig(info)==sig(os.fstat(self.fd))==sig(node.lstat())and
                 sig(before)==sig(PORT.lstat())and PORT.resolve()==node,'observer node changed across held open')
            self.node={'path':str(node),'identity':sig(info)}
            self.selector.register(self.fd,selectors.EVENT_READ)
        except BaseException:
            self.close();raise

    def wait(self,events):
        remaining=self.deadline-time.monotonic();need(remaining>0,'original guest phase channel deadline')
        self.selector.modify(self.fd,events)
        need(self.selector.select(remaining),'guest channel deadline, not EOF')

    def send(self,value):
        raw=canonical(value)+b'\n';need(len(raw)<=65536,'finite actual observer event')
        view=memoryview(raw)
        while view:
            self.wait(selectors.EVENT_WRITE)
            try:n=os.write(self.fd,view)
            except BlockingIOError:continue
            need(n>0,'observer short write');view=view[n:]

    def receive(self):
        while b'\n'not in self.buffer:
            self.wait(selectors.EVENT_READ)
            try:part=os.read(self.fd,65537-len(self.buffer))
            except BlockingIOError:continue
            need(part,'actual observer channel EOF');self.buffer.extend(part)
            need(len(self.buffer)<=65536,'observer request overflow')
        line,_,remaining=self.buffer.partition(b'\n');self.buffer=bytearray(remaining)
        return strict(line)

    def close(self):
        errors=[]
        try:self.selector.close()
        except Exception as error:errors.append(type(error).__name__)
        if self.fd is not None:
            fd=self.fd;self.fd=None
            try:os.close(fd)
            except OSError as error:errors.append(type(error).__name__)
        need(not errors,'observer channel descriptors closure UNKNOWN: '+repr(errors))


class Session:
    def __init__(self,manifest,manifest_pin,modules,request,channel):
        self.manifest=manifest;self.manifest_pin=manifest_pin;self.modules=modules;self.request=request;self.channel=channel
        self.native=modules['omen_steamos_native'];self.runner=modules['omen_ci_result'];self.desktop=None
        self.first=None;self.secondary=[];self.files=[];self.data={};self.actions=[];self.counter=0
        self.guest=self.native.require_guest(manifest['guest_uid'])
        fields={'kind','nonce','phase','identity','targetGeneration','targetBytes','coreContract','seconds','previous'}
        need(type(request)is dict and set(request)==fields and request['kind']=='ARM_OUTPUT_PHASE_V1'and
             request['nonce']==manifest['nonce']and request['phase']in PHASES and
             type(request['seconds'])is int and 0<request['seconds']<=480,'one finite normal output phase')
        identity=request['identity']
        base_fields={'source_commit','run_id','attempt','operation_nonce','executable','consumer_job_ids'}
        need(type(identity)is dict and set(identity)in(base_fields,base_fields|{'controller_source_commit','source_roles'})and
             re.fullmatch('[0-9a-f]{40}',identity['source_commit'])and
             all(re.fullmatch('[1-9][0-9]{0,19}',identity[k])for k in('run_id','attempt'))and
             re.fullmatch('[0-9a-f]{32}',identity['operation_nonce'])and
             identity['executable']['repository']=='CorniiDog/OPEMOS.EXE'and
             identity['executable']['source_commit']==identity['source_commit']and
             identity['executable']['platform']=='windows'and
             type(identity['consumer_job_ids'])is list and 0<len(identity['consumer_job_ids'])<=32 and
             all(type(value)is str and value for value in identity['consumer_job_ids']),
             'actual protected public image-range context/package identity, not a new invented schema')
        controller=identity.get('controller_source_commit',identity['source_commit'])
        need(controller==manifest['controller_commit'],'guest controller A source differs')
        if 'source_roles'in identity:
            roles=identity['source_roles']
            need(roles['controller_commit']==controller==roles['base_commit']and
                 roles['candidate_commit']==identity['source_commit']!=controller,'guest A/B roles swapped')
        need(request['coreContract']==manifest['core_contract']and
             request['targetGeneration']and type(request['targetBytes'])is int and
             12*1024**3<=request['targetBytes']<60000000000,'exact Core/target scope')
        index=PHASES.index(request['phase']);previous=request['previous']
        need(type(previous)is list and [r['phase']for r in previous]==list(PHASES[:index]),'normal phase ordering, no replay/skip')
        phase_deadline=time.monotonic()+request['seconds'];channel.deadline=phase_deadline
        need(request['seconds']>30,'phase requires bounded evidence/teardown reservation')
        self.deadline=phase_deadline-20
        home=Path(pwd.getpwuid(os.getuid()).pw_dir)
        root=home/'.local/state'/('opemos-output-'+manifest['nonce'])
        root.mkdir(mode=0o700,parents=True,exist_ok=True)
        st=root.lstat();need(root.resolve()==root and stat.S_ISDIR(st.st_mode)and st.st_uid==os.getuid()and
             stat.S_IMODE(st.st_mode)==0o700,'actual private output phase root')
        self.output=root/request['phase'];self.output.mkdir(mode=0o700)
        need(os.statvfs(self.output).f_bavail*os.statvfs(self.output).f_frsize>=32*1024**2,
             'real guest report/capture reservation headroom')

    def capture(self,argv,name,seconds=60,require_success=True):
        need(time.monotonic()<self.deadline,'unchanged original guest phase deadline')
        self.counter+=1;directory=self.output/(str(self.counter)+'-'+name)
        env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
        # No PROJECT_TEST_MODE, test root/status tool, caller PATH, preload or
        # source override may reach real Core installed-root operations.
        try:
            receipt=self.runner.capture(argv,b'',{'max_bytes':1048576,'stderr_max_bytes':65536,
                'free_reserve_bytes':1048576},directory,min(seconds,self.deadline-time.monotonic()),env=env)
        except self.runner.TransportFailure as error:
            receipt=error.transport_receipt
        for key,row in receipt.get('streams',{}).items():
            if row.get('sha256')and row.get('identity'):
                raw,pin=read(row['path'],1048577,row['sha256'],os.getuid())
                need(pin['identity']==row['identity'],'ordinary capture raw full9 differs')
                self.files.append(dict(pin,kind='native-'+key,public=False))
        command_pin=self.native.create(directory/'actual-command.json',canonical({'argv':argv,'receipt':receipt}))
        self.files.append(dict(command_pin,kind='actual-command-receipt',public=False))
        if require_success:
            need(receipt.get('complete')is True and receipt.get('local_reaped')is True and
                 receipt.get('numeric_exit')==0,'actual ordinary guest command failed; raw capture retained')
        row=receipt['streams']['stdout'];raw=read(row['path'],1048576,row['sha256'],os.getuid())[0]
        return raw if require_success else(raw,receipt)

    def probe(self,action):
        path=Path(self.manifest_pin['path']).parent/'omen_steamos_probe.py'
        raw,transport=self.capture(['/usr/bin/sudo','-n','/usr/bin/python3','-I','-B',str(path),action,self.manifest_pin['path']],
                         'probe-'+action,30,require_success=False)
        value=strict(raw)
        need(value['kind']=='EXE_STEAMOS_NATIVE_OBSERVATION_V1'and value['guest']['boot_id']==self.guest['boot_id']and
             value['guest']['uid']==0,'actual Root guest metadata identity mismatched')
        for ref in value['raw_files']:
            raw,pin=read(ref['path'],1048577,ref['sha256'],0)
            need(pin['identity']==ref['identity'],'privileged probe raw publication changed')
            self.files.append(dict(pin,kind=ref['kind'],public=False))
        self.data[action]=value
        need(value['first']is None and transport.get('complete')is True and
             transport.get('local_reaped')is True and transport.get('numeric_exit')==0,
             'actual Root guest metadata failed; inner and outer raw evidence retained')
        return value['value']

    def verify_target(self):
        observed=self.probe('disks');target=observed['target'];parts=observed['partitions']
        need(target['size']==self.request['targetBytes'],'actual target capacity differs from creator reservation')
        phase=self.request['phase'];media=observed['installation_media']
        need(bool(media)is(phase=='installation'),'installation medium presence differs from phase')
        def unique(label):
            found=[p for p in parts if p.get('partlabel')==label]
            need(len(found)==1 and found[0].get('uuid'),'actual unique installed partition UUID: '+label)
            return found[0]
        if phase!='installation':
            roots=[p for p in parts if '/'in(p.get('mountpoints')or[])]
            efi=[p for p in parts if any(m in('/efi','/boot/efi')for m in(p.get('mountpoints')or[]))]
            need(len(roots)==len(efi)==1,'actual current root/EFI mounts must belong to same target')
            need(roots[0].get('uuid')and efi[0].get('uuid'),'actual booted root/EFI UUIDs')
            self.data.update(installedRootUUID=roots[0]['uuid'],installedEFIUUID=efi[0]['uuid'])
        self.data.update(targetDevice=target['path'],mediaDevice=media[0]['path']if media else None,
                         mediaDetached=not bool(media),bootID=self.guest['boot_id'])
        return observed

    def core(self,action):
        need(action in('status','update','startup','health','inspect','guard','installed-health'),'finite ordinary Core action')
        wanted=self.manifest['core_sources'];required='lib/installed_update_transaction.py'if action in('update','startup','health','inspect')else'bootstrap/recoveryctl.sh'
        need(required in wanted,'authenticated Core entrypoint identity absent')
        for relative,ref in wanted.items():
            need(type(relative)is str and not relative.startswith('/')and '..'not in Path(relative).parts,'Core source manifest relative path')
            raw,pin=read(CORE/relative,16*1024**2,ref['sha256'],0)
            need(len(raw)==ref['bytes'],'installed Core source size differs')
        if action in('status','guard','installed-health'):
            argv=['/usr/bin/sudo','-n','/usr/bin/bash',str(CORE/'bootstrap/recoveryctl.sh'),action,'--json']
        else:
            # This is the ordinary Core filename entrypoint. Its protected
            # adjacent libraries must remain importable; -I would remove that
            # script directory and is NOT equivalent to Core's public CLI.
            argv=['/usr/bin/sudo','-n','/usr/bin/python3','-B',str(CORE/'lib/installed_update_transaction.py'),action,
                  '--root','/','--policy-root',str(CORE)]
            if action=='update':
                argv+=['--support',str(CORE),'--kernel',self.guest['kernel'],'--nvidia',self.manifest['nvidia_version']]
                cached=self.manifest.get('cached_product')
                if cached:
                    # Finite preauthenticated retained product DATA, not an
                    # arbitrary command or silent online/source fallback.
                    need(set(cached)=={'directory','archive','archiveSHA256'}and
                         re.fullmatch('[0-9a-f]{64}',cached['archiveSHA256']),'exact retained Core product')
                    argv+=['--cache',cached['directory'],'--archive',cached['archive'],'--archive-sha256',cached['archiveSHA256']]
        raw=self.capture(argv,'core-'+action,min(300,self.deadline-time.monotonic()))
        lines=raw.splitlines();need(0<len(lines)<=32 and all(line.strip()for line in lines),'complete bounded Core JSON lines')
        values=[strict(line)for line in lines]
        need(all(type(value)is dict for value in values),'Core structured result objects')
        self.data['core-'+action]=values;return values

    def status(self):
        rows=self.core('status');need(len(rows)==1,'one Core status document')
        value=rows[0];verification=value.get('moduleVerification',{});records=verification.get('records',[])
        names={str(r.get('name','')).replace('-','_')for r in records}
        need(value.get('schemaVersion')==1 and value.get('status')=='healthy'and
             value.get('reason')not in('installed_generation_awaits_boot_health','retained_install_awaits_driver')and
             value.get('target')=={'kernelVersion':self.guest['kernel'],'nvidiaVersion':self.manifest['nvidia_version']}and
             verification.get('status')=='verified'and len(records)==5 and
             names=={'nvidia','nvidia_modeset','nvidia_drm','nvidia_uvm','nvidia_peermem'}and
             all(r.get('present')is True and r.get('exactKernel')is True and r.get('exactUserspace')is True for r in records),
             'actual current Core five-module/payload/boot status not healthy')
        return value

    def ensure_desktop(self):
        if self.desktop is None:self.desktop=self.native.NativeDesktop(self.manifest['guest_uid'],self.deadline)
        return self.desktop

    def wait(self,function,reason,seconds=30):
        until=min(self.deadline,time.monotonic()+seconds);observations=[]
        while True:
            try:return function()
            except self.native.NotReady as missing:
                if not observations:observations.append({'first_ns':time.monotonic_ns(),'reason':str(missing)})
                if time.monotonic()>=until:
                    self.native.create(self.output/('wait-failure-'+str(self.counter)+'.json'),
                        canonical({'reason':reason,'observations':observations,'last_ns':time.monotonic_ns()}))
                    raise RuntimeError(reason)from missing
                time.sleep(min(.1,max(0,until-time.monotonic())))

    def click(self,application,name,role='push button',prefix=False,required_text=None):
        desktop=self.ensure_desktop()
        spec=self.wait(lambda:desktop.discover(application,name,role,prefix=prefix,required_text=required_text),
                       'actual normal native control unavailable: '+name)
        number=len(self.actions)+1
        self.files.append(desktop.screenshot(self.output/('action-'+str(number)+'-before.png')))
        ledger=self.output/('action-'+str(number)+'.jsonl')
        result=desktop.click(spec,ledger)
        raw,pin=read(ledger,1048576,owner=os.getuid());self.files.append(dict(pin,kind='pointer-action',public=True))
        self.files.append(desktop.screenshot(self.output/('action-'+str(number)+'-after.png')))
        self.actions.append({'selector':spec,'result':result,'ledger':pin})
        return spec,result

    def welcome(self):
        need(not self.data['disks']['value']['partitions'],'fresh blank target required before normal welcome mutation')
        profile=self.manifest['welcome']
        for path,ref in profile['assets'].items():
            need(path.startswith(('/usr/lib/opemos-install-media/','/usr/share/opemos-install-media/')),
                 'fixed normal welcome payload root')
            raw,pin=read(path,2*1024**2,ref['sha256'],0);need(len(raw)==ref['bytes'],'actual B welcome asset size')
        helper='/usr/lib/opemos-install-media/opemos-install-helper'
        read(helper,1048576,profile['helperSHA256'],0)
        inventory=self.capture([helper,'inventory'],'normal-welcome-inventory',30).decode('utf-8',errors='strict')
        candidates=[]
        for line in inventory.splitlines():
            fields=line.split('\t');need(len(fields)==7,'actual normal welcome inventory schema')
            if fields[0]==self.data['targetDevice']:
                need(fields[4].strip()=='OPEMOSOUTPUTTARGET'and int(fields[1])==self.request['targetBytes']and
                     re.fullmatch('[0-9a-f]{64}',fields[2]),'normal UI inventory differs from actual virtual target')
                candidates.append(fields)
        need(len(candidates)==1,'one real eligible virtual target in normal welcome inventory')
        selected=candidates[0];desktop=self.ensure_desktop()
        application=self.wait(lambda:desktop.application(profile['title'],profile['rendererSHA256']),
                              'normal source-bound welcome application unavailable')
        self.click(application,'Install SteamOS with NVIDIA drivers',prefix=True)
        # Resolve the actual ordinary button from the observed device/model,
        # then pin its native ID/role/process/window/hit before mouse input.
        self.click(application,selected[3],prefix=True,required_text=selected[0])
        self.click(application,'Continue')
        field,_=self.click(application,'Confirmation phrase',role='entry')
        phrase='ERASE '+Path(selected[0]).name
        typing=desktop.type_confirmation(application,field,phrase,self.output/'confirmation-keys.jsonl')
        raw,pin=read(self.output/'confirmation-keys.jsonl',1048576,owner=os.getuid())
        self.files.append(dict(pin,kind='native-key-ledger',public=True))
        self.data['confirmation']=typing
        state=Path(pwd.getpwuid(os.getuid()).pw_dir)/'.local/state/open-opemos'
        before={p.name for p in state.glob('install-result-*.json')}
        _,begin=self.click(application,'Begin installation')
        self.data['welcome_begin_up_attempted_ns']=begin['up_attempted_ns']
        result=None
        while time.monotonic()<self.deadline:
            paths=[p for p in state.glob('install-result-*.json')if p.name not in before]
            need(len(paths)<=1,'ambiguous normal welcome terminal producer; no retry')
            if paths and stat.S_IMODE(paths[0].lstat().st_mode)==0o400:
                raw,pin=read(paths[0],65536,owner=os.getuid());value=strict(raw)
                need(value['kind']=='EXE_WELCOME_INSTALL_TERMINAL_V1'and value['mock']is False and
                     value['boot_id']==self.guest['boot_id']and value['device']==selected[0]and
                     value['device_identity']==selected[2]and value['mode']=='all'and
                     type(value['started_ns'])is int and value['started_ns']>=begin['up_attempted_ns']and
                     type(value['finished_ns'])is int and value['finished_ns']>=value['started_ns']and
                     value['helper']['sha256']==profile['helperSHA256']and
                     self.native.process(value['server_pid'],os.getuid())['start']==value['server_start']and
                     type(value['numeric_exit'])is int and value['numeric_exit']==0 and value['first']is None and
                     value['secondary']==[]and value['stdout_eof']is True and value['stdout_closed']is True and
                     value['original_reaped']is True and type(value['child']['start'])is int and value['child']['start']>0,
                     'actual normal welcome install failed or process/source/terminal custody unknown')
                self.files.append(dict(pin,kind='normal-welcome-result',public=True))
                log=state/value['log_file'];need(log.parent==state and log.name==value['log_file'],'normal install log basename')
                raw,log_pin=read(log,1048577,owner=os.getuid())
                need(len(raw)==value['capture_bytes'],'normal full raw install log size differs')
                self.files.append(dict(log_pin,kind='install-log',public=True));result=value;break
            time.sleep(.1)
        need(result is not None,'actual normal welcome terminal result unavailable before original deadline')
        self.data['welcome_result']=result
        observed=self.probe('disks');parts=observed['partitions']
        need(all(not any(p.get('mountpoints')or[])for p in parts),'target remains mounted after normal installer return')
        def one(label):
            matches=[p for p in parts if p.get('partlabel')==label]
            need(len(matches)==1 and matches[0].get('uuid'),'actual installed target partition missing/ambiguous: '+label)
            return matches[0]
        # These are the normal EXE mounted-image handoff labels, not a new OS
        # slot policy. The subsequent actual boot MUST match this installed
        # root/EFI pair; no inferred or fabricated boot UUID is emitted here.
        root=one('rootfs-A');efi=one('efi-A')
        self.data.update(installedRootUUID=root['uuid'],installedEFIUUID=efi['uuid'],
                         installedPartitionUUIDs={p['partlabel']:p['uuid']for p in parts},activeRootObserved=False)
        self.files.append(desktop.screenshot(self.output/'welcome-completed.png'))

    def render(self):
        desktop=self.ensure_desktop();value=desktop.nvidia_render(self.manifest['nvidia_version'])
        pin=self.native.create(self.output/'nvidia-render.json',canonical(value))
        self.files.append(dict(pin,kind='nvidia-render',public=True));self.data['nvidia_render']=value
        self.files.append(desktop.screenshot(self.output/'native-phase-desktop.png'))

    def execute(self):
        phase=self.request['phase']
        if phase=='installation':return self.welcome()
        previous=self.request['previous']
        need(all(row['installedRootUUID']==self.data['installedRootUUID']and row['installedEFIUUID']==self.data['installedEFIUUID']
                 for row in previous),'actual booted target/root/EFI differs from installation lineage')
        need(all(row.get('bootID')!=self.guest['boot_id']for row in previous if row['phase']!='installation'),
             'actual distinct installed guest boot required')
        if phase=='baseline':
            self.data['baseline_status']=self.status();return self.render()
        if phase=='update':
            self.data['before_update_status']=self.status();self.render()
            result=self.core('update')
            need(len(result)==1 and result[0].get('state')=='pending-health'and
                 result[0].get('rebootHealthVerified')is False and result[0].get('rebootRequired')is True,
                 'ordinary Core update did not produce a genuine pending-health reboot transaction')
            intent=self.probe('core-intent')
            need(intent['phase']=='pending-health'and intent['preparedBootId']==self.guest['boot_id']and
                 intent['kernel']==self.guest['kernel'],'actual newly prepared Core generation differs')
            self.data['update_intent']=intent;return result
        # Recovery boot uses the actual Core owner, never a raw test plan or
        # retagging a restored previous generation as a successful candidate.
        startup=self.core('startup');health=self.core('installed-health');inspection=self.core('inspect')
        need(len(inspection)==1 and inspection[0].get('state')=='healthy'and
             inspection[0].get('currentRuntimeMatches')is True and inspection[0].get('rebootRequired')is False,
             'actual candidate boot/runtime health not verified')
        # Core inspect is read-only and deliberately does not acknowledge boot
        # health. The actual installed-health acknowledgement below, plus the
        # retained matching intent/new boot, supplies that distinct evidence.
        need(any(v.get('state')=='healthy'and v.get('rebootHealthVerified')is True for v in health),
             'multi-line installed-health did not establish driver boot health')
        need(not any(v.get('state')in('restored','no-pending-intent','held-failed-product')for v in startup+health),
             'restored/absent/held generation cannot pass current candidate recovery')
        intent=self.probe('core-intent');updated=previous[-1]['nativeData']['update_intent']
        need(intent['generation']==updated['generation']and intent['phase']=='healthy'and
             intent['preparedBootId']==updated['preparedBootId']!=self.guest['boot_id']and
             intent['attemptBootId']==self.guest['boot_id']and
             all(intent[k]==updated[k]for k in('kernel','target','authoritySHA256','filesSHA256')),
             'recovery acknowledged another retained driver generation')
        self.data['recovered_intent']=intent;self.data['recovery_status']=self.status();return self.render()

    def verify(self):
        phase=self.request['phase']
        need(self.first is None and not self.secondary,'native phase has retained first/secondary failure')
        need(self.data.get('installedRootUUID')and self.data.get('installedEFIUUID'),'actual target UUIDs absent')
        if phase=='installation':need(self.data.get('welcome_result')is not None and self.actions,'ordinary welcome transaction absent')
        else:need(self.data.get('nvidia_render')is not None,'actual native NVIDIA render absent')
        if phase=='update':need(self.data.get('update_intent',{}).get('phase')=='pending-health','pending candidate intent absent')
        if phase=='recovery':need(self.data.get('recovered_intent',{}).get('phase')=='healthy','actual reboot health absent')
        return {'phase':phase,'guest':self.guest,'targetGeneration':self.request['targetGeneration'],
                'native_UI_or_GPU_proof':'actual observations retained; Root independent acceptance/closure still required'}

    def record_failure(self,error):
        if self.first is None:
            self.first={'type':type(error).__name__,'reason':str(error)[:700]}
            if isinstance(error,self.native.NotReady):self.first['native_readiness']=getattr(error,'evidence',None)
            if self.desktop is not None:
                self.first['actual_native_hit']=getattr(self.desktop,'last_hit',None)
                self.first['actual_native_discovery']=getattr(self.desktop,'last_discovery',None)
                self.first['actual_x_recipient']=getattr(self.desktop,'last_recipient',None)
                self.first['actual_x_window_join']=getattr(self.desktop,'last_x_windows',None)
        else:self.secondary.append({'type':type(error).__name__,'reason':str(error)[:700]})

    def close(self):
        if self.desktop is not None:
            try:self.desktop.close()
            except BaseException as error:self.record_failure(error);raise


class OPEMOSSteamOS:
    ROBOT_LIBRARY_SCOPE='SUITE'
    ROBOT_AUTO_KEYWORDS=False
    def get_keyword_names(self):return ['Verify Exact Guest Target','Execute Ordinary Output Phase','Verify Current Output Phase','Close Native Output Phase']
    def run_keyword(self,name,args,kwargs=None):
        need(_ACTIVE is not None,'ordinary source-bound guest session required')
        try:
            if name=='Verify Exact Guest Target':return _ACTIVE.verify_target()
            if name=='Execute Ordinary Output Phase':return _ACTIVE.execute()
            if name=='Verify Current Output Phase':return _ACTIVE.verify()
            if name=='Close Native Output Phase':return _ACTIVE.close()
            raise RuntimeError('unknown finite output phase keyword')
        except BaseException as error:_ACTIVE.record_failure(error);raise


def reports(session,exit_code):
    """Read actual Robot outputs, including failures; never synthesize reports."""
    raw,pin=read(session.output/'output.xml',16*1024**2,owner=os.getuid())
    root=ET.fromstring(raw)
    need(root.tag=='robot'and root.get('generator','').startswith('Robot 7.5'),
         'actual pinned Robot producer absent')
    tests=root.findall('.//test');need(len(tests)==1,'one ordinary complete output phase test required')
    states=[test.find('status')for test in tests]
    need(all(row is not None and row.get('status')in('PASS','FAIL','SKIP')for row in states),
         'actual Robot test statuses absent')
    result={'numeric_exit':exit_code,'tests':len(tests),
            'passed':sum(row.get('status')=='PASS'for row in states),
            'failed':sum(row.get('status')=='FAIL'for row in states),
            'skipped':sum(row.get('status')=='SKIP'for row in states),'output':pin}
    need((exit_code==0)==(result['passed']==1 and not result['failed']and not result['skipped']),
         'actual Robot exit/status disagreement')
    for name in('report.html','log.html','xunit.xml'):
        _,ref=read(session.output/name,16*1024**2,owner=os.getuid())
        result[name]=ref
    return result


def export_files(session):
    """Stream retained bytes, not paths interpreted by a host shell.

    The receiver must create exclusively, verify each EOF digest and bind the
    final transcript to the exact ARM identity. A sent event is not a host
    persistence acknowledgement or actual VM/process closure.
    """
    selected={}
    for ref in session.files:
        selected[str(Path(ref['path']))]=ref
    for directory,dirs,names in os.walk(session.output,followlinks=False):
        for child in dirs:
            need(not(Path(directory)/child).is_symlink(),'report directory symlink refused')
        for name in names:
            path=Path(directory)/name
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                need(stat.S_ISREG(os.fstat(fd).st_mode)and os.fstat(fd).st_uid==os.getuid(),
                     'owned actual Robot/native output required before durable sealing')
                os.fsync(fd)
            finally:os.close(fd)
            _,ref=read(path,16*1024**2,owner=os.getuid());selected[str(path)]=ref
    # In particular update reports must survive the later explicitly admitted
    # abrupt VM stop. Numeric Robot exit/closed Python files alone is not
    # durable directory publication.
    directories=[Path(root)for root,_,_ in os.walk(session.output,followlinks=False)]
    for directory in sorted(directories,key=lambda path:len(path.parts),reverse=True):
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(fd)
        finally:os.close(fd)
    fd=os.open(session.output.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(session.output.parent.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
    need(len(selected)<=256,'finite phase evidence inventory exceeded')
    total=0;inventory=[]
    for number,(path,expected)in enumerate(sorted(selected.items())):
        raw,ref=read(path,8*1024**2,expected['sha256'],expected['identity']['st_uid'])
        need(ref['identity']==expected['identity'],'retained phase file changed before export')
        total+=len(raw);need(total<=32*1024**2,'original complete phase evidence cap exceeded')
        try:name=str(Path(path).relative_to(session.output)).replace('/','__')
        except ValueError:name='external-'+str(number)+'-'+Path(path).name
        need(re.fullmatch(r'[A-Za-z0-9_.-]{1,180}',name),'finite unambiguous exported evidence name')
        row={'id':number,'name':name,'bytes':len(raw),'sha256':ref['sha256'],
             'guest_identity':ref['identity'],'kind':expected.get('kind','robot-or-native-report')}
        session.channel.send({'kind':'PHASE_FILE_BEGIN_V1','nonce':session.request['nonce'],
                              'phase':session.request['phase'],'file':row})
        for offset in range(0,len(raw),32768):
            session.channel.send({'kind':'PHASE_FILE_CHUNK_V1','id':number,'offset':offset,
                                  'data':base64.b64encode(raw[offset:offset+32768]).decode('ascii')})
        # Revalidate after the whole transfer, not just before its first byte.
        need(read(path,8*1024**2,ref['sha256'],ref['identity']['st_uid'])[1]==ref,
             'phase file changed while streaming')
        session.channel.send({'kind':'PHASE_FILE_END_V1','id':number,'bytes':len(raw),
                              'sha256':ref['sha256']})
        inventory.append(row)
    return inventory,total


def main(argv=None):
    global _ACTIVE
    argv=sys.argv[1:]if argv is None else argv
    need(len(argv)==1 or len(argv)==3 and argv[1]=='--channel-fd'and re.fullmatch('[0-9]{1,6}',argv[2]),
         'one firmware-bound manifest and optional actual inherited observer FD')
    manifest,pin,modules,wheel=bind(argv[0])
    guest=modules['omen_steamos_native'].require_guest(manifest['guest_uid'])
    channel=Channel(time.monotonic()+180,int(argv[2])if len(argv)==3 else None)
    session=None;first=None;secondary=[];result=None
    try:
        with open('/proc/self/cmdline','rb')as command_file:command_raw=command_file.read(32769)
        need(0<len(command_raw)<=32768 and command_raw.endswith(b'\0'),'actual finite guest agent argv observation')
        actual_argv=[part.decode('utf-8',errors='strict')for part in command_raw[:-1].split(b'\0')]
        channel.send({'kind':'OUTPUT_PHASE_HELLO_V1','controller_commit':manifest['controller_commit'],
                      'nonce':manifest['nonce'],'manifest_sha256':pin['sha256'],'guest':guest,
                      'agent_sha256':manifest['files']['omen_steamos_guest.py']['sha256'],
                      'agent_argv':actual_argv,
                      'agent':modules['omen_steamos_native'].process(os.getpid(),os.getuid()),
                      'parent':modules['omen_steamos_native'].process(os.getppid(),os.getuid())})
        request=channel.receive();session=Session(manifest,pin,modules,request,channel);_ACTIVE=session
        need('robot'not in sys.modules,'preloaded Robot controller refused')
        sys.path.insert(0,str(wheel))
        import robot
        need(robot.__version__=='7.5'and str(robot.__file__).startswith(str(wheel)+'/'),
             'actual Robot module is not the pinned read-only wheel')
        # Robot imports the already authenticated controller namespace. This is
        # ordinary library registration, not replacing a method under test.
        need('opemos_output_phase_controller'not in sys.modules,'preloaded phase library refused')
        sys.modules['opemos_output_phase_controller']=sys.modules[__name__]
        exit_code=robot.run(str(Path(pin['path']).parent/'output-install.robot'),
            outputdir=str(session.output),output='output.xml',report='report.html',log='log.html',
            xunit='xunit.xml',console='none',loglevel='INFO',
            variable=['PHASE:'+request['phase'],'PHASE_TIMEOUT:'+str(max(1,int(session.deadline-time.monotonic())))+' seconds'])
        need(type(exit_code)is int,'actual Robot numeric exit absent')
        result=reports(session,exit_code)
        if exit_code:session.record_failure(RuntimeError('ordinary Robot phase failed: '+str(exit_code)))
    except BaseException as error:
        first={'type':type(error).__name__,'reason':str(error)[:700]}
        if session is not None:session.record_failure(error)
    finally:
        if session is not None:
            try:session.close()
            except BaseException as error:secondary.append({'type':type(error).__name__,'reason':str(error)[:700]})
    try:
        need(session is not None,'phase ARM/session never established')
        document={'kind':'ACTUAL_STEAMOS_PHASE_DOCUMENT_V1','identity':session.request['identity'],
                  'nonce':manifest['nonce'],'phase':session.request['phase'],'guest':session.guest,
                  'nativeData':session.data,'actions':session.actions,'first':session.first or first,
                  'secondary':session.secondary+secondary}
        document_pin=session.native.create(session.output/'native-phase.json',canonical(document))
        files,total=export_files(session)
        terminal={'kind':'OUTPUT_PHASE_TERMINAL_V1','identity':session.request['identity'],
            'nonce':manifest['nonce'],'phase':session.request['phase'],
            'targetGeneration':session.request['targetGeneration'],'guest':session.guest,
            'first':({key:(session.first or first).get(key)for key in('type','reason')}
                     if session.first or first else None),'secondary':session.secondary+secondary,
            'robot':result,'native_document_sha256':document_pin['sha256'],
            'inventory_sha256':hashlib.sha256(canonical(files)).hexdigest(),'file_count':len(files),
            'file_bytes':total,'vm_closure':'UNKNOWN; host independent proof required',
            'agent_process_closure':'UNKNOWN; actual parent numeric reap required',
            'completed':bool(result and result['numeric_exit']==0 and session.first is None and
                             first is None and not session.secondary and not secondary)}
        channel.send(terminal)
        return 0 if terminal['completed']else 1
    finally:
        _ACTIVE=None
        channel.close()


if __name__=='__main__':
    raise SystemExit(main())

"""Finite output-install successor of the existing queue/libvirt transaction.

No CLI, queue submission, installed source change or effect occurs on import.
Root installs/adopts the entire authenticated source graph and supplies a NEW
finite grant. Historical R69 grants are deliberately rejected. The existing
readonly queue peer, controller custody, AUTODESTROY/event driver, GPU restore
and descriptor finalizers remain the underlying native implementation.
"""
import hashlib
import base64
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types
import uuid
import xml.etree.ElementTree as ET

PHASES = ('installation', 'baseline', 'update', 'recovery')
ROOT_KIND = 'ROOT_EXACT_OUTPUT_INSTALL_FOUR_BOOT_V1'
MINIMUM_INSTALL_BYTES = 12 * 1024**3
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


def identity(info):
    return {key: getattr(info, key) for key in FIELDS}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def strict(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate protected JSON field'); value[key] = item
        return value
    def constant(value):
        raise ValueError('nonfinite protected JSON constant: ' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def same_guest_epoch(before,after):
    """Stable OS epoch plus progressing observations, never host-clock mixing."""
    fields={'virtualization','numeric_exit','boot_id','kernel','architecture','uid','clock_ns'}
    need(type(before)is dict and type(after)is dict and set(before)==set(after)==fields,
         'complete actual guest observation schema')
    need(type(before['boot_id'])is str and str(uuid.UUID(before['boot_id']))==before['boot_id']
         and uuid.UUID(before['boot_id']).int!=0,'actual canonical nonzero guest boot identity')
    need(all(before[key]==after[key]for key in fields-{'clock_ns'})and
         before['virtualization']in('kvm','qemu')and type(before['numeric_exit'])is int and before['numeric_exit']==0
         and type(after['numeric_exit'])is int and type(before['kernel'])is str and 0<len(before['kernel'])<=256 and
         before['architecture']=='x86_64'and type(before['uid'])is int and before['uid']==1000 and
         all(type(row['clock_ns'])is int and row['clock_ns']>0 for row in(before,after))and
         0<=after['clock_ns']-before['clock_ns']<=480*1000000000,
         'guest epoch changed or monotonic observation moved backwards/exceeded original phase cap')
    return True


def pop_guest_frame(buffer):
    """One bounded line, permitting coalesced frames from a real byte stream."""
    need(type(buffer)is bytearray and len(buffer)<=65537,'finite guest receive buffer')
    boundary=buffer.find(b'\n')
    if boundary<0:
        need(len(buffer)<=65536,'guest channel frame overflow before newline')
        return None
    need(0<boundary<65536,'guest channel frame overflow/empty line')
    raw=bytes(buffer[:boundary]);del buffer[:boundary+1]
    value=strict(raw);need(type(value)is dict,'guest event must be an object')
    return value


def protected_bytes(ref, mode=0o400, grant=False):
    """Bootstrap Root custody before executing any external backend source."""
    path = Path(ref['path']); held = []; chain = []; primary = None
    need(path.is_absolute() and '..' not in path.parts and 3 <= len(path.parts) <= 16,
         'bounded absolute protected operand')
    if grant:
        need(path.parts[1] == 'run' and path.parts[2].startswith('opemos-'), 'exact transient Root grant')
        mounts = [line.split(' - ', 1) for line in Path('/proc/self/mountinfo').read_text().splitlines()]
        need(any(left.split()[4] == '/run' and right.split()[0] == 'tmpfs' for left, right in mounts),
             'actual transient /run tmpfs grant')
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        held.append(fd); chain.append((Path('/'), fd))
        for part in path.parts[1:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            held.append(fd); chain.append((chain[-1][0] / part, fd))
        for name, handle in chain:
            info = os.fstat(handle)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                 and not info.st_mode & 0o022 and identity(info)
                 == identity(name.lstat()), 'protected held/named Root ancestry')
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd); held.append(leaf)
        before = os.fstat(leaf)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode
             and 0 < before.st_size <= 1024**2, 'protected Root leaf mode/type/size')
        raw = bytearray()
        while block := os.read(leaf, 65536):
            raw.extend(block); need(len(raw) <= 1024**2, 'protected operand overflow')
        need(identity(before) == identity(os.fstat(leaf))
             == identity(path.lstat()) == ref['identity']
             and len(raw) == ref['bytes'] and hashlib.sha256(raw).hexdigest() == ref['sha256'],
             'protected held/named operand full9/EOF/hash')
        for name, handle in chain:
            need(identity(os.fstat(handle)) == identity(name.lstat()),
                 'protected ancestor replaced during read')
        return bytes(raw)
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        for fd in reversed(held):
            try: os.close(fd)
            except OSError as error: errors.append(str(error))
        if errors:
            if primary is not None: primary.add_note('protected descriptor closure UNKNOWN: ' + repr(errors))
            else: raise ValueError('protected descriptor closure UNKNOWN: ' + repr(errors))


def backend(refs):
    """Load only the separately Root-adopted existing native sources.

    All bytes are held, hashed and checked before ANY module is executed. No
    sibling source checkout, mutable sys.path discovery, model or replacement
    adapter can silently supply the native implementation.
    """
    names = ('libvirt_peer', 'libvirt_access', 'libvirt_native', 'libvirt_producer', 'owned_command')
    need(os.geteuid() == 0 and set(refs) == set(names), 'Root exact existing native source graph')
    sources = {}
    for name in names:
        ref = refs[name]
        sources[name] = protected_bytes(ref, mode=0o444)
    need(not any(name in sys.modules for name in names), 'no preloaded native module adoption')
    loaded = {}
    try:
        for name in names:
            module = types.ModuleType(name); module.__file__ = refs[name]['path']
            sys.modules[name] = module; loaded[name] = module
            exec(compile(sources[name], module.__file__, 'exec'), module.__dict__)
    except BaseException:
        for name, module in loaded.items():
            if sys.modules.get(name) is module:
                del sys.modules[name]
        raise
    return loaded


def output_runner(grant):
    """No privileged sys.path import before the new Root grant is verified."""
    need('vm_write_ceiling' not in sys.modules and 'root_output_runner' not in sys.modules,
         'fresh exact output runner namespace, no preloaded adapter adoption')
    refs = [('vm_write_ceiling', grant['outputCeilingPin']), ('root_output_runner', grant['outputRunnerPin'])]
    sources = [(name, ref, protected_bytes(ref, mode=0o444)) for name, ref in refs]
    loaded = {}
    try:
        for name, ref, raw in sources:
            module = types.ModuleType(name); module.__file__ = ref['path']
            sys.modules[name] = module; loaded[name] = module
            exec(compile(raw, ref['path'], 'exec'), module.__dict__)
        runner = loaded['root_output_runner']
        need(runner.OUTPUT_INSTALL_MINIMUM_BYTES == MINIMUM_INSTALL_BYTES, 'same production layout minimum')
        return runner
    except BaseException:
        for name, module in loaded.items():
            if sys.modules.get(name) is module: del sys.modules[name]
        raise


def scope(grant, request, candidate, boot, now):
    """New finite grant, not a broadened R69 noInstall/twoBoot grant."""
    need(grant.get('kind') == ROOT_KIND and grant.get('RootIssued') is True
         and grant.get('runtimeAuthorized') is True and grant.get('MODEL_ONLY') is not True,
         'new exact actual output-install authority required')
    need(grant.get('request') == request and grant.get('candidate') == candidate
         and grant.get('bootID') == boot and grant.get('phases') == list(PHASES)
         and grant.get('maxBoots') == 4 and grant.get('noNIC') is True,
         'exact canonical output request/candidate/current boot/four phases')
    need(all(type(grant.get(k)) in (int, float) for k in ('issuedUnix', 'startBeforeUnix', 'wholeDeadlineUnix'))
         and grant['issuedUnix'] <= now < grant['startBeforeUnix'] <= grant['issuedUnix'] + 300
         and now < grant['wholeDeadlineUnix'] <= grant['issuedUnix'] + 900,
         'finite original grant clocks; no refreshed deadline')
    need(candidate['media'] == candidate['original'] and candidate['target'] == candidate['working']
         and candidate['target']['bytes'] >= MINIMUM_INSTALL_BYTES,
         'media/original and distinct installed target/working roles')
    need(candidate['media']['path'] != candidate['target']['path']
         and tuple(candidate['media']['identity'][k] for k in ('st_dev', 'st_ino'))
         != tuple(candidate['target']['identity'][k] for k in ('st_dev', 'st_ino')),
         'immutable media is never the installed writable target')
    need(request['leaseNonce'] == candidate['nonce']
         and re.fullmatch(r'[0-9a-f]{32}', candidate['nonce'])
         and type(candidate['targetGeneration']) is str and candidate['targetGeneration']
         and candidate['coreContract']['repository'] == 'CorniiDog/open-gpu-kernel-modules-steamos-support'
         and re.fullmatch(r'[0-9a-f]{40}', candidate['coreContract']['commit'])
         and re.fullmatch(r'[0-9a-f]{64}', candidate['coreContract']['manifestSHA256']),
         'exact fresh lease/generation and authenticated immutable Core contract')
    need(set(grant['phasePreflights']) == set(PHASES), 'four exact Root current hardware/owner preflight producers')
    for phase, command in grant['phasePreflights'].items():
        need(command['phase'] == phase and command['request'] == request
             and command['identity'] == candidate['identity']
             and type(command['preflightArgv']) is list and 1 <= len(command['preflightArgv']) <= 32
             and all(type(x) is str and '\0' not in x for x in command['preflightArgv'])
             and command['preflightArgv'][0] == command['toolPin']['path'],
             'exact source-bound Root admission producer, no shell/interpolation')
        need(type(command['seconds']) is int and 0 < command['seconds'] <= 480
             and command['preflightArgv'][0] == command['toolPin']['path']
             and type(command['sourcePins']) is list and command['sourcePins'],
             'finite Root admission command; ordinary phase/readback are implemented here')
        expected_stop = 'controller-autodestroy' if phase == 'update' else 'guest-shutdown'
        need(command['stopMode'] == expected_stop, 'exact normal/abrupt recovery phase ordering')
    need(grant.get('abruptRecoveryAuthorized') is True, 'new exact abrupt-recovery scope, not an inherited grant')
    need(type(grant.get('reservedBytes'))is int and grant['reservedBytes']>=512*1024**2,
         'whole finite host guest-transfer/readback/metadata reserve within unchanged60GB budget')
    return grant['wholeDeadlineUnix']


def phase_result(value, phase, candidate, previous):
    """Consume actual native/Robot/install results; never create guest success."""
    need(value.get('kind') == 'ROOT_OUTPUT_INSTALL_NATIVE_PHASE_V1'
         and value.get('phase') == phase and value.get('identity') == candidate['identity']
         and value.get('targetGeneration') == candidate['targetGeneration']
         and value.get('targetSerial') == 'OPEMOSOUTPUTTARGET'
         and value.get('native') is True and value.get('MODEL_ONLY') is False
         and value.get('coreContract') == candidate['coreContract']
         and value.get('first') is None and value.get('secondary') == [], 'actual current native phase result')
    need(value.get('normalWelcomeInstall') is True
         and all(type(value.get(k)) is str and 0 < len(value[k]) <= 128 for k in ('installedRootUUID', 'installedEFIUUID', 'targetDevice'))
         and value.get('targetDevice') != value.get('mediaDevice'),
         'genuine welcome installation to distinct actual target/root/EFI')
    need(value.get('display') == {'width': 1600, 'height': 900}
         and type(value.get('robotExit')) is int and value['robotExit'] == 0
         and type(value.get('robotFailures')) is int and value['robotFailures'] == 0
         and value.get('mediaDetached') is (phase != 'installation')
         and all(value.get('files', {}).get(k) for k in ('output.xml', 'report.html', 'log.html', 'xunit.xml', 'screenshot')),
         'actual supported display/Robot reports/screenshot required')
    if phase == 'installation':
        need(value.get('actualWelcomePointer') is True and type(value.get('installExit')) is int and value['installExit'] == 0,
             'actual welcome pointer and ordinary install exit required')
    else:
        need(value.get('mediaDetached') is True and type(value.get('bootID')) is str
             and str(uuid.UUID(value['bootID'])) == value['bootID'] and uuid.UUID(value['bootID']).int != 0,
             'installed boot without installation medium')
        installed = [row for row in previous if row['phase'] != 'installation']
        need(all(value['bootID'] != row['bootID'] for row in installed), 'three distinct actual installed boot identities')
    for row in previous:
        need(all(value[k] == row[k] for k in ('installedRootUUID', 'installedEFIUUID', 'targetGeneration', 'targetSerial')),
             'same installed target generation/root/EFI across every phase')
    if phase in ('baseline', 'update', 'recovery'):
        need(value.get('nvidia575FiveModules') is True
             and value.get('nvidiaRender') is True and value.get('driverReceiptVerified') is True,
             'actual matching NVIDIA575 five modules/render/receipt, not PCI visibility')
    if phase == 'update':
        intent = value.get('nativeData', {}).get('update_intent', {})
        need(intent.get('phase') == 'pending-health' and intent.get('preparedBootId') == value['bootID']
             and intent.get('kernel') == value.get('kernel') and intent.get('generation'),
             'ordinary Core update is pending new-boot health, not successful reboot')
    if phase == 'recovery':
        before = previous[-1]['nativeData']['update_intent']
        after = value.get('nativeData', {}).get('recovered_intent', {})
        need(value.get('recoveryVerified') is True and after.get('phase') == 'healthy'
             and after.get('preparedBootId') != value['bootID'] == after.get('attemptBootId')
             and all(after.get(k) == before.get(k) for k in
                     ('generation', 'preparedBootId', 'kernel', 'target', 'authoritySHA256', 'filesSHA256')),
             'actual same-target exact candidate generation reboot health proof')
    return value


def validate_output_install_proof(value, context, image_sha256):
    """Consumer of the complete sealed Root result, not a phase-label pass."""
    need(value.get('kind')=='ROOT_VERIFIED_OUTPUT_INSTALL_FOUR_BOOT_V1'
         and value.get('identity')==context and value.get('image_sha256')==image_sha256
         and value.get('accepted')is True and value.get('first')is None and value.get('secondary')==[]
         and value.get('MODEL_ONLY')is False and value.get('logicalLeaseClosed')is True
         and value.get('leaseMustRemainHeld')is False and value.get('launches')==4,
         'exact actual complete current output-install result required')
    need(re.fullmatch('[0-9a-f]{32}',value.get('leaseNonce',''))and
         value.get('rootRequest',{}).get('leaseNonce')==value['leaseNonce'],
         'public result must retain the actual exact Root lease/request binding')
    need(value.get('closure',{}).get('known')is True and value['closure'].get('FDsClosed')is True,
         'actual final controller/descriptor closure required')
    rows=value.get('rows',[]);closures=value.get('phaseClosures',[]);stopped=value.get('stoppedReadbacks',[])
    need([row.get('phase')for row in rows]==list(PHASES)and len(closures)==len(stopped)==4,
         'complete ordinary four-phase producer/closure/stopped graph required')
    candidate={'identity':context,'targetGeneration':value['targetGeneration'],'coreContract':value['coreContract']}
    prior=[]
    for row,closed,readback in zip(rows,closures,stopped):
        phase_result(row,row['phase'],candidate,prior)
        need(closed.get('unknown')==[]and all(closed.get(key)is True for key in
             ('domainAbsent','originalPIDStartAbsent','cgroupEmpty','VFIOFDsAbsent','hostRestored')),
             'one actual phase domain/process/GPU closure missing')
        need(readback.get('first')is None and readback.get('secondary')==[]and
             readback.get('mountClosed')is True and readback.get('loopClosed')is True and
             readback.get('loopAllocationUnknown')is False and readback.get('commandClosureUnknown')is False and
             readback.get('identity')==context and readback.get('phase')==row['phase']and
             readback.get('targetGeneration')==value['targetGeneration']and
             readback.get('phaseResultSHA256')==hashlib.sha256(canonical(row)).hexdigest(),
             'independent stopped result does not join the actual phase')
        prior.append(row)
    return {'target_generation':value['targetGeneration'],'installed_root_uuid':rows[0]['installedRootUUID'],
            'installed_efi_uuid':rows[0]['installedEFIUUID'],'baseline_boot_id':rows[1]['bootID'],
            'update_boot_id':rows[2]['bootID'],'recovery_boot_id':rows[3]['bootID'],
            'driver_generation':rows[3]['nativeData']['recovered_intent']['generation'],
            'OS_kernel_transition':'NOT_PROVEN','hardware_acceptance':False}


def seal_output_install_proof(value,candidate):
    """Local Root receipt only, never a release/upload or new trust endpoint."""
    context=candidate['identity'];public=strict(protected_bytes(candidate['publicRangeReceipt'],mode=0o444,grant=True))
    need(public.get('identity')==context and public.get('completedImagePreserved')is True and
         public.get('normalWindowsImageAndVirtualUSB')is True and public.get('stoppedFullReadback')is True,
         'unchanged actual Windows image/virtualUSB source authority')
    proof=dict(value,kind='ROOT_VERIFIED_OUTPUT_INSTALL_FOUR_BOOT_V1',identity=context,
               targetGeneration=candidate['targetGeneration'],coreContract=candidate['coreContract'],
               publicRangeReceipt=candidate['publicRangeReceipt'],image_sha256=public['imageArtifactRange']['sha256'],
               targetDiskIdentity=identity(Path(candidate['target']['path']).lstat()))
    validate_output_install_proof(proof,context,proof['image_sha256'])
    raw=canonical(proof);need(len(raw)<=1024**2,'complete public output proof exceeds unchanged leaf cap')
    directory=Path('/run/opemos-output-proof-'+candidate['nonce'])
    need(not os.path.lexists(directory),'new create-only local Root proof directory, no replacement')
    directory.mkdir(mode=0o755);path=directory/'output-install.json'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        data=memoryview(raw)
        while data:
            n=os.write(fd,data);need(n>0,'local proof short write');data=data[n:]
        os.fchmod(fd,0o444);os.fsync(fd);st=os.fstat(fd)
        need(st.st_uid==st.st_gid==0 and identity(st)==identity(path.lstat()),'local Root proof named identity')
        pin={'path':str(path),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':identity(st)}
    finally:os.close(fd)
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
    return pin


def guest_phase(connection, domain, registration, request, candidate, phase, previous,
                manifest, deadline, persist):
    """Real bounded libvirt channel transaction to the ordinary A guest agent.

    This does not start/admit a VM, manufacture a report, or prove closure. The
    calling existing transaction independently proves the original QEMU/group,
    GPU restoration and all owned descriptors after each phase.
    """
    import libvirt
    need(os.geteuid() == 0 and isinstance(connection, libvirt.virConnect)
         and isinstance(domain, libvirt.virDomain) and connection.getURI() == 'qemu:///system',
         'actual Root managed guest channel required')
    def current():
        need(time.time() < deadline and domain.UUIDString() == request['domainUUID']
             and domain.name() == request['domainName'] and domain.isActive() and not domain.isPersistent(),
             'original deadline and same transient live domain')
        xml = ET.fromstring(domain.XMLDesc(0))
        binding = xml.find('metadata/{urn:opemos:steamos:libvirt:2}binding')
        need(binding is not None and binding.get('token') == request['jobToken']
             and binding.get('job') == request['jobId'] and binding.get('nonce') == request['leaseNonce']
             and not xml.findall('devices/interface'), 'exact noNIC canonical guest channel binding')
        channels = [c for c in xml.findall('devices/channel')
                    if c.find('target') is not None and c.find('target').get('name') == 'opemos.robot.observer']
        need(len(channels) == 1 and channels[0].get('type') == 'unix', 'one actual existing named observer channel')
        proc = Path('/proc/' + str(registration['leader']['pid']))
        fields = (proc/'stat').read_text().rsplit(')',1)[1].split()
        uids = [line.split()[1:] for line in (proc/'status').read_text().splitlines() if line.startswith('Uid:')]
        need(int(fields[19]) == registration['leader']['start'] and uids == [['64055']*4]
             and (proc/'cgroup').read_text().strip() == '0::/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/'
                 + request['vmSlice'] + '/' + registration['scope'],
             'original actual QEMU birth/four UID/exact pool cgroup')
    need(phase in PHASES and manifest['nonce'] == candidate['nonce']
         and manifest['controller_commit'] == candidate['identity'].get('controller_source_commit',
                                                                      candidate['identity']['source_commit']),
         'current source-A controller medium identity')
    root = Path(candidate['resultRoot'])/('guest-'+phase)
    root.mkdir(mode=0o700)
    need(root.resolve() == root and root.lstat().st_uid == root.lstat().st_gid == 0
         and stat.S_IMODE(root.lstat().st_mode) == 0o700, 'new private Root guest evidence directory')
    stream = None; buffer = bytearray(); files = {}; active = None; total = 0; first = None; secondary = []
    terminal = None; agent_reap=None; events = 0;last_event=None;parent_diagnostic=None;diagnostic_fd_unknown=False
    def send(value):
        raw = memoryview(canonical(value)+b'\n');need(len(raw)<=65536,'finite host channel message')
        while raw:
            current();count=stream.send(raw)
            if count == -2:time.sleep(.005);continue
            need(type(count)is int and count>0,'actual host channel write failed');raw=raw[count:]
    def receive():
        nonlocal events
        while True:
            value=pop_guest_frame(buffer)
            if value is not None:break
            current();part=stream.recv(65537-len(buffer))
            if part == -2:time.sleep(.005);continue
            need(type(part)is bytes and part,'actual guest channel EOF before terminal')
            buffer.extend(part)
        events+=1;need(events<=2048,'finite guest evidence event count')
        return value
    def diagnostic(header,hello=None):
        nonlocal diagnostic_fd_unknown
        need(header.get('kind')=='OUTPUT_AGENT_DIAGNOSTIC_BEGIN_V1'and
             header.get('nonce')==candidate['nonce']and header.get('manifest_sha256')==candidate['observerManifest']['sha256']and
             type(header.get('bytes'))is int and 0<=header['bytes']<=1024**2+1 and
             re.fullmatch('[0-9a-f]{64}',header.get('sha256','')),'finite exact owned-VM diagnostic header')
        if hello is not None:
            need(header.get('parent_pid')==hello['parent']['pid']and header.get('parent_start')==hello['parent']['start']and
                 header.get('uids')==hello['parent']['uids']and header.get('boot_id')==hello['guest']['boot_id'],
                 'diagnostic sender differs from independently observed actual agent parent')
        path=root/'parent-agent.log';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        count=0;digest=hashlib.sha256();original=None
        try:
            while count<header['bytes']:
                row=receive()
                need(row.get('kind')=='OUTPUT_AGENT_DIAGNOSTIC_CHUNK_V1'and type(row.get('offset'))is int and
                     row['offset']==count,'actual parent diagnostic chunk ordering')
                raw=base64.b64decode(row['data'],validate=True)
                need(0<len(raw)<=32768 and count+len(raw)<=header['bytes'],'parent diagnostic data overflow')
                view=memoryview(raw)
                while view:
                    n=os.write(fd,view);need(n>0,'parent diagnostic short write');view=view[n:]
                count+=len(raw);digest.update(raw)
            end=receive()
            need(end.get('kind')=='OUTPUT_AGENT_DIAGNOSTIC_END_V1'and type(end.get('bytes'))is int and
                 end['bytes']==count and end.get('sha256')==digest.hexdigest()==header['sha256'],
                 'actual complete parent diagnostic EOF/hash differs')
            os.fsync(fd);info=os.fstat(fd);need(identity(info)==identity(path.lstat()),'parent diagnostic inode changed')
            result={'path':str(path),'bytes':count,'sha256':digest.hexdigest(),'identity':identity(info),
                    'sender':header,'independentlyMatchedAgentParent':hello is not None}
            persist('guest-parent-complete-diagnostic-'+phase,result)
            return result
        except BaseException as error:
            original=error
            error.add_note('actual partial parent diagnostic retained: '+str(path)+' bytes='+str(count))
            raise
        finally:
            try:os.close(fd)
            except BaseException as error:
                diagnostic_fd_unknown=True
                if original is not None:original.add_note('diagnostic FD closure UNKNOWN: '+str(error))
                else:raise
    try:
        current();stream=connection.newStream(libvirt.VIR_STREAM_NONBLOCK)
        domain.openChannel('opemos.robot.observer',stream,0)
        hello=receive()
        last_event=hello
        persist('guest-first-event-'+phase,hello)
        if hello.get('kind')=='OUTPUT_AGENT_DIAGNOSTIC_BEGIN_V1':
            parent_diagnostic=diagnostic(hello)
            raise ValueError('guest agent failed before source-bound HELLO; complete untrusted diagnostic retained at '+parent_diagnostic['path'])
        need(hello.get('kind')=='OUTPUT_PHASE_HELLO_V1'and hello.get('nonce')==candidate['nonce']
             and hello.get('controller_commit')==manifest['controller_commit']
             and hello.get('manifest_sha256')==candidate['observerManifest']['sha256']
             and hello.get('agent_sha256')==manifest['files']['omen_steamos_guest.py']['sha256']
             and hello.get('guest',{}).get('uid')==1000
             and type(hello.get('agent_argv'))is list and len(hello['agent_argv'])==7
             and hello['agent_argv'][:3]==['/usr/bin/python3','-I','-B']
             and hello['agent_argv'][3].endswith('/omen_steamos_guest.py')
             and hello['agent_argv'][4].endswith('/manifest.json')and hello['agent_argv'][5]=='--channel-fd'
             and all(type(hello.get(role))is dict and type(hello[role].get('pid'))is int
                     and hello[role]['pid']>1 and type(hello[role].get('start'))is int
                     and hello[role]['start']>0 and hello[role].get('uids')==[1000]*4 for role in('agent','parent')),
             'actual bound source-A guest HELLO/agent/parent identity')
        persist('guest-hello-'+phase,hello)
        seconds=min(480,int(deadline-time.time()));need(seconds>30,'remaining unchanged whole deadline')
        arm={'kind':'ARM_OUTPUT_PHASE_V1','nonce':candidate['nonce'],'phase':phase,
              'identity':candidate['identity'],'targetGeneration':candidate['targetGeneration'],
              'targetBytes':candidate['target']['bytes'],'coreContract':candidate['coreContract'],
              'seconds':seconds,'previous':[dict({key:row[key]for key in
                  ('phase','installedRootUUID','installedEFIUUID','bootID')if key in row},
                  nativeData={key:row['nativeData'][key]for key in('update_intent',)
                              if key in row['nativeData']})for row in previous]}
        persist('guest-exact-arm-'+phase,arm)
        send(arm)
        while terminal is None or agent_reap is None:
            value=receive();kind=value.get('kind')
            last_event=value
            if terminal is not None:need(kind in('OUTPUT_AGENT_REAP_V1','OUTPUT_AGENT_DIAGNOSTIC_BEGIN_V1'),
                                       'no extra action/file events after sealed terminal')
            if kind=='PHASE_FILE_BEGIN_V1':
                row=value.get('file',{});number=row.get('id')
                need(active is None and value.get('nonce')==candidate['nonce']and value.get('phase')==phase
                     and set(row)=={'id','name','bytes','sha256','guest_identity','kind'}
                     and type(number)is int and number==len(files)and number<256
                     and type(row.get('bytes'))is int and 0<=row['bytes']<=8*1024**2
                     and re.fullmatch('[0-9a-f]{64}',row.get('sha256',''))
                     and re.fullmatch(r'[A-Za-z0-9_.-]{1,180}',row.get('name',''))
                     and type(row.get('kind'))is str and 0<len(row['kind'])<=128
                     and type(row.get('guest_identity'))is dict and set(row['guest_identity'])==set(FIELDS)
                     and all(type(n)is int and 0<=n<2**64 for n in row['guest_identity'].values()),
                     'finite source-bound guest evidence header')
                need(total+row['bytes']<=32*1024**2,'whole guest phase evidence limit')
                path=root/(str(number)+'-'+row['name'])
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                active={'row':row,'fd':fd,'path':path,'offset':0,'hash':hashlib.sha256()}
            elif kind=='PHASE_FILE_CHUNK_V1':
                need(active is not None and type(value.get('id'))is int and value['id']==active['row']['id']
                     and type(value.get('offset'))is int and value['offset']==active['offset'],'ordered exact guest evidence chunk')
                raw=base64.b64decode(value['data'],validate=True)
                need(0<len(raw)<=32768 and active['offset']+len(raw)<=active['row']['bytes'],
                     'actual evidence size/offset limit')
                view=memoryview(raw)
                while view:
                    n=os.write(active['fd'],view);need(n>0,'actual host evidence short write');view=view[n:]
                active['offset']+=len(raw);active['hash'].update(raw)
            elif kind=='PHASE_FILE_END_V1':
                need(active is not None and type(value.get('id'))is int and value['id']==active['row']['id']
                     and type(value.get('bytes'))is int and value['bytes']==active['offset']==active['row']['bytes']
                     and value.get('sha256')==active['hash'].hexdigest()==active['row']['sha256'],
                     'actual guest evidence EOF/full hash mismatch')
                os.fsync(active['fd']);os.close(active['fd']);active['fd']=None
                info=active['path'].lstat();ref={'path':str(active['path']),'bytes':info.st_size,
                    'sha256':active['row']['sha256'],'identity':identity(info),'guest':active['row']}
                files[str(active['row']['id'])]=ref;total+=info.st_size
                persist('guest-file-'+phase+'-'+str(active['row']['id']),ref);active=None
            elif kind=='OUTPUT_PHASE_TERMINAL_V1':
                need(terminal is None and active is None and value.get('identity')==candidate['identity']
                     and value.get('nonce')==candidate['nonce']and value.get('phase')==phase
                     and value.get('targetGeneration')==candidate['targetGeneration']
                     and same_guest_epoch(hello['guest'],value.get('guest'))
                     and type(value.get('file_bytes'))is int and value['file_bytes']==total
                     and type(value.get('file_count'))is int and value['file_count']==len(files)
                     and value.get('inventory_sha256')==hashlib.sha256(
                         canonical([ref['guest']for ref in files.values()])).hexdigest(),
                     'complete actual guest terminal identity/inventory differs')
                terminal=value;persist('guest-terminal-'+phase,terminal)
            elif kind=='OUTPUT_AGENT_REAP_V1':
                persist('guest-parent-reap-observed-'+phase,value)
                child=value.get('agent',{})
                need(terminal is not None and agent_reap is None and value.get('nonce')==candidate['nonce']
                     and parent_diagnostic is not None and value.get('diagnostic_sha256')==parent_diagnostic['sha256']
                     and value.get('boot_id')==hello['guest']['boot_id']and value.get('manifest_sha256')==hello['manifest_sha256']
                     and value.get('parent_pid')==hello['parent']['pid']and value.get('parent_start')==hello['parent']['start']
                     and value.get('uids')==hello['parent']['uids']and child.get('pid')==hello['agent']['pid']
                     and child.get('start')==hello['agent']['start']and child.get('argv')==hello.get('agent_argv')
                     and type(child.get('numeric_exit'))is int
                     and child.get('original_reaped')is True and child.get('stdout_eof')is True
                     and child.get('stdout_closed')is True and child.get('first')is None and child.get('secondary')==[],
                     'actual original guest agent numeric reap/EOF/pipe closure absent or foreign')
                need((child['numeric_exit']==0)==(terminal.get('completed')is True),
                     'actual guest process exit disagrees with retained Robot/native terminal')
                agent_reap=value
            elif kind=='OUTPUT_AGENT_DIAGNOSTIC_BEGIN_V1':
                need(parent_diagnostic is None and active is None,'one noninterleaved actual agent diagnostic')
                parent_diagnostic=diagnostic(value,hello)
            else:raise ValueError('unexpected actual guest event: '+str(kind))
        directory_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
    except BaseException as error:
        first={'type':type(error).__name__,'reason':str(error)}
        try:
            persist('guest-channel-first-failure-'+phase,{'first':first,'lastActualEvent':last_event,
                'terminalAlreadyRetained':terminal is not None,'completedFiles':files,
                'activeFile':None if active is None else{'header':active['row'],'received_bytes':active['offset'],
                                                       'retained_path':str(active['path'])}})
        except BaseException as error:secondary.append({'phase':'first-failure-persistence','reason':str(error)})
    finally:
        if active is not None and active.get('fd')is not None:
            try:os.fsync(active['fd'])
            except BaseException as error:secondary.append({'phase':'partial-file-sync','reason':str(error)})
            try:os.close(active['fd']);active['fd']=None
            except BaseException as error:secondary.append({'phase':'partial-file-close','reason':str(error)})
        if stream is not None:
            try:stream.abort()
            except BaseException as error:secondary.append({'phase':'actual-stream-abort','reason':str(error)})
        try:
            persist('guest-channel-'+phase,{'first':first,'secondary':secondary,'files':files,
                'terminalReceived':terminal is not None,'actualAgentReap':agent_reap,'parentDiagnostic':parent_diagnostic,'EOF_observed':False,
                'VM_closure':'UNKNOWN; separate actual original-process proof required'})
        except BaseException as error:secondary.append({'phase':'channel-result-persistence','reason':str(error)})
    if first is not None or secondary or terminal is None or agent_reap is None:
        error=ValueError('actual guest transaction failed: '+str(first or secondary or 'terminal/parent reap missing'))
        error.evidence={'first':first,'secondary':secondary,'lastActualEvent':last_event,'terminal':terminal,
                        'actualAgentReap':agent_reap,'files':files,
                        'parentDiagnostic':parent_diagnostic,
                        'lifecycleUnknown':bool(diagnostic_fd_unknown or active is not None and active.get('fd')is not None or
                            any(row['phase']in('partial-file-close','actual-stream-abort')for row in secondary))}
        raise error
    return {'terminal':terminal,'files':files,'agentReap':agent_reap,'parentDiagnostic':parent_diagnostic}


def consume_guest_phase(transaction, phase, candidate, previous):
    """Join real retained reports to the phase contract; no truthy flag adapter."""
    terminal=transaction['terminal'];refs=transaction['files']
    by_name={}
    for ref in refs.values():
        name=ref['guest']['name'];need(name not in by_name,'ambiguous guest report basename')
        # Files were created by this receiver. Reopen held/no-follow and bind
        # all nine fields, EOF, size and hash again before semantic parsing.
        path=Path(ref['path']);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd);raw=bytearray()
            need(identity(before)==ref['identity']and before.st_uid==before.st_gid==0
                 and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1,
                 'actual receiver-owned report permissions/identity')
            while part:=os.read(fd,65536):
                raw.extend(part);need(len(raw)<=8*1024**2,'existing per-file report cap')
            need(identity(before)==identity(os.fstat(fd))==identity(path.lstat())
                 and len(raw)==ref['bytes']and hashlib.sha256(raw).hexdigest()==ref['sha256'],
                 'actual host retained report full9/EOF/hash')
            by_name[name]=(ref,bytes(raw))
        finally:os.close(fd)
    need('native-phase.json'in by_name and by_name['native-phase.json'][0]['sha256']==terminal.get('native_document_sha256'),
         'complete actual native phase document absent/mismatched')
    document=strict(by_name['native-phase.json'][1])
    need(document.get('kind')=='ACTUAL_STEAMOS_PHASE_DOCUMENT_V1'
         and all(document.get(key)==terminal.get(key)for key in('identity','nonce','phase','guest')),
         'native document/terminal subject mismatch')
    data=document['nativeData']
    if terminal.get('completed')is not True or terminal.get('first')is not None or terminal.get('secondary')!=[]:
        original=document.get('first')or terminal.get('first')or {'type':'Unknown','reason':'ordinary native phase failed'}
        error=ValueError(str(original.get('type'))+': '+str(original.get('reason')))
        error.evidence={'originalNativeFailure':original,'secondary':document.get('secondary'),
                        'nativeDocument':by_name['native-phase.json'][0],'allGuestFiles':refs,
                        'actualAgentReap':transaction['agentReap'],'parentDiagnostic':transaction['parentDiagnostic']}
        raise error
    required=('output.xml','report.html','log.html','xunit.xml')
    need(all(name in by_name for name in required),'all ordinary Robot output formats required on actual success')
    xml=ET.fromstring(by_name['output.xml'][1]);tests=xml.findall('.//test')
    need(type(terminal.get('robot'))is dict and
         all(type(terminal['robot'].get(key))is int for key in('numeric_exit','passed','failed','skipped','tests')),
         'actual finite numeric Robot results, not boolean aliases')
    need(xml.tag=='robot'and xml.get('generator','').startswith('Robot 7.5')and len(tests)==1
         and tests[0].find('status')is not None and tests[0].find('status').get('status')=='PASS'
         and terminal['robot']['numeric_exit']==0 and terminal['robot']['passed']==1
         and terminal['robot']['failed']==terminal['robot']['skipped']==0,
         'actual Robot7.5 complete ordinary phase did not pass')
    frames=[ref for name,(ref,raw)in by_name.items()if name.endswith('.png')]
    need(frames and all(by_name[ref['guest']['name']][1][:24]==
         b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'+(1600).to_bytes(4,'big')+(900).to_bytes(4,'big')
         for ref in frames),'actual retained supported-size native PNG frames absent')
    welcome=data.get('welcome_result')if phase=='installation'else previous[0]['nativeData'].get('welcome_result')
    need(type(welcome)is dict and welcome.get('numeric_exit')==0 and welcome.get('first')is None
         and welcome.get('secondary')==[]and welcome.get('stdout_eof')is True
         and welcome.get('stdout_closed')is True and welcome.get('original_reaped')is True,
         'genuine original normal welcome terminal transaction required')
    if phase=='installation':
        actions=document.get('actions',[])
        need(len(actions)==5 and all(row['result']['neutral']['left_down']is False for row in actions),
             'five genuine native welcome pointer pairs with observed neutral state required')
    else:
        render=data.get('nvidia_render',{})
        need('nvidia-render.json'in by_name and strict(by_name['nvidia-render.json'][1])==render
             and render.get('kind')=='ACTUAL_GLX_NVIDIA_READBACK_V1'and render.get('direct')is True
             and same_guest_epoch(terminal['guest'],render.get('guest'))and len(render.get('readbacks',[]))==2,
             'actual current NVIDIA native pixel readbacks absent')
        status=data.get({'baseline':'baseline_status','update':'before_update_status','recovery':'recovery_status'}[phase],{})
        records=status.get('moduleVerification',{}).get('records',[])
        need(status.get('status')=='healthy'and status.get('moduleVerification',{}).get('status')=='verified'
             and len(records)==5 and {str(r.get('name','')).replace('-','_')for r in records}==
                 {'nvidia','nvidia_modeset','nvidia_drm','nvidia_uvm','nvidia_peermem'}
             and all(r.get('present')is True and r.get('exactKernel')is True and r.get('exactUserspace')is True for r in records)
             and status.get('target',{}).get('kernelVersion')==terminal['guest']['kernel']
             and str(status.get('target',{}).get('nvidiaVersion','')).startswith('575.'),
             'same guest/kernel actual Core NVIDIA575 five-module verification absent')
    # Preserve every full native document/unknown field and every file pin in
    # an actual held evidence index, not four duplicated maps in a1MiB public
    # leaf. This is not truncation: the original bytes and complete index stay
    # retained under the exact current operation and their full9/SHA are bound.
    index_raw=canonical({'kind':'EXE_ACTUAL_GUEST_EVIDENCE_INDEX_V1','identity':candidate['identity'],
        'phase':phase,'nativeDocument':by_name['native-phase.json'][0],'allGuestFiles':refs,
        'actualAgentReap':transaction['agentReap']})
    need(len(index_raw)<=1024**2,'complete guest evidence index exceeds unchanged metadata leaf cap')
    index_path=Path(candidate['resultRoot'])/('guest-'+phase)/'host-evidence-index.json'
    fd=os.open(index_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        pending=memoryview(index_raw)
        while pending:
            n=os.write(fd,pending);need(n>0,'guest evidence index short write');pending=pending[n:]
        os.fsync(fd);st=os.fstat(fd);need(identity(st)==identity(index_path.lstat()),'host evidence index name changed')
        index_pin={'path':str(index_path),'bytes':len(index_raw),'sha256':hashlib.sha256(index_raw).hexdigest(),'identity':identity(st)}
    finally:os.close(fd)
    directory_fd=os.open(index_path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(directory_fd)
    finally:os.close(directory_fd)
    native_summary={key:data[key]for key in('welcome_result','update_intent','recovered_intent')if key in data}
    result={'kind':'ROOT_OUTPUT_INSTALL_NATIVE_PHASE_V1','phase':phase,'identity':candidate['identity'],
        'targetGeneration':candidate['targetGeneration'],'targetSerial':'OPEMOSOUTPUTTARGET',
        'native':True,'MODEL_ONLY':False,'coreContract':candidate['coreContract'],'first':None,'secondary':[],
        'normalWelcomeInstall':True,'installedRootUUID':data['installedRootUUID'],
        'installedEFIUUID':data['installedEFIUUID'],'targetDevice':data['targetDevice'],'mediaDevice':data['mediaDevice'],
        'display':{'width':1600,'height':900},'robotExit':terminal['robot']['numeric_exit'],
        'robotFailures':terminal['robot']['failed'],'mediaDetached':data['mediaDetached'],
        'bootID':terminal['guest']['boot_id'],'kernel':terminal['guest']['kernel'],
        'actualWelcomePointer':phase=='installation','installExit':welcome['numeric_exit'],
        'nvidia575FiveModules':phase!='installation','nvidiaRender':phase!='installation',
        'driverReceiptVerified':phase!='installation','recoveryVerified':phase=='recovery',
        'nativeData':native_summary,'nativeDocumentSHA256':terminal['native_document_sha256'],
        'completeNativeDocument':by_name['native-phase.json'][0],'allGuestFilesIndex':index_pin,
        'actualAgentReap':transaction['agentReap'],
        'parentDiagnostic':transaction['parentDiagnostic'],
        'files':{name:by_name[name][0]for name in required},
        'OS_kernel_slot_transition':'NOT_PROVEN; Core driver-generation health is a separate milestone',
        'VM_closure':'UNKNOWN; independent host proof still required'}
    result['files']['screenshot']=frames[-1]
    result['files']['native-evidence-index']=index_pin
    return phase_result(result,phase,candidate,previous)


def stopped_target_readback(candidate,value,closure,command_module,native,tools,deadline,persist):
    """Independent stopped raw target readback through new read-only loop/mount.

    Runs only after actual QEMU/group/VFIO closure. Never mounts the original
    media, reuses a loop, selects an OS slot, changes a filesystem, or cleans an
    unknown resource. Fixed native tools retain numeric exit and raw receipts.
    """
    need(os.geteuid()==0 and closure.get('unknown')==[]and all(closure.get(k)is True for k in
         ('domainAbsent','originalPIDStartAbsent','cgroupEmpty','VFIOFDsAbsent','hostRestored')),
         'complete actual domain and hardware closure before stopped readback')
    for path in('/usr/sbin/losetup','/usr/bin/lsblk','/usr/bin/mount','/usr/bin/umount'):
        need(tools[path]['path']==path,'exact fixed stopped native tool pin')
        native.held(tools[path],32*1024**2)
    target=Path(candidate['target']['path']);before=target.lstat()
    need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==candidate['target']['bytes']
         and all(getattr(before,key)==candidate['target']['identity'][key]
                 for key in('st_dev','st_ino','st_uid','st_gid','st_nlink','st_size')),
         'actual stopped standalone target identity/capacity')
    parent=Path(candidate['resultRoot']);info=parent.lstat()
    need(parent.is_absolute()and parent.resolve()==parent and stat.S_ISDIR(info.st_mode)and
         info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700,'actual private Root stopped output parent')
    root=parent/('stopped-'+value['phase']);root.mkdir(mode=0o700)
    mount=root/'home';mount.mkdir(mode=0o700)
    sequence=0;loop=None;loop_unknown=False;command_unknown=False;mounted=False;first=None;secondary=[];observed=None;records=[];home=None
    def command(argv,name):
        nonlocal sequence,command_unknown
        sequence+=1;paths=[root/(str(sequence)+'-'+name+suffix)for suffix in('.stdout','.stderr')]
        seconds=min(30,deadline-time.time());need(seconds>0,'unchanged whole stopped-readback deadline')
        native.held(tools[argv[0]],32*1024**2)
        try:record=command_module.run_owned_command(argv,None,seconds,paths,stream_limit=1024**2)
        except BaseException:
            command_unknown=True
            raise
        if record.get('lifecycleClosed')is not True or record.get('descendantClosureUNKNOWN',False):command_unknown=True
        records.append(record);persist('stopped-command-'+value['phase']+'-'+str(sequence),record)
        native.held(tools[argv[0]],32*1024**2)
        need(record.get('numericExit')==0 and record.get('lifecycleClosed')is True and
             record.get('firstError')is None and record.get('errors')==[]and
             not record.get('descendantClosureUNKNOWN',False),'actual stopped helper failed/closure unknown')
        path=paths[0];fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            a=os.fstat(fd);raw=os.read(fd,1048577)
            need(len(raw)<=1048576 and len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(path.lstat()),
                 'stopped helper raw full9/EOF/size changed')
            return raw
        finally:os.close(fd)
    def mounted_here():
        return [row for row in Path('/proc/self/mountinfo').read_text().splitlines()
                if row.split(' - ',1)[0].split()[4]==str(mount)]
    try:
        # Inspect actual loop associations before allocation. --nooverlap is
        # not used: its reuse behavior would adopt an unknown prior resource.
        existing=strict(command(['/usr/sbin/losetup','--json','--list','--output','NAME,BACK-FILE,RO'],'loops-before'))
        for row in existing.get('loopdevices',[]):
            name=row.get('back-file')
            if name and os.path.exists(name):
                info=os.stat(name)
                need((info.st_dev,info.st_ino)!=(before.st_dev,before.st_ino),'existing loop already owns stopped target')
        loop_unknown=True
        raw=command(['/usr/sbin/losetup','--find','--show','--read-only','--partscan',str(target)],'new-readonly-loop')
        name=raw.decode('ascii').strip();need(re.fullmatch('/dev/loop[0-9]{1,5}',name),'actual newly returned loop name')
        candidate_loop=Path(name);info=candidate_loop.stat();need(stat.S_ISBLK(info.st_mode),'actual new loop block device')
        associated=strict(command(['/usr/sbin/losetup','--json','--list','--output','NAME,BACK-FILE,RO'],'loops-after'))
        rows=[r for r in associated['loopdevices']if r['name']==name]
        need(len(rows)==1 and rows[0]['ro']is True and os.path.samefile(rows[0]['back-file'],target),
             'new actual loop is read-only and backed by exact owned target')
        loop=candidate_loop;loop_unknown=False
        tree=strict(command(['/usr/bin/lsblk','--json','--paths','--output',
                             'PATH,TYPE,PARTLABEL,UUID,FSTYPE,MOUNTPOINTS',name],'actual-partitions'))
        todo=list(tree['blockdevices']);parts=[]
        while todo:
            row=todo.pop();todo.extend(row.get('children',[]));parts.append(row)
        need(len(parts)<=32 and all(not any(p.get('mountpoints')or[])for p in parts),'stopped target already mounted/ambiguous')
        for label,key in(('rootfs-A','installedRootUUID'),('efi-A','installedEFIUUID')):
            found=[p for p in parts if p.get('partlabel')==label]
            need(len(found)==1 and found[0].get('uuid')==value[key],'independent stopped partition UUID differs: '+label)
        homes=[p for p in parts if p.get('partlabel')=='home']
        need(len(homes)==1 and homes[0].get('fstype')in('ext4','btrfs'),'actual supported unique home filesystem')
        home=homes[0];options='ro,noload,nodev,nosuid,noexec'if home['fstype']=='ext4'else'ro,nologreplay,nodev,nosuid,noexec'
        need(not mounted_here(),'fresh exact stopped mountpoint')
        mounted=True
        command(['/usr/bin/mount','--types',home['fstype'],'--options',options,home['path'],str(mount)],'mount-readonly-home')
        actual=mounted_here()
        need(len(actual)==1 and 'ro'in actual[0].split(' - ',1)[0].split()[5].split(','),
             'actual stopped home mount not read-only')
        # Ordinary reports persist under the real installed user's home. For
        # installation the reports are on the recovery medium's temporary
        # home, so independent target UUID/layout is the available readback;
        # no installed report is fabricated or copied there by this reader.
        pins={}
        if value['phase']!='installation':
            directory=mount/'deck/.local/state'/('opemos-output-'+candidate['nonce'])/value['phase']
            for relative in ('native-phase.json','output.xml','report.html','log.html','xunit.xml'):
                path=directory/relative
                need(path.resolve()==path and directory.resolve()==directory,'no stopped report symlink traversal')
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                try:
                    st=os.fstat(fd);digest=hashlib.sha256();size=0
                    need(stat.S_ISREG(st.st_mode)and st.st_uid==1000 and st.st_nlink==1 and
                         not st.st_mode&0o022 and st.st_size<=8*1024**2,'actual stopped guest report permission/size')
                    while chunk:=os.read(fd,65536):
                        size+=len(chunk);need(size<=8*1024**2,'stopped report crossing');digest.update(chunk)
                    need(size==st.st_size and identity(st)==identity(os.fstat(fd))==identity(path.lstat()),'stopped file full9/EOF differs')
                    expected=value['nativeDocumentSHA256']if relative=='native-phase.json'else value['files'][relative]['sha256']
                    need(digest.hexdigest()==expected,'actual stopped filesystem/report hash differs')
                    pins[relative]={'bytes':size,'sha256':digest.hexdigest(),'identity':identity(st)}
                finally:os.close(fd)
        observed={'partitions':parts,'readbackFiles':pins,'loop':name,'mountOptions':options,
                  'installationReportOnInstalledHome':False if value['phase']=='installation'else True}
    except BaseException as error:first={'type':type(error).__name__,'reason':str(error)}
    finally:
        if mounted:
            try:
                actual=mounted_here()
                if actual:
                    info=os.stat(home['path']);device=str(os.major(info.st_rdev))+':'+str(os.minor(info.st_rdev))
                    need(len(actual)==1 and actual[0].split()[2]==device,'unknown mount source must not be unmounted')
                    command(['/usr/bin/umount',str(mount)],'unmount-owned-home')
                need(not mounted_here(),'owned stopped mount remains');mounted=False
            except BaseException as error:secondary.append({'phase':'owned-unmount','reason':str(error)})
        if loop is not None and not mounted:
            try:
                rows=strict(command(['/usr/sbin/losetup','--json','--list','--output','NAME,BACK-FILE,RO'],
                                    'loops-before-owned-detach'))['loopdevices']
                owned=[row for row in rows if row['name']==str(loop)]
                need(len(owned)==1 and owned[0]['ro']is True and os.path.samefile(owned[0]['back-file'],target),
                     'owned loop association changed; do not detach unknown target')
                command(['/usr/sbin/losetup','--detach',str(loop)],'detach-owned-loop')
                rows=strict(command(['/usr/sbin/losetup','--json','--list','--output','NAME,BACK-FILE,RO'],'loops-final'))['loopdevices']
                need(not any(r['name']==str(loop)for r in rows),'owned loop association remains');loop=None
            except BaseException as error:secondary.append({'phase':'owned-loop-detach','reason':str(error)})
        after=target.lstat()
        if identity(after)!=identity(before):secondary.append({'phase':'target-readonly-integrity','reason':'stopped target full9 changed'})
        result={'phase':value['phase'],'identity':candidate['identity'],'targetGeneration':candidate['targetGeneration'],
            'phaseResultSHA256':hashlib.sha256(canonical(value)).hexdigest(),'first':first,'secondary':secondary,
            'mountClosed':not mounted,'loopClosed':loop is None and not loop_unknown,
            'loopAllocationUnknown':loop_unknown,'commandClosureUnknown':command_unknown,
            'observation':observed,'commands':records}
        persist('actual-stopped-readback-'+value['phase'],result)
    if first is not None or secondary or mounted or loop is not None or loop_unknown or command_unknown:
        error=ValueError('actual stopped readback failed; retained original evidence/unknowns')
        error.evidence=dict(result,lifecycleUnknown=bool(mounted or loop is not None or loop_unknown or command_unknown))
        raise error
    return result


def read_console(connection, domain, request, registration, deadline, persist, capture_path, cap=1024**2):
    """Bounded read-only console bridge for the separately pinned phase agent.

    Uses the actual managed console, not a QEMU-written unlimited host file.
    This returns observations only: a deadline is NOT guest EOF, and libvirt
    stream abort is NOT guest/VM shutdown. No guest keystrokes/login are sent.
    API: libvirt.org/html/libvirt-libvirt-domain.html#virDomainOpenConsole;
    libvirt-python libvirt-override-virStream.py documents recv's -2 result.
    """
    import libvirt
    import gc
    need(os.geteuid() == 0 and isinstance(domain, libvirt.virDomain)
         and isinstance(connection, libvirt.virConnect) and connection.getURI() == 'qemu:///system'
         and type(cap) is int and 0 < cap <= 1024**2
         and time.time() < deadline <= time.time() + 480, 'actual finite Root managed-console bridge')
    def current():
        need(domain.UUIDString() == request['domainUUID'] and domain.name() == request['domainName']
             and domain.isActive() and not domain.isPersistent(), 'same actual live transient domain')
        xml = ET.fromstring(domain.XMLDesc(0))
        metadata = xml.find('metadata/{urn:opemos:steamos:libvirt:2}binding')
        need(metadata is not None and metadata.get('token') == request['jobToken']
             and metadata.get('job') == request['jobId'] and metadata.get('nonce') == request['leaseNonce']
             and not xml.findall('devices/interface') and len(xml.findall('devices/console')) == 1
             and xml.find('devices/console').get('type') == 'pty', 'exact bound noNIC console domain')
        proc = Path('/proc/' + str(registration['leader']['pid']))
        fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        uids = [line.split()[1:] for line in (proc / 'status').read_text().splitlines() if line.startswith('Uid:')]
        expected_cgroup = ('/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/' +
                           request['vmSlice'] + '/' + registration['scope'])
        need(int(fields[19]) == registration['leader']['start'] and uids == [['64055']*4]
             and (proc / 'cgroup').read_text().strip() == '0::' + expected_cgroup,
             'same original actual QEMU birth/four UIDs/exact admitted machine scope')
    path = Path(capture_path)
    need(path.parent == Path('/run/opemos-libvirt-results-' + request['leaseNonce'])
         and re.fullmatch(r'[A-Za-z0-9_.-]{1,120}', path.name), 'exact create-only console capture')
    parent = path.parent.lstat()
    need(parent.st_uid == parent.st_gid == 0 and stat.S_IMODE(parent.st_mode) == 0o700
         and path.parent.resolve() == path.parent, 'protected console capture parent')
    current(); stream = None; primary = None; raw = bytearray(); eof = False; aborted = None; fd = None
    observation = {}
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        stream = connection.newStream(libvirt.VIR_STREAM_NONBLOCK)
        domain.openConsole(None, stream, 0)
        while time.time() < deadline:
            current()
            block = stream.recv(min(65536, cap + 1 - len(raw)))
            if block == -2:
                time.sleep(min(.01, max(0, deadline - time.time()))); continue
            need(type(block) is bytes, 'actual console byte result')
            if not block:
                eof = True; break
            raw.extend(block)
            view = memoryview(block)
            while view:
                count = os.write(fd, view); need(count > 0, 'console capture write progress'); view = view[count:]
            need(len(raw) <= cap, 'bounded console overflow; complete first crossing retained, remaining tail UNKNOWN')
        current()
        observation.update({'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'guestEOF': eof, 'deadlineReached': not eof, 'noGuestInput': True,
            'domainUUID': request['domainUUID'], 'leader': registration['leader']})
        return bytes(raw), observation
    except BaseException as error:
        primary = error
        raise
    finally:
        capture_errors = []
        if fd is not None:
            try:
                os.fsync(fd); info = os.fstat(fd)
                need(identity(info) == identity(path.lstat())
                     and info.st_size == len(raw) and info.st_uid == 0 and info.st_nlink == 1,
                     'console capture exact named custody')
                observation['capturePin'] = {'path': str(path), 'bytes': len(raw),
                    'sha256': hashlib.sha256(raw).hexdigest(), 'identity': identity(info)}
            except BaseException as error: capture_errors.append(str(error))
            finally:
                try: os.close(fd)
                except OSError as error: capture_errors.append(str(error))
        if stream is not None:
            try:
                aborted = stream.abort(); need(aborted == 0, 'actual console stream abort acknowledgement')
            except BaseException as error:
                capture_errors.append('console stream closure UNKNOWN: ' + str(error))
            finally:
                stream = None
                try: gc.collect()
                except BaseException as error: capture_errors.append('console object closure UNKNOWN: ' + str(error))
        try:
            persist('console-reader-closure', {'first': None if primary is None else str(primary),
                'streamAbortNumeric': aborted, 'guestEOF': eof, 'bytes': len(raw),
                'sha256': hashlib.sha256(raw).hexdigest(), 'capture': observation.get('capturePin'),
                'captureErrors': capture_errors, 'noDomainShutdownClaimed': True})
        except BaseException as error:
            capture_errors.append('console closure persistence failed: ' + str(error))
        if capture_errors:
            if primary is not None: primary.add_note('console capture closure UNKNOWN: ' + repr(capture_errors))
            else: raise ValueError('console capture closure UNKNOWN: ' + repr(capture_errors))


def stage_access(candidate, grant_pin, persist):
    """Concrete derivative-only preparation before runtime clocks/Root grant.

    Unlike old R69 stage_io, this never requires media to be inaccessible to
    QEMU, and never modifies the immutable medium to make it accessible. Its
    creator must seal/read-share it BEFORE protected public publication.
    """
    grant = strict(protected_bytes(grant_pin, grant=True)); now = time.time()
    need(os.geteuid() == 0 and grant.get('kind') == 'ROOT_OUTPUT_INSTALL_ACCESS_STAGE_V1'
         and grant.get('RootIssued') is True and grant.get('stageOnly') is True
         and grant.get('runtimeAuthorized') is False and grant['candidate'] == candidate
         and grant['bootID'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
         and grant['issuedUnix'] <= now < grant['startBeforeUnix'] <= grant['issuedUnix'] + 300,
         'new exact stage-only authority; no historical access grant reuse')
    need(type(grant.get('reservedBytes'))is int and grant['reservedBytes']>=512*1024**2,
         'full finite future output-transfer/readback/metadata reserve required before access staging')
    runner = output_runner(grant)
    modules = backend(candidate['backendSources'])
    peer, access, native, producer = (modules[n] for n in
        ('libvirt_peer', 'libvirt_access', 'libvirt_native', 'libvirt_producer'))
    pre = strict(protected_bytes(grant['currentPreflightPin']))
    need(pre['candidate'] == candidate and pre['bootID'] == grant['bootID']
         and pre['producer']['uid'] == 0 and 0 <= now - pre['observedUnix'] <= 30
         and pre['wholeQueueConflictFree'] is True and pre['holderUnknowns'] == []
         and pre['windowsProducerClosed'] is True and pre['allOwnedFDsClosed'] is True,
         'actual fresh complete stage preflight/source/owner/producer closure')
    for key in ('original', 'working'):
        ref = candidate[key]
        fd = os.open(ref['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(peer.ident(os.fstat(fd)) == ref['identity'] == peer.ident(os.lstat(ref['path'])),
                 'actual original/target pre-stage identity')
            if key == 'working':
                need(os.fstat(fd).st_size >= runner.OUTPUT_INSTALL_MINIMUM_BYTES
                     and os.fstat(fd).st_blocks * 512 >= os.fstat(fd).st_size,
                     'actual full raw target allocation, not the six-GiB example')
        finally:
            os.close(fd)
    need(runner.output_storage_ledger(grant['dependencies'], grant['reservedBytes']) == pre['outputLedger'],
         'actual complete pre-stage output ledger')
    for root in (candidate['run'], candidate['output'], candidate['resultRoot']):
        need(not os.path.lexists(root), 'create-only generated IO/result directory')
        need(Path(root).parent == Path('/run') and Path(root).name.startswith('opemos-'),
             'bounded exact generated Root IO directory')
        producer.create_root(root)
    template = native.held(candidate['firmwareVarsTemplate'], 1024**2)
    for path, raw in ((candidate['run'] + '/OVMF_VARS_4M.fd', template),
                      (candidate['output'] + '/serial.raw', b'')):
        with access.Held(str(Path(path).parent)) as parent:
            fd = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent.fd)
            try:
                view = memoryview(raw)
                while view:
                    count = os.write(fd, view); need(count > 0, 'stage IO write progress'); view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent.fd)
    rows = []; after = []
    leaves = [(str(Path(candidate['working']['path']).parent), 'working-parent'),
              (candidate['working']['path'], 'working'), (candidate['run'], 'runtime-parent'),
              (candidate['run'] + '/OVMF_VARS_4M.fd', 'vars'),
              (candidate['output'], 'output-parent'), (candidate['output'] + '/serial.raw', 'serial')]
    for path, role in leaves:
        ref = access.metadata_pin(path)
        if role == 'working': ref = dict(candidate['working'])
        elif not role.endswith('parent'):
            with access.Held(path) as held:
                count, digest = access.hashfd(held.fd); ref.update(bytes=count, sha256=digest)
        row = access.plan(path, ref, role, verified_content=candidate['working'] if role == 'working' else None)
        rows.append(row); after.append(access.apply(row, persist, defer_working_hash=True))
    # Actual same-UID DAC, not a mocked os.access or a Root access test. No
    # descriptors are inherited; this child changes no media or target content.
    tool = grant['nativeTools']['/usr/bin/python3']; native.held(tool, 32*1024**2)
    code = '''import os,sys,json,errno
os.setgroups([]);os.setgid(993);os.setuid(64055)
uids=[line.split()[1:]for line in open('/proc/self/status')if line.startswith('Uid:')]
assert uids==[['64055']*4]
observed={}
for role,path,flags in [('media',sys.argv[1],os.O_RDONLY),('target',sys.argv[2],os.O_RDWR),('observer',sys.argv[3],os.O_RDONLY)]:
    fd=os.open(path,flags|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd);data=os.read(fd,1);assert len(data)==1
        observed[role]={'dev':info.st_dev,'ino':info.st_ino,'read_bytes':len(data)}
    finally:os.close(fd)
    if role!='target':
        try:fd=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        except OSError as error:
            assert error.errno in(errno.EACCES,errno.EPERM)
            observed[role]['write_denied_errno']=error.errno
        else:
            os.close(fd)
            raise RuntimeError('readonly dependency unexpectedly opened writable')
print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'uids':[int(x)for x in uids[0]],'observed':observed,'owned_descriptors_closed':True}),flush=True)
'''
    paths = [Path(candidate['resultRoot']) / n for n in ('media-dac.stdout', 'media-dac.stderr')]
    record = modules['owned_command'].run_owned_command(
        [tool['path'], '-I', '-c', code, candidate['media']['path'], candidate['target']['path'],candidate['observer']['path']],
        None, 5, paths, stream_limit=65536)
    persist('media-dac-child', record)
    need(record['numericExit'] == 0 and record['lifecycleClosed'] is True and record['firstError'] is None
         and record['errors'] == [], 'actual DAC child numeric/EOF/reap/FD/children closure')
    with peer.RootFiles(candidate['resultRoot']) as files, files.lock():
        raw, ref = files.read('media-dac.stdout', mode=0o600, cap=65536)
    dac = strict(raw)
    need(dac.get('uid')==64055 and dac.get('gid')==993 and dac.get('uids')==[64055]*4
         and dac.get('owned_descriptors_closed')is True and set(dac.get('observed',{}))=={'media','target','observer'},
         'actual exact QEMU UID/GID and owned DAC descriptor closure')
    for role in('media','target','observer'):
        row=dac['observed'][role];pin=candidate[role]['identity']
        need(row.get('dev')==pin['st_dev']and row.get('ino')==pin['st_ino']and row.get('read_bytes')==1
             and(role=='target'or row.get('write_denied_errno')in(1,13)),
             'actual readonly media/controller and read-write target open/read permissions')
    media = candidate['media']; fd = os.open(media['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        need(peer.ident(os.fstat(fd)) == media['identity'] == peer.ident(os.lstat(media['path'])),
             'immutable medium full9 unchanged by target-only ACL preparation')
    finally:
        os.close(fd)
    result = {'kind': 'LIBVIRT_R7_ACCESS_STAGE_PENDING_FULL_HASH', 'nonce': candidate['nonce'],
        'bootID': grant['bootID'], 'candidate': candidate, 'grantPin': grant_pin, 'rows': rows, 'after': after,
        'original': candidate['original'], 'workingBefore': candidate['working'],
        'pendingFullContentProof': True, 'runtimeAuthorized': False,
        'mediaDAC': {**dac, 'numeric': record['numericExit'], 'EOF': record['stdoutEOF'] and record['stderrEOF'],
                     'reaped': record['reaped'], 'rawPin': ref}}
    persist('output-access-stage-pending-full-hash', result)
    return result


def run(candidate, request, grant_pin, persist):
    """One new canonical output job; never rewrites/enqueues/rearms a job.

    The ordinary phase and stopped readback are the concrete implementations
    above. Root separately authenticates current hardware/owner admission and
    the entire controller-A medium. Missing admission fails, never N/A/pass.
    """
    grant = strict(protected_bytes(grant_pin, grant=True))
    observer_manifest=strict(protected_bytes(candidate['observerManifest'],mode=0o444))
    need(observer_manifest.get('kind')=='EXE_STEAMOS_PHASE_MEDIA_V1'
         and observer_manifest.get('nonce')==candidate['nonce'], 'exact new source-A guest medium manifest')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    deadline = scope(grant, request, candidate, boot, time.time())
    need(grant['backendSources'] == candidate['backendSources'], 'new grant authenticates entire backend before execution')
    public = strict(protected_bytes(candidate['publicRangeReceipt'], mode=0o444, grant=True))
    media = candidate['media']; extent = public['imageArtifactRange']; backing = extent['backingFile']
    need(public['kind'] == 'ROOT_VERIFIED_STOPPED_WINDOWS_IMAGE_RANGE_V1'
         and public['identity'] == candidate['identity'] and public['normalWindowsImageAndVirtualUSB'] is True
         and public['stoppedFullReadback'] is True and public['tailZero'] is True
         and public['completedImagePreserved'] is True
         and backing['path'] == media['path'] and backing['size'] == media['bytes']
         and backing['sha256'] == media['sha256'] and backing['identity'] == media['identity']
         and extent['offset'] == 0 and extent['bytes'] + extent['tailBytes'] == media['bytes'],
         'exact current protected public range/media/retention join')
    created = strict(protected_bytes(grant['targetCreationPin']))
    need(created['kind'] == 'EXE_FRESH_OUTPUT_RAW_TARGET_V1' and created['creatorUID'] == 0
         and created['bootID'] == boot and created['freshBlank'] is True
         and created['path'] == candidate['target']['path'] and created['identity'] == candidate['target']['identity']
         and created['format'] == 'raw' and created['backingChain'] == []
         and created['capacityBytes'] == candidate['target']['bytes']
         and created['allocatedBytes'] >= created['capacityBytes']
         and created['layoutMinimumBytes'] == MINIMUM_INSTALL_BYTES,
         'actual same-boot create-only raw target provenance, not relabelled original data')
    modules = backend(grant['backendSources'])
    runner = output_runner(grant)
    peer, access, native, producer = (modules[n] for n in
        ('libvirt_peer', 'libvirt_access', 'libvirt_native', 'libvirt_producer'))
    need(candidate['resultRoot'] == '/run/opemos-libvirt-results-' + request['leaseNonce']
         and candidate['resultRoot'] not in (candidate['run'], candidate['output']),
         'one exact protected result root')
    for key, path in (('outputProducerPin', __file__), ('outputRunnerPin', runner.__file__)):
        ref = grant[key]
        need(ref['path'] == path and hashlib.sha256(native.held(ref, 1024**2)).hexdigest() == ref['sha256'],
             'complete exact output implementation graph bound to new grant')

    def current_ledger(label):
        # Future capture/journal names cannot be a frozen file-only list:
        # discover only this exact creator's five bounded roots at each edge.
        paths = list(grant['dependencies']); metadata = []; pending = []
        for path in grant['frameworkPaths']:
            if os.path.lexists(path): paths.append(path)
        roots = [candidate['run'], candidate['output'], candidate['resultRoot'],
                 '/run/opemos-output-proof-'+candidate['nonce'],
                 '/run/opemos-libvirt-queue-' + request['jobToken'],
                 '/run/opemos-vfio-' + request['leaseNonce']]
        pending.extend((Path(root), 0) for root in roots if os.path.lexists(root))
        seen = set()
        while pending:
            path, depth = pending.pop(); need(depth <= 4 and len(seen) < 2048, 'bounded exact output dependency tree')
            info = path.lstat(); key = (info.st_dev, info.st_ino)
            need(key not in seen and not stat.S_ISLNK(info.st_mode), 'no linked/cyclic output dependency')
            seen.add(key)
            if stat.S_ISREG(info.st_mode):
                paths.append(str(path))
            elif stat.S_ISDIR(info.st_mode):
                need(info.st_uid == 0, 'Root-owned generated output namespace')
                pending.extend((child, depth + 1) for child in path.iterdir())
                metadata.append({'path': str(path), 'identity': identity(info), 'allocatedBytes': info.st_blocks*512,
                                 'chargedBytes': max(info.st_size, info.st_blocks*512)})
            else:
                need(str(path) == candidate['run'] + '/vnc.sock' and stat.S_ISSOCK(info.st_mode),
                     'only exact runtime VNC socket, never a device/special dependency')
                metadata.append({'path': str(path), 'identity': identity(info), 'allocatedBytes': info.st_blocks*512,
                                 'chargedBytes': max(info.st_size, info.st_blocks*512)})
        value = runner.output_storage_ledger(paths, grant['reservedBytes'])
        value['metadata'] = metadata; value['chargedBytes'] += sum(row['chargedBytes'] for row in metadata)
        need(value['chargedBytes'] <= 60_000_000_000, 'complete metadata/capture/source/target/media output VM limit')
        headroom = []
        need(type(grant['hostStorageRoots']) is list and grant['hostStorageRoots'], 'actual host storage/headroom roots')
        for root in grant['hostStorageRoots']:
            path = Path(root['path']); need(path.is_absolute() and path.resolve() == path, 'exact host storage root')
            info = path.stat(); space = os.statvfs(path)
            free = space.f_bavail * space.f_frsize
            need(info.st_dev == root['device'] and type(root['requiredFreeBytes']) is int
                 and root['requiredFreeBytes'] >= grant['reservedBytes'] and free >= root['requiredFreeBytes'],
                 'actual same-filesystem host allocation headroom')
            headroom.append({'path': str(path), 'device': info.st_dev, 'freeBytes': free,
                             'requiredFreeBytes': root['requiredFreeBytes']})
        value['hostHeadroom'] = headroom; value['observation'] = label
        persist('complete-output-ledger-' + label, value)
        return value

    def preflight_child(phase):
        command = grant['phasePreflights'][phase]
        native.held(command['toolPin'], 32*1024**2)
        for ref in command['sourcePins']: native.held(ref, 1024**2)
        names = [phase + '-preflight' + suffix for suffix in ('.stdout', '.stderr')]
        paths = [Path(candidate['resultRoot']) / name for name in names]
        seconds = min(command['seconds'], deadline - time.time())
        need(seconds > 0, 'unchanged whole deadline exhausted before phase')
        record = modules['owned_command'].run_owned_command(
            command['preflightArgv'],
            None, seconds, paths,
            stream_limit=1024**2)
        persist('actual-child-' + phase + '-preflight', record)
        need(record['numericExit'] == 0 and record['lifecycleClosed'] is True
             and record['firstError'] is None and record['errors'] == []
             and not record.get('descendantClosureUNKNOWN', False),
             'actual phase child failed/overflow/closure UNKNOWN; retained raw logs')
        with peer.RootFiles(candidate['resultRoot']) as files, files.lock():
            raw, pin = files.read(names[0], mode=0o600, cap=1024**2)
            files.read(names[1], mode=0o600, cap=1024**2)
        value = strict(raw)
        persist('actual-phase-result-pin-' + phase + '-preflight', pin)
        return value

    class OutputOps(native.NativeTransactionOps):
        def full_preflight_and_entry(self, g, r, c):
            self.request = r; self.g = g; self.deadline = deadline
            pre = strict(native.held(g['currentPreflightPin'], 1024**2))
            owners = strict(native.held(g['ownersPin'], 1024**2))
            for value in (pre, owners):
                need(value['bootID'] == boot and value['producer']['uid'] == 0
                     and 0 <= time.time() - value['observedUnix'] <= 30, 'fresh actual full preflight/owners')
            need(pre['candidate'] == c and pre['request'] == r and pre['ownersPin'] == g['ownersPin']
                 and pre['wholeQueueConflictFree'] is True and pre['holderUnknowns'] == []
                 and pre['windowsProducerClosed'] is True and pre['allOwnedFDsClosed'] is True
                 and pre['sourceGatePassed'] is True and pre['installedCurrent'] is True
                 and pre['sourceCommit'] == c['identity'].get('controller_source_commit',c['identity']['source_commit'])
                 and pre['publicRangeReceipt'] == c['publicRangeReceipt']
                 and pre['pool'] == {'cpu.max': '1000000 100000', 'memory.max': str(32*1024**3), 'memory.swap.max': '0'},
                 'entire current producer/public/canonical/resource closure join')
            required = {c['media']['path'], c['target']['path'],c['observer']['path'],c['observerManifest']['path']}
            need(required <= set(g['dependencies']), 'media, target and complete controller medium charged to output VM')
            observed = runner.output_storage_ledger(g['dependencies'], g['reservedBytes'])
            need(observed == pre['outputLedger'], 'actual complete output dependency ledger differs')
            self.preflight = pre; self.diskOpenAttempted = True
            for key in ('original', 'working'):
                ref = c[key] if key == 'original' else g['preparedDiskPins'][key]
                fd = os.open(ref['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                self.diskfds.append(fd)
                need(peer.ident(os.fstat(fd)) == ref['identity'] == peer.ident(os.lstat(ref['path'])), 'held initial media/target full9')
                self.diskfdRecords[fd] = {'key': key, 'identity': ref['identity'],
                    'flags': __import__('fcntl').fcntl(fd, __import__('fcntl').F_GETFL), 'target': ref['path']}
            self.current_entry(r)

        def prepare_io(self, intent):
            # Existing six-role journal applies ONLY to target, vars, runtime
            # and output. Media must already be creator-sealed/readable before
            # public attestation; no ACL/content/identity mutation of it here.
            value = access.verify_prepared(self.c, self.g['preparedAccessPin'], self.g['preparedDiskPins'])
            self.accessRows = value['rows']
            for row in self.accessRows: self.access_persist('acl-before-' + row['role'], row)
            dac=self.preflight['mediaDAC']
            raw_dac=strict(native.held(dac['rawPin'],65536))
            need(all(dac.get(key)==raw_dac.get(key)for key in('uid','gid','uids','observed','owned_descriptors_closed'))
                 and dac.get('uid')==64055 and dac.get('gid')==993 and dac.get('uids')==[64055]*4
                 and dac.get('owned_descriptors_closed')is True and dac.get('numeric')==0
                 and dac.get('EOF')is True and dac.get('reaped')is True,
                 'actual retained same-QEMU UID opens/reads/write refusals and child closure')
            for role in('media','target','observer'):
                row=dac['observed'][role];pin=self.c[role]['identity']
                need(row.get('dev')==pin['st_dev']and row.get('ino')==pin['st_ino']and row.get('read_bytes')==1
                     and(role=='target'or row.get('write_denied_errno')in(1,13)),
                     'actual current DAC subject/permission differs from prepared dependency')

        def recheck_before_domain(self, intent, phase):
            need(1 <= phase <= 4 and time.time() < deadline, 'new finite four-boot lifecycle')
            pre = self.phasePreflight
            need(pre['kind'] == 'ROOT_CURRENT_OUTPUT_PHASE_PREFLIGHT_V1' and pre['bootID'] == boot
                 and pre['identity'] == candidate['identity'] and pre['request'] == request
                 and pre['phase'] == PHASES[phase-1] and pre['producer']['uid'] == 0
                 and 0 <= time.time() - pre['observedUnix'] <= 30
                 and pre['fullHardwareAndOwnerAdmission'] is True and pre['holderUnknowns'] == []
                 and pre['wholeQueueConflictFree'] is True and pre['effects'] == [],
                 'fresh full actual per-boot owner/GPU/canonical admission, never old first-boot evidence')
            peer.NativeOps().entry(intent, 'PREPARED'); peer.NativeOps().budget(self.request, 'PREPARED', None)
            need(runner.output_storage_ledger(self.g['dependencies'], self.g['reservedBytes'])['chargedBytes'] <= 60_000_000_000,
                 'current output VM ledger')
            for fd, key in zip(self.diskfds, ('original', 'working')):
                now = peer.ident(os.fstat(fd)); ref = self.c[key]
                need(now == peer.ident(os.lstat(ref['path'])), 'held/named disk custody')
                fields = tuple(now) if key == 'original' else ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_nlink', 'st_size')
                need(all(now[k] == ref['identity'][k] for k in fields), 'immutable media or same mutable target generation')

        def restore_access(self, intent, closure, locked_files=None):
            # A partial preparation/journal failure must NOT become a successful
            # empty six-role restore merely because no journal was found.
            def complete(files):
                for role in ('working-parent', 'working', 'runtime-parent', 'vars', 'output-parent', 'serial'):
                    files.read('acl-before-' + role + '.json')
            if locked_files is not None:
                complete(locked_files)
            else:
                with peer.RootFiles('/run/opemos-libvirt-queue-' + request['jobToken']) as files, files.lock():
                    complete(files)
            return super().restore_access(intent, closure, locked_files)

    ops = OutputOps(candidate, persist); intent = None; domain = None; rows = []; first = None; secondary = []
    phase_number = 0; launched = 0; final = None; logical_closed = False
    try:
        ops.verify_grant_and_sources(grant_pin, grant)
        ops.full_preflight_and_entry(grant, request, candidate)
        ops.configure_partition(request); need(ops.partition_empty(request), 'unused exact output partition')
        producer.create_root('/run/opemos-vfio-' + request['leaseNonce'])
        producer.create_root('/run/opemos-libvirt-queue-' + request['jobToken'])
        intent = {'kind': 'ROOT_EXACT_QUEUE_LIBVIRT_INTENT_R2', 'request': request, 'bootID': boot,
            'entry': ops.current_entry(request), 'grantPin': grant_pin, 'qemuPin': candidate['qemu'],
            'originalPin': candidate['original'], 'workingPin': candidate['working'],
            'firmwareCodePin': candidate['firmwareCode'], 'endpoints': candidate['hostdev'],
            'wholeDeadlineUnix': deadline, 'producerPin': grant['producerPin'],
            'failureControl': 'LIBVIRT_AUTODESTROY_CONTROLLER_CONNECTION', 'nativeTools': grant['nativeTools'],
            'accessPin': grant['accessPin'], 'accessScope': {'run': candidate['run'], 'output': candidate['output'],
                'working': candidate['working'], 'firmwareVarsTemplate': candidate['firmwareVarsTemplate']},
            'outputInstall': {'phases': list(PHASES), 'identity': candidate['identity'],
                'targetGeneration': candidate['targetGeneration'], 'publicRangeReceipt': candidate['publicRangeReceipt']}}
        def commit(phase, details, registration=None, closed=False):
            nonlocal phase_number
            with peer.RootFiles('/run/opemos-libvirt-queue-' + request['jobToken']) as files, files.lock(True), \
                 peer.RootFiles('/run/opemos-vfio-' + request['leaseNonce']) as lease, lease.lock(True):
                if phase_number == 0: producer.put(files, 'intent.json', intent)
                change = {'closed': closed, 'restored': phase != 'ACTIVE',
                          'changed': [e['bdf'] for e in candidate['hostdev']] if phase == 'ACTIVE' else [],
                          'domain': registration, 'currentDisposition': details}
                producer.append_lease(lease, request, boot, 'OUTPUT_' + phase, change)
                producer.commit_phase(files, request, boot, phase_number, phase,
                    None if registration is None else registration['scope'],
                    None if registration is None else registration['leader'], details)
                phase_number += 1
        commit('PREPARED', {'installationNotStarted': True})
        ops.prepare_io(intent)
        current_ledger('before-first-domain')
        connection = ops.prepare_controller_connection(intent)
        need(connection['heldVerified'] is True, 'owned AUTODESTROY connection')
        with peer.RootFiles('/run/opemos-libvirt-queue-' + request['jobToken']) as files, files.lock(True):
            producer.put(files, 'controller-connection.json', connection)
        phase_closures=[];stopped_readbacks=[]
        for number, phase in enumerate(PHASES, 1):
            ops.phasePreflight = preflight_child(phase)
            ops.recheck_before_domain(intent, number)
            target = dict(candidate['target'], format='raw', backingChain=[], capacityBytes=candidate['target']['bytes'])
            target['identity'] = peer.ident(os.lstat(target['path']))
            native.held(candidate['observer'],64*1024**2)
            xml = runner.output_install_disks_xml(producer.make_xml(candidate, request), candidate['media'], target, number == 1,
                observer=candidate['observer'],manifest_sha256=candidate['observerManifest']['sha256'])
            domain = ops.create_paused(xml); launched += 1
            registration = ops.register_actual_domain(domain, intent)
            commit('ACTIVE', {'phase': phase, 'number': number}, registration)
            current_ledger('during-paused-' + phase)
            peer.observe(request, ops.readonly()); ops.resume_exact(domain, registration, intent)
            fd_proof = runner.observe_output_disk_fds(registration['leader']['pid'], registration['leader']['start'],
                64055, peer.process(registration['leader']['pid'])['cgroup'], candidate['media'], target, number == 1,
                writable_paths=[candidate['run'] + '/OVMF_VARS_4M.fd', *grant['frameworkPaths']],
                readonly_refs=[candidate['observer']])
            persist('disk-access-' + phase, fd_proof)
            transaction=guest_phase(ops.conn,domain,registration,request,candidate,phase,rows,
                                    observer_manifest,min(deadline,time.time()+480),persist)
            value = consume_guest_phase(transaction,phase,candidate,rows)
            for ref in value['files'].values(): native.held(ref, 8*1024**2)
            persist('phase-' + phase, value); rows.append(value)
            if grant['phasePreflights'][phase]['stopMode'] == 'controller-autodestroy':
                current_domain = ops.prepare_disconnect(domain, intent)
                domain = None
                ops.disconnect_exact(current_domain, intent)
            else:
                # A normal ACPI request is not shutdown evidence. The existing
                # event/absence/UID/cgroup/VFIO finalizers must still prove it.
                import libvirt
                need(domain.shutdownFlags(libvirt.VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN)==0,
                     'ordinary actual guest ACPI shutdown request failed')
                ops.wait_guest_shutdown(domain, intent)
            closure = ops.prove_domain_closure(domain, intent)
            domain = None
            need(closure['unknown'] == [] and all(closure[k] is True for k in
                 ('domainAbsent', 'originalPIDStartAbsent', 'cgroupEmpty', 'VFIOFDsAbsent', 'hostRestored')),
                 'complete phase domain/GPU/FD closure')
            commit('PREPARED', closure)
            phase_closures.append(closure)
            stopped = stopped_target_readback(candidate,value,closure,modules['owned_command'],native,
                                              grant['nativeTools'],deadline,persist)
            need(stopped['phaseResultSHA256'] == hashlib.sha256(canonical(value)).hexdigest()
                 and stopped['targetGeneration'] == candidate['targetGeneration']
                 and stopped['phase'] == phase and stopped['identity'] == candidate['identity']
                 and stopped['mountClosed'] is True and stopped['loopClosed'] is True,
                 'actual separate stopped readback, unchanged target and mount/loop closure')
            persist('stopped-readback-' + phase, stopped)
            stopped_readbacks.append(stopped)
            current_ledger('after-stopped-' + phase)
        # The phase producers provide bounded stopped readbacks from actual
        # installed filesystems, with UUID/boot lineage joined above. There is
        # no historical synthetic-home offset or old two-boot ledger reuse.
        ops.original_unchanged(intent)
        ops.restore_access(intent, closure)
        commit('CLOSED', closure, closed=True); logical_closed = True
    except BaseException as error:
        first = {'type': type(error).__name__, 'reason': str(error), 'evidence': getattr(error, 'evidence', None)}
        try: persist('FIRST-output-install', first)
        except BaseException as persistence_error:
            secondary.append({'phase': 'first-failure-persistence', 'type': type(persistence_error).__name__,
                              'reason': str(persistence_error)})
    finally:
        had_domain = domain is not None; domain = None
        try: final = ops.final_close(intent, had_domain)
        except BaseException as error:
            final = {'known': False, 'FDsClosed': False}
            secondary.append({'type': type(error).__name__, 'reason': str(error)})
    if first is not None and isinstance(first.get('evidence'),dict)and first['evidence'].get('lifecycleUnknown')is True:
        final=dict(final,known=False,FDsClosed=False,stoppedReadbackClosureUnknown=first['evidence'])
    if first is not None and intent is not None and not logical_closed and final.get('known') is True and final.get('FDsClosed') is True:
        try:
            current = {'first': first, 'secondary': secondary, 'currentClosure': final,
                       'historicalQMPClosed': None, 'noHistoricalCloseFabrication': True}
            commit('CLOSED', current, closed=True)
            persist('failed-known-current-closure', peer.observe(request, ops.readonly()))
            logical_closed = True
        except BaseException as error:
            secondary.append({'type': type(error).__name__, 'reason': str(error)})
    accepted = first is None and not secondary and len(rows) == 4 and logical_closed and final.get('known') is True and final.get('FDsClosed') is True
    value = {'kind': 'EXE_OUTPUT_INSTALL_FOUR_BOOT_RESULT_V1', 'accepted': accepted, 'first': first,
        'secondary': secondary, 'rows': rows, 'launches': launched, 'closure': final,
        'logicalLeaseClosed': logical_closed, 'leaseMustRemainHeld': not (logical_closed and final.get('known') is True),
        'runtimeAuthorized': grant['runtimeAuthorized'], 'MODEL_ONLY': False,
        'leaseNonce':candidate['nonce'],'rootRequest':request,'rootBootID':boot,'runtimeGrantPin':grant_pin,
        'sourceGraph':{key:grant[key]for key in('outputProducerPin','outputRunnerPin','outputCeilingPin')}}
    value.update(phaseClosures=locals().get('phase_closures',[]),stoppedReadbacks=locals().get('stopped_readbacks',[]))
    if accepted:
        try:
            value['publicInstallProof']=seal_output_install_proof(value,candidate)
            current_ledger('after-sealed-output-proof')
        except BaseException as error:
            value.update(accepted=False,first={'type':type(error).__name__,'reason':str(error),
                'phase':'local-proof-publication','VM_replay_authorized':False})
    persist('terminal-output-install', value)
    return value

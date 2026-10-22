"""Finite output-install successor of the existing queue/libvirt transaction.

No CLI, queue submission, installed source change or effect occurs on import.
Root installs/adopts the entire authenticated source graph and supplies a NEW
finite grant. Historical R69 grants are deliberately rejected. The existing
readonly queue peer, controller custody, AUTODESTROY/event driver, GPU restore
and descriptor finalizers remain the underlying native implementation.
"""
import hashlib
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
    need(set(grant['phaseCommands']) == set(PHASES), 'four exact ordinary Robot/guest phase commands')
    for phase, command in grant['phaseCommands'].items():
        need(command['phase'] == phase and command['request'] == request
             and command['identity'] == candidate['identity']
             and type(command['argv']) is list and 1 <= len(command['argv']) <= 32
             and all(type(x) is str and '\0' not in x for x in command['argv'])
             and command['argv'][0] == command['toolPin']['path'],
             'exact source-bound ordinary phase command, no shell/interpolation')
        need(type(command['seconds']) is int and 0 < command['seconds'] <= 480
             and command['stoppedReadbackArgv'][0] == command['toolPin']['path']
             and command['preflightArgv'][0] == command['toolPin']['path']
             and type(command['sourcePins']) is list and command['sourcePins'],
             'finite normal phase and separate stopped-readback command')
        expected_stop = 'controller-autodestroy' if phase == 'update' else 'guest-shutdown'
        need(command['stopMode'] == expected_stop, 'exact normal/abrupt recovery phase ordering')
    need(grant.get('abruptRecoveryAuthorized') is True, 'new exact abrupt-recovery scope, not an inherited grant')
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
    if phase in ('update', 'recovery'):
        need(value.get('sameTargetKernelTransition') is True and value.get('nvidia575FiveModules') is True
             and value.get('nvidiaRender') is True and value.get('driverReceiptVerified') is True,
             'actual matching NVIDIA575 five modules/render/receipt, not PCI visibility')
    if phase == 'recovery':
        need(value.get('recoveryVerified') is True, 'actual same-target recovery proof')
    return value


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
        fields = Path('/proc/' + str(registration['leader']['pid']) + '/stat').read_text().rsplit(')', 1)[1].split()
        need(int(fields[19]) == registration['leader']['start'], 'same original actual QEMU birth')
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
    code = ('import os,sys,json; os.setgroups([]); os.setgid(993); os.setuid(64055); '
            'print(json.dumps({"uid":os.getuid(),"gid":os.getgid(),'
            '"readable":os.access(sys.argv[1],os.R_OK,effective_ids=True),'
            '"writable":os.access(sys.argv[1],os.W_OK,effective_ids=True),'
            '"targetRW":os.access(sys.argv[2],os.R_OK|os.W_OK,effective_ids=True)}),flush=True)')
    paths = [Path(candidate['resultRoot']) / n for n in ('media-dac.stdout', 'media-dac.stderr')]
    record = modules['owned_command'].run_owned_command(
        [tool['path'], '-I', '-c', code, candidate['media']['path'], candidate['target']['path']],
        None, 5, paths, stream_limit=65536)
    persist('media-dac-child', record)
    need(record['numericExit'] == 0 and record['lifecycleClosed'] is True and record['firstError'] is None
         and record['errors'] == [], 'actual DAC child numeric/EOF/reap/FD/children closure')
    with peer.RootFiles(candidate['resultRoot']) as files, files.lock():
        raw, ref = files.read('media-dac.stdout', mode=0o600, cap=65536)
    dac = strict(raw)
    need(dac == {'uid': 64055, 'gid': 993, 'readable': True, 'writable': False, 'targetRW': True},
         'actual immutable media read-only and separate target read/write permissions')
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

    The ordinary phase commands are separately authenticated source-bound
    native producers, including the existing real Robot sender/observer path.
    Missing native phase input is a failure, never N/A or a synthetic pass.
    """
    grant = strict(protected_bytes(grant_pin, grant=True))
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

    def phase_child(phase, verb='ordinary'):
        command = grant['phaseCommands'][phase]
        native.held(command['toolPin'], 32*1024**2)
        for ref in command['sourcePins']: native.held(ref, 1024**2)
        need(verb in ('ordinary', 'stopped', 'preflight'), 'one finite ordinary phase operation')
        names = [phase + '-' + verb + suffix for suffix in ('.stdout', '.stderr')]
        paths = [Path(candidate['resultRoot']) / name for name in names]
        seconds = min(command['seconds'], deadline - time.time())
        need(seconds > 0, 'unchanged whole deadline exhausted before phase')
        record = modules['owned_command'].run_owned_command(
            command[{'stopped': 'stoppedReadbackArgv', 'preflight': 'preflightArgv', 'ordinary': 'argv'}[verb]],
            None, seconds, paths,
            stream_limit=1024**2)
        persist('actual-child-' + phase + '-' + verb, record)
        need(record['numericExit'] == 0 and record['lifecycleClosed'] is True
             and record['firstError'] is None and record['errors'] == []
             and not record.get('descendantClosureUNKNOWN', False),
             'actual phase child failed/overflow/closure UNKNOWN; retained raw logs')
        with peer.RootFiles(candidate['resultRoot']) as files, files.lock():
            raw, pin = files.read(names[0], mode=0o600, cap=1024**2)
            files.read(names[1], mode=0o600, cap=1024**2)
        value = strict(raw)
        persist('actual-phase-result-pin-' + phase + '-' + verb, pin)
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
                 and pre['sourceCommit'] == c['identity']['source_commit']
                 and pre['publicRangeReceipt'] == c['publicRangeReceipt']
                 and pre['pool'] == {'cpu.max': '1000000 100000', 'memory.max': str(32*1024**3), 'memory.swap.max': '0'},
                 'entire current producer/public/canonical/resource closure join')
            required = {c['media']['path'], c['target']['path']}
            need(required <= set(g['dependencies']), 'both media and target charged to output VM')
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
            need(self.preflight['mediaDAC']['uid'] == 64055
                 and self.preflight['mediaDAC']['readable'] is True
                 and self.preflight['mediaDAC']['writable'] is False
                 and self.preflight['mediaDAC']['numeric'] == 0
                 and self.preflight['mediaDAC']['EOF'] is True
                 and self.preflight['mediaDAC']['reaped'] is True,
                 'real pre-use QEMU UID read-only media access probe required')

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
        for number, phase in enumerate(PHASES, 1):
            ops.phasePreflight = phase_child(phase, verb='preflight')
            ops.recheck_before_domain(intent, number)
            target = dict(candidate['target'], format='raw', backingChain=[], capacityBytes=candidate['target']['bytes'])
            target['identity'] = peer.ident(os.lstat(target['path']))
            xml = runner.output_install_disks_xml(producer.make_xml(candidate, request), candidate['media'], target, number == 1)
            domain = ops.create_paused(xml); launched += 1
            registration = ops.register_actual_domain(domain, intent)
            commit('ACTIVE', {'phase': phase, 'number': number}, registration)
            current_ledger('during-paused-' + phase)
            peer.observe(request, ops.readonly()); ops.resume_exact(domain, registration, intent)
            fd_proof = runner.observe_output_disk_fds(registration['leader']['pid'], registration['leader']['start'],
                64055, peer.process(registration['leader']['pid'])['cgroup'], candidate['media'], target, number == 1,
                writable_paths=[candidate['run'] + '/OVMF_VARS_4M.fd', *grant['frameworkPaths']])
            persist('disk-access-' + phase, fd_proof)
            value = phase_result(phase_child(phase), phase, candidate, rows)
            for ref in value['files'].values(): native.held(ref, 8*1024**2)
            persist('phase-' + phase, value); rows.append(value)
            if grant['phaseCommands'][phase]['stopMode'] == 'controller-autodestroy':
                current_domain = ops.prepare_disconnect(domain, intent)
                domain = None
                ops.disconnect_exact(current_domain, intent)
            else:
                ops.wait_guest_shutdown(domain, intent)
            closure = ops.prove_domain_closure(domain, intent)
            domain = None
            need(closure['unknown'] == [] and all(closure[k] is True for k in
                 ('domainAbsent', 'originalPIDStartAbsent', 'cgroupEmpty', 'VFIOFDsAbsent', 'hostRestored')),
                 'complete phase domain/GPU/FD closure')
            commit('PREPARED', closure)
            stopped = phase_child(phase, verb='stopped')
            need(stopped['phaseResultSHA256'] == hashlib.sha256(canonical(value)).hexdigest()
                 and stopped['targetGeneration'] == candidate['targetGeneration']
                 and stopped['phase'] == phase and stopped['identity'] == candidate['identity']
                 and stopped['mountClosed'] is True and stopped['loopClosed'] is True,
                 'actual separate stopped readback, unchanged target and mount/loop closure')
            persist('stopped-readback-' + phase, stopped)
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
    if first is not None and intent is not None and not logical_closed and final.get('known') is True and final.get('FDsClosed') is True:
        try:
            current = {'first': first, 'secondary': secondary, 'currentClosure': final,
                       'historicalQMPClosed': None, 'noHistoricalCloseFabrication': True}
            commit('CLOSED', current, closed=True)
            persist('failed-known-current-closure', peer.observe(request, ops.readonly()))
            logical_closed = True
        except BaseException as error:
            secondary.append({'type': type(error).__name__, 'reason': str(error)})
    accepted = first is None and len(rows) == 4 and logical_closed and final.get('known') is True and final.get('FDsClosed') is True
    value = {'kind': 'EXE_OUTPUT_INSTALL_FOUR_BOOT_RESULT_V1', 'accepted': accepted, 'first': first,
        'secondary': secondary, 'rows': rows, 'launches': launched, 'closure': final,
        'logicalLeaseClosed': logical_closed, 'leaseMustRemainHeld': not (logical_closed and final.get('known') is True),
        'runtimeAuthorized': grant['runtimeAuthorized'], 'MODEL_ONLY': False}
    persist('terminal-output-install', value)
    return value

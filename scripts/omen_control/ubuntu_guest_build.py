#!/usr/bin/env python3
"""Compile/package in the admitted disposable Ubuntu guest, never on OMEN host.

The controller supplies an authenticated, read-only input medium. Candidate
sources, build scripts and AppImages are interpreted only here, as UID1000.
This is one stage of the normal queue operation, not another VM executor.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zipfile
import types

REPOSITORY = 'CorniiDog/OPEMOS.EXE'
PACKAGES = ('build-essential','ca-certificates','curl','file','genisoimage','git',
            'libayatana-appindicator3-dev','librsvg2-dev','libssl-dev',
            'libwebkit2gtk-4.1-dev','openssh-client','ovmf','patchelf',
            'pkg-config','python3','qemu-system-x86','qemu-utils','xdg-utils','xz-utils')


def need(ok, reason):
    if not ok: raise ValueError(reason)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        while block := source.read(1048576): h.update(block)
    return h.hexdigest()


def extract_inputs(archive, destination, limit):
    """Finite guest-only extraction, with no escaping links or special files."""
    destination = Path(destination)
    need(not destination.exists(), 'fresh source-build workspace')
    destination.mkdir(mode=0o700)
    total = 0; seen = set()
    with tarfile.open(archive, 'r:*') as source:
        for item in source:
            path = Path(item.name)
            need(not path.is_absolute() and path.parts and '..' not in path.parts and
                 '\\' not in item.name and item.name not in seen and
                 (item.isfile() or item.isdir() or item.issym()),
                 'unique relative regular source/tool input')
            seen.add(item.name); total += item.size
            need(len(seen) <= 250000 and total <= limit, 'measured source-build expansion bound')
            target = destination / path
            # Every ancestor was created by this extraction; do not walk links.
            parent = destination
            for part in path.parts[:-1]:
                parent /= part
                need(not parent.is_symlink(), 'input link used as a directory')
                parent.mkdir(mode=0o700, exist_ok=True)
            if item.isdir():
                target.mkdir(mode=0o700, exist_ok=True)
            elif item.issym():
                link = Path(item.linkname)
                need(not link.is_absolute() and
                     (target.parent / link).resolve().is_relative_to(destination.resolve()),
                     'toolchain symlink escapes guest workspace')
                target.symlink_to(item.linkname)
            else:
                fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(fd, 'wb', closefd=False) as output, source.extractfile(item) as data:
                        shutil.copyfileobj(data, output, 1048576); output.flush()
                    os.fchmod(fd, 0o700 if item.mode & 0o111 else 0o600)
                finally: os.close(fd)
    return {'files': len(seen), 'expanded_bytes': total}


def run(argv, cwd, env, log, end, owned):
    remaining = end - time.monotonic()
    need(remaining > 0, 'original source-build deadline expired')
    # Reuse the maintained pidfd/EOF/reap/FD lifecycle implementation. Do not
    # invent a compiler-specific process supervisor or infer closure from exit.
    previous=os.open('.',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        os.chdir(cwd)
        # The maintained child supervisor deliberately supplies a clean env.
        # Carry this guest's explicit toolchain/build inputs in argv instead of
        # relying on process-global environment that the supervisor discards.
        command = ['/usr/bin/env', *[key+'='+value for key,value in sorted(env.items())], *argv]
        native = owned.run_owned_command(command,None,remaining,
            [Path(str(log)+'.stdout'),Path(str(log)+'.stderr')],stream_limit=32*1024*1024)
    finally:
        os.fchdir(previous);os.close(previous)
    return {'argv':argv,'numeric':native['numericExit'],'native':native,
            'logs':[{'name':Path(str(log)+suffix).name,
                     'bytes':Path(str(log)+suffix).stat().st_size,
                     'sha256':sha(str(log)+suffix)} for suffix in('.stdout','.stderr')]}


def prerequisite_apt_options(root):
    return ['-o','Dir::Cache::archives='+str(root),
            '-o','Dir::State::lists='+str(root/'apt-lists'),
            '-o','Dir::Etc::sourcelist='+str(root/'apt-sources.list'),
            '-o','Dir::Etc::sourceparts='+str(root/'apt-sources.d')]


def prerequisite_repository(root, debs, packages, deadline):
    """Expose authenticated dependency bytes without requesting their installation.

    This operation-local index adds no external repository or persistent trust
    configuration. Its package records come only from the already hash-bound
    input medium; APT still resolves against the guest's real installed status.
    """
    need(type(packages) is list and packages and
         all(type(p) is str and re.fullmatch('[a-z0-9][a-z0-9+.-]*',p)
             for p in packages) and len(set(packages)) == len(packages),
         'declared prerequisite package names')
    records = []; available = set()
    for deb in debs:
        remaining = deadline-time.monotonic()
        need(remaining > 0, 'original prerequisite deadline before package metadata')
        control = subprocess.run(['/usr/bin/dpkg-deb','--field',str(root/deb['name'])],
                                 capture_output=True,text=True,check=True,
                                 timeout=min(10,remaining)).stdout.rstrip('\n')
        fields = dict(line.split(': ',1) for line in control.splitlines()
                      if line and not line[0].isspace() and ': ' in line)
        name = fields.get('Package','')
        need(re.fullmatch('[a-z0-9][a-z0-9+.-]*',name) and
             fields.get('Architecture') in ('amd64','all') and fields.get('Version') and
             not any(k in fields for k in ('Filename','Size','SHA256')),
             'actual native prerequisite package control')
        available.add(name)
        records.append(control+'\nFilename: ./'+deb['name']+'\nSize: '+str(deb['bytes'])+
                       '\nSHA256: '+deb['sha256']+'\n\n')
    need(set(packages) <= available, 'declared prerequisite missing from offline input')
    (root/'Packages').write_text(''.join(records))
    (root/'apt-sources.list').write_text('deb [trusted=yes] file:'+str(root)+' ./\n')
    for directory in ('apt-lists','apt-sources.d'):
        (root/directory).mkdir(mode=0o700)
    return {'packages':packages,'index_sha256':sha(root/'Packages')}


def prerequisite_install_argv(root, packages):
    # --no-download consumes APT's archive cache. Local path operands alone
    # can still be queued for acquisition (including a repository copy of the
    # same version); bind the cache to the exact extracted, authenticated debs.
    return ['/usr/bin/apt-get','--yes','--no-download','--no-install-recommends',
            '--no-remove',*prerequisite_apt_options(root),'install',*packages]


def install_prerequisites(config):
    """Only the nonce-bound, new disposable guest's Root may install inputs."""
    need(os.getuid() == os.geteuid() == 0, 'guest prerequisite owner')
    nonce = config['nonce']
    need(re.fullmatch('[0-9a-f]{32}', nonce) and
         Path('/sys/class/dmi/id/product_name').read_text().strip() ==
         'opemos-robot-ubuntu-' + nonce, 'exact disposable guest, never the physical host')
    archive = Path(config['input_archive'])
    mount = subprocess.run(['/usr/bin/findmnt','-n','-o','FSTYPE,OPTIONS','-T',str(archive)],
                           capture_output=True,text=True,check=True,timeout=10).stdout.split()
    need(len(mount) == 2 and mount[0] == 'iso9660' and 'ro' in mount[1].split(','),
         'read-only controller-provided build input medium')
    need(sha(archive) == config['input_sha256'], 'whole actual source-input archive')
    root = Path('/var/lib') / ('opemos-guest-prerequisites-' + nonce)
    need(not root.exists(), 'prerequisite installation is create-only')
    root.mkdir(mode=0o700)
    result = {'kind':'OMEN_GUEST_PREREQUISITES_V1','nonce':nonce,
              'input_sha256':config['input_sha256'],'debs':[],'first_failure':None}
    try:
        total = 0
        with tarfile.open(archive,'r:*') as source:
            for item in source:
                path = Path(item.name)
                if not path.parts or path.parts[0] != 'debs': continue
                need(len(path.parts) == 2 and item.isfile() and path.suffix == '.deb' and
                     re.fullmatch(r'[a-zA-Z0-9+.:_%~-]+\.deb',path.name),
                     'flat regular offline Ubuntu package member')
                total += item.size
                need(total <= config['expanded_bytes'], 'whole admitted package input bound')
                target = root/path.name
                with target.open('xb') as output, source.extractfile(item) as data:
                    shutil.copyfileobj(data,output,1048576)
                target.chmod(0o600)
                result['debs'].append({'name':path.name,'bytes':target.stat().st_size,
                                       'sha256':sha(target)})
        need(result['debs'], 'actual offline prerequisite packages absent')
        # No external guest networking or silent package fallback. All package
        # bytes came from this admitted operation's authenticated input medium.
        deadline = time.monotonic()+600
        result['requested_prerequisites'] = prerequisite_repository(
            root,result['debs'],config['packages'],deadline)
        # The local index makes the complete dependency closure available, but
        # only the authenticated top-level request is an installation operand.
        # Private sources/lists prevent stale guest repositories or networking
        # from changing this transaction; the guest's real dpkg status remains.
        for action,argv in [('index',['/usr/bin/apt-get',*prerequisite_apt_options(root),'update']),
                            ('install',prerequisite_install_argv(root,config['packages']))]:
            remaining = deadline-time.monotonic()
            need(remaining > 0, 'original prerequisite deadline before '+action)
            completed = subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT,timeout=remaining)
            if action == 'index':
                (root/'apt-index.log').write_bytes(completed.stdout)
                need(completed.returncode == 0, 'authenticated local prerequisite index failed: '+
                     completed.stdout[-4096:].decode('utf8','replace'))
        (root/'apt.log').write_bytes(completed.stdout)
        result['apt_numeric'] = completed.returncode
        result['apt_log'] = {'name':'apt.log','bytes':len(completed.stdout),
                             'sha256':hashlib.sha256(completed.stdout).hexdigest()}
        # The existing bootstrap event carries the build-log tail. Preserve
        # apt's actual refusal there, instead of only this wrapper traceback.
        need(completed.returncode == 0,
             'offline guest prerequisite installation failed (exit '+
             str(completed.returncode)+', apt.log sha256 '+
             result['apt_log']['sha256']+'):\n'+
             completed.stdout[-4096:].decode('utf8','replace'))
        for name in ('qemu-img','qemu-system-x86_64','genisoimage','ssh','ssh-keygen','python3'):
            need(shutil.which(name), 'required installed guest executable absent: '+name)
        need(Path('/usr/share/OVMF/OVMF_CODE_4M.fd').is_file(), 'installed guest OVMF absent')
        subprocess.run(['/usr/sbin/modprobe','kvm_intel'],check=True,timeout=10)
        kvm = Path('/dev/kvm'); info = kvm.lstat()
        need(stat.S_ISCHR(info.st_mode) and os.major(info.st_rdev) == 10 and
             os.minor(info.st_rdev) == 232, 'actual guest KVM device required')
        os.chown(kvm,0,1000); os.chmod(kvm,0o660)
        result['guest_kvm_device'] = {'major':10,'minor':232,'uid':0,'gid':1000,'mode':'0660'}
    except BaseException as error:
        result['first_failure'] = {'type':type(error).__name__,'reason':str(error)[:1000]}
        raise
    finally:
        (root/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    return result


def kvm_viability():
    """A real, finite guest-owned KVM machine; no TCG fallback or OS-boot claim."""
    commands = [{'execute':'qmp_capabilities','id':1},
                {'execute':'query-kvm','id':2}, {'execute':'quit','id':3}]
    p = subprocess.run(['/usr/bin/qemu-system-x86_64','-nodefaults','-machine','q35,accel=kvm',
        '-cpu','host','-m','256','-S','-display','none','-nic','none','-monitor','none',
        '-serial','none','-qmp','stdio'],input=''.join(json.dumps(c)+'\n' for c in commands),
        capture_output=True,text=True,timeout=15)
    rows = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
    actual = [r for r in rows if r.get('id') == 2]
    need(p.returncode == 0 and len(actual) == 1 and
         actual[0].get('return') == {'enabled':True,'present':True},
         'actual nested guest KVM unavailable; no fallback')
    return {'numeric':p.returncode,'query_kvm':actual[0]['return'],
            'stderr':p.stderr[:2048],'guest_OS_boot_accepted':False}


def build(config, workspace):
    need(os.getuid() == os.geteuid() == 1000, 'ordinary guest compiler only')
    nonce = config['nonce']; source = config['candidate_source_commit']
    need(re.fullmatch('[0-9a-f]{32}', nonce) and re.fullmatch('[0-9a-f]{40}', source),
         'exact admitted source-build identity')
    need(Path('/sys/class/dmi/id/product_name').read_text().strip() ==
         'opemos-robot-ubuntu-' + nonce, 'source compilation must execute in its admitted VM')
    need(Path('/dev/virtio-ports/opemos.robot.observer').exists(), 'actual guest transport')
    archive = Path(config['input_archive'])
    need(archive.is_file() and sha(archive) == config['input_sha256'], 'exact source-input bytes')
    need(type(config['remaining_seconds'])in(int,float) and 0<config['remaining_seconds']<=7200,
         'same finite admitted build clock')
    end = time.monotonic() + config['remaining_seconds']
    transport = Path(__file__).with_name('owned_command.py')
    need(sha(transport)==config['owned_command_sha256'],'exact maintained guest child transport')
    owned = types.ModuleType('guest_owned_command'); owned.__file__=str(transport)
    exec(compile(transport.read_bytes(),str(transport),'exec'),owned.__dict__)
    root = Path(workspace)
    viability = kvm_viability()
    extracted = extract_inputs(archive, root, config['expanded_bytes'])
    checkout = root / 'source'
    env = {k: v for k, v in os.environ.items() if k in ('HOME','USER','LANG','DISPLAY','XAUTHORITY')}
    env.update(PATH=str(root/'node/bin') + ':' + str(root/'rust/bin') + ':/usr/bin:/bin',
               CARGO_HOME=str(root/'cargo'), RUSTUP_HOME=str(root/'rustup'),
               XDG_CACHE_HOME=str(root/'cache'),
               npm_config_cache=str(root/'npm'), CARGO_NET_OFFLINE='true',
               OPEMOS_EXPERIMENTAL_LINUX='1', OPEMOS_LINUX_ACCEL='kvm',
               OPEMOS_CORE_CONTRACT_ROOT=str(root/'core'),
               GITHUB_ACTIONS='true', GITHUB_REPOSITORY=REPOSITORY,
               GITHUB_SHA=source, GITHUB_RUN_ID=config['producer_run_id'],
               GITHUB_RUN_ATTEMPT=config['producer_attempt'])
    commands = [
        ['node','--version'], ['rustc','--version'],
        ['npm','ci','--offline'], ['npm','run','build:linux-test'],
        ['python3','scripts/stage_linux_packages.py','--source-commit',source,
         '--appliance-image',str(root/'appliance/fedora-builder.qcow2'),
         '--include-native-executable']]
    receipt = {'kind':'OMEN_UBUNTU_GUEST_SOURCE_BUILD_V1','nonce':nonce,
               'source_commit':source,'source_input_sha256':config['input_sha256'],
               'builder_sha256':sha(__file__),'guest_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
               'guest_kernel':os.uname().release,'uid':os.getuid(),'pid':os.getpid(),
               'kvm':viability,'extraction':extracted,'commands':[],'packages':[], 'first_failure':None}
    try:
        for index, argv in enumerate(commands):
            result = run(argv, checkout, env, root/('build-'+str(index)), end, owned)
            receipt['commands'].append(result)
            need(result['numeric'] == 0 and result['native']['lifecycleClosed']is True and
                 result['native']['errors']==[], 'actual guest compiler/package command failed: '+str(index))
        directory = checkout/'linux-package-artifact'
        need(directory.is_dir(), 'guest package output absent')
        logs=directory/'guest-build-logs';logs.mkdir(mode=0o700)
        for command in receipt['commands']:
            for log in command['logs']:
                source_log=root/log['name']
                need(sha(source_log)==log['sha256']and source_log.stat().st_size==log['bytes'],
                     'actual compiler log changed before export')
                shutil.copyfile(source_log,logs/log['name'])
        packages=list(directory.glob('*.AppImage'))
        need(len(packages)==1,'one actual guest-built AppImage')
        companion=Path(str(packages[0])+'.runtime')
        runtime=companion/'ubuntu-prerequisites.tar'
        # Reuse original, read-only download inputs. Candidate build scripts
        # cannot substitute the mutable workspace's copy of a prerequisite.
        members=[]
        with tarfile.open(archive,'r:*')as source, tarfile.open(runtime,'x')as target:
            for item in source:
                if Path(item.name).parts[:1]!=('debs',):continue
                need(item.isfile()and len(Path(item.name).parts)==2,'flat regular prerequisite member')
                data=source.extractfile(item);target.addfile(item,data);data.close()
                members.append({'name':item.name,'bytes':item.size})
        prerequisite={'kind':'OFFLINE_UBUNTU_GUEST_PREREQUISITES_V1',
            'source_input_sha256':config['input_sha256'],'tar_name':runtime.name,
            'tar_bytes':runtime.stat().st_size,'tar_sha256':sha(runtime),
            'expanded_bytes':sum(item['bytes']for item in members),'members':members,
            'packages':config['packages']}
        (companion/'ubuntu-prerequisites.json').write_text(json.dumps(prerequisite,sort_keys=True)+'\n')
        for file in sorted(directory.rglob('*')):
            info = file.lstat()
            need(not stat.S_ISLNK(info.st_mode), 'package output link refused')
            if stat.S_ISREG(info.st_mode):
                receipt['packages'].append({'name':str(file.relative_to(directory)),
                    'bytes':info.st_size,'sha256':sha(file)})
        need(receipt['packages'] and any(p['name'].endswith('.AppImage') for p in receipt['packages']),
             'actual AppImage output required')
        receipt['packaging_provenance'] = json.loads((directory/'provenance.json').read_bytes())
    except BaseException as error:
        receipt['first_failure'] = {'type':type(error).__name__, 'reason':str(error)[:1000]}
        tails=[]
        if receipt['commands']:
            for log in receipt['commands'][-1].get('logs',[]):
                with (root/log['name']).open('rb')as data:
                    data.seek(max(0,log['bytes']-3000))
                    tails.append({'name':log['name'],'tail':data.read(3000).decode('utf-8','replace')})
        print(json.dumps({'kind':'ACTUAL_GUEST_BUILD_FIRST','first':receipt['first_failure'],
                          'command_logs':tails},sort_keys=True),file=sys.stderr,flush=True)
        raise
    finally:
        (root/'guest-build-result.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    return receipt


def export_package(config, workspace, receipt):
    """Copy the actual guest outputs over the existing private virtio channel.

    The host stores this ZIP as opaque candidate DATA. It does not load an ELF,
    execute an AppImage or mount a guest-written filesystem to copy it out.
    """
    root = Path(workspace); directory = root/'source/linux-package-artifact'
    bundle = root/'guest-produced-package.zip'
    with zipfile.ZipFile(bundle,'x',compression=zipfile.ZIP_STORED) as output:
        for expected in receipt['packages']:
            path = directory/expected['name']
            fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                before = os.fstat(fd); digest = hashlib.sha256(); total = 0
                info = zipfile.ZipInfo(expected['name'])
                info.external_attr = (stat.S_IFREG|stat.S_IMODE(before.st_mode)) << 16
                with output.open(info,'w',force_zip64=True) as target:
                    while block := os.read(fd,1048576):
                        total += len(block); digest.update(block); target.write(block)
                fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                          'st_size','st_mtime_ns','st_ctime_ns')
                need(all(getattr(before,k) == getattr(os.fstat(fd),k) == getattr(path.lstat(),k)
                         for k in fields) and total == expected['bytes'] and
                     digest.hexdigest() == expected['sha256'], 'actual package changed during export')
            finally: os.close(fd)
    size = bundle.stat().st_size
    need(0 < size <= config['max_package_bytes'] <= 2147483648,
         'actual produced package exceeds existing candidate bound')
    package_sha = sha(bundle)
    header = {'kind':'GUEST_PACKAGE_BEGIN','nonce':config['nonce'],
              'source_commit':config['candidate_source_commit'],'bytes':size,
              'sha256':package_sha,'build_receipt':receipt}
    wire = (json.dumps(header,sort_keys=True,separators=(',',':'))+'\n').encode()
    need(len(wire) <= 1048576, 'bounded guest build/output header')
    port = os.open('/dev/virtio-ports/opemos.robot.observer',os.O_WRONLY|os.O_CLOEXEC)
    try:
        def send(raw):
            view = memoryview(raw)
            while view:
                count = os.write(port,view); need(count > 0,'guest output channel stalled');view = view[count:]
        send(wire)
        with bundle.open('rb') as data:
            while block := data.read(1048576): send(block)
        send((json.dumps({'kind':'GUEST_PACKAGE_END','nonce':config['nonce'],
                          'bytes':size,'sha256':package_sha},sort_keys=True)+'\n').encode())
    finally: os.close(port)
    return {'bytes':size,'sha256':package_sha}


if __name__ == '__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--verify-kvm':
        nonce=sys.argv[2]
        need(os.getuid()==os.geteuid()==1000 and re.fullmatch('[0-9a-f]{32}',nonce)and
             Path('/sys/class/dmi/id/product_name').read_text().strip()==
             'opemos-robot-ubuntu-'+nonce,'actual ordinary source-bound guest KVM check')
        print(json.dumps(kvm_viability(),sort_keys=True))
    elif sys.argv[1:] == ['--install-prerequisites']:
        path = Path(__file__).with_suffix('.json')
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600, 'Root-owned nonce-bound guest input definition')
        print(json.dumps(install_prerequisites(json.loads(path.read_bytes())),sort_keys=True))
    else:
        need(len(sys.argv) == 4 and sys.argv[1] == '--admitted-source-build', 'fixed guest invocation')
        config = json.loads(Path(sys.argv[2]).read_bytes())
        receipt = build(config, sys.argv[3])
        print(json.dumps(export_package(config,sys.argv[3],receipt),sort_keys=True))

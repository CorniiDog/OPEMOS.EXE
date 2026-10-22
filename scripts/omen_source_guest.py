"""Fixed A guest source/check/build workload, never an OMEN-host entry point.

The existing Root-owned queue provisions this exact agent and its dependencies
on a disposable VM derivative. B is an authenticated readonly source medium;
only its guest working copy is executable. No network or credentials are added.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import time

from omen_source_workloads import WORKLOADS, subject, commands, canonical, need, verify_result
from omen_source_capture import capture

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def read(path, cap, sha=None, sealed=True):
    path=Path(path);fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        before=os.fstat(fd);sig=lambda s:tuple(getattr(s,k)for k in FIELDS)
        need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and
             (not before.st_mode&0o222 if sealed else not before.st_mode&0o022)and
             before.st_size<=cap,'sealed guest input')
        raw=bytearray()
        while block:=os.read(fd,min(65536,cap+1-len(raw))):
            raw.extend(block);need(len(raw)<=cap,'guest input overflow')
        need(len(raw)==before.st_size and sig(before)==sig(os.fstat(fd))==sig(path.lstat())and
             (sha is None or hashlib.sha256(raw).hexdigest()==sha),'guest input full9/hash/EOF')
        return bytes(raw)
    finally:os.close(fd)


def write(path, value):
    raw=canonical(value)+b'\n';need(len(raw)<=1024**2,'bounded complete guest result')
    with Path(path).open('xb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())


def copy_staged(entry, destination):
    pin=entry['inventory'];inventory=json.loads(read(pin['path'],64*1024**2,pin['sha256']))
    need(len(inventory['files'])<=262144,'finite complete offline dependency inventory')
    origin=Path(entry['path']);seen=set();total=0
    for row in inventory['files']:
        relative=Path(row['relative']);need(not relative.is_absolute()and '..'not in relative.parts and
             row['relative']not in seen and type(row['bytes'])is int and 0<=row['bytes']<=4*1024**3,
             'finite unique staged dependency regular leaf')
        seen.add(row['relative']);source=origin/relative;target=destination/relative
        need(not source.is_symlink()and source.resolve().is_relative_to(origin.resolve()),'staged source escaping/link')
        target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);fd=os.open(source,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        try:
            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==row['bytes'],
                                    'actual staged source type/size')
            h=hashlib.sha256();count=0
            with target.open('xb')as output:
                while block:=os.read(fd,1024**2):
                    count+=len(block);total+=len(block);need(count<=row['bytes']and total<=40*1024**3,'offline staged copy budget')
                    output.write(block);h.update(block)
                output.flush();os.fsync(output.fileno())
            need(count==row['bytes']and h.hexdigest()==row['sha256']and
                 all(getattr(before,k)==getattr(os.fstat(fd),k)==getattr(source.stat(),k)for k in FIELDS),
                 'complete staged dependency full9/hash/EOF')
            target.chmod(0o700 if row.get('executable')is True else 0o600)
        finally:os.close(fd)


def extract_source(archive, destination, expected):
    """A sealed git archive only: reject links/devices/traversal/duplicate paths."""
    raw=read(archive,256*1024**2,expected['source_archive_sha256'])
    need(len(raw)==expected['source_archive_bytes'],'exact staged source archive size')
    import io
    destination.mkdir(mode=0o700);seen=set();total=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as source:
        for member in source:
            p=Path(member.name)
            need(not p.is_absolute()and p.parts and '..'not in p.parts and '.'not in p.parts and
                 len(p.parts)<=64 and member.name not in seen and len(seen)<65536 and
                 (member.isfile()or member.isdir()),'finite source archive regular files/directories only')
            seen.add(member.name);target=destination/p
            if member.isdir():target.mkdir(mode=0o700,parents=True,exist_ok=True);continue
            total+=member.size;need(0<=member.size<=64*1024**2 and total<=512*1024**2,'expanded source cap')
            target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with source.extractfile(member)as input, target.open('xb')as output:
                remaining=member.size
                while remaining:
                    block=input.read(min(65536,remaining));need(block,'source archive truncated')
                    output.write(block);remaining-=len(block)
                need(input.read(1)==b'','source member overflow');output.flush();os.fsync(output.fileno())
            target.chmod(0o700 if member.mode&0o111 else 0o600)
    # Commit/tree binding is independently authenticated by Root before media
    # construction. A git archive is not relabelled as a clone with invented HEAD.
    return {'archiveSHA256':hashlib.sha256(raw).hexdigest(),'expandedBytes':total,'entries':len(seen)}


def extract_seed(pin, destination):
    """Actual six locked cache archives from the completed Ubuntu seed job."""
    destination=Path(destination);destination.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(pin['path'],os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));seen=set();total=0
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and
             not before.st_mode&0o222 and before.st_size==pin['bytes']<=512*1024**2,'sealed complete actual seed tar')
        h=hashlib.sha256();count=0
        while block:=os.read(fd,1024**2):h.update(block);count+=len(block);need(count<=pin['bytes'],'seed tar overflow')
        need(count==pin['bytes']and h.hexdigest()==pin['sha256'],'seed tar complete SHA/EOF')
        os.lseek(fd,0,os.SEEK_SET)
        with os.fdopen(os.dup(fd),'rb')as data,tarfile.open(fileobj=data,mode='r:')as source:
            for member in source:
                need(member.isfile()and Path(member.name).name==member.name and member.name not in seen and
                     len(seen)<6 and 0<member.size<=256*1024**2,'six distinct regular seed cache archives only')
                seen.add(member.name);total+=member.size;need(total<=512*1024**2,'actual seed expanded cap')
                with source.extractfile(member)as raw,(destination/member.name).open('xb')as target:
                    remaining=member.size
                    while remaining:
                        block=raw.read(min(65536,remaining));need(block,'seed member EOF');target.write(block);remaining-=len(block)
                    need(raw.read(1)==b'','seed member overflow');target.flush();os.fsync(target.fileno())
        need(len(seen)==6 and all(getattr(before,k)==getattr(os.fstat(fd),k)==getattr(Path(pin['path']).lstat(),k)
             for k in FIELDS),'complete unchanged six-member seed tar')
    finally:os.close(fd)
    return {'sha256':pin['sha256'],'bytes':count,'files':sorted(seen)}


def execute(manifest_path, manifest_sha, output):
    manifest=json.loads(read(manifest_path,1024**2,manifest_sha));spec=subject(manifest['subject'],manifest['identity']['source_commit'])
    need(manifest['kind']=='ROOT_ADMITTED_OMEN_SOURCE_GUEST_V1'and manifest['noNIC']is True and
         manifest['credentialFree']is True and manifest['location']=='OMEN_VM' and
         set(manifest['identity'])=={'repository','source_commit','run_id','attempt','nonce'} and
         0<manifest['remainingSeconds']<=WORKLOADS[spec['workload']][1], 'finite original source job identity/budget')
    expected_platform=WORKLOADS[spec['workload']][0]
    need(platform.machine().lower()in('amd64','x86_64'),'actual x86-64 build guest, not host/ARM emulation label')
    if os.name=='nt':
        need(expected_platform=='windows','actual Windows required')
        # Actual VM manufacturer/model/boot identity, not ImageOS from a hosted job.
        probe=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command',
            '$c=Get-CimInstance Win32_ComputerSystem;$o=Get-CimInstance Win32_OperatingSystem;'
            '@{model=$c.Model;manufacturer=$c.Manufacturer;boot=$o.LastBootUpTime.ToUniversalTime().Ticks;'
            'user=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value}|ConvertTo-Json -Compress'],
            stdin=subprocess.DEVNULL,capture_output=True,timeout=15,check=True)
        need(len(probe.stdout)<=4096 and not probe.stderr,'actual bounded Windows guest identity')
        observed=json.loads(probe.stdout);need('QEMU'in observed['manufacturer']+observed['model']and
            observed['user']not in('S-1-5-18','S-1-5-19','S-1-5-20'),'non-system actual QEMU guest user')
        boot=str(observed['boot']);uid=observed['user'] # Actual Windows SID; never invent a Unix UID.
        if spec['workload']=='windows-build':
            import ctypes
            from ctypes import wintypes
            session=wintypes.DWORD()
            k=ctypes.WinDLL('kernel32',use_last_error=True);u=ctypes.WinDLL('user32',use_last_error=True)
            k.ProcessIdToSessionId.argtypes=[wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)];k.ProcessIdToSessionId.restype=wintypes.BOOL
            u.GetSystemMetrics.argtypes=[ctypes.c_int];u.GetSystemMetrics.restype=ctypes.c_int
            need(k.ProcessIdToSessionId(os.getpid(),ctypes.byref(session))and session.value>0,
                 'actual interactive Windows guest session, not Session0 smoke')
            size=[u.GetSystemMetrics(0),u.GetSystemMetrics(1)]
            need(size==[1600,900],'actual Windows source smoke display must be1600x900')
            observed.update(session_id=int(session.value),actual_display=size)
    else:
        need(os.getuid()!=0 and os.getuid()==os.geteuid(),'unprivileged guest workload')
        virt=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,timeout=5,check=True)
        need(virt.stdout.strip()in(b'kvm',b'qemu')and not virt.stderr,'actual KVM/QEMU VM')
        os_release=Path('/etc/os-release').read_text();need(
            ('ID=ubuntu'in os_release if expected_platform=='ubuntu'else
             expected_platform=='debian12'and 'ID=debian'in os_release and 'VERSION_ID="12"'in os_release),
            'actual admitted distro, not a container alias')
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();uid=os.getuid();observed={'osRelease':os_release}
    output=Path(output);output.mkdir(mode=0o700);source=output/'source'
    deadline=time.monotonic()+manifest['remainingSeconds'];first=None;secondary=[];rows=[]
    result={'kind':'OMEN_GUEST_SOURCE_WORKLOAD_V1','identity':manifest['identity'],'subject':spec,
            'controller_manifest_sha256':manifest_sha,
            'guest':{'location':'OMEN_VM','platform':expected_platform,'boot_id':boot,'uid':uid,
                     'virtualization':'qemu','controller_commit':spec['controller_commit'],
                     'candidate_commit':spec['candidate_commit'],'observed':observed},
            'commands':rows,'status':'failed','first':None,'secondary':secondary,'outputs':[]}
    try:
        required={'omen_source_capture.py','omen_source_workloads.py','omen_source_guest.py','omen_source_guest_parent.py'}
        if spec['workload']=='windows-build':required.add('windows-source-smoke.ps1')
        need(required<=set(manifest['controllerFiles']),'complete sealed A guest execution graph')
        for name,pin in manifest['controllerFiles'].items():
            need(Path(name).name==name,'finite A source leaf');read(Path(manifest_path).parent/name,pin['bytes'],pin['sha256'])
        result['sourceArchive']=extract_source(manifest['sourceArchive'],source,spec)
        if spec['workload']=='windows-build':
            result['seedPackage']=extract_seed(manifest['seedPackage'],source/'build/runtime-cache/windows')
        # Root supplies a protected complete offline dependency tree, NOT argv.
        # Fresh source tree and cache/backend pins are independently qualified at
        # admission; no caller path is interpreted on the privileged host here.
        for entry in manifest['stagedTrees']:
            relative=Path(entry['destination']);need(not relative.is_absolute()and '..'not in relative.parts,
                'guest relative staged dependency destination')
            origin=Path(entry['path']);need(origin.is_dir()and not origin.is_symlink(),'staged dependency tree')
            copy_staged(entry,source/relative)
        env={k:v for k,v in os.environ.items()if k in('PATH','SystemRoot','TEMP','TMP','HOME','USERPROFILE','LOCALAPPDATA',
             'DISPLAY','XAUTHORITY','DBUS_SESSION_BUS_ADDRESS','XDG_RUNTIME_DIR',
             'INCLUDE','LIB','LIBPATH','VCToolsInstallDir','WindowsSdkDir','WindowsSDKVersion','UCRTVersion',
             'UniversalCRTSdkDir','VSINSTALLDIR','VCINSTALLDIR','VSCMD_ARG_TGT_ARCH','VSCMD_VER')}
        need(not any(k in os.environ for k in('GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN','SSH_AUTH_SOCK')),
             'no host Actions/SSH credentials in candidate VM')
        env.update(CARGO_NET_OFFLINE='true',npm_config_offline='true',npm_config_audit='false',
            OPEMOS_EXE_COMMIT=spec['candidate_commit'],OPEMOS_EXPERIMENTAL_LINUX='1',OPEMOS_LINUX_ACCEL='tcg',
            OPEMOS_CORE_CONTRACT_ROOT=str(source/'opemos-core-contracts'),OPEMOS_CORE_EXPECTED_COMMIT=
            'adf372b857cd348b6a18680b45ffcea790f04d4b'if spec['workload']=='linux-integration'else
            'f72aff92a5534b676083ccba974f4185f2d4551f')
        if spec['workload']=='appimage-package':
            env['OPEMOS_CORE_EXPECTED_COMMIT']='01407aa6174b80e92cb7f3dcb534ade5cdd7bf00'
        env.update(CARGO_HOME=str(source/'.cargo'),npm_config_cache=str(source/'.npm'))
        env.update(OPEMOS_CORE_COMMIT=env['OPEMOS_CORE_EXPECTED_COMMIT'],RUST_TOOLCHAIN='1.98.1',NODE_VERSION='22.23.2')
        if os.name=='nt':env['RUSTFLAGS']='-C target-feature=+crt-static'
        # Actual protected checkout identity inside the guest, not a synthetic
        # .git/HEAD or the host mirror's label. Root must stage the matching
        # offline .git object/index tree as part of the complete input inventory.
        git=manifest['tools']['git'];read(git['path'],512*1024**2,git['sha256'],sealed=False)
        validations=[(['rev-parse','HEAD'],spec['candidate_commit']),
                     (['rev-parse','HEAD^{tree}'],spec['candidate_tree'])]
        if spec['workload']in('rust','linux-integration','windows-build','appimage-package'):
            validations.append((['-C','opemos-core-contracts','rev-parse','HEAD'],
                '01407aa6174b80e92cb7f3dcb534ade5cdd7bf00'if spec['workload']=='appimage-package'else env['OPEMOS_CORE_EXPECTED_COMMIT']))
        result['source_validation']=[]
        for number,(arguments,expected)in enumerate(validations):
            seconds=deadline-time.monotonic();need(seconds>0,'original source validation deadline')
            checked=capture([git['path'],*arguments],source,env,output/('validation-'+str(number)),min(30,seconds))
            result['source_validation'].append(checked)
            need(checked['numeric_exit']==0 and checked['first']is None and checked['reaped']and
                 checked['stdoutEOF']and checked['stderrEOF']and checked['FDsClosed']and checked['descendantsAbsent']and
                 Path(checked['stdout']['path']).read_bytes().strip()==expected.encode()and
                 Path(checked['stderr']['path']).read_bytes()==b'','actual exact guest EXE/tree/Core identity failed')
        client=hashlib.sha256((source/'scripts/robot_client.py').read_bytes()).hexdigest()
        for number,template in enumerate(commands(spec['workload'],spec['candidate_commit'])):
            seconds=deadline-time.monotonic();need(seconds>0,'original guest source job deadline exhausted')
            tool=manifest['tools'][template[0]];read(tool['path'],512*1024**2,tool['sha256'],sealed=False)
            need(Path(tool['path']).is_absolute()and not Path(tool['path']).resolve().is_relative_to(source),
                 'SDK tool outside candidate working source')
            prefix=tool.get('argvPrefix',[])
            if os.name=='nt'and template[0]=='npm':
                script=tool['script'];read(script['path'],1024**2,script['sha256'],sealed=False)
                need(Path(script['path']).name.lower()=='npm.cmd'and prefix==['/d','/s','/c',script['path']]and
                     Path(tool['path']).name.lower()=='cmd.exe','finite normal npm.cmd adapter, not arbitrary shell')
            else:need(prefix==[],'no arbitrary workload argv prefix')
            argv=[tool['path']]+tool.get('argvPrefix',[])+[a.replace('@SOURCE@',str(source)).replace('@CONTROLLER@',str(Path(manifest_path).parent))
                .replace('@CLIENT_SHA@',client)for a in template[1:]]
            child_env=dict(env)
            container=None
            if spec['workload']=='debian-12-package'and template[0]=='dbus-run-session':
                # Preserve the original container-only dpkg guard. Do not fake
                # /.dockerenv or opt a real VM root into a container mutation.
                docker=manifest['tools']['docker'];read(docker['path'],512*1024**2,docker['sha256'],sealed=False)
                image=manifest['debianSmokeImage']
                need(type(image)is str and image.startswith('sha256:')and len(image)==71,
                     'existing approved staged Debian smoke image digest, no pull/new trust')
                name='opemos-source-'+manifest['identity']['nonce']
                probe=capture([docker['path'],'container','ls','--all','--filter','name=^/'+name+'$',
                    '--format','{{json .}}'],source,env,output/('container-before-'+str(number)),min(15,seconds))
                need(probe['numeric_exit']==0 and probe['first']is None and probe['reaped']and
                     probe['stdoutEOF']and probe['stderrEOF']and probe['FDsClosed']and
                     Path(probe['stdout']['path']).read_bytes().strip()==b'',
                     'no old/unknown container adoption')
                argv=[docker['path'],'run','--name',name,'--network=none','--pull=never','--user','0:0',
                      '--security-opt=no-new-privileges','--mount','type=bind,src='+str(source)+',dst=/source',
                      '--workdir','/source','--env','OPEMOS_DISPOSABLE_DEBIAN_CONTAINER=1',
                      '--env','OPEMOS_DEBIAN_GUI_SMOKE=1',image,*template]
                container={'name':name,'image':image,'before':probe}
            if os.name=='nt'and template[0]=='cargo'and 'windows_'in template:
                child_env['RUSTFLAGS']+=' -C link-arg=/MANIFEST:EMBED -C link-arg=/MANIFESTINPUT:'+str(source/'scripts/windows-test-v6.manifest')
            row=capture(argv,source,child_env,output/('command-'+str(number)),seconds)
            row['template_argv']=template;row['tool_pin']=tool;rows.append(row)
            if container is not None:
                observed=capture([docker['path'],'container','inspect',container['name']],source,env,
                    output/('container-after-'+str(number)),min(15,max(.1,deadline-time.monotonic())))
                need(observed['numeric_exit']==0 and observed['first']is None and observed['reaped']and
                     observed['stdoutEOF']and observed['stderrEOF']and observed['FDsClosed'],
                     'actual container exit observer closure')
                data=Path(observed['stdout']['path']).read_bytes();need(len(data)<=1024**2,'finite actual container observation')
                values=json.loads(data);need(len(values)==1,'one exact actual guest container')
                value=values[0]
                need(value['Name']=='/'+container['name']and value['Config']['Image']==container['image']and
                     value['HostConfig']['NetworkMode']=='none'and value['State']['Running']is False and
                     value['State']['Pid']==0 and type(value['State']['ExitCode'])is int and
                     value['State']['ExitCode']==row['numeric_exit'],
                     'actual same container/no-network/numeric exit/inner process absence')
                container.update(id=value['Id'],observation=observed,actual=value);row['container']=container
                # Remove only this new, stopped, original-ID container, not its
                # immutable image, package sources, another name or guest state.
                removed=capture([docker['path'],'container','rm',value['Id']],source,env,
                    output/('container-remove-'+str(number)),min(15,max(.1,deadline-time.monotonic())))
                row['container']['removal']=removed
                need(removed['numeric_exit']==0 and removed['first']is None and removed['reaped']and
                     removed['stdoutEOF']and removed['stderrEOF']and removed['FDsClosed'],
                     'owned stopped container removal/closure failed')
            need(row['numeric_exit']==0 and row['first']is None and row['secondary']==[]and row['reaped']and
                 row['stdoutEOF']and row['stderrEOF']and row['FDsClosed']and row['descendantsAbsent'],
                 'actual source command failed or process closure UNKNOWN')
        result['status']='passed'
    except BaseException as error:
        first={'type':type(error).__name__,'reason':str(error)}
    result['first']=first
    # Neither this guest nor its own result attests VM/QEMU/host closure. Root's
    # separate lifecycle finalizer is mandatory even after all commands pass.
    if first is None:
        try:verify_result(result,manifest['identity'],spec)
        except BaseException as error:
            result['status']='failed';result['first']={'type':type(error).__name__,'reason':str(error)}
    write(output/'source-result.json',result)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',required=True)
    parser.add_argument('--sha256',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
    value=execute(args.manifest,args.sha256,args.output);sys.exit(0 if value['status']=='passed'else 1)

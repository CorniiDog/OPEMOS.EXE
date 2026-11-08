#!/usr/bin/env python3
"""Create one disposable, nonce-bound read-only guest observer medium."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parent

def main():
    if len(sys.argv)!=2 or not re.fullmatch(r'[0-9a-f]{32}',sys.argv[1]):
        raise ValueError('one fresh 32-hex nonce required')
    nonce=sys.argv[1]
    out=ROOT/('prepared-'+nonce)
    out.mkdir(mode=0o700)
    source=(ROOT/'observer_guest.py').read_bytes()
    guest=out/'observer_guest.py'
    guest.write_bytes(source);guest.chmod(0o500)
    launch='''#!/bin/bash
set -euo pipefail
umask 077
nonce='''+nonce+'''
media=/media/opemosgui/OPROBOT
package='/media/opemosgui/OPKG197/package/OPEMOS EXE Linux Test_0.1.0_amd64.AppImage'
owned="$HOME/opemos-robot-$nonce"
mkdir -m 700 -- "$owned"
mkdir -m 700 -- "$owned/output"
phase=port_custody
port_ready=0
on_exit() {
    numeric=$?
    if (( numeric != 0 )); then
        printf 'BOOTSTRAP_REFUSED phase=%s numeric=%s\\n' "$phase" "$numeric" >> "$owned/bootstrap.txt"
        if (( port_ready == 1 )); then
            printf '{"kind":"BOOTSTRAP_REFUSED","nonce":"%s","phase":"%s","numeric":%s}\\n' \\
                "$nonce" "$phase" "$numeric" > "$node" || true
        fi
    fi
}
trap on_exit EXIT
printf 'BOOTSTRAP_ONLY nonce=%s boot=%s uid=%s\\n' "$nonce" "$(cat /proc/sys/kernel/random/boot_id)" "$(id -u)" > "$owned/bootstrap.txt"
printf 'DISPLAY=%s XDG_SESSION_TYPE=%s\\n' "${DISPLAY:-}" "${XDG_SESSION_TYPE:-}" >> "$owned/bootstrap.txt"
port=/dev/virtio-ports/opemos.robot.observer
ls -l -- "$port" >> "$owned/bootstrap.txt"
node=$(readlink -f -- "$port")
[[ "$node" == /dev/vport* && -c "$node" ]]
[[ "$(cat "/sys/class/virtio-ports/${node##*/}/name")" == opemos.robot.observer ]]
before=$(stat -Lc '%F %u %g %a %t:%T' -- "$node")
[[ "$before" == "character special file $(id -u) $(id -g) 600 "* ]]
[[ -r "$node" && -w "$node" ]]
after=$(stat -Lc '%F %u %g %a %t:%T' -- "$node")
[[ "$before" == "$after" ]]
printf 'EXACT_PORT before=%s after=%s sudo=NOT_NEEDED sysname=opemos.robot.observer\\n' "$before" "$after" >> "$owned/bootstrap.txt"
port_ready=1
export OPROBOT_PORT_BEFORE="$before" OPROBOT_PORT_AFTER="$after" OPROBOT_PORT_SUDO=NOT_NEEDED
phase=verified_package
test -r "$media/observer_guest.py"
test -r "$package"
printf '%s  %s\\n' '''+hashlib.sha256(source).hexdigest()+''' "$media/observer_guest.py" | sha256sum --check --strict
app="$owned/OPEMOS EXE Linux Test_0.1.0_amd64.AppImage"
cp --no-clobber -- "$package" "$app"
printf '%s  %s\\n' b252781da4a8af77c1439e0197208fc5c607d29bbc7ef18595ed550029ee9580 "$app" | sha256sum --check --strict
chmod u+x -- "$app"
export OPROBOT_NONCE="$nonce" OPEMOS_EXPERIMENTAL_LINUX=1 OPEMOS_LINUX_ACCEL=kvm GDK_BACKEND=x11 WEBKIT_DISABLE_DMABUF_RENDERER=1
phase=native_app_and_observer
"$app" --appimage-extract-and-run > "$owned/app.log" 2>&1 &
app_launcher=$!
printf 'LAUNCHER_PID=%s\\n' "$app_launcher" >> "$owned/bootstrap.txt"
DISPLAY="${DISPLAY:-:0}" python3 "$media/observer_guest.py" "$nonce" 'OPEMOS EXE' > "$owned/observer.log" 2>&1
'''
    start=out/'start.sh';start.write_text(launch);start.chmod(0o500)
    iso=out/'observer.iso'
    argv=['/usr/bin/genisoimage','-quiet','-iso-level','3','-R','-J',
          '-V','OPROBOT','-o',str(iso),'observer_guest.py','start.sh']
    done=subprocess.run(argv,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                        timeout=60,check=False)
    if done.returncode or not iso.is_file():
        raise RuntimeError('observer ISO generator failed: '+repr(done.stderr[:1024]))
    receipt={'kind':'DISPOSABLE_NATIVE_OBSERVER_ISO','nonce':nonce,
             'argv':argv,'numeric':done.returncode,
             'files':{p.name:{'bytes':p.stat().st_size,
                              'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
                      for p in (guest,start,iso)},
             'not_vm_or_gui_acceptance':True}
    (out/'receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    print(json.dumps(receipt,sort_keys=True))


def held_input(ref,cap,owner):
    import stat
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    path=Path(ref['path'])
    if not path.is_absolute()or path.resolve()!=path:raise ValueError('canonical normal input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);identity=lambda s:{k:getattr(s,k)for k in fields}
        if (not stat.S_ISREG(before.st_mode)or before.st_uid!=owner or before.st_nlink!=1 or
            before.st_mode&0o022 or before.st_size!=ref['bytes']or before.st_size>cap or
            identity(before)!=ref['identity']):raise ValueError('normal held input full9/owner/size')
        digest=hashlib.sha256();raw=bytearray()
        while block:=os.read(fd,1048576):
            raw.extend(block)
            if len(raw)>cap:raise ValueError('normal input cap')
            digest.update(block)
        if (len(raw)!=ref['bytes']or digest.hexdigest()!=ref['sha256']or
            identity(before)!=identity(os.fstat(fd))or identity(before)!=identity(path.lstat())):
            raise ValueError('normal input whole hash/epoch')
        return bytes(raw)
    finally:os.close(fd)


def create_file(path,raw,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    try:
        os.fchmod(fd,mode);view=memoryview(raw)
        while view:
            written=os.write(fd,view)
            if written<=0:raise OSError('no file write progress')
            view=view[written:]
        os.fsync(fd)
    finally:os.close(fd)


@contextmanager
def candidate_archive(ref,cap=2*1024**3):
    import stat
    if type(cap)is not int or not 0<cap<=60_000_000_000:raise ValueError('finite admitted input archive bound')
    path=Path(ref['path']);fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    if not path.is_absolute()or path.resolve()!=path:raise ValueError('canonical candidate archive')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);identity=lambda s:{k:getattr(s,k)for k in fields}
        if (not stat.S_ISREG(before.st_mode)or before.st_uid!=os.getuid()or before.st_nlink!=1 or
            before.st_mode&0o022 or not 0<before.st_size<=cap or
            before.st_size!=ref['bytes']or identity(before)!=ref['identity']):
            raise ValueError('actual finite producer archive custody')
        digest=hashlib.sha256()
        while block:=os.read(fd,1048576):digest.update(block)
        if digest.hexdigest()!=ref['sha256']:raise ValueError('actual whole producer archive hash')
        os.lseek(fd,0,os.SEEK_SET)
        with os.fdopen(fd,'rb',closefd=False)as stream:yield stream
        if identity(before)!=identity(os.fstat(fd))or identity(before)!=identity(path.lstat()):
            raise ValueError('producer archive changed across interpretation/extraction')
    finally:os.close(fd)


def extract_candidate(archive_ref,descriptor,destination,expanded_limit):
    """The producer archive remains guest DATA; nothing is executed on host."""
    import stat,zipfile
    if (descriptor['platform']!='ubuntu'or descriptor['repository']!='CorniiDog/OPEMOS.EXE'or
        not re.fullmatch('[0-9a-f]{40}',descriptor['source_commit'])or
        archive_ref['sha256']!=descriptor['artifact_archive_sha256']or
        type(expanded_limit)is not int or not 0<expanded_limit<=2*1024**3):
        raise ValueError('same finite actual Ubuntu producer descriptor/archive')
    # The existing candidate-archive admission is2GiB. Keep the same bound;
    # verify all bytes before interpreting the central directory as DATA.
    directory=Path(destination);directory.mkdir(mode=0o700)
    seen=set();total=0;members=[];executable=None;package=None
    with candidate_archive(archive_ref)as stream,zipfile.ZipFile(stream)as archive:
        entries=archive.infolist()
        if not 1<=len(entries)<=4096:raise ValueError('bounded producer member count')
        for item in entries:
            path=Path(item.filename);mode=item.external_attr>>16
            if (path.is_absolute()or '..'in path.parts or '\\'in item.filename or
                '\x00'in item.filename or not path.parts or item.filename in seen or
                item.flag_bits&1 or (mode and stat.S_IFMT(mode)not in(0,stat.S_IFREG,stat.S_IFDIR))):
                raise ValueError('regular unique producer member, no escape/link/encryption')
            seen.add(item.filename);total+=item.file_size
            if total>expanded_limit:raise ValueError('whole expanded producer bound')
        for item in entries:
            target=directory/item.filename
            if item.is_dir():target.mkdir(mode=0o700,parents=True,exist_ok=True);continue
            target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            digest=hashlib.sha256();size=0
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400)
            try:
                with archive.open(item)as source:
                    while block:=source.read(1048576):
                        size+=len(block)
                        if size>item.file_size:raise ValueError('expanded member grew')
                        digest.update(block);view=memoryview(block)
                        while view:
                            written=os.write(fd,view)
                            if written<=0:raise OSError('producer extraction stalled')
                            view=view[written:]
                os.fchmod(fd,0o500 if item.external_attr>>16&0o111 else 0o400);os.fsync(fd)
            finally:os.close(fd)
            if size!=item.file_size:raise ValueError('short producer member')
            record={'name':item.filename,'bytes':size,'sha256':digest.hexdigest()};members.append(record)
            if target.name==descriptor['package_name']:
                if package is not None:raise ValueError('ambiguous producer package')
                if (record['sha256']!=descriptor['package_sha256']or
                    size!=descriptor.get('package_bytes',descriptor['executable_bytes'])):
                    raise ValueError('exact actual AppImage bytes')
                package=record
            if target.name==descriptor['executable_name']:
                if executable is not None:raise ValueError('ambiguous producer executable')
                if size!=descriptor['executable_bytes']or record['sha256']!=descriptor['executable_sha256']:
                    raise ValueError('exact actual native/AppImage bytes')
                executable=record
    if package is None or executable is None:raise ValueError('actual producer package/executable absent')
    companion=str(Path(package['name']).parent/(Path(package['name']).name+'.runtime'))
    if not any(item['name'].startswith(companion+'/appliance/')for item in members):
        raise ValueError('actual package companion appliance missing')
    result={'members':members,'expandedBytes':total,'package':package,'executable':executable,
            'archiveSHA256':archive_ref['sha256'],'source_commit':descriptor['source_commit']}
    prerequisite=directory/companion/'ubuntu-prerequisites.json'
    if prerequisite.exists():
        if prerequisite.stat().st_size>65536:raise ValueError('finite prerequisite metadata')
        value=json.loads(prerequisite.read_bytes())
        if (value['kind']!='OFFLINE_UBUNTU_GUEST_PREREQUISITES_V1'or
            value['tar_name']!='ubuntu-prerequisites.tar'or
            not re.fullmatch('[0-9a-f]{64}',value['source_input_sha256'])):
            raise ValueError('source-bound offline prerequisite role')
        name=companion+'/'+value['tar_name']
        observed=[row for row in members if row['name']==name]
        if len(observed)!=1 or observed[0]['sha256']!=value['tar_sha256']or observed[0]['bytes']!=value['tar_bytes']:
            raise ValueError('actual prerequisite tar/full candidate archive identity')
        result['prerequisites']=dict(value,relative_path=name)
    return result



def source_medium(config):
    """One read-only source/toolchain medium; no candidate code runs on host."""
    import shlex,zipfile
    nonce=config['nonce'];source=config['source_input']['descriptor'];definition=source['input']
    if (not re.fullmatch('[0-9a-f]{32}',nonce) or source['kind']!='UBUNTU_SOURCE_INPUT_ARTIFACT_V1' or
        definition['kind']!='UBUNTU_GUEST_SOURCE_INPUT_V1' or definition['compiled_or_packaged']is not False or
        config['candidate_source_commit']!=source['source_commit']):
        raise ValueError('source-only medium identity; package success is not yet available')
    root=Path(config['prepared_directory'])
    if (not root.is_absolute()or root.parent.resolve()!=root.parent or
        root.parent.stat().st_uid!=os.getuid()or root.parent.stat().st_mode&0o077):
        raise ValueError('existing owned source-build operation directory')
    root.mkdir(mode=0o700)
    expected={'source-input.json','ubuntu-source-inputs.tar'}
    with candidate_archive(config['source_input']['archive'],config['source_input_cap_bytes'])as stream,zipfile.ZipFile(stream)as archive:
        if len(archive.infolist())!=2 or set(archive.namelist())!=expected:
            raise ValueError('exact source input artifact members')
        item=archive.getinfo('source-input.json')
        if item.file_size>65536 or item.flag_bits&1:raise ValueError('finite source input definition')
        if json.loads(archive.read(item))!=definition:raise ValueError('actual source input definition differs')
        item=archive.getinfo('ubuntu-source-inputs.tar')
        if item.flag_bits&1 or item.file_size!=definition['archive_bytes']:
            raise ValueError('actual source input tar byte count')
        digest=hashlib.sha256();size=0
        with archive.open(item)as data, (root/'ubuntu-source-inputs.tar').open('xb')as output:
            while block:=data.read(1048576):
                size+=len(block)
                if size>definition['archive_bytes']:raise ValueError('source input expanded beyond actual definition')
                digest.update(block);output.write(block)
            output.flush();os.fsync(output.fileno())
        if size!=definition['archive_bytes']or digest.hexdigest()!=definition['archive_sha256']:
            raise ValueError('whole source input tar differs')
    builder=held_input(config['guest_builder_source'],262144,0)
    create_file(root/'ubuntu_guest_build.py',builder,0o444)
    owned=held_input(config['owned_command_source'],262144,0)
    create_file(root/'owned_command.py',owned,0o444)
    guest={'nonce':nonce,'candidate_source_commit':source['source_commit'],
           'producer_run_id':source['producer_run_id'],'producer_attempt':source['producer_attempt'],
           'input_archive':'/media/opemosgui/OPROBOT/ubuntu-source-inputs.tar',
           'input_sha256':definition['archive_sha256'],'expanded_bytes':definition['expanded_bytes'],
           'packages':definition['packages'],
           'remaining_seconds':config['remaining_seconds'],'max_package_bytes':2147483648,
           'owned_command_sha256':hashlib.sha256(owned).hexdigest()}
    create_file(root/'build.json',(json.dumps(guest,sort_keys=True)+'\n').encode(),0o444)
    start='#!/bin/bash\nset -euo pipefail\numask 077\nmedia=/media/opemosgui/OPROBOT\nnonce=NONCE_VALUE\nowned="$HOME/opemos-robot-$nonce"\nmkdir -m 700 -- "$owned"\nnode=$(readlink -f /dev/virtio-ports/opemos.robot.observer)\n[[ "$node" == /dev/vport* && -c "$node" && -w "$node" ]]\n[[ "$(cat /sys/class/virtio-ports/${node##*/}/name)" == opemos.robot.observer ]]\nphase=guest_prerequisites\non_exit() {\n    numeric=$?\n    if (( numeric != 0 )); then\n        details=$(tail -c 8192 "$owned/build.log" 2>/dev/null | base64 -w0 || true)\n        printf \'{"kind":"BOOTSTRAP_REFUSED","nonce":"%s","phase":"%s","numeric":%s,"build_log_base64":"%s"}\\n\' "$nonce" "$phase" "$numeric" "$details" > "$node" || true\n    fi\n}\ntrap on_exit EXIT\nsudo -n /usr/bin/python3 -I -B /usr/local/bin/opemos-source-build-$nonce.py --install-prerequisites > "$owned/build.log" 2>&1\nphase=guest_compilation_and_package\npython3 -I -B "$media/ubuntu_guest_build.py" --admitted-source-build "$media/build.json" "$owned/build" >> "$owned/build.log" 2>&1\n'.replace('NONCE_VALUE',shlex.quote(nonce))
    create_file(root/'start.sh',start.encode(),0o444)
    iso=root/'observer.iso'
    argv=['/usr/bin/genisoimage','-quiet','-iso-level','3','-R','-J','-graft-points','-V','OPROBOT','-o',str(iso),
          'start.sh=start.sh','build.json=build.json','ubuntu_guest_build.py=ubuntu_guest_build.py','owned_command.py=owned_command.py',
          'ubuntu-source-inputs.tar=ubuntu-source-inputs.tar']
    result=subprocess.run(argv,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=600)
    if result.returncode:raise RuntimeError('source input ISO generation failed: '+repr(result.stderr[:2048]))
    iso.chmod(0o400)
    # Verify the large payload from the ACTUAL filesystem image before removing
    # this operation's generated intermediate tar. The original input ZIP and
    # immutable ISO remain retained and charged; no source/backing is a victim.
    intermediate=root/'ubuntu-source-inputs.tar';epoch=intermediate.lstat()
    with (root/'source-ISO-readback.stderr').open('xb')as error:
        # cdrkit isoinfo extracts through a signed-int length and can return
        # success with no bytes for a source payload larger than 2 GiB. Read
        # the same Rock Ridge member with the system large-file archive reader.
        child=subprocess.Popen(['/usr/bin/bsdtar','-xOf',str(iso),'ubuntu-source-inputs.tar'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=error)
        check=hashlib.sha256();count=0
        try:
            while block:=child.stdout.read(1048576):
                count+=len(block)
                if count>definition['archive_bytes']:raise ValueError('source ISO payload exceeds actual input')
                check.update(block)
            child.stdout.close();numeric=child.wait(timeout=30)
        finally:
            if child.poll()is None:child.kill();child.wait(timeout=10)
            child.stdout.close()
    readback={'numeric':numeric,'bytes':count,'sha256':check.hexdigest(),
              'expectedBytes':definition['archive_bytes'],'expectedSHA256':definition['archive_sha256']}
    create_file(root/'source-ISO-readback.json',(json.dumps(readback,sort_keys=True)+'\n').encode(),0o444)
    if numeric or count!=definition['archive_bytes']or check.hexdigest()!=definition['archive_sha256']:
        raise ValueError('actual source ISO whole-payload readback failed: '+json.dumps(readback,sort_keys=True))
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    if any(getattr(epoch,k)!=getattr(intermediate.lstat(),k)for k in fields):
        raise ValueError('generated source intermediate changed; preserve it')
    intermediate.unlink()
    h=hashlib.sha256()
    with iso.open('rb')as data:
        while block:=data.read(1048576):h.update(block)
    return {'kind':'NORMAL_UBUNTU_SOURCE_INPUT_MEDIUM_V1','path':str(iso),'bytes':iso.stat().st_size,
            'sha256':h.hexdigest(),'nonce':nonce,'source_commit':source['source_commit'],
            'source_input_sha256':definition['archive_sha256'],'source_payload_readback':True,
            'generated_intermediate_removed_after_readback':True,'VMOrGUIAcceptance':False}


def pipeline_medium(config):
    """Materialize the existing observer medium from one normal operation."""
    import shlex
    nonce=config['nonce'];descriptor=config['candidate']['descriptor']
    if not re.fullmatch('[0-9a-f]{32}',nonce)or config['source_commit']!=descriptor['source_commit']:
        raise ValueError('same current operation/producer identity')
    root=Path(config['prepared_directory'])
    if (not root.is_absolute()or root.parent.resolve()!=root.parent or
        root.parent.stat().st_uid!=os.getuid()or root.parent.stat().st_mode&0o077):
        raise ValueError('existing owned normal operation directory')
    root.mkdir(mode=0o700)
    candidate=extract_candidate(config['candidate']['archive'],descriptor,root/'candidate',config['expanded_limit'])
    if config.get('guest_prerequisites_required')is True and 'prerequisites'not in candidate:
        raise ValueError('actual OMEN producer prerequisite output missing')
    observer=held_input(config['observer_source'],65536,0)
    create_file(root/'observer_guest.py',observer,0o444)
    if 'prerequisites'in candidate:
        create_file(root/'ubuntu_guest_build.py',held_input(config['guest_builder_source'],262144,0),0o444)
    operation=config['guest_operation']
    display=operation.get('display')
    if (type(display)is not list or len(display)!=2 or
        any(type(value)is not int for value in display)or
        not 640<=display[0]<=3840 or not 480<=display[1]<=2160):
        raise ValueError('finite actual guest display dimensions')
    if (operation['nonce']!=nonce or operation['source_commit']!=descriptor['source_commit']or
        operation['package_sha256']!=descriptor['package_sha256']or
        operation['usb_serial']!='opemos-'+nonce or
        operation['native_executable_sha256']!=descriptor['executable_sha256']):raise ValueError('whole guest config/actual producer binding')
    operation_raw=(json.dumps(operation,sort_keys=True,separators=(',',':'))+'\n').encode()
    if len(operation_raw)>65536:raise ValueError('finite guest operation config')
    create_file(root/'operation.json',operation_raw,0o444)
    package='/media/opemosgui/OPROBOT/candidate/'+candidate['package']['name']
    basename=Path(candidate['package']['name']).name
    # Existing disposable guest login/udev provision owns port access. No host
    # credentials, Root state, pointer activation or build commands are here.
    start='''#!/bin/bash
set -euo pipefail
umask 077
nonce='''+shlex.quote(nonce)+'''
media=/media/opemosgui/OPROBOT
owned="$HOME/opemos-robot-$nonce"
mkdir -m 700 -- "$owned"
mkdir -m 700 -- "$owned/output"
phase=port_custody
port_ready=0
on_exit() {
    numeric=$?
    if (( numeric != 0 )); then
        printf 'BOOTSTRAP_REFUSED phase=%s numeric=%s\\n' "$phase" "$numeric" >> "$owned/bootstrap.txt"
        if (( port_ready == 1 )); then
            app_log=$(tail -c 8192 -- "$owned/app.log" 2>/dev/null | base64 -w0 || true)
            observer_log=$(tail -c 8192 -- "$owned/observer.log" 2>/dev/null | base64 -w0 || true)
            bootstrap_log=$(tail -c 8192 -- "$owned/bootstrap.txt" 2>/dev/null | base64 -w0 || true)
            printf '{"kind":"BOOTSTRAP_REFUSED","nonce":"%s","phase":"%s","numeric":%s,"app_log_base64":"%s","observer_log_base64":"%s","bootstrap_log_base64":"%s"}\\n' \\
                "$nonce" "$phase" "$numeric" "$app_log" "$observer_log" "$bootstrap_log" > "$node" || true
        fi
    fi
}
trap on_exit EXIT
printf 'BOOTSTRAP_ONLY nonce=%s boot=%s uid=%s\\n' "$nonce" "$(cat /proc/sys/kernel/random/boot_id)" "$(id -u)" > "$owned/bootstrap.txt"
node=$(readlink -f -- /dev/virtio-ports/opemos.robot.observer)
[[ "$node" == /dev/vport* && -c "$node" ]]
[[ "$(cat "/sys/class/virtio-ports/${node##*/}/name")" == opemos.robot.observer ]]
before=$(stat -Lc '%F %u %g %a %t:%T' -- "$node")
[[ "$before" == "character special file $(id -u) $(id -g) 600 "* ]]
[[ -r "$node" && -w "$node" ]]
after=$(stat -Lc '%F %u %g %a %t:%T' -- "$node")
[[ "$before" == "$after" ]]
port_ready=1
phase=verified_package
export OPROBOT_PORT_BEFORE="$before" OPROBOT_PORT_AFTER="$after" OPROBOT_PORT_SUDO=NOT_NEEDED
app="$owned/"'''+shlex.quote(basename)+'''
cp --no-clobber -- '''+shlex.quote(package)+''' "$app"
cp -a --no-clobber -- '''+shlex.quote(package+'.runtime')+''' "$app.runtime"
printf '%s  %s\\n' '''+shlex.quote(descriptor['package_sha256'])+''' "$app" | sha256sum --check --strict
chmod u+x -- "$app"
export OPROBOT_NONCE="$nonce" OPEMOS_EXPERIMENTAL_LINUX=1 OPEMOS_LINUX_ACCEL=kvm GDK_BACKEND=x11 WEBKIT_DISABLE_DMABUF_RENDERER=1
phase=guest_display
# Set the guest framebuffer before launching the app. Its 800px minimum
# window height also needs room for the GNOME panel and window decoration.
read -r display_width display_height < <(python3 -c 'import json,sys; print(*json.load(open(sys.argv[1]))["display"])' "$media/operation.json")
display_output=$(xrandr --query | awk '$2 == "connected" && !output { output=$1 } END { print output }')
xrandr --output "$display_output" --mode "${display_width}x${display_height}" >> "$owned/bootstrap.txt" 2>&1
phase=guest_prerequisites
'''+('sudo -n /usr/bin/python3 -I -B /usr/local/bin/opemos-source-build-'+nonce+'.py --install-prerequisites > \"$owned/prerequisites.json\" 2> \"$owned/app.log\"\npython3 -I -B \"$media/ubuntu_guest_build.py\" --verify-kvm '+nonce+' >> \"$owned/prerequisites.json\" 2>> \"$owned/app.log\"\n'if 'prerequisites'in candidate else'')+'''phase=native_app_and_observer
"$app" --appimage-extract-and-run > "$owned/app.log" 2>&1 &
DISPLAY="${DISPLAY:-:0}" python3 "$media/observer_guest.py" "$nonce" 'OPEMOS EXE' --pipeline "$media/operation.json" '''+shlex.quote(hashlib.sha256(operation_raw).hexdigest())+''' > "$owned/observer.log" 2>&1
'''
    create_file(root/'start.sh',start.encode(),0o444)
    iso=root/'observer.iso'
    argv=['/usr/bin/genisoimage','-quiet','-iso-level','3','-R','-J','-V','OPROBOT',
          '-graft-points','-o',str(iso),'observer_guest.py','operation.json','start.sh',
          'candidate=candidate']+(['ubuntu_guest_build.py=ubuntu_guest_build.py']if 'prerequisites'in candidate else[])
    done=subprocess.run(argv,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,check=False)
    if done.returncode or not iso.is_file():raise RuntimeError('normal guest medium creation refused: '+repr(done.stderr[:1024]))
    iso.chmod(0o400);digest=hashlib.sha256()
    with iso.open('rb')as stream:
        while block:=stream.read(1048576):digest.update(block)
    return {'kind':'NORMAL_UBUNTU_CANDIDATE_OBSERVER_ISO','nonce':nonce,'source_commit':descriptor['source_commit'],
        'path':str(iso),'bytes':iso.stat().st_size,'sha256':digest.hexdigest(),'candidate':candidate,
        'operationSHA256':hashlib.sha256(operation_raw).hexdigest(),'hostCandidateExecuted':False,
        'VMOrGUIAcceptance':False}


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--pipeline-config-pin-json':
        ref=json.loads(sys.argv[2]);cfg=json.loads(held_input(ref,1048576,os.getuid()))
        print(json.dumps(source_medium(cfg)if cfg.get('kind')=='ROOT_ADMITTED_UBUNTU_SOURCE_BUILD_V1'else pipeline_medium(cfg),sort_keys=True),flush=True)
    else:main()


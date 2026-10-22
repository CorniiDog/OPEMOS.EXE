"""Trusted guest parent: actual worker wait, then byte transport to the owner VM.

Root provisions this fixed A bootstrap on the disposable derivative using the
existing normal guest recipe. The channel is an exact named virtio device, not
a network endpoint or an arbitrary shell. Importing this module has no effects.
"""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import stat
import sys
import time
from omen_source_capture import capture
from omen_source_guest import read
from omen_source_workloads import canonical, need, subject


def package_archive(package_root, output, identity, spec):
    """Data-only complete archive; never follow a Windows reparse point."""
    import tarfile
    package_root=Path(package_root);output=Path(output)
    need(package_root.is_dir()and not package_root.is_symlink(),'actual completed package directory')
    need(not getattr(package_root.lstat(),'st_file_attributes',0)&
         getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0x400),'no package root reparse adoption')
    archive=output/'guest-package.tar';total=0;count=0;selected=[]
    with tarfile.open(archive,mode='x',format=tarfile.PAX_FORMAT)as tar:
        # os.walk does not follow directory symlinks; inspect each directory
        # before descent as junctions are not necessarily reported as symlinks.
        for directory,dirs,names in os.walk(package_root,followlinks=False):
            for name in sorted(dirs+names):
                p=Path(directory)/name;before=p.lstat()
                need(not stat.S_ISLNK(before.st_mode)and not getattr(before,'st_file_attributes',0)&
                     getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0x400),'no package link/reparse adoption')
                if stat.S_ISDIR(before.st_mode):continue
                need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and
                     0<=before.st_size<=4*1024**3,'actual regular guest package leaf')
                count+=1;total+=before.st_size
                need(count<=65536 and total<=4*1024**3,'complete actual guest package tree cap')
                rel=p.relative_to(package_root).as_posix()
                info=tarfile.TarInfo(rel);info.size=before.st_size;info.mode=stat.S_IMODE(before.st_mode)&0o755;info.mtime=0
                fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
                with os.fdopen(fd,'rb')as source:
                    fields=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
                    need(all(getattr(before,k)==getattr(os.fstat(source.fileno()),k)for k in fields),
                         'package opened another file')
                    tar.addfile(info,source)
                    need(all(getattr(before,k)==getattr(os.fstat(source.fileno()),k)==getattr(p.lstat(),k)for k in fields),
                         'actual package file changed while archived')
    need(count>0,'completed package cannot be empty')
    with archive.open('rb')as source:os.fsync(source.fileno())
    value={'kind':'OMEN_SOURCE_PACKAGE_TAR_V1','identity':identity,'subject':spec,
        'bytes':archive.stat().st_size,'sha256':None,'file_count':count,'file_bytes':total,'chunks':[]}
    h=hashlib.sha256();offset=0
    with archive.open('rb')as source:
        while block:=source.read(16*1024**2):
            name='package-'+str(offset)+'.chunk';tmp=output/name
            with tmp.open('xb')as target:target.write(block);target.flush();os.fsync(target.fileno())
            selected.append((name,tmp,'source-package-chunk'));h.update(block)
            value['chunks'].append({'name':name,'offset':offset,'bytes':len(block),'sha256':hashlib.sha256(block).hexdigest()})
            offset+=len(block)
    need(offset==value['bytes']<=5*1024**3,'whole actual package tar EOF');value['sha256']=h.hexdigest()
    return value,selected


def run(manifest_path, digest, output):
    import json
    manifest=json.loads(read(manifest_path,1024**2,digest));identity=manifest['identity']
    spec=subject(manifest['subject'],identity['source_commit']);controller=Path(manifest_path).parent
    for name,pin in manifest['controllerFiles'].items():read(controller/name,pin['bytes'],pin['sha256'])
    channel=manifest['channel'];need(channel['name']=='org.opemos.source-job.0','fixed source virtio channel')
    if sys.platform=='darwin':
        bridge=manifest['darwinProcessBridge'];read(bridge['path'],16*1024**2,bridge['sha256'])
        os.environ['OPEMOS_DARWIN_PROCESS_BRIDGE']=bridge['path'];os.environ['OPEMOS_DARWIN_PROCESS_BRIDGE_SHA256']=bridge['sha256']
        path=Path(channel['path']);need(path.parent==Path('/dev')and path.name.startswith(('cu.','tty.'))and
             channel['actualGuestDevicePin']['boot']==manifest['guestBoot'],
             'existing actual boot-bound macOS guest virtio/serial device required; no guessed port')
        actual=path.stat();pin=channel['actualGuestDevicePin']
        need(stat.S_ISCHR(actual.st_mode)and actual.st_dev==pin['st_dev']and actual.st_ino==pin['st_ino']and
             actual.st_rdev==pin['st_rdev'],'actual sealed guest character channel identity')
    elif os.name!='nt':
        path=Path(channel['path']);need(path.parent==Path('/dev/virtio-ports')and path.name==channel['name'],
             'actual named Linux virtio channel')
        real=path.resolve(strict=True);need(stat.S_ISCHR(real.stat().st_mode),'actual kernel character port')
    else:
        # The existing guest recipe pins the actual virtio-serial device path
        # observed in that Windows VM; never guess COM1 or a hosted pipe.
        need(channel['path'].startswith('\\\\.\\')and channel['actualGuestDevicePin']['name']==channel['name']and
             channel['actualGuestDevicePin']['boot']==manifest['guestBoot'], 'actual boot-bound Windows device selection')
        path=Path(channel['path'])
    # Parent, not worker, retains the sole connection through numeric wait.
    fd=os.open(path,os.O_RDWR|getattr(os,'O_NOCTTY',0));owned=True
    output=Path(output);output.mkdir(mode=0o700)
    def send(value):
        wire=canonical(dict(value,identity=identity,subject=spec))+b'\n';need(len(wire)<=65536,'finite source frame')
        view=memoryview(wire)
        while view:n=os.write(fd,view);need(n>0,'actual channel progress');view=view[n:]
    try:
        argv=[sys.executable,'-E','-s','-B',str(controller/'omen_source_guest.py'),'--manifest',str(manifest_path),
              '--sha256',digest,'--output',str(output/'worker')]
        # -E/-s permits only the adjacent sealed A dependency graph, ignores
        # PYTHONPATH and user site; neither cwd nor script path is candidate B.
        native=capture(argv,controller,{k:v for k,v in os.environ.items()if k not in
            ('GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN','SSH_AUTH_SOCK','PYTHONPATH','PYTHONHOME')},
            output/'parent-capture',manifest['remainingSeconds'])
        files={};transferred=0
        result_path=output/'worker/source-result.json'
        if not result_path.exists():
            # A failed prerequisite is not a guest/test/clock success. Preserve
            # actual complete bootstrap stderr and numeric failure instead.
            result_path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            diagnostic={'kind':'OMEN_GUEST_SOURCE_PREREQUISITE_FAILED','identity':identity,'subject':spec,
                'controller_manifest_sha256':digest,'status':'failed','guest':{},'commands':[],
                'first':{'phase':'actual-worker-bootstrap','numeric_exit':native['numeric_exit'],
                         'capture_first':native['first'],'stderr':native.get('stderr')},'secondary':native['secondary']}
            with result_path.open('xb')as out:out.write(canonical(diagnostic)+b'\n');out.flush();os.fsync(out.fileno())
        selected=[('source-result.json',result_path,'source-result')]
        selected.extend(('parent-'+name+'.raw',Path(native[name]['path']),'source-log')for name in('stdout','stderr')if name in native)
        # All command raws and package outputs are regular files from the actual
        # completed worker. Split only package files, never alter their bytes.
        selected.extend((d.name+'-'+name+'.raw',p,'source-log')
            for d in sorted((output/'worker').iterdir())if d.is_dir()and
                d.name.startswith(('command-','container-','validation-'))for name in('stdout','stderr')
            if (p:=d/(name+'.raw')).is_file())
        roots={'windows-build':'dist/windows','appimage-package':'linux-package-artifact',
               'debian-12-package':'linux-package-artifact','seed-runtime-source':'build/runtime-cache/windows',
               'macos-build':'build/macos-arm64-evidence'}
        package_root=output/'worker/source'/roots.get(spec['workload'],'__no_package__')
        package_value=None
        if spec['workload']in roots:
            try:
                package_value,leaves=package_archive(package_root,output,identity,spec);selected.extend(leaves)
            except Exception as error:
                # Preserve the worker's original result and complete raw logs.
                # Packaging failure is a separate parent failure, never a
                # rewrite of a passed/failed compiler result or a null pass.
                failure={'phase':'actual-package-archive','type':type(error).__name__,'reason':str(error)}
                if native['first']is None:native['first']=failure
                else:native['secondary'].append(failure)
                failed=output/'parent-package-failure.json'
                with failed.open('xb')as target:target.write(canonical(failure)+b'\n');target.flush();os.fsync(target.fileno())
                selected.append((failed.name,failed,'source-result'))
        package_raw=canonical(package_value)+b'\n'
        package_path=output/'package-files.json'
        with package_path.open('xb')as target:target.write(package_raw);target.flush();os.fsync(target.fileno())
        selected.append(('package-files.json',package_path,'source-result'))
        exported=[];raw_index=[]
        for name,p,kind in selected:
            if p.stat().st_size<=16*1024**2:
                exported.append((name,p,kind));continue
            need(kind=='source-log'and p.stat().st_size<=32*1024**2+65536,'bounded complete large raw source log')
            entry={'name':name,'bytes':p.stat().st_size,'chunks':[]};h=hashlib.sha256();offset=0
            with p.open('rb')as data:
                while block:=data.read(8*1024**2):
                    leaf='log-'+str(len(raw_index))+'-'+str(offset)+'.chunk';dest=output/leaf
                    with dest.open('xb')as target:target.write(block);target.flush();os.fsync(target.fileno())
                    exported.append((leaf,dest,kind));h.update(block)
                    entry['chunks'].append({'name':leaf,'offset':offset,'bytes':len(block),'sha256':hashlib.sha256(block).hexdigest()});offset+=len(block)
            entry['sha256']=h.hexdigest();raw_index.append(entry)
        raw_path=output/'raw-files.json'
        with raw_path.open('xb')as target:target.write(canonical({'files':raw_index})+b'\n');target.flush();os.fsync(target.fileno())
        exported.append(('raw-files.json',raw_path,'source-result'))
        for name,p,kind in exported:
            need(len(files)<512 and name not in files,'finite unique actual source outputs within original reply cap')
            before=p.stat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size<=16*1024**2,
                'bounded actual source output leaf')
            h=hashlib.sha256()
            with p.open('rb')as source:
                while block:=source.read(65536):h.update(block)
            sha=h.hexdigest();send({'kind':'source-file','name':name,'bytes':before.st_size,'sha256':sha,'file_kind':kind})
            count=0
            with p.open('rb')as source:
                while block:=source.read(32768):
                    send({'kind':'source-data','offset':count,'base64':base64.b64encode(block).decode()});count+=len(block)
            need(count==before.st_size and all(getattr(before,k)==getattr(p.stat(),k)for k in
                ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),'actual exported leaf unchanged')
            transferred+=count;need(transferred<=5*1024**3,'whole actual source output transfer cap')
            send({'kind':'source-file-end'});files[name]={'bytes':count,'sha256':sha,'file_kind':kind}
        send({'kind':'source-terminal','files':files,'agentParent':{
            'pid':native.get('pid'),'birth':native.get('birth'),'numericExit':native['numeric_exit'],
            'reaped':native['reaped'],'stdoutEOF':native['stdoutEOF'],'stderrEOF':native['stderrEOF'],
            'FDsClosed':native['FDsClosed'],'first':native['first'],'secondary':native['secondary']}})
    finally:
        if owned:os.close(fd)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--manifest',required=True);p.add_argument('--sha256',required=True)
    p.add_argument('--output',required=True);a=p.parse_args();run(a.manifest,a.sha256,a.output)

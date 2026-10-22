"""Finite read-only A-controller medium, using the existing genisoimage route.

No CLI or effects on import. The admitted Root caller first authenticates this
complete source and its capture primitive. This prepares bytes, never a VM or
native qualification. The source image is neither opened writable nor copied.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

FILES={'omen_steamos_guest.py','omen_steamos_native.py','omen_steamos_probe.py',
       'omen_ci_result.py','output-install.robot','robotframework-7.5-py3-none-any.whl'}
WHEEL_SHA='5a194db36524604fafa1da89adebc837db9a95adf15ffd746e09ce98251e6c68'
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def need(value,reason):
    if not value:raise ValueError(reason)


def ident(info):return {key:getattr(info,key)for key in FIELDS}


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def held(ref,cap):
    path=Path(ref['path']);need(path.is_absolute()and path.resolve()==path,'exact adopted source path')
    # Root-owned non-writable ancestry is required, not just a Root leaf in a
    # replaceable user's directory. No source discovery through sys.path.
    for parent in [path.parent,*path.parent.parents]:
        st=parent.lstat();need(stat.S_ISDIR(st.st_mode)and st.st_uid==st.st_gid==0 and
                              not st.st_mode&0o022,'protected source ancestry')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and
             before.st_nlink==1 and not before.st_mode&0o022 and 0<before.st_size<=cap,
             'actual protected finite source file')
        raw=bytearray()
        while part:=os.read(fd,65536):raw.extend(part);need(len(raw)<=cap,'source overflow')
        need(ident(before)==ident(os.fstat(fd))==ident(path.lstat())==ref['identity']and
             len(raw)==ref['bytes']and hashlib.sha256(raw).hexdigest()==ref['sha256'],
             'adopted source full9/EOF/hash mismatch')
        return bytes(raw)
    finally:os.close(fd)


def create(path,raw,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        view=memoryview(raw)
        while view:
            n=os.write(fd,view);need(n>0,'medium staging short write');view=view[n:]
        os.fchmod(fd,mode);os.fsync(fd);st=os.fstat(fd)
        need(ident(st)==ident(Path(path).lstat()),'medium staging identity replaced')
        return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':ident(st)}
    finally:os.close(fd)


def prepare(directory,manifest,source_refs,generator_ref,capture):
    need(os.geteuid()==os.getuid()==0 and set(source_refs)==FILES,'Root complete finite controller graph')
    need(manifest.get('kind')=='EXE_STEAMOS_PHASE_MEDIA_V1'and manifest.get('guest_uid')==1000 and
         re.fullmatch('[0-9a-f]{32}',manifest.get('nonce',''))and
         re.fullmatch('[0-9a-f]{40}',manifest.get('controller_commit',''))and 'files'not in manifest,
         'exact controller A/nonce/data, not a mutable file manifest')
    need(source_refs['robotframework-7.5-py3-none-any.whl']['sha256']==WHEEL_SHA,'official exact Robot7.5 source')
    blobs={name:held(ref,16*1024**2)for name,ref in source_refs.items()}
    held(generator_ref,32*1024**2)
    need(generator_ref['path']=='/usr/bin/genisoimage','existing fixed ISO generator, no caller argv')
    directory=Path(directory)
    need(directory==Path('/run/opemos-output-controller-'+manifest['nonce'])and not os.path.lexists(directory),
         'one exact fresh generated controller directory')
    directory.mkdir(mode=0o755);work=directory/'source';work.mkdir(mode=0o755)
    # Read-only, Root-owned source bytes are executed only in the actual guest.
    pins={name:create(work/name,raw,0o444)for name,raw in blobs.items()}
    full=dict(manifest,files={name:{'bytes':ref['bytes'],'sha256':ref['sha256']}for name,ref in pins.items()})
    manifest_pin=create(work/'manifest.json',encoded(full),0o444)
    iso=directory/'observer.iso'
    argv=[generator_ref['path'],'-quiet','-iso-level','3','-R','-J','-V','OPROBOT',
          '-o',str(iso),str(work)]
    try:
        result=capture(argv,b'',{'max_bytes':1048576,'stderr_max_bytes':65536,'free_reserve_bytes':67108864},
                       directory/'generator-capture',60,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'})
    except BaseException as error:
        original=getattr(error,'transport_receipt',None)
        diagnostic=original if original is not None else{'first':{'type':type(error).__name__},
            'actual_numeric_exit':'UNKNOWN','VM_started':False}
        try:create(directory/'generator-failure.json',encoded(diagnostic),0o400)
        except BaseException as secondary:error.add_note('generator failure persistence UNKNOWN: '+type(secondary).__name__)
        raise
    # No retry, source rewrite, old ISO adoption, or returncode-only success.
    create(directory/'generator-receipt.json',encoded(result),0o400)
    need(result.get('complete')is True and result.get('local_reaped')is True and
         result.get('numeric_exit')==0,'actual ISO producer failed; original receipt/logs retained')
    st=iso.lstat();need(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and st.st_nlink==1 and
                      0<st.st_size<=64*1024**2,'actual finite generated ISO')
    os.chmod(iso,0o644);st=iso.lstat()
    ref={'path':str(iso),'bytes':st.st_size,'identity':ident(st)}
    fd=os.open(iso,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        digest=hashlib.sha256();length=0
        while part:=os.read(fd,65536):digest.update(part);length+=len(part)
        need(length==st.st_size and ident(st)==ident(os.fstat(fd))==ident(iso.lstat()),'ISO full9/EOF changed')
        ref['sha256']=digest.hexdigest()
    finally:os.close(fd)
    paths=[]
    for parent,dirs,names in os.walk(directory,followlinks=False):
        need(len(paths)<64,'finite complete controller preparation dependency inventory')
        for name in dirs:need(not(Path(parent)/name).is_symlink(),'no controller dependency directory links')
        for name in names:
            path=Path(parent)/name;st=path.lstat()
            need(stat.S_ISREG(st.st_mode)and st.st_nlink==1,'exclusive controller preparation file dependency')
            paths.append(str(path))
    paths.append(str(directory/'receipt.json'))
    out={'kind':'EXE_SOURCE_A_OBSERVER_MEDIUM_V1','manifest':full,'observer':ref,
         'observerManifest':manifest_pin,'sourcePins':pins,'generator':generator_ref,
         'chargedPaths':sorted(paths),'VM_started':False,'native_qualified':False}
    create(directory/'receipt.json',encoded(out),0o400)
    return out

"""Root parent's readable observation of an ALREADY exited R29 finalizer.

No VM, process control, private-data retirement or authority change. This finite
normal-publication amendment must be independently reviewed/adopted by Root.
The ordinary consumer never opens Root0400 native records or receives raw ones.
"""
import hashlib
import os
from pathlib import Path
import stat
import time
from omen_output_lifecycle import protected_bytes, strict, canonical, identity, need


def observe(request_pin):
    need(os.getuid()==os.geteuid()==0,'actual independent Root parent')
    q=strict(protected_bytes(request_pin,grant=True))
    need(q['kind']=='ROOT_ADMITTED_RANGE_FINALIZER_PARENT_OBSERVATION_V1'and q['effectOwner']=='/root',
         'one exact normal publication observation, not arbitrary Root reader')
    validity=q['publicationValidity']
    def clock():
        need(validity['hostBoot']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()and
             type(validity['notBeforeMonotonic'])in(int,float)and type(validity['notAfterMonotonic'])in(int,float)and
             0<validity['notAfterMonotonic']-validity['notBeforeMonotonic']<=14400 and
             validity['notBeforeMonotonic']<=time.monotonic()<validity['notAfterMonotonic'],
             'same original actual publication interval/boot; never extend retention')
    clock();closed=strict(protected_bytes(q['closurePin'],mode=0o444))
    need(closed['kind']=='ROOT_VERIFIED_WINDOWS_RANGE_PUBLICATION_NATIVE_CLOSED_V1'and
         closed['identity']==q['identity']and closed['rangePin']==q['rangePin']and
         closed['publicationValidity']==validity,'exact same R29 range/native closure')
    original=strict(protected_bytes(closed['publicationRequestPin']))
    parent=strict(protected_bytes(closed['RootParentRequestPin']))
    need(parent['kind']=='ROOT_ADMITTED_ONE_WINDOWS_RANGE_PUBLICATION_CLOSURE_V1'and
         parent['publicationRequestPin']==closed['publicationRequestPin']and
         all(parent[k]==closed[k]for k in('actualPublisherNativePin','actualPublisherStdoutPin','actualPublisherStderrPin')),
         'same original source/actual publisher/finalizer parent request')
    n=strict(protected_bytes(q['actualFinalizerNativePin']))
    expected=['/usr/bin/python3','-B','-I',original['rootToolsBootstrapSourcePin']['path'],
              'close-publication',closed['RootParentRequestPin']['path']]
    need(n['argv']==expected and type(n['numericExit'])is int and n['numericExit']==0 and
         all(n.get(k)is True for k in('lifecycleClosed','reaped','stdoutEOF','stderrEOF','childSetRestored','pidfdCaptured'))and
         n['fd']['restored']is True and n['firstError']is None and n['errors']==[]and n['tailUNKNOWN']is False,
         'actual exact finalizer capture numeric0/reap/full EOF/FD/child closure')
    try:birth=Path('/proc',str(n['pid']),'stat').read_text().rsplit(')',1)[1].split()[19]
    except FileNotFoundError:birth=None
    need(birth!=str(n['start']),'original finalizer birth remains live')
    stdout=protected_bytes(q['actualFinalizerStdoutPin']);stderr=protected_bytes(q['actualFinalizerStderrPin'],allow_empty=True)
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    for i,name in enumerate(('actualFinalizerStdoutPin','actualFinalizerStderrPin')):
        pin=q[name];need(pin['bytes']==n['raw'][i]['bytes']and pin['sha256']==n['raw'][i]['sha256']and
            [pin['identity'][k]for k in fields]==n['raw'][i]['full9'],'actual complete native raw pin/full9 binding')
    result=strict(stdout)
    need(stderr==b''and result['kind']=='ROOT_RANGE_PUBLICATION_CLOSURE_LEAF_READBACK'and
         result['publicationClosurePin']==q['closurePin']and result['rangePin']==q['rangePin']and
         result['actualPublisherNativeClosed']is True and
         all(result['actualClosurePersistence'].get(k)is True for k in
             ('fsyncCompleted','FDClosed','directoryFsyncCompleted','directoryFDClosed','readbackCompleted')),
         'actual finalizer persisted/closed/read back this exact leaf')
    value={'kind':'ROOT_VERIFIED_WINDOWS_RANGE_FINALIZER_OBSERVED_V1','identity':q['identity'],
        'rangePin':q['rangePin'],'closurePin':q['closurePin'],'publicationValidity':validity,
        'RootParentRequestPin':closed['RootParentRequestPin'],'publicationRequestPin':closed['publicationRequestPin'],
        'publisherSourcePin':closed['publisherSourcePin'],'expectedFinalizerArgv':expected,
        'actualClosurePersistence':result['actualClosurePersistence'],
        'finalizer':{'pid':n['pid'],'start':n['start'],'numericExit':0,'reaped':True,'stdoutEOF':True,
            'stderrEOF':True,'FDSetRestored':True,'childSetRestored':True,'sameBirthAbsent':True,
            'completeRawReadback':True,'firstError':None,'errors':[],'tailUNKNOWN':False},
        **{name:closed[name]for name in('actualPublisherNativePin','actualPublisherStdoutPin','actualPublisherStderrPin')},
        **{name:q[name]for name in('actualFinalizerNativePin','actualFinalizerStdoutPin','actualFinalizerStderrPin')},
        'parentObservationRequestPin':request_pin,'privateOriginalsRetained':True}
    raw=canonical(value)+b'\n';need(len(raw)<=65536,'complete bounded parent observation')
    out=Path(q['rangePin']['path']).parent/'publication-finalizer-observed.json';clock()
    directory=os.open(out.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fd=None;first=None;secondary=[]
    try:
        meta=os.fstat(directory);need(stat.S_ISDIR(meta.st_mode)and meta.st_uid==meta.st_gid==0 and
             not meta.st_mode&0o022 and identity(meta)==identity(out.parent.lstat()),'same protected Root publication parent')
        fd=os.open(out.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o444,dir_fd=directory)
        view=memoryview(raw)
        while view:clock();count=os.write(fd,view);need(count>0,'whole observation write');view=view[count:]
        os.fsync(fd);meta=os.fstat(fd);pin={'path':str(out),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':identity(meta)}
        os.fsync(directory)
    except BaseException as e:first=e
    finally:
        for handle in(fd,directory):
            if handle is not None:
                try:os.close(handle)
                except BaseException as e:
                    if first is None:first=e
                    else:secondary.append(repr(e))
    if first is not None:
        first.add_note('Create-only observation partial retained; independent close failures '+repr(secondary));raise first
    clock();need(protected_bytes(pin,mode=0o444)==raw,'whole closed observation readback')
    # Caller aligns bytes -> public size explicitly; mode/full9 remain original.
    return {'path':pin['path'],'size':pin['bytes'],'sha256':pin['sha256'],'identity':pin['identity']}

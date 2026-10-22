"""Managed-libvirt source-job controller A, invoked only by normal Root admission.

This is not an installer or a queue replacement. Root must adopt these reviewed
bytes and the existing five backend modules before issuing a fresh source-job
grant. No source/B code is imported or executed by this host process.
"""
import base64
import hashlib
import os
import resource
from pathlib import Path
import stat
import time
import xml.etree.ElementTree as ET

from omen_source_workloads import WORKLOADS, subject, canonical, need, verify_result
from omen_output_lifecycle import protected_bytes, strict, backend, pop_guest_frame


def execute(grant_pin, persist):
    need(os.getuid()==os.geteuid()==0,'normal source controller requires actual Root; never guest B')
    import libvirt
    g=strict(protected_bytes(grant_pin,grant=True));now=time.time()
    need(os.getuid()==os.geteuid()==0 and g['kind']=='ROOT_ADMITTED_OMEN_SOURCE_JOB_V1'and
         g['runtimeAuthorized']is True and g['RootIssued']is True and
         g['hostBoot']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()and
         g['issuedUnix']<=now<g['startBeforeUnix']<=g['issuedUnix']+300,
         'fresh exact Root source-job admission; no prior output/GPU grant reuse')
    spec=subject(g['subject'],g['identity']['source_commit']);duration=WORKLOADS[spec['workload']][1]
    need(g['sourceArchive']['sha256']==spec['source_archive_sha256']and
         g['sourceArchive']['bytes']==spec['source_archive_bytes'],'same complete admitted source archive')
    if spec['workload']=='windows-build':
        seed=strict(protected_bytes(g['seedProofPin'],mode=0o444))
        seed_spec=subject(seed['subject'],g['identity']['source_commit'])
        need(seed['kind']=='ROOT_VERIFIED_OMEN_SOURCE_JOB_CLOSED_V1'and seed_spec['workload']=='seed-runtime-source'and
             all(seed_spec[k]==v for k,v in spec.items()if k!='workload')and
             seed['first']is None and seed['secondary']==[]and seed['closure']['unknown']==[],
             'same-source actual closed seed prerequisite')
        gm=strict(protected_bytes(g['guestManifestPin']))
        need(gm['seedPackage']['sha256']==seed['package']['sha256']and
             gm['seedPackage']['bytes']==seed['package']['bytes'],
             'actual Windows guest seed tar differs from closed seed output')
    need(g['issuedUnix']<g['wholeDeadlineUnix']<=g['issuedUnix']+duration,
         'original required workload budget, never refreshed')
    need(all(type(g[k])in(int,float)for k in('issuedMonotonic','wholeDeadlineMonotonic'))and
         g['issuedMonotonic']<=time.monotonic()<g['wholeDeadlineMonotonic']<=g['issuedMonotonic']+duration,
         'same-boot original monotonic budget, not wall-clock-only timeout')
    deadline=g['wholeDeadlineUnix'];modules=backend(g['backendSources']);peer=modules['libvirt_peer'];native=modules['libvirt_native']
    need(type(g['reservedBytes'])is int and g['reservedBytes']>=10*1024**3+64*1024**2,
         'receiver/publication/exchange complete future-copy reservation within original VM cap')
    root=Path(g['resultRoot']);need(root.parent==Path('/run')and root.name.startswith('opemos-source-job-')and
         not root.exists(),'fresh bounded creator-owned source result root')
    pre=strict(protected_bytes(g['preflightPin']));request=g['queueRequest'];intent=g['queueIntent']
    need(pre['identity']==g['identity']and pre['subject']==spec and pre['hostBoot']==g['hostBoot']and
         pre['controllerSourceQualified']is True and pre['installedCurrent']is True and
         pre['wholeQueueConflictFree']is True and pre['unknown']==[]and pre['ownedDescriptorsClosed']is True and
         0<=now-pre['observedUnix']<=30 and pre['noNIC']is True and pre['noHostdev']is True and
         pre['credentialFreeGuest']is True and pre['candidateHostExecution']is False and
         pre['guestBootstrapSourcePins']==g['guestBootstrapSourcePins']and
         pre['sourceArchive']==g['sourceArchive']and pre['candidateTree']==spec['candidate_tree'],
         'complete actual current/source/bootstrap/media/queue admission; no labels as proof')
    pool={'cpus':10,'memoryBytes':34359738368,'swapBytes':0};need(pre['pool']==pool,'unchanged existing pool')
    peer.NativeOps().entry(intent,'PREPARED');peer.NativeOps().budget(request,'PREPARED',None)
    xml=protected_bytes(g['xmlPin']).decode();tree=ET.fromstring(xml)
    mac=WORKLOADS[spec['workload']][0]=='macos'
    need(tree.tag=='domain'and tree.get('type')==('qemu'if mac else'kvm')and
         tree.find('./os/type').get('arch')==('aarch64'if mac else'x86_64')and tree.findtext('uuid')==request['domainUUID']and
         tree.findtext('name')==request['domainName']and not tree.findall('.//interface')and
         not tree.findall('.//hostdev')and not tree.findall('.//filesystem')and
         not any('commandline'in e.tag for e in tree.iter()),'finite existing KVM domain; no NIC/hostdev/share/argv extension')
    channels=tree.findall('./devices/channel');need(len(channels)==1 and
        channels[0].find('target').get('name')=='org.opemos.source-job.0','one exact named guest-only channel')
    writable={p['path']for p in g['writablePins']};readonly={p['path']for p in g['readonlyPins']}
    need(writable and readonly and not writable&readonly and g['sourceArchive']['path']in readonly,
         'distinct readonly source/dependencies and disposable writable target')
    for disk in tree.findall('./devices/disk'):
        src=disk.find('source');need(src is not None and set(src.attrib)=={'file'},'regular file-backed disks only')
        path=src.get('file');need(path in(readonly if disk.find('readonly')is not None else writable),
             'all exact disks classified before launch')
    for ref in g['protectedHostPins']:native.held(ref,1024**2)
    need(len({(p['identity']['st_dev'],p['identity']['st_ino'])for p in g['readonlyPins']+g['writablePins']})==
         len(g['readonlyPins']+g['writablePins']),'no mutable target aliases any readonly source/base')
    held=[];owned=None;observer=None;stream=None;domain=None;callback=None;timer=None;leader=None;scope=None
    events=[];first=None;secondary=[];guest=None;buffer=bytearray();active=None;transferred=0;files={};observations={}
    started=time.time();root.mkdir(mode=0o700);domain_created=False
    def current():
        need(time.time()<deadline and time.monotonic()<g['wholeDeadlineMonotonic']and
             abs((time.time()-g['issuedUnix'])-(time.monotonic()-g['issuedMonotonic']))<=5 and
             Path('/proc/sys/kernel/random/boot_id').read_text().strip()==g['hostBoot'],
             'original source job clock/host boot')
        entry=peer.process(intent['entry']['pid'])
        need(all(entry[k]==intent['entry'][k]for k in('pid','start','uid'))and entry['uid']==0 and
             entry['cgroup'].startswith(peer.POOL+'/'+request['unit'])and
             hashlib.sha256(canonical(entry['argv'])).hexdigest()==intent['entry']['argvSHA256'],
             'original Root entry birth/UID/cgroup/argv across each bounded stream batch')
        if leader is not None:
            a=peer.process(leader['pid']);need(all(a[k]==leader[k]for k in('pid','start','uid','cgroup'))and
                a['uid']==64055 and a['cgroup'].startswith(peer.POOL+'/'+request['vmSlice']+'/'),
                'original source QEMU birth/UID/pool cgroup')
            raw=peer.process_snapshot(a['pid']);need(raw['uids']==[64055]*4 and raw['start']==a['start'],
                'actual full QEMU UID tuple, not proc inode ownership')
    def disk_fds():
        current();regular={p['path']:p for p in g['readonlyPins']+g['writablePins']+g['extraRegularPins']}
        observed=[]
        for leaf in Path('/proc',str(leader['pid']),'fd').iterdir():
            try:meta=leaf.stat();target=os.readlink(leaf)
            except FileNotFoundError:continue
            if stat.S_ISREG(meta.st_mode):
                need(target in regular,'unknown live QEMU regular FD')
                ref=regular[target];need(meta.st_dev==ref['identity']['st_dev']and meta.st_ino==ref['identity']['st_ino'],
                    'same actual QEMU dependency inode')
                flags=int(next(x.split()[1]for x in Path('/proc',str(leader['pid']),'fdinfo',leaf.name).read_text().splitlines()
                               if x.startswith('flags:')),8)
                if target in readonly:need(flags&os.O_ACCMODE==os.O_RDONLY,'source/base media opened writable')
                observed.append({'target':target,'identity':peer.ident(meta),'flags':flags})
            elif stat.S_ISCHR(meta.st_mode):
                need(target in('/dev/kvm','/dev/null','/dev/urandom','/dev/random','/dev/ptmx','/dev/pts/ptmx',
                                '/dev/rtc0','/dev/hpet'),'no QEMU VFIO/DRM/physical or unknown character device FD')
        current();persist('actual-source-QEMU-FDs',observed)
    def ledger(label,summary=False):
        # Root pins the existing whole-graph ledger implementation as part of A.
        from ubuntu_vm_runner import output_storage_ledger
        mutable=writable|{p['path']for p in g['extraRegularPins']if p['path']not in readonly}
        value=output_storage_ledger(g['dependencies']+[str(p)for p in root.rglob('*')if p.is_file()],g['reservedBytes'],
            platform='windows'if WORKLOADS[spec['workload']][0]=='windows'else'other',
            mutable_paths=mutable)
        # Charge the complete future growth of every permitted QEMU-writable
        # regular inode, not just a sparse COW's present length. The kernel
        # ceiling is set and read back while this new domain is paused below.
        ceiling=g['qemuFileCeilingBytes'];need(type(ceiling)is int and ceiling>0,'finite actual QEMU file ceiling')
        rows={row['path']:row for row in value['files']}
        need(mutable<=set(rows),'all QEMU-writable regular dependencies charged')
        growth=sum(max(0,ceiling-rows[p]['chargedBytes'])for p in mutable)
        value['observedChargedBytes']=value['chargedBytes'];value['growthReserveBytes']=growth
        value['chargedBytes']+=growth
        limit=80_000_000_000 if WORKLOADS[spec['workload']][0]=='windows'else 60_000_000_000
        need(value['chargedBytes']<=limit and value.get('unknown',[])==[],'whole source VM union/storage cap')
        observations[label]=dict(value,unknown=value.get('unknown',[]))
        persist('source-storage-'+label,dict(observedMonotonic=time.monotonic(),
            chargedBytes=value['chargedBytes'],observedChargedBytes=value['observedChargedBytes'],
            growthReserveBytes=growth,uniqueInodes=value['uniqueInodes'],hardBytes=limit)if summary else value)
    try:
        for ref in g['readonlyPins']+g['writablePins']:
            fd=os.open(ref['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);held.append((fd,ref))
            need(peer.ident(os.fstat(fd))==ref['identity']==peer.ident(os.lstat(ref['path'])),'held source/base/working full9')
            if ref['bytes']<=256*1024**2:native.held(ref,ref['bytes'])
            else:need(ref in pre['qualifiedReadonlyOrWorkingPins'],'existing complete base qualification/full9, no unbounded host allocation')
        # QEMU UID probe must independently open/read source/media and fail every
        # readonly write, with actual numeric/EOF/reap/FD closure. Never os.access.
        dac=strict(protected_bytes(g['dacProofPin']))
        need(dac['hostBoot']==g['hostBoot']and type(dac['observedUnix'])in(int,float)and
             0<=time.time()-dac['observedUnix']<=30 and dac['groups']==[993]and
             dac['uids']==[64055]*4 and dac['gid']==993 and type(dac['numericExit'])is int and dac['numericExit']==0 and
             dac['reaped']is True and dac['stdoutEOF']is True and dac['stderrEOF']is True and
             dac['FDsClosed']is True and dac['unknown']==[]and dac['subjects']==g['readonlyPins']+g['writablePins'],
             'fresh exact actual same-UID open/DAC proof')
        ledger('before');need(observations['before']['chargedBytes']<=
            (79_000_000_000 if WORKLOADS[spec['workload']][0]=='windows'else 59_000_000_000),
            'original one-GB early guard before source launch')
        validation=native.native_child(['/usr/bin/virt-xml-validate','-','domain'],deadline,
            g['nativeTools']['/usr/bin/virt-xml-validate'],xml.encode());persist('source-installed-xml',validation)
        need(validation['numeric']==0,'actual installed libvirt XML validation')
        native.bootstrap_event_driver(persist);owned=libvirt.open('qemu:///system');observer=libvirt.openReadOnly('qemu:///system')
        need(owned is not None and observer is not None and owned.getURI()==observer.getURI()=='qemu:///system',
             'independent controlling/readonly system connections')
        timer=libvirt.virEventAddTimeout(100,lambda *a:None,None)
        callback=observer.domainEventRegisterAny(None,libvirt.VIR_DOMAIN_EVENT_ID_LIFECYCLE,
            lambda c,d,e,x,o:events.append({'uuid':d.UUIDString(),'name':d.name(),'event':e,'detail':x}),None)
        need(not any(d.UUIDString()==request['domainUUID']or d.name()==request['domainName']for d in owned.listAllDomains(0)),
             'never adopt existing domain')
        current();peer.NativeOps().entry(intent,'PREPARED')
        domain=owned.createXML(xml,libvirt.VIR_DOMAIN_START_PAUSED|libvirt.VIR_DOMAIN_START_AUTODESTROY);domain_created=True
        matches=[]
        for p in Path('/proc').iterdir():
            if not p.name.isdigit():continue
            try:raw=peer.process_snapshot(int(p.name))
            except(FileNotFoundError,ProcessLookupError):continue
            argv=raw['argv']
            if '-uuid'in argv and argv[argv.index('-uuid')+1]==request['domainUUID']:
                a=peer.process(raw['pid']);need(raw['uids']==[64055]*4 and a['start']==raw['start']and
                    peer.process_snapshot(raw['pid'])==raw,'selected original uniform-UID QEMU role')
                need(a['uid']==64055 and a['cgroup'].startswith(peer.POOL+'/'+request['vmSlice']+'/'),
                     'actual selected QEMU uniform UID and own pool')
                matches.append(a)
        need(len(matches)==1,'unique actual new source QEMU');leader=matches[0]
        scope=leader['cgroup'][len(peer.POOL+'/'+request['vmSlice']+'/'):].split('/')[0]
        peer.NativeOps().budget(request,'ACTIVE',scope);current()
        ceiling=g['qemuFileCeilingBytes']
        original_limits=resource.prlimit(leader['pid'],resource.RLIMIT_FSIZE)
        # Never enlarge an inherited finite ceiling. This is only the exact
        # newly created paused QEMU, with its original birth checked both sides.
        need(all(v==resource.RLIM_INFINITY or v>=ceiling for v in original_limits),
             'source file ceiling cannot relax inherited limits')
        current();resource.prlimit(leader['pid'],resource.RLIMIT_FSIZE,(ceiling,ceiling));current()
        need(resource.prlimit(leader['pid'],resource.RLIMIT_FSIZE)==(ceiling,ceiling),
             'actual kernel QEMU file ceiling readback')
        persist('source-QEMU-kernel-file-ceiling',{'pid':leader['pid'],'birth':leader['start'],
            'original':original_limits,'actual':(ceiling,ceiling),'aggregateAdmission':False})
        need(domain.resume()==0,'actual source VM resume')
        disk_fds()
        stream=owned.newStream(libvirt.VIR_STREAM_NONBLOCK)
        domain.openChannel('org.opemos.source-job.0',stream,0) # no FORCE, no stolen session
        # One finite stream exports actual A-agent result/raw files, not commands.
        terminal=None;last_storage=time.monotonic()
        while terminal is None:
            current()
            need(resource.prlimit(leader['pid'],resource.RLIMIT_FSIZE)==(ceiling,ceiling),
                 'original QEMU kernel file ceiling changed during workload')
            if time.monotonic()-last_storage>=30:
                ledger('during',summary=True);last_storage=time.monotonic()
            block=stream.recv(min(32768,65537-len(buffer)))
            if block==-2:time.sleep(.05);continue
            need(block,'source channel EOF before sealed terminal');buffer.extend(block)
            while True:
                row=pop_guest_frame(buffer)
                if row is None:break
                need(row.get('identity')==g['identity']and row.get('subject')==spec,'same actual source stream identity')
                kind=row.get('kind')
                if kind=='source-file':
                    need(active is None and len(files)<512 and type(row['bytes'])is int and
                         0<=row['bytes']<=16*1024**2 and row['name']==Path(row['name']).name and
                         re_safe(row['name'])and row['name']not in files,'finite create-only source leaf')
                    path=root/row['name'];fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    active={'row':row,'path':path,'fd':fd,'hash':hashlib.sha256(),'count':0}
                elif kind=='source-data':
                    need(active is not None and row['offset']==active['count'],'ordered source byte stream')
                    data=base64.b64decode(row['base64'],validate=True);need(0<len(data)<=32768 and
                        active['count']+len(data)<=active['row']['bytes']and transferred+len(data)<=5*1024**3,
                        'source evidence/package transfer cap')
                    view=memoryview(data)
                    while view:n=os.write(active['fd'],view);need(n>0,'source output write progress');view=view[n:]
                    active['hash'].update(data);active['count']+=len(data);transferred+=len(data)
                elif kind=='source-file-end':
                    need(active is not None and active['count']==active['row']['bytes']and
                        active['hash'].hexdigest()==active['row']['sha256'],'whole source output EOF/hash')
                    os.fchmod(active['fd'],0o444);os.fsync(active['fd']);meta=os.fstat(active['fd']);os.close(active['fd'])
                    files[active['row']['name']]=dict(active['row'],path=str(active['path']),identity=peer.ident(meta))
                    active=None
                elif kind=='source-terminal':
                    need(active is None and row['files']==files_projection(files)and type(row['agentParent']['numericExit'])is int and
                         row['agentParent']['reaped']is True and row['agentParent']['stdoutEOF']is True and
                         row['agentParent']['stderrEOF']is True and row['agentParent']['FDsClosed']is True,
                         'actual independent guest agent parent closure/all outputs')
                    guest=strict((root/'source-result.json').read_bytes())
                    need(guest.get('controller_manifest_sha256')==g['guestManifestPin']['sha256'],
                         'actual guest used another controller/source/tool manifest')
                    if guest.get('status')=='passed':verify_result(guest,g['identity'],spec)
                    else:
                        need(guest.get('identity')==g['identity']and guest.get('subject')==spec,'exact failed guest identity')
                        first={'phase':'guest-source-workload','actual':guest.get('first'),'parent':row['agentParent']}
                    parent=row['agentParent']
                    if parent['numericExit']!=0 or parent.get('first')is not None or parent.get('secondary'):
                        failure={'phase':'guest-source-parent','actual':parent}
                        if first is None:first=failure
                        else:secondary.append(failure)
                    terminal=row
                else:raise ValueError('unknown source frame')
        disk_fds();peer.NativeOps().entry(intent,'PREPARED');ledger('during')
        need(stream.finish()==0,'actual source channel close');stream=None
        need(domain.shutdownFlags(libvirt.VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN)==0,'normal source guest shutdown request')
        while time.time()<deadline:
            need(time.monotonic()<g['wholeDeadlineMonotonic']and
                 abs((time.time()-g['issuedUnix'])-(time.monotonic()-g['issuedMonotonic']))<=5,
                 'original source shutdown clock/deadline')
            libvirt.virEventRunDefaultImpl()
            if not any(d.UUIDString()==request['domainUUID']for d in observer.listAllDomains(0)):break
        need(not any(d.UUIDString()==request['domainUUID']for d in observer.listAllDomains(0))and
             any(e['uuid']==request['domainUUID']and e['name']==request['domainName']and
                 e['event']==libvirt.VIR_DOMAIN_EVENT_STOPPED and e['detail']==libvirt.VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN
                 for e in events),'actual ordinary daemon shutdown/absence, not a request as closure')
    except BaseException as error:
        failure={'type':type(error).__name__,'reason':str(error)}
        if first is None:first=failure;persist('FIRST-source-job',failure)
        else:secondary.append(failure);persist('SECONDARY-source-job',failure)
    finally:
        cleanup_start=len(secondary)
        if stream is not None:
            try:need(stream.abort()==0,'actual channel abort close')
            except BaseException as error:secondary.append({'phase':'channel-close','reason':str(error)})
            finally:stream=None
        # Drop virDomain/virStream references before closing the owning
        # AUTODESTROY connection. A positive virConnectClose refcount is NOT a
        # closed connection and must never become an accepted closure.
        domain=None
        for label,operation in [('own-control',lambda:owned.close()if owned is not None else 0),
            ('own-callback',lambda:observer.domainEventDeregisterAny(callback)if observer is not None and callback is not None else 0)]:
            try:need(operation()in(None,0),'numeric native close failure')
            except BaseException as error:secondary.append({'phase':label,'type':type(error).__name__,'reason':str(error)})
        if active is not None:
            try:os.close(active['fd'])
            except BaseException as error:secondary.append({'phase':'partial-source-file','reason':str(error)})
        closed=False
        try:
            if observer is not None:
                for _ in range(150):
                    libvirt.virEventRunDefaultImpl()
                    if not any(d.UUIDString()==request['domainUUID']or d.name()==request['domainName']for d in observer.listAllDomains(0)):break
                need(not any(d.UUIDString()==request['domainUUID']or d.name()==request['domainName']for d in observer.listAllDomains(0)),
                     'exact AUTODESTROY/ordinary domain still present')
            if leader is not None:
                try:need(peer.process(leader['pid'])['start']!=leader['start'],'original source QEMU remains')
                except(FileNotFoundError,ProcessLookupError):pass
            peer.NativeOps().budget(request,'PREPARED',None)
            closed=True
        except BaseException as error:secondary.append({'phase':'VM-closure','reason':str(error)})
        try:
            if observer is not None:need(observer.close()==0,'observer numeric close')
        except BaseException as error:secondary.append({'phase':'observer-close','reason':str(error)})
        try:
            if timer is not None:need(libvirt.virEventRemoveTimeout(timer)==0,'own event timer close')
        except BaseException as error:secondary.append({'phase':'timer-close','reason':str(error)})
        for fd,ref in held:
            try:
                if ref['path']in readonly:
                    need(peer.ident(os.fstat(fd))==ref['identity']==peer.ident(os.lstat(ref['path'])),
                         'readonly original/source identity drift')
            except BaseException as error:secondary.append({'phase':'held-input-recheck','reason':str(error)})
            finally:
                try:os.close(fd)
                except BaseException as error:secondary.append({'phase':'held-input-close','reason':str(error)})
        for ref in g['protectedHostPins']:
            try:native.held(ref,1024**2)
            except BaseException as error:secondary.append({'phase':'protected-host-source-drift','reason':str(error)})
        try:ledger('after')
        except BaseException as error:secondary.append({'phase':'final-storage','reason':str(error)})
    result={'kind':'ROOT_OMEN_SOURCE_JOB_ACTUAL_EXECUTION_V1','identity':g['identity'],'subject':spec,
        'hostBoot':g['hostBoot'],'startedUnix':started,'finishedUnix':time.time(),'guest':guest,
        'files':files,'leader':leader,'events':events,'pool':pool,'storage':observations,
        'first':first,'secondary':secondary,'closureKnown':closed and len(secondary)==cleanup_start,
        'domainCreated':domain_created,'noGUIImageOrGPUAcceptance':True}
    persist('actual-source-job-final',result)
    return result


def re_safe(name):
    import re
    return re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,159}',name)is not None


def files_projection(files):
    return {name:{k:row[k]for k in('bytes','sha256','file_kind')}for name,row in files.items()}


def publish(grant_pin, execution_pin, native_pin):
    """Independent normal Root parent publishes AFTER controller numeric closure.

    The existing canonical queue must additionally close this publisher before
    the planner can collect it. No process attests its own future wait/reap.
    """
    from omen_ci_reader import read_verified
    g=strict(protected_bytes(grant_pin,grant=True));result=strict(protected_bytes(execution_pin))
    native=strict(protected_bytes(native_pin));spec=subject(g['subject'],g['identity']['source_commit'])
    need(os.geteuid()==0 and g['hostBoot']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()and
         time.time()<g['wholeDeadlineUnix']and result['identity']==g['identity']and result['subject']==spec and
         result['kind']=='ROOT_OMEN_SOURCE_JOB_ACTUAL_EXECUTION_V1'and
         native['argv']==g['fixedControllerArgv']and type(native['numericExit'])is int and native['numericExit']==0 and
         all(native.get(k)is True for k in('lifecycleClosed','reaped','stdoutEOF','stderrEOF','childSetRestored','pidfdCaptured'))and
         native['fd']['restored']is True and native['firstError']is None and native['errors']==[]and native['tailUNKNOWN']is False,
         'actual independent source controller numeric/native/EOF/reap/FD closure')
    try:birth=Path('/proc',str(native['pid']),'stat').read_text().rsplit(')',1)[1].split()[19]
    except FileNotFoundError:birth=None
    need(birth!=str(native['start'])and result['closureKnown']is True,'original controller still alive or VM closure unknown')
    public=Path(g['publicationRoot']);need(public.parent==Path('/run')and
        public.name=='opemos-source-public-'+g['identity']['nonce']and not public.exists(),'one exact create-only public root')
    public.mkdir(mode=0o755);rows=[];mapped={}
    def put(path,raw):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
        try:
            view=memoryview(raw)
            while view:n=os.write(fd,view);need(n>0,'complete source publication');view=view[n:]
            os.fsync(fd);meta=os.fstat(fd)
        finally:os.close(fd)
        return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                'identity':{k:getattr(meta,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}}
    prefix=g['identity']['run_id']+'-'+g['identity']['attempt']+'-'+g['identity']['nonce']+'-'
    for name,row in result['files'].items():
        need(re_safe(name)and row['path']==str(Path(g['resultRoot'])/name)and row['bytes']<=16*1024**2,
             'exact actual source result file')
        observed,data=read_verified(row['path'],16*1024**2,expected_sha=row['sha256'],expected_size=row['bytes'],uid=0)
        need(observed['identity']==row['identity']and stat.S_IMODE(row['identity']['st_mode'])==0o444,
             'actual full source output full9/hash/mode')
        public_name=prefix+name;pin=put(public/public_name,data)
        mapped[name]=public_name
        rows.append(dict(path=pin['path'],size=pin['bytes'],sha256=pin['sha256'],identity=pin['identity'],
                         uid=0,public=True,kind=row['file_kind'],name=public_name,bytes=pin['bytes']))
    # A failed boot/prerequisite can close correctly without ever producing a
    # guest result. Retain that distinction and independently captured Root
    # controller raws; do not invent a guest/process/test identity.
    guest_value=result['guest']
    if guest_value is None:
        need(result['first']is not None,'missing actual guest result without failure')
        guest_value={'kind':'ROOT_SOURCE_GUEST_NOT_OBSERVED_V1','identity':g['identity'],'subject':spec,
                     'status':'failed','guest':{},'commands':[],'first':result['first'],'secondary':result['secondary']}
    guest=put(public/'guest-result.json',canonical(guest_value)+b'\n')
    for index,pin in enumerate(native['sealedRawPins']):
        raw=protected_bytes(pin,allow_empty=True);public_pin=put(public/(prefix+'controller-'+str(index)+'.raw'),raw)
        rows.append(dict(path=public_pin['path'],size=len(raw),bytes=len(raw),sha256=public_pin['sha256'],
                         identity=public_pin['identity'],uid=0,public=True,kind='source-log',
                         name=Path(public_pin['path']).name))
    package_path=Path(g['resultRoot'])/'package-files.json'
    if package_path.exists():package=strict(package_path.read_bytes())
    else:need(result['first']is not None,'missing package metadata without failure');package=None
    if package is not None:
        need(package['kind']=='OMEN_SOURCE_PACKAGE_TAR_V1'and package['identity']==g['identity']and package['subject']==spec,
             'same actual bounded package tar')
        for chunk in package['chunks']:
            need(chunk['name']in mapped,'actual missing package chunk');chunk['public_name']=mapped[chunk['name']]
    limit=80_000_000_000 if WORKLOADS[spec['workload']][0]=='windows'else 60_000_000_000
    from ubuntu_vm_runner import output_storage_ledger
    # Receiver bytes are already materialized; public/exchange copies remain
    # explicitly charged rather than hiding them as post-VM host overhead.
    after=output_storage_ledger(g['dependencies']+
        [str(p)for folder in(Path(g['resultRoot']),public,Path(native_pin['path']).parent)
         for p in folder.rglob('*')if p.is_file()],
        g['reservedBytes']-5*1024**3,platform='windows'if WORKLOADS[spec['workload']][0]=='windows'else'other')
    result['storage']['after']=dict(after,unknown=[])
    value={'kind':'ROOT_VERIFIED_OMEN_SOURCE_JOB_CLOSED_V1','identity':g['identity'],'subject':spec,
        'hostBoot':g['hostBoot'],'startedUnix':result['startedUnix'],'finishedUnix':result['finishedUnix'],
        'guestResultPin':guest,'publicEvidence':rows,'package':package,
        'controllerNativePin':native_pin,'executionPin':execution_pin,'pool':result['pool'],
        'storage':{'limitBytes':limit,'earlyLimitBytes':limit-1_000_000_000,'observations':result['storage']},
        'closure':{**{k:True for k in('domainAbsent','originalPIDStartAbsent','cgroupEmpty','ownedFDsClosed',
            'hostUnchanged','observerClosed','controlClosed','mediaUnchanged','originalBaseUnchanged')},'unknown':[]},
        'first':result['first'],'secondary':result['secondary']}
    # Each true field above derives from execute's actual per-boundary checks
    # and independent native closure. Unknown or failed cleanup never reaches
    # this point. Queue closure still must independently follow this process.
    pin=put(public/'source-job-closed.json',canonical(value)+b'\n')
    fd=os.open(public,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return pin


def main():
    import argparse
    import sys
    from omen_ci_reader import read_verified
    p=argparse.ArgumentParser();p.add_argument('mode',choices=('transaction','execute'))
    p.add_argument('grant');args=p.parse_args()
    need(os.getuid()==os.geteuid()==0,'normal admitted Root source entry only')
    path=Path(args.grant)
    need(path.is_absolute()and path.is_relative_to('/run')and '..'not in path.parts and
         len(path.parts)>=4 and path.parts[2].startswith('opemos-'),'fixed transient source grant namespace')
    for parent in reversed(path.parents):
        info=parent.lstat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==info.st_gid==0 and
             not info.st_mode&0o022,'Root grant ancestry before initial read')
    grant_pin,raw=read_verified(path,1024**2,uid=0);need(protected_bytes(grant_pin,grant=True)==raw,'held initial grant')
    g=strict(raw);need(g['kind']=='ROOT_ADMITTED_OMEN_SOURCE_JOB_V1'and g['runtimeAuthorized']is True,
                       'no source-only preparation or old grant as runtime')
    counter=0;last=None
    def persist(label,value):
        nonlocal counter,last
        need(re_safe(label),'fixed private source event label');counter+=1
        leaf=Path(g['resultRoot'])/('%04d-'%counter+label+'.json');wire=canonical(value)+b'\n'
        need(len(wire)<=1024**2,'complete source event metadata cap; no truncation')
        fd=os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        try:
            view=memoryview(wire)
            while view:n=os.write(fd,view);need(n>0,'private event progress');view=view[n:]
            os.fsync(fd);meta=os.fstat(fd)
            last={'path':str(leaf),'bytes':len(wire),'sha256':hashlib.sha256(wire).hexdigest(),'identity':identity_fields(meta)}
        finally:os.close(fd)
    if args.mode=='execute':
        result=execute(grant_pin,persist)
        need(last is not None,'actual complete execution receipt absent')
        print(canonical(last).decode());return 0 if result['closureKnown']else 1
    # The normal queue runs this parent. Its child alone controls libvirt; only
    # after actual native wait/EOF/FD closure may the parent publish the result.
    modules=backend(g['backendSources']);folder=Path('/run')/('opemos-source-parent-'+g['identity']['nonce'])
    folder.mkdir(mode=0o700);paths=[folder/'controller.stdout',folder/'controller.stderr']
    argv=[sys.executable,'-E','-s','-B',str(Path(__file__).resolve()),'execute',str(path)]
    need(argv==g['fixedControllerArgv'],'exact Root-selected controller argv, never B argv')
    seconds=min(g['wholeDeadlineUnix']-time.time(),g['wholeDeadlineMonotonic']-time.monotonic())
    need(seconds>0,'original parent native deadline')
    record=modules['owned_command'].run_owned_command(argv,None,seconds,paths,stream_limit=1024**2)
    # Seal only exact creator-owned raw leaves; retain original capture full9
    # and separate post-seal observations, never rewrite the measured record.
    record['sealedRawPins']=[]
    for leaf in paths:
        os.chmod(leaf,0o400);pin,body=read_verified(leaf,1024**2,uid=0);record['sealedRawPins'].append(pin)
    native_path=folder/'controller.native.json';wire=canonical(record)+b'\n'
    with native_path.open('xb')as stream:stream.write(wire);stream.flush();os.fsync(stream.fileno())
    native_path.chmod(0o400);native_pin,_=read_verified(native_path,1024**2,uid=0)
    stdout=protected_bytes(record['sealedRawPins'][0])
    need(record['raw'][0]['sha256']==hashlib.sha256(stdout).hexdigest()and len(stdout)==record['raw'][0]['bytes'],
         'complete original captured stdout bytes survived explicit mode sealing')
    execution_pin=strict(stdout);answer=publish(grant_pin,execution_pin,native_pin)
    print(canonical(answer).decode())
    value=strict(protected_bytes(answer,mode=0o444))
    return 0 if value['first']is None and value['secondary']==[]else 1


def identity_fields(meta):
    return {k:getattr(meta,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}


if __name__=='__main__':
    import sys
    sys.exit(main())

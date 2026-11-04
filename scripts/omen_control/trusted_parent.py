import base64, copy, hashlib, importlib.util, json, os, re, stat, sys, time, traceback, types, uuid, zlib
from pathlib import Path
import reference_definitions as L
import runtime_inventory as RI
import produced_resume as RR
NONCE = L.NONCE
SOURCE = L.SOURCE
QUEUE = L.QUEUE
import queue_runtime as QR
PLACEMENT = L.PLACEMENT
BASE = 'steamos-firstboot-' + NONCE
PREVIOUS = BASE + '-e2be9046df54f41ab'
HISTORY = Path('/run/opemos-libvirt-unbooted-history-' + NONCE + '-' + hashlib.sha256(BASE.encode()).hexdigest()[:16])
ROLES = L.ROLES
EXTRA = {'fresh_placement_producer', 'standalone_peer_access_adapter'}
F = L.FIELDS
need = L.need
canon = L.canon
pin = L.pin
read_ref = L.read_ref
ident = L.ident
held_path = L.held_path

def validate_graph(manifest, installed, queue, anchors):
    need(set(manifest['roles']) == set(installed) == ROLES | EXTRA, 'complete exact current14 roles')
    need(hashlib.sha256(canon(manifest)).hexdigest() == anchors['manifestCanonicalSHA256'], 'authenticated exact Source207 manifest canonical content')
    need(manifest['pairedQueue']['sha256'] == anchors['queueSHA256'], 'paired Source207 queue')
    for name, ref in installed.items():
        expected = manifest['roles'][name]
        need(ref==expected,'exact current independently reviewed deployed role full9 '+name)
        i = ref['identity']
        need(ref['path'] == str(Path(anchors['sourceRoot']) / (name + '.py')) and ref['bytes'] == expected['bytes'] <= 65536 and (ref['sha256'] == expected['sha256']), 'current role path/length/hash ' + name)
        need(i['st_uid'] == i['st_gid'] == 0 and stat.S_IMODE(i['st_mode']) == 292 and (i['st_nlink'] == 1) and stat.S_ISREG(i['st_mode']) and (i['st_size'] == ref['bytes']), 'immutable installed Root0444 single regular role ' + name)
    need(len(queue) == 5 and [Path(v['path']).name for v in queue] == anchors['queueNames'], 'full queue five ordered roles')
    need(queue==anchors['currentQueuePrograms'],'all five current Root source placements exact; original deployment remains separate')
    for ref, digest in zip(queue, anchors['queueSHA256s']):
        i = ref['identity']
        need(ref['path'] == str(QR.SOURCE / Path(ref['path']).name) and ref['sha256'] == digest and (i['st_uid'] == i['st_gid'] == 0) and stat.S_IMODE(i['st_mode']) == (0o555 if ref['path'].endswith('.sh') else 0o444) and (i['st_nlink'] == 1) and stat.S_ISREG(i['st_mode']) and (i['st_size'] == ref['bytes']), 'actual paired queue full5')
    return {n: installed[n] for n in sorted(ROLES)}

def historical_spec(parent, original):
    spec = copy.deepcopy(parent['normalizedSpecTemplate'])
    need(spec['approval'] == 'EXACT_PARENT_MINIMAL_PIN' and spec['command'][-1] == 'EXACT_PARENT_FULL_PIN_JSON', 'only two late pin slots')
    spec['approval'] = {k: original[k] for k in ('path', 'bytes', 'sha256')}
    spec['command'][-1] = canon(original).decode()
    return spec

def same_after_retention(before, after):
    need(before['bytes'] == after['bytes'] and before['sha256'] == after['sha256'] and all((before['identity'][k] == after['identity'][k] for k in F if k != 'st_ctime_ns')), 'same retained inode/content; only rename ctime is mutable')

def module_from_held(name, ref):
    raw = read_ref(ref, 65536)
    m = types.ModuleType(name)
    m.__file__ = ref['path']
    sys.modules[name] = m
    try:
        exec(compile(raw, ref['path'], 'exec'), m.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return m

def retain_metadata_file(ref,target,peer,record):
    target = Path(target)
    need(Path(ref['path']).parent == target.parent, 'same directory same-inode metadata retention')
    record('metadata-retention-intent', dict(originalPin=ref, target=str(target), dataRetired=False))
    with peer.RootFiles(target.parent) as f, f.lock(True):
        raw, actual = f.read(Path(ref['path']).name, stat.S_IMODE(ref['identity']['st_mode']))
        need(actual == ref and (not os.path.lexists(target)), 'exact held old leaf and unused retained target')
        __import__('retained_generation').rename_noreplace(f.fd,Path(ref['path']).name,target.name)
        os.fsync(f.fd)
        body, after = f.read(target.name, stat.S_IMODE(ref['identity']['st_mode']))
        same_after_retention(ref, after)
        need(body == raw, 'lossless metadata retention')
    record('metadata-retention-complete', dict(originalPin=ref, retainedPin=after))
    return after

class Run(L.ReferenceRun):

    def metadata_census(self,refs,label,owned_fds=(),runtime_tree=(),publisher_capability=None):
        ops={n:getattr(L,n)for n in('process_snapshot','bounded_text','CensusChurn','mountpoint_identity')};deadline=time.monotonic()+30
        for attempt in range(1,4):
            states=[];failure=None;cuts=[]
            try:
                for _ in range(2):
                    evidence={};states.append(evidence)
                    try:cuts.append(L.bulk_cut(self,refs,evidence,deadline,ops,owned_fds,runtime_tree,publisher_capability))
                    except FileNotFoundError as error:
                        cursor=evidence.get('cursor');need(cursor and str(error.filename).startswith('/proc/'+cursor['pid']+'/'),'exact current proc disappearance only');raise L.CensusChurn('witnessed PID exit',L.vanished_pid(cursor['pid'],error))from error
                need(cuts[0]==cuts[1]and time.monotonic()<deadline,'two actual current-target native cuts inside original30s')
            except BaseException as error:failure=error
            if failure is None:
                self.record_optional('native-census-safety-'+label+'-'+str(attempt),dict(kind='CURRENT_TARGET_SAFETY_CUTS',cuts=cuts,completeCurrentTargetCoverage=True,noTargetUsers=True,diagnosticEnrichmentRequired=False))
            try:L.census_record(self,label,attempt,dict(cuts=states),'FAILED'if failure else'COMPLETE',failure)
            except BaseException as diagnostic_error:
                unavailable=dict(stage=label,round=attempt,type=type(diagnostic_error).__name__,reason=str(diagnostic_error),fullTranscript='UNAVAILABLE_OPTIONAL_DIAGNOSTIC')
                if failure is not None:failure.optionalCensusTranscriptUnavailable=unavailable
                else:
                    if not hasattr(self,'_optional_diagnostics_unavailable'):self._optional_diagnostics_unavailable=[]
                    self._optional_diagnostics_unavailable.append(unavailable)
            if failure:
                positive=any(any(e.get(k)for k in('holders','mappings','cwdRoot','mounts','loops'))for e in states)
                if not isinstance(failure,L.CensusChurn)or positive or attempt==3 or time.monotonic()>=deadline:raise failure
            else:return

    def retain_leaf(self, ref, target):
        return retain_metadata_file(ref,target,self.p,self.record)

    def current_native(self, pre):
        inventory = self.guard()
        unit = self.prior['row']['unit']
        bound = json.loads(self.prior['binding']['value'])
        raw = self.tool(['/usr/bin/systemctl', 'show', unit, '-p', 'Id', '-p', 'LoadState', '-p', 'InvocationID', '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'ControlGroup'], 5)
        manager = dict((line.split('=', 1) for line in raw.decode().splitlines()))
        need(manager == dict(Id=unit, LoadState='loaded', InvocationID=bound['invocation'], ActiveState='failed', SubState='failed', MainPID='0', ControlGroup=''), 'actual original failed invocation with no process/cgroup')
        absent = []
        for path in ['/run/opemos-vfio-' + NONCE, *[str(HISTORY / 'runtime' / n) for n in ('child-grant.json', 'context.json', 'assignment.json')]]:
            try:
                os.lstat(path)
            except FileNotFoundError as e:
                need(e.errno == 2, 'only actual ENOENT')
                absent.append(dict(path=path, error=dict(errno=2, type='FileNotFoundError')))
            else:
                raise RuntimeError('old lease/grant/context/assignment exists: ' + path)
        now = time.time()
        need(pre['observedUnix'] <= now <= pre['observedUnix'] + 30, 'native current after preflight inside30s')
        return dict(kind='ROOT_NORMAL_UNBOOTED_CURRENT_NATIVE_R1', bootID=self.boot, observedUnix=now, unit=manager, domains=[], QEMU=inventory['QEMU'], vfioHolders=inventory['holders'], unknown=inventory['unknown'], absent=absent)

    def finish_continuation(self, parent, prepin):
        pre = json.loads(read_ref(prepin))
        need(pre['preparedAccessPin'] == self.pending and pre['working'] == self.post['working'] and (pre['original'] == self.post['original']) and (pre['queuePrograms'] == self.queue) and (pre['bootID'] == self.boot) and (pre['allOwnedFDsClosed'] is True) and (pre['runtimeAuthorized'] is False), 'actual final preflight lineage')
        native = self.current_native(pre)
        retained = dict(whole=self.history)
        L.verify_enriched_private_history(self, retained, pre, parent)
        with self.p.RootFiles(HISTORY) as f, f.lock(True):
            np = self.prod.put(f, 'current-native.json', native)
        observed = time.time()
        need(pre['observedUnix'] <= native['observedUnix'] <= observed <= pre['observedUnix'] + 30, 'no deadline extension')
        receipt = dict(kind='ROOT_NORMAL_CLOSED_UNBOOTED_PREPARED_CONTINUATION_R1', nonce=NONCE, bootID=self.boot, preparedCandidate=self.c, newJobId=self.newjob, preparedAccessPin=self.pending, preparedDiskPins=self.post, currentPreflightPin=prepin, sourceRoles=self.pins, queuePrograms=self.queue, observedUnix=observed, prior=self.prior, nativeCurrentPin=np)
        with self.p.RootFiles(PLACEMENT) as f, f.lock(True):
            rp = self.prod.put(f, 'closed-unbooted-' + self.a['executionAttempt'][:16] + '.json', receipt)
        parent['unbootedContinuationPin'] = rp
        now = time.time()
        need(now <= pre['observedUnix'] + 30, 'parent within original final window')
        parent.update(issuedUnix=now, startBeforeUnix=min(now + 299, self.a['wholeDeadlineUnix']), wholeDeadlineUnix=min(now + 900, self.a['wholeDeadlineUnix']))
        self.modules['queue_assignment'].execution_job(self.c, parent, self.history)
        return rp

    def make_parent(self, qual, e, codec, now):
        parent = self.parent_design()
        parent.update(kind='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT', RootIssued=True, runtimeAuthorized=True, MODEL_ONLY=False, nonce=NONCE, bootID=self.boot, candidate=self.c, jobId=self.newjob, sourceRoles=self.pins, queuePrograms=self.queue, actualInstalledQueueFull9=self.queue[0], **{k: qual[k] for k in ('sourcePlacementPin', 'placementQualificationPin', 'prequeuePreflightPin')}, preparedAccessPin=self.pending, preparedDiskPins=self.post, splitDiskCapturePins=self.captures, issuedUnix=now, startBeforeUnix=min(now + 299, self.a['wholeDeadlineUnix']), wholeDeadlineUnix=self.a['wholeDeadlineUnix'], postqueueDelegation='ROOT_EXACT_CANONICAL_BINDING_ONLY_R5', priorHistory=e['priorHistory'], priorHistoryCodecPin=codec, workerLockPin=e['workerLockPin'], workerStatePin=e['workerStatePin'], workerLockMode=436, queueStateRoot=str(QUEUE / 'state'), nativeReadOnlyPin=self.native_ref, sudoPin=pin('/usr/bin/sudo', 33554432), workerPythonPin=pin(os.path.realpath('/usr/bin/python3'), 33554432), nativeTools={p: pin(p, 33554432) for p in ('/usr/bin/virt-xml-validate', '/usr/bin/xmllint', '/usr/sbin/losetup', '/usr/bin/mount', '/usr/bin/umount', '/var/lib/opemos-vfio-idle-d3/modprobe', '/var/lib/opemos-vfio-idle-d3/managed_vfio.py')}, installedSchemaReceiptPin=self.a['installedSchemaReceiptPin'], workerArgv=['/usr/bin/python3', str(QR.SOURCE / 'test_queue.py'), '--queue', str(QUEUE / 'state'), 'run'])
        read_ref(parent['installedSchemaReceiptPin'])
        spec = parent['normalizedSpecTemplate']
        spec.update(id=self.newjob, command=['sudo', '-n', '/usr/bin/python3', '-B', self.pins['runtime_entry']['path'], '--parent-pin-json', 'EXACT_PARENT_FULL_PIN_JSON'], files=[{k: self.pins[n][k] for k in ('path', 'bytes', 'sha256')} for n in sorted(self.pins)], libvirt_domain=dict(uuid=self.c['guestUUID'], name=self.c['name'], leaseNonce=NONCE, observer={k: self.pins['libvirt_peer'][k] for k in ('path', 'bytes', 'sha256')}))
        parent['childGrantTemplate'].update(reservationMemory=10737418240, controllerMemory=2147483648, domainMemory=8589934592, noNIC=True, noInstall=True, maxBoots=1, physicalGroup=self.p.GROUP, failureControl='LIBVIRT_AUTODESTROY_CONTROLLER_CONNECTION')
        return parent

    def parent(self):
        self.guard()
        self.retain_metadata()
        e = self.expectation('INSTALLER_BOOT_READY', self.post, self.pending)
        ep = self.record('final-expectation', e)
        qual = self.modules['fresh_placement_producer'].produce(ep, self.seed, self.record)
        q = json.loads(read_ref(qual['placementQualificationPin']))
        now = time.time()
        codec = L.write_prior_history_codec(self, e['priorHistory'])
        parent = self.make_parent(qual, e, codec, now)
        self.finish_continuation(parent, parent['prequeuePreflightPin'])
        pp = self.public('opemos-libvirt-parent-' + NONCE + '.json', parent)
        for name in ('postqueue_issuer', 'runtime_entry'):
            self.modules[name].bind_placement(self.p, parent, pp)
        job = self.modules['postqueue_issuer'].submission_manifest(parent, pp, '/run')
        jp = self.public('opemos-libvirt-job-' + NONCE + '.json', dict(version=1, jobs=[job]))
        self.prod.create_root('/run/opemos-libvirt-runtime-' + NONCE)
        self.control()
        pre = json.loads(read_ref(parent['prequeuePreflightPin']))
        now = time.time()
        need(now < parent['startBeforeUnix'] and now < parent['wholeDeadlineUnix'] and (now - pre['observedUnix'] <= 30), 'original final clock immediately before canonical submission')
        RR.fresh_final_clocks(parent, self.data_parent, pre, parent['prequeuePreflightPin'], now, self.a)
        self._canonical_submit_attempt = dict(jobId=self.newjob, parentPin=pp, manifestPin=jp)
        self.tool(['/usr/bin/sudo', '-n', '-u', 'connor', '/usr/bin/env', 'XDG_RUNTIME_DIR=/run/user/1000', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus', str(QUEUE / 'queue.sh'), '--queue', str(QUEUE / 'state'), 'submit', jp['path']], 15)
        sp = self.record('canonical-submitted', self._canonical_submit_attempt)
        self._canonical_submitted = dict(self._canonical_submit_attempt, submittedPin=sp)
        return L.await_terminal(self, self.newjob, sp, parent['wholeDeadlineUnix'])

    def media(self):
        raise RuntimeError('Source220 forbids format/copy')

Run.copy=Run.media
Run.access_stage=Run.media

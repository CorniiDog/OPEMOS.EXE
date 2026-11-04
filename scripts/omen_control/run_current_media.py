"""Installed normal Root entry for a fresh retained-media generation.

Executable controller code is installed/reviewed once. Each request supplies
protected typed job data. No old session, app-server, review directory, generated
Python body or historical runtime grant is an input.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import zlib
import base64

# Isolated Python omits the script directory. Only the installed, immutable
# Root tree may become an import root; never a candidate/developer checkout.
if __name__ == '__main__':
    here = Path(__file__).absolute().parent
    for node in (here, *here.parents):
        s = os.lstat(node)
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_gid != 0 or s.st_mode & 0o022:
            raise RuntimeError('installed Root controller ancestry')
    s = os.lstat(__file__)
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_gid != 0 or stat.S_IMODE(s.st_mode) != 0o444 or s.st_nlink != 1:
        raise RuntimeError('installed immutable controller entry')
    sys.path.insert(0, str(here))

import libvirt_peer as p
import libvirt_producer as producer
import libvirt_preflight as pre
import libvirt_access as access
from libvirt_native import held, native_child, native_queue_worker
import retained_media as media
import source_contract


def pin(path, cap=67108864):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = p.ident(os.fstat(fd)); h = hashlib.sha256(); n = 0
        p.need(stat.S_ISREG(before['st_mode']) and before['st_nlink'] == 1
               and before['st_size'] <= cap, 'bounded single regular source')
        while b := os.read(fd, 1048576):
            n += len(b); p.need(n <= cap, 'whole input cap'); h.update(b)
        p.need(before == p.ident(os.fstat(fd)) == p.ident(os.lstat(path)), 'full source FD/name epoch')
        return {'path': str(path), 'bytes': n, 'sha256': h.hexdigest(), 'identity': before}
    finally: os.close(fd)


def protected(ref, mode):
    i = ref['identity']
    p.need(i['st_uid'] == i['st_gid'] == 0 and stat.S_ISREG(i['st_mode'])
           and stat.S_IMODE(i['st_mode']) == mode and i['st_nlink'] == 1, 'protected normal input')
    with access.Held(ref['path']) as obj:
        p.need(obj.check() == i, 'protected input ancestry')
        return json.loads(held(ref, 1048576))


def native_module(ref):
    import types
    p.need(ref['sha256'] == 'fd1cc2b458394580a82d08cd5673f67ff6e5f026dbe94129b2950e867f1eebc4',
           'existing independently reviewed readonly native guard')
    module = types.ModuleType('current_readonly_native'); module.__file__ = ref['path']
    exec(compile(held(ref, 65536), ref['path'], 'exec'), module.__dict__)
    return module


def heavy_custody(wrapper, lock_path='/run/user/1000/opemos-heavy.lock', owner_uid=1000):
    """Borrow the actual wrapper ancestor's OFD, never another job's lock.

    The normal Bash wrapper retains its FD across systemd scope execution;
    sudo need not forward it. As in the existing normal recovery lock fence,
    fdinfo identifies the held OFD even after the short-lived flock tool exits.
    Alternate path/UID are only explicit disposable-kernel test inputs. The
    installed entry always calls the fixed normal path and UID1000 defaults.
    """
    source = held(wrapper, 65536)
    i = wrapper['identity']
    p.need(i['st_uid'] == i['st_gid'] == 0 and stat.S_IMODE(i['st_mode']) == 0o555,
           'exact installed normal heavy wrapper')
    fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd); core = p.ident(st)
        p.need(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == owner_uid
               and st.st_nlink == 1 and st.st_size == 0, 'normal empty heavy lock owner/inode')
        chain = []; pid = os.getpid()
        for _ in range(32):
            actor = p.process_snapshot(pid); actor['exe'] = os.readlink('/proc/'+str(pid)+'/exe')
            chain.append(actor)
            p.need(actor['uids'] in ([0]*4, [owner_uid]*4, [owner_uid,0,0,0]),
                   'only actual normal caller/sudo UID ancestry')
            if actor['exe'] == '/usr/bin/bash' and len(actor['argv']) > 1 and actor['argv'][1] == wrapper['path']:
                p.need(actor['uids'] == [owner_uid]*4, 'actual admitted Bash heavy owner'); break
            p.need(actor['ppid'] > 1 and actor['ppid'] != pid, 'heavy wrapper must be a current ancestor')
            pid = actor['ppid']
        else: p.need(False, 'bounded actual heavy wrapper ancestry')
        owner = chain[-1]; matches = []
        for item in Path('/proc/'+str(owner['pid'])+'/fd').iterdir():
            try:
                s = item.stat()
                if (s.st_dev,s.st_ino) != (st.st_dev,st.st_ino): continue
                for line in Path('/proc/'+str(owner['pid'])+'/fdinfo/'+item.name).read_text().splitlines():
                    if not line.startswith('lock:'): continue
                    row = line.split('lock:',1)[1].split()
                    if len(row)<8 or row[1]!='FLOCK' or row[3]!='WRITE': continue
                    major,minor,inode = row[5].split(':')
                    if (int(major,16),int(minor,16),int(inode)) == (os.major(st.st_dev),os.minor(st.st_dev),st.st_ino):
                        matches.append({'fd':int(item.name),'kernelOFDRecord':row})
            except FileNotFoundError: continue
        p.need(len(matches)==1, 'one real heavy-owner inherited FLOCK FD')
        p.need(all(p.ident(os.fstat(fd))[k] == p.ident(os.lstat(lock_path))[k] == core[k]
                   for k in p.CORE+('st_size',)), 'same held/named normal heavy inode')
        for actor in chain:
            now=p.process_snapshot(actor['pid']); now['exe']=os.readlink('/proc/'+str(actor['pid'])+'/exe')
            p.need(now==actor, 'heavy ancestor PID/start/UID/argv/exe/FD lifetime')
        p.need(held(wrapper,65536)==source, 'same installed heavy source after kernel proof')
        return {'sourcePin':wrapper,'lockCore':{k:core[k]for k in p.CORE+('st_size',)},
                'owner':owner,'OFD':matches[0],'ancestry':chain}
    finally: os.close(fd)


class Run:
    def __init__(self, profile_pin, request_pin):
        p.need(os.getuid() == os.geteuid() == 0, 'normal authenticated Root operation')
        self.profile = protected(profile_pin, 0o444)
        self.request = protected(request_pin, 0o400)
        cfg, req = self.profile, self.request
        p.need(cfg['kind'] == 'OPEMOS_INSTALLED_CURRENT_MEDIA_OPERATION_V1'
               and req['kind'] == 'OPEMOS_CURRENT_MEDIA_REQUEST_V1', 'installed code and typed request')
        self.contract_pin = cfg['installedSourceContractPin']
        self.contract = source_contract.validate(cfg['sourceRoles'], cfg['queuePrograms'], self.contract_pin)
        self_pin = self.contract['preparationRoles']['run_current_media']
        p.need(self_pin['path'] == str(Path(__file__).absolute()), 'actual installed entry path')
        held(self_pin, 65536)
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        p.need(req['bootID'] == self.boot and req['installedSourceContractPin'] == self.contract_pin,
               'actual current boot/controller identity')
        self.started = time.time()
        p.need(req['issuedUnix'] <= self.started < req['startBeforeUnix'] <= req['issuedUnix'] + 300,
               'finite genuine Root request')
        p.need(req['startBeforeUnix'] < req['wholeDeadlineUnix'] <= req['issuedUnix'] + 2400,
               'bounded outer operation; child authority remains separately 300/900 seconds')
        p.need(re.fullmatch('[0-9a-f]{32}', req['executionAttempt']) and
               re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', req['jobId']), 'fresh normal execution identifiers')
        self.c = copy.deepcopy(cfg['candidateTemplate'])
        self.c.update(hostBoot=self.boot, jobId=req['jobId'], runtimeAuthorized=False, sourceAccepted=False)
        self.c['lineageNonce'] = self.c['nonce']
        self.c['nonce'] = req['executionAttempt']
        self.c['name'] = 'opemos-libvirt-' + self.c['nonce']
        p.need(self.c['lineageNonce'] == self.contract['guestNonce'] and media.is_adopted(self.c), 'protected retained guest profile')
        p.SOURCE_PLACEMENT_NONCE = self.c['nonce']
        paths = source_contract.operation_paths(self.contract['deployment']['id'], req['executionAttempt'])
        self.c['operationContext'] = {'deploymentId': self.contract['deployment']['id'], 'attempt': req['executionAttempt'], 'paths': paths}
        self.root = Path(paths['operationRoot'])
        self.mount = Path(paths['mountRoot'])
        self.io = Path(paths['ioRoot'])
        self.c.update(run=str(self.io / 'run'), output=str(self.io / 'output'))
        self.loop = None; self.loop_fd = None; self.mounted = False; self.submitted = False
        self.sequence = 0; self.effects = []; self.last_job = None; self.diagnostic_errors = []
        self.heavy = heavy_custody(cfg['queuePrograms'][2])
        self.placement_root = Path(paths['placementRoot'])
        self.native = native_module(cfg['nativeReadOnlyPin'])
        # Read/admit before the first operation namespace or mount effect.
        self.guard_native()
        for path in (self.root, self.mount, self.io, self.placement_root):
            p.need(not os.path.lexists(path), 'fresh owned namespace, unknown existing data preserved ' + str(path))
        producer.create_root(str(self.root))

    def record(self, label, value):
        if label in ('placement-seed', 'retained-media-current-custody'):
            root, name = self.placement_root, label + '.json'
        else:
            root = self.root; self.sequence += 1
            name = str(self.sequence).zfill(3) + '-' + label + '.json'
        with p.RootFiles(root) as files, files.lock(True):
            return producer.put(files, name, value)

    def diagnostic(self, label, value):
        try: return self.record(label,value)
        except Exception as error:
            self.diagnostic_errors.append({'label':label,'type':type(error).__name__,'reason':str(error)})
            return None

    def heavy_guard(self):
        current=heavy_custody(self.profile['queuePrograms'][2])
        p.need(current['owner']==self.heavy['owner'] and current['OFD']==self.heavy['OFD']
               and current['lockCore']==self.heavy['lockCore'], 'same admitted heavy owner for this entire operation')

    def loop_role(self):
        if self.loop_fd is None: return None
        return {'fd': self.loop_fd, 'path': self.loop,
                'backing': self.c['installer']['backing']['path']}

    def tool(self, argv, seconds=30, stage=True, worker=False):
        # No command or executable body comes from the request/candidate.
        ref = self.profile['nativeTools'][argv[0]]
        deadline = self.request['startBeforeUnix'] if stage else self.request['wholeDeadlineUnix']
        self.heavy_guard()
        try:
            end=min(deadline,time.time()+seconds)
            result = native_queue_worker(argv,end,ref) if worker else native_child(argv,end,ref,loop=self.loop_role())
        except BaseException as error:
            value=getattr(error,'nativeChildEvidence',getattr(error,'evidence',None))
            if value is not None:self.diagnostic('native-'+Path(argv[0]).name+'-FIRST',value)
            raise
        self.diagnostic('native-' + Path(argv[0]).name, result)
        if result['numeric'] != 0:
            error=p.Refused('normal native operation failed: '+argv[0]+' exit='+str(result['numeric'])
                            +' stderr='+result.get('stderr','')[:65536])
            error.nativeEvidence=result
            raise error
        return result['stdout']

    def guard_native(self):
        self.native.Devices().guards()
        inventory = self.native.fd_inventory()
        p.need(inventory['unknown'] == inventory['holders'] == inventory['QEMU'] == [],
               'actual current no QEMU/VFIO/unknown holder')
        import libvirt
        conn = libvirt.openReadOnly('qemu:///system')
        try: p.need(conn is not None and conn.getURI() == 'qemu:///system' and conn.listAllDomains(0) == [],
                    'actual empty system libvirt')
        finally:
            if conn is not None: p.need(conn.close() == 0, 'readonly libvirt connection close')

    def private_queue(self):
        """Same-byte immutable private reader. Never SQL-open the original as Root."""
        original = pin(Path(self.profile['queueStateRoot']) / 'queue.sqlite3')
        family = pre.quiet_db_family(original)
        private = self.root / ('private-' + str(self.sequence + 1) + '.sqlite3')
        raw = held(original, 67108864)
        fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        try:
            os.fchmod(fd, 0o400); view = memoryview(raw)
            while view:
                n = os.write(fd, view); p.need(n > 0, 'private snapshot write progress'); view = view[n:]
            os.fsync(fd)
        finally: os.close(fd)
        pp = pin(private)
        p.need(pre.quiet_db_family(original) == family, 'whole original family stayed exact during private capture')
        index = self.record('private-index', {'kind': 'ROOT_CURRENT_EMPTY_WAL_SNAPSHOT_INDEX',
                            'originalPin': original, 'privatePin': pp, 'sqlOnOriginal': False,
                            'knownClosed': True, 'originalFamily': family})
        from held_history_reader import read_private_history
        values, history = pre.private_values(original, pp, index, read_private_history)
        p.need(all(r['finished'] is not None and r['state'] in
                   ('passed', 'failed', 'timed_out', 'output_limit', 'blocked') for r in values['rows']),
               'all prior canonical jobs terminal before media preparation')
        for row in values['rows']:
            result = json.loads(row['result']) if row['result'] else {}
            p.need(result.get('terminalLifecycle', {}).get('reservationRetained') is not True,
                   'no retained reservation, including failed jobs')
            if json.loads(row['spec']).get('libvirt_domain') is not None:
                p.need(result.get('terminalLifecycle', {}).get('phase') == 'CLOSED'
                       and result['terminalLifecycle']['reservationRetained'] is False,
                       'actual canonical libvirt closure; historical unknowns remain data')
        pre.empty_pool(values['rows'])
        return values, history, {'originalQueueDBPin': original, 'privateQueueDBPin': pp,
                                 'privateQueueIndexPin': index}

    def capture_disk(self, ref, role):
        started = time.time(); initial = set(os.listdir('/proc/self/fd'))
        actual = pin(ref['path'], ref['bytes'])
        p.need(actual == ref, 'entire current ' + role + ' bytes/hash/full9')
        proof = {'kind': 'ROOT_CURRENT_HELD_INPROCESS_DISK_CAPTURE', 'bootID': self.boot,
                 'before': ref, 'after': actual, 'fullPin': actual, 'bytesRead': actual['bytes'],
                 'EOF': True, 'readOnly': True, 'FDSetRestored': initial == set(os.listdir('/proc/self/fd')),
                 'children': [], 'childCreated': False, 'sameProcessRead': True,
                 'startedUnix': started, 'finishedUnix': time.time()}
        if role == 'carrier':
            custody = {}; pre.measured(ref, ref['bytes'], False, custody)
            proof['carrierMountCustody'] = custody
        return self.record('capture-' + role, proof)

    def public(self, name, value):
        paths = source_contract.candidate_paths(self.c)
        p.need(name in (Path(paths['parentPath']).name, Path(paths['jobPath']).name), 'two bound public roles')
        raw = p.canon(value); p.need(len(raw) <= 1048576, 'normal public cap')
        with access.Held('/run') as parent:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o444, dir_fd=parent.fd)
            try:
                os.fchmod(fd, 0o444); view = memoryview(raw)
                while view:
                    n = os.write(fd, view); p.need(n > 0, 'public write progress'); view = view[n:]
                os.fsync(fd)
            finally: os.close(fd)
            os.fsync(parent.fd)
        return pin(Path('/run') / name, 1048576)

    def prepare(self):
        values, history, private = self.private_queue()
        p.need(all(r['id'] != self.c['jobId'] for r in values['rows']), 'never rearm or replay an existing job')
        queue = __import__('queue_assignment').load_queue(self.profile['queuePrograms'][0])
        leases = [p.historical_lease_provenance(str(x), values['rows'], values['bindings'], queue, self.boot)
                  for x in sorted(Path('/run').glob('opemos-vfio-*'))]
        p.verify_historical_lease_set(leases, values['rows'], values['bindings'], queue, self.boot)
        for path in (self.mount, self.io, self.placement_root): producer.create_root(str(path))
        backing = self.c['installer']['backing']
        p.need(pin(backing['path'], backing['bytes']) == backing, 'current authenticated retained backing')
        for path in Path('/sys/class/block').glob('loop*/loop/backing_file'):
            p.need(path.read_text().strip() != backing['path'], 'no existing loop adoption or duplicate backing consumer')
        self.diagnostic('readonly-loop-intent', {'backing': backing, 'mount': str(self.mount), 'effects': []})
        self.loop = self.tool(['/usr/sbin/losetup', '--find', '--show', '--read-only', '--nooverlap', backing['path']]).strip()
        p.need(re.fullmatch('/dev/loop[0-9]+', self.loop), 'one actual owned loop')
        self.loop_fd = os.open(self.loop, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        p.need(stat.S_ISBLK(os.fstat(self.loop_fd).st_mode), 'held owned loop block node')
        sysloop = Path('/sys/class/block') / Path(self.loop).name
        p.need((sysloop / 'loop/backing_file').read_text().strip() == backing['path']
               and (sysloop / 'ro').read_text().strip() == '1', 'actual readonly backing association')
        self.effects.append({'loop': self.loop, 'backing': backing})
        self.tool(['/usr/bin/mount', '-t', 'ext4', '-o', 'ro,noload,nodev,nosuid,noexec', self.loop, str(self.mount)])
        self.mounted = media.owned_mount(self.mount, self.loop)
        p.need(self.mounted, 'successful mount must exist in kernel mount table')
        self.effects.append({'mount': str(self.mount), 'loop': self.loop})
        w = self.mount / 'working.raw'; wi = p.ident(os.lstat(w))
        self.c['working'] = {'path': str(w), 'bytes': media.RAW_BYTES, 'sha256': media.RAW_SHA, 'identity': wi}
        self.c['installer']['bootCopy'] = self.c['working']
        self.c['installer'].pop('currentCustody', None); self.c['installer'].pop('currentCustodyPin', None)
        captures = {k: self.capture_disk(self.c[k], k) for k in ('original', 'working')}
        captures.update({k: self.capture_disk(self.c['installer'][field], k)
                         for k, field in [('carrier', 'carrierSource'), ('retainedR66', 'retainedR66')]})
        codec = self.record('prior-history-codec', {'value': {'data': base64.b64encode(zlib.compress(p.canon(values))).decode()}})
        state = Path(self.profile['queueStateRoot']); lock = pin(state / 'worker.lock')
        now = time.time()
        e = {'kind': 'ROOT_LIBVIRT_R4_PREFLIGHT_EXPECTATION', 'RootAdopted': True,
             'purpose': 'INSTALLER_ACCESS_STAGE', 'nonce': self.c['nonce'], 'bootID': self.boot,
             'candidate': self.c, 'issuedUnix': self.request['issuedUnix'],
             'startBeforeUnix': self.request['startBeforeUnix'],
             'wholeDeadlineUnix': min(now + 900, self.request['wholeDeadlineUnix']),
             'nativeReadOnlyPin': self.profile['nativeReadOnlyPin'],
             'historyReaderPin': self.profile['sourceRoles']['held_history_reader'],
             'splitDiskCapturePins': {k: captures[k] for k in ('original', 'working')},
             'preparedAccessPin': None, 'queuePrograms': self.profile['queuePrograms'],
             'sourceRoles': self.profile['sourceRoles'], 'installedSourceContractPin': self.contract_pin,
             'installerContract': self.c['installer'],
             'installerSourceCapturePins': {k: captures[k] for k in ('carrier', 'retainedR66')},
             'workerLockPin': lock, 'workerStatePin': {'path': str(state), 'identity': p.ident(os.lstat(state))},
             'workerLockMode': 0o664, 'priorLeases': leases,
             'unusedPaths': [self.c['run'], self.c['output'], '/run/opemos-vfio-' + self.c['nonce'],
                             '/run/opemos-libvirt-results-' + self.c['nonce']],
             'rootBoundaryPin': {'path': '/', 'identity': p.ident(os.lstat('/'))},
             'priorHistory': {'counts': history['counts'], 'bytes': history['rawBytes'], 'sha256': history['rawSHA256']},
             'priorHistoryCodecPin': codec, **private}
        paths = source_contract.candidate_paths(self.c)
        e['unusedPaths'] += [paths['parentPath'], paths['jobPath'], paths['runtimeRoot']]
        seed = copy.deepcopy(self.profile['placementSeedTemplate'])
        seed.update(nonce=self.c['nonce'], boot=self.boot, original=self.c['original'], working=self.c['working'],
                    backing=backing, operationRoot=str(self.root), operationContext=self.c['operationContext'],
                    lineageNonce=self.c['lineageNonce'], jobId=self.c['jobId'], run=self.c['run'], output=self.c['output'])
        ep = self.record('initial-expectation', e)
        import current_media_preparation
        prepared = current_media_preparation.prepare(ep, seed, self.contract['originCopyReceiptPin'], self.record)
        final = protected(prepared['expectationPin'], 0o400)
        import fresh_media_parent
        result = fresh_media_parent.produce(prepared, final, self.contract_pin, self.c['jobId'], self.public)
        producer.create_root(source_contract.candidate_paths(self.c)['runtimeRoot'])
        return result

    def execute(self):
        result = self.prepare()
        self.guard_native()
        wrapper = self.profile['queuePrograms'][3]['path']
        self.tool(['/usr/bin/sudo', '-n', '-u', 'connor', '/usr/bin/env',
                   'XDG_RUNTIME_DIR=/run/user/1000', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus',
                   wrapper, '--queue', self.profile['queueStateRoot'], 'submit', result['manifestPin']['path']], 15)
        self.submitted = True; self.diagnostic('canonical-submitted', result)
        result['submitted'] = True
        # Normal CLI's worker owns start/admission and every terminal transition.
        self.tool(['/usr/bin/sudo', '-n', '-u', 'connor', '/usr/bin/env',
                   'XDG_RUNTIME_DIR=/run/user/1000', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus',
                   'OPEMOS_QUEUE_HEAVY_ENTRY=1','OPEMOS_QUEUE_HEAVY_FD=9',
                   '/usr/bin/python3', self.profile['queuePrograms'][0]['path'],
                   '--queue', self.profile['queueStateRoot'], 'run'], 1000, stage=False, worker=True)
        status = self.tool(['/usr/bin/sudo', '-n', '-u', 'connor', '/usr/bin/env',
                            'XDG_RUNTIME_DIR=/run/user/1000', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus',
                            wrapper, '--queue', self.profile['queueStateRoot'], 'status', '--job-id', self.c['jobId']],
                           15, stage=False)
        status = json.loads(status); self.last_job = status['job']
        p.need(status['kind'] == 'NORMAL_QUEUE_EXACT_JOB_STATUS_V1' and self.last_job['id'] == self.c['jobId'],
               'actual normal exact-job result')
        self.diagnostic('actual-job-result', status)
        result['actualJob'] = status
        p.need(self.last_job['finished'] is not None and self.last_job['state'] == 'passed',
               'actual VM job did not pass; retain full job/FIRST instead of a success flag')
        return result

    def close_current_mount(self):
        """Only this operation's readonly mount/loop, after actual normal closure."""
        if self.loop is None: return
        self.guard_native()
        values, _, _ = self.private_queue()
        if self.submitted:
            rows = [r for r in values['rows'] if r['id'] == self.c['jobId']]
            p.need(len(rows) == 1, 'submitted job remains in canonical history')
            life = json.loads(rows[0]['result'])['terminalLifecycle']
            p.need(rows[0]['finished'] is not None and life['phase'] == 'CLOSED'
                   and life['reservationRetained'] is False, 'no mount teardown before normal terminal release')
        root = Path('/sys/class/block') / Path(self.loop).name
        p.need((root / 'loop/backing_file').read_text().strip() == self.c['installer']['backing']['path']
               and (root / 'ro').read_text().strip() == '1', 'exact own readonly loop before cleanup')
        # Non-lazy umount refuses a real user; never detach a busy/foreign mount.
        if media.owned_mount(self.mount, self.loop):
            self.tool(['/usr/bin/umount', str(self.mount)], 15, stage=False)
            self.mounted = False
        p.need((root / 'loop/backing_file').read_text().strip() == self.c['installer']['backing']['path']
               and (root / 'ro').read_text().strip() == '1', 'own association after unmount, before detach')
        if self.loop_fd is not None:
            os.close(self.loop_fd); self.loop_fd = None
        # An earlier detach may have requested autoclear: last-reference close can finish it.
        # Never issue detach against a now absent or reused loop association.
        if (root / 'loop/backing_file').exists():
            p.need((root / 'loop/backing_file').read_text().strip() == self.c['installer']['backing']['path']
                   and (root / 'ro').read_text().strip() == '1', 'same own association after held FD close')
            self.tool(['/usr/sbin/losetup', '--detach', self.loop], 15, stage=False)
        p.need(not (root / 'loop/backing_file').exists(), 'own loop detached')
        p.need(not media.owned_mount(self.mount, self.loop), 'actual own mount gone')
        p.need(pin(self.c['installer']['backing']['path'], self.c['installer']['backing']['bytes'])
               == self.c['installer']['backing'], 'entire retained backing unchanged after operation')
        self.diagnostic('current-media-closed', {'loop': self.loop, 'mount': str(self.mount),
                    'retainedMediaUnchanged': True, 'oldLeaseOrACLRestorationClaimed': False})
        self.loop = None


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--profile-pin-json', required=True)
    requests = ap.add_mutually_exclusive_group(required=True)
    requests.add_argument('--request-pin-json'); requests.add_argument('--request-stdin', action='store_true')
    requests.add_argument('--observe-boot', action='store_true'); args = ap.parse_args()
    profile_pin = json.loads(args.profile_pin_json)
    if args.observe_boot:
        cfg = protected(profile_pin, 0o444)
        p.need(cfg['kind'] == 'OPEMOS_INSTALLED_CURRENT_MEDIA_OPERATION_V1', 'installed operation')
        contract = source_contract.validate(cfg['sourceRoles'], cfg['queuePrograms'], cfg['installedSourceContractPin'])
        held(contract['preparationRoles']['run_current_media'], 65536)
        print(p.canon({'kind': 'CURRENT_MEDIA_NATIVE_BOOT_OBSERVATION',
                      'bootID': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                      'observedUnix': time.time(), 'effects': []}).decode(), flush=True)
        return
    if args.request_stdin:
        cfg = protected(profile_pin, 0o444)
        raw = sys.stdin.buffer.read(65537); p.need(len(raw) <= 65536, 'typed request cap')
        data = json.loads(raw)
        p.need(set(data) == {'executionAttempt', 'jobId'}
               and re.fullmatch('[0-9a-f]{32}', data['executionAttempt'])
               and re.fullmatch('[A-Za-z0-9_.-]{1,80}', data['jobId']), 'data only; no executable/candidate host commands')
        now = time.time()
        request = {'kind': 'OPEMOS_CURRENT_MEDIA_REQUEST_V1', **data,
                   'installedSourceContractPin': cfg['installedSourceContractPin'],
                   'bootID': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                   'issuedUnix': now, 'startBeforeUnix': now + 299, 'wholeDeadlineUnix': now + 2400}
        root = '/run/opemos-current-media-requests'
        if not os.path.lexists(root): producer.create_root(root)
        with p.RootFiles(root) as files, files.lock(True):
            request_pin = producer.put(files, data['executionAttempt'] + '.json', request)
    else: request_pin = json.loads(args.request_pin_json)
    run = Run(profile_pin, request_pin)
    first = None
    try: result = run.execute()
    except BaseException as error:
        first = error
        try: run.record('FIRST', {'type': type(error).__name__, 'reason': str(error), 'effects': run.effects,
                                 'native':getattr(error,'nativeEvidence',None),
                                 'nativeChildEvidence':getattr(error,'nativeChildEvidence',getattr(error,'evidence',None)),
                                 'actualJob':run.last_job,'diagnosticErrors':run.diagnostic_errors})
        except BaseException as diagnostic: error.optionalDiagnosticError = repr(diagnostic)
        raise
    finally:
        try: run.close_current_mount()
        except BaseException as close_error:
            if first is not None:
                first.currentMountClosureUnknown = repr(close_error)
                try: run.record('closure-UNKNOWN', {'first': str(first), 'closure': str(close_error), 'effects': run.effects})
                except BaseException: pass
            else: raise
        finally:
            if run.loop_fd is not None: os.close(run.loop_fd); run.loop_fd = None
    print(p.canon(result).decode(), flush=True)


if __name__ == '__main__': main()

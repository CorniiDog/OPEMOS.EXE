import copy
#!/usr/bin/env python3
"""Finite, file-driven test queue. Runs approved commands; grants no guest authority."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
import uuid

GIB = 1024 ** 3
DEFAULT_CPUS = list(range(10))
DEFAULT_RAM = 32 * GIB
TERMINAL = {"passed", "failed", "timed_out", "blocked", "unknown", "output_limit"}
MAX_JOBS = 256
MAX_LOG = 64 * 1024 ** 2
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def file_pin(path):
    path = Path(path).absolute()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        import stat
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), f"Not a regular input: {path}")
        require(before.st_size <= 8 * 1024 ** 2, "Queue inputs/approvals must be <=8MiB; pin large build assets in the approved runner")
        digest = hashlib.sha256()
        while block := os.read(fd, 1024 * 1024):
            digest.update(block)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns), f"Input changed during read: {path}")
        return {"path": str(path), "bytes": before.st_size, "sha256": digest.hexdigest()}
    finally:
        os.close(fd)


def memory(value):
    if type(value) is int:
        require(value > 0, "Memory must be positive")
        return value
    require(type(value) is str, "Memory must be an integer or size string")
    match = re.fullmatch(r"([1-9][0-9]*)(B|MiB|GiB)?", value)
    require(match is not None, "Use bytes, MiB or GiB (e.g. 6GiB)")
    return int(match[1]) * {None: 1, "B": 1, "MiB": 1024 ** 2, "GiB": GIB}[match[2]]


def connect(root):
    root = Path(root).absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not root.is_symlink() and root.stat().st_uid == os.getuid(), "Queue root must be owned, non-symlink")
    db = sqlite3.connect(root / "queue.sqlite3", timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.executescript("""
      CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS pool_unit_bindings (job_id TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY, spec TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
        cpus TEXT, unit TEXT, started REAL, finished REAL, result TEXT);
    """)
    return root, db


def config(db):
    row = db.execute("SELECT value FROM config WHERE id=1").fetchone()
    require(row is not None, "Initialize the queue first")
    return json.loads(row[0])


NVIDIA_RESOURCE = 'omen-iommu-group-1'
NVIDIA_TARGET_FIELDS = {'instance', 'guestBootID', 'kernelRelease', 'kernelSHA256',
                        'gpuUUID', 'driverVersion'}
NVIDIA_PROOF_CHECKS = {'moduleLoaded', 'matchingKernel', 'guestGPUUUID',
                      'driverVersion', 'guestDriverQuerySucceeded'}


def normalize_nvidia_requirement(value, deps, success):
    require(type(value) is dict and set(value) ==
            {'prerequisite', 'target', 'producerSHA256', 'receiptPath'},
            'Exact optional NVIDIA readiness contract')
    require(value['prerequisite'] in deps and success is True,
            'NVIDIA readiness requires explicit successful predecessor')
    target = value['target']
    require(type(target) is dict and set(target) == NVIDIA_TARGET_FIELDS and
            all(type(x) is str and 0 < len(x) <= 256 for x in target.values()),
            'Exact same guest/boot/kernel/GPU/driver target')
    for x in (target['kernelSHA256'], value['producerSHA256']):
        require(type(x) is str and re.fullmatch('[0-9a-f]{64}', x), 'Full source/kernel SHA')
    require(re.fullmatch('/run/opemos-nvidia-readiness-[0-9a-f]{32}/receipt.json', value['receiptPath']),
            'Exact existing Root producer nonce scope; no arbitrary reader')
    return value


def nvidia_readiness_proof(spec):
    """Read-only. No proof, no reservation, no signal or guest operation.

    A ready receipt attests a live same-guest continuity interval, not a completed
    VM or historical build. Its Root producer must hold that guest's lease.
    """
    import stat
    req = spec.get('nvidia_readiness')
    if req is None:
        return None
    normalize_nvidia_requirement(req, spec['depends_on'], spec['requires_success'])
    fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
              'st_size','st_mtime_ns','st_ctime_ns')
    identity = lambda s: tuple(getattr(s, k) for k in fields)
    fds = []
    links = []
    try:
        path = Path(req['receiptPath'])
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        fds.append(fd)
        for name in path.parts[1:-1]:
            parent = fds[-1]
            meta = os.fstat(parent)
            require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and
                    not meta.st_mode & 0o022, 'Protected Root receipt ancestry')
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            fds.append(child)
            links.append((parent, name, child, identity(os.fstat(child))))
        parent = fds[-1]
        receipt_parent = parent
        ps = os.fstat(parent)
        require(ps.st_uid == ps.st_gid == 0 and stat.S_IMODE(ps.st_mode) == 0o755,
                'Root producer public-read-only scope0755')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        fds.append(fd)
        first = os.fstat(fd)
        require(stat.S_ISREG(first.st_mode) and first.st_uid == first.st_gid == 0 and
                first.st_nlink == 1 and stat.S_IMODE(first.st_mode) == 0o444 and
                0 < first.st_size <= 65536, 'Root0444 bounded single-link readiness receipt')
        raw = bytearray()
        while block := os.read(fd, 4096):
            raw.extend(block)
            require(len(raw) <= 65536, 'Complete readiness receipt cap')
        require(identity(first) == identity(os.fstat(fd)) ==
                identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                'Whole receipt held/named full9 stability')
        def unique(pairs):
            out = {}
            for k, v in pairs:
                require(k not in out, 'Duplicate readiness field')
                out[k] = v
            return out
        proof = json.loads(raw, object_pairs_hook=unique)
        require(bytes(raw) == (canonical(proof) + '\n').encode() and set(proof) ==
                {'kind','producerSHA256','target','hostBootID','issuedMonotonic',
                 'expiresMonotonic','checks','hostProcess','continuityHeld','gpuResource'},
                'Exact whole canonical readiness producer schema')
        require(proof['kind'] == 'ROOT_CURRENT_SAME_GUEST_NVIDIA_READY' and
                proof['producerSHA256'] == req['producerSHA256'] and
                proof['target'] == req['target'] and proof['continuityHeld'] is True and proof['gpuResource'] == NVIDIA_RESOURCE,
                'Exact admitted producer/same guest/kernel/GPU/driver; no build or PCI substitution')
        require(proof['hostBootID'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'Current same-host boot')
        now = time.monotonic()
        issued, expires = proof['issuedMonotonic'], proof['expiresMonotonic']
        require(type(issued) in (int,float) and type(expires) in (int,float) and
                0 <= now - issued < 30 and issued <= now < expires <= issued + 30,
                'Current readiness interval <=30s, not historical passed dependency')
        require(type(proof['checks']) is dict and set(proof['checks']) == NVIDIA_PROOF_CHECKS and
                all(v is True for v in proof['checks'].values()), 'All guest driver readiness facts')
        process = proof['hostProcess']
        require(type(process) is dict and set(process) == {'pid','start','uid','cmdlineSHA256'} and
                type(process['pid']) is int and process['pid'] > 0 and
                type(process['start']) is int and process['start'] > 0 and
                type(process['uid']) is int and process['uid'] >= 0 and
                re.fullmatch('[0-9a-f]{64}', process['cmdlineSHA256']), 'Exact positive VM principal')
        proc = Path('/proc') / str(process['pid'])
        pfd = os.open(proc, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        fds.append(pfd)
        def read_proc(name):
            f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=pfd)
            try:
                b = bytearray()
                while x := os.read(f, 4096):
                    b.extend(x)
                    require(len(b) <= 65536, 'Bounded live principal field')
                return bytes(b)
            finally:
                os.close(f)
        def check_process():
            parts = read_proc('stat').rsplit(b')', 1)[1].split()
            require(int(parts[19]) == process['start'] and parts[0] not in (b'Z',b'X') and
                    os.fstat(pfd).st_uid == process['uid'] and
                    hashlib.sha256(read_proc('cmdline')).hexdigest() == process['cmdlineSHA256'],
                    'Same live original VM process, never gone/reused/zombie')
        check_process()
        for parent, name, child, ident in links:
            require(identity(os.fstat(child)) == ident ==
                    identity(os.stat(name,dir_fd=parent,follow_symlinks=False)), 'Root ancestry changed')
        require(identity(first) == identity(os.fstat(fd)) ==
                identity(os.stat(path.name,dir_fd=receipt_parent,follow_symlinks=False)),
                'Readiness changed before dispatch')
        check_process()
        require(time.monotonic() < expires, 'Readiness expired during principal validation')
        return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                'identity':list(identity(first)), 'expiresMonotonic':expires}
    finally:
        first_close = None
        for fd in reversed(fds):
            try: os.close(fd)
            except BaseException as error:
                if first_close is None: first_close = error
        if first_close is not None: raise first_close


def nvidia_wait_reason(spec):
    if 'nvidia_readiness' not in spec:
        return None
    try:
        nvidia_readiness_proof(spec)
    except (ValueError, OSError, KeyError, IndexError, TypeError) as error:
        return {'kind':'NVIDIA_READINESS_WAIT','reason':str(error),'errorType':type(error).__name__,
                'reserved':False,'accepted':False,'retryVM':False}
    return None


GPU_GROUP_OBSERVER_SOURCE = '"""Finite Root READONLY VFIO lease inventory. No creates, SQL, signals or cleanup."""\nimport os,sys,json,stat,time,re,hashlib,fcntl,types\nfrom pathlib import Path\nfrom contextlib import ExitStack\nGROUP=\'omen-iommu-group-1\'\nLEGACY_NONCE=\'77d65157c8f8498db153fba91475f1ff\'\nLEGACY_JOB=\'steamos3828-ab-autorecovery-r4-77d65157c8f8\'\nLEGACY_TEST=\'opemos-vfio-native-test-\'+LEGACY_NONCE+\'-r2\'\nLEGACY_REVIEW=\'opemos-vfio-native-review-\'+LEGACY_NONCE+\'.py\'\nLEGACY_MODULE_SHA=\'09a859f94267748cee5a7715fd4e5649b2e067fdaa43123e91c077fcf412729a\'\nLEGACY_MODULE_BYTES=40315\nMEMBERS=[\'0000:00:01.0\',\'0000:01:00.0\',\'0000:01:00.1\',\'0000:01:00.2\',\'0000:01:00.3\']\nFIELDS=(\'st_dev\',\'st_ino\',\'st_mode\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\')\ndef need(v,why):\n if not v:raise ValueError(why)\ndef ident(s):return {k:getattr(s,k) for k in FIELDS}\ndef core(s):return tuple(getattr(s,k) for k in FIELDS[:6])\ndef unique(pairs):\n out={}\n for k,v in pairs:need(k not in out,\'duplicate field\');out[k]=v\n return out\ndef complete_libvirt_closed(state,recovered=None):\n closed=state.get(\'currentDisposition\')\n if type(closed)is dict and type(closed.get(\'currentClosure\'))is dict and closed[\'currentClosure\'].get(\'newCurrentObservationOnly\')is True:\n  need(recovered is not None,\'recovery CLOSED requires authenticated current implementation\');return recovered(state)\n flat=type(closed)is dict and all(closed.get(k)is True for k in(\'domainAbsent\',\'originalPIDStartAbsent\',\'cgroupEmpty\',\'VFIOFDsAbsent\',\'hostRestored\'))and (closed.get(\'unknown\')is False or(type(closed.get(\'unknown\'))is list and closed[\'unknown\']==[]))\n if flat:return True\n need(type(closed)is dict and set(closed)=={\'currentClosure\',\'first\',\'secondary\',\'historicalQMPClosed\',\'noHistoricalCloseFabrication\'}and closed[\'noHistoricalCloseFabrication\']is True and closed[\'historicalQMPClosed\']is None and closed[\'secondary\']==[],\'exact genuine nested libvirt diagnostic disposition, historical QMP remains unknown\')\n cc=closed[\'currentClosure\'];need(type(cc)is dict and all(cc.get(k)is True for k in(\'known\',\'FDsClosed\',\'domainAbsent\',\'hostRestored\',\'preservePrimary\',\'noSignalOrSysfsEffect\'))and cc.get(\'leaseHeld\')is False and cc.get(\'secondary\')==[]and cc.get(\'historicalQMPClosed\')is None,\'nested complete current domain/FD/host closure\')\n actions=cc.get(\'actions\');need(type(actions)is list and 0<len(actions)<=64 and all(type(x)is dict and set(x)=={\'role\',\'value\'}and type(x[\'role\'])is str for x in actions),\'finite typed native closure actions\');roles=[x[\'role\']for x in actions];need(len(roles)==len(set(roles)),\'unique closure action roles\');values={x[\'role\']:x[\'value\']for x in actions}\n proof=values.get(\'independent-current-domain-host-closure\');need(type(proof)is dict and all(proof.get(k)is True for k in(\'known\',\'ACLRestored\',\'VFIOFDsAbsent\',\'cgroupEmpty\',\'domainAbsent\',\'hostRestored\',\'originalPIDStartAbsent\',\'currentDispositionOnly\',\'originalFullHashVerified\'))and proof.get(\'unknown\')==[]and proof.get(\'historicalQMPClosed\')is None and proof.get(\'controllerWaitpidClaimed\')is False and cc.get(\'closure\')==proof,\'authenticated complete independent current closure/action equality, no historical QMP fabrication\')\n acl=values.get(\'six-ACL-restoration\');need(type(acl)is list and len(acl)==6 and len({x.get(\'path\')for x in acl if type(x)is dict})==6 and all(type(x)is dict and x.get(\'restored\')is True and type(x.get(\'path\'))is str and x[\'path\'].startswith(\'/\')and x.get(\'identity\',{}).get(\'st_uid\')==x.get(\'identity\',{}).get(\'st_gid\')==0 for x in acl),\'exact six distinct Root restored ACL paths\')\n for role in(\'control-connection\',\'observer-connection\'):\n  v=values.get(role);need(type(v)is dict and type(v.get(\'numeric\'))is int and v[\'numeric\']==0,\'positive native libvirt connection close\')\n change=cc.get(\'FDComparison\',{}).get(\'changes\');need(change=={\'added\':[],\'removed\':[],\'replaced\':[]},\'native role FD comparison closed without unknown changes\')\n need(state.get(\'restored\')is True and state.get(\'changed\')==[],\'nested closed native lease restored unchanged\')\n return True\n\nCURRENT_CONTEXT={}\ndef observe(run=\'/run\',sysroot=\'/sys\',procroot=\'/proc\',implementation_definition=None):\n global CURRENT_CONTEXT\n need(os.getuid()==os.geteuid()==0,\'genuine Root readonly lease observer\')\n started=time.monotonic();end=started+8;total=0;rows=[];held=[];nonleases=[];records=[];testBoots=[];libvirtBoots=[]\n def clock():need(time.monotonic()<end,\'finite GPU lease observation8s\')\n with ExitStack() as stack:\n  def fd(path,flags,parent=None):\n   f=os.open(path,flags|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);stack.callback(os.close,f);return f\n  root=fd(run,os.O_RDONLY|os.O_DIRECTORY);rootcore=core(os.fstat(root))\n  need(os.fstat(root).st_uid==os.fstat(root).st_gid==0 and not os.fstat(root).st_mode&0o022,\'Root protected run parent\')\n  names=sorted(n for n in os.listdir(root) if n.startswith(\'opemos-vfio-\'))\n  need(len(names)<=66 and all(re.fullmatch(\'opemos-vfio-[0-9a-f]{32}\',n) or n in (LEGACY_TEST,LEGACY_REVIEW) for n in names),\'finite recognized native lease or exact reviewed no-device artifact namespace\')\n  def read(parent,name,cap=262144,*,as_json=True,mode=0o400):\n   nonlocal total\n   clock();f=fd(name,os.O_RDONLY,parent);s=os.fstat(f)\n   need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode and 0<s.st_size<=cap,\'Root exact-mode single-link complete observer input\')\n   b=bytearray()\n   while True:\n    clock();x=os.read(f,65536)\n    if not x:break\n    b.extend(x);total+=len(x);need(len(b)<=cap and total<=16777216,\'lease record and aggregate cap\')\n   need(len(b)==s.st_size and ident(s)==ident(os.fstat(f))==ident(os.stat(name,dir_fd=parent,follow_symlinks=False)),\'lease full9/read EOF custody\')\n   records.append((parent,name,f,ident(s)))\n   return (json.loads(b,object_pairs_hook=unique) if as_json else bytes(b)),{\'bytes\':len(b),\'sha256\':hashlib.sha256(b).hexdigest(),\'identity\':ident(s)}\n  implementation=None\n  def recovered(state):\n   nonlocal implementation\n   # The current immutable queue supplies its existing definition as DATA.\n   # Root authenticates every module before interpretation; original intent,\n   # phase, lease and diagnostic records remain the unchanged subject.\n   if implementation is None:\n    ref=implementation_definition\n    need(type(ref)is dict and set(ref)=={\'path\',\'bytes\',\'sha256\',\'identity\'},\'current implementation whole definition pin\')\n    path=Path(ref[\'path\']);source_root=path.parent\n    need(path.name==\'installed-controller.json\'and source_root.parent==Path(\'/run\')and re.fullmatch(\'opemos-media-source-[0-9a-f]{32}\',source_root.name),\'one existing current deployment definition\')\n    sourcefd=fd(str(source_root),os.O_RDONLY|os.O_DIRECTORY);sourcecore=core(os.fstat(sourcefd))\n    need(sourcecore[3:5]==(0,0)and stat.S_IMODE(sourcecore[2])==0o555,\'immutable Root source directory\')\n    definition,actual=read(sourcefd,path.name,1048576,mode=0o444)\n    need(dict(actual,path=str(path))==ref,\'current definition held full9/hash\')\n    roles=definition[\'sourceRoles\'];helper=roles[\'source_contract\']\n    def role_bytes(name,pin):\n     need(pin[\'path\']==str(source_root/(name+\'.py\')),\'confined current module role\')\n     body,actual=read(sourcefd,name+\'.py\',1048576,as_json=False,mode=0o444)\n     need(dict(actual,path=pin[\'path\'])==pin,\'current module whole held/named pin\');return body\n    helper_raw=role_bytes(\'source_contract\',helper)\n    need(helper[\'sha256\']==\'4cb604515bbb577e6448283a7b785249929c73216e890a06ca5c531e25bd6e5d\',\'reviewed shared source definition implementation\')\n    shared=types.ModuleType(\'source_contract\');shared.__file__=helper[\'path\'];exec(compile(helper_raw,shared.__file__,\'exec\'),shared.__dict__)\n    need(shared.read_definition(ref)==definition and set(roles)==shared.RUNTIME_ROLES,\'complete current runtime membership\')\n    need(roles[\'libvirt_peer\'][\'sha256\']==\'f9deff3c479e8a805782bcc75642260b6ceb681007b71705a655227f07ff5591\'and roles[\'libvirt_peer\'][\'bytes\']==65324,\'exact reviewed recovery CLOSED implementation\')\n    bodies={name:role_bytes(name,pin)for name,pin in roles.items()}\n    order=(\'libvirt_storage\',\'retained_media\',\'source_contract\',\'libvirt_peer\',\'libvirt_access\',\'guest_firmware_probe\',\'libvirt_native\',\'queue_assignment\',\'libvirt_preflight\',\'libvirt_producer\',\'postqueue_issuer\')\n    previous={name:sys.modules.get(name)for name in order};modules={}\n    def restore_modules():\n     for name,old in previous.items():\n      if old is None:sys.modules.pop(name,None)\n      else:sys.modules[name]=old\n    stack.callback(restore_modules)\n    for name in order:\n     module=types.ModuleType(name);module.__file__=roles[name][\'path\'];sys.modules[name]=module;modules[name]=module\n    for name in order:exec(compile(bodies[name],modules[name].__file__,\'exec\'),modules[name].__dict__)\n    modules[\'source_contract\'].validate(roles,definition[\'queuePrograms\'],ref)\n    held.append((root,source_root.name,sourcefd,sourcecore));implementation=modules[\'libvirt_peer\']\n   peer=implementation;cc=state[\'currentDisposition\'][\'currentClosure\'];rows=cc[\'restorationReadback\']\n   need(type(rows)is list and len(rows)==6,\'complete original restoration journal roles\')\n   journal=Path(rows[0][\'beforePin\'][\'path\']).parent\n   need(journal.parent==Path(\'/run\')and re.fullmatch(\'opemos-libvirt-queue-[0-9a-f]{32}\',journal.name),\'original protected journal namespace\')\n   with peer.RootFiles(journal)as files,files.lock():\n    iraw,ip=files.read(\'intent.json\');intent=json.loads(iraw,object_pairs_hook=unique);request=intent[\'request\'];digest=hashlib.sha256(peer.canon(request)).hexdigest()\n    need(intent[\'kind\']==\'ROOT_EXACT_QUEUE_LIBVIRT_INTENT_R2\'and intent[\'bootID\']==state[\'currentBoot\']and request[\'jobId\']==state[\'jobID\']and request[\'leaseNonce\']==state[\'nonce\']and journal.name==\'opemos-libvirt-queue-\'+request[\'jobToken\']and state[\'requestSHA256\']==digest,\'original Root intent/job/nonce/token/boot/request hash\')\n    with peer._original_readonly_subject(request,implementation_definition):peer.validate_request(request)\n    hraw,hp=files.read(\'phase-head.json\');head=json.loads(hraw,object_pairs_hook=unique)\n    need(set(head)=={\'record\',\'sha256\'}and re.fullmatch(r\'phase-[0-9]{2}\\.json\',head[\'record\']),\'exact original phase head\')\n    praw,pp=files.read(head[\'record\']);phase=json.loads(praw,object_pairs_hook=unique)\n    need(hashlib.sha256(praw).hexdigest()==head[\'sha256\']and phase[\'phase\']==\'CLOSED\'and phase[\'requestSHA256\']==digest and phase[\'bootID\']==state[\'currentBoot\']and phase[\'scope\']is phase[\'leader\']is None and phase[\'details\']==state[\'currentDisposition\'],\'original CLOSED phase and unchanged recovery details\')\n    peer._complete_historical_libvirt_closed(state,request,files)\n    need(files.read(\'intent.json\')==(iraw,ip)and files.read(\'phase-head.json\')==(hraw,hp)and files.read(head[\'record\'])==(praw,pp),\'original intent/phase full9/hash post-use\')\n   clock();return True\n  for name in names:\n   clock()\n   if name==LEGACY_REVIEW:\n    raw,rp=read(root,name,as_json=False)\n    need(rp[\'bytes\']==LEGACY_MODULE_BYTES and rp[\'sha256\']==LEGACY_MODULE_SHA,\'exact retained reviewed native source, not arbitrary prefix file\')\n    nonleases.append({\'name\':name,\'classification\':\'PINNED_REVIEW_SOURCE_NOT_LEASE\',\'source\':rp,\'hardwareAuthority\':False})\n    continue\n   test=name==LEGACY_TEST\n   d=fd(name,os.O_RDONLY|os.O_DIRECTORY,root);ds=os.fstat(d)\n   need(stat.S_ISDIR(ds.st_mode) and ds.st_uid==ds.st_gid==0 and stat.S_IMODE(ds.st_mode)==0o700,\'Root0700 lease directory\')\n   lock=fd(\'lock\',os.O_RDONLY,d);ls=os.fstat(lock)\n   need(stat.S_ISREG(ls.st_mode) and ls.st_uid==ls.st_gid==0 and ls.st_nlink==1 and stat.S_IMODE(ls.st_mode)==0o600,\'exact existing Root0600 lease lock\')\n   fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)\n   head,hp=read(d,\'head.json\')\n   native=set(head)=={\'path\',\'bytes\',\'sha256\',\'identity\'}\n   libvirt=set(head)=={\'revision\',\'state\',\'stateSHA256\'}\n   need(native or(libvirt and not test),\'exact native full-pin or libvirt revision head schema\')\n   if native:\n    state_name=head[\'path\'].rsplit(\'/\',1)[-1]\n    need(head[\'path\']==run+\'/\'+name+\'/\'+state_name,\'head exact own state path, no foreign alias\')\n   else:\n    need(type(head[\'revision\'])is int and 0<=head[\'revision\']<64 and head[\'state\']==\'state-\'+str(head[\'revision\'])+\'.json\'and re.fullmatch(\'[0-9a-f]{64}\',head[\'stateSHA256\'])is not None,\'exact libvirt revision/state/hash\')\n    state_name=head[\'state\']\n   need(re.fullmatch(\'state-(?:[0-9]|[1-5][0-9]|6[0-3])\\\\.json\',state_name),\'bounded same-dir state name\')\n   state,sp=read(d,state_name)\n   if native:need(all(head[k]==sp[k] for k in (\'bytes\',\'sha256\',\'identity\')),\'head full state pin equality\')\n   else:\n    need(state[\'revision\']==head[\'revision\']and sp[\'sha256\']==head[\'stateSHA256\']and state[\'backend\']==\'libvirt\',\'libvirt whole state hash/revision/backend\')\n   CURRENT_CONTEXT={\'leaseRoot\':run+\'/\'+name,\'head\':hp,\'state\':sp,\'nonce\':state.get(\'nonce\'),\'jobID\':state.get(\'jobID\')}\n   if state.get(\'backend\')==\'libvirt\':\n    need(re.fullmatch(\'[0-9a-f]{64}\',state[\'requestSHA256\'])is not None,\'exact libvirt request hash under either head format\')\n    libvirtBoots.append(state[\'currentBoot\'])\n    if state[\'closed\']is True:\n     need(complete_libvirt_closed(state,recovered),\'libvirt CLOSED requires complete proven domain/host restoration\')\n   need(state[\'nonce\']==(LEGACY_NONCE if test else name.removeprefix(\'opemos-vfio-\')) and type(state[\'revision\']) is int and state_name==\'state-\'+str(state[\'revision\'])+\'.json\' and type(state[\'jobID\']) is str and state[\'jobID\'],\'exact lease scope/revision\')\n   need(type(state[\'closed\']) is bool and type(state[\'restored\']) is bool and type(state[\'changed\']) is list,\'typed native lease disposition\')\n   if test:\n    control,cp=read(d,\'control.json\');testBoots.append(control.get(\'bootId\'))\n    need(set(control)=={\'nonce\',\'jobID\',\'bootId\',\'noDevice\',\'modulePin\',\'pythonPin\',\'tools\'} and control[\'noDevice\'] is True and\n         control[\'nonce\']==LEGACY_NONCE and control[\'jobID\']==LEGACY_JOB and state[\'jobID\']==LEGACY_JOB and\n         state[\'snapshot\']=={\'explicitNoDevice\':True} and state[\'changed\']==[] and state[\'qemu\'] is None and\n         state.get(\'testFault\') in (None,\'unknown_owner\'),\'exact isolated no-device producer/control/state contract\')\n    raw,mp=read(d,\'native_vfio_adapter.py\',131072,as_json=False)\n    need(mp[\'bytes\']==LEGACY_MODULE_BYTES and mp[\'sha256\']==LEGACY_MODULE_SHA and\n         control[\'modulePin\']==dict(mp,path=run+\'/\'+name+\'/native_vfio_adapter.py\'),\n         \'no-device module whole current pin equals exact existing reviewed source\')\n    # Preserve closed/restored/testFault as diagnostic history. They authorize no\n    # hardware and cannot exempt any production opemos-vfio-<32hex> lease.\n    nonleases.append({\'name\':name,\'classification\':\'PINNED_EXPLICIT_NO_DEVICE_TEST_NOT_PHYSICAL_LEASE\',\n      \'control\':cp,\'module\':mp,\'head\':hp,\'state\':sp,\'closed\':state[\'closed\'],\'restored\':state[\'restored\'],\n      \'testFault\':state.get(\'testFault\'),\'hardwareAuthority\':False})\n    control2,cp2=read(d,\'control.json\');need(control2==control and cp2==cp,\'no-device control changed\')\n   safe=state[\'closed\'] is True and state[\'restored\'] is True and state[\'changed\']==[]\n   if not test: rows.append({\'leaseRoot\':run+\'/\'+name,\'jobID\':state[\'jobID\'],\'nonce\':state[\'nonce\'],\'revision\':state[\'revision\'],\'closed\':state[\'closed\'],\'restored\':state[\'restored\'],\'changed\':state[\'changed\'],\'safe\':safe,\'head\':hp,\'state\':sp})\n   held.append((root,name,d,core(ds)));held.append((d,\'lock\',lock,core(ls)))\n   h2,hp2=read(d,\'head.json\');need(h2==head and hp2==hp,\'head changed during observation\')\n  # Current boot physical group mapping, not a retained PCI or build receipt.\n  group=sysroot+\'/kernel/iommu_groups/1/devices\';actual=sorted(os.listdir(group));need(actual==MEMBERS,\'exact current physical IOMMU group1 membership\')\n  for b,device in [(\'0000:01:00.0\',\'0x1f15\'),(\'0000:01:00.1\',\'0x10f9\'),(\'0000:01:00.2\',\'0x1ada\'),(\'0000:01:00.3\',\'0x1adb\')]:\n   for key,value in [(\'vendor\',\'0x10de\'),(\'device\',device)]:\n    f=fd(sysroot+\'/bus/pci/devices/\'+b+\'/\'+key,os.O_RDONLY);need(os.read(f,64).decode().strip()==value,\'current GPU endpoint vendor/device\')\n  bootfd=fd(procroot+\'/sys/kernel/random/boot_id\',os.O_RDONLY);boot=os.read(bootfd,64).decode().strip();need(re.fullmatch(\'[0-9a-f-]{36}\',boot),\'current host boot\')\n  need(all(b==boot for b in testBoots),\'same current no-device control boot\');need(all(b==boot for b in libvirtBoots),\'same current libvirt lease boot\')\n  for parent,name,f,original in records:need(ident(os.fstat(f))==original==ident(os.stat(name,dir_fd=parent,follow_symlinks=False)),\'final full9 record held/name replacement\')\n  for parent,name,child,c in held:need(core(os.fstat(child))==c==core(os.stat(name,dir_fd=parent,follow_symlinks=False)),\'held/named lease directory/lock drift\')\n  need(names==sorted(n for n in os.listdir(root) if n.startswith(\'opemos-vfio-\')) and core(os.fstat(root))==rootcore==core(os.stat(run,follow_symlinks=False)),\'whole native lease namespace changed\')\n  pid=os.getpid();pf=fd(procroot+\'/\'+str(pid)+\'/stat\',os.O_RDONLY);parts=os.read(pf,65536).rsplit(b\')\',1)[1].split();actor={\'pid\':pid,\'start\':int(parts[19]),\'uid\':os.getuid()}\n  clock();result={\'kind\':\'ROOT_CURRENT_GPU_GROUP_LEASE_INVENTORY\',\'group\':GROUP,\'members\':actual,\'boot\':boot,\'actor\':actor,\'leaseRows\':rows,\'gpuAvailable\':all(x[\'safe\'] for x in rows),\'nonLeaseEntries\':nonleases,\'complete\':True,\'readOnly\':True,\'effects\':[],\'startedMonotonic\':started,\'completedMonotonic\':time.monotonic(),\'sourceSHA256\':sys.argv[1] if len(sys.argv)>1 else None,\'recordBytesRead\':total}\n # ExitStack close failure cannot produce a successful stdout frame.\n result[\'allOwnedDescriptorsClosed\']=True\n return result\nif __name__==\'__main__\':\n try:print(json.dumps(observe(implementation_definition=json.loads(sys.argv[2])if len(sys.argv)==3 else None),sort_keys=True,separators=(\',\',\':\'),allow_nan=False),flush=True)\n except BaseException as e:\n  import traceback\n  print(json.dumps({\'kind\':\'GPU_LEASE_OBSERVATION_REFUSED\',\'reason\':str(e),\'errorType\':type(e).__name__,\'currentContext\':CURRENT_CONTEXT,\'traceback\':traceback.format_exc(),\'effects\':[]}),file=sys.stderr,flush=True);raise SystemExit(1)\n'
GPU_GROUP_OBSERVER_SHA256 = '444bc650d1a84b581ede27beddeb79ebef84eb98e640b2839da2c0880ba1a777'

# Appended to the existing queue; existing NVIDIA readiness and terminal guards retained.
GPU_GROUP_MEMBERS = ['0000:00:01.0','0000:01:00.0','0000:01:00.1','0000:01:00.2','0000:01:00.3']
GPU_PHYSICAL_ALIASES = {'nvidia-gpu:omen:0000:01:00.0','/dev/vfio/1',
                        *('/sys/bus/pci/devices/'+b for b in GPU_GROUP_MEMBERS[1:])}
def gpu_job(spec):
    return NVIDIA_RESOURCE in spec['resources'] or bool(GPU_PHYSICAL_ALIASES.intersection(spec['resources']))
def effective_resources(spec):
    values=set(spec['resources'])
    if gpu_job(spec): values.add(NVIDIA_RESOURCE)
    return values

def observe_gpu_group():
    """Existing noninteractive sudo Python route; Root reads only, never clears leases."""
    source=GPU_GROUP_OBSERVER_SOURCE
    require(hashlib.sha256(source.encode()).hexdigest()==GPU_GROUP_OBSERVER_SHA256,'Exact Root readonly GPU observer source')
    definition=__import__('source_contract').current_from_queue(__file__)
    implementation=None if definition is None else definition[0]
    launched=time.monotonic()
    result=subprocess.run(['sudo','-n','/usr/bin/python3','-B','-c',source,GPU_GROUP_OBSERVER_SHA256,canonical(implementation)],
                          capture_output=True,text=True,timeout=15)
    # run() returns only after wait/reap and complete stdout/stderr EOF. A timeout
    # is UNKNOWN, never admission. This route requires independent Root-child
    # closure qualification before deployment; no timeout grants GPU use.
    require(result.returncode==0 and result.stderr=='' and 0<len(result.stdout.encode())<=1048576,
            'Root GPU observer numeric/EOF/raw bound refusal: '+str(result.returncode)+':'+result.stderr[:4096])
    def unique(pairs):
        out={}
        for k,v in pairs:
            require(k not in out,'Duplicate GPU observer field');out[k]=v
        return out
    proof=json.loads(result.stdout,object_pairs_hook=unique)
    require(result.stdout==canonical(proof)+'\n','Exact one canonical Root GPU frame')
    validate_gpu_group_observation(proof,launched)
    actor=proof['actor']
    try:
        parts=Path('/proc/'+str(actor['pid'])+'/stat').read_text().rsplit(')',1)[1].split()
        require(int(parts[19])!=actor['start'],'Original Root observer still present after sudo waiter; GPU held')
    except (FileNotFoundError,ProcessLookupError): pass
    return proof

def validate_gpu_group_observation(proof,launched):
    require(type(proof)is dict and set(proof)=={'kind','group','members','boot','actor','leaseRows',
        'gpuAvailable','complete','readOnly','effects','startedMonotonic','completedMonotonic','sourceSHA256',
        'recordBytesRead','allOwnedDescriptorsClosed','nonLeaseEntries'},'Closed Root GPU observer schema')
    require(proof['kind']=='ROOT_CURRENT_GPU_GROUP_LEASE_INVENTORY' and proof['group']==NVIDIA_RESOURCE and
        proof['members']==GPU_GROUP_MEMBERS and proof['boot']==Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
        proof['sourceSHA256']==GPU_GROUP_OBSERVER_SHA256 and proof['complete']is True and proof['readOnly']is True and
        proof['effects']==[] and proof['allOwnedDescriptorsClosed']is True,'Current exact Root/group/boot/source/closed observation')
    actor=proof['actor'];require(type(actor)is dict and set(actor)=={'pid','start','uid'} and
        type(actor['pid'])is int and actor['pid']>0 and type(actor['start'])is int and actor['start']>0 and actor['uid']==0,
        'Exact original Root observer process binding')
    now=time.monotonic();require(type(proof['startedMonotonic'])in(int,float)and type(proof['completedMonotonic'])in(int,float)and
        launched<=proof['startedMonotonic']<=proof['completedMonotonic']<=now and
        now-proof['completedMonotonic']<=1 and proof['completedMonotonic']-proof['startedMonotonic']<=8,
        'Same-host live GPU observation fence, never historical R42 receipt')
    require(type(proof['leaseRows'])is list and len(proof['leaseRows'])<=64 and
        type(proof['gpuAvailable'])is bool and type(proof['recordBytesRead'])is int and 0<=proof['recordBytesRead']<=16777216,
        'Finite whole GPU lease inventory')
    nonlease=proof['nonLeaseEntries']; require(type(nonlease)is list and len(nonlease)<=2,'Finite exact positively classified non-lease artifacts')
    historical_nonce='77d65157c8f8498db153fba91475f1ff'
    reviewed='opemos-vfio-native-review-'+historical_nonce+'.py'
    tested='opemos-vfio-native-test-'+historical_nonce+'-r2'
    seen_nonlease=set()
    for row in nonlease:
        require(type(row)is dict and row.get('name')in(reviewed,tested)and row['name']not in seen_nonlease and row.get('hardwareAuthority')is False,'Exact reviewed/test artifact; never arbitrary ignored prefix')
        seen_nonlease.add(row['name'])
        if row['name']==reviewed:
            require(set(row)=={'name','classification','source','hardwareAuthority'} and row['classification']=='PINNED_REVIEW_SOURCE_NOT_LEASE','Exact review-source disposition')
            module=row['source']; pin_fields=['source']
        else:
            require(set(row)=={'name','classification','control','module','head','state','closed','restored','testFault','hardwareAuthority'} and row['classification']=='PINNED_EXPLICIT_NO_DEVICE_TEST_NOT_PHYSICAL_LEASE' and type(row['closed'])is bool and type(row['restored'])is bool and row['testFault']in(None,'unknown_owner'),'Exact existing explicit no-device test disposition, not physical release')
            module=row['module']; pin_fields=['control','module','head','state']
        require(module['bytes']==40315 and module['sha256']=='09a859f94267748cee5a7715fd4e5649b2e067fdaa43123e91c077fcf412729a','Same exact frozen reviewed no-device source')
        for name in pin_fields:
            ref=row[name];require(type(ref)is dict and set(ref)=={'bytes','sha256','identity'} and type(ref['bytes'])is int and 0<ref['bytes']<=262144 and re.fullmatch('[0-9a-f]{64}',ref['sha256']) and type(ref['identity'])is dict and set(ref['identity'])=={'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'} and ref['identity']['st_uid']==ref['identity']['st_gid']==0 and ref['identity']['st_mode']==0o100400 and ref['identity']['st_nlink']==1 and ref['identity']['st_size']==ref['bytes'],'Complete Root0400 classified artifact full9/hash')
    nonces=set()
    for row in proof['leaseRows']:
        require(type(row)is dict and set(row)=={'leaseRoot','jobID','nonce','revision','closed','restored','changed','safe','head','state'} and
            re.fullmatch('[0-9a-f]{32}',row['nonce']) and row['nonce']not in nonces and
            row['leaseRoot']=='/run/opemos-vfio-'+row['nonce'] and type(row['jobID'])is str and row['jobID'] and
            type(row['revision'])is int and 0<=row['revision']<64 and type(row['closed'])is bool and type(row['restored'])is bool and
            type(row['changed'])is list and type(row['safe'])is bool and
            row['safe']==(row['closed']is True and row['restored']is True and row['changed']==[]),'Exact native lease scope/disposition')
        nonces.add(row['nonce'])
        for key in ('head','state'):
            pin=row[key];require(type(pin)is dict and set(pin)=={'bytes','sha256','identity'}and type(pin['bytes'])is int and
                0<pin['bytes']<=262144 and re.fullmatch('[0-9a-f]{64}',pin['sha256'])and type(pin['identity'])is dict and
                set(pin['identity'])=={'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'}and
                pin['identity']['st_uid']==pin['identity']['st_gid']==0 and pin['identity']['st_nlink']==1 and
                pin['identity']['st_mode']==0o100400 and pin['identity']['st_size']==pin['bytes'],'Root0400 full9 whole native pin')
    require(proof['gpuAvailable']==all(row['safe']for row in proof['leaseRows']),'No fabricated availability summary')
    return proof

def gpu_wait_reason(spec, observation=None):
    if not gpu_job(spec):return None
    try:
        require(NVIDIA_RESOURCE in spec['resources'],'GPU job lacks canonical omen-iommu-group-1 resource; submit corrected new job, preserve old spec')
        proof=observe_gpu_group()if observation is None else observation
        # observation is an internal already-validated choose() cache, never a job field.
        require(proof['gpuAvailable']is True,'Physical GPU lease open, unrestored or unknown; queue terminal state cannot release it')
    except (ValueError,OSError,KeyError,IndexError,TypeError,subprocess.SubprocessError)as error:
        return {'kind':'GPU_GROUP_LEASE_WAIT','group':NVIDIA_RESOURCE,'reason':str(error),'errorType':type(error).__name__,
                'reserved':False,'accepted':False,'retryVM':False,'leaseMutationAuthorized':False}
    return None

def launch_admission_wait(spec):
    return gpu_wait_reason(spec) or nvidia_wait_reason(spec)


# Narrow single libvirt GPU job contract. The peer observer controls no queue data.
LIBVIRT_POOL='/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice'
LIBVIRT_CONTROLLER_MEMORY=2*1024**3
LIBVIRT_DOMAIN_MEMORY=8*1024**3
LIBVIRT_RESERVATION_MEMORY=10*1024**3

def normalize_libvirt_domain(value,base):
    require(type(value)is dict and set(value)=={'uuid','name','leaseNonce','observer'},'Exact libvirt domain intent')
    require(type(value['uuid'])is str and str(uuid.UUID(value['uuid']))==value['uuid'],'Canonical domain UUID')
    require(type(value['name'])is str and re.fullmatch(r'opemos-libvirt-[0-9a-f]{32}',value['name']),'Exact transient domain name')
    require(re.fullmatch(r'[0-9a-f]{32}',value['leaseNonce'])is not None,'Exact GPU lease nonce')
    observer=file_pin(base/value['observer']);require(observer['bytes']<=65536,'Pinned readonly libvirt observer source64KiB')
    return dict(uuid=value['uuid'],name=value['name'],leaseNonce=value['leaseNonce'],observer=observer)


R109_PEER_SHA='f9deff3c479e8a805782bcc75642260b6ceb681007b71705a655227f07ff5591'
R109_PEER_BYTES=65324
R109_ACCESS_SHA='c659275c55005e842e4be51614ee53559a5ecbae712702d49b17dbafa91b04cc'
R109_ACCESS_BYTES=43477
def current_source_root():
    result=__import__('source_contract').current_from_queue(__file__)
    require(result is not None,'current executing queue has paired protected definition')
    return result[1]['deployment']['paths']['sourceRoot']
R109_ORIGINAL_SOURCE_ROOT='/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r107b'
R109_ORIGINAL_PEER_SHA='7e1663f8351247b9643b7c14419119449b0bd0722a46b80ae0f8ea34a9f9816a'
R109_CURRENT_ADAPTER = '"""Exact D23 readonly standalone peer/access adapter proposal, never installed.\nNo deployment, writes, SQL, runtime grant, domain control or sysfs methods.\nQueue owner must independently adopt exact bytes and consumer contract.\n"""\nimport contextlib,copy,hashlib,json,os,re,stat,sys,time,traceback,types\nfrom pathlib import Path\nORIGINAL_SOURCE_ROOT=\'/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r107b\'\nPEER_SHA=\'f9deff3c479e8a805782bcc75642260b6ceb681007b71705a655227f07ff5591\'\nF=(\'st_dev\',\'st_ino\',\'st_mode\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\');CORE=F[:6]\nNONCE=\'cd9ef0826364409da287f6f3e3830c95\';CONTRACT=\'R109_CURRENT_NORMAL_QUEUE_FULL_PHASE_READONLY\'\nPEER_BYTES=65324\nORIGINAL_PEER_SHA=\'7e1663f8351247b9643b7c14419119449b0bd0722a46b80ae0f8ea34a9f9816a\';ORIGINAL_PEER_BYTES=64727\nCLOSED_SUBJECT_PEERS={\'9e5516fcdf57624d786a91741066998605045fe145ce60fbe8bde68f5b494bdd\':61355,\'224aa4a8b06999e318350267195cc681a095aaf2a2b5e407552f8811673a8614\':61400}\nSOURCE_ROOT=None\nSOURCE_CONTRACT_SHA=\'fcc7062dcc4c549ef74c7ada6d7a98b612e28c8c0329f23b8dcd3fb7c9ab761d\'\nCURRENT_DEFINITION=None\nACCESS_SHA=\'c659275c55005e842e4be51614ee53559a5ecbae712702d49b17dbafa91b04cc\';ACCESS_BYTES=43477\nORIGINAL_ACCESS_SHA=\'ee32a4e84df796d6932062ded9e1049ce5e82cbbf01315d8c74da96b9e03aa9e\';ORIGINAL_ACCESS_BYTES=33928\nROLES={\'libvirt_peer\',\'libvirt_access\',\'libvirt_native\',\'libvirt_preflight\',\'libvirt_producer\',\'queue_assignment\',\'runtime_entry\',\'guest_delta\',\'guest_firmware_probe\',\'held_history_reader\',\'two_boot_contract\',\'postqueue_issuer\',\'libvirt_storage\',\'retained_media\',\'source_contract\'}\ndef placement_root(candidate):\n if \'operationContext\'in candidate:\n  need(CURRENT_DEFINITION is not None,\'authenticated shared definition available\');return CURRENT_DEFINITION.candidate_paths(candidate)[\'placementRoot\']\n nonce=candidate[\'nonce\'];need(nonce==NONCE,\'same placement nonce\')\n io=Path(candidate[\'run\']).parent;prefix=\'opemos-libvirt-io-\'+nonce+\'-\'\n if candidate.get(\'installer\',{}).get(\'kind\')==\'AUTHENTICATED_RETAINED_F9AA_READONLY_USB\' or io.name.startswith(prefix):\n  need(io.parent==Path(\'/run\')and re.fullmatch(re.escape(prefix)+\'[0-9a-f]{32}\',io.name)and Path(candidate[\'run\'])==io/\'run\'and Path(candidate[\'output\'])==io/\'output\'and type(candidate.get(\'jobId\'))is str and candidate[\'jobId\'].endswith(\'-e\'+io.name[len(prefix):][:16]),\'protected same attempt IO/job placement\')\n  return \'/run/opemos-steamos-placement-\'+nonce+\'-\'+io.name[len(prefix):]\n return \'/run/opemos-steamos-placement-\'+nonce\ndef canonical(v):return json.dumps(v,sort_keys=True,separators=(\',\',\':\'),allow_nan=False)\ndef need(v,m):\n if not v:raise RuntimeError(m)\ndef ident(s):return{k:getattr(s,k)for k in F}\ndef decode(raw):\n def unique(pairs):\n  value={}\n  for key,item in pairs:need(key not in value,\'duplicate protected JSON key\');value[key]=item\n  return value\n value=json.loads(raw,object_pairs_hook=unique);need(canonical(value).encode()==raw,\'whole canonical protected metadata, no dropped/trailing fields\');return value\ndef record_run_check(proof,event):\n # All native FD/name/core/mount/namespace predicates run before this call.\n # Keep only the current witness; diagnostic transcript growth is no authority.\n proof[\'lastCheck\']=event\n\nclass RootInputs:\n """One readonly bounded held-nofollow /run graph; owns and closes all FDs."""\n def __init__(self,control=None,implementation=None):self.fds=[];self.dirs={};self.currentControl=control;self.implementationPin=implementation;self.implementationRoot=None\n def __enter__(self):\n  self.root=os.open(\'/\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.fds.append(self.root)\n  try:\n   self.run=os.open(\'run\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.root);self.fds.append(self.run)\n   self.dirs={\'/\':(self.root,ident(os.fstat(self.root)),False),\'/run\':(self.run,ident(os.fstat(self.run)),False)};self.runBirth=self.run_row(self.run);rows=[x for x in Path(\'/proc/self/mountinfo\').read_text().splitlines()if x.split()[0]==str(self.runBirth[\'mountID\'])];need(len(rows)==1,\'exact initial run mount\');self.runProof={\'kind\':\'ROOT_BORROWED_RUN_CURRENT_CUSTODY_V1\',\'path\':\'/run\',\'birth\':self.runBirth,\'namespace\':os.readlink(\'/proc/self/ns/mnt\'),\'mountRow\':rows[0],\'lastCheck\':None,\'scopeDescriptorsClosed\':False,\'closeOutcomes\':[]};self.check()\n   if self.currentControl is not None:self.bind_definition(self.currentControl)\n   if self.implementationPin is not None:self.bind_implementation(self.implementationPin)\n   return self\n  except BaseException:\n   self.__exit__(*sys.exc_info());raise\n def run_row(self,fd):\n  raw=Path(\'/proc/self/fdinfo/\'+str(fd)).read_text();v={}\n  for line in raw.splitlines():\n   if line.startswith((\'flags:\',\'mnt_id:\')):k,x=line.split(\':\',1);v[k]=x.strip()\n  need(set(v)=={\'flags\',\'mnt_id\'}and v[\'mnt_id\'].isdigit()and re.fullmatch(\'[0-7]+\',v[\'flags\'])is not None,\'complete actual run descriptor flags/mount\')\n  f=__import__(\'fcntl\');return {\'fd\':fd,\'identity\':ident(os.fstat(fd)),\'target\':os.readlink(\'/proc/self/fd/\'+str(fd)),\'flags\':f.fcntl(fd,f.F_GETFL),\'descriptorFlags\':f.fcntl(fd,f.F_GETFD),\'fdinfoFlags\':v[\'flags\'],\'mountID\':int(v[\'mnt_id\'])}\n def borrowed_run(self):\n  initial=self.runBirth;owned=[];primary=None;event={};startns=os.readlink(\'/proc/self/ns/mnt\')\n  try:\n   event[\'heldBefore\']=self.run_row(self.run)\n   for label,path,anchored in((\'anchored\',\'run\',True),(\'named\',\'/run\',False)):\n    fd=os.open(path,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,**({\'dir_fd\':self.root}if anchored else{}));owned.append(fd);event[label]=self.run_row(fd)\n   event[\'anchoredPath\']=ident(os.stat(\'run\',dir_fd=self.root,follow_symlinks=False));event[\'namedPath\']=ident(os.lstat(\'/run\'));event[\'heldAfter\']=self.run_row(self.run);event[\'anchoredAfter\']=self.run_row(owned[0]);event[\'namedAfter\']=self.run_row(owned[1]);event[\'namespaceBefore\']=startns;event[\'namespaceAfter\']=os.readlink(\'/proc/self/ns/mnt\')\n   rows=[x for x in Path(\'/proc/self/mountinfo\').read_text().splitlines()if x.split()[0]==str(initial[\'mountID\'])];need(len(rows)==1,\'unique current kernel run mount row\');event[\'mountRow\']=rows[0]\n   stable=F[:5];snapshots=[event[k][\'identity\']for k in(\'heldBefore\',\'anchored\',\'named\',\'heldAfter\',\'anchoredAfter\',\'namedAfter\')]+[event[\'anchoredPath\'],event[\'namedPath\']]\n   need(all(all(x[k]==initial[\'identity\'][k]for k in stable)for x in snapshots)and all(event[k][\'target\']==\'/run\'and event[k][\'mountID\']==initial[\'mountID\']and event[k][\'descriptorFlags\']==1 for k in(\'heldBefore\',\'anchored\',\'named\',\'heldAfter\',\'anchoredAfter\',\'namedAfter\')),\'same held/anchored/named run inode/type/mode/owner/mount\')\n   need(event[\'heldBefore\']==dict(initial,identity=event[\'heldBefore\'][\'identity\'])and event[\'heldAfter\']==dict(initial,identity=event[\'heldAfter\'][\'identity\'])and startns==event[\'namespaceAfter\']==self.runProof[\'namespace\'],\'same borrowed run FD/flags/name/namespace\')\n   for name in(\'anchored\',\'named\'):\n    a=event[name];b=event[name+\'After\'];need(a==dict(b,identity=a[\'identity\'])and a[\'flags\']==os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,\'exact temporary nofollow O_PATH run descriptors\')\n   row=rows[0].split();i=initial[\'identity\'];need(stat.S_ISDIR(i[\'st_mode\'])and stat.S_IMODE(i[\'st_mode\'])==0o755 and i[\'st_uid\']==i[\'st_gid\']==0 and initial[\'flags\']&os.O_ACCMODE==os.O_RDONLY and not initial[\'flags\']&os.O_PATH and initial[\'flags\']&os.O_DIRECTORY and initial[\'flags\']&os.O_NOFOLLOW and re.fullmatch(r\'mnt:\\[[0-9]+\\]\',startns)is not None,\'declared borrowed Root0755 readonly run directory\');need(row[3:5]==[\'/\',\'/run\']and row[2]==str(os.major(i[\'st_dev\']))+\':\'+str(os.minor(i[\'st_dev\']))and event[\'mountRow\']==self.runProof[\'mountRow\'],\'same kernel mount root/device/path and original run mount\')\n  except BaseException as error:primary=error;error.evidence={\'kind\':\'BORROWED_RUN_CUSTODY_REFUSAL_R257\',\'birth\':initial,\'event\':event};raise\n  finally:\n   errors=[]\n   for fd in owned[::-1]:\n    try:os.close(fd)\n    except BaseException as e:errors.append({\'fd\':fd,\'type\':type(e).__name__,\'reason\':str(e)})\n   if errors:\n    if primary is not None:primary.ownedRootInputClosureErrors=errors\n    else:raise RuntimeError(canonical({\'ownedRootInputClosureErrors\':errors}))\n  event[\'temporaryDescriptorsClosed\']=True;record_run_check(self.runProof,event);return event\n def check(self):\n  for path,(fd,a,exclusive)in self.dirs.items():\n   if path==\'/run\':self.borrowed_run();continue\n   x=ident(os.fstat(fd));named=ident(os.lstat(path))\n   if not(x==named and all(x[k]==a[k]for k in(CORE if not exclusive else F))):\n    error=RuntimeError(\'held/named declared directory identity/epoch\');error.evidence={\'path\':path,\'role\':\'exclusive\'if exclusive else\'shared-ancestor\',\'birth\':a,\'held\':x,\'named\':named,\'monotonic\':time.monotonic()};raise error\n   need(stat.S_ISDIR(x[\'st_mode\'])and x[\'st_uid\']==x[\'st_gid\']==0,\'Root directory nofollow custody\')\n   need(stat.S_IMODE(x[\'st_mode\'])in((0o755,0o777)if path==\'/\'else(0o755,)if path==\'/run\'else(0o555,)if path in(SOURCE_ROOT,self.implementationRoot) else(0o755,)if path.startswith(\'/run/opemos-steamos-source-\')else(0o700,)),\'exact role-specific directory mode\')\n def bind_definition(self,control):\n  global SOURCE_ROOT,NONCE,CURRENT_DEFINITION\n  need(type(control)is dict and set(control)=={\'definitionPin\',\'parentPin\'},\'closed protected current control input\')\n  ref=control[\'definitionPin\'];root=Path(ref[\'path\']).parent\n  need(root.parent==Path(\'/run\')and Path(ref[\'path\']).name==\'installed-controller.json\',\'direct Root definition leaf\')\n  SOURCE_ROOT=str(root)\n  raw,helper=self.read_path(str(root/\'source_contract.py\'),0o444,65536)\n  need(helper[\'sha256\']==SOURCE_CONTRACT_SHA,\'exact reviewed shared definition implementation\')\n  module=types.ModuleType(\'scoped_source_definition\');module.__file__=str(root/\'source_contract.py\');exec(compile(raw,module.__file__,\'exec\'),module.__dict__)\n  value=module.read_definition(ref);need(value[\'sourceRoles\'][\'source_contract\']==helper,\'same held definition implementation pin\')\n  need(value[\'deployment\'][\'paths\'][\'sourceRoot\']==SOURCE_ROOT and re.fullmatch(\'[0-9a-f]{32}\',value[\'guestNonce\']),\'typed protected deployment/guest lineage\')\n  self.definition=value;self.definitionPin=ref;NONCE=value[\'guestNonce\'];CURRENT_DEFINITION=module\n def bind_implementation(self,ref):\n  need(self.currentControl is not None and CURRENT_DEFINITION is not None,\'original authenticated subject definition first\')\n  root=Path(ref[\'path\']).parent;need(ref[\'path\']==str(root/\'installed-controller.json\')and root.parent==Path(\'/run\')and re.fullmatch(\'opemos-media-source-[0-9a-f]{32}\',root.name),\'separate normal immutable implementation definition\')\n  self.implementationRoot=str(root)\n  raw,actual=self.read_path(ref[\'path\'],0o444,1048576);need(actual==ref,\'held separate implementation definition\')\n  value=CURRENT_DEFINITION.read_definition(ref)\n  need(set(value[\'sourceRoles\'])==ROLES and value[\'deployment\'][\'paths\'][\'sourceRoot\']==str(root),\'complete typed implementation membership/root\')\n  helper=value[\'sourceRoles\'][\'source_contract\'];need(helper[\'sha256\']==SOURCE_CONTRACT_SHA and self.read(helper,0o444,65536),\'unchanged reviewed shared definition implementation\')\n  self.implementationDefinition=value\n def directory(self,path):\n  allowed={SOURCE_ROOT,ORIGINAL_SOURCE_ROOT,self.implementationRoot,getattr(self,\'runtimeRoot\',\'/run/opemos-libvirt-runtime-\'+NONCE),getattr(self,\'placementRoot\',\'/run/opemos-steamos-placement-\'+NONCE)}\n  need(path in allowed,\'declared finite source/context/placement root only\')\n  if path not in self.dirs:\n   fd=os.open(Path(path).name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.run);self.fds.append(fd);self.dirs[path]=(fd,ident(os.fstat(fd)),True)\n  self.check();return self.dirs[path][0]\n def read_path(self,path,mode,cap):\n  path=Path(path);need(path.is_absolute()and path.name not in(\'\',\'.\',\'..\'),\'absolute confined declared leaf\')\n  if str(path.parent)==\'/run\':need(str(path)==(self.currentControl[\'parentPin\'][\'path\']if self.currentControl is not None else\'/run/opemos-libvirt-parent-\'+NONCE+\'.json\'),\'one bound public parent only\');parent=self.run\n  else:parent=self.directory(str(path.parent))\n  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)\n  try:\n   s=os.fstat(fd);a=ident(s);need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode and s.st_nlink==1 and s.st_size<=cap,\'exact Root leaf mode/owner/link/size\');raw=b\'\'\n   while chunk:=os.read(fd,65536):raw+=chunk;need(len(raw)<=cap,\'bounded full leaf stream\')\n   need(a==ident(os.fstat(fd))==ident(os.stat(path.name,dir_fd=parent,follow_symlinks=False))==ident(os.lstat(path))and len(raw)==a[\'st_size\'],\'full held/anchored/named identity and EOF\');self.check();return raw,{\'path\':str(path),\'bytes\':len(raw),\'sha256\':hashlib.sha256(raw).hexdigest(),\'identity\':a}\n  finally:os.close(fd)\n def read(self,ref,mode,cap):\n  raw,actual=self.read_path(ref[\'path\'],mode,cap)\n  if actual!=ref:\n   error=RuntimeError(\'exact declared full9/length/SHA pin\');error.evidence={\'path\':ref[\'path\'],\'expected\':ref,\'actual\':actual};raise error\n  return raw\n def placement_bytes(self,fd,parentfd,ref):\n  """Inner FD/hash check; hold_placement applies exact Root role custody.\n  It does not change Root policy or convert a user fixture into Root proof.\n  """\n  value={\'path\':ref[\'path\'],\'expected\':ref,\'heldBefore\':None,\'heldAfter\':None,\'named\':None,\'heldSHA256\':None,\'namedSHA256\':None,\'heldBytes\':None,\'namedBytes\':None}\n  def bytesof(f):\n   chunks=[];offset=0\n   while True:\n    b=os.pread(f,65536,offset)\n    if not b:break\n    offset+=len(b);need(offset<=1048576,\'unchanged placement metadata1MiB streaming cap\');chunks.append(b)\n   return b\'\'.join(chunks)\n  try:\n   value[\'heldBefore\']=ident(os.fstat(fd));need((__import__(\'fcntl\').fcntl(fd,__import__(\'fcntl\').F_GETFL)&os.O_ACCMODE)==os.O_RDONLY,\'owned placement held FD remains O_RDONLY\');held=bytesof(fd);value.update(heldBytes=len(held),heldSHA256=hashlib.sha256(held).hexdigest())\n   nf=os.open(Path(ref[\'path\']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)\n   try:\n    value[\'named\']=ident(os.fstat(nf));named=bytesof(nf);value.update(namedBytes=len(named),namedSHA256=hashlib.sha256(named).hexdigest());need(value[\'named\']==ident(os.fstat(nf))==ident(os.stat(Path(ref[\'path\']).name,dir_fd=parentfd,follow_symlinks=False))==ident(os.lstat(ref[\'path\'])),\'placement fresh nofollow named FD/path full9\')\n   finally:\n    primary=sys.exc_info()[1]\n    try:os.close(nf)\n    except BaseException as close:\n     if primary is None:raise\n     primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'fd\':nf,\'type\':type(close).__name__,\'reason\':str(close)}]\n   value[\'heldAfter\']=ident(os.fstat(fd));need(value[\'heldBefore\']==value[\'heldAfter\']==value[\'named\']==ref[\'identity\']and len(held)==len(named)==ref[\'bytes\']and value[\'heldSHA256\']==value[\'namedSHA256\']==ref[\'sha256\']and held==named,\'placement held/named full9/raw bytes/length/SHA equal originally bound operand\')\n   return held\n  except BaseException as error:error.placementCustody=value;raise\n @contextlib.contextmanager\n def hold_placement(self,ref):\n  root=getattr(self,\'placementRoot\',\'/run/opemos-steamos-placement-\'+NONCE);need(ref[\'path\']in(root+\'/storage-contract.json\',root+\'/placement-qualified.json\'),\'two exact placement metadata leaves only\');i=ref[\'identity\'];need(set(ref)=={\'path\',\'bytes\',\'sha256\',\'identity\'}and 0<ref[\'bytes\']<=1048576 and stat.S_ISREG(i[\'st_mode\'])and stat.S_IMODE(i[\'st_mode\'])==0o400 and i[\'st_uid\']==i[\'st_gid\']==0 and i[\'st_nlink\']==1 and i[\'st_size\']==ref[\'bytes\'],\'exact Root0400 placement full pin/custody\')\n  parentfd=self.directory(root);fd=os.open(Path(ref[\'path\']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)\n  try:\n   original=self.placement_bytes(fd,parentfd,ref);self.check()\n   def recheck():\n    self.check();raw=self.placement_bytes(fd,parentfd,ref);need(raw==original,\'complete held placement raw bytes identical after observer\');self.check();return ref\n   yield {\'ref\':ref,\'raw\':original,\'recheck\':recheck}\n  finally:\n   primary=sys.exc_info()[1]\n   try:os.close(fd)\n   except BaseException as close:\n    if primary is None:raise\n    primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'fd\':fd,\'type\':type(close).__name__,\'reason\':str(close)}]\n def __exit__(self,*a):\n  errors=[]\n  for fd in self.fds[::-1]:\n   try:\n    os.close(fd)\n    if hasattr(self,\'runProof\'):self.runProof[\'closeOutcomes\'].append({\'fd\':fd,\'closed\':True})\n   except OSError as e:errors.append({\'fd\':fd,\'type\':type(e).__name__,\'reason\':str(e)})\n  self.fds=[]\n  if hasattr(self,\'runProof\'):self.runProof[\'scopeDescriptorsClosed\']=not errors\n  if errors:\n   if a[1]is not None:a[1].ownedRootInputClosureErrors=errors\n   else:raise RuntimeError(canonical({\'ownedRootInputClosureErrors\':errors}))\n\ndef parent_spec(parent,parent_ref):\n s=copy.deepcopy(parent[\'normalizedSpecTemplate\']);need(s[\'approval\']==\'EXACT_PARENT_MINIMAL_PIN\'and s[\'command\'][-1]==\'EXACT_PARENT_FULL_PIN_JSON\',\'two existing late parent-pin slots only\');s[\'approval\']={k:parent_ref[k]for k in(\'path\',\'bytes\',\'sha256\')};s[\'command\'][-1]=canonical(parent_ref)\n need(s[\'command\']==[\'sudo\',\'-n\',\'/usr/bin/python3\',\'-B\',parent[\'sourceRoles\'][\'runtime_entry\'][\'path\'],\'--parent-pin-json\',canonical(parent_ref)]and s[\'id\']==parent[\'jobId\']and s[\'cores\']==4 and s[\'memory\']==10737418240 and s[\'timeout_seconds\']==900 and \'omen-iommu-group-1\'in s[\'resources\'],\'exact ordinary entry and10GiB/4CPU/900s spec\')\n return s\n\ndef verify_inputs(request,io,boot,include_context=True):\n global NONCE\n if io.currentControl is None:need(request[\'leaseNonce\']==NONCE,\'exact historical input scope\')\n parent_path=io.currentControl[\'parentPin\'][\'path\']if io.currentControl is not None else\'/run/opemos-libvirt-parent-\'+NONCE+\'.json\'\n parentRaw,parentRef=io.read_path(parent_path,0o444,1048576);parent=decode(parentRaw)\n if io.currentControl is not None:\n  need(parentRef==io.currentControl[\'parentPin\']and request.get(\'currentControl\')==io.currentControl,\'whole current parent/request pin\')\n  if \'operationContext\'in parent[\'candidate\']:\n   paths=CURRENT_DEFINITION.candidate_paths(parent[\'candidate\']);need(parent[\'candidate\'][\'operationContext\'][\'deploymentId\']==io.definition[\'deployment\'][\'id\']and parent[\'candidate\'][\'lineageNonce\']==io.definition[\'guestNonce\']and parent[\'installedSourceContractPin\']==io.definitionPin and parent_path==paths[\'parentPath\'],\'same protected deployment/operation parent\');io.runtimeRoot=paths[\'runtimeRoot\'];io.placementRoot=paths[\'placementRoot\']\n NONCE=parent[\'nonce\'];need(request[\'leaseNonce\']==NONCE and request[\'domainName\']==\'opemos-libvirt-\'+NONCE,\'same protected current domain/scope\')\n cr=getattr(io,\'runtimeRoot\',\'/run/opemos-libvirt-runtime-\'+NONCE)+\'/context.json\'\n contextRaw=contextRef=context=None\n if include_context:\n  try:contextRaw,contextRef=io.read_path(cr,0o400,1048576);context=decode(contextRaw)\n  except FileNotFoundError:pass\n need(parent[\'kind\']==\'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT\'and parent[\'RootIssued\']is True and parent[\'runtimeAuthorized\']is True and parent.get(\'MODEL_ONLY\')is False and parent[\'bootID\']==boot and parent[\'nonce\']==NONCE and parent[\'contextPath\']==cr,\'existing actual same-boot Root parent; no issuance or clock refresh\')\n if context is not None:need(context[\'parentPin\']==parentRef and context[\'kind\']==\'ROOT_LIBVIRT_R4_RUNTIME_CONTEXT\'and context[\'runtimeAuthorized\']is True and context.get(\'MODEL_ONLY\')is False and context[\'candidate\']==parent[\'candidate\']and context[\'sourceRoles\']==parent[\'sourceRoles\'],\'Root context/candidate/source12 equality; no model promotion\')\n need(type(parent[\'candidate\'].get(\'installer\'))is dict and parent[\'candidate\'][\'installer\'].get(\'kind\')in(\'AUTHENTICATED_F9AA_RAW_RECOVERY_USB_FIRSTBOOT\',\'AUTHENTICATED_RETAINED_F9AA_READONLY_USB\')and parent[\'candidate\'][\'installer\'].get(\'noInstallTarget\')is True,\'this reviewed source branch admits only the retained installer/no target\')\n need(parent[\'issuedUnix\']<parent[\'startBeforeUnix\']<=parent[\'issuedUnix\']+300 and parent[\'wholeDeadlineUnix\']<=parent[\'issuedUnix\']+900,\'original finite parent scope retained; readonly closed observation does not reissue authority\')\n roles=parent[\'sourceRoles\'];need(set(roles)==ROLES,\'complete source12 membership\');compat=io.implementationPin is not None\n if compat:need(io.currentControl is not None and parent[\'installedSourceContractPin\']==io.definitionPin and roles==io.definition[\'sourceRoles\']and parent[\'queuePrograms\']==io.definition[\'queuePrograms\'],\'whole authenticated original V2 source/queue graph remains data\')\n need(compat or (roles[\'libvirt_peer\'][\'bytes\'],roles[\'libvirt_peer\'][\'sha256\'])in((PEER_BYTES,PEER_SHA),(ORIGINAL_PEER_BYTES,ORIGINAL_PEER_SHA))and (roles[\'libvirt_access\'][\'bytes\'],roles[\'libvirt_access\'][\'sha256\'])in((ACCESS_BYTES,ACCESS_SHA),(ORIGINAL_ACCESS_BYTES,ORIGINAL_ACCESS_SHA)),\'frozen reviewed peer/access implementation\')\n need(request[\'observer\']=={k:roles[\'libvirt_peer\'][k]for k in(\'path\',\'bytes\',\'sha256\')}and request[\'jobId\']==parent[\'jobId\'],\'exact original request observer/job\')\n source={}\n for name,ref in sorted(roles.items()):\n  need(ref[\'path\']==str(Path(roles[\'libvirt_peer\'][\'path\']).parent/(name+\'.py\')) and str(Path(roles[\'libvirt_peer\'][\'path\']).parent)in(SOURCE_ROOT,ORIGINAL_SOURCE_ROOT),\'same exact source namespace\');source[name]=io.read(ref,0o444,65536)\n  if not compat:compile(source[name],ref[\'path\'],\'exec\')\n spec=parent_spec(parent,parentRef);bound=spec[\'libvirt_domain\'];need(bound=={\'leaseNonce\':NONCE,\'name\':request[\'domainName\'],\'observer\':request[\'observer\'],\'uuid\':request[\'domainUUID\']}and hashlib.sha256(canonical(spec).encode()).hexdigest()==request[\'specSHA256\'],\'complete final normalized spec/hash/domain identity\')\n original=roles[\'libvirt_peer\'][\'sha256\']==ORIGINAL_PEER_SHA\n need(compat or (roles[\'libvirt_access\'][\'sha256\'],roles[\'libvirt_access\'][\'bytes\'])==((ORIGINAL_ACCESS_SHA,ORIGINAL_ACCESS_BYTES)if original else(ACCESS_SHA,ACCESS_BYTES)),\'one coherent original/current peer/access pair\')\n need(str(Path(roles[\'libvirt_peer\'][\'path\']).parent)==(ORIGINAL_SOURCE_ROOT if original else SOURCE_ROOT),\'same declared original/current source namespace\')\n need(not original or context is None,\'original R107 input supports no-grant qualification only\')\n need(original or roles[\'libvirt_peer\'][\'path\']==SOURCE_ROOT+\'/libvirt_peer.py\',\'current request requires exact new source namespace\')\n implementationRoot=io.implementationRoot if compat else SOURCE_ROOT\n implRaw,implRef=io.read_path(implementationRoot+\'/libvirt_peer.py\',0o444,65536)\n need(implRef[\'sha256\']==PEER_SHA and implRef[\'bytes\']==PEER_BYTES,\'separate exact current peer implementation\')\n accessRaw,accessRef=io.read_path(implementationRoot+\'/libvirt_access.py\',0o444,65536)\n need(accessRef[\'sha256\']==ACCESS_SHA and accessRef[\'bytes\']==ACCESS_BYTES,\'separate exact current access implementation\')\n need(compat or original or roles[\'libvirt_access\']==accessRef,\'new parent access is exact current implementation\')\n implementationSource={}\n if compat:\n  for name,ref in io.implementationDefinition[\'sourceRoles\'].items():\n   need(ref[\'path\']==io.implementationRoot+\'/\'+name+\'.py\',\'current implementation modules never execute original subject sources\')\n   implementationSource[name]=io.read(ref,0o444,65536)\n assignmentRef=grantRef=None;assignment=grant=None\n if context is not None:\n  assignmentRef=context[\'assignmentPin\'];need(assignmentRef[\'path\']==getattr(io,\'runtimeRoot\',\'/run/opemos-libvirt-runtime-\'+NONCE)+\'/assignment.json\'and context[\'grantPin\'][\'path\']==getattr(io,\'runtimeRoot\',\'/run/opemos-libvirt-runtime-\'+NONCE)+\'/child-grant.json\',\'two exact same-scope child control leaves\');assignment=decode(io.read(assignmentRef,0o400,1048576));grantRef=context[\'grantPin\'];grant=decode(io.read(grantRef,0o400,1048576))\n  need(assignment[\'kind\']==\'ROOT_CANONICAL_QUEUE_LIBVIRT_ASSIGNMENT_R4\'and assignment[\'request\']==request and grant[\'assignmentPin\']==assignmentRef and grant[\'parentPin\']==parentRef and grant[\'normalizedSpecSHA256\']==request[\'specSHA256\'],\'canonical assignment and child grant exact request/spec/parent\')\n  need(grant[\'queuePrograms\']==parent[\'queuePrograms\']and grant[\'sourcePlacementPin\']==context[\'sourcePlacementPin\']==parent[\'sourcePlacementPin\']and grant[\'placementQualificationPin\']==context[\'placementQualificationPin\']==parent[\'placementQualificationPin\'],\'current queue authority and placement pins across child/context/parent\')\n  need(grant[\'RootIssued\']is True and grant[\'MODEL_ONLY\']is False and grant[\'runtimeAuthorized\']is True and grant[\'jobId\']==request[\'jobId\']and grant[\'leaseNonce\']==NONCE and grant[\'bootID\']==boot and parent[\'issuedUnix\']<=grant[\'issuedUnix\']<grant[\'startBeforeUnix\']<=parent[\'startBeforeUnix\']and grant[\'wholeDeadlineUnix\']<=parent[\'wholeDeadlineUnix\'],\'existing finite Root child only, no new runtime grant\')\n io.placementRoot=placement_root(parent[\'candidate\'])\n return {\'implementationDefinitionPin\':io.implementationPin,\'implementationSource\':implementationSource,\'implementationRoles\':None if not compat else io.implementationDefinition[\'sourceRoles\'],\'implementationAccessRaw\':accessRaw,\'implementationAccessPin\':accessRef,\'implementationPeerRaw\':implRaw,\'implementationPeerPin\':implRef,\'originalInputOnly\':original,\'parent\':parent,\'parentPin\':parentRef,\'parentRaw\':parentRaw,\'context\':context,\'contextPin\':contextRef,\'contextRaw\':contextRaw,\'source\':source,\'assignmentPin\':assignmentRef,\'assignmentRaw\':None if assignment is None else canonical(assignment).encode(),\'grantPin\':grantRef,\'grantRaw\':None if grant is None else canonical(grant).encode()}\n\ndef _bind_placement(peer,parent,parent_ref,context,verify_access,implementation_definition=None):\n """Bind only the fresh protected same-source/same-scope metadata operand.\n Never changes the frozen peer\'s nonce, strict geometry or owner predicate.\n """\n nonce=parent[\'nonce\'];roles=parent[\'sourceRoles\'];candidate=parent[\'candidate\']\n if \'operationContext\'in candidate:__import__(\'source_contract\').bind_scope(peer,parent)\n peer.need(peer.SOURCE_PLACEMENT_NONCE==nonce and candidate[\'nonce\']==nonce and __import__(\'queue_assignment\').execution_job(candidate,parent)==parent[\'jobId\'],\'D23 unused scope only; D22 is consumed\')\n peer.need(parent[\'RootIssued\']is True and parent[\'kind\']==\'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT\'and parent[\'bootID\']==candidate[\'hostBoot\']and parent_ref[\'path\']==__import__(\'source_contract\').parent_paths(parent)[\'parentPath\'],\'existing exact Root parent/boot/source scope\')\n subject=__import__(\'source_contract\').validate(roles,parent[\'queuePrograms\'],parent[\'installedSourceContractPin\'])\n if implementation_definition is not None:\n  definition=__import__(\'source_contract\').read_definition(implementation_definition)\n  __import__(\'source_contract\').validate(definition[\'sourceRoles\'],definition[\'queuePrograms\'],implementation_definition)\n  peer.need(peer.__file__==definition[\'sourceRoles\'][\'libvirt_peer\'][\'path\']and definition[\'sourceRoles\'][\'libvirt_peer\'][\'sha256\']==PEER_SHA,\'actual separately authenticated current placement implementation\')\n  peer.need(roles==subject[\'sourceRoles\']and parent[\'queuePrograms\']==subject[\'queuePrograms\'],\'whole authenticated original subject graph remains data\')\n else:peer.need((roles[\'libvirt_peer\'][\'sha256\'],roles[\'libvirt_peer\'][\'bytes\'])in((PEER_SHA,PEER_BYTES),(ORIGINAL_PEER_SHA,ORIGINAL_PEER_BYTES))and (roles[\'libvirt_access\'][\'sha256\'],roles[\'libvirt_access\'][\'bytes\'])in((ACCESS_SHA,ACCESS_BYTES),(ORIGINAL_ACCESS_SHA,ORIGINAL_ACCESS_BYTES)),\'frozen exact D23 peer and unchanged access bytes\')\n for name,ref in roles.items():peer.need(ref[\'path\']==str(Path(roles[\'libvirt_peer\'][\'path\']).parent/(name+\'.py\'))and str(Path(roles[\'libvirt_peer\'][\'path\']).parent)in(SOURCE_ROOT,ORIGINAL_SOURCE_ROOT)and ref[\'identity\'][\'st_uid\']==ref[\'identity\'][\'st_gid\']==0 and stat.S_IMODE(ref[\'identity\'][\'st_mode\'])==0o444 and ref[\'identity\'][\'st_nlink\']==1,\'same immutable Root source12 namespace\')\n ref=parent[\'sourcePlacementPin\'];qr=parent[\'placementQualificationPin\'];root=placement_root(candidate)\n if \'operationContext\'in candidate:__import__(\'source_contract\').bind_scope(peer,parent)\n peer.need(ref[\'path\']==root+\'/storage-contract.json\'and qr[\'path\']==root+\'/placement-qualified.json\',\'fresh exact placement+qualification names, no historical receipt\')\n files=peer.RootFiles(root);primary=None;result=None\n try:\n  files.__enter__()\n  raw,actual=files.read(\'storage-contract.json\');qualified,qactual=files.read(\'placement-qualified.json\');peer.need(actual==ref and qactual==qr,\'fresh placement/qualification exact full9/EOF/SHA\')\n  value=json.loads(raw);q=json.loads(qualified);b=value[\'preparationBinding\']\n  peer.need(value[\'kind\']==(\'ROOT_EXACT_STEAMOS_INSTALLER_GAMES_PLACEMENT\'if candidate.get(\'installer\')is not None else\'ROOT_EXACT_STEAMOS_FIXED_GAMES_PLACEMENT\')and value[\'nonce\']==nonce and value[\'boot\']==parent[\'bootID\']and value[\'original\']==candidate[\'original\']and value[\'working\']==candidate[\'working\']and value.get(\'installer\')==candidate.get(\'installer\'),\'same current prepared working placement, no relabel\')\n  peer.need(b[\'sourceRoles\']==roles and b[\'queuePrograms\']==parent[\'queuePrograms\']and b[\'sourceGraphSHA256\']==hashlib.sha256(peer.canon(roles)).hexdigest(),\'placement producer source12/current queue equality\')\n  peer.need(q[\'kind\']==\'ROOT_VERIFIED_FRESH_STEAMOS_PLACEMENT\'and q[\'qualifiedPlacementPin\']==ref and q[\'nonce\']==nonce and q[\'bootID\']==parent[\'bootID\']and q[\'sourceRoles\']==roles and q[\'queuePrograms\']==parent[\'queuePrograms\']and q[\'runtimeAuthorized\']is False and q[\'RootIssuedRuntimeAuthority\']is False,\'complete fresh protected metadata qualification, not a runtime grant\')\n  pre=q[\'currentPreflight\'];prepared=parent[\'preparedDiskPins\'];access_pin=parent[\'preparedAccessPin\']\n  peer.need(type(prepared)is dict and set(prepared)=={\'original\',\'working\'}and prepared[\'original\']==candidate[\'original\']and b[\'preparedDiskPins\']==prepared and access_pin is not None and b[\'preparedAccessPin\']==access_pin==pre[\'preparedAccessPin\']and b[\'splitDiskCapturePins\']==parent[\'splitDiskCapturePins\']==pre[\'splitDiskCapturePins\'],\'exact candidate/pending-access/post-ACL prepared captures/final-preflight lineage\')\n  work=prepared[\'working\'];before_work=candidate[\'working\'];peer.need(work[\'path\']==before_work[\'path\']and work[\'bytes\']==before_work[\'bytes\']and work[\'sha256\']==before_work[\'sha256\']and all(work[\'identity\'][k]==before_work[\'identity\'][k]for k in(\'st_dev\',\'st_ino\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\')),\'same content and stable pre/post ACL working object; full9 remains exact within each epoch\')\n  verify_access(candidate,access_pin,prepared)\n  peer.need(q[\'currentPreflightPin\']==parent[\'prequeuePreflightPin\']and pre[\'bootID\']==parent[\'bootID\']and pre[\'storagePlacement\'][\'receiptPin\']==ref and pre[\'queuePrograms\']==parent[\'queuePrograms\']and pre[\'original\']==candidate[\'original\']and pre[\'kind\']==\'ACTUAL_LIBVIRT_R4_CURRENT_PREFLIGHT\'and pre[\'working\']==prepared[\'working\']and 0<=parent[\'issuedUnix\']-pre[\'observedUnix\']<=30,\'existing normal complete current preflight joins placement before parent issuance\')\n  if context is not None:peer.need(context[\'parentPin\']==parent_ref and context[\'candidate\']==candidate and context[\'sourceRoles\']==roles and context[\'sourcePlacementPin\']==ref and context[\'placementQualificationPin\']==qr,\'context/parent/source12/placement equality\')\n  peer.need(peer.SOURCE_PLACEMENT_PIN is None or peer.SOURCE_PLACEMENT_PIN==ref,\'never replace a different bound placement operand\')\n  again,again_pin=files.read(\'storage-contract.json\');again_q,again_qpin=files.read(\'placement-qualified.json\');peer.need((again,again_pin)==(raw,ref)and(again_q,again_qpin)==(qualified,qr),\'original held/named placement and qualification full9/raw-SHA unchanged after prepared verification\')\n  result={\'placementPin\':ref,\'qualificationPin\':qr,\'sourceGraphSHA256\':b[\'sourceGraphSHA256\'],\'runtimeAuthorityIssued\':False}\n except BaseException as error:primary=error\n finally:\n  try:files.__exit__(None if primary is None else type(primary),primary,None)\n  except BaseException as close:\n   if primary is None:primary=close\n   else:primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'role\':\'bind-placement-ancestors\',\'type\':type(close).__name__,\'reason\':str(close)}]\n if primary is not None:raise primary\n peer.SOURCE_PLACEMENT_PIN=ref\n return result\n\ndef bind_placement(peer,parent,parent_ref,context=None):\n from libvirt_access import verify_prepared\n return _bind_placement(peer,parent,parent_ref,context,verify_prepared)\n\ndef bind_observer_placement(peer,parent,parent_ref,context,implementation_definition=None):\n from libvirt_access import prepared_lineage\n return _bind_placement(peer,parent,parent_ref,context,prepared_lineage,implementation_definition)\n\n@contextlib.contextmanager\ndef load_pair(v):\n names=(\'libvirt_storage\',\'retained_media\',\'source_contract\',\'libvirt_peer\',\'libvirt_access\',\'guest_firmware_probe\',\'libvirt_native\',\'queue_assignment\');missing=object();previous={k:sys.modules.get(k,missing)for k in names}\n try:\n  roles=v[\'implementationRoles\']if v[\'implementationDefinitionPin\']is not None else v[\'parent\'][\'sourceRoles\'];modules={}\n  for name in names:\n   module=types.ModuleType(name);module.__file__=roles[name][\'path\'];sys.modules[name]=module;modules[name]=module\n  for name in names:\n   module=modules[name];body=v[\'implementationSource\'][name]if v[\'implementationDefinitionPin\']is not None else v[\'implementationPeerRaw\']if name==\'libvirt_peer\'else v[\'implementationAccessRaw\']if name==\'libvirt_access\'else v[\'source\'][name];module.__file__=v[\'implementationPeerPin\'][\'path\']if name==\'libvirt_peer\'else v[\'implementationAccessPin\'][\'path\']if name==\'libvirt_access\'else module.__file__;exec(compile(body,module.__file__,\'exec\'),module.__dict__)\n  if v[\'implementationDefinitionPin\']is not None:\n   definition=modules[\'source_contract\'].read_definition(v[\'implementationDefinitionPin\']);modules[\'source_contract\'].validate(definition[\'sourceRoles\'],definition[\'queuePrograms\'],v[\'implementationDefinitionPin\'])\n  yield modules[\'libvirt_peer\'],modules[\'libvirt_access\']\n finally:\n  for name,old in previous.items():\n   if old is missing:sys.modules.pop(name,None)\n   else:sys.modules[name]=old\n\ndef run(request,io,boot):\n v0=verify_inputs(request,io,boot,False)\n with load_pair(v0)as(peer,access):\n  with access.runtime_snapshot(v0[\'parent\'],v0[\'parentPin\'],request,time.monotonic()+14,io)as snapshot:\n   v=verify_inputs(request,io,boot);need(v[\'parentPin\']==v0[\'parentPin\']and v[\'source\']==v0[\'source\'],\'unchanged immutable sources across runtime SH acquisition\')\n   with contextlib.ExitStack()as custody:\n    heldPlacement=custody.enter_context(io.hold_placement(v[\'parent\'][\'sourcePlacementPin\']));heldQualification=custody.enter_context(io.hold_placement(v[\'parent\'][\'placementQualificationPin\']))\n    if io.implementationPin is None:peer.validate_request(request)\n    binding=bind_observer_placement(peer,v[\'parent\'],v[\'parentPin\'],v[\'context\'],io.implementationPin);need(binding[\'placementPin\']==heldPlacement[\'ref\']and binding[\'qualificationPin\']==heldQualification[\'ref\'],\'binding consumes the two retained exact placement pins\')\n    parent=v[\'parent\'];candidate=parent[\'candidate\']\n    def custody(phase,intent,reg,state,files):return access.verify_phase(candidate,parent[\'preparedAccessPin\'],parent[\'preparedDiskPins\'],phase,intent,reg,state,files)\n    proof=peer.observe_closed_subject(request,io.implementationPin,custody=custody)if io.implementationPin is not None else peer.observe(request,custody=custody)\n    need(not v[\'originalInputOnly\']or proof[\'phase\']==\'NOT_PREPARED\',\'old R107 request cannot adopt a current runtime phase\')\n    need(proof.get(\'accessCustody\',{}).get(\'phase\')==proof[\'phase\'],\'actual locked phase access custody required\')\n    proof[\'accessCustody\']={\'kind\':\'ROOT_PHASE_PREPARED_ACCESS_CUSTODY_R1\',\'phase\':proof[\'phase\'],\'nonce\':NONCE,\'bootID\':boot,\'requestSHA256\':hashlib.sha256(peer.canon(request)).hexdigest(),\'parentPin\':v[\'parentPin\'],\'preparedAccessPin\':parent[\'preparedAccessPin\'],\'preparedDiskPins\':parent[\'preparedDiskPins\'],\'sourceGraphSHA256\':binding[\'sourceGraphSHA256\'],\'placementPin\':binding[\'placementPin\'],\'qualificationPin\':binding[\'qualificationPin\'],\'stage\':access.prepared_lineage(candidate,parent[\'preparedAccessPin\'],parent[\'preparedDiskPins\']),\'stageRawBase64\':__import__(\'base64\').b64encode(__import__(\'libvirt_native\').held(parent[\'preparedAccessPin\'],1048576)).decode(\'ascii\'),\'data\':proof[\'accessCustody\']}\n    need(v[\'context\']is not None or proof[\'phase\']==\'NOT_PREPARED\',\'missing context permits only actual NOT_PREPARED, never ACTIVE/CLOSED\')\n    need(proof[\'request\']==request and proof[\'sourceSHA256\']==request[\'observer\'][\'sha256\'] and proof[\'phase\']in(\'NOT_PREPARED\',\'PREPARED\',\'ACTIVE\',\'CLOSED\')and proof[\'allOwnedDescriptorsClosed\']is True and proof[\'effects\']==[],\'unchanged complete readonly observer proof and closure\')\n    # Every complete source and protected control is reread after observer use.\n    for name,ref in v[\'parent\'][\'sourceRoles\'].items():need(io.read(ref,0o444,65536)==v[\'source\'][name],\'post-use exact source12 bytes\')\n    need(io.read(v[\'parentPin\'],0o444,1048576)==v[\'parentRaw\'],\'post-use exact parent bytes\')\n    if v[\'context\']is not None:\n     need(io.read(v[\'contextPin\'],0o400,1048576)==v[\'contextRaw\'],\'post-use exact context bytes\');io.read(v[\'assignmentPin\'],0o400,1048576);io.read(v[\'grantPin\'],0o400,1048576)\n    else:\n     try:io.read_path(getattr(io,\'runtimeRoot\',\'/run/opemos-libvirt-runtime-\'+NONCE)+\'/context.json\',0o400,1048576)\n     except FileNotFoundError:pass\n     else:raise RuntimeError(\'context absence changed during exact NOT_PREPARED observation; no retry\')\n    heldPlacement[\'recheck\']();heldQualification[\'recheck\']()\n    result={\'kind\':\'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION\',\'upstreamObserver\':v[\'parent\'][\'sourceRoles\'][\'libvirt_peer\'],\'implementation\':{\'actualAccessImplementation\':v[\'implementationAccessPin\'],\'actualPeerImplementation\':v[\'implementationPeerPin\'],\'contract\':CONTRACT,\'peer\':v[\'parent\'][\'sourceRoles\'][\'libvirt_peer\'],\'access\':v[\'parent\'][\'sourceRoles\'][\'libvirt_access\'],\'sourceRoles\':v[\'parent\'][\'sourceRoles\'],\'parent\':v[\'parentPin\'],\'context\':v[\'contextPin\'],\'assignment\':v[\'assignmentPin\'],\'grant\':v[\'grantPin\'],\'placementBinding\':binding,\'runtimePublication\':snapshot,\'borrowedRunCustody\':io.runProof},\'proof\':proof,\'effects\':[]}\n    if io.implementationPin is not None:result[\'implementation\'].update(contract=\'CURRENT_NORMAL_CLOSED_SUBJECT_V1\',implementationDefinitionPin=io.implementationPin)\n    need(io.read(v[\'implementationPeerPin\'],0o444,65536)==v[\'implementationPeerRaw\']and io.read(v[\'implementationAccessPin\'],0o444,65536)==v[\'implementationAccessRaw\'],\'held current pair reread after full observation\')\n    io.check()\n need(snapshot[\'readLockClosed\']is True,\'actual runtime read lock closed\');need(len(canonical(result).encode())+1<=1048576,\'unchanged whole Root1MiB envelope\');return result\n\ndef main():\n compat=len(sys.argv)==6 and sys.argv[4]==\'--implementation-definition-pin-json\'and re.fullmatch(\'[0-9a-f]{64}\',sys.argv[1])is not None\n need(os.getuid()==0 and (compat or len(sys.argv)==4 and sys.argv[1]in(PEER_SHA,ORIGINAL_PEER_SHA))and sys.argv[2]==\'--queue-libvirt-request-json\',\'exact existing Root standalone queue argv\')\n request=json.loads(sys.argv[3]);before=set(os.listdir(\'/proc/self/fd\'))\n with RootInputs(request.get(\'currentControl\'),json.loads(sys.argv[5])if compat else None)as io:result=run(request,io,Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip())\n need(before==set(os.listdir(\'/proc/self/fd\')),\'adapter full owned FD closure\');print(canonical(result),flush=True)\nif __name__==\'__main__\':\n try:main()\n except BaseException as e:\n  print(canonical({\'kind\':\'QUEUE_LIBVIRT_FIRST_REFUSAL\',\'type\':type(e).__name__,\'reason\':str(e),\'effects\':[],\'evidence\':getattr(e,\'evidence\',None),\'workingEvidence\':getattr(e,\'workingEvidence\',None),\'placementCustody\':getattr(e,\'placementCustody\',None),\'runtimePublication\':getattr(e,\'runtimePublication\',None),\'rootInputCloseErrors\':getattr(e,\'ownedRootInputClosureErrors\',[]),\'rootFilesCloseErrors\':getattr(e,\'rootFilesCloseErrors\',[]),\'lockCloseErrors\':getattr(e,\'lockCloseErrors\',[]),\'ownedPlacementCloseErrors\':getattr(e,\'ownedPlacementCloseErrors\',[]),\'traceback\':traceback.format_exc()}),file=sys.stderr,flush=True);sys.exit(1)\n'
CLOSED_SUBJECT_PEERS={'9e5516fcdf57624d786a91741066998605045fe145ce60fbe8bde68f5b494bdd':61355,'224aa4a8b06999e318350267195cc681a095aaf2a2b5e407552f8811673a8614':61400}
def libvirt_request(row,bound):
    spec=json.loads(row['spec']);v=spec.get('libvirt_domain')
    if v is None:return None
    require(spec['cores']==4 and spec['memory']==LIBVIRT_RESERVATION_MEMORY and NVIDIA_RESOURCE in spec['resources'],'One4CPU10GiB exclusive GPU reservation')
    require(bound is not None and bound['job_id']==row['id'] and bound['unit']==row['unit'] and bound['specSHA256']==hashlib.sha256(canonical(spec).encode()).hexdigest(),'Current immutable queue binding')
    require(type(bound['invocation'])is str and re.fullmatch(r'[0-9a-f]{32}',bound['invocation']),'Current queue InvocationID')
    token=row['unit'].rsplit('-',1)[1].removesuffix('.service');require(re.fullmatch(r'[0-9a-f]{32}',token),'Current queue job token')
    require(bound['cpus']==json.loads(row['cpus']) and len(bound['cpus'])==4 and len(set(bound['cpus']))==4,'Exact four assigned CPUs')
    vm='opemos-vm-pool-libvirt'+token+'.slice'
    request={'jobId':row['id'],'jobToken':token,'unit':row['unit'],'invocation':bound['invocation'],'specSHA256':bound['specSHA256'],'domainUUID':v['uuid'],'domainName':v['name'],'leaseNonce':v['leaseNonce'],'cpus':bound['cpus'],'controllerMemory':LIBVIRT_CONTROLLER_MEMORY,'domainMemory':LIBVIRT_DOMAIN_MEMORY,'reservationMemory':LIBVIRT_RESERVATION_MEMORY,'vmSlice':vm,'partition':'/opemos/vm/pool/libvirt'+token,'gpuGroup':NVIDIA_RESOURCE,'observer':v['observer']}
    definition=__import__('source_contract').current_from_queue(__file__)
    if definition is not None:
        ref,value=definition
        parent_ref=json.loads(spec['command'][-1]);parent=installer_root_value(parent_ref,0o444,1048576)
        subject_ref=parent['installedSourceContractPin']
        if subject_ref!=ref:
            subject=__import__('source_contract').validate(parent['sourceRoles'],parent['queuePrograms'],subject_ref)
            require(parent['jobId']==row['id']and parent['candidate']['jobId']==row['id']and parent['normalizedSpecTemplate']['libvirt_domain']==v and parent['sourceRoles']['libvirt_peer']==subject['sourceRoles']['libvirt_peer']and v['observer']=={k:subject['sourceRoles']['libvirt_peer'][k]for k in('path','bytes','sha256')},'complete immutable original subject definition/spec/observer')
        else:require(parent['jobId']==row['id']and value['sourceRoles']['libvirt_peer']['path']==v['observer']['path'],'normal canonical parent/current controller definition')
        request['currentControl']={'definitionPin':subject_ref,'parentPin':parent_ref}
    return request

def borrowed_run_pair(a,b,o):
 try:
  x=a['runAncestry'];y=b['runAncestry'];keys={'named','info','ns','observer','parent'}|({'epochs'}if o['sha256']!=BORROWED_PEER_INPUT_SHA else set())
  for r,p in((a,x),(b,y)):
   require(set(p)==keys and p['observer']==o and (all(p['named'][k]==r['identity'][k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid'))if 'epochs'in p else p['named']==r['identity'])and r['target']=='/run'and r['identity']['st_mode']==0o40755 and r['identity']['st_uid']==r['identity']['st_gid']==0,'run proof');u=dict(z.split(':',1)for z in r['fdinfo'].splitlines()if ':'in z);v=dict(z.split(':',1)for z in p['info'].splitlines()if ':'in z);require(len(r['fdinfo'].splitlines())==len(p['info'].splitlines())==4 and set(u)==set(v)=={'pos','flags','mnt_id','ino'},'run facts');flags=int(r['flags'],8);require(flags in(0o2700000,0o12600000)and int(v['flags'],8)==0o12600000 and not r['eventfdID']and u['flags'].strip()==r['flags']and u['mnt_id'].strip()==v['mnt_id'].strip()and u['ino'].strip()==v['ino'].strip()==str(r['identity']['st_ino']),'run mount')
  return all(a[k]==b[k]for k in('fd','target','flags','eventfdID','fdinfo'))and all(a['identity'][k]==b['identity'][k]for k in (('st_dev','st_ino','st_mode','st_uid','st_gid')if 'epochs'in x else('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')))and all(x[k]==y[k]for k in('ns','parent'))
 except(KeyError,TypeError,ValueError,ValueError):return False

def borrowed_fd_key(row):return {k:row[k]for k in('fd','identity','target','flags','eventfdID')}

def borrowed_fd_changes(before,after):
 aa={r['fd']:r for r in before['rows']};bb={r['fd']:r for r in after['rows']};a={n:borrowed_fd_key(r)for n,r in aa.items()};b={n:borrowed_fd_key(r)for n,r in bb.items()};borrowed=before['label']=='readonly-observe-before'and after['label']=='readonly-observe-after'and before.get('borrowedObserver')==after.get('borrowedObserver')and before.get('borrowedObserver')is not None
 return {'added':[b[n]for n in sorted(b.keys()-a.keys())],'removed':[a[n]for n in sorted(a.keys()-b.keys())],'replaced':[{'before':a[n],'after':b[n]}for n in sorted(a.keys()&b.keys())if (not borrowed_run_pair(aa[n],bb[n],before['borrowedObserver'])if borrowed and aa[n]['target']==bb[n]['target']=='/run'else a[n]!=b[n])]}

def validate_readonly_fd_custody(value,proof,request):
    require(type(value)is dict and set(value)=={'kind','before','after','changes','closeOutcomes'}and value['kind']=='ROOT_READONLY_FD_LIFETIME_R240','closed bounded readonly FD evidence')
    fields={'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'}
    def identity(v):
        require(type(v)is dict and set(v)==fields and all(type(n)is int and n>=0 for n in v.values()),'complete typed FD full9')
    def snapshot(v,label,ancestry):
        require(type(v)is dict and set(v)=={'label','actor','atUnix','rows','vanishedDuringFDList'}|({'borrowedObserver'}if ancestry else set())and v['label']==label and v['actor']==proof['producer']and type(v['atUnix'])in(int,float),'exact FD actor and label')
        if ancestry:require(v['borrowedObserver']==request['observer'],'bound borrowed observer input')
        rows=v['rows'];require(type(rows)is list and len(rows)<=256 and len({r['fd']for r in rows})==len(rows),'finite unique FD inventory')
        require(type(v['vanishedDuringFDList'])is list and all(type(n)is int and n>=0 for n in v['vanishedDuringFDList'])and not set(v['vanishedDuringFDList'])&{r['fd']for r in rows},'retained list-race evidence')
        for r in rows:
            anchored=ancestry and r['target']=='/run'
            require(type(r)is dict and set(r)=={'fd','identity','target','flags','eventfdID','fdinfo'}|({'runAncestry'}if anchored else set())and type(r['fd'])is int and r['fd']>=0,'closed FD row schema')
            identity(r['identity']);require(type(r['target'])is str and len(r['target'])<=4096 and type(r['fdinfo'])is str and len(r['fdinfo'])<=8192 and type(r['flags'])is str and re.fullmatch('[0-7]+',r['flags'])is not None and type(r['eventfdID'])is str,'bounded complete FD facts')
            if anchored:
                p=r['runAncestry'];require(type(p)is dict and set(p)==({'named','info','ns','observer','parent'}|({'epochs'}if request['observer']['sha256']!=BORROWED_PEER_INPUT_SHA else set()))and p['observer']==request['observer']and type(p['info'])is str and len(p['info'])<=8192 and re.fullmatch(r'mnt:\[[0-9]+\]',p['ns'])is not None,'positive kernel run ancestry only')
                identity(p['named']);identity(p['parent']);parent=p['parent'];path=Path(request['observer']['path'])
                if request['observer']['sha256']!=BORROWED_PEER_INPUT_SHA:
                    require(set(p['epochs'])=={'snapshot','anchored','named','held'}and p['epochs']['snapshot']==r['identity'],'all raw run epochs retained')
                    for e in p['epochs'].values():identity(e);require(all(e[k]==r['identity'][k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid')),'same positively anchored run epoch core')
                require(path.name=='libvirt_peer.py'and path.parent.parent==Path('/run')and (path.parent==Path(closed_subject_source_root(request))if 'currentControl'in request or request['observer']['sha256']in CLOSED_SUBJECT_PEERS else path.parent in(Path(current_source_root()),Path(R109_ORIGINAL_SOURCE_ROOT))if request['observer']['sha256']in(R109_PEER_SHA,R109_ORIGINAL_PEER_SHA)else re.fullmatch('opemos-steamos-source-[0-9a-f]{32}',path.parent.name)is not None) and stat.S_ISDIR(parent['st_mode'])and parent['st_uid']==parent['st_gid']==0 and not parent['st_mode']&0o022,'protected source ancestry')
    snapshot(value['before'],'readonly-observe-before',True);snapshot(value['after'],'readonly-observe-after',True)
    require(value['before']['atUnix']<=value['after']['atUnix'],'ordered actual FD cuts')
    changes=borrowed_fd_changes(value['before'],value['after']);require(value['changes']==changes==dict(added=[],removed=[],replaced=[]),'all FD lifetime identities stable; only proven shared-run epochs')
    outcomes=value['closeOutcomes'];require(type(outcomes)is list and len(outcomes)==1,'finite actual native close outcomes')
    for close in outcomes:
        require(type(close)is dict and set(close)=={'before','after','numeric','primary'}and close['numeric']==0 and close['primary']is None,'actual numeric native close and no primary')
        snapshot(close['before'],'readonly-before-close',False);snapshot(close['after'],'readonly-after-close',False)
    return value

def closed_subject_source_root(request):
    control=request['currentControl'];parent=installer_root_value(control['parentPin'],0o444,1048576)
    require(parent['installedSourceContractPin']==control['definitionPin']and parent['jobId']==request['jobId']and parent['candidate']['nonce']==request['leaseNonce'],'same original closed subject parent/job/nonce')
    definition=__import__('source_contract').validate(parent['sourceRoles'],parent['queuePrograms'],control['definitionPin'])
    candidate=parent['candidate'];paths=__import__('source_contract').candidate_paths(candidate)
    require(candidate['operationContext']['deploymentId']==definition['deployment']['id']and candidate['lineageNonce']==definition['guestNonce']and control['parentPin']['path']==paths['parentPath'],'same authenticated original deployment/guest/operation namespace')
    ref=parent['sourceRoles']['libvirt_peer']
    require(0<ref['bytes']<=65536 and request['observer']=={k:ref[k]for k in('path','bytes','sha256')},'whole authenticated unchanged original V2 observer')
    template=json.loads(json.dumps(parent['normalizedSpecTemplate']));require(template['approval']=='EXACT_PARENT_MINIMAL_PIN'and template['command'][-1]=='EXACT_PARENT_FULL_PIN_JSON','original V2 parent late slots');template['approval']={k:control['parentPin'][k]for k in('path','bytes','sha256')};template['command'][-1]=canonical(control['parentPin'])
    require(template['id']==request['jobId']and hashlib.sha256(canonical(template).encode()).hexdigest()==request['specSHA256']and template['libvirt_domain']=={'uuid':request['domainUUID'],'name':request['domainName'],'leaseNonce':request['leaseNonce'],'observer':request['observer']},'whole original V2 job/spec/domain binding')
    return definition['deployment']['paths']['sourceRoot']

def closed_subject_implementation(request,implementation_pin):
    """One classification for structured original DATA and current code."""
    if 'currentControl'not in request:return request['observer']['sha256']in CLOSED_SUBJECT_PEERS
    closed_subject_source_root(request)
    current=__import__('source_contract').current_from_queue(__file__)
    require(current is not None,'actual current queue V2 implementation')
    subject=request['currentControl']['definitionPin']
    require(subject==current[0]or implementation_pin is not None,'explicit current implementation for original V2 subject')
    if implementation_pin is not None:require(implementation_pin==current[0],'separately pinned actual current V2 implementation')
    return subject!=current[0]

def validate_libvirt_observation(proof,request,started,implementation_definition_pin=None):
    fields={'kind','request','bootID','producer','sourceSHA256','startedMonotonic','completedMonotonic','phase','scope','leader','intentPin','intentParentPin','lease','domainUUID','persistent','noNIC','fullDomainEnumeration','allOwnedDescriptorsClosed','effects'}
    current_raw=request['observer']['sha256']in(R109_PEER_SHA,R109_ORIGINAL_PEER_SHA)
    compat=closed_subject_implementation(request,implementation_definition_pin)
    if compat:
        require(implementation_definition_pin is not None,'explicit current implementation for closed subject observation')
        definition=__import__('source_contract').read_definition(implementation_definition_pin)
        __import__('source_contract').validate(definition['sourceRoles'],definition['queuePrograms'],implementation_definition_pin)
        require(definition['queuePrograms'][0]['path']==__file__,'actual current queue observation implementation')
        closed_subject_source_root(request);current_raw=True
    elif current_raw:
        require(request['observer']=={'path':(current_source_root() if request['observer']['sha256']==R109_PEER_SHA else R109_ORIGINAL_SOURCE_ROOT)+'/libvirt_peer.py','bytes':R109_PEER_BYTES if request['observer']['sha256']==R109_PEER_SHA else 64727,'sha256':request['observer']['sha256']}and(request['observer']['sha256']==R109_PEER_SHA or proof.get('phase')=='NOT_PREPARED'),'exact current source; preserved original no-grant input only')
    installer=request['observer']['sha256']in(INSTALLER_PEER_SHA,SOURCE201_PEER_SHA,BORROWED_PEER_INPUT_SHA,SOURCE247_PEER_INPUT_SHA)
    installer=installer or current_raw
    if installer:fields=fields|{'accessCustody'}
    borrowed=request['observer']['sha256']in(SOURCE201_PEER_SHA,BORROWED_PEER_INPUT_SHA,SOURCE247_PEER_INPUT_SHA)
    borrowed=borrowed or current_raw
    if borrowed:fields=fields|{'readonlyFDCustody'}
    current_ancestry=request['observer']['sha256']in(SOURCE201_PEER_SHA,SOURCE247_PEER_INPUT_SHA)
    current_ancestry=current_ancestry or current_raw
    if current_ancestry:fields=fields|{'rootAncestorCustody'}
    require(type(proof)is dict and set(proof)==fields and proof['kind']=='ROOT_CURRENT_EXACT_QUEUE_LIBVIRT_DOMAIN_R1','Closed libvirt observation schema')
    require(proof['request']==request and proof['sourceSHA256']==request['observer']['sha256'],'Exact source/request domain observation')
    require(proof['bootID']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Current same-host boot')
    require(proof['producer']['uid']==0 and type(proof['producer']['pid'])is int and type(proof['producer']['start'])is int,'Genuine pinned Root observer principal')
    require(started<=proof['startedMonotonic']<=proof['completedMonotonic']<=time.monotonic() and time.monotonic()-proof['completedMonotonic']<=1,'Current same-host domain observation')
    require(proof['domainUUID']==request['domainUUID'] and proof['persistent']is False and proof['noNIC']is True and proof['fullDomainEnumeration']is True and proof['allOwnedDescriptorsClosed']is True and proof['effects']==[],'Exact transient noNIC closed readonly domain observation')
    if borrowed:validate_readonly_fd_custody(proof['readonlyFDCustody'],proof,request)
    root_ancestry=validate_generated_scope_ancestry(proof['rootAncestorCustody'],proof,request)if current_ancestry else None
    access=validate_installer_access_custody(proof['accessCustody'],proof,request)if installer else None
    if compat:require(proof['phase']=='CLOSED','original subject actual CLOSED/current implementation only')
    if proof['phase']=='NOT_PREPARED':
        require(proof['scope']is None and proof['leader']is None and proof['intentPin']is None and proof['intentParentPin']is None and proof['lease']is None,'No invented pre-intent/domain/lease identity')
        return ({k:proof[k]for k in ('request','phase','scope','leader','domainUUID','persistent','noNIC','intentPin','intentParentPin','lease')}|({'accessCustody':access}if installer else{}))|({'rootAncestorCustody':root_ancestry}if current_ancestry else{})
    fields9=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    for key,suffix,mode in [('intentPin','/intent.json',0o400),('intentParentPin','',0o700)]:
        p=proof[key];expected='/run/opemos-libvirt-queue-'+request['jobToken']+suffix
        require(set(p)=={'path','bytes','sha256','identity'} and p['path']==expected and re.fullmatch(r'[0-9a-f]{64}',p['sha256'])is not None and set(p['identity'])==set(fields9),'Exact protected libvirt intent pin')
        i=p['identity'];require(i['st_uid']==i['st_gid']==0 and i['st_mode']&0o777==mode and (i['st_mode']&0o170000)==(0o100000 if suffix else 0o040000) and (not suffix or i['st_nlink']==1),'Root protected intent custody')
    lease=proof['lease'];require(set(lease)=={'group','nonce','jobId','headPin','statePin','closed','restored','currentBoot'}and lease['group']==NVIDIA_RESOURCE and lease['nonce']==request['leaseNonce']and lease['jobId']==request['jobId']and lease['currentBoot']==proof['bootID'],'Exact same-job GPU lease')
    for k in ('headPin','statePin'):
        p=lease[k];i=p['identity'];require(p['path'].startswith('/run/opemos-vfio-'+request['leaseNonce']+'/')and i['st_uid']==i['st_gid']==0 and i['st_mode']&0o777==0o400 and i['st_nlink']==1 and re.fullmatch(r'[0-9a-f]{64}',p['sha256'])is not None,'Root current GPU lease fullpin')
    require(type(lease['closed'])is bool and type(lease['restored'])is bool and proof['phase']in('PREPARED','ACTIVE','CLOSED'),'Typed current libvirt phase/lease')
    if proof['phase']=='ACTIVE':
        require(type(proof['scope'])is str and len(proof['scope'])<=255 and re.fullmatch(r'machine-[A-Za-z0-9_.\\-]+\.scope',proof['scope']),'Exact observed systemd machine scope')
        leader=proof['leader'];require(type(leader)is dict and set(leader)=={'pid','start','uid'} and all(type(leader[k])is int for k in leader)and leader['pid']>0 and leader['start']>0 and leader['uid']>=0 and lease['closed']is False,'Live exact domain leader and open own lease')
    else:
        require(proof['scope']is None and proof['leader']is None,'No invented inactive machine identity')
        if proof['phase']=='CLOSED':require(lease['closed']is True and lease['restored']is True,'Domain and all four host functions must be closed/restored before queue release')
    return ({k:proof[k]for k in ('request','phase','scope','leader','domainUUID','persistent','noNIC','intentPin','intentParentPin','lease')}|({'accessCustody':access}if installer else{}))|({'rootAncestorCustody':root_ancestry}if current_ancestry else{})

REVIEWED_PEER_IMPLEMENTATION_SHA256='abb5a30b7eae786540aa04333f4e2c9427cbba1d90776fc304bf1a65cb8329cb'
REVIEWED_PEER_INPUTS={'ddeb1e163152fae54ea4446083c58f4f96d582ff65983a960187cacb5f32afb7':39195,'abb5a30b7eae786540aa04333f4e2c9427cbba1d90776fc304bf1a65cb8329cb':40019}
REVIEWED_PEER_ROOT_ADAPTER='import os,sys,json,hashlib,stat,traceback\nPEER_SOURCE=\'"""Exact readonly peer for queue_libvirt_functions.py R1; no effect methods.\\n\\nCLI executes only this verified source under the queue\\\'s existing sudo route.\\nRoot intent and phase/lease heads are separately protected, locked and reread.\\nThe native adapters never treat model data or PID absence as a live domain.\\n"""\\nimport contextlib,fcntl,hashlib,json,os,re,stat,sys,time,traceback\\nimport xml.etree.ElementTree as ET\\nfrom pathlib import Path\\nFIELDS=(\\\'st_dev\\\',\\\'st_ino\\\',\\\'st_mode\\\',\\\'st_uid\\\',\\\'st_gid\\\',\\\'st_nlink\\\',\\\'st_size\\\',\\\'st_mtime_ns\\\',\\\'st_ctime_ns\\\')\\nCORE=(\\\'st_dev\\\',\\\'st_ino\\\',\\\'st_mode\\\',\\\'st_uid\\\',\\\'st_gid\\\',\\\'st_nlink\\\')\\nPOOL=\\\'/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice\\\'\\nGROUP=\\\'omen-iommu-group-1\\\'\\nNS=\\\'urn:opemos:steamos:libvirt:2\\\'\\n\\nclass Refused(RuntimeError):pass\\ndef need(v,m):\\n if not v:raise Refused(m)\\ndef canon(v):return json.dumps(v,sort_keys=True,separators=(\\\',\\\',\\\':\\\'),allow_nan=False).encode()\\ndef ident(s):return{k:getattr(s,k)for k in FIELDS}\\ndef core(s):return{k:getattr(s,k)for k in CORE}\\ndef same(ref,raw,st):return len(raw)==ref[\\\'bytes\\\'] and hashlib.sha256(raw).hexdigest()==ref[\\\'sha256\\\'] and ident(st)==ref[\\\'identity\\\']\\ndef process(pid):\\n need(type(pid)is int and pid>0,\\\'positive PID\\\');p=\\\'/proc/\\\'+str(pid)\\n fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)\\n def read(n,cap=65536):\\n  f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)\\n  try:\\n   out=b\\\'\\\'\\n   while b:=os.read(f,4096):out+=b;need(len(out)<=cap,\\\'proc field bound\\\')\\n   return out\\n  finally:os.close(f)\\n try:\\n  before=read(\\\'stat\\\');parts=before.decode().rsplit(\\\')\\\',1)[1].split();status=read(\\\'status\\\').decode();cg=read(\\\'cgroup\\\').decode().strip();argv=read(\\\'cmdline\\\').split(b\\\'\\\\0\\\');argv=argv[:-1]if argv and argv[-1]==b\\\'\\\'else argv\\n  ids=[x for x in status.splitlines()if x.startswith(\\\'Uid:\\\')];tg=[x for x in status.splitlines()if x.startswith(\\\'Tgid:\\\')]\\n  need(len(ids)==len(tg)==1 and len(set(map(int,ids[0].split()[1:])))==1,\\\'stable one UID/TGID\\\')\\n  need(cg.startswith(\\\'0::/\\\')and \\\'\\\\n\\\'not in cg,\\\'one unified cgroup\\\')\\n  v={\\\'pid\\\':pid,\\\'start\\\':int(parts[19]),\\\'uid\\\':int(ids[0].split()[1]),\\\'tgid\\\':int(tg[0].split()[1]),\\\'ppid\\\':int(parts[1]),\\\'cgroup\\\':cg[3:],\\\'argv\\\':[os.fsdecode(x)for x in argv]}\\n  need(read(\\\'stat\\\').decode().rsplit(\\\')\\\',1)[1].split()[19]==str(v[\\\'start\\\'])and Path(p).is_dir(),\\\'original proc start remained present\\\')\\n  return v\\n finally:os.close(fd)\\n\\n\\nclass RootFiles:\\n """Held nofollow ancestry. Shared /,/run use CORE+current FD/name equality.\\n Private0700 root and every leaf use full9. All descriptors owned/closed.\\n """\\n def __init__(self,path):self.path=Path(path);self.fds=[];self.chain=[];self.fd=None\\n def __enter__(self):\\n  need(str(self.path).startswith(\\\'/run/opemos-\\\')and len(self.path.parts)==3,\\\'exact generated /run root\\\')\\n  fd=os.open(\\\'/\\\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.fds.append(fd);self.chain.append((Path(\\\'/\\\'),fd,core(os.fstat(fd))))\\n  try:\\n   for n in self.path.parts[1:]:\\n    fd=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);self.fds.append(fd);path=self.chain[-1][0]/n;st=os.fstat(fd)\\n    need(st.st_uid==st.st_gid==0 and stat.S_ISDIR(st.st_mode),\\\'Root ancestor type/owner\\\');self.chain.append((path,fd,core(st)))\\n   self.fd=fd;st=os.fstat(fd);need(stat.S_IMODE(st.st_mode)==0o700,\\\'private Root0700\\\');self.private=ident(st);self.check();return self\\n  except BaseException:self.__exit__(*sys.exc_info());raise\\n def check(self):\\n  for p,fd,initial in self.chain:\\n   a=os.fstat(fd);b=os.lstat(p);need(core(a)==core(b)==initial,\\\'ancestor core/FD/name drift\\\')\\n   if p==Path(\\\'/\\\'):need(a.st_uid==a.st_gid==0 and stat.S_IMODE(a.st_mode)in(0o755,0o777),\\\'declared host root boundary\\\')\\n   elif p==Path(\\\'/run\\\'):need(stat.S_IMODE(a.st_mode)==0o755,\\\'shared /run mode\\\')\\n  need(ident(os.fstat(self.fd))==ident(os.lstat(self.path)),\\\'private FD/name full9\\\')\\n def parent_pin(self):\\n  self.check();i=ident(os.fstat(self.fd));return {\\\'path\\\':str(self.path),\\\'bytes\\\':i[\\\'st_size\\\'],\\\'sha256\\\':hashlib.sha256(canon(i)).hexdigest(),\\\'identity\\\':i}\\n def read(self,name,mode=0o400,cap=1048576):\\n  need(re.fullmatch(\\\'[A-Za-z0-9_.-]+\\\',name)is not None,\\\'confined leaf\\\')\\n  f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.fd)\\n  try:\\n   a=os.fstat(f);need(stat.S_ISREG(a.st_mode)and a.st_uid==a.st_gid==0 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==mode and a.st_size<=cap,\\\'Root exact leaf custody/cap\\\');raw=b\\\'\\\'\\n   while b:=os.read(f,65536):raw+=b;need(len(raw)<=cap,\\\'bounded streaming leaf\\\')\\n   need(ident(a)==ident(os.fstat(f))==ident(os.stat(name,dir_fd=self.fd,follow_symlinks=False))and len(raw)==a.st_size,\\\'leaf full9/EOF drift\\\');self.check()\\n   return raw,{\\\'path\\\':str(self.path/name),\\\'bytes\\\':len(raw),\\\'sha256\\\':hashlib.sha256(raw).hexdigest(),\\\'identity\\\':ident(a)}\\n  finally:os.close(f)\\n @contextlib.contextmanager\\n def lock(self,exclusive=False):\\n  f=os.open(\\\'lock\\\',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.fd)\\n  try:\\n   s=os.fstat(f);need(s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and stat.S_ISREG(s.st_mode),\\\'Root lock custody\\\');fcntl.flock(f,fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH|fcntl.LOCK_NB);yield\\n  finally:os.close(f)\\n def __exit__(self,*args):\\n  first=None\\n  for fd in self.fds[::-1]:\\n   try:os.close(fd)\\n   except BaseException as e:first=first or e\\n  self.fds=[]\\n  if first:raise first\\n\\n\\ndef _historical_lease_provenance(directory,rows,binding_pairs,queue,boot):\\n """Locked current disposition + backend-specific immutable provenance.\\n\\n The caller has independently verified the entire current queue snapshot/source\\n and live empty host/pool. This function neither releases a lease nor turns\\n current absence into historical QMP evidence. Returned full pins must survive\\n preflight and postqueue equality, not just this initial outer call.\\n """\\n directory=Path(directory);nonce=directory.name.removeprefix(\\\'opemos-vfio-\\\')\\n need(str(directory)==\\\'/run/opemos-vfio-\\\'+nonce and re.fullmatch(\\\'[0-9a-f]{32}\\\',nonce)is not None,\\\'exact historical physical lease root\\\')\\n need(type(rows)is list and len(rows)<=256 and len({r[\\\'id\\\']for r in rows})==len(rows),\\\'unique full historical rows\\\')\\n bindings=dict(binding_pairs);need(len(bindings)==len(binding_pairs)<=256,\\\'unique full keyed historical bindings\\\')\\n with RootFiles(directory)as files,files.lock():\\n  hraw,hp=files.read(\\\'head.json\\\');head=json.loads(hraw)\\n  need(set(head)=={\\\'path\\\',\\\'bytes\\\',\\\'sha256\\\',\\\'identity\\\'}and str(Path(head[\\\'path\\\']).parent)==str(files.path),\\\'canonical locked historical whole-pin head\\\')\\n  sraw,sp=files.read(Path(head[\\\'path\\\']).name);state=json.loads(sraw)\\n  need(sp==head and state[\\\'nonce\\\']==nonce and state[\\\'closed\\\']is True and state[\\\'restored\\\']is True and state[\\\'changed\\\']==[],\\\'known closed/restored exact historical state; open/foreign/unknown refuses\\\')\\n  matches=[r for r in rows if r[\\\'id\\\']==state[\\\'jobID\\\']]\\n  need(len(matches)==1 and matches[0][\\\'finished\\\']is not None and matches[0][\\\'state\\\']in(\\\'passed\\\',\\\'failed\\\',\\\'timed_out\\\',\\\'output_limit\\\',\\\'blocked\\\'),\\\'exact terminal historical job, never public projection\\\')\\n  row=matches[0];backend=state.get(\\\'backend\\\')\\n  proof={\\\'headPin\\\':hp,\\\'statePin\\\':sp,\\\'jobID\\\':state[\\\'jobID\\\'],\\\'nonce\\\':nonce,\\\'historicalQMPClosed\\\':state.get(\\\'historicalQMPClosed\\\'),\\\'backend\\\':\\\'direct-vfio\\\'if backend is None else backend}\\n  if backend is None:\\n   # Existing direct-VFIO contract is retained exactly; no generic missing file\\n   # fallback can reclassify an unknown/libvirt lease as direct.\\n   craw,cp=files.read(\\\'control.json\\\');control=json.loads(craw)\\n   need(control[\\\'nonce\\\']==nonce and control[\\\'jobID\\\']==state[\\\'jobID\\\']and control[\\\'bootId\\\']==boot,\\\'exact direct historical protected control/current boot\\\')\\n   proof[\\\'controlPin\\\']=cp\\n   need(files.read(\\\'control.json\\\')==(craw,cp),\\\'direct control full9/hash reread\\\')\\n  else:\\n   need(backend==\\\'libvirt\\\',\\\'unknown historical backend refuses\\\')\\n   need(state[\\\'currentBoot\\\']==boot and state[\\\'jobID\\\']in bindings,\\\'libvirt current boot and exact keyed original binding\\\')\\n   bound_raw=bindings[state[\\\'jobID\\\']];need(type(bound_raw)is str,\\\'complete original binding bytes\\\')\\n   request=queue.libvirt_request(row,json.loads(bound_raw));validate_request(request)\\n   digest=hashlib.sha256(canon(request)).hexdigest()\\n   need(request[\\\'jobId\\\']==state[\\\'jobID\\\']and request[\\\'leaseNonce\\\']==nonce and state[\\\'requestSHA256\\\']==digest,\\\'exact original queue request/nonce/job/unit/invocation/digest\\\')\\n   qroot=\\\'/run/opemos-libvirt-queue-\\\'+request[\\\'jobToken\\\']\\n   with RootFiles(qroot)as qfiles,qfiles.lock():\\n    iraw,ip=qfiles.read(\\\'intent.json\\\');intent=json.loads(iraw)\\n    need(intent[\\\'kind\\\']==\\\'ROOT_EXACT_QUEUE_LIBVIRT_INTENT_R2\\\'and intent[\\\'request\\\']==request and intent[\\\'bootID\\\']==boot,\\\'same protected libvirt intent/request/current boot\\\')\\n    phraw,php=qfiles.read(\\\'phase-head.json\\\');phasehead=json.loads(phraw)\\n    need(set(phasehead)=={\\\'record\\\',\\\'sha256\\\'}and re.fullmatch(r\\\'phase-[0-9]{2}\\\\.json\\\',phasehead[\\\'record\\\'])is not None,\\\'bounded exact protected phase head\\\')\\n    praw,pp=qfiles.read(phasehead[\\\'record\\\']);phase=json.loads(praw)\\n    need(hashlib.sha256(praw).hexdigest()==phasehead[\\\'sha256\\\']and phase[\\\'phase\\\']==\\\'CLOSED\\\'and phase[\\\'requestSHA256\\\']==digest and phase[\\\'bootID\\\']==boot and phase[\\\'scope\\\']is None and phase[\\\'leader\\\']is None,\\\'exact CLOSED same request/boot phase, no live registration\\\')\\n    details=phase[\\\'details\\\'];need(details==state[\\\'currentDisposition\\\']and all(details.get(k)is True for k in(\\\'domainAbsent\\\',\\\'originalPIDStartAbsent\\\',\\\'cgroupEmpty\\\',\\\'VFIOFDsAbsent\\\',\\\'hostRestored\\\'))and details.get(\\\'unknown\\\')==[],\\\'full protected current closure relation, no historical close fabrication\\\')\\n    proof.update(intentPin=ip,phaseHeadPin=php,phasePin=pp,queueRequestSHA256=digest,originalBindingSHA256=hashlib.sha256(bound_raw.encode()).hexdigest(),originalRowSHA256=hashlib.sha256(canon(row)).hexdigest())\\n    need(qfiles.read(\\\'intent.json\\\')==(iraw,ip)and qfiles.read(\\\'phase-head.json\\\')==(phraw,php)and qfiles.read(phasehead[\\\'record\\\'])==(praw,pp),\\\'all held libvirt provenance full9/hash post-use reread\\\')\\n  need(files.read(\\\'head.json\\\')==(hraw,hp)and files.read(Path(head[\\\'path\\\']).name)==(sraw,sp),\\\'locked historical head/state full9/hash post-use reread\\\')\\n return proof\\n\\n\\ndef historical_lease_provenance(directory,rows,binding_pairs,queue,boot):\\n try:return _historical_lease_provenance(directory,rows,binding_pairs,queue,boot)\\n except BaseException as error:\\n  # Context is diagnostic only, never a fallback/refusal waiver. Preserve the\\n  # exact primary and any earlier evidence; no metadata is created on failure.\\n  error.evidence={\\\'historicalLeaseRoot\\\':str(directory),\\\'operation\\\':\\\'locked backend-specific historical provenance\\\',\\\'priorEvidence\\\':getattr(error,\\\'evidence\\\',None)}\\n  raise\\n\\n\\ndef verify_historical_lease_set(expected,rows,binding_pairs,queue,boot):\\n need(type(expected)is list and len(expected)<=64 and len({r[\\\'headPin\\\'][\\\'path\\\']for r in expected})==len(expected),\\\'finite unique expected historical lease set\\\')\\n observed=[]\\n for prior in expected:\\n  value=historical_lease_provenance(str(Path(prior[\\\'headPin\\\'][\\\'path\\\']).parent),rows,binding_pairs,queue,boot)\\n  need(value==prior,\\\'entire locked historical backend provenance unchanged\\\')\\n  observed.append(value)\\n return observed\\n\\n\\ndef validate_request(r):\\n fields={\\\'jobId\\\',\\\'jobToken\\\',\\\'unit\\\',\\\'invocation\\\',\\\'specSHA256\\\',\\\'domainUUID\\\',\\\'domainName\\\',\\\'leaseNonce\\\',\\\'cpus\\\',\\\'controllerMemory\\\',\\\'domainMemory\\\',\\\'reservationMemory\\\',\\\'vmSlice\\\',\\\'partition\\\',\\\'gpuGroup\\\',\\\'observer\\\'}\\n need(type(r)is dict and set(r)==fields,\\\'exact upstream request schema\\\')\\n t=r[\\\'jobToken\\\'];need(re.fullmatch(\\\'[0-9a-f]{32}\\\',t)is not None and r[\\\'unit\\\'].endswith(\\\'-\\\'+t+\\\'.service\\\'),\\\'exact queue token/unit\\\')\\n need(re.fullmatch(\\\'[0-9a-f]{32}\\\',r[\\\'invocation\\\'])is not None and re.fullmatch(\\\'[0-9a-f]{64}\\\',r[\\\'specSHA256\\\'])is not None,\\\'queue immutable invocation/spec\\\')\\n need(r[\\\'vmSlice\\\']==\\\'opemos-vm-pool-libvirt\\\'+t+\\\'.slice\\\' and r[\\\'partition\\\']==\\\'/opemos/vm/pool/libvirt\\\'+t,\\\'derived per-job partition\\\')\\n need(r[\\\'controllerMemory\\\']==2*1024**3 and r[\\\'domainMemory\\\']==8*1024**3 and r[\\\'reservationMemory\\\']==10*1024**3,\\\'one10GiB split2+8\\\')\\n need(type(r[\\\'cpus\\\'])is list and len(r[\\\'cpus\\\'])==len(set(r[\\\'cpus\\\']))==4 and all(type(n)is int and 0<=n<10 for n in r[\\\'cpus\\\']),\\\'same exact assigned four CPUs\\\')\\n need(r[\\\'gpuGroup\\\']==GROUP and re.fullmatch(\\\'[0-9a-f]{32}\\\',r[\\\'leaseNonce\\\'])is not None,\\\'one physical group lease\\\')\\n need(re.fullmatch(\\\'opemos-libvirt-[0-9a-f]{32}\\\',r[\\\'domainName\\\'])is not None,\\\'exact libvirt domain name\\\')\\n import uuid\\n need(str(uuid.UUID(r[\\\'domainUUID\\\']))==r[\\\'domainUUID\\\'],\\\'canonical domain UUID\\\')\\n need(type(r[\\\'observer\\\'])is dict and set(r[\\\'observer\\\'])=={\\\'path\\\',\\\'bytes\\\',\\\'sha256\\\'}and 0<r[\\\'observer\\\'][\\\'bytes\\\']<=65536 and re.fullmatch(\\\'[0-9a-f]{64}\\\',r[\\\'observer\\\'][\\\'sha256\\\'])is not None,\\\'upstream exact minimal observer pin\\\')\\n\\n\\ndef validate_hostdev_xml(x,intent):\\n devices=x.findall(\\\'devices/hostdev\\\');need(len(devices)==4,\\\'exact four managed hostdevs\\\')\\n observed=[]\\n for h in devices:\\n  need(h.get(\\\'type\\\')==\\\'pci\\\'and h.get(\\\'mode\\\')==\\\'subsystem\\\'and h.get(\\\'managed\\\')==\\\'yes\\\',\\\'managed-only PCI control\\\')\\n  a=h.find(\\\'source/address\\\');need(a is not None,\\\'explicit source BDF\\\');observed.append(\\\'%04x:%02x:%02x.%x\\\'%tuple(int(a.get(k),0)for k in(\\\'domain\\\',\\\'bus\\\',\\\'slot\\\',\\\'function\\\')))\\n need(len(set(observed))==4 and set(observed)=={e[\\\'bdf\\\']for e in intent[\\\'endpoints\\\']},\\\'exact four distinct original group endpoints\\\')\\n\\ndef read_lease(files,request,boot):\\n raw,hp=files.read(\\\'head.json\\\');head=json.loads(raw);need(set(head)=={\\\'path\\\',\\\'bytes\\\',\\\'sha256\\\',\\\'identity\\\'}and str(Path(head[\\\'path\\\']).parent)==str(files.path)and re.fullmatch(\\\'state-(?:[0-9]|[1-5][0-9]|6[0-3])[.]json\\\',Path(head[\\\'path\\\']).name)is not None,\\\'canonical confined full native state-pin head\\\')\\n b,sp=files.read(Path(head[\\\'path\\\']).name);s=json.loads(b);need(sp==head and Path(head[\\\'path\\\']).name==\\\'state-\\\'+str(s[\\\'revision\\\'])+\\\'.json\\\',\\\'lease head/state exact full9/size/SHA/revision\\\')\\n need(s[\\\'nonce\\\']==request[\\\'leaseNonce\\\']and s[\\\'jobID\\\']==request[\\\'jobId\\\']and s[\\\'currentBoot\\\']==boot and s[\\\'requestSHA256\\\']==hashlib.sha256(canon(request)).hexdigest(),\\\'same request/job/boot lease\\\')\\n need(type(s[\\\'closed\\\'])is bool and type(s[\\\'restored\\\'])is bool and type(s[\\\'changed\\\'])is list and s[\\\'backend\\\']==\\\'libvirt\\\',\\\'typed libvirt lease\\\')\\n return s,{\\\'group\\\':GROUP,\\\'nonce\\\':s[\\\'nonce\\\'],\\\'jobId\\\':s[\\\'jobID\\\'],\\\'headPin\\\':hp,\\\'statePin\\\':sp,\\\'closed\\\':s[\\\'closed\\\'],\\\'restored\\\':s[\\\'restored\\\'],\\\'currentBoot\\\':boot},(raw,b)\\n\\n\\ndef fd_snapshot(label):\\n rows=[];vanished=[];names=os.listdir(\\\'/proc/self/fd\\\');need(len(names)<=256,\\\'bounded FD inventory\\\')\\n for name in sorted(names,key=int):\\n  n=int(name)\\n  try:\\n   a=ident(os.fstat(n));target=os.readlink(\\\'/proc/self/fd/\\\'+name);info=Path(\\\'/proc/self/fdinfo/\\\'+name).read_text();need(len(target)<=4096 and len(info)<=8192 and a==ident(os.fstat(n)),\\\'bounded stable FD observation\\\');fields=dict(x.split(\\\':\\\',1)for x in info.splitlines()if \\\':\\\'in x);rows.append({\\\'fd\\\':n,\\\'identity\\\':a,\\\'target\\\':target,\\\'flags\\\':fields.get(\\\'flags\\\',\\\'\\\').strip(),\\\'eventfdID\\\':fields.get(\\\'eventfd-id\\\',\\\'\\\').strip(),\\\'fdinfo\\\':info})\\n  except FileNotFoundError:vanished.append(n)\\n  except OSError as error:\\n   if error.errno==9:vanished.append(n)\\n   else:raise\\n return {\\\'label\\\':label,\\\'actor\\\':{k:process(os.getpid())[k]for k in(\\\'pid\\\',\\\'start\\\',\\\'uid\\\')},\\\'atUnix\\\':time.time(),\\\'rows\\\':rows,\\\'vanishedDuringFDList\\\':vanished}\\ndef fd_key(row):return {k:row[k]for k in(\\\'fd\\\',\\\'identity\\\',\\\'target\\\',\\\'flags\\\',\\\'eventfdID\\\')}\\ndef fd_changes(before,after):\\n a={r[\\\'fd\\\']:fd_key(r)for r in before[\\\'rows\\\']};b={r[\\\'fd\\\']:fd_key(r)for r in after[\\\'rows\\\']}\\n return {\\\'added\\\':[b[n]for n in sorted(b.keys()-a.keys())],\\\'removed\\\':[a[n]for n in sorted(a.keys()-b.keys())],\\\'replaced\\\':[{\\\'before\\\':a[n],\\\'after\\\':b[n]}for n in sorted(a.keys()&b.keys())if a[n]!=b[n]]}\\ndef fd_equal(before,after):return not any(fd_changes(before,after).values())\\ndef error_value(error):\\n if error is None:return None\\n return {\\\'type\\\':type(error).__name__,\\\'reason\\\':str(error),\\\'traceback\\\':__import__(\\\'traceback\\\').format_exception(type(error),error,error.__traceback__)}\\n\\nclass NativeOps:\\n """Read-only native observation. No daemon/domain/device mutation methods."""\\n def __init__(self,close_pump=None,persist=None):self.conn=None;self.domainObjects={};self.close_pump=close_pump;self.persist=persist;self.closeOutcomes=[]\\n def boot(self):return Path(\\\'/proc/sys/kernel/random/boot_id\\\').read_text().strip()\\n def actor(self):\\n  p=process(os.getpid());return {k:p[k]for k in(\\\'pid\\\',\\\'start\\\',\\\'uid\\\')}\\n def domains(self):\\n  import libvirt\\n  self.conn=libvirt.openReadOnly(\\\'qemu:///system\\\');need(self.conn is not None and self.conn.getURI()==\\\'qemu:///system\\\',\\\'readonly system libvirt\\\')\\n  ds=self.conn.listAllDomains(0);need(len(ds)<=128,\\\'finite complete domain enumeration\\\');out=[]\\n  for d in ds:\\n   x=ET.fromstring(d.XMLDesc(0));u=d.UUIDString();self.domainObjects[u]=d\\n   out.append({\\\'uuid\\\':u,\\\'name\\\':d.name(),\\\'active\\\':bool(d.isActive()),\\\'persistent\\\':bool(d.isPersistent()),\\\'xml\\\':d.XMLDesc(0),\\\'noNIC\\\':not x.findall(\\\'devices/interface\\\')})\\n  need(len({x[\\\'uuid\\\']for x in out})==len(out)and len({x[\\\'name\\\']for x in out})==len(out),\\\'unique full domain inventory\\\');return out\\n def manager(self,unit):\\n  import subprocess\\n  args=[\\\'/usr/bin/systemctl\\\',\\\'show\\\',unit,\\\'-p\\\',\\\'LoadState\\\',\\\'-p\\\',\\\'InvocationID\\\',\\\'-p\\\',\\\'ControlGroup\\\',\\\'-p\\\',\\\'MainPID\\\',\\\'-p\\\',\\\'ActiveState\\\']\\n  p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,close_fds=True)\\n  # Every native child identity is known before wait; short-child failure refuses.\\n  child=process(p.pid)\\n  try:out,err=p.communicate(timeout=5)\\n  finally:\\n   p.stdout.close();p.stderr.close()\\n  need(p.returncode==0 and not err and len(out)<=65536,\\\'bounded manager read\\\');need(not Path(\\\'/proc/\\\'+str(child[\\\'pid\\\'])).exists(),\\\'manager child reaped\\\')\\n  return dict(x.split(\\\'=\\\',1)for x in out.decode().splitlines())\\n def entry(self,intent,phase):\\n  r=intent[\\\'request\\\'];m=self.manager(r[\\\'unit\\\'])\\n  if phase==\\\'CLOSED\\\'and m.get(\\\'LoadState\\\')==\\\'not-found\\\':return\\n  if phase==\\\'CLOSED\\\'and m.get(\\\'LoadState\\\')==\\\'loaded\\\'and m.get(\\\'ActiveState\\\')==\\\'failed\\\':\\n   observed={\\\'unit\\\':r[\\\'unit\\\'],\\\'expectedInvocation\\\':r[\\\'invocation\\\'],\\\'manager\\\':m,\\\'expectedCgroup\\\':POOL+\\\'/\\\'+r[\\\'unit\\\'],\\\'phase\\\':phase}\\n   if self.persist is not None:self.persist(\\\'closed-loaded-failed-manager-before-predicate\\\',observed)\\n   need(m.get(\\\'InvocationID\\\')==r[\\\'invocation\\\']and m.get(\\\'ControlGroup\\\')==\\\'\\\'and m.get(\\\'MainPID\\\')==\\\'0\\\',\\\'same exact failed invocation with no live manager PID/cgroup\\\')\\n   need(not os.path.lexists(\\\'/sys/fs/cgroup\\\'+POOL+\\\'/\\\'+r[\\\'unit\\\']),\\\'exact failed service cgroup actually absent\\\')\\n   after=self.manager(r[\\\'unit\\\'])\\n   if self.persist is not None:self.persist(\\\'closed-loaded-failed-manager-after\\\',{\\\'before\\\':observed,\\\'after\\\':after})\\n   need(after==m,\\\'same failed invocation/state remained stable\\\')\\n   return\\n  need(m.get(\\\'InvocationID\\\')==r[\\\'invocation\\\']and m.get(\\\'ControlGroup\\\')==POOL+\\\'/\\\'+r[\\\'unit\\\'],\\\'current exact own service invocation/cgroup\\\')\\n  need(int(m.get(\\\'MainPID\\\',\\\'0\\\'))==intent[\\\'entry\\\'][\\\'managerMainPID\\\'],\\\'same actual logger MainPID\\\')\\n  if phase!=\\\'CLOSED\\\':\\n   a=process(intent[\\\'entry\\\'][\\\'pid\\\']);need(all(a[k]==intent[\\\'entry\\\'][k]for k in(\\\'pid\\\',\\\'start\\\',\\\'uid\\\'))and a[\\\'uid\\\']==0 and a[\\\'cgroup\\\'].startswith(POOL+\\\'/\\\'+r[\\\'unit\\\']),\\\'current Root queue entry actor\\\')\\n   need(hashlib.sha256(canon(a[\\\'argv\\\'])).hexdigest()==intent[\\\'entry\\\'][\\\'argvSHA256\\\'],\\\'Root entry exact argv\\\')\\n def budget(self,r,phase,scope):\\n  root=Path(\\\'/sys/fs/cgroup\\\'+POOL+\\\'/\\\'+r[\\\'vmSlice\\\']);need(root.is_dir()and not root.is_symlink(),\\\'exact existing VM slice\\\')\\n  fields={n:(root/n).read_text().strip()for n in(\\\'cpu.max\\\',\\\'memory.max\\\',\\\'memory.swap.max\\\',\\\'cpuset.cpus.effective\\\',\\\'cgroup.events\\\',\\\'cgroup.procs\\\')}\\n  need(fields[\\\'cpu.max\\\']==\\\'400000 100000\\\'and fields[\\\'memory.max\\\']==str(8*1024**3)and fields[\\\'memory.swap.max\\\']==\\\'0\\\',\\\'actual VM slice4CPU8GiBswap0\\\')\\n  def cpus(text):\\n   v=set()\\n   for x in text.split(\\\',\\\'):\\n    if \\\'-\\\'in x:a,b=map(int,x.split(\\\'-\\\'));v.update(range(a,b+1))\\n    elif x:v.add(int(x))\\n   return v\\n  need(cpus(fields[\\\'cpuset.cpus.effective\\\'])==set(r[\\\'cpus\\\']),\\\'actual same four CPUs\\\')\\n  pool=Path(\\\'/sys/fs/cgroup\\\'+POOL);need((pool/\\\'cpu.max\\\').read_text().strip()==\\\'1000000 100000\\\'and(pool/\\\'memory.max\\\').read_text().strip()==str(32*1024**3)and(pool/\\\'memory.swap.max\\\').read_text().strip()==\\\'0\\\',\\\'unchanged whole pool\\\')\\n  children=[p.name for p in root.iterdir()if p.is_dir()];need(children==([]if scope is None else[scope]),\\\'no foreign scope even empty\\\')\\n  if phase!=\\\'ACTIVE\\\':need(not fields[\\\'cgroup.procs\\\']and \\\'populated 0\\\'in fields[\\\'cgroup.events\\\'],\\\'inactive partition actually empty\\\')\\n def leader(self,reg,intent):\\n  a=process(reg[\\\'leader\\\'][\\\'pid\\\']);need({k:a[k]for k in(\\\'pid\\\',\\\'start\\\',\\\'uid\\\')}==reg[\\\'leader\\\']and a[\\\'tgid\\\']==a[\\\'pid\\\']and a[\\\'uid\\\']==64055,\\\'fresh original QEMU leader PID/start/UID\\\')\\n  r=intent[\\\'request\\\'];prefix=POOL+\\\'/\\\'+r[\\\'vmSlice\\\']+\\\'/\\\'+reg[\\\'scope\\\'];need(a[\\\'cgroup\\\']==prefix or a[\\\'cgroup\\\'].startswith(prefix+\\\'/\\\'),\\\'exact domain scope descendant\\\')\\n  args=a[\\\'argv\\\'];need(\\\'-uuid\\\'in args and args[args.index(\\\'-uuid\\\')+1]==r[\\\'domainUUID\\\']and \\\'-name\\\'in args and (\\\'guest=\\\'+r[\\\'domainName\\\'])in args[args.index(\\\'-name\\\')+1].split(\\\',\\\'),\\\'exact QEMU UUID/name argv\\\')\\n  fd=os.open(\\\'/proc/\\\'+str(a[\\\'pid\\\'])+\\\'/exe\\\',os.O_RDONLY|os.O_CLOEXEC)\\n  try:\\n   st=os.fstat(fd);ref=intent[\\\'qemuPin\\\'];h=hashlib.sha256();n=0\\n   while b:=os.read(fd,65536):n+=len(b);need(n<=33554432,\\\'QEMU target32MiB\\\');h.update(b)\\n   need(ident(st)==ref[\\\'identity\\\']and n==ref[\\\'bytes\\\']and h.hexdigest()==ref[\\\'sha256\\\']and ident(st)==ident(os.fstat(fd)),\\\'exact current QEMU exe FD/full9/hash\\\')\\n  finally:os.close(fd)\\n  self.active_devices(a,intent)\\n  need(process(a[\\\'pid\\\'])==a,\\\'original actor fully revalidated\\\');return reg[\\\'leader\\\']\\n def active_devices(self,actor,intent):\\n  for e in intent[\\\'endpoints\\\']:\\n   root=Path(\\\'/sys/bus/pci/devices\\\')/e[\\\'bdf\\\']\\n   for field,key in ((\\\'vendor\\\',\\\'vendor\\\'),(\\\'device\\\',\\\'device\\\'),(\\\'class\\\',\\\'class\\\'),(\\\'subsystem_vendor\\\',\\\'subsystemVendor\\\'),(\\\'subsystem_device\\\',\\\'subsystemDevice\\\')):need((root/field).read_text().strip()==e[key],\\\'actual managed endpoint full identity\\\')\\n   need(os.path.basename(os.readlink(root/\\\'iommu_group\\\'))==\\\'1\\\'and os.path.basename(os.readlink(root/\\\'driver\\\'))==\\\'vfio-pci\\\',\\\'all four exact endpoints managed into same vfio group\\\')\\n  found=[];unknown=[];count=0;scanned=0;raw=None;observedFD=None;matched=False\\n  try:\\n   for proc in Path(\\\'/proc\\\').iterdir():\\n    if not proc.name.isdigit():continue\\n    raw=None;observedFD=None;matched=False;scanned+=1;need(scanned<=8192,\\\'bounded managed process inventory\\\')\\n    try:\\n     # Ambient credentials may legitimately be mixed during sudo/setuid. Only\\n     # a matching VFIO holder has the strict selected-QEMU role.\\n     raw=process_snapshot(int(proc.name));fds=list((proc/\\\'fd\\\').iterdir());need(len(fds)<=16384,\\\'bounded managed FD scan\\\')\\n     for fd in fds:\\n      count+=1;need(count<=262144,\\\'bounded whole-host FD scan\\\')\\n      try:target=os.readlink(fd)\\n      except FileNotFoundError:continue\\n      if target in(\\\'/dev/vfio/1\\\',\\\'/dev/vfio/vfio\\\')or target.startswith(\\\'/dev/vfio/devices/\\\'):\\n       matched=True;observedFD={\\\'pid\\\':raw[\\\'pid\\\'],\\\'fd\\\':fd.name,\\\'target\\\':target,\\\'raw\\\':raw}\\n       if self.persist is not None:self.persist(\\\'vfio-holder-before-role\\\',observedFD)\\n       original=process(raw[\\\'pid\\\'])\\n       need(raw[\\\'uids\\\']==[64055]*4 and original[\\\'tgid\\\']==original[\\\'pid\\\']and all(original[k]==raw[k]for k in(\\\'pid\\\',\\\'start\\\',\\\'ppid\\\',\\\'tgid\\\',\\\'argv\\\',\\\'cgroup\\\')),\\\'matched VFIO holder raw/strict principal identity\\\')\\n       need(all(original[k]==actor[k]for k in(\\\'pid\\\',\\\'start\\\',\\\'ppid\\\',\\\'tgid\\\',\\\'uid\\\',\\\'argv\\\',\\\'cgroup\\\'))and original[\\\'uid\\\']==64055,\\\'no foreign VFIO holder\\\')\\n       need(process_snapshot(raw[\\\'pid\\\'])==raw and process(raw[\\\'pid\\\'])==original and os.readlink(fd)==target,\\\'same matched VFIO holder and FD revalidated\\\')\\n       found.append(observedFD)\\n     need(process_snapshot(raw[\\\'pid\\\'])==raw,\\\'ambient FD-scan raw identity stable\\\')\\n    except(FileNotFoundError,ProcessLookupError):\\n     need(not matched,\\\'observed VFIO holder disappearance is unknown; refuse\\\')\\n     continue\\n    except PermissionError:unknown.append(int(proc.name))\\n   need(not unknown and any(x[\\\'target\\\']==\\\'/dev/vfio/1\\\'for x in found),\\\'positive exact QEMU group1 FD and no unknowns; alternate cdev route needs reviewed proof\\\')\\n   if self.persist is not None:self.persist(\\\'vfio-inventory-verified\\\',{\\\'scanned\\\':scanned,\\\'FDs\\\':count,\\\'matched\\\':found,\\\'unknown\\\':unknown})\\n  except BaseException as error:\\n   evidence={\\\'stage\\\':\\\'whole-host-VFIO-FD-inventory\\\',\\\'first\\\':{\\\'type\\\':type(error).__name__,\\\'reason\\\':str(error)},\\\'currentRawActor\\\':raw,\\\'currentMatchedFD\\\':observedFD,\\\'matched\\\':found,\\\'unknown\\\':unknown,\\\'scanned\\\':scanned,\\\'FDs\\\':count,\\\'selectedQEMU\\\':actor}\\n   error.vfioEvidence=evidence\\n   try:\\n    if self.persist is not None:self.persist(\\\'FIRST-vfio-inventory\\\',evidence)\\n   except BaseException as secondary:evidence[\\\'diagnosticPersistenceError\\\']={\\\'type\\\':type(secondary).__name__,\\\'reason\\\':str(secondary)}\\n   raise\\n def restoration(self,intent):\\n  # No signal, unbind, override or rebind. Current absence never invents old QMP.\\n  for e in intent[\\\'endpoints\\\']:\\n   p=Path(\\\'/sys/bus/pci/devices\\\')/e[\\\'bdf\\\'];need(p.exists(),\\\'same physical endpoint\\\')\\n   for field,key in ((\\\'vendor\\\',\\\'vendor\\\'),(\\\'device\\\',\\\'device\\\'),(\\\'class\\\',\\\'class\\\'),(\\\'subsystem_vendor\\\',\\\'subsystemVendor\\\'),(\\\'subsystem_device\\\',\\\'subsystemDevice\\\')):need((p/field).read_text().strip()==e[key],\\\'exact physical endpoint identity\\\')\\n   need(os.path.basename(os.readlink(p/\\\'iommu_group\\\'))==\\\'1\\\',\\\'exact IOMMU group1\\\')\\n   driver=os.path.basename(os.readlink(p/\\\'driver\\\'))if(p/\\\'driver\\\').exists()else None\\n   need(driver==e[\\\'originalDriver\\\']and(p/\\\'driver_override\\\').read_text()==e[\\\'originalOverride\\\'],\\\'all original driver/override states restored\\\')\\n  root=Path(\\\'/dev/vfio\\\');targets={str(root/\\\'1\\\'),str(root/\\\'vfio\\\')};unknown=[];holders=[];count=0\\n  for proc in Path(\\\'/proc\\\').iterdir():\\n   if not proc.name.isdigit():continue\\n   try:\\n    fs=list((proc/\\\'fd\\\').iterdir());need(len(fs)<=16384,\\\'per-process FD bound\\\')\\n    for f in fs:\\n     count+=1;need(count<=262144,\\\'whole host FD bound\\\')\\n     try:t=os.readlink(f)\\n     except FileNotFoundError:continue\\n     if t in targets or t.startswith(\\\'/dev/vfio/devices/\\\'):holders.append({\\\'pid\\\':int(proc.name),\\\'fd\\\':f.name,\\\'target\\\':t})\\n   except FileNotFoundError:continue\\n   except PermissionError:unknown.append(int(proc.name))\\n  need(not holders and not unknown,\\\'complete current VFIO holder/unknown absence\\\')\\n def close(self):\\n  before=fd_snapshot(\\\'readonly-before-close\\\');numeric=None;first=None\\n  try:\\n   self.domainObjects.clear()\\n   if self.conn is not None:\\n    conn=self.conn;self.conn=None;numeric=conn.close();conn=None;need(numeric==0,\\\'readonly libvirt connection close\\\')\\n    if self.close_pump is not None:self.close_pump(\\\'readonly-connection-close\\\')\\n  except BaseException as error:first=error\\n  after=fd_snapshot(\\\'readonly-after-close\\\');v={\\\'before\\\':before,\\\'after\\\':after,\\\'numeric\\\':numeric,\\\'primary\\\':error_value(first)};self.closeOutcomes.append(v)\\n  if self.persist is not None:self.persist(\\\'readonly-connection-close\\\',v)\\n  if first is not None:raise first\\n\\n\\ndef observe(request,ops=None):\\n validate_request(request);ops=NativeOps()if ops is None else ops;started=time.monotonic();before=fd_snapshot(\\\'readonly-observe-before\\\');proof=None;primary=None;secondary=[]\\n try:\\n  need(os.getuid()==0,\\\'actual Root readonly producer\\\');boot=ops.boot();actor=ops.actor();need(actor[\\\'uid\\\']==0,\\\'Root observer actor\\\')\\n  domains=ops.domains();target=[d for d in domains if d[\\\'uuid\\\']==request[\\\'domainUUID\\\']or d[\\\'name\\\']==request[\\\'domainName\\\']]\\n  need(len(target)<=1,\\\'ambiguous target domain\\\');path=\\\'/run/opemos-libvirt-queue-\\\'+request[\\\'jobToken\\\']\\n  proof={\\\'kind\\\':\\\'ROOT_CURRENT_EXACT_QUEUE_LIBVIRT_DOMAIN_R1\\\',\\\'request\\\':request,\\\'bootID\\\':boot,\\\'producer\\\':actor,\\\'sourceSHA256\\\':request[\\\'observer\\\'][\\\'sha256\\\'],\\\'startedMonotonic\\\':started,\\\'completedMonotonic\\\':None,\\\'phase\\\':\\\'NOT_PREPARED\\\',\\\'scope\\\':None,\\\'leader\\\':None,\\\'intentPin\\\':None,\\\'intentParentPin\\\':None,\\\'lease\\\':None,\\\'domainUUID\\\':request[\\\'domainUUID\\\'],\\\'persistent\\\':False,\\\'noNIC\\\':True,\\\'fullDomainEnumeration\\\':True,\\\'allOwnedDescriptorsClosed\\\':False,\\\'effects\\\':[]}\\n  if not os.path.lexists(path):need(not target,\\\'no adoption of target domain without intent\\\')\\n  else:\\n   with RootFiles(path)as files,files.lock():\\n    ir,ip=files.read(\\\'intent.json\\\');intent=json.loads(ir);need(intent[\\\'kind\\\']==\\\'ROOT_EXACT_QUEUE_LIBVIRT_INTENT_R2\\\'and intent[\\\'request\\\']==request and intent[\\\'bootID\\\']==boot,\\\'entire current Root intent/request/boot\\\')\\n    hr,hp=files.read(\\\'phase-head.json\\\');head=json.loads(hr);need(set(head)=={\\\'record\\\',\\\'sha256\\\'}and re.fullmatch(\\\'phase-[0-9]{2}.json\\\',head[\\\'record\\\'])is not None,\\\'bounded phase head\\\')\\n    rr,rp=files.read(head[\\\'record\\\']);reg=json.loads(rr);need(hashlib.sha256(rr).hexdigest()==head[\\\'sha256\\\']and reg[\\\'requestSHA256\\\']==hashlib.sha256(canon(request)).hexdigest()and reg[\\\'bootID\\\']==boot,\\\'phase head/source/scope hash\\\')\\n    phase=reg[\\\'phase\\\'];need(phase in(\\\'PREPARED\\\',\\\'ACTIVE\\\',\\\'CLOSED\\\'),\\\'known exact phase\\\')\\n    with RootFiles(\\\'/run/opemos-vfio-\\\'+request[\\\'leaseNonce\\\'])as leasefiles,leasefiles.lock():\\n     state,lease,old=read_lease(leasefiles,request,boot);ops.entry(intent,phase)\\n     scope=None;leader=None\\n     if phase==\\\'ACTIVE\\\':\\n      need(len(target)==1 and target[0][\\\'uuid\\\']==request[\\\'domainUUID\\\']and target[0][\\\'name\\\']==request[\\\'domainName\\\']and target[0][\\\'active\\\']and not target[0][\\\'persistent\\\']and target[0][\\\'noNIC\\\'],\\\'real exact transient noNIC active domain\\\')\\n      scope=reg[\\\'scope\\\'];need(re.fullmatch(r\\\'machine-[A-Za-z0-9_.\\\\\\\\-]+\\\\.scope\\\',scope)is not None,\\\'actual machine scope name\\\')\\n      x=ET.fromstring(target[0][\\\'xml\\\']);validate_hostdev_xml(x,intent);m=x.find(\\\'metadata/{\\\'+NS+\\\'}binding\\\');need(m is not None and m.get(\\\'token\\\')==request[\\\'jobToken\\\']and m.get(\\\'job\\\')==request[\\\'jobId\\\']and m.get(\\\'nonce\\\')==request[\\\'leaseNonce\\\'],\\\'live immutable domain metadata token\\\')\\n      need(x.findtext(\\\'resource/partition\\\')==request[\\\'partition\\\'],\\\'actual domain partition\\\');leader=ops.leader(reg,intent);need(not state[\\\'closed\\\'],\\\'active lease open\\\')\\n     else:\\n      need(not target,\\\'inactive phase has no target domain; startup/teardown race remains held\\\')\\n      need(reg[\\\'scope\\\']is None and reg[\\\'leader\\\']is None,\\\'no invented inactive identity\\\')\\n      if phase==\\\'CLOSED\\\':need(state[\\\'closed\\\']and state[\\\'restored\\\']and not state[\\\'changed\\\'],\\\'closed restored exact lease\\\');ops.restoration(intent)\\n      else:need(not state[\\\'closed\\\'],\\\'prepared current lease open\\\')\\n     ops.budget(request,phase,scope)\\n     need(files.read(\\\'intent.json\\\')[0]==ir and files.read(\\\'phase-head.json\\\')[0]==hr and files.read(head[\\\'record\\\'])[0]==rr,\\\'immutable intent/phase reread\\\')\\n     need(read_lease(leasefiles,request,boot)[2]==old,\\\'current lease head/state reread\\\')\\n     proof.update(phase=phase,scope=scope,leader=leader,intentPin=ip,intentParentPin=files.parent_pin(),lease=lease)\\n except BaseException as e:primary=e\\n finally:\\n  try:ops.close()\\n  except BaseException as e:\\n   if primary is None:primary=e\\n   else:secondary.append(error_value(e))\\n after=fd_snapshot(\\\'readonly-observe-after\\\');changes=fd_changes(before,after)\\n if any(changes.values()):secondary.append({\\\'type\\\':\\\'FDClosureRefusal\\\',\\\'reason\\\':\\\'all readonly owned FDs closed\\\',\\\'changes\\\':changes})\\n evidence={\\\'primary\\\':error_value(primary),\\\'secondary\\\':secondary,\\\'before\\\':before,\\\'after\\\':after,\\\'closeOutcomes\\\':getattr(ops,\\\'closeOutcomes\\\',[])}\\n if getattr(ops,\\\'persist\\\',None)is not None:ops.persist(\\\'readonly-observer-closure\\\',evidence)\\n if primary is not None:primary.evidence=evidence;raise primary\\n if secondary:\\n  error=Refused(\\\'all readonly owned FDs closed\\\');error.evidence=evidence;raise error\\n proof[\\\'completedMonotonic\\\']=time.monotonic();proof[\\\'allOwnedDescriptorsClosed\\\']=True\\n need(len(canon(proof))+1<=1048576 and proof[\\\'completedMonotonic\\\']-started<15,\\\'canonical observer size/deadline\\\');return proof\\n\\n\\n\\n\\ndef process_snapshot(pid):\\n """Raw stable process metadata; no worker/Root role authorization implied."""\\n need(type(pid)is int and pid>0,\\\'positive raw PID\\\');root=Path(\\\'/proc\\\')/str(pid);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)\\n def read(name):\\n  f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)\\n  try:\\n   raw=b\\\'\\\'\\n   while b:=os.read(f,4096):raw+=b;need(len(raw)<=65536,\\\'bounded raw process field\\\')\\n   return raw\\n  finally:os.close(f)\\n try:\\n  a=read(\\\'stat\\\').decode().rsplit(\\\')\\\',1)[1].split();cmd=read(\\\'cmdline\\\');status=read(\\\'status\\\').decode();cg=read(\\\'cgroup\\\').decode().strip();u=[int(x)for l in status.splitlines()if l.startswith(\\\'Uid:\\\')for x in l.split()[1:]];tg=[int(l.split()[1])for l in status.splitlines()if l.startswith(\\\'Tgid:\\\')]\\n  need(len(u)==4 and len(tg)==1 and cg.startswith(\\\'0::/\\\')and \\\'\\\\n\\\'not in cg,\\\'raw complete UID quartet/TGID/cgroup\\\')\\n  v={\\\'pid\\\':pid,\\\'start\\\':int(a[19]),\\\'ppid\\\':int(a[1]),\\\'uids\\\':u,\\\'tgid\\\':tg[0],\\\'cgroup\\\':cg[3:],\\\'argv\\\':[os.fsdecode(x)for x in cmd.rstrip(b\\\'\\\\0\\\').split(b\\\'\\\\0\\\')]if cmd else[]}\\n  b=read(\\\'stat\\\').decode().rsplit(\\\')\\\',1)[1].split();need((b[19],b[1])==(a[19],a[1])and read(\\\'cmdline\\\')==cmd and [int(x)for l in read(\\\'status\\\').decode().splitlines()if l.startswith(\\\'Uid:\\\')for x in l.split()[1:]]==u and read(\\\'cgroup\\\').decode().strip()==cg,\\\'raw PID/start/ppid/cmdline/UID/cgroup stable\\\')\\n  return v\\n finally:os.close(fd)\\n\\ndef select_worker(expected,persist=None):\\n persist=(lambda *a:None)if persist is None else persist;matches=[];count=0;observed=None\\n try:\\n  for path in Path(\\\'/proc\\\').iterdir():\\n   if not path.name.isdigit():continue\\n   count+=1;need(count<=8192,\\\'finite whole PID enumeration\\\')\\n   try:raw=process_snapshot(int(path.name))\\n   except(FileNotFoundError,ProcessLookupError):continue\\n   if raw[\\\'argv\\\']!=expected:continue\\n   observed=raw;persist(\\\'worker-candidate-before-role\\\',raw)\\n   actor=process(raw[\\\'pid\\\']);need(actor[\\\'start\\\']==raw[\\\'start\\\']and actor[\\\'ppid\\\']==raw[\\\'ppid\\\']and actor[\\\'argv\\\']==raw[\\\'argv\\\']and actor[\\\'cgroup\\\']==raw[\\\'cgroup\\\']and raw[\\\'uids\\\']==[1000]*4 and actor[\\\'uid\\\']==1000 and actor[\\\'tgid\\\']==actor[\\\'pid\\\']==raw[\\\'tgid\\\'],\\\'exact matching canonical worker role UID1000/TGID/argv/start/cgroup\\\')\\n   need(process_snapshot(raw[\\\'pid\\\'])==raw,\\\'matching raw identity after strict role\\\');matches.append(actor)\\n  persist(\\\'worker-candidate-selection\\\',{\\\'scanned\\\':count,\\\'matches\\\':matches});need(len(matches)==1,\\\'exact one canonical live queue worker\\\');return matches[0]\\n except BaseException as error:error.evidence={\\\'candidate\\\':observed,\\\'matches\\\':matches,\\\'scanned\\\':count};raise\\n\\n\\ndef verify_worker_lock(lock_pin,state_pin,mode,worker=None,persist=None):\\n """Exact retained lock under its pinned private parent; never chmod/chown/write.\\n\\n Idle preparation requires no kernel holder and an owned nonblocking EX probe.\\n Issuance instead requires one exact original UID1000 worker\\\'s kernel FLOCK/FD.\\n Every observed field is delivered before the first custody predicate.\\n """\\n persist=(lambda *a:None)if persist is None else persist\\n fd=dfd=None;observed={};before=set(os.listdir(\\\'/proc/self/fd\\\'))\\n def kernel(st):\\n  rows=[]\\n  for line in Path(\\\'/proc/locks\\\').read_text().splitlines():\\n   fields=line.split()\\n   if len(fields)<8 or fields[1]!=\\\'FLOCK\\\'or fields[3]!=\\\'WRITE\\\':continue\\n   major,minor,ino=fields[5].split(\\\':\\\')\\n   if(int(major,16),int(minor,16),int(ino))==(os.major(st.st_dev),os.minor(st.st_dev),st.st_ino):rows.append({\\\'pid\\\':int(fields[4]),\\\'type\\\':fields[1],\\\'access\\\':fields[3]})\\n  return rows\\n try:\\n  path=Path(state_pin[\\\'path\\\']);dfd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);ds=os.fstat(dfd)\\n  fd=os.open(\\\'worker.lock\\\',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dfd);s=os.fstat(fd);raw=os.pread(fd,4097,0)\\n  actual={\\\'path\\\':str(path/\\\'worker.lock\\\'),\\\'bytes\\\':len(raw),\\\'sha256\\\':hashlib.sha256(raw).hexdigest(),\\\'identity\\\':ident(s)}\\n  state_now=ident(ds);children=sorted(os.listdir(dfd));need(len(children)<=128,\\\'bounded canonical state children\\\');observed={\\\'prequeueStatePin\\\':state_pin,\\\'statePin\\\':{\\\'path\\\':str(path),\\\'identity\\\':state_now},\\\'stateChildren\\\':children,\\\'epochChangedBetweenPhases\\\':state_now!=state_pin[\\\'identity\\\'],\\\'workerLockPin\\\':actual,\\\'workerLockMode\\\':stat.S_IMODE(s.st_mode),\\\'kernelFlocks\\\':kernel(s),\\\'worker\\\':worker}\\n  persist(\\\'worker-lock-before-predicate\\\',observed)\\n  need(str(path/\\\'worker.lock\\\')==lock_pin[\\\'path\\\']and state_now==ident(path.lstat())and stat.S_ISDIR(ds.st_mode)and ds.st_uid==ds.st_gid==1000 and stat.S_IMODE(ds.st_mode)==0o700,\\\'exact current held privateUID1000 state0700\\\')\\n  if worker is None:need(state_now==state_pin[\\\'identity\\\'],\\\'idle exact pinned privateUID1000 state0700\\\')\\n  else:need(all(state_now[k]==state_pin[\\\'identity\\\'][k]for k in CORE),\\\'postqueue immutable private state core; only size/mtime/ctime may evolve\\\')\\n  need(actual==lock_pin and stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and s.st_size==0 and raw==b\\\'\\\'and mode==stat.S_IMODE(s.st_mode)and mode in(0o600,0o644,0o664),\\\'exact pinned emptyUID1000 single-link finite worker lock\\\')\\n  if mode==0o664:need(state_pin[\\\'identity\\\'][\\\'st_mode\\\']==stat.S_IFDIR|0o700,\\\'0664 only under exact pinned private state0700\\\')\\n  chain=[];held=[]\\n  if worker is None:\\n   need(observed[\\\'kernelFlocks\\\']==[],\\\'idle exact lock has no kernel holder\\\')\\n   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\\n   try:need(kernel(s)==[{\\\'pid\\\':os.getpid(),\\\'type\\\':\\\'FLOCK\\\',\\\'access\\\':\\\'WRITE\\\'}],\\\'idle probe has sole own kernel FLOCK\\\')\\n   finally:fcntl.flock(fd,fcntl.LOCK_UN)\\n  else:\\n   need(worker[\\\'uid\\\']==1000 and worker[\\\'pid\\\']==worker[\\\'tgid\\\']and process(worker[\\\'pid\\\'])==worker,\\\'same exact currentUID1000 worker PID/start/argv/cgroup\\\')\\n   need(observed[\\\'kernelFlocks\\\']==[{\\\'pid\\\':worker[\\\'pid\\\'],\\\'type\\\':\\\'FLOCK\\\',\\\'access\\\':\\\'WRITE\\\'}],\\\'actual exact worker sole exclusive FLOCK\\\')\\n   pid=worker[\\\'pid\\\']\\n   for _ in range(32):\\n    a=process_snapshot(pid);chain.append({k:a[k]for k in(\\\'pid\\\',\\\'start\\\',\\\'uids\\\',\\\'ppid\\\',\\\'cgroup\\\')})\\n    if pid==1:break\\n    need(a[\\\'ppid\\\']>0 and a[\\\'ppid\\\']!=pid,\\\'finite known worker ancestry\\\');pid=a[\\\'ppid\\\']\\n   need(chain[-1][\\\'pid\\\']==1,\\\'complete bounded current worker ancestry\\\')\\n   items=list(Path(\\\'/proc/\\\'+str(worker[\\\'pid\\\'])+\\\'/fd\\\').iterdir());need(len(items)<=16384,\\\'bounded worker FD enumeration\\\')\\n   for item in items:\\n    try:st=item.stat()\\n    except FileNotFoundError:continue\\n    if(st.st_dev,st.st_ino)==(s.st_dev,s.st_ino):held.append({\\\'fd\\\':int(item.name),\\\'identity\\\':ident(st)})\\n   need(len(held)==1 and held[0][\\\'identity\\\']==lock_pin[\\\'identity\\\'],\\\'positive one actual original-worker lockFD\\\')\\n   for old in chain:need({k:process_snapshot(old[\\\'pid\\\'])[k]for k in old}==old,\\\'worker ancestry stable before/after\\\')\\n   need(process(worker[\\\'pid\\\'])==worker,\\\'same whole original worker after callbacks\\\')\\n  need(ident(os.fstat(fd))==ident(os.stat(\\\'worker.lock\\\',dir_fd=dfd,follow_symlinks=False))==ident(Path(lock_pin[\\\'path\\\']).lstat())==lock_pin[\\\'identity\\\']and ident(os.fstat(dfd))==ident(path.lstat())==state_now and sorted(os.listdir(dfd))==children,\\\'final held/path/state/lock full9 unchanged\\\')\\n  need(kernel(s)==observed[\\\'kernelFlocks\\\'],\\\'kernel FLOCK same after callback\\\')\\n  result={**observed,\\\'ancestry\\\':chain,\\\'heldLockFDs\\\':held,\\\'verified\\\':True};persist(\\\'worker-lock-final\\\',result);return result\\n except BaseException as error:\\n  error.evidence=observed;raise\\n finally:\\n  if fd is not None:os.close(fd)\\n  if dfd is not None:os.close(dfd)\\n  need(before==set(os.listdir(\\\'/proc/self/fd\\\')),\\\'worker lock owned FD restoration\\\')\\n\\n\\nif __name__==\\\'__main__\\\':\\n try:\\n  need(len(sys.argv)==4 and sys.argv[2]==\\\'--queue-libvirt-request-json\\\',\\\'exact queue observer argv\\\')\\n  request=json.loads(sys.argv[3]);need(sys.argv[1]==request[\\\'observer\\\'][\\\'sha256\\\'],\\\'exact queue source SHA operand\\\')\\n  ref=request[\\\'observer\\\'];fd=os.open(ref[\\\'path\\\'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\\n  try:\\n   st=os.fstat(fd);raw=os.read(fd,65537);need(os.read(fd,1)==b\\\'\\\' and len(raw)==ref[\\\'bytes\\\']<=65536 and hashlib.sha256(raw).hexdigest()==ref[\\\'sha256\\\']and st.st_nlink==1 and ident(st)==ident(os.fstat(fd))==ident(os.lstat(ref[\\\'path\\\'])),\\\'upstream minimal pin plus freshly held source full9/EOF/hash\\\')\\n  finally:os.close(fd)\\n  print(canon(observe(request)).decode(),flush=True)\\n except BaseException as e:\\n  reason={\\\'kind\\\':\\\'QUEUE_LIBVIRT_FIRST_REFUSAL\\\',\\\'type\\\':type(e).__name__,\\\'reason\\\':str(e),\\\'effects\\\':[],\\\'evidence\\\':getattr(e,\\\'evidence\\\',None),\\\'traceback\\\':traceback.format_exc()};raw=canon(reason);sys.stderr.buffer.write(raw[:65535]+b\\\'\\\\n\\\');sys.exit(1)\\n\\n\'\nIMPLEMENTATION_SHA=\'abb5a30b7eae786540aa04333f4e2c9427cbba1d90776fc304bf1a65cb8329cb\'\nN={\'__name__\':\'reviewed_queue_peer_definition_only\'}\ntry:\n assert hashlib.sha256(PEER_SOURCE.encode()).hexdigest()==IMPLEMENTATION_SHA and len(sys.argv)==4 and sys.argv[1]==IMPLEMENTATION_SHA and sys.argv[2]==\'--queue-libvirt-request-json\'\n exec(compile(PEER_SOURCE,\'reviewed_R49_peer\',\'exec\'),N);request=json.loads(sys.argv[3]);ref=request[\'observer\'];fd=os.open(ref[\'path\'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n try:\n  st=os.fstat(fd);raw=os.read(fd,65537);assert os.read(fd,1)==b\'\'and len(raw)==ref[\'bytes\']<=65536 and hashlib.sha256(raw).hexdigest()==ref[\'sha256\']and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)in(0o400,0o444)and st.st_nlink==1 and N[\'ident\'](st)==N[\'ident\'](os.fstat(fd))==N[\'ident\'](os.lstat(ref[\'path\']))\n  upstream=dict(ref,identity=N[\'ident\'](st))\n finally:os.close(fd)\n proof=N[\'observe\'](request)\n assert proof[\'request\']==request and proof[\'sourceSHA256\']==ref[\'sha256\']\n result={\'kind\':\'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION\',\'upstreamObserver\':upstream,\'implementation\':{\'bytes\':len(PEER_SOURCE.encode()),\'sha256\':IMPLEMENTATION_SHA},\'proof\':proof,\'effects\':[]}\n print(json.dumps(result,sort_keys=True,separators=(\',\',\':\'),allow_nan=False),flush=True)\nexcept BaseException as e:\n print(json.dumps({\'kind\':\'QUEUE_LIBVIRT_FIRST_REFUSAL\',\'type\':type(e).__name__,\'reason\':str(e),\'effects\':[],\'evidence\':getattr(e,\'evidence\',None),\'traceback\':traceback.format_exc()},sort_keys=True,separators=(\',\',\':\')),file=sys.stderr,flush=True);sys.exit(1)\n'
REVIEWED_PEER_D22_SHA256='5ea0eb7cf2ec3e1cddb470ec3d59675897750c093a7a7ff40a97a046678cd2dd'
REVIEWED_PEER_D22_BYTES=51256
REVIEWED_PEER_D22_ROOT_ADAPTER="import hashlib,json,os,stat,sys,traceback,types\nfrom pathlib import Path\nF=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')\nPARENT={'bytes': 27252, 'identity': {'st_ctime_ns': 1793143828513516525, 'st_dev': 28, 'st_gid': 0, 'st_ino': 428106, 'st_mode': 33060, 'st_mtime_ns': 1793143828513516525, 'st_nlink': 1, 'st_size': 27252, 'st_uid': 0}, 'path': '/run/opemos-libvirt-parent-7e2144b7f6c540948939ad3b40cce901.json', 'sha256': 'baf6cf39ef5eb07e44a7ba0cead7e14a5f0ee0e4a7c0d24e1200606090d6108a'}\nCONTEXT={'path': '/run/opemos-libvirt-runtime-7e2144b7f6c540948939ad3b40cce901/context.json', 'bytes': 11753, 'sha256': '8d0f2cec2462c43224e556897b617eb95457010db068d16a96d7de083c1c7e3f', 'identity': {'st_ctime_ns': 1793143838580607007, 'st_dev': 28, 'st_gid': 0, 'st_ino': 428289, 'st_mode': 33024, 'st_mtime_ns': 1793143838580607007, 'st_nlink': 1, 'st_size': 11753, 'st_uid': 0}}\nPEER={'bytes': 51256, 'identity': {'st_ctime_ns': 1793122522675148421, 'st_dev': 28, 'st_gid': 0, 'st_ino': 403707, 'st_mode': 33060, 'st_mtime_ns': 1793122522675148421, 'st_nlink': 1, 'st_size': 51256, 'st_uid': 0}, 'path': '/run/opemos-steamos-source-7e2144b7f6c540948939ad3b40cce901/libvirt_peer.py', 'sha256': '5ea0eb7cf2ec3e1cddb470ec3d59675897750c093a7a7ff40a97a046678cd2dd'}\nACCESS={'bytes': 15340, 'identity': {'st_ctime_ns': 1793122522652148843, 'st_dev': 28, 'st_gid': 0, 'st_ino': 403705, 'st_mode': 33060, 'st_mtime_ns': 1793122522652148843, 'st_nlink': 1, 'st_size': 15340, 'st_uid': 0}, 'path': '/run/opemos-steamos-source-7e2144b7f6c540948939ad3b40cce901/libvirt_access.py', 'sha256': 'bbbf8cb900f797471d163fb29be9a82cd8f99e33eebefd280af42052a6d9ad17'}\ndef ident(s):return {k:getattr(s,k) for k in F}\ndef need(ok,reason):\n if not ok:raise RuntimeError(reason)\ndef read(ref,cap,modes):\n need(ref['bytes']<=cap,'declared file cap')\n f=os.open(ref['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n try:\n  s=os.fstat(f);before=ident(s);need(before==ref['identity'] and stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode) in modes,'exact held Root file full9/custody')\n  raw=b''\n  while chunk:=os.read(f,65536):raw+=chunk;need(len(raw)<=cap,'bounded held file')\n  need(len(raw)==ref['bytes'] and hashlib.sha256(raw).hexdigest()==ref['sha256'] and before==ident(os.fstat(f))==ident(os.lstat(ref['path'])),'held/name full9 EOF hash')\n  return raw\n finally:os.close(f)\ndef canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)\ntry:\n need(os.getuid()==0 and len(sys.argv)==4 and sys.argv[1]==PEER['sha256'] and sys.argv[2]=='--queue-libvirt-request-json','exact Root queue adapter argv/source')\n request=json.loads(sys.argv[3]);need(type(request)is dict and request.get('observer')=={k:PEER[k] for k in ('path','bytes','sha256')} and request.get('leaseNonce')=='7e2144b7f6c540948939ad3b40cce901','exact original peer request/nonce')\n parent=json.loads(read(PARENT,65536,(0o400,0o444)));context=json.loads(read(CONTEXT,65536,(0o400,0o444)))\n need(parent['kind']=='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT' and parent['contextPath']==CONTEXT['path'] and parent['bootID']==Path('/proc/sys/kernel/random/boot_id').read_text().strip() and parent['jobId']==request['jobId'] and parent['RootIssued'] is True,'exact live Root parent/boot/job')\n need(context['kind']=='ROOT_LIBVIRT_R4_RUNTIME_CONTEXT' and context['parentPin']==PARENT and context['sourceRoles']==parent['sourceRoles'] and context['candidate']==parent['candidate'],'unchanged Root runtime context/parent/source')\n roles=parent['sourceRoles'];need(len(roles)==12 and roles['libvirt_peer']==PEER and roles['libvirt_access']==ACCESS,'exact frozen peer/access roles and full9')\n spec=parent['normalizedSpecTemplate'];bound=spec['libvirt_domain']\n need(spec['id']==request['jobId'] and bound=={'leaseNonce':request['leaseNonce'],'name':request['domainName'],'observer':request['observer'],'uuid':request['domainUUID']} and parent['candidate']['jobId']==request['jobId'] and parent['candidate']['nonce']==request['leaseNonce'],'unchanged original queue specification/domain binding')\n peer_raw=read(PEER,65536,(0o400,0o444));access_raw=read(ACCESS,65536,(0o400,0o444))\n previous_peer=sys.modules.get('libvirt_peer');previous_access=sys.modules.get('libvirt_access')\n try:\n  peer=types.ModuleType('libvirt_peer');peer.__file__=PEER['path'];sys.modules['libvirt_peer']=peer\n  exec(compile(peer_raw,PEER['path'],'exec'),peer.__dict__)\n  access=types.ModuleType('libvirt_access');access.__file__=ACCESS['path'];sys.modules['libvirt_access']=access\n  exec(compile(access_raw,ACCESS['path'],'exec'),access.__dict__)\n  proof=peer.observe(request)\n finally:\n  if previous_peer is None:sys.modules.pop('libvirt_peer',None)\n  else:sys.modules['libvirt_peer']=previous_peer\n  if previous_access is None:sys.modules.pop('libvirt_access',None)\n  else:sys.modules['libvirt_access']=previous_access\n need(proof['request']==request and proof['sourceSHA256']==PEER['sha256'] and proof['phase']=='CLOSED' and proof['allOwnedDescriptorsClosed'] is True,'unchanged actual CLOSED observer and FD closure')\n need(read(PARENT,65536,(0o400,0o444)) and read(CONTEXT,65536,(0o400,0o444)) and read(PEER,65536,(0o400,0o444))==peer_raw and read(ACCESS,65536,(0o400,0o444))==access_raw,'post-use exact held source/parent/context reread')\n result={'kind':'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION','upstreamObserver':PEER,'implementation':{'bytes':PEER['bytes'],'sha256':PEER['sha256'],'access':ACCESS,'parent':PARENT,'context':CONTEXT},'proof':proof,'effects':[]}\n print(canonical(result),flush=True)\nexcept BaseException as error:\n refusal={'kind':'QUEUE_LIBVIRT_FIRST_REFUSAL','type':type(error).__name__,'reason':str(error),'effects':[],'evidence':getattr(error,'evidence',None),'traceback':traceback.format_exc()}\n print(canonical(refusal),file=sys.stderr,flush=True);sys.exit(1)\n"
REVIEWED_PEER_D22_IMPLEMENTATION={'bytes': 51256, 'sha256': '5ea0eb7cf2ec3e1cddb470ec3d59675897750c093a7a7ff40a97a046678cd2dd', 'access': {'bytes': 15340, 'identity': {'st_ctime_ns': 1793122522652148843, 'st_dev': 28, 'st_gid': 0, 'st_ino': 403705, 'st_mode': 33060, 'st_mtime_ns': 1793122522652148843, 'st_nlink': 1, 'st_size': 15340, 'st_uid': 0}, 'path': '/run/opemos-steamos-source-7e2144b7f6c540948939ad3b40cce901/libvirt_access.py', 'sha256': 'bbbf8cb900f797471d163fb29be9a82cd8f99e33eebefd280af42052a6d9ad17'}, 'parent': {'bytes': 27252, 'identity': {'st_ctime_ns': 1793143828513516525, 'st_dev': 28, 'st_gid': 0, 'st_ino': 428106, 'st_mode': 33060, 'st_mtime_ns': 1793143828513516525, 'st_nlink': 1, 'st_size': 27252, 'st_uid': 0}, 'path': '/run/opemos-libvirt-parent-7e2144b7f6c540948939ad3b40cce901.json', 'sha256': 'baf6cf39ef5eb07e44a7ba0cead7e14a5f0ee0e4a7c0d24e1200606090d6108a'}, 'context': {'path': '/run/opemos-libvirt-runtime-7e2144b7f6c540948939ad3b40cce901/context.json', 'bytes': 11753, 'sha256': '8d0f2cec2462c43224e556897b617eb95457010db068d16a96d7de083c1c7e3f', 'identity': {'st_ctime_ns': 1793143838580607007, 'st_dev': 28, 'st_gid': 0, 'st_ino': 428289, 'st_mode': 33024, 'st_mtime_ns': 1793143838580607007, 'st_nlink': 1, 'st_size': 11753, 'st_uid': 0}}}


# SOURCE-ONLY D24 exact adapter proposal; old D22/reviewed branches preserved.
D24_PEER_SHA='a0c34fc011869b6b8e6c72219d028d935d3b2361f5436b93c3fd830f3c1ba82d'
D24_PEER_BYTES=60512
D24_ACCESS_SHA='bbbf8cb900f797471d163fb29be9a82cd8f99e33eebefd280af42052a6d9ad17'
D24_ADAPTER_CONTRACT='D24_ROOT_PARENT_CONTEXT_SOURCE12_FRESH_PLACEMENT_READONLY'
D24_ROOT_ADAPTER='"""Exact D23 readonly standalone peer/access adapter proposal, never installed.\nNo deployment, writes, SQL, runtime grant, domain control or sysfs methods.\nQueue owner must independently adopt exact bytes and consumer contract.\n"""\nimport contextlib,copy,hashlib,json,os,re,stat,sys,time,traceback,types\nfrom pathlib import Path\nF=(\'st_dev\',\'st_ino\',\'st_mode\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\');CORE=F[:6]\nNONCE=\'0d3acd6323384c5cab8837f801e0cb42\';CONTRACT=\'D24_ROOT_PARENT_CONTEXT_SOURCE12_FRESH_PLACEMENT_READONLY\'\nPEER_SHA=\'a0c34fc011869b6b8e6c72219d028d935d3b2361f5436b93c3fd830f3c1ba82d\';PEER_BYTES=60512\nACCESS_SHA=\'bbbf8cb900f797471d163fb29be9a82cd8f99e33eebefd280af42052a6d9ad17\';ACCESS_BYTES=15340\nROLES={\'libvirt_peer\',\'libvirt_access\',\'libvirt_native\',\'libvirt_preflight\',\'libvirt_producer\',\'queue_assignment\',\'runtime_entry\',\'guest_delta\',\'guest_firmware_probe\',\'held_history_reader\',\'two_boot_contract\',\'postqueue_issuer\'}\ndef canonical(v):return json.dumps(v,sort_keys=True,separators=(\',\',\':\'),allow_nan=False)\ndef need(v,m):\n if not v:raise RuntimeError(m)\ndef ident(s):return{k:getattr(s,k)for k in F}\ndef decode(raw):\n def unique(pairs):\n  value={}\n  for key,item in pairs:need(key not in value,\'duplicate protected JSON key\');value[key]=item\n  return value\n value=json.loads(raw,object_pairs_hook=unique);need(canonical(value).encode()==raw,\'whole canonical protected metadata, no dropped/trailing fields\');return value\nclass RootInputs:\n """One readonly bounded held-nofollow /run graph; owns and closes all FDs."""\n def __init__(self):self.fds=[];self.dirs={}\n def __enter__(self):\n  self.root=os.open(\'/\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.fds.append(self.root)\n  try:\n   self.run=os.open(\'run\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.root);self.fds.append(self.run)\n   self.dirs={\'/\':(self.root,ident(os.fstat(self.root)),False),\'/run\':(self.run,ident(os.fstat(self.run)),False)};self.check();return self\n  except BaseException:\n   self.__exit__(*sys.exc_info());raise\n def check(self):\n  for path,(fd,a,exclusive)in self.dirs.items():\n   x=ident(os.fstat(fd));need(x==ident(os.lstat(path))and all(x[k]==a[k]for k in(CORE if not exclusive else F)),\'held/named declared directory identity/epoch\')\n   need(stat.S_ISDIR(x[\'st_mode\'])and x[\'st_uid\']==x[\'st_gid\']==0,\'Root directory nofollow custody\')\n   need(stat.S_IMODE(x[\'st_mode\'])in((0o755,0o777)if path==\'/\'else(0o755,)if path==\'/run\'else(0o755,)if path.startswith(\'/run/opemos-steamos-source-\')else(0o700,)),\'exact role-specific directory mode\')\n def directory(self,path):\n  allowed={\'/run/opemos-steamos-source-\'+NONCE,\'/run/opemos-libvirt-runtime-\'+NONCE,\'/run/opemos-steamos-placement-\'+NONCE}\n  need(path in allowed,\'declared finite source/context/placement root only\')\n  if path not in self.dirs:\n   fd=os.open(Path(path).name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.run);self.fds.append(fd);self.dirs[path]=(fd,ident(os.fstat(fd)),True)\n  self.check();return self.dirs[path][0]\n def read_path(self,path,mode,cap):\n  path=Path(path);need(path.is_absolute()and path.name not in(\'\',\'.\',\'..\'),\'absolute confined declared leaf\')\n  if str(path.parent)==\'/run\':need(str(path)==\'/run/opemos-libvirt-parent-\'+NONCE+\'.json\',\'one normal public parent only\');parent=self.run\n  else:parent=self.directory(str(path.parent))\n  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)\n  try:\n   s=os.fstat(fd);a=ident(s);need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode and s.st_nlink==1 and s.st_size<=cap,\'exact Root leaf mode/owner/link/size\');raw=b\'\'\n   while chunk:=os.read(fd,65536):raw+=chunk;need(len(raw)<=cap,\'bounded full leaf stream\')\n   need(a==ident(os.fstat(fd))==ident(os.stat(path.name,dir_fd=parent,follow_symlinks=False))==ident(os.lstat(path))and len(raw)==a[\'st_size\'],\'full held/anchored/named identity and EOF\');self.check();return raw,{\'path\':str(path),\'bytes\':len(raw),\'sha256\':hashlib.sha256(raw).hexdigest(),\'identity\':a}\n  finally:os.close(fd)\n def read(self,ref,mode,cap):\n  raw,actual=self.read_path(ref[\'path\'],mode,cap);need(actual==ref,\'exact declared full9/length/SHA pin\');return raw\n def placement_bytes(self,fd,parentfd,ref):\n  """Inner FD/hash check; hold_placement applies exact Root role custody.\n  It does not change Root policy or convert a user fixture into Root proof.\n  """\n  value={\'path\':ref[\'path\'],\'expected\':ref,\'heldBefore\':None,\'heldAfter\':None,\'named\':None,\'heldSHA256\':None,\'namedSHA256\':None,\'heldBytes\':None,\'namedBytes\':None}\n  def bytesof(f):\n   chunks=[];offset=0\n   while True:\n    b=os.pread(f,65536,offset)\n    if not b:break\n    offset+=len(b);need(offset<=1048576,\'unchanged placement metadata1MiB streaming cap\');chunks.append(b)\n   return b\'\'.join(chunks)\n  try:\n   value[\'heldBefore\']=ident(os.fstat(fd));need((__import__(\'fcntl\').fcntl(fd,__import__(\'fcntl\').F_GETFL)&os.O_ACCMODE)==os.O_RDONLY,\'owned placement held FD remains O_RDONLY\');held=bytesof(fd);value.update(heldBytes=len(held),heldSHA256=hashlib.sha256(held).hexdigest())\n   nf=os.open(Path(ref[\'path\']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)\n   try:\n    value[\'named\']=ident(os.fstat(nf));named=bytesof(nf);value.update(namedBytes=len(named),namedSHA256=hashlib.sha256(named).hexdigest());need(value[\'named\']==ident(os.fstat(nf))==ident(os.stat(Path(ref[\'path\']).name,dir_fd=parentfd,follow_symlinks=False))==ident(os.lstat(ref[\'path\'])),\'placement fresh nofollow named FD/path full9\')\n   finally:\n    primary=sys.exc_info()[1]\n    try:os.close(nf)\n    except BaseException as close:\n     if primary is None:raise\n     primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'fd\':nf,\'type\':type(close).__name__,\'reason\':str(close)}]\n   value[\'heldAfter\']=ident(os.fstat(fd));need(value[\'heldBefore\']==value[\'heldAfter\']==value[\'named\']==ref[\'identity\']and len(held)==len(named)==ref[\'bytes\']and value[\'heldSHA256\']==value[\'namedSHA256\']==ref[\'sha256\']and held==named,\'placement held/named full9/raw bytes/length/SHA equal originally bound operand\')\n   return held\n  except BaseException as error:error.placementCustody=value;raise\n @contextlib.contextmanager\n def hold_placement(self,ref):\n  root=\'/run/opemos-steamos-placement-\'+NONCE;need(ref[\'path\']in(root+\'/storage-contract.json\',root+\'/placement-qualified.json\'),\'two exact placement metadata leaves only\');i=ref[\'identity\'];need(set(ref)=={\'path\',\'bytes\',\'sha256\',\'identity\'}and 0<ref[\'bytes\']<=1048576 and stat.S_ISREG(i[\'st_mode\'])and stat.S_IMODE(i[\'st_mode\'])==0o400 and i[\'st_uid\']==i[\'st_gid\']==0 and i[\'st_nlink\']==1 and i[\'st_size\']==ref[\'bytes\'],\'exact Root0400 placement full pin/custody\')\n  parentfd=self.directory(root);fd=os.open(Path(ref[\'path\']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)\n  try:\n   original=self.placement_bytes(fd,parentfd,ref);self.check()\n   def recheck():\n    self.check();raw=self.placement_bytes(fd,parentfd,ref);need(raw==original,\'complete held placement raw bytes identical after observer\');self.check();return ref\n   yield {\'ref\':ref,\'raw\':original,\'recheck\':recheck}\n  finally:\n   primary=sys.exc_info()[1]\n   try:os.close(fd)\n   except BaseException as close:\n    if primary is None:raise\n    primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'fd\':fd,\'type\':type(close).__name__,\'reason\':str(close)}]\n def __exit__(self,*a):\n  errors=[]\n  for fd in self.fds[::-1]:\n   try:os.close(fd)\n   except OSError as e:errors.append({\'fd\':fd,\'type\':type(e).__name__,\'reason\':str(e)})\n  self.fds=[]\n  if errors:\n   if a[1]is not None:a[1].ownedRootInputClosureErrors=errors\n   else:raise RuntimeError(canonical({\'ownedRootInputClosureErrors\':errors}))\n\ndef parent_spec(parent,parent_ref):\n s=copy.deepcopy(parent[\'normalizedSpecTemplate\']);need(s[\'approval\']==\'EXACT_PARENT_MINIMAL_PIN\'and s[\'command\'][-1]==\'EXACT_PARENT_FULL_PIN_JSON\',\'two existing late parent-pin slots only\');s[\'approval\']={k:parent_ref[k]for k in(\'path\',\'bytes\',\'sha256\')};s[\'command\'][-1]=canonical(parent_ref)\n need(s[\'command\']==[\'sudo\',\'-n\',\'/usr/bin/python3\',\'-B\',parent[\'sourceRoles\'][\'runtime_entry\'][\'path\'],\'--parent-pin-json\',canonical(parent_ref)]and s[\'id\']==parent[\'jobId\']and s[\'cores\']==4 and s[\'memory\']==10737418240 and s[\'timeout_seconds\']==900 and \'omen-iommu-group-1\'in s[\'resources\'],\'exact ordinary entry and10GiB/4CPU/900s spec\')\n return s\n\ndef verify_inputs(request,io,boot):\n need(request[\'leaseNonce\']==NONCE and request[\'domainName\']==\'opemos-libvirt-\'+NONCE,\'fresh exact D23 scope only\')\n cr=\'/run/opemos-libvirt-runtime-\'+NONCE+\'/context.json\';parentRaw,parentRef=io.read_path(\'/run/opemos-libvirt-parent-\'+NONCE+\'.json\',0o444,1048576);parent=decode(parentRaw)\n try:contextRaw,contextRef=io.read_path(cr,0o400,1048576);context=decode(contextRaw)\n except FileNotFoundError:contextRaw=contextRef=context=None\n need(parent[\'kind\']==\'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT\'and parent[\'RootIssued\']is True and parent[\'runtimeAuthorized\']is True and parent.get(\'MODEL_ONLY\')is False and parent[\'bootID\']==boot and parent[\'nonce\']==NONCE and parent[\'contextPath\']==cr,\'existing actual same-boot Root parent; no issuance or clock refresh\')\n if context is not None:need(context[\'parentPin\']==parentRef and context[\'kind\']==\'ROOT_LIBVIRT_R4_RUNTIME_CONTEXT\'and context[\'runtimeAuthorized\']is True and context.get(\'MODEL_ONLY\')is False and context[\'candidate\']==parent[\'candidate\']and context[\'sourceRoles\']==parent[\'sourceRoles\'],\'Root context/candidate/source12 equality; no model promotion\')\n need(parent[\'issuedUnix\']<parent[\'startBeforeUnix\']<=parent[\'issuedUnix\']+300 and parent[\'wholeDeadlineUnix\']<=parent[\'issuedUnix\']+900,\'original finite parent scope retained; readonly closed observation does not reissue authority\')\n roles=parent[\'sourceRoles\'];need(set(roles)==ROLES,\'complete source12 membership\')\n need(roles[\'libvirt_peer\'][\'bytes\']==PEER_BYTES and roles[\'libvirt_peer\'][\'sha256\']==PEER_SHA and roles[\'libvirt_access\'][\'bytes\']==ACCESS_BYTES and roles[\'libvirt_access\'][\'sha256\']==ACCESS_SHA,\'frozen reviewed peer/access implementation\')\n need(request[\'observer\']=={k:roles[\'libvirt_peer\'][k]for k in(\'path\',\'bytes\',\'sha256\')}and request[\'jobId\']==parent[\'jobId\'],\'exact original request observer/job\')\n source={}\n for name,ref in sorted(roles.items()):\n  need(ref[\'path\']==\'/run/opemos-steamos-source-\'+NONCE+\'/\'+name+\'.py\',\'same exact source namespace\');source[name]=io.read(ref,0o444,65536);compile(source[name],ref[\'path\'],\'exec\')\n spec=parent_spec(parent,parentRef);bound=spec[\'libvirt_domain\'];need(bound=={\'leaseNonce\':NONCE,\'name\':request[\'domainName\'],\'observer\':request[\'observer\'],\'uuid\':request[\'domainUUID\']}and hashlib.sha256(canonical(spec).encode()).hexdigest()==request[\'specSHA256\'],\'complete final normalized spec/hash/domain identity\')\n assignmentRef=grantRef=None;assignment=grant=None\n if context is not None:\n  assignmentRef=context[\'assignmentPin\'];need(assignmentRef[\'path\']==\'/run/opemos-libvirt-runtime-\'+NONCE+\'/assignment.json\'and context[\'grantPin\'][\'path\']==\'/run/opemos-libvirt-runtime-\'+NONCE+\'/child-grant.json\',\'two exact same-scope child control leaves\');assignment=decode(io.read(assignmentRef,0o400,1048576));grantRef=context[\'grantPin\'];grant=decode(io.read(grantRef,0o400,1048576))\n  need(assignment[\'kind\']==\'ROOT_CANONICAL_QUEUE_LIBVIRT_ASSIGNMENT_R4\'and assignment[\'request\']==request and grant[\'assignmentPin\']==assignmentRef and grant[\'parentPin\']==parentRef and grant[\'normalizedSpecSHA256\']==request[\'specSHA256\'],\'canonical assignment and child grant exact request/spec/parent\')\n  need(grant[\'queuePrograms\']==parent[\'queuePrograms\']and grant[\'sourcePlacementPin\']==context[\'sourcePlacementPin\']==parent[\'sourcePlacementPin\']and grant[\'placementQualificationPin\']==context[\'placementQualificationPin\']==parent[\'placementQualificationPin\'],\'current queue authority and placement pins across child/context/parent\')\n  need(grant[\'RootIssued\']is True and grant[\'MODEL_ONLY\']is False and grant[\'runtimeAuthorized\']is True and grant[\'jobId\']==request[\'jobId\']and grant[\'leaseNonce\']==NONCE and grant[\'bootID\']==boot and parent[\'issuedUnix\']<=grant[\'issuedUnix\']<grant[\'startBeforeUnix\']<=parent[\'startBeforeUnix\']and grant[\'wholeDeadlineUnix\']<=parent[\'wholeDeadlineUnix\'],\'existing finite Root child only, no new runtime grant\')\n return {\'parent\':parent,\'parentPin\':parentRef,\'parentRaw\':parentRaw,\'context\':context,\'contextPin\':contextRef,\'contextRaw\':contextRaw,\'source\':source,\'assignmentPin\':assignmentRef,\'assignmentRaw\':None if assignment is None else canonical(assignment).encode(),\'grantPin\':grantRef,\'grantRaw\':None if grant is None else canonical(grant).encode()}\n\ndef bind_placement(peer,parent,parent_ref,context=None):\n """Bind only the fresh protected same-source/same-scope metadata operand.\n Never changes the frozen peer\'s nonce, strict geometry or owner predicate.\n """\n nonce=parent[\'nonce\'];roles=parent[\'sourceRoles\'];candidate=parent[\'candidate\']\n peer.need(nonce==\'0d3acd6323384c5cab8837f801e0cb42\'and peer.SOURCE_PLACEMENT_NONCE==nonce and candidate[\'nonce\']==nonce and candidate[\'jobId\']==parent[\'jobId\'],\'D23 unused scope only; D22 is consumed\')\n peer.need(parent[\'RootIssued\']is True and parent[\'kind\']==\'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT\'and parent[\'bootID\']==candidate[\'hostBoot\']and parent_ref[\'path\']==\'/run/opemos-libvirt-parent-\'+nonce+\'.json\',\'existing exact Root parent/boot/source scope\')\n peer.need(set(roles)=={\'libvirt_peer\',\'libvirt_access\',\'libvirt_native\',\'libvirt_preflight\',\'libvirt_producer\',\'queue_assignment\',\'runtime_entry\',\'guest_delta\',\'guest_firmware_probe\',\'held_history_reader\',\'two_boot_contract\',\'postqueue_issuer\'},\'closed twelve-role binding\')\n peer.need(roles[\'libvirt_peer\'][\'sha256\']==\'a0c34fc011869b6b8e6c72219d028d935d3b2361f5436b93c3fd830f3c1ba82d\'and roles[\'libvirt_peer\'][\'bytes\']==60512 and roles[\'libvirt_access\'][\'sha256\']==\'bbbf8cb900f797471d163fb29be9a82cd8f99e33eebefd280af42052a6d9ad17\'and roles[\'libvirt_access\'][\'bytes\']==15340,\'frozen exact D23 peer and unchanged access bytes\')\n for name,ref in roles.items():peer.need(ref[\'path\']==\'/run/opemos-steamos-source-\'+nonce+\'/\'+name+\'.py\'and ref[\'identity\'][\'st_uid\']==ref[\'identity\'][\'st_gid\']==0 and stat.S_IMODE(ref[\'identity\'][\'st_mode\'])==0o444 and ref[\'identity\'][\'st_nlink\']==1,\'same immutable Root source12 namespace\')\n ref=parent[\'sourcePlacementPin\'];qr=parent[\'placementQualificationPin\'];root=\'/run/opemos-steamos-placement-\'+nonce\n peer.need(ref[\'path\']==root+\'/storage-contract.json\'and qr[\'path\']==root+\'/placement-qualified.json\',\'fresh exact placement+qualification names, no historical receipt\')\n with peer.RootFiles(root)as files:\n  raw,actual=files.read(\'storage-contract.json\');qualified,qactual=files.read(\'placement-qualified.json\');peer.need(actual==ref and qactual==qr,\'fresh placement/qualification exact full9/EOF/SHA\')\n value=json.loads(raw);q=json.loads(qualified);b=value[\'preparationBinding\']\n peer.need(value[\'kind\']==\'ROOT_EXACT_STEAMOS_FIXED_GAMES_PLACEMENT\'and value[\'nonce\']==nonce and value[\'boot\']==parent[\'bootID\']and value[\'working\']==candidate[\'working\'],\'same current prepared working placement, no relabel\')\n peer.need(b[\'sourceRoles\']==roles and b[\'queuePrograms\']==parent[\'queuePrograms\']and b[\'sourceGraphSHA256\']==hashlib.sha256(peer.canon(roles)).hexdigest(),\'placement producer source12/current queue equality\')\n peer.need(q[\'kind\']==\'ROOT_VERIFIED_FRESH_STEAMOS_PLACEMENT\'and q[\'qualifiedPlacementPin\']==ref and q[\'nonce\']==nonce and q[\'bootID\']==parent[\'bootID\']and q[\'sourceRoles\']==roles and q[\'queuePrograms\']==parent[\'queuePrograms\']and q[\'runtimeAuthorized\']is False and q[\'RootIssuedRuntimeAuthority\']is False,\'complete fresh protected metadata qualification, not a runtime grant\')\n pre=q[\'currentPreflight\'];peer.need(q[\'currentPreflightPin\']==parent[\'prequeuePreflightPin\']and pre[\'bootID\']==parent[\'bootID\']and pre[\'storagePlacement\'][\'receiptPin\']==ref and pre[\'queuePrograms\']==parent[\'queuePrograms\']and pre[\'original\']==candidate[\'original\']and pre[\'working\']==candidate[\'working\']and 0<=parent[\'issuedUnix\']-pre[\'observedUnix\']<=30,\'existing normal complete current preflight joins placement before parent issuance\')\n if context is not None:peer.need(context[\'parentPin\']==parent_ref and context[\'candidate\']==candidate and context[\'sourceRoles\']==roles and context[\'sourcePlacementPin\']==ref and context[\'placementQualificationPin\']==qr,\'context/parent/source12/placement equality\')\n peer.need(peer.SOURCE_PLACEMENT_PIN is None or peer.SOURCE_PLACEMENT_PIN==ref,\'never replace a different bound placement operand\')\n peer.SOURCE_PLACEMENT_PIN=ref\n return {\'placementPin\':ref,\'qualificationPin\':qr,\'sourceGraphSHA256\':b[\'sourceGraphSHA256\'],\'runtimeAuthorityIssued\':False}\n\n@contextlib.contextmanager\ndef load_pair(v):\n previous={k:sys.modules.get(k)for k in(\'libvirt_peer\',\'libvirt_access\')}\n try:\n  roles=v[\'parent\'][\'sourceRoles\'];modules={}\n  for name in(\'libvirt_peer\',\'libvirt_access\'):\n   module=types.ModuleType(name);module.__file__=roles[name][\'path\'];sys.modules[name]=module;exec(compile(v[\'source\'][name],module.__file__,\'exec\'),module.__dict__);modules[name]=module\n  yield modules[\'libvirt_peer\'],modules[\'libvirt_access\']\n finally:\n  for name,old in previous.items():\n   if old is None:sys.modules.pop(name,None)\n   else:sys.modules[name]=old\n\ndef run(request,io,boot,observe=None):\n v=verify_inputs(request,io,boot)\n with contextlib.ExitStack()as custody:\n  heldPlacement=custody.enter_context(io.hold_placement(v[\'parent\'][\'sourcePlacementPin\']));heldQualification=custody.enter_context(io.hold_placement(v[\'parent\'][\'placementQualificationPin\']))\n  with load_pair(v)as(peer,access):\n   peer.validate_request(request);binding=bind_placement(peer,v[\'parent\'],v[\'parentPin\'],v[\'context\']);need(binding[\'placementPin\']==heldPlacement[\'ref\']and binding[\'qualificationPin\']==heldQualification[\'ref\'],\'binding consumes the two retained exact placement pins\');proof=peer.observe(request)if observe is None else observe(peer,request)\n   need(v[\'context\']is not None or proof[\'phase\']==\'NOT_PREPARED\',\'missing context permits only actual NOT_PREPARED, never ACTIVE/CLOSED\')\n   need(proof[\'request\']==request and proof[\'sourceSHA256\']==PEER_SHA and proof[\'phase\']in(\'NOT_PREPARED\',\'PREPARED\',\'ACTIVE\',\'CLOSED\')and proof[\'allOwnedDescriptorsClosed\']is True and proof[\'effects\']==[],\'unchanged complete readonly observer proof and closure\')\n  # Every complete source and protected control is reread after observer use.\n  for name,ref in v[\'parent\'][\'sourceRoles\'].items():need(io.read(ref,0o444,65536)==v[\'source\'][name],\'post-use exact source12 bytes\')\n  need(io.read(v[\'parentPin\'],0o444,1048576)==v[\'parentRaw\'],\'post-use exact parent bytes\')\n  if v[\'context\']is not None:\n   need(io.read(v[\'contextPin\'],0o400,1048576)==v[\'contextRaw\'],\'post-use exact context bytes\');io.read(v[\'assignmentPin\'],0o400,1048576);io.read(v[\'grantPin\'],0o400,1048576)\n  else:\n   try:io.read_path(\'/run/opemos-libvirt-runtime-\'+NONCE+\'/context.json\',0o400,1048576)\n   except FileNotFoundError:pass\n   else:raise RuntimeError(\'context absence changed during exact NOT_PREPARED observation; no retry\')\n  heldPlacement[\'recheck\']();heldQualification[\'recheck\']()\n  result={\'kind\':\'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION\',\'upstreamObserver\':v[\'parent\'][\'sourceRoles\'][\'libvirt_peer\'],\'implementation\':{\'contract\':CONTRACT,\'peer\':v[\'parent\'][\'sourceRoles\'][\'libvirt_peer\'],\'access\':v[\'parent\'][\'sourceRoles\'][\'libvirt_access\'],\'sourceRoles\':v[\'parent\'][\'sourceRoles\'],\'parent\':v[\'parentPin\'],\'context\':v[\'contextPin\'],\'assignment\':v[\'assignmentPin\'],\'grant\':v[\'grantPin\'],\'placementBinding\':binding},\'proof\':proof,\'effects\':[]}\n  need(len(canonical(result).encode())+1<=1048576,\'unchanged whole Root1MiB envelope\');return result\n\ndef main():\n need(os.getuid()==0 and len(sys.argv)==4 and sys.argv[1]==PEER_SHA and sys.argv[2]==\'--queue-libvirt-request-json\',\'exact existing Root standalone queue argv\')\n request=json.loads(sys.argv[3]);before=set(os.listdir(\'/proc/self/fd\'))\n with RootInputs()as io:result=run(request,io,Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip())\n need(before==set(os.listdir(\'/proc/self/fd\')),\'adapter full owned FD closure\');print(canonical(result),flush=True)\nif __name__==\'__main__\':\n try:main()\n except BaseException as e:\n  print(canonical({\'kind\':\'QUEUE_LIBVIRT_FIRST_REFUSAL\',\'type\':type(e).__name__,\'reason\':str(e),\'effects\':[],\'evidence\':getattr(e,\'evidence\',None),\'workingEvidence\':getattr(e,\'workingEvidence\',None),\'placementCustody\':getattr(e,\'placementCustody\',None),\'ownedPlacementCloseErrors\':getattr(e,\'ownedPlacementCloseErrors\',[]),\'traceback\':traceback.format_exc()}),file=sys.stderr,flush=True);sys.exit(1)\n'
def validate_d24_peer_envelope(value, request, upstream_full_pin):
    require(set(value) == {'kind', 'upstreamObserver', 'implementation', 'proof', 'effects'} and value['kind'] == 'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION' and (value['effects'] == []), 'exact readonly implementation envelope')
    peer = value['upstreamObserver']
    require(peer == upstream_full_pin and peer['sha256'] == D24_PEER_SHA and (peer['bytes'] == D24_PEER_BYTES) and (request['observer'] == {k: peer[k] for k in ('path', 'bytes', 'sha256')}), 'original upstream held full9+minimal observer membership')
    i = value['implementation']
    require(set(i) == {'contract', 'peer', 'access', 'sourceRoles', 'parent', 'context', 'assignment', 'grant', 'placementBinding'} and i['contract'] == D24_ADAPTER_CONTRACT and (i['peer'] == peer), 'exact adopted standalone adapter schema')
    roles = i['sourceRoles']
    expected = {'libvirt_peer', 'libvirt_access', 'libvirt_native', 'libvirt_preflight', 'libvirt_producer', 'queue_assignment', 'runtime_entry', 'guest_delta', 'guest_firmware_probe', 'held_history_reader', 'two_boot_contract', 'postqueue_issuer'}
    require(set(roles) == expected and roles['libvirt_peer'] == peer and (roles['libvirt_access'] == i['access']) and (i['access']['sha256'] == D24_ACCESS_SHA) and (i['access']['bytes'] == 15340), 'whole source12/peer/access identity')
    nonce = request['leaseNonce']
    require(nonce == '0d3acd6323384c5cab8837f801e0cb42', 'only fresh D23 scope; old D22 adapter remains separate')
    for name, ref in roles.items():
        require(ref['path'] == '/run/opemos-steamos-source-' + nonce + '/' + name + '.py' and ref['identity']['st_uid'] == ref['identity']['st_gid'] == 0 and (stat.S_IMODE(ref['identity']['st_mode']) == 292) and (ref['identity']['st_nlink'] == 1), 'complete same-scope Root source pins')
    current_parent=installer_root_value(i['parent'],0o444,1048576)
    paths=__import__('source_contract').parent_paths(current_parent)
    require(i['parent']['path']==paths['parentPath'],'exact authenticated parent name')
    if i['context'] is None:
        require(value['proof']['phase'] == 'NOT_PREPARED' and i['assignment'] is None and (i['grant'] is None), 'context absent only with actual NOT_PREPARED; no closure projection')
    else:
        require(i['context']['path'] == paths['runtimeRoot'] + '/context.json' and i['assignment']['path'] == paths['runtimeRoot'] + '/assignment.json' and (i['grant']['path'] == paths['runtimeRoot'] + '/child-grant.json'), 'exact context/assignment/grant names')
    b = i['placementBinding']
    require(set(b) == {'placementPin', 'qualificationPin', 'sourceGraphSHA256', 'runtimeAuthorityIssued'} and b['runtimeAuthorityIssued'] is False and (b['sourceGraphSHA256'] == hashlib.sha256(json.dumps(roles, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()) and (b['placementPin']['path'] == '/run/opemos-steamos-placement-' + nonce + '/storage-contract.json') and (b['qualificationPin']['path'] == '/run/opemos-steamos-placement-' + nonce + '/placement-qualified.json'), 'lossless exact full graph placement binding, no authority projection')

    def rootpin(ref, mode, cap):
        require(type(ref) is dict and set(ref) == {'path', 'bytes', 'sha256', 'identity'} and (0 < ref['bytes'] <= cap) and (len(ref['sha256']) == 64), 'complete bounded full pin')
        a = ref['identity']
        require(set(a) == {'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'} and stat.S_ISREG(a['st_mode']) and (stat.S_IMODE(a['st_mode']) == mode) and (a['st_uid'] == a['st_gid'] == 0) and (a['st_nlink'] == 1) and (a['st_size'] == ref['bytes']), 'exact Root full9 regular leaf custody')
    rootpin(i['parent'], 292, 1048576)
    for ref in roles.values():
        rootpin(ref, 292, 65536)
    for ref in (b['placementPin'], b['qualificationPin']):
        rootpin(ref, 256, 1048576)
    if i['context'] is not None:
        for ref in (i['context'], i['assignment'], i['grant']):
            rootpin(ref, 256, 1048576)
    proof = value['proof']
    require(proof['request'] == request and proof['sourceSHA256'] == D24_PEER_SHA and (proof['phase'] in ('NOT_PREPARED', 'PREPARED', 'ACTIVE', 'CLOSED')) and (proof['allOwnedDescriptorsClosed'] is True) and (proof['effects'] == []), 'unchanged native observer proof required')
    return (proof, {'upstreamObserver': peer, 'implementation': i})



# Source-only exact installer extension on reviewed67f; tick is never borrowed from966.
INSTALLER_PEER_SHA='af51ceff147712aefa294102fe470d88a8dbcf13066fe923f62d8cd9fa6b993a'


INSTALLER_PEER_BYTES=62228


INSTALLER_ACCESS_SHA='7a9a952afe49277ac929e340e580d8e1a2fd8e831799bc7399e9e2093b430325'
INSTALLER_ACCESS_BYTES=22226


INSTALLER_ADAPTER_CONTRACT='D24_ROOT_PARENT_CONTEXT_SOURCE12_FRESH_PLACEMENT_READONLY'


INSTALLER_ROOT_ADAPTER = '"""Exact D23 readonly standalone peer/access adapter proposal, never installed.\nNo deployment, writes, SQL, runtime grant, domain control or sysfs methods.\nQueue owner must independently adopt exact bytes and consumer contract.\n"""\nimport contextlib,copy,hashlib,json,os,re,stat,sys,time,traceback,types\nfrom pathlib import Path\nF=(\'st_dev\',\'st_ino\',\'st_mode\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\');CORE=F[:6]\nNONCE=\'cd9ef0826364409da287f6f3e3830c95\';CONTRACT=\'D24_ROOT_PARENT_CONTEXT_SOURCE12_FRESH_PLACEMENT_READONLY\'\nPEER_SHA=\'af51ceff147712aefa294102fe470d88a8dbcf13066fe923f62d8cd9fa6b993a\';PEER_BYTES=62228\nACCESS_SHA=\'7a9a952afe49277ac929e340e580d8e1a2fd8e831799bc7399e9e2093b430325\';ACCESS_BYTES=22226\nROLES={\'libvirt_peer\',\'libvirt_access\',\'libvirt_native\',\'libvirt_preflight\',\'libvirt_producer\',\'queue_assignment\',\'runtime_entry\',\'guest_delta\',\'guest_firmware_probe\',\'held_history_reader\',\'two_boot_contract\',\'postqueue_issuer\'}\ndef canonical(v):return json.dumps(v,sort_keys=True,separators=(\',\',\':\'),allow_nan=False)\ndef need(v,m):\n if not v:raise RuntimeError(m)\ndef ident(s):return{k:getattr(s,k)for k in F}\ndef decode(raw):\n def unique(pairs):\n  value={}\n  for key,item in pairs:need(key not in value,\'duplicate protected JSON key\');value[key]=item\n  return value\n value=json.loads(raw,object_pairs_hook=unique);need(canonical(value).encode()==raw,\'whole canonical protected metadata, no dropped/trailing fields\');return value\nclass RootInputs:\n """One readonly bounded held-nofollow /run graph; owns and closes all FDs."""\n def __init__(self):self.fds=[];self.dirs={}\n def __enter__(self):\n  self.root=os.open(\'/\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.fds.append(self.root)\n  try:\n   self.run=os.open(\'run\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.root);self.fds.append(self.run)\n   self.dirs={\'/\':(self.root,ident(os.fstat(self.root)),False),\'/run\':(self.run,ident(os.fstat(self.run)),False)};self.check();return self\n  except BaseException:\n   self.__exit__(*sys.exc_info());raise\n def check(self):\n  for path,(fd,a,exclusive)in self.dirs.items():\n   x=ident(os.fstat(fd));need(x==ident(os.lstat(path))and all(x[k]==a[k]for k in(CORE if not exclusive else F)),\'held/named declared directory identity/epoch\')\n   need(stat.S_ISDIR(x[\'st_mode\'])and x[\'st_uid\']==x[\'st_gid\']==0,\'Root directory nofollow custody\')\n   need(stat.S_IMODE(x[\'st_mode\'])in((0o755,0o777)if path==\'/\'else(0o755,)if path==\'/run\'else(0o755,)if path.startswith(\'/run/opemos-steamos-source-\')else(0o700,)),\'exact role-specific directory mode\')\n def directory(self,path):\n  allowed={\'/run/opemos-steamos-source-\'+NONCE,\'/run/opemos-libvirt-runtime-\'+NONCE,\'/run/opemos-steamos-placement-\'+NONCE}\n  need(path in allowed,\'declared finite source/context/placement root only\')\n  if path not in self.dirs:\n   fd=os.open(Path(path).name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.run);self.fds.append(fd);self.dirs[path]=(fd,ident(os.fstat(fd)),True)\n  self.check();return self.dirs[path][0]\n def read_path(self,path,mode,cap):\n  path=Path(path);need(path.is_absolute()and path.name not in(\'\',\'.\',\'..\'),\'absolute confined declared leaf\')\n  if str(path.parent)==\'/run\':need(str(path)==\'/run/opemos-libvirt-parent-\'+NONCE+\'.json\',\'one normal public parent only\');parent=self.run\n  else:parent=self.directory(str(path.parent))\n  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)\n  try:\n   s=os.fstat(fd);a=ident(s);need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode and s.st_nlink==1 and s.st_size<=cap,\'exact Root leaf mode/owner/link/size\');raw=b\'\'\n   while chunk:=os.read(fd,65536):raw+=chunk;need(len(raw)<=cap,\'bounded full leaf stream\')\n   need(a==ident(os.fstat(fd))==ident(os.stat(path.name,dir_fd=parent,follow_symlinks=False))==ident(os.lstat(path))and len(raw)==a[\'st_size\'],\'full held/anchored/named identity and EOF\');self.check();return raw,{\'path\':str(path),\'bytes\':len(raw),\'sha256\':hashlib.sha256(raw).hexdigest(),\'identity\':a}\n  finally:os.close(fd)\n def read(self,ref,mode,cap):\n  raw,actual=self.read_path(ref[\'path\'],mode,cap);need(actual==ref,\'exact declared full9/length/SHA pin\');return raw\n def placement_bytes(self,fd,parentfd,ref):\n  """Inner FD/hash check; hold_placement applies exact Root role custody.\n  It does not change Root policy or convert a user fixture into Root proof.\n  """\n  value={\'path\':ref[\'path\'],\'expected\':ref,\'heldBefore\':None,\'heldAfter\':None,\'named\':None,\'heldSHA256\':None,\'namedSHA256\':None,\'heldBytes\':None,\'namedBytes\':None}\n  def bytesof(f):\n   chunks=[];offset=0\n   while True:\n    b=os.pread(f,65536,offset)\n    if not b:break\n    offset+=len(b);need(offset<=1048576,\'unchanged placement metadata1MiB streaming cap\');chunks.append(b)\n   return b\'\'.join(chunks)\n  try:\n   value[\'heldBefore\']=ident(os.fstat(fd));need((__import__(\'fcntl\').fcntl(fd,__import__(\'fcntl\').F_GETFL)&os.O_ACCMODE)==os.O_RDONLY,\'owned placement held FD remains O_RDONLY\');held=bytesof(fd);value.update(heldBytes=len(held),heldSHA256=hashlib.sha256(held).hexdigest())\n   nf=os.open(Path(ref[\'path\']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)\n   try:\n    value[\'named\']=ident(os.fstat(nf));named=bytesof(nf);value.update(namedBytes=len(named),namedSHA256=hashlib.sha256(named).hexdigest());need(value[\'named\']==ident(os.fstat(nf))==ident(os.stat(Path(ref[\'path\']).name,dir_fd=parentfd,follow_symlinks=False))==ident(os.lstat(ref[\'path\'])),\'placement fresh nofollow named FD/path full9\')\n   finally:\n    primary=sys.exc_info()[1]\n    try:os.close(nf)\n    except BaseException as close:\n     if primary is None:raise\n     primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'fd\':nf,\'type\':type(close).__name__,\'reason\':str(close)}]\n   value[\'heldAfter\']=ident(os.fstat(fd));need(value[\'heldBefore\']==value[\'heldAfter\']==value[\'named\']==ref[\'identity\']and len(held)==len(named)==ref[\'bytes\']and value[\'heldSHA256\']==value[\'namedSHA256\']==ref[\'sha256\']and held==named,\'placement held/named full9/raw bytes/length/SHA equal originally bound operand\')\n   return held\n  except BaseException as error:error.placementCustody=value;raise\n @contextlib.contextmanager\n def hold_placement(self,ref):\n  root=\'/run/opemos-steamos-placement-\'+NONCE;need(ref[\'path\']in(root+\'/storage-contract.json\',root+\'/placement-qualified.json\'),\'two exact placement metadata leaves only\');i=ref[\'identity\'];need(set(ref)=={\'path\',\'bytes\',\'sha256\',\'identity\'}and 0<ref[\'bytes\']<=1048576 and stat.S_ISREG(i[\'st_mode\'])and stat.S_IMODE(i[\'st_mode\'])==0o400 and i[\'st_uid\']==i[\'st_gid\']==0 and i[\'st_nlink\']==1 and i[\'st_size\']==ref[\'bytes\'],\'exact Root0400 placement full pin/custody\')\n  parentfd=self.directory(root);fd=os.open(Path(ref[\'path\']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)\n  try:\n   original=self.placement_bytes(fd,parentfd,ref);self.check()\n   def recheck():\n    self.check();raw=self.placement_bytes(fd,parentfd,ref);need(raw==original,\'complete held placement raw bytes identical after observer\');self.check();return ref\n   yield {\'ref\':ref,\'raw\':original,\'recheck\':recheck}\n  finally:\n   primary=sys.exc_info()[1]\n   try:os.close(fd)\n   except BaseException as close:\n    if primary is None:raise\n    primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'fd\':fd,\'type\':type(close).__name__,\'reason\':str(close)}]\n def __exit__(self,*a):\n  errors=[]\n  for fd in self.fds[::-1]:\n   try:os.close(fd)\n   except OSError as e:errors.append({\'fd\':fd,\'type\':type(e).__name__,\'reason\':str(e)})\n  self.fds=[]\n  if errors:\n   if a[1]is not None:a[1].ownedRootInputClosureErrors=errors\n   else:raise RuntimeError(canonical({\'ownedRootInputClosureErrors\':errors}))\n\ndef parent_spec(parent,parent_ref):\n s=copy.deepcopy(parent[\'normalizedSpecTemplate\']);need(s[\'approval\']==\'EXACT_PARENT_MINIMAL_PIN\'and s[\'command\'][-1]==\'EXACT_PARENT_FULL_PIN_JSON\',\'two existing late parent-pin slots only\');s[\'approval\']={k:parent_ref[k]for k in(\'path\',\'bytes\',\'sha256\')};s[\'command\'][-1]=canonical(parent_ref)\n need(s[\'command\']==[\'sudo\',\'-n\',\'/usr/bin/python3\',\'-B\',parent[\'sourceRoles\'][\'runtime_entry\'][\'path\'],\'--parent-pin-json\',canonical(parent_ref)]and s[\'id\']==parent[\'jobId\']and s[\'cores\']==4 and s[\'memory\']==10737418240 and s[\'timeout_seconds\']==900 and \'omen-iommu-group-1\'in s[\'resources\'],\'exact ordinary entry and10GiB/4CPU/900s spec\')\n return s\n\ndef verify_inputs(request,io,boot):\n need(request[\'leaseNonce\']==NONCE and request[\'domainName\']==\'opemos-libvirt-\'+NONCE,\'fresh exact D23 scope only\')\n cr=\'/run/opemos-libvirt-runtime-\'+NONCE+\'/context.json\';parentRaw,parentRef=io.read_path(\'/run/opemos-libvirt-parent-\'+NONCE+\'.json\',0o444,1048576);parent=decode(parentRaw)\n try:contextRaw,contextRef=io.read_path(cr,0o400,1048576);context=decode(contextRaw)\n except FileNotFoundError:contextRaw=contextRef=context=None\n need(parent[\'kind\']==\'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT\'and parent[\'RootIssued\']is True and parent[\'runtimeAuthorized\']is True and parent.get(\'MODEL_ONLY\')is False and parent[\'bootID\']==boot and parent[\'nonce\']==NONCE and parent[\'contextPath\']==cr,\'existing actual same-boot Root parent; no issuance or clock refresh\')\n if context is not None:need(context[\'parentPin\']==parentRef and context[\'kind\']==\'ROOT_LIBVIRT_R4_RUNTIME_CONTEXT\'and context[\'runtimeAuthorized\']is True and context.get(\'MODEL_ONLY\')is False and context[\'candidate\']==parent[\'candidate\']and context[\'sourceRoles\']==parent[\'sourceRoles\'],\'Root context/candidate/source12 equality; no model promotion\')\n need(type(parent[\'candidate\'].get(\'installer\'))is dict and parent[\'candidate\'][\'installer\'].get(\'kind\')==\'AUTHENTICATED_F9AA_RAW_RECOVERY_USB_FIRSTBOOT\'and parent[\'candidate\'][\'installer\'].get(\'noInstallTarget\')is True,\'this reviewed source branch admits only the retained installer/no target\')\n need(parent[\'issuedUnix\']<parent[\'startBeforeUnix\']<=parent[\'issuedUnix\']+300 and parent[\'wholeDeadlineUnix\']<=parent[\'issuedUnix\']+900,\'original finite parent scope retained; readonly closed observation does not reissue authority\')\n roles=parent[\'sourceRoles\'];need(set(roles)==ROLES,\'complete source12 membership\')\n need(roles[\'libvirt_peer\'][\'bytes\']==62228 and roles[\'libvirt_peer\'][\'sha256\']==PEER_SHA and roles[\'libvirt_access\'][\'bytes\']==ACCESS_BYTES and roles[\'libvirt_access\'][\'sha256\']==ACCESS_SHA,\'frozen reviewed peer/access implementation\')\n need(request[\'observer\']=={k:roles[\'libvirt_peer\'][k]for k in(\'path\',\'bytes\',\'sha256\')}and request[\'jobId\']==parent[\'jobId\'],\'exact original request observer/job\')\n source={}\n for name,ref in sorted(roles.items()):\n  need(ref[\'path\']==\'/run/opemos-steamos-source-\'+NONCE+\'/\'+name+\'.py\',\'same exact source namespace\');source[name]=io.read(ref,0o444,65536);compile(source[name],ref[\'path\'],\'exec\')\n spec=parent_spec(parent,parentRef);bound=spec[\'libvirt_domain\'];need(bound=={\'leaseNonce\':NONCE,\'name\':request[\'domainName\'],\'observer\':request[\'observer\'],\'uuid\':request[\'domainUUID\']}and hashlib.sha256(canonical(spec).encode()).hexdigest()==request[\'specSHA256\'],\'complete final normalized spec/hash/domain identity\')\n assignmentRef=grantRef=None;assignment=grant=None\n if context is not None:\n  assignmentRef=context[\'assignmentPin\'];need(assignmentRef[\'path\']==\'/run/opemos-libvirt-runtime-\'+NONCE+\'/assignment.json\'and context[\'grantPin\'][\'path\']==\'/run/opemos-libvirt-runtime-\'+NONCE+\'/child-grant.json\',\'two exact same-scope child control leaves\');assignment=decode(io.read(assignmentRef,0o400,1048576));grantRef=context[\'grantPin\'];grant=decode(io.read(grantRef,0o400,1048576))\n  need(assignment[\'kind\']==\'ROOT_CANONICAL_QUEUE_LIBVIRT_ASSIGNMENT_R4\'and assignment[\'request\']==request and grant[\'assignmentPin\']==assignmentRef and grant[\'parentPin\']==parentRef and grant[\'normalizedSpecSHA256\']==request[\'specSHA256\'],\'canonical assignment and child grant exact request/spec/parent\')\n  need(grant[\'queuePrograms\']==parent[\'queuePrograms\']and grant[\'sourcePlacementPin\']==context[\'sourcePlacementPin\']==parent[\'sourcePlacementPin\']and grant[\'placementQualificationPin\']==context[\'placementQualificationPin\']==parent[\'placementQualificationPin\'],\'current queue authority and placement pins across child/context/parent\')\n  need(grant[\'RootIssued\']is True and grant[\'MODEL_ONLY\']is False and grant[\'runtimeAuthorized\']is True and grant[\'jobId\']==request[\'jobId\']and grant[\'leaseNonce\']==NONCE and grant[\'bootID\']==boot and parent[\'issuedUnix\']<=grant[\'issuedUnix\']<grant[\'startBeforeUnix\']<=parent[\'startBeforeUnix\']and grant[\'wholeDeadlineUnix\']<=parent[\'wholeDeadlineUnix\'],\'existing finite Root child only, no new runtime grant\')\n return {\'parent\':parent,\'parentPin\':parentRef,\'parentRaw\':parentRaw,\'context\':context,\'contextPin\':contextRef,\'contextRaw\':contextRaw,\'source\':source,\'assignmentPin\':assignmentRef,\'assignmentRaw\':None if assignment is None else canonical(assignment).encode(),\'grantPin\':grantRef,\'grantRaw\':None if grant is None else canonical(grant).encode()}\n\ndef _bind_placement(peer,parent,parent_ref,context,verify_access):\n """Bind only the fresh protected same-source/same-scope metadata operand.\n Never changes the frozen peer\'s nonce, strict geometry or owner predicate.\n """\n nonce=parent[\'nonce\'];roles=parent[\'sourceRoles\'];candidate=parent[\'candidate\']\n peer.need(nonce==\'cd9ef0826364409da287f6f3e3830c95\'and peer.SOURCE_PLACEMENT_NONCE==nonce and candidate[\'nonce\']==nonce and __import__(\'queue_assignment\').execution_job(candidate,parent)==parent[\'jobId\'],\'D23 unused scope only; D22 is consumed\')\n peer.need(parent[\'RootIssued\']is True and parent[\'kind\']==\'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT\'and parent[\'bootID\']==candidate[\'hostBoot\']and parent_ref[\'path\']==\'/run/opemos-libvirt-parent-\'+nonce+\'.json\',\'existing exact Root parent/boot/source scope\')\n peer.need(set(roles)=={\'libvirt_peer\',\'libvirt_access\',\'libvirt_native\',\'libvirt_preflight\',\'libvirt_producer\',\'queue_assignment\',\'runtime_entry\',\'guest_delta\',\'guest_firmware_probe\',\'held_history_reader\',\'two_boot_contract\',\'postqueue_issuer\'},\'closed twelve-role binding\')\n peer.need(roles[\'libvirt_peer\'][\'sha256\']==\'af51ceff147712aefa294102fe470d88a8dbcf13066fe923f62d8cd9fa6b993a\'and roles[\'libvirt_peer\'][\'bytes\']==62228 and roles[\'libvirt_access\'][\'sha256\']==\'7a9a952afe49277ac929e340e580d8e1a2fd8e831799bc7399e9e2093b430325\'and roles[\'libvirt_access\'][\'bytes\']==22226,\'frozen exact D23 peer and unchanged access bytes\')\n for name,ref in roles.items():peer.need(ref[\'path\']==\'/run/opemos-steamos-source-\'+nonce+\'/\'+name+\'.py\'and ref[\'identity\'][\'st_uid\']==ref[\'identity\'][\'st_gid\']==0 and stat.S_IMODE(ref[\'identity\'][\'st_mode\'])==0o444 and ref[\'identity\'][\'st_nlink\']==1,\'same immutable Root source12 namespace\')\n ref=parent[\'sourcePlacementPin\'];qr=parent[\'placementQualificationPin\'];root=\'/run/opemos-steamos-placement-\'+nonce\n peer.need(ref[\'path\']==root+\'/storage-contract.json\'and qr[\'path\']==root+\'/placement-qualified.json\',\'fresh exact placement+qualification names, no historical receipt\')\n files=peer.RootFiles(root);primary=None;result=None\n try:\n  files.__enter__()\n  raw,actual=files.read(\'storage-contract.json\');qualified,qactual=files.read(\'placement-qualified.json\');peer.need(actual==ref and qactual==qr,\'fresh placement/qualification exact full9/EOF/SHA\')\n  value=json.loads(raw);q=json.loads(qualified);b=value[\'preparationBinding\']\n  peer.need(value[\'kind\']==(\'ROOT_EXACT_STEAMOS_INSTALLER_GAMES_PLACEMENT\'if candidate.get(\'installer\')is not None else\'ROOT_EXACT_STEAMOS_FIXED_GAMES_PLACEMENT\')and value[\'nonce\']==nonce and value[\'boot\']==parent[\'bootID\']and value[\'original\']==candidate[\'original\']and value[\'working\']==candidate[\'working\']and value.get(\'installer\')==candidate.get(\'installer\'),\'same current prepared working placement, no relabel\')\n  peer.need(b[\'sourceRoles\']==roles and b[\'queuePrograms\']==parent[\'queuePrograms\']and b[\'sourceGraphSHA256\']==hashlib.sha256(peer.canon(roles)).hexdigest(),\'placement producer source12/current queue equality\')\n  peer.need(q[\'kind\']==\'ROOT_VERIFIED_FRESH_STEAMOS_PLACEMENT\'and q[\'qualifiedPlacementPin\']==ref and q[\'nonce\']==nonce and q[\'bootID\']==parent[\'bootID\']and q[\'sourceRoles\']==roles and q[\'queuePrograms\']==parent[\'queuePrograms\']and q[\'runtimeAuthorized\']is False and q[\'RootIssuedRuntimeAuthority\']is False,\'complete fresh protected metadata qualification, not a runtime grant\')\n  pre=q[\'currentPreflight\'];prepared=parent[\'preparedDiskPins\'];access_pin=parent[\'preparedAccessPin\']\n  peer.need(type(prepared)is dict and set(prepared)=={\'original\',\'working\'}and prepared[\'original\']==candidate[\'original\']and b[\'preparedDiskPins\']==prepared and access_pin is not None and b[\'preparedAccessPin\']==access_pin==pre[\'preparedAccessPin\']and b[\'splitDiskCapturePins\']==parent[\'splitDiskCapturePins\']==pre[\'splitDiskCapturePins\'],\'exact candidate/pending-access/post-ACL prepared captures/final-preflight lineage\')\n  work=prepared[\'working\'];before_work=candidate[\'working\'];peer.need(work[\'path\']==before_work[\'path\']and work[\'bytes\']==before_work[\'bytes\']and work[\'sha256\']==before_work[\'sha256\']and all(work[\'identity\'][k]==before_work[\'identity\'][k]for k in(\'st_dev\',\'st_ino\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\')),\'same content and stable pre/post ACL working object; full9 remains exact within each epoch\')\n  verify_access(candidate,access_pin,prepared)\n  peer.need(q[\'currentPreflightPin\']==parent[\'prequeuePreflightPin\']and pre[\'bootID\']==parent[\'bootID\']and pre[\'storagePlacement\'][\'receiptPin\']==ref and pre[\'queuePrograms\']==parent[\'queuePrograms\']and pre[\'original\']==candidate[\'original\']and pre[\'kind\']==\'ACTUAL_LIBVIRT_R4_CURRENT_PREFLIGHT\'and pre[\'working\']==prepared[\'working\']and 0<=parent[\'issuedUnix\']-pre[\'observedUnix\']<=30,\'existing normal complete current preflight joins placement before parent issuance\')\n  if context is not None:peer.need(context[\'parentPin\']==parent_ref and context[\'candidate\']==candidate and context[\'sourceRoles\']==roles and context[\'sourcePlacementPin\']==ref and context[\'placementQualificationPin\']==qr,\'context/parent/source12/placement equality\')\n  peer.need(peer.SOURCE_PLACEMENT_PIN is None or peer.SOURCE_PLACEMENT_PIN==ref,\'never replace a different bound placement operand\')\n  again,again_pin=files.read(\'storage-contract.json\');again_q,again_qpin=files.read(\'placement-qualified.json\');peer.need((again,again_pin)==(raw,ref)and(again_q,again_qpin)==(qualified,qr),\'original held/named placement and qualification full9/raw-SHA unchanged after prepared verification\')\n  result={\'placementPin\':ref,\'qualificationPin\':qr,\'sourceGraphSHA256\':b[\'sourceGraphSHA256\'],\'runtimeAuthorityIssued\':False}\n except BaseException as error:primary=error\n finally:\n  try:files.__exit__(None if primary is None else type(primary),primary,None)\n  except BaseException as close:\n   if primary is None:primary=close\n   else:primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'role\':\'bind-placement-ancestors\',\'type\':type(close).__name__,\'reason\':str(close)}]\n if primary is not None:raise primary\n peer.SOURCE_PLACEMENT_PIN=ref\n return result\n\ndef bind_placement(peer,parent,parent_ref,context=None):\n from libvirt_access import verify_prepared\n return _bind_placement(peer,parent,parent_ref,context,verify_prepared)\n\ndef bind_observer_placement(peer,parent,parent_ref,context):\n from libvirt_access import prepared_lineage\n return _bind_placement(peer,parent,parent_ref,context,prepared_lineage)\n\n@contextlib.contextmanager\ndef load_pair(v):\n names=(\'libvirt_peer\',\'libvirt_access\',\'guest_firmware_probe\',\'libvirt_native\',\'queue_assignment\');missing=object();previous={k:sys.modules.get(k,missing)for k in names}\n try:\n  roles=v[\'parent\'][\'sourceRoles\'];modules={}\n  for name in names:\n   module=types.ModuleType(name);module.__file__=roles[name][\'path\'];sys.modules[name]=module;exec(compile(v[\'source\'][name],module.__file__,\'exec\'),module.__dict__);modules[name]=module\n  yield modules[\'libvirt_peer\'],modules[\'libvirt_access\']\n finally:\n  for name,old in previous.items():\n   if old is missing:sys.modules.pop(name,None)\n   else:sys.modules[name]=old\n\ndef run(request,io,boot,observe=None):\n v=verify_inputs(request,io,boot)\n with contextlib.ExitStack()as custody:\n  heldPlacement=custody.enter_context(io.hold_placement(v[\'parent\'][\'sourcePlacementPin\']));heldQualification=custody.enter_context(io.hold_placement(v[\'parent\'][\'placementQualificationPin\']))\n  with load_pair(v)as(peer,access):\n   peer.validate_request(request);binding=bind_observer_placement(peer,v[\'parent\'],v[\'parentPin\'],v[\'context\']);need(binding[\'placementPin\']==heldPlacement[\'ref\']and binding[\'qualificationPin\']==heldQualification[\'ref\'],\'binding consumes the two retained exact placement pins\')\n   parent=v[\'parent\'];candidate=parent[\'candidate\']\n   def custody(phase,intent,reg,state,files):return access.verify_phase(candidate,parent[\'preparedAccessPin\'],parent[\'preparedDiskPins\'],phase,intent,reg,state,files)\n   proof=peer.observe(request,custody=custody)if observe is None else observe(peer,request,custody)\n   need(proof.get(\'accessCustody\',{}).get(\'phase\')==proof[\'phase\'],\'actual locked phase access custody required\')\n   proof[\'accessCustody\']={\'kind\':\'ROOT_PHASE_PREPARED_ACCESS_CUSTODY_R1\',\'phase\':proof[\'phase\'],\'nonce\':NONCE,\'bootID\':boot,\'requestSHA256\':hashlib.sha256(peer.canon(request)).hexdigest(),\'parentPin\':v[\'parentPin\'],\'preparedAccessPin\':parent[\'preparedAccessPin\'],\'preparedDiskPins\':parent[\'preparedDiskPins\'],\'sourceGraphSHA256\':binding[\'sourceGraphSHA256\'],\'placementPin\':binding[\'placementPin\'],\'qualificationPin\':binding[\'qualificationPin\'],\'stage\':access.prepared_lineage(candidate,parent[\'preparedAccessPin\'],parent[\'preparedDiskPins\']),\'stageRawBase64\':__import__(\'base64\').b64encode(__import__(\'libvirt_native\').held(parent[\'preparedAccessPin\'],1048576)).decode(\'ascii\'),\'data\':proof[\'accessCustody\']}\n   need(v[\'context\']is not None or proof[\'phase\']==\'NOT_PREPARED\',\'missing context permits only actual NOT_PREPARED, never ACTIVE/CLOSED\')\n   need(proof[\'request\']==request and proof[\'sourceSHA256\']==PEER_SHA and proof[\'phase\']in(\'NOT_PREPARED\',\'PREPARED\',\'ACTIVE\',\'CLOSED\')and proof[\'allOwnedDescriptorsClosed\']is True and proof[\'effects\']==[],\'unchanged complete readonly observer proof and closure\')\n  # Every complete source and protected control is reread after observer use.\n  for name,ref in v[\'parent\'][\'sourceRoles\'].items():need(io.read(ref,0o444,65536)==v[\'source\'][name],\'post-use exact source12 bytes\')\n  need(io.read(v[\'parentPin\'],0o444,1048576)==v[\'parentRaw\'],\'post-use exact parent bytes\')\n  if v[\'context\']is not None:\n   need(io.read(v[\'contextPin\'],0o400,1048576)==v[\'contextRaw\'],\'post-use exact context bytes\');io.read(v[\'assignmentPin\'],0o400,1048576);io.read(v[\'grantPin\'],0o400,1048576)\n  else:\n   try:io.read_path(\'/run/opemos-libvirt-runtime-\'+NONCE+\'/context.json\',0o400,1048576)\n   except FileNotFoundError:pass\n   else:raise RuntimeError(\'context absence changed during exact NOT_PREPARED observation; no retry\')\n  heldPlacement[\'recheck\']();heldQualification[\'recheck\']()\n  result={\'kind\':\'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION\',\'upstreamObserver\':v[\'parent\'][\'sourceRoles\'][\'libvirt_peer\'],\'implementation\':{\'contract\':CONTRACT,\'peer\':v[\'parent\'][\'sourceRoles\'][\'libvirt_peer\'],\'access\':v[\'parent\'][\'sourceRoles\'][\'libvirt_access\'],\'sourceRoles\':v[\'parent\'][\'sourceRoles\'],\'parent\':v[\'parentPin\'],\'context\':v[\'contextPin\'],\'assignment\':v[\'assignmentPin\'],\'grant\':v[\'grantPin\'],\'placementBinding\':binding},\'proof\':proof,\'effects\':[]}\n  need(len(canonical(result).encode())+1<=1048576,\'unchanged whole Root1MiB envelope\');return result\n\ndef main():\n need(os.getuid()==0 and len(sys.argv)==4 and sys.argv[1]==PEER_SHA and sys.argv[2]==\'--queue-libvirt-request-json\',\'exact existing Root standalone queue argv\')\n request=json.loads(sys.argv[3]);before=set(os.listdir(\'/proc/self/fd\'))\n with RootInputs()as io:result=run(request,io,Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip())\n need(before==set(os.listdir(\'/proc/self/fd\')),\'adapter full owned FD closure\');print(canonical(result),flush=True)\nif __name__==\'__main__\':\n try:main()\n except BaseException as e:\n  print(canonical({\'kind\':\'QUEUE_LIBVIRT_FIRST_REFUSAL\',\'type\':type(e).__name__,\'reason\':str(e),\'effects\':[],\'evidence\':getattr(e,\'evidence\',None),\'workingEvidence\':getattr(e,\'workingEvidence\',None),\'placementCustody\':getattr(e,\'placementCustody\',None),\'ownedPlacementCloseErrors\':getattr(e,\'ownedPlacementCloseErrors\',[]),\'traceback\':traceback.format_exc()}),file=sys.stderr,flush=True);sys.exit(1)\n'


# Source text inserted only into the immutable Source198 paired candidate.
def installer_root_value(ref, mode, cap):
    require(type(ref) is dict and set(ref)=={'path','bytes','sha256','identity'},'closed Root full pin')
    i=ref['identity'];fields={'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'}
    require(type(i) is dict and set(i)==fields and all(type(i[k]) is int for k in fields)and stat.S_ISREG(i['st_mode'])and stat.S_IMODE(i['st_mode'])==mode and i['st_uid']==i['st_gid']==0 and i['st_nlink']==1 and i['st_size']==ref['bytes']and 0<ref['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',ref['sha256'])is not None,'exact Root leaf identity/type/mode/length/hash')
    fd=os.open(ref['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before={k:getattr(os.fstat(fd),k)for k in fields};raw=b''
        while part:=os.read(fd,65536):raw+=part;require(len(raw)<=cap,'bounded Root input')
        require(before==i=={k:getattr(os.fstat(fd),k)for k in fields}=={k:getattr(os.lstat(ref['path']),k)for k in fields}and len(raw)==ref['bytes']and hashlib.sha256(raw).hexdigest()==ref['sha256'],'Root input held/named full9/EOF/SHA')
        return json.loads(raw)
    finally:os.close(fd)

def validate_closed_restore_epoch(current,row,now,role,disks,fullpin):
    """Authenticate the immutable restore receipt separately from current custody.

    Runtime-parent VNC create/unlink is the sole declared CLOSED timestamp epoch;
    every other role remains full9-equal to the retained restore record.
    """
    fullpin(current['restorePin'],0o400,1048576)
    encoded=current['restoreRawBase64'];require(type(encoded)is str and len(encoded)<=1398104,'bounded immutable restore raw carrier')
    raw=__import__('base64').b64decode(encoded,validate=True)
    require(__import__('base64').b64encode(raw).decode('ascii')==encoded and len(raw)==current['restorePin']['bytes']<=1048576 and hashlib.sha256(raw).hexdigest()==current['restorePin']['sha256'],'whole immutable restore raw length/SHA relation')
    restored=json.loads(raw);require(canonical(restored).encode()==raw,'canonical immutable restore record')
    expected={'path':row['path'],'identity':restored.get('identity'),'ACL':current['ACL'],'restored':True,'contentMayHaveGuestWrites':role=='working'}
    if current['content']is not None:expected.update(current['content'])
    require(restored==expected,'exact immutable restore record schema/content relation')
    stable=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size')
    require(all(restored['identity'][k]==now[k]for k in stable),'current CLOSED stable restore object identity')
    require(role=='runtime-parent' or restored['identity']==now,'only runtime parent permits declared current timestamp epoch drift')
    if role=='working':require(current['content']=={k:disks['working'][k]for k in('bytes','sha256')}and all(now[k]==disks['working']['identity'][k]for k in('st_dev','st_ino','st_uid','st_gid','st_nlink','st_size','st_mtime_ns')),'readonly working content unchanged after closure')
    return restored


def validate_current_io_ancestor(candidate,recorded):
    """Independent queue consumer uses O_PATH: traversal grants no listing/read."""
    path=__import__('source_contract').candidate_paths(candidate)['ioRoot']
    fields={'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'}
    require(type(recorded)is dict and set(recorded)=={'path','identity'}and recorded['path']==path,'exact current stage IO ancestor path')
    old=recorded['identity'];require(type(old)is dict and set(old)==fields and all(type(x)is int for x in old.values())and stat.S_ISDIR(old['st_mode'])and stat.S_IMODE(old['st_mode'])==0o711 and old['st_uid']==old['st_gid']==0,'Root traverse-only stage IO ancestor identity')
    fds=[];names=[];at=Path('/')
    try:
        fd=os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd);names.append(('/',fd))
        for part in Path(path).parts[1:]:
            fd=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);fds.append(fd);at/=part;names.append((str(at),fd))
        core=('st_dev','st_ino','st_mode','st_uid','st_gid')
        for name,fd in names:
            a=os.fstat(fd);b=os.lstat(name)
            require(a.st_uid==a.st_gid==0 and not a.st_mode&0o022 and all(getattr(a,k)==getattr(b,k)for k in core),'same protected nofollow IO ancestor chain')
        now=os.fstat(fds[-1]);require(all(getattr(now,k)==old[k]for k in core),'same current IO ancestor inode/owner/mode')
    finally:
        for fd in reversed(fds):os.close(fd)


def validate_installer_access_custody(custody, proof, request, implementation=None):
    fields9={'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'};core=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink');roles6=['working-parent','working','runtime-parent','vars','output-parent','serial']
    def meta(i,kind):
        require(type(i)is dict and set(i)==fields9 and all(type(i[k])is int for k in fields9)and stat.S_IFMT(i['st_mode'])==kind and i['st_nlink']>0,'exact phase full9/type')
    def fullpin(ref,mode=None,cap=None,immutable_media=False):
        require(type(ref)is dict and set(ref)=={'path','bytes','sha256','identity'}and type(ref['path'])is str and ref['path'].startswith('/')and '..'not in Path(ref['path']).parts and type(ref['bytes'])is int and ref['bytes']>=0 and re.fullmatch('[0-9a-f]{64}',ref['sha256'])is not None,'complete bounded phase pin')
        meta(ref['identity'],stat.S_IFREG);i=ref['identity'];require(((i['st_uid'],i['st_gid'])==(64055,993)if immutable_media else i['st_uid']==i['st_gid']==0) and i['st_nlink']==1 and i['st_size']==ref['bytes']and(mode is None or stat.S_IMODE(i['st_mode'])==mode)and(cap is None or 0<ref['bytes']<=cap),'phase pin owner/link/mode/cap')
    keys={'kind','phase','nonce','bootID','requestSHA256','parentPin','preparedAccessPin','preparedDiskPins','sourceGraphSHA256','placementPin','qualificationPin','stage','stageRawBase64','data'}
    require(type(custody)is dict and set(custody)==keys and custody['kind']=='ROOT_PHASE_PREPARED_ACCESS_CUSTODY_R1'and custody['phase']==proof['phase']and custody['nonce']==request['leaseNonce']and custody['bootID']==proof['bootID']and custody['requestSHA256']==hashlib.sha256(canonical(request).encode()).hexdigest(),'closed purpose/phase/request/boot access custody')
    parentref=custody['parentPin'];require((parentref==request['currentControl']['parentPin']if 'currentControl'in request else parentref['path']=='/run/opemos-libvirt-parent-'+request['leaseNonce']+'.json'),'same exact custody parent');parent=installer_root_value(parentref,0o444,1048576)
    require(parent['kind']=='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT'and parent['RootIssued']is True and parent['runtimeAuthorized']is True and parent.get('MODEL_ONLY')is False and parent['jobId']==request['jobId']and parent['nonce']==request['leaseNonce']and parent['bootID']==proof['bootID'],'genuine same parent/request purpose')
    template=json.loads(json.dumps(parent['normalizedSpecTemplate']));require(template['approval']=='EXACT_PARENT_MINIMAL_PIN'and template['command'][-1]=='EXACT_PARENT_FULL_PIN_JSON','exact two late parent slots');template['approval']={k:parentref[k]for k in('path','bytes','sha256')};template['command'][-1]=canonical(parentref)
    require(hashlib.sha256(canonical(template).encode()).hexdigest()==request['specSHA256']and template['id']==request['jobId']and template['libvirt_domain']=={'uuid':request['domainUUID'],'name':request['domainName'],'leaseNonce':request['leaseNonce'],'observer':request['observer']},'whole normalized queue spec and parent source identity')
    require(custody['preparedAccessPin']==parent['preparedAccessPin']and custody['preparedDiskPins']==parent['preparedDiskPins']and custody['placementPin']==parent['sourcePlacementPin']and custody['qualificationPin']==parent['placementQualificationPin']and custody['sourceGraphSHA256']==hashlib.sha256(canonical(parent['sourceRoles']).encode()).hexdigest(),'exact parent/stage/disks/source/placement custody')
    if implementation is not None:
        b=implementation['placementBinding'];require(parent['sourceRoles']==implementation['sourceRoles']and parentref==implementation['parent']and custody['placementPin']==b['placementPin']and custody['qualificationPin']==b['qualificationPin']and custody['sourceGraphSHA256']==b['sourceGraphSHA256'],'implementation/parent/source/placement exact joins')
    fullpin(custody['preparedAccessPin'],0o400,1048576)
    for key in('placementPin','qualificationPin'):fullpin(custody[key],0o400,1048576)
    disks=custody['preparedDiskPins'];require(type(disks)is dict and set(disks)=={'original','working'},'complete prepared disk graph')
    for key,ref in disks.items():
        immutable=key=='working'and parent['candidate'].get('installer',{}).get('kind')=='AUTHENTICATED_RETAINED_F9AA_READONLY_USB'
        if immutable:require(ref==parent['candidate']['working']and ref['bytes']==8120172544 and ref['sha256']=='f9aa0fa2dd618febf28a5e2a583d1e2b5a8ca3f1205be965da584602ac962f40','same current immutable media pin')
        fullpin(ref,immutable_media=immutable)
    stage=custody['stage'];encoded=custody['stageRawBase64'];require(type(encoded)is str and len(encoded)<=1398104,'bounded lossless stage raw carrier');stage_raw=__import__('base64').b64decode(encoded,validate=True);require(__import__('base64').b64encode(stage_raw).decode('ascii')==encoded and len(stage_raw)==custody['preparedAccessPin']['bytes']<=1048576 and hashlib.sha256(stage_raw).hexdigest()==custody['preparedAccessPin']['sha256']and json.loads(stage_raw)==stage,'entire held stage raw length/SHA/JSON relation');stagekeys={'kind','nonce','bootID','candidate','grantPin','rows','after','original','workingBefore','pendingFullContentProof','runtimeAuthorized'}
    if 'operationContext'in parent['candidate']:stagekeys.add('ioAncestor')
    require(type(stage)is dict and set(stage)==stagekeys and stage['kind']=='LIBVIRT_R7_ACCESS_STAGE_PENDING_FULL_HASH'and stage['nonce']==request['leaseNonce']and stage['bootID']==proof['bootID']and stage['candidate']==parent['candidate']and stage['runtimeAuthorized']is False and stage['pendingFullContentProof']is True,'complete unchanged prepared stage provenance')
    fullpin(stage['grantPin'],0o400,1048576)
    if 'operationContext'in parent['candidate']:validate_current_io_ancestor(parent['candidate'],stage['ioAncestor'])
    candidate=stage['candidate'];require(candidate['nonce']==request['leaseNonce']and candidate['hostBoot']==proof['bootID']and candidate['guestUUID']==request['domainUUID']and candidate['name']==request['domainName']and type(candidate.get('installer'))is dict and candidate['installer']['kind']in('AUTHENTICATED_F9AA_RAW_RECOVERY_USB_FIRSTBOOT','AUTHENTICATED_RETAINED_F9AA_READONLY_USB')and candidate['installer']['noInstallTarget']is True,'same logical prepared guest/firstboot scope, not execution relabel')
    require(stage['original']==disks['original']==candidate['original']and stage['workingBefore']==candidate['working']and all(disks['working'][k]==candidate['working'][k]for k in('path','bytes','sha256')),'prepared original and readonly media exact bytes')
    require(all(disks['working']['identity'][k]==candidate['working']['identity'][k]for k in('st_dev','st_ino','st_uid','st_gid','st_nlink','st_size','st_mtime_ns')),'only declared ACL epoch between candidate/prepared media')
    require(type(stage['rows'])is list and type(stage['after'])is list and len(stage['rows'])==len(stage['after'])==6 and [r['role']for r in stage['rows']]==roles6,'closed ordered six-role provenance')
    paths={'working-parent':str(Path(candidate['working']['path']).parent),'working':candidate['working']['path'],'runtime-parent':candidate['run'],'vars':candidate['run']+'/OVMF_VARS_4M.fd','output-parent':candidate['output'],'serial':candidate['output']+'/serial.raw'}
    for row,after in zip(stage['rows'],stage['after']):
        if __import__('retained_media').validate_stage_row(candidate,row,after,fullpin):continue
        role=row['role'];require(set(row)=={'path','role','before','priorACL','targetACL','uid','rights'}and row['path']==paths[role]==after['path']and row['uid']==64055,'exact six original paths/UID')
        directory=role.endswith('parent');mode=0o700 if directory else 0o600;rights='--x'if role=='working-parent'else('r--'if role=='working'else('rwx'if directory else'rw-'));base='rwx'if directory else'rw-';prior='user::'+base+'\ngroup::---\nother::---\n';target='user::'+base+'\nuser:64055:'+rights+'\ngroup::---\nmask::'+rights+'\nother::---\n'
        require(row['rights']==rights and row['priorACL']==prior and row['targetACL']==target==after['ACL'],'exact original/target numeric ACL text and rights');meta(row['before']['identity'],stat.S_IFDIR if directory else stat.S_IFREG);meta(after['identity'],stat.S_IFDIR if directory else stat.S_IFREG)
        require(row['before']['identity']['st_uid']==row['before']['identity']['st_gid']==after['identity']['st_uid']==after['identity']['st_gid']==0 and stat.S_IMODE(row['before']['identity']['st_mode'])==mode and all(row['before']['identity'][k]==after['identity'][k]for k in(('st_dev','st_ino','st_uid','st_gid','st_nlink','st_size')if role=='runtime-parent'and request['observer']['sha256']in(R109_PEER_SHA,R109_ORIGINAL_PEER_SHA)and custody['preparedAccessPin']['sha256']=='3cf88dbf121c49bb10e9977bb2554e6c62cc7e3cbb153480d9713ef419e9190d'and custody['preparedAccessPin']['path']=='/run/opemos-root-source239-cd9ef0826364409da287f6f3e3830c95-96af5ac9637c40309055725bb9df0c17/034-access-reentry-pending.json'else('st_dev','st_ino','st_uid','st_gid','st_nlink','st_size','st_mtime_ns'))),'same six prepared objects/content epochs')
        require(row['before']['path']==row['path']and set(row['before'])==({'path','identity'}if directory else{'path','bytes','sha256','identity'}),'complete original role metadata')
        require(set(after)==({'path','identity','ACL'}if directory or role=='working' else{'path','identity','ACL','bytes','sha256'}),'complete prepared role metadata')
        if not directory:fullpin(row['before'],0o600)
        if role in('vars','serial'):require(after['bytes']==row['before']['bytes']and after['sha256']==row['before']['sha256']and after['bytes']==after['identity']['st_size'],'ACL-only prepared small-file bytes')
        if role=='working':require(row['before']==candidate['working']and after['identity']==disks['working']['identity']and all(disks['working'][k]==row['before'][k]for k in('path','bytes','sha256')),'exact candidate/postACL working lineage')
    data=custody['data'];require(type(data)is dict and data['phase']==proof['phase'],'native custody phase equality');phase=proof['phase'];pins=data['phasePins']
    if phase=='NOT_PREPARED':require(pins is None,'no invented pre-intent phase/lease heads')
    else:
        pinfields={'intentPin','phaseHeadPin','phaseRecordPin','phaseHead','phaseRecord','leaseHeadPin','leaseStatePin','leaseHead','leaseState'};require(type(pins)is dict and set(pins)==pinfields and pins['intentPin']==proof['intentPin']and pins['leaseHeadPin']==proof['lease']['headPin']and pins['leaseStatePin']==proof['lease']['statePin'],'complete exact intent/phase/lease custody pins')
        root='/run/opemos-libvirt-queue-'+request['jobToken'];lease='/run/opemos-vfio-'+request['leaseNonce']
        for key in('intentPin','phaseHeadPin','phaseRecordPin','leaseHeadPin','leaseStatePin'):fullpin(pins[key],0o400,1048576)
        require(pins['phaseHeadPin']['path']==root+'/phase-head.json'and re.fullmatch(re.escape(root)+r'/phase-(?:0[0-9]|1[0-5])[.]json',pins['phaseRecordPin']['path'])and pins['leaseHeadPin']['path']==lease+'/head.json'and re.fullmatch(re.escape(lease)+r'/state-(?:[0-9]|[1-5][0-9]|6[0-3])[.]json',pins['leaseStatePin']['path']),'confined exact phase and lease head names')
        head=pins['phaseHead'];record=pins['phaseRecord'];state=pins['leaseState'];require(set(head)=={'record','sha256'}and head['record']==Path(pins['phaseRecordPin']['path']).name and head['sha256']==pins['phaseRecordPin']['sha256']and set(record)=={'phase','requestSHA256','bootID','scope','leader','details'}and record['phase']==phase and record['requestSHA256']==custody['requestSHA256']and record['bootID']==proof['bootID']and record['scope']==proof['scope']and record['leader']==proof['leader'],'full actual phase/head/request relation')
        for key,obj in [('phaseHeadPin',head),('phaseRecordPin',record),('leaseHeadPin',pins['leaseHead']),('leaseStatePin',state)]:
            raw=canonical(obj).encode();require(pins[key]['bytes']==len(raw)and pins[key]['sha256']==hashlib.sha256(raw).hexdigest(),'full protected record canonical length/SHA binding')
        statekeys={'nonce','jobID','currentBoot','requestSHA256','backend','closed','restored','changed','historicalQMPClosed','revision','event','atUnix'}
        require(statekeys<=set(state)<=statekeys|{'domain','currentDisposition'}and type(state['revision'])is int and 0<=state['revision']<64 and Path(pins['leaseStatePin']['path']).name=='state-'+str(state['revision'])+'.json'and state['event']in('PREPARED','ACTIVE','KNOWN_DOMAIN_CLOSURE','FAILED_KNOWN_CURRENT_DISPOSITION')and type(state['atUnix'])in(int,float)and __import__('math').isfinite(state['atUnix']),'closed bounded producer native state schema')
        require(pins['leaseHead']==pins['leaseStatePin']and state['nonce']==request['leaseNonce']and state['jobID']==request['jobId']and state['currentBoot']==proof['bootID']and state['requestSHA256']==custody['requestSHA256']and state['backend']=='libvirt'and state['closed']==proof['lease']['closed']and state['restored']==proof['lease']['restored']and state['historicalQMPClosed']is None,'current exact canonical lease state/head, historical unknown retained')
        if phase=='ACTIVE':require(state['closed']is False and state['restored']is False and set(state['changed'])=={'0000:01:00.'+str(i)for i in range(4)}and state['domain']==record['details']and state['domain']['uuid']==request['domainUUID']and state['domain']['name']==request['domainName']and state['domain']['scope']==proof['scope']and state['domain']['leader']==proof['leader'],'active exact four-function original domain state')
        if phase=='CLOSED':require(state['closed']is True and state['restored']is True and state['changed']==[]and state['domain']is None and state['currentDisposition']==record['details']==data['nativeDisposition'],'closed exact phase/native state disposition')
    row_projection=[]
    if phase in('NOT_PREPARED','PREPARED'):
        require(set(data)=={'phase','stage','mutable','phasePins'}and data['stage']==stage and data['mutable']==[],'strict unchanged prelaunch custody, no mutable shortcut')
    else:
        require(set(data)=={'phase','stagePin','rows','nativeDisposition','phasePins'}and data['stagePin']==custody['preparedAccessPin']and type(data['rows'])is list and len(data['rows'])==6 and [r['role']for r in data['rows']]==roles6,'complete current six-role phase custody')
        for current,row,after in zip(data['rows'],stage['rows'],stage['after']):
            role=row['role'];firmware=phase=='ACTIVE'and role=='vars';require(set(current)==({'role','identity','ACL','journalPin','children','socket','restorePin','content'}|({'restoreRawBase64'}if request['observer']['sha256']in(R109_PEER_SHA,R109_ORIGINAL_PEER_SHA)or candidate['installer']['kind']=='AUTHENTICATED_RETAINED_F9AA_READONLY_USB'else set())|({'activeFirmwareOwner'}if firmware else set())),'closed current phase row schema');now=current['identity'];meta(now,stat.S_IFDIR if role.endswith('parent')else stat.S_IFREG);require(all(now[k]==after['identity'][k]for k in(('st_dev','st_ino','st_nlink')if firmware else('st_dev','st_ino','st_uid','st_gid','st_nlink'))),'same current owned six-role object');fullpin(current['journalPin'],0o400,1048576);require(current['journalPin']['path']=='/run/opemos-libvirt-queue-'+request['jobToken']+'/acl-before-'+role+'.json','exact protected original role journal');require(current['journalPin']['bytes']==len(canonical(row).encode())and current['journalPin']['sha256']==hashlib.sha256(canonical(row).encode()).hexdigest(),'entire original role journal content relation')
            expected=sorted((['OVMF_VARS_4M.fd','vnc.sock']if phase=='ACTIVE'or current['socket']is not None else['OVMF_VARS_4M.fd'])if role=='runtime-parent'else['serial.raw'])if role in('runtime-parent','output-parent')else None;require(current['children']==expected,'only declared runtime/output children')
            if firmware:
                owner=current['activeFirmwareOwner'];require(type(owner)is dict and set(owner)=={'leader','gids'}and owner['leader']==proof['leader']and owner['leader']['uid']==64055 and type(owner['gids'])is list and len(owner['gids'])==4 and all(type(g)is int and g>=0 for g in owner['gids'])and len(set(owner['gids']))==1 and (now['st_uid'],now['st_gid'])in((0,0),(64055,owner['gids'][0])),'same registered QEMU firmware owner/GID, no other non-Root role')
            if phase=='ACTIVE':
                require(current['ACL']==row['targetACL']and now['st_mode']==after['identity']['st_mode']and current['restorePin']is None and current['content']is None and current.get('restoreRawBase64')is None,'exact live ACL/mode, no invented restoration')
                if role in('working','working-parent'):require(now==after['identity'],'immutable readonly working/parent full9')
                if role=='vars':require(now['st_size']==after['bytes']<=1048576,'bounded same-size mutable vars')
                if role=='serial':require(after['identity']['st_size']<=now['st_size']<=4194304,'bounded owned append serial')
            else:
                require(current['ACL']==row['priorACL']and now['st_mode']==row['before']['identity']['st_mode'],'exact restored original ACL/mode');fullpin(current['restorePin'],0o400,1048576);require(current['restorePin']['path']=='/run/opemos-libvirt-queue-'+request['jobToken']+'/acl-restored-'+role+'.json','exact protected restore role receipt')
                if role.endswith('parent'):require(current['content']is None,'directory has no invented content hash')
                else:require(type(current['content'])is dict and set(current['content'])=={'bytes','sha256'}and current['content']['bytes']==now['st_size']and re.fullmatch('[0-9a-f]{64}',current['content']['sha256'])is not None,'complete actual restored leaf content pin')
                if request['observer']['sha256']in(R109_PEER_SHA,R109_ORIGINAL_PEER_SHA)or candidate['installer']['kind']=='AUTHENTICATED_RETAINED_F9AA_READONLY_USB':
                    validate_closed_restore_epoch(current,row,now,role,disks,fullpin)
                else:
                    restored={'path':row['path'],'identity':now,'ACL':current['ACL'],'restored':True,'contentMayHaveGuestWrites':role=='working'}
                    if current['content']is not None:restored.update(current['content'])
                    require(current['restorePin']['bytes']==len(canonical(restored).encode())and current['restorePin']['sha256']==hashlib.sha256(canonical(restored).encode()).hexdigest(),'whole actual restore receipt content relation')
                if role=='working':require(current['content']=={k:disks['working'][k]for k in('bytes','sha256')}and all(now[k]==disks['working']['identity'][k]for k in('st_dev','st_ino','st_uid','st_gid','st_nlink','st_size','st_mtime_ns')),'readonly working content unchanged after closure')
            socket=current['socket']
            require(not(phase=='ACTIVE'and role=='runtime-parent')or socket is not None,'active domain has exact VNC socket proof')
            if role=='runtime-parent'and socket is not None:
                require(type(socket)is dict and set(socket)==({'path','identity'}|({'kernelSocketAbsent','networkNamespace'}if phase=='CLOSED'else set()))and socket['path']==candidate['run']+'/vnc.sock'and set(socket['identity'])==fields9 and stat.S_ISSOCK(socket['identity']['st_mode'])and socket['identity']['st_uid']==64055 and socket['identity']['st_nlink']==1,'exact domain-owned VNC socket custody')
                if phase=='CLOSED':require(socket['kernelSocketAbsent']is True and re.fullmatch(r'net:\[[0-9]+\]',socket['networkNamespace'])is not None,'closed VNC node has actual no-kernel-socket proof')
            else:require(socket is None,'no foreign or inactive socket')
            # Full input is validated above. Only declared live mutable size/time
            # observations are omitted from equality; all object/ACL/source/head identities remain.
            stable_identity={k:now[k]for k in core}if phase=='ACTIVE'and role in('runtime-parent','output-parent','vars','serial')else now
            stable_socket=None if socket is None else dict(socket,identity={k:socket['identity'][k]for k in core})
            row_projection.append(dict(current,identity=stable_identity,socket=stable_socket))
        if phase=='ACTIVE':require(data['nativeDisposition']is None,'active has no fabricated closed disposition')
        else:
            native=data['nativeDisposition'];closed=native
            if 'currentClosure'in native:
                require(set(native)=={'first','secondary','currentClosure','historicalQMPClosed','noHistoricalCloseFabrication'}and type(native['first'])is dict and type(native['secondary'])is list and native['historicalQMPClosed']is None and native['noHistoricalCloseFabrication']is True,'exact failed closure wrapper and retained primary/unknown');final=native['currentClosure'];require(final['known']is True and final['FDsClosed']is True and final['leaseHeld']is False,'no unknown failure closure');closed=final['closure'];require(closed['ACLRestored']is True and closed['originalFullHashVerified']is True and closed['historicalQMPClosed']is None,'complete failure original/ACL closure')
            require(all(closed.get(k)is True for k in('domainAbsent','originalPIDStartAbsent','cgroupEmpty','VFIOFDsAbsent','hostRestored'))and closed['unknown']==[]and closed['qemuExitStatus']is None and closed['controllerWaitpidClaimed']is False,'complete independent current closed native proof')
    return {k:custody[k]for k in('kind','phase','nonce','bootID','requestSHA256','parentPin','preparedAccessPin','preparedDiskPins','sourceGraphSHA256','placementPin','qualificationPin')}|{'stageCanonicalSHA256':hashlib.sha256(canonical(stage).encode()).hexdigest(),'phasePins':pins,'rows':row_projection}


SOURCE201_PEER_SHA = '596c6206e8315887eae765b88ebf3cdf93ca56ae74766443af08fcd55817ea86'
SOURCE201_PEER_BYTES = 64581
SOURCE201_ACCESS_SHA = '5dca2ee92ca5c38114bf5c53ca40646031ef6bc430333a06707db9fd9fd6a863'
SOURCE201_ACCESS_BYTES = 34043
SOURCE201_ADAPTER_CONTRACT='D201_ROOT_PARENT_RUNTIME_PUBLICATION_SOURCE12_READONLY'
SOURCE201_ROOT_ADAPTER='"""Exact D23 readonly standalone peer/access adapter proposal, never installed.\nNo deployment, writes, SQL, runtime grant, domain control or sysfs methods.\nQueue owner must independently adopt exact bytes and consumer contract.\n"""\nimport contextlib,copy,hashlib,json,os,re,stat,sys,time,traceback,types\nfrom pathlib import Path\nF=(\'st_dev\',\'st_ino\',\'st_mode\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\');CORE=F[:6]\nNONCE=\'cd9ef0826364409da287f6f3e3830c95\';CONTRACT=\'D201_ROOT_PARENT_RUNTIME_PUBLICATION_SOURCE12_READONLY\'\nPEER_SHA=\'596c6206e8315887eae765b88ebf3cdf93ca56ae74766443af08fcd55817ea86\';PEER_BYTES=64581\nACCESS_SHA=\'5dca2ee92ca5c38114bf5c53ca40646031ef6bc430333a06707db9fd9fd6a863\';ACCESS_BYTES=34043\nROLES={\'libvirt_peer\',\'libvirt_access\',\'libvirt_native\',\'libvirt_preflight\',\'libvirt_producer\',\'queue_assignment\',\'runtime_entry\',\'guest_delta\',\'guest_firmware_probe\',\'held_history_reader\',\'two_boot_contract\',\'postqueue_issuer\'}\ndef canonical(v):return json.dumps(v,sort_keys=True,separators=(\',\',\':\'),allow_nan=False)\ndef need(v,m):\n if not v:raise RuntimeError(m)\ndef ident(s):return{k:getattr(s,k)for k in F}\ndef decode(raw):\n def unique(pairs):\n  value={}\n  for key,item in pairs:need(key not in value,\'duplicate protected JSON key\');value[key]=item\n  return value\n value=json.loads(raw,object_pairs_hook=unique);need(canonical(value).encode()==raw,\'whole canonical protected metadata, no dropped/trailing fields\');return value\ndef record_run_epoch(proof,event):\n raw=(lambda x:canonical(x).encode())(event);last=proof[\'events\'][-1]if proof[\'events\']else None\n if last is not None and last[\'event\']==event:last[\'count\']+=1\n else:proof[\'events\'].append({\'event\':event,\'count\':1})\n proof[\'eventCount\']+=1;proof[\'eventChainSHA256\']=hashlib.sha256(bytes.fromhex(proof[\'eventChainSHA256\'])+raw).hexdigest();need(0<proof[\'eventCount\']<=4096 and len(proof[\'events\'])<=256 and len((lambda x:canonical(x).encode())(proof))<=262144,\'bounded lossless borrowed run epoch runs\')\nclass RootInputs:\n """One readonly bounded held-nofollow /run graph; owns and closes all FDs."""\n def __init__(self):self.fds=[];self.dirs={}\n def __enter__(self):\n  self.root=os.open(\'/\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.fds.append(self.root)\n  try:\n   self.run=os.open(\'run\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.root);self.fds.append(self.run)\n   self.dirs={\'/\':(self.root,ident(os.fstat(self.root)),False),\'/run\':(self.run,ident(os.fstat(self.run)),False)};self.runBirth=self.run_row(self.run);rows=[x for x in Path(\'/proc/self/mountinfo\').read_text().splitlines()if x.split()[0]==str(self.runBirth[\'mountID\'])];need(len(rows)==1,\'exact initial run mount\');self.runProof={\'kind\':\'ROOT_BORROWED_RUN_ANCESTRY_R257\',\'path\':\'/run\',\'birth\':self.runBirth,\'namespace\':os.readlink(\'/proc/self/ns/mnt\'),\'mountRow\':rows[0],\'events\':[],\'eventCount\':0,\'eventChainSHA256\':\'0\'*64,\'scopeDescriptorsClosed\':False,\'closeOutcomes\':[]};self.check();return self\n  except BaseException:\n   self.__exit__(*sys.exc_info());raise\n def run_row(self,fd):\n  raw=Path(\'/proc/self/fdinfo/\'+str(fd)).read_text();v={}\n  for line in raw.splitlines():\n   if line.startswith((\'flags:\',\'mnt_id:\')):k,x=line.split(\':\',1);v[k]=x.strip()\n  need(set(v)=={\'flags\',\'mnt_id\'}and v[\'mnt_id\'].isdigit()and re.fullmatch(\'[0-7]+\',v[\'flags\'])is not None,\'complete actual run descriptor flags/mount\')\n  f=__import__(\'fcntl\');return {\'fd\':fd,\'identity\':ident(os.fstat(fd)),\'target\':os.readlink(\'/proc/self/fd/\'+str(fd)),\'flags\':f.fcntl(fd,f.F_GETFL),\'descriptorFlags\':f.fcntl(fd,f.F_GETFD),\'fdinfoFlags\':v[\'flags\'],\'mountID\':int(v[\'mnt_id\'])}\n def borrowed_run(self):\n  initial=self.runBirth;owned=[];primary=None;event={};startns=os.readlink(\'/proc/self/ns/mnt\')\n  try:\n   event[\'heldBefore\']=self.run_row(self.run)\n   for label,path,anchored in((\'anchored\',\'run\',True),(\'named\',\'/run\',False)):\n    fd=os.open(path,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,**({\'dir_fd\':self.root}if anchored else{}));owned.append(fd);event[label]=self.run_row(fd)\n   event[\'anchoredPath\']=ident(os.stat(\'run\',dir_fd=self.root,follow_symlinks=False));event[\'namedPath\']=ident(os.lstat(\'/run\'));event[\'heldAfter\']=self.run_row(self.run);event[\'anchoredAfter\']=self.run_row(owned[0]);event[\'namedAfter\']=self.run_row(owned[1]);event[\'namespaceBefore\']=startns;event[\'namespaceAfter\']=os.readlink(\'/proc/self/ns/mnt\')\n   rows=[x for x in Path(\'/proc/self/mountinfo\').read_text().splitlines()if x.split()[0]==str(initial[\'mountID\'])];need(len(rows)==1,\'unique current kernel run mount row\');event[\'mountRow\']=rows[0]\n   stable=F[:5];snapshots=[event[k][\'identity\']for k in(\'heldBefore\',\'anchored\',\'named\',\'heldAfter\',\'anchoredAfter\',\'namedAfter\')]+[event[\'anchoredPath\'],event[\'namedPath\']]\n   need(all(all(x[k]==initial[\'identity\'][k]for k in stable)for x in snapshots)and all(event[k][\'target\']==\'/run\'and event[k][\'mountID\']==initial[\'mountID\']and event[k][\'descriptorFlags\']==1 for k in(\'heldBefore\',\'anchored\',\'named\',\'heldAfter\',\'anchoredAfter\',\'namedAfter\')),\'same held/anchored/named run inode/type/mode/owner/mount\')\n   need(event[\'heldBefore\']==dict(initial,identity=event[\'heldBefore\'][\'identity\'])and event[\'heldAfter\']==dict(initial,identity=event[\'heldAfter\'][\'identity\'])and startns==event[\'namespaceAfter\']==self.runProof[\'namespace\'],\'same borrowed run FD/flags/name/namespace\')\n   for name in(\'anchored\',\'named\'):\n    a=event[name];b=event[name+\'After\'];need(a==dict(b,identity=a[\'identity\'])and a[\'flags\']==os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,\'exact temporary nofollow O_PATH run descriptors\')\n   row=rows[0].split();i=initial[\'identity\'];need(stat.S_ISDIR(i[\'st_mode\'])and stat.S_IMODE(i[\'st_mode\'])==0o755 and i[\'st_uid\']==i[\'st_gid\']==0 and initial[\'flags\']&os.O_ACCMODE==os.O_RDONLY and not initial[\'flags\']&os.O_PATH and initial[\'flags\']&os.O_DIRECTORY and initial[\'flags\']&os.O_NOFOLLOW and re.fullmatch(r\'mnt:\\[[0-9]+\\]\',startns)is not None,\'declared borrowed Root0755 readonly run directory\');need(row[3:5]==[\'/\',\'/run\']and row[2]==str(os.major(i[\'st_dev\']))+\':\'+str(os.minor(i[\'st_dev\']))and event[\'mountRow\']==self.runProof[\'mountRow\'],\'same kernel mount root/device/path and original run mount\')\n  except BaseException as error:primary=error;error.evidence={\'kind\':\'BORROWED_RUN_CUSTODY_REFUSAL_R257\',\'birth\':initial,\'event\':event};raise\n  finally:\n   errors=[]\n   for fd in owned[::-1]:\n    try:os.close(fd)\n    except BaseException as e:errors.append({\'fd\':fd,\'type\':type(e).__name__,\'reason\':str(e)})\n   if errors:\n    if primary is not None:primary.ownedRootInputClosureErrors=errors\n    else:raise RuntimeError(canonical({\'ownedRootInputClosureErrors\':errors}))\n  event[\'temporaryDescriptorsClosed\']=True;record_run_epoch(self.runProof,event);return event\n def check(self):\n  for path,(fd,a,exclusive)in self.dirs.items():\n   if path==\'/run\':self.borrowed_run();continue\n   x=ident(os.fstat(fd));named=ident(os.lstat(path))\n   if not(x==named and all(x[k]==a[k]for k in(CORE if not exclusive else F))):\n    error=RuntimeError(\'held/named declared directory identity/epoch\');error.evidence={\'path\':path,\'role\':\'exclusive\'if exclusive else\'shared-ancestor\',\'birth\':a,\'held\':x,\'named\':named,\'monotonic\':time.monotonic()};raise error\n   need(stat.S_ISDIR(x[\'st_mode\'])and x[\'st_uid\']==x[\'st_gid\']==0,\'Root directory nofollow custody\')\n   need(stat.S_IMODE(x[\'st_mode\'])in((0o755,0o777)if path==\'/\'else(0o755,)if path==\'/run\'else(0o755,)if path.startswith(\'/run/opemos-steamos-source-\')else(0o700,)),\'exact role-specific directory mode\')\n def directory(self,path):\n  allowed={\'/run/opemos-steamos-source-\'+NONCE,\'/run/opemos-libvirt-runtime-\'+NONCE,\'/run/opemos-steamos-placement-\'+NONCE}\n  need(path in allowed,\'declared finite source/context/placement root only\')\n  if path not in self.dirs:\n   fd=os.open(Path(path).name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.run);self.fds.append(fd);self.dirs[path]=(fd,ident(os.fstat(fd)),True)\n  self.check();return self.dirs[path][0]\n def read_path(self,path,mode,cap):\n  path=Path(path);need(path.is_absolute()and path.name not in(\'\',\'.\',\'..\'),\'absolute confined declared leaf\')\n  if str(path.parent)==\'/run\':need(str(path)==\'/run/opemos-libvirt-parent-\'+NONCE+\'.json\',\'one normal public parent only\');parent=self.run\n  else:parent=self.directory(str(path.parent))\n  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)\n  try:\n   s=os.fstat(fd);a=ident(s);need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode and s.st_nlink==1 and s.st_size<=cap,\'exact Root leaf mode/owner/link/size\');raw=b\'\'\n   while chunk:=os.read(fd,65536):raw+=chunk;need(len(raw)<=cap,\'bounded full leaf stream\')\n   need(a==ident(os.fstat(fd))==ident(os.stat(path.name,dir_fd=parent,follow_symlinks=False))==ident(os.lstat(path))and len(raw)==a[\'st_size\'],\'full held/anchored/named identity and EOF\');self.check();return raw,{\'path\':str(path),\'bytes\':len(raw),\'sha256\':hashlib.sha256(raw).hexdigest(),\'identity\':a}\n  finally:os.close(fd)\n def read(self,ref,mode,cap):\n  raw,actual=self.read_path(ref[\'path\'],mode,cap)\n  if actual!=ref:\n   error=RuntimeError(\'exact declared full9/length/SHA pin\');error.evidence={\'path\':ref[\'path\'],\'expected\':ref,\'actual\':actual};raise error\n  return raw\n def placement_bytes(self,fd,parentfd,ref):\n  """Inner FD/hash check; hold_placement applies exact Root role custody.\n  It does not change Root policy or convert a user fixture into Root proof.\n  """\n  value={\'path\':ref[\'path\'],\'expected\':ref,\'heldBefore\':None,\'heldAfter\':None,\'named\':None,\'heldSHA256\':None,\'namedSHA256\':None,\'heldBytes\':None,\'namedBytes\':None}\n  def bytesof(f):\n   chunks=[];offset=0\n   while True:\n    b=os.pread(f,65536,offset)\n    if not b:break\n    offset+=len(b);need(offset<=1048576,\'unchanged placement metadata1MiB streaming cap\');chunks.append(b)\n   return b\'\'.join(chunks)\n  try:\n   value[\'heldBefore\']=ident(os.fstat(fd));need((__import__(\'fcntl\').fcntl(fd,__import__(\'fcntl\').F_GETFL)&os.O_ACCMODE)==os.O_RDONLY,\'owned placement held FD remains O_RDONLY\');held=bytesof(fd);value.update(heldBytes=len(held),heldSHA256=hashlib.sha256(held).hexdigest())\n   nf=os.open(Path(ref[\'path\']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)\n   try:\n    value[\'named\']=ident(os.fstat(nf));named=bytesof(nf);value.update(namedBytes=len(named),namedSHA256=hashlib.sha256(named).hexdigest());need(value[\'named\']==ident(os.fstat(nf))==ident(os.stat(Path(ref[\'path\']).name,dir_fd=parentfd,follow_symlinks=False))==ident(os.lstat(ref[\'path\'])),\'placement fresh nofollow named FD/path full9\')\n   finally:\n    primary=sys.exc_info()[1]\n    try:os.close(nf)\n    except BaseException as close:\n     if primary is None:raise\n     primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'fd\':nf,\'type\':type(close).__name__,\'reason\':str(close)}]\n   value[\'heldAfter\']=ident(os.fstat(fd));need(value[\'heldBefore\']==value[\'heldAfter\']==value[\'named\']==ref[\'identity\']and len(held)==len(named)==ref[\'bytes\']and value[\'heldSHA256\']==value[\'namedSHA256\']==ref[\'sha256\']and held==named,\'placement held/named full9/raw bytes/length/SHA equal originally bound operand\')\n   return held\n  except BaseException as error:error.placementCustody=value;raise\n @contextlib.contextmanager\n def hold_placement(self,ref):\n  root=\'/run/opemos-steamos-placement-\'+NONCE;need(ref[\'path\']in(root+\'/storage-contract.json\',root+\'/placement-qualified.json\'),\'two exact placement metadata leaves only\');i=ref[\'identity\'];need(set(ref)=={\'path\',\'bytes\',\'sha256\',\'identity\'}and 0<ref[\'bytes\']<=1048576 and stat.S_ISREG(i[\'st_mode\'])and stat.S_IMODE(i[\'st_mode\'])==0o400 and i[\'st_uid\']==i[\'st_gid\']==0 and i[\'st_nlink\']==1 and i[\'st_size\']==ref[\'bytes\'],\'exact Root0400 placement full pin/custody\')\n  parentfd=self.directory(root);fd=os.open(Path(ref[\'path\']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)\n  try:\n   original=self.placement_bytes(fd,parentfd,ref);self.check()\n   def recheck():\n    self.check();raw=self.placement_bytes(fd,parentfd,ref);need(raw==original,\'complete held placement raw bytes identical after observer\');self.check();return ref\n   yield {\'ref\':ref,\'raw\':original,\'recheck\':recheck}\n  finally:\n   primary=sys.exc_info()[1]\n   try:os.close(fd)\n   except BaseException as close:\n    if primary is None:raise\n    primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'fd\':fd,\'type\':type(close).__name__,\'reason\':str(close)}]\n def __exit__(self,*a):\n  errors=[]\n  for fd in self.fds[::-1]:\n   try:\n    os.close(fd)\n    if hasattr(self,\'runProof\'):self.runProof[\'closeOutcomes\'].append({\'fd\':fd,\'closed\':True})\n   except OSError as e:errors.append({\'fd\':fd,\'type\':type(e).__name__,\'reason\':str(e)})\n  self.fds=[]\n  if hasattr(self,\'runProof\'):self.runProof[\'scopeDescriptorsClosed\']=not errors\n  if errors:\n   if a[1]is not None:a[1].ownedRootInputClosureErrors=errors\n   else:raise RuntimeError(canonical({\'ownedRootInputClosureErrors\':errors}))\n\ndef parent_spec(parent,parent_ref):\n s=copy.deepcopy(parent[\'normalizedSpecTemplate\']);need(s[\'approval\']==\'EXACT_PARENT_MINIMAL_PIN\'and s[\'command\'][-1]==\'EXACT_PARENT_FULL_PIN_JSON\',\'two existing late parent-pin slots only\');s[\'approval\']={k:parent_ref[k]for k in(\'path\',\'bytes\',\'sha256\')};s[\'command\'][-1]=canonical(parent_ref)\n need(s[\'command\']==[\'sudo\',\'-n\',\'/usr/bin/python3\',\'-B\',parent[\'sourceRoles\'][\'runtime_entry\'][\'path\'],\'--parent-pin-json\',canonical(parent_ref)]and s[\'id\']==parent[\'jobId\']and s[\'cores\']==4 and s[\'memory\']==10737418240 and s[\'timeout_seconds\']==900 and \'omen-iommu-group-1\'in s[\'resources\'],\'exact ordinary entry and10GiB/4CPU/900s spec\')\n return s\n\ndef verify_inputs(request,io,boot,include_context=True):\n need(request[\'leaseNonce\']==NONCE and request[\'domainName\']==\'opemos-libvirt-\'+NONCE,\'fresh exact D23 scope only\')\n cr=\'/run/opemos-libvirt-runtime-\'+NONCE+\'/context.json\';parentRaw,parentRef=io.read_path(\'/run/opemos-libvirt-parent-\'+NONCE+\'.json\',0o444,1048576);parent=decode(parentRaw)\n contextRaw=contextRef=context=None\n if include_context:\n  try:contextRaw,contextRef=io.read_path(cr,0o400,1048576);context=decode(contextRaw)\n  except FileNotFoundError:pass\n need(parent[\'kind\']==\'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT\'and parent[\'RootIssued\']is True and parent[\'runtimeAuthorized\']is True and parent.get(\'MODEL_ONLY\')is False and parent[\'bootID\']==boot and parent[\'nonce\']==NONCE and parent[\'contextPath\']==cr,\'existing actual same-boot Root parent; no issuance or clock refresh\')\n if context is not None:need(context[\'parentPin\']==parentRef and context[\'kind\']==\'ROOT_LIBVIRT_R4_RUNTIME_CONTEXT\'and context[\'runtimeAuthorized\']is True and context.get(\'MODEL_ONLY\')is False and context[\'candidate\']==parent[\'candidate\']and context[\'sourceRoles\']==parent[\'sourceRoles\'],\'Root context/candidate/source12 equality; no model promotion\')\n need(type(parent[\'candidate\'].get(\'installer\'))is dict and parent[\'candidate\'][\'installer\'].get(\'kind\')==\'AUTHENTICATED_F9AA_RAW_RECOVERY_USB_FIRSTBOOT\'and parent[\'candidate\'][\'installer\'].get(\'noInstallTarget\')is True,\'this reviewed source branch admits only the retained installer/no target\')\n need(parent[\'issuedUnix\']<parent[\'startBeforeUnix\']<=parent[\'issuedUnix\']+300 and parent[\'wholeDeadlineUnix\']<=parent[\'issuedUnix\']+900,\'original finite parent scope retained; readonly closed observation does not reissue authority\')\n roles=parent[\'sourceRoles\'];need(set(roles)==ROLES,\'complete source12 membership\')\n need(roles[\'libvirt_peer\'][\'bytes\']==64581 and roles[\'libvirt_peer\'][\'sha256\']==PEER_SHA and roles[\'libvirt_access\'][\'bytes\']==ACCESS_BYTES and roles[\'libvirt_access\'][\'sha256\']==ACCESS_SHA,\'frozen reviewed peer/access implementation\')\n need(request[\'observer\']=={k:roles[\'libvirt_peer\'][k]for k in(\'path\',\'bytes\',\'sha256\')}and request[\'jobId\']==parent[\'jobId\'],\'exact original request observer/job\')\n source={}\n for name,ref in sorted(roles.items()):\n  need(ref[\'path\']==\'/run/opemos-steamos-source-\'+NONCE+\'/\'+name+\'.py\',\'same exact source namespace\');source[name]=io.read(ref,0o444,65536);compile(source[name],ref[\'path\'],\'exec\')\n spec=parent_spec(parent,parentRef);bound=spec[\'libvirt_domain\'];need(bound=={\'leaseNonce\':NONCE,\'name\':request[\'domainName\'],\'observer\':request[\'observer\'],\'uuid\':request[\'domainUUID\']}and hashlib.sha256(canonical(spec).encode()).hexdigest()==request[\'specSHA256\'],\'complete final normalized spec/hash/domain identity\')\n assignmentRef=grantRef=None;assignment=grant=None\n if context is not None:\n  assignmentRef=context[\'assignmentPin\'];need(assignmentRef[\'path\']==\'/run/opemos-libvirt-runtime-\'+NONCE+\'/assignment.json\'and context[\'grantPin\'][\'path\']==\'/run/opemos-libvirt-runtime-\'+NONCE+\'/child-grant.json\',\'two exact same-scope child control leaves\');assignment=decode(io.read(assignmentRef,0o400,1048576));grantRef=context[\'grantPin\'];grant=decode(io.read(grantRef,0o400,1048576))\n  need(assignment[\'kind\']==\'ROOT_CANONICAL_QUEUE_LIBVIRT_ASSIGNMENT_R4\'and assignment[\'request\']==request and grant[\'assignmentPin\']==assignmentRef and grant[\'parentPin\']==parentRef and grant[\'normalizedSpecSHA256\']==request[\'specSHA256\'],\'canonical assignment and child grant exact request/spec/parent\')\n  need(grant[\'queuePrograms\']==parent[\'queuePrograms\']and grant[\'sourcePlacementPin\']==context[\'sourcePlacementPin\']==parent[\'sourcePlacementPin\']and grant[\'placementQualificationPin\']==context[\'placementQualificationPin\']==parent[\'placementQualificationPin\'],\'current queue authority and placement pins across child/context/parent\')\n  need(grant[\'RootIssued\']is True and grant[\'MODEL_ONLY\']is False and grant[\'runtimeAuthorized\']is True and grant[\'jobId\']==request[\'jobId\']and grant[\'leaseNonce\']==NONCE and grant[\'bootID\']==boot and parent[\'issuedUnix\']<=grant[\'issuedUnix\']<grant[\'startBeforeUnix\']<=parent[\'startBeforeUnix\']and grant[\'wholeDeadlineUnix\']<=parent[\'wholeDeadlineUnix\'],\'existing finite Root child only, no new runtime grant\')\n return {\'parent\':parent,\'parentPin\':parentRef,\'parentRaw\':parentRaw,\'context\':context,\'contextPin\':contextRef,\'contextRaw\':contextRaw,\'source\':source,\'assignmentPin\':assignmentRef,\'assignmentRaw\':None if assignment is None else canonical(assignment).encode(),\'grantPin\':grantRef,\'grantRaw\':None if grant is None else canonical(grant).encode()}\n\ndef _bind_placement(peer,parent,parent_ref,context,verify_access):\n """Bind only the fresh protected same-source/same-scope metadata operand.\n Never changes the frozen peer\'s nonce, strict geometry or owner predicate.\n """\n nonce=parent[\'nonce\'];roles=parent[\'sourceRoles\'];candidate=parent[\'candidate\']\n peer.need(nonce==\'cd9ef0826364409da287f6f3e3830c95\'and peer.SOURCE_PLACEMENT_NONCE==nonce and candidate[\'nonce\']==nonce and __import__(\'queue_assignment\').execution_job(candidate,parent)==parent[\'jobId\'],\'D23 unused scope only; D22 is consumed\')\n peer.need(parent[\'RootIssued\']is True and parent[\'kind\']==\'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT\'and parent[\'bootID\']==candidate[\'hostBoot\']and parent_ref[\'path\']==\'/run/opemos-libvirt-parent-\'+nonce+\'.json\',\'existing exact Root parent/boot/source scope\')\n peer.need(set(roles)=={\'libvirt_peer\',\'libvirt_access\',\'libvirt_native\',\'libvirt_preflight\',\'libvirt_producer\',\'queue_assignment\',\'runtime_entry\',\'guest_delta\',\'guest_firmware_probe\',\'held_history_reader\',\'two_boot_contract\',\'postqueue_issuer\'},\'closed twelve-role binding\')\n peer.need(roles[\'libvirt_peer\'][\'sha256\']==\'596c6206e8315887eae765b88ebf3cdf93ca56ae74766443af08fcd55817ea86\'and roles[\'libvirt_peer\'][\'bytes\']==64581 and roles[\'libvirt_access\'][\'sha256\']==\'5dca2ee92ca5c38114bf5c53ca40646031ef6bc430333a06707db9fd9fd6a863\'and roles[\'libvirt_access\'][\'bytes\']==34043,\'frozen exact D23 peer and unchanged access bytes\')\n for name,ref in roles.items():peer.need(ref[\'path\']==\'/run/opemos-steamos-source-\'+nonce+\'/\'+name+\'.py\'and ref[\'identity\'][\'st_uid\']==ref[\'identity\'][\'st_gid\']==0 and stat.S_IMODE(ref[\'identity\'][\'st_mode\'])==0o444 and ref[\'identity\'][\'st_nlink\']==1,\'same immutable Root source12 namespace\')\n ref=parent[\'sourcePlacementPin\'];qr=parent[\'placementQualificationPin\'];root=\'/run/opemos-steamos-placement-\'+nonce\n peer.need(ref[\'path\']==root+\'/storage-contract.json\'and qr[\'path\']==root+\'/placement-qualified.json\',\'fresh exact placement+qualification names, no historical receipt\')\n files=peer.RootFiles(root);primary=None;result=None\n try:\n  files.__enter__()\n  raw,actual=files.read(\'storage-contract.json\');qualified,qactual=files.read(\'placement-qualified.json\');peer.need(actual==ref and qactual==qr,\'fresh placement/qualification exact full9/EOF/SHA\')\n  value=json.loads(raw);q=json.loads(qualified);b=value[\'preparationBinding\']\n  peer.need(value[\'kind\']==(\'ROOT_EXACT_STEAMOS_INSTALLER_GAMES_PLACEMENT\'if candidate.get(\'installer\')is not None else\'ROOT_EXACT_STEAMOS_FIXED_GAMES_PLACEMENT\')and value[\'nonce\']==nonce and value[\'boot\']==parent[\'bootID\']and value[\'original\']==candidate[\'original\']and value[\'working\']==candidate[\'working\']and value.get(\'installer\')==candidate.get(\'installer\'),\'same current prepared working placement, no relabel\')\n  peer.need(b[\'sourceRoles\']==roles and b[\'queuePrograms\']==parent[\'queuePrograms\']and b[\'sourceGraphSHA256\']==hashlib.sha256(peer.canon(roles)).hexdigest(),\'placement producer source12/current queue equality\')\n  peer.need(q[\'kind\']==\'ROOT_VERIFIED_FRESH_STEAMOS_PLACEMENT\'and q[\'qualifiedPlacementPin\']==ref and q[\'nonce\']==nonce and q[\'bootID\']==parent[\'bootID\']and q[\'sourceRoles\']==roles and q[\'queuePrograms\']==parent[\'queuePrograms\']and q[\'runtimeAuthorized\']is False and q[\'RootIssuedRuntimeAuthority\']is False,\'complete fresh protected metadata qualification, not a runtime grant\')\n  pre=q[\'currentPreflight\'];prepared=parent[\'preparedDiskPins\'];access_pin=parent[\'preparedAccessPin\']\n  peer.need(type(prepared)is dict and set(prepared)=={\'original\',\'working\'}and prepared[\'original\']==candidate[\'original\']and b[\'preparedDiskPins\']==prepared and access_pin is not None and b[\'preparedAccessPin\']==access_pin==pre[\'preparedAccessPin\']and b[\'splitDiskCapturePins\']==parent[\'splitDiskCapturePins\']==pre[\'splitDiskCapturePins\'],\'exact candidate/pending-access/post-ACL prepared captures/final-preflight lineage\')\n  work=prepared[\'working\'];before_work=candidate[\'working\'];peer.need(work[\'path\']==before_work[\'path\']and work[\'bytes\']==before_work[\'bytes\']and work[\'sha256\']==before_work[\'sha256\']and all(work[\'identity\'][k]==before_work[\'identity\'][k]for k in(\'st_dev\',\'st_ino\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\')),\'same content and stable pre/post ACL working object; full9 remains exact within each epoch\')\n  verify_access(candidate,access_pin,prepared)\n  peer.need(q[\'currentPreflightPin\']==parent[\'prequeuePreflightPin\']and pre[\'bootID\']==parent[\'bootID\']and pre[\'storagePlacement\'][\'receiptPin\']==ref and pre[\'queuePrograms\']==parent[\'queuePrograms\']and pre[\'original\']==candidate[\'original\']and pre[\'kind\']==\'ACTUAL_LIBVIRT_R4_CURRENT_PREFLIGHT\'and pre[\'working\']==prepared[\'working\']and 0<=parent[\'issuedUnix\']-pre[\'observedUnix\']<=30,\'existing normal complete current preflight joins placement before parent issuance\')\n  if context is not None:peer.need(context[\'parentPin\']==parent_ref and context[\'candidate\']==candidate and context[\'sourceRoles\']==roles and context[\'sourcePlacementPin\']==ref and context[\'placementQualificationPin\']==qr,\'context/parent/source12/placement equality\')\n  peer.need(peer.SOURCE_PLACEMENT_PIN is None or peer.SOURCE_PLACEMENT_PIN==ref,\'never replace a different bound placement operand\')\n  again,again_pin=files.read(\'storage-contract.json\');again_q,again_qpin=files.read(\'placement-qualified.json\');peer.need((again,again_pin)==(raw,ref)and(again_q,again_qpin)==(qualified,qr),\'original held/named placement and qualification full9/raw-SHA unchanged after prepared verification\')\n  result={\'placementPin\':ref,\'qualificationPin\':qr,\'sourceGraphSHA256\':b[\'sourceGraphSHA256\'],\'runtimeAuthorityIssued\':False}\n except BaseException as error:primary=error\n finally:\n  try:files.__exit__(None if primary is None else type(primary),primary,None)\n  except BaseException as close:\n   if primary is None:primary=close\n   else:primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'role\':\'bind-placement-ancestors\',\'type\':type(close).__name__,\'reason\':str(close)}]\n if primary is not None:raise primary\n peer.SOURCE_PLACEMENT_PIN=ref\n return result\n\ndef bind_placement(peer,parent,parent_ref,context=None):\n from libvirt_access import verify_prepared\n return _bind_placement(peer,parent,parent_ref,context,verify_prepared)\n\ndef bind_observer_placement(peer,parent,parent_ref,context):\n from libvirt_access import prepared_lineage\n return _bind_placement(peer,parent,parent_ref,context,prepared_lineage)\n\n@contextlib.contextmanager\ndef load_pair(v):\n names=(\'libvirt_peer\',\'libvirt_access\',\'guest_firmware_probe\',\'libvirt_native\',\'queue_assignment\');missing=object();previous={k:sys.modules.get(k,missing)for k in names}\n try:\n  roles=v[\'parent\'][\'sourceRoles\'];modules={}\n  for name in names:\n   module=types.ModuleType(name);module.__file__=roles[name][\'path\'];sys.modules[name]=module;exec(compile(v[\'source\'][name],module.__file__,\'exec\'),module.__dict__);modules[name]=module\n  yield modules[\'libvirt_peer\'],modules[\'libvirt_access\']\n finally:\n  for name,old in previous.items():\n   if old is missing:sys.modules.pop(name,None)\n   else:sys.modules[name]=old\n\ndef run(request,io,boot,observe=None):\n v0=verify_inputs(request,io,boot,False)\n with load_pair(v0)as(peer,access):\n  with access.runtime_snapshot(v0[\'parent\'],v0[\'parentPin\'],request,time.monotonic()+14,io)as snapshot:\n   v=verify_inputs(request,io,boot);need(v[\'parentPin\']==v0[\'parentPin\']and v[\'source\']==v0[\'source\'],\'unchanged immutable sources across runtime SH acquisition\')\n   with contextlib.ExitStack()as custody:\n    heldPlacement=custody.enter_context(io.hold_placement(v[\'parent\'][\'sourcePlacementPin\']));heldQualification=custody.enter_context(io.hold_placement(v[\'parent\'][\'placementQualificationPin\']))\n    peer.validate_request(request);binding=bind_observer_placement(peer,v[\'parent\'],v[\'parentPin\'],v[\'context\']);need(binding[\'placementPin\']==heldPlacement[\'ref\']and binding[\'qualificationPin\']==heldQualification[\'ref\'],\'binding consumes the two retained exact placement pins\')\n    parent=v[\'parent\'];candidate=parent[\'candidate\']\n    def custody(phase,intent,reg,state,files):return access.verify_phase(candidate,parent[\'preparedAccessPin\'],parent[\'preparedDiskPins\'],phase,intent,reg,state,files)\n    proof=peer.observe(request,custody=custody)if observe is None else observe(peer,request,custody)\n    need(proof.get(\'accessCustody\',{}).get(\'phase\')==proof[\'phase\'],\'actual locked phase access custody required\')\n    proof[\'accessCustody\']={\'kind\':\'ROOT_PHASE_PREPARED_ACCESS_CUSTODY_R1\',\'phase\':proof[\'phase\'],\'nonce\':NONCE,\'bootID\':boot,\'requestSHA256\':hashlib.sha256(peer.canon(request)).hexdigest(),\'parentPin\':v[\'parentPin\'],\'preparedAccessPin\':parent[\'preparedAccessPin\'],\'preparedDiskPins\':parent[\'preparedDiskPins\'],\'sourceGraphSHA256\':binding[\'sourceGraphSHA256\'],\'placementPin\':binding[\'placementPin\'],\'qualificationPin\':binding[\'qualificationPin\'],\'stage\':access.prepared_lineage(candidate,parent[\'preparedAccessPin\'],parent[\'preparedDiskPins\']),\'stageRawBase64\':__import__(\'base64\').b64encode(__import__(\'libvirt_native\').held(parent[\'preparedAccessPin\'],1048576)).decode(\'ascii\'),\'data\':proof[\'accessCustody\']}\n    need(v[\'context\']is not None or proof[\'phase\']==\'NOT_PREPARED\',\'missing context permits only actual NOT_PREPARED, never ACTIVE/CLOSED\')\n    need(proof[\'request\']==request and proof[\'sourceSHA256\']==PEER_SHA and proof[\'phase\']in(\'NOT_PREPARED\',\'PREPARED\',\'ACTIVE\',\'CLOSED\')and proof[\'allOwnedDescriptorsClosed\']is True and proof[\'effects\']==[],\'unchanged complete readonly observer proof and closure\')\n    # Every complete source and protected control is reread after observer use.\n    for name,ref in v[\'parent\'][\'sourceRoles\'].items():need(io.read(ref,0o444,65536)==v[\'source\'][name],\'post-use exact source12 bytes\')\n    need(io.read(v[\'parentPin\'],0o444,1048576)==v[\'parentRaw\'],\'post-use exact parent bytes\')\n    if v[\'context\']is not None:\n     need(io.read(v[\'contextPin\'],0o400,1048576)==v[\'contextRaw\'],\'post-use exact context bytes\');io.read(v[\'assignmentPin\'],0o400,1048576);io.read(v[\'grantPin\'],0o400,1048576)\n    else:\n     try:io.read_path(\'/run/opemos-libvirt-runtime-\'+NONCE+\'/context.json\',0o400,1048576)\n     except FileNotFoundError:pass\n     else:raise RuntimeError(\'context absence changed during exact NOT_PREPARED observation; no retry\')\n    heldPlacement[\'recheck\']();heldQualification[\'recheck\']()\n    result={\'kind\':\'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION\',\'upstreamObserver\':v[\'parent\'][\'sourceRoles\'][\'libvirt_peer\'],\'implementation\':{\'contract\':CONTRACT,\'peer\':v[\'parent\'][\'sourceRoles\'][\'libvirt_peer\'],\'access\':v[\'parent\'][\'sourceRoles\'][\'libvirt_access\'],\'sourceRoles\':v[\'parent\'][\'sourceRoles\'],\'parent\':v[\'parentPin\'],\'context\':v[\'contextPin\'],\'assignment\':v[\'assignmentPin\'],\'grant\':v[\'grantPin\'],\'placementBinding\':binding,\'runtimePublication\':snapshot,\'borrowedRunCustody\':io.runProof},\'proof\':proof,\'effects\':[]}\n    io.check()\n need(snapshot[\'readLockClosed\']is True,\'actual runtime read lock closed\');need(len(canonical(result).encode())+1<=1048576,\'unchanged whole Root1MiB envelope\');return result\n\ndef main():\n need(os.getuid()==0 and len(sys.argv)==4 and sys.argv[1]==PEER_SHA and sys.argv[2]==\'--queue-libvirt-request-json\',\'exact existing Root standalone queue argv\')\n request=json.loads(sys.argv[3]);before=set(os.listdir(\'/proc/self/fd\'))\n with RootInputs()as io:result=run(request,io,Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip())\n need(before==set(os.listdir(\'/proc/self/fd\')),\'adapter full owned FD closure\');print(canonical(result),flush=True)\nif __name__==\'__main__\':\n try:main()\n except BaseException as e:\n  print(canonical({\'kind\':\'QUEUE_LIBVIRT_FIRST_REFUSAL\',\'type\':type(e).__name__,\'reason\':str(e),\'effects\':[],\'evidence\':getattr(e,\'evidence\',None),\'workingEvidence\':getattr(e,\'workingEvidence\',None),\'placementCustody\':getattr(e,\'placementCustody\',None),\'runtimePublication\':getattr(e,\'runtimePublication\',None),\'rootInputCloseErrors\':getattr(e,\'ownedRootInputClosureErrors\',[]),\'rootFilesCloseErrors\':getattr(e,\'rootFilesCloseErrors\',[]),\'lockCloseErrors\':getattr(e,\'lockCloseErrors\',[]),\'ownedPlacementCloseErrors\':getattr(e,\'ownedPlacementCloseErrors\',[]),\'traceback\':traceback.format_exc()}),file=sys.stderr,flush=True);sys.exit(1)\n'

class RuntimePublisherTransition(ValueError):
    pass


def validate_runtime_publication(v,request,implementation,producer):
    fields={'kind','parentPin','publisherPin','jobId','nonce','bootID','startedMonotonic','readLockClosed','directory','lock','leaves','publications','head','lockPin','requestSHA256','directoryAfter','completedMonotonic'}
    require(type(v)is dict and set(v)==fields and v['kind']=='ROOT_SHARED_RUNTIME_SNAPSHOT_R201'and v['parentPin']==implementation['parent']and v['publisherPin']==implementation['sourceRoles']['postqueue_issuer']and v['jobId']==request['jobId']and v['nonce']==request['leaseNonce']and v['bootID']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()and v['readLockClosed']is True,'complete same-parent/source/request runtime snapshot')
    root='/run/opemos-libvirt-runtime-'+request['leaseNonce']
    if 'currentControl'in request:
        parent=installer_root_value(request['currentControl']['parentPin'],0o444,1048576)
        require(implementation['parent']==request['currentControl']['parentPin']and parent['installedSourceContractPin']==request['currentControl']['definitionPin'],'same runtime parent/definition')
        root=__import__('source_contract').parent_paths(parent)['runtimeRoot']
    nine={'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'}
    i=v['directory']['identity'];require(set(v['directory'])=={'path','identity'}and v['directory']['path']==root and set(i)==nine and i==v['directoryAfter']and stat.S_ISDIR(i['st_mode'])and stat.S_IMODE(i['st_mode'])==0o700 and i['st_uid']==i['st_gid']==0,'locked runtime full9 epoch')
    def pin(ref,path,mode):
        require(set(ref)=={'path','bytes','sha256','identity'}and ref['path']==path and 0<=ref['bytes']<=1048576 and re.fullmatch('[0-9a-f]{64}',ref['sha256'])is not None,'exact runtime bounded leaf pin')
        x=ref['identity'];require(set(x)==nine and x['st_uid']==x['st_gid']==0 and stat.S_ISREG(x['st_mode'])and stat.S_IMODE(x['st_mode'])==mode and x['st_nlink']==1 and x['st_size']==ref['bytes'],'runtime leaf full9 owner/mode/link')
    pin(v['lockPin'],root+'/lock',0o600);lock=v['lock'];require(set(lock)=={'fd','identity','mode','startedMonotonic','closed','acquiredMonotonic','fdinfo'}and lock['identity']==v['lockPin']['identity']and lock['mode']=='SH'and lock['closed']is True and type(lock['fd'])is int and 0<=lock['startedMonotonic']<=lock['acquiredMonotonic']<=v['completedMonotonic']and 'FLOCK' in lock['fdinfo']and 'READ' in lock['fdinfo'],'actual shared lock identity/lifetime')
    flock=[line.split()for line in lock['fdinfo'].splitlines()if line.startswith('lock:')];require(len(flock)==1 and len(flock[0])==9 and flock[0][2:5]==['FLOCK','ADVISORY','READ']and flock[0][5]==str(producer['pid'])and int(flock[0][6].rsplit(':',1)[1])==v['lockPin']['identity']['st_ino'],'exact actual Root snapshot shared FLOCK holder')
    require(v['startedMonotonic']<=lock['startedMonotonic']<=v['completedMonotonic']<=time.monotonic()and time.monotonic()-v['completedMonotonic']<=1,'current bounded snapshot clock')
    require(type(v['leaves'])is dict and type(v['publications'])is list and len(v['leaves'])==len(v['publications'])<=512,'finite exact publication coverage')
    controls={'issuer-start.json','assignment.json','postqueue-preflight.json','child-grant.json','context.json','FIRST-postqueue-issuer.json'}
    for name,ref in v['leaves'].items():
        require(name in controls or re.fullmatch(r'[0-9]{2,3}-[A-Za-z0-9_.-]{1,96}[.]json',name)is not None,'declared runtime role');pin(ref,root+'/'+name,0o400)
    for n,ref in enumerate(v['publications']):pin(ref,root+'/publication-'+str(n).zfill(3)+'.json',0o400)
    if v['head']is None:require(v['leaves']=={}and v['publications']==[]and v['requestSHA256']is None,'empty locked pre-publisher capsule')
    else:
        h=v['head'];require(set(h)=={'kind','nonce','jobId','bootID','parentPin','publisherPin','ordinal','previousPin','name','leafPin','stateSHA256','requestSHA256','actor','beforeDirectory','afterLeafDirectory'},'closed runtime publication head schema');require(h['actor']['uid']==0 and h['actor']['pid']==h['actor']['tgid']and h['actor']['start']>0,'Root publisher head actor');require(all(set(h[f])==nine and all(h[f][k]==i[k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink'))for f in('beforeDirectory','afterLeafDirectory')),'publisher same directory object');require(h['kind']=='ROOT_DECLARED_RUNTIME_PUBLICATION_R201'and h['nonce']==request['leaseNonce']and h['jobId']==request['jobId']and h['bootID']==v['bootID']and h['parentPin']==v['parentPin']and h['publisherPin']==v['publisherPin']and h['ordinal']==len(v['publications'])-1 and h['leafPin']==v['leaves'][h['name']]and h['previousPin']==(None if len(v['publications'])==1 else v['publications'][-2])and h['stateSHA256']==hashlib.sha256(canonical(v['leaves']).encode()).hexdigest()and h['requestSHA256']==v['requestSHA256'],'complete pinned publisher head and all leaves')
        raw=canonical(h).encode();require(len(raw)==v['publications'][-1]['bytes']and hashlib.sha256(raw).hexdigest()==v['publications'][-1]['sha256'],'whole last publication record bytes/SHA')
    require(v['requestSHA256']in(None,hashlib.sha256(canonical(request).encode()).hexdigest()),'exact publisher assignment request')
    if implementation['context']is not None:
        require(all(v['leaves'].get(k)==implementation[field]for k,field in [('context.json','context'),('assignment.json','assignment'),('child-grant.json','grant')])and v['requestSHA256']is not None,'complete context consumes authenticated published leaves')
    else:require('context.json'not in v['leaves'],'absent context cannot hide a published context')
    return {k:v[k]for k in ('kind','parentPin','publisherPin','jobId','nonce','bootID','directory','lockPin','leaves','publications','head','requestSHA256')}


def runtime_publisher_transition(before,after):
    """Only validated same-request publication plus expected native phase can restart a cut."""
    try:
        a=before['observerExecution']['implementation'];b=after['observerExecution']['implementation'];x=a['runtimePublication'];y=b['runtimePublication']
        phases=(before['phase'],after['phase'])
        if phases not in(('NOT_PREPARED','NOT_PREPARED'),('NOT_PREPARED','PREPARED')):return False
        if any(x[k]!=y[k]for k in('kind','parentPin','publisherPin','jobId','nonce','bootID','lockPin')):return False
        appended=len(y['publications'])>len(x['publications'])and y['publications'][:len(x['publications'])]==x['publications']and all(y['leaves'].get(k)==v for k,v in x['leaves'].items())
        same_context=phases==('NOT_PREPARED','PREPARED')and a['context']is not None and all(a[k]==b[k]for k in('context','assignment','grant'))and x['publications']==y['publications']and x['leaves']==y['leaves']
        if not(appended or same_context):return False
        if any(x['directory']['identity'][k]!=y['directory']['identity'][k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')):return False
        if phases==('NOT_PREPARED','PREPARED'):
            # Both inputs have already traversed the full envelope/native/custody
            # validators. Require the exact initial, unbound native preparation,
            # not ACTIVE/CLOSED or an independent changing lease.
            r=after['request'];lease=after['lease'];pins=after['accessCustody']['phasePins']
            if any(b[k]is None for k in('context','assignment','grant'))or(a['context']is None and not appended):return False
            if any(before[k]is not None for k in('intentPin','intentParentPin','lease'))or any(after[k]is None for k in('intentPin','intentParentPin','lease')):return False
            if after['scope']is not None or after['leader']is not None:return False
            if not(lease['group']==NVIDIA_RESOURCE and lease['nonce']==r['leaseNonce']and lease['jobId']==r['jobId']and lease['currentBoot']==y['bootID']and lease['closed']is False and lease['restored']is True):return False
            state=pins['leaseState'];record=pins['phaseRecord']
            if not(pins['intentPin']==after['intentPin']and pins['leaseHeadPin']==lease['headPin']and pins['leaseStatePin']==lease['statePin']and state['event']=='PREPARED'and state['revision']==0 and state['closed']is False and state['restored']is True and state['changed']==[]and record['phase']=='PREPARED'and record['scope']is None and record['leader']is None and record['details']is None):return False
            if y['requestSHA256']!=hashlib.sha256(canonical(r).encode()).hexdigest()or y['leaves'].get('context.json')!=b['context']or y['leaves'].get('assignment.json')!=b['assignment']or y['leaves'].get('child-grant.json')!=b['grant']:return False
        aa=json.loads(canonical(before));bb=json.loads(canonical(after))
        for v in(aa,bb):
            i=v['observerExecution']['implementation'];i.pop('runtimePublication')
            for k in('context','assignment','grant'):i.pop(k)
        if phases==('NOT_PREPARED','PREPARED'):
            for v in(aa,bb):
                v['phase']='EXPECTED_INITIAL_PREPARATION'
                for k in('intentPin','intentParentPin','lease'):v.pop(k)
                v['accessCustody']['phase']='EXPECTED_INITIAL_PREPARATION';v['accessCustody'].pop('phasePins')
        if aa!=bb:return False
        return all(a[k]is None or a[k]==b[k]for k in('context','assignment','grant'))
    except(KeyError,TypeError):return False


BORROWED_PEER_INPUT_SHA='ba96c1b90d9e816a41c8f2375d040f9a29ae19b371540189de98215c3fff670b'
BORROWED_PEER_INPUT_BYTES=63919
BORROWED_PEER_IMPLEMENTATION={'sha256': '3b4e4f6a33bcf595ae00b4a9bb374182308ceb0930b99f01591914fde143cf71', 'bytes': 65482, 'contract': 'BORROWED_RUN_FD_LIFETIME_R240'}
BORROWED_PEER_ROOT_ADAPTER='"""Exact D23 readonly standalone peer/access adapter proposal, never installed.\nNo deployment, writes, SQL, runtime grant, domain control or sysfs methods.\nQueue owner must independently adopt exact bytes and consumer contract.\n"""\nimport contextlib,copy,hashlib,json,os,re,stat,sys,time,traceback,types\nfrom pathlib import Path\nF=(\'st_dev\',\'st_ino\',\'st_mode\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\');CORE=F[:6]\nNONCE=\'cd9ef0826364409da287f6f3e3830c95\';CONTRACT=\'D201_ROOT_PARENT_RUNTIME_PUBLICATION_SOURCE12_READONLY\'\nPEER_SHA=\'ba96c1b90d9e816a41c8f2375d040f9a29ae19b371540189de98215c3fff670b\';PEER_BYTES=63919\nACCESS_SHA=\'676385485e3f99dd95e0a755f0a9b3d461df45eb6a65edd153474377b2d9280a\';ACCESS_BYTES=32623\nROLES={\'libvirt_peer\',\'libvirt_access\',\'libvirt_native\',\'libvirt_preflight\',\'libvirt_producer\',\'queue_assignment\',\'runtime_entry\',\'guest_delta\',\'guest_firmware_probe\',\'held_history_reader\',\'two_boot_contract\',\'postqueue_issuer\'}\ndef canonical(v):return json.dumps(v,sort_keys=True,separators=(\',\',\':\'),allow_nan=False)\ndef need(v,m):\n if not v:raise RuntimeError(m)\ndef ident(s):return{k:getattr(s,k)for k in F}\ndef decode(raw):\n def unique(pairs):\n  value={}\n  for key,item in pairs:need(key not in value,\'duplicate protected JSON key\');value[key]=item\n  return value\n value=json.loads(raw,object_pairs_hook=unique);need(canonical(value).encode()==raw,\'whole canonical protected metadata, no dropped/trailing fields\');return value\ndef record_run_epoch(proof,event):\n raw=(lambda x:canonical(x).encode())(event);last=proof[\'events\'][-1]if proof[\'events\']else None\n if last is not None and last[\'event\']==event:last[\'count\']+=1\n else:proof[\'events\'].append({\'event\':event,\'count\':1})\n proof[\'eventCount\']+=1;proof[\'eventChainSHA256\']=hashlib.sha256(bytes.fromhex(proof[\'eventChainSHA256\'])+raw).hexdigest();need(0<proof[\'eventCount\']<=4096 and len(proof[\'events\'])<=256 and len((lambda x:canonical(x).encode())(proof))<=262144,\'bounded lossless borrowed run epoch runs\')\nclass RootInputs:\n """One readonly bounded held-nofollow /run graph; owns and closes all FDs."""\n def __init__(self):self.fds=[];self.dirs={}\n def __enter__(self):\n  self.root=os.open(\'/\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.fds.append(self.root)\n  try:\n   self.run=os.open(\'run\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.root);self.fds.append(self.run)\n   self.dirs={\'/\':(self.root,ident(os.fstat(self.root)),False),\'/run\':(self.run,ident(os.fstat(self.run)),False)};self.runBirth=self.run_row(self.run);rows=[x for x in Path(\'/proc/self/mountinfo\').read_text().splitlines()if x.split()[0]==str(self.runBirth[\'mountID\'])];need(len(rows)==1,\'exact initial run mount\');self.runProof={\'kind\':\'ROOT_BORROWED_RUN_ANCESTRY_R257\',\'path\':\'/run\',\'birth\':self.runBirth,\'namespace\':os.readlink(\'/proc/self/ns/mnt\'),\'mountRow\':rows[0],\'events\':[],\'eventCount\':0,\'eventChainSHA256\':\'0\'*64,\'scopeDescriptorsClosed\':False,\'closeOutcomes\':[]};self.check();return self\n  except BaseException:\n   self.__exit__(*sys.exc_info());raise\n def run_row(self,fd):\n  raw=Path(\'/proc/self/fdinfo/\'+str(fd)).read_text();v={}\n  for line in raw.splitlines():\n   if line.startswith((\'flags:\',\'mnt_id:\')):k,x=line.split(\':\',1);v[k]=x.strip()\n  need(set(v)=={\'flags\',\'mnt_id\'}and v[\'mnt_id\'].isdigit()and re.fullmatch(\'[0-7]+\',v[\'flags\'])is not None,\'complete actual run descriptor flags/mount\')\n  f=__import__(\'fcntl\');return {\'fd\':fd,\'identity\':ident(os.fstat(fd)),\'target\':os.readlink(\'/proc/self/fd/\'+str(fd)),\'flags\':f.fcntl(fd,f.F_GETFL),\'descriptorFlags\':f.fcntl(fd,f.F_GETFD),\'fdinfoFlags\':v[\'flags\'],\'mountID\':int(v[\'mnt_id\'])}\n def borrowed_run(self):\n  initial=self.runBirth;owned=[];primary=None;event={};startns=os.readlink(\'/proc/self/ns/mnt\')\n  try:\n   event[\'heldBefore\']=self.run_row(self.run)\n   for label,path,anchored in((\'anchored\',\'run\',True),(\'named\',\'/run\',False)):\n    fd=os.open(path,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,**({\'dir_fd\':self.root}if anchored else{}));owned.append(fd);event[label]=self.run_row(fd)\n   event[\'anchoredPath\']=ident(os.stat(\'run\',dir_fd=self.root,follow_symlinks=False));event[\'namedPath\']=ident(os.lstat(\'/run\'));event[\'heldAfter\']=self.run_row(self.run);event[\'anchoredAfter\']=self.run_row(owned[0]);event[\'namedAfter\']=self.run_row(owned[1]);event[\'namespaceBefore\']=startns;event[\'namespaceAfter\']=os.readlink(\'/proc/self/ns/mnt\')\n   rows=[x for x in Path(\'/proc/self/mountinfo\').read_text().splitlines()if x.split()[0]==str(initial[\'mountID\'])];need(len(rows)==1,\'unique current kernel run mount row\');event[\'mountRow\']=rows[0]\n   stable=F[:5];snapshots=[event[k][\'identity\']for k in(\'heldBefore\',\'anchored\',\'named\',\'heldAfter\',\'anchoredAfter\',\'namedAfter\')]+[event[\'anchoredPath\'],event[\'namedPath\']]\n   need(all(all(x[k]==initial[\'identity\'][k]for k in stable)for x in snapshots)and all(event[k][\'target\']==\'/run\'and event[k][\'mountID\']==initial[\'mountID\']and event[k][\'descriptorFlags\']==1 for k in(\'heldBefore\',\'anchored\',\'named\',\'heldAfter\',\'anchoredAfter\',\'namedAfter\')),\'same held/anchored/named run inode/type/mode/owner/mount\')\n   need(event[\'heldBefore\']==dict(initial,identity=event[\'heldBefore\'][\'identity\'])and event[\'heldAfter\']==dict(initial,identity=event[\'heldAfter\'][\'identity\'])and startns==event[\'namespaceAfter\']==self.runProof[\'namespace\'],\'same borrowed run FD/flags/name/namespace\')\n   for name in(\'anchored\',\'named\'):\n    a=event[name];b=event[name+\'After\'];need(a==dict(b,identity=a[\'identity\'])and a[\'flags\']==os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,\'exact temporary nofollow O_PATH run descriptors\')\n   row=rows[0].split();i=initial[\'identity\'];need(stat.S_ISDIR(i[\'st_mode\'])and stat.S_IMODE(i[\'st_mode\'])==0o755 and i[\'st_uid\']==i[\'st_gid\']==0 and initial[\'flags\']&os.O_ACCMODE==os.O_RDONLY and not initial[\'flags\']&os.O_PATH and initial[\'flags\']&os.O_DIRECTORY and initial[\'flags\']&os.O_NOFOLLOW and re.fullmatch(r\'mnt:\\[[0-9]+\\]\',startns)is not None,\'declared borrowed Root0755 readonly run directory\');need(row[3:5]==[\'/\',\'/run\']and row[2]==str(os.major(i[\'st_dev\']))+\':\'+str(os.minor(i[\'st_dev\']))and event[\'mountRow\']==self.runProof[\'mountRow\'],\'same kernel mount root/device/path and original run mount\')\n  except BaseException as error:primary=error;error.evidence={\'kind\':\'BORROWED_RUN_CUSTODY_REFUSAL_R257\',\'birth\':initial,\'event\':event};raise\n  finally:\n   errors=[]\n   for fd in owned[::-1]:\n    try:os.close(fd)\n    except BaseException as e:errors.append({\'fd\':fd,\'type\':type(e).__name__,\'reason\':str(e)})\n   if errors:\n    if primary is not None:primary.ownedRootInputClosureErrors=errors\n    else:raise RuntimeError(canonical({\'ownedRootInputClosureErrors\':errors}))\n  event[\'temporaryDescriptorsClosed\']=True;record_run_epoch(self.runProof,event);return event\n def check(self):\n  for path,(fd,a,exclusive)in self.dirs.items():\n   if path==\'/run\':self.borrowed_run();continue\n   x=ident(os.fstat(fd));named=ident(os.lstat(path))\n   if not(x==named and all(x[k]==a[k]for k in(CORE if not exclusive else F))):\n    error=RuntimeError(\'held/named declared directory identity/epoch\');error.evidence={\'path\':path,\'role\':\'exclusive\'if exclusive else\'shared-ancestor\',\'birth\':a,\'held\':x,\'named\':named,\'monotonic\':time.monotonic()};raise error\n   need(stat.S_ISDIR(x[\'st_mode\'])and x[\'st_uid\']==x[\'st_gid\']==0,\'Root directory nofollow custody\')\n   need(stat.S_IMODE(x[\'st_mode\'])in((0o755,0o777)if path==\'/\'else(0o755,)if path==\'/run\'else(0o755,)if path.startswith(\'/run/opemos-steamos-source-\')else(0o700,)),\'exact role-specific directory mode\')\n def directory(self,path):\n  allowed={\'/run/opemos-steamos-source-\'+NONCE,\'/run/opemos-libvirt-runtime-\'+NONCE,\'/run/opemos-steamos-placement-\'+NONCE}\n  need(path in allowed,\'declared finite source/context/placement root only\')\n  if path not in self.dirs:\n   fd=os.open(Path(path).name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.run);self.fds.append(fd);self.dirs[path]=(fd,ident(os.fstat(fd)),True)\n  self.check();return self.dirs[path][0]\n def read_path(self,path,mode,cap):\n  path=Path(path);need(path.is_absolute()and path.name not in(\'\',\'.\',\'..\'),\'absolute confined declared leaf\')\n  if str(path.parent)==\'/run\':need(str(path)==\'/run/opemos-libvirt-parent-\'+NONCE+\'.json\',\'one normal public parent only\');parent=self.run\n  else:parent=self.directory(str(path.parent))\n  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)\n  try:\n   s=os.fstat(fd);a=ident(s);need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode and s.st_nlink==1 and s.st_size<=cap,\'exact Root leaf mode/owner/link/size\');raw=b\'\'\n   while chunk:=os.read(fd,65536):raw+=chunk;need(len(raw)<=cap,\'bounded full leaf stream\')\n   need(a==ident(os.fstat(fd))==ident(os.stat(path.name,dir_fd=parent,follow_symlinks=False))==ident(os.lstat(path))and len(raw)==a[\'st_size\'],\'full held/anchored/named identity and EOF\');self.check();return raw,{\'path\':str(path),\'bytes\':len(raw),\'sha256\':hashlib.sha256(raw).hexdigest(),\'identity\':a}\n  finally:os.close(fd)\n def read(self,ref,mode,cap):\n  raw,actual=self.read_path(ref[\'path\'],mode,cap)\n  if actual!=ref:\n   error=RuntimeError(\'exact declared full9/length/SHA pin\');error.evidence={\'path\':ref[\'path\'],\'expected\':ref,\'actual\':actual};raise error\n  return raw\n def placement_bytes(self,fd,parentfd,ref):\n  """Inner FD/hash check; hold_placement applies exact Root role custody.\n  It does not change Root policy or convert a user fixture into Root proof.\n  """\n  value={\'path\':ref[\'path\'],\'expected\':ref,\'heldBefore\':None,\'heldAfter\':None,\'named\':None,\'heldSHA256\':None,\'namedSHA256\':None,\'heldBytes\':None,\'namedBytes\':None}\n  def bytesof(f):\n   chunks=[];offset=0\n   while True:\n    b=os.pread(f,65536,offset)\n    if not b:break\n    offset+=len(b);need(offset<=1048576,\'unchanged placement metadata1MiB streaming cap\');chunks.append(b)\n   return b\'\'.join(chunks)\n  try:\n   value[\'heldBefore\']=ident(os.fstat(fd));need((__import__(\'fcntl\').fcntl(fd,__import__(\'fcntl\').F_GETFL)&os.O_ACCMODE)==os.O_RDONLY,\'owned placement held FD remains O_RDONLY\');held=bytesof(fd);value.update(heldBytes=len(held),heldSHA256=hashlib.sha256(held).hexdigest())\n   nf=os.open(Path(ref[\'path\']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)\n   try:\n    value[\'named\']=ident(os.fstat(nf));named=bytesof(nf);value.update(namedBytes=len(named),namedSHA256=hashlib.sha256(named).hexdigest());need(value[\'named\']==ident(os.fstat(nf))==ident(os.stat(Path(ref[\'path\']).name,dir_fd=parentfd,follow_symlinks=False))==ident(os.lstat(ref[\'path\'])),\'placement fresh nofollow named FD/path full9\')\n   finally:\n    primary=sys.exc_info()[1]\n    try:os.close(nf)\n    except BaseException as close:\n     if primary is None:raise\n     primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'fd\':nf,\'type\':type(close).__name__,\'reason\':str(close)}]\n   value[\'heldAfter\']=ident(os.fstat(fd));need(value[\'heldBefore\']==value[\'heldAfter\']==value[\'named\']==ref[\'identity\']and len(held)==len(named)==ref[\'bytes\']and value[\'heldSHA256\']==value[\'namedSHA256\']==ref[\'sha256\']and held==named,\'placement held/named full9/raw bytes/length/SHA equal originally bound operand\')\n   return held\n  except BaseException as error:error.placementCustody=value;raise\n @contextlib.contextmanager\n def hold_placement(self,ref):\n  root=\'/run/opemos-steamos-placement-\'+NONCE;need(ref[\'path\']in(root+\'/storage-contract.json\',root+\'/placement-qualified.json\'),\'two exact placement metadata leaves only\');i=ref[\'identity\'];need(set(ref)=={\'path\',\'bytes\',\'sha256\',\'identity\'}and 0<ref[\'bytes\']<=1048576 and stat.S_ISREG(i[\'st_mode\'])and stat.S_IMODE(i[\'st_mode\'])==0o400 and i[\'st_uid\']==i[\'st_gid\']==0 and i[\'st_nlink\']==1 and i[\'st_size\']==ref[\'bytes\'],\'exact Root0400 placement full pin/custody\')\n  parentfd=self.directory(root);fd=os.open(Path(ref[\'path\']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)\n  try:\n   original=self.placement_bytes(fd,parentfd,ref);self.check()\n   def recheck():\n    self.check();raw=self.placement_bytes(fd,parentfd,ref);need(raw==original,\'complete held placement raw bytes identical after observer\');self.check();return ref\n   yield {\'ref\':ref,\'raw\':original,\'recheck\':recheck}\n  finally:\n   primary=sys.exc_info()[1]\n   try:os.close(fd)\n   except BaseException as close:\n    if primary is None:raise\n    primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'fd\':fd,\'type\':type(close).__name__,\'reason\':str(close)}]\n def __exit__(self,*a):\n  errors=[]\n  for fd in self.fds[::-1]:\n   try:\n    os.close(fd)\n    if hasattr(self,\'runProof\'):self.runProof[\'closeOutcomes\'].append({\'fd\':fd,\'closed\':True})\n   except OSError as e:errors.append({\'fd\':fd,\'type\':type(e).__name__,\'reason\':str(e)})\n  self.fds=[]\n  if hasattr(self,\'runProof\'):self.runProof[\'scopeDescriptorsClosed\']=not errors\n  if errors:\n   if a[1]is not None:a[1].ownedRootInputClosureErrors=errors\n   else:raise RuntimeError(canonical({\'ownedRootInputClosureErrors\':errors}))\n\ndef parent_spec(parent,parent_ref):\n s=copy.deepcopy(parent[\'normalizedSpecTemplate\']);need(s[\'approval\']==\'EXACT_PARENT_MINIMAL_PIN\'and s[\'command\'][-1]==\'EXACT_PARENT_FULL_PIN_JSON\',\'two existing late parent-pin slots only\');s[\'approval\']={k:parent_ref[k]for k in(\'path\',\'bytes\',\'sha256\')};s[\'command\'][-1]=canonical(parent_ref)\n need(s[\'command\']==[\'sudo\',\'-n\',\'/usr/bin/python3\',\'-B\',parent[\'sourceRoles\'][\'runtime_entry\'][\'path\'],\'--parent-pin-json\',canonical(parent_ref)]and s[\'id\']==parent[\'jobId\']and s[\'cores\']==4 and s[\'memory\']==10737418240 and s[\'timeout_seconds\']==900 and \'omen-iommu-group-1\'in s[\'resources\'],\'exact ordinary entry and10GiB/4CPU/900s spec\')\n return s\n\ndef verify_inputs(request,io,boot,include_context=True):\n need(request[\'leaseNonce\']==NONCE and request[\'domainName\']==\'opemos-libvirt-\'+NONCE,\'fresh exact D23 scope only\')\n cr=\'/run/opemos-libvirt-runtime-\'+NONCE+\'/context.json\';parentRaw,parentRef=io.read_path(\'/run/opemos-libvirt-parent-\'+NONCE+\'.json\',0o444,1048576);parent=decode(parentRaw)\n contextRaw=contextRef=context=None\n if include_context:\n  try:contextRaw,contextRef=io.read_path(cr,0o400,1048576);context=decode(contextRaw)\n  except FileNotFoundError:pass\n need(parent[\'kind\']==\'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT\'and parent[\'RootIssued\']is True and parent[\'runtimeAuthorized\']is True and parent.get(\'MODEL_ONLY\')is False and parent[\'bootID\']==boot and parent[\'nonce\']==NONCE and parent[\'contextPath\']==cr,\'existing actual same-boot Root parent; no issuance or clock refresh\')\n if context is not None:need(context[\'parentPin\']==parentRef and context[\'kind\']==\'ROOT_LIBVIRT_R4_RUNTIME_CONTEXT\'and context[\'runtimeAuthorized\']is True and context.get(\'MODEL_ONLY\')is False and context[\'candidate\']==parent[\'candidate\']and context[\'sourceRoles\']==parent[\'sourceRoles\'],\'Root context/candidate/source12 equality; no model promotion\')\n need(type(parent[\'candidate\'].get(\'installer\'))is dict and parent[\'candidate\'][\'installer\'].get(\'kind\')==\'AUTHENTICATED_F9AA_RAW_RECOVERY_USB_FIRSTBOOT\'and parent[\'candidate\'][\'installer\'].get(\'noInstallTarget\')is True,\'this reviewed source branch admits only the retained installer/no target\')\n need(parent[\'issuedUnix\']<parent[\'startBeforeUnix\']<=parent[\'issuedUnix\']+300 and parent[\'wholeDeadlineUnix\']<=parent[\'issuedUnix\']+900,\'original finite parent scope retained; readonly closed observation does not reissue authority\')\n roles=parent[\'sourceRoles\'];need(set(roles)==ROLES,\'complete source12 membership\')\n need(roles[\'libvirt_peer\'][\'bytes\']==63919 and roles[\'libvirt_peer\'][\'sha256\']==PEER_SHA and roles[\'libvirt_access\'][\'bytes\']==ACCESS_BYTES and roles[\'libvirt_access\'][\'sha256\']==ACCESS_SHA,\'frozen reviewed peer/access implementation\')\n need(request[\'observer\']=={k:roles[\'libvirt_peer\'][k]for k in(\'path\',\'bytes\',\'sha256\')}and request[\'jobId\']==parent[\'jobId\'],\'exact original request observer/job\')\n source={}\n for name,ref in sorted(roles.items()):\n  need(ref[\'path\']==\'/run/opemos-steamos-source-\'+NONCE+\'/\'+name+\'.py\',\'same exact source namespace\');source[name]=io.read(ref,0o444,65536);compile(source[name],ref[\'path\'],\'exec\')\n spec=parent_spec(parent,parentRef);bound=spec[\'libvirt_domain\'];need(bound=={\'leaseNonce\':NONCE,\'name\':request[\'domainName\'],\'observer\':request[\'observer\'],\'uuid\':request[\'domainUUID\']}and hashlib.sha256(canonical(spec).encode()).hexdigest()==request[\'specSHA256\'],\'complete final normalized spec/hash/domain identity\')\n assignmentRef=grantRef=None;assignment=grant=None\n if context is not None:\n  assignmentRef=context[\'assignmentPin\'];need(assignmentRef[\'path\']==\'/run/opemos-libvirt-runtime-\'+NONCE+\'/assignment.json\'and context[\'grantPin\'][\'path\']==\'/run/opemos-libvirt-runtime-\'+NONCE+\'/child-grant.json\',\'two exact same-scope child control leaves\');assignment=decode(io.read(assignmentRef,0o400,1048576));grantRef=context[\'grantPin\'];grant=decode(io.read(grantRef,0o400,1048576))\n  need(assignment[\'kind\']==\'ROOT_CANONICAL_QUEUE_LIBVIRT_ASSIGNMENT_R4\'and assignment[\'request\']==request and grant[\'assignmentPin\']==assignmentRef and grant[\'parentPin\']==parentRef and grant[\'normalizedSpecSHA256\']==request[\'specSHA256\'],\'canonical assignment and child grant exact request/spec/parent\')\n  need(grant[\'queuePrograms\']==parent[\'queuePrograms\']and grant[\'sourcePlacementPin\']==context[\'sourcePlacementPin\']==parent[\'sourcePlacementPin\']and grant[\'placementQualificationPin\']==context[\'placementQualificationPin\']==parent[\'placementQualificationPin\'],\'current queue authority and placement pins across child/context/parent\')\n  need(grant[\'RootIssued\']is True and grant[\'MODEL_ONLY\']is False and grant[\'runtimeAuthorized\']is True and grant[\'jobId\']==request[\'jobId\']and grant[\'leaseNonce\']==NONCE and grant[\'bootID\']==boot and parent[\'issuedUnix\']<=grant[\'issuedUnix\']<grant[\'startBeforeUnix\']<=parent[\'startBeforeUnix\']and grant[\'wholeDeadlineUnix\']<=parent[\'wholeDeadlineUnix\'],\'existing finite Root child only, no new runtime grant\')\n return {\'parent\':parent,\'parentPin\':parentRef,\'parentRaw\':parentRaw,\'context\':context,\'contextPin\':contextRef,\'contextRaw\':contextRaw,\'source\':source,\'assignmentPin\':assignmentRef,\'assignmentRaw\':None if assignment is None else canonical(assignment).encode(),\'grantPin\':grantRef,\'grantRaw\':None if grant is None else canonical(grant).encode()}\n\ndef _bind_placement(peer,parent,parent_ref,context,verify_access):\n """Bind only the fresh protected same-source/same-scope metadata operand.\n Never changes the frozen peer\'s nonce, strict geometry or owner predicate.\n """\n nonce=parent[\'nonce\'];roles=parent[\'sourceRoles\'];candidate=parent[\'candidate\']\n peer.need(nonce==\'cd9ef0826364409da287f6f3e3830c95\'and peer.SOURCE_PLACEMENT_NONCE==nonce and candidate[\'nonce\']==nonce and __import__(\'queue_assignment\').execution_job(candidate,parent)==parent[\'jobId\'],\'D23 unused scope only; D22 is consumed\')\n peer.need(parent[\'RootIssued\']is True and parent[\'kind\']==\'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT\'and parent[\'bootID\']==candidate[\'hostBoot\']and parent_ref[\'path\']==\'/run/opemos-libvirt-parent-\'+nonce+\'.json\',\'existing exact Root parent/boot/source scope\')\n peer.need(set(roles)=={\'libvirt_peer\',\'libvirt_access\',\'libvirt_native\',\'libvirt_preflight\',\'libvirt_producer\',\'queue_assignment\',\'runtime_entry\',\'guest_delta\',\'guest_firmware_probe\',\'held_history_reader\',\'two_boot_contract\',\'postqueue_issuer\'},\'closed twelve-role binding\')\n peer.need(roles[\'libvirt_peer\'][\'sha256\']==\'ba96c1b90d9e816a41c8f2375d040f9a29ae19b371540189de98215c3fff670b\'and roles[\'libvirt_peer\'][\'bytes\']==63919 and roles[\'libvirt_access\'][\'sha256\']==\'676385485e3f99dd95e0a755f0a9b3d461df45eb6a65edd153474377b2d9280a\'and roles[\'libvirt_access\'][\'bytes\']==32623,\'frozen exact D23 peer and unchanged access bytes\')\n for name,ref in roles.items():peer.need(ref[\'path\']==\'/run/opemos-steamos-source-\'+nonce+\'/\'+name+\'.py\'and ref[\'identity\'][\'st_uid\']==ref[\'identity\'][\'st_gid\']==0 and stat.S_IMODE(ref[\'identity\'][\'st_mode\'])==0o444 and ref[\'identity\'][\'st_nlink\']==1,\'same immutable Root source12 namespace\')\n ref=parent[\'sourcePlacementPin\'];qr=parent[\'placementQualificationPin\'];root=\'/run/opemos-steamos-placement-\'+nonce\n peer.need(ref[\'path\']==root+\'/storage-contract.json\'and qr[\'path\']==root+\'/placement-qualified.json\',\'fresh exact placement+qualification names, no historical receipt\')\n files=peer.RootFiles(root);primary=None;result=None\n try:\n  files.__enter__()\n  raw,actual=files.read(\'storage-contract.json\');qualified,qactual=files.read(\'placement-qualified.json\');peer.need(actual==ref and qactual==qr,\'fresh placement/qualification exact full9/EOF/SHA\')\n  value=json.loads(raw);q=json.loads(qualified);b=value[\'preparationBinding\']\n  peer.need(value[\'kind\']==(\'ROOT_EXACT_STEAMOS_INSTALLER_GAMES_PLACEMENT\'if candidate.get(\'installer\')is not None else\'ROOT_EXACT_STEAMOS_FIXED_GAMES_PLACEMENT\')and value[\'nonce\']==nonce and value[\'boot\']==parent[\'bootID\']and value[\'original\']==candidate[\'original\']and value[\'working\']==candidate[\'working\']and value.get(\'installer\')==candidate.get(\'installer\'),\'same current prepared working placement, no relabel\')\n  peer.need(b[\'sourceRoles\']==roles and b[\'queuePrograms\']==parent[\'queuePrograms\']and b[\'sourceGraphSHA256\']==hashlib.sha256(peer.canon(roles)).hexdigest(),\'placement producer source12/current queue equality\')\n  peer.need(q[\'kind\']==\'ROOT_VERIFIED_FRESH_STEAMOS_PLACEMENT\'and q[\'qualifiedPlacementPin\']==ref and q[\'nonce\']==nonce and q[\'bootID\']==parent[\'bootID\']and q[\'sourceRoles\']==roles and q[\'queuePrograms\']==parent[\'queuePrograms\']and q[\'runtimeAuthorized\']is False and q[\'RootIssuedRuntimeAuthority\']is False,\'complete fresh protected metadata qualification, not a runtime grant\')\n  pre=q[\'currentPreflight\'];prepared=parent[\'preparedDiskPins\'];access_pin=parent[\'preparedAccessPin\']\n  peer.need(type(prepared)is dict and set(prepared)=={\'original\',\'working\'}and prepared[\'original\']==candidate[\'original\']and b[\'preparedDiskPins\']==prepared and access_pin is not None and b[\'preparedAccessPin\']==access_pin==pre[\'preparedAccessPin\']and b[\'splitDiskCapturePins\']==parent[\'splitDiskCapturePins\']==pre[\'splitDiskCapturePins\'],\'exact candidate/pending-access/post-ACL prepared captures/final-preflight lineage\')\n  work=prepared[\'working\'];before_work=candidate[\'working\'];peer.need(work[\'path\']==before_work[\'path\']and work[\'bytes\']==before_work[\'bytes\']and work[\'sha256\']==before_work[\'sha256\']and all(work[\'identity\'][k]==before_work[\'identity\'][k]for k in(\'st_dev\',\'st_ino\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\')),\'same content and stable pre/post ACL working object; full9 remains exact within each epoch\')\n  verify_access(candidate,access_pin,prepared)\n  peer.need(q[\'currentPreflightPin\']==parent[\'prequeuePreflightPin\']and pre[\'bootID\']==parent[\'bootID\']and pre[\'storagePlacement\'][\'receiptPin\']==ref and pre[\'queuePrograms\']==parent[\'queuePrograms\']and pre[\'original\']==candidate[\'original\']and pre[\'kind\']==\'ACTUAL_LIBVIRT_R4_CURRENT_PREFLIGHT\'and pre[\'working\']==prepared[\'working\']and 0<=parent[\'issuedUnix\']-pre[\'observedUnix\']<=30,\'existing normal complete current preflight joins placement before parent issuance\')\n  if context is not None:peer.need(context[\'parentPin\']==parent_ref and context[\'candidate\']==candidate and context[\'sourceRoles\']==roles and context[\'sourcePlacementPin\']==ref and context[\'placementQualificationPin\']==qr,\'context/parent/source12/placement equality\')\n  peer.need(peer.SOURCE_PLACEMENT_PIN is None or peer.SOURCE_PLACEMENT_PIN==ref,\'never replace a different bound placement operand\')\n  again,again_pin=files.read(\'storage-contract.json\');again_q,again_qpin=files.read(\'placement-qualified.json\');peer.need((again,again_pin)==(raw,ref)and(again_q,again_qpin)==(qualified,qr),\'original held/named placement and qualification full9/raw-SHA unchanged after prepared verification\')\n  result={\'placementPin\':ref,\'qualificationPin\':qr,\'sourceGraphSHA256\':b[\'sourceGraphSHA256\'],\'runtimeAuthorityIssued\':False}\n except BaseException as error:primary=error\n finally:\n  try:files.__exit__(None if primary is None else type(primary),primary,None)\n  except BaseException as close:\n   if primary is None:primary=close\n   else:primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'role\':\'bind-placement-ancestors\',\'type\':type(close).__name__,\'reason\':str(close)}]\n if primary is not None:raise primary\n peer.SOURCE_PLACEMENT_PIN=ref\n return result\n\ndef bind_placement(peer,parent,parent_ref,context=None):\n from libvirt_access import verify_prepared\n return _bind_placement(peer,parent,parent_ref,context,verify_prepared)\n\ndef bind_observer_placement(peer,parent,parent_ref,context):\n from libvirt_access import prepared_lineage\n return _bind_placement(peer,parent,parent_ref,context,prepared_lineage)\n\nBORROWED_IMPLEMENTATION={\'sha256\': \'3b4e4f6a33bcf595ae00b4a9bb374182308ceb0930b99f01591914fde143cf71\', \'bytes\': 65482, \'contract\': \'BORROWED_RUN_FD_LIFETIME_R240\'}\nBORROWED_SOURCE=__import__(\'zlib\').decompress(__import__(\'base64\').b85decode(\'c-qx{X>;4ywcvOC3M5nSfoy}MB=4k=8CgrWDz@cFcG5Epiv^OPgqT|cq?S1P?{n6>0H7rI%e<=Tu96AhuIHY6?%D4j|M<uAG?^?Hv%BE8O}a^gRhs7QKmPHLJK21-%-6wqxmc&S>sdC6rsKtW7F{L96+Zo=ST3Sv5#?!Atdn(A+!fI}o2St_PsZse8Gq|Z6SwnOJ6-2#+CHA8^K`NP0>6W#2#&w(O!MVDSS4$0GLZ70;jwpedi>$&B5s7mdN@h1!w7$5izWY<FDEJg+GG>{aj8ERvuyE=e-_z4rPv&YHe3|^G}fo)&f(el@$c`Y+53EU_8|^C%T+pG7VTn|jZ=AOUC+zUt<`cl<Co#i&*x`fKgZz`AkxZ~^ZBNAnJ+i1)?V2AbP<P}e9`5K-C~_4_%FcdI?LDH{cvYIONt^mPp6wAoixrj3!Kq$o-gxecLkqzCh0U-r10%Jnm4;UK?aY@b#UFyldMQh&3Thbj+4c5(YS7Q^K=az2e`QH$!5MPpnd_1GW?d_74esR1FM~`k~~>2^8(-&!T;T`86~sX@@BY57V$|kE7E2=U5o*G4Q@W0z^XS2ZT|bW?qv!%v(6hu^sPBv=E1ihTLir3_dKFyo<3d!SC7jV$vkc3=`_ld8$d`ilUcfGz^i5)!^eI&x?873I0%x(BoIt)7gx#t%U4vYeU;u$vdgqsH?#(Sl`1lkwSJ`MY<(9FXb`J>IZlhBvC1Y0bAtc+Zk5uDtbh@(sTp|u({2>5mPNMCuG8T2=@FpP3h)S9=!DM-m?+lS38s@6@Cp!N(OAKDYo86zkIp`Q_}~Ac-$$qC$A@3e&gJpb*~!_54`+Ylr^63t$G;vQLL)e~9QJu*5si~o{OaY)=dW;p!PGRqs5V~PS~SV>Aq;AYgA3OA9X1mzH|uy5hWPX5Dx0OjsEaLApVR2Y?px>%$~=olJpu}@3OqO8#V{TK1k5^^X6bAajFy|lB*eA@SwSd=Bh40oV|QI>bv#=ZX=4gyr2A0{2$9CrTZqI6ftlp%BIYmcNy^CB&WqJ7TQ|aH80|ItdxJJVH+xuXQ#eg*fH;_Xz44`d8q*$iKDA+~vK16b^2=*2G@k%<NTC!rKMMc88%hcM)9<$S2CyOVH{k=lgm*ClF@^m@Z(wHGq=@^s0pj~D;yaIwo5e1QMibh(g+btSZ?g4OBmA08U`Gym>&qXm`sI@ALeFNIU<iQi_-lO$KlW(A_*kUt#ynXy0I4G=)ZaDG?C*64%_bH`QkjeZAC`+W_<DNO`SLTNI<-E&^g7?|b~|AcTMz%f2$5L9sK=L4h;=uM4De$TDEwiB*YWod_DI-;Kh#gY4!baz1}%Mm@9m%&g-E#RWqE}7aeb*@*O!%#tCfC~_VA^2-yL7}pLYjQh|3gq`+$_wLNMaCX+Vx&2lqT#7daotM;v_|BNe#r%hU!08ax{tt7bbZhOiMEFr;OkUE<y#;uBC=*g5kAmKX?4o)$o%2wt+C0IjNf2{yBwD9h#g1U7I1`wF;#UvNt<meVDYcUXC#Zm{Rt!NpaQL-U=elW!IQoFqhvpN%(p4&4PON1X-G;~@QQlfZoL+B?DLJiAWT>F(>@-5`ff2#wO~G`|C6N~YAtbTga1Z3hRl8BnZZ4EqXCnP7PXQ|Zu1Cv6%QQ?wzR)Y*DC1WcSwBV;0)UHsX`pD{xUU-szb6t~iVe~+&KJmv|g*(bm;Z4@Su=F%z=Nm@T#3)6VhLtKP`p7D&pygj6FoA3vA!}BOiZ<FylxJ(x*oS+Cm1RsI}_Jl*}!%p}+X}y_iJ6S<X6I@zn&ib}N(1C86(R32gSxYz!=!rGpKZm#@J}-!b_*24dP6gaUYVrF9?i?$%Q=lca^FU$=JGQd`!X3LKr{TzgwV83lebi>wEsl2y@33_HVt9H1Lz9BY>%ne1XVgSIhgsv<-9hxr!&)ffs0;vsD<H51id54{d2~G)8TbD2?C99-9Y(i=?SaQ3?G@ULxM8$&c^?}tM8}klzrhJ48yw%kFw)y`x>^VClOjE)pV@N3+XGPimiEn0z_YiZ9PFd%veASVkT>Lgz>S(cfH<(isp6K)fZ8ZJ5I_hE5`U^Ae4NqaN(nxKDS>&?j}iQk)_{;I$njH0>Bl6`rcAt$e_h3~LEA1hn3yF_wyZG0I58m377c*$%a;-Sef=8N8z}LNNZHl0STkWF4kXF%xZiZ<^$hz}JKxd;ts?Y*jAO1_oFs{+(h^=j11-T9JTT3dnf*cpr)jZ5fkV_X6z&c-B-9+PvV~nU4>_`UTd#^YaGF9-Vb`a0k+96&tZyW$L8M%9x5PuU9Fa9WMmn-=ayPqoxKX0pIF|_F18{o**pCeA-tLPxFJHg1)E9U-obEhXk6{)12d)2;wEnr<dOK{l2G2rj1Nm!Y8jzI3LA_i|=>){X1&OOAP}tv(@wy5shbFqnUfR|d=f^)g_(1&KRy?I=k|mY3+KN{AkFA3XA>1?3EIwK2C>?KLCr$1;@G-<aee(coE}{Sw@_2KUg`{=b4k?Zcs?4*+rGRuN@US^?u~z}(zN1$Jd>^V2GZ(|+ZjN9mM1VBsC<||9&QVBnB;@ZLpPeX;@JOK}J)k&Pi`le^EP88KTT#0#9(q_UAh_QqsQfRhMrq5>d9p|@)10@%Y$?Px0&+at6d)8b9HI%V6SC{XqLgH|5UUwZ;cw?ZfXcmTmc!wMjrOjS*(Qy@-#h4Cc<8OPqiAZ`a0<Nf)B`~j5|QhM$G?U^GR-^!lxM<=Uqa#0)5*sr?9=5U8;4!gTD0f-j6h{JFYMCng?BFONnR%N4{x8sqsp&#OQ%0>)WX}SSs7sk#7{$6*@{>txB||ZP;8?6k+;l$GXUl2R4fXBNaC7zNtf5265dT&v)BG`cKGMv@vlLp^T7Fj@yoxQr%&(YkSx-!WxYt{p<Uvciy|WQm8=QKyYKW{t33R7@$+3rq?sarkOn!cw-~TD*<!N1VPFbHL$wrlPYCSKt?@&XYnEo$8v)h(#%(J{g$)B8JUt_Qn{<o~muK^*SSPB5f)uO7s(lM}W~<F;mW>nS(Rh|x5eOSqX{XnSD&sUJ1Y%B&Ta%`#^J12!s|HZ%MtgVnWi(H28@tg~XbZo}RQxIA`*-gKMe`t;f^Zci<KH$J>b{o1O)*XBhx9Ucv3n4gN33P16J%MTfUsqxHpB6B_=~8}U<!254UynN?K@I2Q5#!0WK>J1W?7j?8YsgOs}_>pfjlRx5=KOxb$6AP?0X3K0$VaXKRf#}B-A?mdhzA#=zkB-k59f{9DIPiU3Ww=yzxw0B&*^I#KbNQ9+|=P1AIFIfQ^A|2KwPj2(;~mnKuX0j%*L-U{Y`j%@~k^cPDrXXb>0#9z#;JKLJ}C$9{+n(>5t$1s#2j!qVq3>JOUF`i3wf4FU3ol!Q8Mg4lxObU2JcSkeM8hk(T&qwwpeKYu#=+o!OLQ@9@(VgA-?2!2ZP%Yu(kbNGp9Go2WL1_aN37Zr3h0Au-bD{#8pE`tSHO?Qkih`NUz3$(7F6OO3AH*i?juDojJs)?zCp%em8)RZ!ybYMumZi69ztbw6Wb|yAdiqzc0@p8VJrR#Kfm7&lElxsE=<HV40iMV0nSNJ)m=QfPL5sH@RC@WY2PDEfjOV%+Bl`G(0nq*_v69N9pYii*ee#9{bY6xhAlO?LW4o0NzvPa10)1wPKG|dOr;2qCbaOOtgUr$cYPL2xm6{Wy)5=3D;Fb~>r2F2swEWRz4H!x@%#ta}pW8@Nj^K}rzk~hilf^$=Q1n)3=OxDa66|3?(2HGLu!Uf*sXpf?WKyDxfR+1!D7`R!8zkK|B$lEyz7t3GFdwO}2jB+_=!h3hr50)G#xZN6cJr0Bxcm?e+2_%jZY=a!h0>F)O8lw+DA-P<@Dr95$X%Hj|Y<B_lCmPNoFl*5pk7Mnz1hGNS0r$9ySmUio#cf9+pooEK3DG=^A-Y_o`E~j^&*r=`i{(Xj37B}6U)&Yb;&?g*iY>S$U86`-q^N5RaS(KV2JUwY!X|>y{ZzLMdJaM73|!r>fhuTu5~yb(y~kJ}1?UP(1Mn_lZC{>MXHP(scOLrhzC#I0zr2fIy)Xc#I=2-Rza{L>movm^I*1r0xp<$y46qu|C~L>iE^r?ZcZlUD!6G3`n#?4y!^URNh@uUa8yYxLFBTPJ2ab@R(TcFhe%q8A59qV<FGc*_bkT)hJfTW&a54k0vYav-S1^o$IY?2V2rJW)6>9McwQzY_W_g@7pjIllOm81W=Yzu!4$78kpidzmM)&PxwnF327PC92#t8`Uzkr1O*EA=~j_e3K0ZV2T<(+R2VSP|4i}E(C%Ph_RmSpQyHaVOnz*cVCYX;bHOpQcgvRPjt`#Mg%z2vN#*;i7zBN(Fgj|h(UG6kDD1eW&Q%)^NyyKTWbwQ>Ts6!Z4r%-esw`(`leSLXTqEw@FirDK*F&q!MFw&lI4xn;{rTe&$M-9v%PyS?eYrK){?Iq=OUY%7skMi7p^-!}yW>~{eJd$7zUm)Uhm#H^{u48Rc&l6AI#2NFnh1_6MVTu;yqgev3irHvve(}I5&DJ>;p?uaOR?!F~%^4eWEY{OlrYY&M0iif_~%mMeu3@Y^uxbB<xa9X-P0z%;QoV0`BgBIs7zDgFCsUh7bM~8r`NuD92XF<lL3`LhpK#G&e1QiE(M8omAytWUkSu*CQdpJ{gAOx(FBiaw#hn)BUF7I-)*0VV<9qt51QJOx4O)jrUbtg;&?0Lo=DM;}2w9C3#m`XjD=_1b6WmvJ=5cc?Wx<K<oW1_-TlrL|JXapM^#QfnZ0e&kY@2F@52-IZLD2iXC+>sO2Qo7(-fbLH~8d}9F9RqnA2ibhSVN1B}u)VVre7S;SB|+kZ?kFxzncW4~LK_31KLMhCZclLb)>65!Q!F?67#K_1`lQ-G`b}1i4mlk`PXOX60EdRSNMVtn(>x_G6hR_jT%g$tU{>syt`a2bW84|*3Kdfsw;h}ls9~_EnhjRSoXs~toPZu)!+`MIOQ*B!@=9D_U}QW8mq@OIe_);U6>SN&Gyy8XKoLmB_^S)W;=g$Wj9#L=ZC<od+G#T~WB1u@BUERsX|`-RD49FW#Ia}7<)Y81Z5n&Y8nN4Yo3y5b@6Y$|!-z`xwg@If4&YW-cLn_r%w_wpr5T8R72-}W-^Kec9r~W52NE+GITAiBb1w`Gl{c&lEs8S){ED*|BrjqlQ4J5}o0c)sQqr_vjK<`5^ew$ZlbY>L8^A7+JXk*i2ke0VQ+yTCU(z2mh`?T<68~xy^LzHBxPrfJbW;P!;qRDS)@I9OQZ%r<F}5KihXsh+q+>{R{zldBsA2D!{^V>R$9j5pHQQ`sYqDPkk3~#mWcK0}Wvbvz{pJb?WefI0fUTjSf;`l`+0=AK)(LV;O5Ldy-qcocjI}J$L_rSKQE+xxbd@h-E2H_8wr|OB-AARSBE1Psr^Y&l=vHu?D)$1kQ*_V=3uK^<9tb(9Kk)>jErjejGx!FHkv|dSj$;|eKbE7@qj2CkCrN$dmn6^q-9ewkgW^girMt0GiW-L^3uIgh7V)MDEDioZ_2Xm+1PG7+&3d(24`<mt!^aV?bZ8h2AX0NuT0201Ap=!IFBj49BK7}=@(v)H+{AV)JvlU7Rf)VJZ8yse-wE?SXN$0VwTgK7^i;qTgQ)8REE1gP(m(a8g09nNEpHu}p>#vuu|yWpP$3^w56DV&d3nz|uTl}xevNS(jQve5e3$NPd35oAEchRYLje`2#d`Biz);2`uMD2+r-W?yOP7=<>QU}|xrSG%soK#)a>PWO7OAfj!G#&b<CPik_Q}R^Lm+})3EZ)i5Mw9WBVp_0L`8NSqYJgH$P<UcA%>AkP#z(cm9SgTvSdba@*d|Ruy84XKo0h(((@=Z{HOy5_U$4N@=0I}I#Q3VH)L5Jl6_j5>zB5=b0(U?B3Ph_Uj(so>j9H@u>!-PRIFoSHQK79l(%?BMh<e>K1is~CNLOVmj9(z*#;cfIzMPR&seNJfb@yyH>pQSQ-*khPg|+El)L!lfV`9An7dNcH85cwOG<aBnGSRZv^ZOLvc>h1MbHjcXQ2It9Er~Z3FKPT956%fRK6?$r9x5{m(F%-2+#H3_+bC7e6j;|K%~!B@o(<d08SHdNyz{|xl|xiDj>EiD$r*u3xI;{EXThd9DW)8<?Hd+<Kc(X_kTS-|1v!N^yT=|m*M$-NY-AdCzHXd@-uKh6LC1Q!~tE+9ZH}(fQxq&)MdgzOw8)4G}9H}P}*{t8G2LZXjWJLjFG7^1zC@lj+gnw@-+7qMm3ktkY62q-@pGm_ZXRW`r63A=U>$WgfYuboGL0;v!dzwv#V>F=jYAMpIT{Ct*UPMPP6KqPZ9;b?(-xG3l2Y=T^t{U&bKX_CUA=Qi|u|X#;_NB6}NnWtvX3_^GWw0_fL@tW&={ARE=~(B&y}<B@k$%<C&yu;6I938ka}aV(Zt~C)utsg`n|t8x8O~B(d3}%~xijjF_+z-q&JLD`h=aAdE_TvqJJIdlL@AI9oBQ{lfeU%uim>!-^&Bb9aT5rYSLd&-7hBmJr1dZxedryX$Bp=gXV=284VsZ~TfvySLLPIJt$0kv{9;?G1$uC8!jy+b>vww-zi^f<hdcu$AUmWrE8jplsdRkWR#K3l;XmAC!n#G^8g8CQw7fm?m3teVGSqbO^g18J6g02xCY=^Ka76pxIX1{<o-nb{@BgS8V>a-w)U=o{DU4wGwZH+6dYBU4>&scjWV*GIX*vWy}0nJrKGNyC&R=b1wp!^h$SCz~HHp-mZuWJPu>an`xbj&cb{!_8?VTs1P$y#4_Ta)=@o%X~P(NMAM)jT==j;1?B;CRP?nIvb>Z3GQ!L4f|R%9kM$6a7;OO6uNk`03_JoeCM4WpOpU=Ru~x6Tg_KcucDSS1gn{ey)ES-HwOdL*^MY5HSzJI0xGDfsnH`NRFGt!OlprjFh@1sLO^!~r3w`|xXQe)T0?H6ZF5?PJ`f7uU7Hfm~2<&8T4NK;c?WWX~d3Qa(pioJ4j>*@V4C8XO`I(|{tV%w-ceQ5~OJfeG#FN#dd9z}7Ry~)40)+5+f`DDexy#k|>imyAjo-Ri)-U9JhTi~=qKQ~LfM;Gm3)?teoRU!+Fn_+r&WI;BD#?esMAe90nL%{`^>tsp;JVI2mRLO=ja61V0s>Z2aS__kwLwP9k8f33K_*P46fAZfv7QJQo$ER2s5`bII_BrV8v*{Oc?(t}ur&>U`c<@oR`-9}+ueWh(@)Q}PY=<cz?*V`D(XS0y<IIv0cd->KWFa)iq6`9_Qu!N_8H3uRh6yz;@FhUJ9t^LkuO|J(C)i<@osO|M&H<)B7!giB}I{4lHPr}$%DhsUkevPX0yPQDB$=}1$OR>o<4pcf*I{K*@>Ct8pQA#F3FCSejKtfs8g96pAae+Am@Q|lQ8kkCY$t(_8y<wNRAq&VIoch=h7=zVJmIZho*a|K^;S0233;ceci5FzUQU%ikm3pcN~fPlr8JlR-wlSnIUNmyE&YdbF`jFMYPC-P5(4N>(C^<9^TGpjoXNsT09uw9c<bnzHP&aJ3;ge<yA+jgpP4QJ|Q~m!VxO6gF8poKp8^I%9(tHm@O@sXpbvaM3Va&8e>-DjHEbu&%reCzSxY4yJDTry|3IY6}Y3NkT)&La`5@^RP|~Yk{e&q92+4U&^pOv0_4Ex#gd?emOuc;85|c>I(UC{;xHO|5{Lh>`{K6yAG`bfr~Mzd;eV_*AdI0f)JViVBie12z1I+Z=(sFqOFVtmS{IU|t^qjWpY~~~i1!u{5@p%Rlo=}|<VKwVLtHK40TA%sTQFlLH_9X4;kE+f4|&wmwr7DNl0(#RhCgVoK?%S2-(;()ZZ#59T8;nNCB4YM`g^UH1OE96{&_xV_S*wilx!1*{J<kaSxg8LiPvJQ=H9F|XeSsw*%su&Y@`r#O+Z_!;!dG%*(tif6Yn}Jn00_7nrFvU-xb{iHAsNN(3=kM3>{O|m`)w-d#&=4R>@Jrm$jhseXH)dMs4$S#j6~Zs(wMuC$;RIT14*)YazoGg;F!?vQfA;vf9taO6G9^@Imb+15Y*2PHTF=$!HAoUPRwRi8QA}+n8`Hup<Fqw{Q$S5158DEX0{+WarfNCK!2((M5pWN4QO+kx+omVhAG1)iQ4^qC8sSreCo!era%zVY^ZkRNWILm|5MiT2A(<{NqPiR=29~6Os<4#YDKoR+uIwybGf*HEx}PtSJh7QD_VthAemi1dF0G=ZJX;hH}HQabO&8_4(k-FFz8O?Zh)<h_g-V;g0wBG_BDX6R(c~18~a`pQ_6mRRT?Q6zqgI>Z|V+Zp6MiSq(Jm3aK5xrlWZ9pS#Q5{e6Ztw?jv3se24H%^nHZn3MuGl#R7{R^m9Rj9w6?8iBar`M_#Fy4*Z^W-)C<ECq0d-2^4!>5_u97Dd=y6prlKU6Oo?v+j=Wcieaj3N661*9H~1VS&1pP*c!Iq7iQ-LA%>H>EoCV6nO`|J6sI^6{Y3TampxZjLrbf@a|<ud9*^V1G>CzMvYN)*KArtBAFHdl-M#Wxn1rP0I4sz&jE4Qc6~&qS|>TMIV|Pj;>c@T&Ox7;B7a}Md>Pc25=5+iP^1*hLnR_C-iCcy{wcXM!Y=04z-j+eq$mv@D(6Chl2G8E&EEBcEv)+CBlWFA@s`d+9;|Q4<LEZX!oa`R%n~heVW+d?lK9%idYJL5FT;BV!W53|g2O2;ix~M$90OGtL~mqh^c+wu{Qm1*{4d&F?(M&#pG`4+VdfEA5!Xmd7#aXgr`NC|(}`LyH>Qr}#i4bRcTz&e?G(ALzLc^!HNRl#4N{FNW>6v7)AQxV&wzpgP165HwC&r#GT~El`C!DgP_{FSbTOH#a5HYt+@$};OI2m+-BQ^*uY20GN<NLox$)=pj>3APFTgVJufL+IkAF%ep-Fc|{>(&Jrjwz12R3HOD4j*Ri%lposw?p{yiV9thE7J<)pR-`4}&RYd|K@aepFQ5ztl*0a)e4Fn8T7YD3JOBSul*RT4MAn*NcF@AbxU;KVd4J*j|i%m7Mo@eYTSG=>$#^=9h7)9yo5OQ1!5(L`T#I%nTD(8Ep>MgLiNC-tM#7rtY|L<K;<%2Jm3Gt9ehfu0&yOD-`CICAI0Yp19n?*(AZk3paQ;F^Jpce-(eb+#QR?iqfIUTIHg*S5#iNh`zYxWeari?>%}j8I~j0JRL^mP*zLI+R2f?_J6X}luos{%wI}_Y+jUoadzSDfXM6<yE~c`lvio}dq^e{i65k(eX;JK*TSde`UIDdgL`#r=p+|STUtio$3<d%F<XN2e6ft<xAjdpfpv!K{~ppl4ZFNuG4uvU`Tbj0^U5u0bynE~P6>~8tRyXA!hS#K5f2AKvi`crZY4+@|KI|W=VzBJ6`>C8Xp?7)%afxIu;)WF;OM8H8s7n*VLCVI<jnFr^6P%vTI1Zl-#71-4#8F@yQ&f?m=QcyX|MI~e~1j*cEz#0!CBrSiY-QZk|gnWI(oxF*KsW5Vtt0d;J!B+)fS^>Y$<4K(bY-N9tD)7a!ET|r*qhz(A2g<qmffcAQ|gGc)5{B$|VVBOW@h!BE&YycpfNBC8(_AyJO$M^1@*n4J^6s^WzOTi|k;n#tn@6i-FA*#k79ZMn1C9Y$fue=|vYLHC41^YvffiF$jQ?44f|31}vx9cd_^TZEgLhX$x?+LA;CMyQ!7Yi2lmLRAxTFdis{BKUQ=3Txy}p_;NNs`1FSu3p57?d&%#;gu4RM1?fKS8ryKZ%>gGc9cqjS&XC?oJTxc#q~A6^o7*le-jBvvo9wP(cQ|BC{BYQCUN_q?P!QOMshY_fPU{g{r<p_!ho;(a*aULpr1|7>-y9w3%`(Td3&!9rIt}+ZS;4H*&uLx&A;XtMphJyWIlRhd6H^|S^eQR5-tO-u58fxLaJG^>c$g%Y^~a*ebI$ZOfHasSfYXbP#8t9FJ3uQM`3cO^_0<xN)-9>)Xdc7WX1*fUEL!mdgiqtdHp|6=v$fD8_j5KvUt*B|?j`$;ZO8tU)M3)3{OgoI+pNb+<oWs%G>_^YNg^d!;xSQoMdw?ZFVa~jhkdY|lRgbucaND;hJl-;lguWjTE%q-TF;&it49wvZkNGO*p|gKB)X=a1)aPhoeM4|Mk6-D-_rS}+v#+~ieR+RQmewim@hc$uji*IfRr1F41EsxjgE#y5a9f5BgkSO%w|V2i(S{Kf{gXv{u|@;V7y($V3kssm@<`^f0YspAk-+A!Gz2y!EJo}rHx6JaXl87jY<30j~|ZGVhp{Js7yAq3;x)wL9YI05Kkn<t8y^k!wu!t+(e`V2)h%~ULkjZfsfZI=?rJkSymj-iv}ey(|x&izMIXurZTtl88&AJiK@>}r-$ghz7A>(QfSr4LF$G5eBX3K127zyhG}DPVG8P1g2`uXm?SGRwwLsyTVw?sF{kIIszt<<<W9W3(X3C{iCG)se%RR*d1nM<g7IU#o{@QDc@t96C~To`!-r)uxuD<#d2woN@g$4VyF<2QsXqk0`v`;kY>V&$a7%;UZR}EQ)yXnZ3(;JFKj6>-LP<#`B8PW;_R^Kk2++5FxT4Vv+@cgd0jkPEKf;k;VJyYKdgzG-)JjbPxPTqR6s{yJ-Knq?tFUy3OXarfsZpMk;e`*Pn&Tn9EhpZ&b<-ol%I9~yylhuvS4LXqJgztv_vXCq6)%j3NRtC3*eTX?S)DTzX3+p?4ZyZFr3}eJn}4i2+KzySa=yFRfh8pLg_Am~vGzL;wrfUBmQZq`vPemvU9S{1yaI1Fw-pY>u7P>epM@ZYJB_mIZkPVi%vJ8`<<jG>`=KE=jTTR^#j|Kh|H4eSR(U$1Anq_ShEjvc0uOJKvGU5DlLI+#>mle|u<9Pf_q(Czufbz;JZso#UY&t;13>MLCOhV10cXBsGiH01-omsCIF#``o)%j4Srx3t(?~iN4<yN?j7ReZ)zuv3DFFb)Wj=th|E`5$);+Quy{?Pl>gk_*yG%T?crGBV08>ntCIK>QVGJeN`FE{$9r~)@v_xRsEDWrj@%d|tYOfN?M1U}4$}r}7(pvO&H)*+nfPfb;m@O|6Z4BZ$gy9c{Fo;@BxvxqW$Z4tJ&T2`^#UA0!SjpKBH?GMDo@M4<5`bECRX9?#zQhP)*UUybnI~(_z|a$A<sLLkVFQ)fVllNTYZguFM;xoL6=7gUn+Yxw(fgc9eMIp9Oz<&WMwsLW_M>r`Q@a*aGl{&7PF-F~HnoP?zO>^py6LYU19qxwQYI_*;aqg7xz3`N3s<qYfgWVArEk%CK(227LvfR=<PEx-rRz5S(@rU84RQ#Y9i&a_n8H3IN)^C@iGhJe)i=GNH2i{X2Yd8S$bRNr${C3yJvT0T&6;v%kOLvEvI7(@FAhI{ee-kn9?R`A(~bFzVImEL3Y)sF$*R)S^wz}m;aBA`qOfVwoP{k?y>^pm6l=nJqq%K`7%ZmI4mk?zXv%xG*A#6f<`2H@UbmA8Z};1#o1XMqDH4s(fm;pm2Vx6y9RX$TObo39U=RH%A3#aLzy`Tpnq{iR9RM<~nY(sU(OJ1Ib#XPH@4L(CS2c^dt?ylOMi%c14yF#U1zK3*Q-M~*eReZoH*XFi#%%;=1#K>*gl4A=H1CDfjT?QujDfbZ7sT49R|6730*PUkVu=2nVxdfF4-UVa{`ENQnj_n+sk>3=XbD%#)n-OXWp)w6N+o5B4bZ;FVwH7*wa2zMh`by&cyadi{P1}A`NP5C@kfk&`*il{@VHAUWiElw$5RcOYLqGhjdM?NA%Yy{Bt$U1bQ}hqGX*}_fGGb&0l_|bRIo??Ag2X6JJw?AO{7Kth<Wv57ZYwz^R&3K&TD@;{`ghKOxzUp(-A+<S|*)SM8vf;n_uA2Bo0hYNqerLPe0bj%zs;sJ1+2y^6qPlF$<H7R(R_H2-u16VI(h_^Nc$TTO`!-?GlCF9#Zu2PaD&R+-i~Lv%NvZ^_B3hMbfU@L?gVUFj<<j@0Po$X`kIBo|*e9kX-772<+GyXDQcHH1MuBaIU%0C2ay&(%ZD=;sbk+jm=M7%Bv4>HS3A`7>dv6U6mch01@Ne`b^jpO@+O9#yKvO>wXtMfBy32ix<!Lqmbst8s6voAG7!9%&4S)RL+Q9cS{hR^8Qss?7F)B-l5X9L**o`lcs^Z@=Y{K03~LMx8Ya9F4WxoAxSEk#tcQV0*9FFZ}H=j{cV;DHlvfNmsm4WkKDo0rXI$Q2=DD`qZM>JB)UTFxRm7~_f<lLGV?Xs6rI&L6CEs^g&p;T)x)0XEZU#3*+wG-Iy)gPvHWO8s$Rk{l~m$2P?SjuVtMFad}ADtho%kl>aVsjTg)_TUL8sMa;X4waWuj$Ct})%kq^wtuU^&)7FJOijI&6oqT>k2JZbA(6FT)8(k)~|5m4yhCqC^7H76LXk#i+VmxC_b9Ir@RiLkJ`bY|3)QizxrtQFYHeMrfH{s@x80Dq3rkt5#i6~O3&YzMzEcK|8HRc<^v;%CmPG2v9irK?Qno}A3nY6JIScm>1u;o*%RIf+nK!2ZOmdAfLLW(&@f8$4|UI^<{Zo~W4lnY{_h+OLV;Bj$Tj1a=zSuavTG9&}lej=0Irj;Ld9G??C^`-YvUqivqDy7|@fH!rG#IXMb&xH1GMUG7wL%$Uprm&VMFp5Dd#ulDy|I1O?p97;G@YLg~b<JqAXx;$W@_f~_ma8o<PU?36bAZB&;02}QSr7me=rYkDzr=>HcRK={K0Q{$`iaB!JC6}A1U{!=XMx4i(72{Rs3@AvY@3rBlD^zHE0VF3@vBfzw?Qj%mh8MEjnHiwUp!fo~g@V%i5F<7CiQUh%vgN+)8_R^vW)1Til?B+~b{=oVk88e0k$3}hsTLk&0^b00QU*LpMD-3*KgvCjEymd@DHAx8JfJchI!~TFpiS+td|>!Irz06SV-Ed8)9z3Q{sbz`Rassf3+q5Au)8PXSn-HRXC2V67Hl%_C{{=jZB<)N1#6x*aDdW$l<{3(E!@huOg7ECs@+_Noyy*gK65W0mdkIO)v+3`%^+|C$lQ!Kt3S(0R^T*}oZ@3MlMc8i`E4YJkf9GkMLuJyrUIiFn1)C#1xbmF?zrR8lsbg_i#xPxxE6nh-Wat4fxGEsa&-7)La{wuDc1jJ`$Z3S77*$MDl^B>DzG`5bxPwXa8<MPCY`9u>&}l85OcD$G|3>UVdYo~yYhoFABSC{=Vo&PS;HBb^g^M+@BWD<7aJlEXmW`+Uf7eNh0EIloU%usCcN(csI$VoQ6-)yHwWxYMW`!pKk|G|j;!AK<mmBfMvs6ApiPzzT;Q-v1n6FDNeFslU{W~jxCi^wm+|EE{NhW?U(7JlMjuR6Z_-J3wKxcUChvB|eF8n^9LSs6+n{d?xc3ln<d{ij>)Otq#^|q}#^r0+iC9Q90?0(IYO`VU{|k9w^(0|HQuCDO_``C*s#XZl_D|0~8k&WPYKZBNA8XLa2HDhoGz&x?QgRmq4^bM1*%<-zh-(c<fvAlPm+&XgFdEbak5}<biwsyCG3P2b(a|P2GOq}1M%t2MUrBqYKFCG<ot)1}00MYK_KC~gyTS{fScN0U>^xl@d7?C8sL1rGe80o?W1zjt9dI5w_wYJlEXwdd$nUd~R{4ClA?EXa7QeakBMd(B_oS=mB|u%<6WDhFzV%<Rce|Q%UO4tL!+!5l(uYU)d$|k4T*xqu7lk=+D*5{zCdg#flr+6+vSR&?@r;r?lHI5P>qshcgd~#giAx6yvff=OM*mjv6KaoVz=t(FUZm_p#mGbcSmt}L<ld%zlY<n`ftWb`Ot6wN6#1jhRu3h{cE@BK<Em$?{pP^Nw%4-lJ<R3!*9Ni4x*qWK&A=URG*(Nv_<MSG@W?pZbma#n0iug0x~>x_U+8jQ<K<_v#fZh=iOj}!XhhnQxeUlOQNA`tm@Ey{jh3r|{T=0kG!vJyHTPnVs;Fxw*>&KJpLrBs^t3^BCWUv%_3<@qa#fSLC(*AiFMD#;TJ;912RBm5eLFI-&Q7uj&JoJ!EUTxUox(SfE1zsNJ+omd8+4N-q!-<vq_dX|0L@M|V-h~mB{POex5<~Y*&`;DUa%*on)pdLHimk!fg6{8Yi<`mOKL%VE=?#-f8ux@@<+OIPTlXEh;P>tfmPJ+u2O`J4_>NY6O^;ZvghSyxhYiHBl#2Lp5Wh+xl)tsx)*gFemy@&n^|2V$)mH62dAHg=X>Pu$p)mZBDN+G>~g+HvoI_SM3QSlTo1Z6IAXQ`b$9;B8+$CcA2|zwcv6L*U>cv#k3S!rAERdpo35mcDC6bH<moHDpm;RrHHWIpgR`F9+C}!AKKVvVb?8JL8s{El2iRlBqg6fv!*+(3e;?V~zz^N)4S_Kw>v%y|6YLm9sq7}jcZ2VEngvy%fY1#ah$;AT>LZl7%7B4kj}nJ;7;-16f0Hq?P=`Wn2C)=vl-7a(=>IX<gG)_FPD@w>)Y8dGY_k8BQm%5Ai*1?IG2bd?Tm7+QtJYcRzcbBh>B0k|O{E;GoLiOVb(NP>j#N{tR`bNy<sErElWHlEswB{ON(xmsWh&bb@+kL)T~3#pr<Y!?6diK;cG|q;?NrT=N*1{PLMjc@MtPy^q~sck4qLO0)iDqURjMudSw&2zs;HKAsFb)+MC!HH)THw&<tB!!D<OZ~wGFj7NpOeIGj9|7)7vX76Y|#xnC;lfeB;#i(%&G9(q`{q&oNjUM8NQA&*WFPbKv>$suRhMquO@PK+Sf~kCev#!K1cR_Q5l^R95`?2P%>{pB&0w>47Lbg>9iWg7f3&$)X^QF?|*5uRXaLG*u6aQV!#JGQPsQOx-)c|Ni&Z;Mw2XTuuD)yzOUfrBqj(Ei|1N{a22Ya3+Hx2?Hk~cx~3K-dwU}HNrVColr38d=H;}x_B1eo22JFp?M{&L_9z#2_U(lR#_CM7`!YO(lk0!f>Xpax8&o&obA_cl0P}?blicA!$m%x8>v??PYmyJCncZLm6PJn0A6}<Dk%EnZV|sC$EC<RJeTgS&;S!j^oiaiI#7EDam^ubJ*b#gCAb3qS>FqYuiC6SYY=27bWcSxPR&h&S9Cp};^bv*K4{O$!Cu0*6hkf<yk#I216I|Izw4#u7YNke+M&C%d}D{E{Rv9<bZGV?gubhj74WOg6(PEPC02Qg*$QmF=<1q~2*R$jN+ez1Swr{g*eMyrBU}|XCzKX3h)FgP=BM#f-(A)>Tgh?ui<?P_-kj5sOz(2H6cmBKULj<LFC)FxQ5vErCwr`Xzc5*vq<~4=G;mr7yABTkClL^)rrUsA;BoI*&mPWKt=Xy{OIA&6Rk>s}MK!T8Fd{c|C~<1M-^dGzcSv$$(m(f-OW0XMUNQd7M=k$;>VeCmtgVh=TZvriXIqNlk995Q5<Dy?<C&8$yPU_I_ojorG5w8%j`2T{m+ibHLB*Pe4xfiBV0xO&TJU%u$}!zlJwfWF7oy9FSL(|3pk7MV$kLDr3U(Tn4R5p%sw(oLi&0_ukV4B3Nw3#`NJw+MExMUvm(jQ?Uv0E=b#Q8#!prVBT|MQ4NM@n6Ns->)s7aP6PzEPQh1_9;1{}Gdt}8!K=j&K0YgKIWvguyKYljy-qQ~=eayE50>#4kNc$f42j(hbu6%yvl-aBsSCL%;tZ)Yzr)N6ztOQDY!jzCNAYy_PCklW|w`wr_7)ugynx#a#~@K-LlFZCj7R3YWs4lK7h3w*83`SAhyjt)<bKps6g{&M>97$ngb=t%y^qLk2}vP@>L>8pEt-%mvoQ*(K}9!FcX8hQb{Vfa}b<GWs)&-UKMd%G{*ynOx2-f>#rcT03c@Ah80DJhL=kJ33#*aqVyJhOTDD-Iy5Y$6vQo&yOl%w2|LFH+XAhg=oL>8E*zm6K=*!uwN~dG=3^cFSP2SvtX3c=tNnY~m(AhQ~j-mtW$sL19fj*CfZbGIS22`aQ?R7>iXsiJz3JPfgVcXDVXjv}xF;>2n)?Ff$)}v8m~V?mG&@dN1S%GY&P;OW|2Oa`K2JH`P#Cgo!Qy*@#0oumrx=`up0vhDprFJ|2Bxvpq>UCbyl7Pj?f;Z2QK?8|e0YB30m*AP!dE6i!Q<!fC5FzSJ6GP`2HO4ZF9A`y3X7O5_>k?x1GM36N%<neS^h={i^1&UBFdz3yPpTVHac&g;RCwg2UkI`A~m8<UxhWbsQQhmSA4y1U)3+-)2FeSsmn*y;F^y#8z)KS<`mZyVgD>&};--DuBibti;B>ZwM?%A~*d7WuxFF<&M)v4|b`FdU!!*t+XW;17)hTX%fff8HI4Ut70NzT>hCw-$u3rm*z1D5LQ2yO{HdV8;&_Ap<2iE{0UCqaQ^d_GcL39HJ498~8?=QAD#~`N_ksIL0pVLm5T3;M;!zXX1DhI78Tmt}rB7NE=du%h8cRV|<CMr0WD{qrGZ9@R8uK+t84yr@e;5&jqp*=yPM1%tw<X_$leCJ<BoUS$mcy{4h5yT0d$N-_1HGAq(V_0QB{#J_)F2f50c9)>DAJo+Yydy9)p~{hSu+(6HUpS$l3eCi*9O8M-6HxGD5*<S3gz#O8Jow~&Dq6zv)IiWjQ|2keA&L%u_<-fP9yx2-O?Vuj;<E*`Y{L^2G2r%kV)SJnZSzw+SaD?d12ZHN+m*GCb^90y>G@KgU^-#WObi67;)iO7=CIfLU*>NG@%hjFWx4Pme`a{&7Vn`RP-1D8!Twy^+Dc1bl|dA_K`-38)7Oe<sV9aSlUCP8;>Ze3a4o^%6=<0t8PMgj?zANP)rjdMk*xtwp2I?y0(9EUk`ua+OPmxDfb0a4}lAv1C}sJ=YTs5FzBOM-YvLsE<59~4|!$wI#{gKNZP>T(wm!+1=S&hg?h<o&Ug09lwk$kqkkORykU*6bQZa2Ahya%<}N3OeYFuRv<(+~hzl@XqYh39+82ePWgprOYf(NvFrTiCj16WFbNa0Gw`ZMGQIq6?vx-v=^Kf#fJTd7noUkVw)o(>R+cQ=&CDKXn!Xk&JO?FIXQy%j$z<;hF~yjhBSGS;!2~!jHv|O>djsgs{b+>D)gr7-%IT=AM|wMN2Xw!C~;n(y8^bS_!JhHr-or?9OQme*c?N6)|F0(4#Ku52l6@xGDqNWz&gIt^H+#4Ii%6o=DRn6`ehct8~h;-3BI9y`5a&V?fmr1ap=+MdGZe+`SWZ+QDjTG_NV`HU^8t>f1G=PitoK@M)XA0^a&o&{}BO2#Q+e%1)$4j69oV&?7rilSgY%%#dMs_WH2v~Wn;C4nPMbLO7rUZ;ND>zut9S|laB)d-t0r0bbaCoLHO=>3PHU|VIwRjEWx-DoQ(fuEen589KzOmMJaw04tX@%Yb+*+L9e4-ih(5yf?fwf{>AvK<Bg!H*F<zxS~Aw#ZrM;;x=zx~qAFpQ=r~1yT`X@T-V$)KX9C70x1h6ua7qrz*OHpTOC>f-^I6@f<=o54P~DW$X<#+OmfSi?{mT&XW@5&FFI5h;tFCqmhtX;|zB*)E!TWT5lctN$sNXD{`hSQW9J6t(k%0dLK%Yj#%jCZPh`GI~q4ve_^yAslaieHU&Tq8n5^*_Un$cBK)6^EiF8_O9b0}k-hjRMZOMz-IC64tJ(>-G>Dzx6R;Oss^_{jl4I*|+5K7bBpCismXfl-QM{&|T%4aelcz^RHkwO{Y<mcw`Hf=4+H^|+z&?LuLV^cNON)wtGD#FN;vXc?ZIVnz3k-THp40SM!&O!E|2Rog=)-!-Xl*5zBp^sJX%0PENbIAI>DrRJzN>x}U)kn_7By<X0)Q+tV}Pz1A%9*i%}kAH6Xt78|ZZf)?@0zHvcn5Q>55KUc!v<WpfWMG9xdG0kxtpzx<`YXz+{_4dG{QK&KiP9FpQ{Dyxc3??nX$yxDs8qxY%t*^?&Ye?h?t+)sz)h^LBRv7E{g+_dF4SjmGZR*a4<$qxUjgezUhIII%mh?%&_)=@M(q2W9OVli2Z<9DTdc>oVVdmmVm)h5iSL91fgh0x7#{!nFX!pgdm|}Q=Z2C%Z*ufHNhTv>E+Brwp1Q(I-0J{|Ii#@_D5an^*yZ#jctm9R?PLA=sd`g8gRLr9>3b2S^pT}0H%`zi*wm6<k};trKDX+qEJ)DuQ&ByzY63^E-={!Qtp7YD83Tb6WSQBfK)J_(CNvv+U1)sHkTgD&S?Bq_xaK5rt%kZsm}*$BM-z?|HUw0mac`XbRzxYfBVbCtS>M4#rSCtP%vSvThnVzrvVYlQNha-FK!c5%Dh4NL*!|Ytz%2is<MnU&2RR|Ctx}F@j`?soa?Y^f<IA(Kvo#)snyE&DOMfRd8XANx)}p{ItZlQpgV=&^+I)!aJUz$*cyq&6J6tv1Ic(k<RvRgjWwocmX;a4%)=}Z_)=ej&98MeCFv?tfAip2?&Kb)yxW}n6PmuoyBfCn9Er)=g99dv3XXGeN3*ObVI2Bw*6ThsNd#1wcd$DAfa6m0G%ocUnuvJl>JWM)R5obhQ?Sa%Mz_iXVPjg|<;hIb&PI?l)n8y<nEdL)(m$TXOMw6TsoF&25Cmb&GX-&hA)vt$5l;R04&03aD85r25eCpTp^l@z2Wuo?k9v$K<sR0st#gV|dpSM>&i?&f$WrUd!aw-fT;-Wt;HnVm7{imOt42in^yM#=5``2vpfzYi8X<uLjqXhSoL-l>HmX)T7p{*YKa1yrQ<Bwl_tpn6-sgAz_Mu|*36LTpK4TcSDD<MKCUtq;*j7RktW}DC|sp;7bLj~y8=g5k~@#Jkf-F>tF>NzlRyKg7S{+rj+SJUU|^Ec0T$8TSTy-Ll`r=LjY5(NJv`1<Me;^OP^Q8(bcRAdibq&F@0KFrf`nyuEVY?`RX>u7(U)NhjQe5j^XWGq-WMn6EXHzophM4?#f2&MBO+uxmNnoVkr<Ohdez8-uS{_X7i&!?Y$9{zIt;b{2j;N$Vp@Z<59gQJ5l2Yf_cvh)URYS;kxBVs2F!DMy)oG;h>1BF2|GP<A_hWrc2;OH7PUv1#^FDcsK#etvGWSHwp*kewk@Ayft91&m6^%{9+a`}(=CJ*^7_7-kgGK6D-&`qAo4LFh<pCHoLx&wQBIJdFO9UKouoYM^-)qB_JE&FBEMWy$<FZcFIxns=C+}Cu`RHq)<g40Fg3BhJHGwgY}{wYdI(ZbtYS{En2XsHgTrRtl|K__+-DQ!-@Ki%B$BsRg5;m^lkPCkSYt1Xp5#=n+9mO@Q(t;IG>A_Z<lLquCh%35%SYHJVP{X_SCPUyl^MgT${RX&zekX3J>gSt=DXEnW$ThU-yGydyl*?w<s6Os@WDZ3|R3f0m)6fD>|K09%;XC*gkiVQdFY3mK`QM73Il89&LH)|tTkO^GnG2(yail!y-f_S_cPWy!_eSvbwN06lW2Ol->#hFH0#pBS#y~#?|un5fx76m2%oX)f>^iw5Y^scq?w)BI8o8>+%#{rORV}>2&I1Js~!ge${kNxB`Q8w<C7=;$!L0j%g?o33b8`ec&9Iz*m3kz|9`+cCe*G*x_ogq_rla8c&T;BBEr5IH1fiD+`V|wL*SzlTZ=o>q+fznK&vFxbS6VWJ}2Bj_R5()3qdro>sDfUWrY*zS+0~D2PTEWCfM!IkGl-zsu=j?rCIWf%0PrTHsu$zfmlbej`@EukTTPk8tShNf!c+I?EOxF+3#Hp6f6oh^WWagE4`#bQ6c7;4RQxk?>XGnaft{X9+!gY!<=`vly=t&s7$>Iv~ux#lpC=(~2dY90r^z}c9_#GS`qS~uTH)<-Cv;^#OljJNzF{8!4^IFbP;>~7_n~XGx3gs<|L?i$x^AW|Pi~S<K6f)9FAn6Bb@%SgI@4}Ma78Qfgqt%YlXL%#K7<uw8JC%3b`aq>bc}pF^%f_3%{oTFS`!8R-z};Z*g*Wv6-iy~S-T)i<hHh7EuuG5@!MrC11RAh~srcU}$?i1SpG;ouy_u$?>HeGKWxAideDi#=m+p^VCU3^c^C@)va+JP(^>PAVUcB1fPsVRw?N49qqE&>{e5`)~*3%#pUUenr*cNR1EP>$wOgf50kx@0ANE%PF71%9wlReEKUAnV}@zOCePm(bZ=;17zrgX=|*!Xs{cX<&>@Qkpx9I7Ev<7(k{?lYXFcpIvF)i7RcEsvt1iptks*cX_eb(URTt-W^=y&Hw3#~vm{kzFq4823aMOya<YoK!sGG^&8Evvp#grdd9}fg@;0O2v>5jNw&=Lde}P=Wr2VHE)(fx=Tm1@`jG~e3%u*28!J~K9d3(^qa&BG6*l_T{%ee@a)r<<6plF-=BT`bTm9VI7IK*!-LOXzMdb4UOjV{_xLIIdYftzgcN(%i&Ws%Y|9l*!}K;CZxCaKP!pD2=TaZnWV*4ThcG-0#NzA1^|n+~jw6)L5g*t+1b_Je;vzri$?EEnXvi(CR)QlP80Pb22Bcwf0sGpvZl+c^uhlNVjqmMum|MX+5@1&p>yB(i4q)$C2~t2AnD8<X^(tbXM&zovCrhu6(G^jz_R2u*p{twG+{GnyE9}B@$U7VMb!de@BfL!{HOg6zF3@>#m974kP--6)2*-TW0#HWMW1wKinY7%HbA7VnpU8XkLS-S4^nP5*dq~22P`Yy@JI;|Ak%JR?D-tc!n*c3it->#PC3W$y!tNLJ=k2=Di=X%^Y7vRINz3=Hr}6SeqgQOBwF!is9?ExXkNY?*R9nHZJTSVrX2drPKPcHnPr0ns71)@mHQfRAQlt{CKT+_wxGUOlhHo&OhIpwGg*T3MoJ7@)1eK)Q>3Bw=Yf^;W)Mq%zyMV7M2}XAT?_;ww`3t#c5x>kSSPl+9z(~2FHas+%G$z(oZI8!cM0K#eMd~R`eP;zx3X!|+m-a+S63C|JMk-%4H}~kO3kBcW#f80lzsx;e{7EnKDmb)E-qI7@$W^__i%V2)^ZNDU2SLl;wT2lJuy8;<$C~?u0A?-tVDxgC<1qmz0wEX>*_20yd{T;Pklkep_Tn)kj+Djtz2|$oulEs^<U$VH_TK)RKT}q49<1&@_!2u3d^3U<#Q4X?T?O9ofe=69uhKL*ul;~!EZ0*Q6>zxbz({{U@`mD89}2IRQuH>Wslm?}FI~YgId0K(bAq{Mt-zgv7mqdvrghnq7ql(@>s@G`u1QvWqe~ezkec_Mck3t};pOjgxp6jQmvQGLQgStT%2wp*$u{IQZNaj%;K&Rk36nBBXL+yvhPMjKX(*{CO<6Y$rP6E}qB-Kk50jpEZC>@yr$;|SdDUs+E~3M55dY?E@U3prW(aEW`C&(C&2Nnrf9tyw8N?i7BL36H4{@0Xt_SlUVrLNYuKQcRGD8i0as#<p!(}|DE3<htg)zIWU?U`H+6Mk>34smECYe4tm#YZkDr158tLg;FOH?(`hLkg~GOuWR#y)DtDnk4b)THgB%TTD21XTalcX4g-EZ*CBC<FHjLwwYLCZ^mU&Dhr<mY0S2K_m|-$WsW2zh6s!EL`QmBHWP4<y}tzG@9HhfD!OdTM5>dt|ZjpN0h??R=S9Ot8Q4Xm484vY!<l&wXCXGXIQHVmX&v?&Y)^EU#Z2soUPpTEA(%Gw?~??qzm->_3yQ(ARv1YmA&GATiDL67q&wUcVXMPUiGEP007@?0Tg?>zj5;{jQPYcDj4sG>6(k#N`0^jO_X8Lo2I7^E2+b*c84}5>sW9!8%%nnclV4^6BjGPtB-W3pk+08cuf%|d}7--R(+phu&LQ6RWydu+#O#BZJ<RB)S#pi!c~Idzt*Qcd=f+KHQ$ov$@-Jl=!H=ytZ7H#obJFdRF@=D7w}NPl8LLE(F^Z=gm)BB;6z(olS;~FI2>|5NVRM?@C(Uw8suP<Q_L-(`lyg}#=3TNIkT{uL>)N-OD?K*vj4I8YMq(PZK5#G*%Ez*{YrBDn|}IKW8j75<5-`Ct%J{}oU9Qf3zLlK@jTs?rYV}hn~US)?p)m&{a~JMm7B|8@gGS~%CX=!?||5w@Lr!vK1J5iFT6~mPt37kI}k^jUcC|h>~EirkBp85;5?+%Euk;bSJfvL$3EY!ua=TS6|?AN6GAgo-BO4+A=W{Dxk3HeXT~p;$Q0k)w4f$gI`LxFgb&1BdFi}0k-?TF($Ducdfp<2z8aWNdgmLz8JKI?k40DGJz{p8^)I9fMaTHReEj^Ga@w=M3NN8LtyIvt>I2S(qV20JeTy?nIT?m<vn9N%Nr@0w_9EZ&xA;T6Ys#4X2h1#n&v^Wm1hwp9%WQ9{eM(HpNf@@=ZSSXMmqOdtQa|7CJd_HgJhw-(L(m-R6#O<ngwWRo(N{ethU4YcGG9}qenHxMF6AnaYxU>Nc6}2ZMO(hvj&#^+Rd^&s4flsp4gCxN#B|`78+dM^bcriRMw6WK9B8)n77MTe;H6D!K;3S;f6sH()nr<;WSrtA@BCvq;tXYo7kIH*otu&7p_=;YEvp?~sYgy=T1Fpl<Ca8IINIMgj!2pW6MHSC)gwNcE+tb>Jl0X0Jd>o+Om0Mv=%zEQRwW*@=XvtOcQ<tq!-f2%?AUdfe4!ad`*bdTIbf}~n;;SOAl625?O8`q9wbM~>%hu?MA9QMc5v?2&`RK;k=04?Gv-<5E<ErO;5%e$phTK#Grq1*nR)T$_~7H&#qjjg#g~H*ACAw5KOcNNzOd^Yij7vQ<6vv*pPc>*hfuk0^kZF-0pr>+`OuF*-V#jUrR!Uaw=l5pVkd`U%Q<D^9OA`;b$1o$1-o9TOBr^W&l5J<G`ozSKnirf8)y%?ZsR)Qoo`0ptlDLXWw=BO&{Mkdx?tkMeQjx3xK$VcIo6V;=_~L{`FoPl(P~V6Z~I<t_2ruvFW$a-z5n*ruC7;o)pxIU&40RvXe~RLE$Kdw`1QW|F8TUj?f(2epz%-z!zu6YLbGFvOTvWym@Es(?L1_Cm>FRA2>`@AFepgkQ4KI$q3x44wZPF?D}(vy0ZWp6jN8acYy;<$Oi(S_pE1iIY}}eEl_E-sCDrT|3cQm*T9$ke61KdOI%wXRFc+^;G2Ydd;qQ&OgjSWGo|YpSs9g#&w85Wvi>Q~ifeiH;lM7QfyUXf9h;jpSw%28qh%@r~#5PYEx|8RoJP8^tc}rvSr8(KiMVy(NX@$z6n>Tt1^{uBf-44zf4JB&H5D+dyk;%aRnl$Yiu*|WrXj3r<JV5H7K$+Ni+V4f~Nv|=L^+s{68<?cC#p%Y{gBxI&#PP@+L42*cE%smlof+?9$?j`*su(%fDSK*wjE5r<0GJF1>JLed9F1vYQ(~7wY+jfMoAUG@nEkk>u!hm#)Z=)pPOXUvN)Ur@Il4vJfLWSMeg6}nO5znIlcZp1+Lm!00qCu)zK=GA6!w{s9}Hi%p*nj558qc)!1tmIh}F~}M-j(n0B&$e1*HBUiPWzO&)-PWfKd`o$uqFRTfs0TzSNf;Li`dcpldF}UGZ(WoQ7(AwOM?#si;;{y%2Y0uDGQlSdFj9<wxDO(3qW`bGPlPbh)i5Q@!BU16nPxya`w48Hl^N_|B@^r?+Ho<hd5m+(eb|qDW&$BMlvmw#0s-CVPMP<zDpm`HQ!2BaFJ^KNNJSo>+h>`4Y#jfq6Uv*4ig>&8M1?Vq9_JZdyR*7LsLLiF*avOGvHd%qi)AAM~_=_?oq$ra>jCAJXJn5)f8dk^aD8vb8Gm+DLv)jx6)xUF?LD*(JnaC_QW)4WzjlDMNqtg*k&+HOo60zm???VNkameIB0C`q#BYz<Z+KFy8o0m0bii41+s4P4IzO5TWEneyJ_q6`CLqlL7a1^_8k@8>88G)yO4-)~E#LuiC1Am%TkbNn+y+D>(`;qY~lVjz~X9J?)lrDCY<$CpI7R;WU~?wf!;1QNc3JtS#Tv^A<nRk?R+G;MlErj#3jP-%;~UTo=r<=RfKZjB+y+&MiE;`Bri@HSd-9`?GLJts!gxP^3(h?WXwY<=*}~r_v#Dxz_Ov<+5GCfLr8zHMbzEJrsY-Oa{>@kR?`T!{LLXL`~jy`cC&HJPRZI-K_D-xl9-6m_;dqmMh86-UB()_QaR}(S>`R5y!@N@N0($(8Is%TBQ)`Hl%@$z8bQpK)sN<oKA~W((T!r^46<^hB;V}SvJoq<?RQ*ig<6zD9h4K1%ru<YFQbB!7KB@c7_^)-KZ8l^aQdnCXE(061mE(K%FXJf#;S8K$~++5M{^qZ;*24u<hqrnPHk6h6%pa?DNt%>@J^Yy2nkC-|bM|Y<fC6QC+NG1k^MVchcB%W(Jab1K$S?mCgLCM`;^8Dlqrl&}FhFal~up8ukp=pg9?qnyW#tI$P&(LgxkEY=Fa}1QF$A5ztQ8@rH9e)Bw=2`mO2t0HdGD5abJRDpA;K-G)udQdHil)NxDL7<7dr#K|TxZV1m7jP;HA*Ha|f7%aBJBL-|uB2_UD&ljk4Li;fJ<$+{=8*J}~#!Fp2*afAVGy~s7LJgA|IIdvOlL;Be2PkC9zbK)h+09|lVl)b$8JhVl48m-oZPYclkE)_a$RFbK7Lw+x+>ojkE4<hM2ST+4d-8N<1N+4Ya6y^Qzl&P1%PKYT%r+(_z0AkUL{@g=j_SRlpV)}+Fm3pjbJibmQvP(R&aXF9KT(y52m3KzWj_7E3ymvbM0C2%iJhsqq<AkQ7v7QK`_=qiHFQawXML1~d$X{gDbBxL!8NYwSXvYb($Ywfx~|<ThM#iBFpcp^_N(7{wQ%4ZDmQSbY+sO@>Hm}E5SqIU(EkQF|DIqQKan~L`dPd+;!O+ta4=F|vv*TH$8KuQu^T<eoD@jARRPj|eYM+s^q@0ge$D|$9sPm%=Pf7P&Gr-SRq2GwTdlA%$S}WYZ8`UJM0(_5_N3fs7OtlSaW^F8d2dT92ddVdDyOcG(;S()ciTCAQ!lwrvRSF#pW?>e^B4PjuV3%Ksfk8=ZdCuxz>^wo9+DcI0Yu>y2KlkXK$0WfT-~8jAS<>Ub6(EXY*SeKfy%;{aK5dtfIw*ePLqKMp=Bqfk2)#OW+B;D*htH_sM?NS@BjSXvs47;mN!RCCN=}Zsz&(XI~>Qw`WfB%Zf$;iY+#fZngloN)n*;uE4oUiA4j2#^FKW!|7K2<;%S~G^@~+H^PXpYtIaj&>zl=zd=uAeUX}UPv}~9-rm91(+S_~`vT9i+^T<^yX-DY!{Szc}D)={snUuY$r?YDMMK!p#P9ql~-5dI|hLL+CJ6E?es!D;RkFfVdI-VRks$O%r%w~O6F|9(e(f|aZfNmo<(-8*5edA<WXFQL*+v+g&Ed5LJS1WubyjI;+rV@1cNFmDKQq&icyYXti=r}YBrIwPMZw{Mg@A<{aK8yQ5dhIH7e6_?>f6E2%hMhLKxk*|bX$9zwHj(d}j60V_$8QiBOdO!*o;kh+(I~>0%q%S;J>%qpn7H13#Lt38Exe0gIuvI%GdfDW=TO*$jvibWfBB%~O+%mYQd~hGXzb(rK$M?OT6ns0(&b~Ldb4hKtG$<KQ<@(j-9!}SsPgWE1T`}HASMoBIYq%}iu=G<8g=W`NJRI_eLr|YX&t86=|ncO4twi?WGLB3lvvPTZjLF}NRaA^Ld4K+Gq0P>ygP6%e34Ggw=-IL2@Evs5S;vg38!agf*3kR57V^JF=HH57t}MC0h;THV8}i?LK&tj$4EAdGrZhpnI8$xyk}s`SPvExnz?b0bCN4@%pu|%aKrs>x3xF$(<{O5Ri-+Q!{Lxz2!~-QmjMd57+;4m59YoLeL<pV*peM-DGlw!78@vpRpOkV_AY4*p+HYt_QP@<c1+vP^=vS2_S`V9`rDD+&UjM>ASVVC;wga;=t5P~ig#O#CC@+L->=~}#kw|`vF0*HGnzX5JFoYelvUK)N|GCjex4dWOKyDOtaJ}Yg-J!%q{fN!yws*9|6LqEoV<-W4ENB&OGZ|3oWbD`%z^L0xJYy-Ll%z{T)|06X&+=2*iY;D?4)C^fvvszf;=1-YjNl<T@l~37jQ&V=;?}rgdX(br3FWU(K_q;cN3qSo?qZCQ72z74nBn2V}JeFUhk%9co6d7#|G<54G%^qp_FpCb<NNA6xAT>A<UrByeC}IJ9n`^(s#G<g3&y0k2cUJ$aQFzp)jW|BE-wVvk_h_!$s5EY~9#v?)+aMpf)!\'))\nneed(len(BORROWED_SOURCE)==BORROWED_IMPLEMENTATION[\'bytes\']and hashlib.sha256(BORROWED_SOURCE).hexdigest()==BORROWED_IMPLEMENTATION[\'sha256\'],\'exact reviewed readonly successor\')\n@contextlib.contextmanager\ndef load_pair(v):\n names=(\'libvirt_peer\',\'libvirt_access\',\'guest_firmware_probe\',\'libvirt_native\',\'queue_assignment\');missing=object();previous={k:sys.modules.get(k,missing)for k in names}\n try:\n  roles=v[\'parent\'][\'sourceRoles\'];modules={}\n  for name in names:\n   module=types.ModuleType(name);module.__file__=roles[name][\'path\'];sys.modules[name]=module;exec(compile(BORROWED_SOURCE if name==\'libvirt_peer\'else v[\'source\'][name],module.__file__,\'exec\'),module.__dict__);modules[name]=module\n  yield modules[\'libvirt_peer\'],modules[\'libvirt_access\']\n finally:\n  for name,old in previous.items():\n   if old is missing:sys.modules.pop(name,None)\n   else:sys.modules[name]=old\n\ndef run(request,io,boot,observe=None):\n v0=verify_inputs(request,io,boot,False)\n with load_pair(v0)as(peer,access):\n  with access.runtime_snapshot(v0[\'parent\'],v0[\'parentPin\'],request,time.monotonic()+14,io)as snapshot:\n   v=verify_inputs(request,io,boot);need(v[\'parentPin\']==v0[\'parentPin\']and v[\'source\']==v0[\'source\'],\'unchanged immutable sources across runtime SH acquisition\')\n   with contextlib.ExitStack()as custody:\n    heldPlacement=custody.enter_context(io.hold_placement(v[\'parent\'][\'sourcePlacementPin\']));heldQualification=custody.enter_context(io.hold_placement(v[\'parent\'][\'placementQualificationPin\']))\n    peer.validate_request(request);binding=bind_observer_placement(peer,v[\'parent\'],v[\'parentPin\'],v[\'context\']);need(binding[\'placementPin\']==heldPlacement[\'ref\']and binding[\'qualificationPin\']==heldQualification[\'ref\'],\'binding consumes the two retained exact placement pins\')\n    parent=v[\'parent\'];candidate=parent[\'candidate\']\n    def custody(phase,intent,reg,state,files):return access.verify_phase(candidate,parent[\'preparedAccessPin\'],parent[\'preparedDiskPins\'],phase,intent,reg,state,files)\n    proof=peer.observe(request,custody=custody)if observe is None else observe(peer,request,custody)\n    need(proof.get(\'accessCustody\',{}).get(\'phase\')==proof[\'phase\'],\'actual locked phase access custody required\')\n    proof[\'accessCustody\']={\'kind\':\'ROOT_PHASE_PREPARED_ACCESS_CUSTODY_R1\',\'phase\':proof[\'phase\'],\'nonce\':NONCE,\'bootID\':boot,\'requestSHA256\':hashlib.sha256(peer.canon(request)).hexdigest(),\'parentPin\':v[\'parentPin\'],\'preparedAccessPin\':parent[\'preparedAccessPin\'],\'preparedDiskPins\':parent[\'preparedDiskPins\'],\'sourceGraphSHA256\':binding[\'sourceGraphSHA256\'],\'placementPin\':binding[\'placementPin\'],\'qualificationPin\':binding[\'qualificationPin\'],\'stage\':access.prepared_lineage(candidate,parent[\'preparedAccessPin\'],parent[\'preparedDiskPins\']),\'stageRawBase64\':__import__(\'base64\').b64encode(__import__(\'libvirt_native\').held(parent[\'preparedAccessPin\'],1048576)).decode(\'ascii\'),\'data\':proof[\'accessCustody\']}\n    need(v[\'context\']is not None or proof[\'phase\']==\'NOT_PREPARED\',\'missing context permits only actual NOT_PREPARED, never ACTIVE/CLOSED\')\n    need(proof[\'request\']==request and proof[\'sourceSHA256\']==PEER_SHA and proof[\'phase\']in(\'NOT_PREPARED\',\'PREPARED\',\'ACTIVE\',\'CLOSED\')and proof[\'allOwnedDescriptorsClosed\']is True and proof[\'effects\']==[],\'unchanged complete readonly observer proof and closure\')\n    # Every complete source and protected control is reread after observer use.\n    for name,ref in v[\'parent\'][\'sourceRoles\'].items():need(io.read(ref,0o444,65536)==v[\'source\'][name],\'post-use exact source12 bytes\')\n    need(io.read(v[\'parentPin\'],0o444,1048576)==v[\'parentRaw\'],\'post-use exact parent bytes\')\n    if v[\'context\']is not None:\n     need(io.read(v[\'contextPin\'],0o400,1048576)==v[\'contextRaw\'],\'post-use exact context bytes\');io.read(v[\'assignmentPin\'],0o400,1048576);io.read(v[\'grantPin\'],0o400,1048576)\n    else:\n     try:io.read_path(\'/run/opemos-libvirt-runtime-\'+NONCE+\'/context.json\',0o400,1048576)\n     except FileNotFoundError:pass\n     else:raise RuntimeError(\'context absence changed during exact NOT_PREPARED observation; no retry\')\n    heldPlacement[\'recheck\']();heldQualification[\'recheck\']()\n    result={\'kind\':\'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION\',\'upstreamObserver\':v[\'parent\'][\'sourceRoles\'][\'libvirt_peer\'],\'implementation\':{\'contract\':CONTRACT,\'peer\':v[\'parent\'][\'sourceRoles\'][\'libvirt_peer\'],\'access\':v[\'parent\'][\'sourceRoles\'][\'libvirt_access\'],\'sourceRoles\':v[\'parent\'][\'sourceRoles\'],\'parent\':v[\'parentPin\'],\'context\':v[\'contextPin\'],\'assignment\':v[\'assignmentPin\'],\'grant\':v[\'grantPin\'],\'placementBinding\':binding,\'runtimePublication\':snapshot,\'borrowedRunCustody\':io.runProof,\'actualPeerImplementation\':BORROWED_IMPLEMENTATION},\'proof\':proof,\'effects\':[]}\n    io.check()\n need(snapshot[\'readLockClosed\']is True,\'actual runtime read lock closed\');need(len(canonical(result).encode())+1<=1048576,\'unchanged whole Root1MiB envelope\');return result\n\ndef main():\n need(os.getuid()==0 and len(sys.argv)==4 and sys.argv[1]==PEER_SHA and sys.argv[2]==\'--queue-libvirt-request-json\',\'exact existing Root standalone queue argv\')\n request=json.loads(sys.argv[3]);before=set(os.listdir(\'/proc/self/fd\'))\n with RootInputs()as io:result=run(request,io,Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip())\n need(before==set(os.listdir(\'/proc/self/fd\')),\'adapter full owned FD closure\');print(canonical(result),flush=True)\nif __name__==\'__main__\':\n try:main()\n except BaseException as e:\n  print(canonical({\'kind\':\'QUEUE_LIBVIRT_FIRST_REFUSAL\',\'type\':type(e).__name__,\'reason\':str(e),\'effects\':[],\'evidence\':getattr(e,\'evidence\',None),\'workingEvidence\':getattr(e,\'workingEvidence\',None),\'placementCustody\':getattr(e,\'placementCustody\',None),\'runtimePublication\':getattr(e,\'runtimePublication\',None),\'rootInputCloseErrors\':getattr(e,\'ownedRootInputClosureErrors\',[]),\'rootFilesCloseErrors\':getattr(e,\'rootFilesCloseErrors\',[]),\'lockCloseErrors\':getattr(e,\'lockCloseErrors\',[]),\'ownedPlacementCloseErrors\':getattr(e,\'ownedPlacementCloseErrors\',[]),\'traceback\':traceback.format_exc()}),file=sys.stderr,flush=True);sys.exit(1)\n'

SOURCE247_PEER_INPUT_SHA='3b4e4f6a33bcf595ae00b4a9bb374182308ceb0930b99f01591914fde143cf71';SOURCE247_PEER_INPUT_BYTES=65482;SOURCE247_ACCESS_INPUT_SHA='676385485e3f99dd95e0a755f0a9b3d461df45eb6a65edd153474377b2d9280a';SOURCE247_ACCESS_INPUT_BYTES=32623
SOURCE247_TERMINAL_ADAPTER='"""Exact D23 readonly standalone peer/access adapter proposal, never installed.\nNo deployment, writes, SQL, runtime grant, domain control or sysfs methods.\nQueue owner must independently adopt exact bytes and consumer contract.\n"""\nimport contextlib,copy,hashlib,json,os,re,stat,sys,time,traceback,types\nfrom pathlib import Path\nF=(\'st_dev\',\'st_ino\',\'st_mode\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\');CORE=F[:6]\nNONCE=\'cd9ef0826364409da287f6f3e3830c95\';CONTRACT=\'D257_OLD_SOURCE247_CLOSED_TERMINAL_ONLY\'\nPEER_SHA=\'3b4e4f6a33bcf595ae00b4a9bb374182308ceb0930b99f01591914fde143cf71\';PEER_BYTES=65482\nACCESS_SHA=\'676385485e3f99dd95e0a755f0a9b3d461df45eb6a65edd153474377b2d9280a\';ACCESS_BYTES=32623\nROLES={\'libvirt_peer\',\'libvirt_access\',\'libvirt_native\',\'libvirt_preflight\',\'libvirt_producer\',\'queue_assignment\',\'runtime_entry\',\'guest_delta\',\'guest_firmware_probe\',\'held_history_reader\',\'two_boot_contract\',\'postqueue_issuer\'}\ndef canonical(v):return json.dumps(v,sort_keys=True,separators=(\',\',\':\'),allow_nan=False)\ndef need(v,m):\n if not v:raise RuntimeError(m)\ndef ident(s):return{k:getattr(s,k)for k in F}\ndef decode(raw):\n def unique(pairs):\n  value={}\n  for key,item in pairs:need(key not in value,\'duplicate protected JSON key\');value[key]=item\n  return value\n value=json.loads(raw,object_pairs_hook=unique);need(canonical(value).encode()==raw,\'whole canonical protected metadata, no dropped/trailing fields\');return value\ndef record_run_epoch(proof,event):\n raw=(lambda x:canonical(x).encode())(event);last=proof[\'events\'][-1]if proof[\'events\']else None\n if last is not None and last[\'event\']==event:last[\'count\']+=1\n else:proof[\'events\'].append({\'event\':event,\'count\':1})\n proof[\'eventCount\']+=1;proof[\'eventChainSHA256\']=hashlib.sha256(bytes.fromhex(proof[\'eventChainSHA256\'])+raw).hexdigest();need(0<proof[\'eventCount\']<=4096 and len(proof[\'events\'])<=256 and len((lambda x:canonical(x).encode())(proof))<=262144,\'bounded lossless borrowed run epoch runs\')\nclass RootInputs:\n """One readonly bounded held-nofollow /run graph; owns and closes all FDs."""\n def __init__(self):self.fds=[];self.dirs={}\n def __enter__(self):\n  self.root=os.open(\'/\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.fds.append(self.root)\n  try:\n   self.run=os.open(\'run\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.root);self.fds.append(self.run)\n   self.dirs={\'/\':(self.root,ident(os.fstat(self.root)),False),\'/run\':(self.run,ident(os.fstat(self.run)),False)};self.runBirth=self.run_row(self.run);rows=[x for x in Path(\'/proc/self/mountinfo\').read_text().splitlines()if x.split()[0]==str(self.runBirth[\'mountID\'])];need(len(rows)==1,\'exact initial run mount\');self.runProof={\'kind\':\'ROOT_BORROWED_RUN_ANCESTRY_R257\',\'path\':\'/run\',\'birth\':self.runBirth,\'namespace\':os.readlink(\'/proc/self/ns/mnt\'),\'mountRow\':rows[0],\'events\':[],\'eventCount\':0,\'eventChainSHA256\':\'0\'*64,\'scopeDescriptorsClosed\':False,\'closeOutcomes\':[]};self.check();return self\n  except BaseException:\n   self.__exit__(*sys.exc_info());raise\n def run_row(self,fd):\n  raw=Path(\'/proc/self/fdinfo/\'+str(fd)).read_text();v={}\n  for line in raw.splitlines():\n   if line.startswith((\'flags:\',\'mnt_id:\')):k,x=line.split(\':\',1);v[k]=x.strip()\n  need(set(v)=={\'flags\',\'mnt_id\'}and v[\'mnt_id\'].isdigit()and re.fullmatch(\'[0-7]+\',v[\'flags\'])is not None,\'complete actual run descriptor flags/mount\')\n  f=__import__(\'fcntl\');return {\'fd\':fd,\'identity\':ident(os.fstat(fd)),\'target\':os.readlink(\'/proc/self/fd/\'+str(fd)),\'flags\':f.fcntl(fd,f.F_GETFL),\'descriptorFlags\':f.fcntl(fd,f.F_GETFD),\'fdinfoFlags\':v[\'flags\'],\'mountID\':int(v[\'mnt_id\'])}\n def borrowed_run(self):\n  initial=self.runBirth;owned=[];primary=None;event={};startns=os.readlink(\'/proc/self/ns/mnt\')\n  try:\n   event[\'heldBefore\']=self.run_row(self.run)\n   for label,path,anchored in((\'anchored\',\'run\',True),(\'named\',\'/run\',False)):\n    fd=os.open(path,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,**({\'dir_fd\':self.root}if anchored else{}));owned.append(fd);event[label]=self.run_row(fd)\n   event[\'anchoredPath\']=ident(os.stat(\'run\',dir_fd=self.root,follow_symlinks=False));event[\'namedPath\']=ident(os.lstat(\'/run\'));event[\'heldAfter\']=self.run_row(self.run);event[\'anchoredAfter\']=self.run_row(owned[0]);event[\'namedAfter\']=self.run_row(owned[1]);event[\'namespaceBefore\']=startns;event[\'namespaceAfter\']=os.readlink(\'/proc/self/ns/mnt\')\n   rows=[x for x in Path(\'/proc/self/mountinfo\').read_text().splitlines()if x.split()[0]==str(initial[\'mountID\'])];need(len(rows)==1,\'unique current kernel run mount row\');event[\'mountRow\']=rows[0]\n   stable=F[:5];snapshots=[event[k][\'identity\']for k in(\'heldBefore\',\'anchored\',\'named\',\'heldAfter\',\'anchoredAfter\',\'namedAfter\')]+[event[\'anchoredPath\'],event[\'namedPath\']]\n   need(all(all(x[k]==initial[\'identity\'][k]for k in stable)for x in snapshots)and all(event[k][\'target\']==\'/run\'and event[k][\'mountID\']==initial[\'mountID\']and event[k][\'descriptorFlags\']==1 for k in(\'heldBefore\',\'anchored\',\'named\',\'heldAfter\',\'anchoredAfter\',\'namedAfter\')),\'same held/anchored/named run inode/type/mode/owner/mount\')\n   need(event[\'heldBefore\']==dict(initial,identity=event[\'heldBefore\'][\'identity\'])and event[\'heldAfter\']==dict(initial,identity=event[\'heldAfter\'][\'identity\'])and startns==event[\'namespaceAfter\']==self.runProof[\'namespace\'],\'same borrowed run FD/flags/name/namespace\')\n   for name in(\'anchored\',\'named\'):\n    a=event[name];b=event[name+\'After\'];need(a==dict(b,identity=a[\'identity\'])and a[\'flags\']==os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,\'exact temporary nofollow O_PATH run descriptors\')\n   row=rows[0].split();i=initial[\'identity\'];need(stat.S_ISDIR(i[\'st_mode\'])and stat.S_IMODE(i[\'st_mode\'])==0o755 and i[\'st_uid\']==i[\'st_gid\']==0 and initial[\'flags\']&os.O_ACCMODE==os.O_RDONLY and not initial[\'flags\']&os.O_PATH and initial[\'flags\']&os.O_DIRECTORY and initial[\'flags\']&os.O_NOFOLLOW and re.fullmatch(r\'mnt:\\[[0-9]+\\]\',startns)is not None,\'declared borrowed Root0755 readonly run directory\');need(row[3:5]==[\'/\',\'/run\']and row[2]==str(os.major(i[\'st_dev\']))+\':\'+str(os.minor(i[\'st_dev\']))and event[\'mountRow\']==self.runProof[\'mountRow\'],\'same kernel mount root/device/path and original run mount\')\n  except BaseException as error:primary=error;error.evidence={\'kind\':\'BORROWED_RUN_CUSTODY_REFUSAL_R257\',\'birth\':initial,\'event\':event};raise\n  finally:\n   errors=[]\n   for fd in owned[::-1]:\n    try:os.close(fd)\n    except BaseException as e:errors.append({\'fd\':fd,\'type\':type(e).__name__,\'reason\':str(e)})\n   if errors:\n    if primary is not None:primary.ownedRootInputClosureErrors=errors\n    else:raise RuntimeError(canonical({\'ownedRootInputClosureErrors\':errors}))\n  event[\'temporaryDescriptorsClosed\']=True;record_run_epoch(self.runProof,event);return event\n def check(self):\n  for path,(fd,a,exclusive)in self.dirs.items():\n   if path==\'/run\':self.borrowed_run();continue\n   x=ident(os.fstat(fd));named=ident(os.lstat(path))\n   if not(x==named and all(x[k]==a[k]for k in(CORE if not exclusive else F))):\n    error=RuntimeError(\'held/named declared directory identity/epoch\');error.evidence={\'path\':path,\'role\':\'exclusive\'if exclusive else\'shared-ancestor\',\'birth\':a,\'held\':x,\'named\':named,\'monotonic\':time.monotonic()};raise error\n   need(stat.S_ISDIR(x[\'st_mode\'])and x[\'st_uid\']==x[\'st_gid\']==0,\'Root directory nofollow custody\')\n   need(stat.S_IMODE(x[\'st_mode\'])in((0o755,0o777)if path==\'/\'else(0o755,)if path==\'/run\'else(0o755,)if path.startswith(\'/run/opemos-steamos-source-\')else(0o700,)),\'exact role-specific directory mode\')\n def directory(self,path):\n  allowed={\'/run/opemos-steamos-source-\'+NONCE,\'/run/opemos-libvirt-runtime-\'+NONCE,\'/run/opemos-steamos-placement-\'+NONCE}\n  need(path in allowed,\'declared finite source/context/placement root only\')\n  if path not in self.dirs:\n   fd=os.open(Path(path).name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.run);self.fds.append(fd);self.dirs[path]=(fd,ident(os.fstat(fd)),True)\n  self.check();return self.dirs[path][0]\n def read_path(self,path,mode,cap):\n  path=Path(path);need(path.is_absolute()and path.name not in(\'\',\'.\',\'..\'),\'absolute confined declared leaf\')\n  if str(path.parent)==\'/run\':need(str(path)==\'/run/opemos-libvirt-parent-\'+NONCE+\'.json\',\'one normal public parent only\');parent=self.run\n  else:parent=self.directory(str(path.parent))\n  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)\n  try:\n   s=os.fstat(fd);a=ident(s);need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode and s.st_nlink==1 and s.st_size<=cap,\'exact Root leaf mode/owner/link/size\');raw=b\'\'\n   while chunk:=os.read(fd,65536):raw+=chunk;need(len(raw)<=cap,\'bounded full leaf stream\')\n   need(a==ident(os.fstat(fd))==ident(os.stat(path.name,dir_fd=parent,follow_symlinks=False))==ident(os.lstat(path))and len(raw)==a[\'st_size\'],\'full held/anchored/named identity and EOF\');self.check();return raw,{\'path\':str(path),\'bytes\':len(raw),\'sha256\':hashlib.sha256(raw).hexdigest(),\'identity\':a}\n  finally:os.close(fd)\n def read(self,ref,mode,cap):\n  raw,actual=self.read_path(ref[\'path\'],mode,cap)\n  if actual!=ref:\n   error=RuntimeError(\'exact declared full9/length/SHA pin\');error.evidence={\'path\':ref[\'path\'],\'expected\':ref,\'actual\':actual};raise error\n  return raw\n def placement_bytes(self,fd,parentfd,ref):\n  """Inner FD/hash check; hold_placement applies exact Root role custody.\n  It does not change Root policy or convert a user fixture into Root proof.\n  """\n  value={\'path\':ref[\'path\'],\'expected\':ref,\'heldBefore\':None,\'heldAfter\':None,\'named\':None,\'heldSHA256\':None,\'namedSHA256\':None,\'heldBytes\':None,\'namedBytes\':None}\n  def bytesof(f):\n   chunks=[];offset=0\n   while True:\n    b=os.pread(f,65536,offset)\n    if not b:break\n    offset+=len(b);need(offset<=1048576,\'unchanged placement metadata1MiB streaming cap\');chunks.append(b)\n   return b\'\'.join(chunks)\n  try:\n   value[\'heldBefore\']=ident(os.fstat(fd));need((__import__(\'fcntl\').fcntl(fd,__import__(\'fcntl\').F_GETFL)&os.O_ACCMODE)==os.O_RDONLY,\'owned placement held FD remains O_RDONLY\');held=bytesof(fd);value.update(heldBytes=len(held),heldSHA256=hashlib.sha256(held).hexdigest())\n   nf=os.open(Path(ref[\'path\']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)\n   try:\n    value[\'named\']=ident(os.fstat(nf));named=bytesof(nf);value.update(namedBytes=len(named),namedSHA256=hashlib.sha256(named).hexdigest());need(value[\'named\']==ident(os.fstat(nf))==ident(os.stat(Path(ref[\'path\']).name,dir_fd=parentfd,follow_symlinks=False))==ident(os.lstat(ref[\'path\'])),\'placement fresh nofollow named FD/path full9\')\n   finally:\n    primary=sys.exc_info()[1]\n    try:os.close(nf)\n    except BaseException as close:\n     if primary is None:raise\n     primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'fd\':nf,\'type\':type(close).__name__,\'reason\':str(close)}]\n   value[\'heldAfter\']=ident(os.fstat(fd));need(value[\'heldBefore\']==value[\'heldAfter\']==value[\'named\']==ref[\'identity\']and len(held)==len(named)==ref[\'bytes\']and value[\'heldSHA256\']==value[\'namedSHA256\']==ref[\'sha256\']and held==named,\'placement held/named full9/raw bytes/length/SHA equal originally bound operand\')\n   return held\n  except BaseException as error:error.placementCustody=value;raise\n @contextlib.contextmanager\n def hold_placement(self,ref):\n  root=\'/run/opemos-steamos-placement-\'+NONCE;need(ref[\'path\']in(root+\'/storage-contract.json\',root+\'/placement-qualified.json\'),\'two exact placement metadata leaves only\');i=ref[\'identity\'];need(set(ref)=={\'path\',\'bytes\',\'sha256\',\'identity\'}and 0<ref[\'bytes\']<=1048576 and stat.S_ISREG(i[\'st_mode\'])and stat.S_IMODE(i[\'st_mode\'])==0o400 and i[\'st_uid\']==i[\'st_gid\']==0 and i[\'st_nlink\']==1 and i[\'st_size\']==ref[\'bytes\'],\'exact Root0400 placement full pin/custody\')\n  parentfd=self.directory(root);fd=os.open(Path(ref[\'path\']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)\n  try:\n   original=self.placement_bytes(fd,parentfd,ref);self.check()\n   def recheck():\n    self.check();raw=self.placement_bytes(fd,parentfd,ref);need(raw==original,\'complete held placement raw bytes identical after observer\');self.check();return ref\n   yield {\'ref\':ref,\'raw\':original,\'recheck\':recheck}\n  finally:\n   primary=sys.exc_info()[1]\n   try:os.close(fd)\n   except BaseException as close:\n    if primary is None:raise\n    primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'fd\':fd,\'type\':type(close).__name__,\'reason\':str(close)}]\n def __exit__(self,*a):\n  errors=[]\n  for fd in self.fds[::-1]:\n   try:\n    os.close(fd)\n    if hasattr(self,\'runProof\'):self.runProof[\'closeOutcomes\'].append({\'fd\':fd,\'closed\':True})\n   except OSError as e:errors.append({\'fd\':fd,\'type\':type(e).__name__,\'reason\':str(e)})\n  self.fds=[]\n  if hasattr(self,\'runProof\'):self.runProof[\'scopeDescriptorsClosed\']=not errors\n  if errors:\n   if a[1]is not None:a[1].ownedRootInputClosureErrors=errors\n   else:raise RuntimeError(canonical({\'ownedRootInputClosureErrors\':errors}))\n\ndef parent_spec(parent,parent_ref):\n s=copy.deepcopy(parent[\'normalizedSpecTemplate\']);need(s[\'approval\']==\'EXACT_PARENT_MINIMAL_PIN\'and s[\'command\'][-1]==\'EXACT_PARENT_FULL_PIN_JSON\',\'two existing late parent-pin slots only\');s[\'approval\']={k:parent_ref[k]for k in(\'path\',\'bytes\',\'sha256\')};s[\'command\'][-1]=canonical(parent_ref)\n need(s[\'command\']==[\'sudo\',\'-n\',\'/usr/bin/python3\',\'-B\',parent[\'sourceRoles\'][\'runtime_entry\'][\'path\'],\'--parent-pin-json\',canonical(parent_ref)]and s[\'id\']==parent[\'jobId\']and s[\'cores\']==4 and s[\'memory\']==10737418240 and s[\'timeout_seconds\']==900 and \'omen-iommu-group-1\'in s[\'resources\'],\'exact ordinary entry and10GiB/4CPU/900s spec\')\n return s\n\ndef verify_inputs(request,io,boot,include_context=True):\n need(request[\'leaseNonce\']==NONCE and request[\'domainName\']==\'opemos-libvirt-\'+NONCE,\'fresh exact D23 scope only\')\n cr=\'/run/opemos-libvirt-runtime-\'+NONCE+\'/context.json\';parentRaw,parentRef=io.read_path(\'/run/opemos-libvirt-parent-\'+NONCE+\'.json\',0o444,1048576);parent=decode(parentRaw)\n contextRaw=contextRef=context=None\n if include_context:\n  try:contextRaw,contextRef=io.read_path(cr,0o400,1048576);context=decode(contextRaw)\n  except FileNotFoundError:pass\n need(parent[\'kind\']==\'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT\'and parent[\'RootIssued\']is True and parent[\'runtimeAuthorized\']is True and parent.get(\'MODEL_ONLY\')is False and parent[\'bootID\']==boot and parent[\'nonce\']==NONCE and parent[\'contextPath\']==cr,\'existing actual same-boot Root parent; no issuance or clock refresh\')\n if context is not None:need(context[\'parentPin\']==parentRef and context[\'kind\']==\'ROOT_LIBVIRT_R4_RUNTIME_CONTEXT\'and context[\'runtimeAuthorized\']is True and context.get(\'MODEL_ONLY\')is False and context[\'candidate\']==parent[\'candidate\']and context[\'sourceRoles\']==parent[\'sourceRoles\'],\'Root context/candidate/source12 equality; no model promotion\')\n need(type(parent[\'candidate\'].get(\'installer\'))is dict and parent[\'candidate\'][\'installer\'].get(\'kind\')==\'AUTHENTICATED_F9AA_RAW_RECOVERY_USB_FIRSTBOOT\'and parent[\'candidate\'][\'installer\'].get(\'noInstallTarget\')is True,\'this reviewed source branch admits only the retained installer/no target\')\n need(parent[\'issuedUnix\']<parent[\'startBeforeUnix\']<=parent[\'issuedUnix\']+300 and parent[\'wholeDeadlineUnix\']<=parent[\'issuedUnix\']+900,\'original finite parent scope retained; readonly closed observation does not reissue authority\')\n roles=parent[\'sourceRoles\'];need(set(roles)==ROLES,\'complete source12 membership\')\n need(roles[\'libvirt_peer\'][\'bytes\']==65482 and roles[\'libvirt_peer\'][\'sha256\']==PEER_SHA and roles[\'libvirt_access\'][\'bytes\']==ACCESS_BYTES and roles[\'libvirt_access\'][\'sha256\']==ACCESS_SHA,\'frozen reviewed peer/access implementation\')\n need(request[\'observer\']=={k:roles[\'libvirt_peer\'][k]for k in(\'path\',\'bytes\',\'sha256\')}and request[\'jobId\']==parent[\'jobId\'],\'exact original request observer/job\')\n source={}\n for name,ref in sorted(roles.items()):\n  need(ref[\'path\']==\'/run/opemos-steamos-source-\'+NONCE+\'/\'+name+\'.py\',\'same exact source namespace\');source[name]=io.read(ref,0o444,65536);compile(source[name],ref[\'path\'],\'exec\')\n spec=parent_spec(parent,parentRef);bound=spec[\'libvirt_domain\'];need(bound=={\'leaseNonce\':NONCE,\'name\':request[\'domainName\'],\'observer\':request[\'observer\'],\'uuid\':request[\'domainUUID\']}and hashlib.sha256(canonical(spec).encode()).hexdigest()==request[\'specSHA256\'],\'complete final normalized spec/hash/domain identity\')\n assignmentRef=grantRef=None;assignment=grant=None\n if context is not None:\n  assignmentRef=context[\'assignmentPin\'];need(assignmentRef[\'path\']==\'/run/opemos-libvirt-runtime-\'+NONCE+\'/assignment.json\'and context[\'grantPin\'][\'path\']==\'/run/opemos-libvirt-runtime-\'+NONCE+\'/child-grant.json\',\'two exact same-scope child control leaves\');assignment=decode(io.read(assignmentRef,0o400,1048576));grantRef=context[\'grantPin\'];grant=decode(io.read(grantRef,0o400,1048576))\n  need(assignment[\'kind\']==\'ROOT_CANONICAL_QUEUE_LIBVIRT_ASSIGNMENT_R4\'and assignment[\'request\']==request and grant[\'assignmentPin\']==assignmentRef and grant[\'parentPin\']==parentRef and grant[\'normalizedSpecSHA256\']==request[\'specSHA256\'],\'canonical assignment and child grant exact request/spec/parent\')\n  need(grant[\'queuePrograms\']==parent[\'queuePrograms\']and grant[\'sourcePlacementPin\']==context[\'sourcePlacementPin\']==parent[\'sourcePlacementPin\']and grant[\'placementQualificationPin\']==context[\'placementQualificationPin\']==parent[\'placementQualificationPin\'],\'current queue authority and placement pins across child/context/parent\')\n  need(grant[\'RootIssued\']is True and grant[\'MODEL_ONLY\']is False and grant[\'runtimeAuthorized\']is True and grant[\'jobId\']==request[\'jobId\']and grant[\'leaseNonce\']==NONCE and grant[\'bootID\']==boot and parent[\'issuedUnix\']<=grant[\'issuedUnix\']<grant[\'startBeforeUnix\']<=parent[\'startBeforeUnix\']and grant[\'wholeDeadlineUnix\']<=parent[\'wholeDeadlineUnix\'],\'existing finite Root child only, no new runtime grant\')\n return {\'parent\':parent,\'parentPin\':parentRef,\'parentRaw\':parentRaw,\'context\':context,\'contextPin\':contextRef,\'contextRaw\':contextRaw,\'source\':source,\'assignmentPin\':assignmentRef,\'assignmentRaw\':None if assignment is None else canonical(assignment).encode(),\'grantPin\':grantRef,\'grantRaw\':None if grant is None else canonical(grant).encode()}\n\ndef _bind_placement(peer,parent,parent_ref,context,verify_access):\n """Bind only the fresh protected same-source/same-scope metadata operand.\n Never changes the frozen peer\'s nonce, strict geometry or owner predicate.\n """\n nonce=parent[\'nonce\'];roles=parent[\'sourceRoles\'];candidate=parent[\'candidate\']\n peer.need(nonce==\'cd9ef0826364409da287f6f3e3830c95\'and peer.SOURCE_PLACEMENT_NONCE==nonce and candidate[\'nonce\']==nonce and __import__(\'queue_assignment\').execution_job(candidate,parent)==parent[\'jobId\'],\'D23 unused scope only; D22 is consumed\')\n peer.need(parent[\'RootIssued\']is True and parent[\'kind\']==\'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT\'and parent[\'bootID\']==candidate[\'hostBoot\']and parent_ref[\'path\']==\'/run/opemos-libvirt-parent-\'+nonce+\'.json\',\'existing exact Root parent/boot/source scope\')\n peer.need(set(roles)=={\'libvirt_peer\',\'libvirt_access\',\'libvirt_native\',\'libvirt_preflight\',\'libvirt_producer\',\'queue_assignment\',\'runtime_entry\',\'guest_delta\',\'guest_firmware_probe\',\'held_history_reader\',\'two_boot_contract\',\'postqueue_issuer\'},\'closed twelve-role binding\')\n peer.need(roles[\'libvirt_peer\'][\'sha256\']==\'3b4e4f6a33bcf595ae00b4a9bb374182308ceb0930b99f01591914fde143cf71\'and roles[\'libvirt_peer\'][\'bytes\']==65482 and roles[\'libvirt_access\'][\'sha256\']==\'676385485e3f99dd95e0a755f0a9b3d461df45eb6a65edd153474377b2d9280a\'and roles[\'libvirt_access\'][\'bytes\']==32623,\'frozen exact D23 peer and unchanged access bytes\')\n for name,ref in roles.items():peer.need(ref[\'path\']==\'/run/opemos-steamos-source-\'+nonce+\'/\'+name+\'.py\'and ref[\'identity\'][\'st_uid\']==ref[\'identity\'][\'st_gid\']==0 and stat.S_IMODE(ref[\'identity\'][\'st_mode\'])==0o444 and ref[\'identity\'][\'st_nlink\']==1,\'same immutable Root source12 namespace\')\n ref=parent[\'sourcePlacementPin\'];qr=parent[\'placementQualificationPin\'];root=\'/run/opemos-steamos-placement-\'+nonce\n peer.need(ref[\'path\']==root+\'/storage-contract.json\'and qr[\'path\']==root+\'/placement-qualified.json\',\'fresh exact placement+qualification names, no historical receipt\')\n files=peer.RootFiles(root);primary=None;result=None\n try:\n  files.__enter__()\n  raw,actual=files.read(\'storage-contract.json\');qualified,qactual=files.read(\'placement-qualified.json\');peer.need(actual==ref and qactual==qr,\'fresh placement/qualification exact full9/EOF/SHA\')\n  value=json.loads(raw);q=json.loads(qualified);b=value[\'preparationBinding\']\n  peer.need(value[\'kind\']==(\'ROOT_EXACT_STEAMOS_INSTALLER_GAMES_PLACEMENT\'if candidate.get(\'installer\')is not None else\'ROOT_EXACT_STEAMOS_FIXED_GAMES_PLACEMENT\')and value[\'nonce\']==nonce and value[\'boot\']==parent[\'bootID\']and value[\'original\']==candidate[\'original\']and value[\'working\']==candidate[\'working\']and value.get(\'installer\')==candidate.get(\'installer\'),\'same current prepared working placement, no relabel\')\n  peer.need(b[\'sourceRoles\']==roles and b[\'queuePrograms\']==parent[\'queuePrograms\']and b[\'sourceGraphSHA256\']==hashlib.sha256(peer.canon(roles)).hexdigest(),\'placement producer source12/current queue equality\')\n  peer.need(q[\'kind\']==\'ROOT_VERIFIED_FRESH_STEAMOS_PLACEMENT\'and q[\'qualifiedPlacementPin\']==ref and q[\'nonce\']==nonce and q[\'bootID\']==parent[\'bootID\']and q[\'sourceRoles\']==roles and q[\'queuePrograms\']==parent[\'queuePrograms\']and q[\'runtimeAuthorized\']is False and q[\'RootIssuedRuntimeAuthority\']is False,\'complete fresh protected metadata qualification, not a runtime grant\')\n  pre=q[\'currentPreflight\'];prepared=parent[\'preparedDiskPins\'];access_pin=parent[\'preparedAccessPin\']\n  peer.need(type(prepared)is dict and set(prepared)=={\'original\',\'working\'}and prepared[\'original\']==candidate[\'original\']and b[\'preparedDiskPins\']==prepared and access_pin is not None and b[\'preparedAccessPin\']==access_pin==pre[\'preparedAccessPin\']and b[\'splitDiskCapturePins\']==parent[\'splitDiskCapturePins\']==pre[\'splitDiskCapturePins\'],\'exact candidate/pending-access/post-ACL prepared captures/final-preflight lineage\')\n  work=prepared[\'working\'];before_work=candidate[\'working\'];peer.need(work[\'path\']==before_work[\'path\']and work[\'bytes\']==before_work[\'bytes\']and work[\'sha256\']==before_work[\'sha256\']and all(work[\'identity\'][k]==before_work[\'identity\'][k]for k in(\'st_dev\',\'st_ino\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\')),\'same content and stable pre/post ACL working object; full9 remains exact within each epoch\')\n  verify_access(candidate,access_pin,prepared)\n  peer.need(q[\'currentPreflightPin\']==parent[\'prequeuePreflightPin\']and pre[\'bootID\']==parent[\'bootID\']and pre[\'storagePlacement\'][\'receiptPin\']==ref and pre[\'queuePrograms\']==parent[\'queuePrograms\']and pre[\'original\']==candidate[\'original\']and pre[\'kind\']==\'ACTUAL_LIBVIRT_R4_CURRENT_PREFLIGHT\'and pre[\'working\']==prepared[\'working\']and 0<=parent[\'issuedUnix\']-pre[\'observedUnix\']<=30,\'existing normal complete current preflight joins placement before parent issuance\')\n  if context is not None:peer.need(context[\'parentPin\']==parent_ref and context[\'candidate\']==candidate and context[\'sourceRoles\']==roles and context[\'sourcePlacementPin\']==ref and context[\'placementQualificationPin\']==qr,\'context/parent/source12/placement equality\')\n  peer.need(peer.SOURCE_PLACEMENT_PIN is None or peer.SOURCE_PLACEMENT_PIN==ref,\'never replace a different bound placement operand\')\n  again,again_pin=files.read(\'storage-contract.json\');again_q,again_qpin=files.read(\'placement-qualified.json\');peer.need((again,again_pin)==(raw,ref)and(again_q,again_qpin)==(qualified,qr),\'original held/named placement and qualification full9/raw-SHA unchanged after prepared verification\')\n  result={\'placementPin\':ref,\'qualificationPin\':qr,\'sourceGraphSHA256\':b[\'sourceGraphSHA256\'],\'runtimeAuthorityIssued\':False}\n except BaseException as error:primary=error\n finally:\n  try:files.__exit__(None if primary is None else type(primary),primary,None)\n  except BaseException as close:\n   if primary is None:primary=close\n   else:primary.ownedPlacementCloseErrors=getattr(primary,\'ownedPlacementCloseErrors\',[])+[{\'role\':\'bind-placement-ancestors\',\'type\':type(close).__name__,\'reason\':str(close)}]\n if primary is not None:raise primary\n peer.SOURCE_PLACEMENT_PIN=ref\n return result\n\ndef bind_placement(peer,parent,parent_ref,context=None):\n from libvirt_access import verify_prepared\n return _bind_placement(peer,parent,parent_ref,context,verify_prepared)\n\ndef bind_observer_placement(peer,parent,parent_ref,context):\n from libvirt_access import prepared_lineage\n return _bind_placement(peer,parent,parent_ref,context,prepared_lineage)\n\nIMPLEMENTATION_GRAPH=None\nACTUAL_PEER={\'bytes\':64581,\'sha256\':\'596c6206e8315887eae765b88ebf3cdf93ca56ae74766443af08fcd55817ea86\'}\nACTUAL_ACCESS={\'bytes\':34043,\'sha256\':\'5dca2ee92ca5c38114bf5c53ca40646031ef6bc430333a06707db9fd9fd6a863\'}\ndef implementation_file(ref,mode,cap):\n need(type(ref)is dict and set(ref)=={\'path\',\'bytes\',\'sha256\',\'identity\'}and Path(ref[\'path\']).is_absolute()and \'..\'not in Path(ref[\'path\']).parts,\'exact protected implementation pin\');fds=[]\n try:\n  fd=os.open(\'/\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd)\n  for i,name in enumerate(Path(ref[\'path\']).parts[1:]):\n   root=os.fstat(fd);need(root.st_uid==root.st_gid==0 and stat.S_ISDIR(root.st_mode)and not stat.S_IMODE(root.st_mode)&0o022,\'Root nonwritable implementation ancestry\');fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|(os.O_DIRECTORY if i<len(Path(ref[\'path\']).parts)-2 else 0),dir_fd=fd);fds.append(fd)\n  a=ident(os.fstat(fd));need(stat.S_ISREG(a[\'st_mode\'])and stat.S_IMODE(a[\'st_mode\'])==mode and a[\'st_uid\']==a[\'st_gid\']==0 and a[\'st_nlink\']==1,\'Root implementation leaf\');raw=b\'\'\n  while b:=os.read(fd,65536):raw+=b;need(len(raw)<=cap,\'implementation role cap\')\n  need(a==ident(os.fstat(fd))==ident(os.lstat(ref[\'path\']))==ref[\'identity\']and len(raw)==ref[\'bytes\']and hashlib.sha256(raw).hexdigest()==ref[\'sha256\'],\'held implementation full9/SHA/EOF\');return raw\n finally:\n  primary=sys.exc_info()[1];errors=[]\n  for fd in fds[::-1]:\n   try:os.close(fd)\n   except BaseException as e:errors.append({\'fd\':fd,\'type\':type(e).__name__,\'reason\':str(e)})\n  if errors:\n   if primary is None:raise RuntimeError(canonical({\'implementationCloseErrors\':errors}))\n   primary.implementationCloseErrors=errors\n\ndef load_implementation_graph(ref,request):\n v=decode(implementation_file(ref,0o400,1048576));need(set(v)=={\'kind\',\'bootID\',\'peer\',\'access\'}and v[\'kind\']==\'SOURCE257_OLD_SOURCE247_CLOSED_IMPLEMENTATION_DATA\'and v[\'bootID\']==Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip(),\'same-boot finite readonly consumer data only\')\n root=Path(ref[\'path\']).parent;rs=os.lstat(root);need(stat.S_ISDIR(rs.st_mode)and rs.st_uid==rs.st_gid==0 and stat.S_IMODE(rs.st_mode)==0o700,\'exact private implementation namespace\');need(re.fullmatch(\'/var/lib/opemos-source257-implementation-[0-9a-f]{32}\',str(root))is not None and Path(ref[\'path\']).name==\'implementation.json\',\'one private implementation root\')\n for name,expected in((\'peer\',ACTUAL_PEER),(\'access\',ACTUAL_ACCESS)):\n  pin=v[name];need(pin[\'path\']==str(root/(\'libvirt_\'+name+\'.py\'))and all(pin[k]==expected[k]for k in(\'bytes\',\'sha256\')),\'exact separate source-owned consumer implementation\');implementation_file(pin,0o444,65536)\n return dict(v,pin=ref)\n\n@contextlib.contextmanager\ndef load_pair(v):\n names=(\'libvirt_peer\',\'libvirt_access\',\'guest_firmware_probe\',\'libvirt_native\',\'queue_assignment\');missing=object();previous={k:sys.modules.get(k,missing)for k in names}\n try:\n  roles=v[\'parent\'][\'sourceRoles\'];modules={}\n  for name in names:\n   module=types.ModuleType(name);actual=IMPLEMENTATION_GRAPH[\'peer\'if name==\'libvirt_peer\'else\'access\']if name in(\'libvirt_peer\',\'libvirt_access\')else None;module.__file__=actual[\'path\']if actual is not None else roles[name][\'path\'];sys.modules[name]=module;exec(compile(implementation_file(actual,0o444,65536)if actual is not None else v[\'source\'][name],module.__file__,\'exec\'),module.__dict__);modules[name]=module\n  yield modules[\'libvirt_peer\'],modules[\'libvirt_access\']\n finally:\n  for name,old in previous.items():\n   if old is missing:sys.modules.pop(name,None)\n   else:sys.modules[name]=old\n\ndef run(request,io,boot,observe=None):\n v0=verify_inputs(request,io,boot,False)\n with load_pair(v0)as(peer,access):\n  with access.runtime_snapshot(v0[\'parent\'],v0[\'parentPin\'],request,time.monotonic()+14,io)as snapshot:\n   v=verify_inputs(request,io,boot);need(v[\'parentPin\']==v0[\'parentPin\']and v[\'source\']==v0[\'source\'],\'unchanged immutable sources across runtime SH acquisition\')\n   with contextlib.ExitStack()as custody:\n    heldPlacement=custody.enter_context(io.hold_placement(v[\'parent\'][\'sourcePlacementPin\']));heldQualification=custody.enter_context(io.hold_placement(v[\'parent\'][\'placementQualificationPin\']))\n    peer.validate_request(request);binding=bind_observer_placement(peer,v[\'parent\'],v[\'parentPin\'],v[\'context\']);need(binding[\'placementPin\']==heldPlacement[\'ref\']and binding[\'qualificationPin\']==heldQualification[\'ref\'],\'binding consumes the two retained exact placement pins\')\n    parent=v[\'parent\'];candidate=parent[\'candidate\']\n    def custody(phase,intent,reg,state,files):return access.verify_phase(candidate,parent[\'preparedAccessPin\'],parent[\'preparedDiskPins\'],phase,intent,reg,state,files)\n    proof=peer.observe(request,custody=custody)if observe is None else observe(peer,request,custody)\n    need(proof.get(\'accessCustody\',{}).get(\'phase\')==proof[\'phase\'],\'actual locked phase access custody required\');need(proof[\'phase\']==\'CLOSED\',\'old Source247 input supports terminal CLOSED observation only, no VM/source authority\')\n    proof[\'accessCustody\']={\'kind\':\'ROOT_PHASE_PREPARED_ACCESS_CUSTODY_R1\',\'phase\':proof[\'phase\'],\'nonce\':NONCE,\'bootID\':boot,\'requestSHA256\':hashlib.sha256(peer.canon(request)).hexdigest(),\'parentPin\':v[\'parentPin\'],\'preparedAccessPin\':parent[\'preparedAccessPin\'],\'preparedDiskPins\':parent[\'preparedDiskPins\'],\'sourceGraphSHA256\':binding[\'sourceGraphSHA256\'],\'placementPin\':binding[\'placementPin\'],\'qualificationPin\':binding[\'qualificationPin\'],\'stage\':access.prepared_lineage(candidate,parent[\'preparedAccessPin\'],parent[\'preparedDiskPins\']),\'stageRawBase64\':__import__(\'base64\').b64encode(__import__(\'libvirt_native\').held(parent[\'preparedAccessPin\'],1048576)).decode(\'ascii\'),\'data\':proof[\'accessCustody\']}\n    need(v[\'context\']is not None or proof[\'phase\']==\'NOT_PREPARED\',\'missing context permits only actual NOT_PREPARED, never ACTIVE/CLOSED\')\n    need(proof[\'request\']==request and proof[\'sourceSHA256\']==PEER_SHA and proof[\'phase\']in(\'NOT_PREPARED\',\'PREPARED\',\'ACTIVE\',\'CLOSED\')and proof[\'allOwnedDescriptorsClosed\']is True and proof[\'effects\']==[],\'unchanged complete readonly observer proof and closure\')\n    # Every complete source and protected control is reread after observer use.\n    for name,ref in v[\'parent\'][\'sourceRoles\'].items():need(io.read(ref,0o444,65536)==v[\'source\'][name],\'post-use exact source12 bytes\')\n    need(io.read(v[\'parentPin\'],0o444,1048576)==v[\'parentRaw\'],\'post-use exact parent bytes\')\n    if v[\'context\']is not None:\n     need(io.read(v[\'contextPin\'],0o400,1048576)==v[\'contextRaw\'],\'post-use exact context bytes\');io.read(v[\'assignmentPin\'],0o400,1048576);io.read(v[\'grantPin\'],0o400,1048576)\n    else:\n     try:io.read_path(\'/run/opemos-libvirt-runtime-\'+NONCE+\'/context.json\',0o400,1048576)\n     except FileNotFoundError:pass\n     else:raise RuntimeError(\'context absence changed during exact NOT_PREPARED observation; no retry\')\n    heldPlacement[\'recheck\']();heldQualification[\'recheck\']()\n    result={\'kind\':\'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION\',\'upstreamObserver\':v[\'parent\'][\'sourceRoles\'][\'libvirt_peer\'],\'implementation\':{\'contract\':CONTRACT,\'peer\':v[\'parent\'][\'sourceRoles\'][\'libvirt_peer\'],\'access\':v[\'parent\'][\'sourceRoles\'][\'libvirt_access\'],\'sourceRoles\':v[\'parent\'][\'sourceRoles\'],\'parent\':v[\'parentPin\'],\'context\':v[\'contextPin\'],\'assignment\':v[\'assignmentPin\'],\'grant\':v[\'grantPin\'],\'placementBinding\':binding,\'runtimePublication\':snapshot,\'borrowedRunCustody\':io.runProof,\'actualPeerImplementation\':IMPLEMENTATION_GRAPH[\'peer\'],\'actualAccessImplementation\':IMPLEMENTATION_GRAPH[\'access\'],\'implementationGraphPin\':IMPLEMENTATION_GRAPH[\'pin\']},\'proof\':proof,\'effects\':[]}\n    io.check()\n need(snapshot[\'readLockClosed\']is True,\'actual runtime read lock closed\');need(len(canonical(result).encode())+1<=1048576,\'unchanged whole Root1MiB envelope\');return result\n\ndef main():\n global IMPLEMENTATION_GRAPH\n need(os.getuid()==0 and len(sys.argv)==6 and sys.argv[1]==PEER_SHA and sys.argv[2]==\'--queue-libvirt-request-json\'and sys.argv[4]==\'--implementation-pin-json\',\'exact terminal-only readonly adapter argv\')\n request=json.loads(sys.argv[3]);IMPLEMENTATION_GRAPH=load_implementation_graph(json.loads(sys.argv[5]),request);before=set(os.listdir(\'/proc/self/fd\'))\n with RootInputs()as io:result=run(request,io,Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip())\n need(before==set(os.listdir(\'/proc/self/fd\')),\'adapter full owned FD closure\');print(canonical(result),flush=True)\nif __name__==\'__main__\':\n try:main()\n except BaseException as e:\n  print(canonical({\'kind\':\'QUEUE_LIBVIRT_FIRST_REFUSAL\',\'type\':type(e).__name__,\'reason\':str(e),\'effects\':[],\'evidence\':getattr(e,\'evidence\',None),\'workingEvidence\':getattr(e,\'workingEvidence\',None),\'placementCustody\':getattr(e,\'placementCustody\',None),\'runtimePublication\':getattr(e,\'runtimePublication\',None),\'rootInputCloseErrors\':getattr(e,\'ownedRootInputClosureErrors\',[]),\'rootFilesCloseErrors\':getattr(e,\'rootFilesCloseErrors\',[]),\'lockCloseErrors\':getattr(e,\'lockCloseErrors\',[]),\'ownedPlacementCloseErrors\':getattr(e,\'ownedPlacementCloseErrors\',[]),\'traceback\':traceback.format_exc()}),file=sys.stderr,flush=True);sys.exit(1)\n'
SOURCE257_PEER_IMPLEMENTATION={'bytes': 64581, 'sha256': '596c6206e8315887eae765b88ebf3cdf93ca56ae74766443af08fcd55817ea86'}
SOURCE257_ACCESS_IMPLEMENTATION={'bytes': 34043, 'sha256': '5dca2ee92ca5c38114bf5c53ca40646031ef6bc430333a06707db9fd9fd6a863'}
def validate_generated_scope_ancestry(values,proof,request):
    require(type(values)is list and len(values)==(0 if proof['phase']=='NOT_PREPARED'else 2),'complete current generated-root ancestry')
    expected=['/run/opemos-libvirt-queue-'+request['jobToken'],'/run/opemos-vfio-'+request['leaseNonce']]
    stable=[]
    for value,path in zip(values,expected):
        require(set(value)=={'kind','privatePath','privateBefore','privateAfter','run'}and value['kind']=='ROOT_GENERATED_SCOPE_ANCESTRY_R257'and value['privatePath']==path,'exact intent/lease private scope')
        i=value['privateBefore'];require(set(i)=={'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'}and i==value['privateAfter']and stat.S_ISDIR(i['st_mode'])and stat.S_IMODE(i['st_mode'])==0o700 and i['st_uid']==i['st_gid']==0,'private generated root full9 remains strict')
        stable.append({'privatePath':path,'privateIdentity':i,'run':validate_borrowed_run_custody(value['run'])})
    return stable

def validate_borrowed_run_custody(v):
    current=type(v)is dict and v.get('kind')=='ROOT_BORROWED_RUN_CURRENT_CUSTODY_V1'
    shape={'kind','path','birth','namespace','mountRow','scopeDescriptorsClosed','closeOutcomes'}|({'lastCheck'}if current else{'events','eventCount','eventChainSHA256'})
    require(type(v)is dict and set(v)==shape and v['kind']in('ROOT_BORROWED_RUN_CURRENT_CUSTODY_V1','ROOT_BORROWED_RUN_ANCESTRY_R257')and v['path']=='/run'and v['scopeDescriptorsClosed']is True,'complete closed borrowed run custody')
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');core=fields[:5];b=v['birth'];shape={'fd','identity','target','flags','descriptorFlags','fdinfoFlags','mountID'}
    def row(r):
        require(type(r)is dict and set(r)==shape and type(r['fd'])is int and r['fd']>=0 and set(r['identity'])==set(fields)and all(type(r['identity'][k])is int for k in fields)and type(r['mountID'])is int and r['mountID']>0 and type(r['flags'])is int and r['descriptorFlags']==1 and re.fullmatch('[0-7]+',r['fdinfoFlags'])is not None and r['target']=='/run'and int(r['fdinfoFlags'],8)==r['flags']|os.O_CLOEXEC,'exact run FD/full9/flags/mount row')
        require(all(r['identity'][k]==b['identity'][k]for k in core)and r['mountID']==b['mountID'],'same actual stable run core/mount')
    row(b);i=b['identity'];require(stat.S_ISDIR(i['st_mode'])and stat.S_IMODE(i['st_mode'])==0o755 and i['st_uid']==i['st_gid']==0 and b['flags']&os.O_ACCMODE==os.O_RDONLY and not b['flags']&os.O_PATH and b['flags']&os.O_DIRECTORY and b['flags']&os.O_NOFOLLOW and re.fullmatch(r'mnt:\[[0-9]+\]',v['namespace'])is not None,'declared borrowed Root0755 readonly run')
    mount=v['mountRow'].split();require(len(mount)>=10 and mount[0]==str(b['mountID'])and mount[2]==str(os.major(i['st_dev']))+':'+str(os.minor(i['st_dev']))and mount[3:5]==['/','/run'],'actual kernel mount row/root/device/path')
    def event(e):
        require(set(e)=={'heldBefore','anchored','named','anchoredPath','namedPath','heldAfter','anchoredAfter','namedAfter','namespaceBefore','namespaceAfter','mountRow','temporaryDescriptorsClosed'}and e['temporaryDescriptorsClosed']is True and e['namespaceBefore']==e['namespaceAfter']==v['namespace']and e['mountRow']==v['mountRow'],'exact bounded same-namespace closed temporary run check')
        for name in('heldBefore','anchored','named','heldAfter','anchoredAfter','namedAfter'):row(e[name])
        for name in('heldBefore','heldAfter'):require(e[name]==dict(b,identity=e[name]['identity']),'original held run FD/target/flags remain exact')
        require(len({e['anchored']['fd'],e['named']['fd'],b['fd']})==3,'distinct declared held/anchored/named descriptors')
        for name in('anchored','named'):
            a=e[name];z=e[name+'After'];require(a==dict(z,identity=a['identity'])and a['flags']==os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,'same nofollow O_PATH temporary descriptor')
        for name in('anchoredPath','namedPath'):require(set(e[name])==set(fields)and all(e[name][k]==i[k]for k in core),'anchored/name-to-FD run core equality')
    if current:
        event(v['lastCheck'])
    else:
        require(type(v['events'])is list and 0<len(v['events'])<=256 and len(canonical(v).encode())<=262144,'complete bounded lossless legacy run epochs')
        chain='0'*64;count=0
        require(type(v['eventCount'])is int and 0<v['eventCount']<=4096 and type(v['eventChainSHA256'])is str,'bounded complete legacy run epoch count/chain')
        for entry in v['events']:
            require(type(entry)is dict and set(entry)=={'event','count'}and type(entry['count'])is int and 0<entry['count']<=4096,'exact legacy lossless epoch run');e=entry['event'];count+=entry['count'];require(count<=v['eventCount'],'complete ordered legacy epoch runs')
            for repeat in range(entry['count']):chain=hashlib.sha256(bytes.fromhex(chain)+canonical(e).encode()).hexdigest()
            event(e)
        require(count==v['eventCount']and chain==v['eventChainSHA256'],'complete ordered legacy full-event chain no dropped/trailing/corrupt epochs')
    closes=v['closeOutcomes'];require(type(closes)is list and len(closes)>=2 and (current or len(closes)<=16)and all(set(x)=={'fd','closed'}and type(x['fd'])is int and x['closed']is True for x in closes)and len({x['fd']for x in closes})==len(closes)and b['fd']in{x['fd']for x in closes},'actual complete owned scope closure')
    return {'kind':v['kind'],'path':'/run','core':{k:i[k]for k in core},'namespace':v['namespace'],'mountRow':v['mountRow'],'mountID':b['mountID'],'flags':b['flags'],'descriptorFlags':b['descriptorFlags'],'fdinfoFlags':b['fdinfoFlags']}

def validate_installer_peer_envelope(value, request, upstream_full_pin, implementation_definition_pin=None):
    require(set(value) == {'kind', 'upstreamObserver', 'implementation', 'proof', 'effects'} and value['kind'] == 'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION' and (value['effects'] == []), 'exact readonly implementation envelope')
    peer = value['upstreamObserver']
    compat=closed_subject_implementation(request,implementation_definition_pin)
    current=compat or peer['sha256']in(R109_PEER_SHA,R109_ORIGINAL_PEER_SHA)
    old247=peer['sha256']==SOURCE247_PEER_INPUT_SHA
    borrowed=peer['sha256']==BORROWED_PEER_INPUT_SHA
    modern=current or peer['sha256']in(SOURCE201_PEER_SHA,BORROWED_PEER_INPUT_SHA,SOURCE247_PEER_INPUT_SHA)
    peer_sha=SOURCE247_PEER_INPUT_SHA if old247 else BORROWED_PEER_INPUT_SHA if borrowed else SOURCE201_PEER_SHA if modern else INSTALLER_PEER_SHA;peer_bytes=SOURCE247_PEER_INPUT_BYTES if old247 else BORROWED_PEER_INPUT_BYTES if borrowed else SOURCE201_PEER_BYTES if modern else INSTALLER_PEER_BYTES;access_sha=SOURCE247_ACCESS_INPUT_SHA if old247 or borrowed else SOURCE201_ACCESS_SHA if modern else INSTALLER_ACCESS_SHA;access_bytes=SOURCE247_ACCESS_INPUT_BYTES if old247 or borrowed else SOURCE201_ACCESS_BYTES if modern else INSTALLER_ACCESS_BYTES;contract='D257_OLD_SOURCE247_CLOSED_TERMINAL_ONLY'if old247 else SOURCE201_ADAPTER_CONTRACT if modern else INSTALLER_ADAPTER_CONTRACT
    if current:
        peer_sha=peer['sha256'];peer_bytes=R109_PEER_BYTES if peer_sha==R109_PEER_SHA else 64727;access_sha=R109_ACCESS_SHA if peer_sha==R109_PEER_SHA else 'ee32a4e84df796d6932062ded9e1049ce5e82cbbf01315d8c74da96b9e03aa9e';access_bytes=R109_ACCESS_BYTES if peer_sha==R109_PEER_SHA else 33928;contract='R109_CURRENT_NORMAL_QUEUE_FULL_PHASE_READONLY'
    subject_root=current_source_root();implementation_root=current_source_root()
    if compat:
        require(implementation_definition_pin is not None,'explicit authenticated current implementation for original CLOSED subject')
        definition=__import__('source_contract').read_definition(implementation_definition_pin)
        __import__('source_contract').validate(definition['sourceRoles'],definition['queuePrograms'],implementation_definition_pin)
        require(definition['queuePrograms'][0]['path']==__file__,'current queue is actual implementation member')
        implementation_root=definition['deployment']['paths']['sourceRoot']
        subject_root=str(Path(request['currentControl']['definitionPin']['path']).parent)
        subject=__import__('source_contract').read_definition(request['currentControl']['definitionPin'])
        __import__('source_contract').validate(subject['sourceRoles'],subject['queuePrograms'],request['currentControl']['definitionPin'])
        require(peer==subject['sourceRoles']['libvirt_peer'],'whole immutable original V2 observer pin')
        peer_sha=peer['sha256'];peer_bytes=peer['bytes'];access_sha=subject['sourceRoles']['libvirt_access']['sha256'];access_bytes=subject['sourceRoles']['libvirt_access']['bytes'];contract='CURRENT_NORMAL_CLOSED_SUBJECT_V1'
    require(peer == upstream_full_pin and peer['sha256'] == peer_sha and (peer['bytes'] == peer_bytes) and (request['observer'] == {k: peer[k] for k in ('path', 'bytes', 'sha256')}), 'original upstream held full9+minimal observer membership')
    i = value['implementation']
    require(set(i) == ({'contract', 'peer', 'access', 'sourceRoles', 'parent', 'context', 'assignment', 'grant', 'placementBinding'}|({'runtimePublication','borrowedRunCustody'}if modern else set())|({'implementationDefinitionPin'}if compat else set())|({'actualPeerImplementation'}if borrowed else {'actualPeerImplementation','actualAccessImplementation'}if current else {'actualPeerImplementation','actualAccessImplementation','implementationGraphPin'}if old247 else set())) and i['contract'] == contract and (i['peer'] == peer), 'exact adopted standalone adapter schema')
    if borrowed:require(i['actualPeerImplementation']==BORROWED_PEER_IMPLEMENTATION,'exact separate reviewed implementation, unchanged old input')
    if current:
        r=i['actualPeerImplementation'];require(r['path']==implementation_root+'/libvirt_peer.py'and r['sha256']==R109_PEER_SHA and r['bytes']==R109_PEER_BYTES,'exact separately pinned current peer; preserved input distinct')
        require(i['implementationDefinitionPin']==implementation_definition_pin,'exact original subject current implementation definition')if compat else require(request['observer']['sha256']==R109_PEER_SHA or value['proof']['phase']=='NOT_PREPARED','original request cannot adopt new phase')
    if modern:validate_borrowed_run_custody(i['borrowedRunCustody'])
    if old247:
        require(value['proof']['phase']=='CLOSED','oldSource247 terminal-only CLOSED phase')
        for name,expected in [('actualPeerImplementation',SOURCE257_PEER_IMPLEMENTATION),('actualAccessImplementation',SOURCE257_ACCESS_IMPLEMENTATION)]:
            r=i[name];require(all(r[k]==expected[k]for k in('bytes','sha256'))and r['identity']['st_uid']==r['identity']['st_gid']==0 and stat.S_IMODE(r['identity']['st_mode'])==0o444,'exact separate consumer implementation pin')
        gp=i['implementationGraphPin'];require(Path(i['actualPeerImplementation']['path']).parent==Path(i['actualAccessImplementation']['path']).parent==Path(gp['path']).parent and gp['identity']['st_uid']==gp['identity']['st_gid']==0 and stat.S_IMODE(gp['identity']['st_mode'])==0o400,'held implementation graph pin, no old input relabel')
    roles = i['sourceRoles']
    if compat:require(roles==subject['sourceRoles'],'whole immutable original V2 source membership')
    expected = set(__import__('source_contract').RUNTIME_ROLES)if current and (compat or peer_sha==R109_PEER_SHA)else {'libvirt_peer', 'libvirt_access', 'libvirt_native', 'libvirt_preflight', 'libvirt_producer', 'queue_assignment', 'runtime_entry', 'guest_delta', 'guest_firmware_probe', 'held_history_reader', 'two_boot_contract', 'postqueue_issuer'}
    require(set(roles) == expected and roles['libvirt_peer'] == peer and (roles['libvirt_access'] == i['access']) and (i['access']['sha256'] == access_sha) and (i['access']['bytes'] == access_bytes), 'whole source12/peer/access identity')
    nonce = request['leaseNonce']
    require((type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce)),'typed scope nonce')
    for name, ref in roles.items():
        require(ref['path'] == str((Path(subject_root if compat or peer_sha==R109_PEER_SHA else R109_ORIGINAL_SOURCE_ROOT)if current else Path('/run/opemos-steamos-source-'+nonce))/(name+'.py')) and ref['identity']['st_uid'] == ref['identity']['st_gid'] == 0 and (stat.S_IMODE(ref['identity']['st_mode']) == 292) and (ref['identity']['st_nlink'] == 1), 'complete same-scope Root source pins')
    current_parent=installer_root_value(i['parent'],0o444,1048576)
    paths=__import__('source_contract').parent_paths(current_parent)
    require(i['parent']['path']==paths['parentPath'],'exact authenticated parent name')
    if i['context'] is None:
        require(value['proof']['phase'] == 'NOT_PREPARED' and i['assignment'] is None and (i['grant'] is None), 'context absent only with actual NOT_PREPARED; no closure projection')
    else:
        require(i['context']['path'] == paths['runtimeRoot'] + '/context.json' and i['assignment']['path'] == paths['runtimeRoot'] + '/assignment.json' and (i['grant']['path'] == paths['runtimeRoot'] + '/child-grant.json'), 'exact context/assignment/grant names')
    b = i['placementBinding']
    placement_root='/run/opemos-steamos-placement-'+nonce
    if current and (compat or peer_sha==R109_PEER_SHA):
        parent=installer_root_value(i['parent'],0o444,1048576)
        require(parent['jobId']==request['jobId']and parent['candidate']['nonce']==nonce,'same protected candidate/job placement')
        placement_root=str(__import__('retained_media').placement_for_candidate(parent['candidate']))
        if placement_root!='/run/opemos-steamos-placement-'+nonce:require(parent['candidate']['jobId']==request['jobId'],'same current attempt job')
    require(set(b) == {'placementPin', 'qualificationPin', 'sourceGraphSHA256', 'runtimeAuthorityIssued'} and b['runtimeAuthorityIssued'] is False and (b['sourceGraphSHA256'] == hashlib.sha256(json.dumps(roles, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()) and (b['placementPin']['path'] == placement_root + '/storage-contract.json') and (b['qualificationPin']['path'] == placement_root + '/placement-qualified.json'), 'lossless exact full graph placement binding, no authority projection')
    if compat:require(value['proof']['phase']=='CLOSED','original subject actual CLOSED/current implementation only')

    def rootpin(ref, mode, cap):
        require(type(ref) is dict and set(ref) == {'path', 'bytes', 'sha256', 'identity'} and (0 < ref['bytes'] <= cap) and (len(ref['sha256']) == 64), 'complete bounded full pin')
        a = ref['identity']
        require(set(a) == {'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'} and stat.S_ISREG(a['st_mode']) and (stat.S_IMODE(a['st_mode']) == mode) and (a['st_uid'] == a['st_gid'] == 0) and (a['st_nlink'] == 1) and (a['st_size'] == ref['bytes']), 'exact Root full9 regular leaf custody')
    if current:
        rootpin(i['actualPeerImplementation'],292,65536);rootpin(i['actualAccessImplementation'],292,65536)
        r=i['actualAccessImplementation'];require(r['path']==implementation_root+'/libvirt_access.py'and r['sha256']==R109_ACCESS_SHA and r['bytes']==R109_ACCESS_BYTES,'exact separately reviewed current access implementation')
    rootpin(i['parent'], 292, 1048576)
    for ref in roles.values():
        rootpin(ref, 292, 65536)
    for ref in (b['placementPin'], b['qualificationPin']):
        rootpin(ref, 256, 1048576)
    if i['context'] is not None:
        for ref in (i['context'], i['assignment'], i['grant']):
            rootpin(ref, 256, 1048576)
    proof = value['proof']
    require(proof['request'] == request and proof['sourceSHA256'] == peer_sha and (proof['phase'] in ('NOT_PREPARED', 'PREPARED', 'ACTIVE', 'CLOSED')) and (proof['allOwnedDescriptorsClosed'] is True) and (proof['effects'] == []), 'unchanged native observer proof required')
    validate_installer_access_custody(proof['accessCustody'],proof,request,i)
    if modern:i=dict(i,runtimePublication=validate_runtime_publication(i['runtimePublication'],request,i,proof['producer']))
    return (proof, {'upstreamObserver': peer, 'implementation': i})


def current_raw_peer_program(observer,raw,st):
    # One exact current reviewed source needs ordinary source-file metadata
    # when the installed transport executes authenticated bytes via python -c.
    # This does not substitute implementation bytes or observation methods.
    if observer['sha256']!='7e1663f8351247b9643b7c14419119449b0bd0722a46b80ae0f8ea34a9f9816a':return raw.decode('utf-8')
    require(observer['path']=='/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r107b/libvirt_peer.py'and observer['bytes']==64727 and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o444,'Exact R107 current raw peer source context')
    return '__file__='+canonical(observer['path'])+'\n'+raw.decode('utf-8')

def observe_queue_libvirt(request,deadline=None,captures=None,terminal_implementation_pin=None):
    observer=request['observer'];fd=os.open(observer['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd);fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');before=tuple(getattr(st,k)for k in fields);require(st.st_size==observer['bytes']<=65536 and st.st_nlink==1,'Finite exact peer source')
        raw=os.read(fd,65537);require(os.read(fd,1)==b'' and len(raw)==observer['bytes']and hashlib.sha256(raw).hexdigest()==observer['sha256']and before==tuple(getattr(os.fstat(fd),k)for k in fields)==tuple(getattr(os.lstat(observer['path']),k)for k in fields),'Exact held/named full peer source')
    finally:os.close(fd)
    use_reviewed=observer['sha256']in REVIEWED_PEER_INPUTS
    require(not use_reviewed or observer['bytes']==REVIEWED_PEER_INPUTS[observer['sha256']],'Exact admitted upstream peer bytes')
    use_d22=observer['sha256']==REVIEWED_PEER_D22_SHA256
    require(not use_d22 or observer['bytes']==REVIEWED_PEER_D22_BYTES,'Exact frozen D22 upstream peer bytes')
    compat=closed_subject_implementation(request,terminal_implementation_pin)
    current=compat or observer['sha256']in(R109_PEER_SHA,R109_ORIGINAL_PEER_SHA)
    use_installer=observer['sha256']in(INSTALLER_PEER_SHA,SOURCE201_PEER_SHA,BORROWED_PEER_INPUT_SHA,SOURCE247_PEER_INPUT_SHA)
    require(not use_installer or observer['bytes']==(BORROWED_PEER_INPUT_BYTES if observer['sha256']==BORROWED_PEER_INPUT_SHA else SOURCE247_PEER_INPUT_BYTES if observer['sha256']==SOURCE247_PEER_INPUT_SHA else SOURCE201_PEER_BYTES if observer['sha256']==SOURCE201_PEER_SHA else INSTALLER_PEER_BYTES),'exact installer upstream peer')
    use_d24=observer['sha256']==D24_PEER_SHA
    require(not use_d24 or observer['bytes']==D24_PEER_BYTES,'Exact D23 frozen peer60512 bytes')
    if 'currentControl'in request:
        active_definition=__import__('source_contract').current_from_queue(__file__)
        require(active_definition is not None,'executing queue has authenticated current V2 definition')
        require(request['currentControl']['definitionPin']==active_definition[0]or terminal_implementation_pin is not None,'original V2 subject requires separately pinned current implementation')
    require(current or use_installer or use_d24 or use_d22 or use_reviewed,'unstructured original observer has no reviewed executable route')
    started=time.monotonic();command=['sudo','-n','/usr/bin/python3','-B','-c',current_raw_peer_program(observer,raw,st),observer['sha256'],'--queue-libvirt-request-json',canonical(request)]
    stdin_body=None
    if current:
        command=['sudo','-n','/usr/bin/python3','-B','-c',R109_CURRENT_ADAPTER,observer['sha256'],'--queue-libvirt-request-json',canonical(request)]
    if compat:
        require(terminal_implementation_pin is not None,'current implementation definition required for original CLOSED subject')
        command.extend(['--implementation-definition-pin-json',canonical(terminal_implementation_pin)])
    if use_installer and not compat:command[5]=SOURCE247_TERMINAL_ADAPTER if observer['sha256']==SOURCE247_PEER_INPUT_SHA else BORROWED_PEER_ROOT_ADAPTER if observer['sha256']==BORROWED_PEER_INPUT_SHA else SOURCE201_ROOT_ADAPTER if observer['sha256']==SOURCE201_PEER_SHA else INSTALLER_ROOT_ADAPTER;command[6]=observer['sha256']
    if observer['sha256']==SOURCE247_PEER_INPUT_SHA and not compat:
        require(terminal_implementation_pin is not None,'oldSource247 CLOSED observation requires exact terminal implementation operand')
        command.extend(['--implementation-pin-json',canonical(terminal_implementation_pin)])
    elif use_d24 and not compat:command[5]=D24_ROOT_ADAPTER;command[6]=D24_PEER_SHA
    elif use_d22 and not compat:command[5]=REVIEWED_PEER_D22_ROOT_ADAPTER;command[6]=REVIEWED_PEER_D22_SHA256
    elif use_reviewed and not compat:command[5]=REVIEWED_PEER_ROOT_ADAPTER;command[6]=REVIEWED_PEER_IMPLEMENTATION_SHA256
    child=None;result=None;proof=None
    try:
        result=subprocess.run(command,input=stdin_body,capture_output=True,text=True,timeout=15 if deadline is None else min(15,max(.001,deadline-time.monotonic())))
        child={'kind':'QUEUE_LIBVIRT_ADAPTER_RETURNED_CHILD_R201','numeric':result.returncode,'stdoutBytes':len(result.stdout.encode()),'stdoutSHA256':hashlib.sha256(result.stdout.encode()).hexdigest(),'stderrBytes':len(result.stderr.encode()),'stderrSHA256':hashlib.sha256(result.stderr.encode()).hexdigest(),'stderr':result.stderr[:65536],'stderrPrefixOnly':len(result.stderr)>65536,'EOF':True,'reaped':True,'pid':'UNKNOWN_COMPLETEDPROCESS_API','request':request,'sourceSHA256':observer['sha256']}
        require(result.returncode==0 and result.stderr=='' and 0<len(result.stdout.encode())<=1048576,'Closed finite Root libvirt transport: '+str(result.returncode)+':'+result.stderr[:65536])
        proof=json.loads(result.stdout);require(result.stdout==canonical(proof)+'\n','One whole canonical Root libvirt frame')
        implementation=None
        if use_installer or current:
            upstream=dict(observer,identity={k:getattr(st,k)for k in fields})
            proof,implementation=validate_installer_peer_envelope(proof,request,upstream,terminal_implementation_pin if compat else None)
        elif use_d24:
            upstream=dict(observer,identity={k:getattr(st,k)for k in fields})
            proof,implementation=validate_d24_peer_envelope(proof,request,upstream)
        elif use_d22:
            require(set(proof)=={'kind','upstreamObserver','implementation','proof','effects'}and proof['kind']=='ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION'and proof['effects']==[]and proof['implementation']==REVIEWED_PEER_D22_IMPLEMENTATION,'Exact D22 standalone frozen peer/access/Root parent/context envelope')
            upstream=dict(observer,identity={k:getattr(st,k)for k in fields});require(proof['upstreamObserver']==upstream and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)in(0o400,0o444),'Exact original immutable D22 peer full9')
            implementation={'upstreamObserver':upstream,'implementation':proof['implementation']};proof=proof['proof']
        elif use_reviewed:
            require(set(proof)=={'kind','upstreamObserver','implementation','proof','effects'}and proof['kind']=='ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION'and proof['effects']==[]and proof['implementation']=={'bytes':40019,'sha256':REVIEWED_PEER_IMPLEMENTATION_SHA256},'Exact reviewed peer implementation envelope')
            upstream=dict(observer,identity={k:getattr(st,k)for k in fields});require(proof['upstreamObserver']==upstream and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)in(0o400,0o444),'Exact original immutable upstream peer full9, not a substituted spec/source')
            implementation={'upstreamObserver':upstream,'implementation':proof['implementation']};proof=proof['proof']
        stable=validate_libvirt_observation(proof,request,started,terminal_implementation_pin if compat else None)
        if captures is not None:
            capture_observation(captures,dict(request=request,proof=proof,implementation=implementation,adapter=child))
        if implementation is not None:
            execution=copy.deepcopy(implementation)
            if 'borrowedRunCustody'in execution['implementation']:execution['implementation']['borrowedRunCustody']=validate_borrowed_run_custody(execution['implementation']['borrowedRunCustody'])
            stable['observerExecution']=execution
        actor=proof['producer']
        try:
            parts=Path('/proc/'+str(actor['pid'])+'/stat').read_text().rsplit(')',1)[1].split();require(int(parts[19])!=actor['start'],'Original Root observer not reaped; held')
        except(FileNotFoundError,ProcessLookupError):pass
        return stable
    except BaseException as error:
        error.adapterEvidence=child or {'kind':'QUEUE_LIBVIRT_ADAPTER_EXCEPTION_R201','numeric':None,'EOF':'UNKNOWN','reaped':'UNKNOWN','request':request,'stdout':str(getattr(error,'stdout',None))[:65536],'stderr':str(getattr(error,'stderr',None))[:65536]}
        error.evidence={'kind':'QUEUE_LIBVIRT_OBSERVER_REFUSAL_R201','firstEvidence':getattr(error,'evidence',None),'adapter':error.adapterEvidence}
        error.readonlyObserverFailure={'kind':'QUEUE_READONLY_OBSERVER_FAILED_R241','request':request,'first':{'type':type(error).__name__,'reason':str(error),'evidence':error.evidence},'adapter':error.adapterEvidence,'stdout':readonly_observer_stream(result.stdout if result is not None else getattr(error,'stdout',None)),'stderr':readonly_observer_stream(result.stderr if result is not None else getattr(error,'stderr',None)),'parsedFrame':proof}
        raise



def normalize_job(row, base):
    require(type(row) is dict, "Job must be an object")
    allowed = {"id", "platform", "owner", "command", "cwd", "files", "cores", "memory",
               "timeout_seconds", "resources", "depends_on", "requires_success", "approval", "nvidia_readiness", "libvirt_domain"}
    require(not (set(row) - allowed), f"Unknown job fields: {set(row) - allowed}")
    for key in ("id", "platform", "owner"):
        require(type(row.get(key)) is str and NAME.fullmatch(row[key]), f"Invalid {key}")
    command = row.get("command")
    require(type(command) is list and command and len(command) <= 128 and
            all(type(x) is str and x and "\x00" not in x for x in command), "command must be an argv array")
    cwd = (base / row.get("cwd", ".")).resolve(strict=True)
    require(cwd.is_dir(), "cwd must exist")
    files = row.get("files", [])
    require(type(files) is list and len(files) <= 128 and all(type(x) is str for x in files), "files must be paths")
    pins = [file_pin(base / x) for x in files]
    # Admission is an existing immutable owner/Resolver file. Its semantics remain
    # the approved runner's responsibility, including at-use guest and trust guards.
    approval = row.get("approval")
    require(type(approval) is dict and set(approval) == {"path", "sha256"}, "Exact approval path/SHA required")
    approved = file_pin(base / approval["path"])
    require(approved["sha256"] == approval["sha256"], "Approval hash mismatch")
    cores = row.get("cores")
    require(type(cores) is int and cores > 0, "cores must be a positive integer")
    timeout = row.get("timeout_seconds")
    require(type(timeout) is int and 1 <= timeout <= 86400, "Explicit bounded timeout required (1..86400s)")
    resources = row.get("resources", [])
    deps = row.get("depends_on", [])
    for values in (resources, deps):
        require(type(values) is list and len(values) <= 128 and
                all(type(x) is str and x and len(x) <= 512 for x in values) and
                len(values) == len(set(values)), "Invalid resource/dependency list")
    require(resources, "Declare at least one exclusive resource (lane/worktree/output directory)")
    success = row.get("requires_success", True)
    require(type(success) is bool, "requires_success must be boolean")
    require(not (set(deps) & {row["id"]}), "Job cannot depend on itself")
    result = dict(id=row["id"], platform=row["platform"], owner=row["owner"], command=command,
                cwd=str(cwd), files=pins, cores=cores, memory=memory(row["memory"]),
                timeout_seconds=timeout, resources=resources, depends_on=deps,
                requires_success=success, approval=approved)
    if "libvirt_domain" in row:
        result["libvirt_domain"]=normalize_libvirt_domain(row["libvirt_domain"],base)
        require(cores==4 and result["memory"]==LIBVIRT_RESERVATION_MEMORY and NVIDIA_RESOURCE in resources,"Exact4CPU10GiB libvirt GPU job split2+8")
        require(any(p==result["libvirt_domain"]["observer"]for p in pins),"Peer observer is an immutable job file operand")
    if "nvidia_readiness" in row:
        result["nvidia_readiness"] = normalize_nvidia_requirement(row["nvidia_readiness"], deps, success)
        require(NVIDIA_RESOURCE in resources, "Exact exclusive guest NVIDIA GPU resource")
    require(not gpu_job(result) or NVIDIA_RESOURCE in resources,'Every physical OMEN GPU job must declare canonical omen-iommu-group-1')
    return result


def enqueue(db, jobs):
    cfg = config(db)
    retained = list(db.execute("SELECT id,spec,state,finished FROM jobs"))
    existing = {r["id"]: json.loads(r["spec"]) for r in retained}
    outstanding = sum(r["state"] not in TERMINAL or r["state"] == "unknown" or r["finished"] is None for r in retained)
    require(outstanding + len(jobs) <= MAX_JOBS, "Finite outstanding queue limit: 256 jobs")
    ids = [x["id"] for x in jobs]
    require(len(ids) == len(set(ids)) and not set(ids) & existing.keys(), "Duplicate job ID; no implicit retries")
    all_jobs = {**existing, **{x["id"]: x for x in jobs}}
    for job in jobs:
        require(job["cores"] <= len(cfg["cpu_ids"]) and job["memory"] <= cfg["memory_bytes"], "Job exceeds pool capacity")
        require(all(x in all_jobs for x in job["depends_on"]), "Unknown dependency")
    visiting, visited = set(), set()
    def visit(name):
        require(name not in visiting, "Dependency cycle")
        if name in visited:
            return
        visiting.add(name)
        for dep in all_jobs[name]["depends_on"]:
            visit(dep)
        visiting.remove(name)
        visited.add(name)
    for name in all_jobs:
        visit(name)
    with db:
        db.executemany("INSERT INTO jobs(id,spec) VALUES(?,?)", [(j["id"], canonical(j)) for j in jobs])


def choose(rows, cfg):
    """FIFO among runnable jobs; blocked jobs do not block independent later jobs."""
    by_id = {r["id"]: r for r in rows}
    busy_cpu, busy_resources, used_ram = set(), set(), 0
    for row in rows:
        if row["state"] in ("running", "terminal_cleanup"):
            spec = json.loads(row["spec"])
            busy_cpu.update(json.loads(row["cpus"]))
            busy_resources.update(effective_resources(spec))
            used_ram += spec["memory"]
    selected, blocked = [], []
    gpu_observation = None; gpu_observation_error = None
    for row in rows:
        if row["state"] != "pending":
            continue
        spec = json.loads(row["spec"])
        deps = [by_id[x] for x in spec["depends_on"]]
        if any(x["state"] not in TERMINAL for x in deps):
            continue
        if spec["requires_success"] and any(x["state"] != "passed" for x in deps):
            blocked.append((row["id"], "Required predecessor failed; independent jobs continue"))
            continue
        if gpu_job(spec):
            if gpu_observation is None and gpu_observation_error is None:
                try: gpu_observation = observe_gpu_group()
                except (ValueError,OSError,KeyError,IndexError,TypeError,subprocess.SubprocessError) as error: gpu_observation_error = error
            if gpu_observation_error is not None or gpu_wait_reason(spec,gpu_observation) is not None:
                continue
        if nvidia_wait_reason(spec) is not None:
            continue
        available = [c for c in cfg["cpu_ids"] if c not in busy_cpu]
        if len(available) < spec["cores"] or used_ram + spec["memory"] > cfg["memory_bytes"]:
            continue
        if busy_resources.intersection(effective_resources(spec)):
            continue
        cpus = available[:spec["cores"]]
        selected.append((row, spec, cpus))
        busy_cpu.update(cpus)
        busy_resources.update(effective_resources(spec))
        used_ram += spec["memory"]
    return selected, blocked


def systemctl(*args, manager="user"):
    require(manager in ("user", "system"), "Unknown systemd manager")
    command = (["systemctl", "--user"] if manager == "user" else ["systemctl"])
    if manager == "system" and args[0] == "stop":
        command = ["sudo", "-n", *command]
    result = subprocess.run([*command, *args], capture_output=True, text=True, timeout=15)
    require(result.returncode == 0, f"systemctl {args[0]} failed: {result.stderr[:1000]}")
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


CG_PROOF_SOURCE = '"""Complete readonly cgroup proof; no unit or process operation."""\nimport os\nfrom pathlib import Path\nimport stat\nimport time\n\n\ndef need(value, why):\n    if not value:\n        raise ValueError(why)\n\n\ndef identity(st):\n    return tuple(getattr(st, x) for x in (\'st_dev\', \'st_ino\', \'st_mode\', \'st_uid\',\n                 \'st_gid\', \'st_nlink\', \'st_mtime_ns\', \'st_ctime_ns\'))\n\n\n\nclass OwnedFDProofFailure(ValueError):\n    def __init__(self, first, evidence):\n        super().__init__(first + "; owned descriptor evidence=" + repr(evidence))\n        self.evidence = evidence\n\n\nfrom contextlib import contextmanager\n\n@contextmanager\ndef owned_fd_evidence(fd, state):\n    primary = None; secondary = None\n    try:\n        yield fd\n    except BaseException as error:\n        primary = error\n    try:\n        os.close(fd)\n        close = {\'fd\': fd, \'label\': state[\'label\'], \'closed\': True, \'UNKNOWN\': False}\n    except BaseException as error:\n        secondary = error\n        close = {\'fd\': fd, \'label\': state[\'label\'], \'closed\': False, \'UNKNOWN\': True,\n                 \'failure\': type(error).__name__ + \':\' + str(error)}\n    if primary is not None or secondary is not None:\n        previous = getattr(primary, \'evidence\', None)\n        first = previous.get(\'firstFailure\') if type(previous) is dict else None\n        if first is None:\n            cause = primary if primary is not None else secondary\n            first = {\'type\': type(cause).__name__, \'reason\': str(cause)}\n        previous_closes = previous.get(\'closeOutcomes\', []) if type(previous) is dict else []\n        evidence = {\'firstFailure\': first, \'closeOutcomes\': [*previous_closes, close],\n                    \'currentOwnedDescriptor\': dict(state), \'priorEvidence\': previous,\n                    \'operationOrReleaseAuthorized\': False}\n        raise OwnedFDProofFailure(first[\'type\'] + \':\' + first[\'reason\'], evidence) from (primary or secondary)\n\ndef readonly_empty(path, pool, seconds=2):\n    """Final whole-root populated sampling follows all distributed PID reads.\n\n    A zero kernel populated event covers descendants, including UID0. Every\n    traversal error, unsupported field, alias, tree change or late read refuses.\n    Caller must separately bind exact owned unit/invocation/current service.\n    """\n    need(type(seconds) in (int, float) and 0 < seconds <= 2, \'cgroup deadline\')\n    started = time.monotonic(); end = started + seconds\n    def clock(): need(time.monotonic() < end, \'cgroup proof deadline expired\')\n    need(type(path) is str and type(pool) is str and pool.startswith(\'/\') and\n         path.startswith(pool + \'/\') and path.rsplit(\'/\', 1)[0] == pool and\n         not any(x in (\'.\', \'..\') for x in path.split(\'/\')), \'exact direct unit/pool path\')\n    parent = Path(\'/sys/fs/cgroup\') / pool.lstrip(\'/\')\n    root = Path(\'/sys/fs/cgroup\') / path.lstrip(\'/\')\n    clock(); ps = parent.lstat()\n    need(stat.S_ISDIR(ps.st_mode) and parent.resolve(strict=True) == parent, \'pool ancestry/type\')\n    try: first = root.lstat()\n    except FileNotFoundError:\n        clock()\n        need(not os.path.lexists(root) and identity(parent.lstat()) == identity(ps) and\n             parent.resolve(strict=True) == parent, \'absent unit group raced\')\n        clock()\n        return {\'empty\': True, \'absent\': True, \'derivedPath\': path, \'groups\': 0,\n                \'processes\': [], \'includesUID0\': True, \'completeTraversal\': True}\n    need(stat.S_ISDIR(first.st_mode) and root.resolve(strict=True) == root, \'unit group alias/type\')\n\n    def read(node, directory_fd=None):\n        clock(); fd = os.open(node if directory_fd is None else node.name,\n                              os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)\n        field_state = {\'label\': str(node), \'fdOpened\': True, \'identity\': None, \'observedBytes\': 0, \'EOF\': False}\n        with owned_fd_evidence(fd, field_state):\n            before = os.fstat(fd); field_state[\'identity\'] = identity(before); need(stat.S_ISREG(before.st_mode), \'cgroup field type\')\n            raw = bytearray()\n            while block := os.read(fd, 4096):\n                clock(); raw.extend(block); field_state[\'observedBytes\'] = len(raw); need(len(raw) <= 65536, \'cgroup field bound\')\n            field_state[\'EOF\'] = True\n            need(identity(before) == identity(os.fstat(fd)) == identity(node.lstat() if directory_fd is None else\n                     os.stat(node.name, dir_fd=directory_fd, follow_symlinks=False)),\n                 \'cgroup field replaced\')\n            clock(); result = bytes(raw)\n        clock(); return result\n\n    def events(node, directory_fd=None):\n        rows = read(node / \'cgroup.events\', directory_fd).splitlines(); result = {}\n        for row in rows:\n            parts = row.split(); need(len(parts) == 2 and parts[0] not in result, \'cgroup events malformed\')\n            result[parts[0]] = parts[1]\n        need(result.get(b\'populated\') in (b\'0\', b\'1\'), \'kernel populated evidence missing\')\n        return result[b\'populated\']\n\n    def inventory():\n        result = {}\n        def failed(error): raise error\n        for folder, dirs, files in os.walk(root, followlinks=False, onerror=failed):\n            clock(); node = Path(folder); st = node.lstat()\n            need(len(result) < 512 and stat.S_ISDIR(st.st_mode) and\n                 node.resolve(strict=True) == node, \'cgroup subtree type/count/alias\')\n            need(\'cgroup.procs\' in files and \'cgroup.events\' in files, \'cgroup subtree evidence incomplete\')\n            for name in dirs: need(not (node / name).is_symlink(), \'cgroup subgroup alias\')\n            result[str(node)] = identity(st)\n        need(result and str(root) in result, \'cgroup inventory absent/incomplete\')\n        clock(); return result\n\n    held_root = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)\n    with owned_fd_evidence(held_root, {\'label\': \'original-unit-directory\', \'fdOpened\': True, \'originalIdentity\': identity(first)}):\n        need(identity(os.fstat(held_root)) == identity(first), \'held root differs from original\')\n        before = inventory(); processes = []; sampled = {}\n        for folder in sorted(before):\n            node = Path(folder); raw = read(node / \'cgroup.procs\'); values = raw.split()\n            need(all(x.isdigit() and int(x) > 0 for x in values), \'PID list malformed\')\n            processes.extend(map(int, values)); need(len(processes) <= 4096, \'PID inventory bound\')\n            sampled[folder] = (raw, events(node))\n        need(inventory() == before and identity(root.lstat()) == identity(first), \'tree changed during first scan\')\n        for folder, (raw, populated) in sampled.items():\n            node = Path(folder)\n            need(read(node / \'cgroup.procs\') == raw, \'PID membership changed during proof\')\n            need(events(node) == populated, \'subgroup populated changed during proof\')\n        need(inventory() == before and identity(root.lstat()) == identity(first), \'final subtree changed\')\n        # This atomic kernel aggregate is deliberately LAST: distributed PID reads\n        # alone can miss a task migrating into an already-read subgroup.\n        final_root_populated = events(root, held_root)\n        need(inventory() == before, \'tree changed after held aggregate sample\')\n        need(identity(os.fstat(held_root)) == identity(first) == identity(root.lstat()) and\n             identity(parent.lstat()) == identity(ps) and root.resolve(strict=True) == root and\n             parent.resolve(strict=True) == parent, \'original root/pool custody changed after aggregate\')\n        clock()\n        result = {\'empty\': not processes and all(x[1] == b\'0\' for x in sampled.values()) and\n                        final_root_populated == b\'0\',\n                \'absent\': False, \'derivedPath\': path, \'groups\': len(before),\n                \'processes\': processes, \'includesUID0\': True, \'completeTraversal\': True,\n                \'finalWholeRootPopulated\': final_root_populated.decode(),\n                \'seconds\': time.monotonic() - started}\n    clock()\n    result[\'seconds\'] = time.monotonic() - started\n    return result\n'
CG_PROOF_SHA = 'b7a706dc8ae19c931bd7f3ff2d6199ae61ff5fd3025edb18160ba1ad1ee2e529'

POOL_PROOF_SOURCE = '"""Bounded readonly current pool proof, no unit/process/cgroup operation."""\n\nimport os,stat,time,json,re,hashlib,ctypes\n\nfrom pathlib import Path\n\nfrom contextlib import contextmanager,ExitStack\n\ndef need(value, why):\n    if not value:\n        raise ValueError(why)\n\ndef identity(st):\n    return tuple(getattr(st, x) for x in (\'st_dev\', \'st_ino\', \'st_mode\', \'st_uid\',\n                 \'st_gid\', \'st_nlink\', \'st_mtime_ns\', \'st_ctime_ns\'))\n\nclass OwnedFDProofFailure(ValueError):\n    def __init__(self, first, evidence):\n        super().__init__(first + "; owned descriptor evidence=" + repr(evidence))\n        self.evidence = evidence\n\ndef owned_fd_evidence(fd, state):\n    primary = None; secondary = None\n    try:\n        yield fd\n    except BaseException as error:\n        primary = error\n    try:\n        os.close(fd)\n        close = {\'fd\': fd, \'label\': state[\'label\'], \'closed\': True, \'UNKNOWN\': False}\n    except BaseException as error:\n        secondary = error\n        close = {\'fd\': fd, \'label\': state[\'label\'], \'closed\': False, \'UNKNOWN\': True,\n                 \'failure\': type(error).__name__ + \':\' + str(error)}\n    if primary is not None or secondary is not None:\n        previous = getattr(primary, \'evidence\', None)\n        first = previous.get(\'firstFailure\') if type(previous) is dict else None\n        if first is None:\n            cause = primary if primary is not None else secondary\n            first = {\'type\': type(cause).__name__, \'reason\': str(cause)}\n        previous_closes = previous.get(\'closeOutcomes\', []) if type(previous) is dict else []\n        evidence = {\'firstFailure\': first, \'closeOutcomes\': [*previous_closes, close],\n                    \'currentOwnedDescriptor\': dict(state), \'priorEvidence\': previous,\n                    \'operationOrReleaseAuthorized\': False}\n        raise OwnedFDProofFailure(first[\'type\'] + \':\' + first[\'reason\'], evidence) from (primary or secondary)\n\nclass KernelIO:\n    """Nofollow kernel read adapter; injected models never invoke these calls."""\n    def open_dir(self,path,parent=None):return os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)\n    def open_field(self,fd,name):return os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)\n    def close(self,fd):os.close(fd)\n    def fd_id(self,fd):return identity(os.fstat(fd))\n    def path_id(self,path):return identity(os.lstat(path))\n    def child_id(self,fd,name):return identity(os.stat(name,dir_fd=fd,follow_symlinks=False))\n    def names(self,fd):return os.listdir(fd)\n    def read(self,fd,count):return os.read(fd,count)\n    def magic(self,fd):\n        result=(ctypes.c_long*32)();need(ctypes.CDLL(None,use_errno=True).fstatfs(fd,ctypes.byref(result))==0,\'kernel filesystem unavailable\');return result[0]\n\n\ndef cpus(raw):\n    text=raw.decode() if isinstance(raw,bytes) else raw;result=set()\n    need(type(text) is str and text.strip(),\'CPU set unavailable\')\n    for word in text.strip().split(\',\'):\n        if \'-\' in word:\n            pair=word.split(\'-\');need(len(pair)==2 and all(x.isdecimal() for x in pair),\'CPU range syntax\');a,b=map(int,pair);need(0<=a<=b<4096,\'CPU range bound\');result.update(range(a,b+1))\n        else:need(word.isdecimal() and 0<=int(word)<4096,\'CPU syntax\');result.add(int(word))\n    return result\n\n\ndef readonly_pool(pool,props,reservations,prefix,reread_pool,reread_unit,seconds=5,io=None,machine_bindings=None):\n    """Current complete pool epoch; no stop, release, rearm or configuration call."""\n    need(type(seconds) in (int,float) and 0<seconds<=5,\'pool proof deadline\');started=time.monotonic();end=started+seconds;io=KernelIO() if io is None else io\n    def clock():need(time.monotonic()<end,\'pool proof deadline expired\')\n    need(type(pool) is str and pool.startswith(\'/\') and pool.rsplit(\'/\',1)[-1]==\'opemos-vm-pool.slice\' and not any(x in (\'.\',\'..\') for x in pool.split(\'/\')),\'exact current pool path\')\n    need(pool==\'/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice\',\'canonical managed pool parent boundary\')\n    need(type(prefix) is str and re.fullmatch(r\'opemos-testq-[0-9a-f]{12}-\',prefix),\'state-root unit prefix\')\n    pool_keys={\'LoadState\',\'ActiveState\',\'SubState\',\'ControlGroup\',\'MemoryMax\',\'MemorySwapMax\',\'CPUQuotaPerSecUSec\',\'AllowedCPUs\'}\n    def pool_meta(value):\n        need(pool_keys<=set(value) and value[\'LoadState\']==\'loaded\' and value[\'ActiveState\']==\'active\' and value[\'SubState\']==\'active\' and value[\'ControlGroup\']==pool and value[\'MemoryMax\']==str(32*1024**3) and value[\'MemorySwapMax\']==\'0\' and value[\'CPUQuotaPerSecUSec\']==\'10s\' and cpus(value[\'AllowedCPUs\'])==set(range(10)),\'current pool systemd budgets/presence\')\n        return {k:value[k] for k in sorted(pool_keys)}\n    original_props=pool_meta(props);need(type(reservations) is list and len(reservations)<=10,\'current running reservation count\')\n    reserved={};units={};unknown=[];used=set();resources=set();memory=0\n    for row in reservations:\n        unit=row[\'unit\'];need(type(unit) is str and re.fullmatch(re.escape(prefix)+r\'[0-9a-f]{32}\\.service\',unit) and unit not in reserved,\'unique recorded running unit\')\n        need(type(row[\'cpus\']) is list and row[\'cpus\'] and all(type(c) is int for c in row[\'cpus\']) and len(set(row[\'cpus\']))==len(row[\'cpus\']) and set(row[\'cpus\'])<=set(range(10)) and not used.intersection(row[\'cpus\']),\'disjoint assigned current CPUs\');used.update(row[\'cpus\']);need(type(row[\'memory\']) is int and row[\'memory\']>0,\'current assigned memory\');memory+=row[\'memory\'];need(memory<=32*1024**3,\'reserved memory pool sum\')\n        need(type(row[\'resources\']) is list and row[\'resources\'] and not resources.intersection(row[\'resources\']),\'disjoint retained resource leases\');resources.update(row[\'resources\']);reserved[unit]=row\n        clock();current=reread_unit(unit);clock()\n        if current.get(\'LoadState\')==\'not-found\':unknown.append(unit);units[unit]={\'known\':False,\'properties\':dict(current)};continue\n        need(current.get(\'LoadState\')==\'loaded\',\'unit current load unknown\');invocation=current.get(\'InvocationID\');known=row.get(\'invocation\') is not None\n        if not known:\n            need(current.get(\'ActiveState\') in (\'activating\',\'active\',\'deactivating\',\'reloading\',\'inactive\',\'failed\') and str(current.get(\'MainPID\',\'\')).isdecimal(),\'unbound loaded current state/MainPID unavailable\')\n            unknown.append(unit);units[unit]={\'known\':False,\'properties\':dict(current)};continue\n        need(type(invocation) is str and re.fullmatch(r\'[0-9a-f]{32}\',invocation) and invocation==row[\'invocation\'],\'recorded current unit invocation mismatch\')\n        need(current.get(\'ControlGroup\') in (\'\',pool+\'/\'+unit),\'exact unit/current parent cgroup\');need(current.get(\'ActiveState\') in (\'activating\',\'active\',\'deactivating\',\'reloading\',\'inactive\',\'failed\') and str(current.get(\'MainPID\',\'\')).isdecimal(),\'current unit state/MainPID evidence\')\n        need(current.get(\'MemoryMax\')==str(row.get(\'controllerMemory\',row[\'memory\'])) and current.get(\'MemorySwapMax\')==\'0\' and current.get(\'CPUQuotaPerSecUSec\')==str(len(row[\'cpus\']))+\'s\' and cpus(current.get(\'AllowedCPUs\',\'\'))==set(row[\'cpus\']),\'current unit systemd assigned budgets\')\n        units[unit]={\'known\':True,\'properties\':dict(current)}\n    machine_bindings=[] if machine_bindings is None else machine_bindings\n    need(type(machine_bindings)is list and len(machine_bindings)<=1,\'one exact exclusive GPU domain mapping\')\n    vm_by_slice={}\n    for binding in machine_bindings:\n        request=binding[\'request\'];owner=request[\'unit\'];need(owner in units and reserved[owner][\'invocation\']==request[\'invocation\'] and (units[owner][\'known\'] or (binding[\'phase\']==\'CLOSED\' and units[owner][\'properties\'].get(\'LoadState\')==\'not-found\' and units[owner][\'properties\'].get(\'MainPID\')==\'0\' and units[owner][\'properties\'].get(\'InvocationID\')==\'\' and binding[\'lease\'][\'closed\'] is True and binding[\'lease\'][\'restored\'] is True)),\'libvirt requires exact known current queue InvocationID\')\n        need(reserved[owner][\'cpus\']==request[\'cpus\'] and reserved[owner][\'memory\']==10*1024**3 and reserved[owner].get(\'controllerMemory\')==2*1024**3 and \'omen-iommu-group-1\' in reserved[owner][\'resources\'],\'one exact10GiB controller2 plusVM8 reservation\')\n        token=owner.rsplit(\'-\',1)[1].removesuffix(\'.service\');expected=\'opemos-vm-pool-libvirt\'+token+\'.slice\'\n        need(request[\'jobToken\']==token and request[\'vmSlice\']==expected and request[\'domainMemory\']==8*1024**3 and request[\'controllerMemory\']==2*1024**3 and request[\'reservationMemory\']==10*1024**3 and request[\'partition\']==\'/opemos/vm/pool/libvirt\'+token,\'deterministic exact libvirt partition budget\')\n        need(expected not in vm_by_slice and binding[\'phase\'] in (\'PREPARED\',\'ACTIVE\',\'CLOSED\'),\'unique known libvirt phase\')\n        vm_by_slice[expected]=binding\n    def vm_binding(path):\n        relative=path[len(root):].strip(\'/\');first=relative.split(\'/\')[0] if relative else None\n        return vm_by_slice.get(first)\n\n    stack=ExitStack();fd_states=[];held={};field_reads=0\n    # Reuse the exact canonical first-error/close evidence context with this IO\n    # adapter; only its close syscall is injected for synthetic faultcases.\n    @contextmanager\n    def owned(fd,label):\n        primary=None;secondary=None\n        try:yield fd\n        except BaseException as error:primary=error\n        try:io.close(fd);close={\'fd\':fd,\'label\':label,\'closed\':True,\'UNKNOWN\':False}\n        except BaseException as error:secondary=error;close={\'fd\':fd,\'label\':label,\'closed\':False,\'UNKNOWN\':True,\'failure\':type(error).__name__+\':\'+str(error)}\n        fd_states.append(close)\n        if primary is not None or secondary is not None:\n            previous=getattr(primary,\'evidence\',None);first=previous.get(\'firstFailure\') if type(previous) is dict else None\n            if first is None:\n                cause=primary if primary is not None else secondary;first={\'type\':type(cause).__name__,\'reason\':str(cause)}\n            previous_closes=previous.get(\'closeOutcomes\',[]) if type(previous) is dict else []\n            if primary is not None and secondary is None and type(previous) is dict:\n                previous[\'closeOutcomes\'].append(close);raise primary\n            evidence={\'firstFailure\':first,\'closeOutcomes\':[*previous_closes,close],\'currentOwnedDescriptor\':{\'label\':label,\'fdOpened\':True},\'priorEvidenceSummary\':None if previous is None else {\'firstFailure\':previous[\'firstFailure\'],\'priorCloseCount\':len(previous_closes)},\'operationOrReleaseAuthorized\':False}\n            raise OwnedFDProofFailure(first[\'type\']+\':\'+first[\'reason\'],evidence) from (primary or secondary)\n    def dir_open(path,parent=None,label=None):\n        clock();fd=io.open_dir(path,parent);stack.enter_context(owned(fd,label or str(path)));meta=io.fd_id(fd);need(stat.S_ISDIR(meta[2]),\'kernel directory type\');return fd,meta\n    def read(fd,name,record=None,expected=None):\n        nonlocal field_reads\n        clock();field_reads+=1;need(field_reads<=1000000,\'whole pool field-read count\');file=io.open_field(fd,name)\n        with owned(file,name):\n            before=io.fd_id(file);need(stat.S_ISREG(before[2]),\'kernel field regular type\');need(expected is None or before==expected,\'original held budget field identity changed\')\n            if record is not None:record[name]=before\n            raw=bytearray();count=0\n            while True:\n                clock();need(count<32,\'kernel small read-call cap\');part=io.read(file,min(4096,65537-len(raw)));count+=1\n                if not part:break\n                raw.extend(part);need(len(raw)<=65536,\'kernel small field bound\')\n            need(before==io.fd_id(file)==io.child_id(fd,name),\'kernel field descriptor/path changed\');return bytes(raw)\n    def ids(raw):\n        parts=raw.split();need(all(x.isdigit() and int(x)>0 for x in parts),\'kernel PID/TID list malformed\');values=list(map(int,parts));need(len(values)==len(set(values)) and len(values)<=4096,\'kernel group PID/TID bound\');return values\n    def populated(fd):\n        value={}\n        for line in read(fd,\'cgroup.events\').splitlines():\n            words=line.split();need(len(words)==2 and words[0] not in value,\'kernel events malformed/duplicate\');value[words[0]]=words[1]\n        need(value.get(b\'populated\') in (b\'0\',b\'1\'),\'kernel populated unavailable\');return value[b\'populated\']\n    def budgets(fd,memory,allowed,expected=None):\n        record={}\n        def field(name):return read(fd,name,record,None if expected is None else expected[name])\n        need(field(\'memory.max\').strip()==str(memory).encode() and field(\'memory.swap.max\').strip()==b\'0\' and cpus(field(\'cpuset.cpus.effective\'))==set(allowed),\'current kernel memory/swap/CPU budget\');pair=field(\'cpu.max\').split();need(len(pair)==2 and all(x.isdigit() for x in pair) and int(pair[1])>0 and int(pair[0])==len(allowed)*int(pair[1]),\'current kernel CPU quota\');return record\n    def scan(root,rootfd,opening):\n        found={};pending=[(root,rootfd,0)]\n        while pending:\n            clock();path,fd,depth=pending.pop();need(len(found)<5121 and depth<=128,\'complete pool tree count/depth\');meta=io.fd_id(fd);need(meta==io.path_id(path),\'held tree directory identity/custody\');names=io.names(fd);need(type(names) is list and len(names)<=1024 and len(names)==len(set(names)),\'bounded complete group directory listing\');need({\'cgroup.procs\',\'cgroup.threads\',\'cgroup.events\',\'cgroup.type\'}<=set(names),\'group evidence missing\');children=[]\n            for name in sorted(names):\n                need(type(name) is str and name not in (\'.\',\'..\') and \'/\' not in name and \'\\0\' not in name,\'group entry name\');child=io.child_id(fd,name);need(not stat.S_ISLNK(child[2]),\'pool subtree alias\');need(stat.S_ISREG(child[2]) or stat.S_ISDIR(child[2]),\'pool entry unexpected type\')\n                if stat.S_ISDIR(child[2]):\n                    full=path+\'/\'+name;children.append((name,child))\n                    if opening:newfd,seen=dir_open(name,fd,full);need(seen==child,\'subtree open identity\');held[full]=(newfd,seen)\n                    else:need(full in held and io.fd_id(held[full][0])==child,\'tree added/replaced\')\n                    pending.append((full,held[full][0],depth+1))\n            found[path]={\'identity\':meta,\'children\':children,\'names\':sorted(names)}\n        return found\n    def first_pid_directory_identity(procfd,tid):\n        # This marker is created ONLY at the final held PID-directory custody\n        # observation. It never turns a partial process into a complete identity.\n        try:return io.child_id(procfd,str(tid))\n        except OSError as error:\n            if error.errno in (2,3) and error.filename==str(tid):\n                error._opemos_proc_identity_site=(tid,\'/proc/\'+str(tid),\'pid-directory-identity\')\n            raise\n    def proc_once(tid):\n        clock();procfd=io.open_dir(\'/proc\')\n        with owned(procfd,\'proc-root\'):\n            procmeta=io.fd_id(procfd);need(io.magic(procfd)==0x9fa0,\'current proc filesystem\');\n            try:pidfd=io.open_dir(str(tid),procfd)\n            except OSError as error:\n                if error.errno not in (2,3):raise\n                error.evidence={\'firstFailure\':{\'type\':\'TransientProcObservation\',\'errno\':error.errno,\'tid\':tid,\'path\':\'/proc/\'+str(tid),\'stage\':\'pid-directory-open\'},\'closeOutcomes\':[],\'operationOrReleaseAuthorized\':False};raise\n            with owned(pidfd,\'proc-\'+str(tid)):\n                pidmeta=io.fd_id(pidfd);statraw=read(pidfd,\'stat\').decode();parts=statraw[statraw.rfind(\')\')+2:].split();need(len(parts)>=20 and int(statraw.split(\'(\',1)[0])==tid,\'current PID/TID stat schema\');status=read(pidfd,\'status\').decode().splitlines();u=[line.split()[1:] for line in status if line.startswith(\'Uid:\')];tg=[line.split()[1:] for line in status if line.startswith(\'Tgid:\')];need(len(u)==len(tg)==1 and len(u[0])==4 and all(x.isdecimal() for x in u[0]) and len(tg[0])==1 and tg[0][0].isdecimal(),\'current UID0-inclusive status\');cg=read(pidfd,\'cgroup\').decode().splitlines();need(len(cg)==1 and cg[0].startswith(\'0::/\'),\'current PID/TID unified cgroup\');again=read(pidfd,\'stat\').decode();againparts=again[again.rfind(\')\')+2:].split();need(int(againparts[19])==int(parts[19]) and io.fd_id(pidfd)==pidmeta and first_pid_directory_identity(procfd,tid)==pidmeta,\'PID/TID start/parent directory changed\');value={\'tid\':tid,\'start\':int(parts[19]),\'ppid\':int(parts[1]),\'tgid\':int(tg[0][0]),\'uids\':list(map(int,u[0])),\'cgroup\':cg[0][3:]}\n        clock();return value\n    def proc(tid,previous=None):\n        # A first observation has no trustworthy prior identity. Preserve its\n        # original refusal. Only revalidation of a complete parsed task can\n        # produce this typed monitoring-only observation.\n        try:return proc_once(tid)\n        except (OSError,OwnedFDProofFailure) as error:\n            if previous is None:\n                # No complete task identity exists here. This is strictly a\n                # monitoring-only observation, never a task-admission result.\n                cause=error;seen=set();missing=None\n                while cause is not None and id(cause) not in seen:\n                    seen.add(id(cause))\n                    if isinstance(cause,OSError):\n                        if cause.errno in (2,3) and (cause.filename in (\'stat\',\'status\',\'cgroup\') or (cause.filename==str(tid) and getattr(cause,\'_opemos_proc_identity_site\',None)==(tid,\'/proc/\'+str(tid),\'pid-directory-identity\'))):missing=cause\n                        break\n                    cause=cause.__cause__\n                if missing is None:raise\n                evidence=getattr(error,\'evidence\',None)\n                need(type(evidence) is dict and type(evidence.get(\'closeOutcomes\')) is list and evidence[\'closeOutcomes\'] and all(x.get(\'closed\') is True and x.get(\'UNKNOWN\') is False for x in evidence[\'closeOutcomes\']),\'first-read observation descriptors must be closed\')\n                need(any(x.get(\'label\')==\'proc-\'+str(tid) for x in evidence[\'closeOutcomes\']),\'actual held PID directory provenance required\')\n                preserved=evidence[\'firstFailure\']\n                typed={\'type\':\'TransientProcFirstReadObservation\',\'reason\':\'first proc field vanished before complete task observation\',\'errno\':missing.errno,\'tid\':tid,\'path\':\'/proc/\'+str(tid),\'stage\':\'first-task-field-read\',\'field\':\'pid-directory-identity\' if missing.filename==str(tid) else missing.filename,\'originalFailure\':preserved,\'originalStart\':\'UNKNOWN_FIRST_OBSERVATION_INCOMPLETE\'}\n                raise OwnedFDProofFailure(\'TransientProcFirstReadObservation: incomplete identity retained, monitoring only\',dict(evidence,firstFailure=typed)) from error\n            cause=error;seen=set();missing=None\n            while cause is not None and id(cause) not in seen:\n                seen.add(id(cause))\n                if isinstance(cause,OSError):\n                    if cause.errno in (2,3) and cause.filename in (\'stat\',\'status\',\'cgroup\',str(tid)):missing=cause\n                    break\n                cause=cause.__cause__\n            if missing is None:raise\n            need(type(previous) is dict and set(previous)=={\'tid\',\'start\',\'ppid\',\'tgid\',\'uids\',\'cgroup\'} and previous[\'tid\']==tid,\'complete prior task observation required\')\n            evidence=getattr(error,\'evidence\',None)\n            need(type(evidence) is dict and type(evidence.get(\'closeOutcomes\')) is list and evidence[\'closeOutcomes\'] and all(x.get(\'closed\') is True and x.get(\'UNKNOWN\') is False for x in evidence[\'closeOutcomes\']),\'revalidation observation descriptors must be closed\')\n            preserved=evidence[\'firstFailure\']\n            evidence=dict(evidence,firstFailure={\'type\':\'TransientProcRevalidationObservation\',\'reason\':\'previously observed proc task vanished during revalidation\',\'errno\':missing.errno,\'tid\':tid,\'path\':\'/proc/\'+str(tid),\'stage\':\'previous-task-revalidation\',\'process\':dict(previous),\'originalFailure\':preserved})\n            raise OwnedFDProofFailure(\'TransientProcRevalidationObservation: retained original proc failure\',evidence) from error\n    def leader_present(value,pids,tids,path,unit,pop):\n        if value[\'tgid\'] in pids:return\n        need(unit in units and units[unit][\'known\'],\'thread leader requires exact original unit\')\n        error=ValueError(\'thread group leader missing\')\n        error.evidence={\'firstFailure\':{\'type\':\'TransientThreadLeaderObservation\',\'reason\':\'thread group leader missing\',\'stage\':\'thread-leader-coverage\',\'unit\':unit,\'invocation\':reserved[unit][\'invocation\'],\'group\':path[len(\'/sys/fs/cgroup\'):],\'sampledPids\':list(pids),\'sampledTids\':list(tids),\'sampledPopulated\':pop.decode(),\'process\':dict(value)},\'closeOutcomes\':[],\'operationOrReleaseAuthorized\':False}\n        raise error\n    try:\n        basefd,basemeta=dir_open(\'/\',label=\'canonical-host-root\');need(basemeta==io.path_id(\'/\'),\'canonical host root custody\');chain=[(\'/\',basefd,basemeta)];path=\'\';fd=basefd\n        for component in (\'sys\',\'fs\',\'cgroup\'):\n            child=io.child_id(fd,component);need(stat.S_ISDIR(child[2]) and child[3]==child[4]==0,\'canonical cgroup mount ancestor type/owner\');newpath=path+\'/\'+component;fd,meta=dir_open(component,fd,newpath);need(meta==child==io.path_id(newpath),\'canonical cgroup mount ancestor custody\');path=newpath;chain.append((path,fd,meta))\n        mount,mountmeta=fd,meta;need(io.magic(mount)==0x63677270 and mountmeta==io.path_id(\'/sys/fs/cgroup\'),\'canonical cgroup2 mount/custody\');need(mountmeta[3]==mountmeta[4]==0,\'kernel cgroup mount ownership\')\n        for name in pool.lstrip(\'/\').split(\'/\'):\n            child=io.child_id(fd,name);need(stat.S_ISDIR(child[2]) and child[3]==child[4]==0,\'canonical present root/parent type/owner\');fd,meta=dir_open(name,fd,path+\'/\'+name);need(meta==child,\'pool parent/root open custody\');path+=\'/\'+name;chain.append((path,fd,meta))\n        # Unknown logical leases cannot bound a positive current manager process.\n        # Inspect public identity independently even when the pool tree is empty;\n        # refuse rather than adopt, whitelist, bind, stop or release that work.\n        for unit,value in units.items():\n            if not value[\'known\'] and value[\'properties\'].get(\'LoadState\')==\'loaded\':\n                main=int(value[\'properties\'][\'MainPID\'])\n                if main>0:\n                    observed=proc(main)\n                    need(observed[\'tgid\']==main and observed[\'cgroup\']==pool+\'/\'+unit,\'unbound positive MainPID outside exact retained unit boundary\')\n                    need(proc(main)==observed,\'unbound positive MainPID current identity changed\')\n                    need(False,\'unbound positive MainPID cannot authorize managed admission; unknown lease retained\')\n                need(value[\'properties\'].get(\'ControlGroup\') in (\'\',pool+\'/\'+unit),\'unbound loaded current unit boundary unknown\')\n        root=path;rootfd=fd;held[root]=(rootfd,meta);before=scan(root,rootfd,True);root_budget_ids=budgets(rootfd,32*1024**3,list(range(10)));unit_budget_ids={};samples={};tasks={};procs={};main_snapshots={}\n        for path in sorted(before):\n            group=held[path][0];binding=vm_binding(path);ctype=read(group,\'cgroup.type\').strip()\n            need(ctype==b\'domain\' or(binding is not None and ctype in(b\'domain threaded\',b\'threaded\')),\'threaded type only inside exact bound libvirt partition\')\n            pids=[] if ctype==b\'threaded\' else ids(read(group,\'cgroup.procs\'));tids=ids(read(group,\'cgroup.threads\'));pop=populated(group)\n            if binding is None:need(set(pids)<=set(tids),\'cgroup process/thread coverage\')\n            samples[path]={\'pids\':pids,\'tids\':tids,\'populated\':pop,\'type\':ctype};need(len(tasks)+len(tids)<=40960,\'whole pool task bound\')\n            relative=path[len(root):].strip(\'/\');unit=relative.split(\'/\')[0] if relative else None\n            if binding is not None:\n                unit=binding[\'request\'][\'unit\'];vmroot=root+\'/\'+binding[\'request\'][\'vmSlice\'];scope=binding[\'scope\']\n                if path!=vmroot:\n                    need(scope is not None and (path==vmroot+\'/\'+scope or path.startswith(vmroot+\'/\'+scope+\'/\')),\'unknown/foreign libvirt partition subtree\')\n                if path==vmroot:\n                    need(not pids and not tids and ctype==b\'domain\',\'VM partition direct workload/threaded root refused\')\n                    budgets(group,8*1024**3,binding[\'request\'][\'cpus\'])\n                if tids:need(binding[\'phase\']==\'ACTIVE\' and path!=vmroot,\'Only exact live domain tasks below mapped scope\')\n            if tids:\n                need(unit in units and units[unit][\'known\'],\'unmanaged or unbound current workload including UID0\');need(units[unit][\'properties\'].get(\'ControlGroup\')==pool+\'/\'+unit,\'populated managed unit current ControlGroup absent/conflicting\')\n            if binding is None and relative and \'/\' not in relative and unit in units and units[unit][\'known\']:unit_budget_ids[unit]=budgets(group,reserved[unit].get(\'controllerMemory\',reserved[unit][\'memory\']),reserved[unit][\'cpus\'])\n            for tid in tids:\n                need(tid not in tasks,\'task duplicated across groups\');value=proc(tid);need(value[\'cgroup\']==path[len(\'/sys/fs/cgroup\'):],\'current task cgroup membership mismatch\');\n                if binding is None:leader_present(value,pids,tids,path,unit,pop)\n                else:\n                    leader=binding[\'leader\'];need(value[\'tgid\']==leader[\'pid\'] and value[\'uids\']==[leader[\'uid\']]*4,\'Foreign process/TGID/UID in domain thread subtree\')\n                tasks[tid]=value\n        for unit,current in units.items():\n            if not current[\'known\']:continue\n            main=int(current[\'properties\'][\'MainPID\'])\n            if main>0:\n                observed=proc(main);need(observed[\'tgid\']==main and observed[\'cgroup\']==pool+\'/\'+unit,\'positive MainPID current exact unit membership\');need(main in tasks and tasks[main]==observed,\'positive MainPID missing or identity differs from complete tree\');main_snapshots[unit]={\'process\':observed,\'invocation\':reserved[unit][\'invocation\']}\n        for name,binding in vm_by_slice.items():\n            path=root+\'/\'+name\n            need(path in held,\'Exact bound VM partition must exist\')\n            if binding[\'phase\']==\'ACTIVE\':\n                lead=binding[\'leader\'];observed=proc(lead[\'pid\'])\n                need(lead[\'pid\'] in tasks and observed==tasks[lead[\'pid\']] and observed[\'start\']==lead[\'start\'] and observed[\'uids\']==[lead[\'uid\']]*4 and observed[\'cgroup\'].startswith(pool+\'/\'+name+\'/\'+binding[\'scope\']),\'Positive original libvirt leader PID/start/UID/scope\')\n            else:need(populated(held[path][0])==b\'0\',\'Inactive domain partition populated/unknown\')\n        need(scan(root,rootfd,False)==before,\'pool tree changed during distributed read\')\n        for path,sample in samples.items():\n            group=held[path][0];need(read(group,\'cgroup.type\').strip()==sample[\'type\'] and ([] if sample[\'type\']==b\'threaded\' else ids(read(group,\'cgroup.procs\')))==sample[\'pids\'] and ids(read(group,\'cgroup.threads\'))==sample[\'tids\'] and populated(group)==sample[\'populated\'],\'current group membership/populated race\')\n            expected=any(value[\'tids\'] for name,value in samples.items() if name==path or name.startswith(path+\'/\'));need((sample[\'populated\']==b\'1\')==expected,\'kernel group aggregate disagrees with complete task tree\')\n        for tid,value in tasks.items():need(proc(tid,value)==value,\'PID-start/UID/cgroup identity changed\')\n        for unit,value in units.items():clock();need(reread_unit(unit)==value[\'properties\'],\'current unit invocation/properties race\')\n        need(pool_meta(reread_pool())==original_props,\'current pool systemd budget/path race\');budgets(rootfd,32*1024**3,list(range(10)),root_budget_ids)\n        for unit,ids0 in unit_budget_ids.items():budgets(held[root+\'/\'+unit][0],reserved[unit].get(\'controllerMemory\',reserved[unit][\'memory\']),reserved[unit][\'cpus\'],ids0)\n        for name,binding in vm_by_slice.items():budgets(held[root+\'/\'+name][0],8*1024**3,binding[\'request\'][\'cpus\'])\n        for unit,snapshot in main_snapshots.items():need(proc(snapshot[\'process\'][\'tid\'],snapshot[\'process\'])==snapshot[\'process\'] and snapshot[\'invocation\']==units[unit][\'properties\'][\'InvocationID\'],\'final MainPID start/UID/cgroup/invocation changed\')\n        need(scan(root,rootfd,False)==before,\'final whole tree changed\')\n        for path,fd,meta in chain:need(io.fd_id(fd)==meta==io.path_id(path),\'original pool/root/parent custody race\')\n        # LAST distributed checks cover every unknown direct subtree atomically,\n        # then the final held whole-pool kernel aggregate includes UID0 children.\n        for path,sample in samples.items():\n            relative=path[len(root):].strip(\'/\')\n            if relative and \'/\' not in relative and relative not in vm_by_slice and (relative not in units or not units[relative][\'known\']):need(populated(held[path][0])==b\'0\',\'unmanaged subtree final aggregate nonempty\')\n        need(not ids(read(rootfd,\'cgroup.procs\')) and not ids(read(rootfd,\'cgroup.threads\')),\'direct pool unmanaged task appeared\')\n        last=populated(rootfd);need((last==b\'1\')==bool(tasks),\'last kernel whole pool aggregate raced\');need(tasks or last==b\'0\',\'zero jobs require independently current whole pool empty\')\n        for path,fd,meta in chain:need(io.fd_id(fd)==meta==io.path_id(path),\'held aggregate root/parent custody changed\')\n        clock();result={\'admitted\':True,\'libvirtDomains\':machine_bindings,\'poolPresent\':True,\'canonicalPool\':pool,\'groups\':len(before),\'tasks\':list(tasks.values()),\'includesUID0\':True,\'completeBoundedTraversal\':True,\'lastKernelWholePoolPopulated\':last.decode(),\'knownInvocations\':{u:reserved[u][\'invocation\'] for u,v in units.items() if v[\'known\']},\'unknownReservationsRetained\':unknown,\'currentWholePoolEmpty\':not tasks and last==b\'0\',\'positiveMainPIDProofs\':main_snapshots,\'unitProperties\':units,\'completedMonotonic\':time.monotonic(),\'systemdPoolProperties\':original_props,\'rootParentCustody\':[(p,list(m)) for p,f,m in chain],\'fieldReads\':field_reads,\'operationOrReleaseAuthorized\':False,\'stopOrRearmPerformed\':False}\n    except BaseException:\n        stack.__exit__(*__import__(\'sys\').exc_info());raise\n    else:stack.close();clock();result[\'allOwnedDescriptorsClosed\']=all(x[\'closed\'] for x in fd_states);result[\'closeOutcomes\']=fd_states;result[\'seconds\']=time.monotonic()-started;return result\n'
POOL_PROOF_SHA = '1e38e2fe3aaeedaac9fe3492e93bc6b788fe7afbc11594323abce6f0195051aa'

class PoolAdmissionFailure(ValueError):
    def __init__(self, first, evidence):
        self.evidence = evidence
        super().__init__("Current pool admission refused: " + first)

_RAW_SYSTEMCTL = systemctl
_EXPECTED_INVOCATION_CONTEXT = None
_READONLY_BOUNDARY_PREPARATION = False
_EFFECT_FIELDS = ("LoadState", "ActiveState", "SubState", "InvocationID", "ControlGroup", "MainPID", "Result", "ExecMainCode", "ExecMainStatus")


def exact_unit_observation(backend, unit):
    args = ["show", unit]
    for field in _EFFECT_FIELDS:
        args.extend(("-p", field))
    return _RAW_SYSTEMCTL(*args, manager=backend.cfg.get("manager", "user"))


def recent_boundary(proof, observed_at):
    now = time.monotonic()
    require(type(proof.get("completedMonotonic")) in (int, float) and
            0 <= now - proof["completedMonotonic"] <= 1 and
            0 <= now - observed_at <= 1, "Current effect proof/observation expired; reservation retained")


from contextlib import contextmanager

@contextmanager
def immutable_ledger_transaction(db):
    # Acquire every potentially blocking DB lock BEFORE final manager observation.
    # Retain the writer lock through the effect: no independent writer can change
    # the immutable original ledger between its last read and the operation.
    require(not db.in_transaction, "Effect requires its own immutable ledger transaction")
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        db.rollback()
        raise
    else:
        db.commit()


def boundary_pool_epoch(db, backend):
    global _READONLY_BOUNDARY_PREPARATION
    require(not _READONLY_BOUNDARY_PREPARATION, "Nested current pool preparation unsupported")
    _READONLY_BOUNDARY_PREPARATION = True
    try:
        return fresh_pool_epoch(db, backend)
    finally:
        _READONLY_BOUNDARY_PREPARATION = False


class ExpectedInvocation:
    def __init__(self, backend, db, row):
        self.backend, self.db = backend, db
        self.row = dict(row)
        self.bound = json.loads(canonical(row.get("_poolBinding")))
        require(type(self.bound) is dict and self.bound["unit"] == row["unit"] and self.bound["job_id"] == row["id"] and self.bound["prefix"] == backend.prefix and self.bound["stateRoot"] == str(backend.root), "Original immutable invocation ledger unavailable")
        self.unit, self.invocation = row["unit"], self.bound["invocation"]
        backend.owned_unit(self.unit)
        require(type(self.invocation) is str and re.fullmatch(r"[0-9a-f]{32}", self.invocation), "Original invocation unavailable")

    def ledger_current(self):
        row = self.db.execute("SELECT * FROM jobs WHERE id=?", (self.row["id"],)).fetchone()
        saved = self.db.execute("SELECT value FROM pool_unit_bindings WHERE job_id=?", (self.row["id"],)).fetchone()
        require(row is not None and row["state"] == self.row["state"] and row["state"] in ("running", "terminal_cleanup") and row["unit"] == self.unit and row["spec"] == self.row["spec"] and row["cpus"] == self.row["cpus"] and saved is not None and json.loads(saved[0]) == self.bound, "Original invocation/job ledger changed; reservation retained")

    @contextmanager
    def boundary(self, require_empty=False, capture_epoch=False):
        with immutable_ledger_transaction(self.db):
            self.ledger_current()
            rows, proof = boundary_pool_epoch(self.db, self.backend)
            require(proof.get("admitted") is True and self.unit not in proof["unknownReservationsRetained"], "Original invocation current whole pool proof unknown")
            current_row = next((r for r in rows if r["id"] == self.row["id"]), None)
            require(current_row is not None and current_row.get("_poolBinding") == self.bound, "Current enriched original invocation binding changed")
            pool = proof.get("canonicalPool")
            require(pool == "/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice", "Current exact managed pool unavailable")
            unit_epoch = proof["unitProperties"][self.unit]["properties"]
            if require_empty:
                require(type(proof.get("tasks")) is list and not any(t["cgroup"] == pool + "/" + self.unit or t["cgroup"].startswith(pool + "/" + self.unit + "/") for t in proof["tasks"]), "Final whole pool proof has original unit descendants")
            if capture_epoch:
                self.terminal_epoch = terminal_pool_epoch(self.db, rows, proof)
            self.ledger_current()
            # No other manager, input, kernel, ledger read, closure, or log callback
            # after this FINAL exact-unit query and before the caller's effect.
            observed_at = time.monotonic()
            props = exact_unit_observation(self.backend, self.unit)
            require(props.get("LoadState") == "loaded" and props.get("InvocationID") == self.invocation and props.get("ControlGroup") in ("", pool + "/" + self.unit), "Current actual effect is not original immutable unit invocation; reservation retained")
            require(all(props.get(k) == unit_epoch.get(k) for k in ("LoadState", "InvocationID", "ControlGroup", "MainPID", "ActiveState", "SubState")), "Final original unit differs from complete current pool epoch")
            recent_boundary(proof, observed_at)
            yield props

    @contextmanager
    def prepare_terminal(self):
        # No effect permission is yielded. Full receipts/digests are prepared
        # while the unchanged complete ledger is write-locked, before live fence.
        with immutable_ledger_transaction(self.db):
            self.ledger_current()
            rows, proof = boundary_pool_epoch(self.db, self.backend)
            self.terminal_epoch = terminal_pool_epoch(self.db, rows, proof)
            yield

    def recheck_terminal(self, prepared, expected_manager, require_empty):
        require(self.db.in_transaction, "Terminal live fence requires retained writer lock")
        self.ledger_current()
        rows, pool = boundary_pool_epoch(self.db, self.backend)
        current = terminal_pool_epoch(self.db, rows, pool)
        # Same complete comparison, but receipt SHA/JSON work was already done.
        verify_terminal_pool_transition(prepared, current, self.row, False, receipt_hashes=False)
        require(pool['canonicalPool'] == '/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice',
                "Current terminal canonical pool")
        if require_empty:
            path=pool['canonicalPool']+'/'+self.unit
            require(not any(t['cgroup']==path or t['cgroup'].startswith(path+'/') for t in pool['tasks']),
                    "Current terminal own descendants remain")
        self.ledger_current()
        observed=time.monotonic()
        actual=exact_unit_observation(self.backend,self.unit)
        require(all(actual.get(k)==expected_manager.get(k) for k in _EFFECT_FIELDS),
                "Prepared terminal manager changed before exact effect")
        require(all(actual.get(k)==pool['unitProperties'][self.unit]['properties'].get(k)
                    for k in ('LoadState','InvocationID','ControlGroup','MainPID','ActiveState','SubState')),
                "Final terminal manager differs from current full pool")
        recent_boundary(pool,observed)
        # Copy only already-bounded pool metadata; historical strings are not
        # serialized on this live boundary. Caller must act without heavy work.
        return {'kind':'CURRENT_SAME_HOST_TERMINAL_LIVE_FENCE','manager':actual,
                'pool':pool,'ledgerEqualToPrepared':True,'sameWriterTransaction':True}

    def verify(self):
        with self.boundary() as props:
            return props

    def __enter__(self):
        global _EXPECTED_INVOCATION_CONTEXT
        require(_EXPECTED_INVOCATION_CONTEXT is None, "Nested invocation effect context unsupported")
        self.verify();_EXPECTED_INVOCATION_CONTEXT = self
        return self

    def __exit__(self, *args):
        global _EXPECTED_INVOCATION_CONTEXT
        _EXPECTED_INVOCATION_CONTEXT = None


def guarded_systemctl(*args, manager="user"):
    ctx = _EXPECTED_INVOCATION_CONTEXT
    if args and args[0] == "stop":
        require(not _READONLY_BOUNDARY_PREPARATION and ctx is not None and len(args) == 2 and args[1] == ctx.unit and manager == ctx.backend.cfg.get("manager", "user"), "Actual stop has no original invocation caller context")
        with ctx.boundary():
            result = _RAW_SYSTEMCTL(*args, manager=manager)
        ctx.verify()
        return result
    if ctx is not None and not _READONLY_BOUNDARY_PREPARATION and args and args[0] == "show" and len(args) > 1 and args[1] == ctx.unit:
        require(manager == ctx.backend.cfg.get("manager", "user") and len(args[2:]) % 2 == 0 and all(args[i] == "-p" for i in range(2,len(args),2)), "Actual inspect property request unavailable")
        fields = args[3::2]
        require(set(fields) <= set(_EFFECT_FIELDS), "Actual inspect fields outside final observed schema")
        with ctx.boundary() as props:
            # This final exact query IS the requested show; do not add a second
            # potentially blocking show after it, or return a stale earlier A.
            return {key: props[key] for key in fields if key in props}
    return _RAW_SYSTEMCTL(*args, manager=manager)

systemctl = guarded_systemctl


def retain_bound_failure(db, row, reason, evidence=None):
    with db:
        db.execute("UPDATE jobs SET result=? WHERE id=? AND state='running'", (canonical({"reason": reason, "reservationRetained": True, "originalInvocation": None if row.get("_poolBinding") is None else row["_poolBinding"].get("invocation"), "evidence": evidence}), row["id"]))


def fresh_pool_epoch(db, backend, phase="canonical-pool"):
    rows = pool_rows(db, db.execute("SELECT * FROM jobs ORDER BY rowid").fetchall())
    try:proof = backend.validate_pool(rows)
    except BaseException as error:
        error.queueObservation={'phase':phase,'reservations':[{'id':r['id'],'unit':r['unit'],'specSHA256':hashlib.sha256(r['spec'].encode()).hexdigest(),'binding':r['_poolBinding']}for r in rows if r['state']in('running','terminal_cleanup')]};raise
    require(type(proof.get("completedMonotonic")) in (int, float) and 0 <= time.monotonic() - proof["completedMonotonic"] <= 1, "Fresh pool epoch clock unavailable/stale")
    return rows, proof


def output_limit_snapshot(output, expected_prefixes=None):
    """Bounded nofollow custody of the existing logger output; never trims it.
    Oversized log content is an explicit bounded prefix/UNKNOWN tail. That is a
    failed output-limit result, never a complete stream or successful job.
    """
    import stat
    fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    def ident(st): return {k:getattr(st,k) for k in fields}
    core = ('st_dev','st_ino','st_mode','st_uid','st_gid')
    output = Path(output).absolute()
    require(output.resolve(strict=True) == output, "Output path alias")
    dirs = []; close_errors = []; first = None
    try:
        # Held queue -> logs -> exact job, no named traversal after each open.
        for path, name in ((output.parent.parent, None),(output.parent,'logs'),(output,output.name)):
            fd = os.open(path if name is None else name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                         **({} if name is None else {'dir_fd':dirs[-1][1]}))
            dirs.append((path,fd, None))
            before = ident(os.fstat(fd)); dirs[-1]=(path,fd,before)
            require(before['st_uid'] == before['st_gid'] == os.getuid() and
                    stat.S_ISDIR(before['st_mode']) and not (before['st_mode'] & 0o022), "Owned output directory custody")
        dfd=dirs[-1][1]; names=sorted(os.listdir(dfd))
        allowed={'stdout.log','stderr.log','child-start.json','child-result.json','output-limit.json','overflow-stdout.bin','overflow-stderr.bin'}
        require(len(names)<=len(allowed) and set(names)<=allowed, "Unknown output artifact; no adoption")
        records={}; marker=None; marker_raw=None
        for name in names:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dfd)
            try:
                before=ident(os.fstat(fd)); cap=MAX_LOG if name.endswith('.log') else (65536 if name.startswith('overflow-') else 65536)
                require(stat.S_ISREG(before['st_mode']) and before['st_uid']==before['st_gid']==os.getuid() and
                        before['st_nlink']==1 and stat.S_IMODE(before['st_mode'])==0o600, "Exact owned single-link output file")
                require(name.endswith('.log') or before['st_size']<=cap, "Output metadata/boundary block cap")
                h=hashlib.sha256(); prefix=hashlib.sha256(); total=0; small=bytearray(); eof=False
                expected=(expected_prefixes or {}).get(name); prefix_bytes=0 if expected is None else expected['capturedBytes']
                while total<min(before['st_size'],cap):
                    b=os.read(fd,min(65536,cap-total,before['st_size']-total)); require(b,"Output short read")
                    prefix.update(b[:max(0,min(len(b),prefix_bytes-total))]);total+=len(b);h.update(b)
                    if name=='output-limit.json':small.extend(b)
                if before['st_size']<=cap:
                    require(os.read(fd,1)==b'',"Output grew during capture");eof=True
                require(expected is None or (total>=prefix_bytes and prefix.hexdigest()==expected['capturedSHA256']), 'Previously retained output prefix changed')
                os.fsync(fd)
                named=ident(os.stat(name,dir_fd=dfd,follow_symlinks=False))
                require(before==ident(os.fstat(fd))==named,"Output bytes/custody changed during capture")
                records[name]={'identity':before,'bytes':before['st_size'],'capturedBytes':total,
                               'capturedSHA256':h.hexdigest(),'readToEOF':eof,
                               'unreadTail':'NONE' if eof else 'UNKNOWN_OUTPUT_CAP','fullFileSHA256':h.hexdigest() if eof else None}
                if name=='output-limit.json':marker_raw=bytes(small)
            finally:
                try:os.close(fd)
                except BaseException as e:close_errors.append({'scope':name,'type':type(e).__name__,'reason':str(e)})
        if marker_raw is not None:
            def unique(pairs):
                result={}
                for k,v in pairs:require(k not in result,"Duplicate output-limit field");result[k]=v
                return result
            marker=json.loads(marker_raw,object_pairs_hook=unique)
            require(set(marker)=={'stream','bytesAlreadyRetained','boundaryBlockBytes','limit','furtherOutput','jobSuccessful'} and
                    marker['stream'] in ('stdout','stderr') and type(marker['bytesAlreadyRetained']) is int and
                    0<=marker['bytesAlreadyRetained']<=MAX_LOG and type(marker['boundaryBlockBytes']) is int and
                    1<=marker['boundaryBlockBytes']<=65536 and marker['bytesAlreadyRetained']+marker['boundaryBlockBytes']>MAX_LOG and
                    marker['limit']==MAX_LOG and marker['furtherOutput']=='UNKNOWN' and marker['jobSuccessful'] is False,
                    "Exact canonical logger output-limit evidence")
            log=records[marker['stream']+'.log']; overflow=records['overflow-'+marker['stream']+'.bin']
            require(log['bytes']==marker['bytesAlreadyRetained'] and overflow['bytes']==marker['boundaryBlockBytes'] and
                    log['readToEOF'] is True and overflow['readToEOF'] is True,"Complete retained prefix and whole boundary block")
        os.fsync(dfd)
        require(sorted(os.listdir(dfd))==names,"Output artifact set changed during capture")
        for path,fd,before in reversed(dirs):
            held=ident(os.fstat(fd));named=ident(os.lstat(path))
            require(all(before[k]==held[k]==named[k] for k in core),"Held/named output directory changed")
        return {'files':records,'outputLimitMarker':marker,'triggered':marker is not None or any(
                    name.endswith('.log') and item['bytes']>MAX_LOG for name,item in records.items()),
                'furtherOutput':'UNKNOWN' if marker is not None or any(not r['readToEOF'] for r in records.values()) else 'NONE',
                'directories':[{'path':str(path),'before':before,'after':ident(os.fstat(fd))}for path,fd,before in dirs]}
    except BaseException as e:
        first=e;raise
    finally:
        for path,fd,before in reversed(dirs):
            try:os.close(fd)
            except BaseException as e:close_errors.append({'scope':str(path),'type':type(e).__name__,'reason':str(e)})
        if close_errors:
            evidence={'firstFailure':None if first is None else {'type':type(first).__name__,'reason':str(first)},
                      'secondaryOutputCloseFailures':close_errors,'reservationRetained':True}
            print(canonical(evidence),file=sys.stderr,flush=True)
            if first is None:raise OSError('Output capture descriptors unclosed: '+canonical(evidence))


# Queue-owned finite terminal history storage. No runtime authority is conferred.
import stat
import ctypes
import zlib
HISTORY_KIND = 'OPEMOS_PINNED_TERMINAL_EPOCH_R1'
HISTORY_DIRECTORY = 'terminal-history-r1'
HISTORY_FILE_MAX = 64 * 1024**2
HISTORY_METADATA_MAX = 1024**2
HISTORY_NAMESPACE_MAX = 64 * 1024**2
HISTORY_ENTRY_MAX = 1536
HISTORY_FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
HISTORY_ARCHIVE_INDEX = 'lossless-history-index.json'
HISTORY_ARCHIVE_DATA = 'lossless-history-data.zlib'
HISTORY_ARCHIVE_KIND = 'OPEMOS_LOSSLESS_HISTORY_ARCHIVE_R1'
HISTORY_ARCHIVE_STAGE_MAX = 160 * 1024**2

def history_close_owned(fd):
    active=sys.exc_info()[1]
    try:os.close(fd)
    except BaseException as e:
        if active is not None:active.add_note('Secondary history leaf closure UNKNOWN: '+repr(e))
        else:raise

def history_identity(st):
    return {k:getattr(st,k) for k in HISTORY_FIELDS}

def history_equal(fd,parent,name):
    a=history_identity(os.fstat(fd));b=history_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
    require(a==b,'History held/named full9 differs')
    return a

def history_archive_regular(parent,name,uid,cap):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
    try:
        ident=history_equal(fd,parent,name)
        require(stat.S_ISREG(ident['st_mode']) and stat.S_IMODE(ident['st_mode'])==0o400 and ident['st_uid']==uid and ident['st_nlink']==1 and 0<ident['st_size']<=cap,'Lossless archive leaf custody/cap')
        chunks=[];left=ident['st_size']
        while left:
            chunk=os.read(fd,min(left,65536));require(bool(chunk),'Lossless archive short EOF');chunks.append(chunk);left-=len(chunk)
        require(os.read(fd,1)==b'' and history_equal(fd,parent,name)==ident,'Lossless archive EOF/full9')
        return b''.join(chunks),ident
    finally:history_close_owned(fd)

def history_archive_parse(raw,index_ident,data,data_ident):
    index=json.loads(raw)
    require((canonical(index)+'\n').encode()==raw and set(index)=={'kind','dataBytes','dataSHA256','dataIdentity','leaves'} and index['kind']==HISTORY_ARCHIVE_KIND and type(index['leaves'])is list and 0<len(index['leaves'])<=HISTORY_ENTRY_MAX,'Closed canonical archive index')
    require(len(data)==index['dataBytes'] and hashlib.sha256(data).hexdigest()==index['dataSHA256'] and data_ident==index['dataIdentity'],'Complete archive data identity/bytes/SHA')
    leaves={};end=0
    for item in index['leaves']:
        require(set(item)=={'pin','offset','compressedBytes','compressedSHA256'} and type(item['pin'])is dict and set(item['pin'])=={'name','bytes','sha256','identity'},'Closed archived leaf schema')
        pin=item['pin'];name=pin['name'];limit=HISTORY_METADATA_MAX if name.endswith('.epoch.json') else HISTORY_FILE_MAX
        require(type(name)is str and re.fullmatch(r'[0-9a-f]{64}\.(row|epoch)\.json',name)is not None and pin['sha256']==name[:64] and type(pin['bytes'])is int and 0<pin['bytes']<=limit and type(pin['identity'])is dict and set(pin['identity'])==set(HISTORY_FIELDS),'Archived original pin shape')
        require(type(item['offset'])is int and item['offset']==end and type(item['compressedBytes'])is int and 0<item['compressedBytes']<=HISTORY_FILE_MAX and type(item['compressedSHA256'])is str and re.fullmatch(r'[0-9a-f]{64}',item['compressedSHA256'])is not None,'Bounded contiguous compressed leaf')
        end+=item['compressedBytes'];require(end<=len(data) and name not in leaves,'Archive extent/duplicate')
        leaves[name]=item
    require(end==len(data),'No unindexed archive bytes')
    return leaves,data

def history_archive_view_check(view,parent,uid):
    require(type(view)is dict and view.get('active')is True and view['parent']==parent and view['uid']==uid,'Same active operation-scoped history archive view')
    now=history_identity(os.fstat(parent));require(all(now[k]==view['parentIdentity'][k]for k in HISTORY_FIELDS[:6]),'Same held history parent custody')
    return view['archive']

@contextmanager
def history_archive_view(parent,uid,metrics=None):
    """One held archive authentication, confined to this producer/reader call."""
    opened=[];primary=None;view={'active':True,'parent':parent,'uid':uid,'parentIdentity':history_identity(os.fstat(parent)),'archive':None,'leafReads':0,'archiveLeafReads':0,'archivePairAuthentications':0};pair=None
    def read(name,cap):
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);opened.append((name,fd,None));i=history_equal(fd,parent,name);opened[-1]=(name,fd,i)
        require(stat.S_ISREG(i['st_mode'])and stat.S_IMODE(i['st_mode'])==0o400 and i['st_uid']==uid and i['st_nlink']==1 and 0<i['st_size']<=cap,'Lossless archive leaf custody/cap')
        chunks=[];left=i['st_size']
        while left:
            block=os.read(fd,min(left,65536));require(bool(block),'Lossless archive short EOF');chunks.append(block);left-=len(block)
        require(not os.read(fd,1)and history_equal(fd,parent,name)==i,'Lossless archive EOF/full9');return b''.join(chunks),i
    try:
        names=set(os.listdir(parent));pair={HISTORY_ARCHIVE_INDEX,HISTORY_ARCHIVE_DATA}&names
        require(not pair or pair=={HISTORY_ARCHIVE_INDEX,HISTORY_ARCHIVE_DATA},'Incomplete lossless history archive')
        if pair:
            raw,index_ident=read(HISTORY_ARCHIVE_INDEX,HISTORY_METADATA_MAX);data,data_ident=read(HISTORY_ARCHIVE_DATA,HISTORY_FILE_MAX)
            view['archive']=history_archive_parse(raw,index_ident,data,data_ident);view['archivePairAuthentications']=1
            view['archiveBytesRead']=len(raw)+len(data)
        yield view
    except BaseException as error:primary=error;raise
    finally:
        secondary=[]
        try:
            require(({HISTORY_ARCHIVE_INDEX,HISTORY_ARCHIVE_DATA}&set(os.listdir(parent)))==pair,'Archive pair presence unchanged throughout operation')
            for name,fd,i in opened:
                if i is not None:require(history_equal(fd,parent,name)==i,'Held archive index/data full9/name unchanged after all leaf uses')
            if pair is not None:history_inventory(parent,uid,archive_view=view)
        except BaseException as error:secondary.append(error)
        view['active']=False
        close_failed=False
        for name,fd,i in reversed(opened):
            try:os.close(fd)
            except BaseException as error:close_failed=True;secondary.append(error)
        if metrics is not None:
            metrics.update({k:view.get(k,0)for k in('leafReads','archiveLeafReads','archivePairAuthentications','archiveBytesRead')});metrics['archiveDescriptorsClosed']=not close_failed;metrics['archiveAfterGuardPassed']=not secondary
        if secondary:
            if primary is not None:
                for error in secondary:primary.add_note('Secondary operation archive guard/closure: '+repr(error))
            else:
                for error in secondary[1:]:secondary[0].add_note('Secondary operation archive guard/closure: '+repr(error))
                raise secondary[0]

def libvirt_assignment_ready(root,job):
    """Confined readiness only; the header remains untrusted until full intake."""
    require(NAME.fullmatch(job),'Exact assignment readiness job');root=Path(root);uid=os.lstat(root).st_uid
    try:
        with libvirt_export_directory(root,uid)as parent:
            try:s=os.stat(job+'.json',dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:return False
            require(stat.S_ISREG(s.st_mode)and s.st_uid==uid and s.st_nlink==1 and 0<=s.st_size<=65536,'Assignment readiness type/owner/link/cap')
            require(stat.S_IMODE(s.st_mode)in(0o600,0o400),'Assignment readiness producer/immutable mode')
            return stat.S_IMODE(s.st_mode)==0o400 and s.st_size>0
    except FileNotFoundError as error:
        if error.filename==LIBVIRT_EXPORT_DIRECTORY:return False
        raise

def history_archive_index(parent,uid):
    with history_archive_view(parent,uid)as view:return view['archive']


def history_archive_read(parent,pin,uid,cap,archive_view=None):
    if archive_view is not None:archive_view['archiveLeafReads']+=1
    archive=history_archive_index(parent,uid)if archive_view is None else history_archive_view_check(archive_view,parent,uid)
    require(archive is not None and pin['name'] in archive[0],'Missing original history leaf and archive mapping')
    item=archive[0][pin['name']];require(item['pin']==pin,'Exact historical full9 pin preserved in archive')
    data=archive[1];start=item['offset'];compressed=data[start:start+item['compressedBytes']]
    require(hashlib.sha256(compressed).hexdigest()==item['compressedSHA256'],'Archived compressed span SHA')
    stream=zlib.decompressobj();raw=stream.decompress(compressed,cap+1)
    require(stream.eof and not stream.unused_data and not stream.unconsumed_tail and len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],'Archived exact original bytes/hash/bound')
    return raw

def history_archive_write(parent,name,raw):
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
    try:
        view=memoryview(raw)
        while view:
            n=os.write(fd,view[:65536]);require(n>0,'Archive stage write progress');view=view[n:]
        os.fsync(fd);os.fchmod(fd,0o400);os.fsync(fd)
        ident=history_equal(fd,parent,name)
    finally:history_close_owned(fd)
    os.fsync(parent)
    return ident

def history_archive_exchange(rootfd,stage):
    libc=ctypes.CDLL(None,use_errno=True)
    result=libc.renameat2(ctypes.c_int(rootfd),ctypes.c_char_p(HISTORY_DIRECTORY.encode()),
                          ctypes.c_int(rootfd),ctypes.c_char_p(stage.encode()),ctypes.c_uint(2))
    if result!=0:raise OSError(ctypes.get_errno(),'Atomic lossless history directory exchange')
    os.fsync(rootfd)

def history_archive_migrate(root,uid,stage,gate):
    """Offline-only, create-only physical migration; exchanged old directory is rollback.

    Caller must independently prove exclusive queue/worker closure and hold it
    through this call. This function cannot grant that lifecycle authority.
    """
    require(type(stage)is str and re.fullmatch(r'terminal-history-rollback-[a-z0-9-]{1,48}',stage)is not None,'Exact new rollback directory name')
    require(type(gate)is dict and set(gate)=={'offlineQueueAndWorkerClosed','sourceDirectoryIdentity','sourcePinsSHA256','sourceAllocatedBytes','sourceLeafCount'} and gate['offlineQueueAndWorkerClosed'] is True,'External offline lifecycle gate required')
    root=Path(root).absolute();rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        rootid=os.fstat(rootfd);require(rootid.st_uid==uid and stat.S_IMODE(rootid.st_mode)==0o700 and os.getuid()==os.geteuid()==uid,'Owned offline migration root')
        os.mkdir(stage,0o700,dir_fd=rootfd);os.fsync(rootfd)
        staged=os.open(stage,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rootfd)
        try:
            with history_directory(root,uid) as source:
                allocated,count=history_inventory(source,uid)
                require(HISTORY_ARCHIVE_INDEX not in os.listdir(source) and HISTORY_ARCHIVE_DATA not in os.listdir(source),'Only one migration of original format')
                names=sorted(os.listdir(source));require(count==len(names)+1 and len(names)==gate['sourceLeafCount'] and allocated==gate['sourceAllocatedBytes'] and history_identity(os.fstat(source))==gate['sourceDirectoryIdentity'],'Exact frozen original directory inventory')
                leaves=[];blob=bytearray()
                for name in names:
                    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=source)
                    try:ident=history_equal(fd,source,name)
                    finally:history_close_owned(fd)
                    pin={'name':name,'bytes':ident['st_size'],'sha256':name[:64],'identity':ident}
                    raw=history_read_leaf(source,pin,uid,HISTORY_METADATA_MAX if name.endswith('.epoch.json') else HISTORY_FILE_MAX)
                    compressed=zlib.compress(raw,9)
                    require(0<len(compressed)<=HISTORY_FILE_MAX,'Bounded compressed original')
                    leaves.append({'pin':pin,'offset':len(blob),'compressedBytes':len(compressed),'compressedSHA256':hashlib.sha256(compressed).hexdigest()})
                    blob.extend(compressed);require(len(blob)<=HISTORY_FILE_MAX,'Archive active product finite64MiB')
                pins=[item['pin'] for item in leaves]
                require(hashlib.sha256(canonical(pins).encode()).hexdigest()==gate['sourcePinsSHA256'],'All original pins and unknown bytes fixed before migration')
                data=bytes(blob);dataid=history_archive_write(staged,HISTORY_ARCHIVE_DATA,data)
                index={'kind':HISTORY_ARCHIVE_KIND,'dataBytes':len(data),'dataSHA256':hashlib.sha256(data).hexdigest(),'dataIdentity':dataid,'leaves':leaves}
                index_raw=(canonical(index)+'\n').encode();require(len(index_raw)<=HISTORY_METADATA_MAX,'Finite archive index')
                history_archive_write(staged,HISTORY_ARCHIVE_INDEX,index_raw)
                stage_allocated,stage_count=history_inventory(staged,uid)
                require(stage_allocated+HISTORY_METADATA_MAX<=HISTORY_NAMESPACE_MAX*4//5 and stage_count<=HISTORY_ENTRY_MAX,'Unchanged active cap/headroom/entries after migration')
                require(allocated+stage_allocated<=HISTORY_ARCHIVE_STAGE_MAX,'Bounded active plus rollback staging allocation')
                archive=history_archive_index(staged,uid);require(archive is not None and len(archive[0])==len(pins),'Complete staged archive')
                for pin in pins:
                    require(history_archive_read(staged,pin,uid,HISTORY_METADATA_MAX if pin['name'].endswith('.epoch.json') else HISTORY_FILE_MAX)==history_read_leaf(source,pin,uid,HISTORY_METADATA_MAX if pin['name'].endswith('.epoch.json') else HISTORY_FILE_MAX),'Every original exact byte readback before exchange')
            # The external exclusive offline gate must remain held here. Fresh
            # source check closes any accidental pre-exchange mutation window.
            with history_directory(root,uid) as source:
                require(history_identity(os.fstat(source))==gate['sourceDirectoryIdentity'] and history_inventory(source,uid)[0]==allocated and sorted(os.listdir(source))==names,'Original unchanged immediately before exchange')
                for pin in pins:history_read_leaf(source,pin,uid,HISTORY_METADATA_MAX if pin['name'].endswith('.epoch.json') else HISTORY_FILE_MAX)
            history_archive_exchange(rootfd,stage)
            try:
                with history_directory(root,uid) as current:
                    require(history_inventory(current,uid)[0]==stage_allocated,'Active archive allocation after exchange')
                    for pin in pins:history_read_leaf(current,pin,uid,HISTORY_METADATA_MAX if pin['name'].endswith('.epoch.json') else HISTORY_FILE_MAX)
                rollback=os.open(stage,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rootfd)
                try:
                    rollback_id=history_identity(os.fstat(rollback))
                    require(all(rollback_id[k]==gate['sourceDirectoryIdentity'][k] for k in HISTORY_FIELDS[:6]),'Original rollback directory custody after exchange')
                    for pin in pins:history_read_leaf(rollback,pin,uid,HISTORY_METADATA_MAX if pin['name'].endswith('.epoch.json') else HISTORY_FILE_MAX)
                    require(history_inventory(rollback,uid)[0]+stage_allocated<=HISTORY_ARCHIVE_STAGE_MAX,'Post-exchange total bounded')
                finally:history_close_owned(rollback)
            except BaseException:
                history_archive_exchange(rootfd,stage)
                raise
            return {'kind':HISTORY_ARCHIVE_KIND,'originalLeafCount':len(pins),'originalPinsSHA256':gate['sourcePinsSHA256'],'originalAllocatedBytes':allocated,'activeAllocatedBytes':stage_allocated,'activeIndexSHA256':hashlib.sha256(index_raw).hexdigest(),'activeDataSHA256':index['dataSHA256'],'rollbackDirectory':stage,'rollbackPreserved':True,'activePlusRollbackBytes':allocated+stage_allocated,'activeHeadroomLimitBytes':HISTORY_NAMESPACE_MAX*4//5}
        finally:history_close_owned(staged)
    finally:history_close_owned(rootfd)

def history_root(db):
    paths=[r[2] for r in db.execute('PRAGMA database_list') if r[1]=='main']
    require(len(paths)==1 and paths[0] and Path(paths[0]).name=='queue.sqlite3','Exact current queue DB location')
    p=Path(paths[0]);st=os.lstat(p)
    require(stat.S_ISREG(st.st_mode) and st.st_nlink==1,'Current DB custody')
    return p.parent,st.st_uid

@contextmanager
def history_directory(root,uid,create=False):
    # Held nofollow traversal; no pathname-following privileged writes.
    root=Path(root).absolute();opened=[];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);opened.append(fd);links=[]
    try:
        for part in root.parts[1:]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);opened.append(nxt)
            ident=history_equal(nxt,fd,part);links.append((fd,part,nxt,ident));fd=nxt
        st=os.fstat(fd)
        require(st.st_uid==uid and stat.S_IMODE(st.st_mode)==0o700,'Exact UID-owned0700 queue state')
        if create:
            require(os.getuid()==os.geteuid()==uid,'Only genuine queue owner writes history')
            before_create=history_identity(os.fstat(fd))
            try:
                os.mkdir(HISTORY_DIRECTORY,0o700,dir_fd=fd);os.fsync(fd)
                after_create=history_identity(os.fstat(fd))
                require(all(after_create[k]==before_create[k] for k in HISTORY_FIELDS[:5]) and after_create['st_nlink']==before_create['st_nlink']+1,'Only exact owned ext4 child mkdir parent transition')
                parent,name,held,prior=links[-1];links[-1]=(parent,name,held,after_create)
            except FileExistsError:pass
        child=os.open(HISTORY_DIRECTORY,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);opened.append(child)
        ident=history_equal(child,fd,HISTORY_DIRECTORY)
        require(stat.S_ISDIR(ident['st_mode']) and stat.S_IMODE(ident['st_mode'])==0o700 and ident['st_uid']==uid and ident['st_gid']==st.st_gid,'History directory custody')
        yield child
        # Legitimate sibling additions can change ancestor times; identity/type/
        # ownership/mode and held pathname binding cannot change. Leaf full9 stays exact.
        for parent,name,held,prior in links:
            now=history_equal(held,parent,name)
            require(all(now[k]==prior[k] for k in HISTORY_FIELDS[:6]),'History ancestor replaced or custody changed')
        now=history_equal(child,fd,HISTORY_DIRECTORY)
        require(all(now[k]==ident[k] for k in HISTORY_FIELDS[:6]),'History root replaced or custody changed')
    finally:
        active=sys.exc_info()[1];errors=[]
        for x in reversed(opened):
            try:os.close(x)
            except BaseException as e:
                errors.append(repr(e))
        if errors:
            if active is not None:active.add_note('Secondary history descriptor closure UNKNOWN: '+repr(errors))
            else:raise ValueError('History descriptor closure UNKNOWN: '+repr(errors))

def history_read_leaf(parent,pin,uid,cap,archive_view=None):
    if archive_view is not None:history_archive_view_check(archive_view,parent,uid);archive_view['leafReads']+=1
    require(set(pin)=={'name','bytes','sha256','identity'} and type(pin['name'])is str and re.fullmatch(r'[0-9a-f]{64}\.(row|epoch)\.json',pin['name']) is not None,'Closed history leaf pin')
    require(pin['name'].split('.')[0]==pin['sha256'],'Content-addressed leaf name/hash differs')
    require(type(pin['bytes'])is int and 0<pin['bytes']<=cap and re.fullmatch(r'[0-9a-f]{64}',pin['sha256'])is not None,'History finite size/hash')
    try:fd=os.open(pin['name'],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
    except FileNotFoundError:
        return history_archive_read(parent,pin,uid,cap,archive_view)
    try:
        ident=history_equal(fd,parent,pin['name'])
        require(ident==pin['identity'] and stat.S_ISREG(ident['st_mode']) and stat.S_IMODE(ident['st_mode'])==0o400 and ident['st_uid']==uid and ident['st_nlink']==1 and ident['st_size']==pin['bytes'],'History immutable leaf custody')
        chunks=[];left=pin['bytes']
        while left:
            chunk=os.read(fd,min(left,65536));require(bool(chunk),'History short EOF');chunks.append(chunk);left-=len(chunk)
        require(os.read(fd,1)==b'','History trailing data');raw=b''.join(chunks)
        require(history_equal(fd,parent,pin['name'])==ident and hashlib.sha256(raw).hexdigest()==pin['sha256'],'History full bytes/hash/custody changed')
        return raw
    finally:history_close_owned(fd)

def history_inventory(parent,uid,archive_view=None):
    names=sorted(os.listdir(parent));require(len(names)<=HISTORY_ENTRY_MAX,'Finite history entry count')
    total=os.fstat(parent).st_blocks*512;seen=set()
    for name in names:
        require(re.fullmatch(r'[0-9a-f]{64}\.(row|epoch)\.json',name)is not None or name in (HISTORY_ARCHIVE_INDEX,HISTORY_ARCHIVE_DATA),'Unknown history entry retained/refused')
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            s=history_equal(fd,parent,name)
            require(stat.S_ISREG(s['st_mode']) and stat.S_IMODE(s['st_mode'])==0o400 and s['st_uid']==uid and s['st_nlink']==1 and 0<s['st_size']<=HISTORY_FILE_MAX,'History inventory custody/type/cap')
            key=(s['st_dev'],s['st_ino']);require(key not in seen,'Aliased history object');seen.add(key);total+=os.fstat(fd).st_blocks*512
        finally:history_close_owned(fd)
    require(total<=HISTORY_NAMESPACE_MAX,'Existing actual allocated history cap')
    archive=(history_archive_index(parent,uid)if archive_view is None else history_archive_view_check(archive_view,parent,uid))if HISTORY_ARCHIVE_INDEX in names or HISTORY_ARCHIVE_DATA in names else None
    live={name for name in names if re.fullmatch(r'[0-9a-f]{64}\.(row|epoch)\.json',name)is not None}
    archived=set(archive[0]) if archive else set()
    require(not (live & archived),'Conflicting live and archived history leaf names')
    logical=len(live)+len(archived)+1
    require(logical<=HISTORY_ENTRY_MAX and len(names)+1<=HISTORY_ENTRY_MAX,'Unchanged finite logical and physical history entry caps')
    return total,logical

def history_publish(parent,raw,suffix,uid,archive_view=None):
    limit=HISTORY_METADATA_MAX if suffix=='epoch' else HISTORY_FILE_MAX
    require(0<len(raw)<=limit,'History product cap')
    digest=hashlib.sha256(raw).hexdigest();name=digest+'.'+suffix+'.json'
    if name not in os.listdir(parent):
        archived=history_archive_index(parent,uid)if archive_view is None else history_archive_view_check(archive_view,parent,uid)
        if archived is not None and name in archived[0]:
            pin=archived[0][name]['pin']
            require(history_archive_read(parent,pin,uid,limit,archive_view)==raw,'Archived content differs; no adoption')
            return pin
    try:
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
    except FileExistsError:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        try:ident=history_equal(fd,parent,name)
        finally:history_close_owned(fd)
        pin={'name':name,'bytes':len(raw),'sha256':digest,'identity':ident}
        require(history_read_leaf(parent,pin,uid,limit,archive_view)==raw,'Existing content object differs; no adoption')
        return pin
    # Every failure retains the exact partial, blocks inventory on mode0600, and
    # prevents SQL terminal commit. No automatic removal/adoption/retry.
    try:
        offset=0
        while offset<len(raw):
            n=os.write(fd,raw[offset:offset+65536]);require(n>0,'History write made no progress');offset+=n
        os.fsync(fd);os.fchmod(fd,0o400);os.fsync(fd)
        ident=history_equal(fd,parent,name)
    finally:history_close_owned(fd)
    os.fsync(parent)
    pin={'name':name,'bytes':len(raw),'sha256':digest,'identity':ident}
    require(history_read_leaf(parent,pin,uid,limit,archive_view)==raw,'History readback differs')
    return pin

def terminal_history_store(db,epoch,row,invocation):
    require(db.in_transaction,'History preparation retains original SQLite writer lock')
    root,uid=history_root(db)
    raw=(canonical(epoch)+'\n').encode();require(len(raw)<=HISTORY_FILE_MAX,'Complete history within unchanged byte ceiling')
    identity={'jobId':row['id'],'unit':row['unit'],'InvocationID':invocation}
    with history_directory(root,uid,True) as parent:
        allocated,count=history_inventory(parent,uid)
        objects=[(canonical(r)+'\n').encode() for r in epoch['rows']]
        missing={hashlib.sha256(x).hexdigest()+'.row.json':x for x in objects}
        names=set(os.listdir(parent));archive=history_archive_index(parent,uid);present=names|(set(archive[0]) if archive else set())
        extra=sum(((len(x)+4095)//4096)*4096 for n,x in missing.items() if n not in present)
        # Reserve complete worst-case metadata BEFORE any object write; 20% of
        # existing finite64MiB namespace remains headroom, not a raised quota.
        require(allocated+extra+HISTORY_METADATA_MAX<=HISTORY_NAMESPACE_MAX*4//5 and count+len(set(missing)-present)+1<=HISTORY_ENTRY_MAX,'History planned20percent headroom/entries')
        fs=os.fstatvfs(parent);require(fs.f_bavail*fs.f_frsize>=extra+HISTORY_METADATA_MAX+HISTORY_NAMESPACE_MAX//5 and fs.f_favail>=len(missing)+2,'History free bytes/inodes')
        pins=[history_publish(parent,x,'row',uid) for x in objects]
        manifest={'kind':HISTORY_KIND,'identity':identity,'rows':pins,'pool':epoch['pool'],'bindings':epoch['bindings'],'config':epoch['config'],'epochBytes':len(raw),'epochSHA256':hashlib.sha256(raw).hexdigest()}
        mraw=(canonical(manifest)+'\n').encode();pin=history_publish(parent,mraw,'epoch',uid)
        require(history_inventory(parent,uid)[0]<=HISTORY_NAMESPACE_MAX*4//5,'Actual allocated history20percent headroom')
    return {'kind':HISTORY_KIND,'identity':identity,'manifest':pin,'epochBytes':len(raw),'epochSHA256':hashlib.sha256(raw).hexdigest(),'rowCount':len(epoch['rows'])}

def terminal_history_resolve(root,uid,value,job,unit,invocation):
    require(type(value)is dict,'Exact retained terminal epoch type')
    if value.get('kind')!=HISTORY_KIND:
        require(set(value)=={'rows','pool','bindings','config'} and type(value['rows'])is list,'Exact legacy embedded epoch, never unknown reference')
        return value
    require(set(value)=={'kind','identity','manifest','epochBytes','epochSHA256','rowCount'} and value['identity']=={'jobId':job,'unit':unit,'InvocationID':invocation} and type(value['rowCount'])is int and 0<value['rowCount']and type(value['epochBytes'])is int and 0<value['epochBytes']<=HISTORY_FILE_MAX,'Exact original terminal reference context')
    with history_directory(root,uid) as parent:
        history_inventory(parent,uid)
        mraw=history_read_leaf(parent,value['manifest'],uid,HISTORY_METADATA_MAX);m=json.loads(mraw)
        require((canonical(m)+'\n').encode()==mraw and set(m)=={'kind','identity','rows','pool','bindings','config','epochBytes','epochSHA256'} and m['kind']==HISTORY_KIND and m['identity']==value['identity'] and m['epochBytes']==value['epochBytes'] and m['epochSHA256']==value['epochSHA256'] and len(m['rows'])==value['rowCount'],'Whole canonical manifest binding')
        rows=[];row_bytes=2;seen=set()
        for pin in m['rows']:
            b=history_read_leaf(parent,pin,uid,HISTORY_FILE_MAX);r=json.loads(b);require((canonical(r)+'\n').encode()==b,'Whole canonical history row')
            row_bytes+=len(b);require(row_bytes<=HISTORY_FILE_MAX and r['id']not in seen,'Bounded unique complete history rows');seen.add(r['id']);rows.append(r)
        require(len({r['id'] for r in rows})==len(rows),'Unique ordered history IDs')
        epoch={'rows':rows,'pool':m['pool'],'bindings':m['bindings'],'config':m['config']};raw=(canonical(epoch)+'\n').encode()
        require(len(raw)==value['epochBytes'] and hashlib.sha256(raw).hexdigest()==value['epochSHA256'],'Complete ordered epoch reconstruction SHA/bytes')
        # Re-read manifest and every row after decoding to refuse replacement.
        require(history_read_leaf(parent,value['manifest'],uid,HISTORY_METADATA_MAX)==mraw,'Manifest changed during complete decode')
        for pin in m['rows']:history_read_leaf(parent,pin,uid,HISTORY_FILE_MAX)
        return epoch

def terminal_history_load(db,value,row,invocation):
    root,uid=history_root(db)
    return terminal_history_resolve(root,uid,value,row['id'],row['unit'],invocation)


def commit_output_limit(db, backend, row, output):
    ctx=ExpectedInvocation(backend,db,row)
    snapshot=output_limit_snapshot(output)
    require(snapshot['triggered'] is True,"No actual retained output-limit trigger")
    # The snapshot is already fsynced. This is a cancellation INTENT, explicitly
    # not a fabricated numeric terminal or claim that a live group is empty.
    with ctx.prepare_terminal():
        preserved_epoch=bind_terminal_pool_epoch(ctx)
        latest=exact_unit_observation(backend,ctx.unit)
        pending=dict(latest,finalLedgerInvocation=ctx.invocation,outputLimitStopRequired=True,
                     preservedReservationEpoch=terminal_history_store(db,preserved_epoch,ctx.row,ctx.invocation),
                     outputLimitEvidence=snapshot,outputPath=str(output),
                     terminalLifecycle={'phase':'COMMITTED_BEFORE_OWNED_STOP','intendedState':'output_limit',
                                        'reservationRetained':True,'automaticRetryAuthorized':False})
        encoded=canonical(pending)
        fence=ctx.recheck_terminal(ctx.terminal_epoch,latest,False)
        encoded=terminal_encoded_fence(encoded,'zzCommitLiveFence',fence)
        recent_boundary(fence['pool'],time.monotonic())
        db.execute("UPDATE jobs SET state='terminal_cleanup',result=? WHERE id=? AND state='running'",
                   (encoded,row['id']))
        require(db.execute('SELECT changes()').fetchone()[0]==1,'Exactly one original output-limit intent')
    finish_committed_terminal(db,backend,dict(db.execute('SELECT * FROM jobs WHERE id=?',(row['id'],)).fetchone(),_poolBinding=ctx.bound))


def terminal_json_domain(value):
    # Exact json.loads(canonical(value)) domain without escaping/copying every
    # immutable historical result string. Never accepts opaque Python objects.
    import math
    if value is None or type(value) in (str, bool, int): return value
    if type(value) is float:
        require(math.isfinite(value), "Finite terminal JSON number")
        return value
    if type(value) in (tuple, list): return [terminal_json_domain(x) for x in value]
    require(type(value) is dict and all(type(k) is str for k in value), "Closed terminal JSON domain")
    return {k: terminal_json_domain(v) for k, v in value.items()}


def terminal_encoded_fence(encoded, key, fence):
    # The large full receipt is serialized BEFORE the final live query. Only
    # append the small closed current fence; no second full-history serialization.
    require(type(encoded) is str and encoded.endswith('}') and key in
            ('zzCommitLiveFence','zzReleaseLiveFence','zzPeerAckLiveFence'), "Exact prepared terminal fence")
    return encoded[:-1] + ',' + canonical(key) + ':' + canonical(fence) + '}'


def terminal_pool_epoch(db, rows, pool):
    # A closed JSON domain avoids tuple/list representation drift on persistence.
    return terminal_json_domain({'rows':rows,'pool':pool,
        'bindings':[list(r)for r in db.execute('SELECT job_id,value FROM pool_unit_bindings ORDER BY job_id')],
        'config':[list(r)for r in db.execute('SELECT id,value FROM config ORDER BY id')]})


def retained_unknown_marker(row):
    if row['state']!='running' or not row.get('result') or not row.get('_poolBinding'):return False
    value=json.loads(row['result'])
    return (type(value)is dict and value.get('reservationRetained') is True and
            value.get('originalInvocation')==row['_poolBinding']['invocation'] and
            type(value.get('reason')) is str and value['reason'].startswith('Unit evidence missing'))


def bind_terminal_pool_epoch(ctx):
    epoch=ctx.terminal_epoch;pool=epoch['pool'];rows=epoch['rows']
    require(all(pool.get(k)is True for k in ('admitted','includesUID0','completeBoundedTraversal','allOwnedDescriptorsClosed')),
            'Complete UID0 closed initial pool epoch')
    require(pool.get('canonicalPool')=='/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice', 'Canonical terminal pool')
    unknown=pool['unknownReservationsRetained']
    require(type(unknown)is list and len(unknown)==len(set(unknown)) and ctx.unit not in unknown,'Initial exact owned invocation cannot be unknown')
    by_unit={r['unit']:r for r in rows if r['state'] in ('running','terminal_cleanup')}
    require(set(pool['unitProperties'])==set(by_unit), 'Full initial reservation/unit coverage')
    for unit in unknown:
        row=by_unit.get(unit);require(row is not None and retained_unknown_marker(row), 'Only prior exact held unknown leases')
        bound=row['_poolBinding'];entry=pool['unitProperties'][unit];props=entry['properties']
        require(bound['job_id']==row['id'] and bound['unit']==unit and
                type(bound['invocation'])is str and re.fullmatch(r'[0-9a-f]{32}',bound['invocation']) and
                entry['known'] is False and props.get('LoadState')=='not-found' and props.get('MainPID')=='0' and
                props.get('InvocationID')=='' and props.get('ControlGroup')=='' and props.get('ActiveState')=='inactive',
                'Prior unknown is absent manager evidence, never a live/foreign invocation')
        path=pool['canonicalPool']+'/'+unit
        require(not any(t['cgroup']==path or t['cgroup'].startswith(path+'/') for t in pool['tasks']), 'Prior unknown lease has a busy subtree')
    own=next(r for r in rows if r['id']==ctx.row['id'])
    require(own==terminal_json_domain(ctx.row), 'Initial full original row differs from captured immutable caller')
    return epoch


def verify_terminal_pool_transition(initial, current, owned_row, collected, *, receipt_hashes=True):
    # Preserve every other full row/result/binding/resource/config value, not
    # merely the unknown-unit names. Both full raw pool epochs stay in result.
    before=initial['pool'];after=current['pool'];unit=owned_row['unit'];job=owned_row['id']
    require(all(after.get(k)is True for k in ('admitted','includesUID0','completeBoundedTraversal','allOwnedDescriptorsClosed')),
            'Post-effect full UID0 observation unknown')
    require(current['bindings']==initial['bindings'] and current['config']==initial['config'], 'Full bindings/config changed during own finalization')
    require([r['id']for r in current['rows']]==[r['id']for r in initial['rows']], 'Full ordered history changed during own finalization')
    old={r['id']:r for r in initial['rows']};new={r['id']:r for r in current['rows']}
    require(all(new[k]==v for k,v in old.items()if k!=job),'Other full job/spec/cpus/result/finished/resource row changed')
    require(new[job]==terminal_json_domain(owned_row), 'Current complete pending original row changed')
    require({k:v for k,v in old[job].items()if k not in ('state','result')}==
            {k:v for k,v in new[job].items()if k not in ('state','result')}, 'Original own immutable row fields changed')
    require(after['canonicalPool']==before['canonicalPool'] and after['systemdPoolProperties']==before['systemdPoolProperties'], 'Whole pool scope/caps/properties changed')
    require(set(after['unitProperties'])==set(before['unitProperties']), 'New/removed pool reservation scope')
    require({u:v for u,v in after['unitProperties'].items()if u!=unit}==
            {u:v for u,v in before['unitProperties'].items()if u!=unit}, 'Other current unit/invocation properties changed')
    expected=set(before['unknownReservationsRetained']) | ({unit}if collected else set())
    unknown=after['unknownReservationsRetained']
    require(type(unknown)is list and len(unknown)==len(set(unknown)) and set(unknown)==expected,
            'New/removed/changed unknown reservation beyond exact collected own unit')
    def others(tasks):
        path=before['canonicalPool']+'/'+unit
        return sorted([t for t in tasks if not(t['cgroup']==path or t['cgroup'].startswith(path+'/'))],key=lambda t:t['tid'])
    require(others(before['tasks'])==others(after['tasks']), 'New/changed/foreign/busy other task')
    for field in ('knownInvocations','positiveMainPIDProofs'):
        require({u:v for u,v in after[field].items()if u!=unit}=={u:v for u,v in before[field].items()if u!=unit}, 'Other original positive identity proof changed')
    old_custody=before['rootParentCustody'];new_custody=after['rootParentCustody']
    # An owned stop/GC may change cgroup parent nlink/timestamps. Every full raw
    # row is retained, but canonical path/dev/inode/type/UID/GID must not change.
    require([(p,m[:5])for p,m in old_custody]==[(p,m[:5])for p,m in new_custody], 'Pool held ancestor identity/type/owner changed')
    return {'otherRowsPreserved':len(old)-1,'initialEpochSHA256':hashlib.sha256(canonical(initial).encode()).hexdigest() if receipt_hashes else None,
            'retainedUnknownUnits':list(before['unknownReservationsRetained']),'onlyOwnUnitCollectionPermitted':True,
            'currentLedgerSHA256':hashlib.sha256(canonical({k:v for k,v in current.items()if k!='pool'}).encode()).hexdigest() if receipt_hashes else None}


def terminal_observation(props):
    return (props.get("LoadState") == "loaded" and props.get("MainPID") == "0" and
            (props.get("ActiveState") in ("inactive", "failed") or
             (props.get("ActiveState"), props.get("SubState")) == ("active", "exited")) and
            props.get("ExecMainCode") in ("1", "2", "3") and str(props.get("ExecMainStatus", "")).isdigit())


def verify_peer_terminal_ack(original, current, row, peer_unit):
    """Recognize only an observed same-invocation foreign manager exit.

    The original is immutable. The disposable comparison projection below is
    permitted only after every typed transition field is validated. A peer row
    retirement, new job, changed binding, unknown lease or resource change fails.
    """
    require(type(peer_unit) is str and peer_unit != row['unit'], 'Exact foreign peer')
    before, after = original['pool'], current['pool']
    peers = [r for r in original['rows'] if r.get('unit') == peer_unit and r['state'] == 'running']
    require(len(peers) == 1, 'Unique original running peer')
    peer = peers[0]; bound = peer.get('_poolBinding')
    require(type(bound) is dict and bound['job_id'] == peer['id'] and bound['unit'] == peer_unit,
            'Original immutable peer binding')
    first, last = before['unitProperties'][peer_unit], after['unitProperties'][peer_unit]
    a, b = first['properties'], last['properties']
    require(first['known'] is True and last['known'] is True and
            a['LoadState'] == b['LoadState'] == 'loaded' and
            a['InvocationID'] == b['InvocationID'] == bound['invocation'], 'Same loaded peer invocation')
    require((a['ActiveState'],a['SubState']) == ('active','running') and
            a['MainPID'].isdigit() and int(a['MainPID']) > 0 and
            (b['ActiveState'],b['SubState']) in (('failed','failed'),('inactive','dead')) and
            b['MainPID'] == '0', 'Only positive running-to-terminal peer exit')
    path = before['canonicalPool'] + '/' + peer_unit
    require(a['ControlGroup'] == path and b['ControlGroup'] in ('',path), 'Exact peer cgroup')
    allowed = {'ActiveState','SubState','MainPID','ControlGroup'}
    require({k:v for k,v in a.items() if k not in allowed} ==
            {k:v for k,v in b.items() if k not in allowed} and
            {k:v for k,v in first.items() if k != 'properties'} ==
            {k:v for k,v in last.items() if k != 'properties'}, 'All peer resources/evidence preserved')
    require(peer_unit not in before['unknownReservationsRetained'] and
            peer_unit not in after['unknownReservationsRetained'], 'No unknown peer evidence')
    require(before['knownInvocations'][peer_unit] == after['knownInvocations'][peer_unit],
            'Same original positive invocation proof')
    # positiveMainPIDProofs may disappear only with the exact captured peer PID.
    require(peer_unit in before['positiveMainPIDProofs'] and
            peer_unit not in after['positiveMainPIDProofs'], 'Exact peer positive PID disappearance')
    positive=before['positiveMainPIDProofs'][peer_unit]
    require(positive['invocation']==bound['invocation'] and
            positive['process']['tid']==positive['process']['tgid']==int(a['MainPID']) and
            positive['process']['cgroup']==path and
            type(positive['process']['start']) is int and positive['process']['start']>0,
            'Peer captured PID/start/cgroup belongs to immutable invocation')
    remaining = [t for t in before['tasks'] if not (t['cgroup'] == path or t['cgroup'].startswith(path+'/'))]
    require(sorted(remaining,key=lambda t:t['tid']) == sorted(after['tasks'],key=lambda t:t['tid']),
            'Only captured peer tasks removed; no current foreign change')
    projected = terminal_json_domain(original)
    projected['pool']['unitProperties'][peer_unit] = last
    del projected['pool']['positiveMainPIDProofs'][peer_unit]
    projected['pool']['tasks'] = remaining
    verify_terminal_pool_transition(projected,current,row,False)
    return {'kind':'SAME_INVOCATION_PEER_EXIT_ACK_V1','peerUnit':peer_unit,
            'peerJob':peer['id'],'peerInvocation':bound['invocation'],
            'before':first,'after':last,'historicalExitReason':'UNKNOWN',
            'originalEpochSHA256':hashlib.sha256(canonical(original).encode()).hexdigest(),
            'currentEpochSHA256':hashlib.sha256(canonical(current).encode()).hexdigest()}


def acknowledge_committed_peer_exit(db, backend, row, peer_unit):
    """Append a separate current baseline under the normal writer/native guards.

    This API performs no stop, lease release, peer retirement or job submission.
    Original epoch and historical result remain content-addressed evidence.
    """
    require(row['state']=='terminal_cleanup' and row['finished'] is None, 'Only committed retained row')
    saved=json.loads(row['result']); lifecycle=saved['terminalLifecycle']
    require('peerTerminalAcknowledgment' not in saved and lifecycle['phase']=='COMMITTED_BEFORE_OWNED_STOP'
            and lifecycle['reservationRetained'] is True and lifecycle['automaticRetryAuthorized'] is False,
            'One acknowledgment, no replay or closure authority')
    ctx=ExpectedInvocation(backend,db,row)
    require(saved['finalLedgerInvocation']==ctx.invocation,'Original committed invocation')
    check_inputs(json.loads(row['spec']))
    original=terminal_history_load(db,saved['preservedReservationEpoch'],row,ctx.invocation)
    with ctx.prepare_terminal():
        current=ctx.terminal_epoch
        transition=verify_peer_terminal_ack(original,current,row,peer_unit)
        manager=exact_unit_observation(backend,ctx.unit)
        require(terminal_observation(manager) and manager['InvocationID']==ctx.invocation and
                all(manager.get(k)==saved.get(k) for k in ('Result','ExecMainCode','ExecMainStatus')),
                'Current original terminal differs')
        group=backend.whole_owned_cgroup(ctx.unit,manager)
        require(group['empty'] is True,'Current original unit/domain/lease/GPU closure required')
        reference=terminal_history_store(db,current,row,ctx.invocation)
        value=dict(saved,peerTerminalAcknowledgment={'transition':transition,'currentEpoch':reference,
                   'currentOriginalClosure':group})
        encoded=canonical(value)
        fence=ctx.recheck_terminal(current,manager,True)
        require('zzPeerAckLiveFence' not in value,'Peer acknowledgment fence cannot be overwritten')
        encoded=terminal_encoded_fence(encoded,'zzPeerAckLiveFence',fence)
        recent_boundary(fence['pool'],time.monotonic())
        db.execute("UPDATE jobs SET result=? WHERE id=? AND state='terminal_cleanup' AND result=?",
                   (encoded,row['id'],row['result']))
        require(db.execute('SELECT changes()').fetchone()[0]==1,'Exactly original pending row acknowledged')


def finish_committed_terminal(db, backend, row):
    with readonly_observer_phase(db,backend):
        return _finish_committed_terminal(db,backend,row)


def _finish_committed_terminal(db, backend, row):
    require(row["state"] == "terminal_cleanup" and row["finished"] is None,
            "Only durable retained terminal cleanup lease")
    ctx = ExpectedInvocation(backend, db, row)
    saved = json.loads(row["result"])
    lifecycle = saved["terminalLifecycle"]
    require(lifecycle == {"phase": "COMMITTED_BEFORE_OWNED_STOP", "intendedState": lifecycle["intendedState"],
                         "reservationRetained": True, "automaticRetryAuthorized": False} and
            lifecycle["intendedState"] in TERMINAL and saved["finalLedgerInvocation"] == ctx.invocation,
            "Closed immutable terminal commit")
    check_inputs(json.loads(row["spec"]))
    output_limit = saved.get("outputLimitStopRequired") is True
    require(not output_limit or lifecycle["intendedState"] == "output_limit", "Exact output-limit intent")
    preserved_epoch = terminal_history_load(db,saved['preservedReservationEpoch'],row,ctx.invocation)
    if 'peerTerminalAcknowledgment' in saved:
        ack=saved['peerTerminalAcknowledgment']
        require(set(ack)=={'transition','currentEpoch','currentOriginalClosure'},'Exact acknowledgment schema')
        acknowledged=terminal_history_load(db,ack['currentEpoch'],row,ctx.invocation)
        previous=next(r for r in acknowledged['rows'] if r['id']==row['id'])
        require({k:v for k,v in previous.items() if k!='result'}==
                {k:v for k,v in terminal_json_domain(row).items() if k!='result'},
                'Acknowledgment preserves every immutable own field')
        old_result=json.loads(previous['result'])
        require({k:v for k,v in saved.items() if k not in ('peerTerminalAcknowledgment','zzPeerAckLiveFence')}==
                old_result,
                'Acknowledgment preserves complete original saved evidence')
        fence=saved.get('zzPeerAckLiveFence')
        require(type(fence)is dict and set(fence)=={'kind','manager','pool','ledgerEqualToPrepared','sameWriterTransaction'}
                and fence['kind']=='CURRENT_SAME_HOST_TERMINAL_LIVE_FENCE'
                and fence['ledgerEqualToPrepared'] is True and fence['sameWriterTransaction'] is True
                and fence['manager'].get('InvocationID')==ctx.invocation,
                'Exact separately recorded peer acknowledgment fence')
        require(verify_peer_terminal_ack(preserved_epoch,acknowledged,previous,ack['transition']['peerUnit'])
                ==ack['transition'],'Authenticated original-to-current acknowledgment')
        preserved_epoch=acknowledged
    stopped = False
    # Lock precedes every potentially blocking read. The last operation before
    # stop is the same full original-invocation manager guard used for effects.
    with ctx.prepare_terminal():
        preserved_before_stop=verify_terminal_pool_transition(preserved_epoch,ctx.terminal_epoch,row,False)
        latest=exact_unit_observation(backend,ctx.unit)
        require((output_limit or terminal_observation(latest)) and latest.get("InvocationID") == ctx.invocation and (output_limit or all(latest.get(k) == saved.get(k) for k in
                ("Result", "ExecMainCode", "ExecMainStatus"))), "Committed terminal changed")
        pre_stop_fence=ctx.recheck_terminal(ctx.terminal_epoch,latest,not output_limit)
        if (output_limit and latest["ActiveState"] not in ("inactive", "failed")) or (latest["ActiveState"], latest["SubState"]) == ("active", "exited"):
            _RAW_SYSTEMCTL("stop", ctx.unit, manager=backend.cfg.get("manager", "user"))
            stopped = True
        after = exact_unit_observation(backend, ctx.unit)
        collected = (stopped and after.get("LoadState") == "not-found" and after.get("MainPID") == "0" and
                     after.get("InvocationID") == "" and after.get("ControlGroup") == "" and after.get("ActiveState") == "inactive")
        require(collected or (terminal_observation(after) and after["InvocationID"] == ctx.invocation and
                after["ActiveState"] in ("inactive", "failed") and (output_limit or all(after.get(k) == saved.get(k) for k in
                ("Result", "ExecMainCode", "ExecMainStatus")))), "Post-commit manager closure unknown/foreign")
        group = backend.whole_owned_cgroup(ctx.unit, after)
        require(group["empty"] is True, "Post-stop original group not empty")
        closed_output = None
        if output_limit:
            closed_output = output_limit_snapshot(Path(saved["outputPath"]), saved["outputLimitEvidence"]["files"])
            before_output = saved["outputLimitEvidence"]
            for name, item in before_output["files"].items():
                after_item = closed_output["files"].get(name)
                require(after_item is not None and all(item["identity"][k] == after_item["identity"][k] for k in
                        ("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink")) and
                        after_item["bytes"] >= item["bytes"], "Retained output custody/bytes changed")
                if name == "output-limit.json" or name.startswith("overflow-"):
                    require(after_item == item, "Original output-limit marker/boundary changed")
            require(closed_output["triggered"] is True, "Output trigger vanished after stop")
        rows, pool = boundary_pool_epoch(db, backend)
        post_epoch=terminal_pool_epoch(db,rows,pool)
        preserved_after_stop=verify_terminal_pool_transition(preserved_epoch,post_epoch,row,collected)
        path = pool["canonicalPool"] + "/" + ctx.unit
        require(not any(t["cgroup"] == path or t["cgroup"].startswith(path + "/") for t in pool["tasks"]),
                "Post-stop descendants present")
        current = db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone()
        require(dict(current) == {k:v for k,v in row.items() if k != "_poolBinding"}, "Committed row changed during cleanup")
        final = dict(saved, outputLimitClosedEvidence=closed_output,
                     numericAfterOwnedStop=("UNKNOWN_MANAGER_COLLECTED" if collected else
                         {"ExecMainCode":after["ExecMainCode"],"ExecMainStatus":after["ExecMainStatus"]}),
                     terminalLifecycle={"phase":"CLOSED", "intendedState":lifecycle["intendedState"],
                     "reservationRetained":False, "stopReturned":stopped, "managerAfter":after,
                     "postStopCgroupProof":group, "postStopPoolProof":pool,
                     "preStopPoolProof":ctx.terminal_epoch['pool'],"zzPreStopLiveFence":pre_stop_fence,
                     "preservedBeforeStop":preserved_before_stop,"preservedAfterStop":preserved_after_stop})
        encoded=canonical(final)
        release_fence=ctx.recheck_terminal(post_epoch,after,True)
        encoded=terminal_encoded_fence(encoded,'zzReleaseLiveFence',release_fence)
        recent_boundary(release_fence['pool'],time.monotonic())
        db.execute("UPDATE jobs SET state=?,finished=?,result=? WHERE id=? AND state='terminal_cleanup' AND result=?",
                   (lifecycle["intendedState"], time.time(), encoded, row["id"], row["result"]))
        require(db.execute("SELECT changes()").fetchone()[0] == 1, "Exactly one positively closed terminal")


def finish_bound(db, backend, row, state, evidence):
    with readonly_observer_phase(db,backend):
        return _finish_bound(db,backend,row,state,evidence)


def _finish_bound(db, backend, row, state, evidence):
    require(state in TERMINAL, "Exact intended terminal state required")
    ctx = ExpectedInvocation(backend, db, row)
    require(evidence.get("InvocationID") == ctx.invocation, "Inspected terminal is not original invocation")
    current = ctx.verify()
    proof = backend.whole_owned_cgroup(row["unit"], current)
    require(proof["empty"], "Original invocation group changed after fsync")
    pending = dict(evidence, finalLedgerInvocation=ctx.invocation, finalAfterFsyncCgroupProof=proof,
                   terminalLifecycle={"phase": "COMMITTED_BEFORE_OWNED_STOP", "intendedState": state,
                                      "reservationRetained": True, "automaticRetryAuthorized": False})
    with ctx.prepare_terminal():
        pending['preservedReservationEpoch']=terminal_history_store(db,bind_terminal_pool_epoch(ctx),ctx.row,ctx.invocation)
        latest=exact_unit_observation(backend,ctx.unit)
        require(terminal_observation(latest) and all(latest.get(k) == evidence.get(k) for k in
                ("InvocationID", "Result", "ExecMainCode", "ExecMainStatus")),
                "Current original invocation terminal changed after fsync")
        encoded=canonical(pending)
        fence=ctx.recheck_terminal(ctx.terminal_epoch,latest,True)
        encoded=terminal_encoded_fence(encoded,'zzCommitLiveFence',fence)
        recent_boundary(fence['pool'],time.monotonic())
        db.execute("UPDATE jobs SET state='terminal_cleanup',result=? WHERE id=? AND state='running'",
                   (encoded, row["id"]))
        require(db.execute("SELECT changes()").fetchone()[0] == 1, "Exactly one original terminal-evidence commit")
    # BEGIN IMMEDIATE/FULL synchronous commit has returned. No stop before this.
    # Any failure below leaves the durable reservation; tick never retries it.
    finish_committed_terminal(db, backend, dict(db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone(), _poolBinding=ctx.bound))


def planned_ledger_current(db, planned):
    row = db.execute("SELECT * FROM jobs WHERE id=?", (planned["id"],)).fetchone()
    binding = db.execute("SELECT value FROM pool_unit_bindings WHERE job_id=?", (planned["id"],)).fetchone()
    require(row is not None and all(row[k] == planned[k] for k in ("id", "spec", "state", "unit", "cpus", "started")) and row["state"] == "running" and binding is None and planned.get("_poolBinding") is None, "Original uncreated planned lease or absence of binding changed; reservation retained")


def finish_uncreated(db, backend, planned, launch, cgroup_proof):
    require(cgroup_proof.get("empty") is True, "Uncreated own nonce group not empty")
    backend.owned_unit(planned["unit"])
    payload = canonical(dict(launch, currentUncreatedCgroupProof=cgroup_proof, finalUncreatedPlannedLeaseSHA256=hashlib.sha256(canonical({k: planned[k] for k in ("id", "spec", "state", "unit", "cpus", "started")}).encode()).hexdigest()))
    finished_at = time.time()
    with immutable_ledger_transaction(db):
        planned_ledger_current(db, planned)
        rows, proof = boundary_pool_epoch(db, backend)
        current = next((r for r in rows if r["id"] == planned["id"]), None)
        require(current is not None and current.get("_poolBinding") is None and all(current[k] == planned[k] for k in ("id", "spec", "state", "unit", "cpus", "started")), "Current uncreated enriched planned lease changed")
        require(proof.get("admitted") is True and proof.get("canonicalPool") == "/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice" and proof["unitProperties"][planned["unit"]]["properties"].get("LoadState") == "not-found", "Current uncreated pool/nonce proof unavailable")
        planned_ledger_current(db, planned)
        observed_at = time.monotonic()
        actual = exact_unit_observation(backend, planned["unit"])
        require(actual.get("LoadState") == "not-found", "Final uncreated nonce now loaded or unknown; planned reservation retained")
        recent_boundary(proof, observed_at)
        db.execute("UPDATE jobs SET state='failed',finished=?,result=? WHERE id=? AND state='running'", (finished_at, payload, planned["id"]))

NEVER_PREPARED_ROOT_SOURCE='"""Exact finite read-only absence/holder supplement. No device/unit operation.\nExisting authenticated Root domain observer separately brackets this proof.\n"""\nimport os,sys,json,stat,hashlib,time,threading\nfrom pathlib import Path\nFIELDS=(\'st_dev\',\'st_ino\',\'st_mode\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\')\ndef need(v,m):\n if not v:raise ValueError(m)\ndef identity(s):return {k:getattr(s,k)for k in FIELDS}\ndef fdmap():\n out={}\n for n in os.listdir(\'/proc/self/fd\'):\n  try:out[n]=[identity(os.fstat(int(n))),os.readlink(\'/proc/self/fd/\'+n)]\n  except OSError as e:\n   if e.errno not in(2,9):raise\n return out\ndef observe(request,run_path=\'/run\',proc_path=\'/proc\'):\n started=time.monotonic();before=fdmap();root=run=None;primary=None;closes=[];proof=None\n try:\n  need(os.getuid()==os.geteuid()==0,\'genuine Root readonly supplement\')\n  need(type(request)is dict and type(request[\'jobToken\'])is str and __import__(\'re\').fullmatch(\'[0-9a-f]{32}\',request[\'jobToken\'])and __import__(\'re\').fullmatch(\'[0-9a-f]{32}\',request[\'leaseNonce\']),\'exact bounded tokens\')\n  root=os.open(\'/\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);ri=identity(os.fstat(root));need(ri==identity(os.lstat(\'/\'))and ri[\'st_uid\']==0,\'held canonical host root\')\n  # Runtime uses ONLY literal /run. Explicit alternate roots exist solely for\n  # direct generated-file source tests; the closed wire passes no path override.\n  rp=Path(run_path);run=os.open(rp,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);parent=identity(os.fstat(run))\n  need(parent==identity(rp.lstat())and parent[\'st_uid\']==parent[\'st_gid\']==0 and stat.S_ISDIR(parent[\'st_mode\'])and not(parent[\'st_mode\']&0o022),\'protected held run directory\')\n  names=[\'opemos-libvirt-queue-\'+request[\'jobToken\'],\'opemos-vfio-\'+request[\'leaseNonce\']]\n  def absent():\n   for name in names:\n    try:os.stat(name,dir_fd=run,follow_symlinks=False)\n    except FileNotFoundError:pass\n    else:raise ValueError(\'Exact intent/lease path exists or aliases: \'+name)\n   need(identity(os.fstat(run))==parent==identity(rp.lstat())and identity(os.fstat(root))==ri==identity(os.lstat(\'/\')),\'held/named ancestry changed or ABA\')\n  absent();holders=[];unknown=[];count=0;procs=0\n  for p in Path(proc_path).iterdir():\n   if not p.name.isdecimal():continue\n   procs+=1;need(procs<=8192,\'finite whole proc traversal\');tick=None\n   try:\n    tick=int((p/\'stat\').read_text().rsplit(\')\',1)[1].split()[19]);fds=list((p/\'fd\').iterdir());need(len(fds)<=16384,\'finite per-process FDs\')\n    for f in fds:\n     count+=1;need(count<=262144,\'finite complete FD traversal\')\n     try:t=os.readlink(f)\n     except(FileNotFoundError,ProcessLookupError):continue\n     if t in(\'/dev/vfio/1\',\'/dev/vfio/vfio\')or t.startswith(\'/dev/vfio/devices/\'):holders.append({\'pid\':int(p.name),\'start\':tick,\'fd\':f.name,\'target\':t})\n    need(int((p/\'stat\').read_text().rsplit(\')\',1)[1].split()[19])==tick,\'PID reused during current holder observation\')\n   except(FileNotFoundError,ProcessLookupError):\n    try:now=int((p/\'stat\').read_text().rsplit(\')\',1)[1].split()[19])\n    except(FileNotFoundError,ProcessLookupError):pass\n    else:unknown.append({\'pid\':int(p.name),\'originalStart\':tick,\'currentStart\':now,\'reason\':\'incomplete still-present process\'})\n   except BaseException as e:unknown.append({\'pid\':int(p.name),\'reason\':repr(e)})\n  need(not holders and not unknown,\'complete UID0 VFIO holder/unknown absence: \'+repr({\'holders\':holders,\'unknown\':unknown}));absent()\n  proof={\'kind\':\'ROOT_EXACT_NEVER_PREPARED_LIBVIRT_ABSENCE_R1\',\'request\':request,\'bootID\':Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip(),\'actor\':{\'pid\':os.getpid(),\'start\':int(Path(\'/proc/self/stat\').read_text().rsplit(\')\',1)[1].split()[19]),\'uid\':0},\'sourceSHA256\':SOURCE_SHA256,\'startedMonotonic\':started,\'completedMonotonic\':None,\'runPath\':str(rp),\'runIdentity\':parent,\'rootIdentity\':ri,\'absentNames\':names,\'holders\':holders,\'unknown\':unknown,\'processes\':procs,\'FDs\':count,\'effects\':[],\'leaseClosureInvented\':False,\'allOwnedDescriptorsClosed\':False}\n except BaseException as e:primary=e\n finally:\n  for label,fd in [(\'run\',run),(\'host-root\',root)]:\n   if fd is not None:\n    try:os.close(fd);closes.append({\'label\':label,\'closed\':True,\'UNKNOWN\':False})\n    except BaseException as e:\n     closes.append({\'label\':label,\'closed\':False,\'UNKNOWN\':True,\'error\':repr(e)})\n     if primary is None:primary=e\n if primary is not None:\n  error=ValueError({\'firstFailure\':{\'type\':type(primary).__name__,\'reason\':str(primary)},\'closeOutcomes\':closes,\'operationOrReleaseAuthorized\':False,\'closure\':\'UNKNOWN_OR_REFUSED\'})\n  raise error from primary\n need(fdmap()==before and threading.active_count()==1 and not Path(\'/proc/self/task/\'+str(os.getpid())+\'/children\').read_text(),\'complete Root own FD/thread/child closure\')\n proof[\'completedMonotonic\']=time.monotonic();proof[\'allOwnedDescriptorsClosed\']=True;proof[\'closeOutcomes\']=closes\n need(proof[\'completedMonotonic\']-started<=15,\'existing finite Root observation wall\')\n return proof\nif __name__==\'__main__\':\n SOURCE_SHA256=sys.argv[1];request=json.loads(sys.argv[2]);print(json.dumps(observe(request),sort_keys=True,separators=(\',\',\':\')))\n'
NEVER_PREPARED_ROOT_SHA='5d2dc423452f863a3a84ab93838ad80c9d376b90e3f90eca1b743f2e89771f61'

def observe_never_prepared_libvirt(request):
    source=NEVER_PREPARED_ROOT_SOURCE;digest=hashlib.sha256(source.encode()).hexdigest()
    require(digest==NEVER_PREPARED_ROOT_SHA,'Closed exact Root absence source')
    started=time.monotonic()
    proc=subprocess.run(['sudo','-n','/usr/bin/python3','-B','-c',source,digest,canonical(request)],capture_output=True,text=True,timeout=15)
    require(proc.returncode==0 and proc.stderr=='' and 0<len(proc.stdout.encode())<=1048576,'complete existing authenticated Root absence transport')
    p=json.loads(proc.stdout);require(proc.stdout==canonical(p)+'\n','one canonical Root absence frame')
    require(set(p)=={'kind','request','bootID','actor','sourceSHA256','startedMonotonic','completedMonotonic','runPath','runIdentity','rootIdentity','absentNames','holders','unknown','processes','FDs','effects','leaseClosureInvented','allOwnedDescriptorsClosed','closeOutcomes'}and p['kind']=='ROOT_EXACT_NEVER_PREPARED_LIBVIRT_ABSENCE_R1','closed Root absence schema')
    require(p['request']==request and p['sourceSHA256']==digest and p['bootID']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'exact request/source/current boot absence')
    require(started<=p['startedMonotonic']<=p['completedMonotonic']<=time.monotonic()and time.monotonic()-p['completedMonotonic']<=1,'current finite same-host Root absence')
    require(p['actor']['uid']==0 and type(p['actor']['pid'])is int and type(p['actor']['start'])is int and p['actor']['pid']>0 and p['actor']['start']>0,'exact Root absence actor')
    require(p['runPath']=='/run'and p['absentNames']==['opemos-libvirt-queue-'+request['jobToken'],'opemos-vfio-'+request['leaseNonce']]and p['holders']==p['unknown']==p['effects']==[]and p['leaseClosureInvented']is False and p['allOwnedDescriptorsClosed']is True,'no intent/lease adoption or unknown holders')
    require(p['runIdentity']['st_uid']==p['runIdentity']['st_gid']==p['rootIdentity']['st_uid']==0 and not p['runIdentity']['st_mode']&0o022 and len(p['closeOutcomes'])==2 and all(x['closed']is True and x['UNKNOWN']is False for x in p['closeOutcomes']),'held Root ancestry and complete closure')
    diagnostic_originals([(p['actor']['pid'],p['actor']['start'])])
    return p

def failed_libvirt_logger(backend,row,props,collectedProof=None):
    request=libvirt_request(row,row['_poolBinding']);spec=json.loads(row['spec'])
    if collectedProof is None:
        require(props.get('LoadState')=='loaded'and props.get('InvocationID')==request['invocation']and props.get('MainPID')=='0'and props.get('ActiveState')in('failed','inactive')and props.get('ExecMainCode')in('1','2','3')and str(props.get('ExecMainStatus','')).isdigit()and int(props['ExecMainStatus'])!=0,'exact original numeric failed unit, no success projection')
    else:
        require(collected_libvirt_failed_absent(props) and collectedProof['request']==request and collectedProof['kind']=='ROOT_EXACT_COLLECTED_LIBVIRT_FAILED_LOGGER' and collectedProof['managerBefore']['InvocationID']==request['invocation'] and collectedProof['managerBefore']['ActiveState']=='failed','exact authenticated original failed-to-collected record')
    base=backend.root/'logs'/row['id'];fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);records={};values={}
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    def ident(s):return {k:getattr(s,k)for k in fields}
    try:
        parent=ident(os.fstat(fd));require(parent==ident(base.lstat())and parent['st_uid']==parent['st_gid']==os.getuid()and stat.S_IMODE(parent['st_mode'])==0o700,'exact current failed-log parent')
        for name in ('child-start.json','child-result.json','stdout.log','stderr.log'):
            f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            try:
                a=ident(os.fstat(f));cap=1048576 if name.endswith('.json')else MAX_LOG
                require(a==ident(os.stat(name,dir_fd=fd,follow_symlinks=False))and stat.S_ISREG(a['st_mode'])and a['st_nlink']==1 and a['st_uid']==a['st_gid']==os.getuid()and stat.S_IMODE(a['st_mode'])==0o600 and 0<=a['st_size']<=cap,'complete own failed logger leaf custody/cap')
                h=hashlib.sha256();raw=bytearray()
                while chunk:=os.read(f,65536):h.update(chunk);raw.extend(chunk);require(len(raw)<=cap,'complete logger byte cap')
                require(len(raw)==a['st_size']and a==ident(os.fstat(f))==ident(os.stat(name,dir_fd=fd,follow_symlinks=False)),'logger whole EOF/full9 unchanged')
                records[name]={'path':str(base/name),'identity':a,'bytes':len(raw),'sha256':h.hexdigest()}
                if name.endswith('.json'):values[name]=json.loads(raw)
            finally:history_close_owned(f)
        require(parent==ident(os.fstat(fd))==ident(base.lstat()),'logger parent unchanged after complete reads')
    finally:history_close_owned(fd)
    start=values['child-start.json'];end=values['child-result.json'];logger=start['loggerProvenance']
    require(logger==end['loggerProvenance']and logger['uid']==logger['euid']==os.getuid()and logger['jobId']==row['id']and logger['invocation']==request['invocation']and logger['command']==spec['command']and logger['sourceSHA256']==file_pin(Path(__file__).with_name('queue_job.py'))['sha256'],'complete original logger/job/command/source/invocation')
    require(logger['cgroup']=='0::/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/'+row['unit']+'\n','original logger exact queue group')
    require(type(start['pid'])is int and type(start['startTicks'])is int and start['pid']>0 and start['startTicks']>0 and end['childPID']==start['pid']and type(end['childNumericExit'])is int and end['childNumericExit']!=0 and end['childReaped']is True and end['pipeEOF']is True and end['outputLimit']is False and end['startRecordSHA256']==records['child-start.json']['sha256']and end['stdoutBytes']==records['stdout.log']['bytes']and end['stderrBytes']==records['stderr.log']['bytes'],'complete original failed child numeric/raw/EOF/reap')
    expected_numeric=end['childNumericExit']if end['childNumericExit']>=0 else 128-end['childNumericExit']
    if collectedProof is None:
        require(props['ExecMainCode']=='1'and int(props['ExecMainStatus'])==expected_numeric,'manager numeric binds actual logger child result')
    else:
        require(records==collectedProof['files'],'current logger full9/hash exactly equals original protected Root capture; no projected manager numeric')
    originals=diagnostic_originals([(start['pid'],start['startTicks']),(logger['pid'],logger['startTicks'])])
    return {'kind':'EXACT_FAILED_PRE_LEASE_LOGGER_R1','files':records,'numeric':end['childNumericExit'],'originals':originals,'leaseClosureInvented':False}


class SystemdBackend:
    def __init__(self, root, cfg):
        self.root, self.cfg = root, cfg
        self.observer_captures=[];self.observer_capture_receipt=None;self.terminal_implementation_pin=None
        self.prefix = "opemos-testq-" + hashlib.sha256(str(root).encode()).hexdigest()[:12] + "-"

    def ctl(self, *args):
        return systemctl(*args, manager=self.cfg.get("manager", "user"))

    def owned_unit(self, unit):
        require(type(unit) is str and re.fullmatch(re.escape(self.prefix)+r"[0-9a-f]{32}\.service", unit), "Unit is not owned by this queue")

    def pool_properties(self):
        return self.ctl("show", self.cfg["slice"], "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "MemoryMax", "-p", "MemorySwapMax", "-p", "CPUQuotaPerSecUSec", "-p", "AllowedCPUs", "-p", "ControlGroup")

    def pool_unit_properties(self, unit):
        self.owned_unit(unit)
        return self.ctl("show", unit, "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "MainPID", "-p", "ControlGroup", "-p", "InvocationID", "-p", "MemoryMax", "-p", "MemorySwapMax", "-p", "CPUQuotaPerSecUSec", "-p", "AllowedCPUs")

    def capture_pool_unit_binding(self, job_id, spec, cpus, unit):
        self.owned_unit(unit)
        props = self.pool_unit_properties(unit)
        require(props.get("LoadState") == "loaded" and type(props.get("InvocationID")) is str and re.fullmatch(r"[0-9a-f]{32}", props["InvocationID"]), "Current pool own launch has no current invocation; retain lease")
        return {"version": 1, "job_id": job_id, "unit": unit, "stateRoot": str(self.root), "prefix": self.prefix, "specSHA256": hashlib.sha256(canonical(spec).encode()).hexdigest(), "cpus": cpus, "memory": spec["memory"], "invocation": props["InvocationID"], "recordedAtUnix": time.time(), "initialCurrentUnitProperties": props}

    def validate_pool(self, rows):
        deadline=time.monotonic()+15;first=None
        for cut in range(2):
            try:
                proof=self._validate_pool_cut(rows,deadline)
                require(time.monotonic()<deadline,'original whole pool observation deadline')
                if first is not None:proof['runtimePublicationTransition']=first
                return proof
            except RuntimePublisherTransition as error:
                if first is not None:
                    raise pool_observation_unavailable(error.evidence['after']['request'],error.evidence['recordedReservations'],{'kind':'SECOND_RUNTIME_PUBLICATION_TRANSITION_REFUSED','first':first,'second':error.evidence},True) from error
                first=error.evidence
                if time.monotonic()>=deadline:raise pool_observation_unavailable(first['after']['request'],first['recordedReservations'],{'kind':'ORIGINAL_POOL_DEADLINE_DURING_PUBLICATION_TRANSITION','first':first},True) from error
        raise ValueError('no stable complete pool cut')

    def pool_libvirt_observation(self,request,deadline,reservations,observer=None):
        observer=observe_queue_libvirt if observer is None else observer
        try:return observer(request,deadline,self.observer_captures,self.terminal_implementation_pin)
        except Exception as error:
            child=getattr(error,'adapterEvidence',None)
            # A source-open/identity failure or an unknown child is not an
            # honestly completed readonly observation. Preserve its failure.
            if not(type(child)is dict and child.get('EOF')is True and child.get('reaped')is True):raise
            failure={'type':type(error).__name__,'reason':str(error),'evidence':getattr(error,'evidence',None),'readonlyObserverFailure':getattr(error,'readonlyObserverFailure',None)}
            raise pool_observation_unavailable(request,reservations,failure,True) from error

    def _validate_pool_cut(self, rows, deadline):
        cfg = self.cfg
        require(cfg["cpu_ids"] == DEFAULT_CPUS and cfg["memory_bytes"] == DEFAULT_RAM,
                "Production worker requires the authorized 10-core/32-GiB pool")
        require(cfg.get("manager") == "system" and max(cfg["cpu_ids"]) < os.cpu_count(), "Current complete system OMEN pool required")
        props = self.pool_properties()
        reservations = []
        libvirt=[];observed_libvirt=[];requests=[];self._libvirt_requests={};self._libvirt_rows={}
        for row in rows:
            if row["state"] not in ("running", "terminal_cleanup"):
                continue
            self.owned_unit(row["unit"])
            spec = json.loads(row["spec"])
            check_inputs(spec)
            cpus = json.loads(row["cpus"])
            require(len(cpus) == spec["cores"] and row["id"] == spec["id"], "Recorded current job/CPU assignment differs")
            bound = row.get("_poolBinding")
            if bound is not None:
                require(bound["version"] == 1 and bound["job_id"] == row["id"] and bound["unit"] == row["unit"] and bound["stateRoot"] == str(self.root) and bound["prefix"] == self.prefix and bound["specSHA256"] == hashlib.sha256(canonical(spec).encode()).hexdigest() and bound["cpus"] == cpus and bound["memory"] == spec["memory"], "Recorded owned unit invocation binding conflicts")
            reservation={"unit":row["unit"],"cpus":cpus,"memory":spec["memory"],"resources":spec["resources"],"invocation":None if bound is None else bound["invocation"]}
            if "libvirt_domain" in spec:
                reservation["controllerMemory"]=LIBVIRT_CONTROLLER_MEMORY
                if bound is not None:
                    request=libvirt_request(row,bound);self._libvirt_requests[row["unit"]]=request;self._libvirt_rows[row["unit"]]=dict(row)
                    requests.append(request)
            reservations.append(reservation)
        for request in requests:
            observation=self.pool_libvirt_observation(request,deadline,reservations);observed_libvirt.append(observation)
            if observation["phase"]!="NOT_PREPARED":libvirt.append(observation)
        require(hashlib.sha256(POOL_PROOF_SOURCE.encode()).hexdigest() == POOL_PROOF_SHA, "Closed pool proof source pin")
        module = {"__name__": "owned_readonly_pool_admission"}
        exec(compile(POOL_PROOF_SOURCE, "root_pool_proof_r1.py", "exec"), module)
        try:
            proof = module["readonly_pool"](props.get("ControlGroup"), props, reservations, self.prefix, self.pool_properties, self.pool_unit_properties, min(5,max(.001,deadline-time.monotonic())), machine_bindings=libvirt)
        except (ValueError, OSError) as error:
            raise PoolAdmissionFailure(type(error).__name__ + ":" + str(error), {"admitted": False, "firstFailure": getattr(error, "evidence", None), "currentPoolProperties": props, "recordedReservations": reservations, "reservationRetained": True, "operationOrReleaseAuthorized": False}) from error
        for observed in observed_libvirt:
            again=self.pool_libvirt_observation(observed["request"],deadline,reservations)
            verify_libvirt_second_cut(observed,again,reservations,deadline)
        return proof

    def launch(self, spec, cpus, unit, output):
        self.owned_unit(unit)
        env = {"CARGO_BUILD_JOBS": str(len(cpus)), "MAKEFLAGS": f"-j{len(cpus)}",
               "CMAKE_BUILD_PARALLEL_LEVEL": str(len(cpus)), "OMP_NUM_THREADS": str(len(cpus)),
               "OPEMOS_QUEUE_CPUS": ",".join(map(str, cpus)), "OPEMOS_QUEUE_MEMORY": str(spec["memory"])}
        launcher = (["systemd-run", "--user"] if self.cfg.get("manager", "user") == "user"
                    else ["sudo", "-n", "systemd-run", "--uid="+str(os.getuid()), "--gid="+str(os.getgid())])
        command = [*launcher, "--quiet", "--no-block", "--unit=" + unit,
                   "--slice=" + self.cfg["slice"], "--service-type=exec",
                   "--property=AllowedCPUs=" + ",".join(map(str, cpus)),
                   "--property=CPUQuota=" + str(len(cpus) * 100) + "%",
                   "--property=MemoryMax=" + str(LIBVIRT_CONTROLLER_MEMORY if "libvirt_domain" in spec else spec["memory"]), "--property=MemorySwapMax=0",
                   "--property=TasksMax=4096", "--property=KillMode=control-group",
                   "--property=RemainAfterExit=yes",
                   # A log cap must not constrain qcow2 disks/build outputs.
                   "--property=LimitFSIZE=infinity",
                   "--property=TimeoutStopSec=10", "--property=SendSIGKILL=yes",
                   "--property=RuntimeMaxSec=" + str(spec["timeout_seconds"]),
                   "--property=WorkingDirectory=" + spec["cwd"],
                   "--property=StandardOutput=journal", "--property=StandardError=journal"]
        command += ["--setenv=" + k + "=" + v for k, v in env.items()]
        logger = Path(__file__).with_name("queue_job.py")
        require(logger.is_file(), "Bounded log runner is missing")
        command += ["--", "/usr/bin/python3", str(logger), "--logs", str(output),
                    "--limit", str(MAX_LOG), "--", *spec["command"]]
        waiting = launch_admission_wait(spec)
        if waiting is not None:
            return {"readiness_wait": waiting, "unit_not_created": True}
        proc = subprocess.run(command, capture_output=True, text=True, timeout=15)
        if proc.returncode:
            # The launcher completed and was reaped. Distinguish an uncreated
            # unit from an accepted unit whose start/closure still needs polling.
            props = self.ctl("show", unit, "-p", "LoadState")
            if props.get("LoadState") == "not-found":
                return {"launch_failed": True, "exit_code": proc.returncode,
                        "stderr": proc.stderr, "unit_not_created": True}
            return None
        return None

    def inspect(self, unit):
        self.owned_unit(unit)
        props = self.ctl("show", unit, "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
                          "-p", "Result", "-p", "ExecMainCode", "-p", "ExecMainStatus", "-p", "MainPID",
                          "-p", "ControlGroup", "-p", "InvocationID")
        if props.get("LoadState") == "not-found":
            return "unknown", {"reason": "Unit evidence missing; reservation retained"}, False
        exited = props.get("ActiveState") == "active" and props.get("SubState") == "exited"
        if not exited and props.get("ActiveState") in ("activating", "active", "deactivating", "reloading"):
            return None, props, False
        try:
            invocation = props.get("InvocationID")
            require(type(invocation) is str and re.fullmatch(r"[0-9a-f]{32}", invocation),
                    "Missing exact unit invocation; reservation held")
            require(props.get("ExecMainCode") in ("1", "2", "3") and
                    str(props.get("ExecMainStatus", "")).isdigit(), "Missing numeric terminal")
            proof = self.whole_owned_cgroup(unit, props)
            if not proof["empty"] or props.get("MainPID") != "0":
                return None, dict(props, ownedCgroupProof=proof), False
            # Readonly observation: stop can garbage collect this InvocationID.
            # Preserve it until finish_bound has durably committed terminal evidence.
            latest = self.ctl("show", unit, "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
                              "-p", "Result", "-p", "ExecMainCode", "-p", "ExecMainStatus", "-p", "MainPID",
                              "-p", "ControlGroup", "-p", "InvocationID")
            require(latest == props, "Unit changed during closure proof")
            proof = self.whole_owned_cgroup(unit, latest)
            require(proof["empty"], "Cgroup changed before release")
            props["ownedCgroupProof"] = proof
        except (ValueError, OSError) as error:
            return "unknown", dict(props, closureFailure=str(error), closureFailureEvidence=getattr(error, 'evidence', None), reservationRetained=True), False
        if props.get("Result") == "timeout":
            return "timed_out", props, True
        success = props.get("Result") == "success" and props.get("ExecMainCode") == "1" and props.get("ExecMainStatus") == "0"
        return ("passed" if success else "failed"), props, True

    def whole_owned_cgroup(self, unit, props):
        self.owned_unit(unit)
        pool = self.ctl("show", self.cfg["slice"], "-p", "ControlGroup").get("ControlGroup")
        require(type(pool) is str and pool.startswith("/") and Path(pool).name == self.cfg["slice"], "live pool path")
        derived = pool + "/" + unit
        require(type(props.get("ControlGroup")) is str and props["ControlGroup"] in ("", derived), "conflicting unit cgroup")
        _cg_source = CG_PROOF_SOURCE
        require(hashlib.sha256(_cg_source.encode()).hexdigest() == CG_PROOF_SHA, "cgroup source pin")
        _cg = {"__name__": "owned_readonly_cgroup"}
        exec(compile(_cg_source, "root_cgroup_proof_r3.py", "exec"), _cg)
        service=_cg["readonly_empty"](derived,pool,2)
        request=getattr(self,"_libvirt_requests",{}).get(unit)
        if request is None:return service
        observed=observe_queue_libvirt(request,captures=self.observer_captures,terminal_implementation_pin=self.terminal_implementation_pin)
        vm=_cg["readonly_empty"](pool+"/"+request["vmSlice"],pool,2)
        if observed['phase']=='NOT_PREPARED':
            row=getattr(self,'_libvirt_rows',{}).get(unit)
            require(row is not None and libvirt_request(row,row['_poolBinding'])==request and service['empty']is True and vm['empty']is True,'exact bound never-prepared failed row and both groups empty')
            logger=failed_libvirt_logger(self,row,props)
            first=observe_never_prepared_libvirt(request)
            gpu=observe_gpu_group()
            require(gpu['complete']is True and gpu['gpuAvailable']is True and gpu['group']==NVIDIA_RESOURCE and gpu['allOwnedDescriptorsClosed']is True and gpu['effects']==[],'current physical group has no retained/unknown lease')
            require(observe_queue_libvirt(request,captures=self.observer_captures,terminal_implementation_pin=self.terminal_implementation_pin)==observed,'never-prepared domain/intent observation raced')
            last=observe_never_prepared_libvirt(request)
            require(first['runIdentity']==last['runIdentity']and first['rootIdentity']==last['rootIdentity'],'never-prepared ancestry changed between independent observations')
            return {'empty':True,'queueService':service,'libvirtPartition':vm,'libvirtDomain':observed,'neverPrepared':{'kind':'FAILED_BEFORE_LIBVIRT_PREPARATION','logger':logger,'firstRootAbsence':first,'lastRootAbsence':last,'physicalLeaseReadonly':gpu,'leaseEverCreated':False,'leaseClosureInvented':False}}
        require(observed["phase"]=="CLOSED" and observed["lease"]["closed"] and observed["lease"]["restored"],"No libvirt domain/GPU lease release before complete current closure")
        return {"empty":service["empty"] and vm["empty"],"queueService":service,"libvirtPartition":vm,"libvirtDomain":observed}

    def stop(self, unit):
        self.owned_unit(unit)
        self.ctl("stop", unit)


def check_inputs(spec):
    for expected in [*spec["files"], spec["approval"]]:
        require(file_pin(expected["path"]) == expected, "Input/approval changed: " + expected["path"])


def finish(db, name, state, result):
    with db:
        db.execute("UPDATE jobs SET state=?,finished=?,result=? WHERE id=?",
                   (state, time.time(), canonical(result), name))


def pool_rows(db, rows):
    bindings = {row["job_id"]: json.loads(row["value"]) for row in db.execute("SELECT job_id,value FROM pool_unit_bindings")}
    return [dict(row, _poolBinding=bindings.get(row["id"])) for row in rows]

# Exact historical diagnostic protocol. Included in test_queue.py; not a plugin.
DIAGNOSTIC_KIND = 'ROOT_BOUND_STEAMOS3828_R2_R3_DIAGNOSTIC_TERMINAL'
DIAGNOSTIC_APPROVAL = 'EXACT_STEAMOS3828_R2_R3_DIAGNOSTIC_ROOT_APPROVAL'
DIAGNOSTIC_TERMINAL_INPUTS = {}
DIAGNOSTIC_TARGETS = {
    'steamos3828-ab-baseline-r2-e2c149383b0a': {
        'unit': 'opemos-testq-3b4eb7b4288f-d1ef68169b634d6db237cf88f8c6ce62.service',
        'invocation': '70f9f5b3140d4d0dbc33f97f339985e4',
        'nonce': 'e2c149383b0a4548a734281244bbc0de',
        'output': '/var/lib/opemos-steamos3828-bench-boot-r2',
        'nativeNames': ['overlay-create', 'overlay-info', 'unit-observe'],
    },
    'steamos3828-verbose-r3-2749f7b7e490': {
        'unit': 'opemos-testq-3b4eb7b4288f-5cb346aaaab84c30a3e3c0c3b02ed9c0.service',
        'invocation': 'c491cff895354eef839f4ea27c0d1c73',
        'nonce': '2749f7b7e4904fb38d3a35994ce753f8',
        'output': '/var/lib/opemos-steamos3828-verbose-boot-r3',
        'nativeNames': ['unit-observe'],
    },
}


def diagnostic_ledger(db):
    return {'rows': [dict(x) for x in db.execute('SELECT * FROM jobs ORDER BY rowid')],
            'bindings': [list(x) for x in db.execute('SELECT job_id,value FROM pool_unit_bindings ORDER BY job_id')],
            'config': [list(x) for x in db.execute('SELECT * FROM config ORDER BY id')]}


def diagnostic_pool(pool, units):
    require(all(pool.get(k) is True for k in ('includesUID0', 'completeBoundedTraversal', 'admitted', 'allOwnedDescriptorsClosed', 'currentWholePoolEmpty')),
            'diagnostic requires complete current whole UID0 pool and closed descriptors')
    require(pool['tasks'] == [] and pool['lastKernelWholePoolPopulated'] == '0' and
            set(pool['unknownReservationsRetained']) == set(units) and pool['knownInvocations'] == {},
            'only the two exact retained diagnostic reservations, no foreign work')
    for unit in units:
        props = pool['unitProperties'][unit]['properties']
        require(props['LoadState'] == 'not-found' and props['MainPID'] == '0' and props['InvocationID'] == '' and props['ControlGroup'] == '',
                'diagnostic original unit must remain collected, not rearmed')


def diagnostic_identity(actor, unit):
    require(type(actor['pid']) is int and actor['pid'] > 0 and type(actor['start']) is int and actor['start'] > 0 and
            actor['uid'] == ['0'] * 4 and actor['cgroup'] == '0::/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/' + unit,
            'exact positive original Root/native PID-start credentials and cgroup')
    return (actor['pid'], actor['start'])


def diagnostic_originals(identities):
    # Current negative observations do not invent historical starts. Unknown,
    # permission denied, malformed stat, or reused PID stays held.
    observations = []
    for pid, start in sorted(set(tuple(x) for x in identities)):
        require(type(pid) is int and pid > 0 and type(start) is int and start > 0, 'typed original PID-start')
        fd = None
        try:
            fd = os.open('/proc/' + str(pid) + '/stat', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            raw = os.read(fd, 65537)
            require(len(raw) <= 65536, 'bounded complete original proc stat')
            require(os.read(fd, 1) == b'', 'complete proc stat EOF')
        except OSError as error:
            import errno
            require(error.errno in (errno.ENOENT, errno.ESRCH), 'original observation unknown, keep lease')
            observations.append({'pid': pid, 'start': start, 'originalAbsent': True, 'errno': error.errno})
        else:
            text = raw.decode('ascii'); fields = text[text.rfind(')') + 2:].split()
            require(len(fields) >= 20 and text.split(' ', 1)[0] == str(pid), 'valid exact original proc stat')
            raise ValueError('Original PID present or reused; diagnostic release refused: ' + str((pid, start, int(fields[19]))))
        finally:
            if fd is not None: os.close(fd)
    return observations


def diagnostic_asset(pin, whole_hash):
    # Root producer hashes complete stopped assets. Worker rechecks full9 custody
    # of the exact protected inode after that hash, never a reserialized digest.
    import stat
    path = Path(pin['path']); require(path.is_absolute() and path.resolve(strict=True) == path and not any(p.is_symlink() for p in [path, *path.parents]), 'asset no aliases')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        keys = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        st = os.fstat(fd); identity = {k: getattr(st, k) for k in keys}
        require(identity == pin['identity'] and stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022 and 0 < st.st_size == pin['bytes'] <= 60 * 1024**3, 'protected exact full asset identity/cap')
        if whole_hash:
            digest = hashlib.sha256(); count = 0
            while True:
                block = os.read(fd, 1024**2)
                if not block: break
                count += len(block); digest.update(block); require(count <= pin['bytes'], 'asset growth refused')
            require(count == pin['bytes'] and digest.hexdigest() == pin['sha256'], 'complete stopped asset SHA/EOF')
        require(identity == {k: getattr(os.fstat(fd), k) for k in keys} == {k: getattr(os.lstat(path), k) for k in keys}, 'asset held/named custody unchanged')
    finally: os.close(fd)


def diagnostic_host_guard(assets):
    require(os.getuid() == os.geteuid() == 0, 'whole host holder inspection requires actual Root')
    # Reuse the finite exact /proc inspection strategy of the accepted Root
    # postflight. This does not infer success or signal any observed process.
    keys = {tuple(pin['identity'][k] for k in ('st_dev','st_ino')) for values in assets.values() for pin in values}
    prefixes = [t['output'] + '/' for t in DIAGNOSTIC_TARGETS.values()]
    hits = []; errors = []; count = 0
    import errno
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal() or int(path.name) == os.getpid(): continue
        count += 1; require(count <= 32768, 'finite complete proc holder traversal cap')
        try:
            raw = (path/'stat').read_text(); ticks = int(raw[raw.rfind(')')+2:].split()[19])
            argv = (path/'cmdline').read_bytes(); require(len(argv) <= 1048576, 'bounded process argv')
            comm = (path/'comm').read_text().strip()
            if comm.startswith('qemu-system') or b'/home/connor/.local/state/opemos-test-queue-r2/test_queue.py' in argv.split(b'\0') or b'/home/connor/.local/state/opemos-test-queue-r2/queue.sh' in argv.split(b'\0'):
                hits.append({'pid':int(path.name),'start':ticks,'comm':comm,'argv':argv.decode(errors='replace')})
            with os.scandir(path/'fd') as entries:
                for entry in entries:
                    try:
                        target = os.readlink(entry.path); st = os.stat(entry.path)
                        if (st.st_dev,st.st_ino) in keys or any(target.startswith(p) for p in prefixes):
                            hits.append({'pid':int(path.name),'start':ticks,'fd':entry.name,'target':target,'dev':st.st_dev,'ino':st.st_ino})
                    except OSError as error:
                        if error.errno not in (errno.ENOENT,errno.ESRCH): raise
            now = (path/'stat').read_text(); require(int(now[now.rfind(')')+2:].split()[19]) == ticks, 'holder process identity changed during observation')
        except OSError as error:
            if error.errno not in (errno.ENOENT,errno.ESRCH): errors.append({'pid':path.name,'type':type(error).__name__,'errno':error.errno,'reason':str(error)})
    require(not hits and not errors, 'foreign QEMU/worker/asset/output holder or unknown observation: ' + canonical({'hits':hits,'errors':errors}))
    return {'RootUID':0,'completeUID0Traversal':True,'processesInspected':count,'hits':hits,'errors':errors,'completedMonotonic':time.monotonic(),'stopOrSignalPerformed':False}


def diagnostic_inputs(pins):
    required = {'context','approval','terminal','qemu','early','start','result','stdout','stderr','journal','native'}
    require(set(pins) == required, 'closed complete diagnostic input roles')
    out = {}
    for name in ('context','approval','terminal','qemu','early'):
        out[name] = collected_read(pins[name], 0, 0o444 if name == 'approval' else 0o400)
    for name in ('start','result'): out[name] = collected_read(pins[name], 1000, 0o600)
    for name in ('stdout','stderr'): out[name] = collected_read(pins[name], 1000, 0o600, False)
    # This is a fresh Root-protected complete journal capture, not a boolean.
    out['journal'] = collected_read(pins['journal'], 0, 0o444)
    require(type(pins['native']) is dict and len(pins['native']) <= 3, 'finite original native sites')
    out['native'] = {n: collected_read(p, 0, 0o400) for n, p in pins['native'].items()}
    return out


def diagnostic_bundle(row, binding, pins, data, assets, pool, boot):
    target = DIAGNOSTIC_TARGETS[row['id']]; spec = json.loads(row['spec']); unit = target['unit']; inv = target['invocation']
    require(row['state'] == 'running' and row['finished'] is None and row['unit'] == unit and retained_unknown_marker(dict(row, _poolBinding=binding)), 'exact retained historical running lease')
    require(binding['job_id'] == row['id'] and binding['unit'] == unit and binding['invocation'] == inv and
            binding['specSHA256'] == hashlib.sha256(canonical(spec).encode()).hexdigest() and binding['cpus'] == json.loads(row['cpus']) and
            binding['memory'] == spec['memory'] and binding['stateRoot'] == '/home/connor/.local/state/opemos-test-queue-r2/state', 'exact immutable original spec/unit/invocation/binding')
    ctx = data['context']; approval = data['approval']; terminal = data['terminal']; qemu = data['qemu']; early = data['early']
    minimal = lambda p: {k: p[k] for k in ('path','bytes','sha256')}
    require(minimal(pins['approval']) == spec['approval'] == minimal(ctx['approvalPin']) and ctx['jobID'] == approval['jobID'] == row['id'] and
            ctx['nonce'] == approval['nonce'] == target['nonce'] and ctx['jobSHA256'] == spec['files'][0]['sha256'] and
            ctx['hostBoot'] == boot and ctx['CoreProductInstallAuthorized'] is False and target['output'] in spec['resources'], 'actual diagnostic protected approval/context/source/boot')
    require(spec['command'] == ['/usr/bin/sudo','-n','/usr/bin/python3','-B',spec['files'][0]['path']] and spec['cwd'] == str(Path(spec['files'][0]['path']).parent), 'original exact diagnostic command')
    require(set(data['native']) == set(target['nativeNames']), 'all original native captures required')
    origins = {diagnostic_identity(terminal['own'], unit), diagnostic_identity(terminal['QEMU'], unit)}
    require(terminal['numeric'] == 0 and type(terminal['numeric']) is int and terminal['first'] is None and
            terminal['VMStarted'] is True and terminal['guestVersionKernelUserspaceModulesAcceptance'] is False and
            terminal['knownQEMUClosed'] is True and terminal['FDSetRestored'] is True and terminal['busy'] is False and terminal['resources'] == [] and
            terminal['remainingGroupMembers'] == [] and terminal['liveNativeHelpers'] == [] and terminal['secondaryCleanup'] == [] and terminal['children'] == '' and terminal['threads'] == 1, 'complete Root diagnostic closure, NOT baseline/package success')
    require(qemu['actor'] == terminal['QEMU'] == early['actor'] and qemu['unit'] == early['unit'] == unit and qemu['InvocationID'] == early['InvocationID'] == inv and
            type(qemu['numeric']) is int and qemu['numeric'] == 0 and all(qemu[k] is True for k in ('originalAbsent','reaped','waitReturned','stdoutFDClosed','stderrFDClosed')), 'actual bound QEMU numeric/EOF/reap')
    require(len(assets) == 2 and len({a['path'] for a in assets}) == 2 and early['SourceImage'] == ctx['original'], 'exact original and stopped working image set')
    require(assets[0]['path'] == '/var/lib/opemos-steamos3828-ab-bench-20261016-r1/same-guest-ab-original.raw' and assets[0]['bytes'] == 21474836480 and assets[0]['sha256'] == 'aac7d4645208527f893d6dcd5d1facfcc0ef8f40ff1e71f30d592427c76aa8bd', 'original immutable standalone source retained')
    if row['id'].startswith('steamos3828-ab-baseline-r2-'):
        require(minimal(ctx['original']) == minimal(assets[0]) and assets[1]['path'] == target['output'] + '/same-guest-working.qcow2' and assets[1]['bytes'] == 7602176 and assets[1]['sha256'] == '435d557e1f6a59974534b07a78e5f162211c7f75cfe244c61098477199603d4b', 'exact R2 immutable original and stopped overlay')
    else:
        require(ctx['original']['path'] == assets[1]['path'] == '/var/lib/opemos-steamos3828-verbose-diag-r3/diagnostic-verbose.raw' and ctx['original']['bytes'] == assets[1]['bytes'] == 21474836480 and ctx['original']['sha256'] == 'e033c3350bbc56298b6943f57b110085bea811db37a6a0ca02746c914c5cbfc2' and assets[1]['sha256'] == '94bc0b8dc0aee438223b7778c0a9fa56220e240e80c3d0fd6c5c1147cd01f1b7', 'exact admitted R3 disposable preboot and stopped diagnostic hashes, not immutable equality')
    for name, capture in data['native'].items():
        origins.add(diagnostic_identity(capture['actor'], unit))
        require(type(capture['numeric']) is int and capture['numeric'] == 0 and all(capture[k] is True for k in ('originalAbsent','pipesClosed','reaped','stdoutEOF','stderrEOF')), 'each original native capture complete numeric/FD/EOF')
        expected_argv = (['/usr/bin/systemctl','show',unit,'--property=InvocationID,MainPID,ActiveState,ControlGroup,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,AllowedCPUs'] if name == 'unit-observe' else ['/usr/bin/qemu-img','create','-f','qcow2','-F','raw','-b',assets[0]['path'],assets[1]['path']] if name == 'overlay-create' else ['/usr/bin/qemu-img','info','--output=json',assets[1]['path']])
        require(capture['argv'] == expected_argv, 'complete exact original native site argv/assets/unit')
    unit_capture = data['native']['unit-observe']; props = dict(line.split('=', 1) for line in unit_capture['stdout'].splitlines() if '=' in line)
    require(props['InvocationID'] == inv and props['ControlGroup'].endswith('/' + unit) and props['MainPID'] == binding['initialCurrentUnitProperties']['MainPID'], 'original native manager observation binds logger and invocation')
    start = data['start']; result = data['result']; logger = start['loggerProvenance']
    require(logger == result['loggerProvenance'] and logger['jobId'] == row['id'] and logger['command'] == spec['command'] and logger['invocation'] == inv and
            logger['cgroup'] == '0::' + props['ControlGroup'] + '\n' and logger['uid'] == logger['euid'] == 1000 and str(logger['pid']) == props['MainPID'] and
            logger['sourceSHA256'] == 'cf380b2ee3ea2dc3ec5603779b39050b9fb2666f55babac7c76478024b04a417' and start['parentPID'] == logger['pid'], 'exact original deployed logger provenance')
    for pid, ticks in ((start['pid'], start['startTicks']), (logger['pid'], logger['startTicks'])):
        require(type(pid) is int and pid > 0 and type(ticks) is int and ticks > 0, 'positive observed logger/sudo starts, never fabricated')
        origins.add((pid, ticks))
    require(type(result['childNumericExit']) is int and result['childNumericExit'] == 0 and result['childPID'] == start['pid'] and
            result['childReaped'] is True and result['pipeEOF'] is True and result['outputLimit'] is False and
            result['stdoutBytes'] == len(data['stdout']) == pins['stdout']['bytes'] and result['stderrBytes'] == len(data['stderr']) == pins['stderr']['bytes'], 'whole logger numeric0/raw counts/EOF/reap')
    records = []
    for line in data['stdout'].splitlines():
        try: records.append(json.loads(line))
        except (ValueError, UnicodeError): raise ValueError('Diagnostic Root stdout must be complete JSON-line records')
    require([r['BOOT_JOB_EARLY'] for r in records if 'BOOT_JOB_EARLY' in r] == [terminal['own']], 'Root original tied to actual logger stdout')
    for name, value in (('job-terminal.json', terminal), ('qemu-terminal.json', qemu), ('qemu-early.json', early)):
        require([r['LIVE_GUEST_RECEIPT']['value'] for r in records if r.get('LIVE_GUEST_RECEIPT', {}).get('name') == name] == [value], 'whole raw logger and protected Root receipt equality')
    journal = data['journal']; require(journal['numeric'] == 0 and journal['stdoutEOF'] is True and journal['stderrEOF'] is True and journal['reaped'] is True and journal['pipesClosed'] is True, 'complete Root journal capture')
    entries = [json.loads(line) for line in journal['stdout'].splitlines()]
    relevant = [e for e in entries if e.get('UNIT') == unit and e.get('INVOCATION_ID') == inv and e.get('_BOOT_ID') == boot.replace('-', '') and e.get('_PID') == '1' and e.get('_UID') == '0']
    require(any(e.get('MESSAGE', '').startswith('Started ' + unit) for e in relevant) and any(e.get('MESSAGE') == unit + ': Deactivated successfully.' for e in relevant) and
            any(e.get('MESSAGE', '').startswith('Stopped ' + unit) for e in relevant), 'same-invocation original PID1 journal lifecycle, not stop-caller inference')
    return ({'state':'failed','terminalType':'HISTORICAL_DIAGNOSTIC_BASELINE_UNPROVEN','jobId':row['id'],'unit':unit,'invocation':inv,
             'guestBaselineAccepted':False,'packageAcceptance':False,'RootNumeric':0,'loggerChildNumeric':0,'QEMUNumeric':0,
             'newGuestOrCompilerAdmission':False,'evidencePins':pins,'stoppedAssets':assets}, sorted(origins))


def diagnostic_reference_equivalence(original, ordered, rowids):
    """Representation join only. Live ledger comparisons stay order-exact."""
    fields = {'id','spec','state','cpus','unit','started','finished','result'}
    for ledger in (original, ordered):
        require(type(ledger) is dict and set(ledger) == {'rows','bindings','config'} and
                type(ledger['rows']) is list and len(ledger['rows']) == 30 and
                all(type(row) is dict and set(row) == fields and type(row['id']) is str for row in ledger['rows']), 'closed original thirty-row schema')
        ids = [row['id'] for row in ledger['rows']]
        require(len(set(ids)) == 30, 'unique original job IDs, no dropped/duplicate row')
        require(type(ledger['bindings']) is list and len(ledger['bindings']) == 26 and
                all(type(b) is list and len(b) == 2 and type(b[0]) is str and type(b[1]) is str for b in ledger['bindings']) and
                len({b[0] for b in ledger['bindings']}) == 26 and
                ledger['bindings'] == sorted(ledger['bindings'],key=lambda b:b[0]), 'complete unique twenty-six bindings in canonical binding order')
    require([row['id'] for row in original['rows']] == sorted(row['id'] for row in original['rows']), 'preserved original reference is ID-ordered')
    require(canonical({row['id']:row for row in original['rows']}) == canonical({row['id']:row for row in ordered['rows']}) and
            canonical(original['bindings']) == canonical(ordered['bindings']) and canonical(original['config']) == canonical(ordered['config']), 'every original per-ID field/binding/config exact across representations')
    require(type(rowids) is list and len(rowids) == 30 and all(type(p) is list and len(p) == 2 and type(p[0]) is int and p[0] > 0 and type(p[1]) is str for p in rowids) and
            [p[0] for p in rowids] == sorted(set(p[0] for p in rowids)) and
            [p[1] for p in rowids] == [r['id'] for r in ordered['rows']], 'actual unique positive SQLite rowid sequence binds exact ordered rows')
    return {'same30UniqueIDs':True,'allFieldsExact':True,'all26BindingsExact':True,'configExact':True,
            'originalCanonicalSHA256':hashlib.sha256(canonical(original).encode()).hexdigest(),
            'rowidCanonicalSHA256':hashlib.sha256(canonical(ordered).encode()).hexdigest(),'rowids':rowids}


def root_diagnostic_rowid_reference(db, originalIDPin, producerPin, boot):
    require(os.getuid() == os.geteuid() == 0, 'actual Root rowid-reference producer required')
    original = collected_read(originalIDPin,0,0o444)
    ordered = diagnostic_ledger(db)
    rowids = [list(row) for row in db.execute('SELECT rowid,id FROM jobs ORDER BY rowid')]
    proof = diagnostic_reference_equivalence(original,ordered,rowids)
    require(diagnostic_ledger(db) == ordered, 'complete private snapshot unchanged across both actual rowid queries')
    require(producerPin == file_pin(__file__) and boot == Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'same exact Root source/current boot')
    return {'kind':'ROOT_BOUND_R2_R3_ROWID_REFERENCE','RootUID':0,'producerPin':producerPin,'boot':boot,'originalIDReferencePin':originalIDPin,
            'query':'SELECT * FROM jobs ORDER BY rowid','rowidQuery':'SELECT rowid,id FROM jobs ORDER BY rowid',
            'ledger':ordered,'proof':proof}


def read_diagnostic_rowid_reference(pin, producerPin, boot):
    reference = collected_read(pin,0,0o444)
    require(reference['kind'] == 'ROOT_BOUND_R2_R3_ROWID_REFERENCE' and reference['RootUID'] == 0 and reference['producerPin'] == producerPin and
            reference['boot'] == boot and reference['query'] == 'SELECT * FROM jobs ORDER BY rowid' and reference['rowidQuery'] == 'SELECT rowid,id FROM jobs ORDER BY rowid', 'same protected actual rowid-reference/source/boot')
    original = collected_read(reference['originalIDReferencePin'],0,0o444)
    require(diagnostic_reference_equivalence(original,reference['ledger'],reference['proof']['rowids']) == reference['proof'], 'complete independently rechecked representation join')
    return reference['ledger']


def root_diagnostic_receipt(db, backend, inputs, assets, producerPin, boot, expectedLedgerPin):
    require(os.getuid() == os.geteuid() == 0, 'actual Root producer required')
    ledger = diagnostic_ledger(db)
    require(ledger == read_diagnostic_rowid_reference(expectedLedgerPin,producerPin,boot), 'exact protected actual rowid-order reference, not reordered live equality')
    require(len(ledger['rows']) == 30 and len(ledger['bindings']) == 26 and set(inputs) == set(assets) == set(DIAGNOSTIC_TARGETS), 'closed exact thirty-row/twenty-six-binding two-job protocol')
    require([r['id'] for r in ledger['rows'] if r['state'] not in TERMINAL] == list(DIAGNOSTIC_TARGETS), 'no pending/foreign dispatchable or retained work')
    decisions = {}; identities = set(); bindings = dict(ledger['bindings'])
    for job in DIAGNOSTIC_TARGETS:
        row = next(r for r in ledger['rows'] if r['id'] == job); check_inputs(json.loads(row['spec']))
        for pin in assets[job]: diagnostic_asset(pin, True)
        decision, origins = diagnostic_bundle(row, json.loads(bindings[job]), inputs[job], diagnostic_inputs(inputs[job]), assets[job], {}, boot)
        decisions[job] = decision; identities.update(map(tuple, origins))
    host = diagnostic_host_guard(assets)
    require(diagnostic_ledger(db) == ledger, 'producer entire current snapshot unchanged after complete reads')
    _, pool = boundary_pool_epoch(db, backend)
    diagnostic_pool(pool, [t['unit'] for t in DIAGNOSTIC_TARGETS.values()])
    # Issuance is after all full reads; finite receipt is not a cached pool grant.
    originals = diagnostic_originals(identities); recent_boundary(pool, time.monotonic()); issued = time.time()
    return {'kind':DIAGNOSTIC_KIND,'RootUID':0,'jobIds':list(DIAGNOSTIC_TARGETS),'issuedUnix':issued,'expiresUnix':issued + 30,
            'producerPin':producerPin,'expectedLedgerPin':expectedLedgerPin,'ledger':ledger,'inputs':inputs,'assets':assets,'currentBootId':boot,'originals':originals,'pool':pool,'hostGuard':host,'decisions':decisions}


def write_diagnostic_receipt(parentPin, name, receipt):
    """Root-only O_EXCL publication; errors retain partials, never adoption."""
    import stat, traceback
    require(os.getuid() == os.geteuid() == 0 and (name,receipt['kind']) in
            {('diagnostic-receipt.json',DIAGNOSTIC_KIND),('rowid-reference.json','ROOT_BOUND_R2_R3_ROWID_REFERENCE'),('diagnostic-worker-closure.json','ROOT_BOUND_R2_R3_WORKER_CLOSURE'),('postflight-attestation.json','ROOT_BOUND_R2_R3_POSTFLIGHT_ATTESTATION'),('at-use-decision.json','ROOT_BOUND_R2_R3_AT_USE_DECISION')}, 'exact separately admitted Root receipt/reference writer')
    fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    identity = lambda st: {k:getattr(st,k) for k in fields}
    path = Path(parentPin['path']); require(path.is_absolute() and path.resolve(strict=True) == path and not any(p.is_symlink() for p in [path,*path.parents]), 'receipt parent no aliases')
    directory = fd = None; first = None; secondary = []; result = None
    try:
        directory = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        st = os.fstat(directory); require(identity(st) == parentPin['identity'] == identity(os.lstat(path)) and st.st_uid == st.st_gid == 0 and stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o755, 'exact Root-owned non-user-writable parent custody')
        raw = (canonical(receipt)+'\n').encode(); require(len(raw) <= 8*1024**2,'complete receipt cap')
        fd = os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400,dir_fd=directory)
        view = memoryview(raw)
        while view:
            n = os.write(fd,view); require(n > 0,'receipt short-write refusal'); view = view[n:]
        os.fchmod(fd,0o444);os.fsync(fd);os.fsync(directory)
        leaf = os.fstat(fd);require(leaf.st_uid == leaf.st_gid == 0 and leaf.st_nlink == 1 and stat.S_IMODE(leaf.st_mode) == 0o444 and os.pread(fd,len(raw)+1,0) == raw,'complete immutable receipt readback')
        require(identity(leaf) == identity(os.stat(name,dir_fd=directory,follow_symlinks=False)) and identity(os.fstat(directory)) == identity(os.lstat(path)) and
                all(getattr(st,k) == getattr(os.fstat(directory),k) for k in fields[:6]),'full held/named leaf and stable parent identity/owner/type')
        result = {'path':str(path/name),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':identity(leaf)}
    except BaseException as error:
        first = {'type':type(error).__name__,'reason':str(error),'traceback':traceback.format_exc()}
    finally:
        for label, descriptor in (('receipt',fd),('parent',directory)):
            if descriptor is not None:
                try:os.close(descriptor)
                except BaseException as error:secondary.append({'scope':label,'type':type(error).__name__,'reason':str(error),'UNKNOWN':True})
    if first is not None or secondary:
        error = RuntimeError('Root receipt publication/closure failed; retained artifact is not accepted')
        error.evidence = {'first':first,'secondary':secondary,'candidatePin':result,'noCleanupOrRetryAuthorized':True};raise error
    return result


def root_diagnostic_protected_recheck(receipt):
    """Only Root reopens protected originals; never the UID1000 worker."""
    require(os.getuid() == os.geteuid() == 0, 'protected diagnostic verification requires actual Root')
    bindings = dict(receipt['ledger']['bindings']); identities = set(); decisions = {}
    for job in DIAGNOSTIC_TARGETS:
        row = next(r for r in receipt['ledger']['rows'] if r['id'] == job)
        check_inputs(json.loads(row['spec']))
        for pin in receipt['assets'][job]: diagnostic_asset(pin,False)
        decision, origins = diagnostic_bundle(row,json.loads(bindings[job]),receipt['inputs'][job],
                    diagnostic_inputs(receipt['inputs'][job]),receipt['assets'][job],receipt['pool'],receipt['currentBootId'])
        require(decision == receipt['decisions'][job], 'Root protected recheck must reproduce the complete original decision')
        decisions[job] = decision; identities.update(map(tuple,origins))
    require(identities == {(x['pid'],x['start']) for x in receipt['originals']}, 'same full original Root/logger/native identity set')
    return decisions, diagnostic_originals(identities)


def root_diagnostic_at_use(capsule, backend, receiptPin):
    """Existing Root pre-worker stage; closes genuine private snapshot FIRST.

    No privileged worker bridge, service, original SQL, chmod or input copying.
    The existing pinned Root wrapper supplies the reviewed PrivateSnapshot.
    Publication/activation/ordinary queue.sh startup must fit this same-host
    one-second decision. Any elapsed boundary refuses; there is no retry.
    """
    require(os.getuid() == os.geteuid() == 0, 'actual Root at-use producer required')
    receipt = collected_read(receiptPin,0,0o444)
    require(receipt['kind'] == DIAGNOSTIC_KIND and receipt['RootUID'] == 0 and receipt['jobIds'] == list(DIAGNOSTIC_TARGETS), 'exact protected original receipt')
    require(receipt['producerPin'] == file_pin(Path(__file__)) and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == receipt['currentBootId'], 'same current source/boot')
    before = diagnostic_ledger(capsule.c)
    require(before == receipt['ledger'] == read_diagnostic_rowid_reference(receipt['expectedLedgerPin'],receipt['producerPin'],receipt['currentBootId']), 'fresh genuine private full thirty/twenty-six snapshot')
    rows = pool_rows(capsule.c,capsule.c.execute('SELECT * FROM jobs ORDER BY rowid').fetchall())
    decisions, originals = root_diagnostic_protected_recheck(receipt)
    snapshot = capsule.finish()
    require(snapshot['actorUID'] == 0 and snapshot['complete'] is True and snapshot['firstError'] is None and snapshot['secondaryErrors'] == [] and
            snapshot['originalOpenedBySQLite'] is False and snapshot['SQLPathScope'] == 'PRIVATE_CAPSULE_ONLY' and snapshot['originalSHMNeverUsedForCoordination'] is True and
            snapshot['originalBefore'] == snapshot['originalAfter'] and snapshot['cleanup']['complete'] is True and snapshot['cleanup']['remaining'] == [] and
            snapshot['FDSetRestored'] is True and snapshot['initialFDs'] == snapshot['finalFDs'] and snapshot['threads'] == 1 and snapshot['children'] == '',
            'complete Root private snapshot/DB/descriptor/owned transient closure before sealed decision')
    host = diagnostic_host_guard(receipt['assets'])
    observed = time.monotonic(); pool = backend.validate_pool(rows)
    diagnostic_pool(pool,[t['unit'] for t in DIAGNOSTIC_TARGETS.values()])
    units = {job:exact_unit_observation(backend,t['unit']) for job,t in DIAGNOSTIC_TARGETS.items()}
    require(all(p['LoadState'] == 'not-found' and p['MainPID'] == '0' and p['InvocationID'] == p['ControlGroup'] == '' for p in units.values()), 'original units remain collected')
    require(receipt['producerPin'] == file_pin(Path(__file__)) and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == receipt['currentBootId'], 'at-use source/boot unchanged')
    recent_boundary(pool,observed); completed = time.monotonic(); issued = time.time()
    require(0 <= completed - observed <= 1 and 0 <= completed - pool['completedMonotonic'] <= 1 and issued < receipt['expiresUnix'], 'one-second Root observation and original thirty-second receipt; no extension')
    statText = Path('/proc/self/stat').read_text()
    return {'kind':'ROOT_BOUND_R2_R3_AT_USE_DECISION','RootUID':0,'observer':{'pid':os.getpid(),'start':int(statText[statText.rfind(')')+2:].split()[19])},
            'receiptPin':receiptPin,'producerPin':receipt['producerPin'],'currentBootId':receipt['currentBootId'],'targets':DIAGNOSTIC_TARGETS,
            'ledgerSHA256':hashlib.sha256(canonical(before).encode()).hexdigest(),'expectedLedgerPin':receipt['expectedLedgerPin'],
            'protectedInputPins':receipt['inputs'],'assets':receipt['assets'],'decisions':decisions,'originals':originals,
            'privateSnapshot':snapshot,'hostGuard':host,'pool':pool,'units':units,'observedMonotonic':observed,'completedMonotonic':completed,
            'issuedUnix':issued,'expiresUnix':issued+1,'oneSecondBoundary':True,'workerPrivilegeElevation':False}


def diagnostic_at_use_decision(pin, receipt, receiptPin, before, historical=False):
    # Only the public Root-owned exact sealed decision is read by UID1000.
    d = collected_read(pin,0,0o444)
    return verify_diagnostic_at_use_data(d,receipt,receiptPin,before,historical)


def verify_diagnostic_at_use_data(d, receipt, receiptPin, before, historical=False):
    require(set(d) == {'kind','RootUID','observer','receiptPin','producerPin','currentBootId','targets','ledgerSHA256','expectedLedgerPin','protectedInputPins','assets','decisions','originals','privateSnapshot','hostGuard','pool','units','observedMonotonic','completedMonotonic','issuedUnix','expiresUnix','oneSecondBoundary','workerPrivilegeElevation'}, 'closed complete at-use Root decision schema')
    require(d['kind'] == 'ROOT_BOUND_R2_R3_AT_USE_DECISION' and type(d['RootUID']) is int and d['RootUID'] == 0 and
            type(d['observer']['pid']) is int and d['observer']['pid'] > 0 and type(d['observer']['start']) is int and d['observer']['start'] > 0 and
            d['receiptPin'] == receiptPin and d['producerPin'] == receipt['producerPin'] and d['currentBootId'] == receipt['currentBootId'] and
            d['targets'] == DIAGNOSTIC_TARGETS and d['expectedLedgerPin'] == receipt['expectedLedgerPin'] and
            d['ledgerSHA256'] == hashlib.sha256(canonical(before).encode()).hexdigest() and d['protectedInputPins'] == receipt['inputs'] and d['assets'] == receipt['assets'] and
            d['decisions'] == receipt['decisions'], 'exact protected Root decision/source/boot/current ledger/original pins and failed-unproven semantics')
    require({(x['pid'],x['start']) for x in d['originals']} == {(x['pid'],x['start']) for x in receipt['originals']} and
            all(x['originalAbsent'] is True and x['errno'] in (2,3) for x in d['originals']), 'Root original identity observations complete')
    s = d['privateSnapshot']; h = d['hostGuard']
    require(s['actorUID'] == 0 and s['complete'] is True and s['firstError'] is None and s['secondaryErrors'] == [] and
            s['originalOpenedBySQLite'] is False and s['SQLPathScope'] == 'PRIVATE_CAPSULE_ONLY' and s['originalSHMNeverUsedForCoordination'] is True and
            s['originalBefore'] == s['originalAfter'] and s['cleanup']['complete'] is True and s['cleanup']['remaining'] == [] and
            s['FDSetRestored'] is True and s['initialFDs'] == s['finalFDs'] and s['threads'] == 1 and s['children'] == '' and
            h['RootUID'] == 0 and h['completeUID0Traversal'] is True and h['hits'] == h['errors'] == [] and h['stopOrSignalPerformed'] is False,
            'complete Root private SQL/host/FD/child closure, never free-standing booleans')
    diagnostic_pool(d['pool'],[t['unit'] for t in DIAGNOSTIC_TARGETS.values()])
    require(set(d['units']) == set(DIAGNOSTIC_TARGETS) and all(p['LoadState'] == 'not-found' and p['MainPID'] == '0' and p['InvocationID'] == p['ControlGroup'] == '' for p in d['units'].values()), 'Root exact collected unit set')
    require(d['oneSecondBoundary'] is True and d['workerPrivilegeElevation'] is False and type(d['issuedUnix']) in (int,float) and
            d['expiresUnix'] == d['issuedUnix']+1 and 0 <= d['completedMonotonic']-d['observedMonotonic'] <= 1 and
            0 <= d['completedMonotonic']-d['pool']['completedMonotonic'] <= 1, 'unchanged one-second same-host boundary and no elevation')
    if not historical:
        require(file_pin(Path(__file__)) == d['producerPin'] and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == d['currentBootId'] and
                d['issuedUnix'] <= time.time() < d['expiresUnix'] and 0 <= time.monotonic()-d['completedMonotonic'] <= 1, 'at-use Root decision expired/source drift; reservation retained')
        recent_boundary(d['pool'],d['observedMonotonic'])
    return d


def finish_diagnostic(db, backend, receiptPin, authorityPin):
    # Exact Root-owned readable metadata; normal UID1000 worker never impersonates
    # Root or chowns the queue. Legacy qualification/probe mode0400 unchanged.
    receipt = collected_read(receiptPin, 0, 0o444); authority = collected_read(authorityPin, 0, 0o444)
    require(receipt['kind'] == DIAGNOSTIC_KIND and receipt['RootUID'] == 0 and receipt['jobIds'] == list(DIAGNOSTIC_TARGETS), 'dedicated historical diagnostic kind only')
    require(authority['kind'] == DIAGNOSTIC_APPROVAL and authority['runtimeAuthorized'] is True and authority['jobIds'] == receipt['jobIds'] and
            authority['receiptPin'] == receiptPin and authority['producerPin'] == receipt['producerPin'] and authority['queueSourcePin'] == file_pin(__file__) and
            authority['ledgerSHA256'] == hashlib.sha256(canonical(receipt['ledger']).encode()).hexdigest(), 'separate exact two-row Root activation/source/current full ledger')
    require(receipt['issuedUnix'] <= time.time() < receipt['expiresUnix'] <= receipt['issuedUnix'] + 30, 'fresh finite diagnostic receipt')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == receipt['currentBootId'], 'current exact same boot')
    host = receipt['hostGuard']
    require(host['RootUID'] == 0 and host['completeUID0Traversal'] is True and host['hits'] == host['errors'] == [] and host['stopOrSignalPerformed'] is False and
            0 <= time.monotonic() - host['completedMonotonic'] < 30, 'fresh complete protected Root host/holder inspection')
    before = diagnostic_ledger(db); require(before == read_diagnostic_rowid_reference(receipt['expectedLedgerPin'],receipt['producerPin'],receipt['currentBootId']), 'protected actual rowid-order full reference remains exact')
    require(before == receipt['ledger'], 'all thirty rows/twenty-six bindings/config exact')
    require(len(before['rows']) == 30 and len(before['bindings']) == 26 and [r['id'] for r in before['rows'] if r['state'] not in TERMINAL] == receipt['jobIds'], 'no other pending/running work')
    decisionPin = authority['atUseDecisionPin']
    sealed = diagnostic_at_use_decision(decisionPin,receipt,receiptPin,before)
    identities = {(x['pid'],x['start']) for x in sealed['originals']}
    decisions = sealed['decisions']
    for job in receipt['jobIds']:
        row = next(r for r in before['rows'] if r['id'] == job)
        # Ordinary readable public job-source pins remain real worker reads.
        # Root-only asset/metadata verification is never impersonated here.
        check_inputs(json.loads(row['spec']))
    diagnostic_originals(identities)
    with immutable_ledger_transaction(db):
        require(diagnostic_ledger(db) == before, 'immutable whole ledger before current proof')
        rows, pool = boundary_pool_epoch(db, backend); units = [t['unit'] for t in DIAGNOSTIC_TARGETS.values()]
        diagnostic_pool(pool, units)
        for unit in units:
            props = exact_unit_observation(backend, unit)
            require(props['LoadState'] == 'not-found' and props['MainPID'] == '0' and props['InvocationID'] == props['ControlGroup'] == '', 'both original managers still collected')
        diagnostic_originals(identities)
        require(diagnostic_ledger(db) == before and time.time() < receipt['expiresUnix'], 'final ledger and finite original authority')
        diagnostic_at_use_decision(decisionPin,receipt,receiptPin,before)
        recent_boundary(pool, time.monotonic()); finished = time.time()
        for job in receipt['jobIds']:
            old = next(r for r in before['rows'] if r['id'] == job)
            result = {'diagnosticRootReceiptPin':receiptPin,'atUseDecisionPin':decisionPin,'decision':decisions[job], 'originalReservationRetainedResult':old['result'],
                      'finalLedgerInvocation':DIAGNOSTIC_TARGETS[job]['invocation'],'reservationRetained':False,'guestBaselineAccepted':False,'packageAcceptance':False}
            db.execute("UPDATE jobs SET state='failed',finished=?,result=? WHERE id=? AND state='running' AND unit=? AND spec=? AND result=?", (finished,canonical(result),job,old['unit'],old['spec'],old['result']))
            require(db.execute('SELECT changes()').fetchone()[0] == 1, 'exact authorized diagnostic transition')
        after = diagnostic_ledger(db)
        require(after['bindings'] == before['bindings'] and after['config'] == before['config'] and len(after['rows']) == len(before['rows']), 'all bindings/config/history count retained')
        for old, new in zip(before['rows'], after['rows']):
            if old['id'] not in receipt['jobIds']: require(new == old, 'every other historical row unchanged')
            else: require({k:v for k,v in old.items() if k not in ('state','finished','result')} == {k:v for k,v in new.items() if k not in ('state','finished','result')} and new['state'] == 'failed' and new['finished'] == finished, 'only exact terminal fields changed')
        _, post = boundary_pool_epoch(db, backend)
        diagnostic_pool(post, [])
        diagnostic_originals(identities); diagnostic_at_use_decision(decisionPin,receipt,receiptPin,before)
        recent_boundary(post, time.monotonic())
    # Mapping removal occurs after the single durable two-row transaction; the
    # ordinary worker computes aggregate1, not package-success aggregate0.
    for job in receipt['jobIds']: DIAGNOSTIC_TERMINAL_INPUTS.pop(job, None)
    return decisions


def diagnostic_closed_record(record, numeric):
    actor = record['actor']
    require(type(actor['pid']) is int and actor['pid'] > 0 and type(actor['start']) is int and actor['start'] > 0,
            'positive bound closed actor, never inferred from absence')
    require(type(record['numeric']) is int and record['numeric'] == numeric and
            all(record[k] is True for k in ('waitReturned','reaped','originalAbsent','stdoutEOF','stderrEOF','pipesClosed','FDSetRestored')) and
            record['children'] == '' and record['threads'] == 1 and record['first'] is None and record['secondary'] == [],
            'complete actual numeric/EOF/reap/FD/child closure')


def diagnostic_terminal_ledger(before, after, receipt, receiptPin, decisionPin):
    require(receipt['kind'] == DIAGNOSTIC_KIND and receipt['ledger'] == before and receipt['jobIds'] == list(DIAGNOSTIC_TARGETS), 'same exact diagnostic producer/current ledger')
    require(len(before['rows']) == len(after['rows']) == 30 and len(before['bindings']) == 26 and before['bindings'] == after['bindings'] and before['config'] == after['config'], 'full final thirty/twenty-six/config exact')
    for old, new in zip(before['rows'],after['rows']):
        if old['id'] not in DIAGNOSTIC_TARGETS: require(new == old, 'all other twenty-eight rows byte equal')
        else:
            require({k:v for k,v in old.items() if k not in ('state','finished','result')} == {k:v for k,v in new.items() if k not in ('state','finished','result')} and
                    new['state'] == 'failed' and receipt['issuedUnix'] <= new['finished'] < receipt['expiresUnix'], 'exact two diagnostic failed transitions')
            expected = {'diagnosticRootReceiptPin':receiptPin,'atUseDecisionPin':decisionPin,'decision':receipt['decisions'][old['id']], 'originalReservationRetainedResult':old['result'],
                        'finalLedgerInvocation':DIAGNOSTIC_TARGETS[old['id']]['invocation'],'reservationRetained':False,'guestBaselineAccepted':False,'packageAcceptance':False}
            require(json.loads(new['result']) == expected, 'complete exact original failure and diagnostic result, not qualification projection')


def root_diagnostic_postflight(db, backend, receiptPin, workerProofPin):
    """OMEN-only fresh observation, after the canonical worker is closed.

    The caller must use its genuine protected private-copy DB, not original SQL.
    Publication does not claim this Root process or its SSH has already exited.
    """
    require(os.getuid() == os.geteuid() == 0, 'actual Root postflight required')
    receipt = collected_read(receiptPin,0,0o444)
    worker = collected_read(workerProofPin,0,0o444)
    source = file_pin(Path(__file__))
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(set(worker) == {'kind','receiptPin','producerPin','currentBootId','record','completedUnix','authorityPin'} and
            worker['kind'] == 'ROOT_BOUND_R2_R3_WORKER_CLOSURE' and worker['receiptPin'] == receiptPin and
            worker['producerPin'] == receipt['producerPin'] == source and worker['currentBootId'] == receipt['currentBootId'] == boot,
            'protected exact same-source/boot/receipt worker proof')
    authority = collected_read(worker['authorityPin'],0,0o444)
    require(authority['kind'] == DIAGNOSTIC_APPROVAL and authority['runtimeAuthorized'] is True and authority['receiptPin'] == receiptPin and authority['producerPin'] == source and authority['queueSourcePin'] == source, 'original separately activated source/receipt authority')
    decisionPin = authority['atUseDecisionPin']
    sealed = diagnostic_at_use_decision(decisionPin,receipt,receiptPin,receipt['ledger'],historical=True)
    root_diagnostic_protected_recheck(receipt)
    diagnostic_closed_record(worker['record'],1)
    require(type(worker['completedUnix']) in (int,float) and receipt['issuedUnix'] <= worker['completedUnix'], 'same-host worker completion chronology')
    for stream in ('stdout','stderr'):
        collected_read(worker['record'][stream],0,0o444,False)
    for pins in receipt['assets'].values():
        for pin in pins: diagnostic_asset(pin,False)
    host = diagnostic_host_guard(receipt['assets'])
    observed = time.monotonic()
    after = diagnostic_ledger(db)
    diagnostic_terminal_ledger(receipt['ledger'],after,receipt,receiptPin,decisionPin)
    require(all(sealed['issuedUnix'] <= r['finished'] < sealed['expiresUnix'] for r in after['rows'] if r['id'] in DIAGNOSTIC_TARGETS), 'both commits inside sealed Root one-second boundary')
    _, pool = boundary_pool_epoch(db,backend)
    diagnostic_pool(pool,[])
    units = {job:_RAW_SYSTEMCTL('show',t['unit'],manager=backend.cfg['manager']) for job,t in DIAGNOSTIC_TARGETS.items()}
    for p in units.values():
        require(p['LoadState'] == 'not-found' and p['MainPID'] == '0' and p['InvocationID'] == p['ControlGroup'] == '', 'collected original units, never foreign/current manager')
    require(file_pin(Path(__file__)) == source and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot and diagnostic_ledger(db) == after,
            'same-host final source/boot/full ledger unchanged')
    originals = diagnostic_originals([(x['pid'],x['start']) for x in receipt['originals']])
    workerOriginal = diagnostic_originals([(worker['record']['actor']['pid'],worker['record']['actor']['start'])])
    recent_boundary(pool,observed)
    completed = time.monotonic(); issued = time.time()
    require(0 <= completed - pool['completedMonotonic'] <= 1 and 0 <= completed - observed <= 1 and worker['completedUnix'] <= issued,
            'same-host one-second postflight observation/worker boundary')
    rawstat = Path('/proc/self/stat').read_text(); start = int(rawstat[rawstat.rfind(')')+2:].split()[19])
    return {'kind':'ROOT_BOUND_R2_R3_POSTFLIGHT_ATTESTATION','RootUID':0,'observer':{'pid':os.getpid(),'start':start},
            'sourcePin':source,'currentBootId':boot,'receiptPin':receiptPin,'workerProofPin':workerProofPin,'atUseDecisionPin':decisionPin,'atUseDecisionSHA256':decisionPin['sha256'],
            'workerProofSHA256':hashlib.sha256((canonical(worker)+'\n').encode()).hexdigest(),'workerActor':worker['record']['actor'],
            'workerRawPins':{s:worker['record'][s] for s in ('stdout','stderr')},'targets':DIAGNOSTIC_TARGETS,
            'beforeLedgerSHA256':hashlib.sha256(canonical(receipt['ledger']).encode()).hexdigest(),
            'afterLedgerSHA256':hashlib.sha256(canonical(after).encode()).hexdigest(),
            'pool':pool,'units':units,'hostGuard':host,'originals':originals,'workerOriginal':workerOriginal,
            'freshness':{'domain':'OMEN_MONOTONIC_ONLY','observedMonotonic':observed,'completedMonotonic':completed,'maximumAgeSeconds':1,'checked':True},
            'issuedUnix':issued,'historicalObservationOnly':True,'effectOrRetryAuthorized':False}


def diagnostic_postflight_frame(attestationPin, document):
    """Emit on the authenticated Root stdout only after the writer closes."""
    require(os.getuid() == os.geteuid() == 0 and collected_read(attestationPin,0,0o444) == document,
            'exact protected durable postflight reopened after writer close')
    return {'ROOT_DIAGNOSTIC_POSTFLIGHT':{'kind':'CLOSED_ROOT_POSTFLIGHT_CAPTURE','RootUID':0,'actor':document['observer'],
            'sourcePin':document['sourcePin'],'currentBootId':document['currentBootId'],'receiptPin':document['receiptPin'],
            'attestationPin':attestationPin,'documentSHA256':attestationPin['sha256']}}


def verify_diagnostic_post(before, after, receipt, receiptPin, attestation, closure):
    # Historical external consumer: remote clocks are never compared to local.
    # This runs only after the Root process, all three SSH and parent close.
    require(set(closure) == {'RootProducer','RootWorkerSupervisor','worker','RootPostflight','SSH','externalParent'}, 'complete finite outer closure roles')
    require(type(closure['SSH']) is list and [x['phase'] for x in closure['SSH']] == ['producer','worker','postflight'], 'all three actual SSH transports')
    records = [(r,closure[r]) for r in ('RootProducer','RootWorkerSupervisor','worker','RootPostflight','externalParent')] + [('SSH-'+x['phase'],x['record']) for x in closure['SSH']]
    actors = set(); raw = {}
    for role, record in records:
        diagnostic_closed_record(record,1 if role == 'worker' else 0)
        pair = (record['actor']['pid'],record['actor']['start'])
        require(pair not in actors,'distinct actual positive parent/Root/SSH PID-start'); actors.add(pair)
        raw[role] = {}
        for stream in ('stdout','stderr'):
            p = record[stream]
            require(type(p['bytes']) is int and 0 <= p['bytes'] <= MAX_LOG and type(p['path']) is str and Path(p['path']).is_absolute() and
                    type(p['sha256']) is str and re.fullmatch('[0-9a-f]{64}',p['sha256']) is not None,'whole durable raw parent stream pin')
            raw[role][stream] = collected_read(p,1000,0o600,False)
    require(set(attestation) == {'localPin','remotePin','workerProofLocalPin','decisionLocalPin'}, 'exact transported protected attestation contract')
    remote = attestation['remotePin']; ident = remote['identity']
    require(Path(remote['path']).is_absolute() and Path(remote['path']).name == 'postflight-attestation.json', 'exact protected postflight name/path')
    import stat
    require(set(ident) == {'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'} and
            all(type(v) is int for v in ident.values()) and ident['st_uid'] == ident['st_gid'] == 0 and ident['st_nlink'] == 1 and
            stat.S_ISREG(ident['st_mode']) and stat.S_IMODE(ident['st_mode']) == 0o444 and ident['st_size'] == remote['bytes'], 'protected Root full9 regular immutable attestation')
    docraw = collected_read(attestation['localPin'],1000,0o600,False)
    require(remote['bytes'] == len(docraw) and remote['sha256'] == hashlib.sha256(docraw).hexdigest(), 'transported exact whole Root attestation bytes/SHA')
    doc = json.loads(docraw)
    require(set(doc) == {'kind','RootUID','observer','sourcePin','currentBootId','receiptPin','workerProofPin','workerProofSHA256','workerActor','workerRawPins','targets','beforeLedgerSHA256','afterLedgerSHA256','pool','units','hostGuard','originals','workerOriginal','freshness','issuedUnix','historicalObservationOnly','effectOrRetryAuthorized','atUseDecisionPin','atUseDecisionSHA256'}, 'closed complete Root postflight schema')
    require(docraw == (canonical(doc)+'\n').encode(), 'canonical complete attestation, no tail/reordering ambiguity')
    transported = {}
    for phase, rootRole in [('producer','RootProducer'),('worker','RootWorkerSupervisor'),('postflight','RootPostflight')]:
        require(raw[rootRole]['stdout'] == raw['SSH-'+phase]['stdout'] and raw[rootRole]['stderr'] == raw['SSH-'+phase]['stderr'] == b'', 'exact Root/SSH phase bytes/no extra stdout/stderr')
        d, payload = diagnostic_transport_decode(raw[rootRole]['stdout'],phase)
        require(d['actor'] == closure[rootRole]['actor'] and d['sourcePin'] == receipt['producerPin'] and d['currentBootId'] == receipt['currentBootId'] and d['receiptPin'] == receiptPin, 'same authenticated Root actor/source/boot/receipt across complete three streams')
        transported[phase] = (d,payload)
    require(transported['producer'][0]['roles']['receipt']['pin'] == receiptPin and transported['producer'][1]['receipt'] == (canonical(receipt)+'\n').encode() and before == receipt['ledger'], 'whole producer receipt and before ledger originate only in first closed stream')
    require(transported['postflight'][0]['roles']['attestation']['pin'] == remote and transported['postflight'][1]['attestation'] == docraw and
            transported['postflight'][1]['after'] == (canonical(after)+'\n').encode() and closure['RootPostflight']['actor'] == doc['observer'], 'whole after ledger and attestation originate only in final closed stream')
    decisionraw = collected_read(attestation['decisionLocalPin'],1000,0o600,False)
    require(len(decisionraw) == doc['atUseDecisionPin']['bytes'] and hashlib.sha256(decisionraw).hexdigest() == doc['atUseDecisionSHA256'] == doc['atUseDecisionPin']['sha256'], 'whole transported Root at-use decision bound to postflight')
    decision = json.loads(decisionraw)
    require(decisionraw == (canonical(decision)+'\n').encode(), 'complete canonical Root decision')
    verify_diagnostic_at_use_data(decision,receipt,receiptPin,before,historical=True)
    diagnostic_terminal_ledger(before,after,receipt,receiptPin,doc['atUseDecisionPin'])
    require(all(decision['issuedUnix'] <= r['finished'] < decision['expiresUnix'] for r in after['rows'] if r['id'] in DIAGNOSTIC_TARGETS), 'both exact commits inside one-second Root decision')
    workerraw = collected_read(attestation['workerProofLocalPin'],1000,0o600,False); worker = json.loads(workerraw)
    require(workerraw == (canonical(worker)+'\n').encode() and hashlib.sha256(workerraw).hexdigest() == doc['workerProofSHA256'] == doc['workerProofPin']['sha256'] and
            len(workerraw) == doc['workerProofPin']['bytes'] and worker['record']['actor'] == closure['worker']['actor'] == doc['workerActor'] and
            worker['kind'] == 'ROOT_BOUND_R2_R3_WORKER_CLOSURE' and worker['receiptPin'] == receiptPin and worker['producerPin'] == receipt['producerPin'] and
            worker['currentBootId'] == receipt['currentBootId'], 'complete original protected worker closure binding')
    require(transported['worker'][0]['roles']['workerProof']['pin'] == doc['workerProofPin'] and transported['worker'][1]['workerProof'] == workerraw and
            transported['worker'][0]['roles']['decision']['pin'] == doc['atUseDecisionPin'] and transported['worker'][1]['decision'] == decisionraw, 'whole worker proof/decision bytes originate only in second closed stream')
    for stream in ('stdout','stderr'):
        require(transported['worker'][0]['roles'][stream]['pin'] == worker['record'][stream] and transported['worker'][1][stream] == raw['worker'][stream], 'actual whole worker raw bound to second closed stream')
    diagnostic_closed_record(worker['record'],1)
    for stream in ('stdout','stderr'):
        p = worker['record'][stream]
        require(p['bytes'] == len(raw['worker'][stream]) and p['sha256'] == hashlib.sha256(raw['worker'][stream]).hexdigest(), 'Root protected worker raw equals actual closed external capture')
    require(doc['kind'] == 'ROOT_BOUND_R2_R3_POSTFLIGHT_ATTESTATION' and doc['RootUID'] == 0 and
            doc['sourcePin'] == receipt['producerPin'] and doc['currentBootId'] == receipt['currentBootId'] and doc['receiptPin'] == receiptPin and
            doc['targets'] == DIAGNOSTIC_TARGETS and doc['beforeLedgerSHA256'] == hashlib.sha256(canonical(before).encode()).hexdigest() and
            doc['afterLedgerSHA256'] == hashlib.sha256(canonical(after).encode()).hexdigest() and
            doc['historicalObservationOnly'] is True and doc['effectOrRetryAuthorized'] is False, 'exact source/boot/receipt/targets/full ledger historical binding')
    require(doc['workerRawPins'] == {s:worker['record'][s] for s in ('stdout','stderr')}, 'protected worker raw pins unchanged')
    diagnostic_pool(doc['pool'],[])
    require(set(doc['units']) == set(DIAGNOSTIC_TARGETS) and all(p['LoadState'] == 'not-found' and p['MainPID'] == '0' and p['InvocationID'] == p['ControlGroup'] == '' for p in doc['units'].values()), 'exact collected units, no foreign invocation')
    f = doc['freshness']
    require(set(f) == {'domain','observedMonotonic','completedMonotonic','maximumAgeSeconds','checked'} and f['domain'] == 'OMEN_MONOTONIC_ONLY' and
            f['checked'] is True and type(f['maximumAgeSeconds']) is int and f['maximumAgeSeconds'] == 1 and
            type(f['observedMonotonic']) in (int,float) and type(f['completedMonotonic']) in (int,float) and
            0 <= f['completedMonotonic'] - f['observedMonotonic'] <= 1 and 0 <= f['completedMonotonic'] - doc['pool']['completedMonotonic'] <= 1,
            'historical same-host checked one-second boundary, no external clock freshness')
    require(doc['hostGuard']['RootUID'] == 0 and doc['hostGuard']['completeUID0Traversal'] is True and doc['hostGuard']['hits'] == doc['hostGuard']['errors'] == [] and
            doc['hostGuard']['stopOrSignalPerformed'] is False and
            {(x['pid'],x['start']) for x in doc['originals']} == {(x['pid'],x['start']) for x in receipt['originals']} and
            all(set(x) == {'pid','start','originalAbsent','errno'} and x['originalAbsent'] is True and x['errno'] in (2,3) for x in doc['originals']) and
            doc['workerOriginal'] == [{'pid':worker['record']['actor']['pid'],'start':worker['record']['actor']['start'],'originalAbsent':True,'errno':doc['workerOriginal'][0]['errno']}] and
            doc['workerOriginal'][0]['errno'] in (2,3) and worker['completedUnix'] <= doc['issuedUnix'], 'complete Root observation/original and worker closure provenance')
    return {'kind':'EXACT_R2_R3_DIAGNOSTIC_TERMINAL_POSTFLIGHT','accepted':True,'terminalJobIds':list(DIAGNOSTIC_TARGETS),
            'state':'failed','other28RowsUnchanged':True,'all26BindingsAndConfigUnchanged':True,'guestBaselineAccepted':False,'packageAcceptance':False,
            'noNewVMOrCompilerAdmission':True,'receiptPin':receiptPin,'closure':closure,'attestation':attestation,'pool':doc['pool'],
            'historicalSameHostFreshnessAuthenticated':True,'externalClockSubtractionPerformed':False}


def return_readiness_wait(root, db, backend, planned, output, reason):
    """Only a proved never-launched own nonce may return to pending; no lease override."""
    import stat
    with immutable_ledger_transaction(db):
        planned_ledger_current(db, planned)
        actual, proof = boundary_pool_epoch(db, backend)
        require(proof['unitProperties'][planned['unit']]['properties']['LoadState'] == 'not-found',
                'Readiness wait cannot release an existing/unknown unit')
        group = backend.whole_owned_cgroup(planned['unit'], {'ControlGroup':''})
        require(group['empty'] is True, 'Readiness wait requires never-created unit and empty group')
        parent = output.parent
        dfd = os.open(parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        fd = None
        try:
            fd = os.open(output.name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dfd)
            first = os.fstat(fd)
            require(stat.S_ISDIR(first.st_mode) and first.st_uid == first.st_gid == os.getuid() and
                    stat.S_IMODE(first.st_mode) == 0o700 and not os.listdir(fd) and
                    all(getattr(os.stat(output.name,dir_fd=dfd,follow_symlinks=False),k)==getattr(first,k)
                        for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')),
                    'Only exact empty never-launched output directory may retire')
            os.rmdir(output.name, dir_fd=dfd)
            os.fsync(dfd)
        finally:
            try:
                if fd is not None: os.close(fd)
            finally: os.close(dfd)
        planned_ledger_current(db, planned)
        observed = time.monotonic()
        require(exact_unit_observation(backend,planned['unit'])['LoadState']=='not-found',
                'Final same own nonce still uncreated before pending transition')
        recent_boundary(proof,observed)
        changed=db.execute("UPDATE jobs SET state='pending',cpus=NULL,unit=NULL,started=NULL,finished=NULL,result=? WHERE id=? AND state='running' AND unit=? AND cpus=? AND spec=?",(canonical(reason),planned['id'],planned['unit'],planned['cpus'],planned['spec'])).rowcount
        require(changed == 1, 'Exact own never-launched pending transition')


# Same live queue worker connection exports committed row/binding; no new SQLite
# connection or original journal coordination by Root/observers. This is DATA,
# never a Root authority, terminal receipt, closure index, or lease release.
LIBVIRT_ASSIGNMENT_KIND='OPEMOS_CURRENT_LIBVIRT_QUEUE_ASSIGNMENT_EXPORT_R1'
LIBVIRT_EXPORT_DIRECTORY='libvirt-assignment-exports'

@contextmanager
def libvirt_export_directory(root,uid,create=False):
    root=Path(root).absolute();opened=[];links=[]
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);opened.append(fd)
    try:
        for part in root.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);opened.append(child)
            ident=history_equal(child,fd,part);links.append((fd,part,child,ident));fd=child
        st=os.fstat(fd);require(st.st_uid==uid and stat.S_IMODE(st.st_mode)==0o700,'Exact queue owner0700 export parent')
        if create:
            require(os.getuid()==os.geteuid()==uid,'Only current queue owner may publish live assignment')
            before=history_identity(os.fstat(fd))
            try:
                os.mkdir(LIBVIRT_EXPORT_DIRECTORY,0o700,dir_fd=fd);os.fsync(fd)
                after=history_identity(os.fstat(fd));require(all(after[k]==before[k]for k in HISTORY_FIELDS[:5])and after['st_nlink']==before['st_nlink']+1,'Only exact export child ext4 transition')
                parent,name,held,_=links[-1];links[-1]=(parent,name,held,after)
            except FileExistsError:pass
        child=os.open(LIBVIRT_EXPORT_DIRECTORY,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);opened.append(child);initial=history_equal(child,fd,LIBVIRT_EXPORT_DIRECTORY)
        require(stat.S_ISDIR(initial['st_mode'])and initial['st_uid']==uid and initial['st_gid']==st.st_gid and stat.S_IMODE(initial['st_mode'])==0o700,'Owned0700 export namespace')
        yield child
        for parent,name,held,prior in links:
            now=history_equal(held,parent,name);require(all(now[k]==prior[k]for k in HISTORY_FIELDS[:6]),'Export ancestor binding/custody changed')
        now=history_equal(child,fd,LIBVIRT_EXPORT_DIRECTORY);require(all(now[k]==initial[k]for k in HISTORY_FIELDS[:6]),'Export namespace replaced')
    finally:
        first=sys.exc_info()[1];errors=[]
        for x in reversed(opened):
            try:os.close(x)
            except BaseException as e:errors.append(repr(e))
        if errors:
            if first is not None:first.add_note('Export descriptor closure UNKNOWN:'+repr(errors))
            else:raise ValueError('Export descriptor closure UNKNOWN:'+repr(errors))

def libvirt_export_inventory(parent,uid):
    names=os.listdir(parent);require(len(names)==len(set(names)),'Unique assignment export namespace')
    allocated=max(os.fstat(parent).st_size,os.fstat(parent).st_blocks*512);require(allocated<=HISTORY_METADATA_MAX*4//5,'Existing assignment metadata20percent headroom')
    for name in names:
        require(name.endswith('.json')and NAME.fullmatch(name[:-5]),'Unknown assignment export retained/refused')
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            i=history_equal(fd,parent,name);require(stat.S_ISREG(i['st_mode'])and i['st_uid']==uid and i['st_nlink']==1 and stat.S_IMODE(i['st_mode'])==0o400 and 0<i['st_size']<=65536,'Immutable assignment header custody/cap');allocated+=max(i['st_size'],os.fstat(fd).st_blocks*512);require(allocated<=HISTORY_METADATA_MAX*4//5,'Existing assignment metadata20percent headroom')
        finally:history_close_owned(fd)
    require(allocated<=HISTORY_METADATA_MAX*4//5,'Existing assignment metadata20percent headroom');return allocated,names

def libvirt_assignment_read_header(parent,name,uid):
    require(name.endswith('.json')and NAME.fullmatch(name[:-5]),'Exact assignment job filename')
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
    try:
        i=history_equal(fd,parent,name);require(stat.S_ISREG(i['st_mode'])and i['st_uid']==uid and i['st_nlink']==1 and stat.S_IMODE(i['st_mode'])==0o400 and 0<i['st_size']<=65536,'Assignment header full custody')
        raw=os.read(fd,65537);require(len(raw)==i['st_size']and not os.read(fd,1)and history_equal(fd,parent,name)==i,'Assignment header EOF/custody')
        value=json.loads(raw);require((canonical(value)+'\n').encode()==raw,'Canonical assignment header bytes')
        return value,{'name':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':i}
    finally:history_close_owned(fd)

def publish_libvirt_assignment(db,row,bound,metrics=None):
    started=time.monotonic();archive_metrics={}
    require(not db.in_transaction,'Assignment follows committed actual queue binding')
    root,uid=history_root(db);require(uid==os.getuid()==os.geteuid(),'Genuine queue writer owner')
    request=libvirt_request(row,bound);require(request is not None,'Only explicitly admitted libvirt job export')
    before_changes=db.total_changes;db.execute('BEGIN')
    try:
        value=diagnostic_ledger(db);archive_rows=pool_rows(db,value['rows']);own=next(r for r in value['rows']if r['id']==row['id']);bindings=dict(value['bindings'])
        require(own=={k:v for k,v in row.items()if k!='_poolBinding'}and own['state']=='running'and own['finished']is None and own['result']is None and bindings[own['id']]==canonical(bound),'Exact committed running row/binding in same SQL snapshot')
        require(libvirt_request(own,json.loads(bindings[own['id']]))==request,'Snapshot exact immutable spec/unit/invocation/CPU derivation')
        require(len({r['id']for r in value['rows']})==len(value['rows'])and len(bindings)==len(value['bindings']),'Complete unique current history')
        raw=(canonical(value)+'\n').encode();require(len(raw)<=HISTORY_FILE_MAX,'Existing complete64MiB history product bound')
        change_count=db.total_changes;require(change_count==before_changes,'Read snapshot cannot mutate queue SQL')
    finally:db.rollback()
    require(not db.in_transaction and db.total_changes==before_changes,'Readonly snapshot closed without SQL changes')
    objects=[(canonical(r)+'\n').encode()for r in archive_rows]
    with history_directory(root,uid,True)as parent,history_archive_view(parent,uid,archive_metrics)as archive_view:
        allocated,count=history_inventory(parent,uid,archive_view);names=set(os.listdir(parent));archive=history_archive_view_check(archive_view,parent,uid);present=names|(set(archive[0]) if archive else set());missing={hashlib.sha256(x).hexdigest()+'.row.json':x for x in objects};extra=sum(((len(x)+4095)//4096)*4096 for n,x in missing.items()if n not in present)
        require(allocated+extra+HISTORY_METADATA_MAX<=HISTORY_NAMESPACE_MAX*4//5 and count+len(set(missing)-present)+1<=HISTORY_ENTRY_MAX,'Assignment shares unchanged history64MiB/20percent/entry guards')
        space=os.fstatvfs(parent);require(space.f_bavail*space.f_frsize>=extra+HISTORY_METADATA_MAX+HISTORY_NAMESPACE_MAX//5 and space.f_favail>=len(missing)+2,'Assignment bytes/inodes admission')
        rows=[history_publish(parent,x,'row',uid,archive_view)for x in objects]
        manifest={'kind':LIBVIRT_ASSIGNMENT_KIND,'request':request,'rows':rows,'bindings':value['bindings'],'config':value['config'],'canonicalBytes':len(raw),'canonicalSHA256':hashlib.sha256(raw).hexdigest()}
        mp=history_publish(parent,(canonical(manifest)+'\n').encode(),'epoch',uid,archive_view)
        require(history_inventory(parent,uid,archive_view)[0]<=HISTORY_NAMESPACE_MAX*4//5,'Assignment actual history allocation')
    parts=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()
    source=file_pin(Path(__file__));source['identity']=history_identity(os.lstat(source['path']))
    header={'kind':LIBVIRT_ASSIGNMENT_KIND,'request':request,'manifest':mp,'rowCount':len(rows),'bindingCount':len(bindings),'configCount':len(value['config']),'canonicalBytes':len(raw),'canonicalSHA256':hashlib.sha256(raw).hexdigest(),'producer':{'pid':os.getpid(),'start':int(parts[19]),'uid':uid},'source':source,'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'issuedUnix':time.time(),'issuedMonotonic':time.monotonic(),'sameExistingWorkerConnection':True,'snapshotReadTransactionClosed':True,'SQLChanges':0,'rootAuthority':False,'queueOrGpuLeaseReleased':False}
    encoded=(canonical(header)+'\n').encode();require(len(encoded)<=65536,'Bounded assignment header')
    with libvirt_export_directory(root,uid,True)as parent:
        allocated,names=libvirt_export_inventory(parent,uid);name=own['id']+'.json';require(name not in names,'Create-only assignment; no retry/adoption')
        require(allocated+((len(encoded)+4095)//4096)*4096<=HISTORY_METADATA_MAX*4//5,'Assignment metadata unchanged1MiB20percent cap')
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try:
            view=memoryview(encoded)
            while view:n=os.write(fd,view);require(n>0,'Assignment header write progress');view=view[n:]
            os.fsync(fd);os.fchmod(fd,0o400);os.fsync(fd);history_equal(fd,parent,name)
        finally:history_close_owned(fd)
        os.fsync(parent);r,pin=libvirt_assignment_read_header(parent,name,uid);require(r==header,'Assignment exact persisted readback');libvirt_export_inventory(parent,uid)
    if metrics is not None:metrics.update(archive_metrics,elapsedSeconds=time.monotonic()-started,rows=len(rows),bindings=len(bindings),canonicalBytes=len(raw))
    return {'path':str(root/LIBVIRT_EXPORT_DIRECTORY/name),**{k:v for k,v in pin.items()if k!='name'}}

def read_libvirt_assignment_export(root,job,expectedWorker,expectedSource,expectedBoot,maximumAge=30,metrics=None):
    started=time.monotonic();archive_metrics={}
    # Root caller must independently authenticate expectedWorker/source/current
    # manager/owner/locks. UID1000 data alone never authorizes Root effects.
    require(NAME.fullmatch(job)and type(maximumAge)in(int,float)and 0<maximumAge<=30,'Exact finite current assignment intake')
    root=Path(root);uid=os.lstat(root).st_uid
    with libvirt_export_directory(root,uid)as parent:
        libvirt_export_inventory(parent,uid);header,hp=libvirt_assignment_read_header(parent,job+'.json',uid)
        fields={'kind','request','manifest','rowCount','bindingCount','configCount','canonicalBytes','canonicalSHA256','producer','source','bootID','issuedUnix','issuedMonotonic','sameExistingWorkerConnection','snapshotReadTransactionClosed','SQLChanges','rootAuthority','queueOrGpuLeaseReleased'}
        require(set(header)==fields and header['kind']==LIBVIRT_ASSIGNMENT_KIND and header['request']['jobId']==job,'Closed exact assignment schema/job')
        require(header['producer']==expectedWorker and header['source']==expectedSource and header['bootID']==expectedBoot,'External authenticated worker/source/boot binding')
        require(0<=time.monotonic()-header['issuedMonotonic']<=maximumAge and 0<=time.time()-header['issuedUnix']<=maximumAge,'Current same-host assignment freshness, no window extension')
        require(header['sameExistingWorkerConnection']is True and header['snapshotReadTransactionClosed']is True and header['SQLChanges']==0 and header['rootAuthority']is False and header['queueOrGpuLeaseReleased']is False,'Data only exact readonly snapshot disposition')
        with history_directory(root,uid)as history,history_archive_view(history,uid,archive_metrics)as archive_view:
            history_inventory(history,uid,archive_view);mr=history_read_leaf(history,header['manifest'],uid,HISTORY_METADATA_MAX,archive_view);manifest=json.loads(mr)
            require((canonical(manifest)+'\n').encode()==mr and set(manifest)=={'kind','request','rows','bindings','config','canonicalBytes','canonicalSHA256'}and manifest['kind']==LIBVIRT_ASSIGNMENT_KIND and manifest['request']==header['request'],'Whole assignment manifest source/context')
            bindings=dict(manifest['bindings']);require(len(bindings)==len(manifest['bindings']),'Unique whole raw binding strings')
            enriched=[];row_bytes=2;seen=set()
            for pin in manifest['rows']:
                row=json.loads(history_read_leaf(history,pin,uid,HISTORY_FILE_MAX,archive_view))
                require(row['id']not in seen,'Unique complete snapshot rows');seen.add(row['id'])
                require('_poolBinding'in row and row['_poolBinding']==(json.loads(bindings[row['id']])if row['id']in bindings else None),'Every augmented binding matches original raw SQL binding')
                row_bytes+=len(canonical({k:v for k,v in row.items()if k!='_poolBinding'}).encode())+1
                require(row_bytes<=HISTORY_FILE_MAX,'Complete snapshot within unchanged byte ceiling');enriched.append(row)
            rows=[{k:v for k,v in r.items()if k!='_poolBinding'}for r in enriched]
            value={'rows':rows,'bindings':manifest['bindings'],'config':manifest['config']};raw=(canonical(value)+'\n').encode()
            require(len(raw)==header['canonicalBytes']==manifest['canonicalBytes']<=HISTORY_FILE_MAX and hashlib.sha256(raw).hexdigest()==header['canonicalSHA256']==manifest['canonicalSHA256'],'Complete exact current rows/bindings/config SHA')
            require(len(rows)==header['rowCount'] and len({r['id']for r in rows})==len(rows)and len(dict(value['bindings']))==len(value['bindings'])==header['bindingCount']and len(value['config'])==header['configCount'],'Unique complete snapshot counts')
            own=next(r for r in rows if r['id']==job);bound=json.loads(dict(value['bindings'])[job]);require(own['state']=='running'and own['finished']is None and own['result']is None and libvirt_request(own,bound)==header['request'],'Actual snapshot running invocation/spec/request')
            require(history_read_leaf(history,header['manifest'],uid,HISTORY_METADATA_MAX,archive_view)==mr,'Manifest reread unchanged')
            for pin in manifest['rows']:history_read_leaf(history,pin,uid,HISTORY_FILE_MAX,archive_view)
        require(libvirt_assignment_read_header(parent,job+'.json',uid)==(header,hp),'Header reread full9/bytes unchanged')
    if metrics is not None:metrics.update(archive_metrics,elapsedSeconds=time.monotonic()-started,rows=len(rows),bindings=len(bindings),canonicalBytes=len(raw))
    return value,{'header':hp,'request':header['request'],'producer':header['producer'],'source':header['source'],'bootID':header['bootID'],'canonicalBytes':len(raw),'canonicalSHA256':hashlib.sha256(raw).hexdigest(),'snapshotReadTransactionClosed':True,'RootAuthority':False,'closureOrLeaseReleaseClaimed':False}

def tick(root, db, backend, cfg):
    require(not db.execute("SELECT 1 FROM jobs WHERE state='terminal_cleanup'").fetchone(), "Durable terminal cleanup lease held; no automatic cleanup retry or dispatch")
    rows, pool_proof = fresh_pool_epoch(db, backend,"tick-initial")
    for row in rows:
        if row["state"] != "running":
            continue
        if row["unit"] in pool_proof["unknownReservationsRetained"]:
            if row['id'] in DIAGNOSTIC_TERMINAL_INPUTS:
                finish_diagnostic(db,backend,*DIAGNOSTIC_TERMINAL_INPUTS[row['id']]);return
            if row['id']in COLLECTED_TERMINAL_INPUTS:
                finish_collected(db,backend,row,*COLLECTED_TERMINAL_INPUTS[row['id']]);continue
            if row['id'] in COLLECTED_LIBVIRT_FAILED_ORIGINS:
                try:
                    finish_collected_libvirt_failed(db,backend,row)
                except (ValueError,OSError,RuntimeError,subprocess.SubprocessError,sqlite3.Error) as error:
                    retain_bound_failure(db,row,'Unit evidence missing; collected original failed proof refused; reservation retained',
                                         {'type':type(error).__name__,'reason':str(error),'evidence':getattr(error,'evidence',None),
                                          'originalReservationRetainedResult':row['result']})
                continue
            # The complete first refusal already lives on a held original row.
            # Preserve it byte-for-byte while another exact own job finalizes.
            if not retained_unknown_marker(row):
                retain_bound_failure(db, row, "Unit evidence missing or unbound current invocation; reservation retained", pool_proof)
            continue
        output = root / "logs" / row["id"]
        try:
            ctx = ExpectedInvocation(backend, db, row)
            oversized = (output / "output-limit.json").exists() or any(p.exists() and p.stat().st_size > MAX_LOG for p in output.glob("*.log"))
            if oversized:
                commit_output_limit(db, backend, row, output)
                continue
            with ctx:
                state, evidence, empty = backend.inspect(row["unit"])
                ctx.verify()
            if state == "unknown" or (state is not None and not empty):
                retain_bound_failure(db, row, "Original unit current closure unknown", evidence)
                continue
            if state is not None:
                require(evidence.get("InvocationID") == row["_poolBinding"]["invocation"], "Inspection returned different original invocation")
                # Original fsync operations stay scoped to owned transcript files.
                for path in output.iterdir():
                    if path.is_file() and not path.is_symlink():
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                        try: os.fsync(fd)
                        finally: os.close(fd)
                dfd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(dfd)
                finally: os.close(dfd)
                finish_bound(db, backend, row, "output_limit" if oversized else state, evidence)
        except PoolAdmissionFailure:
            # Current whole-pool sampling is not an original-unit terminal result.
            # The existing outer worker retains full first-failure diagnostics and
            # performs its strict same-ledger/vanished-task monitoring proof.
            raise
        except (ValueError, OSError, RuntimeError, subprocess.SubprocessError, sqlite3.Error) as error:
            if db.execute("SELECT state FROM jobs WHERE id=?", (row["id"],)).fetchone()[0] == "terminal_cleanup":
                import traceback
                current_pending = json.loads(db.execute("SELECT result FROM jobs WHERE id=?", (row["id"],)).fetchone()[0])
                current_pending["terminalCleanupFailure"] = {"type": type(error).__name__, "reason": str(error), "traceback": traceback.format_exc(), "evidence": getattr(error, "evidence", None), "reservationRetained": True, "automaticRetryAuthorized": False}
                try:
                    with db: db.execute("UPDATE jobs SET result=? WHERE id=? AND state='terminal_cleanup'", (canonical(current_pending), row["id"]))
                except BaseException as secondary:
                    print(canonical({"firstCleanupFailure": current_pending["terminalCleanupFailure"], "secondaryPersistenceFailure": {"type":type(secondary).__name__, "reason":str(secondary)}, "reservationRetained":True}), file=sys.stderr, flush=True)
                raise
            retain_bound_failure(db, row, "Original immutable invocation current guard refused; reservation retained", getattr(error, "evidence", {"type": type(error).__name__, "reason": str(error)}))
    rows = db.execute("SELECT * FROM jobs ORDER BY rowid").fetchall()
    selected, blocked = choose(rows, cfg)
    for name, why in blocked:
        finish(db, name, "blocked", {"reason": why})
    for proposed, spec, ignored_initial_cpus in selected:
        try:
            check_inputs(spec)
        except (ValueError, OSError) as error:
            finish(db, proposed["id"], "failed", {"reason": str(error), "launched": False})
            continue
        # Hashing and earlier launches/effects may change current reservations.
        current, proof = fresh_pool_epoch(db, backend,"tick-prelaunch")
        reconciled, _ = choose(current, cfg)
        match = next((item for item in reconciled if item[0]["id"] == proposed["id"]), None)
        if match is None:
            continue
        row, fresh_spec, cpus = match
        require(canonical(fresh_spec) == canonical(spec), "Pending approved spec changed after input checks")
        if launch_admission_wait(spec) is not None:
            continue
        unit = backend.prefix + uuid.uuid4().hex + ".service"
        output = root / "logs" / row["id"]
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        with db:
            db.execute("UPDATE jobs SET state='running',cpus=?,unit=?,started=? WHERE id=? AND state='pending'", (canonical(cpus), unit, time.time(), row["id"]))
        planned = dict(row, state="running", unit=unit, cpus=canonical(cpus), _poolBinding=None)
        try:
            # Current planned reservation is counted, but cannot whitelist work.
            actual, boundary = fresh_pool_epoch(db, backend,"tick-prelaunch")
            planned = next(item for item in actual if item["id"] == row["id"])
            require(planned["state"] == "running" and planned["unit"] == unit and json.loads(planned["cpus"]) == cpus and planned["_poolBinding"] is None and canonical(json.loads(planned["spec"])) == canonical(spec), "Actual launch reservation changed")
            require(boundary["unitProperties"][unit]["properties"].get("LoadState") == "not-found", "Fresh nonce unit already exists; no rearm")
            require(0 <= time.monotonic() - boundary["completedMonotonic"] <= 1, "Actual launch pool epoch expired")
            launch = backend.launch(spec, cpus, unit, output)
            if launch and launch.get("readiness_wait"):
                require(launch["unit_not_created"] is True, "Readiness wait before native dispatch only")
                return_readiness_wait(root, db, backend, planned, output, launch["readiness_wait"])
                continue
            if launch and launch.get("launch_failed"):
                _, closure = fresh_pool_epoch(db, backend,"tick-prelaunch")
                require(closure["unitProperties"][unit]["properties"].get("LoadState") == "not-found", "Failed launcher unit absence became unknown")
                proof = backend.whole_owned_cgroup(unit, {"ControlGroup": ""})
                require(proof["empty"], "Uncreated own nonce group not empty")
                finish_uncreated(db, backend, planned, launch, proof)
            else:
                binding = backend.capture_pool_unit_binding(row["id"], spec, cpus, unit)
                with db:
                    db.execute("INSERT INTO pool_unit_bindings(job_id,value) VALUES(?,?)", (row["id"], canonical(binding)))
                if "libvirt_domain" in spec:
                    committed=dict(db.execute("SELECT * FROM jobs WHERE id=?",(row["id"],)).fetchone())
                    publish_libvirt_assignment(db,committed,binding)
        except Exception as error:
            retain_bound_failure(db, dict(planned), "Launch current proof/registration unknown; original reservation retained", {"type": type(error).__name__, "reason": str(error), "evidence": getattr(error, "evidence", None)})
            raise


def persist_monitor_failure(root,error,*,readonly_observation=None):
    import traceback,stat
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');core=fields[:6];fd=None;dfd=None;primary=None;closes=[];proof={}
    def ident(s):return {k:getattr(s,k)for k in fields}
    def held_parent(expected=None):
        x=ident(os.fstat(dfd));require(x==ident(os.lstat(parent))and(expected is None or x==expected),'full9field held diagnostic parent custody');return x
    packet={'kind':'COMPLETE_TYPED_POOL_MONITOR_FAILURE','type':type(error).__name__,'message':str(error),'evidence':getattr(error,'evidence',None),'traceback':traceback.format_exc(),'operationOrReleaseAuthorized':False}
    if readonly_observation is not None:
        require(type(readonly_observation)is dict,'typed readonly transaction packet')
        keys={'kind','batchId','ordinal','encodedPart','encodedPartSHA256'}if readonly_observation.get('kind')=='QUEUE_READONLY_OBSERVER_PART_R241'else{'kind','batchId','partCount','encodedBytes','encodedSHA256','rawBytes','rawSHA256','recordCount','parts','failureIncluded'}
        require(error is None and type(readonly_observation)is dict and set(readonly_observation)==keys and readonly_observation['kind']in('QUEUE_READONLY_OBSERVER_PART_R241','QUEUE_READONLY_OBSERVER_COMMIT_R241')and re.fullmatch('[0-9a-f]{32}',readonly_observation['batchId'])is not None,'closed readonly transaction writer purpose')
        packet=readonly_observation
    raw=(canonical(packet)+'\n').encode();require(len(raw)<=1048576,'complete monitor frame bound');path=Path(root)/('readonly-observations.log'if readonly_observation is not None else'monitor-failures.log');parent=path.parent
    try:
        before=ident(os.lstat(parent));require(stat.S_ISDIR(before['st_mode'])and before['st_uid']==before['st_gid']==os.getuid()and parent.resolve(strict=True)==parent and not any(p.is_symlink()for p in [parent,*parent.parents]),'exact canonical own diagnostic parent');dfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);held_parent(before)
        try:old=ident(os.stat(path.name,dir_fd=dfd,follow_symlinks=False))
        except FileNotFoundError:old=None
        fd=os.open(path.name,os.O_RDWR|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dfd);initial=ident(os.fstat(fd));require(initial==ident(os.stat(path.name,dir_fd=dfd,follow_symlinks=False))and stat.S_ISREG(initial['st_mode'])and initial['st_nlink']==1 and initial['st_uid']==initial['st_gid']==os.getuid()and stat.S_IMODE(initial['st_mode'])==0o600 and (old is None or old==initial),'diagnostic file full9field noalias/custody');require(initial['st_size']+len(raw)<=MAX_LOG,'same finite ordinary log cap');openedParent=held_parent();require(all(openedParent[k]==before[k]for k in core),'parent core unchanged by own file create');require(old is None or openedParent==before,'existing append does not mutate parent9fields')
        if old is None:require(initial['st_size']==0 and openedParent['st_size']>=before['st_size']and openedParent['st_mtime_ns']>=before['st_mtime_ns']and openedParent['st_ctime_ns']>=before['st_ctime_ns'],'exact legitimate file-create parent growth')
        prefix=hashlib.sha256();offset=0
        while offset<initial['st_size']:
            chunk=os.pread(fd,min(65536,initial['st_size']-offset),offset);require(chunk,'complete prior prefix');prefix.update(chunk);offset+=len(chunk)
        require(ident(os.fstat(fd))==initial==ident(os.stat(path.name,dir_fd=dfd,follow_symlinks=False)),'preappend complete file custody');held_parent(openedParent);view=memoryview(raw)
        while view:n=os.write(fd,view);require(n>0,'complete diagnostic append');view=view[n:]
        os.fsync(fd);after=ident(os.fstat(fd));require(after==ident(os.stat(path.name,dir_fd=dfd,follow_symlinks=False))and all(after[k]==initial[k]for k in core)and after['st_size']==initial['st_size']+len(raw)and after['st_mtime_ns']>=initial['st_mtime_ns']and after['st_ctime_ns']>=initial['st_ctime_ns'],'exact held/path9field append growth/custody');held_parent(openedParent);require(os.pread(fd,len(raw),initial['st_size'])==raw,'durable full frame readback');again=hashlib.sha256();offset=0
        while offset<initial['st_size']:
            chunk=os.pread(fd,min(65536,initial['st_size']-offset),offset);require(chunk,'prior prefix EOF');again.update(chunk);offset+=len(chunk)
        require(again.digest()==prefix.digest()and ident(os.fstat(fd))==after==ident(os.stat(path.name,dir_fd=dfd,follow_symlinks=False)),'immutable entire old prefix and full final inode');os.fsync(dfd);held_parent(openedParent);proof={'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'before':initial,'after':after,'parentBefore':before,'parentAfterOwnCreate':openedParent,'oldPrefixSHA256':prefix.hexdigest(),'classificationStillPending':readonly_observation is None}
    except BaseException as cause:primary=cause
    finally:
        for label,value in (('file',fd),('parent',dfd)):
            if value is None:continue
            try:os.close(value);closes.append({'label':label,'fd':value,'closed':True,'UNKNOWN':False})
            except BaseException as cause:
                closes.append({'label':label,'fd':value,'closed':False,'UNKNOWN':True,'error':repr(cause)})
                if primary is None:primary=cause
    proof['closeOutcomes']=closes
    if primary is not None:primary.diagnosticCustody=proof;raise primary
    return proof

def monitor_observed_thread_exit(typed,includeLeader=True):
    # This only proves absence; it never adopts or signals a present PID.
    require(hashlib.sha256(POOL_PROOF_SOURCE.encode()).hexdigest()==POOL_PROOF_SHA,'Closed pool proof source pin')
    module={'__name__':'owned_readonly_thread_exit'}
    exec(compile(POOL_PROOF_SOURCE,'root_pool_proof_r1.py','exec'),module)
    io=module['KernelIO']();owned=contextmanager(module['owned_fd_evidence']);root=io.open_dir('/proc');records=[]
    with owned(root,{'label':'monitor-proc-root'}):
        meta=io.fd_id(root)
        require(io.magic(root)==0x9fa0 and meta==io.path_id('/proc') and meta[3:5]==(0,0),'current held proc root/type/custody')
        for pid in sorted({typed['process']['tid'],typed['process']['tgid']} if includeLeader else {typed['process']['tid']}):
            try:fd=io.open_dir(str(pid),root)
            except OSError as error:
                if error.errno not in (2,3):raise
                try:io.child_id(root,str(pid))
                except OSError as current:
                    if current.errno not in (2,3):raise
                    records.append({'pid':pid,'observedOriginalStart':typed['process']['start'] if pid==typed['process']['tid'] else None,'pathAbsent':True,'errno':current.errno})
                else:require(False,'observed thread/leader path present after missing read')
            else:
                with owned(fd,{'label':'monitor-present-task-'+str(pid)}):
                    require(False,'observed task/leader still present, reused or unknown; exit race refused')
        require(io.fd_id(root)==meta==io.path_id('/proc'),'held proc root changed after absence proof')
    return {'originalThreadAndLeaderPathsAbsent':records,'allOwnedDescriptorsClosed':True,'operationOrReleaseAuthorized':False}

def monitor_first_proc_absence(typed):
    # Actual PID directory absence is required, but never substitutes for a
    # complete fresh pool/lease proof. No original start is invented.
    require(hashlib.sha256(POOL_PROOF_SOURCE.encode()).hexdigest()==POOL_PROOF_SHA,'Closed pool proof source pin')
    module={'__name__':'owned_readonly_initial_proc_exit'}
    exec(compile(POOL_PROOF_SOURCE,'root_pool_proof_r1.py','exec'),module)
    io=module['KernelIO']();owned=contextmanager(module['owned_fd_evidence']);root=io.open_dir('/proc');records=[]
    with owned(root,{'label':'monitor-initial-proc-root'}):
        meta=io.fd_id(root);require(io.magic(root)==0x9fa0 and meta==io.path_id('/proc') and meta[3:5]==(0,0),'current held proc root/type/custody')
        pid=typed['tid']
        try:fd=io.open_dir(str(pid),root)
        except OSError as error:
            if error.errno not in (2,3):raise
            try:io.child_id(root,str(pid))
            except OSError as current:
                if current.errno not in (2,3):raise
                records.append({'pid':pid,'observedOriginalStart':'UNKNOWN_FIRST_OBSERVATION_INCOMPLETE','pathAbsent':True,'errno':current.errno})
            else:require(False,'first-observation task path present after missing read')
        else:
            with owned(fd,{'label':'monitor-initial-present-task-'+str(pid)}):
                require(False,'initial task still live, reused or unknown; no adoption')
        require(io.fd_id(root)==meta==io.path_id('/proc'),'held proc root changed after first-read absence proof')
    return {'incompleteOriginalIdentityPreserved':True,'currentPathAbsenceOnly':records,'allOwnedDescriptorsClosed':True,'operationOrReleaseAuthorized':False}

def monitor_first_proc_read_exit(db,backend,error,typed,rows,running,records):
    original=typed['originalFailure'];require(type(original)is dict and set(original)=={'type','reason'} and original['type']in('ProcessLookupError','FileNotFoundError') and type(original['reason'])is str,'original concrete first-read refusal retained')
    require(typed['originalStart']=='UNKNOWN_FIRST_OBSERVATION_INCOMPLETE','no invented first-observation identity')
    closes=error['firstFailure']['closeOutcomes'];require(any(x.get('label')=='proc-'+str(typed['tid'])for x in closes),'held original PID-directory close provenance')
    fresh_rows,fresh=boundary_pool_epoch(db,backend)
    require(fresh.get('admitted')is True and fresh.get('allOwnedDescriptorsClosed')is True and fresh.get('includesUID0')is True and fresh.get('completeBoundedTraversal')is True and fresh.get('unknownReservationsRetained')==[],'fresh complete UID0 pool proof; no foreign or unknown owner')
    require([(r['id'],r['state'],r['unit'],r['spec'],r['cpus'],r.get('_poolBinding'))for r in fresh_rows]==[(r['id'],r['state'],r['unit'],r['spec'],r['cpus'],r.get('_poolBinding'))for r in rows],'complete original logical ledger unchanged')
    absent=monitor_first_proc_absence(typed)
    for record in records:
        row=next(r for r in running if r['id']==record['jobId']);ctx=ExpectedInvocation(backend,db,row);ctx.ledger_current();props=exact_unit_observation(backend,ctx.unit);epoch=fresh['unitProperties'][ctx.unit]['properties']
        require(props.get('LoadState')=='loaded'and props.get('InvocationID')==ctx.invocation and props.get('ControlGroup')in('', '/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/'+ctx.unit)and all(props.get(k)==epoch.get(k)for k in('LoadState','InvocationID','MainPID','ActiveState','SubState','ControlGroup')),'fresh exact original invocation/manager epoch')
        require(int(props.get('MainPID','0'))!=typed['tid'],'known original MainPID absence never positive')
        if fresh.get('currentWholePoolEmpty')is True:require(terminal_observation(props),'empty pool alone never terminal proof')
        else:require(props.get('ActiveState')in('activating','active','deactivating','reloading'),'nonempty pool requires positively owned current invocation')
    require(0<=time.monotonic()-fresh['completedMonotonic']<=1,'bounded fresh first-read monitoring proof')
    records.append({'incompleteFirstReadObservation':typed,'freshWholePoolProof':fresh,'currentTaskAbsence':absent,'reservationRetained':True,'operationOrReleaseAuthorized':False})
    return {'firstFailure':error,'originalReadonlyMonitor':records,'newAdmissionEffectsReleaseForbidden':True,'originalServiceNotCancelled':True}

def capture_observation(captures, record):
    """Keep bounded optional copies without turning a full sink into a veto."""
    if type(captures) is list and len(captures) < 32:
        captures.append(record)

def verify_libvirt_second_cut(observed,again,reservations,deadline):
    if again==observed:return
    if runtime_publisher_transition(observed,again):
        error=RuntimePublisherTransition('authenticated runtime publication crossed full pool cut')
        error.evidence={'kind':'AUTHENTICATED_RUNTIME_PUBLICATION_TRANSITION','before':observed,'after':again,'deadlineMonotonic':deadline,'recordedReservations':reservations,'operationOrReleaseAuthorized':False};raise error
    raise pool_observation_unavailable(observed['request'],reservations,{'kind':'TWO_VALIDATED_LIBVIRT_CUTS_DIFFER','before':observed,'after':again},True)

def pool_observation_unavailable(request,reservations,failure,closed):
    return PoolAdmissionFailure('libvirt observation unavailable; monitor only',{'kind':'ADMITTED_LIBVIRT_OBSERVATION_UNAVAILABLE','request':request,'recordedReservations':reservations,'firstFailure':failure,'observerChildClosed':closed,'admitted':False,'reservationRetained':True,'operationOrReleaseAuthorized':False})

def monitor_admitted_libvirt(db,backend,error):
    require(type(error)is PoolAdmissionFailure,'exact typed unavailable observation')
    e=error.evidence;require(e.get('kind')=='ADMITTED_LIBVIRT_OBSERVATION_UNAVAILABLE'and e.get('observerChildClosed')is True and e.get('admitted')is False and e.get('reservationRetained')is True and e.get('operationOrReleaseAuthorized')is False,'unavailable proof cannot authorize admission/effect/release')
    rows=pool_rows(db,db.execute('SELECT * FROM jobs ORDER BY rowid').fetchall());running=[r for r in rows if r['state']=='running'];require(running,'original admitted job required for monitor hold');expected=[];records=[];matched=False
    for row in running:
        ctx=ExpectedInvocation(backend,db,row);ctx.ledger_current();spec=json.loads(row['spec']);check_inputs(spec);cpus=json.loads(row['cpus']);b=ctx.bound
        require(b['version']==1 and b['specSHA256']==hashlib.sha256(canonical(spec).encode()).hexdigest()and b['cpus']==cpus and b['memory']==spec['memory'],'same original immutable source/spec/resource binding')
        require(type(row['started'])in(int,float)and 0<=time.time()-row['started']<=spec['timeout_seconds']+5,'original service deadline/reap reserve, no extension')
        props=backend.pool_unit_properties(row['unit']);ctx.ledger_current();require(props.get('LoadState')=='loaded'and props.get('InvocationID')==ctx.invocation and props.get('ControlGroup')in('', '/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/'+row['unit']),'same original actual manager invocation/cgroup; no adopted actor')
        item={'unit':row['unit'],'cpus':cpus,'memory':spec['memory'],'resources':spec['resources'],'invocation':ctx.invocation}
        if 'libvirt_domain'in spec:
            item['controllerMemory']=LIBVIRT_CONTROLLER_MEMORY
            if libvirt_request(row,b)==e['request']:matched=True
        expected.append(item);records.append({'jobId':row['id'],'unit':row['unit'],'invocation':ctx.invocation,'properties':props,'reservationRetained':True,'operationOrReleaseAuthorized':False})
    require(matched and e['recordedReservations']==expected,'all original reservations and exact observed request unchanged; no foreign principal')
    return {'kind':'ADMITTED_LIBVIRT_MONITOR_ONLY_HOLD','firstFailure':e,'originalReadonlyMonitor':records,'newAdmissionEffectsReleaseForbidden':True,'originalServiceNotCancelled':True}

def monitor_membership_race(db,backend,error):
    require(type(error) is PoolAdmissionFailure,'only exact typed pool observation failure')
    e=error.evidence;failure=e.get('firstFailure');require(type(failure)is dict,'complete typed observation required');typed=failure.get('firstFailure');transient=type(typed)is dict and set(typed)=={'type','errno','tid','path','stage'}and typed['type']=='TransientProcObservation'and type(typed['errno'])is int and typed['errno']in(2,3)and type(typed['tid'])is int and typed['tid']>0 and typed['path']=='/proc/'+str(typed['tid'])and typed['stage']=='pid-directory-open';leader=(type(typed)is dict and set(typed)=={'type','reason','stage','unit','invocation','group','sampledPids','sampledTids','sampledPopulated','process'} and typed['type']=='TransientThreadLeaderObservation' and typed['reason']=='thread group leader missing' and typed['stage']=='thread-leader-coverage');revalidation=(type(typed)is dict and set(typed)=={'type','reason','errno','tid','path','stage','process','originalFailure'} and typed['type']=='TransientProcRevalidationObservation' and typed['reason']=='previously observed proc task vanished during revalidation' and type(typed['errno'])is int and typed['errno']in(2,3) and type(typed['tid'])is int and typed['tid']>0 and typed['path']=='/proc/'+str(typed['tid']) and typed['stage']=='previous-task-revalidation');first_read=(type(typed)is dict and set(typed)=={'type','reason','errno','tid','path','stage','field','originalFailure','originalStart'}and typed['type']=='TransientProcFirstReadObservation'and typed['reason']=='first proc field vanished before complete task observation'and type(typed['errno'])is int and typed['errno']in(2,3)and type(typed['tid'])is int and typed['tid']>0 and typed['path']=='/proc/'+str(typed['tid'])and typed['stage']=='first-task-field-read'and typed['field']in('stat','status','cgroup','pid-directory-identity')and typed['originalStart']=='UNKNOWN_FIRST_OBSERVATION_INCOMPLETE');require(typed=={'type':'ValueError','reason':'current group membership/populated race'}or transient or leader or revalidation or first_read,'only exact current membership or vanished proc/thread observation')
    require(e.get('admitted')is False and e.get('reservationRetained')is True and e.get('operationOrReleaseAuthorized')is False,'refused admission cannot authorize effect/release')
    closes=failure.get('closeOutcomes');require(type(closes)is list and closes and all(x.get('closed')is True and x.get('UNKNOWN')is False for x in closes),'all observation descriptors closed')
    rows=pool_rows(db,db.execute('SELECT * FROM jobs ORDER BY rowid').fetchall());running=[r for r in rows if r['state']=='running'];require(running,'no prior admission to monitor')
    records=[];expected=[]
    for row in running:
        ctx=ExpectedInvocation(backend,db,row);ctx.ledger_current();spec=json.loads(row['spec']);cpus=json.loads(row['cpus']);bound=ctx.bound
        require(bound['version']==1 and bound['specSHA256']==hashlib.sha256(canonical(spec).encode()).hexdigest()and bound['cpus']==cpus and bound['memory']==spec['memory'],'original immutable spec/cap binding')
        require(type(row['started'])in(int,float)and 0<=time.time()-row['started']<=spec['timeout_seconds']+5,'original service deadline/reap reserve, no extension')
        props=exact_unit_observation(backend,row['unit']);ctx.ledger_current();require(props.get('LoadState')=='loaded'and props.get('InvocationID')==ctx.invocation and props.get('ControlGroup')in('', '/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/'+row['unit']),'readonly original invocation still exact')
        require(not (transient or revalidation or first_read) or int(props.get('MainPID','0'))!=typed['tid'],'known own MainPID absence never positive');
        records.append({'jobId':row['id'],'unit':row['unit'],'invocation':ctx.invocation,'properties':props,'reservationRetained':True,'operationOrReleaseAuthorized':False})
        expected.append({'unit':row['unit'],'cpus':cpus,'memory':spec['memory'],'resources':spec['resources'],'invocation':ctx.invocation})
        if 'libvirt_domain' in spec:
            expected[-1]['controllerMemory']=LIBVIRT_CONTROLLER_MEMORY
    require(e.get('recordedReservations')==expected,'every observed lease known and exact, no adoption')
    if first_read:
        return monitor_first_proc_read_exit(db,backend,e,typed,rows,running,records)
    if revalidation:
        return monitor_proc_revalidation_exit(db,backend,e,typed,rows,running,records)
    if leader:
        process=typed['process'];require(type(process)is dict and set(process)=={'tid','start','ppid','tgid','uids','cgroup'} and all(type(process[k])is int and process[k]>0 for k in ('tid','start','tgid')) and type(process['ppid'])is int and process['ppid']>=0 and type(process['uids'])is list and len(process['uids'])==4 and all(type(v)is int and v>=0 for v in process['uids']),'complete observed task identity')
        require(type(typed['sampledPids'])is list and type(typed['sampledTids'])is list and all(type(v)is int and v>0 for v in typed['sampledPids']+typed['sampledTids']) and len(set(typed['sampledPids']))==len(typed['sampledPids']) and len(set(typed['sampledTids']))==len(typed['sampledTids']) and set(typed['sampledPids'])<=set(typed['sampledTids']) and process['tid'] in typed['sampledTids'] and process['tgid'] not in typed['sampledPids'] and typed['sampledPopulated']=='1','exact original missing leader coverage')
        matching=[r for r in running if r['unit']==typed['unit']];require(len(matching)==1 and matching[0]['_poolBinding']['invocation']==typed['invocation'],'thread observation original lease/invocation')
        group='/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/'+typed['unit'];require(type(typed['group'])is str and (typed['group']==group or typed['group'].startswith(group+'/')) and process['cgroup']==typed['group'] and all(x not in ('.','..','') for x in typed['group'].split('/')[1:]),'observed thread exact original cgroup, no foreign adoption')
        fresh_rows,fresh=boundary_pool_epoch(db,backend)
        require(fresh.get('admitted')is True and fresh.get('allOwnedDescriptorsClosed')is True and fresh.get('currentWholePoolEmpty')is True and fresh.get('tasks')==[] and fresh.get('lastKernelWholePoolPopulated')=='0' and fresh.get('unknownReservationsRetained')==[],'fresh complete UID0 pool closure required for thread exit observation')
        require([(r['id'],r['state'],r['unit'],r['spec'],r['cpus'],r.get('_poolBinding')) for r in fresh_rows]==[(r['id'],r['state'],r['unit'],r['spec'],r['cpus'],r.get('_poolBinding')) for r in rows],'complete logical ledger unchanged during exit proof')
        absent=monitor_observed_thread_exit(typed)
        for record in records:
            ctx=ExpectedInvocation(backend,db,next(r for r in running if r['id']==record['jobId']));ctx.ledger_current();props=exact_unit_observation(backend,ctx.unit);epoch=fresh['unitProperties'][ctx.unit]['properties'];require(props.get('LoadState')=='loaded' and props.get('InvocationID')==ctx.invocation and props.get('MainPID')=='0' and props.get('ActiveState')in('inactive','failed') and props.get('ControlGroup')in('', '/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/'+ctx.unit) and all(props.get(k)==epoch.get(k) for k in ('LoadState','InvocationID','MainPID','ActiveState','SubState','ControlGroup')),'fresh same-invocation terminal manager context, no live or foreign principal')
        require(0<=time.monotonic()-fresh['completedMonotonic']<=1,'thread exit proof fresh clock')
        records.append({'threadExitObservation':typed,'freshWholePoolProof':fresh,'threadAndLeaderAbsence':absent,'reservationRetained':True,'operationOrReleaseAuthorized':False})
    return {'firstFailure':e,'originalReadonlyMonitor':records,'newAdmissionEffectsReleaseForbidden':True,'originalServiceNotCancelled':True}

def exact_proc_revalidation_evidence(typed,running):
    require(type(typed)is dict and set(typed)=={'type','reason','errno','tid','path','stage','process','originalFailure'} and typed['type']=='TransientProcRevalidationObservation' and typed['reason']=='previously observed proc task vanished during revalidation' and type(typed['errno'])is int and typed['errno']==2 and type(typed['tid'])is int and typed['tid']>0 and typed['path']=='/proc/'+str(typed['tid']) and typed['stage']=='previous-task-revalidation','exact prior task ENOENT revalidation observation')
    process=typed['process']
    require(type(process)is dict and set(process)=={'tid','start','ppid','tgid','uids','cgroup'} and all(type(process[k])is int and process[k]>0 for k in ('tid','start','tgid')) and type(process['ppid'])is int and process['ppid']>=0 and type(process['uids'])is list and len(process['uids'])==4 and all(type(v)is int and v>=0 for v in process['uids']) and process['tid']==typed['tid'],'complete prior task identity, no guessed original')
    # A failed pid-directory open retains a structured observation. A field
    # read after opening that directory retains the earlier raw exception
    # shape. Both are produced only after a complete prior task observation.
    original=typed['originalFailure']
    directory_missing=(type(original)is dict and set(original)=={'type','errno','tid','path','stage'} and original['type']=='TransientProcObservation' and type(original['errno'])is int and original['errno']==2 and type(original['tid'])is int and original['tid']==typed['tid'] and original['path']==typed['path'] and original['stage']=='pid-directory-open')
    field_missing=(type(original)is dict and set(original)=={'type','reason'} and original['type']in('ProcessLookupError','FileNotFoundError') and type(original['reason'])is str)
    require(directory_missing or field_missing,'exact original ENOENT proc refusal retained')
    matches=[]
    for row in running:
        group='/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/'+row['unit']
        if type(process['cgroup'])is str and (process['cgroup']==group or process['cgroup'].startswith(group+'/')):matches.append(row)
    require(len(matches)==1 and all(x not in ('.','..','')for x in process['cgroup'].split('/')[1:]),'prior observed task belongs to exact original lease, no foreign adoption')
    return matches[0]

def monitor_proc_revalidation_exit(db,backend,error,typed,rows,running,records):
    exact_proc_revalidation_evidence(typed,running)
    fresh_rows,fresh=boundary_pool_epoch(db,backend)
    require(fresh.get('admitted')is True and fresh.get('allOwnedDescriptorsClosed')is True and fresh.get('includesUID0')is True and fresh.get('completeBoundedTraversal')is True and fresh.get('unknownReservationsRetained')==[],'fresh complete UID0 pool proof required; never swallow foreign/unknown owners')
    require([(r['id'],r['state'],r['unit'],r['spec'],r['cpus'],r.get('_poolBinding'))for r in fresh_rows]==[(r['id'],r['state'],r['unit'],r['spec'],r['cpus'],r.get('_poolBinding'))for r in rows],'complete original logical ledger unchanged')
    absent=monitor_observed_thread_exit(typed,includeLeader=False)
    for record in records:
        row=next(r for r in running if r['id']==record['jobId']);ctx=ExpectedInvocation(backend,db,row);ctx.ledger_current();props=exact_unit_observation(backend,ctx.unit);epoch=fresh['unitProperties'][ctx.unit]['properties']
        require(props.get('LoadState')=='loaded' and props.get('InvocationID')==ctx.invocation and props.get('ControlGroup')in('', '/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/'+ctx.unit) and all(props.get(k)==epoch.get(k)for k in ('LoadState','InvocationID','MainPID','ActiveState','SubState','ControlGroup')),'fresh exact original invocation/manager epoch')
        require(int(props.get('MainPID','0'))!=typed['tid'],'known original MainPID missing is not a positive monitoring proof')
        if fresh.get('currentWholePoolEmpty')is True:require(terminal_observation(props),'empty pool alone never terminal proof')
        else:require(props.get('ActiveState')in('activating','active','deactivating','reloading'),'nonempty current pool requires still-known invocation')
    require(0<=time.monotonic()-fresh['completedMonotonic']<=1,'fresh bounded proc exit observation')
    records.append({'procRevalidationExitObservation':typed,'freshWholePoolProof':fresh,'observedTaskAbsence':absent,'reservationRetained':True,'operationOrReleaseAuthorized':False})
    return {'firstFailure':error,'originalReadonlyMonitor':records,'newAdmissionEffectsReleaseForbidden':True,'originalServiceNotCancelled':True}

# Finite owner-selected terminal continuation. It does not dispatch pending work,
# invent a lease disposition, stop a worker, or retry a durable cleanup failure.
FAILED_LIBVIRT_TERMINAL_TARGETS = {
    'steamos-firstboot-cd9ef0826364409da287f6f3e3830c95-e2be9046df54f41ab': {
        'unit':'opemos-testq-3b4eb7b4288f-dd2d4a47e34144709a6f681fead80976.service',
        'invocation':'eb0b4c7f7d6545f190dba9cda40aed90',
        'specSHA256':'8dad0bedb02f4a069af66238414ff280cb579f0868bac83a9382a5f80473a752'}}


def reconcile_failed_libvirt_submission(root, db, backend, job_id):
    require(job_id in FAILED_LIBVIRT_TERMINAL_TARGETS, 'Exact admitted failed libvirt submission only')
    require(not db.execute("SELECT 1 FROM jobs WHERE state='terminal_cleanup'").fetchone(),
            'Durable cleanup reservation requires its separate owner; no automatic retry')
    before=diagnostic_ledger(db)
    rows,pool=fresh_pool_epoch(db,backend)
    matches=[r for r in rows if r['id']==job_id]
    require(len(matches)==1, 'Exact failed submission must exist once')
    row=matches[0];target=FAILED_LIBVIRT_TERMINAL_TARGETS[job_id];bound=row.get('_poolBinding')
    require(row['state']=='running' and row['finished'] is None and row['unit']==target['unit']
            and hashlib.sha256(row['spec'].encode()).hexdigest()==target['specSHA256']
            and type(bound)is dict and bound['invocation']==target['invocation'],
            'Original running failed submission/full spec/invocation retained')
    require(row['unit'] not in pool['unknownReservationsRetained'] and
            'libvirt_domain' in json.loads(row['spec']), 'Current libvirt closure cannot be unknown')
    ctx=ExpectedInvocation(backend,db,row)
    with ctx:
        state,evidence,empty=backend.inspect(row['unit'])
        ctx.verify()
    if not (state=='failed' and empty is True and evidence.get('InvocationID')==target['invocation']):
        error=ValueError('Actual original failed terminal and complete closure required')
        error.evidence={'kind':'EXACT_FAILED_LIBVIRT_TERMINAL_REFUSAL','jobId':job_id,
                        'state':state,'empty':empty,'inspection':evidence,
                        'reservationRetained':True,'terminalEffectAuthorized':False}
        raise error
    # Same native path used by ordinary tick: whole_owned_cgroup independently
    # proves logger exit/reap, no-intent/no-lease, domain/partition and GPU closure.
    output=root/'logs'/job_id
    for path in output.iterdir():
        if path.is_file() and not path.is_symlink():
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:os.fsync(fd)
            finally:os.close(fd)
    fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
    require(diagnostic_ledger(db)==before, 'Full current history/bindings/config changed before terminal commit')
    finish_bound(db,backend,row,'failed',evidence)
    after=diagnostic_ledger(db)
    require(before['bindings']==after['bindings'] and before['config']==after['config'] and
            [r['id']for r in before['rows']]==[r['id']for r in after['rows']] and
            [r for r in before['rows']if r['id']!=job_id]==[r for r in after['rows']if r['id']!=job_id],
            'Terminal continuation preserved every other full row, binding and config')
    final=next(r for r in after['rows']if r['id']==job_id);result=json.loads(final['result'])
    require(final['state']=='failed' and type(final['finished'])in(int,float) and
            result['terminalLifecycle']['phase']=='CLOSED' and
            result['terminalLifecycle']['reservationRetained']is False and
            {k:v for k,v in final.items()if k not in('state','finished','result')}==
            {k:v for k,v in row.items()if k not in('state','finished','result','_poolBinding')},
            'Only true canonical failed/CLOSED disposition may release this reservation')
    return {'kind':'EXACT_FAILED_LIBVIRT_CANONICAL_TERMINAL_R1','jobId':job_id,
            'unit':row['unit'],'InvocationID':target['invocation'],'state':final['state'],
            'finished':final['finished'],'terminalLifecycle':result['terminalLifecycle'],
            'otherRowsPreserved':len(after['rows'])-1,'bindingsPreserved':len(after['bindings']),
            'noDispatch':True,'noLeaseClosureInvented':True}


def persist_outer_worker_failure(root,error,lock):
    import traceback
    first={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc(),'evidence':getattr(error,'evidence',None)}
    data={'kind':'COMPLETE_TYPED_OUTER_WORKER_FAILURE_R201','first':first,'poolObservation':getattr(error,'queueObservation',None),'readonlyObserverCapture':getattr(error,'observerCaptureProof',None),'readonlyObserverCaptureFailure':getattr(error,'observerCaptureFailure',None),'adapter':getattr(error,'adapterEvidence',None),'actor':{},'workerLock':{},'source':None,'secondary':[],'reservationRetained':True,'operationOrReleaseAuthorized':False,'actualExitNumeric':'UNKNOWN_UNTIL_OUTER_RECEIPT','intendedExitNumeric':75 if 'pool'in str(error).lower()or'dispatcher'in str(error).lower()else 2}
    try:
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');pid=os.getpid();base=Path('/proc')/str(pid);raw=(base/'stat').read_text();data['actor']={'pid':pid,'start':int(raw.rsplit(')',1)[1].split()[19]),'UIDStatus':(base/'status').read_text(),'argv':os.fsdecode((base/'cmdline').read_bytes()).split('\0'),'cgroup':(base/'cgroup').read_text(),'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip()};data['source']=file_pin(__file__)
        fd=lock.fileno();i={k:getattr(os.fstat(fd),k)for k in fields};named={k:getattr(os.lstat(Path(root)/'worker.lock'),k)for k in fields};data['workerLock']={'fd':fd,'held':i,'named':named,'fdinfo':Path('/proc/self/fdinfo',str(fd)).read_text(),'flockHeldUntilPersistence':False};require(i==named,'worker first-failure held/named lock identity');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);require('FLOCK'in data['workerLock']['fdinfo']and'WRITE'in data['workerLock']['fdinfo'],'actual worker FLOCK evidence');data['workerLock']['flockHeldUntilPersistence']=True
    except BaseException as secondary:data['secondary'].append({'type':type(secondary).__name__,'reason':str(secondary),'UNKNOWN':True})
    error.evidence=data
    try:
        proof=persist_monitor_failure(root,error)
        print(canonical({'kind':'OUTER_WORKER_FIRST_FAILURE_DURABLE','proof':proof,'actualExitNumeric':'UNKNOWN_UNTIL_OUTER_RECEIPT'}),file=sys.stderr,flush=True)
    except BaseException as secondary:
        data['secondary'].append({'type':type(secondary).__name__,'reason':str(secondary),'evidence':getattr(secondary,'diagnosticCustody',None)})
        error.workerFailurePersistence=data
        try:first_hash=hashlib.sha256(canonical(first).encode()).hexdigest()
        except BaseException:first_hash='UNKNOWN_NON_JSON_FIRST_EVIDENCE'
        # A failed diagnostic serializer must never replace the original error.
        small={'kind':'OUTER_WORKER_FIRST_FAILURE_PERSISTENCE_FAILED','firstType':first['type'],'firstMessage':first['message'][:32768],'firstEvidenceSHA256':first_hash,'secondary':[{'type':x['type'],'reason':x['reason'][:32768]}for x in data['secondary']],'readonlyObserverCapture':data['readonlyObserverCapture'],'readonlyObserverCaptureFailure':data['readonlyObserverCaptureFailure'],'reservationRetained':True}
        try:print(canonical(small),file=sys.stderr,flush=True)
        except BaseException as emit:error.workerFailureEmitFailure={'type':type(emit).__name__,'reason':str(emit),'UNKNOWN':True}



def readonly_observer_stream(value):
    if value is None:return None
    if type(value)is str:raw=value.encode()
    elif type(value)is bytes:raw=value
    else:return {'known':False,'type':type(value).__name__}
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw).decode()}



@contextmanager
def readonly_observer_phase(db, backend):
    """Keep report copies outside the native proof and exception contract."""
    try:
        yield
    except BaseException as error:
        if getattr(backend, 'observer_first_failure', None) is None:
            backend.observer_first_failure = getattr(error, 'readonlyObserverFailure', {
                'type': type(error).__name__, 'reason': str(error),
                'evidence': getattr(error, 'evidence', None),
            })
        raise
    finally:
        backend.observer_captures = []
        backend.observer_capture_receipt = None



@contextmanager
def readonly_observer_transaction(root, db, backend):
    """Keep report copies outside the native proof and exception contract."""
    try:
        yield
    except BaseException as error:
        if getattr(backend, 'observer_first_failure', None) is None:
            backend.observer_first_failure = getattr(error, 'readonlyObserverFailure', {
                'type': type(error).__name__, 'reason': str(error),
                'evidence': getattr(error, 'evidence', None),
            })
        raise
    finally:
        backend.observer_captures = []
        backend.observer_capture_receipt = None

             # Original primary exception/traceback resumes; no finally masking.


def worker(root, db, cfg, reconcile_failed_libvirt=None, _backend=None):
    with (root / "worker.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("This queue already has a dispatcher")
        # All heavy work still enters through heavy.sh. That single lock protects
        # old, unmanaged workloads; this dispatcher runs its own jobs concurrently.
        require(os.environ.get("OPEMOS_QUEUE_HEAVY_ENTRY") == "1", "Use queue.sh run (heavy.sh entry)")
        # heavy.sh keeps the lock in the parent systemd-run process. Its FD is not
        # guaranteed to be inherited across scope execution; verify it is held.
        heavy_lock = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "opemos-heavy.lock"
        with heavy_lock.open("a") as held:
            try:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise ValueError("Legacy heavy lock is not held; use queue.sh run")
        try:
            backend = SystemdBackend(root, cfg) if _backend is None else _backend
            if reconcile_failed_libvirt is not None:
                with readonly_observer_transaction(root,db,backend):
                    result=reconcile_failed_libvirt_submission(root,db,backend,reconcile_failed_libvirt)
                print(canonical(result),flush=True)
                return 1  # the actual submitted job failed; reconciliation is not a pass
            monitor_first=None;monitor_count=0
            diagnostic_only = bool(DIAGNOSTIC_TERMINAL_INPUTS)
            while True:
                with readonly_observer_transaction(root,db,backend):
                    try:tick(root, db, backend, cfg)
                    except PoolAdmissionFailure as error:
                        diagnostic={'firstFailure':getattr(error,'evidence',None),'reservationRetained':True,'operationOrReleaseAuthorized':False}
                        try:observation=monitor_admitted_libvirt(db,backend,error)if error.evidence.get('kind')=='ADMITTED_LIBVIRT_OBSERVATION_UNAVAILABLE'else monitor_membership_race(db,backend,error)
                        except BaseException as classification:
                            classification.evidence={'kind':'MONITOR_DISPOSITION_REFUSED','originalMonitorFrame':diagnostic,'classificationFailure':{'type':type(classification).__name__,'reason':str(classification)},'reservationRetained':True,'operationOrReleaseAuthorized':False}
                            try:persist_monitor_failure(root,classification)
                            except Exception as secondary:classification.optionalWorkerFailureReport={'type':type(secondary).__name__,'reason':str(secondary)}
                            raise
                        monitor_count+=1
                        if monitor_first is None:
                            monitor_first=observation;encoded=canonical(observation)
                            try:
                                if len(encoded.encode())<=1048576:print(encoded,file=sys.stderr,flush=True)
                            except OSError:pass
                        elif monitor_count%10==0:
                            try:print(canonical({'knownInvocationMonitorCount':monitor_count,'reservationRetained':True,'effectsReleaseForbidden':True}),file=sys.stderr,flush=True)
                            except OSError:pass
                        time.sleep(1);continue
                    rows = db.execute("SELECT state FROM jobs").fetchall()
                    if diagnostic_only:
                        require(not DIAGNOSTIC_TERMINAL_INPUTS and all(r[0] in TERMINAL for r in rows), "Diagnostic-only worker may not dispatch or reconcile other work")
                        return 1
                    if all(r[0] in TERMINAL for r in rows):
                        return 0 if all(r[0] == "passed" for r in rows) else 1
                    leased = db.execute("SELECT * FROM jobs WHERE state='running'").fetchall()
                    if leased and all(r["result"] and json.loads(r["result"]).get("reason", "").startswith("Unit evidence missing") for r in leased):
                        # Pending jobs that fit have been launched by tick; if only unknown
                        # closures remain, retain leases on disk for explicit owner review.
                        return 2
                    time.sleep(1)
        except BaseException as error:
            try:persist_outer_worker_failure(root,error,lock)
            except Exception as report_error:error.optionalWorkerFailureReport={'type':type(report_error).__name__,'reason':str(report_error)}
            raise


def collected_bundle(spec,binding,context,terminal,start,result,streamPins,originals,pool):
    require(binding['job_id']==spec['id']and binding['specSHA256']==hashlib.sha256(canonical(spec).encode()).hexdigest(),'exact immutable collected spec/binding')
    require({k:context['permitPin'][k]for k in('path','bytes','sha256')}==spec['approval']and context['grant']['jobId']==spec['id']and context['RootEntryProof']['systemd']['InvocationID']==binding['invocation'],'protected Root permit/job/invocation')
    require(terminal['jobId']==spec['id']and terminal['immutableQueuePermitPin']==spec['approval']and terminal['rootEntryContextPin']['sha256']==context['_resolvedPin']['sha256'],'full protected context/qualification binding')
    require(terminal['qualified']is True and terminal['busy']is False and terminal['resources']==[]and terminal['guestAttempts']==0 and terminal['VMOrCompilerStarted']is False and terminal['sourceWritten']is False,'only positive Root readonly qualification')
    require(all(terminal[k]is True for k in ('allControllerDescriptorsClosed','allNativeOriginalsGone','originalBaseFullHashBeforeAfterSame','originalBaseIdentityBeforeAfterSame','originalSourceTerminalStable')),'complete Root source/native closure')
    require(set(terminal['guestToolRequests']['tools'])=={'losetup','mkfs.ext4','mount','poweroff','python3','tar','umount','unshare'},'exact eight roles')
    require(type(start['pid'])is int and type(start['startTicks'])is int and start['pid']>0 and start['startTicks']>0 and result['childPID']==start['pid']and type(result['childNumericExit'])is int and result['childNumericExit']==0 and result['childReaped']is True and result['pipeEOF']is True and result['outputLimit']is False,'actual numeric parent/EOF/not limit')
    require(result['stdoutBytes']==streamPins['stdout']['bytes']and result['stderrBytes']==streamPins['stderr']['bytes'],'whole raw stream pins/counts')
    expected={(n['pid'],n['start'])for n in terminal['native']};expected.add((start['pid'],start['startTicks']));require(expected<={(n['pid'],n['start'])for n in originals}and all(n['originalAbsent']is True for n in originals),'all exact PID-start origins independently gone')
    require(pool['includesUID0']is True and pool['completeBoundedTraversal']is True and pool['admitted']is True and pool['allOwnedDescriptorsClosed']is True and pool['tasks']==[]and pool['lastKernelWholePoolPopulated']=='0','fresh full whole UID0 closure required')
    return {'state':'passed','jobId':spec['id'],'unit':binding['unit'],'invocation':binding['invocation'],'childPID':start['pid'],'childStartTicks':start['startTicks'],'childNumericExit':0,'fullRawPins':streamPins,'qualified':True,'notVMCompilerAdmission':True}

def collected_read(pin,uid,mode=None,parseData=True):
    import stat
    path=Path(pin['path']);require(path.is_absolute()and path.resolve(strict=True)==path and not any(x.is_symlink()for x in [path,*path.parents]),'full metadata path no aliases')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd);fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');require({k:getattr(st,k)for k in fields}==pin['identity']and st.st_uid==st.st_gid==uid and stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_size<=8*1024**2,'exact full held Root/logger identity/type/cap')
        if mode is not None:require(stat.S_IMODE(st.st_mode)==mode,'exact protected metadata mode')
        raw=bytearray()
        while True:
            b=os.read(fd,65536)
            if not b:break
            raw.extend(b);require(len(raw)<=8*1024**2,'complete metadata cap')
        require(len(raw)==pin['bytes']and hashlib.sha256(raw).hexdigest()==pin['sha256']and all(getattr(st,k)==getattr(os.fstat(fd),k)==getattr(os.lstat(path),k)for k in fields),'full metadata bytes/hash/custody')
        def unique(pairs):
            out={}
            for k,v in pairs:require(k not in out,'duplicate metadata field');out[k]=v
            return out
        return json.loads(raw,object_pairs_hook=unique)if parseData else bytes(raw)
    finally:os.close(fd)

def probe_collected_inputs(pins,spec):
    require(type(pins)is dict and set(pins)=={'owner','ownership','request','programs'},'closed genuine-probe input fields')
    owner=collected_read(pins['owner'],0,0o600);ownership=collected_read(pins['ownership'],0);request=collected_read(pins['request'],0,0o600)
    require(type(pins['programs'])is list and len(pins['programs'])==20 and [{k:p[k]for k in('path','bytes','sha256')}for p in pins['programs']]==spec['files'],'full current18program20input source set')
    for p in pins['programs']:collected_read(p,0,0o444,False)
    return {'owner':owner,'ownership':ownership,'request':request,'requestPin':pins['request'],'programs':pins['programs']}

def probe_collected_bundle(spec,binding,context,terminal,start,result,streamPins,originals,pool,extra):
    g=context['grant'];root=context['RootEntryProof'];minimal=lambda p:{k:p[k]for k in('path','bytes','sha256')}
    require(binding['job_id']==spec['id']and binding['unit']==root['systemd']['unit']and binding['invocation']==root['systemd']['InvocationID']and binding['specSHA256']==hashlib.sha256(canonical(spec).encode()).hexdigest(),'exact genuine-probe original spec/unit/invocation')
    require(minimal(context['permitPin'])==spec['approval']and g['jobId']==spec['id']and root['queue']['spec']==dict(spec,approval=spec['approval']),'exact probe protected context/full normalized spec')
    require(root['own']['uids']==[0]*4 and root['own']['argv']==spec['command'][4:]and root['own']['cgroup']=='/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/'+binding['unit']and root['own']['pid']>0 and root['own']['start']>0,'same actual Root original/source/argv/cgroup')
    require(terminal['jobId']==spec['id']and type(terminal['guestAttempts'])is int and terminal['guestAttempts']==1 and terminal['measurementAccepted']is True and terminal['buildAdmissionAccepted']is False and terminal['projectMustStopForPipe']is True,'genuine measured guest1, explicitly blocked build')
    require(terminal['busy']is False and terminal['resources']==[]and terminal['sourceWritten']is False and terminal['allControllerDescriptorsClosed']is True and terminal['allNativeCapturesClosed']is True and terminal['allOwnedNativeIdentitiesAbsent']is True and terminal['originalBaseFullHashBeforeAfterSame']is True,'complete real probe source/native/FD closure')
    owner=extra['owner'];require(owner['jobId']==spec['id']and owner['approvalPin']==spec['approval']and owner['instance']==terminal['instance']==g['instance']and g['outputStage']in spec['resources'],'exact probe lane/owner/current instance')
    require(extra['ownership']['admitted']is True and extra['ownership']['overlap']is False and extra['ownership']['foreignHelpers']==[]and extra['ownership']['lane']==g['outputStage']and extra['ownership']['hostBootId']==g['hostBootId']==root['bootId'],'exact source/lane holder admission')
    request=extra['request'];require(request['jobId']==spec['id']and request['instance']==g['instance']and request['intendedBuildInstance']==terminal['intendedBuildInstance']and request['requestId']==terminal['observation']['requestId']and request['sourceBasePin']==g['sources'][0]['pin']and extra['requestPin']['bytes']==terminal['requestPin']['bytes']and extra['requestPin']['sha256']==terminal['requestPin']['sha256'],'whole request/source/hash binding')
    obs=terminal['observation'];require(obs['jobId']==spec['id']and obs['measurementComplete']is True and obs['failure']is None and obs['uid']==0 and obs['allObservationReadDescriptorsClosed']is True and obs['projectCodeOrCompilerExecuted']is False and obs['kernelConfigurationWritten']is False and obs['corePatternAcceptedForBuild']is False and obs['projectMustStopForPipe']is True and obs['originalPatternStable']is True,'authentic observed pipe, no project admission')
    require(obs['originalCorePatternBefore']==obs['originalCorePatternAfter']==terminal['observedPattern']and terminal['observedPattern']['piped']is True,'complete exact stable original pipe bytes')
    require(set(obs['tools'])=={'losetup','mkfs.ext4','mount','poweroff','python3','tar','umount','unshare'}and terminal['readback']['allReaderDescriptorsClosed']is True and terminal['readback']['allRecordedChildrenReaped']is True,'all8tools/stopped readback')
    logger=start['loggerProvenance'];require(logger==result['loggerProvenance']and logger['jobId']==spec['id']and logger['command']==spec['command']and logger['invocation']==binding['invocation']and logger['cgroup']=='0::'+root['own']['cgroup']+'\n'and logger['uid']==logger['euid']==1000 and start['parentPID']==logger['pid']and root['own']['ppid']==start['pid']and root['own']['start']==start['startTicks'],'whole logger/sudo/Root parent and exact original start')
    require(type(result['childNumericExit'])is int and result['childNumericExit']==0 and result['childPID']==start['pid']and result['childReaped']is True and result['pipeEOF']is True and result['outputLimit']is False and result['stdoutBytes']==streamPins['stdout']['bytes']and result['stderrBytes']==streamPins['stderr']['bytes'],'numeric logger0/full raw EOF sizes')
    captures=terminal['allNativeCaptures'];expected={(root['own']['pid'],root['own']['start']),(start['pid'],start['startTicks']),(logger['pid'],logger['startTicks'])}
    for capture in captures:
        require(capture['numericExit']==0 and capture['parentReaped']is True and capture['stdoutEOF']is True and capture['stderrEOF']is True and capture['logDescriptorsClosed']is True and capture['streamDescriptorsClosed']is True and capture['allGateDescriptorsClosed']is True,'each original capture numeric/EOF/FD')
        early=capture['earlyProcess'];require(early['ppid']==root['own']['pid']and capture['gateEvidence']['READY']['uids']==[0]*4 and capture['gateEvidence']['READY']['cgroup']=='0::'+root['own']['cgroup'],'same Root native credential/cgroup');expected.add((early['pid'],early['start']))
    require(terminal['qemu']['numericExit']==0 and terminal['qemu']['failure']is None,'actual QEMU0 not inferred from agent state')
    require(pool.get('sourceAndLaneHolders')==[]and pool.get('sourcePinsRevalidated')==[x['pin']for x in g['sources']],'fresh Root source/lane custody and no holders')
    require(expected<={(n['pid'],n['start'])for n in originals}and all(n['originalAbsent']is True for n in originals),'all recorded real49 PID-start closures')
    require(pool['includesUID0']is True and pool['completeBoundedTraversal']is True and pool['admitted']is True and pool['allOwnedDescriptorsClosed']is True and pool['tasks']==[]and pool['lastKernelWholePoolPopulated']=='0','fresh complete Root whole-pool closure')
    return {'state':'passed','terminalType':'ACTUAL_GUEST_READONLY_OPERANDS_PROBE','jobId':spec['id'],'unit':binding['unit'],'invocation':binding['invocation'],'childPID':start['pid'],'childStartTicks':start['startTicks'],'childNumericExit':0,'fullRawPins':streamPins,'measurementAccepted':True,'guestAttempts':1,'projectMustStopForPipe':True,'buildAdmissionAccepted':False,'noAdditionalVMOrCompilerAdmission':True}

def typed_collected_bundle(spec,binding,context,terminal,start,result,streams,originals,pool,pins):
    if terminal.get('guestAttempts')==1:
        require('probe'in pins,'explicit genuine probe protected input set required');extra=probe_collected_inputs(pins['probe'],spec)
        return probe_collected_bundle(spec,binding,context,terminal,start,result,streams,originals,pool,extra)
    require('probe'not in pins,'qualification protocol unchanged');return collected_bundle(spec,binding,context,terminal,start,result,streams,originals,pool)

def root_collected_receipt(row,binding,pins,originals,pool,ledger,producerPin):
    require(os.getuid()==os.geteuid()==0,'actual Root producer required')
    spec=json.loads(row['spec']);require(set(pins)in({'context','terminal','start','result','stdout','stderr'},{'context','terminal','start','result','stdout','stderr','probe'}),'closed complete input set')
    context=collected_read(pins['context'],0,0o400);context['_resolvedPin']=pins['context'];terminal=collected_read(pins['terminal'],0,0o600);start=collected_read(pins['start'],1000,0o600);result=collected_read(pins['result'],1000,0o600)
    # Raw streams are held/full-hash verified by caller's existing Root bounded reader;
    # exact complete stream pins are rechecked here without parsing raw bytes as JSON.
    for name in ('stdout','stderr'):require(len(collected_read(pins[name],1000,0o600,False))==pins[name]['bytes'],'actual complete logger raw pin')
    decision=typed_collected_bundle(spec,binding,context,terminal,start,result,{k:pins[k]for k in('stdout','stderr')},originals,pool,pins)
    issued=time.time()
    return {'kind':'ROOT_BOUND_COLLECTED_QUALIFICATION_TERMINAL','issuedUnix':issued,'expiresUnix':issued+30,'producerPin':producerPin,'jobId':row['id'],'row':dict(row),'binding':binding,'ledger':ledger,'pins':pins,'originals':originals,'pool':pool,'decision':decision,'RootUID':0,'currentBootId':context['RootEntryProof']['bootId']}

def finish_collected(db,backend,row,receiptPin,authorityPin):
    receipt=collected_read(receiptPin,0,0o400);authority=collected_read(authorityPin,0,0o400);require(authority['kind']=='EXACT_COLLECTED_TERMINAL_ROOT_APPROVAL'and authority['runtimeAuthorized']is True and authority['jobId']==row['id']and authority['receiptPin']==receiptPin,'separate exact Root activation required')
    require(receipt['kind']=='ROOT_BOUND_COLLECTED_QUALIFICATION_TERMINAL'and receipt['RootUID']==0 and receipt['producerPin']==authority['producerPin']and receipt['jobId']==row['id']and receipt['issuedUnix']<=time.time()<receipt['expiresUnix']<=receipt['issuedUnix']+30,'fresh exact protected Root terminal source')
    check_inputs(json.loads(row['spec']));before=[dict(x)for x in db.execute('SELECT * FROM jobs ORDER BY rowid')];bindings=[list(x)for x in db.execute('SELECT job_id,value FROM pool_unit_bindings ORDER BY job_id')];cfg=[list(x)for x in db.execute('SELECT * FROM config ORDER BY id')];require(before==receipt['ledger']['rows']and bindings==receipt['ledger']['bindings']and cfg==receipt['ledger']['config'],'all ten rows/six bindings/config exact')
    binding=json.loads(next(x[1]for x in bindings if x[0]==row['id']));require(row['state']=='running'and receipt['binding']==binding and binding['unit']==row['unit'],'same running collected original lease')
    ctx=ExpectedInvocation(backend,db,dict(row,_poolBinding=binding));ctx.ledger_current()
    # Re-resolve every durable input; receipt booleans or manager absence cannot supply success.
    pins=receipt['pins'];[collected_read(pins[n],1000,0o600,False)for n in('stdout','stderr')];context=collected_read(pins['context'],0,0o400);context['_resolvedPin']=pins['context'];terminal=collected_read(pins['terminal'],0,0o600);start=collected_read(pins['start'],1000,0o600);result=collected_read(pins['result'],1000,0o600)
    with immutable_ledger_transaction(db):
        ctx.ledger_current();rows,pool=boundary_pool_epoch(db,backend);props=exact_unit_observation(backend,row['unit']);require(props['LoadState']=='not-found'and props['MainPID']=='0'and props['InvocationID']=='','collected original must remain absent')
        require(pool['currentWholePoolEmpty']is True,'whole pool empty before collected release');decision=typed_collected_bundle(json.loads(row['spec']),binding,context,terminal,start,result,{k:pins[k]for k in('stdout','stderr')},receipt['originals'],pool,pins);require(decision==receipt['decision'],'same complete Root decision')
        require([dict(x)for x in db.execute('SELECT * FROM jobs ORDER BY rowid')]==before and [list(x)for x in db.execute('SELECT job_id,value FROM pool_unit_bindings ORDER BY job_id')]==bindings and [list(x)for x in db.execute('SELECT * FROM config ORDER BY id')]==cfg,'final complete immutable ledger equality')
        recent_boundary(pool,time.monotonic());db.execute("UPDATE jobs SET state='passed',finished=?,result=? WHERE id=? AND state='running'",(time.time(),canonical({'collectedRootReceiptPin':receiptPin,'decision':decision}),row['id']));require(db.execute('SELECT changes()').fetchone()[0]==1,'exact sole legal terminal transition')
        after=[dict(x)for x in db.execute('SELECT * FROM jobs ORDER BY rowid')];require(len(after)==len(before)and all(a==b for a,b in zip(after,before)if b['id']!=row['id']),'no historical row changed');require([list(x)for x in db.execute('SELECT job_id,value FROM pool_unit_bindings ORDER BY job_id')]==bindings and [list(x)for x in db.execute('SELECT * FROM config ORDER BY id')]==cfg,'bindings/config unchanged at commit')
    return decision

COLLECTED_TERMINAL_INPUTS={}

COLLECTED_FAILED_ROOT_SOURCE = '"""Finite readonly authenticated original-report/current-lease resolver.\n\nNo manager operation, original SQL, lease write, signal or device open.\nThe caller authenticates the entire source string and supplies exact full pins.\n"""\nimport os,sys,json,stat,hashlib,time,threading,base64,zlib\nfrom pathlib import Path\nFIELDS=(\'st_dev\',\'st_ino\',\'st_mode\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\')\ndef need(v,m):\n    if not v:raise ValueError(m)\ndef ident(s):return {k:getattr(s,k)for k in FIELDS}\ndef readpin(pin,rawBytes=False):\n    path=Path(pin[\'path\']);need(path.is_absolute() and \'..\' not in path.parts,\'exact absolute protected input\')\n    fds=[];rows=[];first=None;raw=None\n    try:\n        fd=os.open(\'/\',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd)\n        rootid=ident(os.fstat(fd));need(rootid==ident(os.lstat(\'/\')) and rootid[\'st_uid\']==rootid[\'st_gid\']==0,\'held canonical root\')\n        rows.append((fd,None,None,rootid))\n        for name in path.parts[1:-1]:\n            parent=fd;fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);fds.append(fd)\n            a=ident(os.fstat(fd));need(a==ident(os.stat(name,dir_fd=parent,follow_symlinks=False)) and a[\'st_uid\']==a[\'st_gid\']==0 and not(a[\'st_mode\']&0o022),\'protected nofollow report ancestry\')\n            rows.append((fd,parent,name,a))\n        parent=fd;fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);fds.append(fd)\n        a=ident(os.fstat(fd));need(a==pin[\'identity\'] and stat.S_ISREG(a[\'st_mode\']) and a[\'st_uid\']==a[\'st_gid\']==0 and stat.S_IMODE(a[\'st_mode\'])==0o400 and a[\'st_nlink\']==1 and 0<=a[\'st_size\']<=1048576,\'exact protected Root0400 full9/cap\')\n        raw=bytearray()\n        while b:=os.read(fd,65536):raw.extend(b);need(len(raw)<=1048576,\'full report cap\')\n        need(len(raw)==pin[\'bytes\'] and hashlib.sha256(raw).hexdigest()==pin[\'sha256\'] and a==ident(os.fstat(fd))==ident(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),\'complete Root report hash/full9/EOF\')\n        for held,p,n,a in reversed(rows):\n            need(ident(os.fstat(held))==a and (ident(os.lstat(\'/\'))==a if p is None else ident(os.stat(n,dir_fd=p,follow_symlinks=False))==a),\'held/named ancestor unchanged\')\n    except BaseException as e:first=e\n    finally:\n        closes=[]\n        for fd in reversed(fds):\n            try:os.close(fd)\n            except BaseException as e:closes.append(repr(e))\n        if closes:raise ValueError({\'first\':repr(first),\'closeFailures\':closes,\'closure\':\'UNKNOWN\'}) from first\n    if first is not None:raise first\n    return bytes(raw) if rawBytes else json.loads(raw)\ndef resolve_r45(request,binding,statepin,stateRoot):\n    started=time.monotonic();before=set(os.listdir(\'/proc/self/fd\'))\n    need(set(binding)=={\'kind\',\'request\',\'reportPin\',\'closurePin\',\'statePin\'} and binding[\'kind\']==\'EXACT_R45_FAILED_ACTIVE_COLLECTED_ORIGIN\' and binding[\'request\']==request and binding[\'statePin\']==statepin,\'exact enrolled R45 original request/current state pins\')\n    state=readpin(statepin);complete=readpin(binding[\'closurePin\'])\n    need(complete[\'request\']==request and complete[\'nextState\']==statepin and complete[\'nativeFirstFailureUnchanged\']is True and complete[\'queueRowNotModified\']is True and complete[\'queueReservationRequiresCanonicalTerminal\']is True and complete[\'historicalQMPClosed\']is None,\'protected complete R45 append-only current disposition\')\n    closure=readpin(complete[\'currentDispositionProof\'])\n    need(state[\'backend\']==\'libvirt\' and state[\'jobID\']==request[\'jobId\'] and state[\'nonce\']==request[\'leaseNonce\'] and state[\'currentBoot\']==Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip() and state[\'closed\']is True and state[\'restored\']is True and state[\'changed\']==[] and state[\'currentDisposition\']==closure and state[\'currentDispositionProofPin\']==complete[\'currentDispositionProof\'],\'exact full protected R45 CLOSED state and complete proof equality\')\n    need(closure[\'request\']==request and closure[\'currentBoot\']==state[\'currentBoot\'] and closure[\'unknown\']==[] and all(closure[k]is True for k in (\'known\',\'domainAbsent\',\'originalPIDStartAbsent\',\'cgroupEmpty\',\'VFIOFDsAbsent\',\'hostRestored\',\'ACLRestored\',\'currentDispositionOnly\',\'noSignalOrRebind\',\'currentOriginalRootProcessGone\')) and closure[\'historicalQMPClosed\']is None and closure[\'qemuExitStatus\']is None and closure[\'controllerWaitpidClaimed\']is False,\'current R45 closure only; historical QMP/wait unknown preserved\')\n    current=complete[\'currentObserver\']\n    need(current[\'request\']==request and current[\'phase\']==\'CLOSED\' and current[\'scope\']is None and current[\'leader\']is None and current[\'lease\'][\'statePin\']==statepin and current[\'lease\'][\'closed\']is True and current[\'lease\'][\'restored\']is True and current[\'allOwnedDescriptorsClosed\']is True and current[\'effects\']==[],\'protected ordinary CLOSED R45 consumer agrees\')\n    m=closure[\'unitBeforeCollection\'];after=closure[\'unitAfterCollection\']\n    need(m[\'LoadState\']==\'loaded\' and m[\'ActiveState\']==\'failed\' and m[\'MainPID\']==\'0\' and m[\'InvocationID\']==request[\'invocation\'] and m[\'ExecMainStatus\']==\'1\' and m[\'ControlGroup\']==\'\' and after[\'LoadState\']==\'not-found\' and after[\'ActiveState\']==\'inactive\' and after[\'MainPID\']==\'0\' and after[\'InvocationID\']==after[\'ControlGroup\']==\'\',\'original numeric failed same invocation collected manager\')\n    refs=complete[\'records\'];need(len(refs)==4 and len({p[\'path\']for p in refs})==4 and refs[2]==complete[\'currentDispositionProof\'],\'exact bounded four protected closure records\')\n    collection=readpin(refs[1]);need(collection[\'before\']==m and collection[\'argv\']==[\'/usr/bin/systemctl\',\'reset-failed\',request[\'unit\']] and type(collection[\'numeric\'])is int and collection[\'numeric\']==0 and collection[\'stdout\']==collection[\'stderr\']==\'\' and collection[\'noSignal\']is True,\'exact retained numeric manager collection, no fabricated waiter proof\')\n    six=readpin(closure[\'sixACLClosurePin\']);need(six[\'closure\'][\'request\']==request and six[\'metadataLeaseUnchanged\']is True and six[\'queueReservationHeld\']is True and len(six[\'restored\'])==6 and len({r[\'path\']for r in six[\'restored\']})==6 and all(r[\'restored\']is True for r in six[\'restored\']),\'exact original six restored ACL receipt\')\n    packed=readpin(binding[\'reportPin\'],True);decoder=zlib.decompressobj(16+zlib.MAX_WBITS);raw=decoder.decompress(packed,1048577)\n    need(len(raw)<=1048576 and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,\'one whole protected R45 original gzip\')\n    report=json.loads(raw);need(report[\'scope\'][\'jobId\']==request[\'jobId\'] and report[\'scope\'][\'nonce\']==request[\'leaseNonce\'] and report[\'scope\'][\'hostBoot\']==state[\'currentBoot\'] and report[\'actor\'][\'uid\']==0 and all(type(report[\'actor\'][k])is int and report[\'actor\'][k]>0 for k in (\'pid\',\'start\')) and report[\'noOriginalSQLAPI\']is True and type(report[\'records\'])is list and len(report[\'records\'])<=128,\'original protected R45 Root report scope\')\n    bypath={}\n    for item in report[\'records\']:\n        if \'pin\'not in item:continue\n        p=item[\'pin\'];need(p[\'path\']not in bypath,\'unique protected original path\');b=base64.b64decode(item[\'rawBase64\'],validate=True)\n        need(len(b)==p[\'bytes\'] and hashlib.sha256(b).hexdigest()==p[\'sha256\'],\'original full raw SHA/count\');bypath[p[\'path\']]=(p,b)\n    tp=closure[\'nativeFirstFailurePin\'];need(tp[\'path\']in bypath and bypath[tp[\'path\']][0]==tp,\'protected original terminal full pin\')\n    terminal=json.loads(bypath[tp[\'path\']][1]);need(terminal[\'kind\']==\'STEAMOS_LIBVIRT_BOUND_QUEUE_TWO_BOOT_RESULT_R2\' and terminal[\'accepted\']is False and type(terminal[\'launches\'])is int and terminal[\'launches\']==1 and terminal[\'NVIDIAFunctionalDriverAccepted\']is False and terminal[\'packageInstalled\']is False and terminal[\'first\']==closure[\'nativeFirstFailure\'] and terminal[\'first\']is not None and terminal[\'secondary\']==closure[\'nativeSecondary\'],\'one genuine failed launch and complete original failure preserved\')\n    candidates=[(p,b)for p,b in bypath.values()if p[\'path\'].endswith(\'/029-domain-candidate-before-role.json\')];need(len(candidates)==1,\'exact one original R45 QEMU candidate\')\n    cp,cb=candidates[0];candidate=json.loads(cb);n=candidate[\'raw\'];pair={\'pid\':n[\'pid\'],\'start\':n[\'start\']}\n    need(candidate[\'nameMatch\']is True and candidate[\'uuidMatch\']is True and all(type(v)is int and v>0 for v in pair.values()) and n[\'tgid\']==pair[\'pid\'] and n[\'uids\']==[64055]*4 and \'-uuid\'in n[\'argv\'] and n[\'argv\'][n[\'argv\'].index(\'-uuid\')+1]==request[\'domainUUID\'] and any(a.startswith(\'guest=\'+request[\'domainName\']+\',\')for a in n[\'argv\']) and n[\'cgroup\'].startswith(\'/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/\'+request[\'vmSlice\']+\'/machine-\'),\'protected original QEMU identity/UUID/name/UID/partition\')\n    absent=six[\'closure\'][\'absentOriginalActors\'];need(len(absent)==2 and all(a[\'originalAbsent\']is True and (a[\'now\']is None or a[\'now\'][\'start\']!=a[\'old\'][\'start\'])for a in absent) and any(a[\'old\'][\'pid\']==pair[\'pid\'] and a[\'old\'][\'start\']==pair[\'start\']for a in absent),\'original QEMU identity matches protected absence receipt\')\n    try:\n        now=Path(\'/proc/\'+str(pair[\'pid\'])+\'/stat\').read_text().rsplit(\')\',1)[1].split();need(int(now[19])!=pair[\'start\'],\'original known R45 QEMU remains live\')\n    except(FileNotFoundError,ProcessLookupError):pass\n    logs={};base=stateRoot+\'/logs/\'+request[\'jobId\']+\'/\'\n    for name in (\'child-start.json\',\'child-result.json\',\'stdout.log\',\'stderr.log\'):\n        pin,b=bypath[base+name];a=pin[\'identity\'];need(a[\'st_uid\']==a[\'st_gid\']==1000 and a[\'st_nlink\']==1 and a[\'st_mode\']==0o100600 and a[\'st_size\']==pin[\'bytes\'],\'original UID1000 logger custody\');logs[name]=pin\n    need(before==set(os.listdir(\'/proc/self/fd\')) and threading.active_count()==1 and not Path(\'/proc/self/task/\'+str(os.getpid())+\'/children\').read_text() and time.monotonic()-started<15,\'finite R45 Root reader FD/thread/child closure\')\n    return {\'kind\':\'ROOT_EXACT_COLLECTED_LIBVIRT_FAILED_LOGGER\',\'request\':request,\'stateRoot\':stateRoot,\'originalReportPin\':binding,\'currentStatePin\':statepin,\'files\':logs,\'managerBefore\':m,\'managerAfter\':after,\'historicalQMPClosed\':None,\'historicalQemuPIDStart\':pair,\'originalCandidatePin\':cp,\'originalLaunchTerminal\':terminal,\'leaseClosed\':True,\'hostRestored\':True,\'RootUID\':0,\'actor\':{\'pid\':os.getpid(),\'start\':int(Path(\'/proc/self/stat\').read_text().rsplit(\')\',1)[1].split()[19])},\'bootID\':state[\'currentBoot\'],\'effects\':[],\'allOwnedDescriptorsClosed\':True,\'completedMonotonic\':time.monotonic()}\n\ndef resolve(request,reportpin,statepin,stateRoot):\n    started=time.monotonic();before=set(os.listdir(\'/proc/self/fd\'))\n    need(os.getuid()==os.geteuid()==0,\'genuine Root reader required\')\n    if request[\'jobId\']==\'steamos3828-libvirt-r45-fc9592bf2e69\':return resolve_r45(request,reportpin,statepin,stateRoot)\n    pausedPolicies={\'steamos3828-libvirt-r31-a5a3a4370069\':\'ROOT_R32_FINITE_EXACT_CURRENT_LIBVIRT_DISPOSITION\',\'steamos3828-libvirt-r36-0e93fa5090ee\':\'ROOT_R37_FINITE_EXACT_CURRENT_LIBVIRT_DISPOSITION\'}\n    paused=request[\'jobId\']in pausedPolicies\n    knownQemu=request[\'jobId\']==\'steamos3828-libvirt-r36-0e93fa5090ee\'\n    originalTerminal=None;historicalQemuPIDStart=None;originalCandidatePin=None\n    state=readpin(statepin)\n    if paused:\n        # Exact separately enrolled R31 gzip producer, not a missing-unit shortcut.\n        packed=readpin(reportpin,True);decoder=zlib.decompressobj(16+zlib.MAX_WBITS)\n        raw=decoder.decompress(packed,1048577)\n        need(len(raw)<=1048576 and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,\'one bounded whole protected gzip EOF\')\n        report=json.loads(raw);need(type(report)is dict and type(report.get(\'records\'))is list and len(report[\'records\'])<=128,\'exact R31 protected report schema\')\n        need(report[\'scope\'][\'jobId\']==request[\'jobId\'] and report[\'scope\'][\'nonce\']==request[\'leaseNonce\'] and report[\'scope\'][\'hostBoot\']==state[\'currentBoot\'] and report[\'actor\'][\'uid\']==0 and type(report[\'actor\'][\'pid\'])is int and report[\'actor\'][\'pid\']>0 and type(report[\'actor\'][\'start\'])is int and report[\'actor\'][\'start\']>0 and report[\'noOriginalSQLAPI\']is True,\'protected original R31 scope/Root actor\')\n        bypath={}\n        for item in report[\'records\']:\n            if \'pin\'not in item:continue\n            p=item[\'pin\'];need(p[\'path\']not in bypath,\'unique protected raw path\')\n            b=base64.b64decode(item[\'rawBase64\'],validate=True);need(len(b)==p[\'bytes\'] and hashlib.sha256(b).hexdigest()==p[\'sha256\'],\'whole protected original raw evidence\')\n            bypath[p[\'path\']]=(p,b)\n        disposition=state[\'currentDisposition\'];decision=readpin(disposition[\'decisionPin\'])\n        need(decision[\'kind\']==pausedPolicies[request[\'jobId\']] and decision[\'RootIssued\']is True and decision[\'metadataOnly\']is True and decision[\'runtimeAuthorized\']is False and decision[\'GPUAuthorized\']is False and decision[\'bootID\']==state[\'currentBoot\'] and decision[\'request\']==request and decision[\'terminalActualLaunches\']==1 and decision[\'historicalQMPClosed\']is None and (knownQemu or decision[\'historicalQemuPIDStart\']is None) and decision[\'noSysfsOrSignalOrDomainOrImageWrite\']is True,\'exact protected Root same-request current disposition decision\')\n        terminalPin=decision[\'terminalPin\'];need(terminalPin[\'path\']in bypath and bypath[terminalPin[\'path\']][0]==terminalPin,\'decision pins complete original failed launch terminal\')\n        originalTerminal=json.loads(bypath[terminalPin[\'path\']][1])\n        need(originalTerminal[\'kind\']==\'STEAMOS_LIBVIRT_BOUND_QUEUE_TWO_BOOT_RESULT_R2\' and originalTerminal[\'accepted\']is False and type(originalTerminal[\'launches\'])is int and originalTerminal[\'launches\']==1 and originalTerminal[\'NVIDIAFunctionalDriverAccepted\']is False and originalTerminal[\'packageInstalled\']is False and originalTerminal[\'first\']is not None,\'one original failed paused launch, never package/driver success\')\n        if knownQemu:\n            historicalQemuPIDStart=decision[\'historicalQemuPIDStart\']\n            need(type(historicalQemuPIDStart)is dict and set(historicalQemuPIDStart)=={\'pid\',\'start\'} and all(type(historicalQemuPIDStart[k])is int and historicalQemuPIDStart[k]>0 for k in (\'pid\',\'start\')),\'typed positive original QEMU identity retained\')\n            candidates=[(p,b)for p,b in bypath.values()if p[\'path\'].endswith(\'/031-FIRST-domain-candidate.json\')]\n            need(len(candidates)==1,\'one protected original failed candidate\')\n            originalCandidatePin,candidateRaw=candidates[0];candidate=json.loads(candidateRaw);native=candidate[\'candidate\']\n            need(candidate[\'request\']==request and candidate[\'noGuestResume\']is True and native[\'pid\']==native[\'tgid\']==historicalQemuPIDStart[\'pid\'] and native[\'start\']==historicalQemuPIDStart[\'start\'] and native[\'uids\']==[64055]*4 and \'-uuid\'in native[\'argv\'] and native[\'argv\'][native[\'argv\'].index(\'-uuid\')+1]==request[\'domainUUID\'] and any(x.startswith(\'guest=\'+request[\'domainName\']+\',\')for x in native[\'argv\']) and native[\'cgroup\'].startswith(\'/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/\'+request[\'vmSlice\']+\'/machine-\'),\'Root decision binds exact original paused QEMU candidate, never invocation projection\')\n            try:\n                now=Path(\'/proc/\'+str(historicalQemuPIDStart[\'pid\'])+\'/stat\').read_text().rsplit(\')\',1)[1].split();need(int(now[19])!=historicalQemuPIDStart[\'start\'],\'original known QEMU process remains live\')\n            except(FileNotFoundError,ProcessLookupError):pass\n        records=[];base=stateRoot+\'/logs/\'+request[\'jobId\']+\'/\'\n        for name in (\'child-start.json\',\'child-result.json\',\'stdout.log\',\'stderr.log\'):\n            p,b=bypath[base+name];records.extend([{\'kind\':\'JOB_LOG_META\',\'value\':dict(p,offset=0)},{\'kind\':\'JOB_LOG_RAW\',\'value\':{\'path\':p[\'path\'],\'offset\':0,\'base64\':base64.b64encode(b).decode()}}])\n    else:\n        records=readpin(reportpin)\n    need(type(records)is list and len(records)<=128,\'finite original full report\')\n    need(state[\'backend\']==\'libvirt\' and state[\'jobID\']==request[\'jobId\'] and state[\'nonce\']==request[\'leaseNonce\'] and state[\'currentBoot\']==Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip() and state[\'closed\']is True and state[\'restored\']is True,\'current exact closed/restored lease\')\n    d=state[\'currentDisposition\'];m=d[\'managerBefore\'];after=d[\'managerAfter\']\n    need((d[\'kind\']==\'CURRENT_INDEPENDENT_POST_PAUSED_LAUNCH_LIBVIRT_DISPOSITION\' and type(d[\'actualLaunchesRetained\'])is int and d[\'actualLaunchesRetained\']==1 and d[\'historicalQMPClosed\']is None and d[\'historicalQemuPIDStart\']==historicalQemuPIDStart if paused else d[\'kind\']==\'CURRENT_INDEPENDENT_ZERO_LAUNCH_LIBVIRT_DISPOSITION\' and type(d[\'actualLaunchesRetained\'])is int and d[\'actualLaunchesRetained\']==0) and d[\'cgroupEmpty\']is True and d[\'domainAbsent\']is True and d[\'VFIOFDsAbsent\']is True and d[\'originalPIDStartAbsent\']is True and d[\'hostRestored\']is True and d[\'unknown\']==[],\'exact independently reconciled closed disposition, not historical QMP inference\')\n    need(m[\'LoadState\']==\'loaded\' and m[\'ActiveState\']==\'failed\' and m[\'MainPID\']==\'0\' and m[\'InvocationID\']==request[\'invocation\'] and m[\'ControlGroup\']==\'\' and after[\'LoadState\']==\'not-found\' and after[\'MainPID\']==\'0\' and after[\'InvocationID\']==after[\'ControlGroup\']==\'\',\'protected same-invocation failed-to-collected manager record\')\n    event=d[\'exactUnitCollection\'];need(event[\'argv\']==[\'/usr/bin/systemctl\',\'reset-failed\',request[\'unit\']] and event[\'numeric\']==0 and event[\'reaped\']is True and event[\'originalAbsent\']is True and event[\'stdoutEOF\']is True and event[\'stderrEOF\']is True and event[\'stderr\']==\'\',\'exact collected unit operation retained closure\')\n    meta={};pieces={}\n    for record in records:\n        kind=record[\'kind\'];v=record[\'value\']\n        if kind==\'JOB_LOG_META\':need(v[\'path\']not in meta,\'unique original log metadata\');meta[v[\'path\']]=v\n        elif kind==\'JOB_LOG_RAW\':pieces.setdefault(v[\'path\'],[]).append(v)\n    need(type(stateRoot)is str and stateRoot.startswith(\'/\') and \'..\'not in Path(stateRoot).parts,\'exact original queue state-root\')\n    logs={};base=stateRoot+\'/logs/\'+request[\'jobId\']+\'/\'\n    for name in (\'child-start.json\',\'child-result.json\',\'stdout.log\',\'stderr.log\'):\n        path=base+name;pin=meta[path];need(pin[\'offset\']==0 and pin[\'identity\'][\'st_uid\']==pin[\'identity\'][\'st_gid\']==1000 and pin[\'identity\'][\'st_nlink\']==1 and pin[\'identity\'][\'st_mode\']==0o100600,\'original logger full custody\')\n        raw=bytearray()\n        for part in pieces[path]:need(part[\'offset\']==len(raw),\'complete ordered raw logger chunks\');raw.extend(base64.b64decode(part[\'base64\'],validate=True))\n        need(len(raw)==pin[\'bytes\'] and hashlib.sha256(raw).hexdigest()==pin[\'sha256\'],\'protected original complete logger bytes\')\n        logs[name]={k:pin[k]for k in (\'path\',\'identity\',\'bytes\',\'sha256\')}\n    if not paused:\n        end=next(x[\'value\']for x in records if x[\'kind\']==\'CLOSURE\');early=next(x[\'value\']for x in records if x[\'kind\']==\'EARLY\')\n        need(end[\'actor\']==early and end[\'FDSetRestored\']is True and end[\'children\']==\'\',\'original Root capture positively closed\')\n    need(before==set(os.listdir(\'/proc/self/fd\')) and threading.active_count()==1 and not Path(\'/proc/self/task/\'+str(os.getpid())+\'/children\').read_text(),\'Root reader full FD/thread/child closure\')\n    need(time.monotonic()-started<15,\'finite existing readonly supplement wall\')\n    return {\'kind\':\'ROOT_EXACT_COLLECTED_LIBVIRT_FAILED_LOGGER\',\'request\':request,\'stateRoot\':stateRoot,\'originalReportPin\':reportpin,\'currentStatePin\':statepin,\'files\':logs,\'managerBefore\':m,\'managerAfter\':after,\'historicalQMPClosed\':state.get(\'historicalQMPClosed\'),\'historicalQemuPIDStart\':historicalQemuPIDStart,\'originalCandidatePin\':originalCandidatePin,\'originalLaunchTerminal\':originalTerminal,\'leaseClosed\':True,\'hostRestored\':True,\'RootUID\':0,\'actor\':{\'pid\':os.getpid(),\'start\':int(Path(\'/proc/self/stat\').read_text().rsplit(\')\',1)[1].split()[19])},\'bootID\':Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip(),\'effects\':[],\'allOwnedDescriptorsClosed\':True,\'completedMonotonic\':time.monotonic()}\nif __name__==\'__main__\':\n    SOURCE_SHA=sys.argv[1];request=json.loads(sys.argv[2]);reportpin=json.loads(sys.argv[3]);statepin=json.loads(sys.argv[4])\n    value=resolve(request,reportpin,statepin,sys.argv[5]);value[\'sourceSHA256\']=SOURCE_SHA\n    print(json.dumps(value,sort_keys=True,separators=(\',\',\':\')))\n'
COLLECTED_FAILED_ROOT_SHA = '0b3827f64579421c01ac775600dd081b663186786caa7bac75255893df2cd044'
COLLECTED_LIBVIRT_FAILED_ORIGINS = {'steamos3828-libvirt-r21-2df01f34c7c1': {'bytes': 166948, 'identity': {'st_ctime_ns': 1792305280429645490, 'st_dev': 28, 'st_gid': 0, 'st_ino': 13740, 'st_mode': 33024, 'st_mtime_ns': 1792305280429645490, 'st_nlink': 1, 'st_size': 166948, 'st_uid': 0}, 'path': '/run/opemos-libvirt-r22-runtime-metadata-2df01f34c7c1461c8b810b05e02b4dad/runtime-postflight-full.json', 'sha256': '551b56c9ee3eb2738092539b00c330693fffc0e9300581abc303413b5f0dd1e0'}, 'steamos3828-libvirt-r31-a5a3a4370069': {'bytes': 73451, 'identity': {'st_ctime_ns': 1792317625344947841, 'st_dev': 28, 'st_gid': 0, 'st_ino': 15469, 'st_mode': 33024, 'st_mtime_ns': 1792317625344947841, 'st_nlink': 1, 'st_size': 73451, 'st_uid': 0}, 'path': '/run/opemos-libvirt-r31-metadata-a5a3a4370069428793527176d45a2a9f/postflight-first-runtime-full.gz', 'sha256': '507a729f132df1a77b312b42a7e3dd8cebfa930ebf829ca70537da71fb4f43a5'}, 'steamos3828-libvirt-r36-0e93fa5090ee': {'bytes': 96284, 'identity': {'st_ctime_ns': 1792326170972697321, 'st_dev': 28, 'st_gid': 0, 'st_ino': 16733, 'st_mode': 33024, 'st_mtime_ns': 1792326170972697321, 'st_nlink': 1, 'st_size': 96284, 'st_uid': 0}, 'path': '/run/opemos-libvirt-r36-metadata-0e93fa5090ee4ccba04db08fac7cf61c/postflight-first-runtime-full.gz', 'sha256': 'b63ef22641fa45b3c533af8b88155977a5e7a1c3e047b289342954b33104657d'}, 'steamos3828-libvirt-r45-fc9592bf2e69': {'kind': 'EXACT_R45_FAILED_ACTIVE_COLLECTED_ORIGIN', 'request': {'controllerMemory': 2147483648, 'cpus': [0, 1, 2, 3], 'domainMemory': 8589934592, 'domainName': 'opemos-libvirt-fc9592bf2e69481f8fc04ca35c0e83d1', 'domainUUID': '64f43b0c-9a98-494d-adc1-0782aea1d32e', 'gpuGroup': 'omen-iommu-group-1', 'invocation': 'c0e88b5df2cc4da8936bb3eb36c042cc', 'jobId': 'steamos3828-libvirt-r45-fc9592bf2e69', 'jobToken': '7731ad7305dc42c18b7aa97a92607f71', 'leaseNonce': 'fc9592bf2e69481f8fc04ca35c0e83d1', 'observer': {'bytes': 39195, 'path': '/run/opemos-libvirt-public-source-fc9592bf2e69481f8fc04ca35c0e83d1/libvirt_peer.py', 'sha256': 'ddeb1e163152fae54ea4446083c58f4f96d582ff65983a960187cacb5f32afb7'}, 'partition': '/opemos/vm/pool/libvirt7731ad7305dc42c18b7aa97a92607f71', 'reservationMemory': 10737418240, 'specSHA256': '640821a5456c1187477607c22366ae4d1e2e069d7aa14c802c3b62e73e9e16e9', 'unit': 'opemos-testq-3b4eb7b4288f-7731ad7305dc42c18b7aa97a92607f71.service', 'vmSlice': 'opemos-vm-pool-libvirt7731ad7305dc42c18b7aa97a92607f71.slice'}, 'reportPin': {'bytes': 99471, 'identity': {'st_ctime_ns': 1792341309898474471, 'st_dev': 28, 'st_gid': 0, 'st_ino': 18545, 'st_mode': 33024, 'st_mtime_ns': 1792341309898474471, 'st_nlink': 1, 'st_size': 99471, 'st_uid': 0}, 'path': '/run/opemos-libvirt-r45-metadata-fc9592bf2e69481f8fc04ca35c0e83d1/postflight-terminal-runtime-full.gz', 'sha256': 'b7f9eafc598d8c942e7177e529a29e66694bd386bf02b4c8c71284414ba102b1'}, 'closurePin': {'bytes': 7956, 'identity': {'st_ctime_ns': 1792342169842319441, 'st_dev': 28, 'st_gid': 0, 'st_ino': 18768, 'st_mode': 33024, 'st_mtime_ns': 1792342169842319441, 'st_nlink': 1, 'st_size': 7956, 'st_uid': 0}, 'path': '/run/opemos-libvirt-r45-close-fc9592bf2e69481f8fc04ca35c0e83d1/close-04-complete.json', 'sha256': '6585e1e33d8a792a1c079369ddd96d42145c4835f768e479648005ffb5ee17a6'}, 'statePin': {'bytes': 10868, 'identity': {'st_ctime_ns': 1792342169817441674, 'st_dev': 28, 'st_gid': 0, 'st_ino': 18762, 'st_mode': 33024, 'st_mtime_ns': 1792342169817441674, 'st_nlink': 1, 'st_size': 10868, 'st_uid': 0}, 'path': '/run/opemos-vfio-fc9592bf2e69481f8fc04ca35c0e83d1/state-2.json', 'sha256': 'fd4ac2b5b77d78ab2a3082f8f5a361d0bb544e33352de77298c79e1fa1dfb3b1'}}}

def collected_libvirt_failed_root(request, observed, stateRoot):
    require(request['jobId'] in COLLECTED_LIBVIRT_FAILED_ORIGINS,
            'No protected original report enrolled for this collected job')
    reportpin=COLLECTED_LIBVIRT_FAILED_ORIGINS[request['jobId']]
    require(observed['request']==request and observed['phase']=='CLOSED' and
            observed['lease']['closed']is True and observed['lease']['restored']is True,
            'Current exact CLOSED/restored observer required')
    source=COLLECTED_FAILED_ROOT_SOURCE;digest=hashlib.sha256(source.encode()).hexdigest()
    require(digest==COLLECTED_FAILED_ROOT_SHA,'Exact authenticated collected Root source')
    statepin=observed['lease']['statePin'];started=time.monotonic()
    proc=subprocess.run(['sudo','-n','/usr/bin/python3','-B','-c',source,digest,
                         canonical(request),canonical(reportpin),canonical(statepin),stateRoot],
                        capture_output=True,text=True,timeout=15)
    require(proc.returncode==0 and proc.stderr=='' and 0<len(proc.stdout.encode())<=65536,
            'Closed bounded authenticated Root original/lease reader')
    value=json.loads(proc.stdout)
    require(proc.stdout==canonical(value)+'\n' and
            value['kind']=='ROOT_EXACT_COLLECTED_LIBVIRT_FAILED_LOGGER' and
            value['sourceSHA256']==digest and value['request']==request and value['stateRoot']==stateRoot and
            value['originalReportPin']==reportpin and value['currentStatePin']==statepin and
            value['RootUID']==0 and value['bootID']==Path('/proc/sys/kernel/random/boot_id').read_text().strip() and value['effects']==[] and value['allOwnedDescriptorsClosed']is True,
            'Exact Root response source/request/pins/closure')
    require(started<=value['completedMonotonic']<=time.monotonic() and
            time.monotonic()-value['completedMonotonic']<1,
            'Same-host current Root original/lease response')
    diagnostic_originals([(value['actor']['pid'],value['actor']['start'])])
    return value


def collected_libvirt_failed_absent(props):
    return (props.get('LoadState')=='not-found' and props.get('MainPID')=='0' and
            props.get('InvocationID')==props.get('ControlGroup')=='' and
            props.get('ActiveState')=='inactive')


def collected_libvirt_failed_pool(pool,row,request):
    require(all(pool.get(k)is True for k in ('admitted','includesUID0',
            'completeBoundedTraversal','allOwnedDescriptorsClosed','currentWholePoolEmpty')) and
            pool['tasks']==[] and pool['lastKernelWholePoolPopulated']=='0' and
            pool['canonicalPool']=='/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice',
            'Complete empty UID0 canonical pool for collected failure')
    require(pool['unknownReservationsRetained']==[row['unit']] and
            set(pool['unitProperties'])=={row['unit']} and
            pool['unitProperties'][row['unit']]['known']is False and
            collected_libvirt_failed_absent(pool['unitProperties'][row['unit']]['properties']),
            'Only exact owned collected reservation may be unknown')
    domains=pool['libvirtDomains']
    require(len(domains)==1 and domains[0]['request']==request and
            domains[0]['phase']=='CLOSED' and domains[0]['scope']is None and
            domains[0]['leader']is None and domains[0]['lease']['closed']is True and
            domains[0]['lease']['restored']is True,
            'Current original domain/physical lease closure, not missing-unit inference')


def finish_collected_libvirt_failed(db,backend,row):
    # Failed-only, exact enrolled original Root capture. No stop/reset/retry or
    # claimed successful guest/driver/package result; old refusal stays nested.
    require(row['id']in COLLECTED_LIBVIRT_FAILED_ORIGINS and row['state']=='running' and
            row['finished']is None,'Exact supported original collected failed row')
    ctx=ExpectedInvocation(backend,db,row);request=libvirt_request(row,ctx.bound)
    check_inputs(json.loads(row['spec']))
    with immutable_ledger_transaction(db):
        ctx.ledger_current();before=diagnostic_ledger(db)
        require([x['id']for x in before['rows']if x['state']not in TERMINAL]==[row['id']],
                'No pending dispatchable, other active or unknown reservation')
        rows,pool=boundary_pool_epoch(db,backend)
        collected_libvirt_failed_pool(pool,row,request)
        props=exact_unit_observation(backend,row['unit'])
        require(collected_libvirt_failed_absent(props),'Collected manager remains exactly absent')
        observed=observe_queue_libvirt(request,captures=backend.observer_captures,terminal_implementation_pin=backend.terminal_implementation_pin)
        rootproof=collected_libvirt_failed_root(request,observed,str(backend.root))
        logger=failed_libvirt_logger(backend,row,props,collectedProof=rootproof)
        group=backend.whole_owned_cgroup(row['unit'],props)
        require(group['empty']is True and group['libvirtDomain']==observed,
                'Exact service/partition/domain/current CLOSED readback')
        initial=terminal_pool_epoch(db,rows,pool)
        reference=terminal_history_store(db,initial,row,ctx.invocation)
        result={'kind':'COLLECTED_LIBVIRT_FAILED_TERMINAL','finalLedgerInvocation':ctx.invocation,
                'childNumericExit':logger['numeric'],'originalFailedLogger':logger,
                'protectedOriginalAndLeaseProof':rootproof,'preservedReservationEpoch':reference,
                'originalReservationRetainedResult':row['result'],
                'finalAfterFsyncCgroupProof':group,'reservationRetained':False,
                'terminalLifecycle':{'phase':'CLOSED','intendedState':'failed',
                    'reservationRetained':False,'automaticRetryAuthorized':False},
                'historicalQMPClosed':rootproof['historicalQMPClosed'],
                'packageAcceptance':False,'NVIDIAFunctionalDriverAccepted':False}
        encoded=canonical(result)
        # Re-resolve every protected/current/log input after fallible history
        # publication/serialization. Nothing earlier is a final effect fence.
        require(collected_libvirt_failed_root_equal(request,observed,rootproof,str(backend.root)),
                'Protected original/lease source changed')
        require(failed_libvirt_logger(backend,row,props,collectedProof=rootproof)==logger,
                'Whole original failed logs changed before final effect')
        ctx.ledger_current();require(diagnostic_ledger(db)==before,'Full current history/bindings/config changed')
        finalrows,finalpool=boundary_pool_epoch(db,backend)
        collected_libvirt_failed_pool(finalpool,row,request)
        require(finalpool['libvirtDomains']==pool['libvirtDomains'],
                'Original exact domain/lease pins changed during collected terminal')
        observed_at=time.monotonic();latest=exact_unit_observation(backend,row['unit'])
        require(latest==props and collected_libvirt_failed_absent(latest),
                'Collected unit replacement/reuse refused')
        recent_boundary(finalpool,observed_at)
        db.execute("UPDATE jobs SET state='failed',finished=?,result=? WHERE id=? AND state='running' AND unit=? AND spec=? AND result=?",
                   (time.time(),encoded,row['id'],row['unit'],row['spec'],row['result']))
        require(db.execute('SELECT changes()').fetchone()[0]==1,'Exactly one original failed collected transition')
    return result


def collected_libvirt_failed_root_equal(request,observed,original,stateRoot):
    current=collected_libvirt_failed_root(request,observed,stateRoot)
    return {k:v for k,v in current.items()if k not in ('completedMonotonic','actor')}=={
        k:v for k,v in original.items()if k not in ('completedMonotonic','actor')}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, default=Path(__file__).parent / "test-queue-state")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("init")
    submit = commands.add_parser("submit")
    submit.add_argument("manifests", type=Path, nargs="+")
    add = commands.add_parser("add", help="One job per test file, using the supplied runner")
    add.add_argument("files", type=Path, nargs="+")
    add.add_argument("--runner", required=True, help="Single executable, e.g. python3 or pytest")
    add.add_argument("--owner", required=True)
    add.add_argument("--platform", required=True)
    add.add_argument("--cores", type=int, required=True)
    add.add_argument("--memory", required=True)
    add.add_argument("--timeout", type=int, required=True)
    add.add_argument("--approval", type=Path, required=True)
    add.add_argument("--resource", action="append", required=True)
    commands.add_parser("plan")
    status_parser=commands.add_parser("status");status_parser.add_argument("--job-id")
    run_parser=commands.add_parser("run");run_parser.add_argument("--collected-proof",type=Path);run_parser.add_argument("--collected-approval",type=Path);run_parser.add_argument("--diagnostic-proof",type=Path);run_parser.add_argument("--diagnostic-approval",type=Path);run_parser.add_argument("--reconcile-failed-libvirt",choices=tuple(FAILED_LIBVIRT_TERMINAL_TARGETS))
    args = parser.parse_args(argv)
    if args.action=='run' and args.reconcile_failed_libvirt is not None:
        require(all(getattr(args,k)is None for k in('collected_proof','collected_approval','diagnostic_proof','diagnostic_approval')),
                'Exact failed submission terminal mode cannot combine alternate authorities')
    if args.action=='run'and (args.collected_proof is not None or args.collected_approval is not None):
        require(args.collected_proof is not None and args.collected_approval is not None,'both exact collected inputs');rp=file_pin(args.collected_proof);ap=file_pin(args.collected_approval);rp['identity']={k:getattr(args.collected_proof.stat(),k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')};ap['identity']={k:getattr(args.collected_approval.stat(),k)for k in rp['identity']};receipt=collected_read(rp,0,0o400);COLLECTED_TERMINAL_INPUTS[receipt['jobId']]=(rp,ap)
    if args.action == 'run' and (args.diagnostic_proof is not None or args.diagnostic_approval is not None):
        require(args.diagnostic_proof is not None and args.diagnostic_approval is not None and args.collected_proof is None and args.collected_approval is None, 'exact separate diagnostic receipt/approval only')
        rp=file_pin(args.diagnostic_proof);ap=file_pin(args.diagnostic_approval)
        for pin in (rp,ap): pin['identity']={k:getattr(os.lstat(pin['path']),k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
        receipt=collected_read(rp,0,0o444)
        require(receipt['kind']==DIAGNOSTIC_KIND and receipt['jobIds']==list(DIAGNOSTIC_TARGETS),'exact two historical diagnostics only')
        for job in receipt['jobIds']:DIAGNOSTIC_TERMINAL_INPUTS[job]=(rp,ap)
    root, db = connect(args.queue)
    if args.action == "init":
        cfg = {"cpu_ids": DEFAULT_CPUS, "memory_bytes": DEFAULT_RAM, "slice": "opemos-vm-pool.slice", "manager": "system"}
        require(db.execute("SELECT 1 FROM config WHERE id=1").fetchone() is None, "Queue is already initialized")
        with db:
            db.execute("INSERT INTO config VALUES(1,?)", (canonical(cfg),))
        print(canonical(cfg))
        return 0
    cfg = config(db)
    if args.action == "submit":
        jobs = []
        for path in args.manifests:
            require(path.stat().st_size <= 1024 ** 2, "Manifest exceeds 1MiB")
            def unique(pairs):
                result = {}
                for k, v in pairs:
                    require(k not in result, "Duplicate JSON field")
                    result[k] = v
                return result
            manifest = json.loads(path.read_text(), object_pairs_hook=unique)
            require(type(manifest) is dict and set(manifest) == {"version", "jobs"} and
                    manifest["version"] == 1 and type(manifest["jobs"]) is list, "Expected version1/jobs manifest")
            jobs += [normalize_job(j, path.absolute().parent) for j in manifest["jobs"]]
        enqueue(db, jobs)
        print(canonical({"queued": [x["id"] for x in jobs]}))
    elif args.action == "add":
        approval = file_pin(args.approval)
        jobs = []
        for path in args.files:
            path = path.absolute()
            job = {"id": "file-" + uuid.uuid4().hex, "platform": args.platform, "owner": args.owner,
                   "command": [args.runner, str(path)], "cwd": str(path.parent), "files": [str(path)],
                   "cores": args.cores, "memory": args.memory, "timeout_seconds": args.timeout,
                   "resources": args.resource, "approval": {k: approval[k] for k in ("path", "sha256")}}
            jobs.append(normalize_job(job, Path.cwd()))
        enqueue(db, jobs)
        print(canonical({"queued": [x["id"] for x in jobs]}))
    elif args.action in ("plan", "status"):
        if args.action=="status"and args.job_id is not None:
            try:
                require(re.fullmatch(r"[A-Za-z0-9_.-]{1,80}",args.job_id)is not None,"Exact normal job identifier")
                row=db.execute("SELECT * FROM jobs WHERE id=?",(args.job_id,)).fetchone()
                require(row is not None,"Normal job is not present")
                binding=db.execute("SELECT * FROM pool_unit_bindings WHERE job_id=?",(args.job_id,)).fetchone()
                print(canonical({"kind":"NORMAL_QUEUE_EXACT_JOB_STATUS_V1","job":dict(row),"binding":None if binding is None else dict(binding)}))
                return 0
            finally:db.close()
        rows = db.execute("SELECT * FROM jobs ORDER BY rowid").fetchall()
        selected, blocked = choose(rows, cfg)
        print(json.dumps({"pool": cfg, "runnable_now": [{"id": x[0]["id"], "cpus": x[2],
                          "memory": x[1]["memory"]} for x in selected], "dependency_blocked": blocked,
                          "readiness_waiting": [{"id":r["id"],"reason":why} for r in rows if r["state"]=="pending" and (why:=nvidia_wait_reason(json.loads(r["spec"]))) is not None],
                          "jobs": [{"id": r["id"], "state": r["state"], "platform": json.loads(r["spec"])["platform"],
                          "unit": r["unit"], "result": json.loads(r["result"]) if r["result"] else None} for r in rows]}, indent=2))
    elif args.action == "run":
        if args.diagnostic_proof is not None:
            try: return worker(root, db, cfg)
            finally: db.close()
        try:return worker(root, db, cfg, args.reconcile_failed_libvirt)
        finally:db.close()
    return 0



def diagnostic_transport_decode(raw, phase):
    """Exact three-stream historical evidence only; never an effect grant."""
    import base64, zlib, stat
    roles = {'producer': {'receipt'}, 'worker': {'workerProof','decision','stdout','stderr'},
             'postflight': {'attestation','after'}}
    require(phase in roles and type(raw) is bytes and 0 < len(raw) <= 8*1024**2, 'finite exact transport phase/frame')
    frame = json.loads(raw)
    require(raw == (canonical(frame)+'\n').encode() and set(frame) == {'DIAGNOSTIC_TRANSPORT'}, 'one whole canonical frame/no tail')
    d = frame['DIAGNOSTIC_TRANSPORT']
    require(set(d) == {'kind','phase','RootUID','actor','sourcePin','currentBootId','receiptPin','rootScope','roles'} and
            d['kind'] == 'CLOSED_R2_R3_DIAGNOSTIC_BYTES' and d['phase'] == phase and d['RootUID'] == 0 and
            set(d['actor']) == {'pid','start'} and all(type(v) is int and v > 0 for v in d['actor'].values()), 'closed Root transport schema/actor')
    require(d['rootScope'] == {'FDSetRestored':True,'threads':1,'children':'','first':None,'secondary':[]}, 'Root scope must close before frame')
    require(set(d['sourcePin']) == {'path','bytes','sha256'} and type(d['sourcePin']['bytes']) is int and 0 < d['sourcePin']['bytes'] <= 8*1024**2 and
            re.fullmatch('[0-9a-f]{64}',d['sourcePin']['sha256']) is not None and Path(d['sourcePin']['path']).is_absolute() and
            type(d['currentBootId']) is str and re.fullmatch('[0-9a-f-]{36}',d['currentBootId']) is not None and set(d['roles']) == roles[phase], 'same bounded source/boot/exact phase roles')
    decoded = {}; total = 0
    fields = {'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'}
    for name, envelope in d['roles'].items():
        require(set(envelope) == {'pin','codec','data'} and envelope['codec'] == 'zlib-base64' and type(envelope['data']) is str, 'closed bytes codec')
        pin = envelope['pin']; require(set(pin) == {'path','bytes','sha256','identity'}, 'exact whole Root artifact pin')
        st = pin['identity']
        require(set(st) == fields and all(type(v) is int for v in st.values()) and st['st_uid'] == st['st_gid'] == 0 and st['st_nlink'] == 1 and
                stat.S_ISREG(st['st_mode']) and stat.S_IMODE(st['st_mode']) == 0o444 and type(pin['bytes']) is int and 0 <= pin['bytes'] <= 8*1024**2 and
                st['st_size'] == pin['bytes'] and Path(pin['path']).is_absolute() and re.fullmatch('[0-9a-f]{64}',pin['sha256']) is not None, 'Root immutable full9/count/SHA')
        compressed = base64.b64decode(envelope['data'],validate=True)
        require(base64.b64encode(compressed).decode() == envelope['data'] and len(compressed) <= 8*1024**2, 'canonical bounded encoded bytes')
        z = zlib.decompressobj(); payload = z.decompress(compressed,pin['bytes']+1)
        require(z.eof and z.unused_data == z.unconsumed_tail == b'' and len(payload) == pin['bytes'] and
                hashlib.sha256(payload).hexdigest() == pin['sha256'], 'complete decoded bytes/eof/count/hash/no trailing stream')
        total += len(payload); require(total <= 16*1024**2, 'finite aggregate decoded phase')
        decoded[name] = payload
    if phase == 'producer':
        require(d['receiptPin'] == d['roles']['receipt']['pin'], 'producer receipt full pin')
    return d, decoded


def diagnostic_transport_frame(phase, receiptPin, artifacts, rootScope):
    """Root caller emits only after actual private/child/lock scope closure."""
    import base64, zlib
    require(os.getuid() == os.geteuid() == 0, 'actual Root evidence producer')
    statText = Path('/proc/self/stat').read_text()
    actor = {'pid':os.getpid(),'start':int(statText[statText.rfind(')')+2:].split()[19])}
    receipt = collected_read(receiptPin,0,0o444)
    require(receipt['producerPin'] == file_pin(Path(__file__)) and receipt['currentBootId'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'current producer source/boot')
    encoded = {}
    for name, pin in artifacts.items():
        raw = collected_read(pin,0,0o444,False)
        encoded[name] = {'pin':pin,'codec':'zlib-base64','data':base64.b64encode(zlib.compress(raw,9)).decode()}
    frame = {'DIAGNOSTIC_TRANSPORT':{'kind':'CLOSED_R2_R3_DIAGNOSTIC_BYTES','phase':phase,'RootUID':0,'actor':actor,
             'sourcePin':receipt['producerPin'],'currentBootId':receipt['currentBootId'],'receiptPin':receiptPin,'rootScope':rootScope,'roles':encoded}}
    diagnostic_transport_decode((canonical(frame)+'\n').encode(),phase)
    return frame


def diagnostic_import_streams(closure, localParent):
    """Controller copies ONLY bytes from closed captures. No remote paths open."""
    import stat
    require(os.getuid() == os.geteuid() == 1000, 'ordinary controller UID1000')
    phaseRoles = [('producer','RootProducer'),('worker','RootWorkerSupervisor'),('postflight','RootPostflight')]
    require([x['phase'] for x in closure['SSH']] == [x[0] for x in phaseRoles], 'three exact authenticated captures')
    decoded = {}; frames = {}; identities = set()
    for phase, rootRole in phaseRoles:
        ssh = next(x['record'] for x in closure['SSH'] if x['phase'] == phase)
        root = closure[rootRole]
        for record in (root,ssh):
            diagnostic_closed_record(record,0)
            pair = (record['actor']['pid'],record['actor']['start']); require(pair not in identities,'distinct Root/transport actors'); identities.add(pair)
        stream = collected_read(ssh['stdout'],1000,0o600,False)
        require(stream == collected_read(root['stdout'],1000,0o600,False) and
                collected_read(ssh['stderr'],1000,0o600,False) == collected_read(root['stderr'],1000,0o600,False) == b'', 'exact closed Root/SSH streams/no stderr')
        d, payload = diagnostic_transport_decode(stream,phase)
        require(d['actor'] == root['actor'], 'Root actor binding from authenticated transport')
        frames[phase] = d; decoded[phase] = payload
    producer = frames['producer']; rp = producer['receiptPin']; receipt = json.loads(decoded['producer']['receipt'])
    require(decoded['producer']['receipt'] == (canonical(receipt)+'\n').encode() and receipt['producerPin'] == producer['sourcePin'] and
            receipt['currentBootId'] == producer['currentBootId'], 'producer canonical receipt/source/boot')
    for d in frames.values():
        require(d['sourcePin'] == receipt['producerPin'] and d['currentBootId'] == receipt['currentBootId'] and d['receiptPin'] == rp,'same invocation source/boot/receipt across all three streams')
    proof = json.loads(decoded['worker']['workerProof']); doc = json.loads(decoded['postflight']['attestation'])
    require(decoded['worker']['workerProof'] == (canonical(proof)+'\n').encode() and decoded['postflight']['attestation'] == (canonical(doc)+'\n').encode(), 'canonical whole worker/attestation')
    require(doc['observer'] == frames['postflight']['actor'] and doc['workerProofPin'] == frames['worker']['roles']['workerProof']['pin'] and
            doc['atUseDecisionPin'] == frames['worker']['roles']['decision']['pin'] and doc['receiptPin'] == rp and
            proof['receiptPin'] == rp and proof['producerPin'] == receipt['producerPin'] and proof['currentBootId'] == receipt['currentBootId'], 'all cross-phase artifact/Root actor bindings')
    diagnostic_closed_record(proof['record'],1)
    for name in ('stdout','stderr'):
        require(proof['record'][name] == frames['worker']['roles'][name]['pin'], 'worker whole raw pin equals authenticated payload')
    parent = Path(localParent['path']); require(parent.is_absolute() and parent.resolve(strict=True) == parent, 'private local destination no aliases')
    fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    identity = lambda s:{k:getattr(s,k) for k in fields}
    fd = os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    copies = {}
    try:
        before = identity(os.fstat(fd)); require(before == localParent['identity'] == identity(parent.lstat()) and before['st_uid'] == before['st_gid'] == 1000 and stat.S_IMODE(before['st_mode']) == 0o700, 'held exact private local parent')
        for phase,payload in decoded.items():
            for role,raw in payload.items():
                name = phase+'-'+role+'.bytes'; leaf = os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
                try:
                    view = memoryview(raw)
                    while view:
                        count = os.write(leaf,view); require(count > 0,'local evidence short write'); view = view[count:]
                    os.fchmod(leaf,0o600); os.fsync(leaf); st = identity(os.fstat(leaf))
                    require(st == identity(os.stat(name,dir_fd=fd,follow_symlinks=False)) and st['st_uid'] == st['st_gid'] == 1000 and st['st_nlink'] == 1 and os.pread(leaf,len(raw)+1,0) == raw,'local full-byte held/path readback')
                    copies[(phase,role)] = {'path':str(parent/name),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':st}
                finally:os.close(leaf)
        os.fsync(fd); require(identity(os.fstat(fd)) == identity(parent.lstat()) and all(identity(os.fstat(fd))[k] == before[k] for k in fields[:6]), 'local parent custody after exact creates')
    finally:os.close(fd)
    import copy
    closed = copy.deepcopy(closure)
    closed['worker'] = dict(proof['record'],stdout=copies[('worker','stdout')],stderr=copies[('worker','stderr')])
    return {'before':receipt['ledger'],'after':json.loads(decoded['postflight']['after']),'receipt':receipt,'receiptPin':rp,
            'closure':closed,'attestation':{'localPin':copies[('postflight','attestation')],'remotePin':frames['postflight']['roles']['attestation']['pin'],
                'workerProofLocalPin':copies[('worker','workerProof')],'decisionLocalPin':copies[('worker','decision')]},'localCopies':list(copies.values())}

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(75 if "pool" in str(exc).lower() or "dispatcher" in str(exc).lower() else 2)

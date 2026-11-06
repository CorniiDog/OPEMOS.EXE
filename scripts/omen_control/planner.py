#!/usr/bin/env python3
"""Fixed, fail-closed OMEN Robot plan hook. No guest control or queue effects.

The Root-owned installed profile pins this hook and its normal operation data.
Candidate identity is authenticated by the broker, not privileged executable
source. Per-run JSON is created from that fixed data; no code is generated.
The normal stage performs the independent queue/source/admission checks.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

PROFILE = Path.home() / '.config/opemos-ci/robot.json'
REGISTRY = Path.home() / '.config/opemos-ci/robot-jobs.json'
FULL9 = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
REPO = 'CorniiDog/OPEMOS.EXE'
SHA = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
NUM = re.compile(r'[1-9][0-9]{0,19}\Z')
NONCE = re.compile(r'[0-9a-f]{32}\Z')

def need(condition, message):
    if not condition:
        raise ValueError(message)

def strict(data):
    def pairs(items):
        obj = {}
        for key, value in items:
            need(key not in obj, 'duplicate JSON field')
            obj[key] = value
        return obj
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))

def held(path, cap, digest=None, owner=None):
    path = Path(path)
    need(path.is_absolute(), 'absolute pinned file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        sig = lambda s: tuple(getattr(s, k) for k in FULL9)
        need(stat.S_ISREG(before.st_mode) and
             before.st_uid == (os.getuid() if owner is None else owner)
             and before.st_nlink == 1 and not before.st_mode & 0o022
             and before.st_size <= cap, 'unsafe owned file')
        raw = bytearray()
        while chunk := os.read(fd, min(65536, cap + 1 - len(raw))):
            raw.extend(chunk)
            need(len(raw) <= cap, 'file cap exceeded')
        need(len(raw) == before.st_size and
             sig(before) == sig(os.fstat(fd)) == sig(path.lstat()),
             'held file identity drift')
        need(digest is None or hashlib.sha256(raw).hexdigest() == digest,
             'file SHA mismatch')
        return bytes(raw)
    finally:
        os.close(fd)

def request():
    raw = sys.stdin.buffer.read(65537)
    need(len(raw) <= 65536, 'request cap exceeded')
    r = strict(raw)
    fields = {
        'version','action','kind','subject','repository','source_commit',
        'run_id','attempt','nonce','consumer_started_epoch'}
    need(type(r) is dict and set(r) in (fields, fields | {'candidate'}),
        'exact Robot request schema required')
    need(r['version'] == 1 and r['repository'] == REPO and
         COMMIT.fullmatch(r['source_commit']) and
         NUM.fullmatch(r['run_id']) and NUM.fullmatch(r['attempt']) and
         NONCE.fullmatch(r['nonce']) and
         type(r['consumer_started_epoch']) is int and
         r['consumer_started_epoch'] > 0,
         'exact protected consumer identity required')
    need(r['action'] in ('prepare','collect') and
         r['kind'] in ('inventory','artifacts','artifact'),
         'unsupported fixed action/kind')
    return r

def key(r):
    return {field:r[field] for field in
            ('repository','source_commit','run_id','attempt','nonce')}

def registered(pin, r, required):
    """Only a pre-pinned whole response for this exact run can become available."""
    if pin is None:
        return None
    need(type(pin) is dict and set(pin) ==
         {'path','sha256','run_id','attempt','nonce','source_commit'},
         'complete fixed operation registry pin required')
    if not all(pin[k] == r[k] for k in
               ('run_id','attempt','nonce','source_commit')):
        return None
    need(type(pin['sha256']) is str and SHA.fullmatch(pin['sha256']),
         'operation SHA invalid')
    response = strict(held(pin['path'], 8*1048576, pin['sha256']))
    need(response.get('identity') == key(r) and
         response.get('available') is True and
         all(k in response for k in required),
         'registered normal operation incomplete or stale')
    return response

def directory(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, 'private real operation directory')
    meta = path.lstat()
    need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid() and
         not meta.st_mode & 0o077, 'private operation directory owner/mode')
    return path

def file_pin(path):
    raw = held(path, 8*1048576)
    return {'path':str(path), 'sha256':hashlib.sha256(raw).hexdigest()}

def candidate(r):
    """Root broker already authenticated API metadata; recheck data custody."""
    item = r.get('candidate')
    need(type(item) is dict and set(item) == {'descriptor','archive'},
         'authenticated candidate package data required')
    value, archive = item['descriptor'], item['archive']
    need(type(value) is dict and value.get('repository') == REPO and
         COMMIT.fullmatch(value.get('source_commit','')) and
         value.get('platform') == r['subject']['platform'] and
         value.get('artifact_id') == r['subject']['artifact_id'] and
         type(archive) is dict and set(archive) == {'path','sha256','bytes'} and
         archive['sha256'] == value.get('artifact_archive_sha256') and
         SHA.fullmatch(archive['sha256']) and type(archive['bytes']) is int and
         0 < archive['bytes'] <= 60000000000,
         'candidate descriptor/archive/subject identity')
    path = Path(archive['path'])
    need(path.is_absolute() and path.resolve() == path, 'real candidate data path')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
             stat.S_IMODE(before.st_mode) == 0o400 and before.st_nlink == 1 and
             before.st_size == archive['bytes'], 'opaque candidate custody')
        digest = hashlib.sha256();size = 0
        while block := os.read(fd, 1048576):
            size += len(block);need(size <= archive['bytes'], 'candidate grew')
            digest.update(block)
        sig = lambda s: tuple(getattr(s,k) for k in FULL9)
        need(size == archive['bytes'] and digest.hexdigest() == archive['sha256'] and
             sig(before) == sig(os.fstat(fd)) == sig(path.lstat()),
             'candidate held bytes/full9 changed')
    finally:os.close(fd)
    return dict(item,archive=dict(archive,identity={k:getattr(before,k)for k in FULL9}))

def operation_policy(pin):
    need(type(pin)is dict and set(pin)=={'path','sha256'}and SHA.fullmatch(pin['sha256']),
         'existing registry normal operation policy pin')
    path=Path(pin['path'])
    need(path.parent.parent==Path('/var/lib/opemos-robot-control-r1/releases')and
         NONCE.fullmatch(path.parent.name)and path.name=='fixed-policy.json',
         'existing immutable deployment policy path')
    for parent in(path.parent,*path.parent.parents):
        s=parent.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and
            not s.st_mode&0o022,'Root current normal deployment ancestry')
    raw=held(path,1048576,pin['sha256'],0);first=path.lstat()
    need(stat.S_IMODE(first.st_mode)==0o444,'immutable Root policy mode')
    policy=strict(raw)
    need(policy['kind']=='ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1'and
         policy['sourceAccepted']is True and policy['runtimeAuthorized']is True and
         policy['network']=='none'and policy['swapBytes']==0,
         'explicit reviewed normal Ubuntu operation scope')
    return policy,dict(pin,bytes=len(raw),uid=0,identity={k:getattr(first,k)for k in FULL9})


def automatic_operation(pin, r, operation_root, normal_policy_pin=None):
    """Bind only typed run data in the installed, hash-pinned normal recipe.

    This is the existing planner's data producer, not another launcher. JSON
    documents are ordinary queue operands; current admission, source, worker,
    hardware, budget and closure are still checked by the normal consumers.
    """
    need(type(pin) is dict and set(pin) == {'path','sha256'} and
         SHA.fullmatch(pin['sha256']), 'installed normal operation recipe pin')
    policy=policy_ref=None
    if normal_policy_pin is not None:policy,policy_ref=operation_policy(normal_policy_pin)
    recipe = strict(held(pin['path'], 8*1048576, pin['sha256'],0 if policy is not None else None))
    need(type(recipe) is dict and set(recipe) == {'schema','documents','prepare','collect'} and
         type(recipe['schema']) is int and recipe['schema'] == 1 and
         type(recipe['documents']) is list, 'normal operation data schema')
    c = candidate(r)
    base = directory(operation_root)
    root = base / ('run-'+r['run_id']+'-'+r['attempt']+'-'+r['nonce'])
    if r['action'] == 'prepare':root.mkdir(mode=0o700)  # create-only identity
    directory(root)
    pins = {}
    def path(name):
        need(type(name) is str and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*',name) and
             name not in ('.','..'), 'fixed operation output basename')
        return root/name
    def bind(value):
        if type(value) is list:return [bind(x) for x in value]
        if type(value) is not dict:return value
        markers = [k for k in value if k.startswith('$')]
        if not markers:return {k:bind(v) for k,v in value.items()}
        need(len(value) == 1, 'one typed data reference')
        tag, name = next(iter(value.items()))
        if tag == '$run':
            need(name in {'repository','source_commit','run_id','attempt','nonce','consumer_started_epoch'}, 'declared run identity only')
            return r[name]
        if tag == '$request':
            need(name == 'prepare', 'original preparation identity only')
            return dict(r, action='prepare')
        if tag == '$candidate':
            if name == '*':return c['descriptor']
            need(name in c['descriptor'], 'declared candidate field only')
            return c['descriptor'][name]
        if tag == '$archive':
            if name=='*':return c['archive']
            need(name in c['archive'], 'opaque archive field only')
            return c['archive'][name]
        if tag == '$path':return str(path(name))
        if tag=='$normal_ubuntu_command':
            need(policy is not None and name=='guest-gui'and
                 {'normal-job.json','identity.json'}<=set(pins),'complete current normal job operands')
            entry=Path(__file__).parent/'scripts/run_omen_robot_guest.py'
            held(entry,8388608,policy['engineSHA256']['scripts/run_omen_robot_guest.py'])
            env={'GITHUB_REPOSITORY':r['repository'],'OPEMOS_SOURCE_SHA':r['source_commit'],
                 'GITHUB_RUN_ID':r['run_id'],'GITHUB_RUN_ATTEMPT':r['attempt'],
                 'OPEMOS_TRANSACTION_NONCE':r['nonce']}
            return ['/usr/bin/env',*[k+'='+v for k,v in env.items()],'/usr/bin/python3',str(entry),
                '--normal-ubuntu-job',json.dumps(pins['normal-job.json'],sort_keys=True,separators=(',',':')),
                json.dumps(pins['identity.json'],sort_keys=True,separators=(',',':'))]
        if tag=='$operand':
            need(policy is not None and name in{'base','code','vars_template','image_carrier','loginPin',
                'ext4_dev','retained_union_bytes','pool_sha256','queue_entry','original_source'},
                'declared operands from the same Root deployment definition')
            return policy['operationOperands'][name]
        if tag in('$policy','$program','$program_pin','$engine','$engine_pin','$engine_sha','$runtime'):
            need(policy is not None,'Root selected current normal operation definition required')
            if tag=='$policy':
                need(name in('pin','value','path','sha256'),'declared normal policy data')
                return policy_ref if name=='pin'else policy if name=='value'else policy_ref[name]
            if tag=='$runtime':
                need(name in('id','root','result','operation','stage'),'declared current Ubuntu runtime role')
                if name=='id':return 'opemos-robot-ubuntu-'+r['nonce']
                if name=='operation':return str(root)
                if name=='stage':return str(Path('/media/connor/Games/OPEMOS/CI-artifacts')/root.name)
                runtime=root/'runtime'
                return str(runtime if name=='root'else runtime/'job-result.json')
            if tag in('$program','$program_pin'):
                need(name in policy['programSHA256']and Path(name).name==name,'Root selected normal program member')
                source=Path(policy_ref['path']).parent/'proof-sources'/name
                digest=policy['programSHA256'][name];uid=0
            else:
                need(name in policy['engineSHA256'],'Root selected existing Engine member')
                source=Path(__file__).parent/name;digest=policy['engineSHA256'][name];uid=os.getuid()
            raw=held(source,8*1048576,digest,uid);s=source.lstat()
            if tag=='$engine_sha':return digest
            observed={'path':str(source),'sha256':digest,'bytes':len(raw),
                      'identity':{k:getattr(s,k)for k in FULL9}}
            return str(source)if tag in('$program','$engine')else observed
        if tag=='$json':return json.dumps(bind(name),sort_keys=True,separators=(',',':'),allow_nan=False)
        if tag=='$result_field':
            need(r['action']=='collect'and type(name)is list and len(name)==2
                 and type(name[1])is list and all(type(k)is str for k in name[1]),
                 'post-terminal declared result field only')
            value=strict(held(path(name[0]),8*1048576))
            for field in name[1]:value=value[field]
            return value
        if tag=='$normal_evidence':
            need(r['action']=='collect'and name=='ubuntu-gui'and policy is not None,
                 'read-only current normal Ubuntu public evidence only')
            runtime=root/'runtime';values=[];charged=0;count=0
            if not runtime.exists():return values
            for item in sorted(runtime.rglob('*')):
                count+=1;need(count<=4096,'bounded actual evidence traversal')
                info=item.lstat();need(not stat.S_ISLNK(info.st_mode),'no evidence symlink')
                if not stat.S_ISREG(info.st_mode):continue
                kind=None
                if item.suffix=='.png':kind='screenshot'
                elif item.suffix=='.html':kind='robot-report'if item.name=='report.html'else'robot-log'
                elif item.suffix=='.xml':kind='robot-xunit'if item.name=='xunit.xml'else'robot-output'
                elif re.fullmatch(r'robot-[1-5]-action\.json',item.name):kind='pointer-action'
                elif re.fullmatch(r'robot-[1-5]-life\.json',item.name):kind='pointer-sender-lifecycle'
                elif re.fullmatch(r'robot-[1-5]-robot\.(stdout|stderr)',item.name):kind='log'
                if kind is None:continue
                raw=held(item,24*1048576);charged+=len(raw);need(charged<=policy['publicEvidenceMaxBytes'],
                      'complete finite public evidence cap, no selection after overflow')
                if kind=='screenshot':need(raw.startswith(b'\x89PNG\r\n\x1a\n'),'actual PNG capture bytes')
                values.append({'path':str(item),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                    'identity':{k:getattr(info,k)for k in FULL9},'public':True,'kind':kind})
            return values
        if tag == '$document':
            need(name in pins, 'previous ordinary JSON document reference')
            return pins[name]
        if tag == '$result':
            need(r['action'] == 'collect', 'result only after normal queue completion')
            return file_pin(path(name))
        if tag == '$job':
            need(type(name) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,47}',name), 'fixed normal job prefix')
            return name+'-'+r['nonce']
        raise ValueError('unknown normal data reference')
    total = 0
    for document in recipe['documents']:
        need(type(document) is dict and set(document) == {'name','value'} and
             document['name'].endswith('.json') and document['name'] not in pins,
             'unique JSON operand only; no generated executable')
        target = path(document['name'])
        raw = (json.dumps(bind(document['value']),sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
        total += len(raw);need(total <= 8*1048576, 'existing operation data bound')
        if r['action'] == 'prepare':
            fd = os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
            try:
                with os.fdopen(fd,'wb',closefd=False) as stream:
                    stream.write(raw);stream.flush();os.fsync(fd)
                os.fchmod(fd,0o400)
            finally:os.close(fd)
        need(held(target,8*1048576) == raw, 'normal operation document changed')
        pins[document['name']] = {'path':str(target),'sha256':hashlib.sha256(raw).hexdigest()}
    response = bind(recipe[r['action']])
    need(type(response) is dict and not {'identity','available'} & response.keys(),
         'planner supplies identity, not template claims')
    if r['action'] == 'prepare':
        need(response.get('expected') == c['descriptor'] and
             all(k in response for k in ('config','operand','plan','staging_path','robot_job',
                  'executable_entry','additional_operations','executable_transaction_path')),
             'complete normal candidate operation required')
    else:need(response.get('effect') == 'READ_ONLY_CURRENT_OPERATION', 'read-only current collection')
    return dict(response, identity=key(r), available=True)

def main():
    r = request()
    p = strict(held(PROFILE, 1048576, owner=0))
    need(p.get('schema') == 1 and p.get('enabled') is True,
         'installed Root profile disabled')
    pin = p.get('fixed_registry', {})
    need(pin.get('path') == str(REGISTRY) and
         isinstance(pin.get('sha256'), str) and SHA.fullmatch(pin['sha256']),
         'fixed Root registry pin missing')
    registry = strict(held(REGISTRY, 4*1048576, pin['sha256']))
    need(registry.get('schema') == 1 and registry.get('repository') == REPO,
         'fixed registry schema/repository mismatch')
    cases = registry.get('cases')
    need(type(cases) is dict, 'configured fixed cases required')
    source = registry.get('source_commit')
    need(type(source) is str and COMMIT.fullmatch(source),
         'registry protected source pin missing')
    need(type(registry.get('artifacts')) is dict and
         set(registry['artifacts']) <= {'windows','ubuntu','macos'} and
         all(type(row) is dict and type(row.get('reason')) is str and
             bool(row['reason']) for row in registry['artifacts'].values()),
         'configured producer states required')
    if r['kind'] == 'inventory':
        need(type(r['subject']) is str and r['subject'] in cases,
             'inventory subject outside exact20')
    elif r['kind'] == 'artifacts':
        need(type(r['subject']) is str and
             r['subject'] in registry['artifacts'],
             'unknown protected producer platform')
    else:
        need(type(r['subject']) is dict and
             set(r['subject']) == {'platform','artifact_id'} and
             r['subject']['platform'] in registry['artifacts'] and
             type(r['subject']['artifact_id']) is str and
             bool(r['subject']['artifact_id']),
             'exact artifact identity required')
    identity = key(r)
    if r['source_commit'] != source:
        result = {'identity':identity,'available':False,
                  'reason':'Root registry source differs from current protected consumer; fresh source and producer reconciliation required'}
    elif r['kind'] == 'artifact' and 'candidate' in r:
        row = registry['artifacts'][r['subject']['platform']]
        result = automatic_operation(row['automatic_operation'], r, p['operation_root'],row.get('operation_policy'))
    elif r['action'] == 'collect':
        # Collection cannot adopt a historical request or invent evidence.
        result = {'identity':identity,'available':False,
                  'reason':'No exact current operation evidence packet registered for read-only failure collection'}
    elif r['kind'] == 'inventory':
        row = cases[r['subject']]
        need(type(row) is dict and type(row.get('reason')) is str and row['reason'],
             'explicit per-case blocker absent')
        result = {'identity':identity,'available':False,'reason':row['reason']}
        result = registered(row.get('operation'), r,
                            ('config','operand','plan','staging_path','robot_job')) or result
    elif r['kind'] == 'artifacts':
        row = registry['artifacts'][r['subject']]
        result = {'identity':identity,'available':False,'reason':row['reason']}
        result = registered(row.get('listing'), r,
                            ('expected_executables',)) or result
    else:
        row = registry['artifacts'][r['subject']['platform']]
        result = {'identity':identity,'available':False,'reason':row['reason']}
        result = registered(row.get('operations',{}).get(r['subject']['artifact_id']),
                            r, ('config','operand','plan','staging_path','robot_job',
                                'expected','executable_entry','additional_operations',
                                'executable_transaction_path')) or result
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(',',':'))+'\n')

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('fixed Robot planner refusal: '+str(exc), file=sys.stderr)
        sys.exit(1)

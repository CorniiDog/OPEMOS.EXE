"""Create-only installation of one exactly reviewed media controller payload.

The owning deployment verifies the protected squash/tree and expected payload
hash before calling this installer. Installation creates code/profiles only;
it never starts a service, mounts media, opens queue SQL, binds GPU or runs a VM.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SOURCE_ROOT = Path('/run/opemos-steamos-source-cd9ef0826364409da287f6f3e3830c95-r120')
RUNTIME = {'libvirt_peer','libvirt_access','libvirt_native','libvirt_preflight','libvirt_producer',
           'queue_assignment','runtime_entry','guest_delta','guest_firmware_probe','held_history_reader',
           'two_boot_contract','postqueue_issuer','libvirt_storage','retained_media','source_contract'}
PREPARE = {'current_media_preparation','fresh_placement_producer','fresh_media_parent','run_current_media'}
QUEUE_NAMES = ('test_queue.py','queue_job.py','heavy.sh','queue.sh','queue-files.sh',
               'retained_media.py','source_contract.py')
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def need(ok, message):
    if not ok: raise RuntimeError(message)


def canon(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def pin(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        i = {k:getattr(os.fstat(fd),k) for k in FIELDS}; raw = b''
        while b := os.read(fd, 65536): raw += b; need(len(raw) <= 8388608, 'installer pin cap')
        need(all(i[k] == getattr(os.fstat(fd),k) == getattr(os.lstat(path),k) for k in FIELDS), 'installed full9/FD/name')
        return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':i}
    finally: os.close(fd)


def root_directory(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and not os.path.lexists(path), 'new exact install directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child; s = os.fstat(fd)
            need(s.st_uid == s.st_gid == 0 and not s.st_mode & 0o022, 'protected installation ancestry')
        os.mkdir(path.name, 0o700, dir_fd=fd); os.fsync(fd)
    finally: os.close(fd)


def put(path, raw, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode); view = memoryview(raw)
        while view:
            n = os.write(fd, view); need(n > 0, 'install write progress'); view = view[n:]
        os.fsync(fd)
    finally: os.close(fd)
    result = pin(path)
    need(result['sha256'] == hashlib.sha256(raw).hexdigest() and result['bytes'] == len(raw), 'installed exact bytes')
    return result


def body(value):
    raw = base64.b64decode(value['base64'], validate=True)
    need(len(raw) == value['bytes'] and hashlib.sha256(raw).hexdigest() == value['sha256'], 'whole reviewed code member')
    return raw


def install(payload):
    need(os.getuid() == os.geteuid() == 0 and payload['kind'] == 'ROOT_REVIEWED_CURRENT_MEDIA_INSTALL_V1', 'Root exact installation')
    need(payload['repository'] == 'CorniiDog/OPEMOS.EXE'
         and re.fullmatch('[0-9a-f]{40}', payload['protectedMain'])
         and re.fullmatch('[0-9a-f]{40}', payload['reviewedHead']), 'verified owning repository/merge identities')
    sources = payload['sources']
    need(set(sources) == RUNTIME | PREPARE | {'standalone_peer_access_adapter'}, 'whole static runtime and preparation source')
    need(set(payload['queueSources']) == set(QUEUE_NAMES), 'whole current queue deployment')
    queue_root = Path(payload['queueRoot'])
    need(re.fullmatch('/var/lib/opemos-queue-r120-[0-9a-f]{32}', str(queue_root)), 'fixed owned queue installation family')
    for name, value in sources.items():
        raw = body(value); need(len(raw) <= 65536, 'unchanged per-role source cap'); compile(raw, name + '.py', 'exec')
    for name, value in payload['queueSources'].items():
        raw = body(value); need(len(raw) <= 1048576, 'whole normal queue member cap')
    for name in ('retained_media','source_contract'):
        need(body(sources[name]) == body(payload['queueSources'][name+'.py']), 'same exact runtime/queue helper')
    root_directory(SOURCE_ROOT); root_directory(queue_root)
    role_pins = {name:put(SOURCE_ROOT/(name+'.py'), body(value), 0o444) for name,value in sources.items()}
    queue = [put(queue_root/name,body(payload['queueSources'][name]),0o555 if name.endswith('.sh')else 0o444)
             for name in QUEUE_NAMES]
    origin = put(SOURCE_ROOT/'origin-copy-data.json', body(payload['originCopyData']), 0o400)
    template = payload['parentTemplate']
    need(template['noNIC'] is True and template['noInstall'] is True and template['maxBoots'] == 1,
         'no privilege or hardware scope expansion')
    contract = {'kind':'OPEMOS_INSTALLED_MEDIA_SOURCE_CONTRACT_V1',
                'repository':payload['repository'],'protectedMain':payload['protectedMain'],
                'reviewedHead':payload['reviewedHead'],
                'sourceRoles':{n:role_pins[n] for n in RUNTIME},
                'preparationRoles':{n:role_pins[n] for n in PREPARE},
                'queuePrograms':queue,'parentTemplate':template,'originCopyReceiptPin':origin}
    contract_pin = put(SOURCE_ROOT/'installed-controller.json',canon(contract),0o444)
    operation = payload['operationProfile']
    need(operation['kind'] == 'OPEMOS_INSTALLED_CURRENT_MEDIA_OPERATION_V1', 'fixed operation profile')
    operation.update(installedSourceContractPin=contract_pin, sourceRoles=contract['sourceRoles'], queuePrograms=queue)
    operation_pin = put(SOURCE_ROOT/'operation-profile.json',canon(operation),0o444)
    drain_root = Path(payload['drainRoot'])
    need(re.fullmatch('/var/lib/opemos-media-drain-r120-[0-9a-f]{32}', str(drain_root)), 'fixed drain source family')
    need(set(payload['drainSources']) == {'media_drain','idle_signal_owner','normal_probe','normal_cycle','media_probe_remote'}, 'exact normal control/drain/probe sources')
    root_directory(drain_root)
    drain_sources = {}
    for name,value in payload['drainSources'].items():
        raw = body(value); compile(raw,name+'.py','exec')
        drain_sources[name] = put(drain_root/(name+'.py'),raw,0o444)
    policy = payload['normalControlPolicy']
    need(drain_sources['normal_probe']['sha256'] == policy['normalProbeSHA256']
         and drain_sources['normal_cycle']['sha256'] == policy['normalCycleSHA256'], 'same actual installed normal control sources')
    normal_sources = {'normal_probe':drain_sources['normal_probe'],'normal_cycle':drain_sources['normal_cycle'],
                      'signalOwner':drain_sources['idle_signal_owner']}
    drain_profile = {'kind':'OPEMOS_INSTALLED_MEDIA_DRAIN_V1','installedSources':normal_sources,
                     'policy':policy,'entryPin':drain_sources['media_drain']}
    drain_profile_pin = put(drain_root/'drain-profile.json',canon(drain_profile),0o444)
    probe_profile = {'kind':'OPEMOS_INSTALLED_MEDIA_PROBE_V1',
                     'normalProbePin':drain_sources['normal_probe'],'policy':policy}
    probe_profile_pin = put(drain_root/'probe-profile.json',canon(probe_profile),0o444)
    for path in (SOURCE_ROOT,queue_root,drain_root):
        os.chmod(path,0o555)
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(fd)
        finally:os.close(fd)
    return {'kind':'CURRENT_MEDIA_CONTROLLER_INSTALLED','protectedMain':payload['protectedMain'],
            'sourceContractPin':contract_pin,'operationProfilePin':operation_pin,
            'sourceRoles':role_pins,'queuePrograms':queue,
            'drainEntryPin':drain_sources['media_drain'],'drainProfilePin':drain_profile_pin,
            'probeEntryPin':drain_sources['media_probe_remote'],'probeProfilePin':probe_profile_pin,
            'normalControlSources':normal_sources,
            'serviceStarted':False,'mounts':[],'queueSubmitted':False,'hardwareEffects':[]}


def install_window(payload):
    need(os.getuid() == os.geteuid() == 0 and payload['kind'] == 'ROOT_REVIEWED_MEDIA_WINDOW_INSTALL_V1', 'Root controller installation')
    root = Path(payload['root'])
    need(re.fullmatch('/var/lib/opemos-media-window-r120-[0-9a-f]{32}', str(root)), 'fixed installed window family')
    need(set(payload['sources']) == {'media_window','media_client','window_common','owned_command','media_probe'}, 'whole fixed window implementation')
    root_directory(root)
    sources = {}
    for name,value in payload['sources'].items():
        raw=body(value);compile(raw,name+'.py','exec');sources[name]=put(root/(name+'.py'),raw,0o444)
    ssh = put(root/'ssh-config',body(payload['existingSSHConfig']),0o444)
    evidence = Path('/var/lib/opemos-media-evidence')
    if not os.path.lexists(evidence): root_directory(evidence)
    else:
        s=os.lstat(evidence);need(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'protected existing evidence owner; preserve contents')
    remote = payload['remoteInstallation']
    client = {'kind':'OPEMOS_INSTALLED_MEDIA_CLIENT_V1','sshConfigPin':ssh,
              'ownedCommandPin':sources['owned_command'],'remoteEntry':remote['operationProfilePin']['path'].rsplit('/',1)[0]+'/run_current_media.py',
              'remoteProfilePin':remote['operationProfilePin'],'remoteHeavyPin':remote['queuePrograms'][2],
              'jobPrefix':payload['jobPrefix']}
    client_pin=put(root/'client-profile.json',canon(client),0o444)
    window = {'kind':'OPEMOS_INSTALLED_MEDIA_WINDOW_V1','maximumWindowSeconds':2700,
              'localSources':dict(sources,sshConfig=ssh),'evidenceRoot':str(evidence),
              'currentProbePin':sources['media_probe'],'controlPolicyPin':payload['controlPolicyPin'],
              'clientProfilePin':client_pin,'remoteDrainEntry':remote['drainEntryPin']['path'],
              'remoteDrainProfilePin':remote['drainProfilePin'],
              'remoteDrainSources':remote['normalControlSources'],
              'sshArgv':['/usr/sbin/runuser','-u','connor','--','/usr/bin/ssh','-T','-F',ssh['path'],
                         '-o','BatchMode=yes','-o','ConnectTimeout=8','-o','StrictHostKeyChecking=yes','opemos-ubuntu-host']}
    window['probeInputs'] = {'policyPin':payload['controlPolicyPin'],
                             'normalProbePin':payload['normalProbePin'],
                             'remoteEntryPin':remote['probeEntryPin'],
                             'remoteProfilePin':remote['probeProfilePin'],
                             'sshArgv':window['sshArgv']}
    result=put(root/'window-profile.json',canon(window),0o444)
    os.chmod(root,0o555)
    return {'kind':'CURRENT_MEDIA_WINDOW_INSTALLED','windowProfilePin':result,'windowEntryPin':sources['media_window'],
            'hardwareEffects':[],'servicesChanged':False,'newCredentialsOrTrust':False}


if __name__ == '__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--payload',required=True);ap.add_argument('--payload-sha256',required=True)
    args=ap.parse_args();ref=pin(args.payload)
    need(ref['sha256']==args.payload_sha256 and ref['identity']['st_uid']==ref['identity']['st_gid']==0
         and stat.S_IMODE(ref['identity']['st_mode'])==0o400,'exact frozen Root payload')
    raw=Path(args.payload).read_bytes();need(hashlib.sha256(raw).hexdigest()==ref['sha256'],'payload reread unchanged')
    value=json.loads(raw)
    result=install_window(value)if value['kind']=='ROOT_REVIEWED_MEDIA_WINDOW_INSTALL_V1'else install(value)
    print(canon(result).decode(),flush=True)

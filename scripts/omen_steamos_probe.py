#!/usr/bin/env python3
"""Finite read-only privileged observations INSIDE the admitted SteamOS VM.

No installer/update policy, raw activation, network, or arbitrary command API.
The source-bound desktop agent invokes this normal program through existing
guest privilege. Permission refusal is a real failed prerequisite, not a reason
to alter sudo/polkit or invent credentials. Nothing executes on import.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

CORE=Path('/home/.steamos/open-gpu-kernel-modules-steamos-support/recovery')
TARGET='OPEMOSOUTPUTTARGET'
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
CAPTURE=None
RAW_FILES=[]
TRANSPORTS=[]


def need(value,reason):
    if not value:raise RuntimeError(reason)


def strict(raw):
    def pairs(rows):
        value={}
        for k,v in rows:need(k not in value,'duplicate native probe metadata');value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite native metadata'))


def sig(info):return {k:getattr(info,k)for k in FIELDS}


def read(path,cap=1048576,owner=0):
    path=Path(path);need(path.is_absolute()and path.resolve()==path,'canonical probe input path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode)and before.st_uid==owner and before.st_nlink==1 and
             not before.st_mode&0o022 and 0<=before.st_size<=cap,'actual probe file permission/type/size')
        raw=bytearray()
        while block:=os.read(fd,min(65536,cap+1-len(raw))):raw.extend(block);need(len(raw)<=cap,'native metadata overflow')
        need(len(raw)==before.st_size and sig(before)==sig(os.fstat(fd))==sig(path.lstat()),'probe input held/named changed')
        return bytes(raw),{'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':sig(before)}
    finally:os.close(fd)


def guest():
    need(os.getuid()==os.geteuid()==0,'actual guest Root metadata role required')
    result=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
    need(result.returncode==0 and result.stdout.strip()in(b'kvm',b'qemu'),'physical host metadata execution refused')
    need(re.search(r'^ID=["\']?steamos["\']?$',Path('/etc/os-release').read_text(),re.M),'actual SteamOS target required')
    return {'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'uid':os.getuid(),'kernel':os.uname().release,'virtualization':result.stdout.decode().strip()}


def media_manifest(path):
    # This is a fixed QEMU firmware datum bound by the new Root VM XML, not a
    # caller's expected hash or an environment/test-root override.
    firmware=Path('/sys/firmware/qemu_fw_cfg/by_name/opt/opemos/observer-manifest-sha256/raw')
    with firmware.open('rb')as stream:expected=stream.read(257).strip().decode('ascii')
    need(re.fullmatch('[0-9a-f]{64}',expected),'Root-bound observer firmware manifest pin absent')
    raw,pin=read(path)
    need(pin['sha256']==expected,'observer medium differs from Root firmware pin')
    value=strict(raw)
    need(value.get('kind')=='EXE_STEAMOS_PHASE_MEDIA_V1'and value.get('guest_uid')==1000 and
         re.fullmatch('[0-9a-f]{40}',value.get('controller_commit',''))and
         re.fullmatch('[0-9a-f]{32}',value.get('nonce','')),'finite authenticated observer media')
    source,source_pin=read(Path(__file__).absolute(),1048576)
    own=value['files']['omen_steamos_probe.py']
    need(source_pin['sha256']==own['sha256']and len(source)==own['bytes'],'actual privileged probe source differs from A')
    root=Path(path).parent
    blobs={}
    for name,ref in value['files'].items():
        need(type(name)is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',name)and name not in('.','..'),
             'fixed observer medium relative filename')
        raw,item=read(root/name,16*1024**2)
        need(item['sha256']==ref['sha256']and len(raw)==ref['bytes'],'complete A observer source graph differs')
        blobs[name]=raw
    global CAPTURE
    CAPTURE={'__name__':'native_root_owned_capture','__file__':str(root/'omen_ci_result.py')}
    exec(compile(blobs['omen_ci_result.py'],CAPTURE['__file__'],'exec'),CAPTURE)
    return value


def command(argv):
    """Reuse the ordinary bounded capture, retaining actual raw OS output."""
    need(CAPTURE is not None,'verified ordinary capture source required')
    directory=Path(tempfile.mkdtemp(prefix='opemos-native-probe-',dir='/run'))
    out=directory/'capture'
    try:
        result=CAPTURE['capture'](argv,b'',{'max_bytes':1048576,'stderr_max_bytes':65536,
            'free_reserve_bytes':1048576},out,10,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'})
    except CAPTURE['TransportFailure']as error:result=error.transport_receipt
    TRANSPORTS.append(result)
    raw=None;publication_errors=[]
    # Export only these newly created native-metadata captures. Preserve the
    # original capture identity AND the measured read-only publication identity.
    try:
        for name,row in result.get('streams',{}).items():
            try:
                need(name in('stdout','stderr')and Path(row['path']).parent==out,'exact newly created capture stream')
                p=Path(row['path']);data,pin=read(p,1048577)
                original_matches=pin['sha256']==row.get('sha256')and pin['identity']==row.get('identity')
                os.chmod(p,0o444);published,published_pin=read(p,1048577)
                need(published==data,'native raw capture changed during read-only publication')
                RAW_FILES.append(dict(published_pin,kind='native-'+name,public=False,
                    capture_identity=pin['identity'],original_capture_matches=original_matches,
                    failure_preserved=not result.get('complete',False)))
                if name=='stdout'and original_matches:raw=data
                if not original_matches:publication_errors.append('original capture custody UNKNOWN')
            except Exception as error:publication_errors.append(type(error).__name__)
    finally:
        os.chown(out,1000,1000);os.chown(directory,1000,1000)
    result['publication_errors']=publication_errors
    need(result.get('complete')is True and result.get('numeric_exit')==0 and
         result.get('local_reaped')is True and raw is not None,'actual native metadata child failed/closure unknown')
    need(not publication_errors,'native capture publication failed; original transport retained')
    need(len(raw)<=262144,'native metadata exceeds finite semantic inventory limit; full raw capture retained')
    return raw


def disk_tree():
    # Fixed read-only SDK command. Byte cap is also imposed by the outer
    # ordinary owned-command transport; no command comes from the request.
    argv=['/usr/bin/lsblk','--json','--bytes','--output','NAME,KNAME,PATH,TYPE,SERIAL,SIZE,RO,PKNAME,UUID,FSTYPE,LABEL,PARTLABEL,MOUNTPOINTS']
    raw=command(argv)
    value=strict(raw);nodes=[]
    def walk(rows,parent=None,depth=0):
        need(type(rows)is list,'actual block inventory list')
        need(depth<=16,'complete block inventory depth bound')
        for row in rows:
            need(type(row)is dict and len(nodes)<256,'complete bounded block tree')
            nodes.append(dict({k:v for k,v in row.items()if k!='children'},observed_parent=parent))
            walk(row.get('children',[]),row['path'],depth+1)
    walk(value['blockdevices'])
    disks=[x for x in nodes if x['type']=='disk'and str(x.get('serial')or'').strip()==TARGET]
    need(len(disks)==1,'one exact fresh virtual installed target serial')
    target=disks[0]
    need(type(target['size'])is int and 12*1024**3<=target['size']<60000000000 and target['ro']in(False,0),
         'actual separate installed target capacity/access')
    parts=[x for x in nodes if x['observed_parent']==target['path']and x['type']=='part']
    media=[x for x in nodes if x['type']=='disk'and str(x.get('serial')or'').strip()=='OPEMOSOUTPUTMEDIA']
    need(len(media)<=1 and (not media or media[0]['path']!=target['path']and media[0]['ro']in(True,1)),
         'installation medium must be distinct and read-only')
    return {'target':target,'partitions':parts,'installation_media':media,'nodes':nodes}


def core_intent(manifest):
    expected=manifest['core_contract']
    need(expected['repository']=='CorniiDog/open-gpu-kernel-modules-steamos-support'and
         re.fullmatch('[0-9a-f]{40}',expected['commit'])and
         re.fullmatch('[0-9a-f]{64}',expected['manifestSHA256']),'exact existing Core source contract')
    # Observe, never interpret/activate/restore private Core state. The normal
    # Core CLI independently verifies policy/current bytes/runtime. These hashes
    # join its ordinary before/after results to the SAME retained generation.
    manager=CORE/'installed-updates'
    pointer_raw,pointer_pin=read(manager/'current.json',4096);pointer=strict(pointer_raw)
    need(set(pointer)=={'generation'}and re.fullmatch(r'txn-[0-9a-f]{32}',pointer['generation']),
         'actual Core current-generation pointer')
    path=manager/pointer['generation']/'intent.json';raw,intent_pin=read(path)
    value=strict(raw)
    def digest(item):return hashlib.sha256(json.dumps(item,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    need(type(value)is dict and all(k in value for k in('phase','kernel','target','authority','files','preparedBootId','attemptBootId')),
         'actual Core retained intent metadata absent')
    again,after_pin=read(manager/'current.json',4096)
    need(again==pointer_raw and after_pin==pointer_pin,'Core selected generation raced')
    return {'kind':'EXE_READ_ONLY_CORE_INTENT_V1','generation':pointer['generation'],
        'pointer':pointer_pin,'intent':intent_pin,'phase':value['phase'],'kernel':value['kernel'],
        'target':value['target'],'preparedBootId':value['preparedBootId'],'attemptBootId':value['attemptBootId'],
        'authoritySHA256':digest(value['authority']),'filesSHA256':digest(value['files']),
        'coreContract':expected,'mutation':False}


def main():
    need(len(sys.argv)==3 and sys.argv[1]in('disks','core-intent'),'one fixed native observation action/manifest')
    environment=guest();manifest=media_manifest(sys.argv[2])
    first=None;value=None
    try:value=disk_tree()if sys.argv[1]=='disks'else core_intent(manifest)
    except Exception as error:first={'type':type(error).__name__,'reason':str(error)[:512]}
    result={'kind':'EXE_STEAMOS_NATIVE_OBSERVATION_V1','guest':environment,'value':value,
            'first':first,'raw_files':RAW_FILES,'transports':TRANSPORTS,'native_VM_acceptance':False}
    raw=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    need(len(raw)<=1048576,'complete native observation cap');sys.stdout.buffer.write(raw+b'\n')
    return 0 if first is None else 1


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('native SteamOS observation failed: '+type(error).__name__,file=sys.stderr)
        raise SystemExit(1)

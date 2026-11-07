#!/usr/bin/python3
"""Controller GitHub + pinned SSH current OMEN observer for Runner21."""
import hashlib,json,os,stat,subprocess,sys,time,types
from pathlib import Path
ROOT=Path('/var/lib/opemos-robot-control-r1/auto-recovery')
SSH=Path('/home/connor/Documents/ChatGPT/Handoff troubleshooting/opemos-scheduler/artifacts/ubuntu-vm-migration/migration-ssh-config')
def need(x,msg):
    if not x:raise RuntimeError(msg)
def sha(x):return hashlib.sha256(x).hexdigest()
def enc(x):return (json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def full9(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def held(path,cap,uid,mode):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_uid==uid and a.st_gid==uid and
             a.st_nlink==1 and stat.S_IMODE(a.st_mode)==mode and 0<a.st_size<=cap,
             'held controller source '+str(path))
        raw=bytearray()
        while b:=os.read(fd,65536):
            raw.extend(b);need(len(raw)<=cap,'controller held source cap')
        need(len(raw)==a.st_size and full9(a)==full9(os.fstat(fd))==
             full9(os.stat(path,follow_symlinks=False)),
             'controller held source identity/EOF '+str(path))
        return bytes(raw)
    finally:os.close(fd)
def module(raw,name):
    m=types.ModuleType(name);m.__file__=name
    exec(compile(raw,name,'exec'),m.__dict__)
    return m
class IdleRunnerStatusTransition(RuntimeError):
    """A genuine idle registration transition needs another full readonly cut."""
    def __init__(self,before,after):
        keys=('runnerOnline','runnerBusy','actionsInProgress')
        self.before={k:before[k]for k in keys};self.after={k:after[k]for k in keys}
        super().__init__('idle Runner21 online/offline transition during current probe: '+json.dumps({'before':self.before,'after':self.after},sort_keys=True))

def require_stable_github(before,after):
    stable=('networkReachable','protectedMain','mainCommit','protectedMainCommit',
            'runnerBusy','actionsInProgress')
    changed=[k for k in stable if after[k]!=before[k]]
    need(not changed,'GitHub non-heartbeat ownership/source changed during OMEN probe: '+','.join(changed))
    if before['runnerOnline']!=after['runnerOnline']:
        need(all(x['runnerBusy']is False and x['actionsInProgress']==0 for x in(before,after)),
             'assigned work changed with Runner21 registration')
        raise IdleRunnerStatusTransition(before,after)

def observe(route_only=False):
    from_source=held(ROOT/'runner21_recovery.py',1048576,0,0o444)
    trigger=module(from_source,'runner21_recovery')
    p=trigger.validate_policy(trigger.strict(held(ROOT/'policy.json',65536,0,0o400)),int(time.time()))
    need(sha(from_source)==p['recoverySourceSHA256'],'current controller wrapper source')
    raw=held(ROOT/'normal_probe.py',1048576,0,0o444)
    need(sha(raw)==p['normalProbeSHA256'],'current remote probe source')
    heartbeat=held(ROOT/'normal_heartbeat.py',1048576,0,0o444)
    need(sha(heartbeat)==p['heartbeatProducerSHA256'],'current heartbeat producer source')
    config=held(SSH,65536,1000,0o600)
    need(sha(config)==p['sshConfigSHA256'],'current pinned existing SSH route')
    m=module(raw,'current_github_and_remote_probe_source')
    github=m.current_github(p,route_only=True)if route_only else m.current_github(p) # existing controller credential only
    prefix=('REMOTE_POLICY='+repr(p)+'\nREMOTE_GITHUB='+repr(github)+
            '\nimport sys\nsys.argv=["reviewed-remote-probe",'+repr('--probe-route'if route_only else'--probe')+']\n').encode()
    source=prefix+raw
    need(len(source)<=1048576,'bounded pinned probe carrier')
    argv=['/usr/sbin/runuser','-u','connor','--','/usr/bin/ssh','-F',str(SSH),'-o','BatchMode=yes',
          '-o','ConnectTimeout=8','opemos-ubuntu-host',
          'sudo -n /usr/bin/python3 -I -B -']
    proc=subprocess.run(argv,input=source,stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,timeout=25,check=False)
    if not(proc.returncode==0 and len(proc.stdout)<=1048576 and
           proc.stderr==b'' and proc.stdout.count(b'\n')==1 and proc.stdout.endswith(b'\n')):
        # This subprocess has actually waited/reaped. Preserve its real stderr
        # separately from the enclosing controller child's traceback/hash.
        raise trigger.failed_probe('controller-ssh',{'numeric':proc.returncode,
            'stdout':proc.stdout,'stderr':proc.stderr,'reaped':True,
            'eof':{'stdout':True,'stderr':True},'first':None})
    v=trigger.strict(proc.stdout)
    trigger.validate_probe(v,p,int(time.time()),route_only=route_only)
    # A second current API read closes the controller-to-OMEN observation.
    after=m.current_github(p,route_only=True)if route_only else m.current_github(p)
    require_stable_github(github,after)
    need(sha(held(SSH,65536,1000,0o600))==p['sshConfigSHA256'] and
         sha(held(ROOT/'normal_probe.py',1048576,0,0o444))==p['normalProbeSHA256'],
         'controller source/SSH changed after remote observation')
    return v
if __name__=='__main__':
    need(sys.argv in([sys.argv[0],'--probe'],[sys.argv[0],'--probe-route'])and os.geteuid()==0,
         'fixed Root controller probe entry')
    print(enc(observe(route_only=sys.argv[1]=='--probe-route')).decode(),end='')

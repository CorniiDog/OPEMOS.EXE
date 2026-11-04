"""Held source/native process/OS lock utilities; no AI coordination APIs."""
import os,sys,json,time,stat,fcntl,hashlib,types,subprocess
from pathlib import Path
F=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def need(v,m):
 if not v:raise RuntimeError(m)

def held(p,sha=None,uid=0):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);a={k:getattr(st,k)for k in F};need(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==uid and st.st_nlink==1,'held exact owner/file')
  raw=b''
  while block:=os.read(fd,65536):raw+=block;need(len(raw)<=8388608,'bounded input')
  need(a=={k:getattr(os.fstat(fd),k)for k in F}=={k:getattr(os.lstat(p),k)for k in F}and len(raw)==st.st_size,'held/named full9/EOF')
  h=hashlib.sha256(raw).hexdigest();need(sha is None or h==sha,'exact held input hash');return raw,dict(path=str(p),bytes=len(raw),sha256=h,identity=a)
 finally:os.close(fd)

def module(raw,name):
 m=types.ModuleType(name);m.__file__=name;exec(compile(raw,name,'exec'),m.__dict__);return m

def put(root,n,v):
 raw=v if type(v)is bytes else(json.dumps(v,sort_keys=True,indent=2)+'\n').encode();p=root/n;fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400)
 try:
  view=memoryview(raw)
  while view:k=os.write(fd,view);need(k>0,'record write');view=view[k:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 return held(p)[1]

def put_diagnostic(root,name,value,errors):
 try:return put(root,name,value)
 except Exception as error:
  errors.append({'stage':name,'type':type(error).__name__,'reason':str(error),'diagnosticOnly':True});return None

def native(owned,root,label,argv,body=None,seconds=30,cap=1048576,allow_stderr=False):
 x=owned.run_owned_command(argv,body,seconds,[root/(label+'-stdout.raw'),root/(label+'-stderr.raw')],stream_limit=cap);diagnostics=[];put_diagnostic(root,label+'-native.json',x,diagnostics)
 if diagnostics:x['optionalReceiptErrors']=diagnostics
 if not(x['numericExit']==0 and x['lifecycleClosed']and(allow_stderr or(root/(label+'-stderr.raw')).stat().st_size==0)):
  error=RuntimeError('actual '+label+' numeric/EOF/reap/FD refusal; numeric='+str(x['numericExit']));error.nativeEvidence=x;raise error
 return x

def manager(unit):
 r=subprocess.run(['/usr/bin/systemctl','show',unit,'-p','LoadState','-p','ActiveState','-p','SubState','-p','MainPID','-p','ControlGroup','-p','InvocationID','-p','UnitFileState','-p','Job'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
 need(r.returncode==0 and not r.stderr,'system manager read');return dict(x.split('=',1)for x in r.stdout.decode().splitlines()if'='in x)

def acquire_recovery_mutex(path,seconds):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);identity={k:getattr(st,k)for k in F}
  need(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,'exact recovery mutex')
  end=time.monotonic()+seconds
  while True:
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
   except BlockingIOError:
    need(time.monotonic()<end,'bounded normal recovery mutex admission; owner untouched');time.sleep(0.1)
  need(identity=={k:getattr(os.fstat(fd),k)for k in F}=={k:getattr(os.lstat(path),k)for k in F},'same held/named recovery mutex after admission')
  return fd
 except BaseException:os.close(fd);raise

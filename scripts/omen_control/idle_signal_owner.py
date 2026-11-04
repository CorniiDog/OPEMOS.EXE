"""Bounded successor of idle retirement: the pidfd owner enforces exact scope."""
import os,signal,stat
from pathlib import Path
LISTENER=b'/home/connor/.local/share/opemos-ci/github-runner/bin/Runner.Listener'

def need(v,m):
 if not v:raise RuntimeError(m)

def selected(row,probe,expected,manager,live,boot):
 need(set(expected)=={'job','unit','invocation','boot','listenerPID','listenerStart','loggerPID','loggerStart'},'exact expected retirement scope')
 need(row['id']==expected['job'] and row['unit']==expected['unit'] and row['state']=='running' and probe['control']['jobId']==expected['job'],'same expected current canonical job/unit')
 need(boot==expected['boot'] and probe['runnerBusy']is False and probe['actionsInProgress']==0 and not probe['guestActive'],'current boot and idle/no queued work at signal owner')
 group='/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/'+expected['unit']
 need(manager['ActiveState']=='active' and manager['InvocationID']==expected['invocation'] and manager['MainPID']==str(expected['loggerPID']) and manager['ControlGroup']==group,'expected current manager invocation/logger/cgroup')
 need(1<=len(live)<=16 and len({x['pid']for x in live})==len(live) and all(x['cgroup']=='0::'+group for x in live),'complete exact own native group')
 logger=[x for x in live if x['pid']==expected['loggerPID']];listeners=[x for x in live if x['argv'][:1]==[LISTENER]]
 need(len(logger)==1 and logger[0]['start']==expected['loggerStart'] and logger[0]['uids']==[1000]*4,'expected logger PID/start/UID')
 need(len(listeners)==1 and listeners[0]['pid']==expected['listenerPID'] and listeners[0]['start']==expected['listenerStart'] and listeners[0]['uids']==[1000]*4 and listeners[0]['argv']==[LISTENER,b'run',b'--startuptype',b'service'],'expected exact listener PID/start/argv/UID')
 need(not any(any(b'Runner.Worker'in z or b'qemu-system-'in z for z in x['argv'])for x in live),'no current build Worker/guest at pidfd owner')
 return listeners[0]

def retire_listener(row,probe,policy,expected,normal,observe_only=False):
 """Same normal pidfd/SIGTERM operation, with required identity at both cuts."""
 def current():
  m=normal.manager(expected['unit']);group=Path('/sys/fs/cgroup')/m['ControlGroup'].lstrip('/')
  need(m['ControlGroup']=='/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/'+expected['unit'] and group.is_dir()and not group.is_symlink(),'exact current expected group')
  pids=[int(x)for x in(group/'cgroup.procs').read_text().splitlines()];need(1<=len(pids)<=16,'bounded complete pidfd-owner actor frontier')
  live=[normal.proc(x)for x in pids];boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  return m,live,selected(row,probe,expected,m,live,boot)
 before=set(os.listdir('/proc/self/fd'));m,live,listener=current();fd=os.pidfd_open(expected['listenerPID'],0)
 try:
  m2,live2,second=current()
  need(second==listener and normal.proc(expected['listenerPID'])==listener,'same expected actor after pidfd open, before signal')
  if not observe_only:signal.pidfd_send_signal(fd,signal.SIGTERM,None,0)
 finally:os.close(fd)
 need(before==set(os.listdir('/proc/self/fd')),'signal-owner FD restoration')
 return dict(pid=listener['pid'],start=listener['start'],unit=expected['unit'],invocation=m2['InvocationID'],exactExpectedScopeCheckedByPIDFDOwner=True,actualSignalSent=not observe_only,pidfdOpenedAndClosed=True,FDSetRestored=True)

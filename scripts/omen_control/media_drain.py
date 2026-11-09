"""Only the authenticated automatic Runner21 generation; normal closure only."""
import os,json,time,re,types,hashlib,fcntl,stat,traceback
from pathlib import Path

def need(v,m):
 if not v:raise RuntimeError(m)
def module(raw,n):
 m=types.ModuleType(n);m.__file__=n;exec(compile(raw,n,'exec'),m.__dict__);return m
def source_bytes(ref):
 fd=os.open(ref['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);i={k:getattr(st,k)for k in ref['identity']};need(i==ref['identity']and st.st_uid==st.st_gid==0 and stat.S_ISREG(st.st_mode)and stat.S_IMODE(st.st_mode)==0o444 and st.st_nlink==1,'installed Root immutable helper');raw=b''
  while b:=os.read(fd,65536):raw+=b;need(len(raw)<=1048576,'source cap')
  need(len(raw)==ref['bytes']and hashlib.sha256(raw).hexdigest()==ref['sha256']and i=={k:getattr(os.fstat(fd),k)for k in i}=={k:getattr(os.lstat(ref['path']),k)for k in i},'whole source full9/EOF/SHA');return raw
 finally:os.close(fd)
def transient_snapshot(error,queue):
 paths={str(queue/'state'/n)for n in('queue.sqlite3','queue.sqlite3-wal','queue.sqlite3-shm')}
 if isinstance(error,FileNotFoundError):return error.filename in paths-{str(queue/'state/queue.sqlite3')}
 return isinstance(error,RuntimeError)and any(str(error).startswith(prefix)for prefix in('queue source changed after private SQL','queue sidecar changed after private SQL','held/named current full9 changed '))and(any(p in str(error)for p in paths)or str(error)in('queue source changed after private SQL','queue sidecar changed after private SQL'))
def snapshot(normal,qraw,end,cuts):
 while True:
  try:return normal.private_queue(qraw)
  except(FileNotFoundError,RuntimeError)as e:
   if not transient_snapshot(e,normal.QUEUE)or time.monotonic()>=end:raise
   cuts.append(dict(type=type(e).__name__,reason=str(e),readOnly=True));time.sleep(.2)
def generation(row,binding,state,p,origins,controller_boot,queue=None):
 need(state['kind']=='RUNNER21_AUTO_RECOVERY_STATE_V1'and state['inflight']is None,'protected controller has no in-flight operation')
 # Current protected lease/source files plus the exact canonical binding and
 # live manager/PIDFD are authority. Historical tick/report formatting is data.
 tx=row['id'].removeprefix('root-github-robot-control-');need(re.fullmatch('[0-9a-f]{32}',tx)is not None,'exact automatic control nonce')
 s=json.loads(row['spec']);root='/var/lib/opemos-robot-control-r1/releases/'+tx
 need(s['id']==row['id']and s['owner']=='root'and s['platform']=='controlplane'and s['cores']==1 and s['memory']==1073741824 and s['resources']==['opemos-robot-controlplane']and s['depends_on']==[],'only exact normal 1CPU/1GiB control job, no VM/build')
 if queue is not None:queue.authenticated_control_window(s)
 else:need(s['timeout_seconds']==21600,'authenticated current queue for finite Root connection')
 need(s['cwd']==root and s['command']==['/usr/bin/python3',root+'/launch.py',root+'/lease.json','/run/user/1000/opemos-robot-control-'+tx],'whole source-pinned original launch command/nonce')
 files=s['files'];expected={'control.py':p['controlBrokerSHA256'],'connection_host.py':p['privatePeerSHA256']}
 if queue is None:expected.update({'host_engine.py':'685de3f64d1ae8cbb1d16ea96ca4830a030679e8d083287a3abaca55414b0505','launch.py':'1d726ad0533fd8d2fee32bbe0d10aa65d69013351abdb3ced901b7e3ba5fd9f9'})
 need(len(files)==5 and {f['path']for f in files}=={root+'/'+n for n in(*expected,'host_engine.py','launch.py','lease.json')},'exact five normal generated source roles')
 for f in files:
  if Path(f['path']).name in expected:need(f['sha256']==expected[Path(f['path']).name],'exact current implementation source graph')
 need(binding['job_id']==row['id']and binding['unit']==row['unit']and binding['memory']==1073741824 and binding['cpus']==[0]and re.fullmatch('[0-9a-f]{32}',binding['invocation'])is not None,'canonical source/resource/unit binding')
 return tx,s,dict(kind='CURRENT_PROTECTED_CONTROL_SOURCE_AND_CANONICAL_BINDING',jobId=row['id'],unit=row['unit'],invocation=binding['invocation'])
def retirement_required(row,control):
 if row['state']=='running':return True
 need(row['state']in('passed','failed','timed_out','blocked','output_limit')and row['finished']is not None and control['terminalLifecycle']=='CLOSED'and control['reservationRetained']is False,'only normal completed/released continuation, no pending/unknown replay')
 return False
def finish_original_worker(row,N,C,qraw,policy,end,transients):
 # Observe normal process completion first. No queue/lease/process mutation.
 innerCuts=[]
 while True:
  manager=C.manager(row['unit']);innerCuts.append(manager)
  if manager.get('MainPID')=='0'and manager.get('ControlGroup')==''and manager.get('ActiveState')in('inactive','failed'):break
  need(time.monotonic()<end,'normal original unit closure deadline; never repeat signal');time.sleep(.5)
 tx=row['id'].removeprefix('root-github-robot-control-');outer='opemos-root-robot-dispatcher-'+tx+'.service'
 while True:
  r=C.run(C.USER_ENV+['/usr/bin/systemctl','--user','show',outer,'-p','ActiveState','-p','MainPID','-p','ControlGroup'],timeout=10);need(r.returncode==0 and not r.stderr,'normal outer worker manager read');props=dict(x.split('=',1)for x in r.stdout.decode().splitlines()if'='in x)
  if props.get('MainPID')=='0'and props.get('ControlGroup')==''and props.get('ActiveState')in('inactive','failed'):break
  need(time.monotonic()<end,'normal outer worker completion deadline');time.sleep(.5)
 locks=[]
 for path in(N.QUEUE/'state/worker.lock',Path('/run/user/1000/opemos-heavy.lock')):
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);need(stat.S_ISREG(st.st_mode)and st.st_uid==1000 and st.st_nlink==1,'exact original lock inode custody');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(dict(path=str(path),dev=st.st_dev,ino=st.st_ino,free=True))
  finally:os.close(fd)
 # The unchanged full reader is mandatory. Unknown or semantic proof failure
 # here is final; it is never retried or converted into authority.
 rows,binds,cfg=snapshot(N,qraw,end,transients);matches=[r for r in rows if r['id']==row['id']];need(len(matches)==1,'exact selected original row retained after worker closure');closed=matches[0];status=N.current_control(closed,policy)
 need(closed['finished']is not None and status['terminalLifecycle']=='CLOSED'and status['reservationRetained']is False,'unchanged full canonical pool+normal terminal release proof after worker/locks closed')
 return dict(closedRow=closed,closedManager=manager,innerCuts=innerCuts,outerManager=props,locks=locks,normalClosureComplete=True,fullPoolProofRequestedOnlyAfterWorkerAndLocksClosed=True)
def execute(data):
 p=data['policy'];rule=data['rule'];gh=data['github'];need(os.getuid()==os.geteuid()==0,'Root normal controller peer')
 need(rule==dict(kind='ROOT_AUTOMATIC_RUNNER21_ONLY_CURRENT_GENERATION',runnerId=21,mainCommit=p['mainCommit'],queueSHA256=p['queueSourceSHA256'],boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()),'exact actual current automatic generation/source rule')
 need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==rule['boot']and p['mainCommit']==rule['mainCommit']and p['queueSourceSHA256']==rule['queueSHA256']and p['runnerId']==21,'same host/source/registered runner')
 need(gh['networkReachable']and gh['mainCommit']==rule['mainCommit']and gh['runnerBusy']is False and type(gh['actionsInProgress'])is int and gh['actionsInProgress']==0 and 0<=time.time()-data['probeAt']<=15,'authenticated fresh installed-controller identity and Runner21 idle facts')
 mods={}
 for n,k in(('normal_probe','normalProbeSHA256'),('normal_cycle','normalCycleSHA256')):
  ref=data['installedSources'][n];raw=source_bytes(ref);need(hashlib.sha256(raw).hexdigest()==p[k],'exact installed normal helper source');mods[n]=module(raw,ref['path'])
 N=mods['normal_probe'];N.REMOTE_POLICY=p;C=mods['normal_cycle'];ref=data['installedSources']['signalOwner'];raw=source_bytes(ref);owner=module(raw,ref['path'])
 before=set(os.listdir('/proc/self/fd'));_,_,qraw=N.local_sources(p);transients=[];rows,binds,cfg=snapshot(N,qraw,time.monotonic()+8,transients);row,foreign,unknown=N.classify_rows(rows,binds,p);need(row and not foreign and not unknown,'sole authenticated normal generation; preserve foreign work')
 bb=[b for b in binds if b['job_id']==row['id']];need(len(bb)==1,'one canonical binding');binding=json.loads(bb[0]['value']);Q=module(qraw,str(N.QUEUE/'test_queue.py'));tx,spec,origin=generation(row,binding,data['recoveryState'],p,data['controllerOrigins'],data['controllerBoot'],Q)
 for f in spec['files']:
  raw,_=N.held(Path(f['path']),1048576,0);need(len(raw)==f['bytes']and N.sha(raw)==f['sha256'],'actual immutable per-generation source/lease bytes')
 lease=json.loads(N.held(Path(spec['command'][2]),65536,0)[0]);need(lease['kind']=='OPEMOS_ROBOT_FIXED_CONTROL_LEASE'and lease['runtimeAuthorized']is True and lease['runnerId']==21 and lease['repository']=='CorniiDog/OPEMOS.EXE'and lease['engine_source_commit']==p['mainCommit']and lease['connection_queue_sha256']==p['queueSourceSHA256'],'exact current Root normal control lease semantics')
 ctl=N.current_control(row,p);need(ctl['brokerSHA256']==p['controlBrokerSHA256'],'current broker only; historical approvals not transferred');actors=N.actors();need(not any(any('Runner.Worker'in z or'qemu-system-'in z for z in a['argv'])for a in actors),'no current Worker or guest')
 if row['state']=='running':need(type(ctl['leaseExpiresUnix'])in(int,float)and time.time()<ctl['leaseExpiresUnix'],'actual running generation still within finite normal lease')
 result=dict(kind='CURRENT_NORMAL_CONTROL_PRIORITY_TRANSITION',job=row['id'],scope=None,initialState=row['state'],signalReplayed=False,first=None,snapshotTransients=transients,operationalEffect=False,controllerGenerationOrigin=origin)
 try:
  if retirement_required(row,ctl):
   need(gh['runnerOnline'],'running listener must be authenticated online')
   manager=C.manager(row['unit']);need(manager['InvocationID']==binding['invocation'],'current manager/canonical invocation')
   group=manager['ControlGroup'];own=[C.proc(a['pid'])for a in actors if row['unit']in a['cgroup']];listeners=[a for a in own if a['argv'][:1]==[owner.LISTENER]];need(len(listeners)==1,'one real current normal listener')
   logger=C.proc(int(manager['MainPID']));listener=listeners[0]
   scope=dict(job=row['id'],unit=row['unit'],invocation=binding['invocation'],boot=rule['boot'],loggerPID=logger['pid'],loggerStart=logger['start'],listenerPID=listener['pid'],listenerStart=listener['start']);result['scope']=scope
   probe=dict(gh,control=ctl,guestActive=False);need(time.time()-data['probeAt']<=15,'fresh before actual scoped native operation')
   result['retirement']=owner.retire_listener(row,probe,p,scope,C,observe_only=data['mode']!='execute');result['operationalEffect']=data['mode']=='execute'
  else:need(ctl['terminalLifecycle']=='CLOSED'and ctl['reservationRetained']is False and not any(row['unit']in a['cgroup']for a in actors),'already-CLOSED generation, never resignal')
  if data['mode']=='execute' or row['state']!='running':
   result.update(finish_original_worker(row,N,C,qraw,p,time.monotonic()+180,transients))
 except BaseException as e:result['first']=dict(type=type(e).__name__,reason=str(e),traceback=traceback.format_exc())
 result['FDSetRestored']=before==set(os.listdir('/proc/self/fd'));need(result['FDSetRestored'],'all observation/pidfd/lock FDs closed');return result

if __name__=='__main__':
 import sys,argparse
 ap=argparse.ArgumentParser();ap.add_argument('--profile-pin-json',required=True);args=ap.parse_args();profile=json.loads(source_bytes(json.loads(args.profile_pin_json)));need(profile['kind']=='OPEMOS_INSTALLED_MEDIA_DRAIN_V1'and profile['entryPin']['path']==str(Path(__file__).absolute()),'installed drain profile/actual entry');source_bytes(profile['entryPin'])
 raw=sys.stdin.buffer.read(1048577);need(len(raw)<=1048576,'bounded typed drain request');DATA=json.loads(raw);need(DATA['installedSources']==profile['installedSources']and DATA['policy']==profile['policy'],'installed controller policy/source contract, no executable body in per-run data');result=execute(DATA);print(json.dumps(result,sort_keys=True),flush=True)
 if result['first']is not None:raise RuntimeError('normal transition incomplete; full first/retirement retained above')

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
def generation(row,binding,state,p,origins,controller_boot):
 need(state['kind']=='RUNNER21_AUTO_RECOVERY_STATE_V1'and state['inflight']is None,'protected controller has no in-flight operation')
 # Current protected lease/source files plus the exact canonical binding and
 # live manager/PIDFD are authority. Historical tick/report formatting is data.
 tx=row['id'].removeprefix('root-github-robot-control-');need(re.fullmatch('[0-9a-f]{32}',tx)is not None,'exact automatic control nonce')
 s=json.loads(row['spec']);root='/var/lib/opemos-robot-control-r1/releases/'+tx
 need(s['id']==row['id']and s['owner']=='root'and s['platform']=='controlplane'and s['cores']==1 and s['memory']==1073741824 and s['resources']==['opemos-robot-controlplane']and s['timeout_seconds']==21600 and s['depends_on']==[],'only exact normal 1CPU/1GiB control job, no VM/build')
 need(s['cwd']==root and s['command']==['/usr/bin/python3',root+'/launch.py',root+'/lease.json','/run/user/1000/opemos-robot-control-'+tx],'whole source-pinned original launch command/nonce')
 files=s['files'];expected={'control.py':p['controlBrokerSHA256'],'connection_host.py':p['privatePeerSHA256'],'host_engine.py':'685de3f64d1ae8cbb1d16ea96ca4830a030679e8d083287a3abaca55414b0505','launch.py':'1d726ad0533fd8d2fee32bbe0d10aa65d69013351abdb3ced901b7e3ba5fd9f9'}
 need(len(files)==5 and {f['path']for f in files}=={root+'/'+n for n in(*expected,'lease.json')},'exact five normal generated source roles')
 for f in files:
  if Path(f['path']).name in expected:need(f['sha256']==expected[Path(f['path']).name],'exact current implementation source graph')
 need(binding['job_id']==row['id']and binding['unit']==row['unit']and binding['memory']==1073741824 and binding['cpus']==[0]and re.fullmatch('[0-9a-f]{32}',binding['invocation'])is not None,'canonical source/resource/unit binding')
 return tx,s,dict(kind='CURRENT_PROTECTED_CONTROL_SOURCE_AND_CANONICAL_BINDING',jobId=row['id'],unit=row['unit'],invocation=binding['invocation'])
def retirement_required(row,control):
 if row['state']=='running':return True
 need(row['state']in('passed','failed','timed_out','blocked','output_limit')and row['finished']is not None and control['terminalLifecycle']=='CLOSED'and control['reservationRetained']is False,'only normal completed/released continuation, no pending/unknown replay')
 return False
def pending_root_observation(N,C,policy,parent_pin,worker=None,qraw=b''):
 # Existing health_queue authenticates the COMPLETE selected graph before any
 # sibling executes. The selected old runtime_entry is immutable DATA; this
 # pre-stop reader needs only its already existing Root/contract primitives.
 import sys
 before=set(os.listdir('/proc/self/fd'));started=time.monotonic()
 ref=policy['healthImplementationDefinitionPin'];raw=N.health_source(ref);definition=json.loads(raw)
 with N.health_queue(qraw,implementation_pin=ref)as queue:
  shared=sys.modules['source_contract'];peer=sys.modules['libvirt_peer'];access=sys.modules['libvirt_access']
  need(shared.read_definition(ref)==definition,'same actual selected health graph')
  parent=json.loads(N.health_source(parent_pin));paths=shared.parent_paths(parent)
  shared.validate(parent['sourceRoles'],parent['queuePrograms'],parent['installedSourceContractPin'])
  nonce=parent['nonce'];boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  need(parent['kind']=='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT'and parent['RootIssued']is True
       and parent_pin['path']==paths['parentPath']and parent['bootID']==parent['candidate']['hostBoot']==boot
       and nonce==parent['candidate']['nonce'],'same original finite parent/boot/nonce')
  need(parent['issuedUnix']<parent['startBeforeUnix']<=parent['issuedUnix']+300
       and parent['startBeforeUnix']<=time.time(),'original finite parent actually expired')
  adapter=types.ModuleType('authenticated_current_embedded_parent_reader')
  adapter.__file__=queue.__file__+'#embedded-current-adapter'
  exec(compile(queue.R109_CURRENT_ADAPTER,adapter.__file__,'exec'),adapter.__dict__)
  spec=adapter.parent_spec(parent,parent_pin)
  def absent_lease():
   with access.Held('/run')as run:
    run.check()
    try:os.stat('opemos-vfio-'+nonce,dir_fd=run.fd,follow_symlinks=False)
    except FileNotFoundError:pass
    else:need(False,'pending original physical lease exists; no closure inference')
    run.check()
  absent_lease();runtime_pin=None;lock_pin=None;runtime=Path(paths['runtimeRoot'])
  try:os.lstat(runtime)
  except FileNotFoundError:pass
  else:
   with peer.RootFiles(runtime)as files,files.lock(False,time.monotonic()+2):
    need(sorted(os.listdir(files.fd))==['lock'],'pending runtime contains context/assignment/grant or unknown data')
    lock_raw,lock_pin=files.read('lock',0o600,4096);need(lock_raw==peer.canon({}),'original canonical normal runtime lock bytes')
    runtime_pin=files.parent_pin();absent_lease();files.check()
  reader=peer.NativeOps()
  try:need(reader.domains()==[],'actual no domain before pending idle-worker stop')
  finally:reader.close()
  value={'kind':'ROOT_EXPIRED_PENDING_NO_RUNTIME_PUBLICATION_V1',
      'request':{'parentPin':parent_pin,'implementationDefinitionPin':ref},'bootID':boot,
      'jobId':parent['jobId'],'nonce':nonce,'normalizedSpecSHA256':hashlib.sha256(peer.canon(spec)).hexdigest(),
      'runtimeRootPin':runtime_pin,'lockIdentity':None if lock_pin is None else lock_pin['identity'],
      'physicalLeaseAbsent':True,'contextAssignmentGrantAbsent':True,'effects':[],
      'startedMonotonic':started}
  if worker is not None:
   actor=peer.process(worker['pid'])
   expected={'pid':worker['pid'],'start':worker['start'],'uid':1000,
             'cgroup':worker['cgroup'].removeprefix('0::'),'argv':[os.fsdecode(x)for x in worker['argv']]}
   need(all(actor[k]==v for k,v in expected.items()),'same source-bound idle worker')
   value['workerLockProof']=peer.verify_worker_lock(parent['workerLockPin'],parent['workerStatePin'],parent['workerLockMode'],actor)
  need(json.loads(N.health_source(parent_pin))==parent,'original parent whole/full9 unchanged')
 need(N.health_source(ref)==raw and before==set(os.listdir('/proc/self/fd')),'complete selected graph/Root FD closure')
 value.update(allOwnedDescriptorsClosed=True,completedMonotonic=time.monotonic())
 return value


def current_dispatcher_context(row,origin,state):
 # Ordinary typed context for an already authenticated current generation;
 # never rewrite preserved Root error/backoff/lastOutcome history.
 need(origin['kind']=='CURRENT_PROTECTED_CONTROL_SOURCE_AND_CANONICAL_BINDING'
      and origin['jobId']==row['id']and origin['unit']==row['unit'],
      'existing authenticated current source/canonical generation')
 tx=row['id'].removeprefix('root-github-robot-control-')
 need(re.fullmatch('[0-9a-f]{32}',tx)is not None,'exact actual current control nonce')
 old=state.get('lastOutcome',{});recorded=old.get('controlJobId',old.get('jobId'))
 need(recorded is None or recorded==row['id'],'conflicting recorded current generation')
 need(old.get('dispatcherNonce',tx)==tx,'conflicting recorded current dispatcher')
 return {'lastOutcome':{'controlJobId':row['id'],'dispatcherNonce':tx}}


def idle_pending_actors(actors):
 need(not any(any('Runner.Worker'in z or 'qemu-system-'in z for z in a['argv'])for a in actors),
      'no current assigned Worker or QEMU before owned worker retirement')

def pending_dispatcher_scope(ref,actor,pids):
 need(ref.get('worker')is not None and ref['pid']>1 and ref['start']is not None,
      'actual source-bound original dispatcher and worker required')
 worker=ref['worker'];need(actor['pid']==worker['pid']and actor['start']==worker['start']
      and actor['cgroup']==worker['cgroup']and actor['uids']==[1000]*4
      and pids==[worker['pid']],'one exact idle owned worker; no other task/helper')
 group=actor['cgroup'].removeprefix('0::');scope=Path(group)
 need(actor['cgroup'].startswith('0::/user.slice/user-1000.slice/user@1000.service/opemos.slice/opemos-heavy.slice/run-')
      and scope.parent.name=='opemos-heavy.slice'and re.fullmatch(r'run-[A-Za-z0-9]+\.scope',scope.name),
      'existing exact owned user heavy scope only')
 return scope.name

def existing_heavy_ofd(N,C,ref):
 # Reuse the existing Bash-held OFD model. No lock acquisition or mutation.
 path=Path('/run/user/1000/opemos-heavy.lock');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  ident=lambda value:{k:getattr(value,k)for k in fields};initial=ident(st)
  need(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==1000 and st.st_nlink==1 and st.st_size==0,
       'existing ordinary empty UID1000 heavy lock')
  parent=C.proc(ref['pid']);need(parent['start']==ref['start']and parent['uids']==[1000]*4
       and len(parent['argv'])>1 and parent['argv'][1]==str(N.QUEUE/'heavy.sh').encode(),
       'same actual source-bound Bash heavy wrapper')
  records=[]
  for pid in(ref['pid'],ref['worker']['pid']):
   found=[];items=list((Path('/proc')/str(pid)/'fd').iterdir());need(len(items)<=16384,'finite heavy-owner descriptors')
   for item in items:
    try:
     obj=item.stat()
     if(obj.st_dev,obj.st_ino)!=(st.st_dev,st.st_ino):continue
     for line in(Path('/proc')/str(pid)/'fdinfo'/item.name).read_text().splitlines():
      if not line.startswith('lock:'):continue
      row=line.split('lock:',1)[1].split()
      if len(row)<8 or row[1]!='FLOCK'or row[3]!='WRITE':continue
      major,minor,inode=row[5].split(':')
      if(int(major,16),int(minor,16),int(inode))==(os.major(st.st_dev),os.minor(st.st_dev),st.st_ino):
       found.append({'fd':int(item.name),'kernelOFDRecord':row})
    except FileNotFoundError:continue
   need(len(found)==1,'one real original heavy OFD in parent and worker');records.append({'pid':pid,**found[0]})
  need(records[0]['kernelOFDRecord']==records[1]['kernelOFDRecord']and C.proc(ref['pid'])==parent
       and initial==ident(os.fstat(fd))==ident(path.lstat()),'same original inherited heavy OFD/parent/named inode')
  return {'path':str(path),'identity':initial,'OFDs':records}
 finally:os.close(fd)

def close_idle_pending_dispatcher(row,N,C,qraw,policy,state,parent_pin,end,transients,origin):
 # A pending parent cannot make the old source worker exit naturally. Only
 # after its control job completed normally may the owning manager stop this
 # exact idle scope. No direct signal, unit creation, queue edit or VM action.
 rows,binds,cfg=snapshot(N,qraw,end,transients)
 closed=next(r for r in rows if r['id']==row['id']);status=N.current_control(closed,policy)
 need(closed['finished']is not None and status['terminalLifecycle']=='CLOSED'
      and status['reservationRetained']is False,'normal control canonical closure before worker stop')
 pending=[r for r in rows if r['state']not in('passed','failed','timed_out','blocked','output_limit')]
 need(len(pending)==1 and pending[0]['state']=='pending'
      and all(pending[0][k]is None for k in('unit','cpus','started','finished','result'))
      and not any(b['job_id']==pending[0]['id']for b in binds),
      'sole never-allocated pending row and no invocation binding')
 context=current_dispatcher_context(row,origin,state)
 ref=C.owning_dispatcher(row,policy,context);actor=C.proc(ref['worker']['pid'])
 proof=pending_root_observation(N,C,policy,parent_pin,actor,qraw)
 need(proof['workerLockProof']['verified']is True,'actual original worker exclusive FLOCK/FD/ancestry')
 need(proof['jobId']==pending[0]['id']and proof['normalizedSpecSHA256']==hashlib.sha256(pending[0]['spec'].encode()).hexdigest(),
      'whole actual pending spec equals authenticated expired original parent')
 idle_pending_actors(N.actors())
 group=Path('/sys/fs/cgroup')/actor['cgroup'].removeprefix('0::').lstrip('/')
 pids=sorted(int(v)for v in(group/'cgroup.procs').read_text().split())
 scope=pending_dispatcher_scope(ref,actor,pids);heavy=existing_heavy_ofd(N,C,ref)
 need(snapshot(N,qraw,end,transients)==(rows,binds,cfg)and C.owning_dispatcher(row,policy,context)==ref
      and C.proc(actor['pid'])==actor and sorted(int(v)for v in(group/'cgroup.procs').read_text().split())==pids
      and existing_heavy_ofd(N,C,ref)==heavy,
      'same complete ledger/current owned worker/source/manager before normal stop')
 import select
 lifetime=os.pidfd_open(actor['pid'],0)
 try:
  need(C.proc(actor['pid'])==actor and not select.select([lifetime],[],[],0)[0],
       'same original live worker pidfd immediately before normal manager stop')
  result=C.run(C.USER_ENV+['/usr/bin/systemctl','--user','stop',scope],timeout=min(30,max(.001,end-time.monotonic())),cap=8192)
  need(result.returncode==0 and not result.stdout and not result.stderr,'normal exact idle worker scope stop failed')
 finally:os.close(lifetime)
 while not C.dispatcher_closed(ref):
  need(time.monotonic()<end,'original dispatcher/worker closure remains unknown; never repeat stop');time.sleep(.1)
 need(snapshot(N,qraw,end,transients)==(rows,binds,cfg),'all canonical rows/bindings/config preserved by manager stop')
 return {'kind':'NORMAL_EXACT_IDLE_DISPATCHER_SCOPE_STOP_FOR_EXPIRED_PENDING',
         'dispatcher':ref,'scope':scope,'originalHeavyOFD':heavy,'pendingJob':pending[0]['id'],'parentPin':parent_pin,
         'RootPendingObservation':proof,'canonicalRowsChanged':False,'VMOrGPUAction':False,
         'nativeHistoricalClosureClaimed':False,'normalManagerStopNumeric':result.returncode,
         'originalWorkerPIDFDOpenedAndClosed':True}


def finish_original_worker(row,N,C,qraw,policy,end,transients,pending=None,state=None,origin=None):
 # Observe normal process completion first. No queue/lease/process mutation.
 innerCuts=[]
 while True:
  manager=C.manager(row['unit']);innerCuts.append(manager)
  if manager.get('MainPID')=='0'and manager.get('ControlGroup')==''and manager.get('ActiveState')in('inactive','failed'):break
  need(time.monotonic()<end,'normal original unit closure deadline; never repeat signal');time.sleep(.5)
 stopped=None
 if pending is not None:
  need(state is not None,'original protected normal recovery state')
  stopped=close_idle_pending_dispatcher(row,N,C,qraw,policy,state,pending,end,transients,origin)
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
 return dict(closedRow=closed,closedManager=manager,innerCuts=innerCuts,outerManager=props,locks=locks,normalClosureComplete=True,fullPoolProofRequestedOnlyAfterWorkerAndLocksClosed=True,idlePendingDispatcherStop=stopped)
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
 bb=[b for b in binds if b['job_id']==row['id']];need(len(bb)==1,'one canonical binding');binding=json.loads(bb[0]['value']);tx,spec,origin=generation(row,binding,data['recoveryState'],p,data['controllerOrigins'],data['controllerBoot'])
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
   result.update(finish_original_worker(row,N,C,qraw,p,time.monotonic()+180,transients,data.get('expiredPendingParentPin'),data['recoveryState'],origin))
 except BaseException as e:result['first']=dict(type=type(e).__name__,reason=str(e),traceback=traceback.format_exc())
 result['FDSetRestored']=before==set(os.listdir('/proc/self/fd'));need(result['FDSetRestored'],'all observation/pidfd/lock FDs closed');return result

if __name__=='__main__':
 import sys,argparse
 ap=argparse.ArgumentParser();ap.add_argument('--profile-pin-json',required=True);args=ap.parse_args();profile=json.loads(source_bytes(json.loads(args.profile_pin_json)));need(profile['kind']=='OPEMOS_INSTALLED_MEDIA_DRAIN_V1'and profile['entryPin']['path']==str(Path(__file__).absolute()),'installed drain profile/actual entry');source_bytes(profile['entryPin'])
 raw=sys.stdin.buffer.read(1048577);need(len(raw)<=1048576,'bounded typed drain request');DATA=json.loads(raw);need(DATA['installedSources']==profile['installedSources']and DATA['policy']==profile['policy'],'installed controller policy/source contract, no executable body in per-run data');result=execute(DATA);print(json.dumps(result,sort_keys=True),flush=True)
 if result['first']is not None:raise RuntimeError('normal transition incomplete; full first/retirement retained above')

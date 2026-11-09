MACHINE_PREFLIGHT_ABI='OPEMOS_VM_MACHINE_PREFLIGHT_R104'
"""Exact no-effect Root preflight producer, no grant/binding issuance.

Only an independently adopted expectation and current protected Control pin are
inputs. Original queue SQLite is hashed O_RDONLY, NEVER opened by SQLite; the
already approved same-byte immutable private snapshot is the only SQL operand.
Output is a bounded protected receipt, never a replacement for source admission.
"""
import hashlib,importlib.util,json,os,sqlite3,stat,time
from pathlib import Path
import libvirt_peer as p
from libvirt_native import held
from libvirt_access import Held,hashfd

QUEUE_SHA='ec8a377b96a4c7b1bac2edab75183011e3c8aad9efeb51130b18d61c42d47e42'
CONTROL_QUEUE_SHA='16177e18b25de4b5b4a45849f5eddb7f7b58527f7d3425d48849927d5843103e'
HISTORY_SHA='03f36772612aabffdbe6be6b76f4353402797fd9e17d4896ced3739de7b6f1c3'

def measured(ref,cap,rootOnly=True,carrier_custody=None):
 if not rootOnly:
  fds=[];shared=[];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd);paths=[('/',fd,p.ident(os.fstat(fd)))];current=Path('/')
  try:
   for name in Path(ref['path']).parts[1:]:
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);fds.append(fd);current=current/name;row=p.ident(os.fstat(fd));admission=__import__('guest_firmware_probe').carrier_shared_ancestor(ref,str(current),fd,row);p.need((row['st_uid']in(0,1000)and not(row['st_mode']&0o022))or admission is not None,'pinned source ancestor permissions');shared.extend([]if admission is None else[(fd,admission)]);paths.append((str(current),fd,row))
   p.need(paths[-1][2]==ref['identity'],'genuine UID1000 or Root operand initial full9');n,d=hashfd(fd);p.need((n,d)==(ref['bytes'],ref['sha256']),'complete UID1000 operand bytes/hash')
   for name,fd,old in paths:p.need(old==p.ident(os.fstat(fd))==p.ident(os.lstat(name)),'every source ancestor/leaf full9 FD/name unchanged')
   custody=__import__('guest_firmware_probe').finish_carrier_ancestry(ref,shared,fd)
   if carrier_custody is not None:p.need(type(carrier_custody)is dict and not carrier_custody,'empty explicit custody output only');carrier_custody.update({}if custody is None else custody)
   return dict(ref)
  finally:
   for fd in fds[::-1]:os.close(fd)
 with Held(ref['path'])as obj:
  old=obj.check();p.need(old==ref['identity']and stat.S_ISREG(old['st_mode'])and old['st_nlink']==1 and old['st_size']<=cap,'exact initial leaf/full9/cap')
  n,d=hashfd(obj.fd);p.need(n==ref['bytes']and d==ref['sha256']and obj.check()==old,'exact full content/FD/name pin')
  return dict(ref)

def disk_capture(ref,proof,boot,rootOnly=True,candidate=None):
 # proof is a separately Root-adopted protected capture. Never re-stamp its
 # start/end or infer remote numeric status from local process disappearance.
 p.need(proof['kind']in('ROOT_LIBVIRT_R7_COMPLETE_DISK_CAPTURE','ROOT_CURRENT_HELD_INPROCESS_DISK_CAPTURE')and proof['bootID']==boot,'exact adopted same-boot full disk capture')
 p.need(proof['before']==ref==proof['after']==proof['fullPin'],'full disk bytes/SHA/full9 before and after')
 p.need(proof['bytesRead']==ref['bytes']and proof['EOF']is True and proof['readOnly']is True and proof['FDSetRestored']is True and proof['children']==[],'whole disk/EOF/FD/child proof')
 if proof['kind']=='ROOT_LIBVIRT_R7_COMPLETE_DISK_CAPTURE':
  p.need(proof['numeric']==0 and proof['stdoutEOF']is True and proof['stderrEOF']is True and proof['reaped']is True and proof['originalAbsent']is True,'actual bounded transport complete, no UNKNOWN adoption')
 else:
  p.need(proof.get('childCreated')is False and proof.get('sameProcessRead')is True and not any(k in proof for k in('numeric','reaped','stdoutEOF','stderrEOF','originalAbsent')),'in-process FD proof must not fabricate a transport child')
 p.need(proof['startedUnix']<=proof['finishedUnix']and proof['finishedUnix']-proof['startedUnix']<=70,'unchanged single-capture run bound')
 if rootOnly:
  cm=__import__('libvirt_access').held_disk(candidate,'working',ref)if candidate is not None and ref==candidate['working']else Held(ref['path'])
  with cm as h:p.need(h.check()==ref['identity'],'full disk capture still names same full9 object')
 else:
  p.need(ref['bytes']==8121049088 and ref['sha256']=='2fc5f2b8992f93deccf66e79133c6ceeb9d8ec2acda82c12ac641dc65cf7a193'and ref['identity']['st_uid']==ref['identity']['st_gid']==1000,'only exact authenticated UID1000 carrier capture role')
  __import__('guest_firmware_probe').validate_carrier_custody(ref,proof.get('carrierMountCustody'),boot);fds=[];shared=[];paths=[];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd);paths.append(('/',fd,p.ident(os.fstat(fd))));at=Path('/')
  try:
   for part in Path(ref['path']).parts[1:]:
    fd=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);fds.append(fd);at=at/part;s=p.ident(os.fstat(fd));admission=__import__('guest_firmware_probe').carrier_shared_ancestor(ref,str(at),fd,s);p.need((s['st_uid']in(0,1000)and not(s['st_mode']&0o022))or admission is not None,'exact source ancestor permissions');shared.extend([]if admission is None else[(fd,admission)]);paths.append((str(at),fd,s))
   p.need(paths[-1][2]==ref['identity'],'current original carrier exact full9 after full capture')
   for path,fd,old in paths:p.need(old==p.ident(os.fstat(fd))==p.ident(os.lstat(path)),'every held/named carrier ancestor stable')
   __import__('guest_firmware_probe').finish_carrier_ancestry(ref,shared,paths[-1][1])
  finally:
   for fd in fds[::-1]:os.close(fd)
 return dict(ref)


def quiet_db_family(original):
 """Authenticate a logical DB-only cut with optional empty WAL/cache DATA.

 SQLite is never opened on the source. A nonempty WAL or rollback journal
 cannot be represented by this same-byte immutable reader and still refuses.
 """
 p.need(Path(original['path']).name=='queue.sqlite3'and original['bytes']<=67108864,'exact adopted finite queue database role')
 measured(original,67108864,False);family={'database':dict(original)}
 for suffix,cap in(('-wal',8388608),('-shm',1048576),('-journal',8388608)):
  path=Path(original['path']+suffix)
  if not os.path.lexists(path):family[suffix]=None;continue
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   i=p.ident(os.fstat(fd));p.need(stat.S_ISREG(i['st_mode'])and i['st_nlink']==1 and i['st_uid']==i['st_gid']==original['identity']['st_uid']==1000 and not stat.S_IMODE(i['st_mode'])&0o022 and i['st_size']<=cap,'single protected current SQLite family role')
   n,h=hashfd(fd);p.need(n==i['st_size']and p.ident(os.fstat(fd))==p.ident(os.lstat(path))==i,'full sidecar bytes/hash/held-name equality');ref=dict(path=str(path),identity=i,bytes=n,sha256=h)
  finally:os.close(fd)
  p.need(suffix!='-journal','rollback journal cannot enter immutable DB-only snapshot')
  if suffix=='-wal':p.need(n==0 and h==hashlib.sha256(b'').hexdigest(),'nonempty WAL requires normal complete-family snapshot; never ignore committed data')
  family[suffix]=ref
 for suffix,ref in family.items():
  if suffix=='database':continue
  if ref is None:p.need(not os.path.lexists(original['path']+suffix),'SQLite family appearance during cut')
  else:measured(ref,1048576 if suffix=='-shm'else 8388608,False)
 measured(original,67108864,False);return family

def private_values(original,private,index,reader):
 # A plain copy cannot be called current: complete source bytes must match,
 # and the retained protected index binds the exact separately held snapshot.
 p.need(original['path']!=private['path']and(original['identity']['st_dev'],original['identity']['st_ino'])!=(private['identity']['st_dev'],private['identity']['st_ino']),'private snapshot is distinct from original')
 p.need(original['bytes']==private['bytes']and original['sha256']==private['sha256'],'lossless exact original/private bytes')
 measured(original,67108864,False);measured(private,67108864,False)
 idx=json.loads(held(index,1048576))
 def no_sidecars():
  if idx.get('kind')=='ROOT_CURRENT_EMPTY_WAL_SNAPSHOT_INDEX':
   p.need(set(idx)=={'kind','originalPin','privatePin','sqlOnOriginal','knownClosed','originalFamily'},'exact whole-family private index schema')
   p.need(quiet_db_family(original)==idx['originalFamily'],'entire current original family full9/hash equals authenticated producer cut')
   refs=(private,)
  else:refs=(original,private)
  for ref in refs:
   for suffix in('-wal','-shm','-journal'):p.need(not os.path.lexists(ref['path']+suffix),'DB-only immutable reader refuses any unproved original/private sidecar '+ref['path']+suffix)
 no_sidecars();p.need(idx['originalPin']==original and idx['privatePin']==private and idx['sqlOnOriginal']is False and idx['knownClosed']is True,'exact private snapshot custody/closure index')
 fd=os.open(private['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);conn=None
 try:
  p.need(p.ident(os.fstat(fd))==private['identity']==p.ident(os.lstat(private['path'])),'held private source full9')
  conn=sqlite3.connect('file:/proc/self/fd/'+str(fd)+'?mode=ro&immutable=1',uri=True,timeout=1);conn.row_factory=sqlite3.Row;conn.execute('PRAGMA query_only=ON');conn.execute('PRAGMA trusted_schema=OFF');conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,8388608);conn.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH,65536);conn.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED,0)
  end=time.monotonic()+10;conn.set_progress_handler(lambda:1 if time.monotonic()>end else 0,1000)
  conn.set_authorizer(lambda action,a,b,db,origin:sqlite3.SQLITE_OK if action in(sqlite3.SQLITE_SELECT,sqlite3.SQLITE_READ,sqlite3.SQLITE_TRANSACTION)or(action==sqlite3.SQLITE_FUNCTION and b=='typeof')else sqlite3.SQLITE_DENY)
  value,stats=reader(conn);raw=p.canon(value);p.need(len(raw)<=67108864,'finite complete canonical history')
  return value,{'rawBytes':len(raw),'rawSHA256':hashlib.sha256(raw).hexdigest(),'counts':{k:len(v)for k,v in value.items()},'sourcePin':original,'privatePin':private,'indexPin':index,'blobStats':stats}
 finally:
  if conn is not None:conn.close()
  os.close(fd)
  measured(original,67108864,False);measured(private,67108864,False);held(index,1048576);no_sidecars()

def empty_pool(rows):
 return _empty_pool_tree(Path('/sys/fs/cgroup'+p.POOL))
def _empty_pool_tree(root):
 fields={n:(root/n).read_text().strip()for n in('cpu.max','memory.max','memory.swap.max','cgroup.events','cgroup.procs')}
 p.need(fields['cpu.max']=='1000000 100000'and fields['memory.max']==str(32*1024**3)and fields['memory.swap.max']=='0'and not fields['cgroup.procs']and 'populated 0'in fields['cgroup.events'],'same exact empty whole kernel pool10CPU32GiBswap0')
 count=0
 for child in root.iterdir():
  if not child.is_dir():continue
  p.need(not child.is_symlink(),'actual pool child cannot alias outside the kernel tree')
  for path,ds,fs in os.walk(child,followlinks=False):
   count+=1;p.need(count<=5121 and not Path(path).is_symlink(),'finite nofollow empty pool traversal')
   for name in('cgroup.procs','cgroup.threads'):p.need(Path(path,name).read_text().strip()=='','all current pool tasks/threads absent')
   p.need('populated 0'in Path(path,'cgroup.events').read_text(),'recursive kernel pool remains unpopulated')
 return fields

# This exact optional branch admits one separately Root-bound, non-GPU control
# reservation. The old idle preparation contract remains unchanged when absent.
CONTROL_PROVIDER_SHA='93094a173988a3243c8fdb09a111189e7ccfe7c4d6befa6be60db187f8dd2199'
CONTROL_MAIN='b4ae93065ca930b32010f94f24b109d4b7bccbae'

def validate_current_control_probe(probe,boot,now):
 # Existing normal authenticated producer schema, never select from queue rows.
 p.need(probe['kind']=='ROOT_RUNNER21_NORMAL_CURRENT_PROBE_V1'and probe['boot']==boot and probe['mainCommit']==CONTROL_MAIN and probe['queueSourceSHA256']==QUEUE_SHA,'same OMEN boot/current adopted queue/Main normal probe')
 p.need(type(probe['atUnix'])in(int,float)and 0<=now-probe['atUnix']<=30,'late normal probe actual timestamp; never retimestamp or use dispatch age')
 control=probe['control'];job=control['jobId'];p.need(__import__('re').fullmatch('root-github-robot-control-[0-9a-f]{32}',job)is not None,'one actual normal provider selected job, no historical literal')
 p.need(control['state']=='running'and control['reservationRetained']is True and control['terminalLifecycle']is None and all(control[k]is True for k in('controllerAlive','listenerAlive','workerAlive','ownUnitBound')),'complete normal current live control facts; private row/actors still independently required')
 p.need(control['sourceCommit']==CONTROL_MAIN and control['queueSourceSHA256']==QUEUE_SHA and control['leaseExpiresUnix']>now,'probe control exact current source/queue/unexpired lease')
 p.need(probe['runnerOnline']is True and probe['runnerBusy']is False and probe['heartbeatCurrent']is True and probe['registeredRunnerId']==probe['runnerId']==21,'actual current Runner21 and heartbeat, not VM readiness')
 # heartbeatNonce is the normal publisher cycle nonce, not assumed to equal the
 # control job suffix. The approved producer attests heartbeatCurrent itself.
 p.need(__import__('re').fullmatch('[0-9a-f]{32}',probe['heartbeatNonce'])is not None,'well formed observed normal publisher nonce')
 p.need(probe['actionsInProgress']==probe['actionsQueued']==0 and probe['otherActiveJobs']==[]and probe['unknownReservations']==[]and probe['guestActive']is False and probe['gpuLeaseActive']is False and probe['sourceOwnerBusy']is False,'no workflow/foreign/guest/GPU/unknown busy condition in normal probe')
 p.need(probe['hostGraphics']=='INTEL_HOST_NVIDIA_GUEST_ONLY'and probe['queueKnown']is True and probe['protectedMain']is True,'Intel-host/VM-only NVIDIA normal control boundary')
 return {'jobId':job,'observedUnix':probe['atUnix'],'normalProbeQueueSHA256':probe['queueSourceSHA256'],'observedHeartbeatPublisherNonce':probe['heartbeatNonce'],'selectionFromAuthenticatedNormalProducerOnly':True,'runtimeAuthorized':False}

def late_control_selection(e,persist):
 ref=e['normalControlProbePin'];tr=e['normalControlProbeTransportPin'];producer=e['normalControlProbeProducerPin'];root=Path(ref['path']).parent
 p.need(__import__('re').fullmatch('/run/opemos-steamos-control-compat-[0-9a-f]{32}',str(root))is not None and Path(ref['path']).name=='control-probe.json'and tr['path']==str(root/'control-probe-transport.json'),'existing receiver same-scope probe metadata leaves; no new endpoint')
 with p.RootFiles(root)as files:
  raw,actual=files.read('control-probe.json');transportRaw,transportActual=files.read('control-probe-transport.json');p.need(actual==ref and transportActual==tr,'held/named protected probe/transport full9/EOF/hash');t=json.loads(transportRaw)
  p.need(t['kind']=='ROOT_EXACT_EXISTING_NORMAL_CONTROL_PROBE_SAME_BYTE_TRANSPORT'and t['sourceHostKind']=='CONTROLLER'and t['targetHostKind']=='OMEN'and t['scopeNonce']==e['nonce']and t['targetBootID']==e['bootID']and t['runtimeAuthorized']is False,'Root existing normal-probe data transport only; controller boot is not OMEN boot')
  p.need(t['producerPin']==producer and producer['identity']['st_uid']==producer['identity']['st_gid']==0 and stat.S_ISREG(producer['identity']['st_mode'])and producer['identity']['st_nlink']==1 and not producer['identity']['st_mode']&0o022,'exact separately admitted controller normal producer custody; never read a controller-only path on OMEN')
  p.need(t['sourceBefore']==t['sourceAfter']==t['sourcePin']and t['targetPin']==ref and t['sourcePin']['bytes']==ref['bytes']and t['sourcePin']['sha256']==ref['sha256']and t['sourcePin']['identity']['st_uid']==t['sourcePin']['identity']['st_gid']==0 and stat.S_ISREG(t['sourcePin']['identity']['st_mode'])and stat.S_IMODE(t['sourcePin']['identity']['st_mode'])==0o400 and t['sourcePin']['identity']['st_nlink']==1,'complete source/receiver same-byte cross-host provenance, full9 identities distinct and retained')
  p.need(0<=time.time()-t['issuedUnix']<=30,'same-dispatch finite probe transport, no timestamp rewrite')
  selected=validate_current_control_probe(json.loads(raw),e['bootID'],time.time());p.need(selected['jobId']==e['knownControl']['jobId'],'expectation uses only late producer-selected job; no fallback/replay or row inference')
  p.need(files.read('control-probe.json')==(raw,actual)and files.read('control-probe-transport.json')==(transportRaw,transportActual),'probe/transport held name and full bytes recheck after selection')
 selected.update(probePin=ref,transportPin=tr,producerPin=producer);persist('late-existing-normal-control-selection',selected);return selected

def control_pre_predicate_evidence(values,job):
 p.need(set(values)=={'rows','bindings','config'},'complete finite canonical rows/bindings/config diagnostic input')
 raw=p.canon(values);p.need(len(raw)<=67108864,'unchanged full canonical64MiB')
 def row(r):
  result=r['result'];return {**{k:r[k]for k in('id','state','unit','started','finished')},'resultIsNone':result is None,'resultBytes':None if result is None else len(result.encode()),'resultSHA256':None if result is None else hashlib.sha256(result.encode()).hexdigest()}
 active=[row(r)for r in values['rows']if r['state']not in('passed','failed','timed_out','output_limit','blocked')or r['finished']is None]
 binding=dict(values['bindings']);matched=[row(r)for r in values['rows']if r['id']==job]
 evidence={'kind':'SAME_PRIVATE_COPY_CONTROL_RELATION_BEFORE_PREDICATE','expectedJobId':job,'counts':{k:len(v)for k,v in values.items()},'rawBytes':len(raw),'rawSHA256':hashlib.sha256(raw).hexdigest(),'expectedRows':matched,'completeActiveRows':active,'activeCount':len(active),'expectedBindingBytes':None if job not in binding else len(binding[job].encode()),'expectedBindingSHA256':None if job not in binding else hashlib.sha256(binding[job].encode()).hexdigest(),'diagnosticOnlyNeverAcceptanceOrSelection':True,'originalSQLCalls':0}
 p.need(len(p.canon(evidence))<=1048576,'same Root1MiB complete refusal evidence, no dropped rows or cap waiver');return evidence

def control_relation(values,admission,queue):
 p.need(set(values)=={'rows','bindings','config'}and len(values['config'])==1,'complete current canonical relation')
 rows=values['rows'];bindings=dict(values['bindings']);p.need(len({r['id']for r in rows})==len(rows)and len(bindings)==len(values['bindings'])and set(bindings).issubset({r['id']for r in rows}),'unique complete current rows/keyed bindings')
 job=admission['jobId'];p.need(__import__('re').fullmatch('root-github-robot-control-[0-9a-f]{32}',job)is not None,'one exact Root selected control ID')
 active=[r for r in rows if r['state']not in('passed','failed','timed_out','output_limit','blocked')or r['finished']is None]
 p.need(len(active)==1 and active[0]['id']==job and active[0]['state']=='running'and active[0]['started']is not None and active[0]['finished']is None and active[0]['result']is None,'only exact bound running control; all other current rows terminal')
 row=active[0];p.need(set(row)=={'id','spec','state','cpus','unit','started','finished','result'},'genuine private eight-column control row');spec=json.loads(row['spec']);tx=job.removeprefix('root-github-robot-control-');release='/var/lib/opemos-robot-control-r1/releases/'+tx
 p.need(spec['id']==job and spec['owner']=='root'and spec['platform']=='controlplane'and spec['resources']==['opemos-robot-controlplane']and spec['cores']==1 and spec['memory']==1073741824,'exact non-GPU1CPU1GiB finite control reservation')
 if spec['timeout_seconds']!=21600:
  queue.authenticated_control_window(spec)
 p.need(spec['command']==['/usr/bin/python3',release+'/launch.py',release+'/lease.json','/run/user/1000/opemos-robot-control-'+tx]and spec['cwd']==release,'exact selected normal controller argv/source lineage')
 p.need(job in bindings,'known control must retain keyed immutable binding');bound=json.loads(bindings[job]);p.need(bound['job_id']==job and bound['unit']==row['unit']and bound['specSHA256']==__import__('hashlib').sha256(queue.canonical(spec).encode()).hexdigest()and len(bound['cpus'])==1 and bound['memory']==1073741824,'canonical selected control spec/unit/resource binding')
 return row,bound,spec

def verify_control_live(values,admission,queue,queue_pin,persist,entry=None):
 row,bound,spec=control_relation(values,admission,queue);tx=row['id'].removeprefix('root-github-robot-control-');release=Path('/var/lib/opemos-robot-control-r1/releases')/tx
 lease_ref=admission['leasePin'];p.need(lease_ref['path']==str(release/'lease.json'),'same exact selected control lease path');lease=json.loads(held(lease_ref,65536));policy_ref=admission['fixedPolicyPin'];p.need(policy_ref['path']==str(release/'fixed-policy.json')and lease['connection_fixed_policy']=={k:policy_ref[k]for k in('path','sha256')},'same exact Root installed fixed control policy')
 policy=json.loads(held(policy_ref,65536));p.need(lease['runnerId']==21 and lease['engine_source_commit']==CONTROL_MAIN and lease['connection_queue_sha256']==CONTROL_QUEUE_SHA and queue_pin['sha256']==QUEUE_SHA and lease['connection_proof_authorized']is False,'current control Main/queue/Runner21 and no VM authority')
 p.need(policy['notBefore']<=time.time()<policy['expiresAt']and policy['sourceCommit']==CONTROL_MAIN and policy['queueSourceSHA256']==CONTROL_QUEUE_SHA,'actual existing current control lease not refreshed')
 targets={'worker':['/usr/bin/python3',queue_pin['path'],'--queue',str(Path(queue_pin['path']).parent/'state'),'run'],'controller':['/usr/bin/python3',str(release/'control.py'),str(release/'lease.json'),'/run/user/1000/opemos-robot-control-'+tx],'listener':['/home/connor/.local/share/opemos-ci/github-runner/bin/Runner.Listener','run','--startuptype','service']};candidates={k:[]for k in targets};unknown=[];scanned=0;cg=p.POOL+'/'+row['unit']
 for at in Path('/proc').iterdir():
  if not at.name.isdigit():continue
  scanned+=1;p.need(scanned<=16384,'bounded relevant actor selection')
  try:
   raw=p.process_snapshot(int(at.name))
   for role,argv in targets.items():
    if raw['argv']==argv and(role=='worker'or raw['cgroup']==cg):candidates[role].append(raw)
  except(FileNotFoundError,ProcessLookupError):continue
  except OSError as error:unknown.append({'pid':at.name,'type':type(error).__name__,'reason':str(error)})
 persist('known-control-raw-actors-before-role-predicate',{'candidates':candidates,'unknown':unknown,'scanned':scanned});p.need(not unknown and all(len(x)==1 for x in candidates.values()),'one exact selected worker/controller/listener; no unknown/duplicate')
 actors={}
 for role,items in candidates.items():
  raw=items[0];actor=p.process(raw['pid']);p.need(actor['uid']==1000 and p.process_snapshot(raw['pid'])==raw,'selected strict uniformUID1000/TGID and stable raw PID/start/argv/cgroup');actors[role]=actor
 worker=actors['worker'];p.need('/opemos-heavy.slice/'in worker['cgroup'],'existing canonical worker in normal heavy scope')
 state=Path(queue_pin['path']).parent/'state';lock=state/'worker.lock';s=os.lstat(lock);lock_ref={'path':str(lock),'bytes':s.st_size,'sha256':__import__('hashlib').sha256(b'').hexdigest(),'identity':p.ident(s)};state_ref={'path':str(state),'identity':p.ident(os.lstat(state))};lockproof=p.verify_worker_lock(lock_ref,state_ref,0o664,worker=worker,persist=persist)
 poolvalues=values;expectedInvocations={row['unit']:bound['invocation']}
 if entry is not None:
  poolvalues=entry['value'];request=entry['request'];p.need(poolvalues['rows'][:-1]==values['rows']and poolvalues['config']==values['config']and len(poolvalues['bindings'])==len(values['bindings'])+1 and all(dict(poolvalues['bindings']).get(k)==v for k,v in values['bindings']),'full current canonical prior plus exact own append for pool proof')
  own=poolvalues['rows'][-1];ownbind=json.loads(dict(poolvalues['bindings'])[request['jobId']]);p.need(own['id']==request['jobId']and own['state']=='running'and own['unit']==request['unit']and ownbind['invocation']==request['invocation']and ownbind['unit']==request['unit']and request['unit']!=row['unit'],'exact distinct actual current VM assignment')
  expectedInvocations[request['unit']]=request['invocation']
 bindings=dict(poolvalues['bindings']);poolrows=[dict(r,_poolBinding=json.loads(bindings[r['id']])if r['id']in bindings else None)for r in poolvalues['rows']];backend=queue.SystemdBackend(state,json.loads(poolvalues['config'][0][1]));pool=backend.validate_pool(poolrows)
 p.need(pool['admitted']is True and pool['unknownReservationsRetained']==[]and pool['knownInvocations']==expectedInvocations,'actual complete whole-pool proof admits only exact current control and own VM if assigned')
 # Canonical backend supplies real MainPID/cgroup/limits/UID0 traversal, not a
 # projected pool. Bind the original normal controller and confined listener.
 control=actors['controller'];listener=actors['listener'];p.need(control['uid']==listener['uid']==1000 and control['cgroup']==listener['cgroup']==cg,'both exact current controller/listener in canonical own unit')
 p.need(control['argv']==['/usr/bin/python3',str(release/'control.py'),str(release/'lease.json'),'/run/user/1000/opemos-robot-control-'+tx]and listener['argv']==['/home/connor/.local/share/opemos-ci/github-runner/bin/Runner.Listener','run','--startuptype','service'],'exact normal broker/listener argv')
 p.need(os.readlink('/proc/'+str(control['pid'])+'/ns/pid')!=os.readlink('/proc/'+str(listener['pid'])+'/ns/pid'),'private listener PID namespace distinct from broker')
 for actor in(worker,control,listener):p.need(p.process(actor['pid'])==actor,'same actual PID/start/UID/argv/cgroup after callbacks')
 return {'jobId':row['id'],'unit':row['unit'],'invocation':bound['invocation'],'rowSHA256':__import__('hashlib').sha256(p.canon(row)).hexdigest(),'bindingRaw':bindings[row['id']],'leasePin':lease_ref,'fixedPolicyPin':policy_ref,'worker':worker,'controller':control,'listener':listener,'workerLockProof':lockproof,'actualPoolProof':pool,'knownControlAdmission':admission,'observedUnix':time.time()}

def current_control_values(e,persist):
 admission=e['knownControl'];p.need(set(admission)=={'jobId','providerPin','recoveryPolicyPin','leasePin','fixedPolicyPin','transportPin'},'exact one known-control operand schema')
 transport_ref=admission['transportPin'];parent=Path(transport_ref['path']).parent;p.need(__import__('re').fullmatch('/run/opemos-steamos-control-compat-[0-9a-f]{32}',str(parent))is not None and Path(transport_ref['path']).name=='r6-provider-transport.json','one exact generated provider transport capsule')
 with p.RootFiles(parent)as files:
  raw,actual=files.read('r6-provider-transport.json',0o400);p.need(actual==transport_ref,'held Root transport full9/bytes/SHA');transport=json.loads(raw)
  p.need(transport['kind']=='ROOT_EXACT_EXISTING_R6_PROVIDER_SAME_BYTE_TRANSPORT'and transport['bootID']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()and transport['scopeNonce']==p.SOURCE_PLACEMENT_NONCE and transport['knownControlJobId']==admission['jobId']and transport['runtimeAuthorized']is False,'same boot/scope/control data-only transport, never new runtime authority')
  p.need(transport['targetPins']=={'normal_probe.py':admission['providerPin'],'policy.json':admission['recoveryPolicyPin']},'exact whole source/receiver/normal consumer pin equality')
  p.need(transport['sourcePins']['normal_probe.py']['sha256']==CONTROL_PROVIDER_SHA and transport['sourcePins']['normal_probe.py']['identity']['st_uid']==transport['sourcePins']['normal_probe.py']['identity']['st_gid']==0 and stat.S_IMODE(transport['sourcePins']['normal_probe.py']['identity']['st_mode'])==0o444,'original controller Root source provenance retained')
 provider=admission['providerPin'];p.need(provider['path']==str(parent/'normal_probe.py')and provider['sha256']==CONTROL_PROVIDER_SHA and transport['sourcePins']['normal_probe.py']['bytes']==provider['bytes'],'exact same-byte retained R6 provider at receiver');p.need(provider['identity']['st_uid']==provider['identity']['st_gid']==0 and stat.S_IMODE(provider['identity']['st_mode'])==0o444,'Root0444 existing provider custody');raw=held(provider,65536);module=__import__('types').ModuleType('held_reviewed_R6_normal_private_copy');exec(compile(raw,provider['path'],'exec'),module.__dict__)
 rp=admission['recoveryPolicyPin'];p.need(rp['path']==str(parent/'policy.json')and rp['sha256']==transport['sourcePins']['policy.json']['sha256']and rp['bytes']==transport['sourcePins']['policy.json']['bytes']and transport['sourcePins']['policy.json']['identity']['st_uid']==transport['sourcePins']['policy.json']['identity']['st_gid']==0 and stat.S_IMODE(transport['sourcePins']['policy.json']['identity']['st_mode'])==0o400,'same-byte original controller Root R6 policy, not self-issued');p.need(rp['identity']['st_uid']==rp['identity']['st_gid']==0 and stat.S_IMODE(rp['identity']['st_mode'])==0o400,'Root0400 existing recovery policy');policy=json.loads(held(rp,65536));p.need(policy['enabled']is True and policy['sourceAccepted']is True and policy['runtimeAuthorized']is True and policy['mainCommit']==CONTROL_MAIN and policy['queueSourceSHA256']==QUEUE_SHA and policy['normalProbeSHA256']==CONTROL_PROVIDER_SHA,'existing admitted current Root provider/policy, not a new authority')
 qref=e['queuePrograms'][0];measured(qref,1048576,False);qraw=held(qref,1048576);p.need(__import__('hashlib').sha256(qraw).hexdigest()==QUEUE_SHA,'current paired queue bytes');q=__import__('types').ModuleType('known_control_canonical_queue');q.__file__=qref['path'];__import__('sys').modules[q.__name__]=q
 try:exec(compile(qraw,qref['path'],'exec'),q.__dict__)
 finally:__import__('sys').modules.pop(q.__name__,None)
 # Unchanged R6 helper: same-byte DB+WAL/SHM guarded private copy, SQL only on
 # private bytes, genuine canonical backend, close and cleanup, then rechecks.
 rows,bindings,config=module.private_queue(qraw);values={'rows':rows,'bindings':[[b['job_id'],b['value']]for b in bindings],'config':[[c['id'],c['value']]for c in config]}
 diagnostic=control_pre_predicate_evidence(values,admission['jobId']);persist('known-control-private-history-before-predicate',diagnostic)
 proof=verify_control_live(values,admission,q,qref,persist);meta={k:diagnostic[k]for k in('counts','rawBytes','rawSHA256','originalSQLCalls')};meta.update(privateCopyProviderPin=provider,knownControlProof=proof);persist('known-control-current-private-history',meta);return values,meta,proof


def preflight_receipt_root(nonce,purpose):
 p.need(nonce==p.SOURCE_PLACEMENT_NONCE and purpose in('INSTALLER_ACCESS_STAGE','INSTALLER_BOOT_READY'),'same retained firstboot scope and exact preflight phase')
 return '/run/opemos-libvirt-preflight-'+nonce+('-access-stage'if purpose=='INSTALLER_ACCESS_STAGE'else'')

def require_phase_result(value,purpose,prepared_access_pin=None):
 p.need(value.get('abi')==MACHINE_PREFLIGHT_ABI and not {'ownersPin','ownersObservedUnix','cohort','selfThreadId'}&set(value),'machine-only current preflight ABI; no AI owner fields')
 stage=purpose=='INSTALLER_ACCESS_STAGE';p.need(purpose in('INSTALLER_ACCESS_STAGE','INSTALLER_BOOT_READY'),'exact distinct preflight phase')
 p.need(value['kind']==('ACTUAL_LIBVIRT_R4_ACCESS_STAGE_PREFLIGHT'if stage else'ACTUAL_LIBVIRT_R4_CURRENT_PREFLIGHT')and value['runtimeAuthorized']is False and value['allOwnedFDsClosed']is True,'complete phase-specific readonly preflight, never runtime authority')
 p.need((prepared_access_pin is None and value['preparedAccessPin']is None)if stage else(prepared_access_pin is not None and value['preparedAccessPin']==prepared_access_pin),'stage cannot consume a future access receipt; final must bind the genuine prepared receipt')
 return value

def storage_for_preflight_phase(c,e,stage_only):
 if not stage_only:return p.storage_contract(c['nonce'])
 # Readonly first phase consumes the existing authentic raw placement seed,
 # not the final source/ACL qualification that it is about to enable.
 p.need(p.SOURCE_PLACEMENT_PIN is None,'access-stage cannot replace/replay an existing final placement binding')
 ref=e['placementSeedPin'];root=str(__import__('retained_media').placement_for_candidate(c));p.need(str(Path(ref['path']).parent)==root and ref['identity']['st_uid']==ref['identity']['st_gid']==0 and stat.S_IMODE(ref['identity']['st_mode'])==0o400,'exact current protected original placement seed')
 with p.RootFiles(root)as files:
  raw,actual=files.read(Path(ref['path']).name);p.need(actual==ref,'seed full9/raw-SHA/name at stage use')
 seed=json.loads(raw);p.need(seed['kind']=='ROOT_EXACT_STEAMOS_INSTALLER_GAMES_PLACEMENT'and seed['nonce']==c['nonce']and seed['boot']==c['hostBoot']and seed['original']==c['original']and seed['working']==c['working']and seed['installer']==c['installer']and 'preparationBinding'not in seed,'genuine pre-ACL seed, no final/preparation receipt relabel')
 try:
  p.SOURCE_PLACEMENT_PIN=ref
  return p.storage_contract(c['nonce'])
 finally:p.SOURCE_PLACEMENT_PIN=None


def paired_queue_sha(record):
 """Current media queue comes from its authenticated installed definition.

 The separate historical control queue identity remains unchanged. No supplied
 hash, branch head, path name or Boolean can substitute for the Root definition.
 """
 c=record.get('candidate',{})
 if 'operationContext'not in c:return QUEUE_SHA
 shared=__import__('source_contract')
 definition=shared.validate(record['sourceRoles'],record['queuePrograms'],record['installedSourceContractPin'])
 shared.candidate_paths(c)
 p.need(c['operationContext']['deploymentId']==definition['deployment']['id']and c['lineageNonce']==definition['guestNonce'],'same authenticated media queue deployment/origin')
 return definition['queuePrograms'][0]['sha256']


def produce(c,e,persist):
 __import__('guest_firmware_probe').require_firstboot_only(c)
 stage_only=e['purpose']=='INSTALLER_ACCESS_STAGE'
 p.need(c.get('installer')is not None and e['purpose']in('INSTALLER_ACCESS_STAGE','INSTALLER_BOOT_READY'),'this source epoch is retained-media boot only; no old installed-disk fallback')
 p.need((e.get('preparedAccessPin') is None) if stage_only else (e.get('preparedAccessPin') is not None),'access-stage preflight cannot consume its own future receipt; final preflight requires it')
 started=time.time();p.need(e['issuedUnix']<=started<e['startBeforeUnix']<=e['issuedUnix']+300,'finite separate Root preflight expectation');before=set(os.listdir('/proc/self/fd'));p.need(os.getuid()==0 and e['RootAdopted']is True and e['kind']=='ROOT_LIBVIRT_R4_PREFLIGHT_EXPECTATION','separate actual Root expectation required')
 p.need(p.ident(os.lstat('/'))==e['rootBoundaryPin']['identity']and e['rootBoundaryPin']['path']=='/'and e['rootBoundaryPin']['identity']['st_uid']==e['rootBoundaryPin']['identity']['st_gid']==0,'exact separately adopted Root boundary including mode/epoch')
 boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();p.need(boot==e['bootID']==c['hostBoot'],'same current host boot')
 __import__('guest_firmware_probe').authenticate_copy_receipt(c,boot)
 import types
 def load(ref,name,digest):
  p.need(ref['sha256']==digest and ref['identity']['st_uid']==ref['identity']['st_gid']==0,'exact accepted readonly source bytes/Root pin');raw=held(ref,65536);m=types.ModuleType(name);exec(compile(raw,ref['path'],'exec'),m.__dict__);return m
 native=load(e['nativeReadOnlyPin'],'held_existing_readonly_native','fd1cc2b458394580a82d08cd5673f67ff6e5f026dbe94129b2950e867f1eebc4')
 reader_sha='ac3d2bccb29bd4ba47b03d86d62d917cfacb2e0220416e503d786189cd379bab'
 if 'operationContext'in c:
  definition=__import__('source_contract').validate(e['sourceRoles'],e['queuePrograms'],e['installedSourceContractPin'])
  p.need(e['historyReaderPin']==definition['sourceRoles']['held_history_reader'],'same authenticated current history reader')
  reader_sha=e['historyReaderPin']['sha256']
 reader=load(e['historyReaderPin'],'held_exact_history_reader',reader_sha).read_private_history
 captures={key:json.loads(held(e['splitDiskCapturePins'][key],1048576))for key in('original','working')}
 for ref in e['splitDiskCapturePins'].values():p.need(ref['identity']['st_uid']==ref['identity']['st_gid']==0 and stat.S_IMODE(ref['identity']['st_mode'])==0o400,'Root protected adopted complete captures')
 original=disk_capture(e.get('preparedDiskPins',c)['original'],captures['original'],boot);working=disk_capture(e.get('preparedDiskPins',c)['working'],captures['working'],boot,candidate=c)
 if e.get('preparedAccessPin')is not None:
  from libvirt_access import verify_prepared
  verify_prepared(c,e['preparedAccessPin'],{'original':original,'working':working})
 # Timestamp is intentionally assigned only AFTER full disk hashes and all
 # observation work. Nothing extends/reuses an earlier30s freshness receipt.
 for key,cap in(('firmwareCode',4194304),('firmwareVarsTemplate',1048576),('qemu',33554432)):measured(c[key],cap)
 p.need(len(e['queuePrograms'])==7 and len({x['path']for x in e['queuePrograms']})==7 and e['queuePrograms'][0]['sha256']==paired_queue_sha(e),'exact paired queue deployment first; old04f cannot be relabeled')
 for ref in e['queuePrograms']:measured(ref,1048576,False)
 for ref in e['sourceRoles'].values():
  p.need(ref['identity']['st_uid']==ref['identity']['st_gid']==0 and stat.S_IMODE(ref['identity']['st_mode'])==0o444,'Root0444 frozen source role');measured(ref,65536)
 p.need(e['purpose']in('INSTALLER_ACCESS_STAGE','INSTALLER_BOOT_READY'),'finite exact installer preflight purpose')
 if e['purpose']=='PCI_RUNTIME_READY':
  p.need(e['guestDeltaReceiptPin']is not None,'generated-only EFI producer/preparation receipt required')
  delta=json.loads(held(e['guestDeltaReceiptPin'],1048576));p.need(delta['workingAfter']==c['working'] and delta['original']==original and delta['knownClosed']is True,'exact prepared EFI working derivative lineage')
  p.need(delta['probePin']['sha256']==e['sourceRoles']['guest_firmware_probe']['sha256'],'same pinned guest EFI producer')
 if e['purpose']in('INSTALLER_ACCESS_STAGE','INSTALLER_BOOT_READY'):
  graph=__import__('guest_firmware_probe').installer_contract(c);p.need(e['installerContract']==c['installer']and (stage_only or e['preparedAccessPin']is not None),'exact raw-media contract; final boot preflight requires prepared access')
  refs=e['installerSourceCapturePins'];p.need(set(refs)=={'carrier','retainedR66'},'both complete source captures before late control/owner clocks; never duplicate long hash after freshness')
  for name,ref in refs.items():p.need(ref['identity']['st_uid']==ref['identity']['st_gid']==0 and stat.S_IMODE(ref['identity']['st_mode'])==0o400,'separately protected actual whole source captures')
  disk_capture(c['installer']['carrierSource'],json.loads(held(refs['carrier'],1048576)),boot,False);disk_capture(c['installer']['retainedR66'],json.loads(held(refs['retainedR66'],1048576)),boot)
  p.need(graph['wholeGraphUpperBound']<=60000000000,'complete literal60GB raw recovery graph')
 control=None
 if e.get('knownControl')is not None:late_control_selection(e,persist);values,history,control=current_control_values(e,persist)
 else:values,history=private_values(e['originalQueueDBPin'],e['privateQueueDBPin'],e['privateQueueIndexPin'],reader)
 p.need(history['counts']==e['priorHistory']['counts']and history['rawBytes']==e['priorHistory']['bytes']and history['rawSHA256']==e['priorHistory']['sha256'],'full genuine adopted current prior rows/bindings/config unchanged')
 if control is None:p.need(all(r['finished']is not None and r['state']in('passed','failed','timed_out','output_limit','blocked')for r in values['rows']),'zero active/unknown historical queue jobs')
 gpu=native.Devices().guards();inventory=native.fd_inventory();p.need(inventory['unknown']==[]and inventory['holders']==[]and inventory['QEMU']==[],'full current native process/FD absence')
 if control is None:
  workerProof=p.verify_worker_lock(e['workerLockPin'],e['workerStatePin'],e['workerLockMode'],persist=persist);pool=empty_pool(values['rows'])
 else:
  workerProof=control['workerLockProof'];pool={k:(Path('/sys/fs/cgroup'+p.POOL)/k).read_text().strip()for k in('cpu.max','memory.max','memory.swap.max')}
  p.need(pool=={'cpu.max':'1000000 100000','memory.max':str(32*1024**3),'memory.swap.max':'0'},'unchanged shared pool10CPU32GiBswap0')
 import libvirt
 conn=libvirt.openReadOnly('qemu:///system')
 try:p.need(conn is not None and conn.getURI()=='qemu:///system'and conn.listAllDomains(0)==[],'no domain adoption/full current enumeration')
 finally:
  if conn is not None:p.need(conn.close()==0,'readonly connection closed')
 from queue_assignment import load_queue
 historical_queue=load_queue(e['queuePrograms'][0],e)
 p.verify_historical_lease_set(e['priorLeases'],values['rows'],values['bindings'],historical_queue,boot)
 for path in e['unusedPaths']:p.need(path not in(c['run'],c['output'])or e.get('preparedAccessPin')is None,'staged IO cannot be silently declared unused');p.need(not os.path.lexists(path),'exact unused runtime/source/lease scope '+path)
 placement=storage_for_preflight_phase(c,e,stage_only);freebytes=placement['outerAvailableBytes'];p.need(freebytes>=72000000000,'literal60GB plus20percent actual placement host margin')
 parent=Path(c['working']['path']).parent;ps=parent.lstat();p.need(ps.st_uid==ps.st_gid==0 and(stat.S_IMODE(ps.st_mode)==0o700 or e.get('preparedAccessPin')is not None or __import__('retained_media').is_adopted(c)) and not parent.is_symlink(),'exact protected current derivative parent')
 p.need(before==set(os.listdir('/proc/self/fd')),'complete preflight owned FD restoration')
 result={'kind':('ACTUAL_LIBVIRT_R4_ACCESS_STAGE_PREFLIGHT' if stage_only else 'ACTUAL_LIBVIRT_R4_CURRENT_PREFLIGHT'),'producer':{k:p.process(os.getpid())[k]for k in('pid','start','uid')},'bootID':boot,'observedUnix':time.time(),'startedUnix':started,'original':original,'working':working,'splitDiskCapturePins':e['splitDiskCapturePins'],'preparedAccessPin':e.get('preparedAccessPin'),'workingParentPin':{'path':str(parent),'identity':p.ident(ps)},'queuePrograms':e['queuePrograms'],'workerLockPin':e['workerLockPin'],'workerStatePin':e['workerStatePin'],'workerLockMode':e['workerLockMode'],'workerLockProof':workerProof,'privateHistory':history,'abi':MACHINE_PREFLIGHT_ABI,'pool':{k:pool[k]for k in('cpu.max','memory.max','memory.swap.max')},'holderUnknowns':[],'GPUGroup':p.GROUP,'storagePlacement':placement,'freeBytes':freebytes,'wholeQueueConflictFree':True,'nativeGPUProof':gpu,'FDInventory':inventory,'allOwnedFDsClosed':True,'runtimeAuthorized':False}
 if control is not None:result['knownControl']=control
 require_phase_result(result,e['purpose'],e.get('preparedAccessPin'))
 persist('current-preflight',result);return result

if __name__=='__main__':
 import sys
 from libvirt_producer import create_root,put
 if len(sys.argv)!=3 or sys.argv[1]!='--context-pin-json':raise ValueError('exact protected preflight context pin')
 context_ref=json.loads(sys.argv[2]);p.need(context_ref['identity']['st_uid']==context_ref['identity']['st_gid']==0 and stat.S_IMODE(context_ref['identity']['st_mode'])==0o400,'Root0400 preflight context');ctx=json.loads(held(context_ref,1048576));e=ctx['expectation'];root=preflight_receipt_root(e['nonce'],e['purpose']);p.need(ctx['output']==root and not os.path.lexists(root),'unique exact preflight receipt namespace');create_root(root)
 def persist(label,value):
  with p.RootFiles(root)as files,files.lock(True):ref=put(files,label+'.json',value)
  print(p.canon({'phase':label,'pin':ref}).decode(),flush=True);return ref
 try:produce(ctx['candidate'],e,persist)
 except BaseException as error:
  persist('FIRST',{'type':type(error).__name__,'reason':str(error),'traceback':__import__('traceback').format_exc(),'allEffects':'receipt-only; no domain/GPU/queue'});raise

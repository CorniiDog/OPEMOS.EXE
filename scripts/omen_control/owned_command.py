"""One bounded operational child primitive for this exact diagnostic, not project code."""
import os,sys,stat,json,hashlib,selectors,signal,subprocess,time,traceback
from pathlib import Path
_CHILD_F=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def _child_birth(pid):return Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
def _child_pin(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode)and a.st_nlink==1;h=hashlib.sha256();n=0
  while b:=os.read(fd,4096):h.update(b);n+=len(b)
  full=[getattr(a,k)for k in _CHILD_F];assert full==[getattr(os.fstat(fd),k)for k in _CHILD_F]==[getattr(p.lstat(),k)for k in _CHILD_F]
  return {'name':p.name,'bytes':n,'sha256':h.hexdigest(),'full9':full}
 finally:os.close(fd)
def run_owned_command(argv,stdin_bytes,seconds,paths,stream_limit=65536,sink=None):
 """All creation, identity, input transfer, pipes and cleanup share this finally.
 No blind PID/group signal: exact start+group or an owned pidfd is required.
 Nonblocking input transfer cannot strand stdout/stderr or escape cleanup on EPIPE.
 """
 beforeFD=set(os.listdir('/proc/self/fd'));child_path=Path('/proc/self/task/'+str(os.getpid())+'/children');beforeChildren=child_path.read_text().strip()
 r={'schema':'opemos-owned-command-v2','argv':list(argv),'pid':None,'start':None,'pgid':None,'spawned':False,'numericExit':None,'reaped':False,'stdoutEOF':False,'stderrEOF':False,'firstError':None,'errors':[],'reason':None,'signals':[],'raw':[],'stdin':{'expectedBytes':len(stdin_bytes)if stdin_bytes is not None else 0,'writtenBytes':0,'closed':stdin_bytes is None,'complete':stdin_bytes is None},'fd':{'restored':False,'closeErrors':[]},'tailUNKNOWN':False}
 p=None;pidfd=None;sel=None;files=[];created_paths=[];pipes=[];counts=[0,0];eof=[False,False];phase='output_creation';stopped=False;end=time.monotonic()+seconds
 def error(kind,ex=None):
  row={'kind':kind,'phase':phase,'type':None if ex is None else type(ex).__name__,'message':kind if ex is None else str(ex),'traceback':None if ex is None else traceback.format_exc()}
  if r['firstError']is None:r['firstError']=row
  r['errors'].append({k:v for k,v in row.items()if k!='traceback'})
 def put(n,b):
  if counts[n]+len(b)>stream_limit+4096:r['tailUNKNOWN']=True;raise RuntimeError('Only one complete crossing retained; remaining tail UNKNOWN')
  if sink is None:
   view=memoryview(b)
   while view:
    k=os.write(files[n],view)
    if k<=0:raise OSError('No capture write progress')
    view=view[k:]
  else:sink(files[n],b)
  counts[n]+=len(b)
  if counts[n]>stream_limit:
   r['reason']='complete_first_crossing_retained';raise RuntimeError('Finite complete crossing retained')
 def stop():
  nonlocal stopped,phase
  if p is None or p.poll()is not None:return
  phase='owned_stop'
  for sig,wait in [(signal.SIGTERM,.3),(signal.SIGKILL,1.0)]:
   if p.poll()is not None:break
   try:
    if r['start']is not None and _child_birth(p.pid)==r['start']and os.getpgid(p.pid)==p.pid:
     os.killpg(p.pid,sig);method='exact_start_group'
    elif pidfd is not None and hasattr(signal,'pidfd_send_signal'):
     signal.pidfd_send_signal(pidfd,sig);method='owned_pidfd_leader_only';r['descendantClosureUNKNOWN']=True
    else:raise RuntimeError('No current owned start/group or pidfd; no signal performed')
    r['signals'].append({'signal':int(sig),'method':method,'pid':p.pid,'start':r['start']})
    try:p.wait(timeout=wait)
    except subprocess.TimeoutExpired:pass
   except ProcessLookupError:
    try:p.wait(timeout=wait)
    except subprocess.TimeoutExpired:pass
   except BaseException as ex:error('owned_stop_failure',ex);break
  stopped=True
 try:
  for q in paths:
   files.append(os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600));created_paths.append(q)
  phase='popen';r['popenAttempted']=True
  p=subprocess.Popen(argv,stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,close_fds=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C','SYSTEMD_PAGER':'cat','SYSTEMD_COLORS':'0'})
  r.update(pid=p.pid,spawned=True);pipes=[p.stdout,p.stderr]+([p.stdin]if p.stdin is not None else [])
  phase='birth_capture'
  if hasattr(os,'pidfd_open'):
   try:pidfd=os.pidfd_open(p.pid,0);r['pidfdCaptured']=True
   except ProcessLookupError:r['pidfdCaptured']=False
  r['start']=_child_birth(p.pid);r['pgid']=os.getpgid(p.pid);assert r['pgid']==p.pid,'Expected newly owned session/group'
  phase='stream_setup';sel=selectors.DefaultSelector()
  for n,q in enumerate((p.stdout,p.stderr)):os.set_blocking(q.fileno(),False);sel.register(q,selectors.EVENT_READ,('out',n))
  if p.stdin is not None:
   os.set_blocking(p.stdin.fileno(),False)
   if stdin_bytes:sel.register(p.stdin,selectors.EVENT_WRITE,('in',0))
   else:p.stdin.close();r['stdin'].update(closed=True,complete=True)
  phase='pump'
  while sel.get_map():
   if time.monotonic()>=end:r['reason']='command_deadline';raise TimeoutError('Whole child transfer/capture deadline')
   for key,_ in sel.select(min(.05,max(0,end-time.monotonic()))):
    kind,n=key.data
    if kind=='in':
     try:
      offset=r['stdin']['writtenBytes'];k=os.write(key.fd,stdin_bytes[offset:offset+4096]);assert k>0;r['stdin']['writtenBytes']+=k
      if r['stdin']['writtenBytes']==len(stdin_bytes):sel.unregister(key.fileobj);p.stdin.close();r['stdin'].update(closed=True,complete=True)
     except BrokenPipeError as ex:error('stdin_broken_pipe',ex);raise
    else:
     try:b=os.read(key.fd,4096)
     except BlockingIOError:continue
     if not b:sel.unregister(key.fileobj);eof[n]=True
     else:put(n,b)
  phase='normal_wait';p.wait(timeout=max(.1,end-time.monotonic()))
 except BaseException as ex:
  error('command_lifecycle_failure',ex)
 finally:
  # No first exception, including Popen/birth/initial stdin, can skip this path.
  try:stop()
  except BaseException as ex:error('owned_stop_finally_failure',ex)
  phase='stdin_close'
  if p is not None and p.stdin is not None:
   try:p.stdin.close();r['stdin']['closed']=True
   except BaseException as ex:error('stdin_close_failure',ex);r['fd']['closeErrors'].append(repr(ex))
  phase='drain_after_stop';drainEnd=time.monotonic()+2
  if p is not None:
   for n,q in enumerate((p.stdout,p.stderr)):
    try:os.set_blocking(q.fileno(),False)
    except BaseException as ex:error('stream_setup_cleanup_failure',ex)
   while not all(eof)and time.monotonic()<drainEnd:
    progress=False
    for n,q in enumerate((p.stdout,p.stderr)):
     if eof[n]or q.closed:continue
     try:
      b=os.read(q.fileno(),4096)
      if not b:eof[n]=True;progress=True
      else:put(n,b);progress=True
     except BlockingIOError:pass
     except BaseException as ex:error('stream_drain_failure',ex);r['tailUNKNOWN']=True;drainEnd=time.monotonic();break
    if not progress:time.sleep(.01)
   phase='final_wait'
   try:r['numericExit']=p.wait(timeout=1);r['reaped']=True
   except BaseException as ex:error('wait_failure',ex)
  phase='fd_persist_close'
  for fd in files:
   try:os.fsync(fd)
   except BaseException as ex:error('capture_fsync_failure',ex);r['fd']['closeErrors'].append(repr(ex))
   try:os.close(fd)
   except BaseException as ex:error('capture_close_failure',ex);r['fd']['closeErrors'].append(repr(ex))
  for q in pipes:
   try:q.close()
   except BaseException as ex:error('pipe_close_failure',ex);r['fd']['closeErrors'].append(repr(ex))
  if sel is not None:
   try:sel.close()
   except BaseException as ex:error('selector_close_failure',ex);r['fd']['closeErrors'].append(repr(ex))
  if pidfd is not None:
   try:os.close(pidfd)
   except BaseException as ex:error('pidfd_close_failure',ex);r['fd']['closeErrors'].append(repr(ex))
  r['stdoutEOF'],r['stderrEOF']=eof;r['streamBytes']=counts
  phase='raw_identity'
  for q in created_paths:
   if q.exists():
    try:r['raw'].append(_child_pin(q))
    except BaseException as ex:error('raw_pin_failure',ex)
  r['fd']['restored']=set(os.listdir('/proc/self/fd'))==beforeFD
  r['childSetRestored']=child_path.read_text().strip()==beforeChildren
  if not r['fd']['restored']:error('owned_fd_set_not_restored')
  if not r['childSetRestored']:error('owned_child_set_not_restored')
  r['lifecycleClosed']=bool((r['reaped']if p is not None else r['childSetRestored'])and all(eof if p is not None else (True,True))and r['stdin']['closed']and r['fd']['restored']and not r['fd']['closeErrors']and r['childSetRestored']and not r.get('descendantClosureUNKNOWN',False))
  r['elapsedSeconds']=time.monotonic()-(end-seconds)
 return r

def classify_command(record,contract):
 """Recomputed by every consumer. No caller-supplied allowed exit list."""
 required=True;policy='REQUIRED_ZERO';why=None
 if contract.get('query')not in ('required-query','required-process','blkid'):why='invalid_query_kind'
 if(contract.get('stage')=='driver')!=(contract.get('query')=='required-process'):why=why or'query_stage_kind_mismatch'
 if contract.get('stage')not in ('before-normal-fixture','after-normal-copy','driver'):why='invalid_stage'
 if contract.get('argv')!=record.get('argv'):why=why or'exact_argv_mismatch'
 target=contract.get('target',{})
 if contract.get('query')=='blkid':
  node=target.get('node');role=target.get('role')
  if not isinstance(node,str)or not __import__('re').fullmatch(r'vd[a-z]+(?:[0-9]+)?',node):why=why or'invalid_signature_node'
  if role not in ('synthetic','working')or contract.get('argv')!=['blkid','-p','-o','export','/dev/'+str(node)]:why=why or'invalid_signature_target_argv'
  if contract.get('stage')=='before-normal-fixture':
   required=False;policy='PREFIXTURE_BLANK_NO_SIGNATURE'
   if target.get('kind')!='whole'or target.get('diskBytes')!=67108864 or target.get('freshBlankOrigin')!='create_new_windows_64MiB_before_any_fixture_command':why=why or'blank_exemption_not_bound'
 if not record.get('spawned')or type(record.get('numericExit'))is not int:why=why or'no_actual_numeric_child'
 if record.get('firstError')is not None or record.get('errors')or record.get('reason')is not None:why=why or'actual_lifecycle_or_capture_failure'
 if not record.get('lifecycleClosed')or not record.get('reaped')or not record.get('stdoutEOF')or not record.get('stderrEOF'):why=why or'reap_eof_fd_closure_unknown'
 if record.get('start')is None or not record.get('fd',{}).get('restored'):why=why or'identity_or_fd_unknown'
 si=record.get('stdin',{})
 if not si.get('complete')or not si.get('closed')or si.get('writtenBytes')!=si.get('expectedBytes'):why=why or'stdin_incomplete'
 numeric=record.get('numericExit');raw=record.get('raw',[])
 if len(raw)!=2 or any(type(x.get('bytes'))is not int or not __import__('re').fullmatch('[0-9a-f]{64}',str(x.get('sha256')))for x in raw):why=why or'raw_stream_pins_missing'
 if not record.get('childSetRestored')or record.get('fd',{}).get('closeErrors'):why=why or'child_or_fd_close_unknown'
 if policy=='PREFIXTURE_BLANK_NO_SIGNATURE':
  empty=hashlib.sha256(b'').hexdigest()
  if numeric!=2 or len(raw)!=2 or any(r.get('bytes')!=0 or r.get('sha256')!=empty for r in raw):why=why or'not_exact_silent_blank_blkid_no_signature'
 elif numeric!=0:why=why or'required_query_nonzero'
 return {'schema':'opemos-typed-command-outcome-v2','stage':contract.get('stage'),'query':contract.get('query'),'target':target,'argv':record.get('argv'),'policy':policy,'required':required,'numericExit':numeric,'status':('REQUIRED_OK'if required else'OBSERVATION_NO_SIGNATURE')if why is None else'FAILED','accepted':why is None,'failureKind':why,'firstCause':({'recordFirstError':True,'kind':record['firstError']['kind'],'phase':record['firstError']['phase']}if record.get('firstError')is not None else None) if why is None else{'kind':why,'numericExit':numeric},'lifecycleClosed':record.get('lifecycleClosed',False)}

def validate_collector_manifest(m,stage):
 """Verify the same full typed ledger in driver and serial consumer; failure is data."""
 def req(x,msg):
  if not x:raise ValueError(msg)
 req(m.get('kind')=='PR196_WORKING_PARTITION_TYPED_DIAGNOSTIC_V2'and m.get('stage')==stage,'Exact typed collector kind/stage')
 rows=m.get('commands');req(isinstance(rows,list)and len(rows)<=40,'Finite actual command ledger')
 failures=[];labels=[];signatures=[];udev=[]
 files=m.get('files');req(isinstance(files,list),'Whole raw file ledger');filepins={p['name']:p for p in files};req(len(filepins)==len(files),'No duplicate raw manifest file')
 fixed={
 'initial-systemd-jobs':['systemctl','list-jobs','--no-pager','--no-legend','--full'],
 'initial-udev-units':['systemctl','show','systemd-udevd.service','systemd-udev-trigger.service','systemd-udevd-control.socket','systemd-udevd-kernel.socket','-p','Id','-p','ActiveState','-p','SubState','-p','Result','-p','Job','-p','InvocationID','-p','ExecMainPID','-p','ExecMainCode','-p','ExecMainStatus','-p','NRestarts'],
 'udev-journal':['journalctl','-b','-u','systemd-udevd.service','--no-pager','--output=short-monotonic','-n','80'],
 'kernel-current':['dmesg','--time-format=raw']}
 for index,row in enumerate(rows,1):
  req(row.get('index')==index,'No omitted/reordered ledger entries');c=row['contract'];r=row['record'];label=c.get('label');labels.append(label)
  req(c.get('stage')==stage and row.get('outcome')==classify_command(r,c),'Recomputed typed command outcome')
  if label in fixed:req(c.get('query')=='required-query'and c.get('argv')==fixed[label],'Exact required query argv')
  elif isinstance(label,str)and label.startswith('initial-udev-'):
   node=label[len('initial-udev-'):];req(__import__('re').fullmatch(r'vd[a-z]+(?:[0-9]+)?',node),'Finite udev node')
   req(c.get('query')=='required-query'and c.get('argv')==['udevadm','info','--query=property','--path=/sys/class/block/'+node],'Exact required per-device query');udev.append(node)
  elif isinstance(label,str)and label.startswith('bounded-signature-'):
   t=c.get('target',{});req(c.get('query')=='blkid'and label=='bounded-signature-'+str(t.get('role'))+'-'+str(t.get('node')),'Exact signature role/label target')
   req(t.get('kind')in ('whole','partition1')and t.get('diskBytes')==67108864,'Exact owned diagnostic geometry');signatures.append((t.get('role'),t.get('kind')))
  else:raise ValueError('Unrecognized required collector command')
  for n,pin in enumerate(r.get('raw',[])):
   expected=f'{index:02d}-'+('stdout'if n==0 else'stderr')+'.raw'
   req(pin.get('name')==expected and expected in filepins,'Exact per-command stream filename')
   full=filepins[expected];req(pin['bytes']==full['bytes']and pin['sha256']==full['sha256'],'Actual raw bytes/hash bound to typed outcome')
   req(pin['full9']==[full['identity'][k]for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')],'Actual raw identity bound to typed outcome')
  if not row['outcome']['accepted']:failures.append(row)
 req(len(labels)==len(set(labels)),'No duplicate labels hiding omitted queries')
 allAccepted=not failures
 requiredOK=all(x['outcome']['status']=='REQUIRED_OK'for x in rows if x['outcome']['required'])
 observationCount=sum(x['outcome']['status']=='OBSERVATION_NO_SIGNATURE'for x in rows)
 req(m.get('allTypedResultsAccepted')==allAccepted and m.get('requiredQueriesSucceeded')==requiredOK and m.get('expectedBlankObservations')==observationCount,'No aggregate flag overrides typed failure')
 if failures:
  f=m.get('firstCause');req(isinstance(f,dict)and f.get('origin')=='collector-command'and f.get('index')==failures[0]['index']and f.get('outcome')==failures[0]['outcome'],'Earliest actual required command cause preserved')
 if m.get('executionComplete'):
  req(labels[:2]==['initial-systemd-jobs','initial-udev-units']and labels[-2:]==['udev-journal','kernel-current'],'Complete ordinary query boundaries')
  req(udev==m.get('observedVirtioNodes')and len(udev)>=5,'Every observed virtio device queried')
  expected={(role,kind)for role in ('synthetic','working')for kind in (('whole',)if stage=='before-normal-fixture'else('whole','partition1'))}
  req(len(signatures)==len(expected)and set(signatures)==expected,'All exact per-stage signature queries present')
 valid=bool(m.get('executionComplete')and not m.get('failure')and m.get('firstCause')is None and allAccepted and not m.get('ownChildren')and not m.get('metadataCrossing'))
 req(m.get('complete')is valid,'Complete cannot hide any failure/unknown')
 return {'schema':'opemos-typed-collector-validation-v2','stage':stage,'validDiagnostic':valid,'allTypedResultsAccepted':allAccepted,'requiredQueriesSucceeded':requiredOK,'expectedBlankObservations':observationCount,'firstCause':m.get('firstCause'),'commands':len(rows),'executionComplete':bool(m.get('executionComplete'))}

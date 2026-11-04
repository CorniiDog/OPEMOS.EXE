"""Specific Root intent/lease/domain producer; disabled until a real Root grant.

No direct binder, physical sysfs writer, host kill/killpg or domain adoption.
Queue request comes from immutable libvirt_request, never invented unit tokens.
The exact current Root entry/registration precedes queue ACTIVE acceptance.
"""
import hashlib,json,os,re,stat,time
import xml.etree.ElementTree as E
import libvirt_peer as peer

def put(files,name,value,mode=0o400):
 peer.need(re.fullmatch('[A-Za-z0-9_.-]+',name)is not None,'confined generated leaf')
 raw=peer.canon(value);peer.need(len(raw)<=1048576,'unchanged metadata1MiB')
 fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode,dir_fd=files.fd)
 try:
  os.fchmod(fd,mode);view=memoryview(raw)
  while view:n=os.write(fd,view);peer.need(n>0,'write progress');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 os.fsync(files.fd);return files.read(name,mode)[1]

def record_prior_history(values, record):
 """Whole accepted history as bounded leaves, not one metadata-sized blob."""
 import base64,zlib
 raw=peer.canon(values);peer.need(len(raw)<=64*1024**2,'unchanged whole history64MiB')
 compressed=zlib.compress(raw)
 chunks=[]
 for offset in range(0,len(compressed),524288):
  chunks.append(record('prior-history-part',{'offset':offset,'data':base64.b64encode(compressed[offset:offset+524288]).decode()}))
 return record('prior-history-codec',{'value':{'kind':'ROOT_PRIOR_HISTORY_CHUNKS_V1','bytes':len(compressed),'sha256':hashlib.sha256(compressed).hexdigest(),'chunks':chunks}})

def head(files,name,value):
 # Only the tiny owned head is replaced; every full phase/state/audit is O_EXCL.
 temporary=name+'.new';pin=put(files,temporary,value)
 os.rename(temporary,name,src_dir_fd=files.fd,dst_dir_fd=files.fd);os.fsync(files.fd)
 return files.read(name)[1]

def create_root(path):
 peer.need(str(path).startswith('/run/opemos-')and len(str(path).split('/'))==3,'exact generated root')
 fd=os.open('/run',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  peer.need(os.fstat(fd).st_uid==os.fstat(fd).st_gid==0 and stat.S_IMODE(os.fstat(fd).st_mode)==0o755,'Root /run custody')
  os.mkdir(os.path.basename(path),0o700,dir_fd=fd);os.fsync(fd)
 finally:os.close(fd)
 with peer.RootFiles(path)as f:put(f,'lock',{},0o600)

def commit_phase(files,request,boot,number,phase,scope=None,leader=None,details=None):
 peer.need(number in range(16)and phase in('PREPARED','ACTIVE','CLOSED'),'finite declared phase')
 record={'phase':phase,'requestSHA256':hashlib.sha256(peer.canon(request)).hexdigest(),'bootID':boot,'scope':scope,'leader':leader,'details':details}
 pin=put(files,'phase-'+str(number).zfill(2)+'.json',record)
 return head(files,'phase-head.json',{'record':os.path.basename(pin['path']),'sha256':pin['sha256']})

def append_lease(files,request,boot,event,changes):
 try:
  raw,_=files.read('head.json');h=json.loads(raw);peer.need(set(h)=={'path','bytes','sha256','identity'}and str(__import__('pathlib').Path(h['path']).parent)==str(files.path),'canonical exact native state-pin head');previous_raw,previous_pin=files.read(__import__('pathlib').Path(h['path']).name);peer.need(previous_pin==h,'complete canonical native head/state full9/SHA');previous=json.loads(previous_raw);rev=previous['revision']+1
  peer.need(previous['nonce']==request['leaseNonce']and previous['jobID']==request['jobId']and previous['currentBoot']==boot and previous['requestSHA256']==hashlib.sha256(peer.canon(request)).hexdigest(),'no old/foreign lease adoption')
 except FileNotFoundError:
  peer.need(event=='PREPARED','only initial prepared lease may be absent');rev=0;previous={'nonce':request['leaseNonce'],'jobID':request['jobId'],'currentBoot':boot,'requestSHA256':hashlib.sha256(peer.canon(request)).hexdigest(),'backend':'libvirt','closed':False,'restored':True,'changed':[],'historicalQMPClosed':None}
 peer.need(rev<64 and not(previous.get('closed')is True),'bounded no-rearm lease')
 value={**previous,**changes,'revision':rev,'event':event,'atUnix':time.time()}
 pin=put(files,'state-'+str(rev)+'.json',value)
 audit=put(files,'audit-'+str(rev)+'.json',{'prior':None if rev==0 else h,'next':pin,'event':event})
 head(files,'head.json',pin)  # unchanged canonical whole-native lease reader protocol
 return value,pin,audit

def require_grant(grant,request,c,boot):
 __import__('guest_firmware_probe').require_firstboot_only(c)
 peer.need(c.get('installer')is not None,'this fresh installer source scope forbids installed-disk fallback')
 peer.need(grant.get('kind')=='ROOT_EXACT_LIBVIRT_TWO_BOOT_AUTHORITY_R2'and grant.get('RootIssued')is True and grant.get('runtimeAuthorized')is True,'separate real Root authority required')
 peer.need(grant['jobId']==request['jobId']and grant['domainName']==request['domainName']and grant['domainUUID']==request['domainUUID']and grant['leaseNonce']==request['leaseNonce']and grant['bootID']==boot,'exact grant job/domain/lease/boot')
 now=time.time();peer.need(grant['issuedUnix']<=now<grant['startBeforeUnix']<=grant['issuedUnix']+300 and grant['wholeDeadlineUnix']<=grant['issuedUnix']+900,'finite original300/900 clocks')
 peer.need(grant['reservationMemory']==10*1024**3 and grant['controllerMemory']==2*1024**3 and grant['domainMemory']==8*1024**3 and grant['cpus']==request['cpus'],'one exact10GiB and same four CPUs')
 peer.need(grant['observerPin']==request['observer']and grant['noNIC']is True and grant['noInstall']is True and grant['maxBoots']==1 and grant['physicalGroup']==peer.GROUP,'exact observer/no-install/full-group contract')
 peer.need(grant.get('failureControl')=='LIBVIRT_AUTODESTROY_CONTROLLER_CONNECTION','no unaccounted watchdog or alternate binder')
 peer.need(grant['originalPin']==c['original']and grant['workingPin']==c['working']and grant['guestUUID']==c['guestUUID']and grant['firmwareCodePin']==c['firmwareCode'],'same original/working/guest/firmware pins')
 peer.need(grant['currentPreflightPin']is not None and grant.get('preflightABI')==__import__('libvirt_preflight').MACHINE_PREFLIGHT_ABI and 0<=now-grant['preflightObservedUnix']<=30,'fresh protected complete machine preflight source')
 peer.need(grant.get('preparedAccessPin')is not None and set(grant.get('preparedDiskPins',{}))=={'original','working'}and set(grant.get('splitDiskCapturePins',{}))=={'original','working'},'complete pregrant ACL stage/posthash/late custody lineage')
 if c.get('installer')is not None:__import__('guest_firmware_probe').installer_contract(c);peer.need(grant.get('installerContract')==c['installer'],'grant bound exact installer/no target/readonly media/full charges')
 return grant['wholeDeadlineUnix']

def make_xml(c,request):
 peer.validate_request(request)
 adopted=__import__('retained_media').is_adopted(c)
 if c.get('installer')is not None:
  __import__('guest_firmware_probe').installer_contract(c)
  if adopted:__import__('retained_media').observe(c)
 xml=render_domain_xml(c,request,adopted)
 if c.get('installer')is not None:__import__('guest_firmware_probe').validate_installer_xml(c,E.fromstring(xml))
 return xml

def render_domain_xml(c,request,adopted=False):
 """Pure domain XML, no grant, machine admission or native effects."""
 E.register_namespace('opemos',peer.NS)
 d=E.Element('domain',type='kvm')
 def x(parent,tag,text=None,**attrs):
  n=E.SubElement(parent,tag,attrs)
  if text is not None:n.text=str(text)
  return n
 x(d,'name',request['domainName']);x(d,'uuid',request['domainUUID'])
 x(x(d,'metadata'),'{'+peer.NS+'}binding',None,token=request['jobToken'],job=request['jobId'],nonce=request['leaseNonce'])
 x(d,'memory',5120,unit='MiB');x(d,'currentMemory',5120,unit='MiB');cpus=','.join(map(str,request['cpus']))
 x(d,'vcpu',3,placement='static',cpuset=cpus);t=x(d,'cputune');x(t,'global_period',100000);x(t,'global_quota',400000)
 for i in range(3):x(t,'vcpupin',None,vcpu=str(i),cpuset=cpus)
 x(t,'emulatorpin',None,cpuset=cpus)
 mt=x(d,'memtune');x(mt,'hard_limit',8388608,unit='KiB');x(mt,'swap_hard_limit',8388608,unit='KiB')
 x(x(d,'resource'),'partition',request['partition']);o=x(d,'os');x(o,'type','hvm',arch='x86_64',machine='q35')
 x(o,'loader',c['firmwareCode']['path'],readonly='yes',type='pflash');x(o,'nvram',c['run']+'/OVMF_VARS_4M.fd');
 if c.get('installer')is None:x(o,'boot',None,dev='hd')
 x(o,'bootmenu',None,enable='yes')
 x(x(d,'features'),'acpi');x(d,'cpu',None,mode='host-passthrough',check='none');x(d,'clock',None,offset='utc')
 for n in('on_poweroff','on_reboot','on_crash'):x(d,n,'destroy')
 dev=x(d,'devices');x(dev,'emulator',c['qemu']['path']);disk=x(dev,'disk',None,type='file',device='disk');x(disk,'driver',None,name='qemu',type='raw',cache='none');source=x(disk,'source',None,file=c['working']['path']);
 if c.get('installer')is None:x(disk,'target',None,dev='sda',bus='sata');x(disk,'serial','OPEMOS3828ABR4')
 else:
  if adopted:x(source,'seclabel',None,model='dac',relabel='no')
  x(disk,'target',None,dev='sda',bus='usb');x(disk,'serial','OPEMOS_STEAMOS_RETAINED_ISO');x(disk,'readonly');x(disk,'boot',None,order='1')
 x(dev,'controller',None,type='sata',index='0');x(dev,'controller',None,type='pci',index='0',model='pcie-root');rp=x(dev,'controller',None,type='pci',index='1',model='pcie-root-port');x(rp,'target',None,chassis='1',port='0x10');x(rp,'address',None,type='pci',domain='0x0000',bus='0x00',slot='0x02',function='0x0')
 for i in range(4):
  h=x(dev,'hostdev',None,mode='subsystem',type='pci',managed='yes');x(x(h,'source'),'address',None,domain='0x0000',bus='0x01',slot='0x00',function=hex(i));x(h,'alias',None,name='ua-opemos-vfio-'+str(i));a=dict(type='pci',domain='0x0000',bus='0x01',slot='0x00',function=hex(i))
  if i==0:a['multifunction']='on'
  x(h,'address',None,**a)
 s=x(dev,'serial',None,type='file');x(s,'source',None,path=c['output']+'/serial.raw',append='on');x(s,'target',None,type='isa-serial',port='0')
 g=x(dev,'graphics',None,type='vnc',autoport='no');x(g,'listen',None,type='socket',socket=c['run']+'/vnc.sock');x(x(x(dev,'video'),'model',None,type='virtio',heads='1',primary='yes'),'resolution',None,x='1600',y='900');x(dev,'controller',None,type='usb',model='qemu-xhci',index='0');x(dev,'input',None,type='tablet',bus='usb');x(dev,'input',None,type='keyboard',bus='usb');x(dev,'memballoon',None,model='none')
 return E.tostring(d,encoding='unicode')+'\n'


class Transaction:
 """One owning queue entry. ops performs native observation/effects or explicit model.

 Every producer outcome is reread by the unchanged upstream queue validator.
 Native ops must be installed-schema-qualified and source-pinned before grant.
 """
 def __init__(self,c,request,grant,grant_pin,ops,persist):
  peer.validate_request(request);self.c=c;self.r=request;self.ops=ops;self.persist=self.report;self.optional_terminal_sink=persist;self.diagnosticObservations={};self.lastDiagnostic=None;self.g=grant;self.gp=grant_pin;self.boot=ops.boot();self.deadline=require_grant(grant,request,c,self.boot);self.number=0;self.launched=0;self.domain=None;self.intent=None;self.first=None
 def report(self,label,value):
  self.lastDiagnostic={'label':label,'value':value}
  if label in self.diagnosticObservations or len(self.diagnosticObservations)<32:self.diagnosticObservations[label]=value
 def prepare(self):
  r=self.r;ops=self.ops;ops.verify_grant_and_sources(self.gp,self.g);ops.full_preflight_and_entry(self.g,r,self.c)
  ops.configure_partition(r)  # exact8GiB/4CPU/swap0 under existing pool; no memory expansion
  peer.need(ops.partition_empty(r),'unused exact VM partition')
  create_root('/run/opemos-vfio-'+r['leaseNonce']);create_root('/run/opemos-libvirt-queue-'+r['jobToken'])
  self.intent={'kind':'ROOT_EXACT_QUEUE_LIBVIRT_INTENT_R2','request':r,'bootID':self.boot,'entry':ops.current_entry(r),'grantPin':self.gp,'qemuPin':self.c['qemu'],'workingPin':self.c['working'],'originalPin':self.c['original'],'firmwareCodePin':self.c['firmwareCode'],'endpoints':self.c['hostdev'],'wholeDeadlineUnix':self.deadline,'producerPin':self.g['producerPin'],'failureControl':'LIBVIRT_AUTODESTROY_CONTROLLER_CONNECTION','nativeTools':self.g['nativeTools'],'accessPin':self.g['accessPin'],'accessScope':{'run':self.c['run'],'output':self.c['output'],'working':self.c['working'],'firmwareVarsTemplate':self.c['firmwareVarsTemplate']}}
  with peer.RootFiles('/run/opemos-libvirt-queue-'+r['jobToken'])as f,f.lock(True),peer.RootFiles('/run/opemos-vfio-'+r['leaseNonce'])as l,l.lock(True):
   put(f,'intent.json',self.intent);append_lease(l,r,self.boot,'PREPARED',{});commit_phase(f,r,self.boot,self.number,'PREPARED');self.number+=1
  ops.prepare_io(self.intent)  # authenticate/journal all six prepared ACLs before any connection failure
  connection=ops.prepare_controller_connection(self.intent)
  peer.need(connection['heldVerified']is True,'exact controller-owned AUTODESTROY connection')
  with peer.RootFiles('/run/opemos-libvirt-queue-'+r['jobToken'])as f,f.lock(True):put(f,'controller-connection.json',connection)
  self.persist('PREPARED',peer.observe(r,ops.readonly()))
 def launch(self,phase):
  peer.need(phase==self.launched+1 and phase<=2 and self.domain is None and time.time()<self.deadline,'max two distinct bounded boots')
  self.ops.recheck_before_domain(self.intent,phase);xml=make_xml(self.c,self.r)
  self.domain=self.ops.create_paused(xml);self.launched+=1
  # Domain may exist before registration. Observer must refuse that startup race,
  # not claim PREPARED empty; no queue whitelist until authentic ACTIVE commit.
  observed=self.ops.register_actual_domain(self.domain,self.intent)
  peer.need(observed['uuid']==self.r['domainUUID']and observed['name']==self.r['domainName']and observed['persistent']is False and observed['noNIC']is True,'actual transient domain registration')
  with peer.RootFiles('/run/opemos-libvirt-queue-'+self.r['jobToken'])as f,f.lock(True),peer.RootFiles('/run/opemos-vfio-'+self.r['leaseNonce'])as l,l.lock(True):
   append_lease(l,self.r,self.boot,'ACTIVE',{'changed':[e['bdf']for e in self.c['hostdev']],'restored':False,'domain':observed});commit_phase(f,self.r,self.boot,self.number,'ACTIVE',observed['scope'],observed['leader'],observed);self.number+=1
  self.persist('ACTIVE-'+str(phase),peer.observe(self.r,self.ops.readonly()));self.ops.resume_exact(self.domain,observed,self.intent)
  graphical=self.ops.capture_graphical_first(phase,self.intent)
  if not graphical['displayContent']['nonBlank']:
   serial_error=None;diagnostic=None
   try:diagnostic=self.ops.measure_guest(phase,self.intent)
   except peer.Refused as error:
    if str(error)!='actual guest serial measurement deadline':raise
    serial_error=peer.error_value(error)
   evidence={'graphical':graphical,'secondarySerialError':serial_error,'secondarySerialBytes':None if diagnostic is None else len(diagnostic),'secondarySerialSHA256':None if diagnostic is None else hashlib.sha256(diagnostic).hexdigest(),'noGuestBootOrUIOrRenderAcceptance':True};self.persist('graphical-inactive-secondary-serial-diagnosis-'+str(phase),evidence);error=peer.Refused('actual graphical observation inactive at unchanged30s deadline; secondary serial is diagnostic only');error.evidence=evidence;raise error
  return self.ops.measure_guest(phase,self.intent)
 def stop(self,abrupt,final=False):
  peer.need(self.domain is not None,'exact active handle')
  if abrupt:
   registration=self.ops.prepare_disconnect(self.domain,self.intent)
   self.domain=None  # release the controlling libvirt domain handle before final connection close
   self.ops.disconnect_exact(registration,self.intent)
  else:self.ops.wait_guest_shutdown(self.domain,self.intent)
  closure=self.ops.prove_domain_closure(self.domain,self.intent)
  peer.need(closure['domainAbsent']and closure['originalPIDStartAbsent']and closure['cgroupEmpty']and closure['VFIOFDsAbsent']and closure['hostRestored']and not closure['unknown'],'complete current domain/host restoration; unknown holds')
  peer.need(closure['qemuExitStatus']is None and closure['controllerWaitpidClaimed']is False,'truthful daemon child lifecycle')
  if not abrupt or final:self.ops.restore_access(self.intent,closure)
  phase='PREPARED'if abrupt and not final else'CLOSED'
  with peer.RootFiles('/run/opemos-libvirt-queue-'+self.r['jobToken'])as f,f.lock(True),peer.RootFiles('/run/opemos-vfio-'+self.r['leaseNonce'])as l,l.lock(True):
   append_lease(l,self.r,self.boot,'KNOWN_DOMAIN_CLOSURE',{'restored':True,'changed':[],'closed':not abrupt or final,'domain':None,'currentDisposition':closure});commit_phase(f,self.r,self.boot,self.number,phase,details=closure);self.number+=1
  self.domain=None;self.persist('CLOSURE-'+str(self.launched),closure);self.persist(phase,peer.observe(self.r,self.ops.readonly()))
 def run(self,guest_parser,guest_contract):
  rows=[];primary=None;secondary=[];closed=False
  try:
   self.prepare()
   if self.c.get('installer')is not None:
    proof=__import__('guest_firmware_probe').installer_contract(self.c);raw=self.launch(1);v=__import__('json').loads(raw);peer.need(v['kind']=='ACTUAL_RETAINED_INSTALLER_BOOT_DIAGNOSTIC'and v['domainUUID']==self.r['domainUUID']and v['mediaPin']==self.c['working']and v['graphicalFirst']is True,'installer-specific observed domain/media/frame binding, never old installed reporter');rows.append({'phase':1,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'value':v});self.persist('installer-boot-only-observation',rows[-1]);self.stop(True,final=True);self.ops.original_unchanged(self.intent);closed=True
   for phase in(()if self.c.get('installer')is not None else(1,2)):
    raw=self.launch(phase);parsed=guest_parser.scan(raw,guest_contract,phase);peer.need(parsed is not None,'actual guest identity/PCI before count');v,b=parsed
    if phase==2:peer.need(v['bootId']!=rows[0]['value']['bootId']and v['previousBootId']==rows[0]['value']['bootId']and v['previousBootSHA256']==rows[0]['sha256'],'same disk two-boot ledger')
    self.ops.prove_firmware_route(self.intent,phase,v['bootId']);row={'phase':phase,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'value':v};rows.append(row);self.persist('guest-'+str(phase),row);self.stop(phase==1)
   if self.c.get('installer')is None:peer.need(self.ops.stopped_readback(self.intent)==rows,'stopped ledger/serial equality');self.ops.original_unchanged(self.intent);closed=True
  except BaseException as e:primary={'type':type(e).__name__,'reason':str(e),'traceback':__import__('traceback').format_exc(),'evidence':getattr(e,'evidence',None)}
  finally:
   had_domain=self.domain is not None;self.domain=None  # drop all owning domain refs before closing connection on failure too
   try:final=self.ops.final_close(self.intent,had_domain)
   except BaseException as e:final={'known':False,'leaseHeld':True};secondary.append({'type':type(e).__name__,'reason':str(e)})
  # Kernel/domain absence is independent of durable logical closure. Never
  # project an open PREPARED/ACTIVE lease to released after an earlier failure.
  lease_closed=False
  if self.intent is not None:
   try:
    with peer.RootFiles('/run/opemos-vfio-'+self.r['leaseNonce'])as files,files.lock():
     state,binding,_=peer.read_lease(files,self.r,self.boot);lease_closed=state['closed']and state['restored']and not state['changed'];final['leaseStatePin']=binding['statePin'];final['leaseHeadPin']=binding['headPin']
   except BaseException as e:secondary.append({'type':type(e).__name__,'reason':str(e)})
  secondary.extend(final.get('secondary',[]))
  if primary is not None and self.intent is not None and final.get('known')is True and final.get('FDsClosed')is True and not lease_closed:
   try:
    proof={'first':primary,'secondary':secondary,'currentClosure':final,'historicalQMPClosed':None,'noHistoricalCloseFabrication':True}
    with peer.RootFiles('/run/opemos-libvirt-queue-'+self.r['jobToken'])as files,files.lock(True),peer.RootFiles('/run/opemos-vfio-'+self.r['leaseNonce'])as lf,lf.lock(True):
     previous,_,_=peer.read_lease(lf,self.r,self.boot);peer.need(not previous['closed'],'no closed lease rearm')
     append_lease(lf,self.r,self.boot,'FAILED_KNOWN_CURRENT_DISPOSITION',{'closed':True,'restored':True,'changed':[],'domain':None,'currentDisposition':proof});commit_phase(files,self.r,self.boot,self.number,'CLOSED',details=proof);self.number+=1
    observed=peer.observe(self.r,self.ops.readonly());self.persist('FAILED-CLOSED-current-disposition',observed);final['leaseStatePin']=observed['lease']['statePin'];final['leaseHeadPin']=observed['lease']['headPin'];lease_closed=True
   except BaseException as error:secondary.append(peer.error_value(error));final['known']=False
  final['logicalLeaseClosed']=lease_closed
  diagnostic=closed and self.c.get('installer')is not None and final.get('known')is True and lease_closed
  accepted=closed and self.c.get('installer')is None and final.get('known')is True and lease_closed
  result={'kind':'STEAMOS_LIBVIRT_BOUND_QUEUE_TWO_BOOT_RESULT_R2','MODEL_ONLY':self.ops.MODEL_ONLY,'accepted':accepted,'first':primary,'secondary':secondary,'rows':rows,'launches':self.launched,'closure':final,'leaseMustRemainHeld':not(final.get('known')is True and lease_closed),'acceptanceGates':{'graphicalFirstFrames':[n for n,v in getattr(self.ops,'graphical',{}).items()if v['displayContent']['nonBlank']],'graphicalObservedFrames':list(getattr(self.ops,'graphical',{})),'graphicalDiagnosticOnlyFrames':[n for n,v in getattr(self.ops,'graphical',{}).items()if not v['displayContent']['nonBlank']],'canonicalGuestPCIAccepted':closed and self.c.get('installer')is None,'matchingSameGuestKernelNVIDIA575Readiness':'UNMEASURED; no install authorized','NVIDIARenderAccepted':False,'twoBootRestartAccepted':closed and self.c.get('installer')is None,'automaticABFallbackAccepted':False},'NVIDIAFunctionalDriverAccepted':False,'AutomaticABFallbackAccepted':False,'packageInstalled':False,'runtimeAuthorized':(not self.ops.MODEL_ONLY and self.g.get('runtimeAuthorized')is True)}
  if self.c.get('installer')is not None:result.update(installerDiagnosticComplete=diagnostic,installerEntryAccepted=False,installedSystemAccepted=False,guestOSIdentityAccepted=False,graphProof=__import__('guest_firmware_probe').installer_contract(self.c),acceptanceReason='Live graphical/media boot observation requires independent actual screen/OS review; no driver/install/recovery success from metadata')
  self.report('terminal',result)
  if self.optional_terminal_sink is not None:
   try:self.optional_terminal_sink('terminal',result)
   except Exception as error:result['secondary'].append({'type':type(error).__name__,'reason':str(error),'optionalReport':True,'runtimeAuthority':False})
  return result

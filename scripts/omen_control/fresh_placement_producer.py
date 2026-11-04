"""Source-only normal metadata producer proposal; no CLI/effect entry point.
Future independently admitted Root normal preparation supplies live mounted IO,
complete original/working captures, six ACL proof, protected current expectation
and current machine admission. This function cannot prepare media or manufacture those inputs.
It writes only new Root0400 storage/qualification records with existing put().
"""
import hashlib,json,os,stat,time
from pathlib import Path
import libvirt_peer as peer
import libvirt_access as access
import libvirt_preflight as pre
import libvirt_producer as producer
from libvirt_native import held
# Guest lineage is bound by the installed definition, not a code selector.

def protected(ref):
 i=ref['identity'];peer.need(i['st_uid']==i['st_gid']==0 and stat.S_IMODE(i['st_mode'])==0o400 and i['st_nlink']==1,'Root0400 protected metadata input')
 return json.loads(held(ref,1048576))

def produce(expectation_pin,seed_pin,persist):
 """Must run under separately admitted existing Root preparation, never now.
 A negative guard retains exact partial metadata and never authorizes runtime.
 """
 started=time.time();peer.need(os.getuid()==0,'native Root preparation producer only');e=protected(expectation_pin);seed=protected(seed_pin);c=e['candidate'];NONCE=c['nonce'];root=str(__import__('retained_media').placement_root(c))
 peer.need(e['kind']=='ROOT_LIBVIRT_R4_PREFLIGHT_EXPECTATION'and e['RootAdopted']is True and e['issuedUnix']<=started<e['startBeforeUnix']<=e['issuedUnix']+300 and e['purpose']in('PCI_RUNTIME_READY','INSTALLER_BOOT_READY'),'separate original finite current expectation; no issuance here')
 peer.need(c.get('installer')is not None and e['purpose']=='INSTALLER_BOOT_READY','installer-only source preparation, no old disk fallback')
 peer.need(e['nonce']==c['nonce']==NONCE and c['hostBoot']==e['bootID']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'fresh unused scope/current boot')
 peer.need(seed['kind']==('ROOT_EXACT_STEAMOS_INSTALLER_GAMES_PLACEMENT'if c.get('installer')is not None else'ROOT_EXACT_STEAMOS_FIXED_GAMES_PLACEMENT')and seed['nonce']==NONCE and seed['boot']==e['bootID']and seed_pin==e['placementSeedPin']and Path(seed_pin['path']).parent==Path(root),'existing normal fresh placement seed, not D22 relabel')
 peer.need(seed['working']==c['working']and (seed['working']['identity']['st_uid']==seed['working']['identity']['st_gid']==0 or (__import__('retained_media').is_adopted(c)and __import__('retained_media').observe(c)['working']==seed['working'])) and seed['working']['bytes']==(8120172544 if c.get('installer')is not None else 21474836480)and seed['wholeGraphUpperBound']==(__import__('guest_firmware_probe').installer_contract(c)['wholeGraphUpperBound']if c.get('installer')is not None else 58449672960)<60000000000 and seed['hostFloor']==72000000000,'same Root working inode, literal60e9 graph and20percent margin')
 if c.get('installer')is not None:__import__('guest_firmware_probe').authenticate_copy_receipt(c,e['bootID']);peer.need(seed['installer']==c['installer']and seed['backing']==c['installer']['backing'],'same complete installer/charged backing producer data')
 peer.need(seed['placement']['path']=='/media/connor/Games/OPEMOS/SteamOS-test-storage-20261027-ae79cd4de452'and seed['placement']['identity']['st_uid']==seed['placement']['identity']['st_gid']==1000,'exact previously authorized regular-file storage parent; no physical media API')
 definition=__import__('source_contract').validate(e['sourceRoles'],e['queuePrograms'],e['installedSourceContractPin']);peer.need(c['operationContext']['deploymentId']==definition['deployment']['id']and c['lineageNonce']==definition['guestNonce'],'same installed deployment/origin lineage')
 peer.need(peer.SOURCE_PLACEMENT_NONCE==NONCE and peer.SOURCE_PLACEMENT_PIN is None,'unbound current placement')
 for role,ref in e['sourceRoles'].items():
  peer.need(ref['identity']['st_uid']==ref['identity']['st_gid']==0 and stat.S_IMODE(ref['identity']['st_mode'])==0o444 and Path(ref['path']).name==role+'.py','immutable installed role');compile(held(ref,1048576),ref['path'],'exec')
 for ref in e['queuePrograms']:pre.measured(ref,1048576,False)
 peer.need(len(e['queuePrograms'])==7 and e['queuePrograms'][0]['sha256']==pre.paired_queue_sha(e),'current independently adopted full5 paired queue authority')
 # Reuse whole-hash captures, then exact post-ACL custody; no duplicate40GiB hash.
 captures={key:protected(ref)for key,ref in e['splitDiskCapturePins'].items()};peer.need(set(captures)=={'original','working'},'both original/working whole captures')
 disks={key:pre.disk_capture(e['preparedDiskPins'][key],captures[key],e['bootID'],candidate=c)for key in('original','working')};access.verify_prepared(c,e['preparedAccessPin'],disks)
 value=dict(seed);peer.need('preparationBinding'not in value,'fresh seed cannot contain a consumed binding');value['preparationBinding']={'expectationPin':expectation_pin,'seedPin':seed_pin,'preflightABI':pre.MACHINE_PREFLIGHT_ABI,'sourceRoles':e['sourceRoles'],'sourceGraphSHA256':hashlib.sha256(peer.canon(e['sourceRoles'])).hexdigest(),'queuePrograms':e['queuePrograms'],'splitDiskCapturePins':e['splitDiskCapturePins'],'preparedAccessPin':e['preparedAccessPin'],'preparedDiskPins':disks,'runtimeAuthorized':False}
 # The existing RootFiles and put implement EXCL/NOFOLLOW/fchmod/fsync/full reread.
 # This producer never creates a namespace or lock, and never deletes a partial.
 with peer.RootFiles(root)as files,files.lock(True):
  peer.need(not os.path.lexists(root+'/storage-contract.json')and not os.path.lexists(root+'/placement-qualified.json'),'one fresh create-only placement output; no replay')
  ref=producer.put(files,'storage-contract.json',value)
 peer.SOURCE_PLACEMENT_PIN=ref
 observed=peer.storage_contract(NONCE,persist=persist);peer.need(observed['receiptPin']==ref,'unchanged actual storage guard consumes exact emitted operand')
 # Full genuine current queue/history/process/holders/native/pool/IOMMU/clock
 # checks are the unchanged normal preflight, not projected flags in this seed.
 records=[]
 def capture(label,v):
  r=persist(label,v);records.append((label,r));return r
 current=pre.produce(c,e,capture);current_pins=[ref for label,ref in records if label=='current-preflight'];peer.need(len(current_pins)==1 and current['storagePlacement']['receiptPin']==ref,'one complete normal current preflight/placement join')
 q={'kind':'ROOT_VERIFIED_FRESH_STEAMOS_PLACEMENT','nonce':NONCE,'bootID':e['bootID'],'qualifiedPlacementPin':ref,'sourceRoles':e['sourceRoles'],'queuePrograms':e['queuePrograms'],'expectationPin':expectation_pin,'seedPin':seed_pin,'currentPreflightPin':current_pins[0],'currentPreflight':current,'runtimeAuthorized':False,'RootIssuedRuntimeAuthority':False,'observedUnix':current['observedUnix']}
 with peer.RootFiles(root)as files,files.lock(True):qualification=producer.put(files,'placement-qualified.json',q)
 peer.need(time.time()<e['startBeforeUnix'],'original finite preparation clock, no refresh')
 return {'sourcePlacementPin':ref,'placementQualificationPin':qualification,'prequeuePreflightPin':current_pins[0],'observedUnix':current['observedUnix'],'sourceRoles':e['sourceRoles'],'queuePrograms':e['queuePrograms'],'sourceAccepted':False,'runtimeAuthorized':False,'RootIssued':False,'partialNeverDeleted':True}

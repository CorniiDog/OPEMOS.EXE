"""Only the existing disposable SteamOS two-boot measurement/closure transaction."""
import json,hashlib,base64,re
PREFIX=b'OPEMOS_STEAMOS_AB_V1 '
CAP=65536
class Refused(RuntimeError):pass
def need(v,m):
    if not v:raise Refused(m)
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def scan(raw,contract,phase):
    need(len(raw)<=4194304,'serial total cap')
    complete=raw.split(b'\n');pending=complete.pop();need(len(pending)<=131072,'pending serial fragment cap');frames=[]
    for line in complete:
        if line.endswith(b'\r'):line=line[:-1]
        if not line.startswith(PREFIX):continue
        parts=line[len(PREFIX):].split(b' ');need(len(parts)==3,'closed serial frame schema');nonce,sha,encoded=parts
        need(nonce==contract['nonce'].encode()and re.fullmatch(b'[0-9a-f]{64}',sha)is not None,'serial scope/digest')
        need(len(encoded)<=((CAP+2)//3)*4,'encoded guest receipt cap')
        try:b=base64.b64decode(encoded,validate=True);value=json.loads(b)
        except Exception as e:raise Refused('guest frame encoding/JSON')from e
        need(len(b)<=CAP and hashlib.sha256(b).hexdigest().encode()==sha and canonical(value)==b,'canonical guest receipt bytes/hash')
        validate(value,contract,phase);frames.append((value,b))
    need(len(frames)<=1,'duplicate measurement frame');return None if not frames else frames[0]
def validate(v,c,phase):
    keys={'schemaVersion','kind','nonce','guestUUID','phase','bootId','kernel','osReleaseFiles','parsedOS','slot','rootMount','homeMount','cmdline','health','reporterSHA256','previousBootSHA256','previousBootId','GPURequired','nvidiaPCI','productInstalled'}
    need(type(v)is dict and set(v)==keys,'measurement exact field graph')
    need(v['schemaVersion']==1 and v['kind']=='ACTUAL_STEAMOS_AB_GUEST_MEASUREMENT'and v['nonce']==c['nonce']and v['guestUUID']==c['guestUUID']and v['phase']==phase,'actual guest scope/phase')
    need(v['reporterSHA256']==c['reporterSHA256']and re.fullmatch('[0-9a-f-]{36}',v['bootId'])is not None,'reporter source/boot ID')
    need(v['parsedOS'].get('ID')=='steamos','actual guest OS is SteamOS')
    need(v['parsedOS'].get('VERSION_ID',v['parsedOS'].get('DISTRIB_RELEASE'))=='3.8.28','actual SteamOS 3.8.28 version required, not source label')
    need(v['kernel'].startswith('6.18.50')and 'console=ttyS0,115200n8'in v['cmdline'].split(),'actual target kernel/serial route')
    need(v['slot']in c['rootUUIDs'],'actual admitted slot')
    for k in('rootMount','homeMount'):
        q=v[k];need(q['numeric']==0 and q['EOF']and q['reaped']and q['FDClosed'],'complete guest native mount evidence')
    need(v['rootMount']['stdout'].split()[0]==c['rootUUIDs'][v['slot']]and v['homeMount']['stdout'].split()[0]==c['syntheticHomeUUID'],'root slot/shared ledger mount identity')
    h=v['health'];need(h['systemState']['stdout'].strip()in('running','degraded'),'actual settled health state')
    for n in('systemState','failedUnits','bootRegistration'):
        need(h[n]['EOF']and h[n]['reaped']and h[n]['FDClosed'],'native health child/FD closure')
    need(v['GPURequired']is True and v['productInstalled']is False,'GPU-first no product install scope')
    rows=v['nvidiaPCI'];need(type(rows)is list and len(rows)==4 and len({x['guestBDF']for x in rows})==4,'four unique actual guest PCI functions')
    for e in c['nvidiaPCI']:
        matches=[x for x in rows if x['vendor']==e['vendor']and x['device']==e['device']]
        need(len(matches)==1 and all(matches[0][k]==e[k]for k in('class','subsystemVendor','subsystemDevice')),'guest exact NVIDIA identity before phase counted')
    if phase==1:need(v['previousBootId']is None and v['previousBootSHA256']is None,'first-boot ledger empty')
def run_two_boot(vm,c):
    """vm is the exact existing owned QEMU lifecycle, or an explicitly labeled test backend."""
    receipts=[];first=None;secondary=[];accepted=False
    try:
        for phase in(1,2):
            vm.launch(phase);raw=vm.wait_measurement(phase);r=scan(raw,c,phase);need(r is not None,'guest identity not established before deadline');value,body=r
            if phase==2:
                need(value['bootId']!=receipts[0]['value']['bootId'],'changed real guest boot ID')
                need(value['previousBootId']==receipts[0]['value']['bootId']and value['previousBootSHA256']==receipts[0]['sha256'],'same shared guest ledger/source lineage')
            receipts.append({'phase':phase,'value':value,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()});vm.persist('guest-measurement-'+str(phase)+'.json',receipts[-1])
            end=vm.abrupt_off()if phase==1 else vm.shutdown()
            need(end['numeric']==(-9 if phase==1 else 0),'exact first off/second terminal numeric')
            need(all(end[k]for k in('reaped','stdoutClosed','stderrClosed','QMPClosed','groupEmpty','pidfdClosed','knownOriginalAbsent')),'complete QEMU closure before restart/release')
        back=vm.readback()
        need(len(back)==2,'two stopped shared-ledger receipts')
        for x,y in zip(receipts,back):need(y['bytes']==x['bytes']and y['sha256']==x['sha256']and y['value']==x['value'],'stopped readback vs actual serial exact equality')
        vm.original_unchanged();accepted=True
    except BaseException as e:first={'type':type(e).__name__,'reason':str(e)}
    finally:
        try:closure=vm.close()
        except BaseException as e:closure={'known':False};secondary.append({'type':type(e).__name__,'reason':str(e)})
    need(type(closure)is dict,'closure shape')
    result={'kind':'STEAMOS3828_SAME_GUEST_RESTART_RECOVERY_RESULT','accepted':accepted and closure.get('known')is True,'first':first,'secondary':secondary,'measurements':receipts,'closure':closure,'automaticABFallbackProved':False,'packagePostUpdateAcceptance':False,'NVIDIAFunctionalDriverRenderOutputAcceptance':False,'NVIDIAPCIEnumerationAccepted':accepted and closure.get('known')is True}
    vm.persist('two-boot-result.json',result);return result

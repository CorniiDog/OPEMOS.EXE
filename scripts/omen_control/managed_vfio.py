"""Existing first-init option inside the admitted normal Root transaction.

Libvirt is the only binder. No sysfs power/reset writes or persistent config.
Initial inherited D3cold wake can still fail; setting Y is not a boot claim.
"""
import os
from pathlib import Path

MODULES=('vfio_pci','vfio_pci_core')
DEPENDENCIES=('vfio','irqbypass')
TOOL='/var/lib/opemos-vfio-idle-d3/modprobe'
REMOVE='/var/lib/opemos-vfio-idle-d3/rmmod'
F=('st_dev','st_ino','st_mode','st_uid','st_gid')

def cached():
    rows={}
    for bdf in ('0000:00:01.0',)+tuple('0000:01:00.'+str(i)for i in range(4)):
        root=Path('/sys/bus/pci/devices')/bdf;rows[bdf]={}
        for name in ('power/control','power/runtime_status','power_state','d3cold_allowed'):
            try:rows[bdf][name]=(root/name).read_text().strip()
            except OSError as error:rows[bdf][name]={'diagnosticUnavailable':type(error).__name__}
    return rows

def initial_plan(loaded):
    if set(loaded)!=set(MODULES)or any(type(v)is not bool or v for v in loaded.values()):
        raise ValueError('VFIO was already loaded; do not relabel or reload its option lifetime')
    return [TOOL,'--ignore-install','--first-time','vfio-pci','disable_idle_d3=1']

def module_identity(name):
    s=Path('/sys/module',name).lstat();return {k:getattr(s,k)for k in F}

def proven_custody(before,result,after):
    initial_plan(before['loaded'])
    if not(result['numeric']==0 and result['closure']=='KNOWN'and result['EOF']is True and result['reaped']is True
           and result['primary']is None and result['secondary']==[]and after['option']=='Y'and set(after['modules'])==set(MODULES)):
        raise ValueError('VFIO initialization is unproven; no module removal authority')
    return {'state':'PROVEN','before':before,'after':after,'command':result}

def removal_plan(custody,current):
    if custody.get('state')!='PROVEN':raise ValueError('ambiguous/partial VFIO initialization; retain FIRST and ownership')
    for name in MODULES:
        value=current[name];allowed={'vfio_pci'}if name=='vfio_pci_core'else set()
        if not(value['identity']==custody['after']['modules'][name]and set(value['holders'])<=allowed
               and value['refcnt']==len(value['holders'])):
            raise ValueError('foreign/drifted VFIO module ownership; do not unload')
    # rmmod removes exactly its named module; modprobe -r recursively removes
    # unused dependencies, including modules that predated this lease.
    return [[REMOVE,'vfio_pci'],[REMOVE,'vfio_pci_core']]

def prepare(ops,peer,native_child):
    peer.need(os.getuid()==os.geteuid()==0,'existing admitted Root transaction')
    prior=getattr(ops,'vfioCustody',None)
    if prior is not None:
        peer.need(prior['state']=='PROVEN'and Path('/sys/module/vfio_pci/parameters/disable_idle_d3').read_text().strip()=='Y'
            and all(module_identity(n)==prior['after']['modules'][n]for n in MODULES),'own proven first-init remains exact')
        return
    peer.NativeOps().restoration(ops.intent)
    before={'loaded':{n:Path('/sys/module',n).exists()for n in MODULES},
            'dependencies':{n:Path('/sys/module',n).exists()for n in DEPENDENCIES}}
    argv=initial_plan(before['loaded'])
    for endpoint in ops.intent['endpoints']:
        p=Path('/sys/bus/pci/devices')/endpoint['bdf']/'driver_override'
        peer.need(p.read_text()==endpoint['originalOverride'],'original override before initialization')
    deadline=ops.effect_clock('create')
    # This protected custody record is ownership evidence, not an optional
    # summary or startup permit. No grant or hardware authority comes from it.
    ops.access_persist('vfio-init-before',{'job':ops.request,'before':before,'argv':argv,'source':ops.g['nativeTools'][TOOL]})
    ops.vfioCustody={'state':'ATTEMPTED','before':before}
    result=None
    try:
        result=native_child(argv,deadline,ops.g['nativeTools'][TOOL])
        ops.report('VFIO-first-init-command',result)
        peer.need(result['numeric']==0,'actual first VFIO helper failed')
        after={'option':Path('/sys/module/vfio_pci/parameters/disable_idle_d3').read_text().strip(),
               'modules':{n:module_identity(n)for n in MODULES}}
        custody=proven_custody(before,result,after)
        ops.vfioCustody=custody
        try:ops.access_persist('vfio-init-proven',custody)
        except OSError as diagnostic:ops.report('optional-VFIO-proven-publication',{'type':type(diagnostic).__name__})
    except BaseException as first:
        # Failed/partial/unknown initialization never becomes unload authority.
        first.evidence={'kind':'VFIO_FIRST_INIT_FAILED','command':result,'custody':ops.vfioCustody,'priorEvidence':getattr(first,'evidence',None)}
        ops.report('VFIO-init-FIRST',{'primary':{'type':type(first).__name__,'reason':str(first)},'custody':ops.vfioCustody})
        raise
    peer.NativeOps().restoration(ops.intent)
    ops.report('VFIO-first-init-effective',{'latchedAtFirstDriverInit':True,'option':'disable_idle_d3=1',
        'cachedPower':cached(),'initialWakeStillRequired':True,'domainOrCPUClaimed':False})

def restore(ops,peer,native_child,closure):
    custody=getattr(ops,'vfioCustody',None)
    if custody is None or custody['state']=='RESTORED':return
    peer.need(custody['state']=='PROVEN','ambiguous/partial initialization; retain FIRST and ownership')
    peer.need(all(closure.get(k)is True for k in ('domainAbsent','originalPIDStartAbsent','cgroupEmpty',
        'VFIOFDsAbsent','hostRestored'))and closure.get('unknown')==[],'complete normal libvirt closure before module cleanup')
    peer.NativeOps().restoration(ops.intent)
    driver=Path('/sys/bus/pci/drivers/vfio-pci')
    peer.need(not driver.exists()or not any(p.name.startswith('0000:')for p in driver.iterdir()),'no VFIO-bound device')
    current={n:{'identity':module_identity(n),'holders':[p.name for p in (Path('/sys/module',n)/'holders').iterdir()],
                  'refcnt':int((Path('/sys/module',n)/'refcnt').read_text())}for n in MODULES}
    commands=removal_plan(custody,current)
    for argv in commands:
        name=argv[1];root=Path('/sys/module',name)
        peer.need(module_identity(name)==custody['after']['modules'][name]and not list((root/'holders').iterdir())
            and int((root/'refcnt').read_text())==0,'same own unused module immediately before single removal')
        result=native_child(argv,ops.effect_clock('cleanup'),ops.g['nativeTools'][REMOVE])
        ops.report('VFIO-single-remove-'+name,result)
        peer.need(result['numeric']==0 and not root.exists(),'own exact module not removed; preserve FIRST/lease')
    peer.NativeOps().restoration(ops.intent)
    deps={n:Path('/sys/module',n).exists()for n in DEPENDENCIES}
    peer.need(all(not was or deps[n]for n,was in custody['before']['dependencies'].items()),'preexisting dependencies preserved')
    ops.vfioCustody=dict(custody,state='RESTORED')
    try:ops.access_persist('vfio-init-restored',{'onlyOwnTwoModulesRemoved':True,'originalDependencies':custody['before']['dependencies'],
        'currentDependencies':deps,'newUnusedDependenciesPreserved':True})
    except OSError as diagnostic:ops.report('optional-VFIO-restored-publication',{'type':type(diagnostic).__name__})

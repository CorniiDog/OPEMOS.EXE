"""Existing VFIO first-init mitigation; libvirt remains the only PCI binder.

Called only inside the independently admitted normal Root transaction. No
standalone command, persistent modprobe config, sysfs PM write or reset exists.
The initial D3cold -> D0 managed wake can still fail: this option is mitigation,
never evidence of a guest boot or safety of an inherited hardware state.
"""
import os
from pathlib import Path

MODULES=('vfio_pci','vfio_pci_core')
TOOL='/var/lib/opemos-vfio-idle-d3/modprobe'

def cached():
    """Cached power attributes only; never PCI config, link or nvidia-smi."""
    rows={}
    for bdf in ('0000:00:01.0',)+tuple('0000:01:00.'+str(i)for i in range(4)):
        root=Path('/sys/bus/pci/devices')/bdf
        rows[bdf]={}
        for name in ('power/control','power/runtime_status','power_state','d3cold_allowed'):
            try:rows[bdf][name]=(root/name).read_text().strip()
            except OSError as error:rows[bdf][name]={'diagnosticUnavailable':type(error).__name__}
    return rows

def initial_plan(loaded):
    if set(loaded)!=set(MODULES)or any(type(v)is not bool or v for v in loaded.values()):
        raise ValueError('VFIO was already loaded; do not relabel or reload its option lifetime')
    return [TOOL,'--ignore-install','--first-time','vfio-pci','disable_idle_d3=1']

def prepare(ops,peer,native_child):
    peer.need(os.getuid()==os.geteuid()==0,'existing admitted Root transaction')
    if getattr(ops,'vfioOwnedFirstInit',False):
        peer.need(Path('/sys/module/vfio_pci/parameters/disable_idle_d3').read_text().strip()=='Y','own first-init option unchanged')
        return
    peer.NativeOps().restoration(ops.intent)
    loaded={name:Path('/sys/module',name).exists()for name in MODULES}
    argv=initial_plan(loaded)
    ops.report('VFIO-first-init-before',{'loaded':loaded,'cachedPower':cached(),
        'initialWakeStillRequired':True,'noPCIOrPowerControlWrites':True})
    # No ids/new_id/override/bind argument: loading the existing module must not
    # replace libvirt's independently guarded all-four managed-device sequence.
    for endpoint in ops.intent['endpoints']:
        p=Path('/sys/bus/pci/devices')/endpoint['bdf']/'driver_override'
        peer.need(p.read_text()==endpoint['originalOverride'],'original override before module initialization')
    ops.vfioOwnedFirstInit=True  # partial helper failure must retain ownership
    result=native_child(argv,ops.effect_clock('create'),ops.g['nativeTools'][TOOL])
    ops.report('VFIO-first-init-command',result)
    peer.need(result['numeric']==0,'actual first VFIO module initialization failed; preserve FIRST')
    peer.need(all(Path('/sys/module',name).exists()for name in MODULES)and
        Path('/sys/module/vfio_pci/parameters/disable_idle_d3').read_text().strip()=='Y','first-init option/readback')
    peer.NativeOps().restoration(ops.intent)
    ops.report('VFIO-first-init-effective',{'latchedAtFirstDriverInit':True,
        'option':'disable_idle_d3=1','cachedPower':cached(),'domainOrCPUClaimed':False})

def restore(ops,peer,native_child,closure):
    if not getattr(ops,'vfioOwnedFirstInit',False):return
    peer.need(all(closure.get(k)is True for k in ('domainAbsent','originalPIDStartAbsent',
        'cgroupEmpty','VFIOFDsAbsent','hostRestored'))and closure.get('unknown')==[],
        'no module removal before complete normal libvirt closure')
    peer.NativeOps().restoration(ops.intent)
    driver=Path('/sys/bus/pci/drivers/vfio-pci')
    peer.need(not driver.exists()or not any(p.name.startswith('0000:')for p in driver.iterdir()),'no VFIO-bound device')
    for name in MODULES:
        root=Path('/sys/module')/name
        if not root.exists():continue
        holders={p.name for p in (root/'holders').iterdir()}
        peer.need(holders<=({'vfio_pci'}if name=='vfio_pci_core'else set())and
                  int((root/'refcnt').read_text())==(1 if name=='vfio_pci_core'and holders else 0),
                  'only own unused VFIO module graph; foreign users retain state')
    result=native_child([TOOL,'--remove','vfio_pci','vfio_pci_core'],
                        ops.effect_clock('cleanup'),ops.g['nativeTools'][TOOL])
    ops.report('VFIO-first-init-original-setting-restoration',result)
    peer.need(result['numeric']==0 and not any(Path('/sys/module',n).exists()for n in MODULES),
              'original unloaded VFIO state not restored; retain normal lease')
    peer.NativeOps().restoration(ops.intent);ops.vfioOwnedFirstInit=False

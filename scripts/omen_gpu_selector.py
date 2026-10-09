#!/usr/bin/env python3
"""Read-only hardware inventory for the requested OMEN desktop selector.

Host rendering and VM passthrough are distinct. This probe never selects PRIME
profiles, detaches drivers, or treats a saved inventory as current hardware.
"""
import json
import argparse
import shutil
import subprocess
import tempfile
import sys
from pathlib import Path


def probe(devices=Path('/sys/bus/pci/devices')):
    displays = []
    for device in sorted(devices.iterdir()):
        if int((device / 'class').read_text().strip(), 16) >> 16 != 3:
            continue
        vendor = (device / 'vendor').read_text().strip().lower()
        driver = device / 'driver'
        group = device / 'iommu_group'
        displays.append({'address': device.name, 'vendor': vendor,
                         'driver': driver.resolve().name if driver.is_symlink() else None,
                         'bootDisplay': (device / 'boot_vga').read_text().strip() == '1',
                         'groupMembers': sorted(p.name for p in (group / 'devices').iterdir())
                         if group.is_symlink() else []})
    internal = any(d['vendor'] == '0x8086' and d['address'] == '0000:00:02.0' for d in displays)
    nvidia = [d for d in displays if d['vendor'] == '0x10de']
    return {'displayDevices': displays,
            'internalGraphicsCandidateDetected': internal,
            'internalGraphicsAvailable': False,
            'internalGraphicsReason': 'OMEN integrated Intel display candidate detected; active display route still requires validation.' if internal else 'No OMEN integrated Intel display detected. Internal graphics cannot be selected.',
            'gpuPresent': bool(nvidia),
            'gpuLabel': 'GPU — detected (active output unverified)' if nvidia else 'GPU — not detected',
            'gpuHostDisplayInUse': any(d['bootDisplay'] and d['driver'] == 'nvidia' for d in nvidia),
            'vmPassthroughAccepted': False,
            'applyAllowed': False,
            'applyReason': 'Hardware transition requires exact live Core admission, ownership and rollback checks; no transition performed.'}


def inspect(devices=Path('/sys/bus/pci/devices')):
    try:
        return probe(devices)
    except (OSError, ValueError):
        # Missing, malformed or racing sysfs must not become an empty success.
        return {'inspectionFailed': True, 'internalGraphicsAvailable': False,
                'gpuLabel': 'GPU — inspection unavailable',
                'vmPassthroughAccepted': False, 'applyAllowed': False,
                'applyReason': 'Hardware inspection failed. No graphics change is available; refresh after resolving the device metadata error.'}


def desktop():
    # The Ubuntu Qt6 package supplies qml, not necessarily qmlscene. Prefer
    # explicitly Qt6 names/paths; do not select an ambiguous unversioned qml.
    runner = shutil.which('qml6')
    for qt6 in (Path('/usr/lib/qt6/bin/qml'), Path('/usr/lib/qt6/bin/qmlscene')):
        if runner is None and qt6.is_file():
            runner = str(qt6)
    if runner is None:
        runner = shutil.which('qmlscene')
    if runner is None:
        raise RuntimeError('Existing Qt6 qml or qmlscene runtime is unavailable; no package installation or graphics change attempted.')
    template = Path(__file__).with_name('omen-gpu-selector.qml').read_text()
    # JSON is data, not QML code; escape line separators for JS parsing.
    inventory = json.dumps(json.dumps(inspect(), ensure_ascii=True), ensure_ascii=True)
    with tempfile.TemporaryDirectory(prefix='opemos-gpu-selector-') as directory:
        view = Path(directory) / 'selector.qml'
        view.write_text(template.replace('__OPEMOS_GPU_INVENTORY__', inventory))
        subprocess.run([runner, str(view)], check=True, timeout=900)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--desktop', action='store_true')
    if parser.parse_args().desktop:
        try:
            desktop()
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            print('Graphics selector could not start. No graphics change performed: ' + str(error), file=sys.stderr)
            sys.exit(1)
    else:
        print(json.dumps(inspect(), sort_keys=True))

"""Finite R8 investigation with retained exact 7b8 inputs, NOT acceptance.
No bottle relocation/acquisition, Valve download, Build or deadline increase.
The original aac numeric exit2 diagnostic remains immutable in Git/run history.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

archive = Path(sys.argv[1])
root = Path(__file__).resolve().parents[1]
out = root / 'build/retained-startup-diagnostic'
out.mkdir(parents=True, exist_ok=False)
receipt = {'acceptance': False, 'stages': {}, 'noBuild': True, 'noProducerReplay': True}
diagnostic_deadline = time.monotonic() + 25 * 60
def save():
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()
def run(name, command, timeout):
    row = {'command': command}
    receipt['stages'][name] = row
    remaining = diagnostic_deadline - time.monotonic() - 30
    if remaining <= 0:
        row['notStarted'] = 'aggregate diagnostic execution budget exhausted'
        save()
        raise RuntimeError(row['notStarted'])
    timeout = min(timeout, remaining)
    row['outerTimeoutSeconds'] = timeout
    with (out / (name + '.log')).open('wb') as log:
        child = subprocess.Popen(command, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        row['pid'] = child.pid
        try:
            row['exit'] = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            row['timedOut'] = True
            os.killpg(child.pid, signal.SIGKILL)
            row['cleanupExit'] = child.wait(timeout=10)
        try:
            os.killpg(child.pid, 0)
            row['processGroupAbsent'] = False
        except ProcessLookupError:
            row['processGroupAbsent'] = True
    save()
    if not row['processGroupAbsent']:
        raise RuntimeError('Diagnostic group survives; stop affected session')
    return row.get('exit') == 0

expected = 'ee2d1300f4277ae32e7ea15bab1c72525a79fd63304fc6c096be8f551e1c74e4'
if archive.stat().st_size != 1102474395 or digest(archive) != expected:
    raise ValueError('Retained whole archive mismatch; no execution')
receipt['archiveSHA256'] = expected
scratch = Path(tempfile.mkdtemp(prefix='opemos-7b8-diagnostic-')).resolve()
subprocess.run(['ditto', '-x', '-k', str(archive), str(scratch)], check=True, timeout=120)
destination = root / 'dist/macos'
destination.mkdir(parents=True, exist_ok=False)
app = destination / 'SteamOS NVIDIA Builder.app'
(scratch / app.name).rename(app)
exe = app / 'Contents/MacOS/steamos-nvidia-image-builder'
expected_exe = 'bed169ef62af88d8066fcc9e431fc87889d1c7b3617e09c927434c48dfec6812'
if digest(exe) != expected_exe:
    raise ValueError('Retained executable mismatch')
probe = Path.home() / 'Documents/opemos-chooser-diagnostic.img'
probe.parent.mkdir(exist_ok=True)
with probe.open('xb') as stream:
    stream.write(b'Chooser attribute probe only; never an accepted recovery image.\n')
probe.chmod(0o444)
try:
    helper = out / 'macos-ui-smoke'
    if run('helper-build', ['xcrun', 'swiftc', 'tests/macos-ui-smoke.swift', '-o', str(helper)], 90):
        run('native-chooser-observation', [str(helper), str(app), str(out), str(probe), '--chooser-diagnostic'], 150)
    if subprocess.run(['/usr/bin/pgrep', '-f', str(exe)], capture_output=True).returncode != 1:
        raise RuntimeError('Retained app survives; no guest launch')
    command = ['cargo', 'test', '--manifest-path', 'src-tauri/Cargo.toml', '--locked',
               '--target', 'aarch64-apple-darwin', '--lib']
    for name, test in [
        ('reservation-race', 'output_transaction::tests::simultaneous_processes_cannot_reserve_the_same_output_pair'),
        ('readiness-pipes', 'tests::guest_readiness_attempt_is_bounded_reaped_and_output_limited'),
        ('mac-state-paths', 'portable_state::tests::mac_resources_provenance_and_readonly_app_use_separate_user_state'),
    ]:
        run(name, command + [test, '--', '--exact', '--nocapture', '--test-threads=1'], 1200)
    run('actual-guest-traced-fault', ['python3', 'scripts/run_macos_guest_fault.py'], 1200)
except Exception as error:
    receipt['error'] = str(error)
    raise
finally:
    receipt['archiveUnchanged'] = digest(archive) == expected
    receipt['executableUnchanged'] = digest(exe) == expected_exe
    receipt['probeUnchanged'] = probe.read_bytes() == b'Chooser attribute probe only; never an accepted recovery image.\n'
    receipt['qemuAbsent'] = subprocess.run(['/usr/bin/pgrep', '-f', 'qemu-system-'], capture_output=True).returncode == 1
    save()
if not all(receipt[k] for k in ['archiveUnchanged', 'executableUnchanged', 'probeUnchanged', 'qemuAbsent']):
    raise RuntimeError('Immutable input or guest closure failure')

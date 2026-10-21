"""One R9 owned M1 process/pipe observation, never product acceptance.

Compile the current focused test, then observe its unmodified readiness call.
No runtime, app, guest, input acquisition, replacement method or timeout change.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

root = Path(__file__).resolve().parents[1]
out = root / 'build/retained-startup-diagnostic'
out.mkdir(parents=True, exist_ok=False)
receipt = {'acceptance': False, 'writerIdentity': 'UNKNOWN', 'samples': [],
           'uid': os.getuid(), 'source': subprocess.check_output(
               ['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
           'noRuntimeAppGuestAcquisition': True, 'productionLogicUnchanged': True}


def save():
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


def processes():
    result = subprocess.run(['/bin/ps', '-axo', 'pid=,ppid=,pgid=,uid=,lstart=,comm='],
                            capture_output=True, text=True, timeout=3)
    result.check_returncode()
    rows = []
    for line in result.stdout.splitlines():
        parts = line.split(None, 9)
        if len(parts) == 10:
            rows.append({'pid': int(parts[0]), 'ppid': int(parts[1]),
                         'pgid': int(parts[2]), 'uid': int(parts[3]),
                         'birth': ' '.join(parts[4:9]), 'executable': parts[9]})
    return rows


build_command = ['cargo', 'test', '--manifest-path', 'src-tauri/Cargo.toml', '--locked',
                 '--target', 'aarch64-apple-darwin', '--lib',
                 'guest_readiness_attempt_is_bounded_reaped_and_output_limited',
                 '--no-run', '--message-format=json']
with (out / 'compile.log').open('wb') as log:
    build = subprocess.Popen(build_command, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                             start_new_session=True)
    receipt['compile'] = {'command': build_command, 'pid': build.pid}
    try:
        receipt['compile']['exit'] = build.wait(timeout=1200)
    finally:
        if build.poll() is None:
            os.killpg(build.pid, signal.SIGKILL)
            receipt['compile']['cleanupExit'] = build.wait(timeout=5)
        try:
            os.killpg(build.pid, 0)
            receipt['compile']['groupAbsent'] = False
        except ProcessLookupError:
            receipt['compile']['groupAbsent'] = True
        save()
if receipt['compile'].get('exit') != 0 or not receipt['compile']['groupAbsent']:
    raise RuntimeError('Native compile failed or process closure unproved; no focused launch')
artifacts = []
for line in (out / 'compile.log').read_text().splitlines():
    if not line.startswith('{'):
        continue
    row = json.loads(line)
    if (row.get('reason') == 'compiler-artifact' and row.get('profile', {}).get('test')
            and row.get('target', {}).get('name') == 'steamos_nvidia_image_builder_lib'
            and row.get('executable')):
        artifacts.append(row['executable'])
if len(artifacts) != 1:
    raise ValueError('Expected one current-source native test executable')
command = [artifacts[0], 'tests::guest_readiness_attempt_is_bounded_reaped_and_output_limited',
           '--exact', '--nocapture', '--test-threads=1']
child = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         start_new_session=True)
receipt['test'] = {'command': command, 'pid': child.pid}
started = time.monotonic()
deadline = started + 90
roots = set()
reader_fds = {'0', '1', '2'}
observed = {}
captured = bytearray()
last_sample = None
next_sample = started
selector = selectors.DefaultSelector()
selector.register(child.stdout, selectors.EVENT_READ)
try:
    with (out / 'focused.log').open('wb') as log:
        while selector.get_map() or child.poll() is None:
            if time.monotonic() >= deadline:
                receipt['test']['timeout'] = True
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
                raise RuntimeError('Focused diagnostic exceeded finite bound; inner closure UNKNOWN')
            for key, _ in selector.select(0.02):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    receipt['test']['outputEOFSeconds'] = time.monotonic() - started
                    continue
                log.write(data)
                log.flush()
                captured.extend(data)
                if len(captured) > 2 * 1024**2:
                    raise RuntimeError('Focused diagnostic output exceeded finite bound')
                for match in re.finditer(rb'STREAM_DIAGNOSTIC root=(\d+) reader=(\d+) stdoutFD=(\d+) stderrFD=(\d+)', captured):
                    if int(match[2]) != child.pid:
                        raise RuntimeError('Foreign readiness test identity')
                    roots.add(int(match[1]))
                    reader_fds.update([match[3].decode(), match[4].decode()])
            if roots and time.monotonic() >= next_sample:
                selected = [r for r in processes() if r['pid'] == child.pid or r['pgid'] in roots]
                if any(r['uid'] != os.getuid() for r in selected):
                    raise RuntimeError('Foreign UID in observed owned group; no signal authorized')
                for row in selected:
                    observed[(row['pid'], row['birth'])] = row
                if selected != last_sample:
                    row = {'seconds': time.monotonic() - started, 'processes': selected}
                    # Only this test and its isolated group; never inspect unrelated FDs.
                    if selected:
                        ids = ','.join(str(r['pid']) for r in selected)
                        fd = subprocess.run(['/usr/sbin/lsof', '-nP', '-a', '-p', ids,
                                             '-d', ','.join(sorted(reader_fds)), '-FpcfDin'], capture_output=True,
                                            text=True, timeout=3)
                        row['lsof'] = {'exit': fd.returncode, 'stdout': fd.stdout,
                                       'stderr': fd.stderr}
                    receipt['samples'].append(row)
                    last_sample = selected
                    save()
                next_sample = time.monotonic() + 0.1
        receipt['test']['exit'] = child.wait(timeout=5)
        receipt['test']['seconds'] = time.monotonic() - started
finally:
    selector.close()
    child.stdout.close()
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGKILL)
        receipt['test']['cleanupExit'] = child.wait(timeout=5)
    final = processes()
    receipt['observedIdentities'] = list(observed.values())
    receipt['remainingOriginalIdentities'] = [r for r in final if (r['pid'], r['birth']) in observed]
    receipt['remainingOwnedGroups'] = [r for r in final if r['pgid'] in roots]
    receipt['rootPids'] = sorted(roots)
    receipt['closureVerified'] = (bool(roots) and child.poll() is not None and
                                  not receipt['remainingOriginalIdentities'] and
                                  not receipt['remainingOwnedGroups'])
    receipt['evidence'] = {p.name: {'bytes': p.stat().st_size,
                           'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                           for p in out.iterdir() if p.is_file() and p.name != 'receipt.json'}
    save()
if not receipt['closureVerified']:
    raise RuntimeError('Actual original process/group closure remains unproved; no next stage')
# Collection success never changes the original test's numeric result.

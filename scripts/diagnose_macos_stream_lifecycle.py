"""One finite owned M1 process/pipe causal batch, never product acceptance.

Compile current original tests, then observe their unchanged callers/assertions.
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
def collect_case(name, ordinal):
    command = [artifacts[0], name, '--exact', '--nocapture', '--test-threads=1']
    env = dict(os.environ, OPEMOS_STREAM_TRACE='1')
    child = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             start_new_session=True, env=env)
    case = {'name': name, 'command': command, 'pid': child.pid, 'samples': []}
    receipt.setdefault('cases', []).append(case)
    started = time.monotonic()
    deadline = started + 90
    roots = set()
    observed = {}
    captured = bytearray()
    reader_fds = {'0', '1', '2'}
    last_sample = None
    next_sample = started
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    try:
        with (out / f'case-{ordinal}.log').open('wb') as log:
            while selector.get_map() or child.poll() is None:
                if time.monotonic() >= deadline:
                    case['timeout'] = True
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
                    raise RuntimeError('Finite native case timed out; inner closure UNKNOWN')
                for key, _ in selector.select(0.005):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        case['outputEOFSeconds'] = time.monotonic() - started
                        continue
                    log.write(data)
                    log.flush()
                    captured.extend(data)
                    if len(captured) > 2 * 1024**2:
                        raise RuntimeError('Native case output exceeded finite bound')
                    for match in re.finditer(rb'owned guest producer root=(\d+) group=(\d+)', captured):
                        if match[1] != match[2]:
                            raise RuntimeError('Original producer group mismatch')
                        roots.add(int(match[1]))
                    for match in re.finditer(rb'STREAM_DIAGNOSTIC root=(\d+) reader=(\d+) stdoutFD=(\d+) stderrFD=(\d+)', captured):
                        if int(match[2]) != child.pid:
                            raise RuntimeError('Foreign test reader identity')
                        roots.add(int(match[1]))
                        reader_fds.update([match[3].decode(), match[4].decode()])
                if roots and time.monotonic() >= next_sample:
                    selected = [r for r in processes() if r['pid'] == child.pid or r['pgid'] in roots]
                    if any(r['uid'] != os.getuid() for r in selected):
                        raise RuntimeError('Foreign UID observed; no signal authorized')
                    for row in selected:
                        observed[(row['pid'], row['birth'])] = row
                    if selected != last_sample:
                        row = {'seconds': time.monotonic() - started, 'processes': selected}
                        if selected:
                            ids = ','.join(str(r['pid']) for r in selected)
                            fd = subprocess.run(['/usr/sbin/lsof', '-nP', '-a', '-p', ids,
                                                 '-d', ','.join(sorted(reader_fds)), '-FpcfDin'],
                                                capture_output=True, text=True, timeout=3)
                            row['lsof'] = {'exit': fd.returncode, 'stdout': fd.stdout, 'stderr': fd.stderr}
                        case['samples'].append(row)
                        last_sample = selected
                    next_sample = time.monotonic() + 0.02
            case['exit'] = child.wait(timeout=5)
            case['seconds'] = time.monotonic() - started
            if case['exit'] == 0 and b'1 passed; 0 failed' not in captured:
                raise RuntimeError('Exact native case did not execute; zero matched is not acceptance')
    finally:
        selector.close()
        child.stdout.close()
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            case['cleanupExit'] = child.wait(timeout=5)
        final = processes()
        case['observedIdentities'] = list(observed.values())
        case['remainingOriginalIdentities'] = [r for r in final if (r['pid'], r['birth']) in observed]
        case['remainingOwnedGroups'] = [r for r in final if r['pgid'] in roots]
        case['rootPids'] = sorted(roots)
        case['closureVerified'] = (child.poll() is not None and
                                   not case['remainingOriginalIdentities'] and not case['remainingOwnedGroups'])
        traces = []
        for line in captured.decode(errors='replace').splitlines():
            if line.startswith('STREAM_TRACE '):
                traces.extend(json.loads(line[len('STREAM_TRACE '):]))
        (out / f'case-{ordinal}-trace.json').write_text(json.dumps(traces, indent=2) + '\n')
        case['traceEvents'] = len(traces)
        receipt['evidence'] = {p.name: {'bytes': p.stat().st_size,
                               'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                               for p in out.iterdir() if p.is_file() and p.name != 'receipt.json'}
        save()
    if not case['closureVerified']:
        raise RuntimeError('Actual original native case closure unproved; stop affected batch')


# One finite batch; ordinary test failures remain numeric failures, and do not
# suppress the independent original fault cases when actual process closure holds.
for ordinal, name in enumerate([
    'tests::guest_readiness_attempt_is_bounded_reaped_and_output_limited',
    'tests::structured_guest_command_is_framed_bounded_and_reaped',
    'tests::guest_stream_lifecycle_joins_inherited_writers_and_retains_primary_failures',
    'tests::guest_shutdown_observation_retains_transport_and_closure_separately',
    'guest_process::tests::owned_guest_cancel_and_repeated_finalize_retain_original_custody',
    'guest_process::tests::repeated_stop_still_refuses_external_reap',
    'guest_process::tests::darwin_unknown_or_foreign_group_never_becomes_owned_exit',
]):
    collect_case(name, ordinal)
receipt['collectionComplete'] = True
receipt['allActualTestsPassed'] = all(c['exit'] == 0 for c in receipt['cases'])
save()
raise SystemExit(0 if receipt['allActualTestsPassed'] else 1)

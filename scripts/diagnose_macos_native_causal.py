"""Finite same-producer native collection, not app/GUI/runtime acceptance."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

root = Path(__file__).resolve().parents[1]
out = root / 'build/retained-startup-diagnostic'
out.mkdir(parents=True, exist_ok=False)
receipt = {'acceptance': False, 'collectionOnly': True, 'stages': [],
           'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
           'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(), 'egid': os.getegid(),
           'started': time.time(), 'noBulkProducerOrApp': True}


def save():
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


def stage(label, argv, seconds):
    with (out / (label + '.log')).open('xb') as log:
        child = subprocess.Popen(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        row = {'label': label, 'command': argv, 'pid': child.pid, 'started': time.time()}
        receipt['stages'].append(row)
        save()
        try:
            row['exit'] = child.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            row['timeout'] = True
            os.killpg(child.pid, signal.SIGKILL)
            row['cleanupExit'] = child.wait(timeout=5)
        finally:
            log.flush()
            os.fsync(log.fileno())
            row['reaped'] = child.returncode is not None
            try:
                os.killpg(child.pid, 0)
                row['outerGroupAbsent'] = False
            except ProcessLookupError:
                row['outerGroupAbsent'] = True
            row['finished'] = time.time()
            save()
    return row


try:
    command = ['cargo', 'test', '--manifest-path', 'src-tauri/Cargo.toml', '--locked',
               '--target', 'aarch64-apple-darwin', '--lib', 'native_causal_diagnostic',
               '--no-run', '--message-format=json']
    built = stage('compile', command, 1200)
    if built.get('exit') != 0 or not built['outerGroupAbsent']:
        raise RuntimeError('Native diagnostic compile failed/closure unknown; no test launch')
    executables = []
    for line in (out / 'compile.log').read_text().splitlines():
        if line.startswith('{'):
            row = json.loads(line)
            if (row.get('reason') == 'compiler-artifact' and row.get('profile', {}).get('test')
                    and row.get('target', {}).get('name') == 'steamos_nvidia_image_builder_lib'
                    and row.get('executable')):
                executables.append(row['executable'])
    if len(executables) != 1:
        raise ValueError('One exact current-source native test executable required')
    exe = Path(executables[0])
    receipt['testExecutable'] = {'path': str(exe), 'bytes': exe.stat().st_size,
                                'sha256': hashlib.sha256(exe.read_bytes()).hexdigest()}
    observed = stage('native-causal', [str(exe), 'native_causal_diagnostic', '--nocapture',
                                     '--test-threads=1'], 45)
    receipt['collectionCompleted'] = observed.get('exit') == 0 and observed['outerGroupAbsent']
    receipt['innerClosure'] = 'Read literal native per-case identities/EOF/reap/group membership; outer absence is not inner proof'
    if not receipt['collectionCompleted']:
        raise RuntimeError('Finite native collection failed; retain first failure and unknown closure')
except BaseException as error:
    receipt['firstFailure'] = {'type': type(error).__name__, 'reason': str(error)}
    raise
finally:
    receipt['finished'] = time.time()
    receipt['files'] = {p.name: {'bytes': p.stat().st_size,
                               'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                        for p in out.iterdir() if p.is_file() and p.name != 'receipt.json'}
    save()

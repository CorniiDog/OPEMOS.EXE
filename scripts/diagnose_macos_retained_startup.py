"""One finite diagnostic of the retained failed aac app, NOT GUI acceptance."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

archive = Path(sys.argv[1])
out = Path('build/retained-startup-diagnostic').resolve()
out.mkdir(parents=True, exist_ok=False)
def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()
expected = '8132e612ad392ab4617b05eb0a67de3462a7a0e794995b663267d729c622abf8'
if archive.stat().st_size != 1102475167 or digest(archive) != expected:
    raise ValueError('Retained full archive identity mismatch; no execution')
root = Path(tempfile.mkdtemp(prefix='opemos-aac-diagnostic-')).resolve()
subprocess.run(['ditto', '-x', '-k', str(archive), str(root)], check=True, timeout=120)
app = root / 'SteamOS NVIDIA Builder.app'
exe = app / 'Contents/MacOS/steamos-nvidia-image-builder'
if digest(exe) != '2f2c8d482a2a1e81e1f6d61e90966ec70ce62ed57eb95ff60d886080da0b6246':
    raise ValueError('Retained executable identity mismatch')
receipt = {'acceptance': False, 'archiveSHA256': expected, 'command': [str(exe)], 'app': str(app)}
with (out / 'stdout.log').open('wb') as stdout, (out / 'stderr.log').open('wb') as stderr:
    child = subprocess.Popen([str(exe)], stdout=stdout, stderr=stderr, start_new_session=True)
    receipt['pid'] = child.pid
    try:
        receipt['exit'] = child.wait(timeout=20)
    except subprocess.TimeoutExpired:
        receipt['timedOut'] = True
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        receipt['cleanupExit'] = child.returncode
    try:
        os.killpg(child.pid, 0)
        receipt['processGroupAbsent'] = False
    except ProcessLookupError:
        receipt['processGroupAbsent'] = True
receipt['archiveUnchanged'] = digest(archive) == expected
receipt['executableUnchanged'] = digest(exe) == '2f2c8d482a2a1e81e1f6d61e90966ec70ce62ed57eb95ff60d886080da0b6246'
# Capture actual display after diagnostic, under an independent finite reserve.
shot = subprocess.run(['/usr/sbin/screencapture', '-x', str(out / 'after-startup.png')], timeout=10)
receipt['screenshotExit'] = shot.returncode
(out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt))
if not receipt['processGroupAbsent'] or not receipt['archiveUnchanged'] or not receipt['executableUnchanged']:
    raise RuntimeError('Diagnostic closure or immutable input failure')

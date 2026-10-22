"""Fixed A data packaging INSIDE actual OMEN macOS; no signing/publication."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

if sys.platform!='darwin':raise SystemExit('Actual admitted OMEN macOS SDK/guest required')
source=Path.cwd();apps=list((source/'src-tauri/target/release/bundle/macos').glob('*.app'))
if len(apps)!=1:raise SystemExit('Exactly one current native built app required')
app=apps[0];binary=app/'Contents/MacOS/steamos-nvidia-image-builder'
if binary.is_symlink()or not binary.is_file():raise SystemExit('Actual regular native app executable missing')
arch=subprocess.run(['/usr/bin/lipo','-archs',str(binary)],capture_output=True,check=True,timeout=15)
if arch.stdout.strip()!=b'arm64'or arch.stderr:raise SystemExit('Actual arm64 executable required, not translated x86')
out=source/'build/macos-arm64-evidence';out.mkdir(mode=0o700,parents=True,exist_ok=False)
target=out/binary.name;shutil.copyfile(binary,target);target.chmod(0o700)
subprocess.run(['/usr/bin/ditto','-c','-k','--sequesterRsrc','--keepParent',str(app),
    str(out/'SteamOS-NVIDIA-Builder-arm64.app.zip')],stdin=subprocess.DEVNULL,check=True,timeout=120)
def pin(path):
    h=hashlib.sha256()
    with path.open('rb')as stream:
        while block:=stream.read(1024**2):h.update(block)
    return {'name':path.name,'bytes':path.stat().st_size,'sha256':h.hexdigest()}
value={'kind':'OMEN_NATIVE_MAC_PACKAGE_V1','exe_source_commit':os.environ['OPEMOS_EXE_COMMIT'],
       'execution_location':'OMEN_VM','artifact':{'architectures':'arm64','executable':str(target)},
       'files':[pin(target),pin(out/'SteamOS-NVIDIA-Builder-arm64.app.zip')],
       'GUIBuildAccepted':False,'imageCompleted':False,'signingOrPublication':False}
with (out/'receipt.json').open('x')as stream:json.dump(value,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())

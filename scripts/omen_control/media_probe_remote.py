"""Fixed installed readonly normal probe with authenticated JSON configuration."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types


def read(ref):
    fd=os.open(ref['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        i={k:getattr(os.fstat(fd),k)for k in ref['identity']};raw=b''
        if i!=ref['identity']or i['st_uid']!=0 or i['st_gid']!=0 or not stat.S_ISREG(i['st_mode'])or stat.S_IMODE(i['st_mode'])!=0o444:
            raise RuntimeError('immutable normal probe source')
        while b:=os.read(fd,65536):
            raw+=b
            if len(raw)>1048576:raise RuntimeError('probe input cap')
        if len(raw)!=ref['bytes']or hashlib.sha256(raw).hexdigest()!=ref['sha256']or any(i[k]!=getattr(os.fstat(fd),k)or i[k]!=getattr(os.lstat(ref['path']),k)for k in i):
            raise RuntimeError('probe source full9/EOF/hash')
        return raw
    finally:os.close(fd)


def main():
    if os.getuid()!=os.geteuid()or os.getuid()!=0:raise RuntimeError('authenticated Root readonly peer')
    ap=argparse.ArgumentParser();ap.add_argument('--profile-pin-json',required=True);a=ap.parse_args()
    profile=json.loads(read(json.loads(a.profile_pin_json)))
    if profile['kind']!='OPEMOS_INSTALLED_MEDIA_PROBE_V1':raise RuntimeError('probe profile')
    raw=sys.stdin.buffer.read(65537)
    if len(raw)>65536:raise RuntimeError('typed probe data cap')
    data=json.loads(raw)
    if set(data)!={'github'}:raise RuntimeError('data only; no executable producer')
    ref=profile['normalProbePin'];source=read(ref)
    if ref['sha256']!=profile['policy']['normalProbeSHA256']:raise RuntimeError('same normal source identity')
    m=types.ModuleType('installed_normal_media_probe');m.__file__=ref['path']
    # These are the existing normal probe's explicit configuration inputs. Its
    # executable bytes and observation methods remain unchanged.
    m.__dict__.update(REMOTE_POLICY=profile['policy'],REMOTE_GITHUB=data['github'])
    exec(compile(source,ref['path'],'exec'),m.__dict__)
    value=m.observe()
    print(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False),flush=True)


if __name__=='__main__':main()

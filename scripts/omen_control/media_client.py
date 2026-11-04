"""Existing authenticated SSH -> fixed installed media entry, JSON data only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import types
import uuid


def held(ref, cap=1048576):
    fd = os.open(ref['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    try:
        i = {k: getattr(os.fstat(fd), k) for k in fields}; raw = b''
        if i != ref['identity'] or not stat.S_ISREG(i['st_mode']) or i['st_nlink'] != 1:
            raise RuntimeError('exact installed client input')
        while chunk := os.read(fd, 65536):
            raw += chunk
            if len(raw) > cap: raise RuntimeError('client input cap')
        if len(raw) != ref['bytes'] or hashlib.sha256(raw).hexdigest() != ref['sha256'] or any(
                i[k] != getattr(os.fstat(fd), k) or i[k] != getattr(os.lstat(ref['path']), k) for k in fields):
            raise RuntimeError('client input full9/EOF/hash')
        return raw
    finally: os.close(fd)


def execute(profile_pin, root, attempt):
    if os.getuid() != 0 or profile_pin['identity']['st_uid'] != profile_pin['identity']['st_gid'] or profile_pin['identity']['st_uid'] != 0:
        raise RuntimeError('authenticated installed Root client profile')
    profile = json.loads(held(profile_pin))
    if profile['kind'] != 'OPEMOS_INSTALLED_MEDIA_CLIENT_V1' or stat.S_IMODE(profile_pin['identity']['st_mode']) != 0o444:
        raise RuntimeError('immutable installed client profile')
    cfg = profile['sshConfigPin']; held(cfg, 65536)
    if cfg['identity']['st_uid'] != cfg['identity']['st_gid'] or cfg['identity']['st_uid'] != 0 or stat.S_IMODE(cfg['identity']['st_mode']) != 0o444:
        raise RuntimeError('immutable installed copy of existing authenticated SSH config')
    source = profile['ownedCommandPin']; raw = held(source, 65536)
    if source['sha256'] != '8bef0493ec80da6278f884e60a31a1445b4a45661837095de74055f3a56ed102':
        raise RuntimeError('reviewed owned child lifecycle implementation')
    module = types.ModuleType('owned_media_client'); module.__file__ = source['path']
    exec(compile(raw, source['path'], 'exec'), module.__dict__)
    if len(attempt) != 32 or any(x not in '0123456789abcdef' for x in attempt): raise RuntimeError('attempt identifier')
    root = Path(root)
    if os.path.lexists(root): raise RuntimeError('unused evidence directory')
    root.mkdir(mode=0o700)
    data = {'executionAttempt': attempt, 'jobId': profile['jobPrefix'] + '-e' + attempt[:16]}
    # One unchanged normal heavy wrapper owns preparation AND the worker. The
    # worker uses its existing in-wrapper CLI entry rather than reacquiring the
    # same lock. Root entry revalidates the real Bash ancestor/FD/OFD throughout.
    remote = ['/usr/bin/env','XDG_RUNTIME_DIR=/run/user/1000',
              'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus',
              profile['remoteHeavyPin']['path'],'/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-B', profile['remoteEntry'],
              '--profile-pin-json', json.dumps(profile['remoteProfilePin'], sort_keys=True, separators=(',', ':')),
              '--request-stdin']
    argv = ['/usr/sbin/runuser', '-u', 'connor', '--', '/usr/bin/ssh', '-T', '-F', cfg['path'],
            '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=yes',
            'opemos-ubuntu-host', shlex.join(remote)]
    result = module.run_owned_command(argv, json.dumps(data, sort_keys=True, separators=(',', ':')).encode(),
                                       2450, [root / 'stdout.raw', root / 'stderr.raw'], stream_limit=8388608)
    with (root / 'native.json').open('x') as f: json.dump(result, f, indent=2); f.write('\n')
    if result['numericExit'] != 0 or not result['lifecycleClosed'] or not result['fd']['restored'] or not result['childSetRestored']:
        raise RuntimeError('actual native media attempt failed; full raw/FIRST and closure retained at ' + str(root))
    return result


if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--profile-pin-json', required=True)
    ap.add_argument('--evidence', required=True); ap.add_argument('--attempt', required=True); args = ap.parse_args()
    execute(json.loads(args.profile_pin_json), args.evidence, args.attempt)

"""Installed bounded media priority window. Deployment review stays outside runtime.

Only installed immutable code/profile and current machine/OS/GitHub facts can
admit a request. An idle normal control generation is retired through the same
scoped pidfd protocol; active builds and foreign owners are preserved.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import time
import types

ROOT = Path('/var/lib/opemos-robot-control-r1/auto-recovery')
TIMER = 'opemos-runner21-recovery.timer'
SERVICE = 'opemos-runner21-recovery.service'
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def need(ok, message):
    if not ok: raise RuntimeError(message)


def read(ref, cap=1048576, modes=(0o400,0o444)):
    fd = os.open(ref['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        i = {k: getattr(os.fstat(fd), k) for k in FIELDS}; raw = b''
        need(i == ref['identity'] and i['st_uid'] == i['st_gid'] == 0
             and stat.S_ISREG(i['st_mode']) and stat.S_IMODE(i['st_mode']) in modes
             and i['st_nlink'] == 1, 'immutable installed window input')
        while b := os.read(fd, 65536): raw += b; need(len(raw) <= cap, 'window input cap')
        need(len(raw) == ref['bytes'] and hashlib.sha256(raw).hexdigest() == ref['sha256']
             and all(i[k] == getattr(os.fstat(fd), k) == getattr(os.lstat(ref['path']), k) for k in FIELDS),
             'whole window input full9/EOF/hash')
        return raw
    finally: os.close(fd)


def module(ref, name):
    m = types.ModuleType(name); m.__file__ = ref['path']
    exec(compile(read(ref), ref['path'], 'exec'), m.__dict__)
    return m


def idle_builds(value):
    need(value['networkReachable'] is True and value['runnerBusy'] is False
         and type(value['actionsInProgress']) is int and value['actionsInProgress'] == 0,
         'current authenticated Runner21 idle/no assigned build')
    need(value['sourceOwnerBusy'] is False and value['queueKnown'] is True
         and value['otherActiveJobs'] == [] and value['unknownReservations'] == []
         and value['guestActive'] is False and value['gpuLeaseActive'] is False
         and value['hostGraphics'] == 'INTEL_HOST_NVIDIA_GUEST_ONLY',
         'actual source/queue/native/pool ownership, Intel host')


def admitted_media(value):
    idle_builds(value)
    c = value['control']
    need((c['state'] == 'absent' or (c['terminalLifecycle'] == 'CLOSED'
                                    and c['reservationRetained'] is False))
         and value['workerLockFree'] is True and value['runnerOnline'] is False,
         'normal control/worker/heavy closure and real runner offline before VM')



def observe_after_drain(probe, inputs, deadline, cuts):
    """Only expected idle API status convergence can request a new full cut."""
    while True:
        need(time.monotonic() < deadline, 'bounded runner status convergence before fresh cut')
        try:
            value = probe.observe(inputs)
        except probe.RunnerStatusTransition as error:
            cuts.append({'runnerStatusTransition': {'before': error.before, 'after': error.after}})
            remaining = deadline - time.monotonic()
            need(remaining > 0, 'bounded runner status convergence after normal drain')
            time.sleep(min(.5, remaining))
            continue
        need(time.monotonic() < deadline, 'bounded runner status convergence after fresh cut')
        return value


def execute(profile_pin, attempt):
    need(os.getuid() == os.geteuid() == 0 and re.fullmatch('[0-9a-f]{32}', attempt), 'Root typed request')
    profile = json.loads(read(profile_pin))
    need(profile['kind'] == 'OPEMOS_INSTALLED_MEDIA_WINDOW_V1'
         and profile['maximumWindowSeconds'] == 2700, 'installed finite operation profile')
    for ref in profile['localSources'].values(): read(ref)
    need(profile['localSources']['media_window']['path'] == str(Path(__file__).absolute()),
         'actual installed window entry')
    W = module(profile['localSources']['window_common'], 'media_window_common')
    owned = module(profile['localSources']['owned_command'], 'media_window_owned')
    probe = module(profile['currentProbePin'], 'media_current_machine_probe')
    client = module(profile['localSources']['media_client'], 'media_normal_client')
    evidence = Path(profile['evidenceRoot']) / attempt
    need(not os.path.lexists(evidence), 'fresh create-only operation identity')
    evidence.mkdir(mode=0o700)
    errors = []
    def record(name, value): return W.put_diagnostic(evidence, name, value, errors)
    def command(name, argv, seconds=30):
        return W.native(owned, evidence, name, argv, seconds=seconds, allow_stderr=True)
    def service_idle():
        end = time.monotonic() + 15
        while True:
            state = W.manager(SERVICE)
            need(state['LoadState'] == 'loaded' and state['UnitFileState'] == 'static', 'fixed normal recovery service')
            if state['ActiveState'] in ('inactive','failed') and state['MainPID'] == '0' and state['ControlGroup'] == state['Job'] == '':
                return
            need(time.monotonic() < end, 'bounded genuine recovery completion; no signal')
            time.sleep(.2)
    lock = W.acquire_recovery_mutex(ROOT / 'recovery.lock', 20)
    restore = 'opemos-media-restore-' + attempt[:16]
    paused = backstop = False; first = None; closure_errors = []
    try:
        service_idle()
        before = probe.observe(profile['probeInputs']); idle_builds(before); record('actual-before.json', before)
        original = W.manager(TIMER)
        need(original['ActiveState'] == 'active' and original['UnitFileState'] == 'enabled'
             and original['Job'] == '', 'existing enabled automatic recovery owner')
        for suffix in ('.service','.timer'):
            v = W.manager(restore + suffix)
            need(v['LoadState'] == 'not-found' and v['ActiveState'] == 'inactive'
                 and v['Job'] == '', 'unused finite restoration unit')
        command('backstop', ['/usr/bin/systemd-run', '--unit=' + restore, '--on-active=2700s',
                            '--timer-property=AccuracySec=1s', '/usr/bin/systemctl', 'start', TIMER])
        backstop = True
        paused = True; command('pause-renewal', ['/usr/bin/systemctl', 'stop', TIMER])
        need(W.manager(TIMER)['ActiveState'] == 'inactive', 'normal renewal pause verified')
        service_idle()
        current = probe.observe(profile['probeInputs']); idle_builds(current)
        c = current['control']
        if c['state'] != 'absent' and not (c['terminalLifecycle'] == 'CLOSED' and c['reservationRetained'] is False):
            # Fresh journal/source/policy data are authenticated by the installed
            # controller. The remote fixed drain program receives JSON only.
            policy = json.loads(read(profile['controlPolicyPin'], modes=(0o400,0o444,0o600)))
            state, _ = W.held(ROOT / 'state.json')
            origins = []  # report/journal formatting is not control ownership
            data = {'mode':'execute','rule':{'kind':'ROOT_AUTOMATIC_RUNNER21_ONLY_CURRENT_GENERATION',
                    'runnerId':21,'mainCommit':policy['mainCommit'],'queueSHA256':policy['queueSourceSHA256'],
                    'boot':current['boot']}, 'policy':policy,'recoveryState':json.loads(state),
                    'github':{k:current[k] for k in ('networkReachable','protectedMain','mainCommit',
                                                    'runnerOnline','runnerBusy','actionsInProgress','actionsQueued')},
                    'probeAt':current['atUnix'], 'controllerOrigins':origins,
                    'controllerBoot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                    'installedSources':profile['remoteDrainSources']}
            remote = ['sudo','-n','/usr/bin/python3','-I','-B',profile['remoteDrainEntry'],
                      '--profile-pin-json',json.dumps(profile['remoteDrainProfilePin'],sort_keys=True,separators=(',',':'))]
            ssh = profile['sshArgv'] + [shlex.join(remote)]
            W.native(owned,evidence,'normal-drain',ssh,json.dumps(data,sort_keys=True,separators=(',',':')).encode(),
                     seconds=210,allow_stderr=True)
            closed = json.loads((evidence/'normal-drain-stdout.raw').read_bytes())
            need(closed['first'] is None and closed['normalClosureComplete'] is True
                 and closed['FDSetRestored'] is True, 'single normal current-owner drain/closure')
        end = time.monotonic() + 20; cuts = []
        while True:
            after = observe_after_drain(probe, profile['probeInputs'], end, cuts)
            idle_builds(after); cuts.append(after)
            control = after['control']
            closed = control['state'] == 'absent' or (control['terminalLifecycle'] == 'CLOSED'
                                                       and control['reservationRetained'] is False)
            if closed and after['workerLockFree'] is True and after['runnerOnline'] is False: break
            need(time.monotonic() < end, 'bounded normal closure/offline convergence; never resignal')
            time.sleep(.5)
        admitted_media(after); record('actual-at-media-entry.json', {'cuts':cuts,'final':after})
        # Static client/entry, fresh typed request. There is no per-run LLM review
        # or code generation here; deployment review precedes installation.
        result = client.execute(profile['clientProfilePin'], evidence/'media', attempt)
        return result
    except BaseException as error:
        first = error
        record('FIRST.json',{'type':type(error).__name__,'reason':str(error)})
        raise
    finally:
        if paused:
            try:
                command('restore-renewal',['/usr/bin/systemctl','start',TIMER])
                need(W.manager(TIMER)['ActiveState']=='active','normal recovery timer restored')
            except BaseException as error: closure_errors.append(str(error))
        if backstop and not closure_errors:
            try: command('retire-backstop',['/usr/bin/systemctl','stop',restore+'.timer'])
            except BaseException as error: closure_errors.append(str(error))
        os.close(lock)
        record('final.json',{'first':None if first is None else str(first),'cleanup':closure_errors,
                             'diagnosticErrors':errors,'guestAcceptanceClaimed':False})
        if closure_errors and first is None: raise RuntimeError('restoration unknown; finite backstop preserved: '+repr(closure_errors))


if __name__ == '__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--profile-pin-json',required=True)
    ap.add_argument('--attempt',required=True);a=ap.parse_args()
    execute(json.loads(a.profile_pin_json),a.attempt)

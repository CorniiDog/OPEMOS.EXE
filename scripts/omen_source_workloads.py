"""Finite guest-only commands for the existing OMEN required-check ingress.

This is controller A code. Never load a command, environment or script from a
candidate workflow on the host. Candidate B is checked out only inside the VM.
No effects occur at import. Tool/cache provisioning is an independent admission.
"""
import hashlib
import json
import re

REPO = 'CorniiDog/OPEMOS.EXE'
CORE = 'f72aff92a5534b676083ccba974f4185f2d4551f'
INTEGRATION_CORE = 'adf372b857cd348b6a18680b45ffcea790f04d4b'
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
NUMBER = re.compile(r'[1-9][0-9]{0,19}\Z')
WORKLOADS = {
    'frontend-and-docs': ('ubuntu', 900),
    'rust': ('ubuntu', 1800),
    'linux-integration': ('ubuntu', 1800),
    'debian-12-package': ('debian12', 2400),
    'seed-runtime-source': ('ubuntu', 1800),
    'windows-build': ('windows', 7200),
    'appimage-package': ('ubuntu', 3600),
    'producer-metadata-diagnostic': ('windows',300),
    'macos-build': ('macos',5400),
}
PARENT_WORKLOADS={'.github/workflows/checks.yml':{'frontend-and-docs','rust','linux-integration','debian-12-package'},
    '.github/workflows/windows-portable.yml':{'seed-runtime-source','windows-build','producer-metadata-diagnostic'},
    '.github/workflows/ubuntu-executable.yml':{'appimage-package'},
    '.github/workflows/macos-arm64.yml':{'macos-build'}}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def selection(value, controller):
    fields = {'repository', 'controller_commit', 'candidate_commit', 'base_commit',
              'pull_request', 'repository_id', 'head_repository_id', 'workload',
              'candidate_tree','parent_run','parent_attempt','parent_workflow'}
    branch=type(value)is dict and value.get('source_kind')=='branch'
    provenance={'producer_event','producer_ref','workflow_commit'}
    if type(value)is dict and provenance&set(value):
        need(provenance<=set(value),'complete original workflow/event/ref provenance')
        fields|=provenance
    need(type(value) is dict and set(value) == (fields|{'source_kind','source_ref'}if branch else fields), 'finite source workload subject')
    if branch:
        ref=value['source_ref'];need(type(ref)is str and re.fullmatch(r'refs/heads/[A-Za-z0-9_][A-Za-z0-9_./-]{0,239}',ref)and
            ref!='refs/heads/main'and not any(x in ref for x in('..','//','/.','.lock'))and not ref.endswith(('/','.')),
            'finite original branch source ref')
    if provenance<=set(value):
        need(value['producer_event']in('push','workflow_dispatch','pull_request')and
             type(value['workflow_commit'])is str and COMMIT.fullmatch(value['workflow_commit'])and
             value['producer_ref']==('refs/pull/'+str(value['pull_request'])+'/merge'if value['producer_event']=='pull_request'else
                 value.get('source_ref','refs/heads/main')),'exact original event/ref/workflow identity')
    need(value['repository'] == REPO and value['controller_commit'] == controller and
         all(type(value[k]) is str and COMMIT.fullmatch(value[k]) for k in
             ('controller_commit', 'candidate_commit', 'base_commit', 'candidate_tree')) and
         value['workload'] in WORKLOADS and
         all(type(value[k]) is int and value[k] > 0 for k in
             ('repository_id', 'head_repository_id')) and
         value['repository_id'] == value['head_repository_id'] and
         type(value['pull_request']) is int and 0 <= value['pull_request'] < 2**31,
         'exact same-repository source/archive/tree identity')
    need(value['parent_workflow']in PARENT_WORKLOADS and value['workload']in PARENT_WORKLOADS[value['parent_workflow']]and
         all(type(value[k])is str and NUMBER.fullmatch(value[k])for k in('parent_run','parent_attempt')),
         'finite original required parent run/attempt/workload scope')
    if branch:need(value['pull_request']==0 and value['base_commit']==controller,'branch has no invented PR association')
    elif value['pull_request']:
        need(value['base_commit'] == controller != value['candidate_commit'], 'distinct A/PR B roles')
    else:
        need(value['base_commit'] == value['candidate_commit'] == controller, 'exact Main source job')
    return value


def subject(value, controller):
    need(type(value)is dict and {'source_archive_sha256','source_archive_bytes'}<=set(value),
         'Root-bound immutable source archive required')
    selection({k:v for k,v in value.items()if k not in('source_archive_sha256','source_archive_bytes')},controller)
    need(type(value['source_archive_bytes'])is int and 0<value['source_archive_bytes']<=256*1024**2 and
         type(value['source_archive_sha256'])is str and SHA.fullmatch(value['source_archive_sha256']),
         'bounded exact Root source archive identity')
    return value


def commands(workload, source):
    """Fixed argv tokens, not shell/YAML from B; paths expand only in the guest."""
    need(workload in WORKLOADS, 'unknown required workload')
    if workload=='producer-metadata-diagnostic':
        return [['python','-B','scripts/diagnose_windows_producer_metadata.py']]
    npm = [['npm', 'ci', '--offline', '--no-audit', '--no-fund']]
    rust = [['cargo', 'fmt', '--manifest-path', 'src-tauri/Cargo.toml', '--', '--check'],
            ['cargo', 'clippy', '--offline', '--locked', '--manifest-path', 'src-tauri/Cargo.toml',
             '--all-targets', '--all-features', '--', '-D', 'warnings'],
            ['cargo', 'test', '--offline', '--locked', '--manifest-path', 'src-tauri/Cargo.toml']]
    if workload=='macos-build':
        return npm+[['python','-B','-m','unittest','discover','-s','tests','-p','test_omen_source_jobs.py','-v']]+rust+[
            ['npm','run','build:app'],['python','-B','@CONTROLLER@/macos-source-package.py']]
    if workload == 'frontend-and-docs':
        return npm + [['npm', 'run', 'test:frontend'], ['git', 'diff', '--check']]
    if workload == 'rust':
        return [['node', 'scripts/check_core_maintainer_workflow.mjs']] + rust
    if workload == 'linux-integration':
        return [['python', '-B', 'tests/robot/test_peerpid_namespace.py', '--source',
                 '@SOURCE@/scripts/robot_client.py', '--sha256', '@CLIENT_SHA@'],
                ['python', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_omen*.py', '-v'],
                *[['cargo', 'test', '--offline', '--locked', '--manifest-path', 'src-tauri/Cargo.toml', case,
                   '--', '--ignored'] for case in
                  ('exact_core_source_intent_matrix_matches_rust_contract',
                   'immutable_core_generation_reaches_guest_consumption_and_activation',
                   'live_linux_disposable_host_tools')]]
    if workload == 'debian-12-package':
        return [['bash', 'scripts/check_linux_host.sh']] + npm + [
            ['npm', 'run', 'build:debian12-test'],
            ['python', '-B', 'scripts/check_linux_packaging.py', '--expected-libc', '2.36', '--expected-openssl', 'libssl3'],
            ['python', '-B', 'scripts/check_linux_appimage.py'],
            ['dbus-run-session', '--', 'xvfb-run', '--auto-servernum', 'tini', '-s', '--',
             'python3', 'scripts/check_debian_package_install.py'],
            ['python', '-B', 'scripts/acquire_appliance_windows.py', '--output', 'build/appliance/linux'],
            ['python', '-B', 'scripts/stage_linux_packages.py', '--source-commit', source,
             '--appliance-image', 'build/appliance/linux/fedora-builder.qcow2']]
    if workload == 'seed-runtime-source':
        # Acquisition remains the existing lock verifier; all files must already
        # be staged. The guest has no NIC and never receives Actions credentials.
        return [['python', '-B', 'scripts/acquire_runtime_windows.py', '--component', name,
                 '--cache', 'build/runtime-cache/windows'] for name in
                ('git-for-windows', 'github-cli', 'python', 'qemu', 'cdrtools-binary', 'cdrtools-source')]
    if workload == 'windows-build':
        return [['python', '-B', '-m', 'unittest', 'discover', '-s', 'tests',
                 '-p', 'test_omen_producer_native.py', '-v']] + npm + [
            ['node', 'scripts/windows-portable-workflow.mjs'],
            ['node', '--test', 'tests/windows-portable-workflow.test.mjs'],
            ['node', 'scripts/check_core_maintainer_workflow.mjs'],
            ['python', '-B', '-m', 'unittest',
             'tests.runtime_bundle_packaging.RuntimeBundlePackagingTests.test_windows_runtime_adds_exact_core_zstd_dependency'],
            ['cargo', 'test', '--offline', '--locked', '--manifest-path', 'src-tauri/Cargo.toml', '--lib', 'windows_'],
            ['pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-File', 'bundle_windows.ps1',
             '-CoreRoot', 'opemos-core-contracts'],
            ['pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-File', '@CONTROLLER@/windows-source-smoke.ps1']]
    return npm + [['npm', 'run', 'build:linux-test'],
                  ['python', '-B', 'scripts/acquire_appliance_windows.py', '--output', 'build/appliance/linux'],
                  ['python', '-B', 'scripts/stage_linux_packages.py', '--source-commit', source,
                   '--appliance-image', 'build/appliance/linux/fedora-builder.qcow2']]


def dependencies(workload):
    """Only real output/setup prerequisites within the existing fixed commands.

    Check failures do not gate independent checks or a useful build attempt.
    Overall source/package acceptance still requires every command to pass.
    """
    graph={
        'frontend-and-docs': [(),(0,),()],
        'rust': [(),(),(),()],
        'linux-integration': [(),(),(),(),()],
        'debian-12-package': [(),(),(0,1),(2,),(2,),(2,3),(),(2,3,4,6)],
        'seed-runtime-source': [(),(),(),(),(),()],
        'windows-build': [(),(),(),(),(),(),(),(1,),(7,)],
        'appimage-package': [(),(0,),(),(1,2)],
        'producer-metadata-diagnostic': [()],
        'macos-build': [(),(),(),(),(),(0,),(5,)],
    }
    need(workload in graph,'unknown finite command dependency graph')
    rows=graph[workload]
    need(len(rows)==len(commands(workload,'0'*40))and
         all(all(type(p)is int and 0<=p<i for p in deps)for i,deps in enumerate(rows)),
         'complete forward-only finite workload dependencies')
    return rows


def command_status(row):
    """A nonzero exit is ordinary ONLY with complete healthy native capture.

    Timeout/overflow/unknown identity/negative signal exit/cleanup errors are
    hard stops, never an ordinary compiler failure to continue through.
    """
    healthy=(type(row.get('numeric_exit'))is int and row['numeric_exit']>=0 and
        row.get('first')is None and row.get('secondary')==[]and
        all(row.get(k)is True for k in('reaped','stdoutEOF','stderrEOF','FDsClosed','descendantsAbsent'))and
        type(row.get('pid'))is int and row['pid']>0 and
        type(row.get('birth'))is int and row['birth']>0)
    for name in('stdout','stderr'):
        pin=row.get(name,{})
        healthy=healthy and type(pin.get('sha256'))is str and bool(SHA.fullmatch(pin['sha256']))and \
            type(pin.get('bytes'))is int and 0<=pin['bytes']<=32*1024**2
    return ('passed'if row['numeric_exit']==0 else'failed')if healthy else'hard-failed'


def hard_stop_event(manifest_sha, phase, index, rows, failure_ordinal, cause):
    """Called only at the sealed A producer's caught hard exception boundary.

    The Root-pinned manifest/result transport authenticates the producer; this
    record binds its exact event to the failure list and original captured row.
    An ordinary command failure is never a hard-event cause.
    """
    attempted=len(rows)>index
    return {'kind':'OMEN_SOURCE_HARD_STOP_V1','manifest_sha256':manifest_sha,
        'phase':phase,'command_index':index,'stop_before':index+int(attempted),
        'failure_ordinal':failure_ordinal,'cause':cause,
        'row_sha256':hashlib.sha256(canonical(rows[index])).hexdigest()if attempted else None}


def blocked_command(template, dependencies, rows, hard_stop=None):
    blocked=[p for p in dependencies if rows[p]['status']!='passed']
    need(blocked or hard_stop,'only an actual prerequisite or hard stop blocks a command')
    return {'template_argv':template,'status':'blocked','numeric_exit':None,
            'blocked_by':blocked,'stop_reason':None if hard_stop is None else
                'Hard stop: '+hard_stop['cause']['type']+': '+hard_stop['cause']['reason'],
            'hard_stop_sha256':None if hard_stop is None else hashlib.sha256(canonical(hard_stop)).hexdigest()}


def verify_diagnostics(value, request, spec):
    need(type(value) is dict and value.get('kind') == 'OMEN_GUEST_SOURCE_WORKLOAD_V1' and
         value.get('identity') == request and value.get('subject') == spec,
         'same current source workload result, not GUI acceptance')
    guest = value['guest']
    need(guest['location'] == 'OMEN_VM' and guest['virtualization'] in ('kvm', 'qemu') and
         guest['platform'] == WORKLOADS[spec['workload']][0] and
         type(guest['boot_id']) is str and 0 < len(guest['boot_id']) <= 128 and
         (type(guest['uid']) is str and re.fullmatch(r'S-1-5-21-[0-9-]{1,160}',guest['uid'])
          if guest['platform']=='windows'else type(guest['uid']) is int and guest['uid'] > 0) and
         guest['controller_commit'] == spec['controller_commit'] and
         guest['candidate_commit'] == spec['candidate_commit'], 'actual guest/source provenance')
    rows = value['commands']
    expected = commands(spec['workload'], spec['candidate_commit'])
    need(type(rows) is list and len(rows) == len(expected), 'complete fixed command set')
    graph=dependencies(spec['workload'])
    need('hard_stop'in value,'explicit hard-event absence/presence required')
    event=value['hard_stop'];boundary=len(rows);event_row=None
    if event is not None:
        need(type(event)is dict and set(event)=={'kind','manifest_sha256','phase','command_index',
             'stop_before','failure_ordinal','cause','row_sha256'}and
             event['kind']=='OMEN_SOURCE_HARD_STOP_V1'and
             event['manifest_sha256']==value['controller_manifest_sha256']and
             type(event['manifest_sha256'])is str and SHA.fullmatch(event['manifest_sha256'])and
             type(event['command_index'])is int and 0<=event['command_index']<len(rows)and
             type(event['stop_before'])is int and
             event['stop_before']in(event['command_index'],event['command_index']+1)and
             event['phase']in('input-preparation','source-validation','command-preflight',
                             'command-capture','command-finalize'),
             'exact finite hard-event phase/index/manifest provenance')
        failures=[value['first'],*value['secondary']];ordinal=event['failure_ordinal'];cause=event['cause']
        need(type(ordinal)is int and 0<=ordinal<len(failures)and failures[ordinal]==cause and
             type(cause)is dict and set(cause)=={'kind','phase','command_index','type','reason'}and
             cause['kind']=='source-hard-stop'and cause['phase']==event['phase']and
             cause['command_index']==event['command_index']and
             all(type(cause[k])is str and 0<len(cause[k])<=65536 for k in('type','reason')),
             'hard event must reference its actual distinct caught failure, not ordinary first')
        boundary=event['stop_before'];i=event['command_index']
        if event['phase']in('input-preparation','source-validation'):
            need(i==boundary==0 and event['row_sha256']is None,'preparation precedes all workload commands')
        elif event['phase']=='command-preflight':
            need(boundary==i and event['row_sha256']is None,'preflight precedes its unstarted command')
        elif event['phase']=='command-capture'and boundary==i:
            need(event['row_sha256']is None,'capture exception has no invented returned child')
        else:
            need(boundary==i+1 and rows[i].get('status')!='blocked'and
                 event['row_sha256']==hashlib.sha256(canonical(rows[i])).hexdigest(),
                 'post-capture hard event binds original actual row at exact boundary')
            if event['phase']=='command-capture':need(command_status(rows[i])=='hard-failed',
                'ordinary numeric failure is not a captured hard event')
            event_row=i
    for i,(wanted,row)in enumerate(zip(expected,rows)):
        need(row['template_argv']==wanted,'fixed command order/identity changed')
        deps=[p for p in graph[i]if rows[p]['status']!='passed']
        if row.get('status')=='blocked':
            active=event if event is not None and i>=boundary else None
            need(row==blocked_command(wanted,graph[i],rows,active),
                 'blocked row must bind exact hard-event digest/boundary or actual prerequisite')
        else:
            need(i<boundary and not deps and row.get('status')==command_status(row)and
                 (row['status']!='hard-failed'or i==event_row),
                 'attempted command after hard stop/failed prerequisite or misclassified capture')
    passed=event is None and all(r['status']=='passed'for r in rows)
    need(value['status']==('passed'if passed else'failed')and
         (value['first']is None and value['secondary']==[]and event is None if passed else value['first']is not None),
         'truthful failed/blocked aggregation')
    return value


def verify_result(value, request, spec):
    verify_diagnostics(value,request,spec)
    need(value['first'] is None and value['secondary'] == [] and value['status'] == 'passed',
         'failed or incomplete source job')
    return value


def diagnostic_binding(value, request, spec, manifest_sha):
    """Parent/Root/collector join over original result bytes, not a skip grant."""
    need(type(manifest_sha)is str and SHA.fullmatch(manifest_sha)and
         value.get('controller_manifest_sha256')==manifest_sha,
         'diagnostics belong to exact independently admitted A guest manifest')
    if value.get('kind')=='OMEN_GUEST_SOURCE_WORKLOAD_V1':verify_diagnostics(value,request,spec)
    else:
        need(value.get('kind')=='OMEN_GUEST_SOURCE_PREREQUISITE_FAILED'and
             value.get('identity')==request and value.get('subject')==spec and
             value.get('status')=='failed'and value.get('commands')==[]and value.get('first')is not None,
             'only exact failed bootstrap diagnostic, never invented command outcomes')
    event=value.get('hard_stop')
    return {'kind':'OMEN_SOURCE_DIAGNOSTIC_BINDING_V1','manifest_sha256':manifest_sha,
        'result_sha256':hashlib.sha256(canonical(value)).hexdigest(),
        'hard_stop_sha256':None if event is None else hashlib.sha256(canonical(event)).hexdigest()}

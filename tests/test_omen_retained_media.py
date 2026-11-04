"""Typed producer/queue joins. Kernel mount and hardware are explicitly not modeled as passes."""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import subprocess
import uuid
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'scripts' / 'omen_control'
sys.path.insert(0, str(SOURCE))
import retained_media as media
import source_contract
import media_window
import idle_signal_owner
import media_probe
import normal_probe
import types


def pin(path, mode, uid, gid, size, ino, sha='a' * 64):
    return {'path': path, 'bytes': size, 'sha256': sha,
            'identity': {'st_dev': 7, 'st_ino': ino, 'st_mode': mode,
                         'st_uid': uid, 'st_gid': gid, 'st_nlink': 1,
                         'st_size': size, 'st_mtime_ns': 1, 'st_ctime_ns': 1}}


def operand():
    work = pin('/run/owned-ro/working.raw', 0o100640, 64055, 993,
               media.RAW_BYTES, 12, media.RAW_SHA)
    backing = pin('/owned/backing.raw', 0o100600, 0, 0, 8400000000, 30)
    parent = {'path': '/run/owned-ro', 'identity': pin('/run/owned-ro', 0o40710, 0, 0, 4096, 2)['identity']}
    value = {'kind': media.PROOF, 'nonce': 'c' * 32, 'bootID': 'current-boot',
             'working': work, 'parent': parent, 'backing': backing,
             'mount': {'id': 123, 'parent': 22, 'device': '7:4', 'root': '/',
                       'target': '/run/owned-ro', 'options': ['ro', 'nodev', 'nosuid', 'noexec'],
                       'optional': [], 'type': 'ext4', 'source': '/dev/loop4',
                       'superOptions': ['ro', 'norecovery']},
             'loop': {'path': '/dev/loop4', 'backing': backing['path'], 'offset': 0,
                      'sizeLimit': 0, 'readOnly': True},
             'workingACL': media.MEDIA_ACL, 'parentACL': media.PARENT_ACL,
             'origin': {'kind': 'HISTORICAL_RAW_COPY_ORIGIN_DATA', 'bootID': 'old-boot',
                        'rawBytes': media.RAW_BYTES, 'rawSHA256': media.RAW_SHA,
                        'recordSHA256': 'b' * 64}, 'allOwnedFDsClosed': True}
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    ref = pin('/run/new/custody.json', 0o100400, 0, 0, len(raw), 40,
              hashlib.sha256(raw).hexdigest())
    c = {'nonce': 'c' * 32, 'hostBoot': 'current-boot', 'working': work,
         'installer': {'kind': media.KIND, 'bootCopy': work, 'backing': backing,
                       'currentCustody': value, 'currentCustodyPin': ref}}
    return c, value


class RetainedMediaContract(unittest.TestCase):
    def test_normal_worker_transport_outlives_short_helper_without_resetting_deadline(self):
        """Real owned child transport; child models the normal worker boundary only."""
        import libvirt_native as native
        import install_media_controller as installer
        import time
        executable=str(Path(sys.executable).resolve());ref=installer.pin(executable)
        command=[executable,'-B','-c','import time;time.sleep(11);print("worker-complete")']
        result=native.native_queue_worker(command,time.time()+15,ref)
        self.assertEqual(result['numeric'],0)
        self.assertTrue(result['EOF']and result['reaped']and result['pipesClosed'])
        self.assertEqual(result['groupRemaining'],[])
        self.assertEqual(result['closure'],'KNOWN')
        with self.assertRaises(subprocess.TimeoutExpired)as short:
            native.native_child(command,time.time()+15,ref)
        self.assertTrue(short.exception.nativeChildEvidence['reaped'])
        self.assertTrue(short.exception.nativeChildEvidence['EOF'])
        with self.assertRaises(Exception)as expired:
            native.native_queue_worker(command,time.time()-1,ref)
        self.assertIn('deadline',str(expired.exception))
        bad=copy.deepcopy(ref);bad['sha256']='0'*64
        with self.assertRaises(Exception):native.native_queue_worker(command,time.time()+15,bad)

    @unittest.skipUnless(os.geteuid()==0 and sys.platform=='linux','disposable Linux CI Root only')
    def test_real_geometry_not_optional_sink_is_authority(self):
        """Sparse geometry fixture only, not F9AA content/native-media acceptance."""
        import libvirt_peer as peer
        import libvirt_storage as storage
        with tempfile.TemporaryDirectory(dir='/run',prefix='opemos-geometry-')as directory:
            path=Path(directory)/'working.raw';path.touch(mode=0o600)
            with path.open('r+b')as file:file.truncate(media.RAW_BYTES)
            expected=pin(str(path),0o100600,0,0,media.RAW_BYTES,1,media.RAW_SHA)
            expected['identity']=peer.ident(path.stat())
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            def failed_sink(label,value):raise OSError('optional diagnostic is unwritable')
            try:
                actual=peer.working_metadata(fd,parent,str(path),expected,{},'fixture-geometry')
                value,errors=storage.working_geometry(actual,expected,True,False,failed_sink)
                self.assertEqual(value,expected['identity']);self.assertEqual(len(errors),1)
                with path.open('r+b')as file:file.truncate(4096)
                actual=peer.working_metadata(fd,parent,str(path),expected,{},'fixture-wrong-geometry')
                with self.assertRaises(peer.Refused)as caught:
                    storage.working_geometry(actual,expected,True,False,failed_sink)
                self.assertIn('inode/geometry',str(caught.exception))
                self.assertEqual(len(caught.exception.optionalDiagnosticErrors),1)
            finally:os.close(fd);os.close(parent)

    @unittest.skipUnless(os.geteuid()==0 and sys.platform=='linux','disposable Linux CI Root only')
    def test_actual_bash_ancestor_ofd_fence_without_forwarding_fd(self):
        """Real kernel ancestry/OFD; fixture UID0/path are not normal UID1000 admission."""
        import install_media_controller as installer
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);wrapper=root/'heavy.sh';lock=root/'heavy.lock'
            wrapper.write_text('#!/bin/bash\nset -euo pipefail\nexec 9>"$1"\nflock -n 9\nshift\n"$@"\n')
            wrapper.chmod(0o555);ref=installer.pin(wrapper)
            code=('import sys,json,os;sys.path.insert(0,sys.argv[1]);'
                  'from run_current_media import heavy_custody;'
                  'p=json.loads(sys.argv[2]);v=heavy_custody(p,sys.argv[3],0);'
                  'print(json.dumps(v));'
                  'p["sha256"]="0"*64;'
                  '\ntry:heavy_custody(p,sys.argv[3],0)'
                  '\nexcept Exception:pass'
                  '\nelse:raise AssertionError("wrong source hash passed")')
            command=['/usr/bin/bash',str(wrapper),str(lock),sys.executable,'-B','-c',code,
                     str(SOURCE),json.dumps(ref),str(lock)]
            result=subprocess.run(command,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            value=json.loads(result.stdout)
            self.assertEqual(value['owner']['exe'],'/usr/bin/bash')
            self.assertEqual(value['owner']['argv'][1],str(wrapper))
            self.assertEqual(value['sourcePin'],ref)
            self.assertEqual(value['OFD']['fd'],9)

    def test_real_runner_assignment_survives_missing_optional_telemetry(self):
        """Production routing reader with explicit API data, not a method override."""
        busy = False
        assigned = 0
        def api(endpoint):
            if '/actions/runners?' in endpoint:
                return {'runners':[{'id':21,'name':'opemos-omen-robot',
                                    'labels':[{'name':'opemos-omen-robot'}],
                                    'busy':busy,'status':'online'}]}
            if '/actions/runs?status=in_progress' in endpoint:
                return {'total_count':1,'workflow_runs':[{'id':7,'status':'in_progress',
                         'path':'.github/workflows/omen-robot.yml'}]}
            if '/actions/runs/7/jobs?' in endpoint:
                return {'total_count':assigned,'jobs':[
                    {'id':9,'run_id':7,'status':'in_progress','labels':['opemos-omen-robot'],
                     'runner_id':21}] if assigned else []}
            raise RuntimeError('optional endpoint unavailable')
        client=types.SimpleNamespace(gh_json=api,runner21_assigned_jobs=normal_probe.runner21_assigned_jobs)
        policy={'mainCommit':'a'*40,'queueSourceSHA256':'b'*64}
        value=media_probe.github(policy,client)
        self.assertIsNone(value['protectedMain'])
        self.assertIsNone(value['actionsQueued'])
        self.assertFalse(value['heartbeatCurrent'])
        self.assertEqual(value['actionsInProgress'],0)
        self.assertFalse(value['runnerBusy'])
        assigned=1; busy=True
        value=media_probe.github(policy,client)
        self.assertEqual(value['actionsInProgress'],1)
        self.assertTrue(value['runnerBusy'])

    @unittest.skipUnless(os.geteuid() == 0 and sys.platform == 'linux', 'disposable Linux CI Root only')
    def test_installed_normal_entry_without_connect_syscall(self):
        """Actual installer/isolated entry; external queue helpers and media are MODELED, never executed."""
        import install_media_controller as installer
        import ctypes
        if os.path.lexists(installer.SOURCE_ROOT): self.skipTest('existing source owner preserved')
        token = uuid.uuid4().hex
        queue_root = Path('/var/lib/opemos-queue-r120-' + token)
        drain_root = Path('/var/lib/opemos-media-drain-r120-' + token)
        public_parent=Path('/run/opemos-libvirt-parent-cd9ef0826364409da287f6f3e3830c95.json')
        if os.path.lexists(public_parent): self.skipTest('existing public owner preserved')
        parent_identity=None
        fixture=Path('/run/opemos-connected-fixture-'+token)
        placement=Path('/run/opemos-steamos-placement-cd9ef0826364409da287f6f3e3830c95')
        runtime=Path('/run/opemos-libvirt-runtime-cd9ef0826364409da287f6f3e3830c95')
        for path in (fixture,placement,runtime):
            if os.path.lexists(path):self.skipTest('existing connected fixture owner preserved')
        created=[]
        def member(raw):
            return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                    'base64':__import__('base64').b64encode(raw).decode()}
        names = installer.RUNTIME | installer.PREPARE | {'standalone_peer_access_adapter'}
        sources = {n:member((SOURCE/(n+'.py')).read_bytes()) for n in names}
        queue_sources = {n:member((SOURCE/n).read_bytes() if (SOURCE/n).exists()
                                  else b'# MODELED existing external queue helper; not executed by this test\n')
                         for n in installer.QUEUE_NAMES}
        model = member(b'# MODELED existing normal helper; not executed by this test\n')
        drains = {'media_drain':member((SOURCE/'media_drain.py').read_bytes()),
                  'idle_signal_owner':member((SOURCE/'idle_signal_owner.py').read_bytes()),
                  'media_probe_remote':member((SOURCE/'media_probe_remote.py').read_bytes()),
                  'normal_probe':model,'normal_cycle':model}
        payload = {'kind':'ROOT_REVIEWED_CURRENT_MEDIA_INSTALL_V1','repository':'CorniiDog/OPEMOS.EXE',
                   'protectedMain':'a'*40,'reviewedHead':'b'*40,  # modeled identity DATA, no review fabricated
                   'sources':sources,'queueSources':queue_sources,'queueRoot':str(queue_root),
                   'originCopyData':member(b'{}'), 'drainRoot':str(drain_root),'drainSources':drains,
                   'normalControlPolicy':{'normalProbeSHA256':model['sha256'],'normalCycleSHA256':model['sha256']},
                   'parentTemplate':{'noNIC':True,'noInstall':True,'maxBoots':1},
                   'operationProfile':{'kind':'OPEMOS_INSTALLED_CURRENT_MEDIA_OPERATION_V1'}}
        def deny_connect():
            class Filter(ctypes.Structure):
                _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
            class Program(ctypes.Structure):
                _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
            filters=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,42),
                               Filter(0x06,0,0,0x00050001),Filter(0x06,0,0,0x7fff0000))
            libc=ctypes.CDLL(None,use_errno=True);program=Program(4,filters)
            if libc.prctl(38,1,0,0,0)!=0 or libc.prctl(22,2,ctypes.byref(program),0,0)!=0:os._exit(125)
        try:
            installed = installer.install(payload)
            self.assertEqual(installed['hardwareEffects'], [])
            ref = installed['operationProfilePin']
            result = subprocess.run(['/usr/bin/python3','-I','-B',str(installer.SOURCE_ROOT/'run_current_media.py'),
                                     '--profile-pin-json',json.dumps(ref),'--observe-boot'],
                                    capture_output=True,timeout=15,preexec_fn=deny_connect)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            value=json.loads(result.stdout)
            self.assertEqual(value['kind'],'CURRENT_MEDIA_NATIVE_BOOT_OBSERVATION')
            self.assertEqual(value['bootID'],Path('/proc/sys/kernel/random/boot_id').read_text().strip())
            self.assertEqual(value['effects'],[])
            # Real protected-input adapter reader consumes actual installed
            # sources, including exact byte counts. Native facts are not used
            # by verify_inputs, and are not claimed by this test.
            import standalone_peer_access_adapter as adapter
            roles={n:installed['sourceRoles'][n]for n in installer.RUNTIME}
            nonce=adapter.NONCE;boot=value['bootID']
            observer={k:roles['libvirt_peer'][k]for k in ('path','bytes','sha256')}
            domain={'leaseNonce':nonce,'name':'opemos-libvirt-'+nonce,
                    'uuid':'64f43b0c-9a98-494d-adc1-0782aea1d32e','observer':observer}
            spec={'id':'fixture-fresh-job','platform':'steamos','owner':'root','cwd':'/run',
                  'files':[{k:roles[n][k]for k in ('path','bytes','sha256')}for n in sorted(roles)],
                  'cores':4,'memory':10737418240,'timeout_seconds':900,'depends_on':[],'requires_success':True,
                  'resources':['omen-iommu-group-1'],'libvirt_domain':domain,
                  'approval':'EXACT_PARENT_MINIMAL_PIN',
                  'command':['sudo','-n','/usr/bin/python3','-B',roles['runtime_entry']['path'],
                             '--parent-pin-json','EXACT_PARENT_FULL_PIN_JSON']}
            # Byte-sized media is an explicit content/storage MODEL. This case
            # cannot satisfy the real fixed-F9AA preflight or issue a VM grant.
            # Source files, ACLs, protected metadata, /run FDs, readonly system
            # libvirt connection, adapter process and final queue consumer are real.
            import libvirt_producer as producer
            import libvirt_access as acl
            import libvirt_peer as peer
            import time
            for path in (fixture,placement,runtime):producer.create_root(str(path));created.append(path)
            for name in ('media','run','output'):(fixture/name).mkdir(mode=0o700)
            original=installer.put(fixture/'original.raw',b'fixture original',0o400)
            working=installer.put(fixture/'media/working.raw',b'fixture media',0o600)
            installer.put(fixture/'run/OVMF_VARS_4M.fd',b'fixture vars',0o600)
            installer.put(fixture/'output/serial.raw',b'',0o600)
            c={'nonce':nonce,'hostBoot':boot,'jobId':spec['id'],'guestUUID':domain['uuid'],'name':domain['name'],
               'original':original,'working':working,'run':str(fixture/'run'),'output':str(fixture/'output'),
               'installer':{'kind':'AUTHENTICATED_F9AA_RAW_RECOVERY_USB_FIRSTBOOT','noInstallTarget':True}}
            def save(label,value):return installer.put(fixture/(label+'.json'),installer.canon(value),0o400)
            rows=[];after=[]
            leaves=[(fixture/'media','working-parent'),(fixture/'media/working.raw','working'),
                    (fixture/'run','runtime-parent'),(fixture/'run/OVMF_VARS_4M.fd','vars'),
                    (fixture/'output','output-parent'),(fixture/'output/serial.raw','serial')]
            for path,role in leaves:
                ref=working if role=='working'else acl.metadata_pin(str(path))
                if not role.endswith('parent')and role!='working':ref=installer.pin(path)
                row=acl.plan(str(path),ref,role,verified_content=working if role=='working'else None,
                             readonly_media=role=='working')
                rows.append(row);after.append(acl.apply(row,save,defer_working_hash=True))
            disks={'original':original,'working':installer.pin(fixture/'media/working.raw')}
            stage={'kind':'LIBVIRT_R7_ACCESS_STAGE_PENDING_FULL_HASH','nonce':nonce,'bootID':boot,'candidate':c,
                   'grantPin':save('fixture-stage-data',{'fixtureOnly':True}),'rows':rows,'after':after,
                   'original':original,'workingBefore':working,'pendingFullContentProof':True,'runtimeAuthorized':False}
            stagepin=save('access-stage',stage)
            captures={n:save('capture-'+n,{'explicitNativeMediaModel':True})for n in('original','working')}
            binding={'sourceRoles':roles,'queuePrograms':installed['queuePrograms'],
                     'sourceGraphSHA256':hashlib.sha256(installer.canon(roles)).hexdigest(),
                     'preparedAccessPin':stagepin,'preparedDiskPins':disks,'splitDiskCapturePins':captures}
            storage={'kind':'ROOT_EXACT_STEAMOS_INSTALLER_GAMES_PLACEMENT','nonce':nonce,'boot':boot,
                     'original':original,'working':working,'installer':c['installer'],'preparationBinding':binding}
            storagepin=installer.put(placement/'storage-contract.json',installer.canon(storage),0o400)
            now=time.time()
            pre={'bootID':boot,'kind':'ACTUAL_LIBVIRT_R4_CURRENT_PREFLIGHT','observedUnix':now,
                 'original':original,'working':disks['working'],'preparedAccessPin':stagepin,
                 'splitDiskCapturePins':captures,'queuePrograms':installed['queuePrograms'],
                 'storagePlacement':{'receiptPin':storagepin},'explicitNativeMediaModel':True}
            prepin=save('preflight-data',pre)
            qualification={'kind':'ROOT_VERIFIED_FRESH_STEAMOS_PLACEMENT','qualifiedPlacementPin':storagepin,
                           'nonce':nonce,'bootID':boot,'sourceRoles':roles,'queuePrograms':installed['queuePrograms'],
                           'runtimeAuthorized':False,'RootIssuedRuntimeAuthority':False,
                           'currentPreflightPin':prepin,'currentPreflight':pre}
            qualifiedpin=installer.put(placement/'placement-qualified.json',installer.canon(qualification),0o400)
            parent={'kind':'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT','RootIssued':True,
                    'runtimeAuthorized':True,'MODEL_ONLY':False,'bootID':boot,'nonce':nonce,
                    'contextPath':'/run/opemos-libvirt-runtime-'+nonce+'/context.json',
                    'candidate':c,'issuedUnix':now,'startBeforeUnix':now+299,'wholeDeadlineUnix':now+900,
                    'sourceRoles':roles,'jobId':spec['id'],'normalizedSpecTemplate':spec,
                    'installedSourceContractPin':installed['sourceContractPin'],'queuePrograms':installed['queuePrograms'],
                    'preparedAccessPin':stagepin,'preparedDiskPins':disks,'splitDiskCapturePins':captures,
                    'sourcePlacementPin':storagepin,'placementQualificationPin':qualifiedpin,'prequeuePreflightPin':prepin,
                    'TEST_SCOPE':'Structural/source/ACL/readonly observer only; no real media qualification or grant'}
            parent_ref=installer.put(public_parent,installer.canon(parent),0o444)
            parent_identity=parent_ref['identity']
            actual_spec=adapter.parent_spec(parent,parent_ref)
            request={'leaseNonce':nonce,'domainName':domain['name'],'domainUUID':domain['uuid'],
                     'observer':observer,'jobId':spec['id'],
                     'specSHA256':hashlib.sha256(installer.canon(actual_spec)).hexdigest()}
            jobtoken=uuid.uuid4().hex
            request.update(jobToken=jobtoken,unit='opemos-testq-abcdefabcdef-'+jobtoken+'.service',invocation='a'*32,
                           cpus=[0,1,2,3],controllerMemory=2147483648,domainMemory=8589934592,
                           reservationMemory=10737418240,vmSlice='opemos-vm-pool-libvirt'+jobtoken+'.slice',
                           partition='/opemos/vm/pool/libvirt'+jobtoken,gpuGroup='omen-iommu-group-1')
            with adapter.RootInputs()as inputs:
                accepted=adapter.verify_inputs(request,inputs,boot,include_context=False)
                self.assertEqual(accepted['implementationAccessPin'],roles['libvirt_access'])
                self.assertFalse(accepted['originalInputOnly'])
                with adapter.load_pair(accepted)as(current_peer,current_access):
                    import postqueue_issuer as issuer
                    current_peer.SOURCE_PLACEMENT_PIN=None
                    issuer.bind_placement(current_peer,parent,parent_ref)
                    entry=types.ModuleType('actual_installed_entry');entry.__file__=roles['runtime_entry']['path']
                    exec(compile(Path(entry.__file__).read_bytes(),entry.__file__,'exec'),entry.__dict__)
                    self.assertEqual(entry.validate_context_sources({'sourceRoles':roles}),roles)
                    entry.bind_placement(current_peer,parent,parent_ref)
                    issuer.submission_manifest(parent,parent_ref,'/run')
                    for fault in ('missing','foreign','original-current'):
                        bad=copy.deepcopy(parent)
                        if fault=='missing':bad['sourceRoles'].pop('libvirt_storage')
                        elif fault=='foreign':bad['sourceRoles']['foreign']=bad['sourceRoles']['libvirt_storage']
                        else:bad['sourceRoles']['libvirt_peer']['sha256']=adapter.ORIGINAL_PEER_SHA
                        with self.assertRaises(Exception):issuer.bind_placement(current_peer,bad,parent_ref)
                queue_spec=importlib.util.spec_from_file_location('actual_connected_queue',SOURCE/'test_queue.py')
                queue=importlib.util.module_from_spec(queue_spec);sys.modules[queue_spec.name]=queue
                try:
                    queue_spec.loader.exec_module(queue)
                    captures=[]
                    actual=queue.observe_queue_libvirt(request,captures=captures)
                    self.assertEqual(actual['phase'],'NOT_PREPARED')
                    self.assertTrue(captures)
                    self.assertTrue(captures[-1]['proof']['allOwnedDescriptorsClosed'])
                finally:sys.modules.pop(queue_spec.name,None)
                for wrong in (dict(request,specSHA256='0'*64),dict(request,jobId='foreign-job'),
                              dict(request,observer=dict(observer,sha256=adapter.ORIGINAL_PEER_SHA))):
                    with self.assertRaises(RuntimeError):adapter.verify_inputs(wrong,inputs,boot,include_context=False)
        finally:
            if parent_identity is not None:
                self.assertEqual(media.identity(os.lstat(public_parent)),parent_identity)
                public_parent.unlink()
            for path in (installer.SOURCE_ROOT,queue_root,drain_root,*reversed(created)):
                if path.exists(): shutil.rmtree(path)

    def test_idle_offline_transition_requires_fresh_post_drain_cut(self):
        """Actual producer predicate and consumer; API/peer facts are explicit modeled inputs."""
        import time
        online = {'runnerOnline':True, 'runnerBusy':False, 'actionsInProgress':0}
        offline = dict(online, runnerOnline=False)
        calls = []
        final = dict(offline, networkReachable=True, sourceOwnerBusy=False, queueKnown=True,
                     otherActiveJobs=[], unknownReservations=[], guestActive=False,
                     gpuLeaseActive=False, hostGraphics='INTEL_HOST_NVIDIA_GUEST_ONLY',
                     workerLockFree=True, control={'state':'passed', 'terminalLifecycle':'CLOSED',
                                                   'reservationRetained':False})
        def modeled_external_observation(inputs):
            calls.append(inputs)
            if len(calls) == 1: media_probe.require_stable_assignment(online, offline)
            media_probe.require_stable_assignment(offline, offline)
            return final
        probe = types.SimpleNamespace(observe=modeled_external_observation,
                                      RunnerStatusTransition=media_probe.RunnerStatusTransition)
        cuts = []
        result = media_window.observe_after_drain(probe, {'modeledAPI':True}, time.monotonic()+3, cuts)
        self.assertIs(result, final)
        self.assertEqual(len(calls),2)
        self.assertEqual(cuts,[{'runnerStatusTransition':{'before':online,'after':offline}}])
        media_window.admitted_media(result)
        with self.assertRaises(media_probe.RunnerStatusTransition):
            media_probe.require_stable_assignment(online, offline)  # no pre-drain retry/acceptance
        with self.assertRaisesRegex(RuntimeError,'bounded runner status'):
            media_window.observe_after_drain(types.SimpleNamespace(
                observe=lambda inputs:media_probe.require_stable_assignment(online,offline),
                RunnerStatusTransition=media_probe.RunnerStatusTransition), {}, time.monotonic()-1, [])

    def test_assigned_busy_and_unknown_probe_failures_remain_final(self):
        import time
        idle={'runnerOnline':True,'runnerBusy':False,'actionsInProgress':0}
        for after in (dict(idle,runnerBusy=True),dict(idle,actionsInProgress=1),
                      dict(idle,runnerOnline=False,actionsInProgress=1)):
            calls=[]
            def external(inputs):
                calls.append(inputs);media_probe.require_stable_assignment(idle,after)
            probe=types.SimpleNamespace(observe=external,RunnerStatusTransition=media_probe.RunnerStatusTransition)
            with self.assertRaises(RuntimeError) as caught:
                media_window.observe_after_drain(probe,{},time.monotonic()+3,[])
            self.assertNotIsInstance(caught.exception,media_probe.RunnerStatusTransition)
            self.assertEqual(len(calls),1)
        def unknown(inputs):raise RuntimeError('actual source drift')
        with self.assertRaisesRegex(RuntimeError,'actual source drift'):
            media_window.observe_after_drain(types.SimpleNamespace(
                observe=unknown,RunnerStatusTransition=media_probe.RunnerStatusTransition),{},time.monotonic()+3,[])

    def test_repository_queue_and_heartbeat_are_not_media_permission(self):
        for queued in (None, 0, 100):
            value = {'networkReachable':True,'runnerBusy':False,'actionsInProgress':0,
                     'actionsQueued':queued,'heartbeatCurrent':False,'sourceOwnerBusy':False,
                     'queueKnown':True,'otherActiveJobs':[],'unknownReservations':[],
                     'guestActive':False,'gpuLeaseActive':False,
                     'hostGraphics':'INTEL_HOST_NVIDIA_GUEST_ONLY','workerLockFree':True,
                     'runnerOnline':False,'control':{'state':'absent'}}
            media_window.admitted_media(value)
            bad = dict(value, actionsInProgress=1)
            with self.assertRaises(RuntimeError): media_window.admitted_media(bad)
            bad = dict(value, sourceOwnerBusy=True)
            with self.assertRaises(RuntimeError): media_window.admitted_media(bad)

    def test_pidfd_selection_keeps_actual_worker_and_owner_guards(self):
        expected = {'job':'control-one','unit':'fixture.service','invocation':'a'*32,
                    'boot':'actual-boot','listenerPID':11,'listenerStart':101,
                    'loggerPID':10,'loggerStart':100}
        group = '/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/fixture.service'
        row = {'id':'control-one','unit':'fixture.service','state':'running'}
        probe = {'control':{'jobId':'control-one'},'runnerBusy':False,
                 'actionsInProgress':0,'actionsQueued':200,'guestActive':False}
        manager = {'ActiveState':'active','InvocationID':'a'*32,'MainPID':'10','ControlGroup':group}
        live = [{'pid':10,'start':100,'uids':[1000]*4,'cgroup':'0::'+group,'argv':[b'logger']},
                {'pid':11,'start':101,'uids':[1000]*4,'cgroup':'0::'+group,
                 'argv':[idle_signal_owner.LISTENER,b'run',b'--startuptype',b'service']}]
        self.assertEqual(idle_signal_owner.selected(row,probe,expected,manager,live,'actual-boot')['pid'],11)
        foreign = copy.deepcopy(live); foreign[1]['start'] += 1
        with self.assertRaises(RuntimeError): idle_signal_owner.selected(row,probe,expected,manager,foreign,'actual-boot')
        foreign = live + [{'pid':12,'start':102,'uids':[1000]*4,'cgroup':'0::'+group,'argv':[b'Runner.Worker']}]
        with self.assertRaises(RuntimeError): idle_signal_owner.selected(row,probe,expected,manager,foreign,'actual-boot')

    def test_historical_origin_is_data_current_custody_is_current(self):
        c, v = operand()
        self.assertIs(media.validate_record(c, v), v)
        self.assertNotEqual(v['origin']['bootID'], v['bootID'])

    def test_wrong_current_scope_or_boot_refused(self):
        for key in ('nonce', 'bootID'):
            c, v = operand(); v[key] = 'wrong'
            with self.subTest(key=key), self.assertRaises(ValueError):
                media.validate_record(c, v)

    def test_raw_hash_owner_and_geometry_are_not_relabeled(self):
        for key, value in [('st_uid', 0), ('st_gid', 0), ('st_ino', 99), ('st_size', 1)]:
            c, v = operand(); v['working'] = copy.deepcopy(v['working'])
            v['working']['identity'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                media.validate_record(c, v)
        c, v = operand(); v['working'] = copy.deepcopy(v['working']); v['working']['sha256'] = '0' * 64
        with self.assertRaises(ValueError): media.validate_record(c, v)

    def test_writable_or_replaying_mount_and_loop_refused(self):
        for field in ('rw-mount', 'loop-rw', 'journal', 'alias'):
            c, v = operand()
            if field == 'rw-mount': v['mount']['options'].append('rw')
            if field == 'loop-rw': v['loop']['readOnly'] = False
            if field == 'journal': v['mount']['superOptions'] = ['ro']
            if field == 'alias': v['loop']['backing'] = '/foreign.raw'
            with self.subTest(field=field), self.assertRaises(ValueError): media.validate_record(c, v)

    def test_schema_acl_or_unknown_closure_refused(self):
        for field in ('extra', 'ACL', 'closure'):
            c, v = operand()
            if field == 'extra': v['approval'] = True
            if field == 'ACL': v['workingACL'] += 'other::rwx\n'
            if field == 'closure': v['allOwnedFDsClosed'] = False
            with self.subTest(field=field), self.assertRaises(ValueError): media.validate_record(c, v)

    def test_both_normal_queue_stage_roles_preserve_exact_baseline(self):
        c, v = operand()
        calls = []
        def fullpin(ref, mode, cap):
            calls.append((ref, mode, cap))
            self.assertEqual(ref, c['installer']['currentCustodyPin'])
        for role in ('working', 'working-parent'):
            ref = v['working'] if role == 'working' else v['parent']
            acl = v['workingACL'] if role == 'working' else v['parentACL']
            row = {'path': ref['path'], 'role': role, 'before': ref, 'priorACL': acl,
                   'targetACL': acl, 'uid': 64055,
                   'rights': 'r--' if role == 'working' else '--x',
                   'immutableMediaCustodyPin': c['installer']['currentCustodyPin']}
            after = {'path': ref['path'], 'identity': ref['identity'], 'ACL': acl}
            self.assertTrue(media.validate_stage_row(c, row, after, fullpin))
            changed = copy.deepcopy(after); changed['identity']['st_ctime_ns'] += 1
            with self.assertRaises(ValueError): media.validate_stage_row(c, row, changed, fullpin)
        self.assertEqual(len(calls), 4)

    def test_legacy_or_new_writable_roles_cannot_claim_immutable_exception(self):
        self.assertFalse(media.is_adopted({'installer': None}))
        self.assertFalse(media.is_adopted({}))
        c, v = operand()
        self.assertFalse(media.validate_stage_row(c, {'role': 'vars'}, {}, None))

    def test_normal_queue_calls_the_same_typed_consumer(self):
        # Import the actual queue module, not a duplicate validator or source assertion.
        spec = importlib.util.spec_from_file_location('retained_test_actual_queue', SOURCE / 'test_queue.py')
        queue = importlib.util.module_from_spec(spec); sys.modules[spec.name] = queue
        try:
            spec.loader.exec_module(queue)
            # The original D24 source schema remains twelve-role DATA. A real
            # wrong-scope refusal must not become a NameError from current-only
            # variables accidentally inserted in this legacy consumer.
            legacy=set(source_contract.RUNTIME_ROLES)-{'libvirt_storage','retained_media','source_contract'}
            roles={n:pin('/run/legacy/'+n+'.py',0o100444,0,0,1,500+i)for i,n in enumerate(sorted(legacy))}
            roles['libvirt_peer']=pin('/run/legacy/libvirt_peer.py',0o100444,0,0,queue.D24_PEER_BYTES,600,queue.D24_PEER_SHA)
            roles['libvirt_access']=pin('/run/legacy/libvirt_access.py',0o100444,0,0,15340,601,queue.D24_ACCESS_SHA)
            observer={k:roles['libvirt_peer'][k]for k in ('path','bytes','sha256')}
            envelope={'kind':'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION','effects':[],
                      'upstreamObserver':roles['libvirt_peer'],'proof':{},
                      'implementation':{'contract':queue.D24_ADAPTER_CONTRACT,'peer':roles['libvirt_peer'],
                        'access':roles['libvirt_access'],'sourceRoles':roles,'parent':None,'context':None,
                        'assignment':None,'grant':None,'placementBinding':None}}
            with self.assertRaisesRegex(ValueError,'only fresh D23 scope'):
                queue.validate_d24_peer_envelope(envelope,{'observer':observer,'leaseNonce':'c'*32},roles['libvirt_peer'])
            c, v = operand()
            self.assertEqual(queue.R109_PEER_SHA,
                             hashlib.sha256((SOURCE / 'libvirt_peer.py').read_bytes()).hexdigest())
            self.assertEqual(queue.R109_ACCESS_SHA,
                             hashlib.sha256((SOURCE / 'libvirt_access.py').read_bytes()).hexdigest())
            self.assertEqual(queue.R109_CURRENT_ADAPTER,
                             (SOURCE / 'standalone_peer_access_adapter.py').read_text())
        finally: sys.modules.pop(spec.name, None)

    @unittest.skipIf(os.geteuid() == 0, 'normal queue CLI runs as the unprivileged queue owner')
    def test_normal_exact_job_status_preserves_complete_row(self):
        spec = importlib.util.spec_from_file_location('retained_status_actual_queue', SOURCE / 'test_queue.py')
        queue = importlib.util.module_from_spec(spec); sys.modules[spec.name] = queue
        spec.loader.exec_module(queue)
        try:
            with tempfile.TemporaryDirectory(prefix='opemos-job-status-') as directory:
                state = Path(directory) / 'state'
                with contextlib.redirect_stdout(io.StringIO()): queue.main(['--queue', str(state), 'init'])
                root, db = queue.connect(state)
                value = {'terminalLifecycle': {'phase': 'CLOSED', 'reservationRetained': False},
                         'first': {'reason': 'actual test failure retained'}, 'unknown': None}
                row = {'id': 'fixture-one', 'spec': '{"platform":"steamos"}', 'state': 'failed',
                       'cpus': '[0,1,2,3]', 'unit': 'fixture.service', 'started': 10.0,
                       'finished': 11.0, 'result': json.dumps(value)}
                db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)', tuple(row.values()))
                db.commit(); db.close()
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(queue.main(['--queue', str(state), 'status', '--job-id', row['id']]), 0)
                got = json.loads(output.getvalue())
                self.assertEqual(got, {'kind': 'NORMAL_QUEUE_EXACT_JOB_STATUS_V1', 'job': row, 'binding': None})
        finally: sys.modules.pop(spec.name, None)

    @unittest.skipUnless(os.geteuid() == 0, 'real protected-parent transport requires disposable CI Root')
    def test_complete_actual_queue_phase_consumer_with_protected_parent(self):
        """Real Root metadata transport and entire stage consumer; native/media facts are MODELED.

        No VM, mount or disk bytes are simulated as successful hardware. The
        separate Root observer must supply those actual facts before execution.
        """
        spec = importlib.util.spec_from_file_location('retained_phase_actual_queue', SOURCE / 'test_queue.py')
        queue = importlib.util.module_from_spec(spec); sys.modules[spec.name] = queue
        spec.loader.exec_module(queue)
        root = Path(tempfile.mkdtemp(prefix='opemos-retained-ci-', dir='/run'))
        parent_path = Path('/run/opemos-libvirt-parent-' + 'c' * 32 + '.json')
        if os.path.lexists(parent_path):
            root.rmdir(); sys.modules.pop(spec.name, None)
            self.skipTest('existing owner of exact fixture parent is preserved')
        parent_identity = None
        before_fd = set(os.listdir('/proc/self/fd'))
        def canonical(v): return json.dumps(v, sort_keys=True, separators=(',', ':')).encode()
        def put(path, v, mode):
            raw = canonical(v)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            try:
                os.fchmod(fd, mode); os.write(fd, raw); os.fsync(fd)
                ident = media.identity(os.fstat(fd))
            finally: os.close(fd)
            return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'identity': ident}
        try:
            c, value = operand()
            c.update(jobId='retained-fixture-job', guestUUID='64f43b0c-9a98-494d-adc1-0782aea1d32e',
                     name='opemos-libvirt-' + c['nonce'], run=str(root / 'run'), output=str(root / 'output'),
                     original=pin('/MODELED/golden.raw', 0o100400, 0, 0, 21474836480, 66))
            c['installer']['noInstallTarget'] = True
            c['installer']['currentCustodyPin'] = put(root / 'custody.json', value, 0o400)
            roles = {name: pin('/MODELED/source/' + name + '.py', 0o100444, 0, 0, 1, 100 + n)
                     for n, name in enumerate(sorted(source_contract.RUNTIME_ROLES))}
            observer = {k: roles['libvirt_peer'][k] for k in ('path', 'bytes', 'sha256')}
            domain = {'uuid': c['guestUUID'], 'name': c['name'], 'leaseNonce': c['nonce'], 'observer': observer}
            template = {'id': c['jobId'], 'approval': 'EXACT_PARENT_MINIMAL_PIN',
                        'command': ['entry', 'EXACT_PARENT_FULL_PIN_JSON'], 'libvirt_domain': domain}
            rows, after = [], []
            for role in ('working-parent', 'working', 'runtime-parent', 'vars', 'output-parent', 'serial'):
                directory = role.endswith('parent')
                if role in ('working', 'working-parent'):
                    ref = value['working'] if role == 'working' else value['parent']
                    acl = value['workingACL'] if role == 'working' else value['parentACL']
                    row = {'path': ref['path'], 'role': role, 'before': ref, 'priorACL': acl, 'targetACL': acl,
                           'uid': 64055, 'rights': 'r--' if role == 'working' else '--x',
                           'immutableMediaCustodyPin': c['installer']['currentCustodyPin']}
                    a = {'path': ref['path'], 'identity': ref['identity'], 'ACL': acl}
                else:
                    path = c['run'] if role == 'runtime-parent' else c['output'] if role == 'output-parent' else c['run'] + '/OVMF_VARS_4M.fd' if role == 'vars' else c['output'] + '/serial.raw'
                    rights = 'rwx' if directory else 'rw-'; base = 'rwx' if directory else 'rw-'
                    prior = 'user::' + base + '\ngroup::---\nother::---\n'
                    target = 'user::' + base + '\nuser:64055:' + rights + '\ngroup::---\nmask::' + rights + '\nother::---\n'
                    ref = pin(path, 0o40700 if directory else 0o100600, 0, 0, 4096 if directory else 1, 200 + len(rows))
                    if directory: ref = {k: ref[k] for k in ('path', 'identity')}
                    row = {'path': path, 'role': role, 'before': ref, 'priorACL': prior, 'targetACL': target, 'uid': 64055, 'rights': rights}
                    i = dict(ref['identity'], st_mode=0o40770 if directory else 0o100660)
                    a = {'path': path, 'identity': i, 'ACL': target}
                    if not directory: a.update(bytes=ref['bytes'], sha256=ref['sha256'])
                rows.append(row); after.append(a)
            disks = {'original': c['original'], 'working': c['working']}
            stage = {'kind': 'LIBVIRT_R7_ACCESS_STAGE_PENDING_FULL_HASH', 'nonce': c['nonce'],
                     'bootID': c['hostBoot'], 'candidate': c, 'grantPin': put(root / 'grant.json', {}, 0o400),
                     'rows': rows, 'after': after, 'original': c['original'], 'workingBefore': c['working'],
                     'pendingFullContentProof': True, 'runtimeAuthorized': False}
            stage_pin = put(root / 'stage.json', stage, 0o400)
            placement = put(root / 'placement.json', {}, 0o400); qualification = put(root / 'qualification.json', {}, 0o400)
            parent = {'kind': 'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT', 'RootIssued': True, 'runtimeAuthorized': True,
                      'MODEL_ONLY': False, 'jobId': c['jobId'], 'nonce': c['nonce'], 'bootID': c['hostBoot'],
                      'candidate': c, 'sourceRoles': roles, 'normalizedSpecTemplate': template,
                      'preparedAccessPin': stage_pin, 'preparedDiskPins': disks,
                      'sourcePlacementPin': placement, 'placementQualificationPin': qualification}
            parent_pin = put(parent_path, parent, 0o444); parent_identity = parent_pin['identity']
            normalized = copy.deepcopy(template); normalized['approval'] = {k: parent_pin[k] for k in ('path', 'bytes', 'sha256')}
            normalized['command'][-1] = canonical(parent_pin).decode()
            request = {'jobId': c['jobId'], 'jobToken': 'd' * 32, 'leaseNonce': c['nonce'],
                       'domainUUID': c['guestUUID'], 'domainName': c['name'], 'observer': observer,
                       'specSHA256': hashlib.sha256(canonical(normalized)).hexdigest()}
            proof = {'phase': 'NOT_PREPARED', 'bootID': c['hostBoot'], 'intentPin': None, 'scope': None,
                     'leader': None, 'lease': None}
            custody = {'kind': 'ROOT_PHASE_PREPARED_ACCESS_CUSTODY_R1', 'phase': proof['phase'],
                       'nonce': c['nonce'], 'bootID': c['hostBoot'], 'requestSHA256': hashlib.sha256(canonical(request)).hexdigest(),
                       'parentPin': parent_pin, 'preparedAccessPin': stage_pin, 'preparedDiskPins': disks,
                       'sourceGraphSHA256': hashlib.sha256(canonical(roles)).hexdigest(),
                       'placementPin': placement, 'qualificationPin': qualification, 'stage': stage,
                       'stageRawBase64': __import__('base64').b64encode(canonical(stage)).decode(),
                       'data': {'phase': proof['phase'], 'stage': stage, 'mutable': [], 'phasePins': None}}
            queue.validate_installer_access_custody(custody, proof, request)
            for mutation in ('stage-raw', 'current-hash', 'media-owner'):
                bad = copy.deepcopy(custody)
                if mutation == 'stage-raw': bad['stageRawBase64'] = 'e30='
                if mutation == 'current-hash': bad['stage']['candidate']['installer']['currentCustodyPin']['sha256'] = '0' * 64
                if mutation == 'media-owner': bad['stage']['rows'][1]['before']['identity']['st_uid'] = 0
                with self.subTest(mutation=mutation), self.assertRaises((ValueError, RuntimeError)):
                    queue.validate_installer_access_custody(bad, proof, request)
        finally:
            if parent_identity is not None:
                self.assertEqual(media.identity(os.lstat(parent_path)), parent_identity)
                parent_path.unlink()
            shutil.rmtree(root)
            sys.modules.pop(spec.name, None)
            self.assertEqual(set(os.listdir('/proc/self/fd')), before_fd)


if __name__ == '__main__': unittest.main()

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import json
import subprocess
import os
import time
import threading
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import ubuntu_vm_runner as runner


def fixture_spawn_receipt(child, kind):
    # Read before any wait/poll/cancel: an unreaped child cannot be PID-reused.
    root = Path('/proc') / str(child.pid)
    fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    row = {'pid': child.pid, 'startTicks': int(fields[19]), 'ppid': int(fields[1]),
           'uid': root.stat().st_uid, 'kind': kind}
    if row['ppid'] != os.getpid() or row['uid'] != os.getuid():
        raise AssertionError('fixture child ownership changed')
    line = 'OPEMOS_FIXTURE_SPAWN ' + json.dumps(row, separators=(',', ':'))
    if len(line.encode()) > 4096:
        raise AssertionError('fixture receipt exceeds bound')
    print(line, flush=True)
    return row


def fixture_reap_receipt(child, row):
    if child.returncode is None:
        raise AssertionError('fixture child not reaped')
    try:
        fields = (Path('/proc') / str(child.pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    except FileNotFoundError:
        pass
    else:
        if int(fields[19]) == row['startTicks']:
            raise AssertionError('original fixture identity survives reap')
    print('OPEMOS_FIXTURE_REAP ' + json.dumps(
        {**row, 'exit': child.returncode, 'originalIdentityAbsent': True},
        separators=(',', ':')), flush=True)


class RunnerTest(unittest.TestCase):
    def test_virtual_usb_keyboard_chords_release_before_next_and_keep_original_deadline(self):
        """Production text sender; QMP/guest timing modeled, not a GUI pass."""
        spec=importlib.util.spec_from_file_location('normal_timed_keyboard',
            Path(__file__).resolve().parents[1]/'scripts/omen_control/connection_control.py')
        sender=importlib.util.module_from_spec(spec);spec.loader.exec_module(sender)
        clock=[0.0];release=[0.0];calls=[];timeouts=[]
        def call(command,args):
            self.assertEqual(command,'send-key')
            self.assertGreaterEqual(clock[0],release[0])
            self.assertEqual(args['hold-time'],100)
            release[0]=clock[0]+args['hold-time']/1000
            calls.append(args['keys'])
            return {}
        pipeline=object.__new__(sender.Pipeline)
        pipeline.binding={};pipeline.end=30;pipeline.actions=[]
        pipeline.q=SimpleNamespace(call=call,s=SimpleNamespace(settimeout=timeouts.append))
        def sleep(seconds):clock[0]+=seconds
        value='/media/opemosgui/STEAMOS_RAW/STEAMOS/steamdeck-repair-latest.img'
        with patch.object(sender,'process'),patch.object(sender.time,'monotonic',side_effect=lambda:clock[0]),\
             patch.object(sender.time,'sleep',side_effect=sleep):
            pipeline.text(value)
            self.assertEqual(calls[0],[{'type':'qcode','data':'ctrl'},{'type':'qcode','data':'a'}])
            typed=''
            for keys in calls[1:]:
                codes=[key['data']for key in keys];shift=codes[:-1]==['shift'];code=codes[-1]
                typed+=('_'if shift and code=='minus'else {'slash':'/','minus':'-','dot':'.','spc':' '}.get(
                    code,code.upper()if shift else code))
            self.assertEqual(typed,value)
            self.assertEqual(pipeline.end,30)
            self.assertTrue(all(row['actualQMPInput'][0]['response']=={}for row in pipeline.actions))
            self.assertTrue(all(0<timeout<=10 for timeout in timeouts))
            # An expired/insufficient interval cannot send the next chord.
            count=len(calls);pipeline.end=clock[0]+.1
            with self.assertRaisesRegex(RuntimeError,'deadline before chord'):pipeline.key('a')
            self.assertEqual(len(calls),count)
            # A delayed reply consumes the same deadline, never resets it.
            pipeline.end=clock[0]+1
            def late(command,args):clock[0]+=2;return {}
            pipeline.q.call=late
            with self.assertRaisesRegex(RuntimeError,'deadline after chord'):pipeline.key('a')

    def test_virtual_usb_robot_owned_sender_retains_actual_child_raw_and_nonzero(self):
        import hashlib
        spec=importlib.util.spec_from_file_location('actual_normal_ci10_sender',
            Path(__file__).resolve().parents[1]/'scripts/omen_control/connection_control.py')
        sender=importlib.util.module_from_spec(spec);spec.loader.exec_module(sender)
        baseline=set(os.listdir('/proc/self/fd'))
        with tempfile.TemporaryDirectory(prefix='normal-ci10-owned-child-')as directory:
            root=Path(directory);root.chmod(0o700)
            for numeric in(0,7):
                lane=root/str(numeric);lane.mkdir(mode=0o700)
                paths={name:(str(lane/name),65536)for name in sender.CI10_OUTPUTS}
                records=sender.ci10_reserve_paths(paths,lane)
                try:
                    life,out,err=sender.ci10_run_child([sys.executable,'-I','-c',
                        'import sys;print("actual-owned-sender");print("actual-stderr",file=sys.stderr);sys.exit('+str(numeric)+')'],
                        records,seconds=10)
                    self.assertEqual(life['numeric_exit'],numeric)
                    for key in('waited','stdout_EOF','stderr_EOF','pipes_closed','original_gone'):
                        self.assertIs(life[key],True,key)
                    self.assertEqual(out,b'actual-owned-sender\n');self.assertEqual(err,b'actual-stderr\n')
                    self.assertTrue(all(life['raw_complete'].values()))
                    self.assertFalse(life['deadline_expired']);self.assertEqual(life['secondary_errors'],[])
                    if numeric:self.assertEqual(life['first_failure']['type'],'ChildNonzero')
                    else:self.assertIsNone(life['first_failure'])
                    for label,raw in(('stdout',out),('stderr',err)):
                        proof=life['raw'][label];self.assertEqual(proof['sha256'],hashlib.sha256(raw).hexdigest())
                        self.assertEqual(Path(proof['path']).read_bytes(),raw)
                        self.assertEqual(proof['identity'],sender.ci10_sig(Path(proof['path']).stat()))
                finally:self.assertEqual(sender.ci10_close_outputs(records),[])
        self.assertEqual(set(os.listdir('/proc/self/fd')),baseline)

    def test_virtual_usb_native_observer_uses_exact_producer_elf_bound(self):
        import hashlib
        spec=importlib.util.spec_from_file_location('actual_native_descriptor_observer',
            Path(__file__).resolve().parents[1]/'scripts/omen_control/observer_guest.py')
        observer=importlib.util.module_from_spec(spec);spec.loader.exec_module(observer)
        raw=Path('/proc/self/exe').read_bytes();expected={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        # The production diagnostic allowance stays unchanged. The normal
        # pipeline uses its separately authenticated exact producer ELF role.
        with patch.object(observer,'CAP',1):
            with self.assertRaisesRegex(RuntimeError,'native executable size'):observer.proc_identity(os.getpid())
            actual=observer.proc_identity(os.getpid(),expected)
            self.assertEqual(actual['exe_sha256'],expected['sha256'])
            for bad in(dict(expected,sha256='0'*64),dict(expected,bytes=len(raw)+1),
                       dict(expected,bytes=1073741825)):
                with self.subTest(bad=bad),self.assertRaises(RuntimeError):observer.proc_identity(os.getpid(),bad)

    def test_virtual_usb_robot_requires_independent_action_specific_native_transition(self):
        spec=importlib.util.spec_from_file_location('normal_native_pointer',
            Path(__file__).resolve().parents[1]/'scripts/omen_control/connection_control.py')
        sender=importlib.util.module_from_spec(spec);spec.loader.exec_module(sender)
        bridge=sender.RobotPipeline.__new__(sender.RobotPipeline)
        current={'kind':'NATIVE_OBSERVATION','value':{'windows':[],
            'namesByWindow':[{'window_id':42,'names':['Build NVIDIA Image']}]}}
        bridge.p=SimpleNamespace(end=time.monotonic()+30,app={'pid':73,'window_id':42},
            cfg={'labels':{},'input_path':'/readonly/exact-input.img'},request=lambda kind:current)
        # Successful input delivery is insufficient: no chooser appeared.
        with patch.object(sender.time,'monotonic',side_effect=[0,26]):
            with self.assertRaisesRegex(RuntimeError,'action-specific native transition absent'):
                bridge.after_state('chooser-open',{})
        current['value']['windows']=[{'pid':73,'window_id':43,'transient_for':42,'dialog_type':True}]
        self.assertIs(bridge.after_state('chooser-open',{}),current)
        # A surviving chooser cannot be relabelled as input selection.
        with patch.object(sender.time,'monotonic',side_effect=[0,26]):
            with self.assertRaisesRegex(RuntimeError,'action-specific native transition absent'):
                bridge.after_state('chooser-confirm-exact-input',{})
        current['value']['windows']=[]
        current['value']['namesByWindow'][0]['names']=['exact-input.img']
        with patch.object(sender.time,'monotonic',side_effect=[0,26]):
            with self.assertRaisesRegex(RuntimeError,'action-specific native transition absent'):
                bridge.after_state('chooser-confirm-exact-input',{})
        current['value']['namesByWindow'][0]['names']=['/wrong/exact-input.img']
        with patch.object(sender.time,'monotonic',side_effect=[0,26]):
            with self.assertRaisesRegex(RuntimeError,'action-specific native transition absent'):
                bridge.after_state('chooser-confirm-exact-input',{})
        current['value']['namesByWindow'][0]['names']=['/readonly/exact-input.img']
        self.assertIs(bridge.after_state('chooser-confirm-exact-input',{}),current)

    def test_virtual_usb_candidate_medium_preserves_actual_package_companion_and_refuses_escape(self):
        import hashlib,io,stat,zipfile
        spec=importlib.util.spec_from_file_location('normal_ubuntu_candidate_medium',
            Path(__file__).resolve().parents[1]/'scripts/omen_control/prepare_observer_iso.py')
        medium=importlib.util.module_from_spec(spec);spec.loader.exec_module(medium)
        package=b'actual package DATA, never executed';native=b'actual inner native DATA, never executed'
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        with tempfile.TemporaryDirectory(prefix='opemos-candidate-medium-') as directory:
            root=Path(directory);root.chmod(0o700)
            def archive(name,fault=None,separate=False):
                stream=io.BytesIO()
                with zipfile.ZipFile(stream,'w')as out:
                    member=zipfile.ZipInfo('package/candidate.AppImage');member.external_attr=(stat.S_IFREG|0o755)<<16
                    out.writestr(member,package)
                    if separate:out.writestr('package/native-app',native)
                    out.writestr('package/candidate.AppImage.runtime/appliance/appliance-manifest.json',b'{}')
                    if fault=='escape':out.writestr('../escaped',b'bad')
                    if fault=='link':
                        link=zipfile.ZipInfo('linked');link.external_attr=(stat.S_IFLNK|0o777)<<16;out.writestr(link,'/foreign')
                path=root/name;path.write_bytes(stream.getvalue());path.chmod(0o400);s=path.stat()
                return {'path':str(path),'bytes':s.st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                        'identity':{k:getattr(s,k)for k in fields}}
            ref=archive('producer.zip')
            descriptor={'platform':'ubuntu','repository':'CorniiDog/OPEMOS.EXE','source_commit':'a'*40,
                'artifact_archive_sha256':ref['sha256'],'executable_name':'candidate.AppImage',
                'package_name':'candidate.AppImage','executable_bytes':len(package),
                'package_sha256':hashlib.sha256(package).hexdigest(),'executable_sha256':hashlib.sha256(package).hexdigest()}
            newref=archive('native-producer.zip',separate=True)
            newdesc=dict(descriptor,artifact_archive_sha256=newref['sha256'],package_bytes=len(package),
                         executable_name='native-app',executable_bytes=len(native),
                         executable_sha256=hashlib.sha256(native).hexdigest())
            separated=medium.extract_candidate(newref,newdesc,root/'native-extracted',1048576)
            self.assertNotEqual(separated['package']['sha256'],separated['executable']['sha256'])
            self.assertEqual(separated['package']['name'],'package/candidate.AppImage')
            result=medium.extract_candidate(ref,descriptor,root/'extracted',1048576)
            self.assertEqual(result['executable']['sha256'],descriptor['package_sha256'])
            self.assertEqual((root/'extracted/package/candidate.AppImage').read_bytes(),package)
            self.assertEqual(stat.S_IMODE((root/'extracted/package/candidate.AppImage').stat().st_mode),0o500)
            for fault in ('escape','link'):
                badref=archive(fault+'.zip',fault);bad=dict(descriptor,artifact_archive_sha256=badref['sha256'])
                with self.subTest(fault=fault),self.assertRaises(ValueError):
                    medium.extract_candidate(badref,bad,root/('refused-'+fault),1048576)
                self.assertFalse((root/'escaped').exists())
            with self.assertRaisesRegex(ValueError,'expanded producer bound'):
                medium.extract_candidate(ref,descriptor,root/'too-large',1)
            with self.assertRaisesRegex(ValueError,'AppImage bytes'):
                medium.extract_candidate(ref,dict(descriptor,executable_sha256='0'*64),root/'wrong-package',1048576)

    def test_virtual_usb_native_sender_preserves_partial_qmp_and_rejects_foreign_target(self):
        import copy,importlib.util
        spec=importlib.util.spec_from_file_location('ubuntu_connection_control',
            Path(__file__).resolve().parents[1]/'scripts/omen_control/connection_control.py')
        control=importlib.util.module_from_spec(spec);spec.loader.exec_module(control)
        nonce='a'*32;birth={'pid':731,'start_ticks':'241','inherited_nonce':nonce,'exe_sha256':'e'*64}
        binding={'nonce':nonce,'artifact_source':'c'*40,'package_sha256':'d'*64}
        cfg={'nonce':nonce,'source_commit':'c'*40,'package_sha256':'d'*64,'whole_seconds':60,'native_executable_sha256':'e'*64,'display':[1600,900]}
        ready={'nonce':nonce,'process':birth,'app':{'pid':731,'window_id':412}}
        native={'pid':731,'window_id':412,'enabled':True,'visible':True,'readOnlyObservation':True,
                'rect':[30,40,100,24],'point':{'x':80,'y':52}}
        events=[]
        def send(command,args):
            events.append((command,args))
            if len(events)==2:raise TimeoutError('modeled lost QMP ACK after actual request')
            return {}
        q=SimpleNamespace(s=SimpleNamespace(settimeout=lambda n:None),call=send)
        operation=control.Pipeline(binding,cfg,q,None,ready,Path('/modeled-admitted-private-runtime'))
        operation.target=lambda *a,**k:{'value':copy.deepcopy(native)}
        # Model external native/socket/frame facts explicitly. The production
        # pointer sender records and checks its actual ordered event calls.
        with patch.object(control,'process',return_value=None),patch.object(control,'frame',
                return_value={'width':1600,'height':900}):
            with self.assertRaises(TimeoutError):operation.click('Build','Build NVIDIA Image')
            self.assertEqual(len(operation.actions),1)
            self.assertEqual(len(operation.actions[0]['actualQMPInput']),2)
            self.assertIsNone(operation.actions[0]['actualQMPInput'][1]['response'])
            events.clear();bad=copy.deepcopy(native);bad['pid']=732
            operation.target=lambda *a,**k:{'value':bad}
            with self.assertRaisesRegex(RuntimeError,'native control process'):
                operation.click('Build','Build NVIDIA Image')
            self.assertEqual(events,[])
            operation.target=lambda *a,**k:{'value':native};operation.end=time.monotonic()-1
            with self.assertRaisesRegex(RuntimeError,'deadline before actual pointer'):
                operation.click('Build','Build NVIDIA Image')
            self.assertEqual(events,[])
            # A timed chord schedules its own release. A late successful ACK
            # must fail the original deadline and retain the attempted chord.
            operation.end=1
            with patch.object(control.time,'monotonic',side_effect=[0,0,2]):
                with self.assertRaisesRegex(RuntimeError,'deadline after chord'):
                    operation.key('a',('ctrl',))
            self.assertEqual(len(events),1)
            self.assertEqual(operation.actions[-1]['kind'],'keyboard')
            self.assertEqual(len(operation.actions[-1]['actualQMPInput']),1)
            self.assertEqual(operation.actions[-1]['actualQMPInput'][0]['response'],{})
            events.clear();action_count=len(operation.actions)
            with patch.object(control.time,'monotonic',return_value=2):
                with self.assertRaisesRegex(RuntimeError,'deadline before chord'):
                    operation.key('a',('ctrl',))
            self.assertEqual(events,[])
            self.assertEqual(len(operation.actions),action_count)

    def test_virtual_usb_readback_matches_guest_observed_image_without_second_host_copy(self):
        import copy,hashlib,stat
        nonce='b'*32;output='/home/guest/opemos-robot-'+nonce+'/built.img'
        payload=b'completed guest image'*512
        birth={'pid':713,'start_ticks':'123','inherited_nonce':nonce}
        image={'path':output,'bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),
               'identity':dict(st_dev=7,st_ino=45,st_mode=stat.S_IFREG|0o600,st_uid=1000,
                   st_gid=1000,st_nlink=1,st_size=len(payload),st_mtime_ns=4,st_ctime_ns=4)}
        witness={'kind':'NATIVE_OBSERVATION','request_kind':'FILE','nonce':nonce,
                 'sequence':12,'clock_ns':12345,'process':birth,'value':image}
        # Guest process/image facts are explicit model DATA. Actual host file,
        # allocation, flush and every-byte comparison use the production path.
        with tempfile.TemporaryDirectory(prefix='opemos-observed-usb-') as directory:
            root=Path(directory);root.chmod(0o700)
            with runner.virtual_usb_backing(root,1048576,0) as (backing,fd):
                os.pwrite(fd,payload,0)
                value=runner.virtual_usb_readback_observed(backing,fd,witness,birth,nonce,output)
                self.assertEqual(value['readbackSHA256'],image['sha256'])
                self.assertEqual(value['bytesRead'],1048576)
                self.assertFalse(value['guestGUIOrBootAcceptanceClaimed'])
                self.assertEqual(sorted(p.name for p in root.iterdir()),['virtual-usb.raw'])
                for fault in ('nonce','process','path','extent','hash','owner'):
                    bad=copy.deepcopy(witness)
                    if fault=='nonce':bad['nonce']='c'*32
                    elif fault=='process':bad['process']['start_ticks']='124'
                    elif fault=='path':bad['value']['path']='/tmp/foreign.img'
                    elif fault=='extent':bad['value']['bytes']+=512
                    elif fault=='hash':bad['value']['sha256']='0'*64
                    else:bad['value']['identity']['st_uid']=0
                    with self.subTest(fault=fault),self.assertRaises(ValueError):
                        runner.virtual_usb_readback_observed(backing,fd,bad,birth,nonce,output)
                for offset in (0,len(payload)+31):
                    os.pwrite(fd,b'x',offset)
                    with self.subTest(offset=offset),self.assertRaises(ValueError):
                        runner.virtual_usb_readback_observed(backing,fd,witness,birth,nonce,output)
                    os.pwrite(fd,payload[:1] if offset==0 else b'\0',offset)

    def test_virtual_usb_native_target_uses_current_pid_window_and_real_geometry(self):
        spec=importlib.util.spec_from_file_location('ubuntu_native_observer',
            Path(__file__).resolve().parents[1]/'scripts/omen_control/observer_guest.py')
        observer=importlib.util.module_from_spec(spec);spec.loader.exec_module(observer)
        states={x:x for x in('enabled','sensitive','visible','showing','defunct','screen')}
        class Node:
            def __init__(self,name='',pid=731,role='push button',children=(),rect=(30,40,100,24)):
                self.name=name;self.pid=pid;self.role=role;self.children=list(children)
                self.rect=rect;self.flags={'enabled','sensitive','visible','showing'}
            def get_name(self):return self.name
            def get_process_id(self):return self.pid
            def get_role_name(self):return self.role
            def get_attributes(self):return ['toolkit:fixture-native']
            def get_accessible_id(self):return 'observed-control-17'
            def get_child_count(self):return len(self.children)
            def get_child_at_index(self,index):return self.children[index]
            def get_state_set(self):return SimpleNamespace(contains=lambda flag:flag in self.flags)
            def get_component_iface(self):return SimpleNamespace(get_extents=lambda kind:
                SimpleNamespace(x=self.rect[0],y=self.rect[1],width=self.rect[2],height=self.rect[3]))
            def do_action(self,*args):raise AssertionError('Observation must never activate native controls')
        target=Node('Build NVIDIA Image');app=Node(children=[target]);desktop=Node(children=[app])
        window={'pid':731,'window_id':481,'rect':[0,0,900,700]}
        actual=observer.observed_control(desktop,window,'Build NVIDIA Image',['push button'],states,[1280,800])
        self.assertEqual(actual['point'],{'x':80,'y':52})
        self.assertEqual(actual['rect'],[30,40,100,24]);self.assertTrue(actual['readOnlyObservation'])
        actual=observer.observed_control(desktop,window,'Build NVIDIA Image',['push button'],
            states,[1280,800],hit_test=lambda x,y:[481,482])
        self.assertEqual(actual['nativeAccessibleId'],'observed-control-17')
        self.assertEqual(actual['hitObservation'],'native-same-control-unoccluded')
        with self.assertRaisesRegex(RuntimeError,'occluded'):
            observer.observed_control(desktop,window,'Build NVIDIA Image',['push button'],
                states,[1280,800],hit_test=lambda x,y:[999])
        for fault in('foreign-pid','disabled','hidden','defunct','outside','duplicate','role'):
            target.pid=731;target.role='push button';target.rect=(30,40,100,24)
            target.flags={'enabled','sensitive','visible','showing'};app.children=[target]
            if fault=='foreign-pid':target.pid=732
            elif fault=='disabled':target.flags.remove('enabled')
            elif fault=='hidden':target.flags.remove('showing')
            elif fault=='defunct':target.flags.add('defunct')
            elif fault=='outside':target.rect=(850,40,100,24)
            elif fault=='duplicate':app.children.append(Node('Build NVIDIA Image'))
            else:target.role='entry'
            with self.subTest(fault=fault),self.assertRaises(RuntimeError):
                observer.observed_control(desktop,window,'Build NVIDIA Image',['push button'],states,[1280,800])

    def test_virtual_usb_real_file_descriptor_and_qemu_attachment_preserve_source(self):
        import fcntl
        with tempfile.TemporaryDirectory(prefix='opemos-virtual-usb-') as directory:
            root = Path(directory); root.chmod(0o700)
            original = root / 'source.raw'; original.write_bytes(b'immutable source')
            with runner.virtual_usb_backing(root, 1048576, 0) as (backing, fd):
                args = runner.virtual_usb_qemu_arguments(backing, fd, 'a' * 32)
                self.assertIn(f'file=/proc/self/fd/{fd}', args[1])
                self.assertIn('usb-storage', args[3])
                self.assertNotIn('/dev/', ' '.join(args))
                self.assertEqual(os.pread(fd, 512, 0), bytes(512))
                self.assertGreaterEqual(os.fstat(fd).st_blocks * 512, backing['capacityBytes'])
                os.pwrite(fd, b'guest USB bytes', 0); os.fsync(fd)
                for fault in ('inode', 'capacityBytes', 'uid'):
                    bad = dict(backing); bad[fault] += 1
                    with self.subTest(fault=fault), self.assertRaises(ValueError):
                        runner.virtual_usb_qemu_arguments(bad, fd, 'a' * 32)
                with self.assertRaises(ValueError):
                    runner.virtual_usb_qemu_arguments(backing, fd, '../escape')
                self.assertTrue(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            with self.assertRaises(OSError): os.fstat(fd)
            self.assertEqual((root / 'virtual-usb.raw').read_bytes()[:15], b'guest USB bytes')
            self.assertEqual(original.read_bytes(), b'immutable source')
            with self.assertRaises(FileExistsError):
                with runner.virtual_usb_backing(root, 1048576, 0): pass

    def test_virtual_usb_refuses_unbudgeted_or_foreign_placement_before_creation(self):
        with tempfile.TemporaryDirectory(prefix='opemos-virtual-usb-refuse-') as directory:
            root = Path(directory); root.chmod(0o700)
            for capacity, charged in ((True, 0), (513, 0), (0, 0), (1048576, runner.VM_BUDGET_BYTES)):
                with self.subTest(capacity=capacity, charged=charged), self.assertRaises(ValueError):
                    with runner.virtual_usb_backing(root, capacity, charged): pass
                self.assertFalse((root / 'virtual-usb.raw').exists())
            root.chmod(0o755)
            with self.assertRaises(ValueError):
                with runner.virtual_usb_backing(root, 1048576, 0): pass
            self.assertFalse((root / 'virtual-usb.raw').exists())

    def test_virtual_usb_full_readback_detects_payload_tail_and_source_drift(self):
        import hashlib
        with tempfile.TemporaryDirectory(prefix='opemos-virtual-usb-readback-') as directory:
            root = Path(directory); root.chmod(0o700)
            image = root / 'actual-output.img'; payload = b'image bytes' * 512
            image.write_bytes(payload); image.chmod(0o400)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                      'st_size', 'st_mtime_ns', 'st_ctime_ns')
            ref = {'path': str(image), 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
                   'identity': {name: getattr(image.stat(), name) for name in fields}}
            with runner.virtual_usb_backing(root, 1048576, 0) as (backing, fd):
                os.pwrite(fd, payload, 0)
                alias = {'path': backing['path'], 'bytes': backing['capacityBytes'], 'sha256': '0' * 64,
                         'identity': {name: getattr(os.fstat(fd), name) for name in fields}}
                with self.assertRaisesRegex(ValueError, 'alias'):
                    runner.virtual_usb_readback(backing, fd, alias)
                value = runner.virtual_usb_readback(backing, fd, ref)
                self.assertEqual(value['bytesRead'], 1048576)
                self.assertEqual(value['readbackSHA256'], ref['sha256'])
                self.assertEqual(value['backingSHA256'], hashlib.sha256(payload + bytes(1048576-len(payload))).hexdigest())
                self.assertFalse(value['guestGUIOrBootAcceptanceClaimed'])
                for offset, expected in ((0, 'differs'), (len(payload) + 100, 'tail')):
                    os.pwrite(fd, b'x', offset)
                    with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, expected):
                        runner.virtual_usb_readback(backing, fd, ref)
                    os.pwrite(fd, payload[:1] if offset == 0 else b'\0', offset)
                image.chmod(0o600); image.write_bytes(b'changed'.ljust(len(payload), b'!')); image.chmod(0o400)
                with self.assertRaises(ValueError): runner.virtual_usb_readback(backing, fd, ref)

    def test_launcher_relay_refuses_unisolated_or_missing_base_before_spawn(self):
        with patch.object(runner.subprocess, 'Popen') as spawn:
            for selected in (True, 1, 'true'):
                with self.subTest(selected=selected), self.assertRaisesRegex(ValueError, 'stdio relay'):
                    runner.launch_bounded(Path('/unused.qcow2'), 1000000, relay_stdio=selected)
            with self.assertRaisesRegex(ValueError, 'immutable base'):
                runner.launch_bounded(Path('/unused.qcow2'), 1000000,
                                      firmware={'code':'code','vars':'vars'},
                                      isolated_ssh=True, relay_stdio=True)
            spawn.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'stdio relay'):
            runner.run_owned_vm('/unused', relay_stdio=True)

    def test_launcher_relay_completion_quits_guest_and_closes_namespace(self):
        self.assert_launcher_relay_cleanup(cancelled=False)

    def test_launcher_timeout_joins_cancelled_transport_before_return(self):
        self.assert_launcher_relay_cleanup(cancelled=True)

    def assert_launcher_relay_cleanup(self, cancelled):
        with tempfile.TemporaryDirectory(prefix='opemos-relay-launch-') as directory:
            image = Path(directory) / 'active.qcow2'
            base = Path(directory) / 'base.qcow2'
            image.write_bytes(b'fixture'); base.write_bytes(b'fixture base')
            program = ('import json,sys; print(json.dumps({"QMP":{}}),flush=True); '
                       'a=json.loads(input()); print(json.dumps({"return":{},"id":a["id"]}),flush=True); '
                       'b=json.loads(input()); print(json.dumps({"return":{"running":True,"status":"running"},"id":b["id"]}),flush=True); '
                       'c=json.loads(input()); sys.exit(0 if c.get("execute")=="quit" else 9)')
            fd = os.open('/proc/self/ns/net', os.O_RDONLY)
            finished = threading.Event()
            children = []
            identities = []
            real_spawn, real_which = subprocess.Popen, runner.shutil.which
            def spawn(*args, **kwargs):
                child = real_spawn(*args, **kwargs)
                children.append(child)
                identities.append(fixture_spawn_receipt(child, 'qmp-launcher'))
                return child
            def transport(namespace, identity, deadline, ancestry, cancel):
                self.assertEqual(namespace, fd)
                if cancelled:
                    if not cancel.wait(5):
                        raise AssertionError('launcher did not cancel transport')
                finished.set()
                return 7
            with patch.object(runner, 'windows_launch_command', return_value=[sys.executable, '-c', program]), \
                    patch.object(runner.shutil, 'which', side_effect=lambda name: sys.executable if name == 'qemu-system-x86_64' else real_which(name)), \
                    patch.object(runner.subprocess, 'Popen', side_effect=spawn), \
                    patch.object(runner, 'pin_owned_qemu_network', return_value=(fd, (), ())), \
                    patch.object(runner, 'relay_owned_guest_stdio', side_effect=transport):
                if cancelled:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        runner.launch_bounded(image, 1000000, 1, firmware={'code':'code','vars':'vars'},
                                              isolated_ssh=True, relay_stdio=True, relay_base=base)
                else:
                    self.assertEqual(runner.launch_bounded(image, 1000000, 3,
                                     firmware={'code':'code','vars':'vars'}, isolated_ssh=True,
                                     relay_stdio=True, relay_base=base), 7)
            self.assertTrue(finished.is_set())
            self.assertEqual(len(children), 1)
            self.assertEqual(children[0].returncode, 0)
            fixture_reap_receipt(children[0], identities[0])
            with self.assertRaises(OSError):
                os.fstat(fd)
            with self.assertRaises(ChildProcessError):
                os.waitpid(children[0].pid, os.WNOHANG)

    def test_stdio_relay_cancelled_before_connection_never_spawns(self):
        cancel = threading.Event()
        cancel.set()
        with patch.object(runner.subprocess, 'Popen') as spawn, \
                patch.object(runner.os, 'fstat') as inspected:
            with self.assertRaisesRegex(InterruptedError, 'cancelled'):
                runner.relay_owned_guest_stdio(-1, (), time.monotonic() + 2, (), cancel)
            spawn.assert_not_called()
            inspected.assert_not_called()

    def test_stdio_relay_refuses_changed_launcher_ancestor_before_connection(self):
        fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
        parent = int(fields[1])
        parent_root = Path('/proc') / str(parent)
        parent_fields = (parent_root / 'stat').read_text().rsplit(')', 1)[1].split()
        identity = (os.getpid(), int(fields[19]), os.getuid(), parent)
        stale_parent = (parent, int(parent_fields[19]) + 1,
                        parent_root.stat().st_uid, int(parent_fields[1]))
        fd = os.open('/proc/self/ns/net', os.O_RDONLY)
        try:
            with patch.object(runner.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(ValueError, 'ancestry changed'):
                    runner.relay_owned_guest_stdio(fd, identity, time.monotonic() + 2,
                                                  (identity, stale_parent))
                spawn.assert_not_called()
        finally:
            os.close(fd)

    def test_stdio_relay_silent_child_deadline_kills_and_reaps(self):
        self.assert_silent_relay_reaped(cancelled=False)

    def test_stdio_relay_cancelled_child_kills_and_reaps(self):
        self.assert_silent_relay_reaped(cancelled=True)

    def assert_silent_relay_reaped(self, cancelled):
        fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
        identity = (os.getpid(), int(fields[19]), os.getuid(), int(fields[1]))
        fd = os.open('/proc/self/ns/net', os.O_RDONLY)
        real_stat, real_spawn = os.stat, subprocess.Popen
        children = []
        identities = []
        cancel = threading.Event()
        def simulated_host_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if str(path) == '/proc/self/ns/net':
                return SimpleNamespace(st_dev=result.st_dev, st_ino=result.st_ino + 1)
            return result
        def silent_owned_child(*args, **kwargs):
            child = real_spawn([sys.executable, '-c', 'import time; time.sleep(30)'],
                               start_new_session=True, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(child)
            identities.append(fixture_spawn_receipt(child, 'silent-relay'))
            if cancelled:
                cancel.set()
            return child
        try:
            with patch.object(runner.os, 'stat', side_effect=simulated_host_stat), \
                    patch.object(runner.shutil, 'which', return_value=sys.executable), \
                    patch.object(runner.subprocess, 'Popen', side_effect=silent_owned_child):
                failure, message = ((InterruptedError, 'cancelled') if cancelled
                                    else (TimeoutError, 'absolute deadline'))
                with self.assertRaisesRegex(failure, message):
                    runner.relay_owned_guest_stdio(fd, identity, time.monotonic() + 0.15,
                                                  (identity,), cancel)
            self.assertEqual(len(children), 1)
            self.assertEqual(children[0].returncode, -9)
            fixture_reap_receipt(children[0], identities[0])
            with self.assertRaises(ChildProcessError):
                os.waitpid(children[0].pid, os.WNOHANG)
        finally:
            os.close(fd)
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait()

    def test_stdio_relay_refuses_host_namespace_without_spawning(self):
        fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
        identity = (os.getpid(), int(fields[19]), os.getuid(), int(fields[1]))
        fd = os.open('/proc/self/ns/net', os.O_RDONLY)
        try:
            with patch.object(runner.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(ValueError, 'private QEMU namespace'):
                    runner.relay_owned_guest_stdio(fd, identity, time.monotonic() + 2, (identity,))
                spawn.assert_not_called()
        finally:
            os.close(fd)

    def test_stdio_relay_refuses_reused_identity_before_connection(self):
        fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
        identity = (os.getpid(), int(fields[19]) + 1, os.getuid(), int(fields[1]))
        fd = os.open('/proc/self/ns/net', os.O_RDONLY)
        try:
            with patch.object(runner.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(ValueError, 'ancestry changed'):
                    runner.relay_owned_guest_stdio(fd, identity, time.monotonic() + 2, (identity,))
                spawn.assert_not_called()
        finally:
            os.close(fd)

    def test_relay_refuses_invalid_pid_deadline_and_symlink_before_namespace_open(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'image'
            target.write_bytes(b'fixture')
            linked = Path(directory) / 'linked'
            linked.symlink_to(target)
            with patch.object(runner.os, 'open') as opened:
                for pid in (0, -1, True, '1'):
                    with self.subTest(pid=pid), self.assertRaises(ValueError):
                        runner.pin_owned_qemu_network(pid, [target], time.monotonic() + 2)
                for deadline in (float('nan'), float('inf'), time.monotonic() - 1):
                    with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                        runner.pin_owned_qemu_network(os.getpid(), [target], deadline)
                with self.assertRaisesRegex(ValueError, 'unsafe required'):
                    runner.pin_owned_qemu_network(os.getpid(), [linked], time.monotonic() + 2)
                opened.assert_not_called()

    def test_relay_refuses_dead_launcher_without_opening_any_namespace(self):
        child = subprocess.Popen([sys.executable, '-c', 'pass'])
        identity = fixture_spawn_receipt(child, 'dead-launcher')
        child.wait(timeout=5)
        fixture_reap_receipt(child, identity)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'image'
            target.write_bytes(b'fixture')
            with patch.object(runner.os, 'open') as opened:
                with self.assertRaises(FileNotFoundError):
                    runner.pin_owned_qemu_network(child.pid, [target], time.monotonic() + 2)
                opened.assert_not_called()

    def test_isolated_ssh_refuses_malformed_or_non_windows_before_spawn(self):
        with patch.object(runner.subprocess, 'Popen') as spawn:
            for selected in ('true', 1, None, True):
                with self.subTest(selected=selected), self.assertRaisesRegex(ValueError, 'isolated SSH'):
                    runner.launch_bounded(Path('/unused.qcow2'), 1000000, isolated_ssh=selected)
            spawn.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'explicit isolated SSH'):
            runner.run_owned_vm('/unused', isolated_ssh='true')

    def test_monitor_flood_and_ignored_quit_are_killed_and_reaped(self):
        greeting = ('import json,sys,time; print(json.dumps({"QMP":{}}),flush=True); '
                    'a=json.loads(input()); print(json.dumps({"return":{},"id":a["id"]}),flush=True); '
                    'b=json.loads(input()); print(json.dumps({"return":{"running":True,"status":"running"},"id":b["id"]}),flush=True); ')
        for suffix, error in [('sys.stdout.write("x"*70000); sys.stdout.flush(); time.sleep(30)', ValueError),
                              ('time.sleep(30)', subprocess.TimeoutExpired)]:
            with self.subTest(error=error), tempfile.TemporaryDirectory(prefix='opemos-qmp-kill-') as directory:
                image = Path(directory) / 'active.qcow2'
                image.write_bytes(b'fixture')
                real_which = runner.shutil.which
                real_popen = runner.subprocess.Popen
                children = []
                def spawn(*args, **kwargs):
                    child = real_popen(*args, **kwargs)
                    children.append(child)
                    return child
                with patch.object(runner, 'windows_launch_command', return_value=[sys.executable, '-c', greeting + suffix]), patch.object(runner.shutil, 'which', side_effect=lambda name: sys.executable if name == 'qemu-system-x86_64' else real_which(name)), patch.object(runner.subprocess, 'Popen', side_effect=spawn):
                    with self.assertRaises(error):
                        runner.launch_bounded(image, 1000000, 1, firmware={'code':'code.fd','vars':'vars.fd'})
                self.assertEqual(len(children), 1)
                self.assertEqual(children[0].returncode, -9)
                receipts = list(Path(directory).glob('receipt-qmp-*.json'))
                self.assertEqual(len(receipts), 1)
                self.assertFalse(json.loads(receipts[0].read_text())['workflowAccepted'])

    def test_protocol_refusal_sends_quit_and_reaps_owned_child(self):
        with tempfile.TemporaryDirectory(prefix='opemos-qmp-refusal-') as directory:
            image = Path(directory) / 'active.qcow2'
            image.write_bytes(b'fixture')
            program = ('import json,sys; print("{}",flush=True); '
                       'a=json.loads(input()); sys.exit(0 if a.get("execute")=="quit" else 9)')
            real_which = runner.shutil.which
            real_popen = runner.subprocess.Popen
            children = []
            def spawn(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                children.append(child)
                return child
            with patch.object(runner, 'windows_launch_command', return_value=[sys.executable, '-c', program]), patch.object(runner.shutil, 'which', side_effect=lambda name: sys.executable if name == 'qemu-system-x86_64' else real_which(name)), patch.object(runner.subprocess, 'Popen', side_effect=spawn):
                with self.assertRaisesRegex(ValueError, 'greeting'):
                    runner.launch_bounded(image, 1000000, 3, firmware={'code':'code.fd','vars':'vars.fd'})
            self.assertEqual(len(children), 1)
            self.assertEqual(children[0].returncode, 0)
            self.assertEqual(list(Path(directory).glob('receipt-qmp-*.json')), [])

    def test_firmware_launcher_stdio_records_monitor_not_acceptance(self):
        with tempfile.TemporaryDirectory(prefix='opemos-qmp-launch-') as directory:
            image = Path(directory) / 'active.qcow2'
            image.write_bytes(b'fixture')
            program = ('import json,sys; print(json.dumps({"QMP":{}}),flush=True); '
                       'a=json.loads(input()); print(json.dumps({"return":{},"id":a["id"]}),flush=True); '
                       'b=json.loads(input()); print(json.dumps({"return":{"running":True,"status":"running"},"id":b["id"]}),flush=True)')
            real_which = runner.shutil.which
            with patch.object(runner, 'windows_launch_command', return_value=[sys.executable, '-c', program]) as prepare, patch.object(runner.shutil, 'which', side_effect=lambda name: sys.executable if name == 'qemu-system-x86_64' else real_which(name)):
                self.assertEqual(runner.launch_bounded(image, 1000000, 3, firmware={'code':'code.fd','vars':'vars.fd'}, isolated_ssh=True), 0)
            prepare.assert_called_once_with(image, image.parent / 'code.fd', image.parent / 'vars.fd', isolated_ssh=True)
            receipts = list(Path(directory).glob('receipt-qmp-*.json'))
            self.assertEqual(len(receipts), 1)
            evidence = json.loads(receipts[0].read_text())
            self.assertTrue(evidence['monitorStatus']['running'])
            self.assertFalse(evidence['workflowAccepted'])

    def test_stdio_qmp_exact_status_and_refusals(self):
        import os
        import io
        cases = [(b'{"QMP":{}}\n{"return":{},"id":1}\n{"event":"RESET"}\n{"return":{"running":true,"status":"running"},"id":2}\n', None),
                 (b'{}\n', 'greeting'),
                 (b'{"QMP":{}}\n{"return":{},"id":9}\n', 'identity'),
                 (b'{"QMP":{}}\n', 'closed')]
        for payload, error in cases:
            read_fd, write_fd = os.pipe()
            os.write(write_fd, payload); os.close(write_fd)
            with os.fdopen(read_fd, 'rb', buffering=0) as reader:
                writer = io.BytesIO()
                if error:
                    with self.assertRaisesRegex(ValueError, error):
                        runner.qmp_stdio_status(reader, writer)
                else:
                    self.assertTrue(runner.qmp_stdio_status(reader, writer)['running'])
                    self.assertEqual([json.loads(line)['execute'] for line in writer.getvalue().splitlines()], ['qmp_capabilities', 'query-status'])

    def test_stdio_qmp_silent_peer_expires_without_deadline_reset(self):
        import os
        read_fd, write_fd = os.pipe()
        try:
            with os.fdopen(read_fd, 'rb', buffering=0) as reader, tempfile.TemporaryFile() as writer:
                with self.assertRaises(TimeoutError):
                    runner.qmp_stdio_status(reader, writer, 0.02)
        finally:
            os.close(write_fd)

    def test_firmware_lifecycle_accounts_and_preserves_record_after_export(self):
        with tempfile.TemporaryDirectory(prefix='opemos-gen2-cycle-') as directory:
            root = Path(directory)
            (root / '.opemos-migration-owned').write_text('OPEMOS.EXE\n')
            base, image = root / 'base.qcow2', root / 'active.qcow2'
            subprocess.run(['qemu-img', 'create', '-f', 'qcow2', str(base), '16M'], check=True, capture_output=True)
            subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(image)], check=True, capture_output=True)
            code, variables = root / 'code.fd', root / 'vars.fd'
            for path, size in ((code, 3653632), (variables, 540672)):
                path.write_bytes(b'\0' * size)
            info = variables.stat()
            firmware = {'code': code.name, 'codeSha256': runner.base_digest(code),
                        'vars': variables.name, 'varsIdentity': [info.st_dev, info.st_ino]}
            manifest = {'schemaVersion': 1, 'image': image.name, 'retained': [],
                        'base': base.name, 'baseSha256': runner.base_digest(base),
                        'writeCeilingBytes': 12000000, 'windowsFirmware': firmware}
            (root / 'manifest.json').write_text(json.dumps(manifest))
            expected_allocation = sum(p.stat().st_blocks * 512 for p in root.iterdir())
            with patch.object(runner, 'require_ntfs_envelope', return_value={}), patch.object(runner, 'launch_bounded', return_value=0) as launch:
                before = (root / 'manifest.json').read_bytes()
                with patch.object(runner, 'recover_retirement') as recover, self.assertRaisesRegex(ValueError, 'exact migrated Agent-Boot base'):
                    runner.run_owned_vm(root, isolated_ssh=True)
                recover.assert_not_called()
                launch.assert_not_called()
                self.assertEqual((root / 'manifest.json').read_bytes(), before)
                self.assertTrue(image.exists())
                receipt = runner.run_owned_vm(root)
            launch.assert_called_once_with(image, 12000000, 300, firmware=firmware)
            updated = json.loads((root / 'manifest.json').read_text())
            self.assertEqual(updated['windowsFirmware'], firmware)
            self.assertNotIn('isolatedSsh', updated)  # Selection is per run, never sticky.
            self.assertEqual(runner.base_digest(base), manifest['baseSha256'])
            self.assertTrue(code.exists() and variables.exists())
            # The lock is created during admission and contributes no blocks.
            self.assertGreaterEqual(receipt['totalAfterAllocatedBytes'], expected_allocation)

    def test_firmware_changed_code_or_replaced_vars_refuses_preserving_files(self):
        with tempfile.TemporaryDirectory(prefix='opemos-firmware-') as directory:
            root = Path(directory)
            code, variables = root / 'code.fd', root / 'vars.fd'
            for path, size in ((code, 3653632), (variables, 540672)):
                with path.open('wb') as output:
                    output.truncate(size)
            info = variables.stat()
            record = {'code': code.name, 'codeSha256': runner.base_digest(code),
                      'vars': variables.name, 'varsIdentity': [info.st_dev, info.st_ino]}
            self.assertEqual(runner.validate_windows_firmware(root, record, ['active.qcow2', 'base.qcow2']), {'code.fd', 'vars.fd'})
            with code.open('r+b') as output:
                output.write(b'changed')
            with self.assertRaisesRegex(ValueError, 'CODE hash'):
                runner.validate_windows_firmware(root, record, [])
            record['codeSha256'] = runner.base_digest(code)
            variables.rename(root / 'preserved-vars.fd')
            with variables.open('wb') as output:
                output.truncate(540672)
            with self.assertRaisesRegex(ValueError, 'VARS identity'):
                runner.validate_windows_firmware(root, record, [])
            self.assertTrue((root / 'preserved-vars.fd').exists())

    def test_windows_refuses_changed_pool_limits(self):
        pool = '0::/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/owned.service\n'
        with patch.object(Path, 'read_text', side_effect=[pool, '34359738368', '1']):
            with self.assertRaisesRegex(ValueError, 'limits changed'):
                runner.require_windows_pool()

    def test_windows_pool_accepts_ten_cpu_limit_and_refuses_old_twelve(self):
        pool = '0::/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/owned.service\n'
        with patch.object(Path, 'read_text', side_effect=[pool, '34359738368', '0', '1000000 100000', '0-9']):
            runner.require_windows_pool()
        with patch.object(Path, 'read_text', side_effect=[pool, '34359738368', '0', '1200000 100000']):
            with self.assertRaisesRegex(ValueError, 'limits changed'):
                runner.require_windows_pool()

    def test_windows_command_preserves_gen2_resources_and_only_kvm_group(self):
        import os
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory(prefix='opemos-uefi-') as directory:
            root = Path(directory)
            image, code, variables = (root / name for name in ('active.qcow2', 'code.fd', 'vars.fd'))
            for path, size in ((image, 1), (code, 3653632), (variables, 540672)):
                with path.open('wb') as output:
                    output.truncate(size)
            real_stat = Path.stat
            device_group = os.getgid() + 10000
            def device_stat(path, *args, **kwargs):
                if str(path) == '/dev/kvm':
                    return SimpleNamespace(st_mode=0o020660, st_gid=device_group)
                return real_stat(path, *args, **kwargs)
            with patch.object(runner, 'require_windows_pool'), patch.object(runner, 'require_ntfs_envelope'), patch.object(Path, 'stat', device_stat), patch.object(runner.os, 'access', return_value=True), patch.object(runner.os, 'getgroups', return_value=[device_group, device_group + 1]), patch.object(runner.shutil, 'which', side_effect=lambda name: '/usr/bin/' + name):
                command = runner.windows_launch_command(image, code, variables)
                ssh_command = runner.windows_launch_command(image, code, variables, isolated_ssh=True)
                with self.assertRaisesRegex(ValueError, 'explicit'):
                    runner.windows_launch_command(image, code, variables, isolated_ssh='true')
            self.assertEqual(command[command.index('-m') + 1], '6152')
            self.assertEqual(command[command.index('-smp') + 1], '2')
            self.assertIn('q35,accel=kvm', command)
            self.assertNotIn('q35,accel=tcg', command)
            self.assertIn('--groups=' + str(device_group), command)
            self.assertNotIn('--groups=' + str(device_group + 1), command)
            self.assertIn('if=pflash,format=raw,readonly=on,file=' + str(code), command)
            self.assertIn('if=pflash,format=raw,file=' + str(variables), command)
            self.assertEqual(command[command.index('-nic') + 1], 'none')
            self.assertIn('--unshare-net', ssh_command)
            self.assertEqual(ssh_command[ssh_command.index('-nic') + 1],
                             'user,model=e1000,mac=00:15:5d:10:0f:02,restrict=on,net=172.22.64.0/20,host=172.22.64.1,hostfwd=tcp:127.0.0.1:2222-172.22.79.248:22')
            self.assertNotIn('0.0.0.0', ' '.join(ssh_command))

    def test_windows_refuses_unadmitted_process_before_image_or_tools(self):
        with patch.object(Path, 'read_text', return_value='0::/user.slice/unrelated.service\n'), patch.object(runner.subprocess, 'run') as tools:
            with self.assertRaisesRegex(ValueError, 'inherit'):
                runner.windows_launch_command('/absent/image', '/absent/code', '/absent/vars')
            tools.assert_not_called()

    def test_windows_refuses_firmware_outside_envelope_before_kvm(self):
        with patch.object(runner, 'require_windows_pool'), patch.object(runner, 'require_ntfs_envelope'), patch.object(runner, 'launch_command') as launch:
            with self.assertRaisesRegex(ValueError, 'contained direct file'):
                runner.windows_launch_command('/owned/image', '/external/code', '/owned/vars')
            launch.assert_not_called()

    def test_backed_runtime_refuses_unknown_slot_ceiling_before_admission(self):
        for value in (None, True, 0, 60_000_000_000):
            with self.subTest(ceiling=value), tempfile.TemporaryDirectory(prefix='opemos-slot-') as directory:
                root=Path(directory)
                (root/'.opemos-migration-owned').write_text('OPEMOS.EXE\n')
                (root/'manifest.json').write_text(json.dumps({'schemaVersion':1,
                    'image':'active.qcow2','retained':[],'base':'base.qcow2',
                    'baseSha256':'unverified','writeCeilingBytes':value}))
                with patch.object(runner,'require_ntfs_envelope') as admission, patch.object(runner,'launch_bounded') as launch:
                    with self.assertRaisesRegex(ValueError,'exact backed-runtime write ceiling'):
                        runner.run_owned_vm(root)
                    admission.assert_not_called(); launch.assert_not_called()

    def test_active_image_not_double_charged_but_retained_image_is(self):
        import vm_write_ceiling
        with tempfile.TemporaryDirectory(prefix='opemos-admission-') as directory:
            root=Path(directory)
            (root / '.opemos-migration-owned').write_text('OPEMOS.EXE\n')
            image=root / 'generated.qcow2'
            subprocess.run(['qemu-img','create','-f','qcow2',str(image),'16M'],check=True,capture_output=True)
            subprocess.run(['qemu-io','-f','qcow2','-c','write -P 0x55 0 6M',str(image)],check=True,capture_output=True)
            identity=[image.stat().st_dev,image.stat().st_ino]
            (root / 'manifest.json').write_text(json.dumps({'schemaVersion':1,'image':image.name,'retained':[],'generated':{image.name:identity}}))
            def bounded_guest(path,ceiling,timeout):
                if path.stat().st_size > ceiling:
                    raise ValueError('image already exceeds write ceiling')
                return 0
            with patch.object(vm_write_ceiling,'VM_BUDGET_BYTES',16*1024*1024), patch.object(runner,'VM_BUDGET_BYTES',16*1024*1024), patch.object(runner,'launch_bounded',side_effect=bounded_guest):
                receipt=runner.run_owned_vm(root)
            self.assertFalse(image.exists())
            self.assertTrue(Path(receipt['export']).exists())
            self.assertLess(receipt['totalAfterAllocatedBytes'],16*1024*1024)
            # A separate retained file exhausts the reserved budget; it is not
            # an external Windows backup exemption and must refuse admission.
            retained=root / 'retained.bin'
            retained.write_bytes(b'x'*(15*1024*1024))
            manifest=json.loads((root / 'manifest.json').read_text())
            manifest['retained'].append(retained.name)
            (root / 'manifest.json').write_text(json.dumps(manifest))
            with patch.object(vm_write_ceiling,'VM_BUDGET_BYTES',16*1024*1024), patch.object(runner,'launch_bounded') as launch:
                with self.assertRaises(ValueError):
                    runner.run_owned_vm(root)
                launch.assert_not_called()

    def test_recovery_at_retirement_switch_and_unlink_boundaries(self):
        # Inject interruption only at the retirement boundaries; real QEMU
        # compare/check proves equivalent bytes before recovery may unlink.
        for phase in ('before-first-reference', 'journal-durable', 'references-durable', 'unlink-durable'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(prefix='opemos-crash-') as directory:
                root=Path(directory)
                (root / '.opemos-migration-owned').write_text('OPEMOS.EXE\n')
                source=root / 'source.qcow2'
                subprocess.run(['qemu-img','create','-f','qcow2',str(source),'16M'],check=True,capture_output=True)
                (root / 'manifest.json').write_text(json.dumps({'schemaVersion':1,'image':source.name,'retained':[]}))
                with patch.object(runner,'launch_bounded',return_value=0):
                    first=runner.run_owned_vm(root)
                old=Path(first['export'])
                real_sync=runner.sync_directory
                def interrupt(path):
                    real_sync(path)
                    journal=root / '.retirement.json'
                    if not journal.exists():
                        return
                    state=json.loads((root / 'manifest.json').read_text())
                    reached=(phase=='before-first-reference' and state['image']==old.name or
                             phase=='journal-durable' and old.name in state['retained'] or
                             phase=='references-durable' and old.name not in state['retained'] and old.exists() or
                             phase=='unlink-durable' and not old.exists())
                    if reached:
                        raise RuntimeError('injected interruption')
                with patch.object(runner,'launch_bounded',return_value=0), patch.object(runner,'sync_directory',side_effect=interrupt):
                    with self.assertRaisesRegex(RuntimeError,'injected interruption'):
                        runner.run_owned_vm(root)
                self.assertTrue((root / '.retirement.json').exists())
                manifest=json.loads((root / 'manifest.json').read_text())
                runner.recover_retirement(root,manifest)
                self.assertFalse(old.exists())
                self.assertTrue(source.exists())
                self.assertFalse((root / '.retirement.json').exists())
                recovered=json.loads((root / 'manifest.json').read_text())
                self.assertNotIn(old.name,recovered['retained'])
                self.assertTrue((root / recovered['image']).exists())

    def test_recovery_refuses_mismatched_identity(self):
        with tempfile.TemporaryDirectory(prefix='opemos-recovery-') as directory:
            root = Path(directory)
            old = root / 'generated.qcow2'
            old.write_bytes(b'preserve')
            (root / 'receipt-test.json').write_text(json.dumps({'retirementCandidate': old.name}))
            (root / '.retirement.json').write_text(json.dumps({'old': old.name,
                'identity': [-1, -1], 'replacement': 'replacement.qcow2', 'receipt': 'receipt-test.json'}))
            with self.assertRaises(ValueError):
                runner.recover_retirement(root, {'image': 'replacement.qcow2', 'retained': []})
            self.assertEqual(old.read_bytes(), b'preserve')
            self.assertTrue((root / '.retirement.json').exists())

    def test_missing_old_cannot_clear_journal_for_replaced_candidate(self):
        with tempfile.TemporaryDirectory(prefix='opemos-missing-old-') as directory:
            root=Path(directory)
            replacement=root/'replacement.qcow2'
            replacement.write_bytes(b'not the verified replacement')
            (root/'receipt-test.json').write_text(json.dumps({'retirementCandidate':'old.qcow2'}))
            (root/'.retirement.json').write_text(json.dumps({'old':'old.qcow2',
                'identity':[-1,-1],'replacement':replacement.name,
                'replacementIdentity':[-2,-2],'receipt':'receipt-test.json'}))
            with self.assertRaisesRegex(ValueError,'matching replacement identity'):
                runner.recover_retirement(root,{'image':replacement.name,'retained':[],
                    'generated':{replacement.name:[-2,-2]}})
            self.assertTrue((root/'.retirement.json').exists())
            self.assertEqual(replacement.read_bytes(),b'not the verified replacement')

    def test_missing_old_with_valid_replacement_preserves_dangling_references(self):
        for retained, generated_old in ((True, False), (False, True), (True, True)):
            with self.subTest(retained=retained, generated=generated_old), tempfile.TemporaryDirectory(prefix='opemos-dangling-') as directory:
                root=Path(directory)
                replacement=root/'replacement.qcow2'
                subprocess.run(['qemu-img','create','-f','qcow2',str(replacement),'16M'],check=True,capture_output=True)
                identity=[replacement.stat().st_dev,replacement.stat().st_ino]
                manifest={'image':replacement.name,'retained':['old.qcow2'] if retained else [],
                          'generated':{replacement.name:identity}}
                if generated_old:
                    manifest['generated']['old.qcow2']=[-1,-1]
                (root/'manifest.json').write_text(json.dumps(manifest))
                (root/'receipt-test.json').write_text(json.dumps({'retirementCandidate':'old.qcow2'}))
                journal=root/'.retirement.json'
                journal.write_text(json.dumps({'old':'old.qcow2','identity':[-1,-1],
                    'replacement':replacement.name,'replacementIdentity':identity,'receipt':'receipt-test.json'}))
                before={p.name:p.read_bytes() for p in root.iterdir()}
                with self.assertRaisesRegex(ValueError,'still referenced'):
                    runner.recover_retirement(root,manifest)
                self.assertEqual(before,{p.name:p.read_bytes() for p in root.iterdir()})

    def test_retirement_dotdot_refused_before_receipt_or_tools(self):
        for key in ('old','replacement','receipt'):
            with self.subTest(key=key), tempfile.TemporaryDirectory(prefix='opemos-path-') as directory:
                root=Path(directory)
                transaction={'old':'old.qcow2','identity':[-1,-1],
                    'replacement':'replacement.qcow2','receipt':'absent.json'}
                transaction[key]='..'
                journal=root/'.retirement.json'
                journal.write_text(json.dumps(transaction))
                before=journal.read_bytes()
                with patch.object(runner.subprocess,'run') as tools:
                    with self.assertRaisesRegex(ValueError,'unsafe retirement path'):
                        runner.recover_retirement(root,{'image':'replacement.qcow2','retained':[]})
                    tools.assert_not_called()
                self.assertEqual(journal.read_bytes(),before)

    def test_export_limit_failure_preserves_source(self):
        with tempfile.TemporaryDirectory(prefix='opemos-export-limit-') as directory:
            root = Path(directory)
            (root / '.opemos-migration-owned').write_text('OPEMOS.EXE\n')
            source = root / 'source.qcow2'
            subprocess.run(['qemu-img', 'create', '-f', 'qcow2', str(source), '16M'], check=True, capture_output=True)
            original = source.read_bytes()
            with self.assertRaises(subprocess.CalledProcessError):
                runner.compact_owned_image(root, source.name, 'partial.qcow2', export_ceiling=4096)
            self.assertEqual(source.read_bytes(), original)
            partial = root / 'partial.qcow2'
            if partial.exists():
                self.assertLessEqual(partial.stat().st_size, 4096)

    def test_repeated_lifecycle_real_export_and_failed_guest(self):
        with tempfile.TemporaryDirectory(prefix='opemos-lifecycle-') as directory:
            root = Path(directory)
            (root / '.opemos-migration-owned').write_text('OPEMOS.EXE\n')
            image = root / 'source.qcow2'
            subprocess.run(['qemu-img', 'create', '-f', 'qcow2', str(image), '16M'], check=True, capture_output=True)
            subprocess.run(['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x55 0 8M', str(image)], check=True, capture_output=True)
            (root / 'manifest.json').write_text(json.dumps({'schemaVersion': 1, 'image': image.name, 'retained': []}))
            with patch.object(runner, 'launch_bounded', return_value=0) as launch:
                first = runner.run_owned_vm(root)
                second = runner.run_owned_vm(root)
                third = runner.run_owned_vm(root)
                self.assertEqual(launch.call_count, 3)
            self.assertFalse(Path(first['export']).exists())
            self.assertFalse(Path(second['export']).exists())
            self.assertTrue(Path(third['export']).exists())
            self.assertLess(third['totalAfterAllocatedBytes'], 16 * 1024 * 1024)
            final_receipts = [json.loads(path.read_text()) for path in root.glob('receipt-*.json')]
            self.assertTrue(any(record.get('retiredGeneratedImage') == Path(second['export']).name for record in final_receipts))
            self.assertTrue(first['referenceSwitched'])
            self.assertTrue(second['referenceSwitched'])
            self.assertTrue(image.exists())
            manifest = (root / 'manifest.json').read_bytes()
            with patch.object(runner, 'launch_bounded', return_value=1):
                with patch.object(runner, 'recover_retirement', wraps=runner.recover_retirement) as cleanup:
                    with self.assertRaises(RuntimeError):
                        runner.run_owned_vm(root)
                    self.assertEqual(cleanup.call_count, 2)
            self.assertEqual((root / 'manifest.json').read_bytes(), manifest)
            retained = Path(third['export']).stat()
            expected_identity = [retained.st_dev, retained.st_ino]
            failures=[json.loads(path.read_text()) for path in root.glob('receipt-failure-*.json')]
            self.assertEqual(len(failures),1)
            self.assertEqual(failures[0]['status'],'FAILED')
            self.assertTrue(failures[0]['currentImageRetained'])
            self.assertEqual(failures[0]['admittedImageIdentity'], expected_identity)
            self.assertEqual(failures[0]['retainedImageIdentity'], expected_identity)
            self.assertFalse(failures[0]['referenceSwitched'])
            self.assertGreater(failures[0]['totalAfterAllocatedBytes'],0)
            (root / 'unexpected').write_bytes(b'retain')
            with patch.object(runner, 'launch_bounded') as launch:
                with self.assertRaises(ValueError):
                    runner.run_owned_vm(root)
                launch.assert_not_called()

    def test_fixed_closed_launch(self):
        with tempfile.TemporaryDirectory(prefix='opemos-runner-') as directory:
            image = Path(directory) / 'owned.qcow2'
            image.write_bytes(b'fixture')
            with patch('shutil.which', side_effect=lambda name: '/usr/bin/' + name):
                command = runner.launch_command(image)
            self.assertEqual(command.count('--bind'), 1)
            self.assertIn('--unshare-all', command)
            self.assertEqual(command[command.index('--bind') + 1:command.index('--bind') + 3], [str(image), str(image)])
            self.assertEqual(command[command.index('-nic') + 1], 'none')
            with patch('shutil.which', side_effect=lambda name: '/usr/bin/' + name):
                privileged = runner.launch_command(image, memory_mib=30720, cpus=12, privileged_namespace=True)
            self.assertEqual(privileged[:2], ['/usr/bin/sudo', '-n'])
            self.assertIn('--clear-groups', privileged)
            self.assertIn('--no-new-privs', privileged)
            self.assertIn('--unshare-net', privileged)
            self.assertEqual(privileged[privileged.index('-smp') + 1], '12')
            with patch('shutil.which', return_value=None):
                with self.assertRaises(RuntimeError):
                    runner.launch_command(image)
            link = Path(directory) / 'link'
            link.symlink_to(image)
            with self.assertRaises(ValueError):
                runner.launch_command(link)

    def test_virtual_usb_chooser_waits_for_consumed_native_prefix_before_next_key_and_pointer(self):
        spec=importlib.util.spec_from_file_location('native_chooser_sender',
            Path(__file__).resolve().parents[1]/'scripts/omen_control/connection_control.py')
        sender=importlib.util.module_from_spec(spec);spec.loader.exec_module(sender)
        clock=[0.];events=[];committed=[0];queries={}
        p=object.__new__(sender.Pipeline);p.cfg={'input_path':'/ab'};p.end=30;p.app={'pid':731,'window_id':481}
        dialog={'window_id':482,'pid':731,'dialog_type':True,'transient_for':481}
        p.windows=lambda:[dialog]
        def key(code,modifiers=()):
            if code not in('l','a')or not modifiers:
                self.assertEqual(committed[0],len([e for e in events if e[0]=='character']))
                events.append(('character',code))
            clock[0]+=.125
        p.key=key
        def click(action,*args,**kwargs):
            if action=='chooser-confirm-exact-input':self.assertEqual(committed[0],3)
            events.append(('pointer',action))
        p.click=click
        def request(kind,**args):
            self.assertEqual(kind,'CHOOSER_LOCATION');n=args['prefix_length'];queries[n]=queries.get(n,0)+1
            # QMP already ACKed; native GTK consumes this character later.
            if queries[n]>1:committed[0]=n
            return {'value':dict(available=True,readOnlyObservation=True,pid=731,window_id=482,
                requestedPrefixCharacters=n,committedCharacters=committed[0],
                declaredPrefixMatched=committed[0]>=n,exactDeclaredInput=committed[0]==3)}
        p.request=request
        with patch.object(sender.time,'monotonic',side_effect=lambda:clock[0]),patch.object(sender.time,'sleep',side_effect=lambda seconds:clock.__setitem__(0,clock[0]+seconds)):
            p.choose('chooser-open','Choose','/ab','Open')
        self.assertEqual([e[1]for e in events if e[0]=='pointer'],['chooser-open','chooser-confirm-exact-input'])
        self.assertEqual(queries,{1:2,2:2,3:2});self.assertEqual(p.end,30)
        # A late/wrong native value cannot obtain a pointer confirmation or a
        # fresh deadline, despite every preceding keyboard ACK succeeding.
        p.end=clock[0]+.05;p.request=lambda *a,**k:{'value':{'available':False}}
        with patch.object(sender.time,'monotonic',side_effect=lambda:clock[0]),patch.object(sender.time,'sleep',side_effect=lambda seconds:clock.__setitem__(0,clock[0]+seconds)):
            with self.assertRaisesRegex(RuntimeError,'native chooser text not consumed'):
                p.chooser_location(dialog,1)
        self.assertEqual([e[1]for e in events if e[0]=='pointer'].count('chooser-confirm-exact-input'),1)

    def test_virtual_usb_native_chooser_compares_only_declared_nonsecret_focused_location(self):
        spec=importlib.util.spec_from_file_location('native_chooser_observer',
            Path(__file__).resolve().parents[1]/'scripts/omen_control/observer_guest.py')
        observer=importlib.util.module_from_spec(spec);spec.loader.exec_module(observer)
        states={k:k for k in('visible','showing','focused','editable','defunct','screen')}
        declared='/media/source/image.img';reads=[]
        class Node:
            def __init__(self,children=()):
                self.children=list(children);self.pid=731;self.role='entry';self.value=declared
                self.flags={'visible','showing','focused','editable'};self.caret=len(declared);self.selection=None
            def get_process_id(self):return self.pid
            def get_role_name(self):return self.role
            def get_child_count(self):return len(self.children)
            def get_child_at_index(self,i):return self.children[i]
            def get_state_set(self):return SimpleNamespace(contains=lambda flag:flag in self.flags)
            def get_component_iface(self):return SimpleNamespace(get_extents=lambda _:SimpleNamespace(x=10,y=10,width=200,height=30))
            def get_text_iface(self):reads.append('read');return self
            def get_character_count(self):return len(self.value)
            def get_text(self,start,end):return self.value[start:end]
            def get_caret_offset(self):return self.caret
            def get_n_selections(self):return int(self.selection is not None)
            def get_selection(self,_):return SimpleNamespace(start_offset=self.selection[0],end_offset=self.selection[1])
            def set_text_contents(self,*a):raise AssertionError('read-only observer must not edit text')
        entry=Node();app=Node([entry]);app.role='application';app.flags=set();desktop=Node([app])
        window=dict(dialog_type=True,pid=731,window_id=482,rect=[0,0,400,300])
        actual=observer.observed_chooser_location(desktop,window,declared,len(declared),states)
        self.assertTrue(actual['exactDeclaredInput']);self.assertEqual(actual['committedCharacters'],len(declared))
        self.assertNotIn(declared,str(actual));self.assertTrue(actual['readOnlyObservation'])
        entry.selection=(6,len(declared));entry.caret=len(declared)
        actual=observer.observed_chooser_location(desktop,window,declared,7,states)
        self.assertEqual(actual['committedCharacters'],6) # autocomplete is not typed consumption
        entry.value='/other/image.img';entry.caret=len(entry.value);entry.selection=None
        self.assertFalse(observer.observed_chooser_location(desktop,window,declared,len(declared),states)['declaredPrefixMatched'])
        for fault in('password','foreign','hidden','unfocused'):
            entry.role='entry';entry.pid=731;entry.flags={'visible','showing','focused','editable'};reads.clear()
            if fault=='password':entry.role='password text'
            elif fault=='foreign':entry.pid=732
            elif fault=='hidden':entry.flags.remove('showing')
            else:entry.flags.remove('focused')
            self.assertFalse(observer.observed_chooser_location(desktop,window,declared,1,states)['available'])
            self.assertEqual(reads,[])



if __name__ == '__main__':
    unittest.main()

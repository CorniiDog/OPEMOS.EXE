"""Public synthetic FD/failure safety tests; not actual canonical qualification.

The mini producers below are explicit unit operands, never VM acceptance. Run
these project tests only in admitted CI/VM; the private real producer is a
separate REQUIRED command and receipt gate.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

path=Path(__file__).resolve().parents[1]/"scripts/omen_ci_stage.py"
spec=importlib.util.spec_from_file_location("metadata_safety_stage",path)
stage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class SourceProducerInstallationCustody(unittest.TestCase):
    def test_actual_optional_workflow_target_is_in_full_original_custody(self):
        source=Path(__file__).resolve().parents[1]/'scripts/omen_control/install_remote.py'
        spec=importlib.util.spec_from_file_location('source_producer_installer',source)
        installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory)
            with mock.patch.object(installer,'ROOT',root/'root'), \
                 mock.patch.object(installer,'CONFIG',root/'config'), \
                 mock.patch.object(installer,'RUNNER',root/'runner'):
                for enabled in (False,True):
                    payload={'policy':{'sourceBuildEnabled':enabled}}
                    selected=installer.targets(payload)
                    self.assertEqual('producerWorkflow'in selected,enabled)
                    for path in selected.values():
                        path.parent.mkdir(parents=True,exist_ok=True)
                        if not path.exists():path.write_bytes(b'original exact installed bytes')
                    before={name:installer.full(path)for name,path in selected.items()}
                    outcomes={name:'unchanged'for name in selected}
                    result=installer.original_custody(before,dict(before),outcomes,root,payload)
                    self.assertEqual(set(result),set(selected))
                    self.assertTrue(all(item['location']=='original-target'for item in result.values()))
                    if enabled:
                        # A drift in the seventh target must fail just like
                        # drift in the original six, never disappear from custody.
                        selected['producerWorkflow'].write_bytes(b'changed workflow grant')
                        with self.assertRaisesRegex(RuntimeError,'installed target drift producerWorkflow'):
                            installer.original_custody(before,dict(before),outcomes,root,payload)

    def test_normal_create_materializer_uses_same_source_enabled_target_set(self):
        import types
        root=Path(__file__).resolve().parents[1]/'scripts/omen_control'
        def load(name):
            spec=importlib.util.spec_from_file_location('actual_create_'+name,root/(name+'.py'))
            value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
        cycle=load('normal_cycle');installer=(root/'install_remote.py').read_bytes()
        control=b'Root source fixture DATA';hook=b'Root hook fixture DATA'
        sha=lambda data:hashlib.sha256(data).hexdigest()
        for enabled in (False,True):
            template={'kind':'ROOT_REVIEWED_ROBOT_CONTROL_MATERIALIZATION_V1','mainCommit':'a'*40,
                'runnerId':21,'queueSourceSHA256':'b'*64,'queueLoggerSHA256':'c'*64,
                'sources':{'control.py':{'hex':control.hex(),'sha256':sha(control)},
                           'job-started.sh':{'hex':hook.hex(),'sha256':sha(hook)}},
                'policy':{'kind':'ROOT_NORMAL_UBUNTU_GUI_BUILD_WRITE_POLICY_V1','sourceCommit':'a'*40,
                    'queueSourceSHA256':'b'*64,'queueLoggerSHA256':'c'*64,'sourceBuildEnabled':enabled},
                'registry':{'artifacts':{'ubuntu':{}}},'profile':{'fixed_registry':{}}}
            raw=cycle.enc(template)
            policy={'normalTemplateSHA256':sha(raw),'currentReleaseTx':'d'*32,
                'normalInstallerSHA256':sha(installer),'mainCommit':'a'*40,'queueSourceSHA256':'b'*64,
                'queueLoggerSHA256':'c'*64,'controlBrokerSHA256':sha(control),'jobStartedSHA256':sha(hook)}
            probe=types.SimpleNamespace(pin_source=lambda *args:(installer,{}))
            # Source custody and predecessor/process facts are modeled here;
            # actual production materialize() and targets() build the payload.
            with mock.patch.object(cycle,'REMOTE_TEMPLATE_HEX',raw.hex(),create=True), \
                 mock.patch.object(cycle,'closed_receipt',return_value={'MODELED_CLOSED_PREDECESSOR':True}):
                payload,actual_installer=cycle.materialize(policy,probe,'e'*32,{'unit':'opemos-testq-aa-bb.service'}, {})
            result=json.loads(payload)
            self.assertEqual(set(result['prior']),set(actual_installer.targets(result)))
            self.assertEqual('producerWorkflow'in result['prior'],enabled)
            self.assertEqual(result['transaction'],'e'*32)

    def test_remote_create_failure_preserves_actual_stderr_in_existing_wrapper_capture(self):
        import io,types,subprocess
        source=Path(__file__).resolve().parents[1]/'scripts/omen_control/controller_cycle.py'
        spec=importlib.util.spec_from_file_location('actual_remote_effect_capture',source)
        cycle=importlib.util.module_from_spec(spec);spec.loader.exec_module(cycle)
        for raw in (b"KeyError: 'producerWorkflow'\n",b'x'*70000+b'actual final failure'):
            stream=io.BytesIO();child=subprocess.CompletedProcess(['modeled SSH'],1,b'',raw)
            with mock.patch.object(cycle.sys,'stderr',types.SimpleNamespace(buffer=stream)):
                with self.assertRaisesRegex(RuntimeError,'finite remote ordinary effect; numeric=1'):
                    cycle.require_remote_effect(child)
            self.assertEqual(stream.getvalue(),raw[-65536:])
        cycle.require_remote_effect(subprocess.CompletedProcess(['modeled SSH'],0,b'{}\n',b''))


class OwnedNBDDisconnect(unittest.TestCase):
    """Real owned PID/pidfd exit, with device/sysfs operations modeled."""
    def setUp(self):
        import sys
        source=Path(__file__).resolve().parents[1]/'scripts/omen_control/provision_observer_rule.py'
        sys.path.insert(0,str(source.parent));previous=os.umask(0o077)
        try:
            spec=importlib.util.spec_from_file_location('owned_nbd_disconnect_fixture',source)
            self.helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.helper)
        finally:os.umask(previous);sys.path.pop(0)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.sysfs=Path(self.temp.name);self.before_fd=set(os.listdir('/proc/self/fd'))

    def child(self):
        import subprocess,sys
        p=subprocess.Popen([sys.executable,'-I','-B','-c','import os; os.read(0,1)'],
                           stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        path=Path('/proc')/str(p.pid)
        owner={'pid':p.pid,'start_ticks':(path/'stat').read_text().rsplit(')',1)[1].split()[19],
               'argv':[os.fsdecode(x)for x in(path/'cmdline').read_bytes().split(b'\0')if x]}
        (self.sysfs/'pid').write_text(str(p.pid))
        def close():
            if p.poll()is None:p.communicate(b'x',timeout=5)
            elif p.stdin and not p.stdin.closed:p.stdin.close()
        self.addCleanup(close)
        return p,owner

    def test_sysfs_clears_before_original_daemon_exits_and_is_reaped(self):
        import threading,time
        p,owner=self.child();h=self.helper;exits=[];threads=[];calls=[]
        def disconnect(argv,**kwargs):
            calls.append(argv);(self.sysfs/'pid').unlink()
            # The kernel association has gone; the SAME real child is still
            # alive. This reproduced the old immediate /proc failure.
            self.assertIsNone(p.poll())
            def finish():time.sleep(.3);p.communicate(b'x',timeout=5);exits.append(p.returncode)
            thread=threading.Thread(target=finish);thread.start();threads.append(thread)
            return {'numeric':0}
        with mock.patch.object(h,'SYS',self.sysfs),mock.patch.object(h,'cmd',side_effect=disconnect), \
             mock.patch.object(h,'idle',return_value={'holders_empty':True,'mounts_empty':True,'sysfs_pid_absent':True})as idle:
            started=time.monotonic();result=h.detach(owner);elapsed=time.monotonic()-started
        for thread in threads:thread.join(timeout=5);self.assertFalse(thread.is_alive())
        self.assertEqual(exits,[0]);self.assertGreaterEqual(elapsed,.25)
        self.assertTrue(result['pid_absent']);self.assertTrue(result['original_pidfd_exited'])
        self.assertEqual(calls,[['/usr/bin/sudo','-n','/usr/bin/qemu-nbd','--disconnect',h.NODE]])
        idle.assert_called_once();self.assertFalse((Path('/proc')/str(p.pid)).exists())
        self.assertEqual(set(os.listdir('/proc/self/fd')),self.before_fd)

    def test_changed_birth_refuses_before_disconnect_and_original_deadline_never_extends(self):
        import types
        p,owner=self.child();h=self.helper
        with mock.patch.object(h,'SYS',self.sysfs),mock.patch.object(h,'cmd')as command:
            with self.assertRaisesRegex(RuntimeError,'birth/argv changed'):
                h.detach(dict(owner,start_ticks=str(int(owner['start_ticks'])+1)))
            command.assert_not_called()
        ticks=iter([0.,10.01])
        clock=types.SimpleNamespace(monotonic=lambda:next(ticks),sleep=lambda seconds:self.fail('expired operation must not sleep'))
        def disconnected(*args,**kwargs):(self.sysfs/'pid').unlink();return {'numeric':0}
        with mock.patch.object(h,'SYS',self.sysfs),mock.patch.object(h,'time',clock), \
             mock.patch.object(h,'cmd',side_effect=disconnected)as command,mock.patch.object(h,'idle')as idle:
            with self.assertRaisesRegex(RuntimeError,'closure observation deadline expired'):h.detach(owner)
            command.assert_called_once();idle.assert_not_called()
        self.assertIsNone(p.poll()) # refusal did not signal/kill the owned child
        p.communicate(b'x',timeout=5);self.assertEqual(p.returncode,0)
        self.assertEqual(set(os.listdir('/proc/self/fd')),self.before_fd)


class UbuntuOwnedUnixSockets(unittest.TestCase):
    """Actual Linux sockets at a future normal operation path over108 bytes."""
    def setUp(self):
        for role in ('connection_control','job'):
            source=Path(__file__).resolve().parents[1]/'scripts/omen_control'/(role+'.py')
            spec=importlib.util.spec_from_file_location('long_socket_'+role,source)
            module=importlib.util.module_from_spec(spec)
            # job.py deliberately sets the production process umask. Loading
            # it as a fixture must not change later tests' ambient file modes.
            previous=os.umask(0o077)
            try:spec.loader.exec_module(module)
            finally:os.umask(previous)
            setattr(self,role,module)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/('future-owned-operation-'+'a'*64)/('runtime-'+'b'*64)
        self.root.mkdir(parents=True);self.root.chmod(0o700)
        self.assertGreater(len(os.fsencode(self.root/'observer.sock')),108)

    def test_long_logical_paths_connect_all_three_socket_roles_with_real_peer_and_qmp(self):
        import subprocess,sys
        program="""import os,socket,sys,json,selectors
os.umask(0o077)
sel=selectors.DefaultSelector();servers=[]
for name in ('qmp.sock','vnc.sock','observer.sock'):
 s=socket.socket(socket.AF_UNIX);s.bind(name);s.listen(1);servers.append(s);sel.register(s,selectors.EVENT_READ,name)
print('READY',flush=True)
for _ in range(3):
 key=sel.select(5)[0][0];c,_=key.fileobj.accept();sel.unregister(key.fileobj)
 with c:
  if key.data=='qmp.sock':
   c.sendall(b'{"QMP":{}}\\n');f=c.makefile('rb')
   for response in ({},{'name':'same-owned-VM'}):
    request=json.loads(f.readline());c.sendall((json.dumps({'return':response,'id':request['id']})+'\\n').encode())
   f.close()
  else:c.sendall(key.data.encode())
for s in servers:s.close()
sel.close()
"""
        directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        child=None
        try:
            child=subprocess.Popen([sys.executable,'-I','-B','-c',program],
                cwd=f'/proc/self/fd/{directory}',pass_fds=(directory,),
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.assertEqual(child.stdout.readline(),b'READY\n')
            q=self.job.qmp_connect(self.root/'qmp.sock',child.pid,self.connection_control.connect_owned,child)
            try:self.assertEqual(self.job.qmp_call(q,2,'query-name'),{'name':'same-owned-VM'})
            finally:self.job.QMP_BUFFERS.pop(q.fileno(),None);q.close()
            for name in ('vnc.sock','observer.sock'):
                with self.connection_control.connect_owned(self.root/name,child.pid)as sock:
                    self.assertEqual(sock.recv(64),name.encode())
            out,err=child.communicate(timeout=5)
            self.assertEqual((child.returncode,out,err),(0,b'',b''))
            self.assertEqual(os.fstat(directory).st_ino,self.root.lstat().st_ino)
        finally:
            if child is not None:
                if child.poll()is None:child.kill()
                child.communicate(timeout=5)
            os.close(directory)

    def test_ready_failure_and_bad_greeting_release_qmp_before_normal_finalizer(self):
        import subprocess,sys
        program="""import os,socket,json
os.umask(0o077)
s=socket.socket(socket.AF_UNIX);s.bind('qmp.sock');s.listen(1);s.settimeout(5)
print('READY',flush=True)
for attempt in range(3):
 c,_=s.accept();c.settimeout(3)
 with c:
  with c.makefile('rb')as f:
   c.sendall((b'{}\\n'if attempt==0 else b'{"QMP":{}}\\n'))
   if attempt:
    request=json.loads(f.readline());c.sendall((json.dumps({'return':{},'id':request['id']})+'\\n').encode())
   if attempt==2:
    request=json.loads(f.readline());c.sendall((json.dumps({'return':{'name':'original-owned-VM'},'id':request['id']})+'\\n').encode())
   assert f.read(1)==b'', 'previous QMP client must close before next finalizer client'
s.close()
"""
        directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        child=None
        try:
            child=subprocess.Popen([sys.executable,'-I','-B','-c',program],
                cwd=f'/proc/self/fd/{directory}',pass_fds=(directory,),
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.assertEqual(child.stdout.readline(),b'READY\n')
            with self.assertRaisesRegex(RuntimeError,'QMP greeting absent'):
                with self.connection_control.owned_qmp(self.root/'qmp.sock',child.pid):
                    self.fail('bad greeting must refuse')
            with self.assertRaisesRegex(TimeoutError,'original observer READY failure'):
                with self.connection_control.owned_qmp(self.root/'qmp.sock',child.pid):
                    raise TimeoutError('original observer READY failure')
            with self.connection_control.owned_qmp(self.root/'qmp.sock',child.pid)as finalizer:
                self.assertEqual(finalizer.call('query-name'),{'name':'original-owned-VM'})
            out,err=child.communicate(timeout=5)
            self.assertEqual((child.returncode,out,err),(0,b'',b''))
        finally:
            if child is not None:
                if child.poll()is None:child.kill()
                child.communicate(timeout=5)
            os.close(directory)

    def test_generated_pipeline_bootstrap_preserves_real_failure_and_bounded_guest_logs(self):
        import base64,subprocess
        source=Path(__file__).resolve().parents[1]/'scripts/omen_control/prepare_observer_iso.py'
        spec=importlib.util.spec_from_file_location('generated_bootstrap',source)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        nonce='a'*32;digest='b'*64;commit='c'*40
        operation={'nonce':nonce,'source_commit':commit,'package_sha256':digest,
                   'usb_serial':'opemos-'+nonce,'native_executable_sha256':'d'*64,'display':[1600,900]}
        descriptor={'source_commit':commit,'package_sha256':digest,'executable_sha256':'d'*64}
        config={'nonce':nonce,'source_commit':commit,'candidate':{'descriptor':descriptor,'archive':{}},
                'prepared_directory':str(self.root/'prepared'),'guest_operation':operation,
                'observer_source':{},'expanded_limit':4096}
        def iso(argv,**kwargs):
            Path(argv[argv.index('-o')+1]).write_bytes(b'unit-medium-only')
            return subprocess.CompletedProcess(argv,0,b'',b'')
        with mock.patch.object(module,'extract_candidate',return_value={'package':{'name':'app.AppImage'}}),\
             mock.patch.object(module,'held_input',return_value=b'# exact observer fixture'),\
             mock.patch.object(module.subprocess,'run',side_effect=iso):
            module.pipeline_medium(config)
        script=(self.root/'prepared/start.sh').read_text()
        trap=script[script.index('on_exit() {'):script.index('node=$(readlink')]
        logs=self.root/'guest-logs';logs.mkdir(mode=0o700)
        app=b'original app failure with quotes \" and newline\n'*300
        observer=b'actual native window absent\n'
        (logs/'app.log').write_bytes(app);(logs/'observer.log').write_bytes(observer)
        port=self.root/'typed-port';port.write_bytes(b'')
        run=subprocess.run(['/bin/bash','-c',
             'set -euo pipefail\nowned=$1;node=$2;nonce=$3;phase=native_app_and_observer;port_ready=1\n'+trap+'exit 7\n',
             'generated-bootstrap',str(logs),str(port),nonce],capture_output=True,timeout=5)
        self.assertEqual(run.returncode,7)
        actual=json.loads(port.read_bytes())
        self.assertEqual((actual['kind'],actual['nonce'],actual['phase'],actual['numeric']),
                         ('BOOTSTRAP_REFUSED',nonce,'native_app_and_observer',7))
        self.assertEqual(base64.b64decode(actual['app_log_base64']),app[-8192:])
        self.assertEqual(base64.b64decode(actual['observer_log_base64']),observer)
        self.assertLess(port.stat().st_size,65536)

    def test_private_socket_custody_and_exact_peer_remain_required(self):
        import socket
        path=self.root/'qmp.sock';server=socket.socket(socket.AF_UNIX)
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        old=os.umask(0o077)
        try:
            server.bind(f'/proc/self/fd/{fd}/qmp.sock');server.listen(3)
            with self.assertRaisesRegex(RuntimeError,'exact QEMU'):
                self.connection_control.connect_owned(path,os.getpid()+100000)
            self.root.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError,'private VM socket directory'):
                self.connection_control.connect_owned(path,os.getpid())
            self.root.chmod(0o700);path.rename(self.root/'original.sock');path.symlink_to(self.root/'original.sock')
            with self.assertRaisesRegex(RuntimeError,'private VM socket required'):
                self.connection_control.connect_owned(path,os.getpid())
        finally:os.umask(old);os.close(fd);server.close()

    def test_known_child_exit_is_first_before_twenty_second_qmp_wait(self):
        import subprocess,sys,time
        child=subprocess.Popen([sys.executable,'-I','-B','-c',
            'import sys;sys.stderr.write("original startup failure\\n");sys.exit(7)'],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out,err=child.communicate(timeout=5);self.assertEqual(child.returncode,7)
        started=time.monotonic()
        with self.assertRaisesRegex(RuntimeError,'QEMU exited before QMP startup: numeric 7'):
            self.job.qmp_connect(self.root/'qmp.sock',child.pid,self.connection_control.connect_owned,child)
        self.assertLess(time.monotonic()-started,1)
        self.assertEqual((out,err),(b'',b'original startup failure\n'))


class LosslessHistoryRepack(unittest.TestCase):
    """Real owned files/exchange/readback; no canonical-job acceptance claim."""
    def setUp(self):
        source=Path(__file__).resolve().parents[1]/'scripts/omen_control/test_queue.py'
        spec=importlib.util.spec_from_file_location('history_repack_queue',source)
        self.q=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.q)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700);self.uid=os.getuid()

    def publish(self,label):
        raw=(self.q.canonical({'id':label,'originalUnknown':'preserved','payload':label*131072})+'\n').encode()
        with self.q.history_directory(self.root,self.uid,True)as fd:
            pin=self.q.history_publish(fd,raw,'row',self.uid)
        return pin,raw

    def gate(self,pins):
        with self.q.history_directory(self.root,self.uid)as fd:
            allocated,count=self.q.history_inventory(fd,self.uid)
            self.assertEqual(count,len(pins)+1)
            return {'offlineQueueAndWorkerClosed':True,
                    'sourceDirectoryIdentity':self.q.history_identity(os.fstat(fd)),
                    'sourcePinsSHA256':hashlib.sha256(self.q.canonical(sorted(pins,key=lambda p:p['name'])).encode()).hexdigest(),
                    'sourceAllocatedBytes':allocated,'sourceLeafCount':len(pins)}

    def test_actual_ancestor_sibling_linkcount_changes_do_not_change_held_identity(self):
        q=self.q;parent=self.root/'owned-parent';parent.mkdir(mode=0o700)
        state=parent/'state';state.mkdir(mode=0o700)
        before=parent.stat();pin=None
        with q.history_directory(state,self.uid,True)as fd:
            pin=q.history_publish(fd,b'{"original":"retained"}\n','row',self.uid)
            (parent/'genuine-new-sibling').mkdir(mode=0o700)
            self.assertEqual(parent.stat().st_ino,before.st_ino)
            self.assertEqual(parent.stat().st_nlink,before.st_nlink+1)
        with q.history_directory(state,self.uid)as fd:
            self.assertEqual(q.history_read_leaf(fd,pin,self.uid,q.HISTORY_FILE_MAX),b'{"original":"retained"}\n')
        # Nofollow held/named inode identity is still strict: renaming the
        # parent and substituting another directory cannot pass on linkcount.
        with self.assertRaises(ValueError):
            with q.history_directory(state,self.uid):
                parent.rename(self.root/'original-parent-retained')
                parent.mkdir(mode=0o700)

    def test_existing_archive_and_new_live_leaves_repack_without_losing_original_pins(self):
        original,first=self.publish('old')
        q=self.q;limits=(q.HISTORY_FILE_MAX,q.HISTORY_METADATA_MAX,q.HISTORY_NAMESPACE_MAX,q.HISTORY_ENTRY_MAX,q.HISTORY_ARCHIVE_STAGE_MAX)
        q.history_archive_migrate(self.root,self.uid,'terminal-history-rollback-first',self.gate([original]))
        new,second=self.publish('new');pins=[original,new];gate=self.gate(pins)
        result=q.history_archive_migrate(self.root,self.uid,'terminal-history-rollback-second',gate)
        self.assertTrue(result['rollbackPreserved']);self.assertEqual(result['originalLeafCount'],2)
        self.assertLess(result['activeAllocatedBytes'],gate['sourceAllocatedBytes'])
        self.assertEqual(limits,(q.HISTORY_FILE_MAX,q.HISTORY_METADATA_MAX,q.HISTORY_NAMESPACE_MAX,q.HISTORY_ENTRY_MAX,q.HISTORY_ARCHIVE_STAGE_MAX))
        rootfd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:all_retained=q.history_retained_allocation(rootfd,self.uid)
        finally:os.close(rootfd)
        self.assertEqual(result['allRetainedAllocatedBytes'],all_retained)
        self.assertGreater(all_retained,result['activePlusRollbackBytes'])
        # The FIRST rollback is still physically charged after a second
        # exchange. It cannot disappear from the budget because it is older.
        with mock.patch.object(q,'HISTORY_ARCHIVE_STAGE_MAX',result['activePlusRollbackBytes']):
            with self.assertRaisesRegex(ValueError,'All retained history generations'):
                q.history_archive_migrate(self.root,self.uid,'terminal-history-rollback-third',self.gate(pins))
        self.assertFalse((self.root/'terminal-history-rollback-third').exists())
        with q.history_directory(self.root,self.uid)as fd:
            self.assertEqual(set(os.listdir(fd)),{q.HISTORY_ARCHIVE_INDEX,q.HISTORY_ARCHIVE_DATA})
            archive=q.history_archive_index(fd,self.uid)
            self.assertEqual({n:v['pin']for n,v in archive[0].items()},{p['name']:p for p in pins})
            for pin,raw in ((original,first),(new,second)):
                # Legacy four-argument consumer contract stays valid.
                self.assertEqual(q.history_read_leaf(fd,pin,self.uid,q.HISTORY_FILE_MAX),raw)
        rollback=os.open(self.root/'terminal-history-rollback-second',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            for pin,raw in ((original,first),(new,second)):
                self.assertEqual(q.history_read_leaf(rollback,pin,self.uid,q.HISTORY_FILE_MAX),raw)
        finally:os.close(rollback)

    def test_complete_originals_over_64MiB_use_compact_closed_epoch_without_sql_edits(self):
        import sqlite3
        q=self.q;rows=[];pins=[];expected={}
        payload='x'*(22*1024**2)
        for i in range(3):
            row={'id':'closed-'+str(i),'unit':'original-'+str(i)+'.service','state':'failed',
                 'spec':'original complete spec','cpus':'[0]','finished':i+1,
                 'result':q.canonical({'terminalLifecycle':{'phase':'CLOSED','reservationRetained':False},
                                      'originalUnknown':'preserved','payload':payload+str(i)})}
            raw=(q.canonical(row)+'\n').encode();rows.append(row)
            with q.history_directory(self.root,self.uid,True)as fd:
                pin=q.history_publish(fd,raw,'row',self.uid)
            pins.append(pin);expected[pin['name']]=hashlib.sha256(raw).hexdigest()
            if i==1:
                q.history_archive_migrate(self.root,self.uid,'terminal-history-rollback-large',self.gate(pins))
        owned={'id':'current','unit':'current.service','state':'running','result':None}
        epoch={'rows':rows+[owned],'pool':{'original':'all pool fields'},'bindings':[],'config':[]}
        self.assertGreater(len((q.canonical(epoch)+'\n').encode()),q.HISTORY_FILE_MAX)
        db=sqlite3.connect(self.root/'queue.sqlite3')
        try:
            db.execute('CREATE TABLE originals (id TEXT PRIMARY KEY, value TEXT)')
            for row in rows:db.execute('INSERT INTO originals VALUES (?,?)',(row['id'],q.canonical(row)))
            db.commit();before=list(db.execute('SELECT * FROM originals ORDER BY id'));changes=db.total_changes
            db.execute('BEGIN IMMEDIATE')
            ref=q.terminal_history_store(db,epoch,owned,'a'*32);db.commit()
            self.assertEqual(ref['kind'],q.HISTORY_COMPACT_KIND)
            self.assertLess(ref['epochBytes'],4096)
            actual=q.terminal_history_resolve(self.root,self.uid,ref,owned['id'],owned['unit'],'a'*32)
            self.assertEqual(actual['rows'],[q.terminal_closed_row(r)for r in rows]+[owned])
            self.assertEqual((db.total_changes,list(db.execute('SELECT * FROM originals ORDER BY id'))),(changes,before))
            with q.history_directory(self.root,self.uid)as fd:
                for pin in pins:
                    raw=q.history_read_leaf(fd,pin,self.uid,q.HISTORY_FILE_MAX)
                    self.assertEqual(hashlib.sha256(raw).hexdigest(),expected[pin['name']])
            changed=dict(rows[0],result=rows[0]['result']+' ')
            self.assertNotEqual(q.terminal_closed_row(changed),actual['rows'][0])
            with self.assertRaisesRegex(ValueError,'reference context'):
                q.terminal_history_resolve(self.root,self.uid,dict(ref,epochBytes=q.HISTORY_FILE_MAX+1),owned['id'],owned['unit'],'a'*32)
        finally:db.close()

    def test_complete_assignment_producer_and_reader_preserve_over64MiB_originals(self):
        import sqlite3
        q=self.q;db=sqlite3.connect(self.root/'queue.sqlite3');db.row_factory=sqlite3.Row
        db.executescript('CREATE TABLE jobs(id TEXT,unit TEXT,state TEXT,spec TEXT,cpus TEXT,finished REAL,result TEXT);'
                         'CREATE TABLE pool_unit_bindings(job_id TEXT,value TEXT);CREATE TABLE config(id INTEGER,value TEXT);')
        rows=[];pins=[];payload='x'*(22*1024**2)
        try:
            for i in range(3):
                row={'id':'original-'+str(i),'unit':'original-'+str(i)+'.service','state':'failed','spec':'exact-original',
                     'cpus':'[0]','finished':i+1,'result':q.canonical({'terminalLifecycle':{'phase':'CLOSED','reservationRetained':False},'originalUnknown':'preserved','payload':payload+str(i)})}
                rows.append(row);db.execute('INSERT INTO jobs VALUES(:id,:unit,:state,:spec,:cpus,:finished,:result)',row)
                enriched=dict(row,_poolBinding=None)
                with q.history_directory(self.root,self.uid,True)as fd:
                    pins.append(q.history_publish(fd,(q.canonical(enriched)+'\n').encode(),'row',self.uid))
            q.history_archive_migrate(self.root,self.uid,'terminal-history-rollback-assignment-large',self.gate(pins))
            own={'id':'current','unit':'current.service','state':'running','spec':'exact-current','cpus':'[1]','finished':None,'result':None}
            bound={'version':1,'invocation':'a'*32};db.execute('INSERT INTO jobs VALUES(:id,:unit,:state,:spec,:cpus,:finished,:result)',own)
            db.execute('INSERT INTO pool_unit_bindings VALUES(?,?)',(own['id'],q.canonical(bound)));db.execute('INSERT INTO config VALUES(1,?)',('{}',));db.commit()
            before=q.diagnostic_ledger(db);changes=db.total_changes
            # Immutable VM request derivation is unchanged and separately
            # exercised by the existing installed Root fixture. This codec test
            # models that operand only, never a VM or privileged approval.
            request={'jobId':own['id'],'modeledImmutableRequest':True}
            with mock.patch.object(q,'libvirt_request',return_value=request):
                pin=q.publish_libvirt_assignment(db,dict(own,_poolBinding=bound),bound)
                with q.libvirt_export_directory(self.root,self.uid)as fd:
                    header,_=q.libvirt_assignment_read_header(fd,own['id']+'.json',self.uid)
                self.assertGreater(header['canonicalBytes'],64*1024**2)
                self.assertLessEqual(header['canonicalBytes'],q.HISTORY_ASSIGNMENT_MAX)
                value,evidence=q.read_libvirt_assignment_export(self.root,own['id'],header['producer'],header['source'],header['bootID'])
                self.assertEqual(value,before);self.assertEqual(evidence['canonicalSHA256'],header['canonicalSHA256'])
                self.assertEqual((db.total_changes,q.diagnostic_ledger(db)),(changes,before))
                with self.assertRaisesRegex(ValueError,'worker/source/boot'):
                    q.read_libvirt_assignment_export(self.root,own['id'],header['producer'],dict(header['source'],sha256='0'*64),header['bootID'])
                archive=self.root/q.HISTORY_DIRECTORY/q.HISTORY_ARCHIVE_DATA
                archive.chmod(0o600)
                with archive.open('r+b')as stream:
                    first=stream.read(1);stream.seek(0);stream.write(bytes([first[0]^1]));stream.flush();os.fsync(stream.fileno())
                archive.chmod(0o400)
                with self.assertRaises(ValueError):
                    q.read_libvirt_assignment_export(self.root,own['id'],header['producer'],header['source'],header['bootID'])
        finally:db.close()

    def test_archived_logical_rows_do_not_consume_physical_entry_slots(self):
        import sqlite3
        q=self.q;rows=[];pins=[]
        # Grow across two real generations so every retained physical
        # namespace also remains under the scaled eight-entry fixture bound.
        for first in (0,5):
            with q.history_directory(self.root,self.uid,True)as fd:
                for i in range(first,first+5):
                    row={'id':'archived-'+str(i),'unit':'original-'+str(i)+'.service',
                         'state':'failed','spec':'exact-original','cpus':'[0]',
                         'result':q.canonical({'terminalLifecycle':{'phase':'CLOSED','reservationRetained':False}})}
                    rows.append(row);pins.append(q.history_publish(fd,(q.canonical(row)+'\n').encode(),'row',self.uid))
            q.history_archive_migrate(self.root,self.uid,'terminal-history-rollback-logical-'+str(first),self.gate(pins))
        with q.history_directory(self.root,self.uid)as fd:
            self.assertEqual(set(os.listdir(fd)),{q.HISTORY_ARCHIVE_INDEX,q.HISTORY_ARCHIVE_DATA})
        db=sqlite3.connect(self.root/'queue.sqlite3')
        try:
            own={'id':'new-current','unit':'new-current.service','state':'running','spec':'exact-current','cpus':'[1]','result':None}
            epoch={'rows':rows+[own],'pool':{'modeled':True},'bindings':[],'config':[]}
            db.execute('BEGIN IMMEDIATE')
            # Scale only the entry-count fixture bound: ten real archived
            # originals exceed eight slots, yet their actual two files plus
            # current row/manifest occupy four. The old logical-slot bug still
            # fails; thousands of redundant durable fsyncs add no coverage.
            self.assertGreater(len(rows),8)
            with mock.patch.object(q,'HISTORY_ENTRY_MAX',8),mock.patch.object(q,'terminal_history_maintain',side_effect=AssertionError('no physical capacity pressure')):
                written={};read={}
                ref=q.terminal_history_store(db,epoch,own,'a'*32,metrics=written)
                db.commit()
                actual=q.terminal_history_resolve(self.root,self.uid,ref,own['id'],own['unit'],'a'*32,metrics=read)
                for metrics in (written,read):
                    self.assertEqual(metrics['archivePairAuthentications'],1)
                    self.assertGreaterEqual(metrics['archiveLeafReads'],len(rows))
                    self.assertTrue(metrics['archiveDescriptorsClosed']);self.assertTrue(metrics['archiveAfterGuardPassed'])
            self.assertEqual(actual['rows'],[q.terminal_closed_row(r)for r in rows]+[own])
            with q.history_directory(self.root,self.uid)as fd:
                self.assertEqual(len(os.listdir(fd)),4) # two archive files, current row, manifest
                for i in range(5):q.history_publish(fd,q.canonical({'additionalPhysicalLeaf':i}).encode(),'row',self.uid)
                with mock.patch.object(q,'HISTORY_ENTRY_MAX',8),self.assertRaisesRegex(ValueError,'Finite history entry count'):
                    q.history_inventory(fd,self.uid)
        finally:db.close()

    def test_real_bulk_archive_roundtrip_authenticates_pair_per_operation_not_per_original(self):
        import sqlite3
        q=self.q;rows=[];pins=[]
        with q.history_directory(self.root,self.uid,True)as fd:
            for i in range(512):
                row={'id':'bulk-'+str(i),'unit':'original.service','state':'failed',
                     'spec':'exact-original','result':q.canonical({'terminalLifecycle':{'phase':'CLOSED','reservationRetained':False},'payload':'x'*2048})}
                rows.append(row);pins.append(q.history_publish(fd,(q.canonical(row)+'\n').encode(),'row',self.uid))
        with mock.patch.object(q,'history_archive_parse',wraps=q.history_archive_parse)as parsed:
            q.history_archive_migrate(self.root,self.uid,'terminal-history-rollback-bulk',self.gate(pins))
        self.assertLess(parsed.call_count,20) # all creator readback passes, not 2N opens/parses
        db=sqlite3.connect(self.root/'queue.sqlite3')
        try:
            own={'id':'current','unit':'current.service','state':'running','result':None}
            epoch={'rows':rows+[own],'pool':{'modeled':True},'bindings':[],'config':[]};db.execute('BEGIN IMMEDIATE')
            written={};read={};ref=q.terminal_history_store(db,epoch,own,'a'*32,metrics=written);db.commit()
            actual=q.terminal_history_resolve(self.root,self.uid,ref,own['id'],own['unit'],'a'*32,metrics=read)
            self.assertEqual(actual['rows'],[q.terminal_closed_row(row)for row in rows]+[own])
            for metrics in (written,read):
                self.assertEqual(metrics['archivePairAuthentications'],1);self.assertGreaterEqual(metrics['archiveLeafReads'],len(rows))
                self.assertTrue(metrics['archiveAfterGuardPassed']);self.assertTrue(metrics['archiveDescriptorsClosed'])
        finally:db.close()

    def test_closed_reference_compares_every_original_byte_at_normal_terminal_boundary(self):
        q=self.q;unit='owned.service'
        closed={'id':'old','unit':'old.service','state':'failed','spec':'exact original spec','cpus':'[0]',
                'result':q.canonical({'terminalLifecycle':{'phase':'CLOSED','reservationRetained':False}})}
        running={'id':'current','unit':unit,'state':'running','result':None,'spec':'current','cpus':'[1]'}
        pending=dict(running,state='terminal_cleanup',result='retained original pending result')
        pool={'admitted':True,'includesUID0':True,'completeBoundedTraversal':True,'allOwnedDescriptorsClosed':True,
              'canonicalPool':'/modeled-pool','systemdPoolProperties':{},'unitProperties':{unit:{}},
              'unknownReservationsRetained':[],'knownInvocations':{unit:'a'*32},'positiveMainPIDProofs':{},
              'tasks':[],'rootParentCustody':[('/modeled-pool',[1,2,0o40755,0,0,2,3,4])]}
        before={'rows':[q.terminal_closed_row(closed),running],'pool':copy.deepcopy(pool),'bindings':[],'config':[]}
        after={'rows':[closed,pending],'pool':copy.deepcopy(pool),'bindings':[],'config':[]}
        self.assertEqual(q.verify_terminal_pool_transition(before,after,pending,False)['otherRowsPreserved'],1)
        queued={'id':'next-normal-job','state':'pending','unit':None,'started':None,'finished':None,
                'result':None,'cpus':None,'_poolBinding':None,'spec':'retained queued source operands'}
        appended=copy.deepcopy(after);appended['rows'].append(queued)
        self.assertEqual(q.verify_terminal_pool_transition(before,appended,pending,False)['otherRowsPreserved'],1)
        self.assertEqual(appended['rows'][-1],queued)
        for key,value in [('state','running'),('unit','new.service'),('started',1),('finished',2),
                          ('result','changed'),('cpus','[2]'),('_poolBinding',{})]:
            wrong=copy.deepcopy(appended);wrong['rows'][-1][key]=value
            expected=('New appended job must never have allocated a unit or resource'
                if key in('unit','started','cpus','_poolBinding')else
                'Only new unallocated pending or normally CLOSED never-started metadata')
            with self.subTest(newPending=key),self.assertRaisesRegex(ValueError,expected):
                q.verify_terminal_pool_transition(before,wrong,pending,False)
        duplicate=copy.deepcopy(appended);duplicate['rows'][-1]['id']=closed['id']
        with self.assertRaisesRegex(ValueError,'Full ordered original history'):
            q.verify_terminal_pool_transition(before,duplicate,pending,False)
        for key,value in [('spec','changed'),('cpus','[4]'),('result',closed['result']+' '),('unit','foreign.service')]:
            changed=copy.deepcopy(after);changed['rows'][0][key]=value
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'Other full job'):
                q.verify_terminal_pool_transition(before,changed,pending,False)

    def test_normal_terminal_writer_repackages_before_headroom_failure_without_sql_changes(self):
        import sqlite3
        q=self.q;rows=[];pins=[]
        # Scaled operation storage bounds keep this a small real-file test;
        # all production writer/fence/archive/readback code is executed.
        with mock.patch.object(q,'HISTORY_NAMESPACE_MAX',512*1024), \
             mock.patch.object(q,'HISTORY_METADATA_MAX',64*1024), \
             mock.patch.object(q,'HISTORY_ARCHIVE_STAGE_MAX',2*1024**2):
            for i in range(3):
                row={'id':'prior-'+str(i),'unit':'prior-'+str(i)+'.service','state':'failed',
                     'result':q.canonical({'terminalLifecycle':{'phase':'CLOSED','reservationRetained':False},
                                          'payload':str(i)*96*1024})}
                raw=(q.canonical(row)+'\n').encode();rows.append(row)
                with q.history_directory(self.root,self.uid,True)as fd:pins.append(q.history_publish(fd,raw,'row',self.uid))
            own={'id':'current','unit':'current.service','state':'running','result':'x'*(96*1024)}
            epoch={'rows':rows+[own],'pool':{},'bindings':[],'config':[]}
            db=sqlite3.connect(self.root/'queue.sqlite3');db.row_factory=sqlite3.Row
            try:
                db.execute('CREATE TABLE jobs (id TEXT PRIMARY KEY, unit TEXT, state TEXT, result TEXT)')
                db.execute('CREATE TABLE pool_unit_bindings (job_id TEXT PRIMARY KEY, value TEXT)')
                for r in rows+[own]:db.execute('INSERT INTO jobs VALUES (?,?,?,?)',tuple(r[k]for k in ('id','unit','state','result')))
                db.execute('INSERT INTO pool_unit_bindings VALUES (?,?)',(own['id'],q.canonical({'invocation':'a'*32})))
                db.commit();before=[tuple(r)for r in db.execute('SELECT * FROM jobs')];changes=db.total_changes
                db.execute('BEGIN IMMEDIATE');ref=q.terminal_history_store(db,epoch,own,'a'*32);db.commit()
                self.assertEqual(([tuple(r)for r in db.execute('SELECT * FROM jobs')],db.total_changes),(before,changes))
                rollbacks=list(self.root.glob('terminal-history-rollback-auto-*'));self.assertEqual(len(rollbacks),1)
                actual=q.terminal_history_resolve(self.root,self.uid,ref,own['id'],own['unit'],'a'*32)
                self.assertEqual(actual['rows'],[q.terminal_closed_row(r)for r in rows]+[own])
                with q.history_directory(self.root,self.uid)as fd:
                    self.assertLess(q.history_inventory(fd,self.uid)[0],256*1024)
                    for pin in pins:self.assertEqual(hashlib.sha256(q.history_read_leaf(fd,pin,self.uid,q.HISTORY_FILE_MAX)).hexdigest(),pin['sha256'])
                # The rollback is retained; this test grants no cleanup or
                # process/VM authority and does not erase historical originals.
                self.assertTrue(rollbacks[0].is_dir())
            finally:db.close()

    def test_unfinished_reserved_unknown_and_nonjson_results_are_never_compacted(self):
        q=self.q
        for state,result in [('running',None),('terminal_cleanup',q.canonical({'terminalLifecycle':{'phase':'CLOSED','reservationRetained':False}})),
            ('unknown',q.canonical({'terminalLifecycle':{'phase':'CLOSED','reservationRetained':True}})),
            ('failed','original unreadable result'),('failed','null')]:
            row={'id':'preserved','unit':'original.service','state':state,'result':result}
            self.assertEqual(q.terminal_closed_row(row),row)

    def test_wrong_complete_pin_set_refuses_before_exchange_and_preserves_old_pair(self):
        original,raw=self.publish('old');q=self.q
        q.history_archive_migrate(self.root,self.uid,'terminal-history-rollback-first',self.gate([original]))
        new,other=self.publish('new');gate=self.gate([original,new]);gate['sourcePinsSHA256']='0'*64
        before={p.name:p.read_bytes()for p in (self.root/q.HISTORY_DIRECTORY).iterdir()}
        with self.assertRaisesRegex(ValueError,'All original pins'):
            q.history_archive_migrate(self.root,self.uid,'terminal-history-rollback-refused',gate)
        self.assertEqual(before,{p.name:p.read_bytes()for p in (self.root/q.HISTORY_DIRECTORY).iterdir()})
        with q.history_directory(self.root,self.uid)as fd:
            self.assertEqual(q.history_read_leaf(fd,original,self.uid,q.HISTORY_FILE_MAX),raw)
            self.assertEqual(q.history_read_leaf(fd,new,self.uid,q.HISTORY_FILE_MAX),other)


class MetadataOwnedClosure(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.queue=self.root/"queue";self.queue.mkdir(mode=0o700)
        (self.queue/"queue.sqlite3").write_bytes(b"unit opaque volume, no canonical-source claim")
        self.counter=0

    def config(self,body,relation="same"):
        self.counter+=1;source=self.root/("synthetic-producer-"+str(self.counter)+".py")
        raw=("import json,os,sys\ndef main(argv):\n"+"\n".join("    "+line for line in body.splitlines())+"\n").encode()
        source.write_bytes(raw);source.chmod(0o600)
        scratch=self.queue if relation=="same" else self.queue/"scratch"if relation=="nested"else self.root/"scratch"
        scratch.mkdir(mode=0o700,exist_ok=True)
        return {"queue_dir":str(self.queue),"queue_entry":{"path":str(source),"sha256":hashlib.sha256(raw).hexdigest()},
                "queue_modules":[],"queue_metadata":{"scratch_dir":str(scratch),"max_bytes":128*1024**2,"free_reserve_bytes":0}}

    def assert_closed(self,proof,complete):
        self.assertEqual(proof["complete"],complete)
        self.assertTrue(proof["capture_fd_closed"])
        self.assertTrue(proof["sealed_manifest_fds_closed"])
        self.assertTrue(proof["normal_queue_descriptors_closed"])
        self.assertEqual(stage.descriptor_keys(proof["queue_fds_before"]),stage.descriptor_keys(proof["queue_fds_after_owned_close"]))
        self.assertTrue(proof["owned_descriptors"][0]["allocated"]["open"])
        self.assertTrue(proof["owned_descriptors"][0]["before_close"]["open"])
        self.assertFalse(proof["owned_descriptors"][0]["after_close"]["open"])

    def test_actual_owned_spool_closes_before_real_scan_same_nested_and_separate(self):
        for relation in ("same","nested","separate"):
            with self.subTest(relation=relation):
                proof={};value=stage.queue_call(self.config('print(json.dumps({"unit_only":True,"unknown":[1,2,3]}))\nreturn 0',relation),"status",capture_receipt=proof)
                self.assertEqual(value,{"unit_only":True,"unknown":[1,2,3]})
                self.assert_closed(proof,True);self.assertEqual(proof["producer_exit"],0)

    def cleanup_leaks(self,proof):
        before={row["fd"]for row in proof["queue_fds_before"]}
        for row in proof.get("queue_fds_after_owned_close",[]):
            if row["fd"]not in before and row["target"].startswith(str(self.queue)+"/unit-leak"):
                actual=stage.descriptor_observation(row["fd"])
                self.assertEqual(actual,row)
                os.close(row["fd"])

    def test_genuine_named_and_unlinked_anonymous_queue_fd_leaks_still_refused(self):
        for anonymous in (False,True):
            body='p=os.path.join(argv[1],"unit-leak")\nfd=os.open(p,os.O_CREAT|os.O_RDWR,0o600)\n'
            if anonymous:body+='os.unlink(p)\n'
            body+='print(json.dumps({"unit_only":True}))\nreturn 0'
            proof={}
            try:
                with self.assertRaises(stage.MetadataConsumerFailure)as caught:stage.queue_call(self.config(body),"status",capture_receipt=proof)
                self.assertIs(caught.exception.metadata_receipt,proof)
                self.assertFalse(proof["normal_queue_descriptors_closed"]);self.assertFalse(proof["complete"])
                self.assertTrue(proof["capture_fd_closed"])
                self.assertIn("left queue descriptors",str(caught.exception))
                self.assertTrue(any("unit-leak"in row["target"]for row in proof["queue_fds_after_owned_close"]))
                if anonymous:self.assertTrue(any(row["target"].endswith(" (deleted)")for row in proof["queue_fds_after_owned_close"]))
            finally:self.cleanup_leaks(proof)

    def test_producer_failure_retains_numeric_exit_and_complete_actual_fd_cleanup(self):
        proof={}
        with self.assertRaises(stage.MetadataConsumerFailure)as caught:
            stage.queue_call(self.config('print("partial producer output")\nreturn 7'),"status",capture_receipt=proof)
        self.assert_closed(proof,False);self.assertEqual(proof["producer_exit"],7)
        self.assertIn("consumer failed",caught.exception.metadata_receipt["first_failure"]["reason"])

    def test_overflow_failure_retains_byte_observations_without_truncation_or_fd_leak(self):
        proof={}
        with self.assertRaises(stage.MetadataConsumerFailure):
            stage.queue_call(self.config('print("x"*(9*1024**2))\nreturn 0'),"status",capture_receipt=proof)
        self.assert_closed(proof,False)
        self.assertGreater(proof["observed_bytes"],proof["before"]["cap_bytes"])
        self.assertFalse(proof["complete"]);self.assertIn("no truncation",proof["first_failure"]["reason"])

    def test_parse_and_partial_utf8_failures_still_close_owned_spool_before_scan(self):
        for producer in ('print("{malformed")\nreturn 0','sys.stdout.buffer.write(b"\\xc3")\nreturn 0'):
            proof={}
            with self.assertRaises(stage.MetadataConsumerFailure):stage.queue_call(self.config(producer),"status",capture_receipt=proof)
            self.assert_closed(proof,False);self.assertEqual(proof["producer_exit"],0)
            self.assertIn(proof["first_failure"]["type"],("JSONDecodeError","UnicodeDecodeError"))

    def test_close_fault_is_not_promoted_to_success_even_after_actual_fd_closes(self):
        original=stage.MetadataCapture.close
        def fail_after_close(value):
            already_closed=value.closed
            original(value)
            if not already_closed:raise ValueError("unit close verification fault after actual owned close")
        proof={}
        with mock.patch.object(stage.MetadataCapture,"close",fail_after_close):
            with self.assertRaises(stage.MetadataConsumerFailure):
                stage.queue_call(self.config('print("{}")\nreturn 0'),"status",capture_receipt=proof)
        self.assert_closed(proof,False);self.assertTrue(proof["close_failures"])
        self.assertIn("verification fault",proof["first_failure"]["reason"])

    def test_real_leak_is_retained_alongside_original_producer_failure(self):
        proof={};body='os.open(os.path.join(argv[1],"unit-leak"),os.O_CREAT|os.O_RDWR,0o600)\nprint("partial")\nreturn 9'
        try:
            with self.assertRaises(stage.MetadataConsumerFailure):stage.queue_call(self.config(body),"status",capture_receipt=proof)
            self.assertEqual(proof["producer_exit"],9);self.assertIn("consumer failed",proof["first_failure"]["reason"])
            self.assertTrue(proof["capture_fd_closed"]);self.assertFalse(proof["normal_queue_descriptors_closed"])
            self.assertTrue(any("left queue descriptors"in x["reason"]for x in proof["close_failures"]))
        finally:self.cleanup_leaks(proof)

    def test_sealed_manifest_descriptor_has_own_exact_before_after_close_custody(self):
        manifest={"version":1,"jobs":[{"id":"unit-only","cwd":"/unit","command":["/usr/bin/true"],"files":[],"approval":{"path":"/unit/admission.json"}}]}
        path=self.root/"manifest.json";raw=json.dumps(manifest).encode();path.write_bytes(raw);path.chmod(0o600)
        pin={"path":str(path),"sha256":hashlib.sha256(raw).hexdigest()}
        body='value=json.loads(open(argv[3]).read())\nprint(json.dumps({"unit_manifest":value["version"]}))\nreturn 0'
        proof={};value=stage.queue_call(self.config(body),"submit",[pin],capture_receipt=proof)
        self.assertEqual(value,{"unit_manifest":1});self.assert_closed(proof,True)
        self.assertEqual([x["role"]for x in proof["owned_descriptors"]],["metadata-capture","sealed-manifest"])
        self.assertTrue(all(x["after_close"]["open"]is False for x in proof["owned_descriptors"]))
        # Permission refusal is a required negative, independent of guest umask.
        with self.subTest(mode="0664-manifest-refused"):
            path.chmod(0o664)
            try:
                rejected={}
                with self.assertRaisesRegex(stage.MetadataConsumerFailure,"group/world writable"):
                    stage.queue_call(self.config(body),"submit",[pin],capture_receipt=rejected)
                self.assertEqual(path.read_bytes(),raw)
            finally:path.chmod(0o600)


class OrdinaryDispatcherStartup(unittest.TestCase):
    """Real queue/SQL/locks and normal close API; clock only is modeled."""
    def setUp(self):
        import contextlib,io,gc
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        source=path.parent/'omen_control/test_queue.py'
        spec=importlib.util.spec_from_file_location('startup_actual_queue',source)
        self.q=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.q)
        self.state=self.root/'state'
        with contextlib.redirect_stdout(io.StringIO()):self.q.main(['--queue',str(self.state),'init'])
        gc.collect()
        lock=self.state/'worker.lock';lock.write_bytes(b'');lock.chmod(0o664)
        marker=self.root/'admission.json';marker.write_text('{"fixtureOnly":true}');marker.chmod(0o600)
        self.job={'id':'correlated-unstarted-ubuntu','owner':'exe','platform':'ubuntu',
                  'command':['/usr/bin/true'],'cwd':str(self.root),'files':[str(marker)],
                  'cores':1,'memory':'1GiB','timeout_seconds':30,'resources':['fixture-only'],
                  'approval':{'path':str(marker),'sha256':hashlib.sha256(marker.read_bytes()).hexdigest()}}
        self.manifest=self.root/'manifest.json';self.manifest.write_text(json.dumps({'version':1,'jobs':[self.job]}));self.manifest.chmod(0o600)
        self.pin={'path':str(self.manifest),'sha256':hashlib.sha256(self.manifest.read_bytes()).hexdigest()}
        cfg={'cpu_ids':self.q.DEFAULT_CPUS,'memory_bytes':self.q.DEFAULT_RAM,
             'slice':'opemos-vm-pool.slice','manager':'system'}
        self.config={'queue_dir':str(self.state),'queue_entry':{'path':str(source),
                     'sha256':hashlib.sha256(source.read_bytes()).hexdigest()},'queue_modules':[],
                     'queue_metadata':{'scratch_dir':str(self.state),'max_bytes':128*1024**2,'free_reserve_bytes':0},
                     'pool_sha256':hashlib.sha256(json.dumps(cfg,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
        stage.queue_call(self.config,'submit',[self.pin])

    def test_absent_dispatcher_fails_correlated_job_promptly_without_late_launch(self):
        clock=[100.0];evidence={}
        def sleep(seconds):clock[0]+=seconds
        with mock.patch.object(stage.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(stage.time,'sleep',side_effect=sleep):
            with self.assertRaisesRegex(ValueError,'Ordinary dispatcher unavailable'):
                stage.wait_jobs(self.config,[self.job['id']],[self.pin],10000,evidence)
        self.assertLessEqual(clock[0],135)
        self.assertEqual(evidence['closure'],'CLOSED')
        self.assertEqual(evidence['normal_pending_closure']['closed_unstarted'],[self.job['id']])
        row=stage.queue_status(self.config)[self.job['id']]
        self.assertEqual(row['state'],'failed');self.assertIsNone(row['unit'])
        self.assertIs(row['result']['launched'],False)
        self.assertIs(row['result']['reservationRetained'],False)
        # The normal scheduler cannot start this closed request later.
        result=stage.queue_call(self.config,'status')
        self.assertEqual(result['runnable_now'],[])

    def test_live_worker_and_changed_manifest_refuse_pending_closure(self):
        import subprocess,sys
        body='import fcntl,sys;f=open(sys.argv[1]);fcntl.flock(f,fcntl.LOCK_EX);print("held",flush=True);sys.stdin.read(1)'
        worker=subprocess.Popen([sys.executable,'-I','-c',body,str(self.state/'worker.lock')],
                                stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(worker.stdout.readline().strip(),'held')
            with self.assertRaises(stage.MetadataConsumerFailure):
                stage.queue_call(self.config,'fail-unstarted',[self.pin])
            cut={};stage.queue_status(self.config,diagnostic=cut)
            self.assertIs(cut['worker_lock_free'],False)
        finally:
            worker.stdin.close();worker.wait(timeout=5);worker.stdout.close()
        wrong=dict(self.job,command=['/usr/bin/false'])
        self.manifest.write_text(json.dumps({'version':1,'jobs':[wrong]}))
        wrong_pin=dict(self.pin,sha256=hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        with self.assertRaises(stage.MetadataConsumerFailure):stage.queue_call(self.config,'fail-unstarted',[wrong_pin])
        row=stage.queue_status(self.config)[self.job['id']]
        self.assertEqual(row['state'],'pending');self.assertIsNone(row['unit'])

    def test_native_empty_worker_lock_accepts_0664_but_refuses_executable_otherwrite_or_content(self):
        lock=self.state/'worker.lock'
        cut={};stage.queue_status(self.config,diagnostic=cut)
        self.assertIs(cut['worker_lock_free'],True)
        for mode,content in((0o764,b''),(0o666,b''),(0o664,b'not an empty native lock')):
            with self.subTest(mode=oct(mode),content=bool(content)):
                lock.write_bytes(content);lock.chmod(mode)
                with self.assertRaisesRegex(ValueError,'worker lock custody'):
                    stage.queue_status(self.config,diagnostic={})
                with self.assertRaises(stage.MetadataConsumerFailure):
                    stage.queue_call(self.config,'fail-unstarted',[self.pin])
                self.assertEqual(stage.queue_status(self.config)[self.job['id']]['state'],'pending')
        lock.write_bytes(b'');lock.chmod(0o664)
        result=stage.queue_call(self.config,'fail-unstarted',[self.pin])
        self.assertEqual(result['closed_unstarted'],[self.job['id']])


    def test_absent_worker_with_started_or_unknown_work_fails_without_release(self):
        import sqlite3
        for state in('running','unknown'):
            with self.subTest(state=state):
                # Canonical/kernel execution is modeled; SQL/lock/wait are real.
                with sqlite3.connect(self.state/'queue.sqlite3')as db:
                    retained=json.dumps({'reason':'Unit evidence missing; original reservation retained'})if state=='unknown'else None
                    db.execute('UPDATE jobs SET state=?,unit=?,started=?,cpus=?,result=? WHERE id=?',
                               (state,'fixture-started-unit.service',1,'[0]',retained,self.job['id']))
                db.close()  # sqlite's context commits; it does not close the FD
                clock=[100.0];evidence={}
                with mock.patch.object(stage.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(stage.time,'sleep',side_effect=lambda n:clock.__setitem__(0,clock[0]+n)):
                    with self.assertRaisesRegex(ValueError,'Ordinary dispatcher unavailable'):
                        stage.wait_jobs(self.config,[self.job['id']],[self.pin],10000,evidence)
                self.assertEqual(evidence['closure'],'UNKNOWN')
                self.assertIs(evidence['reservationRetained'],True)
                self.assertNotIn('normal_pending_closure',evidence)
                row=stage.queue_status(self.config)[self.job['id']]
                self.assertEqual((row['state'],row['unit']),(state,'fixture-started-unit.service'))
                with self.assertRaises(stage.MetadataConsumerFailure):stage.queue_call(self.config,'fail-unstarted',[self.pin])

    def test_late_status_cannot_extend_original_wait_deadline(self):
        clock=[1.0];called=[]
        def status(config,diagnostic):clock[0]=11.0;return {self.job['id']:{'state':'passed'}}
        with mock.patch.object(stage.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(stage,'queue_status',side_effect=status):
            with self.assertRaisesRegex(ValueError,'deadline after status'):
                stage.wait_jobs(self.config,[self.job['id']],[self.pin],10,{})

    @unittest.skipUnless(os.getuid()==1000 and Path('/run/user/1000/bus').exists(),
                         'actual ordinary user manager unavailable')
    def test_real_existing_manager_reenters_error_two_once_but_not_normal_failure_one(self):
        """Benign finite source fixture only; no listener, queue or VM effect."""
        import subprocess,sys,time,uuid
        source=path.parent/'omen_control/normal_cycle.py'
        spec=importlib.util.spec_from_file_location('actual_dispatcher_properties',source)
        cycle=importlib.util.module_from_spec(spec);spec.loader.exec_module(cycle)
        env=dict(os.environ,XDG_RUNTIME_DIR='/run/user/1000',DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/1000/bus')
        for code,expected in((2,2),(1,1)):
            unit='opemos-source-fixture-reentry-'+uuid.uuid4().hex+'.service'
            counter=self.root/('counter-'+str(code))
            body='import os,sys;f=open(sys.argv[1],"a");f.write("attempt\\n");f.flush();os.fsync(f.fileno());f.close();sys.exit(int(sys.argv[2]))'
            def call(args):return subprocess.run(args,env=env,capture_output=True,text=True,timeout=10)
            try:
                launch=call(['/usr/bin/systemd-run','--user','--unit='+unit,
                    '--property=RuntimeMaxSec=10','--property=MemoryMax=67108864',
                    '--property=MemorySwapMax=0','--property=AllowedCPUs=1',
                    *cycle.DISPATCHER_REENTRY_PROPERTIES,sys.executable,'-I','-c',body,str(counter),str(code)])
                self.assertEqual(launch.returncode,0,launch.stderr)
                end=time.monotonic()+12
                while True:
                    props=call(['/usr/bin/systemctl','--user','show',unit,'-p','ActiveState','-p','MainPID','-p','ControlGroup'])
                    self.assertEqual(props.returncode,0,props.stderr)
                    m=dict(z.split('=',1)for z in props.stdout.splitlines()if'='in z)
                    if m.get('ActiveState')=='failed'and m.get('MainPID')=='0'and m.get('ControlGroup')=='':break
                    self.assertLess(time.monotonic(),end,props.stdout);time.sleep(.1)
                self.assertEqual(counter.read_text().splitlines(),['attempt']*expected)
            finally:
                call(['/usr/bin/systemctl','--user','stop',unit])
                call(['/usr/bin/systemctl','--user','reset-failed',unit])


class RequiredCanonicalAdmission(unittest.TestCase):
    def test_public_safety_or_old_source_cannot_substitute_for_required_actual_omen_fixture(self):
        pins={name:"a"*64 for name in stage.QUALIFICATION_FILES}
        for value in ({},{"status":"passed","uid":1000,"numeric_exit":0,"public_safety_batch_substitute":True},
                      {"kind":"OPEMOS_REQUIRED_CANONICAL_METADATA_VM_QUALIFICATION_V1","status":"passed","source_commit":"b"*40}):
            with self.assertRaises(ValueError):stage.validate_canonical_qualification(value,pins,"c"*40,"a"*64)
        with self.assertRaises(ValueError):stage.validate_canonical_qualification({},pins,"c"*40,"e"*64)

    def test_qualified_source_needs_all_three_actual_closed_captures_and_preserved_unknown_rows(self):
        import stat
        pins={name:"a"*64 for name in stage.QUALIFICATION_FILES}
        cases=[]
        for relation in ("same","nested","separate"):
            identity={key:0 for key in stage._FULL9};identity.update(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o600,st_uid=1000,st_gid=1000)
            allocated={"fd":9,"open":True,"target":"/unit/anonymous (deleted)","identity":identity}
            before=copy.deepcopy(allocated);before["identity"]["st_size"]=33*1024**2
            proof={"bytes":33*1024**2,"producer_source_sha256":stage.CANONICAL_QUEUE_SHA,"job_rows":77,"producer_exit":0,
                   "all_rows_retained":True,"complete":True,"capture_fd_closed":True,"sealed_manifest_fds_closed":True,
                   "normal_queue_descriptors_closed":True,"queue_fds_before":[],"queue_fds_after_owned_close":[],
                   "owned_descriptors":[{"role":"metadata-capture","allocated":allocated,"before_close":before,"after_close":{"fd":9,"open":False}}]}
            probe={"status":"passed","full_bytes":33*1024**2,"wire_bytes":33*1024**2,"wire_sha256":"b"*64,
                   "local_numeric_exit":0,"actual_SSH_claim":False,**{k:True for k in ("wire_EOF","transport_complete","local_reaped",
                   "all_unknown_rows_equal","guarded_expiry_removed_only_new_owned_probe","retained_full_receipt_equal")}}
            cases.append({"scratch_relation":relation,"status":"passed","job_rows":77,"unknown_fields_preserved":True,
                          "normal_producer_exit":0,"metadata_custody":proof,"result_transport_retention":probe})
        value={"kind":"OPEMOS_REQUIRED_CANONICAL_METADATA_VM_QUALIFICATION_V1","status":"passed","source_commit":"c"*40,
               "uid":1000,"numeric_exit":0,"canonical_fixture_sha256":stage.CANONICAL_QUEUE_SHA,"canonical_fixture_bytes":388189,
               "source_pins":pins,"public_safety_batch_substitute":False,"genuine_vm_receipt":True,"cases":cases}
        stage.validate_canonical_qualification(value,pins,"c"*40,"a"*64)
        for field in ("complete","capture_fd_closed","normal_queue_descriptors_closed","all_rows_retained"):
            changed=copy.deepcopy(value);changed["cases"][0]["metadata_custody"][field]=False
            with self.assertRaises(ValueError):stage.validate_canonical_qualification(changed,pins,"c"*40,"a"*64)
        changed=copy.deepcopy(value);changed["cases"][0]["metadata_custody"]["owned_descriptors"][0]["after_close"]["open"]=True
        with self.assertRaises(ValueError):stage.validate_canonical_qualification(changed,pins,"c"*40,"a"*64)
        changed=copy.deepcopy(value);changed["cases"].pop()
        with self.assertRaises(ValueError):stage.validate_canonical_qualification(changed,pins,"c"*40,"a"*64)


if __name__=="__main__":
    unittest.main()

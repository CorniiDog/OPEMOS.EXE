"""Composed CI8 control/custody regressions. Run only in admitted CI/guest.

Local synthetic children exercise actual pipes/files/closure, never SSH or VM
acceptance. No project tests/imports were run by the source author.
"""
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


def module(name,path=None):
    path=path or Path(__file__).resolve().parents[1]/'scripts'/(name+'.py')
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

C=module('omen_ci');R=C._RESULT


class JoinedVerdict(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        previous=Path.cwd();os.chdir(self.temp.name);self.addCleanup(os.chdir,previous)
        self.root=Path.cwd();self.contract={'max_bytes':8*1024**2,'stderr_max_bytes':65536,'free_reserve_bytes':0}
        config=self.root/'installed-config.json';config.write_text(json.dumps({'result_contract':self.contract,
            'controller_program_sha256':C.current_source_pin()['sha256']}));config.chmod(0o600)
        self.env={'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'900','GITHUB_RUN_ATTEMPT':'3',
            'OPEMOS_CONTROLLER_CONFIG_SHA256':hashlib.sha256(config.read_bytes()).hexdigest()}
        self.config=config
        patch=mock.patch.object(C,'CONFIG',config);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.dict(os.environ,self.env);patch.start();self.addCleanup(patch.stop)
        old=C._RESULT_LIMIT;C._RESULT_LIMIT=self.contract['max_bytes'];self.addCleanup(setattr,C,'_RESULT_LIMIT',old)
        fixture=module('ci8_inventory_fixture',Path(__file__).with_name('test_omen_ci.py'))
        values=fixture.AllVMVisibility();values.setUp();self.result=copy.deepcopy(values.result)
        # Rebind real synthetic inventory fixture to executable fixture run900/3.
        self.result.update(source_commit='a'*40,run_id='900',attempt='3')
        for row in self.result['vms'].values():row.update(source_commit='a'*40,run_id='900',attempt='3')
        self.exe=module('ci8_executable_fixture',Path(__file__).with_name('test_omen_ci_executables.py'))
        self.expected=self.exe.expected()
        self.result['executable_acceptance']=C._EXECUTABLES['report'](self.expected,self.exe.outcomes(self.expected),'a'*40,'900','3')
        self.result=C.write_summary(self.result)
        self.run={'head_sha':'a'*40,'run_started_at':'2026-10-19T00:00:00Z'}

    def seal_dispatch(self,numeric=0,closed=True):
        receipt=R['capture']([sys.executable,'-I','-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read());sys.stderr.write("synthetic complete diagnostic");sys.exit('+str(numeric)+')'],
            json.dumps(self.result).encode(),self.contract,self.root/'actual-local-transport',20)
        self.assertEqual(receipt['numeric_exit'],numeric);self.assertTrue(receipt['local_reaped'])
        sealed=[]
        for role in ('known-hosts','private-key'):
            fd=C.sealed_bytes(b'SYNTHETIC_NOT_CREDENTIAL',role);os.close(fd);sealed.append({'fd':fd,'role':role,'closed':True})
        receipt.update(complete=closed,sealed_descriptors=sealed,request_identity={'repository':C.REPOSITORY,**C.run_identity(self.env)})
        R['write_full']('ci-transport-index.json',receipt,1024**2)
        C.record_dispatch_verdict(self.env,types.SimpleNamespace(returncode=numeric,transport_receipt=receipt),self.result)
        child=subprocess.Popen([sys.executable,'-I','-c','pass']);code=child.wait()
        R['write_full']('ci-heavy-control.json',{'version':1,**C.run_identity(self.env),'controller_source':C.current_source_pin(),
            'local_process_started':True,'local_pid':child.pid,'local_reaped':closed,'numeric_exit':code},1024**2)

    def publish_both(self,result=None):
        calls=[]
        def api(endpoint,value=None):calls.append(value);return {}
        with mock.patch.object(C,'gh_api',side_effect=api):
            vm=C.publish_vm_statuses('900','3',self.run,result or copy.deepcopy(self.result))
            artifacts=C.publish_executable_statuses('900','3',self.run,vm,self.expected)
        self.assertEqual(len([x for x in calls if x['context'] in {r['github_context']for r in C._INVENTORY['REQUIRED']}]),20)
        return vm,artifacts,calls

    def wait_bridge(self,calls,passed):
        statuses=[dict(v,id=i+1)for i,v in enumerate(calls)];raw=json.dumps(statuses).encode()
        env={**self.env,'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':C.REPOSITORY,'GITHUB_REF':'refs/heads/main',
            'GITHUB_REF_PROTECTED':'true','OPEMOS_EXISTING_CONTROLLER_ENABLED':'true','GITHUB_TOKEN':'synthetic-read-only-not-a-token'}
        # Hosted wait uses the actual emitted statuses through its normal parser.
        # Existing local summary files are kept; run wait in a fresh hosted dir.
        hosted=self.root/'hosted';hosted.mkdir()
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def read(self,cap):return raw
        with contextlib.chdir(hosted),mock.patch.object(C,'read_expected_envelope',return_value={'expected_executables':self.expected}),mock.patch.object(C.urllib.request,'urlopen',return_value=Response()):
            if passed:C.wait_existing(env)
            else:
                with self.assertRaises(ValueError):C.wait_existing(env)
            value=json.loads(Path('ci-summary.json').read_bytes())
            self.assertEqual(value['aggregate']['status'],'passed'if passed else'failed')

    def test_zero_closed_exact_join_passes_both_publishers_and_hosted_wait(self):
        self.seal_dispatch();control=C.record_control_verdict(self.env,0);self.assertTrue(control['accepted'])
        vm,artifacts,calls=self.publish_both();self.assertEqual(vm['aggregate']['status'],'passed');self.assertEqual(artifacts['aggregate']['status'],'passed')
        self.assertTrue(all(x['state']=='success'for x in calls));self.wait_bridge(calls,True)

    def test_passing_summary_with_numeric255_never_publishes_success_or_passes_wait(self):
        self.seal_dispatch(255);C.record_control_verdict(self.env,1)
        vm,artifacts,calls=self.publish_both();self.assertTrue(all(x['state']=='failure'for x in calls))
        self.assertEqual(json.loads(Path('ci-summary.json').read_bytes())['aggregate']['status'],'passed')
        self.assertEqual(artifacts['aggregate']['status'],'failed');self.wait_bridge(calls,False)

    def test_parent_nonzero_and_unknown_child_closure_refuse_before_any_success(self):
        self.seal_dispatch(closed=False);control=C.record_control_verdict(self.env,7);self.assertFalse(control['accepted'])
        _,_,calls=self.publish_both();self.assertTrue(all(x['state']=='failure'for x in calls))

    def test_standalone_publisher_cannot_accept_passing_summary_without_control(self):
        calls=[]
        with mock.patch.object(C,'current_gh_run',return_value=('900','3',self.run)),mock.patch.object(C,'consumer_expectations',return_value=self.expected),mock.patch.object(C,'gh_api',side_effect=lambda endpoint,value=None:calls.append(value)or{}):
            with self.assertRaises(ValueError):C.publish_existing(self.env)
        self.assertTrue(calls);self.assertTrue(all(x['state']=='failure'for x in calls))

    def test_current_source_run_attempt_and_summary_replacement_invalidate_join(self):
        self.seal_dispatch();C.record_control_verdict(self.env,0)
        self.assertFalse(C.publication_verdict('900','4',self.run,self.result)['accepted'])
        changed=copy.deepcopy(self.result);changed['nonce']='f'*32
        self.assertFalse(C.publication_verdict('900','3',self.run,changed)['accepted'])
        # Actual path replacement with same semantic bytes still breaks full9.
        replacement=self.root/'replacement';replacement.write_bytes(Path('ci-summary.json').read_bytes());replacement.replace('ci-summary.json')
        self.assertFalse(C.publication_verdict('900','3',self.run,self.result)['accepted'])

    def test_wrong_installed_source_pin_and_boolean_zero_never_grant_acceptance(self):
        self.seal_dispatch();C.record_control_verdict(self.env,0)
        config=json.loads(self.config.read_bytes());config['controller_program_sha256']='0'*64
        self.config.write_text(json.dumps(config))
        with mock.patch.dict(os.environ,OPEMOS_CONTROLLER_CONFIG_SHA256=hashlib.sha256(self.config.read_bytes()).hexdigest()):
            self.assertFalse(C.publication_verdict('900','3',self.run,self.result)['accepted'])
        self.assertFalse(C.zero_exit(False));self.assertFalse(C.zero_exit('0'));self.assertTrue(C.zero_exit(0))

    def test_existing_gh_parent_failure_is_recorded_before_both_publications(self):
        self.seal_dispatch();seen=[]
        def pub(*args):
            seen.append(json.loads(Path('ci-control-verdict.json').read_bytes()))
            return {'aggregate':{'status':'failed'}}
        with mock.patch.object(C,'current_gh_run',return_value=('900','3',self.run)),mock.patch.object(C,'consumer_expectations',return_value=self.expected),mock.patch.object(C,'enter_heavy',return_value=7),mock.patch.object(C,'publish_vm_statuses',side_effect=pub),mock.patch.object(C,'publish_executable_statuses',side_effect=pub):
            with self.assertRaises(ValueError):C.existing_gh(self.env)
        self.assertEqual(len(seen),2);self.assertTrue(all(x['parent_numeric_exit']==7 and x['accepted']is False for x in seen))

    def test_fresh_inventory_cli_consumes_verified_large_contract_not_result_cap(self):
        # Fresh child imports the exact source normally; no global cap inherited.
        Path('ci-summary.json').unlink();value=copy.deepcopy(self.result);value['unknown_future']='z'*(2*1024**2)
        R['write_full']('ci-summary.json',value,self.contract['max_bytes'])
        bootstrap="import runpy,pathlib,sys; n=runpy.run_path(sys.argv[1],run_name='synthetic_fresh_report'); n['main'].__globals__['CONFIG']=pathlib.Path(sys.argv[2]); sys.argv=[sys.argv[1],'inventory-report']; sys.exit(n['main']())"
        child=subprocess.run([sys.executable,'-I','-c',bootstrap,str(Path(C.__file__).absolute()),str(self.config)],env={**os.environ,**self.env},capture_output=True,timeout=30)
        self.assertEqual(child.returncode,0,child.stderr.decode());report=json.loads(Path('ci-inventory-report.json').read_bytes())
        self.assertEqual(report['unknown_future'],value['unknown_future']);self.assertEqual(len(report['vms']),20)
        self.assertEqual(report['aggregate']['status'],'passed')


class PrefixAndFailureCustody(unittest.TestCase):
    def contract(self):return {'max_bytes':1024**2,'stderr_max_bytes':65536,'free_reserve_bytes':0}

    def test_short_prefix_then_zero_or_eio_retains_exact_actual_bytes_and_first_error(self):
        for mode in ('zero','eio'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory()as temp:
                root=Path(temp);real=os.write;counts={}
                def writer(fd,data):
                    target=os.readlink('/proc/self/fd/'+str(fd))
                    if target==str(root/'capture'/'stdout'):
                        counts[fd]=counts.get(fd,0)+1
                        if counts[fd]==1:return real(fd,data[:3])
                        if counts[fd]==2:
                            if mode=='zero':return 0
                            raise OSError(5,'synthetic EIO')
                    return real(fd,data)
                with mock.patch.object(R['os'],'write',side_effect=writer):
                    with self.assertRaises(R['TransportFailure'])as caught:
                        R['capture']([sys.executable,'-I','-c','import sys;sys.stdout.write("abcdefgh")'],b'',self.contract(),root/'capture',20)
                receipt=caught.exception.transport_receipt;row=receipt['streams']['stdout'];raw=(root/'capture'/'stdout').read_bytes()
                self.assertEqual(raw,b'abc');self.assertEqual(row['bytes'],len(raw));self.assertEqual(row['sha256'],hashlib.sha256(raw).hexdigest())
                self.assertEqual(row['observation']['identity']['st_size'],len(raw));self.assertEqual(row['received_bytes'],8)
                self.assertTrue(row['FD_closed']);self.assertTrue(receipt['local_reaped']);self.assertFalse(receipt['complete'])
                self.assertIn('first_failure',receipt)

    def test_original_write_failure_retains_fsync_and_close_failures_together(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);real_write=os.write;real_sync=os.fsync;real_close=os.close;writes=[]
            target=str(root/'capture'/'stdout')
            def is_stream(fd):
                try:return os.readlink('/proc/self/fd/'+str(fd))==target
                except OSError:return False
            def writer(fd,data):
                if is_stream(fd):
                    if not writes:writes.append(fd);return real_write(fd,data[:3])
                    raise OSError(5,'synthetic write failure')
                return real_write(fd,data)
            def sync(fd):
                if is_stream(fd):raise OSError(28,'synthetic fsync failure')
                return real_sync(fd)
            def close(fd):
                stream=is_stream(fd);real_close(fd)
                if stream:raise OSError(5,'synthetic closure report failure')
            with mock.patch.object(R['os'],'write',side_effect=writer),mock.patch.object(R['os'],'fsync',side_effect=sync),mock.patch.object(R['os'],'close',side_effect=close):
                with self.assertRaises(R['TransportFailure'])as caught:
                    R['capture']([sys.executable,'-I','-c','import sys;sys.stdout.write("abcdefgh")'],b'',self.contract(),root/'capture',20)
            receipt=caught.exception.transport_receipt
            self.assertEqual(receipt['first_failure']['errno'],5)
            self.assertTrue(any(x.get('errno')==28 for x in receipt['stream_failures']))
            self.assertTrue(receipt['close_failures']);self.assertFalse(receipt['streams']['stdout']['FD_closed'])
            self.assertEqual(receipt['streams']['stdout']['bytes'],3)

    def test_primary_capture_failure_survives_receipt_persistence_failure(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);real=R['write_full']
            def persist(path,value,cap):
                if Path(path).name=='receipt.json':raise OSError(28,'synthetic full disk')
                return real(path,value,cap)
            with mock.patch.dict(R,write_full=persist):
                with self.assertRaises(R['TransportFailure'])as caught:
                    R['capture']([sys.executable,'-I','-c','import time;time.sleep(10)'],b'',self.contract(),root/'capture',0.01)
            receipt=caught.exception.transport_receipt
            self.assertTrue(receipt['local_process_started']);self.assertTrue(receipt['local_reaped']);self.assertTrue(receipt['timeout'])
            self.assertIn('deadline',receipt['first_failure']['reason']);self.assertEqual(receipt['receipt_durability'],'UNKNOWN')
            self.assertEqual(receipt['persistence_failures'][0]['type'],'OSError');self.assertIn('local_pid',receipt)
            self.assertTrue(all(row['FD_closed']for row in receipt['streams'].values()))

    def test_secondary_persistence_keeps_original_through_outer_ssh_handler(self):
        with tempfile.TemporaryDirectory()as temp,contextlib.chdir(temp):
            root=Path(temp);key=root/'synthetic-key';key.write_bytes(b'SYNTHETIC_DATA_NOT_PRIVATE_KEY');key.chmod(0o600)
            sourcepins=[{'path':'/synthetic/config','sha256':'a'*64}]
            config={'ssh_config':sourcepins[0],'ssh_dependencies':[],'result_contract':self.contract(),
                'route':{'source_pins_sha256':hashlib.sha256(json.dumps(sourcepins,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                'hostname':'100.119.12.93','user':'connor','port':22,'known_hosts':{'path':'/synthetic/hosts','sha256':'b'*64},'private_key_path':str(key)}}
            original={'complete':False,'local_process_started':True,'local_pid':123,'local_start':456,'numeric_exit':-9,'local_reaped':True,
                'streams':{'stdout':{'path':'synthetic stdout','bytes':3,'EOF':False}},'first_failure':{'reason':'Original synthetic capture deadline'},
                'persistence_failures':[{'type':'OSError'}],'receipt_durability':'UNKNOWN'}
            def capture(*args):raise R['TransportFailure'](original)
            real=R['write_full']
            def persist(path,value,cap):
                if Path(path).name=='ci-transport-index.json':raise OSError(28,'synthetic index disk failure')
                return real(path,value,cap)
            request=json.dumps({'repository':C.REPOSITORY,'source_commit':'a'*40,'run_id':'900','attempt':'3'}).encode()
            with mock.patch.object(C,'pinned',return_value=b'synthetic public route'),mock.patch.dict(R,capture=capture,write_full=persist):
                with self.assertRaises(R['TransportFailure'])as caught:C.ssh_run(config,'SYNTHETIC_COMMAND_SENTINEL',request)
            receipt=caught.exception.transport_receipt
            self.assertEqual(receipt['local_pid'],123);self.assertEqual(receipt['local_start'],456);self.assertTrue(receipt['local_process_started'])
            self.assertEqual(receipt['first_failure']['reason'],'Original synthetic capture deadline');self.assertEqual(len(receipt['persistence_failures']),2)
            self.assertTrue(all(x['closed']for x in receipt['sealed_descriptors']));self.assertNotIn('SYNTHETIC_COMMAND_SENTINEL',json.dumps(receipt))

    def test_closed_stdio_wait_timeout_safe_schema_never_serializes_command(self):
        with tempfile.TemporaryDirectory()as temp:
            marker='SYNTHETIC_BOOTSTRAP_COMMAND_MUST_NOT_ENTER_RECEIPT'
            command=[sys.executable,'-I','-c','import os,time;os.close(1);os.close(2);time.sleep(20) # '+marker]
            with self.assertRaises(R['TransportFailure'])as caught:R['capture'](command,b'',self.contract(),Path(temp)/'capture',30)
            receipt=caught.exception.transport_receipt
            self.assertEqual(receipt['first_failure']['type'],'TimeoutExpired');self.assertEqual(receipt['first_failure']['timeout_seconds'],5)
            self.assertTrue(all(x['EOF']for x in receipt['streams'].values()));self.assertTrue(receipt['local_reaped'])
            self.assertNotIn(marker,json.dumps(receipt));self.assertNotIn('import os,time',(Path(temp)/'capture'/'receipt.json').read_text())


if __name__=='__main__':unittest.main()

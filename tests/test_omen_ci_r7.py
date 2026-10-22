"""R7 coherent custody/result faults; synthetic safety, no runtime acceptance.

Only admitted CI/VM executes this suite. Source author did not run/import it.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


def module(name):
    path=Path(__file__).resolve().parents[1]/"scripts"/(name+".py")
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

stage=module('omen_ci_stage');controller=module('omen_ci');R=stage._RESULT


class CacheAndLineage(unittest.TestCase):
    def test_existing_cache_requires_original_source_and_complete_cached_bytes(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);root.chmod(0o700);source=root/'source';source.write_bytes(b'actual retained source');source.chmod(0o600)
            sha=hashlib.sha256(source.read_bytes()).hexdigest();item={'path':str(source),'sha256':sha,'size':source.stat().st_size};cache=root/sha
            charge,_=stage.retain_pin(item,cache,4096,4096);self.assertEqual(charge,item['size'])
            charge,_=stage.retain_pin(item,cache,0,4096);self.assertEqual(charge,0)
            # Both original and retained-copy mode guards remain meaningful
            # negatives; no global umask change or production relaxation.
            for label,target in(("source",source),("cache",cache)):
                with self.subTest(group_writable=label):
                    target.chmod(0o664)
                    try:
                        with self.assertRaises(ValueError):stage.retain_pin(item,cache,4096,4096)
                        self.assertEqual(cache.read_bytes(),b'actual retained source')
                    finally:target.chmod(0o600)
            source.unlink()
            with self.assertRaises(OSError):stage.retain_pin(item,cache,4096,4096)
            source.write_bytes(b'actual retained source');source.chmod(0o600);cache.write_bytes(b'failed partial')
            with self.assertRaises(ValueError):stage.retain_pin(item,cache,4096,4096)
            self.assertEqual(cache.read_bytes(),b'failed partial')

    def test_shared_runtime_conflicts_both_originals_and_bridge_view(self):
        I=stage._INVENTORY
        self.assertEqual(I['runtime_conflicts']({'original-a':'same-clone','original-b':'same-clone'}),{'original-a','original-b'})
        self.assertEqual(I['runtime_conflicts']({'original-a':'a-clone','original-b':'b-clone'}),set())
        # Exercise real final normalizer using the public per-row setup, not a
        # mocked normalizer. Duplicate originals stay visible and both red.
        path=Path(__file__).with_name('test_omen_ci.py');spec=importlib.util.spec_from_file_location('r7_inventory_fixture',path)
        value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
        example=value.AllVMVisibility();example.setUp();result=copy.deepcopy(example.result);ids=list(result['vms'])
        result['vms'][ids[1]]['runtime_instance_id']=result['vms'][ids[0]]['runtime_instance_id']
        actual=I['normalize'](result)
        self.assertEqual(len(actual['vms']),20)
        self.assertTrue(all(actual['vms'][x]['status']=='failed'for x in ids[:2]))
        for index,row in enumerate(result['vms'].values()):
            row.update(actual_receipt_verified=False,bridge_status_verified=True,status_id=index+1)
        result['status_bridge_view']=True
        bridged=I['normalize'](result)
        self.assertTrue(all(bridged['vms'][x]['status']=='failed'for x in ids[:2]))

    def test_shared_retained_original_source_identity_cannot_count_twice(self):
        path=Path(__file__).with_name('test_omen_ci.py');spec=importlib.util.spec_from_file_location('r7_lineage_fixture',path)
        value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);example=value.AllVMVisibility();example.setUp()
        result=copy.deepcopy(example.result);ids=list(result['vms'])
        result['vms'][ids[1]]['original_source']=copy.deepcopy(result['vms'][ids[0]]['original_source'])
        actual=stage._INVENTORY['normalize'](result)
        self.assertTrue(all(actual['vms'][x]['status']=='failed'for x in ids[:2]))
        result['vms'][ids[1]].pop('original_source')
        self.assertEqual(stage._INVENTORY['normalize'](result)['vms'][ids[1]]['status'],'failed')


class FullResultComposition(unittest.TestCase):
    def policy(self,cap=8*1024**2):return {'max_bytes':cap,'stderr_max_bytes':65536,'free_reserve_bytes':0}

    def test_full_receipt_over_old1m4m_survives_control_and_guarded_expiry(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);root.chmod(0o700);(root/'.receipts').mkdir(mode=0o700)
            stage.create_json(root/stage.MARKER,{'schema':1,'uid':os.getuid(),'purpose':'OPEMOS CI copies only'})
            name='run-12-1-'+'b'*32;run=root/name;run.mkdir(mode=0o700);(run/'artifacts').mkdir(mode=0o700);stage.create_json(run/'.lock',{})
            contract=self.policy();stage.create_json(run/'.owned.json',{'schema':1,'name':name,'uid':os.getuid(),'created':100,'expires':100+stage.TTL,'job_ids':['unit'],'result_max_bytes':contract['max_bytes']})
            value={'run_name':name,'active':False,'queue_rows':{'unit':{'unknown':{'nested':'z'*(5*1024**2)}}},'fixture_only':True}
            size=R['write_full'](run/'receipt.json',value,contract['max_bytes']);self.assertGreater(size,4*1024**2)
            self.assertEqual(stage.load_result(run/'receipt.json',contract['max_bytes'])[0],value)
            import io
            wire=io.BytesIO();R['emit'](value,wire,contract['max_bytes'],str(root));self.assertEqual(json.loads(wire.getvalue()),value)
            removed=stage.expire({'result_contract':contract},{'unit':{'state':'passed','result':{}}},100+stage.TTL,root)
            self.assertEqual(removed,[name]);self.assertEqual(stage.load_result(root/'.receipts'/(name+'.json'),contract['max_bytes'])[0],value)

    def test_budget_composition_refuses_before_effects_and_partial_is_not_promoted(self):
        config={'result_contract':self.policy(),'queue_metadata':{'max_bytes':8*1024**2}}
        with self.assertRaises(ValueError):R['composition'](config,{'admitted_vm_ids':['a'],'expected_executables':{'b':{}}})
        with tempfile.TemporaryDirectory()as temp:
            p=Path(temp)/'receipt.json'
            with self.assertRaises(ValueError):R['write_full'](p,{'unknown':'x'*200},32)
            self.assertFalse(p.exists());self.assertTrue(p.with_name('receipt.json.partial').exists())
            with self.assertRaises(FileExistsError):R['write_full'](p,{},4096)

    def test_full_result_scratch_reserve_is_admitted_before_any_effect(self):
        import types
        with tempfile.TemporaryDirectory()as temp:
            scratch=Path(temp);scratch.chmod(0o700)
            config={"result_contract":self.policy(384*1024**2),"queue_metadata":{"max_bytes":8*1024**2,"scratch_dir":str(scratch)}}
            with mock.patch.object(R["os"],"statvfs",return_value=types.SimpleNamespace(f_bavail=0,f_frsize=4096)):
                with self.assertRaisesRegex(ValueError,"scratch volume"):R["composition"](config,{"admitted_vm_ids":[],"expected_executables":{}})
            self.assertEqual(list(scratch.iterdir()),[])

    def test_complete_transport_numeric_stderr_and_timeout_are_durable_before_parse(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)
            for label,body,code in [('normal','import sys;sys.stdout.write("{bad-json");sys.stderr.write("retained diagnostic");sys.exit(7)',7),
                                    ('large','import sys;sys.stdout.write("x"*(5*1024**2))',0)]:
                receipt=R['capture']([sys.executable,'-I','-c',body],b'',self.policy(),root/label,20)
                self.assertEqual(receipt['numeric_exit'],code);self.assertTrue(receipt['local_reaped']);self.assertTrue(receipt['complete'])
                self.assertTrue((root/label/'receipt.json').exists());self.assertTrue(receipt['streams']['stdout']['EOF'])
                self.assertEqual(receipt['remote_closure'],'UNKNOWN')
            with self.assertRaises(R['TransportFailure'])as caught:
                R['capture']([sys.executable,'-I','-c','import sys,time;print("partial",flush=True);time.sleep(10)'],b'',self.policy(),root/'timeout',0.05)
            self.assertTrue(caught.exception.transport_receipt['timeout']);self.assertTrue(caught.exception.transport_receipt['local_reaped'])
            self.assertEqual(hashlib.sha256((root/'timeout'/'stdout').read_bytes()).hexdigest(),caught.exception.transport_receipt['streams']['stdout']['sha256'])
            self.assertTrue((root/'timeout'/'receipt.json').exists())

    def test_transport_overflow_is_explicit_partial_never_a_valid_reply(self):
        with tempfile.TemporaryDirectory()as temp:
            with self.assertRaises(R['TransportFailure'])as caught:
                R['capture']([sys.executable,'-I','-c','import sys;sys.stdout.write("x"*(3*1024**2))'],b'',self.policy(1024**2),Path(temp)/'overflow',20)
            receipt=caught.exception.transport_receipt
            self.assertFalse(receipt['complete']);self.assertIn('envelope',receipt['first_failure']['reason'])
            self.assertLessEqual(receipt['streams']['stdout']['bytes'],1024**2+131072)
            self.assertTrue(receipt['local_reaped'])


class SourceAndSealedFD(unittest.TestCase):
    def test_early_nonsecret_queue_source_failure_keeps_full_reader_evidence(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);p=root/'source.py';p.write_text('def main(argv):return 0\n')
            config={'queue_modules':[],'queue_entry':{'path':str(p),'sha256':'0'*64}}
            with self.assertRaises(stage._READER.SourceReadFailure)as caught:stage.queue_call(config,'status')
            evidence=caught.exception.nonsecret_source_evidence
            self.assertTrue(evidence['EOF']);self.assertTrue(evidence['closeOutcomes'][0]['closed'])
            self.assertIn('hash mismatch',evidence['firstFailure']['reason'])

    def test_second_sealed_allocation_failure_closes_first_without_ssh_or_secret_serialization(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);previous=Path.cwd();os.chdir(root)
            try:
                key=root/'synthetic-key';key.write_bytes(b'SYNTHETIC_UNIT_DATA_NOT_A_KEY');key.chmod(0o600)
                pins=[];closure=hashlib.sha256(json.dumps(pins,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                config={'ssh_config':{'path':'/synthetic/config','sha256':'a'*64},'ssh_dependencies':[],
                    'result_contract':{'max_bytes':1024**2,'stderr_max_bytes':65536,'free_reserve_bytes':0},
                    'route':{'source_pins_sha256':hashlib.sha256(json.dumps([{'path':'/synthetic/config','sha256':'a'*64}],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                        'hostname':'100.119.12.93','user':'connor','port':22,'known_hosts':{'path':'/synthetic/hosts','sha256':'b'*64},'private_key_path':str(key)}}
                first=[];real=controller.sealed_bytes
                def allocate(raw,name):
                    if first:raise OSError('unit second allocation failure')
                    fd=real(raw,name);first.append(fd);return fd
                with mock.patch.object(controller,'pinned',return_value=b'unit known-hosts'),mock.patch.object(controller,'sealed_bytes',allocate),mock.patch.dict(controller._RESULT,{'capture':mock.Mock(side_effect=AssertionError('SSH must not start'))}):
                    with self.assertRaises(controller._RESULT['TransportFailure'])as caught:controller.ssh_run(config,'fixed reviewed command',b'{}')
                with self.assertRaises(OSError):os.fstat(first[0])
                receipt=caught.exception.transport_receipt;self.assertTrue(receipt['sealed_descriptors'][0]['closed'])
                raw=json.dumps(receipt).encode();self.assertNotIn(key.read_bytes(),raw)
                self.assertTrue(Path('ci-transport-index.json').exists())
            finally:os.chdir(previous)

    def test_legacy_requests_fail_even_with_live_main_metadata(self):
        for path in (".github/workflows/omen-full-stack.yml",".github/workflows/omen-full-stack-existing-controller.yml"):
            run={"event":"workflow_dispatch","head_branch":"main","path":path,"status":"in_progress","conclusion":None,
                 "run_attempt":1,"head_sha":"a"*40}
            with mock.patch.object(controller,"gh_api",side_effect=[run,{"protected":True}]):
                with self.assertRaises(ValueError):controller.current_gh_run({"OPEMOS_GITHUB_RUN_ID":"12"})

    def test_early_nonsecret_dependency_refusal_is_not_generic_or_secret_material(self):
        with tempfile.TemporaryDirectory()as temp:
            p=Path(temp)/'dependency.py';p.write_text('UNIT_ONLY = True\n')
            config={"queue_modules":[{"module":"unit_dependency","path":str(p),"sha256":"0"*64}]}
            with self.assertRaises(stage._READER.SourceReadFailure)as caught:stage.queue_call(config,'status')
            self.assertTrue(caught.exception.nonsecret_source_evidence['closeOutcomes'][0]['closed'])
            self.assertTrue(caught.exception.nonsecret_source_evidence['EOF'])

    def test_early_closed_request_pipe_still_retains_actual_stderr_and_exit(self):
        with tempfile.TemporaryDirectory()as temp:
            contract={"max_bytes":1024**2,"stderr_max_bytes":65536,"free_reserve_bytes":0}
            body='import os,sys;os.close(0);sys.stderr.write("ordinary numeric diagnostic");sys.stderr.flush();sys.exit(23)'
            try:receipt=R['capture']([sys.executable,'-I','-c',body],b'x'*1024,contract,Path(temp)/'closed-input',20)
            except R['TransportFailure']as error:receipt=error.transport_receipt
            self.assertEqual(receipt['numeric_exit'],23);self.assertTrue(receipt['streams']['stderr']['EOF'])
            self.assertEqual(Path(receipt['streams']['stderr']['path']).read_bytes(),b'ordinary numeric diagnostic')
            self.assertTrue(receipt['local_reaped']);self.assertEqual(receipt['remote_closure'],'UNKNOWN')


if __name__=='__main__':unittest.main()

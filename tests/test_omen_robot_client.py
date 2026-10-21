"""Actual local AF_UNIX/UID/read-only file cases; execute only in admitted VM/CI.

The tiny server supplies protocol fixtures, not VM/pointer acceptance. No client
method is overridden. Production fixed socket constants relocate only to the
owned temporary Unix socket for these finite transport cases.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bound_robot_client', ROOT/'scripts/robot_client.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class NativeClientContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rpc-')
        self.root = Path(self.temp.name)
        self.sock = str(self.root/'control.sock')
        self.exchange = self.root/'exchange'; self.exchange.mkdir(mode=0o700)
        self.env = patch.dict(os.environ, {
            'GITHUB_REPOSITORY': M.REPO, 'OPEMOS_SOURCE_SHA': 'a'*40,
            'GITHUB_RUN_ID': '101', 'GITHUB_RUN_ATTEMPT': '2',
            'OPEMOS_ROBOT_CONTROL_SOCKET': self.sock,
            'OPEMOS_ROBOT_REPORT_EXCHANGE': str(self.exchange),
            'OPEMOS_ROBOT_REPORT_DIR': str(self.root/'reports')})
        self.env.start()
        self.constants = patch.multiple(M, SOCKET=self.sock, EXCHANGE=str(self.exchange))
        self.constants.start()
        self.server = None; self.thread = None; self.errors = []; self.requests = []

    def tearDown(self):
        if self.thread:
            self.thread.join(timeout=3)
            self.assertFalse(self.thread.is_alive(), 'owned server thread closure')
        if self.server:
            self.server.close()
        self.constants.stop(); self.env.stop(); self.temp.cleanup()
        self.assertEqual(self.errors, [])

    def serve(self, mutate=None, raw=None):
        self.server = socket.socket(socket.AF_UNIX)
        self.server.bind(self.sock); os.chmod(self.sock, 0o600)
        self.server.listen(1); self.server.settimeout(3)
        def worker():
            try:
                with self.server.accept()[0] as peer:
                    peer.settimeout(3); data = bytearray()
                    while not data.endswith(b'\n'):
                        block = peer.recv(8192)
                        if not block: raise ValueError('request EOF')
                        data.extend(block)
                        if len(data)>65536: raise ValueError('request cap')
                    request = json.loads(data); self.requests.append(request)
                    reply = {'identity': {k:request[k] for k in ('repository','source_commit','run_id','attempt','nonce')},
                             'action':request['action'], 'subject':request['subject'],
                             'status':'passed','scope':'CONNECTION_ONLY_OLD_ARTIFACT_NO_FULLSTACK_ACCEPTANCE',
                             'vms':{},'platforms':{},'public_evidence':[]}
                    if mutate: mutate(reply)
                    wire = raw if raw is not None else json.dumps(reply).encode()+b'\n'
                    try: peer.sendall(wire)
                    except BrokenPipeError: pass  # Expected over-cap/refused client.
            except BaseException as error:
                self.errors.append(repr(error))
        self.thread = threading.Thread(target=worker); self.thread.start()

    def engine(self): return M.Engine(self.root/'private')

    def test_actual_unix_roundtrip_scope_and_closure(self):
        self.serve(); client=self.engine()
        self.assertEqual(client.connection(), {'exports':[]})
        self.assertEqual(self.requests[0]['version'],2)
        self.assertEqual(self.requests[0]['subject'],'ubuntu_native_chooser_connection')
        self.assertEqual(len(self.requests[0]['nonce']),32)
        self.assertTrue(all(v['status']=='unavailable' for v in client.results.values()))

    def test_connection_cannot_promote_other_acceptance(self):
        def mutate(reply):
            reply['vms']={next(iter(self.engine().results)):'passed'}
            reply['platforms']={'windows':'passed','ubuntu':'passed','macos':'passed'}
        self.serve(mutate); client=self.engine(); client.connection()
        self.assertTrue(all(v['status']=='unavailable' for v in client.results.values()))
        self.assertTrue(all(v['status']=='unavailable' for v in client.artifacts.values()))

    def test_wrong_nonce_is_refused(self):
        self.serve(lambda r:r['identity'].update(nonce='b'*32))
        with self.assertRaisesRegex(ValueError,'reply identity'): self.engine().connection()

    def test_wrong_action_is_refused(self):
        self.serve(lambda r:r.update(action='persist'))
        with self.assertRaisesRegex(ValueError,'action/subject'): self.engine().connection()

    def test_connection_scope_missing_is_refused(self):
        self.serve(lambda r:r.pop('scope'))
        with self.assertRaisesRegex(ValueError,'scope missing'): self.engine().connection()

    def test_broker_failed_stays_failed(self):
        self.serve(lambda r:r.update(status='failed'))
        with self.assertRaisesRegex(ValueError,'connection proof failed'): self.engine().connection()

    def typed_failure(self, reply):
        reply.pop('scope')
        reply.update(status='failed', all20_passed=False, all_platforms_passed=False,
                     acceptance='SOURCE_AND_ACTUAL_CASE_ONLY; NO_INFERRED_FULLSTACK_PASS',
                     failure={'kind':'OPEMOS_BROKER_FAILURE_V1', 'code':'ACTIONS_TOKEN_REQUIRED',
                              'reason':M.PUBLIC_FAILURES['ACTIONS_TOKEN_REQUIRED'],
                              'error_type':'ValueError', 'private_recorded':True, 'secondary':[]})

    def test_authenticated_failure_is_durable_before_required_assertion(self):
        self.serve(self.typed_failure)
        with patch.dict(os.environ, {'OPEMOS_REQUIRED_PRODUCER':json.dumps({
                'platform':'ubuntu','producer_run_id':'10','producer_attempt':'2',
                'artifact_id':'30','descriptor_sha256':'b'*64})}):
            client=self.engine()
            with self.assertRaisesRegex(ValueError,'ACTIONS_TOKEN_REQUIRED'):
                client.produced_platform()
        nonce=self.requests[0]['nonce']
        first=client.reports/('broker-failure-'+nonce+'.json')
        required=client.reports/'broker-required.json'
        self.assertEqual(json.loads(first.read_bytes()),json.loads(required.read_bytes()))
        self.assertEqual(first.stat().st_mode & 0o777,0o600)
        self.assertFalse(json.loads(first.read_bytes())['all20_passed'])

    def test_failure_persistence_collision_preserves_first_cause_and_old_data(self):
        self.serve(self.typed_failure);client=self.engine()
        # Actual OS directory collision, not a replacement persistence method.
        (client.reports/'broker-required.json').mkdir()
        with patch.dict(os.environ, {'OPEMOS_REQUIRED_PRODUCER':json.dumps({
                'platform':'ubuntu','producer_run_id':'10','producer_attempt':'2',
                'artifact_id':'30','descriptor_sha256':'b'*64})}):
            with self.assertRaisesRegex(ValueError,'ACTIONS_TOKEN_REQUIRED.*required failure receipt persistence failed'):
                client.produced_platform()
        self.assertTrue((client.reports/'broker-required.json').is_dir())
        self.assertEqual(len(list(client.reports.glob('broker-failure-*.json'))),1)

    def test_unknown_or_reflecting_failure_never_published(self):
        def mutate(reply):
            self.typed_failure(reply);reply['failure']['reason']='untrusted private exception text'
        self.serve(mutate);client=self.engine()
        with self.assertRaisesRegex(ValueError,'strict nonsecret'):
            client.connection()
        self.assertEqual(list(client.reports.glob('broker-failure-*')),[])

    def test_wrong_identity_failure_never_published(self):
        def mutate(reply):
            self.typed_failure(reply);reply['identity']['nonce']='b'*32
        self.serve(mutate);client=self.engine()
        with self.assertRaisesRegex(ValueError,'reply identity'):client.connection()
        self.assertEqual(list(client.reports.glob('broker-failure-*')),[])

    def test_actual_client_to_normal_finalizer_process_preserves_failed_identity(self):
        target={'platform':'ubuntu','producer_run_id':'10','producer_attempt':'2',
                'artifact_id':'30','descriptor_sha256':'b'*64}
        self.serve(self.typed_failure)
        with patch.dict(os.environ, {'OPEMOS_REQUIRED_PRODUCER':json.dumps(target),
                'OPEMOS_ROBOT_REPORT_DIR':str(self.root/'robot-results')}):
            client=self.engine()
            with self.assertRaisesRegex(ValueError,'ACTIONS_TOKEN_REQUIRED'):
                client.produced_platform()
        preflight=self.root/'robot-preflight';preflight.mkdir()
        context={'repository':M.REPO,'source_commit':'a'*40,'target':target,'nonce':'c'*32}
        producer={'source_commit':'a'*40,'platform':'ubuntu'}
        (preflight/'required-context.json').write_text(json.dumps({'context':context,'producer':producer}))
        env=dict(os.environ,GITHUB_SHA='a'*40)
        command=[sys.executable,'-B',str(ROOT/'scripts/required_omen.py'),'finalize-scope']
        child=subprocess.run(command,cwd=self.root,env=env,capture_output=True,timeout=15)
        self.assertEqual(child.returncode,1,child.stderr.decode())
        self.assertIn(b'ACTIONS_TOKEN_REQUIRED',child.stderr)
        result=json.loads((self.root/'required-result/required-result.json').read_bytes())
        self.assertEqual(result['context'],context)
        self.assertEqual(result['producer'],producer)
        self.assertEqual(result['consumer'],{'run_id':'101','attempt':'2'})
        self.assertTrue(result['diagnostic_only']);self.assertFalse(result['actualGUIAccepted'])
        self.assertEqual(result['broker_failure']['code'],'ACTIONS_TOKEN_REQUIRED')
        for name in ('output.xml','report.html','log.html','xunit.xml'):
            self.assertTrue((self.root/'robot-results'/name).is_file())
        self.assertEqual(list(self.root.rglob('*.png')),[])

    def test_duplicate_reply_fields_are_refused(self):
        self.serve(raw=b'{"status":"passed","status":"failed"}\n')
        with self.assertRaisesRegex(ValueError,'duplicate broker'): self.engine().connection()

    def test_truncated_reply_eof_is_refused(self):
        self.serve(raw=b'{"status":"passed"}')
        with self.assertRaisesRegex(ValueError,'reply EOF'): self.engine().connection()

    def test_unknown_vm_refused_before_socket(self):
        with self.assertRaisesRegex(ValueError,'unknown required VM'): self.engine().vm('not-in-inventory')

    def report(self):
        data=b'actual read-only public fixture';name='101-2-current.png'
        p=self.exchange/name;p.write_bytes(data);p.chmod(0o400)
        return p, {'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'kind':'screenshot'}

    def test_readonly_held_report_is_copied(self):
        p,row=self.report();self.serve(lambda r:r.update(public_evidence=[row]))
        result=self.engine().connection();self.assertEqual(len(result['exports']),1)
        self.assertEqual((self.root/'reports'/p.name).read_bytes(),p.read_bytes())

    def test_writable_report_is_refused(self):
        p,row=self.report();p.chmod(0o600);self.serve(lambda r:r.update(public_evidence=[row]))
        with self.assertRaisesRegex(ValueError,'read-only public'): self.engine().connection()

    def test_wrong_report_hash_is_refused(self):
        _,row=self.report();row['sha256']='0'*64;self.serve(lambda r:r.update(public_evidence=[row]))
        with self.assertRaisesRegex(ValueError,'custody/hash'): self.engine().connection()

    def test_report_symlink_is_refused(self):
        p,row=self.report();q=self.exchange/'101-2-link.png';q.symlink_to(p);row['name']=q.name
        self.serve(lambda r:r.update(public_evidence=[row]))
        with self.assertRaises(OSError): self.engine().connection()

    def test_prior_run_report_name_is_refused(self):
        _,row=self.report();row['name']='100-2-prior.png';self.serve(lambda r:r.update(public_evidence=[row]))
        with self.assertRaisesRegex(ValueError,'current report basename'): self.engine().connection()

    def test_preexisting_output_is_not_overwritten(self):
        _,row=self.report();client=self.engine();target=client.reports/row['name'];target.write_bytes(b'keep')
        self.serve(lambda r:r.update(public_evidence=[row]))
        with self.assertRaises(FileExistsError):client.connection()
        self.assertEqual(target.read_bytes(),b'keep')

    def test_group_readable_private_state_is_refused(self):
        private=self.root/'private';private.mkdir(mode=0o750)
        with self.assertRaisesRegex(ValueError,'private current-run'):self.engine()


if __name__=='__main__':unittest.main()

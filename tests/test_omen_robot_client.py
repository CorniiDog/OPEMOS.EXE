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

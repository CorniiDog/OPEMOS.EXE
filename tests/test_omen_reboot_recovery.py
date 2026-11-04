"""Normal consumer tests: external Root/kernel facts are explicitly MODELED.

These exercise real private SQLite writer/rollback/durable-retained behavior.
They cannot prove Root UID, journald, PCI, libvirt or a guest boot. No approval
is fabricated and no method under test is replaced.
"""
import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

SPEC=importlib.util.spec_from_file_location('omen_reboot_recovery',Path(__file__).parents[1]/'scripts/omen_control/reboot_recovery.py')
R=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(R)
JOB='steamos-firstboot-fixture';UNIT='opemos-testq-123456789abc-'+'f'*32+'.service'
OLD='11111111-1111-4111-8111-111111111111';NEW='22222222-2222-4222-8222-222222222222'

class ModeledNativeBoundary:
    """Only the external native-I/O boundary, not consumer/source validation."""
    def __init__(self,db,fault=None):self.db=db;self.fault=fault;self.calls=0
    def __call__(self,job):
        self.calls+=1;epoch=R.ledger(self.db);row,binding,spec=R.selected(epoch,job)
        proof={'kind':'ROOT_HOST_REBOOT_INTERRUPTED_CURRENT_DISPOSITION','job_id':job,
            'epochSHA256':R.sha(R.canonical(epoch).encode()),'binding':binding,'specSHA256':binding['specSHA256'],
            'oldBoot':OLD,'currentBoot':NEW,'journal':[{'_BOOT_ID':OLD.replace('-',''),
            '_SYSTEMD_INVOCATION_ID':binding['invocation'],'_SYSTEMD_UNIT':row['unit'],
            '__REALTIME_TIMESTAMP':str(int((row['started']+1)*1000000))}],
            'domainInventory':[],'unit':{'LoadState':'not-found','ActiveState':'inactive','MainPID':'0','ControlGroup':'','InvocationID':''},
            'wholePoolEmpty':True,'allFourBaselineAndVFIOFDsAbsent':True,'hostIntel':True,
            'originalWholeHashVerified':True,'unknown':[],'allOwnedDescriptorsClosed':True,'effects':[],
            'observedMonotonic':time.monotonic(),'observedUnix':time.time()}
        if self.fault:self.fault(self,proof)
        return proof

class RebootReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.db=sqlite3.connect(self.root/'queue.sqlite3',isolation_level=None);self.db.row_factory=sqlite3.Row
        self.db.executescript('CREATE TABLE jobs(id TEXT PRIMARY KEY,spec TEXT,state TEXT,unit TEXT,cpus TEXT,started REAL,finished REAL,result TEXT);CREATE TABLE pool_unit_bindings(job_id TEXT PRIMARY KEY,value TEXT);CREATE TABLE config(id INTEGER PRIMARY KEY,value TEXT);')
        spec={'id':JOB,'libvirt_domain':{'uuid':OLD},'cores':4,'memory':10737418240,'resources':['omen-iommu-group-1'],'files':[{'sha256':'a'*64,'path':'/lost/old-source.py','bytes':3}]}
        binding={'job_id':JOB,'unit':UNIT,'invocation':'b'*32,'specSHA256':R.sha(R.canonical(spec).encode()),'cpus':[0,1,2,3],'memory':spec['memory'],'recordedAtUnix':100.2}
        self.db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)',(JOB,R.canonical(spec),'running',UNIT,'[0,1,2,3]',100,None,'{"first":"old failure retained"}'))
        self.db.execute('INSERT INTO pool_unit_bindings VALUES(?,?)',(JOB,R.canonical(binding)))
        self.db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)',('queued-independent','{}','pending',None,None,None,None,None))
        self.db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)',('historical','{}','failed',None,None,10,20,'{"original":true}'))
        self.db.execute('INSERT INTO config VALUES(1,?)',('{"cpu_ids":[0,1,2,3,4,5,6,7,8,9],"memory_bytes":34359738368}'))
        self.before=R.ledger(self.db)
    def tearDown(self):self.db.close();self.temp.cleanup()
    def test_normal_private_producer_consumer_preserves_pending_history_and_no_rearm(self):
        native=ModeledNativeBoundary(self.db);result=R.reconcile(self.db,JOB,native,self.root)
        self.assertEqual(native.calls,2);row=next(x for x in R.ledger(self.db)['rows']if x['id']==JOB)
        self.assertEqual(row['state'],'failed');self.assertIsNotNone(row['finished'])
        self.assertEqual(result['terminalLifecycle']['closureDomain'],'CURRENT_BOOT_RECONCILIATION')
        self.assertFalse(result['terminalLifecycle']['reservationRetained'])
        self.assertIsNone(result['historicalQMPClosed']);self.assertIsNone(result['historicalLeaseClosed'])
        self.assertEqual(json.loads(R.read_pin(result['historicalRowPin'],1048576)),self.before['rows'][0])
        after=R.ledger(self.db);self.assertEqual(after['bindings'],self.before['bindings']);self.assertEqual(after['config'],self.before['config'])
        self.assertEqual(after['rows'][1:],self.before['rows'][1:])
        with self.assertRaises(ValueError):R.reconcile(self.db,JOB,native,self.root)
        self.assertEqual(native.calls,2);self.assertEqual(R.ledger(self.db),after)
    def test_native_and_provenance_faults_refuse_before_any_queue_write(self):
        faults={
            'sameboot':lambda p:p.update(currentBoot=OLD),
            'wrongboot':lambda p:p['journal'][0].update(_BOOT_ID='3'*32),
            'wronginvocation':lambda p:p['journal'][0].update(_SYSTEMD_INVOCATION_ID='d'*32),
            'wrongunit':lambda p:p['journal'][0].update(_SYSTEMD_UNIT='foreign.service'),
            'wrongstart':lambda p:p['journal'][0].update(__REALTIME_TIMESTAMP='1'),
            'source':lambda p:p.update(specSHA256='0'*64),
            'binding':lambda p:p['binding'].update(invocation='c'*32),
            'epoch':lambda p:p.update(epochSHA256='0'*64),
            'domain':lambda p:p.update(domainInventory=[{'foreign':True}]),
            'unitreplacement':lambda p:p['unit'].update(InvocationID='c'*32),
            'holder':lambda p:p.update(allFourBaselineAndVFIOFDsAbsent=False),
            'pool':lambda p:p.update(wholePoolEmpty=False),
            'intel':lambda p:p.update(hostIntel=False),
            'originalhash':lambda p:p.update(originalWholeHashVerified=False),
            'unknown':lambda p:p.update(unknown=['unreadable PID']),
            'fd':lambda p:p.update(allOwnedDescriptorsClosed=False)}
        for name,change in faults.items():
            with self.subTest(name=name),tempfile.TemporaryDirectory()as history:
                def fault(boundary,proof):change(proof)
                with self.assertRaises(ValueError):R.reconcile(self.db,JOB,ModeledNativeBoundary(self.db,fault),Path(history))
                self.assertEqual(R.ledger(self.db),self.before)
    def test_first_post_prepare_native_failure_retains_durable_reservation(self):
        def fault(native,proof):
            if native.calls==2:proof['unknown']=['native observation unavailable']
        with self.assertRaises(ValueError):R.reconcile(self.db,JOB,ModeledNativeBoundary(self.db,fault),self.root)
        self.db.close();self.db=sqlite3.connect(self.root/'queue.sqlite3',isolation_level=None);self.db.row_factory=sqlite3.Row
        row=R.ledger(self.db)['rows'][0];self.assertEqual(row['state'],'terminal_cleanup');self.assertIsNone(row['finished'])
        saved=json.loads(row['result']);self.assertTrue(saved['terminalLifecycle']['reservationRetained'])
        self.assertFalse(saved['automaticRetryAuthorized']);self.assertEqual(R.ledger(self.db)['rows'][1:],self.before['rows'][1:])
        continued=self.root/'explicit-continuation';continued.mkdir()
        result=R.reconcile(self.db,JOB,ModeledNativeBoundary(self.db),continued)
        self.assertFalse(result['terminalLifecycle']['reservationRetained'])
        self.assertEqual(json.loads(R.read_pin(result['historicalRowPin'],1048576)),self.before['rows'][0])
        self.assertEqual(R.ledger(self.db)['rows'][0]['state'],'failed')
    def test_expired_final_fence_keeps_pending_not_released(self):
        def fault(native,proof):
            if native.calls==2:proof['observedMonotonic']-=6
        with self.assertRaisesRegex(ValueError,'fresh final native'):R.reconcile(self.db,JOB,ModeledNativeBoundary(self.db,fault),self.root)
        self.assertEqual(R.ledger(self.db)['rows'][0]['state'],'terminal_cleanup')
    def test_real_competing_sqlite_writer_lock_keeps_original_row(self):
        other=sqlite3.connect(self.root/'queue.sqlite3',isolation_level=None);self.db.execute('PRAGMA busy_timeout=1');other.execute('BEGIN IMMEDIATE')
        try:
            with self.assertRaises(sqlite3.OperationalError):R.reconcile(self.db,JOB,ModeledNativeBoundary(self.db),self.root)
        finally:other.rollback();other.close()
        self.assertEqual(R.ledger(self.db),self.before)
    def test_canonical_drift_during_root_capture_cannot_release(self):
        def drift(native,proof):
            if native.calls==1:self.db.execute('UPDATE config SET value=? WHERE id=1',('{"changed":true}',))
        with self.assertRaisesRegex(ValueError,'whole ledger drift'):R.reconcile(self.db,JOB,ModeledNativeBoundary(self.db,drift),self.root)
        self.assertEqual(R.ledger(self.db)['rows'],self.before['rows'])
    def test_cleanup_error_does_not_replace_original_failure(self):
        def close():raise OSError('owned close failed')
        with self.assertRaisesRegex(ValueError,'original native failure')as result:
            with R.closing(close):raise ValueError('original native failure')
        self.assertIn('Owned recovery closure also failed',str(result.exception.__notes__))
    def test_real_pin_symlink_and_replacement_refuse(self):
        path=self.root/'original.json';pin=R.preserve(path,{'original':True})
        self.assertEqual(json.loads(R.read_pin(pin,4096)),{'original':True})
        path.rename(self.root/'retained.json');path.write_text('{"original":true}\n')
        with self.assertRaises(ValueError):R.read_pin(pin,4096)
        path.unlink();path.symlink_to(self.root/'retained.json')
        with self.assertRaises(ValueError):R.read_pin(pin,4096)
    def test_candidate_checkout_entry_cannot_supply_a_privileged_profile(self):
        profile=self.root/'candidate-profile.json';profile.write_text('{}')
        result=subprocess.run([sys.executable,R.__file__,'observe',str(profile),JOB],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'installed Root profile only',result.stderr)
        self.assertEqual(result.stdout,b'')

if __name__=='__main__':unittest.main()

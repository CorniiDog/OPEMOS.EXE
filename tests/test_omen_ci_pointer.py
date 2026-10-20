"""CI9 real-pointer contract faults, synthetic files only, no native GUI claim.

Run in admitted guest/CI; author did not import/execute these project tests.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

HERE=Path(__file__).parent
base_module=module('ci9_case_fixture',HERE/'test_omen_ci.py')
fixture=module('ci9_generated_policy',HERE/'omen_ci_pointer_fixture.py')
exe_fixture=module('ci9_exe_fixture',HERE/'test_omen_ci_executables.py')
S=base_module.stage


class ActualActionContract(unittest.TestCase):
    def setUp(self):
        self.base=base_module.EvidenceAdmission();self.base.setUp();self.addCleanup(self.base.doCleanups)
        self.receipt=self.base.receipt;self.plan=self.base.plan;self.operand=self.base.operand

    def mutate(self,action,change):
        ref=self.receipt['pointer_actions'][action];item=self.receipt['files'][ref]
        path=Path(item['path']);value=json.loads(path.read_bytes());change(value)
        if 'source_context'in value:
            for key in('action','action_id','sequence','identity','session','app','target','point','clock','before','transition_ref','sender_lifecycle_ref','target_observation_ref'):
                value['source_context'][key]=copy.deepcopy(value[key])
        raw=json.dumps(value,sort_keys=True).encode();path.write_bytes(raw);item.update(size=len(raw),sha256=hashlib.sha256(raw).hexdigest());item.pop('_gui_validated_identity',None)

    def mutate_ref(self,ref,change):
        item=self.receipt['files'][ref];path=Path(item['path']);value=json.loads(path.read_bytes());change(value)
        raw=json.dumps(value,sort_keys=True).encode();path.write_bytes(raw);item.update(size=len(raw),sha256=hashlib.sha256(raw).hexdigest());item.pop('_gui_validated_identity',None)

    def read(self,action):return json.loads(Path(self.receipt['files'][self.receipt['pointer_actions'][action]]['path']).read_bytes())
    def validate(self):return S.validate_receipt(self.receipt,'windows-full-stack',self.plan,self.operand)
    def proof(self):return S.validate_gui_pointer(self.receipt,self.plan,self.operand)

    def test_complete_five_action_bytes_pass_policy_with_identical_fresh_frame_pixels(self):
        self.validate();proof=self.proof()
        self.assertEqual(len(proof['actions']),5);self.assertTrue(proof['verified'])
        self.assertTrue(self.read('Build')['source_context']['unknown_future']['retained'])
        frames=[row[side]for row in proof['actions']for side in('before','after')]
        self.assertEqual(len({x['frame_sha256']for x in frames}),1)
        self.assertEqual(len({x['capture_id']for x in frames}),10)
        self.assertEqual(len({json.dumps(x['identity'],sort_keys=True)for x in frames}),10)

    def test_label_png_only_without_actual_action_bytes_is_rejected(self):
        self.receipt.pop('pointer_actions')
        with self.assertRaisesRegex(ValueError,'five required'):self.validate()

    def test_keyboard_ax_dom_and_direct_backend_never_replace_required_activation(self):
        for wrong in('keyboard','AXPress','DOM-click','direct-backend'):
            original=self.read('Build')
            self.mutate('Build',lambda x:x.update(backend=wrong))
            with self.subTest(method=wrong),self.assertRaises(ValueError):self.validate()
            self.mutate('Build',lambda x:(x.clear(),x.update(original)))

    def test_foreign_source_run_attempt_nonce_executable_session_or_action_is_rejected(self):
        for field,value in(('source_commit','0'*40),('run_id','899'),('attempt','2'),('operation_nonce','f'*32)):
            original=self.read('Build');self.mutate('Build',lambda x:x['identity'].update({field:value}))
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate()
            self.mutate('Build',lambda x:(x.clear(),x.update(original)))
        self.mutate('Build',lambda x:x['identity']['executable'].update(executable_sha256='0'*64))
        with self.assertRaises(ValueError):self.validate()

    def test_wrong_app_birth_window_control_and_coordinates_are_rejected(self):
        mutations=(lambda x:x['app']['process'].update(start=999),lambda x:x['app'].update(window_id='foreign'),
            lambda x:x['target'].update(control_id='another-control'),lambda x:x['target'].update(enabled=False),lambda x:x['point'].update(x=63))
        for change in mutations:
            original=self.read('Build');self.mutate('Build',change)
            with self.assertRaises(ValueError):self.validate()
            self.mutate('Build',lambda x:(x.clear(),x.update(original)))

    def test_missing_or_out_of_order_down_up_and_qmp_refusal_cannot_pass(self):
        changes=(lambda x:x['phases'].pop(),lambda x:x['phases'].reverse(),lambda x:x['phases'][1]['response'].update(error={'class':'ActualRefusal'}),
            lambda x:x['phases'][2]['request']['arguments']['events'][0]['data'].update(down=True),lambda x:x.update(click_count=2))
        for change in changes:
            original=self.read('Build');self.mutate('Build',change)
            with self.assertRaises(ValueError):self.validate()
            self.mutate('Build',lambda x:(x.clear(),x.update(original)))

    def test_stale_replayed_acquisition_cross_action_and_cross_clock_refuse(self):
        changes=(lambda x:x['clock'].update(id='foreign-epoch'),lambda x:x['phases'][0].update(sent_tick=0),
            lambda x:x['before'].update(tick=0),lambda x:x.update(action_id=self.read('chooser-open')['action_id']),
            lambda x:x['before'].update(capture_id=self.read('chooser-open')['before']['capture_id']))
        for change in changes:
            original=self.read('Build');self.mutate('Build',change)
            with self.assertRaises(ValueError):self.validate()
            self.mutate('Build',lambda x:(x.clear(),x.update(original)))

    def test_frame_bytes_or_original_ppm_conversion_cannot_be_substituted(self):
        row=self.read('Build');original=row['before']['original_ref'];item=self.receipt['files'][original]
        path=Path(item['path']);raw=bytearray(path.read_bytes());raw[-1]^=1;path.write_bytes(raw)
        item.update(sha256=hashlib.sha256(raw).hexdigest())
        self.mutate_ref(row['before']['capture_ref'],lambda x:x.update(original_sha256=item['sha256']))
        self.mutate_ref(row['before']['conversion_ref'],lambda x:x.update(original_sha256=item['sha256']))
        with self.assertRaisesRegex(ValueError,'RGB bytes'):self.validate()

    def test_sender_numeric_eof_birth_and_closure_unknown_never_pass(self):
        row=self.read('Build');ref=row['sender_lifecycle_ref']
        for field,value in(('numeric_exit',7),('stdout_EOF',False),('original_gone',None)):
            self.mutate_ref(ref,lambda x:x.update({field:value}))
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate()
            self.mutate_ref(ref,lambda x:x.update(numeric_exit=0,stdout_EOF=True,original_gone=True))

    def test_send_success_and_failure_screenshot_do_not_become_build_success(self):
        self.proof() # performed pointer scope is separate from actual Build.
        self.receipt['status']='failed'
        with self.assertRaisesRegex(ValueError,'did not pass'):self.validate()
        self.receipt['status']='passed';row=self.read('Build')
        self.mutate_ref(row['transition_ref'],lambda x:x.update(status='failed'))
        with self.assertRaises(ValueError):self.validate()

    def test_exact_input_write_output_backing_and_device_join_cannot_change(self):
        actions=('chooser-confirm-exact-input','virtualUSB-Write-confirmation')
        for action,field in((actions[0],'input_sha256'),(actions[1],'usb_backing_identity'),(actions[1],'usb_device_identity'),(actions[1],'output_image_sha256')):
            ref=self.read(action)['transition_ref'];original=json.loads(Path(self.receipt['files'][ref]['path']).read_bytes())
            self.mutate_ref(ref,lambda x:x['observation'].update({field:'foreign'}))
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate()
            self.mutate_ref(ref,lambda x:(x.clear(),x.update(original)))

    def test_actual_pointer_proof_is_required_in_same_per_executable_report_path(self):
        values=exe_fixture.expected();windows=next(x for x in values.values()if x['platform']=='windows')
        rows=exe_fixture.outcomes(values);name=S._EXECUTABLES['key'](windows)
        self.plan['nonce']=rows[name]['operation_nonce'];self.receipt['nonce']=self.plan['nonce']
        self.receipt['output']['nonce']=self.plan['nonce'];self.receipt['readiness_fault']['nonce']=self.plan['nonce']
        fixture.attach(S,self.receipt,self.plan,self.operand,Path(self.base.pointer_temp.name)/'joined',expected_executable=windows)
        self.validate();proof=self.proof()
        # This is a synthetic composed shape, not native pointer acceptance.
        rows[name]['pointer_acceptance']=proof
        self.assertEqual(S._EXECUTABLES['report'](values,rows,self.plan['source_commit'],'900','3')['aggregate']['status'],'passed')
        rows[name].pop('pointer_acceptance')
        self.assertEqual(S._EXECUTABLES['report'](values,rows,self.plan['source_commit'],'900','3')['artifacts'][name]['status'],'failed')

    def test_mac_requires_actual_post_observation_and_never_synthetic_delivery_ack(self):
        host=self.receipt['roles']['imaging_host'];host.update(platform='darwin',architecture='arm64')
        fixture.attach(S,self.receipt,self.plan,self.operand,Path(self.base.pointer_temp.name)/'mac','darwin')
        self.proof()
        self.mutate('Build',lambda x:x.update(delivery_ack='delivered'))
        with self.assertRaisesRegex(ValueError,'no delivery ACK'):self.proof()

    def test_same_bytes_frame_replacement_between_validation_and_cache_is_refused(self):
        self.validate();row=self.read('Build');item=self.receipt['files'][row['before']['ref']]
        path=Path(item['path']);replacement=path.with_name('new-identical-acquisition.png')
        replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);replacement.replace(path)
        cache=Path(self.base.pointer_temp.name)/'cache';cache.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'original descriptor'):
            S.retain_pin(item,cache/item['sha256'],1024**2,1024**2)

    def test_pointer_log_replacement_and_unknown_original_fields_stay_unverified(self):
        row=self.read('Build');self.mutate('Build',lambda x:x['app'].update(process={'pid':10,'start':'UNKNOWN'}))
        with self.assertRaises(ValueError):self.validate()
        self.mutate('Build',lambda x:(x.clear(),x.update(row)))
        path=Path(self.receipt['files'][self.receipt['pointer_actions']['Build']]['path']);path.write_bytes(b'{"generic":"replacement"}')
        with self.assertRaises(ValueError):self.validate()

    def test_independently_admitted_actual_destination_and_empty_raw_streams_join_normal_consumer(self):
        self.validate();row=self.read('Build')
        self.assertEqual(row['actual_destination']['observed']['qmp_name'],'synthetic-qmp-host')
        life=json.loads(Path(self.receipt['files'][row['sender_lifecycle_ref']]['path']).read_bytes())
        self.assertEqual(life['raw']['stderr']['size'],0)
        self.assertEqual(life['raw']['stderr']['sha256'],hashlib.sha256(b'').hexdigest())
        self.assertTrue(life['raw']['stdout']['full9_unchanged'])

    def test_actual_foreign_coherent_qmp_destination_cannot_credit_declared_runtime(self):
        self.mutate('Build',lambda row:row['actual_destination']['observed'].update(qmp_name='another-coherent-VM',qemu_process={'pid':999,'start':999}))
        with self.assertRaisesRegex(ValueError,'destination'):self.validate()

    def test_context_before_capture_cannot_substitute_same_pixels_other_acquisition(self):
        self.mutate('Build',lambda row:row['source_context'].update(before_capture_path=self.receipt['files'][self.read('chooser-open')['before']['capture_ref']]['path']))
        with self.assertRaisesRegex(ValueError,'before acquisition'):self.validate()

    def test_destination_admission_must_be_independently_pinned_not_context_labels(self):
        self.operand['gui_destination_admission']['sha256']='0'*64
        with self.assertRaises(ValueError):self.validate()

    def test_missing_or_replaced_required_reserved_inode_never_passes(self):
        self.mutate('Build',lambda row:row['output_reservations']['sender_lifecycle_path']['created_identity'].update(st_ino=987654))
        with self.assertRaisesRegex(ValueError,'reserved'):self.validate()

    def test_sender_raw_bytes_must_survive_not_only_hashes_or_fabricated_nonempty(self):
        row=self.read('Build');context=row['source_context'];ref=context['sender_stderr_ref'];item=self.receipt['files'][ref]
        Path(item['path']).write_bytes(b'original sender failure not an ACK')
        item.update(size=Path(item['path']).stat().st_size,sha256=hashlib.sha256(Path(item['path']).read_bytes()).hexdigest())
        with self.assertRaisesRegex(ValueError,'raw sender'):self.validate()

    def test_raw_empty_is_allowed_only_for_typed_truthful_stream_pin(self):
        item={'size':0,'sha256':hashlib.sha256(b'').hexdigest(),'kind':'pointer-sender-stderr'}
        self.assertTrue(S.pointer_evidence_size(item));item['kind']='log';self.assertFalse(S.pointer_evidence_size(item))
        item.update(kind='pointer-sender-stdout',sha256='0'*64);self.assertFalse(S.pointer_evidence_size(item))

    def test_attempted_request_lost_reply_prefix_remains_failed_in_normal_consumer(self):
        self.mutate('Build',lambda row:(row.update(status='failed'),row['phases'][1].update(response={'UNKNOWN':True},returned_tick=None,delivery='UNKNOWN')))
        with self.assertRaises(ValueError):self.validate()
        row=self.read('Build');self.assertEqual(row['phases'][1]['request']['execute'],'input-send-event')
        self.assertEqual(row['phases'][1]['response'],{'UNKNOWN':True})

    def test_raw_or_destination_failure_cannot_supply_per_executable_acceptance(self):
        self.validate();proof=self.proof();values=exe_fixture.expected();rows=exe_fixture.outcomes(values)
        windows=next(value for value in values.values()if value['platform']=='windows');key=S._EXECUTABLES['key'](windows)
        rows[key].pop('pointer_acceptance',None)
        self.assertEqual(S._EXECUTABLES['report'](values,rows,self.plan['source_commit'],'900','3')['artifacts'][key]['status'],'failed')

    def test_truthful_empty_raw_retention_and_cached_target_custody_remain_bound(self):
        self.validate();row=self.read('Build');item=self.receipt['files'][row['source_context']['sender_stderr_ref']]
        cache=Path(self.base.pointer_temp.name)/'empty-raw-cache';cache.mkdir(mode=0o700);target=cache/item['sha256']
        count,pin=S.retain_pin(item,target,1024**2,1024**2);self.assertEqual(count,0);self.assertEqual(target.read_bytes(),b'')
        count,pin=S.retain_pin(item,target,1024**2,1024**2);self.assertEqual(count,0)
        target.write_bytes(b'foreign cached bytes')
        with self.assertRaises(ValueError):S.retain_pin(item,target,1024**2,1024**2)


if __name__=='__main__':unittest.main()

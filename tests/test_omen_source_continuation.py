"""UNRUN: only execute in admitted OMEN VMs.

Metadata cases prove the finite schema, not native/VM properties. Real capture
cases use actual children and files, never override capture or the validator.
They are not the required complete normal source workload/Root transaction.
"""
import copy
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
from omen_source_capture import capture
from omen_source_ci import reports
from omen_source_workloads import (WORKLOADS,commands,dependencies,command_status,
    blocked_command,verify_diagnostics,verify_result)


def metadata_result(workload='rust'):
    """Explicit schema fixtures, not invented real executions."""
    spec={'workload':workload,'controller_commit':'a'*40,'candidate_commit':'b'*40}
    identity={'nonce':'metadata-only'}
    rows=[]
    for i,argv in enumerate(commands(workload,'b'*40)):
        rows.append({'template_argv':argv,'status':'passed','numeric_exit':0,
            'first':None,'secondary':[],'pid':100+i,'birth':123,
            **{k:True for k in('reaped','stdoutEOF','stderrEOF','FDsClosed','descendantsAbsent')},
            **{k:{'sha256':hashlib.sha256(b'').hexdigest(),'bytes':0}for k in('stdout','stderr')}})
    value={'kind':'OMEN_GUEST_SOURCE_WORKLOAD_V1','identity':identity,'subject':spec,
        'guest':{'location':'OMEN_VM','virtualization':'qemu','platform':WORKLOADS[workload][0],
            'boot_id':'metadata-only','uid':'S-1-5-21-1-2-3-1000'if workload=='windows-build'else 1000,
            'controller_commit':'a'*40,'candidate_commit':'b'*40},
        'commands':rows,'status':'passed','first':None,'secondary':[]}
    return value,identity,spec


class FiniteOutcomeMetadata(unittest.TestCase):
    def test_every_existing_command_has_explicit_backward_only_dependencies(self):
        for workload in WORKLOADS:
            with self.subTest(workload=workload):
                value,identity,spec=metadata_result(workload)
                self.assertEqual(len(dependencies(workload)),len(value['commands']))
                self.assertEqual(verify_result(value,identity,spec),value)

    def test_ordinary_first_failure_and_later_independent_pass_remain_overall_failed(self):
        value,identity,spec=metadata_result()
        value['commands'][0].update(numeric_exit=7,status='failed')
        value.update(status='failed',first={'command_index':0,'numeric_exit':7})
        self.assertEqual(verify_diagnostics(value,identity,spec),value)
        self.assertEqual(value['commands'][3]['status'],'passed')
        with self.assertRaises(ValueError):verify_result(value,identity,spec)
        bad=copy.deepcopy(value);bad['status']='passed'
        with self.assertRaises(ValueError):verify_diagnostics(bad,identity,spec)

    def test_failed_npm_blocks_only_build_consumers_not_other_checks(self):
        for workload,index in(('frontend-and-docs',0),('windows-build',1),('macos-build',0),('appimage-package',0)):
            with self.subTest(workload=workload):
                value,identity,spec=metadata_result(workload);rows=value['commands'];graph=dependencies(workload)
                rows[index].update(numeric_exit=1,status='failed')
                for i in range(index+1,len(rows)):
                    if any(rows[p]['status']!='passed'for p in graph[i]):
                        rows[i]=blocked_command(rows[i]['template_argv'],graph[i],rows)
                value.update(status='failed',first={'command_index':index})
                verify_diagnostics(value,identity,spec)
                if workload=='windows-build':
                    self.assertEqual(rows[6]['status'],'passed');self.assertEqual(rows[8]['blocked_by'],[7])
                if workload=='macos-build':self.assertEqual(rows[4]['status'],'passed')

    def test_capture_unknown_overflow_signal_timeout_and_cleanup_are_hard_not_ordinary(self):
        value,_,_=metadata_result();base=value['commands'][0]
        faults=[{'numeric_exit':-15},{'birth':'UNKNOWN'},{'FDsClosed':False},
            {'first':{'reason':'timeout'}},{'secondary':[{'reason':'cleanup'}]},
            {'stdout':{'bytes':32*1024**2+1,'sha256':'a'*64}}]
        for change in faults:
            with self.subTest(change=change):self.assertEqual(command_status(dict(base,**change)),'hard-failed')

    def test_hard_stop_blocks_all_remaining_and_rejects_a_later_attempt(self):
        value,identity,spec=metadata_result();rows=value['commands'];graph=dependencies('rust')
        rows[0].update(status='hard-failed',first={'reason':'capture deadline'},numeric_exit=-15)
        value.update(status='failed',first={'command_index':0,'reason':'capture deadline'})
        for i in range(1,len(rows)):rows[i]=blocked_command(rows[i]['template_argv'],graph[i],rows,'Hard stop: capture deadline')
        verify_diagnostics(value,identity,spec)
        bad=copy.deepcopy(value);bad['commands'][2]=metadata_result()[0]['commands'][2]
        with self.assertRaises(ValueError):verify_diagnostics(bad,identity,spec)

    def test_no_silent_omission_fake_block_or_nonzero_pass(self):
        value,identity,spec=metadata_result()
        for mutate in('omit','fakeblock','exit'):
            bad=copy.deepcopy(value)
            if mutate=='omit':bad['commands'].pop()
            elif mutate=='exit':bad['commands'][0]['numeric_exit']=1
            else:bad['commands'][1]={'template_argv':bad['commands'][1]['template_argv'],
                'status':'blocked','numeric_exit':None,'blocked_by':[],'stop_reason':None}
            with self.assertRaises(ValueError):verify_diagnostics(bad,identity,spec)

    def test_report_retains_failed_passed_and_blocked_and_finalizer_failure(self):
        value,_,_=metadata_result('frontend-and-docs');rows=value['commands']
        rows[0].update(status='failed',numeric_exit=1)
        rows[1]=blocked_command(rows[1]['template_argv'],dependencies('frontend-and-docs')[1],rows)
        with tempfile.TemporaryDirectory()as d:
            reports(d,value,'original failure')
            suite=ET.parse(Path(d)/'xunit.xml').getroot()
            self.assertEqual((suite.get('tests'),suite.get('failures'),suite.get('skipped')),('3','1','1'))
            self.assertEqual(len(suite.findall('testcase/failure')),1)
            self.assertEqual(len(suite.findall('testcase/skipped')),1)
            self.assertIn('blocked_by',(Path(d)/'report.html').read_text())
        with tempfile.TemporaryDirectory()as d:
            reports(d,metadata_result()[0],'actual Root closure failure')
            suite=ET.parse(Path(d)/'xunit.xml').getroot();self.assertEqual(suite.get('failures'),'1')


class RealCaptureContinuationBoundary(unittest.TestCase):
    def test_actual_nonzero_then_independent_child_and_truthful_report(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);rows=[]
            for i,code in enumerate((7,0,3)):
                argv=[sys.executable,'-I','-c',"import sys;print('actual child');print('retained stderr',file=sys.stderr);sys.exit("+str(code)+")"]
                row=capture(argv,root,dict(os.environ),root/('child-'+str(i)),15)
                row['status']=command_status(row);row['template_argv']=argv;rows.append(row)
                self.assertEqual(row['numeric_exit'],code)
                self.assertEqual(row['status'],'passed'if code==0 else'failed')
                self.assertIsNone(row['first']);self.assertEqual(row['secondary'],[])
                for name in('stdout','stderr'):
                    raw=Path(row[name]['path']).read_bytes()
                    self.assertEqual(hashlib.sha256(raw).hexdigest(),row[name]['sha256'])
            out=root/'report';out.mkdir();reports(out,{'commands':rows},'two real nonzero exits')
            suite=ET.parse(out/'xunit.xml').getroot()
            self.assertEqual((suite.get('tests'),suite.get('failures')),('3','2'))
            self.assertNotEqual(rows[0]['pid'],rows[1]['pid'])


if __name__=='__main__':unittest.main()

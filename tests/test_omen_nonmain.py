"""UNRUN. Execute inside OMEN. Metadata fixtures prove no OS/VM property."""
import copy
import json
from pathlib import Path
import sys
import unittest
import base64
import hashlib
import time

sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
from omen_ci_executables import source_roles,descriptor
from required_omen import candidate_identity
from omen_source_workloads import selection
from omen_robot_gate import controller_selection
from omen_source_guard import validate_controller
from omen_robot import identity

REPO='CorniiDog/OPEMOS.EXE';A='a'*40;B='b'*40

def branch():
    return {'repository':REPO,'controller_commit':A,'candidate_commit':B,'base_commit':A,
        'repository_id':7,'head_repository_id':7,'pull_request':0,
        'source_kind':'branch','source_ref':'refs/heads/feature/normal'}


class NonMainMetadataOnly(unittest.TestCase):
    def test_branch_same_content_retains_distinct_ref_role_through_actual_robot_identity(self):
        roles=dict(branch(),candidate_commit=A)
        value=identity({'GITHUB_REPOSITORY':REPO,'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1',
            'OPEMOS_SOURCE_SHA':A,'OPEMOS_CONTROLLER_SHA':A,'OPEMOS_SOURCE_ROLES':json.dumps(roles)})
        self.assertEqual(value['source_roles'],roles)
        legacy={k:v for k,v in roles.items()if k not in('source_kind','source_ref')}
        legacy['pull_request']=210
        with self.assertRaises(ValueError):identity({'GITHUB_REPOSITORY':REPO,'GITHUB_RUN_ID':'1',
            'GITHUB_RUN_ATTEMPT':'1','OPEMOS_SOURCE_SHA':A,'OPEMOS_CONTROLLER_SHA':A,
            'OPEMOS_SOURCE_ROLES':json.dumps(legacy)})

    def test_reviewed_nonmain_controller_is_not_candidate_privilege_or_Main_merge(self):
        raw=b'fixed reviewed workflow bytes';now=int(time.time())
        q={'kind':'ROOT_REVIEWED_TEST_CONTROLLER_V1','control_commit':A,'implementation_commit':B,
           'workflow_ref':REPO+'/.github/workflows/omen-robot.yml@refs/heads/reviewed-control',
           'workflow_sha256':hashlib.sha256(raw).hexdigest(),'source_graph_sha256':'c'*64,
           'review_receipt_sha256':'d'*64}
        state={'source_commit':A,'checked_at':now,'expires_at':now+180,'controller_qualification':q}
        env={'GITHUB_REPOSITORY':REPO,'GITHUB_SHA':B,'GITHUB_WORKFLOW_SHA':B,'GITHUB_REF':'refs/heads/reviewed-control',
             'GITHUB_REF_PROTECTED':'false','GITHUB_WORKFLOW_REF':q['workflow_ref'],
             'OPEMOS_OMEN_ROBOT_RUNNER_STATE':json.dumps(state)}
        def read(path):
            if path=='branches/main':return {'protected':True,'commit':{'sha':A}}
            self.assertEqual(path,'contents/.github/workflows/omen-robot.yml?ref='+B)
            return {'encoding':'base64','size':len(raw),'content':base64.b64encode(raw).decode()}
        execution=controller_selection(read,env)
        run={'id':1,'run_attempt':2,'repository':{'id':7,'full_name':REPO},'head_repository':{'id':7,'full_name':REPO},
             'path':'.github/workflows/omen-robot.yml','event':'workflow_dispatch','head_sha':B,'head_branch':'reviewed-control'}
        job={'id':3,'run_id':1,'status':'in_progress','name':'required-platform-robot'}
        profile={'schema':'FINITE_VM_ONLY_V1','enabled':True,'controller_commit':A,'controller_qualification':q}
        value=validate_controller(run,job,execution,raw,profile)
        self.assertIs(value['runtimeAuthorized'],False)
        self.assertEqual(value['allowed_actions'],['execute-produced-platform'])
        # A public heartbeat cannot change Root's independently held profile.
        with self.assertRaises(ValueError):validate_controller(run,job,execution,raw,
            dict(profile,controller_qualification=dict(q,review_receipt_sha256='e'*64)))
        with self.assertRaises(ValueError):validate_controller(run,job,execution,raw,dict(profile,enabled=False))
        for bad in(dict(env,OPEMOS_OMEN_ROBOT_RUNNER_STATE='{}'),dict(env,GITHUB_SHA='f'*40),
                   dict(env,OPEMOS_OMEN_ROBOT_RUNNER_STATE=json.dumps(dict(state,checked_at=now-181,expires_at=now-1)))):
            with self.assertRaises(ValueError):controller_selection(read,bad)

    def test_branch_without_PR_uses_actual_ref_endpoint_and_current_A(self):
        roles=branch();reads=[]
        def read(path):
            reads.append(path)
            return {'branches/main':{'protected':True,'commit':{'sha':A}},
                '':{'id':7,'full_name':REPO,'fork':False},
                'git/ref/heads/feature/normal':{'ref':roles['source_ref'],'object':{'type':'commit','sha':B}}}[path]
        self.assertEqual(candidate_identity(roles,read),roles)
        self.assertNotIn('pulls/0',reads)

    def test_branch_move_delete_foreign_and_control_movement_refuse(self):
        for fault in('branch','controller','foreign','deleted'):
            with self.subTest(fault=fault):
                r=branch()
                def read(path):
                    if path=='branches/main':return {'protected':True,'commit':{'sha':'c'*40 if fault=='controller'else A}}
                    if path=='':return {'id':9 if fault=='foreign'else 7,'full_name':REPO,'fork':False}
                    if fault=='deleted':raise KeyError('actual ref unavailable')
                    return {'ref':r['source_ref'],'object':{'type':'commit','sha':'c'*40 if fault=='branch'else B}}
                with self.assertRaises((ValueError,KeyError)):candidate_identity(r,read)

    def test_discriminated_roles_preserve_legacy_PR_and_no_invented_branch_PR(self):
        r=branch();self.assertEqual(source_roles(r,controller=A,candidate=B),r)
        old={k:v for k,v in r.items()if k not in('source_kind','source_ref')};old['pull_request']=210
        self.assertEqual(source_roles(old),old)
        for key,value in(('pull_request',210),('head_repository_id',8),('source_ref','refs/heads/../main'),
                          ('source_ref','refs/heads/main')):
            bad=dict(r,**{key:value})
            with self.assertRaises(ValueError):source_roles(bad)

    def test_source_event_matrix_original_ref_and_workflow_not_rewritten(self):
        for event in('push','workflow_dispatch','pull_request'):
            for workload,path in(('windows-build','windows-portable.yml'),('appimage-package','ubuntu-executable.yml'),
                                  ('macos-build','macos-arm64.yml')):
                with self.subTest(event=event,workload=workload):
                    r=branch();r.update(workload=workload,candidate_tree='c'*40,parent_run='1',parent_attempt='2',
                        parent_workflow='.github/workflows/'+path,producer_event=event,
                        producer_ref=r['source_ref'],workflow_commit=B)
                    if event=='pull_request':
                        r.pop('source_kind');r.pop('source_ref');r.update(pull_request=210,
                            producer_ref='refs/pull/210/merge',workflow_commit='d'*40)
                    self.assertEqual(selection(r,A),r)
                    bad=dict(r,producer_ref='refs/heads/main')
                    with self.assertRaises(ValueError):selection(bad,A)

    def test_producers_complete_before_separate_controller_no_wait_or_write(self):
        root=Path(__file__).parents[1]
        for file in('windows-portable.yml','ubuntu-executable.yml','macos-arm64.yml'):
            text=(root/'.github/workflows'/file).read_text()
            self.assertIn('pending-reviewed-controller',text)
            self.assertNotIn('dispatch-and-wait',text);self.assertNotIn('actions: write',text)
            self.assertNotIn('Non-Main/PR/fork source is not admitted',text)
            self.assertNotIn('runs-on: macos-',text)
        controller=(root/'.github/workflows/omen-robot.yml').read_text()
        self.assertIn('types: [completed]',controller);self.assertIn('candidate_ref:',controller)

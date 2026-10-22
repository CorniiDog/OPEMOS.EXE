#!/usr/bin/env python3
"""Fixed, fail-closed OMEN Robot plan hook. No guest control or queue effects.

The Root-owned installed profile pins this hook and an exact UID1000 registry. A complete
operation may be supplied only by that registry for the exact consumer run.
The normal stage performs the independent queue/source/admission checks.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import xml.etree.ElementTree as ET

PROFILE = Path.home() / '.config/opemos-ci/robot.json'
REGISTRY = Path.home() / '.config/opemos-ci/robot-jobs.json'
FULL9 = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
REPO = 'CorniiDog/OPEMOS.EXE'
SHA = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
NUM = re.compile(r'[1-9][0-9]{0,19}\Z')
NONCE = re.compile(r'[0-9a-f]{32}\Z')

def roles(r):
    value=r.get('source_roles')
    if value is None:
        need('controller_source_commit'not in r,'controller without candidate role binding')
        return None
    need(type(value)is dict and set(value)=={'repository','controller_commit','candidate_commit',
         'pull_request','base_commit','repository_id','head_repository_id'},'finite A/B roles')
    need(value['repository']==REPO and
         all(type(value[k])is str and COMMIT.fullmatch(value[k])for k in('controller_commit','candidate_commit','base_commit'))and
         value['controller_commit']==value['base_commit']==r['controller_source_commit']and
         value['candidate_commit']==r['source_commit']!=value['controller_commit']and
         type(value['pull_request'])is int and 0<value['pull_request']<2**31 and
         all(type(value[k])is int and value[k]>0 for k in('repository_id','head_repository_id'))and
         value['repository_id']==value['head_repository_id'],'exact same-repository A/B identity')
    need(r['kind']=='artifact','candidate only for exact admitted artifact')
    return value

def need(condition, message):
    if not condition:
        raise ValueError(message)

def strict(data):
    def pairs(items):
        obj = {}
        for key, value in items:
            need(key not in obj, 'duplicate JSON field')
            obj[key] = value
        return obj
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))

def held(path, cap, digest=None, owner=None):
    path = Path(path)
    need(path.is_absolute(), 'absolute pinned file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        sig = lambda s: tuple(getattr(s, k) for k in FULL9)
        need(stat.S_ISREG(before.st_mode) and
             before.st_uid == (os.getuid() if owner is None else owner)
             and before.st_nlink == 1 and not before.st_mode & 0o022
             and before.st_size <= cap, 'unsafe owned file')
        raw = bytearray()
        while chunk := os.read(fd, min(65536, cap + 1 - len(raw))):
            raw.extend(chunk)
            need(len(raw) <= cap, 'file cap exceeded')
        need(len(raw) == before.st_size and
             sig(before) == sig(os.fstat(fd)) == sig(path.lstat()),
             'held file identity drift')
        need(digest is None or hashlib.sha256(raw).hexdigest() == digest,
             'file SHA mismatch')
        return bytes(raw)
    finally:
        os.close(fd)

def request():
    raw = sys.stdin.buffer.read(65537)
    need(len(raw) <= 65536, 'request cap exceeded')
    r = strict(raw)
    fields={
        'version','action','kind','subject','repository','source_commit',
        'run_id','attempt','nonce','consumer_started_epoch'}
    need(type(r) is dict and set(r) in(fields,fields|{'controller_source_commit','source_roles'}),
        'exact Robot request schema required')
    need(r['version'] == 1 and r['repository'] == REPO and
         COMMIT.fullmatch(r['source_commit']) and
         NUM.fullmatch(r['run_id']) and NUM.fullmatch(r['attempt']) and
         NONCE.fullmatch(r['nonce']) and
         type(r['consumer_started_epoch']) is int and
         r['consumer_started_epoch'] > 0,
         'exact protected consumer identity required')
    need(r['action'] in ('prepare','collect') and
         r['kind'] in ('inventory','artifacts','artifact'),
         'unsupported fixed action/kind')
    roles(r)
    return r

def key(r):
    value={field:r[field] for field in('repository','source_commit','run_id','attempt','nonce')}
    if roles(r)is not None:value.update(controller_source_commit=r['controller_source_commit'],source_roles=r['source_roles'])
    return value

def registered(pin, r, required):
    """Only a pre-pinned whole response for this exact run can become available."""
    if pin is None:
        return None
    fields={'path','sha256','run_id','attempt','nonce','source_commit'}
    if roles(r)is not None:fields|={'controller_source_commit','source_roles'}
    need(type(pin) is dict and set(pin) == fields,
         'complete fixed operation registry pin required')
    if not all(pin[k] == r[k] for k in
               ('run_id','attempt','nonce','source_commit')):
        return None
    if roles(r)is not None:
        need(all(pin[k]==r[k]for k in('controller_source_commit','source_roles')),'registered A/B source binding differs')
    need(type(pin['sha256']) is str and SHA.fullmatch(pin['sha256']),
         'operation SHA invalid')
    response = strict(held(pin['path'], 8*1048576, pin['sha256']))
    need(response.get('identity') == key(r) and
         response.get('available') is True and
         all(k in response for k in required),
         'registered normal operation incomplete or stale')
    return response

def collect(profile, r, prepared):
    """Actual normal queue + held output reader, not a prewritten pass packet.

    Root adopts this same finite hook and its explicit current-A stage path.
    The registry/operation pin is unchanged during the operation. Only current
    normal jobs and their ordinary output files are observed; never submit,
    rerun, expire, mutate the queue, or execute a candidate script here.
    """
    stage_pin=profile['stage'];path=Path(stage_pin['path'])
    need(path.is_absolute()and path.resolve()==path and path.name=='omen_ci_stage.py',
         'explicit current-A installed stage path')
    # The stage seals its complete dependency graph before its normal queue
    # reader executes. This exact Root profile pin is not a request parameter.
    # The existing stage/reader dependency graph runs as the hook UID and
    # requires that same actual owner. Root owns the profile/hash authority,
    # not a mismatched-UID copy of one file in an otherwise user-owned graph.
    source=held(path,8*1048576,stage_pin['sha256'],owner=os.getuid())
    ns={'__name__':'root_existing_readonly_collector','__file__':str(path)}
    exec(compile(source,str(path),'exec'),ns)
    cfg=ns['load_pinned'](prepared['config'])
    rows=ns['queue_status'](cfg)
    operand=prepared['operand'];robot=prepared['robot_job']
    ids=list(operand['job_ids'])
    for extra in prepared.get('additional_operations',[]):ids.extend(extra['job_ids'])
    need(ids and len(ids)==len(set(ids))and robot['job_id']in ids,'exact complete current job set')
    need(ns['closed_jobs'](ids,rows),'ordinary jobs not terminal; no collection retry or control effect')
    closures=[]
    for job in ids:
        live=rows[job];life=(live.get('result')or{}).get('terminalLifecycle',{})
        group=life.get('postStopCgroupProof',{});pool=life.get('postStopPoolProof',{})
        closures.append(life.get('phase')=='CLOSED'and group.get('completeTraversal')is True and
            group.get('includesUID0')is True and group.get('empty')is True and group.get('processes')==[]and
            pool.get('admitted')is True and pool.get('allOwnedDescriptorsClosed')is True)
        need(type(live.get('started'))in(int,float)and live['started']>=r['consumer_started_epoch']and
             type(live.get('finished'))in(int,float)and live['started']<=live['finished'],
             'old/untimed normal queue job cannot cover this consumer')
    receipt,receipt_sha=ns['load_result'](operand['receipt'],cfg['result_contract']['max_bytes'])
    proof,proof_sha=ns['load_result'](robot['result_path'],cfg['result_contract']['max_bytes'])
    expected=dict(r,action='prepare')
    need(proof.get('identity')==expected and all(receipt.get(k)==r[k]for k in('source_commit','run_id','attempt'))and
         receipt.get('nonce')==prepared['plan']['nonce'],'current actual receipt/Robot identity differs')
    if roles(r)is not None:
        need(all(x.get('source_roles')==r['source_roles']and x.get('controller_source_commit')==r['controller_source_commit']
                 for x in(receipt,prepared['plan'])),'collector lost controller A / candidate B')
    public=[x for x in receipt.get('files',{}).values()if x.get('public')is True]
    public.extend(x for x in proof.get('reports',[])if x.get('public')is True)
    # Read the actual retained RF report, not just numeric flags in JSON.
    outputs=[x for x in proof.get('reports',[])if x.get('kind')=='robot-output']
    need(len(outputs)==1,'one actual ordinary Robot output')
    row=outputs[0];pin,raw=ns['_READER'].read_verified(row['path'],16*1048576,
        expected_sha=row['sha256'],expected_size=row.get('size'),uid=os.getuid())
    need(pin['identity']==row['identity'],'Robot report full9 changed')
    xml=ET.fromstring(raw);tests=xml.findall('.//test')
    need(xml.tag=='robot'and xml.attrib.get('generator','').startswith('Robot')and tests,
         'actual Robot XML, not unavailable diagnostic')
    failed=sum(test.find('status')is None or test.find('status').attrib.get('status')!='PASS'for test in tests)
    need(type(proof.get('tests_failed'))is int and proof['tests_failed']==failed and
         type(proof.get('numeric_exit'))is int and (proof['numeric_exit']==0)==(failed==0),
         'actual Robot XML/exit result differs')
    return {'identity':key(r),'available':True,'effect':'READ_ONLY_CURRENT_OPERATION',
        'job_ids':ids,'queue_job_id':robot['job_id'],
        'queue_state':'passed'if all(rows[j]['state']=='passed'for j in ids)else'failed',
        'queue_lifecycle_closed':all(closures),'closure':'CLOSED'if all(closures)else'UNKNOWN',
        'receipt_path':operand['receipt'],'receipt_sha256':receipt_sha,
        'robot_result_path':robot['result_path'],'robot_result_sha256':proof_sha,'public_evidence':public}

def main():
    r = request()
    p = strict(held(PROFILE, 1048576, owner=0))
    need(p.get('schema') == 1 and p.get('enabled') is True,
         'installed Root profile disabled')
    pin = p.get('fixed_registry', {})
    need(pin.get('path') == str(REGISTRY) and
         isinstance(pin.get('sha256'), str) and SHA.fullmatch(pin['sha256']),
         'fixed Root registry pin missing')
    registry = strict(held(REGISTRY, 4*1048576, pin['sha256']))
    need(registry.get('schema') == 1 and registry.get('repository') == REPO,
         'fixed registry schema/repository mismatch')
    cases = registry.get('cases')
    need(type(cases) is dict and len(cases) == 20,
         'all20 explicit fixed cases required')
    source = registry.get('source_commit')
    need(type(source) is str and COMMIT.fullmatch(source),
         'registry protected source pin missing')
    need(type(registry.get('artifacts')) is dict and
         set(registry['artifacts']) == {'windows','ubuntu','macos'} and
         all(type(row) is dict and type(row.get('reason')) is str and
             bool(row['reason']) for row in registry['artifacts'].values()),
         'all three protected producer states required')
    if r['kind'] == 'inventory':
        need(type(r['subject']) is str and r['subject'] in cases,
             'inventory subject outside exact20')
    elif r['kind'] == 'artifacts':
        need(type(r['subject']) is str and
             r['subject'] in registry['artifacts'],
             'unknown protected producer platform')
    else:
        need(type(r['subject']) is dict and
             set(r['subject']) == {'platform','artifact_id'} and
             r['subject']['platform'] in registry['artifacts'] and
             type(r['subject']['artifact_id']) is str and
             bool(r['subject']['artifact_id']),
             'exact artifact identity required')
    identity = key(r)
    if r.get('controller_source_commit',r['source_commit']) != source:
        result = {'identity':identity,'available':False,
                  'reason':'Root registry source differs from current protected consumer; fresh source and producer reconciliation required'}
    elif r['action'] == 'collect':
        if r['kind']=='inventory':pin=cases[r['subject']].get('operation')
        elif r['kind']=='artifact':pin=registry['artifacts'][r['subject']['platform']].get('operations',{}).get(r['subject']['artifact_id'])
        else:pin=None
        prepared=registered(pin,r,('config','operand','plan','robot_job'))
        need(prepared is not None,'no exact registered ordinary operation to collect')
        result=collect(p,r,prepared)
    elif r['kind'] == 'inventory':
        row = cases[r['subject']]
        need(type(row) is dict and type(row.get('reason')) is str and row['reason'],
             'explicit per-case blocker absent')
        result = {'identity':identity,'available':False,'reason':row['reason']}
        result = registered(row.get('operation'), r,
                            ('config','operand','plan','staging_path','robot_job')) or result
    elif r['kind'] == 'artifacts':
        row = registry['artifacts'][r['subject']]
        result = {'identity':identity,'available':False,'reason':row['reason']}
        result = registered(row.get('listing'), r,
                            ('expected_executables',)) or result
    else:
        row = registry['artifacts'][r['subject']['platform']]
        result = {'identity':identity,'available':False,'reason':row['reason']}
        result = registered(row.get('operations',{}).get(r['subject']['artifact_id']),
                            r, ('config','operand','plan','staging_path','robot_job',
                                'expected','executable_entry','additional_operations',
                                'executable_transaction_path')) or result
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(',',':'))+'\n')

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('fixed Robot planner refusal: '+str(exc), file=sys.stderr)
        sys.exit(1)

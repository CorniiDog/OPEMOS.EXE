#!/usr/bin/env python3
"""Installed ordinary queue job step, executed ONLY in its admitted case lane."""
import hashlib
import json
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0,str(Path(__file__).parent))
from omen_robot import raw_file,strict,require,dump,FULL9


def main():
    import robot
    require(len(sys.argv)==5,'Usage: identity.json identity-sha suite output-directory')
    request=strict(raw_file(sys.argv[1],1048576,sys.argv[2],os.getuid()))
    output=Path(sys.argv[4]);require(output.is_absolute()and output.parent.resolve()==output.parent and not os.path.lexists(output),'Fresh exact owned Robot output required')
    output.mkdir(mode=0o700)
    suite=Path(sys.argv[3]);require(suite.name in ('guest.robot','role.robot'),'Only installed reviewed case suites')
    for key,value in request.items():
        if key in ('run_id','attempt'):require(os.environ[{'run_id':'GITHUB_RUN_ID','attempt':'GITHUB_RUN_ATTEMPT'}[key]]==value,'Consumer identity mismatch')
    require(os.environ['OPEMOS_SOURCE_SHA']==request['source_commit']and os.environ['OPEMOS_TRANSACTION_NONCE']==request['nonce'],'Stale guest job source/nonce')
    code=robot.run(str(suite),outputdir=str(output),output='output.xml',report='report.html',log='log.html',xunit='xunit.xml')
    reports=[];raw=raw_file(output/'output.xml',16*1024**2,owner=os.getuid());tree=ET.fromstring(raw)
    statuses=[test.find('status').attrib['status']for test in tree.findall('.//test')]
    clicks=sum(kw.attrib.get('name')=='Click Observed Native Control'and kw.find('status')is not None and kw.find('status').attrib['status']=='PASS'for kw in tree.findall('.//kw'))
    for name,kind in [('output.xml','robot-output'),('report.html','robot-report'),('log.html','robot-log'),('xunit.xml','robot-xunit')]:
        path=output/name;data=raw_file(path,16*1024**2,owner=os.getuid());info=path.lstat()
        reports.append({'path':str(path),'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'identity':{k:getattr(info,k)for k in FULL9},'kind':kind,'public':True})
    dump(output/'result.json',{'identity':request,'numeric_exit':code,'tests_failed':sum(x!='PASS'for x in statuses),'tests_passed':statuses.count('PASS'),'actual_pointer_calls':clicks,'reports':reports,'suite_sha256':hashlib.sha256(raw_file(suite)).hexdigest()})
    return code

if __name__=='__main__':raise SystemExit(main())

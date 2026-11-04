"""Owner-local proposed data adapter; no SteamOS-owned code is changed.
This is history comparison evidence, never an authority/driver/GPU readiness proof.
Existing private-copy/custody/Root/source/closure guards are prerequisites.
"""
import os,json,hashlib,sqlite3,codecs
from pathlib import Path

def resolve_terminal(queue_module,queue_root,queue_uid,row):
    result=json.loads(row['result'])
    epoch=queue_module.terminal_history_resolve(queue_root,queue_uid,result['preservedReservationEpoch'],row['id'],row['unit'],result['finalLedgerInvocation'])
    # Exact whole result remains intact; no reference is relabeled as full rows.
    return {'terminal':result,'preservedEpoch':epoch,'epochSHA256':hashlib.sha256((queue_module.canonical(epoch)+'\n').encode()).hexdigest(),'runtimeAuthorized':False}

def read_private_history(c,*,maximum_bytes=64*1024**2):
    """Actual private SQL8MiB value cap; old large TEXT via readonly blob, not SQL
    projection of result/result IS NULL. Caller supplies an already authenticated
    private DB; never opens or coordinates original queue SQLite/journals.
    """
    if c.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)!=8*1024**2:raise ValueError('unchanged SQL8MiB cap')
    if type(maximum_bytes)is not int or not 0<maximum_bytes<=64*1024**2:raise ValueError('finite unchanged per-product64MiB ceiling')
    total=0;rows=[];stats=[]
    query='SELECT rowid,id,spec,state,cpus,unit,started,finished,typeof(result) FROM jobs ORDER BY rowid'
    for record in c.execute(query):
        rowid,*values,typ=record
        if typ not in ('null','text'):raise ValueError('original result type')
        r=dict(zip(('id','spec','state','cpus','unit','started','finished'),values));r['result']=None
        if len(json.dumps(r,sort_keys=True,separators=(',',':')).encode())>1024**2:raise ValueError('unchanged1MiB per-row metadata cap')
        if typ=='text':
            decoder=codecs.getincrementaldecoder('utf-8')('strict');parts=[];h=hashlib.sha256();n=0
            with c.blobopen('jobs','result',rowid,readonly=True) as b:
                size=len(b)
                if size>maximum_bytes-total:raise ValueError('finite private result aggregate')
                while n<size:
                    chunk=b.read(min(65536,size-n))
                    if not chunk:raise ValueError('short private result blob')
                    n+=len(chunk);h.update(chunk);parts.append(decoder.decode(chunk))
                if b.read(1)!=b'':raise ValueError('private blob trailing data')
                parts.append(decoder.decode(b'',final=True))
            r['result']=''.join(parts);total+=n;stats.append({'id':r['id'],'bytes':n,'sha256':h.hexdigest()})
        if len(rows)>=256:raise ValueError('finite private row count')
        rows.append(r)
    value={'rows':rows,'bindings':[list(x) for x in c.execute('SELECT job_id,value FROM pool_unit_bindings ORDER BY rowid')],'config':[list(x) for x in c.execute('SELECT id,value FROM config ORDER BY rowid')]}
    metadata={k:v for k,v in value.items() if k!='rows'}
    if len(json.dumps(metadata,sort_keys=True,separators=(',',':')).encode())>1024**2:raise ValueError('unchanged1MiB bindings/config metadata cap')
    return value,stats

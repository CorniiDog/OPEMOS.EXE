"""Finite lossless CI result and local transport custody for the existing route."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import time
import uuid

FULL9=("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
FALLBACK_MAX=1024**2
HARD_MAX=1024**3


def require(value,message):
    if not value:raise ValueError(message)


def policy(value):
    require(isinstance(value,dict)and set(value)=={"max_bytes","stderr_max_bytes","free_reserve_bytes"},"Reviewed complete result/transport policy missing")
    require(type(value["max_bytes"])is int and FALLBACK_MAX<=value["max_bytes"]<=HARD_MAX and
            type(value["stderr_max_bytes"])is int and 65536<=value["stderr_max_bytes"]<=16*1024**2 and
            type(value["free_reserve_bytes"])is int and value["free_reserve_bytes"]>=0,"Finite reviewed full result/diagnostic bounds required")
    return value


def composition(config,plan):
    p=policy(config["result_contract"])
    # Compact full JSON retains every unknown row/value. Its dominant queue
    # component has the existing complete metadata bound. Leaf receipts retain
    # their unchanged1MiB cap; executable operation has outer/build/heal/install.
    leaves=len(plan.get("admitted_vm_ids",[]))+4*len(plan.get("expected_executables",{}))
    minimum=config["queue_metadata"]["max_bytes"]+leaves*3*1024**2+256*1024**2
    require(p["max_bytes"]>=minimum,"Reviewed full result budget cannot compose metadata+all leaf receipts+custody; refuse before effects")
    scratch=Path(config["queue_metadata"]["scratch_dir"])
    require(scratch.is_absolute()and scratch.resolve()==scratch,"Exact full-result scratch directory required")
    info=scratch.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==os.getuid()and not info.st_mode&0o077,"Private owned full-result scratch required")
    space=os.statvfs(scratch)
    require(space.f_bavail*space.f_frsize>=p["max_bytes"]+p["free_reserve_bytes"],"Full-result scratch volume lacks complete contract+reserve before effects")
    return {"max_bytes":p["max_bytes"],"metadata_max_bytes":config["queue_metadata"]["max_bytes"],
            "leaf_receipts":leaves,"leaf_max_bytes":1024**2,"leaf_canonical_expansion_max":3,"custody_plan_overhead_bytes":256*1024**2,
            "composed_minimum_bytes":minimum,"unknown_fields_preserved":True}


def encoded(value):
    return json.JSONEncoder(sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).iterencode(value)


def write_full(path,value,cap):
    """Create-only complete JSON; failed partials retained and never promoted."""
    path=Path(path);partial=path.with_name(path.name+".partial")
    fd=os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    total=0;primary=None
    try:
        for chunk in encoded(value):
            raw=chunk.encode();require(total+len(raw)<=cap,"Complete result exceeds reviewed contract; failed partial retained, no truncation/pass")
            view=memoryview(raw)
            while view:
                n=os.write(fd,view);require(n>0,"Complete result write failed");total+=n;view=view[n:]
        os.fsync(fd)
    except BaseException as error:primary=error
    finally:
        try:os.close(fd)
        except BaseException as close:
            raise ValueError("Full-result close UNKNOWN; primary="+repr(primary)+"; close="+repr(close))from primary
    if primary is not None:raise primary
    os.link(partial,path,follow_symlinks=False) # never replace a preexisting receipt
    partial.unlink()
    return total


def emit(value,stream,cap,scratch):
    # Complete serialization is admitted before emitting the first stdout byte.
    import tempfile
    with tempfile.TemporaryFile(mode="w+b",dir=scratch)as file:
        total=0
        for chunk in encoded(value):
            raw=chunk.encode();require(total+len(raw)<=cap,"Full control result exceeds joined contract")
            view=memoryview(raw)
            while view:
                n=file.write(view);require(type(n)is int and n>0,"Complete result spool write failed");total+=n;view=view[n:]
        file.flush();before=os.fstat(file.fileno());require(before.st_size==total,"Complete result spool length differs");file.seek(0)
        while block:=file.read(65536):
            view=memoryview(block)
            while view:
                n=stream.write(view);require(type(n)is int and n>0,"Complete control stream write failed");view=view[n:]
        stream.flush()
        require(tuple(getattr(before,k)for k in FULL9)==tuple(getattr(os.fstat(file.fileno()),k)for k in FULL9),"Result spool full9 drift")


class TransportFailure(ValueError):
    def __init__(self,receipt):
        self.transport_receipt=receipt
        super().__init__(receipt.get("first_failure",{}).get("reason","Local transport failed; remote closure UNKNOWN"))


def safe_error(error, phase, started=None, receipt=None):
    """Never stringify command-bearing subprocess errors or caller operands."""
    row={"type":type(error).__name__,"phase":phase,"reason":phase+": "+type(error).__name__}
    if isinstance(error,OSError):row["errno"]=error.errno
    if isinstance(error,subprocess.TimeoutExpired):row["timeout_seconds"]=error.timeout
    if started is not None:row["duration_seconds"]=max(0,time.monotonic()-started)
    if receipt is not None:
        row.update(local_pid=receipt.get("local_pid","UNKNOWN"),local_start=receipt.get("local_start","UNKNOWN"),
                   numeric_exit=receipt.get("numeric_exit","UNKNOWN"))
    return row


def persist_transport(path,receipt):
    """Secondary persistence cannot replace collected first-process custody."""
    try:write_full(path,receipt,1024**2)
    except BaseException as error:
        receipt["complete"]=False
        receipt.setdefault("persistence_failures",[]).append(safe_error(error,"Transport receipt persistence"))
        receipt["receipt_durability"]="UNKNOWN"
        receipt.setdefault("first_failure",safe_error(error,"Transport receipt persistence"))
        raise TransportFailure(receipt)from error


def capture(command,data,contract,directory,timeout,env=None):
    """Finite complete stream custody; local closure never proves remote closure."""
    p=policy(contract);directory=Path(directory);directory.mkdir(mode=0o700)
    require(directory.resolve()==directory.absolute(),"Canonical private transport directory required")
    space=os.statvfs(directory)
    require(space.f_bavail*space.f_frsize>=p["max_bytes"]+p["stderr_max_bytes"]+p["free_reserve_bytes"]+262144,"Transport volume lacks finite complete capture reserve")
    receipt={"version":2,"remote_closure":"UNKNOWN","local_process_started":False,"local_reaped":False,
             "timeout":False,"streams":{},"close_failures":[],"stream_failures":[]}
    files={};child=None;selector=selectors.DefaultSelector();failure=None
    started=time.monotonic();deadline=started+timeout;phase="Transport preparation"
    try:
        for name,cap in (("stdout",p["max_bytes"]),("stderr",p["stderr_max_bytes"])):
            path=directory/name;fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            files[name]=(fd,path,cap,hashlib.sha256())
            receipt["streams"][name]={"path":str(path),"bytes":0,"received_bytes":0,"EOF":False,"complete":True}
        phase="Local transport spawn"
        child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        receipt.update(local_pid=child.pid,local_process_started=True)
        try:
            raw=Path('/proc/'+str(child.pid)+'/stat').read_text();receipt["local_start"]=int(raw[raw.rindex(')')+2:].split()[19])
        except (OSError,ValueError):receipt["local_start"]="UNKNOWN"
        try:
            child.stdin.write(data or b"");child.stdin.close();receipt["stdin_closed"]=True
        except (BrokenPipeError,OSError)as error:
            failure=safe_error(error,"Local request pipe closed early",started,receipt);receipt["stdin_failure"]=failure
            try:child.stdin.close()
            except (BrokenPipeError,OSError):pass
        for name,pipe in (("stdout",child.stdout),("stderr",child.stderr)):
            os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ,name)
        phase="Transport stream capture"
        while selector.get_map():
            if time.monotonic()>deadline:
                receipt["timeout"]=True
                failure=failure or {"type":"Deadline","reason":"Local SSH deadline exceeded; remote closure UNKNOWN"}
                if child.poll()is None:child.kill()
                deadline=time.monotonic()+5
                if receipt.get("drain_deadline_set"):
                    for key in list(selector.get_map().values()):
                        receipt["streams"][key.data]["complete"]=False;selector.unregister(key.fileobj)
                    break
                receipt["drain_deadline_set"]=True
            for key,_ in selector.select(0.1):
                name=key.data;row=receipt["streams"][name];fd,path,cap,digest=files[name]
                block=os.read(key.fileobj.fileno(),65536)
                if not block:
                    row["EOF"]=True;selector.unregister(key.fileobj);continue
                row["received_bytes"]+=len(block)
                if row["bytes"]+len(block)>cap:
                    failure=failure or {"type":"Overflow","reason":name+" exceeded finite admitted transport envelope; no partial reply accepted"}
                    if child.poll()is None:child.kill()
                    if not receipt.get("drain_deadline_set"):deadline=time.monotonic()+5;receipt["drain_deadline_set"]=True
                if row["bytes"]+len(block)>cap+131072:
                    row["complete"]=False;selector.unregister(key.fileobj);continue
                view=memoryview(block)
                while view:
                    n=os.write(fd,view);require(type(n)is int and 0<n<=len(view),"Complete transport spool write failed")
                    # Each real retained prefix is accounted before another
                    # write can return zero or raise. Received != retained.
                    digest.update(view[:n]);row["bytes"]+=n;view=view[n:]
        phase="Local wait after stream EOF"
        receipt["numeric_exit"]=child.wait(timeout=5);receipt["local_reaped"]=True
    except BaseException as error:
        failure=failure or safe_error(error,phase,started,receipt)
        if isinstance(error,subprocess.TimeoutExpired):receipt["timeout"]=True
        if child is not None:
            try:
                if child.poll()is None:child.kill()
                receipt["numeric_exit"]=child.wait(timeout=5);receipt["local_reaped"]=True
            except BaseException as close:receipt["close_failures"].append(safe_error(close,"Local reap",started,receipt))
    finally:
        try:selector.close()
        except BaseException as error:receipt["close_failures"].append(safe_error(error,"Selector close",started,receipt))
        if child is not None:
            for pipe in (child.stdin,child.stdout,child.stderr):
                if pipe is not None:
                    try:pipe.close()
                    except BaseException as error:receipt["close_failures"].append(safe_error(error,"Local pipe close",started,receipt))
        for name,(fd,path,cap,digest)in files.items():
            row=receipt["streams"][name];row["written_prefix_sha256"]=digest.hexdigest();row["written_prefix_bytes"]=row["bytes"]
            try:os.fsync(fd)
            except BaseException as error:
                event=safe_error(error,"Transport spool fsync",started,receipt);receipt["stream_failures"].append(event);failure=failure or event
            try:
                before=os.fstat(fd);observed=hashlib.sha256();total=0
                require(0<=before.st_size<=cap+131072,"Transport observed spool exceeds finite envelope")
                while block:=os.pread(fd,min(65536,cap+131073-total),total):
                    total+=len(block);require(total<=cap+131072,"Transport observation overflow");observed.update(block)
                row["observation"]={"bytes":total,"sha256":observed.hexdigest(),"EOF":True,
                    "identity":{k:getattr(before,k)for k in FULL9}}
                require(tuple(getattr(before,k)for k in FULL9)==tuple(getattr(os.fstat(fd),k)for k in FULL9)==
                        tuple(getattr(path.lstat(),k)for k in FULL9),"Transport spool full9/path identity drift")
                require(total==before.st_size==row["written_prefix_bytes"]and observed.hexdigest()==row["written_prefix_sha256"],"Transport observed bytes differ from written prefix")
                row.update(bytes=total,sha256=observed.hexdigest(),identity=row["observation"]["identity"],observation_verified=True)
            except BaseException as error:
                row.update(sha256=None,identity=None,observation_verified=False,retained_custody="UNKNOWN")
                event=safe_error(error,"Transport spool observation",started,receipt);receipt["stream_failures"].append(event);failure=failure or event
            finally:
                try:os.close(fd);row["FD_closed"]=True
                except BaseException as error:
                    row["FD_closed"]=False;receipt["close_failures"].append(safe_error(error,"Transport spool close",started,receipt))
    receipt["complete"]=bool(not failure and receipt["local_reaped"]and not receipt["close_failures"]and
        len(receipt["streams"])==2 and all(x["EOF"]and x["complete"]and x.get("observation_verified")and x.get("FD_closed")for x in receipt["streams"].values()))
    if failure:receipt["first_failure"]=failure
    receipt["duration_seconds"]=max(0,time.monotonic()-started)
    persist_transport(directory/'receipt.json',receipt)
    if not receipt["complete"]:raise TransportFailure(receipt)
    return receipt

"""Actual bounded child capture INSIDE a disposable OMEN source-build VM.

Windows children are created suspended, assigned to an owned kill-on-close job,
then resumed. Linux children use a fresh session. No host/remote closure claim.
"""
import ctypes
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

CAP = 32 * 1024**2


def linux_user_processes():
    result={}
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():continue
        try:
            status=(path/'status').read_text();uids=next(x.split()[1:]for x in status.splitlines()if x.startswith('Uid:'))
            if int(uids[0])!=os.getuid():continue
            raw=(path/'stat').read_text();birth=int(raw.rsplit(')',1)[1].split()[19])
            result[int(path.name)]={'birth':birth,'uids':[int(x)for x in uids]}
        except(FileNotFoundError,ProcessLookupError):continue
    return result


def capture(argv, cwd, env, directory, seconds):
    directory = Path(directory); directory.mkdir(mode=0o700)
    before = time.monotonic(); deadline = before + seconds
    original_users=linux_user_processes()if os.name!='nt'else None
    row = {'argv': argv, 'numeric_exit': None, 'birth': 'UNKNOWN', 'reaped': False,
           'stdoutEOF': False, 'stderrEOF': False, 'FDsClosed': False,
           'descendantsAbsent': False, 'first': None, 'secondary': []}
    handles = []; readers = []; stop = None; wait = None; empty = None; proc = None

    def failure(error):
        item = {'type': type(error).__name__, 'reason': str(error)}
        if row['first'] is None: row['first'] = item
        else: row['secondary'].append(item)

    def drain(stream, name):
        count = 0; digest = hashlib.sha256(); output = directory / (name + '.raw')
        try:
            with output.open('xb') as target:
                while True:
                    block = stream.read(65536)
                    if not block: row[name + 'EOF'] = True; break
                    if count + len(block) > CAP + 65536:
                        raise ValueError(name + ' stream beyond retained overflow sentinel')
                    target.write(block); digest.update(block); count += len(block)
                    if count > CAP:
                        failure(ValueError(name + ' overflow; retained crossing bytes'))
                        if stop is not None: stop()
                target.flush(); os.fsync(target.fileno())
        except BaseException as error:
            failure(error)
            if stop is not None:
                try: stop()
                except BaseException as secondary: failure(secondary)
        finally:
            try: stream.close()
            except BaseException as error: failure(error)
            row[name] = {'path': str(output), 'bytes': count, 'sha256': digest.hexdigest()}

    try:
        if os.name == 'nt':
            from ctypes import wintypes as w
            import msvcrt
            k = ctypes.WinDLL('kernel32', use_last_error=True)
            class SECURITY(ctypes.Structure):
                _fields_ = [('length', w.DWORD), ('descriptor', w.LPVOID), ('inherit', w.BOOL)]
            class STARTUP(ctypes.Structure):
                _fields_ = [('cb', w.DWORD), ('reserved', w.LPWSTR), ('desktop', w.LPWSTR),
                    ('title', w.LPWSTR), ('x', w.DWORD), ('y', w.DWORD), ('xs', w.DWORD),
                    ('ys', w.DWORD), ('xc', w.DWORD), ('yc', w.DWORD), ('fill', w.DWORD),
                    ('flags', w.DWORD), ('show', w.WORD), ('extra', w.WORD), ('data', ctypes.POINTER(w.BYTE)),
                    ('stdin', w.HANDLE), ('stdout', w.HANDLE), ('stderr', w.HANDLE)]
            class PROCESS(ctypes.Structure):
                _fields_ = [('process', w.HANDLE), ('thread', w.HANDLE), ('pid', w.DWORD), ('tid', w.DWORD)]
            class BASIC_LIMIT(ctypes.Structure):
                _fields_ = [('processTime', ctypes.c_int64), ('jobTime', ctypes.c_int64), ('flags', w.DWORD),
                    ('minimum', ctypes.c_size_t), ('maximum', ctypes.c_size_t), ('active', w.DWORD),
                    ('affinity', ctypes.c_size_t), ('priority', w.DWORD), ('scheduling', w.DWORD)]
            class IO(ctypes.Structure):
                _fields_ = [(name, ctypes.c_uint64) for name in ('readOps','writeOps','otherOps','read','write','other')]
            class EXTENDED(ctypes.Structure):
                _fields_ = [('basic', BASIC_LIMIT), ('io', IO), ('processMemory', ctypes.c_size_t),
                    ('jobMemory', ctypes.c_size_t), ('peakProcess', ctypes.c_size_t), ('peakJob', ctypes.c_size_t)]
            class ACCOUNT(ctypes.Structure):
                _fields_ = [(name, ctypes.c_int64) for name in ('user','kernel','userPeriod','kernelPeriod')] + [
                    (name, w.DWORD) for name in ('faults','total','active','terminated')]
            prototypes = {
                'CreatePipe': ([ctypes.POINTER(w.HANDLE),ctypes.POINTER(w.HANDLE),ctypes.POINTER(SECURITY),w.DWORD],w.BOOL),
                'SetHandleInformation': ([w.HANDLE,w.DWORD,w.DWORD],w.BOOL),
                'CreateJobObjectW': ([w.LPVOID,w.LPCWSTR],w.HANDLE),
                'SetInformationJobObject': ([w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD],w.BOOL),
                'QueryInformationJobObject': ([w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)],w.BOOL),
                'AssignProcessToJobObject': ([w.HANDLE,w.HANDLE],w.BOOL),
                'TerminateJobObject': ([w.HANDLE,w.UINT],w.BOOL),
                'TerminateProcess': ([w.HANDLE,w.UINT],w.BOOL),
                'ResumeThread': ([w.HANDLE],w.DWORD),
                'WaitForSingleObject': ([w.HANDLE,w.DWORD],w.DWORD),
                'GetExitCodeProcess': ([w.HANDLE,ctypes.POINTER(w.DWORD)],w.BOOL),
                'GetProcessTimes': ([w.HANDLE,ctypes.POINTER(w.FILETIME),ctypes.POINTER(w.FILETIME),
                                     ctypes.POINTER(w.FILETIME),ctypes.POINTER(w.FILETIME)],w.BOOL),
                'CreateProcessW': ([w.LPCWSTR,w.LPWSTR,w.LPVOID,w.LPVOID,w.BOOL,w.DWORD,w.LPVOID,
                                    w.LPCWSTR,ctypes.POINTER(STARTUP),ctypes.POINTER(PROCESS)],w.BOOL),
                'CloseHandle': ([w.HANDLE],w.BOOL)}
            for name, (args, result) in prototypes.items():
                getattr(k,name).argtypes=args; getattr(k,name).restype=result
            def check(value):
                if not value: raise ctypes.WinError(ctypes.get_last_error())
                return value
            def close(handle):
                check(k.CloseHandle(handle)); handles.remove(handle)
            job=check(k.CreateJobObjectW(None,None)); handles.append(job)
            limits=EXTENDED(); limits.basic.flags=0x2000 # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway
            check(k.SetInformationJobObject(job,9,ctypes.byref(limits),ctypes.sizeof(limits)))
            sa=SECURITY(ctypes.sizeof(SECURITY),None,True); pipes={}
            for name in ('stdout','stderr'):
                read=w.HANDLE(); write=w.HANDLE();check(k.CreatePipe(ctypes.byref(read),ctypes.byref(write),ctypes.byref(sa),0))
                handles.extend([read.value,write.value]);check(k.SetHandleInformation(read,1,0));pipes[name]=(read.value,write.value)
            # A dedicated empty stdin pipe gives actual EOF, not inherited console input.
            sr=w.HANDLE();sw=w.HANDLE();check(k.CreatePipe(ctypes.byref(sr),ctypes.byref(sw),ctypes.byref(sa),0))
            handles.extend([sr.value,sw.value]);check(k.SetHandleInformation(sw,1,0))
            info=STARTUP();info.cb=ctypes.sizeof(info);info.flags=0x100;info.stdin=sr;info.stdout=pipes['stdout'][1];info.stderr=pipes['stderr'][1]
            pi=PROCESS();block=ctypes.create_unicode_buffer('\0'.join(k+'='+v for k,v in sorted(env.items()))+'\0\0')
            command=ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
            check(k.CreateProcessW(argv[0],command,None,None,True,0x4|0x400,block,str(cwd),ctypes.byref(info),ctypes.byref(pi)))
            handles.extend([pi.process,pi.thread]);row['pid']=int(pi.pid)
            times=[w.FILETIME() for _ in range(4)];check(k.GetProcessTimes(pi.process,*[ctypes.byref(x)for x in times]))
            row['birth']=(times[0].dwHighDateTime<<32)|times[0].dwLowDateTime
            try:check(k.AssignProcessToJobObject(job,pi.process))
            except BaseException:
                check(k.TerminateProcess(pi.process,1));k.WaitForSingleObject(pi.process,5000);raise
            stop=lambda:check(k.TerminateJobObject(job,1))
            def wait():
                result=k.WaitForSingleObject(pi.process,100)
                if result==0:
                    code=w.DWORD();check(k.GetExitCodeProcess(pi.process,ctypes.byref(code)));return int(code.value)
                if result!=258:raise ctypes.WinError(ctypes.get_last_error())
                return None
            def empty():
                observed=ACCOUNT();check(k.QueryInformationJobObject(job,1,ctypes.byref(observed),ctypes.sizeof(observed),None))
                return observed.active==0
            streams={}
            for name,(rd,wr)in pipes.items():
                close(wr);fd=msvcrt.open_osfhandle(rd,os.O_RDONLY|os.O_BINARY);handles.remove(rd)
                streams[name]=os.fdopen(fd,'rb',buffering=0)
            close(sr.value);close(sw.value)
            if k.ResumeThread(pi.thread)==0xffffffff:raise ctypes.WinError(ctypes.get_last_error())
        else:
            proc=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            row['pid']=proc.pid
            row['birth']=int(Path('/proc',str(proc.pid),'stat').read_text().rsplit(')',1)[1].split()[19])
            def stop():
                # Never signal a numeric group after losing the original birth.
                current=int(Path('/proc',str(proc.pid),'stat').read_text().rsplit(')',1)[1].split()[19])
                if current != row['birth']:raise ProcessLookupError('original command birth absent')
                os.killpg(proc.pid,signal.SIGKILL)
            def wait():
                result=os.waitid(os.P_PID,proc.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                return None if result is None else proc.wait(timeout=5)
            def empty():
                try:os.killpg(proc.pid,0);return False
                except ProcessLookupError:return True
            streams={'stdout':proc.stdout,'stderr':proc.stderr}
        for name,stream in streams.items():
            reader=threading.Thread(target=drain,args=(stream,name),daemon=True);reader.start();readers.append(reader)
        while True:
            code=wait()
            if code is not None:row['numeric_exit']=code;row['reaped']=True;break
            time.sleep(.05)
            if time.monotonic()>=deadline:
                failure(TimeoutError('original guest command deadline'));stop()
                # Same process only; final wait/pipe drain is cleanup, not a new execution budget.
                end=time.monotonic()+5
                while time.monotonic()<end:
                    code=wait()
                    if code is not None:row['numeric_exit']=code;row['reaped']=True;break
                break
        row['descendantsAbsent']=empty()
        if not row['descendantsAbsent']:
            failure(ValueError('owned command descendants remain'));stop()
        for reader in readers:reader.join(timeout=5)
        if any(reader.is_alive()for reader in readers):failure(ValueError('raw pipe EOF/reader join UNKNOWN'))
        if os.name!='nt':
            after_users=linux_user_processes();new={pid:value for pid,value in after_users.items()
                if original_users.get(pid)!=value}
            row['actualUserProcessesAfter']=new
            if new:
                row['descendantsAbsent']=False
                failure(ValueError('new same-UID process birth outside original baseline; never blind-kill/adopt'))
    except BaseException as error:
        failure(error)
        if stop is not None:
            try:stop()
            except ProcessLookupError:pass
            except BaseException as secondary:failure(secondary)
    finally:
        for handle in reversed(handles[:]):
            try:check(k.CloseHandle(handle));handles.remove(handle)
            except BaseException as error:failure(error)
        if proc is not None:
            try:
                if not row['reaped']:row['numeric_exit']=proc.wait(timeout=5);row['reaped']=True
                for stream in (proc.stdout,proc.stderr):stream.close()
            except BaseException as error:failure(error)
        row['FDsClosed']=not handles and all(not t.is_alive()for t in readers) and not row['secondary']
        row['elapsed_monotonic']=time.monotonic()-before
    return row

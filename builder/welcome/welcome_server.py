#!/usr/bin/env python3
"""Loopback-only controller for the installation-media welcome application."""

import argparse
import hashlib
import http.server
import json
import os
import re
import select
import signal
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit


def start_firmware_bound_output_observer(state_root):
    """Guest-only launcher of the verified A medium; never host PR execution.

    Ordinary installations without this exact QEMU firmware operand do
    nothing. Missing guest permissions/media are real failures, not invented
    credentials, an alternate source, or a readiness/pass marker.
    """
    firmware = Path('/sys/firmware/qemu_fw_cfg/by_name/opt/opemos/observer-manifest-sha256/raw')
    if not firmware.exists():
        if Path('/dev/virtio-ports/opemos.robot.observer').exists():
            raise RuntimeError('output observer port exists but firmware manifest is unavailable; no source executed')
        return
    if os.getuid() != 1000:
        raise RuntimeError('output observer requires the actual desktop UID1000')
    expected = firmware.read_bytes().strip().decode('ascii')
    if not re.fullmatch('[0-9a-f]{64}', expected):
        raise RuntimeError('invalid output controller firmware manifest pin')
    outcome={}
    def worker():
        first = None; numeric = None; eof = False; total = 0
        directory = None; port_fd = None
        try:
            # A named, newly created per-boot directory prevents duplicate
            # launch/adoption and preserves failures across later boots.
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            directory = Path(state_root) / ('output-observer-' + boot)
            directory.mkdir(mode=0o700)
            def fixed_child(argv, seconds, name, cap, pass_fds=()):
                process = None; failure = None; errors = []; raw = bytearray(); eof_seen = False; code = None; birth = None
                end = time.monotonic() + seconds
                try:
                    with (directory/(name+'.log')).open('xb') as capture:
                        process = subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                                   stderr=subprocess.STDOUT,pass_fds=pass_fds)
                        try:birth=int(Path('/proc/'+str(process.pid)+'/stat').read_text().rsplit(')',1)[1].split()[19])
                        except (OSError,ValueError):birth=None
                        while True:
                            remaining = end-time.monotonic()
                            if remaining <= 0: raise RuntimeError('original '+name+' deadline exceeded')
                            if not select.select([process.stdout],[],[],remaining)[0]:
                                raise RuntimeError(name+' output deadline, not EOF')
                            block = os.read(process.stdout.fileno(),min(65536,cap+1-len(raw)))
                            if not block: eof_seen = True; break
                            raw.extend(block);capture.write(block);capture.flush()
                            if len(raw)>cap: raise RuntimeError(name+' first crossing byte retained; unknown tail')
                        code=process.wait(timeout=max(.001,end-time.monotonic()))
                        capture.flush();os.fsync(capture.fileno())
                except BaseException as error: failure={'type':type(error).__name__,'reason':str(error)[:700]}
                finally:
                    if process is not None:
                        if process.poll()is None:
                            try:process.terminate();code=process.wait(timeout=5)
                            except BaseException as error:
                                errors.append(str(error)[:300])
                                try:process.kill();code=process.wait(timeout=5)
                                except BaseException as cleanup:errors.append(str(cleanup)[:300])
                        else:code=process.returncode
                        try:process.stdout.close()
                        except BaseException as error:errors.append(str(error)[:300])
                    lifecycle={'argv':argv,'numeric_exit':code,'stdout_eof':eof_seen,'bytes':len(raw),
                            'pid':None if process is None else process.pid,'start':birth,
                            'original_reaped':process is not None and process.returncode is not None,
                            'stdout_closed':process is not None and process.stdout.closed,
                            'descendant_closure':'UNKNOWN; host VM proof required','first':failure,'secondary':errors}
                    with (directory/(name+'-result.json')).open('x')as receipt:
                        json.dump(lifecycle,receipt)
                        receipt.flush();os.fsync(receipt.fileno())
                if failure is not None or errors:
                    error=RuntimeError(name+' failed; original raw/terminal evidence retained')
                    error.capture_lifecycle=lifecycle;error.captured_raw=bytes(raw)
                    raise error
                return code,bytes(raw),lifecycle
            device = Path('/dev/disk/by-label/OPROBOT').resolve(strict=True)
            if not stat.S_ISBLK(device.stat().st_mode):
                raise RuntimeError('real output controller block medium absent')
            # Existing desktop UDisks policy only. No sudoers, passwords,
            # polkit changes, network, installer mode or fake mount adapter.
            mount_exit, _, _ = fixed_child(['/usr/bin/udisksctl', 'mount', '--block-device', str(device),
                '--options', 'ro', '--no-user-interaction'],15,'mount',65536)
            locations = []
            def unescape(value):
                return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)
            for line in Path('/proc/self/mountinfo').read_text().splitlines():
                before, after = line.split(' - ', 1); fields = before.split(); source = after.split()
                if source[0] == 'iso9660' and Path(unescape(source[1])).resolve() == device and 'ro' in fields[5].split(','):
                    locations.append(Path(unescape(fields[4])))
            if len(locations) != 1:
                raise RuntimeError('exact actual read-only controller mount missing/ambiguous; UDisks exit '+str(mount_exit))
            medium = locations[0]; manifest = medium/'manifest.json'
            def held(path, limit, digest):
                fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                try:
                    before = os.fstat(fd)
                    if not (stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                            and not before.st_mode & 0o022 and 0 < before.st_size <= limit):
                        raise RuntimeError('controller source permissions/size invalid')
                    raw = bytearray()
                    while part := os.read(fd, 65536):
                        raw.extend(part)
                        if len(raw) > limit: raise RuntimeError('controller source overflow')
                    fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
                    identity = lambda value: tuple(getattr(value,k)for k in fields)
                    if not (identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
                            and len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == digest):
                        raise RuntimeError('actual controller full9/EOF/hash differs')
                    return bytes(raw)
                finally: os.close(fd)
            raw = held(manifest, 1048576, expected)
            def pairs(rows):
                value = {}
                for key, item in rows:
                    if key in value: raise RuntimeError('duplicate controller manifest field')
                    value[key] = item
                return value
            value = json.loads(raw, object_pairs_hook=pairs)
            if value.get('kind') != 'EXE_STEAMOS_PHASE_MEDIA_V1' or value.get('guest_uid') != os.getuid():
                raise RuntimeError('wrong source-A observer manifest')
            names = {'omen_steamos_guest.py','omen_steamos_native.py','omen_steamos_probe.py',
                     'omen_ci_result.py','output-install.robot','robotframework-7.5-py3-none-any.whl'}
            if set(value['files']) != names: raise RuntimeError('incomplete finite controller graph')
            for name, ref in value['files'].items():
                if len(held(medium/name, 16*1024**2, ref['sha256'])) != ref['bytes']:
                    raise RuntimeError('controller dependency size differs')
            # B is allowed to run in the guest; only the hash-bound A agent
            # implements the observer. It repeats the firmware/source check.
            port=Path('/dev/virtio-ports/opemos.robot.observer');node=port.resolve(strict=True)
            if node.parent!=Path('/dev') or not re.fullmatch(r'vport[0-9]+p[0-9]+',node.name):
                raise RuntimeError('exact original output observer port absent at reap')
            if Path('/sys/class/virtio-ports',node.name,'name').read_text().strip()!='opemos.robot.observer':
                raise RuntimeError('observer port sysfs identity changed at reap')
            info=node.stat()
            if not stat.S_ISCHR(info.st_mode)or info.st_uid!=os.getuid()or stat.S_IMODE(info.st_mode)!=0o600:
                raise RuntimeError('actual observer reap port permission changed')
            # One actual port open, held by the parent across child exit.
            # Passing the same verified descriptor avoids a close/reopen gap
            # and does not contend with virtio-console's exclusive open.
            port_fd=os.open(node,os.O_RDWR|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
            if (os.fstat(port_fd).st_dev,os.fstat(port_fd).st_ino)!=(info.st_dev,info.st_ino):
                raise RuntimeError('observer parent held port changed')
            try:
                numeric, raw, agent_lifecycle = fixed_child(['/usr/bin/python3','-I','-B',str(medium/'omen_steamos_guest.py'),
                    str(manifest),'--channel-fd',str(port_fd)],870,'agent',MAX_COMMAND_OUTPUT,pass_fds=(port_fd,))
            except RuntimeError as error:
                if not hasattr(error,'capture_lifecycle'):raise
                agent_lifecycle=error.capture_lifecycle;raw=error.captured_raw;numeric=agent_lifecycle['numeric_exit']
            total=len(raw);eof=agent_lifecycle['stdout_eof']
            # The agent cannot attest its own exit. Its actual parent sends
            # the numeric wait/pipe-close observation only AFTER wait returns.
            event={'kind':'OUTPUT_AGENT_REAP_V1','nonce':value['nonce'],'boot_id':boot,
                   'manifest_sha256':expected,'parent_pid':os.getpid(),
                   'parent_start':int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]),
                   'uids':[int(x)for line in Path('/proc/self/status').read_text().splitlines()if line.startswith('Uid:')for x in line.split()[1:]],
                   'agent':agent_lifecycle}
            if (os.fstat(port_fd).st_dev,os.fstat(port_fd).st_ino)!=(info.st_dev,info.st_ino):
                raise RuntimeError('observer reap port changed across open')
            end=time.monotonic()+5
            def send_parent(item):
                body=memoryview(json.dumps(item,sort_keys=True,separators=(',',':')).encode()+b'\n')
                if len(body)>65536:raise RuntimeError('finite parent event cap')
                while body:
                    remaining=end-time.monotonic()
                    if remaining<=0 or not select.select([],[port_fd],[],remaining)[1]:
                        raise RuntimeError('actual parent reap publication deadline')
                    try:count=os.write(port_fd,body)
                    except BlockingIOError:continue
                    if count<=0:raise RuntimeError('actual parent reap short write')
                    body=body[count:]
            # Complete actual agent diagnostics survive an SDK process exit,
            # including failure before Robot could seal its own terminal.
            import base64
            digest=hashlib.sha256(raw).hexdigest()
            send_parent({**{key:event[key]for key in('nonce','boot_id','manifest_sha256','parent_pid','parent_start','uids')},
                         'kind':'OUTPUT_AGENT_DIAGNOSTIC_BEGIN_V1','bytes':len(raw),'sha256':digest})
            for offset in range(0,len(raw),32768):
                send_parent({'kind':'OUTPUT_AGENT_DIAGNOSTIC_CHUNK_V1','offset':offset,
                             'data':base64.b64encode(raw[offset:offset+32768]).decode('ascii')})
            send_parent({'kind':'OUTPUT_AGENT_DIAGNOSTIC_END_V1','bytes':len(raw),'sha256':digest})
            event['diagnostic_sha256']=digest
            send_parent(event)
            if numeric != 0 or agent_lifecycle['first']is not None or agent_lifecycle['secondary']:
                raise RuntimeError('actual output observer failed; numeric exit '+str(numeric)+'; original complete/prefix diagnostics retained')
        except BaseException as error:
            first = {'type':type(error).__name__,'reason':str(error)[:700]}
        finally:
            secondary = []
            if port_fd is not None:
                try:os.close(port_fd);port_fd=None
                except BaseException as error:secondary.append('observer parent FD close UNKNOWN: '+type(error).__name__)
            if directory is not None:
                try:
                    with (directory/'launcher-result.json').open('x') as result:
                        json.dump({'first':first,'secondary':secondary,'numeric_exit':numeric,
                            'stdout_eof':eof,'bytes':total,'manifest_sha256':expected,
                            'VM_closure':'UNKNOWN; independent host proof required'},result,sort_keys=True)
                        result.flush(); os.fsync(result.fileno())
                except BaseException as error:
                    print('Output observer failure persistence UNKNOWN: '+type(error).__name__,flush=True)
                    secondary.append('launcher result persistence UNKNOWN')
            outcome.update(first=first,secondary=secondary,numeric_exit=numeric,stdout_eof=eof)
    thread=threading.Thread(target=worker,name='firmware-bound-output-observer',daemon=False)
    thread.observer_result=outcome
    thread.start()
    return thread

MAX_REQUEST = 16 * 1024
MAX_COMMAND_OUTPUT = 1024 * 1024
MAX_DIAGNOSTICS = 128 * 1024
MAX_STATIC_FILE = 2 * 1024 * 1024
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/opemos.svg": ("opemos.svg", "image/svg+xml"),
    "/assets/install.svg": ("assets/install.svg", "image/svg+xml"),
    "/assets/recovery.svg": ("assets/recovery.svg", "image/svg+xml"),
    "/assets/gaming.svg": ("assets/gaming.svg", "image/svg+xml"),
}


class Controller:
    def __init__(self, args):
        self.mock = args.mock
        self.ui_root = args.ui_root.resolve()
        self.runtime = args.runtime.resolve()
        self.helper = Path(args.helper)
        self.rollback = Path(args.rollback)
        self.state_root = Path(args.state_root)
        self.token = os.urandom(32).hex()
        self.nonce = os.urandom(18).hex()
        self.origin = ""
        self.httpd = None
        self.lock = threading.Lock()
        self.operation = {
            "schemaVersion": 1,
            "status": "idle",
            "phase": "ready",
            "progress": 0,
            "message": "Choose an operation.",
            "terminal": False,
        }
        self.operation_marker = self.runtime / "operation-running"

    def run_command(self, argv, timeout=30):
        process = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        payload = process.stdout[: MAX_COMMAND_OUTPUT + 1]
        if len(payload) > MAX_COMMAND_OUTPUT:
            raise RuntimeError("The helper returned excessive output.")
        text = payload.decode("utf-8", "replace")
        if process.returncode != 0:
            summary = " ".join(text.split())[-600:]
            raise RuntimeError(summary or f"The helper exited with status {process.returncode}.")
        return text

    @staticmethod
    def clean(value, maximum=256):
        if not isinstance(value, str) or not value or len(value) > maximum:
            raise ValueError("A request field is missing or invalid.")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("A request field contains control data.")
        return value

    def bootstrap(self):
        if self.mock:
            return {
                "schemaVersion": 1,
                "mode": "simulation",
                "nvidiaVersion": "575.64.05",
                "supportRevision": "cbc442704406",
                "environment": "macOS safe preview",
                "disks": [
                    {
                        "device": "/dev/vda",
                        "bytes": 32_000_000_000,
                        "identity": "1" * 64,
                        "model": "Synthetic SteamOS target",
                        "serial": "SYNTHETIC-001",
                        "transport": "VirtIO",
                        "layout": "blank",
                    }
                ],
            }
        media = self.run_command([str(self.helper), "media-info"])
        values = {}
        for line in media.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value
        if values.get("status") != "ready":
            raise RuntimeError("Installation-media identity is unavailable.")
        inventory = self.run_command([str(self.helper), "inventory"])
        disks = []
        for line in inventory.splitlines():
            fields = line.split("\t")
            if len(fields) != 7:
                raise RuntimeError("The disk inventory returned an unsupported record.")
            device, byte_text, identity, model, serial, transport, layout = fields
            if not device.startswith("/dev/") or not identity or len(identity) != 64:
                raise RuntimeError("The disk inventory returned an unsafe identity.")
            disks.append({
                "device": device,
                "bytes": int(byte_text),
                "identity": identity,
                "model": model or "Unknown model",
                "serial": serial or "Not reported",
                "transport": transport or "Unknown bus",
                "layout": layout,
            })
        return {
            "schemaVersion": 1,
            "mode": "live",
            "nvidiaVersion": values.get("nvidiaVersion", "unknown"),
            "supportRevision": values.get("supportRevision", "")[:12],
            "environment": "SteamOS recovery media",
            "disks": disks,
        }

    def update_operation(self, **values):
        with self.lock:
            progress = values.get("progress")
            remains_running = values.get("status", self.operation.get("status")) == "running"
            if remains_running and isinstance(progress, (int, float)):
                previous = self.operation.get("progress", 0)
                if isinstance(previous, (int, float)):
                    values["progress"] = max(previous, progress)
            self.operation = {**self.operation, **values}

    def mark_runtime_state(self, name):
        marker = self.runtime / name
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)

    def operation_status(self):
        with self.lock:
            return dict(self.operation)

    def require_idle(self):
        with self.lock:
            if self.operation["status"] == "running":
                raise RuntimeError("Disk mutation is active; this operation is unavailable until it finishes.")

    def start_install(self, document):
        mode = self.clean(document.get("mode"))
        device = self.clean(document.get("device"))
        identity = self.clean(document.get("identity"))
        confirmation = self.clean(document.get("confirmation"))
        if mode not in ("all", "system"):
            raise ValueError("The installation mode is unsupported.")
        basename = device.rsplit("/", 1)[-1]
        phrase = f"{'ERASE' if mode == 'all' else 'REINSTALL'} {basename}"
        if confirmation != phrase or len(identity) != 64 or any(c not in "0123456789abcdef" for c in identity):
            raise ValueError("The confirmation or disk identity did not match.")
        with self.lock:
            if self.operation["status"] == "running":
                raise RuntimeError("An installation is already running.")
            descriptor = os.open(self.operation_marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                self.operation = {
                    "schemaVersion": 1,
                    "status": "running",
                    "phase": "validating",
                    "progress": 4,
                    "message": "Revalidating the selected physical disk.",
                    "terminal": False,
                }
            finally:
                os.close(descriptor)
        thread = threading.Thread(
            target=self._mock_install if self.mock else self._live_install,
            args=(mode, device, identity, confirmation),
            daemon=True,
        )
        try:
            thread.start()
        except Exception:
            self.operation_marker.unlink(missing_ok=True)
            self.update_operation(
                status="failed", phase="failed", progress=100,
                message="The installation worker could not start.", terminal=True,
            )
            raise
        return self.operation_status()

    def _mock_install(self, _mode, _device, _identity, _confirmation):
        try:
            stages = [
                (18, "preparing", "Preparing the target layout."),
                (55, "installing", "Running the protected Valve installation."),
                (76, "slot-a", "Installing recovery into rootfs-A."),
                (89, "slot-b", "Installing recovery into rootfs-B."),
                (96, "verifying", "Independently verifying both A/B guardians."),
            ]
            for progress, phase, message in stages:
                time.sleep(0.35)
                self.update_operation(progress=progress, phase=phase, message=message)
            time.sleep(0.35)
            self.update_operation(
                status="complete", phase="complete", progress=100,
                message="Synthetic installation and A/B verification completed.", terminal=True,
            )
            self.mark_runtime_state("operation-complete")
        except Exception as error:
            self.update_operation(
                status="failed", phase="failed", progress=100,
                message=str(error)[:700], terminal=True,
            )
        finally:
            self.operation_marker.unlink(missing_ok=True)

    def _live_install(self, mode, device, identity, confirmation):
        command = [
            "sudo", str(self.helper), "install", mode, device, identity,
            "--confirm", confirmation,
        ]
        log_directory = self.state_root
        process = None
        operation_id = os.urandom(16).hex()
        started_ns = time.monotonic_ns()
        status = None
        first = None
        secondary = []
        stdout_eof = False
        stdout_closed = False
        child_birth = None
        helper_pin = None
        log_path = None
        result_descriptor = None
        total = 0
        boot_id = None
        server_start = None
        try:
            if log_directory.is_symlink():
                raise RuntimeError("The installer log directory is unsafe.")
            log_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(log_directory, 0o700)
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            server_stat = Path(f"/proc/{os.getpid()}/stat").read_text()
            server_start = int(server_stat[server_stat.rfind(")") + 2:].split()[19])
            result_descriptor = os.open(log_directory / ("install-result-" + operation_id + ".json"),
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            # Reserve the whole bounded terminal record BEFORE target mutation.
            # A failed reservation leaves its exact pending artifact, not an
            # overwritten original or a falsely successful installation result.
            os.posix_fallocate(result_descriptor, 0, 65536)
            os.fsync(result_descriptor)
            helper_fd = os.open(self.helper, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                helper_before = os.fstat(helper_fd)
                fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
                sig = lambda value: {key: getattr(value, key) for key in fields}
                if not (stat.S_ISREG(helper_before.st_mode) and helper_before.st_uid == 0 and
                        helper_before.st_nlink == 1 and not helper_before.st_mode & 0o022 and
                        0 < helper_before.st_size <= MAX_COMMAND_OUTPUT):
                    raise RuntimeError("The protected installation helper has unsafe source custody.")
                digest = hashlib.sha256(); helper_size = 0
                while block := os.read(helper_fd, 65536):
                    helper_size += len(block)
                    if helper_size > MAX_COMMAND_OUTPUT:
                        raise RuntimeError("The protected installation helper exceeded its source bound.")
                    digest.update(block)
                if not (helper_size == helper_before.st_size and
                        sig(helper_before) == sig(os.fstat(helper_fd)) == sig(self.helper.lstat())):
                    raise RuntimeError("The protected installation helper changed during source inspection.")
                helper_pin = {"path": str(self.helper), "sha256": digest.hexdigest(), "identity": sig(helper_before)}
            finally:
                os.close(helper_fd)
            log_path = log_directory / ("install-" + operation_id + ".log")
            with log_path.open("xb") as output:
                os.chmod(log_path, 0o600)
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, start_new_session=True,
                )
                try:
                    raw_stat = Path(f"/proc/{process.pid}/stat").read_text()
                    child_birth = int(raw_stat[raw_stat.rfind(")") + 2:].split()[19])
                except (OSError, ValueError, IndexError):
                    # A fast exit is not a fabricated retained process identity.
                    child_birth = None
                while True:
                    block = process.stdout.read1(min(65536, MAX_COMMAND_OUTPUT + 1 - total))
                    if not block:
                        stdout_eof = True
                        break
                    total += len(block)
                    output.write(block)
                    output.flush()
                    if total > MAX_COMMAND_OUTPUT:
                        # Preserve the actual first crossing byte; unknown tail
                        # is not EOF. No unbounded TextIO readline allocation.
                        os.fsync(output.fileno())
                        raise RuntimeError("The installer returned excessive output.")
                    message = " ".join(block.decode("utf-8", "replace").split())[:500]
                    if message:
                        lowered = message.lower()
                        progress, phase = 24, "installing"
                        if "rootfs-a" in lowered:
                            progress, phase = 68, "slot-a"
                        elif "rootfs-b" in lowered:
                            progress, phase = 82, "slot-b"
                        elif "verif" in lowered or "guardian" in lowered:
                            progress, phase = 92, "verifying"
                        elif "partition" in lowered or "format" in lowered:
                            progress, phase = 18, "preparing"
                        self.update_operation(message=message, progress=progress, phase=phase)
                os.fsync(output.fileno())
            status = process.wait()
            if status != 0:
                raise RuntimeError(f"Installation stopped with status {status}. Review diagnostics before booting the target.")
            marker = log_directory / "last-install-log"
            descriptor, temporary = tempfile.mkstemp(prefix=".last-install-log-", dir=log_directory)
            try:
                os.fchmod(descriptor, 0o600)
                os.write(descriptor, (str(log_path) + "\n").encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, marker)
            self.update_operation(
                status="complete", phase="complete", progress=100,
                message="Installation and A/B recovery verification completed.", terminal=True,
            )
            self.mark_runtime_state("operation-complete")
        except Exception as error:
            first = {"type": type(error).__name__, "reason": str(error)[:700]}
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    status = process.wait(timeout=5)
                except ProcessLookupError:
                    pass
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    status = process.wait()
                except Exception as cleanup:
                    secondary.append({"phase": "process-stop", "type": type(cleanup).__name__})
            self.update_operation(
                status="failed", phase="failed", progress=100,
                message=str(error)[:700], terminal=True,
            )
        finally:
            if process is not None:
                if status is None:
                    status = process.poll()
                try:
                    if process.stdout is not None:
                        process.stdout.close()
                        stdout_closed = process.stdout.closed
                except Exception as cleanup:
                    secondary.append({"phase": "stdout-close", "type": type(cleanup).__name__})
            try:
                self.operation_marker.unlink(missing_ok=True)
            except Exception as cleanup:
                secondary.append({"phase": "operation-marker", "type": type(cleanup).__name__})
            result = {"kind": "EXE_WELCOME_INSTALL_TERMINAL_V1", "operation_id": operation_id,
                "boot_id": boot_id, "server_pid": os.getpid(), "server_start": server_start,
                "server_uid": os.getuid(), "started_ns": started_ns, "finished_ns": time.monotonic_ns(),
                "mode": mode, "device": device, "device_identity": identity, "helper": helper_pin,
                "child": None if process is None else {"pid": process.pid, "start": child_birth},
                "numeric_exit": status, "stdout_eof": stdout_eof, "stdout_closed": stdout_closed,
                "original_reaped": process is not None and process.returncode is not None,
                "descendant_closure": "UNKNOWN; independent actual VM/process closure required",
                "first": first, "secondary": secondary,
                "log_file": None if log_path is None else log_path.name, "capture_bytes": total,
                "mock": False, "VM_or_NVIDIA_acceptance": False}
            try:
                self.persist_install_result(result, result_descriptor)
            except Exception as persistence:
                # A result-persistence error must not become a success receipt,
                # nor replace a prior installation failure with a second cause.
                self.update_operation(status="failed", phase="failed", progress=100,
                    message=(first["reason"] if first else
                             "Installation result could not be retained: " + type(persistence).__name__), terminal=True)
            finally:
                if result_descriptor is not None:
                    try:
                        os.close(result_descriptor)
                    except OSError as close_error:
                        self.update_operation(status="failed", phase="failed", progress=100,
                            message=(first["reason"] if first else
                                     "Installation result descriptor closure is unknown: " + type(close_error).__name__), terminal=True)

    def persist_install_result(self, value, reserved=None):
        """Normal per-operation producer, useful to diagnostics and native tests.

        Never writes a VM pass, overwrites an old result, or accepts a caller's
        requested exit/closure. Mock mode never emits this normal receipt.
        """
        if self.mock or value.get("mock") is not False:
            raise RuntimeError("Synthetic installation cannot publish a normal result.")
        operation_id = value["operation_id"]
        if len(operation_id) != 32 or any(c not in "0123456789abcdef" for c in operation_id):
            raise RuntimeError("Invalid installation result identity.")
        root = self.state_root
        meta = root.lstat()
        if not (root.resolve() == root and stat.S_ISDIR(meta.st_mode) and
                meta.st_uid == os.getuid() and not meta.st_mode & 0o077):
            raise RuntimeError("Unsafe installation result directory.")
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(raw) > 65536:
            raise RuntimeError("Installation result exceeded its bound.")
        path = root / ("install-result-" + operation_id + ".json")
        descriptor = reserved if reserved is not None else os.open(path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            before = os.fstat(descriptor)
            if not (stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                    before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
                    (before.st_dev, before.st_ino) == (path.lstat().st_dev, path.lstat().st_ino)):
                raise RuntimeError("Reserved installation result custody changed.")
            os.lseek(descriptor, 0, os.SEEK_SET)
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise RuntimeError("Short installation result write.")
                view = view[written:]
            os.ftruncate(descriptor, len(raw))
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
        finally:
            if reserved is None:
                os.close(descriptor)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def diagnostics(self):
        if self.mock:
            return {
                "schemaVersion": 1,
                "text": "Safe simulation\n\nSynthetic target: /dev/vda (eligible)\nNo disks, privileges, or installers are reachable.",
            }
        sections = []
        for operation in ("media-info", "inventory-report"):
            try:
                sections.append(self.run_command([str(self.helper), operation]))
            except Exception as error:
                sections.append(f"{operation}: {error}")
        marker = self.state_root / "last-install-log"
        try:
            if marker.is_file() and not marker.is_symlink():
                log = Path(marker.read_text(encoding="utf-8")[:4096].strip())
                root = self.state_root.resolve()
                if log.is_file() and not log.is_symlink() and log.resolve().parent == root:
                    sections.append("Last installation log\n" + log.read_text(encoding="utf-8")[-65536:])
        except OSError:
            pass
        return {"schemaVersion": 1, "text": "\n\n".join(sections)[:MAX_DIAGNOSTICS]}

    def power(self, action):
        self.require_idle()
        if action not in ("stay", "restart", "shutdown"):
            raise ValueError("The requested completion action is unsupported.")
        if self.mock or action == "stay":
            return {"schemaVersion": 1, "status": "simulated" if self.mock else "ready", "action": action}
        self.mark_runtime_state("power-requested")
        subprocess.Popen(
            ["systemctl", "reboot" if action == "restart" else "poweroff"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return {"schemaVersion": 1, "status": "requested", "action": action}

    def rollback_action(self):
        self.require_idle()
        if self.mock:
            return {"schemaVersion": 1, "status": "simulated"}
        if not self.rollback.is_file() or self.rollback.is_symlink():
            raise RuntimeError("The recovery tool is unavailable.")
        terminal = next((tool for tool in ("konsole", "xterm") if shutil_which(tool)), None)
        if terminal is None:
            raise RuntimeError("A recovery terminal is unavailable.")
        command = [terminal, "-e", "sudo", str(self.rollback)]
        subprocess.Popen(command, stdin=subprocess.DEVNULL, start_new_session=True)
        return {"schemaVersion": 1, "status": "opened"}

    def close(self):
        self.require_idle()
        browser_pid = self.runtime / "browser.pid"
        try:
            value = browser_pid.read_text(encoding="ascii").strip()
            if value.isdigit() and int(value) > 1:
                threading.Timer(0.75, lambda: os.kill(int(value), signal.SIGTERM)).start()
        except (OSError, ValueError, ProcessLookupError):
            pass
        threading.Timer(1.0, self.httpd.shutdown).start()


def shutil_which(name):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "OPEMOSWelcome/1"

    def log_message(self, _format, *_args):
        return

    @property
    def controller(self):
        return self.server.controller

    def send_payload(self, status, payload, content_type="application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", f"default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self' 'nonce-{self.controller.nonce}'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        if self.headers.get("X-OPEMOS-Token") != self.controller.token:
            return False
        origin = self.headers.get("Origin")
        if origin == self.controller.origin:
            return True
        # Browsers do not normally send Origin for same-origin GET requests.
        # Those endpoints are read-only and still require the unguessable token
        # injected into the loopback-served page. Mutations remain origin-bound.
        return self.command == "GET" and origin is None

    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith("/api/"):
            if not self.authorized():
                self.send_payload(403, {"error": "The welcome session is unauthorized."})
                return
            try:
                if path == "/api/bootstrap":
                    result = self.controller.bootstrap()
                elif path == "/api/status":
                    result = self.controller.operation_status()
                elif path == "/api/diagnostics":
                    result = self.controller.diagnostics()
                else:
                    self.send_payload(404, {"error": "Unknown operation."})
                    return
                self.send_payload(200, result)
            except Exception as error:
                self.send_payload(500, {"error": str(error)[:700]})
            return
        record = STATIC_FILES.get(path)
        if record is None:
            self.send_payload(404, b"Not found\n", "text/plain; charset=utf-8")
            return
        relative, content_type = record
        candidate = (self.controller.ui_root / relative).resolve()
        if candidate.parent != self.controller.ui_root and self.controller.ui_root not in candidate.parents:
            self.send_payload(404, b"Not found\n", "text/plain; charset=utf-8")
            return
        try:
            if candidate.is_symlink() or not candidate.is_file():
                raise OSError("The requested asset is unsafe.")
            body = candidate.read_bytes()
            if len(body) > MAX_STATIC_FILE:
                raise OSError("The requested asset is excessive.")
            if path in ("/", "/index.html"):
                body = body.replace(b'"__OPEMOS_SESSION_TOKEN__"', json.dumps(self.controller.token).encode())
                body = body.replace(b"__OPEMOS_CSP_NONCE__", self.controller.nonce.encode("ascii"))
                marker = self.controller.runtime / "ui-ready"
                descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.close(descriptor)
            self.send_payload(200, body, content_type)
        except OSError:
            self.send_payload(404, b"Not found\n", "text/plain; charset=utf-8")

    def do_POST(self):
        path = urlsplit(self.path).path
        if not self.authorized():
            self.send_payload(403, {"error": "The welcome session is unauthorized."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_REQUEST or self.headers.get("Content-Type") != "application/json":
                raise ValueError("The request is malformed or excessive.")
            document = json.loads(self.rfile.read(length))
            if not isinstance(document, dict):
                raise ValueError("The request has an unsupported shape.")
            if path == "/api/install":
                result = self.controller.start_install(document)
            elif path == "/api/power":
                result = self.controller.power(document.get("action"))
            elif path == "/api/rollback":
                result = self.controller.rollback_action()
            elif path == "/api/close":
                result = {"schemaVersion": 1, "status": "closing"}
                self.controller.close()
            else:
                self.send_payload(404, {"error": "Unknown operation."})
                return
            self.send_payload(200, result)
        except (ValueError, json.JSONDecodeError) as error:
            self.send_payload(400, {"error": str(error)[:700]})
        except Exception as error:
            self.send_payload(500, {"error": str(error)[:700]})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ui-root", type=Path)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--output-observer-only", action="store_true")
    parser.add_argument("--helper", default="/usr/lib/opemos-install-media/opemos-install-helper")
    parser.add_argument("--rollback", default="/home/deck/tools/opemos-rollback-last-update")
    parser.add_argument("--state-root", default="/home/deck/.local/state/open-opemos")
    parser.add_argument("--mock", action="store_true")
    args = parser.parse_args()
    if args.output_observer_only:
        if args.mock or args.ui_root is not None or args.runtime is not None:
            parser.error('finite output observer does not accept mock/UI/runtime overrides')
        state=Path(args.state_root)
        if state!=Path('/home/deck/.local/state/open-opemos'):
            parser.error('fixed normal guest output observer state required')
        if not Path('/sys/firmware/qemu_fw_cfg/by_name/opt/opemos/observer-manifest-sha256/raw').exists():
            if Path('/dev/virtio-ports/opemos.robot.observer').exists():
                raise RuntimeError('observer channel exists without required firmware manifest')
            return 0
        if os.getuid()!=1000:raise RuntimeError('actual admitted desktop UID1000 required')
        virtual=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
        if virtual.returncode!=0 or virtual.stdout.strip()not in(b'kvm',b'qemu'):
            raise RuntimeError('physical host observer execution refused before state creation')
        state.mkdir(mode=0o700,parents=True,exist_ok=True)
        info=state.lstat()
        if state.resolve()!=state or not stat.S_ISDIR(info.st_mode)or info.st_uid!=os.getuid()or stat.S_IMODE(info.st_mode)!=0o700:
            raise RuntimeError('actual private guest observer state required')
        thread=start_firmware_bound_output_observer(state)
        if thread is None:return 0  # no firmware operand, no observer work
        thread.join(890)
        if thread.is_alive():raise RuntimeError('finite observer worker closure UNKNOWN')
        result=thread.observer_result
        return 0 if result.get('first')is None and result.get('secondary')==[]and result.get('numeric_exit')==0 and result.get('stdout_eof')is True else 1
    if args.ui_root is None or args.runtime is None:
        parser.error('--ui-root and --runtime are required for the normal welcome UI')
    args.runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.runtime, 0o700)
    controller = Controller(args)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.controller = controller
    controller.httpd = server
    controller.origin = f"http://127.0.0.1:{server.server_port}"
    port_file = args.runtime / "port"
    port_file.write_text(str(server.server_port) + "\n", encoding="ascii")
    os.chmod(port_file, 0o600)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())

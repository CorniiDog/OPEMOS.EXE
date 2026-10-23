"""Native SteamOS guest SDK operations for the finite output-install test.

No import-time SDK loading or effects. Run only in the admitted graphical OMEN
guest as its real desktop UID. AT-SPI is observation only; input is XTest real
motion/button events, never accessibility activation, DOM, or a label click.
API ownership: https://docs.gtk.org/atspi2/class.Accessible.html and
https://docs.gtk.org/atspi2/method.Component.get_accessible_at_point.html .
"""
import ctypes as C
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import time
import zlib

FULL9=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


class NotReady(RuntimeError):
    """Only a missing native object; integrity/foreign/ambiguous is not retryable."""


def need(value, reason):
    if not value:raise RuntimeError(reason)


def signature(info):return {k:getattr(info,k)for k in FULL9}


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def held(path, cap, expected=None):
    path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and not before.st_mode&0o022 and
             0<=before.st_size<=cap,'bounded non-writable source/evidence file')
        raw=bytearray()
        while block:=os.read(fd,min(65536,cap+1-len(raw))):
            raw.extend(block);need(len(raw)<=cap,'held file overflow')
        need(len(raw)==before.st_size and signature(before)==signature(os.fstat(fd))==signature(path.lstat()),
             'held/named source/evidence changed')
        need(expected is None or hashlib.sha256(raw).hexdigest()==expected,'held source/evidence SHA mismatch')
        return bytes(raw),signature(before)
    finally:os.close(fd)


def create(path, raw):
    """Create-only actual guest evidence. No replacement or retry on collision."""
    path=Path(path)
    need(path.is_absolute()and path.parent.resolve()==path.parent and not os.path.lexists(path),'fresh evidence path')
    parent=path.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode)and parent.st_uid==os.getuid()and not parent.st_mode&0o077,'private guest evidence root')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        view=memoryview(raw)
        while view:
            count=os.write(fd,view);need(count>0,'short guest evidence write');view=view[count:]
        os.fsync(fd);info=os.fstat(fd)
        need(signature(info)==signature(path.lstat()),'guest output named inode changed')
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(directory)
        finally:os.close(directory)
        return {'path':str(path),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':signature(info)}
    finally:os.close(fd)


def process(pid, expected_uid):
    need(type(pid)is int and pid>1,'actual desktop PID')
    proc=Path('/proc')/str(pid)
    def birth():
        value=(proc/'stat').read_text();return int(value[value.rfind(')')+2:].split()[19])
    first=birth()
    uids=[line.split()[1:]for line in(proc/'status').read_text().splitlines()if line.startswith('Uid:')]
    need(uids==[[str(expected_uid)]*4],'all four actual desktop process UIDs')
    # /proc inode ownership is not the process UID. Hold the real executable.
    fd=os.open(proc/'exe',os.O_RDONLY|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and 0<before.st_size<=256*1024**2,'bounded actual executable')
        digest=hashlib.sha256();total=0
        while block:=os.read(fd,1048576):digest.update(block);total+=len(block)
        need(total==before.st_size and signature(before)==signature(os.fstat(fd))and birth()==first,'process/executable changed')
        after=[line.split()[1:]for line in(proc/'status').read_text().splitlines()if line.startswith('Uid:')]
        need(after==uids,'process UID changed during observation')
        return {'pid':pid,'start':first,'uids':[int(x)for x in uids[0]],
                'exe_sha256':digest.hexdigest(),'exe_identity':signature(before)}
    finally:os.close(fd)


def require_guest(expected_uid):
    need(type(expected_uid)is int and expected_uid>0 and os.getuid()==os.geteuid()==expected_uid,
         'native GUI must execute as exact admitted non-root guest desktop UID')
    result=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
    need(result.returncode==0 and result.stdout.strip()in(b'kvm',b'qemu')and len(result.stderr)<=4096,
         'actual KVM/QEMU guest required; physical host refused')
    release=Path('/etc/os-release').read_text()
    need(re.search(r'^ID=["\']?steamos["\']?$',release,re.M),'actual SteamOS guest required')
    need(os.uname().machine=='x86_64','exact existing x86_64 SteamOS output lane, not an invented ARM lane')
    return {'virtualization':result.stdout.decode().strip(),'numeric_exit':result.returncode,
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'kernel':os.uname().release,'architecture':os.uname().machine,
            'uid':os.getuid(),'clock_ns':time.monotonic_ns()}


class NativeDesktop:
    """Qualified native object -> hit -> XTest pair -> observed neutral state."""
    def __init__(self, expected_uid, deadline):
        self.guest=require_guest(expected_uid);self.uid=expected_uid;self.deadline=deadline
        self.display=None;self.closed=False
        # These bindings use the guest's installed SDK; absence is a real
        # prerequisite failure. Never install another dependency or mock it.
        import gi
        gi.require_version('Atspi','2.0')
        from gi.repository import Atspi, Gio, GLib
        # A user service can start before the display manager imports its
        # session environment. Read the actual existing user manager through
        # its native local SDK, never guess :0, copy cookies, dump environment
        # secrets, or change credentials/session configuration.
        bus=Gio.bus_get_sync(Gio.BusType.SESSION,None)
        readiness=[];until=min(deadline,time.monotonic()+30)
        while True:
            answer=bus.call_sync('org.freedesktop.systemd1','/org/freedesktop/systemd1',
                'org.freedesktop.DBus.Properties','Get',
                GLib.Variant('(ss)',('org.freedesktop.systemd1.Manager','Environment')),
                GLib.VariantType.new('(v)'),Gio.DBusCallFlags.NONE,1000,None).unpack()[0]
            values=answer.unpack()if hasattr(answer,'unpack')else answer
            need(type(values)is list or type(values)is tuple,'actual systemd session environment schema')
            selected={}
            for entry in values:
                need(type(entry)is str and '='in entry,'actual session environment entry schema')
                key,_,value=entry.partition('=')
                if key in('DISPLAY','XAUTHORITY','XDG_SESSION_TYPE','WAYLAND_DISPLAY'):
                    need(key not in selected and len(value)<=4096,'finite unique native session variable')
                    selected[key]=value
            readiness.append({'clock_ns':time.monotonic_ns(),'display_present':bool(selected.get('DISPLAY')),
                              'allowed_keys':sorted(selected)})
            if selected.get('DISPLAY'):
                for key,value in selected.items():
                    need(key not in os.environ or os.environ[key]==value,'conflicting actual session environment')
                    os.environ[key]=value
                break
            if time.monotonic()>=until:
                error=NotReady('actual graphical session DISPLAY absent before original native deadline')
                error.evidence={'native_session_readiness':readiness};raise error
            time.sleep(min(.5,max(0,until-time.monotonic())))
        self.session_readiness=readiness
        self.a=Atspi
        self.a.set_timeout(1000,1000)
        self.desktop=self.a.get_desktop(0)
        need(self.desktop is not None,'actual AT-SPI desktop absent')
        xname=ctypes.util.find_library('X11');tname=ctypes.util.find_library('Xtst')
        need(xname and tname,'actual X11/XTest SDK absent')
        self.x=C.CDLL(xname);self.xt=C.CDLL(tname)
        self.x.XOpenDisplay.argtypes=[C.c_char_p];self.x.XOpenDisplay.restype=C.c_void_p
        self.x.XDefaultRootWindow.argtypes=[C.c_void_p];self.x.XDefaultRootWindow.restype=C.c_ulong
        self.x.XDefaultScreen.argtypes=[C.c_void_p];self.x.XDefaultScreen.restype=C.c_int
        self.x.XDisplayWidth.argtypes=[C.c_void_p,C.c_int];self.x.XDisplayWidth.restype=C.c_int
        self.x.XDisplayHeight.argtypes=[C.c_void_p,C.c_int];self.x.XDisplayHeight.restype=C.c_int
        self.x.XSync.argtypes=[C.c_void_p,C.c_int];self.x.XSync.restype=C.c_int
        self.x.XCloseDisplay.argtypes=[C.c_void_p];self.x.XCloseDisplay.restype=C.c_int
        self.x.XConnectionNumber.argtypes=[C.c_void_p];self.x.XConnectionNumber.restype=C.c_int
        self.x.XQueryPointer.argtypes=[C.c_void_p,C.c_ulong,C.POINTER(C.c_ulong),C.POINTER(C.c_ulong),
            C.POINTER(C.c_int),C.POINTER(C.c_int),C.POINTER(C.c_int),C.POINTER(C.c_int),C.POINTER(C.c_uint)]
        self.x.XQueryPointer.restype=C.c_int
        self.xt.XTestFakeMotionEvent.argtypes=[C.c_void_p,C.c_int,C.c_int,C.c_int,C.c_ulong]
        self.xt.XTestFakeMotionEvent.restype=C.c_int
        self.xt.XTestFakeButtonEvent.argtypes=[C.c_void_p,C.c_uint,C.c_int,C.c_ulong]
        self.xt.XTestFakeButtonEvent.restype=C.c_int
        self.display=self.x.XOpenDisplay(None)
        need(self.display,'actual X11 session absent; no Xvfb/Wayland substitution')
        try:
            connection=self.x.XConnectionNumber(self.display)
            with socket.fromfd(connection,socket.AF_UNIX,socket.SOCK_STREAM)as peer:
                pid,uid,gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
            need(pid>1 and uid in(0,self.uid),'real local guest display server peer')
            server=Path('/proc')/str(pid)
            comm=(server/'comm').read_text().strip()
            need(comm in('Xorg','Xwayland'),'offscreen/nested/fake X server refused')
            raw=(server/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
            server_uids=[line.split()[1:]for line in(server/'status').read_text().splitlines()if line.startswith('Uid:')]
            need(len(server_uids)==1 and len(server_uids[0])==4 and all(int(v)in(0,self.uid)for v in server_uids[0]),
                 'actual guest display server credentials')
            self.server={'pid':pid,'start':int(fields[19]),'uid':uid,'gid':gid,'comm':comm,'uids':server_uids[0]}
            if comm=='Xwayland':
                parent=Path('/proc')/fields[1];compositor=(parent/'comm').read_text().strip()
                need(compositor in('gamescope','kwin_wayland'),'Xwayland must belong to actual guest compositor')
                raw_parent=(parent/'stat').read_text()
                self.server.update(compositor_pid=int(fields[1]),compositor=compositor,
                    compositor_start=int(raw_parent[raw_parent.rfind(')')+2:].split()[19]))
            self.root=self.x.XDefaultRootWindow(self.display);screen=self.x.XDefaultScreen(self.display)
            self.size={'width':self.x.XDisplayWidth(self.display,screen),'height':self.x.XDisplayHeight(self.display,screen)}
            need(self.size=={'width':1600,'height':900},'actual supported guest mode must be1600x900')
        except BaseException:
            self.close();raise

    def current(self):
        need(not self.closed and self.display and time.monotonic()<self.deadline,'original finite native phase deadline/session')
        need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.guest['boot_id'],'guest rebooted during native phase')
        server=Path('/proc')/str(self.server['pid']);raw=(server/'stat').read_text()
        need(int(raw[raw.rfind(')')+2:].split()[19])==self.server['start']and
             (server/'comm').read_text().strip()==self.server['comm'],'actual display server epoch changed')
        need([line.split()[1:]for line in(server/'status').read_text().splitlines()if line.startswith('Uid:')]==[self.server['uids']],
             'actual display server credentials changed')
        if 'compositor_pid'in self.server:
            parent=Path('/proc')/str(self.server['compositor_pid']);parent_stat=(parent/'stat').read_text()
            need(raw[raw.rfind(')')+2:].split()[1]==str(self.server['compositor_pid'])and
                 int(parent_stat[parent_stat.rfind(')')+2:].split()[19])==self.server['compositor_start']and
                 (parent/'comm').read_text().strip()==self.server['compositor'],'actual guest compositor epoch changed')

    def pointer(self):
        self.current();root=C.c_ulong();child=C.c_ulong();rx=C.c_int();ry=C.c_int();wx=C.c_int();wy=C.c_int();mask=C.c_uint()
        need(self.x.XQueryPointer(self.display,self.root,C.byref(root),C.byref(child),C.byref(rx),C.byref(ry),
             C.byref(wx),C.byref(wy),C.byref(mask))==1,'actual pointer query failed')
        return {'x':rx.value,'y':ry.value,'mask':mask.value,'left_down':bool(mask.value&256),'clock_ns':time.monotonic_ns()}

    def x_client_pid(self,window):
        """Server-observed local client PID, never a WM property fallback.

        ABI reference: official libXres1.2.2 XRes.h/XRes.c, archive SHA256
        9a7446f3484b9b7538ac5ee30d2c1ce9e5b7fbbaf1440e02f6cca186a1fa745f.
        QueryVersion returns1; QueryClientIds returns X11 Success (numeric0).
        These are distinct native SDK conventions, not success normalization.
        """
        self.current()
        if not hasattr(self,'xr'):
            library=ctypes.util.find_library('XRes');need(library,'native XRes SDK missing; no PID-property substitute')
            class Spec(C.Structure):_fields_=[('client',C.c_ulong),('mask',C.c_uint)]
            class Value(C.Structure):_fields_=[('spec',Spec),('length',C.c_long),('value',C.c_void_p)]
            xr=C.CDLL(library)
            xr.XResQueryExtension.argtypes=[C.c_void_p,C.POINTER(C.c_int),C.POINTER(C.c_int)];xr.XResQueryExtension.restype=C.c_int
            xr.XResQueryVersion.argtypes=[C.c_void_p,C.POINTER(C.c_int),C.POINTER(C.c_int)];xr.XResQueryVersion.restype=C.c_int
            xr.XResQueryClientIds.argtypes=[C.c_void_p,C.c_long,C.POINTER(Spec),C.POINTER(C.c_long),C.POINTER(C.POINTER(Value))]
            xr.XResQueryClientIds.restype=C.c_int
            xr.XResGetClientPid.argtypes=[C.POINTER(Value)];xr.XResGetClientPid.restype=C.c_int
            xr.XResClientIdsDestroy.argtypes=[C.c_long,C.POINTER(Value)];xr.XResClientIdsDestroy.restype=None
            event=C.c_int();error=C.c_int();major=C.c_int();minor=C.c_int()
            need(xr.XResQueryExtension(self.display,C.byref(event),C.byref(error))!=0 and
                 xr.XResQueryVersion(self.display,C.byref(major),C.byref(minor))==1 and
                 (major.value,minor.value)>=(1,2),'actual XRes1.2 local PID support required')
            self.xr=xr;self.xr_spec=Spec;self.xr_value=Value
        spec=self.xr_spec(window,2);count=C.c_long();values=C.POINTER(self.xr_value)()
        result=self.xr.XResQueryClientIds(self.display,1,C.byref(spec),C.byref(count),C.byref(values))
        try:
            need(result==0 and count.value==1 and values and values[0].spec.mask==2,
                 'actual X client PID query failed/unknown/ambiguous')
            pid=self.xr.XResGetClientPid(C.byref(values[0]));need(pid>1,'actual X client PID unknown; no input')
            return pid
        finally:
            if values:self.xr.XResClientIdsDestroy(count,values)

    def window_manager(self):
        """Independently qualify only the real WM frame role, not arbitrary parents."""
        atom=self.x.XInternAtom(self.display,b'_NET_SUPPORTING_WM_CHECK',True)
        window_type=self.x.XInternAtom(self.display,b'WINDOW',True)
        need(atom and window_type,'actual window manager identity unavailable')
        def supporting(window):
            actual=C.c_ulong();fmt=C.c_int();count=C.c_ulong();remaining=C.c_ulong();data=C.c_void_p()
            code=self.x.XGetWindowProperty(self.display,window,atom,0,1,False,window_type,
                C.byref(actual),C.byref(fmt),C.byref(count),C.byref(remaining),C.byref(data))
            try:
                need(code==0 and actual.value==window_type and fmt.value==32 and count.value==1 and
                     remaining.value==0 and data.value,'actual WM supporting-window property unknown')
                return int(C.cast(data,C.POINTER(C.c_ulong))[0])
            finally:
                if data.value:self.x.XFree(data)
        window=supporting(self.root);need(window>1 and supporting(window)==window,'actual WM self association missing')
        pid=self.x_client_pid(window);actor=process(pid,self.uid)
        executable=Path(os.readlink('/proc/'+str(pid)+'/exe'))
        need(str(executable)in('/usr/bin/kwin_x11','/usr/bin/kwin_wayland','/usr/bin/gamescope'),
             'unknown window manager executable; no parent waiver')
        raw,pin=held(executable,256*1024**2,actor['exe_sha256'])
        need(pin['st_uid']==0 and not pin['st_mode']&0o022 and process(pid,self.uid)==actor,
             'actual WM source/epoch/UID changed')
        return {'window':window,'actor':actor,'executable':str(executable)}

    def pointer_recipient(self,actor,point,window=None,require_pointer=True):
        """Actual topmost X window path, not a hit scoped inside a covered app.

        The exact native actor must also own an actual X11 client under the
        pointer. Native Wayland objects cannot silently become XTest targets.
        After Down only the already-owned client ID/actor/point is checked;
        control labels or titles are not required to stay unchanged for Up.
        """
        self.current();need(process(actor['pid'],self.uid)==actor,'pointer recipient actor epoch changed')
        self.x.XInternAtom.argtypes=[C.c_void_p,C.c_char_p,C.c_int];self.x.XInternAtom.restype=C.c_ulong
        self.x.XGetWindowProperty.argtypes=[C.c_void_p,C.c_ulong,C.c_ulong,C.c_long,C.c_long,C.c_int,C.c_ulong,
            C.POINTER(C.c_ulong),C.POINTER(C.c_int),C.POINTER(C.c_ulong),C.POINTER(C.c_ulong),C.POINTER(C.c_void_p)]
        self.x.XGetWindowProperty.restype=C.c_int
        self.x.XFree.argtypes=[C.c_void_p];self.x.XFree.restype=C.c_int
        self.x.XTranslateCoordinates.argtypes=[C.c_void_p,C.c_ulong,C.c_ulong,C.c_int,C.c_int,
            C.POINTER(C.c_int),C.POINTER(C.c_int),C.POINTER(C.c_ulong)]
        self.x.XTranslateCoordinates.restype=C.c_int
        pid_atom=self.x.XInternAtom(self.display,b'_NET_WM_PID',True)
        cardinal=self.x.XInternAtom(self.display,b'CARDINAL',True)
        need(pid_atom and cardinal,'actual X11 PID property type unavailable')
        selected=None;current=self.root;path=[]
        self.last_recipient={'path':path,'selected_client':None,'point':point,'clock_ns':time.monotonic_ns()}
        if require_pointer:
            observed=self.pointer();need([observed['x'],observed['y']]==point,'actual pointer point changed')
        for _ in range(32):
            child=C.c_ulong();x=C.c_int();y=C.c_int()
            need(self.x.XTranslateCoordinates(self.display,self.root,current,*point,C.byref(x),C.byref(y),C.byref(child))!=0,
                 'actual topmost point translation failed')
            if current!=self.root:
                actual=C.c_ulong();fmt=C.c_int();count=C.c_ulong();remaining=C.c_ulong();data=C.c_void_p()
                result=self.x.XGetWindowProperty(self.display,current,pid_atom,0,1,False,cardinal,
                    C.byref(actual),C.byref(fmt),C.byref(count),C.byref(remaining),C.byref(data))
                observed=None;owner_pid=self.x_client_pid(current)
                path.append({'window':current,'server_client_pid':owner_pid,'property_pid':None})
                if owner_pid!=actor['pid']:
                    need(selected is None,'foreign X client inside the owned recipient; no input')
                    wm=self.window_manager()
                    need(wm['actor']['pid']==owner_pid,'foreign/unqualified overlay above target; no input')
                    path[-1]['qualified_wm_frame']=wm
                try:
                    need(result==0,'actual pointer recipient PID query failed')
                    if actual.value:
                        need(actual.value==cardinal and fmt.value==32 and count.value==1 and remaining.value==0 and data.value,
                             'actual pointer PID property schema unknown')
                        observed=int(C.cast(data,C.POINTER(C.c_ulong))[0])
                        path[-1]['property_pid']=observed
                        need(observed==owner_pid,'PID property does not match server-observed client PID')
                    if owner_pid==actor['pid']and selected is None:selected=current
                finally:
                    if data.value:self.x.XFree(data)
            if not child.value:break
            need(child.value!=current,'cyclic native X window path');current=child.value
        else:raise RuntimeError('actual X11 pointer recipient traversal bound')
        self.last_recipient={'path':path,'selected_client':selected,'point':point,'clock_ns':time.monotonic_ns()}
        need(selected is not None and(window is None or selected==window),'exact owned native X11 client not under pointer')
        need(process(actor['pid'],self.uid)==actor,'pointer recipient changed during observation')
        return self.last_recipient

    def qualify_x_window(self,actor,native,recipient):
        """Unique same-actor/title/geometry X client matches the native frame."""
        self.x.XQueryTree.argtypes=[C.c_void_p,C.c_ulong,C.POINTER(C.c_ulong),C.POINTER(C.c_ulong),
            C.POINTER(C.POINTER(C.c_ulong)),C.POINTER(C.c_uint)];self.x.XQueryTree.restype=C.c_int
        self.x.XGetGeometry.argtypes=[C.c_void_p,C.c_ulong,C.POINTER(C.c_ulong),C.POINTER(C.c_int),C.POINTER(C.c_int),
            C.POINTER(C.c_uint),C.POINTER(C.c_uint),C.POINTER(C.c_uint),C.POINTER(C.c_uint)]
        self.x.XGetGeometry.restype=C.c_int
        pid_atom=self.x.XInternAtom(self.display,b'_NET_WM_PID',True)
        name_atom=self.x.XInternAtom(self.display,b'_NET_WM_NAME',True)
        utf8=self.x.XInternAtom(self.display,b'UTF8_STRING',True)
        cardinal=self.x.XInternAtom(self.display,b'CARDINAL',True)
        need(pid_atom and name_atom and utf8 and cardinal,'actual native X window identity properties absent')
        def prop(window,atom,expected):
            actual=C.c_ulong();fmt=C.c_int();count=C.c_ulong();remaining=C.c_ulong();data=C.c_void_p()
            result=self.x.XGetWindowProperty(self.display,window,atom,0,1024,False,expected,
                C.byref(actual),C.byref(fmt),C.byref(count),C.byref(remaining),C.byref(data))
            try:
                need(result==0 and remaining.value==0,'native X property failed/overflowed')
                if not actual.value:return None
                need(actual.value==expected and data.value,'native X property has unknown type')
                if expected==cardinal:
                    need(fmt.value==32 and count.value==1,'native X PID cardinal schema')
                    return int(C.cast(data,C.POINTER(C.c_ulong))[0])
                need(fmt.value==8 and 0<count.value<=4096,'native X title schema/size')
                return C.string_at(data,count.value).decode('utf-8',errors='strict')
            finally:
                if data.value:self.x.XFree(data)
        todo=[(self.root,0)];seen=set();matches=[];observations=[]
        while todo:
            self.current();window,depth=todo.pop()
            need(window not in seen and len(seen)<4096 and depth<=32,'complete bounded actual X window traversal')
            seen.add(window)
            if window!=self.root and prop(window,pid_atom,cardinal)==actor['pid']:
                name=prop(window,name_atom,utf8)
                root=C.c_ulong();x=C.c_int();y=C.c_int();w=C.c_uint();h=C.c_uint();border=C.c_uint();bits=C.c_uint()
                need(self.x.XGetGeometry(self.display,window,C.byref(root),C.byref(x),C.byref(y),C.byref(w),C.byref(h),
                     C.byref(border),C.byref(bits))!=0,'native X client geometry unavailable')
                child=C.c_ulong();sx=C.c_int();sy=C.c_int()
                need(self.x.XTranslateCoordinates(self.display,window,self.root,0,0,C.byref(sx),C.byref(sy),C.byref(child))!=0,
                     'native X client screen origin unavailable')
                rect=[sx.value,sy.value,w.value,h.value]
                observations.append({'window':window,'name':name,'rect':rect})
                if name==native['window_name']and rect==native['window_rect']:matches.append(window)
            root=C.c_ulong();parent=C.c_ulong();children=C.POINTER(C.c_ulong)();count=C.c_uint()
            need(self.x.XQueryTree(self.display,window,C.byref(root),C.byref(parent),C.byref(children),C.byref(count))!=0,
                 'actual X window child traversal failed')
            try:
                need(count.value<=4096,'actual X child count overflow')
                todo.extend((int(children[i]),depth+1)for i in range(count.value))
            finally:
                if children:self.x.XFree(children)
        self.last_x_windows={'native':native,'actual_clients':observations,'matches':matches,'clock_ns':time.monotonic_ns()}
        need(len(matches)==1 and matches[0]==recipient['selected_client'],
             'topmost actual X client does not uniquely match the exact native actor/window')
        need(process(actor['pid'],self.uid)==actor,'native X actor epoch changed during qualification')
        return matches[0]

    def tree(self):
        todo=[(self.desktop,0)];count=0
        while todo:
            self.current();obj,depth=todo.pop();count+=1
            need(obj is not None and count<=4096 and depth<=32,'complete bounded native tree')
            yield obj
            children=obj.get_child_count();need(type(children)is int and 0<=children<=4096,'native child count')
            todo.extend((obj.get_child_at_index(i),depth+1)for i in range(children))

    def application(self,title,exe_sha256):
        """Observe a unique real frame/actor; a title alone never authorizes it."""
        need(type(title)is str and title and re.fullmatch('[0-9a-f]{64}',exe_sha256),'exact current renderer source identity')
        matches=[]
        for obj in self.tree():
            if obj.get_role_name()in('frame','window')and obj.get_name()==title:
                actor=process(obj.get_process_id(),self.uid)
                if actor['exe_sha256']==exe_sha256:
                    identifier=obj.get_accessible_id();need(identifier,'native frame accessible ID absent')
                    matches.append({'process':actor,'window_accessible_id':identifier})
        if not matches:raise NotReady('actual source-bound welcome frame not mapped yet')
        need(len(matches)==1,'one source-bound actual welcome native frame required')
        return matches[0]

    def discover(self,application,name,role,description=None,prefix=False,required_text=None):
        """Native discovery followed by retained-ID/window/hit revalidation.

        The phase source supplies its fixed semantic selector. The actual API
        supplies the opaque accessible ID, not a fabricated DOM/object ID. No
        candidate/host workflow supplies coordinates or an input implementation.
        """
        actor=application['process'];matches=[]
        self.last_discovery={'name':name,'role':role,'required_text':required_text,'prefix':prefix,
                             'actor':actor,'actual_role_objects':[],'clock_ns':time.monotonic_ns()}
        need(process(actor['pid'],self.uid)==actor,'native discovery actor changed')
        for obj in self.tree():
            if obj.get_process_id()!=actor['pid']or obj.get_role_name()!=role:continue
            actual=obj.get_name()
            rows=self.last_discovery['actual_role_objects']
            need(len(rows)<128,'native discovery diagnostic bound exceeded; no input')
            description_value=obj.get_description()
            rows.append({'name':actual[:1024],'accessible_id':obj.get_accessible_id(),
                         'description':description_value[:1024]if isinstance(description_value,str)else description_value})
            if not(actual.startswith(name)if prefix else actual==name):continue
            if required_text is not None and required_text not in actual.split():continue
            desc=obj.get_description()
            if description is not None and desc!=description:continue
            states=obj.get_state_set()
            if not all(states.contains(s)for s in(self.a.StateType.ENABLED,self.a.StateType.VISIBLE,self.a.StateType.SHOWING)):continue
            identifier=obj.get_accessible_id();need(identifier,'native control accessible ID absent; no label-only fallback')
            matches.append({'accessible_id':identifier,'name':actual,'role':role,'description':desc,
                            'process':actor,'window_accessible_id':application['window_accessible_id']})
        if not matches:raise NotReady('actual native control not mapped/enabled yet')
        need(len(matches)==1,'unique actual qualified native control missing/ambiguous')
        self.control(matches[0])
        return matches[0]

    def control(self, spec):
        self.current()
        need(type(spec)is dict and set(spec)=={'accessible_id','name','role','description','process','window_accessible_id'},'exact native selector schema')
        need(type(spec['accessible_id'])is str and spec['accessible_id'],'no label-only native control selector')
        need(type(spec['window_accessible_id'])is str and spec['window_accessible_id'],'exact retained native window ID')
        wanted=spec['process'];need(process(wanted['pid'],self.uid)==wanted,'native actor birth/UID/executable changed')
        todo=[(self.desktop,0)];seen=0;matches=[];windows=[]
        while todo:
            self.current()
            obj,depth=todo.pop();seen+=1
            need(seen<=4096 and depth<=32,'complete bounded native accessibility traversal')
            pid=obj.get_process_id()
            if pid==wanted['pid'] and obj.get_accessible_id()==spec['accessible_id']and obj.get_name()==spec['name']and obj.get_role_name()==spec['role']and obj.get_description()==spec['description']:
                matches.append(obj)
            if pid==wanted['pid']and obj.get_accessible_id()==spec['window_accessible_id']and obj.get_role_name()in('frame','window'):
                windows.append(obj)
            count=obj.get_child_count();need(type(count)is int and 0<=count<=4096,'actual native child count')
            todo.extend((obj.get_child_at_index(i),depth+1)for i in range(count))
        need(len(matches)==len(windows)==1,'one exact qualified native control/window required')
        obj=matches[0];states=obj.get_state_set()
        need(all(states.contains(s)for s in(self.a.StateType.ENABLED,self.a.StateType.VISIBLE,self.a.StateType.SHOWING)),
             'actual native control must be enabled, visible and showing')
        component=obj.get_component_iface();need(component is not None,'actual component interface absent')
        rect=component.get_extents(self.a.CoordType.SCREEN)
        need(0<=rect.x<rect.x+rect.width<=1600 and 0<=rect.y<rect.y+rect.height<=900,
             'actual native control outside supported viewport')
        point=(rect.x+rect.width//2,rect.y+rect.height//2)
        window_component=windows[0].get_component_iface();need(window_component is not None,'native window component absent')
        window_rect=window_component.get_extents(self.a.CoordType.SCREEN)
        need(window_rect.x<=rect.x and window_rect.y<=rect.y and
             rect.x+rect.width<=window_rect.x+window_rect.width and rect.y+rect.height<=window_rect.y+window_rect.height,
             'control outside the exact retained native window')
        hit=window_component.get_accessible_at_point(*point,self.a.CoordType.SCREEN)
        self.last_hit={'target':{'accessible_id':spec['accessible_id'],'name':spec['name'],'role':spec['role'],
                      'process':wanted},'window_accessible_id':spec['window_accessible_id'],
                      'rect':[rect.x,rect.y,rect.width,rect.height],'point':list(point),'clock_ns':time.monotonic_ns(),
                      'actual_hit':None if hit is None else{'accessible_id':hit.get_accessible_id(),
                        'name':hit.get_name(),'role':hit.get_role_name(),'pid':hit.get_process_id()}}
        need(hit is not None and hit==obj,'native hit did not return the exact retained control')
        return obj,{'rect':[rect.x,rect.y,rect.width,rect.height],'point':list(point),'process':wanted,
                    'accessible_id':spec['accessible_id'],'clock_ns':time.monotonic_ns(),
                    'window_rect':[window_rect.x,window_rect.y,window_rect.width,window_rect.height],
                    'window_name':windows[0].get_name()}

    def click(self,spec,ledger):
        """Every attempt durable before SDK call; independent owned Up on error."""
        ledger=Path(ledger);parent=ledger.parent.lstat()
        need(ledger.is_absolute()and ledger.parent.resolve()==ledger.parent and stat.S_ISDIR(parent.st_mode)and
             parent.st_uid==os.getuid()and not parent.st_mode&0o077,'exact private native action ledger parent')
        fd=os.open(ledger,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        down_attempted=False;up_attempted=False;neutral_observed=False;first=None;secondary=[];up_tick=None
        def record(value):
            value=dict(value,clock_ns=time.monotonic_ns())
            raw=canonical(value)+b'\n';need(len(raw)<=16384,'bounded native action record')
            view=memoryview(raw)
            while view:
                n=os.write(fd,view);need(n>0,'short native ledger write');view=view[n:]
            os.fsync(fd)
        try:
            obj,initial=self.control(spec);point=initial['point']
            need(not self.pointer()['left_down'],'preexisting/unowned held left button')
            pre_recipient=self.pointer_recipient(spec['process'],point,require_pointer=False)
            owned_window=self.qualify_x_window(spec['process'],initial,pre_recipient)
            record({'phase':'qualified-before-motion','recipient':pre_recipient,'window':owned_window})
            record({'phase':'motion','attempted':True,'native':initial})
            need(self.xt.XTestFakeMotionEvent(self.display,-1,*point,0)!=0,'actual XTest motion failed')
            self.x.XSync(self.display,False)
            current=self.pointer();need([current['x'],current['y']]==point,'actual pointer did not reach native target')
            _,fresh=self.control(spec);need(fresh['rect']==initial['rect']and fresh['point']==point,'target moved before Down')
            recipient=self.pointer_recipient(spec['process'],point,owned_window)
            self.qualify_x_window(spec['process'],fresh,recipient)
            record({'phase':'actual-x11-recipient','observation':recipient})
            record({'phase':'down','attempted':True,'owned_pair_pending':True,'native':fresh})
            down_attempted=True
            returned=self.xt.XTestFakeButtonEvent(self.display,1,True,0)
            record({'phase':'down-return','numeric':returned,'delivery_ack':False})
            need(returned!=0,'XTest Down returned failure')
            self.x.XSync(self.display,False)
            held_pointer=self.pointer();need(held_pointer['left_down'],'actual Down state not observed')
            # Recheck actor, but do NOT require a UI control to remain unchanged
            # after Down; some widgets change state before Up. An owned Up is
            # paired on the same exact display/actor under the original deadline.
            need(process(spec['process']['pid'],self.uid)==spec['process'],'actor changed before owned Up')
            need([held_pointer['x'],held_pointer['y']]==point,'owned pair pointer recipient changed')
            record({'phase':'owned-up-recipient','observation':self.pointer_recipient(spec['process'],point,owned_window)})
            up_tick=time.monotonic_ns()
            record({'phase':'up','attempted':True,'same_owned_pair':True})
            up_attempted=True;returned=self.xt.XTestFakeButtonEvent(self.display,1,False,0)
            record({'phase':'up-return','numeric':returned,'delivery_ack':False})
            need(returned!=0,'XTest Up returned failure');self.x.XSync(self.display,False)
            neutral=self.pointer();need(not neutral['left_down'],'actual input neutrality unproven')
            neutral_observed=True
            record({'phase':'neutral','observed':neutral})
            return {'native':initial,'button':'left','click_count':1,'neutral':neutral,'backend':'XTest','up_attempted_ns':up_tick}
        except BaseException as error:
            first=error
            if down_attempted and not neutral_observed:
                try:
                    self.current();need(process(spec['process']['pid'],self.uid)==spec['process'],'cleanup actor unknown')
                    observed=self.pointer()
                    if observed['left_down']:
                        need([observed['x'],observed['y']]==initial['point'],'owned cleanup recipient point unknown')
                        record({'phase':'cleanup-owned-recipient','observation':
                                self.pointer_recipient(spec['process'],initial['point'],owned_window)})
                        record({'phase':'cleanup-up','attempted':True,'same_owned_pair':True})
                        up_attempted=True
                        returned=self.xt.XTestFakeButtonEvent(self.display,1,False,0)
                        record({'phase':'cleanup-up-return','numeric':returned,'delivery_ack':False})
                        need(returned!=0,'owned cleanup Up failed');self.x.XSync(self.display,False)
                        observed=self.pointer()
                    need(not observed['left_down'],'cleanup input neutrality UNKNOWN')
                    neutral_observed=True;record({'phase':'cleanup-neutral','observed':observed})
                except BaseException as cleanup:secondary.append(type(cleanup).__name__)
            try:record({'phase':'failed','first':type(error).__name__,'secondary':secondary,
                        'down_attempted':down_attempted,'up_attempted':up_attempted})
            except BaseException as persistence:secondary.append(type(persistence).__name__)
            for item in secondary:error.add_note('native secondary: '+item)
            raise
        finally:
            try:os.close(fd)
            except OSError as error:
                if first is None:raise
                first.add_note('native ledger close UNKNOWN: '+type(error).__name__)

    def close(self):
        if self.display:
            display=self.display;self.display=None
            need(self.x.XCloseDisplay(display)==0,'actual X11 connection closure failed')
            self.closed=True

    def type_confirmation(self,application,field_spec,text,ledger):
        """Real key pairs into a pointer-focused field, never button activation.

        Typing the normal erase phrase is not a shortcut for the required native
        Begin-installation click. Every owned key/Shift has independent release
        and actual keymap neutrality observation on failure.
        """
        need(type(text)is str and re.fullmatch(r'ERASE [a-z0-9]{1,48}',text),'only exact ordinary disk erase phrase')
        actor=application['process'];owned=[];primary=None;fd=None
        need(field_spec['process']==actor,'confirmation field belongs to another actor')
        field,_=self.control(field_spec)
        need(field.get_state_set().contains(self.a.StateType.FOCUSED)and field.get_editable_text_iface()is not None,
             'real pointer-focused editable confirmation field required')
        text_iface=field.get_text_iface();need(text_iface is not None and text_iface.get_text(0,-1)=='',
             'confirmation field must actually be empty; no select-all/direct state bypass')
        self.x.XGetInputFocus.argtypes=[C.c_void_p,C.POINTER(C.c_ulong),C.POINTER(C.c_int)];self.x.XGetInputFocus.restype=C.c_int
        self.x.XInternAtom.argtypes=[C.c_void_p,C.c_char_p,C.c_int];self.x.XInternAtom.restype=C.c_ulong
        self.x.XGetWindowProperty.argtypes=[C.c_void_p,C.c_ulong,C.c_ulong,C.c_long,C.c_long,C.c_int,C.c_ulong,
            C.POINTER(C.c_ulong),C.POINTER(C.c_int),C.POINTER(C.c_ulong),C.POINTER(C.c_ulong),C.POINTER(C.c_void_p)]
        self.x.XGetWindowProperty.restype=C.c_int
        self.x.XQueryTree.argtypes=[C.c_void_p,C.c_ulong,C.POINTER(C.c_ulong),C.POINTER(C.c_ulong),C.POINTER(C.POINTER(C.c_ulong)),C.POINTER(C.c_uint)]
        self.x.XQueryTree.restype=C.c_int
        self.x.XFree.argtypes=[C.c_void_p];self.x.XFree.restype=C.c_int
        self.x.XQueryKeymap.argtypes=[C.c_void_p,C.c_void_p];self.x.XQueryKeymap.restype=C.c_int
        self.x.XStringToKeysym.argtypes=[C.c_char_p];self.x.XStringToKeysym.restype=C.c_ulong
        self.x.XKeysymToKeycode.argtypes=[C.c_void_p,C.c_ulong];self.x.XKeysymToKeycode.restype=C.c_ubyte
        self.x.XkbKeycodeToKeysym.argtypes=[C.c_void_p,C.c_ubyte,C.c_int,C.c_int];self.x.XkbKeycodeToKeysym.restype=C.c_ulong
        self.xt.XTestFakeKeyEvent.argtypes=[C.c_void_p,C.c_uint,C.c_int,C.c_ulong];self.xt.XTestFakeKeyEvent.restype=C.c_int
        def keys():
            value=C.create_string_buffer(32)
            need(self.x.XQueryKeymap(self.display,value)!=0,'actual keymap query failed')
            return value.raw
        def focused():
            self.current();need(process(actor['pid'],self.uid)==actor,'typing actor epoch changed')
            need(field.get_state_set().contains(self.a.StateType.FOCUSED),'native confirmation field lost real focus')
            focus=C.c_ulong();revert=C.c_int();self.x.XGetInputFocus(self.display,C.byref(focus),C.byref(revert))
            window=focus.value;atom=self.x.XInternAtom(self.display,b'_NET_WM_PID',False)
            for _ in range(32):
                need(window not in(0,1,self.root),'unowned keyboard focus')
                actual=C.c_ulong();fmt=C.c_int();count=C.c_ulong();remain=C.c_ulong();data=C.c_void_p()
                code=self.x.XGetWindowProperty(self.display,window,atom,0,1,False,0,C.byref(actual),C.byref(fmt),C.byref(count),C.byref(remain),C.byref(data))
                try:
                    if code==0 and data.value and fmt.value==32 and count.value==1:
                        need(C.cast(data,C.POINTER(C.c_ulong))[0]==actor['pid'],'foreign keyboard focus actor')
                        return window
                finally:
                    if data.value:self.x.XFree(data)
                root=C.c_ulong();parent=C.c_ulong();children=C.POINTER(C.c_ulong)();n=C.c_uint()
                need(self.x.XQueryTree(self.display,window,C.byref(root),C.byref(parent),C.byref(children),C.byref(n))!=0,'focus ancestry unknown')
                if children:self.x.XFree(children)
                window=parent.value
            raise RuntimeError('keyboard focus ancestry bound')
        path=Path(ledger);parent=path.parent.lstat()
        need(path.is_absolute()and path.parent.resolve()==path.parent and parent.st_uid==self.uid and
             stat.S_ISDIR(parent.st_mode)and not parent.st_mode&0o077,'private typing ledger')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        def record(value):
            raw=canonical(dict(value,clock_ns=time.monotonic_ns()))+b'\n'
            need(len(raw)<=4096,'bounded key event record')
            view=memoryview(raw)
            while view:
                n=os.write(fd,view);need(n>0,'short key ledger write');view=view[n:]
            os.fsync(fd)
        def event(code,down,cleanup=False):
            focus=focused();record({'keycode':code,'down':down,'attempted':True,'focus':focus,'cleanup':cleanup})
            if down:owned.append(code)
            returned=self.xt.XTestFakeKeyEvent(self.display,code,down,0)
            record({'keycode':code,'down':down,'numeric_return':returned,'delivery_ack':False})
            need(returned!=0,'native key SDK return failed');self.x.XSync(self.display,False)
            observed=bool(keys()[code//8]&(1<<(code%8)))
            need(observed is down,'actual key state differs from owned request')
            if not down:owned.remove(code)
        try:
            need(not any(keys())and not self.pointer()['mask']&0xff,'preexisting/unowned key or modifier state')
            focused()
            for char in text:
                self.current();symbol=self.x.XStringToKeysym(b'space'if char==' 'else char.encode('ascii'))
                code=self.x.XKeysymToKeycode(self.display,symbol);need(code and symbol,'actual keyboard mapping unavailable')
                base=self.x.XkbKeycodeToKeysym(self.display,code,0,0);shifted=self.x.XkbKeycodeToKeysym(self.display,code,0,1)
                need(symbol in(base,shifted),'actual keyboard level unsupported')
                shift=None
                if symbol!=base:
                    shift=self.x.XKeysymToKeycode(self.display,self.x.XStringToKeysym(b'Shift_L'));need(shift,'actual Shift mapping absent')
                    event(shift,True)
                event(code,True);event(code,False)
                if shift:event(shift,False)
            need(not any(keys()),'actual key neutrality UNKNOWN')
            need(text_iface.get_text(0,-1)==text,'actual native confirmation text differs from typed phrase')
            record({'neutral':True,'typed_characters':len(text)})
            return {'typed_characters':len(text),'neutral':True,'backend':'XTest','activation_bypass':False}
        except BaseException as error:
            primary=error;errors=[]
            for code in reversed(owned[:]):
                try:event(code,False,True)
                except BaseException as cleanup:errors.append(type(cleanup).__name__)
            try:record({'first':type(error).__name__,'secondary':errors,'owned_pending':owned})
            except BaseException as persistence:errors.append(type(persistence).__name__)
            for item in errors:error.add_note('owned key cleanup: '+item)
            raise
        finally:
            try:os.close(fd)
            except OSError as error:
                if primary is None:raise
                primary.add_note('key ledger close UNKNOWN: '+type(error).__name__)

    def screenshot(self,path):
        """Read actual display pixels; no generated frame or viewer scaling."""
        class Visual(C.Structure):
            _fields_=[('ext_data',C.c_void_p),('visualid',C.c_ulong),('class_',C.c_int),
                ('red_mask',C.c_ulong),('green_mask',C.c_ulong),('blue_mask',C.c_ulong),
                ('bits_per_rgb',C.c_int),('map_entries',C.c_int)]
        self.current();image=None;primary=None;started=time.monotonic_ns()
        self.x.XDefaultVisual.argtypes=[C.c_void_p,C.c_int];self.x.XDefaultVisual.restype=C.POINTER(Visual)
        self.x.XGetImage.argtypes=[C.c_void_p,C.c_ulong,C.c_int,C.c_int,C.c_uint,C.c_uint,C.c_ulong,C.c_int]
        self.x.XGetImage.restype=C.c_void_p
        self.x.XGetPixel.argtypes=[C.c_void_p,C.c_int,C.c_int];self.x.XGetPixel.restype=C.c_ulong
        self.x.XDestroyImage.argtypes=[C.c_void_p];self.x.XDestroyImage.restype=C.c_int
        try:
            visual=self.x.XDefaultVisual(self.display,self.x.XDefaultScreen(self.display)).contents
            need(visual.class_==4,'actual TrueColor display required')
            masks=[visual.red_mask,visual.green_mask,visual.blue_mask]
            need(all(masks)and not(masks[0]&masks[1]or masks[0]&masks[2]or masks[1]&masks[2]),'actual TrueColor pixel masks')
            scales=[]
            for mask in masks:
                shift=(mask&-mask).bit_length()-1;maximum=mask>>shift
                need(maximum<=65535 and maximum&(maximum+1)==0,'contiguous actual pixel component')
                scales.append((mask,shift,maximum))
            image=self.x.XGetImage(self.display,self.root,0,0,1600,900,C.c_ulong(-1).value,2)
            need(image,'actual display acquisition failed')
            pixels=bytearray()
            for y in range(900):
                self.current();pixels.append(0)
                for x in range(1600):
                    pixel=self.x.XGetPixel(image,x,y)
                    pixels.extend(round(((pixel&mask)>>shift)*255/maximum)for mask,shift,maximum in scales)
            def chunk(kind,body):return struct.pack('!I',len(body))+kind+body+struct.pack('!I',zlib.crc32(kind+body)&0xffffffff)
            raw=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!IIBBBBB',1600,900,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(bytes(pixels)))+chunk(b'IEND',b'')
            need(len(raw)<=16*1024**2,'actual screenshot cap')
            self.current();pin=create(path,raw)
            return dict(pin,kind='screenshot',public=True,display=self.size,guest=self.guest,
                        server=self.server,started_ns=started,finished_ns=time.monotonic_ns())
        except BaseException as error:primary=error;raise
        finally:
            if image:
                try:need(self.x.XDestroyImage(image)!=0,'native image descriptor closure failed')
                except BaseException as error:
                    if primary is None:raise
                    primary.add_note('native image close UNKNOWN: '+type(error).__name__)

    def nvidia_render(self,expected_version):
        """Actual direct GLX GPU clear/readback, separate from GUI acceptance.

        A pbuffer is not a window or screenshot substitute. The normal welcome
        pointer transaction still needs its actual desktop frames and reports.
        """
        self.current();need(re.fullmatch(r'575\.[0-9]+\.[0-9]+',expected_version),'exact required575 version')
        name=ctypes.util.find_library('GL');need(name,'actual GLX SDK missing');gl=C.CDLL(name)
        display=self.display;screen=self.x.XDefaultScreen(display)
        gl.glXChooseFBConfig.argtypes=[C.c_void_p,C.c_int,C.POINTER(C.c_int),C.POINTER(C.c_int)];gl.glXChooseFBConfig.restype=C.POINTER(C.c_void_p)
        gl.glXCreateNewContext.argtypes=[C.c_void_p,C.c_void_p,C.c_int,C.c_void_p,C.c_int];gl.glXCreateNewContext.restype=C.c_void_p
        gl.glXCreatePbuffer.argtypes=[C.c_void_p,C.c_void_p,C.POINTER(C.c_int)];gl.glXCreatePbuffer.restype=C.c_ulong
        gl.glXMakeContextCurrent.argtypes=[C.c_void_p,C.c_ulong,C.c_ulong,C.c_void_p];gl.glXMakeContextCurrent.restype=C.c_int
        gl.glXIsDirect.argtypes=[C.c_void_p,C.c_void_p];gl.glXIsDirect.restype=C.c_int
        gl.glXDestroyPbuffer.argtypes=[C.c_void_p,C.c_ulong];gl.glXDestroyPbuffer.restype=None
        gl.glXDestroyContext.argtypes=[C.c_void_p,C.c_void_p];gl.glXDestroyContext.restype=None
        gl.glGetString.argtypes=[C.c_uint];gl.glGetString.restype=C.c_char_p
        gl.glGetError.argtypes=[];gl.glGetError.restype=C.c_uint
        gl.glClearColor.argtypes=[C.c_float]*4;gl.glClearColor.restype=None
        gl.glClear.argtypes=[C.c_uint];gl.glClear.restype=None
        gl.glFinish.argtypes=[];gl.glFinish.restype=None
        gl.glReadPixels.argtypes=[C.c_int,C.c_int,C.c_int,C.c_int,C.c_uint,C.c_uint,C.c_void_p];gl.glReadPixels.restype=None
        self.x.XFree.argtypes=[C.c_void_p];self.x.XFree.restype=C.c_int
        configs=None;context=None;pbuffer=0;primary=None;bound=False
        try:
            attributes=(C.c_int*15)(0x8012,1,0x8010,4,0x8011,1,8,8,9,8,10,8,11,8,0)
            count=C.c_int();configs=gl.glXChooseFBConfig(display,screen,attributes,C.byref(count))
            need(configs and 0<count.value<=4096,'actual compatible GLX framebuffer config')
            context=gl.glXCreateNewContext(display,configs[0],0x8014,None,True);need(context,'actual GLX context creation')
            pbuffer=gl.glXCreatePbuffer(display,configs[0],(C.c_int*5)(0x8041,4,0x8040,4,0));need(pbuffer,'actual GLX pbuffer')
            need(gl.glXMakeContextCurrent(display,pbuffer,pbuffer,context)!=0,'actual GLX make-current');bound=True
            need(gl.glXIsDirect(display,context)==1,'indirect/software GLX context refused')
            strings={key:gl.glGetString(enum)for key,enum in(('vendor',0x1f00),('renderer',0x1f01),('version',0x1f02))}
            need(all(type(v)is bytes and 0<len(v)<=1024 for v in strings.values()),'actual GL identity strings')
            strings={k:v.decode('utf-8',errors='strict')for k,v in strings.items()}
            need('NVIDIA'in strings['vendor']and 'NVIDIA'in strings['version']and
                 re.search(r'\b'+re.escape(expected_version)+r'\b',strings['version'])and
                 not any(s in strings['renderer'].lower()for s in('llvmpipe','softpipe','software')),
                 'actual current NVIDIA575 direct renderer required')
            need(gl.glGetError()==0,'initial GL error')
            observations=[]
            for color,expected in(((1.,0.,0.,1.),bytes((255,0,0,255))*16),((0.,1.,0.,1.),bytes((0,255,0,255))*16)):
                self.current();gl.glClearColor(*color);gl.glClear(0x4000);gl.glFinish()
                pixels=(C.c_ubyte*64)();gl.glReadPixels(0,0,4,4,0x1908,0x1401,pixels)
                need(gl.glGetError()==0 and bytes(pixels)==expected,'actual GPU clear/readback did not match')
                observations.append({'sha256':hashlib.sha256(bytes(pixels)).hexdigest(),'bytes':64,'clock_ns':time.monotonic_ns()})
            return {'kind':'ACTUAL_GLX_NVIDIA_READBACK_V1','guest':self.guest,'direct':True,
                    'identity':strings,'readbacks':observations,'GUI_acceptance':False}
        except BaseException as error:primary=error;raise
        finally:
            errors=[]
            if bound:
                try:need(gl.glXMakeContextCurrent(display,0,0,None)!=0,'GLX unbind failed')
                except BaseException as error:errors.append(type(error).__name__)
            for operation in((lambda:gl.glXDestroyPbuffer(display,pbuffer))if pbuffer else None,
                             (lambda:gl.glXDestroyContext(display,context))if context else None,
                             (lambda:self.x.XFree(configs))if configs else None):
                if operation:
                    try:operation()
                    except BaseException as error:errors.append(type(error).__name__)
            if errors:
                if primary is None:raise RuntimeError('native GLX cleanup UNKNOWN: '+repr(errors))
                primary.add_note('native GLX cleanup UNKNOWN: '+repr(errors))

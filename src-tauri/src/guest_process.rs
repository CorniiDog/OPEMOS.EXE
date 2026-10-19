//! Custody for the existing SSH guest-command producer only, not QEMU.
use std::{
    io,
    process::{Child, Command, ExitStatus},
};

pub(crate) struct GuestChild {
    child: Child,
    reaped: Option<ExitStatus>,
    #[cfg(unix)]
    birth: String,
    #[cfg(windows)]
    job: windows_job::Job,
}

impl std::ops::Deref for GuestChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}
impl std::ops::DerefMut for GuestChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

/// No guest instruction executes before its tree is bound to this owner.
pub(crate) fn spawn_guest_process(command: &mut Command) -> Result<GuestChild, String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        let job =
            windows_job::Job::new().map_err(|e| format!("Could not create guest job: {e}"))?;
        spawn_guest_in_job(command, job)
    }
    #[cfg(unix)]
    let child = command
        .spawn()
        .map_err(|e| format!("Could not spawn owned guest command: {e}"))?;
    #[cfg(unix)]
    {
        let mut child = child;
        let birth = match unix_birth(child.id()) {
            Ok(birth) => birth,
            Err(error) => {
                // This freshly returned, unreaped direct child was created
                // with process_group(0); no foreign PID lookup is authorized.
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.kill();
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            return Err(format!("Guest birth unavailable: {error}; root={status}"))
                        }
                        result if std::time::Instant::now() >= deadline => {
                            return Err(format!(
                                "Guest birth unavailable: {error}; cleanup={result:?}"
                            ))
                        }
                        _ => std::thread::sleep(std::time::Duration::from_millis(1)),
                    }
                }
            }
        };
        #[cfg(test)]
        eprintln!(
            "owned guest producer root={} group={} {birth}",
            child.id(),
            child.id()
        );
        Ok(GuestChild {
            child,
            reaped: None,
            birth,
        })
    }
}

#[cfg(windows)]
fn spawn_guest_in_job(command: &mut Command, job: windows_job::Job) -> Result<GuestChild, String> {
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0000_0004 | 0x0800_0000);
    let mut child = command
        .spawn()
        .map_err(|e| format!("Could not spawn owned guest command: {e}"))?;
    if let Err(error) = job.bind_and_resume(&child) {
        let kill = child.kill();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(format!(
                        "Guest job binding/resume refused: {error}; kill={kill:?}; root={status}"
                    ))
                }
                result if std::time::Instant::now() >= deadline => {
                    return Err(format!(
                    "Guest job binding/resume refused: {error}; kill={kill:?}; cleanup={result:?}"
                ))
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(1)),
            }
        }
    }
    Ok(GuestChild {
        child,
        reaped: None,
        job,
    })
}

#[cfg(target_os = "linux")]
fn unix_birth(pid: u32) -> io::Result<String> {
    use std::{io::Read, os::unix::fs::MetadataExt};
    let mut file = std::fs::File::open(format!("/proc/{pid}/stat"))?;
    let uid = file.metadata()?.uid();
    if uid != unsafe { libc::geteuid() } {
        return Err(io::Error::other("guest UID mismatch"));
    }
    let mut stat = String::new();
    file.by_ref().take(8193).read_to_string(&mut stat)?;
    if stat.len() > 8192 {
        return Err(io::Error::other("guest stat excessive"));
    }
    let fields = stat
        .rsplit_once(')')
        .ok_or_else(|| io::Error::other("guest stat malformed"))?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let ticks = fields
        .get(19)
        .ok_or_else(|| io::Error::other("guest birth absent"))?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    Ok(format!("uid={uid} birthTicks={ticks}"))
}

#[cfg(target_os = "macos")]
fn unix_birth(pid: u32) -> io::Result<String> {
    let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    if unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    } != size
    {
        return Err(io::Error::last_os_error());
    }
    if info.pbi_pid != pid || info.pbi_uid != unsafe { libc::geteuid() } {
        return Err(io::Error::other("guest birth/UID mismatch"));
    }
    Ok(format!(
        "uid={} birth={}.{:06}",
        info.pbi_uid, info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}

impl GuestChild {
    pub(crate) fn observed_exit(&mut self) -> io::Result<bool> {
        if self.reaped.is_some() {
            return Ok(true);
        }
        #[cfg(unix)]
        {
            // WNOWAIT retains our direct child's PID even after it exits. That
            // occupied PID binds the original process_group(0) identity; do not
            // require a late getpgid(zombie), and never reap before tree stop.
            let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            #[cfg(target_os = "macos")]
            let pid = info.si_pid;
            #[cfg(not(target_os = "macos"))]
            let pid = unsafe { info.si_pid() };
            Ok(pid != 0)
        }
        #[cfg(windows)]
        {
            self.child.try_wait().map(|status| {
                self.reaped = status;
                status.is_some()
            })
        }
    }

    pub(crate) fn stop_tree(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        {
            if self.reaped.is_some() {
                return Ok(());
            }
            // A prior external wait/ECHILD must refuse signaling. Successful
            // WNOWAIT proves this is still our unreaped original direct child.
            self.observed_exit()?;
            #[cfg(test)]
            eprintln!(
                "owned guest signal root={} {} unreaped=true",
                self.child.id(),
                self.birth
            );
            #[cfg(not(test))]
            let _ = &self.birth;
            let group = i32::try_from(self.child.id()).map_err(io::Error::other)?;
            if group <= 0 {
                return Err(io::Error::other("invalid owned group"));
            }
            if unsafe { libc::kill(-group, libc::SIGKILL) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
            Ok(())
        }
        #[cfg(windows)]
        self.job.stop()
    }

    pub(crate) fn reap_owned(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.reaped {
            return Ok(Some(status));
        }
        let status = self.child.try_wait()?;
        self.reaped = status;
        Ok(status)
    }

    pub(crate) fn tree_absent(&self) -> io::Result<bool> {
        #[cfg(unix)]
        {
            let group = i32::try_from(self.child.id()).map_err(io::Error::other)?;
            if unsafe { libc::kill(-group, 0) } == 0 {
                return Ok(false);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(true)
            } else {
                Err(error)
            }
        }
        #[cfg(windows)]
        self.job.absent()
    }
}

#[cfg(all(test, target_os = "macos"))]
mod native_causal_diagnostic {
    use super::*;
    use std::{
        io::Read,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        process::Stdio,
        time::{Duration, Instant},
    };

    fn snapshot(label: &str, pid: u32) {
        let pgid = unsafe { libc::getpgid(pid as i32) };
        let pgid_error = if pgid < 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        let sid = unsafe { libc::getsid(pid as i32) };
        let sid_error = if sid < 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        let mut bsd = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        let got = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut bsd as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        let bsd_error = if got != size {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        eprintln!("NATIVE_SNAPSHOT {label} pid={pid} pgid={pgid} pgidError={pgid_error:?} sid={sid} sidError={sid_error:?} bsdBytes={got} bsdError={bsd_error:?} nativePid={} ppid={} bsdPGID={} uid={} gid={} ruid={} rgid={} status={} birth={}.{}", bsd.pbi_pid, bsd.pbi_ppid, bsd.pbi_pgid, bsd.pbi_uid, bsd.pbi_gid, bsd.pbi_ruid, bsd.pbi_rgid, bsd.pbi_status, bsd.pbi_start_tvsec, bsd.pbi_start_tvusec);
    }

    #[test]
    fn native_causal_diagnostic_original_producer_groups_and_eof() {
        eprintln!(
            "COLLECTION_ONLY parent={} uid={} euid={} gid={} egid={}",
            std::process::id(),
            unsafe { libc::getuid() },
            unsafe { libc::geteuid() },
            unsafe { libc::getgid() },
            unsafe { libc::getegid() }
        );
        snapshot("parent", std::process::id());
        for (label, script) in [
            ("normal-exited-root", "printf 'ROOT=%s\\n' $$; exit 7"),
            ("live-root-writer", "sh -c 'sleep 0.4; exit 37' & w=$!; printf 'ROOT=%s WRITER=%s\\n' $$ $w; wait $w; printf 'WRITER_WAIT=%s\\n' $?; exit 9"),
            ("exited-root-writer", "sh -c 'sleep 0.4; exit 37' & w=$!; printf 'ROOT=%s WRITER=%s\\n' $$ $w; exit 11"),
        ] {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut child = spawn_guest_process(&mut command).expect("actual unchanged owned producer");
            let root = child.id();
            let mut stdout = child.stdout.take().unwrap();
            let mut stderr = child.stderr.take().unwrap();
            for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) }, 0);
            }
            std::thread::sleep(Duration::from_millis(40));
            let mut raw = Vec::new(); let mut errors = Vec::new(); let mut block = [0; 8192];
            match stdout.read(&mut block) { Ok(n) => raw.extend_from_slice(&block[..n]), Err(e) if e.kind()==io::ErrorKind::WouldBlock => {}, Err(e) => errors.push(format!("first read:{e}")) }
            let text=String::from_utf8_lossy(&raw);
            let writer=text.split_whitespace().find_map(|x| x.strip_prefix("WRITER=").and_then(|x|x.parse::<u32>().ok()));
            snapshot(&format!("{label}-before"),root);
            let kfd=unsafe { libc::kqueue() }; assert!(kfd>=0); let queue=unsafe { OwnedFd::from_raw_fd(kfd) };
            if let Some(writer)=writer {
                snapshot("writer-before",writer);
                let event=libc::kevent { ident:writer as _, filter:libc::EVFILT_PROC, flags:libc::EV_ADD|libc::EV_ENABLE|libc::EV_ONESHOT, fflags:libc::NOTE_EXIT|libc::NOTE_EXITSTATUS, data:0, udata:std::ptr::null_mut() };
                let result=unsafe { libc::kevent(queue.as_raw_fd(), &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
                eprintln!("WRITER_EXIT_WATCH writer={writer} registration={result} error={:?}",if result<0 {Some(io::Error::last_os_error())} else {None});
            }
            eprintln!("BEFORE_STOP case={label} root={root} writer={writer:?} stdoutFD={} stderrFD={} WNOWAIT={:?}",stdout.as_raw_fd(),stderr.as_raw_fd(),child.observed_exit());
            let stopped=child.stop_tree();
            eprintln!("ORIGINAL_STOP case={label} result={stopped:?} errno={:?}",stopped.as_ref().err().and_then(|e|e.raw_os_error()));
            snapshot(&format!("{label}-after-stop"),root);
            // Diagnostic-only bounded fallback uses the original unreaped Child
            // handle. Writers are finite; no guessed descendant/group signal.
            eprintln!("DIRECT_ROOT_HANDLE_KILL case={label} result={:?}",child.kill());
            let deadline=Instant::now()+Duration::from_secs(3); let mut out_eof=false;let mut err_eof=false;let mut status=None;
            while Instant::now()<deadline && (!out_eof || !err_eof || status.is_none()) {
                if !out_eof { match stdout.read(&mut block) { Ok(0)=>out_eof=true, Ok(n)=>raw.extend_from_slice(&block[..n]), Err(e) if e.kind()==io::ErrorKind::WouldBlock=>{}, Err(e)=>{errors.push(format!("stdout:{e}"));break;} } }
                if !err_eof { match stderr.read(&mut block) { Ok(0)=>err_eof=true, Ok(n)=>eprintln!("CHILD_STDERR case={label} {:?}",String::from_utf8_lossy(&block[..n])), Err(e) if e.kind()==io::ErrorKind::WouldBlock=>{}, Err(e)=>{errors.push(format!("stderr:{e}"));break;} } }
                if status.is_none(){status=child.reap_owned().expect("original root handle reap");}
                std::thread::sleep(Duration::from_millis(2));
            }
            if let Some(writer)=writer {
                let mut event=unsafe { std::mem::zeroed::<libc::kevent>() }; let timeout=libc::timespec {tv_sec:0,tv_nsec:0};
                let n=unsafe {libc::kevent(queue.as_raw_fd(),std::ptr::null(),0,&mut event,1,&timeout)};
                let (event_flags,event_fflags,event_data)=(event.flags,event.fflags,event.data);
                eprintln!("WRITER_EXIT_EVENT case={label} writer={writer} events={n} flags={} fflags={} rawWaitStatus={} errno={:?}; status UNKNOWN unless NOTE_EXITSTATUS delivered",event_flags,event_fflags,event_data,if n<0{Some(io::Error::last_os_error())}else{None});
                snapshot("writer-after",writer);
            }
            let members=Command::new("/bin/ps").args(["-axo","pid=,ppid=,pgid=,uid=,stat=,command="]).output().unwrap();
            let group_rows=String::from_utf8_lossy(&members.stdout).lines().filter(|line|line.split_whitespace().nth(2).and_then(|x|x.parse::<u32>().ok())==Some(root)).map(str::to_owned).collect::<Vec<_>>();
            eprintln!("FINAL case={label} rootStatus={status:?} stdoutEOF={out_eof} stderrEOF={err_eof} sourceBytes={:?} readErrors={errors:?} groupMembers={group_rows:?} originalTreeAbsent={:?}",String::from_utf8_lossy(&raw),child.tree_absent());
            drop(stdout);drop(stderr);drop(queue);
            assert!(status.is_some() && out_eof && err_eof && errors.is_empty(),"finite diagnostic root/FD closure UNKNOWN");
        }
    }
}

#[cfg(windows)]
mod windows_job {
    use super::*;
    use std::{
        ffi::c_void,
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    };
    type Handle = *mut c_void;
    #[repr(C)]
    #[derive(Default)]
    struct BasicLimits {
        process_time: i64,
        job_time: i64,
        flags: u32,
        min_working_set: usize,
        max_working_set: usize,
        process_limit: u32,
        affinity: usize,
        priority: u32,
        scheduling: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimits {
        basic: BasicLimits,
        io: [u64; 6],
        process_memory: usize,
        job_memory: usize,
        peak_process: usize,
        peak_job: usize,
    }
    #[repr(C)]
    #[derive(Default)]
    struct Accounting {
        times: [i64; 4],
        page_faults: u32,
        total: u32,
        active: u32,
        terminated: u32,
    }
    #[repr(C)]
    struct ThreadEntry {
        size: u32,
        usage: u32,
        id: u32,
        owner: u32,
        base: i32,
        delta: i32,
        flags: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(job: Handle, class: i32, data: *const c_void, size: u32) -> i32;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn IsProcessInJob(process: Handle, job: Handle, result: *mut i32) -> i32;
        fn GetProcessTimes(
            process: Handle,
            created: *mut u64,
            exited: *mut u64,
            kernel: *mut u64,
            user: *mut u64,
        ) -> i32;
        fn TerminateJobObject(job: Handle, code: u32) -> i32;
        fn QueryInformationJobObject(
            job: Handle,
            class: i32,
            data: *mut c_void,
            size: u32,
            returned: *mut u32,
        ) -> i32;
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
        fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry) -> i32;
        fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry) -> i32;
        fn OpenThread(access: u32, inherit: i32, id: u32) -> Handle;
        fn GetProcessIdOfThread(thread: Handle) -> u32;
        fn ResumeThread(thread: Handle) -> u32;
    }
    pub(super) struct Job(OwnedHandle);
    impl Job {
        pub(super) fn new() -> io::Result<Self> {
            let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = Self(unsafe { OwnedHandle::from_raw_handle(raw) });
            let mut limits = ExtendedLimits::default();
            limits.basic.flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if unsafe {
                SetInformationJobObject(
                    raw,
                    9,
                    (&limits as *const ExtendedLimits).cast(),
                    std::mem::size_of::<ExtendedLimits>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }
        pub(super) fn bind_and_resume(&self, child: &Child) -> io::Result<()> {
            if unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), child.as_raw_handle()) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut in_job = 0;
            if unsafe { IsProcessInJob(child.as_raw_handle(), self.0.as_raw_handle(), &mut in_job) }
                == 0
                || in_job == 0
            {
                return Err(io::Error::other(
                    "suspended guest was not bound to owned job",
                ));
            }
            let (mut created, mut exited, mut kernel, mut user) = (0, 0, 0, 0);
            if unsafe {
                GetProcessTimes(
                    child.as_raw_handle(),
                    &mut created,
                    &mut exited,
                    &mut kernel,
                    &mut user,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            #[cfg(test)]
            eprintln!(
                "owned guest job bound root={} birthFileTime={created} suspended=true",
                child.id()
            );
            let raw = unsafe { CreateToolhelp32Snapshot(4, 0) };
            if raw == -1isize as Handle {
                return Err(io::Error::last_os_error());
            }
            let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
            let mut entry: ThreadEntry = unsafe { std::mem::zeroed() };
            entry.size = std::mem::size_of::<ThreadEntry>() as u32;
            let mut found = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) } != 0;
            let mut remaining = 131072;
            while found && remaining > 0 {
                remaining -= 1;
                if entry.owner == child.id() {
                    let raw = unsafe { OpenThread(0x802, 0, entry.id) };
                    if raw.is_null() {
                        return Err(io::Error::last_os_error());
                    }
                    let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
                    if unsafe { GetProcessIdOfThread(thread.as_raw_handle()) } != child.id() {
                        return Err(io::Error::other("suspended guest thread identity changed"));
                    }
                    if unsafe { ResumeThread(thread.as_raw_handle()) } != 1 {
                        return Err(io::Error::other(
                            "guest initial thread was not suspended exactly once",
                        ));
                    }
                    return Ok(());
                }
                found = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) } != 0;
            }
            Err(io::Error::other(
                "suspended guest initial thread unavailable",
            ))
        }
        pub(super) fn stop(&self) -> io::Result<()> {
            if unsafe { TerminateJobObject(self.0.as_raw_handle(), 1) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
        pub(super) fn absent(&self) -> io::Result<bool> {
            let mut info = Accounting::default();
            if unsafe {
                QueryInformationJobObject(
                    self.0.as_raw_handle(),
                    1,
                    (&mut info as *mut Accounting).cast(),
                    std::mem::size_of::<Accounting>() as u32,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(info.active == 0)
        }
    }

    #[test]
    fn windows_owned_job_binding_failure_never_runs_guest_code() {
        use std::{
            os::windows::process::CommandExt,
            process::Stdio,
            time::{Duration, Instant},
        };
        let job = Job::new().expect("create real owned native job");
        let mut limits = ExtendedLimits::default();
        limits.basic.flags = 0x2000 | 0x8; // KILL_ON_CLOSE | ACTIVE_PROCESS
        limits.basic.process_limit = 1;
        assert_ne!(
            unsafe {
                SetInformationJobObject(
                    job.0.as_raw_handle(),
                    9,
                    (&limits as *const ExtendedLimits).cast(),
                    std::mem::size_of::<ExtendedLimits>() as u32,
                )
            },
            0
        );
        let mut occupant = Command::new("cmd.exe");
        occupant
            .args(["/d", "/c", "exit 0"])
            .creation_flags(4 | 0x0800_0000)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut occupant = occupant
            .spawn()
            .expect("create one exact suspended quota occupant");
        assert_ne!(
            unsafe { AssignProcessToJobObject(job.0.as_raw_handle(), occupant.as_raw_handle()) },
            0
        );
        let marker = std::env::temp_dir().join(format!(
            "opemos-binding-refused-{}-{}",
            std::process::id(),
            occupant.id()
        ));
        assert!(!marker.exists());
        let mut command = Command::new("cmd.exe");
        command
            .args(["/d", "/c"])
            .arg(format!("echo MUST_NOT_RUN>\"{}\"", marker.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let result = super::spawn_guest_in_job(&mut command, job);
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("actual native job quota binding must refuse"),
        };
        eprintln!("actual native binding failure: {error}");
        assert!(error.contains("binding/resume refused"));
        assert!(
            error.contains("root="),
            "failed candidate root closure must be measured: {error}"
        );
        assert!(!marker.exists(), "unbound guest code must never run");
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(status) = occupant.try_wait().unwrap() {
                eprintln!("owned quota occupant closed status={status}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "owned quota occupant did not close"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn owned_guest_cancel_and_repeated_finalize_retain_original_custody() {
        use std::{
            process::Stdio,
            time::{Duration, Instant},
        };
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = spawn_guest_process(&mut command).unwrap();
        child.stop_tree().unwrap();
        child.stop_tree().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !child.observed_exit().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let status = child.reap_owned().unwrap().unwrap();
        assert_eq!(child.reap_owned().unwrap(), Some(status));
        child.stop_tree().unwrap(); // Cached original closure must not signal a reused PID.
        assert!(child.tree_absent().unwrap());
    }
}

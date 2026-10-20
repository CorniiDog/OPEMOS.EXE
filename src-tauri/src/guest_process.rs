//! Custody for the existing SSH guest-command producer only, not QEMU.
use std::{
    io,
    process::{Child, Command, ExitStatus},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

// Notification is not proof of thread termination or EOF. It only wakes the
// owning caller so its real JoinHandle/native custody checks need not wait for
// another coalesced timer tick after a reader has completed its body.
#[derive(Clone, Debug)]
pub(crate) struct GuestReaderWake {
    owner: thread::Thread,
    completed: Arc<AtomicUsize>,
}

pub(crate) struct GuestReaderCompletion(GuestReaderWake);

impl GuestReaderWake {
    fn new() -> Self {
        Self {
            owner: thread::current(),
            completed: Arc::new(AtomicUsize::new(0)),
        }
    }
    pub(crate) fn guard(&self) -> GuestReaderCompletion {
        GuestReaderCompletion(self.clone())
    }
}

impl Drop for GuestReaderCompletion {
    fn drop(&mut self) {
        self.0.completed.fetch_add(1, Ordering::Release);
        self.0.owner.unpark();
    }
}

pub(crate) struct GuestChild {
    child: Child,
    pub(crate) reader_wake: GuestReaderWake,
    #[cfg(test)]
    pub(crate) native_trace: native_trace::NativeTrace,
    reaped: Option<ExitStatus>,
    #[cfg(unix)]
    birth: String,
    #[cfg(unix)]
    stop_requested: bool,
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
            reader_wake: GuestReaderWake::new(),
            #[cfg(test)]
            native_trace: native_trace::NativeTrace::new(child.id()),
            child,
            reaped: None,
            birth,
            stop_requested: false,
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
        reader_wake: GuestReaderWake::new(),
        #[cfg(test)]
        native_trace: native_trace::NativeTrace::new(child.id()),
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

#[cfg(target_os = "linux")]
fn linux_group_members(group: i32) -> io::Result<Vec<i32>> {
    use std::io::Read;
    #[cfg(test)]
    use std::os::unix::fs::MetadataExt;
    if group <= 0 {
        return Err(io::Error::other("invalid guest group enumeration"));
    }
    let mut members = Vec::new();
    for (count, entry) in std::fs::read_dir("/proc")?.enumerate() {
        if count >= 65536 {
            return Err(io::Error::other("guest process enumeration excessive"));
        }
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let mut file = match std::fs::File::open(entry.path().join("stat")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            result => result?,
        };
        let mut raw = String::new();
        file.by_ref().take(8193).read_to_string(&mut raw)?;
        let fields = raw
            .rsplit_once(')')
            .ok_or_else(|| io::Error::other("guest stat malformed"))?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        if raw.len() > 8192 {
            return Err(io::Error::other("guest stat excessive"));
        }
        let observed = fields
            .get(2)
            .ok_or_else(|| io::Error::other("guest group absent"))?
            .parse::<i32>()
            .map_err(io::Error::other)?;
        if observed == group {
            // procfs inode ownership is not process identity: it may become
            // root-owned for an exited/nondumpable same-UID process. Read the
            // kernel's actual credentials, never waive an unknown/foreign UID.
            let mut status = String::new();
            let source = match std::fs::File::open(entry.path().join("status")) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                result => result?,
            };
            source.take(65537).read_to_string(&mut status)?;
            if status.len() > 65536 {
                return Err(io::Error::other("guest status excessive"));
            }
            let uids = status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .ok_or_else(|| io::Error::other("guest process credentials unavailable"))?
                .split_whitespace()
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(io::Error::other)?;
            if uids.len() != 4 || uids.iter().any(|uid| *uid != unsafe { libc::geteuid() }) {
                return Err(io::Error::other("guest group contains foreign UID"));
            }
            #[cfg(test)]
            eprintln!("owned Linux group member pid={pid} group={group} procInodeUID={} actualUIDs={uids:?}", file.metadata()?.uid());
            members.push(pid);
        }
    }
    members.sort_unstable();
    Ok(members)
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

#[cfg(target_os = "macos")]
fn darwin_group_members(group: i32) -> io::Result<Vec<i32>> {
    if group <= 0 {
        return Err(io::Error::other("invalid guest group enumeration"));
    }
    // libproc returns zero on both empty enumeration and error. Unknown or
    // denied enumeration must never become evidence that writers are absent.
    let mut members = [0_i32; 1024];
    unsafe { *libc::__error() = 0 };
    let bytes = unsafe {
        libc::proc_listpids(
            2, // PROC_PGRP_ONLY, sys/proc_info.h
            group as u32,
            members.as_mut_ptr().cast(),
            std::mem::size_of_val(&members) as i32,
        )
    };
    let error = io::Error::last_os_error();
    if bytes < 0 || (bytes == 0 && error.raw_os_error() != Some(0)) {
        return Err(error);
    }
    if bytes as usize >= std::mem::size_of_val(&members)
        || !(bytes as usize).is_multiple_of(std::mem::size_of::<i32>())
    {
        return Err(io::Error::other("guest group enumeration incomplete"));
    }
    let count = bytes as usize / std::mem::size_of::<i32>();
    let mut observed = members[..count].to_vec();
    if observed.iter().any(|pid| *pid <= 0) {
        return Err(io::Error::other("guest group enumeration invalid member"));
    }
    observed.sort_unstable();
    if observed.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(io::Error::other("guest group enumeration duplicate member"));
    }
    Ok(observed)
}

#[cfg(all(test, target_os = "macos"))]
fn darwin_member_note(pid: i32) -> String {
    let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let actual = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if actual != size || info.pbi_pid != pid as u32 {
        return format!("pid={pid} uid=UNKNOWN birth=UNKNOWN state=UNKNOWN");
    }
    format!(
        "pid={pid} uid={} birth={}.{:06} state={}",
        info.pbi_uid, info.pbi_start_tvsec, info.pbi_start_tvusec, info.pbi_status
    )
}

#[cfg(target_os = "macos")]
fn darwin_only_exited_original(
    group: i32,
    root: i32,
    original_birth: &str,
    exited_wnowait: bool,
) -> io::Result<bool> {
    if group <= 0 || group != root || !exited_wnowait || original_birth.is_empty() {
        return Err(io::Error::other(
            "original exited guest group identity unavailable",
        ));
    }
    let members = darwin_group_members(group)?;
    #[cfg(test)]
    {
        let details = members
            .iter()
            .map(|pid| darwin_member_note(*pid))
            .collect::<Vec<_>>();
        eprintln!(
            "owned guest native group root={root} birth={original_birth} uid={} state=WNOWAIT_EXITED memberIDs={members:?} members={details:?}",
            unsafe { libc::geteuid() }
        );
    }
    // waitid(WNOWAIT) retains the original direct child's occupied PID and
    // birth identity until reap. XNU includes that exited zombie in zombproc.
    // No other group member may be called absent, even if its own state is
    // unknown or it is not permitted to receive the group signal.
    Ok(members.is_empty() || members == [root])
}

impl GuestChild {
    pub(crate) fn bind_reader_owner(&mut self) {
        self.reader_wake = GuestReaderWake::new();
    }
    pub(crate) fn wait_reader_progress(&self, deadline: Instant, closing: bool) {
        if closing
            && (self.reader_wake.completed.load(Ordering::Acquire) != 0
                || self.reader_wake.owner.id() != thread::current().id())
        {
            // A notified body can still be in Rust thread-exit bookkeeping.
            // Yield only during the original bounded cleanup, never treat the
            // notification as is_finished/join or extend the deadline.
            thread::yield_now();
        } else {
            thread::park_timeout(
                Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
    #[cfg(test)]
    pub(crate) fn native_final_observation(&mut self) {
        // Observe only after the unchanged real joins. Never stop, reap, retry,
        // or turn a late native observation into successful deadline closure.
        if !self.native_trace.enabled() {
            return;
        }
        self.native_trace
            .record("final.reaped_cached", 0, i64::from(self.reaped.is_some()));
        self.native_trace.record(
            "final.stdout_handle_owned",
            1,
            i64::from(self.stdout.is_some()),
        );
        self.native_trace.record(
            "final.stderr_handle_owned",
            2,
            i64::from(self.stderr.is_some()),
        );
        #[cfg(target_os = "macos")]
        {
            let exited = self.observed_exit();
            self.native_trace.record(
                "final.exit_observation",
                0,
                match exited {
                    Ok(exited) => i64::from(exited),
                    Err(error) => -i64::from(error.raw_os_error().unwrap_or(1)),
                },
            );
            self.native_trace
                .record("final.group.enter", 0, i64::from(self.id()));
            let members = darwin_group_members(self.id() as i32);
            self.native_trace.record(
                "final.group.return",
                0,
                match &members {
                    Ok(members) => members.len() as i64,
                    Err(error) => -i64::from(error.raw_os_error().unwrap_or(1)),
                },
            );
            if let Ok(members) = members {
                for member in members {
                    self.native_trace
                        .record("final.group.member", 0, i64::from(member));
                }
            }
        }
    }

    /// Keep the original direct child unreaped while proving its isolated group
    /// has no descendants. A successful kill request is not this proof.
    pub(crate) fn descendants_absent(&mut self) -> io::Result<bool> {
        #[cfg(test)]
        self.native_trace.record("descendants_absent.enter", 0, 0);
        let result: io::Result<bool> = (|| {
            #[cfg(unix)]
            {
                if !self.observed_exit()? {
                    return Ok(false);
                }
                let group = i32::try_from(self.child.id()).map_err(io::Error::other)?;
                #[cfg(target_os = "macos")]
                let members = {
                    #[cfg(test)]
                    self.native_trace
                        .record("group.enumeration.enter", 0, i64::from(group));
                    let result = darwin_group_members(group);
                    #[cfg(test)]
                    {
                        self.native_trace.record(
                            "group.enumeration.return",
                            0,
                            match &result {
                                Ok(members) => members.len() as i64,
                                Err(error) => -i64::from(error.raw_os_error().unwrap_or(1)),
                            },
                        );
                        if let Ok(members) = &result {
                            for member in members {
                                self.native_trace
                                    .record("group.member", 0, i64::from(*member));
                            }
                        }
                    }
                    result?
                };
                #[cfg(target_os = "linux")]
                let members = linux_group_members(group)?;
                Ok(members.is_empty() || members == [group])
            }
            #[cfg(windows)]
            self.job.absent()
        })();
        #[cfg(test)]
        self.native_trace.record(
            "descendants_absent.return",
            0,
            match &result {
                Ok(value) => i64::from(*value),
                Err(error) => -i64::from(error.raw_os_error().unwrap_or(1)),
            },
        );
        result
    }

    pub(crate) fn observed_exit(&mut self) -> io::Result<bool> {
        #[cfg(test)]
        self.native_trace.record("observed_exit.enter", 0, 0);
        let result: io::Result<bool> = (|| {
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
        })();
        #[cfg(test)]
        self.native_trace.record(
            "observed_exit.return",
            0,
            match &result {
                Ok(value) => i64::from(*value),
                Err(error) => -i64::from(error.raw_os_error().unwrap_or(1)),
            },
        );
        result
    }

    pub(crate) fn stop_tree(&mut self) -> io::Result<()> {
        #[cfg(test)]
        self.native_trace.record("stop_tree.enter", 0, 0);
        let result: io::Result<()> = (|| {
            #[cfg(unix)]
            {
                if self.reaped.is_some() {
                    return Ok(());
                }
                // A prior external wait/ECHILD must refuse signaling. Successful
                // WNOWAIT proves this is still our unreaped original direct child.
                let exited = self.observed_exit()?;
                // XNU may reject another signal to a dying original. Skip it only
                // after a complete native enumeration proves there is no other
                // member; a cached successful request cannot hide inherited writers.
                #[cfg(target_os = "macos")]
                if self.stop_requested {
                    let group = i32::try_from(self.child.id()).map_err(io::Error::other)?;
                    let members = {
                        #[cfg(test)]
                        self.native_trace
                            .record("group.enumeration.enter", 0, i64::from(group));
                        let result = darwin_group_members(group);
                        #[cfg(test)]
                        {
                            self.native_trace.record(
                                "group.enumeration.return",
                                0,
                                match &result {
                                    Ok(members) => members.len() as i64,
                                    Err(error) => -i64::from(error.raw_os_error().unwrap_or(1)),
                                },
                            );
                            if let Ok(members) = &result {
                                for member in members {
                                    self.native_trace
                                        .record("group.member", 0, i64::from(*member));
                                }
                            }
                        }
                        result?
                    };
                    if members.is_empty() || members == [group] {
                        return Ok(());
                    }
                    for member in members {
                        if member == group {
                            // observed_exit above retains the ORIGINAL direct
                            // child with WNOWAIT even when XNU no longer exposes
                            // its proc_bsdinfo. Do not replace that custody proof
                            // with an unavailable zombie metadata query.
                            continue;
                        }
                        // Unknown/foreign UID stays a refusal, never absent.
                        unix_birth(member as u32)?;
                    }
                }
                #[cfg(not(target_os = "macos"))]
                let _ = exited;
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
                #[cfg(test)]
                self.native_trace
                    .record("signal.enter", 0, i64::from(group));
                let signal_result = unsafe { libc::kill(-group, libc::SIGKILL) };
                let signal_error = (signal_result != 0).then(io::Error::last_os_error);
                #[cfg(test)]
                self.native_trace.record(
                    "signal.return",
                    0,
                    signal_error
                        .as_ref()
                        .map(|error| -i64::from(error.raw_os_error().unwrap_or(1)))
                        .unwrap_or(0),
                );
                if let Some(error) = signal_error {
                    #[cfg(target_os = "macos")]
                    if error.raw_os_error() == Some(libc::EPERM)
                        && exited
                        && darwin_only_exited_original(group, group, &self.birth, exited)?
                    {
                        // WNOWAIT retains the original direct child; native group
                        // has no live or foreign member. The original is already
                        // exited, so direct child.kill() would reintroduce EPERM.
                        self.stop_requested = true;
                        return Ok(());
                    }
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        return Err(error);
                    }
                } else {
                    self.stop_requested = true;
                }
                Ok(())
            }
            #[cfg(windows)]
            self.job.stop()
        })();
        #[cfg(test)]
        self.native_trace.record(
            "stop_tree.return",
            0,
            match &result {
                Ok(value) => {
                    let _ = value;
                    0
                }
                Err(error) => -i64::from(error.raw_os_error().unwrap_or(1)),
            },
        );
        result
    }

    pub(crate) fn reap_owned(&mut self) -> io::Result<Option<ExitStatus>> {
        #[cfg(test)]
        self.native_trace.record("reap_owned.enter", 0, 0);
        let result: io::Result<Option<ExitStatus>> = (|| {
            if let Some(status) = self.reaped {
                return Ok(Some(status));
            }
            let status = self.child.try_wait()?;
            self.reaped = status;
            Ok(status)
        })();
        #[cfg(test)]
        self.native_trace.record(
            "reap_owned.return",
            0,
            match &result {
                Ok(value) => i64::from(value.is_some()),
                Err(error) => -i64::from(error.raw_os_error().unwrap_or(1)),
            },
        );
        #[cfg(all(test, unix))]
        if let Ok(Some(status)) = &result {
            use std::os::unix::process::ExitStatusExt;
            self.native_trace
                .record("reap.status.raw", 0, i64::from(status.into_raw()));
        }
        result
    }

    pub(crate) fn tree_absent(&self) -> io::Result<bool> {
        #[cfg(test)]
        self.native_trace.record("tree_absent.enter", 0, 0);
        let result: io::Result<bool> = (|| {
            #[cfg(unix)]
            {
                let group = i32::try_from(self.child.id()).map_err(io::Error::other)?;
                if unsafe { libc::kill(-group, 0) } == 0 {
                    return Ok(false);
                }
                let error = io::Error::last_os_error();
                #[cfg(target_os = "macos")]
                if error.raw_os_error() == Some(libc::EPERM) {
                    return Ok(darwin_group_members(group)?.is_empty());
                }
                if error.raw_os_error() == Some(libc::ESRCH) {
                    Ok(true)
                } else {
                    Err(error)
                }
            }
            #[cfg(windows)]
            self.job.absent()
        })();
        #[cfg(test)]
        self.native_trace.record(
            "tree_absent.return",
            0,
            match &result {
                Ok(value) => i64::from(*value),
                Err(error) => -i64::from(error.raw_os_error().unwrap_or(1)),
            },
        );
        result
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
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_exited_root_only_group_preserves_status_and_streams() {
        use std::{
            io::Read,
            process::Stdio,
            time::{Duration, Instant},
        };
        assert!(!darwin_group_members(unsafe { libc::getpgrp() })
            .unwrap()
            .is_empty());
        assert!(darwin_group_members(0).is_err());
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "printf original-output; exit 7"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = spawn_guest_process(&mut command).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !child.observed_exit().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let members = darwin_group_members(child.id() as i32).unwrap();
        eprintln!("retained original native members={members:?}");
        assert!(members.is_empty() || members == [child.id() as i32]);
        assert!(darwin_only_exited_original(
            child.id() as i32,
            child.id() as i32,
            &child.birth,
            true
        )
        .unwrap());
        child.stop_tree().unwrap();
        let mut output = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        let mut errors = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut errors)
            .unwrap();
        assert_eq!(output, "original-output");
        assert!(errors.is_empty());
        let status = child.reap_owned().unwrap().unwrap();
        eprintln!(
            "owned guest native closure root={} stdoutEOF=true stderrEOF=true reapedStatus={status}",
            child.id()
        );
        assert_eq!(status.code(), Some(7));
        assert!(child.tree_absent().unwrap());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_unknown_or_foreign_group_never_becomes_owned_exit() {
        let current = unsafe { libc::getpgrp() };
        let members = darwin_group_members(current).unwrap();
        assert!(!members.is_empty());
        assert!(
            darwin_only_exited_original(current, current + 1, "uid=501 birth=known", true).is_err()
        );
        assert!(
            darwin_only_exited_original(current, current, "uid=501 birth=known", false).is_err()
        );
        assert!(darwin_only_exited_original(current, current, "", true).is_err());
    }
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

    #[test]
    fn repeated_stop_still_refuses_external_reap() {
        use std::process::Stdio;
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = spawn_guest_process(&mut command).unwrap();
        child.stop_tree().unwrap();
        // Exercise the real Child handle outside GuestChild's reaping custody.
        child.wait().unwrap();
        assert_eq!(
            child.stop_tree().unwrap_err().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn repeated_stop_closes_real_late_group_writer_before_original_reap() {
        use std::{
            io::Read,
            os::unix::process::CommandExt,
            process::Stdio,
            time::{Duration, Instant},
        };
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "exit 7"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut original = spawn_guest_process(&mut command).unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        while !original.observed_exit().unwrap() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(1));
        }
        original.stop_tree().unwrap();
        // Real OS member joining the still-custodied group AFTER successful
        // first stop. No replacement stop/read method or cached-success mock.
        let mut late = Command::new("/bin/sh")
            .args(["-c", "exec sleep 30"])
            .process_group(original.id() as i32)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut errors = late.stderr.take().unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        let outcome = loop {
            match late.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Err(error) => break Err(error.to_string()),
                _ if Instant::now() >= until => {
                    break Err("late writer survived repeated stop".into())
                }
                _ => {
                    if let Err(error) = original.stop_tree() {
                        break Err(error.to_string());
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        };
        // Cleanup only the exact direct test child on a failed assertion path.
        if outcome.is_err() {
            let _ = late.kill();
            let _ = late.wait();
        }
        assert!(!outcome.unwrap().success());
        let mut diagnostics = Vec::new();
        errors.read_to_end(&mut diagnostics).unwrap();
        assert!(diagnostics.is_empty()); // Real stderr EOF after writer reaping.
        assert!(original.descendants_absent().unwrap());
        assert_eq!(original.reap_owned().unwrap().unwrap().code(), Some(7));
        assert!(original.tree_absent().unwrap());
    }
}

// Native observation only: bounded, no I/O or shared event mutex on the timed
// path. Each OnceLock slot has exactly one producer. Original deadlines,
// assertions and process-control calls remain authoritative.
#[cfg(test)]
pub(crate) mod native_trace {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    };
    use std::time::Instant;

    const CAPACITY: usize = 2048;
    #[derive(Debug)]
    struct Event {
        ns: u64,
        phase: &'static str,
        stream: u8,
        value: i64,
    }
    #[derive(Debug)]
    struct Inner {
        root: u32,
        start: Instant,
        next: AtomicUsize,
        slots: Box<[OnceLock<Event>]>,
    }
    #[derive(Clone, Debug, Default)]
    pub(crate) struct NativeTrace(Option<Arc<Inner>>);
    impl NativeTrace {
        pub(crate) fn enabled(&self) -> bool {
            self.0.is_some()
        }
        pub(crate) fn new(root: u32) -> Self {
            if !cfg!(target_os = "macos")
                || std::env::var_os("OPEMOS_NATIVE_GUEST_TRACE").as_deref()
                    != Some(std::ffi::OsStr::new("1"))
            {
                return Self::default();
            }
            Self(Some(Arc::new(Inner {
                root,
                start: Instant::now(),
                next: AtomicUsize::new(0),
                slots: (0..CAPACITY).map(|_| OnceLock::new()).collect(),
            })))
        }
        pub(crate) fn record(&self, phase: &'static str, stream: u8, value: i64) {
            let Some(inner) = &self.0 else { return };
            let ns = inner.start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            let index = inner.next.fetch_add(1, Ordering::Relaxed);
            if let Some(slot) = inner.slots.get(index) {
                let _ = slot.set(Event {
                    ns,
                    phase,
                    stream,
                    value,
                });
            }
        }
        pub(crate) fn deadline(&self, phase: &'static str, deadline: Instant) {
            if let Some(inner) = &self.0 {
                self.record(
                    phase,
                    0,
                    deadline
                        .saturating_duration_since(inner.start)
                        .as_nanos()
                        .min(i64::MAX as u128) as i64,
                );
            }
        }
    }
    impl Drop for Inner {
        fn drop(&mut self) {
            // Last owner is dropped only after the existing actual joins and
            // caller result. No diagnostic formatting on the timed path.
            let events = self.slots.iter().filter_map(OnceLock::get).map(|e|
                serde_json::json!({"ns":e.ns,"phase":e.phase,"stream":e.stream,"value":e.value})
            ).collect::<Vec<_>>();
            let count = self.next.load(Ordering::Relaxed);
            eprintln!(
                "NATIVE_GUEST_TRACE {}",
                serde_json::json!({
                    "schema":1,"root":self.root,"capacity":CAPACITY,
                    "overflow":count.saturating_sub(CAPACITY),"events":events
                })
            );
        }
    }
}

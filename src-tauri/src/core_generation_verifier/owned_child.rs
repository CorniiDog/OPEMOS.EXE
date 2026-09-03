//! Test-only owned child lifecycle for a future detached-signature verifier.
//! This module owns process containment and bounded I/O only. Signature and
//! OpenPGP semantics remain in the parent verifier contract.

use super::*;
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd as _},
    os::unix::{
        fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        process::CommandExt as _,
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const PIPE_CHUNK_BYTES: usize = 16 * 1024;
const MAX_ARGUMENTS: usize = 16;
const MAX_ARGUMENT_BYTES: usize = 256;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
static SNAPSHOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
struct OwnedChildLimits {
    stdout_bytes: usize,
    stderr_bytes: usize,
    timeout: Duration,
    terminate_grace: Duration,
}

#[derive(Debug)]
struct OwnedChildOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    pid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnedChildError {
    MissingExecutable,
    UnsafeExecutable,
    SnapshotFailed,
    SpawnFailed,
    WaitFailed,
    Cancelled,
    TimedOut,
    StdoutExceeded,
    StderrExceeded,
    PipeReadFailed,
    CleanupFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnedChildFailure {
    primary: OwnedChildError,
    cleanup_failed: bool,
}

impl From<OwnedChildError> for OwnedChildFailure {
    fn from(primary: OwnedChildError) -> Self {
        Self {
            primary,
            cleanup_failed: false,
        }
    }
}

impl PartialEq<OwnedChildError> for OwnedChildFailure {
    fn eq(&self, other: &OwnedChildError) -> bool {
        self.primary == *other && !self.cleanup_failed
    }
}

impl OwnedChildError {
    fn code(self) -> &'static str {
        match self {
            Self::MissingExecutable => "verifier_executable_missing",
            Self::UnsafeExecutable => "verifier_executable_unsafe",
            Self::SnapshotFailed => "verifier_snapshot_failed",
            Self::SpawnFailed => "verifier_spawn_failed",
            Self::WaitFailed => "verifier_wait_failed",
            Self::Cancelled => "verifier_cancelled",
            Self::TimedOut => "verifier_timeout",
            Self::StdoutExceeded => "verifier_stdout_exceeded",
            Self::StderrExceeded => "verifier_stderr_exceeded",
            Self::PipeReadFailed => "verifier_pipe_read_failed",
            Self::CleanupFailed => "verifier_cleanup_failed",
        }
    }
}

struct ExecutableSnapshot {
    parent: File,
    parent_path: PathBuf,
    parent_identity: (u64, u64),
    root: File,
    root_path: PathBuf,
    root_name: CString,
    executable: File,
    executable_identity: (u64, u64),
    executable_size: u64,
    executable_sha256: String,
    cleaned: bool,
}

impl ExecutableSnapshot {
    fn create(
        source: &Path,
        expected_sha256: &str,
        scratch_parent: &Path,
    ) -> Result<Self, OwnedChildError> {
        if !source.is_absolute() || !scratch_parent.is_absolute() {
            return Err(OwnedChildError::UnsafeExecutable);
        }
        if expected_sha256.len() != 64
            || !expected_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(OwnedChildError::UnsafeExecutable);
        }
        let mut source_options = OpenOptions::new();
        source_options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        let mut source_file = match source_options.open(source) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(OwnedChildError::MissingExecutable)
            }
            Err(_) => return Err(OwnedChildError::UnsafeExecutable),
        };
        let source_before = source_file
            .metadata()
            .map_err(|_| OwnedChildError::UnsafeExecutable)?;
        if !source_before.is_file()
            || source_before.nlink() != 1
            || source_before.len() == 0
            || source_before.len() > MAX_EXECUTABLE_BYTES
            || source_before.uid() != unsafe { libc::geteuid() }
            || source_before.permissions().mode() & 0o022 != 0
            || source_before.permissions().mode() & 0o100 == 0
        {
            return Err(OwnedChildError::UnsafeExecutable);
        }
        let (parent, parent_identity, root, root_name) =
            create_private_snapshot_root(scratch_parent)?;
        let executable_name = c"verifier-child";
        let result = (|| {
            let descriptor = unsafe {
                libc::openat(
                    root.as_raw_fd(),
                    executable_name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o500,
                )
            };
            if descriptor < 0 {
                return Err(OwnedChildError::SnapshotFailed);
            }
            let mut destination = unsafe { File::from_raw_fd(descriptor) };
            let mut digest = Sha256::new();
            let mut copied = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = source_file
                    .read(&mut buffer)
                    .map_err(|_| OwnedChildError::SnapshotFailed)?;
                if count == 0 {
                    break;
                }
                copied = copied
                    .checked_add(count as u64)
                    .ok_or(OwnedChildError::SnapshotFailed)?;
                if copied > source_before.len() || copied > MAX_EXECUTABLE_BYTES {
                    return Err(OwnedChildError::SnapshotFailed);
                }
                destination
                    .write_all(&buffer[..count])
                    .map_err(|_| OwnedChildError::SnapshotFailed)?;
                digest.update(&buffer[..count]);
            }
            destination
                .sync_all()
                .map_err(|_| OwnedChildError::SnapshotFailed)?;
            let source_after = source_file
                .metadata()
                .map_err(|_| OwnedChildError::SnapshotFailed)?;
            let destination_metadata = destination
                .metadata()
                .map_err(|_| OwnedChildError::SnapshotFailed)?;
            if copied != source_before.len()
                || source_before.dev() != source_after.dev()
                || source_before.ino() != source_after.ino()
                || source_before.len() != source_after.len()
                || source_before.mtime() != source_after.mtime()
                || source_before.mtime_nsec() != source_after.mtime_nsec()
                || source_before.ctime() != source_after.ctime()
                || source_before.ctime_nsec() != source_after.ctime_nsec()
                || !destination_metadata.is_file()
                || destination_metadata.nlink() != 1
                || destination_metadata.len() != copied
                || destination_metadata.permissions().mode() & 0o7777 != 0o500
            {
                return Err(OwnedChildError::SnapshotFailed);
            }
            // Finalize the digest so the copy loop cannot be optimized into a
            // size-only copy. Exact source/destination equality is then checked
            // by independently hashing the private snapshot below.
            let source_hash = format!("{:x}", digest.finalize());
            if source_hash != expected_sha256
                || hash_open_file(&mut destination, copied)? != source_hash
            {
                return Err(OwnedChildError::SnapshotFailed);
            }
            root.sync_all()
                .map_err(|_| OwnedChildError::SnapshotFailed)?;
            let identity = (destination_metadata.dev(), destination_metadata.ino());
            require_snapshot_entry(&root, executable_name, identity)?;
            let executable_descriptor = unsafe {
                libc::openat(
                    root.as_raw_fd(),
                    executable_name.as_ptr(),
                    // This exact descriptor is the exec path. It must survive
                    // posix_spawn long enough for `/dev/fd/N` to resolve; all
                    // unrelated descriptors retain O_CLOEXEC.
                    libc::O_RDONLY | libc::O_NOFOLLOW,
                )
            };
            if executable_descriptor < 0 {
                return Err(OwnedChildError::SnapshotFailed);
            }
            let executable = unsafe { File::from_raw_fd(executable_descriptor) };
            #[cfg(not(target_os = "linux"))]
            if unsafe { libc::fcntl(executable.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(OwnedChildError::SnapshotFailed);
            }
            let executable_metadata = executable
                .metadata()
                .map_err(|_| OwnedChildError::SnapshotFailed)?;
            if executable_metadata.dev() != identity.0 || executable_metadata.ino() != identity.1 {
                return Err(OwnedChildError::SnapshotFailed);
            }
            drop(destination);
            Ok((executable, identity))
        })();
        let (executable, executable_identity) = match result {
            Ok(value) => value,
            Err(error) => {
                let _ = cleanup_snapshot_root(
                    &parent,
                    scratch_parent,
                    parent_identity,
                    &root,
                    &root_name,
                    None,
                );
                return Err(error);
            }
        };
        Ok(Self {
            parent,
            parent_path: scratch_parent.to_owned(),
            parent_identity,
            root,
            root_path: scratch_parent.join(
                root_name
                    .to_str()
                    .map_err(|_| OwnedChildError::SnapshotFailed)?,
            ),
            executable,
            root_name,
            executable_identity,
            executable_size: source_before.len(),
            executable_sha256: expected_sha256.to_owned(),
            cleaned: false,
        })
    }

    fn executable_path(&self) -> String {
        #[cfg(target_os = "linux")]
        {
            return format!("/proc/self/fd/{}", self.executable.as_raw_fd());
        }
        #[cfg(not(target_os = "linux"))]
        {
            // macOS does not permit executing /dev/fd. This cfg(test)-only
            // lifecycle adapter therefore uses its private snapshot pathname
            // and binds it immediately before and after spawn. Production
            // reachability requires a reviewed platform helper/signature path.
            self.root_path
                .join("verifier-child")
                .to_string_lossy()
                .into_owned()
        }
    }

    fn require_bound(&self) -> Result<(), OwnedChildError> {
        require_parent_entry(&self.parent_path, &self.parent, self.parent_identity)?;
        require_root_entry(&self.parent, &self.root_name, &self.root)?;
        require_snapshot_entry(&self.root, c"verifier-child", self.executable_identity)?;
        let mut executable = self
            .executable
            .try_clone()
            .map_err(|_| OwnedChildError::SnapshotFailed)?;
        let metadata = executable
            .metadata()
            .map_err(|_| OwnedChildError::SnapshotFailed)?;
        if metadata.dev() != self.executable_identity.0
            || metadata.ino() != self.executable_identity.1
            || metadata.len() != self.executable_size
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o7777 != 0o500
            || hash_open_file(&mut executable, self.executable_size)? != self.executable_sha256
        {
            return Err(OwnedChildError::SnapshotFailed);
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), OwnedChildError> {
        cleanup_snapshot_root(
            &self.parent,
            &self.parent_path,
            self.parent_identity,
            &self.root,
            &self.root_name,
            Some(self.executable_identity),
        )?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for ExecutableSnapshot {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = cleanup_snapshot_root(
                &self.parent,
                &self.parent_path,
                self.parent_identity,
                &self.root,
                &self.root_name,
                Some(self.executable_identity),
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnedChildHookPoint {
    BeforeLaunchValidation,
    AfterSpawn,
    BeforeCleanup,
}

fn run_owned_verifier_child<C>(
    executable: &Path,
    expected_executable_sha256: &str,
    arguments: &[&str],
    scratch_parent: &Path,
    limits: OwnedChildLimits,
    cancelled: C,
) -> Result<OwnedChildOutput, OwnedChildFailure>
where
    C: Fn() -> bool,
{
    run_owned_verifier_child_with_hook(
        executable,
        expected_executable_sha256,
        arguments,
        scratch_parent,
        limits,
        cancelled,
        |_point, _snapshot| {},
    )
}

#[allow(clippy::too_many_arguments)]
fn run_owned_verifier_child_with_hook<C, H>(
    executable: &Path,
    expected_executable_sha256: &str,
    arguments: &[&str],
    scratch_parent: &Path,
    limits: OwnedChildLimits,
    cancelled: C,
    mut hook: H,
) -> Result<OwnedChildOutput, OwnedChildFailure>
where
    C: Fn() -> bool,
    H: FnMut(OwnedChildHookPoint, &ExecutableSnapshot),
{
    validate_limits(limits)?;
    validate_arguments(arguments)?;
    if cancelled() {
        return Err(OwnedChildError::Cancelled.into());
    }
    let mut snapshot =
        ExecutableSnapshot::create(executable, expected_executable_sha256, scratch_parent)?;
    let outcome = run_snapshot_child(&snapshot, arguments, limits, &cancelled, &mut hook);
    hook(OwnedChildHookPoint::BeforeCleanup, &snapshot);
    match (outcome, snapshot.cleanup()) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(primary), Ok(())) => Err(primary.into()),
        (Ok(_), Err(cleanup)) => Err(cleanup.into()),
        (Err(primary), Err(_cleanup)) => Err(OwnedChildFailure {
            primary,
            cleanup_failed: true,
        }),
    }
}

fn run_snapshot_child<C, H>(
    snapshot: &ExecutableSnapshot,
    arguments: &[&str],
    limits: OwnedChildLimits,
    cancelled: &C,
    hook: &mut H,
) -> Result<OwnedChildOutput, OwnedChildError>
where
    C: Fn() -> bool,
    H: FnMut(OwnedChildHookPoint, &ExecutableSnapshot),
{
    if cancelled() {
        return Err(OwnedChildError::Cancelled);
    }
    hook(OwnedChildHookPoint::BeforeLaunchValidation, snapshot);
    snapshot.require_bound()?;
    let mut command = Command::new(snapshot.executable_path());
    command
        .args(arguments)
        .current_dir("/")
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.process_group(0);
    let mut child = command.spawn().map_err(|_| OwnedChildError::SpawnFailed)?;
    hook(OwnedChildHookPoint::AfterSpawn, snapshot);
    if snapshot.require_bound().is_err() {
        terminate_group_and_reap(&mut child, limits.terminate_grace);
        return Err(OwnedChildError::SnapshotFailed);
    }
    let pid = child.id();
    let stdout = child.stdout.take().ok_or_else(|| {
        terminate_group_and_reap(&mut child, limits.terminate_grace);
        OwnedChildError::SpawnFailed
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        terminate_group_and_reap(&mut child, limits.terminate_grace);
        OwnedChildError::SpawnFailed
    })?;
    let stop_readers = Arc::new(AtomicBool::new(false));
    let (pipe_sender, pipe_receiver) = mpsc::channel();
    let stdout_reader = match spawn_bounded_drain(
        stdout,
        limits.stdout_bytes,
        PipeKind::Stdout,
        Arc::clone(&stop_readers),
        pipe_sender.clone(),
    ) {
        Ok(reader) => reader,
        Err(error) => {
            terminate_group_and_reap(&mut child, limits.terminate_grace);
            return Err(error);
        }
    };
    let stderr_reader = match spawn_bounded_drain(
        stderr,
        limits.stderr_bytes,
        PipeKind::Stderr,
        Arc::clone(&stop_readers),
        pipe_sender,
    ) {
        Ok(reader) => reader,
        Err(error) => {
            stop_readers.store(true, Ordering::SeqCst);
            terminate_group_and_reap(&mut child, limits.terminate_grace);
            let _ = stdout_reader.join();
            return Err(error);
        }
    };
    let deadline = Instant::now() + limits.timeout;
    let mut stdout_result = None;
    let mut stderr_result = None;
    let mut outcome = loop {
        // Cancellation is the first terminal condition sampled in every
        // supervisor turn. It therefore wins over a simultaneously observed
        // pipe bound/read failure, child exit, or timeout.
        if cancelled() {
            terminate_group_and_reap(&mut child, limits.terminate_grace);
            break Err(OwnedChildError::Cancelled);
        }
        while let Ok(event) = pipe_receiver.try_recv() {
            let failed = event.output.exceeded || event.output.read_failed;
            store_pipe_event(event, &mut stdout_result, &mut stderr_result);
            if failed {
                terminate_group_and_reap(&mut child, limits.terminate_grace);
                break;
            }
        }
        if cancelled() {
            terminate_group_and_reap(&mut child, limits.terminate_grace);
            break Err(OwnedChildError::Cancelled);
        }
        if stdout_result
            .as_ref()
            .is_some_and(|result| result.exceeded || result.read_failed)
            || stderr_result
                .as_ref()
                .is_some_and(|result| result.exceeded || result.read_failed)
        {
            let error = if stdout_result
                .as_ref()
                .is_some_and(|result| result.read_failed)
                || stderr_result
                    .as_ref()
                    .is_some_and(|result| result.read_failed)
            {
                OwnedChildError::PipeReadFailed
            } else if stdout_result.as_ref().is_some_and(|result| result.exceeded) {
                OwnedChildError::StdoutExceeded
            } else {
                OwnedChildError::StderrExceeded
            };
            break Err(error);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if cancelled() {
                    terminate_group_and_reap(&mut child, limits.terminate_grace);
                    break Err(OwnedChildError::Cancelled);
                }
                terminate_group_and_reap(&mut child, limits.terminate_grace);
                break Ok(status);
            }
            Ok(None) => {}
            Err(_) => {
                terminate_group_and_reap(&mut child, limits.terminate_grace);
                break Err(OwnedChildError::WaitFailed);
            }
        }
        if Instant::now() >= deadline {
            if cancelled() {
                terminate_group_and_reap(&mut child, limits.terminate_grace);
                break Err(OwnedChildError::Cancelled);
            }
            terminate_group_and_reap(&mut child, limits.terminate_grace);
            break Err(OwnedChildError::TimedOut);
        }
        thread::sleep(POLL_INTERVAL);
    };
    let pipe_deadline = Instant::now() + limits.terminate_grace;
    while (stdout_result.is_none() || stderr_result.is_none()) && Instant::now() < pipe_deadline {
        match pipe_receiver.recv_timeout(POLL_INTERVAL) {
            Ok(event) => store_pipe_event(event, &mut stdout_result, &mut stderr_result),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    stop_readers.store(true, Ordering::SeqCst);
    stdout_reader
        .join()
        .map_err(|_| OwnedChildError::PipeReadFailed)?;
    stderr_reader
        .join()
        .map_err(|_| OwnedChildError::PipeReadFailed)?;
    while let Ok(event) = pipe_receiver.try_recv() {
        store_pipe_event(event, &mut stdout_result, &mut stderr_result);
    }
    let stdout = stdout_result.ok_or(OwnedChildError::PipeReadFailed)?;
    let stderr = stderr_result.ok_or(OwnedChildError::PipeReadFailed)?;
    if outcome.is_ok() {
        if stdout.read_failed || stderr.read_failed {
            outcome = Err(OwnedChildError::PipeReadFailed);
        } else if stdout.exceeded {
            outcome = Err(OwnedChildError::StdoutExceeded);
        } else if stderr.exceeded {
            outcome = Err(OwnedChildError::StderrExceeded);
        }
    }
    outcome.map(|status| OwnedChildOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        pid,
    })
}

struct BoundedPipe {
    bytes: Vec<u8>,
    exceeded: bool,
    read_failed: bool,
}

#[derive(Clone, Copy)]
enum PipeKind {
    Stdout,
    Stderr,
}

struct PipeEvent {
    kind: PipeKind,
    output: BoundedPipe,
}

fn store_pipe_event(
    event: PipeEvent,
    stdout: &mut Option<BoundedPipe>,
    stderr: &mut Option<BoundedPipe>,
) {
    let target = match event.kind {
        PipeKind::Stdout => stdout,
        PipeKind::Stderr => stderr,
    };
    if target.is_none() {
        *target = Some(event.output);
    }
}

fn spawn_bounded_drain<R>(
    pipe: R,
    limit: usize,
    kind: PipeKind,
    stop: Arc<AtomicBool>,
    sender: mpsc::Sender<PipeEvent>,
) -> Result<thread::JoinHandle<()>, OwnedChildError>
where
    R: Read + AsRawFd + Send + 'static,
{
    let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(OwnedChildError::PipeReadFailed);
    }
    Ok(thread::spawn(move || {
        let output = drain_bounded(pipe, limit, &stop);
        let _ = sender.send(PipeEvent { kind, output });
    }))
}

fn drain_bounded(mut pipe: impl Read, limit: usize, stop: &AtomicBool) -> BoundedPipe {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0_u8; PIPE_CHUNK_BYTES];
    loop {
        if stop.load(Ordering::SeqCst) {
            return BoundedPipe {
                bytes,
                exceeded: false,
                read_failed: false,
            };
        }
        let count = match pipe.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
                continue;
            }
            Err(_) => {
                return BoundedPipe {
                    bytes,
                    exceeded: false,
                    read_failed: true,
                }
            }
        };
        if count == 0 {
            return BoundedPipe {
                bytes,
                exceeded: false,
                read_failed: false,
            };
        }
        let remaining = limit.saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining {
            return BoundedPipe {
                bytes,
                exceeded: true,
                read_failed: false,
            };
        }
    }
}

fn terminate_group_and_reap(child: &mut Child, grace: Duration) {
    let Ok(group) = i32::try_from(child.id()) else {
        let _ = child.kill();
        let _ = child.wait();
        return;
    };
    unsafe {
        libc::kill(-group, libc::SIGTERM);
    }
    let deadline = Instant::now() + grace;
    while process_group_exists(group) && Instant::now() < deadline {
        thread::sleep(POLL_INTERVAL);
    }
    if process_group_exists(group) {
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
    }
    let _ = child.wait();
}

fn process_group_exists(group: i32) -> bool {
    let result = unsafe { libc::kill(-group, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn validate_limits(limits: OwnedChildLimits) -> Result<(), OwnedChildError> {
    if limits.stdout_bytes == 0
        || limits.stderr_bytes == 0
        || limits.stdout_bytes > MAX_OPENPGP_STATUS_BYTES
        || limits.stderr_bytes > MAX_OPENPGP_STATUS_BYTES
        || limits.timeout.is_zero()
        || limits.timeout > Duration::from_secs(300)
        || limits.terminate_grace.is_zero()
        || limits.terminate_grace > Duration::from_secs(5)
    {
        return Err(OwnedChildError::SnapshotFailed);
    }
    Ok(())
}

fn validate_arguments(arguments: &[&str]) -> Result<(), OwnedChildError> {
    if arguments.len() > MAX_ARGUMENTS
        || arguments.iter().any(|argument| {
            argument.is_empty()
                || argument.len() > MAX_ARGUMENT_BYTES
                || argument.as_bytes().contains(&0)
        })
    {
        return Err(OwnedChildError::SpawnFailed);
    }
    Ok(())
}

fn create_private_snapshot_root(
    parent_path: &Path,
) -> Result<(File, (u64, u64), File, CString), OwnedChildError> {
    let metadata =
        fs::symlink_metadata(parent_path).map_err(|_| OwnedChildError::SnapshotFailed)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(OwnedChildError::SnapshotFailed);
    }
    let mut parent_options = OpenOptions::new();
    parent_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let parent = parent_options
        .open(parent_path)
        .map_err(|_| OwnedChildError::SnapshotFailed)?;
    let opened_parent = parent
        .metadata()
        .map_err(|_| OwnedChildError::SnapshotFailed)?;
    if opened_parent.dev() != metadata.dev()
        || opened_parent.ino() != metadata.ino()
        || !opened_parent.is_dir()
        || opened_parent.uid() != unsafe { libc::geteuid() }
        || opened_parent.permissions().mode() & 0o077 != 0
    {
        return Err(OwnedChildError::SnapshotFailed);
    }
    let parent_identity = (opened_parent.dev(), opened_parent.ino());
    for _ in 0..8 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OwnedChildError::SnapshotFailed)?
            .as_nanos();
        let basename = format!(
            ".verifier-{}-{nonce}-{}",
            std::process::id(),
            SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let name = CString::new(basename).map_err(|_| OwnedChildError::SnapshotFailed)?;
        let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if created != 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(OwnedChildError::SnapshotFailed);
        }
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            unsafe {
                libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
            }
            return Err(OwnedChildError::SnapshotFailed);
        }
        let root = unsafe { File::from_raw_fd(descriptor) };
        require_root_entry(&parent, &name, &root)?;
        return Ok((parent, parent_identity, root, name));
    }
    Err(OwnedChildError::SnapshotFailed)
}

fn require_parent_entry(
    parent_path: &Path,
    parent: &File,
    identity: (u64, u64),
) -> Result<(), OwnedChildError> {
    let path_metadata =
        fs::symlink_metadata(parent_path).map_err(|_| OwnedChildError::SnapshotFailed)?;
    let opened = parent
        .metadata()
        .map_err(|_| OwnedChildError::SnapshotFailed)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || path_metadata.dev() != identity.0
        || path_metadata.ino() != identity.1
        || opened.dev() != identity.0
        || opened.ino() != identity.1
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.permissions().mode() & 0o077 != 0
    {
        return Err(OwnedChildError::SnapshotFailed);
    }
    Ok(())
}

fn hash_open_file(file: &mut File, expected_size: u64) -> Result<String, OwnedChildError> {
    use std::io::{Seek as _, SeekFrom};
    file.seek(SeekFrom::Start(0))
        .map_err(|_| OwnedChildError::SnapshotFailed)?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| OwnedChildError::SnapshotFailed)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(OwnedChildError::SnapshotFailed)?;
        if total > expected_size {
            return Err(OwnedChildError::SnapshotFailed);
        }
        digest.update(&buffer[..count]);
    }
    if total != expected_size {
        return Err(OwnedChildError::SnapshotFailed);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn statat(parent: &File, name: &CString) -> Result<libc::stat, OwnedChildError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(OwnedChildError::SnapshotFailed);
    }
    Ok(unsafe { stat.assume_init() })
}

fn statat_optional(parent: &File, name: &CString) -> Result<Option<libc::stat>, OwnedChildError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(Some(unsafe { stat.assume_init() }));
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(OwnedChildError::SnapshotFailed)
    }
}

fn require_root_entry(parent: &File, name: &CString, root: &File) -> Result<(), OwnedChildError> {
    let stat = statat(parent, name)?;
    let opened = root
        .metadata()
        .map_err(|_| OwnedChildError::SnapshotFailed)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_dev as u64 != opened.dev()
        || stat.st_ino != opened.ino()
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.permissions().mode() & 0o7777 != 0o700
    {
        return Err(OwnedChildError::SnapshotFailed);
    }
    Ok(())
}

fn require_snapshot_entry(
    root: &File,
    name: &std::ffi::CStr,
    identity: (u64, u64),
) -> Result<(), OwnedChildError> {
    let name = CString::new(name.to_bytes()).map_err(|_| OwnedChildError::SnapshotFailed)?;
    let stat = statat(root, &name)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_dev as u64 != identity.0
        || stat.st_ino != identity.1
        || stat.st_nlink != 1
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o7777 != 0o500
    {
        return Err(OwnedChildError::SnapshotFailed);
    }
    Ok(())
}

fn cleanup_snapshot_root(
    parent: &File,
    parent_path: &Path,
    parent_identity: (u64, u64),
    root: &File,
    root_name: &CString,
    executable_identity: Option<(u64, u64)>,
) -> Result<(), OwnedChildError> {
    require_parent_entry(parent_path, parent, parent_identity)
        .map_err(|_| OwnedChildError::CleanupFailed)?;
    require_root_entry(parent, root_name, root).map_err(|_| OwnedChildError::CleanupFailed)?;
    let executable_name =
        CString::new(c"verifier-child".to_bytes()).map_err(|_| OwnedChildError::CleanupFailed)?;
    if let Some(identity) = executable_identity {
        require_snapshot_entry(root, c"verifier-child", identity)
            .map_err(|_| OwnedChildError::CleanupFailed)?;
        if unsafe { libc::unlinkat(root.as_raw_fd(), c"verifier-child".as_ptr(), 0) } != 0 {
            return Err(OwnedChildError::CleanupFailed);
        }
        root.sync_all()
            .map_err(|_| OwnedChildError::CleanupFailed)?;
    } else if let Some(stat) =
        statat_optional(root, &executable_name).map_err(|_| OwnedChildError::CleanupFailed)?
    {
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_nlink != 1
            || stat.st_uid != unsafe { libc::geteuid() }
            || stat.st_mode & 0o7777 != 0o500
        {
            return Err(OwnedChildError::CleanupFailed);
        }
        if unsafe { libc::unlinkat(root.as_raw_fd(), executable_name.as_ptr(), 0) } != 0 {
            return Err(OwnedChildError::CleanupFailed);
        }
        root.sync_all()
            .map_err(|_| OwnedChildError::CleanupFailed)?;
    }
    require_root_entry(parent, root_name, root).map_err(|_| OwnedChildError::CleanupFailed)?;
    require_parent_entry(parent_path, parent, parent_identity)
        .map_err(|_| OwnedChildError::CleanupFailed)?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), root_name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(OwnedChildError::CleanupFailed);
    }
    parent
        .sync_all()
        .map_err(|_| OwnedChildError::CleanupFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    const PRIMARY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    struct HelperFixture {
        root: PathBuf,
        executable: PathBuf,
        executable_sha256: String,
    }

    impl HelperFixture {
        fn new(name: &str) -> Self {
            let root = private_test_root(name);
            let source = root.join("helper.rs");
            let executable = root.join("helper");
            fs::write(&source, HELPER_SOURCE).unwrap();
            let output = Command::new("rustc")
                .args(["--edition", "2021"])
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .output()
                .expect("compile owned-child fixture");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let executable_sha256 = format!("{:x}", Sha256::digest(fs::read(&executable).unwrap()));
            Self {
                root,
                executable,
                executable_sha256,
            }
        }

        fn run<C: Fn() -> bool>(
            &self,
            scenario: &str,
            limits: OwnedChildLimits,
            cancelled: C,
        ) -> Result<OwnedChildOutput, OwnedChildFailure> {
            let before = snapshot_residue(&self.root);
            let result = run_owned_verifier_child(
                &self.executable,
                &self.executable_sha256,
                &[scenario],
                &self.root,
                limits,
                cancelled,
            );
            assert_eq!(snapshot_residue(&self.root), before);
            result
        }
    }

    impl Drop for HelperFixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.executable);
            let _ = fs::remove_file(self.root.join("helper.rs"));
            let _ = fs::remove_dir(&self.root);
        }
    }

    fn limits() -> OwnedChildLimits {
        OwnedChildLimits {
            stdout_bytes: 64 * 1024,
            stderr_bytes: 64 * 1024,
            timeout: Duration::from_secs(2),
            terminate_grace: Duration::from_millis(100),
        }
    }

    fn private_test_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "opemos-owned-verifier-{name}-{}-{nonce}",
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&root).unwrap();
        root
    }

    fn snapshot_residue(root: &Path) -> Vec<String> {
        let mut names = fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".verifier-"))
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn process_absent(pid: u32) -> bool {
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
        let result = unsafe { libc::kill(pid, 0) };
        result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    #[test]
    fn valid_status_is_bounded_and_parsed_by_existing_contract() {
        let fixture = HelperFixture::new("valid");
        let output = fixture.run("valid", limits(), || false).unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(process_absent(output.pid));
        let parsed = validate_openpgp_status(&output.stdout, PRIMARY).unwrap();
        assert_eq!(parsed.primary_fingerprint, PRIMARY);
        assert_eq!(parsed.hash_algorithm_id, 8);
    }

    #[test]
    fn nonzero_and_malformed_results_remain_signature_contract_failures() {
        let fixture = HelperFixture::new("delegation");
        let nonzero = fixture.run("nonzero", limits(), || false).unwrap();
        assert_eq!(nonzero.status.code(), Some(7));
        assert!(!nonzero.stderr.is_empty());
        let mut delegated = |_payload: &[u8],
                             _signature: &[u8],
                             _keyring: &[u8],
                             _role: &str,
                             _cancelled: &dyn Fn() -> bool| {
            Ok(DetachedVerifierOutput {
                exit_status: nonzero.status.code().unwrap(),
                status: nonzero.stdout.clone(),
            })
        };
        assert!(verifier_result(
            &mut delegated,
            b"payload",
            b"signature",
            b"keyring",
            PRIMARY,
            "fixture",
            &|| false,
        )
        .is_err());

        let malformed = fixture.run("malformed", limits(), || false).unwrap();
        assert!(malformed.status.success());
        assert!(validate_openpgp_status(&malformed.stdout, PRIMARY).is_err());
    }

    fn exercise_timeout_and_cancellation() {
        let fixture = HelperFixture::new("stop");
        let mut timeout_limits = limits();
        timeout_limits.timeout = Duration::from_millis(80);
        assert_eq!(
            fixture.run("hang", timeout_limits, || false).unwrap_err(),
            OwnedChildError::TimedOut
        );

        let cancelled = Arc::new(AtomicBool::new(false));
        let trigger = Arc::clone(&cancelled);
        let setter = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            trigger.store(true, Ordering::SeqCst);
        });
        assert_eq!(
            fixture
                .run("hang", limits(), || cancelled.load(Ordering::SeqCst))
                .unwrap_err(),
            OwnedChildError::Cancelled
        );
        setter.join().unwrap();
    }

    fn exercise_output_floods() {
        let fixture = HelperFixture::new("flood");
        let mut small = limits();
        small.stdout_bytes = 4096;
        small.stderr_bytes = 4096;
        assert_eq!(
            fixture.run("flood-stdout", small, || false).unwrap_err(),
            OwnedChildError::StdoutExceeded
        );
        assert_eq!(
            fixture.run("flood-stderr", small, || false).unwrap_err(),
            OwnedChildError::StderrExceeded
        );
        assert!(matches!(
            fixture
                .run("flood-both", small, || false)
                .unwrap_err()
                .primary,
            OwnedChildError::StdoutExceeded | OwnedChildError::StderrExceeded
        ));

        let polls = AtomicUsize::new(0);
        assert_eq!(
            fixture
                .run("flood-both", small, || {
                    // Allow snapshot + pre-spawn polling, then make
                    // cancellation simultaneously eligible with pipe bounds.
                    polls.fetch_add(1, Ordering::SeqCst) >= 2
                })
                .unwrap_err(),
            OwnedChildError::Cancelled
        );
    }

    fn exercise_descendant_pipe_holder() {
        let fixture = HelperFixture::new("descendant");
        let started = Instant::now();
        let output = fixture.run("descendant", limits(), || false).unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        let descendant = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        for _ in 0..40 {
            if process_absent(descendant) {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("owned verifier descendant survived process-group cleanup");
    }

    #[test]
    fn dangerous_process_cases_complete_under_outer_watchdog() {
        for worker in [
            "owned_child_timeout_and_cancellation_worker",
            "owned_child_output_flood_worker",
            "owned_child_descendant_pipe_worker",
        ] {
            run_worker_with_watchdog(worker);
        }
    }

    #[test]
    #[ignore = "invoked under dangerous_process_cases_complete_under_outer_watchdog"]
    fn owned_child_timeout_and_cancellation_worker() {
        exercise_timeout_and_cancellation();
    }

    #[test]
    #[ignore = "invoked under dangerous_process_cases_complete_under_outer_watchdog"]
    fn owned_child_output_flood_worker() {
        exercise_output_floods();
    }

    #[test]
    #[ignore = "invoked under dangerous_process_cases_complete_under_outer_watchdog"]
    fn owned_child_descendant_pipe_worker() {
        exercise_descendant_pipe_holder();
    }

    fn run_worker_with_watchdog(worker: &str) {
        let test_name = format!("core_generation_verifier::owned_child::tests::{worker}");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg(&test_name)
            .arg("--ignored")
            .arg("--nocapture")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = command.spawn().expect("spawn bounded test worker");
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            match child.try_wait().expect("poll bounded test worker") {
                Some(status) => {
                    assert!(status.success(), "test worker {test_name} failed: {status}");
                    break;
                }
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                None => {
                    terminate_group_and_reap(&mut child, Duration::from_millis(100));
                    panic!("test worker {test_name} exceeded its outer watchdog");
                }
            }
        }
    }

    #[test]
    fn fast_exit_signal_races_are_stable_and_leave_no_residue() {
        let fixture = HelperFixture::new("race");
        for _ in 0..24 {
            let output = fixture.run("exit-fast", limits(), || false).unwrap();
            assert!(output.status.success());
            assert!(process_absent(output.pid));
        }
    }

    #[test]
    fn missing_and_unsafe_executables_have_stable_bounded_errors() {
        let root = private_test_root("missing");
        let missing = root.join("missing");
        assert_eq!(
            run_owned_verifier_child(&missing, &"0".repeat(64), &[], &root, limits(), || false)
                .unwrap_err(),
            OwnedChildError::MissingExecutable
        );
        let unsafe_file = root.join("unsafe");
        fs::write(&unsafe_file, b"not executable").unwrap();
        fs::set_permissions(&unsafe_file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            run_owned_verifier_child(
                &unsafe_file,
                &format!("{:x}", Sha256::digest(b"not executable")),
                &[],
                &root,
                limits(),
                || false,
            )
            .unwrap_err(),
            OwnedChildError::UnsafeExecutable
        );
        assert_eq!(
            run_owned_verifier_child(&unsafe_file, &"0".repeat(64), &[], &root, limits(), || {
                false
            },)
            .unwrap_err(),
            OwnedChildError::UnsafeExecutable
        );
        for error in [
            OwnedChildError::MissingExecutable,
            OwnedChildError::UnsafeExecutable,
            OwnedChildError::SnapshotFailed,
            OwnedChildError::SpawnFailed,
            OwnedChildError::WaitFailed,
            OwnedChildError::Cancelled,
            OwnedChildError::TimedOut,
            OwnedChildError::StdoutExceeded,
            OwnedChildError::StderrExceeded,
            OwnedChildError::PipeReadFailed,
            OwnedChildError::CleanupFailed,
        ] {
            assert!(error.code().len() <= 32);
            assert!(error
                .code()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        }
        fs::remove_file(unsafe_file).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn cancellation_before_snapshot_creates_no_residue() {
        let fixture = HelperFixture::new("early-cancel");
        assert_eq!(
            fixture.run("valid", limits(), || true).unwrap_err(),
            OwnedChildError::Cancelled
        );
        let before = snapshot_residue(&fixture.root);
        assert_eq!(
            run_owned_verifier_child(
                &fixture.executable,
                &"0".repeat(64),
                &["valid"],
                &fixture.root,
                limits(),
                || false,
            )
            .unwrap_err(),
            OwnedChildError::SnapshotFailed
        );
        assert_eq!(snapshot_residue(&fixture.root), before);
    }

    #[test]
    fn parent_root_and_executable_replacement_fail_before_launch() {
        for target in ["parent", "root", "executable", "executable-after-spawn"] {
            let fixture = HelperFixture::new(target);
            let before = snapshot_residue(&fixture.root);
            let mut saved = None;
            let result = run_owned_verifier_child_with_hook(
                &fixture.executable,
                &fixture.executable_sha256,
                &["exit-fast"],
                &fixture.root,
                limits(),
                || false,
                |point, snapshot| match point {
                    OwnedChildHookPoint::BeforeLaunchValidation
                        if target != "executable-after-spawn" =>
                    {
                        if target == "parent" {
                            let moved = snapshot.parent_path.with_extension("owned-saved");
                            fs::rename(&snapshot.parent_path, &moved).unwrap();
                            let mut builder = fs::DirBuilder::new();
                            builder.mode(0o700).create(&snapshot.parent_path).unwrap();
                            saved = Some(moved);
                        } else if target == "root" {
                            let moved = snapshot.root_path.with_extension("owned-saved");
                            fs::rename(&snapshot.root_path, &moved).unwrap();
                            let mut builder = fs::DirBuilder::new();
                            builder.mode(0o700).create(&snapshot.root_path).unwrap();
                            saved = Some(moved);
                        } else {
                            let live = snapshot.root_path.join("verifier-child");
                            let moved = snapshot.root_path.join("verifier-child.saved");
                            fs::rename(&live, &moved).unwrap();
                            fs::copy(&fixture.executable, &live).unwrap();
                            fs::set_permissions(&live, fs::Permissions::from_mode(0o500)).unwrap();
                            saved = Some(moved);
                        }
                    }
                    OwnedChildHookPoint::AfterSpawn if target == "executable-after-spawn" => {
                        let live = snapshot.root_path.join("verifier-child");
                        let moved = snapshot.root_path.join("verifier-child.saved");
                        fs::rename(&live, &moved).unwrap();
                        fs::copy(&fixture.executable, &live).unwrap();
                        fs::set_permissions(&live, fs::Permissions::from_mode(0o500)).unwrap();
                        saved = Some(moved);
                    }
                    OwnedChildHookPoint::BeforeCleanup => {
                        let moved = saved.take().unwrap();
                        if target == "parent" {
                            fs::remove_dir(&snapshot.parent_path).unwrap();
                            fs::rename(moved, &snapshot.parent_path).unwrap();
                        } else if target == "root" {
                            fs::remove_dir(&snapshot.root_path).unwrap();
                            fs::rename(moved, &snapshot.root_path).unwrap();
                        } else {
                            let live = snapshot.root_path.join("verifier-child");
                            fs::remove_file(live).unwrap();
                            fs::rename(moved, snapshot.root_path.join("verifier-child")).unwrap();
                        }
                    }
                    _ => {}
                },
            );
            assert_eq!(result.unwrap_err(), OwnedChildError::SnapshotFailed);
            assert_eq!(snapshot_residue(&fixture.root), before);
        }
    }

    #[test]
    fn primary_failure_is_preserved_when_cleanup_also_fails() {
        let fixture = HelperFixture::new("primary-cleanup");
        let mut snapshot_root = None;
        let mut saved_executable = None;
        let failure = run_owned_verifier_child_with_hook(
            &fixture.executable,
            &fixture.executable_sha256,
            &["exit-fast"],
            &fixture.root,
            limits(),
            || false,
            |point, snapshot| match point {
                OwnedChildHookPoint::AfterSpawn => {
                    let live = snapshot.root_path.join("verifier-child");
                    let saved = snapshot.root_path.join("verifier-child.saved");
                    fs::rename(&live, &saved).unwrap();
                    fs::copy(&fixture.executable, &live).unwrap();
                    fs::set_permissions(&live, fs::Permissions::from_mode(0o500)).unwrap();
                    snapshot_root = Some(snapshot.root_path.clone());
                    saved_executable = Some(saved);
                }
                OwnedChildHookPoint::BeforeCleanup => {
                    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o777)).unwrap();
                }
                _ => {}
            },
        )
        .unwrap_err();
        assert_eq!(failure.primary, OwnedChildError::SnapshotFailed);
        assert!(failure.cleanup_failed);

        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
        let snapshot_root = snapshot_root.unwrap();
        fs::remove_file(snapshot_root.join("verifier-child")).unwrap();
        fs::rename(
            saved_executable.unwrap(),
            snapshot_root.join("verifier-child"),
        )
        .unwrap();
        fs::remove_file(snapshot_root.join("verifier-child")).unwrap();
        fs::remove_dir(snapshot_root).unwrap();
        assert!(snapshot_residue(&fixture.root).is_empty());
    }

    const HELPER_SOURCE: &str = r#"
use std::{io::{self, Write}, process::{Command, Stdio}, thread, time::Duration};

fn flood(mut stream: impl Write + Send + 'static) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let chunk = [b'X'; 16 * 1024];
        for _ in 0..128 {
            if stream.write_all(&chunk).is_err() { break; }
        }
        let _ = stream.flush();
    })
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("valid") => print!("[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-09-03 1788436800 0 4 0 1 8 00 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"),
        Some("malformed") => print!("not-openpgp-status\n"),
        Some("nonzero") => { eprintln!("fixture rejection"); std::process::exit(7); }
        Some("hang") | Some("pipe-holder") => thread::sleep(Duration::from_secs(60)),
        Some("flood-stdout") => { let handle = flood(io::stdout()); let _ = handle.join(); }
        Some("flood-stderr") => { let handle = flood(io::stderr()); let _ = handle.join(); }
        Some("flood-both") => {
            let out = flood(io::stdout());
            let err = flood(io::stderr());
            let _ = out.join();
            let _ = err.join();
        }
        Some("descendant") => {
            let child = Command::new(std::env::current_exe().unwrap())
                .arg("pipe-holder")
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            println!("{}", child.id());
        }
        Some("exit-fast") => {}
        _ => std::process::exit(9),
    }
}
"#;
}

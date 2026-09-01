use super::*;

pub(crate) struct ApplianceSession {
    pub(crate) child: Child,
    pub(crate) watchdog: QemuWatchdog,
    pub(crate) runtime_dir: PathBuf,
    pub(crate) ssh_key: PathBuf,
    pub(crate) ssh_port: u16,
    pub(crate) qmp_port: u16,
    pub(crate) started_at: Instant,
    pub(crate) state: String,
    pub(crate) message: String,
    pub(crate) input_image: PathBuf,
    pub(crate) input_sha256_before: String,
    pub(crate) attached_image: PathBuf,
    pub(crate) attached_sha256_before: String,
    pub(crate) working_image: PathBuf,
    pub(crate) input_preparation: InputPreparation,
    pub(crate) target_system: Option<TargetSystemDiscovery>,
    pub(crate) nvidia_resolution: Option<NvidiaPublishedResolution>,
    pub(crate) nvidia_source_selection: Option<String>,
    pub(crate) nvidia_userspace: Option<NvidiaUserspaceResolution>,
    pub(crate) nvidia_installer_bundle: Option<NvidiaInstallerBundleState>,
    pub(crate) nvidia_install_validation: Option<NvidiaInstallHandoffResult>,
    pub(crate) nvidia_installation: Option<NvidiaInstallHandoffResult>,
}

pub(crate) struct NvidiaBuildSession {
    pub(crate) child: Child,
    pub(crate) watchdog: QemuWatchdog,
    pub(crate) runtime_dir: PathBuf,
    pub(crate) ssh_key: PathBuf,
    pub(crate) ssh_port: u16,
    pub(crate) qmp_port: u16,
    pub(crate) started_at: Instant,
    pub(crate) state: String,
    pub(crate) message: String,
    pub(crate) acceleration: String,
    pub(crate) attached_working_image: Option<PathBuf>,
}

#[derive(Clone)]
pub(crate) struct NvidiaBuildConnection {
    pub(crate) runtime_dir: PathBuf,
    pub(crate) ssh_key: PathBuf,
    pub(crate) ssh_port: u16,
}

impl From<&NvidiaBuildSession> for NvidiaBuildConnection {
    fn from(session: &NvidiaBuildSession) -> Self {
        Self {
            runtime_dir: session.runtime_dir.clone(),
            ssh_key: session.ssh_key.clone(),
            ssh_port: session.ssh_port,
        }
    }
}

#[derive(Clone)]
pub(crate) struct ImageInspectionSession {
    pub(crate) runtime_dir: PathBuf,
    pub(crate) ssh_key: PathBuf,
    pub(crate) ssh_port: u16,
    pub(crate) qmp_port: u16,
    pub(crate) input_image: PathBuf,
    pub(crate) input_sha256_before: String,
    pub(crate) attached_image: PathBuf,
    pub(crate) attached_sha256_before: String,
    pub(crate) working_image: PathBuf,
    pub(crate) input_preparation: InputPreparation,
}

impl From<&ApplianceSession> for ImageInspectionSession {
    fn from(session: &ApplianceSession) -> Self {
        Self {
            runtime_dir: session.runtime_dir.clone(),
            ssh_key: session.ssh_key.clone(),
            ssh_port: session.ssh_port,
            qmp_port: session.qmp_port,
            input_image: session.input_image.clone(),
            input_sha256_before: session.input_sha256_before.clone(),
            attached_image: session.attached_image.clone(),
            attached_sha256_before: session.attached_sha256_before.clone(),
            working_image: session.working_image.clone(),
            input_preparation: session.input_preparation.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputFormat {
    Raw,
    Bzip2,
    Gzip,
    Xz,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InputProgress {
    pub(crate) stage: String,
    pub(crate) processed_bytes: u64,
    pub(crate) total_bytes: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GuestResourcePlan {
    pub(crate) schema_version: u32,
    pub(crate) workload: String,
    pub(crate) host_memory_bytes: u64,
    pub(crate) host_logical_cpus: usize,
    pub(crate) guest_memory_mib: u64,
    pub(crate) guest_vcpus: usize,
}

pub(crate) fn plan_guest_resources(
    host_memory_bytes: u64,
    host_logical_cpus: usize,
    build_worker: bool,
) -> Result<GuestResourcePlan, String> {
    const GIB: u64 = 1024 * 1024 * 1024;
    if host_memory_bytes < 6 * GIB {
        return Err(format!(
            "At least {} bytes of host RAM are required; detected {host_memory_bytes}.",
            6 * GIB
        ));
    }
    if host_logical_cpus == 0 {
        return Err("Host CPU detection returned zero logical processors.".into());
    }
    let host_memory_mib = host_memory_bytes / (1024 * 1024);
    let guest_memory_mib = if build_worker {
        (host_memory_mib / 3).clamp(4096, 6144)
    } else {
        (host_memory_mib / 4).clamp(2048, 4096)
    };
    let max_vcpus = if build_worker { 6 } else { 4 };
    let guest_vcpus = if host_logical_cpus <= 2 {
        1
    } else {
        host_logical_cpus.saturating_sub(1).min(max_vcpus)
    };
    Ok(GuestResourcePlan {
        schema_version: 1,
        workload: if build_worker {
            "x86-build-install"
        } else {
            "native-inspection"
        }
        .into(),
        host_memory_bytes,
        host_logical_cpus,
        guest_memory_mib,
        guest_vcpus,
    })
}

pub(crate) fn detect_guest_resources(build_worker: bool) -> Result<GuestResourcePlan, String> {
    let output = Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .map_err(|error| format!("Could not detect host RAM with sysctl: {error}"))?;
    if !output.status.success() {
        return Err("Could not detect host RAM with sysctl.".into());
    }
    let host_memory_bytes = String::from_utf8(output.stdout)
        .map_err(|_| "Host RAM report was not valid UTF-8.")?
        .trim()
        .parse::<u64>()
        .map_err(|_| "Host RAM report did not contain a byte count.")?;
    let host_logical_cpus = thread::available_parallelism()
        .map(|count| count.get())
        .map_err(|error| format!("Could not detect host CPU count: {error}"))?;
    plan_guest_resources(host_memory_bytes, host_logical_cpus, build_worker)
}

pub(crate) type ProgressCallback<'a> = dyn Fn(&str, u64, u64) + 'a;

pub(crate) struct ReportingReader<'a> {
    pub(crate) inner: File,
    pub(crate) stage: &'static str,
    pub(crate) processed: u64,
    pub(crate) total: u64,
    pub(crate) next_report: u64,
    pub(crate) progress: Option<&'a ProgressCallback<'a>>,
    pub(crate) cancel: Option<&'a AtomicBool>,
}

pub(crate) struct BoundedWriter<W> {
    pub(crate) inner: W,
    pub(crate) written: u64,
    pub(crate) limit: u64,
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let remaining = self.limit.saturating_sub(self.written);
        if remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "normalized image exceeds the safety limit",
            ));
        }
        let allowed = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| io::Error::other("normalized image size conversion failed"))?;
        let count = self.inner.write(&buffer[..allowed])?;
        self.written = self
            .written
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("normalized image size overflowed"))?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Read for ReportingReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self
            .cancel
            .is_some_and(|cancel| cancel.load(Ordering::Relaxed))
        {
            return Err(io::Error::other("image preparation cancelled"));
        }
        let count = self.inner.read(buffer)?;
        self.processed += count as u64;
        if self.processed >= self.next_report || count == 0 {
            if let Some(progress) = self.progress {
                progress(self.stage, self.processed, self.total);
            }
            self.next_report = self.processed.saturating_add(64 * 1024 * 1024);
        }
        Ok(count)
    }
}

impl InputFormat {
    fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Bzip2 => "bzip2",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
        }
    }
}

pub(crate) struct RuntimeGuard {
    pub(crate) path: PathBuf,
    pub(crate) armed: bool,
}

pub(crate) struct NvidiaBuildRuntimeGuard {
    pub(crate) path: PathBuf,
    pub(crate) armed: bool,
}

pub(crate) struct PartialOutputGuard {
    pub(crate) path: PathBuf,
    pub(crate) armed: bool,
}

pub(crate) struct StagingDirectoryGuard {
    pub(crate) path: PathBuf,
    pub(crate) armed: bool,
}

pub(crate) struct QemuWatchdog {
    #[cfg(unix)]
    pub(crate) child: Child,
    #[cfg(unix)]
    pub(crate) keepalive: Option<UnixStream>,
}

impl QemuWatchdog {
    fn finish(&mut self) {
        #[cfg(unix)]
        {
            self.keepalive.take();
            for _ in 0..30 {
                if self.child.try_wait().ok().flatten().is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl Drop for QemuWatchdog {
    fn drop(&mut self) {
        self.finish();
    }
}

pub(crate) fn isolate_process_group(command: &mut Command) {
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(not(unix))]
    let _ = command;
}

#[cfg(unix)]
pub(crate) fn spawn_qemu_watchdog(qemu_pid: u32) -> Result<QemuWatchdog, String> {
    let (reader, writer) = UnixStream::pair()
        .map_err(|error| format!("Could not create the QEMU lifecycle watchdog: {error}"))?;
    let reader: OwnedFd = reader.into();
    let child = Command::new("/bin/sh")
        .args([
            "-c",
            "cat >/dev/null; kill -TERM -- \"-$1\" 2>/dev/null || exit 0; i=0; while kill -0 -- \"-$1\" 2>/dev/null && test \"$i\" -lt 20; do sleep 0.1; i=$((i + 1)); done; kill -KILL -- \"-$1\" 2>/dev/null || true",
            "steamos-qemu-watchdog",
            &qemu_pid.to_string(),
        ])
        .stdin(Stdio::from(reader))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("Could not start the QEMU lifecycle watchdog: {error}"))?;
    Ok(QemuWatchdog {
        child,
        keepalive: Some(writer),
    })
}

#[cfg(not(unix))]
pub(crate) fn spawn_qemu_watchdog(_qemu_pid: u32) -> Result<QemuWatchdog, String> {
    Ok(QemuWatchdog {})
}

impl Drop for PartialOutputGuard {
    fn drop(&mut self) {
        if self.armed && self.path.is_file() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl Drop for StagingDirectoryGuard {
    fn drop(&mut self) {
        if self.armed && self.path.is_dir() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        if self.armed && self.path.is_dir() {
            let _ = archive_and_remove_runtime(&self.path);
        }
    }
}

impl Drop for NvidiaBuildRuntimeGuard {
    fn drop(&mut self) {
        if self.armed && self.path.is_dir() {
            let _ = archive_and_remove_nvidia_build_runtime(&self.path);
        }
    }
}

impl Drop for ApplianceSession {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.watchdog.finish();
        if self.runtime_dir.is_dir() {
            let _ = archive_and_remove_runtime(&self.runtime_dir);
        }
    }
}

impl Drop for NvidiaBuildSession {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.watchdog.finish();
        if self.runtime_dir.is_dir() {
            let _ = archive_and_remove_nvidia_build_runtime(&self.runtime_dir);
        }
    }
}

pub(crate) struct ApplianceManager {
    pub(crate) session: Option<ApplianceSession>,
    pub(crate) preparing: bool,
    pub(crate) cancel_preparation: Arc<AtomicBool>,
}

#[derive(Default)]
pub(crate) struct NvidiaBuildManager {
    pub(crate) session: Option<NvidiaBuildSession>,
    pub(crate) starting: bool,
    pub(crate) cancel_build: Arc<AtomicBool>,
}

impl Drop for NvidiaBuildManager {
    fn drop(&mut self) {
        if let Some(session) = self.session.as_mut() {
            let _ = session.child.kill();
            let _ = session.child.wait();
        }
    }
}

impl Default for ApplianceManager {
    fn default() -> Self {
        Self {
            session: None,
            preparing: false,
            cancel_preparation: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Drop for ApplianceManager {
    fn drop(&mut self) {
        self.cancel_preparation.store(true, Ordering::Relaxed);
        if let Some(session) = self.session.as_mut() {
            let _ = session.child.kill();
            let _ = session.child.wait();
        }
    }
}

pub(crate) fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri should have a repository parent")
        .to_path_buf()
}

pub(crate) fn appliance_dir() -> PathBuf {
    repository_root().join("builder/appliance")
}
pub(crate) fn appliance_path() -> PathBuf {
    appliance_dir().join("fedora-builder.qcow2")
}

pub(crate) fn nvidia_build_appliance_path() -> PathBuf {
    appliance_dir().join("fedora-builder-x86_64.qcow2")
}

pub(crate) fn runtime_root() -> PathBuf {
    appliance_dir().join("runtime")
}

pub(crate) fn nvidia_build_runtime_root() -> PathBuf {
    appliance_dir().join("runtime-x86_64-managed")
}

pub(crate) fn nvidia_build_qemu_spec(
    host_arch: &str,
) -> Result<(&'static str, &'static str, &'static str), String> {
    match host_arch {
        "aarch64" => Ok(("tcg", "q35,accel=tcg", "max")),
        "x86_64" => Ok(("hvf", "q35,accel=hvf", "host")),
        arch => Err(format!("Unsupported host architecture: {arch}")),
    }
}

pub(crate) fn process_is_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub(crate) fn archive_and_remove_runtime(runtime_dir: &Path) -> Result<Option<PathBuf>, String> {
    let log_source = runtime_dir.join("qemu.log");
    let resources_source = runtime_dir.join("resources.json");
    let archive = if log_source.is_file() || resources_source.is_file() {
        let archive_dir = runtime_root().join("logs");
        fs::create_dir_all(&archive_dir)
            .map_err(|e| format!("Could not create the appliance log archive: {e}"))?;
        let session_name = runtime_dir
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unknown-session");
        let archive_path = archive_dir.join(format!("{session_name}.log"));
        let resources_path = archive_dir.join(format!("{session_name}.resources.json"));
        if log_source.is_file() {
            fs::copy(&log_source, &archive_path)
                .map_err(|e| format!("Could not archive the appliance log: {e}"))?;
        }
        if resources_source.is_file() {
            fs::copy(&resources_source, &resources_path)
                .map_err(|e| format!("Could not archive the appliance resource plan: {e}"))?;
        }
        Some(if archive_path.is_file() {
            archive_path
        } else {
            resources_path
        })
    } else {
        None
    };
    fs::remove_dir_all(runtime_dir)
        .map_err(|e| format!("Could not remove the disposable appliance runtime: {e}"))?;
    Ok(archive)
}

pub(crate) fn archive_and_remove_nvidia_build_runtime(
    runtime_dir: &Path,
) -> Result<Option<PathBuf>, String> {
    let diagnostic_sources = [
        ("RESOURCES", runtime_dir.join("resources.json")),
        ("QEMU", runtime_dir.join("qemu.log")),
        ("NVIDIA BUILD", runtime_dir.join("nvidia-build.log")),
        ("BUILD RESULT", runtime_dir.join("nvidia-build-result.json")),
        ("NVIDIA INSTALL", runtime_dir.join("nvidia-install.log")),
        (
            "NVIDIA INSTALL MUTATION",
            runtime_dir.join("nvidia-install-mutation.log"),
        ),
        (
            "INSTALL RESULT",
            runtime_dir.join("nvidia-install-result.json"),
        ),
        (
            "INSTALL MUTATION RESULT",
            runtime_dir.join("nvidia-install-mutation-result.json"),
        ),
    ];
    let archive = if diagnostic_sources
        .iter()
        .any(|(_, source)| source.is_file())
    {
        let archive_dir = nvidia_build_runtime_root().join("logs");
        fs::create_dir_all(&archive_dir)
            .map_err(|e| format!("Could not create the x86 build log archive: {e}"))?;
        let session_name = runtime_dir
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unknown-session");
        let archive_path = archive_dir.join(format!("{session_name}.log"));
        let archive_file = File::create(&archive_path)
            .map_err(|e| format!("Could not create the x86 build diagnostic archive: {e}"))?;
        let mut archive_writer = BufWriter::new(archive_file);
        for (label, source) in diagnostic_sources {
            if !source.is_file() {
                continue;
            }
            writeln!(archive_writer, "===== {label} =====")
                .map_err(|e| format!("Could not write the x86 build diagnostic header: {e}"))?;
            let mut source_file = File::open(&source)
                .map_err(|e| format!("Could not read x86 build diagnostics: {e}"))?;
            io::copy(&mut source_file, &mut archive_writer)
                .map_err(|e| format!("Could not archive x86 build diagnostics: {e}"))?;
            writeln!(archive_writer)
                .map_err(|e| format!("Could not finish x86 build diagnostics: {e}"))?;
        }
        archive_writer
            .flush()
            .map_err(|e| format!("Could not flush x86 build diagnostics: {e}"))?;
        Some(archive_path)
    } else {
        None
    };
    fs::remove_dir_all(runtime_dir)
        .map_err(|e| format!("Could not remove the x86 build-appliance runtime: {e}"))?;
    Ok(archive)
}

pub(crate) fn cleanup_abandoned_runtimes() -> Result<(), String> {
    let root = runtime_root();
    if !root.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(&root)
        .map_err(|e| format!("Could not inspect appliance runtime state: {e}"))?
    {
        let entry = entry.map_err(|e| format!("Could not inspect a runtime entry: {e}"))?;
        let path = entry.path();
        let is_session = path.is_dir()
            && path
                .file_name()
                .and_then(|value| value.to_str())
                .map(|name| name.starts_with("session-"))
                .unwrap_or(false);
        if !is_session {
            continue;
        }
        let active = fs::read_to_string(path.join("qemu.pid"))
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .map(process_is_alive)
            .unwrap_or(false);
        if !active {
            archive_and_remove_runtime(&path)?;
        }
    }
    Ok(())
}

pub(crate) fn cleanup_abandoned_nvidia_build_runtimes() -> Result<(), String> {
    let root = nvidia_build_runtime_root();
    if !root.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(&root)
        .map_err(|e| format!("Could not inspect x86 build-appliance runtime state: {e}"))?
    {
        let entry =
            entry.map_err(|e| format!("Could not inspect an x86 build-appliance runtime: {e}"))?;
        let path = entry.path();
        let is_session = path.is_dir()
            && path
                .file_name()
                .and_then(|value| value.to_str())
                .map(|name| name.starts_with("session-"))
                .unwrap_or(false);
        if !is_session {
            continue;
        }
        let active = fs::read_to_string(path.join("qemu.pid"))
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .map(process_is_alive)
            .unwrap_or(false);
        if !active {
            archive_and_remove_nvidia_build_runtime(&path)?;
        }
    }
    Ok(())
}

pub(crate) fn supported_image(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".img")
        || name.ends_with(".img.bz2")
        || name.ends_with(".img.gz")
        || name.ends_with(".img.xz")
}

pub(crate) fn qemu_binary_name() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "aarch64" => Ok("qemu-system-aarch64"),
        "x86_64" => Ok("qemu-system-x86_64"),
        arch => Err(format!("Unsupported host architecture: {arch}")),
    }
}

pub(crate) fn find_binary(binary: &str) -> Option<PathBuf> {
    let from_path = Command::new("which")
        .arg(binary)
        .output()
        .ok()
        .and_then(|output| {
            output
                .status
                .success()
                .then(|| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()))
        });
    from_path.filter(|path| path.is_file()).or_else(|| {
        ["/opt/homebrew/bin", "/usr/local/bin"]
            .into_iter()
            .map(|dir| PathBuf::from(dir).join(binary))
            .find(|path| path.is_file())
    })
}

pub(crate) fn find_qemu() -> Option<PathBuf> {
    qemu_binary_name().ok().and_then(find_binary)
}

pub(crate) fn qemu_version(path: &Path) -> Option<String> {
    let output = Command::new(path).arg("--version").output().ok()?;
    output.status.success().then(|| {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_string()
    })
}

pub(crate) fn runtime_executable_provenance(
    path: &Path,
) -> Result<RuntimeExecutableProvenance, String> {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or("QEMU executable filename is invalid for build provenance.")?;
    let version = qemu_version(path)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or("QEMU version is unavailable for build provenance.")?;
    Ok(RuntimeExecutableProvenance {
        filename: filename.into(),
        version,
    })
}

pub(crate) fn runtime_file_provenance(
    path: &Path,
    stage: &str,
    progress: Option<&ProgressCallback<'_>>,
    cancel: Option<&AtomicBool>,
) -> Result<RuntimeFileProvenance, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect builder appliance provenance: {error}"))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        return Err("Builder appliance provenance requires a non-empty regular file.".into());
    }
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or("Builder appliance filename is invalid for build provenance.")?;
    Ok(RuntimeFileProvenance {
        filename: filename.into(),
        bytes: metadata.len(),
        sha256: sha256_file_with_progress(path, stage, progress, cancel)?,
    })
}

pub(crate) fn collect_build_runtime_provenance(
    nvidia_installed: bool,
    progress: Option<&ProgressCallback<'_>>,
    cancel: Option<&AtomicBool>,
) -> Result<BuildRuntimeProvenance, String> {
    let native_qemu_path = find_qemu().ok_or("Native QEMU is unavailable for build provenance.")?;
    let native_qemu = runtime_executable_provenance(&native_qemu_path)?;
    let native_appliance = runtime_file_provenance(
        &appliance_path(),
        "hashing-native-appliance",
        progress,
        cancel,
    )?;
    let (x86_installer_qemu, x86_installer_appliance) = if nvidia_installed {
        let qemu = find_binary("qemu-system-x86_64")
            .ok_or("x86_64 QEMU is unavailable for build provenance.")?;
        (
            Some(runtime_executable_provenance(&qemu)?),
            Some(runtime_file_provenance(
                &nvidia_build_appliance_path(),
                "hashing-x86-appliance",
                progress,
                cancel,
            )?),
        )
    } else {
        (None, None)
    };
    Ok(BuildRuntimeProvenance {
        host_os: std::env::consts::OS.into(),
        host_architecture: std::env::consts::ARCH.into(),
        native_qemu,
        x86_installer_qemu,
        native_appliance,
        x86_installer_appliance,
    })
}

pub(crate) fn smoke_test_qemu(path: &Path) -> Result<(), String> {
    let mut command = Command::new(path);
    command
        .args([
            "-machine",
            "none",
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "none",
            "-nodefaults",
            "-S",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    isolate_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|e| format!("Could not start QEMU: {e}"))?;
    let mut watchdog = match spawn_qemu_watchdog(child.id()) {
        Ok(watchdog) => watchdog,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    thread::sleep(Duration::from_millis(350));
    if child
        .try_wait()
        .map_err(|e| format!("Could not inspect QEMU: {e}"))?
        .is_none()
    {
        child
            .kill()
            .map_err(|e| format!("Could not stop QEMU smoke test: {e}"))?;
        child
            .wait()
            .map_err(|e| format!("Could not finish QEMU smoke test: {e}"))?;
        watchdog.finish();
        Ok(())
    } else {
        watchdog.finish();
        use std::io::Read;
        let mut detail = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut detail);
        }
        Err(format!(
            "QEMU exited unexpectedly during startup: {}",
            detail.trim()
        ))
    }
}

pub(crate) fn run_checked(command: &mut Command, description: &str) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|e| format!("{description}: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if detail.is_empty() {
        format!("{description}: {}", output.status)
    } else {
        format!("{description}: {detail}")
    })
}

pub(crate) fn copy_new_file(
    source: &Path,
    destination: &Path,
    description: &str,
) -> Result<(), String> {
    let mut source_file = File::open(source).map_err(|e| format!("{description}: {e}"))?;
    let mut destination_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|e| format!("{description}: {e}"))?;
    io::copy(&mut source_file, &mut destination_file)
        .and_then(|_| destination_file.sync_all())
        .map_err(|e| format!("{description}: {e}"))?;
    Ok(())
}

pub(crate) fn homebrew_qemu_share() -> Result<PathBuf, String> {
    let brew = find_binary("brew").ok_or("Homebrew is required to locate QEMU firmware.")?;
    let output = Command::new(brew)
        .args(["--prefix", "qemu"])
        .output()
        .map_err(|e| format!("Could not locate the QEMU Homebrew prefix: {e}"))?;
    if !output.status.success() {
        return Err("Homebrew could not locate QEMU.".into());
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()).join("share/qemu"))
}

pub(crate) fn allocate_ssh_port() -> Result<u16, String> {
    TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("Could not allocate a guest SSH port: {e}"))?
        .local_addr()
        .map(|address| address.port())
        .map_err(|e| format!("Could not inspect the guest SSH port: {e}"))
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, String> {
    sha256_file_with_progress(path, "hashing", None, None)
}

pub(crate) fn sha256_file_with_progress(
    path: &Path,
    stage: &str,
    progress: Option<&ProgressCallback<'_>>,
    cancel: Option<&AtomicBool>,
) -> Result<String, String> {
    let file = File::open(path)
        .map_err(|e| format!("Could not open {} for hashing: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    let total = fs::metadata(path)
        .map_err(|e| format!("Could not inspect {} for hashing: {e}", path.display()))?
        .len();
    let mut processed = 0_u64;
    let mut next_report = 128 * 1024 * 1024;
    loop {
        if cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed)) {
            return Err("Image preparation cancelled.".into());
        }
        let count = reader
            .read(&mut buffer)
            .map_err(|e| format!("Could not hash {}: {e}", path.display()))?;
        if count == 0 {
            if let Some(progress) = progress {
                progress(stage, processed, total);
            }
            break;
        }
        hasher.update(&buffer[..count]);
        processed += count as u64;
        if processed >= next_report {
            if let Some(progress) = progress {
                progress(stage, processed, total);
            }
            next_report = processed.saturating_add(128 * 1024 * 1024);
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub(crate) fn detect_input_format(path: &Path) -> Result<InputFormat, String> {
    let mut file = File::open(path).map_err(|e| {
        format!(
            "Could not open {} for format detection: {e}",
            path.display()
        )
    })?;
    let mut signature = [0_u8; 6];
    let count = file
        .read(&mut signature)
        .map_err(|e| format!("Could not inspect {}: {e}", path.display()))?;
    let signature = &signature[..count];
    Ok(if signature.starts_with(b"BZh") {
        InputFormat::Bzip2
    } else if signature.starts_with(&[0x1f, 0x8b]) {
        InputFormat::Gzip
    } else if signature.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        InputFormat::Xz
    } else {
        InputFormat::Raw
    })
}

pub(crate) fn normalize_input(
    source: &Path,
    runtime_dir: &Path,
    format: InputFormat,
    progress: Option<&ProgressCallback<'_>>,
    cancel: Option<&AtomicBool>,
) -> Result<PathBuf, String> {
    if format == InputFormat::Raw {
        return Ok(source.to_path_buf());
    }
    let destination = runtime_dir.join("normalized-input.img");
    if format == InputFormat::Bzip2 {
        if let Some(seven_zip) = find_binary("7zz") {
            normalize_bzip2_parallel(
                &seven_zip,
                ParallelBzip2Tool::SevenZip,
                source,
                &destination,
                runtime_dir,
                progress,
                cancel,
            )?;
            return Ok(destination);
        }
        if let Some(pbzip2) = find_binary("pbzip2") {
            normalize_bzip2_parallel(
                &pbzip2,
                ParallelBzip2Tool::Pbzip2,
                source,
                &destination,
                runtime_dir,
                progress,
                cancel,
            )?;
            return Ok(destination);
        }
    }
    let source_file =
        File::open(source).map_err(|e| format!("Could not open the compressed input: {e}"))?;
    let source_bytes = source_file
        .metadata()
        .map_err(|e| format!("Could not inspect the compressed input: {e}"))?
        .len();
    let source_reader = ReportingReader {
        inner: source_file,
        stage: "decompressing",
        processed: 0,
        total: source_bytes,
        next_report: 0,
        progress,
        cancel,
    };
    let output_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&destination)
        .map_err(|e| format!("Could not create the normalized image: {e}"))?;
    let mut writer = BoundedWriter {
        inner: BufWriter::new(output_file),
        written: 0,
        limit: MAX_NORMALIZED_IMAGE_BYTES,
    };
    let copied = match format {
        InputFormat::Bzip2 => io::copy(
            &mut bzip2::read::BzDecoder::new(BufReader::new(source_reader)),
            &mut writer,
        ),
        InputFormat::Gzip => io::copy(
            &mut flate2::read::GzDecoder::new(BufReader::new(source_reader)),
            &mut writer,
        ),
        InputFormat::Xz => io::copy(
            &mut xz2::read::XzDecoder::new(BufReader::new(source_reader)),
            &mut writer,
        ),
        InputFormat::Raw => unreachable!(),
    }
    .map_err(|e| format!("Could not decompress the {} input: {e}", format.name()))?;
    writer
        .flush()
        .and_then(|_| writer.inner.get_ref().sync_all())
        .map_err(|e| format!("Could not finish the normalized image: {e}"))?;
    if copied == 0 {
        return Err("The compressed input produced an empty image.".into());
    }
    Ok(destination)
}

#[derive(Clone, Copy)]
pub(crate) enum ParallelBzip2Tool {
    SevenZip,
    Pbzip2,
}

pub(crate) fn normalize_bzip2_parallel(
    binary: &Path,
    tool: ParallelBzip2Tool,
    source: &Path,
    destination: &Path,
    runtime_dir: &Path,
    progress: Option<&ProgressCallback<'_>>,
    cancel: Option<&AtomicBool>,
) -> Result<(), String> {
    if cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed)) {
        return Err("Image preparation cancelled.".into());
    }
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|e| format!("Could not create the normalized image: {e}"))?;
    let (name, error_filename) = match tool {
        ParallelBzip2Tool::SevenZip => ("7-Zip", "sevenzip.log"),
        ParallelBzip2Tool::Pbzip2 => ("pbzip2", "pbzip2.log"),
    };
    let error_path = runtime_dir.join(error_filename);
    let error_log = File::create(&error_path)
        .map_err(|e| format!("Could not create the parallel decompressor log: {e}"))?;
    let workers = thread::available_parallelism()
        .map(|count| count.get().saturating_sub(2).clamp(1, 6))
        .unwrap_or(1);
    let mut command = Command::new(binary);
    match tool {
        ParallelBzip2Tool::SevenZip => {
            command
                .arg("x")
                .arg("-so")
                .arg(format!("-mmt={workers}"))
                .arg(source);
        }
        ParallelBzip2Tool::Pbzip2 => {
            command
                .arg("-d")
                .arg("-c")
                .arg(format!("-p{workers}"))
                .arg(source);
        }
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(output))
        .stderr(Stdio::from(error_log))
        .spawn()
        .map_err(|e| format!("Could not start {name} bzip2 decompression: {e}"))?;
    let status = loop {
        if cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed)) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Image preparation cancelled.".into());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("Could not inspect {name} decompression: {e}"))?
        {
            break status;
        }
        if let Some(progress) = progress {
            let output_bytes = fs::metadata(destination)
                .map(|value| value.len())
                .unwrap_or(0);
            if output_bytes > MAX_NORMALIZED_IMAGE_BYTES {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{name} output exceeded the {}-byte normalized-image safety limit.",
                    MAX_NORMALIZED_IMAGE_BYTES
                ));
            }
            progress("decompressing-output", output_bytes, 0);
        } else if fs::metadata(destination)
            .map(|value| value.len() > MAX_NORMALIZED_IMAGE_BYTES)
            .unwrap_or(false)
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{name} output exceeded the {}-byte normalized-image safety limit.",
                MAX_NORMALIZED_IMAGE_BYTES
            ));
        }
        thread::sleep(Duration::from_millis(500));
    };
    if !status.success() {
        let detail = fs::read_to_string(&error_path).unwrap_or_default();
        return Err(if detail.trim().is_empty() {
            format!("{name} bzip2 decompression failed with {status}.")
        } else {
            format!("{name} bzip2 decompression failed: {}", detail.trim())
        });
    }
    let output_bytes = fs::metadata(destination)
        .map_err(|e| format!("Could not inspect the parallel decompression output: {e}"))?
        .len();
    if output_bytes == 0 || output_bytes > MAX_NORMALIZED_IMAGE_BYTES {
        return Err("The compressed input produced an empty or implausibly large image.".into());
    }
    if let Some(progress) = progress {
        progress("decompressing-output", output_bytes, 0);
    }
    File::open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|e| format!("Could not finish the normalized image: {e}"))
}

pub(crate) fn prepare_session(
    input_image: Option<&Path>,
    progress: Option<&ProgressCallback<'_>>,
    cancel: Option<&AtomicBool>,
) -> Result<ApplianceSession, String> {
    cleanup_abandoned_runtimes()?;
    let appliance = appliance_path();
    if !appliance.is_file() {
        return Err(format!(
            "Builder appliance not found: {}",
            appliance.display()
        ));
    }
    let qemu = find_qemu()
        .ok_or_else(|| format!("{} is required.", qemu_binary_name().unwrap_or("QEMU")))?;
    let qemu_img = find_binary("qemu-img").ok_or("qemu-img is required.")?;
    let ssh_keygen = find_binary("ssh-keygen").ok_or("ssh-keygen is required.")?;
    let resources = detect_guest_resources(false)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System clock error: {e}"))?
        .as_millis();
    let runtime_dir = runtime_root().join(format!("session-{timestamp}-{}", std::process::id()));
    let cloud_init_dir = runtime_dir.join("cloud-init");
    fs::create_dir_all(&cloud_init_dir)
        .map_err(|e| format!("Could not create runtime directory: {e}"))?;
    let mut runtime_guard = RuntimeGuard {
        path: runtime_dir.clone(),
        armed: true,
    };
    fs::write(
        runtime_dir.join("resources.json"),
        serde_json::to_vec_pretty(&resources)
            .map_err(|error| format!("Could not serialize native resource plan: {error}"))?,
    )
    .map_err(|error| format!("Could not record native resource plan: {error}"))?;

    let ssh_key = runtime_dir.join("builder_key");
    run_checked(
        Command::new(ssh_keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&ssh_key),
        "Could not generate the runtime SSH identity",
    )?;
    let public_key = fs::read_to_string(ssh_key.with_extension("pub"))
        .map_err(|e| format!("Could not read the runtime SSH public key: {e}"))?;
    let source_user_data = fs::read_to_string(appliance_dir().join("cloud-init/user-data"))
        .map_err(|e| format!("Could not read cloud-init user-data: {e}"))?;
    let marker = "    lock_passwd: true\n";
    if !source_user_data.contains(marker) {
        return Err("Cloud-init user-data does not contain the SSH key insertion marker.".into());
    }
    let runtime_user_data = source_user_data.replacen(
        marker,
        &format!(
            "{marker}    ssh_authorized_keys:\n      - {}\n",
            public_key.trim()
        ),
        1,
    );
    fs::write(cloud_init_dir.join("user-data"), runtime_user_data)
        .map_err(|e| format!("Could not write runtime cloud-init user-data: {e}"))?;
    fs::copy(
        appliance_dir().join("cloud-init/meta-data"),
        cloud_init_dir.join("meta-data"),
    )
    .map_err(|e| format!("Could not copy cloud-init meta-data: {e}"))?;

    let runtime_disk = runtime_dir.join("session.qcow2");
    run_checked(
        Command::new(&qemu_img)
            .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
            .arg(&appliance)
            .arg(&runtime_disk),
        "Could not create the disposable appliance overlay",
    )?;
    let synthetic_disk = runtime_dir.join("synthetic-test.img");
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&synthetic_disk)
        .and_then(|file| file.set_len(64 * 1024 * 1024))
        .map_err(|e| format!("Could not create the sparse synthetic test disk: {e}"))?;
    let synthetic_working_disk = runtime_dir.join("synthetic-working.img");
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&synthetic_working_disk)
        .and_then(|file| file.set_len(64 * 1024 * 1024))
        .map_err(|e| format!("Could not create the sparse synthetic working disk: {e}"))?;
    let input_image = if let Some(path) = input_image {
        path.to_path_buf()
    } else {
        let fixture = runtime_dir.join("user-input-fixture.img");
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&fixture)
            .map_err(|e| format!("Could not create the user-image inspection fixture: {e}"))?;
        file.set_len(8 * 1024 * 1024)
            .map_err(|e| format!("Could not size the user-image inspection fixture: {e}"))?;
        let mut mbr = [0_u8; 512];
        mbr[446 + 4] = 0x83;
        mbr[446 + 8..446 + 12].copy_from_slice(&2048_u32.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&8192_u32.to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xaa;
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(&mbr))
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("Could not initialize the user-image inspection fixture: {e}"))?;
        fixture
    };
    let input_sha256_before =
        sha256_file_with_progress(&input_image, "hashing-source", progress, cancel)?;
    let source_bytes = fs::metadata(&input_image)
        .map_err(|e| format!("Could not inspect the input size: {e}"))?
        .len();
    let input_format = detect_input_format(&input_image)?;
    let normalizer = match input_format {
        InputFormat::Raw => "direct",
        InputFormat::Bzip2 if find_binary("7zz").is_some() => "sevenzip",
        InputFormat::Bzip2 if find_binary("pbzip2").is_some() => "pbzip2",
        InputFormat::Bzip2 => "embedded-bzip2",
        InputFormat::Gzip => "embedded-gzip",
        InputFormat::Xz => "embedded-xz",
    };
    let attached_image =
        normalize_input(&input_image, &runtime_dir, input_format, progress, cancel)?;
    let image_bytes = fs::metadata(&attached_image)
        .map_err(|e| format!("Could not inspect the normalized image size: {e}"))?
        .len();
    if image_bytes == 0 || image_bytes > MAX_NORMALIZED_IMAGE_BYTES {
        return Err(format!(
            "Normalized image size {image_bytes} is outside the supported 1-{} byte range.",
            MAX_NORMALIZED_IMAGE_BYTES
        ));
    }
    preflight_host_build_space(&runtime_dir, &input_image, image_bytes)?;
    let attached_sha256_before = if attached_image == input_image {
        input_sha256_before.clone()
    } else {
        sha256_file_with_progress(&attached_image, "hashing-image", progress, cancel)?
    };
    let input_preparation = InputPreparation {
        source_format: input_format.name().into(),
        normalizer: normalizer.into(),
        normalized: input_format != InputFormat::Raw,
        source_bytes,
        image_bytes,
    };
    let working_image = runtime_dir.join("user-working.qcow2");
    run_checked(
        Command::new(&qemu_img)
            .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
            .arg(&attached_image)
            .arg(&working_image),
        "Could not create the disposable user-image working layer",
    )?;
    let seed_image = runtime_dir.join("seed.iso");
    run_checked(
        Command::new("hdiutil")
            .args([
                "makehybrid",
                "-quiet",
                "-iso",
                "-joliet",
                "-default-volume-name",
                "cidata",
                "-o",
            ])
            .arg(&seed_image)
            .arg(&cloud_init_dir),
        "Could not create the cloud-init seed image",
    )?;
    let appended_seed = runtime_dir.join("seed.iso.iso");
    if !seed_image.is_file() && appended_seed.is_file() {
        fs::rename(appended_seed, &seed_image)
            .map_err(|e| format!("Could not normalize seed image name: {e}"))?;
    }
    if !seed_image.is_file() {
        return Err("Cloud-init seed image was not created.".into());
    }

    let share = homebrew_qemu_share()?;
    let (machine, code_name, vars_name) = match std::env::consts::ARCH {
        "aarch64" => ("virt,accel=hvf", "edk2-aarch64-code.fd", "edk2-arm-vars.fd"),
        "x86_64" => ("q35,accel=hvf", "edk2-x86_64-code.fd", "edk2-i386-vars.fd"),
        arch => return Err(format!("Unsupported host architecture: {arch}")),
    };
    let uefi_code = share.join(code_name);
    let vars_template = share.join(vars_name);
    if !uefi_code.is_file() || !vars_template.is_file() {
        return Err(format!(
            "Required QEMU firmware was not found under {}.",
            share.display()
        ));
    }
    let vars_image = runtime_dir.join("uefi-vars.fd");
    fs::copy(&vars_template, &vars_image)
        .map_err(|e| format!("Could not create the writable UEFI variable store: {e}"))?;
    let ssh_port = allocate_ssh_port()?;
    let mut qmp_port = allocate_ssh_port()?;
    while qmp_port == ssh_port {
        qmp_port = allocate_ssh_port()?;
    }
    let log = File::create(runtime_dir.join("qemu.log"))
        .map_err(|e| format!("Could not create the QEMU log: {e}"))?;
    let log_err = log
        .try_clone()
        .map_err(|e| format!("Could not prepare the QEMU log: {e}"))?;
    let input_drive_path = attached_image
        .to_str()
        .ok_or("The selected image path is not valid UTF-8.")?
        .replace(',', ",,");
    let working_drive_path = working_image
        .to_str()
        .ok_or("The working image path is not valid UTF-8.")?
        .replace(',', ",,");

    let guest_vcpus = resources.guest_vcpus.to_string();
    let guest_memory_mib = resources.guest_memory_mib.to_string();
    let mut command = Command::new(qemu);
    command
        .args([
            "-name",
            "SteamOS NVIDIA Builder",
            "-machine",
            machine,
            "-cpu",
            "host",
            "-smp",
            &guest_vcpus,
            "-m",
            &guest_memory_mib,
        ])
        .arg("-qmp")
        .arg(format!("tcp:127.0.0.1:{qmp_port},server=on,wait=off"))
        .arg("-drive")
        .arg(format!(
            "file={},if=pflash,format=raw,readonly=on",
            uefi_code.display()
        ))
        .arg("-drive")
        .arg(format!(
            "file={},if=pflash,format=raw",
            vars_image.display()
        ))
        .arg("-drive")
        .arg(format!(
            "file={},if=virtio,format=qcow2",
            runtime_disk.display()
        ))
        .arg("-drive")
        .arg(format!(
            "file={},if=virtio,format=raw,readonly=on",
            seed_image.display()
        ))
        .arg("-drive")
        .arg(format!(
            "file={},if=none,format=raw,id=synthetic",
            synthetic_disk.display()
        ))
        .args([
            "-device",
            "virtio-blk-pci,drive=synthetic,serial=steamos-synthetic",
        ])
        .arg("-drive")
        .arg(format!(
            "file={},if=none,format=raw,id=synthetic-working",
            synthetic_working_disk.display()
        ))
        .args([
            "-device",
            "virtio-blk-pci,drive=synthetic-working,serial=steamos-working",
        ])
        .arg("-drive")
        .arg(format!(
            "file={},if=none,format=raw,readonly=on,id=user-input",
            input_drive_path
        ))
        .args(["-device", "pcie-root-port,id=user-input-port"])
        .args([
            "-device",
            "virtio-blk-pci,bus=user-input-port,drive=user-input,serial=steamos-user-input,id=user-input-device",
        ])
        .arg("-drive")
        .arg(format!(
            "file={},if=none,format=qcow2,id=user-working",
            working_drive_path
        ))
        .args([
            "-device",
            "virtio-blk-pci,drive=user-working,serial=steamos-user-working",
        ])
        .args([
            "-device",
            "virtio-rng-pci",
            "-device",
            "virtio-net-pci,netdev=net0",
        ])
        .arg("-netdev")
        .arg(format!("user,id=net0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22"))
        .args(["-display", "none", "-monitor", "none", "-serial", "stdio"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    isolate_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|e| format!("Could not start the Fedora builder appliance: {e}"))?;
    if let Err(error) = fs::write(runtime_dir.join("qemu.pid"), child.id().to_string()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "Could not record the appliance process ID: {error}"
        ));
    }
    let watchdog = match spawn_qemu_watchdog(child.id()) {
        Ok(watchdog) => watchdog,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };

    runtime_guard.armed = false;
    Ok(ApplianceSession {
        child,
        watchdog,
        runtime_dir,
        ssh_key,
        ssh_port,
        qmp_port,
        started_at: Instant::now(),
        state: "booting".into(),
        message: "Fedora builder appliance is booting.".into(),
        input_image,
        input_sha256_before,
        attached_image,
        attached_sha256_before,
        working_image,
        input_preparation,
        target_system: None,
        nvidia_resolution: None,
        nvidia_source_selection: None,
        nvidia_userspace: None,
        nvidia_installer_bundle: None,
        nvidia_install_validation: None,
        nvidia_installation: None,
    })
}

pub(crate) fn prepare_nvidia_build_session(
    target_working_image: Option<&Path>,
) -> Result<NvidiaBuildSession, String> {
    cleanup_abandoned_nvidia_build_runtimes()?;
    let appliance = nvidia_build_appliance_path();
    if !appliance.is_file() {
        return Err(format!(
            "x86_64 Fedora build appliance not found: {}",
            appliance.display()
        ));
    }
    let qemu = find_binary("qemu-system-x86_64")
        .ok_or("qemu-system-x86_64 is required for NVIDIA artifact builds.")?;
    let qemu_img = find_binary("qemu-img").ok_or("qemu-img is required.")?;
    let ssh_keygen = find_binary("ssh-keygen").ok_or("ssh-keygen is required.")?;
    let (acceleration, machine, cpu_model) = nvidia_build_qemu_spec(std::env::consts::ARCH)?;
    let resources = detect_guest_resources(true)?;
    let attached_working_image = target_working_image
        .map(|path| -> Result<PathBuf, String> {
            let metadata = fs::symlink_metadata(path)
                .map_err(|e| format!("Could not inspect the handoff working image: {e}"))?;
            if !metadata.file_type().is_file() {
                return Err("The handoff working image is not a safe regular file.".into());
            }
            let path = fs::canonicalize(path)
                .map_err(|e| format!("Could not resolve the handoff working image: {e}"))?;
            let output = Command::new(&qemu_img)
                .args(["info", "--output=json"])
                .arg(&path)
                .output()
                .map_err(|e| format!("Could not inspect the handoff qcow2: {e}"))?;
            if !output.status.success() {
                return Err("The handoff working image failed qemu-img inspection.".into());
            }
            let info: serde_json::Value = serde_json::from_slice(&output.stdout)
                .map_err(|e| format!("The handoff qemu-img report is invalid JSON: {e}"))?;
            if info.get("format").and_then(|value| value.as_str()) != Some("qcow2") {
                return Err("The handoff working image is not qcow2.".into());
            }
            Ok(path)
        })
        .transpose()?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System clock error: {e}"))?
        .as_millis();
    let runtime_dir =
        nvidia_build_runtime_root().join(format!("session-{timestamp}-{}", std::process::id()));
    let cloud_init_dir = runtime_dir.join("cloud-init");
    fs::create_dir_all(&cloud_init_dir)
        .map_err(|e| format!("Could not create the x86 build runtime: {e}"))?;
    let mut runtime_guard = NvidiaBuildRuntimeGuard {
        path: runtime_dir.clone(),
        armed: true,
    };
    fs::write(
        runtime_dir.join("resources.json"),
        serde_json::to_vec_pretty(&resources)
            .map_err(|error| format!("Could not serialize x86 resource plan: {error}"))?,
    )
    .map_err(|error| format!("Could not record x86 resource plan: {error}"))?;

    let ssh_key = runtime_dir.join("builder_key");
    run_checked(
        Command::new(ssh_keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&ssh_key),
        "Could not generate the x86 build-appliance SSH identity",
    )?;
    let public_key = fs::read_to_string(ssh_key.with_extension("pub"))
        .map_err(|e| format!("Could not read the x86 build-appliance SSH key: {e}"))?;
    let source_user_data = fs::read_to_string(appliance_dir().join("cloud-init/user-data"))
        .map_err(|e| format!("Could not read cloud-init user-data: {e}"))?;
    let marker = "    lock_passwd: true\n";
    if !source_user_data.contains(marker) {
        return Err("Cloud-init user-data does not contain the SSH key insertion marker.".into());
    }
    let runtime_user_data = source_user_data.replacen(
        marker,
        &format!(
            "{marker}    ssh_authorized_keys:\n      - {}\n",
            public_key.trim()
        ),
        1,
    );
    fs::write(cloud_init_dir.join("user-data"), runtime_user_data)
        .map_err(|e| format!("Could not write x86 build cloud-init data: {e}"))?;
    fs::copy(
        appliance_dir().join("cloud-init/meta-data"),
        cloud_init_dir.join("meta-data"),
    )
    .map_err(|e| format!("Could not copy x86 build cloud-init metadata: {e}"))?;

    let runtime_disk = runtime_dir.join("session.qcow2");
    run_checked(
        Command::new(qemu_img)
            .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
            .arg(&appliance)
            .arg(&runtime_disk),
        "Could not create the disposable x86 build-appliance overlay",
    )?;
    let seed_image = runtime_dir.join("seed.iso");
    run_checked(
        Command::new("hdiutil")
            .args([
                "makehybrid",
                "-quiet",
                "-iso",
                "-joliet",
                "-default-volume-name",
                "cidata",
                "-o",
            ])
            .arg(&seed_image)
            .arg(&cloud_init_dir),
        "Could not create the x86 build-appliance cloud-init seed",
    )?;
    let appended_seed = runtime_dir.join("seed.iso.iso");
    if !seed_image.is_file() && appended_seed.is_file() {
        fs::rename(appended_seed, &seed_image)
            .map_err(|e| format!("Could not normalize x86 build seed name: {e}"))?;
    }
    if !seed_image.is_file() {
        return Err("The x86 build-appliance cloud-init seed was not created.".into());
    }

    let share = homebrew_qemu_share()?;
    let uefi_code = share.join("edk2-x86_64-code.fd");
    let vars_template = share.join("edk2-i386-vars.fd");
    if !uefi_code.is_file() || !vars_template.is_file() {
        return Err(format!(
            "Required x86 QEMU firmware was not found under {}.",
            share.display()
        ));
    }
    let vars_image = runtime_dir.join("uefi-vars.fd");
    fs::copy(&vars_template, &vars_image)
        .map_err(|e| format!("Could not create the x86 UEFI variable store: {e}"))?;
    let ssh_port = allocate_ssh_port()?;
    let mut qmp_port = allocate_ssh_port()?;
    while qmp_port == ssh_port {
        qmp_port = allocate_ssh_port()?;
    }
    let log = File::create(runtime_dir.join("qemu.log"))
        .map_err(|e| format!("Could not create the x86 build-appliance log: {e}"))?;
    let log_err = log
        .try_clone()
        .map_err(|e| format!("Could not prepare the x86 build-appliance log: {e}"))?;

    let guest_vcpus = resources.guest_vcpus.to_string();
    let guest_memory_mib = resources.guest_memory_mib.to_string();
    let mut qemu_command = Command::new(qemu);
    qemu_command
        .args([
            "-name",
            "SteamOS NVIDIA x86 Build Worker",
            "-machine",
            machine,
            "-cpu",
            cpu_model,
            "-smp",
            &guest_vcpus,
            "-m",
            &guest_memory_mib,
        ])
        .arg("-drive")
        .arg(format!(
            "file={},if=pflash,format=raw,readonly=on",
            uefi_code.display()
        ))
        .arg("-drive")
        .arg(format!(
            "file={},if=pflash,format=raw",
            vars_image.display()
        ))
        .arg("-drive")
        .arg(format!(
            "file={},if=virtio,format=qcow2",
            runtime_disk.display()
        ))
        .arg("-drive")
        .arg(format!(
            "file={},if=virtio,format=raw,readonly=on",
            seed_image.display()
        ));
    isolate_process_group(&mut qemu_command);
    let mut child = qemu_command
        .args([
            "-device",
            "pcie-root-port,id=steamos-target-port,chassis=10,slot=10",
            "-device",
            "virtio-rng-pci",
            "-device",
            "virtio-net-pci,netdev=net0",
        ])
        .arg("-netdev")
        .arg(format!("user,id=net0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22"))
        .arg("-qmp")
        .arg(format!("tcp:127.0.0.1:{qmp_port},server=on,wait=off"))
        .args(["-display", "none", "-monitor", "none", "-serial", "stdio"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|e| format!("Could not start the x86 Fedora build appliance: {e}"))?;
    if let Err(error) = fs::write(runtime_dir.join("qemu.pid"), child.id().to_string()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "Could not record the x86 build-appliance process ID: {error}"
        ));
    }
    let watchdog = match spawn_qemu_watchdog(child.id()) {
        Ok(watchdog) => watchdog,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };

    runtime_guard.armed = false;
    Ok(NvidiaBuildSession {
        child,
        watchdog,
        runtime_dir,
        ssh_key,
        ssh_port,
        qmp_port,
        started_at: Instant::now(),
        state: "booting".into(),
        message: if acceleration == "tcg" {
            "x86_64 Fedora build appliance is booting under software emulation.".into()
        } else {
            "x86_64 Fedora build appliance is booting.".into()
        },
        acceleration: acceleration.into(),
        attached_working_image,
    })
}

pub(crate) trait GuestConnection {
    fn ssh_key(&self) -> &Path;
    fn ssh_port(&self) -> u16;
    fn runtime_dir(&self) -> &Path;
}

impl GuestConnection for ApplianceSession {
    fn ssh_key(&self) -> &Path {
        &self.ssh_key
    }

    fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }
}

impl GuestConnection for ImageInspectionSession {
    fn ssh_key(&self) -> &Path {
        &self.ssh_key
    }

    fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }
}

impl GuestConnection for NvidiaBuildSession {
    fn ssh_key(&self) -> &Path {
        &self.ssh_key
    }

    fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }
}

impl GuestConnection for NvidiaBuildConnection {
    fn ssh_key(&self) -> &Path {
        &self.ssh_key
    }

    fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }
}

pub(crate) fn ssh_command(session: &impl GuestConnection) -> Result<Command, String> {
    let ssh = find_binary("ssh").ok_or("ssh is required for the guest handshake.")?;
    let mut command = Command::new(ssh);
    command
        .arg("-p")
        .arg(session.ssh_port().to_string())
        .arg("-i")
        .arg(session.ssh_key())
        .args([
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=2",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "builder@127.0.0.1",
        ]);
    Ok(command)
}

pub(crate) fn run_guest_command(
    session: &impl GuestConnection,
    command: &str,
) -> Result<String, String> {
    let output = ssh_command(session)?
        .arg(command)
        .output()
        .map_err(|e| format!("Could not run the structured guest command: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        return Err(if detail.is_empty() {
            format!("Guest command exited with {}.", output.status)
        } else {
            format!("Guest command exited with {}: {detail}", output.status)
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(crate) fn read_qmp_response(
    reader: &mut BufReader<TcpStream>,
) -> Result<serde_json::Value, String> {
    loop {
        let mut line = String::new();
        if reader
            .read_line(&mut line)
            .map_err(|e| format!("Could not read the QEMU monitor response: {e}"))?
            == 0
        {
            return Err("QEMU closed its monitor connection unexpectedly.".into());
        }
        let value: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| format!("QEMU returned an invalid monitor response: {e}"))?;
        if let Some(error) = value.get("error") {
            return Err(format!("QEMU monitor command failed: {error}"));
        }
        if value.get("return").is_some() {
            return Ok(value);
        }
    }
}

pub(crate) fn qmp_remove_user_input(session: &ImageInspectionSession) -> Result<(), String> {
    let mut stream = TcpStream::connect(("127.0.0.1", session.qmp_port))
        .map_err(|e| format!("Could not connect to the QEMU monitor: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| format!("Could not configure the QEMU monitor: {e}"))?;
    let reader_stream = stream
        .try_clone()
        .map_err(|e| format!("Could not prepare the QEMU monitor reader: {e}"))?;
    let mut reader = BufReader::new(reader_stream);
    let mut greeting = String::new();
    reader
        .read_line(&mut greeting)
        .map_err(|e| format!("Could not read the QEMU monitor greeting: {e}"))?;
    let greeting: serde_json::Value = serde_json::from_str(&greeting)
        .map_err(|e| format!("QEMU returned an invalid monitor greeting: {e}"))?;
    if greeting.get("QMP").is_none() {
        return Err("QEMU monitor did not provide a QMP greeting.".into());
    }
    stream
        .write_all(b"{\"execute\":\"qmp_capabilities\"}\n")
        .and_then(|_| stream.flush())
        .map_err(|e| format!("Could not enable QEMU monitor capabilities: {e}"))?;
    read_qmp_response(&mut reader)?;
    stream
        .write_all(b"{\"execute\":\"device_del\",\"arguments\":{\"id\":\"user-input-device\"}}\n")
        .and_then(|_| stream.flush())
        .map_err(|e| format!("Could not request source-device removal: {e}"))?;
    read_qmp_response(&mut reader)?;
    Ok(())
}

pub(crate) fn qmp_attach_nvidia_target(session: &NvidiaBuildSession) -> Result<(), String> {
    let Some(target) = session.attached_working_image.as_ref() else {
        return Ok(());
    };
    let target = target
        .to_str()
        .ok_or("The handoff working-image path is not valid UTF-8.")?;
    let mut stream = TcpStream::connect(("127.0.0.1", session.qmp_port))
        .map_err(|e| format!("Could not connect to the x86 QEMU monitor: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| format!("Could not configure the x86 QEMU monitor: {e}"))?;
    let reader_stream = stream
        .try_clone()
        .map_err(|e| format!("Could not prepare the x86 QEMU monitor reader: {e}"))?;
    let mut reader = BufReader::new(reader_stream);
    let mut greeting = String::new();
    reader
        .read_line(&mut greeting)
        .map_err(|e| format!("Could not read the x86 QEMU monitor greeting: {e}"))?;
    let greeting: serde_json::Value = serde_json::from_str(&greeting)
        .map_err(|e| format!("x86 QEMU returned an invalid monitor greeting: {e}"))?;
    if greeting.get("QMP").is_none() {
        return Err("x86 QEMU monitor did not provide a QMP greeting.".into());
    }
    let mut execute = |command: serde_json::Value| -> Result<(), String> {
        let mut bytes = serde_json::to_vec(&command)
            .map_err(|e| format!("Could not encode an x86 QEMU monitor command: {e}"))?;
        bytes.push(b'\n');
        stream
            .write_all(&bytes)
            .and_then(|_| stream.flush())
            .map_err(|e| format!("Could not write an x86 QEMU monitor command: {e}"))?;
        read_qmp_response(&mut reader)?;
        Ok(())
    };
    execute(serde_json::json!({ "execute": "qmp_capabilities" }))?;
    execute(serde_json::json!({
        "execute": "blockdev-add",
        "arguments": {
            "node-name": "steamos-target-file",
            "driver": "file",
            "filename": target
        }
    }))?;
    execute(serde_json::json!({
        "execute": "blockdev-add",
        "arguments": {
            "node-name": "steamos-target-qcow2",
            "driver": "qcow2",
            "file": "steamos-target-file"
        }
    }))?;
    execute(serde_json::json!({
        "execute": "device_add",
        "arguments": {
            "driver": "virtio-blk-pci",
            "drive": "steamos-target-qcow2",
            "id": "steamos-install-target-device",
            "bus": "steamos-target-port",
            "serial": "steamos-target"
        }
    }))?;
    run_guest_command(
        session,
        "set -eu; for attempt in $(seq 1 50); do test -b /dev/disk/by-id/virtio-steamos-target && break; sleep 0.1; done; TARGET=/dev/disk/by-id/virtio-steamos-target; test -b \"$TARGET\"; test \"$(sudo blockdev --getro \"$TARGET\")\" = 0; ! findmnt -rn -S \"$TARGET\" >/dev/null 2>&1",
    )?;
    Ok(())
}

pub(crate) fn handshake(session: &impl GuestConnection) -> Result<String, String> {
    run_guest_command(session, "cat /etc/steamos-builder-ready")
}

pub(crate) fn collect_guest_health(session: &impl GuestConnection) -> Result<GuestHealth, String> {
    const HEALTH_COMMAND: &str = r#"set -eu
test "$(cat /etc/steamos-builder-ready)" = "$(printf 'SteamOS NVIDIA Image Builder appliance\nREADY')"
printf 'PROTOCOL=1\n'
printf 'HOSTNAME=%s\n' "$(hostname)"
printf 'ARCH=%s\n' "$(uname -m)"
. /etc/os-release
printf 'OS=%s\n' "$PRETTY_NAME"
printf 'AVAILABLE=%s\n' "$(df -B1 --output=avail / | tail -n 1 | tr -d ' ')"
for tool in bash lsblk blkid findmnt mount umount sha256sum stat cp sync dd sfdisk mkfs.ext4 blockdev btrfs btrfstune awk od cut sort head find; do
  command -v "$tool" >/dev/null 2>&1 && printf 'TOOL=%s\n' "$tool" || printf 'MISSING=%s\n' "$tool"
done"#;
    let output = run_guest_command(session, HEALTH_COMMAND)?;
    let mut protocol_version = None;
    let mut hostname = None;
    let mut architecture = None;
    let mut operating_system = None;
    let mut available_bytes = None;
    let mut required_tools = Vec::new();
    let mut missing_tools = Vec::new();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "PROTOCOL" => protocol_version = Some(value.to_string()),
            "HOSTNAME" => hostname = Some(value.to_string()),
            "ARCH" => architecture = Some(value.to_string()),
            "OS" => operating_system = Some(value.to_string()),
            "AVAILABLE" => {
                available_bytes = value.parse::<u64>().ok();
            }
            "TOOL" => required_tools.push(value.to_string()),
            "MISSING" => missing_tools.push(value.to_string()),
            _ => {}
        }
    }
    if !missing_tools.is_empty() {
        return Err(format!(
            "Builder appliance is missing required tools: {}.",
            missing_tools.join(", ")
        ));
    }
    let protocol_version =
        protocol_version.ok_or("Guest health response omitted protocol version.")?;
    if protocol_version != "1" {
        return Err(format!(
            "Unsupported guest protocol version {protocol_version}; expected 1."
        ));
    }
    Ok(GuestHealth {
        protocol_version,
        hostname: hostname.ok_or("Guest health response omitted hostname.")?,
        architecture: architecture.ok_or("Guest health response omitted architecture.")?,
        operating_system: operating_system
            .ok_or("Guest health response omitted operating system.")?,
        available_bytes: available_bytes
            .ok_or("Guest health response omitted available disk space.")?,
        required_tools,
    })
}

pub(crate) fn scp_command(session: &impl GuestConnection) -> Result<Command, String> {
    let scp = find_binary("scp").ok_or("scp is required for controlled guest file transfer.")?;
    let mut command = Command::new(scp);
    command
        .arg("-P")
        .arg(session.ssh_port().to_string())
        .arg("-i")
        .arg(session.ssh_key())
        .args([
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
        ]);
    Ok(command)
}

pub(crate) fn session_status(session: &ApplianceSession) -> ApplianceStatus {
    ApplianceStatus {
        state: session.state.clone(),
        message: session.message.clone(),
        ssh_port: Some(session.ssh_port),
        runtime_path: Some(session.runtime_dir.to_string_lossy().into_owned()),
        input: Some(session.input_preparation.clone()),
    }
}

pub(crate) fn nvidia_build_status(session: &NvidiaBuildSession) -> NvidiaBuildStatus {
    NvidiaBuildStatus {
        state: session.state.clone(),
        message: session.message.clone(),
        architecture: "x86_64".into(),
        acceleration: session.acceleration.clone(),
        ssh_port: Some(session.ssh_port),
        runtime_path: Some(session.runtime_dir.to_string_lossy().into_owned()),
    }
}

pub(crate) fn stopped_nvidia_build_status(message: impl Into<String>) -> NvidiaBuildStatus {
    let acceleration = nvidia_build_qemu_spec(std::env::consts::ARCH)
        .map(|(acceleration, _, _)| acceleration)
        .unwrap_or("unavailable");
    NvidiaBuildStatus {
        state: "stopped".into(),
        message: message.into(),
        architecture: "x86_64".into(),
        acceleration: acceleration.into(),
        ssh_port: None,
        runtime_path: None,
    }
}

#[tauri::command]
pub(crate) async fn check_nvidia_build_environment() -> Result<NvidiaBuildEnvironment, String> {
    tauri::async_runtime::spawn_blocking(check_nvidia_build_environment_blocking)
        .await
        .map_err(|error| format!("NVIDIA build-environment worker failed: {error}"))
}

pub(crate) fn check_nvidia_build_environment_blocking() -> NvidiaBuildEnvironment {
    let host_arch = std::env::consts::ARCH.to_string();
    let appliance = nvidia_build_appliance_path();
    let appliance_present = appliance.is_file();
    let appliance_path = appliance.to_string_lossy().into_owned();
    let Ok((acceleration, _, _)) = nvidia_build_qemu_spec(&host_arch) else {
        return NvidiaBuildEnvironment {
            ready: false,
            host_arch,
            guest_arch: "x86_64".into(),
            acceleration: "unavailable".into(),
            qemu_binary: None,
            qemu_version: None,
            qemu_launch_test: false,
            appliance_present,
            appliance_path,
            message: "The host architecture cannot run the x86 build appliance.".into(),
        };
    };
    let Some(qemu) = find_binary("qemu-system-x86_64") else {
        return NvidiaBuildEnvironment {
            ready: false,
            host_arch,
            guest_arch: "x86_64".into(),
            acceleration: acceleration.into(),
            qemu_binary: None,
            qemu_version: None,
            qemu_launch_test: false,
            appliance_present,
            appliance_path,
            message: "qemu-system-x86_64 is required for NVIDIA artifact builds.".into(),
        };
    };
    let version = qemu_version(&qemu);
    let launch_result = smoke_test_qemu(&qemu);
    let firmware_present = homebrew_qemu_share()
        .map(|share| {
            share.join("edk2-x86_64-code.fd").is_file() && share.join("edk2-i386-vars.fd").is_file()
        })
        .unwrap_or(false);
    let ready = appliance_present && version.is_some() && launch_result.is_ok() && firmware_present;
    let message = if !appliance_present {
        "The separate x86_64 Fedora build appliance has not been prepared.".into()
    } else if version.is_none() {
        "QEMU was found, but its version could not be determined.".into()
    } else if let Err(error) = &launch_result {
        error.clone()
    } else if !firmware_present {
        "Required x86 QEMU firmware is unavailable.".into()
    } else if acceleration == "tcg" {
        "x86_64 build worker is available under slower software emulation.".into()
    } else {
        "x86_64 build worker is available with hardware acceleration.".into()
    };
    NvidiaBuildEnvironment {
        ready,
        host_arch,
        guest_arch: "x86_64".into(),
        acceleration: acceleration.into(),
        qemu_binary: Some(qemu.to_string_lossy().into_owned()),
        qemu_version: version,
        qemu_launch_test: launch_result.is_ok(),
        appliance_present,
        appliance_path,
        message,
    }
}

#[tauri::command]
pub(crate) async fn start_nvidia_build_appliance(
    app: tauri::AppHandle,
) -> Result<NvidiaBuildStatus, String> {
    tauri::async_runtime::spawn_blocking(move || start_nvidia_build_appliance_blocking(app))
        .await
        .map_err(|error| format!("NVIDIA build-appliance startup worker failed: {error}"))?
}

pub(crate) fn start_nvidia_build_appliance_blocking(
    app: tauri::AppHandle,
) -> Result<NvidiaBuildStatus, String> {
    let manager_state = app.state::<Mutex<NvidiaBuildManager>>();
    {
        let mut manager = manager_state
            .lock()
            .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
        if manager.starting {
            return Ok(NvidiaBuildStatus {
                state: "starting".into(),
                message: "The x86_64 Fedora build appliance is being prepared.".into(),
                architecture: "x86_64".into(),
                acceleration: nvidia_build_qemu_spec(std::env::consts::ARCH)?.0.into(),
                ssh_port: None,
                runtime_path: None,
            });
        }
        if let Some(session) = manager.session.as_mut() {
            if session
                .child
                .try_wait()
                .map_err(|e| format!("Could not inspect the x86 build appliance: {e}"))?
                .is_none()
            {
                return Ok(nvidia_build_status(session));
            }
            manager.session = None;
        }
        manager.starting = true;
        manager.cancel_build.store(false, Ordering::Relaxed);
    }
    let prepared = prepare_nvidia_build_session(None);
    let mut manager = manager_state
        .lock()
        .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
    manager.starting = false;
    let session = prepared?;
    let status = nvidia_build_status(&session);
    manager.session = Some(session);
    Ok(status)
}

#[tauri::command]
pub(crate) async fn get_nvidia_build_appliance_status(
    app: tauri::AppHandle,
) -> Result<NvidiaBuildStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let manager_state = app.state::<Mutex<NvidiaBuildManager>>();
        let mut manager = manager_state
            .lock()
            .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
        if manager.starting {
            return Ok(NvidiaBuildStatus {
                state: "starting".into(),
                message: "The x86_64 Fedora build appliance is being prepared.".into(),
                architecture: "x86_64".into(),
                acceleration: nvidia_build_qemu_spec(std::env::consts::ARCH)?.0.into(),
                ssh_port: None,
                runtime_path: None,
            });
        }
        let Some(session) = manager.session.as_mut() else {
            return Ok(stopped_nvidia_build_status(
                "The x86_64 Fedora build appliance is stopped.",
            ));
        };
        if let Some(exit) = session
            .child
            .try_wait()
            .map_err(|e| format!("Could not inspect the x86 build appliance: {e}"))?
        {
            session.state = "failed".into();
            session.message = format!(
                "x86_64 Fedora build appliance exited with {exit}. See its archived log for details."
            );
            return Ok(nvidia_build_status(session));
        }
        if session.state != "booting" {
            return Ok(nvidia_build_status(session));
        }
        if fs::read_to_string(session.runtime_dir.join("qemu.log"))
            .map(|log| log.contains(r"\EFI\steamos\grubx64.efi"))
            .unwrap_or(false)
        {
            session.state = "failed".into();
            session.message = "x86_64 appliance selected the attached SteamOS data disk as its boot device instead of Fedora.".into();
            return Ok(nvidia_build_status(session));
        }
        match handshake(session) {
            Ok(output) if output == READY_MARKER => match collect_guest_health(session) {
                Ok(health) if health.architecture == "x86_64" => {
                    match qmp_attach_nvidia_target(session) {
                        Ok(()) => {
                            session.state = "ready".into();
                            session.message = if session.attached_working_image.is_some() {
                                "x86_64 Fedora build appliance is ready; the SteamOS working image was attached after boot.".into()
                            } else {
                                "x86_64 Fedora build appliance is ready.".into()
                            };
                        }
                        Err(error) => {
                            session.state = "failed".into();
                            session.message = format!(
                                "Fedora booted, but the SteamOS working-image hotplug failed: {error}"
                            );
                        }
                    }
                }
                Ok(health) => {
                    session.state = "failed".into();
                    session.message = format!(
                        "Build appliance reported architecture {}; expected x86_64.",
                        health.architecture
                    );
                }
                Err(error) => {
                    session.state = "failed".into();
                    session.message = format!("Build-appliance health check failed: {error}");
                }
            },
            Ok(_) => {
                session.state = "failed".into();
                session.message = "Build-appliance handshake returned an unexpected marker.".into();
            }
            Err(_) if session.started_at.elapsed() >= NVIDIA_BUILD_BOOT_TIMEOUT => {
                session.state = "timedOut".into();
                session.message =
                    "x86_64 Fedora build appliance did not become ready within 10 minutes.".into();
            }
            Err(_) => {}
        }
        Ok(nvidia_build_status(session))
    })
    .await
    .map_err(|error| format!("NVIDIA build-appliance status worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn nvidia_build_guest_health(
    app: tauri::AppHandle,
) -> Result<GuestHealth, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let manager_state = app.state::<Mutex<NvidiaBuildManager>>();
        let manager = manager_state
            .lock()
            .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
        let session = manager
            .session
            .as_ref()
            .ok_or("The x86_64 Fedora build appliance is not running.")?;
        if session.state != "ready" {
            return Err("The x86_64 Fedora build appliance is not ready.".into());
        }
        let health = collect_guest_health(session)?;
        if health.architecture != "x86_64" {
            return Err(format!(
                "Build appliance reported architecture {}; expected x86_64.",
                health.architecture
            ));
        }
        Ok(health)
    })
    .await
    .map_err(|error| format!("NVIDIA build-appliance health worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn build_nvidia_target_development(
    app: tauri::AppHandle,
    support_repository: String,
    output_dir: String,
    steamos_version: String,
    kernel_version: String,
    nvidia_version: String,
) -> Result<NvidiaDevelopmentArtifact, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let manager_state = app.state::<Mutex<NvidiaBuildManager>>();
        let (connection, cancel) = {
            let mut manager = manager_state
                .lock()
                .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
            manager.cancel_build.store(false, Ordering::Relaxed);
            let cancel = manager.cancel_build.clone();
            let session = manager
                .session
                .as_mut()
                .ok_or("The x86_64 Fedora build appliance is not running.")?;
            if session.state != "ready" {
                return Err("The x86_64 Fedora build appliance is not ready.".into());
            }
            session.state = "building".into();
            session.message = format!(
                "Building NVIDIA {nvidia_version} for exact kernel {kernel_version}."
            );
            (NvidiaBuildConnection::from(&*session), cancel)
        };
        let spec = NvidiaTargetBuildSpec {
            steamos_version,
            kernel_version,
            nvidia_version,
        };
        let result = build_nvidia_for_target(
            &connection,
            Path::new(&support_repository),
            Path::new(&output_dir),
            &spec,
            Some(&cancel),
        );
        if let Ok(mut manager) = manager_state.lock() {
            if let Some(session) = manager
                .session
                .as_mut()
                .filter(|session| session.ssh_port == connection.ssh_port)
            {
                session.state = "ready".into();
                session.message = match &result {
                    Ok(_) => "Development NVIDIA artifact build completed and validated.".into(),
                    Err(error) => format!(
                        "Development NVIDIA artifact build stopped without a usable artifact: {error}"
                    ),
                };
            }
        }
        result
    })
    .await
    .map_err(|error| format!("NVIDIA target-build worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn read_nvidia_build_appliance_log(
    app: tauri::AppHandle,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let runtime_dir = {
            let manager_state = app.state::<Mutex<NvidiaBuildManager>>();
            let manager = manager_state
                .lock()
                .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
            let Some(session) = manager.session.as_ref() else {
                return Ok(String::new());
            };
            session.runtime_dir.clone()
        };
        // Fedora boot and compiler output can advance by substantially more than
        // 32 KiB between UI polls under emulation. Keep a wide enough rolling
        // window for the frontend to find overlap without repeatedly shipping
        // the complete, unbounded logs.
        const LOG_LIMIT: usize = 256 * 1024;
        let qemu_bytes = fs::read(runtime_dir.join("qemu.log"))
            .map_err(|e| format!("Could not read the x86 build-appliance log: {e}"))?;
        let qemu_start = qemu_bytes.len().saturating_sub(LOG_LIMIT);
        let mut output = String::from_utf8_lossy(&qemu_bytes[qemu_start..]).into_owned();
        let build_log = runtime_dir.join("nvidia-build.log");
        if build_log.is_file() {
            let build_bytes = fs::read(build_log)
                .map_err(|e| format!("Could not read the NVIDIA target-build log: {e}"))?;
            let build_start = build_bytes.len().saturating_sub(LOG_LIMIT);
            output.push_str("\n[NVIDIA target build]\n");
            output.push_str(&String::from_utf8_lossy(&build_bytes[build_start..]));
        }
        let install_log = runtime_dir.join("nvidia-install.log");
        if install_log.is_file() {
            let install_bytes = fs::read(install_log)
                .map_err(|e| format!("Could not read the NVIDIA installer log: {e}"))?;
            let install_start = install_bytes.len().saturating_sub(LOG_LIMIT);
            output.push_str("\n[NVIDIA offline-root validation]\n");
            output.push_str(&String::from_utf8_lossy(&install_bytes[install_start..]));
        }
        let mutation_log = runtime_dir.join("nvidia-install-mutation.log");
        if mutation_log.is_file() {
            let mutation_bytes = fs::read(mutation_log)
                .map_err(|e| format!("Could not read the NVIDIA installation log: {e}"))?;
            let mutation_start = mutation_bytes.len().saturating_sub(LOG_LIMIT);
            output.push_str("\n[NVIDIA offline-root installation]\n");
            output.push_str(&String::from_utf8_lossy(&mutation_bytes[mutation_start..]));
        }
        Ok(output)
    })
    .await
    .map_err(|error| format!("NVIDIA build-appliance log worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn check_builder_environment() -> Result<BuilderEnvironment, String> {
    tauri::async_runtime::spawn_blocking(check_builder_environment_blocking)
        .await
        .map_err(|error| format!("Builder environment worker failed: {error}"))
}

pub(crate) fn check_builder_environment_blocking() -> BuilderEnvironment {
    let host_os = std::env::consts::OS.to_string();
    let host_arch = std::env::consts::ARCH.to_string();
    let appliance = appliance_path();
    let appliance_present = appliance.is_file();
    let appliance_path = appliance.to_string_lossy().into_owned();
    let binary_name = match qemu_binary_name() {
        Ok(value) => value,
        Err(message) => {
            return BuilderEnvironment {
                ready: false,
                host_os,
                host_arch,
                qemu_binary: None,
                qemu_version: None,
                qemu_launch_test: false,
                message,
                appliance_present,
                appliance_path,
            }
        }
    };
    let Some(qemu) = find_qemu() else {
        return BuilderEnvironment {
            ready: false,
            host_os,
            host_arch,
            qemu_binary: None,
            qemu_version: None,
            qemu_launch_test: false,
            appliance_present,
            appliance_path,
            message: format!("{binary_name} is required before the builder appliance can run."),
        };
    };
    let version = qemu_version(&qemu);
    if version.is_none() {
        return BuilderEnvironment {
            ready: false,
            host_os,
            host_arch,
            qemu_binary: Some(qemu.to_string_lossy().into_owned()),
            qemu_version: None,
            qemu_launch_test: false,
            appliance_present,
            appliance_path,
            message: "QEMU was found, but its version could not be determined.".into(),
        };
    }
    if let Err(message) = smoke_test_qemu(&qemu) {
        return BuilderEnvironment {
            ready: false,
            host_os,
            host_arch,
            qemu_binary: Some(qemu.to_string_lossy().into_owned()),
            qemu_version: version,
            qemu_launch_test: false,
            appliance_present,
            appliance_path,
            message,
        };
    }
    let ready = appliance_present;
    BuilderEnvironment {
        ready,
        host_os,
        host_arch,
        qemu_binary: Some(qemu.to_string_lossy().into_owned()),
        qemu_version: version,
        qemu_launch_test: true,
        appliance_present,
        appliance_path,
        message: if ready {
            "Host prerequisites are ready.".into()
        } else {
            "QEMU is ready. Fedora builder appliance is missing.".into()
        },
    }
}

#[tauri::command]
pub(crate) async fn start_appliance(
    path: String,
    app: tauri::AppHandle,
) -> Result<ApplianceStatus, String> {
    let recovery_app = app.clone();
    match tauri::async_runtime::spawn_blocking(move || start_appliance_blocking(path, app)).await {
        Ok(result) => result,
        Err(error) => {
            if let Ok(mut manager) = recovery_app.state::<Mutex<ApplianceManager>>().lock() {
                manager.preparing = false;
            }
            Err(format!("Image preparation worker failed: {error}"))
        }
    }
}

pub(crate) fn start_appliance_blocking(
    path: String,
    app: tauri::AppHandle,
) -> Result<ApplianceStatus, String> {
    let input = fs::canonicalize(PathBuf::from(path))
        .map_err(|e| format!("Could not resolve the selected image: {e}"))?;
    if !input.is_file() {
        return Err("The selected image is no longer available.".into());
    }
    if !supported_image(&input) {
        return Err(
            "Select a SteamOS recovery image (.img, .img.bz2, .img.gz, or .img.xz).".into(),
        );
    }
    let manager_state = app.state::<Mutex<ApplianceManager>>();
    let mut manager = manager_state
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    if manager.preparing {
        return Err("Another image is already being prepared.".into());
    }
    if let Some(session) = manager.session.as_mut() {
        if session
            .child
            .try_wait()
            .map_err(|e| format!("Could not inspect the appliance: {e}"))?
            .is_none()
        {
            return Ok(session_status(session));
        }
        manager.session = None;
    }
    manager.cancel_preparation.store(false, Ordering::Relaxed);
    manager.preparing = true;
    let cancel = manager.cancel_preparation.clone();
    drop(manager);

    let report_progress = |stage: &str, processed_bytes: u64, total_bytes: u64| {
        let _ = app.emit_to(
            "build-progress",
            "input-progress",
            InputProgress {
                stage: stage.into(),
                processed_bytes,
                total_bytes,
            },
        );
    };
    let prepared = prepare_session(Some(&input), Some(&report_progress), Some(&cancel));
    let mut manager = manager_state
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    manager.preparing = false;
    if cancel.load(Ordering::Relaxed) {
        drop(prepared);
        return Err("Image preparation cancelled.".into());
    }
    let session = prepared?;
    let status = session_status(&session);
    manager.session = Some(session);
    Ok(status)
}

#[tauri::command]
pub(crate) async fn get_appliance_status(app: tauri::AppHandle) -> Result<ApplianceStatus, String> {
    tauri::async_runtime::spawn_blocking(move || get_appliance_status_blocking(app))
        .await
        .map_err(|error| format!("Appliance status worker failed: {error}"))?
}

pub(crate) fn get_appliance_status_blocking(
    app: tauri::AppHandle,
) -> Result<ApplianceStatus, String> {
    let manager_state = app.state::<Mutex<ApplianceManager>>();
    let (snapshot, session_port, started_at) = {
        let mut manager = manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        if manager.preparing {
            return Ok(ApplianceStatus {
                state: "preparing".into(),
                message: "Input image preparation is running in the background.".into(),
                ssh_port: None,
                runtime_path: None,
                input: None,
            });
        }
        let Some(session) = manager.session.as_mut() else {
            return Ok(ApplianceStatus {
                state: "stopped".into(),
                message: "Builder appliance is stopped.".into(),
                ssh_port: None,
                runtime_path: None,
                input: None,
            });
        };
        if let Some(exit) = session
            .child
            .try_wait()
            .map_err(|e| format!("Could not inspect the appliance: {e}"))?
        {
            session.state = "failed".into();
            session.message = format!(
                "Builder appliance exited unexpectedly with {exit}. See qemu.log for details."
            );
            return Ok(session_status(session));
        }
        if session.state != "booting" {
            return Ok(session_status(session));
        }
        (
            ImageInspectionSession::from(&*session),
            session.ssh_port,
            session.started_at,
        )
    };

    let handshake_result = handshake(&snapshot);
    let mut manager = manager_state
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    let Some(session) = manager.session.as_mut() else {
        return Ok(ApplianceStatus {
            state: "stopped".into(),
            message: "Builder appliance is stopped.".into(),
            ssh_port: None,
            runtime_path: None,
            input: None,
        });
    };
    if session.ssh_port != session_port || session.state != "booting" {
        return Ok(session_status(session));
    }
    match handshake_result {
        Ok(output) if output == READY_MARKER => {
            session.state = "ready".into();
            session.message = "Builder appliance is ready.".into();
        }
        Ok(_) => {
            session.state = "failed".into();
            session.message = "Builder handshake returned an unexpected marker.".into();
        }
        Err(_) if started_at.elapsed() >= BOOT_TIMEOUT => {
            session.state = "timedOut".into();
            session.message = "Builder appliance did not become ready within 120 seconds.".into();
        }
        Err(_) => {}
    }
    Ok(session_status(session))
}

pub(crate) fn ready_session_snapshot(
    app: &tauri::AppHandle,
    operation: &str,
) -> Result<ImageInspectionSession, String> {
    let manager_state = app.state::<Mutex<ApplianceManager>>();
    let manager = manager_state
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    let session = manager
        .session
        .as_ref()
        .ok_or("Builder appliance is not running.")?;
    if session.state != "ready" {
        return Err(format!("Builder appliance is not ready for {operation}."));
    }
    Ok(ImageInspectionSession::from(session))
}

#[tauri::command]
pub(crate) async fn read_appliance_log(app: tauri::AppHandle) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || read_appliance_log_blocking(app))
        .await
        .map_err(|error| format!("Appliance log worker failed: {error}"))?
}

pub(crate) fn read_appliance_log_blocking(app: tauri::AppHandle) -> Result<String, String> {
    let log_path = {
        let manager_state = app.state::<Mutex<ApplianceManager>>();
        let manager = manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        let Some(session) = manager.session.as_ref() else {
            return Ok(String::new());
        };
        session.runtime_dir.join("qemu.log")
    };
    let bytes = fs::read(log_path).map_err(|e| format!("Could not read the appliance log: {e}"))?;
    const LOG_LIMIT: usize = 256 * 1024;
    let start = bytes.len().saturating_sub(LOG_LIMIT);
    Ok(String::from_utf8_lossy(&bytes[start..]).into_owned())
}

#[tauri::command]
pub(crate) async fn guest_health(app: tauri::AppHandle) -> Result<GuestHealth, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let session = ready_session_snapshot(&app, "health checks")?;
        collect_guest_health(&session)
    })
    .await
    .map_err(|error| format!("Guest health worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn verify_guest_transfer(app: tauri::AppHandle) -> Result<TransferProof, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let session = ready_session_snapshot(&app, "file transfer")?;
        run_transfer_proof(&session)
    })
    .await
    .map_err(|error| format!("Guest transfer worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn inspect_test_disk(
    app: tauri::AppHandle,
) -> Result<SyntheticDiskInspection, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let session = ready_session_snapshot(&app, "synthetic disk inspection")?;
        inspect_synthetic_disk(&session)
    })
    .await
    .map_err(|error| format!("Synthetic disk worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn inspect_selected_image(
    app: tauri::AppHandle,
) -> Result<UserImageInspection, String> {
    tauri::async_runtime::spawn_blocking(move || inspect_selected_image_blocking(app))
        .await
        .map_err(|error| format!("Image inspection worker failed: {error}"))?
}

pub(crate) fn inspect_selected_image_blocking(
    app: tauri::AppHandle,
) -> Result<UserImageInspection, String> {
    let session = ready_session_snapshot(&app, "selected image inspection")?;
    let cancel = app
        .state::<Mutex<ApplianceManager>>()
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?
        .cancel_preparation
        .clone();
    let report_progress = |stage: &str, processed_bytes: u64, total_bytes: u64| {
        let _ = app.emit_to(
            "build-progress",
            "input-progress",
            InputProgress {
                stage: stage.into(),
                processed_bytes,
                total_bytes,
            },
        );
    };
    inspect_user_image(&session, Some(&report_progress), Some(&cancel))
}

#[tauri::command]
pub(crate) async fn verify_working_image(
    app: tauri::AppHandle,
) -> Result<WorkingImageVerification, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let session = ready_session_snapshot(&app, "working-image verification")?;
        if !session.working_image.is_file() {
            return Err("The disposable working image is unavailable.".into());
        }
        verify_user_working_image(&session)
    })
    .await
    .map_err(|error| format!("Working-image verification worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn mutate_test_marker(app: tauri::AppHandle) -> Result<MarkerMutation, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let session = ready_session_snapshot(&app, "synthetic marker mutation")?;
        mutate_synthetic_marker(&session)
    })
    .await
    .map_err(|error| format!("Synthetic mutation worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn mutate_selected_marker(
    app: tauri::AppHandle,
) -> Result<UserMarkerMutation, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let session = ready_session_snapshot(&app, "selected-image marker mutation")?;
        let mutation = mutate_user_marker(&session)?;
        let manager_state = app.state::<Mutex<ApplianceManager>>();
        let mut manager = manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        let active = manager
            .session
            .as_mut()
            .filter(|active| active.ssh_port == session.ssh_port)
            .ok_or("Builder session ended before target metadata could be recorded.")?;
        active.target_system = Some(mutation.system.clone());
        Ok(mutation)
    })
    .await
    .map_err(|error| format!("Selected-image mutation worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn assess_nvidia_target(
    app: tauri::AppHandle,
) -> Result<NvidiaTargetReadiness, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let manager_state = app.state::<Mutex<ApplianceManager>>();
        let manager = manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        let system = manager
            .session
            .as_ref()
            .and_then(|session| session.target_system.as_ref())
            .ok_or("Target SteamOS metadata has not been discovered yet.")?;
        Ok(assess_nvidia_target_system(system))
    })
    .await
    .map_err(|error| format!("NVIDIA target-assessment worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn resolve_published_nvidia(
    app: tauri::AppHandle,
    source_selection: Option<String>,
    allow_experimental_upstream: Option<bool>,
) -> Result<NvidiaPublishedResolution, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let manager_state = app.state::<Mutex<ApplianceManager>>();
        let (target, runtime_dir, cancel) = {
            let manager = manager_state
                .lock()
                .map_err(|_| "Appliance state lock is unavailable.")?;
            let session = manager
                .session
                .as_ref()
                .ok_or("The builder appliance is not running.")?;
            let system = session
                .target_system
                .as_ref()
                .ok_or("Target SteamOS metadata has not been discovered yet.")?;
            (
                assess_nvidia_target_system(system),
                session.runtime_dir.clone(),
                manager.cancel_preparation.clone(),
            )
        };
        let report_progress = |stage: &str, processed_bytes: u64, total_bytes: u64| {
            let _ = app.emit_to(
                "build-progress",
                "nvidia-resolution-progress",
                NvidiaResolutionProgress {
                    stage: stage.into(),
                    processed_bytes,
                    total_bytes,
                },
            );
        };
        let selection = source_selection.as_deref().unwrap_or("automatic");
        let resolution = if !target.ready {
            resolve_published_nvidia_for_target(
                target,
                &runtime_dir,
                &nvidia_http_client()?,
                &[],
                &cancel,
                &report_progress,
            )?
        } else {
            if cancel.load(Ordering::Relaxed) {
                return Err("Published NVIDIA resolution cancelled.".into());
            }
            report_progress("querying-nvidia-releases", 0, 1);
            let client = nvidia_http_client()?;
            let releases = fetch_github_releases(&client)?;
            report_progress("querying-nvidia-releases", 1, 1);
            let explicit_source = match selection {
                "automatic" => None,
                "latest" => fetch_nvidia_source_branches(&client)?
                    .into_iter()
                    .next()
                    .map(Some)
                    .ok_or("No NVIDIA source branches are available.")?,
                branch if branch.starts_with("project:") => {
                    let name = branch.trim_start_matches("project:");
                    fetch_nvidia_source_branches(&client)?
                        .into_iter()
                        .find(|branch| branch.name == name)
                        .ok_or_else(|| {
                            format!(
                                "Selected project NVIDIA source branch {name} is no longer available."
                            )
                        })
                        .map(Some)?
                }
                branch if valid_nvidia_source_branch(branch).is_some() => {
                    fetch_nvidia_source_branches(&client)?
                        .into_iter()
                        .find(|candidate| candidate.name == branch)
                        .ok_or_else(|| {
                            format!(
                                "Selected project NVIDIA source branch {branch} is no longer available."
                            )
                        })
                        .map(Some)?
                }
                upstream if upstream.starts_with("upstream:") => {
                    let settings = load_builder_settings(&app)?;
                    if !settings.include_upstream_nvidia_releases {
                        return Err(
                            "Experimental upstream NVIDIA releases are disabled in settings."
                                .into(),
                        );
                    }
                    if allow_experimental_upstream != Some(true) {
                        return Err(
                            "Experimental upstream NVIDIA selection requires explicit per-build acknowledgement."
                                .into(),
                        );
                    }
                    let tag = upstream.trim_start_matches("upstream:");
                    let tags = fetch_upstream_nvidia_tags(&client)?;
                    let selected = tags
                        .into_iter()
                        .find(|candidate| candidate.name == tag)
                        .ok_or_else(|| {
                            format!(
                                "Selected upstream NVIDIA release {tag} no longer exists."
                            )
                        })?;
                    Some(selected)
                }
                _ => return Err("NVIDIA source selection is invalid.".into()),
            };

            if let Some(selected) = explicit_source {
                preflight_nvidia_userspace(&client, &selected.version)?;
                if selected.experimental {
                    explicit_nvidia_build_resolution(
                        target,
                        &selected,
                        format!("upstream-tag-{}", selected.name),
                    )?
                } else {
                    let matching_releases: Vec<_> = releases
                        .iter()
                        .filter(|release| {
                            published_release_identity(&release.tag_name)
                                .is_some_and(|identity| identity.nvidia_version == selected.version)
                        })
                        .cloned()
                        .collect();
                    let selected_resolution = resolve_published_nvidia_for_target(
                        target.clone(),
                        &runtime_dir,
                        &client,
                        &matching_releases,
                        &cancel,
                        &report_progress,
                    )?;
                    if selected_resolution.status == "compatible" {
                        selected_resolution
                    } else {
                        let baseline = selected_resolution
                            .build_plan
                            .as_ref()
                            .map(|plan| plan.baseline_release.clone())
                            .unwrap_or_else(|| {
                                format!("selected-project-source-{}", selected.name)
                            });
                        explicit_nvidia_build_resolution(target, &selected, baseline)?
                    }
                }
            } else {
                let mut automatic = resolve_published_nvidia_for_target(
                    target,
                    &runtime_dir,
                    &client,
                    &releases,
                    &cancel,
                    &report_progress,
                )?;
                if automatic.status == "build_required" {
                    let branches = fetch_nvidia_source_branches(&client)?;
                    let plan = automatic
                        .build_plan
                        .as_mut()
                        .ok_or("NVIDIA resolver omitted the automatic build plan.")?;
                    let selected = branches
                        .iter()
                        .find(|branch| branch.name == plan.source_branch)
                        .ok_or_else(|| {
                            format!(
                                "Automatic NVIDIA source branch {} is no longer available.",
                                plan.source_branch
                            )
                        })?;
                    plan.source_commit = selected.commit.clone();
                }
                automatic
            }
        };
        let mut manager = manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        let active = manager
            .session
            .as_mut()
            .filter(|session| session.runtime_dir == runtime_dir)
            .ok_or("Builder session ended before NVIDIA resolution could be recorded.")?;
        active.nvidia_resolution = Some(resolution.clone());
        active.nvidia_source_selection = Some(selection.to_string());
        active.nvidia_userspace = None;
        active.nvidia_installer_bundle = None;
        active.nvidia_install_validation = None;
        active.nvidia_installation = None;
        Ok(resolution)
    })
    .await
    .map_err(|error| format!("Published NVIDIA resolver worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn prepare_nvidia_userspace(
    app: tauri::AppHandle,
) -> Result<NvidiaUserspaceResolution, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let manager_state = app.state::<Mutex<ApplianceManager>>();
        let (runtime_dir, nvidia_version, cancel) = {
            let manager = manager_state
                .lock()
                .map_err(|_| "Appliance state lock is unavailable.")?;
            let session = manager
                .session
                .as_ref()
                .ok_or("The builder appliance is not running.")?;
            let resolution = session
                .nvidia_resolution
                .as_ref()
                .filter(|resolution| resolution.status == "compatible")
                .ok_or("A compatible published NVIDIA artifact must be verified first.")?;
            let publication = resolution
                .publication
                .as_ref()
                .ok_or("Compatible NVIDIA resolution omitted publication metadata.")?;
            if let Some(userspace) = session
                .nvidia_userspace
                .as_ref()
                .filter(|userspace| userspace.nvidia_version == publication.nvidia_version)
            {
                return Ok(userspace.clone());
            }
            (
                session.runtime_dir.clone(),
                publication.nvidia_version.clone(),
                manager.cancel_preparation.clone(),
            )
        };
        let report_progress = |stage: &str, processed_bytes: u64, total_bytes: u64| {
            let _ = app.emit_to(
                "build-progress",
                "nvidia-resolution-progress",
                NvidiaResolutionProgress {
                    stage: stage.into(),
                    processed_bytes,
                    total_bytes,
                },
            );
        };
        let userspace = resolve_nvidia_userspace_for_version(
            &runtime_dir,
            &nvidia_version,
            &nvidia_http_client()?,
            &cancel,
            &report_progress,
        )?;
        let mut manager = manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        let active = manager
            .session
            .as_mut()
            .filter(|session| session.runtime_dir == runtime_dir)
            .ok_or("Builder session ended before NVIDIA userspace inputs could be recorded.")?;
        active.nvidia_userspace = Some(userspace.clone());
        active.nvidia_installer_bundle = None;
        active.nvidia_install_validation = None;
        active.nvidia_installation = None;
        Ok(userspace)
    })
    .await
    .map_err(|error| format!("NVIDIA userspace preparation worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn prepare_nvidia_installer_bundle(
    app: tauri::AppHandle,
) -> Result<NvidiaInstallerBundle, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let manager_state = app.state::<Mutex<ApplianceManager>>();
        let (runtime_dir, cancel, steamos_version, nvidia_version, staged_packages, existing_bundle) = {
            let manager = manager_state
                .lock()
                .map_err(|_| "Appliance state lock is unavailable.")?;
            let session = manager
                .session
                .as_ref()
                .ok_or("The builder appliance is not running.")?;
            session
                .nvidia_resolution
                .as_ref()
                .filter(|resolution| resolution.status == "compatible")
                .ok_or("A compatible published NVIDIA artifact must be verified first.")?;
            let userspace = session
                .nvidia_userspace
                .as_ref()
                .filter(|userspace| {
                    userspace.status == "prepared"
                        && userspace.signature_status == "pending-x86-validation"
                        && valid_prepared_userspace_packages(&userspace.packages)
                })
                .ok_or("Exact NVIDIA userspace packages must be staged first.")?;
            let publication_version = session
                .nvidia_resolution
                .as_ref()
                .and_then(|resolution| resolution.publication.as_ref())
                .map(|publication| publication.nvidia_version.as_str())
                .ok_or("Compatible NVIDIA resolution omitted publication metadata.")?;
            if userspace.nvidia_version != publication_version {
                return Err(
                    "Staged NVIDIA userspace version does not match the publication.".into(),
                );
            }
            let steamos_version = session
                .target_system
                .as_ref()
                .and_then(|target| target.version_id.clone())
                .ok_or("Target SteamOS version is unavailable.")?;
            (
                session.runtime_dir.clone(),
                manager.cancel_preparation.clone(),
                steamos_version,
                publication_version.to_owned(),
                userspace.packages.clone(),
                session.nvidia_installer_bundle.clone(),
            )
        };
        let report_progress = |stage: &str, processed_bytes: u64, total_bytes: u64| {
            let _ = app.emit_to(
                "build-progress",
                "nvidia-resolution-progress",
                NvidiaResolutionProgress {
                    stage: stage.into(),
                    processed_bytes,
                    total_bytes,
                },
            );
        };
        let client = nvidia_http_client()?;
        let bundle = if let Some(bundle) = existing_bundle {
            validate_staged_nvidia_installer_bundle(&bundle)?;
            bundle
        } else {
            prepare_pinned_nvidia_installer_bundle(
                &runtime_dir,
                &client,
                &cancel,
                &report_progress,
            )?
        };
        validate_staged_nvidia_installer_bundle(&bundle)?;
        let packages = stage_reviewed_userspace_closure(
            &bundle.root,
            &steamos_version,
            &nvidia_version,
            &staged_packages,
            &client,
            &cancel,
            &report_progress,
        )?;
        let report = bundle.report.clone();
        let mut manager = manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        let active = manager
            .session
            .as_mut()
            .filter(|session| session.runtime_dir == runtime_dir)
            .ok_or("Builder session ended before the NVIDIA installer could be recorded.")?;
        active.nvidia_installer_bundle = Some(bundle);
        let userspace = active
            .nvidia_userspace
            .as_mut()
            .ok_or("Builder session lost its NVIDIA userspace state.")?;
        userspace.packages = packages;
        userspace.reason = "reviewed_userspace_closure_staged".into();
        userspace.message = format!(
            "Staged the complete reviewed NVIDIA {nvidia_version} userspace closure for SteamOS {steamos_version}; signatures remain pending x86 appliance verification."
        );
        Ok(report)
    })
    .await
    .map_err(|error| format!("NVIDIA installer preparation worker failed: {error}"))?
}

pub(crate) fn stop_session_process(session: &mut ApplianceSession) -> Result<(), String> {
    if session
        .child
        .try_wait()
        .map_err(|e| format!("Could not inspect the appliance: {e}"))?
        .is_none()
    {
        if let Some(ssh) = find_binary("ssh") {
            let _ = Command::new(ssh)
                .arg("-p")
                .arg(session.ssh_port.to_string())
                .arg("-i")
                .arg(&session.ssh_key)
                .args([
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=2",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "LogLevel=ERROR",
                    "builder@127.0.0.1",
                    "sudo systemctl poweroff",
                ])
                .output();
        }
        for _ in 0..20 {
            if session
                .child
                .try_wait()
                .map_err(|e| format!("Could not inspect appliance shutdown: {e}"))?
                .is_some()
            {
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }
        if session
            .child
            .try_wait()
            .map_err(|e| format!("Could not inspect appliance shutdown: {e}"))?
            .is_none()
        {
            session
                .child
                .kill()
                .map_err(|e| format!("Could not force-stop the appliance: {e}"))?;
            session
                .child
                .wait()
                .map_err(|e| format!("Could not finish appliance shutdown: {e}"))?;
        }
    }
    session.watchdog.finish();
    Ok(())
}

pub(crate) fn stop_session(session: &mut ApplianceSession) -> Result<Option<PathBuf>, String> {
    stop_session_process(session)?;
    archive_and_remove_runtime(&session.runtime_dir)
}

pub(crate) fn stop_nvidia_build_session(
    session: &mut NvidiaBuildSession,
) -> Result<Option<PathBuf>, String> {
    if session
        .child
        .try_wait()
        .map_err(|e| format!("Could not inspect the x86 build appliance: {e}"))?
        .is_none()
    {
        if let Ok(mut command) = ssh_command(session) {
            let _ = command.arg("sudo systemctl poweroff").output();
        }
        for _ in 0..40 {
            if session
                .child
                .try_wait()
                .map_err(|e| format!("Could not inspect x86 build-appliance shutdown: {e}"))?
                .is_some()
            {
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }
        if session
            .child
            .try_wait()
            .map_err(|e| format!("Could not inspect x86 build-appliance shutdown: {e}"))?
            .is_none()
        {
            session
                .child
                .kill()
                .map_err(|e| format!("Could not force-stop the x86 build appliance: {e}"))?;
            session
                .child
                .wait()
                .map_err(|e| format!("Could not finish x86 build-appliance shutdown: {e}"))?;
        }
    }
    session.watchdog.finish();
    archive_and_remove_nvidia_build_runtime(&session.runtime_dir)
}

#[tauri::command]
pub(crate) async fn stop_nvidia_build_appliance(
    app: tauri::AppHandle,
) -> Result<NvidiaBuildStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let manager_state = app.state::<Mutex<NvidiaBuildManager>>();
        let mut manager = manager_state
            .lock()
            .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
        manager.cancel_build.store(true, Ordering::Relaxed);
        let Some(mut session) = manager.session.take() else {
            return Ok(stopped_nvidia_build_status(
                "The x86_64 Fedora build appliance is stopped.",
            ));
        };
        let archived_log = stop_nvidia_build_session(&mut session)?;
        let mut status = stopped_nvidia_build_status(
            "x86_64 Fedora build appliance stopped; its disposable disk and credentials were removed.",
        );
        status.runtime_path = archived_log.map(|path| path.to_string_lossy().into_owned());
        Ok(status)
    })
    .await
    .map_err(|error| format!("NVIDIA build-appliance shutdown worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn stop_appliance(app: tauri::AppHandle) -> Result<ApplianceStatus, String> {
    tauri::async_runtime::spawn_blocking(move || stop_appliance_blocking(app))
        .await
        .map_err(|error| format!("Appliance shutdown worker failed: {error}"))?
}

pub(crate) fn stop_appliance_blocking(app: tauri::AppHandle) -> Result<ApplianceStatus, String> {
    let manager_state = app.state::<Mutex<ApplianceManager>>();
    let mut manager = manager_state
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    manager.cancel_preparation.store(true, Ordering::Relaxed);
    if manager.preparing {
        return Ok(ApplianceStatus {
            state: "stopping".into(),
            message: "Cancelling background image preparation.".into(),
            ssh_port: None,
            runtime_path: None,
            input: None,
        });
    }
    let Some(mut session) = manager.session.take() else {
        return Ok(ApplianceStatus {
            state: "stopped".into(),
            message: "Builder appliance is stopped.".into(),
            ssh_port: None,
            runtime_path: None,
            input: None,
        });
    };
    let archived_log = stop_session(&mut session)?;
    Ok(ApplianceStatus {
        state: "stopped".into(),
        message: "Builder appliance stopped; disposable disk and credentials were removed.".into(),
        ssh_port: None,
        runtime_path: archived_log.map(|path| path.to_string_lossy().into_owned()),
        input: None,
    })
}

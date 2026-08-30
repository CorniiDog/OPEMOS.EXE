use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::utils::config::Color;
use tauri::{Emitter, Manager};

const READY_MARKER: &str = "SteamOS NVIDIA Image Builder appliance\nREADY";
const BOOT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Serialize)]
struct ImageInfo {
    path: String,
    name: String,
}

#[derive(Serialize)]
struct BuilderEnvironment {
    ready: bool,
    host_os: String,
    host_arch: String,
    qemu_binary: Option<String>,
    qemu_version: Option<String>,
    qemu_launch_test: bool,
    message: String,
    appliance_present: bool,
    appliance_path: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplianceStatus {
    state: String,
    message: String,
    ssh_port: Option<u16>,
    runtime_path: Option<String>,
    input: Option<InputPreparation>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InputPreparation {
    source_format: String,
    normalizer: String,
    normalized: bool,
    source_bytes: u64,
    image_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GuestHealth {
    protocol_version: String,
    hostname: String,
    architecture: String,
    operating_system: String,
    available_bytes: u64,
    required_tools: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferProof {
    bytes_verified: usize,
    guest_sha256: String,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SyntheticDiskInspection {
    device: String,
    disk_bytes: u64,
    read_only: bool,
    partition_table: String,
    partition: String,
    partition_start_bytes: u64,
    partition_bytes: u64,
    filesystem: String,
    filesystem_label: String,
    filesystem_uuid: String,
    mounted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MarkerMutation {
    marker_path: String,
    marker_content: String,
    source_sha256_before: String,
    source_sha256_after: String,
    working_sha256: String,
    source_unchanged: bool,
    working_read_only: bool,
    mounted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImageNodeInspection {
    path: String,
    node_type: String,
    size_bytes: u64,
    start_bytes: Option<u64>,
    filesystem: Option<String>,
    filesystem_label: Option<String>,
    partition_label: Option<String>,
    partition_type: Option<String>,
    partition_uuid: Option<String>,
    filesystem_uuid: Option<String>,
    mounted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserImageInspection {
    device: String,
    disk_bytes: u64,
    read_only: bool,
    partition_table: Option<String>,
    nodes: Vec<ImageNodeInspection>,
    source_sha256_before: String,
    source_sha256_after: String,
    source_unchanged: bool,
    image_sha256_before: String,
    image_sha256_after: String,
    image_unchanged: bool,
    input: InputPreparation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkingImageVerification {
    source_device: String,
    working_device: String,
    source_bytes: u64,
    working_bytes: u64,
    source_read_only: bool,
    working_read_only: bool,
    source_mounted: bool,
    working_mounted: bool,
    source_partition_table: Option<String>,
    working_partition_table: Option<String>,
    layout_matches: bool,
    overlay_format: String,
}

#[derive(Deserialize)]
struct LsblkResponse {
    blockdevices: Vec<LsblkNode>,
}

#[derive(Deserialize)]
struct LsblkNode {
    path: String,
    #[serde(rename = "type")]
    node_type: String,
    size: u64,
    start: Option<u64>,
    fstype: Option<String>,
    label: Option<String>,
    partlabel: Option<String>,
    parttype: Option<String>,
    partuuid: Option<String>,
    uuid: Option<String>,
    mountpoints: Option<Vec<Option<String>>>,
    children: Option<Vec<LsblkNode>>,
}

struct ApplianceSession {
    child: Child,
    runtime_dir: PathBuf,
    ssh_key: PathBuf,
    ssh_port: u16,
    started_at: Instant,
    state: String,
    message: String,
    input_image: PathBuf,
    input_sha256_before: String,
    attached_image: PathBuf,
    attached_sha256_before: String,
    working_image: PathBuf,
    input_preparation: InputPreparation,
}

#[derive(Clone)]
struct ImageInspectionSession {
    ssh_key: PathBuf,
    ssh_port: u16,
    input_image: PathBuf,
    input_sha256_before: String,
    attached_image: PathBuf,
    attached_sha256_before: String,
    input_preparation: InputPreparation,
}

impl From<&ApplianceSession> for ImageInspectionSession {
    fn from(session: &ApplianceSession) -> Self {
        Self {
            ssh_key: session.ssh_key.clone(),
            ssh_port: session.ssh_port,
            input_image: session.input_image.clone(),
            input_sha256_before: session.input_sha256_before.clone(),
            attached_image: session.attached_image.clone(),
            attached_sha256_before: session.attached_sha256_before.clone(),
            input_preparation: session.input_preparation.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputFormat {
    Raw,
    Bzip2,
    Gzip,
    Xz,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InputProgress {
    stage: String,
    processed_bytes: u64,
    total_bytes: u64,
}

type ProgressCallback<'a> = dyn Fn(&str, u64, u64) + 'a;

struct ReportingReader<'a> {
    inner: File,
    stage: &'static str,
    processed: u64,
    total: u64,
    next_report: u64,
    progress: Option<&'a ProgressCallback<'a>>,
    cancel: Option<&'a AtomicBool>,
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
            self.next_report = self.processed.saturating_add(8 * 1024 * 1024);
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

struct RuntimeGuard {
    path: PathBuf,
    armed: bool,
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        if self.armed && self.path.is_dir() {
            let _ = archive_and_remove_runtime(&self.path);
        }
    }
}

impl Drop for ApplianceSession {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if self.runtime_dir.is_dir() {
            let _ = archive_and_remove_runtime(&self.runtime_dir);
        }
    }
}

struct ApplianceManager {
    session: Option<ApplianceSession>,
    preparing: bool,
    cancel_preparation: Arc<AtomicBool>,
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

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri should have a repository parent")
        .to_path_buf()
}

fn appliance_dir() -> PathBuf {
    repository_root().join("builder/appliance")
}
fn appliance_path() -> PathBuf {
    appliance_dir().join("fedora-builder.qcow2")
}

fn runtime_root() -> PathBuf {
    appliance_dir().join("runtime")
}

fn process_is_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn archive_and_remove_runtime(runtime_dir: &Path) -> Result<Option<PathBuf>, String> {
    let log_source = runtime_dir.join("qemu.log");
    let archive = if log_source.is_file() {
        let archive_dir = runtime_root().join("logs");
        fs::create_dir_all(&archive_dir)
            .map_err(|e| format!("Could not create the appliance log archive: {e}"))?;
        let session_name = runtime_dir
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unknown-session");
        let archive_path = archive_dir.join(format!("{session_name}.log"));
        fs::copy(&log_source, &archive_path)
            .map_err(|e| format!("Could not archive the appliance log: {e}"))?;
        Some(archive_path)
    } else {
        None
    };
    fs::remove_dir_all(runtime_dir)
        .map_err(|e| format!("Could not remove the disposable appliance runtime: {e}"))?;
    Ok(archive)
}

fn cleanup_abandoned_runtimes() -> Result<(), String> {
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

fn supported_image(path: &Path) -> bool {
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

fn qemu_binary_name() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "aarch64" => Ok("qemu-system-aarch64"),
        "x86_64" => Ok("qemu-system-x86_64"),
        arch => Err(format!("Unsupported host architecture: {arch}")),
    }
}

fn find_binary(binary: &str) -> Option<PathBuf> {
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

fn find_qemu() -> Option<PathBuf> {
    qemu_binary_name().ok().and_then(find_binary)
}

fn qemu_version(path: &Path) -> Option<String> {
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

fn smoke_test_qemu(path: &Path) -> Result<(), String> {
    let mut child = Command::new(path)
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
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not start QEMU: {e}"))?;
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
        Ok(())
    } else {
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

fn run_checked(command: &mut Command, description: &str) -> Result<(), String> {
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

fn homebrew_qemu_share() -> Result<PathBuf, String> {
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

fn allocate_ssh_port() -> Result<u16, String> {
    TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("Could not allocate a guest SSH port: {e}"))?
        .local_addr()
        .map(|address| address.port())
        .map_err(|e| format!("Could not inspect the guest SSH port: {e}"))
}

#[cfg(test)]
fn sha256_file(path: &Path) -> Result<String, String> {
    sha256_file_with_progress(path, "hashing", None, None)
}

fn sha256_file_with_progress(
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
    let mut next_report = 32 * 1024 * 1024;
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
            next_report = processed.saturating_add(32 * 1024 * 1024);
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn detect_input_format(path: &Path) -> Result<InputFormat, String> {
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

fn normalize_input(
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
    let mut writer = BufWriter::new(output_file);
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
        .and_then(|_| writer.get_ref().sync_all())
        .map_err(|e| format!("Could not finish the normalized image: {e}"))?;
    if copied == 0 {
        return Err("The compressed input produced an empty image.".into());
    }
    Ok(destination)
}

#[derive(Clone, Copy)]
enum ParallelBzip2Tool {
    SevenZip,
    Pbzip2,
}

fn normalize_bzip2_parallel(
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
        .map(|count| count.get().saturating_sub(1).max(1))
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
            progress("decompressing-output", output_bytes, 0);
        }
        thread::sleep(Duration::from_millis(150));
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
    if output_bytes == 0 {
        return Err("The compressed input produced an empty image.".into());
    }
    if let Some(progress) = progress {
        progress("decompressing-output", output_bytes, 0);
    }
    File::open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|e| format!("Could not finish the normalized image: {e}"))
}

fn prepare_session(
    input_image: Option<&Path>,
    progress: Option<&ProgressCallback<'_>>,
    cancel: Option<&AtomicBool>,
) -> Result<ApplianceSession, String> {
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
    let marker = "    lock_passwd: false\n";
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

    let mut child = Command::new(qemu)
        .args([
            "-name",
            "SteamOS NVIDIA Builder",
            "-machine",
            machine,
            "-cpu",
            "host",
            "-smp",
            "4",
            "-m",
            "4096",
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
        .args([
            "-device",
            "virtio-blk-pci,drive=user-input,serial=steamos-user-input",
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
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|e| format!("Could not start the Fedora builder appliance: {e}"))?;
    if let Err(error) = fs::write(runtime_dir.join("qemu.pid"), child.id().to_string()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "Could not record the appliance process ID: {error}"
        ));
    }

    runtime_guard.armed = false;
    Ok(ApplianceSession {
        child,
        runtime_dir,
        ssh_key,
        ssh_port,
        started_at: Instant::now(),
        state: "booting".into(),
        message: "Fedora builder appliance is booting.".into(),
        input_image,
        input_sha256_before,
        attached_image,
        attached_sha256_before,
        working_image,
        input_preparation,
    })
}

trait GuestConnection {
    fn ssh_key(&self) -> &Path;
    fn ssh_port(&self) -> u16;
}

impl GuestConnection for ApplianceSession {
    fn ssh_key(&self) -> &Path {
        &self.ssh_key
    }

    fn ssh_port(&self) -> u16 {
        self.ssh_port
    }
}

impl GuestConnection for ImageInspectionSession {
    fn ssh_key(&self) -> &Path {
        &self.ssh_key
    }

    fn ssh_port(&self) -> u16 {
        self.ssh_port
    }
}

fn ssh_command(session: &impl GuestConnection) -> Result<Command, String> {
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
            "builder@127.0.0.1",
        ]);
    Ok(command)
}

fn run_guest_command(session: &impl GuestConnection, command: &str) -> Result<String, String> {
    let output = ssh_command(session)?
        .arg(command)
        .output()
        .map_err(|e| format!("Could not run the structured guest command: {e}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if detail.is_empty() {
            format!("Guest command exited with {}.", output.status)
        } else {
            detail
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn handshake(session: &ApplianceSession) -> Result<String, String> {
    run_guest_command(session, "cat /etc/steamos-builder-ready")
}

fn collect_guest_health(session: &ApplianceSession) -> Result<GuestHealth, String> {
    const HEALTH_COMMAND: &str = r#"set -eu
test "$(cat /etc/steamos-builder-ready)" = "$(printf 'SteamOS NVIDIA Image Builder appliance\nREADY')"
printf 'PROTOCOL=1\n'
printf 'HOSTNAME=%s\n' "$(hostname)"
printf 'ARCH=%s\n' "$(uname -m)"
. /etc/os-release
printf 'OS=%s\n' "$PRETTY_NAME"
printf 'AVAILABLE=%s\n' "$(df -B1 --output=avail / | tail -n 1 | tr -d ' ')"
for tool in bash lsblk blkid findmnt mount umount sha256sum stat cp sync dd sfdisk mkfs.ext4 blockdev; do
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

fn scp_command(session: &ApplianceSession) -> Result<Command, String> {
    let scp = find_binary("scp").ok_or("scp is required for controlled guest file transfer.")?;
    let mut command = Command::new(scp);
    command
        .arg("-P")
        .arg(session.ssh_port.to_string())
        .arg("-i")
        .arg(&session.ssh_key)
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
        ]);
    Ok(command)
}

fn run_transfer_proof(session: &ApplianceSession) -> Result<TransferProof, String> {
    const PROBE: &[u8] = b"STEAMOS_BUILDER_TRANSFER_PROBE_V1\n";
    const GUEST_INPUT: &str = "/tmp/steamos-builder-transfer-probe.in";
    const GUEST_OUTPUT: &str = "/tmp/steamos-builder-transfer-probe.out";
    let host_input = session.runtime_dir.join("transfer-probe.in");
    let host_output = session.runtime_dir.join("transfer-probe.out");
    fs::write(&host_input, PROBE).map_err(|e| format!("Could not create transfer probe: {e}"))?;

    run_checked(
        scp_command(session)?
            .arg(&host_input)
            .arg(format!("builder@127.0.0.1:{GUEST_INPUT}")),
        "Could not copy the transfer probe into the guest",
    )?;
    let guest_sha256 = run_guest_command(
        session,
        "set -eu; sha256sum /tmp/steamos-builder-transfer-probe.in | cut -d ' ' -f 1; cp /tmp/steamos-builder-transfer-probe.in /tmp/steamos-builder-transfer-probe.out; sync",
    )?;
    run_checked(
        scp_command(session)?
            .arg(format!("builder@127.0.0.1:{GUEST_OUTPUT}"))
            .arg(&host_output),
        "Could not copy the transfer probe back from the guest",
    )?;
    let returned = fs::read(&host_output)
        .map_err(|e| format!("Could not read the returned transfer probe: {e}"))?;
    let _ = run_guest_command(
        session,
        "rm -f /tmp/steamos-builder-transfer-probe.in /tmp/steamos-builder-transfer-probe.out",
    );
    if returned != PROBE {
        return Err("Returned transfer probe did not match the original bytes.".into());
    }
    Ok(TransferProof {
        bytes_verified: returned.len(),
        guest_sha256,
        message: "Host-to-guest-to-host transfer verified byte-for-byte.".into(),
    })
}

fn inspect_synthetic_disk(session: &ApplianceSession) -> Result<SyntheticDiskInspection, String> {
    const INSPECT_COMMAND: &str = r#"set -eu
DEVICE=/dev/disk/by-id/virtio-steamos-synthetic
PART=/dev/disk/by-id/virtio-steamos-synthetic-part1
test -b "$DEVICE"
if findmnt -rn -S "$DEVICE" >/dev/null 2>&1 || findmnt -rn -S "$PART" >/dev/null 2>&1; then
  echo 'Synthetic test device was unexpectedly mounted.' >&2
  exit 1
fi
sudo blockdev --setrw "$DEVICE"
printf 'label: dos\nunit: sectors\n\n2048,98304,83,*\n' | sudo sfdisk --wipe always "$DEVICE" >/dev/null
for attempt in $(seq 1 20); do
  test -b "$PART" && break
  sleep 0.1
done
test -b "$PART"
sudo mkfs.ext4 -q -F -L STEAMOS_TEST -U 11111111-2222-3333-4444-555555555555 "$PART"
sync
sudo blockdev --setro "$DEVICE"
DISK_NODE=$(basename "$(readlink -f "$DEVICE")")
PART_NODE=$(basename "$(readlink -f "$PART")")
START_SECTORS=$(cat "/sys/class/block/$PART_NODE/start")
MOUNTED=0
findmnt -rn -S "$PART" >/dev/null 2>&1 && MOUNTED=1
printf 'DEVICE=%s\n' "$DEVICE"
printf 'DISK_BYTES=%s\n' "$(sudo blockdev --getsize64 "$DEVICE")"
printf 'READ_ONLY=%s\n' "$(sudo blockdev --getro "$DEVICE")"
printf 'PARTITION_TABLE=%s\n' "$(sudo blkid -p -s PTTYPE -o value "$DEVICE")"
printf 'PARTITION=%s\n' "$PART"
printf 'PARTITION_START_BYTES=%s\n' "$((START_SECTORS * 512))"
printf 'PARTITION_BYTES=%s\n' "$(sudo blockdev --getsize64 "$PART")"
printf 'FILESYSTEM=%s\n' "$(sudo blkid -s TYPE -o value "$PART")"
printf 'FILESYSTEM_LABEL=%s\n' "$(sudo blkid -s LABEL -o value "$PART")"
printf 'FILESYSTEM_UUID=%s\n' "$(sudo blkid -s UUID -o value "$PART")"
printf 'MOUNTED=%s\n' "$MOUNTED"
test "$(sudo blockdev --getro "$DEVICE")" = 1
test "$MOUNTED" = 0
test -n "$DISK_NODE""#;
    let output = run_guest_command(session, INSPECT_COMMAND)?;
    let mut values = std::collections::HashMap::new();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key, value);
        }
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("Synthetic disk inspection omitted {key}."))
    };
    let parse_u64 = |key: &str| -> Result<u64, String> {
        required(key)?
            .parse::<u64>()
            .map_err(|e| format!("Synthetic disk inspection returned invalid {key}: {e}"))
    };
    Ok(SyntheticDiskInspection {
        device: required("DEVICE")?.to_string(),
        disk_bytes: parse_u64("DISK_BYTES")?,
        read_only: required("READ_ONLY")? == "1",
        partition_table: required("PARTITION_TABLE")?.to_string(),
        partition: required("PARTITION")?.to_string(),
        partition_start_bytes: parse_u64("PARTITION_START_BYTES")?,
        partition_bytes: parse_u64("PARTITION_BYTES")?,
        filesystem: required("FILESYSTEM")?.to_string(),
        filesystem_label: required("FILESYSTEM_LABEL")?.to_string(),
        filesystem_uuid: required("FILESYSTEM_UUID")?.to_string(),
        mounted: required("MOUNTED")? == "1",
    })
}

fn append_image_nodes(
    node: LsblkNode,
    logical_sector_bytes: u64,
    nodes: &mut Vec<ImageNodeInspection>,
) {
    let mounted = node
        .mountpoints
        .as_ref()
        .is_some_and(|mountpoints| mountpoints.iter().flatten().any(|value| !value.is_empty()));
    nodes.push(ImageNodeInspection {
        path: node.path,
        node_type: node.node_type,
        size_bytes: node.size,
        start_bytes: node
            .start
            .and_then(|start| start.checked_mul(logical_sector_bytes)),
        filesystem: node.fstype,
        filesystem_label: node.label,
        partition_label: node.partlabel,
        partition_type: node.parttype,
        partition_uuid: node.partuuid,
        filesystem_uuid: node.uuid,
        mounted,
    });
    for child in node.children.unwrap_or_default() {
        append_image_nodes(child, logical_sector_bytes, nodes);
    }
}

fn inspect_user_image(
    session: &ImageInspectionSession,
    progress: Option<&ProgressCallback<'_>>,
    cancel: Option<&AtomicBool>,
) -> Result<UserImageInspection, String> {
    const DEVICE: &str = "/dev/disk/by-id/virtio-steamos-user-input";
    let read_only = run_guest_command(
        session,
        "set -eu; DEVICE=/dev/disk/by-id/virtio-steamos-user-input; test -b \"$DEVICE\"; sudo blockdev --getro \"$DEVICE\"",
    )? == "1";
    if !read_only {
        return Err("Selected image was not attached read-only; inspection was stopped.".into());
    }
    let parse_device_number = |command: &str, description: &str| -> Result<u64, String> {
        run_guest_command(session, command)?
            .parse::<u64>()
            .map_err(|e| {
                format!("Selected image inspection returned an invalid {description}: {e}")
            })
    };
    let disk_bytes = parse_device_number(
        "set -eu; DEVICE=/dev/disk/by-id/virtio-steamos-user-input; sudo blockdev --getsize64 \"$DEVICE\"",
        "disk size",
    )?;
    let logical_sector_bytes = parse_device_number(
        "set -eu; DEVICE=/dev/disk/by-id/virtio-steamos-user-input; sudo blockdev --getss \"$DEVICE\"",
        "logical sector size",
    )?;
    let partition_table = run_guest_command(
        session,
        "DEVICE=/dev/disk/by-id/virtio-steamos-user-input; sudo blkid -p -s PTTYPE -o value \"$DEVICE\" 2>/dev/null || true",
    )?;
    let json = run_guest_command(
        session,
        "set -eu; DEVICE=/dev/disk/by-id/virtio-steamos-user-input; sudo lsblk --json --bytes --output PATH,TYPE,SIZE,START,FSTYPE,LABEL,PARTLABEL,PARTTYPE,PARTUUID,UUID,MOUNTPOINTS \"$DEVICE\"",
    )?;
    let response: LsblkResponse = serde_json::from_str(&json)
        .map_err(|e| format!("Could not parse selected image layout from the guest: {e}"))?;
    let mut nodes = Vec::new();
    for node in response.blockdevices {
        append_image_nodes(node, logical_sector_bytes, &mut nodes);
    }
    if nodes.is_empty() {
        return Err("Selected image inspection returned no block devices.".into());
    }
    if let Some(node) = nodes.iter().find(|node| node.mounted) {
        return Err(format!(
            "Selected image node {} was unexpectedly mounted; inspection was stopped.",
            node.path
        ));
    }
    let source_sha256_after = sha256_file_with_progress(
        &session.input_image,
        "verifying-source-after",
        progress,
        cancel,
    )?;
    let source_unchanged = session.input_sha256_before == source_sha256_after;
    if !source_unchanged {
        return Err(format!(
            "Selected image changed during read-only inspection (before {}, after {}).",
            session.input_sha256_before, source_sha256_after
        ));
    }
    let image_sha256_after = if session.attached_image == session.input_image {
        source_sha256_after.clone()
    } else {
        sha256_file_with_progress(
            &session.attached_image,
            "verifying-image-after",
            progress,
            cancel,
        )?
    };
    let image_unchanged = session.attached_sha256_before == image_sha256_after;
    if !image_unchanged {
        return Err(format!(
            "Normalized image changed during read-only inspection (before {}, after {}).",
            session.attached_sha256_before, image_sha256_after
        ));
    }
    Ok(UserImageInspection {
        device: DEVICE.into(),
        disk_bytes,
        read_only,
        partition_table: (!partition_table.is_empty()).then_some(partition_table),
        nodes,
        source_sha256_before: session.input_sha256_before.clone(),
        source_sha256_after,
        source_unchanged,
        image_sha256_before: session.attached_sha256_before.clone(),
        image_sha256_after,
        image_unchanged,
        input: session.input_preparation.clone(),
    })
}

fn verify_user_working_image(
    session: &ApplianceSession,
) -> Result<WorkingImageVerification, String> {
    const SOURCE: &str = "/dev/disk/by-id/virtio-steamos-user-input";
    const WORKING: &str = "/dev/disk/by-id/virtio-steamos-user-working";
    const VERIFY_COMMAND: &str = r#"set -eu
SOURCE=/dev/disk/by-id/virtio-steamos-user-input
WORKING=/dev/disk/by-id/virtio-steamos-user-working
test -b "$SOURCE"
test -b "$WORKING"
SOURCE_MOUNTED=0
WORKING_MOUNTED=0
lsblk -nr -o MOUNTPOINTS "$SOURCE" | grep -q '[^[:space:]]' && SOURCE_MOUNTED=1 || true
lsblk -nr -o MOUNTPOINTS "$WORKING" | grep -q '[^[:space:]]' && WORKING_MOUNTED=1 || true
printf 'SOURCE_BYTES=%s\n' "$(sudo blockdev --getsize64 "$SOURCE")"
printf 'WORKING_BYTES=%s\n' "$(sudo blockdev --getsize64 "$WORKING")"
printf 'SOURCE_READ_ONLY=%s\n' "$(sudo blockdev --getro "$SOURCE")"
printf 'WORKING_READ_ONLY=%s\n' "$(sudo blockdev --getro "$WORKING")"
printf 'SOURCE_MOUNTED=%s\n' "$SOURCE_MOUNTED"
printf 'WORKING_MOUNTED=%s\n' "$WORKING_MOUNTED"
printf 'SOURCE_PARTITION_TABLE=%s\n' "$(sudo blkid -p -s PTTYPE -o value "$SOURCE" 2>/dev/null || true)"
printf 'WORKING_PARTITION_TABLE=%s\n' "$(sudo blkid -p -s PTTYPE -o value "$WORKING" 2>/dev/null || true)"
test "$(sudo blockdev --getro "$SOURCE")" = 1
test "$(sudo blockdev --getro "$WORKING")" = 0
test "$(sudo blockdev --getsize64 "$SOURCE")" = "$(sudo blockdev --getsize64 "$WORKING")"
test "$SOURCE_MOUNTED" = 0
test "$WORKING_MOUNTED" = 0"#;
    let output = run_guest_command(session, VERIFY_COMMAND)?;
    let mut values = std::collections::HashMap::new();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key, value);
        }
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| format!("Working-image verification omitted {key}."))
    };
    let parse_u64 = |key: &str| -> Result<u64, String> {
        required(key)?
            .parse::<u64>()
            .map_err(|e| format!("Working-image verification returned invalid {key}: {e}"))
    };
    let source_bytes = parse_u64("SOURCE_BYTES")?;
    let working_bytes = parse_u64("WORKING_BYTES")?;
    let source_partition_table = required("SOURCE_PARTITION_TABLE")?;
    let working_partition_table = required("WORKING_PARTITION_TABLE")?;
    let layout_matches =
        source_bytes == working_bytes && source_partition_table == working_partition_table;
    if !layout_matches {
        return Err("The disposable working layer does not match the source image layout.".into());
    }
    Ok(WorkingImageVerification {
        source_device: SOURCE.into(),
        working_device: WORKING.into(),
        source_bytes,
        working_bytes,
        source_read_only: required("SOURCE_READ_ONLY")? == "1",
        working_read_only: required("WORKING_READ_ONLY")? == "1",
        source_mounted: required("SOURCE_MOUNTED")? == "1",
        working_mounted: required("WORKING_MOUNTED")? == "1",
        source_partition_table: (!source_partition_table.is_empty())
            .then(|| source_partition_table.to_string()),
        working_partition_table: (!working_partition_table.is_empty())
            .then(|| working_partition_table.to_string()),
        layout_matches,
        overlay_format: "qcow2".into(),
    })
}

fn mutate_synthetic_marker(session: &ApplianceSession) -> Result<MarkerMutation, String> {
    const MARKER_PATH: &str = "/etc/steamos-nvidia-image-builder-test";
    const MARKER_CONTENT: &str = "SteamOS NVIDIA Image Builder synthetic marker\nprotocol=1\n";
    const MUTATE_COMMAND: &str = r#"set -eu
SOURCE=/dev/disk/by-id/virtio-steamos-synthetic
WORK=/dev/disk/by-id/virtio-steamos-working
WORK_PART=/dev/disk/by-id/virtio-steamos-working-part1
MOUNT_DIR=/mnt/steamos-builder-marker
EXPECTED=$(printf 'SteamOS NVIDIA Image Builder synthetic marker\nprotocol=1')
test -b "$SOURCE"
test -b "$WORK"
test "$(sudo blockdev --getro "$SOURCE")" = 1
SOURCE_BEFORE=$(sudo sha256sum "$SOURCE" | cut -d ' ' -f 1)
sudo blockdev --setrw "$WORK"
sudo dd if="$SOURCE" of="$WORK" bs=4M conv=fsync status=none
sudo blockdev --rereadpt "$WORK"
for attempt in $(seq 1 20); do
  test -b "$WORK_PART" && break
  sleep 0.1
done
test -b "$WORK_PART"
sudo mkdir -p "$MOUNT_DIR"
cleanup_mount() {
  findmnt -rn -M "$MOUNT_DIR" >/dev/null 2>&1 && sudo umount "$MOUNT_DIR" || true
}
trap cleanup_mount EXIT
sudo mount -o rw "$WORK_PART" "$MOUNT_DIR"
sudo mkdir -p "$MOUNT_DIR/etc"
printf 'SteamOS NVIDIA Image Builder synthetic marker\nprotocol=1\n' | sudo tee "$MOUNT_DIR/etc/steamos-nvidia-image-builder-test" >/dev/null
sync
test "$(sudo cat "$MOUNT_DIR/etc/steamos-nvidia-image-builder-test")" = "$EXPECTED"
sudo umount "$MOUNT_DIR"
trap - EXIT
sudo blockdev --setro "$WORK"
SOURCE_AFTER=$(sudo sha256sum "$SOURCE" | cut -d ' ' -f 1)
WORKING_SHA=$(sudo sha256sum "$WORK" | cut -d ' ' -f 1)
MOUNTED=0
findmnt -rn -S "$WORK_PART" >/dev/null 2>&1 && MOUNTED=1
printf 'SOURCE_BEFORE=%s\n' "$SOURCE_BEFORE"
printf 'SOURCE_AFTER=%s\n' "$SOURCE_AFTER"
printf 'WORKING_SHA=%s\n' "$WORKING_SHA"
printf 'WORKING_READ_ONLY=%s\n' "$(sudo blockdev --getro "$WORK")"
printf 'MOUNTED=%s\n' "$MOUNTED"
test "$SOURCE_BEFORE" = "$SOURCE_AFTER"
test "$SOURCE_BEFORE" != "$WORKING_SHA"
test "$(sudo blockdev --getro "$WORK")" = 1
test "$MOUNTED" = 0"#;
    let output = run_guest_command(session, MUTATE_COMMAND)?;
    let mut values = std::collections::HashMap::new();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key, value);
        }
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("Synthetic marker mutation omitted {key}."))
    };
    let source_sha256_before = required("SOURCE_BEFORE")?.to_string();
    let source_sha256_after = required("SOURCE_AFTER")?.to_string();
    Ok(MarkerMutation {
        marker_path: MARKER_PATH.into(),
        marker_content: MARKER_CONTENT.into(),
        source_unchanged: source_sha256_before == source_sha256_after,
        source_sha256_before,
        source_sha256_after,
        working_sha256: required("WORKING_SHA")?.to_string(),
        working_read_only: required("WORKING_READ_ONLY")? == "1",
        mounted: required("MOUNTED")? == "1",
    })
}

fn session_status(session: &ApplianceSession) -> ApplianceStatus {
    ApplianceStatus {
        state: session.state.clone(),
        message: session.message.clone(),
        ssh_port: Some(session.ssh_port),
        runtime_path: Some(session.runtime_dir.to_string_lossy().into_owned()),
        input: Some(session.input_preparation.clone()),
    }
}

#[tauri::command]
fn check_builder_environment() -> BuilderEnvironment {
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
async fn start_appliance(path: String, app: tauri::AppHandle) -> Result<ApplianceStatus, String> {
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

fn start_appliance_blocking(
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
fn get_appliance_status(
    manager: tauri::State<'_, Mutex<ApplianceManager>>,
) -> Result<ApplianceStatus, String> {
    let mut manager = manager
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
        session.message =
            format!("Builder appliance exited unexpectedly with {exit}. See qemu.log for details.");
        return Ok(session_status(session));
    }
    if session.state == "booting" {
        match handshake(session) {
            Ok(output) if output == READY_MARKER => {
                session.state = "ready".into();
                session.message = "Builder appliance is ready.".into();
            }
            Ok(_) => {
                session.state = "failed".into();
                session.message = "Builder handshake returned an unexpected marker.".into();
            }
            Err(_) if session.started_at.elapsed() >= BOOT_TIMEOUT => {
                session.state = "timedOut".into();
                session.message =
                    "Builder appliance did not become ready within 120 seconds.".into();
            }
            Err(_) => {}
        }
    }
    Ok(session_status(session))
}

#[tauri::command]
fn read_appliance_log(
    manager: tauri::State<'_, Mutex<ApplianceManager>>,
) -> Result<String, String> {
    let log_path = {
        let manager = manager
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        let Some(session) = manager.session.as_ref() else {
            return Ok(String::new());
        };
        session.runtime_dir.join("qemu.log")
    };
    let bytes = fs::read(log_path).map_err(|e| format!("Could not read the appliance log: {e}"))?;
    const LOG_LIMIT: usize = 64 * 1024;
    let start = bytes.len().saturating_sub(LOG_LIMIT);
    Ok(String::from_utf8_lossy(&bytes[start..]).into_owned())
}

#[tauri::command]
fn guest_health(manager: tauri::State<'_, Mutex<ApplianceManager>>) -> Result<GuestHealth, String> {
    let manager = manager
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    let session = manager
        .session
        .as_ref()
        .ok_or("Builder appliance is not running.")?;
    if session.state != "ready" {
        return Err("Builder appliance is not ready for health checks.".into());
    }
    collect_guest_health(session)
}

#[tauri::command]
fn verify_guest_transfer(
    manager: tauri::State<'_, Mutex<ApplianceManager>>,
) -> Result<TransferProof, String> {
    let manager = manager
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    let session = manager
        .session
        .as_ref()
        .ok_or("Builder appliance is not running.")?;
    if session.state != "ready" {
        return Err("Builder appliance is not ready for file transfer.".into());
    }
    run_transfer_proof(session)
}

#[tauri::command]
fn inspect_test_disk(
    manager: tauri::State<'_, Mutex<ApplianceManager>>,
) -> Result<SyntheticDiskInspection, String> {
    let manager = manager
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    let session = manager
        .session
        .as_ref()
        .ok_or("Builder appliance is not running.")?;
    if session.state != "ready" {
        return Err("Builder appliance is not ready for synthetic disk inspection.".into());
    }
    inspect_synthetic_disk(session)
}

#[tauri::command]
async fn inspect_selected_image(app: tauri::AppHandle) -> Result<UserImageInspection, String> {
    tauri::async_runtime::spawn_blocking(move || inspect_selected_image_blocking(app))
        .await
        .map_err(|error| format!("Image inspection worker failed: {error}"))?
}

fn inspect_selected_image_blocking(app: tauri::AppHandle) -> Result<UserImageInspection, String> {
    let manager_state = app.state::<Mutex<ApplianceManager>>();
    let (session, cancel) = {
        let manager = manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        let session = manager
            .session
            .as_ref()
            .ok_or("Builder appliance is not running.")?;
        if session.state != "ready" {
            return Err("Builder appliance is not ready for selected image inspection.".into());
        }
        (
            ImageInspectionSession::from(session),
            manager.cancel_preparation.clone(),
        )
    };
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
fn verify_working_image(
    manager: tauri::State<'_, Mutex<ApplianceManager>>,
) -> Result<WorkingImageVerification, String> {
    let manager = manager
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    let session = manager
        .session
        .as_ref()
        .ok_or("Builder appliance is not running.")?;
    if session.state != "ready" {
        return Err("Builder appliance is not ready for working-image verification.".into());
    }
    if !session.working_image.is_file() {
        return Err("The disposable working image is unavailable.".into());
    }
    verify_user_working_image(session)
}

#[tauri::command]
fn mutate_test_marker(
    manager: tauri::State<'_, Mutex<ApplianceManager>>,
) -> Result<MarkerMutation, String> {
    let manager = manager
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    let session = manager
        .session
        .as_ref()
        .ok_or("Builder appliance is not running.")?;
    if session.state != "ready" {
        return Err("Builder appliance is not ready for synthetic marker mutation.".into());
    }
    mutate_synthetic_marker(session)
}

fn stop_session(session: &mut ApplianceSession) -> Result<Option<PathBuf>, String> {
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
    archive_and_remove_runtime(&session.runtime_dir)
}

#[tauri::command]
async fn stop_appliance(app: tauri::AppHandle) -> Result<ApplianceStatus, String> {
    tauri::async_runtime::spawn_blocking(move || stop_appliance_blocking(app))
        .await
        .map_err(|error| format!("Appliance shutdown worker failed: {error}"))?
}

fn stop_appliance_blocking(app: tauri::AppHandle) -> Result<ApplianceStatus, String> {
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

#[tauri::command]
fn validate_image(path: String) -> Result<ImageInfo, String> {
    let path = PathBuf::from(path);
    if !path.is_file() {
        return Err("The selected path is not a file.".into());
    }
    if !supported_image(&path) {
        return Err(
            "Select a SteamOS recovery image (.img, .img.bz2, .img.gz, or .img.xz).".into(),
        );
    }
    let canonical = fs::canonicalize(&path)
        .map_err(|e| format!("Could not resolve the selected image: {e}"))?;
    let name = canonical
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("Invalid image name")?
        .to_string();
    Ok(ImageInfo {
        path: canonical.to_string_lossy().into_owned(),
        name,
    })
}

#[tauri::command]
fn open_progress_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(progress) = app.get_webview_window("build-progress") {
        progress
            .show()
            .map_err(|e| format!("Could not show the build progress window: {e}"))?;
        progress
            .set_focus()
            .map_err(|e| format!("Could not focus the build progress window: {e}"))?;
        return Ok(());
    }
    let main = app
        .get_webview_window("main")
        .ok_or("The main application window is unavailable.")?;
    let progress = tauri::WebviewWindowBuilder::new(
        &app,
        "build-progress",
        tauri::WebviewUrl::App("build.html".into()),
    )
    .title("SteamOS NVIDIA Builder — Progress")
    .inner_size(680.0, 620.0)
    .min_inner_size(680.0, 620.0)
    .resizable(true)
    .theme(Some(tauri::Theme::Dark))
    .background_color(Color(13, 17, 23, 255))
    .visible(false)
    .parent(&main)
    .map_err(|e| format!("Could not couple the build progress window: {e}"))?
    .build()
    .map_err(|e| format!("Could not create the build progress window: {e}"))?;
    progress
        .show()
        .map_err(|e| format!("Could not show the build progress window: {e}"))?;
    progress
        .set_focus()
        .map_err(|e| format!("Could not focus the build progress window: {e}"))
}

#[tauri::command]
fn prototype_build(path: String) -> Result<String, String> {
    let input = PathBuf::from(path);
    if !input.is_file() || !supported_image(&input) {
        return Err("The selected SteamOS image is no longer available or supported.".into());
    }
    let output = input
        .parent()
        .ok_or("Could not determine input folder")?
        .join("SteamOS-NVIDIA-PROTOTYPE.txt");
    fs::write(&output, format!("SteamOS NVIDIA Image Builder prototype\n\nInput image:\n{}\n\nThis is not a bootable image.\n", input.display())).map_err(|e| format!("Could not create prototype output: {e}"))?;
    #[cfg(target_os = "macos")]
    Command::new("open")
        .arg("-R")
        .arg(&output)
        .spawn()
        .map_err(|e| format!("Created output but Finder reveal failed: {e}"))?;
    Ok(output.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_supported_recovery_image_names() {
        for name in [
            "recovery.img",
            "recovery.img.bz2",
            "recovery.img.gz",
            "recovery.img.xz",
        ] {
            assert!(
                supported_image(Path::new(name)),
                "{name} should be supported"
            );
        }
        for name in ["recovery.iso", "recovery.bz2", "recovery.img.zip"] {
            assert!(
                !supported_image(Path::new(name)),
                "{name} should be rejected"
            );
        }
    }

    #[test]
    fn normalization_detects_content_and_is_idempotent_for_raw_images() {
        const PAYLOAD: &[u8] = b"SteamOS image normalization fixture\n";
        let root = std::env::temp_dir().join(format!(
            "steamos-builder-normalization-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("create normalization test directory");

        let raw = root.join("raw.img");
        fs::write(&raw, PAYLOAD).expect("write raw fixture");
        assert_eq!(detect_input_format(&raw).unwrap(), InputFormat::Raw);
        assert_eq!(
            normalize_input(&raw, &root, InputFormat::Raw, None, None).unwrap(),
            raw
        );

        let bzip_source = root.join("compressed-but-named.img");
        let mut bzip = bzip2::write::BzEncoder::new(
            File::create(&bzip_source).expect("create bzip fixture"),
            bzip2::Compression::best(),
        );
        bzip.write_all(PAYLOAD).expect("compress bzip fixture");
        bzip.finish().expect("finish bzip fixture");
        assert_eq!(
            detect_input_format(&bzip_source).unwrap(),
            InputFormat::Bzip2
        );
        let bzip_runtime = root.join("bzip-runtime");
        fs::create_dir(&bzip_runtime).unwrap();
        let reports = Mutex::new(Vec::new());
        let report = |stage: &str, processed: u64, total: u64| {
            reports
                .lock()
                .unwrap()
                .push((stage.to_string(), processed, total));
        };
        let bzip_image = normalize_input(
            &bzip_source,
            &bzip_runtime,
            InputFormat::Bzip2,
            Some(&report),
            None,
        )
        .expect("normalize bzip fixture");
        assert_eq!(fs::read(bzip_image).unwrap(), PAYLOAD);
        let reports = reports.into_inner().unwrap();
        assert!(!reports.is_empty());
        let final_report = reports.last().unwrap();
        assert!(matches!(
            final_report.0.as_str(),
            "decompressing" | "decompressing-output"
        ));
        assert!(final_report.1 > 0);
        if final_report.2 > 0 {
            assert_eq!(final_report.1, final_report.2);
        }

        let cancelled_runtime = root.join("cancelled-runtime");
        fs::create_dir(&cancelled_runtime).unwrap();
        let cancellation = AtomicBool::new(true);
        let error = normalize_input(
            &bzip_source,
            &cancelled_runtime,
            InputFormat::Bzip2,
            None,
            Some(&cancellation),
        )
        .expect_err("cancelled normalization should stop");
        assert!(error.contains("cancelled"));

        let gzip_source = root.join("fixture.img.gz");
        let mut gzip = flate2::write::GzEncoder::new(
            File::create(&gzip_source).expect("create gzip fixture"),
            flate2::Compression::best(),
        );
        gzip.write_all(PAYLOAD).expect("compress gzip fixture");
        gzip.finish().expect("finish gzip fixture");
        assert_eq!(
            detect_input_format(&gzip_source).unwrap(),
            InputFormat::Gzip
        );
        let gzip_runtime = root.join("gzip-runtime");
        fs::create_dir(&gzip_runtime).unwrap();
        let gzip_image =
            normalize_input(&gzip_source, &gzip_runtime, InputFormat::Gzip, None, None)
                .expect("normalize gzip fixture");
        assert_eq!(fs::read(gzip_image).unwrap(), PAYLOAD);

        let xz_source = root.join("fixture.img.xz");
        let mut xz =
            xz2::write::XzEncoder::new(File::create(&xz_source).expect("create xz fixture"), 9);
        xz.write_all(PAYLOAD).expect("compress xz fixture");
        xz.finish().expect("finish xz fixture");
        assert_eq!(detect_input_format(&xz_source).unwrap(), InputFormat::Xz);
        let xz_runtime = root.join("xz-runtime");
        fs::create_dir(&xz_runtime).unwrap();
        let xz_image = normalize_input(&xz_source, &xz_runtime, InputFormat::Xz, None, None)
            .expect("normalize xz fixture");
        assert_eq!(fs::read(xz_image).unwrap(), PAYLOAD);

        fs::remove_dir_all(root).expect("remove normalization test directory");
    }

    #[test]
    #[ignore = "launches the local Fedora/QEMU appliance"]
    fn live_appliance_reaches_ready_marker() {
        let appliance = appliance_path();
        let appliance_sha256_before = sha256_file(&appliance).expect("hash appliance before");
        let input_root = std::env::temp_dir().join(format!(
            "steamos-builder-live-compressed-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        ));
        fs::create_dir_all(&input_root).expect("create live input directory");
        let raw_fixture = input_root.join("fixture.img");
        let mut raw_file = File::create(&raw_fixture).expect("create live raw fixture");
        raw_file.set_len(8 * 1024 * 1024).unwrap();
        let mut mbr = [0_u8; 512];
        mbr[446 + 4] = 0x83;
        mbr[446 + 8..446 + 12].copy_from_slice(&2048_u32.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&8192_u32.to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xaa;
        raw_file.write_all(&mbr).unwrap();
        raw_file.sync_all().unwrap();
        drop(raw_file);
        let compressed_fixture = input_root.join("fixture.img.bz2");
        let mut encoder = bzip2::write::BzEncoder::new(
            File::create(&compressed_fixture).expect("create live compressed fixture"),
            bzip2::Compression::best(),
        );
        let mut raw_file = File::open(&raw_fixture).unwrap();
        io::copy(&mut raw_file, &mut encoder).expect("compress live fixture");
        encoder.finish().expect("finish live compressed fixture");
        fs::remove_file(raw_fixture).expect("remove intermediate live raw fixture");
        let mut session = prepare_session(Some(&compressed_fixture), None, None)
            .expect("the appliance should start");
        assert!(session.input_preparation.normalized);
        assert_eq!(session.input_preparation.source_format, "bzip2");
        assert_eq!(session.input_preparation.image_bytes, 8 * 1024 * 1024);
        let deadline = Instant::now() + BOOT_TIMEOUT;
        loop {
            assert_eq!(
                session.child.try_wait().expect("QEMU status"),
                None,
                "QEMU exited before readiness"
            );
            if handshake(&session).as_deref() == Ok(READY_MARKER) {
                break;
            }
            assert!(Instant::now() < deadline, "guest handshake timed out");
            thread::sleep(Duration::from_secs(1));
        }
        let health = collect_guest_health(&session).expect("guest health should pass");
        assert_eq!(health.protocol_version, "1");
        assert!(!health.required_tools.is_empty());
        let transfer = run_transfer_proof(&session).expect("transfer proof should pass");
        assert_eq!(transfer.bytes_verified, 34);
        let disk = inspect_synthetic_disk(&session).expect("synthetic disk inspection should pass");
        assert_eq!(disk.disk_bytes, 64 * 1024 * 1024);
        assert!(disk.read_only);
        assert_eq!(disk.partition_table, "dos");
        assert_eq!(disk.partition_start_bytes, 1024 * 1024);
        assert_eq!(disk.partition_bytes, 48 * 1024 * 1024);
        assert_eq!(disk.filesystem, "ext4");
        assert_eq!(disk.filesystem_label, "STEAMOS_TEST");
        assert_eq!(disk.filesystem_uuid, "11111111-2222-3333-4444-555555555555");
        assert!(!disk.mounted);
        let mutation = mutate_synthetic_marker(&session)
            .expect("synthetic working-copy marker mutation should pass");
        assert!(mutation.source_unchanged);
        assert_eq!(mutation.source_sha256_before, mutation.source_sha256_after);
        assert_ne!(mutation.source_sha256_after, mutation.working_sha256);
        assert!(mutation.working_read_only);
        assert!(!mutation.mounted);
        assert_eq!(
            mutation.marker_path,
            "/etc/steamos-nvidia-image-builder-test"
        );
        let inspection_session = ImageInspectionSession::from(&session);
        let input = inspect_user_image(&inspection_session, None, None)
            .expect("user image inspection should pass");
        assert_eq!(input.disk_bytes, 8 * 1024 * 1024);
        assert!(input.read_only);
        assert!(input.source_unchanged);
        assert_eq!(input.source_sha256_before, input.source_sha256_after);
        assert_eq!(input.partition_table.as_deref(), Some("dos"));
        assert_eq!(input.nodes.len(), 2);
        assert!(input.nodes.iter().all(|node| !node.mounted));
        let partition = input
            .nodes
            .iter()
            .find(|node| node.node_type == "part")
            .expect("fixture partition should be discovered");
        assert_eq!(partition.start_bytes, Some(1024 * 1024));
        assert_eq!(partition.size_bytes, 4 * 1024 * 1024);
        let working = verify_user_working_image(&session)
            .expect("user working image verification should pass");
        assert_eq!(working.source_bytes, 8 * 1024 * 1024);
        assert_eq!(working.source_bytes, working.working_bytes);
        assert!(working.source_read_only);
        assert!(!working.working_read_only);
        assert!(!working.source_mounted);
        assert!(!working.working_mounted);
        assert!(working.layout_matches);
        assert_eq!(working.source_partition_table.as_deref(), Some("dos"));
        assert_eq!(working.working_partition_table.as_deref(), Some("dos"));
        assert_eq!(working.overlay_format, "qcow2");
        let runtime_dir = session.runtime_dir.clone();
        let archived_log = stop_session(&mut session)
            .expect("the ready appliance should stop and clean up")
            .expect("the QEMU log should be archived");
        assert!(
            !runtime_dir.exists(),
            "the disposable runtime should be removed"
        );
        assert!(
            archived_log.is_file(),
            "the archived QEMU log should remain"
        );
        assert_eq!(
            appliance_sha256_before,
            sha256_file(&appliance).expect("hash appliance after"),
            "the base appliance must remain unchanged"
        );
        fs::remove_dir_all(input_root).expect("remove live compressed input directory");
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .on_page_load(|webview, payload| {
            if webview.label() == "main"
                && payload.event() == tauri::webview::PageLoadEvent::Finished
            {
                let _ = webview.window().show();
            }
        })
        .manage(Mutex::new(ApplianceManager::default()))
        .setup(|_| {
            cleanup_abandoned_runtimes().map_err(std::io::Error::other)?;
            Ok(())
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            check_builder_environment,
            start_appliance,
            get_appliance_status,
            read_appliance_log,
            guest_health,
            verify_guest_transfer,
            inspect_test_disk,
            inspect_selected_image,
            verify_working_image,
            mutate_test_marker,
            stop_appliance,
            validate_image,
            open_progress_window,
            prototype_build
        ])
        .build(tauri::generate_context!())
        .expect("error while building SteamOS NVIDIA Image Builder");

    app.run(|app_handle, event| match event {
        tauri::RunEvent::WindowEvent {
            label,
            event: tauri::WindowEvent::CloseRequested { .. },
            ..
        } if label == "main" => {
            if let Ok(mut manager) = app_handle.state::<Mutex<ApplianceManager>>().lock() {
                manager.cancel_preparation.store(true, Ordering::Relaxed);
                if let Some(mut session) = manager.session.take() {
                    let _ = stop_session(&mut session);
                }
            }
            app_handle.exit(0);
        }
        tauri::RunEvent::ExitRequested { .. } => {
            if let Ok(mut manager) = app_handle.state::<Mutex<ApplianceManager>>().lock() {
                manager.cancel_preparation.store(true, Ordering::Relaxed);
                if let Some(mut session) = manager.session.take() {
                    let _ = stop_session(&mut session);
                }
            }
        }
        _ => {}
    });
}

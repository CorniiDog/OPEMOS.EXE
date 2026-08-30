use serde::Serialize;
use std::{
    fs::{self, File},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::Manager;

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

struct ApplianceSession {
    child: Child,
    runtime_dir: PathBuf,
    ssh_key: PathBuf,
    ssh_port: u16,
    started_at: Instant,
    state: String,
    message: String,
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

#[derive(Default)]
struct ApplianceManager {
    session: Option<ApplianceSession>,
}

impl Drop for ApplianceManager {
    fn drop(&mut self) {
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

fn prepare_session() -> Result<ApplianceSession, String> {
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
        Command::new(qemu_img)
            .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
            .arg(&appliance)
            .arg(&runtime_disk),
        "Could not create the disposable appliance overlay",
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

    Ok(ApplianceSession {
        child,
        runtime_dir,
        ssh_key,
        ssh_port,
        started_at: Instant::now(),
        state: "booting".into(),
        message: "Fedora builder appliance is booting.".into(),
    })
}

fn ssh_command(session: &ApplianceSession) -> Result<Command, String> {
    let ssh = find_binary("ssh").ok_or("ssh is required for the guest handshake.")?;
    let mut command = Command::new(ssh);
    command
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
        ]);
    Ok(command)
}

fn run_guest_command(session: &ApplianceSession, command: &str) -> Result<String, String> {
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
for tool in bash lsblk blkid findmnt mount umount sha256sum stat cp sync; do
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

fn session_status(session: &ApplianceSession) -> ApplianceStatus {
    ApplianceStatus {
        state: session.state.clone(),
        message: session.message.clone(),
        ssh_port: Some(session.ssh_port),
        runtime_path: Some(session.runtime_dir.to_string_lossy().into_owned()),
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
fn start_appliance(
    manager: tauri::State<'_, Mutex<ApplianceManager>>,
) -> Result<ApplianceStatus, String> {
    let mut manager = manager
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
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
    let session = prepare_session()?;
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
    let Some(session) = manager.session.as_mut() else {
        return Ok(ApplianceStatus {
            state: "stopped".into(),
            message: "Builder appliance is stopped.".into(),
            ssh_port: None,
            runtime_path: None,
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
    let manager = manager
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    let Some(session) = manager.session.as_ref() else {
        return Ok(String::new());
    };
    let bytes = fs::read(session.runtime_dir.join("qemu.log"))
        .map_err(|e| format!("Could not read the appliance log: {e}"))?;
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
fn stop_appliance(
    manager: tauri::State<'_, Mutex<ApplianceManager>>,
) -> Result<ApplianceStatus, String> {
    let mut manager = manager
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    let Some(mut session) = manager.session.take() else {
        return Ok(ApplianceStatus {
            state: "stopped".into(),
            message: "Builder appliance is stopped.".into(),
            ssh_port: None,
            runtime_path: None,
        });
    };
    let archived_log = stop_session(&mut session)?;
    Ok(ApplianceStatus {
        state: "stopped".into(),
        message: "Builder appliance stopped; disposable disk and credentials were removed.".into(),
        ssh_port: None,
        runtime_path: archived_log.map(|path| path.to_string_lossy().into_owned()),
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
    #[ignore = "launches the local Fedora/QEMU appliance"]
    fn live_appliance_reaches_ready_marker() {
        let mut session = prepare_session().expect("the appliance should start");
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
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
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
            stop_appliance,
            validate_image,
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
                if let Some(mut session) = manager.session.take() {
                    let _ = stop_session(&mut session);
                }
            }
            app_handle.exit(0);
        }
        tauri::RunEvent::ExitRequested { .. } => {
            if let Ok(mut manager) = app_handle.state::<Mutex<ApplianceManager>>().lock() {
                if let Some(mut session) = manager.session.take() {
                    let _ = stop_session(&mut session);
                }
            }
        }
        _ => {}
    });
}

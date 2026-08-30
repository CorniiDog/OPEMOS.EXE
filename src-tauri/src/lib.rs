use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

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

fn appliance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri should have a repository parent")
        .join("builder")
        .join("appliance")
        .join("fedora-builder.qcow2")
    }

fn supported_image(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    name.ends_with(".img")
        || name.ends_with(".img.bz2")
        || name.ends_with(".img.gz")
        || name.ends_with(".img.xz")
}

fn qemu_binary_name() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "qemu-system-aarch64",
        "x86_64" => "qemu-system-x86_64",
        _ => "qemu-system-aarch64",
    }
}

fn find_qemu() -> Option<PathBuf> {
    let binary = qemu_binary_name();

    if let Ok(path) = which_in_path(binary) {
        return Some(path);
    }

    let candidates = [
        PathBuf::from("/opt/homebrew/bin").join(binary),
        PathBuf::from("/usr/local/bin").join(binary),
    ];

    candidates.into_iter().find(|path| path.is_file())
}

fn which_in_path(binary: &str) -> Result<PathBuf, String> {
    let output = Command::new("which")
        .arg(binary)
        .output()
        .map_err(|e| format!("Could not search PATH: {e}"))?;

    if !output.status.success() {
        return Err(format!("{binary} was not found in PATH."));
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if path.is_empty() {
        return Err(format!("{binary} returned an empty path."));
    }

    Ok(PathBuf::from(path))
}

fn qemu_version(path: &Path) -> Option<String> {
    let output = Command::new(path).arg("--version").output().ok()?;

    if !output.status.success() {
        return None;
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .map(str::trim)
        .map(str::to_string)
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

    match child
        .try_wait()
        .map_err(|e| format!("Could not inspect QEMU process: {e}"))?
    {
        None => {
            child
                .kill()
                .map_err(|e| format!("QEMU started but could not be stopped: {e}"))?;

            child
                .wait()
                .map_err(|e| format!("Could not finish QEMU smoke test: {e}"))?;

            Ok(())
        }

        Some(status) => {
            let stderr = child
                .stderr
                .take()
                .and_then(|mut stderr| {
                    use std::io::Read;

                    let mut text = String::new();
                    stderr.read_to_string(&mut text).ok()?;

                    Some(text)
                })
                .unwrap_or_default();

            let stderr = stderr.trim();

            if stderr.is_empty() {
                Err(format!(
                    "QEMU exited unexpectedly during startup with status {status}."
                ))
            } else {
                Err(format!(
                    "QEMU exited unexpectedly during startup: {stderr}"
                ))
            }
        }
    }
}

#[tauri::command]
fn check_builder_environment() -> BuilderEnvironment {
    let host_os = std::env::consts::OS.to_string();
    let host_arch = std::env::consts::ARCH.to_string();

    let appliance = appliance_path();
    let appliance_present = appliance.is_file();
    let appliance_path = appliance.to_string_lossy().into_owned();

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
            message: format!(
                "{} is required before the builder appliance can run.",
                qemu_binary_name()
            ),
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
            message: "QEMU was found, but its version could not be determined.".to_string(),
        };
    }

    if let Err(error) = smoke_test_qemu(&qemu) {
        return BuilderEnvironment {
            ready: false,
            host_os,
            host_arch,
            qemu_binary: Some(qemu.to_string_lossy().into_owned()),
            qemu_version: version,
            qemu_launch_test: false,
            appliance_present,
            appliance_path,
            message: error,
        };
    }

    if !appliance_present {
        return BuilderEnvironment {
            ready: false,
            host_os,
            host_arch,
            qemu_binary: Some(qemu.to_string_lossy().into_owned()),
            qemu_version: version,
            qemu_launch_test: true,
            appliance_present: false,
            appliance_path,
            message: "QEMU is ready. Fedora builder appliance is missing.".to_string(),
        };
    }

    BuilderEnvironment {
        ready: true,
        host_os,
        host_arch,
        qemu_binary: Some(qemu.to_string_lossy().into_owned()),
        qemu_version: version,
        qemu_launch_test: true,
        appliance_present: true,
        appliance_path,
        message: "Builder environment is ready.".to_string(),
    }
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
        return Err(
            "The selected SteamOS image is no longer available or supported.".into(),
        );
    }

    let parent = input
        .parent()
        .ok_or("Could not determine input folder")?;

    let output = parent.join("SteamOS-NVIDIA-PROTOTYPE.txt");

    fs::write(
        &output,
        format!(
            concat!(
                "SteamOS NVIDIA Image Builder prototype\n",
                "\n",
                "Input image:\n",
                "{}\n",
                "\n",
                "This is not a bootable image.\n"
            ),
            input.display()
        ),
    )
    .map_err(|e| format!("Could not create prototype output: {e}"))?;

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg("-R")
            .arg(&output)
            .spawn()
            .map_err(|e| {
                format!("Created output but Finder reveal failed: {e}")
            })?;
    }

    Ok(output.to_string_lossy().into_owned())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            check_builder_environment,
            validate_image,
            prototype_build
        ])
        .run(tauri::generate_context!())
        .expect(
            "error while running SteamOS NVIDIA Image Builder",
        );
}
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, ChildStdout, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{Emitter, Manager};

mod app;
mod appliance;
mod compatibility_preview;
mod contracts;
// The persistent cache lifecycle is contract-agnostic and remains inactive
// until Core publishes the authenticated generation-discovery descriptor. Its
// durable host adapter is Unix-only until a reviewed Windows ACL/replace layer
// exists.
#[cfg(unix)]
#[allow(dead_code)]
mod core_generation_cache;
// Inactive, dependency-injected host acquisition. No production transport,
// trust root, command, or activation path is wired to this module.
#[cfg(unix)]
#[allow(dead_code)]
mod core_generation_acquisition;
// Closed policy/checkpoint parsing and fixture compatibility for Core's
// inactive bootstrap contract. No production authority or endpoint is wired.
#[cfg(unix)]
#[allow(dead_code)]
mod core_generation_bootstrap;
// Private sealed authentication capability and verifier-evidence contract for
// inactive generation planning. No production verifier or trust path is wired.
#[cfg(unix)]
#[allow(dead_code)]
mod core_generation_verifier;
// Closed request-plan compatibility derived from snapshot-bound evidence. No
// production verifier, network, command, cache, or UI path is wired.
#[cfg(unix)]
#[allow(dead_code)]
mod core_generation_request_plan;
// Closed parsing and compatibility coverage for Core-owned NVIDIA source
// authorization. Production selection remains on the legacy path until an
// authenticated Core generation carries this contract and equivalence passes.
#[allow(dead_code)]
mod core_source_intent;
// The migration adapter is exercised before activation. Its production entry
// points remain deliberately unused until Core publishes an immutable manifest.
#[allow(dead_code)]
mod core_contracts;
// Closed schema-1 parsing for Core's inactive reviewed-lock generation
// contract. This is intentionally disconnected from network discovery and
// activation until a production trust root and bootstrap checkpoint exist.
#[allow(dead_code)]
mod core_generation_contracts;
#[cfg(test)]
mod core_test_repository;
mod host_platform;
mod host_storage;
mod image;
mod installer;
mod maintainer_release;
mod nvidia;
#[cfg(unix)]
#[allow(dead_code)]
mod output_transaction;
mod portable_state;
mod runtime_bundle;
mod settings;
mod windows;
#[cfg(windows)]
mod windows_ssh;

pub use app::run;
use appliance::*;
use contracts::*;
use host_platform::*;
use host_storage::*;
use image::*;
use installer::*;
use maintainer_release::*;
use nvidia::*;
pub use portable_state::prepare_portable_state;
use portable_state::{portable_cache_root, portable_settings_path};
pub use runtime_bundle::activate_runtime_bundle;
use runtime_bundle::{bundled_runtime_binary, bundled_runtime_required};
use settings::*;

pub fn run_core_driver_resolver(arguments: &[String]) -> Result<Option<String>, String> {
    if arguments.first().map(String::as_str) != Some("resolve-core-driver") {
        return Ok(None);
    }
    let (mut steamos, mut kernel, mut architecture) = (None, None, None);
    let mut candidates = Vec::new();
    let mut index = 1;
    while index < arguments.len() {
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("Missing value for {}.", arguments[index]))?;
        match arguments[index].as_str() {
            "--steamos" if steamos.is_none() => steamos = Some(value.clone()),
            "--kernel" if kernel.is_none() => kernel = Some(value.clone()),
            "--architecture" if architecture.is_none() => architecture = Some(value.clone()),
            "--steamos" | "--kernel" | "--architecture" => {
                return Err(format!("Duplicate resolver option {}.", arguments[index]));
            }
            "--candidate-sha256" => {
                let path = arguments
                    .get(index + 2)
                    .ok_or("Missing candidate path after SHA-256.")?;
                let bytes = fs::read(path)
                    .map_err(|error| format!("Could not read Core candidate: {error}"))?;
                let observed = format!("{:x}", Sha256::digest(&bytes));
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    || observed != *value
                {
                    return Err(
                        "OPEMOS Core candidate does not match its authenticated SHA-256.".into(),
                    );
                }
                candidates.push(bytes);
                index += 1;
            }
            option => return Err(format!("Unsupported resolver option {option}.")),
        }
        index += 2;
    }
    let target = core_contracts::CoreResolverTarget {
        steamos_version: steamos.ok_or("Missing --steamos resolver target.")?,
        kernel_version: kernel.ok_or("Missing --kernel resolver target.")?,
        architecture: architecture.ok_or("Missing --architecture resolver target.")?,
    };
    serde_json::to_string(&core_contracts::select_core_driver_resolution(
        &target,
        &candidates,
    )?)
    .map(Some)
    .map_err(|error| format!("Could not encode selected Core driver resolution: {error}"))
}

#[cfg(target_os = "windows")]
pub fn run_windows_usb_writer_helper(arguments: &[String]) -> Result<Option<String>, String> {
    image::run_windows_usb_writer_helper(arguments)
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_usb_writer_helper(arguments: &[String]) -> Result<Option<String>, String> {
    image::run_windows_usb_writer_helper(arguments)
}

#[cfg(target_os = "windows")]
pub fn run_windows_virtual_usb_harness(arguments: &[String]) -> Result<Option<String>, String> {
    let command = arguments.first().map(String::as_str);
    if !matches!(
        command,
        Some("contained-virtual-usb")
            | Some("contained-virtual-usb-retain")
            | Some("contained-virtual-usb-cleanup")
    ) {
        return Ok(None);
    }
    if command == Some("contained-virtual-usb-cleanup") {
        if arguments.len() != 3 || arguments[1] != "--root" {
            return Err("Usage: contained-virtual-usb-cleanup --root ROOT.".into());
        }
        let root = PathBuf::from(&arguments[2]);
        let root = fs::canonicalize(&root)
            .map_err(|error| format!("Could not canonicalize the virtual-USB root: {error}"))?;
        let target = root.join("virtual-usb-32g.raw");
        cleanup_windows_virtual_usb(&root, &target)?;
        return serde_json::to_string(&serde_json::json!({
            "schemaVersion": 1, "status": "passed",
            "kind": "harness-owned-file-backed-virtual-usb-cleanup",
            "capacityBytes": WINDOWS_VIRTUAL_USB_BYTES,
            "cleaned": true, "physicalMedia": false
        }))
        .map(Some)
        .map_err(|error| format!("Could not encode virtual-USB cleanup evidence: {error}"));
    }
    if arguments.len() != 5 || arguments[1] != "--root" || arguments[3] != "--image" {
        return Err(format!(
            "Usage: {} --root ROOT --image IMAGE.",
            command.unwrap_or("contained-virtual-usb")
        ));
    }
    let root = PathBuf::from(&arguments[2]);
    let image = PathBuf::from(&arguments[4]);
    let target = fs::canonicalize(&root)
        .map_err(|error| format!("Could not canonicalize the virtual-USB root: {error}"))?
        .join("virtual-usb-32g.raw");
    let (image, image_bytes, image_sha256) = validate_usb_image_identity(
        image
            .to_str()
            .ok_or("The source image path is not valid UTF-8.")?,
    )?;
    let mut media = create_windows_virtual_usb(&root, &target)?;
    let cancel = AtomicBool::new(false);
    let result = copy_and_verify_usb_image(
        &image,
        &mut media,
        image_bytes,
        &image_sha256,
        &cancel,
        |_| {},
    );
    drop(media);
    let retain = command == Some("contained-virtual-usb-retain");
    let verified_sha256 = if retain {
        result?
    } else {
        let cleanup = cleanup_windows_virtual_usb(&root, &target);
        match (result, cleanup) {
            (Ok(sha256), Ok(())) => sha256,
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
            (Err(primary), Err(cleanup)) => {
                return Err(format!("{primary} Cleanup also failed: {cleanup}"));
            }
        }
    };
    if sha256_file(&image)? != image_sha256 || target.exists() == !retain {
        return Err("Contained virtual-USB cleanup or source preservation failed.".into());
    }
    serde_json::to_string(&serde_json::json!({
        "schemaVersion": 1, "status": "passed",
        "kind": "harness-owned-file-backed-virtual-usb",
        "capacityBytes": WINDOWS_VIRTUAL_USB_BYTES, "bytesWritten": image_bytes,
        "sourceSha256": image_sha256, "verifiedSha256": verified_sha256,
        "flushed": true, "cleaned": !retain, "retained": retain,
        "targetPath": if retain { Some(target.to_string_lossy().into_owned()) } else { None },
        "sourcePreserved": true,
        "physicalMedia": false
    }))
    .map(Some)
    .map_err(|error| format!("Could not encode virtual-USB evidence: {error}"))
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_virtual_usb_harness(arguments: &[String]) -> Result<Option<String>, String> {
    if matches!(
        arguments.first().map(String::as_str),
        Some("contained-virtual-usb")
            | Some("contained-virtual-usb-retain")
            | Some("contained-virtual-usb-cleanup")
    ) {
        return Err("The contained virtual-USB executable harness requires Windows.".into());
    }
    Ok(None)
}

#[derive(Debug, PartialEq, Eq)]
struct HeadlessImageBuildRequest {
    input: PathBuf,
    output_root: PathBuf,
}

fn parse_headless_image_build_request(
    arguments: &[String],
) -> Result<Option<HeadlessImageBuildRequest>, String> {
    if arguments.first().map(String::as_str) != Some("headless-build") {
        return Ok(None);
    }
    if arguments.len() != 5 || arguments[1] != "--input" || arguments[3] != "--output-root" {
        return Err(
            "Usage: headless-build --input IMAGE --output-root EMPTY_OWNED_DIRECTORY.".into(),
        );
    }
    Ok(Some(HeadlessImageBuildRequest {
        input: PathBuf::from(&arguments[2]),
        output_root: PathBuf::from(&arguments[4]),
    }))
}

#[cfg(target_os = "windows")]
fn validate_headless_build_paths(
    request: HeadlessImageBuildRequest,
) -> Result<HeadlessImageBuildRequest, String> {
    let input_metadata = fs::symlink_metadata(&request.input)
        .map_err(|error| format!("Could not inspect the headless-build input: {error}"))?;
    if input_metadata.file_type().is_symlink() || !input_metadata.is_file() {
        return Err("The headless-build input must be a non-linked regular file.".into());
    }
    let input = fs::canonicalize(&request.input)
        .map_err(|error| format!("Could not canonicalize the headless-build input: {error}"))?;

    let output_metadata = fs::symlink_metadata(&request.output_root)
        .map_err(|error| format!("Could not inspect the headless-build output root: {error}"))?;
    if output_metadata.file_type().is_symlink() || !output_metadata.is_dir() {
        return Err("The headless-build output root must be a non-linked directory.".into());
    }
    let output_root = fs::canonicalize(&request.output_root).map_err(|error| {
        format!("Could not canonicalize the headless-build output root: {error}")
    })?;
    if fs::read_dir(&output_root)
        .map_err(|error| format!("Could not inspect the headless-build output root: {error}"))?
        .next()
        .is_some()
    {
        return Err("The headless-build output root must be empty before construction.".into());
    }
    if input.starts_with(&output_root) || output_root == input {
        return Err("The headless-build input and output root must be separate.".into());
    }
    Ok(HeadlessImageBuildRequest { input, output_root })
}

#[cfg(target_os = "windows")]
struct HeadlessImageBuildCleanup(Option<tauri::AppHandle>);

#[cfg(target_os = "windows")]
impl Drop for HeadlessImageBuildCleanup {
    fn drop(&mut self) {
        if let Some(app) = self.0.take() {
            let _ = stop_appliance_blocking(app);
        }
    }
}

#[cfg(target_os = "windows")]
fn wait_for_headless_appliance(app: &tauri::AppHandle, nvidia: bool) -> Result<(), String> {
    let deadline = Instant::now()
        + if nvidia {
            NVIDIA_BUILD_BOOT_TIMEOUT + Duration::from_secs(60)
        } else {
            BOOT_TIMEOUT + Duration::from_secs(60)
        };
    loop {
        let (state, message) = if nvidia {
            let status =
                tauri::async_runtime::block_on(get_nvidia_build_appliance_status(app.clone()))?;
            (status.state, status.message)
        } else {
            let status = get_appliance_status_blocking(app.clone())?;
            (status.state, status.message)
        };
        match state.as_str() {
            "ready" => return Ok(()),
            "failed" | "timedOut" => return Err(message),
            _ if Instant::now() >= deadline => {
                return Err(
                    "The headless build appliance exceeded its bounded readiness deadline.".into(),
                )
            }
            _ => thread::sleep(Duration::from_millis(750)),
        }
    }
}

#[cfg(target_os = "windows")]
fn run_windows_headless_image_build(request: HeadlessImageBuildRequest) -> Result<String, String> {
    let request = validate_headless_build_paths(request)?;
    let input_sha256 = sha256_file(&request.input)?;
    let app = tauri::Builder::default()
        .any_thread()
        .manage(Mutex::new(ApplianceManager::default()))
        .manage(Mutex::new(NvidiaBuildManager::default()))
        .build(tauri::generate_context!())
        .map_err(|error| format!("Could not create the headless build runtime: {error}"))?;
    let app = app.handle().clone();
    let mut cleanup = HeadlessImageBuildCleanup(Some(app.clone()));

    start_appliance_blocking(
        request.input.to_string_lossy().into_owned(),
        Some(request.output_root.to_string_lossy().into_owned()),
        app.clone(),
    )?;
    wait_for_headless_appliance(&app, false)?;
    let inspection_deadline = Instant::now() + Duration::from_secs(60);
    let inspection = loop {
        match inspect_selected_image_blocking(app.clone()) {
            Err(error)
                if transient_guest_connection_error(&error)
                    && Instant::now() < inspection_deadline =>
            {
                thread::sleep(Duration::from_millis(250));
            }
            result => break result?,
        }
    };
    if !inspection.layout.recognized {
        return Err("The headless-build input is not a recognized SteamOS layout.".into());
    }
    tauri::async_runtime::block_on(verify_working_image(app.clone()))?;
    preflight_selected_marker_blocking(app.clone())?;
    let mutation = mutate_selected_marker_after_preflight_blocking(app.clone())?;
    if !mutation.input_unchanged {
        return Err(
            "The headless build could not prove that its source remained unchanged.".into(),
        );
    }
    let target = tauri::async_runtime::block_on(assess_nvidia_target(app.clone()))?;
    if !target.ready {
        return Err(format!(
            "The headless-build target is not installable: {}",
            target.message
        ));
    }

    let mut resolution = tauri::async_runtime::block_on(resolve_published_nvidia(
        app.clone(),
        Some("automatic".into()),
        Some(false),
    ))?;
    let mut nvidia_appliance_ready = false;
    if resolution.status == "build_required" {
        start_nvidia_install_appliance_blocking(app.clone())?;
        wait_for_headless_appliance(&app, true)?;
        nvidia_appliance_ready = true;
        resolution = tauri::async_runtime::block_on(build_nvidia_target_on_demand(app.clone()))?;
    }
    if resolution.status != "compatible" {
        return Err(format!(
            "No exact authenticated NVIDIA support is available: {}",
            resolution.message
        ));
    }
    tauri::async_runtime::block_on(prepare_nvidia_userspace(app.clone()))?;
    tauri::async_runtime::block_on(prepare_nvidia_installer_bundle(app.clone()))?;
    if !nvidia_appliance_ready {
        start_nvidia_install_appliance_blocking(app.clone())?;
        wait_for_headless_appliance(&app, true)?;
    }
    let validation = validate_nvidia_install_handoff_blocking(app.clone())?;
    if validation.status != "validated" || !validation.mounts_released {
        return Err("The headless-build installer handoff did not close-validate.".into());
    }
    let installed = install_nvidia_to_working_image_blocking(app.clone())?;
    if installed.status != "success" || !installed.mounts_released {
        return Err("The headless-build installer did not finish with released mounts.".into());
    }
    let exported = export_marker_image_blocking(app.clone(), false)?;
    if exported.source_sha256 != input_sha256 || sha256_file(&request.input)? != input_sha256 {
        return Err("The headless build could not prove final source immutability.".into());
    }
    let completed = completed_nvidia_image_from_path(&exported.path)?
        .ok_or("The headless build output omitted its authenticated adjacent manifest.")?;
    let stopped = stop_appliance_blocking(app.clone())?;
    if stopped.state != "stopped" {
        return Err("The headless build could not confirm appliance cleanup.".into());
    }
    cleanup.0 = None;
    serde_json::to_string(&serde_json::json!({
        "schemaVersion": 1,
        "status": "passed",
        "kind": "headless-authenticated-nvidia-image-build",
        "sourceSha256": input_sha256,
        "output": completed.output,
        "physicalMedia": false,
        "published": false,
        "cleanupComplete": true
    }))
    .map_err(|error| format!("Could not encode headless-build evidence: {error}"))
}

#[cfg(target_os = "windows")]
pub fn run_windows_headless_image_builder(arguments: &[String]) -> Result<Option<String>, String> {
    let Some(request) = parse_headless_image_build_request(arguments)? else {
        return Ok(None);
    };
    run_windows_headless_image_build(request).map(Some)
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_headless_image_builder(arguments: &[String]) -> Result<Option<String>, String> {
    if parse_headless_image_build_request(arguments)?.is_some() {
        return Err("The headless authenticated image builder requires Windows.".into());
    }
    Ok(None)
}

const READY_MARKER: &str = "SteamOS NVIDIA Image Builder appliance\nREADY";
#[cfg(target_os = "windows")]
const BOOT_TIMEOUT: Duration = Duration::from_secs(300);
#[cfg(not(target_os = "windows"))]
const BOOT_TIMEOUT: Duration = Duration::from_secs(120);
const TCG_HARNESS_BOOT_TIMEOUT_SECS: u64 = 1200;
#[cfg(all(test, target_os = "linux"))]
const TCG_HARNESS_OUTER_TIMEOUT_SECS: u64 = 1260;
const NVIDIA_BUILD_BOOT_TIMEOUT: Duration = Duration::from_secs(600);
const NVIDIA_RELEASES_API: &str =
    "https://api.github.com/repos/CorniiDog/OPEMOS/releases?per_page=100";
const NVIDIA_RELEASE_REPOSITORY: &str = "CorniiDog/OPEMOS";
const NVIDIA_SOURCE_BRANCHES_API: &str =
    "https://api.github.com/repos/CorniiDog/open-gpu-kernel-modules-steamos/branches?per_page=100";
const NVIDIA_SOURCE_REPOSITORY: &str = "CorniiDog/open-gpu-kernel-modules-steamos";
const NVIDIA_UPSTREAM_TAGS_API: &str =
    "https://api.github.com/repos/NVIDIA/open-gpu-kernel-modules/tags?per_page=100";
const NVIDIA_UPSTREAM_REPOSITORY: &str = "NVIDIA/open-gpu-kernel-modules";
const GAMESCOPE_SOURCE_BRANCHES_API: &str =
    "https://api.github.com/repos/CorniiDog/gamescope-nvidia/branches?per_page=100";
const GAMESCOPE_SOURCE_REPOSITORY: &str = "CorniiDog/gamescope-nvidia";
const GAMESCOPE_UPSTREAM_TAGS_API: &str =
    "https://api.github.com/repos/ValveSoftware/gamescope/tags?per_page=100";
const GAMESCOPE_UPSTREAM_REPOSITORY: &str = "ValveSoftware/gamescope";
const NVIDIA_RESOLVER_SCHEMA: u32 = 2;
const BUILDER_SETTINGS_SCHEMA: u32 = 4;
const APPROVED_VALVE_SIGNER: &str = "889B5EBDDD505A683621900DAF1D2199EF0A3CCF";
const RELEASES_RESPONSE_LIMIT: u64 = 4 * 1024 * 1024;
const CHECKSUM_RESPONSE_LIMIT: u64 = 4 * 1024;
const PROVENANCE_RESPONSE_LIMIT: u64 = 1024 * 1024;
const NVIDIA_ARCHIVE_LIMIT: u64 = 1024 * 1024 * 1024;
const NVIDIA_ARCHIVE_MEMBER_LIMIT: u64 = 1024 * 1024 * 1024;
const NVIDIA_ARCHIVE_EXPANDED_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const NVIDIA_HANDOFF_FREE_SPACE_RESERVE: u64 = 512 * 1024 * 1024;
const HOST_RUNTIME_FREE_SPACE_RESERVE: u64 = 4 * 1024 * 1024 * 1024;
const HOST_OUTPUT_FREE_SPACE_RESERVE: u64 = 64 * 1024 * 1024;
const _: () = assert!(NVIDIA_ARCHIVE_LIMIT >= 700 * 1024 * 1024);
const _: () = assert!(NVIDIA_ARCHIVE_LIMIT <= 2 * 1024 * 1024 * 1024);
#[cfg(test)]
const ARCH_ARCHIVE_INDEX_LIMIT: u64 = 8 * 1024 * 1024;
const NVIDIA_UTILS_ARCHIVE_LIMIT: u64 = 512 * 1024 * 1024;
const LIB32_NVIDIA_UTILS_ARCHIVE_LIMIT: u64 = 128 * 1024 * 1024;
const NVIDIA_DEPENDENCY_ARCHIVE_LIMIT: u64 = 256 * 1024 * 1024;
const NVIDIA_DEPENDENCY_LIMIT: usize = 16;
const ARCH_PACKAGE_SIGNATURE_LIMIT: u64 = 16 * 1024;
const MAX_NORMALIZED_IMAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const NVIDIA_SUPPORT_REPOSITORY: &str = "CorniiDog/OPEMOS";
const NVIDIA_SUPPORT_COMMIT: &str = "9df9e4f9871f463f565a9ffd3ec41003a4a100f0";
const NVIDIA_INSTALLER_COMMIT: &str = NVIDIA_SUPPORT_COMMIT;
const NVIDIA_SUPPORT_BUILD_COMMIT: &str = NVIDIA_SUPPORT_COMMIT;
// Compatibility target only. This does not become the production installer pin
// until its canonical manifest is published through an immutable channel.
const OPEMOS_CORE_COMPATIBILITY_COMMIT: &str = "a1c03c9658c5ed885f094b5f8e0896d818fee785";
const OPEMOS_CORE_COMPATIBILITY_MANIFEST_SHA256: &str =
    "34fa1dfa0351f3bfede0451632063b496ca41da3544d07296a5e4a42a9756cd1";
const OPEMOS_CORE_COMPATIBILITY_BUNDLE_ID: &str =
    "225a5c08ebfb77b3e2ba61aa92c678ba59a13321185f3b6766194e97bf8318fa";
#[cfg(test)]
const NVIDIA_UTILS_SIGNER: &str = "05C7775A9E8B977407FE08E69D4C5AA15426DA0A";
#[cfg(test)]
const LIB32_NVIDIA_UTILS_SIGNER: &str = "D2E95FEC015CF1F911AAAB0C3D4C5008BB5C8D29";
const NVIDIA_USERSPACE_LOCK_PATH: &str = "locks/userspace/steamos-3.8.14-nvidia-575.64.05.json";
const NVIDIA_USERSPACE_KEYRING_PATH: &str =
    "trust/keyrings/archlinux-nvidia-userspace-2025-08-01.gpg";
const NVIDIA_USERSPACE_KEYRING_NAME: &str = "archlinux-nvidia-userspace-2025-08-01.gpg";
const NVIDIA_USERSPACE_KEYRING_SHA256: &str =
    "8a2657da58e7efe162cc9ee76f361b085c9f49daa62baa6e077831aa05ea0bd4";
const NVIDIA_USERSPACE_LOCK_SHA256: &str =
    "a73dd0af6afbd4337c045ddc1ac827081b111ffd4a8c6a8f1efcbaf9d97002a7";
const NVIDIA_COMPRESSION_PROFILE: &str = "btrfs-zstd3";
const NVIDIA_COMPRESSION_WRITE_POLICY: &str = "compress-force=zstd:3";
const NVIDIA_REQUIRED_KERNEL_ARGUMENTS: [&str; 4] = [
    "rd.driver.blacklist=nouveau",
    "modprobe.blacklist=nouveau",
    "nvidia-drm.modeset=1",
    "nvidia-drm.fbdev=1",
];

#[cfg(test)]
include!("tests.rs");

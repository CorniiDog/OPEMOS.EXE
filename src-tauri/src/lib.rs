use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::utils::config::Color;
use tauri::{Emitter, Manager};

const READY_MARKER: &str = "SteamOS NVIDIA Image Builder appliance\nREADY";
const BOOT_TIMEOUT: Duration = Duration::from_secs(120);
const NVIDIA_BUILD_BOOT_TIMEOUT: Duration = Duration::from_secs(600);
const NVIDIA_RELEASES_API: &str = "https://api.github.com/repos/CorniiDog/open-gpu-kernel-modules-steamos-support/releases?per_page=100";
const NVIDIA_RELEASE_REPOSITORY: &str = "CorniiDog/open-gpu-kernel-modules-steamos-support";
const NVIDIA_RESOLVER_SCHEMA: u32 = 2;
const APPROVED_VALVE_SIGNER: &str = "889B5EBDDD505A683621900DAF1D2199EF0A3CCF";
const RELEASES_RESPONSE_LIMIT: u64 = 4 * 1024 * 1024;
const CHECKSUM_RESPONSE_LIMIT: u64 = 4 * 1024;
const PROVENANCE_RESPONSE_LIMIT: u64 = 1024 * 1024;
const NVIDIA_ARCHIVE_LIMIT: u64 = 512 * 1024 * 1024;
const ARCH_ARCHIVE_INDEX_LIMIT: u64 = 8 * 1024 * 1024;
const NVIDIA_UTILS_ARCHIVE_LIMIT: u64 = 512 * 1024 * 1024;
const LIB32_NVIDIA_UTILS_ARCHIVE_LIMIT: u64 = 128 * 1024 * 1024;
const ARCH_PACKAGE_SIGNATURE_LIMIT: u64 = 16 * 1024;
const NVIDIA_SUPPORT_REPOSITORY: &str = "CorniiDog/open-gpu-kernel-modules-steamos-support";
const NVIDIA_INSTALLER_COMMIT: &str = "064b540d32dc22070a953724366e14b78a8b3460";
const NVIDIA_UTILS_SIGNER: &str = "05C7775A9E8B977407FE08E69D4C5AA15426DA0A";
const LIB32_NVIDIA_UTILS_SIGNER: &str = "D2E95FEC015CF1F911AAAB0C3D4C5008BB5C8D29";

struct PinnedInstallerFile {
    path: &'static str,
    sha256: &'static str,
    bytes: u64,
    executable: bool,
}

const PINNED_INSTALLER_FILES: [PinnedInstallerFile; 7] = [
    PinnedInstallerFile {
        path: "bootstrap/install_to_root.sh",
        sha256: "f35349b228bede8c73a6c0511ac9ee8ab2f4ea4a1b4c5710c9e527b8aec80c6f",
        bytes: 11_903,
        executable: true,
    },
    PinnedInstallerFile {
        path: "bootstrap/prepare_nvidia_package_keyring.py",
        sha256: "4b0fb99452e95bca66cf1e1a1e94396f023946885dc04016795c5b532eefbb33",
        bytes: 2_995,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/common.sh",
        sha256: "fa66c6d7d6569bfc95d7d7b971e4f7ba3bc5ac454294c42faf7e48fe28c63ec2",
        bytes: 6_862,
        executable: false,
    },
    PinnedInstallerFile {
        path: "lib/run_in_process_group.py",
        sha256: "06ada2883b18e40a8114861644e03bf59bc10b9bd8174a5437e47fc77a3f177f",
        bytes: 250,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/validate_install_inputs.py",
        sha256: "4f2ad25fb9ab90b367667372bf96683fe171427e5d0a210497becabbbfa87691",
        bytes: 15_741,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/write_install_result.py",
        sha256: "a0d66199d09f0ab0fea5901444461d25d9d443b3d01acdf3fdab34e83589f254",
        bytes: 3_317,
        executable: true,
    },
    PinnedInstallerFile {
        path: "trust/nvidia-userspace-package-signers.json",
        sha256: "9ac4de749f4d881bb177f45eb42dbef718bebcfe1d8702a9f4a06abc0a2b53c5",
        bytes: 584,
        executable: false,
    },
];

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaBuildEnvironment {
    ready: bool,
    host_arch: String,
    guest_arch: String,
    acceleration: String,
    qemu_binary: Option<String>,
    qemu_version: Option<String>,
    qemu_launch_test: bool,
    appliance_present: bool,
    appliance_path: String,
    message: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaBuildStatus {
    state: String,
    message: String,
    architecture: String,
    acceleration: String,
    ssh_port: Option<u16>,
    runtime_path: Option<String>,
}

#[derive(Clone)]
struct NvidiaTargetBuildSpec {
    steamos_version: String,
    kernel_version: String,
    nvidia_version: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaDevelopmentArtifact {
    archive_path: String,
    checksum_path: String,
    build_info_path: String,
    provenance_path: String,
    result_path: String,
    archive_sha256: String,
    steamos_version: String,
    kernel_version: String,
    nvidia_version: String,
    trust: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportBuildResult {
    schema_version: u32,
    status: String,
    reason: String,
    message: String,
    trust: String,
    target: SupportBuildTarget,
    artifact: Option<SupportBuildArtifact>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportBuildTarget {
    steamos_version: String,
    kernel_version: String,
    nvidia_version: String,
    architecture: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportBuildArtifact {
    archive: String,
    checksum: String,
    build_info: String,
    provenance: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportBuildProvenance {
    schema_version: u32,
    trust: String,
    target: SupportBuildTarget,
    artifact: SupportProvenanceArtifact,
    headers: SupportProvenanceHeaders,
    modules: Vec<SupportProvenanceModule>,
}

#[derive(Deserialize)]
struct SupportProvenanceArtifact {
    archive: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportProvenanceHeaders {
    signature_status: String,
    signing_key_fingerprint: String,
    primary_key_fingerprint: String,
    authentication: String,
}

#[derive(Deserialize)]
struct SupportProvenanceModule {
    name: String,
    sha256: String,
    version: String,
    architecture: String,
    vermagic: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValveTrustManifest {
    schema_version: u32,
    signers: Vec<ValveTrustSigner>,
}

#[derive(Deserialize)]
struct ValveTrustSigner {
    fingerprint: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaTargetReadiness {
    ready: bool,
    status: String,
    message: String,
    steamos_version: Option<String>,
    kernel_version: Option<String>,
    architecture: String,
}

#[derive(Clone, Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    published_at: Option<String>,
    assets: Vec<GithubReleaseAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct GithubReleaseAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublishedReleaseIdentity {
    steamos_version: String,
    kernel_version: String,
    nvidia_version: String,
    tag: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaPublishedPublication {
    tag: String,
    steamos_version: String,
    kernel_version: String,
    nvidia_version: String,
    published_at: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaPublishedArtifact {
    archive_path: String,
    checksum_path: String,
    provenance_path: String,
    archive_sha256: String,
    trust: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaPublishedResolution {
    schema_version: u32,
    status: String,
    reason: String,
    message: String,
    compatibility: Option<String>,
    target: NvidiaTargetReadiness,
    publication: Option<NvidiaPublishedPublication>,
    artifact: Option<NvidiaPublishedArtifact>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaUserspacePackage {
    name: String,
    filename: String,
    full_version: String,
    package_path: String,
    signature_path: String,
    package_sha256: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaUserspaceResolution {
    schema_version: u32,
    status: String,
    reason: String,
    message: String,
    nvidia_version: String,
    signature_status: String,
    packages: Vec<NvidiaUserspacePackage>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaInstallerBundleFile {
    path: String,
    sha256: String,
    bytes: u64,
    executable: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaInstallerBundle {
    schema_version: u32,
    status: String,
    reason: String,
    message: String,
    repository: String,
    commit: String,
    files: Vec<NvidiaInstallerBundleFile>,
}

#[derive(Clone)]
struct NvidiaInstallerBundleState {
    root: PathBuf,
    report: NvidiaInstallerBundle,
}

struct NvidiaInstallInputs {
    image_runtime_dir: PathBuf,
    working_image: PathBuf,
    installer_root: PathBuf,
    archive: PathBuf,
    checksum: PathBuf,
    provenance: PathBuf,
    archive_sha256: String,
    trust: String,
    steamos_version: String,
    kernel_version: String,
    nvidia_version: String,
    packages: Vec<NvidiaUserspacePackage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallResult {
    schema_version: u32,
    status: String,
    reason: String,
    message: String,
    phase: String,
    target: SupportInstallTarget,
    trust: String,
    cleanup: SupportInstallCleanup,
    validation: Option<SupportInstallValidation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallTarget {
    steamos_version: String,
    kernel_version: String,
    nvidia_version: String,
    architecture: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallCleanup {
    mounts_released: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallValidation {
    archive_sha256: String,
    keyring: SupportInstallKeyring,
    packages: Vec<SupportInstallPackage>,
}

#[derive(Deserialize)]
struct SupportInstallKeyring {
    name: String,
    sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallPackage {
    name: String,
    full_version: String,
    pkgver: String,
    pkgrel: String,
    signer: String,
    sha256: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaInstallHandoffResult {
    schema_version: u32,
    status: String,
    reason: String,
    message: String,
    phase: String,
    appliance_architecture: String,
    root_partition_label: String,
    boot_partition_label: String,
    support_commit: String,
    steamos_version: String,
    kernel_version: String,
    nvidia_version: String,
    trust: String,
    archive_sha256: String,
    keyring_sha256: String,
    packages: Vec<SupportInstallPackage>,
    mounts_released: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaResolutionProgress {
    stage: String,
    processed_bytes: u64,
    total_bytes: u64,
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

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetSystemDiscovery {
    os_id: Option<String>,
    pretty_name: Option<String>,
    version_id: Option<String>,
    build_id: Option<String>,
    variant_id: Option<String>,
    architecture: String,
    kernel_versions: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserMarkerMutation {
    marker_path: String,
    marker_content: String,
    target_partition: String,
    target_partition_label: String,
    filesystem: String,
    input_sha256_before: String,
    input_sha256_after: String,
    input_unchanged: bool,
    working_read_only: bool,
    mounted: bool,
    system: TargetSystemDiscovery,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportedImage {
    path: String,
    manifest_path: String,
    bytes: u64,
    sha256: String,
    source_sha256: String,
    layout_scheme: String,
    marker_path: String,
}

struct MarkerManifestData<'a> {
    input: &'a Path,
    output: &'a Path,
    input_preparation: &'a InputPreparation,
    input_sha256: &'a str,
    normalized_sha256: &'a str,
    output_bytes: u64,
    output_sha256: &'a str,
    layout: &'a SteamOsLayoutDiscovery,
    target_system: &'a TargetSystemDiscovery,
    nvidia_installation: Option<&'a NvidiaInstallHandoffResult>,
}

fn marker_build_manifest(data: MarkerManifestData<'_>) -> serde_json::Value {
    let nvidia_installed = data.nvidia_installation.is_some();
    let result_class = if nvidia_installed {
        "nvidia-mutation-valid"
    } else {
        "mutation-valid"
    };
    let milestone = if nvidia_installed {
        "nvidia-offline-installed"
    } else {
        "marker-only"
    };
    let modified_paths = if nvidia_installed {
        serde_json::json!([
            "/etc/steamos-nvidia-image-builder-test",
            "/etc/modprobe.d/99-open-gpu-kernel-modules-steamos.conf",
            "/etc/mkinitcpio.conf.d/90-open-gpu-kernel-modules-steamos.conf",
            "/usr/lib/modules/<target-kernel>/updates/open-gpu-kernel-modules-steamos",
            "/var/lib/open-gpu-kernel-modules-steamos-support/offline-install",
            "/boot"
        ])
    } else {
        serde_json::json!(["/etc/steamos-nvidia-image-builder-test"])
    };
    serde_json::json!({
        "schemaVersion": 1,
        "resultClass": result_class,
        "application": {
            "name": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "commit": null
        },
        "builderProtocolVersion": "1",
        "input": {
            "filename": data.input.file_name().and_then(|value| value.to_str()).unwrap_or("unknown"),
            "sourceFormat": data.input_preparation.source_format,
            "normalizer": data.input_preparation.normalizer,
            "sourceBytes": data.input_preparation.source_bytes,
            "normalizedBytes": data.input_preparation.image_bytes,
            "sourceSha256": data.input_sha256,
            "normalizedSha256": data.normalized_sha256
        },
        "output": {
            "filename": data.output.file_name().and_then(|value| value.to_str()).unwrap_or("unknown.img"),
            "format": "raw",
            "bytes": data.output_bytes,
            "sha256": data.output_sha256
        },
        "steamos": {
            "layoutScheme": data.layout.scheme,
            "id": data.target_system.os_id,
            "prettyName": data.target_system.pretty_name,
            "versionId": data.target_system.version_id,
            "buildId": data.target_system.build_id,
            "variantId": data.target_system.variant_id,
            "architecture": data.target_system.architecture,
            "targetKernels": data.target_system.kernel_versions
        },
        "integration": {
            "milestone": milestone,
            "nvidia": data.nvidia_installation,
            "gamescope": null,
            "modifiedPaths": modified_paths
        },
        "validation": {
            "candidateAttachedReadOnly": true,
            "layoutRecognized": data.layout.recognized,
            "markerVerified": true,
            "nvidiaPayloadVerified": nvidia_installed,
            "sourceUnchanged": true,
            "passed": true
        }
    })
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
    layout: SteamOsLayoutDiscovery,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SteamOsPartitionRole {
    role: String,
    path: String,
    size_bytes: u64,
    filesystem: String,
    filesystem_label: String,
    partition_label: String,
    partition_type: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SteamOsLayoutDiscovery {
    recognized: bool,
    scheme: Option<String>,
    roles: Vec<SteamOsPartitionRole>,
    issues: Vec<String>,
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
    qmp_port: u16,
    started_at: Instant,
    state: String,
    message: String,
    input_image: PathBuf,
    input_sha256_before: String,
    attached_image: PathBuf,
    attached_sha256_before: String,
    working_image: PathBuf,
    input_preparation: InputPreparation,
    target_system: Option<TargetSystemDiscovery>,
    nvidia_resolution: Option<NvidiaPublishedResolution>,
    nvidia_userspace: Option<NvidiaUserspaceResolution>,
    nvidia_installer_bundle: Option<NvidiaInstallerBundleState>,
    nvidia_install_validation: Option<NvidiaInstallHandoffResult>,
    nvidia_installation: Option<NvidiaInstallHandoffResult>,
}

struct NvidiaBuildSession {
    child: Child,
    runtime_dir: PathBuf,
    ssh_key: PathBuf,
    ssh_port: u16,
    started_at: Instant,
    state: String,
    message: String,
    acceleration: String,
    attached_working_image: Option<PathBuf>,
}

#[derive(Clone)]
struct NvidiaBuildConnection {
    runtime_dir: PathBuf,
    ssh_key: PathBuf,
    ssh_port: u16,
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
struct ImageInspectionSession {
    runtime_dir: PathBuf,
    ssh_key: PathBuf,
    ssh_port: u16,
    qmp_port: u16,
    input_image: PathBuf,
    input_sha256_before: String,
    attached_image: PathBuf,
    attached_sha256_before: String,
    working_image: PathBuf,
    input_preparation: InputPreparation,
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

struct RuntimeGuard {
    path: PathBuf,
    armed: bool,
}

struct NvidiaBuildRuntimeGuard {
    path: PathBuf,
    armed: bool,
}

struct PartialOutputGuard {
    path: PathBuf,
    armed: bool,
}

struct StagingDirectoryGuard {
    path: PathBuf,
    armed: bool,
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
        if self.runtime_dir.is_dir() {
            let _ = archive_and_remove_nvidia_build_runtime(&self.runtime_dir);
        }
    }
}

struct ApplianceManager {
    session: Option<ApplianceSession>,
    preparing: bool,
    cancel_preparation: Arc<AtomicBool>,
}

#[derive(Default)]
struct NvidiaBuildManager {
    session: Option<NvidiaBuildSession>,
    starting: bool,
    cancel_build: Arc<AtomicBool>,
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

fn nvidia_build_appliance_path() -> PathBuf {
    appliance_dir().join("fedora-builder-x86_64.qcow2")
}

fn runtime_root() -> PathBuf {
    appliance_dir().join("runtime")
}

fn nvidia_build_runtime_root() -> PathBuf {
    appliance_dir().join("runtime-x86_64-managed")
}

fn nvidia_build_qemu_spec(
    host_arch: &str,
) -> Result<(&'static str, &'static str, &'static str), String> {
    match host_arch {
        "aarch64" => Ok(("tcg", "q35,accel=tcg", "max")),
        "x86_64" => Ok(("hvf", "q35,accel=hvf", "host")),
        arch => Err(format!("Unsupported host architecture: {arch}")),
    }
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

fn archive_and_remove_nvidia_build_runtime(runtime_dir: &Path) -> Result<Option<PathBuf>, String> {
    let diagnostic_sources = [
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

fn cleanup_abandoned_nvidia_build_runtimes() -> Result<(), String> {
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

fn copy_new_file(source: &Path, destination: &Path, description: &str) -> Result<(), String> {
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
            progress("decompressing-output", output_bytes, 0);
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
        nvidia_userspace: None,
        nvidia_installer_bundle: None,
        nvidia_install_validation: None,
        nvidia_installation: None,
    })
}

fn prepare_nvidia_build_session(
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
    let log = File::create(runtime_dir.join("qemu.log"))
        .map_err(|e| format!("Could not create the x86 build-appliance log: {e}"))?;
    let log_err = log
        .try_clone()
        .map_err(|e| format!("Could not prepare the x86 build-appliance log: {e}"))?;

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
        ));
    if let Some(target) = &attached_working_image {
        let target = target
            .to_str()
            .ok_or("The handoff working-image path is not valid UTF-8.")?
            .replace(',', ",,");
        qemu_command
            .arg("-drive")
            .arg(format!(
                "file={target},if=none,format=qcow2,id=steamos-install-target"
            ))
            .args([
                "-device",
                "virtio-blk-pci,drive=steamos-install-target,serial=steamos-target",
            ]);
    }
    let mut child = qemu_command
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
        .map_err(|e| format!("Could not start the x86 Fedora build appliance: {e}"))?;
    if let Err(error) = fs::write(runtime_dir.join("qemu.pid"), child.id().to_string()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "Could not record the x86 build-appliance process ID: {error}"
        ));
    }

    runtime_guard.armed = false;
    Ok(NvidiaBuildSession {
        child,
        runtime_dir,
        ssh_key,
        ssh_port,
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

trait GuestConnection {
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
            "-o",
            "LogLevel=ERROR",
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

fn read_qmp_response(reader: &mut BufReader<TcpStream>) -> Result<serde_json::Value, String> {
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

fn qmp_remove_user_input(session: &ImageInspectionSession) -> Result<(), String> {
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

fn handshake(session: &impl GuestConnection) -> Result<String, String> {
    run_guest_command(session, "cat /etc/steamos-builder-ready")
}

fn collect_guest_health(session: &impl GuestConnection) -> Result<GuestHealth, String> {
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

fn scp_command(session: &impl GuestConnection) -> Result<Command, String> {
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

fn valid_numeric_version(value: &str, components: std::ops::RangeInclusive<usize>) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    components.contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_kernel_version(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'~' | b'-')
        })
}

fn validate_nvidia_target_build_spec(spec: &NvidiaTargetBuildSpec) -> Result<(), String> {
    if !valid_numeric_version(&spec.steamos_version, 3..=3) {
        return Err("SteamOS target version must contain three numeric components.".into());
    }
    if !valid_numeric_version(&spec.nvidia_version, 2..=3) {
        return Err("NVIDIA target version must contain two or three numeric components.".into());
    }
    if !valid_kernel_version(&spec.kernel_version) {
        return Err("Target kernel contains unsupported characters.".into());
    }
    Ok(())
}

fn assess_nvidia_target_system(system: &TargetSystemDiscovery) -> NvidiaTargetReadiness {
    let unavailable = |status: &str, message: String| NvidiaTargetReadiness {
        ready: false,
        status: status.into(),
        message,
        steamos_version: system.version_id.clone(),
        kernel_version: None,
        architecture: system.architecture.clone(),
    };
    let is_steamos = system
        .os_id
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("steamos"))
        || system
            .pretty_name
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains("steamos"));
    if !is_steamos {
        return unavailable(
            "unsupported-system",
            "The selected root does not identify itself as SteamOS; NVIDIA resolution is disabled."
                .into(),
        );
    }
    let Some(steamos_version) = system.version_id.as_deref() else {
        return unavailable(
            "missing-version",
            "The selected SteamOS root does not provide VERSION_ID; NVIDIA resolution is disabled."
                .into(),
        );
    };
    if !valid_numeric_version(steamos_version, 3..=3) {
        return unavailable(
            "invalid-version",
            format!(
                "SteamOS VERSION_ID {steamos_version:?} is not an exact three-component version; NVIDIA resolution is disabled."
            ),
        );
    }
    if system.architecture != "x86_64" {
        return unavailable(
            "unsupported-architecture",
            format!(
                "Target architecture {} is not supported by the NVIDIA artifact workflow.",
                system.architecture
            ),
        );
    }
    let mut kernels = system.kernel_versions.clone();
    kernels.sort();
    kernels.dedup();
    if kernels.is_empty() {
        return unavailable(
            "no-kernel",
            "No target kernel module directory was discovered; NVIDIA resolution is disabled."
                .into(),
        );
    }
    if kernels.len() != 1 {
        return unavailable(
            "ambiguous-kernel",
            format!(
                "The image contains multiple target kernels ({}). The boot kernel is not proven, so NVIDIA resolution is disabled.",
                kernels.join(", ")
            ),
        );
    }
    let kernel_version = kernels.remove(0);
    if !valid_kernel_version(&kernel_version) {
        return unavailable(
            "invalid-kernel",
            "Target kernel contains unsupported characters.".into(),
        );
    }
    NvidiaTargetReadiness {
        ready: true,
        status: "exact-target".into(),
        message: format!(
            "Exact NVIDIA target is ready for support-repository resolution: SteamOS {steamos_version}, kernel {kernel_version}, x86_64."
        ),
        steamos_version: Some(steamos_version.into()),
        kernel_version: Some(kernel_version),
        architecture: system.architecture.clone(),
    }
}

fn numeric_version(value: &str, components: std::ops::RangeInclusive<usize>) -> Option<Vec<u64>> {
    let parts: Vec<_> = value.split('.').collect();
    if !components.contains(&parts.len()) {
        return None;
    }
    parts
        .into_iter()
        .map(|part| part.parse::<u64>().ok())
        .collect()
}

fn published_release_identity(tag: &str) -> Option<PublishedReleaseIdentity> {
    let remainder = tag.strip_prefix("steamos-")?;
    let (steamos_version, remainder) = remainder.split_once("-nvidia-")?;
    let (nvidia_version, kernel_version) = remainder.split_once("-k")?;
    numeric_version(steamos_version, 3..=3)?;
    numeric_version(nvidia_version, 2..=3)?;
    if !valid_kernel_version(kernel_version) {
        return None;
    }
    Some(PublishedReleaseIdentity {
        steamos_version: steamos_version.into(),
        kernel_version: kernel_version.into(),
        nvidia_version: nvidia_version.into(),
        tag: tag.into(),
    })
}

fn select_published_nvidia_release(
    target: &NvidiaTargetReadiness,
    releases: &[GithubRelease],
) -> Result<Option<(PublishedReleaseIdentity, GithubRelease, String)>, String> {
    if !target.ready {
        return Ok(None);
    }
    let target_steamos = target
        .steamos_version
        .as_deref()
        .ok_or("Ready NVIDIA target omitted its SteamOS version.")?;
    let target_kernel = target
        .kernel_version
        .as_deref()
        .ok_or("Ready NVIDIA target omitted its kernel version.")?;
    let target_version = numeric_version(target_steamos, 3..=3)
        .ok_or("Ready NVIDIA target contains an invalid SteamOS version.")?;
    let mut candidates = Vec::new();
    for release in releases {
        if release.draft || release.prerelease {
            continue;
        }
        let Some(identity) = published_release_identity(&release.tag_name) else {
            continue;
        };
        let steam_version =
            numeric_version(&identity.steamos_version, 3..=3).expect("validated release version");
        if steam_version[..2] != target_version[..2]
            || steam_version > target_version
            || identity.kernel_version != target_kernel
        {
            continue;
        }
        let nvidia_version =
            numeric_version(&identity.nvidia_version, 2..=3).expect("validated NVIDIA version");
        candidates.push((
            steam_version,
            nvidia_version,
            release.published_at.clone().unwrap_or_default(),
            identity,
            release.clone(),
        ));
    }
    candidates
        .sort_by(|left, right| (&left.0, &left.1, &left.2).cmp(&(&right.0, &right.1, &right.2)));
    Ok(candidates.pop().map(|(_, _, _, identity, release)| {
        let compatibility = if identity.steamos_version == target_steamos {
            "exact"
        } else {
            "same_series_fallback"
        };
        (identity, release, compatibility.into())
    }))
}

fn published_asset_name(identity: &PublishedReleaseIdentity) -> String {
    format!("nvidia-open-{}-x86_64.tar.gz", identity.tag)
}

fn expected_release_asset_url(tag: &str, name: &str) -> String {
    format!("https://github.com/{NVIDIA_RELEASE_REPOSITORY}/releases/download/{tag}/{name}")
}

fn unique_release_asset<'a>(
    release: &'a GithubRelease,
    name: &str,
) -> Result<Option<&'a GithubReleaseAsset>, String> {
    let matches: Vec<_> = release
        .assets
        .iter()
        .filter(|asset| asset.name == name)
        .collect();
    if matches.len() > 1 {
        return Err(format!(
            "Published NVIDIA release contains duplicate asset {name}."
        ));
    }
    Ok(matches.into_iter().next())
}

fn github_sha256(asset: &GithubReleaseAsset) -> Result<String, String> {
    let digest = asset
        .digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| format!("GitHub did not provide a valid SHA-256 for {}.", asset.name))?;
    Ok(digest.to_ascii_lowercase())
}

struct PublishedArchiveInspection {
    build_info: Vec<u8>,
    provenance: Vec<u8>,
    module_hashes: HashMap<String, String>,
}

fn inspect_published_nvidia_archive(path: &Path) -> Result<PublishedArchiveInspection, String> {
    const METADATA_LIMIT: u64 = 1024 * 1024;
    const UNCOMPRESSED_LIMIT: u64 = 256 * 1024 * 1024;
    let file = File::open(path)
        .map_err(|e| format!("Could not open the published NVIDIA archive: {e}"))?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let expected_modules = [
        "nvidia-drm.ko",
        "nvidia-modeset.ko",
        "nvidia-peermem.ko",
        "nvidia-uvm.ko",
        "nvidia.ko",
    ];
    let mut build_info = None;
    let mut provenance = None;
    let mut module_hashes = HashMap::new();
    let mut total_size = 0_u64;
    let entries = archive
        .entries()
        .map_err(|e| format!("Published NVIDIA artifact is not a readable tar.gz archive: {e}"))?;
    for entry in entries {
        let mut entry = entry
            .map_err(|e| format!("Could not inspect a published NVIDIA archive entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("Published NVIDIA archive contains an invalid path: {e}"))?;
        if path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err("Published NVIDIA archive contains an unsafe path.".into());
        }
        let name = path
            .to_str()
            .ok_or("Published NVIDIA archive contains a non-UTF-8 path.")?
            .to_owned();
        let kind = entry.header().entry_type();
        if matches!(name.as_str(), "modules" | "modules/") && kind.is_dir() {
            continue;
        }
        if !kind.is_file() {
            return Err(format!(
                "Published NVIDIA archive contains an unsupported entry: {name}."
            ));
        }
        let size = entry.size();
        total_size = total_size
            .checked_add(size)
            .filter(|value| *value <= UNCOMPRESSED_LIMIT)
            .ok_or("Published NVIDIA archive expands beyond the safety limit.")?;
        if name == "BUILD-INFO.txt" || name == "PROVENANCE.json" {
            if size > METADATA_LIMIT {
                return Err(format!("Published NVIDIA metadata is too large: {name}."));
            }
            let mut bytes = Vec::with_capacity(size as usize);
            entry
                .read_to_end(&mut bytes)
                .map_err(|e| format!("Could not read {name} from the NVIDIA archive: {e}"))?;
            let destination = if name == "BUILD-INFO.txt" {
                &mut build_info
            } else {
                &mut provenance
            };
            if destination.replace(bytes).is_some() {
                return Err(format!("Published NVIDIA archive repeats {name}."));
            }
            continue;
        }
        let Some(module_name) = name.strip_prefix("modules/") else {
            return Err(format!(
                "Published NVIDIA archive contains an unexpected entry: {name}."
            ));
        };
        if !expected_modules.contains(&module_name) || module_name.contains('/') {
            return Err(format!(
                "Published NVIDIA archive contains an unexpected module: {name}."
            ));
        }
        let mut hasher = Sha256::new();
        io::copy(&mut entry, &mut hasher)
            .map_err(|e| format!("Could not hash {name} from the NVIDIA archive: {e}"))?;
        if module_hashes
            .insert(module_name.into(), format!("{:x}", hasher.finalize()))
            .is_some()
        {
            return Err(format!("Published NVIDIA archive repeats {name}."));
        }
    }
    if module_hashes.len() != expected_modules.len()
        || !expected_modules
            .iter()
            .all(|name| module_hashes.contains_key(*name))
    {
        return Err("Published NVIDIA archive does not contain the exact five-module set.".into());
    }
    Ok(PublishedArchiveInspection {
        build_info: build_info.ok_or("Published NVIDIA archive omitted BUILD-INFO.txt.")?,
        provenance: provenance.ok_or("Published NVIDIA archive omitted PROVENANCE.json.")?,
        module_hashes,
    })
}

fn nvidia_http_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .user_agent("steamos-nvidia-image-builder/0.1")
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(15 * 60))
        .build()
        .map_err(|e| format!("Could not initialize secure NVIDIA release downloads: {e}"))
}

fn read_http_response_limited(
    mut response: reqwest::blocking::Response,
    limit: u64,
    description: &str,
) -> Result<Vec<u8>, String> {
    response = response
        .error_for_status()
        .map_err(|e| format!("Could not download {description}: {e}"))?;
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(format!("{description} exceeds the download safety limit."));
    }
    let mut bytes = Vec::new();
    response
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Could not read {description}: {e}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{description} exceeds the download safety limit."));
    }
    Ok(bytes)
}

fn fetch_github_releases(client: &reqwest::blocking::Client) -> Result<Vec<GithubRelease>, String> {
    let response = client
        .get(NVIDIA_RELEASES_API)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .map_err(|e| format!("Could not query published NVIDIA releases: {e}"))?;
    let bytes = read_http_response_limited(response, RELEASES_RESPONSE_LIMIT, "release metadata")?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("Published NVIDIA release metadata is invalid JSON: {e}"))
}

struct PublishedDownloadContext<'a> {
    client: &'a reqwest::blocking::Client,
    cancel: &'a AtomicBool,
    progress: &'a dyn Fn(&str, u64, u64),
}

fn download_release_asset(
    context: &PublishedDownloadContext<'_>,
    asset: &GithubReleaseAsset,
    expected_url: &str,
    destination: &Path,
    limit: u64,
    stage: &str,
) -> Result<String, String> {
    if asset.browser_download_url != expected_url {
        return Err(format!(
            "GitHub returned an unexpected download URL for {}.",
            asset.name
        ));
    }
    if asset.size > limit {
        return Err(format!(
            "Published asset {} exceeds the safety limit.",
            asset.name
        ));
    }
    if destination.exists() {
        return Err(format!(
            "Refusing to overwrite a staged NVIDIA artifact: {}",
            destination.display()
        ));
    }
    let partial = destination.with_file_name(format!(
        ".{}.partial",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("Published NVIDIA asset has an invalid filename.")?
    ));
    if partial.exists() {
        fs::remove_file(&partial)
            .map_err(|e| format!("Could not remove an abandoned NVIDIA download: {e}"))?;
    }
    let mut guard = PartialOutputGuard {
        path: partial.clone(),
        armed: true,
    };
    let mut response = context
        .client
        .get(expected_url)
        .header("Accept", "application/octet-stream")
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| format!("Could not download {}: {e}", asset.name))?;
    if response
        .content_length()
        .is_some_and(|length| length > limit || length != asset.size)
    {
        return Err(format!(
            "Published asset {} has an unexpected download size.",
            asset.name
        ));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|e| format!("Could not stage {}: {e}", asset.name))?;
    let mut hasher = Sha256::new();
    let mut downloaded = 0_u64;
    let mut next_report = 0_u64;
    let mut buffer = vec![0_u8; 256 * 1024];
    loop {
        if context.cancel.load(Ordering::Relaxed) {
            return Err("Published NVIDIA artifact download cancelled.".into());
        }
        let count = response
            .read(&mut buffer)
            .map_err(|e| format!("Could not read {}: {e}", asset.name))?;
        if count == 0 {
            break;
        }
        downloaded = downloaded
            .checked_add(count as u64)
            .filter(|value| *value <= limit)
            .ok_or_else(|| format!("Published asset {} exceeds the safety limit.", asset.name))?;
        output
            .write_all(&buffer[..count])
            .map_err(|e| format!("Could not write {}: {e}", asset.name))?;
        hasher.update(&buffer[..count]);
        if downloaded >= next_report {
            (context.progress)(stage, downloaded, asset.size);
            next_report = downloaded.saturating_add(1024 * 1024);
        }
    }
    output
        .flush()
        .map_err(|e| format!("Could not finish staging {}: {e}", asset.name))?;
    if downloaded != asset.size {
        return Err(format!(
            "Published asset {} downloaded {downloaded} bytes; expected {}.",
            asset.name, asset.size
        ));
    }
    let digest = format!("{:x}", hasher.finalize());
    if digest != github_sha256(asset)? {
        return Err(format!(
            "GitHub digest verification failed for {}.",
            asset.name
        ));
    }
    (context.progress)(stage, downloaded, asset.size);
    fs::rename(&partial, destination)
        .map_err(|e| format!("Could not finalize {}: {e}", asset.name))?;
    guard.armed = false;
    Ok(digest)
}

fn metadata_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
}

fn validate_published_nvidia_artifact(
    archive_path: &Path,
    checksum_path: &Path,
    provenance_path: &Path,
    identity: &PublishedReleaseIdentity,
    archive_sha256: &str,
) -> Result<String, String> {
    let checksum = fs::read_to_string(checksum_path)
        .map_err(|e| format!("Could not read the published NVIDIA checksum: {e}"))?;
    let expected_sha256 = checksum
        .split_whitespace()
        .next()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("Published NVIDIA checksum sidecar is invalid.")?
        .to_ascii_lowercase();
    if expected_sha256 != archive_sha256 {
        return Err("Published NVIDIA checksum does not match the downloaded archive.".into());
    }
    let inspection = inspect_published_nvidia_archive(archive_path)?;
    let external_provenance = fs::read(provenance_path)
        .map_err(|e| format!("Could not read published NVIDIA provenance: {e}"))?;
    if external_provenance != inspection.provenance {
        return Err(
            "Published NVIDIA archive provenance does not match its external sidecar file.".into(),
        );
    }
    let provenance: SupportBuildProvenance = serde_json::from_slice(&external_provenance)
        .map_err(|e| format!("Published NVIDIA provenance is invalid JSON: {e}"))?;
    if !matches!(
        provenance.trust.as_str(),
        "locally-built-verified" | "certified-published"
    ) {
        return Err(format!(
            "Published NVIDIA artifact has unsupported trust classification {}.",
            provenance.trust
        ));
    }
    let spec = NvidiaTargetBuildSpec {
        steamos_version: identity.steamos_version.clone(),
        kernel_version: identity.kernel_version.clone(),
        nvidia_version: identity.nvidia_version.clone(),
    };
    validate_support_build_provenance(
        &provenance,
        &spec,
        &provenance.trust,
        APPROVED_VALVE_SIGNER,
    )?;
    for module in &provenance.modules {
        if inspection.module_hashes.get(&module.name) != Some(&module.sha256.to_ascii_lowercase()) {
            return Err(format!(
                "Published NVIDIA module does not match provenance: {}.",
                module.name
            ));
        }
    }
    let build_info = std::str::from_utf8(&inspection.build_info)
        .map_err(|e| format!("Published NVIDIA build information is not UTF-8: {e}"))?;
    if metadata_field(build_info, "steamos_version") != Some(identity.steamos_version.as_str())
        || metadata_field(build_info, "kernel_version") != Some(identity.kernel_version.as_str())
        || metadata_field(build_info, "nvidia_version") != Some(identity.nvidia_version.as_str())
        || metadata_field(build_info, "build_architecture") != Some("x86_64")
        || metadata_field(build_info, "trust_classification") != Some(provenance.trust.as_str())
        || metadata_field(build_info, "release_tag") != Some(identity.tag.as_str())
        || metadata_field(build_info, "release_asset")
            != archive_path.file_name().and_then(|name| name.to_str())
    {
        return Err("Published NVIDIA build information does not match its publication.".into());
    }
    Ok(provenance.trust)
}

fn resolve_published_nvidia_for_target(
    target: NvidiaTargetReadiness,
    runtime_dir: &Path,
    client: &reqwest::blocking::Client,
    releases: &[GithubRelease],
    cancel: &AtomicBool,
    progress: &impl Fn(&str, u64, u64),
) -> Result<NvidiaPublishedResolution, String> {
    if !target.ready {
        return Ok(NvidiaPublishedResolution {
            schema_version: NVIDIA_RESOLVER_SCHEMA,
            status: "unsupported_target".into(),
            reason: target.status.clone(),
            message: target.message.clone(),
            compatibility: None,
            target,
            publication: None,
            artifact: None,
        });
    }
    let Some((identity, release, compatibility)) =
        select_published_nvidia_release(&target, releases)?
    else {
        return Ok(NvidiaPublishedResolution {
            schema_version: NVIDIA_RESOLVER_SCHEMA,
            status: "no_compatible_artifact".into(),
            reason: "no_compatible_release".into(),
            message: "No published NVIDIA release matches the exact target kernel within the permitted SteamOS compatibility range.".into(),
            compatibility: None,
            target,
            publication: None,
            artifact: None,
        });
    };
    let publication = NvidiaPublishedPublication {
        tag: identity.tag.clone(),
        steamos_version: identity.steamos_version.clone(),
        kernel_version: identity.kernel_version.clone(),
        nvidia_version: identity.nvidia_version.clone(),
        published_at: release.published_at.clone(),
    };
    let archive_name = published_asset_name(&identity);
    let checksum_name = format!("{archive_name}.sha256");
    let provenance_name = format!(
        "{}.provenance.json",
        archive_name.trim_end_matches(".tar.gz")
    );
    let required_names = [&archive_name, &checksum_name, &provenance_name];
    let mut selected_assets = Vec::new();
    let mut missing_assets = Vec::new();
    for name in required_names {
        match unique_release_asset(&release, name)? {
            Some(asset) => selected_assets.push(asset),
            None => missing_assets.push(name.clone()),
        }
    }
    if !missing_assets.is_empty() {
        return Ok(NvidiaPublishedResolution {
            schema_version: NVIDIA_RESOLVER_SCHEMA,
            status: "no_compatible_artifact".into(),
            reason: "release_assets_missing".into(),
            message: format!(
                "The matching NVIDIA publication is incomplete; missing {}.",
                missing_assets.join(", ")
            ),
            compatibility: Some(compatibility),
            target,
            publication: Some(publication),
            artifact: None,
        });
    }
    let archive_asset = selected_assets[0];
    let checksum_asset = selected_assets[1];
    let provenance_asset = selected_assets[2];
    let output_dir = runtime_dir.join(format!(
        "published-nvidia-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    fs::create_dir(&output_dir)
        .map_err(|e| format!("Could not create the published NVIDIA staging directory: {e}"))?;
    let archive_path = output_dir.join(&archive_name);
    let checksum_path = output_dir.join(&checksum_name);
    let provenance_path = output_dir.join(&provenance_name);
    let mut archive_guard = PartialOutputGuard {
        path: archive_path.clone(),
        armed: true,
    };
    let mut checksum_guard = PartialOutputGuard {
        path: checksum_path.clone(),
        armed: true,
    };
    let mut provenance_guard = PartialOutputGuard {
        path: provenance_path.clone(),
        armed: true,
    };
    let download = PublishedDownloadContext {
        client,
        cancel,
        progress,
    };
    let checksum_url = expected_release_asset_url(&identity.tag, &checksum_name);
    download_release_asset(
        &download,
        checksum_asset,
        &checksum_url,
        &checksum_path,
        CHECKSUM_RESPONSE_LIMIT,
        "downloading-nvidia-checksum",
    )?;
    let provenance_url = expected_release_asset_url(&identity.tag, &provenance_name);
    download_release_asset(
        &download,
        provenance_asset,
        &provenance_url,
        &provenance_path,
        PROVENANCE_RESPONSE_LIMIT,
        "downloading-nvidia-provenance",
    )?;
    let archive_url = expected_release_asset_url(&identity.tag, &archive_name);
    let archive_sha256 = download_release_asset(
        &download,
        archive_asset,
        &archive_url,
        &archive_path,
        NVIDIA_ARCHIVE_LIMIT,
        "downloading-nvidia-archive",
    )?;
    progress("validating-nvidia-artifact", 0, 1);
    let trust = validate_published_nvidia_artifact(
        &archive_path,
        &checksum_path,
        &provenance_path,
        &identity,
        &archive_sha256,
    )?;
    progress("validating-nvidia-artifact", 1, 1);
    archive_guard.armed = false;
    checksum_guard.armed = false;
    provenance_guard.armed = false;
    Ok(NvidiaPublishedResolution {
        schema_version: NVIDIA_RESOLVER_SCHEMA,
        status: "compatible".into(),
        reason: "published_artifact_verified".into(),
        message: format!(
            "Verified published NVIDIA {} artifact for exact kernel {} ({trust}).",
            identity.nvidia_version, identity.kernel_version
        ),
        compatibility: Some(compatibility),
        target,
        publication: Some(publication),
        artifact: Some(NvidiaPublishedArtifact {
            archive_path: archive_path.to_string_lossy().into_owned(),
            checksum_path: checksum_path.to_string_lossy().into_owned(),
            provenance_path: provenance_path.to_string_lossy().into_owned(),
            archive_sha256,
            trust,
        }),
    })
}

fn arch_package_release_key(value: &str) -> Option<Vec<u64>> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.is_empty()
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
    {
        return None;
    }
    parts
        .into_iter()
        .map(|part| part.parse::<u64>().ok())
        .collect()
}

fn arch_index_hrefs(index: &str) -> HashSet<&str> {
    index
        .split("href=\"")
        .skip(1)
        .filter_map(|rest| rest.split_once('"').map(|(href, _)| href))
        .collect()
}

fn select_arch_userspace_package(
    index: &str,
    package: &str,
    nvidia_version: &str,
) -> Result<(String, String), String> {
    if !matches!(package, "nvidia-utils" | "lib32-nvidia-utils")
        || !valid_numeric_version(nvidia_version, 2..=3)
    {
        return Err("Invalid NVIDIA userspace package selection request.".into());
    }
    let hrefs = arch_index_hrefs(index);
    let prefix = format!("{package}-{nvidia_version}-");
    let suffix = "-x86_64.pkg.tar.zst";
    let mut candidates = Vec::new();
    for href in &hrefs {
        let Some(release) = href
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(suffix))
        else {
            continue;
        };
        let Some(release_key) = arch_package_release_key(release) else {
            continue;
        };
        if !hrefs.contains(format!("{href}.sig").as_str()) {
            continue;
        }
        candidates.push((release_key, release.to_string(), (*href).to_string()));
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let Some((highest_key, highest_release, highest_filename)) = candidates.pop() else {
        return Err(format!(
            "The Arch Linux Archive has no signed x86_64 {package} package for exact NVIDIA version {nvidia_version}."
        ));
    };
    if candidates
        .last()
        .is_some_and(|candidate| candidate.0 == highest_key)
    {
        return Err(format!(
            "The Arch Linux Archive returned an ambiguous highest {package} package release."
        ));
    }
    Ok((
        highest_filename,
        format!("{nvidia_version}-{highest_release}"),
    ))
}

fn arch_package_directory(package: &str) -> Result<&'static str, String> {
    match package {
        "nvidia-utils" => Ok("https://archive.archlinux.org/packages/n/nvidia-utils"),
        "lib32-nvidia-utils" => Ok("https://archive.archlinux.org/packages/l/lib32-nvidia-utils"),
        _ => Err("Unsupported NVIDIA userspace package name.".into()),
    }
}

fn download_arch_userspace_asset(
    client: &reqwest::blocking::Client,
    url: &str,
    destination: &Path,
    limit: u64,
    cancel: &AtomicBool,
    stage: &str,
    progress: &impl Fn(&str, u64, u64),
) -> Result<String, String> {
    if destination.exists() {
        return Err(format!(
            "Refusing to overwrite a staged NVIDIA userspace input: {}",
            destination.display()
        ));
    }
    let partial = destination.with_file_name(format!(
        ".{}.partial",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("NVIDIA userspace asset has an invalid filename.")?
    ));
    if partial.exists() {
        fs::remove_file(&partial)
            .map_err(|e| format!("Could not remove an abandoned userspace download: {e}"))?;
    }
    let mut guard = PartialOutputGuard {
        path: partial.clone(),
        armed: true,
    };
    let mut response = client
        .get(url)
        .header("Accept", "application/octet-stream")
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| format!("Could not download NVIDIA userspace input: {e}"))?;
    if response
        .content_length()
        .is_some_and(|length| length == 0 || length > limit)
    {
        return Err("NVIDIA userspace input has an invalid download size.".into());
    }
    let total = response.content_length().unwrap_or(0);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|e| format!("Could not stage NVIDIA userspace input: {e}"))?;
    let mut hasher = Sha256::new();
    let mut downloaded = 0_u64;
    let mut next_report = 0_u64;
    let mut buffer = vec![0_u8; 256 * 1024];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("NVIDIA userspace download cancelled.".into());
        }
        let count = response
            .read(&mut buffer)
            .map_err(|e| format!("Could not read NVIDIA userspace input: {e}"))?;
        if count == 0 {
            break;
        }
        downloaded = downloaded
            .checked_add(count as u64)
            .filter(|value| *value <= limit)
            .ok_or("NVIDIA userspace input exceeds the safety limit.")?;
        output
            .write_all(&buffer[..count])
            .map_err(|e| format!("Could not write NVIDIA userspace input: {e}"))?;
        hasher.update(&buffer[..count]);
        if downloaded >= next_report {
            progress(stage, downloaded, total);
            next_report = downloaded.saturating_add(1024 * 1024);
        }
    }
    if downloaded == 0 || (total != 0 && downloaded != total) {
        return Err("NVIDIA userspace input download was incomplete.".into());
    }
    output
        .flush()
        .map_err(|e| format!("Could not finish NVIDIA userspace input: {e}"))?;
    progress(stage, downloaded, total);
    fs::rename(&partial, destination)
        .map_err(|e| format!("Could not finalize NVIDIA userspace input: {e}"))?;
    guard.armed = false;
    Ok(format!("{:x}", hasher.finalize()))
}

fn resolve_nvidia_userspace_for_version(
    runtime_dir: &Path,
    nvidia_version: &str,
    client: &reqwest::blocking::Client,
    cancel: &AtomicBool,
    progress: &impl Fn(&str, u64, u64),
) -> Result<NvidiaUserspaceResolution, String> {
    if !valid_numeric_version(nvidia_version, 2..=3) {
        return Err("Published NVIDIA artifact has an invalid userspace version.".into());
    }
    let output_dir = runtime_dir.join(format!(
        "nvidia-userspace-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    fs::create_dir(&output_dir)
        .map_err(|e| format!("Could not create NVIDIA userspace staging: {e}"))?;
    let mut output_guard = StagingDirectoryGuard {
        path: output_dir.clone(),
        armed: true,
    };
    let mut packages = Vec::new();
    for (package, package_limit, package_stage, signature_stage) in [
        (
            "nvidia-utils",
            NVIDIA_UTILS_ARCHIVE_LIMIT,
            "downloading-nvidia-utils",
            "downloading-nvidia-utils-signature",
        ),
        (
            "lib32-nvidia-utils",
            LIB32_NVIDIA_UTILS_ARCHIVE_LIMIT,
            "downloading-lib32-nvidia-utils",
            "downloading-lib32-nvidia-utils-signature",
        ),
    ] {
        if cancel.load(Ordering::Relaxed) {
            return Err("NVIDIA userspace resolution cancelled.".into());
        }
        let directory = arch_package_directory(package)?;
        progress("querying-arch-package-index", packages.len() as u64, 2);
        let index_response = client
            .get(format!("{directory}/"))
            .header("Accept", "text/html")
            .send()
            .map_err(|e| format!("Could not query the Arch Linux Archive for {package}: {e}"))?;
        let index_bytes = read_http_response_limited(
            index_response,
            ARCH_ARCHIVE_INDEX_LIMIT,
            &format!("{package} archive index"),
        )?;
        let index = std::str::from_utf8(&index_bytes)
            .map_err(|e| format!("{package} archive index is not UTF-8: {e}"))?;
        let (filename, full_version) =
            select_arch_userspace_package(index, package, nvidia_version)?;
        let signature_filename = format!("{filename}.sig");
        let package_path = output_dir.join(&filename);
        let signature_path = output_dir.join(&signature_filename);
        let package_sha256 = download_arch_userspace_asset(
            client,
            &format!("{directory}/{filename}"),
            &package_path,
            package_limit,
            cancel,
            package_stage,
            progress,
        )?;
        download_arch_userspace_asset(
            client,
            &format!("{directory}/{signature_filename}"),
            &signature_path,
            ARCH_PACKAGE_SIGNATURE_LIMIT,
            cancel,
            signature_stage,
            progress,
        )?;
        packages.push(NvidiaUserspacePackage {
            name: package.into(),
            filename,
            full_version,
            package_path: package_path.to_string_lossy().into_owned(),
            signature_path: signature_path.to_string_lossy().into_owned(),
            package_sha256,
        });
    }
    progress("querying-arch-package-index", 2, 2);
    let resolution = NvidiaUserspaceResolution {
        schema_version: 1,
        status: "prepared".into(),
        reason: "signed_packages_staged".into(),
        message: format!(
            "Staged exact NVIDIA {nvidia_version} userspace packages and detached signatures; trust remains pending x86 appliance verification."
        ),
        nvidia_version: nvidia_version.into(),
        signature_status: "pending-x86-validation".into(),
        packages,
    };
    output_guard.armed = false;
    Ok(resolution)
}

fn validate_pinned_installer_contract() -> Result<u64, String> {
    if NVIDIA_INSTALLER_COMMIT.len() != 40
        || !NVIDIA_INSTALLER_COMMIT
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("Pinned NVIDIA installer commit is invalid.".into());
    }
    let mut paths = HashSet::new();
    let mut total = 0_u64;
    for file in &PINNED_INSTALLER_FILES {
        let path = Path::new(file.path);
        if file.path.is_empty()
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || !paths.insert(file.path)
            || file.sha256.len() != 64
            || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || file.bytes == 0
        {
            return Err("Pinned NVIDIA installer file contract is invalid.".into());
        }
        total = total
            .checked_add(file.bytes)
            .ok_or("Pinned NVIDIA installer size overflowed.")?;
    }
    Ok(total)
}

fn download_pinned_installer_file(
    client: &reqwest::blocking::Client,
    file: &PinnedInstallerFile,
    destination: &Path,
    completed_before: u64,
    total_bytes: u64,
    cancel: &AtomicBool,
    progress: &impl Fn(&str, u64, u64),
) -> Result<(), String> {
    if destination.exists() {
        return Err(format!(
            "Refusing to overwrite a staged NVIDIA installer file: {}",
            destination.display()
        ));
    }
    let parent = destination
        .parent()
        .ok_or("Pinned NVIDIA installer path has no parent.")?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("Could not create NVIDIA installer directory: {e}"))?;
    let partial = destination.with_file_name(format!(
        ".{}.partial",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("Pinned NVIDIA installer filename is invalid.")?
    ));
    let mut partial_guard = PartialOutputGuard {
        path: partial.clone(),
        armed: true,
    };
    let url = format!(
        "https://raw.githubusercontent.com/{NVIDIA_SUPPORT_REPOSITORY}/{NVIDIA_INSTALLER_COMMIT}/{}",
        file.path
    );
    let mut response = client
        .get(url)
        .header("Accept", "application/octet-stream")
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| {
            format!(
                "Could not download pinned installer file {}: {e}",
                file.path
            )
        })?;
    if response
        .content_length()
        .is_some_and(|length| length != file.bytes)
    {
        return Err(format!(
            "Pinned installer file {} has an unexpected download size.",
            file.path
        ));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|e| format!("Could not stage pinned installer file {}: {e}", file.path))?;
    let mut hasher = Sha256::new();
    let mut downloaded = 0_u64;
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("NVIDIA installer bundle download cancelled.".into());
        }
        let count = response
            .read(&mut buffer)
            .map_err(|e| format!("Could not read pinned installer file {}: {e}", file.path))?;
        if count == 0 {
            break;
        }
        downloaded = downloaded
            .checked_add(count as u64)
            .filter(|value| *value <= file.bytes)
            .ok_or_else(|| format!("Pinned installer file {} is too large.", file.path))?;
        output
            .write_all(&buffer[..count])
            .map_err(|e| format!("Could not write pinned installer file {}: {e}", file.path))?;
        hasher.update(&buffer[..count]);
        progress(
            "downloading-nvidia-installer",
            completed_before + downloaded,
            total_bytes,
        );
    }
    if downloaded != file.bytes {
        return Err(format!(
            "Pinned installer file {} downloaded {downloaded} bytes; expected {}.",
            file.path, file.bytes
        ));
    }
    let digest = format!("{:x}", hasher.finalize());
    if digest != file.sha256 {
        return Err(format!(
            "Pinned installer file {} failed SHA-256 verification.",
            file.path
        ));
    }
    output
        .flush()
        .map_err(|e| format!("Could not finish pinned installer file {}: {e}", file.path))?;
    fs::rename(&partial, destination).map_err(|e| {
        format!(
            "Could not finalize pinned installer file {}: {e}",
            file.path
        )
    })?;
    partial_guard.armed = false;
    Ok(())
}

fn prepare_pinned_nvidia_installer_bundle(
    runtime_dir: &Path,
    client: &reqwest::blocking::Client,
    cancel: &AtomicBool,
    progress: &impl Fn(&str, u64, u64),
) -> Result<NvidiaInstallerBundleState, String> {
    let total_bytes = validate_pinned_installer_contract()?;
    let root = runtime_dir.join(format!("nvidia-installer-{NVIDIA_INSTALLER_COMMIT}"));
    fs::create_dir(&root)
        .map_err(|e| format!("Could not create pinned NVIDIA installer staging: {e}"))?;
    let mut root_guard = StagingDirectoryGuard {
        path: root.clone(),
        armed: true,
    };
    let mut completed = 0_u64;
    let mut files = Vec::new();
    for file in &PINNED_INSTALLER_FILES {
        let destination = root.join(file.path);
        download_pinned_installer_file(
            client,
            file,
            &destination,
            completed,
            total_bytes,
            cancel,
            progress,
        )?;
        completed += file.bytes;
        files.push(NvidiaInstallerBundleFile {
            path: file.path.into(),
            sha256: file.sha256.into(),
            bytes: file.bytes,
            executable: file.executable,
        });
    }
    let report = NvidiaInstallerBundle {
        schema_version: 1,
        status: "verified".into(),
        reason: "pinned_installer_verified".into(),
        message: format!(
            "Downloaded and verified the pinned offline installer from support commit {NVIDIA_INSTALLER_COMMIT}."
        ),
        repository: NVIDIA_SUPPORT_REPOSITORY.into(),
        commit: NVIDIA_INSTALLER_COMMIT.into(),
        files,
    };
    let manifest = serde_json::to_vec_pretty(&report)
        .map_err(|e| format!("Could not serialize NVIDIA installer manifest: {e}"))?;
    let manifest_path = root.join("installer-bundle.json");
    let staged_manifest = root.join(".installer-bundle.json.partial");
    fs::write(&staged_manifest, manifest)
        .map_err(|e| format!("Could not stage NVIDIA installer manifest: {e}"))?;
    fs::rename(staged_manifest, manifest_path)
        .map_err(|e| format!("Could not finalize NVIDIA installer manifest: {e}"))?;
    progress("downloading-nvidia-installer", total_bytes, total_bytes);
    root_guard.armed = false;
    Ok(NvidiaInstallerBundleState { root, report })
}

fn validate_staged_nvidia_installer_bundle(
    state: &NvidiaInstallerBundleState,
) -> Result<(), String> {
    if state.report.schema_version != 1
        || state.report.status != "verified"
        || state.report.repository != NVIDIA_SUPPORT_REPOSITORY
        || state.report.commit != NVIDIA_INSTALLER_COMMIT
        || state.report.files.len() != PINNED_INSTALLER_FILES.len()
    {
        return Err(
            "Staged NVIDIA installer manifest no longer matches the pinned contract.".into(),
        );
    }
    for pinned in &PINNED_INSTALLER_FILES {
        let path = state.root.join(pinned.path);
        let metadata = fs::symlink_metadata(&path).map_err(|e| {
            format!(
                "Could not inspect staged installer file {}: {e}",
                pinned.path
            )
        })?;
        if !metadata.file_type().is_file()
            || metadata.len() != pinned.bytes
            || sha256_file(&path)? != pinned.sha256
        {
            return Err(format!(
                "Staged NVIDIA installer file no longer matches its pin: {}.",
                pinned.path
            ));
        }
    }
    Ok(())
}

fn nvidia_development_asset_name(spec: &NvidiaTargetBuildSpec) -> String {
    let kernel_tag: String = spec
        .kernel_version
        .chars()
        .map(|character| match character {
            '/' | ' ' | ':' | '+' => '-',
            other => other,
        })
        .collect();
    format!(
        "nvidia-open-steamos-{}-nvidia-{}-k{}-x86_64.tar.gz",
        spec.steamos_version, spec.nvidia_version, kernel_tag
    )
}

fn validate_support_build_result(
    document: SupportBuildResult,
    spec: &NvidiaTargetBuildSpec,
) -> Result<(SupportBuildArtifact, String), String> {
    if document.schema_version != 1 {
        return Err(format!(
            "Unsupported NVIDIA build-result schema version {}.",
            document.schema_version
        ));
    }
    if document.target.steamos_version != spec.steamos_version
        || document.target.kernel_version != spec.kernel_version
        || document.target.nvidia_version != spec.nvidia_version
        || document.target.architecture != "x86_64"
    {
        return Err("NVIDIA build result does not match the requested target identity.".into());
    }
    if document.status != "success" {
        if document.artifact.is_some() {
            return Err("Failed NVIDIA build result unexpectedly contains an artifact.".into());
        }
        return Err(format!(
            "NVIDIA target build {} ({}): {}",
            document.status, document.reason, document.message
        ));
    }
    if document.reason != "build_complete" {
        return Err(format!(
            "Successful NVIDIA build result has unexpected reason {}.",
            document.reason
        ));
    }
    if !matches!(
        document.trust.as_str(),
        "development-unverified" | "locally-built-verified"
    ) {
        return Err(format!(
            "Local NVIDIA build returned unsupported trust classification {}.",
            document.trust
        ));
    }
    let artifact = document
        .artifact
        .ok_or("Successful NVIDIA build result omitted artifact metadata.")?;
    let asset_name = nvidia_development_asset_name(spec);
    let checksum_name = format!("{asset_name}.sha256");
    let build_info_name = format!("{}.build-info.txt", asset_name.trim_end_matches(".tar.gz"));
    let provenance_name = format!("{}.provenance.json", asset_name.trim_end_matches(".tar.gz"));
    if artifact.archive != asset_name
        || artifact.checksum != checksum_name
        || artifact.build_info != build_info_name
        || artifact.provenance != provenance_name
        || artifact.sha256.len() != 64
        || !artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("NVIDIA build result contains invalid artifact identity or hash data.".into());
    }
    Ok((artifact, document.trust))
}

fn validate_support_build_provenance(
    document: &SupportBuildProvenance,
    spec: &NvidiaTargetBuildSpec,
    trust: &str,
    approved_signer: &str,
) -> Result<(), String> {
    if document.schema_version != 1
        || document.trust != trust
        || document.target.steamos_version != spec.steamos_version
        || document.target.kernel_version != spec.kernel_version
        || document.target.nvidia_version != spec.nvidia_version
        || document.target.architecture != "x86_64"
        || document.artifact.archive != nvidia_development_asset_name(spec)
    {
        return Err("NVIDIA provenance does not match the accepted build result.".into());
    }
    if document.headers.signature_status != "verified"
        || document.headers.authentication != "detached-signature-verified-with-pinned-keyring"
        || (document.headers.signing_key_fingerprint != approved_signer
            && document.headers.primary_key_fingerprint != approved_signer)
    {
        return Err("NVIDIA provenance does not confirm the approved Valve signer.".into());
    }
    let expected_modules = [
        "nvidia-drm.ko",
        "nvidia-modeset.ko",
        "nvidia-peermem.ko",
        "nvidia-uvm.ko",
        "nvidia.ko",
    ];
    let mut module_names: Vec<&str> = document
        .modules
        .iter()
        .map(|module| module.name.as_str())
        .collect();
    module_names.sort_unstable();
    if module_names != expected_modules {
        return Err("NVIDIA provenance does not contain the exact five-module set.".into());
    }
    for module in &document.modules {
        if module.version != spec.nvidia_version
            || module.architecture != "x86_64"
            || module.vermagic.split_whitespace().next() != Some(spec.kernel_version.as_str())
            || module.sha256.len() != 64
            || !module.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(format!(
                "NVIDIA provenance contains invalid metadata for {}.",
                module.name
            ));
        }
    }
    Ok(())
}

fn run_guest_command_logged(
    session: &impl GuestConnection,
    command: &str,
    log_path: &Path,
    cancel: Option<&AtomicBool>,
) -> Result<(), String> {
    let log = File::create(log_path)
        .map_err(|e| format!("Could not create the NVIDIA target-build log: {e}"))?;
    let log_err = log
        .try_clone()
        .map_err(|e| format!("Could not prepare the NVIDIA target-build log: {e}"))?;
    let mut child = ssh_command(session)?
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|e| format!("Could not start the NVIDIA target build: {e}"))?;
    let status = loop {
        if cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed)) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("NVIDIA target build cancelled.".into());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("Could not inspect the NVIDIA target build: {e}"))?
        {
            break status;
        }
        thread::sleep(Duration::from_millis(500));
    };
    if status.success() {
        return Ok(());
    }
    let bytes = fs::read(log_path).unwrap_or_default();
    let start = bytes.len().saturating_sub(8 * 1024);
    let detail = String::from_utf8_lossy(&bytes[start..]).trim().to_string();
    Err(if detail.is_empty() {
        format!("NVIDIA target build exited with {status}.")
    } else {
        format!("NVIDIA target build exited with {status}: {detail}")
    })
}

fn build_nvidia_for_target(
    session: &impl GuestConnection,
    support_repository: &Path,
    output_dir: &Path,
    spec: &NvidiaTargetBuildSpec,
    cancel: Option<&AtomicBool>,
) -> Result<NvidiaDevelopmentArtifact, String> {
    validate_nvidia_target_build_spec(spec)?;
    let support_repository = fs::canonicalize(support_repository)
        .map_err(|e| format!("Could not resolve the NVIDIA support repository: {e}"))?;
    for required in [
        "bootstrap/build_for_target.sh",
        "bootstrap/prepare_valve_keyring.py",
        "lib/common.sh",
        "trust/valve-package-signers.json",
    ] {
        if !support_repository.join(required).is_file() {
            return Err(format!(
                "NVIDIA support repository is missing required file {required}."
            ));
        }
    }
    let trust_manifest: ValveTrustManifest = serde_json::from_reader(
        File::open(support_repository.join("trust/valve-package-signers.json"))
            .map_err(|e| format!("Could not read the Valve trust manifest: {e}"))?,
    )
    .map_err(|e| format!("Valve trust manifest is invalid JSON: {e}"))?;
    let approved_signer = trust_manifest
        .signers
        .first()
        .filter(|_| trust_manifest.schema_version == 1 && trust_manifest.signers.len() == 1)
        .map(|signer| signer.fingerprint.to_ascii_uppercase())
        .filter(|fingerprint| {
            matches!(fingerprint.len(), 40 | 64)
                && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .ok_or("Valve trust manifest must contain exactly one full approved signer fingerprint.")?;
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("Could not create the NVIDIA artifact output directory: {e}"))?;
    let output_dir = fs::canonicalize(output_dir)
        .map_err(|e| format!("Could not resolve the NVIDIA artifact output directory: {e}"))?;
    let asset_name = nvidia_development_asset_name(spec);
    let checksum_name = format!("{asset_name}.sha256");
    let build_info_name = format!("{}.build-info.txt", asset_name.trim_end_matches(".tar.gz"));
    let provenance_name = format!("{}.provenance.json", asset_name.trim_end_matches(".tar.gz"));
    let result_name = format!(
        "{}.build-result.json",
        asset_name.trim_end_matches(".tar.gz")
    );
    for name in [
        &asset_name,
        &checksum_name,
        &build_info_name,
        &provenance_name,
        &result_name,
    ] {
        if output_dir.join(name).exists() {
            return Err(format!(
                "Refusing to overwrite an existing NVIDIA artifact: {}",
                output_dir.join(name).display()
            ));
        }
    }

    let transfer_archive = session.runtime_dir().join("support-repository.tar.gz");
    run_checked(
        Command::new("tar")
            // Prevent macOS tar from adding AppleDouble/xattr headers that GNU tar
            // reports as unknown while unpacking the checkout in Fedora.
            .env("COPYFILE_DISABLE", "1")
            .args(["--no-xattrs", "-czf"])
            .arg(&transfer_archive)
            .args(["--exclude", ".git", "--exclude", "target", "-C"])
            .arg(&support_repository)
            .arg("."),
        "Could not package the NVIDIA support repository",
    )?;
    run_checked(
        scp_command(session)?
            .arg(&transfer_archive)
            .arg("builder@127.0.0.1:/tmp/steamos-nvidia-support.tar.gz"),
        "Could not copy the NVIDIA support repository into the x86 guest",
    )?;
    let build_command = format!(
        r#"set -eu; rm -rf /tmp/steamos-nvidia-support /tmp/steamos-nvidia-artifacts; mkdir -p /tmp/steamos-nvidia-support /tmp/steamos-nvidia-artifacts; tar -xzf /tmp/steamos-nvidia-support.tar.gz -C /tmp/steamos-nvidia-support; cd /tmp/steamos-nvidia-support; sudo dnf install -y bsdtar gnupg2 python3; python3 ./bootstrap/prepare_valve_keyring.py --output /tmp/steamos-nvidia-artifacts/valve-package-signers.gpg; signer="$(python3 -c 'import json; data=json.load(open("trust/valve-package-signers.json", encoding="utf-8")); signers=data["signers"]; assert data["schemaVersion"] == 1 and len(signers) == 1; print(signers[0]["fingerprint"])')"; bash ./bootstrap/build_for_target.sh --steamos {} --kernel {} --nvidia {} --architecture x86_64 --install-dependencies --output /tmp/steamos-nvidia-artifacts --result-json /tmp/steamos-nvidia-artifacts/build-result.json --header-keyring /tmp/steamos-nvidia-artifacts/valve-package-signers.gpg --header-signer "$signer""#,
        spec.steamos_version, spec.kernel_version, spec.nvidia_version
    );
    let execution_result = run_guest_command_logged(
        session,
        &build_command,
        &session.runtime_dir().join("nvidia-build.log"),
        cancel,
    );

    let staged_result = session.runtime_dir().join("nvidia-build-result.json");
    let result_transfer = run_checked(
        scp_command(session)?
            .arg("builder@127.0.0.1:/tmp/steamos-nvidia-artifacts/build-result.json")
            .arg(&staged_result),
        "Could not copy the NVIDIA build result from the x86 guest",
    );
    if let Err(transfer_error) = result_transfer {
        return Err(execution_result.err().unwrap_or(transfer_error));
    }
    let result_document: SupportBuildResult = serde_json::from_reader(
        File::open(&staged_result)
            .map_err(|e| format!("Could not read the NVIDIA build result: {e}"))?,
    )
    .map_err(|e| format!("NVIDIA build result is invalid JSON: {e}"))?;
    let (result_artifact, result_trust) = validate_support_build_result(result_document, spec)?;
    execution_result?;

    let download_dir = session.runtime_dir().join("artifact-download");
    fs::create_dir_all(&download_dir)
        .map_err(|e| format!("Could not create the artifact download staging directory: {e}"))?;
    for name in [
        &asset_name,
        &checksum_name,
        &build_info_name,
        &provenance_name,
    ] {
        run_checked(
            scp_command(session)?
                .arg(format!(
                    "builder@127.0.0.1:/tmp/steamos-nvidia-artifacts/{name}"
                ))
                .arg(&download_dir),
            "Could not copy a generated NVIDIA artifact from the x86 guest",
        )?;
    }

    let staged_archive = download_dir.join(&asset_name);
    let staged_checksum = download_dir.join(&checksum_name);
    let staged_build_info = download_dir.join(&build_info_name);
    let staged_provenance = download_dir.join(&provenance_name);
    let expected_sha256 = fs::read_to_string(&staged_checksum)
        .map_err(|e| format!("Could not read the NVIDIA artifact checksum: {e}"))?
        .split_whitespace()
        .next()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("Generated NVIDIA artifact checksum is invalid.")?
        .to_ascii_lowercase();
    let archive_sha256 = sha256_file(&staged_archive)?;
    if archive_sha256 != expected_sha256 {
        return Err("Generated NVIDIA artifact checksum verification failed.".into());
    }
    if archive_sha256 != result_artifact.sha256.to_ascii_lowercase() {
        return Err("NVIDIA build-result hash does not match the returned archive.".into());
    }
    let listing = Command::new("tar")
        .args(["-tzf"])
        .arg(&staged_archive)
        .output()
        .map_err(|e| format!("Could not inspect the generated NVIDIA archive: {e}"))?;
    if !listing.status.success() {
        return Err("Generated NVIDIA artifact is not a readable tar.gz archive.".into());
    }
    let entries = String::from_utf8_lossy(&listing.stdout);
    let expected_modules = [
        "modules/nvidia-drm.ko",
        "modules/nvidia-modeset.ko",
        "modules/nvidia-peermem.ko",
        "modules/nvidia-uvm.ko",
        "modules/nvidia.ko",
    ];
    for entry in entries.lines() {
        if entry.starts_with('/')
            || entry == ".."
            || entry.starts_with("../")
            || entry.contains("/../")
            || entry.ends_with("/..")
        {
            return Err("Generated NVIDIA artifact contains an unsafe path.".into());
        }
        let allowed = entry == "modules/"
            || entry == "BUILD-INFO.txt"
            || entry == "PROVENANCE.json"
            || expected_modules.contains(&entry);
        if !allowed {
            return Err(format!(
                "Generated NVIDIA artifact contains an unexpected entry: {entry}"
            ));
        }
    }
    if !expected_modules
        .iter()
        .all(|expected| entries.lines().any(|entry| entry == *expected))
        || !entries.lines().any(|entry| entry == "BUILD-INFO.txt")
        || !entries.lines().any(|entry| entry == "PROVENANCE.json")
    {
        return Err("Generated NVIDIA artifact is missing required modules or metadata.".into());
    }
    let build_info = fs::read_to_string(&staged_build_info)
        .map_err(|e| format!("Could not read generated NVIDIA build metadata: {e}"))?;
    let archived_build_info = Command::new("tar")
        .args(["-xOzf"])
        .arg(&staged_archive)
        .arg("BUILD-INFO.txt")
        .output()
        .map_err(|e| format!("Could not extract NVIDIA archive metadata: {e}"))?;
    if !archived_build_info.status.success()
        || archived_build_info.stdout.as_slice() != build_info.as_bytes()
    {
        return Err("NVIDIA archive metadata does not match its external build-info file.".into());
    }
    let metadata = |key: &str| {
        build_info
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
    };
    if metadata("steamos_version") != Some(spec.steamos_version.as_str())
        || metadata("kernel_version") != Some(spec.kernel_version.as_str())
        || metadata("nvidia_version") != Some(spec.nvidia_version.as_str())
        || metadata("build_architecture") != Some("x86_64")
        || metadata("trust_classification") != Some(result_trust.as_str())
        || metadata("header_authentication")
            != Some("detached-signature-verified-with-pinned-keyring")
        || metadata("header_signature_status") != Some("verified")
    {
        return Err(
            "Generated NVIDIA artifact metadata does not match the requested target.".into(),
        );
    }
    let provenance_bytes = fs::read(&staged_provenance)
        .map_err(|e| format!("Could not read generated NVIDIA provenance: {e}"))?;
    let archived_provenance = Command::new("tar")
        .args(["-xOzf"])
        .arg(&staged_archive)
        .arg("PROVENANCE.json")
        .output()
        .map_err(|e| format!("Could not extract NVIDIA archive provenance: {e}"))?;
    if !archived_provenance.status.success()
        || archived_provenance.stdout.as_slice() != provenance_bytes.as_slice()
    {
        return Err("NVIDIA archive provenance does not match its external sidecar file.".into());
    }
    let provenance: SupportBuildProvenance = serde_json::from_slice(&provenance_bytes)
        .map_err(|e| format!("NVIDIA provenance is invalid JSON: {e}"))?;
    validate_support_build_provenance(&provenance, spec, &result_trust, &approved_signer)?;
    for module in &provenance.modules {
        let archived_module = Command::new("tar")
            .args(["-xOzf"])
            .arg(&staged_archive)
            .arg(format!("modules/{}", module.name))
            .output()
            .map_err(|e| format!("Could not extract {} for verification: {e}", module.name))?;
        if !archived_module.status.success()
            || format!("{:x}", Sha256::digest(&archived_module.stdout))
                != module.sha256.to_ascii_lowercase()
        {
            return Err(format!(
                "Archived NVIDIA module does not match provenance: {}.",
                module.name
            ));
        }
    }

    let final_archive = output_dir.join(&asset_name);
    let final_checksum = output_dir.join(&checksum_name);
    let final_build_info = output_dir.join(&build_info_name);
    let final_provenance = output_dir.join(&provenance_name);
    let final_result = output_dir.join(&result_name);
    let mut archive_guard = PartialOutputGuard {
        path: final_archive.clone(),
        armed: true,
    };
    let mut checksum_guard = PartialOutputGuard {
        path: final_checksum.clone(),
        armed: true,
    };
    let mut build_info_guard = PartialOutputGuard {
        path: final_build_info.clone(),
        armed: true,
    };
    let mut provenance_guard = PartialOutputGuard {
        path: final_provenance.clone(),
        armed: true,
    };
    let mut result_guard = PartialOutputGuard {
        path: final_result.clone(),
        armed: true,
    };
    copy_new_file(
        &staged_archive,
        &final_archive,
        "Could not finalize the NVIDIA archive",
    )?;
    copy_new_file(
        &staged_checksum,
        &final_checksum,
        "Could not finalize the NVIDIA checksum",
    )?;
    copy_new_file(
        &staged_build_info,
        &final_build_info,
        "Could not finalize the NVIDIA build metadata",
    )?;
    copy_new_file(
        &staged_provenance,
        &final_provenance,
        "Could not finalize the NVIDIA provenance",
    )?;
    copy_new_file(
        &staged_result,
        &final_result,
        "Could not finalize the NVIDIA build result",
    )?;
    archive_guard.armed = false;
    checksum_guard.armed = false;
    build_info_guard.armed = false;
    provenance_guard.armed = false;
    result_guard.armed = false;
    Ok(NvidiaDevelopmentArtifact {
        archive_path: final_archive.to_string_lossy().into_owned(),
        checksum_path: final_checksum.to_string_lossy().into_owned(),
        build_info_path: final_build_info.to_string_lossy().into_owned(),
        provenance_path: final_provenance.to_string_lossy().into_owned(),
        result_path: final_result.to_string_lossy().into_owned(),
        archive_sha256,
        steamos_version: spec.steamos_version.clone(),
        kernel_version: spec.kernel_version.clone(),
        nvidia_version: spec.nvidia_version.clone(),
        trust: result_trust,
    })
}

fn run_transfer_proof(session: &impl GuestConnection) -> Result<TransferProof, String> {
    const PROBE: &[u8] = b"STEAMOS_BUILDER_TRANSFER_PROBE_V1\n";
    const GUEST_INPUT: &str = "/tmp/steamos-builder-transfer-probe.in";
    const GUEST_OUTPUT: &str = "/tmp/steamos-builder-transfer-probe.out";
    let host_input = session.runtime_dir().join("transfer-probe.in");
    let host_output = session.runtime_dir().join("transfer-probe.out");
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

fn inspect_synthetic_disk(
    session: &impl GuestConnection,
) -> Result<SyntheticDiskInspection, String> {
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

fn discover_steamos_layout(
    partition_table: Option<&str>,
    nodes: &[ImageNodeInspection],
) -> SteamOsLayoutDiscovery {
    const ESP_TYPE: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
    const BASIC_DATA_TYPE: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
    const ROOT_X86_64_TYPE: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
    const VAR_TYPE: &str = "4d21b016-b534-45c2-a9fb-5c16e091fd2d";
    const HOME_TYPE: &str = "933ac7e1-2eb4-4f13-b844-0e14e2aef915";

    let expected = [
        ("esp", "vfat", "esp", "esp", ESP_TYPE),
        ("efi", "vfat", "efi", "efi-a", BASIC_DATA_TYPE),
        ("rootfs", "btrfs", "rootfs", "rootfs-a", ROOT_X86_64_TYPE),
        ("var", "ext4", "var", "var-a", VAR_TYPE),
        ("home", "ext4", "home", "home", HOME_TYPE),
    ];
    let mut roles = Vec::new();
    let mut issues = Vec::new();
    if partition_table != Some("gpt") {
        issues.push("Expected a GPT partition table.".into());
    }
    if nodes.iter().any(|node| node.mounted) {
        issues.push("At least one image filesystem is already mounted.".into());
    }
    for (role, filesystem, filesystem_label, partition_label, partition_type) in expected {
        let matches = nodes
            .iter()
            .filter(|node| {
                node.node_type == "part"
                    && node
                        .filesystem
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(filesystem))
                    && node
                        .filesystem_label
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(filesystem_label))
                    && node
                        .partition_label
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(partition_label))
                    && node
                        .partition_type
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(partition_type))
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            issues.push(format!(
                "Expected exactly one {role} partition, found {}.",
                matches.len()
            ));
            continue;
        }
        let node = matches[0];
        roles.push(SteamOsPartitionRole {
            role: role.into(),
            path: node.path.clone(),
            size_bytes: node.size_bytes,
            filesystem: filesystem.into(),
            filesystem_label: filesystem_label.into(),
            partition_label: partition_label.into(),
            partition_type: partition_type.into(),
        });
    }
    let recognized = issues.is_empty() && roles.len() == expected.len();
    SteamOsLayoutDiscovery {
        recognized,
        scheme: recognized.then(|| "valve-recovery-a".into()),
        roles,
        issues,
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
    let partition_table = (!partition_table.is_empty()).then_some(partition_table);
    let layout = discover_steamos_layout(partition_table.as_deref(), &nodes);
    Ok(UserImageInspection {
        device: DEVICE.into(),
        disk_bytes,
        read_only,
        partition_table,
        nodes,
        source_sha256_before: session.input_sha256_before.clone(),
        source_sha256_after,
        source_unchanged,
        image_sha256_before: session.attached_sha256_before.clone(),
        image_sha256_after,
        image_unchanged,
        input: session.input_preparation.clone(),
        layout,
    })
}

fn verify_user_working_image(
    session: &impl GuestConnection,
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

fn mutate_synthetic_marker(session: &impl GuestConnection) -> Result<MarkerMutation, String> {
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
for attempt in $(seq 1 30); do
  test -b "$WORK_PART" && break
  sudo blockdev --rereadpt "$WORK" 2>/dev/null || true
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

fn normalize_os_release_field(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let unquoted = if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    };
    (!unquoted.is_empty()).then(|| unquoted.to_string())
}

fn mutate_user_marker(session: &ImageInspectionSession) -> Result<UserMarkerMutation, String> {
    const MARKER_PATH: &str = "/etc/steamos-nvidia-image-builder-test";
    const MARKER_CONTENT: &str =
        "SteamOS NVIDIA Image Builder marker\nprotocol=1\nmilestone=marker-only\n";
    const PREFLIGHT_COMMAND: &str = r#"set -eu
SOURCE=/dev/disk/by-id/virtio-steamos-user-input
WORK=/dev/disk/by-id/virtio-steamos-user-working
test -b "$SOURCE"
test -b "$WORK"
test "$(sudo blockdev --getro "$SOURCE")" = 1
test "$(sudo blockdev --getro "$WORK")" = 0
if lsblk -nr -o MOUNTPOINTS "$SOURCE" | grep -q '[^[:space:]]' || lsblk -nr -o MOUNTPOINTS "$WORK" | grep -q '[^[:space:]]'; then
  echo 'A selected-image device was unexpectedly mounted before mutation.' >&2
  exit 1
fi"#;
    run_guest_command(session, PREFLIGHT_COMMAND)?;
    qmp_remove_user_input(session)?;
    const MUTATE_COMMAND: &str = r#"set -eu
SOURCE=/dev/disk/by-id/virtio-steamos-user-input
WORK=/dev/disk/by-id/virtio-steamos-user-working
MOUNT_DIR=/mnt/steamos-user-marker
EXPECTED=$(printf 'SteamOS NVIDIA Image Builder marker\nprotocol=1\nmilestone=marker-only')
for attempt in $(seq 1 150); do
  test ! -b "$SOURCE" && break
  sleep 0.1
done
if test -b "$SOURCE"; then
  echo 'The read-only source device did not finish detaching within 15 seconds.' >&2
  exit 1
fi
test -b "$WORK"
TARGETS=$(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "rootfs-A" && $3 == "btrfs" { print $1 }')
test "$(printf '%s\n' "$TARGETS" | sed '/^$/d' | wc -l | tr -d ' ')" = 1
TARGET=$(printf '%s\n' "$TARGETS" | sed '/^$/d')
sudo mkdir -p "$MOUNT_DIR"
WAS_SEEDING=0
SEEDING_RESTORED=0
SOURCE_ROOT=
RESTORE_SOURCE_RO=0
cleanup_marker() {
  if findmnt -rn -M "$MOUNT_DIR" >/dev/null 2>&1 && test "$RESTORE_SOURCE_RO" = 1 && test -n "$SOURCE_ROOT"; then
    sudo btrfs property set -f -ts "$SOURCE_ROOT" ro true >/dev/null 2>&1 || true
  fi
  findmnt -rn -M "$MOUNT_DIR" >/dev/null 2>&1 && sudo umount "$MOUNT_DIR" || true
  if test "$WAS_SEEDING" = 1 && test "$SEEDING_RESTORED" = 0; then
    sudo btrfstune -f -S 1 "$TARGET" >/dev/null 2>&1 || true
  fi
  sudo blockdev --setro "$WORK" >/dev/null 2>&1 || true
}
trap cleanup_marker EXIT
sudo mount -o rw,subvolid=5 "$TARGET" "$MOUNT_DIR"
if findmnt -rn -M "$MOUNT_DIR" -o OPTIONS | tr ',' '\n' | grep -qx ro; then
  sudo umount "$MOUNT_DIR"
  sudo btrfstune -f -S 0 "$TARGET"
  WAS_SEEDING=1
  sudo mount -o rw,subvolid=5 "$TARGET" "$MOUNT_DIR"
fi
findmnt -rn -M "$MOUNT_DIR" -o OPTIONS | tr ',' '\n' | grep -qx rw
DEFAULT_INFO=$(sudo btrfs subvolume get-default "$MOUNT_DIR")
DEFAULT_PATH=$(printf '%s\n' "$DEFAULT_INFO" | sed -n 's/^.* path //p')
if test -z "$DEFAULT_PATH" && printf '%s\n' "$DEFAULT_INFO" | grep -q '^ID 5 (FS_TREE)$'; then
  DEFAULT_PATH='<FS_TREE>'
fi
test -n "$DEFAULT_PATH"
case "$DEFAULT_PATH" in
  '<FS_TREE>') SOURCE_ROOT="$MOUNT_DIR"; SNAPSHOT_ROOT= ;;
  /*|*..*) echo 'Unsafe Btrfs default subvolume path.' >&2; exit 1 ;;
  *) SOURCE_ROOT="$MOUNT_DIR/$DEFAULT_PATH"; SNAPSHOT_ROOT="$MOUNT_DIR/steamos-nvidia-marker-root" ;;
esac
if test ! -d "$SOURCE_ROOT"; then
  echo 'The Btrfs default root subvolume path is unavailable.' >&2
  exit 1
fi
SOURCE_ROOT_RO=$(sudo btrfs property get -ts "$SOURCE_ROOT" ro | awk -F= '$1 == "ro" { print $2 }')
test "$SOURCE_ROOT_RO" = true || test "$SOURCE_ROOT_RO" = false
if test "$SOURCE_ROOT_RO" = true; then
  sudo btrfs property set -f -ts "$SOURCE_ROOT" ro false
  RESTORE_SOURCE_RO=1
fi
if test -n "$SNAPSHOT_ROOT"; then
  test ! -e "$SNAPSHOT_ROOT"
  sudo btrfs subvolume snapshot "$SOURCE_ROOT" "$SNAPSHOT_ROOT" >/dev/null
  MUTATION_ROOT="$SNAPSHOT_ROOT"
else
  MUTATION_ROOT="$SOURCE_ROOT"
fi
release_value() {
  RELEASE_FILE="$1"
  RELEASE_KEY="$2"
  if test -f "$RELEASE_FILE"; then
    sudo awk -F= -v wanted="$RELEASE_KEY" '$1 == wanted { sub(/^[^=]*=/, ""); print; exit }' "$RELEASE_FILE" \
      | tr '\r\n' '  ' | cut -c1-512
  fi
}
OS_RELEASE="$MUTATION_ROOT/etc/os-release"
if test ! -f "$OS_RELEASE" || test -L "$OS_RELEASE"; then
  OS_RELEASE="$MUTATION_ROOT/usr/lib/os-release"
fi
if test ! -f "$OS_RELEASE" || test -L "$OS_RELEASE"; then
  OS_RELEASE=
fi
OS_ID=$(release_value "$OS_RELEASE" ID)
OS_PRETTY_NAME=$(release_value "$OS_RELEASE" PRETTY_NAME)
OS_VERSION_ID=$(release_value "$OS_RELEASE" VERSION_ID)
OS_BUILD_ID=$(release_value "$OS_RELEASE" BUILD_ID)
OS_VARIANT_ID=$(release_value "$OS_RELEASE" VARIANT_ID)
TARGET_ARCH=unknown
for ELF_PATH in "$MUTATION_ROOT/usr/bin/bash" "$MUTATION_ROOT/bin/bash"; do
  if test -f "$ELF_PATH" && test ! -L "$ELF_PATH"; then
    ELF_MACHINE=$(sudo od -An -t u2 -j 18 -N 2 "$ELF_PATH" | tr -d '[:space:]')
    case "$ELF_MACHINE" in
      62) TARGET_ARCH=x86_64 ;;
      183) TARGET_ARCH=aarch64 ;;
    esac
    break
  fi
done
KERNELS=
for MODULE_ROOT in "$MUTATION_ROOT/usr/lib/modules"; do
  if test -d "$MODULE_ROOT" && test ! -L "$MODULE_ROOT"; then
    KERNELS=$(sudo find "$MODULE_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' \
      | LC_ALL=C sort -u | awk '/^[A-Za-z0-9._+:-]+$/ { print }' | head -32)
    test -n "$KERNELS" && break
  fi
done
sudo mkdir -p "$MUTATION_ROOT/etc"
printf 'SteamOS NVIDIA Image Builder marker\nprotocol=1\nmilestone=marker-only\n' | sudo tee "$MUTATION_ROOT/etc/steamos-nvidia-image-builder-test" >/dev/null
sync
test "$(sudo cat "$MUTATION_ROOT/etc/steamos-nvidia-image-builder-test")" = "$EXPECTED"
if test "$RESTORE_SOURCE_RO" = 1; then
  sudo btrfs property set -f -ts "$SOURCE_ROOT" ro true
  RESTORE_SOURCE_RO=0
fi
if test -n "$SNAPSHOT_ROOT"; then
  sudo btrfs property set -ts "$SNAPSHOT_ROOT" ro true
  test "$(sudo btrfs property get -ts "$SNAPSHOT_ROOT" ro | awk -F= '$1 == "ro" { print $2 }')" = true
  sudo btrfs subvolume set-default "$SNAPSHOT_ROOT"
fi
sudo umount "$MOUNT_DIR"
if test "$WAS_SEEDING" = 1; then
  sudo btrfstune -f -S 1 "$TARGET"
  SEEDING_RESTORED=1
fi
sudo blockdev --setro "$WORK"
sudo mount -o ro "$TARGET" "$MOUNT_DIR"
test "$(sudo cat "$MOUNT_DIR/etc/steamos-nvidia-image-builder-test")" = "$EXPECTED"
if test -n "$SNAPSHOT_ROOT"; then
  test "$(sudo btrfs property get -ts "$MOUNT_DIR" ro | awk -F= '$1 == "ro" { print $2 }')" = true
fi
sudo umount "$MOUNT_DIR"
trap - EXIT
MOUNTED=0
findmnt -rn -S "$TARGET" >/dev/null 2>&1 && MOUNTED=1
printf 'TARGET=%s\n' "$TARGET"
printf 'PARTITION_LABEL=%s\n' "$(sudo blkid -s PARTLABEL -o value "$TARGET")"
printf 'FILESYSTEM=%s\n' "$(sudo blkid -s TYPE -o value "$TARGET")"
printf 'WORKING_READ_ONLY=%s\n' "$(sudo blockdev --getro "$WORK")"
printf 'MOUNTED=%s\n' "$MOUNTED"
printf 'OS_ID=%s\n' "$OS_ID"
printf 'OS_PRETTY_NAME=%s\n' "$OS_PRETTY_NAME"
printf 'OS_VERSION_ID=%s\n' "$OS_VERSION_ID"
printf 'OS_BUILD_ID=%s\n' "$OS_BUILD_ID"
printf 'OS_VARIANT_ID=%s\n' "$OS_VARIANT_ID"
printf 'TARGET_ARCH=%s\n' "$TARGET_ARCH"
printf '%s\n' "$KERNELS" | while IFS= read -r KERNEL; do
  test -n "$KERNEL" && printf 'KERNEL=%s\n' "$KERNEL"
done
test "$(sudo blockdev --getro "$WORK")" = 1
test "$MOUNTED" = 0"#;
    let output = run_guest_command(session, MUTATE_COMMAND)?;
    let mut values = std::collections::HashMap::new();
    let mut kernel_versions = Vec::new();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key == "KERNEL" {
                if !value.is_empty() && !kernel_versions.iter().any(|kernel| kernel == value) {
                    kernel_versions.push(value.to_string());
                }
            } else {
                values.insert(key, value);
            }
        }
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("Selected-image marker mutation omitted {key}."))
    };
    let input_sha256_after = sha256_file_with_progress(
        &session.input_image,
        "verifying-source-after-mutation",
        None,
        None,
    )?;
    let input_unchanged = session.input_sha256_before == input_sha256_after;
    if !input_unchanged {
        return Err(format!(
            "Selected input changed during working-layer mutation (before {}, after {}).",
            session.input_sha256_before, input_sha256_after
        ));
    }
    let optional_release = |key: &str| {
        values
            .get(key)
            .and_then(|value| normalize_os_release_field(value))
    };
    let system = TargetSystemDiscovery {
        os_id: optional_release("OS_ID"),
        pretty_name: optional_release("OS_PRETTY_NAME"),
        version_id: optional_release("OS_VERSION_ID"),
        build_id: optional_release("OS_BUILD_ID"),
        variant_id: optional_release("OS_VARIANT_ID"),
        architecture: required("TARGET_ARCH")?.to_string(),
        kernel_versions,
    };
    Ok(UserMarkerMutation {
        marker_path: MARKER_PATH.into(),
        marker_content: MARKER_CONTENT.into(),
        target_partition: required("TARGET")?.to_string(),
        target_partition_label: required("PARTITION_LABEL")?.to_string(),
        filesystem: required("FILESYSTEM")?.to_string(),
        input_sha256_before: session.input_sha256_before.clone(),
        input_sha256_after,
        input_unchanged,
        working_read_only: required("WORKING_READ_ONLY")? == "1",
        mounted: required("MOUNTED")? == "1",
        system,
    })
}

fn output_path_for_input(input: &Path, nvidia_installed: bool) -> Result<PathBuf, String> {
    let parent = input
        .parent()
        .ok_or("Could not determine the selected image folder.")?;
    let filename = input
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("The selected image filename is not valid UTF-8.")?;
    let mut base = filename.to_string();
    for suffix in [".bz2", ".gz", ".xz", ".img"] {
        if base.to_ascii_lowercase().ends_with(suffix) {
            base.truncate(base.len() - suffix.len());
        }
    }
    if base.is_empty() {
        base = "SteamOS".into();
    }
    loop {
        let lower = base.to_ascii_lowercase();
        let suffix = ["-marker", "-nvidia"]
            .into_iter()
            .find(|suffix| lower.ends_with(suffix));
        let Some(suffix) = suffix else { break };
        base.truncate(base.len() - suffix.len());
    }
    if base.is_empty() {
        base = "SteamOS".into();
    }
    let output_base = format!(
        "{base}-{}",
        if nvidia_installed { "nvidia" } else { "marker" }
    );
    for number in 1..=9999_u32 {
        let suffix = if number == 1 {
            String::new()
        } else {
            format!("-{number}")
        };
        let candidate = parent.join(format!("{output_base}{suffix}.img"));
        if !candidate.exists() && !manifest_path_for_output(&candidate).exists() {
            return Ok(candidate);
        }
    }
    Err("Could not choose an unused output filename.".into())
}

fn manifest_path_for_output(output: &Path) -> PathBuf {
    let mut path = output.as_os_str().to_os_string();
    path.push(".manifest.json");
    PathBuf::from(path)
}

fn write_json_file(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("Could not create build manifest: {e}"))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)
        .map_err(|e| format!("Could not serialize build manifest: {e}"))?;
    writer
        .write_all(b"\n")
        .and_then(|_| writer.flush())
        .and_then(|_| writer.get_ref().sync_all())
        .map_err(|e| format!("Could not finish build manifest: {e}"))
}

fn parse_qemu_img_progress(line: &str) -> Option<f64> {
    let end = line.rfind("/100%)")?;
    let start = line[..end].rfind('(')? + 1;
    line[start..end].trim().parse::<f64>().ok()
}

fn convert_working_image(
    qemu_img: &Path,
    source: &Path,
    destination: &Path,
    virtual_bytes: u64,
    progress: Option<&ProgressCallback<'_>>,
    cancel: Option<&AtomicBool>,
) -> Result<(), String> {
    let mut child = Command::new(qemu_img)
        .args(["convert", "-p", "-f", "qcow2", "-O", "raw"])
        .arg(source)
        .arg(destination)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not start raw-image export: {e}"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or("Could not monitor raw-image export progress.")?;
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut buffer = [0_u8; 1024];
        let mut pending = String::new();
        let mut detail = String::new();
        loop {
            match stderr.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    let chunk = String::from_utf8_lossy(&buffer[..count]);
                    detail.push_str(&chunk);
                    pending.push_str(&chunk);
                    while let Some(index) = pending.find(['\r', '\n']) {
                        let line = pending[..index].to_string();
                        pending.drain(..=index);
                        if let Some(percent) = parse_qemu_img_progress(&line) {
                            let _ = sender.send(percent);
                        }
                    }
                }
                Err(error) => {
                    detail.push_str(&format!("\nCould not read export progress: {error}"));
                    break;
                }
            }
        }
        if let Some(percent) = parse_qemu_img_progress(&pending) {
            let _ = sender.send(percent);
        }
        detail
    });
    let status = loop {
        if cancel.is_some_and(|value| value.load(Ordering::Relaxed)) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err("Image export cancelled.".into());
        }
        while let Ok(percent) = receiver.try_recv() {
            if let Some(progress) = progress {
                let processed = ((percent / 100.0) * virtual_bytes as f64) as u64;
                progress(
                    "exporting-image",
                    processed.min(virtual_bytes),
                    virtual_bytes,
                );
            }
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("Could not inspect raw-image export: {e}"))?
        {
            break status;
        }
        thread::sleep(Duration::from_millis(150));
    };
    let detail = reader
        .join()
        .map_err(|_| "Raw-image export progress worker failed.".to_string())?;
    if !status.success() {
        return Err(if detail.trim().is_empty() {
            format!("Raw-image export failed with {status}.")
        } else {
            format!("Raw-image export failed: {}", detail.trim())
        });
    }
    if let Some(progress) = progress {
        progress("exporting-image", virtual_bytes, virtual_bytes);
    }
    let output =
        File::open(destination).map_err(|e| format!("Could not open the exported image: {e}"))?;
    output
        .sync_all()
        .map_err(|e| format!("Could not flush the exported image: {e}"))
}

fn verify_marker_from_validation_overlay(session: &ImageInspectionSession) -> Result<(), String> {
    qmp_remove_user_input(session)?;
    const VERIFY_COMMAND: &str = r#"set -eu
SOURCE=/dev/disk/by-id/virtio-steamos-user-input
WORK=/dev/disk/by-id/virtio-steamos-user-working
MOUNT_DIR=/mnt/steamos-export-validation
EXPECTED=$(printf 'SteamOS NVIDIA Image Builder marker\nprotocol=1\nmilestone=marker-only')
for attempt in $(seq 1 150); do
  test ! -b "$SOURCE" && break
  sleep 0.1
done
if test -b "$SOURCE"; then
  echo 'The exported-image source device did not finish detaching within 15 seconds.' >&2
  exit 1
fi
test -b "$WORK"
TARGETS=$(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "rootfs-A" && $3 == "btrfs" { print $1 }')
test "$(printf '%s\n' "$TARGETS" | sed '/^$/d' | wc -l | tr -d ' ')" = 1
TARGET=$(printf '%s\n' "$TARGETS" | sed '/^$/d')
sudo blockdev --setro "$WORK"
sudo mkdir -p "$MOUNT_DIR"
cleanup_validation() {
  findmnt -rn -M "$MOUNT_DIR" >/dev/null 2>&1 && sudo umount "$MOUNT_DIR" || true
}
trap cleanup_validation EXIT
sudo mount -o ro "$TARGET" "$MOUNT_DIR"
test "$(sudo cat "$MOUNT_DIR/etc/steamos-nvidia-image-builder-test")" = "$EXPECTED"
sudo umount "$MOUNT_DIR"
trap - EXIT
test "$(sudo blockdev --getro "$WORK")" = 1
! findmnt -rn -S "$TARGET" >/dev/null 2>&1"#;
    run_guest_command(session, VERIFY_COMMAND).map(|_| ())
}

fn verify_nvidia_from_validation_overlay(
    session: &ImageInspectionSession,
    installation: &NvidiaInstallHandoffResult,
) -> Result<(), String> {
    let command = format!(
        r#"set -euo pipefail
WORK=/dev/disk/by-id/virtio-steamos-user-working
ROOT=/mnt/steamos-nvidia-export-root
test -b "$WORK"
test "$(sudo blockdev --getro "$WORK")" = 1
mapfile -t ROOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "rootfs-A" && $3 == "btrfs" {{print $1}}')
mapfile -t BOOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "efi-A" && ($3 == "vfat" || $3 == "fat") {{print $1}}')
test "${{#ROOT_PARTS[@]}}" -eq 1
test "${{#BOOT_PARTS[@]}}" -eq 1
sudo mkdir -p "$ROOT"
ROOT_MOUNTED=0
BOOT_MOUNTED=0
cleanup() {{
  rc=$?
  trap - EXIT INT TERM
  if (( BOOT_MOUNTED )); then sudo umount "$ROOT/boot" || rc=1; fi
  if (( ROOT_MOUNTED )); then sudo umount "$ROOT" || rc=1; fi
  ! findmnt -rn -M "$ROOT/boot" >/dev/null 2>&1 || rc=1
  ! findmnt -rn -M "$ROOT" >/dev/null 2>&1 || rc=1
  exit "$rc"
}}
trap cleanup EXIT INT TERM
sudo mount -o ro "${{ROOT_PARTS[0]}}" "$ROOT"
ROOT_MOUNTED=1
test -d "$ROOT/boot"
test ! -L "$ROOT/boot"
sudo mount -o ro "${{BOOT_PARTS[0]}}" "$ROOT/boot"
BOOT_MOUNTED=1
MODULE_ROOT="$ROOT/usr/lib/modules/{}/updates/open-gpu-kernel-modules-steamos"
for MODULE in nvidia nvidia-drm nvidia-modeset nvidia-peermem nvidia-uvm; do
  test -f "$MODULE_ROOT/$MODULE.ko.zst"
  test ! -L "$MODULE_ROOT/$MODULE.ko.zst"
done
grep -qx 'blacklist nouveau' "$ROOT/etc/modprobe.d/99-open-gpu-kernel-modules-steamos.conf"
grep -qx 'options nvidia-drm modeset=1 fbdev=1' "$ROOT/etc/modprobe.d/99-open-gpu-kernel-modules-steamos.conf"
grep -qx 'MODULES=(nvidia nvidia_modeset nvidia_uvm nvidia_drm)' "$ROOT/etc/mkinitcpio.conf.d/90-open-gpu-kernel-modules-steamos.conf"
STATE="$ROOT/var/lib/open-gpu-kernel-modules-steamos-support/offline-install"
test "$(cat "$STATE/kernel-version")" = "{}"
test "$(cat "$STATE/nvidia-version")" = "{}"
test -f "$STATE/PROVENANCE.json"
test -f "$STATE/BUILD-INFO.txt"
find "$ROOT/usr/lib/firmware/nvidia/{}" -type f -name 'gsp*.bin' -print -quit | grep -q .
find "$ROOT/var/lib/pacman/local" -mindepth 1 -maxdepth 1 -type d -name 'nvidia-utils-{}-*' -print -quit | grep -q .
find "$ROOT/var/lib/pacman/local" -mindepth 1 -maxdepth 1 -type d -name 'lib32-nvidia-utils-{}-*' -print -quit | grep -q .
find "$ROOT/boot" -maxdepth 1 -type f -name 'initramfs*.img' -size +0c -print -quit | grep -q .
sudo umount "$ROOT/boot"
BOOT_MOUNTED=0
sudo umount "$ROOT"
ROOT_MOUNTED=0
! findmnt -rn -M "$ROOT/boot" >/dev/null 2>&1
! findmnt -rn -M "$ROOT" >/dev/null 2>&1
trap - EXIT INT TERM"#,
        installation.kernel_version,
        installation.kernel_version,
        installation.nvidia_version,
        installation.nvidia_version,
        installation.nvidia_version,
        installation.nvidia_version,
    );
    run_guest_command(session, &command).map(|_| ())
}

fn wait_for_ready(session: &mut ApplianceSession, cancel: &AtomicBool) -> Result<(), String> {
    let deadline = Instant::now() + BOOT_TIMEOUT;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("Image export cancelled.".into());
        }
        if let Some(status) = session
            .child
            .try_wait()
            .map_err(|e| format!("Could not inspect validation appliance: {e}"))?
        {
            return Err(format!(
                "Validation appliance exited unexpectedly with {status}."
            ));
        }
        if handshake(session).ok().as_deref() == Some(READY_MARKER) {
            session.state = "ready".into();
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("Validation appliance did not become ready within 120 seconds.".into());
        }
        thread::sleep(Duration::from_millis(750));
    }
}

fn export_marker_image_blocking(app: tauri::AppHandle) -> Result<ExportedImage, String> {
    let manager_state = app.state::<Mutex<ApplianceManager>>();
    let (mut session, cancel) = {
        let mut manager = manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        if manager.preparing {
            return Err("Another image operation is already running.".into());
        }
        let session = manager
            .session
            .take()
            .ok_or("Builder appliance is not running.")?;
        if !matches!(
            session.state.as_str(),
            "ready" | "handoff-validated" | "nvidia-installed"
        ) {
            manager.session = Some(session);
            return Err("Builder appliance is not ready for image export.".into());
        }
        manager.cancel_preparation.store(false, Ordering::Relaxed);
        manager.preparing = true;
        (session, manager.cancel_preparation.clone())
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
    let result = (|| {
        if cancel.load(Ordering::Relaxed) {
            return Err("Image export cancelled.".into());
        }
        if session.target_system.is_none() {
            return Err("Target SteamOS metadata was not recorded before export.".into());
        }
        if session.state == "ready" {
            run_guest_command(
                &ImageInspectionSession::from(&session),
                "set -eu; sync; WORK=/dev/disk/by-id/virtio-steamos-user-working; test \"$(sudo blockdev --getro \"$WORK\")\" = 1; ! findmnt -rn -S \"$WORK\" >/dev/null 2>&1",
            )?;
            stop_session_process(&mut session)?;
        } else if session
            .child
            .try_wait()
            .map_err(|e| format!("Could not inspect the handed-off appliance: {e}"))?
            .is_none()
        {
            return Err("The native appliance is unexpectedly still running after handoff.".into());
        }
        let nvidia_installation = session.nvidia_installation.clone();
        if session.state == "nvidia-installed" && nvidia_installation.is_none() {
            return Err("NVIDIA-installed state omitted its structured result.".into());
        }
        let final_path =
            output_path_for_input(&session.input_image, nvidia_installation.is_some())?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("System clock error: {e}"))?
            .as_nanos();
        let partial_name = format!(
            ".{}.partial-{}-{timestamp}",
            final_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("steamos-marker.img"),
            std::process::id()
        );
        let partial_path = final_path
            .parent()
            .ok_or("Could not determine the output folder.")?
            .join(partial_name);
        let mut partial_guard = PartialOutputGuard {
            path: partial_path.clone(),
            armed: true,
        };
        let qemu_img = find_binary("qemu-img").ok_or("qemu-img is required for image export.")?;
        convert_working_image(
            &qemu_img,
            &session.working_image,
            &partial_path,
            session.input_preparation.image_bytes,
            Some(&report_progress),
            Some(&cancel),
        )?;
        let exported_bytes = fs::metadata(&partial_path)
            .map_err(|e| format!("Could not inspect the exported image: {e}"))?
            .len();
        if exported_bytes != session.input_preparation.image_bytes {
            return Err(format!(
                "Exported image size mismatch: expected {}, received {exported_bytes}.",
                session.input_preparation.image_bytes
            ));
        }
        stop_session(&mut session)?;

        let validation_progress = |stage: &str, processed: u64, total: u64| {
            let mapped = match stage {
                "hashing-source" | "verifying-source-after" => "hashing-output",
                other => other,
            };
            report_progress(mapped, processed, total);
        };
        report_progress("starting-output-validation", 0, 1);
        let mut validation = prepare_session(
            Some(&partial_path),
            Some(&validation_progress),
            Some(&cancel),
        )?;
        wait_for_ready(&mut validation, &cancel)?;
        let validation_snapshot = ImageInspectionSession::from(&validation);
        let inspection = inspect_user_image(
            &validation_snapshot,
            Some(&validation_progress),
            Some(&cancel),
        )?;
        if !inspection.layout.recognized {
            return Err(format!(
                "Exported image no longer matches the supported Valve layout: {}",
                inspection.layout.issues.join(" ")
            ));
        }
        if inspection.disk_bytes != exported_bytes || !inspection.read_only {
            return Err("Exported image failed independent size/read-only validation.".into());
        }
        verify_marker_from_validation_overlay(&validation_snapshot)?;
        if let Some(installation) = &nvidia_installation {
            verify_nvidia_from_validation_overlay(&validation_snapshot, installation)?;
        }
        let output_sha256 = inspection.source_sha256_after.clone();
        if output_sha256 == session.attached_sha256_before {
            return Err("Exported image hash matches the unmodified source; marker changes were not preserved.".into());
        }
        stop_session(&mut validation)?;

        let source_sha256 = sha256_file_with_progress(
            &session.input_image,
            "verifying-source-after-export",
            Some(&report_progress),
            Some(&cancel),
        )?;
        if source_sha256 != session.input_sha256_before {
            return Err(format!(
                "Original input changed during export (before {}, after {source_sha256}).",
                session.input_sha256_before
            ));
        }
        if final_path.exists() {
            return Err(format!(
                "The chosen output path appeared during export: {}",
                final_path.display()
            ));
        }
        let final_manifest_path = manifest_path_for_output(&final_path);
        if final_manifest_path.exists() {
            return Err(format!(
                "The chosen manifest path appeared during export: {}",
                final_manifest_path.display()
            ));
        }
        let partial_manifest_path = manifest_path_for_output(&partial_path);
        let manifest = marker_build_manifest(MarkerManifestData {
            input: &session.input_image,
            output: &final_path,
            input_preparation: &session.input_preparation,
            input_sha256: &source_sha256,
            normalized_sha256: &session.attached_sha256_before,
            output_bytes: exported_bytes,
            output_sha256: &output_sha256,
            layout: &inspection.layout,
            target_system: session
                .target_system
                .as_ref()
                .ok_or("Target SteamOS metadata is unavailable for the manifest.")?,
            nvidia_installation: nvidia_installation.as_ref(),
        });
        let mut manifest_guard = PartialOutputGuard {
            path: partial_manifest_path.clone(),
            armed: true,
        };
        write_json_file(&partial_manifest_path, &manifest)?;
        fs::rename(&partial_path, &final_path)
            .map_err(|e| format!("Could not finalize the exported image: {e}"))?;
        if let Err(error) = fs::rename(&partial_manifest_path, &final_manifest_path) {
            let rollback = fs::rename(&final_path, &partial_path);
            return Err(if let Err(rollback_error) = rollback {
                format!(
                    "Could not finalize the build manifest ({error}); the image also could not be returned to its temporary name ({rollback_error})."
                )
            } else {
                format!("Could not finalize the build manifest: {error}")
            });
        }
        partial_guard.armed = false;
        manifest_guard.armed = false;
        #[cfg(target_os = "macos")]
        let _ = Command::new("open").arg("-R").arg(&final_path).spawn();
        Ok(ExportedImage {
            path: final_path.to_string_lossy().into_owned(),
            manifest_path: final_manifest_path.to_string_lossy().into_owned(),
            bytes: exported_bytes,
            sha256: output_sha256,
            source_sha256,
            layout_scheme: inspection.layout.scheme.unwrap_or_default(),
            marker_path: "/etc/steamos-nvidia-image-builder-test".into(),
        })
    })();
    if let Ok(mut manager) = manager_state.lock() {
        manager.preparing = false;
    }
    result
}

#[tauri::command]
async fn export_marker_image(app: tauri::AppHandle) -> Result<ExportedImage, String> {
    tauri::async_runtime::spawn_blocking(move || export_marker_image_blocking(app))
        .await
        .map_err(|error| format!("Image export worker failed: {error}"))?
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

fn nvidia_build_status(session: &NvidiaBuildSession) -> NvidiaBuildStatus {
    NvidiaBuildStatus {
        state: session.state.clone(),
        message: session.message.clone(),
        architecture: "x86_64".into(),
        acceleration: session.acceleration.clone(),
        ssh_port: Some(session.ssh_port),
        runtime_path: Some(session.runtime_dir.to_string_lossy().into_owned()),
    }
}

fn stopped_nvidia_build_status(message: impl Into<String>) -> NvidiaBuildStatus {
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
async fn check_nvidia_build_environment() -> Result<NvidiaBuildEnvironment, String> {
    tauri::async_runtime::spawn_blocking(check_nvidia_build_environment_blocking)
        .await
        .map_err(|error| format!("NVIDIA build-environment worker failed: {error}"))
}

fn check_nvidia_build_environment_blocking() -> NvidiaBuildEnvironment {
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
async fn start_nvidia_build_appliance(app: tauri::AppHandle) -> Result<NvidiaBuildStatus, String> {
    tauri::async_runtime::spawn_blocking(move || start_nvidia_build_appliance_blocking(app))
        .await
        .map_err(|error| format!("NVIDIA build-appliance startup worker failed: {error}"))?
}

fn start_nvidia_build_appliance_blocking(
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
async fn get_nvidia_build_appliance_status(
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
        match handshake(session) {
            Ok(output) if output == READY_MARKER => match collect_guest_health(session) {
                Ok(health) if health.architecture == "x86_64" => {
                    session.state = "ready".into();
                    session.message = "x86_64 Fedora build appliance is ready.".into();
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
async fn nvidia_build_guest_health(app: tauri::AppHandle) -> Result<GuestHealth, String> {
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
async fn build_nvidia_target_development(
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
async fn read_nvidia_build_appliance_log(app: tauri::AppHandle) -> Result<String, String> {
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
        const LOG_LIMIT: usize = 32 * 1024;
        let qemu_bytes = fs::read(runtime_dir.join("qemu.log"))
            .map_err(|e| format!("Could not read the x86 build-appliance log: {e}"))?;
        let qemu_start = qemu_bytes.len().saturating_sub(LOG_LIMIT / 4);
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
async fn check_builder_environment() -> Result<BuilderEnvironment, String> {
    tauri::async_runtime::spawn_blocking(check_builder_environment_blocking)
        .await
        .map_err(|error| format!("Builder environment worker failed: {error}"))
}

fn check_builder_environment_blocking() -> BuilderEnvironment {
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
async fn get_appliance_status(app: tauri::AppHandle) -> Result<ApplianceStatus, String> {
    tauri::async_runtime::spawn_blocking(move || get_appliance_status_blocking(app))
        .await
        .map_err(|error| format!("Appliance status worker failed: {error}"))?
}

fn get_appliance_status_blocking(app: tauri::AppHandle) -> Result<ApplianceStatus, String> {
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

fn ready_session_snapshot(
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
async fn read_appliance_log(app: tauri::AppHandle) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || read_appliance_log_blocking(app))
        .await
        .map_err(|error| format!("Appliance log worker failed: {error}"))?
}

fn read_appliance_log_blocking(app: tauri::AppHandle) -> Result<String, String> {
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
    const LOG_LIMIT: usize = 32 * 1024;
    let start = bytes.len().saturating_sub(LOG_LIMIT);
    Ok(String::from_utf8_lossy(&bytes[start..]).into_owned())
}

#[tauri::command]
async fn guest_health(app: tauri::AppHandle) -> Result<GuestHealth, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let session = ready_session_snapshot(&app, "health checks")?;
        collect_guest_health(&session)
    })
    .await
    .map_err(|error| format!("Guest health worker failed: {error}"))?
}

#[tauri::command]
async fn verify_guest_transfer(app: tauri::AppHandle) -> Result<TransferProof, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let session = ready_session_snapshot(&app, "file transfer")?;
        run_transfer_proof(&session)
    })
    .await
    .map_err(|error| format!("Guest transfer worker failed: {error}"))?
}

#[tauri::command]
async fn inspect_test_disk(app: tauri::AppHandle) -> Result<SyntheticDiskInspection, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let session = ready_session_snapshot(&app, "synthetic disk inspection")?;
        inspect_synthetic_disk(&session)
    })
    .await
    .map_err(|error| format!("Synthetic disk worker failed: {error}"))?
}

#[tauri::command]
async fn inspect_selected_image(app: tauri::AppHandle) -> Result<UserImageInspection, String> {
    tauri::async_runtime::spawn_blocking(move || inspect_selected_image_blocking(app))
        .await
        .map_err(|error| format!("Image inspection worker failed: {error}"))?
}

fn inspect_selected_image_blocking(app: tauri::AppHandle) -> Result<UserImageInspection, String> {
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
async fn verify_working_image(app: tauri::AppHandle) -> Result<WorkingImageVerification, String> {
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
async fn mutate_test_marker(app: tauri::AppHandle) -> Result<MarkerMutation, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let session = ready_session_snapshot(&app, "synthetic marker mutation")?;
        mutate_synthetic_marker(&session)
    })
    .await
    .map_err(|error| format!("Synthetic mutation worker failed: {error}"))?
}

#[tauri::command]
async fn mutate_selected_marker(app: tauri::AppHandle) -> Result<UserMarkerMutation, String> {
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
async fn assess_nvidia_target(app: tauri::AppHandle) -> Result<NvidiaTargetReadiness, String> {
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
async fn resolve_published_nvidia(
    app: tauri::AppHandle,
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
            resolve_published_nvidia_for_target(
                target,
                &runtime_dir,
                &client,
                &releases,
                &cancel,
                &report_progress,
            )?
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
async fn prepare_nvidia_userspace(
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
async fn prepare_nvidia_installer_bundle(
    app: tauri::AppHandle,
) -> Result<NvidiaInstallerBundle, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let manager_state = app.state::<Mutex<ApplianceManager>>();
        let (runtime_dir, cancel) = {
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
                        && userspace.packages.len() == 2
                })
                .ok_or("Exact NVIDIA userspace packages must be staged first.")?;
            if let Some(bundle) = session.nvidia_installer_bundle.as_ref() {
                validate_staged_nvidia_installer_bundle(bundle)?;
                return Ok(bundle.report.clone());
            }
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
            (
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
        let bundle = prepare_pinned_nvidia_installer_bundle(
            &runtime_dir,
            &nvidia_http_client()?,
            &cancel,
            &report_progress,
        )?;
        validate_staged_nvidia_installer_bundle(&bundle)?;
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
        Ok(report)
    })
    .await
    .map_err(|error| format!("NVIDIA installer preparation worker failed: {error}"))?
}

fn collect_nvidia_install_inputs(
    session: &ApplianceSession,
) -> Result<NvidiaInstallInputs, String> {
    let target = session
        .target_system
        .as_ref()
        .ok_or("Target SteamOS metadata has not been discovered yet.")?;
    let resolution = session
        .nvidia_resolution
        .as_ref()
        .filter(|resolution| resolution.status == "compatible")
        .ok_or("A compatible published NVIDIA artifact must be verified first.")?;
    let publication = resolution
        .publication
        .as_ref()
        .ok_or("Compatible NVIDIA resolution omitted publication metadata.")?;
    let artifact = resolution
        .artifact
        .as_ref()
        .ok_or("Compatible NVIDIA resolution omitted its verified artifact.")?;
    let userspace = session
        .nvidia_userspace
        .as_ref()
        .filter(|userspace| {
            userspace.status == "prepared"
                && userspace.signature_status == "pending-x86-validation"
                && userspace.packages.len() == 2
        })
        .ok_or("Exact NVIDIA userspace packages must be staged first.")?;
    let installer = session
        .nvidia_installer_bundle
        .as_ref()
        .ok_or("The pinned offline NVIDIA installer must be staged first.")?;
    validate_staged_nvidia_installer_bundle(installer)?;
    if userspace.nvidia_version != publication.nvidia_version {
        return Err("Staged NVIDIA userspace version does not match the publication.".into());
    }
    let steamos_version = target
        .version_id
        .clone()
        .ok_or("Target SteamOS version is unavailable.")?;
    let kernel_version = resolution
        .target
        .kernel_version
        .clone()
        .ok_or("NVIDIA resolution omitted the exact target kernel.")?;
    let inputs = NvidiaInstallInputs {
        image_runtime_dir: session.runtime_dir.clone(),
        working_image: session.working_image.clone(),
        installer_root: installer.root.clone(),
        archive: PathBuf::from(&artifact.archive_path),
        checksum: PathBuf::from(&artifact.checksum_path),
        provenance: PathBuf::from(&artifact.provenance_path),
        archive_sha256: artifact.archive_sha256.clone(),
        trust: artifact.trust.clone(),
        steamos_version,
        kernel_version,
        nvidia_version: publication.nvidia_version.clone(),
        packages: userspace.packages.clone(),
    };
    for path in [
        &inputs.working_image,
        &inputs.archive,
        &inputs.checksum,
        &inputs.provenance,
    ] {
        if !fs::symlink_metadata(path)
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false)
        {
            return Err(format!(
                "Required NVIDIA handoff input is not a safe file: {}",
                path.display()
            ));
        }
    }
    for package in &inputs.packages {
        for path in [&package.package_path, &package.signature_path] {
            let path = Path::new(path);
            if !fs::symlink_metadata(path)
                .map(|metadata| metadata.file_type().is_file())
                .unwrap_or(false)
            {
                return Err(format!(
                    "Required NVIDIA userspace input is not a safe file: {}",
                    path.display()
                ));
            }
        }
    }
    Ok(inputs)
}

fn start_nvidia_install_appliance_blocking(
    app: tauri::AppHandle,
) -> Result<NvidiaBuildStatus, String> {
    let build_manager_state = app.state::<Mutex<NvidiaBuildManager>>();
    {
        let manager = build_manager_state
            .lock()
            .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
        if manager.starting || manager.session.is_some() {
            return Err("Another x86_64 Fedora appliance is already active.".into());
        }
    }
    let image_manager_state = app.state::<Mutex<ApplianceManager>>();
    let working_image = {
        let mut manager = image_manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        if manager.preparing {
            return Err("Another image operation is already running.".into());
        }
        let session = manager
            .session
            .as_mut()
            .ok_or("The builder appliance is not running.")?;
        if session.state != "ready" {
            return Err("The builder appliance is not ready for the x86 handoff.".into());
        }
        collect_nvidia_install_inputs(session)?;
        run_guest_command(
            &ImageInspectionSession::from(&*session),
            "set -eu; sync; WORK=/dev/disk/by-id/virtio-steamos-user-working; test \"$(sudo blockdev --getro \"$WORK\")\" = 1; ! findmnt -rn -S \"$WORK\" >/dev/null 2>&1",
        )?;
        stop_session_process(session)?;
        session.state = "handoff".into();
        session.message =
            "Working image preserved for read-only validation in the x86_64 appliance.".into();
        session.working_image.clone()
    };

    {
        let mut manager = build_manager_state
            .lock()
            .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
        if manager.starting || manager.session.is_some() {
            return Err("Another x86_64 Fedora appliance is already active.".into());
        }
        manager.starting = true;
        manager.cancel_build.store(false, Ordering::Relaxed);
    }
    let prepared = prepare_nvidia_build_session(Some(&working_image));
    let mut manager = build_manager_state
        .lock()
        .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
    manager.starting = false;
    let mut session = prepared?;
    session.message = if session.acceleration == "tcg" {
        "x86_64 Fedora installer appliance is booting under software emulation.".into()
    } else {
        "x86_64 Fedora installer appliance is booting.".into()
    };
    let status = nvidia_build_status(&session);
    manager.session = Some(session);
    Ok(status)
}

#[tauri::command]
async fn start_nvidia_install_appliance(
    app: tauri::AppHandle,
) -> Result<NvidiaBuildStatus, String> {
    tauri::async_runtime::spawn_blocking(move || start_nvidia_install_appliance_blocking(app))
        .await
        .map_err(|error| format!("NVIDIA installer-appliance startup worker failed: {error}"))?
}

fn validate_nvidia_install_result(
    document: SupportInstallResult,
    inputs: &NvidiaInstallInputs,
    expected_status: &str,
    expected_reason: &str,
    expected_phase: &str,
) -> Result<NvidiaInstallHandoffResult, String> {
    if document.schema_version != 1
        || document.status != expected_status
        || document.reason != expected_reason
        || document.phase != expected_phase
    {
        return Err(format!(
            "Offline installer validation did not succeed: {} ({}): {}",
            document.status, document.reason, document.message
        ));
    }
    if document.target.steamos_version != inputs.steamos_version
        || document.target.kernel_version != inputs.kernel_version
        || document.target.nvidia_version != inputs.nvidia_version
        || document.target.architecture != "x86_64"
        || document.trust != inputs.trust
        || !document.cleanup.mounts_released
    {
        return Err(
            "Offline installer validation result does not match the handoff target.".into(),
        );
    }
    let validation = document
        .validation
        .ok_or("Offline installer validation result omitted verified input metadata.")?;
    if validation.archive_sha256 != inputs.archive_sha256
        || validation.keyring.name != "approved-package-signers.gpg"
        || validation.keyring.sha256.len() != 64
        || !validation
            .keyring
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || validation.packages.len() != 2
    {
        return Err(
            "Offline installer validation metadata does not match the staged inputs.".into(),
        );
    }
    for expected in &inputs.packages {
        let signer = match expected.name.as_str() {
            "nvidia-utils" => NVIDIA_UTILS_SIGNER,
            "lib32-nvidia-utils" => LIB32_NVIDIA_UTILS_SIGNER,
            _ => return Err("Unexpected NVIDIA userspace package in the handoff.".into()),
        };
        let validated = validation
            .packages
            .iter()
            .find(|package| package.name == expected.name)
            .ok_or_else(|| format!("Offline validation omitted {}.", expected.name))?;
        if validated.full_version != expected.full_version
            || validated.pkgver != inputs.nvidia_version
            || validated.signer != signer
            || validated.sha256 != expected.package_sha256
            || validated.pkgrel.is_empty()
        {
            return Err(format!(
                "Offline validation metadata does not match staged {}.",
                expected.name
            ));
        }
    }
    Ok(NvidiaInstallHandoffResult {
        schema_version: 1,
        status: document.status,
        reason: document.reason,
        message: document.message,
        phase: document.phase,
        appliance_architecture: "x86_64".into(),
        root_partition_label: "rootfs-A".into(),
        boot_partition_label: "efi-A".into(),
        support_commit: NVIDIA_INSTALLER_COMMIT.into(),
        steamos_version: inputs.steamos_version.clone(),
        kernel_version: inputs.kernel_version.clone(),
        nvidia_version: inputs.nvidia_version.clone(),
        trust: inputs.trust.clone(),
        archive_sha256: inputs.archive_sha256.clone(),
        keyring_sha256: validation.keyring.sha256,
        packages: validation.packages,
        mounts_released: true,
    })
}

fn copy_install_input_to_guest(
    connection: &NvidiaBuildConnection,
    source: &Path,
    guest_name: &str,
) -> Result<(), String> {
    run_checked(
        scp_command(connection)?
            .arg(source)
            .arg(format!("builder@127.0.0.1:/tmp/{guest_name}")),
        "Could not transfer a verified NVIDIA installer input into the x86 guest",
    )
}

fn validate_nvidia_install_handoff_blocking(
    app: tauri::AppHandle,
) -> Result<NvidiaInstallHandoffResult, String> {
    let image_manager_state = app.state::<Mutex<ApplianceManager>>();
    let inputs = {
        let manager = image_manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        let session = manager
            .session
            .as_ref()
            .filter(|session| session.state == "handoff")
            .ok_or("The working image is not awaiting x86 validation.")?;
        collect_nvidia_install_inputs(session)?
    };
    let build_manager_state = app.state::<Mutex<NvidiaBuildManager>>();
    let (connection, cancel) = {
        let mut manager = build_manager_state
            .lock()
            .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
        manager.cancel_build.store(false, Ordering::Relaxed);
        let cancel = manager.cancel_build.clone();
        let session = manager
            .session
            .as_mut()
            .ok_or("The x86_64 Fedora installer appliance is not running.")?;
        if session.state != "ready" {
            return Err("The x86_64 Fedora installer appliance is not ready.".into());
        }
        if session.attached_working_image.as_ref() != Some(&inputs.working_image) {
            return Err("The x86 appliance is not attached to the expected working image.".into());
        }
        session.state = "validating".into();
        session.message = "Validating exact NVIDIA inputs against mounted rootfs-A.".into();
        (NvidiaBuildConnection::from(&*session), cancel)
    };

    let installer_archive = connection.runtime_dir.join("offline-installer.tar.gz");
    run_checked(
        Command::new("tar")
            .env("COPYFILE_DISABLE", "1")
            .args(["--no-xattrs", "-czf"])
            .arg(&installer_archive)
            .args(["-C"])
            .arg(&inputs.installer_root)
            .arg("."),
        "Could not package the pinned NVIDIA installer",
    )?;
    copy_install_input_to_guest(&connection, &installer_archive, "offline-installer.tar.gz")?;
    copy_install_input_to_guest(&connection, &inputs.archive, "nvidia-modules.tar.gz")?;
    copy_install_input_to_guest(
        &connection,
        &inputs.checksum,
        "nvidia-modules.tar.gz.sha256",
    )?;
    copy_install_input_to_guest(
        &connection,
        &inputs.provenance,
        "nvidia-modules.provenance.json",
    )?;
    for package in &inputs.packages {
        let stem = match package.name.as_str() {
            "nvidia-utils" => "nvidia-utils",
            "lib32-nvidia-utils" => "lib32-nvidia-utils",
            _ => return Err("Unexpected NVIDIA userspace package in the handoff.".into()),
        };
        copy_install_input_to_guest(
            &connection,
            Path::new(&package.package_path),
            &format!("{stem}.pkg.tar.zst"),
        )?;
        copy_install_input_to_guest(
            &connection,
            Path::new(&package.signature_path),
            &format!("{stem}.pkg.tar.zst.sig"),
        )?;
    }

    let command = format!(
        r#"set -euo pipefail
WORK=/tmp/steamos-nvidia-offline-install
TARGET=/dev/disk/by-id/virtio-steamos-target
ROOT=/mnt/steamos-nvidia-target
sudo dnf install -y bsdtar gnupg2 python3 kmod pacman archlinux-keyring
rm -rf "$WORK"
mkdir -p "$WORK/support"
tar -xzf /tmp/offline-installer.tar.gz -C "$WORK/support"
python3 "$WORK/support/bootstrap/prepare_nvidia_package_keyring.py" --source /usr/share/pacman/keyrings/archlinux.gpg --output "$WORK/approved-package-signers.gpg"
test -b "$TARGET"
mapfile -t ROOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$TARGET" | awk '$2 == "rootfs-A" && $3 == "btrfs" {{print $1}}')
mapfile -t BOOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$TARGET" | awk '$2 == "efi-A" && ($3 == "vfat" || $3 == "fat") {{print $1}}')
test "${{#ROOT_PARTS[@]}}" -eq 1
test "${{#BOOT_PARTS[@]}}" -eq 1
test "${{ROOT_PARTS[0]}}" != "${{BOOT_PARTS[0]}}"
sudo mkdir -p "$ROOT"
ROOT_MOUNTED=0
BOOT_MOUNTED=0
cleanup() {{
  rc=$?
  if (( BOOT_MOUNTED )); then sudo umount "$ROOT/boot" || rc=1; fi
  if (( ROOT_MOUNTED )); then sudo umount "$ROOT" || rc=1; fi
  ! findmnt -rn -M "$ROOT/boot" >/dev/null 2>&1 || rc=1
  ! findmnt -rn -M "$ROOT" >/dev/null 2>&1 || rc=1
  exit "$rc"
}}
trap cleanup EXIT INT TERM
sudo mount -o ro "${{ROOT_PARTS[0]}}" "$ROOT"
ROOT_MOUNTED=1
test -d "$ROOT/boot"
test ! -L "$ROOT/boot"
sudo mount -o ro "${{BOOT_PARTS[0]}}" "$ROOT/boot"
BOOT_MOUNTED=1
sudo bash "$WORK/support/bootstrap/install_to_root.sh" --validate-only --root "$ROOT" --archive /tmp/nvidia-modules.tar.gz --checksum /tmp/nvidia-modules.tar.gz.sha256 --provenance /tmp/nvidia-modules.provenance.json --kernel {} --nvidia-utils /tmp/nvidia-utils.pkg.tar.zst --nvidia-utils-signature /tmp/nvidia-utils.pkg.tar.zst.sig --lib32-nvidia-utils /tmp/lib32-nvidia-utils.pkg.tar.zst --lib32-nvidia-utils-signature /tmp/lib32-nvidia-utils.pkg.tar.zst.sig --package-keyring "$WORK/approved-package-signers.gpg" --result-json "$WORK/install-result.json"
sudo umount "$ROOT/boot"
BOOT_MOUNTED=0
sudo umount "$ROOT"
ROOT_MOUNTED=0
! findmnt -rn -M "$ROOT/boot" >/dev/null 2>&1
! findmnt -rn -M "$ROOT" >/dev/null 2>&1
trap - EXIT INT TERM"#,
        inputs.kernel_version
    );
    let execution_result = run_guest_command_logged(
        &connection,
        &command,
        &connection.runtime_dir.join("nvidia-install.log"),
        Some(&cancel),
    );
    let staged_result = connection.runtime_dir.join("nvidia-install-result.json");
    let result_transfer = run_checked(
        scp_command(&connection)?
            .arg("builder@127.0.0.1:/tmp/steamos-nvidia-offline-install/install-result.json")
            .arg(&staged_result),
        "Could not copy the NVIDIA installer validation result from the x86 guest",
    );
    if let Err(transfer_error) = result_transfer {
        return Err(execution_result.err().unwrap_or(transfer_error));
    }
    fs::copy(
        &staged_result,
        inputs
            .image_runtime_dir
            .join("nvidia-install-validation.json"),
    )
    .map_err(|e| format!("Could not preserve the NVIDIA installer result: {e}"))?;
    let document: SupportInstallResult = serde_json::from_reader(
        File::open(&staged_result)
            .map_err(|e| format!("Could not read the NVIDIA installer result: {e}"))?,
    )
    .map_err(|e| format!("NVIDIA installer result is invalid JSON: {e}"))?;
    let validation = validate_nvidia_install_result(
        document,
        &inputs,
        "validated",
        "validation_complete",
        "validated",
    )?;
    execution_result?;

    {
        let mut manager = build_manager_state
            .lock()
            .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
        let session = manager
            .session
            .as_mut()
            .ok_or("The x86 installer appliance ended after validation.")?;
        session.state = "ready".into();
        session.message =
            "Read-only NVIDIA validation passed; the appliance is ready for installation.".into();
    }
    let mut manager = image_manager_state
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    let session = manager
        .session
        .as_mut()
        .filter(|session| session.working_image == inputs.working_image)
        .ok_or("Builder session ended before NVIDIA validation could be recorded.")?;
    session.state = "handoff-validated".into();
    session.message = "NVIDIA inputs passed read-only x86_64 offline-root validation.".into();
    session.nvidia_install_validation = Some(validation.clone());
    Ok(validation)
}

#[tauri::command]
async fn validate_nvidia_install_handoff(
    app: tauri::AppHandle,
) -> Result<NvidiaInstallHandoffResult, String> {
    tauri::async_runtime::spawn_blocking(move || validate_nvidia_install_handoff_blocking(app))
        .await
        .map_err(|error| format!("NVIDIA installer validation worker failed: {error}"))?
}

fn install_nvidia_to_working_image_blocking(
    app: tauri::AppHandle,
) -> Result<NvidiaInstallHandoffResult, String> {
    let image_manager_state = app.state::<Mutex<ApplianceManager>>();
    let inputs = {
        let manager = image_manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        let session = manager
            .session
            .as_ref()
            .filter(|session| session.state == "handoff-validated")
            .ok_or("The working image has not passed the x86 validation handoff.")?;
        session
            .nvidia_install_validation
            .as_ref()
            .filter(|result| {
                result.status == "validated"
                    && result.reason == "validation_complete"
                    && result.mounts_released
            })
            .ok_or("The recorded NVIDIA validation result is not installable.")?;
        collect_nvidia_install_inputs(session)?
    };
    let build_manager_state = app.state::<Mutex<NvidiaBuildManager>>();
    let (connection, cancel) = {
        let mut manager = build_manager_state
            .lock()
            .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
        manager.cancel_build.store(false, Ordering::Relaxed);
        let cancel = manager.cancel_build.clone();
        let session = manager
            .session
            .as_mut()
            .ok_or("The x86_64 Fedora installer appliance is not running.")?;
        if session.state != "ready"
            || session.attached_working_image.as_ref() != Some(&inputs.working_image)
        {
            return Err(
                "The validated x86 appliance is not attached to the expected working image.".into(),
            );
        }
        session.state = "installing".into();
        session.message = format!(
            "Installing NVIDIA {} for exact kernel {}.",
            inputs.nvidia_version, inputs.kernel_version
        );
        (NvidiaBuildConnection::from(&*session), cancel)
    };

    let command = format!(
        r#"set -euo pipefail
WORK=/tmp/steamos-nvidia-offline-install
TARGET=/dev/disk/by-id/virtio-steamos-target
TOP=/mnt/steamos-nvidia-top
ROOT=/mnt/steamos-nvidia-target
test -b "$TARGET"
test -d "$WORK/support"
test -f "$WORK/approved-package-signers.gpg"
mapfile -t ROOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$TARGET" | awk '$2 == "rootfs-A" && $3 == "btrfs" {{print $1}}')
mapfile -t BOOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$TARGET" | awk '$2 == "efi-A" && ($3 == "vfat" || $3 == "fat") {{print $1}}')
test "${{#ROOT_PARTS[@]}}" -eq 1
test "${{#BOOT_PARTS[@]}}" -eq 1
test "${{ROOT_PARTS[0]}}" != "${{BOOT_PARTS[0]}}"
sudo mkdir -p "$TOP" "$ROOT"
TOP_MOUNTED=0
ROOT_MOUNTED=0
ROOT_IS_TOP=0
BOOT_MOUNTED=0
RESTORE_ROOT_RO=0
WAS_SEEDING=0
SEEDING_RESTORED=0
SOURCE_ROOT=
cleanup() {{
  rc=$?
  trap - EXIT INT TERM
  if (( BOOT_MOUNTED )); then sudo umount "$ROOT/boot" || rc=1; fi
  if (( ROOT_MOUNTED )); then sudo umount "$ROOT" || rc=1; fi
  if (( RESTORE_ROOT_RO )) && (( TOP_MOUNTED )) && test -n "$SOURCE_ROOT"; then
    sudo btrfs property set -f -ts "$SOURCE_ROOT" ro true || rc=1
  fi
  if (( TOP_MOUNTED )); then sudo umount "$TOP" || rc=1; fi
  if (( WAS_SEEDING )) && ! (( SEEDING_RESTORED )); then
    sudo btrfstune -f -S 1 "${{ROOT_PARTS[0]}}" || rc=1
  fi
  ! findmnt -rn -M "$ROOT/boot" >/dev/null 2>&1 || rc=1
  ! findmnt -rn -M "$ROOT" >/dev/null 2>&1 || rc=1
  ! findmnt -rn -M "$TOP" >/dev/null 2>&1 || rc=1
  exit "$rc"
}}
trap cleanup EXIT INT TERM
sudo mount -o rw,subvolid=5 "${{ROOT_PARTS[0]}}" "$TOP"
TOP_MOUNTED=1
if findmnt -rn -M "$TOP" -o OPTIONS | tr ',' '\n' | grep -qx ro; then
  sudo umount "$TOP"
  TOP_MOUNTED=0
  sudo btrfstune -f -S 0 "${{ROOT_PARTS[0]}}"
  WAS_SEEDING=1
  sudo mount -o rw,subvolid=5 "${{ROOT_PARTS[0]}}" "$TOP"
  TOP_MOUNTED=1
fi
findmnt -rn -M "$TOP" -o OPTIONS | tr ',' '\n' | grep -qx rw
DEFAULT_INFO=$(sudo btrfs subvolume get-default "$TOP")
DEFAULT_PATH=$(printf '%s\n' "$DEFAULT_INFO" | sed -n 's/^.* path //p')
if test -z "$DEFAULT_PATH" && printf '%s\n' "$DEFAULT_INFO" | grep -q '^ID 5 (FS_TREE)$'; then DEFAULT_PATH='<FS_TREE>'; fi
case "$DEFAULT_PATH" in
  '<FS_TREE>') SOURCE_ROOT="$TOP"; ROOT="$TOP"; ROOT_IS_TOP=1 ;;
  ''|/*|*..*) echo 'Unsafe Btrfs default subvolume path.' >&2; exit 1 ;;
  *) SOURCE_ROOT="$TOP/$DEFAULT_PATH" ;;
esac
test -d "$SOURCE_ROOT"
SOURCE_ROOT_RO=$(sudo btrfs property get -ts "$SOURCE_ROOT" ro | awk -F= '$1 == "ro" {{print $2}}')
test "$SOURCE_ROOT_RO" = true || test "$SOURCE_ROOT_RO" = false
if test "$SOURCE_ROOT_RO" = true; then
  sudo btrfs property set -f -ts "$SOURCE_ROOT" ro false
  RESTORE_ROOT_RO=1
fi
if ! (( ROOT_IS_TOP )); then
  sudo mount -o rw,subvol="$DEFAULT_PATH" "${{ROOT_PARTS[0]}}" "$ROOT"
  ROOT_MOUNTED=1
fi
findmnt -rn -M "$ROOT" -o OPTIONS | tr ',' '\n' | grep -qx rw
test -d "$ROOT/boot"
test ! -L "$ROOT/boot"
sudo mount -o rw "${{BOOT_PARTS[0]}}" "$ROOT/boot"
BOOT_MOUNTED=1
sudo bash "$WORK/support/bootstrap/install_to_root.sh" --root "$ROOT" --archive /tmp/nvidia-modules.tar.gz --checksum /tmp/nvidia-modules.tar.gz.sha256 --provenance /tmp/nvidia-modules.provenance.json --kernel {} --nvidia-utils /tmp/nvidia-utils.pkg.tar.zst --nvidia-utils-signature /tmp/nvidia-utils.pkg.tar.zst.sig --lib32-nvidia-utils /tmp/lib32-nvidia-utils.pkg.tar.zst --lib32-nvidia-utils-signature /tmp/lib32-nvidia-utils.pkg.tar.zst.sig --package-keyring "$WORK/approved-package-signers.gpg" --result-json "$WORK/install-mutation-result.json"
INITRAMFS_OK=0
while IFS= read -r INITRAMFS; do
  test -n "$INITRAMFS" || continue
  LISTING=$(sudo chroot "$ROOT" /usr/bin/lsinitcpio "/boot/$(basename "$INITRAMFS")")
  if printf '%s\n' "$LISTING" | grep -q 'nvidia\.ko' \
    && printf '%s\n' "$LISTING" | grep -q 'nvidia-modeset\.ko' \
    && printf '%s\n' "$LISTING" | grep -q 'nvidia-uvm\.ko' \
    && printf '%s\n' "$LISTING" | grep -q 'nvidia-drm\.ko'; then
    INITRAMFS_OK=1
    break
  fi
done < <(sudo find "$ROOT/boot" -maxdepth 1 -type f -name 'initramfs*.img' -print)
test "$INITRAMFS_OK" = 1
sync
sudo umount "$ROOT/boot"
BOOT_MOUNTED=0
if (( ROOT_MOUNTED )); then sudo umount "$ROOT"; ROOT_MOUNTED=0; fi
if (( RESTORE_ROOT_RO )); then
  sudo btrfs property set -f -ts "$SOURCE_ROOT" ro true
  RESTORE_ROOT_RO=0
fi
sudo umount "$TOP"
TOP_MOUNTED=0
if (( WAS_SEEDING )); then
  sudo btrfstune -f -S 1 "${{ROOT_PARTS[0]}}"
  SEEDING_RESTORED=1
fi
! findmnt -rn -M "$ROOT/boot" >/dev/null 2>&1
! findmnt -rn -M "$ROOT" >/dev/null 2>&1
! findmnt -rn -M "$TOP" >/dev/null 2>&1
trap - EXIT INT TERM"#,
        inputs.kernel_version
    );
    let execution_result = run_guest_command_logged(
        &connection,
        &command,
        &connection.runtime_dir.join("nvidia-install-mutation.log"),
        Some(&cancel),
    );
    let staged_result = connection
        .runtime_dir
        .join("nvidia-install-mutation-result.json");
    let result_transfer = run_checked(
        scp_command(&connection)?
            .arg("builder@127.0.0.1:/tmp/steamos-nvidia-offline-install/install-mutation-result.json")
            .arg(&staged_result),
        "Could not copy the NVIDIA installation result from the x86 guest",
    );
    if let Err(transfer_error) = result_transfer {
        return Err(execution_result.err().unwrap_or(transfer_error));
    }
    fs::copy(
        &staged_result,
        inputs
            .image_runtime_dir
            .join("nvidia-install-mutation-result.json"),
    )
    .map_err(|e| format!("Could not preserve the NVIDIA installation result: {e}"))?;
    let document: SupportInstallResult = serde_json::from_reader(
        File::open(&staged_result)
            .map_err(|e| format!("Could not read the NVIDIA installation result: {e}"))?,
    )
    .map_err(|e| format!("NVIDIA installation result is invalid JSON: {e}"))?;
    let installation = validate_nvidia_install_result(
        document,
        &inputs,
        "success",
        "install_complete",
        "complete",
    )?;
    execution_result?;

    {
        let mut manager = build_manager_state
            .lock()
            .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
        let mut session = manager
            .session
            .take()
            .ok_or("The x86 installer appliance ended before cleanup.")?;
        stop_nvidia_build_session(&mut session)?;
    }
    let mut manager = image_manager_state
        .lock()
        .map_err(|_| "Appliance state lock is unavailable.")?;
    let session = manager
        .session
        .as_mut()
        .filter(|session| session.working_image == inputs.working_image)
        .ok_or("Builder session ended before NVIDIA installation could be recorded.")?;
    session.state = "nvidia-installed".into();
    session.message = "NVIDIA payload installed into the disposable working image.".into();
    session.nvidia_installation = Some(installation.clone());
    Ok(installation)
}

#[tauri::command]
async fn install_nvidia_to_working_image(
    app: tauri::AppHandle,
) -> Result<NvidiaInstallHandoffResult, String> {
    tauri::async_runtime::spawn_blocking(move || install_nvidia_to_working_image_blocking(app))
        .await
        .map_err(|error| format!("NVIDIA offline installation worker failed: {error}"))?
}

fn stop_session_process(session: &mut ApplianceSession) -> Result<(), String> {
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
    Ok(())
}

fn stop_session(session: &mut ApplianceSession) -> Result<Option<PathBuf>, String> {
    stop_session_process(session)?;
    archive_and_remove_runtime(&session.runtime_dir)
}

fn stop_nvidia_build_session(session: &mut NvidiaBuildSession) -> Result<Option<PathBuf>, String> {
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
    archive_and_remove_nvidia_build_runtime(&session.runtime_dir)
}

#[tauri::command]
async fn stop_nvidia_build_appliance(app: tauri::AppHandle) -> Result<NvidiaBuildStatus, String> {
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
    .inner_size(680.0, 680.0)
    .min_inner_size(680.0, 680.0)
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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn selects_isolated_x86_build_acceleration_by_host() {
        assert_eq!(
            nvidia_build_qemu_spec("aarch64").unwrap(),
            ("tcg", "q35,accel=tcg", "max")
        );
        assert_eq!(
            nvidia_build_qemu_spec("x86_64").unwrap(),
            ("hvf", "q35,accel=hvf", "host")
        );
        assert!(nvidia_build_qemu_spec("unsupported").is_err());
    }

    #[test]
    fn validates_and_names_exact_nvidia_target_builds() {
        let spec = NvidiaTargetBuildSpec {
            steamos_version: "3.8.14".into(),
            kernel_version: "6.16.12-valve24.4-1-neptune-616-gfe145653a794".into(),
            nvidia_version: "575.64.05".into(),
        };
        validate_nvidia_target_build_spec(&spec).unwrap();
        assert_eq!(
            nvidia_development_asset_name(&spec),
            "nvidia-open-steamos-3.8.14-nvidia-575.64.05-k6.16.12-valve24.4-1-neptune-616-gfe145653a794-x86_64.tar.gz"
        );
        for invalid in [
            NvidiaTargetBuildSpec {
                steamos_version: "3.8".into(),
                ..spec.clone()
            },
            NvidiaTargetBuildSpec {
                kernel_version: "$(uname)".into(),
                ..spec.clone()
            },
            NvidiaTargetBuildSpec {
                nvidia_version: "latest".into(),
                ..spec.clone()
            },
        ] {
            assert!(validate_nvidia_target_build_spec(&invalid).is_err());
        }
    }

    #[test]
    fn validates_versioned_support_build_results() {
        let spec = NvidiaTargetBuildSpec {
            steamos_version: "3.8.14".into(),
            kernel_version: "6.16.12-valve24.4-1-neptune-616-gfe145653a794".into(),
            nvidia_version: "575.64.05".into(),
        };
        let asset = nvidia_development_asset_name(&spec);
        let result = serde_json::json!({
            "schemaVersion": 1,
            "status": "success",
            "reason": "build_complete",
            "message": "fixture passed",
            "trust": "development-unverified",
            "target": {
                "steamosVersion": spec.steamos_version,
                "kernelVersion": spec.kernel_version,
                "nvidiaVersion": spec.nvidia_version,
                "architecture": "x86_64"
            },
            "artifact": {
                "archive": asset,
                "checksum": format!("{asset}.sha256"),
                "buildInfo": format!("{}.build-info.txt", asset.trim_end_matches(".tar.gz")),
                "provenance": format!("{}.provenance.json", asset.trim_end_matches(".tar.gz")),
                "sha256": "a".repeat(64)
            }
        });
        let parsed: SupportBuildResult = serde_json::from_value(result.clone()).unwrap();
        let (artifact, trust) = validate_support_build_result(parsed, &spec).unwrap();
        assert_eq!(artifact.archive, asset);
        assert_eq!(trust, "development-unverified");

        let mut failure = result.clone();
        failure["status"] = serde_json::json!("failed");
        failure["reason"] = serde_json::json!("headers_not_found");
        failure["message"] = serde_json::json!("exact headers unavailable");
        failure.as_object_mut().unwrap().remove("artifact");
        let error = validate_support_build_result(serde_json::from_value(failure).unwrap(), &spec)
            .unwrap_err();
        assert!(error.contains("headers_not_found"));

        let mut wrong_target = result;
        wrong_target["target"]["kernelVersion"] = serde_json::json!("wrong-kernel");
        assert!(validate_support_build_result(
            serde_json::from_value(wrong_target).unwrap(),
            &spec,
        )
        .is_err());

        let signer = "889B5EBDDD505A683621900DAF1D2199EF0A3CCF";
        let modules: Vec<_> = [
            "nvidia-drm.ko",
            "nvidia-modeset.ko",
            "nvidia-peermem.ko",
            "nvidia-uvm.ko",
            "nvidia.ko",
        ]
        .into_iter()
        .map(|name| {
            serde_json::json!({
                "name": name,
                "sha256": "b".repeat(64),
                "version": spec.nvidia_version,
                "architecture": "x86_64",
                "vermagic": format!("{} SMP preempt", spec.kernel_version)
            })
        })
        .collect();
        let provenance = serde_json::json!({
            "schemaVersion": 1,
            "trust": "development-unverified",
            "target": {
                "steamosVersion": spec.steamos_version,
                "kernelVersion": spec.kernel_version,
                "nvidiaVersion": spec.nvidia_version,
                "architecture": "x86_64"
            },
            "artifact": {
                "archive": asset
            },
            "headers": {
                "signatureStatus": "verified",
                "signingKeyFingerprint": signer,
                "primaryKeyFingerprint": "not-reported",
                "authentication": "detached-signature-verified-with-pinned-keyring"
            },
            "modules": modules
        });
        let parsed: SupportBuildProvenance = serde_json::from_value(provenance.clone()).unwrap();
        validate_support_build_provenance(&parsed, &spec, "development-unverified", signer)
            .unwrap();

        let mut wrong_module = provenance;
        wrong_module["modules"][0]["vermagic"] = serde_json::json!("wrong-kernel SMP");
        let parsed: SupportBuildProvenance = serde_json::from_value(wrong_module).unwrap();
        assert!(validate_support_build_provenance(
            &parsed,
            &spec,
            "development-unverified",
            signer,
        )
        .is_err());
    }

    #[test]
    fn requires_one_unambiguous_offline_nvidia_kernel() {
        let target = TargetSystemDiscovery {
            os_id: Some("steamos".into()),
            pretty_name: Some("SteamOS".into()),
            version_id: Some("3.8.14".into()),
            build_id: None,
            variant_id: None,
            architecture: "x86_64".into(),
            kernel_versions: vec!["6.16.12-valve24.4-1-neptune-616-gfe145653a794".into()],
        };
        let ready = assess_nvidia_target_system(&target);
        assert!(ready.ready);
        assert_eq!(ready.status, "exact-target");
        assert_eq!(
            ready.kernel_version.as_deref(),
            Some("6.16.12-valve24.4-1-neptune-616-gfe145653a794")
        );

        let no_kernel = assess_nvidia_target_system(&TargetSystemDiscovery {
            kernel_versions: Vec::new(),
            ..target.clone()
        });
        assert!(!no_kernel.ready);
        assert_eq!(no_kernel.status, "no-kernel");

        let ambiguous = assess_nvidia_target_system(&TargetSystemDiscovery {
            kernel_versions: vec!["6.16.12-valve24.4".into(), "6.16.12-valve24.5".into()],
            ..target.clone()
        });
        assert!(!ambiguous.ready);
        assert_eq!(ambiguous.status, "ambiguous-kernel");

        let wrong_architecture = assess_nvidia_target_system(&TargetSystemDiscovery {
            architecture: "aarch64".into(),
            ..target
        });
        assert!(!wrong_architecture.ready);
        assert_eq!(wrong_architecture.status, "unsupported-architecture");
    }

    fn published_release_fixture(steamos: &str, kernel: &str, nvidia: &str) -> GithubRelease {
        let tag = format!("steamos-{steamos}-nvidia-{nvidia}-k{kernel}");
        let archive = format!("nvidia-open-{tag}-x86_64.tar.gz");
        let names = [
            archive.clone(),
            format!("{archive}.sha256"),
            format!("{}.provenance.json", archive.trim_end_matches(".tar.gz")),
        ];
        GithubRelease {
            tag_name: tag.clone(),
            draft: false,
            prerelease: false,
            published_at: Some("2026-08-30T20:43:15Z".into()),
            assets: names
                .into_iter()
                .map(|name| GithubReleaseAsset {
                    browser_download_url: expected_release_asset_url(&tag, &name),
                    name,
                    size: 1,
                    digest: Some(format!("sha256:{}", "a".repeat(64))),
                })
                .collect(),
        }
    }

    fn ready_published_target(steamos: &str, kernel: &str) -> NvidiaTargetReadiness {
        NvidiaTargetReadiness {
            ready: true,
            status: "exact-target".into(),
            message: "fixture".into(),
            steamos_version: Some(steamos.into()),
            kernel_version: Some(kernel.into()),
            architecture: "x86_64".into(),
        }
    }

    #[test]
    fn follows_schema_two_published_nvidia_selection_policy() {
        let kernel = "6.16.12-valve24.5-1-neptune-616-gb2f7cfe85e45";
        let releases = vec![
            published_release_fixture("3.8.15", kernel, "575.64.05"),
            published_release_fixture("3.8.16", kernel, "575.64.05"),
            published_release_fixture("3.8.16", kernel, "580.1.1"),
            published_release_fixture("3.9.0", kernel, "999.1.1"),
        ];
        let (exact, _, compatibility) =
            select_published_nvidia_release(&ready_published_target("3.8.16", kernel), &releases)
                .unwrap()
                .unwrap();
        assert_eq!(exact.steamos_version, "3.8.16");
        assert_eq!(exact.nvidia_version, "580.1.1");
        assert_eq!(compatibility, "exact");

        let (fallback, _, compatibility) =
            select_published_nvidia_release(&ready_published_target("3.8.17", kernel), &releases)
                .unwrap()
                .unwrap();
        assert_eq!(fallback.steamos_version, "3.8.16");
        assert_eq!(compatibility, "same_series_fallback");

        assert!(select_published_nvidia_release(
            &ready_published_target("3.8.14", "6.16.12-valve24.4-1-neptune-616-gfe145653a794"),
            &releases,
        )
        .unwrap()
        .is_none());
        assert!(select_published_nvidia_release(
            &ready_published_target("3.9.0", "different-kernel"),
            &releases,
        )
        .unwrap()
        .is_none());

        let exact_name = published_asset_name(&exact);
        let exact_release = releases
            .iter()
            .find(|release| release.tag_name == exact.tag)
            .unwrap();
        assert!(unique_release_asset(exact_release, &exact_name)
            .unwrap()
            .is_some());
        let provenance_name = format!("{}.provenance.json", exact_name.trim_end_matches(".tar.gz"));
        assert!(unique_release_asset(exact_release, &provenance_name)
            .unwrap()
            .is_some());
    }

    #[test]
    fn selects_exact_signed_arch_userspace_packages_independently() {
        let nvidia_index = r#"
            <a href="nvidia-utils-575.64.05-1-x86_64.pkg.tar.zst">old</a>
            <a href="nvidia-utils-575.64.05-1-x86_64.pkg.tar.zst.sig">old signature</a>
            <a href="nvidia-utils-575.64.05-2-x86_64.pkg.tar.zst">selected</a>
            <a href="nvidia-utils-575.64.05-2-x86_64.pkg.tar.zst.sig">selected signature</a>
            <a href="nvidia-utils-575.64.05-3-x86_64.pkg.tar.zst">unsigned</a>
            <a href="nvidia-utils-580.1.1-1-x86_64.pkg.tar.zst">wrong version</a>
            <a href="nvidia-utils-580.1.1-1-x86_64.pkg.tar.zst.sig">wrong signature</a>
        "#;
        let lib32_index = r#"
            <a href="lib32-nvidia-utils-575.64.05-1-x86_64.pkg.tar.zst">selected</a>
            <a href="lib32-nvidia-utils-575.64.05-1-x86_64.pkg.tar.zst.sig">selected signature</a>
        "#;
        let (nvidia, nvidia_full_version) =
            select_arch_userspace_package(nvidia_index, "nvidia-utils", "575.64.05").unwrap();
        let (lib32, lib32_full_version) =
            select_arch_userspace_package(lib32_index, "lib32-nvidia-utils", "575.64.05").unwrap();
        assert_eq!(nvidia, "nvidia-utils-575.64.05-2-x86_64.pkg.tar.zst");
        assert_eq!(nvidia_full_version, "575.64.05-2");
        assert_eq!(lib32, "lib32-nvidia-utils-575.64.05-1-x86_64.pkg.tar.zst");
        assert_eq!(lib32_full_version, "575.64.05-1");
        assert!(select_arch_userspace_package(nvidia_index, "nvidia-utils", "575.64.06").is_err());
        assert!(arch_package_release_key("01").is_none());
        assert!(arch_package_release_key("1..2").is_none());
    }

    #[test]
    #[ignore = "queries the live Arch Linux Archive package indexes"]
    fn live_arch_userspace_package_selection() {
        let client = nvidia_http_client().expect("create HTTPS client");
        for (package, expected) in [
            (
                "nvidia-utils",
                "nvidia-utils-575.64.05-2-x86_64.pkg.tar.zst",
            ),
            (
                "lib32-nvidia-utils",
                "lib32-nvidia-utils-575.64.05-1-x86_64.pkg.tar.zst",
            ),
        ] {
            let directory = arch_package_directory(package).expect("known package directory");
            let response = client
                .get(format!("{directory}/"))
                .send()
                .expect("query package index");
            let bytes = read_http_response_limited(
                response,
                ARCH_ARCHIVE_INDEX_LIMIT,
                "live package index",
            )
            .expect("read package index");
            let index = std::str::from_utf8(&bytes).expect("UTF-8 package index");
            let (filename, _) = select_arch_userspace_package(index, package, "575.64.05")
                .expect("select exact signed package");
            assert_eq!(filename, expected);
        }
    }

    #[test]
    fn pinned_installer_contract_is_safe_and_versioned() {
        assert_eq!(validate_pinned_installer_contract().unwrap(), 41_652);
        assert_eq!(PINNED_INSTALLER_FILES.len(), 7);
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "bootstrap/install_to_root.sh" && file.executable));
        assert!(PINNED_INSTALLER_FILES.iter().any(|file| {
            file.path == "trust/nvidia-userspace-package-signers.json" && !file.executable
        }));
    }

    #[test]
    fn accepts_only_exact_offline_installer_validation_results() {
        let digest = |byte: char| byte.to_string().repeat(64);
        let staged_package =
            |name: &str, release: &str, signer_digest: char| NvidiaUserspacePackage {
                name: name.into(),
                filename: format!("{name}-575.64.05-{release}-x86_64.pkg.tar.zst"),
                full_version: format!("575.64.05-{release}"),
                package_path: format!("/{name}.pkg.tar.zst"),
                signature_path: format!("/{name}.pkg.tar.zst.sig"),
                package_sha256: digest(signer_digest),
            };
        let inputs = NvidiaInstallInputs {
            image_runtime_dir: "/image-runtime".into(),
            working_image: "/working.qcow2".into(),
            installer_root: "/installer".into(),
            archive: "/modules.tar.gz".into(),
            checksum: "/modules.tar.gz.sha256".into(),
            provenance: "/modules.provenance.json".into(),
            archive_sha256: digest('a'),
            trust: "certified-published".into(),
            steamos_version: "3.8.14".into(),
            kernel_version: "6.16.12-valve24.4-1-neptune-616-gfe145653a794".into(),
            nvidia_version: "575.64.05".into(),
            packages: vec![
                staged_package("nvidia-utils", "2", 'b'),
                staged_package("lib32-nvidia-utils", "1", 'c'),
            ],
        };
        let validated_package =
            |name: &str, release: &str, signer: &str, signer_digest: char| SupportInstallPackage {
                name: name.into(),
                full_version: format!("575.64.05-{release}"),
                pkgver: "575.64.05".into(),
                pkgrel: release.into(),
                signer: signer.into(),
                sha256: digest(signer_digest),
            };
        let result = SupportInstallResult {
            schema_version: 1,
            status: "validated".into(),
            reason: "validation_complete".into(),
            message: "validated fixture".into(),
            phase: "validated".into(),
            target: SupportInstallTarget {
                steamos_version: "3.8.14".into(),
                kernel_version: inputs.kernel_version.clone(),
                nvidia_version: "575.64.05".into(),
                architecture: "x86_64".into(),
            },
            trust: "certified-published".into(),
            cleanup: SupportInstallCleanup {
                mounts_released: true,
            },
            validation: Some(SupportInstallValidation {
                archive_sha256: digest('a'),
                keyring: SupportInstallKeyring {
                    name: "approved-package-signers.gpg".into(),
                    sha256: digest('d'),
                },
                packages: vec![
                    validated_package("nvidia-utils", "2", NVIDIA_UTILS_SIGNER, 'b'),
                    validated_package("lib32-nvidia-utils", "1", LIB32_NVIDIA_UTILS_SIGNER, 'c'),
                ],
            }),
        };
        let accepted = validate_nvidia_install_result(
            result,
            &inputs,
            "validated",
            "validation_complete",
            "validated",
        )
        .expect("the exact installer result should pass");
        assert_eq!(accepted.root_partition_label, "rootfs-A");
        assert_eq!(accepted.boot_partition_label, "efi-A");
        assert!(accepted.mounts_released);

        let rejected = SupportInstallResult {
            schema_version: 1,
            status: "validated".into(),
            reason: "validation_complete".into(),
            message: "wrong signer fixture".into(),
            phase: "validated".into(),
            target: SupportInstallTarget {
                steamos_version: "3.8.14".into(),
                kernel_version: inputs.kernel_version.clone(),
                nvidia_version: "575.64.05".into(),
                architecture: "x86_64".into(),
            },
            trust: "certified-published".into(),
            cleanup: SupportInstallCleanup {
                mounts_released: true,
            },
            validation: Some(SupportInstallValidation {
                archive_sha256: digest('a'),
                keyring: SupportInstallKeyring {
                    name: "approved-package-signers.gpg".into(),
                    sha256: digest('d'),
                },
                packages: vec![
                    validated_package("nvidia-utils", "2", LIB32_NVIDIA_UTILS_SIGNER, 'b'),
                    validated_package("lib32-nvidia-utils", "1", LIB32_NVIDIA_UTILS_SIGNER, 'c'),
                ],
            }),
        };
        assert!(validate_nvidia_install_result(
            rejected,
            &inputs,
            "validated",
            "validation_complete",
            "validated"
        )
        .err()
        .expect("a package-specific signer mismatch must fail")
        .contains("nvidia-utils"));
    }

    #[test]
    #[ignore = "downloads and verifies the immutable support-installer snapshot"]
    fn live_pinned_nvidia_installer_bundle() {
        struct TestDirectory(PathBuf);
        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = TestDirectory(std::env::temp_dir().join(format!(
            "steamos-builder-pinned-installer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        )));
        fs::create_dir(&root.0).expect("create pinned installer test directory");
        let cancel = AtomicBool::new(false);
        let state = prepare_pinned_nvidia_installer_bundle(
            &root.0,
            &nvidia_http_client().expect("create HTTPS client"),
            &cancel,
            &|_, _, _| {},
        )
        .expect("download pinned installer bundle");
        validate_staged_nvidia_installer_bundle(&state).expect("validate staged installer");
        assert_eq!(state.report.status, "verified");
        assert_eq!(state.report.commit, NVIDIA_INSTALLER_COMMIT);
        assert_eq!(state.report.files.len(), PINNED_INSTALLER_FILES.len());
        assert!(state.root.join("installer-bundle.json").is_file());
        let serialized = serde_json::to_string(&state.report).expect("serialize installer report");
        assert!(!serialized.contains(&root.0.to_string_lossy().to_string()));
    }

    #[test]
    #[ignore = "downloads and validates the current published NVIDIA release"]
    fn live_published_nvidia_resolution() {
        struct TestDirectory(PathBuf);
        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = TestDirectory(std::env::temp_dir().join(format!(
            "steamos-builder-published-nvidia-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        )));
        fs::create_dir(&root.0).expect("create published NVIDIA test directory");
        let kernel = "6.16.12-valve24.5-1-neptune-616-gb2f7cfe85e45";
        let client = nvidia_http_client().expect("create NVIDIA HTTPS client");
        let releases = fetch_github_releases(&client).expect("fetch GitHub releases");
        let cancel = AtomicBool::new(false);
        let result = resolve_published_nvidia_for_target(
            ready_published_target("3.8.16", kernel),
            &root.0,
            &client,
            &releases,
            &cancel,
            &|stage, processed, total| println!("{stage}: {processed}/{total}"),
        )
        .expect("resolve and validate published NVIDIA artifact");
        assert_eq!(result.schema_version, 2);
        assert_eq!(result.status, "compatible");
        assert_eq!(result.compatibility.as_deref(), Some("exact"));
        assert_eq!(
            result
                .artifact
                .as_ref()
                .map(|artifact| artifact.trust.as_str()),
            Some("locally-built-verified")
        );
    }

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
    fn derives_non_overwriting_raw_output_names() {
        let root = std::env::temp_dir().join(format!(
            "steamos-builder-output-name-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("create output-name test directory");
        let compressed = root.join("steamdeck-repair.img.bz2");
        assert_eq!(
            output_path_for_input(&compressed, false).unwrap(),
            root.join("steamdeck-repair-marker.img")
        );
        fs::write(root.join("steamdeck-repair-marker.img"), b"occupied")
            .expect("reserve first output name");
        assert_eq!(
            output_path_for_input(&compressed, false).unwrap(),
            root.join("steamdeck-repair-marker-2.img")
        );
        assert_eq!(
            output_path_for_input(&root.join("raw.img"), false).unwrap(),
            root.join("raw-marker.img")
        );
        fs::write(root.join("already-marker.img"), b"input")
            .expect("create already-suffixed input");
        assert_eq!(
            output_path_for_input(&root.join("already-marker.img"), false).unwrap(),
            root.join("already-marker-2.img")
        );
        let manifest_only_input = root.join("manifest-only.img.xz");
        fs::write(
            manifest_path_for_output(&root.join("manifest-only-marker.img")),
            b"occupied",
        )
        .expect("reserve first manifest name");
        assert_eq!(
            output_path_for_input(&manifest_only_input, false).unwrap(),
            root.join("manifest-only-marker-2.img")
        );
        assert_eq!(
            output_path_for_input(
                &root.join("steamdeck-repair-nvidia-nvidia-marker.img"),
                true,
            )
            .unwrap(),
            root.join("steamdeck-repair-nvidia.img")
        );
        assert_eq!(
            output_path_for_input(&root.join("steamdeck-repair-marker.img"), true).unwrap(),
            root.join("steamdeck-repair-nvidia.img")
        );
        fs::remove_dir_all(root).expect("remove output-name test directory");
    }

    #[test]
    fn parses_qemu_img_percentage_output() {
        assert_eq!(parse_qemu_img_progress("    (42.50/100%)"), Some(42.5));
        assert_eq!(parse_qemu_img_progress("not progress"), None);
    }

    #[test]
    fn normalizes_bounded_os_release_values_without_executing_them() {
        assert_eq!(
            normalize_os_release_field("\"SteamOS 3.8\""),
            Some("SteamOS 3.8".into())
        );
        assert_eq!(
            normalize_os_release_field("'steamdeck'"),
            Some("steamdeck".into())
        );
        assert_eq!(normalize_os_release_field("   "), None);
        assert_eq!(
            normalize_os_release_field("$(touch /tmp/must-not-run)"),
            Some("$(touch /tmp/must-not-run)".into())
        );
    }

    #[test]
    fn marker_manifest_is_versioned_and_omits_host_paths() {
        let input = Path::new("/Users/private-user/Downloads/recovery.img.bz2");
        let output = Path::new("/Users/private-user/Downloads/recovery-marker.img");
        let preparation = InputPreparation {
            source_format: "bzip2".into(),
            normalizer: "sevenzip".into(),
            normalized: true,
            source_bytes: 10,
            image_bytes: 20,
        };
        let layout = SteamOsLayoutDiscovery {
            recognized: true,
            scheme: Some("valve-recovery-a".into()),
            roles: Vec::new(),
            issues: Vec::new(),
        };
        let target_system = TargetSystemDiscovery {
            os_id: Some("steamos".into()),
            pretty_name: Some("SteamOS".into()),
            version_id: Some("3.8.14".into()),
            build_id: Some("20260707.10".into()),
            variant_id: Some("steamdeck".into()),
            architecture: "x86_64".into(),
            kernel_versions: vec!["6.11.11-valve1-neptune-611".into()],
        };
        let manifest = marker_build_manifest(MarkerManifestData {
            input,
            output,
            input_preparation: &preparation,
            input_sha256: "input-hash",
            normalized_sha256: "normalized-hash",
            output_bytes: 20,
            output_sha256: "output-hash",
            layout: &layout,
            target_system: &target_system,
            nvidia_installation: None,
        });
        assert_eq!(manifest["schemaVersion"], 1);
        assert_eq!(manifest["resultClass"], "mutation-valid");
        assert_eq!(manifest["validation"]["passed"], true);
        assert_eq!(manifest["input"]["filename"], "recovery.img.bz2");
        assert_eq!(manifest["output"]["filename"], "recovery-marker.img");
        assert_eq!(manifest["steamos"]["architecture"], "x86_64");
        assert_eq!(
            manifest["steamos"]["targetKernels"][0],
            "6.11.11-valve1-neptune-611"
        );
        let serialized = serde_json::to_string(&manifest).expect("serialize manifest fixture");
        assert!(!serialized.contains("private-user"));
        assert!(!serialized.contains("/Users/"));

        let installation = NvidiaInstallHandoffResult {
            schema_version: 1,
            status: "success".into(),
            reason: "install_complete".into(),
            message: "installed".into(),
            phase: "complete".into(),
            appliance_architecture: "x86_64".into(),
            root_partition_label: "rootfs-A".into(),
            boot_partition_label: "efi-A".into(),
            support_commit: NVIDIA_INSTALLER_COMMIT.into(),
            steamos_version: "3.8.14".into(),
            kernel_version: "6.11.11-valve1-neptune-611".into(),
            nvidia_version: "575.64.05".into(),
            trust: "certified-published".into(),
            archive_sha256: "a".repeat(64),
            keyring_sha256: "b".repeat(64),
            packages: Vec::new(),
            mounts_released: true,
        };
        let nvidia_manifest = marker_build_manifest(MarkerManifestData {
            input,
            output: Path::new("/Users/private-user/Downloads/recovery-nvidia.img"),
            input_preparation: &preparation,
            input_sha256: "input-hash",
            normalized_sha256: "normalized-hash",
            output_bytes: 20,
            output_sha256: "output-hash",
            layout: &layout,
            target_system: &target_system,
            nvidia_installation: Some(&installation),
        });
        assert_eq!(nvidia_manifest["resultClass"], "nvidia-mutation-valid");
        assert_eq!(
            nvidia_manifest["integration"]["nvidia"]["nvidiaVersion"],
            "575.64.05"
        );
        assert_eq!(nvidia_manifest["validation"]["nvidiaPayloadVerified"], true);
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
    fn recognizes_observed_valve_recovery_layout_conservatively() {
        let partition = |path: &str,
                         size_bytes: u64,
                         filesystem: &str,
                         filesystem_label: &str,
                         partition_label: &str,
                         partition_type: &str| ImageNodeInspection {
            path: path.into(),
            node_type: "part".into(),
            size_bytes,
            start_bytes: Some(0),
            filesystem: Some(filesystem.into()),
            filesystem_label: Some(filesystem_label.into()),
            partition_label: Some(partition_label.into()),
            partition_type: Some(partition_type.into()),
            partition_uuid: Some("fixture-partition-uuid".into()),
            filesystem_uuid: Some("fixture-filesystem-uuid".into()),
            mounted: false,
        };
        let mut nodes = vec![
            partition(
                "/dev/vdc1",
                67_091_456,
                "vfat",
                "esp",
                "esp",
                "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
            ),
            partition(
                "/dev/vdc2",
                134_217_728,
                "vfat",
                "efi",
                "efi-A",
                "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
            ),
            partition(
                "/dev/vdc3",
                5_368_709_120,
                "btrfs",
                "rootfs",
                "rootfs-A",
                "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
            ),
            partition(
                "/dev/vdc4",
                268_435_456,
                "ext4",
                "var",
                "var-A",
                "4d21b016-b534-45c2-a9fb-5c16e091fd2d",
            ),
            partition(
                "/dev/vdc5",
                2_147_466_752,
                "ext4",
                "home",
                "home",
                "933ac7e1-2eb4-4f13-b844-0e14e2aef915",
            ),
        ];
        let detected = discover_steamos_layout(Some("gpt"), &nodes);
        assert!(detected.recognized);
        assert_eq!(detected.scheme.as_deref(), Some("valve-recovery-a"));
        assert_eq!(detected.roles.len(), 5);
        assert!(detected.issues.is_empty());

        nodes[2].partition_label = Some("unexpected-root".into());
        let rejected = discover_steamos_layout(Some("gpt"), &nodes);
        assert!(!rejected.recognized);
        assert!(rejected.issues.iter().any(|issue| issue.contains("rootfs")));
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
        let retry_mutation = mutate_synthetic_marker(&session)
            .expect("repeated synthetic marker mutation should remain idempotent");
        assert!(retry_mutation.source_unchanged);
        assert_eq!(
            retry_mutation.source_sha256_before,
            retry_mutation.source_sha256_after
        );
        assert!(retry_mutation.working_read_only);
        assert!(!retry_mutation.mounted);
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

    #[test]
    #[ignore = "launches the separately prepared x86_64 Fedora build appliance"]
    fn live_nvidia_build_appliance_reaches_ready_marker() {
        let appliance = nvidia_build_appliance_path();
        let appliance_sha256_before = sha256_file(&appliance).expect("hash x86 appliance before");
        let mut session =
            prepare_nvidia_build_session(None).expect("the x86 build appliance should start");
        let deadline = Instant::now() + NVIDIA_BUILD_BOOT_TIMEOUT;
        loop {
            assert_eq!(
                session.child.try_wait().expect("x86 QEMU status"),
                None,
                "x86 QEMU exited before readiness"
            );
            if handshake(&session).as_deref() == Ok(READY_MARKER) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "x86 build-appliance handshake timed out"
            );
            thread::sleep(Duration::from_secs(1));
        }
        let health = collect_guest_health(&session).expect("x86 guest health should pass");
        assert_eq!(health.protocol_version, "1");
        assert_eq!(health.architecture, "x86_64");
        assert!(!health.required_tools.is_empty());
        let runtime_dir = session.runtime_dir.clone();
        let archived_log = stop_nvidia_build_session(&mut session)
            .expect("the x86 appliance should stop and clean up")
            .expect("the x86 QEMU log should be archived");
        assert!(!runtime_dir.exists(), "the x86 runtime should be removed");
        assert!(archived_log.is_file(), "the x86 log should remain");
        assert_eq!(
            appliance_sha256_before,
            sha256_file(&appliance).expect("hash x86 appliance after"),
            "the x86 base appliance must remain unchanged"
        );
    }

    #[test]
    #[ignore = "launches x86_64 Fedora with a disposable handoff qcow2"]
    fn live_nvidia_build_appliance_attaches_handoff_qcow2() {
        let qemu_img = find_binary("qemu-img").expect("qemu-img is required");
        let root = std::env::temp_dir().join(format!(
            "steamos-builder-handoff-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create handoff test directory");
        let target = root.join("working.qcow2");
        run_checked(
            Command::new(&qemu_img)
                .args(["create", "-f", "qcow2"])
                .arg(&target)
                .arg("64M"),
            "create handoff fixture",
        )
        .expect("create handoff qcow2");
        let mut session = prepare_nvidia_build_session(Some(&target))
            .expect("the x86 handoff appliance should start");
        let deadline = Instant::now() + NVIDIA_BUILD_BOOT_TIMEOUT;
        loop {
            assert_eq!(
                session.child.try_wait().expect("x86 QEMU status"),
                None,
                "x86 QEMU exited before readiness"
            );
            if handshake(&session).as_deref() == Ok(READY_MARKER) {
                break;
            }
            assert!(Instant::now() < deadline, "x86 handoff appliance timed out");
            thread::sleep(Duration::from_secs(1));
        }
        run_guest_command(
            &session,
            "set -eu; TARGET=/dev/disk/by-id/virtio-steamos-target; test -b \"$TARGET\"; test \"$(sudo blockdev --getro \"$TARGET\")\" = 0; ! findmnt -rn -S \"$TARGET\" >/dev/null 2>&1",
        )
        .expect("the handoff device should be uniquely addressable and unmounted");
        stop_nvidia_build_session(&mut session).expect("stop handoff appliance");
        run_checked(
            Command::new(qemu_img).args(["check"]).arg(&target),
            "validate handoff fixture",
        )
        .expect("handoff qcow2 should remain valid");
        fs::remove_dir_all(root).expect("remove handoff fixture");
    }

    #[test]
    #[ignore = "downloads dependencies/headers/source and compiles NVIDIA under x86_64 QEMU"]
    fn live_nvidia_offline_target_build() {
        let support_repository = std::env::var_os("NVIDIA_SUPPORT_REPO")
            .map(PathBuf::from)
            .expect("set NVIDIA_SUPPORT_REPO to the support-repository checkout");
        let output_dir = std::env::var_os("NVIDIA_TARGET_ARTIFACT_DIR")
            .map(PathBuf::from)
            .expect("set NVIDIA_TARGET_ARTIFACT_DIR to an empty output directory");
        let mut session =
            prepare_nvidia_build_session(None).expect("the x86 build appliance should start");
        let deadline = Instant::now() + NVIDIA_BUILD_BOOT_TIMEOUT;
        loop {
            assert_eq!(
                session.child.try_wait().expect("x86 QEMU status"),
                None,
                "x86 QEMU exited before readiness"
            );
            if handshake(&session).as_deref() == Ok(READY_MARKER) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "x86 build-appliance handshake timed out"
            );
            thread::sleep(Duration::from_secs(1));
        }
        let health = collect_guest_health(&session).expect("x86 guest health should pass");
        assert_eq!(health.architecture, "x86_64");
        let spec = NvidiaTargetBuildSpec {
            steamos_version: "3.8.14".into(),
            kernel_version: "6.16.12-valve24.4-1-neptune-616-gfe145653a794".into(),
            nvidia_version: "575.64.05".into(),
        };
        let connection = NvidiaBuildConnection::from(&session);
        let build_log = connection.runtime_dir.join("nvidia-build.log");
        let build_result = thread::scope(|scope| {
            let worker = scope.spawn(|| {
                build_nvidia_for_target(&connection, &support_repository, &output_dir, &spec, None)
            });
            let mut printed_bytes = 0_u64;
            while !worker.is_finished() {
                if let Ok(mut log) = File::open(&build_log) {
                    if log.seek(SeekFrom::Start(printed_bytes)).is_ok() {
                        let mut update = Vec::new();
                        if log.read_to_end(&mut update).is_ok() && !update.is_empty() {
                            std::io::stdout()
                                .write_all(&update)
                                .and_then(|_| std::io::stdout().flush())
                                .expect("print NVIDIA build progress");
                            printed_bytes += update.len() as u64;
                        }
                    }
                }
                thread::sleep(Duration::from_secs(1));
            }
            if let Ok(mut log) = File::open(&build_log) {
                if log.seek(SeekFrom::Start(printed_bytes)).is_ok() {
                    let mut update = Vec::new();
                    if log.read_to_end(&mut update).is_ok() && !update.is_empty() {
                        std::io::stdout()
                            .write_all(&update)
                            .and_then(|_| std::io::stdout().flush())
                            .expect("print final NVIDIA build progress");
                    }
                }
            }
            worker.join().expect("NVIDIA build worker should not panic")
        });
        let stop_result = stop_nvidia_build_session(&mut session);
        let artifact = build_result.expect("the exact-kernel NVIDIA target build should pass");
        stop_result.expect("the x86 build appliance should stop cleanly");
        println!(
            "{}",
            serde_json::to_string_pretty(&artifact).expect("serialize NVIDIA artifact report")
        );
        assert_eq!(artifact.trust, "development-unverified");
        assert!(Path::new(&artifact.archive_path).is_file());
        assert!(Path::new(&artifact.checksum_path).is_file());
        assert!(Path::new(&artifact.build_info_path).is_file());
        assert!(Path::new(&artifact.provenance_path).is_file());
        assert!(Path::new(&artifact.result_path).is_file());
    }

    #[test]
    #[ignore = "requires STEAMOS_RECOVERY_IMAGE and launches the local Fedora/QEMU appliance"]
    fn live_recovery_image_layout_report() {
        let input = std::env::var_os("STEAMOS_RECOVERY_IMAGE")
            .map(PathBuf::from)
            .expect("set STEAMOS_RECOVERY_IMAGE to a Valve recovery image");
        let mut session = prepare_session(Some(&input), None, None)
            .expect("the recovery-image appliance session should start");
        for _ in 0..160 {
            assert_eq!(
                session.child.try_wait().expect("QEMU status"),
                None,
                "QEMU exited before readiness"
            );
            if handshake(&session).ok().as_deref() == Some(READY_MARKER) {
                session.state = "ready".into();
                break;
            }
            thread::sleep(Duration::from_millis(750));
        }
        assert_eq!(session.state, "ready", "appliance did not become ready");
        let inspection_session = ImageInspectionSession::from(&session);
        let inspection = inspect_user_image(&inspection_session, None, None)
            .expect("the recovery image should inspect read-only");
        assert!(
            inspection.layout.recognized,
            "the selected recovery image layout was not recognized: {}",
            inspection.layout.issues.join(" ")
        );
        assert_eq!(
            inspection.layout.scheme.as_deref(),
            Some("valve-recovery-a")
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&inspection).expect("serialize recovery-image report")
        );
        let working = verify_user_working_image(&session)
            .expect("the recovery-image working layer should verify");
        println!(
            "{}",
            serde_json::to_string_pretty(&working).expect("serialize working-layer report")
        );
        let mutation = mutate_user_marker(&inspection_session)
            .expect("the recovery-image working layer should accept the marker");
        assert!(mutation.input_unchanged);
        assert!(mutation.working_read_only);
        assert!(!mutation.mounted);
        assert_eq!(mutation.target_partition_label, "rootfs-A");
        assert_eq!(mutation.filesystem, "btrfs");
        let nvidia_target = assess_nvidia_target_system(&mutation.system);
        assert!(
            nvidia_target.ready,
            "the recovery image should provide one exact NVIDIA target: {}",
            nvidia_target.message
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&mutation).expect("serialize marker-mutation report")
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&nvidia_target)
                .expect("serialize NVIDIA target readiness")
        );
        stop_session(&mut session).expect("stop recovery-image appliance session");
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
        .manage(Mutex::new(NvidiaBuildManager::default()))
        .setup(|_| {
            cleanup_abandoned_runtimes().map_err(std::io::Error::other)?;
            cleanup_abandoned_nvidia_build_runtimes().map_err(std::io::Error::other)?;
            Ok(())
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            check_builder_environment,
            check_nvidia_build_environment,
            start_appliance,
            start_nvidia_build_appliance,
            get_appliance_status,
            get_nvidia_build_appliance_status,
            read_appliance_log,
            read_nvidia_build_appliance_log,
            guest_health,
            nvidia_build_guest_health,
            build_nvidia_target_development,
            verify_guest_transfer,
            inspect_test_disk,
            inspect_selected_image,
            verify_working_image,
            mutate_test_marker,
            mutate_selected_marker,
            assess_nvidia_target,
            resolve_published_nvidia,
            prepare_nvidia_userspace,
            prepare_nvidia_installer_bundle,
            start_nvidia_install_appliance,
            validate_nvidia_install_handoff,
            install_nvidia_to_working_image,
            export_marker_image,
            stop_appliance,
            stop_nvidia_build_appliance,
            validate_image,
            open_progress_window,
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
            if let Ok(mut manager) = app_handle.state::<Mutex<NvidiaBuildManager>>().lock() {
                if let Some(mut session) = manager.session.take() {
                    let _ = stop_nvidia_build_session(&mut session);
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
            if let Ok(mut manager) = app_handle.state::<Mutex<NvidiaBuildManager>>().lock() {
                if let Some(mut session) = manager.session.take() {
                    let _ = stop_nvidia_build_session(&mut session);
                }
            }
        }
        _ => {}
    });
}

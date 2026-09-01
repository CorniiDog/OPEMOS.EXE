use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
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
const BUILDER_SETTINGS_SCHEMA: u32 = 3;
const APPROVED_VALVE_SIGNER: &str = "889B5EBDDD505A683621900DAF1D2199EF0A3CCF";
const RELEASES_RESPONSE_LIMIT: u64 = 4 * 1024 * 1024;
const CHECKSUM_RESPONSE_LIMIT: u64 = 4 * 1024;
const PROVENANCE_RESPONSE_LIMIT: u64 = 1024 * 1024;
const NVIDIA_ARCHIVE_LIMIT: u64 = 1024 * 1024 * 1024;
const NVIDIA_ARCHIVE_MEMBER_LIMIT: u64 = 1024 * 1024 * 1024;
const NVIDIA_ARCHIVE_EXPANDED_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const NVIDIA_HANDOFF_FREE_SPACE_RESERVE: u64 = 512 * 1024 * 1024;
const _: () = assert!(NVIDIA_ARCHIVE_LIMIT >= 700 * 1024 * 1024);
const _: () = assert!(NVIDIA_ARCHIVE_LIMIT <= 2 * 1024 * 1024 * 1024);
const ARCH_ARCHIVE_INDEX_LIMIT: u64 = 8 * 1024 * 1024;
const NVIDIA_UTILS_ARCHIVE_LIMIT: u64 = 512 * 1024 * 1024;
const LIB32_NVIDIA_UTILS_ARCHIVE_LIMIT: u64 = 128 * 1024 * 1024;
const NVIDIA_DEPENDENCY_ARCHIVE_LIMIT: u64 = 256 * 1024 * 1024;
const NVIDIA_DEPENDENCY_LIMIT: usize = 16;
const ARCH_PACKAGE_SIGNATURE_LIMIT: u64 = 16 * 1024;
const MAX_NORMALIZED_IMAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const NVIDIA_SUPPORT_REPOSITORY: &str = "CorniiDog/open-gpu-kernel-modules-steamos-support";
const NVIDIA_SUPPORT_COMMIT: &str = "f8c569c72fc6c1ecfba3d1a87235886f09baaa63";
const NVIDIA_INSTALLER_COMMIT: &str = NVIDIA_SUPPORT_COMMIT;
const NVIDIA_SUPPORT_BUILD_COMMIT: &str = NVIDIA_SUPPORT_COMMIT;
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BuilderSettings {
    schema_version: u32,
    auto_release_verified_nvidia: bool,
    track_steamos_driver_updates: bool,
    #[serde(default)]
    include_upstream_nvidia_releases: bool,
    #[serde(default)]
    omit_optional_cuda: bool,
}

impl Default for BuilderSettings {
    fn default() -> Self {
        Self {
            schema_version: BUILDER_SETTINGS_SCHEMA,
            auto_release_verified_nvidia: false,
            track_steamos_driver_updates: false,
            include_upstream_nvidia_releases: false,
            omit_optional_cuda: false,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GithubMaintainerStatus {
    gh_available: bool,
    authenticated: bool,
    authorized: bool,
    username: Option<String>,
    permission: Option<String>,
    message: String,
}

#[derive(Deserialize)]
struct GithubRepositoryPermission {
    permission: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaReleasePublication {
    status: String,
    repository: String,
    tag: String,
    url: String,
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportPublicationPlan {
    schema_version: u32,
    status: String,
    repository: String,
    tag: String,
    target_commit: String,
    trust: String,
    archive_sha256: String,
    assets: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct GithubBranchCommit {
    sha: String,
}

#[derive(Clone, Debug, Deserialize)]
struct GithubBranch {
    name: String,
    commit: GithubBranchCommit,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaSourceBranch {
    name: String,
    version: String,
    commit: String,
    origin: String,
    repository: String,
    selection: String,
    experimental: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MaintainerWorkspaceSource {
    component: String,
    origin: String,
    repository: String,
    reference: String,
    commit: String,
    label: String,
    experimental: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MaintainerWorkspacePlan {
    schema_version: u32,
    status: String,
    plan_id: String,
    component: String,
    origin: String,
    repository: String,
    reference: String,
    commit: String,
    architecture: String,
    isolation: String,
    maintainer: String,
    permission: String,
    remote_mutation_allowed: bool,
    message: String,
}

struct PinnedInstallerFile {
    path: &'static str,
    sha256: &'static str,
    bytes: u64,
    executable: bool,
}

const PINNED_INSTALLER_FILES: [PinnedInstallerFile; 15] = [
    PinnedInstallerFile {
        path: "bootstrap/install_to_root.sh",
        sha256: "731765273a355270c25c13c45a341d7e3c7354c87331e548d8d3ee1404077c81",
        bytes: 22_373,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/common.sh",
        sha256: "484390ce35347c8783258b79ad9e1e54aad3c59e5247a60562876981adb4e9be",
        bytes: 7_129,
        executable: false,
    },
    PinnedInstallerFile {
        path: "lib/run_in_process_group.py",
        sha256: "06ada2883b18e40a8114861644e03bf59bc10b9bd8174a5437e47fc77a3f177f",
        bytes: 250,
        executable: false,
    },
    PinnedInstallerFile {
        path: "lib/update_grub_nvidia_args.py",
        sha256: "035e97a9019087d8486dc9eebeb8def1d7365c88cc1b6638c511a1e5b137ee68",
        bytes: 3_145,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/validate_install_inputs.py",
        sha256: "2b411a3846109146c1a49ba2be1ec553a0c1f8b4ebb8c8416e6db3aee63e9cd6",
        bytes: 84_674,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/write_install_result.py",
        sha256: "9113cb701047865b7fda330cd64aa76e0c1ededcd7240402594a881da123783c",
        bytes: 26_819,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/measure_btrfs_payload.py",
        sha256: "04c2ad0779257961981609bb4c120760dd79838c000a466cfd9394cb5973eddc",
        bytes: 24_592,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/atomic_output.py",
        sha256: "4182f1e1fab6ed5a9ebe59a40250335774b46354a64fbb7b00c7429ea8b4cc05",
        bytes: 1_117,
        executable: false,
    },
    PinnedInstallerFile {
        path: "lib/gaming_payload_profiles.py",
        sha256: "ed0e54389a648ef6bafed62cf799254a460de1c5c54ddf1409beea9167455eeb",
        bytes: 6_066,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/verify_installed_modules.py",
        sha256: "b860a3b7655773c6b3fc2b7712d65811fd960195e45bac1e69552e7eedec5571",
        bytes: 5_139,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/verify_installed_userspace.py",
        sha256: "233b3282423faeefa1967f2a39a051c59418e6b87ce67ef4b2a4a9a834dc4178",
        bytes: 10_985,
        executable: true,
    },
    PinnedInstallerFile {
        path: "trust/nvidia-userspace-package-signers.json",
        sha256: "dbe87b0e11cae8dca671be491ffbf24bcbb22ff3a1712c4156ef88c4b476db95",
        bytes: 1_197,
        executable: false,
    },
    PinnedInstallerFile {
        path: NVIDIA_USERSPACE_KEYRING_PATH,
        sha256: NVIDIA_USERSPACE_KEYRING_SHA256,
        bytes: 21_552,
        executable: false,
    },
    PinnedInstallerFile {
        path: NVIDIA_USERSPACE_LOCK_PATH,
        sha256: NVIDIA_USERSPACE_LOCK_SHA256,
        bytes: 5_623,
        executable: false,
    },
    PinnedInstallerFile {
        path: "profiles/gaming/reviewed-policy-v1.json",
        sha256: "4e11a8ea25f8aec91f5f7bbb0dfd5733209e28f0a0337e9f419b3268359f5b27",
        bytes: 397,
        executable: false,
    },
];

const PINNED_PUBLISHER_FILES: [PinnedInstallerFile; 2] = [
    PinnedInstallerFile {
        path: "bootstrap/publish_artifacts.sh",
        sha256: "ce7cb271a73ab0f13f701965d49b103e6d228714e171ac16c22b89b776ba0cde",
        bytes: 3_726,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/validate_publish_inputs.py",
        sha256: "a45c6ed32154a1fb4961e91396c3b5ca0392bcd7853d80026d752486fe0bdb87",
        bytes: 16_258,
        executable: true,
    },
];

#[derive(Serialize)]
struct ImageInfo {
    path: String,
    name: String,
}

#[derive(Serialize)]
struct ImageOutputPreview {
    input_path: String,
    output_path: String,
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

#[derive(Clone, Serialize)]
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
    source: SupportProvenanceSource,
    headers: SupportProvenanceHeaders,
    modules: Vec<SupportProvenanceModule>,
}

#[derive(Deserialize)]
struct SupportProvenanceArtifact {
    archive: String,
}

#[derive(Deserialize)]
struct SupportProvenanceSource {
    repository: String,
    branch: String,
    commit: String,
    dirty: String,
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
    build_info_path: Option<String>,
    provenance_path: String,
    archive_sha256: String,
    archive_bytes: u64,
    expanded_bytes: u64,
    trust: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaOnDemandBuildPlan {
    steamos_version: String,
    kernel_version: String,
    nvidia_version: String,
    baseline_release: String,
    support_commit: String,
    expected_trust: String,
    source_origin: String,
    source_repository: String,
    source_branch: String,
    source_commit: String,
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
    build_plan: Option<NvidiaOnDemandBuildPlan>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaUserspacePackage {
    name: String,
    role: String,
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

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReviewedUserspaceLock {
    schema_version: u32,
    status: String,
    target: ReviewedUserspaceTarget,
    keyring: ReviewedUserspaceKeyring,
    missing_review: Vec<String>,
    packages: Vec<ReviewedUserspacePackage>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReviewedUserspaceTarget {
    steamos_version: String,
    nvidia_version: String,
    architecture: String,
}

#[derive(Clone, Deserialize)]
struct ReviewedUserspaceKeyring {
    filename: String,
    sha256: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReviewedUserspacePackage {
    name: String,
    version: String,
    architecture: String,
    filename: String,
    signature_filename: String,
    package_sha256: String,
    signature_sha256: String,
    signer_fingerprint: String,
    installed_size: u64,
    dependencies: Vec<String>,
    provides: Vec<String>,
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

#[derive(Clone)]
struct NvidiaInstallInputs {
    image_runtime_dir: PathBuf,
    working_image: PathBuf,
    installer_root: PathBuf,
    archive: PathBuf,
    checksum: PathBuf,
    provenance: PathBuf,
    archive_sha256: String,
    archive_bytes: u64,
    expanded_bytes: u64,
    provenance_sha256: String,
    trust: String,
    steamos_version: String,
    kernel_version: String,
    nvidia_version: String,
    packages: Vec<NvidiaUserspacePackage>,
    userspace_lock: ReviewedUserspaceLock,
}

#[derive(Clone, Deserialize)]
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
    validation: Option<SupportInstallValidationDocument>,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum SupportInstallValidationDocument {
    Verified(Box<SupportInstallValidation>),
    Failed(Box<SupportInstallFailureValidation>),
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallTarget {
    steamos_version: String,
    kernel_version: String,
    nvidia_version: String,
    architecture: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallCleanup {
    mounts_released: bool,
    compression_policy_restored: bool,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SupportInstallGamingPayload {
    schema_version: u32,
    status: String,
    profile_id: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallValidation {
    archive_sha256: String,
    provenance_sha256: String,
    userspace_lock: SupportInstallPinnedIdentity,
    pacman_database: SupportInstallPacmanDatabase,
    boot: SupportInstallBoot,
    keyring: SupportInstallKeyring,
    packages: Vec<SupportInstallPackage>,
    package_dependency_closure: Vec<SupportInstallDependency>,
    gaming_payload: SupportInstallGamingPayload,
    compression: SupportInstallCompression,
    storage: SupportInstallStorage,
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallFailureValidation {
    #[serde(default)]
    storage: Option<SupportInstallStorage>,
    #[serde(default)]
    compression: Option<SupportInstallCompression>,
    #[serde(default)]
    missing_dependencies: Vec<String>,
    #[serde(default)]
    dependency_requested_by: Option<String>,
    #[serde(default)]
    package_name: Option<String>,
    #[serde(default)]
    signer_fingerprint: Option<String>,
    #[serde(default)]
    missing_packages: Vec<String>,
    #[serde(default)]
    unexpected_packages: Vec<String>,
    #[serde(default)]
    duplicate_packages: Vec<String>,
    #[serde(default)]
    package_mismatches: Vec<SupportInstallPackageMismatch>,
    #[serde(default)]
    package_record: Option<String>,
    #[serde(default)]
    invalid_fields: Vec<String>,
    #[serde(default)]
    measurement_failure: Option<SupportInstallMeasurementFailure>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SupportInstallMeasurementFailure {
    phase: String,
    command: Option<String>,
    exit_status: Option<i16>,
    stderr: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallPackageMismatch {
    package_name: String,
    invalid_fields: Vec<String>,
    expected: HashMap<String, serde_json::Value>,
    actual: HashMap<String, serde_json::Value>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallStorage {
    root_available_bytes: u64,
    root_required_bytes: u64,
    var_available_bytes: u64,
    var_required_bytes: u64,
    efi_available_bytes: u64,
    efi_required_bytes: u64,
    package_installed_bytes: u64,
    package_compressed_bytes: u64,
    package_replaced_bytes: u64,
    module_installed_bytes: u64,
    module_replaced_bytes: u64,
    initramfs_reserve_bytes: u64,
    #[serde(default)]
    root_conservative_required_bytes: Option<u64>,
    #[serde(default)]
    root_measured_required_bytes: Option<u64>,
    #[serde(default)]
    root_logical_required_bytes: Option<u64>,
    #[serde(default)]
    measured_payload_allocated_bytes: Option<u64>,
    #[serde(default)]
    compression_payload_allocated_bytes: Option<u64>,
    #[serde(default)]
    compression_filesystem_overhead_bytes: Option<u64>,
    #[serde(default)]
    compression_safety_reserve_bytes: Option<u64>,
    #[serde(default)]
    compression_reserve_bytes: Option<u64>,
    #[serde(default)]
    replacement_candidate_logical_bytes: Option<u64>,
    #[serde(default)]
    replacement_credit_bytes: Option<u64>,
    #[serde(default)]
    package_noop_credit_bytes: Option<u64>,
    #[serde(default)]
    module_noop_credit_bytes: Option<u64>,
    #[serde(default)]
    root_final_margin_bytes: Option<i64>,
    #[serde(default)]
    root_shortfall_bytes: Option<u64>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallPinnedIdentity {
    name: String,
    sha256: String,
}

#[derive(Clone, Deserialize)]
struct SupportInstallDependency {
    name: String,
    version: String,
    source: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallCompressionMeasurement {
    schema_version: u32,
    status: String,
    profile: String,
    write_policy: String,
    measurement_method: String,
    declared_payload_bytes: u64,
    scratch_filesystem_bytes: u64,
    payload_allocated_bytes: u64,
    data_allocated_bytes: u64,
    metadata_allocated_bytes: u64,
    system_allocated_bytes: u64,
    filesystem_overhead_bytes: u64,
    package_measurements: Vec<SupportInstallPackageMeasurement>,
    module_allocated_bytes: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallPackageMeasurement {
    filename: String,
    allocated_bytes: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallCompression {
    filesystem: String,
    enabled: bool,
    options: Vec<String>,
    admission_basis: String,
    compression_savings_credited_bytes: u64,
    declared_package_bytes: u64,
    package_archive_bytes: u64,
    package_archive_savings_bytes: u64,
    declared_sizes_likely_conservative: bool,
    assessment: String,
    #[serde(default)]
    requested_profile: Option<String>,
    #[serde(default)]
    write_policy: Option<String>,
    #[serde(default)]
    measurement: Option<SupportInstallCompressionMeasurement>,
    #[serde(default)]
    measured_payload_savings_bytes: Option<u64>,
    #[serde(default)]
    admission_authorized: Option<bool>,
    #[serde(default)]
    mutation_profile_implemented: Option<bool>,
    #[serde(default)]
    compression_ratio: Option<String>,
    #[serde(default)]
    all_payload_destinations_on_root_filesystem: Option<bool>,
    #[serde(default)]
    replacement_credit_policy: Option<String>,
    #[serde(default)]
    module_payload_noop: Option<bool>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallPacmanDatabase {
    path: String,
    package_count: u64,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallBoot {
    rootfs_boot_path: String,
    efi_mount_path: String,
    grub_configuration: String,
    required_kernel_arguments: Vec<String>,
}

#[derive(Clone, Deserialize)]
struct SupportInstallKeyring {
    name: String,
    sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportInstallPackage {
    name: String,
    role: String,
    filename: String,
    signature_filename: String,
    full_version: String,
    pkgver: String,
    pkgrel: String,
    architecture: String,
    signer: String,
    sha256: String,
    signature_sha256: String,
    installed_size: u64,
    dependencies: Vec<String>,
    provides: Vec<String>,
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
    provenance_sha256: String,
    pacman_database_path: String,
    pacman_package_count: u64,
    rootfs_boot_path: String,
    efi_mount_path: String,
    grub_configuration: String,
    required_kernel_arguments: Vec<String>,
    keyring_sha256: String,
    packages: Vec<SupportInstallPackage>,
    storage: SupportInstallStorage,
    compression: SupportInstallCompression,
    mounts_released: bool,
    compression_policy_restored: bool,
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
    nvidia_resolution: Option<&'a NvidiaPublishedResolution>,
    nvidia_source_selection: Option<&'a str>,
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
    let nvidia_source_policy = data.nvidia_installation.map(|installation| {
        let selection = data.nvidia_source_selection.unwrap_or("automatic");
        let automatic = selection == "automatic";
        let plan = data
            .nvidia_resolution
            .and_then(|resolution| resolution.build_plan.as_ref());
        let source_origin = plan
            .map(|plan| plan.source_origin.as_str())
            .unwrap_or("project");
        let source_repository = plan
            .map(|plan| plan.source_repository.as_str())
            .or(Some(if source_origin == "upstream" {
                NVIDIA_UPSTREAM_REPOSITORY
            } else {
                NVIDIA_SOURCE_REPOSITORY
            }));
        let fallback_reference = (!automatic).then(|| {
            selection
                .strip_prefix("project:")
                .map(str::to_string)
                .unwrap_or_else(|| format!("nvidia/{}", installation.nvidia_version))
        });
        serde_json::json!({
            "selection": selection,
            "mode": if automatic { "automatic" } else { "pinned" },
            "nvidiaVersion": installation.nvidia_version,
            "sourceOrigin": source_origin,
            "sourceRepository": source_repository,
            "sourceReference": plan.map(|plan| plan.source_branch.as_str()).or(fallback_reference.as_deref()),
            "sourceCommit": plan.map(|plan| plan.source_commit.as_str()),
            "updateBehavior": if automatic {
                "follow-newest-compatible-verified-profile"
            } else {
                "rebuild-exact-version-or-require-user-decision"
            }
        })
    });
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
            "nvidiaSourcePolicy": nvidia_source_policy,
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
    nvidia_source_selection: Option<String>,
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
    qmp_port: u16,
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

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GuestResourcePlan {
    schema_version: u32,
    workload: String,
    host_memory_bytes: u64,
    host_logical_cpus: usize,
    guest_memory_mib: u64,
    guest_vcpus: usize,
}

fn plan_guest_resources(
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

fn detect_guest_resources(build_worker: bool) -> Result<GuestResourcePlan, String> {
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

struct BoundedWriter<W> {
    inner: W,
    written: u64,
    limit: u64,
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

fn archive_and_remove_nvidia_build_runtime(runtime_dir: &Path) -> Result<Option<PathBuf>, String> {
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

fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join("settings.json"))
        .map_err(|error| format!("Could not determine the settings directory: {error}"))
}

fn load_builder_settings(app: &tauri::AppHandle) -> Result<BuilderSettings, String> {
    let path = settings_path(app)?;
    if !path.exists() {
        return Ok(BuilderSettings::default());
    }
    let mut settings: BuilderSettings = serde_json::from_reader(
        File::open(&path).map_err(|error| format!("Could not open settings.json: {error}"))?,
    )
    .map_err(|error| format!("settings.json is invalid: {error}"))?;
    if matches!(settings.schema_version, 1 | 2) {
        if settings.schema_version == 1 {
            settings.include_upstream_nvidia_releases = false;
        }
        settings.schema_version = BUILDER_SETTINGS_SCHEMA;
        settings.omit_optional_cuda = false;
        save_builder_settings(app, &settings)?;
    } else if settings.schema_version != BUILDER_SETTINGS_SCHEMA {
        return Err(format!(
            "Unsupported settings schema {}; expected {}.",
            settings.schema_version, BUILDER_SETTINGS_SCHEMA
        ));
    }
    Ok(settings)
}

fn save_builder_settings(app: &tauri::AppHandle, settings: &BuilderSettings) -> Result<(), String> {
    if settings.schema_version != BUILDER_SETTINGS_SCHEMA {
        return Err(format!(
            "Only settings schema {BUILDER_SETTINGS_SCHEMA} can be saved."
        ));
    }
    let path = settings_path(app)?;
    let parent = path
        .parent()
        .ok_or("Settings path has no parent directory.")?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Could not create the settings directory: {error}"))?;
    let temporary = parent.join(format!(".settings.json.{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec_pretty(settings)
        .map_err(|error| format!("Could not serialize settings: {error}"))?;
    fs::write(&temporary, bytes)
        .map_err(|error| format!("Could not stage settings.json: {error}"))?;
    fs::rename(&temporary, &path)
        .map_err(|error| format!("Could not finalize settings.json: {error}"))
}

fn github_maintainer_status() -> Result<GithubMaintainerStatus, String> {
    let Some(gh) = find_binary("gh") else {
        return Ok(GithubMaintainerStatus {
            gh_available: false,
            authenticated: false,
            authorized: false,
            username: None,
            permission: None,
            message: "GitHub CLI is not available. The packaged application must bundle it before maintainer publishing can be enabled.".into(),
        });
    };
    let auth = Command::new(&gh)
        .args(["auth", "status", "--hostname", "github.com"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("Could not check GitHub authentication: {error}"))?;
    if !auth.success() {
        return Ok(GithubMaintainerStatus {
            gh_available: true,
            authenticated: false,
            authorized: false,
            username: None,
            permission: None,
            message:
                "GitHub is not connected. Use browser login to authorize the maintainer workflow."
                    .into(),
        });
    }
    let user_output = Command::new(&gh)
        .args(["api", "user", "--jq", ".login"])
        .output()
        .map_err(|error| format!("Could not query the authenticated GitHub account: {error}"))?;
    if !user_output.status.success() {
        return Err(
            "GitHub authentication succeeded, but the account identity could not be verified."
                .into(),
        );
    }
    let username = String::from_utf8(user_output.stdout)
        .map_err(|_| "GitHub returned a non-UTF-8 account name.".to_string())?
        .trim()
        .to_string();
    if username.is_empty()
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("GitHub returned an invalid account name.".into());
    }
    let permission = github_repository_permission(&gh, &username, NVIDIA_SUPPORT_REPOSITORY)?;
    let authorized = permission
        .as_deref()
        .is_some_and(github_permission_can_publish);
    Ok(GithubMaintainerStatus {
        gh_available: true,
        authenticated: true,
        authorized,
        username: Some(username.clone()),
        permission: permission.clone(),
        message: if authorized {
            format!("Connected as {username}; release permission verified.")
        } else {
            format!(
                "Connected as {username}, but release permission for {NVIDIA_SUPPORT_REPOSITORY} was not verified."
            )
        },
    })
}

fn parse_github_repository_permission(response: &[u8]) -> Result<String, String> {
    let permission: GithubRepositoryPermission = serde_json::from_slice(response)
        .map_err(|error| format!("GitHub returned an invalid permission response: {error}"))?;
    let permission = permission.permission.trim();
    if permission.is_empty()
        || !permission
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err("GitHub returned an invalid repository permission.".into());
    }
    Ok(permission.to_string())
}

fn github_repository_permission(
    gh: &Path,
    username: &str,
    repository: &str,
) -> Result<Option<String>, String> {
    if username.is_empty()
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !matches!(
            repository,
            NVIDIA_SUPPORT_REPOSITORY | NVIDIA_SOURCE_REPOSITORY | GAMESCOPE_SOURCE_REPOSITORY
        )
    {
        return Err("Refusing to query permission for an unapproved repository identity.".into());
    }
    let endpoint = format!("repos/{repository}/collaborators/{username}/permission");
    let output = Command::new(gh)
        .args(["api", &endpoint])
        .output()
        .map_err(|error| format!("Could not verify {repository} permission: {error}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    parse_github_repository_permission(&output.stdout).map(Some)
}

fn github_permission_can_publish(permission: &str) -> bool {
    matches!(permission, "admin" | "maintain" | "write" | "push")
}

#[tauri::command]
fn get_builder_settings(app: tauri::AppHandle) -> Result<BuilderSettings, String> {
    load_builder_settings(&app)
}

#[tauri::command]
async fn update_builder_settings(
    app: tauri::AppHandle,
    settings: BuilderSettings,
) -> Result<BuilderSettings, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let current = load_builder_settings(&app)?;
        let mut settings = settings;
        settings.schema_version = BUILDER_SETTINGS_SCHEMA;
        if settings.omit_optional_cuda {
            return Err(
                "Optional CUDA omission is unavailable until the pinned support repository provides a reviewed gaming payload profile."
                    .into(),
            );
        }
        let enabling_auto_release =
            settings.auto_release_verified_nvidia && !current.auto_release_verified_nvidia;
        if enabling_auto_release && !github_maintainer_status()?.authorized {
            return Err(
                "Auto-release cannot be enabled until GitHub maintainer permission is verified."
                    .into(),
            );
        }
        save_builder_settings(&app, &settings)?;
        Ok(settings)
    })
    .await
    .map_err(|error| format!("Settings worker failed: {error}"))?
}

#[tauri::command]
async fn get_github_maintainer_status() -> Result<GithubMaintainerStatus, String> {
    tauri::async_runtime::spawn_blocking(github_maintainer_status)
        .await
        .map_err(|error| format!("GitHub authorization worker failed: {error}"))?
}

#[tauri::command]
async fn connect_github_maintainer() -> Result<GithubMaintainerStatus, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let gh = find_binary("gh").ok_or(
            "GitHub CLI is not available. Install it for development; release packages will bundle it.",
        )?;

        #[cfg(target_os = "macos")]
        {
            let quoted_gh = format!("'{}'", gh.to_string_lossy().replace('\'', "'\\''"));
            let terminal_command = format!(
                "{quoted_gh} auth login --hostname github.com --git-protocol https --web --clipboard --skip-ssh-key"
            );
            let apple_script = r#"on run argv
tell application "Terminal"
    activate
    do script (item 1 of argv)
end tell
end run"#;
            let status = Command::new("/usr/bin/osascript")
                .args(["-e", apple_script, "--", &terminal_command])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .status()
                .map_err(|error| format!("Could not open GitHub login in Terminal: {error}"))?;
            if !status.success() {
                return Err("Could not open a visible GitHub login in Terminal.".into());
            }
            Ok(GithubMaintainerStatus {
                gh_available: true,
                authenticated: false,
                authorized: false,
                username: None,
                permission: None,
                message: "GitHub login opened in Terminal. Complete the browser authorization; this panel will detect it automatically.".into(),
            })
        }

        #[cfg(not(target_os = "macos"))]
        Err("Visible GitHub login is currently implemented only for the macOS development application.".into())
    })
    .await
    .map_err(|error| format!("GitHub login worker failed: {error}"))?
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
    let mut child = Command::new(qemu)
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
        nvidia_source_selection: None,
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

    runtime_guard.armed = false;
    Ok(NvidiaBuildSession {
        child,
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

fn qmp_attach_nvidia_target(session: &NvidiaBuildSession) -> Result<(), String> {
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

fn select_nvidia_build_baseline(
    target: &NvidiaTargetReadiness,
    releases: &[GithubRelease],
) -> Result<Option<PublishedReleaseIdentity>, String> {
    if !target.ready {
        return Ok(None);
    }
    let target_steamos = target
        .steamos_version
        .as_deref()
        .ok_or("Ready NVIDIA target omitted its SteamOS version.")?;
    let target_version = numeric_version(target_steamos, 3..=3)
        .ok_or("Ready NVIDIA target contains an invalid SteamOS version.")?;
    let mut older_or_equal = Vec::new();
    let mut newer = Vec::new();
    for release in releases {
        if release.draft || release.prerelease {
            continue;
        }
        let Some(identity) = published_release_identity(&release.tag_name) else {
            continue;
        };
        let steam_version =
            numeric_version(&identity.steamos_version, 3..=3).expect("validated release version");
        if steam_version[..2] != target_version[..2] {
            continue;
        }
        let nvidia_version =
            numeric_version(&identity.nvidia_version, 2..=3).expect("validated NVIDIA version");
        let candidate = (
            steam_version.clone(),
            nvidia_version,
            release.published_at.clone().unwrap_or_default(),
            identity,
        );
        if steam_version <= target_version {
            older_or_equal.push(candidate);
        } else {
            newer.push(candidate);
        }
    }
    older_or_equal
        .sort_by(|left, right| (&left.0, &left.1, &left.2).cmp(&(&right.0, &right.1, &right.2)));
    if let Some((_, _, _, identity)) = older_or_equal.pop() {
        return Ok(Some(identity));
    }
    let Some(nearest_version) = newer.iter().map(|candidate| &candidate.0).min().cloned() else {
        return Ok(None);
    };
    Ok(newer
        .into_iter()
        .filter(|candidate| candidate.0 == nearest_version)
        .max_by(|left, right| (&left.1, &left.2).cmp(&(&right.1, &right.2)))
        .map(|(_, _, _, identity)| identity))
}

fn explicit_nvidia_build_resolution(
    target: NvidiaTargetReadiness,
    source: &NvidiaSourceBranch,
    baseline_release: String,
) -> Result<NvidiaPublishedResolution, String> {
    if !target.ready {
        return Err("An explicit NVIDIA source requires a ready exact image target.".into());
    }
    let steamos_version = target
        .steamos_version
        .clone()
        .ok_or("Ready NVIDIA target omitted its SteamOS version.")?;
    let kernel_version = target
        .kernel_version
        .clone()
        .ok_or("Ready NVIDIA target omitted its exact kernel.")?;
    Ok(NvidiaPublishedResolution {
        schema_version: NVIDIA_RESOLVER_SCHEMA,
        status: "build_required".into(),
        reason: if source.experimental {
            "experimental_upstream_selected".into()
        } else {
            "selected_version_artifact_missing".into()
        },
        message: format!(
            "No published artifact for selected NVIDIA {} matches exact kernel {}.",
            source.version, kernel_version
        ),
        compatibility: Some(if source.experimental {
            "experimental_upstream".into()
        } else {
            "on_demand_exact_kernel".into()
        }),
        target,
        publication: None,
        artifact: None,
        build_plan: Some(NvidiaOnDemandBuildPlan {
            steamos_version,
            kernel_version,
            nvidia_version: source.version.clone(),
            baseline_release,
            support_commit: NVIDIA_SUPPORT_BUILD_COMMIT.into(),
            expected_trust: "locally-built-verified".into(),
            source_origin: source.origin.clone(),
            source_repository: source.repository.clone(),
            source_branch: source.name.clone(),
            source_commit: source.commit.clone(),
        }),
    })
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
    archive_bytes: u64,
    expanded_bytes: u64,
}

fn inspect_published_nvidia_archive(path: &Path) -> Result<PublishedArchiveInspection, String> {
    const METADATA_LIMIT: u64 = 1024 * 1024;
    let archive_bytes = fs::symlink_metadata(path)
        .map_err(|e| format!("Could not inspect the published NVIDIA archive: {e}"))
        .and_then(|metadata| {
            if !metadata.file_type().is_file() {
                return Err("Published NVIDIA archive is not a safe regular file.".into());
            }
            if metadata.len() > NVIDIA_ARCHIVE_LIMIT {
                return Err("Published NVIDIA archive exceeds the compressed safety limit.".into());
            }
            Ok(metadata.len())
        })?;
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
        if size > NVIDIA_ARCHIVE_MEMBER_LIMIT {
            return Err(format!(
                "Published NVIDIA archive member exceeds the safety limit: {name}."
            ));
        }
        total_size = total_size
            .checked_add(size)
            .filter(|value| *value <= NVIDIA_ARCHIVE_EXPANDED_LIMIT)
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
        archive_bytes,
        expanded_bytes: total_size,
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

fn valid_nvidia_source_branch(value: &str) -> Option<&str> {
    let version = value.strip_prefix("nvidia/")?;
    numeric_version(version, 2..=3)?;
    Some(version)
}

fn valid_upstream_nvidia_tag(value: &str) -> Option<&str> {
    numeric_version(value, 2..=3)?;
    Some(value)
}

fn valid_nvidia_source_identity(
    origin: &str,
    repository: &str,
    reference: &str,
    version: &str,
) -> bool {
    match origin {
        "project" => {
            repository == NVIDIA_SOURCE_REPOSITORY
                && valid_nvidia_source_branch(reference) == Some(version)
        }
        "upstream" => {
            repository == NVIDIA_UPSTREAM_REPOSITORY
                && valid_upstream_nvidia_tag(reference) == Some(version)
        }
        _ => false,
    }
}

fn valid_maintainer_git_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with(['.', '/'])
        && !value.ends_with(['.', '/'])
        && !value.ends_with(".lock")
        && !value.contains("..")
        && !value.contains("//")
        && !value.contains("@{")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

fn valid_git_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn fetch_maintainer_branches(
    client: &reqwest::blocking::Client,
    api: &str,
    component: &str,
    repository: &str,
) -> Result<Vec<MaintainerWorkspaceSource>, String> {
    let response = client
        .get(api)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .map_err(|error| format!("Could not query {component} project branches: {error}"))?;
    let bytes = read_http_response_limited(
        response,
        RELEASES_RESPONSE_LIMIT,
        &format!("{component} project branch metadata"),
    )?;
    let branches: Vec<GithubBranch> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{component} branch metadata is invalid JSON: {error}"))?;
    let mut result = Vec::new();
    for branch in branches {
        if !valid_maintainer_git_reference(&branch.name) || !valid_git_commit(&branch.commit.sha) {
            continue;
        }
        result.push(MaintainerWorkspaceSource {
            component: component.into(),
            origin: "project".into(),
            repository: repository.into(),
            reference: branch.name.clone(),
            commit: branch.commit.sha.to_ascii_lowercase(),
            label: branch.name,
            experimental: false,
        });
    }
    if result.is_empty() {
        return Err(format!(
            "The approved {component} project repository exposed no safe branches."
        ));
    }
    result.sort_by(|left, right| left.reference.cmp(&right.reference));
    Ok(result)
}

fn fetch_maintainer_gamescope_tags(
    client: &reqwest::blocking::Client,
) -> Result<Vec<MaintainerWorkspaceSource>, String> {
    let response = client
        .get(GAMESCOPE_UPSTREAM_TAGS_API)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .map_err(|error| format!("Could not query upstream Gamescope tags: {error}"))?;
    let bytes = read_http_response_limited(
        response,
        RELEASES_RESPONSE_LIMIT,
        "upstream Gamescope tag metadata",
    )?;
    let tags: Vec<GithubBranch> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Upstream Gamescope tag metadata is invalid JSON: {error}"))?;
    let mut result = Vec::new();
    for tag in tags {
        if numeric_version(&tag.name, 2..=4).is_none() || !valid_git_commit(&tag.commit.sha) {
            continue;
        }
        result.push(MaintainerWorkspaceSource {
            component: "gamescope".into(),
            origin: "upstream".into(),
            repository: GAMESCOPE_UPSTREAM_REPOSITORY.into(),
            reference: tag.name.clone(),
            commit: tag.commit.sha.to_ascii_lowercase(),
            label: tag.name,
            experimental: true,
        });
    }
    if result.is_empty() {
        return Err("The approved Gamescope upstream exposed no numeric release tags.".into());
    }
    result.sort_by(|left, right| {
        let left_version = numeric_version(&left.reference, 2..=4).expect("validated tag");
        let right_version = numeric_version(&right.reference, 2..=4).expect("validated tag");
        right_version.cmp(&left_version)
    });
    Ok(result)
}

fn fetch_maintainer_workspace_sources(
    client: &reqwest::blocking::Client,
) -> Result<Vec<MaintainerWorkspaceSource>, String> {
    let (nvidia_project, nvidia_upstream, gamescope_project, gamescope_upstream) =
        thread::scope(|scope| {
            let nvidia_project = scope.spawn(|| fetch_nvidia_source_branches(client));
            let nvidia_upstream = scope.spawn(|| fetch_upstream_nvidia_tags(client));
            let gamescope_project = scope.spawn(|| {
                fetch_maintainer_branches(
                    client,
                    GAMESCOPE_SOURCE_BRANCHES_API,
                    "gamescope",
                    GAMESCOPE_SOURCE_REPOSITORY,
                )
            });
            let gamescope_upstream = scope.spawn(|| fetch_maintainer_gamescope_tags(client));
            Ok::<_, String>((
                nvidia_project
                    .join()
                    .map_err(|_| "NVIDIA project source query panicked.")??,
                nvidia_upstream
                    .join()
                    .map_err(|_| "NVIDIA upstream source query panicked.")??,
                gamescope_project
                    .join()
                    .map_err(|_| "Gamescope project source query panicked.")??,
                gamescope_upstream
                    .join()
                    .map_err(|_| "Gamescope upstream source query panicked.")??,
            ))
        })?;
    let mut result = nvidia_project
        .into_iter()
        .map(|source| MaintainerWorkspaceSource {
            component: "nvidia".into(),
            origin: source.origin,
            repository: source.repository,
            reference: source.name,
            commit: source.commit,
            label: source.version,
            experimental: source.experimental,
        })
        .collect::<Vec<_>>();
    result.extend(
        nvidia_upstream
            .into_iter()
            .map(|source| MaintainerWorkspaceSource {
                component: "nvidia".into(),
                origin: source.origin,
                repository: source.repository,
                reference: source.name,
                commit: source.commit,
                label: source.version,
                experimental: source.experimental,
            }),
    );
    result.extend(gamescope_project);
    result.extend(gamescope_upstream);
    Ok(result)
}

fn require_maintainer_authorization() -> Result<GithubMaintainerStatus, String> {
    let status = github_maintainer_status()?;
    if !status.authorized {
        return Err(
            "Maintainer workspace access requires a fresh verified GitHub repository permission check."
                .into(),
        );
    }
    Ok(status)
}

#[tauri::command]
async fn list_maintainer_workspace_sources() -> Result<Vec<MaintainerWorkspaceSource>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        require_maintainer_authorization()?;
        fetch_maintainer_workspace_sources(&nvidia_http_client()?)
    })
    .await
    .map_err(|error| format!("Maintainer source-list worker failed: {error}"))?
}

#[tauri::command]
async fn plan_maintainer_workspace(
    component: String,
    origin: String,
    reference: String,
    commit: String,
) -> Result<MaintainerWorkspacePlan, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let authorization = require_maintainer_authorization()?;
        let matches = fetch_maintainer_workspace_sources(&nvidia_http_client()?)?
            .into_iter()
            .filter(|source| {
                source.component == component
                    && source.origin == origin
                    && source.reference == reference
                    && source.commit == commit
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(
                "The selected maintainer source changed or is no longer an exact approved reference. Refresh and select it again."
                    .into(),
            );
        }
        let source = &matches[0];
        let maintainer = authorization
            .username
            .ok_or("GitHub maintainer identity disappeared during planning.")?;
        let permission = if source.origin == "project" {
            let gh = find_binary("gh").ok_or("GitHub CLI disappeared during planning.")?;
            let permission = github_repository_permission(&gh, &maintainer, &source.repository)?
                .ok_or_else(|| {
                    format!(
                        "Maintainer access to {} could not be verified.",
                        source.repository
                    )
                })?;
            if !github_permission_can_publish(&permission) {
                return Err(format!(
                    "The connected account has {permission} access to {}; write access is required before a project workspace can be prepared.",
                    source.repository
                ));
            }
            permission
        } else {
            "approved-upstream-read-only".into()
        };
        let identity = format!(
            "{}\0{}\0{}\0{}\0{}",
            source.component, source.origin, source.repository, source.reference, source.commit
        );
        let plan_id = format!("{:x}", Sha256::digest(identity.as_bytes()));
        Ok(MaintainerWorkspacePlan {
            schema_version: 1,
            status: "planned".into(),
            plan_id,
            component: source.component.clone(),
            origin: source.origin.clone(),
            repository: source.repository.clone(),
            reference: source.reference.clone(),
            commit: source.commit.clone(),
            architecture: "x86_64".into(),
            isolation: "disposable-maintainer-appliance".into(),
            maintainer,
            permission,
            remote_mutation_allowed: false,
            message: "Exact source identity verified. Workspace creation, credentials, and every remote mutation remain separate confirmation gates.".into(),
        })
    })
    .await
    .map_err(|error| format!("Maintainer workspace planner failed: {error}"))?
}

fn fetch_nvidia_source_branches(
    client: &reqwest::blocking::Client,
) -> Result<Vec<NvidiaSourceBranch>, String> {
    let response = client
        .get(NVIDIA_SOURCE_BRANCHES_API)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .map_err(|error| format!("Could not query NVIDIA source branches: {error}"))?;
    let bytes = read_http_response_limited(
        response,
        RELEASES_RESPONSE_LIMIT,
        "NVIDIA source branch metadata",
    )?;
    let branches: Vec<GithubBranch> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("NVIDIA source branch metadata is invalid JSON: {error}"))?;
    let mut result: Vec<_> = branches
        .into_iter()
        .filter_map(|branch| {
            let version = valid_nvidia_source_branch(&branch.name)?.to_string();
            if branch.commit.sha.len() != 40
                || !branch
                    .commit
                    .sha
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return None;
            }
            Some(NvidiaSourceBranch {
                selection: format!("project:{}", branch.name),
                name: branch.name,
                version,
                commit: branch.commit.sha.to_ascii_lowercase(),
                origin: "project".into(),
                repository: NVIDIA_SOURCE_REPOSITORY.into(),
                experimental: false,
            })
        })
        .collect();
    result.sort_by(|left, right| {
        let left_version = numeric_version(&left.version, 2..=3).expect("validated branch");
        let right_version = numeric_version(&right.version, 2..=3).expect("validated branch");
        right_version.cmp(&left_version)
    });
    if result.is_empty() {
        return Err(
            "The NVIDIA source repository exposed no valid nvidia/<version> branches.".into(),
        );
    }
    Ok(result)
}

fn fetch_upstream_nvidia_tags(
    client: &reqwest::blocking::Client,
) -> Result<Vec<NvidiaSourceBranch>, String> {
    let response = client
        .get(NVIDIA_UPSTREAM_TAGS_API)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .map_err(|error| format!("Could not query upstream NVIDIA tags: {error}"))?;
    let bytes = read_http_response_limited(
        response,
        RELEASES_RESPONSE_LIMIT,
        "upstream NVIDIA tag metadata",
    )?;
    let tags: Vec<GithubBranch> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Upstream NVIDIA tag metadata is invalid JSON: {error}"))?;
    let mut result: Vec<_> = tags
        .into_iter()
        .filter_map(|tag| {
            let version = valid_upstream_nvidia_tag(&tag.name)?.to_string();
            if tag.commit.sha.len() != 40
                || !tag.commit.sha.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return None;
            }
            Some(NvidiaSourceBranch {
                selection: format!("upstream:{}", tag.name),
                name: tag.name,
                version,
                commit: tag.commit.sha.to_ascii_lowercase(),
                origin: "upstream".into(),
                repository: NVIDIA_UPSTREAM_REPOSITORY.into(),
                experimental: true,
            })
        })
        .collect();
    result.sort_by(|left, right| {
        let left_version = numeric_version(&left.version, 2..=3).expect("validated tag");
        let right_version = numeric_version(&right.version, 2..=3).expect("validated tag");
        right_version.cmp(&left_version)
    });
    if result.is_empty() {
        return Err("NVIDIA exposed no valid numeric upstream release tags.".into());
    }
    Ok(result)
}

#[tauri::command]
async fn list_nvidia_source_branches(
    app: tauri::AppHandle,
) -> Result<Vec<NvidiaSourceBranch>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let client = nvidia_http_client()?;
        let mut sources = fetch_nvidia_source_branches(&client)?;
        if load_builder_settings(&app)?.include_upstream_nvidia_releases {
            sources.extend(fetch_upstream_nvidia_tags(&client)?);
        }
        Ok(sources)
    })
    .await
    .map_err(|error| format!("NVIDIA source-list worker failed: {error}"))?
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
) -> Result<(String, PublishedArchiveInspection), String> {
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
    Ok((provenance.trust, inspection))
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
            build_plan: None,
        });
    }
    let Some((identity, release, compatibility)) =
        select_published_nvidia_release(&target, releases)?
    else {
        let Some(baseline) = select_nvidia_build_baseline(&target, releases)? else {
            return Ok(NvidiaPublishedResolution {
                schema_version: NVIDIA_RESOLVER_SCHEMA,
                status: "no_compatible_artifact".into(),
                reason: "no_compatible_release".into(),
                message: "No same-series NVIDIA publication is available to select a supported driver version for an exact-kernel build.".into(),
                compatibility: None,
                target,
                publication: None,
                artifact: None,
                build_plan: None,
            });
        };
        let steamos_version = target
            .steamos_version
            .clone()
            .ok_or("Ready NVIDIA target omitted its SteamOS version.")?;
        let kernel_version = target
            .kernel_version
            .clone()
            .ok_or("Ready NVIDIA target omitted its kernel version.")?;
        let nvidia_version = baseline.nvidia_version.clone();
        let baseline_release = baseline.tag.clone();
        return Ok(NvidiaPublishedResolution {
            schema_version: NVIDIA_RESOLVER_SCHEMA,
            status: "build_required".into(),
            reason: "exact_kernel_artifact_missing".into(),
            message: format!(
                "No published artifact matches exact kernel {kernel_version}. NVIDIA {nvidia_version} can be built locally for this exact target using the verified same-series baseline {baseline_release}."
            ),
            compatibility: Some("on_demand_exact_kernel".into()),
            target,
            publication: None,
            artifact: None,
            build_plan: Some(NvidiaOnDemandBuildPlan {
                steamos_version,
                kernel_version,
                nvidia_version: nvidia_version.clone(),
                baseline_release,
                support_commit: NVIDIA_SUPPORT_BUILD_COMMIT.into(),
                expected_trust: "locally-built-verified".into(),
                source_origin: "project".into(),
                source_repository: NVIDIA_SOURCE_REPOSITORY.into(),
                source_branch: format!("nvidia/{nvidia_version}"),
                source_commit: String::new(),
            }),
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
            build_plan: None,
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
    let (trust, inspection) = validate_published_nvidia_artifact(
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
            build_info_path: None,
            provenance_path: provenance_path.to_string_lossy().into_owned(),
            archive_sha256,
            archive_bytes: inspection.archive_bytes,
            expanded_bytes: inspection.expanded_bytes,
            trust,
        }),
        build_plan: None,
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

fn arch_index_hrefs(index: &str) -> HashSet<String> {
    index
        .split("href=\"")
        .skip(1)
        .filter_map(|rest| rest.split_once('"').map(|(href, _)| href))
        .filter_map(|href| {
            percent_encoding::percent_decode_str(href)
                .decode_utf8()
                .ok()
                .map(|decoded| decoded.into_owned())
        })
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
        candidates.push((release_key, release.to_string(), href.to_string()));
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

fn query_arch_userspace_package(
    client: &reqwest::blocking::Client,
    package: &str,
    nvidia_version: &str,
) -> Result<(String, String), String> {
    let directory = arch_package_directory(package)?;
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
    select_arch_userspace_package(index, package, nvidia_version)
}

fn arch_dependency_name(specification: &str) -> Result<&str, String> {
    let name = specification
        .split(['<', '>', '='])
        .next()
        .unwrap_or_default();
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@._+-".contains(&byte))
    {
        return Err(format!(
            "Installer requested an unsupported Arch dependency identity: {specification}"
        ));
    }
    Ok(name)
}

#[cfg(test)]
fn natural_arch_version_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let (mut left_at, mut right_at) = (0, 0);
    while left_at < left.len() && right_at < right.len() {
        if left[left_at].is_ascii_digit() && right[right_at].is_ascii_digit() {
            let left_end = (left_at..left.len())
                .find(|index| !left[*index].is_ascii_digit())
                .unwrap_or(left.len());
            let right_end = (right_at..right.len())
                .find(|index| !right[*index].is_ascii_digit())
                .unwrap_or(right.len());
            let left_number = &left[left_at..left_end];
            let right_number = &right[right_at..right_end];
            let left_trimmed = left_number
                .iter()
                .position(|byte| *byte != b'0')
                .map(|index| &left_number[index..])
                .unwrap_or(&left_number[left_number.len().saturating_sub(1)..]);
            let right_trimmed = right_number
                .iter()
                .position(|byte| *byte != b'0')
                .map(|index| &right_number[index..])
                .unwrap_or(&right_number[right_number.len().saturating_sub(1)..]);
            let compared = left_trimmed
                .len()
                .cmp(&right_trimmed.len())
                .then_with(|| left_trimmed.cmp(right_trimmed))
                .then_with(|| left_number.len().cmp(&right_number.len()).reverse());
            if compared != std::cmp::Ordering::Equal {
                return compared;
            }
            left_at = left_end;
            right_at = right_end;
            continue;
        }
        let compared = left[left_at].cmp(&right[right_at]);
        if compared != std::cmp::Ordering::Equal {
            return compared;
        }
        left_at += 1;
        right_at += 1;
    }
    left.len().cmp(&right.len())
}

#[cfg(test)]
fn select_arch_dependency_package(index: &str, package: &str) -> Result<(String, String), String> {
    arch_dependency_name(package)?;
    let hrefs = arch_index_hrefs(index);
    let prefix = format!("{package}-");
    let suffixes = ["-x86_64.pkg.tar.zst", "-any.pkg.tar.zst"];
    let mut candidates = Vec::new();
    for href in &hrefs {
        let Some(without_prefix) = href.strip_prefix(&prefix) else {
            continue;
        };
        let Some((full_version, architecture)) =
            suffixes.iter().enumerate().find_map(|(rank, suffix)| {
                without_prefix
                    .strip_suffix(suffix)
                    .map(|version| (version, rank))
            })
        else {
            continue;
        };
        if href.len() > 255
            || Path::new(href).file_name().and_then(|name| name.to_str()) != Some(href)
            || full_version.is_empty()
            || !full_version.contains('-')
            || !full_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"@._+~:-".contains(&byte))
            || !hrefs.contains(format!("{href}.sig").as_str())
        {
            continue;
        }
        candidates.push((full_version.to_string(), architecture, href.to_string()));
    }
    candidates.sort_by(|left, right| {
        natural_arch_version_cmp(&left.0, &right.0)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    let Some((full_version, _, filename)) = candidates.pop() else {
        return Err(format!(
            "The Arch Linux Archive has no signed x86_64/any package for dependency {package}."
        ));
    };
    Ok((filename, full_version))
}

fn arch_dependency_directory(package: &str) -> Result<String, String> {
    let package = arch_dependency_name(package)?;
    let initial = package
        .chars()
        .next()
        .ok_or("Arch dependency name is empty.")?
        .to_ascii_lowercase();
    if !initial.is_ascii_alphanumeric() {
        return Err("Arch dependency has an unsupported archive directory.".into());
    }
    Ok(format!(
        "https://archive.archlinux.org/packages/{initial}/{package}"
    ))
}

#[cfg(test)]
fn query_arch_dependency_package(
    client: &reqwest::blocking::Client,
    specification: &str,
) -> Result<(String, String, String, String), String> {
    let package = arch_dependency_name(specification)?;
    let directory = arch_dependency_directory(package)?;
    let response = client
        .get(format!("{directory}/"))
        .header("Accept", "text/html")
        .send()
        .map_err(|error| {
            format!("Could not query the Arch Linux Archive for {package}: {error}")
        })?;
    let bytes = read_http_response_limited(
        response,
        ARCH_ARCHIVE_INDEX_LIMIT,
        &format!("{package} archive index"),
    )?;
    let index = std::str::from_utf8(&bytes)
        .map_err(|error| format!("{package} archive index is not UTF-8: {error}"))?;
    let (filename, full_version) = select_arch_dependency_package(index, package)?;
    Ok((package.into(), directory, filename, full_version))
}

#[cfg(test)]
fn stage_arch_dependency_package(
    staging_dir: &Path,
    specification: &str,
    client: &reqwest::blocking::Client,
    cancel: &AtomicBool,
    progress: &impl Fn(&str, u64, u64),
) -> Result<NvidiaUserspacePackage, String> {
    progress("querying-arch-dependency-index", 0, 0);
    let (name, directory, filename, full_version) =
        query_arch_dependency_package(client, specification)?;
    let signature_filename = format!("{filename}.sig");
    let package_path = staging_dir.join(&filename);
    let signature_path = staging_dir.join(&signature_filename);
    let package_sha256 = download_arch_userspace_asset(
        client,
        &format!("{directory}/{filename}"),
        &package_path,
        NVIDIA_DEPENDENCY_ARCHIVE_LIMIT,
        cancel,
        "downloading-userspace-dependency",
        progress,
    )?;
    if let Err(error) = download_arch_userspace_asset(
        client,
        &format!("{directory}/{signature_filename}"),
        &signature_path,
        ARCH_PACKAGE_SIGNATURE_LIMIT,
        cancel,
        "downloading-userspace-dependency-signature",
        progress,
    ) {
        let _ = fs::remove_file(&package_path);
        let _ = fs::remove_file(&signature_path);
        return Err(error);
    }
    Ok(NvidiaUserspacePackage {
        name,
        role: "dependency".into(),
        filename,
        full_version,
        package_path: package_path.to_string_lossy().into_owned(),
        signature_path: signature_path.to_string_lossy().into_owned(),
        package_sha256,
    })
}

fn preflight_nvidia_userspace(
    client: &reqwest::blocking::Client,
    nvidia_version: &str,
) -> Result<Vec<String>, String> {
    ["nvidia-utils", "lib32-nvidia-utils"]
        .into_iter()
        .map(|package| {
            query_arch_userspace_package(client, package, nvidia_version)
                .map(|(filename, _)| filename)
                .map_err(|error| {
                    format!(
                        "NVIDIA {nvidia_version} cannot be selected because matching signed {package} input is unavailable: {error}"
                    )
                })
        })
        .collect()
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
        progress("querying-arch-package-index", packages.len() as u64, 2);
        let directory = arch_package_directory(package)?;
        let (filename, full_version) =
            query_arch_userspace_package(client, package, nvidia_version)?;
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
            role: "nvidia-userspace".into(),
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

fn valid_prepared_userspace_packages(packages: &[NvidiaUserspacePackage]) -> bool {
    if !(2..=2 + NVIDIA_DEPENDENCY_LIMIT).contains(&packages.len()) {
        return false;
    }
    let mut names = HashSet::new();
    for package in packages {
        if !names.insert(package.name.as_str()) {
            return false;
        }
        match package.name.as_str() {
            "nvidia-utils" | "lib32-nvidia-utils" => {
                if package.role != "nvidia-userspace" {
                    return false;
                }
            }
            _ if package.role == "dependency" => {}
            _ => return false,
        }
    }
    names.contains("nvidia-utils") && names.contains("lib32-nvidia-utils")
}

fn exact_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn load_reviewed_userspace_lock(
    installer_root: &Path,
    steamos_version: &str,
    nvidia_version: &str,
) -> Result<ReviewedUserspaceLock, String> {
    let lock_path = installer_root.join(NVIDIA_USERSPACE_LOCK_PATH);
    let keyring_path = installer_root.join(NVIDIA_USERSPACE_KEYRING_PATH);
    for (path, description) in [
        (&lock_path, "reviewed NVIDIA userspace lock"),
        (&keyring_path, "reviewed NVIDIA userspace keyring"),
    ] {
        if !fs::symlink_metadata(path)
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false)
        {
            return Err(format!("Pinned {description} is not a safe regular file."));
        }
    }
    if sha256_file(&keyring_path)? != NVIDIA_USERSPACE_KEYRING_SHA256 {
        return Err("Pinned NVIDIA userspace keyring no longer matches its reviewed hash.".into());
    }
    let lock: ReviewedUserspaceLock = serde_json::from_reader(
        File::open(&lock_path)
            .map_err(|error| format!("Could not read reviewed NVIDIA userspace lock: {error}"))?,
    )
    .map_err(|error| format!("Reviewed NVIDIA userspace lock is invalid JSON: {error}"))?;
    if lock.schema_version != 1
        || lock.status != "reviewed"
        || !lock.missing_review.is_empty()
        || lock.target.steamos_version != steamos_version
        || lock.target.nvidia_version != nvidia_version
        || lock.target.architecture != "x86_64"
        || lock.keyring.filename != NVIDIA_USERSPACE_KEYRING_NAME
        || lock.keyring.sha256 != NVIDIA_USERSPACE_KEYRING_SHA256
        || !(2..=2 + NVIDIA_DEPENDENCY_LIMIT).contains(&lock.packages.len())
    {
        return Err(format!(
            "No complete reviewed userspace lock is pinned for SteamOS {steamos_version} and NVIDIA {nvidia_version}."
        ));
    }
    let mut names = HashSet::new();
    for package in &lock.packages {
        let expected_filename = format!(
            "{}-{}-{}.pkg.tar.zst",
            package.name, package.version, package.architecture
        );
        if arch_dependency_name(&package.name)? != package.name
            || !matches!(package.architecture.as_str(), "x86_64" | "any")
            || package.filename != expected_filename
            || package.signature_filename != format!("{}.sig", package.filename)
            || !exact_lower_hex(&package.package_sha256, 64)
            || !exact_lower_hex(&package.signature_sha256, 64)
            || !package
                .signer_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || package.signer_fingerprint.len() != 40
            || package.installed_size == 0
            || package.dependencies.len() > 64
            || package.provides.len() > 64
            || package
                .dependencies
                .iter()
                .chain(&package.provides)
                .any(|relation| relation.is_empty() || relation.len() > 256)
            || !names.insert(package.name.as_str())
        {
            return Err("Reviewed NVIDIA userspace lock contains an unsafe package record.".into());
        }
    }
    if !names.contains("nvidia-utils") || !names.contains("lib32-nvidia-utils") {
        return Err("Reviewed NVIDIA userspace lock omits a required NVIDIA seed package.".into());
    }
    Ok(lock)
}

fn validate_locked_userspace_package(
    staged: &NvidiaUserspacePackage,
    locked: &ReviewedUserspacePackage,
) -> Result<(), String> {
    let expected_role = if matches!(locked.name.as_str(), "nvidia-utils" | "lib32-nvidia-utils") {
        "nvidia-userspace"
    } else {
        "dependency"
    };
    let package_path = Path::new(&staged.package_path);
    let signature_path = Path::new(&staged.signature_path);
    if staged.name != locked.name
        || staged.role != expected_role
        || staged.filename != locked.filename
        || staged.full_version != locked.version
        || package_path.file_name().and_then(|name| name.to_str()) != Some(locked.filename.as_str())
        || signature_path.file_name().and_then(|name| name.to_str())
            != Some(locked.signature_filename.as_str())
        || !fs::symlink_metadata(package_path)
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false)
        || !fs::symlink_metadata(signature_path)
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false)
        || sha256_file(package_path)? != locked.package_sha256
        || sha256_file(signature_path)? != locked.signature_sha256
    {
        return Err(format!(
            "Staged {} does not exactly match the reviewed userspace lock.",
            locked.name
        ));
    }
    Ok(())
}

fn stage_reviewed_userspace_closure(
    installer_root: &Path,
    steamos_version: &str,
    nvidia_version: &str,
    staged: &[NvidiaUserspacePackage],
    client: &reqwest::blocking::Client,
    cancel: &AtomicBool,
    progress: &impl Fn(&str, u64, u64),
) -> Result<Vec<NvidiaUserspacePackage>, String> {
    let lock = load_reviewed_userspace_lock(installer_root, steamos_version, nvidia_version)?;
    let staging_dir = staged
        .first()
        .and_then(|package| Path::new(&package.package_path).parent())
        .ok_or("NVIDIA userspace staging directory is unavailable.")?;
    let staged_by_name: HashMap<&str, &NvidiaUserspacePackage> = staged
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect();
    if staged_by_name.len() != staged.len() {
        return Err("Staged NVIDIA userspace inputs contain duplicate package names.".into());
    }
    if staged_by_name
        .keys()
        .any(|name| !lock.packages.iter().any(|package| package.name == *name))
    {
        return Err(
            "Staged NVIDIA userspace inputs contain a package outside the reviewed lock.".into(),
        );
    }

    let mut closure = Vec::with_capacity(lock.packages.len());
    for (index, locked) in lock.packages.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err("Reviewed NVIDIA userspace closure staging cancelled.".into());
        }
        progress(
            "staging-reviewed-userspace-closure",
            index as u64,
            lock.packages.len() as u64,
        );
        if let Some(existing) = staged_by_name.get(locked.name.as_str()) {
            validate_locked_userspace_package(existing, locked)?;
            closure.push((*existing).clone());
            continue;
        }
        if matches!(locked.name.as_str(), "nvidia-utils" | "lib32-nvidia-utils") {
            return Err(format!(
                "Reviewed userspace closure is missing {}.",
                locked.name
            ));
        }
        let directory = arch_dependency_directory(&locked.name)?;
        let package_path = staging_dir.join(&locked.filename);
        let signature_path = staging_dir.join(&locked.signature_filename);
        for path in [&package_path, &signature_path] {
            if path.exists() {
                fs::remove_file(path).map_err(|error| {
                    format!("Could not replace an incomplete locked dependency: {error}")
                })?;
            }
        }
        let package_sha256 = download_arch_userspace_asset(
            client,
            &format!("{directory}/{}", locked.filename),
            &package_path,
            NVIDIA_DEPENDENCY_ARCHIVE_LIMIT,
            cancel,
            "downloading-locked-userspace-dependency",
            progress,
        )?;
        let signature_sha256 = download_arch_userspace_asset(
            client,
            &format!("{directory}/{}", locked.signature_filename),
            &signature_path,
            ARCH_PACKAGE_SIGNATURE_LIMIT,
            cancel,
            "downloading-locked-userspace-signature",
            progress,
        )?;
        if package_sha256 != locked.package_sha256 || signature_sha256 != locked.signature_sha256 {
            let _ = fs::remove_file(&package_path);
            let _ = fs::remove_file(&signature_path);
            return Err(format!(
                "Downloaded {} does not match the reviewed userspace lock.",
                locked.name
            ));
        }
        closure.push(NvidiaUserspacePackage {
            name: locked.name.clone(),
            role: "dependency".into(),
            filename: locked.filename.clone(),
            full_version: locked.version.clone(),
            package_path: package_path.to_string_lossy().into_owned(),
            signature_path: signature_path.to_string_lossy().into_owned(),
            package_sha256,
        });
    }
    progress(
        "staging-reviewed-userspace-closure",
        lock.packages.len() as u64,
        lock.packages.len() as u64,
    );
    Ok(closure)
}

fn validate_pinned_support_files(files: &[PinnedInstallerFile]) -> Result<u64, String> {
    if NVIDIA_SUPPORT_COMMIT.len() != 40
        || !NVIDIA_SUPPORT_COMMIT
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("Pinned NVIDIA support commit is invalid.".into());
    }
    let mut paths = HashSet::new();
    let mut total = 0_u64;
    for file in files {
        let path = Path::new(file.path);
        if file.path.is_empty()
            || !file.path.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
            })
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || !paths.insert(file.path)
            || file.sha256.len() != 64
            || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || file.bytes == 0
        {
            return Err("Pinned NVIDIA support-file contract is invalid.".into());
        }
        total = total
            .checked_add(file.bytes)
            .ok_or("Pinned NVIDIA support-file size overflowed.")?;
    }
    Ok(total)
}

fn apply_pinned_file_permissions(path: &Path, executable: bool) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mode = if executable { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("Could not set pinned support-file permissions: {error}"))?;
    }
    #[cfg(not(unix))]
    let _ = (path, executable);
    Ok(())
}

fn pinned_installer_guest_permissions() -> Result<String, String> {
    validate_pinned_installer_contract()?;
    let mut command = String::new();
    for executable in [false, true] {
        let mode = if executable { "0755" } else { "0644" };
        let paths = PINNED_INSTALLER_FILES
            .iter()
            .filter(|file| file.executable == executable)
            .map(|file| format!("\"$WORK/support/{}\"", file.path))
            .collect::<Vec<_>>();
        if !paths.is_empty() {
            command.push_str(&format!("chmod {mode} {};\n", paths.join(" ")));
        }
    }
    Ok(command)
}

fn validate_pinned_installer_contract() -> Result<u64, String> {
    validate_pinned_support_files(&PINNED_INSTALLER_FILES)
}

fn validate_pinned_publisher_contract() -> Result<u64, String> {
    validate_pinned_support_files(&PINNED_PUBLISHER_FILES)
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
            "Refusing to overwrite a staged NVIDIA support file: {}",
            destination.display()
        ));
    }
    let parent = destination
        .parent()
        .ok_or("Pinned NVIDIA support-file path has no parent.")?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("Could not create NVIDIA support-file directory: {e}"))?;
    let partial = destination.with_file_name(format!(
        ".{}.partial",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("Pinned NVIDIA support filename is invalid.")?
    ));
    let mut partial_guard = PartialOutputGuard {
        path: partial.clone(),
        armed: true,
    };
    let url = format!(
        "https://raw.githubusercontent.com/{NVIDIA_SUPPORT_REPOSITORY}/{NVIDIA_SUPPORT_COMMIT}/{}",
        file.path
    );
    let mut response = client
        .get(url)
        .header("Accept", "application/octet-stream")
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| format!("Could not download pinned support file {}: {e}", file.path))?;
    if response
        .content_length()
        .is_some_and(|length| length != file.bytes)
    {
        return Err(format!(
            "Pinned support file {} has an unexpected download size.",
            file.path
        ));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|e| format!("Could not stage pinned support file {}: {e}", file.path))?;
    let mut hasher = Sha256::new();
    let mut downloaded = 0_u64;
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("NVIDIA support-file download cancelled.".into());
        }
        let count = response
            .read(&mut buffer)
            .map_err(|e| format!("Could not read pinned support file {}: {e}", file.path))?;
        if count == 0 {
            break;
        }
        downloaded = downloaded
            .checked_add(count as u64)
            .filter(|value| *value <= file.bytes)
            .ok_or_else(|| format!("Pinned support file {} is too large.", file.path))?;
        output
            .write_all(&buffer[..count])
            .map_err(|e| format!("Could not write pinned support file {}: {e}", file.path))?;
        hasher.update(&buffer[..count]);
        progress(
            "downloading-nvidia-installer",
            completed_before + downloaded,
            total_bytes,
        );
    }
    if downloaded != file.bytes {
        return Err(format!(
            "Pinned support file {} downloaded {downloaded} bytes; expected {}.",
            file.path, file.bytes
        ));
    }
    let digest = format!("{:x}", hasher.finalize());
    if digest != file.sha256 {
        return Err(format!(
            "Pinned support file {} failed SHA-256 verification.",
            file.path
        ));
    }
    output
        .flush()
        .map_err(|e| format!("Could not finish pinned support file {}: {e}", file.path))?;
    drop(output);
    apply_pinned_file_permissions(&partial, file.executable)?;
    fs::rename(&partial, destination)
        .map_err(|e| format!("Could not finalize pinned support file {}: {e}", file.path))?;
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

fn validate_staged_pinned_files(root: &Path, files: &[PinnedInstallerFile]) -> Result<(), String> {
    for pinned in files {
        let path = root.join(pinned.path);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("Could not inspect pinned file {}: {e}", pinned.path))?;
        if !metadata.file_type().is_file()
            || metadata.len() != pinned.bytes
            || sha256_file(&path)? != pinned.sha256
        {
            return Err(format!(
                "Staged support file no longer matches its pin: {}.",
                pinned.path
            ));
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o7777 != if pinned.executable { 0o755 } else { 0o644 } {
            return Err(format!(
                "Staged support file has unexpected permissions: {}.",
                pinned.path
            ));
        }
    }
    Ok(())
}

fn prepare_pinned_nvidia_publisher(runtime_dir: &Path) -> Result<PathBuf, String> {
    let total_bytes = validate_pinned_publisher_contract()?;
    let root = runtime_dir.join(format!("nvidia-publisher-{NVIDIA_SUPPORT_COMMIT}"));
    if root.is_dir() {
        validate_staged_pinned_files(&root, &PINNED_PUBLISHER_FILES)?;
        return Ok(root);
    }
    fs::create_dir(&root)
        .map_err(|e| format!("Could not create pinned NVIDIA publisher staging: {e}"))?;
    let mut root_guard = StagingDirectoryGuard {
        path: root.clone(),
        armed: true,
    };
    let client = nvidia_http_client()?;
    let cancel = AtomicBool::new(false);
    let mut completed = 0_u64;
    for file in &PINNED_PUBLISHER_FILES {
        download_pinned_installer_file(
            &client,
            file,
            &root.join(file.path),
            completed,
            total_bytes,
            &cancel,
            &|_, _, _| {},
        )?;
        completed += file.bytes;
    }
    validate_staged_pinned_files(&root, &PINNED_PUBLISHER_FILES)?;
    root_guard.armed = false;
    Ok(root)
}

fn validate_support_publication_plan(
    plan: &SupportPublicationPlan,
    identity: &PublishedReleaseIdentity,
    archive_sha256: &str,
    expected_assets: &[String; 4],
) -> Result<(), String> {
    if plan.schema_version != 1
        || plan.status != "ready"
        || plan.repository != NVIDIA_SUPPORT_REPOSITORY
        || plan.tag != identity.tag
        || plan.target_commit != NVIDIA_SUPPORT_BUILD_COMMIT
        || plan.trust != "locally-built-verified"
        || plan.archive_sha256 != archive_sha256
        || plan.assets.as_slice() != expected_assets
    {
        return Err(
            "Pinned support publisher returned a plan that does not match the verified artifact."
                .into(),
        );
    }
    Ok(())
}

fn support_publisher_command(
    publisher: &Path,
    archive: &Path,
    checksum: &Path,
    build_info: &Path,
    provenance: &Path,
) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(publisher)
        .arg("--archive")
        .arg(archive)
        .arg("--checksum")
        .arg(checksum)
        .arg("--build-info")
        .arg(build_info)
        .arg("--provenance")
        .arg(provenance);
    command
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
    validate_staged_pinned_files(&state.root, &PINNED_INSTALLER_FILES)
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
    if !matches!(
        document.source.repository.as_str(),
        NVIDIA_SOURCE_REPOSITORY | NVIDIA_UPSTREAM_REPOSITORY
    ) || document.source.branch.is_empty()
        || document.source.commit.len() != 40
        || !document
            .source
            .commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || document.source.dirty != "0"
    {
        return Err("NVIDIA provenance contains an invalid or dirty source identity.".into());
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

enum NvidiaSupportSource<'a> {
    Local(&'a Path),
    PinnedGithub,
}

struct NvidiaSourcePin<'a> {
    origin: &'a str,
    repository: &'a str,
    reference: &'a str,
    commit: &'a str,
}

#[cfg(test)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvidiaSourceContractPreflight {
    schema_version: u32,
    status: String,
    architecture: String,
    support_repository: String,
    support_commit: String,
    source_repository: String,
    source_reference: String,
    source_commit: String,
    source_repository_url: String,
    plan: serde_json::Value,
}

#[cfg(test)]
fn preflight_nvidia_source_contract(
    session: &impl GuestConnection,
    pin: &NvidiaSourcePin<'_>,
    spec: &NvidiaTargetBuildSpec,
) -> Result<NvidiaSourceContractPreflight, String> {
    validate_nvidia_target_build_spec(spec)?;
    if !valid_nvidia_source_identity(
        pin.origin,
        pin.repository,
        pin.reference,
        &spec.nvidia_version,
    ) || pin.commit.len() != 40
        || !pin.commit.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(
            "Pinned NVIDIA source origin/reference/commit does not match the requested version."
                .into(),
        );
    }

    let command = format!(
        r#"set -eu
rm -rf /tmp/steamos-nvidia-contract-support /tmp/steamos-nvidia-contract-source
sudo dnf install -y git-core
git clone --quiet https://github.com/{NVIDIA_SUPPORT_REPOSITORY}.git /tmp/steamos-nvidia-contract-support
git -C /tmp/steamos-nvidia-contract-support checkout --quiet --detach {NVIDIA_SUPPORT_BUILD_COMMIT}
test "$(git -C /tmp/steamos-nvidia-contract-support rev-parse HEAD)" = "{NVIDIA_SUPPORT_BUILD_COMMIT}"
test -z "$(git -C /tmp/steamos-nvidia-contract-support status --porcelain)"
mkdir -p /tmp/steamos-nvidia-contract-source
git -C /tmp/steamos-nvidia-contract-source init --quiet
git -C /tmp/steamos-nvidia-contract-source remote add origin https://github.com/{source_repository}.git
git -C /tmp/steamos-nvidia-contract-source fetch --quiet --depth 1 origin refs/tags/{source_reference}
test "$(git -C /tmp/steamos-nvidia-contract-source rev-parse 'FETCH_HEAD^{{commit}}')" = "{source_commit}"
git -C /tmp/steamos-nvidia-contract-source checkout --quiet --detach {source_commit}
test "$(git -C /tmp/steamos-nvidia-contract-source rev-parse HEAD)" = "{source_commit}"
test -z "$(git -C /tmp/steamos-nvidia-contract-source status --porcelain)"
test -d /tmp/steamos-nvidia-contract-source/kernel-open
source_repository_url="$(SOURCE_REPO={source_repository} bash -c 'source /tmp/steamos-nvidia-contract-support/lib/common.sh; printf %s "$SOURCE_REPO_URL"')"
test "$source_repository_url" = "https://github.com/{source_repository}.git"
plan="$(bash /tmp/steamos-nvidia-contract-support/bootstrap/build_for_target.sh --resolve-only --steamos {steamos_version} --kernel {kernel_version} --nvidia {nvidia_version} --architecture x86_64)"
python3 - "$plan" "$source_repository_url" <<'PY'
import json
import platform
import sys

plan = json.loads(sys.argv[1])
expected = {{
    "steamosVersion": "{steamos_version}",
    "kernelVersion": "{kernel_version}",
    "nvidiaVersion": "{nvidia_version}",
    "architecture": "x86_64",
}}
assert plan.get("schemaVersion") == 1
assert plan.get("status") == "ready"
assert all(plan["target"].get(key) == value for key, value in expected.items())
print(json.dumps({{
    "schemaVersion": 1,
    "status": "ready",
    "architecture": platform.machine(),
    "supportRepository": "{support_repository}",
    "supportCommit": "{support_commit}",
    "sourceRepository": "{source_repository}",
    "sourceReference": "{source_reference}",
    "sourceCommit": "{source_commit}",
    "sourceRepositoryUrl": sys.argv[2],
    "plan": plan,
}}, sort_keys=True, separators=(",", ":")))
PY"#,
        support_repository = NVIDIA_SUPPORT_REPOSITORY,
        support_commit = NVIDIA_SUPPORT_BUILD_COMMIT,
        source_repository = pin.repository,
        source_reference = pin.reference,
        source_commit = pin.commit.to_ascii_lowercase(),
        steamos_version = spec.steamos_version,
        kernel_version = spec.kernel_version,
        nvidia_version = spec.nvidia_version,
    );
    let output = run_guest_command(session, &command)?;
    let structured_output = output
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .ok_or("NVIDIA source-contract preflight did not return structured JSON.")?;
    let report: NvidiaSourceContractPreflight = serde_json::from_str(structured_output)
        .map_err(|e| format!("NVIDIA source-contract preflight returned invalid JSON: {e}"))?;
    let expected_commit = pin.commit.to_ascii_lowercase();
    if report.schema_version != 1
        || report.status != "ready"
        || report.architecture != "x86_64"
        || report.support_repository != NVIDIA_SUPPORT_REPOSITORY
        || report.support_commit != NVIDIA_SUPPORT_BUILD_COMMIT
        || report.source_repository != pin.repository
        || report.source_reference != pin.reference
        || report.source_commit.to_ascii_lowercase() != expected_commit
        || report.source_repository_url != format!("https://github.com/{}.git", pin.repository)
        || report.plan.get("status").and_then(|value| value.as_str()) != Some("ready")
    {
        return Err(
            "The x86 NVIDIA source/build-plan contract did not match its pinned inputs.".into(),
        );
    }
    Ok(report)
}

fn build_nvidia_for_target_from_source(
    session: &impl GuestConnection,
    support_source: NvidiaSupportSource<'_>,
    source_pin: Option<NvidiaSourcePin<'_>>,
    output_dir: &Path,
    spec: &NvidiaTargetBuildSpec,
    cancel: Option<&AtomicBool>,
) -> Result<NvidiaDevelopmentArtifact, String> {
    validate_nvidia_target_build_spec(spec)?;
    let expected_source = source_pin
        .as_ref()
        .map(|pin| (pin.repository.to_string(), pin.commit.to_ascii_lowercase()));
    if let Some(pin) = source_pin.as_ref() {
        if !valid_nvidia_source_identity(
            pin.origin,
            pin.repository,
            pin.reference,
            &spec.nvidia_version,
        ) || pin.commit.len() != 40
            || !pin.commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(
                "Pinned NVIDIA source origin/reference/commit does not match the requested version."
                    .into(),
            );
        }
    }
    let (local_support_repository, approved_signer) = match support_source {
        NvidiaSupportSource::Local(repository) => {
            let repository = fs::canonicalize(repository)
                .map_err(|e| format!("Could not resolve the NVIDIA support repository: {e}"))?;
            for required in [
                "bootstrap/build_for_target.sh",
                "bootstrap/prepare_valve_keyring.py",
                "lib/common.sh",
                "trust/valve-package-signers.json",
            ] {
                if !repository.join(required).is_file() {
                    return Err(format!(
                        "NVIDIA support repository is missing required file {required}."
                    ));
                }
            }
            let trust_manifest: ValveTrustManifest = serde_json::from_reader(
                File::open(repository.join("trust/valve-package-signers.json"))
                    .map_err(|e| format!("Could not read the Valve trust manifest: {e}"))?,
            )
            .map_err(|e| format!("Valve trust manifest is invalid JSON: {e}"))?;
            let signer = trust_manifest
                .signers
                .first()
                .filter(|_| trust_manifest.schema_version == 1 && trust_manifest.signers.len() == 1)
                .map(|signer| signer.fingerprint.to_ascii_uppercase())
                .filter(|fingerprint| {
                    matches!(fingerprint.len(), 40 | 64)
                        && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                .ok_or("Valve trust manifest must contain exactly one full approved signer fingerprint.")?;
            (Some(repository), signer)
        }
        NvidiaSupportSource::PinnedGithub => (None, APPROVED_VALVE_SIGNER.to_ascii_uppercase()),
    };
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

    if let Some(support_repository) = local_support_repository.as_ref() {
        let transfer_archive = session.runtime_dir().join("support-repository.tar.gz");
        run_checked(
            Command::new("tar")
                // Prevent macOS tar from adding AppleDouble/xattr headers that GNU tar
                // reports as unknown while unpacking the checkout in Fedora.
                .env("COPYFILE_DISABLE", "1")
                .args(["--no-xattrs", "-czf"])
                .arg(&transfer_archive)
                .args(["--exclude", ".git", "--exclude", "target", "-C"])
                .arg(support_repository)
                .arg("."),
            "Could not package the NVIDIA support repository",
        )?;
        run_checked(
            scp_command(session)?
                .arg(&transfer_archive)
                .arg("builder@127.0.0.1:/tmp/steamos-nvidia-support.tar.gz"),
            "Could not copy the NVIDIA support repository into the x86 guest",
        )?;
    }
    let support_setup = if local_support_repository.is_some() {
        "mkdir -p /tmp/steamos-nvidia-support; tar -xzf /tmp/steamos-nvidia-support.tar.gz -C /tmp/steamos-nvidia-support;".to_string()
    } else {
        format!(
            "sudo dnf install -y git gcc15; git clone --quiet https://github.com/{NVIDIA_SUPPORT_REPOSITORY}.git /tmp/steamos-nvidia-support; cd /tmp/steamos-nvidia-support; git checkout --quiet --detach {NVIDIA_SUPPORT_BUILD_COMMIT}; test \"$(git rev-parse HEAD)\" = {NVIDIA_SUPPORT_BUILD_COMMIT}; test -z \"$(git status --porcelain)\";"
        )
    };
    let compiler_requirement = if local_support_repository.is_some() {
        ""
    } else {
        " --require-compiler-major-match"
    };
    let (source_setup, source_argument, source_environment) = if let Some(pin) = source_pin {
        (
            format!(
                "mkdir -p /tmp/steamos-nvidia-source; git -C /tmp/steamos-nvidia-source init --quiet; git -C /tmp/steamos-nvidia-source remote add origin https://github.com/{}.git; git -C /tmp/steamos-nvidia-source fetch --quiet --depth 1 origin {}; git -C /tmp/steamos-nvidia-source checkout --quiet --detach {}; test \"$(git -C /tmp/steamos-nvidia-source rev-parse HEAD)\" = {}; test -z \"$(git -C /tmp/steamos-nvidia-source status --porcelain)\";",
                pin.repository, pin.commit, pin.commit, pin.commit
            ),
            " --source /tmp/steamos-nvidia-source",
            format!("SOURCE_REPO={} ", pin.repository),
        )
    } else {
        (String::new(), "", String::new())
    };
    let build_command = format!(
        r#"set -eu; rm -rf /tmp/steamos-nvidia-support /tmp/steamos-nvidia-source /tmp/steamos-nvidia-artifacts; mkdir -p /tmp/steamos-nvidia-artifacts; {support_setup} {source_setup} cd /tmp/steamos-nvidia-support; sudo dnf install -y bsdtar gnupg2 python3; python3 ./bootstrap/prepare_valve_keyring.py --output /tmp/steamos-nvidia-artifacts/valve-package-signers.gpg; signer="$(python3 -c 'import json; data=json.load(open("trust/valve-package-signers.json", encoding="utf-8")); signers=data["signers"]; assert data["schemaVersion"] == 1 and len(signers) == 1; print(signers[0]["fingerprint"])')"; {source_environment}bash ./bootstrap/build_for_target.sh --steamos {} --kernel {} --nvidia {} --architecture x86_64 --install-dependencies{compiler_requirement}{source_argument} --output /tmp/steamos-nvidia-artifacts --result-json /tmp/steamos-nvidia-artifacts/build-result.json --header-keyring /tmp/steamos-nvidia-artifacts/valve-package-signers.gpg --header-signer "$signer""#,
        spec.steamos_version, spec.kernel_version, spec.nvidia_version,
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
    if expected_source
        .as_ref()
        .is_some_and(|(repository, commit)| {
            provenance.source.repository != *repository
                || provenance.source.commit.to_ascii_lowercase() != *commit
        })
    {
        return Err(
            "NVIDIA provenance does not match the exact pinned source repository and commit."
                .into(),
        );
    }
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

fn build_nvidia_for_target(
    session: &impl GuestConnection,
    support_repository: &Path,
    output_dir: &Path,
    spec: &NvidiaTargetBuildSpec,
    cancel: Option<&AtomicBool>,
) -> Result<NvidiaDevelopmentArtifact, String> {
    build_nvidia_for_target_from_source(
        session,
        NvidiaSupportSource::Local(support_repository),
        None,
        output_dir,
        spec,
        cancel,
    )
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
  WAS_SEEDING=1
  sudo btrfstune -f -S 0 "$TARGET"
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
  RESTORE_SOURCE_RO=1
  sudo btrfs property set -f -ts "$SOURCE_ROOT" ro false
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

fn host_available_bytes(path: &Path) -> Result<u64, String> {
    let output = Command::new("df")
        .args(["-P", "-k"])
        .arg(path)
        .output()
        .map_err(|error| format!("Could not measure host output space: {error}"))?;
    if !output.status.success() {
        return Err("Could not measure host output space with df.".into());
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "Host output-space report was not valid UTF-8.")?;
    let fields: Vec<_> = stdout
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .ok_or("Host output-space report was empty.")?
        .split_whitespace()
        .collect();
    if fields.len() < 6 {
        return Err("Host output-space report had an unexpected format.".into());
    }
    fields[fields.len() - 3]
        .parse::<u64>()
        .ok()
        .and_then(|blocks| blocks.checked_mul(1024))
        .ok_or_else(|| "Host output-space report contained an invalid byte count.".into())
}

fn validate_output_destination(
    input: &Path,
    output: &Path,
    required_bytes: u64,
) -> Result<(), String> {
    if !fs::symlink_metadata(input)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
    {
        return Err("The selected input is no longer a safe regular file.".into());
    }
    let parent = output
        .parent()
        .ok_or("Could not determine the output folder.")?;
    let resolved_parent = fs::canonicalize(parent)
        .map_err(|error| format!("Could not resolve the output folder: {error}"))?;
    if !fs::symlink_metadata(&resolved_parent)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
    {
        return Err("The output folder is not a safe directory.".into());
    }
    let filename = output
        .file_name()
        .ok_or("The output path has no filename.")?;
    let resolved_output = resolved_parent.join(filename);
    let resolved_input = fs::canonicalize(input)
        .map_err(|error| format!("Could not resolve the selected input: {error}"))?;
    if resolved_output == resolved_input {
        return Err("The output path resolves to the selected input image.".into());
    }
    if let Ok(metadata) = fs::symlink_metadata(&resolved_output) {
        #[cfg(unix)]
        if metadata.file_type().is_block_device() || metadata.file_type().is_char_device() {
            return Err("The output path resolves to a device node.".into());
        }
        return Err(format!(
            "The output path already exists: {}",
            resolved_output.display()
        ));
    }
    if required_bytes > 0 {
        let available = host_available_bytes(&resolved_parent)?;
        if available < required_bytes {
            return Err(format!(
                "The output folder needs at least {required_bytes} free bytes; only {available} are available."
            ));
        }
    }
    Ok(())
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
    let mut package_assertions = String::new();
    for package in &installation.packages {
        if arch_dependency_name(&package.name)? != package.name
            || package.full_version.is_empty()
            || package.full_version.len() > 256
            || !package
                .full_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"@._+~:-".contains(&byte))
        {
            return Err("Installed package manifest contains an unsafe identity.".into());
        }
        package_assertions.push_str(&format!(
            "test \"$(package_versions '{}')\" = '{}'\n",
            package.name, package.full_version
        ));
    }
    let command = format!(
        r#"set -euo pipefail
WORK=/dev/disk/by-id/virtio-steamos-user-working
ROOT=/mnt/steamos-nvidia-export-root
test -b "$WORK"
test "$(sudo blockdev --getro "$WORK")" = 1
mapfile -t ROOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "rootfs-A" && $3 == "btrfs" {{print $1}}')
mapfile -t BOOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "efi-A" && ($3 == "vfat" || $3 == "fat") {{print $1}}')
mapfile -t VAR_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "var-A" && $3 == "ext4" {{print $1}}')
test "${{#ROOT_PARTS[@]}}" -eq 1
test "${{#BOOT_PARTS[@]}}" -eq 1
test "${{#VAR_PARTS[@]}}" -eq 1
test "${{ROOT_PARTS[0]}}" != "${{BOOT_PARTS[0]}}"
test "${{ROOT_PARTS[0]}}" != "${{VAR_PARTS[0]}}"
test "${{BOOT_PARTS[0]}}" != "${{VAR_PARTS[0]}}"
sudo mkdir -p "$ROOT"
ROOT_MOUNTED=0
VAR_MOUNTED=0
EFI_MOUNTED=0
cleanup() {{
  rc=$?
  trap - EXIT INT TERM
  if (( EFI_MOUNTED )); then sudo umount "$ROOT/efi" || rc=1; fi
  if (( VAR_MOUNTED )); then sudo umount "$ROOT/var" || rc=1; fi
  if (( ROOT_MOUNTED )); then sudo umount "$ROOT" || rc=1; fi
  ! findmnt -rn -M "$ROOT/efi" >/dev/null 2>&1 || rc=1
  ! findmnt -rn -M "$ROOT/var" >/dev/null 2>&1 || rc=1
  ! findmnt -rn -M "$ROOT" >/dev/null 2>&1 || rc=1
  exit "$rc"
}}
trap cleanup EXIT INT TERM
sudo mount -o ro "${{ROOT_PARTS[0]}}" "$ROOT"
ROOT_MOUNTED=1
test -d "$ROOT/boot"
test ! -L "$ROOT/boot"
test -d "$ROOT/efi"
test ! -L "$ROOT/efi"
test -d "$ROOT/var"
test ! -L "$ROOT/var"
sudo mount -o ro "${{VAR_PARTS[0]}}" "$ROOT/var"
VAR_MOUNTED=1
sudo mount -o ro "${{BOOT_PARTS[0]}}" "$ROOT/efi"
EFI_MOUNTED=1
MODULE_ROOT="$ROOT/usr/lib/modules/{}/updates/open-gpu-kernel-modules-steamos"
for MODULE in nvidia nvidia-drm nvidia-modeset nvidia-peermem nvidia-uvm; do
  test -f "$MODULE_ROOT/$MODULE.ko.zst"
  test ! -L "$MODULE_ROOT/$MODULE.ko.zst"
  test "$(sudo modinfo -F version "$MODULE_ROOT/$MODULE.ko.zst")" = "{}"
  test "$(sudo modinfo -F vermagic "$MODULE_ROOT/$MODULE.ko.zst" | awk '{{print $1}}')" = "{}"
done
grep -qx 'blacklist nouveau' "$ROOT/etc/modprobe.d/99-open-gpu-kernel-modules-steamos.conf"
grep -qx 'options nvidia-drm modeset=1 fbdev=1' "$ROOT/etc/modprobe.d/99-open-gpu-kernel-modules-steamos.conf"
grep -qx 'MODULES=(nvidia nvidia_modeset nvidia_uvm nvidia_drm)' "$ROOT/etc/mkinitcpio.conf.d/90-open-gpu-kernel-modules-steamos.conf"
GRUB="$ROOT/efi/EFI/steamos/grub.cfg"
test -f "$GRUB"
test ! -L "$GRUB"
awk '
BEGIN {{
  required[1]="rd.driver.blacklist=nouveau"
  required[2]="modprobe.blacklist=nouveau"
  required[3]="nvidia-drm.modeset=1"
  required[4]="nvidia-drm.fbdev=1"
  for (index=1; index<=4; index++) {{
    key[index]=required[index]
    sub(/=.*/, "", key[index])
  }}
}}
/^[[:space:]]*(steamenv_boot[[:space:]]+)?(linux|linuxefi|linux16)[[:space:]]+/ {{
  entries++
  delete count
  for (field=1; field<=NF; field++) {{
    if ($field ~ /^#/) break
    token_key=$field
    sub(/=.*/, "", token_key)
    for (index=1; index<=4; index++) {{
      if (token_key == key[index]) {{
        if ($field != required[index]) invalid=1
        count[index]++
      }}
    }}
  }}
  for (index=1; index<=4; index++) if (count[index] != 1) invalid=1
}}
END {{ if (entries == 0 || invalid) exit 1 }}
' "$GRUB"
STATE="$ROOT/var/lib/open-gpu-kernel-modules-steamos-support/offline-install"
test "$(cat "$STATE/kernel-version")" = "{}"
test "$(cat "$STATE/nvidia-version")" = "{}"
test -f "$STATE/PROVENANCE.json"
test ! -L "$STATE/PROVENANCE.json"
test "$(sha256sum "$STATE/PROVENANCE.json" | awk '{{print $1}}')" = "{}"
test -f "$STATE/BUILD-INFO.txt"
test ! -L "$STATE/BUILD-INFO.txt"
find "$ROOT/usr/lib/firmware/nvidia/{}" -type f -name 'gsp*.bin' -print -quit | grep -q .
PACMAN_DATABASE="$ROOT{}"
test -d "$PACMAN_DATABASE"
test ! -L "$PACMAN_DATABASE"
test -d "$PACMAN_DATABASE/local"
test ! -L "$PACMAN_DATABASE/local"
package_versions() {{
  wanted="$1"
  find "$PACMAN_DATABASE/local" -mindepth 2 -maxdepth 2 -type f -name desc -exec \
    awk -v wanted="$wanted" '
      $0 == "%NAME%" {{ getline; name=$0 }}
      $0 == "%VERSION%" {{ getline; version=$0 }}
      END {{ if (name == wanted) print version }}
    ' {{}} \;
}}
{}
find "$ROOT/boot" -maxdepth 1 -type f -name 'initramfs*.img' -size +0c -print -quit | grep -q .
sudo umount "$ROOT/efi"
EFI_MOUNTED=0
sudo umount "$ROOT/var"
VAR_MOUNTED=0
sudo umount "$ROOT"
ROOT_MOUNTED=0
! findmnt -rn -M "$ROOT/efi" >/dev/null 2>&1
! findmnt -rn -M "$ROOT/var" >/dev/null 2>&1
! findmnt -rn -M "$ROOT" >/dev/null 2>&1
trap - EXIT INT TERM"#,
        installation.kernel_version,
        installation.nvidia_version,
        installation.kernel_version,
        installation.kernel_version,
        installation.nvidia_version,
        installation.provenance_sha256,
        installation.nvidia_version,
        installation.pacman_database_path,
        package_assertions,
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
        let required_output_bytes = session
            .input_preparation
            .image_bytes
            .checked_add(64 * 1024 * 1024)
            .ok_or("Host output-space requirement overflowed.")?;
        validate_output_destination(&session.input_image, &final_path, required_output_bytes)?;
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
        validate_output_destination(&session.input_image, &final_path, 0)?;
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
            nvidia_resolution: session.nvidia_resolution.as_ref(),
            nvidia_source_selection: session.nvidia_source_selection.as_deref(),
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
    const LOG_LIMIT: usize = 256 * 1024;
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
                && valid_prepared_userspace_packages(&userspace.packages)
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
    let lock = load_reviewed_userspace_lock(
        &installer.root,
        &steamos_version,
        &publication.nvidia_version,
    )?;
    if userspace.packages.len() != lock.packages.len() {
        return Err("The complete reviewed NVIDIA userspace closure has not been staged.".into());
    }
    let mut ordered_packages = Vec::with_capacity(lock.packages.len());
    for locked in &lock.packages {
        let staged = userspace
            .packages
            .iter()
            .find(|package| package.name == locked.name)
            .ok_or_else(|| format!("Reviewed userspace closure is missing {}.", locked.name))?;
        validate_locked_userspace_package(staged, locked)?;
        ordered_packages.push(staged.clone());
    }
    let mut inputs = NvidiaInstallInputs {
        image_runtime_dir: session.runtime_dir.clone(),
        working_image: session.working_image.clone(),
        installer_root: installer.root.clone(),
        archive: PathBuf::from(&artifact.archive_path),
        checksum: PathBuf::from(&artifact.checksum_path),
        provenance: PathBuf::from(&artifact.provenance_path),
        archive_sha256: artifact.archive_sha256.clone(),
        archive_bytes: artifact.archive_bytes,
        expanded_bytes: artifact.expanded_bytes,
        provenance_sha256: String::new(),
        trust: artifact.trust.clone(),
        steamos_version,
        kernel_version,
        nvidia_version: publication.nvidia_version.clone(),
        packages: ordered_packages,
        userspace_lock: lock,
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
    inputs.provenance_sha256 = sha256_file(&inputs.provenance)?;
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

fn validate_on_demand_build_plan(session: &ApplianceSession) -> Result<(), String> {
    let resolution = session
        .nvidia_resolution
        .as_ref()
        .filter(|resolution| resolution.status == "build_required")
        .ok_or("No exact-kernel NVIDIA on-demand build is pending.")?;
    let plan = resolution
        .build_plan
        .as_ref()
        .ok_or("NVIDIA resolver omitted the on-demand build plan.")?;
    let target = &resolution.target;
    if !target.ready
        || target.steamos_version.as_deref() != Some(plan.steamos_version.as_str())
        || target.kernel_version.as_deref() != Some(plan.kernel_version.as_str())
        || target.architecture != "x86_64"
        || plan.support_commit != NVIDIA_SUPPORT_BUILD_COMMIT
        || plan.expected_trust != "locally-built-verified"
        || !valid_nvidia_source_identity(
            &plan.source_origin,
            &plan.source_repository,
            &plan.source_branch,
            &plan.nvidia_version,
        )
        || plan.source_commit.len() != 40
        || !plan
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("NVIDIA on-demand build plan does not match the exact image target or pinned support policy.".into());
    }
    validate_nvidia_target_build_spec(&NvidiaTargetBuildSpec {
        steamos_version: plan.steamos_version.clone(),
        kernel_version: plan.kernel_version.clone(),
        nvidia_version: plan.nvidia_version.clone(),
    })
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
        match session.nvidia_resolution.as_ref().map(|resolution| resolution.status.as_str()) {
            Some("compatible") => {
                collect_nvidia_install_inputs(session)?;
            }
            Some("build_required") => validate_on_demand_build_plan(session)?,
            _ => return Err("A compatible artifact or exact-kernel on-demand build plan is required before x86 handoff.".into()),
        }
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

#[tauri::command]
async fn build_nvidia_target_on_demand(
    app: tauri::AppHandle,
) -> Result<NvidiaPublishedResolution, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let image_manager_state = app.state::<Mutex<ApplianceManager>>();
        let (image_runtime_dir, target, plan) = {
            let manager = image_manager_state
                .lock()
                .map_err(|_| "Appliance state lock is unavailable.")?;
            let session = manager
                .session
                .as_ref()
                .ok_or("The image-builder session is not running.")?;
            if session.state != "handoff" {
                return Err("The working image has not been handed to the x86_64 appliance.".into());
            }
            validate_on_demand_build_plan(session)?;
            let resolution = session
                .nvidia_resolution
                .as_ref()
                .ok_or("NVIDIA resolution is unavailable.")?;
            (
                session.runtime_dir.clone(),
                resolution.target.clone(),
                resolution
                    .build_plan
                    .clone()
                    .ok_or("NVIDIA resolver omitted the on-demand build plan.")?,
            )
        };
        let build_manager_state = app.state::<Mutex<NvidiaBuildManager>>();
        let (connection, cancel) = {
            let mut manager = build_manager_state
                .lock()
                .map_err(|_| "NVIDIA build-appliance state lock is unavailable.")?;
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
                "Building NVIDIA {} for exact kernel {}.",
                plan.nvidia_version, plan.kernel_version
            );
            (NvidiaBuildConnection::from(&*session), cancel)
        };
        let output_dir = image_runtime_dir.join("on-demand-nvidia-artifacts");
        let spec = NvidiaTargetBuildSpec {
            steamos_version: plan.steamos_version.clone(),
            kernel_version: plan.kernel_version.clone(),
            nvidia_version: plan.nvidia_version.clone(),
        };
        let build = build_nvidia_for_target_from_source(
            &connection,
            NvidiaSupportSource::PinnedGithub,
            Some(NvidiaSourcePin {
                origin: &plan.source_origin,
                repository: &plan.source_repository,
                reference: &plan.source_branch,
                commit: &plan.source_commit,
            }),
            &output_dir,
            &spec,
            Some(&cancel),
        );
        if let Ok(mut manager) = build_manager_state.lock() {
            if let Some(session) = manager
                .session
                .as_mut()
                .filter(|session| session.ssh_port == connection.ssh_port)
            {
                session.state = "ready".into();
                session.message = match &build {
                    Ok(_) => "Exact-kernel NVIDIA artifact build completed and validated.".into(),
                    Err(error) => format!(
                        "Exact-kernel NVIDIA artifact build stopped without a usable artifact: {error}"
                    ),
                };
            }
        }
        let artifact = build?;
        if artifact.trust != plan.expected_trust {
            return Err(format!(
                "On-demand artifact trust was {}; expected {}. The artifact will not be installed.",
                artifact.trust, plan.expected_trust
            ));
        }
        let build_info = fs::read_to_string(&artifact.build_info_path)
            .map_err(|error| format!("Could not re-open on-demand build metadata: {error}"))?;
        if metadata_field(&build_info, "source_commit") != Some(plan.source_commit.as_str())
            || metadata_field(&build_info, "source_repository")
                != Some(plan.source_repository.as_str())
            || metadata_field(&build_info, "support_commit") != Some(NVIDIA_SUPPORT_BUILD_COMMIT)
            || metadata_field(&build_info, "source_dirty") != Some("0")
            || metadata_field(&build_info, "support_dirty") != Some("0")
        {
            return Err(
                "On-demand artifact metadata does not match the pinned clean source/support commits."
                    .into(),
            );
        }
        let inspection = inspect_published_nvidia_archive(Path::new(&artifact.archive_path))?;
        let resolution = NvidiaPublishedResolution {
            schema_version: NVIDIA_RESOLVER_SCHEMA,
            status: "compatible".into(),
            reason: "on_demand_artifact_verified".into(),
            message: format!(
                "Built and verified NVIDIA {} locally for exact kernel {}.",
                plan.nvidia_version, plan.kernel_version
            ),
            compatibility: Some("on_demand_exact_kernel".into()),
            target,
            publication: Some(NvidiaPublishedPublication {
                tag: format!(
                    "on-demand-steamos-{}-nvidia-{}-k{}",
                    plan.steamos_version, plan.nvidia_version, plan.kernel_version
                ),
                steamos_version: plan.steamos_version.clone(),
                kernel_version: plan.kernel_version.clone(),
                nvidia_version: plan.nvidia_version.clone(),
                published_at: None,
            }),
            artifact: Some(NvidiaPublishedArtifact {
                archive_path: artifact.archive_path,
                checksum_path: artifact.checksum_path,
                build_info_path: Some(artifact.build_info_path),
                provenance_path: artifact.provenance_path,
                archive_sha256: artifact.archive_sha256,
                archive_bytes: inspection.archive_bytes,
                expanded_bytes: inspection.expanded_bytes,
                trust: artifact.trust,
            }),
            build_plan: Some(plan),
        };
        let mut manager = image_manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        let session = manager
            .session
            .as_mut()
            .filter(|session| session.runtime_dir == image_runtime_dir && session.state == "handoff")
            .ok_or("Image-builder session ended before the on-demand artifact could be recorded.")?;
        session.nvidia_resolution = Some(resolution.clone());
        session.nvidia_userspace = None;
        session.nvidia_installer_bundle = None;
        session.nvidia_install_validation = None;
        session.nvidia_installation = None;
        Ok(resolution)
    })
    .await
    .map_err(|error| format!("On-demand NVIDIA build worker failed: {error}"))?
}

#[tauri::command]
async fn publish_on_demand_nvidia_release(
    app: tauri::AppHandle,
) -> Result<NvidiaReleasePublication, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let settings = load_builder_settings(&app)?;
        if !settings.auto_release_verified_nvidia {
            return Err("Maintainer auto-release is not enabled in settings.".into());
        }
        let maintainer = github_maintainer_status()?;
        if !maintainer.authorized {
            return Err("GitHub maintainer permission could not be re-verified immediately before publication.".into());
        }
        let (publication, artifact, plan, runtime_dir) = {
            let manager_state = app.state::<Mutex<ApplianceManager>>();
            let manager = manager_state
                .lock()
                .map_err(|_| "Appliance state lock is unavailable.")?;
            let session = manager
                .session
                .as_ref()
                .ok_or("The image-builder session is not running.")?;
            let resolution = session
                .nvidia_resolution
                .as_ref()
                .filter(|resolution| {
                    resolution.status == "compatible"
                        && resolution.reason == "on_demand_artifact_verified"
                })
                .ok_or("Only a newly built and verified on-demand artifact can be published.")?;
            (
                resolution
                    .publication
                    .clone()
                    .ok_or("On-demand artifact omitted publication identity.")?,
                resolution
                    .artifact
                    .clone()
                    .ok_or("On-demand artifact omitted verified files.")?,
                resolution
                    .build_plan
                    .clone()
                    .ok_or("On-demand artifact omitted its pinned build plan.")?,
                session.runtime_dir.clone(),
            )
        };
        if artifact.trust != "locally-built-verified"
            || plan.expected_trust != "locally-built-verified"
            || plan.support_commit != NVIDIA_SUPPORT_BUILD_COMMIT
            || plan.source_origin != "project"
            || plan.source_repository != NVIDIA_SOURCE_REPOSITORY
            || publication.steamos_version != plan.steamos_version
            || publication.kernel_version != plan.kernel_version
            || publication.nvidia_version != plan.nvidia_version
            || !valid_nvidia_source_identity(
                &plan.source_origin,
                &plan.source_repository,
                &plan.source_branch,
                &plan.nvidia_version,
            )
            || plan.source_commit.len() != 40
            || !plan
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("On-demand artifact no longer satisfies the release trust policy.".into());
        }
        let identity = PublishedReleaseIdentity {
            steamos_version: plan.steamos_version.clone(),
            kernel_version: plan.kernel_version.clone(),
            nvidia_version: plan.nvidia_version.clone(),
            tag: format!(
                "steamos-{}-nvidia-{}-k{}",
                plan.steamos_version, plan.nvidia_version, plan.kernel_version
            ),
        };
        let expected_archive = published_asset_name(&identity);
        let expected_checksum = format!("{expected_archive}.sha256");
        let expected_build_info = format!(
            "{}.build-info.txt",
            expected_archive.trim_end_matches(".tar.gz")
        );
        let expected_provenance = format!(
            "{}.provenance.json",
            expected_archive.trim_end_matches(".tar.gz")
        );
        let archive = PathBuf::from(&artifact.archive_path);
        let checksum = PathBuf::from(&artifact.checksum_path);
        let build_info = artifact
            .build_info_path
            .as_ref()
            .map(PathBuf::from)
            .ok_or("On-demand artifact omitted its external build-info file.")?;
        let provenance = PathBuf::from(&artifact.provenance_path);
        for (path, expected) in [
            (&archive, expected_archive.as_str()),
            (&checksum, expected_checksum.as_str()),
            (&build_info, expected_build_info.as_str()),
            (&provenance, expected_provenance.as_str()),
        ] {
            if path.file_name().and_then(|name| name.to_str()) != Some(expected)
                || !fs::symlink_metadata(path)
                    .map(|metadata| metadata.file_type().is_file())
                    .unwrap_or(false)
            {
                return Err(format!("Release input is missing or has an unexpected name: {expected}."));
            }
        }
        if sha256_file(&archive)? != artifact.archive_sha256 {
            return Err("Release archive changed after on-demand validation.".into());
        }
        let archived_build_info = Command::new("tar")
            .args(["-xOzf"])
            .arg(&archive)
            .arg("BUILD-INFO.txt")
            .output()
            .map_err(|error| format!("Could not re-open archived build metadata: {error}"))?;
        if !archived_build_info.status.success()
            || archived_build_info.stdout
                != fs::read(&build_info)
                    .map_err(|error| format!("Could not re-open release build metadata: {error}"))?
        {
            return Err(
                "External release build metadata no longer matches the validated archive.".into(),
            );
        }
        let (publish_trust, inspection) = validate_published_nvidia_artifact(
            &archive,
            &checksum,
            &provenance,
            &identity,
            &artifact.archive_sha256,
        )?;
        if publish_trust != "locally-built-verified" {
            return Err("Release artifact failed the final published-artifact trust contract.".into());
        }
        if inspection.archive_bytes != artifact.archive_bytes
            || inspection.expanded_bytes != artifact.expanded_bytes
        {
            return Err("Release archive size accounting changed after validation.".into());
        }
        find_binary("python3").ok_or("Python 3 is required by the pinned support publisher.")?;
        find_binary("gh").ok_or("GitHub CLI disappeared before publication.")?;
        let publisher_root = prepare_pinned_nvidia_publisher(&runtime_dir)?;
        let publisher = publisher_root.join("bootstrap/publish_artifacts.sh");
        let canonical_asset = |path: &Path| {
            fs::canonicalize(path)
                .map(|path| path.to_string_lossy().into_owned())
                .map_err(|error| format!("Could not resolve a release input path: {error}"))
        };
        let expected_assets = [
            canonical_asset(&archive)?,
            canonical_asset(&checksum)?,
            canonical_asset(&build_info)?,
            canonical_asset(&provenance)?,
        ];
        let dry_run = support_publisher_command(
            &publisher,
            &archive,
            &checksum,
            &build_info,
            &provenance,
        )
        .arg("--dry-run")
        .output()
        .map_err(|error| format!("Could not run the pinned support publisher dry-run: {error}"))?;
        if !dry_run.status.success() {
            let detail = String::from_utf8_lossy(&dry_run.stderr).trim().to_string();
            return Err(if detail.is_empty() {
                "Pinned support publisher rejected the release inputs.".into()
            } else {
                format!("Pinned support publisher rejected the release inputs: {detail}")
            });
        }
        let publication_plan: SupportPublicationPlan = serde_json::from_slice(&dry_run.stdout)
            .map_err(|error| {
                format!("Pinned support publisher returned an invalid dry-run plan: {error}")
            })?;
        validate_support_publication_plan(
            &publication_plan,
            &identity,
            &artifact.archive_sha256,
            &expected_assets,
        )?;

        let maintainer = github_maintainer_status()?;
        if !maintainer.authorized {
            return Err("GitHub maintainer permission expired before publication.".into());
        }
        let output = support_publisher_command(
            &publisher,
            &archive,
            &checksum,
            &build_info,
            &provenance,
        )
        .arg("--create-only")
        .output()
        .map_err(|error| format!("Could not run the pinned support publisher: {error}"))?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(if detail.is_empty() {
                "The pinned support publisher rejected the release. No existing release was modified."
                    .into()
            } else {
                format!(
                    "The pinned support publisher rejected the release; no existing release was modified: {detail}"
                )
            });
        }
        let url = format!(
            "https://github.com/{NVIDIA_SUPPORT_REPOSITORY}/releases/tag/{}",
            identity.tag
        );
        Ok(NvidiaReleasePublication {
            status: "published".into(),
            repository: NVIDIA_SUPPORT_REPOSITORY.into(),
            tag: identity.tag.clone(),
            url,
            message: format!(
                "Published verified NVIDIA artifact as {} through the pinned canonical support publisher.",
                identity.tag
            ),
        })
    })
    .await
    .map_err(|error| format!("NVIDIA release worker failed: {error}"))?
}

fn validate_support_storage(
    storage: &SupportInstallStorage,
    compression: &SupportInstallCompression,
    expect_sufficient: bool,
) -> Result<(), String> {
    const ROOT_METADATA_RESERVE: u64 = 64 * 1024 * 1024;
    const MIN_INITRAMFS_RESERVE: u64 = 64 * 1024 * 1024;
    const VAR_RESERVE: u64 = 16 * 1024 * 1024;
    const MIN_EFI_RESERVE: u64 = 1024 * 1024;
    if storage.package_compressed_bytes == 0
        || storage.package_installed_bytes == 0
        || storage.module_installed_bytes == 0
        || storage.package_replaced_bytes > storage.package_installed_bytes
        || storage.module_replaced_bytes > storage.module_installed_bytes
        || storage.initramfs_reserve_bytes < MIN_INITRAMFS_RESERVE
        || storage.var_required_bytes != VAR_RESERVE
        || storage.efi_required_bytes < MIN_EFI_RESERVE
    {
        return Err("Offline installer returned invalid storage accounting.".into());
    }
    let conservative_root = checked_space_sum([
        storage.package_installed_bytes - storage.package_replaced_bytes,
        storage.module_installed_bytes - storage.module_replaced_bytes,
        storage.initramfs_reserve_bytes,
        ROOT_METADATA_RESERVE,
    ])?;
    if compression.declared_package_bytes != storage.package_installed_bytes
        || compression.package_archive_bytes != storage.package_compressed_bytes
        || compression.package_archive_savings_bytes
            != storage
                .package_installed_bytes
                .saturating_sub(storage.package_compressed_bytes)
    {
        return Err(
            "Offline installer compression context does not match package accounting.".into(),
        );
    }
    if compression.requested_profile.as_deref() == Some(NVIDIA_COMPRESSION_PROFILE) {
        let measurement = compression
            .measurement
            .as_ref()
            .ok_or("Offline installer omitted its Btrfs payload measurement.")?;
        let declared_payload = checked_space_sum([
            storage.package_installed_bytes,
            storage.module_installed_bytes,
        ])?;
        let replacement_credit = storage
            .replacement_credit_bytes
            .ok_or("Offline installer omitted its measured replacement credit.")?;
        let package_noop_credit = storage
            .package_noop_credit_bytes
            .ok_or("Offline installer omitted its package no-op credit.")?;
        let module_noop_credit = storage
            .module_noop_credit_bytes
            .ok_or("Offline installer omitted its module no-op credit.")?;
        let combined_noop_credit = checked_space_sum([package_noop_credit, module_noop_credit])?;
        let compression_reserve =
            checked_space_sum([storage.initramfs_reserve_bytes, ROOT_METADATA_RESERVE])?;
        let measured_root = checked_space_sum([
            measurement
                .payload_allocated_bytes
                .checked_sub(replacement_credit)
                .ok_or("Offline installer replacement credit exceeds measured allocation.")?,
            compression_reserve,
        ])?;
        let logical_root = checked_space_sum([declared_payload, compression_reserve])?;
        let replacement_candidate = checked_space_sum([
            storage.package_replaced_bytes,
            storage.module_replaced_bytes,
        ])?;
        let package_measurement_total = checked_space_sum(
            measurement
                .package_measurements
                .iter()
                .map(|item| item.allocated_bytes)
                .chain(std::iter::once(measurement.module_allocated_bytes)),
        )?;
        let expected_ratio_millionths = u128::from(measurement.payload_allocated_bytes) * 1_000_000
            / u128::from(declared_payload);
        let expected_ratio = format!(
            "{}.{:06}",
            expected_ratio_millionths / 1_000_000,
            expected_ratio_millionths % 1_000_000
        );
        let final_margin = i128::from(storage.root_available_bytes) - i128::from(measured_root);
        let final_margin = i64::try_from(final_margin)
            .map_err(|_| "Offline installer returned an excessive root-space margin.")?;
        let root_shortfall = if final_margin < 0 {
            final_margin.unsigned_abs()
        } else {
            0
        };
        if compression.filesystem != "btrfs"
            || compression.write_policy.as_deref() != Some(NVIDIA_COMPRESSION_WRITE_POLICY)
            || compression.admission_basis
                != "scratch-btrfs-allocated-physical-bytes-minus-noop-credit-plus-reserves"
            || compression.assessment != "measured-profile-admission-ready"
            || measurement.schema_version != 1
            || measurement.status != "measured"
            || measurement.profile != NVIDIA_COMPRESSION_PROFILE
            || measurement.write_policy != NVIDIA_COMPRESSION_WRITE_POLICY
            || measurement.measurement_method != "scratch-btrfs-filesystem-usage-used-delta"
            || measurement.declared_payload_bytes != declared_payload
            || measurement.payload_allocated_bytes == 0
            || measurement.data_allocated_bytes == 0
            || measurement.data_allocated_bytes > measurement.payload_allocated_bytes
            || package_measurement_total > measurement.payload_allocated_bytes
            || measurement.filesystem_overhead_bytes
                != measurement
                    .payload_allocated_bytes
                    .saturating_sub(measurement.data_allocated_bytes)
            || measurement.scratch_filesystem_bytes < declared_payload
            || storage.root_conservative_required_bytes != Some(conservative_root)
            || storage.root_logical_required_bytes != Some(logical_root)
            || storage.root_measured_required_bytes != Some(measured_root)
            || storage.root_required_bytes != measured_root
            || storage.measured_payload_allocated_bytes != Some(measurement.payload_allocated_bytes)
            || storage.compression_payload_allocated_bytes
                != Some(measurement.payload_allocated_bytes)
            || storage.compression_filesystem_overhead_bytes
                != Some(measurement.filesystem_overhead_bytes)
            || storage.compression_safety_reserve_bytes != Some(ROOT_METADATA_RESERVE)
            || storage.compression_reserve_bytes != Some(compression_reserve)
            || storage.replacement_candidate_logical_bytes != Some(replacement_candidate)
            || replacement_credit != combined_noop_credit
            || storage.module_noop_credit_bytes
                != Some(if compression.module_payload_noop == Some(true) {
                    measurement.module_allocated_bytes
                } else {
                    0
                })
            || storage.root_final_margin_bytes != Some(final_margin)
            || storage.root_shortfall_bytes != Some(root_shortfall)
            || compression.measured_payload_savings_bytes
                != Some(declared_payload.saturating_sub(measurement.payload_allocated_bytes))
            || compression.compression_savings_credited_bytes
                != conservative_root.saturating_sub(measured_root)
            || compression.mutation_profile_implemented != Some(true)
            || compression.compression_ratio.as_deref() != Some(expected_ratio.as_str())
            || compression.all_payload_destinations_on_root_filesystem != Some(true)
            || compression.replacement_credit_policy.as_deref() != Some("exact-payload-noop-only")
            || compression.module_payload_noop.is_none()
        {
            return Err(
                "Offline installer returned inconsistent Btrfs measurement metadata.".into(),
            );
        }
    } else if compression.requested_profile.is_none() {
        if storage.root_required_bytes != conservative_root
            || compression.admission_basis != "logical-uncompressed-conservative"
            || compression.compression_savings_credited_bytes != 0
            || compression.measurement.is_some()
        {
            return Err(
                "Offline installer conservative storage accounting is inconsistent.".into(),
            );
        }
    } else {
        return Err("Offline installer returned an unsupported compression profile.".into());
    }
    let sufficient = storage.root_available_bytes >= storage.root_required_bytes
        && storage.var_available_bytes >= storage.var_required_bytes
        && storage.efi_available_bytes >= storage.efi_required_bytes;
    if sufficient != expect_sufficient
        || compression
            .admission_authorized
            .is_some_and(|authorized| authorized != sufficient)
    {
        return Err("Offline installer storage status does not match its byte accounting.".into());
    }
    Ok(())
}

fn validate_nvidia_storage_failure(
    document: &SupportInstallResult,
    inputs: &NvidiaInstallInputs,
) -> Result<String, String> {
    if document.schema_version != 1
        || document.status != "failed"
        || document.reason != "target_space_insufficient"
        || document.target.kernel_version != inputs.kernel_version
        || document.target.steamos_version != "unknown"
        || document.target.nvidia_version != "unknown"
        || document.target.architecture != "x86_64"
        || !document.cleanup.mounts_released
        || !document.cleanup.compression_policy_restored
    {
        return Err("Offline installer returned an invalid storage-failure result.".into());
    }
    let storage =
        match document.validation.as_ref() {
            Some(SupportInstallValidationDocument::Failed(validation)) => validation
                .storage
                .as_ref()
                .ok_or("Offline installer storage failure omitted authoritative accounting.")?,
            _ => {
                return Err(
                    "Offline installer storage failure omitted authoritative accounting.".into(),
                )
            }
        };
    let compression = match document.validation.as_ref() {
        Some(SupportInstallValidationDocument::Failed(validation)) => validation
            .compression
            .as_ref()
            .ok_or("Offline installer storage failure omitted compression accounting.")?,
        _ => {
            return Err("Offline installer storage failure omitted compression accounting.".into())
        }
    };
    validate_support_storage(storage, compression, false)?;
    let root_shortfall = storage
        .root_required_bytes
        .saturating_sub(storage.root_available_bytes);
    let package_growth = storage
        .package_installed_bytes
        .saturating_sub(storage.package_replaced_bytes);
    let module_growth = storage
        .module_installed_bytes
        .saturating_sub(storage.module_replaced_bytes);
    let metadata_reserve = storage
        .root_required_bytes
        .saturating_sub(package_growth)
        .saturating_sub(module_growth)
        .saturating_sub(storage.initramfs_reserve_bytes);
    Ok(format!(
        "SteamOS rootfs-A needs {} but has {} available—a {} shortfall. Root accounting: {} userspace growth, {} module growth, {} initramfs reserve, and {} metadata/safety reserve. var-A needs {} / has {}; efi-A needs {} / has {}. No mutation began.",
        human_bytes(storage.root_required_bytes),
        human_bytes(storage.root_available_bytes),
        human_bytes(root_shortfall),
        human_bytes(package_growth),
        human_bytes(module_growth),
        human_bytes(storage.initramfs_reserve_bytes),
        human_bytes(metadata_reserve),
        human_bytes(storage.var_required_bytes),
        human_bytes(storage.var_available_bytes),
        human_bytes(storage.efi_required_bytes),
        human_bytes(storage.efi_available_bytes),
    ))
}

fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let value = bytes as f64;
    if value >= GIB {
        format!("{:.2} GiB", value / GIB)
    } else if value >= MIB {
        format!("{:.1} MiB", value / MIB)
    } else if value >= KIB {
        format!("{:.1} KiB", value / KIB)
    } else {
        format!("{bytes} bytes")
    }
}

fn concise_json_value(value: &serde_json::Value) -> String {
    const LIMIT: usize = 160;
    let rendered = serde_json::to_string(value).unwrap_or_else(|_| "<invalid>".into());
    if rendered.chars().count() <= LIMIT {
        return rendered;
    }
    let mut concise: String = rendered.chars().take(LIMIT).collect();
    concise.push('…');
    concise
}

fn valid_support_measurement_failure(detail: &SupportInstallMeasurementFailure) -> bool {
    const PHASES: [&str; 12] = [
        "dependency_check",
        "image_create",
        "filesystem_create",
        "mount",
        "baseline_usage",
        "package_extraction",
        "package_usage",
        "module_extraction",
        "module_compression",
        "final_usage",
        "cleanup",
        "launcher",
    ];
    const COMMANDS: [&str; 12] = [
        "btrfs",
        "findmnt",
        "mkfs.btrfs",
        "mount",
        "umount",
        "zstd",
        "image-create",
        "btrfs-filesystem-usage",
        "package-archive",
        "module-archive",
        "zstd-compress",
        "zstd-decompress",
    ];
    PHASES.contains(&detail.phase.as_str())
        && detail
            .command
            .as_deref()
            .is_none_or(|command| COMMANDS.contains(&command) || command == "measurement-helper")
        && detail
            .exit_status
            .is_none_or(|status| (-255..=255).contains(&status))
        && detail.stderr.as_deref().is_none_or(|stderr| {
            stderr.len() <= 512
                && stderr
                    .bytes()
                    .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
        })
}

fn support_install_failure_message(document: &SupportInstallResult) -> String {
    let mut details = Vec::new();
    if let Some(SupportInstallValidationDocument::Failed(validation)) = &document.validation {
        if !validation.missing_packages.is_empty() {
            details.push(format!(
                "missing packages: {}",
                validation.missing_packages.join(", ")
            ));
        }
        if !validation.unexpected_packages.is_empty() {
            details.push(format!(
                "unexpected packages: {}",
                validation.unexpected_packages.join(", ")
            ));
        }
        if !validation.duplicate_packages.is_empty() {
            details.push(format!(
                "duplicate packages: {}",
                validation.duplicate_packages.join(", ")
            ));
        }
        for mismatch in &validation.package_mismatches {
            let fields = mismatch
                .invalid_fields
                .iter()
                .map(|field| {
                    let expected = mismatch
                        .expected
                        .get(field)
                        .map(concise_json_value)
                        .unwrap_or_else(|| "<omitted>".into());
                    let actual = mismatch
                        .actual
                        .get(field)
                        .map(concise_json_value)
                        .unwrap_or_else(|| "<omitted>".into());
                    format!("{field}: expected {expected}, received {actual}")
                })
                .collect::<Vec<_>>()
                .join(", ");
            details.push(format!("{} ({fields})", mismatch.package_name));
        }
        if !validation.missing_dependencies.is_empty() {
            let requested_by = validation
                .dependency_requested_by
                .as_deref()
                .map(|name| format!(" requested by {name}"))
                .unwrap_or_default();
            details.push(format!(
                "missing dependencies{requested_by}: {}",
                validation.missing_dependencies.join(", ")
            ));
        }
        if let Some(record) = &validation.package_record {
            details.push(format!(
                "package database record {record} has invalid fields: {}",
                validation.invalid_fields.join(", ")
            ));
        } else if !validation.invalid_fields.is_empty() {
            details.push(format!(
                "invalid fields: {}",
                validation.invalid_fields.join(", ")
            ));
        }
        if let Some(package) = &validation.package_name {
            let signer = validation
                .signer_fingerprint
                .as_deref()
                .map(|fingerprint| format!("; signer {fingerprint}"))
                .unwrap_or_default();
            details.push(format!("package: {package}{signer}"));
        }
        if let Some(measurement) = &validation.measurement_failure {
            if valid_support_measurement_failure(measurement) {
                let command = measurement
                    .command
                    .as_deref()
                    .map(|command| format!(" command {command}"))
                    .unwrap_or_default();
                let status = measurement
                    .exit_status
                    .map(|status| format!(" exit {status}"))
                    .unwrap_or_default();
                let stderr = measurement
                    .stderr
                    .as_deref()
                    .map(|stderr| format!("; {stderr}"))
                    .unwrap_or_default();
                details.push(format!(
                    "measurement phase {}{command}{status}{stderr}",
                    measurement.phase
                ));
            } else {
                details.push("measurement diagnostics were malformed and were ignored".into());
            }
        }
    }
    let summary = format!(
        "Offline installer validation did not succeed: {} ({}): {}",
        document.status, document.reason, document.message
    );
    if details.is_empty() {
        summary
    } else {
        format!("{summary} Details: {}.", details.join("; "))
    }
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
        return Err(support_install_failure_message(&document));
    }
    if document.target.steamos_version != inputs.steamos_version
        || document.target.kernel_version != inputs.kernel_version
        || document.target.nvidia_version != inputs.nvidia_version
        || document.target.architecture != "x86_64"
        || document.trust != inputs.trust
        || !document.cleanup.mounts_released
        || !document.cleanup.compression_policy_restored
    {
        return Err(
            "Offline installer validation result does not match the handoff target.".into(),
        );
    }
    let validation = match document.validation {
        Some(SupportInstallValidationDocument::Verified(validation)) => validation,
        _ => {
            return Err(
                "Offline installer validation result omitted verified input metadata.".into(),
            );
        }
    };
    validate_support_storage(&validation.storage, &validation.compression, true)?;
    if validation.gaming_payload.schema_version != 1
        || validation.gaming_payload.status != "not-requested"
        || validation.gaming_payload.profile_id != "gaming-no-cuda-v1"
    {
        return Err("Offline installer returned unexpected gaming-payload metadata.".into());
    }
    let lock = &inputs.userspace_lock;
    if validation.archive_sha256 != inputs.archive_sha256
        || validation.provenance_sha256 != inputs.provenance_sha256
        || validation.userspace_lock.name
            != Path::new(NVIDIA_USERSPACE_LOCK_PATH)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
        || validation.userspace_lock.sha256 != NVIDIA_USERSPACE_LOCK_SHA256
        || validation.pacman_database.path != "/usr/lib/holo/pacmandb"
        || !(1..=100_000).contains(&validation.pacman_database.package_count)
        || validation.boot.rootfs_boot_path != "/boot"
        || validation.boot.efi_mount_path != "/efi"
        || validation.boot.grub_configuration != "/efi/EFI/steamos/grub.cfg"
        || validation.boot.required_kernel_arguments
            != NVIDIA_REQUIRED_KERNEL_ARGUMENTS.map(str::to_owned)
        || validation.keyring.name != NVIDIA_USERSPACE_KEYRING_NAME
        || validation.keyring.sha256 != NVIDIA_USERSPACE_KEYRING_SHA256
        || validation.packages.len() != inputs.packages.len()
        || validation.packages.len() != lock.packages.len()
    {
        return Err(
            "Offline installer validation metadata does not match the staged inputs.".into(),
        );
    }
    let mut validated_names = HashSet::new();
    if validation
        .packages
        .iter()
        .any(|package| !validated_names.insert(package.name.as_str()))
    {
        return Err("Offline validation returned duplicate package identities.".into());
    }
    for validated in &validation.packages {
        let expected = inputs
            .packages
            .iter()
            .find(|package| package.name == validated.name)
            .ok_or_else(|| {
                format!(
                    "Offline validation returned unlocked package {}.",
                    validated.name
                )
            })?;
        let locked = lock
            .packages
            .iter()
            .find(|package| package.name == validated.name)
            .ok_or_else(|| {
                format!(
                    "Offline validation returned package {} outside the reviewed lock.",
                    validated.name
                )
            })?;
        let expected_role = if matches!(locked.name.as_str(), "nvidia-utils" | "lib32-nvidia-utils")
        {
            "nvidia-userspace"
        } else {
            "dependency"
        };
        if validated.name != expected.name
            || validated.filename != expected.filename
            || validated.signature_filename != locked.signature_filename
            || validated.full_version != expected.full_version
            || validated.full_version != locked.version
            || validated.role != expected.role
            || validated.role != expected_role
            || validated.architecture != locked.architecture
            || validated.sha256 != expected.package_sha256
            || validated.sha256 != locked.package_sha256
            || validated.signature_sha256 != locked.signature_sha256
            || validated.installed_size != locked.installed_size
            || validated.dependencies != locked.dependencies
            || validated.provides != locked.provides
            || validated.pkgrel.is_empty()
            || validated.signer != locked.signer_fingerprint
        {
            return Err(format!(
                "Offline validation metadata does not match staged {}.",
                expected.name
            ));
        }
        match locked.name.as_str() {
            "nvidia-utils" | "lib32-nvidia-utils" if validated.pkgver == inputs.nvidia_version => {}
            "nvidia-utils" | "lib32-nvidia-utils" => {
                return Err(format!(
                    "Offline validation returned an unapproved version for {}.",
                    expected.name
                ));
            }
            _ if expected_role == "dependency" && !validated.pkgver.is_empty() => {}
            _ => return Err("Unexpected userspace package role in the handoff.".into()),
        }
    }
    if validation.compression.requested_profile.is_some() {
        let measurements = validation
            .compression
            .measurement
            .as_ref()
            .ok_or("Offline validation omitted measured package allocation details.")?;
        if measurements.package_measurements.len() != validation.packages.len()
            || measurements
                .package_measurements
                .iter()
                .zip(&validation.packages)
                .any(|(measurement, package)| measurement.filename != package.filename)
        {
            return Err(
                "Offline validation package allocation identities do not match the locked payload."
                    .into(),
            );
        }
    }
    if validation.package_dependency_closure.is_empty()
        || validation.package_dependency_closure.len() > 4_096
    {
        return Err("Offline validation returned an invalid package dependency closure.".into());
    }
    let mut closure_names = HashSet::new();
    for dependency in &validation.package_dependency_closure {
        if arch_dependency_name(&dependency.name)? != dependency.name
            || dependency.version.is_empty()
            || dependency.version.len() > 256
            || !matches!(dependency.source.as_str(), "incoming" | "installed")
            || !closure_names.insert(dependency.name.as_str())
        {
            return Err("Offline validation returned an unsafe package dependency closure.".into());
        }
    }
    for package in &validation.packages {
        if !validation
            .package_dependency_closure
            .iter()
            .any(|dependency| {
                dependency.name == package.name
                    && dependency.version == package.full_version
                    && dependency.source == "incoming"
            })
        {
            return Err(format!(
                "Offline validation dependency closure omitted incoming {}.",
                package.name
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
        provenance_sha256: inputs.provenance_sha256.clone(),
        pacman_database_path: validation.pacman_database.path,
        pacman_package_count: validation.pacman_database.package_count,
        rootfs_boot_path: validation.boot.rootfs_boot_path,
        efi_mount_path: validation.boot.efi_mount_path,
        grub_configuration: validation.boot.grub_configuration,
        required_kernel_arguments: validation.boot.required_kernel_arguments,
        keyring_sha256: validation.keyring.sha256,
        packages: validation.packages,
        storage: validation.storage,
        compression: validation.compression,
        mounts_released: true,
        compression_policy_restored: true,
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

fn nvidia_handoff_checksum(archive_sha256: &str) -> Result<String, String> {
    if archive_sha256.len() != 64 || !archive_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Verified NVIDIA archive SHA-256 is invalid.".into());
    }
    Ok(format!(
        "{}  nvidia-modules.tar.gz\n",
        archive_sha256.to_ascii_lowercase()
    ))
}

fn stage_nvidia_handoff_checksum(
    runtime_dir: &Path,
    archive_sha256: &str,
) -> Result<PathBuf, String> {
    let path = runtime_dir.join("nvidia-modules.tar.gz.sha256");
    let checksum = nvidia_handoff_checksum(archive_sha256)?;
    let output = OpenOptions::new().create_new(true).write(true).open(&path);
    let mut output = match output {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&path).map_err(|inspect_error| {
                format!(
                    "Could not inspect the existing normalized NVIDIA checksum: {inspect_error}"
                )
            })?;
            if !metadata.file_type().is_file() {
                return Err(
                    "Existing normalized NVIDIA checksum is not a safe regular file.".into(),
                );
            }
            let existing = fs::read_to_string(&path).map_err(|read_error| {
                format!("Could not read the existing normalized NVIDIA checksum: {read_error}")
            })?;
            if existing != checksum {
                return Err(
                    "Existing normalized NVIDIA checksum does not match this verified artifact."
                        .into(),
                );
            }
            return Ok(path);
        }
        Err(error) => {
            return Err(format!(
                "Could not stage the normalized NVIDIA checksum: {error}"
            ));
        }
    };
    output
        .write_all(checksum.as_bytes())
        .and_then(|_| output.sync_all())
        .map_err(|error| format!("Could not finish the normalized NVIDIA checksum: {error}"))?;
    Ok(path)
}

fn safe_regular_file_size(path: &Path, description: &str) -> Result<u64, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect {description}: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{description} is not a safe regular file."));
    }
    Ok(metadata.len())
}

fn checked_space_sum(parts: impl IntoIterator<Item = u64>) -> Result<u64, String> {
    parts
        .into_iter()
        .try_fold(0_u64, |total, value| total.checked_add(value))
        .ok_or_else(|| "NVIDIA free-space estimate overflowed.".into())
}

fn nvidia_handoff_space_requirement(
    inputs: &NvidiaInstallInputs,
    installer_archive: &Path,
) -> Result<u64, String> {
    let measured_archive = safe_regular_file_size(&inputs.archive, "NVIDIA module archive")?;
    if measured_archive != inputs.archive_bytes {
        return Err("NVIDIA module archive size changed after validation.".into());
    }
    let mut transfer_sizes = vec![
        inputs.archive_bytes,
        inputs.expanded_bytes,
        safe_regular_file_size(installer_archive, "pinned offline installer archive")?,
        safe_regular_file_size(&inputs.provenance, "NVIDIA provenance")?,
        NVIDIA_HANDOFF_FREE_SPACE_RESERVE,
    ];
    for package in &inputs.packages {
        let package_bytes = safe_regular_file_size(
            Path::new(&package.package_path),
            &format!("{} package", package.name),
        )?;
        transfer_sizes.push(package_bytes);
        transfer_sizes.push(safe_regular_file_size(
            Path::new(&package.signature_path),
            &format!("{} signature", package.name),
        )?);
    }
    checked_space_sum(transfer_sizes)
}

fn require_guest_free_space(
    connection: &impl GuestConnection,
    path: &str,
    required: u64,
    description: &str,
) -> Result<(), String> {
    run_guest_command(
        connection,
        &format!(
            "set -eu; AVAILABLE=$(df -B1 --output=avail {path} | tail -n 1 | tr -d ' '); case \"$AVAILABLE\" in ''|*[!0-9]*) echo 'Could not measure {description} free space.' >&2; exit 1;; esac; if test \"$AVAILABLE\" -lt {required}; then echo '{description} needs at least {required} free bytes; only '\"$AVAILABLE\"' are available.' >&2; exit 1; fi"
        ),
    )
    .map(|_| ())
}

fn guest_userspace_filenames(package: &NvidiaUserspacePackage) -> Result<(String, String), String> {
    let filename = package.filename.as_str();
    if !filename.ends_with(".pkg.tar.zst")
        || filename.is_empty()
        || filename.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric()
                || matches!(byte, b'@' | b'.' | b'_' | b'+' | b':' | b'-'))
        })
        || Path::new(filename)
            .file_name()
            .and_then(|name| name.to_str())
            != Some(filename)
    {
        return Err(format!(
            "Reviewed userspace package {} has an unsafe guest filename.",
            package.name
        ));
    }
    Ok((filename.into(), format!("{filename}.sig")))
}

fn userspace_installer_arguments(packages: &[NvidiaUserspacePackage]) -> Result<String, String> {
    let mut arguments = String::new();
    let mut nvidia_utils = false;
    let mut lib32_nvidia_utils = false;
    for package in packages {
        let (filename, signature_filename) = guest_userspace_filenames(package)?;
        let option = match package.name.as_str() {
            "nvidia-utils" if package.role == "nvidia-userspace" && !nvidia_utils => {
                nvidia_utils = true;
                "nvidia-utils"
            }
            "lib32-nvidia-utils" if package.role == "nvidia-userspace" && !lib32_nvidia_utils => {
                lib32_nvidia_utils = true;
                "lib32-nvidia-utils"
            }
            _ if package.role == "dependency" => "dependency-package",
            _ => return Err("Unexpected userspace package in the installer handoff.".into()),
        };
        arguments.push_str(&format!(" --{option} /tmp/{filename}"));
        arguments.push_str(&format!(
            " --{} /tmp/{signature_filename}",
            if option == "dependency-package" {
                "dependency-signature"
            } else if option == "nvidia-utils" {
                "nvidia-utils-signature"
            } else {
                "lib32-nvidia-utils-signature"
            }
        ));
    }
    if !nvidia_utils || !lib32_nvidia_utils {
        return Err("The installer handoff is missing a required NVIDIA userspace seed.".into());
    }
    Ok(arguments)
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
    let appliance_required = nvidia_handoff_space_requirement(&inputs, &installer_archive)?;
    require_guest_free_space(
        &connection,
        "/tmp",
        appliance_required,
        "The x86 appliance NVIDIA handoff",
    )?;
    copy_install_input_to_guest(&connection, &installer_archive, "offline-installer.tar.gz")?;
    copy_install_input_to_guest(&connection, &inputs.archive, "nvidia-modules.tar.gz")?;
    let handoff_checksum =
        stage_nvidia_handoff_checksum(&connection.runtime_dir, &inputs.archive_sha256)?;
    copy_install_input_to_guest(
        &connection,
        &handoff_checksum,
        "nvidia-modules.tar.gz.sha256",
    )?;
    copy_install_input_to_guest(
        &connection,
        &inputs.provenance,
        "nvidia-modules.provenance.json",
    )?;
    for package in &inputs.packages {
        let (filename, signature_filename) = guest_userspace_filenames(package)?;
        copy_install_input_to_guest(&connection, Path::new(&package.package_path), &filename)?;
        copy_install_input_to_guest(
            &connection,
            Path::new(&package.signature_path),
            &signature_filename,
        )?;
    }

    let validation_attempt = 1_usize;
    let validation = {
        let userspace_arguments = userspace_installer_arguments(&inputs.packages)?;
        let installer_permissions = pinned_installer_guest_permissions()?;
        let command = format!(
            r#"set -euo pipefail
WORK=/tmp/steamos-nvidia-offline-install
TARGET=/dev/disk/by-id/virtio-steamos-target
ROOT=/mnt/steamos-nvidia-target
rm -rf "$WORK"
mkdir -p "$WORK/support"
tar -xzf /tmp/offline-installer.tar.gz -C "$WORK/support"
{installer_permissions}
test -b "$TARGET"
mapfile -t ROOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$TARGET" | awk '$2 == "rootfs-A" && $3 == "btrfs" {{print $1}}')
mapfile -t BOOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$TARGET" | awk '$2 == "efi-A" && ($3 == "vfat" || $3 == "fat") {{print $1}}')
mapfile -t VAR_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$TARGET" | awk '$2 == "var-A" && $3 == "ext4" {{print $1}}')
test "${{#ROOT_PARTS[@]}}" -eq 1
test "${{#BOOT_PARTS[@]}}" -eq 1
test "${{#VAR_PARTS[@]}}" -eq 1
test "${{ROOT_PARTS[0]}}" != "${{BOOT_PARTS[0]}}"
test "${{ROOT_PARTS[0]}}" != "${{VAR_PARTS[0]}}"
test "${{BOOT_PARTS[0]}}" != "${{VAR_PARTS[0]}}"
sudo mkdir -p "$ROOT"
ROOT_MOUNTED=0
VAR_MOUNTED=0
EFI_MOUNTED=0
cleanup() {{
  rc=$?
  if (( EFI_MOUNTED )); then sudo umount "$ROOT/efi" || rc=1; fi
  if (( VAR_MOUNTED )); then sudo umount "$ROOT/var" || rc=1; fi
  if (( ROOT_MOUNTED )); then sudo umount "$ROOT" || rc=1; fi
  ! findmnt -rn -M "$ROOT/efi" >/dev/null 2>&1 || rc=1
  ! findmnt -rn -M "$ROOT/var" >/dev/null 2>&1 || rc=1
  ! findmnt -rn -M "$ROOT" >/dev/null 2>&1 || rc=1
  exit "$rc"
}}
trap cleanup EXIT INT TERM
sudo mount -o ro "${{ROOT_PARTS[0]}}" "$ROOT"
ROOT_MOUNTED=1
test -d "$ROOT/boot"
test ! -L "$ROOT/boot"
test -d "$ROOT/efi"
test ! -L "$ROOT/efi"
test -d "$ROOT/var"
test ! -L "$ROOT/var"
sudo mount -o ro "${{VAR_PARTS[0]}}" "$ROOT/var"
VAR_MOUNTED=1
sudo mount -o ro "${{BOOT_PARTS[0]}}" "$ROOT/efi"
EFI_MOUNTED=1
if test ! -d "$ROOT/usr/lib/holo/pacmandb/local"; then
  echo 'The selected SteamOS recovery root lacks its expected /usr/lib/holo/pacmandb/local package database; refusing NVIDIA mutation.' >&2
  exit 1
fi
sudo dnf install -y bsdtar gnupg2 python3 kmod pacman
test -d /var/tmp
test "$(findmnt -rn -T /var/tmp -o FSTYPE)" != tmpfs
test -f "$WORK/support/{keyring_path}"
test -f "$WORK/support/{lock_path}"
sudo env TMPDIR=/var/tmp bash "$WORK/support/bootstrap/install_to_root.sh" --validate-only --compression-profile {compression_profile} --root "$ROOT" --archive /tmp/nvidia-modules.tar.gz --checksum /tmp/nvidia-modules.tar.gz.sha256 --provenance /tmp/nvidia-modules.provenance.json --kernel {kernel}{userspace_arguments} --package-keyring "$WORK/support/{keyring_path}" --userspace-lock "$WORK/support/{lock_path}" --progress-attempt {validation_attempt} --result-json "$WORK/install-result.json"
sudo umount "$ROOT/efi"
EFI_MOUNTED=0
sudo umount "$ROOT/var"
VAR_MOUNTED=0
sudo umount "$ROOT"
ROOT_MOUNTED=0
! findmnt -rn -M "$ROOT/efi" >/dev/null 2>&1
! findmnt -rn -M "$ROOT/var" >/dev/null 2>&1
! findmnt -rn -M "$ROOT" >/dev/null 2>&1
trap - EXIT INT TERM"#,
            keyring_path = NVIDIA_USERSPACE_KEYRING_PATH,
            lock_path = NVIDIA_USERSPACE_LOCK_PATH,
            kernel = inputs.kernel_version,
            userspace_arguments = userspace_arguments,
            compression_profile = NVIDIA_COMPRESSION_PROFILE,
            installer_permissions = installer_permissions,
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
            inputs.image_runtime_dir.join(format!(
                "nvidia-install-validation-{validation_attempt}.json"
            )),
        )
        .map_err(|e| format!("Could not preserve the NVIDIA installer result: {e}"))?;
        fs::copy(
            &staged_result,
            inputs
                .image_runtime_dir
                .join("nvidia-install-validation.json"),
        )
        .map_err(|e| format!("Could not preserve the latest NVIDIA installer result: {e}"))?;
        let document: SupportInstallResult = serde_json::from_reader(
            File::open(&staged_result)
                .map_err(|e| format!("Could not read the NVIDIA installer result: {e}"))?,
        )
        .map_err(|e| format!("NVIDIA installer result is invalid JSON: {e}"))?;
        if document.status == "failed" && document.reason == "target_space_insufficient" {
            let message = validate_nvidia_storage_failure(&document, &inputs)?;
            if execution_result.is_ok() {
                return Err(
                    "Offline installer reported insufficient storage with a successful process exit."
                        .into(),
                );
            }
            return Err(message);
        }
        let validation = validate_nvidia_install_result(
            document,
            &inputs,
            "validated",
            "validation_complete",
            "validated",
        )?;
        execution_result?;
        validation
    };

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
    let userspace_arguments = userspace_installer_arguments(&inputs.packages)?;
    let command = format!(
        r#"set -euo pipefail
WORK=/tmp/steamos-nvidia-offline-install
TARGET=/dev/disk/by-id/virtio-steamos-target
TOP=/mnt/steamos-nvidia-top
ROOT=/mnt/steamos-nvidia-target
test -b "$TARGET"
test -d "$WORK/support"
test -f "$WORK/support/{keyring_path}"
test -f "$WORK/support/{lock_path}"
mapfile -t ROOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$TARGET" | awk '$2 == "rootfs-A" && $3 == "btrfs" {{print $1}}')
mapfile -t BOOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$TARGET" | awk '$2 == "efi-A" && ($3 == "vfat" || $3 == "fat") {{print $1}}')
mapfile -t VAR_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$TARGET" | awk '$2 == "var-A" && $3 == "ext4" {{print $1}}')
test "${{#ROOT_PARTS[@]}}" -eq 1
test "${{#BOOT_PARTS[@]}}" -eq 1
test "${{#VAR_PARTS[@]}}" -eq 1
test "${{ROOT_PARTS[0]}}" != "${{BOOT_PARTS[0]}}"
test "${{ROOT_PARTS[0]}}" != "${{VAR_PARTS[0]}}"
test "${{BOOT_PARTS[0]}}" != "${{VAR_PARTS[0]}}"
sudo mkdir -p "$TOP" "$ROOT"
TOP_MOUNTED=0
ROOT_MOUNTED=0
ROOT_IS_TOP=0
VAR_MOUNTED=0
EFI_MOUNTED=0
RESTORE_ROOT_RO=0
WAS_SEEDING=0
SEEDING_RESTORED=0
SOURCE_ROOT=
cleanup() {{
  rc=$?
  trap - EXIT INT TERM
  if (( EFI_MOUNTED )); then sudo umount "$ROOT/efi" || rc=1; fi
  if (( VAR_MOUNTED )); then sudo umount "$ROOT/var" || rc=1; fi
  if (( ROOT_MOUNTED )); then sudo umount "$ROOT" || rc=1; fi
  if (( RESTORE_ROOT_RO )) && (( TOP_MOUNTED )) && test -n "$SOURCE_ROOT"; then
    sudo btrfs property set -f -ts "$SOURCE_ROOT" ro true || rc=1
  fi
  if (( TOP_MOUNTED )); then sudo umount "$TOP" || rc=1; fi
  if (( WAS_SEEDING )) && ! (( SEEDING_RESTORED )); then
    sudo btrfstune -f -S 1 "${{ROOT_PARTS[0]}}" || rc=1
  fi
  ! findmnt -rn -M "$ROOT/efi" >/dev/null 2>&1 || rc=1
  ! findmnt -rn -M "$ROOT/var" >/dev/null 2>&1 || rc=1
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
  WAS_SEEDING=1
  sudo btrfstune -f -S 0 "${{ROOT_PARTS[0]}}"
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
  RESTORE_ROOT_RO=1
  sudo btrfs property set -f -ts "$SOURCE_ROOT" ro false
fi
if ! (( ROOT_IS_TOP )); then
  sudo mount -o rw,subvol="$DEFAULT_PATH" "${{ROOT_PARTS[0]}}" "$ROOT"
  ROOT_MOUNTED=1
fi
findmnt -rn -M "$ROOT" -o OPTIONS | tr ',' '\n' | grep -qx rw
root_compression_option() {{
  option=$(findmnt -rn -M "$ROOT" -o OPTIONS | tr ',' '\n' | awk '/^compress(=|-force=)/ {{ if (found) exit 2; found=$0 }} END {{ print found }}')
  case "$option" in compress=no) printf '\n' ;; *) printf '%s\n' "$option" ;; esac
}}
ORIGINAL_ROOT_COMPRESSION=$(root_compression_option)
test -d "$ROOT/boot"
test ! -L "$ROOT/boot"
test -d "$ROOT/efi"
test ! -L "$ROOT/efi"
test -d "$ROOT/var"
test ! -L "$ROOT/var"
sudo mount -o rw "${{VAR_PARTS[0]}}" "$ROOT/var"
VAR_MOUNTED=1
sudo mount -o rw "${{BOOT_PARTS[0]}}" "$ROOT/efi"
EFI_MOUNTED=1
test -d /var/tmp
test "$(findmnt -rn -T /var/tmp -o FSTYPE)" != tmpfs
sudo env TMPDIR=/var/tmp bash "$WORK/support/bootstrap/install_to_root.sh" --compression-profile {compression_profile} --root "$ROOT" --archive /tmp/nvidia-modules.tar.gz --checksum /tmp/nvidia-modules.tar.gz.sha256 --provenance /tmp/nvidia-modules.provenance.json --kernel {kernel}{userspace_arguments} --package-keyring "$WORK/support/{keyring_path}" --userspace-lock "$WORK/support/{lock_path}" --result-json "$WORK/install-mutation-result.json"
test "$(root_compression_option)" = "$ORIGINAL_ROOT_COMPRESSION"
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
sudo umount "$ROOT/efi"
EFI_MOUNTED=0
sudo umount "$ROOT/var"
VAR_MOUNTED=0
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
! findmnt -rn -M "$ROOT/efi" >/dev/null 2>&1
! findmnt -rn -M "$ROOT/var" >/dev/null 2>&1
! findmnt -rn -M "$ROOT" >/dev/null 2>&1
! findmnt -rn -M "$TOP" >/dev/null 2>&1
trap - EXIT INT TERM"#,
        keyring_path = NVIDIA_USERSPACE_KEYRING_PATH,
        lock_path = NVIDIA_USERSPACE_LOCK_PATH,
        kernel = inputs.kernel_version,
        userspace_arguments = userspace_arguments,
        compression_profile = NVIDIA_COMPRESSION_PROFILE,
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
fn preview_image_output(path: String) -> Result<ImageOutputPreview, String> {
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
    let output = output_path_for_input(&canonical, true)?;
    Ok(ImageOutputPreview {
        input_path: canonical.to_string_lossy().into_owned(),
        output_path: output.to_string_lossy().into_owned(),
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

#[tauri::command]
async fn open_maintainer_window(app: tauri::AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(require_maintainer_authorization)
        .await
        .map_err(|error| format!("Maintainer permission worker failed: {error}"))??;
    if let Some(window) = app.get_webview_window("maintainer-workspace") {
        window
            .show()
            .map_err(|error| format!("Could not show the maintainer window: {error}"))?;
        window
            .set_focus()
            .map_err(|error| format!("Could not focus the maintainer window: {error}"))?;
        return Ok(());
    }
    let main = app
        .get_webview_window("main")
        .ok_or("The main application window is unavailable.")?;
    let window = tauri::WebviewWindowBuilder::new(
        &app,
        "maintainer-workspace",
        tauri::WebviewUrl::App("maintainer.html".into()),
    )
    .title("SteamOS NVIDIA Builder — Maintainer Workspace")
    .inner_size(900.0, 720.0)
    .min_inner_size(820.0, 640.0)
    .resizable(true)
    .theme(Some(tauri::Theme::Dark))
    .background_color(Color(13, 17, 23, 255))
    .visible(false)
    .parent(&main)
    .map_err(|error| format!("Could not couple the maintainer window: {error}"))?
    .build()
    .map_err(|error| format!("Could not create the maintainer window: {error}"))?;
    window
        .show()
        .map_err(|error| format!("Could not show the maintainer window: {error}"))?;
    window
        .set_focus()
        .map_err(|error| format!("Could not focus the maintainer window: {error}"))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn preserves_reviewed_userspace_filenames_across_guest_handoff() {
        let package = |name: &str, role: &str, filename: &str| NvidiaUserspacePackage {
            name: name.into(),
            role: role.into(),
            filename: filename.into(),
            full_version: "1-1".into(),
            package_path: format!("/host/{filename}"),
            signature_path: format!("/host/{filename}.sig"),
            package_sha256: "a".repeat(64),
        };
        let packages = vec![
            package(
                "nvidia-utils",
                "nvidia-userspace",
                "nvidia-utils-575.64.05-2-x86_64.pkg.tar.zst",
            ),
            package(
                "lib32-nvidia-utils",
                "nvidia-userspace",
                "lib32-nvidia-utils-575.64.05-1-x86_64.pkg.tar.zst",
            ),
            package(
                "egl-wayland",
                "dependency",
                "egl-wayland-4:1.1.19-1-x86_64.pkg.tar.zst",
            ),
        ];
        let arguments = userspace_installer_arguments(&packages)
            .expect("reviewed filenames should produce installer arguments");
        for package in &packages {
            assert!(arguments.contains(&format!("/tmp/{}", package.filename)));
            assert!(arguments.contains(&format!("/tmp/{}.sig", package.filename)));
        }
        assert!(!arguments.contains("dependency-0"));

        let unsafe_package = package("egl-wayland", "dependency", "../egl-wayland.pkg.tar.zst");
        assert!(guest_userspace_filenames(&unsafe_package).is_err());
    }

    #[test]
    fn settings_schema_contains_preferences_but_no_credentials() {
        let serialized = serde_json::to_string(&BuilderSettings {
            schema_version: BUILDER_SETTINGS_SCHEMA,
            auto_release_verified_nvidia: true,
            track_steamos_driver_updates: true,
            include_upstream_nvidia_releases: true,
            omit_optional_cuda: false,
        })
        .unwrap();
        assert!(serialized.contains("autoReleaseVerifiedNvidia"));
        assert!(serialized.contains("trackSteamosDriverUpdates"));
        assert!(serialized.contains("includeUpstreamNvidiaReleases"));
        assert!(serialized.contains("omitOptionalCuda"));
        for forbidden in ["token", "password", "secret", "ssh"] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn appliance_cloud_init_requires_ephemeral_key_authentication() {
        let user_data = include_str!("../../builder/appliance/cloud-init/user-data");
        assert!(user_data.contains("    lock_passwd: true\n"));
        assert!(user_data.contains("ssh_pwauth: false\n"));
        assert!(!user_data.contains("chpasswd:"));
        assert!(!user_data.contains("password: builder"));
        assert!(!user_data.contains("ssh_pwauth: true"));
    }

    #[test]
    fn reads_top_level_github_repository_permission() {
        let response = br#"{
            "permission": "admin",
            "role_name": "admin",
            "user": { "login": "CorniiDog" }
        }"#;
        let permission = parse_github_repository_permission(response).unwrap();
        assert_eq!(permission, "admin");
        assert!(github_permission_can_publish(&permission));
        assert!(github_permission_can_publish("maintain"));
        assert!(github_permission_can_publish("write"));
        assert!(!github_permission_can_publish("triage"));
        assert!(!github_permission_can_publish("read"));
        assert!(parse_github_repository_permission(br#"{"user":{"permission":"admin"}}"#).is_err());
    }

    #[test]
    fn accepts_only_versioned_project_nvidia_branches() {
        assert_eq!(
            valid_nvidia_source_branch("nvidia/575.64.05"),
            Some("575.64.05")
        );
        assert_eq!(valid_nvidia_source_branch("nvidia/610.57"), Some("610.57"));
        for invalid in [
            "main",
            "latest",
            "nvidia/latest",
            "nvidia/575;touch",
            "upstream/575.64.05",
        ] {
            assert!(valid_nvidia_source_branch(invalid).is_none());
        }
        assert!(valid_nvidia_source_identity(
            "project",
            NVIDIA_SOURCE_REPOSITORY,
            "nvidia/575.64.05",
            "575.64.05"
        ));
        assert!(valid_nvidia_source_identity(
            "upstream",
            NVIDIA_UPSTREAM_REPOSITORY,
            "580.159.04",
            "580.159.04"
        ));
        assert!(!valid_nvidia_source_identity(
            "upstream",
            NVIDIA_SOURCE_REPOSITORY,
            "580.159.04",
            "580.159.04"
        ));
    }

    #[test]
    fn maintainer_workspace_accepts_only_confined_git_references() {
        for valid in ["master", "nvidia/575.64.05", "3.16.23.6", "feature_safe-1"] {
            assert!(valid_maintainer_git_reference(valid));
        }
        for invalid in [
            "",
            ".hidden",
            "/absolute",
            "ends/",
            "feature..other",
            "feature//other",
            "feature@{old}",
            "refs.lock",
            "branch with space",
            "branch;touch",
        ] {
            assert!(!valid_maintainer_git_reference(invalid), "{invalid}");
        }
        assert!(valid_git_commit(&"a".repeat(40)));
        assert!(!valid_git_commit(&"a".repeat(39)));
        assert!(!valid_git_commit(&format!("{}g", "a".repeat(39))));
        assert_eq!(GAMESCOPE_SOURCE_REPOSITORY, "CorniiDog/gamescope-nvidia");
        assert_eq!(GAMESCOPE_UPSTREAM_REPOSITORY, "ValveSoftware/gamescope");
    }

    #[test]
    fn explicit_upstream_source_is_pinned_and_never_treated_as_automatic() {
        let target =
            ready_published_target("3.8.14", "6.16.12-valve24.4-1-neptune-616-gfe145653a794");
        let source = NvidiaSourceBranch {
            name: "580.159.04".into(),
            version: "580.159.04".into(),
            commit: "a".repeat(40),
            origin: "upstream".into(),
            repository: NVIDIA_UPSTREAM_REPOSITORY.into(),
            selection: "upstream:580.159.04".into(),
            experimental: true,
        };
        let resolution =
            explicit_nvidia_build_resolution(target, &source, "upstream-tag-580.159.04".into())
                .unwrap();
        assert_eq!(resolution.status, "build_required");
        assert_eq!(
            resolution.compatibility.as_deref(),
            Some("experimental_upstream")
        );
        let plan = resolution.build_plan.unwrap();
        assert_eq!(plan.source_origin, "upstream");
        assert_eq!(plan.source_repository, NVIDIA_UPSTREAM_REPOSITORY);
        assert_eq!(plan.source_branch, "580.159.04");
        assert!(valid_nvidia_source_identity(
            &plan.source_origin,
            &plan.source_repository,
            &plan.source_branch,
            &plan.nvidia_version
        ));
    }

    #[test]
    #[ignore = "queries NVIDIA's official tags and Arch userspace package indexes"]
    fn live_upstream_nvidia_source_preflight() {
        let client = nvidia_http_client().expect("create HTTPS client");
        let tags = fetch_upstream_nvidia_tags(&client).expect("fetch upstream tags");
        assert!(tags.iter().all(|tag| {
            tag.experimental
                && valid_nvidia_source_identity(
                    &tag.origin,
                    &tag.repository,
                    &tag.name,
                    &tag.version,
                )
                && tag.commit.len() == 40
        }));
        let packages =
            preflight_nvidia_userspace(&client, "575.64.05").expect("preflight userspace");
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().all(|package| package.contains("575.64.05")));
    }

    #[test]
    #[ignore = "launches x86_64 Fedora and checks pinned upstream/support repositories over the network"]
    fn live_upstream_nvidia_source_contract_in_x86_appliance() {
        let client = nvidia_http_client().expect("create HTTPS client");
        let source = fetch_upstream_nvidia_tags(&client)
            .expect("fetch upstream tags")
            .into_iter()
            .find(|tag| tag.version == "575.64.05")
            .expect("NVIDIA upstream 575.64.05 tag should remain available");
        let packages =
            preflight_nvidia_userspace(&client, &source.version).expect("preflight userspace");
        assert_eq!(packages.len(), 2);

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
            nvidia_version: source.version.clone(),
        };
        let pin = NvidiaSourcePin {
            origin: &source.origin,
            repository: &source.repository,
            reference: &source.name,
            commit: &source.commit,
        };
        let connection = NvidiaBuildConnection::from(&session);
        let preflight = preflight_nvidia_source_contract(&connection, &pin, &spec);
        let stop_result = stop_nvidia_build_session(&mut session);
        let preflight = preflight.expect("the pinned upstream source contract should pass");
        stop_result.expect("the x86 build appliance should stop cleanly");

        println!(
            "{}",
            serde_json::to_string_pretty(&preflight.plan).expect("serialize support build plan")
        );
        assert_eq!(preflight.source_commit, source.commit.to_ascii_lowercase());
        assert_eq!(preflight.source_reference, "575.64.05");
    }

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
    fn plans_bounded_guest_resources_from_host_capacity() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let native = plan_guest_resources(16 * GIB, 10, false).expect("native plan");
        assert_eq!(native.guest_memory_mib, 4096);
        assert_eq!(native.guest_vcpus, 4);
        assert_eq!(native.workload, "native-inspection");

        let build = plan_guest_resources(32 * GIB, 12, true).expect("build plan");
        assert_eq!(build.guest_memory_mib, 6144);
        assert_eq!(build.guest_vcpus, 6);
        assert_eq!(build.workload, "x86-build-install");

        let constrained = plan_guest_resources(8 * GIB, 2, true).expect("constrained plan");
        assert_eq!(constrained.guest_memory_mib, 4096);
        assert_eq!(constrained.guest_vcpus, 1);
        assert!(plan_guest_resources(4 * GIB, 8, false).is_err());
        assert!(plan_guest_resources(16 * GIB, 0, false).is_err());
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
            "source": {
                "repository": NVIDIA_SOURCE_REPOSITORY,
                "branch": "nvidia/575.64.05",
                "commit": "c".repeat(40),
                "dirty": "0"
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
    fn plans_an_exact_kernel_build_without_reusing_mismatched_modules() {
        let target_kernel = "6.16.12-valve24.4-1-neptune-616-gfe145653a794";
        let published_kernel = "6.16.12-valve24.5-1-neptune-616-gb2f7cfe85e45";
        let releases = vec![
            published_release_fixture("3.8.16", published_kernel, "575.64.05"),
            published_release_fixture("3.9.0", published_kernel, "999.1.1"),
        ];
        let target = ready_published_target("3.8.14", target_kernel);
        assert!(select_published_nvidia_release(&target, &releases)
            .unwrap()
            .is_none());
        let baseline = select_nvidia_build_baseline(&target, &releases)
            .unwrap()
            .unwrap();
        assert_eq!(baseline.steamos_version, "3.8.16");
        assert_eq!(baseline.nvidia_version, "575.64.05");
        assert_eq!(baseline.kernel_version, published_kernel);

        let cancel = AtomicBool::new(false);
        let result = resolve_published_nvidia_for_target(
            target,
            &std::env::temp_dir(),
            &nvidia_http_client().unwrap(),
            &releases,
            &cancel,
            &|_, _, _| {},
        )
        .unwrap();
        assert_eq!(result.status, "build_required");
        assert_eq!(result.reason, "exact_kernel_artifact_missing");
        assert!(result.artifact.is_none());
        let plan = result.build_plan.unwrap();
        assert_eq!(plan.steamos_version, "3.8.14");
        assert_eq!(plan.kernel_version, target_kernel);
        assert_eq!(plan.nvidia_version, "575.64.05");
        assert_eq!(plan.expected_trust, "locally-built-verified");
        assert_eq!(plan.support_commit, NVIDIA_SUPPORT_BUILD_COMMIT);
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
    fn selects_latest_signed_arch_dependency_and_rejects_unsafe_requests() {
        let index = r#"
            <a href="egl-wayland-1.1.9-2-x86_64.pkg.tar.zst">old</a>
            <a href="egl-wayland-1.1.9-2-x86_64.pkg.tar.zst.sig">old signature</a>
            <a href="egl-wayland-1.1.10-1-x86_64.pkg.tar.zst">new</a>
            <a href="egl-wayland-1.1.10-1-x86_64.pkg.tar.zst.sig">new signature</a>
            <a href="egl-wayland-4%3A1.1.21-1-x86_64.pkg.tar.zst">epoch release</a>
            <a href="egl-wayland-4%3A1.1.21-1-x86_64.pkg.tar.zst.sig">epoch signature</a>
            <a href="egl-wayland-99.0-1-x86_64.pkg.tar.zst">unsigned</a>
        "#;
        assert_eq!(
            select_arch_dependency_package(index, "egl-wayland").unwrap(),
            (
                "egl-wayland-4:1.1.21-1-x86_64.pkg.tar.zst".into(),
                "4:1.1.21-1".into()
            )
        );
        assert_eq!(
            arch_dependency_name("egl-wayland>=1.1.0").unwrap(),
            "egl-wayland"
        );
        assert!(arch_dependency_name("../../unsafe>=1").is_err());
        assert!(select_arch_dependency_package(index, "missing").is_err());
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
    #[ignore = "queries and downloads a signed dependency from the live Arch Linux Archive"]
    fn live_arch_dependency_staging() {
        let client = nvidia_http_client().expect("create HTTPS client");
        let staging = std::env::temp_dir().join(format!(
            "steamos-nvidia-egl-wayland-test-{}",
            std::process::id()
        ));
        if staging.exists() {
            fs::remove_dir_all(&staging).expect("remove abandoned dependency fixture");
        }
        fs::create_dir(&staging).expect("create dependency staging fixture");
        let package = stage_arch_dependency_package(
            &staging,
            "egl-wayland",
            &client,
            &AtomicBool::new(false),
            &|_, _, _| {},
        )
        .expect("stage signed egl-wayland dependency");
        assert_eq!(package.name, "egl-wayland");
        assert_eq!(package.role, "dependency");
        assert!(package.filename.contains(':'));
        assert!(package.full_version.contains(':'));
        assert_eq!(package.package_sha256.len(), 64);
        assert!(Path::new(&package.package_path).is_file());
        assert!(Path::new(&package.signature_path).is_file());
        fs::remove_dir_all(staging).expect("clean dependency staging fixture");
    }

    #[test]
    fn pinned_installer_contract_is_safe_and_versioned() {
        assert_eq!(validate_pinned_installer_contract().unwrap(), 221_058);
        assert_eq!(PINNED_INSTALLER_FILES.len(), 15);
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "bootstrap/install_to_root.sh" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/update_grub_nvidia_args.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/measure_btrfs_payload.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/atomic_output.py" && !file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/gaming_payload_profiles.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/verify_installed_modules.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/verify_installed_userspace.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES.iter().any(|file| {
            file.path == "profiles/gaming/reviewed-policy-v1.json" && !file.executable
        }));
        assert!(PINNED_INSTALLER_FILES.iter().any(|file| {
            file.path == "trust/nvidia-userspace-package-signers.json" && !file.executable
        }));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == NVIDIA_USERSPACE_LOCK_PATH && !file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == NVIDIA_USERSPACE_KEYRING_PATH && !file.executable));
        let guest_permissions = pinned_installer_guest_permissions().unwrap();
        assert!(guest_permissions.contains("chmod 0755 "));
        assert!(guest_permissions.contains("\"$WORK/support/lib/measure_btrfs_payload.py\""));
        assert!(guest_permissions.contains("chmod 0644 "));
        assert!(guest_permissions.contains("\"$WORK/support/lib/atomic_output.py\""));
    }

    #[test]
    fn pinned_publisher_contract_is_safe_and_versioned() {
        assert_eq!(validate_pinned_publisher_contract().unwrap(), 19_984);
        assert_eq!(PINNED_PUBLISHER_FILES.len(), 2);
        assert!(PINNED_PUBLISHER_FILES
            .iter()
            .any(|file| file.path == "bootstrap/publish_artifacts.sh" && file.executable));
        assert!(PINNED_PUBLISHER_FILES
            .iter()
            .any(|file| file.path == "lib/validate_publish_inputs.py" && file.executable));
    }

    #[test]
    fn normalizes_verified_checksum_for_fixed_guest_archive_name() {
        let digest = "A".repeat(64);
        assert_eq!(
            nvidia_handoff_checksum(&digest).unwrap(),
            format!("{}  nvidia-modules.tar.gz\n", "a".repeat(64))
        );
        assert!(nvidia_handoff_checksum(&"g".repeat(64)).is_err());
        assert!(nvidia_handoff_checksum("abcd").is_err());
    }

    #[test]
    fn archive_and_space_limits_match_the_pinned_support_contract() {
        assert_eq!(NVIDIA_ARCHIVE_MEMBER_LIMIT, 1024 * 1024 * 1024);
        assert_eq!(NVIDIA_ARCHIVE_EXPANDED_LIMIT, 2 * 1024 * 1024 * 1024);
        assert_eq!(checked_space_sum([1, 2, 3]).unwrap(), 6);
        assert!(checked_space_sum([u64::MAX, 1]).is_err());

        let source = include_str!("lib.rs")
            .split("#[cfg(test)]\n#[allow(clippy::items_after_test_module)]\nmod tests {")
            .next()
            .expect("production source");
        assert!(!source.contains("Could not measure target root free space."));
        assert!(source.contains("validate_nvidia_storage_failure"));
        assert!(source.contains("NVIDIA module archive size changed after validation."));
        assert!(source.contains("--validate-only --compression-profile {compression_profile}"));
        assert!(source.contains("compression.mutation_profile_implemented != Some(true)"));
    }

    #[test]
    fn support_publication_plan_must_match_rust_owned_identity_and_asset_order() {
        let identity = PublishedReleaseIdentity {
            steamos_version: "3.8.14".into(),
            kernel_version: "6.16.12-valve24.4-1-neptune-616-gfe145653a794".into(),
            nvidia_version: "575.64.05".into(),
            tag: "steamos-3.8.14-nvidia-575.64.05-k6.16.12-valve24.4-1-neptune-616-gfe145653a794"
                .into(),
        };
        let assets = [
            "/tmp/nvidia.tar.gz".into(),
            "/tmp/nvidia.tar.gz.sha256".into(),
            "/tmp/nvidia.build-info.txt".into(),
            "/tmp/nvidia.provenance.json".into(),
        ];
        let mut plan = SupportPublicationPlan {
            schema_version: 1,
            status: "ready".into(),
            repository: NVIDIA_SUPPORT_REPOSITORY.into(),
            tag: identity.tag.clone(),
            target_commit: NVIDIA_SUPPORT_BUILD_COMMIT.into(),
            trust: "locally-built-verified".into(),
            archive_sha256: "a".repeat(64),
            assets: assets.to_vec(),
        };
        assert!(
            validate_support_publication_plan(&plan, &identity, &"a".repeat(64), &assets).is_ok()
        );

        plan.assets.swap(0, 1);
        assert!(
            validate_support_publication_plan(&plan, &identity, &"a".repeat(64), &assets).is_err()
        );
        plan.assets.swap(0, 1);
        plan.target_commit = "b".repeat(40);
        assert!(
            validate_support_publication_plan(&plan, &identity, &"a".repeat(64), &assets).is_err()
        );
    }

    #[test]
    fn offline_handoff_mounts_var_and_efi_without_hiding_root_boot() {
        let source = include_str!("lib.rs")
            .split("#[cfg(test)]\n#[allow(clippy::items_after_test_module)]\nmod tests {")
            .next()
            .expect("production source");
        assert_eq!(source.matches("mapfile -t VAR_PARTS").count(), 3);
        assert_eq!(
            source
                .matches(r#"sudo mount -o ro "${{VAR_PARTS[0]}}" "$ROOT/var""#)
                .count(),
            2
        );
        assert_eq!(
            source
                .matches(r#"sudo mount -o rw "${{VAR_PARTS[0]}}" "$ROOT/var""#)
                .count(),
            1
        );
        assert_eq!(
            source
                .matches(r#"if (( VAR_MOUNTED )); then sudo umount "$ROOT/var""#)
                .count(),
            3
        );
        assert_eq!(source.matches("mapfile -t BOOT_PARTS").count(), 3);
        assert_eq!(
            source
                .matches(r#"sudo mount -o ro "${{BOOT_PARTS[0]}}" "$ROOT/efi""#)
                .count(),
            2
        );
        assert_eq!(
            source
                .matches(r#"sudo mount -o rw "${{BOOT_PARTS[0]}}" "$ROOT/efi""#)
                .count(),
            1
        );
        assert_eq!(
            source
                .matches(r#"if (( EFI_MOUNTED )); then sudo umount "$ROOT/efi""#)
                .count(),
            3
        );
        assert!(!source.contains(r#""${{BOOT_PARTS[0]}}" "$ROOT/boot""#));
        assert!(source.contains(r#"validation.pacman_database.path != "/usr/lib/holo/pacmandb""#));
        assert!(
            source.contains(r#"(steamenv_boot[[:space:]]+)?(linux|linuxefi|linux16)[[:space:]]+"#)
        );
    }

    #[test]
    fn accepts_only_exact_offline_installer_validation_results() {
        let digest = |byte: char| byte.to_string().repeat(64);
        fn conservative_compression(storage: &SupportInstallStorage) -> SupportInstallCompression {
            SupportInstallCompression {
                filesystem: "btrfs".into(),
                enabled: false,
                options: Vec::new(),
                admission_basis: "logical-uncompressed-conservative".into(),
                compression_savings_credited_bytes: 0,
                declared_package_bytes: storage.package_installed_bytes,
                package_archive_bytes: storage.package_compressed_bytes,
                package_archive_savings_bytes: storage
                    .package_installed_bytes
                    .saturating_sub(storage.package_compressed_bytes),
                declared_sizes_likely_conservative: false,
                assessment: "informational-package-archive-proxy-not-admission-credit".into(),
                requested_profile: None,
                write_policy: None,
                measurement: None,
                measured_payload_savings_bytes: None,
                admission_authorized: None,
                mutation_profile_implemented: None,
                compression_ratio: None,
                all_payload_destinations_on_root_filesystem: None,
                replacement_credit_policy: None,
                module_payload_noop: None,
            }
        }
        let staged_package =
            |name: &str, release: &str, signer_digest: char| NvidiaUserspacePackage {
                name: name.into(),
                role: "nvidia-userspace".into(),
                filename: format!("{name}-575.64.05-{release}-x86_64.pkg.tar.zst"),
                full_version: format!("575.64.05-{release}"),
                package_path: format!("/{name}.pkg.tar.zst"),
                signature_path: format!("/{name}.pkg.tar.zst.sig"),
                package_sha256: digest(signer_digest),
            };
        let locked_package = |name: &str, release: &str, signer: &str, package_digest: char| {
            let filename = format!("{name}-575.64.05-{release}-x86_64.pkg.tar.zst");
            ReviewedUserspacePackage {
                name: name.into(),
                version: format!("575.64.05-{release}"),
                architecture: "x86_64".into(),
                signature_filename: format!("{filename}.sig"),
                filename,
                package_sha256: digest(package_digest),
                signature_sha256: digest('f'),
                signer_fingerprint: signer.into(),
                installed_size: 1,
                dependencies: Vec::new(),
                provides: Vec::new(),
            }
        };
        let userspace_lock = ReviewedUserspaceLock {
            schema_version: 1,
            status: "reviewed".into(),
            target: ReviewedUserspaceTarget {
                steamos_version: "3.8.14".into(),
                nvidia_version: "575.64.05".into(),
                architecture: "x86_64".into(),
            },
            keyring: ReviewedUserspaceKeyring {
                filename: NVIDIA_USERSPACE_KEYRING_NAME.into(),
                sha256: NVIDIA_USERSPACE_KEYRING_SHA256.into(),
            },
            missing_review: Vec::new(),
            packages: vec![
                locked_package("nvidia-utils", "2", NVIDIA_UTILS_SIGNER, 'b'),
                locked_package("lib32-nvidia-utils", "1", LIB32_NVIDIA_UTILS_SIGNER, 'c'),
            ],
        };
        let inputs = NvidiaInstallInputs {
            image_runtime_dir: "/image-runtime".into(),
            working_image: "/working.qcow2".into(),
            installer_root: "/installer".into(),
            archive: "/modules.tar.gz".into(),
            checksum: "/modules.tar.gz.sha256".into(),
            provenance: "/modules.provenance.json".into(),
            archive_sha256: digest('a'),
            archive_bytes: 700 * 1024 * 1024,
            expanded_bytes: 900 * 1024 * 1024,
            provenance_sha256: digest('e'),
            trust: "certified-published".into(),
            steamos_version: "3.8.14".into(),
            kernel_version: "6.16.12-valve24.4-1-neptune-616-gfe145653a794".into(),
            nvidia_version: "575.64.05".into(),
            packages: vec![
                staged_package("nvidia-utils", "2", 'b'),
                staged_package("lib32-nvidia-utils", "1", 'c'),
            ],
            userspace_lock,
        };
        let validated_package =
            |name: &str, release: &str, signer: &str, signer_digest: char| SupportInstallPackage {
                name: name.into(),
                role: "nvidia-userspace".into(),
                filename: format!("{name}-575.64.05-{release}-x86_64.pkg.tar.zst"),
                signature_filename: format!("{name}-575.64.05-{release}-x86_64.pkg.tar.zst.sig"),
                full_version: format!("575.64.05-{release}"),
                pkgver: "575.64.05".into(),
                pkgrel: release.into(),
                architecture: "x86_64".into(),
                signer: signer.into(),
                sha256: digest(signer_digest),
                signature_sha256: digest('f'),
                installed_size: 1,
                dependencies: Vec::new(),
                provides: Vec::new(),
            };
        let storage = SupportInstallStorage {
            root_available_bytes: 256 * 1024 * 1024,
            root_required_bytes: 128 * 1024 * 1024 + 3_000,
            var_available_bytes: 32 * 1024 * 1024,
            var_required_bytes: 16 * 1024 * 1024,
            efi_available_bytes: 2 * 1024 * 1024,
            efi_required_bytes: 1024 * 1024,
            package_installed_bytes: 1_000,
            package_compressed_bytes: 500,
            package_replaced_bytes: 0,
            module_installed_bytes: 2_000,
            module_replaced_bytes: 0,
            initramfs_reserve_bytes: 64 * 1024 * 1024,
            root_conservative_required_bytes: None,
            root_measured_required_bytes: None,
            root_logical_required_bytes: None,
            measured_payload_allocated_bytes: None,
            compression_payload_allocated_bytes: None,
            compression_filesystem_overhead_bytes: None,
            compression_safety_reserve_bytes: None,
            compression_reserve_bytes: None,
            replacement_candidate_logical_bytes: None,
            replacement_credit_bytes: None,
            package_noop_credit_bytes: None,
            module_noop_credit_bytes: None,
            root_final_margin_bytes: None,
            root_shortfall_bytes: None,
        };
        let compression = conservative_compression(&storage);
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
                compression_policy_restored: true,
            },
            validation: Some(SupportInstallValidationDocument::Verified(Box::new(
                SupportInstallValidation {
                    archive_sha256: digest('a'),
                    provenance_sha256: digest('e'),
                    userspace_lock: SupportInstallPinnedIdentity {
                        name: Path::new(NVIDIA_USERSPACE_LOCK_PATH)
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                        sha256: NVIDIA_USERSPACE_LOCK_SHA256.into(),
                    },
                    pacman_database: SupportInstallPacmanDatabase {
                        path: "/usr/lib/holo/pacmandb".into(),
                        package_count: 1_158,
                    },
                    boot: SupportInstallBoot {
                        rootfs_boot_path: "/boot".into(),
                        efi_mount_path: "/efi".into(),
                        grub_configuration: "/efi/EFI/steamos/grub.cfg".into(),
                        required_kernel_arguments: NVIDIA_REQUIRED_KERNEL_ARGUMENTS
                            .map(str::to_owned)
                            .to_vec(),
                    },
                    keyring: SupportInstallKeyring {
                        name: NVIDIA_USERSPACE_KEYRING_NAME.into(),
                        sha256: NVIDIA_USERSPACE_KEYRING_SHA256.into(),
                    },
                    packages: vec![
                        validated_package("nvidia-utils", "2", NVIDIA_UTILS_SIGNER, 'b'),
                        validated_package(
                            "lib32-nvidia-utils",
                            "1",
                            LIB32_NVIDIA_UTILS_SIGNER,
                            'c',
                        ),
                    ],
                    package_dependency_closure: vec![
                        SupportInstallDependency {
                            name: "nvidia-utils".into(),
                            version: "575.64.05-2".into(),
                            source: "incoming".into(),
                        },
                        SupportInstallDependency {
                            name: "lib32-nvidia-utils".into(),
                            version: "575.64.05-1".into(),
                            source: "incoming".into(),
                        },
                    ],
                    gaming_payload: SupportInstallGamingPayload {
                        schema_version: 1,
                        status: "not-requested".into(),
                        profile_id: "gaming-no-cuda-v1".into(),
                    },
                    compression: compression.clone(),
                    storage: storage.clone(),
                },
            ))),
        };
        fn verified_validation(
            document: &mut SupportInstallResult,
        ) -> &mut SupportInstallValidation {
            match document.validation.as_mut().expect("fixture validation") {
                SupportInstallValidationDocument::Verified(validation) => validation,
                SupportInstallValidationDocument::Failed(_) => panic!("expected verified fixture"),
            }
        }
        let mut wrong_database = result.clone();
        verified_validation(&mut wrong_database)
            .pacman_database
            .path = "/var/lib/pacman".into();
        assert!(validate_nvidia_install_result(
            wrong_database,
            &inputs,
            "validated",
            "validation_complete",
            "validated"
        )
        .is_err());
        let mut empty_database = result.clone();
        verified_validation(&mut empty_database)
            .pacman_database
            .package_count = 0;
        assert!(validate_nvidia_install_result(
            empty_database,
            &inputs,
            "validated",
            "validation_complete",
            "validated"
        )
        .is_err());
        let mut wrong_boot_policy = result.clone();
        verified_validation(&mut wrong_boot_policy)
            .boot
            .required_kernel_arguments[2] = "nvidia-drm.modeset=0".into();
        assert!(validate_nvidia_install_result(
            wrong_boot_policy,
            &inputs,
            "validated",
            "validation_complete",
            "validated"
        )
        .is_err());
        let mut dependency_inputs = inputs.clone();
        dependency_inputs.packages.push(NvidiaUserspacePackage {
            name: "egl-wayland".into(),
            role: "dependency".into(),
            filename: "egl-wayland-4:1.1.19-1-x86_64.pkg.tar.zst".into(),
            full_version: "4:1.1.19-1".into(),
            package_path: "/egl-wayland.pkg.tar.zst".into(),
            signature_path: "/egl-wayland.pkg.tar.zst.sig".into(),
            package_sha256: digest('f'),
        });
        dependency_inputs
            .userspace_lock
            .packages
            .push(ReviewedUserspacePackage {
                name: "egl-wayland".into(),
                version: "4:1.1.19-1".into(),
                architecture: "x86_64".into(),
                filename: "egl-wayland-4:1.1.19-1-x86_64.pkg.tar.zst".into(),
                signature_filename: "egl-wayland-4:1.1.19-1-x86_64.pkg.tar.zst.sig".into(),
                package_sha256: digest('f'),
                signature_sha256: digest('1'),
                signer_fingerprint: "A".repeat(40),
                installed_size: 1,
                dependencies: Vec::new(),
                provides: Vec::new(),
            });
        let mut dependency_result = result.clone();
        let dependency_validation = verified_validation(&mut dependency_result);
        dependency_validation.packages.push(SupportInstallPackage {
            name: "egl-wayland".into(),
            role: "dependency".into(),
            filename: "egl-wayland-4:1.1.19-1-x86_64.pkg.tar.zst".into(),
            signature_filename: "egl-wayland-4:1.1.19-1-x86_64.pkg.tar.zst.sig".into(),
            full_version: "4:1.1.19-1".into(),
            pkgver: "1.1.19".into(),
            pkgrel: "1".into(),
            architecture: "x86_64".into(),
            signer: "A".repeat(40),
            sha256: digest('f'),
            signature_sha256: digest('1'),
            installed_size: 1,
            dependencies: Vec::new(),
            provides: Vec::new(),
        });
        dependency_validation
            .package_dependency_closure
            .push(SupportInstallDependency {
                name: "egl-wayland".into(),
                version: "4:1.1.19-1".into(),
                source: "incoming".into(),
            });
        dependency_validation.storage.package_installed_bytes += 2_048;
        dependency_validation.storage.package_compressed_bytes += 1_024;
        dependency_validation.storage.root_required_bytes += 2_048;
        dependency_validation.compression =
            conservative_compression(&dependency_validation.storage);
        verified_validation(&mut dependency_result)
            .packages
            .swap(0, 2);
        let dependency_accepted = validate_nvidia_install_result(
            dependency_result.clone(),
            &dependency_inputs,
            "validated",
            "validation_complete",
            "validated",
        )
        .expect("the complete reviewed dependency manifest should pass in any order");
        assert_eq!(dependency_accepted.packages.len(), 3);
        verified_validation(&mut dependency_result).packages[0].signer = "B".repeat(40);
        assert!(validate_nvidia_install_result(
            dependency_result,
            &dependency_inputs,
            "validated",
            "validation_complete",
            "validated",
        )
        .is_err());
        let mut measured_result = result.clone();
        let measured_validation = verified_validation(&mut measured_result);
        measured_validation.storage.root_conservative_required_bytes =
            Some(128 * 1024 * 1024 + 3_000);
        measured_validation.storage.root_logical_required_bytes = Some(128 * 1024 * 1024 + 3_000);
        measured_validation.storage.root_measured_required_bytes = Some(128 * 1024 * 1024 + 1_500);
        measured_validation.storage.root_required_bytes = 128 * 1024 * 1024 + 1_500;
        measured_validation.storage.measured_payload_allocated_bytes = Some(1_500);
        measured_validation
            .storage
            .compression_payload_allocated_bytes = Some(1_500);
        measured_validation
            .storage
            .compression_filesystem_overhead_bytes = Some(300);
        measured_validation.storage.compression_safety_reserve_bytes = Some(64 * 1024 * 1024);
        measured_validation.storage.compression_reserve_bytes = Some(128 * 1024 * 1024);
        measured_validation
            .storage
            .replacement_candidate_logical_bytes = Some(0);
        measured_validation.storage.replacement_credit_bytes = Some(0);
        measured_validation.storage.package_noop_credit_bytes = Some(0);
        measured_validation.storage.module_noop_credit_bytes = Some(0);
        measured_validation.storage.root_final_margin_bytes = Some(134_216_228);
        measured_validation.storage.root_shortfall_bytes = Some(0);
        measured_validation.compression = SupportInstallCompression {
            filesystem: "btrfs".into(),
            enabled: false,
            options: Vec::new(),
            admission_basis:
                "scratch-btrfs-allocated-physical-bytes-minus-noop-credit-plus-reserves".into(),
            compression_savings_credited_bytes: 1_500,
            declared_package_bytes: 1_000,
            package_archive_bytes: 500,
            package_archive_savings_bytes: 500,
            declared_sizes_likely_conservative: true,
            assessment: "measured-profile-admission-ready".into(),
            requested_profile: Some(NVIDIA_COMPRESSION_PROFILE.into()),
            write_policy: Some(NVIDIA_COMPRESSION_WRITE_POLICY.into()),
            measurement: Some(SupportInstallCompressionMeasurement {
                schema_version: 1,
                status: "measured".into(),
                profile: NVIDIA_COMPRESSION_PROFILE.into(),
                write_policy: NVIDIA_COMPRESSION_WRITE_POLICY.into(),
                measurement_method: "scratch-btrfs-filesystem-usage-used-delta".into(),
                declared_payload_bytes: 3_000,
                scratch_filesystem_bytes: 2 * 1024 * 1024 * 1024,
                payload_allocated_bytes: 1_500,
                data_allocated_bytes: 1_200,
                metadata_allocated_bytes: 200,
                system_allocated_bytes: 100,
                filesystem_overhead_bytes: 300,
                package_measurements: vec![
                    SupportInstallPackageMeasurement {
                        filename: "nvidia-utils-575.64.05-2-x86_64.pkg.tar.zst".into(),
                        allocated_bytes: 400,
                    },
                    SupportInstallPackageMeasurement {
                        filename: "lib32-nvidia-utils-575.64.05-1-x86_64.pkg.tar.zst".into(),
                        allocated_bytes: 400,
                    },
                ],
                module_allocated_bytes: 700,
            }),
            measured_payload_savings_bytes: Some(1_500),
            admission_authorized: Some(true),
            mutation_profile_implemented: Some(true),
            compression_ratio: Some("0.500000".into()),
            all_payload_destinations_on_root_filesystem: Some(true),
            replacement_credit_policy: Some("exact-payload-noop-only".into()),
            module_payload_noop: Some(false),
        };
        let measured = validate_nvidia_install_result(
            measured_result,
            &inputs,
            "validated",
            "validation_complete",
            "validated",
        )
        .expect("the exact measured Btrfs storage contract should pass");
        assert_eq!(
            measured.compression.requested_profile.as_deref(),
            Some(NVIDIA_COMPRESSION_PROFILE)
        );
        let mut wrong_gaming_payload = result.clone();
        verified_validation(&mut wrong_gaming_payload)
            .gaming_payload
            .status = "applied".into();
        assert!(validate_nvidia_install_result(
            wrong_gaming_payload,
            &inputs,
            "validated",
            "validation_complete",
            "validated",
        )
        .err()
        .expect("an unrequested gaming payload must fail")
        .contains("gaming-payload"));
        let mut unrestored_compression = result.clone();
        unrestored_compression.cleanup.compression_policy_restored = false;
        assert!(validate_nvidia_install_result(
            unrestored_compression,
            &inputs,
            "validated",
            "validation_complete",
            "validated",
        )
        .is_err());
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

        let insufficient_storage = SupportInstallStorage {
            root_available_bytes: 1,
            root_required_bytes: 128 * 1024 * 1024 + 3_000,
            var_available_bytes: 32 * 1024 * 1024,
            var_required_bytes: 16 * 1024 * 1024,
            efi_available_bytes: 2 * 1024 * 1024,
            efi_required_bytes: 1024 * 1024,
            package_installed_bytes: 1_000,
            package_compressed_bytes: 500,
            package_replaced_bytes: 0,
            module_installed_bytes: 2_000,
            module_replaced_bytes: 0,
            initramfs_reserve_bytes: 64 * 1024 * 1024,
            root_conservative_required_bytes: None,
            root_measured_required_bytes: None,
            root_logical_required_bytes: None,
            measured_payload_allocated_bytes: None,
            compression_payload_allocated_bytes: None,
            compression_filesystem_overhead_bytes: None,
            compression_safety_reserve_bytes: None,
            compression_reserve_bytes: None,
            replacement_candidate_logical_bytes: None,
            replacement_credit_bytes: None,
            package_noop_credit_bytes: None,
            module_noop_credit_bytes: None,
            root_final_margin_bytes: None,
            root_shortfall_bytes: None,
        };
        let insufficient_compression = conservative_compression(&insufficient_storage);
        let storage_failure = SupportInstallResult {
            schema_version: 1,
            status: "failed".into(),
            reason: "target_space_insufficient".into(),
            message: "insufficient conservative free space on: root".into(),
            phase: "validation".into(),
            target: SupportInstallTarget {
                steamos_version: "unknown".into(),
                kernel_version: inputs.kernel_version.clone(),
                nvidia_version: "unknown".into(),
                architecture: "x86_64".into(),
            },
            trust: "certified-published".into(),
            cleanup: SupportInstallCleanup {
                mounts_released: true,
                compression_policy_restored: true,
            },
            validation: Some(SupportInstallValidationDocument::Failed(Box::new(
                SupportInstallFailureValidation {
                    storage: Some(insufficient_storage),
                    compression: Some(insufficient_compression),
                    ..Default::default()
                },
            ))),
        };
        let message = validate_nvidia_storage_failure(&storage_failure, &inputs)
            .expect("authoritative storage failure should pass");
        assert!(message.contains("128.0 MiB"));
        assert!(message.contains("shortfall"));
        assert!(message.contains("userspace growth"));

        let mut lock_failure = storage_failure.clone();
        lock_failure.reason = "userspace_lock_mismatch".into();
        lock_failure.message = "The incoming package set differs from the reviewed lock.".into();
        lock_failure.validation = Some(SupportInstallValidationDocument::Failed(Box::new(
            SupportInstallFailureValidation {
                missing_packages: vec!["egl-gbm".into(), "egl-x11".into()],
                unexpected_packages: vec!["placeholder".into()],
                duplicate_packages: vec!["nvidia-utils".into()],
                package_mismatches: vec![SupportInstallPackageMismatch {
                    package_name: "egl-wayland".into(),
                    invalid_fields: vec!["filename".into(), "signatureFilename".into()],
                    expected: HashMap::from([
                        ("filename".into(), serde_json::json!("reviewed.pkg.tar.zst")),
                        (
                            "signatureFilename".into(),
                            serde_json::json!("reviewed.pkg.tar.zst.sig"),
                        ),
                    ]),
                    actual: HashMap::from([
                        ("filename".into(), serde_json::json!("renamed.pkg.tar.zst")),
                        (
                            "signatureFilename".into(),
                            serde_json::json!("renamed.pkg.tar.zst.sig"),
                        ),
                    ]),
                }],
                ..Default::default()
            },
        )));
        let detailed = support_install_failure_message(&lock_failure);
        for required in [
            "egl-gbm",
            "egl-x11",
            "placeholder",
            "nvidia-utils",
            "egl-wayland",
            "filename: expected",
            "signatureFilename: expected",
        ] {
            assert!(detailed.contains(required));
        }

        let mut measurement_failure = storage_failure.clone();
        measurement_failure.reason = "compression_measurement_mount_failed".into();
        measurement_failure.message = "Scratch Btrfs loop mount failed.".into();
        measurement_failure.validation = Some(SupportInstallValidationDocument::Failed(Box::new(
            SupportInstallFailureValidation {
                measurement_failure: Some(SupportInstallMeasurementFailure {
                    phase: "mount".into(),
                    command: Some("mount".into()),
                    exit_status: Some(32),
                    stderr: Some("wrong fs type, bad option, or bad superblock".into()),
                }),
                ..Default::default()
            },
        )));
        let measurement_message = support_install_failure_message(&measurement_failure);
        for required in [
            "measurement phase mount",
            "command mount",
            "exit 32",
            "wrong fs type",
        ] {
            assert!(measurement_message.contains(required));
        }
        if let Some(SupportInstallValidationDocument::Failed(validation)) =
            &mut measurement_failure.validation
        {
            validation
                .measurement_failure
                .as_mut()
                .expect("measurement failure fixture")
                .command = Some("/bin/sh".into());
        }
        assert!(support_install_failure_message(&measurement_failure)
            .contains("measurement diagnostics were malformed"));

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
                compression_policy_restored: true,
            },
            validation: Some(SupportInstallValidationDocument::Verified(Box::new(
                SupportInstallValidation {
                    archive_sha256: digest('a'),
                    provenance_sha256: digest('e'),
                    userspace_lock: SupportInstallPinnedIdentity {
                        name: Path::new(NVIDIA_USERSPACE_LOCK_PATH)
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                        sha256: NVIDIA_USERSPACE_LOCK_SHA256.into(),
                    },
                    pacman_database: SupportInstallPacmanDatabase {
                        path: "/usr/lib/holo/pacmandb".into(),
                        package_count: 1_158,
                    },
                    boot: SupportInstallBoot {
                        rootfs_boot_path: "/boot".into(),
                        efi_mount_path: "/efi".into(),
                        grub_configuration: "/efi/EFI/steamos/grub.cfg".into(),
                        required_kernel_arguments: NVIDIA_REQUIRED_KERNEL_ARGUMENTS
                            .map(str::to_owned)
                            .to_vec(),
                    },
                    keyring: SupportInstallKeyring {
                        name: NVIDIA_USERSPACE_KEYRING_NAME.into(),
                        sha256: NVIDIA_USERSPACE_KEYRING_SHA256.into(),
                    },
                    packages: vec![
                        validated_package("nvidia-utils", "2", LIB32_NVIDIA_UTILS_SIGNER, 'b'),
                        validated_package(
                            "lib32-nvidia-utils",
                            "1",
                            LIB32_NVIDIA_UTILS_SIGNER,
                            'c',
                        ),
                    ],
                    package_dependency_closure: vec![
                        SupportInstallDependency {
                            name: "nvidia-utils".into(),
                            version: "575.64.05-2".into(),
                            source: "incoming".into(),
                        },
                        SupportInstallDependency {
                            name: "lib32-nvidia-utils".into(),
                            version: "575.64.05-1".into(),
                            source: "incoming".into(),
                        },
                    ],
                    gaming_payload: SupportInstallGamingPayload {
                        schema_version: 1,
                        status: "not-requested".into(),
                        profile_id: "gaming-no-cuda-v1".into(),
                    },
                    compression: compression.clone(),
                    storage,
                },
            ))),
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
        let lock = load_reviewed_userspace_lock(&state.root, "3.8.14", "575.64.05")
            .expect("validate reviewed userspace lock and minimal keyring");
        assert_eq!(lock.packages.len(), 6);
        assert!(lock.missing_review.is_empty());
        assert_eq!(state.report.status, "verified");
        assert_eq!(state.report.commit, NVIDIA_INSTALLER_COMMIT);
        assert_eq!(state.report.files.len(), PINNED_INSTALLER_FILES.len());
        assert!(state.root.join("installer-bundle.json").is_file());
        #[cfg(unix)]
        for file in &PINNED_INSTALLER_FILES {
            let mode = fs::symlink_metadata(state.root.join(file.path))
                .expect("inspect pinned installer mode")
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(mode, if file.executable { 0o755 } else { 0o644 });
        }
        let serialized = serde_json::to_string(&state.report).expect("serialize installer report");
        assert!(!serialized.contains(&root.0.to_string_lossy().to_string()));
    }

    #[test]
    #[ignore = "downloads every non-seed package in the reviewed userspace lock"]
    fn live_reviewed_nvidia_userspace_dependencies() {
        struct TestDirectory(PathBuf);
        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = TestDirectory(std::env::temp_dir().join(format!(
            "steamos-builder-reviewed-userspace-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        )));
        fs::create_dir(&root.0).expect("create reviewed userspace test directory");
        let cancel = AtomicBool::new(false);
        let client = nvidia_http_client().expect("create HTTPS client");
        let state =
            prepare_pinned_nvidia_installer_bundle(&root.0, &client, &cancel, &|_, _, _| {})
                .expect("download pinned installer bundle");
        let lock = load_reviewed_userspace_lock(&state.root, "3.8.14", "575.64.05")
            .expect("load reviewed userspace lock");
        let dependencies: Vec<_> = lock
            .packages
            .iter()
            .filter(|package| {
                !matches!(package.name.as_str(), "nvidia-utils" | "lib32-nvidia-utils")
            })
            .collect();
        assert_eq!(dependencies.len(), 4);
        for package in dependencies {
            let directory = arch_dependency_directory(&package.name).expect("archive directory");
            let package_path = root.0.join(&package.filename);
            let signature_path = root.0.join(&package.signature_filename);
            let package_sha256 = download_arch_userspace_asset(
                &client,
                &format!("{directory}/{}", package.filename),
                &package_path,
                NVIDIA_DEPENDENCY_ARCHIVE_LIMIT,
                &cancel,
                "test-package",
                &|_, _, _| {},
            )
            .expect("download reviewed dependency");
            let signature_sha256 = download_arch_userspace_asset(
                &client,
                &format!("{directory}/{}", package.signature_filename),
                &signature_path,
                ARCH_PACKAGE_SIGNATURE_LIMIT,
                &cancel,
                "test-signature",
                &|_, _, _| {},
            )
            .expect("download reviewed dependency signature");
            assert_eq!(package_sha256, package.package_sha256);
            assert_eq!(signature_sha256, package.signature_sha256);
        }
    }

    #[test]
    #[ignore = "downloads and verifies the immutable support publisher snapshot"]
    fn live_pinned_nvidia_publisher() {
        struct TestDirectory(PathBuf);
        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = TestDirectory(std::env::temp_dir().join(format!(
            "steamos-builder-pinned-publisher-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        )));
        fs::create_dir(&root.0).expect("create pinned publisher test directory");
        let publisher_root =
            prepare_pinned_nvidia_publisher(&root.0).expect("download pinned publisher");
        validate_staged_pinned_files(&publisher_root, &PINNED_PUBLISHER_FILES)
            .expect("validate staged publisher");
        assert!(publisher_root
            .join("bootstrap/publish_artifacts.sh")
            .is_file());
        assert!(publisher_root
            .join("lib/validate_publish_inputs.py")
            .is_file());
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
        assert_eq!(
            output_path_for_input(&root.join("Steam Deck 🐧 recovery.img.xz"), true).unwrap(),
            root.join("Steam Deck 🐧 recovery-nvidia.img")
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
    fn rejects_unsafe_or_unavailable_output_destinations() {
        let root = std::env::temp_dir().join(format!(
            "steamos-builder-output-safety-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("create output-safety test directory");
        let input = root.join("input.img");
        let output = root.join("output.img");
        fs::write(&input, b"input").expect("create output-safety input");
        assert!(validate_output_destination(&input, &output, 1).is_ok());
        assert!(host_available_bytes(&root).expect("measure temporary volume") > 0);
        assert!(validate_output_destination(&input, &input, 0)
            .expect_err("input/output alias must fail")
            .contains("selected input"));
        fs::write(&output, b"occupied").expect("create occupied output");
        assert!(validate_output_destination(&input, &output, 0)
            .expect_err("existing output must fail")
            .contains("already exists"));
        #[cfg(unix)]
        assert!(
            validate_output_destination(&input, Path::new("/dev/null"), 0)
                .expect_err("device output must fail")
                .contains("device node")
        );
        assert!(
            validate_output_destination(&input, &root.join("too-large.img"), u64::MAX)
                .expect_err("impossible capacity request must fail")
                .contains("needs at least")
        );
        fs::remove_dir_all(root).expect("remove output-safety test directory");
    }

    #[test]
    fn parses_qemu_img_percentage_output() {
        assert_eq!(parse_qemu_img_progress("    (42.50/100%)"), Some(42.5));
        assert_eq!(parse_qemu_img_progress("not progress"), None);
    }

    #[test]
    fn bounds_normalized_image_writes() {
        let mut exact = BoundedWriter {
            inner: Vec::new(),
            written: 0,
            limit: 4,
        };
        exact.write_all(b"test").expect("write exact limit");
        assert!(exact.write_all(b"!").is_err());
        assert_eq!(exact.inner, b"test");

        let mut oversized = BoundedWriter {
            inner: Vec::new(),
            written: 0,
            limit: 3,
        };
        assert!(oversized.write_all(b"test").is_err());
        assert_eq!(oversized.inner, b"tes");
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
            nvidia_resolution: None,
            nvidia_source_selection: None,
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
            provenance_sha256: "c".repeat(64),
            pacman_database_path: "/usr/lib/holo/pacmandb".into(),
            pacman_package_count: 1_158,
            rootfs_boot_path: "/boot".into(),
            efi_mount_path: "/efi".into(),
            grub_configuration: "/efi/EFI/steamos/grub.cfg".into(),
            required_kernel_arguments: NVIDIA_REQUIRED_KERNEL_ARGUMENTS.map(str::to_owned).to_vec(),
            keyring_sha256: "b".repeat(64),
            packages: Vec::new(),
            storage: SupportInstallStorage {
                root_available_bytes: 256 * 1024 * 1024,
                root_required_bytes: 128 * 1024 * 1024 + 3_000,
                var_available_bytes: 32 * 1024 * 1024,
                var_required_bytes: 16 * 1024 * 1024,
                efi_available_bytes: 2 * 1024 * 1024,
                efi_required_bytes: 1024 * 1024,
                package_installed_bytes: 1_000,
                package_compressed_bytes: 500,
                package_replaced_bytes: 0,
                module_installed_bytes: 2_000,
                module_replaced_bytes: 0,
                initramfs_reserve_bytes: 64 * 1024 * 1024,
                root_conservative_required_bytes: None,
                root_measured_required_bytes: None,
                root_logical_required_bytes: None,
                measured_payload_allocated_bytes: None,
                compression_payload_allocated_bytes: None,
                compression_filesystem_overhead_bytes: None,
                compression_safety_reserve_bytes: None,
                compression_reserve_bytes: None,
                replacement_candidate_logical_bytes: None,
                replacement_credit_bytes: None,
                package_noop_credit_bytes: None,
                module_noop_credit_bytes: None,
                root_final_margin_bytes: None,
                root_shortfall_bytes: None,
            },
            compression: SupportInstallCompression {
                filesystem: "btrfs".into(),
                enabled: false,
                options: Vec::new(),
                admission_basis: "logical-uncompressed-conservative".into(),
                compression_savings_credited_bytes: 0,
                declared_package_bytes: 1_000,
                package_archive_bytes: 500,
                package_archive_savings_bytes: 500,
                declared_sizes_likely_conservative: false,
                assessment: "informational-package-archive-proxy-not-admission-credit".into(),
                requested_profile: None,
                write_policy: None,
                measurement: None,
                measured_payload_savings_bytes: None,
                admission_authorized: None,
                mutation_profile_implemented: None,
                compression_ratio: None,
                all_payload_destinations_on_root_filesystem: None,
                replacement_credit_policy: None,
                module_payload_noop: None,
            },
            mounts_released: true,
            compression_policy_restored: true,
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
            nvidia_resolution: None,
            nvidia_source_selection: Some("project:nvidia/575.64.05"),
        });
        assert_eq!(nvidia_manifest["resultClass"], "nvidia-mutation-valid");
        assert_eq!(
            nvidia_manifest["integration"]["nvidia"]["nvidiaVersion"],
            "575.64.05"
        );
        assert_eq!(nvidia_manifest["validation"]["nvidiaPayloadVerified"], true);
        assert_eq!(
            nvidia_manifest["integration"]["nvidiaSourcePolicy"]["mode"],
            "pinned"
        );
        assert_eq!(
            nvidia_manifest["integration"]["nvidiaSourcePolicy"]["updateBehavior"],
            "rebuild-exact-version-or-require-user-decision"
        );
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
        qmp_attach_nvidia_target(&session)
            .expect("hotplug the handoff device after Fedora readiness");
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
    fn live_recovery_package_database_layout_report() {
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
        let report = run_guest_command(
            &session,
            r#"set -euo pipefail
DISK=/dev/disk/by-id/virtio-steamos-user-input
ROOT=/mnt/steamos-package-root
VAR=/mnt/steamos-package-var
EFI=/mnt/steamos-package-efi
mapfile -t ROOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$DISK" | awk '$2 == "rootfs-A" && $3 == "btrfs" {print $1}')
mapfile -t VAR_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$DISK" | awk '$2 == "var-A" && $3 == "ext4" {print $1}')
mapfile -t EFI_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$DISK" | awk '$2 == "efi-A" && ($3 == "vfat" || $3 == "fat") {print $1}')
test "${#ROOT_PARTS[@]}" -eq 1
test "${#VAR_PARTS[@]}" -eq 1
test "${#EFI_PARTS[@]}" -eq 1
sudo mkdir -p "$ROOT" "$VAR" "$EFI"
ROOT_MOUNTED=0
VAR_MOUNTED=0
EFI_MOUNTED=0
cleanup() {
  rc=$?
  if (( EFI_MOUNTED )); then sudo umount "$EFI" || rc=1; fi
  if (( VAR_MOUNTED )); then sudo umount "$VAR" || rc=1; fi
  if (( ROOT_MOUNTED )); then sudo umount "$ROOT" || rc=1; fi
  exit "$rc"
}
trap cleanup EXIT
sudo mount -o ro "${ROOT_PARTS[0]}" "$ROOT"
ROOT_MOUNTED=1
sudo mount -o ro "${VAR_PARTS[0]}" "$VAR"
VAR_MOUNTED=1
sudo mount -o ro "${EFI_PARTS[0]}" "$EFI"
EFI_MOUNTED=1
root_db=absent
var_db=absent
holo_db=absent
test -d "$ROOT/var/lib/pacman" && root_db=present
test -d "$VAR/lib/pacman" && var_db=present
test -d "$ROOT/usr/lib/holo/pacmandb/local" && holo_db=present
root_local=0
var_local=0
holo_local=0
test ! -d "$ROOT/var/lib/pacman/local" || root_local=$(sudo find "$ROOT/var/lib/pacman/local" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
test ! -d "$VAR/lib/pacman/local" || var_local=$(sudo find "$VAR/lib/pacman/local" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
test ! -d "$ROOT/usr/lib/holo/pacmandb/local" || holo_local=$(sudo find "$ROOT/usr/lib/holo/pacmandb/local" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
printf 'root_pacman_db=%s\n' "$root_db"
printf 'root_local_packages=%s\n' "$root_local"
printf 'var_pacman_db=%s\n' "$var_db"
printf 'var_local_packages=%s\n' "$var_local"
printf 'holo_pacman_db=%s\n' "$holo_db"
printf 'holo_local_packages=%s\n' "$holo_local"
printf '%s\n' '--- root /etc/fstab ---'
if test -f "$ROOT/etc/fstab"; then sudo sed -n '1,120p' "$ROOT/etc/fstab"; else printf '%s\n' '<absent>'; fi
printf '%s\n' '--- var-A top-level ---'
sudo find "$VAR" -mindepth 1 -maxdepth 2 -printf '%P\n' | LC_ALL=C sort | head -120
printf '%s\n' '--- root /boot ---'
sudo find "$ROOT/boot" -mindepth 1 -maxdepth 2 -printf '%P\n' | LC_ALL=C sort | head -120
printf '%s\n' '--- efi-A top-level ---'
sudo find "$EFI" -mindepth 1 -maxdepth 3 -printf '%P\n' | LC_ALL=C sort | head -160
printf '%s\n' '--- efi-A SteamOS GRUB configuration ---'
if test -f "$EFI/EFI/steamos/grub.cfg"; then sudo sed -n '1,240p' "$EFI/EFI/steamos/grub.cfg"; else printf '%s\n' '<absent>'; fi
sudo umount "$EFI"
EFI_MOUNTED=0
sudo umount "$VAR"
VAR_MOUNTED=0
sudo umount "$ROOT"
ROOT_MOUNTED=0
trap - EXIT"#,
        )
        .expect("read-only package database layout inspection should pass");
        println!("{report}");
        assert!(report.contains("root_pacman_db=absent"));
        assert!(report.contains("var_pacman_db=absent"));
        assert!(report.contains("holo_pacman_db=present"));
        assert!(report.contains("lib/overlays"));
        assert!(report.contains("EFI/steamos/grub.cfg"));
        assert!(report.contains("steamenv_boot\tlinux /boot/vmlinuz-linux-neptune-616"));
        stop_session(&mut session).expect("stop recovery-image appliance session");
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
            get_builder_settings,
            update_builder_settings,
            get_github_maintainer_status,
            connect_github_maintainer,
            list_nvidia_source_branches,
            list_maintainer_workspace_sources,
            plan_maintainer_workspace,
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
            build_nvidia_target_on_demand,
            publish_on_demand_nvidia_release,
            validate_nvidia_install_handoff,
            install_nvidia_to_working_image,
            export_marker_image,
            stop_appliance,
            stop_nvidia_build_appliance,
            validate_image,
            preview_image_output,
            open_progress_window,
            open_maintainer_window,
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

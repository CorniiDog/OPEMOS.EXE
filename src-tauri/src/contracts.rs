use super::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BuilderSettings {
    pub(crate) schema_version: u32,
    pub(crate) auto_release_verified_nvidia: bool,
    pub(crate) track_steamos_driver_updates: bool,
    #[serde(default)]
    pub(crate) include_upstream_nvidia_releases: bool,
    #[serde(default)]
    pub(crate) omit_optional_cuda: bool,
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
pub(crate) struct GithubMaintainerStatus {
    pub(crate) gh_available: bool,
    pub(crate) authenticated: bool,
    pub(crate) authorized: bool,
    pub(crate) username: Option<String>,
    pub(crate) permission: Option<String>,
    pub(crate) message: String,
}

#[derive(Deserialize)]
pub(crate) struct GithubRepositoryPermission {
    pub(crate) permission: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaReleasePublication {
    pub(crate) status: String,
    pub(crate) repository: String,
    pub(crate) tag: String,
    pub(crate) url: String,
    pub(crate) message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportPublicationPlan {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) repository: String,
    pub(crate) tag: String,
    pub(crate) target_commit: String,
    pub(crate) trust: String,
    pub(crate) archive_sha256: String,
    pub(crate) assets: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct GithubBranchCommit {
    pub(crate) sha: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct GithubBranch {
    pub(crate) name: String,
    pub(crate) commit: GithubBranchCommit,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaSourceBranch {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) commit: String,
    pub(crate) origin: String,
    pub(crate) repository: String,
    pub(crate) selection: String,
    pub(crate) experimental: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MaintainerWorkspaceSource {
    pub(crate) component: String,
    pub(crate) origin: String,
    pub(crate) repository: String,
    pub(crate) reference: String,
    pub(crate) commit: String,
    pub(crate) label: String,
    pub(crate) experimental: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MaintainerWorkspacePlan {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) plan_id: String,
    pub(crate) component: String,
    pub(crate) origin: String,
    pub(crate) repository: String,
    pub(crate) reference: String,
    pub(crate) commit: String,
    pub(crate) architecture: String,
    pub(crate) isolation: String,
    pub(crate) maintainer: String,
    pub(crate) permission: String,
    pub(crate) remote_mutation_allowed: bool,
    pub(crate) message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MaintainerLocalWorktree {
    pub(crate) path: String,
    pub(crate) repository: String,
    pub(crate) head: String,
    pub(crate) branch: Option<String>,
    pub(crate) changed_files: usize,
    pub(crate) vscode_available: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MaintainerCommitReview {
    pub(crate) repository: String,
    pub(crate) path: String,
    pub(crate) branch: String,
    pub(crate) head: String,
    pub(crate) index_tree: String,
    pub(crate) staged_paths: Vec<String>,
    pub(crate) patch_sha256: String,
    pub(crate) patch_preview: String,
    pub(crate) message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MaintainerLocalCommit {
    pub(crate) repository: String,
    pub(crate) path: String,
    pub(crate) branch: String,
    pub(crate) previous_head: String,
    pub(crate) commit: String,
    pub(crate) index_tree: String,
    pub(crate) pushed: bool,
    pub(crate) message: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MaintainerLocalBranch {
    pub(crate) name: String,
    pub(crate) commit: String,
    pub(crate) current: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MaintainerCheckoutReview {
    pub(crate) repository: String,
    pub(crate) path: String,
    pub(crate) current_branch: String,
    pub(crate) current_head: String,
    pub(crate) target_branch: String,
    pub(crate) target_commit: String,
    pub(crate) message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MaintainerCheckoutResult {
    pub(crate) repository: String,
    pub(crate) path: String,
    pub(crate) previous_branch: String,
    pub(crate) previous_head: String,
    pub(crate) branch: String,
    pub(crate) head: String,
    pub(crate) remote_changed: bool,
    pub(crate) message: String,
}

pub(crate) struct PinnedInstallerFile {
    pub(crate) path: &'static str,
    pub(crate) sha256: &'static str,
    pub(crate) bytes: u64,
    pub(crate) executable: bool,
}

pub(crate) const PINNED_INSTALLER_FILES: [PinnedInstallerFile; 16] = [
    PinnedInstallerFile {
        path: "bootstrap/install_to_root.sh",
        sha256: "59d87712273f8e5cfe1ace75dfcd8f363b9d362531da1a463b29bc5c89fabe75",
        bytes: 31_314,
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
        sha256: "ae98ef5072308a8186dffda3249b41e2849d637877dea79b39895b6570ae9863",
        bytes: 85_059,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/write_install_result.py",
        sha256: "03a1bb88d15f72083ba14a7d183274a2dcd383faac24f781020d39c23ae2d1b1",
        bytes: 33_992,
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
        path: "lib/prepare_pacman_config.py",
        sha256: "60c20abd7444a07ef191bd6ef5fe7c7863fd9a89328fcf507f1f2a3558982f64",
        bytes: 2_962,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/gaming_payload_profiles.py",
        sha256: "ed0e54389a648ef6bafed62cf799254a460de1c5c54ddf1409beea9167455eeb",
        bytes: 6_066,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/verify_installed_modules.py",
        sha256: "d1da199092b285a4bab439c96c784fb3bdc09f059ec309189f5d4091c8396ccb",
        bytes: 10_895,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/verify_installed_userspace.py",
        sha256: "bcc62b683e893ec2586d3bedcb81b8f2c71c14a349827d5857a72d7aa87302ae",
        bytes: 12_053,
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

pub(crate) const PINNED_PUBLISHER_FILES: [PinnedInstallerFile; 2] = [
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
pub(crate) struct ImageInfo {
    pub(crate) path: String,
    pub(crate) name: String,
}

#[derive(Serialize)]
pub(crate) struct ImageOutputPreview {
    pub(crate) input_path: String,
    pub(crate) output_path: String,
}

#[derive(Serialize)]
pub(crate) struct BuilderEnvironment {
    pub(crate) ready: bool,
    pub(crate) host_os: String,
    pub(crate) host_arch: String,
    pub(crate) qemu_binary: Option<String>,
    pub(crate) qemu_version: Option<String>,
    pub(crate) qemu_launch_test: bool,
    pub(crate) message: String,
    pub(crate) appliance_present: bool,
    pub(crate) appliance_path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaBuildEnvironment {
    pub(crate) ready: bool,
    pub(crate) host_arch: String,
    pub(crate) guest_arch: String,
    pub(crate) acceleration: String,
    pub(crate) qemu_binary: Option<String>,
    pub(crate) qemu_version: Option<String>,
    pub(crate) qemu_launch_test: bool,
    pub(crate) appliance_present: bool,
    pub(crate) appliance_path: String,
    pub(crate) message: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaBuildStatus {
    pub(crate) state: String,
    pub(crate) message: String,
    pub(crate) architecture: String,
    pub(crate) acceleration: String,
    pub(crate) ssh_port: Option<u16>,
    pub(crate) runtime_path: Option<String>,
}

#[derive(Clone)]
pub(crate) struct NvidiaTargetBuildSpec {
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaDevelopmentArtifact {
    pub(crate) archive_path: String,
    pub(crate) checksum_path: String,
    pub(crate) build_info_path: String,
    pub(crate) provenance_path: String,
    pub(crate) result_path: String,
    pub(crate) archive_sha256: String,
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) trust: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportBuildResult {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) reason: String,
    pub(crate) message: String,
    pub(crate) trust: String,
    pub(crate) target: SupportBuildTarget,
    pub(crate) artifact: Option<SupportBuildArtifact>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportBuildTarget {
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) architecture: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportBuildArtifact {
    pub(crate) archive: String,
    pub(crate) checksum: String,
    pub(crate) build_info: String,
    pub(crate) provenance: String,
    pub(crate) sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportBuildProvenance {
    pub(crate) schema_version: u32,
    pub(crate) trust: String,
    pub(crate) target: SupportBuildTarget,
    pub(crate) artifact: SupportProvenanceArtifact,
    pub(crate) source: SupportProvenanceSource,
    pub(crate) headers: SupportProvenanceHeaders,
    pub(crate) modules: Vec<SupportProvenanceModule>,
}

#[derive(Deserialize)]
pub(crate) struct SupportProvenanceArtifact {
    pub(crate) archive: String,
}

#[derive(Deserialize)]
pub(crate) struct SupportProvenanceSource {
    pub(crate) repository: String,
    pub(crate) branch: String,
    pub(crate) commit: String,
    pub(crate) dirty: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportProvenanceHeaders {
    pub(crate) signature_status: String,
    pub(crate) signing_key_fingerprint: String,
    pub(crate) primary_key_fingerprint: String,
    pub(crate) authentication: String,
}

#[derive(Deserialize)]
pub(crate) struct SupportProvenanceModule {
    pub(crate) name: String,
    pub(crate) sha256: String,
    pub(crate) version: String,
    pub(crate) architecture: String,
    pub(crate) vermagic: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ValveTrustManifest {
    pub(crate) schema_version: u32,
    pub(crate) signers: Vec<ValveTrustSigner>,
}

#[derive(Deserialize)]
pub(crate) struct ValveTrustSigner {
    pub(crate) fingerprint: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaTargetReadiness {
    pub(crate) ready: bool,
    pub(crate) status: String,
    pub(crate) message: String,
    pub(crate) steamos_version: Option<String>,
    pub(crate) kernel_version: Option<String>,
    pub(crate) architecture: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct GithubRelease {
    pub(crate) tag_name: String,
    pub(crate) draft: bool,
    pub(crate) prerelease: bool,
    pub(crate) published_at: Option<String>,
    pub(crate) assets: Vec<GithubReleaseAsset>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct GithubReleaseAsset {
    pub(crate) name: String,
    pub(crate) browser_download_url: String,
    pub(crate) size: u64,
    pub(crate) digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublishedReleaseIdentity {
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) tag: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaPublishedPublication {
    pub(crate) tag: String,
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) published_at: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaPublishedArtifact {
    pub(crate) archive_path: String,
    pub(crate) checksum_path: String,
    pub(crate) build_info_path: Option<String>,
    pub(crate) provenance_path: String,
    pub(crate) archive_sha256: String,
    pub(crate) archive_bytes: u64,
    pub(crate) expanded_bytes: u64,
    pub(crate) trust: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaOnDemandBuildPlan {
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) baseline_release: String,
    pub(crate) support_commit: String,
    pub(crate) expected_trust: String,
    pub(crate) source_origin: String,
    pub(crate) source_repository: String,
    pub(crate) source_branch: String,
    pub(crate) source_commit: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaPublishedResolution {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) reason: String,
    pub(crate) message: String,
    pub(crate) compatibility: Option<String>,
    pub(crate) target: NvidiaTargetReadiness,
    pub(crate) publication: Option<NvidiaPublishedPublication>,
    pub(crate) artifact: Option<NvidiaPublishedArtifact>,
    pub(crate) build_plan: Option<NvidiaOnDemandBuildPlan>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaUserspacePackage {
    pub(crate) name: String,
    pub(crate) role: String,
    pub(crate) filename: String,
    pub(crate) full_version: String,
    pub(crate) package_path: String,
    pub(crate) signature_path: String,
    pub(crate) package_sha256: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaUserspaceResolution {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) reason: String,
    pub(crate) message: String,
    pub(crate) nvidia_version: String,
    pub(crate) signature_status: String,
    pub(crate) packages: Vec<NvidiaUserspacePackage>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewedUserspaceLock {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) target: ReviewedUserspaceTarget,
    pub(crate) keyring: ReviewedUserspaceKeyring,
    pub(crate) missing_review: Vec<String>,
    pub(crate) packages: Vec<ReviewedUserspacePackage>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewedUserspaceTarget {
    pub(crate) steamos_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) architecture: String,
}

#[derive(Clone, Deserialize)]
pub(crate) struct ReviewedUserspaceKeyring {
    pub(crate) filename: String,
    pub(crate) sha256: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewedUserspacePackage {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) architecture: String,
    pub(crate) filename: String,
    pub(crate) signature_filename: String,
    pub(crate) package_sha256: String,
    pub(crate) signature_sha256: String,
    pub(crate) signer_fingerprint: String,
    pub(crate) installed_size: u64,
    pub(crate) dependencies: Vec<String>,
    pub(crate) provides: Vec<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaInstallerBundleFile {
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
    pub(crate) executable: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaInstallerBundle {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) reason: String,
    pub(crate) message: String,
    pub(crate) repository: String,
    pub(crate) commit: String,
    pub(crate) files: Vec<NvidiaInstallerBundleFile>,
}

#[derive(Clone)]
pub(crate) struct NvidiaInstallerBundleState {
    pub(crate) root: PathBuf,
    pub(crate) report: NvidiaInstallerBundle,
}

#[derive(Clone)]
pub(crate) struct NvidiaInstallInputs {
    pub(crate) image_runtime_dir: PathBuf,
    pub(crate) working_image: PathBuf,
    pub(crate) installer_root: PathBuf,
    pub(crate) archive: PathBuf,
    pub(crate) checksum: PathBuf,
    pub(crate) provenance: PathBuf,
    pub(crate) archive_sha256: String,
    pub(crate) archive_bytes: u64,
    pub(crate) expanded_bytes: u64,
    pub(crate) provenance_sha256: String,
    pub(crate) trust: String,
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) packages: Vec<NvidiaUserspacePackage>,
    pub(crate) userspace_lock: ReviewedUserspaceLock,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallResult {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) reason: String,
    pub(crate) message: String,
    pub(crate) phase: String,
    pub(crate) target: SupportInstallTarget,
    pub(crate) trust: String,
    pub(crate) cleanup: SupportInstallCleanup,
    pub(crate) validation: Option<SupportInstallValidationDocument>,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum SupportInstallValidationDocument {
    Verified(Box<SupportInstallValidation>),
    Failed(Box<SupportInstallFailureValidation>),
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallTarget {
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) architecture: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallCleanup {
    pub(crate) mounts_released: bool,
    pub(crate) compression_policy_restored: bool,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SupportInstallGamingPayload {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) profile_id: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallValidation {
    pub(crate) archive_sha256: String,
    pub(crate) provenance_sha256: String,
    pub(crate) userspace_lock: SupportInstallPinnedIdentity,
    pub(crate) pacman_database: SupportInstallPacmanDatabase,
    pub(crate) boot: SupportInstallBoot,
    pub(crate) keyring: SupportInstallKeyring,
    pub(crate) packages: Vec<SupportInstallPackage>,
    pub(crate) package_dependency_closure: Vec<SupportInstallDependency>,
    pub(crate) gaming_payload: SupportInstallGamingPayload,
    pub(crate) compression: SupportInstallCompression,
    pub(crate) storage: SupportInstallStorage,
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallFailureValidation {
    #[serde(default)]
    pub(crate) storage: Option<SupportInstallStorage>,
    #[serde(default)]
    pub(crate) compression: Option<SupportInstallCompression>,
    #[serde(default)]
    pub(crate) missing_dependencies: Vec<String>,
    #[serde(default)]
    pub(crate) dependency_requested_by: Option<String>,
    #[serde(default)]
    pub(crate) package_name: Option<String>,
    #[serde(default)]
    pub(crate) signer_fingerprint: Option<String>,
    #[serde(default)]
    pub(crate) missing_packages: Vec<String>,
    #[serde(default)]
    pub(crate) unexpected_packages: Vec<String>,
    #[serde(default)]
    pub(crate) duplicate_packages: Vec<String>,
    #[serde(default)]
    pub(crate) package_mismatches: Vec<SupportInstallPackageMismatch>,
    #[serde(default)]
    pub(crate) package_record: Option<String>,
    #[serde(default)]
    pub(crate) invalid_fields: Vec<String>,
    #[serde(default)]
    pub(crate) measurement_failure: Option<SupportInstallMeasurementFailure>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SupportInstallMeasurementFailure {
    pub(crate) phase: String,
    pub(crate) command: Option<String>,
    pub(crate) exit_status: Option<i16>,
    pub(crate) stderr: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallPackageMismatch {
    pub(crate) package_name: String,
    pub(crate) invalid_fields: Vec<String>,
    pub(crate) expected: HashMap<String, serde_json::Value>,
    pub(crate) actual: HashMap<String, serde_json::Value>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallStorage {
    pub(crate) root_available_bytes: u64,
    pub(crate) root_required_bytes: u64,
    pub(crate) var_available_bytes: u64,
    pub(crate) var_required_bytes: u64,
    pub(crate) efi_available_bytes: u64,
    pub(crate) efi_required_bytes: u64,
    pub(crate) package_installed_bytes: u64,
    pub(crate) package_compressed_bytes: u64,
    pub(crate) package_replaced_bytes: u64,
    pub(crate) module_installed_bytes: u64,
    pub(crate) module_replaced_bytes: u64,
    pub(crate) initramfs_reserve_bytes: u64,
    #[serde(default)]
    pub(crate) root_conservative_required_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) root_measured_required_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) root_logical_required_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) measured_payload_allocated_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) compression_payload_allocated_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) compression_filesystem_overhead_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) compression_safety_reserve_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) compression_reserve_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) replacement_candidate_logical_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) replacement_credit_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) package_noop_credit_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) module_noop_credit_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) root_final_margin_bytes: Option<i64>,
    #[serde(default)]
    pub(crate) root_shortfall_bytes: Option<u64>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallPinnedIdentity {
    pub(crate) name: String,
    pub(crate) sha256: String,
}

#[derive(Clone, Deserialize)]
pub(crate) struct SupportInstallDependency {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) source: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallCompressionMeasurement {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) profile: String,
    pub(crate) write_policy: String,
    pub(crate) measurement_method: String,
    pub(crate) declared_payload_bytes: u64,
    pub(crate) scratch_filesystem_bytes: u64,
    pub(crate) payload_allocated_bytes: u64,
    pub(crate) data_allocated_bytes: u64,
    pub(crate) metadata_allocated_bytes: u64,
    pub(crate) system_allocated_bytes: u64,
    pub(crate) filesystem_overhead_bytes: u64,
    pub(crate) package_measurements: Vec<SupportInstallPackageMeasurement>,
    pub(crate) module_allocated_bytes: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallPackageMeasurement {
    pub(crate) filename: String,
    pub(crate) allocated_bytes: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallCompression {
    pub(crate) filesystem: String,
    pub(crate) enabled: bool,
    pub(crate) options: Vec<String>,
    pub(crate) admission_basis: String,
    pub(crate) compression_savings_credited_bytes: u64,
    pub(crate) declared_package_bytes: u64,
    pub(crate) package_archive_bytes: u64,
    pub(crate) package_archive_savings_bytes: u64,
    pub(crate) declared_sizes_likely_conservative: bool,
    pub(crate) assessment: String,
    #[serde(default)]
    pub(crate) requested_profile: Option<String>,
    #[serde(default)]
    pub(crate) write_policy: Option<String>,
    #[serde(default)]
    pub(crate) measurement: Option<SupportInstallCompressionMeasurement>,
    #[serde(default)]
    pub(crate) measured_payload_savings_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) admission_authorized: Option<bool>,
    pub(crate) pacman_check_space_bypass_authorized: bool,
    pub(crate) pacman_check_space_policy: String,
    #[serde(default)]
    pub(crate) mutation_profile_implemented: Option<bool>,
    #[serde(default)]
    pub(crate) compression_ratio: Option<String>,
    #[serde(default)]
    pub(crate) all_payload_destinations_on_root_filesystem: Option<bool>,
    #[serde(default)]
    pub(crate) replacement_credit_policy: Option<String>,
    #[serde(default)]
    pub(crate) module_payload_noop: Option<bool>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallPacmanDatabase {
    pub(crate) path: String,
    pub(crate) package_count: u64,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallBoot {
    pub(crate) rootfs_boot_path: String,
    pub(crate) efi_mount_path: String,
    pub(crate) grub_configuration: String,
    pub(crate) required_kernel_arguments: Vec<String>,
}

#[derive(Clone, Deserialize)]
pub(crate) struct SupportInstallKeyring {
    pub(crate) name: String,
    pub(crate) sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallPackage {
    pub(crate) name: String,
    pub(crate) role: String,
    pub(crate) filename: String,
    pub(crate) signature_filename: String,
    pub(crate) full_version: String,
    pub(crate) pkgver: String,
    pub(crate) pkgrel: String,
    pub(crate) architecture: String,
    pub(crate) signer: String,
    pub(crate) sha256: String,
    pub(crate) signature_sha256: String,
    pub(crate) installed_size: u64,
    pub(crate) dependencies: Vec<String>,
    pub(crate) provides: Vec<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaInstallHandoffResult {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) reason: String,
    pub(crate) message: String,
    pub(crate) phase: String,
    pub(crate) appliance_architecture: String,
    pub(crate) root_partition_label: String,
    pub(crate) boot_partition_label: String,
    pub(crate) support_commit: String,
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) trust: String,
    pub(crate) archive_sha256: String,
    pub(crate) provenance_sha256: String,
    pub(crate) pacman_database_path: String,
    pub(crate) pacman_package_count: u64,
    pub(crate) rootfs_boot_path: String,
    pub(crate) efi_mount_path: String,
    pub(crate) grub_configuration: String,
    pub(crate) required_kernel_arguments: Vec<String>,
    pub(crate) keyring_sha256: String,
    pub(crate) packages: Vec<SupportInstallPackage>,
    pub(crate) storage: SupportInstallStorage,
    pub(crate) compression: SupportInstallCompression,
    pub(crate) mounts_released: bool,
    pub(crate) compression_policy_restored: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaResolutionProgress {
    pub(crate) stage: String,
    pub(crate) processed_bytes: u64,
    pub(crate) total_bytes: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApplianceStatus {
    pub(crate) state: String,
    pub(crate) message: String,
    pub(crate) ssh_port: Option<u16>,
    pub(crate) runtime_path: Option<String>,
    pub(crate) input: Option<InputPreparation>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InputPreparation {
    pub(crate) source_format: String,
    pub(crate) normalizer: String,
    pub(crate) normalized: bool,
    pub(crate) source_bytes: u64,
    pub(crate) image_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GuestHealth {
    pub(crate) protocol_version: String,
    pub(crate) hostname: String,
    pub(crate) architecture: String,
    pub(crate) operating_system: String,
    pub(crate) available_bytes: u64,
    pub(crate) required_tools: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferProof {
    pub(crate) bytes_verified: usize,
    pub(crate) guest_sha256: String,
    pub(crate) message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SyntheticDiskInspection {
    pub(crate) device: String,
    pub(crate) disk_bytes: u64,
    pub(crate) read_only: bool,
    pub(crate) partition_table: String,
    pub(crate) partition: String,
    pub(crate) partition_start_bytes: u64,
    pub(crate) partition_bytes: u64,
    pub(crate) filesystem: String,
    pub(crate) filesystem_label: String,
    pub(crate) filesystem_uuid: String,
    pub(crate) mounted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MarkerMutation {
    pub(crate) marker_path: String,
    pub(crate) marker_content: String,
    pub(crate) source_sha256_before: String,
    pub(crate) source_sha256_after: String,
    pub(crate) working_sha256: String,
    pub(crate) source_unchanged: bool,
    pub(crate) working_read_only: bool,
    pub(crate) mounted: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TargetSystemDiscovery {
    pub(crate) os_id: Option<String>,
    pub(crate) pretty_name: Option<String>,
    pub(crate) version_id: Option<String>,
    pub(crate) build_id: Option<String>,
    pub(crate) variant_id: Option<String>,
    pub(crate) architecture: String,
    pub(crate) kernel_versions: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UserMarkerMutation {
    pub(crate) marker_path: String,
    pub(crate) marker_content: String,
    pub(crate) target_partition: String,
    pub(crate) target_partition_label: String,
    pub(crate) filesystem: String,
    pub(crate) input_sha256_before: String,
    pub(crate) input_sha256_after: String,
    pub(crate) input_unchanged: bool,
    pub(crate) working_read_only: bool,
    pub(crate) mounted: bool,
    pub(crate) system: TargetSystemDiscovery,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExportedImage {
    pub(crate) path: String,
    pub(crate) manifest_path: String,
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
    pub(crate) source_sha256: String,
    pub(crate) layout_scheme: String,
    pub(crate) marker_path: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UsbTargetCandidate {
    pub(crate) device_identifier: String,
    pub(crate) device_node: String,
    pub(crate) media_name: String,
    pub(crate) bus_protocol: String,
    pub(crate) bytes: u64,
    pub(crate) identity_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UsbTargetPreflight {
    pub(crate) image_path: String,
    pub(crate) image_bytes: u64,
    pub(crate) image_sha256: String,
    pub(crate) targets: Vec<UsbTargetCandidate>,
    pub(crate) writes_allowed: bool,
    pub(crate) message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UsbWritePreflightSession {
    pub(crate) status: String,
    pub(crate) session_token: String,
    pub(crate) device_identifier: String,
    pub(crate) device_node: String,
    pub(crate) image_sha256: String,
    pub(crate) identity_token: String,
    pub(crate) expires_at_unix_ms: u128,
    pub(crate) writes_allowed: bool,
    pub(crate) message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UsbWritePreflightCancellation {
    pub(crate) status: String,
    pub(crate) cancelled: bool,
    pub(crate) writes_allowed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UsbWritePreflightStatus {
    pub(crate) status: String,
    pub(crate) active: bool,
    pub(crate) expires_in_ms: u128,
    pub(crate) writes_allowed: bool,
    pub(crate) device_identifier: Option<String>,
    pub(crate) image_sha256: Option<String>,
    pub(crate) identity_token: Option<String>,
    pub(crate) message: String,
}

pub(crate) struct MarkerManifestData<'a> {
    pub(crate) input: &'a Path,
    pub(crate) output: &'a Path,
    pub(crate) input_preparation: &'a InputPreparation,
    pub(crate) input_sha256: &'a str,
    pub(crate) normalized_sha256: &'a str,
    pub(crate) output_bytes: u64,
    pub(crate) output_sha256: &'a str,
    pub(crate) layout: &'a SteamOsLayoutDiscovery,
    pub(crate) target_system: &'a TargetSystemDiscovery,
    pub(crate) nvidia_installation: Option<&'a NvidiaInstallHandoffResult>,
    pub(crate) nvidia_resolution: Option<&'a NvidiaPublishedResolution>,
    pub(crate) nvidia_source_selection: Option<&'a str>,
    pub(crate) runtime: &'a BuildRuntimeProvenance,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeExecutableProvenance {
    pub(crate) filename: String,
    pub(crate) version: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeFileProvenance {
    pub(crate) filename: String,
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BuildRuntimeProvenance {
    pub(crate) host_os: String,
    pub(crate) host_architecture: String,
    pub(crate) native_qemu: RuntimeExecutableProvenance,
    pub(crate) x86_installer_qemu: Option<RuntimeExecutableProvenance>,
    pub(crate) native_appliance: RuntimeFileProvenance,
    pub(crate) x86_installer_appliance: Option<RuntimeFileProvenance>,
}

pub(crate) fn marker_build_manifest(data: MarkerManifestData<'_>) -> serde_json::Value {
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
        "runtime": data.runtime,
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
pub(crate) struct ImageNodeInspection {
    pub(crate) path: String,
    pub(crate) node_type: String,
    pub(crate) size_bytes: u64,
    pub(crate) start_bytes: Option<u64>,
    pub(crate) filesystem: Option<String>,
    pub(crate) filesystem_label: Option<String>,
    pub(crate) partition_label: Option<String>,
    pub(crate) partition_type: Option<String>,
    pub(crate) partition_uuid: Option<String>,
    pub(crate) filesystem_uuid: Option<String>,
    pub(crate) mounted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UserImageInspection {
    pub(crate) device: String,
    pub(crate) disk_bytes: u64,
    pub(crate) read_only: bool,
    pub(crate) partition_table: Option<String>,
    pub(crate) nodes: Vec<ImageNodeInspection>,
    pub(crate) source_sha256_before: String,
    pub(crate) source_sha256_after: String,
    pub(crate) source_unchanged: bool,
    pub(crate) image_sha256_before: String,
    pub(crate) image_sha256_after: String,
    pub(crate) image_unchanged: bool,
    pub(crate) input: InputPreparation,
    pub(crate) layout: SteamOsLayoutDiscovery,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SteamOsPartitionRole {
    pub(crate) role: String,
    pub(crate) path: String,
    pub(crate) size_bytes: u64,
    pub(crate) filesystem: String,
    pub(crate) filesystem_label: String,
    pub(crate) partition_label: String,
    pub(crate) partition_type: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SteamOsLayoutDiscovery {
    pub(crate) recognized: bool,
    pub(crate) scheme: Option<String>,
    pub(crate) roles: Vec<SteamOsPartitionRole>,
    pub(crate) issues: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkingImageVerification {
    pub(crate) source_device: String,
    pub(crate) working_device: String,
    pub(crate) source_bytes: u64,
    pub(crate) working_bytes: u64,
    pub(crate) source_read_only: bool,
    pub(crate) working_read_only: bool,
    pub(crate) source_mounted: bool,
    pub(crate) working_mounted: bool,
    pub(crate) source_partition_table: Option<String>,
    pub(crate) working_partition_table: Option<String>,
    pub(crate) layout_matches: bool,
    pub(crate) overlay_format: String,
}

#[derive(Deserialize)]
pub(crate) struct LsblkResponse {
    pub(crate) blockdevices: Vec<LsblkNode>,
}

#[derive(Deserialize)]
pub(crate) struct LsblkNode {
    pub(crate) path: String,
    #[serde(rename = "type")]
    pub(crate) node_type: String,
    pub(crate) size: u64,
    pub(crate) start: Option<u64>,
    pub(crate) fstype: Option<String>,
    pub(crate) label: Option<String>,
    pub(crate) partlabel: Option<String>,
    pub(crate) parttype: Option<String>,
    pub(crate) partuuid: Option<String>,
    pub(crate) uuid: Option<String>,
    pub(crate) mountpoints: Option<Vec<Option<String>>>,
    pub(crate) children: Option<Vec<LsblkNode>>,
}

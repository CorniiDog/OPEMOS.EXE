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
    #[serde(default)]
    pub(crate) recent_maintainer_worktrees: Vec<String>,
}

impl Default for BuilderSettings {
    fn default() -> Self {
        Self {
            schema_version: BUILDER_SETTINGS_SCHEMA,
            auto_release_verified_nvidia: false,
            track_steamos_driver_updates: false,
            include_upstream_nvidia_releases: false,
            omit_optional_cuda: false,
            recent_maintainer_worktrees: Vec::new(),
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

pub(crate) const PINNED_INSTALLER_FILES: [PinnedInstallerFile; 50] = [
    PinnedInstallerFile {
        path: "bootstrap/install_to_root.sh",
        sha256: "4bcb351d99608ff1cc6be3cf891d219e5fe78f0584f716d5a352891dbcf3f222",
        bytes: 59_191,
        executable: true,
    },
    PinnedInstallerFile {
        path: "bootstrap/install_recovery_guardian_to_root.sh",
        sha256: "654d48ad8e96195ca32519eba67471248961e5f57cdc4ebae880e551fc7a3f91",
        bytes: 7_927,
        executable: true,
    },
    PinnedInstallerFile {
        path: "bootstrap/launch_desktop_companion.sh",
        sha256: "3f233e0e48c2c6debe0d09d0ee22bde641bdd7dba6bc1bdb96de31e2eae76cd9",
        bytes: 1_140,
        executable: true,
    },
    PinnedInstallerFile {
        path: "bootstrap/launch_interstitial.sh",
        sha256: "f65bd4a16c87fa554b68ee41b362abb3e00f294de60dcf9bef7d63fc5e5aab6d",
        bytes: 1_087,
        executable: true,
    },
    PinnedInstallerFile {
        path: "bootstrap/run_guardian_with_interstitial.sh",
        sha256: "59e9d97850cf7b49182dd7e96492fee223512feca5b05358044f1b6669b08857",
        bytes: 1_674,
        executable: true,
    },
    PinnedInstallerFile {
        path: "bootstrap/recoveryctl.sh",
        sha256: "ff218a0af004e5abd6acfcd1116d3f88bde3692178b363152cc9d6df356c4747",
        bytes: 14_522,
        executable: true,
    },
    PinnedInstallerFile {
        path: "bootstrap/online_install.sh",
        sha256: "5b1443169eb30a8c1c2f34ccfeddaeed682dd752e6787d00edd4d0f3f4b31833",
        bytes: 14_160,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/common.sh",
        sha256: "72451b4d70230959337de5f933d88c36b60d0ef2147403e1d5ba7285b9a8936f",
        bytes: 7_110,
        executable: false,
    },
    PinnedInstallerFile {
        path: "lib/recovery_status.py",
        sha256: "bd5d6c826bd97f6f337f30edda59ce1f93a936fb148841d397ed194b27d6670b",
        bytes: 7_887,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/desktop_update_generations.py",
        sha256: "2d19fa64824a384ce61c655f39e89276b365447cbcbe670c1e72e3e1a8112588",
        bytes: 38_358,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/interstitial_progress.py",
        sha256: "a84877ea601f104718a1ba266d15cf2deb9ed5b36c8339c0aba81f3889eefe3e",
        bytes: 9_766,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/validate_interstitial_binary.py",
        sha256: "fea7e5e24a9273bc4704a9e5ecde6a11fc218ed13826ec69614aaa59a507d103",
        bytes: 3_558,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/recovery_transaction.py",
        sha256: "4caf8dac4296779c1f098c3c2475d70898f633ae81e1f00f7d83c73c7648d3bb",
        bytes: 4_373,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/recovery_release_plan.py",
        sha256: "c76c50b4b1a3490410e958c7c0c60987cfc7fee16d5e20e63b2f13b4d6aa6f8a",
        bytes: 3_856,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/update_recovery_grub_args.py",
        sha256: "93a1d1559d222f9aca1173da862f8032c15eb9634dda7ee3c0223b0138a130ad",
        bytes: 1_378,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/open_opemos_contract.py",
        sha256: "e4fc16f9822a8ca3d8bbad0f8ff6c7cd8399b4666953089a6843a06c622e525b",
        bytes: 3_650,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/validate_recovery_install_path.py",
        sha256: "2f4b41aaf86ba149b7e75e804222d3143845314d8d29250505cb28d68c4de3ff",
        bytes: 2_610,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/run_in_process_group.py",
        sha256: "06ada2883b18e40a8114861644e03bf59bc10b9bd8174a5437e47fc77a3f177f",
        bytes: 250,
        executable: false,
    },
    PinnedInstallerFile {
        path: "lib/verify_bind_mount.py",
        sha256: "c5a6a21274cfcdffa14407db64b2825289ab616d6538738dd10e3717b520a6d8",
        bytes: 2_640,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/update_grub_nvidia_args.py",
        sha256: "035e97a9019087d8486dc9eebeb8def1d7365c88cc1b6638c511a1e5b137ee68",
        bytes: 3_145,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/validate_install_inputs.py",
        sha256: "c1f62fa2c048f5dc7d0cfb610556c7382eff43f7f67dbda9307c55eb6c307a60",
        bytes: 94_275,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/authenticated_cache_bundle.py",
        sha256: "148ea7fbb85738700901895293f26ed192395918395655e1b2e10f20a5748bc5",
        bytes: 27_965,
        executable: false,
    },
    PinnedInstallerFile {
        path: "lib/resolve_authenticated_install_bundle.py",
        sha256: "3b9d493b898842f066adbd450ee6a1acecb6997e3d08785422cc945b5ab49e06",
        bytes: 5_973,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/write_install_result.py",
        sha256: "7152fd316772bb04532fb37ad34f6066518d0e81a60b6c8209e659ff50bc62e8",
        bytes: 63_307,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/capture_bounded_command.py",
        sha256: "a0d2290d1df62a07b546e182035bd651802b4b0762f262e7e6f6cbf13d158659",
        bytes: 2_965,
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
        sha256: "12c4c41f26615b476da295574db7e80a8cc6a1862ac040e97592b80d1b6d2bba",
        bytes: 4_100,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/gaming_payload_profiles.py",
        sha256: "b26767e246fc849d2685cdf2556442668883179f3cda163d5f27daf94227e0fd",
        bytes: 13_377,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/repack_gaming_userspace.py",
        sha256: "09565f447bb2d1ea574525690c535de61658d2c55ebcf564c43814cd33b392f0",
        bytes: 16_569,
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
        sha256: "704cb3052bdcbf53acfe8183bedd071d4265e89af4974586a68341e3ccb4a1b7",
        bytes: 15_534,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/check_initramfs_workspace.py",
        sha256: "b5be7223222f02029ccf3a979d4f60bf5c60a56d9ea0aa322192ad17400560e3",
        bytes: 15_967,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/run_pacman_transaction.py",
        sha256: "b8c95f9ceea93f1d22954a2f24c9e5e27c8d3ad676a2b43a1ef46e60a922d2cd",
        bytes: 2_723,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/snapshot_install_input.py",
        sha256: "37ef81c3c304d0548ad0edea3ae81e9afd0e0375c94beff1d75afb4ec4cbb8ba",
        bytes: 4_059,
        executable: false,
    },
    PinnedInstallerFile {
        path: "lib/snapshot_target_execution.py",
        sha256: "9d7946b39639dfe185af95dacd7a585fa127cf4c3bd694ed6e1de5492e2a2b72",
        bytes: 13_336,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/verify_initramfs.py",
        sha256: "cc2cbf20fd2f8453ec6db18ed14a4162b3bdc8bd5f70135eae5e4b51f1ec1a00",
        bytes: 10_229,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/validate_install_contract.py",
        sha256: "3a0520b0b6d476b2c9c1ae4c2ca7b4b25c8a496fc98374e26d75edd83c40ea65",
        bytes: 23_592,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/payload_receipt.py",
        sha256: "8a0f75698ebd27a9f608c316e4bc38360c254af8cc27d8a995eb7fc5a6ef7884",
        bytes: 11_428,
        executable: false,
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
        sha256: "f93bfa20134fc9bf9bada94c0c44029dc195cca41454ab6a5062168ed9e0d209",
        bytes: 1_042,
        executable: false,
    },
    PinnedInstallerFile {
        path: "support/recovery/opemos-nvidia-guardian.service.in",
        sha256: "537a34afe65550ef7dca2d5b9725dbd42e1961c3a8a25a0cce7ffe4217d5c018",
        bytes: 341,
        executable: false,
    },
    PinnedInstallerFile {
        path: "support/recovery/opemos-interstitial.service.in",
        sha256: "3225436d6d97cad3b51069b6f657bc8346b52234e4f169fa205e2555242dc57f",
        bytes: 1_730,
        executable: false,
    },
    PinnedInstallerFile {
        path: "support/recovery/opemos-nvidia-repair.service.in",
        sha256: "87cb1564c90f977af4a89e2e15f82590160a745ff5c40ad2b20aea8d41082c07",
        bytes: 276,
        executable: false,
    },
    PinnedInstallerFile {
        path: "support/recovery/opemos-nvidia-repair.timer",
        sha256: "24fe32bd2e9abde716d81238d7ba9dec41f4486e215bf47c923ab72662ede2d6",
        bytes: 229,
        executable: false,
    },
    PinnedInstallerFile {
        path: "support/recovery/90-opemos-nvidia-repair",
        sha256: "8aa86928816be4dfc9ee0022871fb3d3a6ce70ca05efe03d0a67e1adeb66e14c",
        bytes: 126,
        executable: true,
    },
    PinnedInstallerFile {
        path: "support/recovery/90-opemos-nvidia-guardian.conf",
        sha256: "9cfec066ffcba283d572d8e146024cd19b4a7479032232d17920df4b2972a3d3",
        bytes: 505,
        executable: false,
    },
    PinnedInstallerFile {
        path: "trust/desktop-update-signers.json",
        sha256: "673780febd887c25c307cc0f98e36f741a36c2c32c683e171c045d9e0856638f",
        bytes: 95,
        executable: false,
    },
];

pub(crate) const PINNED_PUBLISHER_FILES: [PinnedInstallerFile; 2] = [
    PinnedInstallerFile {
        path: "bootstrap/publish_artifacts.sh",
        sha256: "683943eea91c0367419cef9362857dae3b26617ab448d295a929c90d1c06de68",
        bytes: 3_693,
        executable: true,
    },
    PinnedInstallerFile {
        path: "lib/validate_publish_inputs.py",
        sha256: "b547d16179d7d706093fa916769e080a0e33073a555b0fa80425b669b57b94e9",
        bytes: 16_225,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct GithubRelease {
    pub(crate) tag_name: String,
    pub(crate) draft: bool,
    pub(crate) prerelease: bool,
    pub(crate) published_at: Option<String>,
    pub(crate) assets: Vec<GithubReleaseAsset>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) core_authorization: Option<NvidiaCoreBuildAuthorization>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaCoreBuildAuthorization {
    pub(crate) policy_name: String,
    pub(crate) policy_sha256: String,
    pub(crate) baseline_archive_sha256: String,
    pub(crate) baseline_provenance_sha256: String,
    pub(crate) baseline_trust: String,
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
    pub(crate) input_source_mode: String,
    pub(crate) input_bundle_cache_id: Option<String>,
    pub(crate) trust: String,
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) packages: Vec<NvidiaUserspacePackage>,
    pub(crate) userspace_lock: ReviewedUserspaceLock,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallInputNames {
    pub(crate) archive: Option<String>,
    pub(crate) provenance: Option<String>,
    pub(crate) nvidia_utils: Option<String>,
    pub(crate) lib32_nvidia_utils: Option<String>,
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
    pub(crate) inputs: SupportInstallInputNames,
    pub(crate) cleanup: SupportInstallCleanup,
    pub(crate) validation: Option<SupportInstallValidationDocument>,
    pub(crate) module_verification: Option<SupportModuleVerification>,
    pub(crate) userspace_verification: Option<SupportUserspaceVerification>,
    pub(crate) initramfs_workspace: Option<SupportInitramfsWorkspace>,
    pub(crate) initramfs_verification: Option<SupportInitramfsVerification>,
    pub(crate) payload_receipt: Option<SupportPayloadReceipt>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportModuleVerification {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) reason: String,
    pub(crate) modules: Vec<SupportInstalledModule>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SupportInstalledModule {
    pub(crate) module_name: String,
    pub(crate) target_relative_path: String,
    pub(crate) representation: String,
    pub(crate) expected_payload_sha256: String,
    pub(crate) actual_payload_sha256: String,
    pub(crate) expected_mode: String,
    pub(crate) actual_mode: String,
    pub(crate) expected_uid: u32,
    pub(crate) actual_uid: u32,
    pub(crate) expected_gid: u32,
    pub(crate) actual_gid: u32,
    pub(crate) compressed_size_bytes: u64,
    pub(crate) decompression_status: String,
    pub(crate) invalid_fields: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportUserspaceVerification {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) reason: String,
    pub(crate) packages: Vec<SupportVerifiedUserspacePackage>,
    pub(crate) pacman_database: SupportVerifiedPacmanDatabase,
    pub(crate) gsp_firmware: SupportVerifiedGspFirmware,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportVerifiedUserspacePackage {
    pub(crate) package_name: String,
    pub(crate) version: String,
    pub(crate) package_sha256: String,
    pub(crate) package_query_verified: bool,
    pub(crate) pacman_integrity_verified: bool,
    pub(crate) payload_verified: bool,
    pub(crate) directories: u64,
    pub(crate) regular_files: u64,
    pub(crate) symlinks: u64,
    pub(crate) hardlinks: u64,
    pub(crate) shared_libraries: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportVerifiedPacmanDatabase {
    pub(crate) path: String,
    pub(crate) status: String,
    pub(crate) verified_package_count: u64,
    pub(crate) consistency_verified: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportVerifiedGspFirmware {
    pub(crate) status: String,
    pub(crate) version: String,
    pub(crate) target_relative_files: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportPayloadReceipt {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) reason: String,
    pub(crate) target: SupportPayloadReceiptTarget,
    pub(crate) receipt_id: String,
    pub(crate) rootfs_relative_path: String,
    pub(crate) records: Vec<SupportPayloadReceiptRecord>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportPayloadReceiptTarget {
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) architecture: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportPayloadReceiptRecord {
    pub(crate) role: String,
    pub(crate) filename: String,
    pub(crate) size_bytes: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInitramfsWorkspace {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) reason: String,
    pub(crate) phase: String,
    pub(crate) condition: String,
    pub(crate) required_bytes: u64,
    pub(crate) required_inodes: u64,
    pub(crate) available_bytes: Option<u64>,
    pub(crate) available_inodes: Option<u64>,
    pub(crate) inode_capacity_mode: Option<String>,
    pub(crate) mode: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInitramfsVerification {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) kernel_version: String,
    pub(crate) required_modules: Vec<String>,
    pub(crate) rootfs_only_modules: Vec<String>,
    pub(crate) tools: SupportInitramfsTools,
    pub(crate) config: SupportInitramfsFileIdentity,
    pub(crate) images: Vec<SupportInitramfsImage>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInitramfsTools {
    pub(crate) mkinitcpio: SupportInitramfsFileIdentity,
    pub(crate) lsinitcpio: SupportInitramfsFileIdentity,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInitramfsFileIdentity {
    pub(crate) path: String,
    pub(crate) size_bytes: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInitramfsImage {
    pub(crate) filename: String,
    pub(crate) size_bytes: u64,
    pub(crate) sha256: String,
    pub(crate) listing_sha256: String,
    pub(crate) entries: u64,
    pub(crate) modules: HashMap<String, String>,
    pub(crate) config_path: String,
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
    pub(crate) runtime_mounts_expected: u64,
    pub(crate) runtime_mounts_released: u64,
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
    pub(crate) input_source: SupportInstallInputSource,
    pub(crate) archive_sha256: String,
    pub(crate) provenance_sha256: String,
    pub(crate) userspace_lock: SupportInstallPinnedIdentity,
    pub(crate) pacman_database: SupportInstallPacmanDatabase,
    pub(crate) boot: SupportInstallBoot,
    pub(crate) keyring: SupportInstallKeyring,
    pub(crate) packages: Vec<SupportInstallPackage>,
    pub(crate) modules: Vec<SupportInstallValidatedModule>,
    pub(crate) package_dependency_closure: Vec<SupportInstallDependency>,
    pub(crate) gaming_payload: SupportInstallGamingPayload,
    pub(crate) compression: SupportInstallCompression,
    pub(crate) storage: SupportInstallStorage,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SupportInstallValidatedModule {
    pub(crate) name: String,
    pub(crate) payload_sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupportInstallInputSource {
    pub(crate) mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) bundle_cache_id: Option<String>,
}

impl Default for SupportInstallInputSource {
    fn default() -> Self {
        Self {
            mode: "direct".into(),
            bundle_cache_id: None,
        }
    }
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SupportInstallPinnedIdentity {
    pub(crate) name: String,
    pub(crate) sha256: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SupportInstallDependency {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) source: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    pub(crate) invalid_options: Vec<String>,
    pub(crate) write_incompatible_options: Vec<String>,
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
    pub(crate) filesystem_mount_exclusive: Option<bool>,
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
#[serde(deny_unknown_fields)]
pub(crate) struct SupportInstallKeyring {
    pub(crate) name: String,
    pub(crate) sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    pub(crate) input_source_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) input_bundle_cache_id: Option<String>,
    pub(crate) pacman_database_path: String,
    pub(crate) pacman_package_count: u64,
    pub(crate) rootfs_boot_path: String,
    pub(crate) efi_mount_path: String,
    pub(crate) grub_configuration: String,
    pub(crate) required_kernel_arguments: Vec<String>,
    pub(crate) keyring_sha256: String,
    pub(crate) initramfs_workspace: SupportInitramfsWorkspace,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) initramfs_verification: Option<SupportInitramfsVerification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) module_verification: Option<SupportModuleVerification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) userspace_verification: Option<SupportUserspaceVerification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) payload_receipt: Option<SupportPayloadReceipt>,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CompletedNvidiaImage {
    #[serde(flatten)]
    pub(crate) output: ExportedImage,
    pub(crate) nvidia_version: String,
    pub(crate) kernel_version: String,
    pub(crate) steamos_version: String,
    pub(crate) trust: String,
    pub(crate) source_selection: String,
    pub(crate) source_mode: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UsbTargetCandidate {
    pub(crate) device_identifier: String,
    pub(crate) device_node: String,
    pub(crate) media_name: String,
    pub(crate) bus_protocol: String,
    pub(crate) bytes: u64,
    pub(crate) block_size: u64,
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

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UsbWriteProgress {
    pub(crate) phase: String,
    pub(crate) bytes_completed: u64,
    pub(crate) bytes_total: u64,
    pub(crate) message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UsbWriteResult {
    pub(crate) status: String,
    pub(crate) device_identifier: String,
    pub(crate) device_node: String,
    pub(crate) bytes_written: u64,
    pub(crate) image_sha256: String,
    pub(crate) verified_sha256: String,
    pub(crate) ejected: bool,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct UsbHelperWriteRequest {
    pub(crate) schema_version: u32,
    pub(crate) protocol: String,
    pub(crate) request_id: String,
    pub(crate) intent_token: String,
    pub(crate) expires_at_unix_ms: u64,
    pub(crate) image_path: String,
    pub(crate) image_bytes: u64,
    pub(crate) image_sha256: String,
    pub(crate) device_identifier: String,
    pub(crate) canonical_device_node: String,
    pub(crate) raw_device_node: String,
    pub(crate) device_capacity_bytes: u64,
    pub(crate) device_identity_token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct UsbHelperAttestation {
    pub(crate) schema_version: u32,
    pub(crate) protocol: String,
    pub(crate) helper_version: String,
    pub(crate) process_id: u32,
    pub(crate) effective_user_id: u32,
    pub(crate) executable_sha256: String,
    pub(crate) signing_identity: String,
    pub(crate) independently_authenticated: bool,
    pub(crate) independently_authorized: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct UsbHelperEvent {
    pub(crate) schema_version: u32,
    pub(crate) protocol: String,
    pub(crate) request_id: String,
    pub(crate) sequence: u32,
    pub(crate) phase: String,
    pub(crate) outcome: String,
    pub(crate) bytes_completed: u64,
    pub(crate) bytes_total: u64,
    pub(crate) image_sha256: String,
    pub(crate) device_identity_token: String,
    pub(crate) message: String,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct UsbHelperTrustPolicy<'a> {
    pub(crate) executable_sha256: &'a str,
    pub(crate) signing_identity: &'a str,
    pub(crate) helper_version: &'a str,
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
    let welcome_revision = nvidia_installed.then(install_media_welcome_revision);
    let modified_paths = if nvidia_installed {
        serde_json::json!([
            "/etc/steamos-nvidia-image-builder-test",
            "/etc/modprobe.d/99-open-gpu-kernel-modules-steamos.conf",
            "/etc/mkinitcpio.conf.d/90-open-gpu-kernel-modules-steamos.conf",
            "/usr/lib/modules/<target-kernel>/updates/open-gpu-kernel-modules-steamos",
            "/var/lib/open-gpu-kernel-modules-steamos-support/offline-install",
            "/home/deck/tools/opemos-rollback-last-update",
            "/home/deck/tools/open-opemos-welcome",
            "/home/deck/Desktop/Open-OPEMOS.desktop",
            "/home/deck/.config/autostart/Open-OPEMOS.desktop",
            "/home/deck/.local/share/icons/hicolor/scalable/apps/opemos.svg",
            "/usr/lib/opemos-install-media/opemos-install-helper",
            "/usr/lib/opemos-install-media/welcome_server.py",
            "/usr/lib/opemos-install-media/repair_device.sh",
            "/usr/lib/opemos-install-media/support",
            "/usr/lib/opemos-install-media/support-revision",
            "/usr/lib/opemos-install-media/nvidia-version",
            "/usr/share/opemos-install-media/ui/gtk-3.0/gtk.css",
            "/usr/share/opemos-install-media/ui/welcome",
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
            "recoveryRollbackVerified": nvidia_installed,
            "installationMediaWelcomeVerified": nvidia_installed,
            "installationMediaWelcomeRevision": welcome_revision,
            "installedRecoveryGuardianPayloadVerified": nvidia_installed,
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

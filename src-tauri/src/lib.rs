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
    process::{Child, Command, Stdio},
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
mod nvidia;
#[cfg(unix)]
#[allow(dead_code)]
mod output_transaction;
mod settings;
mod windows;

pub use app::run;
use appliance::*;
use contracts::*;
use host_platform::*;
use host_storage::*;
use image::*;
use installer::*;
use nvidia::*;
use settings::*;

const READY_MARKER: &str = "SteamOS NVIDIA Image Builder appliance\nREADY";
const BOOT_TIMEOUT: Duration = Duration::from_secs(120);
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
const NVIDIA_SUPPORT_COMMIT: &str = "cbc44270440652875739c9386235ee8ae22861c9";
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

use super::*;
use crate::{
    core_generation_bootstrap::installed_trust::{
        authenticate_installed_discovery, authenticate_installed_manifest, InstalledTrustPins,
        CHECKPOINT_FILENAME, KEYRING_FILENAME, POLICY_FILENAME,
    },
    core_generation_cache::{
        activation::{
            acknowledge_installed_authenticated_activation,
            begin_installed_authenticated_activation,
        },
        appliance_staging::stage_pending_generation_for_appliance,
        FilesystemCapacity,
    },
    core_generation_contracts::{validate_discovery_bytes, validate_manifest_bytes},
    core_generation_verifier::DetachedVerifierOutput,
};
use serde_json::Value;
use std::{
    ffi::OsStr,
    fs,
    io::{Cursor, Read},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

// This exact, explicitly non-production Core successor adds authenticated
// appliance-generation lineage consumption. Tests obtain it only from a cache
// verified against the canonical GitHub repository; availability does not
// promote it to the production bundle pin.
const DEVELOPMENT_HANDOFF_COMMIT: &str = "adf372b857cd348b6a18680b45ffcea790f04d4b";
const HANDOFF_FILENAME: &str = "opemos-core-generation-handoff-v1.json";
const DEVELOPMENT_OPERATION: &str = "development-generation-v1";
const DEVELOPMENT_STEAMOS: &str = "3.8.14";
const DEVELOPMENT_KERNEL: &str = "6.16.12-valve24.4-1-neptune-616-gfe145653a794";
const DEVELOPMENT_NVIDIA: &str = "575.64.05";

struct FixtureTransport {
    files: BTreeMap<String, Vec<u8>>,
}

struct AmpleCapacity;

impl FilesystemCapacityProbe for AmpleCapacity {
    fn probe(&self, _pinned_root: &fs::File) -> std::io::Result<FilesystemCapacity> {
        Ok(FilesystemCapacity {
            available_bytes: u64::MAX,
            allocation_unit_bytes: 4096,
            available_inodes: None,
        })
    }
}

impl GenerationTransport for FixtureTransport {
    fn open(&mut self, name: &str) -> Result<Box<dyn Read>, String> {
        self.files
            .get(name)
            .cloned()
            .map(|bytes| Box::new(Cursor::new(bytes)) as Box<dyn Read>)
            .ok_or_else(|| format!("development generation omitted {name}"))
    }

    fn open_authenticated_payload(
        &mut self,
        request: &AuthenticatedPayloadRequest,
    ) -> Result<Box<dyn Read>, String> {
        self.open(request.filename())
    }
}

fn valid_development_signature() -> DetachedVerifierOutput {
    DetachedVerifierOutput {
        exit_status: 0,
        status: concat!(
            "[GNUPG:] NEWSIG\n",
            "[GNUPG:] KEY_CONSIDERED AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 0\n",
            "[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ",
            "2026-09-03 1788436800 0 4 0 1 10 00 ",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        )
        .as_bytes()
        .to_vec(),
    }
}

fn github_core_repository() -> PathBuf {
    crate::core_test_repository::required_github_core_repository(DEVELOPMENT_HANDOFF_COMMIT)
}

fn export_core_sources(repository: &Path, destination: &Path) {
    for relative in [
        "lib/consume_appliance_generation.py",
        "lib/generate_development_appliance_generation.py",
        "lib/userspace_lock_bootstrap_contract.py",
        "lib/userspace_lock_generation_contract.py",
        "lib/userspace_lock_verifier_evidence.py",
    ] {
        let output = Command::new("git")
            .args(["show", &format!("{DEVELOPMENT_HANDOFF_COMMIT}:{relative}")])
            .current_dir(repository)
            .output()
            .expect("export immutable Core development source");
        assert!(
            output.status.success(),
            "Core development source {relative} is missing"
        );
        let path = destination.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, output.stdout).unwrap();
    }
}

fn run_python(arguments: &[&OsStr], source_root: &Path) -> std::process::Output {
    Command::new("python3")
        .args(arguments)
        .current_dir(source_root)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run immutable Core development helper")
}

fn write_private(path: &Path, payload: &[u8]) {
    fs::write(path, payload).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}

fn make_writable(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                make_writable(&entry.path());
            }
        }
    } else if metadata.is_file() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn create() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "opemos-development-generation-integration-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        make_writable(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "requires the exact unpublished Core development-generation commit"]
fn immutable_core_generation_reaches_guest_consumption_and_activation() {
    let repository = github_core_repository();
    let temporary = TemporaryRoot::create();
    let root = temporary.path();
    let source_root = root.join("core-source");
    fs::create_dir(&source_root).unwrap();
    export_core_sources(&repository, &source_root);

    let generated = root.join("generated");
    let generator = source_root.join("lib/generate_development_appliance_generation.py");
    let generator_output = run_python(
        &[
            generator.as_os_str(),
            OsStr::new("--development-test"),
            OsStr::new("--output"),
            generated.as_os_str(),
        ],
        &source_root,
    );
    assert!(
        generator_output.status.success(),
        "{}",
        String::from_utf8_lossy(&generator_output.stderr)
    );
    let summary: Value = serde_json::from_slice(&generator_output.stdout).unwrap();
    assert_eq!(summary["trust"], "development-test-only");

    let generated_handoff = generated.join("handoff");
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(&generated_handoff).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() != OsStr::new(HANDOFF_FILENAME) {
            files.insert(
                entry.file_name().into_string().unwrap(),
                fs::read(entry.path()).unwrap(),
            );
        }
    }
    let discovery_bytes = files[DISCOVERY_FILENAME].clone();
    let discovery_signature = files[DISCOVERY_SIGNATURE_FILENAME].clone();
    let discovery = validate_discovery_bytes(&discovery_bytes).unwrap();
    let manifest_bytes = files[&discovery.generation.manifest_filename].clone();
    let manifest_signature = files[&discovery.generation.signature_filename].clone();
    let manifest = validate_manifest_bytes(&manifest_bytes).unwrap();
    let target = discovery.targets[0].target.clone();
    assert_eq!(target, manifest.target_locks[0].target);

    let policy_bytes = fs::read(generated.join("trust/policy.json")).unwrap();
    let keyring = fs::read(generated.join("trust/opemos-userspace-lock-generations.gpg")).unwrap();
    let checkpoint_bytes = fs::read(generated.join("trust/checkpoint.json")).unwrap();
    let cache = CoreGenerationCache::open(&root.join("cache")).unwrap();
    let mut transport = FixtureTransport { files };
    let capacity = AmpleCapacity;
    let identity = acquire_inactive_generation(
        &cache,
        "development-acquisition",
        &InactiveAcquisitionPolicy {
            policy_payload: &policy_bytes,
            keyring_payload: &keyring,
            target: &target,
            capacity_probe: &capacity,
        },
        &mut transport,
        &mut |_, _, _, _, cancelled| {
            if cancelled() {
                Err("verification cancelled".into())
            } else {
                Ok(valid_development_signature())
            }
        },
        || false,
    )
    .unwrap();
    assert_eq!(
        identity.manifest_sha256,
        discovery.generation.manifest_sha256
    );
    let trust_root = root.join("installed-trust");
    fs::create_dir(&trust_root).unwrap();
    fs::set_permissions(&trust_root, fs::Permissions::from_mode(0o700)).unwrap();
    write_private(&trust_root.join(POLICY_FILENAME), &policy_bytes);
    write_private(&trust_root.join(KEYRING_FILENAME), &keyring);
    write_private(&trust_root.join(CHECKPOINT_FILENAME), &checkpoint_bytes);
    let pins = InstalledTrustPins::fixture(&policy_bytes, &keyring, &checkpoint_bytes);
    let pending = authenticate_installed_discovery(
        &trust_root,
        &pins,
        &discovery_bytes,
        &discovery_signature,
        &|| false,
        |_, _, _, _, _| Ok(valid_development_signature()),
    )
    .unwrap();
    let (generation, checkpoint) = authenticate_installed_manifest(
        pending,
        &manifest_bytes,
        &manifest_signature,
        &|| false,
        |_, _, _, _, _| Ok(valid_development_signature()),
    )
    .unwrap();
    let pending_state = begin_installed_authenticated_activation(
        &cache,
        &generation,
        &checkpoint,
        &target,
        &[],
        DEVELOPMENT_OPERATION,
        || false,
    )
    .unwrap();
    assert_eq!(pending_state.pending.as_ref(), Some(&identity));

    let destination = root.join("appliance");
    fs::create_dir(&destination).unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
    let mut staged = stage_pending_generation_for_appliance(
        &cache,
        &generation,
        &checkpoint,
        &target,
        &[],
        DEVELOPMENT_OPERATION,
        &destination,
        || false,
    )
    .unwrap();
    staged.revalidate().unwrap();
    let handoff = destination.join(format!(
        "handoff-{DEVELOPMENT_OPERATION}-{}",
        identity.manifest_sha256
    ));
    assert!(handoff.join(HANDOFF_FILENAME).is_file());

    let prepared = root.join("prepared");
    let consumer = source_root.join("lib/consume_appliance_generation.py");
    let consumer_output = run_python(
        &[
            consumer.as_os_str(),
            OsStr::new("--development-test"),
            OsStr::new("--handoff"),
            handoff.as_os_str(),
            OsStr::new("--operation-id"),
            OsStr::new(DEVELOPMENT_OPERATION),
            OsStr::new("--policy"),
            generated.join("trust/policy.json").as_os_str(),
            OsStr::new("--keyring"),
            generated
                .join("trust/opemos-userspace-lock-generations.gpg")
                .as_os_str(),
            OsStr::new("--checkpoint"),
            generated.join("trust/checkpoint.json").as_os_str(),
            OsStr::new("--gpgv"),
            generated.join("trust/development-gpgv").as_os_str(),
            OsStr::new("--steamos"),
            OsStr::new(DEVELOPMENT_STEAMOS),
            OsStr::new("--kernel"),
            OsStr::new(DEVELOPMENT_KERNEL),
            OsStr::new("--nvidia"),
            OsStr::new(DEVELOPMENT_NVIDIA),
            OsStr::new("--architecture"),
            OsStr::new("x86_64"),
            OsStr::new("--output"),
            prepared.as_os_str(),
        ],
        &source_root,
    );
    assert!(
        consumer_output.status.success(),
        "{}",
        String::from_utf8_lossy(&consumer_output.stderr)
    );
    let result: Value = serde_json::from_slice(&consumer_output.stdout).unwrap();
    assert_eq!(result["status"], "prepared");
    assert_eq!(result["trust"], "development-test-only");
    assert_eq!(
        result["generation"]["manifestSha256"],
        identity.manifest_sha256
    );
    assert_eq!(result["packages"].as_array().unwrap().len(), 6);
    assert!(prepared.join("installer-inputs-v1.json").is_file());

    staged.revalidate().unwrap();
    staged.retire().unwrap();
    let active = acknowledge_installed_authenticated_activation(
        &cache,
        &generation,
        &checkpoint,
        &target,
        &[],
        DEVELOPMENT_OPERATION,
        pending_state.revision,
    )
    .unwrap();
    assert_eq!(active.active, Some(identity));
    assert!(active.pending.is_none());
}

//! Inactive, test-only bridge from verifier-sealed Core generation inputs to
//! the host cache's pending-activation transaction. Raw identities, manifests,
//! and durable state are deliberately not accepted by this entry point.

use super::*;
use crate::{
    core_generation_bootstrap::{
        validate_authenticated_bootstrap_activation, AuthenticatedBootstrapCheckpoint,
    },
    core_generation_contracts::{
        DurableGenerationIdentity, GenerationActivationState, GenerationTarget, DISCOVERY_FILENAME,
        DISCOVERY_SIGNATURE_FILENAME,
    },
    core_generation_verifier::AuthenticatedGeneration,
};
use std::os::unix::fs::MetadataExt as _;

const TRUST_RECORD_FILENAME: &str = "acquisition-trust-v1.json";
const INVENTORY_READ_BUFFER_BYTES: usize = 64 * 1024;

type ExpectedInventory = BTreeMap<String, (u64, String)>;

/// Begins an inactive host-cache activation using only verifier-created and
/// checkpoint-sealed capabilities. Production wiring remains intentionally
/// absent until the installed trust root and discovery channel are active.
pub(crate) fn begin_authenticated_activation<C>(
    cache: &CoreGenerationCache,
    generation: &AuthenticatedGeneration,
    checkpoint: &AuthenticatedBootstrapCheckpoint,
    expected_target: &GenerationTarget,
    lineage: &[&AuthenticatedGeneration],
    operation_id: &str,
    cancelled: C,
) -> Result<CoreGenerationCacheState, String>
where
    C: Fn() -> bool,
{
    begin_authenticated_activation_with_hook(
        cache,
        generation,
        checkpoint,
        expected_target,
        lineage,
        operation_id,
        cancelled,
        |_| {},
    )
}

#[allow(clippy::too_many_arguments)]
fn begin_authenticated_activation_with_hook<C, H>(
    cache: &CoreGenerationCache,
    generation: &AuthenticatedGeneration,
    checkpoint: &AuthenticatedBootstrapCheckpoint,
    expected_target: &GenerationTarget,
    lineage: &[&AuthenticatedGeneration],
    operation_id: &str,
    cancelled: C,
    mut hook: H,
) -> Result<CoreGenerationCacheState, String>
where
    C: Fn() -> bool,
    H: FnMut(&'static str),
{
    poll_cancelled(&cancelled)?;
    if !safe_operation_id(operation_id) {
        return Err("Core generation activation operation identity is invalid.".into());
    }
    let expected_inventory = expected_authenticated_inventory(generation)?;

    let _process_guard = CACHE_TRANSACTION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _file_guard = cache.acquire_lock()?;
    hook("after-lock");
    poll_cancelled(&cancelled)?;

    let mut state = cache.load_state_unlocked()?;
    let activation_state = GenerationActivationState {
        high_water_sequence: state.high_water_sequence,
        active: state
            .active
            .as_ref()
            .map(|identity| DurableGenerationIdentity {
                sequence: identity.sequence,
                manifest_sha256: identity.manifest_sha256.clone(),
            }),
    };
    let authorized = validate_authenticated_bootstrap_activation(
        generation,
        checkpoint,
        expected_target,
        &activation_state,
        lineage,
    )?;
    let identity = CoreGenerationIdentity {
        sequence: authorized.sequence,
        generation_id: authorized.manifest_sha256.clone(),
        manifest_sha256: authorized.manifest_sha256,
    };
    identity.validate()?;

    let generation_path = cache.generation_path(&identity)?;
    let pinned =
        pin_generation_directory(&generation_path, "authenticated cached Core generation")?;
    cache.require_generation_committed(&identity)?;
    hook("after-pin-before-inventory");
    verify_authenticated_inventory(&pinned, &expected_inventory, &cancelled)?;
    hook("after-first-inventory");
    require_pinned_generation_directory(
        &generation_path,
        &pinned,
        "authenticated cached Core generation",
    )?;
    cache.require_unique_committed_sequence(&identity)?;

    if let Some(pending) = state.pending.as_ref() {
        if pending == &identity && state.pending_operation_id.as_deref() == Some(operation_id) {
            return Ok(state);
        }
        return Err("Another Core generation is already pending health validation.".into());
    }
    hook("before-state-save");
    poll_cancelled(&cancelled)?;
    // Cancellation is intentionally polled before the final, uninterrupted
    // verification-to-state-publication boundary. All cache evidence is then
    // rechecked under the same process and file locks immediately before CAS.
    verify_authenticated_inventory(&pinned, &expected_inventory, &cancelled)?;
    require_pinned_generation_directory(
        &generation_path,
        &pinned,
        "authenticated cached Core generation",
    )?;
    cache.require_unique_committed_sequence(&identity)?;
    if cache.load_state_unlocked()? != state {
        return Err("Core generation cache state changed before activation.".into());
    }
    hook("final-cancellation-boundary");
    // This is the cancellation linearization point. Once it passes, the
    // durable state publication is intentionally non-cancellable so callers
    // cannot receive an ambiguous cancelled-but-pending result.
    poll_cancelled(&cancelled)?;

    state.pending = Some(identity);
    state.pending_operation_id = Some(operation_id.into());
    cache.save_next_state(state)
}

fn expected_authenticated_inventory(
    generation: &AuthenticatedGeneration,
) -> Result<ExpectedInventory, String> {
    let inputs = generation.request_plan_inputs();
    let discovery = generation.discovery();
    let evidence = generation.canonical_evidence_bytes()?;
    let mut inventory = BTreeMap::new();
    for (name, bytes) in [
        (DISCOVERY_FILENAME, inputs.discovery_payload),
        (DISCOVERY_SIGNATURE_FILENAME, inputs.discovery_signature),
        (
            discovery.generation.manifest_filename.as_str(),
            inputs.manifest_payload,
        ),
        (
            discovery.generation.signature_filename.as_str(),
            inputs.manifest_signature,
        ),
        (TRUST_RECORD_FILENAME, evidence.as_slice()),
    ] {
        insert_inventory_record(&mut inventory, name, bytes.len() as u64, sha256(bytes))?;
    }
    for file in &generation.manifest().files {
        insert_inventory_record(
            &mut inventory,
            &file.filename,
            file.size,
            file.sha256.clone(),
        )?;
    }
    Ok(inventory)
}

fn insert_inventory_record(
    inventory: &mut ExpectedInventory,
    name: &str,
    size: u64,
    hash: String,
) -> Result<(), String> {
    let folded = name.to_ascii_lowercase();
    if inventory
        .keys()
        .any(|existing| existing.to_ascii_lowercase() == folded)
        || inventory.insert(name.into(), (size, hash)).is_some()
    {
        return Err("Authenticated generation inventory contains a filename collision.".into());
    }
    Ok(())
}

fn verify_authenticated_inventory(
    pinned: &PinnedGenerationDirectory,
    expected: &ExpectedInventory,
    cancelled: &impl Fn() -> bool,
) -> Result<(), String> {
    poll_cancelled(cancelled)?;
    let mut actual = BTreeSet::new();
    let mut names = directory_names_bounded(&pinned.file, expected.len().saturating_add(1))?;
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if names.len() != expected.len() {
        return Err("Authenticated Core generation inventory is not exact.".into());
    }
    for name in names {
        poll_cancelled(cancelled)?;
        let name = name
            .to_str()
            .map_err(|_| "Authenticated Core generation filename is not UTF-8.".to_string())?
            .to_owned();
        if !actual.insert(name.clone()) {
            return Err("Authenticated Core generation inventory contains a duplicate.".into());
        }
        let (expected_size, expected_hash) = expected
            .get(&name)
            .ok_or("Authenticated Core generation inventory contains an unexpected file.")?;
        verify_inventory_file(
            &pinned.file,
            &name,
            *expected_size,
            expected_hash,
            cancelled,
        )?;
    }
    if actual.len() != expected.len() || expected.keys().any(|name| !actual.contains(name)) {
        return Err("Authenticated Core generation inventory is incomplete.".into());
    }
    Ok(())
}

fn verify_inventory_file(
    parent: &File,
    name: &str,
    expected_size: u64,
    expected_hash: &str,
    cancelled: &impl Fn() -> bool,
) -> Result<(), String> {
    let name = CString::new(name)
        .map_err(|_| "Authenticated Core generation filename is unsafe.".to_string())?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(format!(
            "Could not open authenticated Core generation file: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let before = file.metadata().map_err(|error| {
        format!("Could not identify authenticated Core generation file: {error}")
    })?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != unsafe { libc::geteuid() }
        || before.permissions().mode() & 0o7777 != 0o400
        || before.len() != expected_size
    {
        return Err("Authenticated Core generation file metadata is invalid.".into());
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; INVENTORY_READ_BUFFER_BYTES];
    loop {
        poll_cancelled(cancelled)?;
        let read = file.read(&mut buffer).map_err(|error| {
            format!("Could not read authenticated Core generation file: {error}")
        })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or("Authenticated Core generation file size overflowed.")?;
        if total > expected_size {
            return Err("Authenticated Core generation file exceeds its declared size.".into());
        }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|error| {
        format!("Could not recheck authenticated Core generation file: {error}")
    })?;
    if total != expected_size
        || format!("{:x}", digest.finalize()) != expected_hash
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.nlink() != after.nlink()
        || before.uid() != after.uid()
        || before.mode() != after.mode()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("Authenticated Core generation file changed during verification.".into());
    }
    Ok(())
}

fn poll_cancelled(cancelled: &impl Fn() -> bool) -> Result<(), String> {
    if cancelled() {
        Err("Core generation activation was cancelled.".into())
    } else {
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core_generation_bootstrap::{
            authenticate_installed_bootstrap_checkpoint, expected_generation_authority,
            BootstrapAuthority, BootstrapChannel, BootstrapCheckpoint, BootstrapCompatibility,
            BootstrapPolicy, BootstrapReplayPolicy,
        },
        core_generation_contracts::{
            DiscoveryGeneration, GenerationCompatibility, GenerationDiscovery, GenerationFile,
            GenerationLock, GenerationManifest, GenerationTargetLock, DISCOVERY_SIGNATURE_SCHEME,
            MAX_LINEAGE_GENERATIONS, OPENPGP_HASH_ALGORITHM_IDS,
        },
        core_generation_verifier::{
            authenticate_discovery_snapshot, authenticate_manifest_snapshot, DetachedVerifierOutput,
        },
    };
    use std::{
        os::unix::fs::PermissionsExt as _,
        path::PathBuf,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TestGeneration {
        authenticated: AuthenticatedGeneration,
        files: BTreeMap<String, Vec<u8>>,
        identity: CoreGenerationIdentity,
    }

    struct FixtureAuthority {
        policy: BootstrapPolicy,
        policy_payload: Vec<u8>,
        keyring: Vec<u8>,
    }

    fn fixture_target(version: &str) -> GenerationTarget {
        GenerationTarget {
            steamos_version: version.into(),
            kernel_version: "6.11.11-valve1-1-neptune-611".into(),
            nvidia_version: "575.64.05".into(),
            architecture: "x86_64".into(),
        }
    }

    fn authority(seed: &str) -> FixtureAuthority {
        let keyring = format!("fixture-generation-keyring-{seed}").into_bytes();
        let policy = BootstrapPolicy {
            schema_version: 1,
            kind: "opemos-userspace-lock-bootstrap-policy".into(),
            status: "active".into(),
            policy_id: "opemos-userspace-lock-generations".into(),
            policy_schema_version: 1,
            authority: BootstrapAuthority {
                keyring_filename: "opemos-userspace-lock-generations.gpg".into(),
                keyring_sha256: sha256(&keyring),
                primary_signing_fingerprint: if seed == "primary" {
                    "A".repeat(40)
                } else {
                    "D".repeat(40)
                },
                signature_scheme: DISCOVERY_SIGNATURE_SCHEME.into(),
                allowed_hash_algorithm_ids: OPENPGP_HASH_ALGORITHM_IDS.to_vec(),
            },
            channel: BootstrapChannel {
                origin: "https://updates.opemos.invalid".into(),
                discovery_path: "/userspace-locks/reviewed/opemos-userspace-lock-discovery-v1.json"
                    .into(),
                discovery_filename: DISCOVERY_FILENAME.into(),
                discovery_signature_filename: DISCOVERY_SIGNATURE_FILENAME.into(),
                immutable_release_path_prefix: "/userspace-locks/releases/".into(),
                release_tag_prefix: "opemos-userspace-lock-generation-v1-s".into(),
                allow_redirects: false,
            },
            compatibility: BootstrapCompatibility {
                discovery_schema_versions: vec![1],
                generation_manifest_schema_versions: vec![1],
                userspace_lock_schema_versions: vec![1],
                installer_result_schema_versions: vec![1],
            },
            replay_policy: BootstrapReplayPolicy {
                require_monotonic_high_water: true,
                require_immediate_predecessor: true,
                allow_authenticated_lineage_catchup: true,
                maximum_lineage_generations: MAX_LINEAGE_GENERATIONS,
            },
        };
        let policy_payload = canonical(&policy);
        FixtureAuthority {
            policy,
            policy_payload,
            keyring,
        }
    }

    fn generation(
        authority_fixture: &FixtureAuthority,
        sequence: u64,
        previous_manifest_sha256: Option<String>,
        expected_target: &GenerationTarget,
    ) -> TestGeneration {
        let payload_name = format!("userspace-lock-{sequence}.json");
        let payload = format!("{{\"schemaVersion\":1,\"sequence\":{sequence}}}\n").into_bytes();
        let lock = GenerationLock {
            filename: payload_name.clone(),
            schema_version: 1,
            sha256: sha256(&payload),
            size: payload.len() as u64,
        };
        let target_lock = GenerationTargetLock {
            target: expected_target.clone(),
            lock: lock.clone(),
        };
        let generation_authority = expected_generation_authority(
            &authority_fixture.policy,
            &authority_fixture.policy_payload,
        )
        .unwrap();
        let manifest = GenerationManifest {
            schema_version: 1,
            kind: "opemos-userspace-lock-generation".into(),
            channel: "reviewed".into(),
            sequence,
            published_at: "2026-09-03T00:00:00Z".into(),
            authority: generation_authority.clone(),
            previous_manifest_sha256: previous_manifest_sha256.clone(),
            target_locks: vec![target_lock.clone()],
            files: vec![GenerationFile {
                role: "userspace-lock".into(),
                filename: payload_name.clone(),
                size: payload.len() as u64,
                sha256: sha256(&payload),
            }],
        };
        let manifest_payload = canonical(&manifest);
        let manifest_signature = format!("manifest-signature-{sequence}").into_bytes();
        let manifest_sha256 = sha256(&manifest_payload);
        let tag = format!("opemos-userspace-lock-generation-v1-s{sequence}");
        let discovery = GenerationDiscovery {
            schema_version: 1,
            kind: "opemos-userspace-lock-discovery".into(),
            channel: "reviewed".into(),
            sequence,
            published_at: "2026-09-03T00:00:00Z".into(),
            authority: generation_authority,
            compatibility: GenerationCompatibility {
                discovery_schema_version: 1,
                generation_manifest_schema_version: 1,
                userspace_lock_schema_version: 1,
                minimum_installer_result_schema_version: 1,
            },
            generation: DiscoveryGeneration {
                release_tag: tag.clone(),
                manifest_filename: format!("{tag}.manifest.json"),
                manifest_sha256: manifest_sha256.clone(),
                manifest_size: manifest_payload.len() as u64,
                signature_filename: format!("{tag}.manifest.json.sig"),
                signature_sha256: sha256(&manifest_signature),
                signature_size: manifest_signature.len() as u64,
                previous_manifest_sha256,
            },
            targets: vec![target_lock],
        };
        let discovery_payload = canonical(&discovery);
        let discovery_signature = format!("discovery-signature-{sequence}").into_bytes();
        let fingerprint = authority_fixture
            .policy
            .authority
            .primary_signing_fingerprint
            .clone();
        let pending = authenticate_discovery_snapshot(
            &authority_fixture.policy_payload,
            &authority_fixture.keyring,
            &discovery_payload,
            &discovery_signature,
            &|| false,
            |_payload, _signature, _keyring, _fingerprint, _cancelled| {
                Ok(valid_verifier_output(&fingerprint))
            },
        )
        .unwrap();
        let authenticated = authenticate_manifest_snapshot(
            pending,
            &manifest_payload,
            &manifest_signature,
            &|| false,
            |_payload, _signature, _keyring, _fingerprint, _cancelled| {
                Ok(valid_verifier_output(&fingerprint))
            },
        )
        .unwrap();
        let evidence = authenticated.canonical_evidence_bytes().unwrap();
        let mut files = BTreeMap::from([
            (DISCOVERY_FILENAME.into(), discovery_payload),
            (DISCOVERY_SIGNATURE_FILENAME.into(), discovery_signature),
            (
                discovery.generation.manifest_filename.clone(),
                manifest_payload,
            ),
            (
                discovery.generation.signature_filename.clone(),
                manifest_signature,
            ),
            (TRUST_RECORD_FILENAME.into(), evidence),
            (payload_name, payload),
        ]);
        assert_eq!(
            files.len(),
            expected_authenticated_inventory(&authenticated)
                .unwrap()
                .len()
        );
        let identity = CoreGenerationIdentity {
            sequence,
            generation_id: manifest_sha256.clone(),
            manifest_sha256,
        };
        TestGeneration {
            authenticated,
            files: std::mem::take(&mut files),
            identity,
        }
    }

    fn valid_verifier_output(fingerprint: &str) -> DetachedVerifierOutput {
        DetachedVerifierOutput {
            exit_status: 0,
            status: format!(
                "[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG {0} 2026-09-03 1788436800 0 4 0 1 8 00 {0}\n",
                fingerprint
            )
            .into_bytes(),
        }
    }

    fn canonical<T: serde::Serialize>(value: &T) -> Vec<u8> {
        let value = serde_json::to_value(value).unwrap();
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn checkpoint(
        authority_fixture: &FixtureAuthority,
        bootstrap: &TestGeneration,
    ) -> AuthenticatedBootstrapCheckpoint {
        let payload = canonical(&BootstrapCheckpoint {
            schema_version: 1,
            kind: "opemos-userspace-lock-bootstrap-checkpoint".into(),
            policy_sha256: sha256(&authority_fixture.policy_payload),
            minimum_sequence: bootstrap.identity.sequence,
            minimum_manifest_sha256: bootstrap.identity.manifest_sha256.clone(),
        });
        authenticate_installed_bootstrap_checkpoint(
            &payload,
            &sha256(&payload),
            &bootstrap.authenticated,
        )
        .unwrap()
    }

    fn temporary_cache(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "opemos-activation-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn stage(cache: &CoreGenerationCache, generation: &TestGeneration, operation: &str) {
        let reservation = generation
            .files
            .values()
            .map(|bytes| bytes.len() as u64)
            .sum();
        cache
            .stage_candidate(
                operation,
                reservation,
                &generation.identity,
                |root| {
                    for (name, bytes) in &generation.files {
                        let mut options = OpenOptions::new();
                        options.write(true).create_new(true).mode(0o600);
                        let mut file = options.open(root.join(name)).map_err(|e| e.to_string())?;
                        file.write_all(bytes).map_err(|e| e.to_string())?;
                        file.sync_all().map_err(|e| e.to_string())?;
                    }
                    Ok(())
                },
                |_root| Ok(()),
            )
            .unwrap();
    }

    fn acknowledge(
        cache: &CoreGenerationCache,
        generation: &TestGeneration,
        state: &CoreGenerationCacheState,
        operation: &str,
    ) {
        let inventory = expected_authenticated_inventory(&generation.authenticated).unwrap();
        cache
            .acknowledge_healthy(&generation.identity, operation, state.revision, |root| {
                let pinned = pin_generation_directory(root, "test authenticated generation")?;
                verify_authenticated_inventory(&pinned, &inventory, &|| false)
            })
            .unwrap();
    }

    fn cleanup(root: &Path) {
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
        make_writable(root);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sealed_bridge_covers_fresh_forward_and_lineage_catchup() {
        let root = temporary_cache("progression");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let trust = authority("primary");
        let target = fixture_target("3.8.14");
        let first = generation(&trust, 1, None, &target);
        let checkpoint = checkpoint(&trust, &first);
        stage(&cache, &first, "stage-first");
        let pending = begin_authenticated_activation(
            &cache,
            &first.authenticated,
            &checkpoint,
            &target,
            &[],
            "activate-first",
            || false,
        )
        .unwrap();
        assert_eq!(pending.pending.as_ref(), Some(&first.identity));
        acknowledge(&cache, &first, &pending, "activate-first");

        let second = generation(
            &trust,
            2,
            Some(first.identity.manifest_sha256.clone()),
            &target,
        );
        stage(&cache, &second, "stage-second");
        let pending = begin_authenticated_activation(
            &cache,
            &second.authenticated,
            &checkpoint,
            &target,
            &[],
            "activate-second",
            || false,
        )
        .unwrap();
        acknowledge(&cache, &second, &pending, "activate-second");

        let third = generation(
            &trust,
            3,
            Some(second.identity.manifest_sha256.clone()),
            &target,
        );
        let fourth = generation(
            &trust,
            4,
            Some(third.identity.manifest_sha256.clone()),
            &target,
        );
        stage(&cache, &fourth, "stage-fourth");
        let pending = begin_authenticated_activation(
            &cache,
            &fourth.authenticated,
            &checkpoint,
            &target,
            &[&third.authenticated],
            "activate-fourth",
            || false,
        )
        .unwrap();
        assert_eq!(pending.pending.as_ref(), Some(&fourth.identity));
        cleanup(&root);
    }

    #[test]
    fn sealed_bridge_rejects_wrong_trust_target_and_lineage() {
        let root = temporary_cache("authorization");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let primary = authority("primary");
        let rotated = authority("rotated");
        let target = fixture_target("3.8.14");
        let first = generation(&primary, 1, None, &target);
        let checkpoint = checkpoint(&primary, &first);
        let rotated_first = generation(&rotated, 1, None, &target);
        assert!(begin_authenticated_activation(
            &cache,
            &rotated_first.authenticated,
            &checkpoint,
            &target,
            &[],
            "activate-rotated",
            || false,
        )
        .is_err());

        stage(&cache, &first, "stage-first");
        assert!(begin_authenticated_activation(
            &cache,
            &first.authenticated,
            &checkpoint,
            &fixture_target("3.8.15"),
            &[],
            "activate-wrong-target",
            || false,
        )
        .is_err());
        let third = generation(&primary, 3, Some("1".repeat(64)), &target);
        stage(&cache, &third, "stage-third");
        assert!(begin_authenticated_activation(
            &cache,
            &third.authenticated,
            &checkpoint,
            &target,
            &[],
            "activate-broken-lineage",
            || false,
        )
        .is_err());

        let second = generation(
            &primary,
            2,
            Some(first.identity.manifest_sha256.clone()),
            &target,
        );
        let third = generation(
            &primary,
            3,
            Some(second.identity.manifest_sha256.clone()),
            &target,
        );
        let fourth = generation(
            &primary,
            4,
            Some(third.identity.manifest_sha256.clone()),
            &target,
        );
        assert!(begin_authenticated_activation(
            &cache,
            &fourth.authenticated,
            &checkpoint,
            &target,
            &[&third.authenticated, &second.authenticated],
            "activate-reordered-lineage",
            || false,
        )
        .is_err());
        let rotated_second = generation(
            &rotated,
            2,
            Some(first.identity.manifest_sha256.clone()),
            &target,
        );
        assert!(begin_authenticated_activation(
            &cache,
            &third.authenticated,
            &checkpoint,
            &target,
            &[&rotated_second.authenticated],
            "activate-mixed-lineage",
            || false,
        )
        .is_err());
        let excessive = (0..=MAX_LINEAGE_GENERATIONS)
            .map(|_| &second.authenticated)
            .collect::<Vec<_>>();
        assert!(begin_authenticated_activation(
            &cache,
            &third.authenticated,
            &checkpoint,
            &target,
            &excessive,
            "activate-excessive-lineage",
            || false,
        )
        .is_err());
        cleanup(&root);
    }

    #[test]
    fn sealed_bridge_requires_exact_committed_inventory() {
        for case in [
            "uncommitted",
            "missing",
            "tampered",
            "extra",
            "mismatch",
            "fifo",
        ] {
            let root = temporary_cache(case);
            let cache = CoreGenerationCache::open(&root).unwrap();
            let trust = authority("primary");
            let target = fixture_target("3.8.14");
            let generation = generation(&trust, 1, None, &target);
            let checkpoint = checkpoint(&trust, &generation);
            if case == "uncommitted" {
                let generation_root = root
                    .join("generations")
                    .join(&generation.identity.generation_id);
                fs::create_dir(&generation_root).unwrap();
                fs::set_permissions(&generation_root, fs::Permissions::from_mode(0o500)).unwrap();
            } else {
                stage(&cache, &generation, "stage-generation");
                let generation_root = root
                    .join("generations")
                    .join(&generation.identity.generation_id);
                if case == "missing" {
                    fs::set_permissions(&generation_root, fs::Permissions::from_mode(0o700))
                        .unwrap();
                    fs::remove_file(generation_root.join("userspace-lock-1.json")).unwrap();
                    fs::set_permissions(&generation_root, fs::Permissions::from_mode(0o500))
                        .unwrap();
                } else if case == "tampered" {
                    let path = generation_root.join("userspace-lock-1.json");
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::write(&path, b"tampered").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
                } else if case == "extra" {
                    fs::set_permissions(&generation_root, fs::Permissions::from_mode(0o700))
                        .unwrap();
                    fs::write(generation_root.join("extra"), b"extra").unwrap();
                    fs::set_permissions(
                        generation_root.join("extra"),
                        fs::Permissions::from_mode(0o400),
                    )
                    .unwrap();
                    fs::set_permissions(&generation_root, fs::Permissions::from_mode(0o500))
                        .unwrap();
                } else {
                    let path = generation_root.join(TRUST_RECORD_FILENAME);
                    if case == "fifo" {
                        fs::set_permissions(&generation_root, fs::Permissions::from_mode(0o700))
                            .unwrap();
                        fs::remove_file(&path).unwrap();
                        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
                        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o400) }, 0);
                        fs::set_permissions(&generation_root, fs::Permissions::from_mode(0o500))
                            .unwrap();
                    } else {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    }
                }
            }
            assert!(begin_authenticated_activation(
                &cache,
                &generation.authenticated,
                &checkpoint,
                &target,
                &[],
                "activate-generation",
                || false,
            )
            .is_err());
            assert_eq!(cache.load_state().unwrap().pending, None);
            cleanup(&root);
        }
    }

    #[test]
    fn pending_activation_is_idempotent_only_for_exact_operation() {
        let root = temporary_cache("pending");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let trust = authority("primary");
        let target = fixture_target("3.8.14");
        let first = generation(&trust, 1, None, &target);
        let checkpoint = checkpoint(&trust, &first);
        stage(&cache, &first, "stage-first");
        let pending = begin_authenticated_activation(
            &cache,
            &first.authenticated,
            &checkpoint,
            &target,
            &[],
            "same-operation",
            || false,
        )
        .unwrap();
        let repeated = begin_authenticated_activation(
            &cache,
            &first.authenticated,
            &checkpoint,
            &target,
            &[],
            "same-operation",
            || false,
        )
        .unwrap();
        assert_eq!(pending, repeated);
        assert!(begin_authenticated_activation(
            &cache,
            &first.authenticated,
            &checkpoint,
            &target,
            &[],
            "different-operation",
            || false,
        )
        .is_err());
        cleanup(&root);
    }

    #[test]
    fn cancellation_before_lock_and_before_save_preserves_state() {
        let root = temporary_cache("cancellation");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let trust = authority("primary");
        let target = fixture_target("3.8.14");
        let first = generation(&trust, 1, None, &target);
        let checkpoint = checkpoint(&trust, &first);
        stage(&cache, &first, "stage-first");
        assert!(begin_authenticated_activation(
            &cache,
            &first.authenticated,
            &checkpoint,
            &target,
            &[],
            "cancel-before-lock",
            || true,
        )
        .is_err());
        let calls = AtomicUsize::new(0);
        assert!(begin_authenticated_activation(
            &cache,
            &first.authenticated,
            &checkpoint,
            &target,
            &[],
            "cancel-after-lock",
            || calls.fetch_add(1, Ordering::SeqCst) >= 1,
        )
        .is_err());
        let cancel = AtomicBool::new(false);
        assert!(begin_authenticated_activation_with_hook(
            &cache,
            &first.authenticated,
            &checkpoint,
            &target,
            &[],
            "cancel-before-save",
            || cancel.load(Ordering::SeqCst),
            |phase| {
                if phase == "before-state-save" {
                    cancel.store(true, Ordering::SeqCst);
                }
            },
        )
        .is_err());
        cancel.store(false, Ordering::SeqCst);
        assert!(begin_authenticated_activation_with_hook(
            &cache,
            &first.authenticated,
            &checkpoint,
            &target,
            &[],
            "cancel-final-boundary",
            || cancel.load(Ordering::SeqCst),
            |phase| {
                if phase == "final-cancellation-boundary" {
                    cancel.store(true, Ordering::SeqCst);
                }
            },
        )
        .is_err());
        let inside_inventory = AtomicBool::new(false);
        let inventory_polls = AtomicUsize::new(0);
        assert!(begin_authenticated_activation_with_hook(
            &cache,
            &first.authenticated,
            &checkpoint,
            &target,
            &[],
            "cancel-during-inventory",
            || {
                inside_inventory.load(Ordering::SeqCst)
                    && inventory_polls.fetch_add(1, Ordering::SeqCst) >= 2
            },
            |phase| {
                if phase == "after-pin-before-inventory" {
                    inside_inventory.store(true, Ordering::SeqCst);
                }
            },
        )
        .is_err());
        assert_eq!(
            cache.load_state().unwrap(),
            CoreGenerationCacheState::default()
        );
        cleanup(&root);
    }

    #[test]
    fn two_cache_handles_serialize_pending_authorization() {
        let root = temporary_cache("concurrency");
        let first_cache = CoreGenerationCache::open(&root).unwrap();
        let second_cache = CoreGenerationCache::open(&root).unwrap();
        let trust = authority("primary");
        let target = fixture_target("3.8.14");
        let first = generation(&trust, 1, None, &target);
        let second = generation(
            &trust,
            2,
            Some(first.identity.manifest_sha256.clone()),
            &target,
        );
        let checkpoint_payload = canonical(&BootstrapCheckpoint {
            schema_version: 1,
            kind: "opemos-userspace-lock-bootstrap-checkpoint".into(),
            policy_sha256: sha256(&trust.policy_payload),
            minimum_sequence: first.identity.sequence,
            minimum_manifest_sha256: first.identity.manifest_sha256.clone(),
        });
        stage(&first_cache, &first, "stage-race-first");
        stage(&first_cache, &second, "stage-race-second");

        let trust_digest = sha256(&checkpoint_payload);
        let first_checkpoint = authenticate_installed_bootstrap_checkpoint(
            &checkpoint_payload,
            &trust_digest,
            &first.authenticated,
        )
        .unwrap();
        let second_checkpoint = authenticate_installed_bootstrap_checkpoint(
            &checkpoint_payload,
            &trust_digest,
            &second.authenticated,
        )
        .unwrap();
        let first_target = target.clone();
        let second_target = target.clone();
        let first_thread = std::thread::spawn(move || {
            begin_authenticated_activation(
                &first_cache,
                &first.authenticated,
                &first_checkpoint,
                &first_target,
                &[],
                "race-first",
                || false,
            )
        });
        let second_thread = std::thread::spawn(move || {
            begin_authenticated_activation(
                &second_cache,
                &second.authenticated,
                &second_checkpoint,
                &second_target,
                &[],
                "race-second",
                || false,
            )
        });
        let outcomes = [first_thread.join().unwrap(), second_thread.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|result| result.is_err()).count(), 1);
        let durable = CoreGenerationCache::open(&root)
            .unwrap()
            .load_state()
            .unwrap();
        assert!(durable.pending.is_some());
        assert_eq!(durable.revision, 1);
        assert_eq!(durable.high_water_sequence, 0);
        assert_eq!(durable.active, None);
        assert_eq!(durable.last_known_good, None);
        cleanup(&root);
    }

    #[test]
    fn replay_after_rollback_is_rejected_by_durable_high_water() {
        let root = temporary_cache("rollback-replay");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let trust = authority("primary");
        let target = fixture_target("3.8.14");
        let first = generation(&trust, 1, None, &target);
        let checkpoint = checkpoint(&trust, &first);
        let second = generation(
            &trust,
            2,
            Some(first.identity.manifest_sha256.clone()),
            &target,
        );
        stage(&cache, &first, "stage-first");
        stage(&cache, &second, "stage-second");
        let first_pending = begin_authenticated_activation(
            &cache,
            &first.authenticated,
            &checkpoint,
            &target,
            &[],
            "activate-first",
            || false,
        )
        .unwrap();
        acknowledge(&cache, &first, &first_pending, "activate-first");
        let second_pending = begin_authenticated_activation(
            &cache,
            &second.authenticated,
            &checkpoint,
            &target,
            &[],
            "activate-second",
            || false,
        )
        .unwrap();
        let second_active = cache
            .acknowledge_healthy(
                &second.identity,
                "activate-second",
                second_pending.revision,
                |root| {
                    let pinned = pin_generation_directory(root, "test second generation")?;
                    verify_authenticated_inventory(
                        &pinned,
                        &expected_authenticated_inventory(&second.authenticated)?,
                        &|| false,
                    )
                },
            )
            .unwrap();
        let rolled_back = cache
            .rollback_to_last_known_good(&second.identity, second_active.revision, |root| {
                let pinned = pin_generation_directory(root, "test first generation")?;
                verify_authenticated_inventory(
                    &pinned,
                    &expected_authenticated_inventory(&first.authenticated)?,
                    &|| false,
                )
            })
            .unwrap();
        assert_eq!(rolled_back.high_water_sequence, 2);
        assert_eq!(rolled_back.active.as_ref(), Some(&first.identity));
        assert!(begin_authenticated_activation(
            &cache,
            &second.authenticated,
            &checkpoint,
            &target,
            &[],
            "replay-second",
            || false,
        )
        .is_err());
        assert_eq!(cache.load_state().unwrap(), rolled_back);
        cleanup(&root);
    }

    #[test]
    fn inventory_verification_is_bound_to_the_outer_pinned_directory() {
        let root = temporary_cache("swap-restore");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let trust = authority("primary");
        let target = fixture_target("3.8.14");
        let generation = generation(&trust, 1, None, &target);
        let checkpoint = checkpoint(&trust, &generation);
        stage(&cache, &generation, "stage-generation");
        let generations = root.join("generations");
        let live = generations.join(&generation.identity.generation_id);
        let authenticated_replacement = generations.join("authenticated-replacement");
        let pinned_original = generations.join("pinned-original");
        fs::create_dir(&authenticated_replacement).unwrap();
        fs::set_permissions(
            &authenticated_replacement,
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        for (name, bytes) in &generation.files {
            let path = authenticated_replacement.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
        }
        fs::set_permissions(
            &authenticated_replacement,
            fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        let payload = live.join("userspace-lock-1.json");
        let original = fs::read(&payload).unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&payload, vec![b'X'; original.len()]).unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o400)).unwrap();

        let swapped = AtomicBool::new(false);
        let result = begin_authenticated_activation_with_hook(
            &cache,
            &generation.authenticated,
            &checkpoint,
            &target,
            &[],
            "swap-before-inventory",
            || false,
            |phase| {
                if phase == "after-pin-before-inventory" {
                    fs::rename(&live, &pinned_original).unwrap();
                    fs::rename(&authenticated_replacement, &live).unwrap();
                    swapped.store(true, Ordering::SeqCst);
                } else if phase == "after-first-inventory" {
                    fs::rename(&live, &authenticated_replacement).unwrap();
                    fs::rename(&pinned_original, &live).unwrap();
                    swapped.store(false, Ordering::SeqCst);
                }
            },
        );
        if swapped.load(Ordering::SeqCst) {
            fs::rename(&live, &authenticated_replacement).unwrap();
            fs::rename(&pinned_original, &live).unwrap();
        }
        assert!(result.is_err());
        assert_eq!(cache.load_state().unwrap().pending, None);
        cleanup(&root);
    }

    #[test]
    fn cached_generation_change_before_save_is_rejected() {
        let root = temporary_cache("race");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let trust = authority("primary");
        let target = fixture_target("3.8.14");
        let first = generation(&trust, 1, None, &target);
        let checkpoint = checkpoint(&trust, &first);
        stage(&cache, &first, "stage-first");
        let file = root
            .join("generations")
            .join(&first.identity.generation_id)
            .join("userspace-lock-1.json");
        assert!(begin_authenticated_activation_with_hook(
            &cache,
            &first.authenticated,
            &checkpoint,
            &target,
            &[],
            "race-before-save",
            || false,
            |phase| {
                if phase == "before-state-save" {
                    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::write(&file, b"changed during activation").unwrap();
                    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
                }
            },
        )
        .is_err());
        assert_eq!(cache.load_state().unwrap().pending, None);
        cleanup(&root);
    }
}

use super::*;
use serde::de::DeserializeSeed as _;

const MAX_SUPPORT_INSTALL_RESULT_BYTES: u64 = 32 * 1024 * 1024;

struct UniqueJson;

impl<'de> serde::de::DeserializeSeed<'de> for UniqueJson {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> serde::de::Visitor<'de> for UniqueJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_some<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        UniqueJson.deserialize(deserializer)
    }
    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        while sequence.next_element_seed(UniqueJson)?.is_some() {}
        Ok(())
    }
    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            map.next_value_seed(UniqueJson)?;
        }
        Ok(())
    }
}

fn reject_duplicate_json_keys(bytes: &[u8]) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    UniqueJson
        .deserialize(&mut deserializer)
        .map_err(|error| format!("NVIDIA installer result is invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("NVIDIA installer result is invalid JSON: {error}"))
}

pub(crate) fn read_support_install_result(path: &Path) -> Result<SupportInstallResult, String> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect the NVIDIA installer result: {error}"))?;
    if !path_metadata.file_type().is_file()
        || path_metadata.len() == 0
        || path_metadata.len() > MAX_SUPPORT_INSTALL_RESULT_BYTES
    {
        return Err("NVIDIA installer result is linked, empty, or exceeds 32 MiB.".into());
    }
    let file = File::open(path)
        .map_err(|error| format!("Could not open the NVIDIA installer result: {error}"))?;
    let opened_metadata = file.metadata().map_err(|error| {
        format!("Could not inspect the opened NVIDIA installer result: {error}")
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != opened_metadata.dev()
            || path_metadata.ino() != opened_metadata.ino()
        {
            return Err("NVIDIA installer result changed while being opened.".into());
        }
    }
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.take(MAX_SUPPORT_INSTALL_RESULT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Could not read the NVIDIA installer result: {error}"))?;
    if bytes.len() as u64 != opened_metadata.len()
        || bytes.len() as u64 > MAX_SUPPORT_INSTALL_RESULT_BYTES
    {
        return Err("NVIDIA installer result changed size while being read.".into());
    }
    reject_duplicate_json_keys(&bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("NVIDIA installer result is invalid JSON: {error}"))
}

pub(crate) fn collect_nvidia_install_inputs(
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

pub(crate) fn validate_on_demand_build_plan(session: &ApplianceSession) -> Result<(), String> {
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

pub(crate) fn start_nvidia_install_appliance_blocking(
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
pub(crate) async fn start_nvidia_install_appliance(
    app: tauri::AppHandle,
) -> Result<NvidiaBuildStatus, String> {
    tauri::async_runtime::spawn_blocking(move || start_nvidia_install_appliance_blocking(app))
        .await
        .map_err(|error| format!("NVIDIA installer-appliance startup worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn build_nvidia_target_on_demand(
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
pub(crate) async fn publish_on_demand_nvidia_release(
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

pub(crate) fn validate_support_storage(
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
            || compression.pacman_check_space_bypass_authorized != expect_sufficient
            || compression.pacman_check_space_policy
                != if expect_sufficient {
                    "temporary-config-disable-after-live-revalidation"
                } else {
                    "preserve"
                }
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
            || compression.pacman_check_space_bypass_authorized
            || compression.pacman_check_space_policy != "preserve"
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

pub(crate) fn validate_nvidia_storage_failure(
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

pub(crate) fn human_bytes(bytes: u64) -> String {
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

pub(crate) fn concise_json_value(value: &serde_json::Value) -> String {
    const LIMIT: usize = 160;
    let rendered = serde_json::to_string(value).unwrap_or_else(|_| "<invalid>".into());
    if rendered.chars().count() <= LIMIT {
        return rendered;
    }
    let mut concise: String = rendered.chars().take(LIMIT).collect();
    concise.push('…');
    concise
}

pub(crate) fn valid_support_measurement_failure(detail: &SupportInstallMeasurementFailure) -> bool {
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

pub(crate) fn support_install_failure_message(document: &SupportInstallResult) -> String {
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

pub(crate) fn validate_nvidia_install_result(
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
        || document.cleanup.runtime_mounts_expected > 64
        || document.cleanup.runtime_mounts_expected != document.cleanup.runtime_mounts_released
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
        let mismatched_fields = [
            (validated.name != expected.name, "name"),
            (
                validated.filename != expected.filename || validated.filename != locked.filename,
                "filename",
            ),
            (
                validated.signature_filename != locked.signature_filename,
                "signatureFilename",
            ),
            (
                validated.full_version != expected.full_version
                    || validated.full_version != locked.version,
                "fullVersion",
            ),
            (
                validated.role != expected.role || validated.role != expected_role,
                "role",
            ),
            (
                validated.architecture != locked.architecture,
                "architecture",
            ),
            (
                validated.sha256 != expected.package_sha256
                    || validated.sha256 != locked.package_sha256,
                "sha256",
            ),
            (
                validated.signature_sha256 != locked.signature_sha256,
                "signatureSha256",
            ),
            (
                validated.installed_size != locked.installed_size,
                "installedSize",
            ),
            (
                !package_relations_match(&validated.dependencies, &locked.dependencies),
                "dependencies",
            ),
            (
                !package_relations_match(&validated.provides, &locked.provides),
                "provides",
            ),
            (validated.pkgrel.is_empty(), "pkgrel"),
            (validated.signer != locked.signer_fingerprint, "signer"),
        ]
        .into_iter()
        .filter_map(|(mismatched, field)| mismatched.then_some(field))
        .collect::<Vec<_>>();
        if !mismatched_fields.is_empty() {
            return Err(format!(
                "Offline validation metadata does not match staged {} fields: {}.",
                expected.name,
                mismatched_fields.join(", ")
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

pub(crate) fn copy_install_input_to_guest(
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

pub(crate) fn nvidia_handoff_checksum(archive_sha256: &str) -> Result<String, String> {
    if archive_sha256.len() != 64 || !archive_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Verified NVIDIA archive SHA-256 is invalid.".into());
    }
    Ok(format!(
        "{}  nvidia-modules.tar.gz\n",
        archive_sha256.to_ascii_lowercase()
    ))
}

pub(crate) fn stage_nvidia_handoff_checksum(
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

pub(crate) fn safe_regular_file_size(path: &Path, description: &str) -> Result<u64, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect {description}: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{description} is not a safe regular file."));
    }
    Ok(metadata.len())
}

pub(crate) fn checked_space_sum(parts: impl IntoIterator<Item = u64>) -> Result<u64, String> {
    parts
        .into_iter()
        .try_fold(0_u64, |total, value| total.checked_add(value))
        .ok_or_else(|| "Free-space estimate overflowed.".into())
}

pub(crate) fn nvidia_handoff_space_requirement(
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

pub(crate) fn require_guest_free_space(
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

pub(crate) fn guest_userspace_filenames(
    package: &NvidiaUserspacePackage,
) -> Result<(String, String), String> {
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

pub(crate) fn userspace_installer_arguments(
    packages: &[NvidiaUserspacePackage],
) -> Result<String, String> {
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

pub(crate) fn validate_nvidia_install_handoff_blocking(
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
        let document = read_support_install_result(&staged_result)?;
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
pub(crate) async fn validate_nvidia_install_handoff(
    app: tauri::AppHandle,
) -> Result<NvidiaInstallHandoffResult, String> {
    tauri::async_runtime::spawn_blocking(move || validate_nvidia_install_handoff_blocking(app))
        .await
        .map_err(|error| format!("NVIDIA installer validation worker failed: {error}"))?
}

pub(crate) fn install_nvidia_to_working_image_blocking(
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
    let mutation_attempt = 2_usize;
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
sudo env TMPDIR=/var/tmp bash "$WORK/support/bootstrap/install_to_root.sh" --compression-profile {compression_profile} --root "$ROOT" --archive /tmp/nvidia-modules.tar.gz --checksum /tmp/nvidia-modules.tar.gz.sha256 --provenance /tmp/nvidia-modules.provenance.json --kernel {kernel}{userspace_arguments} --package-keyring "$WORK/support/{keyring_path}" --userspace-lock "$WORK/support/{lock_path}" --progress-attempt {mutation_attempt} --result-json "$WORK/install-mutation-result.json"
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
        mutation_attempt = mutation_attempt,
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
    let document = read_support_install_result(&staged_result)?;
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
pub(crate) async fn install_nvidia_to_working_image(
    app: tauri::AppHandle,
) -> Result<NvidiaInstallHandoffResult, String> {
    tauri::async_runtime::spawn_blocking(move || install_nvidia_to_working_image_blocking(app))
        .await
        .map_err(|error| format!("NVIDIA offline installation worker failed: {error}"))?
}

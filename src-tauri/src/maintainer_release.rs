use super::*;

const RELEASE_RESULT_LIMIT: usize = 1024 * 1024;

fn imported_publisher_rejection(stderr: &[u8]) -> String {
    if stderr.len() > RELEASE_RESULT_LIMIT {
        return "Pinned Core publisher rejected the imported product; its diagnostic exceeded the output limit.".into();
    }
    let detail = String::from_utf8_lossy(stderr).trim().to_string();
    if detail.is_empty() {
        "Pinned Core publisher rejected the imported product.".into()
    } else {
        format!("Pinned Core publisher rejected the imported product: {detail}")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MaintainerReleaseAuthorization {
    operation_id: String,
    attempt: u64,
    decision: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MaintainerReleaseRequest {
    operation_id: String,
    attempt: u64,
    authorization: Option<MaintainerReleaseAuthorization>,
}

#[derive(Clone)]
struct ReleaseRuntime {
    support_root: PathBuf,
    state: PathBuf,
    plan: PathBuf,
    inputs: Option<[PathBuf; 4]>,
}

#[derive(Default)]
pub(crate) struct MaintainerReleaseManager {
    imported: Option<ReleaseRuntime>,
}

fn write_create_or_exact(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| format!("Could not write {label}: {error}"))?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if fs::read(path).map_err(|error| format!("Could not read {label}: {error}"))? == bytes
            {
                Ok(())
            } else {
                Err(format!(
                    "Existing {label} does not match the exact release plan."
                ))
            }
        }
        Err(error) => Err(format!("Could not create {label}: {error}")),
    }
}

fn release_runtime(app: &tauri::AppHandle) -> Result<ReleaseRuntime, String> {
    if let Some(runtime) = app
        .state::<Mutex<MaintainerReleaseManager>>()
        .lock()
        .map_err(|_| "Maintainer release state lock is unavailable.")?
        .imported
        .clone()
    {
        return Ok(runtime);
    }
    let (publication, artifact, plan, runtime_dir) = {
        let manager_state = app.state::<Mutex<ApplianceManager>>();
        let manager = manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        let session = manager
            .session
            .as_ref()
            .ok_or("Build and validate the exact NVIDIA product before preparing its release.")?;
        let resolution = session
            .nvidia_resolution
            .as_ref()
            .filter(|value| value.status == "compatible" && value.reason == "on_demand_artifact_verified")
            .ok_or("Only a newly built and verified exact-target NVIDIA product may be prepared for release.")?;
        (
            resolution
                .publication
                .clone()
                .ok_or("Verified product omitted release identity.")?,
            resolution
                .artifact
                .clone()
                .ok_or("Verified product omitted release assets.")?,
            resolution
                .build_plan
                .clone()
                .ok_or("Verified product omitted its build plan.")?,
            session.runtime_dir.clone(),
        )
    };
    if artifact.trust != "locally-built-verified"
        || plan.expected_trust != "locally-built-verified"
        || plan.support_commit != NVIDIA_SUPPORT_BUILD_COMMIT
        || publication.steamos_version != plan.steamos_version
        || publication.kernel_version != plan.kernel_version
        || publication.nvidia_version != plan.nvidia_version
    {
        return Err("Verified product no longer satisfies the exact release contract.".into());
    }
    let identity = PublishedReleaseIdentity {
        steamos_version: plan.steamos_version,
        kernel_version: plan.kernel_version,
        nvidia_version: plan.nvidia_version,
        tag: format!(
            "steamos-{}-nvidia-{}-k{}",
            publication.steamos_version, publication.nvidia_version, publication.kernel_version
        ),
    };
    let archive = fs::canonicalize(&artifact.archive_path)
        .map_err(|error| format!("Could not resolve release archive: {error}"))?;
    let checksum = fs::canonicalize(&artifact.checksum_path)
        .map_err(|error| format!("Could not resolve release checksum: {error}"))?;
    let build_info = fs::canonicalize(
        artifact
            .build_info_path
            .as_deref()
            .ok_or("Verified product omitted build metadata.")?,
    )
    .map_err(|error| format!("Could not resolve release build metadata: {error}"))?;
    let provenance = fs::canonicalize(&artifact.provenance_path)
        .map_err(|error| format!("Could not resolve release provenance: {error}"))?;
    let support_root = prepare_pinned_nvidia_publisher(&runtime_dir)?;
    let output = support_publisher_command(
        &support_root.join("bootstrap/publish_artifacts.sh"),
        &archive,
        &checksum,
        &build_info,
        &provenance,
    )
    .arg("--dry-run")
    .output()
    .map_err(|error| format!("Could not prepare the pinned release plan: {error}"))?;
    if !output.status.success() || output.stdout.len() > RELEASE_RESULT_LIMIT {
        return Err("Pinned Core publisher rejected the bounded release plan.".into());
    }
    let publication_plan: SupportPublicationPlan =
        serde_json::from_slice(&output.stdout).map_err(|error| {
            format!("Pinned Core publisher returned an invalid release plan: {error}")
        })?;
    let expected =
        [archive, checksum, build_info, provenance].map(|path| path.to_string_lossy().into_owned());
    validate_support_publication_plan(
        &publication_plan,
        &identity,
        &artifact.archive_sha256,
        &expected,
    )?;
    let plan_path = runtime_dir.join("maintainer-release-plan.json");
    write_create_or_exact(&plan_path, &output.stdout, "maintainer release plan")?;
    Ok(ReleaseRuntime {
        support_root,
        state: runtime_dir.join("maintainer-release-operation.json"),
        plan: plan_path,
        inputs: None,
    })
}

fn discover_imported_release_inputs(directory: &Path) -> Result<[PathBuf; 4], String> {
    if !fs::symlink_metadata(directory)
        .map(|value| value.file_type().is_dir())
        .unwrap_or(false)
    {
        return Err("Verified product selection must be one real directory.".into());
    }
    let directory = fs::canonicalize(directory)
        .map_err(|error| format!("Could not resolve the verified product folder: {error}"))?;
    let mut archive = None;
    let mut checksum = None;
    let mut build_info = None;
    let mut provenance = None;
    let mut count = 0usize;
    for entry in fs::read_dir(&directory)
        .map_err(|error| format!("Could not inspect verified product folder: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("Could not inspect verified product entry: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("Could not inspect verified product entry: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err(
                "Verified product folder may contain only four regular publisher inputs.".into(),
            );
        }
        count += 1;
        let path = fs::canonicalize(entry.path())
            .map_err(|error| format!("Could not resolve verified product entry: {error}"))?;
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or("Verified product filename is not UTF-8.")?;
        let slot = if name.ends_with(".tar.gz.sha256") {
            &mut checksum
        } else if name.ends_with(".tar.gz") {
            &mut archive
        } else if name.ends_with(".build-info.txt") {
            &mut build_info
        } else if name.ends_with(".provenance.json") {
            &mut provenance
        } else {
            return Err("Verified product folder contains an unexpected file.".into());
        };
        if slot.replace(path).is_some() {
            return Err("Verified product folder contains duplicate publisher inputs.".into());
        }
    }
    if count != 4 {
        return Err("Verified product folder must contain exactly four publisher inputs.".into());
    }
    Ok([
        archive.ok_or("Release archive is missing.")?,
        checksum.ok_or("Release checksum is missing.")?,
        build_info.ok_or("Release build-info is missing.")?,
        provenance.ok_or("Release provenance is missing.")?,
    ])
}

fn imported_release_runtime(
    app: &tauri::AppHandle,
    directory: &Path,
) -> Result<ReleaseRuntime, String> {
    let inputs = discover_imported_release_inputs(directory)?;
    let actual = sha256_file(&inputs[0])?;
    let runtime_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("Could not resolve application data: {error}"))?
        .join("maintainer-release-import")
        .join(&actual);
    fs::create_dir_all(&runtime_dir)
        .map_err(|error| format!("Could not create maintainer release state: {error}"))?;
    let support_root = prepare_pinned_nvidia_publisher(&runtime_dir)?;
    let output = support_publisher_command(
        &support_root.join("bootstrap/publish_artifacts.sh"),
        &inputs[0],
        &inputs[1],
        &inputs[2],
        &inputs[3],
    )
    .arg("--dry-run")
    .output()
    .map_err(|error| format!("Could not validate imported publisher inputs: {error}"))?;
    if !output.status.success() {
        return Err(imported_publisher_rejection(&output.stderr));
    }
    if output.stdout.len() > RELEASE_RESULT_LIMIT {
        return Err("Pinned Core publisher returned an oversized imported-product plan.".into());
    }
    let plan: SupportPublicationPlan = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!("Pinned Core publisher returned invalid imported-product JSON: {error}")
    })?;
    let expected = inputs
        .clone()
        .map(|path| path.to_string_lossy().into_owned());
    if plan.schema_version != 1
        || plan.status != "ready"
        || plan.repository != NVIDIA_SUPPORT_REPOSITORY
        || plan.target_commit != NVIDIA_SUPPORT_BUILD_COMMIT
        || plan.trust != "locally-built-verified"
        || plan.assets.as_slice() != expected
    {
        return Err("Imported product does not match the pinned Core publication contract.".into());
    }
    if plan.archive_sha256 != actual {
        return Err("Imported release archive identity is inconsistent.".into());
    }
    let plan_path = runtime_dir.join("maintainer-release-plan.json");
    write_create_or_exact(&plan_path, &output.stdout, "maintainer release plan")?;
    Ok(ReleaseRuntime {
        support_root,
        state: runtime_dir.join("maintainer-release-operation.json"),
        plan: plan_path,
        inputs: Some(inputs),
    })
}

#[tauri::command]
pub(crate) async fn import_maintainer_release_product(
    app: tauri::AppHandle,
    directory: String,
) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let runtime = imported_release_runtime(&app, Path::new(&directory))?;
        let operation = run_core_session(&runtime, "execute", None, None)?;
        app.state::<Mutex<MaintainerReleaseManager>>()
            .lock()
            .map_err(|_| "Maintainer release state lock is unavailable.")?
            .imported = Some(runtime);
        Ok(operation)
    })
    .await
    .map_err(|error| format!("Maintainer product-import worker failed: {error}"))?
}

fn run_core_session(
    runtime: &ReleaseRuntime,
    command: &str,
    observed: Option<&Path>,
    attempt: Option<u64>,
) -> Result<serde_json::Value, String> {
    let python = find_binary("python3")
        .or_else(|| find_binary("python"))
        .ok_or("Python 3 is required by the pinned Core release session.")?;
    let mut process = Command::new(python);
    process
        .arg(
            runtime
                .support_root
                .join("lib/release_operation_session.py"),
        )
        .arg(command)
        .arg("--state")
        .arg(&runtime.state);
    if command == "execute" || command == "reconcile" {
        process.arg("--plan").arg(&runtime.plan);
    }
    if let Some(path) = observed {
        process.arg("--observed").arg(path);
    }
    if let Some(value) = attempt {
        process.arg("--attempt").arg(value.to_string());
    }
    let output = process
        .output()
        .map_err(|error| format!("Could not run the pinned Core release session: {error}"))?;
    if !output.status.success() || output.stdout.len() > RELEASE_RESULT_LIMIT {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if detail.is_empty() {
            "Pinned Core release session failed closed.".into()
        } else {
            detail
        });
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Pinned Core release session returned invalid JSON: {error}"))
}

fn bind_request(
    value: &serde_json::Value,
    request: &MaintainerReleaseRequest,
) -> Result<(), String> {
    if value.get("operationId").and_then(serde_json::Value::as_str) != Some(&request.operation_id)
        || value.get("attempt").and_then(serde_json::Value::as_u64) != Some(request.attempt)
    {
        return Err("Release command request is stale or belongs to another operation.".into());
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn prepare_maintainer_release_operation(
    app: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let runtime = release_runtime(&app)?;
        run_core_session(&runtime, "execute", None, None)
    })
    .await
    .map_err(|error| format!("Maintainer release-plan worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn run_maintainer_release_operation(
    app: tauri::AppHandle,
    command: String,
    request: MaintainerReleaseRequest,
) -> Result<serde_json::Value, String> {
    let runtime = release_runtime(&app)?;
    let current = run_core_session(&runtime, "status", None, None)?;
    bind_request(&current, &request)?;
    match command.as_str() {
        "status" => Ok(current),
        "cancel" => run_core_session(&runtime, "cancel", None, None),
        "reconcile" => Err("Missing-asset retry is unavailable until the create-only publisher reports an exact observed inventory.".into()),
        "execute" => {
            let authorization = request.authorization.as_ref()
                .ok_or("Explicit authorization for this exact release attempt is required.")?;
            if authorization.operation_id != request.operation_id
                || authorization.attempt != request.attempt
                || authorization.decision != "create"
                || current.get("decision").and_then(serde_json::Value::as_str) != Some("create")
            {
                return Err("Release authorization does not match the exact planned attempt.".into());
            }
            if let Some(inputs) = runtime.inputs.as_ref() {
                let settings = load_builder_settings(&app)?;
                if !settings.auto_release_verified_nvidia || !github_maintainer_status()?.authorized {
                    return Err("Maintainer release permission is not enabled and freshly verified.".into());
                }
                let dry_run = support_publisher_command(
                    &runtime.support_root.join("bootstrap/publish_artifacts.sh"),
                    &inputs[0], &inputs[1], &inputs[2], &inputs[3],
                ).arg("--dry-run").output().map_err(|error| format!("Could not revalidate imported product: {error}"))?;
                if !dry_run.status.success() || fs::read(&runtime.plan).map_err(|error| format!("Could not reread release plan: {error}"))? != dry_run.stdout {
                    return Err("Imported product changed after authorization.".into());
                }
                if !github_maintainer_status()?.authorized {
                    return Err("GitHub maintainer permission expired before publication.".into());
                }
                let output = support_publisher_command(
                    &runtime.support_root.join("bootstrap/publish_artifacts.sh"),
                    &inputs[0], &inputs[1], &inputs[2], &inputs[3],
                ).arg("--create-only").output().map_err(|error| format!("Could not run pinned create-only publisher: {error}"))?;
                if !output.status.success() {
                    let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    return Err(format!("Pinned create-only publisher rejected the release: {detail}"));
                }
            } else {
                publish_on_demand_nvidia_release(app.clone()).await?;
            }
            let assets = current.get("assets").and_then(serde_json::Value::as_array)
                .ok_or("Core release operation omitted its asset inventory.")?;
            let observed_assets = assets.iter().map(|asset| serde_json::json!({
                "name": asset.get("name"), "sha256": asset.get("sha256"), "bytes": asset.get("bytes")
            })).collect::<Vec<_>>();
            let observed = serde_json::json!({
                "repository": current.get("repository"), "tag": current.get("tag"),
                "targetCommit": current.get("targetCommit"), "assets": observed_assets,
            });
            let observed_path = runtime.state.with_file_name("maintainer-release-observed.json");
            write_create_or_exact(&observed_path,
                &serde_json::to_vec(&observed).map_err(|error| format!("Could not encode observed release: {error}"))?,
                "observed release inventory")?;
            run_core_session(&runtime, "reconcile", Some(&observed_path), Some(request.attempt + 1))
        }
        _ => Err("Unsupported maintainer release-session command.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ImportFixture(PathBuf);

    impl ImportFixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "opemos-maintainer-release-import-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("create import fixture");
            for name in [
                "product.tar.gz",
                "product.tar.gz.sha256",
                "product.build-info.txt",
                "product.provenance.json",
            ] {
                fs::write(root.join(name), name).expect("write import fixture");
            }
            Self(root)
        }
    }

    impl Drop for ImportFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn request(operation_id: &str, attempt: u64) -> MaintainerReleaseRequest {
        MaintainerReleaseRequest {
            operation_id: operation_id.into(),
            attempt,
            authorization: None,
        }
    }

    #[test]
    fn release_requests_bind_exact_operation_and_attempt() {
        let current = serde_json::json!({"operationId": "a", "attempt": 2});
        assert!(bind_request(&current, &request("a", 2)).is_ok());
        assert!(bind_request(&current, &request("b", 2)).is_err());
        assert!(bind_request(&current, &request("a", 1)).is_err());
    }

    #[test]
    fn imported_publisher_rejection_retains_only_bounded_diagnostics() {
        assert_eq!(
            imported_publisher_rejection(b"validate_publish_inputs.py: zstd failed\r\n"),
            "Pinned Core publisher rejected the imported product: validate_publish_inputs.py: zstd failed"
        );
        assert_eq!(
            imported_publisher_rejection(b" \r\n"),
            "Pinned Core publisher rejected the imported product."
        );
        assert_eq!(
            imported_publisher_rejection(&vec![b'x'; RELEASE_RESULT_LIMIT + 1]),
            "Pinned Core publisher rejected the imported product; its diagnostic exceeded the output limit."
        );
    }

    #[test]
    fn imported_release_inputs_are_closed_world_regular_files() {
        let fixture = ImportFixture::new();
        let inputs = discover_imported_release_inputs(&fixture.0).expect("discover exact inputs");
        assert!(inputs[0].ends_with("product.tar.gz"));
        assert!(inputs[1].ends_with("product.tar.gz.sha256"));
        assert!(inputs[2].ends_with("product.build-info.txt"));
        assert!(inputs[3].ends_with("product.provenance.json"));

        fs::write(fixture.0.join("unexpected.txt"), "unexpected").expect("write extra file");
        assert!(discover_imported_release_inputs(&fixture.0)
            .unwrap_err()
            .contains("unexpected file"));
        fs::remove_file(fixture.0.join("unexpected.txt")).expect("remove extra file");

        fs::write(fixture.0.join("duplicate.tar.gz"), "duplicate").expect("write duplicate");
        assert!(discover_imported_release_inputs(&fixture.0)
            .unwrap_err()
            .contains("duplicate publisher inputs"));
        fs::remove_file(fixture.0.join("duplicate.tar.gz")).expect("remove duplicate");

        fs::create_dir(fixture.0.join("nested")).expect("create nested directory");
        assert!(discover_imported_release_inputs(&fixture.0)
            .unwrap_err()
            .contains("only four regular publisher inputs"));

        #[cfg(unix)]
        {
            let linked = fixture.0.with_extension("linked");
            let _ = fs::remove_file(&linked);
            std::os::unix::fs::symlink(&fixture.0, &linked).expect("link import fixture");
            assert!(discover_imported_release_inputs(&linked)
                .unwrap_err()
                .contains("must be one real directory"));
            fs::remove_file(linked).expect("remove import fixture link");
        }
    }
}

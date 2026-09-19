use super::*;

const RELEASE_RESULT_LIMIT: usize = 1024 * 1024;
const CORE_SESSION_BOOTSTRAP: &str = "import runpy,sys; library=sys.argv.pop(1); script=sys.argv.pop(1); sys.path.insert(0,library); sys.argv[0]=script; runpy.run_path(script,run_name='__main__')";
const R1_BUNDLE_MANIFEST: &str = "opemos-driver-bundle-steamos-3.8.14-nvidia-575.64.05-k6.16.12-valve24.4-1-neptune-616-gfe145653a794-modules-zstd-r1-x86_64.manifest.json";
const R1_BUNDLE_MANIFEST_SHA256: &str =
    "3e36fc5490ca4186ec7dbd79e9bd5cb1453d56845aafefd7703f7730bed5bcc1";
const R1_PRODUCT_CORE_COMMIT: &str = "0b9550ab0ffc9ababe79800a407835c9c4a27dd0";
const R1_INSTALLER_ARCHIVE_SHA256: &str =
    "3412cf68ee79450f58afd4bb09e6c8dc9ed1f20ef4410118127ff98211727784";
const R1_INSTALLER_ARCHIVE_BYTES: u64 = 21_634_427;

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

fn validate_materialized_result(
    result: &serde_json::Value,
    manifest: &serde_json::Value,
    output_dir: &Path,
) -> Result<[PathBuf; 4], String> {
    let expected_target = serde_json::json!({
        "steamosVersion": "3.8.14",
        "kernelVersion": "6.16.12-valve24.4-1-neptune-616-gfe145653a794",
        "nvidiaVersion": "575.64.05",
        "architecture": "x86_64",
    });
    let expected_representation = serde_json::json!({
        "productMember": "payload/nvidia-driver.tar.zst",
        "installerContainer": "tar+gzip",
        "modules": "ko.zst",
        "conversion": "none-byte-identical",
    });
    let top_level = result.as_object();
    if top_level.is_none_or(|value| {
        value.len() != 8
            || ![
                "schemaVersion",
                "status",
                "target",
                "core",
                "source",
                "release",
                "representation",
                "outputs",
            ]
            .iter()
            .all(|field| value.contains_key(*field))
    }) || result
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || result.get("status").and_then(serde_json::Value::as_str) != Some("materialized")
        || result.get("target") != Some(&expected_target)
        || result.get("representation") != Some(&expected_representation)
        || result.get("core")
            != Some(&serde_json::json!({
                "repository": NVIDIA_SUPPORT_REPOSITORY,
                "commit": R1_PRODUCT_CORE_COMMIT,
            }))
        || result.get("source") != manifest.get("source")
        || result.get("release") != manifest.get("release")
    {
        return Err("Materialized product does not match the exact r1 Core contract.".into());
    }
    let outputs = result
        .get("outputs")
        .and_then(serde_json::Value::as_object)
        .ok_or("Core materializer omitted its output inventory.")?;
    if outputs.len() != 4
        || !["archive", "checksum", "provenance", "buildInfo"]
            .iter()
            .all(|role| outputs.contains_key(*role))
    {
        return Err("Core materializer returned a non-canonical output inventory.".into());
    }
    let canonical_output = fs::canonicalize(output_dir)
        .map_err(|error| format!("Could not resolve materialized output: {error}"))?;
    let mut paths = Vec::new();
    for role in ["archive", "checksum", "buildInfo", "provenance"] {
        let record = outputs[role]
            .as_object()
            .ok_or("Core materializer returned an invalid output record.")?;
        if record.len() != 3 {
            return Err("Core materializer returned a non-canonical output record.".into());
        }
        let name = record
            .get("name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| {
                name.len() <= 255
                    && name
                        .bytes()
                        .next()
                        .is_some_and(|byte| byte.is_ascii_alphanumeric())
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
                    && Path::new(name).file_name().and_then(|value| value.to_str()) == Some(*name)
            })
            .ok_or("Core materializer returned an unsafe output name.")?;
        let bytes = record
            .get("bytes")
            .and_then(serde_json::Value::as_u64)
            .filter(|value| *value > 0)
            .ok_or("Core materializer returned an invalid output size.")?;
        let sha256 = record
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or("Core materializer returned an invalid output SHA-256.")?;
        let unresolved = output_dir.join(name);
        let metadata = fs::symlink_metadata(&unresolved)
            .map_err(|error| format!("Could not inspect materialized output: {error}"))?;
        let path = fs::canonicalize(&unresolved)
            .map_err(|error| format!("Could not resolve materialized output: {error}"))?;
        if !metadata.file_type().is_file()
            || path.parent() != Some(canonical_output.as_path())
            || metadata.len() != bytes
            || sha256_file(&path)? != sha256
        {
            return Err("Materialized output does not match the Core result record.".into());
        }
        if role == "archive"
            && (bytes != R1_INSTALLER_ARCHIVE_BYTES || sha256 != R1_INSTALLER_ARCHIVE_SHA256)
        {
            return Err(
                "Materialized installer archive does not match the exact r1 identity.".into(),
            );
        }
        paths.push(path);
    }
    paths
        .try_into()
        .map_err(|_| "Core materializer output count changed.".into())
}

fn core_materializer_command(
    python: &Path,
    support_root: &Path,
    manifest: &Path,
    asset_dir: &Path,
    output_dir: &Path,
) -> Command {
    let mut command = Command::new(python);
    let library = support_root.join("lib");
    let script = library.join("materialize_driver_product.py");
    append_core_script_args(&mut command, &library, &script);
    command
        .arg("--manifest")
        .arg(manifest)
        .arg("--asset-dir")
        .arg(asset_dir)
        .arg("--expected-manifest-sha256")
        .arg(R1_BUNDLE_MANIFEST_SHA256)
        .arg("--expected-core-commit")
        .arg(R1_PRODUCT_CORE_COMMIT)
        .arg("--expected-steamos")
        .arg("3.8.14")
        .arg("--expected-kernel")
        .arg("6.16.12-valve24.4-1-neptune-616-gfe145653a794")
        .arg("--expected-nvidia")
        .arg("575.64.05")
        .arg("--expected-architecture")
        .arg("x86_64")
        .arg("--output-dir")
        .arg(output_dir);
    command
}

fn append_core_script_args(command: &mut Command, library: &Path, script: &Path) {
    command
        .arg("-c")
        .arg(CORE_SESSION_BOOTSTRAP)
        .arg(library)
        .arg(script);
}

fn materialize_r1_release_inputs(
    directory: &Path,
    runtime_dir: &Path,
    support_root: &Path,
) -> Result<[PathBuf; 4], String> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| format!("Could not inspect the verified product folder: {error}"))?;
    if !metadata.file_type().is_dir() {
        return Err("Verified r1 product selection must be one real directory.".into());
    }
    let directory = fs::canonicalize(directory)
        .map_err(|error| format!("Could not resolve the verified product folder: {error}"))?;
    let entries = fs::read_dir(&directory)
        .map_err(|error| format!("Could not inspect verified r1 product folder: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Could not inspect verified r1 product entry: {error}"))?;
    if entries.len() != 3
        || entries.iter().any(|entry| {
            fs::symlink_metadata(entry.path())
                .map(|value| !value.file_type().is_file())
                .unwrap_or(true)
        })
    {
        return Err(
            "Verified r1 product folder must contain exactly three regular bundle files.".into(),
        );
    }
    let manifest_path = directory.join(R1_BUNDLE_MANIFEST);
    if sha256_file(&manifest_path)? != R1_BUNDLE_MANIFEST_SHA256 {
        return Err("Verified r1 bundle manifest does not match its pinned SHA-256.".into());
    }
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path)
            .map_err(|error| format!("Could not read verified r1 bundle manifest: {error}"))?,
    )
    .map_err(|error| format!("Verified r1 bundle manifest is invalid JSON: {error}"))?;
    let output_dir = runtime_dir.join("materialized-r1-installer");
    let result_path = runtime_dir.join("materialized-r1-result.json");
    let retained_result = fs::symlink_metadata(&result_path).ok();
    if retained_result
        .as_ref()
        .is_some_and(|metadata| metadata.file_type().is_file())
    {
        if retained_result.is_some_and(|metadata| metadata.len() > RELEASE_RESULT_LIMIT as u64) {
            return Err("Retained Core materialization result is excessive.".into());
        }
        let result = serde_json::from_slice(&fs::read(&result_path).map_err(|error| {
            format!("Could not read retained Core materialization result: {error}")
        })?)
        .map_err(|error| {
            format!("Retained Core materialization result is invalid JSON: {error}")
        })?;
        return validate_materialized_result(&result, &manifest, &output_dir);
    }
    if result_path.exists() || result_path.is_symlink() {
        return Err("Retained Core materialization result is not a regular file.".into());
    }
    if output_dir.exists() {
        return Err(
            "Incomplete retained Core materialization output requires owned cleanup.".into(),
        );
    }
    fs::create_dir(&output_dir)
        .map_err(|error| format!("Could not create materialized installer output: {error}"))?;
    let mut output_guard = StagingDirectoryGuard {
        path: output_dir.clone(),
        armed: true,
    };
    let python = find_binary("python3")
        .or_else(|| find_binary("python"))
        .ok_or("Python 3 is required by the pinned Core product materializer.")?;
    let output = core_materializer_command(
        &python,
        support_root,
        &manifest_path,
        &directory,
        &output_dir,
    )
    .output()
    .map_err(|error| format!("Could not run the pinned Core product materializer: {error}"))?;
    if !output.status.success() || output.stdout.len() > RELEASE_RESULT_LIMIT {
        return Err(imported_publisher_rejection(&output.stderr)
            .replace("Pinned Core publisher", "Pinned Core product materializer"));
    }
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Pinned Core materializer returned invalid JSON: {error}"))?;
    let inputs = validate_materialized_result(&result, &manifest, &output_dir)?;
    if let Err(error) =
        write_create_or_exact(&result_path, &output.stdout, "Core materialization result")
    {
        let _ = fs::remove_file(&result_path);
        return Err(error);
    }
    output_guard.armed = false;
    Ok(inputs)
}

fn imported_release_runtime(
    app: &tauri::AppHandle,
    directory: &Path,
) -> Result<ReleaseRuntime, String> {
    let cache = match portable_cache_root() {
        Some(root) => root.clone(),
        None => app
            .path()
            .app_local_data_dir()
            .map_err(|error| format!("Could not resolve application data: {error}"))?,
    };
    let is_r1_bundle = directory.join(R1_BUNDLE_MANIFEST).exists();
    let actual = if is_r1_bundle {
        R1_INSTALLER_ARCHIVE_SHA256.into()
    } else {
        sha256_file(&discover_imported_release_inputs(directory)?[0])?
    };
    let runtime_dir = cache.join("maintainer-release-import").join(&actual);
    fs::create_dir_all(&runtime_dir)
        .map_err(|error| format!("Could not create maintainer release state: {error}"))?;
    let support_root = prepare_pinned_nvidia_publisher(&runtime_dir)?;
    let inputs = if is_r1_bundle {
        materialize_r1_release_inputs(directory, &runtime_dir, &support_root)?
    } else {
        discover_imported_release_inputs(directory)?
    };
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
    validate_imported_publication_plan(
        &plan,
        &inputs,
        &actual,
        if is_r1_bundle {
            R1_PRODUCT_CORE_COMMIT
        } else {
            NVIDIA_SUPPORT_BUILD_COMMIT
        },
    )?;
    let plan_path = runtime_dir.join("maintainer-release-plan.json");
    write_create_or_exact(&plan_path, &output.stdout, "maintainer release plan")?;
    Ok(ReleaseRuntime {
        support_root,
        state: runtime_dir.join("maintainer-release-operation.json"),
        plan: plan_path,
        inputs: Some(inputs),
    })
}

fn validate_imported_publication_plan(
    plan: &SupportPublicationPlan,
    inputs: &[PathBuf; 4],
    actual: &str,
    expected_product_commit: &str,
) -> Result<(), String> {
    let expected = inputs
        .clone()
        .map(|path| path.to_string_lossy().into_owned());
    if plan.schema_version != 1
        || plan.status != "ready"
        || plan.repository != NVIDIA_SUPPORT_REPOSITORY
        || plan.target_commit != expected_product_commit
        || plan.trust != "locally-built-verified"
        || plan.assets.as_slice() != expected
    {
        return Err("Imported product does not match the pinned Core publication contract.".into());
    }
    if plan.archive_sha256 != actual {
        return Err("Imported release archive identity is inconsistent.".into());
    }
    Ok(())
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
    let mut process = core_session_command(&python, runtime, command, observed, attempt);
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

fn core_session_command(
    python: &Path,
    runtime: &ReleaseRuntime,
    command: &str,
    observed: Option<&Path>,
    attempt: Option<u64>,
) -> Command {
    let library = runtime.support_root.join("lib");
    let script = library.join("release_operation_session.py");
    let mut process = Command::new(python);
    append_core_script_args(&mut process, &library, &script);
    process.arg(command).arg("--state").arg(&runtime.state);
    if command == "execute" || command == "reconcile" {
        process.arg("--plan").arg(&runtime.plan);
    }
    if let Some(path) = observed {
        process.arg("--observed").arg(path);
    }
    if let Some(value) = attempt {
        process.arg("--attempt").arg(value.to_string());
    }
    process
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
    fn core_session_bootstrap_imports_sibling_module_and_preserves_arguments() {
        let fixture = ImportFixture::new();
        let library = fixture.0.join("support/lib");
        fs::create_dir_all(&library).expect("create Core library fixture");
        fs::write(
            library.join("release_operation.py"),
            "VALUE = 'sibling-loaded'\n",
        )
        .expect("write sibling module");
        fs::write(
            library.join("release_operation_session.py"),
            "import json, sys\nfrom release_operation import VALUE\nprint(json.dumps({'value': VALUE, 'argv': sys.argv}))\n",
        )
        .expect("write Core session fixture");
        let runtime = ReleaseRuntime {
            support_root: fixture.0.join("support"),
            state: fixture.0.join("state.json"),
            plan: fixture.0.join("plan.json"),
            inputs: None,
        };
        let python = find_binary("python3")
            .or_else(|| find_binary("python"))
            .expect("Python 3 is required for the Core session regression");
        let output = core_session_command(&python, &runtime, "execute", None, Some(7))
            .output()
            .expect("run Core session bootstrap");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("parse fixture output");
        assert_eq!(value["value"], "sibling-loaded");
        assert_eq!(
            value["argv"][0],
            library
                .join("release_operation_session.py")
                .to_string_lossy()
                .as_ref()
        );
        assert_eq!(value["argv"][1], "execute");
        assert_eq!(value["argv"][2], "--state");
        assert_eq!(value["argv"][3], runtime.state.to_string_lossy().as_ref());
        assert_eq!(value["argv"][4], "--plan");
        assert_eq!(value["argv"][5], runtime.plan.to_string_lossy().as_ref());
        assert_eq!(value["argv"][6], "--attempt");
        assert_eq!(value["argv"][7], 7.to_string());
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
    fn r1_materializer_command_binds_exact_product_and_consumer_identities() {
        let command = core_materializer_command(
            Path::new("python3"),
            Path::new("support"),
            Path::new(R1_BUNDLE_MANIFEST),
            Path::new("assets"),
            Path::new("output"),
        );
        let arguments = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(arguments[0], "-c");
        assert_eq!(arguments[1], CORE_SESSION_BOOTSTRAP);
        assert_eq!(arguments[2], "support/lib");
        assert_eq!(arguments[3], "support/lib/materialize_driver_product.py");
        for expected in [
            R1_BUNDLE_MANIFEST,
            R1_BUNDLE_MANIFEST_SHA256,
            R1_PRODUCT_CORE_COMMIT,
            "3.8.14",
            "6.16.12-valve24.4-1-neptune-616-gfe145653a794",
            "575.64.05",
            "x86_64",
        ] {
            assert!(arguments.iter().any(|value| value == expected));
        }
        assert!(!arguments.iter().any(|value| value.contains("convert")));
    }

    #[test]
    fn materializer_bootstrap_imports_sibling_module_under_isolated_python() {
        let fixture = ImportFixture::new();
        let library = fixture.0.join("support/lib");
        fs::create_dir_all(&library).expect("create Core materializer fixture");
        fs::write(
            library.join("driver_binary_bundle.py"),
            "VALUE = 'materializer-sibling-loaded'\n",
        )
        .expect("write sibling materializer module");
        let script = library.join("materialize_driver_product.py");
        fs::write(
            &script,
            "import argparse\nfrom driver_binary_bundle import VALUE\nparser = argparse.ArgumentParser()\nparser.parse_args()\nprint(VALUE)\n",
        )
        .expect("write materializer fixture");
        let python = find_binary("python3")
            .or_else(|| find_binary("python"))
            .expect("Python 3 is required for the isolated materializer regression");
        let mut command = Command::new(python);
        command.arg("-I");
        append_core_script_args(&mut command, &library, &script);
        command.arg("--help");
        let output = command
            .output()
            .expect("run isolated materializer bootstrap");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("usage:"));
    }

    #[test]
    fn r1_materialization_result_rejects_identity_or_representation_changes() {
        let manifest = serde_json::json!({
            "source": {"repository": "CorniiDog/open-gpu-kernel-modules-steamos", "commit": "40bd1b5d6d39ae4e4180b7a665df144b08854d14"},
            "release": {"repository": NVIDIA_SUPPORT_REPOSITORY, "tag": "exact-r1"},
        });
        let base = serde_json::json!({
            "schemaVersion": 1,
            "status": "materialized",
            "target": {
                "steamosVersion": "3.8.14",
                "kernelVersion": "6.16.12-valve24.4-1-neptune-616-gfe145653a794",
                "nvidiaVersion": "575.64.05",
                "architecture": "x86_64"
            },
            "core": {"repository": NVIDIA_SUPPORT_REPOSITORY, "commit": R1_PRODUCT_CORE_COMMIT},
            "source": manifest["source"],
            "release": manifest["release"],
            "representation": {
                "productMember": "payload/nvidia-driver.tar.zst",
                "installerContainer": "tar+gzip",
                "modules": "ko.zst",
                "conversion": "none-byte-identical"
            },
            "outputs": {}
        });
        let mut changed_core = base.clone();
        changed_core["core"]["commit"] = serde_json::json!(NVIDIA_SUPPORT_COMMIT);
        assert!(
            validate_materialized_result(&changed_core, &manifest, Path::new("unused"))
                .unwrap_err()
                .contains("exact r1 Core contract")
        );
        let mut converted = base;
        converted["representation"]["conversion"] = serde_json::json!("recompressed");
        assert!(
            validate_materialized_result(&converted, &manifest, Path::new("unused"))
                .unwrap_err()
                .contains("exact r1 Core contract")
        );
    }

    #[test]
    fn r1_publication_plan_retains_product_provenance_commit() {
        let inputs = [
            PathBuf::from("product.tar.gz"),
            PathBuf::from("product.tar.gz.sha256"),
            PathBuf::from("product.build-info.txt"),
            PathBuf::from("product.provenance.json"),
        ];
        let plan = SupportPublicationPlan {
            schema_version: 1,
            status: "ready".into(),
            repository: NVIDIA_SUPPORT_REPOSITORY.into(),
            tag: "unused-by-import".into(),
            target_commit: R1_PRODUCT_CORE_COMMIT.into(),
            trust: "locally-built-verified".into(),
            archive_sha256: R1_INSTALLER_ARCHIVE_SHA256.into(),
            assets: inputs
                .clone()
                .map(|path| path.to_string_lossy().into_owned())
                .to_vec(),
        };
        assert!(validate_imported_publication_plan(
            &plan,
            &inputs,
            R1_INSTALLER_ARCHIVE_SHA256,
            R1_PRODUCT_CORE_COMMIT,
        )
        .is_ok());
        assert!(validate_imported_publication_plan(
            &plan,
            &inputs,
            R1_INSTALLER_ARCHIVE_SHA256,
            NVIDIA_SUPPORT_BUILD_COMMIT,
        )
        .is_err());
    }

    #[cfg(windows)]
    #[test]
    fn imported_plan_accepts_the_exact_publisher_result_paths() {
        let inputs = [
            PathBuf::from(r"C:\Users\connor\product\archive.tar.gz"),
            PathBuf::from(r"C:\Users\connor\product\archive.tar.gz.sha256"),
            PathBuf::from(r"C:\Users\connor\product\build-info.txt"),
            PathBuf::from(r"C:\Users\connor\product\provenance.json"),
        ];
        let mut plan = SupportPublicationPlan {
            schema_version: 1,
            status: "ready".into(),
            repository: NVIDIA_SUPPORT_REPOSITORY.into(),
            tag: "unused-by-import".into(),
            target_commit: NVIDIA_SUPPORT_BUILD_COMMIT.into(),
            trust: "locally-built-verified".into(),
            archive_sha256: "a".repeat(64),
            assets: inputs
                .clone()
                .map(|path| path.to_string_lossy().into_owned())
                .to_vec(),
        };
        assert!(validate_imported_publication_plan(
            &plan,
            &inputs,
            &"a".repeat(64),
            NVIDIA_SUPPORT_BUILD_COMMIT,
        )
        .is_ok());

        plan.assets[0] = support_publisher_path(&inputs[0]);
        assert!(validate_imported_publication_plan(
            &plan,
            &inputs,
            &"a".repeat(64),
            NVIDIA_SUPPORT_BUILD_COMMIT,
        )
        .is_err());
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

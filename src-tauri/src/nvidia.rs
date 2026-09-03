use super::*;

pub(crate) fn valid_numeric_version(
    value: &str,
    components: std::ops::RangeInclusive<usize>,
) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    components.contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

pub(crate) fn valid_kernel_version(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'~' | b'-')
        })
}

pub(crate) fn validate_nvidia_target_build_spec(
    spec: &NvidiaTargetBuildSpec,
) -> Result<(), String> {
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

pub(crate) fn assess_nvidia_target_system(system: &TargetSystemDiscovery) -> NvidiaTargetReadiness {
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

pub(crate) fn numeric_version(
    value: &str,
    components: std::ops::RangeInclusive<usize>,
) -> Option<Vec<u64>> {
    let parts: Vec<_> = value.split('.').collect();
    if !components.contains(&parts.len()) {
        return None;
    }
    parts
        .into_iter()
        .map(|part| part.parse::<u64>().ok())
        .collect()
}

fn validate_ready_nvidia_target(target: &NvidiaTargetReadiness) -> Result<(), String> {
    if !target.ready {
        return Ok(());
    }
    let steamos = target
        .steamos_version
        .as_deref()
        .ok_or("Ready NVIDIA target omitted its SteamOS version.")?;
    let kernel = target
        .kernel_version
        .as_deref()
        .ok_or("Ready NVIDIA target omitted its kernel version.")?;
    if target.status != "exact-target"
        || target.architecture != "x86_64"
        || numeric_version(steamos, 3..=3).is_none()
        || !valid_kernel_version(kernel)
    {
        return Err("Ready NVIDIA target contains contradictory or invalid metadata.".into());
    }
    Ok(())
}

pub(crate) fn published_release_identity(tag: &str) -> Option<PublishedReleaseIdentity> {
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

pub(crate) fn select_published_nvidia_release(
    target: &NvidiaTargetReadiness,
    releases: &[GithubRelease],
) -> Result<Option<(PublishedReleaseIdentity, GithubRelease, String)>, String> {
    validate_ready_nvidia_target(target)?;
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
    let mut seen_tags = HashSet::new();
    if candidates
        .iter()
        .any(|candidate| !seen_tags.insert(candidate.3.tag.as_str()))
    {
        return Err(
            "Published NVIDIA release metadata contains a duplicate compatible tag.".into(),
        );
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

pub(crate) fn select_nvidia_build_baseline(
    target: &NvidiaTargetReadiness,
    releases: &[GithubRelease],
) -> Result<Option<PublishedReleaseIdentity>, String> {
    validate_ready_nvidia_target(target)?;
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
    let mut seen_tags = HashSet::new();
    if older_or_equal
        .iter()
        .chain(newer.iter())
        .any(|candidate| !seen_tags.insert(candidate.3.tag.as_str()))
    {
        return Err("Published NVIDIA release metadata contains a duplicate baseline tag.".into());
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

pub(crate) fn explicit_nvidia_build_resolution(
    target: NvidiaTargetReadiness,
    source: &NvidiaSourceBranch,
    baseline_release: String,
) -> Result<NvidiaPublishedResolution, String> {
    validate_ready_nvidia_target(&target)?;
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
            core_authorization: None,
        }),
    })
}

pub(crate) fn published_asset_name(identity: &PublishedReleaseIdentity) -> String {
    format!("nvidia-open-{}-x86_64.tar.gz", identity.tag)
}

pub(crate) fn expected_release_asset_url(tag: &str, name: &str) -> String {
    format!("https://github.com/{NVIDIA_RELEASE_REPOSITORY}/releases/download/{tag}/{name}")
}

pub(crate) fn unique_release_asset<'a>(
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

pub(crate) fn github_sha256(asset: &GithubReleaseAsset) -> Result<String, String> {
    let digest = asset
        .digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| format!("GitHub did not provide a valid SHA-256 for {}.", asset.name))?;
    Ok(digest.to_ascii_lowercase())
}

pub(crate) struct PublishedArchiveInspection {
    build_info: Vec<u8>,
    provenance: Vec<u8>,
    module_hashes: HashMap<String, String>,
    pub(crate) archive_bytes: u64,
    pub(crate) expanded_bytes: u64,
}

pub(crate) fn inspect_published_nvidia_archive(
    path: &Path,
) -> Result<PublishedArchiveInspection, String> {
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

pub(crate) fn nvidia_http_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .user_agent("steamos-nvidia-image-builder/0.1")
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(15 * 60))
        .build()
        .map_err(|e| format!("Could not initialize secure NVIDIA release downloads: {e}"))
}

pub(crate) fn read_http_response_limited(
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

pub(crate) fn fetch_github_releases(
    client: &reqwest::blocking::Client,
) -> Result<Vec<GithubRelease>, String> {
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

pub(crate) fn valid_nvidia_source_branch(value: &str) -> Option<&str> {
    let version = value.strip_prefix("nvidia/")?;
    numeric_version(version, 2..=3)?;
    Some(version)
}

pub(crate) fn valid_upstream_nvidia_tag(value: &str) -> Option<&str> {
    numeric_version(value, 2..=3)?;
    Some(value)
}

pub(crate) fn valid_nvidia_source_identity(
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

pub(crate) fn valid_maintainer_git_reference(value: &str) -> bool {
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

pub(crate) fn valid_git_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn fetch_maintainer_branches(
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

pub(crate) fn fetch_maintainer_gamescope_tags(
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

pub(crate) fn fetch_maintainer_workspace_sources(
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

pub(crate) fn require_maintainer_authorization() -> Result<GithubMaintainerStatus, String> {
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
pub(crate) async fn list_maintainer_workspace_sources(
) -> Result<Vec<MaintainerWorkspaceSource>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        require_maintainer_authorization()?;
        fetch_maintainer_workspace_sources(&nvidia_http_client()?)
    })
    .await
    .map_err(|error| format!("Maintainer source-list worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn plan_maintainer_workspace(
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

pub(crate) fn repository_from_remote(remote: &str) -> Option<String> {
    let trimmed = remote.trim().trim_end_matches('/').trim_end_matches(".git");
    let path = trimmed
        .strip_prefix("https://github.com/")
        .or_else(|| trimmed.strip_prefix("http://github.com/"))
        .or_else(|| trimmed.strip_prefix("ssh://git@github.com/"))
        .or_else(|| trimmed.strip_prefix("git@github.com:"))?;
    let mut parts = path.split('/');
    let owner = parts.next()?;
    let repository = parts.next()?;
    if owner.is_empty() || repository.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(format!("{owner}/{repository}"))
}

pub(crate) fn git_output_bytes(
    path: &Path,
    args: &[&str],
    description: &str,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(path)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("Could not {description}: {error}"))?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "Could not {description}; Git output was unavailable."
        ));
    };
    let mut bytes = Vec::new();
    if let Err(error) = stdout.take((limit + 1) as u64).read_to_end(&mut bytes) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("Could not {description}: {error}"));
    }
    if bytes.len() > limit {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "Could not {description}; Git output exceeded the safe limit."
        ));
    }
    let status = child
        .wait()
        .map_err(|error| format!("Could not finish {description}: {error}"))?;
    if !status.success() {
        return Err(format!(
            "Could not {description}; the selected folder is not a usable Git worktree."
        ));
    }
    Ok(bytes)
}

fn git_output(path: &Path, args: &[&str], description: &str) -> Result<String, String> {
    String::from_utf8(git_output_bytes(path, args, description, 4 * 1024 * 1024)?)
        .map(|value| value.trim().to_owned())
        .map_err(|_| format!("Could not {description}; Git returned non-UTF-8 output."))
}

pub(crate) fn bounded_git_mutation(
    binary: &Path,
    path: &Path,
    args: &[&str],
    input: Option<&[u8]>,
    timeout: Duration,
    limit: usize,
    description: &str,
) -> Result<Vec<u8>, String> {
    let mut command = Command::new(binary);
    command
        .arg("-C")
        .arg(path)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    isolate_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("Could not {description}: {error}"))?;
    let cleanup = |child: &mut Child| {
        #[cfg(unix)]
        {
            let _ = Command::new("kill")
                .args(["-KILL", &format!("-{}", child.id())])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = child.kill();
        let _ = child.wait();
    };
    if let Some(bytes) = input {
        let Some(mut stdin) = child.stdin.take() else {
            cleanup(&mut child);
            return Err(format!("Could not open {description} input."));
        };
        if let Err(error) = stdin.write_all(bytes) {
            cleanup(&mut child);
            return Err(format!("Could not provide {description} input: {error}"));
        }
    }
    drop(child.stdin.take());
    let Some(stdout) = child.stdout.take() else {
        cleanup(&mut child);
        return Err(format!("Could not read {description} output."));
    };
    let Some(stderr) = child.stderr.take() else {
        cleanup(&mut child);
        return Err(format!("Could not read {description} errors."));
    };
    let stdout_thread = thread::spawn(move || read_bounded_git_stream(stdout, limit));
    let stderr_thread = thread::spawn(move || read_bounded_git_stream(stderr, limit));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                cleanup(&mut child);
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(format!("Could not inspect {description}: {error}"));
            }
        }
        if Instant::now() >= deadline {
            cleanup(&mut child);
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(format!(
                "Could not {description}; Git exceeded the safe time limit."
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    cleanup(&mut child);
    let stdout = stdout_thread
        .join()
        .map_err(|_| format!("Could not collect {description} output."))?
        .map_err(|error| format!("Could not read {description} output: {error}"))?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| format!("Could not collect {description} errors."))?
        .map_err(|error| format!("Could not read {description} errors: {error}"))?;
    if stdout.len() > limit || stderr.len() > limit {
        return Err(format!(
            "Could not {description}; Git output exceeded the safe limit."
        ));
    }
    if !status.success() {
        let detail = String::from_utf8_lossy(&stderr);
        return Err(format!("Could not {description}: {}", detail.trim()));
    }
    Ok(stdout)
}

pub(crate) fn read_bounded_git_stream(mut stream: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_add(1).saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    Ok(kept)
}

fn vscode_binary() -> Option<PathBuf> {
    find_binary("code").or_else(|| {
        let candidate =
            PathBuf::from("/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code");
        candidate.is_file().then_some(candidate)
    })
}

static MAINTAINER_WORKTREE_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(crate) fn managed_maintainer_worktree_destination(
    root: &Path,
    repository: &str,
    commit: &str,
) -> Result<PathBuf, String> {
    if ![
        NVIDIA_SOURCE_REPOSITORY,
        NVIDIA_UPSTREAM_REPOSITORY,
        GAMESCOPE_SOURCE_REPOSITORY,
        GAMESCOPE_UPSTREAM_REPOSITORY,
    ]
    .contains(&repository)
        || !valid_git_commit(commit)
    {
        return Err("The managed worktree identity is not an approved exact source.".into());
    }
    let directory = format!("{}--{}", repository.replace('/', "--"), &commit[..12]);
    Ok(root.join(directory))
}

fn managed_maintainer_worktree_root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let root = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not determine the managed-worktree directory: {error}"))?
        .join("maintainer-worktrees");
    fs::create_dir_all(&root)
        .map_err(|error| format!("Could not create the managed-worktree directory: {error}"))?;
    let metadata = fs::symlink_metadata(&root)
        .map_err(|error| format!("Could not inspect the managed-worktree directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("The managed-worktree location must be a real directory, not a link.".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err("The managed-worktree directory is not owned by the current user.".into());
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Could not secure the managed-worktree directory: {error}"))?;
    }
    Ok(root)
}

fn make_maintainer_worktree_blocking(
    app: tauri::AppHandle,
    component: String,
    origin: String,
    repository: String,
    reference: String,
    commit: String,
) -> Result<MaintainerLocalWorktree, String> {
    require_maintainer_authorization()?;
    if !valid_local_branch_name(&reference) || !valid_git_commit(&commit) {
        return Err("The requested managed checkout has an unsafe Git identity.".into());
    }
    let matches = fetch_maintainer_workspace_sources(&nvidia_http_client()?)?
        .into_iter()
        .filter(|source| {
            source.component == component
                && source.origin == origin
                && source.repository == repository
                && source.reference == reference
                && source.commit == commit
        })
        .count();
    if matches != 1 {
        return Err("The planned source changed before its managed checkout could be created. Refresh and verify the workspace plan again.".into());
    }

    let root = managed_maintainer_worktree_root(&app)?;
    let destination = managed_maintainer_worktree_destination(&root, &repository, &commit)?;
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("The managed checkout destination is not a real directory.".into());
            }
            return inspect_authorized_maintainer_worktree(
                destination.to_string_lossy().into_owned(),
                repository,
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "Could not inspect the managed checkout destination: {error}"
            ));
        }
    }

    let sequence = MAINTAINER_WORKTREE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(
        ".creating-{}-{}-{}",
        std::process::id(),
        sequence,
        &commit[..12]
    ));
    fs::create_dir(&temporary).map_err(|error| {
        format!("Could not create the private checkout staging directory: {error}")
    })?;
    #[cfg(unix)]
    if let Err(error) = fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700)) {
        let _ = fs::remove_dir(&temporary);
        return Err(format!(
            "Could not secure the private checkout staging directory: {error}"
        ));
    }

    let create = (|| {
        let git = Path::new("git");
        bounded_git_mutation(
            git,
            &temporary,
            &["init", "--quiet"],
            None,
            Duration::from_secs(15),
            64 * 1024,
            "initialize the managed checkout",
        )?;
        let remote = format!("https://github.com/{repository}.git");
        bounded_git_mutation(
            git,
            &temporary,
            &["remote", "add", "origin", &remote],
            None,
            Duration::from_secs(15),
            64 * 1024,
            "bind the approved origin",
        )?;
        let fetch_reference = format!(
            "refs/{}/{reference}",
            if origin == "project" { "heads" } else { "tags" }
        );
        bounded_git_mutation(
            git,
            &temporary,
            &[
                "fetch",
                "--no-tags",
                "--depth=1",
                "origin",
                &fetch_reference,
            ],
            None,
            Duration::from_secs(180),
            1024 * 1024,
            "fetch the exact verified source",
        )?;
        let fetched = git_output(
            &temporary,
            &["rev-parse", "FETCH_HEAD"],
            "verify the fetched source commit",
        )?;
        if !fetched.eq_ignore_ascii_case(&commit) {
            return Err("The fetched reference no longer identifies the verified commit.".into());
        }
        bounded_git_mutation(
            git,
            &temporary,
            &["checkout", "--quiet", "-b", &reference, &commit],
            None,
            Duration::from_secs(30),
            1024 * 1024,
            "create the exact managed branch",
        )?;
        fs::rename(&temporary, &destination).map_err(|error| {
            format!("Could not publish the managed checkout atomically: {error}")
        })?;
        Ok::<(), String>(())
    })();
    if let Err(error) = create {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    let worktree = inspect_authorized_maintainer_worktree(
        destination.to_string_lossy().into_owned(),
        repository,
    )?;
    if worktree.head != commit || worktree.branch.as_deref() != Some(reference.as_str()) {
        return Err("The new managed checkout does not match the verified source identity.".into());
    }
    Ok(worktree)
}

#[tauri::command]
pub(crate) async fn make_maintainer_worktree(
    app: tauri::AppHandle,
    component: String,
    origin: String,
    repository: String,
    reference: String,
    commit: String,
) -> Result<MaintainerLocalWorktree, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let worktree = make_maintainer_worktree_blocking(
            app.clone(),
            component,
            origin,
            repository,
            reference,
            commit,
        )?;
        remember_maintainer_worktree(&app, Path::new(&worktree.path))?;
        Ok(worktree)
    })
    .await
    .map_err(|error| format!("Managed maintainer-worktree worker failed: {error}"))?
}

fn inspect_maintainer_worktree_blocking(
    path: String,
    repository: String,
) -> Result<MaintainerLocalWorktree, String> {
    require_maintainer_authorization()?;
    inspect_authorized_maintainer_worktree(path, repository)
}

fn inspect_authorized_maintainer_worktree(
    path: String,
    repository: String,
) -> Result<MaintainerLocalWorktree, String> {
    if ![
        NVIDIA_SOURCE_REPOSITORY,
        NVIDIA_UPSTREAM_REPOSITORY,
        GAMESCOPE_SOURCE_REPOSITORY,
        GAMESCOPE_UPSTREAM_REPOSITORY,
    ]
    .contains(&repository.as_str())
    {
        return Err("The planned repository is not an approved maintainer source.".into());
    }
    let selected = fs::canonicalize(&path)
        .map_err(|error| format!("Could not resolve the selected worktree: {error}"))?;
    if !selected.is_dir() {
        return Err("The selected worktree is not a directory.".into());
    }
    let root = PathBuf::from(git_output(
        &selected,
        &["rev-parse", "--show-toplevel"],
        "resolve the Git worktree root",
    )?);
    let root = fs::canonicalize(root)
        .map_err(|error| format!("Could not resolve the Git worktree root: {error}"))?;
    if root != selected {
        return Err(
            "Select the root folder of the Git worktree, not one of its subfolders.".into(),
        );
    }
    let remote = git_output(
        &root,
        &["remote", "get-url", "origin"],
        "read the origin remote",
    )?;
    let actual_repository = repository_from_remote(&remote)
        .ok_or("The worktree origin is not a recognized GitHub repository URL.")?;
    if !actual_repository.eq_ignore_ascii_case(&repository) {
        return Err(format!(
            "This worktree belongs to {actual_repository}, but the verified plan requires {repository}."
        ));
    }
    let head = git_output(&root, &["rev-parse", "HEAD"], "read the worktree HEAD")?;
    if !valid_git_commit(&head) {
        return Err("The worktree HEAD is not a valid 40-character Git commit.".into());
    }
    let branch = git_output(
        &root,
        &["branch", "--show-current"],
        "read the worktree branch",
    )?;
    let status = git_output(
        &root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
        "inspect worktree changes",
    )?;
    let changed_files = status.lines().take(10_001).count();
    if changed_files > 10_000 {
        return Err(
            "The worktree has more than 10,000 changed paths; review it outside the app.".into(),
        );
    }
    Ok(MaintainerLocalWorktree {
        path: root.to_string_lossy().into_owned(),
        repository: actual_repository,
        head: head.to_ascii_lowercase(),
        branch: (!branch.is_empty()).then_some(branch),
        changed_files,
        vscode_available: vscode_binary().is_some(),
    })
}

#[tauri::command]
pub(crate) async fn inspect_maintainer_worktree(
    app: tauri::AppHandle,
    path: String,
    repository: String,
) -> Result<MaintainerLocalWorktree, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let worktree = inspect_maintainer_worktree_blocking(path, repository)?;
        remember_maintainer_worktree(&app, Path::new(&worktree.path))?;
        Ok(worktree)
    })
    .await
    .map_err(|error| format!("Maintainer worktree inspector failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn list_recent_maintainer_worktrees(
    app: tauri::AppHandle,
    repository: String,
) -> Result<Vec<MaintainerLocalWorktree>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        require_maintainer_authorization()?;
        let settings = load_builder_settings(&app)?;
        let mut worktrees = Vec::new();
        for path in settings.recent_maintainer_worktrees {
            if let Ok(worktree) = inspect_authorized_maintainer_worktree(path, repository.clone()) {
                worktrees.push(worktree);
            }
        }
        Ok(worktrees)
    })
    .await
    .map_err(|error| format!("Recent maintainer-worktree worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn open_maintainer_worktree_in_vscode(
    app: tauri::AppHandle,
    path: String,
    repository: String,
) -> Result<MaintainerLocalWorktree, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let worktree = inspect_maintainer_worktree_blocking(path, repository)?;
        let code = vscode_binary().ok_or(
            "VS Code's command-line launcher is unavailable. Install VS Code or add the 'code' command to PATH.",
        )?;
        Command::new(code)
            .arg("--reuse-window")
            .arg(&worktree.path)
            .spawn()
            .map_err(|error| format!("Could not open the selected worktree in VS Code: {error}"))?;
        remember_maintainer_worktree(&app, Path::new(&worktree.path))?;
        Ok(worktree)
    })
    .await
    .map_err(|error| format!("VS Code launcher worker failed: {error}"))?
}

pub(crate) fn validate_local_commit_message(message: &str) -> Result<(), String> {
    if message.is_empty() || message.trim() != message || message.len() > 2_048 {
        return Err(
            "The commit message must be 1-2,048 characters with no leading or trailing whitespace."
                .into(),
        );
    }
    if message.contains('\r')
        || message
            .chars()
            .any(|character| character.is_control() && character != '\n')
    {
        return Err("The commit message contains unsupported control characters.".into());
    }
    let subject = message.lines().next().unwrap_or("");
    if subject.is_empty() || subject.len() > 72 {
        return Err("The commit subject must be 1-72 characters.".into());
    }
    Ok(())
}

fn staged_paths(path: &Path) -> Result<Vec<String>, String> {
    let output = git_output_bytes(
        path,
        &["diff", "--cached", "--name-only", "-z"],
        "inspect a bounded staged path list",
        4 * 1024 * 1024,
    )?;
    let mut paths = Vec::new();
    for raw in output
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let path = std::str::from_utf8(raw)
            .map_err(|_| "A staged path is not valid UTF-8 and cannot be reviewed safely.")?;
        if paths.len() >= 1_000 {
            return Err(
                "More than 1,000 paths are staged; split the commit before continuing.".into(),
            );
        }
        paths.push(path.to_owned());
    }
    if paths.is_empty() {
        return Err(
            "No staged changes are available. Stage reviewed files in VS Code first.".into(),
        );
    }
    Ok(paths)
}

const MAINTAINER_PATCH_LIMIT: usize = 1024 * 1024;

pub(crate) fn contains_sensitive_patch_content(patch: &str) -> bool {
    let added_content = patch
        .lines()
        .filter_map(|line| line.strip_prefix('+').filter(|_| !line.starts_with("+++ ")))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    let markers = [
        ["-----begin private ", "key-----"].concat(),
        ["-----begin rsa private ", "key-----"].concat(),
        ["-----begin open", "ssh private key-----"].concat(),
        ["authorization: ", "bearer "].concat(),
        ["github", "_pat_"].concat(),
        ["gh", "p_"].concat(),
        ["aws_secret", "_access_key"].concat(),
    ];
    markers
        .iter()
        .any(|marker| added_content.contains(marker.as_str()))
}

fn staged_patch(path: &Path) -> Result<(String, String), String> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(path)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args([
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            "--full-index",
            "--no-color",
            "--unified=3",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("Could not start the staged patch review: {error}"))?;
    let mut bytes = Vec::new();
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Could not read the staged patch review.".into());
    };
    if let Err(error) = stdout
        .take((MAINTAINER_PATCH_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("Could not read the staged patch review: {error}"));
    }
    if bytes.len() > MAINTAINER_PATCH_LIMIT {
        let _ = child.kill();
        let _ = child.wait();
        return Err(
            "The staged patch exceeds 1 MiB; split it into smaller reviewable commits.".into(),
        );
    }
    let status = child
        .wait()
        .map_err(|error| format!("Could not finish the staged patch review: {error}"))?;
    if !status.success() || bytes.is_empty() {
        return Err("Git could not produce a non-empty staged patch review.".into());
    }
    let patch = String::from_utf8(bytes)
        .map_err(|_| "The staged patch is not valid UTF-8 and cannot be reviewed safely.")?;
    if patch
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err("The staged patch contains unsupported control characters.".into());
    }
    if contains_sensitive_patch_content(&patch) {
        return Err("The staged patch appears to contain a credential or private key. Remove it from the staged set before committing.".into());
    }
    let sha256 = format!("{:x}", Sha256::digest(patch.as_bytes()));
    Ok((patch, sha256))
}

pub(crate) fn unsafe_staged_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    path.starts_with('/')
        || path.chars().any(char::is_control)
        || path.split('/').any(|part| part == ".." || part.is_empty())
        || lower.split('/').any(|part| {
            part == ".env"
                || part.starts_with(".env.")
                || part.contains("credential")
                || part.contains("secret")
                || part == ".ssh"
        })
        || ["node_modules/", "target/", "src-tauri/target/", ".git/"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        || [
            ".img", ".qcow2", ".iso", ".raw", ".pem", ".key", ".p12", ".pfx",
        ]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn review_staged_commit_blocking(
    path: String,
    repository: String,
    message: String,
) -> Result<MaintainerCommitReview, String> {
    validate_local_commit_message(&message)?;
    let worktree = inspect_maintainer_worktree_blocking(path, repository)?;
    let branch = worktree
        .branch
        .ok_or("Local commits require a named branch; detached HEAD is not allowed.")?;
    let paths = staged_paths(Path::new(&worktree.path))?;
    let unsafe_paths = paths
        .iter()
        .filter(|path| unsafe_staged_path(path))
        .take(20)
        .cloned()
        .collect::<Vec<_>>();
    if !unsafe_paths.is_empty() {
        return Err(format!(
            "The staged set includes blocked generated or credential-like paths: {}",
            unsafe_paths.join(", ")
        ));
    }
    let index_tree = git_output(
        Path::new(&worktree.path),
        &["write-tree"],
        "snapshot the exact staged tree",
    )?;
    if !valid_git_commit(&index_tree) {
        return Err("Git did not return a valid staged tree identity.".into());
    }
    let (patch_preview, patch_sha256) = staged_patch(Path::new(&worktree.path))?;
    Ok(MaintainerCommitReview {
        repository: worktree.repository,
        path: worktree.path,
        branch,
        head: worktree.head,
        index_tree,
        staged_paths: paths,
        patch_sha256,
        patch_preview,
        message,
    })
}

#[tauri::command]
pub(crate) async fn review_maintainer_staged_commit(
    path: String,
    repository: String,
    message: String,
) -> Result<MaintainerCommitReview, String> {
    tauri::async_runtime::spawn_blocking(move || {
        review_staged_commit_blocking(path, repository, message)
    })
    .await
    .map_err(|error| format!("Maintainer commit-review worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn create_maintainer_local_commit(
    path: String,
    repository: String,
    message: String,
    expected_head: String,
    expected_index_tree: String,
    expected_patch_sha256: String,
) -> Result<MaintainerLocalCommit, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let review = review_staged_commit_blocking(path, repository, message)?;
        if review.head != expected_head
            || review.index_tree != expected_index_tree
            || review.patch_sha256 != expected_patch_sha256
        {
            return Err("HEAD, the staged tree, or its reviewed patch changed after review. Review the commit again.".into());
        }
        let output = bounded_git_mutation(Path::new("git"), Path::new(&review.path),
            &["commit-tree", &review.index_tree, "-p", &review.head], Some(review.message.as_bytes()),
            Duration::from_secs(15), 64 * 1024, "create the exact local commit object")?;
        let commit = String::from_utf8(output)
            .map_err(|_| "Git returned a non-UTF-8 local commit identity.")?
            .trim()
            .to_owned();
        if !valid_git_commit(&commit) {
            return Err("Git returned an invalid local commit identity.".into());
        }
        bounded_git_mutation(Path::new("git"), Path::new(&review.path),
            &["update-ref", "-m", "commit: maintainer workspace", "HEAD", &commit, &review.head], None,
            Duration::from_secs(15), 64 * 1024, "attach the local commit atomically")?;
        Ok(MaintainerLocalCommit {
            repository: review.repository,
            path: review.path,
            branch: review.branch,
            previous_head: review.head,
            commit,
            index_tree: review.index_tree,
            pushed: false,
            message: "Created an exact local commit from the reviewed staged tree. Nothing was pushed.".into(),
        })
    })
    .await
    .map_err(|error| format!("Maintainer local-commit worker failed: {error}"))?
}

pub(crate) fn valid_local_branch_name(value: &str) -> bool {
    valid_maintainer_git_reference(value)
        && value != "HEAD"
        && !value.starts_with('-')
        && !value.starts_with("refs/")
        && !value.ends_with(['~', '^'])
}

fn local_branches_blocking(
    path: String,
    repository: String,
) -> Result<(MaintainerLocalWorktree, Vec<MaintainerLocalBranch>), String> {
    let worktree = inspect_maintainer_worktree_blocking(path, repository)?;
    let current_branch = worktree
        .branch
        .as_deref()
        .ok_or("Branch changes require a named current branch; detached HEAD is not allowed.")?;
    if worktree.changed_files != 0 {
        return Err("Branch changes require a completely clean worktree, index, and untracked-file set. Commit, move, or remove those changes manually first.".into());
    }
    let output = git_output_bytes(
        Path::new(&worktree.path),
        &[
            "for-each-ref",
            "--format=%(refname:short)%09%(objectname)",
            "refs/heads/",
        ],
        "list a bounded set of local branches",
        1024 * 1024,
    )?;
    let stdout =
        String::from_utf8(output).map_err(|_| "Local branch metadata is not valid UTF-8.")?;
    let mut branches = Vec::new();
    for line in stdout.lines().filter(|line| !line.is_empty()) {
        if branches.len() >= 1_000 {
            return Err(
                "More than 1,000 local branches exist; manage them directly with Git.".into(),
            );
        }
        let (name, commit) = line
            .split_once('\t')
            .ok_or("Git returned malformed local branch metadata.")?;
        if !valid_local_branch_name(name) || !valid_git_commit(commit) {
            return Err("Git returned an unsafe local branch identity.".into());
        }
        branches.push(MaintainerLocalBranch {
            name: name.into(),
            commit: commit.to_ascii_lowercase(),
            current: name == current_branch,
        });
    }
    if branches.is_empty() || branches.iter().filter(|branch| branch.current).count() != 1 {
        return Err("The current named branch is missing from the local branch set.".into());
    }
    Ok((worktree, branches))
}

#[tauri::command]
pub(crate) async fn list_maintainer_local_branches(
    path: String,
    repository: String,
) -> Result<Vec<MaintainerLocalBranch>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        local_branches_blocking(path, repository).map(|(_, branches)| branches)
    })
    .await
    .map_err(|error| format!("Maintainer local-branch worker failed: {error}"))?
}

fn review_checkout_blocking(
    path: String,
    repository: String,
    target_branch: String,
) -> Result<MaintainerCheckoutReview, String> {
    if !valid_local_branch_name(&target_branch) {
        return Err("The selected local branch name is unsafe.".into());
    }
    let (worktree, branches) = local_branches_blocking(path, repository)?;
    let current_branch = worktree.branch.ok_or("The current branch disappeared.")?;
    let matches = branches
        .iter()
        .filter(|branch| branch.name == target_branch)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err("The selected local branch is missing or ambiguous. Refresh branches.".into());
    }
    Ok(MaintainerCheckoutReview {
        repository: worktree.repository,
        path: worktree.path,
        current_branch,
        current_head: worktree.head,
        target_branch,
        target_commit: matches[0].commit.clone(),
        message: "Clean local branch change reviewed. No fetch, reset, force, remote, or file-discard operation is allowed.".into(),
    })
}

#[tauri::command]
pub(crate) async fn review_maintainer_checkout(
    path: String,
    repository: String,
    target_branch: String,
) -> Result<MaintainerCheckoutReview, String> {
    tauri::async_runtime::spawn_blocking(move || {
        review_checkout_blocking(path, repository, target_branch)
    })
    .await
    .map_err(|error| format!("Maintainer checkout-review worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn execute_maintainer_checkout(
    path: String,
    repository: String,
    target_branch: String,
    expected_head: String,
    expected_target_commit: String,
) -> Result<MaintainerCheckoutResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let review = review_checkout_blocking(path, repository, target_branch)?;
        if review.current_head != expected_head || review.target_commit != expected_target_commit {
            return Err("The current or target branch changed after review. Review the branch change again.".into());
        }
        let output = Command::new("git")
            .arg("-C")
            .arg(&review.path)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "switch",
                "--no-guess",
                "--",
                &review.target_branch,
            ])
            .output()
            .map_err(|error| format!("Could not switch the clean local branch: {error}"))?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Git refused the clean local branch change: {}", detail.trim()));
        }
        let checkout_path = Path::new(&review.path);
        let after_branch = git_output(
            checkout_path,
            &["branch", "--show-current"],
            "verify the resulting local branch",
        )?;
        let after_head = git_output(
            checkout_path,
            &["rev-parse", "HEAD"],
            "verify the resulting local HEAD",
        )?;
        let after_status = git_output(
            checkout_path,
            &["status", "--porcelain=v1", "--untracked-files=all"],
            "verify the resulting clean worktree",
        )?;
        if after_branch != review.target_branch
            || after_head != review.target_commit
            || !after_status.is_empty()
        {
            return Err("The local branch change did not finish in the exact reviewed clean state. Inspect the worktree manually; no cleanup was attempted.".into());
        }
        Ok(MaintainerCheckoutResult {
            repository: review.repository,
            path: review.path,
            previous_branch: review.current_branch,
            previous_head: review.current_head,
            branch: review.target_branch,
            head: review.target_commit,
            remote_changed: false,
            message: "Changed to the exact reviewed local branch. No fetch, reset, force, or remote operation occurred.".into(),
        })
    })
    .await
    .map_err(|error| format!("Maintainer checkout worker failed: {error}"))?
}

pub(crate) fn fetch_nvidia_source_branches(
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

pub(crate) fn fetch_upstream_nvidia_tags(
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
pub(crate) async fn list_nvidia_source_branches(
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

pub(crate) struct PublishedDownloadContext<'a> {
    client: &'a reqwest::blocking::Client,
    cancel: &'a AtomicBool,
    progress: &'a dyn Fn(&str, u64, u64),
}

pub(crate) fn download_release_asset(
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
    admit_host_storage(&[StorageRequest {
        path: destination
            .parent()
            .ok_or("Published NVIDIA asset path has no parent.")?,
        bytes: checked_space_sum([asset.size, HOST_STORAGE_METADATA_RESERVE])?,
        inodes: 1,
        purpose: "published NVIDIA artifact staging",
    }])?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|e| storage_io_error(&format!("Could not stage {}", asset.name), e))?;
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
            .map_err(|e| storage_io_error(&format!("Could not write {}", asset.name), e))?;
        hasher.update(&buffer[..count]);
        if downloaded >= next_report {
            (context.progress)(stage, downloaded, asset.size);
            next_report = downloaded.saturating_add(1024 * 1024);
        }
    }
    output
        .sync_all()
        .map_err(|e| storage_io_error(&format!("Could not finish staging {}", asset.name), e))?;
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

pub(crate) fn metadata_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
}

pub(crate) fn validate_published_nvidia_artifact(
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

pub(crate) fn resolve_published_nvidia_for_target(
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
    validate_ready_nvidia_target(&target)?;
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
                core_authorization: None,
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
    admit_host_storage(&[StorageRequest {
        path: runtime_dir,
        bytes: checked_space_sum([
            archive_asset.size,
            checksum_asset.size,
            provenance_asset.size,
            HOST_STORAGE_METADATA_RESERVE,
        ])?,
        inodes: 4,
        purpose: "the complete published NVIDIA artifact staging batch",
    }])?;
    fs::create_dir(&output_dir)
        .map_err(|e| storage_io_error("Could not create published NVIDIA staging", e))?;
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

#[cfg(test)]
pub(crate) fn arch_package_release_key(value: &str) -> Option<Vec<u64>> {
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

#[cfg(test)]
pub(crate) fn arch_index_hrefs(index: &str) -> HashSet<String> {
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

#[cfg(test)]
pub(crate) fn select_arch_userspace_package(
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

pub(crate) fn arch_package_directory(package: &str) -> Result<&'static str, String> {
    match package {
        "nvidia-utils" => Ok("https://archive.archlinux.org/packages/n/nvidia-utils"),
        "lib32-nvidia-utils" => Ok("https://archive.archlinux.org/packages/l/lib32-nvidia-utils"),
        _ => Err("Unsupported NVIDIA userspace package name.".into()),
    }
}

#[cfg(test)]
pub(crate) fn query_arch_userspace_package(
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

pub(crate) fn arch_dependency_name(specification: &str) -> Result<&str, String> {
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
pub(crate) fn natural_arch_version_cmp(left: &str, right: &str) -> std::cmp::Ordering {
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
pub(crate) fn select_arch_dependency_package(
    index: &str,
    package: &str,
) -> Result<(String, String), String> {
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

pub(crate) fn arch_dependency_directory(package: &str) -> Result<String, String> {
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
pub(crate) fn query_arch_dependency_package(
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
pub(crate) fn stage_arch_dependency_package(
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

#[cfg(test)]
pub(crate) fn preflight_nvidia_userspace(
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

pub(crate) fn download_arch_userspace_asset(
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
    admit_host_storage(&[StorageRequest {
        path: destination
            .parent()
            .ok_or("NVIDIA userspace asset path has no parent.")?,
        bytes: checked_space_sum([
            if total == 0 { limit } else { total },
            HOST_STORAGE_METADATA_RESERVE,
        ])?,
        inodes: 1,
        purpose: "reviewed NVIDIA userspace package staging",
    }])?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|e| storage_io_error("Could not stage NVIDIA userspace input", e))?;
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
            .map_err(|e| storage_io_error("Could not write NVIDIA userspace input", e))?;
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
        .sync_all()
        .map_err(|e| storage_io_error("Could not finish NVIDIA userspace input", e))?;
    progress(stage, downloaded, total);
    fs::rename(&partial, destination)
        .map_err(|e| format!("Could not finalize NVIDIA userspace input: {e}"))?;
    guard.armed = false;
    Ok(format!("{:x}", hasher.finalize()))
}

pub(crate) fn resolve_nvidia_userspace_for_version(
    runtime_dir: &Path,
    installer_root: &Path,
    steamos_version: &str,
    nvidia_version: &str,
    client: &reqwest::blocking::Client,
    cancel: &AtomicBool,
    progress: &impl Fn(&str, u64, u64),
) -> Result<NvidiaUserspaceResolution, String> {
    if !valid_numeric_version(nvidia_version, 2..=3) {
        return Err("Published NVIDIA artifact has an invalid userspace version.".into());
    }
    let lock = load_reviewed_userspace_lock(installer_root, steamos_version, nvidia_version)?;
    admit_host_storage(&[StorageRequest {
        path: runtime_dir,
        bytes: 0,
        inodes: 1,
        purpose: "reviewed NVIDIA userspace staging directory",
    }])?;
    let output_dir = runtime_dir.join(format!(
        "nvidia-userspace-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    fs::create_dir(&output_dir)
        .map_err(|e| storage_io_error("Could not create NVIDIA userspace staging", e))?;
    let mut output_guard = StagingDirectoryGuard {
        path: output_dir.clone(),
        armed: true,
    };
    let mut packages = Vec::with_capacity(lock.packages.len());
    for locked in &lock.packages {
        if cancel.load(Ordering::Relaxed) {
            return Err("NVIDIA userspace resolution cancelled.".into());
        }
        progress(
            "staging-reviewed-userspace-closure",
            packages.len() as u64,
            lock.packages.len() as u64,
        );
        let directory = if matches!(locked.name.as_str(), "nvidia-utils" | "lib32-nvidia-utils") {
            arch_package_directory(&locked.name)?.into()
        } else {
            arch_dependency_directory(&locked.name)?
        };
        let package_limit = match locked.name.as_str() {
            "nvidia-utils" => NVIDIA_UTILS_ARCHIVE_LIMIT,
            "lib32-nvidia-utils" => LIB32_NVIDIA_UTILS_ARCHIVE_LIMIT,
            _ => NVIDIA_DEPENDENCY_ARCHIVE_LIMIT,
        };
        let package_path = output_dir.join(&locked.filename);
        let signature_path = output_dir.join(&locked.signature_filename);
        let package_sha256 = download_arch_userspace_asset(
            client,
            &format!("{directory}/{}", locked.filename),
            &package_path,
            package_limit,
            cancel,
            "downloading-locked-userspace-package",
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
            return Err(format!(
                "Downloaded {} does not match the reviewed userspace lock.",
                locked.name
            ));
        }
        let package = NvidiaUserspacePackage {
            name: locked.name.clone(),
            role: if matches!(locked.name.as_str(), "nvidia-utils" | "lib32-nvidia-utils") {
                "nvidia-userspace".into()
            } else {
                "dependency".into()
            },
            filename: locked.filename.clone(),
            full_version: locked.version.clone(),
            package_path: package_path.to_string_lossy().into_owned(),
            signature_path: signature_path.to_string_lossy().into_owned(),
            package_sha256,
        };
        validate_locked_userspace_package(&package, locked)?;
        packages.push(package);
    }
    progress(
        "staging-reviewed-userspace-closure",
        lock.packages.len() as u64,
        lock.packages.len() as u64,
    );
    let resolution = NvidiaUserspaceResolution {
        schema_version: 1,
        status: "prepared".into(),
        reason: "reviewed_userspace_closure_staged".into(),
        message: format!(
            "Staged the complete reviewed NVIDIA {nvidia_version} userspace closure for SteamOS {steamos_version}; signatures remain pending x86 appliance verification."
        ),
        nvidia_version: nvidia_version.into(),
        signature_status: "pending-x86-validation".into(),
        packages,
    };
    output_guard.armed = false;
    Ok(resolution)
}

pub(crate) fn valid_prepared_userspace_packages(packages: &[NvidiaUserspacePackage]) -> bool {
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

pub(crate) fn exact_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn canonical_package_relations(relations: &[String]) -> Option<Vec<&str>> {
    if relations.len() > 64 {
        return None;
    }
    let mut seen = HashSet::new();
    let mut canonical = Vec::with_capacity(relations.len());
    for relation in relations {
        if relation.is_empty()
            || relation.len() > 256
            || !relation.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'@' | b'.' | b'_' | b'+' | b'<' | b'>' | b'=' | b':' | b'-'
                    )
            })
            || !seen.insert(relation.as_str())
        {
            return None;
        }
        canonical.push(relation.as_str());
    }
    canonical.sort_unstable();
    Some(canonical)
}

pub(crate) fn package_relations_match(left: &[String], right: &[String]) -> bool {
    matches!(
        (
            canonical_package_relations(left),
            canonical_package_relations(right)
        ),
        (Some(left), Some(right)) if left == right
    )
}

pub(crate) fn load_reviewed_userspace_lock(
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
            || canonical_package_relations(&package.dependencies).is_none()
            || canonical_package_relations(&package.provides).is_none()
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

pub(crate) fn validate_locked_userspace_package(
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

pub(crate) fn stage_reviewed_userspace_closure(
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

pub(crate) fn validate_pinned_support_files(
    commit: &str,
    files: &[PinnedInstallerFile],
) -> Result<u64, String> {
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
            || !file
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

pub(crate) fn apply_pinned_file_permissions(path: &Path, executable: bool) -> Result<(), String> {
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

pub(crate) fn pinned_installer_guest_permissions() -> Result<String, String> {
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

pub(crate) fn validate_pinned_installer_contract() -> Result<u64, String> {
    validate_pinned_support_files(NVIDIA_INSTALLER_COMMIT, &PINNED_INSTALLER_FILES)
}

pub(crate) fn validate_pinned_publisher_contract() -> Result<u64, String> {
    validate_pinned_support_files(NVIDIA_SUPPORT_COMMIT, &PINNED_PUBLISHER_FILES)
}

pub(crate) fn download_pinned_installer_file(
    client: &reqwest::blocking::Client,
    source: (&str, &PinnedInstallerFile),
    destination: &Path,
    completed_before: u64,
    total_bytes: u64,
    cancel: &AtomicBool,
    progress: &impl Fn(&str, u64, u64),
) -> Result<(), String> {
    let (commit, file) = source;
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
        "https://raw.githubusercontent.com/{NVIDIA_SUPPORT_REPOSITORY}/{commit}/{}",
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
    admit_host_storage(&[StorageRequest {
        path: parent,
        bytes: checked_space_sum([file.bytes, HOST_STORAGE_METADATA_RESERVE])?,
        inodes: 1,
        purpose: "pinned NVIDIA installer staging",
    }])?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|e| {
            storage_io_error(
                &format!("Could not stage pinned support file {}", file.path),
                e,
            )
        })?;
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
        output.write_all(&buffer[..count]).map_err(|e| {
            storage_io_error(
                &format!("Could not write pinned support file {}", file.path),
                e,
            )
        })?;
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
    output.sync_all().map_err(|e| {
        storage_io_error(
            &format!("Could not finish pinned support file {}", file.path),
            e,
        )
    })?;
    drop(output);
    apply_pinned_file_permissions(&partial, file.executable)?;
    fs::rename(&partial, destination)
        .map_err(|e| format!("Could not finalize pinned support file {}: {e}", file.path))?;
    partial_guard.armed = false;
    Ok(())
}

fn pinned_bundle_inodes(
    files: &[PinnedInstallerFile],
    additional_files: u64,
) -> Result<u64, String> {
    let mut directories = HashSet::new();
    for file in files {
        let mut parent = Path::new(file.path).parent();
        while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
            directories.insert(path.to_path_buf());
            parent = path.parent();
        }
    }
    (files.len() as u64)
        .checked_add(directories.len() as u64)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(additional_files))
        .ok_or_else(|| "Pinned support bundle inode requirement overflowed.".into())
}

pub(crate) fn prepare_pinned_nvidia_installer_bundle(
    runtime_dir: &Path,
    client: &reqwest::blocking::Client,
    cancel: &AtomicBool,
    progress: &impl Fn(&str, u64, u64),
) -> Result<NvidiaInstallerBundleState, String> {
    let total_bytes = validate_pinned_installer_contract()?;
    let root = runtime_dir.join(format!("nvidia-installer-{NVIDIA_INSTALLER_COMMIT}"));
    let staging_inodes = pinned_bundle_inodes(&PINNED_INSTALLER_FILES, 1)?;
    admit_host_storage(&[StorageRequest {
        path: runtime_dir,
        bytes: checked_space_sum([
            total_bytes,
            PROVENANCE_RESPONSE_LIMIT,
            HOST_STORAGE_METADATA_RESERVE,
        ])?,
        inodes: staging_inodes,
        purpose: "the complete pinned NVIDIA installer bundle and manifest",
    }])?;
    fs::create_dir(&root)
        .map_err(|e| storage_io_error("Could not create pinned NVIDIA installer staging", e))?;
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
            (NVIDIA_INSTALLER_COMMIT, file),
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
        .map_err(|e| storage_io_error("Could not stage NVIDIA installer manifest", e))?;
    fs::rename(staged_manifest, manifest_path)
        .map_err(|e| format!("Could not finalize NVIDIA installer manifest: {e}"))?;
    progress("downloading-nvidia-installer", total_bytes, total_bytes);
    root_guard.armed = false;
    Ok(NvidiaInstallerBundleState { root, report })
}

pub(crate) fn validate_staged_pinned_files(
    root: &Path,
    files: &[PinnedInstallerFile],
) -> Result<(), String> {
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

pub(crate) fn prepare_pinned_nvidia_publisher(runtime_dir: &Path) -> Result<PathBuf, String> {
    let total_bytes = validate_pinned_publisher_contract()?;
    let root = runtime_dir.join(format!("nvidia-publisher-{NVIDIA_SUPPORT_COMMIT}"));
    if root.is_dir() {
        validate_staged_pinned_files(&root, &PINNED_PUBLISHER_FILES)?;
        return Ok(root);
    }
    admit_host_storage(&[StorageRequest {
        path: runtime_dir,
        bytes: checked_space_sum([total_bytes, HOST_STORAGE_METADATA_RESERVE])?,
        inodes: pinned_bundle_inodes(&PINNED_PUBLISHER_FILES, 0)?,
        purpose: "the complete pinned NVIDIA publisher bundle",
    }])?;
    fs::create_dir(&root)
        .map_err(|e| storage_io_error("Could not create pinned NVIDIA publisher staging", e))?;
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
            (NVIDIA_SUPPORT_COMMIT, file),
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

pub(crate) fn validate_support_publication_plan(
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

pub(crate) fn support_publisher_command(
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

pub(crate) fn validate_staged_nvidia_installer_bundle(
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

pub(crate) fn nvidia_development_asset_name(spec: &NvidiaTargetBuildSpec) -> String {
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

pub(crate) fn validate_support_build_result(
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

pub(crate) fn validate_support_build_provenance(
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

pub(crate) fn run_guest_command_logged(
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
    let detail = guest_command_failure_detail(&bytes);
    Err(if detail.is_empty() {
        format!("NVIDIA appliance command exited with {status}.")
    } else {
        format!("NVIDIA appliance command exited with {status}: {detail}")
    })
}

pub(crate) fn guest_command_failure_detail(bytes: &[u8]) -> String {
    const TAIL_BYTES: usize = 64 * 1024;
    const MAX_DETAIL_CHARACTERS: usize = 2 * 1024;
    const MAX_DETAIL_LINES: usize = 12;

    let start = bytes.len().saturating_sub(TAIL_BYTES);
    let tail = String::from_utf8_lossy(&bytes[start..]);
    let contract_failure = tail
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| line.starts_with("installer contract rejected:"));
    if let Some(failure) = contract_failure {
        return failure.chars().take(MAX_DETAIL_CHARACTERS).collect();
    }
    let mut lines = Vec::new();
    for line in tail.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("STEAMOS_NVIDIA_PROGRESS ")
            || line.starts_with(",\"")
        {
            continue;
        }
        if lines.last().is_some_and(|previous| *previous == line) {
            continue;
        }
        lines.push(line);
        if lines.len() > MAX_DETAIL_LINES {
            lines.remove(0);
        }
    }
    let detail = lines.join("\n");
    if detail.chars().count() <= MAX_DETAIL_CHARACTERS {
        detail
    } else {
        let suffix: String = detail
            .chars()
            .rev()
            .take(MAX_DETAIL_CHARACTERS)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("…{suffix}")
    }
}

pub(crate) enum NvidiaSupportSource<'a> {
    Local(&'a Path),
    PinnedGithub,
}

pub(crate) struct NvidiaSourcePin<'a> {
    pub(crate) origin: &'a str,
    pub(crate) repository: &'a str,
    pub(crate) reference: &'a str,
    pub(crate) commit: &'a str,
}

#[cfg(test)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NvidiaSourceContractPreflight {
    schema_version: u32,
    status: String,
    architecture: String,
    support_repository: String,
    support_commit: String,
    source_repository: String,
    pub(crate) source_reference: String,
    pub(crate) source_commit: String,
    source_repository_url: String,
    pub(crate) plan: serde_json::Value,
}

#[cfg(test)]
pub(crate) fn preflight_nvidia_source_contract(
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

pub(crate) fn build_nvidia_for_target_from_source(
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
    admit_host_storage(&[StorageRequest {
        path: session.runtime_dir(),
        bytes: checked_space_sum([
            NVIDIA_ARCHIVE_LIMIT,
            CHECKSUM_RESPONSE_LIMIT,
            PROVENANCE_RESPONSE_LIMIT,
            PROVENANCE_RESPONSE_LIMIT,
            HOST_STORAGE_METADATA_RESERVE,
        ])?,
        inodes: 5,
        purpose: "generated NVIDIA artifact handoff staging",
    }])?;
    fs::create_dir_all(&download_dir).map_err(|e| {
        storage_io_error(
            "Could not create the artifact download staging directory",
            e,
        )
    })?;
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

pub(crate) fn build_nvidia_for_target(
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

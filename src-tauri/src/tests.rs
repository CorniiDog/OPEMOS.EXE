#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn qemu_watchdog_terminates_its_exact_child_when_keepalive_closes() {
        let mut target = Command::new("/bin/sh");
        target
            .args(["-c", "exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        isolate_process_group(&mut target);
        let mut target = target.spawn().expect("start watchdog target");
        let watchdog = spawn_qemu_watchdog(target.id()).expect("start lifecycle watchdog");
        drop(watchdog);
        let exit = target.try_wait().expect("inspect watchdog target");
        if exit.is_none() {
            let _ = target.kill();
            let _ = target.wait();
        }
        assert!(exit.is_some(), "watchdog left its target running");
    }

    #[test]
    #[ignore = "launches a local QEMU smoke process and verifies watchdog cleanup"]
    fn live_qemu_smoke_watchdog_exits_cleanly() {
        smoke_test_qemu(&find_qemu().expect("QEMU is required"))
            .expect("QEMU smoke process should start and stop cleanly");
    }

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
    fn maintainer_worktree_remote_parser_accepts_only_github_repository_roots() {
        assert_eq!(
            repository_from_remote("https://github.com/CorniiDog/gamescope-nvidia.git"),
            Some("CorniiDog/gamescope-nvidia".into())
        );
        assert_eq!(
            repository_from_remote("git@github.com:CorniiDog/gamescope-nvidia.git"),
            Some("CorniiDog/gamescope-nvidia".into())
        );
        assert_eq!(
            repository_from_remote("ssh://git@github.com/ValveSoftware/gamescope"),
            Some("ValveSoftware/gamescope".into())
        );
        assert_eq!(repository_from_remote("https://example.com/owner/repository"), None);
        assert_eq!(repository_from_remote("https://github.com/owner/repository/extra"), None);
    }

    #[test]
    fn maintainer_local_commit_rejects_unsafe_messages_and_paths() {
        assert!(validate_local_commit_message("Add guarded local commit flow").is_ok());
        assert!(validate_local_commit_message("").is_err());
        assert!(validate_local_commit_message(" leading").is_err());
        assert!(validate_local_commit_message("trailing ").is_err());
        assert!(validate_local_commit_message(&"x".repeat(73)).is_err());
        assert!(validate_local_commit_message("subject\rbody").is_err());

        assert!(!unsafe_staged_path("src/maintainer.js"));
        assert!(!unsafe_staged_path("docs/commit-design.md"));
        assert!(unsafe_staged_path(".env"));
        assert!(unsafe_staged_path("config/production.secret.json"));
        assert!(unsafe_staged_path("src-tauri/target/debug/app"));
        assert!(unsafe_staged_path("output/recovery.img"));
        assert!(unsafe_staged_path("keys/release.pem"));
        assert!(unsafe_staged_path("../outside.txt"));
        assert!(unsafe_staged_path("line\nbreak.txt"));

        assert!(!contains_sensitive_patch_content(
            "diff --git a/src/app.rs b/src/app.rs\n+++ b/src/app.rs\n+safe local code"
        ));
        assert!(contains_sensitive_patch_content(
            "+Authorization: Bearer example-token"
        ));
        let private_key_marker = ["+-----BEGIN OPEN", "SSH PRIVATE KEY-----"].concat();
        assert!(contains_sensitive_patch_content(&private_key_marker));
        let github_token_marker = ["+token=github", "_pat_example"].concat();
        assert!(contains_sensitive_patch_content(&github_token_marker));
        let removed_token_marker = ["-token=github", "_pat_example"].concat();
        assert!(!contains_sensitive_patch_content(&removed_token_marker));
        let context_token_marker = [" token=github", "_pat_example"].concat();
        assert!(!contains_sensitive_patch_content(&context_token_marker));
        let header_marker = ["+++ github", "_pat_example"].concat();
        assert!(!contains_sensitive_patch_content(&header_marker));
    }

    #[test]
    fn maintainer_checkout_accepts_only_safe_local_branch_names() {
        assert!(valid_local_branch_name("main"));
        assert!(valid_local_branch_name("feature/local-context"));
        assert!(valid_local_branch_name("release-1.2.3"));
        assert!(!valid_local_branch_name("HEAD"));
        assert!(!valid_local_branch_name("refs/heads/main"));
        assert!(!valid_local_branch_name("--detach"));
        assert!(!valid_local_branch_name("../main"));
        assert!(!valid_local_branch_name("feature//unsafe"));
        assert!(!valid_local_branch_name("feature@{1}"));
        assert!(!valid_local_branch_name("branch.lock"));
        assert!(!valid_local_branch_name("branch name"));
    }

    #[test]
    fn usb_candidate_parser_rejects_internal_virtual_and_undersized_disks() {
        let removable = serde_json::json!({
            "DeviceIdentifier": "disk7",
            "DeviceNode": "/dev/disk7",
            "Whole": true,
            "Internal": false,
            "VirtualOrPhysical": "Physical",
            "RemovableMedia": true,
            "Ejectable": true,
            "TotalSize": 64_000_000_000_u64,
            "MediaName": "Test USB",
            "BusProtocol": "USB"
        });
        let candidate = usb_candidate_from_diskutil_info(&removable, 32_000_000_000, Some("disk7"))
            .expect("safe removable disk");
        assert_eq!(candidate.device_identifier, "disk7");
        assert_eq!(candidate.device_node, "/dev/disk7");

        let mut internal = removable.clone();
        internal["Internal"] = serde_json::json!(true);
        assert!(usb_candidate_from_diskutil_info(&internal, 32_000_000_000, Some("disk7")).is_none());

        let mut virtual_disk = removable.clone();
        virtual_disk["VirtualOrPhysical"] = serde_json::json!("Virtual");
        assert!(usb_candidate_from_diskutil_info(&virtual_disk, 32_000_000_000, Some("disk7")).is_none());

        assert!(usb_candidate_from_diskutil_info(&removable, 128_000_000_000, Some("disk7")).is_none());

        assert!(usb_candidate_from_diskutil_info(&removable, 32_000_000_000, Some("disk8")).is_none());

        let mut partition = removable;
        partition["DeviceIdentifier"] = serde_json::json!("disk7s1");
        partition["DeviceNode"] = serde_json::json!("/dev/disk7s1");
        assert!(usb_candidate_from_diskutil_info(&partition, 32_000_000_000, Some("disk7s1")).is_none());
    }

    #[test]
    fn usb_preflight_state_replaces_cancels_and_expires_sessions() {
        let now = Instant::now();
        let mut manager = UsbPreparationManager::default();
        manager.arm("first".into(), now);
        assert!(manager.is_armed());
        assert!(!manager.cancel(Some("wrong"), now));
        assert!(manager.is_armed());

        manager.arm("second".into(), now);
        assert!(!manager.cancel(Some("first"), now));
        assert!(manager.cancel(Some("second"), now));
        assert!(!manager.is_armed());

        manager.arm("expired".into(), now);
        assert!(!manager.cancel(Some("expired"), now + USB_PREFLIGHT_TTL));
        assert!(!manager.is_armed());

        manager.arm("cancel-any".into(), now);
        assert!(manager.cancel(None, now));
        assert!(!manager.is_armed());
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
        assert_eq!(validate_pinned_installer_contract().unwrap(), 247_343);
        assert_eq!(PINNED_INSTALLER_FILES.len(), 16);
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
            .any(|file| file.path == "lib/prepare_pacman_config.py" && file.executable));
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
        assert!(guest_permissions.contains("\"$WORK/support/lib/prepare_pacman_config.py\""));
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

        let source = include_str!("installer.rs");
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
        let source = concat!(include_str!("installer.rs"), include_str!("image.rs"));
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
    fn package_relations_ignore_order_but_reject_unsafe_or_ambiguous_sets() {
        let reviewed = vec![
            "libglvnd".to_string(),
            "egl-wayland".to_string(),
            "egl-gbm".to_string(),
            "egl-x11".to_string(),
        ];
        let validated = vec![
            "egl-gbm".to_string(),
            "egl-wayland".to_string(),
            "egl-x11".to_string(),
            "libglvnd".to_string(),
        ];
        assert!(package_relations_match(&reviewed, &validated));

        let duplicate = vec!["egl-gbm".to_string(), "egl-gbm".to_string()];
        assert!(!package_relations_match(&duplicate, &validated));
        assert!(!package_relations_match(
            &["../../unsafe".to_string()],
            &["../../unsafe".to_string()]
        ));
        assert!(!package_relations_match(
            &["egl-gbm".to_string()],
            &validated
        ));
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
                pacman_check_space_bypass_authorized: false,
                pacman_check_space_policy: "preserve".into(),
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
        let mut userspace_lock = ReviewedUserspaceLock {
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
        userspace_lock.packages[0].dependencies = vec![
            "libglvnd".into(),
            "egl-wayland".into(),
            "egl-gbm".into(),
            "egl-x11".into(),
        ];
        userspace_lock.packages[0].provides = vec!["vulkan-driver".into(), "opengl-driver".into()];
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
        let validated_package = |name: &str, release: &str, signer: &str, signer_digest: char| {
            let mut package = SupportInstallPackage {
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
            if name == "nvidia-utils" {
                package.dependencies = vec![
                    "egl-gbm".into(),
                    "egl-wayland".into(),
                    "egl-x11".into(),
                    "libglvnd".into(),
                ];
                package.provides = vec!["opengl-driver".into(), "vulkan-driver".into()];
            }
            package
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
        let mismatch = validate_nvidia_install_result(
            dependency_result,
            &dependency_inputs,
            "validated",
            "validation_complete",
            "validated",
        );
        let mismatch = match mismatch {
            Ok(_) => panic!("changed package metadata must fail"),
            Err(error) => error,
        };
        assert!(mismatch.contains("signer"), "unexpected error: {mismatch}");
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
            pacman_check_space_bypass_authorized: true,
            pacman_check_space_policy: "temporary-config-disable-after-live-revalidation".into(),
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
    fn enforces_host_build_space_reserves_without_overflow() {
        let required = checked_space_sum([
            8 * 1024 * 1024 * 1024,
            HOST_RUNTIME_FREE_SPACE_RESERVE,
            8 * 1024 * 1024 * 1024,
            HOST_OUTPUT_FREE_SPACE_RESERVE,
        ])
        .expect("calculate shared-volume requirement");
        assert_eq!(required, 20 * 1024 * 1024 * 1024 + 64 * 1024 * 1024);
        assert!(require_host_space(required, required, "test volume").is_ok());
        let error = require_host_space(required - 1, required, "test volume")
            .expect_err("one-byte shortfall must fail");
        assert!(error.contains("before guest startup"));
        assert!(error.contains(&format!("{required} bytes")));
        assert!(error.contains(&format!("{} bytes", required - 1)));
        assert!(checked_space_sum([u64::MAX, 1]).is_err());
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
        let runtime = BuildRuntimeProvenance {
            host_os: "macos".into(),
            host_architecture: "aarch64".into(),
            native_qemu: RuntimeExecutableProvenance {
                filename: "qemu-system-aarch64".into(),
                version: "QEMU emulator version 11.1.1".into(),
            },
            x86_installer_qemu: None,
            native_appliance: RuntimeFileProvenance {
                filename: "fedora-builder.qcow2".into(),
                bytes: 528_154_624,
                sha256: "a".repeat(64),
            },
            x86_installer_appliance: None,
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
            runtime: &runtime,
        });
        assert_eq!(manifest["schemaVersion"], 1);
        assert_eq!(manifest["resultClass"], "mutation-valid");
        assert_eq!(manifest["validation"]["passed"], true);
        assert_eq!(manifest["input"]["filename"], "recovery.img.bz2");
        assert_eq!(manifest["output"]["filename"], "recovery-marker.img");
        assert_eq!(manifest["steamos"]["architecture"], "x86_64");
        assert_eq!(manifest["runtime"]["hostOs"], "macos");
        assert_eq!(manifest["runtime"]["hostArchitecture"], "aarch64");
        assert_eq!(
            manifest["runtime"]["nativeQemu"]["filename"],
            "qemu-system-aarch64"
        );
        assert_eq!(
            manifest["runtime"]["nativeAppliance"]["sha256"],
            "a".repeat(64)
        );
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
                pacman_check_space_bypass_authorized: false,
                pacman_check_space_policy: "preserve".into(),
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
            runtime: &runtime,
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

        let raw_with_compressed_suffix = root.join("raw-content.img.gz");
        fs::write(&raw_with_compressed_suffix, PAYLOAD).expect("write mismatched raw fixture");
        assert!(supported_image(&raw_with_compressed_suffix));
        assert_eq!(
            detect_input_format(&raw_with_compressed_suffix).unwrap(),
            InputFormat::Raw
        );
        assert_eq!(
            normalize_input(
                &raw_with_compressed_suffix,
                &root,
                InputFormat::Raw,
                None,
                None
            )
            .unwrap(),
            raw_with_compressed_suffix
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
        assert!(supported_image(&bzip_source));
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

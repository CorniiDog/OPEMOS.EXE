#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn guest_failure_details_drop_progress_noise_and_remain_bounded() {
        let progress = "STEAMOS_NVIDIA_PROGRESS {\"schemaVersion\":1,\"attempt\":2,\"phase\":\"hashing\",\"indeterminate\":false,\"completed\":4,\"total\":8,\"unit\":\"bytes\"}";
        let log = format!(
            "{progress}\n{progress}\nsnapshot_target_execution.py: execution input has an unsafe parent: bin/bash\n[open-gpu-kernel-modules-steamos-support] Target-owned inputs are unsafe.\nWorkspace preparation metadata is valid only for validation results.\n"
        );
        let detail = guest_command_failure_detail(log.as_bytes());
        assert!(!detail.contains("STEAMOS_NVIDIA_PROGRESS"));
        assert!(detail.contains("unsafe parent: bin/bash"));
        assert!(detail.contains("Target-owned inputs are unsafe"));
        assert!(detail.chars().count() <= 2 * 1024 + 1);
    }

    #[test]
    fn guest_failure_details_prioritize_support_contract_rejections() {
        let log = "[OPEMOS] Offline-root NVIDIA inputs validated without mutation.\ninstaller contract rejected: progress record regressed\n>>> ==> Updating trust database...\n";
        assert_eq!(
            guest_command_failure_detail(log.as_bytes()),
            "installer contract rejected: progress record regressed"
        );
    }

    #[test]
    fn final_grub_validator_is_portable_and_rejects_duplicate_arguments() {
        let run = |grub: &str| {
            let mut child = std::process::Command::new("awk")
                .arg(crate::image::NVIDIA_GRUB_VALIDATION_AWK)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("launch the host AWK implementation");
            let mut stdin = child.stdin.take().expect("open AWK stdin");
            std::io::Write::write_all(&mut stdin, grub.as_bytes()).expect("write GRUB fixture");
            drop(stdin);
            child.wait_with_output().expect("wait for AWK")
        };
        let valid = "steamenv_boot linux /vmlinuz rd.driver.blacklist=nouveau modprobe.blacklist=nouveau nvidia-drm.modeset=1 nvidia-drm.fbdev=1\n";
        let output = run(valid);
        assert!(
            output.status.success(),
            "portable AWK validator rejected a valid entry: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let duplicate = format!("{valid}linux /vmlinuz rd.driver.blacklist=nouveau rd.driver.blacklist=nouveau modprobe.blacklist=nouveau nvidia-drm.modeset=1 nvidia-drm.fbdev=1\n");
        assert!(!run(&duplicate).status.success());
    }

    fn initramfs_verification_fixture() -> serde_json::Value {
        let kernel = "6.16.12-valve-fixture";
        let module_path = |name: &str| format!("usr/lib/modules/{kernel}/kernel/nvidia/{name}.zst");
        serde_json::json!({
            "schemaVersion": 1,
            "status": "verified",
            "kernelVersion": kernel,
            "requiredModules": ["nvidia.ko", "nvidia-modeset.ko", "nvidia-uvm.ko", "nvidia-drm.ko"],
            "rootfsOnlyModules": ["nvidia-peermem.ko"],
            "tools": {
                "mkinitcpio": {"path": "/usr/bin/mkinitcpio", "sizeBytes": 4096, "sha256": "a".repeat(64)},
                "lsinitcpio": {"path": "/usr/bin/lsinitcpio", "sizeBytes": 4096, "sha256": "b".repeat(64)}
            },
            "config": {
                "path": "/etc/modprobe.d/99-open-gpu-kernel-modules-steamos.conf",
                "sizeBytes": 128,
                "sha256": "c".repeat(64)
            },
            "images": [{
                "filename": "initramfs-linux.img",
                "sizeBytes": 1024,
                "sha256": "d".repeat(64),
                "listingSha256": "e".repeat(64),
                "entries": 23,
                "modules": {
                    "nvidia.ko": module_path("nvidia.ko"),
                    "nvidia-drm.ko": module_path("nvidia-drm.ko"),
                    "nvidia-modeset.ko": module_path("nvidia-modeset.ko"),
                    "nvidia-uvm.ko": module_path("nvidia-uvm.ko")
                },
                "configPath": "etc/modprobe.d/99-open-gpu-kernel-modules-steamos.conf"
            }]
        })
    }

    fn parse_initramfs_fixture(value: serde_json::Value) -> SupportInitramfsVerification {
        serde_json::from_value(value).expect("typed initramfs verification fixture")
    }

    fn successful_install_proofs(
        kernel: &str,
        nvidia: &str,
        packages: &[SupportInstallPackage],
    ) -> (
        SupportModuleVerification,
        SupportUserspaceVerification,
        SupportPayloadReceipt,
    ) {
        let module_names = [
            "nvidia.ko",
            "nvidia-drm.ko",
            "nvidia-modeset.ko",
            "nvidia-peermem.ko",
            "nvidia-uvm.ko",
        ];
        let modules = module_names
            .iter()
            .enumerate()
            .map(|(index, name)| SupportInstalledModule {
                module_name: (*name).into(),
                target_relative_path: format!(
                    "usr/lib/modules/{kernel}/updates/open-gpu-kernel-modules-steamos/{name}.zst"
                ),
                representation: ".ko.zst".into(),
                expected_payload_sha256: ((b'a' + index as u8) as char)
                    .to_string()
                    .repeat(64),
                actual_payload_sha256: ((b'a' + index as u8) as char)
                    .to_string()
                    .repeat(64),
                expected_mode: "0644".into(),
                actual_mode: "0644".into(),
                expected_uid: 0,
                actual_uid: 0,
                expected_gid: 0,
                actual_gid: 0,
                compressed_size_bytes: 1,
                decompression_status: "verified".into(),
                invalid_fields: Vec::new(),
            })
            .collect();
        let verified_packages = packages
            .iter()
            .map(|package| SupportVerifiedUserspacePackage {
                package_name: package.name.clone(),
                version: package.full_version.clone(),
                package_sha256: package.sha256.clone(),
                package_query_verified: true,
                pacman_integrity_verified: true,
                payload_verified: true,
                directories: 1,
                regular_files: 1,
                symlinks: 0,
                hardlinks: 0,
                shared_libraries: 1,
            })
            .collect::<Vec<_>>();
        let receipt_roles = [
            ("buildInfo", "BUILD-INFO.txt"),
            ("provenance", "PROVENANCE.json"),
            ("validation", "validation.json"),
            ("moduleVerification", "module-verification.json"),
            ("userspaceVerification", "userspace-verification.json"),
            ("initramfsVerification", "initramfs-verification.json"),
        ];
        (
            SupportModuleVerification {
                schema_version: 1,
                status: "verified".into(),
                reason: "installed_modules_verified".into(),
                modules,
            },
            SupportUserspaceVerification {
                schema_version: 1,
                status: "verified".into(),
                reason: "installed_userspace_verified".into(),
                pacman_database: SupportVerifiedPacmanDatabase {
                    path: "/usr/lib/holo/pacmandb".into(),
                    status: "verified".into(),
                    verified_package_count: verified_packages.len() as u64,
                    consistency_verified: true,
                },
                packages: verified_packages,
                gsp_firmware: SupportVerifiedGspFirmware {
                    status: "verified".into(),
                    version: nvidia.into(),
                    target_relative_files: vec![format!(
                        "usr/lib/firmware/nvidia/{nvidia}/gsp.bin"
                    )],
                },
            },
            SupportPayloadReceipt {
                schema_version: 1,
                status: "verified".into(),
                reason: "payload_receipt_verified".into(),
                target: SupportPayloadReceiptTarget {
                    steamos_version: "3.8.14".into(),
                    kernel_version: kernel.into(),
                    nvidia_version: nvidia.into(),
                    architecture: "x86_64".into(),
                },
                receipt_id: "f".repeat(64),
                rootfs_relative_path: "usr/lib/open-gpu-kernel-modules-steamos-support/offline-install/receipt.json".into(),
                records: receipt_roles
                    .iter()
                    .enumerate()
                    .map(|(index, (role, filename))| SupportPayloadReceiptRecord {
                        role: (*role).into(),
                        filename: (*filename).into(),
                        size_bytes: 1,
                        sha256: ((b'1' + index as u8) as char).to_string().repeat(64),
                    })
                    .collect(),
            },
        )
    }

    #[test]
    fn validates_bounded_initramfs_verification_contract() {
        let kernel = "6.16.12-valve-fixture";
        let exact = parse_initramfs_fixture(initramfs_verification_fixture());
        validate_support_initramfs_verification(&exact, kernel)
            .expect("exact initramfs verification should pass");

        let mut additive = initramfs_verification_fixture();
        additive["futureTopLevel"] = serde_json::json!({"schema": 1});
        additive["tools"]["mkinitcpio"]["futureIdentity"] = serde_json::json!(true);
        additive["images"][0]["futureImage"] = serde_json::json!("ignored");
        validate_support_initramfs_verification(&parse_initramfs_fixture(additive), kernel)
            .expect("schema-1 additions must remain forward compatible");

        let mut cases = Vec::new();
        let mut wrong_tool = initramfs_verification_fixture();
        wrong_tool["tools"]["mkinitcpio"]["path"] = serde_json::json!("/tmp/mkinitcpio");
        cases.push(wrong_tool);
        let mut oversized_tool = initramfs_verification_fixture();
        oversized_tool["tools"]["lsinitcpio"]["sizeBytes"] = serde_json::json!(8 * 1024 * 1024 + 1);
        cases.push(oversized_tool);
        let mut uppercase_hash = initramfs_verification_fixture();
        uppercase_hash["config"]["sha256"] = serde_json::json!("A".repeat(64));
        cases.push(uppercase_hash);
        let mut wrong_kernel = initramfs_verification_fixture();
        wrong_kernel["kernelVersion"] = serde_json::json!("6.16.12-other");
        cases.push(wrong_kernel);
        let mut duplicate_image = initramfs_verification_fixture();
        let image = duplicate_image["images"][0].clone();
        duplicate_image["images"].as_array_mut().unwrap().push(image);
        cases.push(duplicate_image);
        let mut oversized_image = initramfs_verification_fixture();
        oversized_image["images"][0]["sizeBytes"] = serde_json::json!(2_u64 * 1024 * 1024 * 1024 + 1);
        cases.push(oversized_image);
        let mut escaped_module = initramfs_verification_fixture();
        escaped_module["images"][0]["modules"]["nvidia.ko"] = serde_json::json!("../nvidia.ko");
        cases.push(escaped_module);
        let mut duplicate_module_path = initramfs_verification_fixture();
        duplicate_module_path["images"][0]["modules"]["nvidia-drm.ko"] =
            duplicate_module_path["images"][0]["modules"]["nvidia.ko"].clone();
        cases.push(duplicate_module_path);
        let mut missing_module = initramfs_verification_fixture();
        missing_module["images"][0]["modules"]
            .as_object_mut()
            .unwrap()
            .remove("nvidia-uvm.ko");
        cases.push(missing_module);
        let mut rootfs_only_in_initramfs = initramfs_verification_fixture();
        rootfs_only_in_initramfs["images"][0]["modules"]["nvidia-peermem.ko"] =
            serde_json::json!(format!(
                "usr/lib/modules/{kernel}/kernel/nvidia/nvidia-peermem.ko.zst"
            ));
        cases.push(rootfs_only_in_initramfs);
        let mut wrong_required_contract = initramfs_verification_fixture();
        wrong_required_contract["requiredModules"][0] = serde_json::json!("nvidia-peermem.ko");
        cases.push(wrong_required_contract);
        let mut missing_rootfs_only_contract = initramfs_verification_fixture();
        missing_rootfs_only_contract["rootfsOnlyModules"] = serde_json::json!([]);
        cases.push(missing_rootfs_only_contract);
        let mut wrong_config = initramfs_verification_fixture();
        wrong_config["images"][0]["configPath"] = serde_json::json!("etc/modprobe.d/hostile.conf");
        cases.push(wrong_config);

        for hostile in cases {
            let hostile = parse_initramfs_fixture(hostile);
            assert!(validate_support_initramfs_verification(&hostile, kernel).is_err());
        }
    }

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
            recent_maintainer_worktrees: vec!["/private/worktree".into()],
        })
        .unwrap();
        assert!(serialized.contains("autoReleaseVerifiedNvidia"));
        assert!(serialized.contains("trackSteamosDriverUpdates"));
        assert!(serialized.contains("includeUpstreamNvidiaReleases"));
        assert!(serialized.contains("omitOptionalCuda"));
        assert!(serialized.contains("recentMaintainerWorktrees"));
        for forbidden in ["token", "password", "secret", "ssh"] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[cfg(unix)]
    #[test]
    fn github_command_runner_bounds_runtime_and_output() {
        let (status, stdout, stderr) = bounded_command_output_with_limits(
            Path::new("/bin/sh"),
            &["-c", "printf success"],
            "run bounded fixture",
            Duration::from_secs(1),
            64,
        )
        .expect("bounded command should complete");
        assert!(status.success());
        assert_eq!(stdout, b"success");
        assert!(stderr.is_empty());

        let started = Instant::now();
        let timeout = bounded_command_output_with_limits(
            Path::new("/bin/sh"),
            &["-c", "sleep 5"],
            "run timeout fixture",
            Duration::from_millis(50),
            64,
        )
        .expect_err("bounded command must time out");
        assert!(timeout.contains("safety time limit"));
        assert!(started.elapsed() < Duration::from_secs(2));

        let excessive = bounded_command_output_with_limits(
            Path::new("/bin/sh"),
            &["-c", "printf 0123456789"],
            "run output fixture",
            Duration::from_secs(1),
            4,
        )
        .expect_err("bounded command must cap output");
        assert!(excessive.contains("excessive output"));
    }

    #[test]
    fn recent_maintainer_settings_are_bounded_absolute_and_unique() {
        assert!(validate_recent_maintainer_worktrees(&[
            "/private/worktree-a".into(),
            "/private/worktree-b".into(),
        ])
        .is_ok());
        assert!(validate_recent_maintainer_worktrees(&["relative/worktree".into()]).is_err());
        assert!(validate_recent_maintainer_worktrees(&[
            "/private/repeated".into(),
            "/private/repeated".into(),
        ])
        .is_err());
        assert!(validate_recent_maintainer_worktrees(
            &(0..11)
                .map(|index| format!("/private/worktree-{index}"))
                .collect::<Vec<_>>()
        )
        .is_err());
    }

    #[test]
    fn settings_writes_are_unique_atomic_durable_and_leave_no_temporary_files() {
        let root = std::env::temp_dir().join(format!("steamos-settings-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root); fs::create_dir_all(&root).expect("create settings fixture");
        let path = root.join("settings.json");
        let settings = BuilderSettings { track_steamos_driver_updates: true, ..Default::default() };
        save_builder_settings_path(&path, &settings).expect("save settings atomically");
        let loaded: BuilderSettings = serde_json::from_slice(&fs::read(&path).expect("read settings"))
            .expect("parse settings");
        assert!(loaded.track_steamos_driver_updates);
        let shared = Arc::new(path.clone());
        let writers = (0..8).map(|index| {
            let path = Arc::clone(&shared);
            thread::spawn(move || {
                let settings = BuilderSettings {
                    track_steamos_driver_updates: index % 2 == 0,
                    include_upstream_nvidia_releases: index % 3 == 0,
                    ..Default::default()
                };
                save_builder_settings_path(&path, &settings)
            })
        }).collect::<Vec<_>>();
        for writer in writers { writer.join().expect("settings writer thread").expect("serialized settings write"); }
        serde_json::from_slice::<BuilderSettings>(&fs::read(&path).expect("read concurrent settings"))
            .expect("concurrent settings remain complete JSON");
        #[cfg(unix)] assert_eq!(fs::metadata(&path).expect("settings metadata").permissions().mode() & 0o777, 0o600);
        assert!(fs::read_dir(&root).expect("list settings fixture")
            .all(|entry| !entry.expect("settings entry").file_name().to_string_lossy().ends_with(".tmp")));
        fs::remove_dir_all(root).expect("remove settings fixture");
    }

    #[test]
    fn settings_mutex_poisoning_does_not_permanently_disable_persistence() {
        let poisoned = thread::spawn(|| {
            let _guard = settings_transaction_lock().expect("acquire settings lock to poison");
            panic!("intentional settings lock poison");
        });
        assert!(poisoned.join().is_err());
        let root = std::env::temp_dir().join(format!(
            "steamos-settings-poison-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("settings poison clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create poison recovery fixture");
        let path = root.join("settings.json");
        save_builder_settings_path(&path, &BuilderSettings::default())
            .expect("persist settings after recovering poisoned mutex");
        load_builder_settings_path_unlocked(&path)
            .expect("load settings after recovering poisoned mutex");
        fs::remove_dir_all(root).expect("remove poison recovery fixture");
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess helper for settings advisory-lock regressions"]
    fn settings_process_helper() {
        let path = PathBuf::from(std::env::var_os("SETTINGS_HELPER_PATH").expect("helper path"));
        let mode = std::env::var("SETTINGS_HELPER_MODE").expect("helper mode");
        let _guard = settings_transaction_lock().expect("helper in-process lock");
        let _file_guard = acquire_settings_file_lock(&path, Duration::from_secs(4))
            .expect("helper file lock");
        if mode == "hold" {
            fs::write(
                std::env::var_os("SETTINGS_HELPER_READY").expect("ready path"),
                b"locked\n",
            )
            .expect("record held lock");
            thread::sleep(Duration::from_secs(30));
            return;
        }
        let mut settings = load_builder_settings_path_unlocked(&path).expect("helper load");
        if mode == "migrate" {
            return;
        }
        match mode.as_str() {
            "track" => settings.track_steamos_driver_updates = true,
            "upstream" => settings.include_upstream_nvidia_releases = true,
            "recover" => settings.auto_release_verified_nvidia = false,
            _ => panic!("unknown settings helper mode"),
        }
        thread::sleep(Duration::from_millis(100));
        save_builder_settings_path_unlocked(&path, &settings).expect("helper save");
    }

    #[cfg(unix)]
    fn spawn_settings_helper(path: &Path, mode: &str, ready: Option<&Path>) -> std::process::Child {
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .args([
                "--exact",
                "tests::settings_process_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("SETTINGS_HELPER_PATH", path)
            .env("SETTINGS_HELPER_MODE", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(ready) = ready {
            command.env("SETTINGS_HELPER_READY", ready);
        }
        command.spawn().expect("spawn settings helper")
    }

    #[cfg(unix)]
    #[test]
    fn settings_transactions_serialize_across_processes_and_recover_after_crash() {
        let root = std::env::temp_dir().join(format!(
            "steamos-settings-processes-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("settings fixture clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create process settings fixture");
        let path = root.join("settings.json");
        save_builder_settings_path(&path, &BuilderSettings::default())
            .expect("seed process settings");

        let mut first = spawn_settings_helper(&path, "track", None);
        let mut second = spawn_settings_helper(&path, "upstream", None);
        assert!(first.wait().expect("wait for first writer").success());
        assert!(second.wait().expect("wait for second writer").success());
        let merged = load_builder_settings_path_unlocked(&path).expect("load merged settings");
        assert!(merged.track_steamos_driver_updates);
        assert!(merged.include_upstream_nvidia_releases);

        let ready = root.join("holder-ready");
        let mut holder = spawn_settings_helper(&path, "hold", Some(&ready));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(ready.exists(), "holder never acquired the advisory lock");
        let timeout = acquire_settings_file_lock(&path, Duration::from_millis(100))
            .err()
            .expect("contention should time out");
        assert!(timeout.contains("Timed out"));
        holder.kill().expect("terminate lock holder");
        holder.wait().expect("reap lock holder");

        let mut recovery = spawn_settings_helper(&path, "recover", None);
        assert!(recovery.wait().expect("wait for recovery writer").success());
        let recovered = load_builder_settings_path_unlocked(&path).expect("load recovered settings");
        assert!(recovered.track_steamos_driver_updates);
        assert!(recovered.include_upstream_nvidia_releases);
        assert_eq!(
            fs::metadata(&path).expect("settings metadata").permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(root.join(".settings.json.lock"))
                .expect("lock metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(fs::read_dir(&root).expect("list process settings fixture").all(|entry| {
            !entry
                .expect("settings entry")
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));

        fs::write(
            &path,
            b"{\n  \"schemaVersion\": 1,\n  \"autoReleaseVerifiedNvidia\": false,\n  \"trackSteamosDriverUpdates\": true\n}\n",
        )
        .expect("stage schema-one settings");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("secure schema-one settings");
        let mut migrator = spawn_settings_helper(&path, "migrate", None);
        let mut migration_writer = spawn_settings_helper(&path, "upstream", None);
        assert!(migrator.wait().expect("wait for migrator").success());
        assert!(migration_writer
            .wait()
            .expect("wait for migration writer")
            .success());
        let migrated = load_builder_settings_path_unlocked(&path).expect("load migrated settings");
        assert_eq!(migrated.schema_version, BUILDER_SETTINGS_SCHEMA);
        assert!(migrated.track_steamos_driver_updates);
        assert!(migrated.include_upstream_nvidia_releases);
        assert!(migrated.recent_maintainer_worktrees.is_empty());
        fs::remove_dir_all(root).expect("remove process settings fixture");
    }

    #[cfg(unix)]
    #[test]
    fn settings_transactions_repair_owned_modes_and_reject_links() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "steamos-settings-safety-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("settings safety clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create settings safety fixture");
        let real = root.join("real");
        fs::create_dir(&real).expect("create real settings directory");
        let linked = root.join("linked");
        symlink(&real, &linked).expect("link settings directory");
        assert!(save_builder_settings_path(
            &linked.join("settings.json"),
            &BuilderSettings::default()
        )
        .expect_err("linked parent must fail")
        .contains("real directory"));

        let path = real.join("settings.json");
        save_builder_settings_path(&path, &BuilderSettings::default())
            .expect("seed secure settings");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("weaken fixture settings mode");
        load_builder_settings_path_unlocked(&path)
            .expect("owned settings mode should be repaired safely");
        assert_eq!(
            fs::metadata(&path)
                .expect("repaired settings metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        fs::remove_file(&path).expect("remove insecure settings");
        let target = real.join("target.json");
        fs::write(&target, b"{}\n").expect("write symlink target");
        symlink(&target, &path).expect("link settings file");
        assert!(load_builder_settings_path_unlocked(&path).is_err());
        fs::remove_file(&path).expect("remove linked settings");

        let lock = real.join(".settings.json.lock");
        fs::remove_file(&lock).expect("remove regular lock");
        symlink(&target, &lock).expect("link settings lock");
        assert!(save_builder_settings_path(&path, &BuilderSettings::default())
            .expect_err("linked lock must fail")
            .contains("regular file"));
        fs::remove_file(&lock).expect("remove linked lock");
        fs::write(&lock, b"persistent-lock-sentinel\n").expect("seed lock sentinel");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))
            .expect("secure lock sentinel");
        let guard = acquire_settings_file_lock(&path, Duration::from_secs(1))
            .expect("acquire persistent lock");
        assert_eq!(
            fs::read(&lock).expect("read lock sentinel"),
            b"persistent-lock-sentinel\n"
        );
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644))
            .expect("drift lock mode");
        assert!(guard.verify().is_err(), "lock mode drift must fail closed");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))
            .expect("restore lock mode");
        let replaced = real.join("replaced.lock");
        fs::rename(&lock, &replaced).expect("replace held lock path");
        fs::write(&lock, b"replacement\n").expect("create replacement lock");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))
            .expect("secure replacement lock");
        assert!(guard.verify().is_err(), "lock inode replacement must fail closed");
        drop(guard);
        fs::remove_dir_all(root).expect("remove settings safety fixture");
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
    fn managed_maintainer_worktrees_have_exact_confined_destinations() {
        let root = Path::new("/private/managed-worktrees");
        let commit = "a".repeat(40);
        assert_eq!(
            managed_maintainer_worktree_destination(
                root,
                NVIDIA_SOURCE_REPOSITORY,
                &commit,
            )
            .unwrap(),
            root.join("CorniiDog--open-gpu-kernel-modules-steamos--aaaaaaaaaaaa")
        );
        assert!(managed_maintainer_worktree_destination(
            root,
            "unapproved/repository",
            &commit,
        )
        .is_err());
        assert!(managed_maintainer_worktree_destination(
            root,
            NVIDIA_SOURCE_REPOSITORY,
            "not-a-commit",
        )
        .is_err());
        assert!(!valid_local_branch_name("-option"));
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
    fn maintainer_git_output_is_streamed_to_a_hard_limit() {
        struct TemporaryGitDirectory(PathBuf);
        impl Drop for TemporaryGitDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = TemporaryGitDirectory(std::env::temp_dir().join(format!(
            "steamos-maintainer-git-output-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )));
        fs::create_dir(&root.0).expect("create git output fixture");
        let git = |args: &[&str]| {
            let status = Command::new("git")
                .arg("-C")
                .arg(&root.0)
                .args(args)
                .status()
                .expect("run fixture git");
            assert!(status.success());
        };
        git(&["init", "--quiet"]);
        git(&["config", "user.name", "Local Test"]);
        git(&["config", "user.email", "local@example.invalid"]);
        fs::write(root.0.join("large.txt"), "x".repeat(4_096)).expect("write large fixture");
        git(&["add", "large.txt"]);
        git(&["commit", "--quiet", "-m", "large fixture"]);

        let error = git_output_bytes(
            &root.0,
            &["show", "--format=", "--no-color", "HEAD"],
            "read bounded test output",
            128,
        )
        .expect_err("large Git output must be rejected");
        assert!(error.contains("exceeded the safe limit"));
        assert_eq!(
            git_output_bytes(&root.0, &["rev-parse", "HEAD"], "read HEAD", 64)
                .expect("bounded HEAD")
                .len(),
            41
        );
    }

    #[cfg(unix)]
    #[test]
    fn maintainer_git_mutations_bound_output_encoding_failure_and_lifetime() {
        use std::os::unix::fs::PermissionsExt;
        struct Fixture(PathBuf);
        impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
        let root = Fixture(std::env::temp_dir().join(format!("steamos-fake-git-{}", std::process::id())));
        let _ = fs::remove_dir_all(&root.0);
        fs::create_dir_all(&root.0).expect("create fake Git fixture");
        let binary = root.0.join("git");
        fs::write(&binary, r#"#!/bin/sh
mode=$(cat "$2/mode")
case "$mode" in
  overflow) dd if=/dev/zero bs=1024 count=2 2>/dev/null ;;
  stderr-overflow) dd if=/dev/zero bs=1024 count=2 1>&2 2>/dev/null ;;
  timeout) printf partial; sleep 30 ;;
  broken-pipe) exec 0<&-; sleep 30 ;;
  descendant) sleep 30 & echo $! > "$2/descendant.pid"; exit 0 ;;
  nonutf8) printf '\377' ;;
  failure) printf partial-error >&2; exit 7 ;;
  success) printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' ;;
esac
"#).expect("write fake Git");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).expect("chmod fake Git");
        let run = |mode: &str, timeout| {
            fs::write(root.0.join("mode"), mode).expect("select fake Git mode");
            bounded_git_mutation(&binary, &root.0, &["commit-tree"], Some(b"message"), timeout, 64, "test Git mutation")
        };
        assert!(run("overflow", Duration::from_secs(1)).unwrap_err().contains("safe limit"));
        assert!(run("stderr-overflow", Duration::from_secs(1)).unwrap_err().contains("safe limit"));
        fs::write(root.0.join("mode"), "broken-pipe").expect("select broken pipe");
        assert!(bounded_git_mutation(&binary, &root.0, &["commit-tree"], Some(&vec![b'x'; 1024 * 1024]),
            Duration::from_secs(1), 64, "test broken Git input").is_err());
        let started = Instant::now();
        assert!(run("timeout", Duration::from_millis(100)).unwrap_err().contains("time limit"));
        assert!(started.elapsed() < Duration::from_secs(2));
        run("descendant", Duration::from_secs(1)).expect("clean descendant mode");
        let descendant = fs::read_to_string(root.0.join("descendant.pid")).expect("descendant pid");
        let alive = Command::new("kill").args(["-0", descendant.trim()])
            .stdout(Stdio::null()).stderr(Stdio::null()).status().expect("inspect descendant");
        assert!(!alive.success(), "bounded runner left a descendant alive");
        let non_utf8 = run("nonutf8", Duration::from_secs(1)).expect("capture non-UTF8 bytes");
        assert!(String::from_utf8(non_utf8).is_err());
        assert!(run("failure", Duration::from_secs(1)).unwrap_err().contains("partial-error"));
        assert_eq!(run("success", Duration::from_secs(1)).expect("successful bounded Git"), b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
        struct FailingReader(bool);
        impl Read for FailingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.0 { return Err(io::Error::other("injected read failure")); }
                self.0 = true; buffer[0] = b'x'; Ok(1)
            }
        }
        assert!(read_bounded_git_stream(FailingReader(false), 64).is_err());

        let repository = root.0.join("repository");
        fs::create_dir(&repository).expect("create atomic-ref repository");
        let git = |args: &[&str]| {
            let output = Command::new("git").arg("-C").arg(&repository).args(args)
                .output().expect("run real fixture Git");
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            String::from_utf8(output.stdout).expect("UTF-8 fixture Git").trim().to_owned()
        };
        git(&["init", "--quiet"]); git(&["config", "user.name", "Local Test"]);
        git(&["config", "user.email", "local@example.invalid"]);
        fs::write(repository.join("file"), "one").expect("write atomic fixture");
        git(&["add", "file"]); git(&["commit", "--quiet", "-m", "initial"]);
        let old = git(&["rev-parse", "HEAD"]); let tree = git(&["write-tree"]);
        let created = bounded_git_mutation(Path::new("git"), &repository,
            &["commit-tree", &tree, "-p", &old], Some(b"bounded commit"), Duration::from_secs(2), 64 * 1024,
            "create fixture commit").expect("bounded commit-tree");
        let created = String::from_utf8(created).expect("commit identity UTF-8").trim().to_owned();
        bounded_git_mutation(Path::new("git"), &repository,
            &["update-ref", "HEAD", &created, &old], None, Duration::from_secs(2), 64 * 1024,
            "atomically attach fixture commit").expect("atomic update-ref");
        assert_eq!(git(&["rev-parse", "HEAD"]), created);
        assert!(bounded_git_mutation(Path::new("git"), &repository,
            &["update-ref", "HEAD", &old, &old], None, Duration::from_secs(2), 64 * 1024,
            "reject stale fixture HEAD").is_err());
    }

    #[test]
    fn usb_candidate_parser_uses_real_macos_keys_and_rejects_unsafe_disks() {
        let removable = serde_json::json!({
            "DeviceIdentifier": "disk7",
            "DeviceNode": "/dev/disk7",
            "WholeDisk": true,
            "Internal": false,
            "VirtualOrPhysical": "Physical",
            "RemovableMedia": true,
            "Ejectable": true,
            "Writable": true,
            "TotalSize": 64_000_000_000_u64,
            "DeviceBlockSize": 512,
            "MediaName": "Test USB",
            "BusProtocol": "USB",
            "DeviceTreePath": "IODeviceTree:/fixture/usb@1"
        });
        let candidate = usb_candidate_from_diskutil_info(&removable, 32_000_000_000, Some("disk7"))
            .expect("safe removable disk");
        assert_eq!(candidate.device_identifier, "disk7");
        assert_eq!(candidate.device_node, "/dev/disk7");

        let mut partition_metadata = removable.clone();
        partition_metadata["WholeDisk"] = serde_json::json!(false);
        partition_metadata["Whole"] = serde_json::json!(true);
        assert!(usb_candidate_from_diskutil_info(
            &partition_metadata,
            32_000_000_000,
            Some("disk7")
        )
        .is_none());

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

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_diskutil_list_places_plist_before_filters() {
        assert_eq!(
            DISKUTIL_EXTERNAL_PHYSICAL_LIST_ARGS,
            ["list", "-plist", "external", "physical"]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_usb_authorization_receives_one_close_on_exec_descriptor() {
        use std::os::fd::AsRawFd as _;

        let root = std::env::temp_dir().join(format!(
            "steamos-authopen-fd-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create descriptor fixture");
        let path = root.join("payload");
        fs::write(&path, b"authorized descriptor fixture").expect("write descriptor fixture");
        let file = File::open(&path).expect("open descriptor fixture");
        let (sender, receiver) = UnixStream::pair().expect("create descriptor socket pair");

        let mut byte = [1_u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: byte.len(),
        };
        let mut control = [0_usize; 8];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control) as _;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        assert!(!header.is_null());
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), file.as_raw_fd());
            message.msg_controllen = (*header).cmsg_len as _;
        }
        assert_eq!(unsafe { libc::sendmsg(sender.as_raw_fd(), &message, 0) }, 1);
        receiver
            .set_nonblocking(true)
            .expect("make descriptor receiver nonblocking");
        let mut received = receive_authorized_descriptor(&receiver)
            .expect("receive descriptor")
            .expect("descriptor should be ready");
        let mut payload = String::new();
        received
            .read_to_string(&mut payload)
            .expect("read received descriptor");
        assert_eq!(payload, "authorized descriptor fixture");
        assert_ne!(
            unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        fs::remove_dir_all(root).expect("remove descriptor fixture");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_usb_authorization_uses_the_protected_system_utility() {
        validate_system_authopen().expect("system authopen should be protected and root-owned");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "invokes macOS Authorization Services for a harmless user-owned temporary file"]
    fn live_macos_authopen_returns_the_exact_owned_file_descriptor() {
        let root = std::env::temp_dir().join(format!(
            "steamos-authopen-live-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create authopen fixture");
        let path = root.join("payload");
        fs::write(&path, b"authopen live fixture").expect("write authopen fixture");
        let cancel = AtomicBool::new(false);
        let mut opened = authorized_open_path(&path, &cancel).expect("authorize owned fixture");
        let mut payload = String::new();
        opened
            .read_to_string(&mut payload)
            .expect("read authopen fixture");
        assert_eq!(payload, "authopen live fixture");
        fs::remove_dir_all(root).expect("remove authopen fixture");
    }

    #[test]
    fn usb_preflight_state_replaces_cancels_and_expires_sessions() {
        let now = Instant::now();
        let mut manager = UsbPreparationManager::default();
        let fixture_image_sha = "b".repeat(64);
        let fixture_identity = "c".repeat(64);
        let arm = |manager: &mut UsbPreparationManager, token: &str| {
            manager.arm(
                token.into(),
                "disk7".into(),
                fixture_image_sha.clone(),
                fixture_identity.clone(),
                now,
            );
        };
        arm(&mut manager, "first");
        assert!(manager.is_armed());
        let active = manager.status("first", now + Duration::from_secs(1));
        assert!(active.active);
        assert_eq!(active.status, "armed");
        assert!(active.expires_in_ms > 0);
        assert_eq!(active.writes_allowed, physical_usb_writes_allowed());
        assert_eq!(active.device_identifier.as_deref(), Some("disk7"));
        assert_eq!(active.image_sha256.as_deref(), Some(fixture_image_sha.as_str()));
        assert_eq!(active.identity_token.as_deref(), Some(fixture_identity.as_str()));
        let stale = manager.status("wrong", now + Duration::from_secs(1));
        assert!(!stale.active);
        assert_eq!(stale.status, "stale-token");
        assert!(stale.device_identifier.is_none());
        assert!(stale.image_sha256.is_none());
        assert!(stale.identity_token.is_none());
        assert!(manager.is_armed());
        assert!(!manager.cancel("wrong", now));
        assert!(manager.is_armed());

        arm(&mut manager, "second");
        let replaced = manager.status("first", now + Duration::from_secs(1));
        assert_eq!(replaced.status, "stale-token");
        assert!(replaced.device_identifier.is_none());
        assert!(replaced.image_sha256.is_none());
        assert!(replaced.identity_token.is_none());
        assert!(manager.is_armed());
        assert!(!manager.cancel("first", now));
        assert!(manager.cancel("second", now));
        assert!(!manager.is_armed());

        arm(&mut manager, "expired");
        let expired = manager.status("expired", now + USB_PREFLIGHT_TTL);
        assert_eq!(expired.status, "expired");
        assert!(!expired.active);
        assert_eq!(expired.device_identifier.as_deref(), Some("disk7"));
        assert!(!manager.is_armed());

        let missing = manager.status("expired", now + USB_PREFLIGHT_TTL);
        assert_eq!(missing.status, "not-armed");

        arm(&mut manager, "cancel-all");
        manager.cancel_all();
        assert!(!manager.is_armed());
    }

    #[test]
    fn usb_preflight_session_tokens_are_exact_hex_digests() {
        assert!(valid_usb_preflight_session_token(&"a".repeat(64)));
        assert!(valid_usb_preflight_session_token(&"A0".repeat(32)));
        assert!(!valid_usb_preflight_session_token(""));
        assert!(!valid_usb_preflight_session_token(&"a".repeat(63)));
        assert!(!valid_usb_preflight_session_token(&"a".repeat(65)));
        assert!(!valid_usb_preflight_session_token(&format!("{}g", "a".repeat(63))));
    }

    #[test]
    fn usb_image_identity_rejects_manifest_and_content_drift() {
        struct TemporaryUsbDirectory(PathBuf);
        impl Drop for TemporaryUsbDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = TemporaryUsbDirectory(std::env::temp_dir().join(format!(
            "steamos-usb-image-identity-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )));
        fs::create_dir(&root.0).expect("create USB identity fixture");
        let image = root.0.join("completed.img");
        let original = vec![0x3c_u8; 4096];
        fs::write(&image, &original).expect("write image fixture");
        let sha256 = format!("{:x}", Sha256::digest(&original));
        let manifest = manifest_path_for_output(&image);
        let write_manifest = |filename: &str, bytes: u64, hash: &str| {
            fs::write(
                &manifest,
                serde_json::to_vec(&serde_json::json!({
                    "output": {
                        "filename": filename,
                        "format": "raw",
                        "bytes": bytes,
                        "sha256": hash
                    }
                }))
                .expect("serialize manifest"),
            )
            .expect("write manifest fixture");
        };
        write_manifest("completed.img", original.len() as u64, &sha256);
        let (_, bytes, actual) = validate_usb_image_identity(
            image.to_str().expect("UTF-8 fixture path"),
        )
        .expect("valid image identity");
        assert_eq!(bytes, original.len() as u64);
        assert_eq!(actual, sha256);

        fs::write(&image, vec![0x7a_u8; original.len()]).expect("tamper image fixture");
        let (_, discovery_bytes, declared, _) = inspect_usb_image_manifest_identity(
            image.to_str().expect("UTF-8 fixture path"),
        )
        .expect("read-only discovery defers the expensive content hash");
        assert_eq!(discovery_bytes, original.len() as u64);
        assert_eq!(declared, sha256);
        assert!(validate_usb_image_identity(image.to_str().unwrap()).is_err());

        fs::write(&image, &original).expect("restore image fixture");
        write_manifest("different.img", original.len() as u64, &sha256);
        assert!(validate_usb_image_identity(image.to_str().unwrap()).is_err());

        write_manifest("completed.img", original.len() as u64 + 1, &sha256);
        assert!(validate_usb_image_identity(image.to_str().unwrap()).is_err());
    }

    #[test]
    fn completed_nvidia_image_requires_exact_manifest_bound_success() {
        struct TemporaryCompletedDirectory(PathBuf);
        impl Drop for TemporaryCompletedDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = TemporaryCompletedDirectory(std::env::temp_dir().join(format!(
            "steamos-completed-image-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )));
        fs::create_dir(&root.0).expect("create completed-image fixture");
        let image = root.0.join("completed-nvidia.img");
        let payload = vec![0x5a_u8; 4096];
        fs::write(&image, &payload).expect("write completed image fixture");
        assert!(completed_nvidia_image_from_path(image.to_str().unwrap())
            .expect("an ordinary image is not a completed output")
            .is_none());

        let sha256 = format!("{:x}", Sha256::digest(&payload));
        let mut manifest = serde_json::json!({
            "schemaVersion": 1,
            "resultClass": "nvidia-mutation-valid",
            "input": {"sourceSha256": "b".repeat(64)},
            "output": {
                "filename": "completed-nvidia.img",
                "format": "raw",
                "bytes": payload.len(),
                "sha256": sha256
            },
            "steamos": {"layoutScheme": "valve-recovery-a"},
            "validation": {
                "passed": true,
                "sourceUnchanged": true,
                "candidateAttachedReadOnly": true,
                "layoutRecognized": true,
                "markerVerified": true,
                "nvidiaPayloadVerified": true,
                "installationMediaWelcomeVerified": true,
                "installationMediaWelcomeRevision": install_media_welcome_revision(),
                "installedRecoveryGuardianPayloadVerified": true
            },
            "integration": {
                "milestone": "nvidia-offline-installed",
                "nvidia": {
                    "status": "success",
                    "phase": "complete",
                    "reason": "install_complete",
                    "mountsReleased": true,
                    "compressionPolicyRestored": true,
                    "nvidiaVersion": "575.64.05",
                    "kernelVersion": "6.16.12-valve24.4-1-neptune-616-test",
                    "steamosVersion": "3.8.14",
                    "trust": "locally-built-verified"
                },
                "nvidiaSourcePolicy": {
                    "selection": "automatic",
                    "mode": "automatic"
                }
            }
        });
        let manifest_path = manifest_path_for_output(&image);
        let write_manifest = |value: &serde_json::Value| {
            fs::write(
                &manifest_path,
                serde_json::to_vec(value).expect("serialize completed-image manifest"),
            )
            .expect("write completed-image manifest");
        };
        write_manifest(&manifest);
        let completed = completed_nvidia_image_from_path(image.to_str().unwrap())
            .expect("validate completed output")
            .expect("recognize completed output");
        assert_eq!(
            completed.output.path,
            fs::canonicalize(&image)
                .expect("canonical completed image")
                .to_string_lossy()
        );
        assert_eq!(completed.output.sha256, sha256);
        assert_eq!(completed.output.layout_scheme, "valve-recovery-a");
        assert_eq!(completed.nvidia_version, "575.64.05");
        assert_eq!(completed.steamos_version, "3.8.14");
        assert_eq!(completed.source_selection, "automatic");
        assert!(validate_completed_nvidia_version(
            &Some(completed),
            Some("575.64.05")
        )
        .is_ok());

        let completed = completed_nvidia_image_from_path(image.to_str().unwrap())
            .expect("revalidate completed output")
            .expect("recognize completed output again");
        let mismatch = validate_completed_nvidia_version(&Some(completed), Some("580.1.2"))
            .expect_err("a different explicitly requested NVIDIA version must not be reused");
        assert!(mismatch.contains("original Valve recovery image"));

        manifest["validation"]["nvidiaPayloadVerified"] = serde_json::json!(false);
        write_manifest(&manifest);
        assert!(completed_nvidia_image_from_path(image.to_str().unwrap()).is_err());

        manifest["validation"]["nvidiaPayloadVerified"] = serde_json::json!(true);
        manifest["validation"]
            .as_object_mut()
            .unwrap()
            .remove("installationMediaWelcomeVerified");
        write_manifest(&manifest);
        assert!(completed_nvidia_image_from_path(image.to_str().unwrap()).is_err());

        manifest["validation"]["installationMediaWelcomeVerified"] = serde_json::json!(true);
        manifest["validation"]
            .as_object_mut()
            .unwrap()
            .remove("installedRecoveryGuardianPayloadVerified");
        write_manifest(&manifest);
        assert!(completed_nvidia_image_from_path(image.to_str().unwrap()).is_err());

        manifest["validation"]["installedRecoveryGuardianPayloadVerified"] =
            serde_json::json!(true);
        manifest["resultClass"] = serde_json::json!("marker-only");
        write_manifest(&manifest);
        assert!(completed_nvidia_image_from_path(image.to_str().unwrap()).is_err());
    }

    #[test]
    fn usb_write_intent_binds_phrase_device_capacity_and_identity() {
        let target = UsbTargetCandidate {
            device_identifier: "disk7".into(),
            device_node: "/dev/disk7".into(),
            media_name: "Fixture USB".into(),
            bus_protocol: "USB".into(),
            bytes: 64_000_000_000,
            block_size: 512,
            identity_token: "a".repeat(64),
        };
        assert!(validate_usb_write_intent(
            &target,
            32_000_000_000,
            "disk7",
            &"a".repeat(64),
            "ERASE disk7"
        )
        .is_ok());
        assert!(validate_usb_write_intent(
            &target,
            32_000_000_000,
            "disk7",
            &"a".repeat(64),
            "erase disk7"
        )
        .is_err());
        assert!(validate_usb_write_intent(
            &target,
            32_000_000_000,
            "disk8",
            &"a".repeat(64),
            "ERASE disk8"
        )
        .is_err());
        assert!(validate_usb_write_intent(
            &target,
            32_000_000_000,
            "disk7",
            &"b".repeat(64),
            "ERASE disk7"
        )
        .is_err());
        assert!(validate_usb_write_intent(
            &target,
            128_000_000_000,
            "disk7",
            &"a".repeat(64),
            "ERASE disk7"
        )
        .is_err());
    }

    fn helper_exchange_fixture() -> (
        UsbHelperWriteRequest,
        UsbHelperAttestation,
        Vec<UsbHelperEvent>,
    ) {
        let hash = "a".repeat(64);
        let identity = "b".repeat(64);
        let request_id = "c".repeat(64);
        let request = UsbHelperWriteRequest {
            schema_version: 1,
            protocol: USB_HELPER_PROTOCOL.into(),
            request_id: request_id.clone(),
            intent_token: "d".repeat(64),
            expires_at_unix_ms: 1_050_000,
            image_path: "/private/var/tmp/completed.img".into(),
            image_bytes: 8 * 1024 * 1024,
            image_sha256: hash.clone(),
            device_identifier: "disk7".into(),
            canonical_device_node: "/dev/disk7".into(),
            raw_device_node: "/dev/rdisk7".into(),
            device_capacity_bytes: 16 * 1024 * 1024,
            device_identity_token: identity.clone(),
        };
        let attestation = UsbHelperAttestation {
            schema_version: 1,
            protocol: USB_HELPER_PROTOCOL.into(),
            helper_version: "1.0.0".into(),
            process_id: 42,
            effective_user_id: 0,
            executable_sha256: "e".repeat(64),
            signing_identity: "TEAM.example.usb-helper".into(),
            independently_authenticated: true,
            independently_authorized: true,
        };
        let events = ["unmount", "open", "write", "fsync", "readback", "cleanup"]
            .into_iter()
            .enumerate()
            .map(|(sequence, phase)| UsbHelperEvent {
                schema_version: 1,
                protocol: USB_HELPER_PROTOCOL.into(),
                request_id: request_id.clone(),
                sequence: sequence as u32,
                phase: phase.into(),
                outcome: "succeeded".into(),
                bytes_completed: request.image_bytes,
                bytes_total: request.image_bytes,
                image_sha256: hash.clone(),
                device_identity_token: identity.clone(),
                message: phase.into(),
            })
            .collect();
        (request, attestation, events)
    }

    #[test]
    fn usb_helper_protocol_binds_attestation_intent_device_image_and_outcomes() {
        let (request, attestation, events) = helper_exchange_fixture();
        let policy = UsbHelperTrustPolicy {
            executable_sha256: &"e".repeat(64),
            signing_identity: "TEAM.example.usb-helper",
            helper_version: "1.0.0",
        };
        validate_usb_helper_exchange(&request, &attestation, &events, &policy, 1_000_000)
            .expect("exact authenticated exchange");

        for mutation in ["image", "device", "request", "progress", "phase", "terminal"] {
            let (mut request, mut attestation, mut events) = helper_exchange_fixture();
            match mutation {
                "image" => request.image_sha256 = "f".repeat(64),
                "device" => events[2].device_identity_token = "f".repeat(64),
                "request" => events[1].request_id = "f".repeat(64),
                "progress" => events[2].bytes_completed = request.image_bytes + 1,
                "phase" => events[2].phase = "format".into(),
                "terminal" => { events.pop(); }
                _ => unreachable!(),
            }
            assert!(validate_usb_helper_exchange(&request, &attestation, &events, &policy, 1_000_000).is_err(), "{mutation} drift must fail");
            attestation.independently_authenticated = true;
        }

        for mutation in ["unauthenticated", "unauthorized", "pid", "uid", "binary", "signer", "version"] {
            let (request, mut attestation, events) = helper_exchange_fixture();
            match mutation {
                "unauthenticated" => attestation.independently_authenticated = false,
                "unauthorized" => attestation.independently_authorized = false,
                "pid" => attestation.process_id = 0,
                "uid" => attestation.effective_user_id = 501,
                "binary" => attestation.executable_sha256 = "f".repeat(64),
                "signer" => attestation.signing_identity = "attacker".into(),
                "version" => attestation.helper_version = "2.0.0".into(),
                _ => unreachable!(),
            }
            assert!(validate_usb_helper_exchange(&request, &attestation, &events, &policy, 1_000_000).is_err(), "{mutation} attestation must fail");
        }
        assert!(validate_usb_helper_exchange(&request, &attestation, &events, &policy, 1_050_000).is_err(), "expired intent must fail");
    }

    #[test]
    fn usb_helper_protocol_accepts_bounded_cancel_cleanup_but_not_partial_success() {
        let (request, attestation, mut events) = helper_exchange_fixture();
        let policy = UsbHelperTrustPolicy {
            executable_sha256: &"e".repeat(64),
            signing_identity: "TEAM.example.usb-helper",
            helper_version: "1.0.0",
        };
        events.truncate(3);
        events.push(UsbHelperEvent {
            sequence: 3,
            phase: "cancel".into(),
            outcome: "cancelled".into(),
            bytes_completed: 4 * 1024 * 1024,
            message: "cancel acknowledged".into(),
            ..events[2].clone()
        });
        events.push(UsbHelperEvent {
            sequence: 4,
            phase: "cleanup".into(),
            outcome: "cancelled".into(),
            bytes_completed: 4 * 1024 * 1024,
            message: "device closed".into(),
            ..events[2].clone()
        });
        validate_usb_helper_exchange(&request, &attestation, &events, &policy, 1_000_000)
            .expect("bounded cancellation with cleanup");

        let (_, _, mut partial) = helper_exchange_fixture();
        partial.retain(|event| event.phase != "fsync");
        for (sequence, event) in partial.iter_mut().enumerate() { event.sequence = sequence as u32; }
        assert!(validate_usb_helper_exchange(&request, &attestation, &partial, &policy, 1_000_000).is_err());
        let (_, _, mut oversized) = helper_exchange_fixture();
        oversized[0].message = "x".repeat(513);
        assert!(validate_usb_helper_exchange(&request, &attestation, &oversized, &policy, 1_000_000).is_err());
    }

    #[test]
    fn usb_helper_wire_protocol_rejects_malformed_duplicate_unknown_and_oversized_records() {
        let (request, attestation, events) = helper_exchange_fixture();
        let request_json = serde_json::to_vec(&request).expect("serialize request");
        let attestation_json = serde_json::to_vec(&attestation).expect("serialize attestation");
        let event_jsonl = events
            .iter()
            .map(|event| serde_json::to_string(event).expect("serialize event"))
            .collect::<Vec<_>>()
            .join("\n");
        let decoded = decode_usb_helper_exchange(
            &request_json,
            &attestation_json,
            event_jsonl.as_bytes(),
        )
        .expect("decode exact bounded exchange");
        assert_eq!(decoded.2.len(), events.len());

        assert!(decode_usb_helper_exchange(b"{} trailing", &attestation_json, event_jsonl.as_bytes()).is_err());
        let duplicate = String::from_utf8(request_json.clone())
            .expect("UTF-8 request")
            .replacen("{", "{\"schemaVersion\":1,", 1);
        assert!(decode_usb_helper_exchange(duplicate.as_bytes(), &attestation_json, event_jsonl.as_bytes()).is_err());
        let unknown = String::from_utf8(request_json.clone())
            .expect("UTF-8 request")
            .replacen("{", "{\"unexpected\":true,", 1);
        assert!(decode_usb_helper_exchange(unknown.as_bytes(), &attestation_json, event_jsonl.as_bytes()).is_err());
        assert!(decode_usb_helper_exchange(&vec![b'x'; 32 * 1024 + 1], &attestation_json, event_jsonl.as_bytes()).is_err());
        assert!(decode_usb_helper_exchange(&request_json, &attestation_json, &vec![b'x'; 4 * 1024 + 1]).is_err());
    }

    #[test]
    fn usb_copy_engine_writes_verifies_and_cancels_synthetic_media() {
        struct TemporaryUsbDirectory(PathBuf);
        impl Drop for TemporaryUsbDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = TemporaryUsbDirectory(std::env::temp_dir().join(format!(
            "steamos-usb-copy-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )));
        fs::create_dir(&root.0).expect("create USB copy fixture");
        let image = root.0.join("source.img");
        let target = root.0.join("target.media");
        let mut payload = vec![0_u8; 9 * 1024 * 1024 + 37];
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte = ((index * 31 + 17) % 251) as u8;
        }
        fs::write(&image, &payload).expect("write source image");
        fs::write(&target, vec![0xa5; payload.len() + 4096]).expect("prepare target media");
        let expected = format!("{:x}", Sha256::digest(&payload));
        let cancel = AtomicBool::new(false);
        let mut phases = Vec::new();
        let mut target_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&target)
            .expect("open target media");
        let verified = copy_and_verify_usb_image(
            &image,
            &mut target_file,
            payload.len() as u64,
            &expected,
            &cancel,
            |progress| phases.push(progress.phase),
        )
        .expect("write and verify synthetic media");
        assert_eq!(verified, expected);
        assert!(phases.iter().any(|phase| phase == "writing"));
        assert!(phases.iter().any(|phase| phase == "verifying"));
        let written = fs::read(&target).expect("read target media");
        assert_eq!(&written[..payload.len()], payload.as_slice());
        assert_eq!(&written[payload.len()..], &[0xa5; 4096]);

        fs::write(&target, vec![0_u8; payload.len()]).expect("reset target media");
        let cancel = AtomicBool::new(false);
        let mut target_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&target)
            .expect("reopen target media");
        let result = copy_and_verify_usb_image(
            &image,
            &mut target_file,
            payload.len() as u64,
            &expected,
            &cancel,
            |progress| {
                if progress.phase == "writing" && progress.bytes_completed > 0 {
                    cancel.store(true, Ordering::Relaxed);
                }
            },
        );
        assert!(result.expect_err("cancelled write must fail").contains("cancelled"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "attaches a small disposable macOS virtual disk and writes its raw device"]
    fn live_usb_copy_engine_writes_virtual_macos_media() {
        struct AttachedImage {
            root: PathBuf,
            device: Option<String>,
        }
        impl Drop for AttachedImage {
            fn drop(&mut self) {
                if let Some(device) = self.device.take() {
                    let _ = Command::new("/usr/bin/hdiutil")
                        .args(["detach", "-force", &device])
                        .status();
                }
                let _ = fs::remove_dir_all(&self.root);
            }
        }
        let root = std::env::temp_dir().join(format!(
            "steamos-usb-virtual-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create virtual USB fixture");
        let image_path = root.join("media.sparseimage");
        let create = Command::new("/usr/bin/hdiutil")
            .args(["create", "-size", "16m", "-type", "SPARSE", "-layout", "NONE"])
            .arg(&image_path)
            .output()
            .expect("create sparse virtual disk");
        assert!(create.status.success(), "hdiutil create failed");
        let attached = Command::new("/usr/bin/hdiutil")
            .args(["attach", "-nomount"])
            .arg(&image_path)
            .output()
            .expect("attach sparse virtual disk");
        assert!(attached.status.success(), "hdiutil attach failed");
        let device = String::from_utf8(attached.stdout)
            .expect("UTF-8 hdiutil output")
            .lines()
            .find_map(|line| line.split_whitespace().next())
            .filter(|value| value.starts_with("/dev/disk"))
            .expect("attached disk node")
            .to_string();
        let fixture = AttachedImage {
            root,
            device: Some(device.clone()),
        };
        let raw_device = device.replacen("/dev/disk", "/dev/rdisk", 1);
        let payload_path = fixture.root.join("payload.img");
        let payload = vec![0x5a_u8; 6 * 1024 * 1024];
        fs::write(&payload_path, &payload).expect("write virtual USB payload");
        let expected = format!("{:x}", Sha256::digest(&payload));
        let mut raw = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&raw_device)
            .expect("open virtual raw disk");
        let verified = copy_and_verify_usb_image(
            &payload_path,
            &mut raw,
            payload.len() as u64,
            &expected,
            &AtomicBool::new(false),
            |_| {},
        )
        .expect("write and verify virtual raw disk");
        assert_eq!(verified, expected);
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
        assert_eq!(NVIDIA_RELEASE_REPOSITORY, "CorniiDog/OPEMOS");
        assert_eq!(NVIDIA_SUPPORT_REPOSITORY, "CorniiDog/OPEMOS");
        assert!(NVIDIA_RELEASES_API.contains("/repos/CorniiDog/OPEMOS/releases"));
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

        let duplicated = vec![releases[1].clone(), releases[1].clone()];
        assert!(select_published_nvidia_release(
            &ready_published_target("3.8.16", kernel),
            &duplicated,
        )
        .is_err());
        assert!(select_nvidia_build_baseline(
            &ready_published_target("3.8.17", "different-kernel"),
            &duplicated,
        )
        .is_err());
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
        assert_eq!(validate_pinned_installer_contract().unwrap(), 583_001);
        assert_eq!(PINNED_INSTALLER_FILES.len(), 50);
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "bootstrap/install_to_root.sh" && file.executable));
        assert!(PINNED_INSTALLER_FILES.iter().any(|file| {
            file.path == "bootstrap/install_recovery_guardian_to_root.sh" && file.executable
        }));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "bootstrap/recoveryctl.sh" && file.executable));
        assert!(PINNED_INSTALLER_FILES.iter().any(|file| {
            file.path == "bootstrap/launch_desktop_companion.sh" && file.executable
        }));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "bootstrap/launch_interstitial.sh" && file.executable));
        assert!(PINNED_INSTALLER_FILES.iter().any(|file| {
            file.path == "bootstrap/run_guardian_with_interstitial.sh" && file.executable
        }));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/desktop_update_generations.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/interstitial_progress.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES.iter().any(|file| {
            file.path == "lib/validate_interstitial_binary.py" && file.executable
        }));
        assert!(PINNED_INSTALLER_FILES.iter().any(|file| {
            file.path == "trust/desktop-update-signers.json" && !file.executable
        }));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/open_opemos_contract.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES.iter().any(|file| {
            file.path == "support/recovery/opemos-nvidia-guardian.service.in"
                && !file.executable
        }));
        assert!(PINNED_INSTALLER_FILES.iter().any(|file| {
            file.path == "support/recovery/opemos-interstitial.service.in" && !file.executable
        }));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/update_grub_nvidia_args.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/verify_bind_mount.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/snapshot_target_execution.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/measure_btrfs_payload.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/snapshot_install_input.py" && !file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/validate_install_contract.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/payload_receipt.py" && !file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/run_pacman_transaction.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/atomic_output.py" && !file.executable));
        assert!(PINNED_INSTALLER_FILES.iter().any(|file| {
            file.path == "lib/authenticated_cache_bundle.py" && !file.executable
        }));
        assert!(PINNED_INSTALLER_FILES.iter().any(|file| {
            file.path == "lib/resolve_authenticated_install_bundle.py" && file.executable
        }));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/prepare_pacman_config.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/gaming_payload_profiles.py" && file.executable));
        assert!(PINNED_INSTALLER_FILES
            .iter()
            .any(|file| file.path == "lib/repack_gaming_userspace.py" && file.executable));
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
        assert!(guest_permissions.contains("\"$WORK/support/lib/verify_bind_mount.py\""));
        assert!(guest_permissions.contains("\"$WORK/support/lib/snapshot_target_execution.py\""));
        assert!(guest_permissions.contains("\"$WORK/support/lib/capture_bounded_command.py\""));
        assert!(guest_permissions.contains("\"$WORK/support/lib/verify_initramfs.py\""));
        assert!(guest_permissions.contains("chmod 0644 "));
        assert!(guest_permissions.contains("\"$WORK/support/lib/atomic_output.py\""));

        let uppercase_commit = "A".repeat(40);
        assert!(validate_pinned_support_files(&uppercase_commit, &PINNED_INSTALLER_FILES)
            .is_err());
        let uppercase_digest = [PinnedInstallerFile {
            path: "safe/file",
            sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            bytes: 1,
            executable: false,
        }];
        assert!(validate_pinned_support_files(NVIDIA_SUPPORT_COMMIT, &uppercase_digest).is_err());
    }

    #[test]
    fn installer_result_reader_rejects_empty_truncated_duplicate_and_excessive_documents() {
        let root = std::env::temp_dir().join(format!(
            "steamos-installer-result-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create installer-result fixture");
        let path = root.join("result.json");
        fs::write(&path, []).expect("write empty result");
        assert!(read_support_install_result(&path).is_err());
        fs::write(&path, br#"{"schemaVersion":1,"status":"success""#)
            .expect("write truncated result");
        assert!(read_support_install_result(&path).is_err());
        fs::write(&path, br#"{"schemaVersion":1,"schemaVersion":1}"#)
            .expect("write duplicate top-level result");
        assert!(read_support_install_result(&path).is_err());
        fs::write(&path, br#"{"schemaVersion":1,"cleanup":{"mountsReleased":true,"mountsReleased":false}}"#)
            .expect("write duplicate nested result");
        assert!(read_support_install_result(&path).is_err());
        let file = File::create(&path).expect("create excessive result");
        file.set_len(32 * 1024 * 1024 + 1)
            .expect("size excessive result");
        assert!(read_support_install_result(&path).is_err());
        fs::remove_dir_all(root).expect("remove installer-result fixture");
    }

    #[test]
    fn pinned_publisher_contract_is_safe_and_versioned() {
        assert_eq!(validate_pinned_publisher_contract().unwrap(), 19_918);
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
        assert_eq!(
            source
                .matches("lib/validate_install_contract.py\" --result")
                .count(),
            2
        );
        assert!(source.contains("install-progress.log"));
        assert!(source.contains("opemos-install-media/support\" -type l"));
        assert!(source.contains("opemos-install-media/ui/gtk-3.0"));
        assert!(source.contains("install-mutation-progress.log"));
        assert_eq!(source.matches("mapfile -t HOME_PARTS").count(), 2);
        assert_eq!(
            source
                .matches(r#"sudo mount -o rw "${{HOME_PARTS[0]}}" "$ROOT/home""#)
                .count(),
            1
        );
        assert_eq!(
            source
                .matches(r#"sudo mount -o ro "${{HOME_PARTS[0]}}" "$ROOT/home""#)
                .count(),
            1
        );
        assert_eq!(
            source
                .matches(r#"if (( HOME_MOUNTED )); then sudo umount "$ROOT/home""#)
                .count(),
            2
        );
    }

    #[test]
    fn recovery_rollback_action_is_bundled_and_fail_closed() {
        let script = std::str::from_utf8(RECOVERY_ROLLBACK_SCRIPT).unwrap();
        for label in [
            "esp", "efi-A", "efi-B", "rootfs-A", "rootfs-B", "var-A", "var-B", "home",
        ] {
            assert!(script.contains(label));
        }
        assert!(script.contains("valid_disk \"$disk\" || die"));
        assert!(script.contains("-o ro,norecovery"));
        assert!(script.contains("-name 'nvidia.ko*'"));
        assert!(script.contains("modinfo -F vermagic"));
        assert!(script.contains("Type %s exactly to confirm"));
        assert!(script.contains("steamos-chroot --no-overlay --disk \"$disk\""));
        assert!(script.contains("steamos-bootconf --image \"$slot\" set-mode reboot"));
        assert!(!script.contains("repair_device.sh"));
        assert!(script.contains("Eligible rollback slots"));
    }

    #[test]
    fn installation_media_welcome_is_bundled_with_a_bounded_privilege_boundary() {
        let welcome = std::str::from_utf8(INSTALL_MEDIA_WELCOME).unwrap();
        let helper = std::str::from_utf8(INSTALL_MEDIA_HELPER).unwrap();
        let patcher = std::str::from_utf8(INSTALL_MEDIA_PATCHER).unwrap();
        let desktop = std::str::from_utf8(INSTALL_MEDIA_DESKTOP).unwrap();
        let gtk_css = std::str::from_utf8(INSTALL_MEDIA_GTK_CSS).unwrap();
        let server = std::str::from_utf8(INSTALL_MEDIA_WELCOME_SERVER).unwrap();
        let html = std::str::from_utf8(INSTALL_MEDIA_WELCOME_HTML).unwrap();
        let javascript = std::str::from_utf8(INSTALL_MEDIA_WELCOME_JS).unwrap();

        assert!(desktop.contains("Name=Install SteamOS with NVIDIA drivers"));
        assert!(desktop.contains("Exec=/home/deck/tools/open-opemos-welcome"));
        assert!(desktop.contains("X-KDE-AutostartScript=true"));
        assert!(include_str!("installer.rs").contains(
            "sudo install -m 0755 /tmp/Open-OPEMOS.desktop"
        ));
        assert!(welcome.contains("SteamOS with NVIDIA drivers"));
        assert!(welcome.contains("Maintained by OPEMOS"));
        assert!(welcome.contains("Install SteamOS with NVIDIA drivers"));
        assert!(welcome.contains("Reinstall SteamOS with NVIDIA drivers"));
        assert!(welcome.contains("Do not power off the computer or disconnect either drive"));
        assert!(welcome.contains("sudo \"$HELPER\" install"));
        assert!(welcome.contains("Diagnostics — review media identity"));
        assert!(welcome.contains("last-install-log"));
        assert!(welcome.contains("flock -n 8"));
        assert!(welcome.contains("TRUE shutdown"));
        assert!(welcome.contains("FALSE restart"));
        assert!(welcome.contains("restart) systemctl reboot"));
        assert!(welcome.contains("remove the USB as the screen turns off"));
        assert!(welcome.contains("--start-fullscreen"));
        assert!(welcome.contains("WELCOME_SERVER"));
        assert!(!welcome.contains("eval "));
        assert!(server.contains("ThreadingHTTPServer((\"127.0.0.1\", 0)"));
        assert!(server.contains("X-OPEMOS-Token"));
        assert!(!server.contains("shell=True"));
        assert!(html.contains("close-app"));
        assert!(javascript.contains("/api/install"));
        assert!(gtk_css.contains("@define-color opemos_blue"));
        assert!(gtk_css.contains("linear-gradient(to right, @opemos_blue, @opemos_green)"));

        assert!(helper.contains("MINIMUM_INSTALL_BYTES"));
        assert!(helper.contains("is_recovery_disk \"$device\""));
        assert!(helper.contains("lsblk -snrpo PATH,TYPE \"$resolved\""));
        assert!(helper.contains("mounted_child \"$device\""));
        assert!(helper.contains("disk_identity \"$device\""));
        assert!(helper.contains("typed confirmation did not match; nothing changed"));
        assert!(helper.contains("flock -n 9"));
        assert!(helper.contains("OPEMOS_FAIL_FAST=1"));
        assert!(helper.contains("install_recovery_guardian_to_root.sh"));
        assert!(helper.contains("for slot in A B"));
        assert!(helper.contains("media-info)"));
        assert!(helper.contains("verify_guardian_slot"));
        assert!(helper.contains("launch_interstitial.sh"));
        assert!(helper.contains("run_guardian_with_interstitial.sh"));
        assert!(helper.contains("interstitial_progress.py"));
        assert!(helper.contains("validate_interstitial_binary.py"));
        assert!(helper.contains("opemos-interstitial.service"));
        assert!(!helper.contains("--interstitial-binary"));
        assert!(!helper.contains("bin/opemos-interstitial"));
        assert!(helper.contains("installed recovery guardian verification failed"));
        assert!(helper.contains("ui_stage \"Installing the recovery guardian into rootfs-$slot"));
        assert!(!helper.contains("eval "));

        assert!(patcher.contains("unsupported Valve installer structure for guarded anchor"));
        assert!(patcher.contains("Open OPEMOS requires an explicit target disk"));
        assert!(patcher.contains("OPEMOS_SKIP_JUPITER_FIRMWARE"));
        assert!(patcher.contains("OPEMOS_NO_REBOOT"));
        assert!(patcher.contains("OPEMOS_FAIL_FAST"));
        assert!(!patcher.contains("subprocess"));
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
        let additive_source: SupportInstallInputSource = serde_json::from_value(
            serde_json::json!({"mode":"direct","futureProducerField":true}),
        )
        .expect("schema-1 source provenance must remain forward-additive");
        assert_eq!(additive_source.mode, "direct");
        assert!(additive_source.bundle_cache_id.is_none());
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
            input_source_mode: "direct".into(),
            input_bundle_cache_id: None,
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
                runtime_mounts_expected: 4,
                runtime_mounts_released: 4,
                compression_policy_restored: true,
            },
            initramfs_workspace: Some(SupportInitramfsWorkspace {
                schema_version: 1,
                status: "verified".into(),
                reason: "initramfs_workspace_target_available".into(),
                phase: "target_directory".into(),
                condition: "available".into(),
                required_bytes: 4_096,
                required_inodes: 1,
                available_bytes: Some(32 * 1024 * 1024),
                available_inodes: Some(8_192),
                inode_capacity_mode: Some("finite-statvfs".into()),
                mode: Some("1777".into()),
            }),
            initramfs_verification: None,
            module_verification: None,
            userspace_verification: None,
            payload_receipt: None,
            validation: Some(SupportInstallValidationDocument::Verified(Box::new(
                SupportInstallValidation {
                    input_source: SupportInstallInputSource::default(),
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
        let mut successful = result.clone();
        successful.status = "success".into();
        successful.reason = "install_complete".into();
        successful.phase = "complete".into();
        successful.initramfs_workspace = Some(SupportInitramfsWorkspace {
            schema_version: 1,
            status: "verified".into(),
            reason: "initramfs_workspace_available".into(),
            phase: "mounted_workspace".into(),
            condition: "available".into(),
            required_bytes: 64 * 1024 * 1024,
            required_inodes: 4_096,
            available_bytes: Some(128 * 1024 * 1024),
            available_inodes: None,
            inode_capacity_mode: Some("dynamic-probed".into()),
            mode: Some("1777".into()),
        });
        let mut initramfs = initramfs_verification_fixture();
        initramfs["kernelVersion"] = serde_json::json!(inputs.kernel_version.clone());
        for path in initramfs["images"][0]["modules"]
            .as_object_mut()
            .expect("module fixture")
            .values_mut()
        {
            *path = serde_json::json!(path
                .as_str()
                .expect("module path")
                .replace("6.16.12-valve-fixture", &inputs.kernel_version));
        }
        successful.initramfs_verification = Some(parse_initramfs_fixture(initramfs));
        let successful_packages = match successful.validation.as_ref().unwrap() {
            SupportInstallValidationDocument::Verified(validation) => validation.packages.clone(),
            SupportInstallValidationDocument::Failed(_) => unreachable!(),
        };
        let (modules, userspace, receipt) = successful_install_proofs(
            &inputs.kernel_version,
            &inputs.nvidia_version,
            &successful_packages,
        );
        successful.module_verification = Some(modules);
        successful.userspace_verification = Some(userspace);
        successful.payload_receipt = Some(receipt);
        let installed = validate_nvidia_install_result(
            successful.clone(),
            &inputs,
            "success",
            "install_complete",
            "complete",
        )
        .expect("a success with exact initramfs evidence should pass");
        assert_eq!(
            installed
                .initramfs_verification
                .as_ref()
                .expect("retained initramfs verification")
                .images
                .len(),
            1
        );
        assert_eq!(installed.input_source_mode, "direct");
        assert!(installed.input_bundle_cache_id.is_none());
        assert_eq!(
            installed.initramfs_workspace.inode_capacity_mode.as_deref(),
            Some("dynamic-probed")
        );
        assert_eq!(
            installed
                .payload_receipt
                .as_ref()
                .expect("retained payload receipt")
                .receipt_id,
            "f".repeat(64)
        );

        let mut missing_modules = successful.clone();
        missing_modules.module_verification = None;
        assert!(validate_nvidia_install_result(
            missing_modules,
            &inputs,
            "success",
            "install_complete",
            "complete",
        )
        .is_err());
        let mut changed_module = successful.clone();
        changed_module
            .module_verification
            .as_mut()
            .unwrap()
            .modules[0]
            .actual_payload_sha256 = "0".repeat(64);
        assert!(validate_nvidia_install_result(
            changed_module,
            &inputs,
            "success",
            "install_complete",
            "complete",
        )
        .is_err());
        let mut unchecked_userspace = successful.clone();
        unchecked_userspace
            .userspace_verification
            .as_mut()
            .unwrap()
            .packages[0]
            .pacman_integrity_verified = false;
        assert!(validate_nvidia_install_result(
            unchecked_userspace,
            &inputs,
            "success",
            "install_complete",
            "complete",
        )
        .is_err());
        let mut changed_receipt = successful.clone();
        changed_receipt.payload_receipt.as_mut().unwrap().receipt_id = "F".repeat(64);
        assert!(validate_nvidia_install_result(
            changed_receipt,
            &inputs,
            "success",
            "install_complete",
            "complete",
        )
        .is_err());

        let mut contradictory_workspace = successful.clone();
        contradictory_workspace
            .initramfs_workspace
            .as_mut()
            .expect("workspace fixture")
            .available_inodes = Some(4_096);
        assert!(validate_nvidia_install_result(
            contradictory_workspace,
            &inputs,
            "success",
            "install_complete",
            "complete",
        )
        .err()
        .expect("dynamic inode evidence with a finite count must fail")
        .contains("inode-capacity"));

        let mut authenticated_inputs = inputs.clone();
        authenticated_inputs.input_source_mode = "authenticated-bundle".into();
        authenticated_inputs.input_bundle_cache_id = Some(digest('9'));
        let mut authenticated = successful;
        verified_validation(&mut authenticated).input_source = SupportInstallInputSource {
            mode: "authenticated-bundle".into(),
            bundle_cache_id: Some(digest('9')),
        };
        let authenticated = validate_nvidia_install_result(
            authenticated,
            &authenticated_inputs,
            "success",
            "install_complete",
            "complete",
        )
        .expect("authenticated bundle provenance should pass");
        assert_eq!(authenticated.input_source_mode, "authenticated-bundle");
        assert_eq!(authenticated.input_bundle_cache_id, Some(digest('9')));

        let mut unexpected_cache = result.clone();
        verified_validation(&mut unexpected_cache).input_source = SupportInstallInputSource {
            mode: "authenticated-bundle".into(),
            bundle_cache_id: Some(digest('8')),
        };
        assert!(validate_nvidia_install_result(
            unexpected_cache,
            &authenticated_inputs,
            "validated",
            "validation_complete",
            "validated",
        )
        .err()
        .expect("well-formed but stale cache identity must fail")
        .contains("staged handoff"));

        for (mode, cache_id) in [
            ("authenticated-bundle", None),
            ("authenticated-bundle", Some("A".repeat(64))),
            ("direct", Some(digest('9'))),
            ("network", None),
        ] {
            let mut hostile = result.clone();
            verified_validation(&mut hostile).input_source = SupportInstallInputSource {
                mode: mode.into(),
                bundle_cache_id: cache_id,
            };
            assert!(validate_nvidia_install_result(
                hostile,
                &inputs,
                "validated",
                "validation_complete",
                "validated",
            )
            .is_err(), "hostile input source {mode} must fail");
        }
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
                runtime_mounts_expected: 4,
                runtime_mounts_released: 4,
                compression_policy_restored: true,
            },
            initramfs_workspace: Some(SupportInitramfsWorkspace {
                schema_version: 1,
                status: "verified".into(),
                reason: "initramfs_workspace_available".into(),
                phase: "mounted_workspace".into(),
                condition: "available".into(),
                required_bytes: 64 * 1024 * 1024,
                required_inodes: 4_096,
                available_bytes: Some(128 * 1024 * 1024),
                available_inodes: None,
                inode_capacity_mode: Some("dynamic-probed".into()),
                mode: Some("1777".into()),
            }),
            initramfs_verification: None,
            module_verification: None,
            userspace_verification: None,
            payload_receipt: None,
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
                runtime_mounts_expected: 4,
                runtime_mounts_released: 4,
                compression_policy_restored: true,
            },
            initramfs_workspace: Some(SupportInitramfsWorkspace {
                schema_version: 1,
                status: "verified".into(),
                reason: "initramfs_workspace_target_available".into(),
                phase: "target_directory".into(),
                condition: "available".into(),
                required_bytes: 4_096,
                required_inodes: 1,
                available_bytes: Some(32 * 1024 * 1024),
                available_inodes: Some(8_192),
                inode_capacity_mode: Some("finite-statvfs".into()),
                mode: Some("1777".into()),
            }),
            initramfs_verification: None,
            module_verification: None,
            userspace_verification: None,
            payload_receipt: None,
            validation: Some(SupportInstallValidationDocument::Verified(Box::new(
                SupportInstallValidation {
                    input_source: SupportInstallInputSource::default(),
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
        assert_eq!(
            output_path_for_nvidia_version(
                &root.join("Steam Deck 🐧 recovery.img.xz"),
                "575.64.05",
            )
            .unwrap(),
            root.join("Steam Deck 🐧 recovery-nvidia-575.64.05.img")
        );
        assert_eq!(
            output_path_for_nvidia_version(
                &root.join("Steam Deck 🐧 recovery-nvidia-570.1.2.img"),
                "575.64.05",
            )
            .unwrap(),
            root.join("Steam Deck 🐧 recovery-nvidia-575.64.05.img")
        );
        assert!(output_path_for_nvidia_version(
            &root.join("Steam Deck recovery.img"),
            "575.64.05/unsafe",
        )
        .is_err());
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
            input_source_mode: "direct".into(),
            input_bundle_cache_id: None,
            pacman_database_path: "/usr/lib/holo/pacmandb".into(),
            pacman_package_count: 1_158,
            rootfs_boot_path: "/boot".into(),
            efi_mount_path: "/efi".into(),
            grub_configuration: "/efi/EFI/steamos/grub.cfg".into(),
            required_kernel_arguments: NVIDIA_REQUIRED_KERNEL_ARGUMENTS.map(str::to_owned).to_vec(),
            keyring_sha256: "b".repeat(64),
            initramfs_workspace: SupportInitramfsWorkspace {
                schema_version: 1,
                status: "verified".into(),
                reason: "initramfs_workspace_available".into(),
                phase: "mounted_workspace".into(),
                condition: "available".into(),
                required_bytes: 64 * 1024 * 1024,
                required_inodes: 4_096,
                available_bytes: Some(128 * 1024 * 1024),
                available_inodes: None,
                inode_capacity_mode: Some("dynamic-probed".into()),
                mode: Some("1777".into()),
            },
            initramfs_verification: None,
            module_verification: None,
            userspace_verification: None,
            payload_receipt: None,
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
        assert_eq!(nvidia_manifest["validation"]["recoveryRollbackVerified"], true);
        assert_eq!(
            nvidia_manifest["validation"]["installationMediaWelcomeVerified"],
            true
        );
        assert_eq!(
            nvidia_manifest["validation"]["installationMediaWelcomeRevision"],
            install_media_welcome_revision()
        );
        assert_eq!(
            nvidia_manifest["validation"]["installedRecoveryGuardianPayloadVerified"],
            true
        );
        assert!(nvidia_manifest["integration"]["modifiedPaths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path == "/home/deck/tools/opemos-rollback-last-update"));
        assert!(nvidia_manifest["integration"]["modifiedPaths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path == "/home/deck/tools/open-opemos-welcome"));
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

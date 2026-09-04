//! EXE-owned host adapters. Experimental Linux support never supplies Core policy.
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

pub(crate) type QemuSpec = (&'static str, &'static str, &'static str);

pub(crate) fn plan_host_qemu(
    os: &str,
    host: &str,
    guest: &str,
    enabled: bool,
    mode: &str,
    kvm: bool,
) -> Result<QemuSpec, String> {
    match (os, host, guest) {
        ("macos", "aarch64", "aarch64") => Ok(("hvf", "virt,accel=hvf", "host")),
        ("macos", "x86_64", "x86_64") => Ok(("hvf", "q35,accel=hvf", "host")),
        ("macos", "aarch64", "x86_64") => Ok(("tcg", "q35,accel=tcg", "max")),
        ("linux", "x86_64", "x86_64") => {
            if !enabled {
                return Err("Experimental Linux testing is disabled. Set OPEMOS_EXPERIMENTAL_LINUX=1 to opt in.".into());
            }
            match mode {
                "kvm" if kvm => Ok(("kvm", "q35,accel=kvm", "host")),
                "kvm" => Err("KVM is unavailable or inaccessible. Explicitly select OPEMOS_LINUX_ACCEL=tcg for software testing; no automatic fallback is used.".into()),
                "tcg" => Ok(("tcg", "q35,accel=tcg", "max")),
                _ => Err("OPEMOS_LINUX_ACCEL must be exactly kvm or tcg.".into()),
            }
        }
        _ => Err(format!(
            "Unsupported host/guest combination: {os}/{host}/{guest}."
        )),
    }
}

pub(crate) fn bounded_host_text(path: &Path) -> Result<String, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(65537).read_to_end(&mut bytes))
        .map_err(|error| {
            format!(
                "Could not read host information {}: {error}",
                path.display()
            )
        })?;
    if bytes.len() > 65536 {
        return Err("Host information exceeds its size limit.".into());
    }
    String::from_utf8(bytes).map_err(|_| "Host information is not UTF-8.".into())
}

pub(crate) fn supported_linux_distribution(text: &str) -> bool {
    let mut ids = text.lines().filter_map(|line| line.strip_prefix("ID="));
    matches!(
        ids.next(),
        Some("ubuntu" | "debian" | "\"ubuntu\"" | "\"debian\"" | "'ubuntu'" | "'debian'")
    ) && ids.next().is_none()
}

pub(crate) fn linux_memory_bytes(text: &str) -> Result<u64, String> {
    let mut entries = text
        .lines()
        .filter_map(|line| line.strip_prefix("MemTotal:"));
    let fields: Vec<_> = entries
        .next()
        .ok_or("Host MemTotal is missing.")?
        .split_whitespace()
        .collect();
    if entries.next().is_some()
        || fields.len() != 2
        || fields[1] != "kB"
        || !fields[0].bytes().all(|b| b.is_ascii_digit())
    {
        return Err("Host MemTotal is malformed or duplicated.".into());
    }
    fields[0]
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(1024))
        .filter(|value| *value != 0)
        .ok_or_else(|| "Host MemTotal is zero or overflowed.".into())
}

pub(crate) fn kvm_usable() -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::{
            fs::OpenOptions,
            os::{fd::AsRawFd, unix::fs::FileTypeExt},
        };
        let Ok(file) = OpenOptions::new().read(true).write(true).open("/dev/kvm") else {
            return false;
        };
        if !file
            .metadata()
            .is_ok_and(|metadata| metadata.file_type().is_char_device())
        {
            return false;
        }
        // KVM_GET_API_VERSION is a read-only capability query; Linux ABI version 12.
        unsafe { libc::ioctl(file.as_raw_fd(), 0xae00) == 12 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

pub(crate) fn current_host_qemu(host: &str, guest: &str) -> Result<QemuSpec, String> {
    let linux = std::env::consts::OS == "linux";
    if !linux {
        return plan_host_qemu(std::env::consts::OS, host, guest, false, "", false);
    }
    if linux && !supported_linux_distribution(&bounded_host_text(Path::new("/etc/os-release"))?) {
        return Err(
            "Experimental Linux testing currently supports Ubuntu and Debian hosts only.".into(),
        );
    }
    let enabled = std::env::var("OPEMOS_EXPERIMENTAL_LINUX").as_deref() == Ok("1");
    let mode = match std::env::var("OPEMOS_LINUX_ACCEL") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => "kvm".into(),
        Err(_) => return Err("OPEMOS_LINUX_ACCEL is not valid UTF-8.".into()),
    };
    plan_host_qemu(
        std::env::consts::OS,
        host,
        guest,
        enabled,
        &mode,
        linux && mode == "kvm" && kvm_usable(),
    )
}

pub(crate) fn linux_firmware_pair(root: &Path) -> Result<(PathBuf, PathBuf), String> {
    for (code, vars) in [
        ("OVMF_CODE_4M.fd", "OVMF_VARS_4M.fd"),
        ("OVMF_CODE.fd", "OVMF_VARS.fd"),
    ] {
        let code = root.join(code);
        let vars = root.join(vars);
        if [&code, &vars].iter().all(|path| {
            File::open(path)
                .and_then(|file| file.metadata())
                .is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0)
        }) {
            return Ok((code, vars));
        }
    }
    Err("A matched OVMF code/variable firmware pair is missing; install the ovmf package.".into())
}

pub(crate) fn host_firmware(guest: &str) -> Result<(PathBuf, PathBuf), String> {
    if std::env::consts::OS == "linux" {
        if guest != "x86_64" {
            return Err("Experimental Linux firmware supports x86_64 guests only.".into());
        }
        return linux_firmware_pair(Path::new("/usr/share/OVMF"));
    }
    let share = crate::appliance::homebrew_qemu_share()?;
    let (code, vars) = match guest {
        "aarch64" => ("edk2-aarch64-code.fd", "edk2-arm-vars.fd"),
        "x86_64" => ("edk2-x86_64-code.fd", "edk2-i386-vars.fd"),
        _ => return Err("Unsupported guest firmware architecture.".into()),
    };
    let pair = (share.join(code), share.join(vars));
    if !pair.0.is_file() || !pair.1.is_file() {
        return Err(format!(
            "Required QEMU firmware was not found under {}.",
            share.display()
        ));
    }
    Ok(pair)
}

pub(crate) fn seed_iso_command(
    os: &str,
    binary: &Path,
    source: &Path,
    destination: &Path,
) -> Result<Command, String> {
    let mut command = Command::new(binary);
    match os {
        "macos" => {
            command.args([
                "makehybrid",
                "-quiet",
                "-iso",
                "-joliet",
                "-default-volume-name",
                "cidata",
                "-o",
            ]);
        }
        "linux" => {
            command.args([
                "-quiet",
                "-iso-level",
                "3",
                "-J",
                "-R",
                "-V",
                "cidata",
                "-o",
            ]);
        }
        _ => return Err("Host seed-ISO creation is unsupported.".into()),
    }
    command.arg(destination).arg(source);
    Ok(command)
}

pub(crate) fn create_host_seed(source: &Path, destination: &Path) -> Result<(), String> {
    let os = std::env::consts::OS;
    let name = if os == "linux" {
        "genisoimage"
    } else {
        "hdiutil"
    };
    let binary = crate::appliance::find_binary(name)
        .filter(|path| usable_host_executable(path))
        .ok_or_else(|| format!("{name} is required to create the cloud-init seed."))?;
    crate::appliance::run_checked(
        &mut seed_iso_command(os, &binary, source, destination)?,
        "Could not create the cloud-init seed image",
    )
}

pub(crate) fn usable_host_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(name) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        path.is_file() && unsafe { libc::access(name.as_ptr(), libc::X_OK) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

pub(crate) fn parse_memory_limit(value: &str) -> Result<Option<u64>, String> {
    let value = value.trim();
    if value == "max" {
        return Ok(None);
    }
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Malformed Linux cgroup memory limit.".into());
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|bytes| *bytes > 0)
        .map(Some)
        .ok_or_else(|| "Invalid Linux cgroup memory limit.".into())
}

pub(crate) fn linux_effective_memory_bytes() -> Result<u64, String> {
    let physical = linux_memory_bytes(&bounded_host_text(Path::new("/proc/meminfo"))?)?;
    let membership = bounded_host_text(Path::new("/proc/self/cgroup"))?;
    let mut entries = membership
        .lines()
        .filter_map(|line| line.strip_prefix("0::"));
    let path = entries
        .next()
        .ok_or("Experimental Linux resource discovery requires cgroup v2.")?;
    if entries.next().is_some()
        || !path.starts_with('/')
        || path.split('/').any(|part| part == ".." || part == ".")
    {
        return Err("Linux cgroup membership is malformed.".into());
    }
    let root = Path::new("/sys/fs/cgroup");
    let mut directory = root.join(path.trim_start_matches('/'));
    let mut budget = physical;
    loop {
        let limit = directory.join("memory.max");
        if limit.exists() {
            if let Some(bytes) = parse_memory_limit(&bounded_host_text(&limit)?)? {
                budget = budget.min(bytes);
            }
        } else if directory != root {
            return Err("Linux cgroup memory budget could not be determined.".into());
        }
        if directory == root {
            break;
        }
        if !directory.pop() || !directory.starts_with(root) {
            return Err("Linux cgroup path escaped its root.".into());
        }
    }
    Ok(budget)
}

pub(crate) fn linux_host_prerequisites() -> Result<(), String> {
    for name in ["qemu-img", "genisoimage", "ssh", "ssh-keygen", "python3"] {
        if !crate::appliance::find_binary(name).is_some_and(|path| usable_host_executable(&path)) {
            return Err(format!(
                "Experimental Linux host prerequisite is missing: {name}."
            ));
        }
    }
    host_firmware("x86_64")?;
    linux_memory_bytes(&bounded_host_text(Path::new("/proc/meminfo"))?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn acceleration_is_explicit_and_never_silently_falls_back() {
        assert!(plan_host_qemu("linux", "x86_64", "x86_64", false, "tcg", false).is_err());
        assert!(plan_host_qemu("linux", "x86_64", "x86_64", true, "kvm", false).is_err());
        assert_eq!(
            plan_host_qemu("linux", "x86_64", "x86_64", true, "kvm", true).unwrap(),
            ("kvm", "q35,accel=kvm", "host")
        );
        assert_eq!(
            plan_host_qemu("linux", "x86_64", "x86_64", true, "tcg", false).unwrap(),
            ("tcg", "q35,accel=tcg", "max")
        );
        for mode in ["", "auto", "KVM", "tcg "] {
            assert!(plan_host_qemu("linux", "x86_64", "x86_64", true, mode, true).is_err());
        }
        for (os, host, guest) in [
            ("windows", "x86_64", "x86_64"),
            ("linux", "aarch64", "x86_64"),
            ("linux", "x86_64", "aarch64"),
        ] {
            assert!(plan_host_qemu(os, host, guest, true, "tcg", true).is_err());
        }
        assert_eq!(
            plan_host_qemu("macos", "aarch64", "x86_64", false, "", false).unwrap(),
            ("tcg", "q35,accel=tcg", "max")
        );
        assert_eq!(
            plan_host_qemu("macos", "aarch64", "aarch64", false, "", false).unwrap(),
            ("hvf", "virt,accel=hvf", "host")
        );
        assert_eq!(
            plan_host_qemu("macos", "x86_64", "x86_64", false, "", false).unwrap(),
            ("hvf", "q35,accel=hvf", "host")
        );
    }
    #[test]
    fn distribution_and_memory_reports_are_bounded_and_fail_closed() {
        for text in ["ID=ubuntu\n", "ID=\"debian\"\nID_LIKE=ubuntu"] {
            assert!(supported_linux_distribution(text));
        }
        for text in ["", "ID=fedora", "ID_LIKE=debian", "ID=ubuntu\nID=debian"] {
            assert!(!supported_linux_distribution(text));
        }
        assert_eq!(
            linux_memory_bytes("Other: 7\nMemTotal: 1234 kB\n").unwrap(),
            1234 * 1024
        );
        for text in [
            "",
            "MemTotal: 0 kB",
            "MemTotal: +1 kB",
            "MemTotal: 1 MB",
            "MemTotal: 18446744073709551615 kB",
            "MemTotal: 1 kB\nMemTotal: 2 kB",
            "MemTotal: 1 kB extra",
        ] {
            assert!(linux_memory_bytes(text).is_err());
        }
    }
    #[test]
    fn seed_arguments_preserve_paths_without_shell_interpretation() {
        let source = Path::new("/tmp/cloud init;literal");
        let output = Path::new("/tmp/seed image.iso");
        for os in ["macos", "linux"] {
            let command =
                seed_iso_command(os, Path::new("/bin/seed-tool"), source, output).unwrap();
            let args: Vec<_> = command.get_args().collect();
            assert_eq!(args[args.len() - 2], output.as_os_str());
            assert_eq!(args[args.len() - 1], source.as_os_str());
        }
        assert!(seed_iso_command("windows", Path::new("seed"), source, output).is_err());
    }
    #[test]
    fn firmware_never_mixes_pair_variants_and_host_reads_are_bounded() {
        let root =
            std::env::temp_dir().join(format!("opemos-linux-firmware-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("OVMF_CODE_4M.fd"), b"code").unwrap();
        fs::write(root.join("OVMF_VARS.fd"), b"vars").unwrap();
        assert!(linux_firmware_pair(&root).is_err());
        fs::write(root.join("OVMF_VARS_4M.fd"), b"vars").unwrap();
        assert_eq!(
            linux_firmware_pair(&root).unwrap().1,
            root.join("OVMF_VARS_4M.fd")
        );
        let info = root.join("info");
        fs::write(&info, vec![b'a'; 65537]).unwrap();
        assert!(bounded_host_text(&info).is_err());
        fs::write(&info, [255]).unwrap();
        assert!(bounded_host_text(&info).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn executable_permissions_and_memory_limits_fail_closed() {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::env::temp_dir().join(format!("opemos-host-permissions-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let tool = root.join("tool");
        fs::write(&tool, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!usable_host_executable(&tool));
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(usable_host_executable(&tool));
        assert!(!usable_host_executable(&root));
        assert_eq!(parse_memory_limit("max\n").unwrap(), None);
        assert_eq!(
            parse_memory_limit("2147483648\n").unwrap(),
            Some(2147483648)
        );
        for value in ["", "0", "-1", "+2", "1 MB", "18446744073709551616"] {
            assert!(parse_memory_limit(value).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_environment_gates_are_isolated_per_process() {
        for (enabled, mode) in [("0", "tcg"), ("1", "auto"), ("1", "tcg")] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "host_platform::tests::runtime_environment_worker",
                    "--ignored",
                    "--nocapture",
                ])
                .env("OPEMOS_EXPERIMENTAL_LINUX", enabled)
                .env("OPEMOS_LINUX_ACCEL", mode)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated helper for actual experimental Linux environment gates"]
    fn runtime_environment_worker() {
        let result = current_host_qemu(std::env::consts::ARCH, "x86_64");
        let supported =
            supported_linux_distribution(&bounded_host_text(Path::new("/etc/os-release")).unwrap())
                && std::env::consts::ARCH == "x86_64";
        let enabled = std::env::var("OPEMOS_EXPERIMENTAL_LINUX").as_deref() == Ok("1");
        let tcg = std::env::var("OPEMOS_LINUX_ACCEL").as_deref() == Ok("tcg");
        if supported && enabled && tcg {
            assert_eq!(result.unwrap().0, "tcg");
        } else {
            assert!(result.is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires installed Linux QEMU/OVMF/genisoimage and explicit experimental acceleration"]
    fn live_linux_disposable_host_tools() {
        use crate::appliance::{find_binary, run_checked, sha256_file, smoke_test_qemu};
        use std::io::{Seek, SeekFrom};
        assert_eq!(
            std::env::var("OPEMOS_EXPERIMENTAL_LINUX").as_deref(),
            Ok("1")
        );
        current_host_qemu("x86_64", "x86_64").unwrap();
        linux_host_prerequisites().unwrap();
        let budget = linux_effective_memory_bytes().unwrap();
        println!("Linux effective memory budget: {budget} bytes; QEMU smoke uses 64 MiB.");
        if budget < 6 * 1024 * 1024 * 1024 {
            assert!(crate::appliance::detect_guest_resources(false).is_err());
            let environment = crate::appliance::check_builder_environment_blocking();
            assert!(!environment.ready);
            assert_eq!(
                environment.acceleration.as_deref(),
                Some(current_host_qemu("x86_64", "x86_64").unwrap().0)
            );
            assert!(environment.message.contains("effective memory budget"));
        }
        struct Scratch(PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = Scratch(
            std::env::temp_dir().join(format!("opemos linux host {} {nonce}", std::process::id())),
        );
        fs::create_dir(&root.0).unwrap();
        let base = root.0.join("original.raw");
        fs::write(&base, vec![0x5a; 128 * 1024]).unwrap();
        let before = sha256_file(&base).unwrap();
        let overlay = root.0.join("disposable overlay.qcow2");
        let qemu_img = find_binary("qemu-img").unwrap();
        run_checked(
            Command::new(&qemu_img)
                .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
                .arg(&base)
                .arg(&overlay),
            "create test overlay",
        )
        .unwrap();
        let output = Command::new(qemu_img)
            .args(["info", "--output=json"])
            .arg(&overlay)
            .output()
            .unwrap();
        assert!(output.status.success());
        let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(info["format"], "qcow2");
        assert_eq!(info["backing-filename"], base.to_str().unwrap());
        let source = root.0.join("cloud init");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("user-data"), b"#cloud-config\n").unwrap();
        fs::write(
            source.join("meta-data"),
            b"instance-id: opemos-disposable-test\n",
        )
        .unwrap();
        let seed = root.0.join("seed image.iso");
        create_host_seed(&source, &seed).unwrap();
        let mut iso = File::open(&seed).unwrap();
        iso.seek(SeekFrom::Start(32768)).unwrap();
        let mut descriptor = [0_u8; 72];
        iso.read_exact(&mut descriptor).unwrap();
        assert_eq!(&descriptor[1..6], b"CD001");
        assert_eq!(
            std::str::from_utf8(&descriptor[40..72]).unwrap().trim(),
            "cidata"
        );
        smoke_test_qemu(&find_binary("qemu-system-x86_64").unwrap()).unwrap();
        assert_eq!(sha256_file(&base).unwrap(), before);
    }
}

#[cfg(target_os = "macos")]
use std::process::Command;
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};

pub(crate) const STORAGE_NO_SPACE_CODE: &str = "storage-admission-no-space";
pub(crate) const HOST_STORAGE_METADATA_RESERVE: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostVolumeSpace {
    pub(crate) volume_id: String,
    pub(crate) available_bytes: u64,
    // Some filesystems (notably dynamically allocated stores) do not expose a
    // meaningful inode ceiling. None means byte admission remains authoritative.
    pub(crate) available_inodes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageRequest<'a> {
    pub(crate) path: &'a Path,
    pub(crate) bytes: u64,
    pub(crate) inodes: u64,
    pub(crate) purpose: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MeasuredStorageRequest<'a> {
    pub(crate) volume: HostVolumeSpace,
    pub(crate) bytes: u64,
    pub(crate) inodes: u64,
    pub(crate) purpose: &'a str,
}

struct VolumeBudget<'a> {
    available_bytes: u64,
    available_inodes: Option<u64>,
    required_bytes: u64,
    required_inodes: u64,
    purposes: Vec<&'a str>,
}

// libc field widths differ between macOS and Linux; retain the portable cast.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn host_volume_space(path: &Path) -> Result<HostVolumeSpace, String> {
    let resolved = fs::canonicalize(path)
        .map_err(|error| format!("Could not resolve host storage path: {error}"))?;
    let metadata = fs::metadata(&resolved)
        .map_err(|error| format!("Could not identify host storage volume: {error}"))?;
    let path = CString::new(resolved.as_os_str().as_bytes())
        .map_err(|_| "Host storage path contains an embedded NUL byte.".to_string())?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(format!(
            "Could not measure host filesystem space: {}",
            std::io::Error::last_os_error()
        ));
    }
    let stats = unsafe { stats.assume_init() };
    let available_bytes = (stats.f_bavail as u64)
        .checked_mul(stats.f_frsize)
        .ok_or("Host filesystem-space report overflowed.")?;
    let available_inodes = (stats.f_files != 0).then_some(stats.f_favail as u64);
    Ok(HostVolumeSpace {
        volume_id: host_allocation_pool_id(&resolved, metadata.dev())?,
        available_bytes,
        available_inodes,
    })
}

pub(crate) fn admit_measured_storage(
    requests: &[MeasuredStorageRequest<'_>],
) -> Result<(), String> {
    let coalesce_unknown_macos_pool = requests
        .iter()
        .any(|request| request.volume.volume_id == "macos-unknown-allocation-pool");
    let mut volumes: BTreeMap<String, VolumeBudget<'_>> = BTreeMap::new();
    for request in requests {
        let volume_id = if coalesce_unknown_macos_pool {
            "macos-unknown-allocation-pool".to_string()
        } else {
            request.volume.volume_id.clone()
        };
        let entry = volumes.entry(volume_id).or_insert(VolumeBudget {
            available_bytes: request.volume.available_bytes,
            available_inodes: request.volume.available_inodes,
            required_bytes: 0,
            required_inodes: 0,
            purposes: Vec::new(),
        });
        // Measurements for the same volume can race with unrelated activity.
        // The lower observation is the only safe aggregate baseline.
        entry.available_bytes = entry.available_bytes.min(request.volume.available_bytes);
        entry.available_inodes = match (entry.available_inodes, request.volume.available_inodes) {
            (Some(left), Some(right)) => Some(left.min(right)),
            _ => None,
        };
        entry.required_bytes = entry
            .required_bytes
            .checked_add(request.bytes)
            .ok_or("Host storage byte requirement overflowed.")?;
        entry.required_inodes = entry
            .required_inodes
            .checked_add(request.inodes)
            .ok_or("Host storage inode requirement overflowed.")?;
        entry.purposes.push(request.purpose);
    }
    for (_id, budget) in volumes {
        let purpose = budget.purposes.join("; ");
        if budget.available_bytes < budget.required_bytes {
            return Err(no_space_error(
                &purpose,
                budget.required_bytes,
                budget.available_bytes,
                None,
            ));
        }
        if let Some(available_inodes) = budget.available_inodes {
            if available_inodes < budget.required_inodes {
                return Err(no_space_error(
                    &purpose,
                    budget.required_bytes,
                    budget.available_bytes,
                    Some((budget.required_inodes, available_inodes)),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn host_allocation_pool_id(path: &Path, _device: u64) -> Result<String, String> {
    let output = Command::new("/usr/sbin/diskutil")
        .args(["info", "-plist"])
        .arg(path)
        .output();
    if let Ok(output) = output {
        if !output.status.success() {
            return Ok("macos-unknown-allocation-pool".into());
        }
        let report = String::from_utf8(output.stdout)
            .map_err(|_| "Host allocation-pool report was not valid UTF-8.")?;
        if let Some(container) = plist_string(&report, "APFSContainerReference") {
            return Ok(format!("apfs-container:{container}"));
        }
        if let Some(identifier) = plist_string(&report, "DeviceIdentifier") {
            return Ok(format!("device:{identifier}"));
        }
        return Ok("macos-unknown-allocation-pool".into());
    }
    Ok("macos-unknown-allocation-pool".into())
}

#[cfg(target_os = "macos")]
fn plist_string<'a>(document: &'a str, key: &str) -> Option<&'a str> {
    let tail = document.split_once(&format!("<key>{key}</key>"))?.1;
    let value = tail.split_once("<string>")?.1;
    value.split_once("</string>").map(|(value, _)| value.trim())
}

#[cfg(not(target_os = "macos"))]
fn host_allocation_pool_id(_path: &Path, device: u64) -> Result<String, String> {
    Ok(format!("device-number:{device}"))
}

pub(crate) fn admit_host_storage(requests: &[StorageRequest<'_>]) -> Result<(), String> {
    let measured = requests
        .iter()
        .map(|request| {
            Ok(MeasuredStorageRequest {
                volume: host_volume_space(request.path)?,
                bytes: request.bytes,
                inodes: request.inodes,
                purpose: request.purpose,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    admit_measured_storage(&measured)
}

pub(crate) fn preflight_normalization_and_build(
    runtime_dir: &Path,
    output_parent: &Path,
    image_bytes: u64,
    normalization_required: bool,
    plan_export: bool,
) -> Result<(), String> {
    let normalization_bytes = if normalization_required {
        image_bytes
    } else {
        0
    };
    let runtime_bytes = crate::checked_space_sum([
        normalization_bytes,
        image_bytes,
        crate::HOST_RUNTIME_FREE_SPACE_RESERVE,
    ])?;
    let mut requests = vec![StorageRequest {
        path: runtime_dir,
        bytes: runtime_bytes,
        inodes: 13,
        purpose: "normalization, the working overlay, and runtime reserve",
    }];
    if plan_export {
        requests.push(StorageRequest {
            path: output_parent,
            bytes: crate::checked_space_sum([image_bytes, crate::HOST_OUTPUT_FREE_SPACE_RESERVE])?,
            inodes: 2,
            purpose: "output staging and the manifest (retained for image-plus-USB workflows)",
        });
    }
    admit_host_storage(&requests)
}

pub(crate) fn storage_io_error(context: &str, error: std::io::Error) -> String {
    if matches!(error.raw_os_error(), Some(libc::ENOSPC | libc::EDQUOT))
        || error.kind() == std::io::ErrorKind::StorageFull
    {
        format!("{context}: {STORAGE_NO_SPACE_CODE}: {error}")
    } else {
        format!("{context}: {error}")
    }
}

pub(crate) fn storage_process_error(context: &str, detail: &str) -> String {
    let lower = detail.to_ascii_lowercase();
    if lower.contains("no space left on device")
        || lower.contains("disk full")
        || lower.contains("not enough space")
        || lower.contains("disk quota exceeded")
    {
        format!("{context}: {STORAGE_NO_SPACE_CODE}: {}", detail.trim())
    } else if detail.trim().is_empty() {
        context.to_string()
    } else {
        format!("{context}: {}", detail.trim())
    }
}

fn no_space_error(
    purpose: &str,
    required: u64,
    available: u64,
    inodes: Option<(u64, u64)>,
) -> String {
    let inode_detail = inodes.map_or_else(String::new, |(required, available)| {
        format!(" It also needs {required} filesystem entries, but only {available} are available.")
    });
    format!(
        "{STORAGE_NO_SPACE_CODE}: Host storage admission failed for {purpose}: needs at least {} ({required} bytes) free, but only {} ({available} bytes) is available.{inode_detail} Free space on the named volume and retry.",
        crate::human_bytes(required),
        crate::human_bytes(available),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(
        volume_id: u64,
        available_bytes: u64,
        available_inodes: Option<u64>,
        bytes: u64,
        inodes: u64,
        purpose: &'static str,
    ) -> MeasuredStorageRequest<'static> {
        MeasuredStorageRequest {
            volume: HostVolumeSpace {
                volume_id: volume_id.to_string(),
                available_bytes,
                available_inodes,
            },
            bytes,
            inodes,
            purpose,
        }
    }

    #[test]
    fn aggregates_same_volume_allocations_without_recounting_capacity() {
        let requests = [
            request(7, 100, Some(20), 60, 2, "normalization"),
            request(7, 100, Some(20), 40, 3, "retained output"),
        ];
        assert!(admit_measured_storage(&requests).is_ok());
        let error = admit_measured_storage(&[
            requests[0].clone(),
            request(7, 100, Some(20), 41, 3, "retained output"),
        ])
        .expect_err("shared volume must account for both writes once");
        assert!(error.contains(STORAGE_NO_SPACE_CODE));
        assert!(error.contains("101 bytes"));
    }

    #[test]
    fn admits_independent_volume_budgets_independently() {
        assert!(admit_measured_storage(&[
            request(7, 60, Some(2), 60, 2, "runtime"),
            request(8, 40, Some(2), 40, 2, "output"),
        ])
        .is_ok());
        let error = admit_measured_storage(&[
            request(7, 59, Some(2), 60, 2, "runtime"),
            request(8, 1000, Some(2), 40, 2, "output"),
        ])
        .expect_err("one short volume must reject the plan");
        assert!(error.contains("runtime"));
    }

    #[test]
    fn rejects_overflow_and_known_inode_exhaustion_but_allows_dynamic_inodes() {
        assert!(admit_measured_storage(&[
            request(7, u64::MAX, None, u64::MAX, 100, "dynamic inode store"),
            request(7, u64::MAX, None, 1, 100, "overflow"),
        ])
        .expect_err("summation overflow must fail closed")
        .contains("overflowed"));

        let inode_error =
            admit_measured_storage(&[request(7, 100, Some(1), 1, 2, "manifest publication")])
                .expect_err("known inode shortage must fail");
        assert!(inode_error.contains(STORAGE_NO_SPACE_CODE));
        assert!(inode_error.contains("filesystem entries"));
        assert!(admit_measured_storage(&[request(
            7,
            100,
            None,
            1,
            u64::MAX,
            "dynamic inode store",
        )])
        .is_ok());
    }

    #[test]
    fn uses_the_lower_of_racing_same_volume_measurements() {
        let error = admit_measured_storage(&[
            request(7, 100, Some(10), 40, 1, "first phase"),
            request(7, 50, Some(9), 20, 1, "second phase"),
        ])
        .expect_err("lower contemporaneous observation must win");
        assert!(error.contains("60 bytes"));
        assert!(error.contains("50 bytes"));
    }

    #[test]
    fn realistic_shared_and_split_volume_plans_do_not_double_count_images() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let shared_required = 12 * GIB + 12 * GIB + 12 * GIB + 4 * GIB + 64 * 1024 * 1024;
        assert!(admit_measured_storage(&[
            request(
                7,
                shared_required,
                Some(100),
                28 * GIB,
                13,
                "normalize and work"
            ),
            request(
                7,
                shared_required,
                Some(100),
                12 * GIB + 64 * 1024 * 1024,
                2,
                "retain and write USB",
            ),
        ])
        .is_ok());

        assert!(admit_measured_storage(&[
            request(7, 36 * GIB, Some(100), 36 * GIB, 13, "normalize and work"),
            request(
                8,
                12 * GIB + 64 * 1024 * 1024,
                Some(100),
                12 * GIB + 64 * 1024 * 1024,
                2,
                "retain and write USB",
            ),
        ])
        .is_ok());
    }

    #[test]
    fn unresolved_macos_pool_coalesces_the_entire_measurement_batch() {
        let mut unknown = request(7, 100, None, 60, 1, "unknown runtime pool");
        unknown.volume.volume_id = "macos-unknown-allocation-pool".into();
        let concrete = request(8, 100, None, 60, 1, "resolved output pool");
        assert!(admit_measured_storage(&[unknown, concrete])
            .expect_err("mixed lookup results must fail against one conservative pool")
            .contains("120 bytes"));
    }
}

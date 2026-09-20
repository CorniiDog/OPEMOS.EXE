use super::*;

pub(crate) fn run_transfer_proof(session: &impl GuestConnection) -> Result<TransferProof, String> {
    const PROBE: &[u8] = b"STEAMOS_BUILDER_TRANSFER_PROBE_V1\n";
    const GUEST_INPUT: &str = "/tmp/steamos-builder-transfer-probe.in";
    const GUEST_OUTPUT: &str = "/tmp/steamos-builder-transfer-probe.out";
    let host_input = session.runtime_dir().join("transfer-probe.in");
    let host_output = session.runtime_dir().join("transfer-probe.out");
    fs::write(&host_input, PROBE).map_err(|e| format!("Could not create transfer probe: {e}"))?;

    run_checked(
        scp_command(session)?
            .arg(&host_input)
            .arg(format!("builder@127.0.0.1:{GUEST_INPUT}")),
        "Could not copy the transfer probe into the guest",
    )?;
    let guest_sha256 = run_guest_command(
        session,
        "set -eu; sha256sum /tmp/steamos-builder-transfer-probe.in | cut -d ' ' -f 1; cp /tmp/steamos-builder-transfer-probe.in /tmp/steamos-builder-transfer-probe.out; sync",
    )?;
    run_checked(
        scp_command(session)?
            .arg(format!("builder@127.0.0.1:{GUEST_OUTPUT}"))
            .arg(&host_output),
        "Could not copy the transfer probe back from the guest",
    )?;
    let returned = fs::read(&host_output)
        .map_err(|e| format!("Could not read the returned transfer probe: {e}"))?;
    let _ = run_guest_command(
        session,
        "rm -f /tmp/steamos-builder-transfer-probe.in /tmp/steamos-builder-transfer-probe.out",
    );
    if returned != PROBE {
        return Err("Returned transfer probe did not match the original bytes.".into());
    }
    Ok(TransferProof {
        bytes_verified: returned.len(),
        guest_sha256,
        message: "Host-to-guest-to-host transfer verified byte-for-byte.".into(),
    })
}

pub(crate) fn inspect_synthetic_disk(
    session: &impl GuestConnection,
) -> Result<SyntheticDiskInspection, String> {
    const INSPECT_COMMAND: &str = r#"set -eu
DEVICE=/dev/disk/by-id/virtio-steamos-synthetic
PART=/dev/disk/by-id/virtio-steamos-synthetic-part1
test -b "$DEVICE"
if findmnt -rn -S "$DEVICE" >/dev/null 2>&1 || findmnt -rn -S "$PART" >/dev/null 2>&1; then
  echo 'Synthetic test device was unexpectedly mounted.' >&2
  exit 1
fi
sudo blockdev --setrw "$DEVICE"
printf 'label: dos\nunit: sectors\n\n2048,98304,83,*\n' | sudo sfdisk --wipe always "$DEVICE" >/dev/null
for attempt in $(seq 1 20); do
  test -b "$PART" && break
  sleep 0.1
done
test -b "$PART"
sudo mkfs.ext4 -q -F -L STEAMOS_TEST -U 11111111-2222-3333-4444-555555555555 "$PART"
sync
sudo blockdev --setro "$DEVICE"
DISK_NODE=$(basename "$(readlink -f "$DEVICE")")
PART_NODE=$(basename "$(readlink -f "$PART")")
START_SECTORS=$(cat "/sys/class/block/$PART_NODE/start")
MOUNTED=0
findmnt -rn -S "$PART" >/dev/null 2>&1 && MOUNTED=1
printf 'DEVICE=%s\n' "$DEVICE"
printf 'DISK_BYTES=%s\n' "$(sudo blockdev --getsize64 "$DEVICE")"
printf 'READ_ONLY=%s\n' "$(sudo blockdev --getro "$DEVICE")"
printf 'PARTITION_TABLE=%s\n' "$(sudo blkid -p -s PTTYPE -o value "$DEVICE")"
printf 'PARTITION=%s\n' "$PART"
printf 'PARTITION_START_BYTES=%s\n' "$((START_SECTORS * 512))"
printf 'PARTITION_BYTES=%s\n' "$(sudo blockdev --getsize64 "$PART")"
printf 'FILESYSTEM=%s\n' "$(sudo blkid -s TYPE -o value "$PART")"
printf 'FILESYSTEM_LABEL=%s\n' "$(sudo blkid -s LABEL -o value "$PART")"
printf 'FILESYSTEM_UUID=%s\n' "$(sudo blkid -s UUID -o value "$PART")"
printf 'MOUNTED=%s\n' "$MOUNTED"
test "$(sudo blockdev --getro "$DEVICE")" = 1
test "$MOUNTED" = 0
test -n "$DISK_NODE""#;
    let output = run_guest_command(session, INSPECT_COMMAND)?;
    let mut values = std::collections::HashMap::new();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key, value);
        }
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("Synthetic disk inspection omitted {key}."))
    };
    let parse_u64 = |key: &str| -> Result<u64, String> {
        required(key)?
            .parse::<u64>()
            .map_err(|e| format!("Synthetic disk inspection returned invalid {key}: {e}"))
    };
    Ok(SyntheticDiskInspection {
        device: required("DEVICE")?.to_string(),
        disk_bytes: parse_u64("DISK_BYTES")?,
        read_only: required("READ_ONLY")? == "1",
        partition_table: required("PARTITION_TABLE")?.to_string(),
        partition: required("PARTITION")?.to_string(),
        partition_start_bytes: parse_u64("PARTITION_START_BYTES")?,
        partition_bytes: parse_u64("PARTITION_BYTES")?,
        filesystem: required("FILESYSTEM")?.to_string(),
        filesystem_label: required("FILESYSTEM_LABEL")?.to_string(),
        filesystem_uuid: required("FILESYSTEM_UUID")?.to_string(),
        mounted: required("MOUNTED")? == "1",
    })
}

pub(crate) fn append_image_nodes(
    node: LsblkNode,
    logical_sector_bytes: u64,
    nodes: &mut Vec<ImageNodeInspection>,
) {
    let mounted = node
        .mountpoints
        .as_ref()
        .is_some_and(|mountpoints| mountpoints.iter().flatten().any(|value| !value.is_empty()));
    nodes.push(ImageNodeInspection {
        path: node.path,
        node_type: node.node_type,
        size_bytes: node.size,
        start_bytes: node
            .start
            .and_then(|start| start.checked_mul(logical_sector_bytes)),
        filesystem: node.fstype,
        filesystem_label: node.label,
        partition_label: node.partlabel,
        partition_type: node.parttype,
        partition_uuid: node.partuuid,
        filesystem_uuid: node.uuid,
        mounted,
    });
    for child in node.children.unwrap_or_default() {
        append_image_nodes(child, logical_sector_bytes, nodes);
    }
}

pub(crate) fn discover_steamos_layout(
    partition_table: Option<&str>,
    nodes: &[ImageNodeInspection],
) -> SteamOsLayoutDiscovery {
    const ESP_TYPE: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
    const BASIC_DATA_TYPE: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
    const ROOT_X86_64_TYPE: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
    const VAR_TYPE: &str = "4d21b016-b534-45c2-a9fb-5c16e091fd2d";
    const HOME_TYPE: &str = "933ac7e1-2eb4-4f13-b844-0e14e2aef915";

    let expected = [
        ("esp", "vfat", "esp", "esp", ESP_TYPE),
        ("efi", "vfat", "efi", "efi-a", BASIC_DATA_TYPE),
        ("rootfs", "btrfs", "rootfs", "rootfs-a", ROOT_X86_64_TYPE),
        ("var", "ext4", "var", "var-a", VAR_TYPE),
        ("home", "ext4", "home", "home", HOME_TYPE),
    ];
    let mut roles = Vec::new();
    let mut issues = Vec::new();
    if partition_table != Some("gpt") {
        issues.push("Expected a GPT partition table.".into());
    }
    if nodes.iter().any(|node| node.mounted) {
        issues.push("At least one image filesystem is already mounted.".into());
    }
    for (role, filesystem, filesystem_label, partition_label, partition_type) in expected {
        let matches = nodes
            .iter()
            .filter(|node| {
                node.node_type == "part"
                    && node
                        .filesystem
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(filesystem))
                    && node
                        .filesystem_label
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(filesystem_label))
                    && node
                        .partition_label
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(partition_label))
                    && node
                        .partition_type
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(partition_type))
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            issues.push(format!(
                "Expected exactly one {role} partition, found {}.",
                matches.len()
            ));
            continue;
        }
        let node = matches[0];
        roles.push(SteamOsPartitionRole {
            role: role.into(),
            path: node.path.clone(),
            size_bytes: node.size_bytes,
            filesystem: filesystem.into(),
            filesystem_label: filesystem_label.into(),
            partition_label: partition_label.into(),
            partition_type: partition_type.into(),
        });
    }
    let recognized = issues.is_empty() && roles.len() == expected.len();
    SteamOsLayoutDiscovery {
        recognized,
        scheme: recognized.then(|| "valve-recovery-a".into()),
        roles,
        issues,
    }
}

pub(crate) fn inspect_user_image(
    session: &ImageInspectionSession,
    progress: Option<&ProgressCallback<'_>>,
    cancel: Option<&AtomicBool>,
) -> Result<UserImageInspection, String> {
    const DEVICE: &str = "/dev/disk/by-id/virtio-steamos-user-input";
    let read_only = parse_guest_read_only_property(
        &run_guest_command_with_timeout(
            session,
            "set -eu; DEVICE=/dev/disk/by-id/virtio-steamos-user-input; test -b \"$DEVICE\"; NODE=$(basename \"$(readlink -f \"$DEVICE\")\"); cat \"/sys/class/block/$NODE/ro\"",
            Duration::from_secs(10),
        )?,
        "selected image",
    )?;
    if !read_only {
        return Err("Selected image was not attached read-only; inspection was stopped.".into());
    }
    let parse_device_number = |command: &str, description: &str| -> Result<u64, String> {
        run_guest_command(session, command)?
            .parse::<u64>()
            .map_err(|e| {
                format!("Selected image inspection returned an invalid {description}: {e}")
            })
    };
    let disk_bytes = parse_device_number(
        "set -eu; DEVICE=/dev/disk/by-id/virtio-steamos-user-input; sudo blockdev --getsize64 \"$DEVICE\"",
        "disk size",
    )?;
    let logical_sector_bytes = parse_device_number(
        "set -eu; DEVICE=/dev/disk/by-id/virtio-steamos-user-input; sudo blockdev --getss \"$DEVICE\"",
        "logical sector size",
    )?;
    let partition_table = run_guest_command(
        session,
        "DEVICE=/dev/disk/by-id/virtio-steamos-user-input; sudo blkid -p -s PTTYPE -o value \"$DEVICE\" 2>/dev/null || true",
    )?;
    let json = run_guest_command(
        session,
        "set -eu; DEVICE=/dev/disk/by-id/virtio-steamos-user-input; sudo lsblk --json --bytes --output PATH,TYPE,SIZE,START,FSTYPE,LABEL,PARTLABEL,PARTTYPE,PARTUUID,UUID,MOUNTPOINTS \"$DEVICE\"",
    )?;
    let response: LsblkResponse = serde_json::from_str(&json)
        .map_err(|e| format!("Could not parse selected image layout from the guest: {e}"))?;
    let mut nodes = Vec::new();
    for node in response.blockdevices {
        append_image_nodes(node, logical_sector_bytes, &mut nodes);
    }
    if nodes.is_empty() {
        return Err("Selected image inspection returned no block devices.".into());
    }
    if let Some(node) = nodes.iter().find(|node| node.mounted) {
        return Err(format!(
            "Selected image node {} was unexpectedly mounted; inspection was stopped.",
            node.path
        ));
    }
    let source_sha256_after = sha256_file_with_progress(
        &session.input_image,
        "verifying-source-after",
        progress,
        cancel,
    )?;
    let source_unchanged = session.input_sha256_before == source_sha256_after;
    if !source_unchanged {
        return Err(format!(
            "Selected image changed during read-only inspection (before {}, after {}).",
            session.input_sha256_before, source_sha256_after
        ));
    }
    let image_sha256_after = if session.attached_image == session.input_image {
        source_sha256_after.clone()
    } else {
        sha256_file_with_progress(
            &session.attached_image,
            "verifying-image-after",
            progress,
            cancel,
        )?
    };
    let image_unchanged = session.attached_sha256_before == image_sha256_after;
    if !image_unchanged {
        return Err(format!(
            "Normalized image changed during read-only inspection (before {}, after {}).",
            session.attached_sha256_before, image_sha256_after
        ));
    }
    let partition_table = (!partition_table.is_empty()).then_some(partition_table);
    let layout = discover_steamos_layout(partition_table.as_deref(), &nodes);
    Ok(UserImageInspection {
        device: DEVICE.into(),
        disk_bytes,
        read_only,
        partition_table,
        nodes,
        source_sha256_before: session.input_sha256_before.clone(),
        source_sha256_after,
        source_unchanged,
        image_sha256_before: session.attached_sha256_before.clone(),
        image_sha256_after,
        image_unchanged,
        input: session.input_preparation.clone(),
        layout,
    })
}

pub(crate) fn verify_user_working_image(
    session: &impl GuestConnection,
) -> Result<WorkingImageVerification, String> {
    const SOURCE: &str = "/dev/disk/by-id/virtio-steamos-user-input";
    const WORKING: &str = "/dev/disk/by-id/virtio-steamos-user-working";
    const VERIFY_COMMAND: &str = r#"set -eu
SOURCE=/dev/disk/by-id/virtio-steamos-user-input
WORKING=/dev/disk/by-id/virtio-steamos-user-working
test -b "$SOURCE"
test -b "$WORKING"
SOURCE_MOUNTED=0
WORKING_MOUNTED=0
lsblk -nr -o MOUNTPOINTS "$SOURCE" | grep -q '[^[:space:]]' && SOURCE_MOUNTED=1 || true
lsblk -nr -o MOUNTPOINTS "$WORKING" | grep -q '[^[:space:]]' && WORKING_MOUNTED=1 || true
printf 'SOURCE_BYTES=%s\n' "$(sudo blockdev --getsize64 "$SOURCE")"
printf 'WORKING_BYTES=%s\n' "$(sudo blockdev --getsize64 "$WORKING")"
printf 'SOURCE_READ_ONLY=%s\n' "$(sudo blockdev --getro "$SOURCE")"
printf 'WORKING_READ_ONLY=%s\n' "$(sudo blockdev --getro "$WORKING")"
printf 'SOURCE_MOUNTED=%s\n' "$SOURCE_MOUNTED"
printf 'WORKING_MOUNTED=%s\n' "$WORKING_MOUNTED"
printf 'SOURCE_PARTITION_TABLE=%s\n' "$(sudo blkid -p -s PTTYPE -o value "$SOURCE" 2>/dev/null || true)"
printf 'WORKING_PARTITION_TABLE=%s\n' "$(sudo blkid -p -s PTTYPE -o value "$WORKING" 2>/dev/null || true)"
test "$(sudo blockdev --getro "$SOURCE")" = 1
test "$(sudo blockdev --getro "$WORKING")" = 0
test "$(sudo blockdev --getsize64 "$SOURCE")" = "$(sudo blockdev --getsize64 "$WORKING")"
test "$SOURCE_MOUNTED" = 0
test "$WORKING_MOUNTED" = 0"#;
    let output = run_guest_command(session, VERIFY_COMMAND)?;
    let mut values = std::collections::HashMap::new();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key, value);
        }
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| format!("Working-image verification omitted {key}."))
    };
    let parse_u64 = |key: &str| -> Result<u64, String> {
        required(key)?
            .parse::<u64>()
            .map_err(|e| format!("Working-image verification returned invalid {key}: {e}"))
    };
    let source_bytes = parse_u64("SOURCE_BYTES")?;
    let working_bytes = parse_u64("WORKING_BYTES")?;
    let source_partition_table = required("SOURCE_PARTITION_TABLE")?;
    let working_partition_table = required("WORKING_PARTITION_TABLE")?;
    let layout_matches =
        source_bytes == working_bytes && source_partition_table == working_partition_table;
    if !layout_matches {
        return Err("The disposable working layer does not match the source image layout.".into());
    }
    Ok(WorkingImageVerification {
        source_device: SOURCE.into(),
        working_device: WORKING.into(),
        source_bytes,
        working_bytes,
        source_read_only: required("SOURCE_READ_ONLY")? == "1",
        working_read_only: required("WORKING_READ_ONLY")? == "1",
        source_mounted: required("SOURCE_MOUNTED")? == "1",
        working_mounted: required("WORKING_MOUNTED")? == "1",
        source_partition_table: (!source_partition_table.is_empty())
            .then(|| source_partition_table.to_string()),
        working_partition_table: (!working_partition_table.is_empty())
            .then(|| working_partition_table.to_string()),
        layout_matches,
        overlay_format: "qcow2".into(),
    })
}

pub(crate) fn mutate_synthetic_marker(
    session: &impl GuestConnection,
) -> Result<MarkerMutation, String> {
    const MARKER_PATH: &str = "/etc/steamos-nvidia-image-builder-test";
    const MARKER_CONTENT: &str = "SteamOS NVIDIA Image Builder synthetic marker\nprotocol=1\n";
    const MUTATE_COMMAND: &str = r#"set -eu
SOURCE=/dev/disk/by-id/virtio-steamos-synthetic
WORK=/dev/disk/by-id/virtio-steamos-working
WORK_PART=/dev/disk/by-id/virtio-steamos-working-part1
MOUNT_DIR=/mnt/steamos-builder-marker
EXPECTED=$(printf 'SteamOS NVIDIA Image Builder synthetic marker\nprotocol=1')
test -b "$SOURCE"
test -b "$WORK"
test "$(sudo blockdev --getro "$SOURCE")" = 1
SOURCE_BEFORE=$(sudo sha256sum "$SOURCE" | cut -d ' ' -f 1)
sudo blockdev --setrw "$WORK"
sudo dd if="$SOURCE" of="$WORK" bs=4M conv=fsync status=none
for attempt in $(seq 1 30); do
  test -b "$WORK_PART" && break
  sudo blockdev --rereadpt "$WORK" 2>/dev/null || true
  sleep 0.1
done
test -b "$WORK_PART"
sudo mkdir -p "$MOUNT_DIR"
cleanup_mount() {
  findmnt -rn -M "$MOUNT_DIR" >/dev/null 2>&1 && sudo umount "$MOUNT_DIR" || true
}
trap cleanup_mount EXIT
sudo mount -o rw "$WORK_PART" "$MOUNT_DIR"
sudo mkdir -p "$MOUNT_DIR/etc"
printf 'SteamOS NVIDIA Image Builder synthetic marker\nprotocol=1\n' | sudo tee "$MOUNT_DIR/etc/steamos-nvidia-image-builder-test" >/dev/null
sync
test "$(sudo cat "$MOUNT_DIR/etc/steamos-nvidia-image-builder-test")" = "$EXPECTED"
sudo umount "$MOUNT_DIR"
trap - EXIT
sudo blockdev --setro "$WORK"
SOURCE_AFTER=$(sudo sha256sum "$SOURCE" | cut -d ' ' -f 1)
WORKING_SHA=$(sudo sha256sum "$WORK" | cut -d ' ' -f 1)
MOUNTED=0
findmnt -rn -S "$WORK_PART" >/dev/null 2>&1 && MOUNTED=1
printf 'SOURCE_BEFORE=%s\n' "$SOURCE_BEFORE"
printf 'SOURCE_AFTER=%s\n' "$SOURCE_AFTER"
printf 'WORKING_SHA=%s\n' "$WORKING_SHA"
printf 'WORKING_READ_ONLY=%s\n' "$(sudo blockdev --getro "$WORK")"
printf 'MOUNTED=%s\n' "$MOUNTED"
test "$SOURCE_BEFORE" = "$SOURCE_AFTER"
test "$SOURCE_BEFORE" != "$WORKING_SHA"
test "$(sudo blockdev --getro "$WORK")" = 1
test "$MOUNTED" = 0"#;
    let output = run_guest_command(session, MUTATE_COMMAND)?;
    let mut values = std::collections::HashMap::new();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key, value);
        }
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("Synthetic marker mutation omitted {key}."))
    };
    let source_sha256_before = required("SOURCE_BEFORE")?.to_string();
    let source_sha256_after = required("SOURCE_AFTER")?.to_string();
    Ok(MarkerMutation {
        marker_path: MARKER_PATH.into(),
        marker_content: MARKER_CONTENT.into(),
        source_unchanged: source_sha256_before == source_sha256_after,
        source_sha256_before,
        source_sha256_after,
        working_sha256: required("WORKING_SHA")?.to_string(),
        working_read_only: required("WORKING_READ_ONLY")? == "1",
        mounted: required("MOUNTED")? == "1",
    })
}

pub(crate) fn parse_guest_read_only_property(
    value: &str,
    description: &str,
) -> Result<bool, String> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(format!(
            "{description} returned an invalid read-only property; expected exactly 0 or 1."
        )),
    }
}

pub(crate) fn normalize_os_release_field(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let unquoted = if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    };
    (!unquoted.is_empty()).then(|| unquoted.to_string())
}

pub(crate) fn preflight_user_marker(session: &ImageInspectionSession) -> Result<(), String> {
    const PREFLIGHT_COMMAND: &str = r#"set -eu
SOURCE=/dev/disk/by-id/virtio-steamos-user-input
WORK=/dev/disk/by-id/virtio-steamos-user-working
fail_preflight() {
  printf 'Selected-image mutation preflight failed: %s\n' "$1" >&2
  exit 1
}
test -b "$SOURCE" || fail_preflight 'read-only source device is unavailable'
test -b "$WORK" || fail_preflight 'disposable working device is unavailable'
read_only_property() {
  node=$(basename "$(readlink -f "$1")") || return 1
  value=$(cat "/sys/class/block/$node/ro") || return 1
  case "$value" in
    0|1) printf '%s' "$value" ;;
    *) return 1 ;;
  esac
}
SOURCE_READ_ONLY=$(read_only_property "$SOURCE") || fail_preflight 'source read-only property is invalid'
WORK_READ_ONLY=$(read_only_property "$WORK") || fail_preflight 'working read-only property is invalid'
test "$SOURCE_READ_ONLY" = 1 || fail_preflight 'source device is not read-only'
test "$WORK_READ_ONLY" = 0 || fail_preflight 'working device is not writable'
if lsblk -nr -o MOUNTPOINTS "$SOURCE" | grep -q '[^[:space:]]' || lsblk -nr -o MOUNTPOINTS "$WORK" | grep -q '[^[:space:]]'; then
  fail_preflight 'a selected-image device is unexpectedly mounted'
fi"#;
    run_guest_command(session, PREFLIGHT_COMMAND).map(|_| ())
}

pub(crate) fn mutate_user_marker_after_preflight(
    session: &ImageInspectionSession,
) -> Result<UserMarkerMutation, String> {
    const MARKER_PATH: &str = "/etc/steamos-nvidia-image-builder-test";
    const MARKER_CONTENT: &str =
        "SteamOS NVIDIA Image Builder marker\nprotocol=1\nmilestone=marker-only\n";
    const MUTATE_COMMAND: &str = r#"set -eu
SOURCE=/dev/disk/by-id/virtio-steamos-user-input
WORK=/dev/disk/by-id/virtio-steamos-user-working
MOUNT_DIR=/mnt/steamos-user-marker
EXPECTED=$(printf 'SteamOS NVIDIA Image Builder marker\nprotocol=1\nmilestone=marker-only')
printf 'OPEMOS_MUTATION_CHANNEL_READY\n'
for attempt in $(seq 1 150); do
  test ! -b "$SOURCE" && break
  sleep 0.1
done
if test -b "$SOURCE"; then
  echo 'The read-only source device did not finish detaching within 15 seconds.' >&2
  exit 1
fi
test -b "$WORK"
TARGETS=$(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "rootfs-A" && $3 == "btrfs" { print $1 }')
test "$(printf '%s\n' "$TARGETS" | sed '/^$/d' | wc -l | tr -d ' ')" = 1
TARGET=$(printf '%s\n' "$TARGETS" | sed '/^$/d')
sudo mkdir -p "$MOUNT_DIR"
WAS_SEEDING=0
SEEDING_RESTORED=0
SOURCE_ROOT=
RESTORE_SOURCE_RO=0
cleanup_marker() {
  if findmnt -rn -M "$MOUNT_DIR" >/dev/null 2>&1 && test "$RESTORE_SOURCE_RO" = 1 && test -n "$SOURCE_ROOT"; then
    sudo btrfs property set -f -ts "$SOURCE_ROOT" ro true >/dev/null 2>&1 || true
  fi
  findmnt -rn -M "$MOUNT_DIR" >/dev/null 2>&1 && sudo umount "$MOUNT_DIR" || true
  if test "$WAS_SEEDING" = 1 && test "$SEEDING_RESTORED" = 0; then
    sudo btrfstune -f -S 1 "$TARGET" >/dev/null 2>&1 || true
  fi
  sudo blockdev --setro "$WORK" >/dev/null 2>&1 || true
}
trap cleanup_marker EXIT
sudo mount -o rw,subvolid=5 "$TARGET" "$MOUNT_DIR"
if findmnt -rn -M "$MOUNT_DIR" -o OPTIONS | tr ',' '\n' | grep -qx ro; then
  sudo umount "$MOUNT_DIR"
  WAS_SEEDING=1
  sudo btrfstune -f -S 0 "$TARGET"
  sudo mount -o rw,subvolid=5 "$TARGET" "$MOUNT_DIR"
fi
findmnt -rn -M "$MOUNT_DIR" -o OPTIONS | tr ',' '\n' | grep -qx rw
DEFAULT_INFO=$(sudo btrfs subvolume get-default "$MOUNT_DIR")
DEFAULT_PATH=$(printf '%s\n' "$DEFAULT_INFO" | sed -n 's/^.* path //p')
if test -z "$DEFAULT_PATH" && printf '%s\n' "$DEFAULT_INFO" | grep -q '^ID 5 (FS_TREE)$'; then
  DEFAULT_PATH='<FS_TREE>'
fi
test -n "$DEFAULT_PATH"
case "$DEFAULT_PATH" in
  '<FS_TREE>') SOURCE_ROOT="$MOUNT_DIR"; SNAPSHOT_ROOT= ;;
  /*|*..*) echo 'Unsafe Btrfs default subvolume path.' >&2; exit 1 ;;
  *) SOURCE_ROOT="$MOUNT_DIR/$DEFAULT_PATH"; SNAPSHOT_ROOT="$MOUNT_DIR/steamos-nvidia-marker-root" ;;
esac
if test ! -d "$SOURCE_ROOT"; then
  echo 'The Btrfs default root subvolume path is unavailable.' >&2
  exit 1
fi
SOURCE_ROOT_RO=$(sudo btrfs property get -ts "$SOURCE_ROOT" ro | awk -F= '$1 == "ro" { print $2 }')
test "$SOURCE_ROOT_RO" = true || test "$SOURCE_ROOT_RO" = false
if test "$SOURCE_ROOT_RO" = true; then
  RESTORE_SOURCE_RO=1
  sudo btrfs property set -f -ts "$SOURCE_ROOT" ro false
fi
if test -n "$SNAPSHOT_ROOT"; then
  test ! -e "$SNAPSHOT_ROOT"
  sudo btrfs subvolume snapshot "$SOURCE_ROOT" "$SNAPSHOT_ROOT" >/dev/null
  MUTATION_ROOT="$SNAPSHOT_ROOT"
else
  MUTATION_ROOT="$SOURCE_ROOT"
fi
release_value() {
  RELEASE_FILE="$1"
  RELEASE_KEY="$2"
  if test -f "$RELEASE_FILE"; then
    sudo awk -F= -v wanted="$RELEASE_KEY" '$1 == wanted { sub(/^[^=]*=/, ""); print; exit }' "$RELEASE_FILE" \
      | tr '\r\n' '  ' | cut -c1-512
  fi
}
OS_RELEASE="$MUTATION_ROOT/etc/os-release"
if test ! -f "$OS_RELEASE" || test -L "$OS_RELEASE"; then
  OS_RELEASE="$MUTATION_ROOT/usr/lib/os-release"
fi
if test ! -f "$OS_RELEASE" || test -L "$OS_RELEASE"; then
  OS_RELEASE=
fi
OS_ID=$(release_value "$OS_RELEASE" ID)
OS_PRETTY_NAME=$(release_value "$OS_RELEASE" PRETTY_NAME)
OS_VERSION_ID=$(release_value "$OS_RELEASE" VERSION_ID)
OS_BUILD_ID=$(release_value "$OS_RELEASE" BUILD_ID)
OS_VARIANT_ID=$(release_value "$OS_RELEASE" VARIANT_ID)
TARGET_ARCH=unknown
for ELF_PATH in "$MUTATION_ROOT/usr/bin/bash" "$MUTATION_ROOT/bin/bash"; do
  if test -f "$ELF_PATH" && test ! -L "$ELF_PATH"; then
    ELF_MACHINE=$(sudo od -An -t u2 -j 18 -N 2 "$ELF_PATH" | tr -d '[:space:]')
    case "$ELF_MACHINE" in
      62) TARGET_ARCH=x86_64 ;;
      183) TARGET_ARCH=aarch64 ;;
    esac
    break
  fi
done
KERNELS=
for MODULE_ROOT in "$MUTATION_ROOT/usr/lib/modules"; do
  if test -d "$MODULE_ROOT" && test ! -L "$MODULE_ROOT"; then
    KERNELS=$(sudo find "$MODULE_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' \
      | LC_ALL=C sort -u | awk '/^[A-Za-z0-9._+:-]+$/ { print }' | head -32)
    test -n "$KERNELS" && break
  fi
done
sudo mkdir -p "$MUTATION_ROOT/etc"
printf 'SteamOS NVIDIA Image Builder marker\nprotocol=1\nmilestone=marker-only\n' | sudo tee "$MUTATION_ROOT/etc/steamos-nvidia-image-builder-test" >/dev/null
sync
test "$(sudo cat "$MUTATION_ROOT/etc/steamos-nvidia-image-builder-test")" = "$EXPECTED"
if test "$RESTORE_SOURCE_RO" = 1; then
  sudo btrfs property set -f -ts "$SOURCE_ROOT" ro true
  RESTORE_SOURCE_RO=0
fi
if test -n "$SNAPSHOT_ROOT"; then
  sudo btrfs property set -ts "$SNAPSHOT_ROOT" ro true
  test "$(sudo btrfs property get -ts "$SNAPSHOT_ROOT" ro | awk -F= '$1 == "ro" { print $2 }')" = true
  sudo btrfs subvolume set-default "$SNAPSHOT_ROOT"
fi
sudo umount "$MOUNT_DIR"
if test "$WAS_SEEDING" = 1; then
  sudo btrfstune -f -S 1 "$TARGET"
  SEEDING_RESTORED=1
fi
sudo blockdev --setro "$WORK"
sudo mount -o ro "$TARGET" "$MOUNT_DIR"
test "$(sudo cat "$MOUNT_DIR/etc/steamos-nvidia-image-builder-test")" = "$EXPECTED"
if test -n "$SNAPSHOT_ROOT"; then
  test "$(sudo btrfs property get -ts "$MOUNT_DIR" ro | awk -F= '$1 == "ro" { print $2 }')" = true
fi
sudo umount "$MOUNT_DIR"
trap - EXIT
MOUNTED=0
findmnt -rn -S "$TARGET" >/dev/null 2>&1 && MOUNTED=1
printf 'TARGET=%s\n' "$TARGET"
printf 'PARTITION_LABEL=%s\n' "$(sudo blkid -s PARTLABEL -o value "$TARGET")"
printf 'FILESYSTEM=%s\n' "$(sudo blkid -s TYPE -o value "$TARGET")"
printf 'WORKING_READ_ONLY=%s\n' "$(sudo blockdev --getro "$WORK")"
printf 'MOUNTED=%s\n' "$MOUNTED"
printf 'OS_ID=%s\n' "$OS_ID"
printf 'OS_PRETTY_NAME=%s\n' "$OS_PRETTY_NAME"
printf 'OS_VERSION_ID=%s\n' "$OS_VERSION_ID"
printf 'OS_BUILD_ID=%s\n' "$OS_BUILD_ID"
printf 'OS_VARIANT_ID=%s\n' "$OS_VARIANT_ID"
printf 'TARGET_ARCH=%s\n' "$TARGET_ARCH"
printf '%s\n' "$KERNELS" | while IFS= read -r KERNEL; do
  test -n "$KERNEL" && printf 'KERNEL=%s\n' "$KERNEL"
done
test "$(sudo blockdev --getro "$WORK")" = 1
test "$MOUNTED" = 0"#;
    #[cfg(windows)]
    let output = {
        let output = crate::windows_ssh::run_gated_command(
            session.ssh_port,
            &session.ssh_key,
            MUTATE_COMMAND,
            "OPEMOS_MUTATION_CHANNEL_READY",
            Duration::from_secs(30),
            Duration::from_secs(120),
            64 * 1024,
            || qmp_remove_user_input(session),
        )?;
        if output.status != 0 {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if stderr.is_empty() { stdout } else { stderr };
            return Err(if detail.is_empty() {
                format!("Guest command exited with status {}.", output.status)
            } else {
                format!(
                    "Guest command exited with status {}: {detail}",
                    output.status
                )
            });
        }
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    };
    #[cfg(not(windows))]
    let output = {
        let mut mutation = start_guest_command(session, MUTATE_COMMAND)?;
        let stderr_drain = start_guest_stderr_drain(&mut mutation)?;
        let stdout = mutation
            .stdout
            .take()
            .ok_or("Could not capture the mutation guest command output.")?;
        let readiness =
            read_guest_command_ready_line(&mut mutation, stdout, Duration::from_secs(30));
        let (stdout, channel_ready) = match readiness {
            Ok(readiness) => readiness,
            Err(error) => {
                let _ = stderr_drain.join();
                return Err(format!("Could not establish the mutation channel: {error}"));
            }
        };
        if channel_ready.trim() != "OPEMOS_MUTATION_CHANNEL_READY" {
            stop_guest_command_group(&mut mutation);
            let _ = stderr_drain.join();
            return Err("Mutation guest command omitted the channel readiness marker.".into());
        }
        if let Err(error) = qmp_remove_user_input(session) {
            stop_guest_command_group(&mut mutation);
            let _ = stderr_drain.join();
            return Err(error);
        }
        finish_guest_command_with_stdout(mutation, stdout, String::new(), stderr_drain)?
    };
    let mut values = std::collections::HashMap::new();
    let mut kernel_versions = Vec::new();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key == "KERNEL" {
                if !value.is_empty() && !kernel_versions.iter().any(|kernel| kernel == value) {
                    kernel_versions.push(value.to_string());
                }
            } else {
                values.insert(key, value);
            }
        }
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("Selected-image marker mutation omitted {key}."))
    };
    let input_sha256_after = sha256_file_with_progress(
        &session.input_image,
        "verifying-source-after-mutation",
        None,
        None,
    )?;
    let input_unchanged = session.input_sha256_before == input_sha256_after;
    if !input_unchanged {
        return Err(format!(
            "Selected input changed during working-layer mutation (before {}, after {}).",
            session.input_sha256_before, input_sha256_after
        ));
    }
    let optional_release = |key: &str| {
        values
            .get(key)
            .and_then(|value| normalize_os_release_field(value))
    };
    let system = TargetSystemDiscovery {
        os_id: optional_release("OS_ID"),
        pretty_name: optional_release("OS_PRETTY_NAME"),
        version_id: optional_release("OS_VERSION_ID"),
        build_id: optional_release("OS_BUILD_ID"),
        variant_id: optional_release("OS_VARIANT_ID"),
        architecture: required("TARGET_ARCH")?.to_string(),
        kernel_versions,
    };
    Ok(UserMarkerMutation {
        marker_path: MARKER_PATH.into(),
        marker_content: MARKER_CONTENT.into(),
        target_partition: required("TARGET")?.to_string(),
        target_partition_label: required("PARTITION_LABEL")?.to_string(),
        filesystem: required("FILESYSTEM")?.to_string(),
        input_sha256_before: session.input_sha256_before.clone(),
        input_sha256_after,
        input_unchanged,
        working_read_only: required("WORKING_READ_ONLY")? == "1",
        mounted: required("MOUNTED")? == "1",
        system,
    })
}

pub(crate) fn mutate_user_marker(
    session: &ImageInspectionSession,
) -> Result<UserMarkerMutation, String> {
    preflight_user_marker(session)?;
    mutate_user_marker_after_preflight(session)
}

#[cfg(test)]
pub(crate) fn output_path_for_input(
    input: &Path,
    nvidia_installed: bool,
) -> Result<PathBuf, String> {
    output_path_for_input_label(
        input,
        input.parent(),
        if nvidia_installed { "nvidia" } else { "marker" },
    )
}

#[cfg(test)]
pub(crate) fn output_path_for_nvidia_version(
    input: &Path,
    nvidia_version: &str,
) -> Result<PathBuf, String> {
    let parts: Vec<_> = nvidia_version.split('.').collect();
    if !(2..=3).contains(&parts.len())
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("The resolved NVIDIA version is not safe for an output filename.".into());
    }
    output_path_for_input_label(input, input.parent(), &format!("nvidia-{nvidia_version}"))
}

pub(crate) fn output_path_for_input_in_directory(
    input: &Path,
    output_directory: &Path,
    nvidia_installed: bool,
) -> Result<PathBuf, String> {
    output_path_for_input_label(
        input,
        Some(output_directory),
        if nvidia_installed { "nvidia" } else { "marker" },
    )
}

pub(crate) fn output_path_for_nvidia_version_in_directory(
    input: &Path,
    output_directory: &Path,
    nvidia_version: &str,
) -> Result<PathBuf, String> {
    let parts: Vec<_> = nvidia_version.split('.').collect();
    if !(2..=3).contains(&parts.len())
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("The resolved NVIDIA version is not safe for an output filename.".into());
    }
    output_path_for_input_label(
        input,
        Some(output_directory),
        &format!("nvidia-{nvidia_version}"),
    )
}

fn output_path_for_input_label(
    input: &Path,
    output_directory: Option<&Path>,
    output_label: &str,
) -> Result<PathBuf, String> {
    let parent = output_directory.ok_or("Could not determine the selected image folder.")?;
    let filename = input
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("The selected image filename is not valid UTF-8.")?;
    let mut base = filename.to_string();
    for suffix in [".bz2", ".gz", ".xz", ".img"] {
        if base.to_ascii_lowercase().ends_with(suffix) {
            base.truncate(base.len() - suffix.len());
        }
    }
    if base.is_empty() {
        base = "SteamOS".into();
    }
    loop {
        let lower = base.to_ascii_lowercase();
        let suffix = ["-marker", "-nvidia"]
            .into_iter()
            .find(|suffix| lower.ends_with(suffix));
        if let Some(suffix) = suffix {
            base.truncate(base.len() - suffix.len());
            continue;
        }
        let Some(index) = lower.rfind("-nvidia-") else {
            break;
        };
        let version = &base[index + "-nvidia-".len()..];
        let version_parts: Vec<_> = version.split('.').collect();
        if !(2..=3).contains(&version_parts.len())
            || version_parts
                .iter()
                .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            break;
        }
        base.truncate(index);
    }
    if base.is_empty() {
        base = "SteamOS".into();
    }
    let output_base = format!("{base}-{output_label}");
    for number in 1..=9999_u32 {
        let suffix = if number == 1 {
            String::new()
        } else {
            format!("-{number}")
        };
        let candidate = parent.join(format!("{output_base}{suffix}.img"));
        if !candidate.exists() && !manifest_path_for_output(&candidate).exists() {
            return Ok(candidate);
        }
    }
    Err("Could not choose an unused output filename.".into())
}

pub(crate) fn preflight_host_build_space(
    runtime_dir: &Path,
    output_parent: &Path,
    image_bytes: u64,
) -> Result<(), String> {
    let output_parent = fs::canonicalize(output_parent)
        .map_err(|error| format!("Could not resolve the future output folder: {error}"))?;
    let runtime_required = checked_space_sum([image_bytes, HOST_RUNTIME_FREE_SPACE_RESERVE])?;
    let output_required = checked_space_sum([image_bytes, HOST_OUTPUT_FREE_SPACE_RESERVE])?;
    admit_host_storage(&[
        StorageRequest {
            path: runtime_dir,
            bytes: runtime_required,
            inodes: 12,
            purpose: "the runtime volume (working overlay and temporary build data)",
        },
        StorageRequest {
            path: &output_parent,
            bytes: output_required,
            inodes: 2,
            purpose: "the retained output image and manifest",
        },
    ])
}

pub(crate) fn validate_output_destination(
    input: &Path,
    output: &Path,
    required_bytes: u64,
) -> Result<(), String> {
    if !fs::symlink_metadata(input)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
    {
        return Err("The selected input is no longer a safe regular file.".into());
    }
    let parent = output
        .parent()
        .ok_or("Could not determine the output folder.")?;
    let resolved_parent = fs::canonicalize(parent)
        .map_err(|error| format!("Could not resolve the output folder: {error}"))?;
    if !fs::symlink_metadata(&resolved_parent)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
    {
        return Err("The output folder is not a safe directory.".into());
    }
    let filename = output
        .file_name()
        .ok_or("The output path has no filename.")?;
    let resolved_output = resolved_parent.join(filename);
    let resolved_input = fs::canonicalize(input)
        .map_err(|error| format!("Could not resolve the selected input: {error}"))?;
    if resolved_output == resolved_input {
        return Err("The output path resolves to the selected input image.".into());
    }
    if let Ok(metadata) = fs::symlink_metadata(&resolved_output) {
        #[cfg(unix)]
        if metadata.file_type().is_block_device() || metadata.file_type().is_char_device() {
            return Err("The output path resolves to a device node.".into());
        }
        #[cfg(not(unix))]
        let _ = metadata;
        return Err(format!(
            "The output path already exists: {}",
            resolved_output.display()
        ));
    }
    if required_bytes > 0 {
        admit_host_storage(&[StorageRequest {
            path: &resolved_parent,
            bytes: required_bytes,
            inodes: 2,
            purpose: "the output image export and manifest",
        }])?;
    }
    Ok(())
}

pub(crate) fn manifest_path_for_output(output: &Path) -> PathBuf {
    let mut path = output.as_os_str().to_os_string();
    path.push(".manifest.json");
    PathBuf::from(path)
}

pub(crate) fn write_json_file(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("Could not create build manifest: {e}"))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)
        .map_err(|e| format!("Could not serialize build manifest: {e}"))?;
    writer
        .write_all(b"\n")
        .and_then(|_| writer.flush())
        .and_then(|_| writer.get_ref().sync_all())
        .map_err(|e| format!("Could not finish build manifest: {e}"))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn rename_without_replacement(source: &Path, destination: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
    })?;
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn rename_without_replacement(source: &Path, destination: &Path) -> io::Result<()> {
    fs::hard_link(source, destination)?;
    if let Err(error) = fs::remove_file(source) {
        let rollback = fs::remove_file(destination);
        return Err(match rollback {
            Ok(()) => error,
            Err(rollback_error) => io::Error::other(format!(
                "could not remove source after no-replace publication ({error}); rollback also failed ({rollback_error})"
            )),
        });
    }
    Ok(())
}

pub(crate) fn parse_qemu_img_progress(line: &str) -> Option<f64> {
    let end = line.rfind("/100%)")?;
    let start = line[..end].rfind('(')? + 1;
    line[start..end].trim().parse::<f64>().ok()
}

pub(crate) fn convert_working_image(
    qemu_img: &Path,
    source: &Path,
    destination: &Path,
    virtual_bytes: u64,
    progress: Option<&ProgressCallback<'_>>,
    cancel: Option<&AtomicBool>,
) -> Result<(), String> {
    let mut child = Command::new(qemu_img)
        .args(["convert", "-p", "-f", "qcow2", "-O", "raw"])
        .arg(source)
        .arg(destination)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not start raw-image export: {e}"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or("Could not monitor raw-image export progress.")?;
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut buffer = [0_u8; 1024];
        let mut pending = String::new();
        let mut detail = String::new();
        loop {
            match stderr.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    let chunk = String::from_utf8_lossy(&buffer[..count]);
                    detail.push_str(&chunk);
                    pending.push_str(&chunk);
                    while let Some(index) = pending.find(['\r', '\n']) {
                        let line = pending[..index].to_string();
                        pending.drain(..=index);
                        if let Some(percent) = parse_qemu_img_progress(&line) {
                            let _ = sender.send(percent);
                        }
                    }
                }
                Err(error) => {
                    detail.push_str(&format!("\nCould not read export progress: {error}"));
                    break;
                }
            }
        }
        if let Some(percent) = parse_qemu_img_progress(&pending) {
            let _ = sender.send(percent);
        }
        detail
    });
    let status = loop {
        if cancel.is_some_and(|value| value.load(Ordering::Relaxed)) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err("Image export cancelled.".into());
        }
        while let Ok(percent) = receiver.try_recv() {
            if let Some(progress) = progress {
                let processed = ((percent / 100.0) * virtual_bytes as f64) as u64;
                progress(
                    "exporting-image",
                    processed.min(virtual_bytes),
                    virtual_bytes,
                );
            }
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("Could not inspect raw-image export: {e}"))?
        {
            break status;
        }
        thread::sleep(Duration::from_millis(150));
    };
    let detail = reader
        .join()
        .map_err(|_| "Raw-image export progress worker failed.".to_string())?;
    if !status.success() {
        return Err(storage_process_error(
            &format!("Raw-image export failed with {status}"),
            &detail,
        ));
    }
    if let Some(progress) = progress {
        progress("exporting-image", virtual_bytes, virtual_bytes);
    }
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .open(destination)
        .map_err(|e| storage_io_error("Could not open the exported image", e))?;
    output
        .sync_all()
        .map_err(|e| storage_io_error("Could not flush the exported image", e))
}

pub(crate) fn verify_marker_from_validation_overlay(
    session: &ImageInspectionSession,
) -> Result<(), String> {
    qmp_remove_user_input(session)?;
    const VERIFY_COMMAND: &str = r#"set -eu
SOURCE=/dev/disk/by-id/virtio-steamos-user-input
WORK=/dev/disk/by-id/virtio-steamos-user-working
MOUNT_DIR=/mnt/steamos-export-validation
EXPECTED=$(printf 'SteamOS NVIDIA Image Builder marker\nprotocol=1\nmilestone=marker-only')
for attempt in $(seq 1 150); do
  test ! -b "$SOURCE" && break
  sleep 0.1
done
if test -b "$SOURCE"; then
  echo 'The exported-image source device did not finish detaching within 15 seconds.' >&2
  exit 1
fi
test -b "$WORK"
TARGETS=$(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "rootfs-A" && $3 == "btrfs" { print $1 }')
test "$(printf '%s\n' "$TARGETS" | sed '/^$/d' | wc -l | tr -d ' ')" = 1
TARGET=$(printf '%s\n' "$TARGETS" | sed '/^$/d')
sudo blockdev --setro "$WORK"
sudo mkdir -p "$MOUNT_DIR"
cleanup_validation() {
  findmnt -rn -M "$MOUNT_DIR" >/dev/null 2>&1 && sudo umount "$MOUNT_DIR" || true
}
trap cleanup_validation EXIT
sudo mount -o ro "$TARGET" "$MOUNT_DIR"
test "$(sudo cat "$MOUNT_DIR/etc/steamos-nvidia-image-builder-test")" = "$EXPECTED"
sudo umount "$MOUNT_DIR"
trap - EXIT
test "$(sudo blockdev --getro "$WORK")" = 1
! findmnt -rn -S "$TARGET" >/dev/null 2>&1"#;
    run_guest_command(session, VERIFY_COMMAND).map(|_| ())
}

pub(crate) const NVIDIA_GRUB_VALIDATION_AWK: &str = r#"BEGIN {
  required[1]="rd.driver.blacklist=nouveau"
  required[2]="modprobe.blacklist=nouveau"
  required[3]="nvidia-drm.modeset=1"
  required[4]="nvidia-drm.fbdev=1"
  for (slot=1; slot<=4; slot++) {
    key[slot]=required[slot]
    sub(/=.*/, "", key[slot])
  }
}
/^[[:space:]]*(steamenv_boot[[:space:]]+)?(linux|linuxefi|linux16)[[:space:]]+/ {
  entries++
  delete count
  for (field=1; field<=NF; field++) {
    if ($field ~ /^#/) break
    token_key=$field
    sub(/=.*/, "", token_key)
    for (slot=1; slot<=4; slot++) {
      if (token_key == key[slot]) {
        if ($field != required[slot]) invalid=1
        count[slot]++
      }
    }
  }
  for (slot=1; slot<=4; slot++) if (count[slot] != 1) invalid=1
}
END { if (entries == 0 || invalid) exit 1 }
"#;

pub(crate) fn verify_nvidia_from_validation_overlay(
    session: &ImageInspectionSession,
    installation: &NvidiaInstallHandoffResult,
) -> Result<(), String> {
    let recovery_script_sha256 = format!("{:x}", Sha256::digest(RECOVERY_ROLLBACK_SCRIPT));
    let welcome_sha256 = format!("{:x}", Sha256::digest(INSTALL_MEDIA_WELCOME));
    let welcome_server_sha256 = format!("{:x}", Sha256::digest(INSTALL_MEDIA_WELCOME_SERVER));
    let welcome_helper_sha256 = format!("{:x}", Sha256::digest(INSTALL_MEDIA_HELPER));
    let welcome_desktop_sha256 = format!("{:x}", Sha256::digest(INSTALL_MEDIA_DESKTOP));
    let welcome_icon_sha256 = format!("{:x}", Sha256::digest(INSTALL_MEDIA_ICON));
    let welcome_gtk_css_sha256 = format!("{:x}", Sha256::digest(INSTALL_MEDIA_GTK_CSS));
    let mut welcome_asset_assertions = String::new();
    for (path, bytes) in [
        ("index.html", INSTALL_MEDIA_WELCOME_HTML),
        ("app.css", INSTALL_MEDIA_WELCOME_CSS),
        ("app.js", INSTALL_MEDIA_WELCOME_JS),
        ("opemos.svg", INSTALL_MEDIA_ICON),
        ("assets/install.svg", INSTALL_MEDIA_WELCOME_INSTALL_ART),
        ("assets/recovery.svg", INSTALL_MEDIA_WELCOME_RECOVERY_ART),
        ("assets/gaming.svg", INSTALL_MEDIA_WELCOME_GAMING_ART),
    ] {
        let sha256 = format!("{:x}", Sha256::digest(bytes));
        welcome_asset_assertions.push_str(&format!(
            "test -f \"$ROOT/usr/share/opemos-install-media/ui/welcome/{path}\"\n\
             test ! -L \"$ROOT/usr/share/opemos-install-media/ui/welcome/{path}\"\n\
             test \"$(sha256sum \"$ROOT/usr/share/opemos-install-media/ui/welcome/{path}\" | awk '{{print $1}}')\" = \"{sha256}\"\n\
             test \"$(stat -c '%a:%u:%g' \"$ROOT/usr/share/opemos-install-media/ui/welcome/{path}\")\" = 644:0:0\n",
        ));
    }
    let mut install_media_support_assertions = String::new();
    validate_installer_file_records(&installation.support_files)?;
    for file in &installation.support_files {
        let mode = if file.executable { "755" } else { "644" };
        install_media_support_assertions.push_str(&format!(
            "test -f \"$ROOT/usr/lib/opemos-install-media/support/{path}\"\n\
             test ! -L \"$ROOT/usr/lib/opemos-install-media/support/{path}\"\n\
             test \"$(sha256sum \"$ROOT/usr/lib/opemos-install-media/support/{path}\" | awk '{{print $1}}')\" = \"{sha256}\"\n\
             test \"$(stat -c '%a:%u:%g' \"$ROOT/usr/lib/opemos-install-media/support/{path}\")\" = {mode}:0:0\n",
            path = file.path,
            sha256 = file.sha256,
        ));
    }
    let mut package_assertions = String::new();
    for package in &installation.packages {
        if arch_dependency_name(&package.name)? != package.name
            || package.full_version.is_empty()
            || package.full_version.len() > 256
            || !package
                .full_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"@._+~:-".contains(&byte))
        {
            return Err("Installed package manifest contains an unsafe identity.".into());
        }
        package_assertions.push_str(&format!(
            "test \"$(package_versions '{}')\" = '{}'\n",
            package.name, package.full_version
        ));
    }
    let receipt_assertions = payload_receipt_overlay_assertions(
        installation
            .payload_receipt
            .as_ref()
            .ok_or("Installed NVIDIA result omitted its rootfs payload receipt.")?,
    )?;
    let command = format!(
        r#"set -euo pipefail
WORK=/dev/disk/by-id/virtio-steamos-user-working
ROOT=/mnt/steamos-nvidia-export-root
test -b "$WORK"
test "$(sudo blockdev --getro "$WORK")" = 1
mapfile -t ROOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "rootfs-A" && $3 == "btrfs" {{print $1}}')
mapfile -t BOOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "efi-A" && ($3 == "vfat" || $3 == "fat") {{print $1}}')
mapfile -t VAR_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "var-A" && $3 == "ext4" {{print $1}}')
mapfile -t HOME_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "home" && $3 == "ext4" {{print $1}}')
test "${{#ROOT_PARTS[@]}}" -eq 1
test "${{#BOOT_PARTS[@]}}" -eq 1
test "${{#VAR_PARTS[@]}}" -eq 1
test "${{#HOME_PARTS[@]}}" -eq 1
test "${{ROOT_PARTS[0]}}" != "${{BOOT_PARTS[0]}}"
test "${{ROOT_PARTS[0]}}" != "${{VAR_PARTS[0]}}"
test "${{BOOT_PARTS[0]}}" != "${{VAR_PARTS[0]}}"
test "${{HOME_PARTS[0]}}" != "${{ROOT_PARTS[0]}}"
test "${{HOME_PARTS[0]}}" != "${{BOOT_PARTS[0]}}"
test "${{HOME_PARTS[0]}}" != "${{VAR_PARTS[0]}}"
sudo mkdir -p "$ROOT"
ROOT_MOUNTED=0
VAR_MOUNTED=0
EFI_MOUNTED=0
HOME_MOUNTED=0
cleanup() {{
  rc=$?
  trap - EXIT INT TERM
  if (( EFI_MOUNTED )); then sudo umount "$ROOT/efi" || rc=1; fi
  if (( VAR_MOUNTED )); then sudo umount "$ROOT/var" || rc=1; fi
  if (( HOME_MOUNTED )); then sudo umount "$ROOT/home" || rc=1; fi
  if (( ROOT_MOUNTED )); then sudo umount "$ROOT" || rc=1; fi
  ! findmnt -rn -M "$ROOT/efi" >/dev/null 2>&1 || rc=1
  ! findmnt -rn -M "$ROOT/var" >/dev/null 2>&1 || rc=1
  ! findmnt -rn -M "$ROOT/home" >/dev/null 2>&1 || rc=1
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
test -d "$ROOT/home"
test ! -L "$ROOT/home"
sudo mount -o ro "${{HOME_PARTS[0]}}" "$ROOT/home"
HOME_MOUNTED=1
sudo mount -o ro "${{VAR_PARTS[0]}}" "$ROOT/var"
VAR_MOUNTED=1
sudo mount -o ro "${{BOOT_PARTS[0]}}" "$ROOT/efi"
EFI_MOUNTED=1
MODULE_ROOT="$ROOT/usr/lib/modules/{}/updates/open-gpu-kernel-modules-steamos"
for MODULE in nvidia nvidia-drm nvidia-modeset nvidia-peermem nvidia-uvm; do
  test -f "$MODULE_ROOT/$MODULE.ko.zst"
  test ! -L "$MODULE_ROOT/$MODULE.ko.zst"
  test "$(sudo modinfo -F version "$MODULE_ROOT/$MODULE.ko.zst")" = "{}"
  test "$(sudo modinfo -F vermagic "$MODULE_ROOT/$MODULE.ko.zst" | awk '{{print $1}}')" = "{}"
done
grep -qx 'blacklist nouveau' "$ROOT/etc/modprobe.d/99-open-gpu-kernel-modules-steamos.conf"
grep -qx 'options nvidia-drm modeset=1 fbdev=1' "$ROOT/etc/modprobe.d/99-open-gpu-kernel-modules-steamos.conf"
grep -qx 'MODULES=(nvidia nvidia_modeset nvidia_uvm nvidia_drm)' "$ROOT/etc/mkinitcpio.conf.d/90-open-gpu-kernel-modules-steamos.conf"
GRUB="$ROOT/efi/EFI/steamos/grub.cfg"
test -f "$GRUB"
test ! -L "$GRUB"
awk '{}' "$GRUB"
STATE="$ROOT/var/lib/open-gpu-kernel-modules-steamos-support/offline-install"
test "$(cat "$STATE/kernel-version")" = "{}"
test "$(cat "$STATE/nvidia-version")" = "{}"
test -f "$STATE/PROVENANCE.json"
test ! -L "$STATE/PROVENANCE.json"
test "$(sha256sum "$STATE/PROVENANCE.json" | awk '{{print $1}}')" = "{}"
test -f "$STATE/BUILD-INFO.txt"
test ! -L "$STATE/BUILD-INFO.txt"
find "$ROOT/usr/lib/firmware/nvidia/{}" -type f -name 'gsp*.bin' -print -quit | grep -q .
PACMAN_DATABASE="$ROOT{}"
test -d "$PACMAN_DATABASE"
test ! -L "$PACMAN_DATABASE"
test -d "$PACMAN_DATABASE/local"
test ! -L "$PACMAN_DATABASE/local"
package_versions() {{
  wanted="$1"
  find "$PACMAN_DATABASE/local" -mindepth 2 -maxdepth 2 -type f -name desc -exec \
    awk -v wanted="$wanted" '
      $0 == "%NAME%" {{ getline; name=$0 }}
      $0 == "%VERSION%" {{ getline; version=$0 }}
      END {{ if (name == wanted) print version }}
    ' {{}} \;
}}
{}
find "$ROOT/boot" -maxdepth 1 -type f -name 'initramfs*.img' -size +0c -print -quit | grep -q .
DECK_ID=$(awk -F: '$1 == "deck" {{print $3 ":" $4}}' "$ROOT/etc/passwd")
test -n "$DECK_ID"
test "$(printf '%s\n' "$DECK_ID" | wc -l | tr -d ' ')" = 1
test -f "$ROOT/home/deck/tools/opemos-rollback-last-update"
test ! -L "$ROOT/home/deck/tools/opemos-rollback-last-update"
test "$(sha256sum "$ROOT/home/deck/tools/opemos-rollback-last-update" | awk '{{print $1}}')" = "{}"
test "$(stat -c '%a' "$ROOT/home/deck/tools/opemos-rollback-last-update")" = 755
test "$(stat -c '%u:%g' "$ROOT/home/deck/tools/opemos-rollback-last-update")" = "$DECK_ID"
test ! -e "$ROOT/home/deck/Desktop/OPEMOS-Rollback.desktop"
test -f "$ROOT/home/deck/tools/open-opemos-welcome"
test ! -L "$ROOT/home/deck/tools/open-opemos-welcome"
test "$(sha256sum "$ROOT/home/deck/tools/open-opemos-welcome" | awk '{{print $1}}')" = "{}"
test "$(stat -c '%a' "$ROOT/home/deck/tools/open-opemos-welcome")" = 755
test "$(stat -c '%u:%g' "$ROOT/home/deck/tools/open-opemos-welcome")" = "$DECK_ID"
for DESKTOP in "$ROOT/home/deck/Desktop/Open-OPEMOS.desktop" "$ROOT/home/deck/.config/autostart/Open-OPEMOS.desktop"; do
  test -f "$DESKTOP"
  test ! -L "$DESKTOP"
  test "$(sha256sum "$DESKTOP" | awk '{{print $1}}')" = "{}"
  test "$(stat -c '%u:%g' "$DESKTOP")" = "$DECK_ID"
done
test "$(stat -c '%a' "$ROOT/home/deck/Desktop/Open-OPEMOS.desktop")" = 755
test "$(stat -c '%a' "$ROOT/home/deck/.config/autostart/Open-OPEMOS.desktop")" = 644
test -f "$ROOT/home/deck/.local/share/icons/hicolor/scalable/apps/opemos.svg"
test ! -L "$ROOT/home/deck/.local/share/icons/hicolor/scalable/apps/opemos.svg"
test "$(sha256sum "$ROOT/home/deck/.local/share/icons/hicolor/scalable/apps/opemos.svg" | awk '{{print $1}}')" = "{}"
test "$(stat -c '%a' "$ROOT/home/deck/.local/share/icons/hicolor/scalable/apps/opemos.svg")" = 644
test "$(stat -c '%u:%g' "$ROOT/home/deck/.local/share/icons/hicolor/scalable/apps/opemos.svg")" = "$DECK_ID"
test -f "$ROOT/usr/lib/opemos-install-media/opemos-install-helper"
test ! -L "$ROOT/usr/lib/opemos-install-media/opemos-install-helper"
test "$(sha256sum "$ROOT/usr/lib/opemos-install-media/opemos-install-helper" | awk '{{print $1}}')" = "{}"
test "$(stat -c '%a:%u:%g' "$ROOT/usr/lib/opemos-install-media/opemos-install-helper")" = 755:0:0
test -f "$ROOT/usr/lib/opemos-install-media/welcome_server.py"
test ! -L "$ROOT/usr/lib/opemos-install-media/welcome_server.py"
test "$(sha256sum "$ROOT/usr/lib/opemos-install-media/welcome_server.py" | awk '{{print $1}}')" = "{}"
test "$(stat -c '%a:%u:%g' "$ROOT/usr/lib/opemos-install-media/welcome_server.py")" = 755:0:0
test -f "$ROOT/usr/lib/opemos-install-media/repair_device.sh"
test ! -L "$ROOT/usr/lib/opemos-install-media/repair_device.sh"
test "$(stat -c '%a:%u:%g' "$ROOT/usr/lib/opemos-install-media/repair_device.sh")" = 755:0:0
grep -Fqx 'DISK="${{STEAMOS_TARGET_DISK:?Open OPEMOS requires an explicit target disk}}"' "$ROOT/usr/lib/opemos-install-media/repair_device.sh"
grep -Fq 'OPEMOS_SKIP_JUPITER_FIRMWARE' "$ROOT/usr/lib/opemos-install-media/repair_device.sh"
grep -Fq 'OPEMOS_NO_REBOOT' "$ROOT/usr/lib/opemos-install-media/repair_device.sh"
grep -Fq 'OPEMOS_FAIL_FAST' "$ROOT/usr/lib/opemos-install-media/repair_device.sh"
test "$(cat "$ROOT/usr/lib/opemos-install-media/support-revision")" = "{}"
test "$(cat "$ROOT/usr/lib/opemos-install-media/nvidia-version")" = "{}"
test "$(stat -c '%a:%u:%g' "$ROOT/usr/lib/opemos-install-media/support-revision")" = 644:0:0
test "$(stat -c '%a:%u:%g' "$ROOT/usr/lib/opemos-install-media/nvidia-version")" = 644:0:0
for DIRECTORY in "$ROOT/usr/share" "$ROOT/usr/share/opemos-install-media" "$ROOT/usr/share/opemos-install-media/ui" "$ROOT/usr/share/opemos-install-media/ui/gtk-3.0" "$ROOT/usr/share/opemos-install-media/ui/welcome" "$ROOT/usr/share/opemos-install-media/ui/welcome/assets"; do
  test -d "$DIRECTORY"
  test ! -L "$DIRECTORY"
done
test -f "$ROOT/usr/share/opemos-install-media/ui/gtk-3.0/gtk.css"
test ! -L "$ROOT/usr/share/opemos-install-media/ui/gtk-3.0/gtk.css"
test "$(sha256sum "$ROOT/usr/share/opemos-install-media/ui/gtk-3.0/gtk.css" | awk '{{print $1}}')" = "{}"
test "$(stat -c '%a:%u:%g' "$ROOT/usr/share/opemos-install-media/ui/gtk-3.0/gtk.css")" = 644:0:0
{}
{}
{}
sudo umount "$ROOT/efi"
EFI_MOUNTED=0
sudo umount "$ROOT/var"
VAR_MOUNTED=0
sudo umount "$ROOT/home"
HOME_MOUNTED=0
sudo umount "$ROOT"
ROOT_MOUNTED=0
! findmnt -rn -M "$ROOT/efi" >/dev/null 2>&1
! findmnt -rn -M "$ROOT/var" >/dev/null 2>&1
! findmnt -rn -M "$ROOT/home" >/dev/null 2>&1
! findmnt -rn -M "$ROOT" >/dev/null 2>&1
trap - EXIT INT TERM"#,
        installation.kernel_version,
        installation.nvidia_version,
        installation.kernel_version,
        NVIDIA_GRUB_VALIDATION_AWK,
        installation.kernel_version,
        installation.nvidia_version,
        installation.provenance_sha256,
        installation.nvidia_version,
        installation.pacman_database_path,
        package_assertions,
        recovery_script_sha256,
        welcome_sha256,
        welcome_desktop_sha256,
        welcome_icon_sha256,
        welcome_helper_sha256,
        welcome_server_sha256,
        installation.support_commit,
        installation.nvidia_version,
        welcome_gtk_css_sha256,
        welcome_asset_assertions,
        install_media_support_assertions,
        receipt_assertions,
    );
    run_guest_command(session, &command).map(|_| ())
}

pub(crate) fn payload_receipt_overlay_assertions(
    receipt: &SupportPayloadReceipt,
) -> Result<String, String> {
    validate_support_payload_receipt_record(receipt)?;
    let expected_manifest = serde_json::to_string(&serde_json::json!({
        "schemaVersion": 1,
        "status": "verified",
        "reason": "payload_receipt_committed",
        "target": receipt.target,
        "records": receipt.records,
        "receiptId": receipt.receipt_id,
    }))
    .map_err(|error| format!("Could not serialize expected payload receipt: {error}"))?;
    if expected_manifest.contains('\'') {
        return Err("Payload-receipt identity is unsafe for read-only guest validation.".into());
    }
    let mut assertions = format!(
        "RECEIPT_SUPPORT=\"$ROOT/usr/lib/open-gpu-kernel-modules-steamos-support\"\n\
         RECEIPT_ROOT=\"$RECEIPT_SUPPORT/offline-install\"\n\
         test -d \"$RECEIPT_SUPPORT\"\n\
         test ! -L \"$RECEIPT_SUPPORT\"\n\
         test -d \"$RECEIPT_ROOT\"\n\
         test ! -L \"$RECEIPT_ROOT\"\n\
         test \"$(find \"$RECEIPT_ROOT\" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')\" = 7\n\
         test -f \"$RECEIPT_ROOT/receipt.json\"\n\
         test ! -L \"$RECEIPT_ROOT/receipt.json\"\n\
         test \"$(stat -c '%s' \"$RECEIPT_ROOT/receipt.json\")\" -gt 0\n\
         test \"$(stat -c '%s' \"$RECEIPT_ROOT/receipt.json\")\" -le 65536\n\
         test \"$(stat -c '%a:%u:%g' \"$RECEIPT_ROOT/receipt.json\")\" = 644:0:0\n\
         python3 -c 'import json,sys\n\
unique=lambda pairs: dict(pairs) if len(pairs)==len({{key for key,value in pairs}}) else (_ for _ in ()).throw(ValueError(\"duplicate JSON key\"))\n\
actual=json.load(open(sys.argv[1],encoding=\"utf-8\"),object_pairs_hook=unique,parse_constant=lambda value: 1/0)\n\
expected=json.loads(sys.argv[2])\n\
assert isinstance(actual,dict)\n\
assert all(actual.get(key)==value for key,value in expected.items())' \"$RECEIPT_ROOT/receipt.json\" '{expected_manifest}'\n",
    );
    for record in &receipt.records {
        assertions.push_str(&format!(
            "test -f \"$RECEIPT_ROOT/{filename}\"\n\
             test ! -L \"$RECEIPT_ROOT/{filename}\"\n\
             test \"$(stat -c '%s' \"$RECEIPT_ROOT/{filename}\")\" = {size}\n\
             test \"$(sha256sum \"$RECEIPT_ROOT/{filename}\" | awk '{{print $1}}')\" = {sha256}\n\
             test \"$(stat -c '%a:%u:%g' \"$RECEIPT_ROOT/{filename}\")\" = 644:0:0\n",
            filename = record.filename,
            size = record.size_bytes,
            sha256 = record.sha256,
        ));
    }
    Ok(assertions)
}

pub(crate) fn wait_for_ready(
    session: &mut ApplianceSession,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let deadline = Instant::now() + BOOT_TIMEOUT;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("Image export cancelled.".into());
        }
        if let Some(status) = session
            .child
            .try_wait()
            .map_err(|e| format!("Could not inspect validation appliance: {e}"))?
        {
            return Err(format!(
                "Validation appliance exited unexpectedly with {status}."
            ));
        }
        if handshake(session).ok().as_deref() == Some(READY_MARKER) {
            session.state = "ready".into();
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("Validation appliance did not become ready within 120 seconds.".into());
        }
        thread::sleep(Duration::from_millis(750));
    }
}

pub(crate) fn export_marker_image_blocking(
    app: tauri::AppHandle,
    _reveal_in_finder: bool,
) -> Result<ExportedImage, String> {
    let manager_state = app.state::<Mutex<ApplianceManager>>();
    let (mut session, cancel) = {
        let mut manager = manager_state
            .lock()
            .map_err(|_| "Appliance state lock is unavailable.")?;
        if manager.preparing {
            return Err("Another image operation is already running.".into());
        }
        let session = manager
            .session
            .take()
            .ok_or("Builder appliance is not running.")?;
        if !matches!(
            session.state.as_str(),
            "ready" | "handoff-validated" | "nvidia-installed"
        ) {
            manager.session = Some(session);
            return Err("Builder appliance is not ready for image export.".into());
        }
        manager.cancel_preparation.store(false, Ordering::Relaxed);
        manager.preparing = true;
        (session, manager.cancel_preparation.clone())
    };
    let report_progress = |stage: &str, processed_bytes: u64, total_bytes: u64| {
        let _ = app.emit_to(
            "build-progress",
            "input-progress",
            InputProgress {
                stage: stage.into(),
                processed_bytes,
                total_bytes,
            },
        );
    };
    let result = (|| {
        if cancel.load(Ordering::Relaxed) {
            return Err("Image export cancelled.".into());
        }
        if session.target_system.is_none() {
            return Err("Target SteamOS metadata was not recorded before export.".into());
        }
        if session.state == "ready" {
            run_guest_command(
                &ImageInspectionSession::from(&session),
                "set -eu; sync; WORK=/dev/disk/by-id/virtio-steamos-user-working; test \"$(sudo blockdev --getro \"$WORK\")\" = 1; ! findmnt -rn -S \"$WORK\" >/dev/null 2>&1",
            )?;
            stop_session_process(&mut session)?;
        } else if session
            .child
            .try_wait()
            .map_err(|e| format!("Could not inspect the handed-off appliance: {e}"))?
            .is_none()
        {
            return Err("The native appliance is unexpectedly still running after handoff.".into());
        }
        let nvidia_installation = session.nvidia_installation.clone();
        if session.state == "nvidia-installed" && nvidia_installation.is_none() {
            return Err("NVIDIA-installed state omitted its structured result.".into());
        }
        let final_path = match nvidia_installation.as_ref() {
            Some(installation) => output_path_for_nvidia_version_in_directory(
                &session.input_image,
                &session.output_directory,
                &installation.nvidia_version,
            )?,
            None => output_path_for_input_in_directory(
                &session.input_image,
                &session.output_directory,
                false,
            )?,
        };
        let required_output_bytes = session
            .input_preparation
            .image_bytes
            .checked_add(64 * 1024 * 1024)
            .ok_or("Host output-space requirement overflowed.")?;
        validate_output_destination(&session.input_image, &final_path, required_output_bytes)?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("System clock error: {e}"))?
            .as_nanos();
        let partial_name = format!(
            ".{}.partial-{}-{timestamp}",
            final_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("steamos-marker.img"),
            std::process::id()
        );
        let partial_path = final_path
            .parent()
            .ok_or("Could not determine the output folder.")?
            .join(partial_name);
        let mut partial_guard = PartialOutputGuard {
            path: partial_path.clone(),
            armed: true,
        };
        let qemu_img = find_binary("qemu-img").ok_or("qemu-img is required for image export.")?;
        convert_working_image(
            &qemu_img,
            &session.working_image,
            &partial_path,
            session.input_preparation.image_bytes,
            Some(&report_progress),
            Some(&cancel),
        )?;
        let exported_bytes = fs::metadata(&partial_path)
            .map_err(|e| format!("Could not inspect the exported image: {e}"))?
            .len();
        if exported_bytes != session.input_preparation.image_bytes {
            return Err(format!(
                "Exported image size mismatch: expected {}, received {exported_bytes}.",
                session.input_preparation.image_bytes
            ));
        }
        stop_session(&mut session)?;

        let validation_progress = |stage: &str, processed: u64, total: u64| {
            let mapped = match stage {
                "hashing-source" | "verifying-source-after" => "hashing-output",
                other => other,
            };
            report_progress(mapped, processed, total);
        };
        report_progress("starting-output-validation", 0, 1);
        let mut validation = prepare_session(
            Some(&partial_path),
            Some(&validation_progress),
            Some(&cancel),
            false,
        )?;
        wait_for_ready(&mut validation, &cancel)?;
        let validation_snapshot = ImageInspectionSession::from(&validation);
        let inspection = inspect_user_image(
            &validation_snapshot,
            Some(&validation_progress),
            Some(&cancel),
        )?;
        if !inspection.layout.recognized {
            return Err(format!(
                "Exported image no longer matches the supported Valve layout: {}",
                inspection.layout.issues.join(" ")
            ));
        }
        if inspection.disk_bytes != exported_bytes || !inspection.read_only {
            return Err("Exported image failed independent size/read-only validation.".into());
        }
        verify_marker_from_validation_overlay(&validation_snapshot)?;
        if let Some(installation) = &nvidia_installation {
            verify_nvidia_from_validation_overlay(&validation_snapshot, installation)?;
        }
        let output_sha256 = inspection.source_sha256_after.clone();
        if output_sha256 == session.attached_sha256_before {
            return Err("Exported image hash matches the unmodified source; marker changes were not preserved.".into());
        }
        stop_session(&mut validation)?;

        let source_sha256 = sha256_file_with_progress(
            &session.input_image,
            "verifying-source-after-export",
            Some(&report_progress),
            Some(&cancel),
        )?;
        if source_sha256 != session.input_sha256_before {
            return Err(format!(
                "Original input changed during export (before {}, after {source_sha256}).",
                session.input_sha256_before
            ));
        }
        validate_output_destination(&session.input_image, &final_path, 0)?;
        let final_manifest_path = manifest_path_for_output(&final_path);
        if final_manifest_path.exists() {
            return Err(format!(
                "The chosen manifest path appeared during export: {}",
                final_manifest_path.display()
            ));
        }
        let partial_manifest_path = manifest_path_for_output(&partial_path);
        let runtime_provenance = collect_build_runtime_provenance(
            nvidia_installation.is_some(),
            Some(&report_progress),
            Some(&cancel),
        )?;
        let manifest = marker_build_manifest(MarkerManifestData {
            input: &session.input_image,
            output: &final_path,
            input_preparation: &session.input_preparation,
            input_sha256: &source_sha256,
            normalized_sha256: &session.attached_sha256_before,
            output_bytes: exported_bytes,
            output_sha256: &output_sha256,
            layout: &inspection.layout,
            target_system: session
                .target_system
                .as_ref()
                .ok_or("Target SteamOS metadata is unavailable for the manifest.")?,
            nvidia_installation: nvidia_installation.as_ref(),
            nvidia_resolution: session.nvidia_resolution.as_ref(),
            nvidia_source_selection: session.nvidia_source_selection.as_deref(),
            runtime: &runtime_provenance,
        });
        let mut manifest_guard = PartialOutputGuard {
            path: partial_manifest_path.clone(),
            armed: true,
        };
        write_json_file(&partial_manifest_path, &manifest)?;
        rename_without_replacement(&partial_path, &final_path)
            .map_err(|e| format!("Could not finalize the exported image: {e}"))?;
        if let Err(error) = rename_without_replacement(&partial_manifest_path, &final_manifest_path)
        {
            let rollback = rename_without_replacement(&final_path, &partial_path);
            return Err(if let Err(rollback_error) = rollback {
                format!(
                    "Could not finalize the build manifest ({error}); the image also could not be returned to its temporary name ({rollback_error})."
                )
            } else {
                format!("Could not finalize the build manifest: {error}")
            });
        }
        partial_guard.armed = false;
        manifest_guard.armed = false;
        #[cfg(target_os = "macos")]
        if _reveal_in_finder {
            let _ = Command::new("open").arg("-R").arg(&final_path).spawn();
        }
        Ok(ExportedImage {
            path: final_path.to_string_lossy().into_owned(),
            manifest_path: final_manifest_path.to_string_lossy().into_owned(),
            bytes: exported_bytes,
            sha256: output_sha256,
            source_sha256,
            layout_scheme: inspection.layout.scheme.unwrap_or_default(),
            marker_path: "/etc/steamos-nvidia-image-builder-test".into(),
        })
    })();
    if let Ok(mut manager) = manager_state.lock() {
        manager.preparing = false;
    }
    result
}

#[tauri::command]
pub(crate) async fn export_marker_image(
    app: tauri::AppHandle,
    reveal_in_finder: Option<bool>,
) -> Result<ExportedImage, String> {
    tauri::async_runtime::spawn_blocking(move || {
        export_marker_image_blocking(app, reveal_in_finder.unwrap_or(true))
    })
    .await
    .map_err(|error| format!("Image export worker failed: {error}"))?
}

#[tauri::command]
pub(crate) fn reveal_completed_image(path: String) -> Result<(), String> {
    let output = fs::canonicalize(&path)
        .map_err(|error| format!("Could not resolve the completed image: {error}"))?;
    let metadata = fs::metadata(&output)
        .map_err(|error| format!("Could not inspect the completed image: {error}"))?;
    if !metadata.is_file() || output.extension().and_then(|value| value.to_str()) != Some("img") {
        return Err("Only a completed raw image can be revealed.".into());
    }
    let manifest_bytes = fs::read(manifest_path_for_output(&output))
        .map_err(|error| format!("Could not read the completed-image manifest: {error}"))?;
    if manifest_bytes.len() > 1024 * 1024 {
        return Err("The completed-image manifest is unexpectedly large.".into());
    }
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("Could not parse the completed-image manifest: {error}"))?;
    let filename = output.file_name().and_then(|value| value.to_str());
    if manifest
        .pointer("/validation/passed")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
        || manifest
            .pointer("/output/filename")
            .and_then(serde_json::Value::as_str)
            != filename
        || manifest
            .pointer("/output/bytes")
            .and_then(serde_json::Value::as_u64)
            != Some(metadata.len())
    {
        return Err("The image is not bound to a successful matching build manifest.".into());
    }

    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg("-R").arg(&output);
        command
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("explorer.exe");
        command.arg(format!("/select,{}", output.display()));
        command
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(
            output
                .parent()
                .ok_or("Completed output has no parent folder.")?,
        );
        command
    };

    command
        .spawn()
        .map_err(|error| format!("Could not reveal the completed image: {error}"))?;
    Ok(())
}

#[tauri::command]
pub(crate) fn validate_image(path: String) -> Result<ImageInfo, String> {
    let path = PathBuf::from(path);
    if !path.is_file() {
        return Err("The selected path is not a file.".into());
    }
    if !supported_image(&path) {
        return Err(
            "Select a SteamOS recovery image (.img, .img.bz2, .img.gz, or .img.xz).".into(),
        );
    }
    let canonical = fs::canonicalize(&path)
        .map_err(|error| format!("Could not resolve the selected image: {error}"))?;
    let name = canonical
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("Invalid image name")?
        .to_string();
    Ok(ImageInfo {
        path: canonical.to_string_lossy().into_owned(),
        name,
    })
}

#[tauri::command]
pub(crate) fn preview_image_output(
    path: String,
    output_directory: Option<String>,
) -> Result<ImageOutputPreview, String> {
    let path = PathBuf::from(path);
    if !path.is_file() {
        return Err("The selected path is not a file.".into());
    }
    if !supported_image(&path) {
        return Err(
            "Select a SteamOS recovery image (.img, .img.bz2, .img.gz, or .img.xz).".into(),
        );
    }
    let canonical = fs::canonicalize(&path)
        .map_err(|error| format!("Could not resolve the selected image: {error}"))?;
    let output_directory = match output_directory {
        Some(directory) => {
            let directory = fs::canonicalize(directory)
                .map_err(|error| format!("Could not resolve the output folder: {error}"))?;
            if !directory.is_dir() {
                return Err("The output folder is not a safe directory.".into());
            }
            directory
        }
        None => canonical
            .parent()
            .ok_or("Could not determine the selected image folder.")?
            .to_path_buf(),
    };
    let output = output_path_for_input_in_directory(&canonical, &output_directory, true)?;
    Ok(ImageOutputPreview {
        input_path: canonical.to_string_lossy().into_owned(),
        output_path: output.to_string_lossy().into_owned(),
    })
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn usb_candidate_from_diskutil_info(
    info: &serde_json::Value,
    image_bytes: u64,
    expected_identifier: Option<&str>,
) -> Option<UsbTargetCandidate> {
    let object = info.as_object()?;
    let identifier = object.get("DeviceIdentifier")?.as_str()?;
    if expected_identifier.is_some_and(|expected| expected != identifier) {
        return None;
    }
    if !identifier.starts_with("disk")
        || identifier.len() <= 4
        || !identifier[4..].bytes().all(|byte| byte.is_ascii_digit())
        || object.get("WholeDisk").and_then(|value| value.as_bool()) != Some(true)
        || object.get("Internal").and_then(|value| value.as_bool()) != Some(false)
        || object.get("Writable").and_then(|value| value.as_bool()) != Some(true)
        || object
            .get("VirtualOrPhysical")
            .and_then(|value| value.as_str())
            != Some("Physical")
    {
        return None;
    }
    let removable = object
        .get("RemovableMedia")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let ejectable = object
        .get("Ejectable")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if !removable && !ejectable {
        return None;
    }
    let bytes = object.get("TotalSize")?.as_u64()?;
    if bytes < image_bytes || bytes > 2 * 1024 * 1024 * 1024 * 1024 {
        return None;
    }
    let device_node = object.get("DeviceNode")?.as_str()?;
    if device_node != format!("/dev/{identifier}") {
        return None;
    }
    let media_name: String = object
        .get("MediaName")
        .and_then(|value| value.as_str())
        .unwrap_or("External removable media")
        .chars()
        .take(120)
        .collect();
    let bus_protocol: String = object
        .get("BusProtocol")
        .and_then(|value| value.as_str())
        .unwrap_or("Unknown")
        .chars()
        .take(40)
        .collect();
    let device_tree_path = object
        .get("DeviceTreePath")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())?;
    let block_size = object.get("DeviceBlockSize")?.as_u64()?;
    if !matches!(block_size, 512 | 1024 | 2048 | 4096) || !image_bytes.is_multiple_of(block_size) {
        return None;
    }
    let identity = format!(
        "{identifier}\0{device_node}\0{bytes}\0{block_size}\0{media_name}\0{bus_protocol}\0{device_tree_path}"
    );
    Some(UsbTargetCandidate {
        device_identifier: identifier.into(),
        device_node: device_node.into(),
        media_name,
        bus_protocol,
        bytes,
        block_size,
        identity_token: format!("{:x}", Sha256::digest(identity.as_bytes())),
    })
}

pub(crate) const USB_PREFLIGHT_TTL: Duration = Duration::from_secs(60);
#[cfg(target_os = "macos")]
pub(crate) fn physical_usb_writes_allowed() -> bool {
    validate_system_authopen().is_ok()
}
#[cfg(target_os = "windows")]
pub(crate) fn physical_usb_writes_allowed() -> bool {
    true
}
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(crate) fn physical_usb_writes_allowed() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn usb_write_permission_message() -> &'static str {
    "macOS will request permission for only the selected raw device when writing begins."
}

#[cfg(target_os = "windows")]
fn usb_write_permission_message() -> &'static str {
    "Windows will request administrator approval for only this exact revalidated USB write."
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn usb_write_permission_message() -> &'static str {
    "Physical writing is not available on this platform yet."
}
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const USB_HELPER_PROTOCOL: &str = "org.steamos-nvidia-builder.usb-writer/1";

#[cfg_attr(not(test), allow(dead_code))]
fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decode_usb_helper_exchange(
    request_json: &[u8],
    attestation_json: &[u8],
    event_jsonl: &[u8],
) -> Result<
    (
        UsbHelperWriteRequest,
        UsbHelperAttestation,
        Vec<UsbHelperEvent>,
    ),
    String,
> {
    const MAX_DOCUMENT_BYTES: usize = 32 * 1024;
    const MAX_EVENT_STREAM_BYTES: usize = 8 * 1024 * 1024;
    const MAX_EVENT_LINE_BYTES: usize = 4 * 1024;
    if request_json.is_empty()
        || attestation_json.is_empty()
        || request_json.len() > MAX_DOCUMENT_BYTES
        || attestation_json.len() > MAX_DOCUMENT_BYTES
        || event_jsonl.is_empty()
        || event_jsonl.len() > MAX_EVENT_STREAM_BYTES
    {
        return Err("The USB helper protocol payload is empty or oversized.".into());
    }
    let request = serde_json::from_slice(request_json)
        .map_err(|_| "The USB helper request document is malformed.".to_string())?;
    let attestation = serde_json::from_slice(attestation_json)
        .map_err(|_| "The USB helper attestation document is malformed.".to_string())?;
    let mut events = Vec::new();
    for line in event_jsonl.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_EVENT_LINE_BYTES {
            return Err("The USB helper emitted an oversized event record.".into());
        }
        events.push(
            serde_json::from_slice(line)
                .map_err(|_| "The USB helper emitted a malformed event record.".to_string())?,
        );
    }
    Ok((request, attestation, events))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_usb_helper_exchange(
    request: &UsbHelperWriteRequest,
    attestation: &UsbHelperAttestation,
    events: &[UsbHelperEvent],
    policy: &UsbHelperTrustPolicy<'_>,
    now_unix_ms: u64,
) -> Result<(), String> {
    const MAX_EVENTS: usize = 16_384;
    const MAX_MESSAGE_BYTES: usize = 512;
    if request.schema_version != 1 || attestation.schema_version != 1 {
        return Err("The USB helper schema version is unsupported.".into());
    }
    if request.protocol != USB_HELPER_PROTOCOL || attestation.protocol != USB_HELPER_PROTOCOL {
        return Err("The USB helper protocol identity is invalid.".into());
    }
    if request.request_id.len() != 64
        || !valid_sha256(&request.request_id)
        || !valid_usb_preflight_session_token(&request.intent_token)
        || !valid_sha256(&request.image_sha256)
        || !valid_sha256(&request.device_identity_token)
    {
        return Err("The USB helper request contains an invalid identity token.".into());
    }
    if request.expires_at_unix_ms <= now_unix_ms
        || request.expires_at_unix_ms.saturating_sub(now_unix_ms)
            > USB_PREFLIGHT_TTL.as_millis() as u64
    {
        return Err("The USB helper intent is expired or exceeds the allowed lifetime.".into());
    }
    if request.image_bytes == 0 || request.device_capacity_bytes < request.image_bytes {
        return Err("The USB helper image/device size boundary is invalid.".into());
    }
    let image = Path::new(&request.image_path);
    let canonical = Path::new(&request.canonical_device_node);
    let raw = Path::new(&request.raw_device_node);
    if !image.is_absolute()
        || !canonical.is_absolute()
        || !raw.is_absolute()
        || request.image_path.len() > 4096
        || request.canonical_device_node.len() > 1024
        || request.raw_device_node.len() > 1024
        || request.image_path.contains("/../")
        || request.canonical_device_node.contains("/../")
        || request.raw_device_node.contains("/../")
        || request.device_identifier.is_empty()
        || request.device_identifier.len() > 128
        || canonical.file_name().and_then(|value| value.to_str())
            != Some(request.device_identifier.as_str())
        || raw
            .file_name()
            .and_then(|value| value.to_str())
            .is_none_or(|value| {
                value != request.device_identifier
                    && value != format!("r{}", request.device_identifier)
            })
    {
        return Err("The USB helper device paths are not canonical absolute paths.".into());
    }
    if !attestation.independently_authenticated
        || !attestation.independently_authorized
        || attestation.process_id == 0
        || attestation.effective_user_id != 0
        || !attestation
            .executable_sha256
            .eq_ignore_ascii_case(policy.executable_sha256)
        || attestation.signing_identity != policy.signing_identity
        || attestation.helper_version != policy.helper_version
    {
        return Err("The USB helper is not independently authenticated and authorized.".into());
    }
    if events.is_empty() || events.len() > MAX_EVENTS {
        return Err("The USB helper event stream is missing or oversized.".into());
    }
    let required = ["unmount", "open", "write", "fsync", "readback", "cleanup"];
    let mut seen = std::collections::HashSet::new();
    let mut terminal = false;
    let mut last_phase_rank = 0_u8;
    let mut last_progress = std::collections::HashMap::new();
    for (index, event) in events.iter().enumerate() {
        if event.schema_version != 1
            || event.protocol != USB_HELPER_PROTOCOL
            || event.request_id != request.request_id
            || event.sequence as usize != index
            || event.bytes_total != request.image_bytes
            || event.bytes_completed > event.bytes_total
            || event.image_sha256 != request.image_sha256
            || event.device_identity_token != request.device_identity_token
            || event.message.len() > MAX_MESSAGE_BYTES
        {
            return Err("The USB helper event stream drifted from the authorized request.".into());
        }
        if terminal {
            return Err("The USB helper emitted events after its terminal outcome.".into());
        }
        if !matches!(
            event.phase.as_str(),
            "unmount" | "open" | "write" | "fsync" | "readback" | "cancel" | "cleanup"
        ) || !matches!(
            event.outcome.as_str(),
            "started" | "progress" | "succeeded" | "failed" | "cancelled"
        ) {
            return Err("The USB helper emitted an unknown phase or outcome.".into());
        }
        let phase_rank = match event.phase.as_str() {
            "unmount" => 1,
            "open" => 2,
            "write" => 3,
            "fsync" => 4,
            "readback" => 5,
            "cancel" => 6,
            "cleanup" => 7,
            _ => unreachable!(),
        };
        if phase_rank < last_phase_rank
            || last_progress
                .insert(event.phase.as_str(), event.bytes_completed)
                .is_some_and(|previous| event.bytes_completed < previous)
        {
            return Err("The USB helper phase or progress sequence moved backward.".into());
        }
        last_phase_rank = phase_rank;
        if event.outcome == "succeeded" {
            seen.insert(event.phase.as_str());
        }
        terminal = event.phase == "cleanup"
            && matches!(event.outcome.as_str(), "succeeded" | "failed" | "cancelled");
    }
    if !terminal {
        return Err("The USB helper event stream ended without cleanup.".into());
    }
    let cancelled_or_failed = events
        .iter()
        .any(|event| matches!(event.outcome.as_str(), "cancelled" | "failed"));
    if !cancelled_or_failed && required.iter().any(|phase| !seen.contains(phase)) {
        return Err("The USB helper reported success without every required outcome.".into());
    }
    let last = events.last().expect("nonempty event stream");
    if !cancelled_or_failed
        && (last.outcome != "succeeded" || last.bytes_completed != request.image_bytes)
    {
        return Err("The USB helper did not prove complete cleanup after verification.".into());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) const WINDOWS_VIRTUAL_USB_BYTES: u64 = 32 * 1024 * 1024 * 1024;

#[cfg(target_os = "windows")]
mod windows_virtual_usb {
    use super::WINDOWS_VIRTUAL_USB_BYTES;
    use std::{
        ffi::c_void,
        fs::{self, File, OpenOptions},
        os::windows::io::AsRawHandle,
        path::{Path, PathBuf},
        ptr,
    };

    const FSCTL_SET_SPARSE: u32 = 0x0009_00c4;
    const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;

    #[repr(C)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: [u32; 2],
        last_access_time: [u32; 2],
        last_write_time: [u32; 2],
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn DeviceIoControl(
            device: *mut c_void,
            control_code: u32,
            input: *mut c_void,
            input_bytes: u32,
            output: *mut c_void,
            output_bytes: u32,
            returned_bytes: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn GetFileInformationByHandle(
            file: *mut c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }
    fn exact_owned_path(root: &Path, target: &Path) -> Result<PathBuf, String> {
        let root = fs::canonicalize(root)
            .map_err(|error| format!("Could not canonicalize the virtual-USB root: {error}"))?;
        if target.parent() != Some(root.as_path())
            || target.file_name().and_then(|name| name.to_str()) != Some("virtual-usb-32g.raw")
        {
            return Err("The virtual USB path escaped its harness-owned root.".into());
        }
        Ok(target.to_path_buf())
    }

    fn mark_sparse(file: &File) -> Result<(), String> {
        let mut returned = 0_u32;
        let result = unsafe {
            DeviceIoControl(
                file.as_raw_handle().cast(),
                FSCTL_SET_SPARSE,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if result == 0 {
            return Err(format!(
                "Could not mark the harness-owned virtual USB sparse: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub(crate) fn is_sparse(file: &File) -> Result<bool, String> {
        let mut information = std::mem::MaybeUninit::<ByHandleFileInformation>::zeroed();
        let result = unsafe {
            GetFileInformationByHandle(file.as_raw_handle().cast(), information.as_mut_ptr())
        };
        if result == 0 {
            return Err(format!(
                "Could not inspect the harness-owned virtual USB: {}",
                std::io::Error::last_os_error()
            ));
        }
        let information = unsafe { information.assume_init() };
        Ok(information.file_attributes & FILE_ATTRIBUTE_SPARSE_FILE != 0)
    }

    pub(crate) fn create(root: &Path, target: &Path) -> Result<File, String> {
        let target = exact_owned_path(root, target)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|error| format!("Could not create the harness-owned virtual USB: {error}"))?;
        if let Err(error) = mark_sparse(&file).and_then(|()| {
            file.set_len(WINDOWS_VIRTUAL_USB_BYTES)
                .map_err(|error| format!("Could not size the harness-owned virtual USB: {error}"))
        }) {
            drop(file);
            let _ = fs::remove_file(&target);
            return Err(error);
        }
        if file.metadata().map_err(|error| error.to_string())?.len() != WINDOWS_VIRTUAL_USB_BYTES
            || !is_sparse(&file)?
        {
            drop(file);
            let _ = fs::remove_file(&target);
            return Err("The harness-owned virtual USB is not an exact sparse 32 GiB file.".into());
        }
        Ok(file)
    }

    pub(crate) fn cleanup(root: &Path, target: &Path) -> Result<(), String> {
        let target = exact_owned_path(root, target)?;
        let metadata = fs::symlink_metadata(&target)
            .map_err(|error| format!("Could not inspect the virtual USB for cleanup: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != WINDOWS_VIRTUAL_USB_BYTES
        {
            return Err("Refusing to clean a drifted virtual-USB target.".into());
        }
        fs::remove_file(target)
            .map_err(|error| format!("Could not clean the harness-owned virtual USB: {error}"))
    }
}

#[cfg(target_os = "windows")]
pub(crate) use windows_virtual_usb::{
    cleanup as cleanup_windows_virtual_usb, create as create_windows_virtual_usb,
    is_sparse as windows_virtual_usb_is_sparse,
};

#[derive(Clone)]
struct ArmedUsbPreflight {
    session_token: String,
    expires_at: Instant,
    device_identifier: String,
    image_sha256: String,
    identity_token: String,
}

#[derive(Default)]
pub(crate) struct UsbPreparationManager {
    generation: u64,
    armed: Option<ArmedUsbPreflight>,
    active_token: Option<String>,
    cancel_write: Option<Arc<AtomicBool>>,
}

impl UsbPreparationManager {
    pub(crate) fn cancel_all(&mut self) {
        self.armed = None;
        if let Some(cancel) = self.cancel_write.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        self.active_token = None;
    }

    pub(crate) fn arm(
        &mut self,
        session_token: String,
        device_identifier: String,
        image_sha256: String,
        identity_token: String,
        now: Instant,
    ) {
        self.generation = self.generation.wrapping_add(1).max(1);
        self.armed = Some(ArmedUsbPreflight {
            session_token,
            expires_at: now + USB_PREFLIGHT_TTL,
            device_identifier,
            image_sha256,
            identity_token,
        });
    }

    pub(crate) fn cancel(&mut self, session_token: &str, now: Instant) -> bool {
        if self
            .armed
            .as_ref()
            .is_some_and(|armed| now >= armed.expires_at)
        {
            self.armed = None;
        }
        let mut cancelled = self
            .armed
            .as_ref()
            .is_some_and(|armed| session_token == armed.session_token);
        if cancelled {
            self.armed = None;
        }
        if self.active_token.as_deref() == Some(session_token) {
            if let Some(cancel) = &self.cancel_write {
                cancel.store(true, Ordering::Relaxed);
            }
            cancelled = true;
        }
        cancelled
    }

    fn is_writing(&self, session_token: &str) -> bool {
        self.active_token.as_deref() == Some(session_token)
    }

    fn armed(&mut self, session_token: &str, now: Instant) -> Option<ArmedUsbPreflight> {
        if self
            .armed
            .as_ref()
            .is_some_and(|armed| now >= armed.expires_at)
        {
            self.armed = None;
        }
        self.armed
            .as_ref()
            .filter(|armed| armed.session_token == session_token)
            .cloned()
    }

    fn begin_write(&mut self, session_token: &str, now: Instant) -> Option<Arc<AtomicBool>> {
        self.armed(session_token, now)?;
        if self.active_token.is_some() {
            return None;
        }
        self.armed = None;
        let cancel = Arc::new(AtomicBool::new(false));
        self.active_token = Some(session_token.into());
        self.cancel_write = Some(cancel.clone());
        Some(cancel)
    }

    fn finish_write(&mut self, session_token: &str) {
        if self.active_token.as_deref() == Some(session_token) {
            self.active_token = None;
            self.cancel_write = None;
        }
    }

    pub(crate) fn status(&mut self, session_token: &str, now: Instant) -> UsbWritePreflightStatus {
        if self.active_token.as_deref() == Some(session_token) {
            return UsbWritePreflightStatus {
                status: "writing".into(),
                active: true,
                expires_in_ms: 0,
                writes_allowed: false,
                device_identifier: None,
                image_sha256: None,
                identity_token: None,
                message: "A USB writer operation is active.".into(),
            };
        }
        if let Some(armed) = self.armed.as_ref() {
            if now >= armed.expires_at {
                let matching_token = session_token == armed.session_token;
                let identity = matching_token.then(|| {
                    (
                        armed.device_identifier.clone(),
                        armed.image_sha256.clone(),
                        armed.identity_token.clone(),
                    )
                });
                self.armed = None;
                return UsbWritePreflightStatus {
                    status: if matching_token { "expired" } else { "stale-token" }.into(),
                    active: false,
                    expires_in_ms: 0,
                    writes_allowed: false,
                    device_identifier: identity.as_ref().map(|value| value.0.clone()),
                    image_sha256: identity.as_ref().map(|value| value.1.clone()),
                    identity_token: identity.map(|value| value.2),
                    message: if matching_token {
                        "The USB intent session expired. Revalidate the image and target before confirming again."
                    } else {
                        "This USB intent token does not identify the active session."
                    }
                    .into(),
                };
            }
            if session_token != armed.session_token {
                return UsbWritePreflightStatus {
                    status: "stale-token".into(),
                    active: false,
                    expires_in_ms: 0,
                    writes_allowed: false,
                    device_identifier: None,
                    image_sha256: None,
                    identity_token: None,
                    message: "This USB intent token does not identify the active session.".into(),
                };
            }
            return UsbWritePreflightStatus {
                status: "armed".into(),
                active: true,
                expires_in_ms: armed.expires_at.duration_since(now).as_millis(),
                writes_allowed: physical_usb_writes_allowed(),
                device_identifier: Some(armed.device_identifier.clone()),
                image_sha256: Some(armed.image_sha256.clone()),
                identity_token: Some(armed.identity_token.clone()),
                message: if physical_usb_writes_allowed() {
                    usb_write_permission_message()
                } else if cfg!(target_os = "windows") {
                    "The confirmed USB intent session is active, but OPEMOS must be restarted as administrator before Windows can open the disk."
                } else {
                    "The confirmed USB intent session is active. Physical writing is not available on this platform yet."
                }
                .into(),
            };
        }
        UsbWritePreflightStatus {
            status: "not-armed".into(),
            active: false,
            expires_in_ms: 0,
            writes_allowed: false,
            device_identifier: None,
            image_sha256: None,
            identity_token: None,
            message: "No USB intent session is active.".into(),
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    pub(crate) fn is_armed(&self) -> bool {
        self.armed.is_some()
    }

    #[cfg(test)]
    pub(crate) fn begin_write_for_test(
        &mut self,
        session_token: &str,
        now: Instant,
    ) -> Option<Arc<AtomicBool>> {
        self.begin_write(session_token, now)
    }
}

impl Drop for UsbPreparationManager {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

pub(crate) trait UsbWriteMedia: Read + Write + Seek {
    fn durable_flush(&mut self) -> std::io::Result<()>;
}

impl UsbWriteMedia for File {
    fn durable_flush(&mut self) -> std::io::Result<()> {
        self.sync_all()
    }
}

pub(crate) fn copy_and_verify_usb_image(
    image: &Path,
    target: &mut impl UsbWriteMedia,
    image_bytes: u64,
    expected_sha256: &str,
    cancel: &AtomicBool,
    mut progress: impl FnMut(UsbWriteProgress),
) -> Result<String, String> {
    const BUFFER_BYTES: usize = 4 * 1024 * 1024;
    let mut input = BufReader::with_capacity(
        BUFFER_BYTES,
        File::open(image)
            .map_err(|error| format!("Could not open the completed image: {error}"))?,
    );
    target
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("Could not seek the selected USB device: {error}"))?;
    let mut buffer = vec![0_u8; BUFFER_BYTES];
    let mut written = 0_u64;
    progress(UsbWriteProgress {
        phase: "writing".into(),
        bytes_completed: 0,
        bytes_total: image_bytes,
        message: "Writing the validated image to USB.".into(),
    });
    while written < image_bytes {
        if cancel.load(Ordering::Relaxed) {
            return Err("USB writing was cancelled. The partially written device is not bootable and must be rewritten.".into());
        }
        let remaining = image_bytes - written;
        let requested = usize::try_from(remaining.min(BUFFER_BYTES as u64))
            .map_err(|_| "USB write size overflowed.")?;
        input
            .read_exact(&mut buffer[..requested])
            .map_err(|error| format!("Could not read the completed image: {error}"))?;
        target
            .write_all(&buffer[..requested])
            .map_err(|error| format!("Could not write the selected USB device: {error}"))?;
        written = written
            .checked_add(requested as u64)
            .ok_or("USB write progress overflowed.")?;
        progress(UsbWriteProgress {
            phase: "writing".into(),
            bytes_completed: written,
            bytes_total: image_bytes,
            message: "Writing the validated image to USB.".into(),
        });
    }
    progress(UsbWriteProgress {
        phase: "flushing".into(),
        bytes_completed: image_bytes,
        bytes_total: image_bytes,
        message: "Durably flushing the selected USB device before readback.".into(),
    });
    if let Err(error) = target.durable_flush() {
        #[cfg(target_os = "macos")]
        if error.raw_os_error() == Some(25) {
            let status = Command::new("/bin/sync").status().map_err(|sync_error| {
                format!("Could not flush the selected USB device: {sync_error}")
            })?;
            if !status.success() {
                return Err("macOS could not flush the selected USB device.".into());
            }
        } else {
            return Err(format!("Could not flush the selected USB device: {error}"));
        }
        #[cfg(not(target_os = "macos"))]
        return Err(format!("Could not flush the selected USB device: {error}"));
    }
    target
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("Could not rewind the selected USB device: {error}"))?;
    let mut verified = 0_u64;
    let mut hasher = Sha256::new();
    while verified < image_bytes {
        if cancel.load(Ordering::Relaxed) {
            return Err(
                "USB verification was cancelled. The device write was not accepted as verified."
                    .into(),
            );
        }
        let remaining = image_bytes - verified;
        let requested = usize::try_from(remaining.min(BUFFER_BYTES as u64))
            .map_err(|_| "USB verification size overflowed.")?;
        target
            .read_exact(&mut buffer[..requested])
            .map_err(|error| format!("Could not verify the selected USB device: {error}"))?;
        hasher.update(&buffer[..requested]);
        verified = verified
            .checked_add(requested as u64)
            .ok_or("USB verification progress overflowed.")?;
        progress(UsbWriteProgress {
            phase: "verifying".into(),
            bytes_completed: verified,
            bytes_total: image_bytes,
            message: "Reading the USB device back and verifying SHA-256.".into(),
        });
    }
    let actual = format!("{:x}", hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected_sha256) {
        return Err(
            "USB verification failed: the bytes read back do not match the built image.".into(),
        );
    }
    Ok(actual)
}

pub(crate) fn valid_usb_preflight_session_token(session_token: &str) -> bool {
    session_token.len() == 64 && session_token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(target_os = "macos")]
pub(crate) const DISKUTIL_EXTERNAL_PHYSICAL_LIST_ARGS: [&str; 4] =
    ["list", "-plist", "external", "physical"];

#[cfg(target_os = "macos")]
fn plist_command_json(
    mut command: Command,
    description: &str,
) -> Result<serde_json::Value, String> {
    let plist = command
        .output()
        .map_err(|error| format!("Could not {description}: {error}"))?;
    if !plist.status.success() {
        let detail: String = String::from_utf8_lossy(&plist.stderr)
            .trim()
            .chars()
            .take(512)
            .collect();
        return Err(format!(
            "Could not {description}; diskutil exited with {}{}.",
            plist.status,
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        ));
    }
    if plist.stdout.len() > 4 * 1024 * 1024 {
        return Err(format!(
            "Could not {description}; diskutil returned more than 4 MiB of metadata."
        ));
    }
    let mut child = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", "--", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("Could not start the property-list parser: {error}"))?;
    child
        .stdin
        .take()
        .ok_or("Could not open the property-list parser input.")?
        .write_all(&plist.stdout)
        .map_err(|error| format!("Could not provide disk metadata to the parser: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("Could not read parsed disk metadata: {error}"))?;
    if !output.status.success() || output.stdout.len() > 4 * 1024 * 1024 {
        return Err("macOS returned malformed disk metadata.".into());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Could not decode disk metadata: {error}"))
}

#[cfg(target_os = "macos")]
fn discover_usb_targets(image_bytes: u64) -> Result<Vec<UsbTargetCandidate>, String> {
    let mut list_command = Command::new("/usr/sbin/diskutil");
    list_command.args(DISKUTIL_EXTERNAL_PHYSICAL_LIST_ARGS);
    let list = plist_command_json(list_command, "list external physical disks")?;
    let identifiers = list
        .get("WholeDisks")
        .and_then(|value| value.as_array())
        .ok_or("macOS did not return a whole-disk list.")?;
    if identifiers.len() > 64 {
        return Err("macOS returned too many external disks to inspect safely.".into());
    }
    let mut targets = Vec::new();
    for identifier in identifiers {
        let Some(identifier) = identifier.as_str() else {
            continue;
        };
        if !identifier.starts_with("disk")
            || identifier.len() <= 4
            || !identifier[4..].bytes().all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let mut info_command = Command::new("/usr/sbin/diskutil");
        info_command.args(["info", "-plist", identifier]);
        let info = plist_command_json(info_command, "inspect an external disk")?;
        if let Some(target) = usb_candidate_from_diskutil_info(&info, image_bytes, Some(identifier))
        {
            targets.push(target);
        }
    }
    targets.sort_by(|left, right| left.device_identifier.cmp(&right.device_identifier));
    Ok(targets)
}

#[cfg(target_os = "macos")]
fn revalidate_usb_target(identifier: &str, image_bytes: u64) -> Result<UsbTargetCandidate, String> {
    if !identifier.starts_with("disk")
        || identifier.len() <= 4
        || !identifier[4..].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("The selected device identifier is invalid.".into());
    }
    let mut info_command = Command::new("/usr/sbin/diskutil");
    info_command.args(["info", "-plist", identifier]);
    let info = plist_command_json(info_command, "revalidate the selected external disk")?;
    usb_candidate_from_diskutil_info(&info, image_bytes, Some(identifier)).ok_or_else(|| {
        "The selected disk is no longer the same eligible whole removable device.".into()
    })
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn usb_candidates_from_windows_json(
    bytes: &[u8],
    image_bytes: u64,
) -> Result<Vec<UsbTargetCandidate>, String> {
    usb_candidates_from_windows_json_state(bytes, image_bytes, false)
}

#[cfg(any(target_os = "windows", test))]
fn usb_candidates_from_windows_json_state(
    bytes: &[u8],
    image_bytes: u64,
    require_offline: bool,
) -> Result<Vec<UsbTargetCandidate>, String> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("Windows returned more than 4 MiB of disk metadata.".into());
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("Windows returned malformed disk metadata: {error}"))?;
    let disks = match value {
        serde_json::Value::Array(v) => v,
        serde_json::Value::Object(_) => vec![value],
        serde_json::Value::Null => Vec::new(),
        _ => return Err("Windows returned an invalid disk inventory.".into()),
    };
    if disks.len() > 64 {
        return Err("Windows returned too many disks to inspect safely.".into());
    }
    let mut targets = Vec::new();
    for disk in disks {
        let Some(object) = disk.as_object() else {
            continue;
        };
        if !object
            .get("BusType")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .eq_ignore_ascii_case("USB")
        {
            continue;
        }
        let Some(index) = object.get("Index").and_then(|v| v.as_u64()) else {
            continue;
        };
        if index > 1024 {
            continue;
        }
        if object.get("IsBoot").and_then(|v| v.as_bool()) != Some(false)
            || object.get("IsSystem").and_then(|v| v.as_bool()) != Some(false)
            || object.get("IsReadOnly").and_then(|v| v.as_bool()) != Some(false)
            || object.get("IsOffline").and_then(|v| v.as_bool()) != Some(require_offline)
        {
            continue;
        }
        if object.get("MediaType").and_then(|v| v.as_str()) != Some("Removable Media") {
            continue;
        }
        let Some(bytes) = object.get("Size").and_then(|v| v.as_u64()) else {
            continue;
        };
        if bytes < image_bytes || bytes > 2 * 1024 * 1024 * 1024 * 1024 {
            continue;
        }
        let Some(block_size) = object.get("BytesPerSector").and_then(|v| v.as_u64()) else {
            continue;
        };
        if !matches!(block_size, 512 | 1024 | 2048 | 4096)
            || !image_bytes.is_multiple_of(block_size)
        {
            continue;
        }
        let device_node = format!(r"\\.\PHYSICALDRIVE{index}");
        let Some(unique_id) = object
            .get("UniqueId")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
        else {
            continue;
        };
        let Some(serial_number) = object
            .get("SerialNumber")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            continue;
        };
        let media_name: String = object
            .get("FriendlyName")
            .and_then(|v| v.as_str())
            .unwrap_or("USB removable media")
            .chars()
            .take(120)
            .collect();
        let identity = format!(
            "{index}\0{device_node}\0{bytes}\0{block_size}\0{media_name}\0{unique_id}\0{serial_number}"
        );
        let stable_identity = format!("{unique_id}\0{serial_number}");
        targets.push((
            UsbTargetCandidate {
                device_identifier: format!("PhysicalDrive{index}"),
                device_node,
                media_name,
                bus_protocol: "USB".into(),
                bytes,
                block_size,
                identity_token: format!("{:x}", Sha256::digest(identity.as_bytes())),
            },
            stable_identity,
        ));
    }
    let mut counts = std::collections::HashMap::new();
    for (_, stable_identity) in &targets {
        *counts.entry(stable_identity.clone()).or_insert(0_usize) += 1;
    }
    let mut targets: Vec<_> = targets
        .into_iter()
        .filter_map(|(target, stable_identity)| {
            (counts.get(&stable_identity) == Some(&1)).then_some(target)
        })
        .collect();
    targets.sort_by(|a, b| a.device_identifier.cmp(&b.device_identifier));
    Ok(targets)
}

#[cfg(target_os = "windows")]
fn discover_usb_targets(image_bytes: u64) -> Result<Vec<UsbTargetCandidate>, String> {
    let script = "Get-Disk | ForEach-Object { $d=$_; $w=Get-CimInstance Win32_DiskDrive -Filter ('Index='+$d.Number) -ErrorAction Stop; [pscustomobject]@{Index=$d.Number;FriendlyName=$d.FriendlyName;BusType=[string]$d.BusType;Size=[uint64]$d.Size;BytesPerSector=[uint64]$d.LogicalSectorSize;UniqueId=[string]$d.UniqueId;SerialNumber=[string]$w.SerialNumber;MediaType=[string]$w.MediaType;IsBoot=[bool]$d.IsBoot;IsSystem=[bool]$d.IsSystem;IsReadOnly=[bool]$d.IsReadOnly;IsOffline=[bool]$d.IsOffline} } | ConvertTo-Json -Compress";
    let output = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .output()
        .map_err(|error| format!("Could not start Windows removable-drive inspection: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(500)
            .collect::<String>();
        return Err(format!(
            "Windows removable-drive inspection failed{}.",
            if detail.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", detail.trim())
            }
        ));
    }
    usb_candidates_from_windows_json(&output.stdout, image_bytes)
}

#[cfg(any(target_os = "windows", test))]
fn windows_disk_number(identifier: &str) -> Result<u32, String> {
    let value = identifier
        .strip_prefix("PhysicalDrive")
        .ok_or("The selected Windows device identifier is invalid.")?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("The selected Windows device identifier is invalid.".into());
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|number| *number <= 1024)
        .ok_or_else(|| "The selected Windows device identifier is invalid.".into())
}

#[cfg(target_os = "windows")]
fn windows_powershell(script: &str, description: &str) -> Result<Vec<u8>, String> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .output()
        .map_err(|error| format!("Could not {description}: {error}"))?;
    if !output.status.success() {
        let detail: String = String::from_utf8_lossy(&output.stderr)
            .trim()
            .chars()
            .take(500)
            .collect();
        return Err(format!(
            "Could not {description}{}.",
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        ));
    }
    Ok(output.stdout)
}

#[cfg(target_os = "windows")]
fn windows_process_is_elevated() -> bool {
    let script = "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }";
    Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "windows")]
fn windows_disk_inventory(number: u32) -> Result<Vec<u8>, String> {
    windows_powershell(
        &format!("$d=Get-Disk -Number {number} -ErrorAction Stop; $w=Get-CimInstance Win32_DiskDrive -Filter ('Index='+$d.Number) -ErrorAction Stop; [pscustomobject]@{{Index=$d.Number;FriendlyName=$d.FriendlyName;BusType=[string]$d.BusType;Size=[uint64]$d.Size;BytesPerSector=[uint64]$d.LogicalSectorSize;UniqueId=[string]$d.UniqueId;SerialNumber=[string]$w.SerialNumber;MediaType=[string]$w.MediaType;IsBoot=[bool]$d.IsBoot;IsSystem=[bool]$d.IsSystem;IsReadOnly=[bool]$d.IsReadOnly;IsOffline=[bool]$d.IsOffline}} | ConvertTo-Json -Compress"),
        "revalidate the selected Windows removable disk",
    )
}

#[cfg(target_os = "windows")]
fn revalidate_usb_target(identifier: &str, image_bytes: u64) -> Result<UsbTargetCandidate, String> {
    revalidate_windows_usb_target_state(identifier, image_bytes, false)
}

#[cfg(target_os = "windows")]
fn revalidate_windows_usb_target_state(
    identifier: &str,
    image_bytes: u64,
    require_offline: bool,
) -> Result<UsbTargetCandidate, String> {
    let number = windows_disk_number(identifier)?;
    let targets = usb_candidates_from_windows_json_state(
        &windows_disk_inventory(number)?,
        image_bytes,
        require_offline,
    )?;
    if targets.len() != 1 || targets[0].device_identifier != identifier {
        return Err(
            "The selected disk is no longer the same eligible whole removable device.".into(),
        );
    }
    Ok(targets
        .into_iter()
        .next()
        .expect("one guarded Windows target"))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn discover_usb_targets(_image_bytes: u64) -> Result<Vec<UsbTargetCandidate>, String> {
    Err(
        "Read-only USB target discovery is currently implemented only for macOS and Windows."
            .into(),
    )
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn revalidate_usb_target(
    _identifier: &str,
    _image_bytes: u64,
) -> Result<UsbTargetCandidate, String> {
    Err("Read-only USB target revalidation is currently implemented only for macOS.".into())
}

pub(crate) fn validate_usb_image_identity(
    image_path: &str,
) -> Result<(PathBuf, u64, String), String> {
    let (image, image_bytes, image_sha256, _) = validated_usb_image_manifest(image_path)?;
    Ok((image, image_bytes, image_sha256))
}

fn validated_usb_image_manifest(
    image_path: &str,
) -> Result<(PathBuf, u64, String, serde_json::Value), String> {
    let (image, image_bytes, declared_sha256, manifest) =
        inspect_usb_image_manifest_identity(image_path)?;
    let actual_sha256 = sha256_file(&image)?;
    if !actual_sha256.eq_ignore_ascii_case(&declared_sha256) {
        return Err("The completed image changed after its build manifest was written.".into());
    }
    Ok((image, image_bytes, actual_sha256, manifest))
}

pub(crate) fn inspect_usb_image_manifest_identity(
    image_path: &str,
) -> Result<(PathBuf, u64, String, serde_json::Value), String> {
    let image = fs::canonicalize(image_path)
        .map_err(|error| format!("Could not resolve the completed image: {error}"))?;
    if image.extension().and_then(|value| value.to_str()) != Some("img") {
        return Err("USB preparation requires a raw .img output.".into());
    }
    let metadata = fs::metadata(&image)
        .map_err(|error| format!("Could not inspect the completed image: {error}"))?;
    if !metadata.is_file() {
        return Err("The completed image is not a regular file.".into());
    }
    if metadata.len() == 0 || metadata.len() % 512 != 0 {
        return Err(
            "USB preparation requires a non-empty raw image aligned to 512-byte sectors.".into(),
        );
    }
    let manifest_path = manifest_path_for_output(&image);
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("Could not read the adjacent build manifest: {error}"))?;
    if manifest_bytes.len() > 1024 * 1024 {
        return Err("The adjacent build manifest is unexpectedly large.".into());
    }
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("Could not parse the adjacent build manifest: {error}"))?;
    let output = manifest
        .get("output")
        .and_then(|value| value.as_object())
        .ok_or("The adjacent build manifest has no output identity.")?;
    let filename = image
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let declared_bytes = output.get("bytes").and_then(|value| value.as_u64());
    let sha256 = output
        .get("sha256")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if output.get("filename").and_then(|value| value.as_str()) != Some(filename)
        || output.get("format").and_then(|value| value.as_str()) != Some("raw")
        || declared_bytes != Some(metadata.len())
        || sha256.len() != 64
        || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(
            "The image and adjacent build manifest do not have a valid matching output identity."
                .into(),
        );
    }
    Ok((image, metadata.len(), sha256.to_ascii_lowercase(), manifest))
}

pub(crate) fn completed_nvidia_image_from_path(
    image_path: &str,
) -> Result<Option<CompletedNvidiaImage>, String> {
    let canonical = fs::canonicalize(image_path)
        .map_err(|error| format!("Could not resolve the selected image: {error}"))?;
    let manifest_path = manifest_path_for_output(&canonical);
    if !manifest_path.exists() {
        return Ok(None);
    }
    let (image, bytes, sha256, manifest) = validated_usb_image_manifest(image_path)?;
    let validation = manifest
        .get("validation")
        .and_then(serde_json::Value::as_object)
        .ok_or("The adjacent build manifest has no validation record.")?;
    for field in [
        "passed",
        "sourceUnchanged",
        "candidateAttachedReadOnly",
        "layoutRecognized",
        "markerVerified",
        "nvidiaPayloadVerified",
        "installationMediaWelcomeVerified",
        "installedRecoveryGuardianPayloadVerified",
    ] {
        if validation.get(field).and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(format!(
                "The adjacent build manifest does not confirm {field}."
            ));
        }
    }
    if validation
        .get("installationMediaWelcomeRevision")
        .and_then(serde_json::Value::as_str)
        != Some(install_media_welcome_revision().as_str())
    {
        return Err("The completed image predates the current installation-media application. Rebuild it from the original Valve recovery image.".into());
    }
    let integration = manifest
        .get("integration")
        .and_then(serde_json::Value::as_object)
        .ok_or("The adjacent build manifest has no integration record.")?;
    let nvidia = integration
        .get("nvidia")
        .and_then(serde_json::Value::as_object)
        .ok_or("The adjacent build manifest has no NVIDIA installation result.")?;
    if manifest
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || manifest
            .get("resultClass")
            .and_then(serde_json::Value::as_str)
            != Some("nvidia-mutation-valid")
        || integration
            .get("milestone")
            .and_then(serde_json::Value::as_str)
            != Some("nvidia-offline-installed")
        || nvidia.get("status").and_then(serde_json::Value::as_str) != Some("success")
        || nvidia.get("phase").and_then(serde_json::Value::as_str) != Some("complete")
        || nvidia.get("reason").and_then(serde_json::Value::as_str) != Some("install_complete")
        || nvidia
            .get("mountsReleased")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || nvidia
            .get("compressionPolicyRestored")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err(
            "The adjacent build manifest is not a completed NVIDIA mutation result.".into(),
        );
    }
    let source_sha256 = manifest
        .pointer("/input/sourceSha256")
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("The adjacent build manifest has an invalid source-image identity.")?;
    let layout_scheme = manifest
        .pointer("/steamos/layoutScheme")
        .and_then(serde_json::Value::as_str)
        .filter(|value| *value == "valve-recovery-a")
        .ok_or("The adjacent build manifest has an unsupported SteamOS layout identity.")?;
    let required_identity = |pointer: &str, description: &str| {
        manifest
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("The adjacent build manifest has no valid {description}."))
    };
    let nvidia_version = required_identity("/integration/nvidia/nvidiaVersion", "NVIDIA version")?;
    let kernel_version = required_identity("/integration/nvidia/kernelVersion", "kernel version")?;
    let steamos_version =
        required_identity("/integration/nvidia/steamosVersion", "SteamOS version")?;
    let trust = required_identity("/integration/nvidia/trust", "NVIDIA trust classification")?;
    let source_selection = required_identity(
        "/integration/nvidiaSourcePolicy/selection",
        "NVIDIA source selection",
    )?;
    let source_mode = required_identity(
        "/integration/nvidiaSourcePolicy/mode",
        "NVIDIA source policy mode",
    )?;
    Ok(Some(CompletedNvidiaImage {
        output: ExportedImage {
            path: image.to_string_lossy().into_owned(),
            manifest_path: manifest_path.to_string_lossy().into_owned(),
            bytes,
            sha256,
            source_sha256: source_sha256.to_ascii_lowercase(),
            layout_scheme: layout_scheme.into(),
            marker_path: "/etc/steamos-nvidia-image-builder-test".into(),
        },
        nvidia_version,
        kernel_version,
        steamos_version,
        trust,
        source_selection,
        source_mode,
    }))
}

#[tauri::command]
pub(crate) async fn inspect_completed_nvidia_image(
    path: String,
    requested_nvidia_version: Option<String>,
) -> Result<Option<CompletedNvidiaImage>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let completed = completed_nvidia_image_from_path(&path)?;
        validate_completed_nvidia_version(&completed, requested_nvidia_version.as_deref())?;
        Ok(completed)
    })
    .await
    .map_err(|error| format!("Completed-image inspection worker failed: {error}"))?
}

pub(crate) fn validate_completed_nvidia_version(
    completed: &Option<CompletedNvidiaImage>,
    requested_nvidia_version: Option<&str>,
) -> Result<(), String> {
    if let (Some(completed), Some(requested)) = (completed, requested_nvidia_version) {
        if completed.nvidia_version != requested {
            return Err(format!(
                "This completed image contains NVIDIA {}, but NVIDIA {} is selected. Select the original Valve recovery image to build the requested version; an already-mutated image is never silently reused or upgraded in place.",
                completed.nvidia_version, requested
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_usb_write_intent(
    target: &UsbTargetCandidate,
    image_bytes: u64,
    requested_identifier: &str,
    expected_identity_token: &str,
    confirmation: &str,
) -> Result<(), String> {
    let macos_shape = requested_identifier
        .strip_prefix("disk")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        && target.device_node == format!("/dev/{requested_identifier}");
    let windows_shape = requested_identifier
        .strip_prefix("PhysicalDrive")
        .is_some_and(|digits| {
            !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit())
                && (digits == "0" || !digits.starts_with('0'))
        })
        && target.device_node == format!(r"\\.\PHYSICALDRIVE{}", &requested_identifier[13..]);
    if !macos_shape && !windows_shape {
        return Err("The selected device identifier is invalid.".into());
    }
    let expected_confirmation = format!("ERASE {requested_identifier}");
    if confirmation != expected_confirmation {
        return Err(format!(
            "Type {expected_confirmation} exactly to confirm the selected whole disk."
        ));
    }
    if target.device_identifier != requested_identifier {
        return Err("The revalidated disk does not match the requested whole device.".into());
    }
    if expected_identity_token.len() != 64
        || !expected_identity_token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || target.identity_token != expected_identity_token
    {
        return Err("The selected disk identity changed after discovery. Refresh removable drives and select it again.".into());
    }
    if target.bytes < image_bytes {
        return Err("The selected disk is no longer large enough for the completed image.".into());
    }
    if image_bytes == 0 || !image_bytes.is_multiple_of(target.block_size) {
        return Err(
            "The completed image is not aligned to the selected disk's logical block size.".into(),
        );
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn inspect_usb_targets(image_path: String) -> Result<UsbTargetPreflight, String> {
    tauri::async_runtime::spawn_blocking(move || {
        // Discovery is non-mutating and follows a completed-image inspection that already
        // hashed the image. Recheck its bounded manifest and current byte length here; the
        // authorization phase deliberately performs the full hash again immediately before
        // opening the selected raw device.
        let (image, image_bytes, image_sha256, _) =
            inspect_usb_image_manifest_identity(&image_path)?;
        let targets = discover_usb_targets(image_bytes)?;
        let targets_empty = targets.is_empty();
        let writes_allowed = physical_usb_writes_allowed();
        Ok(UsbTargetPreflight {
            image_path: image.to_string_lossy().into_owned(),
            image_bytes,
            image_sha256,
            targets,
            writes_allowed,
            message: if targets_empty {
                "No eligible removable USB drives were found. Connect or replug a drive, then refresh."
            } else if writes_allowed {
                "Eligible removable drives are shown. The image and exact device will be revalidated immediately before guarded whole-disk writing."
            } else if cfg!(target_os = "windows") {
                "Eligible removable drives are shown read-only. Restart OPEMOS as administrator to enable guarded Windows whole-disk writing."
            } else {
                "Eligible removable drives are shown read-only. Physical USB writing is not available on this platform yet."
            }
            .into(),
        })
    })
    .await
    .map_err(|error| format!("USB target discovery worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn inspect_usb_targets_for_build(
    input_path: String,
) -> Result<UsbTargetPreflight, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let input = fs::canonicalize(&input_path)
            .map_err(|error| format!("Could not resolve the selected image: {error}"))?;
        let metadata = fs::metadata(&input)
            .map_err(|error| format!("Could not inspect the selected image: {error}"))?;
        if !metadata.is_file() {
            return Err("The selected image is not a regular file.".into());
        }
        let format = detect_input_format(&input)?;
        let minimum_bytes = if format == InputFormat::Raw {
            metadata.len()
        } else {
            0
        };
        let targets = discover_usb_targets(minimum_bytes)?;
        let targets_empty = targets.is_empty();
        Ok(UsbTargetPreflight {
            image_path: input.to_string_lossy().into_owned(),
            image_bytes: minimum_bytes,
            image_sha256: String::new(),
            targets,
            writes_allowed: false,
            message: if targets_empty {
                "No eligible removable USB drives were found. Connect or replug a drive, then refresh."
            } else if format == InputFormat::Raw {
                "Eligible removable drives are shown. Exact image identity and capacity will be checked again after the build."
            } else {
                "Eligible removable drives are shown. The compressed input's final raw size will be checked after export before writing."
            }
            .into(),
        })
    })
    .await
    .map_err(|error| format!("USB target discovery worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn arm_usb_write_preflight(
    app: tauri::AppHandle,
    image_path: String,
    device_identifier: String,
    identity_token: String,
    confirmation: String,
) -> Result<UsbWritePreflightSession, String> {
    let (image, image_bytes, image_sha256) =
        tauri::async_runtime::spawn_blocking(move || validate_usb_image_identity(&image_path))
            .await
            .map_err(|error| format!("USB image revalidation worker failed: {error}"))??;
    let expected_confirmation = format!("ERASE {device_identifier}");
    if confirmation != expected_confirmation {
        return Err(format!(
            "Type {expected_confirmation} exactly to confirm the selected whole disk."
        ));
    }
    let target_identifier = device_identifier.clone();
    let target = tauri::async_runtime::spawn_blocking(move || {
        revalidate_usb_target(&target_identifier, image_bytes)
    })
    .await
    .map_err(|error| format!("USB device revalidation worker failed: {error}"))??;
    validate_usb_write_intent(
        &target,
        image_bytes,
        &device_identifier,
        &identity_token,
        &confirmation,
    )?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "The system clock is earlier than the Unix epoch.")?;
    let expires_at_unix_ms = now
        .checked_add(USB_PREFLIGHT_TTL)
        .ok_or("USB preflight expiration overflowed.")?
        .as_millis();
    let manager_state = app.state::<Mutex<UsbPreparationManager>>();
    let mut manager = manager_state
        .lock()
        .map_err(|_| "USB preparation state is unavailable.")?;
    let generation = manager.generation().wrapping_add(1).max(1);
    let session_identity = format!(
        "{}\0{}\0{}\0{}\0{}",
        generation,
        image_sha256,
        target.identity_token,
        target.device_identifier,
        now.as_nanos()
    );
    let session_token = format!("{:x}", Sha256::digest(session_identity.as_bytes()));
    manager.arm(
        session_token.clone(),
        target.device_identifier.clone(),
        image_sha256.clone(),
        target.identity_token.clone(),
        Instant::now(),
    );
    Ok(UsbWritePreflightSession {
        status: "armed".into(),
        session_token,
        device_identifier: target.device_identifier,
        device_node: target.device_node,
        image_sha256,
        identity_token: target.identity_token,
        expires_at_unix_ms,
        writes_allowed: physical_usb_writes_allowed(),
        message: format!(
            "Intent confirmed for {}. {} This authorization expires in 60 seconds.",
            image.display(),
            if physical_usb_writes_allowed() {
                usb_write_permission_message()
            } else if cfg!(target_os = "windows") {
                "Restart OPEMOS as administrator to enable the guarded Windows whole-disk writer."
            } else {
                "Physical writing is not available on this platform yet."
            },
        ),
    })
}

#[tauri::command]
pub(crate) fn cancel_usb_write_preflight(
    app: tauri::AppHandle,
    session_token: String,
) -> Result<UsbWritePreflightCancellation, String> {
    if !valid_usb_preflight_session_token(&session_token) {
        return Err("The USB intent session token is invalid.".into());
    }
    let manager_state = app.state::<Mutex<UsbPreparationManager>>();
    let mut manager = manager_state
        .lock()
        .map_err(|_| "USB preparation state is unavailable.")?;
    let writing = manager.is_writing(&session_token);
    let cancelled = manager.cancel(&session_token, Instant::now());
    Ok(UsbWritePreflightCancellation {
        status: if writing && cancelled {
            "cancellation-requested"
        } else if cancelled {
            "cancelled"
        } else {
            "not-armed"
        }
        .into(),
        cancelled,
        writes_allowed: false,
    })
}

#[tauri::command]
pub(crate) fn get_usb_write_preflight_status(
    app: tauri::AppHandle,
    session_token: String,
) -> Result<UsbWritePreflightStatus, String> {
    if !valid_usb_preflight_session_token(&session_token) {
        return Err("The USB intent session token is invalid.".into());
    }
    let manager_state = app.state::<Mutex<UsbPreparationManager>>();
    let mut manager = manager_state
        .lock()
        .map_err(|_| "USB preparation state is unavailable.")?;
    Ok(manager.status(&session_token, Instant::now()))
}

#[cfg(target_os = "macos")]
fn unmount_usb_target(identifier: &str) -> Result<(), String> {
    let output = Command::new("/usr/sbin/diskutil")
        .args(["unmountDisk", identifier])
        .output()
        .map_err(|error| {
            format!("Could not ask macOS to unmount the selected USB disk: {error}")
        })?;
    if !output.status.success() {
        return Err("macOS could not unmount every volume on the selected USB disk. Close files using it and try again.".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn eject_usb_target(identifier: &str) -> bool {
    Command::new("/usr/sbin/diskutil")
        .args(["eject", identifier])
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "macos")]
fn remount_usb_target(identifier: &str) -> bool {
    Command::new("/usr/sbin/diskutil")
        .args(["mountDisk", identifier])
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(any(target_os = "windows", test))]
fn windows_volume_belongs_exclusively_to_disk(
    disks: &[u32],
    selected: u32,
) -> Result<bool, String> {
    if disks.is_empty() {
        return Err("Windows returned a volume without any disk extents.".into());
    }
    if disks.contains(&selected) && disks.iter().any(|disk| *disk != selected) {
        return Err(
            "A Windows volume spans the selected disk and another disk; refusing the write.".into(),
        );
    }
    Ok(disks.iter().all(|disk| *disk == selected))
}

#[cfg(target_os = "macos")]
pub(crate) fn validate_system_authopen() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let path = Path::new("/usr/libexec/authopen");
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect macOS authopen: {error}"))?;
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("Could not resolve macOS authopen: {error}"))?;
    if canonical != path
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(
            "The macOS authorization utility is not a protected root-owned executable.".into(),
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn receive_authorized_descriptor(socket: &UnixStream) -> io::Result<Option<File>> {
    let mut byte = [0_u8; 1];
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
    let received = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
    if received < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if received == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "authopen closed without returning a device descriptor",
        ));
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authopen returned truncated descriptor metadata",
        ));
    }
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null()
        || unsafe { (*header).cmsg_level } != libc::SOL_SOCKET
        || unsafe { (*header).cmsg_type } != libc::SCM_RIGHTS
        || unsafe { (*header).cmsg_len }
            != unsafe { libc::CMSG_LEN(std::mem::size_of::<i32>() as _) }
        || !unsafe { libc::CMSG_NXTHDR(&message, header) }.is_null()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authopen returned an invalid descriptor message",
        ));
    }
    let descriptor = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>()) };
    if descriptor < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authopen returned an invalid descriptor",
        ));
    }
    let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if descriptor_flags < 0
        || unsafe {
            libc::fcntl(
                descriptor,
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        } < 0
    {
        unsafe { libc::close(descriptor) };
        return Err(io::Error::last_os_error());
    }
    Ok(Some(unsafe { File::from_raw_fd(descriptor) }))
}

#[cfg(target_os = "macos")]
pub(crate) fn authorized_open_path(path: &Path, cancel: &AtomicBool) -> Result<File, String> {
    validate_system_authopen()?;
    let (parent_socket, child_socket) = UnixStream::pair()
        .map_err(|error| format!("Could not prepare macOS USB authorization: {error}"))?;
    parent_socket
        .set_nonblocking(true)
        .map_err(|error| format!("Could not prepare macOS authorization polling: {error}"))?;
    let child_output: OwnedFd = child_socket.into();
    let mut child = Command::new("/usr/libexec/authopen")
        .args(["-stdoutpipe", "-o", "2"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(child_output))
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Could not start macOS USB authorization: {error}"))?;
    let started = Instant::now();
    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("USB authorization was cancelled before the device was opened.".into());
        }
        match receive_authorized_descriptor(&parent_socket) {
            Ok(Some(file)) => {
                let output = child.wait_with_output().map_err(|error| {
                    format!("Could not finish macOS USB authorization: {error}")
                })?;
                if !output.status.success() {
                    return Err(
                        "macOS did not authorize access to the selected raw USB device.".into(),
                    );
                }
                return Ok(file);
            }
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                let output = child.wait_with_output().map_err(|wait_error| {
                    format!("Could not finish macOS USB authorization: {wait_error}")
                })?;
                let detail: String = String::from_utf8_lossy(&output.stderr)
                    .trim()
                    .chars()
                    .take(300)
                    .collect();
                return Err(if detail.is_empty() {
                    "macOS did not authorize access to the selected raw USB device.".into()
                } else {
                    format!("macOS USB authorization failed: {detail}")
                });
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "Could not receive the authorized USB device descriptor: {error}"
                ));
            }
        }
        if started.elapsed() >= Duration::from_secs(120) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("macOS USB authorization timed out before any device was opened.".into());
        }
        if child
            .try_wait()
            .map_err(|error| format!("Could not inspect macOS USB authorization: {error}"))?
            .is_some()
        {
            let detail = child
                .stderr
                .take()
                .and_then(|stderr| {
                    let mut bytes = Vec::new();
                    stderr.take(4096).read_to_end(&mut bytes).ok()?;
                    Some(String::from_utf8_lossy(&bytes).trim().to_string())
                })
                .unwrap_or_default();
            return Err(if detail.is_empty() {
                "macOS did not authorize access to the selected raw USB device.".into()
            } else {
                format!("macOS USB authorization failed: {detail}")
            });
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(target_os = "macos")]
fn open_usb_raw_device(
    target: &UsbTargetCandidate,
    cancel: &AtomicBool,
) -> Result<(File, Vec<File>), String> {
    use std::os::unix::fs::MetadataExt as _;

    let raw_node = PathBuf::from(format!("/dev/r{}", target.device_identifier));
    let metadata = fs::symlink_metadata(&raw_node)
        .map_err(|error| format!("Could not inspect {}: {error}", raw_node.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_char_device() {
        return Err("The selected raw USB node is not a direct character device.".into());
    }
    let file = authorized_open_path(&raw_node, cancel)?;
    let opened = file
        .metadata()
        .map_err(|error| format!("Could not inspect the authorized USB descriptor: {error}"))?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if !opened.file_type().is_char_device()
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.rdev() != metadata.rdev()
        || flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDWR
    {
        return Err(
            "The authorized descriptor does not identify the exact selected read/write raw device."
                .into(),
        );
    }
    Ok((file, Vec::new()))
}

#[cfg(target_os = "windows")]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsUsbWriterRequest {
    schema_version: u32,
    expires_at_unix_ms: u64,
    image_path: String,
    image_bytes: u64,
    image_sha256: String,
    device_identifier: String,
    device_node: String,
    media_name: String,
    device_bytes: u64,
    block_size: u64,
    identity_token: String,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsUsbWriterReceipt {
    schema_version: u32,
    request_sha256: String,
    success: bool,
    verified_sha256: String,
    ejected: bool,
    error: String,
}

#[cfg(any(target_os = "windows", test))]
fn validate_windows_usb_writer_receipt(
    bytes: &[u8],
    process_exit_code: u32,
    expected_request_sha256: &str,
    expected_image_sha256: &str,
) -> Result<WindowsUsbWriterReceipt, String> {
    if bytes.len() > 32 * 1024 {
        return Err("The elevated Windows USB writer receipt is oversized.".into());
    }
    let receipt: WindowsUsbWriterReceipt = serde_json::from_slice(bytes)
        .map_err(|_| "The elevated Windows USB writer receipt is malformed.")?;
    if receipt.schema_version != 1 || receipt.request_sha256 != expected_request_sha256 {
        return Err("The elevated Windows USB writer receipt identity is invalid.".into());
    }
    if receipt.success {
        if process_exit_code != 0 {
            return Err(format!(
                "The elevated Windows USB writer reported success but exited with code {process_exit_code}."
            ));
        }
        if !receipt.error.is_empty()
            || !valid_sha256(&receipt.verified_sha256)
            || !receipt
                .verified_sha256
                .eq_ignore_ascii_case(expected_image_sha256)
        {
            return Err(
                "The elevated Windows USB writer success receipt does not match the expected verified image digest."
                    .into(),
            );
        }
        return Ok(receipt);
    }
    if !receipt.verified_sha256.is_empty() || receipt.ejected || receipt.error.is_empty() {
        return Err("The elevated Windows USB writer failure receipt is inconsistent.".into());
    }
    Err(receipt.error)
}

#[cfg(target_os = "windows")]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsUsbWriterProgress {
    schema_version: u32,
    request_sha256: String,
    sequence: u64,
    phase: String,
    bytes_completed: u64,
    bytes_total: u64,
    message: String,
}

#[cfg(target_os = "windows")]
fn persist_windows_writer_progress(
    path: &Path,
    request_sha256: &str,
    sequence: u64,
    progress: &UsbWriteProgress,
) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt as _;
    let record = WindowsUsbWriterProgress {
        schema_version: 1,
        request_sha256: request_sha256.into(),
        sequence,
        phase: progress.phase.chars().take(32).collect(),
        bytes_completed: progress.bytes_completed.min(progress.bytes_total),
        bytes_total: progress.bytes_total,
        message: progress.message.chars().take(512).collect(),
    };
    let bytes = serde_json::to_vec(&record)
        .map_err(|error| format!("Could not encode bounded USB writer progress: {error}"))?;
    let partial = path.with_extension("json.partial");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&partial)
        .map_err(|error| format!("Could not create bounded USB writer progress: {error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("Could not persist bounded USB writer progress: {error}"))?;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }
    let existing = partial
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let replacement = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe { MoveFileExW(existing.as_ptr(), replacement.as_ptr(), 1 | 8) } == 0 {
        return Err(format!(
            "Could not atomically publish bounded USB writer progress: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn perform_windows_usb_write(
    request: &WindowsUsbWriterRequest,
    cancel: &AtomicBool,
    mut progress: impl FnMut(UsbWriteProgress),
) -> Result<(String, bool), String> {
    if !windows_process_is_elevated() {
        return Err("The bounded Windows USB writer was not elevated.".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "The system clock is earlier than the Unix epoch.")?
        .as_millis() as u64;
    if request.schema_version != 1
        || request.expires_at_unix_ms <= now
        || request.expires_at_unix_ms.saturating_sub(now) > USB_PREFLIGHT_TTL.as_millis() as u64
        || !valid_sha256(&request.image_sha256)
        || !valid_sha256(&request.identity_token)
    {
        return Err("The bounded Windows USB writer request is invalid or expired.".into());
    }
    let (image, image_bytes, image_sha256) = validate_usb_image_identity(&request.image_path)?;
    if image_bytes != request.image_bytes || image_sha256 != request.image_sha256 {
        return Err("The completed image changed before elevated USB writing.".into());
    }
    let target = revalidate_usb_target(&request.device_identifier, image_bytes)?;
    if target.device_node != request.device_node
        || target.media_name != request.media_name
        || target.bytes != request.device_bytes
        || target.block_size != request.block_size
        || target.identity_token != request.identity_token
    {
        return Err(
            "The selected Windows removable disk changed before elevation completed.".into(),
        );
    }
    progress(UsbWriteProgress {
        phase: "locking".into(),
        bytes_completed: 0,
        bytes_total: image_bytes,
        message: "Locking and dismounting every selected-disk volume.".into(),
    });
    unmount_usb_target(&target.device_identifier)?;
    let (mut device, volume_locks) = open_usb_raw_device(&target, cancel)?;
    let opened =
        match revalidate_windows_usb_target_state(&target.device_identifier, image_bytes, true) {
            Ok(opened) => opened,
            Err(error) => {
                drop(device);
                drop(volume_locks);
                return Err(match recover_windows_usb_target(&target) {
                    Ok(true) => format!("{error} The unchanged target was safely ejected."),
                    Ok(false) => format!("{error} The unchanged target was returned online."),
                    Err(recovery) => format!("{error} {recovery}"),
                });
            }
        };
    if opened.identity_token != target.identity_token {
        drop(device);
        drop(volume_locks);
        return Err(match recover_windows_usb_target(&target) {
            Ok(_) => "The selected Windows removable disk changed after raw open; the unchanged target was recovered.".into(),
            Err(recovery) => format!("The selected Windows removable disk changed after raw open. {recovery}"),
        });
    }
    let result = copy_and_verify_usb_image(
        &image,
        &mut device,
        image_bytes,
        &image_sha256,
        cancel,
        |update| progress(update),
    );
    drop(device);
    drop(volume_locks);
    let verified = match result {
        Ok(verified) => verified,
        Err(error) => {
            return Err(match recover_windows_usb_target(&target) {
                Ok(true) => format!("{error} The unchanged target was safely ejected."),
                Ok(false) => format!("{error} The unchanged target was returned online."),
                Err(recovery) => format!("{error} {recovery}"),
            });
        }
    };
    progress(UsbWriteProgress {
        phase: "releasing".into(),
        bytes_completed: image_bytes,
        bytes_total: image_bytes,
        message: "Releasing and safely ejecting the selected USB disk.".into(),
    });
    let ejected = recover_windows_usb_target(&target)?;
    Ok((verified, ejected))
}

#[cfg(target_os = "windows")]
pub(crate) fn run_windows_usb_writer_helper(
    arguments: &[String],
) -> Result<Option<String>, String> {
    if arguments.first().map(String::as_str) != Some("windows-usb-writer-helper") {
        return Ok(None);
    }
    if arguments.len() != 9
        || arguments[1] != "--request"
        || arguments[3] != "--request-sha256"
        || arguments[5] != "--receipt"
        || arguments[7] != "--progress"
    {
        return Err("Invalid bounded Windows USB writer helper arguments.".into());
    }
    let request_path = PathBuf::from(&arguments[2]);
    let receipt_path = PathBuf::from(&arguments[6]);
    let progress_path = PathBuf::from(&arguments[8]);
    let root = request_path
        .parent()
        .ok_or("The bounded Windows USB writer request has no parent.")?;
    if !request_path.is_absolute()
        || !receipt_path.is_absolute()
        || receipt_path.parent() != Some(root)
        || progress_path.parent() != Some(root)
        || request_path.file_name().and_then(|v| v.to_str()) != Some("request.json")
        || receipt_path.file_name().and_then(|v| v.to_str()) != Some("receipt.json")
        || progress_path.file_name().and_then(|v| v.to_str()) != Some("progress.json")
    {
        return Err("The bounded Windows USB writer paths are invalid.".into());
    }
    let request_bytes = fs::read(&request_path)
        .map_err(|error| format!("Could not read the bounded USB writer request: {error}"))?;
    if request_bytes.len() > 32 * 1024
        || format!("{:x}", Sha256::digest(&request_bytes)) != arguments[4]
    {
        return Err("The bounded Windows USB writer request identity is invalid.".into());
    }
    let request: WindowsUsbWriterRequest = serde_json::from_slice(&request_bytes)
        .map_err(|_| "The bounded Windows USB writer request is malformed.")?;
    let cancel_path = root.join("cancel");
    let cancel = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let watcher_cancel = cancel.clone();
    let watcher_stop = stop.clone();
    let watcher = thread::spawn(move || {
        while !watcher_stop.load(Ordering::Relaxed) {
            if cancel_path.exists() {
                watcher_cancel.store(true, Ordering::Relaxed);
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    let mut sequence = 0_u64;
    let outcome = perform_windows_usb_write(&request, &cancel, |progress| {
        sequence = sequence.saturating_add(1);
        let _ = persist_windows_writer_progress(&progress_path, &arguments[4], sequence, &progress);
    });
    sequence = sequence.saturating_add(1);
    let terminal_progress = match &outcome {
        Ok(_) => UsbWriteProgress {
            phase: "finalizing".into(),
            bytes_completed: request.image_bytes,
            bytes_total: request.image_bytes,
            message: "The exact USB write receipt is being finalized.".into(),
        },
        Err(error) => UsbWriteProgress {
            phase: if cancel.load(Ordering::Relaxed) {
                "cancelled".into()
            } else {
                "failed".into()
            },
            bytes_completed: 0,
            bytes_total: request.image_bytes,
            message: error.chars().take(512).collect(),
        },
    };
    let _ = persist_windows_writer_progress(
        &progress_path,
        &arguments[4],
        sequence,
        &terminal_progress,
    );
    stop.store(true, Ordering::Relaxed);
    let _ = watcher.join();
    let receipt = match outcome {
        Ok((verified_sha256, ejected)) => WindowsUsbWriterReceipt {
            schema_version: 1,
            request_sha256: arguments[4].clone(),
            success: true,
            verified_sha256,
            ejected,
            error: String::new(),
        },
        Err(error) => WindowsUsbWriterReceipt {
            schema_version: 1,
            request_sha256: arguments[4].clone(),
            success: false,
            verified_sha256: String::new(),
            ejected: false,
            error: error.chars().take(1000).collect(),
        },
    };
    let receipt_bytes = serde_json::to_vec(&receipt)
        .map_err(|error| format!("Could not encode the bounded USB writer receipt: {error}"))?;
    let mut receipt_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt_path)
        .map_err(|error| format!("Could not create the bounded USB writer receipt: {error}"))?;
    receipt_file
        .write_all(&receipt_bytes)
        .and_then(|_| receipt_file.sync_all())
        .map_err(|error| format!("Could not persist the bounded USB writer receipt: {error}"))?;
    Ok(Some("bounded Windows USB writer completed".into()))
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn run_windows_usb_writer_helper(
    arguments: &[String],
) -> Result<Option<String>, String> {
    if arguments.first().map(String::as_str) == Some("windows-usb-writer-helper") {
        return Err("The bounded Windows USB writer helper requires Windows.".into());
    }
    Ok(None)
}

#[cfg(target_os = "windows")]
struct WindowsProcessHandle(*mut std::ffi::c_void);

#[cfg(target_os = "windows")]
impl Drop for WindowsProcessHandle {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        extern "system" {
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }
        unsafe { CloseHandle(self.0) };
    }
}

#[cfg(target_os = "windows")]
fn launch_exact_elevated_writer(
    executable: &Path,
    parameters: &str,
) -> Result<WindowsProcessHandle, String> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt as _;
    #[repr(C)]
    struct ShellExecuteInfoW {
        size: u32,
        mask: u32,
        hwnd: *mut c_void,
        verb: *const u16,
        file: *const u16,
        parameters: *const u16,
        directory: *const u16,
        show: i32,
        instance: *mut c_void,
        id_list: *mut c_void,
        class: *const u16,
        class_key: *mut c_void,
        hot_key: u32,
        icon_or_monitor: *mut c_void,
        process: *mut c_void,
    }
    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteExW(info: *mut ShellExecuteInfoW) -> i32;
    }
    let verb = "runas\0".encode_utf16().collect::<Vec<_>>();
    let file = executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let args = parameters.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut info = ShellExecuteInfoW {
        size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
        mask: 0x0000_0040 | 0x0000_0400,
        hwnd: std::ptr::null_mut(),
        verb: verb.as_ptr(),
        file: file.as_ptr(),
        parameters: args.as_ptr(),
        directory: std::ptr::null(),
        show: 0,
        instance: std::ptr::null_mut(),
        id_list: std::ptr::null_mut(),
        class: std::ptr::null(),
        class_key: std::ptr::null_mut(),
        hot_key: 0,
        icon_or_monitor: std::ptr::null_mut(),
        process: std::ptr::null_mut(),
    };
    if unsafe { ShellExecuteExW(&mut info) } == 0 || info.process.is_null() {
        return Err(
            "Windows elevation was cancelled or failed before the bounded USB writer started."
                .into(),
        );
    }
    Ok(WindowsProcessHandle(info.process))
}

#[cfg(target_os = "windows")]
fn quote_windows_argument(value: &std::ffi::OsStr) -> String {
    let value = value.to_string_lossy();
    let mut quoted = String::from("\"");
    let mut backslashes = 0_usize;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
        } else {
            if character == '"' {
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            } else {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
            }
            backslashes = 0;
            quoted.push(character);
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(target_os = "windows")]
fn launch_elevated_windows_usb_writer(
    image: &Path,
    image_bytes: u64,
    image_sha256: &str,
    target: &UsbTargetCandidate,
    cancel: &AtomicBool,
    mut progress: impl FnMut(UsbWriteProgress),
) -> Result<UsbWriteResult, String> {
    struct ExchangeCleanup(PathBuf);
    impl Drop for ExchangeCleanup {
        fn drop(&mut self) {
            for name in [
                "cancel",
                "receipt.json",
                "request.json",
                "progress.json",
                "progress.json.partial",
            ] {
                let _ = fs::remove_file(self.0.join(name));
            }
            let _ = fs::remove_dir(&self.0);
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "The system clock is earlier than the Unix epoch.")?;
    let root = std::env::temp_dir().join(format!(
        "opemos-usb-writer-{}-{}",
        std::process::id(),
        now.as_nanos()
    ));
    fs::create_dir(&root)
        .map_err(|error| format!("Could not create the bounded USB writer exchange: {error}"))?;
    let _cleanup = ExchangeCleanup(root.clone());
    let request_path = root.join("request.json");
    let receipt_path = root.join("receipt.json");
    let cancel_path = root.join("cancel");
    let progress_path = root.join("progress.json");
    let request = WindowsUsbWriterRequest {
        schema_version: 1,
        expires_at_unix_ms: now
            .checked_add(USB_PREFLIGHT_TTL)
            .ok_or("USB writer expiration overflowed.")?
            .as_millis() as u64,
        image_path: image.to_string_lossy().into_owned(),
        image_bytes,
        image_sha256: image_sha256.into(),
        device_identifier: target.device_identifier.clone(),
        device_node: target.device_node.clone(),
        media_name: target.media_name.clone(),
        device_bytes: target.bytes,
        block_size: target.block_size,
        identity_token: target.identity_token.clone(),
    };
    let request_bytes = serde_json::to_vec(&request)
        .map_err(|error| format!("Could not encode the bounded USB writer request: {error}"))?;
    let request_sha256 = format!("{:x}", Sha256::digest(&request_bytes));
    let mut request_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&request_path)
        .map_err(|error| format!("Could not create the bounded USB writer request: {error}"))?;
    request_file
        .write_all(&request_bytes)
        .and_then(|_| request_file.sync_all())
        .map_err(|error| format!("Could not persist the bounded USB writer request: {error}"))?;
    drop(request_file);
    let executable = std::env::current_exe()
        .map_err(|error| format!("Could not resolve the OPEMOS executable: {error}"))?;
    let parameters = format!(
        "windows-usb-writer-helper --request {} --request-sha256 {} --receipt {} --progress {}",
        quote_windows_argument(request_path.as_os_str()),
        request_sha256,
        quote_windows_argument(receipt_path.as_os_str()),
        quote_windows_argument(progress_path.as_os_str()),
    );
    progress(UsbWriteProgress {
        phase: "authorizing".into(),
        bytes_completed: 0,
        bytes_total: image_bytes,
        message: "Waiting for Windows authorization for the exact selected USB operation.".into(),
    });
    let child = launch_exact_elevated_writer(&executable, &parameters)?;
    #[link(name = "kernel32")]
    extern "system" {
        fn WaitForSingleObject(handle: *mut std::ffi::c_void, milliseconds: u32) -> u32;
        fn GetExitCodeProcess(handle: *mut std::ffi::c_void, code: *mut u32) -> i32;
        fn TerminateProcess(handle: *mut std::ffi::c_void, code: u32) -> i32;
    }
    let deadline = Instant::now() + Duration::from_secs(24 * 60 * 60);
    let mut last_sequence = 0_u64;
    let mut last_phase_rank = 0_u8;
    let mut last_phase_bytes = 0_u64;
    let mut cancellation_deadline = None;
    let status = loop {
        if cancel.load(Ordering::Relaxed) && !cancel_path.exists() {
            let _ = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&cancel_path);
            cancellation_deadline = Some(Instant::now() + Duration::from_secs(30));
        }
        if let Ok(bytes) = fs::read(&progress_path) {
            if bytes.len() <= 4096 {
                if let Ok(record) = serde_json::from_slice::<WindowsUsbWriterProgress>(&bytes) {
                    let rank = match record.phase.as_str() {
                        "locking" => 1,
                        "writing" => 2,
                        "flushing" => 3,
                        "verifying" => 4,
                        "releasing" => 5,
                        "finalizing" | "cancelled" | "failed" => 6,
                        _ => 0,
                    };
                    if record.schema_version == 1
                        && record.request_sha256 == request_sha256
                        && record.sequence > last_sequence
                        && rank >= last_phase_rank
                        && rank != 0
                        && record.bytes_total == image_bytes
                        && record.bytes_completed <= record.bytes_total
                        && (rank != last_phase_rank || record.bytes_completed >= last_phase_bytes)
                    {
                        last_sequence = record.sequence;
                        last_phase_rank = rank;
                        last_phase_bytes = record.bytes_completed;
                        progress(UsbWriteProgress {
                            phase: record.phase,
                            bytes_completed: record.bytes_completed,
                            bytes_total: record.bytes_total,
                            message: record.message,
                        });
                    }
                }
            }
        }
        let wait = unsafe { WaitForSingleObject(child.0, 100) };
        if wait == 0 {
            let mut code = u32::MAX;
            if unsafe { GetExitCodeProcess(child.0, &mut code) } == 0 {
                return Err("Could not inspect the exact elevated USB writer process.".into());
            }
            break code;
        }
        if wait != 258 {
            std::mem::forget(_cleanup);
            return Err("Could not wait for the exact elevated USB writer process.".into());
        }
        if Instant::now() >= deadline
            || cancellation_deadline.is_some_and(|value| Instant::now() >= value)
        {
            if !cancel_path.exists() {
                let _ = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&cancel_path);
            }
            if unsafe { WaitForSingleObject(child.0, 30_000) } != 0 {
                unsafe { TerminateProcess(child.0, 2) };
                if unsafe { WaitForSingleObject(child.0, 30_000) } != 0 {
                    std::mem::forget(_cleanup);
                    return Err("The exact elevated Windows USB writer did not terminate; its exchange was retained for manual handling.".into());
                }
            }
            return Err(if cancellation_deadline.is_some() {
                "The exact elevated Windows USB writer was terminated after it did not settle within 30 seconds of cancellation.".into()
            } else {
                "The elevated Windows USB writer exceeded its bounded lifetime.".into()
            });
        }
    };
    let receipt_bytes = fs::read(&receipt_path).map_err(|error| {
        format!(
            "The elevated Windows USB writer returned no verifiable receipt (exit {status}): {error}"
        )
    })?;
    let receipt =
        validate_windows_usb_writer_receipt(&receipt_bytes, status, &request_sha256, image_sha256)?;
    progress(UsbWriteProgress {
        phase: "completed".into(),
        bytes_completed: image_bytes,
        bytes_total: image_bytes,
        message: "USB writing and readback completed with a verified exact-operation receipt."
            .into(),
    });
    Ok(UsbWriteResult {
        status: "verified".into(),
        device_identifier: target.device_identifier.clone(),
        device_node: target.device_node.clone(),
        bytes_written: image_bytes,
        image_sha256: image_sha256.into(),
        verified_sha256: receipt.verified_sha256,
        ejected: receipt.ejected,
        message: if receipt.ejected {
            "USB writing and byte-for-byte verification completed; Windows ejected the device."
                .into()
        } else {
            "USB writing and byte-for-byte verification completed, but Windows could not eject the device; use Safely Remove Hardware before unplugging it.".into()
        },
    })
}

#[cfg(target_os = "windows")]
fn unmount_usb_target(identifier: &str) -> Result<(), String> {
    if !windows_process_is_elevated() {
        return Err("Windows USB writing requires running OPEMOS as administrator.".into());
    }
    revalidate_usb_target(identifier, 0)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn eject_usb_target(identifier: &str) -> bool {
    use std::ffi::c_void;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;

    let Ok(number) = windows_disk_number(identifier) else {
        return false;
    };
    if revalidate_windows_usb_target_state(identifier, 0, true).is_err() {
        return false;
    }
    let Ok(file) = OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(0x8000_0000 | 0x4000_0000)
        .share_mode(0x0000_0001 | 0x0000_0002)
        .open(format!(r"\\.\PHYSICALDRIVE{number}"))
    else {
        return false;
    };
    #[link(name = "kernel32")]
    extern "system" {
        fn DeviceIoControl(
            device: *mut c_void,
            code: u32,
            input: *mut c_void,
            input_bytes: u32,
            output: *mut c_void,
            output_bytes: u32,
            returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
    }
    let mut returned = 0_u32;
    let mut prevent = 0_u8;
    let released = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x002d_4804,
            (&mut prevent as *mut u8).cast(),
            1,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    } != 0;
    released
        && unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                0x002d_4808,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        } != 0
}

#[cfg(target_os = "windows")]
fn remount_usb_target(identifier: &str) -> bool {
    let Ok(number) = windows_disk_number(identifier) else {
        return false;
    };
    let script = format!(
        "$d=Get-Disk -Number {number} -ErrorAction Stop; if ($d.BusType -ne 'USB' -or $d.IsBoot -or $d.IsSystem) {{ exit 1 }}; if ($d.IsOffline) {{ Set-Disk -Number {number} -IsOffline $false -ErrorAction Stop }}"
    );
    windows_powershell(
        &script,
        "return the unchanged Windows removable disk online",
    )
    .is_ok()
}

#[cfg(target_os = "windows")]
fn recover_windows_usb_target(target: &UsbTargetCandidate) -> Result<bool, String> {
    let (current, offline) = match revalidate_windows_usb_target_state(
        &target.device_identifier,
        0,
        true,
    ) {
        Ok(current) => (current, true),
        Err(offline_error) => match revalidate_windows_usb_target_state(
            &target.device_identifier,
            0,
            false,
        ) {
            Ok(current) => (current, false),
            Err(online_error) => return Err(format!("The selected Windows disk could not be revalidated as offline ({offline_error}) or online ({online_error}); leave it connected for manual handling.")),
        },
    };
    if !windows_usb_recovery_identity_is_unchanged(target, &current) {
        return Err("The selected Windows disk identity drifted during the operation; it was not remounted or ejected and requires manual handling.".into());
    }
    if !offline {
        return Ok(false);
    }
    if eject_usb_target(&target.device_identifier) {
        return Ok(true);
    }
    if remount_usb_target(&target.device_identifier) {
        return Ok(false);
    }
    Err("Windows could neither safely eject nor return the unchanged selected disk online; leave it connected for manual handling.".into())
}

#[cfg(any(target_os = "windows", test))]
fn windows_usb_recovery_identity_is_unchanged(
    original: &UsbTargetCandidate,
    current: &UsbTargetCandidate,
) -> bool {
    current.device_identifier == original.device_identifier
        && current.identity_token == original.identity_token
}

#[cfg(target_os = "windows")]
fn lock_windows_disk_volumes(number: u32) -> Result<Vec<File>, String> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStringExt as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;

    #[link(name = "kernel32")]
    extern "system" {
        fn FindFirstVolumeW(name: *mut u16, length: u32) -> *mut c_void;
        fn FindNextVolumeW(find: *mut c_void, name: *mut u16, length: u32) -> i32;
        fn FindVolumeClose(find: *mut c_void) -> i32;
        fn GetLastError() -> u32;
        fn DeviceIoControl(
            device: *mut c_void,
            code: u32,
            input: *mut c_void,
            input_bytes: u32,
            output: *mut c_void,
            output_bytes: u32,
            returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
    }
    struct FindHandle(*mut c_void);
    impl Drop for FindHandle {
        fn drop(&mut self) {
            unsafe { FindVolumeClose(self.0) };
        }
    }
    const INVALID_HANDLE_VALUE: *mut c_void = -1_isize as *mut c_void;
    const ERROR_NO_MORE_FILES: u32 = 18;
    const ERROR_MORE_DATA: u32 = 234;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;
    const FSCTL_LOCK_VOLUME: u32 = 0x0009_0018;
    const FSCTL_DISMOUNT_VOLUME: u32 = 0x0009_0020;
    let mut name = vec![0_u16; 1024];
    let raw_find = unsafe { FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
    if raw_find == INVALID_HANDLE_VALUE {
        return Err(
            "Windows could not enumerate volume GUID objects for the selected disk.".into(),
        );
    }
    let find = FindHandle(raw_find);
    let mut locked = Vec::new();
    loop {
        let end = name.iter().position(|value| *value == 0).ok_or(
            "Windows returned an unterminated volume GUID while locking the selected disk.",
        )?;
        let mut volume_path = std::ffi::OsString::from_wide(&name[..end]);
        let mut path = PathBuf::from(&volume_path);
        if path.to_string_lossy().ends_with('\\') {
            let mut value = path.to_string_lossy().into_owned();
            value.pop();
            volume_path = value.into();
            path = PathBuf::from(&volume_path);
        }
        let inspect = OpenOptions::new()
            .read(true)
            .access_mode(0x8000_0000)
            .share_mode(0x0000_0001 | 0x0000_0002)
            .open(&path)
            .map_err(|error| {
                format!(
                    "Could not inspect Windows volume GUID {}: {error}",
                    path.display()
                )
            })?;
        let mut extents = vec![0_u8; 4096];
        let returned = loop {
            let mut returned = 0_u32;
            let ok = unsafe {
                DeviceIoControl(
                    inspect.as_raw_handle(),
                    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                    std::ptr::null_mut(),
                    0,
                    extents.as_mut_ptr().cast(),
                    extents.len() as u32,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            } != 0;
            if ok {
                break returned as usize;
            }
            if unsafe { GetLastError() } != ERROR_MORE_DATA || extents.len() >= 1024 * 1024 {
                return Err(format!(
                    "Could not obtain disk extents for Windows volume GUID {}.",
                    path.display()
                ));
            }
            extents.resize(extents.len() * 2, 0);
        };
        if returned < 8 {
            return Err(format!(
                "Windows returned truncated disk extents for volume GUID {}.",
                path.display()
            ));
        }
        let count = u32::from_le_bytes(extents[0..4].try_into().unwrap_or_default()) as usize;
        let required = 8_usize
            .checked_add(
                count
                    .checked_mul(24)
                    .ok_or("Windows volume extent count overflowed.")?,
            )
            .ok_or("Windows volume extent size overflowed.")?;
        if count == 0 || returned < required {
            return Err(format!(
                "Windows returned invalid disk extents for volume GUID {}.",
                path.display()
            ));
        }
        let disks = (0..count)
            .map(|index| {
                let offset = 8 + index * 24;
                u32::from_le_bytes(extents[offset..offset + 4].try_into().unwrap_or_default())
            })
            .collect::<Vec<_>>();
        let selected_volume = windows_volume_belongs_exclusively_to_disk(&disks, number)
            .map_err(|error| format!("{error} Volume GUID: {}", path.display()))?;
        drop(inspect);
        if selected_volume {
            let volume = OpenOptions::new()
                .read(true)
                .write(true)
                .access_mode(0x8000_0000 | 0x4000_0000)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .open(&path)
                .map_err(|error| {
                    format!(
                        "Could not exclusively open selected-disk volume GUID {}: {error}",
                        path.display()
                    )
                })?;
            let mut returned = 0_u32;
            for (code, action) in [
                (FSCTL_LOCK_VOLUME, "lock"),
                (FSCTL_DISMOUNT_VOLUME, "dismount"),
            ] {
                if unsafe {
                    DeviceIoControl(
                        volume.as_raw_handle(),
                        code,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        0,
                        &mut returned,
                        std::ptr::null_mut(),
                    )
                } == 0
                {
                    return Err(format!(
                        "Windows could not {action} selected-disk volume GUID {}.",
                        path.display()
                    ));
                }
            }
            locked.push(volume);
        }
        name.fill(0);
        if unsafe { FindNextVolumeW(find.0, name.as_mut_ptr(), name.len() as u32) } == 0 {
            if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                break;
            }
            return Err("Windows volume GUID enumeration failed before completion.".into());
        }
    }
    Ok(locked)
}

#[cfg(target_os = "windows")]
fn open_usb_raw_device(
    target: &UsbTargetCandidate,
    _cancel: &AtomicBool,
) -> Result<(File, Vec<File>), String> {
    use std::ffi::c_void;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;

    #[repr(C)]
    struct StorageDeviceNumber {
        device_type: u32,
        device_number: u32,
        partition_number: u32,
    }
    #[repr(C)]
    struct GetLengthInformation {
        length: i64,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn DeviceIoControl(
            device: *mut c_void,
            control_code: u32,
            input: *mut c_void,
            input_bytes: u32,
            output: *mut c_void,
            output_bytes: u32,
            returned_bytes: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
    }

    let ioctl = |file: &File,
                 code: u32,
                 input: *mut c_void,
                 input_bytes: u32,
                 output: *mut c_void,
                 output_bytes: u32| {
        let mut returned = 0_u32;
        (unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                code,
                input,
                input_bytes,
                output,
                output_bytes,
                &mut returned,
                std::ptr::null_mut(),
            )
        }) != 0
    };

    let number = windows_disk_number(&target.device_identifier)?;
    if target.device_node != format!(r"\\.\PHYSICALDRIVE{number}") {
        return Err(
            "The selected Windows raw-device path no longer matches its disk number.".into(),
        );
    }
    let before = revalidate_usb_target(&target.device_identifier, 0)?;
    if before.identity_token != target.identity_token
        || before.bytes != target.bytes
        || before.block_size != target.block_size
    {
        return Err("The selected Windows removable disk changed before raw open.".into());
    }
    let volume_locks = lock_windows_disk_volumes(number)?;
    let opened = (|| -> Result<File, String> {
        windows_powershell(
        &format!("$d=Get-Disk -Number {number} -ErrorAction Stop; if ($d.BusType -ne 'USB' -or $d.IsBoot -or $d.IsSystem -or $d.IsReadOnly -or $d.IsOffline) {{ throw 'disk safety guard refused' }}; Set-Disk -Number {number} -IsOffline $true -ErrorAction Stop; if (-not (Get-Disk -Number {number}).IsOffline) {{ throw 'disk did not become offline' }}"),
        "take only the locked selected Windows removable disk offline",
    )?;
        let offline = revalidate_windows_usb_target_state(&target.device_identifier, 0, true)?;
        if offline.identity_token != target.identity_token {
            return Err("The selected Windows removable disk changed while it was locked.".into());
        }
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
        let file = OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE)
        .share_mode(0)
        .custom_flags(FILE_FLAG_WRITE_THROUGH)
        .open(&target.device_node)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::PermissionDenied {
                "Windows denied exclusive raw-disk access. Run OPEMOS as administrator and close programs using the USB drive.".into()
            } else {
                format!("Could not exclusively open the selected Windows raw disk: {error}")
            }
        })?;
        const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002d_1080;
        const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405c;
        let mut opened_number = StorageDeviceNumber {
            device_type: 0,
            device_number: u32::MAX,
            partition_number: 0,
        };
        let number_ok = ioctl(
            &file,
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            std::ptr::null_mut(),
            0,
            (&mut opened_number as *mut StorageDeviceNumber).cast(),
            std::mem::size_of::<StorageDeviceNumber>() as u32,
        );
        let mut opened_length = GetLengthInformation { length: -1 };
        let length_ok = ioctl(
            &file,
            IOCTL_DISK_GET_LENGTH_INFO,
            std::ptr::null_mut(),
            0,
            (&mut opened_length as *mut GetLengthInformation).cast(),
            std::mem::size_of::<GetLengthInformation>() as u32,
        );
        let mut query = [0_u8; 12];
        let mut descriptor = [0_u8; 4096];
        let descriptor_ok = ioctl(
            &file,
            0x002d_1400,
            query.as_mut_ptr().cast(),
            query.len() as u32,
            descriptor.as_mut_ptr().cast(),
            descriptor.len() as u32,
        );
        let serial_offset =
            u32::from_le_bytes(descriptor[24..28].try_into().unwrap_or_default()) as usize;
        let serial = if descriptor_ok && serial_offset > 0 && serial_offset < descriptor.len() {
            let end = descriptor[serial_offset..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|offset| serial_offset + offset)
                .unwrap_or(descriptor.len());
            String::from_utf8_lossy(&descriptor[serial_offset..end])
                .trim()
                .to_string()
        } else {
            String::new()
        };
        let inventory_serial = windows_powershell(
        &format!("$w=Get-CimInstance Win32_DiskDrive -Filter 'Index={number}' -ErrorAction Stop; [Console]::Out.Write(([string]$w.SerialNumber).Trim())"),
        "bind the opened Windows raw disk to its stable serial identity",
    )?;
        let inventory_serial = String::from_utf8(inventory_serial)
            .map_err(|_| "Windows returned an invalid selected-disk serial identity.")?;
        if !number_ok
            || !length_ok
            || opened_number.device_number != number
            || opened_number.partition_number != u32::MAX
            || u64::try_from(opened_length.length).ok() != Some(target.bytes)
            || !descriptor_ok
            || descriptor[10] == 0
            || u32::from_le_bytes(descriptor[28..32].try_into().unwrap_or_default()) != 7
            || serial.is_empty()
            || serial != inventory_serial.trim()
        {
            return Err("The opened Windows raw handle does not identify the exact selected whole disk and capacity.".into());
        }
        Ok(file)
    })();
    match opened {
        Ok(file) => Ok((file, volume_locks)),
        Err(error) => {
            drop(volume_locks);
            let disposition = recover_windows_usb_target(target)
                .map(|ejected| {
                    if ejected {
                        "safely ejected"
                    } else {
                        "returned online"
                    }
                    .to_string()
                })
                .unwrap_or_else(|recovery| recovery);
            Err(format!("{error} Target recovery: {disposition}"))
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn unmount_usb_target(_identifier: &str) -> Result<(), String> {
    Err("USB writing is currently implemented only for macOS.".into())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn eject_usb_target(_identifier: &str) -> bool {
    false
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn remount_usb_target(_identifier: &str) -> bool {
    false
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn open_usb_raw_device(
    _target: &UsbTargetCandidate,
    _cancel: &AtomicBool,
) -> Result<(File, Vec<File>), String> {
    Err("USB writing is currently implemented only for macOS.".into())
}

#[tauri::command]
pub(crate) async fn write_image_to_usb(
    app: tauri::AppHandle,
    session_token: String,
    image_path: String,
) -> Result<UsbWriteResult, String> {
    if !physical_usb_writes_allowed() {
        return Err(if cfg!(target_os = "windows") {
            "Windows USB writing requires running OPEMOS as administrator.".into()
        } else {
            "Physical USB writing is not available on this platform yet.".into()
        });
    }
    if !valid_usb_preflight_session_token(&session_token) {
        return Err("The USB intent session token is invalid.".into());
    }
    let manager_state = app.state::<Mutex<UsbPreparationManager>>();
    let armed = {
        let mut manager = manager_state
            .lock()
            .map_err(|_| "USB preparation state is unavailable.")?;
        manager.armed(&session_token, Instant::now()).ok_or(
            "The USB intent session expired or was replaced. Revalidate the image and device.",
        )?
    };
    let (image, image_bytes, image_sha256) =
        tauri::async_runtime::spawn_blocking(move || validate_usb_image_identity(&image_path))
            .await
            .map_err(|error| format!("USB image revalidation worker failed: {error}"))??;
    if image_sha256 != armed.image_sha256 {
        return Err("The completed image identity changed after USB confirmation.".into());
    }
    let target_identifier = armed.device_identifier.clone();
    let target = tauri::async_runtime::spawn_blocking(move || {
        revalidate_usb_target(&target_identifier, image_bytes)
    })
    .await
    .map_err(|error| format!("USB device revalidation worker failed: {error}"))??;
    if target.identity_token != armed.identity_token {
        return Err("The selected removable device was replaced after confirmation.".into());
    }
    let cancel = {
        let mut manager = manager_state
            .lock()
            .map_err(|_| "USB preparation state is unavailable.")?;
        manager
            .begin_write(&session_token, Instant::now())
            .ok_or("The USB intent session is no longer available for writing.")?
    };
    let app_for_progress = app.clone();
    let device_identifier = target.device_identifier.clone();
    let device_node = target.device_node.clone();
    let expected_sha256 = image_sha256.clone();
    let worker = tauri::async_runtime::spawn_blocking(move || {
        #[cfg(target_os = "windows")]
        if !windows_process_is_elevated() {
            return launch_elevated_windows_usb_writer(
                &image,
                image_bytes,
                &expected_sha256,
                &target,
                &cancel,
                |progress| {
                    let _ = app_for_progress.emit("usb-write-progress", progress);
                },
            );
        }
        let _ = app_for_progress.emit(
            "usb-write-progress",
            UsbWriteProgress {
                phase: "unmounting".into(),
                bytes_completed: 0,
                bytes_total: image_bytes,
                message: "Unmounting the selected removable disk without writing to it.".into(),
            },
        );
        unmount_usb_target(&target.device_identifier)?;
        let revalidated = revalidate_usb_target(&target.device_identifier, image_bytes)?;
        if revalidated.identity_token != target.identity_token {
            return Err("The selected removable device changed while it was being unmounted.".into());
        }
        let _ = app_for_progress.emit(
            "usb-write-progress",
            UsbWriteProgress {
                phase: "authorizing".into(),
                bytes_completed: 0,
                bytes_total: image_bytes,
                message: usb_write_permission_message().into(),
            },
        );
        let (mut device, volume_locks) = match open_usb_raw_device(&revalidated, &cancel) {
            Ok(device) => device,
            Err(error) => {
                #[cfg(target_os = "windows")]
                return Err(error);
                #[cfg(not(target_os = "windows"))]
                let _ = remount_usb_target(&revalidated.device_identifier);
                #[cfg(not(target_os = "windows"))]
                return Err(error);
            }
        };
        #[cfg(target_os = "windows")]
        let opened_result = revalidate_windows_usb_target_state(
            &revalidated.device_identifier,
            image_bytes,
            true,
        );
        #[cfg(not(target_os = "windows"))]
        let opened_result = revalidate_usb_target(&revalidated.device_identifier, image_bytes);
        let opened_target = match opened_result {
            Ok(target) => target,
            Err(error) => {
                drop(device);
                drop(volume_locks);
                #[cfg(target_os = "windows")]
                {
                    return Err(match recover_windows_usb_target(&revalidated) {
                        Ok(true) => format!("{error} The unchanged target was safely ejected."),
                        Ok(false) => format!("{error} The unchanged target was returned online."),
                        Err(recovery) => format!("{error} {recovery}"),
                    });
                }
                #[cfg(not(target_os = "windows"))]
                let _ = remount_usb_target(&revalidated.device_identifier);
                #[cfg(not(target_os = "windows"))]
                return Err(error);
            }
        };
        if opened_target.identity_token != revalidated.identity_token {
            drop(device);
            drop(volume_locks);
            #[cfg(target_os = "windows")]
            return Err(match recover_windows_usb_target(&revalidated) {
                Ok(_) => "The selected removable device changed during authorization; the unchanged target was recovered.".into(),
                Err(recovery) => format!("The selected removable device changed during authorization. {recovery}"),
            });
            #[cfg(not(target_os = "windows"))]
            return Err("The selected removable device changed during authorization.".into());
        }
        let copy_result = copy_and_verify_usb_image(
            &image,
            &mut device,
            image_bytes,
            &expected_sha256,
            &cancel,
            |progress| {
                let _ = app_for_progress.emit("usb-write-progress", progress);
            },
        );
        drop(device);
        drop(volume_locks);
        let verified_sha256 = match copy_result {
            Ok(sha256) => sha256,
            Err(error) => {
                #[cfg(target_os = "windows")]
                {
                    return Err(match recover_windows_usb_target(&revalidated) {
                        Ok(true) => format!("{error} The unchanged target was safely ejected."),
                        Ok(false) => format!("{error} The unchanged target was returned online."),
                        Err(recovery) => format!("{error} {recovery}"),
                    });
                }
                #[cfg(not(target_os = "windows"))]
                let _ = eject_usb_target(&revalidated.device_identifier);
                #[cfg(not(target_os = "windows"))]
                return Err(error);
            }
        };
        #[cfg(target_os = "windows")]
        let ejected = recover_windows_usb_target(&revalidated)?;
        #[cfg(not(target_os = "windows"))]
        let ejected = eject_usb_target(&revalidated.device_identifier);
        Ok(UsbWriteResult {
            status: "verified".into(),
            device_identifier,
            device_node,
            bytes_written: image_bytes,
            image_sha256: expected_sha256,
            verified_sha256,
            ejected,
            message: if ejected {
                if cfg!(target_os = "windows") {
                    "USB writing and byte-for-byte verification completed; Windows ejected the device."
                } else {
                    "USB writing and byte-for-byte verification completed; the device was ejected safely."
                }
            } else {
                "USB writing and byte-for-byte verification completed, but the operating system could not eject the device; use its safe-removal workflow before unplugging it."
            }
            .into(),
        })
    })
    .await;
    if let Ok(mut manager) = manager_state.lock() {
        manager.finish_write(&session_token);
    }
    worker.map_err(|error| format!("USB writer worker failed: {error}"))?
}

#[cfg(test)]
mod windows_usb_inventory_tests {
    use super::*;

    #[test]
    fn accepts_only_exact_capacity_eligible_usb_physical_drives() {
        // PowerShell ConvertTo-Json escapes each backslash in the canonical
        // Win32_DiskDrive DeviceID. Keep this as wire-format JSON so the test
        // covers decoding as well as the exact identity comparison.
        let json = br#"[{"FriendlyName":"USB Drive","BusType":"USB","MediaType":"Removable Media","SerialNumber":"SERIAL-3","Size":16000000000,"BytesPerSector":512,"UniqueId":"USBSTOR\\DISK&VEN_TEST","Index":3,"IsBoot":false,"IsSystem":false,"IsReadOnly":false,"IsOffline":false},{"FriendlyName":"Internal","BusType":"NVMe","MediaType":"Fixed hard disk media","SerialNumber":"SERIAL-0","Size":1000000000000,"BytesPerSector":512,"UniqueId":"PCI\\INTERNAL","Index":0,"IsBoot":true,"IsSystem":true,"IsReadOnly":false,"IsOffline":false},{"FriendlyName":"Too small","BusType":"USB","MediaType":"Removable Media","SerialNumber":"SERIAL-4","Size":1024,"BytesPerSector":512,"UniqueId":"USBSTOR\\SMALL","Index":4,"IsBoot":false,"IsSystem":false,"IsReadOnly":false,"IsOffline":false}]"#;
        let targets = usb_candidates_from_windows_json(json, 8 * 1024 * 1024).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].device_identifier, "PhysicalDrive3");
        assert_eq!(targets[0].device_node, r"\\.\PHYSICALDRIVE3");
        assert_eq!(&targets[0].device_node.as_bytes()[..4], b"\\\\.\\");
        assert_eq!(targets[0].bus_protocol, "USB");
        assert_eq!(targets[0].identity_token.len(), 64);
    }

    #[test]
    fn empty_replug_and_hostile_windows_inventories_fail_safely() {
        assert!(usb_candidates_from_windows_json(b"null", 512)
            .unwrap()
            .is_empty());
        assert!(usb_candidates_from_windows_json(b"[]", 512)
            .unwrap()
            .is_empty());
        assert!(usb_candidates_from_windows_json(b"not-json", 512)
            .unwrap_err()
            .contains("malformed"));
        let boot = br#"{"FriendlyName":"USB Boot","BusType":"USB","MediaType":"Removable Media","SerialNumber":"SERIAL-8","Size":4096,"BytesPerSector":512,"UniqueId":"USBSTOR\\BOOT","Index":8,"IsBoot":true,"IsSystem":false,"IsReadOnly":false,"IsOffline":false}"#;
        assert!(usb_candidates_from_windows_json(boot, 512)
            .unwrap()
            .is_empty());
        let missing_identity = br#"{"FriendlyName":"No identity","BusType":"USB","MediaType":"Removable Media","SerialNumber":"","Size":4096,"BytesPerSector":512,"UniqueId":"","Index":2,"IsBoot":false,"IsSystem":false,"IsReadOnly":false,"IsOffline":false}"#;
        assert!(usb_candidates_from_windows_json(missing_identity, 512)
            .unwrap()
            .is_empty());
        for field in ["IsBoot", "IsSystem", "IsReadOnly", "IsOffline"] {
            let mut value: serde_json::Value = serde_json::from_slice(br#"{"FriendlyName":"Guarded","BusType":"USB","MediaType":"Removable Media","SerialNumber":"SERIAL-2","Size":4096,"BytesPerSector":512,"UniqueId":"USBSTOR\\SAFE","Index":2,"IsBoot":false,"IsSystem":false,"IsReadOnly":false,"IsOffline":false}"#).unwrap();
            value[field] = serde_json::Value::Bool(true);
            assert!(
                usb_candidates_from_windows_json(&serde_json::to_vec(&value).unwrap(), 512)
                    .unwrap()
                    .is_empty()
            );
        }
        let fixed = br#"{"FriendlyName":"Fixed USB","BusType":"USB","MediaType":"Fixed hard disk media","SerialNumber":"SERIAL-2","Size":4096,"BytesPerSector":512,"UniqueId":"USBSTOR\\SAFE","Index":2,"IsBoot":false,"IsSystem":false,"IsReadOnly":false,"IsOffline":false}"#;
        assert!(usb_candidates_from_windows_json(fixed, 512)
            .unwrap()
            .is_empty());

        let duplicate = br#"[{"FriendlyName":"USB A","BusType":"USB","MediaType":"Removable Media","SerialNumber":"SAME-SERIAL","Size":4096,"BytesPerSector":512,"UniqueId":"USBSTOR\\SAME","Index":2,"IsBoot":false,"IsSystem":false,"IsReadOnly":false,"IsOffline":false},{"FriendlyName":"USB B","BusType":"USB","MediaType":"Removable Media","SerialNumber":"SAME-SERIAL","Size":4096,"BytesPerSector":512,"UniqueId":"USBSTOR\\SAME","Index":3,"IsBoot":false,"IsSystem":false,"IsReadOnly":false,"IsOffline":false}]"#;
        assert!(usb_candidates_from_windows_json(duplicate, 512)
            .unwrap()
            .is_empty());

        let original = br#"{"FriendlyName":"USB","BusType":"USB","MediaType":"Removable Media","SerialNumber":"SERIAL-A","Size":4096,"BytesPerSector":512,"UniqueId":"USBSTOR\\A","Index":2,"IsBoot":false,"IsSystem":false,"IsReadOnly":false,"IsOffline":false}"#;
        let changed = br#"{"FriendlyName":"USB","BusType":"USB","MediaType":"Removable Media","SerialNumber":"SERIAL-B","Size":4096,"BytesPerSector":512,"UniqueId":"USBSTOR\\B","Index":2,"IsBoot":false,"IsSystem":false,"IsReadOnly":false,"IsOffline":false}"#;
        let original = usb_candidates_from_windows_json(original, 512).unwrap();
        let changed = usb_candidates_from_windows_json(changed, 512).unwrap();
        assert_ne!(original[0].identity_token, changed[0].identity_token);
    }

    #[test]
    fn windows_disk_identifiers_accept_only_bounded_physical_drive_numbers() {
        assert_eq!(windows_disk_number("PhysicalDrive0").unwrap(), 0);
        assert_eq!(windows_disk_number("PhysicalDrive1024").unwrap(), 1024);
        for identifier in [
            "",
            "PhysicalDrive",
            "physicaldrive4",
            "PhysicalDrive-1",
            "PhysicalDrive4\\..\\0",
            "PhysicalDrive1025",
            r"\\.\PHYSICALDRIVE4",
        ] {
            assert!(windows_disk_number(identifier).is_err(), "{identifier}");
        }
    }

    #[test]
    fn windows_usb_write_intent_binds_exact_physical_drive_shape() {
        let target = UsbTargetCandidate {
            device_identifier: "PhysicalDrive4".into(),
            device_node: r"\\.\PHYSICALDRIVE4".into(),
            media_name: "Removable USB".into(),
            bus_protocol: "USB".into(),
            bytes: 31_264_289_280,
            block_size: 512,
            identity_token: "a".repeat(64),
        };
        validate_usb_write_intent(
            &target,
            8_120_172_544,
            "PhysicalDrive4",
            &target.identity_token,
            "ERASE PhysicalDrive4",
        )
        .expect("exact Windows whole-disk intent");
        for (identifier, phrase) in [
            ("PhysicalDrive04", "ERASE PhysicalDrive04"),
            ("physicaldrive4", "ERASE physicaldrive4"),
            (
                "PhysicalDrive4\\Partition1",
                "ERASE PhysicalDrive4\\Partition1",
            ),
            ("PhysicalDrive4", "ERASE PhysicalDrive5"),
        ] {
            assert!(validate_usb_write_intent(
                &target,
                8_120_172_544,
                identifier,
                &target.identity_token,
                phrase,
            )
            .is_err());
        }
    }

    #[test]
    fn exact_disk_volume_extents_include_lettered_and_unlettered_and_exclude_foreign() {
        let selected = 7;
        let fixtures = [
            ("lettered-data", vec![selected]),
            ("unlettered-efi", vec![selected]),
            ("foreign-system", vec![0]),
        ];
        let selected_names = fixtures
            .iter()
            .filter_map(|(name, disks)| {
                windows_volume_belongs_exclusively_to_disk(disks, selected)
                    .unwrap()
                    .then_some(*name)
            })
            .collect::<Vec<_>>();
        assert_eq!(selected_names, ["lettered-data", "unlettered-efi"]);
        assert!(windows_volume_belongs_exclusively_to_disk(&[selected, 0], selected).is_err());
        assert!(windows_volume_belongs_exclusively_to_disk(&[], selected).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires an explicitly provisioned disposable multi-volume Windows test disk"]
    fn windows_native_disposable_volumes_lock_dismount_refuse_busy_file_and_release_on_failure() {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        let disk_number = std::env::var("OPEMOS_TEST_WINDOWS_DISPOSABLE_DISK_NUMBER")
            .expect("disposable disk number is required")
            .parse::<u32>()
            .expect("disposable disk number must be numeric");
        let busy_file = PathBuf::from(
            std::env::var_os("OPEMOS_TEST_WINDOWS_DISPOSABLE_BUSY_FILE")
                .expect("disposable busy-file path is required"),
        );

        let busy = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&busy_file)
            .expect("the disposable busy file must open");
        let error = lock_windows_disk_volumes(disk_number)
            .expect_err("an open file must prevent exclusive volume locking");
        assert!(error.contains("could not lock selected-disk volume GUID"));
        drop(busy);

        let reacquired = lock_windows_disk_volumes(disk_number).expect(
            "all prior volume locks must be released, then every volume must lock and dismount",
        );
        assert!(
            reacquired.len() >= 2,
            "the native regression requires two disposable volumes"
        );
    }

    #[test]
    fn helper_dispatch_precedes_portable_runtime_initialization() {
        let source = include_str!("main.rs");
        let helper = source
            .find("run_windows_usb_writer_helper")
            .expect("helper dispatch");
        let runtime = source
            .find("activate_runtime_bundle")
            .expect("runtime setup");
        let state = source.find("prepare_portable_state").expect("state setup");
        assert!(helper < runtime && helper < state);
    }

    #[test]
    fn elevated_receipt_requires_exact_success_exit_request_and_image_digest() {
        let request_sha256 = "1".repeat(64);
        let image_sha256 = "a".repeat(64);
        let receipt = |request: &str, success: bool, verified: &str, ejected: bool, error: &str| {
            serde_json::to_vec(&WindowsUsbWriterReceipt {
                schema_version: 1,
                request_sha256: request.into(),
                success,
                verified_sha256: verified.into(),
                ejected,
                error: error.into(),
            })
            .unwrap()
        };

        let valid = receipt(&request_sha256, true, &image_sha256, true, "");
        let accepted =
            validate_windows_usb_writer_receipt(&valid, 0, &request_sha256, &image_sha256)
                .expect("exact successful receipt");
        assert_eq!(accepted.verified_sha256, image_sha256);

        for (bytes, status) in [
            (b"not-json".to_vec(), 0),
            (receipt(&"2".repeat(64), true, &image_sha256, true, ""), 0),
            (receipt(&request_sha256, true, &"b".repeat(64), true, ""), 0),
            (valid.clone(), 9),
            (
                receipt(&request_sha256, false, &image_sha256, true, "failed"),
                1,
            ),
            (receipt(&request_sha256, false, "", false, ""), 1),
        ] {
            assert!(validate_windows_usb_writer_receipt(
                &bytes,
                status,
                &request_sha256,
                &image_sha256,
            )
            .is_err());
        }
    }

    #[test]
    fn same_number_identity_replacement_is_not_eligible_for_windows_recovery() {
        let original = UsbTargetCandidate {
            device_identifier: "PhysicalDrive4".into(),
            device_node: r"\\.\PHYSICALDRIVE4".into(),
            media_name: "Removable USB".into(),
            bus_protocol: "USB".into(),
            bytes: 31_264_289_280,
            block_size: 512,
            identity_token: "a".repeat(64),
        };
        let mut replacement = original.clone();
        replacement.identity_token = "b".repeat(64);
        assert!(!windows_usb_recovery_identity_is_unchanged(
            &original,
            &replacement
        ));
        assert!(windows_usb_recovery_identity_is_unchanged(
            &original, &original
        ));
    }
}

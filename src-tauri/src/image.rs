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
    let read_only = run_guest_command(
        session,
        "set -eu; DEVICE=/dev/disk/by-id/virtio-steamos-user-input; test -b \"$DEVICE\"; sudo blockdev --getro \"$DEVICE\"",
    )? == "1";
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

pub(crate) fn mutate_user_marker(
    session: &ImageInspectionSession,
) -> Result<UserMarkerMutation, String> {
    const MARKER_PATH: &str = "/etc/steamos-nvidia-image-builder-test";
    const MARKER_CONTENT: &str =
        "SteamOS NVIDIA Image Builder marker\nprotocol=1\nmilestone=marker-only\n";
    const PREFLIGHT_COMMAND: &str = r#"set -eu
SOURCE=/dev/disk/by-id/virtio-steamos-user-input
WORK=/dev/disk/by-id/virtio-steamos-user-working
test -b "$SOURCE"
test -b "$WORK"
test "$(sudo blockdev --getro "$SOURCE")" = 1
test "$(sudo blockdev --getro "$WORK")" = 0
if lsblk -nr -o MOUNTPOINTS "$SOURCE" | grep -q '[^[:space:]]' || lsblk -nr -o MOUNTPOINTS "$WORK" | grep -q '[^[:space:]]'; then
  echo 'A selected-image device was unexpectedly mounted before mutation.' >&2
  exit 1
fi"#;
    run_guest_command(session, PREFLIGHT_COMMAND)?;
    qmp_remove_user_input(session)?;
    const MUTATE_COMMAND: &str = r#"set -eu
SOURCE=/dev/disk/by-id/virtio-steamos-user-input
WORK=/dev/disk/by-id/virtio-steamos-user-working
MOUNT_DIR=/mnt/steamos-user-marker
EXPECTED=$(printf 'SteamOS NVIDIA Image Builder marker\nprotocol=1\nmilestone=marker-only')
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
    let output = run_guest_command(session, MUTATE_COMMAND)?;
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

pub(crate) fn output_path_for_input(
    input: &Path,
    nvidia_installed: bool,
) -> Result<PathBuf, String> {
    let parent = input
        .parent()
        .ok_or("Could not determine the selected image folder.")?;
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
        let Some(suffix) = suffix else { break };
        base.truncate(base.len() - suffix.len());
    }
    if base.is_empty() {
        base = "SteamOS".into();
    }
    let output_base = format!(
        "{base}-{}",
        if nvidia_installed { "nvidia" } else { "marker" }
    );
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

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HostVolumeSpace {
    filesystem: String,
    available_bytes: u64,
}

pub(crate) fn host_volume_space(path: &Path) -> Result<HostVolumeSpace, String> {
    let output = Command::new("df")
        .args(["-P", "-k"])
        .arg(path)
        .output()
        .map_err(|error| format!("Could not measure host filesystem space: {error}"))?;
    if !output.status.success() {
        return Err("Could not measure host filesystem space with df.".into());
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "Host filesystem-space report was not valid UTF-8.")?;
    let fields: Vec<_> = stdout
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .ok_or("Host filesystem-space report was empty.")?
        .split_whitespace()
        .collect();
    if fields.len() < 6 {
        return Err("Host filesystem-space report had an unexpected format.".into());
    }
    let available_bytes = fields[fields.len() - 3]
        .parse::<u64>()
        .ok()
        .and_then(|blocks| blocks.checked_mul(1024))
        .ok_or_else(|| {
            "Host filesystem-space report contained an invalid byte count.".to_string()
        })?;
    Ok(HostVolumeSpace {
        filesystem: fields[0].to_string(),
        available_bytes,
    })
}

pub(crate) fn host_available_bytes(path: &Path) -> Result<u64, String> {
    Ok(host_volume_space(path)?.available_bytes)
}

pub(crate) fn require_host_space(
    available: u64,
    required: u64,
    purpose: &str,
) -> Result<(), String> {
    if available >= required {
        return Ok(());
    }
    Err(format!(
        "Host disk-space preflight failed before guest startup: {purpose} needs at least {} ({required} bytes) free, but only {} ({available} bytes) is available.",
        human_bytes(required),
        human_bytes(available),
    ))
}

pub(crate) fn preflight_host_build_space(
    runtime_dir: &Path,
    input_image: &Path,
    image_bytes: u64,
) -> Result<(), String> {
    let output_parent = input_image
        .parent()
        .ok_or("Could not determine the future output folder.")?;
    let output_parent = fs::canonicalize(output_parent)
        .map_err(|error| format!("Could not resolve the future output folder: {error}"))?;
    let runtime = host_volume_space(runtime_dir)?;
    let output = host_volume_space(&output_parent)?;
    let runtime_required = checked_space_sum([image_bytes, HOST_RUNTIME_FREE_SPACE_RESERVE])?;
    let output_required = checked_space_sum([image_bytes, HOST_OUTPUT_FREE_SPACE_RESERVE])?;

    if runtime.filesystem == output.filesystem {
        let required = checked_space_sum([runtime_required, output_required])?;
        require_host_space(
            runtime.available_bytes,
            required,
            "the shared runtime/output volume",
        )
    } else {
        require_host_space(
            runtime.available_bytes,
            runtime_required,
            "the runtime volume (working overlay and temporary build data)",
        )?;
        require_host_space(
            output.available_bytes,
            output_required,
            "the output volume (final raw image and export reserve)",
        )
    }
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
        return Err(format!(
            "The output path already exists: {}",
            resolved_output.display()
        ));
    }
    if required_bytes > 0 {
        let available = host_available_bytes(&resolved_parent)?;
        if available < required_bytes {
            return Err(format!(
                "The output folder needs at least {required_bytes} free bytes; only {available} are available."
            ));
        }
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
        return Err(if detail.trim().is_empty() {
            format!("Raw-image export failed with {status}.")
        } else {
            format!("Raw-image export failed: {}", detail.trim())
        });
    }
    if let Some(progress) = progress {
        progress("exporting-image", virtual_bytes, virtual_bytes);
    }
    let output =
        File::open(destination).map_err(|e| format!("Could not open the exported image: {e}"))?;
    output
        .sync_all()
        .map_err(|e| format!("Could not flush the exported image: {e}"))
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

pub(crate) fn verify_nvidia_from_validation_overlay(
    session: &ImageInspectionSession,
    installation: &NvidiaInstallHandoffResult,
) -> Result<(), String> {
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
    let command = format!(
        r#"set -euo pipefail
WORK=/dev/disk/by-id/virtio-steamos-user-working
ROOT=/mnt/steamos-nvidia-export-root
test -b "$WORK"
test "$(sudo blockdev --getro "$WORK")" = 1
mapfile -t ROOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "rootfs-A" && $3 == "btrfs" {{print $1}}')
mapfile -t BOOT_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "efi-A" && ($3 == "vfat" || $3 == "fat") {{print $1}}')
mapfile -t VAR_PARTS < <(lsblk -nrpo PATH,PARTLABEL,FSTYPE "$WORK" | awk '$2 == "var-A" && $3 == "ext4" {{print $1}}')
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
  trap - EXIT INT TERM
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
awk '
BEGIN {{
  required[1]="rd.driver.blacklist=nouveau"
  required[2]="modprobe.blacklist=nouveau"
  required[3]="nvidia-drm.modeset=1"
  required[4]="nvidia-drm.fbdev=1"
  for (index=1; index<=4; index++) {{
    key[index]=required[index]
    sub(/=.*/, "", key[index])
  }}
}}
/^[[:space:]]*(steamenv_boot[[:space:]]+)?(linux|linuxefi|linux16)[[:space:]]+/ {{
  entries++
  delete count
  for (field=1; field<=NF; field++) {{
    if ($field ~ /^#/) break
    token_key=$field
    sub(/=.*/, "", token_key)
    for (index=1; index<=4; index++) {{
      if (token_key == key[index]) {{
        if ($field != required[index]) invalid=1
        count[index]++
      }}
    }}
  }}
  for (index=1; index<=4; index++) if (count[index] != 1) invalid=1
}}
END {{ if (entries == 0 || invalid) exit 1 }}
' "$GRUB"
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
        installation.kernel_version,
        installation.nvidia_version,
        installation.kernel_version,
        installation.kernel_version,
        installation.nvidia_version,
        installation.provenance_sha256,
        installation.nvidia_version,
        installation.pacman_database_path,
        package_assertions,
    );
    run_guest_command(session, &command).map(|_| ())
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

pub(crate) fn export_marker_image_blocking(app: tauri::AppHandle) -> Result<ExportedImage, String> {
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
        let final_path =
            output_path_for_input(&session.input_image, nvidia_installation.is_some())?;
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
        fs::rename(&partial_path, &final_path)
            .map_err(|e| format!("Could not finalize the exported image: {e}"))?;
        if let Err(error) = fs::rename(&partial_manifest_path, &final_manifest_path) {
            let rollback = fs::rename(&final_path, &partial_path);
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
        let _ = Command::new("open").arg("-R").arg(&final_path).spawn();
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
pub(crate) async fn export_marker_image(app: tauri::AppHandle) -> Result<ExportedImage, String> {
    tauri::async_runtime::spawn_blocking(move || export_marker_image_blocking(app))
        .await
        .map_err(|error| format!("Image export worker failed: {error}"))?
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
pub(crate) fn preview_image_output(path: String) -> Result<ImageOutputPreview, String> {
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
    let output = output_path_for_input(&canonical, true)?;
    Ok(ImageOutputPreview {
        input_path: canonical.to_string_lossy().into_owned(),
        output_path: output.to_string_lossy().into_owned(),
    })
}

pub(crate) fn usb_candidate_from_diskutil_info(
    info: &serde_json::Value,
    image_bytes: u64,
) -> Option<UsbTargetCandidate> {
    let object = info.as_object()?;
    let identifier = object.get("DeviceIdentifier")?.as_str()?;
    if !identifier.starts_with("disk")
        || identifier.len() <= 4
        || !identifier[4..].bytes().all(|byte| byte.is_ascii_digit())
        || object.get("Whole").and_then(|value| value.as_bool()) != Some(true)
        || object.get("Internal").and_then(|value| value.as_bool()) != Some(false)
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
    Some(UsbTargetCandidate {
        device_identifier: identifier.into(),
        device_node: device_node.into(),
        media_name: object
            .get("MediaName")
            .and_then(|value| value.as_str())
            .unwrap_or("External removable media")
            .chars()
            .take(120)
            .collect(),
        bus_protocol: object
            .get("BusProtocol")
            .and_then(|value| value.as_str())
            .unwrap_or("Unknown")
            .chars()
            .take(40)
            .collect(),
        bytes,
    })
}

#[cfg(target_os = "macos")]
fn plist_command_json(
    mut command: Command,
    description: &str,
) -> Result<serde_json::Value, String> {
    let plist = command
        .output()
        .map_err(|error| format!("Could not {description}: {error}"))?;
    if !plist.status.success() || plist.stdout.len() > 4 * 1024 * 1024 {
        return Err(format!(
            "Could not {description}; diskutil returned an invalid response."
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
    list_command.args(["list", "external", "physical", "-plist"]);
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
        if let Some(target) = usb_candidate_from_diskutil_info(&info, image_bytes) {
            targets.push(target);
        }
    }
    targets.sort_by(|left, right| left.device_identifier.cmp(&right.device_identifier));
    Ok(targets)
}

#[cfg(not(target_os = "macos"))]
fn discover_usb_targets(_image_bytes: u64) -> Result<Vec<UsbTargetCandidate>, String> {
    Err("Read-only USB target discovery is currently implemented only for macOS.".into())
}

#[tauri::command]
pub(crate) async fn inspect_usb_targets(image_path: String) -> Result<UsbTargetPreflight, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let image = fs::canonicalize(&image_path)
            .map_err(|error| format!("Could not resolve the completed image: {error}"))?;
        if image.extension().and_then(|value| value.to_str()) != Some("img") {
            return Err("USB preparation requires a raw .img output.".into());
        }
        let metadata = fs::metadata(&image)
            .map_err(|error| format!("Could not inspect the completed image: {error}"))?;
        if !metadata.is_file() {
            return Err("The completed image is not a regular file.".into());
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
        let filename = image.file_name().and_then(|value| value.to_str()).unwrap_or("");
        let manifest_bytes = output.get("bytes").and_then(|value| value.as_u64());
        let sha256 = output.get("sha256").and_then(|value| value.as_str()).unwrap_or("");
        if output.get("filename").and_then(|value| value.as_str()) != Some(filename)
            || output.get("format").and_then(|value| value.as_str()) != Some("raw")
            || manifest_bytes != Some(metadata.len())
            || sha256.len() != 64
            || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("The image and adjacent build manifest do not have a valid matching output identity.".into());
        }
        let targets = discover_usb_targets(metadata.len())?;
        Ok(UsbTargetPreflight {
            image_path: image.to_string_lossy().into_owned(),
            image_bytes: metadata.len(),
            image_sha256: sha256.to_ascii_lowercase(),
            targets,
            writes_allowed: false,
            message: "Read-only discovery complete. Direct disk writes remain disabled; select a target only for review.".into(),
        })
    })
    .await
    .map_err(|error| format!("USB target discovery worker failed: {error}"))?
}

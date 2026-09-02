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
    output_path_for_input_label(input, if nvidia_installed { "nvidia" } else { "marker" })
}

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
    output_path_for_input_label(input, &format!("nvidia-{nvidia_version}"))
}

fn output_path_for_input_label(input: &Path, output_label: &str) -> Result<PathBuf, String> {
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
    let recovery_desktop_sha256 = format!("{:x}", Sha256::digest(RECOVERY_ROLLBACK_DESKTOP));
    let welcome_sha256 = format!("{:x}", Sha256::digest(INSTALL_MEDIA_WELCOME));
    let welcome_helper_sha256 = format!("{:x}", Sha256::digest(INSTALL_MEDIA_HELPER));
    let welcome_desktop_sha256 = format!("{:x}", Sha256::digest(INSTALL_MEDIA_DESKTOP));
    let welcome_icon_sha256 = format!("{:x}", Sha256::digest(INSTALL_MEDIA_ICON));
    let welcome_gtk_css_sha256 = format!("{:x}", Sha256::digest(INSTALL_MEDIA_GTK_CSS));
    let mut install_media_support_assertions = String::new();
    for file in &PINNED_INSTALLER_FILES {
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
test -f "$ROOT/home/deck/Desktop/OPEMOS-Rollback.desktop"
test ! -L "$ROOT/home/deck/Desktop/OPEMOS-Rollback.desktop"
test "$(sha256sum "$ROOT/home/deck/Desktop/OPEMOS-Rollback.desktop" | awk '{{print $1}}')" = "{}"
test "$(stat -c '%a' "$ROOT/home/deck/Desktop/OPEMOS-Rollback.desktop")" = 755
test "$(stat -c '%u:%g' "$ROOT/home/deck/Desktop/OPEMOS-Rollback.desktop")" = "$DECK_ID"
test -f "$ROOT/home/deck/tools/open-opemos-welcome"
test ! -L "$ROOT/home/deck/tools/open-opemos-welcome"
test "$(sha256sum "$ROOT/home/deck/tools/open-opemos-welcome" | awk '{{print $1}}')" = "{}"
test "$(stat -c '%a' "$ROOT/home/deck/tools/open-opemos-welcome")" = 755
test "$(stat -c '%u:%g' "$ROOT/home/deck/tools/open-opemos-welcome")" = "$DECK_ID"
for DESKTOP in "$ROOT/home/deck/Desktop/Open-OPEMOS.desktop" "$ROOT/home/deck/.config/autostart/Open-OPEMOS.desktop"; do
  test -f "$DESKTOP"
  test ! -L "$DESKTOP"
  test "$(sha256sum "$DESKTOP" | awk '{{print $1}}')" = "{}"
  test "$(stat -c '%a' "$DESKTOP")" = 644
  test "$(stat -c '%u:%g' "$DESKTOP")" = "$DECK_ID"
done
test -f "$ROOT/home/deck/.local/share/icons/hicolor/scalable/apps/opemos.svg"
test ! -L "$ROOT/home/deck/.local/share/icons/hicolor/scalable/apps/opemos.svg"
test "$(sha256sum "$ROOT/home/deck/.local/share/icons/hicolor/scalable/apps/opemos.svg" | awk '{{print $1}}')" = "{}"
test "$(stat -c '%a' "$ROOT/home/deck/.local/share/icons/hicolor/scalable/apps/opemos.svg")" = 644
test "$(stat -c '%u:%g' "$ROOT/home/deck/.local/share/icons/hicolor/scalable/apps/opemos.svg")" = "$DECK_ID"
test -f "$ROOT/usr/lib/opemos-install-media/opemos-install-helper"
test ! -L "$ROOT/usr/lib/opemos-install-media/opemos-install-helper"
test "$(sha256sum "$ROOT/usr/lib/opemos-install-media/opemos-install-helper" | awk '{{print $1}}')" = "{}"
test "$(stat -c '%a:%u:%g' "$ROOT/usr/lib/opemos-install-media/opemos-install-helper")" = 755:0:0
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
for DIRECTORY in "$ROOT/usr/share" "$ROOT/usr/share/opemos-install-media" "$ROOT/usr/share/opemos-install-media/ui" "$ROOT/usr/share/opemos-install-media/ui/gtk-3.0"; do
  test -d "$DIRECTORY"
  test ! -L "$DIRECTORY"
done
test -f "$ROOT/usr/share/opemos-install-media/ui/gtk-3.0/gtk.css"
test ! -L "$ROOT/usr/share/opemos-install-media/ui/gtk-3.0/gtk.css"
test "$(sha256sum "$ROOT/usr/share/opemos-install-media/ui/gtk-3.0/gtk.css" | awk '{{print $1}}')" = "{}"
test "$(stat -c '%a:%u:%g' "$ROOT/usr/share/opemos-install-media/ui/gtk-3.0/gtk.css")" = 644:0:0
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
        recovery_desktop_sha256,
        welcome_sha256,
        welcome_desktop_sha256,
        welcome_icon_sha256,
        welcome_helper_sha256,
        NVIDIA_SUPPORT_COMMIT,
        installation.nvidia_version,
        welcome_gtk_css_sha256,
        install_media_support_assertions,
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

pub(crate) fn export_marker_image_blocking(
    app: tauri::AppHandle,
    reveal_in_finder: bool,
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
            Some(installation) => {
                output_path_for_nvidia_version(&session.input_image, &installation.nvidia_version)?
            }
            None => output_path_for_input(&session.input_image, false)?,
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
        if reveal_in_finder {
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
#[cfg(not(target_os = "macos"))]
pub(crate) fn physical_usb_writes_allowed() -> bool {
    false
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
                    "The confirmed USB intent session is active. macOS will request permission to open only the revalidated raw device when writing begins."
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
}

pub(crate) fn copy_and_verify_usb_image(
    image: &Path,
    target: &mut File,
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
    if let Err(error) = target.sync_all() {
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

#[cfg(not(target_os = "macos"))]
fn discover_usb_targets(_image_bytes: u64) -> Result<Vec<UsbTargetCandidate>, String> {
    Err("Read-only USB target discovery is currently implemented only for macOS.".into())
}

#[cfg(not(target_os = "macos"))]
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
    if !requested_identifier.starts_with("disk")
        || requested_identifier.len() <= 4
        || !requested_identifier[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err("The selected device identifier is invalid.".into());
    }
    let expected_confirmation = format!("ERASE {requested_identifier}");
    if confirmation != expected_confirmation {
        return Err(format!(
            "Type {expected_confirmation} exactly to confirm the selected whole disk."
        ));
    }
    if target.device_identifier != requested_identifier
        || target.device_node != format!("/dev/{requested_identifier}")
    {
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
        let writes_allowed = physical_usb_writes_allowed();
        Ok(UsbTargetPreflight {
            image_path: image.to_string_lossy().into_owned(),
            image_bytes,
            image_sha256,
            targets,
            writes_allowed,
            message: if writes_allowed {
                "Eligible removable drives are shown. The image and exact device will be revalidated before macOS requests permission to open it."
            } else {
                "Read-only discovery complete. Physical USB writing is not available on this platform yet."
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
        Ok(UsbTargetPreflight {
            image_path: input.to_string_lossy().into_owned(),
            image_bytes: minimum_bytes,
            image_sha256: String::new(),
            targets,
            writes_allowed: false,
            message: if format == InputFormat::Raw {
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
                "macOS will request permission for only the selected raw device when writing begins."
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
fn open_usb_raw_device(target: &UsbTargetCandidate, cancel: &AtomicBool) -> Result<File, String> {
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
    Ok(file)
}

#[cfg(not(target_os = "macos"))]
fn unmount_usb_target(_identifier: &str) -> Result<(), String> {
    Err("USB writing is currently implemented only for macOS.".into())
}

#[cfg(not(target_os = "macos"))]
fn eject_usb_target(_identifier: &str) -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
fn remount_usb_target(_identifier: &str) -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
fn open_usb_raw_device(_target: &UsbTargetCandidate, _cancel: &AtomicBool) -> Result<File, String> {
    Err("USB writing is currently implemented only for macOS.".into())
}

#[tauri::command]
pub(crate) async fn write_image_to_usb(
    app: tauri::AppHandle,
    session_token: String,
    image_path: String,
) -> Result<UsbWriteResult, String> {
    if !physical_usb_writes_allowed() {
        return Err("Physical USB writing is not available on this platform yet.".into());
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
                message: "Waiting for macOS permission to open only the selected raw device."
                    .into(),
            },
        );
        let mut device = match open_usb_raw_device(&revalidated, &cancel) {
            Ok(device) => device,
            Err(error) => {
                let _ = remount_usb_target(&revalidated.device_identifier);
                return Err(error);
            }
        };
        let opened_target = match revalidate_usb_target(&revalidated.device_identifier, image_bytes)
        {
            Ok(target) => target,
            Err(error) => {
                drop(device);
                let _ = remount_usb_target(&revalidated.device_identifier);
                return Err(error);
            }
        };
        if opened_target.identity_token != revalidated.identity_token {
            drop(device);
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
        let verified_sha256 = match copy_result {
            Ok(sha256) => sha256,
            Err(error) => {
                let _ = eject_usb_target(&revalidated.device_identifier);
                return Err(error);
            }
        };
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
                "USB writing and byte-for-byte verification completed; the device was ejected safely."
            } else {
                "USB writing and byte-for-byte verification completed. macOS could not eject the device automatically."
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

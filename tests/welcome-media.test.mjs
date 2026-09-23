import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const helper = readFileSync("builder/welcome/opemos-install-helper", "utf8");
const welcome = readFileSync("builder/welcome/open-opemos-welcome", "utf8");
const desktop = readFileSync("builder/welcome/Open-OPEMOS.desktop", "utf8");
const gtkCss = readFileSync("builder/welcome/gtk.css", "utf8");
const controller = readFileSync("builder/welcome/welcome_server.py", "utf8");
const application = readFileSync("builder/welcome/app.js", "utf8");

test("installation-media UI delegates only bounded operations", () => {
  assert.match(desktop, /^Name=Install SteamOS with NVIDIA drivers$/m);
  assert.match(desktop, /^Terminal=false$/m);
  assert.match(desktop, /^X-KDE-AutostartScript=true$/m);
  assert.match(welcome, /SteamOS with NVIDIA drivers/);
  assert.match(welcome, /Maintained by OPEMOS/);
  assert.match(welcome, /run_install all/);
  assert.match(welcome, /run_install system/);
  assert.match(welcome, /Do not power off the computer or disconnect either drive/);
  assert.match(welcome, /Diagnostics — review media identity/);
  assert.match(welcome, /last-install-log/);
  assert.match(welcome, /flock -n 8/);
  assert.match(welcome, /welcome-startup\.log/);
  assert.match(welcome, /installer is already running/);
  assert.match(welcome, /before a stable window opened/);
  assert.match(welcome, /--start-fullscreen/);
  assert.match(welcome, /welcome_server\.py/);
  assert.match(welcome, /TRUE shutdown/);
  assert.match(welcome, /FALSE restart/);
  assert.match(welcome, /restart\) systemctl reboot/);
  assert.match(welcome, /remove the USB as the screen turns off/);
  assert.match(gtkCss, /linear-gradient\(to right, @opemos_blue, @opemos_green\)/);
  assert.doesNotMatch(welcome, /\beval\b/);
  assert.doesNotMatch(helper, /\beval\b/);
  assert.match(controller, /127\.0\.0\.1/);
  assert.match(controller, /X-OPEMOS-Token/);
  assert.match(controller, /self\.headers\.get\("Origin"\)/);
  assert.doesNotMatch(controller, /shell\s*=\s*True/);
  assert.match(application, /The installer cannot close while disk mutation is active/);
});

test("install helper binds and revalidates a physical device identity", () => {
  assert.match(helper, /is_recovery_disk "\$device"/);
  assert.match(helper, /lsblk -snrpo PATH,TYPE "\$resolved"/);
  assert.match(helper, /mounted_child "\$device"/);
  assert.match(helper, /blockdev --getsize64/);
  assert.match(helper, /disk_identity "\$device"/);
  assert.match(helper, /selected disk identity changed immediately before installation/);
  assert.match(helper, /flock -n 9/);
  assert.match(helper, /case "\$mode" in all\|system/);
  assert.match(helper, /layout=fresh/);
  assert.match(helper, /"\$mode" != system.*has_exact_steamos_layout/);
  assert.match(helper, /count=\$\(lsblk -nrpo PARTN,PARTLABEL,TYPE "\$device"[\s\S]*\[\[ "\$count" == "\$\{#labels\[@\]\}" \]\] \|\| return 1/);
  assert.doesNotMatch(helper.match(/disk_status\(\) \{[\s\S]*?\n\}/)?.[0] || "", /FSTYPE|has_exact_steamos_layout/);
  assert.match(helper, /PARTN,PARTLABEL,TYPE/);
  assert.match(helper, /install_recovery_guardian_to_root\.sh/);
  assert.match(helper, /for slot in A B/);
  assert.match(helper, /--support-revision "\$support_revision"/);
  assert.match(helper, /media-info\)/);
  assert.match(helper, /verify_guardian_slot/);
  assert.match(helper, /installed recovery guardian verification failed/);
  assert.match(helper, /\$payload\/lib\/run_in_process_group\.py/);
  assert.match(helper, /\$payload\/lib\/payload_receipt\.py/);
  assert.match(helper, /\$payload\/lib\/atomic_output\.py/);
  assert.match(helper, /ui_stage "Installing the recovery guardian into rootfs-\$slot/);
});

test("guardian installation binds persistent home and slot-matched etc overlays with owned cleanup", () => {
  const lifecycle = helper.match(/install_guardian_slot\(\) \{[\s\S]*?\n\}\n\ninstall_to_disk/)?.[0] || "";
  assert.match(lifecycle, /partition_by_label "\$device" "rootfs-\$slot"/);
  assert.match(lifecycle, /partition_by_label "\$device" home/);
  assert.match(lifecycle, /partition_by_label "\$device" "var-\$slot"/);
  assert.doesNotMatch(lifecycle, /steamos-chroot[^\n]*steamos-readonly disable/);
  assert.match(lifecycle, /disable_readonly\(\)[\s\S]*mount -o rw "\$root_device" "\$root_mount"/);
  assert.match(lifecycle, /btrfs property set "\$root_mount" ro false/);
  assert.match(lifecycle, /if ! umount "\$root_mount"; then[\s\S]*btrfs property set "\$root_mount" ro true/);
  assert.match(lifecycle, /disable_readonly \|\| \{[\s\S]*could not disable read-only mode for rootfs-\$slot/);
  assert.match(lifecycle, /trap cleanup_guardian_installation EXIT INT TERM/);
  assert.match(lifecycle, /mount -o rw "\$root_device" "\$root_mount"/);
  assert.match(lifecycle, /mount -o rw "\$home_device" "\$home_mount"/);
  assert.match(lifecycle, /mount -o rw "\$var_device" "\$var_mount"/);
  assert.match(lifecycle, /etc_root=\$var_mount\/lib\/overlays\/etc\/upper/);
  assert.match(lifecycle, /--root "\$root_mount"/);
  assert.match(lifecycle, /--persistent-home-root "\$home_mount"/);
  assert.match(lifecycle, /--persistent-etc-root "\$etc_root"/);
  assert.match(lifecycle, /umount "\$var_mount"[\s\S]*umount "\$home_mount"[\s\S]*umount "\$root_mount"/);
  assert.match(lifecycle, /steamos-readonly status\)" == enabled \]\]; then\s+return 0/);
  assert.match(lifecycle, /restore_readonly\(\)[\s\S]*mount -o remount,rw \/ && steamos-readonly enable/);
  assert.equal(lifecycle.match(/restore_readonly/g)?.length, 3);
  assert.match(lifecycle, /restore_readonly \|\| \{[\s\S]*could not confirm read-only mode was restored/);
  assert.match(helper, /install_guardian_slot "\$device" "\$slot" "\$support_revision" "\$nvidia_version"/);
});

test("guardian verification reads shared payload and both slot-matched persistent etc overlays", () => {
  const verification = helper.match(/verify_guardian_slot\(\) \{[\s\S]*?\n\}\n\ninstall_guardian_slot/)?.[0] || "";
  assert.match(verification, /partition_by_label "\$device" home/);
  assert.match(verification, /partition_by_label "\$device" "var-\$slot"/);
  assert.match(verification, /mount -o ro,noload "\$home_device" "\$home_mount"/);
  assert.match(verification, /mount -o ro,noload "\$var_device" "\$var_mount"/);
  assert.match(verification, /payload=\$home_mount\/\.steamos\/open-gpu-kernel-modules-steamos-support\/recovery/);
  assert.match(verification, /units=\$var_mount\/lib\/overlays\/etc\/upper/);
  assert.match(verification, /Environment=HOME=\/root/);
  assert.match(verification, /recovery guardian verification failed for persistent slot-\$slot state/);
});

test("guarded patcher accepts the audited Valve contract without broad rewriting", (context) => {
  const directory = mkdtempSync(join(tmpdir(), "opemos-welcome-test-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const source = join(directory, "repair_device.sh");
  const output = join(directory, "protected-repair_device.sh");
  const fixture = `#!/bin/bash
DISK=/dev/nvme0n1
DISK_SUFFIX=p
prompt_reboot()
{
  local msg=$1
}
diskpart() { echo "$DISK$DISK_SUFFIX$1"; }
echo "$PARTITION_TABLE" | sfdisk "$DISK"
steamos-chroot --no-overlay --disk "$DISK"
  if [[ $writeOS = 1 ]]; then
    # Set up ESP/EFI boot partitions
    :
  fi
  # Stage a BIOS update for next reboot if updating OS. OOBE images like this one don't auto-update the bios on boot.
  if [[ $writeOS = 1 ]]; then
    :
  fi
  # Perform a controller update if updating OS.  OOBE images like this one don't auto-update controllers on boot.
  if [[ $writeOS = 1 ]]; then
    :
  fi
case all in
all)
  writeHome=1
  sanitize_all
  repair_steps
  ;;
esac
sleep infinity
sleep infinity
sleep infinity
sleep infinity
sleep infinity
`;
  writeFileSync(source, fixture);
  execFileSync("python3", ["builder/welcome/patch_repair_device.py", source, output]);
  execFileSync("bash", ["-n", output]);
  const patched = readFileSync(output, "utf8");
  assert.match(patched, /STEAMOS_TARGET_DISK:\?Open OPEMOS requires an explicit target disk/);
  assert.match(patched, /OPEMOS_SKIP_JUPITER_FIRMWARE/);
  assert.match(patched, /OPEMOS_FAIL_FAST/);
  assert.doesNotMatch(patched, /^DISK=\/dev\/nvme0n1$/m);
  assert.doesNotMatch(patched, /^  sanitize_all$/m);
});

test("guarded patcher rejects an unknown Valve installer shape", (context) => {
  const directory = mkdtempSync(join(tmpdir(), "opemos-welcome-reject-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const source = join(directory, "repair_device.sh");
  const output = join(directory, "protected-repair_device.sh");
  writeFileSync(source, "#!/bin/bash\nDISK=/dev/a-future-layout\n");
  const result = spawnSync(
    "python3",
    ["builder/welcome/patch_repair_device.py", source, output],
    { encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unsupported Valve installer structure/);
});

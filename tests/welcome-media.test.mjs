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

test("installation-media UI delegates only bounded operations", () => {
  assert.match(desktop, /^Name=Open OPEMOS$/m);
  assert.match(desktop, /^Terminal=false$/m);
  assert.match(desktop, /^X-KDE-AutostartScript=true$/m);
  assert.match(welcome, /Welcome to OPEMOS/);
  assert.match(welcome, /run_install all/);
  assert.match(welcome, /run_install system/);
  assert.match(welcome, /Do not power off the computer or disconnect either drive/);
  assert.match(welcome, /Diagnostics — review media identity/);
  assert.match(welcome, /last-install-log/);
  assert.match(welcome, /flock -n 8/);
  assert.match(gtkCss, /linear-gradient\(to right, @opemos_blue, @opemos_green\)/);
  assert.doesNotMatch(welcome, /\beval\b/);
  assert.doesNotMatch(helper, /\beval\b/);
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
  assert.match(helper, /PARTN,PARTLABEL,TYPE/);
  assert.match(helper, /install_recovery_guardian_to_root\.sh/);
  assert.match(helper, /for slot in A B/);
  assert.match(helper, /--support-revision "\$support_revision"/);
  assert.match(helper, /media-info\)/);
  assert.match(helper, /verify_guardian_slot/);
  assert.match(helper, /installed recovery guardian verification failed/);
  assert.match(helper, /ui_stage "Installing the recovery guardian into rootfs-\$slot/);
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

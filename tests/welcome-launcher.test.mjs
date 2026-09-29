import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

function fixture(context) {
  const root = mkdtempSync(join(tmpdir(), "opemos-welcome-launcher-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const bin = join(root, "bin");
  const state = join(root, "state");
  const ui = join(root, "ui");
  const pci = join(root, "pci");
  mkdirSync(bin);
  mkdirSync(ui);
  mkdirSync(pci);
  const helper = join(root, "helper");
  const server = join(root, "server.py");
  const qt6Qmlscene = join(bin, "qt6-qmlscene");
  const qml = join(ui, "opemos-welcome.qml");
  const launcher = join(root, "open-opemos-welcome");
  const lock = join(root, "welcome.lock");
  const visible = join(root, "visible.log");
  writeFileSync(helper, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  writeFileSync(qml, 'import QtQuick\nItem { property string url: "__OPEMOS_INSTALLER_URL__" }\n');
  writeFileSync(server, `#!/usr/bin/env python3
import pathlib, signal, sys, time
runtime = pathlib.Path(sys.argv[sys.argv.index("--runtime") + 1])
(runtime / "port").write_text("43210\\n", encoding="ascii")
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True: time.sleep(0.1)
`, { mode: 0o755 });
  for (const browser of [
    "chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
    "firefox", "firefox-esr",
  ]) {
    writeFileSync(join(bin, browser), "#!/bin/sh\nexit 7\n", { mode: 0o755 });
  }
  writeFileSync(join(bin, "zenity"), `#!/bin/sh
printf '%s\\n' "$*" >>${JSON.stringify(visible)}
case " $* " in *" --list "*) exit 1;; esac
exit 0
`, { mode: 0o755 });

  let source = readFileSync("builder/welcome/open-opemos-welcome", "utf8");
  source = source
    .replace("readonly HELPER=/usr/lib/opemos-install-media/opemos-install-helper", `readonly HELPER=${helper}`)
    .replace("readonly UI_CONFIG=/usr/share/opemos-install-media/ui", `readonly UI_CONFIG=${ui}`)
    .replace("readonly WELCOME_UI=/usr/share/opemos-install-media/ui/welcome", `readonly WELCOME_UI=${ui}`)
    .replace('readonly WELCOME_QML="$WELCOME_UI/opemos-welcome.qml"', `readonly WELCOME_QML=${qml}`)
    .replace("readonly WELCOME_SERVER=/usr/lib/opemos-install-media/welcome_server.py", `readonly WELCOME_SERVER=${server}`)
    .replace("readonly QT6_QMLSCENE=/usr/lib/qt6/bin/qmlscene", `readonly QT6_QMLSCENE=${qt6Qmlscene}`)
    .replace("readonly PCI_DEVICES_ROOT=/sys/bus/pci/devices", `readonly PCI_DEVICES_ROOT=${pci}`)
    .replace("readonly GRAPHICAL_READY_TIMEOUT_SECONDS=20", "readonly GRAPHICAL_READY_TIMEOUT_SECONDS=1")
    .replace("readonly STATE_DIRECTORY=/home/deck/.local/state/open-opemos", `readonly STATE_DIRECTORY=${state}`)
    .replace("exec 8>/tmp/open-opemos-welcome.lock", `exec 8>${lock}`);
  writeFileSync(launcher, source);
  chmodSync(launcher, 0o755);
  return { bin, launcher, lock, pci, qt6Qmlscene, state, visible };
}

function addGraphicsDevice(pci, address, vendor, { bootVga = "0", driver = "" } = {}) {
  const device = join(pci, address);
  mkdirSync(device);
  writeFileSync(join(device, "class"), "0x030000\n");
  writeFileSync(join(device, "vendor"), `${vendor}\n`);
  writeFileSync(join(device, "boot_vga"), `${bootVga}\n`);
  if (driver) writeFileSync(join(device, "driver-name"), driver);
}

test("the recovery image Qt WebEngine shell is the primary fullscreen runtime", (context) => {
  const { bin, launcher, qt6Qmlscene, visible } = fixture(context);
  writeFileSync(qt6Qmlscene, `#!/bin/sh
qml=$1
grep -q 'http://127.0.0.1:43210/' "$qml" || exit 8
touch "$(dirname "$qml")/ui-ready"
sleep 2.1
exit 0
`, { mode: 0o755 });
  const result = spawnSync("bash", [launcher], {
    encoding: "utf8", env: testEnvironment(bin), timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.throws(() => readFileSync(visible, "utf8"), { code: "ENOENT" });
});

test("an Intel display and NVIDIA render hybrid uses one OpenGL device path and records both devices", (context) => {
  const { bin, launcher, pci, qt6Qmlscene, state } = fixture(context);
  addGraphicsDevice(pci, "0000:00:02.0", "0x8086", { bootVga: "1" });
  addGraphicsDevice(pci, "0000:01:00.0", "0x10de");
  writeFileSync(qt6Qmlscene, `#!/bin/sh
test "$QSG_RHI_BACKEND" = opengl || exit 20
test "$QSG_INFO" = 1 || exit 21
test "$DRI_PRIME" = 0 || exit 26
case "$QTWEBENGINE_CHROMIUM_FLAGS" in
  *--use-gl=angle*--use-angle=gl*--disable-features=Vulkan*) ;;
  *) exit 22;;
esac
case "$QT_LOGGING_RULES" in *qt.webenginecontext.debug=true*) ;; *) exit 23;; esac
touch "$(dirname "$1")/ui-ready"
sleep 2.1
`, { mode: 0o755 });
  const result = spawnSync("bash", [launcher], {
    encoding: "utf8", env: testEnvironment(bin), timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  const log = readFileSync(join(state, "welcome-startup.log"), "utf8");
  assert.match(log, /Intel display\/NVIDIA render hybrid coherent OpenGL/);
  assert.match(log, /pci=0000:00:02\.0 vendor=0x8086/);
  assert.match(log, /pci=0000:01:00\.0 vendor=0x10de/);
});

test("an NVIDIA boot display does not force the Intel-display hybrid policy", (context) => {
  const { bin, launcher, pci, qt6Qmlscene, state } = fixture(context);
  addGraphicsDevice(pci, "0000:00:02.0", "0x8086");
  addGraphicsDevice(pci, "0000:01:00.0", "0x10de", { bootVga: "1" });
  writeFileSync(qt6Qmlscene, `#!/bin/sh
test -z "\${QSG_RHI_BACKEND:-}" || exit 27
test -z "\${QTWEBENGINE_CHROMIUM_FLAGS:-}" || exit 28
touch "$(dirname "$1")/ui-ready"
sleep 2.1
`, { mode: 0o755 });
  const result = spawnSync("bash", [launcher], {
    encoding: "utf8", env: testEnvironment(bin), timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  const log = readFileSync(join(state, "welcome-startup.log"), "utf8");
  assert.match(log, /automatic accelerated backend/);
});

test("a failed accelerated Qt launch retries with coherent software rendering", (context) => {
  const { bin, launcher, qt6Qmlscene, state } = fixture(context);
  writeFileSync(qt6Qmlscene, `#!/bin/sh
if [ "\${QT_QUICK_BACKEND:-}" != software ]; then exit 24; fi
test "$QTWEBENGINE_CHROMIUM_FLAGS" = --disable-gpu || exit 25
touch "$(dirname "$1")/ui-ready"
sleep 2.1
`, { mode: 0o755 });
  const result = spawnSync("bash", [launcher], {
    encoding: "utf8", env: testEnvironment(bin), timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  const log = readFileSync(join(state, "welcome-startup.log"), "utf8");
  assert.match(log, /qt:auto\) exited with status 24/);
  assert.match(log, /software fallback/);
});

test("a hung accelerated renderer is bounded before the software retry", (context) => {
  const { bin, launcher, qt6Qmlscene, state } = fixture(context);
  writeFileSync(qt6Qmlscene, `#!/bin/sh
if [ "\${QT_QUICK_BACKEND:-}" != software ]; then
  trap 'exit 0' TERM
  while :; do sleep 0.1; done
fi
touch "$(dirname "$1")/ui-ready"
sleep 2.1
`, { mode: 0o755 });
  const result = spawnSync("bash", [launcher], {
    encoding: "utf8", env: testEnvironment(bin), timeout: 6000,
  });
  assert.equal(result.status, 0, result.stderr);
  const log = readFileSync(join(state, "welcome-startup.log"), "utf8");
  assert.match(log, /did not report a ready interface within 1 seconds/);
  assert.match(log, /software fallback/);
});

test("a PATH Qt 5 qmlscene is not mistaken for the recovery image Qt 6 runtime", (context) => {
  const { bin, launcher, visible } = fixture(context);
  writeFileSync(join(bin, "qmlscene"), "#!/bin/sh\nexit 99\n", { mode: 0o755 });
  const result = spawnSync("bash", [launcher], {
    encoding: "utf8", env: testEnvironment(bin), timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(readFileSync(visible, "utf8"), /full-screen installer could not open/);
});

function testEnvironment(bin) {
  return {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
  };
}

test("browser instant exit is logged and opens the existing fallback", (context) => {
  const { bin, launcher, state, visible } = fixture(context);
  const result = spawnSync("bash", [launcher], {
    encoding: "utf8", env: testEnvironment(bin), timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  const log = readFileSync(join(state, "welcome-startup.log"), "utf8");
  assert.match(log, /browser \(chromium\) exited with status 7/);
  assert.match(readFileSync(visible, "utf8"), /full-screen installer could not open/);
});

test("a failed Chromium runtime tries Firefox before opening the fallback", (context) => {
  const { bin, launcher, visible } = fixture(context);
  writeFileSync(join(bin, "firefox"), `#!/bin/sh
for argument in "$@"; do
  case "$argument" in
    --profile) profile_next=1;;
    *) if [ "\${profile_next:-0}" = 1 ]; then profile=$argument; profile_next=0; fi;;
  esac
done
touch "$(dirname "$profile")/ui-ready"
sleep 2.1
exit 0
`, { mode: 0o755 });
  const result = spawnSync("bash", [launcher], {
    encoding: "utf8", env: testEnvironment(bin), timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.throws(() => readFileSync(visible, "utf8"), { code: "ENOENT" });
});

test("a second launch reports the held singleton instead of silently succeeding", async (context) => {
  const { bin, launcher, lock, visible } = fixture(context);
  const holder = spawn("flock", [lock, "sleep", "5"], { stdio: "ignore" });
  context.after(() => holder.kill("SIGTERM"));
  await new Promise((resolve) => setTimeout(resolve, 100));
  const result = spawnSync("bash", [launcher], {
    encoding: "utf8", env: testEnvironment(bin), timeout: 5000,
  });
  assert.equal(result.status, 1, result.stderr);
  assert.match(readFileSync(visible, "utf8"), /installer is already running/);
});

test("a stable browser window exits cleanly without opening the fallback", (context) => {
  const { bin, launcher, visible } = fixture(context);
  writeFileSync(join(bin, "chromium"), `#!/bin/sh
for argument in "$@"; do
  case "$argument" in
    --user-data-dir=*) profile=\${argument#--user-data-dir=};;
  esac
done
touch "$(dirname "$profile")/ui-ready"
sleep 2.1
exit 0
`, { mode: 0o755 });
  const result = spawnSync("bash", [launcher], {
    encoding: "utf8", env: testEnvironment(bin), timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.throws(() => readFileSync(visible, "utf8"), { code: "ENOENT" });
});

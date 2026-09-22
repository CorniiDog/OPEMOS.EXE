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
  mkdirSync(bin);
  mkdirSync(ui);
  const helper = join(root, "helper");
  const server = join(root, "server.py");
  const launcher = join(root, "open-opemos-welcome");
  const lock = join(root, "welcome.lock");
  const visible = join(root, "visible.log");
  writeFileSync(helper, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  writeFileSync(server, `#!/usr/bin/env python3
import pathlib, signal, sys, time
runtime = pathlib.Path(sys.argv[sys.argv.index("--runtime") + 1])
(runtime / "port").write_text("43210\\n", encoding="ascii")
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True: time.sleep(0.1)
`, { mode: 0o755 });
  writeFileSync(join(bin, "chromium"), "#!/bin/sh\nexit 7\n", { mode: 0o755 });
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
    .replace("readonly WELCOME_SERVER=/usr/lib/opemos-install-media/welcome_server.py", `readonly WELCOME_SERVER=${server}`)
    .replace("readonly STATE_DIRECTORY=/home/deck/.local/state/open-opemos", `readonly STATE_DIRECTORY=${state}`)
    .replace("exec 8>/tmp/open-opemos-welcome.lock", `exec 8>${lock}`);
  writeFileSync(launcher, source);
  chmodSync(launcher, 0o755);
  return { bin, launcher, lock, state, visible };
}

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

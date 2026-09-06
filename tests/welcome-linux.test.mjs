import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";

const launcher = readFileSync("test_welcome_linux.sh", "utf8");

function run(extraEnv = {}) {
  return spawnSync("bash", ["test_welcome_linux.sh"], {
    cwd: process.cwd(), encoding: "utf8", env: { ...process.env, ...extraEnv },
  });
}

test("Linux welcome UI exposes the same print-only non-GUI contract", () => {
  const result = run({ OPEMOS_GRAPHICAL_TEST_PRINT_ONLY: "1", DISPLAY: "", WAYLAND_DISPLAY: "" });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /welcome_server\.py --mock --ui-root .*builder\/welcome\n$/);
  assert.equal(result.stderr, "");
});

test("Linux preview fails closed without a graphical session", () => {
  const result = run({ OPEMOS_GRAPHICAL_TEST_PRINT_ONLY: "0", DISPLAY: "", WAYLAND_DISPLAY: "" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /X11 or Wayland graphical session is required/);
  assert.doesNotMatch(result.stdout, /Opening/);
});

test("Linux preview uses deterministic browsers and isolated loopback state", () => {
  assert.match(launcher, /for candidate in google-chrome-stable google-chrome chromium chromium-browser/);
  assert.match(launcher, /URL="http:\/\/127\.0\.0\.1:\$PORT\/"/);
  assert.match(launcher, /HOME="\$RUNTIME\/home"/);
  assert.match(launcher, /XDG_CONFIG_HOME="\$RUNTIME\/config"/);
  assert.match(launcher, /XDG_CACHE_HOME="\$RUNTIME\/cache"/);
  assert.match(launcher, /--user-data-dir="\$RUNTIME\/browser"/);
  assert.match(launcher, /--disable-background-networking/);
  assert.match(launcher, /No disks, privileges, QEMU processes, or installers are used/);
  assert.doesNotMatch(launcher, /sudo|pkexec|qemu-system|lsblk|diskutil|\/dev\/sd|\/dev\/nvme/);
});

test("normal server exit terminates the browser and removes isolated runtime", () => {
  const scratch = mkdtempSync(join(tmpdir(), "opemos-welcome-linux-test-"));
  const bin = join(scratch, "bin");
  const record = join(scratch, "browser-args");
  spawnSync("mkdir", ["-p", bin]);
  writeFileSync(join(bin, "python3"), `#!/usr/bin/env bash\nset -eu\nruntime=\nwhile [[ $# -gt 0 ]]; do [[ $1 == --runtime ]] && { runtime=$2; shift 2; continue; }; shift; done\nprintf '4242\\n' >"$runtime/port"\nsleep 0.2\n`);
  writeFileSync(join(bin, "google-chrome-stable"), `#!/usr/bin/env bash\nprintf '%s\\n' "$@" >"$OPEMOS_BROWSER_RECORD"\ntrap 'exit 0' TERM INT\nwhile :; do sleep 0.05; done\n`);
  chmodSync(join(bin, "python3"), 0o755); chmodSync(join(bin, "google-chrome-stable"), 0o755);
  const result = run({ DISPLAY: ":99", WAYLAND_DISPLAY: "", TMPDIR: scratch,
    PATH: `${bin}:/usr/bin:/bin`, OPEMOS_BROWSER_RECORD: record });
  assert.equal(result.status, 0, result.stderr);
  const args = readFileSync(record, "utf8");
  assert.match(args, /--app=http:\/\/127\.0\.0\.1:4242\//);
  assert.match(args, /--start-fullscreen/);
  assert.deepEqual(spawnSync("bash", ["-c", `compgen -G '${scratch}/opemos-welcome-linux.*'`], { encoding: "utf8" }).stdout, "");
  rmSync(scratch, { recursive: true, force: true });
});

test("closing the isolated browser normally stops the controller and cleans state", () => {
  const scratch = mkdtempSync(join(tmpdir(), "opemos-welcome-linux-close-"));
  const bin = join(scratch, "bin");
  spawnSync("mkdir", ["-p", bin]);
  writeFileSync(join(bin, "python3"), `#!/usr/bin/env bash\nset -eu\nruntime=\ntrap 'exit 0' TERM INT\nwhile [[ $# -gt 0 ]]; do [[ $1 == --runtime ]] && { runtime=$2; shift 2; continue; }; shift; done\nprintf '4444\\n' >"$runtime/port"\nwhile :; do sleep 0.05; done\n`);
  writeFileSync(join(bin, "google-chrome-stable"), "#!/usr/bin/env bash\nsleep 0.15\n");
  chmodSync(join(bin, "python3"), 0o755); chmodSync(join(bin, "google-chrome-stable"), 0o755);
  const result = run({ DISPLAY: ":99", WAYLAND_DISPLAY: "", TMPDIR: scratch, PATH: `${bin}:/usr/bin:/bin` });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(spawnSync("bash", ["-c", `compgen -G '${scratch}/opemos-welcome-linux.*'`], { encoding: "utf8" }).stdout, "");
  rmSync(scratch, { recursive: true, force: true });
});

const pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

test("termination signals reap controller and browser and remove runtime", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "opemos-welcome-linux-signal-"));
  const bin = join(scratch, "bin");
  const record = join(scratch, "browser-started");
  spawnSync("mkdir", ["-p", bin]);
  const sleeper = `#!/usr/bin/env bash\nset -eu\ntrap 'exit 0' TERM INT\n${'runtime='}\nwhile [[ $# -gt 0 ]]; do [[ $1 == --runtime ]] && { runtime=$2; shift 2; continue; }; shift; done\n[[ -z "$runtime" ]] || printf '4343\\n' >"$runtime/port"\n[[ -z "${'${OPEMOS_BROWSER_RECORD:-}'}" ]] || printf 'started\\n' >"$OPEMOS_BROWSER_RECORD"\nwhile :; do sleep 0.05; done\n`;
  writeFileSync(join(bin, "python3"), sleeper);
  writeFileSync(join(bin, "google-chrome-stable"), sleeper);
  chmodSync(join(bin, "python3"), 0o755); chmodSync(join(bin, "google-chrome-stable"), 0o755);
  const child = spawn("bash", ["test_welcome_linux.sh"], { cwd: process.cwd(), stdio: "ignore",
    env: { ...process.env, DISPLAY: ":99", WAYLAND_DISPLAY: "", TMPDIR: scratch,
      PATH: `${bin}:/usr/bin:/bin`, OPEMOS_BROWSER_RECORD: record } });
  for (let attempt = 0; attempt < 100 && !existsSync(record); attempt += 1) await pause(20);
  assert.ok(existsSync(record), "browser must start before signal injection");
  child.kill("SIGTERM");
  const status = await new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
  assert.equal(status.code, 130); assert.equal(status.signal, null);
  assert.equal(spawnSync("bash", ["-c", `compgen -G '${scratch}/opemos-welcome-linux.*'`], { encoding: "utf8" }).stdout, "");
  rmSync(scratch, { recursive: true, force: true });
});

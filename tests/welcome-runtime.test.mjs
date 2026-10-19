import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

test("mock welcome controller serves and completes the real UI contract safely", async (context) => {
  const runtime = mkdtempSync(join(tmpdir(), "opemos-welcome-runtime-"));
  const child = spawn("python3", [
    "builder/welcome/welcome_server.py", "--mock",
    "--ui-root", "builder/welcome", "--runtime", runtime,
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  let spawnError;
  child.on("error", (error) => { spawnError = error; });
  const closed = new Promise((resolve) => child.once("close", resolve));
  child.stderr.on("data", (chunk) => { stderr = (stderr + chunk.toString("utf8")).slice(-16384); });
  context.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
    let timer;
    await Promise.race([closed, new Promise((resolve) => { timer = setTimeout(() => { child.kill("SIGKILL"); resolve(); }, 2500); })]);
    clearTimeout(timer);
    await closed;
    rmSync(runtime, { recursive: true, force: true });
  });

  let port;
  const started = performance.now();
  const deadline = started + 2000;
  while (performance.now() < deadline && !spawnError && child.exitCode === null && child.signalCode === null) {
    try {
      port = readFileSync(join(runtime, "port"), "utf8").trim();
      // The port file and stderr pipe are independent process boundaries.
      // Both are emitted by the real producer, but Node may observe the file
      // before dispatching the pipe's data event. Join both within the same
      // original two-second bound; do not assert on an undrained pipe.
      if (/^\d+$/.test(port) && /OPEMOS_STARTUP numeric-loopback-bound [0-9.]+/.test(stderr)) break;
    }
    catch {
      if (child.exitCode !== null || child.signalCode !== null) break;
    }
    await pause(20);
  }
  if (!port && /PermissionError: \[Errno 1\] Operation not permitted/.test(stderr)) {
    context.skip("sandbox does not permit an ephemeral loopback listener");
    return;
  }
  const python = spawnSync("python3", ["-c", "import sys; print(sys.executable); print(sys.version)"], { encoding: "utf8", timeout: 2000 });
  assert.match(port ?? "", /^\d+$/, JSON.stringify({
    elapsedMs: performance.now() - started, spawnError: spawnError?.message,
    exitCode: child.exitCode, signal: child.signalCode, stderr,
    python: python.stdout, pythonDiagnosticError: python.stderr,
  }));
  assert.match(stderr, /OPEMOS_STARTUP before-numeric-loopback-bind/);
  assert.match(stderr, /OPEMOS_STARTUP numeric-loopback-bound [0-9.]+/);
  context.diagnostic(JSON.stringify({ readinessMs: performance.now() - started, startup: stderr, python: python.stdout }));
  const origin = `http://127.0.0.1:${port}`;
  const html = await (await fetch(`${origin}/`)).text();
  const readyMarker = statSync(join(runtime, "ui-ready"));
  assert.equal(readyMarker.mode & 0o777, 0o600);
  const token = html.match(/window\.__OPEMOS_SESSION_TOKEN__=("[0-9a-f]+")/)?.[1];
  assert.ok(token);
  const headers = {
    "Content-Type": "application/json",
    "Origin": origin,
    "X-OPEMOS-Token": JSON.parse(token),
  };

  const unauthorized = await fetch(`${origin}/api/bootstrap`);
  assert.equal(unauthorized.status, 403);
  const readHeaders = {
    "Content-Type": "application/json",
    "X-OPEMOS-Token": JSON.parse(token),
  };
  const bootstrap = await (await fetch(`${origin}/api/bootstrap`, { headers: readHeaders })).json();
  assert.equal(bootstrap.mode, "simulation");
  assert.equal(bootstrap.disks.length, 1);

  const originlessMutation = await fetch(`${origin}/api/install`, {
    method: "POST", headers: readHeaders,
    body: JSON.stringify({ mode: "all", device: "/dev/vda", identity: "1".repeat(64), confirmation: "ERASE vda" }),
  });
  assert.equal(originlessMutation.status, 403);

  const rejected = await fetch(`${origin}/api/install`, {
    method: "POST", headers,
    body: JSON.stringify({ mode: "all", device: "/dev/vda", identity: "1".repeat(64), confirmation: "ERASE wrong" }),
  });
  assert.equal(rejected.status, 400);
  const accepted = await fetch(`${origin}/api/install`, {
    method: "POST", headers,
    body: JSON.stringify({ mode: "all", device: "/dev/vda", identity: "1".repeat(64), confirmation: "ERASE vda" }),
  });
  assert.equal(accepted.status, 200);
  const closeDuringMutation = await fetch(`${origin}/api/close`, {
    method: "POST", headers, body: "{}",
  });
  assert.equal(closeDuringMutation.status, 500);

  let operation;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    operation = await (await fetch(`${origin}/api/status`, { headers })).json();
    if (operation.terminal) break;
    await pause(100);
  }
  assert.equal(operation.status, "complete");
  assert.equal(operation.progress, 100);
  const diagnostics = await (await fetch(`${origin}/api/diagnostics`, { headers })).json();
  assert.match(diagnostics.text, /No disks, privileges, or installers are reachable/);
  const close = await fetch(`${origin}/api/close`, {
    method: "POST", headers, body: "{}",
  });
  assert.equal(close.status, 200, "close must return before loopback shutdown");
  assert.equal((await close.json()).status, "closing");
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("welcome controller did not close")), 2500);
    child.once("exit", () => { clearTimeout(timeout); resolve(); });
  });
});

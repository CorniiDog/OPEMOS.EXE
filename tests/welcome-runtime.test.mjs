import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
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
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  context.after(() => {
    if (child.exitCode === null) child.kill("SIGTERM");
    rmSync(runtime, { recursive: true, force: true });
  });

  let port;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { port = readFileSync(join(runtime, "port"), "utf8").trim(); break; }
    catch {
      if (child.exitCode !== null) break;
      await pause(20);
    }
  }
  if (!port && /PermissionError: \[Errno 1\] Operation not permitted/.test(stderr)) {
    context.skip("sandbox does not permit an ephemeral loopback listener");
    return;
  }
  assert.match(port, /^\d+$/);
  const origin = `http://127.0.0.1:${port}`;
  const html = await (await fetch(`${origin}/`)).text();
  const token = html.match(/window\.__OPEMOS_SESSION_TOKEN__=("[0-9a-f]+")/)?.[1];
  assert.ok(token);
  const headers = {
    "Content-Type": "application/json",
    "Origin": origin,
    "X-OPEMOS-Token": JSON.parse(token),
  };

  const unauthorized = await fetch(`${origin}/api/bootstrap`);
  assert.equal(unauthorized.status, 403);
  const bootstrap = await (await fetch(`${origin}/api/bootstrap`, { headers })).json();
  assert.equal(bootstrap.mode, "simulation");
  assert.equal(bootstrap.disks.length, 1);

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
});

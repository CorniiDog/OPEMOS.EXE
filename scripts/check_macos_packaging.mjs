#!/usr/bin/env node
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const commandTimeoutMs = 30_000;

export function packagingCommands(root) {
  const payload = join(root, "payload");
  const image = join(root, "headless-packaging-smoke.dmg");
  return [
    ["/usr/bin/hdiutil", ["create", "-quiet", "-fs", "HFS+", "-format", "UDZO", "-volname", "SteamOS Packaging Smoke", "-srcfolder", payload, image]],
    ["/usr/bin/hdiutil", ["verify", image]],
  ];
}

export function classifyCommandFailure(result, phase) {
  if (result.error?.code === "ETIMEDOUT") return `host tool timed out during ${phase}`;
  if (result.error) return `host tool could not start during ${phase}: ${result.error.message}`;
  if (result.status !== 0) {
    const detail = String(result.stderr || result.stdout || "no diagnostic output").trim().slice(0, 4096);
    return `host tool failed during ${phase} (exit ${result.status}): ${detail}`;
  }
  return null;
}

export async function runBoundedCommand(command, args, timeoutMs = commandTimeoutMs) {
  return await new Promise((resolve) => {
    const child = spawn(command, args, {
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const output = { stdout: "", stderr: "", status: null, error: null };
    const append = (field, chunk) => {
      if (output[field].length < 1024 * 1024) {
        output[field] += chunk.toString("utf8").slice(0, 1024 * 1024 - output[field].length);
      }
    };
    child.stdout?.on("data", (chunk) => append("stdout", chunk));
    child.stderr?.on("data", (chunk) => append("stderr", chunk));
    let timedOut = false;
    let killTimer;
    const timeout = setTimeout(() => {
      timedOut = true;
      try { process.kill(-child.pid, "SIGTERM"); } catch {}
      killTimer = setTimeout(() => {
        try { process.kill(-child.pid, "SIGKILL"); } catch {}
      }, 1000);
    }, timeoutMs);
    child.once("error", (error) => {
      output.error = error;
    });
    child.once("close", (status) => {
      clearTimeout(timeout);
      clearTimeout(killTimer);
      output.status = status;
      if (timedOut) output.error = Object.assign(new Error("command timed out"), { code: "ETIMEDOUT" });
      resolve(output);
    });
  });
}

async function main() {
  if (process.platform !== "darwin") {
    console.log(JSON.stringify({ schemaVersion: 1, status: "skipped", phase: "host", reason: "macOS hdiutil is unavailable" }));
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "steamos-packaging-smoke-"));
  try {
    const payload = join(root, "payload");
    await mkdir(payload, { mode: 0o700 });
    await writeFile(join(payload, "README.txt"), "SteamOS NVIDIA Builder headless packaging smoke\n", { mode: 0o600 });
    for (const [command, args] of packagingCommands(root)) {
      const phase = args[0];
      const result = await runBoundedCommand(command, args);
      const failure = classifyCommandFailure(result, phase);
      if (failure) {
        console.error(JSON.stringify({ schemaVersion: 1, status: "failed", phase: "host-packaging", reason: failure }));
        process.exitCode = 1;
        return;
      }
    }
    console.log(JSON.stringify({ schemaVersion: 1, status: "passed", phase: "host-packaging", reason: "headless compressed DMG creation and verification succeeded" }));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) await main();

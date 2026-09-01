#!/usr/bin/env node
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
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
      const result = spawnSync(command, args, { encoding: "utf8", timeout: commandTimeoutMs, maxBuffer: 1024 * 1024 });
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

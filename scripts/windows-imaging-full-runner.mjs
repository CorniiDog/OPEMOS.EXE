#!/usr/bin/env node
import { lstat, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { fileURLToPath } from "node:url";
import { runWindowsImagingFull } from "./windows-imaging-partial.mjs";

const PHASES = Object.freeze([
  "officialSteamOsAuthenticated", "immutableDriverOnlyRelease",
  "driverBundleOfflineValidated", "driverBundleSourceEvidence",
  "imageConstructed", "imageExported", "candidateEnumeratedOwned32GiBUsb",
  "candidateWroteCompleteImage", "candidateFlushed", "completeReadbackHashMatched",
  "retainedUsbBooted", "steamOsInstalled", "steamOsReinstalled", "reinstallBooted",
  "noOrphans", "cancellationCleanup",
]);
const KEYS = new Set(["schemaVersion", "kind", "ownedRoot", "exeCommit", "exeSha256",
  "exePath", "exeProvenancePath", "steamOsPath", "driverFiles",
  "steamOsImage", "driverBundle", "virtualUsb", "actions"]);

function fail(message) { throw new Error(message); }
function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== expected.size || Object.keys(value).some(key => !expected.has(key))) {
    fail(`${label} fields are not closed.`);
  }
}
async function realFile(value, label) {
  const info = await lstat(value);
  if (info.isSymbolicLink() || !info.isFile()) fail(`${label} must be a real file.`);
  return realpath(value);
}
async function realDirectory(value, label) {
  const info = await lstat(value);
  if (info.isSymbolicLink() || !info.isDirectory()) fail(`${label} must be a real directory.`);
  return realpath(value);
}
async function sha256(value) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(value)) hash.update(chunk);
  return hash.digest("hex");
}
function inside(root, value, label) {
  const relative = path.relative(root, value);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail(`${label} must be beneath the owned full-run root.`);
  }
}
function waitFor(promise, timeoutMs) {
  let timer;
  return Promise.race([
    promise,
    new Promise(resolve => { timer = setTimeout(() => resolve(false), timeoutMs); }),
  ]).finally(() => clearTimeout(timer));
}
function ownedCommand(command, phase, context, spawnProcess, terminationGraceMs) {
  let child;
  let settled = false;
  let resolveCompletion;
  const completion = new Promise(resolve => { resolveCompletion = resolve; });
  const settlement = completion.then(() => true, () => true);
  try {
    child = spawnProcess(command.executable, command.args, {
      cwd: command.cwd, shell: false, windowsHide: true,
      env: { ...process.env, OPEMOS_FULL_PHASE: phase, OPEMOS_FULL_DEADLINE: String(context.deadline) },
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    settled = true;
    resolveCompletion(Promise.reject(error));
  }
  let stdout = "";
  let stderr = "";
  child?.stdout?.setEncoding("utf8"); child?.stderr?.setEncoding("utf8");
  child?.stdout?.on("data", chunk => { stdout += chunk; if (stdout.length > 1024 * 1024) child.kill(); });
  child?.stderr?.on("data", chunk => { stderr += chunk; if (stderr.length > 1024 * 1024) child.kill(); });
  child?.once("error", error => { if (!settled) { settled = true; resolveCompletion(Promise.reject(error)); } });
  child?.once("exit", code => {
    if (settled) return;
    settled = true;
    if (code !== 0) return resolveCompletion(Promise.reject(new Error(`${phase} exited ${code}: ${stderr.trim()}`)));
    try {
      const receipt = JSON.parse(stdout);
      exactKeys(receipt, new Set(["schemaVersion", "status", "phase"]), `${phase} receipt`);
      if (receipt.schemaVersion !== 1 || receipt.status !== "passed" || receipt.phase !== phase) fail(`${phase} receipt identity is invalid.`);
      resolveCompletion(true);
    } catch (error) { resolveCompletion(Promise.reject(error)); }
  });
  return {
    completion,
    async cancelAndWait() {
      if (!settled && child) {
        const gracefulRequested = child.kill("SIGTERM");
        if (gracefulRequested) {
          const grace = Math.min(terminationGraceMs, Math.max(1, context.deadline - Date.now() - 1));
          if (await waitFor(settlement, grace)) return true;
        }
        if (!settled && child.kill("SIGKILL") === false) fail(`${phase} refused forced termination.`);
        if (!settled) {
          const forced = Math.max(1, context.deadline - Date.now() - 1);
          if (!await waitFor(settlement, forced)) fail(`${phase} did not exit after forced termination.`);
        }
      }
      try { await completion; } catch {}
      return settled;
    },
  };
}

export async function runWindowsImagingFullPlan(planPath, {
  spawnProcess = spawn, platform = process.platform, timeoutMs, terminationGraceMs = 2000,
} = {}) {
  if (platform !== "win32") fail("The Windows full runner requires Windows.");
  if (!Number.isSafeInteger(terminationGraceMs) || terminationGraceMs < 1 || terminationGraceMs > 30_000) {
    fail("The Windows full runner termination grace is invalid.");
  }
  const canonicalPlanPath = await realFile(planPath, "Full-run plan");
  const plan = JSON.parse(await readFile(planPath, "utf8"));
  exactKeys(plan, KEYS, "Full-run plan");
  if (plan.schemaVersion !== 1 || plan.kind !== "opemos-windows-imaging-full") fail("Full-run plan identity is invalid.");
  const ownedRoot = path.resolve(plan.ownedRoot);
  const canonicalOwnedRoot = await realDirectory(ownedRoot, "Owned full-run root");
  inside(canonicalOwnedRoot, canonicalPlanPath, "Full-run plan");
  const canonicalInputs = {};
  for (const [label, value] of Object.entries({
    "Candidate executable": plan.exePath,
    "Candidate provenance": plan.exeProvenancePath,
    "Official SteamOS input": plan.steamOsPath,
  })) {
    if (!path.isAbsolute(value || "")) fail(`${label} path is invalid.`);
    const canonical = await realFile(value, label);
    inside(canonicalOwnedRoot, canonical, label);
    canonicalInputs[label] = canonical;
  }
  const executableInfo = await lstat(canonicalInputs["Candidate executable"]);
  if (executableInfo.size <= 0 || await sha256(canonicalInputs["Candidate executable"]) !== plan.exeSha256) fail("Candidate executable identity changed.");
  const provenance = Object.fromEntries((await readFile(canonicalInputs["Candidate provenance"], "ascii")).trim().split(/\r?\n/).map(line => {
    const separator = line.indexOf("=");
    if (separator < 1) fail("Candidate provenance is malformed.");
    return [line.slice(0, separator), line.slice(separator + 1)];
  }));
  if (provenance.source_commit !== plan.exeCommit || provenance.sha256 !== plan.exeSha256 ||
      Number(provenance.size) !== executableInfo.size || provenance.signed !== "false" || provenance.portable !== "true") {
    fail("Candidate provenance identity changed.");
  }
  const steamOsInfo = await lstat(canonicalInputs["Official SteamOS input"]);
  if (steamOsInfo.size !== plan.steamOsImage?.bytes || await sha256(canonicalInputs["Official SteamOS input"]) !== plan.steamOsImage?.sha256) {
    fail("Official SteamOS input identity changed.");
  }
  exactKeys(plan.driverFiles, new Set(["manifest", "driver-product", "sha256-sidecar"]), "Driver files");
  const driverIdentities = new Map([
    ["manifest", { name: null, sha256: plan.driverBundle?.manifestSha256 }],
    ...plan.driverBundle.assets.map(asset => [asset.role, asset]),
  ]);
  for (const [role, value] of Object.entries(plan.driverFiles)) {
    const identity = driverIdentities.get(role);
    if (!identity || !path.isAbsolute(value || "")) fail(`Driver ${role} path is invalid.`);
    const canonical = await realFile(value, `Driver ${role}`);
    inside(canonicalOwnedRoot, canonical, `Driver ${role}`);
    const info = await lstat(canonical);
    if ((identity.name && path.basename(value) !== identity.name) ||
        (identity.bytes && info.size !== identity.bytes) || await sha256(canonical) !== identity.sha256) {
      fail(`Driver ${role} identity changed.`);
    }
  }
  exactKeys(plan.actions, new Set(PHASES), "Full-run actions");
  const actions = {};
  for (const phase of PHASES) {
    const command = plan.actions[phase];
    exactKeys(command, new Set(["executable", "sha256", "args", "cwd"]), `${phase} command`);
    if (!path.isAbsolute(command.executable) || !path.isAbsolute(command.cwd) || !Array.isArray(command.args) ||
        !/^[0-9a-f]{64}$/.test(command.sha256 || "") ||
        command.args.some(value => typeof value !== "string" || value.includes("\0"))) fail(`${phase} command is invalid.`);
    const canonicalExecutable = await realFile(command.executable, `${phase} executable`);
    const canonicalCwd = await realDirectory(command.cwd, `${phase} working directory`);
    inside(canonicalOwnedRoot, canonicalExecutable, `${phase} executable`);
    inside(canonicalOwnedRoot, canonicalCwd, `${phase} working directory`);
    if (await sha256(canonicalExecutable) !== command.sha256) fail(`${phase} executable identity changed.`);
    const canonicalCommand = { ...command, executable: canonicalExecutable, cwd: canonicalCwd };
    actions[phase] = context => ownedCommand(canonicalCommand, phase, context, spawnProcess, terminationGraceMs);
  }
  return runWindowsImagingFull({
    exeCommit: plan.exeCommit, exeSha256: plan.exeSha256,
    expectedExeCommit: plan.exeCommit, expectedExeSha256: plan.exeSha256,
    steamOsImage: plan.steamOsImage, expectedSteamOsImage: plan.steamOsImage,
    driverBundle: plan.driverBundle, expectedDriverBundle: plan.driverBundle,
    virtualUsb: plan.virtualUsb, expectedVirtualUsb: plan.virtualUsb, actions, timeoutMs,
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) fail("Usage: windows-imaging-full-runner.mjs PLAN.json");
    process.stdout.write(`${JSON.stringify(await runWindowsImagingFullPlan(path.resolve(process.argv[2])))}\n`);
  } catch (error) {
    process.stderr.write(`${error?.message || error}\n`);
    process.exitCode = 1;
  }
}

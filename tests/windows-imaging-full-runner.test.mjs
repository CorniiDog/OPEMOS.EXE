import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { createHash } from "node:crypto";
import { runWindowsImagingFullPlan } from "../scripts/windows-imaging-full-runner.mjs";

const phases = ["officialSteamOsAuthenticated", "immutableDriverOnlyRelease", "driverBundleOfflineValidated",
  "driverBundleSourceEvidence", "imageConstructed", "imageExported", "candidateEnumeratedOwned32GiBUsb",
  "candidateWroteCompleteImage", "candidateFlushed", "completeReadbackHashMatched", "retainedUsbBooted",
  "steamOsInstalled", "steamOsReinstalled", "reinstallBooted", "noOrphans", "cancellationCleanup"];
const sha = "a".repeat(64);

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "opemos-full-runner-"));
  const bin = path.join(root, "bin"); await mkdir(bin); const executable = path.join(bin, "phase.exe"); await writeFile(executable, "fixture");
  const executableSha256 = createHash("sha256").update("fixture").digest("hex");
  const candidate = path.join(root, "candidate.exe"); await writeFile(candidate, "candidate");
  const candidateSha256 = createHash("sha256").update("candidate").digest("hex");
  const candidateProvenance = path.join(root, "provenance.txt");
  await writeFile(candidateProvenance, `source_commit=${"b".repeat(40)}\nsize=9\nsha256=${candidateSha256}\nsigned=false\nportable=true\n`);
  const steamOs = path.join(root, "steamos.img.bz2"); await writeFile(steamOs, "s");
  const steamOsSha256 = createHash("sha256").update("s").digest("hex");
  const manifest = path.join(root, "manifest.json"); await writeFile(manifest, "manifest");
  const manifestSha256 = createHash("sha256").update("manifest").digest("hex");
  const driver = path.join(root, "driver.tar.gz"); await writeFile(driver, "driver");
  const driverSha256 = createHash("sha256").update("driver").digest("hex");
  const sidecar = path.join(root, "driver.tar.gz.sha256"); await writeFile(sidecar, "sidecar");
  const sidecarSha256 = createHash("sha256").update("sidecar").digest("hex");
  const actions = Object.fromEntries(phases.map(phase => [phase, { executable, sha256: executableSha256, args: [phase], cwd: root }]));
  const plan = { schemaVersion: 1, kind: "opemos-windows-imaging-full", ownedRoot: root,
    exeCommit: "b".repeat(40), exeSha256: candidateSha256, exePath: candidate,
    exeProvenancePath: candidateProvenance, steamOsPath: steamOs,
    driverFiles: { manifest, "driver-product": driver, "sha256-sidecar": sidecar },
    steamOsImage: { schemaVersion: 1, kind: "official-steamos-recovery", url: "https://steamdeck-images.steamos.cloud/recovery/exact.img.bz2", bytes: 1, sha256: steamOsSha256, authenticationEvidenceSha256: sha },
    driverBundle: { offlineValidated: true, manifestSha256, schemaVersion: 1,
      kind: "opemos-driver-binary-bundle",
      contract: { releaseBundleManifestSchemaVersion: 1, driverProductManifestSchemaVersion: 1 },
      release: { repository: "CorniiDog/OPEMOS", tag: "exact" },
      core: { repository: "CorniiDog/OPEMOS", commit: "c".repeat(40) },
      source: { repository: "CorniiDog/open-gpu-kernel-modules-steamos", commit: "d".repeat(40) },
      target: { architecture: "x86_64", steamosVersion: "3.8.14", kernelVersion: "6.16.12-valve24.4-1-neptune-616-gfe145653a794", nvidiaVersion: "575.64.05" },
      compatibility: { architecture: "exact", kernel: "exact", fallback: false },
      assets: [
        { role: "driver-product", name: "driver.tar.gz", bytes: 6, sha256: driverSha256 },
        { role: "sha256-sidecar", name: "driver.tar.gz.sha256", bytes: 7, sha256: sidecarSha256 },
      ], provenanceSha256: sha, buildEvidenceSha256: sha },
    virtualUsb: { schemaVersion: 1, kind: "harness-owned-virtual-usb", capacityBytes: 32 * 1024 ** 3, identitySha256: sha }, actions };
  const file = path.join(root, "plan.json"); await writeFile(file, JSON.stringify(plan)); return { root, file, plan };
}
function childFor(phase, log, failure) {
  const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => { queueMicrotask(() => child.emit("exit", 143)); return true; };
  queueMicrotask(() => { log.push(phase); if (phase === failure) { child.stderr.end("demonstrated failure"); child.emit("exit", 7); } else { child.stdout.end(JSON.stringify({ schemaVersion: 1, status: "passed", phase })); child.emit("exit", 0); } });
  return child;
}

test("executes the exact full sequence and cleanup without a shell", async () => {
  const { file } = await fixture(); const log = []; const invocations = [];
  const result = await runWindowsImagingFullPlan(file, { platform: "win32", spawnProcess(executable, args, options) { invocations.push({ executable, args, options }); return childFor(args[0], log); } });
  assert.deepEqual(log, phases); assert.equal(result.status, "passed"); assert.equal(result.published, false);
  assert.ok(invocations.every(value => value.options.shell === false && value.options.windowsHide === true));
});

test("failed install runs cleanup and never reaches reinstall", async () => {
  const { file } = await fixture(); const log = [];
  await assert.rejects(runWindowsImagingFullPlan(file, { platform: "win32", spawnProcess(_executable, args) { return childFor(args[0], log, "steamOsInstalled"); } }), /exited 7/);
  assert.equal(log.includes("steamOsReinstalled"), false); assert.equal(log.at(-1), "cancellationCleanup");
});

test("refuses commands outside the owned full-run root before spawning", async () => {
  const { file, plan, root } = await fixture(); plan.actions.imageConstructed.executable = path.join(path.dirname(root), "outside.exe");
  await writeFile(plan.actions.imageConstructed.executable, "fixture"); await writeFile(file, JSON.stringify(plan));
  let spawned = false; await assert.rejects(runWindowsImagingFullPlan(file, { platform: "win32", spawnProcess() { spawned = true; } }), /beneath the owned/); assert.equal(spawned, false);
});

test("refuses a changed phase executable before spawning", async () => {
  const { file, plan } = await fixture(); plan.actions.imageConstructed.sha256 = "e".repeat(64); await writeFile(file, JSON.stringify(plan));
  let spawned = false; await assert.rejects(runWindowsImagingFullPlan(file, { platform: "win32", spawnProcess() { spawned = true; } }), /identity changed/); assert.equal(spawned, false);
});

test("refuses an intermediate directory redirect outside the owned root", async () => {
  const { file, plan, root } = await fixture();
  const outside = await mkdtemp(path.join(tmpdir(), "opemos-full-runner-outside-"));
  const redirectedExecutable = path.join(outside, "phase.exe"); await writeFile(redirectedExecutable, "fixture");
  const redirect = path.join(root, "redirect"); await symlink(outside, redirect, "junction");
  plan.actions.imageConstructed.executable = path.join(redirect, "phase.exe");
  await writeFile(file, JSON.stringify(plan));
  let spawned = false;
  await assert.rejects(runWindowsImagingFullPlan(file, { platform: "win32", spawnProcess() { spawned = true; } }), /beneath the owned/);
  assert.equal(spawned, false);
});

test("forces and proves child exit when graceful termination is refused", async () => {
  const { file } = await fixture(); const signals = []; const log = [];
  await assert.rejects(runWindowsImagingFullPlan(file, {
    platform: "win32", timeoutMs: 80, terminationGraceMs: 5,
    spawnProcess(_executable, args) {
      const phase = args[0];
      if (phase !== "officialSteamOsAuthenticated") return childFor(phase, log);
      const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
      child.kill = signal => {
        signals.push(signal);
        if (signal === "SIGTERM") return false;
        queueMicrotask(() => child.emit("exit", 137)); return true;
      };
      return child;
    },
  }), /timed out during officialSteamOsAuthenticated/);
  assert.deepEqual(signals, ["SIGTERM", "SIGKILL"]);
  assert.equal(log.at(-1), "cancellationCleanup");
});

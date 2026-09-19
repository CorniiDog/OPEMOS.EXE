import assert from "node:assert/strict";
import test from "node:test";
import { runWindowsImagingFull } from "../scripts/windows-imaging-partial.mjs";

const sha = "a".repeat(64);
const commit = "b".repeat(40);
const phases = [
  "officialSteamOsAuthenticated", "immutableDriverOnlyRelease",
  "driverBundleOfflineValidated", "driverBundleSourceEvidence",
  "imageConstructed", "imageExported", "candidateEnumeratedOwned32GiBUsb",
  "candidateWroteCompleteImage", "candidateFlushed", "completeReadbackHashMatched",
  "noOrphans",
];
const steamOs = {
  schemaVersion: 1, kind: "official-steamos-recovery",
  url: "https://steamdeck-images.steamos.cloud/recovery/steamdeck-oobe-repair-20260707.10-3.8.14.img.bz2",
  bytes: 4096, sha256: sha, authenticationEvidenceSha256: sha,
};
const bundle = {
  offlineValidated: true, manifestSha256: sha, schemaVersion: 1,
  kind: "opemos-driver-binary-bundle",
  contract: { releaseBundleManifestSchemaVersion: 1, driverProductManifestSchemaVersion: 1 },
  release: { repository: "CorniiDog/OPEMOS", tag: "driver-v1" },
  core: { repository: "CorniiDog/OPEMOS", commit },
  source: { repository: "NVIDIA/open-gpu-kernel-modules", commit },
  target: { architecture: "x86_64", steamosVersion: "3.8", kernelVersion: "6.11.11", nvidiaVersion: "580.1" },
  compatibility: { architecture: "exact", kernel: "exact", fallback: false },
  assets: [
    { role: "driver-product", name: "opemos-driver-v1-x86_64.tar.gz", bytes: 4096, sha256: sha },
    { role: "sha256-sidecar", name: "opemos-driver-v1-x86_64.tar.gz.sha256", bytes: 128, sha256: sha },
  ],
  provenanceSha256: sha, buildEvidenceSha256: sha,
};
const usb = {
  schemaVersion: 1, kind: "harness-owned-virtual-usb",
  capacityBytes: 32 * 1024 ** 3, identitySha256: sha,
};
const pins = {
  exeCommit: commit, exeSha256: sha, expectedExeCommit: commit, expectedExeSha256: sha,
  steamOsImage: steamOs, expectedSteamOsImage: steamOs,
  driverBundle: bundle, expectedDriverBundle: bundle,
  virtualUsb: usb, expectedVirtualUsb: usb,
};
function settled(value = true) {
  return { completion: Promise.resolve(value), cancelAndWait: async () => true };
}
function actions(log = []) {
  return {
    ...Object.fromEntries(phases.map(name => [name, context => {
      assert.equal(context.mode, "full");
      log.push(name);
      return settled();
    }])),
    cancellationCleanup: () => { log.push("cancellationCleanup"); return settled(); },
  };
}

test("full runner proves exact final construction, write, flush, readback, and orphan cleanup", async () => {
  const log = [];
  const result = await runWindowsImagingFull({ ...pins, actions: actions(log), timeoutMs: 5 * 60 * 60 * 1000 });
  assert.equal(result.mode, "full");
  assert.equal(result.claim, "publication-gate");
  assert.equal(result.published, false);
  assert.equal(result.installSuccess, false);
  assert.equal(result.retainedUsbBooted, false);
  assert.deepEqual(log, [...phases, "cancellationCleanup"]);
});

test("full runner refuses missing source evidence before any action", async () => {
  const value = actions();
  delete value.driverBundleSourceEvidence;
  await assert.rejects(runWindowsImagingFull({ ...pins, actions: value }), /missing: driverBundleSourceEvidence/);
});

test("failed write settles before cleanup and cannot reach readback", async () => {
  const log = [];
  const value = actions(log);
  value.candidateWroteCompleteImage = () => ({
    completion: Promise.resolve(false),
    cancelAndWait: async () => { log.push("write-settled"); return true; },
  });
  await assert.rejects(runWindowsImagingFull({ ...pins, actions: value }), /did not prove success/);
  assert.equal(log.includes("completeReadbackHashMatched"), false);
  assert.equal(log.indexOf("write-settled") < log.indexOf("cancellationCleanup"), true);
});

test("asynchronous cleanup can settle after the failed phase aborts the run", async () => {
  const log = [];
  const value = actions(log);
  value.candidateWroteCompleteImage = () => settled(false);
  value.cancellationCleanup = () => ({
    completion: new Promise(resolve => setImmediate(() => { log.push("cancellationCleanup"); resolve(true); })),
    cancelAndWait: async () => true,
  });
  await assert.rejects(runWindowsImagingFull({ ...pins, actions: value }), /did not prove success/);
  assert.equal(log.at(-1), "cancellationCleanup");
});

test("full identity mismatches fail before construction or write actions", async () => {
  const log = [];
  await assert.rejects(runWindowsImagingFull({
    ...pins,
    expectedSteamOsImage: { ...steamOs, sha256: "c".repeat(64) },
    actions: actions(log),
  }), /does not match independent pins/);
  assert.deepEqual(log, []);
});

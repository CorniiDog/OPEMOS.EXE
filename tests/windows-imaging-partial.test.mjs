import assert from "node:assert/strict";
import test from "node:test";
import { runWindowsImagingPartial } from "../scripts/windows-imaging-partial.mjs";

const sha = "a".repeat(64);
const commit = "b".repeat(40);
const phases = [
  "officialSteamOsAuthenticated", "immutableDriverOnlyRelease", "driverBundleOfflineValidated",
  "imageConstructed", "imageExported", "candidateEnumeratedOwned32GiBUsb",
  "candidateWroteCompleteImage", "candidateFlushed", "completeReadbackHashMatched",
];
const steamOs = {
  schemaVersion: 1, kind: "official-steamos-recovery",
  url: "https://steamdeck-images.steamos.cloud/recovery/steamdeck-recovery.img.bz2",
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
    ...Object.fromEntries(phases.map(name => [name, () => { log.push(name); return settled(); }])),
    cancellationCleanup: () => { log.push("cancellationCleanup"); return settled(); },
  };
}

test("partial runner emits construction/write/readback evidence without install claims", async () => {
  const log = [];
  const result = await runWindowsImagingPartial({ ...pins, actions: actions(log) });
  assert.equal(result.mode, "partial");
  assert.equal(result.claim, "construction-write-readback");
  assert.equal(result.published, false);
  assert.equal(result.steamOsInstalled, false);
  assert.deepEqual(log, [...phases, "cancellationCleanup"]);
});

test("all independent identities fail before action work", async () => {
  for (const changed of [
    { expectedExeSha256: "c".repeat(64) },
    { expectedSteamOsImage: { ...steamOs, bytes: steamOs.bytes + 1 } },
    { expectedDriverBundle: { ...bundle, manifestSha256: "c".repeat(64) } },
    { expectedVirtualUsb: { ...usb, identitySha256: "c".repeat(64) } },
    { virtualUsb: { ...usb, capacityBytes: usb.capacityBytes - 1 } },
  ]) {
    const log = [];
    await assert.rejects(runWindowsImagingPartial({ ...pins, ...changed, actions: actions(log) }));
    assert.deepEqual(log, []);
  }
});

test("missing, unowned, and false phase results fail closed", async () => {
  const missing = actions(); delete missing.candidateFlushed;
  await assert.rejects(runWindowsImagingPartial({ ...pins, actions: missing }), /missing: candidateFlushed/);
  const unowned = actions(); unowned.imageExported = async () => true;
  await assert.rejects(runWindowsImagingPartial({ ...pins, actions: unowned }), /owned operation/);
  const failed = actions(); failed.completeReadbackHashMatched = () => settled(false);
  await assert.rejects(runWindowsImagingPartial({ ...pins, actions: failed }), /did not prove success/);
});

test("mid-write cancellation settles before owned cleanup", async () => {
  const log = [];
  const controller = new AbortController();
  const value = actions(log);
  let release;
  value.candidateWroteCompleteImage = () => ({
    completion: new Promise(resolve => { release = resolve; }),
    cancelAndWait: async () => { log.push("write-settled"); release(false); return true; },
  });
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(runWindowsImagingPartial({ ...pins, actions: value, signal: controller.signal, timeoutMs: 100 }), /cancelled/);
  assert.equal(log.indexOf("write-settled") < log.indexOf("cancellationCleanup"), true);
});

test("cleanup timeout cancels and settles inside the same total deadline", async () => {
  const value = actions();
  let release;
  let settled = false;
  value.cancellationCleanup = () => ({
    completion: new Promise(resolve => { release = resolve; }),
    cancelAndWait: async () => { settled = true; release(false); return true; },
  });
  await assert.rejects(runWindowsImagingPartial({ ...pins, actions: value, timeoutMs: 40 }), /timed out during cancellationCleanup/);
  assert.equal(settled, true);
});

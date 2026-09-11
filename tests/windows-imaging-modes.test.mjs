import assert from "node:assert/strict";
import test from "node:test";
import { validateWindowsImagingResult, windowsImagingMode } from "../scripts/windows-imaging-modes.mjs";

const sha = "a".repeat(64);
const commit = "b".repeat(40);

function driverBundle() {
  return {
    offlineValidated: true,
    manifestSha256: sha,
    schemaVersion: 1,
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
    provenanceSha256: sha,
    buildEvidenceSha256: sha,
  };
}

function result(mode) {
  const spec = windowsImagingMode(mode);
  const base = {
    schemaVersion: 1, status: "passed", mode, claim: spec.claim,
    sealedWindowsBase: true, disposableOverlay: true, windowsReinstalled: false,
    combinedNvidiaSteamOsAsset: false, published: false,
    exeCommit: commit, exeSha256: sha,
    evidence: Object.fromEntries(spec.requires.map(field => [field, true])),
  };
  if (mode === "full") Object.assign(base, { retainedUsbBooted: true, steamOsInstalled: true, steamOsReinstalled: true, reinstallBooted: true, installSuccess: true });
  else Object.assign(base, { retainedUsbBooted: false, steamOsInstalled: false, steamOsReinstalled: false, reinstallBooted: false, installSuccess: false });
  if (mode !== "short") base.driverBundle = driverBundle();
  return base;
}

function validate(value, requiredMode) {
  return validateWindowsImagingResult(value, requiredMode, value.mode === "short" ? undefined : driverBundle());
}

test("modes expose distinct claims and require an independent requested mode", () => {
  assert.deepEqual(windowsImagingMode("short").targetMinutes, [5, 20]);
  assert.equal(windowsImagingMode("partial").claim, "construction-write-readback");
  assert.equal(windowsImagingMode("full").claim, "publication-gate");
  for (const value of [undefined, "", "fast", "FULL", "full "]) assert.throws(() => windowsImagingMode(value), /explicitly/);
  assert.throws(() => validateWindowsImagingResult(result("short")), /explicitly/);
});

test("short never satisfies partial or full", () => {
  assert.equal(validate(result("short"), "short").accepted, true);
  assert.throws(() => validate(result("short"), "partial"), /shorter/);
  assert.throws(() => validate(result("partial"), "full"), /shorter/);
});

test("every required evidence bit fails closed", () => {
  for (const mode of ["short", "partial", "full"]) {
    const base = result(mode);
    for (const field of Object.keys(base.evidence)) {
      const changed = structuredClone(base); delete changed.evidence[field];
      assert.throws(() => validate(changed, mode), new RegExp(field));
    }
  }
});

test("negative boundary declarations must be present and false", () => {
  for (const field of ["windowsReinstalled", "combinedNvidiaSteamOsAsset", "published"]) {
    for (const value of [undefined, true]) {
      const changed = result("partial");
      if (value === undefined) delete changed[field]; else changed[field] = value;
      assert.throws(() => validate(changed, "partial"));
    }
  }
});

test("short and partial explicitly deny every boot, install, and reinstall claim", () => {
  const fields = ["retainedUsbBooted", "steamOsInstalled", "steamOsReinstalled", "reinstallBooted", "installSuccess"];
  for (const mode of ["short", "partial"]) for (const field of fields) for (const value of [undefined, true]) {
    const changed = result(mode);
    if (value === undefined) delete changed[field]; else changed[field] = value;
    assert.throws(() => validate(changed, mode), /explicitly deny/);
  }
});

test("full requires affirmative boot, install, and reinstall claims", () => {
  for (const field of ["retainedUsbBooted", "steamOsInstalled", "steamOsReinstalled", "reinstallBooted", "installSuccess"]) for (const value of [undefined, false]) {
    const changed = result("full");
    if (value === undefined) delete changed[field]; else changed[field] = value;
    assert.throws(() => validate(changed, "full"), /incomplete/);
  }
});

test("non-short validation requires and matches an independent bundle requirement", () => {
  const partial = result("partial");
  assert.throws(() => validateWindowsImagingResult(partial, "partial"), /requirement/);
  const changedPin = driverBundle();
  changedPin.manifestSha256 = "c".repeat(64);
  assert.throws(() => validateWindowsImagingResult(partial, "partial", changedPin), /does not match/);
});

test("every immutable driver-only bundle identity fails closed when omitted or altered", () => {
  const mutations = [
    b => { delete b.manifestSha256; }, b => { b.manifestSha256 = "A".repeat(64); },
    b => { delete b.offlineValidated; }, b => { b.offlineValidated = false; },
    b => { delete b.schemaVersion; }, b => { b.schemaVersion = 2; },
    b => { delete b.contract.releaseBundleManifestSchemaVersion; }, b => { b.contract.driverProductManifestSchemaVersion = 2; },
    b => { delete b.release.repository; }, b => { delete b.release.tag; },
    b => { delete b.core.commit; }, b => { delete b.source.repository; },
    b => { delete b.target.kernelVersion; }, b => { b.target.architecture = "aarch64"; },
    b => { delete b.compatibility.kernel; }, b => { b.compatibility.fallback = true; },
    b => { delete b.assets[0].bytes; }, b => { b.assets[0].sha256 = "A".repeat(64); },
    b => { delete b.assets[1].bytes; }, b => { b.assets[1].name = "different.sha256"; },
    b => { delete b.provenanceSha256; }, b => { delete b.buildEvidenceSha256; },
  ];
  for (const mutate of mutations) {
    const changed = result("partial"); mutate(changed.driverBundle);
    assert.throws(() => validate(changed, "partial"));
  }
});

test("overlay, executable, and claim identities remain fail closed", () => {
  for (const mutate of [
    r => { r.sealedWindowsBase = false; }, r => { r.disposableOverlay = false; },
    r => { r.exeSha256 = "A".repeat(64); }, r => { r.claim = "end-to-end"; },
  ]) {
    const changed = result("partial"); mutate(changed);
    assert.throws(() => validate(changed, "partial"));
  }
});

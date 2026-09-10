#!/usr/bin/env node
const MODES = Object.freeze({
  short: { claim: "bounded-feedback", targetMinutes: [5, 20], requires: ["unitContractsUi", "usbEnumeration", "physicalDiskRefusal", "driverBundleManifest", "cancellationCleanup", "smallWriterFixture"] },
  partial: { claim: "construction-write-readback", targetMinutes: [120, 240], requires: ["officialSteamOsAuthenticated", "immutableDriverOnlyRelease", "driverBundleOfflineValidated", "imageConstructed", "imageExported", "candidateEnumeratedOwned32GiBUsb", "candidateWroteCompleteImage", "candidateFlushed", "completeReadbackHashMatched"] },
  full: { claim: "publication-gate", targetMinutes: [360, 600], requires: ["officialSteamOsAuthenticated", "immutableDriverOnlyRelease", "driverBundleOfflineValidated", "driverBundleSourceEvidence", "imageConstructed", "imageExported", "candidateEnumeratedOwned32GiBUsb", "candidateWroteCompleteImage", "candidateFlushed", "completeReadbackHashMatched", "retainedUsbBooted", "steamOsInstalled", "steamOsReinstalled", "reinstallBooted", "noOrphans"] },
});
const HEX40 = /^[0-9a-f]{40}$/; const HEX64 = /^[0-9a-f]{64}$/;
function fail(message) { throw new Error(message); }
export function windowsImagingMode(mode) {
  if (!Object.hasOwn(MODES, mode)) fail("Windows imaging mode must be explicitly short, partial, or full.");
  return structuredClone(MODES[mode]);
}
export function validateWindowsImagingResult(result, requiredMode = result?.mode) {
  const selected = windowsImagingMode(result?.mode); const required = windowsImagingMode(requiredMode);
  const order = ["short", "partial", "full"];
  if (order.indexOf(result.mode) < order.indexOf(requiredMode)) fail("A shorter Windows imaging mode cannot satisfy the required mode.");
  if (result.schemaVersion !== 1 || result.status !== "passed" || result.claim !== selected.claim) fail("Windows imaging result identity is invalid.");
  if (result.sealedWindowsBase !== true || result.disposableOverlay !== true || result.windowsReinstalled === true) fail("Windows imaging must reuse the sealed base through a disposable overlay.");
  if (result.combinedNvidiaSteamOsAsset === true) fail("Combined NVIDIA and SteamOS release assets are forbidden.");
  if (!HEX40.test(result.exeCommit || "") || !HEX64.test(result.exeSha256 || "")) fail("Candidate executable identity is invalid.");
  for (const field of selected.requires) if (result.evidence?.[field] !== true) fail(`Windows ${result.mode} evidence is incomplete: ${field}.`);
  if (result.mode !== "short") {
    if (!HEX40.test(result.coreCommit || "") || !HEX40.test(result.driverSourceCommit || "") || !HEX64.test(result.bundleManifestSha256 || "") || !result.releaseTag || !result.bundleAssetName) fail("Immutable driver-only bundle identity is incomplete.");
    if (result.installSuccess === true && result.mode !== "full") fail("Partial mode cannot claim install or reinstall success.");
  }
  if (result.mode === "full" && result.published === true) fail("Validation does not authorize publication.");
  return { schemaVersion: 1, mode: result.mode, requiredMode, claim: selected.claim, targetMinutes: selected.targetMinutes, accepted: true };
}

#!/usr/bin/env node

const MODES = Object.freeze({
  short: {
    claim: "bounded-feedback",
    targetMinutes: [5, 20],
    requires: ["unitContractsUi", "usbEnumeration", "physicalDiskRefusal", "driverBundleManifest", "cancellationCleanup", "smallWriterFixture"],
  },
  partial: {
    claim: "construction-write-readback",
    targetMinutes: [120, 240],
    requires: ["officialSteamOsAuthenticated", "immutableDriverOnlyRelease", "driverBundleOfflineValidated", "imageConstructed", "imageExported", "candidateEnumeratedOwned32GiBUsb", "candidateWroteCompleteImage", "candidateFlushed", "completeReadbackHashMatched"],
  },
  full: {
    claim: "publication-gate",
    targetMinutes: [360, 600],
    requires: ["officialSteamOsAuthenticated", "immutableDriverOnlyRelease", "driverBundleOfflineValidated", "driverBundleSourceEvidence", "imageConstructed", "imageExported", "candidateEnumeratedOwned32GiBUsb", "candidateWroteCompleteImage", "candidateFlushed", "completeReadbackHashMatched", "retainedUsbBooted", "steamOsInstalled", "steamOsReinstalled", "reinstallBooted", "noOrphans"],
  },
});

const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$/;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024;

function fail(message) { throw new Error(message); }

export function windowsImagingMode(mode) {
  if (!Object.hasOwn(MODES, mode)) fail("Windows imaging mode must be explicitly short, partial, or full.");
  return structuredClone(MODES[mode]);
}

function validateIdentity(identity, label) {
  if (!identity || !REPOSITORY.test(identity.repository || "") || !HEX40.test(identity.commit || "")) {
    fail(`Immutable driver-only bundle ${label} identity is incomplete.`);
  }
}

function validateAsset(asset, role) {
  if (asset?.role !== role || !SAFE_NAME.test(asset.name || "") || !Number.isSafeInteger(asset.bytes) || asset.bytes <= 0 || asset.bytes > MAX_ASSET_BYTES || !HEX64.test(asset.sha256 || "")) {
    fail(`Immutable driver-only bundle ${role} asset identity is incomplete.`);
  }
}

function validateDriverBundle(bundle, expectedBundle) {
  if (!bundle || bundle.offlineValidated !== true || !HEX64.test(bundle.manifestSha256 || "")) fail("Immutable driver-only bundle manifest identity is incomplete.");
  if (!expectedBundle) fail("Independent immutable driver-only bundle requirement is missing.");
  if (bundle.schemaVersion !== 1 || bundle.kind !== "opemos-driver-binary-bundle" || bundle.contract?.releaseBundleManifestSchemaVersion !== 1 || bundle.contract?.driverProductManifestSchemaVersion !== 1) fail("Immutable driver-only bundle schema identity is incomplete.");
  if (!REPOSITORY.test(bundle.release?.repository || "") || typeof bundle.release?.tag !== "string" || bundle.release.tag.length < 1 || bundle.release.tag.length > 255) fail("Immutable driver-only bundle Release identity is incomplete.");
  validateIdentity(bundle.core, "Core");
  validateIdentity(bundle.source, "source");
  if (bundle.target?.architecture !== "x86_64" || !bundle.target?.steamosVersion || !bundle.target?.kernelVersion || !bundle.target?.nvidiaVersion) fail("Immutable driver-only bundle target identity is incomplete.");
  if (bundle.compatibility?.architecture !== "exact" || bundle.compatibility?.kernel !== "exact" || bundle.compatibility?.fallback !== false) fail("Immutable driver-only bundle compatibility identity is incomplete.");
  if (!Array.isArray(bundle.assets) || bundle.assets.length !== 2) fail("Immutable driver-only bundle asset inventory is incomplete.");
  validateAsset(bundle.assets[0], "driver-product");
  validateAsset(bundle.assets[1], "sha256-sidecar");
  if (bundle.assets[1].name !== `${bundle.assets[0].name}.sha256`) fail("Immutable driver-only bundle asset inventory is inconsistent.");
  if (!HEX64.test(bundle.provenanceSha256 || "") || !HEX64.test(bundle.buildEvidenceSha256 || "")) fail("Immutable driver-only bundle provenance and build-source evidence is incomplete.");
  if (JSON.stringify(bundle) !== JSON.stringify({ ...expectedBundle, offlineValidated: true })) fail("Driver-only bundle result does not match the independent immutable requirement.");
}

export function validateWindowsImagingResult(result, requiredMode, expectedDriverBundle) {
  const selected = windowsImagingMode(result?.mode);
  windowsImagingMode(requiredMode);
  const order = ["short", "partial", "full"];
  if (order.indexOf(result.mode) < order.indexOf(requiredMode)) fail("A shorter Windows imaging mode cannot satisfy the required mode.");
  if (result.schemaVersion !== 1 || result.status !== "passed" || result.claim !== selected.claim) fail("Windows imaging result identity is invalid.");
  if (result.sealedWindowsBase !== true || result.disposableOverlay !== true || result.windowsReinstalled !== false) fail("Windows imaging must explicitly reuse the sealed base through a disposable overlay without reinstalling Windows.");
  if (result.combinedNvidiaSteamOsAsset !== false) fail("Combined NVIDIA and SteamOS release assets must be explicitly absent.");
  if (result.published !== false) fail("Validation must explicitly declare that publication did not occur.");
  if (!HEX40.test(result.exeCommit || "") || !HEX64.test(result.exeSha256 || "")) fail("Candidate executable identity is invalid.");
  for (const field of selected.requires) if (result.evidence?.[field] !== true) fail(`Windows ${result.mode} evidence is incomplete: ${field}.`);
  if (result.mode !== "full" && ["retainedUsbBooted", "steamOsInstalled", "steamOsReinstalled", "reinstallBooted", "installSuccess"].some(field => result[field] !== false)) fail(`${result.mode} mode must explicitly deny boot, install, and reinstall claims.`);
  if (result.mode === "full" && ["retainedUsbBooted", "steamOsInstalled", "steamOsReinstalled", "reinstallBooted", "installSuccess"].some(field => result[field] !== true)) fail("Full mode boot, install, and reinstall claims are incomplete.");
  if (result.mode !== "short") validateDriverBundle(result.driverBundle, expectedDriverBundle);
  return { schemaVersion: 1, mode: result.mode, requiredMode, claim: selected.claim, targetMinutes: selected.targetMinutes, accepted: true };
}

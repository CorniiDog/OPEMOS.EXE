#!/usr/bin/env node
import { validateWindowsImagingResult, windowsImagingMode } from "./windows-imaging-modes.mjs";

const PHASES = Object.freeze([
  "officialSteamOsAuthenticated",
  "immutableDriverOnlyRelease",
  "driverBundleOfflineValidated",
  "imageConstructed",
  "imageExported",
  "candidateEnumeratedOwned32GiBUsb",
  "candidateWroteCompleteImage",
  "candidateFlushed",
  "completeReadbackHashMatched",
]);
const CLEANUP = "cancellationCleanup";
const COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const USB_BYTES = 32 * 1024 ** 3;

function fail(message) { throw new Error(message); }
function left(deadline) {
  const value = deadline - Date.now();
  if (value <= 0) fail("Windows partial mode exhausted its total deadline.");
  return value;
}
function exact(actual, expected, label) {
  if (!expected || JSON.stringify(actual) !== JSON.stringify(expected)) fail(label + " does not match independent pins.");
}
function validateSteamOs(image) {
  let source;
  try { source = new URL(image?.url); } catch { fail("Official SteamOS identity is incomplete."); }
  if (!image || image.schemaVersion !== 1 || image.kind !== "official-steamos-recovery" ||
      source.protocol !== "https:" || source.hostname !== "steamdeck-images.steamos.cloud" ||
      !Number.isSafeInteger(image.bytes) || image.bytes <= 0 ||
      !SHA256.test(image.sha256 || "") || !SHA256.test(image.authenticationEvidenceSha256 || "")) {
    fail("Official SteamOS identity is incomplete.");
  }
}
function validateCandidate(commit, sha256, expectedCommit, expectedSha256) {
  if (!COMMIT.test(expectedCommit || "") || !SHA256.test(expectedSha256 || "") ||
      commit !== expectedCommit || sha256 !== expectedSha256) {
    fail("Candidate executable identity does not match independent pins.");
  }
}
function validateTarget(target, expectedTarget) {
  if (!target || target.schemaVersion !== 1 || target.kind !== "harness-owned-virtual-usb" ||
      target.capacityBytes !== USB_BYTES || !SHA256.test(target.identitySha256 || "")) {
    fail("Partial mode requires the exact harness-owned 32 GiB virtual USB.");
  }
  exact(target, expectedTarget, "Virtual USB identity");
}
function requireActions(actions) {
  if (!actions || typeof actions !== "object" || Array.isArray(actions)) fail("Windows partial-mode actions are required.");
  for (const name of [...PHASES, CLEANUP]) {
    if (typeof actions[name] !== "function") fail("Windows partial-mode action is missing: " + name + ".");
  }
}
function owned(value, label) {
  if (!value || typeof value !== "object" || !value.completion || typeof value.cancelAndWait !== "function") {
    fail("Windows partial-mode action did not return an owned operation: " + label + ".");
  }
  return value;
}
async function bounded(promise, deadline, message) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve(promise),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), left(deadline)); }),
    ]);
  } finally { clearTimeout(timer); }
}
async function runOwned(action, context, phaseDeadline, totalDeadline, label) {
  const operation = owned(action(context), label);
  let timer;
  let rejectAbort;
  let failure;
  const onAbort = () => rejectAbort(new Error("Windows partial mode was cancelled during " + label + "."));
  const aborted = new Promise((_, reject) => {
    rejectAbort = reject;
    if (context.signal.aborted) onAbort();
    else context.signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("Windows partial mode timed out during " + label + ".")), left(phaseDeadline));
    });
    const result = await Promise.race([Promise.resolve(operation.completion), aborted, timeout]);
    if (result !== true) fail("Windows partial-mode action did not prove success: " + label + ".");
    return;
  } catch (error) { failure = error; }
  finally {
    clearTimeout(timer);
    context.signal.removeEventListener("abort", onAbort);
  }
  context.controller.abort();
  const stopped = await bounded(operation.cancelAndWait(), totalDeadline, "Windows partial-mode action did not settle: " + label + ".");
  if (stopped !== true) fail("Windows partial-mode action did not prove cancellation and settlement: " + label + ".");
  await bounded(Promise.resolve(operation.completion).catch(() => false), totalDeadline, "Windows partial-mode action remained unsettled: " + label + ".");
  throw failure;
}

export async function runWindowsImagingPartial({
  exeCommit, exeSha256, expectedExeCommit, expectedExeSha256,
  steamOsImage, expectedSteamOsImage, driverBundle, expectedDriverBundle,
  virtualUsb, expectedVirtualUsb, actions, signal, timeoutMs = 4 * 60 * 60 * 1000,
}) {
  requireActions(actions);
  validateCandidate(exeCommit, exeSha256, expectedExeCommit, expectedExeSha256);
  validateSteamOs(steamOsImage);
  exact(steamOsImage, expectedSteamOsImage, "Official SteamOS identity");
  exact(driverBundle, expectedDriverBundle, "Driver-only bundle identity");
  validateTarget(virtualUsb, expectedVirtualUsb);
  validateWindowsImagingResult({
    schemaVersion: 1, status: "passed", mode: "partial", claim: windowsImagingMode("partial").claim,
    sealedWindowsBase: true, disposableOverlay: true, windowsReinstalled: false,
    combinedNvidiaSteamOsAsset: false, published: false,
    retainedUsbBooted: false, steamOsInstalled: false, steamOsReinstalled: false,
    reinstallBooted: false, installSuccess: false,
    exeCommit, exeSha256, driverBundle,
    evidence: Object.fromEntries(PHASES.map(name => [name, true])),
  }, "partial", expectedDriverBundle);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 20 || timeoutMs > 4 * 60 * 60 * 1000) {
    fail("Windows partial-mode timeout must be between 20 ms and 4 hours.");
  }

  const totalDeadline = Date.now() + timeoutMs;
  const reserve = Math.max(10, Math.floor(timeoutMs / 4));
  const phaseDeadline = totalDeadline - reserve;
  const controller = new AbortController();
  const relay = () => controller.abort();
  signal?.addEventListener("abort", relay, { once: true });
  if (signal?.aborted) controller.abort();
  const context = Object.freeze({
    mode: "partial", exeCommit, exeSha256, steamOsImage, driverBundle,
    virtualUsb, signal: controller.signal, controller, deadline: totalDeadline,
  });
  const evidence = {};
  let primaryError;
  try {
    for (const name of PHASES) {
      if (controller.signal.aborted) fail("Windows partial mode was cancelled.");
      await runOwned(actions[name], context, phaseDeadline, totalDeadline, name);
      evidence[name] = true;
    }
  } catch (error) { primaryError = error; }

  try {
    const cleanupBudget = left(totalDeadline);
    await runOwned(actions[CLEANUP], context, Date.now() + Math.max(1, Math.floor(cleanupBudget / 2)), totalDeadline, CLEANUP);
  } catch (cleanupError) {
    if (primaryError) throw new AggregateError([primaryError, cleanupError], "Windows partial mode failed and cleanup did not complete.");
    throw cleanupError;
  } finally { signal?.removeEventListener("abort", relay); }
  if (primaryError) throw primaryError;
  if (controller.signal.aborted) fail("Windows partial mode was cancelled.");

  const result = {
    schemaVersion: 1, status: "passed", mode: "partial",
    claim: windowsImagingMode("partial").claim,
    sealedWindowsBase: true, disposableOverlay: true, windowsReinstalled: false,
    combinedNvidiaSteamOsAsset: false, published: false,
    retainedUsbBooted: false, steamOsInstalled: false, steamOsReinstalled: false,
    reinstallBooted: false, installSuccess: false,
    exeCommit, exeSha256, driverBundle, evidence,
  };
  validateWindowsImagingResult(result, "partial", expectedDriverBundle);
  return result;
}

#!/usr/bin/env node
import { validateWindowsImagingResult, windowsImagingMode } from "./windows-imaging-modes.mjs";

const CHECKS = Object.freeze([
  "unitContractsUi",
  "usbEnumeration",
  "physicalDiskRefusal",
  "driverBundleManifest",
  "smallWriterFixture",
]);
const CLEANUP = "cancellationCleanup";
const COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;

function fail(message) { throw new Error(message); }

function requireActions(actions) {
  if (!actions || typeof actions !== "object" || Array.isArray(actions)) fail("Windows short-mode actions are required.");
  for (const name of [...CHECKS, CLEANUP]) if (typeof actions[name] !== "function") fail(`Windows short-mode action is missing: ${name}.`);
}

async function bounded(action, context, deadline, label) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) fail(`Windows short mode timed out before ${label}.`);
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Windows short mode timed out during ${label}.`)), remaining);
  });
  try {
    const value = await Promise.race([Promise.resolve().then(() => action(context)), timeout]);
    if (value !== true) fail(`Windows short-mode action did not prove success: ${label}.`);
  } finally {
    clearTimeout(timer);
  }
}

export async function runWindowsImagingShort({
  exeCommit,
  exeSha256,
  actions,
  signal,
  timeoutMs = 20 * 60 * 1000,
}) {
  requireActions(actions);
  if (!COMMIT.test(exeCommit || "") || !SHA256.test(exeSha256 || "")) fail("Candidate executable identity is invalid.");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 20 * 60 * 1000) fail("Windows short-mode timeout must be between 1 ms and 20 minutes.");
  const deadline = Date.now() + timeoutMs;
  const evidence = {};
  const context = Object.freeze({ mode: "short", exeCommit, exeSha256, signal, deadline });
  let primaryError;
  try {
    for (const name of CHECKS) {
      if (signal?.aborted) fail("Windows short mode was cancelled.");
      await bounded(actions[name], context, deadline, name);
      evidence[name] = true;
    }
  } catch (error) {
    primaryError = error;
  }
  try {
    const cleanupDeadline = Math.max(deadline, Date.now() + Math.min(timeoutMs, 5_000));
    await bounded(actions[CLEANUP], context, cleanupDeadline, CLEANUP);
    evidence[CLEANUP] = true;
  } catch (cleanupError) {
    if (primaryError) throw new AggregateError([primaryError, cleanupError], "Windows short mode failed and cleanup did not complete.");
    throw cleanupError;
  }
  if (primaryError) throw primaryError;
  if (signal?.aborted) fail("Windows short mode was cancelled.");

  const spec = windowsImagingMode("short");
  const result = {
    schemaVersion: 1,
    status: "passed",
    mode: "short",
    claim: spec.claim,
    sealedWindowsBase: true,
    disposableOverlay: true,
    windowsReinstalled: false,
    combinedNvidiaSteamOsAsset: false,
    published: false,
    retainedUsbBooted: false,
    steamOsInstalled: false,
    steamOsReinstalled: false,
    reinstallBooted: false,
    installSuccess: false,
    exeCommit,
    exeSha256,
    evidence,
  };
  validateWindowsImagingResult(result, "short");
  return result;
}

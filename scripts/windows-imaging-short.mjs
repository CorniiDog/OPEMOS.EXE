#!/usr/bin/env node
import { validateWindowsImagingResult, windowsImagingMode } from "./windows-imaging-modes.mjs";

const CHECKS = Object.freeze(["unitContractsUi", "usbEnumeration", "physicalDiskRefusal", "driverBundleManifest", "smallWriterFixture"]);
const CLEANUP = "cancellationCleanup";
const COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;

function fail(message) { throw new Error(message); }
function remaining(deadline) {
  const value = deadline - Date.now();
  if (value <= 0) fail("Windows short mode exhausted its total deadline.");
  return value;
}
async function beforeDeadline(promise, deadline, message) {
  let timer;
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), remaining(deadline));
    });
    return await Promise.race([Promise.resolve(promise), timeout]);
  } finally {
    clearTimeout(timer);
  }
}
function requireActions(actions) {
  if (!actions || typeof actions !== "object" || Array.isArray(actions)) fail("Windows short-mode actions are required.");
  for (const name of [...CHECKS, CLEANUP]) if (typeof actions[name] !== "function") fail(`Windows short-mode action is missing: ${name}.`);
}
function operationFrom(value, label) {
  if (!value || typeof value !== "object" || !value.completion || typeof value.cancelAndWait !== "function") {
    fail(`Windows short-mode action did not return an owned operation: ${label}.`);
  }
  return value;
}

async function runOwnedAction(action, context, actionDeadline, totalDeadline, label) {
  const operation = operationFrom(action(context), label);
  let failure;
  let passed;
  let timer;
  let rejectAbort;
  const onAbort = () => rejectAbort(new Error(`Windows short mode was cancelled during ${label}.`));
  const aborted = new Promise((_, reject) => {
    rejectAbort = reject;
    if (context.signal.aborted) onAbort();
    else context.signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Windows short mode timed out during ${label}.`)), remaining(actionDeadline));
    });
    passed = await Promise.race([Promise.resolve(operation.completion), aborted, timeout]);
    if (passed !== true) fail(`Windows short-mode action did not prove success: ${label}.`);
    return;
  } catch (error) {
    failure = error;
  } finally {
    clearTimeout(timer);
    context.signal.removeEventListener("abort", onAbort);
  }
  context.controller.abort();
  const stopped = await beforeDeadline(operation.cancelAndWait(), totalDeadline, `Windows short-mode action did not settle before the total deadline: ${label}.`);
  if (stopped !== true) fail(`Windows short-mode action did not prove cancellation and settlement: ${label}.`);
  await beforeDeadline(Promise.resolve(operation.completion).catch(() => false), totalDeadline, `Windows short-mode action remained unsettled: ${label}.`);
  throw failure;
}

export async function runWindowsImagingShort({
  exeCommit,
  exeSha256,
  expectedExeCommit,
  expectedExeSha256,
  actions,
  signal,
  timeoutMs = 20 * 60 * 1000,
}) {
  requireActions(actions);
  if (!COMMIT.test(expectedExeCommit || "") || !SHA256.test(expectedExeSha256 || "") || exeCommit !== expectedExeCommit || exeSha256 !== expectedExeSha256) fail("Candidate executable identity does not match independent pins.");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 20 * 60 * 1000) fail("Windows short-mode timeout must be between 10 ms and 20 minutes.");

  const totalDeadline = Date.now() + timeoutMs;
  const teardownReserve = Math.max(5, Math.floor(timeoutMs / 4));
  const actionDeadline = totalDeadline - teardownReserve;
  const controller = new AbortController();
  const relay = () => controller.abort();
  signal?.addEventListener("abort", relay, { once: true });
  if (signal?.aborted) controller.abort();
  const context = Object.freeze({ mode: "short", exeCommit, exeSha256, signal: controller.signal, controller, deadline: totalDeadline });
  const evidence = {};
  let primaryError;
  try {
    for (const name of CHECKS) {
      if (controller.signal.aborted) fail("Windows short mode was cancelled.");
      await runOwnedAction(actions[name], context, actionDeadline, totalDeadline, name);
      evidence[name] = true;
    }
  } catch (error) {
    primaryError = error;
  } finally {
    signal?.removeEventListener("abort", relay);
  }

  try {
    const cleaned = await beforeDeadline(actions[CLEANUP](context), totalDeadline, "Windows short-mode cleanup exceeded the total deadline.");
    if (cleaned !== true) fail("Windows short-mode cleanup did not prove success.");
    evidence[CLEANUP] = true;
  } catch (cleanupError) {
    if (primaryError) throw new AggregateError([primaryError, cleanupError], "Windows short mode failed and cleanup did not complete.");
    throw cleanupError;
  }
  if (primaryError) throw primaryError;
  if (controller.signal.aborted) fail("Windows short mode was cancelled.");

  const spec = windowsImagingMode("short");
  const result = {
    schemaVersion: 1, status: "passed", mode: "short", claim: spec.claim,
    sealedWindowsBase: true, disposableOverlay: true, windowsReinstalled: false,
    combinedNvidiaSteamOsAsset: false, published: false,
    retainedUsbBooted: false, steamOsInstalled: false, steamOsReinstalled: false,
    reinstallBooted: false, installSuccess: false,
    exeCommit, exeSha256, evidence,
  };
  validateWindowsImagingResult(result, "short");
  return result;
}

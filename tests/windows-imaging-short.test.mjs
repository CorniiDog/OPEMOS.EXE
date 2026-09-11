import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import test from "node:test";
import { runWindowsImagingShort } from "../scripts/windows-imaging-short.mjs";

const commit = "b".repeat(40);
const sha = "a".repeat(64);
const names = ["unitContractsUi", "usbEnumeration", "physicalDiskRefusal", "driverBundleManifest", "smallWriterFixture"];
const pins = { exeCommit: commit, exeSha256: sha, expectedExeCommit: commit, expectedExeSha256: sha };

function settled(value = true) {
  return { completion: Promise.resolve(value), cancelAndWait: async () => true };
}
function actions(log = []) {
  return {
    ...Object.fromEntries(names.map(name => [name, () => { log.push(name); return settled(); }])),
    cancellationCleanup: () => { log.push("cancellationCleanup"); return settled(); },
  };
}

test("short runner emits only a validated bounded-feedback result", async () => {
  const log = [];
  const result = await runWindowsImagingShort({ ...pins, actions: actions(log) });
  assert.equal(result.mode, "short");
  assert.equal(result.claim, "bounded-feedback");
  assert.equal(result.published, false);
  assert.equal(result.steamOsInstalled, false);
  assert.deepEqual(log, [...names, "cancellationCleanup"]);
});

test("candidate identity must match independent pins before actions", async () => {
  const log = [];
  await assert.rejects(runWindowsImagingShort({ ...pins, expectedExeCommit: "c".repeat(40), actions: actions(log) }), /independent pins/);
  assert.deepEqual(log, []);
});

test("missing, unowned, and non-success actions fail closed", async () => {
  const missing = actions(); delete missing.physicalDiskRefusal;
  await assert.rejects(runWindowsImagingShort({ ...pins, actions: missing }), /missing: physicalDiskRefusal/);
  const unowned = actions(); unowned.usbEnumeration = () => Promise.resolve(true);
  await assert.rejects(runWindowsImagingShort({ ...pins, actions: unowned }), /owned operation/);
  for (const value of [false, undefined, "true"]) {
    const changed = actions();
    changed.usbEnumeration = () => ({ completion: Promise.resolve(value), cancelAndWait: async () => true });
    await assert.rejects(runWindowsImagingShort({ ...pins, actions: changed }), /did not prove success/);
  }
});

test("mid-action cancellation settles owned work before cleanup", async () => {
  const order = [];
  const controller = new AbortController();
  const value = actions(order);
  let release;
  value.unitContractsUi = context => ({
    completion: new Promise(resolve => { release = resolve; }),
    cancelAndWait: async () => { order.push("settled"); release(false); return true; },
  });
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(runWindowsImagingShort({ ...pins, actions: value, signal: controller.signal, timeoutMs: 100 }), /cancelled/);
  assert.deepEqual(order, ["settled", "cancellationCleanup"]);
});

test("timeout kills and waits for a real child before cleanup", async () => {
  const order = [];
  const value = actions(order);
  let child;
  value.unitContractsUi = () => {
    child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
    const completion = new Promise(resolve => child.once("exit", () => resolve(false)));
    return {
      completion,
      cancelAndWait: async () => {
        child.kill();
        await completion;
        order.push("child-exited");
        return child.exitCode !== null || child.signalCode !== null;
      },
    };
  };
  await assert.rejects(runWindowsImagingShort({ ...pins, actions: value, timeoutMs: 200 }), /timed out/);
  assert.deepEqual(order, ["child-exited", "cancellationCleanup"]);
  assert.equal(child.exitCode !== null || child.signalCode !== null, true);
});

test("cleanup failure is terminal and preserves the primary error", async () => {
  const value = actions();
  value.unitContractsUi = () => ({ completion: Promise.reject(new Error("primary")), cancelAndWait: async () => true });
  value.cancellationCleanup = () => ({ completion: Promise.reject(new Error("cleanup")), cancelAndWait: async () => true });
  await assert.rejects(runWindowsImagingShort({ ...pins, actions: value }), error => {
    assert.equal(error instanceof AggregateError, true);
    assert.equal(error.errors.length, 2);
    return true;
  });
});

test("one total deadline also bounds and settles cleanup", async () => {
  const value = actions();
  let settledCleanup = false;
  let release;
  value.cancellationCleanup = () => ({
    completion: new Promise(resolve => { release = resolve; }),
    cancelAndWait: async () => { settledCleanup = true; release(false); return true; },
  });
  await assert.rejects(runWindowsImagingShort({ ...pins, actions: value, timeoutMs: 30 }), /timed out during cancellationCleanup/);
  assert.equal(settledCleanup, true);
});

test("mid-cleanup cancellation is observed and settled", async () => {
  const controller = new AbortController();
  const value = actions();
  let release;
  let settledCleanup = false;
  value.cancellationCleanup = () => ({
    completion: new Promise(resolve => { release = resolve; }),
    cancelAndWait: async () => { settledCleanup = true; release(false); return true; },
  });
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(runWindowsImagingShort({ ...pins, actions: value, signal: controller.signal, timeoutMs: 100 }), /cancelled during cancellationCleanup/);
  assert.equal(settledCleanup, true);
});

test("cleanup timeout kills and waits for its real child", async () => {
  const value = actions();
  let child;
  let observedExit = false;
  value.cancellationCleanup = () => {
    child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
    const completion = new Promise(resolve => child.once("exit", () => { observedExit = true; resolve(false); }));
    return {
      completion,
      cancelAndWait: async () => { child.kill(); await completion; return observedExit; },
    };
  };
  await assert.rejects(runWindowsImagingShort({ ...pins, actions: value, timeoutMs: 100 }), /timed out during cancellationCleanup/);
  assert.equal(observedExit, true);
  assert.equal(child.exitCode !== null || child.signalCode !== null, true);
});

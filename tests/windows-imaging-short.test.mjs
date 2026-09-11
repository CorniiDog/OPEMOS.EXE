import assert from "node:assert/strict";
import test from "node:test";
import { runWindowsImagingShort } from "../scripts/windows-imaging-short.mjs";

const commit = "b".repeat(40);
const sha = "a".repeat(64);
const names = ["unitContractsUi", "usbEnumeration", "physicalDiskRefusal", "driverBundleManifest", "smallWriterFixture", "cancellationCleanup"];

function actions(log = []) {
  return Object.fromEntries(names.map(name => [name, async context => {
    assert.equal(context.mode, "short");
    log.push(name);
    return true;
  }]));
}

test("short runner emits only a validated bounded-feedback result", async () => {
  const log = [];
  const result = await runWindowsImagingShort({ exeCommit: commit, exeSha256: sha, actions: actions(log) });
  assert.equal(result.mode, "short");
  assert.equal(result.claim, "bounded-feedback");
  assert.equal(result.published, false);
  assert.equal(result.steamOsInstalled, false);
  assert.deepEqual(log, names);
  assert.deepEqual(Object.keys(result.evidence).sort(), [...names].sort());
});

test("short runner rejects missing and non-success actions", async () => {
  const missing = actions();
  delete missing.physicalDiskRefusal;
  await assert.rejects(runWindowsImagingShort({ exeCommit: commit, exeSha256: sha, actions: missing }), /missing: physicalDiskRefusal/);
  for (const value of [false, undefined, "true"]) {
    const changed = actions();
    changed.usbEnumeration = async () => value;
    await assert.rejects(runWindowsImagingShort({ exeCommit: commit, exeSha256: sha, actions: changed }), /did not prove success/);
  }
});

test("failure and cancellation still run cleanup exactly once", async () => {
  for (const setup of [
    value => { value.unitContractsUi = async () => { throw new Error("check failed"); }; },
    (value, controller) => { controller.abort(); },
  ]) {
    const log = [];
    const controller = new AbortController();
    const value = actions(log);
    setup(value, controller);
    await assert.rejects(runWindowsImagingShort({ exeCommit: commit, exeSha256: sha, actions: value, signal: controller.signal }), /failed|cancelled/);
    assert.deepEqual(log, ["cancellationCleanup"]);
  }
});

test("absolute timeout is bounded and cleanup follows the timed-out action", async () => {
  const log = [];
  const value = actions(log);
  value.unitContractsUi = () => new Promise(() => {});
  await assert.rejects(runWindowsImagingShort({ exeCommit: commit, exeSha256: sha, actions: value, timeoutMs: 20 }), /timed out/);
  assert.deepEqual(log, ["cancellationCleanup"]);
});

test("cleanup failure is terminal and preserves a primary failure", async () => {
  const value = actions();
  value.unitContractsUi = async () => { throw new Error("primary"); };
  value.cancellationCleanup = async () => { throw new Error("cleanup"); };
  await assert.rejects(runWindowsImagingShort({ exeCommit: commit, exeSha256: sha, actions: value }), error => {
    assert.equal(error instanceof AggregateError, true);
    assert.equal(error.errors.length, 2);
    return true;
  });
});

test("invalid candidate identity is rejected before any action runs", async () => {
  const log = [];
  await assert.rejects(runWindowsImagingShort({ exeCommit: "not-a-commit", exeSha256: sha, actions: actions(log) }), /Candidate executable identity/);
  assert.deepEqual(log, []);
});

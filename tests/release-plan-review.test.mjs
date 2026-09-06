import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { createReleaseCommandController, createReleaseReviewSession, describeReleaseOperation, normalizeReleaseOperation, releaseOperationAuthorizable } from "../src/release-plan-review.js";

const schema = JSON.parse(await readFile(new URL("./fixtures/opemos-core/release-operation-v1.schema.json", import.meta.url)));
const baseAssets = ["archive.tar", "manifest.json", "manifest.json.sig", "provenance.json"].map((name, index) => ({
  name, sha256: String(index + 1).repeat(64), bytes: index + 1, state: "pending",
}));
function operation(overrides = {}) {
  const assets = overrides.assets || baseAssets;
  const completedAssets = assets.filter((asset) => asset.state === "present").length;
  return { schemaVersion: 1, operationId: "a".repeat(64), repository: "CorniiDog/OPEMOS",
    tag: "opemos-v1", targetCommit: "b".repeat(40), attempt: 1, lifecycle: "planned",
    decision: "create", progress: { phase: "planning", completedAssets, totalAssets: assets.length, indeterminate: true },
    assets, message: "Exact release may be created.", ...overrides };
}
const planned = operation();
const presentAssets = baseAssets.map((asset) => ({ ...asset, state: "present" }));
const retryAssets = baseAssets.map((asset, index) => ({ ...asset, state: index === 3 ? "missing" : "present" }));
const completeProgress = { phase: "complete", completedAssets: 4, totalAssets: 4, indeterminate: false };
const retryProgress = { phase: "reconciling", completedAssets: 3, totalAssets: 4, indeterminate: false };

test("vendored release operation schema is the exact immutable Core contract", () => {
  assert.equal(schema.$id, "https://corniidog.github.io/OPEMOS/contracts/schemas/release-operation-v1.schema.json");
  assert.deepEqual(schema.required, ["schemaVersion", "operationId", "repository", "tag", "targetCommit", "attempt", "lifecycle", "decision", "progress", "assets"]);
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.properties.progress.required, ["phase", "completedAssets", "totalAssets", "indeterminate"]);
});

test("release review accepts and freezes one closed Core operation with matching progress", () => {
  const value = normalizeReleaseOperation(planned);
  assert.ok(value);
  assert.equal(releaseOperationAuthorizable(value), true);
  assert.throws(() => { value.progress.phase = "failed"; }, TypeError);
  assert.throws(() => { value.assets[0].state = "conflict"; }, TypeError);
});

test("release review rejects malformed, additive, duplicate, oversized, and inconsistent progress", () => {
  for (const mutation of [
    { schemaVersion: 2 }, { operationId: "A".repeat(64) }, { repository: "invalid" },
    { targetCommit: "main" }, { attempt: 0 }, { lifecycle: "executing" }, { decision: "replace" },
    { progress: { ...planned.progress, phase: "uploading" } },
    { progress: { ...planned.progress, completedAssets: 1 } },
    { assets: baseAssets.slice(0, 3) }, { assets: [...baseAssets, baseAssets[0]] }, { callerTrust: true },
  ]) assert.equal(normalizeReleaseOperation(operation(mutation)), null);
  assert.equal(normalizeReleaseOperation(operation({ assets: baseAssets.map((a, i) => i ? a : { ...a, bytes: 2147483649 }) })), null);
});

test("authorization admits only create or missing-only retry and never terminal results", () => {
  const retry = normalizeReleaseOperation(operation({ attempt: 2, lifecycle: "reconciling", decision: "retry-missing",
    progress: retryProgress, assets: retryAssets }));
  assert.equal(releaseOperationAuthorizable(retry), true);
  for (const value of [
    operation({ assets: presentAssets, progress: { ...planned.progress, completedAssets: 4 } }),
    operation({ lifecycle: "succeeded", decision: "already-complete", assets: presentAssets, progress: completeProgress }),
    operation({ lifecycle: "failed", decision: "conflict", assets: baseAssets.map((a) => ({ ...a, state: "conflict" })),
      progress: { phase: "failed", completedAssets: 0, totalAssets: 4, indeterminate: false } }),
    operation({ lifecycle: "cancelled", decision: "cancelled", progress: { phase: "cancelled", completedAssets: 0, totalAssets: 4, indeterminate: true } }),
  ]) assert.equal(releaseOperationAuthorizable(normalizeReleaseOperation(value)), false);
});

test("explicit authorization is identity-bound, idempotent, and invalidated by a new attempt", () => {
  const session = createReleaseReviewSession();
  session.review(planned);
  const first = session.authorize();
  assert.strictEqual(session.authorize(), first);
  assert.deepEqual(first, { operationId: planned.operationId, attempt: 1, decision: "create" });
  session.review(operation({ attempt: 2 }));
  assert.equal(session.snapshot().authorization, null);
});

test("terminal reconciliation explains completion, conflict, and cancellation without authorizing", () => {
  const complete = normalizeReleaseOperation(operation({ lifecycle: "succeeded", decision: "already-complete", assets: presentAssets, progress: completeProgress }));
  const conflict = normalizeReleaseOperation(operation({ lifecycle: "failed", decision: "conflict",
    assets: baseAssets.map((a) => ({ ...a, state: "conflict" })), progress: { phase: "failed", completedAssets: 0, totalAssets: 4, indeterminate: false } }));
  const cancelled = normalizeReleaseOperation(operation({ lifecycle: "cancelled", decision: "cancelled",
    progress: { phase: "cancelled", completedAssets: 0, totalAssets: 4, indeterminate: true } }));
  assert.match(describeReleaseOperation(complete), /exactly matches/);
  assert.match(describeReleaseOperation(conflict), /conflict.*blocked/i);
  assert.match(describeReleaseOperation(cancelled), /cancelled.*cannot claim success/i);
});

test("review reconciliation preserves exact ordered identity and rejects stale replacement", () => {
  const session = createReleaseReviewSession();
  session.review(planned);
  const retry = operation({ attempt: 2, lifecycle: "reconciling", decision: "retry-missing", assets: retryAssets, progress: retryProgress });
  session.reconcile(retry);
  assert.throws(() => session.reconcile({ ...retry, attempt: 3, operationId: "c".repeat(64) }), /immutable operation identity/);
  assert.throws(() => session.reconcile(planned), /stale/);
  assert.throws(() => session.reconcile({ ...retry, message: "changed" }), /existing attempt/);
});

test("closed command controller binds start, progress verification, retry, and terminal status", async () => {
  const session = createReleaseReviewSession();
  session.review(planned);
  const calls = [];
  const outputs = [
    planned,
    operation({ attempt: 2, lifecycle: "reconciling", decision: "retry-missing", assets: retryAssets, progress: retryProgress }),
    operation({ attempt: 2, lifecycle: "succeeded", decision: "already-complete", assets: presentAssets, progress: completeProgress }),
  ];
  const controller = createReleaseCommandController(session, async (command, request) => {
    calls.push([command, request]); return outputs.shift();
  });
  await assert.rejects(controller.start(), /Explicit authorization/);
  session.authorize();
  await controller.start();
  assert.deepEqual(calls[0][1].authorization, { operationId: planned.operationId, attempt: 1, decision: "create" });
  await controller.verify();
  assert.equal(session.snapshot().operation.progress.completedAssets, 3);
  await assert.rejects(controller.retry(), /Explicit authorization/);
  session.authorize();
  await controller.retry();
  assert.deepEqual(calls.map(([command]) => command), ["execute", "status", "reconcile"]);
  assert.equal(session.snapshot().operation.lifecycle, "succeeded");
});

test("command controller rejects identity substitution and concurrent commands without replacing state", async () => {
  const session = createReleaseReviewSession();
  session.review(planned);
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const controller = createReleaseCommandController(session, async () => pending);
  session.authorize();
  const first = controller.start();
  await assert.rejects(controller.verify(), /already in progress/);
  release({ ...planned, operationId: "c".repeat(64) });
  await assert.rejects(first, /immutable operation identity/);
  assert.equal(session.snapshot().operation.operationId, planned.operationId);
});

test("command cancellation is accepted once and terminal results are immutable", async () => {
  const session = createReleaseReviewSession();
  session.review(planned);
  const cancelled = operation({ lifecycle: "cancelled", decision: "cancelled",
    progress: { phase: "cancelled", completedAssets: 0, totalAssets: 4, indeterminate: true } });
  const controller = createReleaseCommandController(session, async () => cancelled);
  await controller.cancel();
  assert.equal(session.snapshot().operation.lifecycle, "cancelled");
  const altered = { ...cancelled, message: "substituted" };
  assert.throws(() => session.acceptCommandResult(altered), /terminal release result/);
});

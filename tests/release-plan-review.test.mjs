import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { normalizeReleaseOperation, releaseOperationAuthorizable } from "../src/release-plan-review.js";

const schema = JSON.parse(await readFile(new URL("./fixtures/opemos-core/release-operation-v1.schema.json", import.meta.url)));
const assets = ["archive.tar", "manifest.json", "manifest.json.sig", "provenance.json"].map((name, index) => ({
  name, sha256: String(index + 1).repeat(64), bytes: index + 1, state: "pending",
}));
const planned = { schemaVersion: 1, operationId: "a".repeat(64), repository: "CorniiDog/OPEMOS",
  tag: "opemos-v1", targetCommit: "b".repeat(40), attempt: 1, lifecycle: "planned",
  decision: "create", assets, message: "Exact release may be created." };

test("vendored release operation schema is the exact immutable Core contract", () => {
  assert.equal(schema.$id, "https://corniidog.github.io/OPEMOS/contracts/schemas/release-operation-v1.schema.json");
  assert.deepEqual(schema.required, ["schemaVersion", "operationId", "repository", "tag", "targetCommit", "attempt", "lifecycle", "decision", "assets"]);
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.properties.lifecycle.enum, ["planned", "reconciling", "succeeded", "failed", "cancelled"]);
  assert.deepEqual(schema.properties.decision.enum, ["create", "retry-missing", "already-complete", "conflict", "cancelled"]);
});

test("release review accepts and freezes one closed Core operation", () => {
  const operation = normalizeReleaseOperation(planned);
  assert.ok(operation);
  assert.equal(releaseOperationAuthorizable(operation), true);
  assert.throws(() => { operation.tag = "other"; }, TypeError);
  assert.throws(() => { operation.assets[0].state = "conflict"; }, TypeError);
});

test("release review rejects malformed, additive, duplicate, and oversized inputs", () => {
  for (const mutation of [
    { schemaVersion: 2 }, { operationId: "A".repeat(64) }, { repository: "invalid" },
    { targetCommit: "main" }, { attempt: 0 }, { lifecycle: "executing" }, { decision: "replace" },
    { assets: assets.slice(0, 3) }, { assets: [...assets, assets[0]] }, { callerTrust: true },
  ]) assert.equal(normalizeReleaseOperation({ ...planned, ...mutation }), null);
  assert.equal(normalizeReleaseOperation({ ...planned, assets: assets.map((a, i) => i ? a : { ...a, bytes: 2147483649 }) }), null);
});

test("authorization admits only create or missing-only retry and never terminal results", () => {
  const retry = normalizeReleaseOperation({ ...planned, attempt: 2, lifecycle: "reconciling", decision: "retry-missing",
    assets: assets.map((asset, index) => ({ ...asset, state: index === 3 ? "missing" : "present" })) });
  assert.equal(releaseOperationAuthorizable(retry), true);
  for (const value of [
    { ...planned, assets: assets.map((asset) => ({ ...asset, state: "present" })) },
    { ...planned, lifecycle: "succeeded", decision: "already-complete", assets: assets.map((asset) => ({ ...asset, state: "present" })) },
    { ...planned, lifecycle: "failed", decision: "conflict", assets: assets.map((asset) => ({ ...asset, state: "conflict" })) },
    { ...planned, lifecycle: "cancelled", decision: "cancelled" },
  ]) assert.equal(releaseOperationAuthorizable(normalizeReleaseOperation(value)), false);
});

import assert from "node:assert/strict";
import test from "node:test";
import { normalizeReleasePlan, releasePlanReady } from "../src/release-plan-review.js";

const valid = {
  coreCommit: "a".repeat(40),
  bundleId: "opemos-core-v1",
  bundleSha256: "b".repeat(64),
  releaseId: "opemos-release-v1",
  gates: { package: "passed", build: "passed", signature: "passed", checksum: "passed", provenance: "passed" },
};

test("release review accepts only an exact immutable identity with closed gate states", () => {
  const plan = normalizeReleasePlan(valid);
  assert.ok(plan);
  assert.equal(releasePlanReady(plan), true);
  for (const mutation of [
    { coreCommit: "main" },
    { bundleId: "../bundle" },
    { bundleSha256: "B".repeat(64) },
    { releaseId: "" },
    { gates: { ...valid.gates, signature: "unknown" } },
  ]) assert.equal(normalizeReleasePlan({ ...valid, ...mutation }), null);
});

test("release authorization stays closed for missing, failed, running, or omitted evidence", () => {
  assert.equal(releasePlanReady(null), false);
  for (const state of ["failed", "running", "pending"]) {
    const plan = normalizeReleasePlan({ ...valid, gates: { ...valid.gates, provenance: state } });
    assert.equal(releasePlanReady(plan), false);
  }
  assert.equal(releasePlanReady(normalizeReleasePlan({ ...valid, gates: {} })), false);
});

test("normalized release plans cannot be mutated after review", () => {
  const plan = normalizeReleasePlan(valid);
  assert.throws(() => { plan.releaseId = "other"; }, TypeError);
  assert.throws(() => { plan.gates.signature = "failed"; }, TypeError);
  assert.equal(releasePlanReady(plan), true);
});

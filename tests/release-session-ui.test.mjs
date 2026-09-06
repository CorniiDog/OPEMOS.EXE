import assert from "node:assert/strict";
import test from "node:test";
import { installReleasePlanReview } from "../src/release-plan-review.js";

const assets = ["archive.tar", "manifest.json", "manifest.json.sig", "provenance.json"].map((name, index) => ({
  name, sha256: String(index + 1).repeat(64), bytes: index + 1, state: "pending",
}));
const progress = (phase, completedAssets, indeterminate = false) => ({
  phase, completedAssets, totalAssets: 4, indeterminate,
});
const operation = (overrides = {}) => ({
  schemaVersion: 1,
  operationId: "a".repeat(64),
  repository: "CorniiDog/OPEMOS",
  tag: "opemos-v1",
  targetCommit: "b".repeat(40),
  attempt: 1,
  lifecycle: "planned",
  decision: "create",
  progress: progress("planning", 0, true),
  assets,
  message: "Exact release may be created.",
  ...overrides,
});

class FakeNode {
  constructor() {
    this.textContent = "";
    this.disabled = false;
    this.dataset = {};
    this.children = [];
    this.listeners = new Map();
  }
  addEventListener(name, callback) { this.listeners.set(name, callback); }
  replaceChildren() { this.children = []; }
  append(child) { this.children.push(child); }
  async click() { await this.listeners.get("click")?.(); }
}

function fixtureDocument() {
  const ids = ["release-repository", "release-tag", "release-target-commit", "release-operation-id",
    "authorize-release", "release-plan-status", "release-assets", "release-progress",
    "release-start", "release-verify", "release-retry", "release-cancel-operation"];
  const nodes = Object.fromEntries(ids.map((id) => [id, new FakeNode()]));
  return {
    nodes,
    querySelector(selector) { return nodes[selector.slice(1)]; },
    createElement() { return new FakeNode(); },
  };
}

const turn = () => new Promise((resolve) => setImmediate(resolve));

test("closed maintainer UI fixture authorizes, starts, observes, retries, and verifies one identity", async () => {
  const document = fixtureDocument();
  const planned = operation();
  const retryAssets = assets.map((asset, index) => ({ ...asset, state: index === 3 ? "missing" : "present" }));
  const retry = operation({ attempt: 2, lifecycle: "reconciling", decision: "retry-missing",
    progress: progress("reconciling", 3), assets: retryAssets });
  const complete = operation({ attempt: 2, lifecycle: "succeeded", decision: "already-complete",
    progress: progress("complete", 4), assets: assets.map((asset) => ({ ...asset, state: "present" })) });
  const outputs = [planned, retry, complete];
  const calls = [];
  const scheduled = [];
  const view = installReleasePlanReview(document, async (command, request) => {
    calls.push([command, request]);
    return outputs.shift();
  }, { schedule: (callback) => scheduled.push(callback), maxPolls: 4 });

  view.render(planned);
  assert.equal(document.nodes["authorize-release"].disabled, false);
  assert.equal(document.nodes["release-start"].disabled, true);
  await document.nodes["authorize-release"].click();
  assert.equal(document.nodes["release-start"].disabled, false);
  await document.nodes["release-start"].click();
  await turn();

  assert.equal(view.snapshot().operation.decision, "retry-missing");
  assert.equal(document.nodes["release-progress"].textContent, "reconciling / 3/4 assets");
  assert.equal(document.nodes["release-retry"].disabled, true);
  assert.equal(scheduled.length, 1);
  await document.nodes["authorize-release"].click();
  assert.equal(document.nodes["release-retry"].disabled, false);
  await document.nodes["release-retry"].click();
  scheduled[0]();
  await turn();

  assert.deepEqual(calls.map(([command]) => command), ["execute", "status", "reconcile"]);
  assert.equal(view.snapshot().operation.lifecycle, "succeeded");
  assert.equal(document.nodes["release-progress"].textContent, "complete / 4/4 assets");
  assert.match(document.nodes["release-plan-status"].textContent, /exactly matches/);
  assert.equal(document.nodes["release-cancel-operation"].disabled, true);
});

test("closed maintainer UI cancellation cannot claim completion and invalidates polling", async () => {
  const document = fixtureDocument();
  const planned = operation();
  const cancelled = operation({ lifecycle: "cancelled", decision: "cancelled",
    progress: progress("cancelled", 0, true),
    message: "Operation was cancelled; no additional remote completion is claimed." });
  const calls = [];
  const view = installReleasePlanReview(document, async (command) => {
    calls.push(command);
    return cancelled;
  }, { schedule: () => assert.fail("cancelled UI scheduled another poll"), maxPolls: 2 });

  view.render(planned);
  await document.nodes["release-cancel-operation"].click();
  assert.deepEqual(calls, ["cancel"]);
  assert.equal(view.snapshot().operation.lifecycle, "cancelled");
  assert.equal(view.poller.snapshot().active, false);
  assert.match(document.nodes["release-plan-status"].textContent, /cancelled.*cannot claim success/i);
  assert.equal(document.nodes["release-start"].disabled, true);
  assert.equal(document.nodes["release-retry"].disabled, true);
});

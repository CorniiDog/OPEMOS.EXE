import assert from "node:assert/strict";
import test from "node:test";
import { CORE_MAINTAINER_WORKFLOW, CORE_MAINTAINER_WORKFLOW_COMMIT, installMaintainerReleaseWorkflow, validateMaintainerReleaseWorkflow } from "../src/maintainer-release-workflow.js";
const clone = () => JSON.parse(JSON.stringify(CORE_MAINTAINER_WORKFLOW));
test("bundles the exact canonical Core target and ordered non-remote phases", () => {
  assert.equal(CORE_MAINTAINER_WORKFLOW_COMMIT, "342e81025da0551facee2a28e8f2d9ddf1bd2fd6");
  assert.equal(validateMaintainerReleaseWorkflow(clone()), true);
  assert.deepEqual(CORE_MAINTAINER_WORKFLOW.steps.map(({ id }) => id), ["resolve", "build", "package", "bundle", "validate", "release-dry-run"]);
  assert.ok(CORE_MAINTAINER_WORKFLOW.steps.every(({ mutatesRemote }) => mutatesRemote === false));
  assert.deepEqual(CORE_MAINTAINER_WORKFLOW.publication, { mode: "dry-run-only", requiresSeparateAuthorization: true, combinedNvidiaSteamOsAsset: false });
});
for (const [name, mutate] of [
  ["extra field", value => { value.remote = true; }],
  ["changed target", value => { value.target.nvidiaVersion = "999.0"; }],
  ["substituted phase", value => { value.steps[2].entrypoint = "arbitrary/tool"; }],
  ["reordered phases", value => { [value.steps[0], value.steps[1]] = [value.steps[1], value.steps[0]]; }],
  ["remote mutation", value => { value.steps[5].mutatesRemote = true; }],
  ["combined image", value => { value.publication.combinedNvidiaSteamOsAsset = true; }],
]) test(`rejects ${name}`, () => { const value = clone(); mutate(value); assert.equal(validateMaintainerReleaseWorkflow(value), false); });
test("renders the exact plan without enabling publication", () => {
  const nodes = new Map();
  for (const id of ["maintainer-workflow-status", "maintainer-workflow-target", "maintainer-workflow-source", "maintainer-workflow-core", "maintainer-workflow-steps"]) nodes.set(`#${id}`, { textContent: "", className: "", replaceChildren(...children) { this.children = children; } });
  const document = { querySelector: selector => nodes.get(selector), createElement: () => ({ textContent: "", title: "" }) };
  installMaintainerReleaseWorkflow(document);
  assert.equal(nodes.get("#maintainer-workflow-status").textContent, "Exact Core plan ready");
  assert.match(nodes.get("#maintainer-workflow-target").textContent, /SteamOS 3\.8\.16.*6\.16\.12-valve24\.5-1-neptune-616-gb2f7cfe85e45.*NVIDIA 575\.64\.05/);
  assert.equal(nodes.get("#maintainer-workflow-steps").children.length, 6);
});

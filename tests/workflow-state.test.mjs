import assert from "node:assert/strict";
import test from "node:test";

import {
  admitBuildStart,
  admitImageSelection,
  deriveBuildAdmission,
} from "../src/workflow-state.js";

const ready = {
  hasImage: true,
  hasCompletedOutput: false,
  buildRunning: false,
  usbWriting: false,
  hostReady: true,
  exportMode: "image",
  upstreamSelected: false,
  upstreamApproved: false,
};

test("build admission names every normal workflow phase", () => {
  assert.deepEqual(deriveBuildAdmission({ ...ready, hasImage: false }), {
    phase: "empty", canBuild: false, blocker: "no-image",
  });
  assert.deepEqual(deriveBuildAdmission(ready), {
    phase: "selected", canBuild: true, blocker: null,
  });
  assert.deepEqual(deriveBuildAdmission({ ...ready, buildRunning: true }), {
    phase: "building", canBuild: false, blocker: "building",
  });
  assert.deepEqual(deriveBuildAdmission({ ...ready, hasCompletedOutput: true }), {
    phase: "complete", canBuild: false, blocker: "complete",
  });
  assert.deepEqual(deriveBuildAdmission({
    ...ready, hasCompletedOutput: true, usbWriting: true,
  }), {
    phase: "usb-writing", canBuild: false, blocker: "usb-writing",
  });
});

test("build admission rejects every independent readiness blocker", () => {
  const cases = [
    [{ hasImage: false }, "no-image"],
    [{ hostReady: false }, "host-unavailable"],
    [{ exportMode: null }, "no-output"],
    [{ upstreamSelected: true, upstreamApproved: false }, "upstream-unapproved"],
  ];
  for (const [change, blocker] of cases) {
    assert.deepEqual(deriveBuildAdmission({ ...ready, ...change }), {
      phase: change.hasImage === false ? "empty" : "selected",
      canBuild: false,
      blocker,
    });
  }
  for (const exportMode of ["image", "usb", "both"]) {
    assert.equal(deriveBuildAdmission({ ...ready, exportMode }).canBuild, true);
  }
  assert.equal(deriveBuildAdmission({
    ...ready, upstreamSelected: true, upstreamApproved: true,
  }).canBuild, true);
});

test("build admission fails closed for malformed and impossible snapshots", () => {
  assert.throws(() => deriveBuildAdmission(null), /snapshot must be an object/);
  assert.throws(() => deriveBuildAdmission({ ...ready, hasImage: "yes" }), /hasImage must be boolean/);
  assert.throws(() => deriveBuildAdmission({ ...ready, exportMode: "disk" }), /exportMode is invalid/);
  assert.throws(() => deriveBuildAdmission({
    ...ready, buildRunning: true, usbWriting: true,
  }), /cannot run concurrently/);
  assert.throws(() => deriveBuildAdmission({
    ...ready, buildRunning: true, hasCompletedOutput: true,
  }), /completed output cannot still be building/);
});

test("build start uses the same fail-closed admission at the event boundary", () => {
  assert.deepEqual(admitBuildStart(ready), {
    accepted: true, phase: "building", blocker: null,
  });
  for (const change of [
    { hasImage: false },
    { hostReady: false },
    { exportMode: null },
    { upstreamSelected: true, upstreamApproved: false },
    { hasCompletedOutput: true },
    { usbWriting: true },
  ]) {
    const result = admitBuildStart({ ...ready, ...change });
    assert.equal(result.accepted, false);
    assert.notEqual(result.blocker, null);
  }
  assert.throws(() => admitBuildStart({
    ...ready, buildRunning: true, usbWriting: true,
  }), /cannot run concurrently/);
});

test("image selection is allowed only outside active mutation phases", () => {
  for (const snapshot of [
    { ...ready, hasImage: false },
    ready,
    { ...ready, hasCompletedOutput: true },
  ]) {
    const result = admitImageSelection(snapshot);
    assert.equal(result.accepted, true);
    assert.equal(result.blocker, null);
  }
  assert.deepEqual(admitImageSelection({ ...ready, buildRunning: true }), {
    accepted: false, phase: "building", blocker: "building",
  });
  assert.deepEqual(admitImageSelection({ ...ready, usbWriting: true }), {
    accepted: false, phase: "usb-writing", blocker: "usb-writing",
  });
  assert.throws(() => admitImageSelection({
    ...ready, buildRunning: true, usbWriting: true,
  }), /cannot run concurrently/);
});

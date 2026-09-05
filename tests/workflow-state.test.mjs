import assert from "node:assert/strict";
import test from "node:test";

import { deriveBuildAdmission } from "../src/workflow-state.js";

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

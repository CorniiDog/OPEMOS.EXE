import assert from "node:assert/strict";
import test from "node:test";

import {
  admitBuildStart,
  admitImageSelection,
  admitOutputDirectorySelection,
  admitUsbPreflightCancel,
  admitUsbPreflightStart,
  admitUsbTargetSelection,
  admitUsbWriteStart,
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

test("USB write start requires a completed image and active preflight capability", () => {
  const complete = { ...ready, hasCompletedOutput: true };
  assert.deepEqual(admitUsbWriteStart(complete, { hasPreflightSession: true }), {
    accepted: true, phase: "complete", blocker: null,
  });
  assert.deepEqual(admitUsbWriteStart(complete, { hasPreflightSession: false }), {
    accepted: false, phase: "complete", blocker: "no-usb-preflight",
  });
  for (const snapshot of [
    { ...ready, hasImage: false },
    ready,
    { ...ready, buildRunning: true },
  ]) {
    const result = admitUsbWriteStart(snapshot, { hasPreflightSession: true });
    assert.equal(result.accepted, false);
    assert.equal(result.blocker, "no-completed-output");
  }
  assert.throws(() => admitUsbWriteStart(complete, null), /capability must be an object/);
  assert.throws(
    () => admitUsbWriteStart(complete, { hasPreflightSession: "yes" }),
    /hasPreflightSession must be boolean/,
  );
  assert.deepEqual(admitUsbWriteStart({
    ...complete, usbWriting: true,
  }, { hasPreflightSession: true }), {
    accepted: false, phase: "usb-writing", blocker: "no-completed-output",
  });
});

test("output directory changes require the selected non-mutating phase", () => {
  assert.deepEqual(admitOutputDirectorySelection(ready), {
    accepted: true, phase: "selected", blocker: null,
  });
  const cases = [
    [{ hasImage: false }, "empty", "no-image"],
    [{ hasCompletedOutput: true }, "complete", "complete"],
    [{ buildRunning: true }, "building", "building"],
    [{ usbWriting: true }, "usb-writing", "usb-writing"],
  ];
  for (const [change, phase, blocker] of cases) {
    assert.deepEqual(admitOutputDirectorySelection({ ...ready, ...change }), {
      accepted: false, phase, blocker,
    });
  }
  assert.throws(() => admitOutputDirectorySelection({
    ...ready, buildRunning: true, usbWriting: true,
  }), /cannot run concurrently/);
});

test("USB preflight start requires exact completed-image confirmation and target identity", () => {
  const complete = { ...ready, hasCompletedOutput: true };
  const capability = {
    armPending: false, hasTarget: true, hasIdentityToken: true, confirmationMatches: true,
  };
  assert.deepEqual(admitUsbPreflightStart(complete, capability), {
    accepted: true, phase: "complete", blocker: null,
  });
  const cases = [
    [{ armPending: true }, "preflight-pending"],
    [{ hasTarget: false }, "no-usb-target"],
    [{ hasIdentityToken: false }, "no-usb-identity"],
    [{ confirmationMatches: false }, "confirmation-mismatch"],
  ];
  for (const [change, blocker] of cases) {
    assert.deepEqual(admitUsbPreflightStart(complete, { ...capability, ...change }), {
      accepted: false, phase: "complete", blocker,
    });
  }
  assert.equal(admitUsbPreflightStart(ready, capability).blocker, "no-completed-output");
  assert.throws(() => admitUsbPreflightStart(complete, null), /capability must be an object/);
  for (const name of Object.keys(capability)) {
    assert.throws(
      () => admitUsbPreflightStart(complete, { ...capability, [name]: "yes" }),
      new RegExp(name + " must be boolean"),
    );
  }
});

test("USB preflight cancellation requires one live completed-image session", () => {
  const complete = { ...ready, hasCompletedOutput: true };
  const available = { cancelPending: false, hasPreflightSession: true };
  assert.deepEqual(admitUsbPreflightCancel(complete, available), {
    accepted: true, phase: "complete", blocker: null,
  });
  assert.deepEqual(admitUsbPreflightCancel(complete, {
    ...available, cancelPending: true,
  }), {
    accepted: false, phase: "complete", blocker: "cancellation-pending",
  });
  assert.deepEqual(admitUsbPreflightCancel(complete, {
    ...available, hasPreflightSession: false,
  }), {
    accepted: false, phase: "complete", blocker: "no-usb-preflight",
  });
  assert.equal(admitUsbPreflightCancel(ready, available).blocker, "no-completed-output");
  assert.throws(() => admitUsbPreflightCancel(complete, null), /capability must be an object/);
  assert.throws(
    () => admitUsbPreflightCancel(complete, { ...available, cancelPending: 1 }),
    /cancelPending must be boolean/,
  );
  assert.throws(
    () => admitUsbPreflightCancel(complete, { ...available, hasPreflightSession: "yes" }),
    /hasPreflightSession must be boolean/,
  );
});

test("USB target selection changes only in stable image phases", () => {
  assert.deepEqual(admitUsbTargetSelection(ready), {
    accepted: true, phase: "selected", blocker: null,
  });
  assert.deepEqual(admitUsbTargetSelection({ ...ready, hasCompletedOutput: true }), {
    accepted: true, phase: "complete", blocker: null,
  });
  const cases = [
    [{ hasImage: false }, "empty", "no-image"],
    [{ buildRunning: true }, "building", "building"],
    [{ usbWriting: true }, "usb-writing", "usb-writing"],
  ];
  for (const [change, phase, blocker] of cases) {
    assert.deepEqual(admitUsbTargetSelection({ ...ready, ...change }), {
      accepted: false, phase, blocker,
    });
  }
  assert.throws(() => admitUsbTargetSelection({
    ...ready, buildRunning: true, usbWriting: true,
  }), /cannot run concurrently/);
});

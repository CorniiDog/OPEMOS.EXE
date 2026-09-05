import assert from "node:assert/strict";
import test from "node:test";

import {
  admitBuildStart,
  admitBuildSourceRefresh,
  admitBuildSourceSelection,
  admitImageSelection,
  admitExportModeSelection,
  admitOutputDirectorySelection,
  admitUsbPreflightCancel,
  admitUsbConfirmationEdit,
  admitUsbPreflightStart,
  admitUsbReviewOpen,
  admitUsbReviewDismiss,
  admitUsbTargetSelection,
  admitUsbTargetRefresh,
  admitUsbTargetClear,
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
    ...ready, hasCompletedOutput: true, usbWriting: true, exportMode: "both",
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
  assert.throws(() => deriveBuildAdmission({
    ...ready, hasImage: false, buildRunning: true,
  }), /active build requires its selected image/);
  assert.throws(() => deriveBuildAdmission({
    ...ready, buildRunning: true, exportMode: null,
  }), /active build requires its output mode/);
  assert.throws(() => deriveBuildAdmission({
    ...ready, buildRunning: true, upstreamSelected: true,
  }), /active upstream build requires explicit approval/);
  assert.throws(() => deriveBuildAdmission({
    ...ready, hasImage: false, hasCompletedOutput: true,
  }), /completed output requires its selected image/);
  assert.throws(() => deriveBuildAdmission({
    ...ready, hasCompletedOutput: true, exportMode: null,
  }), /completed output requires an output mode/);
  assert.throws(() => deriveBuildAdmission({
    ...ready, usbWriting: true,
  }), /USB writing requires a completed output/);
  assert.throws(() => deriveBuildAdmission({
    ...ready, hasCompletedOutput: true, usbWriting: true,
  }), /USB writing requires a USB output mode/);
  assert.throws(() => deriveBuildAdmission({
    ...ready, upstreamApproved: true,
  }), /upstream approval requires an upstream source/);
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
    { hasCompletedOutput: true, usbWriting: true, exportMode: "both" },
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
  assert.deepEqual(admitImageSelection({ ...ready, hasCompletedOutput: true, usbWriting: true, exportMode: "both" }), {
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
    ...complete, usbWriting: true, exportMode: "both",
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
    [{ hasCompletedOutput: true, usbWriting: true, exportMode: "both" }, "usb-writing", "usb-writing"],
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
    [{ hasCompletedOutput: true, usbWriting: true, exportMode: "both" }, "usb-writing", "usb-writing"],
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

test("USB target clearing requires one target in a stable image phase", () => {
  const present = { hasTarget: true };
  assert.deepEqual(admitUsbTargetClear(ready, present), {
    accepted: true, phase: "selected", blocker: null,
  });
  assert.deepEqual(admitUsbTargetClear({ ...ready, hasCompletedOutput: true }, present), {
    accepted: true, phase: "complete", blocker: null,
  });
  assert.deepEqual(admitUsbTargetClear(ready, { hasTarget: false }), {
    accepted: false, phase: "selected", blocker: "no-usb-target",
  });
  assert.deepEqual(admitUsbTargetClear({ ...ready, buildRunning: true }, present), {
    accepted: false, phase: "building", blocker: "building",
  });
  assert.deepEqual(admitUsbTargetClear({ ...ready, hasCompletedOutput: true, usbWriting: true, exportMode: "both" }, present), {
    accepted: false, phase: "usb-writing", blocker: "usb-writing",
  });
  assert.throws(() => admitUsbTargetClear(ready, null), /capability must be an object/);
  assert.throws(
    () => admitUsbTargetClear(ready, { hasTarget: "yes" }),
    /hasTarget must be boolean/,
  );
});

test("USB review opens only for a completed image with a selected target", () => {
  const complete = { ...ready, hasCompletedOutput: true };
  assert.deepEqual(admitUsbReviewOpen(complete, { hasTarget: true }), {
    accepted: true, phase: "complete", blocker: null,
  });
  assert.deepEqual(admitUsbReviewOpen(complete, { hasTarget: false }), {
    accepted: false, phase: "complete", blocker: "no-usb-target",
  });
  assert.equal(
    admitUsbReviewOpen(ready, { hasTarget: true }).blocker,
    "no-completed-output",
  );
  assert.equal(
    admitUsbReviewOpen({ ...ready, buildRunning: true }, { hasTarget: true }).blocker,
    "no-completed-output",
  );
  assert.equal(
    admitUsbReviewOpen({ ...ready, hasCompletedOutput: true, usbWriting: true, exportMode: "both" }, { hasTarget: true }).blocker,
    "no-completed-output",
  );
  assert.throws(() => admitUsbReviewOpen(complete, null), /capability must be an object/);
  assert.throws(
    () => admitUsbReviewOpen(complete, { hasTarget: "yes" }),
    /hasTarget must be boolean/,
  );
});

test("USB review dismissal remains available until destructive writing starts", () => {
  const cases = [
    [{ hasImage: false }, "empty"],
    [{}, "selected"],
    [{ hasCompletedOutput: true }, "complete"],
    [{ buildRunning: true }, "building"],
  ];
  for (const [change, phase] of cases) {
    assert.deepEqual(admitUsbReviewDismiss({ ...ready, ...change }), {
      accepted: true, phase, blocker: null,
    });
  }
  assert.deepEqual(admitUsbReviewDismiss({ ...ready, hasCompletedOutput: true, usbWriting: true, exportMode: "both" }), {
    accepted: false, phase: "usb-writing", blocker: "usb-writing",
  });
  assert.throws(() => admitUsbReviewDismiss({
    ...ready, buildRunning: true, usbWriting: true,
  }), /cannot run concurrently/);
});

test("image export-mode changes only before build mutation begins", () => {
  assert.deepEqual(admitExportModeSelection({ ...ready, hasImage: false }), {
    accepted: true, phase: "empty", blocker: null,
  });
  assert.deepEqual(admitExportModeSelection(ready), {
    accepted: true, phase: "selected", blocker: null,
  });
  const cases = [
    [{ hasCompletedOutput: true }, "complete", "complete"],
    [{ buildRunning: true }, "building", "building"],
    [{ hasCompletedOutput: true, usbWriting: true, exportMode: "both" }, "usb-writing", "usb-writing"],
  ];
  for (const [change, phase, blocker] of cases) {
    assert.deepEqual(admitExportModeSelection({ ...ready, ...change }), {
      accepted: false, phase, blocker,
    });
  }
  assert.throws(() => admitExportModeSelection({
    ...ready, buildRunning: true, usbWriting: true,
  }), /cannot run concurrently/);
});

test("build source intent changes only before build mutation begins", () => {
  for (const snapshot of [{ ...ready, hasImage: false }, ready]) {
    assert.equal(admitBuildSourceSelection(snapshot).accepted, true);
  }
  const cases = [
    [{ hasCompletedOutput: true }, "complete", "complete"],
    [{ buildRunning: true }, "building", "building"],
    [{ hasCompletedOutput: true, usbWriting: true, exportMode: "both" }, "usb-writing", "usb-writing"],
  ];
  for (const [change, phase, blocker] of cases) {
    assert.deepEqual(admitBuildSourceSelection({ ...ready, ...change }), {
      accepted: false, phase, blocker,
    });
  }
  assert.throws(() => admitBuildSourceSelection({
    ...ready, buildRunning: true, usbWriting: true,
  }), /cannot run concurrently/);
});

test("source branch refresh commits only for the latest editable request", () => {
  const current = { generation: 3, currentGeneration: 3 };
  assert.deepEqual(admitBuildSourceRefresh(ready, current), {
    accepted: true, phase: "selected", blocker: null,
  });
  assert.deepEqual(admitBuildSourceRefresh(ready, {
    generation: 2, currentGeneration: 3,
  }), {
    accepted: false, phase: "selected", blocker: "stale-source-refresh",
  });
  assert.equal(
    admitBuildSourceRefresh({ ...ready, buildRunning: true }, current).blocker,
    "building",
  );
  assert.equal(
    admitBuildSourceRefresh({ ...ready, hasCompletedOutput: true }, current).blocker,
    "complete",
  );
  assert.throws(() => admitBuildSourceRefresh(ready, null), /capability must be an object/);
  for (const capability of [
    { generation: 0, currentGeneration: 1 },
    { generation: 1, currentGeneration: 1.5 },
    { generation: Number.MAX_SAFE_INTEGER + 1, currentGeneration: 1 },
  ]) {
    assert.throws(
      () => admitBuildSourceRefresh(ready, capability),
      /must be a positive safe integer/,
    );
  }
});

test("USB confirmation editing requires an idle completed-image target", () => {
  const complete = { ...ready, hasCompletedOutput: true };
  const editable = { hasTarget: true, armPending: false, hasPreflightSession: false };
  assert.deepEqual(admitUsbConfirmationEdit(complete, editable), {
    accepted: true, phase: "complete", blocker: null,
  });
  const cases = [
    [{ armPending: true }, "preflight-pending"],
    [{ hasPreflightSession: true }, "usb-preflight-active"],
    [{ hasTarget: false }, "no-usb-target"],
  ];
  for (const [change, blocker] of cases) {
    assert.deepEqual(admitUsbConfirmationEdit(complete, { ...editable, ...change }), {
      accepted: false, phase: "complete", blocker,
    });
  }
  assert.equal(admitUsbConfirmationEdit(ready, editable).blocker, "no-completed-output");
  assert.equal(
    admitUsbConfirmationEdit({ ...ready, hasCompletedOutput: true, usbWriting: true, exportMode: "both" }, editable).blocker,
    "no-completed-output",
  );
  assert.throws(() => admitUsbConfirmationEdit(complete, null), /capability must be an object/);
  for (const name of Object.keys(editable)) {
    assert.throws(
      () => admitUsbConfirmationEdit(complete, { ...editable, [name]: "yes" }),
      new RegExp(name + " must be boolean"),
    );
  }
});

test("manual USB target refresh runs only in stable image phases", () => {
  assert.deepEqual(admitUsbTargetRefresh(ready), {
    accepted: true, phase: "selected", blocker: null,
  });
  assert.deepEqual(admitUsbTargetRefresh({ ...ready, hasCompletedOutput: true }), {
    accepted: true, phase: "complete", blocker: null,
  });
  const cases = [
    [{ hasImage: false }, "empty", "no-image"],
    [{ buildRunning: true }, "building", "building"],
    [{ hasCompletedOutput: true, usbWriting: true, exportMode: "both" }, "usb-writing", "usb-writing"],
  ];
  for (const [change, phase, blocker] of cases) {
    assert.deepEqual(admitUsbTargetRefresh({ ...ready, ...change }), {
      accepted: false, phase, blocker,
    });
  }
  assert.throws(() => admitUsbTargetRefresh({
    ...ready, buildRunning: true, usbWriting: true,
  }), /cannot run concurrently/);
});

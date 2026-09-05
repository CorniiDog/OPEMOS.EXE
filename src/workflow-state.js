const EXPORT_MODES = new Set(["image", "usb", "both"]);

function requireBoolean(name, value) {
  if (typeof value !== "boolean") throw new TypeError(`${name} must be boolean`);
}

export function deriveBuildAdmission(snapshot) {
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
    throw new TypeError("workflow snapshot must be an object");
  }
  const {
    hasImage,
    hasCompletedOutput,
    buildRunning,
    usbWriting,
    hostReady,
    exportMode,
    upstreamSelected,
    upstreamApproved,
  } = snapshot;
  for (const [name, value] of Object.entries({
    hasImage,
    hasCompletedOutput,
    buildRunning,
    usbWriting,
    hostReady,
    upstreamSelected,
    upstreamApproved,
  })) requireBoolean(name, value);
  if (exportMode !== null && !EXPORT_MODES.has(exportMode)) {
    throw new TypeError("exportMode is invalid");
  }
  if (buildRunning && usbWriting) {
    throw new Error("build and USB write cannot run concurrently");
  }
  if (buildRunning && hasCompletedOutput) {
    throw new Error("a completed output cannot still be building");
  }
  if (hasCompletedOutput && !hasImage) {
    throw new Error("a completed output requires its selected image");
  }
  if (usbWriting && !hasCompletedOutput) {
    throw new Error("USB writing requires a completed output");
  }
  if (upstreamApproved && !upstreamSelected) {
    throw new Error("upstream approval requires an upstream source");
  }

  const phase = usbWriting
    ? "usb-writing"
    : buildRunning
      ? "building"
      : hasCompletedOutput
        ? "complete"
        : hasImage
          ? "selected"
          : "empty";
  const blocker = buildRunning
    ? "building"
    : usbWriting
      ? "usb-writing"
      : hasCompletedOutput
        ? "complete"
        : !hasImage
          ? "no-image"
          : !hostReady
            ? "host-unavailable"
            : !exportMode
              ? "no-output"
              : upstreamSelected && !upstreamApproved
                ? "upstream-unapproved"
                : null;
  return Object.freeze({ phase, canBuild: blocker === null, blocker });
}

export function admitBuildStart(snapshot) {
  const admission = deriveBuildAdmission(snapshot);
  return Object.freeze({
    accepted: admission.canBuild,
    phase: admission.canBuild ? "building" : admission.phase,
    blocker: admission.canBuild ? null : admission.blocker,
  });
}

export function admitImageSelection(snapshot) {
  const admission = deriveBuildAdmission(snapshot);
  const accepted = admission.phase !== "building" && admission.phase !== "usb-writing";
  return Object.freeze({
    accepted,
    phase: admission.phase,
    blocker: accepted ? null : admission.blocker,
  });
}

export function admitUsbWriteStart(snapshot, capability) {
  const admission = deriveBuildAdmission(snapshot);
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) {
    throw new TypeError("USB capability must be an object");
  }
  requireBoolean("hasPreflightSession", capability.hasPreflightSession);
  const accepted = admission.phase === "complete" && capability.hasPreflightSession;
  const blocker = accepted
    ? null
    : admission.phase !== "complete"
      ? "no-completed-output"
      : "no-usb-preflight";
  return Object.freeze({ accepted, phase: admission.phase, blocker });
}

export function admitOutputDirectorySelection(snapshot) {
  const admission = deriveBuildAdmission(snapshot);
  const accepted = admission.phase === "selected";
  const blocker = accepted
    ? null
    : admission.phase === "empty"
      ? "no-image"
      : admission.phase;
  return Object.freeze({ accepted, phase: admission.phase, blocker });
}

export function admitUsbPreflightStart(snapshot, capability) {
  const admission = deriveBuildAdmission(snapshot);
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) {
    throw new TypeError("USB preflight capability must be an object");
  }
  const { armPending, hasTarget, hasIdentityToken, confirmationMatches } = capability;
  for (const [name, value] of Object.entries({
    armPending, hasTarget, hasIdentityToken, confirmationMatches,
  })) requireBoolean(name, value);
  const blocker = admission.phase !== "complete"
    ? "no-completed-output"
    : armPending
      ? "preflight-pending"
      : !hasTarget
        ? "no-usb-target"
        : !hasIdentityToken
          ? "no-usb-identity"
          : !confirmationMatches
            ? "confirmation-mismatch"
            : null;
  return Object.freeze({ accepted: blocker === null, phase: admission.phase, blocker });
}

export function admitUsbPreflightCancel(snapshot, capability) {
  const admission = deriveBuildAdmission(snapshot);
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) {
    throw new TypeError("USB cancellation capability must be an object");
  }
  const { cancelPending, hasPreflightSession } = capability;
  requireBoolean("cancelPending", cancelPending);
  requireBoolean("hasPreflightSession", hasPreflightSession);
  const blocker = admission.phase !== "complete"
    ? "no-completed-output"
    : cancelPending
      ? "cancellation-pending"
      : !hasPreflightSession
        ? "no-usb-preflight"
        : null;
  return Object.freeze({ accepted: blocker === null, phase: admission.phase, blocker });
}

export function admitUsbTargetSelection(snapshot) {
  const admission = deriveBuildAdmission(snapshot);
  const accepted = admission.phase === "selected" || admission.phase === "complete";
  const blocker = accepted
    ? null
    : admission.phase === "empty"
      ? "no-image"
      : admission.blocker;
  return Object.freeze({ accepted, phase: admission.phase, blocker });
}

export function admitUsbTargetClear(snapshot, capability) {
  const admission = admitUsbTargetSelection(snapshot);
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) {
    throw new TypeError("USB target clear capability must be an object");
  }
  requireBoolean("hasTarget", capability.hasTarget);
  const blocker = !admission.accepted
    ? admission.blocker
    : !capability.hasTarget
      ? "no-usb-target"
      : null;
  return Object.freeze({ accepted: blocker === null, phase: admission.phase, blocker });
}

export function admitUsbReviewOpen(snapshot, capability) {
  const admission = deriveBuildAdmission(snapshot);
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) {
    throw new TypeError("USB review capability must be an object");
  }
  requireBoolean("hasTarget", capability.hasTarget);
  const blocker = admission.phase !== "complete"
    ? "no-completed-output"
    : !capability.hasTarget
      ? "no-usb-target"
      : null;
  return Object.freeze({ accepted: blocker === null, phase: admission.phase, blocker });
}

export function admitUsbReviewDismiss(snapshot) {
  const admission = deriveBuildAdmission(snapshot);
  const accepted = admission.phase !== "usb-writing";
  return Object.freeze({
    accepted,
    phase: admission.phase,
    blocker: accepted ? null : "usb-writing",
  });
}

export function admitExportModeSelection(snapshot) {
  const admission = deriveBuildAdmission(snapshot);
  const accepted = admission.phase === "empty" || admission.phase === "selected";
  return Object.freeze({
    accepted,
    phase: admission.phase,
    blocker: accepted ? null : admission.blocker,
  });
}

export function admitBuildSourceSelection(snapshot) {
  const admission = deriveBuildAdmission(snapshot);
  const accepted = admission.phase === "empty" || admission.phase === "selected";
  return Object.freeze({
    accepted,
    phase: admission.phase,
    blocker: accepted ? null : admission.blocker,
  });
}

export function admitBuildSourceRefresh(snapshot, capability) {
  const admission = admitBuildSourceSelection(snapshot);
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) {
    throw new TypeError("source refresh capability must be an object");
  }
  const { generation, currentGeneration } = capability;
  for (const [name, value] of Object.entries({ generation, currentGeneration })) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new TypeError(`${name} must be a positive safe integer`);
    }
  }
  const blocker = !admission.accepted
    ? admission.blocker
    : generation !== currentGeneration
      ? "stale-source-refresh"
      : null;
  return Object.freeze({ accepted: blocker === null, phase: admission.phase, blocker });
}

export function admitUsbConfirmationEdit(snapshot, capability) {
  const admission = deriveBuildAdmission(snapshot);
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) {
    throw new TypeError("USB confirmation capability must be an object");
  }
  const { hasTarget, armPending, hasPreflightSession } = capability;
  for (const [name, value] of Object.entries({
    hasTarget, armPending, hasPreflightSession,
  })) requireBoolean(name, value);
  const blocker = admission.phase !== "complete"
    ? "no-completed-output"
    : armPending
      ? "preflight-pending"
      : hasPreflightSession
        ? "usb-preflight-active"
        : !hasTarget
          ? "no-usb-target"
          : null;
  return Object.freeze({ accepted: blocker === null, phase: admission.phase, blocker });
}

export function admitUsbTargetRefresh(snapshot) {
  const admission = deriveBuildAdmission(snapshot);
  const accepted = admission.phase === "selected" || admission.phase === "complete";
  const blocker = accepted
    ? null
    : admission.phase === "empty"
      ? "no-image"
      : admission.blocker;
  return Object.freeze({ accepted, phase: admission.phase, blocker });
}

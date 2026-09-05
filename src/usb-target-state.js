import { deriveBuildAdmission } from "./workflow-state.js";

function requireBoolean(name, value) {
  if (typeof value !== "boolean") throw new TypeError(`${name} must be boolean`);
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

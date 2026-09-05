import { deriveBuildAdmission } from "./workflow-state.js";

const USB_PROGRESS_PHASES = new Map([
  ["unmounting", 0],
  ["authorizing", 1],
  ["writing", 2],
  ["verifying", 3],
]);

function requireBoolean(name, value) {
  if (typeof value !== "boolean") throw new TypeError(`${name} must be boolean`);
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

function validBoundedString(value, maximum = 4096) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

export function admitUsbWriteCompletion(snapshot, result, capability) {
  const admission = deriveBuildAdmission(snapshot);
  if (admission.phase !== "usb-writing") {
    return Object.freeze({ accepted: false, phase: admission.phase, blocker: "no-active-usb-write" });
  }
  const validHash = (value) => typeof value === "string" && /^[0-9a-f]{64}$/i.test(value);
  if (!capability || typeof capability !== "object" || Array.isArray(capability)
    || !validBoundedString(capability.sessionToken)
    || !validBoundedString(capability.imagePath)
    || !validBoundedString(capability.deviceIdentifier)
    || !validBoundedString(capability.deviceNode)
    || !validHash(capability.imageSha256)) {
    return Object.freeze({ accepted: false, phase: admission.phase, blocker: "malformed-write-context" });
  }
  const validResult = result
    && typeof result === "object"
    && !Array.isArray(result)
    && result.status === "verified"
    && result.deviceIdentifier === capability.deviceIdentifier
    && result.deviceNode === capability.deviceNode
    && Number.isSafeInteger(result.bytesWritten)
    && result.bytesWritten > 0
    && validHash(result.imageSha256)
    && validHash(result.verifiedSha256)
    && result.imageSha256.toLowerCase() === capability.imageSha256.toLowerCase()
    && result.imageSha256.toLowerCase() === result.verifiedSha256.toLowerCase()
    && typeof result.ejected === "boolean"
    && validBoundedString(result.message, 8192);
  return Object.freeze({
    accepted: Boolean(validResult),
    phase: admission.phase,
    blocker: validResult ? null : "invalid-write-result",
  });
}

function validUsbProgress(progress) {
  return Boolean(progress
    && typeof progress === "object"
    && !Array.isArray(progress)
    && USB_PROGRESS_PHASES.has(progress.phase)
    && Number.isSafeInteger(progress.bytesCompleted)
    && progress.bytesCompleted >= 0
    && Number.isSafeInteger(progress.bytesTotal)
    && progress.bytesTotal > 0
    && progress.bytesCompleted <= progress.bytesTotal
    && typeof progress.message === "string"
    && progress.message.length > 0
    && progress.message.length <= 8192
    && ((progress.phase === "unmounting" || progress.phase === "authorizing")
      ? progress.bytesCompleted === 0
      : true));
}

export function admitUsbWriteProgress(snapshot, progress, previous = null) {
  const admission = deriveBuildAdmission(snapshot);
  if (admission.phase !== "usb-writing") {
    return Object.freeze({ accepted: false, phase: admission.phase, blocker: "no-active-usb-write" });
  }
  if (!validUsbProgress(progress) || (previous !== null && !validUsbProgress(previous))) {
    return Object.freeze({ accepted: false, phase: admission.phase, blocker: "malformed-progress" });
  }
  const currentPhase = USB_PROGRESS_PHASES.get(progress.phase);
  const previousPhase = previous === null ? -1 : USB_PROGRESS_PHASES.get(previous.phase);
  const regressed = currentPhase < previousPhase
    || (currentPhase === previousPhase && progress.bytesCompleted < previous.bytesCompleted)
    || (previous !== null && progress.bytesTotal !== previous.bytesTotal);
  return Object.freeze({
    accepted: !regressed,
    phase: admission.phase,
    blocker: regressed ? "regressing-progress" : null,
  });
}

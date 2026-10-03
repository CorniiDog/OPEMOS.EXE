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
  if (buildRunning && usbWriting) {
    throw new Error("build and USB write cannot run concurrently");
  }
  if (buildRunning && hasCompletedOutput) {
    throw new Error("a completed output cannot still be building");
  }
  if (buildRunning && !hasImage) {
    throw new Error("an active build requires its selected image");
  }
  if (buildRunning && upstreamSelected && !upstreamApproved) {
    throw new Error("an active upstream build requires explicit approval");
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
            : upstreamSelected && !upstreamApproved
                ? "upstream-unapproved"
                : null;
  return Object.freeze({ phase, canBuild: blocker === null, blocker });
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

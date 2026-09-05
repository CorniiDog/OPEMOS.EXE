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

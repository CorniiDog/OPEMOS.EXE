import { deriveBuildAdmission } from "./workflow-state.js";

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

export function admitExportModeSelection(snapshot) {
  const admission = deriveBuildAdmission(snapshot);
  const accepted = admission.phase === "empty" || admission.phase === "selected";
  return Object.freeze({
    accepted,
    phase: admission.phase,
    blocker: accepted ? null : admission.blocker,
  });
}

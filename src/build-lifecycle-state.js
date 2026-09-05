import { deriveBuildAdmission } from "./workflow-state.js";

export function admitBuildStart(snapshot) {
  const admission = deriveBuildAdmission(snapshot);
  return Object.freeze({
    accepted: admission.canBuild,
    phase: admission.canBuild ? "building" : admission.phase,
    blocker: admission.canBuild ? null : admission.blocker,
  });
}

export function admitBuildCompletion(snapshot) {
  const admission = deriveBuildAdmission(snapshot);
  const accepted = admission.phase === "building";
  return Object.freeze({
    accepted,
    phase: admission.phase,
    blocker: accepted ? null : "no-active-build",
  });
}

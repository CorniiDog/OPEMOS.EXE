import { deriveBuildAdmission } from "./workflow-state.js";

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

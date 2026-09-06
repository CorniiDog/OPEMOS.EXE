const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const GATES = ["package", "build", "signature", "checksum", "provenance"];

export function normalizeReleasePlan(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const plan = {
    coreCommit: String(value.coreCommit || ""),
    bundleId: String(value.bundleId || ""),
    bundleSha256: String(value.bundleSha256 || ""),
    releaseId: String(value.releaseId || ""),
    gates: Object.fromEntries(GATES.map((gate) => [gate, value.gates?.[gate] || "pending"])),
  };
  if (!COMMIT.test(plan.coreCommit) || !SAFE_ID.test(plan.bundleId)
    || !SHA256.test(plan.bundleSha256) || !SAFE_ID.test(plan.releaseId)
    || GATES.some((gate) => !["pending", "running", "passed", "failed"].includes(plan.gates[gate]))) {
    return null;
  }
  return Object.freeze({ ...plan, gates: Object.freeze({ ...plan.gates }) });
}

export function releasePlanReady(plan) {
  return Boolean(plan && GATES.every((gate) => plan.gates[gate] === "passed"));
}

export function installReleasePlanReview(document) {
  const fields = {
    coreCommit: document.querySelector("#release-core-commit"),
    bundleId: document.querySelector("#release-bundle-id"),
    bundleSha256: document.querySelector("#release-bundle-sha256"),
    releaseId: document.querySelector("#release-id"),
  };
  const authorize = document.querySelector("#authorize-release");
  const status = document.querySelector("#release-plan-status");
  const gateNodes = Object.fromEntries(GATES.map((gate) => [gate, document.querySelector(`[data-release-gate="${gate}"]`)]));

  function render(value) {
    const plan = normalizeReleasePlan(value);
    for (const [name, node] of Object.entries(fields)) node.textContent = plan?.[name] || "—";
    for (const gate of GATES) {
      const state = plan?.gates[gate] || "pending";
      gateNodes[gate].textContent = state;
      gateNodes[gate].dataset.state = state;
    }
    authorize.disabled = !releasePlanReady(plan);
    status.textContent = plan
      ? (releasePlanReady(plan) ? "All review gates passed. Explicit authorization is available." : "Waiting for every release evidence gate to pass.")
      : "No immutable release plan loaded.";
  }

  render(null);
  return Object.freeze({ render });
}

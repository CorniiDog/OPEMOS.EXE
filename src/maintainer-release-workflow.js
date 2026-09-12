export const CORE_MAINTAINER_WORKFLOW_COMMIT = "b02ff79265e20bd7ef4fa4e16835c3c343afdee2";
const steps = [
  ["resolve", "bootstrap/build_for_target.sh", "build-plan-json", ["target", "source"]],
  ["build", "bootstrap/build_for_target.sh", "build-result-v1", ["target", "source", "authenticatedHeaders"]],
  ["package", "lib/build_driver_product.py", "compiled-driver-product-v1", ["buildArtifacts", "provenance"]],
  ["bundle", "lib/driver_binary_bundle.py", "driver-binary-bundle-v1", ["compiledDriverProduct", "releaseIdentity"]],
  ["validate", "lib/validate_publish_inputs.py", "publication-plan-v1", ["canonicalAssetSet", "repository"]],
  ["release-dry-run", "bootstrap/publish_artifacts.sh", "publication-plan-v1", ["canonicalAssetSet", "dryRun"]],
].map(([id, entrypoint, result, requiredInputs]) => ({ id, entrypoint, result, requiredInputs, mutatesRemote: false }));
const deepFreeze = value => {
  if (value && typeof value === "object") { Object.values(value).forEach(deepFreeze); Object.freeze(value); }
  return value;
};
export const CORE_MAINTAINER_WORKFLOW = deepFreeze({
  schemaVersion: 1, kind: "opemos-maintainer-release-workflow", status: "available",
  target: { steamosVersion: "3.8.14", kernelVersion: "6.16.12-valve24.4-1-neptune-616-gfe145653a794", nvidiaVersion: "575.64.05", architecture: "x86_64" },
  capability: { id: "exact-target-driver-release-v1", available: true, policy: { name: "exact-target-builds-v1.json", sha256: "3c43dd181aa36cf74a009c7a211a9ec60c7d81a5596af0870b023f281f0edecc" } },
  contracts: { workflow: "maintainer-release-workflow-v1.schema.json", buildResult: { schemaVersion: 1, writer: "lib/write_build_result.py" }, releaseProgressResult: { schemaVersion: 1, schema: "contracts/schemas/release-operation-v1.schema.json", session: "lib/release_operation_session.py" } },
  publication: { mode: "dry-run-only", requiresSeparateAuthorization: true, combinedNvidiaSteamOsAsset: false },
  source: { repository: "CorniiDog/open-gpu-kernel-modules-steamos", ref: "refs/heads/nvidia/575.64.05", commit: "40bd1b5d6d39ae4e4180b7a665df144b08854d14" },
  steps,
});
const canonical = JSON.stringify(CORE_MAINTAINER_WORKFLOW);
export function validateMaintainerReleaseWorkflow(value) { return JSON.stringify(value) === canonical; }
export function installMaintainerReleaseWorkflow(document) {
  if (!validateMaintainerReleaseWorkflow(CORE_MAINTAINER_WORKFLOW)) throw new Error("Bundled Core maintainer workflow is invalid.");
  const plan = CORE_MAINTAINER_WORKFLOW;
  const status = document.querySelector("#maintainer-workflow-status");
  status.textContent = "Exact Core plan ready"; status.className = "status ready";
  document.querySelector("#maintainer-workflow-target").textContent = `SteamOS ${plan.target.steamosVersion} · ${plan.target.kernelVersion} · NVIDIA ${plan.target.nvidiaVersion}`;
  document.querySelector("#maintainer-workflow-source").textContent = `${plan.source.repository}@${plan.source.commit}`;
  document.querySelector("#maintainer-workflow-core").textContent = CORE_MAINTAINER_WORKFLOW_COMMIT;
  document.querySelector("#maintainer-workflow-steps").replaceChildren(...plan.steps.map((step) => {
    const item = document.createElement("li"); item.textContent = `${step.id} · ${step.result}`; item.title = `${step.entrypoint} (${step.requiredInputs.join(", ")})`; return item;
  }));
}

const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const ASSET_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$/;
const LIFECYCLES = new Set(["planned", "reconciling", "succeeded", "failed", "cancelled"]);
const DECISIONS = new Set(["create", "retry-missing", "already-complete", "conflict", "cancelled"]);
const ASSET_STATES = new Set(["pending", "present", "missing", "conflict"]);
const REQUIRED = new Set(["schemaVersion", "operationId", "repository", "tag", "targetCommit", "attempt", "lifecycle", "decision", "assets"]);

function exactKeys(value, required, optional = []) {
  const keys = Object.keys(value);
  return keys.length >= required.size && keys.length <= required.size + optional.length
    && keys.every((key) => required.has(key) || optional.includes(key))
    && [...required].every((key) => Object.hasOwn(value, key));
}

export function normalizeReleaseOperation(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || !exactKeys(value, REQUIRED, ["message"]) || value.schemaVersion !== 1
    || !SHA256.test(value.operationId) || !REPOSITORY.test(value.repository)
    || typeof value.tag !== "string" || value.tag.length < 1 || value.tag.length > 200
    || !COMMIT.test(value.targetCommit) || !Number.isInteger(value.attempt)
    || value.attempt < 1 || value.attempt > 1000 || !LIFECYCLES.has(value.lifecycle)
    || !DECISIONS.has(value.decision) || !Array.isArray(value.assets)
    || value.assets.length < 4 || value.assets.length > 16
    || (Object.hasOwn(value, "message") && (typeof value.message !== "string" || value.message.length > 500))) return null;

  const names = new Set();
  const assets = [];
  for (const asset of value.assets) {
    if (!asset || typeof asset !== "object" || Array.isArray(asset)
      || !exactKeys(asset, new Set(["name", "sha256", "bytes", "state"]))
      || !ASSET_NAME.test(asset.name) || names.has(asset.name) || !SHA256.test(asset.sha256)
      || !Number.isInteger(asset.bytes) || asset.bytes < 1 || asset.bytes > 2147483648
      || !ASSET_STATES.has(asset.state)) return null;
    names.add(asset.name);
    assets.push(Object.freeze({ name: asset.name, sha256: asset.sha256, bytes: asset.bytes, state: asset.state }));
  }
  const normalized = { schemaVersion: 1, operationId: value.operationId, repository: value.repository,
    tag: value.tag, targetCommit: value.targetCommit, attempt: value.attempt,
    lifecycle: value.lifecycle, decision: value.decision, assets: Object.freeze(assets) };
  if (Object.hasOwn(value, "message")) normalized.message = value.message;
  return Object.freeze(normalized);
}

export function releaseOperationAuthorizable(operation) {
  if (!operation) return false;
  if (operation.lifecycle === "planned" && operation.decision === "create") {
    return operation.assets.every((asset) => asset.state === "pending");
  }
  return operation.lifecycle === "reconciling" && operation.decision === "retry-missing"
    && operation.assets.some((asset) => asset.state === "missing")
    && operation.assets.every((asset) => asset.state === "present" || asset.state === "missing");
}

export function installReleasePlanReview(document) {
  const fields = {
    repository: document.querySelector("#release-repository"), tag: document.querySelector("#release-tag"),
    targetCommit: document.querySelector("#release-target-commit"), operationId: document.querySelector("#release-operation-id"),
  };
  const authorize = document.querySelector("#authorize-release");
  const status = document.querySelector("#release-plan-status");
  const assets = document.querySelector("#release-assets");

  function render(value) {
    const operation = normalizeReleaseOperation(value);
    for (const [name, node] of Object.entries(fields)) node.textContent = operation?.[name] || "—";
    assets.replaceChildren();
    for (const asset of operation?.assets || []) {
      const item = document.createElement("li");
      item.textContent = asset.name + " · " + asset.bytes + " bytes · " + asset.sha256 + " · " + asset.state;
      item.dataset.state = asset.state;
      assets.append(item);
    }
    authorize.disabled = !releaseOperationAuthorizable(operation);
    status.textContent = operation
      ? (operation.lifecycle + " · " + operation.decision + " · attempt " + operation.attempt + ". " + (operation.message || "")).trim()
      : "No immutable Core release operation loaded.";
  }

  render(null);
  return Object.freeze({ render });
}

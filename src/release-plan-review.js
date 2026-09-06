const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const ASSET_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$/;
const LIFECYCLES = new Set(["planned", "reconciling", "succeeded", "failed", "cancelled"]);
const DECISIONS = new Set(["create", "retry-missing", "already-complete", "conflict", "cancelled"]);
const ASSET_STATES = new Set(["pending", "present", "missing", "conflict"]);
const REQUIRED = new Set(["schemaVersion", "operationId", "repository", "tag", "targetCommit", "attempt", "lifecycle", "decision", "progress", "assets"]);
const PROGRESS_PHASES = new Set(["planning", "reconciling", "complete", "failed", "cancelled"]);

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
  const progress = value.progress;
  const completedAssets = assets.filter((asset) => asset.state === "present").length;
  if (!progress || typeof progress !== "object" || Array.isArray(progress)
    || !exactKeys(progress, new Set(["phase", "completedAssets", "totalAssets", "indeterminate"]))
    || !PROGRESS_PHASES.has(progress.phase) || !Number.isInteger(progress.completedAssets)
    || progress.completedAssets < 0 || progress.completedAssets > 16
    || progress.totalAssets !== assets.length || progress.completedAssets !== completedAssets
    || typeof progress.indeterminate !== "boolean") return null;
  const normalized = { schemaVersion: 1, operationId: value.operationId, repository: value.repository,
    tag: value.tag, targetCommit: value.targetCommit, attempt: value.attempt,
    lifecycle: value.lifecycle, decision: value.decision,
    progress: Object.freeze({ phase: progress.phase, completedAssets: progress.completedAssets,
      totalAssets: progress.totalAssets, indeterminate: progress.indeterminate }),
    assets: Object.freeze(assets) };
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

export function describeReleaseOperation(operation) {
  if (!operation) return "No immutable Core release operation loaded.";
  if (operation.lifecycle === "succeeded" && operation.decision === "already-complete") {
    return "The remote release exactly matches this immutable operation. No action is needed.";
  }
  if (operation.lifecycle === "failed" || operation.decision === "conflict") {
    return "Release reconciliation found a conflict. Authorization is blocked.";
  }
  if (operation.lifecycle === "cancelled" || operation.decision === "cancelled") {
    return "This release operation was cancelled and cannot claim success.";
  }
  return (operation.lifecycle + " · " + operation.decision + " · attempt " + operation.attempt + ". " + (operation.message || "")).trim();
}

function sameReleaseIdentity(left, right) {
  return left.operationId === right.operationId && left.repository === right.repository
    && left.tag === right.tag && left.targetCommit === right.targetCommit
    && left.assets.length === right.assets.length
    && left.assets.every((asset, index) => {
      const other = right.assets[index];
      return asset.name === other.name && asset.sha256 === other.sha256 && asset.bytes === other.bytes;
    });
}

function terminalReleaseOperation(operation) {
  return operation.lifecycle === "succeeded" || operation.lifecycle === "failed"
    || operation.lifecycle === "cancelled";
}

export function createReleaseReviewSession() {
  let operation = null;
  let authorization = null;
  const authorizationMatches = () => Boolean(authorization && operation
    && authorization.operationId === operation.operationId
    && authorization.attempt === operation.attempt
    && authorization.decision === operation.decision);

  return Object.freeze({
    review(value) {
      const next = normalizeReleaseOperation(value);
      operation = next;
      if (!authorizationMatches()) authorization = null;
      return operation;
    },
    authorize() {
      if (!releaseOperationAuthorizable(operation)) throw new Error("This release operation is not authorizable.");
      if (!authorizationMatches()) authorization = Object.freeze({
        operationId: operation.operationId, attempt: operation.attempt, decision: operation.decision,
      });
      return authorization;
    },
    reconcile(value) {
      const next = normalizeReleaseOperation(value);
      if (!operation || !next) throw new Error("Release reconciliation result is malformed or has no reviewed plan.");
      if (!sameReleaseIdentity(operation, next)) throw new Error("Release reconciliation changed the immutable operation identity.");
      if (next.attempt < operation.attempt) throw new Error("Release reconciliation result is stale.");
      if (next.attempt === operation.attempt) {
        if (JSON.stringify(next) !== JSON.stringify(operation)) throw new Error("Release reconciliation changed an existing attempt.");
        return operation;
      }
      if (terminalReleaseOperation(operation)) throw new Error("A terminal release result cannot be replaced.");
      operation = next;
      authorization = null;
      return operation;
    },
    acceptCommandResult(value) {
      const next = normalizeReleaseOperation(value);
      if (!operation || !next) throw new Error("Release command result is malformed or has no reviewed operation.");
      if (!sameReleaseIdentity(operation, next)) throw new Error("Release command changed the immutable operation identity.");
      if (next.attempt < operation.attempt) throw new Error("Release command result is stale.");
      if (terminalReleaseOperation(operation) && JSON.stringify(next) !== JSON.stringify(operation)) {
        throw new Error("A terminal release result cannot be replaced.");
      }
      operation = next;
      if (!authorizationMatches()) authorization = null;
      return operation;
    },
    snapshot() {
      return Object.freeze({ operation, authorization: authorizationMatches() ? authorization : null });
    },
  });
}

export function createReleaseCommandController(session, runCommand) {
  if (!session || typeof runCommand !== "function") throw new TypeError("A release session and command runner are required.");
  let request = 0;
  let busy = false;
  async function run(command, requiresAuthorization = false) {
    if (busy) throw new Error("A release command is already in progress.");
    const before = session.snapshot();
    if (!before.operation) throw new Error("No immutable Core release operation is loaded.");
    const authorization = before.authorization;
    if (requiresAuthorization && !authorization) {
      throw new Error("Explicit authorization for this exact release attempt is required.");
    }
    const token = ++request;
    busy = true;
    try {
      const value = await runCommand(command, Object.freeze({ operationId: before.operation.operationId,
        attempt: before.operation.attempt, authorization }));
      if (token !== request) return session.snapshot().operation;
      return session.acceptCommandResult(value);
    } finally {
      if (token === request) busy = false;
    }
  }
  return Object.freeze({
    start: () => run("execute", true), verify: () => run("status"),
    retry: () => run("reconcile", true), cancel: () => run("cancel"),
    invalidate() { request += 1; busy = false; },
    snapshot: () => Object.freeze({ ...session.snapshot(), busy }),
  });
}

export function installReleasePlanReview(document, runCommand = null) {
  const fields = {
    repository: document.querySelector("#release-repository"), tag: document.querySelector("#release-tag"),
    targetCommit: document.querySelector("#release-target-commit"), operationId: document.querySelector("#release-operation-id"),
  };
  const authorize = document.querySelector("#authorize-release");
  const status = document.querySelector("#release-plan-status");
  const assets = document.querySelector("#release-assets");
  const progress = document.querySelector("#release-progress");
  const start = document.querySelector("#release-start");
  const verify = document.querySelector("#release-verify");
  const retry = document.querySelector("#release-retry");
  const cancel = document.querySelector("#release-cancel-operation");
  const session = createReleaseReviewSession();
  const commands = runCommand ? createReleaseCommandController(session, runCommand) : null;

  function render(value) {
    const operation = session.review(value);
    for (const [name, node] of Object.entries(fields)) node.textContent = operation?.[name] || "—";
    assets.replaceChildren();
    for (const asset of operation?.assets || []) {
      const item = document.createElement("li");
      item.textContent = asset.name + " · " + asset.bytes + " bytes · " + asset.sha256 + " · " + asset.state;
      item.dataset.state = asset.state;
      assets.append(item);
    }
    authorize.disabled = !releaseOperationAuthorizable(operation);
    const commandReady = Boolean(commands && operation);
    const authorized = Boolean(session.snapshot().authorization);
    start.disabled = !commandReady || !authorized || operation.decision !== "create";
    verify.disabled = !commandReady;
    retry.disabled = !commandReady || !authorized || operation.decision !== "retry-missing";
    cancel.disabled = !commandReady || terminalReleaseOperation(operation);
    progress.textContent = operation
      ? `${operation.progress.phase} / ${operation.progress.completedAssets}/${operation.progress.totalAssets} assets${operation.progress.indeterminate ? " / waiting" : ""}`
      : "No durable release progress loaded.";
    status.textContent = describeReleaseOperation(operation);
  }

  authorize.addEventListener("click", () => {
    try {
      const authorization = session.authorize();
      render(session.snapshot().operation);
      authorize.disabled = true;
      status.textContent = "Explicit local authorization recorded for operation " + authorization.operationId + ", attempt " + authorization.attempt + ". The inactive command adapter may now start this exact attempt.";
    } catch (error) {
      authorize.disabled = true;
      status.textContent = String(error);
    }
  });

  for (const [button, command, label] of [[start, "start", "Starting"], [verify, "verify", "Verifying"],
    [retry, "retry", "Retrying missing assets"], [cancel, "cancel", "Cancelling"]]) {
    button.addEventListener("click", async () => {
      if (!commands) return;
      for (const node of [start, verify, retry, cancel, authorize]) node.disabled = true;
      status.textContent = `${label} exact operation...`;
      try { render(await commands[command]()); }
      catch (error) {
        render(session.snapshot().operation);
        status.textContent = String(error);
      }
    });
  }

  render(null);
  return Object.freeze({ render, snapshot: session.snapshot, commands });
}

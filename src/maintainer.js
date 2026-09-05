import { installCompatibilityPreview } from "./compatibility-preview.js";
import { operationContextMatches } from "./operation-context.js";
import { installWindowDrag } from "./window-drag.js";
import { installKeyboardBindings, runKeyboardDefaultAction } from "./keyboard.js";

const { invoke } = window.__TAURI__.core;
const { getCurrentWebviewWindow } = window.__TAURI__.webviewWindow;
const openFolder = (options) => invoke("plugin:dialog|open", { options });
const $ = (selector) => document.querySelector(selector);
const maintainerWindow = getCurrentWebviewWindow();
installWindowDrag(maintainerWindow);
installCompatibilityPreview(document, invoke, () => openFolder({
  multiple: false,
  directory: false,
  filters: [{ name: "Core resolver JSON", extensions: ["json"] }],
}));
await maintainerWindow.onCloseRequested(async (event) => {
  event.preventDefault();
  await maintainerWindow.emitTo("main", "companion-window-hidden", { label: "maintainer-workspace" });
  await maintainerWindow.hide();
});

const elements = {
  permission: $("#permission-status"), refresh: $("#refresh-sources"),
  component: $("#component"), origin: $("#origin"), referenceSelect: $("#source-reference"),
  repository: $("#repository"), reference: $("#reference"), commit: $("#commit"),
  upstreamNotice: $("#upstream-notice"), planButton: $("#plan-workspace"),
  message: $("#workspace-message"), planTitle: $("#plan-title"), planStatus: $("#plan-status"),
  planId: $("#plan-id"), architecture: $("#architecture"), isolation: $("#isolation"),
  remoteMutation: $("#remote-mutation"), worktreeCard: $("#local-worktree-card"),
  recentWorktree: $("#recent-worktree"), chooseWorktree: $("#choose-worktree"),
  makeWorktree: $("#make-worktree"), worktreePath: $("#worktree-path"),
  worktreeBranch: $("#worktree-branch"), worktreeHead: $("#worktree-head"),
  worktreeChanges: $("#worktree-changes"), openVscode: $("#open-vscode"),
  worktreeMessage: $("#worktree-message"),
  localCommitPanel: $("#local-commit-panel"), commitMessage: $("#commit-message"),
  reviewStaged: $("#review-staged"), stagedReview: $("#staged-review"),
  createLocalCommit: $("#create-local-commit"), commitStatus: $("#commit-message-status"),
  stagedPatch: $("#staged-patch"),
  checkoutPanel: $("#checkout-panel"), localBranch: $("#local-branch"),
  loadLocalBranches: $("#load-local-branches"), reviewCheckout: $("#review-checkout"),
  checkoutReview: $("#checkout-review"), executeCheckout: $("#execute-checkout"),
  checkoutStatus: $("#checkout-status"),
};

let sources = [];
let loading = false;
let plannedRepository = null;
let plannedSource = null;
let localWorktree = null;
let commitReview = null;
let branchReview = null;
let workspaceGeneration = 0;

installKeyboardBindings([
  {
    key: "Enter",
    accelerator: true,
    allowInEditable: true,
    when: () => document.activeElement === elements.commitMessage,
    run: () => runKeyboardDefaultAction(elements.reviewStaged),
  },
]);

function sourceKey(source) {
  return JSON.stringify([
    source.component, source.origin, source.repository, source.reference, source.commit,
  ]);
}

function selectedSource() {
  const key = elements.referenceSelect.value;
  return sources.find((source) => source.component === elements.component.value
    && source.origin === elements.origin.value && sourceKey(source) === key) || null;
}

function renderSelection() {
  const previous = elements.referenceSelect.value;
  const matches = sources.filter((source) => source.component === elements.component.value
    && source.origin === elements.origin.value);
  elements.referenceSelect.replaceChildren();
  for (const source of matches) {
    const option = document.createElement("option");
    option.value = sourceKey(source);
    option.textContent = `${source.label} · ${source.commit.slice(0, 12)}`;
    elements.referenceSelect.append(option);
  }
  if (matches.some((source) => sourceKey(source) === previous)) elements.referenceSelect.value = previous;
  const selected = selectedSource();
  elements.repository.textContent = selected?.repository || "—";
  elements.repository.title = selected?.repository || "";
  elements.reference.textContent = selected?.reference || "—";
  elements.reference.title = selected?.reference || "";
  elements.commit.textContent = selected?.commit || "—";
  elements.commit.title = selected?.commit || "";
  elements.upstreamNotice.classList.toggle("hidden", selected?.origin !== "upstream");
  elements.planButton.disabled = loading || !selected;
}

function resetPlan() {
  workspaceGeneration += 1;
  plannedRepository = null;
  plannedSource = null;
  localWorktree = null;
  commitReview = null;
  branchReview = null;
  elements.planTitle.textContent = "No workspace prepared";
  elements.planStatus.textContent = "Idle";
  elements.planStatus.className = "status";
  elements.planId.textContent = "—";
  elements.remoteMutation.textContent = "Blocked";
  elements.worktreeCard.classList.add("hidden");
  elements.recentWorktree.replaceChildren(new Option("No Recent Folders", ""));
  elements.recentWorktree.disabled = true;
  elements.openVscode.disabled = true;
  elements.localCommitPanel.classList.add("hidden");
  elements.checkoutPanel.classList.add("hidden");
}

function disableSourceControls(disabled) {
  elements.refresh.disabled = disabled;
  elements.component.disabled = disabled;
  elements.origin.disabled = disabled;
  elements.referenceSelect.disabled = disabled;
}

function setWorkspaceMutationPending(pending) {
  loading = pending;
  elements.refresh.disabled = pending;
  elements.component.disabled = pending || !sources.length;
  elements.origin.disabled = pending || !sources.length;
  elements.referenceSelect.disabled = pending || !sources.length;
  elements.chooseWorktree.disabled = pending;
  elements.makeWorktree.disabled = pending;
  elements.recentWorktree.disabled = pending || elements.recentWorktree.options.length <= 1;
  elements.openVscode.disabled = pending || !localWorktree?.vscodeAvailable;
  elements.commitMessage.disabled = pending;
  elements.reviewStaged.disabled = pending || !localWorktree || !elements.commitMessage.value.trim();
  elements.loadLocalBranches.disabled = pending;
  elements.localBranch.disabled = pending || !elements.localBranch.value;
  elements.reviewCheckout.disabled = pending || !elements.localBranch.value;
  renderSelection();
}

async function loadSources() {
  loading = true;
  elements.refresh.disabled = true;
  elements.component.disabled = true;
  elements.origin.disabled = true;
  elements.referenceSelect.disabled = true;
  elements.planButton.disabled = true;
  elements.permission.textContent = "Checking permission";
  elements.permission.className = "status pending";
  elements.message.textContent = "Refreshing approved repositories and exact commits…";
  elements.message.className = "message";
  resetPlan();
  try {
    sources = await invoke("list_maintainer_workspace_sources");
    elements.permission.textContent = "Maintainer verified";
    elements.permission.className = "status ready";
    elements.message.textContent = `${sources.length} exact source identities available.`;
  } catch (error) {
    sources = [];
    elements.permission.textContent = "Access denied";
    elements.permission.className = "status failed";
    elements.message.textContent = String(error);
    elements.message.className = "message error";
  } finally {
    loading = false;
    elements.refresh.disabled = false;
    elements.component.disabled = !sources.length;
    elements.origin.disabled = !sources.length;
    elements.referenceSelect.disabled = !sources.length;
    renderSelection();
  }
}

elements.component.addEventListener("change", () => { resetPlan(); renderSelection(); });
elements.origin.addEventListener("change", () => { resetPlan(); renderSelection(); });
elements.referenceSelect.addEventListener("change", () => { resetPlan(); renderSelection(); });
elements.refresh.addEventListener("click", loadSources);
elements.planButton.addEventListener("click", async () => {
  const source = selectedSource();
  if (!source) return;
  loading = true;
  disableSourceControls(true);
  renderSelection();
  elements.message.textContent = "Rechecking permission and resolving the selected reference…";
  elements.message.className = "message";
  elements.planStatus.textContent = "Verifying";
  elements.planStatus.className = "status pending";
  try {
    const plan = await invoke("plan_maintainer_workspace", {
      component: source.component,
      origin: source.origin,
      reference: source.reference,
      commit: source.commit,
    });
    const current = selectedSource();
    if (!current || current.repository !== source.repository || current.reference !== source.reference
      || current.commit !== source.commit) {
      throw new Error("The source selection changed while the plan was being verified. Verify it again.");
    }
    elements.planTitle.textContent = `${plan.component === "nvidia" ? "NVIDIA" : "Gamescope"} workspace identity verified`;
    elements.planStatus.textContent = "Planned";
    elements.planStatus.className = "status ready";
    elements.planId.textContent = plan.planId;
    elements.planId.title = plan.planId;
    elements.architecture.textContent = plan.architecture;
    elements.isolation.textContent = plan.isolation.replaceAll("-", " ");
    elements.remoteMutation.textContent = plan.remoteMutationAllowed ? "Allowed" : "Blocked pending confirmation";
    plannedRepository = plan.repository;
    plannedSource = {
      component: plan.component,
      origin: plan.origin,
      repository: plan.repository,
      reference: plan.reference,
      commit: plan.commit,
    };
    elements.worktreeCard.classList.remove("hidden");
    elements.message.textContent = plan.message;
    await refreshRecentWorktrees(plan.repository, workspaceGeneration);
  } catch (error) {
    resetPlan();
    elements.planStatus.textContent = "Rejected";
    elements.planStatus.className = "status failed";
    elements.message.textContent = String(error);
    elements.message.className = "message error";
  } finally {
    loading = false;
    disableSourceControls(false);
    renderSelection();
  }
});

function renderWorktree(worktree) {
  workspaceGeneration += 1;
  localWorktree = worktree;
  commitReview = null;
  branchReview = null;
  elements.worktreePath.textContent = worktree?.path || "—";
  elements.worktreePath.title = worktree?.path || "";
  elements.worktreeBranch.textContent = worktree?.branch || (worktree ? "Detached HEAD" : "—");
  elements.worktreeHead.textContent = worktree?.head || "—";
  elements.worktreeHead.title = worktree?.head || "";
  elements.worktreeChanges.textContent = worktree ? `${worktree.changedFiles} changed path${worktree.changedFiles === 1 ? "" : "s"}` : "—";
  elements.openVscode.disabled = !worktree?.vscodeAvailable;
  elements.localCommitPanel.classList.toggle("hidden", !worktree);
  elements.checkoutPanel.classList.toggle("hidden", !worktree);
  elements.reviewStaged.disabled = !worktree || !elements.commitMessage.value.trim();
  elements.stagedReview.classList.add("hidden");
  elements.stagedPatch.classList.add("hidden");
  elements.createLocalCommit.classList.add("hidden");
  elements.localBranch.replaceChildren(new Option("Load clean local branches first", ""));
  elements.localBranch.disabled = true;
  elements.reviewCheckout.disabled = true;
  elements.checkoutReview.classList.add("hidden");
  elements.executeCheckout.classList.add("hidden");
}

async function refreshRecentWorktrees(repository, generation = workspaceGeneration) {
  elements.recentWorktree.replaceChildren(new Option("Checking Recent Folders…", ""));
  elements.recentWorktree.disabled = true;
  try {
    const worktrees = await invoke("list_recent_maintainer_worktrees", { repository });
    if (generation !== workspaceGeneration || repository !== plannedRepository) return;
    elements.recentWorktree.replaceChildren(new Option(
      worktrees.length ? "Select Recent Folder" : "No Recent Folders",
      "",
    ));
    for (const worktree of worktrees) {
      const option = new Option(worktree.path.split(/[\\/]/).at(-1) || worktree.path, worktree.path);
      option.title = worktree.path;
      elements.recentWorktree.append(option);
    }
    elements.recentWorktree.disabled = !worktrees.length;
  } catch (error) {
    if (generation !== workspaceGeneration) return;
    elements.recentWorktree.replaceChildren(new Option("Recent Folders Unavailable", ""));
    elements.recentWorktree.disabled = true;
    elements.worktreeMessage.textContent = String(error);
    elements.worktreeMessage.className = "message error";
  }
}

elements.chooseWorktree.addEventListener("click", async () => {
  if (!plannedRepository) return;
  const dialogGeneration = workspaceGeneration;
  const repository = plannedRepository;
  const path = await openFolder({ directory: true, multiple: false, title: "Select matching Git worktree" });
  if (!path) return;
  if (dialogGeneration !== workspaceGeneration || repository !== plannedRepository) return;
  elements.worktreeMessage.textContent = "Validating the worktree root, origin, HEAD, and change state…";
  elements.worktreeMessage.className = "message";
  renderWorktree(null);
  const generation = workspaceGeneration;
  try {
    const worktree = await invoke("inspect_maintainer_worktree", { path, repository });
    if (generation !== workspaceGeneration || repository !== plannedRepository) return;
    renderWorktree(worktree);
    void refreshRecentWorktrees(repository, workspaceGeneration);
    elements.worktreeMessage.textContent = worktree.vscodeAvailable
      ? "Valid local target. VS Code can reuse its current window for this worktree."
      : "Valid local target, but the VS Code command-line launcher was not found.";
  } catch (error) {
    if (generation !== workspaceGeneration) return;
    elements.worktreeMessage.textContent = String(error);
    elements.worktreeMessage.className = "message error";
  }
});

elements.recentWorktree.addEventListener("change", async () => {
  const path = elements.recentWorktree.value;
  if (!path || !plannedRepository) return;
  const repository = plannedRepository;
  const generation = workspaceGeneration;
  setWorkspaceMutationPending(true);
  elements.worktreeMessage.textContent = "Revalidating the recent folder before selecting it…";
  elements.worktreeMessage.className = "message";
  try {
    const worktree = await invoke("inspect_maintainer_worktree", { path, repository });
    if (generation !== workspaceGeneration || repository !== plannedRepository) return;
    renderWorktree(worktree);
    void refreshRecentWorktrees(repository, workspaceGeneration);
    elements.worktreeMessage.textContent = worktree.vscodeAvailable
      ? "Recent local target revalidated. VS Code can reuse its current window for this worktree."
      : "Recent local target revalidated, but the VS Code command-line launcher was not found.";
  } catch (error) {
    if (generation !== workspaceGeneration) return;
    elements.worktreeMessage.textContent = String(error);
    elements.worktreeMessage.className = "message error";
    void refreshRecentWorktrees(repository, workspaceGeneration);
  } finally {
    setWorkspaceMutationPending(false);
  }
});

elements.makeWorktree.addEventListener("click", async () => {
  if (!plannedSource) return;
  const source = { ...plannedSource };
  const generation = workspaceGeneration;
  setWorkspaceMutationPending(true);
  elements.worktreeMessage.textContent = "Creating or reopening a dedicated checkout at the exact verified commit…";
  elements.worktreeMessage.className = "message";
  try {
    const worktree = await invoke("make_maintainer_worktree", source);
    if (generation !== workspaceGeneration
      || JSON.stringify(source) !== JSON.stringify(plannedSource)) return;
    renderWorktree(worktree);
    void refreshRecentWorktrees(source.repository, workspaceGeneration);
    elements.worktreeMessage.textContent = worktree.vscodeAvailable
      ? "Managed local target is ready. VS Code can reuse its current window for this worktree."
      : "Managed local target is ready, but the VS Code command-line launcher was not found.";
  } catch (error) {
    if (generation !== workspaceGeneration) return;
    elements.worktreeMessage.textContent = String(error);
    elements.worktreeMessage.className = "message error";
  } finally {
    setWorkspaceMutationPending(false);
  }
});

elements.openVscode.addEventListener("click", async () => {
  if (!localWorktree || !plannedRepository) return;
  const context = {
    generation: workspaceGeneration,
    path: localWorktree.path,
    repository: plannedRepository,
  };
  elements.openVscode.disabled = true;
  elements.worktreeMessage.textContent = "Revalidating and opening the selected worktree in VS Code…";
  try {
    const refreshed = await invoke("open_maintainer_worktree_in_vscode", {
      path: context.path, repository: context.repository,
    });
    if (!operationContextMatches(context, {
      generation: workspaceGeneration,
      path: localWorktree?.path,
      repository: plannedRepository,
    })) return;
    renderWorktree(refreshed);
    elements.worktreeMessage.textContent = "Opened the validated worktree in VS Code.";
  } catch (error) {
    if (!operationContextMatches(context, {
      generation: workspaceGeneration,
      path: localWorktree?.path,
      repository: plannedRepository,
    })) return;
    elements.worktreeMessage.textContent = String(error);
    elements.worktreeMessage.className = "message error";
    elements.openVscode.disabled = false;
  }
});

elements.commitMessage.addEventListener("input", () => {
  commitReview = null;
  elements.reviewStaged.disabled = !localWorktree || !elements.commitMessage.value.trim();
  elements.stagedReview.classList.add("hidden");
  elements.stagedPatch.classList.add("hidden");
  elements.createLocalCommit.classList.add("hidden");
});

elements.reviewStaged.addEventListener("click", async () => {
  if (!localWorktree || !plannedRepository) return;
  const generation = workspaceGeneration;
  const worktreePath = localWorktree.path;
  const repository = plannedRepository;
  const message = elements.commitMessage.value;
  elements.reviewStaged.disabled = true;
  elements.commitStatus.textContent = "Revalidating the worktree and snapshotting its exact staged tree…";
  elements.commitStatus.className = "message";
  try {
    commitReview = await invoke("review_maintainer_staged_commit", {
      path: worktreePath, repository, message,
    });
    if (generation !== workspaceGeneration || worktreePath !== localWorktree?.path
      || repository !== plannedRepository || message !== elements.commitMessage.value) return;
    const visiblePaths = commitReview.stagedPaths.slice(0, 20).join(", ");
    const remaining = Math.max(0, commitReview.stagedPaths.length - 20);
    elements.stagedReview.textContent = `${commitReview.stagedPaths.length} staged path${commitReview.stagedPaths.length === 1 ? "" : "s"}: ${visiblePaths}${remaining ? `, and ${remaining} more` : ""}`;
    elements.stagedReview.classList.remove("hidden");
    elements.stagedPatch.textContent = commitReview.patchPreview;
    elements.stagedPatch.classList.remove("hidden");
    elements.createLocalCommit.classList.remove("hidden");
    elements.commitStatus.textContent = `Review bound to ${commitReview.head.slice(0, 12)} and tree ${commitReview.indexTree.slice(0, 12)}. Nothing has been committed or pushed.`;
  } catch (error) {
    if (generation !== workspaceGeneration) return;
    commitReview = null;
    elements.commitStatus.textContent = String(error);
    elements.commitStatus.className = "message error";
  } finally {
    elements.reviewStaged.disabled = !localWorktree || !elements.commitMessage.value.trim();
  }
});

elements.createLocalCommit.addEventListener("click", async () => {
  if (!commitReview || !localWorktree || !plannedRepository) return;
  elements.createLocalCommit.disabled = true;
  setWorkspaceMutationPending(true);
  elements.commitStatus.textContent = "Revalidating HEAD and the staged tree before the atomic local commit…";
  try {
    const result = await invoke("create_maintainer_local_commit", {
      path: localWorktree.path,
      repository: plannedRepository,
      message: elements.commitMessage.value,
      expectedHead: commitReview.head,
      expectedIndexTree: commitReview.indexTree,
      expectedPatchSha256: commitReview.patchSha256,
    });
    elements.commitStatus.textContent = `${result.message} ${result.commit.slice(0, 12)} on ${result.branch}.`;
    elements.commitStatus.className = "message";
    elements.commitMessage.value = "";
    commitReview = null;
    elements.stagedReview.classList.add("hidden");
    elements.stagedPatch.classList.add("hidden");
    elements.createLocalCommit.classList.add("hidden");
    const refreshed = await invoke("inspect_maintainer_worktree", {
      path: localWorktree.path, repository: plannedRepository,
    });
    renderWorktree(refreshed);
    elements.commitStatus.textContent = `${result.message} ${result.commit.slice(0, 12)} on ${result.branch}.`;
  } catch (error) {
    commitReview = null;
    elements.commitStatus.textContent = String(error);
    elements.commitStatus.className = "message error";
    elements.createLocalCommit.classList.add("hidden");
    elements.stagedReview.classList.add("hidden");
    elements.stagedPatch.classList.add("hidden");
  } finally {
    setWorkspaceMutationPending(false);
    elements.createLocalCommit.disabled = false;
    elements.reviewStaged.disabled = !localWorktree || !elements.commitMessage.value.trim();
  }
});

elements.loadLocalBranches.addEventListener("click", async () => {
  if (!localWorktree || !plannedRepository) return;
  const generation = workspaceGeneration;
  const worktreePath = localWorktree.path;
  const repository = plannedRepository;
  branchReview = null;
  elements.loadLocalBranches.disabled = true;
  elements.checkoutStatus.textContent = "Revalidating cleanliness and loading existing local branches…";
  elements.checkoutStatus.className = "message";
  try {
    const branches = await invoke("list_maintainer_local_branches", {
      path: worktreePath, repository,
    });
    if (generation !== workspaceGeneration || worktreePath !== localWorktree?.path
      || repository !== plannedRepository) return;
    elements.localBranch.replaceChildren();
    for (const branch of branches) {
      const option = document.createElement("option");
      option.value = branch.name;
      option.textContent = `${branch.name}${branch.current ? " (current)" : ""} · ${branch.commit.slice(0, 12)}`;
      elements.localBranch.append(option);
    }
    elements.localBranch.disabled = false;
    elements.reviewCheckout.disabled = false;
    elements.checkoutStatus.textContent = `${branches.length} clean local branch context${branches.length === 1 ? "" : "s"} available. No remote was queried.`;
  } catch (error) {
    if (generation !== workspaceGeneration) return;
    elements.localBranch.replaceChildren(new Option("Clean local branches unavailable", ""));
    elements.localBranch.disabled = true;
    elements.reviewCheckout.disabled = true;
    elements.checkoutStatus.textContent = String(error);
    elements.checkoutStatus.className = "message error";
  } finally {
    elements.loadLocalBranches.disabled = false;
  }
});

elements.localBranch.addEventListener("change", () => {
  branchReview = null;
  elements.checkoutReview.classList.add("hidden");
  elements.executeCheckout.classList.add("hidden");
});

elements.reviewCheckout.addEventListener("click", async () => {
  if (!localWorktree || !plannedRepository || !elements.localBranch.value) return;
  const generation = workspaceGeneration;
  const worktreePath = localWorktree.path;
  const repository = plannedRepository;
  const targetBranch = elements.localBranch.value;
  elements.reviewCheckout.disabled = true;
  elements.checkoutStatus.textContent = "Revalidating the clean current and target branch identities…";
  try {
    branchReview = await invoke("review_maintainer_checkout", {
      path: worktreePath,
      repository,
      targetBranch,
    });
    if (generation !== workspaceGeneration || worktreePath !== localWorktree?.path
      || repository !== plannedRepository || targetBranch !== elements.localBranch.value) return;
    elements.checkoutReview.textContent = `${branchReview.currentBranch} ${branchReview.currentHead.slice(0, 12)} → ${branchReview.targetBranch} ${branchReview.targetCommit.slice(0, 12)}. ${branchReview.message}`;
    elements.checkoutReview.classList.remove("hidden");
    elements.executeCheckout.classList.remove("hidden");
    elements.checkoutStatus.textContent = "Branch change reviewed; execute will revalidate everything again.";
    elements.checkoutStatus.className = "message";
  } catch (error) {
    if (generation !== workspaceGeneration) return;
    branchReview = null;
    elements.checkoutStatus.textContent = String(error);
    elements.checkoutStatus.className = "message error";
  } finally {
    elements.reviewCheckout.disabled = !elements.localBranch.value;
  }
});

elements.executeCheckout.addEventListener("click", async () => {
  if (!branchReview || !localWorktree || !plannedRepository) return;
  elements.executeCheckout.disabled = true;
  setWorkspaceMutationPending(true);
  elements.checkoutStatus.textContent = "Performing the freshly revalidated clean local branch change…";
  try {
    const result = await invoke("execute_maintainer_checkout", {
      path: localWorktree.path,
      repository: plannedRepository,
      targetBranch: branchReview.targetBranch,
      expectedHead: branchReview.currentHead,
      expectedTargetCommit: branchReview.targetCommit,
    });
    const message = `${result.message} ${result.branch} at ${result.head.slice(0, 12)}.`;
    const refreshed = await invoke("inspect_maintainer_worktree", {
      path: localWorktree.path, repository: plannedRepository,
    });
    renderWorktree(refreshed);
    elements.checkoutStatus.textContent = message;
    elements.checkoutStatus.className = "message";
  } catch (error) {
    branchReview = null;
    elements.checkoutStatus.textContent = String(error);
    elements.checkoutStatus.className = "message error";
    elements.checkoutReview.classList.add("hidden");
    elements.executeCheckout.classList.add("hidden");
  } finally {
    setWorkspaceMutationPending(false);
    elements.executeCheckout.disabled = false;
  }
});

await loadSources();

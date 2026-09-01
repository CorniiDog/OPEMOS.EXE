const { invoke } = window.__TAURI__.core;
const openFolder = (options) => invoke("plugin:dialog|open", { options });
const $ = (selector) => document.querySelector(selector);

const elements = {
  permission: $("#permission-status"), refresh: $("#refresh-sources"),
  component: $("#component"), origin: $("#origin"), referenceSelect: $("#source-reference"),
  repository: $("#repository"), reference: $("#reference"), commit: $("#commit"),
  upstreamNotice: $("#upstream-notice"), planButton: $("#plan-workspace"),
  message: $("#workspace-message"), planTitle: $("#plan-title"), planStatus: $("#plan-status"),
  planId: $("#plan-id"), architecture: $("#architecture"), isolation: $("#isolation"),
  remoteMutation: $("#remote-mutation"), worktreeCard: $("#local-worktree-card"),
  chooseWorktree: $("#choose-worktree"), worktreePath: $("#worktree-path"),
  worktreeBranch: $("#worktree-branch"), worktreeHead: $("#worktree-head"),
  worktreeChanges: $("#worktree-changes"), openVscode: $("#open-vscode"),
  worktreeMessage: $("#worktree-message"),
  localCommitPanel: $("#local-commit-panel"), commitMessage: $("#commit-message"),
  reviewStaged: $("#review-staged"), stagedReview: $("#staged-review"),
  createLocalCommit: $("#create-local-commit"), commitStatus: $("#commit-message-status"),
};

let sources = [];
let loading = false;
let plannedRepository = null;
let localWorktree = null;
let commitReview = null;

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
  plannedRepository = null;
  localWorktree = null;
  commitReview = null;
  elements.planTitle.textContent = "No workspace prepared";
  elements.planStatus.textContent = "Idle";
  elements.planStatus.className = "status";
  elements.planId.textContent = "—";
  elements.remoteMutation.textContent = "Blocked";
  elements.worktreeCard.classList.add("hidden");
  elements.openVscode.disabled = true;
  elements.localCommitPanel.classList.add("hidden");
}

function disableSourceControls(disabled) {
  elements.refresh.disabled = disabled;
  elements.component.disabled = disabled;
  elements.origin.disabled = disabled;
  elements.referenceSelect.disabled = disabled;
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
    elements.worktreeCard.classList.remove("hidden");
    elements.message.textContent = plan.message;
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
  localWorktree = worktree;
  commitReview = null;
  elements.worktreePath.textContent = worktree?.path || "—";
  elements.worktreePath.title = worktree?.path || "";
  elements.worktreeBranch.textContent = worktree?.branch || (worktree ? "Detached HEAD" : "—");
  elements.worktreeHead.textContent = worktree?.head || "—";
  elements.worktreeHead.title = worktree?.head || "";
  elements.worktreeChanges.textContent = worktree ? `${worktree.changedFiles} changed path${worktree.changedFiles === 1 ? "" : "s"}` : "—";
  elements.openVscode.disabled = !worktree?.vscodeAvailable;
  elements.localCommitPanel.classList.toggle("hidden", !worktree);
  elements.reviewStaged.disabled = !worktree || !elements.commitMessage.value.trim();
  elements.stagedReview.classList.add("hidden");
  elements.createLocalCommit.classList.add("hidden");
}

elements.chooseWorktree.addEventListener("click", async () => {
  if (!plannedRepository) return;
  const path = await openFolder({ directory: true, multiple: false, title: "Select matching Git worktree" });
  if (!path) return;
  elements.worktreeMessage.textContent = "Validating the worktree root, origin, HEAD, and change state…";
  elements.worktreeMessage.className = "message";
  renderWorktree(null);
  try {
    const worktree = await invoke("inspect_maintainer_worktree", { path, repository: plannedRepository });
    renderWorktree(worktree);
    elements.worktreeMessage.textContent = worktree.vscodeAvailable
      ? "Valid local target. VS Code can reuse its current window for this worktree."
      : "Valid local target, but the VS Code command-line launcher was not found.";
  } catch (error) {
    elements.worktreeMessage.textContent = String(error);
    elements.worktreeMessage.className = "message error";
  }
});

elements.openVscode.addEventListener("click", async () => {
  if (!localWorktree || !plannedRepository) return;
  elements.openVscode.disabled = true;
  elements.worktreeMessage.textContent = "Revalidating and opening the selected worktree in VS Code…";
  try {
    const refreshed = await invoke("open_maintainer_worktree_in_vscode", {
      path: localWorktree.path, repository: plannedRepository,
    });
    renderWorktree(refreshed);
    elements.worktreeMessage.textContent = "Opened the validated worktree in VS Code.";
  } catch (error) {
    elements.worktreeMessage.textContent = String(error);
    elements.worktreeMessage.className = "message error";
    elements.openVscode.disabled = false;
  }
});

elements.commitMessage.addEventListener("input", () => {
  commitReview = null;
  elements.reviewStaged.disabled = !localWorktree || !elements.commitMessage.value.trim();
  elements.stagedReview.classList.add("hidden");
  elements.createLocalCommit.classList.add("hidden");
});

elements.reviewStaged.addEventListener("click", async () => {
  if (!localWorktree || !plannedRepository) return;
  elements.reviewStaged.disabled = true;
  elements.commitStatus.textContent = "Revalidating the worktree and snapshotting its exact staged tree…";
  elements.commitStatus.className = "message";
  try {
    commitReview = await invoke("review_maintainer_staged_commit", {
      path: localWorktree.path, repository: plannedRepository, message: elements.commitMessage.value,
    });
    const visiblePaths = commitReview.stagedPaths.slice(0, 20).join(", ");
    const remaining = Math.max(0, commitReview.stagedPaths.length - 20);
    elements.stagedReview.textContent = `${commitReview.stagedPaths.length} staged path${commitReview.stagedPaths.length === 1 ? "" : "s"}: ${visiblePaths}${remaining ? `, and ${remaining} more` : ""}`;
    elements.stagedReview.classList.remove("hidden");
    elements.createLocalCommit.classList.remove("hidden");
    elements.commitStatus.textContent = `Review bound to ${commitReview.head.slice(0, 12)} and tree ${commitReview.indexTree.slice(0, 12)}. Nothing has been committed or pushed.`;
  } catch (error) {
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
  elements.commitStatus.textContent = "Revalidating HEAD and the staged tree before the atomic local commit…";
  try {
    const result = await invoke("create_maintainer_local_commit", {
      path: localWorktree.path,
      repository: plannedRepository,
      message: elements.commitMessage.value,
      expectedHead: commitReview.head,
      expectedIndexTree: commitReview.indexTree,
    });
    elements.commitStatus.textContent = `${result.message} ${result.commit.slice(0, 12)} on ${result.branch}.`;
    elements.commitStatus.className = "message";
    elements.commitMessage.value = "";
    commitReview = null;
    elements.stagedReview.classList.add("hidden");
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
  } finally {
    elements.createLocalCommit.disabled = false;
    elements.reviewStaged.disabled = !localWorktree || !elements.commitMessage.value.trim();
  }
});

await loadSources();

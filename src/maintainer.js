const { invoke } = window.__TAURI__.core;
const $ = (selector) => document.querySelector(selector);

const elements = {
  permission: $("#permission-status"), refresh: $("#refresh-sources"),
  component: $("#component"), origin: $("#origin"), referenceSelect: $("#source-reference"),
  repository: $("#repository"), reference: $("#reference"), commit: $("#commit"),
  upstreamNotice: $("#upstream-notice"), planButton: $("#plan-workspace"),
  message: $("#workspace-message"), planTitle: $("#plan-title"), planStatus: $("#plan-status"),
  planId: $("#plan-id"), architecture: $("#architecture"), isolation: $("#isolation"),
  remoteMutation: $("#remote-mutation"),
};

let sources = [];
let loading = false;

function selectedSource() {
  const commit = elements.referenceSelect.value;
  return sources.find((source) => source.component === elements.component.value
    && source.origin === elements.origin.value && source.commit === commit) || null;
}

function renderSelection() {
  const previous = elements.referenceSelect.value;
  const matches = sources.filter((source) => source.component === elements.component.value
    && source.origin === elements.origin.value);
  elements.referenceSelect.replaceChildren();
  for (const source of matches) {
    const option = document.createElement("option");
    option.value = source.commit;
    option.textContent = `${source.label} · ${source.commit.slice(0, 12)}`;
    elements.referenceSelect.append(option);
  }
  if (matches.some((source) => source.commit === previous)) elements.referenceSelect.value = previous;
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
  elements.planTitle.textContent = "No workspace prepared";
  elements.planStatus.textContent = "Idle";
  elements.planStatus.className = "status";
  elements.planId.textContent = "—";
  elements.remoteMutation.textContent = "Blocked";
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
    elements.planTitle.textContent = `${plan.component === "nvidia" ? "NVIDIA" : "Gamescope"} workspace identity verified`;
    elements.planStatus.textContent = "Planned";
    elements.planStatus.className = "status ready";
    elements.planId.textContent = plan.planId;
    elements.planId.title = plan.planId;
    elements.architecture.textContent = plan.architecture;
    elements.isolation.textContent = plan.isolation.replaceAll("-", " ");
    elements.remoteMutation.textContent = plan.remoteMutationAllowed ? "Allowed" : "Blocked pending confirmation";
    elements.message.textContent = plan.message;
  } catch (error) {
    resetPlan();
    elements.planStatus.textContent = "Rejected";
    elements.planStatus.className = "status failed";
    elements.message.textContent = String(error);
    elements.message.className = "message error";
  } finally {
    loading = false;
    renderSelection();
  }
});

await loadSources();

const { invoke } = window.__TAURI__.core;
const { getCurrentWebviewWindow } = window.__TAURI__.webviewWindow;
const open = (options) => invoke("plugin:dialog|open", { options });
const openUrl = (url) => invoke("plugin:opener|open_url", { url });

const $ = (selector) => document.querySelector(selector);
const elements = {
  dropZone: $("#drop-zone"), chooseImage: $("#choose-image"), openValve: $("#open-valve"),
  selectionCard: $("#selection-card"), selectedName: $("#selected-name"), selectedPath: $("#selected-path"),
  selectionStatus: $("#selection-status"), buildCard: $("#build-card"), buildButton: $("#build-button"),
  progressWrap: $("#progress-wrap"), progressBar: $("#progress-bar"), progressLabel: $("#progress-label"),
  resultMessage: $("#result-message"), environmentTitle: $("#environment-title"),
  environmentMessage: $("#environment-message"), environmentDetails: $("#environment-details"),
  environmentStatus: $("#environment-status"), startAppliance: $("#start-appliance"), stopAppliance: $("#stop-appliance"),
};

let currentImage = null;
let hostReady = false;
let statusTimer = null;

function showApplianceStatus(status) {
  const labels = { booting: "Booting", ready: "Ready", failed: "Failed", timedOut: "Timed out", stopped: "Stopped" };
  elements.environmentTitle.textContent = status.state === "ready" ? "Builder is ready" : "Builder appliance";
  elements.environmentMessage.textContent = status.message;
  elements.environmentDetails.textContent = [status.sshPort ? `Local control port: ${status.sshPort}` : "", status.runtimePath || ""].filter(Boolean).join(" · ");
  elements.environmentStatus.textContent = labels[status.state] || status.state;
  const failed = status.state === "failed" || status.state === "timedOut";
  elements.environmentStatus.className = `status ${status.state === "booting" ? "pending" : failed ? "failed" : ""}`;
  elements.startAppliance.classList.toggle("hidden", !hostReady || status.state === "booting" || status.state === "ready");
  elements.stopAppliance.classList.toggle("hidden", status.state === "stopped");
  if (status.state !== "booting" && statusTimer) {
    clearInterval(statusTimer);
    statusTimer = null;
  }
}

async function refreshApplianceStatus() {
  try { showApplianceStatus(await invoke("get_appliance_status")); }
  catch (error) { showApplianceStatus({ state: "failed", message: String(error) }); }
}

async function checkEnvironment() {
  try {
    const environment = await invoke("check_builder_environment");
    hostReady = environment.ready;
    elements.environmentTitle.textContent = environment.ready ? "Host prerequisites ready" : "Builder unavailable";
    elements.environmentMessage.textContent = environment.message;
    elements.environmentDetails.textContent = [environment.host_os, environment.host_arch, environment.qemu_version].filter(Boolean).join(" · ");
    elements.environmentStatus.textContent = environment.ready ? "Available" : "Unavailable";
    elements.environmentStatus.className = `status ${environment.ready ? "" : "failed"}`;
    elements.startAppliance.classList.toggle("hidden", !environment.ready);
    if (environment.ready) await refreshApplianceStatus();
  } catch (error) {
    elements.environmentTitle.textContent = "Environment check failed";
    elements.environmentMessage.textContent = String(error);
    elements.environmentStatus.textContent = "Failed";
    elements.environmentStatus.className = "status failed";
  }
}

elements.startAppliance.addEventListener("click", async () => {
  elements.startAppliance.disabled = true;
  try {
    showApplianceStatus(await invoke("start_appliance"));
    statusTimer ??= setInterval(refreshApplianceStatus, 1500);
  } catch (error) { showApplianceStatus({ state: "failed", message: String(error) }); }
  finally { elements.startAppliance.disabled = false; }
});

elements.stopAppliance.addEventListener("click", async () => {
  elements.stopAppliance.disabled = true;
  try { showApplianceStatus(await invoke("stop_appliance")); }
  catch (error) { showApplianceStatus({ state: "failed", message: String(error) }); }
  finally { elements.stopAppliance.disabled = false; }
});

async function selectImage(path) {
  try {
    const info = await invoke("validate_image", { path });
    currentImage = info.path;
    elements.selectedName.textContent = info.name;
    elements.selectedPath.textContent = info.path;
    elements.selectionStatus.textContent = "Recognized";
    elements.selectionCard.classList.remove("hidden");
    elements.buildCard.classList.remove("hidden");
    elements.resultMessage.textContent = "";
  } catch {
    currentImage = null;
    elements.selectedName.textContent = path.split(/[\\/]/).pop();
    elements.selectedPath.textContent = path;
    elements.selectionStatus.textContent = "Unsupported";
    elements.selectionCard.classList.remove("hidden");
    elements.buildCard.classList.add("hidden");
  }
}

elements.chooseImage.addEventListener("click", async () => {
  const selected = await open({ multiple: false, directory: false, filters: [{ name: "SteamOS recovery image", extensions: ["img", "bz2", "gz", "xz"] }] });
  if (typeof selected === "string") await selectImage(selected);
});
elements.openValve.addEventListener("click", () => openUrl("https://store.steampowered.com/steamos/download/?ver=steamdeck"));

elements.buildButton.addEventListener("click", async () => {
  if (!currentImage) return;
  elements.buildButton.disabled = true;
  elements.progressWrap.classList.remove("hidden");
  elements.resultMessage.textContent = "";
  for (const [label, progress] of [["Preparing builder…", 15], ["Checking SteamOS image…", 34], ["Preparing output…", 53], ["Simulating NVIDIA integration…", 72], ["Simulating Gamescope integration…", 88], ["Finalizing prototype…", 100]]) {
    elements.progressLabel.textContent = label;
    elements.progressBar.style.width = `${progress}%`;
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  try {
    const output = await invoke("prototype_build", { path: currentImage });
    elements.resultMessage.textContent = `Prototype created: ${output}`;
    elements.resultMessage.className = "result-message success";
    elements.progressLabel.textContent = "Prototype complete.";
  } catch (error) {
    elements.resultMessage.textContent = String(error);
    elements.resultMessage.className = "result-message error";
  } finally { elements.buildButton.disabled = false; }
});

await getCurrentWebviewWindow().onDragDropEvent(async (event) => {
  if (event.payload.type === "over") { elements.dropZone.classList.add("dragging"); return; }
  elements.dropZone.classList.remove("dragging");
  if (event.payload.type === "drop") {
    const [path] = event.payload.paths;
    if (path) await selectImage(path);
  }
});

await checkEnvironment();

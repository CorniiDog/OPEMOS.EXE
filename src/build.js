const { invoke } = window.__TAURI__.core;
const { getCurrentWebviewWindow } = window.__TAURI__.webviewWindow;

const $ = (selector) => document.querySelector(selector);
const elements = {
  inputName: $("#input-name"), statusTitle: $("#status-title"), statusMessage: $("#status-message"),
  statusBadge: $("#status-badge"), progressBar: $("#progress-bar"), buildLog: $("#build-log"),
  cancelBuild: $("#cancel-build"), closeWindow: $("#close-window"),
};
const progressWindow = getCurrentWebviewWindow();
let running = false;
let cancelling = false;
let stageLog = [];
let lastApplianceLog = "";

function setStatus(state, title, message, progress) {
  elements.statusTitle.textContent = title;
  elements.statusMessage.textContent = message;
  elements.statusBadge.textContent = state === "complete" ? "Complete" : state === "failed" ? "Failed" : state === "cancelled" ? "Cancelled" : "Working";
  elements.statusBadge.className = `status ${state === "complete" ? "" : state === "failed" || state === "cancelled" ? "failed" : "pending"}`;
  elements.progressBar.style.width = `${progress}%`;
}

function addStageLog(message) {
  stageLog.push(`[builder] ${message}`);
  renderLogs("");
}

function renderLogs(applianceLog) {
  if (applianceLog.trim()) lastApplianceLog = applianceLog.trim();
  elements.buildLog.textContent = [...stageLog, lastApplianceLog].filter(Boolean).join("\n");
  elements.buildLog.scrollTop = elements.buildLog.scrollHeight;
}

async function refreshLogs() {
  try { renderLogs(await invoke("read_appliance_log")); }
  catch (error) { addStageLog(`Could not refresh appliance log: ${error}`); }
}

async function finish(state, message) {
  running = false;
  elements.cancelBuild.disabled = true;
  elements.closeWindow.classList.remove("hidden");
  await progressWindow.emitTo("main", "build-finished", { state, message });
}

async function cancelBuild() {
  if (!running || cancelling) return;
  cancelling = true;
  elements.cancelBuild.disabled = true;
  setStatus("running", "Cancelling safely…", "Stopping the disposable builder appliance.", 90);
  addStageLog("Cancellation requested.");
  try { await invoke("stop_appliance"); }
  catch (error) { addStageLog(`Shutdown warning: ${error}`); }
  setStatus("cancelled", "Build cancelled", "The original image was not modified.", 100);
  addStageLog("Build cancelled; disposable session stopped.");
  await finish("cancelled", "Prototype build cancelled.");
  cancelling = false;
}

async function runBuild(request) {
  if (running) return;
  running = true;
  cancelling = false;
  stageLog = [];
  lastApplianceLog = "";
  elements.closeWindow.classList.add("hidden");
  elements.cancelBuild.disabled = false;
  elements.inputName.textContent = request.name;
  setStatus("running", "Preparing builder", "Creating an isolated Fedora session.", 8);
  addStageLog(`Input: ${request.path}`);

  let logTimer = null;
  try {
    const started = await invoke("start_appliance");
    addStageLog(`Appliance session created on local port ${started.sshPort}.`);
    setStatus("running", "Starting builder", "Waiting for the Fedora guest readiness handshake.", 22);
    logTimer = setInterval(refreshLogs, 750);

    while (!cancelling) {
      const status = await invoke("get_appliance_status");
      await refreshLogs();
      if (status.state === "ready") break;
      if (status.state === "failed" || status.state === "timedOut") throw new Error(status.message);
      await new Promise((resolve) => setTimeout(resolve, 750));
    }
    if (cancelling) return;

    addStageLog("STEAMOS_BUILDER_READY received.");
    setStatus("running", "Creating prototype output", "Validating the selected image and writing the prototype result.", 78);
    const output = await invoke("prototype_build", { path: request.path });
    addStageLog(`Prototype output created: ${output}`);
    setStatus("running", "Finalizing", "Stopping the disposable builder session.", 92);
    await invoke("stop_appliance");
    addStageLog("Builder session stopped.");
    setStatus("complete", "Prototype complete", "Finder opened the generated prototype output.", 100);
    await finish("complete", `Prototype created: ${output}`);
  } catch (error) {
    if (cancelling) return;
    addStageLog(`ERROR: ${error}`);
    try { await invoke("stop_appliance"); } catch (stopError) { addStageLog(`Shutdown warning: ${stopError}`); }
    setStatus("failed", "Build failed", String(error), 100);
    await finish("failed", `Prototype build failed: ${error}`);
  } finally {
    if (logTimer) clearInterval(logTimer);
    await refreshLogs();
  }
}

elements.cancelBuild.addEventListener("click", cancelBuild);
elements.closeWindow.addEventListener("click", () => progressWindow.hide());
await progressWindow.listen("build-requested", (event) => runBuild(event.payload));
await progressWindow.onCloseRequested(async (event) => {
  event.preventDefault();
  if (running) await cancelBuild();
  await progressWindow.hide();
});

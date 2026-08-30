const { invoke } = window.__TAURI__.core;
const { getAllWebviewWindows, getCurrentWebviewWindow } = window.__TAURI__.webviewWindow;
const open = (options) => invoke("plugin:dialog|open", { options });
const openUrl = (url) => invoke("plugin:opener|open_url", { url });

const $ = (selector) => document.querySelector(selector);
const elements = {
  dropZone: $("#drop-zone"), chooseImage: $("#choose-image"), openValve: $("#open-valve"),
  selectionCard: $("#selection-card"), selectedName: $("#selected-name"), selectedPath: $("#selected-path"),
  selectionStatus: $("#selection-status"), buildCard: $("#build-card"), buildButton: $("#build-button"),
  resultMessage: $("#result-message"), environmentTitle: $("#environment-title"),
  environmentMessage: $("#environment-message"), environmentDetails: $("#environment-details"),
  environmentStatus: $("#environment-status"),
};

let currentImage = null;
let currentImageName = null;
let hostReady = false;

function updateBuildButton() {
  elements.buildButton.disabled = !currentImage || !hostReady;
}

async function checkEnvironment() {
  try {
    const environment = await invoke("check_builder_environment");
    hostReady = environment.ready;
    elements.environmentTitle.textContent = environment.ready ? "Ready to build" : "Builder unavailable";
    elements.environmentMessage.textContent = environment.ready
      ? "The isolated builder will start automatically when you begin."
      : environment.message;
    elements.environmentDetails.textContent = [environment.host_os, environment.host_arch, environment.qemu_version].filter(Boolean).join(" · ");
    elements.environmentStatus.textContent = environment.ready ? "Available" : "Unavailable";
    elements.environmentStatus.className = `status ${environment.ready ? "" : "failed"}`;
  } catch (error) {
    hostReady = false;
    elements.environmentTitle.textContent = "Environment check failed";
    elements.environmentMessage.textContent = String(error);
    elements.environmentStatus.textContent = "Failed";
    elements.environmentStatus.className = "status failed";
  }
  updateBuildButton();
}

async function selectImage(path) {
  try {
    const info = await invoke("validate_image", { path });
    currentImage = info.path;
    currentImageName = info.name;
    elements.selectedName.textContent = info.name;
    elements.selectedPath.textContent = info.path;
    elements.selectionStatus.textContent = "Ready";
    elements.selectionStatus.className = "status";
    elements.selectionCard.classList.remove("hidden");
    elements.buildCard.classList.remove("hidden");
    elements.resultMessage.textContent = "";
  } catch (error) {
    currentImage = null;
    currentImageName = null;
    elements.selectedName.textContent = path.split(/[\\/]/).pop();
    elements.selectedPath.textContent = path;
    elements.selectionStatus.textContent = "Unsupported";
    elements.selectionStatus.className = "status failed";
    elements.selectionCard.classList.remove("hidden");
    elements.buildCard.classList.add("hidden");
    elements.resultMessage.textContent = String(error);
  }
  updateBuildButton();
}

elements.chooseImage.addEventListener("click", async () => {
  const selected = await open({ multiple: false, directory: false, filters: [{ name: "SteamOS recovery image", extensions: ["img", "bz2", "gz", "xz"] }] });
  if (typeof selected === "string") await selectImage(selected);
});

elements.openValve.addEventListener("click", () => openUrl("https://store.steampowered.com/steamos/download/?ver=steamdeck"));

elements.buildButton.addEventListener("click", async () => {
  if (!currentImage || !hostReady) return;
  elements.buildButton.disabled = true;
  elements.resultMessage.textContent = "Build progress opened in a separate window.";
  const windows = await getAllWebviewWindows();
  const progressWindow = windows.find((window) => window.label === "build-progress");
  if (!progressWindow) {
    elements.resultMessage.textContent = "The build progress window is unavailable.";
    elements.resultMessage.className = "result-message error";
    updateBuildButton();
    return;
  }
  await progressWindow.emit("build-requested", { path: currentImage, name: currentImageName });
  await progressWindow.show();
  await progressWindow.setFocus();
});

const mainWindow = getCurrentWebviewWindow();
await mainWindow.listen("build-finished", (event) => {
  const { state, message } = event.payload;
  elements.resultMessage.textContent = message;
  elements.resultMessage.className = `result-message ${state === "complete" ? "success" : state === "failed" ? "error" : ""}`;
  updateBuildButton();
});

await mainWindow.onDragDropEvent(async (event) => {
  if (event.payload.type === "over") { elements.dropZone.classList.add("dragging"); return; }
  elements.dropZone.classList.remove("dragging");
  if (event.payload.type === "drop") {
    const [path] = event.payload.paths;
    if (path) await selectImage(path);
  }
});

await checkEnvironment();

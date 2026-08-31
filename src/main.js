const { invoke } = window.__TAURI__.core;
const { getAllWebviewWindows, getCurrentWebviewWindow } = window.__TAURI__.webviewWindow;
const open = (options) => invoke("plugin:dialog|open", { options });
const openUrl = (url) => invoke("plugin:opener|open_url", { url });

const $ = (selector) => document.querySelector(selector);
const elements = {
  dropZone: $("#drop-zone"), chooseImage: $("#choose-image"), openValve: $("#open-valve"),
  dropTitle: $("#drop-title"), dropMessage: $("#drop-message"),
  selectionCard: $("#selection-card"), selectedName: $("#selected-name"), selectedPath: $("#selected-path"),
  selectionStatus: $("#selection-status"), buildCard: $("#build-card"), buildButton: $("#build-button"),
  nvidiaSource: $("#nvidia-source"),
  resultMessage: $("#result-message"), environmentTitle: $("#environment-title"),
  environmentMessage: $("#environment-message"), environmentDetails: $("#environment-details"),
  environmentStatus: $("#environment-status"),
  settingsButton: $("#settings-button"), settingsClose: $("#settings-close"),
  settingsPanel: $("#settings-panel"), settingsScrim: $("#settings-scrim"),
  trackDriverUpdates: $("#track-driver-updates"), autoReleaseNvidia: $("#auto-release-nvidia"),
  autoReleaseSetting: $("#auto-release-setting"), autoReleaseStatus: $("#auto-release-status"),
  githubStatus: $("#github-status"), githubConnect: $("#github-connect"),
  settingsMessage: $("#settings-message"),
};

let currentImage = null;
let currentImageName = null;
let hostReady = false;
let progressReady = false;
let builderSettings = {
  schemaVersion: 1,
  autoReleaseVerifiedNvidia: false,
  trackSteamosDriverUpdates: false,
};
let githubMaintainer = null;
let githubLoginPoll = 0;
let githubLoginPending = false;
let autoReleaseVerificationPending = false;
const mainWindow = getCurrentWebviewWindow();

await mainWindow.listen("build-progress-ready", () => { progressReady = true; });

async function waitForProgressWindow(progressWindow) {
  progressReady = false;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    await progressWindow.emit("build-progress-probe");
    await new Promise((resolve) => setTimeout(resolve, 100));
    if (progressReady) return;
  }
  throw new Error("The build progress window did not become ready.");
}

function updateBuildButton() {
  elements.buildButton.disabled = !currentImage || !hostReady;
}

function renderSettings() {
  elements.trackDriverUpdates.checked = builderSettings.trackSteamosDriverUpdates;
  elements.autoReleaseNvidia.checked = builderSettings.autoReleaseVerifiedNvidia;
  elements.autoReleaseNvidia.disabled = autoReleaseVerificationPending || !githubMaintainer?.authorized;
  elements.autoReleaseSetting.classList.toggle("pending", autoReleaseVerificationPending);
  elements.githubStatus.textContent = githubMaintainer?.message || "GitHub status has not been checked.";
  elements.githubConnect.textContent = githubLoginPending
    ? "Waiting for GitHub…"
    : (githubMaintainer?.authenticated ? "Reconnect" : "Connect GitHub");
}

async function refreshGithubMaintainer() {
  elements.githubStatus.textContent = "Checking GitHub authentication and repository permission…";
  try {
    githubMaintainer = await invoke("get_github_maintainer_status");
  } catch (error) {
    githubMaintainer = null;
    elements.settingsMessage.textContent = String(error);
    elements.settingsMessage.className = "settings-message error";
  }
  renderSettings();
}

async function pollGithubMaintainer(poll) {
  for (let attempt = 1; attempt <= 150 && poll === githubLoginPoll; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    if (poll !== githubLoginPoll) return;
    try {
      githubMaintainer = await invoke("get_github_maintainer_status");
      renderSettings();
      if (githubMaintainer.authenticated) {
        githubLoginPending = false;
        elements.settingsMessage.textContent = githubMaintainer.authorized
          ? "Maintainer permission verified."
          : "GitHub connected, but this account cannot publish to the support repository.";
        elements.settingsMessage.className = githubMaintainer.authorized ? "settings-message" : "settings-message error";
        elements.githubConnect.disabled = false;
        renderSettings();
        return;
      }
      elements.settingsMessage.textContent = `Waiting for GitHub authorization… ${attempt * 2}s`;
    } catch (error) {
      elements.settingsMessage.textContent = `Waiting for GitHub authorization: ${String(error)}`;
      elements.settingsMessage.className = "settings-message error";
    }
  }
  if (poll === githubLoginPoll) {
    githubLoginPending = false;
    elements.githubConnect.disabled = false;
    elements.settingsMessage.textContent = "GitHub login is still pending. Finish it in Terminal, then reconnect to check again.";
    elements.settingsMessage.className = "settings-message error";
    renderSettings();
  }
}

async function loadSettings() {
  try {
    builderSettings = await invoke("get_builder_settings");
    elements.settingsMessage.textContent = "Settings are saved automatically.";
    elements.settingsMessage.className = "settings-message";
  } catch (error) {
    elements.settingsMessage.textContent = String(error);
    elements.settingsMessage.className = "settings-message error";
  }
  renderSettings();
}

async function saveSettings(next) {
  const previous = builderSettings;
  builderSettings = { ...builderSettings, ...next, schemaVersion: 1 };
  renderSettings();
  try {
    builderSettings = await invoke("update_builder_settings", { settings: builderSettings });
    elements.settingsMessage.textContent = "Settings saved.";
    elements.settingsMessage.className = "settings-message";
  } catch (error) {
    builderSettings = previous;
    elements.settingsMessage.textContent = String(error);
    elements.settingsMessage.className = "settings-message error";
  }
  renderSettings();
}

function setSettingsOpen(opened) {
  elements.settingsPanel.classList.toggle("hidden", !opened);
  elements.settingsScrim.classList.toggle("hidden", !opened);
  elements.settingsButton.setAttribute("aria-expanded", String(opened));
  if (opened) refreshGithubMaintainer();
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

async function loadNvidiaSourceBranches() {
  elements.nvidiaSource.disabled = true;
  try {
    const branches = await invoke("list_nvidia_source_branches");
    for (const branch of branches) {
      const option = document.createElement("option");
      option.value = branch.name;
      option.textContent = `${branch.version} · ${branch.commit.slice(0, 12)}`;
      elements.nvidiaSource.append(option);
    }
  } catch (error) {
    elements.resultMessage.textContent = `Could not load optional NVIDIA branches: ${error}`;
  } finally {
    elements.nvidiaSource.disabled = false;
  }
}

async function selectImage(path) {
  elements.dropZone.classList.add("processing");
  elements.chooseImage.disabled = true;
  elements.dropTitle.textContent = "Checking selected image…";
  elements.dropMessage.textContent = "Validating the file path and supported format.";
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
  } finally {
    elements.dropZone.classList.remove("processing");
    elements.chooseImage.disabled = false;
    elements.dropTitle.textContent = currentImage ? "SteamOS image selected" : "Drop SteamOS recovery image here";
    elements.dropMessage.textContent = currentImage ? "Review it below, then build a separate validated image." : ".img, .img.bz2, .img.gz, or .img.xz";
  }
  updateBuildButton();
}

elements.chooseImage.addEventListener("click", async () => {
  const selected = await open({ multiple: false, directory: false, filters: [{ name: "SteamOS recovery image", extensions: ["img", "bz2", "gz", "xz"] }] });
  if (typeof selected === "string") await selectImage(selected);
});

elements.openValve.addEventListener("click", () => openUrl("https://store.steampowered.com/steamos/download/?ver=steamdeck"));

elements.settingsButton.addEventListener("click", () => setSettingsOpen(true));
elements.settingsClose.addEventListener("click", () => setSettingsOpen(false));
elements.settingsScrim.addEventListener("click", () => setSettingsOpen(false));
elements.trackDriverUpdates.addEventListener("change", () => saveSettings({
  trackSteamosDriverUpdates: elements.trackDriverUpdates.checked,
}));
elements.autoReleaseNvidia.addEventListener("change", async () => {
  const previous = builderSettings;
  const enabled = elements.autoReleaseNvidia.checked;
  builderSettings = { ...builderSettings, autoReleaseVerifiedNvidia: enabled, schemaVersion: 1 };
  autoReleaseVerificationPending = true;
  elements.autoReleaseStatus.textContent = enabled ? "Checking maintainer permission…" : "Saving…";
  elements.autoReleaseStatus.className = "setting-status";
  renderSettings();
  try {
    builderSettings = await invoke("update_builder_settings", { settings: builderSettings });
    elements.autoReleaseStatus.textContent = enabled ? "Confirmed" : "Disabled";
    elements.autoReleaseStatus.className = enabled ? "setting-status confirmed" : "setting-status";
  } catch (error) {
    builderSettings = previous;
    elements.autoReleaseStatus.textContent = String(error);
    elements.autoReleaseStatus.className = "setting-status error";
  } finally {
    autoReleaseVerificationPending = false;
    renderSettings();
  }
});
elements.githubConnect.addEventListener("click", async () => {
  const poll = ++githubLoginPoll;
  githubLoginPending = true;
  elements.githubConnect.disabled = true;
  renderSettings();
  elements.settingsMessage.textContent = "Opening a visible GitHub login in Terminal…";
  elements.settingsMessage.className = "settings-message";
  try {
    githubMaintainer = await invoke("connect_github_maintainer");
    renderSettings();
    elements.githubConnect.disabled = true;
    elements.settingsMessage.textContent = githubMaintainer.message;
    void pollGithubMaintainer(poll);
  } catch (error) {
    githubLoginPending = false;
    elements.settingsMessage.textContent = String(error);
    elements.settingsMessage.className = "settings-message error";
    elements.githubConnect.disabled = false;
    renderSettings();
  }
});

elements.buildButton.addEventListener("click", async () => {
  if (!currentImage || !hostReady) return;
  elements.buildButton.disabled = true;
  elements.resultMessage.textContent = "Build progress opened in a separate window.";
  try {
    await invoke("open_progress_window");
    const windows = await getAllWebviewWindows();
    const progressWindow = windows.find((window) => window.label === "build-progress");
    if (!progressWindow) throw new Error("The build progress window is unavailable.");
    await waitForProgressWindow(progressWindow);
    await progressWindow.emit("build-requested", {
      path: currentImage,
      name: currentImageName,
      sourceSelection: elements.nvidiaSource.value,
    });
  } catch (error) {
    elements.resultMessage.textContent = String(error);
    elements.resultMessage.className = "result-message error";
    updateBuildButton();
  }
});

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

const header = document.querySelector("header");
const downloadCard = document.querySelector(".download-card");
const environmentCard = document.querySelector(".environment-card");
header.after(downloadCard);
elements.dropZone.after(environmentCard);
environmentCard.after(elements.selectionCard);
elements.selectionCard.after(elements.buildCard);
await checkEnvironment();
await loadSettings();
await loadNvidiaSourceBranches();

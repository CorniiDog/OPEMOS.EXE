import { operationContextMatches } from "./operation-context.js";

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
  exportMode: $("#export-mode"),
  nvidiaSource: $("#nvidia-source"), upstreamWarning: $("#upstream-warning"),
  allowUpstreamBuild: $("#allow-upstream-build"),
  summaryInput: $("#summary-input"), summaryOutput: $("#summary-output"),
  summaryAction: $("#summary-action"),
  resultMessage: $("#result-message"), environmentTitle: $("#environment-title"),
  usbCard: $("#usb-card"), usbTarget: $("#usb-target"),
  usbTargetDetail: $("#usb-target-detail"), refreshUsbTargets: $("#refresh-usb-targets"),
  usbMessage: $("#usb-message"), usbConfirmationRow: $("#usb-confirmation-row"),
  usbConfirmation: $("#usb-confirmation"), usbConfirmationHelp: $("#usb-confirmation-help"),
  armUsbPreflight: $("#arm-usb-preflight"), cancelUsbPreflight: $("#cancel-usb-preflight"),
  checkUsbPreflight: $("#check-usb-preflight"), writeUsbImage: $("#write-usb-image"),
  closeUsbMenu: $("#close-usb-menu"), reviewUsbTarget: $("#review-usb-target"),
  environmentMessage: $("#environment-message"), environmentDetails: $("#environment-details"),
  environmentStatus: $("#environment-status"),
  settingsButton: $("#settings-button"), settingsClose: $("#settings-close"),
  settingsPanel: $("#settings-panel"), settingsScrim: $("#settings-scrim"),
  trackDriverUpdates: $("#track-driver-updates"), includeUpstreamNvidia: $("#include-upstream-nvidia"),
  omitOptionalCuda: $("#omit-optional-cuda"), omitCudaStatus: $("#omit-cuda-status"),
  autoReleaseNvidia: $("#auto-release-nvidia"),
  autoReleaseSetting: $("#auto-release-setting"), autoReleaseStatus: $("#auto-release-status"),
  githubStatus: $("#github-status"), githubConnect: $("#github-connect"),
  openMaintainer: $("#open-maintainer"),
  settingsMessage: $("#settings-message"),
};

let currentImage = null;
let currentImageName = null;
let plannedOutput = null;
let completedOutput = null;
let usbPreflightSession = null;
let usbContextGeneration = 0;
let usbArmPending = false;
let usbWriting = false;
let buildRunning = false;
let activeExportMode = "image";
let hostReady = false;
let progressReady = false;
let builderSettings = {
  schemaVersion: 3,
  autoReleaseVerifiedNvidia: false,
  trackSteamosDriverUpdates: false,
  includeUpstreamNvidiaReleases: false,
  omitOptionalCuda: false,
};
let githubMaintainer = null;
let githubLoginPoll = 0;
let githubLoginPending = false;
let autoReleaseVerificationPending = false;
let settingsSavePending = false;
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
  const upstreamSelected = elements.nvidiaSource.value.startsWith("upstream:");
  const usbTargetRequired = elements.exportMode.value !== "image";
  elements.buildButton.disabled = buildRunning || usbWriting || !currentImage || !hostReady
    || (usbTargetRequired && !elements.usbTarget.value)
    || (upstreamSelected && !elements.allowUpstreamBuild.checked);
}

function renderExportMode() {
  const usbRequested = elements.exportMode.value !== "image";
  elements.reviewUsbTarget.classList.toggle("hidden", !usbRequested || !currentImage);
  if (!usbRequested || !currentImage) elements.usbCard.classList.add("hidden");
  if (usbRequested && !completedOutput?.path && !elements.usbTarget.value) {
    elements.usbMessage.textContent = "Select a removable target now. Its identity and final capacity will be checked again after the build.";
  }
  renderSourceWarning();
}

function renderSourceWarning() {
  const upstreamSelected = elements.nvidiaSource.value.startsWith("upstream:");
  elements.upstreamWarning.classList.toggle("hidden", !upstreamSelected);
  if (!upstreamSelected) elements.allowUpstreamBuild.checked = false;
  const selectedLabel = elements.nvidiaSource.selectedOptions[0]?.textContent || "Automatic";
  const sourceSummary = upstreamSelected
    ? `${selectedLabel} will be built only after its exact source and userspace inputs pass validation.`
    : `${selectedLabel} will prefer an exact trusted release, then use the isolated x86_64 builder when required.`;
  const destination = elements.exportMode.selectedOptions[0]?.textContent || "Export as image";
  elements.summaryAction.textContent = `${sourceSummary} Destination: ${destination}.`;
  updateBuildButton();
}

function waitForPaint() {
  return new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
}

function renderSettings() {
  elements.trackDriverUpdates.checked = builderSettings.trackSteamosDriverUpdates;
  elements.trackDriverUpdates.disabled = settingsSavePending;
  elements.includeUpstreamNvidia.checked = builderSettings.includeUpstreamNvidiaReleases;
  elements.includeUpstreamNvidia.disabled = settingsSavePending;
  elements.omitOptionalCuda.checked = builderSettings.omitOptionalCuda;
  elements.omitOptionalCuda.disabled = true;
  elements.omitCudaStatus.textContent = "Unavailable for current builds — the complete NVIDIA driver will be used.";
  elements.autoReleaseNvidia.checked = builderSettings.autoReleaseVerifiedNvidia;
  elements.autoReleaseNvidia.disabled = settingsSavePending || !githubMaintainer?.authorized;
  elements.autoReleaseSetting.classList.toggle("pending", autoReleaseVerificationPending);
  elements.githubStatus.textContent = githubMaintainer?.message || "GitHub status has not been checked.";
  elements.githubConnect.textContent = githubLoginPending
    ? "Waiting for GitHub…"
    : (githubMaintainer?.authenticated ? "Reconnect" : "Connect GitHub");
  elements.openMaintainer.disabled = !githubMaintainer?.authorized;
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
  builderSettings = { ...builderSettings, ...next, schemaVersion: 3 };
  settingsSavePending = true;
  elements.settingsMessage.textContent = "Saving…";
  elements.settingsMessage.className = "settings-message";
  renderSettings();
  try {
    await waitForPaint();
    builderSettings = await invoke("update_builder_settings", { settings: builderSettings });
    elements.settingsMessage.textContent = "Settings saved.";
    elements.settingsMessage.className = "settings-message";
  } catch (error) {
    builderSettings = previous;
    elements.settingsMessage.textContent = String(error);
    elements.settingsMessage.className = "settings-message error";
  } finally {
    settingsSavePending = false;
    renderSettings();
  }
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
  const previous = elements.nvidiaSource.value;
  elements.nvidiaSource.disabled = true;
  elements.nvidiaSource.querySelectorAll("optgroup").forEach((group) => group.remove());
  try {
    const branches = await invoke("list_nvidia_source_branches");
    const project = document.createElement("optgroup");
    project.label = "Project-supported branches";
    const upstream = document.createElement("optgroup");
    upstream.label = "Experimental NVIDIA upstream tags";
    for (const branch of branches) {
      const option = document.createElement("option");
      option.value = branch.selection;
      option.textContent = `${branch.version} · ${branch.commit.slice(0, 12)}`;
      (branch.experimental ? upstream : project).append(option);
    }
    if (project.children.length) elements.nvidiaSource.append(project);
    if (upstream.children.length) elements.nvidiaSource.append(upstream);
    if ([...elements.nvidiaSource.options].some((option) => option.value === previous)) {
      elements.nvidiaSource.value = previous;
    } else {
      elements.nvidiaSource.value = "automatic";
    }
  } catch (error) {
    elements.resultMessage.textContent = `Could not load optional NVIDIA branches: ${error}`;
  } finally {
    elements.nvidiaSource.disabled = false;
    renderSourceWarning();
  }
}

async function selectImage(path) {
  usbContextGeneration += 1;
  if (usbPreflightSession) {
    await invoke("cancel_usb_write_preflight", { sessionToken: usbPreflightSession.sessionToken }).catch(() => {});
  }
  completedOutput = null;
  usbPreflightSession = null;
  elements.usbCard.classList.add("hidden");
  elements.usbTarget.replaceChildren(new Option("No target selected", ""));
  elements.usbTarget.disabled = true;
  elements.usbTargetDetail.textContent = "Connect a USB drive, then refresh.";
  elements.usbMessage.textContent = "";
  elements.usbConfirmationRow.classList.add("hidden");
  elements.armUsbPreflight.classList.add("hidden");
  elements.cancelUsbPreflight.classList.add("hidden");
  elements.checkUsbPreflight.classList.add("hidden");
  elements.writeUsbImage.classList.add("hidden");
  elements.dropZone.classList.add("processing");
  elements.chooseImage.disabled = true;
  elements.dropTitle.textContent = "Checking selected image…";
  elements.dropMessage.textContent = "Validating the file path and supported format.";
  try {
    const info = await invoke("validate_image", { path });
    const preview = await invoke("preview_image_output", { path: info.path });
    currentImage = info.path;
    currentImageName = info.name;
    plannedOutput = preview.output_path;
    elements.selectedName.textContent = info.name;
    elements.selectedPath.textContent = info.path;
    elements.summaryInput.textContent = preview.input_path;
    elements.summaryInput.title = preview.input_path;
    elements.summaryOutput.textContent = preview.output_path;
    elements.summaryOutput.title = preview.output_path;
    elements.selectionStatus.textContent = "Ready";
    elements.selectionStatus.className = "status";
    elements.selectionCard.classList.remove("hidden");
    elements.buildCard.classList.remove("hidden");
    elements.resultMessage.textContent = "";
  } catch (error) {
    currentImage = null;
    currentImageName = null;
    plannedOutput = null;
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
  renderExportMode();
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
elements.includeUpstreamNvidia.addEventListener("change", async () => {
  await saveSettings({
    includeUpstreamNvidiaReleases: elements.includeUpstreamNvidia.checked,
  });
  await loadNvidiaSourceBranches();
});
elements.nvidiaSource.addEventListener("change", renderSourceWarning);
elements.allowUpstreamBuild.addEventListener("change", updateBuildButton);
elements.autoReleaseNvidia.addEventListener("change", async () => {
  const previous = builderSettings;
  const enabled = elements.autoReleaseNvidia.checked;
  builderSettings = { ...builderSettings, autoReleaseVerifiedNvidia: enabled, schemaVersion: 3 };
  autoReleaseVerificationPending = true;
  settingsSavePending = true;
  elements.autoReleaseStatus.textContent = enabled ? "Checking maintainer permission…" : "Saving…";
  elements.autoReleaseStatus.className = "setting-status";
  renderSettings();
  try {
    await waitForPaint();
    builderSettings = await invoke("update_builder_settings", { settings: builderSettings });
    elements.autoReleaseStatus.textContent = enabled ? "Confirmed" : "Disabled";
    elements.autoReleaseStatus.className = enabled ? "setting-status confirmed" : "setting-status";
  } catch (error) {
    builderSettings = previous;
    elements.autoReleaseStatus.textContent = String(error);
    elements.autoReleaseStatus.className = "setting-status error";
  } finally {
    autoReleaseVerificationPending = false;
    settingsSavePending = false;
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

elements.openMaintainer.addEventListener("click", async () => {
  elements.openMaintainer.disabled = true;
  elements.settingsMessage.textContent = "Rechecking permission and opening the maintainer workspace…";
  elements.settingsMessage.className = "settings-message";
  try {
    await waitForPaint();
    await invoke("open_maintainer_window");
    setSettingsOpen(false);
  } catch (error) {
    elements.settingsMessage.textContent = String(error);
    elements.settingsMessage.className = "settings-message error";
  } finally {
    renderSettings();
  }
});

elements.buildButton.addEventListener("click", async () => {
  if (!currentImage || !hostReady) return;
  elements.buildButton.disabled = true;
  buildRunning = true;
  activeExportMode = elements.exportMode.value;
  elements.exportMode.disabled = true;
  elements.resultMessage.textContent = "Build progress opened in a separate window.";
  try {
    const preview = await invoke("preview_image_output", { path: currentImage });
    plannedOutput = preview.output_path;
    elements.summaryOutput.textContent = plannedOutput;
    elements.summaryOutput.title = plannedOutput;
    await invoke("open_progress_window");
    const windows = await getAllWebviewWindows();
    const progressWindow = windows.find((window) => window.label === "build-progress");
    if (!progressWindow) throw new Error("The build progress window is unavailable.");
    await waitForProgressWindow(progressWindow);
    await progressWindow.emit("build-requested", {
      path: currentImage,
      name: currentImageName,
      sourceSelection: elements.nvidiaSource.value,
      allowExperimentalUpstream: elements.nvidiaSource.value.startsWith("upstream:")
        && elements.allowUpstreamBuild.checked,
      exportMode: activeExportMode,
    });
  } catch (error) {
    elements.resultMessage.textContent = String(error);
    elements.resultMessage.className = "result-message error";
    buildRunning = false;
    elements.exportMode.disabled = false;
    updateBuildButton();
  }
});

await mainWindow.listen("build-finished", (event) => {
  const { state, message, output, inputPath } = event.payload;
  elements.resultMessage.textContent = message;
  elements.resultMessage.className = `result-message ${state === "complete" ? "success" : state === "failed" ? "error" : ""}`;
  buildRunning = false;
  elements.exportMode.disabled = false;
  updateBuildButton();
  if (state === "complete" && output?.path && inputPath === currentImage) {
    usbContextGeneration += 1;
    completedOutput = output;
    if (activeExportMode !== "image") {
      elements.usbCard.classList.remove("hidden");
      elements.usbMessage.textContent = "The image is ready. Refresh and reconfirm the selected removable drive before writing.";
    }
  }
});

elements.refreshUsbTargets.addEventListener("click", async () => {
  if (!completedOutput?.path && !currentImage) return;
  usbContextGeneration += 1;
  const generation = usbContextGeneration;
  const imagePath = completedOutput?.path || currentImage;
  if (usbPreflightSession) {
    await invoke("cancel_usb_write_preflight", { sessionToken: usbPreflightSession.sessionToken }).catch(() => {});
    usbPreflightSession = null;
  }
  elements.cancelUsbPreflight.classList.add("hidden");
  elements.checkUsbPreflight.classList.add("hidden");
  elements.refreshUsbTargets.disabled = true;
  elements.usbTarget.disabled = true;
  elements.usbMessage.textContent = "Inspecting whole external physical disks without opening them for writing…";
  elements.usbMessage.className = "result-message";
  try {
    const preflight = completedOutput?.path
      ? await invoke("inspect_usb_targets", { imagePath })
      : await invoke("inspect_usb_targets_for_build", { inputPath: imagePath });
    if (generation !== usbContextGeneration || (completedOutput?.path || currentImage) !== imagePath) return;
    elements.usbTarget.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = preflight.targets.length ? "Select a removable drive for review" : "No eligible removable drives found";
    elements.usbTarget.append(placeholder);
    for (const target of preflight.targets) {
      const option = document.createElement("option");
      option.value = target.deviceIdentifier;
      option.textContent = `${target.mediaName} · ${target.deviceNode} · ${(target.bytes / 1_000_000_000).toFixed(1)} GB`;
      option.dataset.detail = `${target.busProtocol}; whole physical removable disk; ${completedOutput?.path ? "final capacity eligible" : "capacity rechecked after build"}`;
      option.dataset.identityToken = target.identityToken;
      option.dataset.bytes = String(target.bytes);
      elements.usbTarget.append(option);
    }
    elements.usbTarget.disabled = !preflight.targets.length;
    elements.usbMessage.textContent = preflight.message;
  } catch (error) {
    if (generation !== usbContextGeneration) return;
    elements.usbMessage.textContent = String(error);
    elements.usbMessage.className = "result-message error";
  } finally {
    if (generation === usbContextGeneration) elements.refreshUsbTargets.disabled = false;
  }
});

elements.usbTarget.addEventListener("change", async () => {
  usbContextGeneration += 1;
  if (usbPreflightSession) {
    await invoke("cancel_usb_write_preflight", { sessionToken: usbPreflightSession.sessionToken }).catch(() => {});
  }
  usbPreflightSession = null;
  elements.cancelUsbPreflight.classList.add("hidden");
  elements.checkUsbPreflight.classList.add("hidden");
  elements.writeUsbImage.classList.add("hidden");
  elements.usbConfirmation.value = "";
  const identifier = elements.usbTarget.value;
  const canConfirm = Boolean(identifier && completedOutput?.path);
  elements.usbConfirmationRow.classList.toggle("hidden", !canConfirm);
  elements.armUsbPreflight.classList.toggle("hidden", !canConfirm);
  elements.armUsbPreflight.disabled = true;
  elements.usbConfirmationHelp.textContent = canConfirm
    ? `Type ERASE ${identifier} exactly. A final warning still appears before writing.`
    : "Select a target first.";
  elements.usbTargetDetail.textContent = elements.usbTarget.selectedOptions[0]?.dataset.detail
    || "Connect a USB drive, then refresh.";
  if (identifier && !completedOutput?.path) {
    elements.usbMessage.textContent = "Target selected for this build. After export, refresh and confirm it again before any write begins.";
  }
  updateBuildButton();
});

elements.usbConfirmation.addEventListener("input", () => {
  elements.armUsbPreflight.disabled = usbArmPending
    || elements.usbConfirmation.value !== `ERASE ${elements.usbTarget.value}`;
});

elements.armUsbPreflight.addEventListener("click", async () => {
  const option = elements.usbTarget.selectedOptions[0];
  if (usbArmPending || !completedOutput?.path || !option?.value || !option.dataset.identityToken) return;
  const generation = usbContextGeneration;
  const imagePath = completedOutput.path;
  const deviceIdentifier = option.value;
  const identityToken = option.dataset.identityToken;
  const confirmation = elements.usbConfirmation.value;
  usbArmPending = true;
  elements.armUsbPreflight.disabled = true;
  elements.usbMessage.textContent = "Rehashing the image and immediately revalidating the selected disk identity…";
  elements.usbMessage.className = "result-message";
  try {
    const session = await invoke("arm_usb_write_preflight", {
      imagePath,
      deviceIdentifier,
      identityToken,
      confirmation,
    });
    const currentOption = elements.usbTarget.selectedOptions[0];
    if (!operationContextMatches(
      { generation, imagePath, deviceIdentifier, identityToken, confirmation },
      {
        generation: usbContextGeneration,
        imagePath: completedOutput?.path,
        deviceIdentifier: currentOption?.value,
        identityToken: currentOption?.dataset.identityToken,
        confirmation: elements.usbConfirmation.value,
      },
    )) {
      await invoke("cancel_usb_write_preflight", { sessionToken: session.sessionToken }).catch(() => {});
      return;
    }
    usbPreflightSession = session;
    elements.usbMessage.textContent = usbPreflightSession.message;
    elements.cancelUsbPreflight.classList.remove("hidden");
    elements.checkUsbPreflight.classList.remove("hidden");
    elements.writeUsbImage.classList.toggle("hidden", !usbPreflightSession.writesAllowed);
  } catch (error) {
    if (generation !== usbContextGeneration) return;
    usbPreflightSession = null;
    elements.usbMessage.textContent = String(error);
    elements.usbMessage.className = "result-message error";
  } finally {
    usbArmPending = false;
    if (generation === usbContextGeneration) {
      elements.armUsbPreflight.disabled = elements.usbConfirmation.value !== `ERASE ${elements.usbTarget.value}`;
    }
  }
});

elements.checkUsbPreflight.addEventListener("click", async () => {
  if (!usbPreflightSession?.sessionToken) return;
  const context = {
    generation: usbContextGeneration,
    imagePath: completedOutput?.path,
    sessionToken: usbPreflightSession.sessionToken,
  };
  elements.checkUsbPreflight.disabled = true;
  try {
    const status = await invoke("get_usb_write_preflight_status", {
      sessionToken: context.sessionToken,
    });
    if (!operationContextMatches(context, {
      generation: usbContextGeneration,
      imagePath: completedOutput?.path,
      sessionToken: usbPreflightSession?.sessionToken,
    })) return;
    const identityMatches =
      status.deviceIdentifier === usbPreflightSession.deviceIdentifier &&
      status.imageSha256 === usbPreflightSession.imageSha256 &&
      status.identityToken === usbPreflightSession.identityToken;
    if (status.active && !identityMatches) {
      usbPreflightSession = null;
      elements.checkUsbPreflight.classList.add("hidden");
      elements.cancelUsbPreflight.classList.add("hidden");
      elements.writeUsbImage.classList.add("hidden");
      elements.usbMessage.textContent = "USB intent status no longer matches the confirmed device and image. Revalidate before continuing.";
      elements.usbMessage.className = "result-message error";
      return;
    }
    const remaining = status.active ? ` ${Math.ceil(Number(status.expiresInMs) / 1000)} seconds remain.` : "";
    const identity = status.deviceIdentifier && status.imageSha256
      ? ` Target /dev/${status.deviceIdentifier}; image SHA-256 ${status.imageSha256.slice(0, 12)}….`
      : "";
    elements.usbMessage.textContent = `${status.message}${identity}${remaining}`;
    elements.usbMessage.className = "result-message";
    if (!status.active) {
      usbPreflightSession = null;
      elements.checkUsbPreflight.classList.add("hidden");
      elements.cancelUsbPreflight.classList.add("hidden");
      elements.writeUsbImage.classList.add("hidden");
    }
  } catch (error) {
    if (!operationContextMatches(context, {
      generation: usbContextGeneration,
      imagePath: completedOutput?.path,
      sessionToken: usbPreflightSession?.sessionToken,
    })) return;
    elements.usbMessage.textContent = String(error);
    elements.usbMessage.className = "result-message error";
  } finally {
    if (context.generation === usbContextGeneration
      && context.sessionToken === usbPreflightSession?.sessionToken) {
      elements.checkUsbPreflight.disabled = false;
    }
  }
});

elements.cancelUsbPreflight.addEventListener("click", async () => {
  if (!usbPreflightSession?.sessionToken) return;
  const context = {
    generation: usbContextGeneration,
    imagePath: completedOutput?.path,
    sessionToken: usbPreflightSession.sessionToken,
  };
  let cancellationCompleted = false;
  try {
    const result = await invoke("cancel_usb_write_preflight", { sessionToken: context.sessionToken });
    if (!operationContextMatches(context, {
      generation: usbContextGeneration,
      imagePath: completedOutput?.path,
      sessionToken: usbPreflightSession?.sessionToken,
    })) return;
    cancellationCompleted = true;
    elements.usbMessage.textContent = result.cancelled
      ? (result.status === "cancellation-requested"
        ? "Cancellation requested. The writer will stop at the next safe block boundary; this device must be rewritten before use."
        : "USB preparation cancelled. No disk was opened or changed.")
      : "No matching USB preparation was active; no disk was opened or changed.";
    elements.usbMessage.className = "result-message";
  } catch (error) {
    if (!operationContextMatches(context, {
      generation: usbContextGeneration,
      imagePath: completedOutput?.path,
      sessionToken: usbPreflightSession?.sessionToken,
    })) return;
    elements.usbMessage.textContent = `Could not confirm USB preparation cancellation: ${error}`;
    elements.usbMessage.className = "result-message error";
  } finally {
    if (cancellationCompleted && operationContextMatches(context, {
      generation: usbContextGeneration,
      imagePath: completedOutput?.path,
      sessionToken: usbPreflightSession?.sessionToken,
    })) {
      usbPreflightSession = null;
      elements.cancelUsbPreflight.classList.add("hidden");
      elements.checkUsbPreflight.classList.add("hidden");
      elements.writeUsbImage.classList.add("hidden");
      elements.armUsbPreflight.disabled = elements.usbConfirmation.value !== `ERASE ${elements.usbTarget.value}`;
    }
  }
});

elements.exportMode.addEventListener("change", renderExportMode);
elements.exportMode.addEventListener("change", () => {
  if (elements.exportMode.value !== "image" && currentImage) {
    elements.usbCard.classList.remove("hidden");
  }
});
elements.reviewUsbTarget.addEventListener("click", () => {
  if (currentImage && elements.exportMode.value !== "image") {
    elements.usbCard.classList.remove("hidden");
  }
});
elements.closeUsbMenu.addEventListener("click", () => elements.usbCard.classList.add("hidden"));

await mainWindow.listen("usb-write-progress", (event) => {
  if (!usbWriting) return;
  const progress = event.payload;
  const ratio = progress.bytesTotal > 0 ? progress.bytesCompleted / progress.bytesTotal : 0;
  elements.usbMessage.textContent = `${progress.message} ${(ratio * 100).toFixed(1)}%`;
  elements.usbMessage.className = "result-message";
});

elements.writeUsbImage.addEventListener("click", async () => {
  if (usbWriting || !usbPreflightSession?.sessionToken || !completedOutput?.path) return;
  const device = usbPreflightSession.deviceNode;
  if (!window.confirm(`FINAL WARNING\n\nErase ${device} and write the validated SteamOS image?\n\nEvery existing partition and file on this device will be destroyed.`)) return;
  usbWriting = true;
  elements.writeUsbImage.disabled = true;
  elements.refreshUsbTargets.disabled = true;
  elements.checkUsbPreflight.disabled = true;
  elements.buildButton.disabled = true;
  elements.usbMessage.textContent = "Unmounting and revalidating the selected removable disk…";
  try {
    const result = await invoke("write_image_to_usb", {
      sessionToken: usbPreflightSession.sessionToken,
      imagePath: completedOutput.path,
    });
    usbPreflightSession = null;
    elements.usbMessage.textContent = result.message;
    elements.usbMessage.className = "result-message success";
    elements.writeUsbImage.classList.add("hidden");
    elements.checkUsbPreflight.classList.add("hidden");
    elements.cancelUsbPreflight.classList.add("hidden");
  } catch (error) {
    usbPreflightSession = null;
    elements.usbMessage.textContent = String(error);
    elements.usbMessage.className = "result-message error";
    elements.writeUsbImage.classList.add("hidden");
    elements.checkUsbPreflight.classList.add("hidden");
    elements.cancelUsbPreflight.classList.add("hidden");
  } finally {
    usbWriting = false;
    elements.writeUsbImage.disabled = false;
    elements.refreshUsbTargets.disabled = false;
    elements.checkUsbPreflight.disabled = false;
    updateBuildButton();
  }
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
elements.buildCard.after(elements.usbCard);
await checkEnvironment();
await loadSettings();
await loadNvidiaSourceBranches();

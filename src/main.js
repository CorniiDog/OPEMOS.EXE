import { installCompatibilityPreview } from "./compatibility-preview.js";
import { presentHostEnvironment } from "./host-status.js";
import { buildCompletionMatches, operationContextMatches } from "./operation-context.js";
import {
  admitBuildStart,
  admitImageSelection,
  admitUsbWriteStart,
  deriveBuildAdmission,
} from "./workflow-state.js";
import { installWindowDrag } from "./window-drag.js";
import {
  installKeyboardBindings,
  keepKeyboardFocusInside,
  runKeyboardDefaultAction,
} from "./keyboard.js";

const { invoke } = window.__TAURI__.core;
const { getAllWebviewWindows, getCurrentWebviewWindow } = window.__TAURI__.webviewWindow;
const open = (options) => invoke("plugin:dialog|open", { options });
installCompatibilityPreview(document, invoke, () => open({
  multiple: false,
  directory: false,
  filters: [{ name: "Core resolver JSON", extensions: ["json"] }],
}));
const openUrl = (url) => invoke("plugin:opener|open_url", { url });

const $ = (selector) => document.querySelector(selector);
const elements = {
  appShell: $("#app-shell"), companionScrim: $("#companion-scrim"),
  companionScrimLabel: $("#companion-scrim-label"),
  dropZone: $("#drop-zone"), chooseImage: $("#choose-image"), openValve: $("#open-valve"),
  dropTitle: $("#drop-title"), dropMessage: $("#drop-message"),
  readinessGrid: $("#readiness-grid"), downloadCard: $("#download-card"),
  selectionCard: $("#selection-card"), selectedName: $("#selected-name"), selectedPath: $("#selected-path"),
  selectionStatus: $("#selection-status"), buildCard: $("#build-card"), buildButton: $("#build-button"),
  exportImage: $("#export-image"), chooseOutputFolder: $("#choose-output-folder"),
  resetOutputFolder: $("#reset-output-folder"), outputFolderLabel: $("#output-folder-label"),
  usbPicker: $("#usb-picker"),
  nvidiaSource: $("#nvidia-source"), upstreamWarning: $("#upstream-warning"),
  allowUpstreamBuild: $("#allow-upstream-build"),
  summaryInput: $("#summary-input"), summaryOutput: $("#summary-output"),
  summaryAction: $("#summary-action"),
  resultMessage: $("#result-message"), environmentTitle: $("#environment-title"),
  usbCard: $("#usb-card"), usbScrim: $("#usb-scrim"), usbTarget: $("#usb-target"),
  usbTargetDetail: $("#usb-target-detail"), refreshUsbTargets: $("#refresh-usb-targets"),
  clearUsbTarget: $("#clear-usb-target"),
  usbPickerMessage: $("#usb-picker-message"), usbDialogTarget: $("#usb-dialog-target"),
  usbMessage: $("#usb-message"), usbConfirmationRow: $("#usb-confirmation-row"),
  usbConfirmation: $("#usb-confirmation"), usbConfirmationHelp: $("#usb-confirmation-help"),
  armUsbPreflight: $("#arm-usb-preflight"), cancelUsbPreflight: $("#cancel-usb-preflight"),
  writeUsbImage: $("#write-usb-image"), usbActiveWarning: $("#usb-active-warning"),
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
let outputDirectory = null;
let outputSelectionGeneration = 0;
let plannedOutput = null;
let completedOutput = null;
let completedOutputImported = false;
let imageSelectionGeneration = 0;
let usbPreflightSession = null;
let usbContextGeneration = 0;
let usbArmPending = false;
let usbCancelPending = false;
let usbWriting = false;
let buildRunning = false;
let activeExportMode = "image";
let pendingBuildFinished = null;
let buildContextGeneration = 0;
let activeBuildContext = null;
let pendingUsbTarget = null;
let hostReady = false;
let progressReady = false;
let builderSettings = {
  schemaVersion: 4,
  autoReleaseVerifiedNvidia: false,
  trackSteamosDriverUpdates: false,
  includeUpstreamNvidiaReleases: false,
  omitOptionalCuda: false,
  recentMaintainerWorktrees: [],
};
let githubMaintainer = null;
let githubLoginPoll = 0;
let githubLoginPending = false;
let autoReleaseVerificationPending = false;
let settingsSavePending = false;
let activeCompanion = null;
const mainWindow = getCurrentWebviewWindow();
installWindowDrag(mainWindow);

await mainWindow.listen("build-progress-ready", () => { progressReady = true; });

function setCompanionMode(label = null) {
  activeCompanion = label;
  const active = Boolean(label);
  document.body.classList.toggle("companion-active", active);
  elements.companionScrim.classList.toggle("hidden", !active);
  elements.appShell.inert = active;
  elements.appShell.setAttribute("aria-hidden", String(active));
  if (label === "maintainer-workspace") {
    elements.companionScrimLabel.textContent = "Maintainer Workspace is open";
  } else if (active) {
    elements.companionScrimLabel.textContent = "Build Progress is open";
  }
}

async function focusActiveCompanion() {
  if (!activeCompanion) return;
  const label = activeCompanion;
  const windows = await getAllWebviewWindows();
  const companion = windows.find((window) => window.label === label);
  if (!companion || label !== activeCompanion) {
    setCompanionMode();
    return;
  }
  await companion.setFocus();
}

elements.companionScrim.addEventListener("click", () => { void focusActiveCompanion(); });
await mainWindow.onFocusChanged(({ payload: focused }) => {
  if (focused && activeCompanion) void focusActiveCompanion();
});
await mainWindow.listen("companion-window-hidden", ({ payload }) => {
  if (payload?.label !== activeCompanion) return;
  setCompanionMode();
  if (payload.label === "build-progress" && pendingBuildFinished) {
    const completion = pendingBuildFinished;
    pendingBuildFinished = null;
    void applyBuildFinished(completion);
  }
});

async function waitForProgressWindow(progressWindow) {
  progressReady = false;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    await progressWindow.emit("build-progress-probe");
    await new Promise((resolve) => setTimeout(resolve, 100));
    if (progressReady) return;
  }
  throw new Error("The build progress window did not become ready.");
}

function currentBuildSnapshot() {
  return {
    hasImage: Boolean(currentImage),
    hasCompletedOutput: Boolean(completedOutput?.path),
    buildRunning,
    usbWriting,
    hostReady,
    exportMode: selectedExportMode(),
    upstreamSelected: elements.nvidiaSource.value.startsWith("upstream:"),
    upstreamApproved: elements.allowUpstreamBuild.checked,
  };
}

function updateBuildButton() {
  elements.buildButton.disabled = !deriveBuildAdmission(currentBuildSnapshot()).canBuild;
}

function selectedExportMode() {
  const image = elements.exportImage.checked;
  const usb = Boolean(elements.usbTarget.value);
  if (image && usb) return "both";
  if (usb) return "usb";
  if (image) return "image";
  return null;
}

function hasUsbTargets() {
  return [...elements.usbTarget.options].some((option) => Boolean(option.value));
}

function renderExportMode() {
  const completedImageReady = Boolean(completedOutput?.path);
  const finalUsbReady = Boolean(completedImageReady && elements.usbTarget.value);
  elements.reviewUsbTarget.classList.toggle("hidden", !completedImageReady);
  elements.reviewUsbTarget.disabled = !finalUsbReady || usbWriting;
  elements.reviewUsbTarget.textContent = finalUsbReady
    ? "Review & Write Selected USB…"
    : "Select a USB Drive to Continue";
  renderSourceWarning();
}

function setUsbMenuOpen(opened) {
  const wasOpen = !elements.usbCard.classList.contains("hidden");
  if (opened && !elements.settingsPanel.classList.contains("hidden")) setSettingsOpen(false);
  const selected = elements.usbTarget.selectedOptions[0];
  elements.usbDialogTarget.textContent = selected?.value
    ? `${selected.textContent} — ${selected.dataset.detail || "identity ready for final validation"}`
    : "No drive selected";
  elements.usbCard.classList.toggle("hidden", !opened);
  elements.usbScrim.classList.toggle("hidden", !opened);
  elements.reviewUsbTarget.setAttribute("aria-expanded", String(opened));
  if (opened) {
    requestAnimationFrame(() => elements.closeUsbMenu.focus());
  } else if (wasOpen && !elements.reviewUsbTarget.classList.contains("hidden")) {
    requestAnimationFrame(() => elements.reviewUsbTarget.focus());
  }
}

async function dismissUsbMenu() {
  if (usbWriting) return;
  usbContextGeneration += 1;
  const session = usbPreflightSession;
  usbPreflightSession = null;
  renderUsbConfirmationPhase(false);
  setUsbMenuOpen(false);
  if (session?.sessionToken) {
    await invoke("cancel_usb_write_preflight", { sessionToken: session.sessionToken }).catch(() => {});
  }
}

function renderUsbConfirmationPhase(prepared = Boolean(usbPreflightSession)) {
  const canConfirm = Boolean(elements.usbTarget.value && completedOutput?.path);
  elements.usbConfirmationRow.classList.toggle("hidden", !canConfirm || prepared);
  elements.armUsbPreflight.classList.toggle("hidden", !canConfirm || prepared);
  elements.writeUsbImage.classList.toggle("hidden", !prepared || !usbPreflightSession?.writesAllowed);
  elements.cancelUsbPreflight.classList.toggle("hidden", !prepared);
  elements.armUsbPreflight.disabled = usbArmPending
    || elements.usbConfirmation.value !== `ERASE ${elements.usbTarget.value}`;
}

function renderSourceWarning() {
  if (completedOutput?.path) {
    const identity = completedOutput.nvidiaVersion
      ? `NVIDIA ${completedOutput.nvidiaVersion} for SteamOS ${completedOutput.steamosVersion}`
      : "This manifest-bound NVIDIA output";
    elements.summaryAction.textContent = `${identity} is already complete. No rebuild or reinstall will run; select a USB drive to review the destructive write.`;
    updateBuildButton();
    return;
  }
  const upstreamSelected = elements.nvidiaSource.value.startsWith("upstream:");
  elements.upstreamWarning.classList.toggle("hidden", !upstreamSelected);
  if (!upstreamSelected) elements.allowUpstreamBuild.checked = false;
  const selectedLabel = elements.nvidiaSource.selectedOptions[0]?.textContent || "Automatic";
  const sourceSummary = upstreamSelected
    ? `${selectedLabel} will be built only after its exact source and userspace inputs pass validation.`
    : `${selectedLabel} will prefer an exact trusted release, then use the isolated x86_64 builder when required.`;
  const destination = selectedExportMode() === "both"
    ? "Keep the image and write the selected USB drive"
    : selectedExportMode() === "usb"
      ? "Write only the selected USB drive"
      : selectedExportMode() === "image"
        ? "Keep the exported image"
        : "Select at least one output";
  elements.summaryAction.textContent = `${sourceSummary} Destination: ${destination}.`;
  updateBuildButton();
}

function applyCompletedOutput(output, imported = false) {
  completedOutput = output;
  completedOutputImported = imported;
  plannedOutput = output.path;
  elements.buildCard.classList.add("completed-output-selected");
  elements.appShell.classList.add("completed-output-selected");
  elements.exportImage.checked = true;
  elements.exportImage.disabled = true;
  elements.chooseOutputFolder.disabled = true;
  elements.resetOutputFolder.disabled = true;
  elements.summaryOutput.textContent = output.path;
  elements.summaryOutput.title = output.path;
  elements.selectionStatus.textContent = output.nvidiaVersion
    ? `NVIDIA ${output.nvidiaVersion}`
    : (imported ? "Verified output" : "Complete");
  elements.selectionStatus.className = "status";
  const installedIdentity = output.nvidiaVersion
    ? `NVIDIA ${output.nvidiaVersion}, SteamOS ${output.steamosVersion}, kernel ${output.kernelVersion}, trust ${output.trust}.`
    : "Manifest-bound output.";
  elements.resultMessage.title = installedIdentity;
  elements.resultMessage.textContent = imported
    ? `Verified existing NVIDIA ${output.nvidiaVersion || "image"} output${output.steamosVersion ? ` for SteamOS ${output.steamosVersion}` : ""}. No rebuild needed; select a USB drive.`
    : `NVIDIA image complete and verified. Select a USB drive to write it, or keep the exported image.`;
  elements.resultMessage.className = "result-message success";
  renderSourceWarning();
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
  builderSettings = { ...builderSettings, ...next, schemaVersion: 4 };
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
  if (opened && !elements.usbCard.classList.contains("hidden")) void dismissUsbMenu();
  elements.settingsPanel.classList.toggle("hidden", !opened);
  elements.settingsScrim.classList.toggle("hidden", !opened);
  elements.settingsButton.setAttribute("aria-expanded", String(opened));
  if (opened) {
    refreshGithubMaintainer();
    requestAnimationFrame(() => elements.settingsClose.focus());
  } else {
    requestAnimationFrame(() => elements.settingsButton.focus());
  }
}

async function checkEnvironment() {
  try {
    const environment = await invoke("check_builder_environment");
    const presentation = presentHostEnvironment(environment);
    hostReady = presentation.ready;
    elements.environmentTitle.textContent = presentation.title;
    elements.environmentMessage.textContent = presentation.message;
    elements.environmentDetails.textContent = presentation.details;
    elements.environmentStatus.textContent = presentation.status;
    elements.environmentStatus.className = `status ${presentation.ready ? "" : "failed"}`;
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
      option.dataset.nvidiaVersion = branch.version;
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
  outputSelectionGeneration += 1;
  const selection = admitImageSelection(currentBuildSnapshot());
  if (!selection.accepted) {
    elements.resultMessage.textContent = selection.phase === "building"
      ? "The selected image cannot be changed while a build is running. Cancel or finish the build first."
      : "The selected image cannot be changed while a USB write is running.";
    elements.resultMessage.className = "result-message error";
    return;
  }
  const selectionGeneration = ++imageSelectionGeneration;
  let selectionError = null;
  usbContextGeneration += 1;
  const previousUsbSession = usbPreflightSession;
  usbPreflightSession = null;
  completedOutput = null;
  completedOutputImported = false;
  currentImage = null;
  currentImageName = null;
  plannedOutput = null;
  pendingUsbTarget = null;
  elements.buildCard.classList.remove("completed-output-selected");
  elements.buildCard.classList.add("hidden");
  elements.appShell.classList.remove("completed-output-selected");
  elements.exportImage.checked = true;
  elements.exportImage.disabled = false;
  elements.chooseOutputFolder.disabled = false;
  elements.resetOutputFolder.disabled = false;
  setUsbMenuOpen(false);
  elements.usbTarget.replaceChildren();
  const usbPlaceholder = document.createElement("option");
  usbPlaceholder.value = "";
  usbPlaceholder.textContent = "Connect a USB drive, then refresh…";
  usbPlaceholder.disabled = true;
  usbPlaceholder.selected = true;
  elements.usbTarget.append(usbPlaceholder);
  elements.usbTarget.disabled = true;
  elements.usbPicker.classList.add("is-empty");
  elements.usbPicker.classList.remove("is-loading");
  elements.clearUsbTarget.classList.add("hidden");
  elements.usbTargetDetail.textContent = "Connect a USB drive, then refresh.";
  elements.usbPickerMessage.textContent = "No USB drive will be written unless one is selected.";
  elements.usbMessage.textContent = "";
  elements.usbMessage.className = "result-message";
  elements.usbMessage.removeAttribute("title");
  elements.usbConfirmationRow.classList.add("hidden");
  elements.armUsbPreflight.classList.add("hidden");
  elements.cancelUsbPreflight.classList.add("hidden");
  elements.writeUsbImage.classList.add("hidden");
  elements.dropZone.classList.add("processing");
  elements.chooseImage.disabled = true;
  elements.nvidiaSource.disabled = true;
  elements.allowUpstreamBuild.disabled = true;
  elements.selectedName.textContent = path.split(/[\\/]/).pop();
  elements.selectedName.title = elements.selectedName.textContent;
  elements.selectedPath.textContent = path;
  elements.selectedPath.title = path;
  elements.selectionStatus.textContent = "Checking…";
  elements.selectionStatus.className = "status pending";
  elements.selectionCard.classList.remove("hidden");
  elements.readinessGrid.classList.add("has-selection");
  elements.dropTitle.textContent = "Checking selected image…";
  elements.dropMessage.textContent = "Validating the file path and supported format.";
  elements.resultMessage.textContent = "Checking whether this is an original recovery image or a manifest-bound NVIDIA output…";
  updateBuildButton();
  try {
    if (previousUsbSession) {
      await invoke("cancel_usb_write_preflight", { sessionToken: previousUsbSession.sessionToken }).catch(() => {});
      if (selectionGeneration !== imageSelectionGeneration) return;
    }
    const info = await invoke("validate_image", { path });
    if (selectionGeneration !== imageSelectionGeneration) return;
    elements.dropMessage.textContent = "Checking for a matching completed-output manifest and verifying image bytes.";
    const selectedSource = elements.nvidiaSource.selectedOptions[0];
    const requestedNvidiaVersion = ["automatic", "latest"].includes(elements.nvidiaSource.value)
      ? null
      : (selectedSource?.dataset.nvidiaVersion || null);
    const completed = await invoke("inspect_completed_nvidia_image", {
      path: info.path,
      requestedNvidiaVersion,
    });
    if (selectionGeneration !== imageSelectionGeneration) return;
    const preview = completed ? { input_path: info.path, output_path: info.path }
      : await invoke("preview_image_output", { path: info.path, outputDirectory });
    if (selectionGeneration !== imageSelectionGeneration) return;
    currentImage = info.path;
    currentImageName = info.name;
    plannedOutput = preview.output_path;
    elements.selectedName.textContent = info.name;
    elements.selectedName.title = info.name;
    elements.selectedPath.textContent = info.path;
    elements.selectedPath.title = info.path;
    elements.summaryInput.textContent = preview.input_path;
    elements.summaryInput.title = preview.input_path;
    elements.summaryOutput.textContent = preview.output_path;
    elements.summaryOutput.title = preview.output_path;
    elements.selectionStatus.textContent = "Ready";
    elements.selectionStatus.className = "status";
    elements.buildCard.classList.remove("hidden");
    elements.resultMessage.textContent = "";
    if (completed) applyCompletedOutput(completed, true);
  } catch (error) {
    if (selectionGeneration !== imageSelectionGeneration) return;
    selectionError = String(error);
    currentImage = null;
    currentImageName = null;
    plannedOutput = null;
    elements.selectedName.textContent = path.split(/[\\/]/).pop();
    elements.selectedName.title = elements.selectedName.textContent;
    elements.selectedPath.textContent = path;
    elements.selectedPath.title = path;
    elements.selectionStatus.textContent = "Unsupported";
    elements.selectionStatus.className = "status failed";
    elements.selectionCard.classList.remove("hidden");
    elements.readinessGrid.classList.add("has-selection");
    elements.buildCard.classList.add("hidden");
    elements.resultMessage.textContent = selectionError;
  } finally {
    if (selectionGeneration !== imageSelectionGeneration) return;
    elements.dropZone.classList.remove("processing");
    elements.chooseImage.disabled = false;
    elements.nvidiaSource.disabled = false;
    elements.allowUpstreamBuild.disabled = false;
    elements.downloadCard.classList.toggle("hidden", Boolean(currentImage));
    elements.dropTitle.textContent = selectionError
      ? "Choose another SteamOS image"
      : completedOutput?.path
        ? "Validated NVIDIA image ready"
        : currentImage ? "SteamOS image selected" : "Drop SteamOS recovery image here";
    elements.dropMessage.textContent = selectionError
      || (completedOutput?.path
        ? "No rebuild is needed. Select a USB destination below."
        : currentImage ? "Review it above, then build a separate validated image." : ".img, .img.bz2, .img.gz, or .img.xz");
    elements.dropMessage.title = selectionError || "";
  }
  updateBuildButton();
  renderExportMode();
  if (currentImage) elements.refreshUsbTargets.click();
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
  builderSettings = { ...builderSettings, autoReleaseVerifiedNvidia: enabled, schemaVersion: 4 };
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
    setCompanionMode("maintainer-workspace");
  } catch (error) {
    elements.settingsMessage.textContent = String(error);
    elements.settingsMessage.className = "settings-message error";
  } finally {
    renderSettings();
  }
});

async function selectOutputDirectory(directory) {
  const revision = ++outputSelectionGeneration;
  if (!currentImage || completedOutput || buildRunning) return;
  elements.chooseOutputFolder.disabled = true;
  elements.resetOutputFolder.disabled = true;
  try {
    const preview = await invoke("preview_image_output", {
      path: currentImage,
      outputDirectory: directory,
    });
    if (revision !== outputSelectionGeneration || !currentImage) return;
    outputDirectory = directory;
    plannedOutput = preview.output_path;
    elements.summaryOutput.textContent = plannedOutput;
    elements.summaryOutput.title = plannedOutput;
    elements.outputFolderLabel.textContent = directory || "Alongside the source image";
    elements.outputFolderLabel.title = directory || "";
    elements.resetOutputFolder.classList.toggle("hidden", !directory);
  } catch (error) {
    if (revision !== outputSelectionGeneration) return;
    elements.resultMessage.textContent = String(error);
    elements.resultMessage.className = "result-message error";
  } finally {
    if (revision === outputSelectionGeneration) {
      elements.chooseOutputFolder.disabled = false;
      elements.resetOutputFolder.disabled = false;
    }
  }
}

elements.chooseOutputFolder.addEventListener("click", async () => {
  const directory = await open({ multiple: false, directory: true });
  if (typeof directory === "string" && directory) await selectOutputDirectory(directory);
});
elements.resetOutputFolder.addEventListener("click", () => { void selectOutputDirectory(null); });

elements.buildButton.addEventListener("click", async () => {
  const exportMode = selectedExportMode();
  if (!admitBuildStart(currentBuildSnapshot()).accepted) return;
  const buildContext = {
    generation: ++buildContextGeneration,
    requestId: crypto.randomUUID(),
    inputPath: currentImage,
    selectionGeneration: imageSelectionGeneration,
  };
  activeBuildContext = buildContext;
  elements.buildButton.disabled = true;
  buildRunning = true;
  activeExportMode = exportMode;
  const selectedUsb = elements.usbTarget.selectedOptions[0];
  pendingUsbTarget = selectedUsb?.value && exportMode !== "image"
    ? {
      deviceIdentifier: selectedUsb.value,
      identityToken: selectedUsb.dataset.identityToken,
    }
    : null;
  elements.exportImage.disabled = true;
  elements.chooseOutputFolder.disabled = true;
  elements.resetOutputFolder.disabled = true;
  elements.chooseImage.disabled = true;
  elements.usbTarget.disabled = true;
  elements.refreshUsbTargets.disabled = true;
  elements.resultMessage.textContent = "Build progress opened in a separate window.";
  try {
    const preview = await invoke("preview_image_output", { path: currentImage, outputDirectory });
    plannedOutput = preview.output_path;
    elements.summaryOutput.textContent = plannedOutput;
    elements.summaryOutput.title = plannedOutput;
    await invoke("open_progress_window");
    setCompanionMode("build-progress");
    const windows = await getAllWebviewWindows();
    const progressWindow = windows.find((window) => window.label === "build-progress");
    if (!progressWindow) throw new Error("The build progress window is unavailable.");
    await waitForProgressWindow(progressWindow);
    await progressWindow.emit("build-requested", {
      requestId: buildContext.requestId,
      path: currentImage,
      name: currentImageName,
      sourceSelection: elements.nvidiaSource.value,
      allowExperimentalUpstream: elements.nvidiaSource.value.startsWith("upstream:")
        && elements.allowUpstreamBuild.checked,
      exportMode: activeExportMode,
      outputDirectory,
    });
  } catch (error) {
    if (!operationContextMatches(buildContext, activeBuildContext || {})) return;
    activeBuildContext = null;
    if (activeCompanion === "build-progress") setCompanionMode();
    elements.resultMessage.textContent = String(error);
    elements.resultMessage.className = "result-message error";
    buildRunning = false;
    elements.exportImage.disabled = false;
    elements.chooseOutputFolder.disabled = false;
    elements.resetOutputFolder.disabled = false;
    elements.chooseImage.disabled = false;
    elements.usbTarget.disabled = !hasUsbTargets();
    elements.refreshUsbTargets.disabled = false;
    updateBuildButton();
  }
});

async function revealCompletedImage(path) {
  try {
    await invoke("reveal_completed_image", { path });
    return true;
  } catch (error) {
    elements.resultMessage.textContent += ` The image is complete, but it could not be revealed automatically: ${error}`;
    elements.resultMessage.className = "result-message error";
    return false;
  }
}

async function applyBuildFinished(completion) {
  const { state, message, output, inputPath } = completion;
  const buildContext = activeBuildContext;
  if (!buildCompletionMatches(completion, buildContext)
    || buildContext.selectionGeneration !== imageSelectionGeneration) return;
  elements.resultMessage.textContent = message;
  elements.resultMessage.className = `result-message ${state === "complete" ? "success" : state === "failed" ? "error" : ""}`;
  if (state === "complete" && output?.path && inputPath === currentImage) {
    usbContextGeneration += 1;
    const completed = await invoke("inspect_completed_nvidia_image", {
      path: output.path,
      requestedNvidiaVersion: null,
    }).catch(() => null);
    if (!operationContextMatches(buildContext, activeBuildContext || {})
      || buildContext.selectionGeneration !== imageSelectionGeneration
      || inputPath !== currentImage) return;
    applyCompletedOutput(completed || output);
    if (activeExportMode === "image") {
      await revealCompletedImage(output.path);
    } else {
      const preferredTarget = pendingUsbTarget;
      pendingUsbTarget = null;
      elements.resultMessage.textContent = "The image is complete. Revalidating the exported bytes and matching the previously selected USB drive…";
      elements.resultMessage.className = "result-message";
      elements.usbMessage.textContent = "Revalidating the completed image and selected USB drive before destructive confirmation…";
      elements.usbMessage.className = "result-message";
      setUsbMenuOpen(true);
      elements.usbDialogTarget.textContent = preferredTarget
        ? `Revalidating ${preferredTarget.deviceIdentifier}…`
        : "Refreshing removable drives…";
      await mainWindow.setFocus().catch(() => {});
      const restored = await refreshUsbTargets(preferredTarget);
      if (restored) {
        setUsbMenuOpen(true);
      } else {
        elements.usbDialogTarget.textContent = "Select the removable drive again";
        elements.resultMessage.textContent = "The image is complete, but the previously selected USB drive could not be matched exactly. The USB review remains open so you can refresh and select it again.";
        elements.resultMessage.className = "result-message error";
        if (!elements.usbMessage.classList.contains("error")) {
          elements.usbMessage.textContent = "The earlier USB identity is no longer an exact match. Nothing was written. Refresh and select the intended whole removable drive again.";
          elements.usbMessage.className = "result-message error";
        }
        renderUsbConfirmationPhase(false);
      }
    }
  } else {
    pendingUsbTarget = null;
  }
  if (!operationContextMatches(buildContext, activeBuildContext || {})) return;
  activeBuildContext = null;
  buildRunning = false;
  elements.exportImage.disabled = false;
  elements.chooseImage.disabled = false;
  elements.usbTarget.disabled = !hasUsbTargets();
  elements.refreshUsbTargets.disabled = false;
  updateBuildButton();
}

await mainWindow.listen("build-finished", async (event) => {
  if (!buildCompletionMatches(event.payload, activeBuildContext)) return;
  if (activeCompanion === "build-progress") {
    if (pendingBuildFinished) return;
    pendingBuildFinished = event.payload;
    return;
  }
  await applyBuildFinished(event.payload);
});

async function refreshUsbTargets(preferredTarget = null) {
  if (!completedOutput?.path && !currentImage) return;
  usbContextGeneration += 1;
  const generation = usbContextGeneration;
  const imagePath = completedOutput?.path || currentImage;
  elements.cancelUsbPreflight.classList.add("hidden");
  elements.refreshUsbTargets.disabled = true;
  elements.refreshUsbTargets.setAttribute("aria-busy", "true");
  elements.refreshUsbTargets.textContent = "Scanning…";
  elements.usbTarget.disabled = true;
  elements.usbPicker.classList.add("is-empty", "is-loading");
  elements.usbMessage.textContent = "Inspecting whole external physical disks without opening them for writing…";
  elements.usbPickerMessage.textContent = elements.usbMessage.textContent;
  elements.usbMessage.className = "result-message";
  const previousSession = usbPreflightSession;
  usbPreflightSession = null;
  renderUsbConfirmationPhase(false);
  if (previousSession?.sessionToken) {
    await invoke("cancel_usb_write_preflight", { sessionToken: previousSession.sessionToken }).catch(() => {});
    if (generation !== usbContextGeneration) return;
  }
  try {
    const preflight = completedOutput?.path
      ? await invoke("inspect_usb_targets", { imagePath })
      : await invoke("inspect_usb_targets_for_build", { inputPath: imagePath });
    if (generation !== usbContextGeneration || (completedOutput?.path || currentImage) !== imagePath) return;
    elements.usbTarget.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Select a removable drive…";
    placeholder.disabled = true;
    placeholder.selected = true;
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
    elements.usbPicker.classList.toggle("is-empty", !preflight.targets.length);
    elements.clearUsbTarget.classList.add("hidden");
    elements.usbMessage.textContent = preflight.message;
    elements.usbPickerMessage.textContent = preflight.message;
    renderExportMode();
    if (preferredTarget) {
      const preferred = [...elements.usbTarget.options].find((option) => (
        option.value === preferredTarget.deviceIdentifier
          && option.dataset.identityToken === preferredTarget.identityToken
      ));
      if (preferred) {
        preferred.selected = true;
        renderUsbTargetSelection();
        return true;
      }
    }
    return false;
  } catch (error) {
    if (generation !== usbContextGeneration) return;
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Refresh to inspect removable drives…";
    placeholder.disabled = true;
    placeholder.selected = true;
    elements.usbTarget.replaceChildren(placeholder);
    elements.usbTarget.disabled = true;
    elements.usbPicker.classList.add("is-empty");
    elements.clearUsbTarget.classList.add("hidden");
    elements.usbTargetDetail.textContent = "No current removable-drive inventory.";
    elements.usbMessage.textContent = String(error);
    elements.usbMessage.className = "result-message error";
    elements.usbPickerMessage.textContent = `Drive inspection failed: ${error}`;
    renderUsbConfirmationPhase(false);
    renderExportMode();
  } finally {
    if (generation === usbContextGeneration) {
      elements.refreshUsbTargets.disabled = false;
      elements.refreshUsbTargets.removeAttribute("aria-busy");
      elements.refreshUsbTargets.textContent = "Refresh Drives";
      elements.usbPicker.classList.remove("is-loading");
    }
  }
  return false;
}

elements.refreshUsbTargets.addEventListener("click", async () => {
  await refreshUsbTargets();
});

function renderUsbTargetSelection() {
  elements.cancelUsbPreflight.classList.add("hidden");
  elements.writeUsbImage.classList.add("hidden");
  elements.usbConfirmation.value = "";
  elements.usbMessage.removeAttribute("title");
  const identifier = elements.usbTarget.value;
  elements.clearUsbTarget.classList.toggle("hidden", !identifier);
  const canConfirm = Boolean(identifier && completedOutput?.path);
  renderUsbConfirmationPhase(false);
  elements.usbConfirmationHelp.textContent = canConfirm
    ? `Type ERASE ${identifier} exactly. A final warning still appears before writing.`
    : "Select a target first.";
  elements.usbTargetDetail.textContent = elements.usbTarget.selectedOptions[0]?.dataset.detail
    || "Connect a USB drive, then refresh.";
  if (identifier && !completedOutput?.path) {
    elements.usbPickerMessage.textContent = "Selected for this build. The drive must be refreshed and selected again after export.";
  } else if (identifier) {
    elements.usbPickerMessage.textContent = "Final drive identity selected. Review the destructive write separately when ready.";
  } else {
    elements.usbPickerMessage.textContent = "No USB drive will be written unless one is selected.";
  }
  renderExportMode();
}

elements.usbTarget.addEventListener("change", async () => {
  const generation = ++usbContextGeneration;
  const previousSession = usbPreflightSession;
  usbPreflightSession = null;
  renderUsbTargetSelection();
  if (previousSession?.sessionToken) {
    await invoke("cancel_usb_write_preflight", { sessionToken: previousSession.sessionToken }).catch(() => {});
  }
  if (generation !== usbContextGeneration) return;
});

elements.clearUsbTarget.addEventListener("click", () => {
  if (!elements.usbTarget.value) return;
  elements.usbTarget.value = "";
  elements.usbTarget.dispatchEvent(new Event("change"));
  elements.usbTarget.focus();
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
  elements.armUsbPreflight.setAttribute("aria-busy", "true");
  elements.armUsbPreflight.textContent = "Revalidating…";
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
    elements.usbMessage.title = usbPreflightSession.message;
    elements.usbMessage.textContent = usbPreflightSession.writesAllowed
      ? "Image and drive identity confirmed. Continue when you are ready to erase and write the selected USB drive."
      : usbPreflightSession.message;
    renderUsbConfirmationPhase(true);
  } catch (error) {
    if (generation !== usbContextGeneration) return;
    usbPreflightSession = null;
    elements.usbMessage.textContent = String(error);
    elements.usbMessage.className = "result-message error";
  } finally {
    usbArmPending = false;
    elements.armUsbPreflight.removeAttribute("aria-busy");
    elements.armUsbPreflight.textContent = "Confirm & Prepare USB";
    if (generation === usbContextGeneration) {
      elements.armUsbPreflight.disabled = elements.usbConfirmation.value !== `ERASE ${elements.usbTarget.value}`;
    }
  }
});

elements.cancelUsbPreflight.addEventListener("click", async () => {
  if (usbCancelPending || !usbPreflightSession?.sessionToken) return;
  const context = {
    generation: usbContextGeneration,
    imagePath: completedOutput?.path,
    sessionToken: usbPreflightSession.sessionToken,
  };
  let cancellationCompleted = false;
  usbCancelPending = true;
  elements.cancelUsbPreflight.disabled = true;
  elements.cancelUsbPreflight.setAttribute("aria-busy", "true");
  elements.cancelUsbPreflight.textContent = "Cancelling…";
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
      elements.usbMessage.removeAttribute("title");
      renderUsbConfirmationPhase(false);
    }
    usbCancelPending = false;
    elements.cancelUsbPreflight.disabled = false;
    elements.cancelUsbPreflight.removeAttribute("aria-busy");
    elements.cancelUsbPreflight.textContent = "Back";
  }
});

elements.exportImage.addEventListener("change", renderExportMode);
elements.reviewUsbTarget.addEventListener("click", () => {
  if (currentImage && completedOutput?.path && elements.usbTarget.value) {
    setUsbMenuOpen(true);
  }
});
elements.closeUsbMenu.addEventListener("click", () => { void dismissUsbMenu(); });
elements.usbScrim.addEventListener("click", () => { void dismissUsbMenu(); });

installKeyboardBindings([
  {
    key: "Enter",
    allowInEditable: true,
    when: () => !elements.usbCard.classList.contains("hidden")
      && document.activeElement === elements.usbConfirmation
      && elements.usbConfirmation.value === `ERASE ${elements.usbTarget.value}`,
    run: () => runKeyboardDefaultAction(elements.armUsbPreflight),
  },
  {
    key: "Tab",
    shift: "any",
    allowInEditable: true,
    preventDefault: false,
    when: () => !elements.usbCard.classList.contains("hidden")
      || !elements.settingsPanel.classList.contains("hidden"),
    run: (event) => {
      const usbOpen = !elements.usbCard.classList.contains("hidden");
      if (keepKeyboardFocusInside(event, usbOpen ? elements.usbCard : elements.settingsPanel)) {
        event.preventDefault();
      }
    },
  },
  {
    key: "Escape",
    allowInEditable: true,
    when: () => !elements.usbCard.classList.contains("hidden"),
    run: () => { void dismissUsbMenu(); },
  },
  {
    key: "Escape",
    allowInEditable: true,
    when: () => !elements.settingsPanel.classList.contains("hidden"),
    run: () => setSettingsOpen(false),
  },
]);

await mainWindow.listen("usb-write-progress", (event) => {
  if (!usbWriting) return;
  const progress = event.payload;
  const ratio = progress.bytesTotal > 0 ? progress.bytesCompleted / progress.bytesTotal : 0;
  elements.usbMessage.textContent = `${progress.message} ${(ratio * 100).toFixed(1)}%`;
  elements.usbMessage.className = "result-message";
});

elements.writeUsbImage.addEventListener("click", async () => {
  const admission = admitUsbWriteStart(currentBuildSnapshot(), {
    hasPreflightSession: Boolean(usbPreflightSession?.sessionToken),
  });
  if (!admission.accepted) return;
  const device = usbPreflightSession.deviceNode;
  if (!window.confirm(`FINAL WARNING\n\nErase ${device} and write the validated SteamOS image?\n\nEvery existing partition and file on this device will be destroyed.`)) return;
  usbWriting = true;
  elements.chooseImage.disabled = true;
  elements.usbActiveWarning.classList.remove("hidden");
  elements.writeUsbImage.disabled = true;
  elements.refreshUsbTargets.disabled = true;
  elements.closeUsbMenu.disabled = true;
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
    elements.cancelUsbPreflight.classList.add("hidden");
    // An imported image already exists at a user-selected path. Revealing it
    // after a USB-only operation falsely implies that this run exported it.
    if (activeExportMode === "both" && !completedOutputImported) {
      const revealed = await revealCompletedImage(completedOutput.path);
      if (revealed) elements.usbMessage.textContent = `${result.message} Finder opened the retained image.`;
    }
  } catch (error) {
    usbPreflightSession = null;
    elements.usbMessage.textContent = String(error);
    elements.usbMessage.className = "result-message error";
    elements.usbMessage.removeAttribute("title");
    renderUsbConfirmationPhase(false);
  } finally {
    usbWriting = false;
    elements.chooseImage.disabled = false;
    elements.usbActiveWarning.classList.add("hidden");
    elements.writeUsbImage.disabled = false;
    elements.refreshUsbTargets.disabled = false;
    elements.closeUsbMenu.disabled = false;
    updateBuildButton();
  }
});

await mainWindow.onDragDropEvent(async (event) => {
  if (document.getElementById("compatibility-dialog").open) return;
  if (event.payload.type === "over") { elements.dropZone.classList.add("dragging"); return; }
  elements.dropZone.classList.remove("dragging");
  if (event.payload.type === "drop") {
    const [path] = event.payload.paths;
    if (path) await selectImage(path);
  }
});

await checkEnvironment();
await loadSettings();
await loadNvidiaSourceBranches();

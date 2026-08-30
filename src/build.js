const { invoke } = window.__TAURI__.core;
const { getCurrentWebviewWindow } = window.__TAURI__.webviewWindow;

const $ = (selector) => document.querySelector(selector);
const elements = {
  inputName: $("#input-name"), statusTitle: $("#status-title"), statusMessage: $("#status-message"),
  statusBadge: $("#status-badge"), progressBar: $("#progress-bar"), buildLog: $("#build-log"),
  logFollow: $("#log-follow"), cancelBuild: $("#cancel-build"), closeWindow: $("#close-window"),
  releaseDialog: $("#release-dialog"), releaseSummary: $("#release-summary"),
  releaseCancel: $("#release-cancel"), releaseConfirm: $("#release-confirm"),
};
const progressWindow = getCurrentWebviewWindow();
let running = false;
let cancelling = false;
let lastApplianceLog = "";
let lastNvidiaApplianceLog = "";
let pendingLogChunks = [];
let followingLogs = true;
let refreshingLogs = false;

function normalizeTerminalText(text) {
  return text
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]/g, "");
}

const ansiColors = ["#111827", "#ef4444", "#22c55e", "#eab308", "#3b82f6", "#d946ef", "#06b6d4", "#d1d5db"];
const ansiBrightColors = ["#6b7280", "#ff7070", "#6ee7a0", "#fde047", "#7da6ff", "#f08cff", "#67e8f9", "#ffffff"];

function ansi256Color(index) {
  if (index < 8) return ansiColors[index];
  if (index < 16) return ansiBrightColors[index - 8];
  if (index < 232) {
    const value = index - 16;
    const levels = [0, 95, 135, 175, 215, 255];
    return `rgb(${levels[Math.floor(value / 36)]},${levels[Math.floor(value / 6) % 6]},${levels[value % 6]})`;
  }
  const gray = 8 + (index - 232) * 10;
  return `rgb(${gray},${gray},${gray})`;
}

function freshAnsiState() {
  return { color: "", background: "", bold: false };
}

let ansiState = freshAnsiState();

function appendAnsiText(parent, text, state) {
  const pattern = /\x1b\[([0-?]*)([ -/]*)([@-~])/g;
  let offset = 0;
  const appendChunk = (chunk) => {
    if (!chunk) return;
    if (!state.color && !state.background && !state.bold) {
      parent.append(document.createTextNode(chunk));
      return;
    }
    const span = document.createElement("span");
    span.textContent = chunk;
    if (state.color) span.style.color = state.color;
    if (state.background) span.style.backgroundColor = state.background;
    if (state.bold) span.style.fontWeight = "700";
    parent.append(span);
  };
  for (const match of text.matchAll(pattern)) {
    appendChunk(text.slice(offset, match.index));
    offset = match.index + match[0].length;
    if (match[3] !== "m" || match[2]) continue;
    const codes = match[1] === "" ? [0] : match[1].split(";").map(Number);
    for (let index = 0; index < codes.length; index += 1) {
      const code = codes[index];
      if (code === 0) Object.assign(state, { color: "", background: "", bold: false });
      else if (code === 1) state.bold = true;
      else if (code === 22) state.bold = false;
      else if (code >= 30 && code <= 37) state.color = ansiColors[code - 30];
      else if (code >= 90 && code <= 97) state.color = ansiBrightColors[code - 90];
      else if (code === 39) state.color = "";
      else if (code >= 40 && code <= 47) state.background = ansiColors[code - 40];
      else if (code >= 100 && code <= 107) state.background = ansiBrightColors[code - 100];
      else if (code === 49) state.background = "";
      else if ((code === 38 || code === 48) && codes[index + 1] === 5) {
        const color = ansi256Color(codes[index + 2]);
        if (code === 38) state.color = color; else state.background = color;
        index += 2;
      } else if ((code === 38 || code === 48) && codes[index + 1] === 2) {
        const color = `rgb(${codes[index + 2]},${codes[index + 3]},${codes[index + 4]})`;
        if (code === 38) state.color = color; else state.background = color;
        index += 4;
      }
    }
  }
  appendChunk(text.slice(offset));
}

function setStatus(state, title, message, progress, activity = "Working") {
  elements.statusTitle.textContent = title;
  elements.statusMessage.textContent = message;
  elements.statusBadge.textContent = state === "complete" ? "Complete" : state === "failed" ? "Failed" : state === "cancelled" ? "Cancelled" : activity;
  elements.statusBadge.className = `status ${state === "complete" ? "" : state === "failed" || state === "cancelled" ? "failed" : "pending"}`;
  elements.progressBar.style.width = `${progress}%`;
}

function addStageLog(message) {
  const color = message.startsWith("ERROR:") ? "31" : message.includes("warning") ? "33" : "36";
  queueLogChunk(`\x1b[1;${color}m[builder]\x1b[0m ${message}\n`);
}

function confirmNvidiaRelease(summary) {
  elements.releaseSummary.textContent = summary;
  elements.releaseDialog.showModal();
  elements.releaseCancel.focus();
  return new Promise((resolve) => {
    const finish = (approved) => {
      elements.releaseDialog.close();
      elements.releaseCancel.removeEventListener("click", cancel);
      elements.releaseConfirm.removeEventListener("click", confirm);
      elements.releaseDialog.removeEventListener("cancel", cancelEvent);
      resolve(approved);
    };
    const cancel = () => finish(false);
    const confirm = () => finish(true);
    const cancelEvent = (event) => { event.preventDefault(); finish(false); };
    elements.releaseCancel.addEventListener("click", cancel);
    elements.releaseConfirm.addEventListener("click", confirm);
    elements.releaseDialog.addEventListener("cancel", cancelEvent);
  });
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = -1;
  do { value /= 1024; unit += 1; } while (value >= 1024 && unit < units.length - 1);
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`;
}

function showInputProgress(progress) {
  if (!running || cancelling) return;
  if (progress.stage === "starting-output-validation") {
    setStatus("running", "Starting output validation", "Booting a fresh appliance to inspect the exported image independently.", 98.2, "Validating");
    return;
  }
  if (progress.stage === "decompressing-output") {
    setStatus("running", "Normalizing compressed image", `Parallel decompressor produced ${formatBytes(progress.processedBytes)} of raw image data.`, 12, "Unzipping");
    return;
  }
  if (!progress.totalBytes) return;
  const ratio = Math.min(progress.processedBytes / progress.totalBytes, 1);
  const amount = `${formatBytes(progress.processedBytes)} of ${formatBytes(progress.totalBytes)}`;
  if (progress.stage === "hashing-source") {
    setStatus("running", "Verifying source image", `Computing the original input SHA-256: ${amount}.`, 4 + ratio * 4, "Hashing");
  } else if (progress.stage === "decompressing") {
    setStatus("running", "Normalizing compressed image", `Read ${amount} of the compressed input.`, 8 + ratio * 8, "Unzipping");
  } else if (progress.stage === "hashing-image") {
    setStatus("running", "Verifying normalized image", `Computing the disposable raw-image SHA-256: ${amount}.`, 16 + ratio * 6, "Hashing");
  } else if (progress.stage === "verifying-source-after") {
    setStatus("running", "Verifying source integrity", `Confirming the original input remains unchanged: ${amount}.`, 88 + ratio * 2, "Hashing");
  } else if (progress.stage === "verifying-image-after") {
    setStatus("running", "Verifying image integrity", `Confirming the attached raw image remains unchanged: ${amount}.`, 90 + ratio * 2, "Hashing");
  } else if (progress.stage === "exporting-image") {
    setStatus("running", "Exporting raw image", `Flattening the verified working layer: ${amount}.`, 97 + ratio, "Exporting");
  } else if (progress.stage === "hashing-output") {
    setStatus("running", "Validating exported image", `Hashing the independently attached raw output: ${amount}.`, 98.2 + ratio * 0.6, "Validating");
  } else if (progress.stage === "verifying-source-after-export") {
    setStatus("running", "Rechecking original image", `Confirming the original input remains unchanged: ${amount}.`, 98.8 + ratio * 0.7, "Hashing");
  }
}

function showNvidiaResolutionProgress(progress) {
  if (!running || cancelling) return;
  const total = Number(progress.totalBytes) || 0;
  const processed = Number(progress.processedBytes) || 0;
  const ratio = total > 0 ? Math.min(processed / total, 1) : 0;
  if (progress.stage === "querying-nvidia-releases") {
    setStatus("running", "Checking NVIDIA compatibility", "Querying published support releases for the exact image kernel.", 95.55, "Resolving");
  } else if (progress.stage === "downloading-nvidia-checksum") {
    setStatus("running", "Downloading NVIDIA verification data", "Retrieving the published archive checksum through the host.", 95.6, "Downloading");
  } else if (progress.stage === "downloading-nvidia-provenance") {
    setStatus("running", "Downloading NVIDIA provenance", "Retrieving the structured trust and module record.", 95.65, "Downloading");
  } else if (progress.stage === "downloading-nvidia-archive") {
    setStatus("running", "Downloading compatible NVIDIA modules", `${formatBytes(processed)} of ${formatBytes(total)} transferred.`, 95.7 + ratio * 0.2, "Downloading");
  } else if (progress.stage === "validating-nvidia-artifact") {
    setStatus("running", "Validating NVIDIA artifact", "Checking GitHub digests, checksum, embedded provenance, exact vermagic, and all five module hashes.", 95.92 + ratio * 0.06, "Validating");
  } else if (progress.stage === "querying-arch-package-index") {
    setStatus("running", "Resolving NVIDIA userspace", "Finding exact signed nvidia-utils packages in the Arch Linux Archive.", 95.98, "Resolving");
  } else if (progress.stage === "downloading-nvidia-utils") {
    setStatus("running", "Downloading NVIDIA userspace", `${formatBytes(processed)}${total ? ` of ${formatBytes(total)}` : ""} transferred.`, 96 + ratio * 0.35, "Downloading");
  } else if (progress.stage === "downloading-nvidia-utils-signature") {
    setStatus("running", "Downloading NVIDIA signature", "Staging the detached nvidia-utils signature for appliance verification.", 96.36, "Downloading");
  } else if (progress.stage === "downloading-lib32-nvidia-utils") {
    setStatus("running", "Downloading 32-bit NVIDIA userspace", `${formatBytes(processed)}${total ? ` of ${formatBytes(total)}` : ""} transferred.`, 96.38 + ratio * 0.2, "Downloading");
  } else if (progress.stage === "downloading-lib32-nvidia-utils-signature") {
    setStatus("running", "Downloading 32-bit NVIDIA signature", "Staging the detached lib32-nvidia-utils signature for appliance verification.", 96.59, "Downloading");
  } else if (progress.stage === "downloading-nvidia-installer") {
    setStatus("running", "Preparing pinned NVIDIA installer", `Verified ${formatBytes(processed)} of ${formatBytes(total)} from the immutable support snapshot.`, 96.6 + ratio * 0.05, "Verifying");
  }
}

function flushPendingLogs() {
  if (!pendingLogChunks.length || !followingLogs) return;
  const content = pendingLogChunks.join("");
  pendingLogChunks = [];
  const fragment = document.createDocumentFragment();
  appendAnsiText(fragment, content, ansiState);
  elements.buildLog.append(fragment);
  elements.buildLog.scrollTop = elements.buildLog.scrollHeight;
  elements.logFollow.textContent = "Following live output";
  elements.logFollow.classList.remove("paused");
}

function queueLogChunk(content) {
  if (!content) return;
  pendingLogChunks.push(content);
  if (!followingLogs) {
    elements.logFollow.textContent = "New output · Jump to latest";
    elements.logFollow.classList.add("paused");
    return;
  }
  flushPendingLogs();
}

function applianceLogDelta(previous, current) {
  if (!previous) return current;
  if (current === previous) return "";
  if (current.startsWith(previous)) return current.slice(previous.length);

  // Once the backend's bounded tail rolls forward, find the shared suffix/prefix
  // and append only bytes that have not already been painted.
  const probeLength = Math.min(2048, previous.length);
  const probe = previous.slice(-probeLength);
  const overlapAt = current.lastIndexOf(probe);
  if (overlapAt >= 0) return current.slice(overlapAt + probeLength);
  return `\n\x1b[33m[log] Output advanced beyond the live buffer; resuming from the latest tail.\x1b[0m\n${current}`;
}

function renderLogs(applianceLog, source = "native") {
  const normalizedLog = normalizeTerminalText(applianceLog);
  if (!normalizedLog) return;
  const previous = source === "nvidia" ? lastNvidiaApplianceLog : lastApplianceLog;
  let delta = applianceLogDelta(previous, normalizedLog);
  if (!previous && source === "nvidia") {
    delta = `\n\x1b[1;35m[x86_64 installer appliance]\x1b[0m\n${delta}`;
  }
  if (source === "nvidia") lastNvidiaApplianceLog = normalizedLog;
  else lastApplianceLog = normalizedLog;
  queueLogChunk(delta);
}

function pauseLogFollowing() {
  if (!followingLogs) return;
  followingLogs = false;
  elements.logFollow.textContent = "Scroll paused";
  elements.logFollow.classList.add("paused");
}

function resumeLogFollowing() {
  followingLogs = true;
  flushPendingLogs();
}

async function refreshLogs() {
  if (refreshingLogs) return;
  refreshingLogs = true;
  try {
    const [nativeLog, nvidiaLog] = await Promise.allSettled([
      invoke("read_appliance_log"),
      invoke("read_nvidia_build_appliance_log"),
    ]);
    if (nativeLog.status === "fulfilled") renderLogs(nativeLog.value, "native");
    if (nvidiaLog.status === "fulfilled") renderLogs(nvidiaLog.value, "nvidia");
  } catch (error) { addStageLog(`Could not refresh appliance log: ${error}`); }
  finally { refreshingLogs = false; }
}

async function finish(state, message) {
  running = false;
  elements.cancelBuild.disabled = true;
  elements.closeWindow.classList.remove("hidden");
  await progressWindow.emitTo("main", "build-finished", { state, message });
}

async function stopAllWorkers() {
  const stops = await Promise.allSettled([
    invoke("stop_appliance"),
    invoke("stop_nvidia_build_appliance"),
  ]);
  for (const stop of stops) {
    if (stop.status === "rejected") addStageLog(`Shutdown warning: ${stop.reason}`);
  }
}

async function cancelBuild() {
  if (!running || cancelling) return;
  cancelling = true;
  elements.cancelBuild.disabled = true;
  setStatus("running", "Cancelling safely…", "Stopping all disposable builder workers.", 90, "Cancelling");
  addStageLog("Cancellation requested.");
  await stopAllWorkers();
  setStatus("cancelled", "Build cancelled", "The original image was not modified.", 100);
  addStageLog("Build cancelled; disposable image and NVIDIA workers stopped.");
  await finish("cancelled", "Image build cancelled.");
}

async function runBuild(request) {
  if (running) return;
  running = true;
  cancelling = false;
  lastApplianceLog = "";
  lastNvidiaApplianceLog = "";
  pendingLogChunks = [];
  ansiState = freshAnsiState();
  followingLogs = true;
  elements.buildLog.replaceChildren();
  elements.logFollow.textContent = "Following live output";
  elements.logFollow.classList.remove("paused");
  elements.closeWindow.classList.add("hidden");
  elements.cancelBuild.disabled = false;
  elements.inputName.textContent = request.name;
  const compressedInput = /\.(?:bz2|gz|xz)$/i.test(request.name);
  setStatus(
    "running",
    compressedInput ? "Normalizing compressed image" : "Preparing builder",
    compressedInput
      ? "Streaming the image into disposable raw storage; the original remains unchanged."
      : "Raw image detected; using it directly without another conversion.",
    8,
  );
  addStageLog(`Input: ${request.path}`);

  let logTimer = null;
  let nvidiaInstalled = false;
  try {
    const started = await invoke("start_appliance", { path: request.path });
    addStageLog(`Input preparation: detected ${started.input.sourceFormat}; engine=${started.input.normalizer}; normalized=${started.input.normalized}; ${started.input.sourceBytes} source bytes → ${started.input.imageBytes} raw image bytes.`);
    addStageLog(`Appliance session created on local port ${started.sshPort}.`);
    setStatus("running", "Starting builder", "Waiting for the Fedora guest readiness handshake.", 22);
    logTimer = setInterval(refreshLogs, 1000);

    while (!cancelling) {
      const status = await invoke("get_appliance_status");
      await refreshLogs();
      if (status.state === "ready") break;
      if (status.state === "failed" || status.state === "timedOut") throw new Error(status.message);
      await new Promise((resolve) => setTimeout(resolve, 750));
    }
    if (cancelling) return;

    addStageLog("STEAMOS_BUILDER_READY received.");
    setStatus("running", "Checking builder health", "Verifying the guest protocol, tools, architecture, and available space.", 45);
    const health = await invoke("guest_health");
    addStageLog(`Health: protocol ${health.protocolVersion}; ${health.operatingSystem}; ${health.architecture}; ${health.hostname}.`);
    addStageLog(`Health: ${health.requiredTools.length} required tools available; ${health.availableBytes} bytes free.`);
    if (cancelling) return;

    setStatus("running", "Verifying isolated transfer", "Sending a harmless probe through Fedora and checking the returned bytes.", 62, "Transferring");
    const transfer = await invoke("verify_guest_transfer");
    addStageLog(`Transfer: ${transfer.message}`);
    addStageLog(`Transfer: ${transfer.bytesVerified} bytes; guest SHA256 ${transfer.guestSha256}.`);
    if (cancelling) return;

    setStatus("running", "Inspecting synthetic disk", "Preparing a dedicated test filesystem, locking it read-only, and inspecting its metadata.", 74);
    const disk = await invoke("inspect_test_disk");
    addStageLog(`Synthetic disk: ${disk.diskBytes} bytes; ${disk.partitionTable} partition table; read-only=${disk.readOnly}.`);
    addStageLog(`Synthetic partition: offset ${disk.partitionStartBytes}; size ${disk.partitionBytes}; mounted=${disk.mounted}.`);
    addStageLog(`Synthetic filesystem: ${disk.filesystem}; label ${disk.filesystemLabel}; UUID ${disk.filesystemUuid}.`);
    if (cancelling) return;

    setStatus("running", "Testing safe mutation", "Cloning the synthetic source, writing only to the working copy, and verifying source immutability.", 82);
    const mutation = await invoke("mutate_test_marker");
    addStageLog(`Marker mutation: wrote ${mutation.markerPath} to the synthetic working copy.`);
    addStageLog(`Marker mutation: source unchanged=${mutation.sourceUnchanged}; working read-only=${mutation.workingReadOnly}; mounted=${mutation.mounted}.`);
    addStageLog(`Marker mutation: source SHA256 ${mutation.sourceSha256After}; working SHA256 ${mutation.workingSha256}.`);
    if (cancelling) return;

    setStatus("running", "Inspecting selected image", "Reading its disk layout without mounting or modifying it.", 88, "Inspecting");
    const image = await invoke("inspect_selected_image");
    addStageLog(`Selected image: ${image.diskBytes} bytes; ${image.partitionTable || "unrecognized"} partition table; read-only=${image.readOnly}.`);
    for (const node of image.nodes) {
      const details = [
        node.startBytes != null && `offset=${node.startBytes}`,
        node.filesystem && `filesystem=${node.filesystem}`,
        node.filesystemLabel && `label=${node.filesystemLabel}`,
        node.partitionLabel && `partition-label=${node.partitionLabel}`,
        node.partitionType && `partition-type=${node.partitionType}`,
        node.partitionUuid && `partition-UUID=${node.partitionUuid}`,
        node.filesystemUuid && `UUID=${node.filesystemUuid}`,
      ].filter(Boolean).join("; ");
      addStageLog(`Image node: ${node.path}; type=${node.nodeType}; size=${node.sizeBytes}; mounted=${node.mounted}${details ? `; ${details}` : ""}.`);
    }
    if (image.layout.recognized) {
      addStageLog(`SteamOS layout: recognized ${image.layout.scheme} with ${image.layout.roles.length} required partition roles.`);
      for (const role of image.layout.roles) {
        addStageLog(`SteamOS role: ${role.role} → ${role.path}; ${role.filesystem}; label=${role.partitionLabel}; size=${role.sizeBytes}.`);
      }
    } else {
      addStageLog(`warning: SteamOS layout is not recognized safely: ${image.layout.issues.join(" ")}`);
    }
    addStageLog(`Selected image SHA256: ${image.sourceSha256After}; unchanged=${image.sourceUnchanged}.`);
    if (image.input.normalized) {
      addStageLog(`Normalized image SHA256: ${image.imageSha256After}; unchanged=${image.imageUnchanged}.`);
    }
    if (cancelling) return;

    setStatus("running", "Preparing isolated working layer", "Verifying a disposable writable overlay without mounting or changing it.", 93);
    const working = await invoke("verify_working_image");
    addStageLog(`Working layer: ${working.overlayFormat}; ${working.workingBytes} bytes; layout matches source=${working.layoutMatches}.`);
    addStageLog(`Working isolation: source read-only=${working.sourceReadOnly}; working read-only=${working.workingReadOnly}; source mounted=${working.sourceMounted}; working mounted=${working.workingMounted}.`);
    if (cancelling) return;

    setStatus("running", "Writing harmless image marker", "Mounting only the disposable rootfs-A working layer and verifying the deterministic marker.", 95, "Mutating");
    const selectedMutation = await invoke("mutate_selected_marker");
    addStageLog(`Selected-image marker: wrote and re-opened ${selectedMutation.markerPath} on ${selectedMutation.targetPartition}.`);
    addStageLog(`Selected-image marker: filesystem=${selectedMutation.filesystem}; partition-label=${selectedMutation.targetPartitionLabel}; working read-only=${selectedMutation.workingReadOnly}; mounted=${selectedMutation.mounted}.`);
    addStageLog(`Selected-image safety: original unchanged=${selectedMutation.inputUnchanged}; SHA256 ${selectedMutation.inputSha256After}.`);
    const target = selectedMutation.system;
    const targetIdentity = [target.prettyName || target.osId || "Unknown SteamOS", target.versionId, target.buildId && `build ${target.buildId}`].filter(Boolean).join(" · ");
    addStageLog(`Target system: ${targetIdentity}; architecture=${target.architecture}.`);
    if (target.kernelVersions.length) {
      addStageLog(`Target kernels: ${target.kernelVersions.join(", ")}.`);
    } else {
      addStageLog("warning: No target kernel module directories were discovered; NVIDIA compatibility resolution will remain unavailable.");
    }
    if (cancelling) return;

    setStatus("running", "Assessing NVIDIA target", "Requiring an exact SteamOS version, x86_64 architecture, and one unambiguous target kernel.", 95.5, "Resolving");
    const nvidiaTarget = await invoke("assess_nvidia_target");
    if (nvidiaTarget.ready) {
      addStageLog(`NVIDIA target: ${nvidiaTarget.message}`);

      setStatus("running", "Resolving published NVIDIA support", "Looking for a verified publication matching the image's exact kernel.", 95.55, "Resolving");
      let nvidiaResolution = await invoke("resolve_published_nvidia", {
        sourceSelection: request.sourceSelection || "automatic",
      });
      let x86ApplianceReady = false;
      if (nvidiaResolution.status === "build_required") {
        const plan = nvidiaResolution.buildPlan;
        addStageLog(`NVIDIA on-demand plan: ${plan.nvidiaVersion} from ${plan.sourceBranch}@${plan.sourceCommit.slice(0, 12)} for exact kernel ${plan.kernelVersion}.`);
        addStageLog(`NVIDIA version baseline: ${plan.baselineRelease}; pinned support commit ${plan.supportCommit}.`);
        const approved = window.confirm(
          `No published NVIDIA artifact exactly matches this SteamOS kernel.\n\n` +
          `Build NVIDIA ${plan.nvidiaVersion} locally for:\n${plan.kernelVersion}\n\n` +
          "On Apple Silicon this x86_64 build uses software emulation and may take 30–60 minutes or longer. Continue?"
        );
        if (approved) {
          setStatus("running", "Starting exact-kernel NVIDIA build", "Handing the working image to the managed x86_64 Fedora appliance before the long local build.", 95.7, "Starting");
          const buildAppliance = await invoke("start_nvidia_install_appliance");
          addStageLog(`x86 build appliance: ${buildAppliance.acceleration}; working image attached exclusively after native shutdown.`);
          while (!cancelling) {
            const status = await invoke("get_nvidia_build_appliance_status");
            await refreshLogs();
            if (status.state === "ready") break;
            if (status.state === "failed" || status.state === "timedOut") throw new Error(status.message);
            await new Promise((resolve) => setTimeout(resolve, 750));
          }
          if (cancelling) return;
          x86ApplianceReady = true;
          setStatus("running", "Building exact-kernel NVIDIA modules", "Downloading authenticated Valve headers and compiling all five modules in isolated x86_64 Fedora. Live compiler output is shown below.", 96, "Compiling");
          nvidiaResolution = await invoke("build_nvidia_target_on_demand");
          const builtArtifact = nvidiaResolution.artifact;
          addStageLog(`NVIDIA on-demand artifact: trust=${builtArtifact.trust}; SHA256 ${builtArtifact.archiveSha256}.`);
          addStageLog("On-demand artifact passed exact-target, compiler, header-signature, provenance, vermagic, architecture, and module-hash validation.");
          const settings = await invoke("get_builder_settings");
          if (settings.autoReleaseVerifiedNvidia) {
            const maintainer = await invoke("get_github_maintainer_status");
            if (!maintainer.authorized) {
              addStageLog(`warning: Automated release is enabled, but maintainer access is unavailable: ${maintainer.message}`);
            } else {
              const publication = nvidiaResolution.publication;
              const releaseTag = `steamos-${publication.steamosVersion}-nvidia-${publication.nvidiaVersion}-k${publication.kernelVersion}`;
              const publishApproved = await confirmNvidiaRelease(
                `Repository: CorniiDog/open-gpu-kernel-modules-steamos-support\n` +
                `Tag: ${releaseTag}\n` +
                `Support commit: ${nvidiaResolution.buildPlan.supportCommit}\n` +
                `Source: ${nvidiaResolution.buildPlan.sourceBranch}@${nvidiaResolution.buildPlan.sourceCommit}\n` +
                `Trust: ${builtArtifact.trust}\n` +
                `SHA-256: ${builtArtifact.archiveSha256}`
              );
              if (publishApproved) {
                setStatus("running", "Publishing verified NVIDIA artifact", "Rechecking GitHub maintainer access, release identity, hashes, and collision policy before upload.", 96.35, "Publishing");
                const release = await invoke("publish_on_demand_nvidia_release");
                addStageLog(`NVIDIA release: ${release.message}`);
                if (release.url) addStageLog(`NVIDIA release URL: ${release.url}`);
              } else {
                addStageLog("NVIDIA release: maintainer declined publication; the verified local artifact remains build-local.");
              }
            }
          }
        } else {
          addStageLog("warning: Exact-kernel NVIDIA build was declined; continuing with a marker-only output.");
        }
      }
      if (nvidiaResolution.status === "compatible") {
        const publication = nvidiaResolution.publication;
        const artifact = nvidiaResolution.artifact;
        addStageLog(`NVIDIA artifact identity: ${publication.tag}; compatibility=${nvidiaResolution.compatibility}.`);
        addStageLog(`NVIDIA artifact: version ${publication.nvidiaVersion}; trust=${artifact.trust}; SHA256 ${artifact.archiveSha256}.`);
        addStageLog("NVIDIA artifact passed host-side checksum, provenance, exact-kernel, architecture, and five-module validation.");
        const userspace = await invoke("prepare_nvidia_userspace");
        for (const packageInput of userspace.packages) {
          addStageLog(`NVIDIA userspace: ${packageInput.name} ${packageInput.fullVersion}; SHA256 ${packageInput.packageSha256}.`);
        }
        addStageLog(`NVIDIA userspace signatures: ${userspace.signatureStatus}; exact packages are staged for the managed x86 installer.`);
        const installer = await invoke("prepare_nvidia_installer_bundle");
        addStageLog(`NVIDIA installer: pinned ${installer.repository}@${installer.commit}; ${installer.files.length} files verified.`);
        if (!x86ApplianceReady) {
          setStatus("running", "Starting x86 installer validation", "Handing the preserved working image to the managed x86_64 Fedora appliance.", 96.67, "Starting");
          const installerAppliance = await invoke("start_nvidia_install_appliance");
          addStageLog(`x86 installer appliance: ${installerAppliance.acceleration}; working image attached exclusively after native shutdown.`);
          while (!cancelling) {
            const status = await invoke("get_nvidia_build_appliance_status");
            await refreshLogs();
            if (status.state === "ready") break;
            if (status.state === "failed" || status.state === "timedOut") throw new Error(status.message);
            await new Promise((resolve) => setTimeout(resolve, 750));
          }
          if (cancelling) return;
        }
        setStatus("running", "Validating offline NVIDIA install", "Mounting rootfs-A and efi-A read-only, authenticating userspace, and checking the exact-kernel installer contract.", 96.8, "Validating");
        const validation = await invoke("validate_nvidia_install_handoff");
        addStageLog(`NVIDIA offline validation: ${validation.message}`);
        addStageLog(`NVIDIA trust: ${validation.trust}; keyring SHA256 ${validation.keyringSha256}; mounts released=${validation.mountsReleased}.`);
        for (const packageInput of validation.packages) {
          addStageLog(`NVIDIA signature verified: ${packageInput.name} ${packageInput.fullVersion}; signer ${packageInput.signer}.`);
        }
        setStatus("running", "Installing NVIDIA into working image", "Applying authenticated userspace, exact-kernel modules, firmware, depmod, and SteamOS initramfs changes only to the disposable overlay.", 96.85, "Installing");
        const installation = await invoke("install_nvidia_to_working_image");
        nvidiaInstalled = true;
        addStageLog(`NVIDIA installation: ${installation.message}`);
        addStageLog(`NVIDIA ${installation.nvidiaVersion} installed for ${installation.kernelVersion}; trust=${installation.trust}; mounts released=${installation.mountsReleased}.`);
        addStageLog("NVIDIA initramfs contents were checked in x86_64 Fedora; the exported image will now receive an independent read-only structural inspection.");
      } else if (nvidiaResolution.status !== "build_required") {
        addStageLog(`warning: ${nvidiaResolution.message}`);
        addStageLog(`NVIDIA publication status: ${nvidiaResolution.reason}; continuing with a marker-only output.`);
      }
    } else {
      addStageLog(`warning: ${nvidiaTarget.message}`);
      addStageLog(`NVIDIA target status: ${nvidiaTarget.status}; no driver artifact will be selected or built.`);
    }
    if (cancelling) return;

    setStatus("running", "Exporting raw image", "Stopping the mutation VM, flattening its working layer, and validating the result in a fresh appliance.", 97, "Exporting");
    const output = await invoke("export_marker_image");
    addStageLog(`Exported image: ${output.path}; ${output.bytes} bytes; raw layout=${output.layoutScheme}.`);
    addStageLog(`Build manifest: ${output.manifestPath}.`);
    addStageLog(`Export validation: marker=${output.markerPath}; SHA256 ${output.sha256}.`);
    addStageLog(`Source safety: original SHA256 ${output.sourceSha256}; unchanged=true.`);
    setStatus("complete", nvidiaInstalled ? "NVIDIA mutation complete" : "Marker image complete", "Finder opened the validated raw image.", 100);
    await finish("complete", `${nvidiaInstalled ? "NVIDIA-mutated image" : "Marker image"} created: ${output.path}`);
  } catch (error) {
    if (cancelling) return;
    addStageLog(`ERROR: ${error}`);
    await stopAllWorkers();
    setStatus("failed", "Build failed", String(error), 100);
    await finish("failed", `Image build failed: ${error}`);
  } finally {
    if (logTimer) clearInterval(logTimer);
    await refreshLogs();
  }
}

elements.cancelBuild.addEventListener("click", cancelBuild);
elements.closeWindow.addEventListener("click", () => progressWindow.hide());
elements.logFollow.addEventListener("click", resumeLogFollowing);
elements.buildLog.addEventListener("wheel", (event) => {
  if (event.deltaY < 0) pauseLogFollowing();
}, { passive: true });
elements.buildLog.addEventListener("scroll", () => {
  const distanceFromBottom = elements.buildLog.scrollHeight
    - elements.buildLog.clientHeight
    - elements.buildLog.scrollTop;
  if (distanceFromBottom > 24) {
    pauseLogFollowing();
  } else if (!followingLogs) {
    resumeLogFollowing();
  }
}, { passive: true });
elements.buildLog.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "a") {
    event.preventDefault();
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(elements.buildLog);
    selection.removeAllRanges();
    selection.addRange(range);
  }
});
await progressWindow.listen("build-requested", (event) => runBuild(event.payload));
await progressWindow.listen("input-progress", (event) => showInputProgress(event.payload));
await progressWindow.listen("nvidia-resolution-progress", (event) => showNvidiaResolutionProgress(event.payload));
await progressWindow.listen("build-progress-probe", () => progressWindow.emitTo("main", "build-progress-ready"));
await progressWindow.emitTo("main", "build-progress-ready");
await progressWindow.onCloseRequested(async (event) => {
  event.preventDefault();
  if (running) await cancelBuild();
  await progressWindow.hide();
});

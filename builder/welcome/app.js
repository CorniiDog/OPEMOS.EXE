"use strict";

const view = document.querySelector("#view");
const safetyMessage = document.querySelector("#safety-message");
const sessionToken = window.__OPEMOS_SESSION_TOKEN__;
const state = { bootstrap: null, mode: null, disk: null, polling: false, running: false };

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", "X-OPEMOS-Token": sessionToken, ...(options.headers || {}) },
  });
  const document = await response.json().catch(() => ({ error: "The controller returned an invalid response." }));
  if (!response.ok) throw new Error(document.error || `The controller returned ${response.status}.`);
  return document;
}

function button(label, action, className = "") {
  return `<button type="button" class="${className}" data-action="${action}">${label}</button>`;
}
function formatBytes(bytes) { return `${(Number(bytes) / 1_000_000_000).toFixed(1)} GB`; }
function setError(error) {
  safetyMessage.textContent = error instanceof Error ? error.message : String(error);
  safetyMessage.parentElement.classList.add("error");
}
function setSafe(message) {
  safetyMessage.textContent = message;
  safetyMessage.parentElement.classList.remove("error");
}

function home() {
  state.mode = null;
  state.disk = null;
  view.innerHTML = `
    <div class="welcome-layout">
      <div>
        <p class="lead">Choose an installation or recovery operation. Disk identity is checked again immediately before any change.</p>
        <div class="choices">
          <button class="choice" data-action="choose-install"><strong>Install SteamOS with NVIDIA drivers</strong><span>Erase one explicitly selected disk and install this image.</span></button>
          <button class="choice" data-action="choose-reinstall"><strong>Reinstall SteamOS with NVIDIA drivers</strong><span>Preserve games and personal files on a recognized SteamOS layout.</span></button>
          <button class="choice" data-action="rollback"><strong>Recovery</strong><span>Select a previously working NVIDIA-ready A/B slot.</span></button>
          <button class="choice" data-action="diagnostics"><strong>Diagnostics</strong><span>Review media identity, eligible disks, and the last installation result.</span></button>
        </div>
      </div>
      <aside class="feature-card">
        <img src="assets/install.svg" alt="A recovery image flowing safely into a computer">
        <span class="label">Designed for recovery</span>
        <h2>Install with the target clearly in view.</h2>
        <p>The OPEMOS-maintained installer excludes its own boot disk and revalidates the chosen physical device before Valve's installer begins.</p>
      </aside>
    </div>`;
  setSafe(state.bootstrap.mode === "simulation"
    ? "Safe simulation: no host disks, privileges, or installers are reachable."
    : "Ready. The running installation medium is excluded automatically.");
}

function eligibleDisks(mode) {
  return state.bootstrap.disks.filter((disk) => mode === "all" || disk.layout === "steamos");
}

function chooseDisk(mode) {
  state.mode = mode;
  state.disk = null;
  const disks = eligibleDisks(mode);
  view.innerHTML = `
    <div class="panel">
      <span class="label">${mode === "all" ? "Fresh installation" : "System reinstall"}</span>
      <h2>Select a whole physical disk</h2>
      <p class="lead">${disks.length ? "Only eligible targets are listed." : "No eligible target is currently available."}</p>
      <div class="disks">${disks.map((disk, index) => `
        <button class="disk" data-disk="${index}"><span><strong>${escapeHtml(disk.model)}</strong><small>${escapeHtml(disk.device)} · ${formatBytes(disk.bytes)} · ${escapeHtml(disk.transport)} · ${disk.layout === "steamos" ? "recognized SteamOS" : "blank or replaceable"}</small></span><span class="status">Eligible</span></button>`).join("")}</div>
      <div class="actions">${button("Back", "home", "secondary")}${button("Refresh disks", "refresh", "secondary")}${button("Continue", "confirm", "primary")}</div>
    </div>`;
}

async function refreshDisks() {
  const mode = state.mode;
  setSafe("Refreshing the protected physical-disk inventory…");
  try { state.bootstrap = await api("/api/bootstrap"); chooseDisk(mode); }
  catch (error) { setError(error); }
}

function confirmDisk() {
  if (!state.disk) { setError("Select an eligible disk before continuing."); return; }
  const basename = state.disk.device.split("/").pop();
  const phrase = `${state.mode === "all" ? "ERASE" : "REINSTALL"} ${basename}`;
  view.innerHTML = `
    <div class="panel">
      <span class="label">Final disk confirmation</span>
      <h2>${state.mode === "all" ? `Everything on ${escapeHtml(state.disk.device)} will be erased` : `SteamOS on ${escapeHtml(state.disk.device)} will be reinstalled`}</h2>
      <p class="lead warning">Type <strong>${escapeHtml(phrase)}</strong> exactly. The device identity will be rechecked before mutation.</p>
      <input id="phrase" autocomplete="off" spellcheck="false" placeholder="${escapeHtml(phrase)}" aria-label="Confirmation phrase">
      <div class="actions">${button("Back", "choose-again", "secondary")}${button("Begin installation", "begin", "danger")}</div>
    </div>`;
  view.querySelector("#phrase").focus();
}

async function begin() {
  const basename = state.disk.device.split("/").pop();
  const required = `${state.mode === "all" ? "ERASE" : "REINSTALL"} ${basename}`;
  const confirmation = view.querySelector("#phrase")?.value || "";
  if (confirmation !== required) { setError(`Confirmation did not match. Type ${required} exactly; nothing was changed.`); return; }
  state.running = true;
  renderProgress({ progress: 2, phase: "starting", message: "Starting protected installation." });
  try {
    await api("/api/install", { method: "POST", body: JSON.stringify({
      mode: state.mode, device: state.disk.device, identity: state.disk.identity, confirmation,
    }) });
    pollStatus();
  } catch (error) {
    state.running = false;
    chooseDisk(state.mode);
    setError(error);
  }
}

function phaseArtwork(phase) {
  if (phase.includes("slot") || phase.includes("verif") || phase === "complete")
    return ["assets/recovery.svg", "Recovery follows every slot", "Both A/B roots are checked before the result is accepted."];
  if (phase.includes("install"))
    return ["assets/gaming.svg", "Built for the big screen", "SteamOS and its matching NVIDIA stack are being installed together."];
  return ["assets/install.svg", "A deliberate installation", "The selected target is being checked and prepared safely."];
}

function renderProgress(operation) {
  const [image, title, copy] = phaseArtwork(operation.phase || "");
  const progress = Math.max(0, Math.min(100, Number(operation.progress) || 0));
  view.innerHTML = `
    <div class="panel progress-layout">
      <div><span class="label">${state.bootstrap.mode === "simulation" ? "Safe simulation" : "Protected installation"}</span>
        <h2>${escapeHtml((operation.phase || "working").replaceAll("-", " "))}</h2>
        <p class="lead warning">Do not power off the computer or disconnect either drive.</p>
        <div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${progress}"><i style="--progress:${progress}%"></i></div>
        <p class="lead">${escapeHtml(operation.message || "Working…")}</p>
      </div>
      <aside class="slide"><img src="${image}" alt="Installation progress illustration"><strong>${title}</strong><span>${copy}</span></aside>
    </div>`;
  setSafe(operation.terminal ? operation.message : "Installation is active. Keep the target and installation media connected.");
}

function failureScreen(operation) {
  view.innerHTML = `<div class="panel">
    <span class="label">Installation stopped safely</span>
    <h2>The target was not accepted as complete</h2>
    <p class="lead warning">${escapeHtml(operation.message || "The installation failed.")}</p>
    <p class="lead">Do not boot the target until diagnostics explain the failure. The installation media remains available.</p>
    <div class="actions">${button("Return home", "home", "secondary")}${button("Open diagnostics", "diagnostics", "primary")}</div>
  </div>`;
  setError(operation.message || "Installation failed. Open diagnostics for details.");
}

async function pollStatus() {
  if (state.polling) return;
  state.polling = true;
  try {
    while (state.running) {
      const operation = await api("/api/status");
      renderProgress(operation);
      if (operation.terminal) {
        state.running = false;
        if (operation.status === "complete") completionScreen();
        else failureScreen(operation);
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 350));
    }
  } catch (error) { state.running = false; setError(error); }
  finally { state.polling = false; }
}

async function diagnostics() {
  view.innerHTML = `<div class="panel"><span class="label">Installation-media diagnostics</span><h2>Collecting a bounded report…</h2></div>`;
  try {
    const report = await api("/api/diagnostics");
    view.innerHTML = `<div class="panel"><span class="label">Installation-media diagnostics</span><h2>Media and target report</h2><pre>${escapeHtml(report.text)}</pre><div class="actions">${button("Back", "home", "secondary")}</div></div>`;
  } catch (error) { home(); setError(error); }
}

async function rollback() {
  try {
    const result = await api("/api/rollback", { method: "POST", body: "{}" });
    view.innerHTML = `<div class="panel"><span class="label">Recovery</span><h2>${result.status === "simulated" ? "Recovery simulation" : "Recovery terminal opened"}</h2><p class="lead">The recovery tool verifies eligible NVIDIA-ready A/B slots before changing the default boot target.</p><div class="actions">${button("Back", "home", "primary")}</div></div>`;
  } catch (error) { setError(error); }
}

function completionScreen() {
  view.innerHTML = `<div class="panel completion-layout">
    <img src="assets/recovery.svg" alt="Verified A/B recovery slots">
    <div><span class="label">Installation complete · Maintained by OPEMOS</span><h2>SteamOS with NVIDIA drivers is ready to boot</h2>
      <p class="lead">Shut Down is recommended. Remove the installation USB after power-off, then boot from the installed drive.</p>
      <p class="lead warning">If you restart, remove the USB as the screen turns off or choose the installed disk from the boot menu.</p>
      <div class="actions">${button("Stay Here", "home", "secondary")}${button("Restart", "restart", "secondary")}${button("Shut Down", "shutdown", "primary")}</div>
    </div></div>`;
}

async function power(action) {
  try {
    const result = await api("/api/power", { method: "POST", body: JSON.stringify({ action }) });
    if (state.bootstrap.mode === "simulation") {
      view.innerHTML = `<div class="panel"><span class="label">Safe simulation</span><h2>${escapeHtml(action)} requested</h2><p class="lead">No host power service was called.</p><div class="actions">${button("Return home", "home", "primary")}</div></div>`;
    } else if (result.status === "requested") setSafe(`${action} requested. Keep the installation media connected until the screen turns off.`);
  } catch (error) { setError(error); }
}

async function closeApplication() {
  if (state.running) { setError("The installer cannot close while disk mutation is active."); return; }
  try { await api("/api/close", { method: "POST", body: "{}" }); }
  catch (error) { setError(error); }
}

view.addEventListener("click", (event) => {
  const target = event.target.closest("button");
  if (!target || target.disabled) return;
  if (target.dataset.disk !== undefined) {
    state.disk = eligibleDisks(state.mode)[Number(target.dataset.disk)];
    view.querySelectorAll(".disk").forEach((disk) => disk.classList.toggle("selected", disk === target));
    return;
  }
  const actions = {
    home, "choose-install": () => chooseDisk("all"), "choose-reinstall": () => chooseDisk("system"),
    "choose-again": () => chooseDisk(state.mode), refresh: refreshDisks, confirm: confirmDisk,
    begin, diagnostics, rollback, restart: () => power("restart"), shutdown: () => power("shutdown"),
  };
  actions[target.dataset.action]?.();
});
view.addEventListener("keydown", (event) => { if (event.key === "Enter" && event.target.id === "phrase") begin(); });
document.querySelector("#close-app").addEventListener("click", closeApplication);

async function initialize() {
  try {
    state.bootstrap = await api("/api/bootstrap");
    document.querySelector("#nvidia-version").textContent = state.bootstrap.nvidiaVersion;
    document.querySelector("#support-revision").textContent = state.bootstrap.supportRevision;
    document.querySelector("#environment").textContent = state.bootstrap.environment;
    const badge = document.querySelector("#environment-badge");
    badge.textContent = state.bootstrap.mode === "simulation" ? "Safe simulation" : "Installation media";
    badge.classList.toggle("simulation", state.bootstrap.mode === "simulation");
    home();
  } catch (error) {
    setError(error);
    view.innerHTML = `<div class="panel"><span class="label">Startup failed</span><h2>The installation controller is unavailable</h2><p class="lead">${escapeHtml(error.message)}</p></div>`;
  }
}

initialize();

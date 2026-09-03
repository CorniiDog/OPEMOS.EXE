"use strict";

const view = document.querySelector("#view");
const state = { action: "install", disk: null, progress: 0, timer: null };
const disks = [
  { id: "vda", name: "Synthetic SteamOS target", detail: "/dev/vda · 32.0 GB · VirtIO", eligible: true },
  { id: "vdb", name: "Booted installation media", detail: "/dev/vdb · 8.0 GB · USB", eligible: false, reason: "recovery-medium" },
  { id: "vdc", name: "Mounted data disk", detail: "/dev/vdc · 64.0 GB · VirtIO", eligible: false, reason: "mounted-or-swap-active" },
];

function button(label, action, className = "") {
  return `<button type="button" class="${className}" data-action="${action}">${label}</button>`;
}

function home() {
  state.disk = null;
  view.innerHTML = `
    <div class="welcome-layout">
      <div>
        <p class="lead">Choose an installation or recovery operation. Every device and result shown in this preview is synthetic.</p>
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
        <p>The OPEMOS-maintained installer rechecks the physical disk immediately before Valve's installer begins.</p>
      </aside>
    </div>`;
}

function chooseDisk(mode) {
  state.action = mode;
  view.innerHTML = `
    <div class="panel">
      <span class="label">${mode === "install" ? "Fresh installation" : "System reinstall"}</span>
      <h2>Select a whole physical disk</h2>
      <p class="lead">The running recovery medium and unavailable disks are excluded automatically.</p>
      <div class="disks">
        ${disks.filter((disk) => disk.eligible).map((disk) => `<button class="disk" data-disk="${disk.id}"><span><strong>${disk.name}</strong><small>${disk.detail}</small></span><span class="status">Eligible</span></button>`).join("")}
      </div>
      <div class="actions">${button("Back", "home", "secondary")}${button("Review diagnostics", "diagnostics", "secondary")}${button("Continue", "confirm", "primary")}</div>
    </div>`;
}

function confirmDisk() {
  if (!state.disk) {
    view.querySelector(".lead").textContent = "Select the synthetic target before continuing.";
    return;
  }
  const phrase = `${state.action === "install" ? "ERASE" : "REINSTALL"} vda`;
  view.innerHTML = `
    <div class="panel">
      <span class="label">Final disk confirmation</span>
      <h2>${state.action === "install" ? "Everything on /dev/vda would be erased" : "Both simulated OS slots would be replaced"}</h2>
      <p class="lead warning">This is a visual simulation. Type <strong>${phrase}</strong> to exercise the confirmation flow.</p>
      <input id="phrase" autocomplete="off" spellcheck="false" placeholder="${phrase}" aria-label="Confirmation phrase">
      <div class="actions">${button("Back", "choose-again", "secondary")}${button("Begin simulation", "begin", "danger")}</div>
    </div>`;
  view.querySelector("#phrase").focus();
}

function begin() {
  const required = `${state.action === "install" ? "ERASE" : "REINSTALL"} vda`;
  if (view.querySelector("#phrase").value !== required) {
    view.querySelector(".lead").textContent = `Confirmation did not match. Type ${required} exactly; nothing was changed.`;
    return;
  }
  state.progress = 6;
  view.innerHTML = `
    <div class="panel progress-layout">
      <div>
        <span class="label">Simulated installation</span><h2 id="stage">Validating the selected physical disk</h2>
        <p class="lead warning">Do not disconnect the target while a real installation is running.</p>
        <div class="progress"><i></i></div><p id="detail" class="lead">No host operation is running in this preview.</p>
      </div>
      <aside class="slide"><img id="feature-image" src="assets/install.svg" alt="Installation illustration"><strong id="feature-title">A deliberate installation</strong><span id="feature-copy">Your selected disk is identified and checked again before mutation.</span></aside>
    </div>`;
  const stages = [
    [18, "Preparing the target layout", "assets/install.svg", "A deliberate installation", "The source media stays separate while the selected target is prepared."],
    [56, "Running the protected Valve installation", "assets/gaming.svg", "Built for the big screen", "Matching NVIDIA graphics, Vulkan, video, and firmware are carried into the installed system."],
    [76, "Installing recovery into rootfs-A", "assets/recovery.svg", "Recovery follows every slot", "The persistent guardian records exact kernel and driver identity outside replaceable roots."],
    [88, "Installing recovery into rootfs-B", "assets/recovery.svg", "Both A/B slots are covered", "Updates do not need to leave the alternate system slot without a recovery path."],
    [96, "Verifying both A/B guardians", "assets/recovery.svg", "Trust, then verify", "The installer reopens both slots and checks the installed recovery identity before success."],
    [100, "Installation simulation complete", "assets/gaming.svg", "Ready for hardware testing", "Remove the installation medium after shutdown, then boot from the installed drive."],
  ];
  let index = 0;
  clearInterval(state.timer);
  state.timer = setInterval(() => {
    const [progress, stage, image, title, copy] = stages[index++];
    state.progress = progress;
    view.querySelector(".progress i").style.setProperty("--progress", `${progress}%`);
    view.querySelector("#stage").textContent = stage;
    view.querySelector("#feature-image").src = image;
    view.querySelector("#feature-title").textContent = title;
    view.querySelector("#feature-copy").textContent = copy;
    if (progress === 100) {
      clearInterval(state.timer);
      view.querySelector("#detail").innerHTML = `Both simulated slots passed identity verification.<div class="actions">${button("Return home", "home", "secondary")}${button("Finish", "complete", "primary")}</div>`;
    }
  }, 650);
}

function diagnostics() {
  view.innerHTML = `
    <div class="panel"><span class="label">Installation-media diagnostics</span><h2>Safe simulated inventory</h2>
      <pre>schema=1
supportRevision=305f1199f5745136902de1c88655a9192fb91de3
nvidiaVersion=575.64.05
status=ready

Synthetic SteamOS target  32.0 GB  [eligible]
Booted installation media  8.0 GB  [recovery-medium]
Mounted data disk  64.0 GB  [mounted-or-swap-active]</pre>
      <div class="actions">${button("Back", "home", "secondary")}</div>
    </div>`;
}

function completionScreen() {
  view.innerHTML = `<div class="panel completion-layout">
    <img src="assets/recovery.svg" alt="Verified A/B recovery slots">
    <div><span class="label">Installation complete · Maintained by OPEMOS</span><h2>SteamOS with NVIDIA drivers is ready to boot</h2>
      <p class="lead">Shut Down is recommended. Remove the installation USB after power-off, then boot from the installed disk.</p>
      <p class="lead warning">If you restart, remove the USB as the screen turns off or choose the installed disk from the boot menu.</p>
      <div class="actions">${button("Stay Here", "home", "secondary")}${button("Restart", "simulate-restart", "secondary")}${button("Shut Down", "simulate-shutdown", "primary")}</div>
    </div></div>`;
}

function simulatedPowerAction(action) {
  view.innerHTML = `<div class="panel"><span class="label">Safe simulation</span><h2>${action} requested</h2><p class="lead">A real installation would now ask systemd to ${action.toLowerCase()}. This macOS preview did not call any power or system service.</p><div class="actions">${button("Return to welcome", "home", "primary")}</div></div>`;
}

function rollback() {
  view.innerHTML = `<div class="panel"><span class="label">Recovery simulation</span><h2>Choose a verified slot</h2><p class="lead">Slot A is the current simulated slot. Slot B contains a structurally matching NVIDIA kernel payload.</p><div class="choices"><button class="disk" data-action="complete"><span><strong>rootfs-B</strong><small>SteamOS 3.8.16 · NVIDIA 575.64.05</small></span><span class="status">Eligible</span></button></div><div class="actions">${button("Back", "home", "secondary")}</div></div>`;
}

view.addEventListener("click", (event) => {
  const target = event.target.closest("button");
  if (!target) return;
  if (target.dataset.disk) {
    state.disk = target.dataset.disk;
    view.querySelectorAll(".disk").forEach((disk) => disk.classList.toggle("selected", disk === target));
    return;
  }
  const actions = {
    home, "choose-install": () => chooseDisk("install"), "choose-reinstall": () => chooseDisk("reinstall"),
    "choose-again": () => chooseDisk(state.action), confirm: confirmDisk, begin,
    diagnostics, rollback, complete: () => { clearInterval(state.timer); completionScreen(); },
    "simulate-restart": () => simulatedPowerAction("Restart"),
    "simulate-shutdown": () => simulatedPowerAction("Shut down"),
  };
  actions[target.dataset.action]?.();
});

view.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && event.target.id === "phrase") begin();
});

home();

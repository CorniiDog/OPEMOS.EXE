const ANSI_CSI = /\x1b\[[0-?]*[ -/]*[@-~]/g;
const ANSI_OSC = /\x1b\][^\x07]*(?:\x07|\x1b\\)/g;
const INSTALLER_PROGRESS_PREFIX = "STEAMOS_NVIDIA_PROGRESS ";

const INSTALLER_PROGRESS_STAGES = {
  holo_database: [64, "Reading the Holo package database", "validation"],
  hashing: [65, "Hashing an authenticated installer input", "validation"],
  archive_layout: [66, "Inspecting the NVIDIA module archive", "validation"],
  modules: [67, "Verifying exact-kernel NVIDIA modules", "validation"],
  userspace_packages: [68, "Verifying signed userspace packages", "validation"],
  dependency_closure: [69, "Resolving the package dependency closure", "validation"],
  storage_calculation: [70, "Calculating target storage requirements", "validation"],
  pacman_policy: [72, "Preparing the confined package transaction", "installation"],
  runtime_mounts: [73, "Attaching target runtime filesystems", "installation"],
  userspace_install: [75, "Installing authenticated NVIDIA userspace", "installation"],
  userspace_verification: [77, "Verifying installed userspace files", "installation"],
  module_install: [79, "Installing exact-kernel NVIDIA modules", "installation"],
  module_verification: [80, "Verifying all five installed modules", "installation"],
  grub_update: [81, "Updating NVIDIA boot arguments", "installation"],
  depmod: [82, "Refreshing module dependencies", "installation"],
  initramfs: [83, "Generating the SteamOS initramfs", "installation"],
  installation_state: [84, "Recording verified installation state", "installation"],
  mount_cleanup: [84, "Releasing installer mounts", "installation"],
};

const ROUTINE_LINE = /^(?:\[\s*\d+(?:\.\d+)?\]\s|\[\s*OK\s*\]|\s*(?:Starting|Started|Stopping|Stopped|Finished|Reached target|Listening on|Mounted|Mounting|Found device|Expecting device|Created slice|Activated swap|Activating swap|Closed|Set up automount)\b|UEFI firmware|ArmTrngLib|Tpm2|BdsDxe:|Error: Image at|Image type X64|error: \.\.\/\.\.\/grub-core\/|(?:invalid\s+)?environment block\.|\s*(?:serial port|terminal)\s+|isn't found\.$|sparse file not$|allowed\.$|\s*Booting `Fedora Linux|Fedora Linux \d+|Kernel .* on |enp\d|Try contacting this VM|steamos-builder login:|qemu-system-|QEMU: Terminated|cloud-init\[|P\+q6E616D65|\[\*+\s*\]\s+Job |^[M\r]$|\[[^\]]+\]\s+(?:CC|LD|AR|BTF|MODPOST)\b|\s*(?:CC|LD|AR|BTF|MODPOST)\s+\[M\]|make\[\d+\]: (?:Entering|Leaving) directory|\s*\[\s*\d+\/\d+\]|\s*\(\d+\/\d+\)|Updating and loading repositories:|Repositories loaded\.|\s*Fedora .*100%|Package .* is already installed\.|Package\s+Arch\s+Version|\s*[A-Za-z0-9@._+:-]+\s+(?:x86_64|any|noarch)\s+|Downloading Packages:|Running transaction|Complete!$|Last metadata expiration check:|Dependencies resolved\.|Package\s+Architecture\s+Version|Transaction Summary|\s*(?:Installing|Upgrading|Verifying|Preparing)\s*:|Total (?:download )?size|Total size of inbound packages|After this operation|Installed size:|Replacing:|Importing OpenPGP key|UserID\s*:|Fingerprint:|From\s*:|The key was successfully imported|>>>|-+$|Is this ok \[y\/N\])/i;

const NVIDIA_MILESTONES = [
  [32, "Preparing isolated NVIDIA build", /Installing Fedora offline-target build dependencies/i],
  [35, "Locating exact Valve headers", /Discovering exact Valve headers package/i],
  [38, "Downloading exact Valve headers", /Downloading exact Valve headers/i],
  [40, "Authenticating Valve headers", /Downloading Valve headers-package signature|headers.*signature.*verified/i],
  [43, "Preparing exact-kernel NVIDIA sources", /Using installed GCC|source (?:branch|commit)|Preparing.*NVIDIA.*source/i],
  [46, "Compiling NVIDIA core", /Building NVIDIA|\[\s*nvidia\s*\]\s+CC\b/i],
  [51, "Linking NVIDIA core", /LD \[M\]\s+nvidia\.o|\[\s*nvidia\s*\]\s+LD\b/i],
  [54, "Compiling companion NVIDIA modules", /\[\s*nvidia-(?:modeset|drm|uvm|peermem)\s*\]\s+CC\b/i],
  [57, "Validating all five NVIDIA modules", /MODPOST Module\.symvers|LD \[M\]\s+nvidia-(?:modeset|drm|uvm|peermem)\.ko/i],
  [59, "Packaging exact-kernel NVIDIA artifact", /BTF \[M\].*nvidia|Packaging.*(?:artifact|archive)/i],
  [61, "NVIDIA artifact ready", /Offline-target NVIDIA artifact created|artifact passed exact-target/i],
  [63, "Preparing offline installer", /\[NVIDIA offline-root validation\]|NVIDIA installer: pinned/i],
  [66, "Authenticating offline install inputs", /signature verified|Generating pacman master key|package keyring/i],
  [69, "Offline install inputs validated", /Offline-root NVIDIA inputs validated without mutation|validation_complete/i],
  [71, "Starting NVIDIA image mutation", /\[NVIDIA offline-root installation\]/i],
  [74, "Installing matching NVIDIA userspace", /target-root pacman|Installing.*nvidia-utils/i],
  [77, "Installing NVIDIA modules and firmware", /GSP firmware|Installing.*(?:kernel modules|firmware)|modules_install/i],
  [80, "Refreshing module dependencies", /\bdepmod\b/i],
  [82, "Generating SteamOS initramfs", /\bmkinitcpio\b|Generating.*initramfs/i],
  [84, "Validating installed NVIDIA image", /install_complete|Offline-root NVIDIA installation complete|initramfs contents were checked/i],
];

export function inferNvidiaDiagnosticMilestone(value) {
  const text = stripTerminalFormatting(value);
  let result = { progress: 30, label: "Preparing the isolated NVIDIA environment" };
  for (const [progress, label, pattern] of NVIDIA_MILESTONES) {
    if (pattern.test(text) && progress >= result.progress) result = { progress, label };
  }
  return result;
}

export function inferInstallerValidationProgress(value) {
  const normalized = stripTerminalFormatting(value);
  if (new TextEncoder().encode(normalized).length > 16 * 1024 * 1024) return null;
  const records = [];
  const previous = new Map();
  for (const rawLine of normalized.split("\n")) {
    const line = rawLine.trim();
    if (!line.startsWith(INSTALLER_PROGRESS_PREFIX)) continue;
    if (new TextEncoder().encode(line).length > 4096) return null;
    const payload = line.slice(INSTALLER_PROGRESS_PREFIX.length);
    const keys = [...payload.matchAll(/"((?:\\.|[^"\\])*)"\s*:/g)].map((match) => match[1]);
    if (new Set(keys).size !== keys.length) return null;
    let document;
    try {
      document = JSON.parse(payload);
    } catch {
      return null;
    }
    const stage = INSTALLER_PROGRESS_STAGES[document.phase];
    const attempt = Number(document.attempt);
    const indeterminate = document.indeterminate === true;
    const completed = indeterminate ? null : Number(document.completed);
    const total = indeterminate ? null : Number(document.total);
    const unit = document.unit;
    if (document.schemaVersion !== 1
        || !stage
        || typeof document.indeterminate !== "boolean"
        || !Number.isSafeInteger(attempt) || attempt < 0 || attempt > 1_000_000
        || (!indeterminate && !["bytes", "items"].includes(unit))
        || (completed !== null && (!Number.isSafeInteger(completed) || completed < 0))
        || (total !== null && (!Number.isSafeInteger(total) || total <= 0))
        || ((completed === null) !== (total === null))
        || (completed !== null && completed > total)) {
      return null;
    }
    if (!indeterminate) {
      const key = `${attempt}\0${document.phase}`;
      const prior = previous.get(key);
      if (prior && (completed < prior.completed || total !== prior.total || unit !== prior.unit)) return null;
      previous.set(key, { completed, total, unit });
    }
    records.push({
      attempt,
      completed,
      kind: stage[2],
      label: stage[1],
      overallProgress: stage[0],
      stage: document.phase,
      stepProgress: total === null ? null : completed / total,
      total,
      unit: indeterminate ? "none" : unit,
    });
  }
  return records.at(-1) ?? null;
}

export function stripInstallerProgressProtocol(value) {
  return stripTerminalFormatting(value)
    .split("\n")
    .filter((line) => !line.trim().startsWith(INSTALLER_PROGRESS_PREFIX))
    .join("\n");
}

export function summarizeBuildFailure(rawError, rawLog = "") {
  const log = stripInstallerProgressProtocol(rawLog);
  const contractMatches = [...log.matchAll(/^installer contract rejected:\s*([^\n]+)$/gm)];
  if (contractMatches.length) {
    const reason = contractMatches.at(-1)[1].trim().replace(/[.]+$/, "");
    return `Pinned support installer contract failed: ${reason}. No image mutation was accepted; update the support bundle and retry.`;
  }
  const safetyMatches = [...log.matchAll(/snapshot_target_execution\.py:\s*([^\n]+)/g)];
  if (safetyMatches.length) {
    const reason = safetyMatches.at(-1)[1].trim().replace(/[.]+$/, "");
    return `Installer safety check failed: ${reason}. No image mutation was accepted.`;
  }
  const supportMatches = [...log.matchAll(/^\[open-gpu-kernel-modules-steamos-support\]\s+([^\n]+)$/gm)];
  if (supportMatches.length) return supportMatches.at(-1)[1].trim();

  const cleanError = stripInstallerProgressProtocol(rawError)
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !/^[,{}\[\]"]/.test(line))
    .at(-1) || "The build worker stopped unexpectedly.";
  return cleanError.length > 360 ? `${cleanError.slice(0, 357)}…` : cleanError;
}

export function stripTerminalFormatting(value) {
  return String(value ?? "")
    .replace(ANSI_OSC, "")
    .replace(ANSI_CSI, "")
    .replace(/\r\n?/g, "\n")
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
}

export function redactDiagnosticSecrets(value) {
  return String(value ?? "")
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, "<private-key-redacted>")
    .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, "<github-token-redacted>")
    .replace(/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, "<github-token-redacted>")
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}/gi, "$1<redacted>")
    .replace(/\b(Authorization\s*:\s*)[^\n]+/gi, "$1<redacted>")
    .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi, "$1<credentials-redacted>@")
    .replace(/([?&](?:access_?token|auth|key|password|secret|token)=)[^&#\s]+/gi, "$1<redacted>")
    .replace(/\/Users\/[^/\s]+(?=\/)/g, "/Users/<user>")
    .replace(/\b[A-Za-z]:\\Users\\[^\\\s]+(?=\\)/g, "C:\\Users\\<user>")
    .replace(/\/home\/(?!steamos-builder(?:\/|\b))[^/\s]+(?=\/)/g, "/home/<user>");
}

function compactLines(lines) {
  const selected = [];
  let omitted = 0;
  let previous = null;
  let repeats = 0;
  const seen = new Set();

  const flushOmitted = () => {
    if (omitted > 0) selected.push(`[... ${omitted} routine or redundant line${omitted === 1 ? "" : "s"} omitted ...]`);
    omitted = 0;
  };

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].replace(/[ \t]+$/g, "");
    const trimmed = line.trim();
    if (!trimmed) {
      if (omitted > 0) continue;
      if (selected.length && selected[selected.length - 1] !== "") selected.push("");
      continue;
    }

    if (trimmed === previous) {
      repeats += 1;
      omitted += 1;
      continue;
    }
    if (repeats > 0) repeats = 0;
    previous = trimmed;

    if (seen.has(trimmed)) {
      omitted += 1;
      continue;
    }
    seen.add(trimmed);

    if (ROUTINE_LINE.test(trimmed)) {
      omitted += 1;
      continue;
    }

    flushOmitted();
    selected.push(line);
  }
  flushOmitted();
  return selected;
}

function boundSummary(lines) {
  const maxLines = 1200;
  const maxCharacters = 200_000;
  let bounded = lines;
  if (bounded.length > maxLines) {
    const removed = bounded.length - maxLines;
    bounded = [
      ...bounded.slice(0, 250),
      `[... ${removed} older diagnostic lines omitted to bound clipboard size ...]`,
      ...bounded.slice(-950),
    ];
  }
  let result = bounded.join("\n").trim();
  if (result.length > maxCharacters) {
    const tailLength = 150_000;
    const headLength = maxCharacters - tailLength;
    result = `${result.slice(0, headLength)}\n[... diagnostic text truncated to bound clipboard size ...]\n${result.slice(-tailLength)}`;
  }
  return result;
}

export function buildDiagnosticLog(rawLog, metadata = {}) {
  const sanitized = redactDiagnosticSecrets(stripInstallerProgressProtocol(rawLog));
  const compacted = boundSummary(compactLines(sanitized.split("\n")));
  const generatedAt = metadata.generatedAt || new Date().toISOString();
  const status = metadata.status || "Unknown";
  const inputName = redactDiagnosticSecrets(metadata.inputName || "Unknown input").split(/[\\/]/).pop();
  const header = [
    "SteamOS NVIDIA Image Builder — diagnostic log",
    `Generated: ${generatedAt}`,
    `Status: ${status}`,
    `Input: ${inputName || "Unknown input"}`,
    "Note: routine VM boot, compiler progress, repeated lines, host usernames, and credentials were removed. The full in-app log is unchanged.",
  ];
  return `${header.join("\n")}\n\n${compacted || "No diagnostic output has been recorded yet."}\n`;
}

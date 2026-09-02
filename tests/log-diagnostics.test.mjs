import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  buildDiagnosticLog,
  inferInstallerValidationProgress,
  inferNvidiaDiagnosticMilestone,
  redactDiagnosticSecrets,
  stripInstallerProgressProtocol,
  stripTerminalFormatting,
  summarizeBuildFailure,
} from "../src/log-diagnostics.js";

test("terminal formatting is removed without losing messages", () => {
  assert.equal(stripTerminalFormatting("\x1b[1;31mERROR\x1b[0m\rnext"), "ERROR\nnext");
});

test("NVIDIA log milestones advance build and installation progress", () => {
  assert.deepEqual(
    inferNvidiaDiagnosticMilestone("Installing Fedora offline-target build dependencies..."),
    { progress: 32, label: "Preparing isolated NVIDIA build" },
  );
  assert.deepEqual(
    inferNvidiaDiagnosticMilestone("Building NVIDIA 575.64.05\n  MODPOST Module.symvers"),
    { progress: 57, label: "Validating all five NVIDIA modules" },
  );
  assert.deepEqual(
    inferNvidiaDiagnosticMilestone("Offline-target NVIDIA artifact created.\n[NVIDIA offline-root installation]\nRunning depmod -b /target"),
    { progress: 80, label: "Refreshing module dependencies" },
  );
  assert.deepEqual(
    inferNvidiaDiagnosticMilestone("mkinitcpio completed\ninstall_complete"),
    { progress: 84, label: "Validating installed NVIDIA image" },
  );
});

test("structured installer validation progress is strict and measurable", () => {
  const prefix = "STEAMOS_NVIDIA_PROGRESS ";
  const marker = `${prefix}{"schemaVersion":1,"attempt":2,"phase":"hashing","indeterminate":false,"completed":3145728,"total":6291456,"unit":"bytes"}`;
  assert.deepEqual(inferInstallerValidationProgress(`older log\n${marker}`), {
    attempt: 2,
    completed: 3145728,
    kind: "validation",
    label: "Hashing an authenticated installer input",
    overallProgress: 65,
    stage: "hashing",
    stepProgress: 0.5,
    total: 6291456,
    unit: "bytes",
  });
  assert.equal(stripInstallerProgressProtocol(`before\n${marker}\nafter`), "before\nafter");
  assert.deepEqual(
    inferInstallerValidationProgress(`${prefix}{"schemaVersion":1,"attempt":0,"phase":"dependency_closure","indeterminate":true}`),
    {
      attempt: 0,
      completed: null,
      kind: "validation",
      label: "Resolving the package dependency closure",
      overallProgress: 69,
      stage: "dependency_closure",
      stepProgress: null,
      total: null,
      unit: "none",
    },
  );
  assert.equal(inferInstallerValidationProgress(`${prefix}{"schemaVersion":1,"attempt":1,"phase":"unknown","indeterminate":true}`), null);
  assert.equal(inferInstallerValidationProgress(`${prefix}{"schemaVersion":1,"attempt":1,"phase":"modules","indeterminate":false,"completed":6,"total":5,"unit":"items"}`), null);
  assert.equal(inferInstallerValidationProgress(`${marker}\n${prefix}{"schemaVersion":1,`), null);
  assert.equal(inferInstallerValidationProgress(`${prefix}{"schemaVersion":1,"schemaVersion":1,"attempt":1,"phase":"hashing","indeterminate":true}`), null);
  assert.equal(inferInstallerValidationProgress(`${prefix}{"schemaVersion":1,"attempt":2,"phase":"hashing","indeterminate":false,"completed":4,"total":5,"unit":"items"}\n${prefix}{"schemaVersion":1,"attempt":2,"phase":"hashing","indeterminate":false,"completed":3,"total":5,"unit":"items"}`), null);
  assert.notEqual(inferInstallerValidationProgress(marker.replace(/}$/, ',"future":{"accepted":true}}')), null);
});

test("structured installer mutation progress reports real package and module work", () => {
  const prefix = "STEAMOS_NVIDIA_PROGRESS ";
  assert.deepEqual(
    inferInstallerValidationProgress(`${prefix}{"schemaVersion":1,"attempt":2,"phase":"module_verification","indeterminate":false,"completed":3,"total":5,"unit":"items"}`),
    {
      attempt: 2,
      completed: 3,
      kind: "installation",
      label: "Verifying all five installed modules",
      overallProgress: 80,
      stage: "module_verification",
      stepProgress: 0.6,
      total: 5,
      unit: "items",
    },
  );
});

test("terminal failure summaries retain the root cause without progress protocol", () => {
  const progress = 'STEAMOS_NVIDIA_PROGRESS {"schemaVersion":1,"attempt":2,"phase":"hashing","indeterminate":false,"completed":4,"total":8,"unit":"bytes"}';
  const raw = `NVIDIA target build exited with exit status: 1: ${progress}`;
  const log = `${progress}\nsnapshot_target_execution.py: execution input has an unsafe parent: bin/bash\n[open-gpu-kernel-modules-steamos-support] Target-owned inputs are unsafe.`;
  assert.equal(
    summarizeBuildFailure(raw, log),
    "Installer safety check failed: execution input has an unsafe parent: bin/bash. No image mutation was accepted.",
  );
  assert.doesNotMatch(buildDiagnosticLog(log), /STEAMOS_NVIDIA_PROGRESS/);
});

test("support contract failures outrank unrelated appliance cleanup output", () => {
  const log = [
    "[OPEMOS] Offline-root NVIDIA inputs validated without mutation.",
    "installer contract rejected: progress record regressed",
    ">>> ==> Updating trust database...",
  ].join("\n");
  assert.equal(
    summarizeBuildFailure(
      "NVIDIA appliance command exited with exit status: 1: >>> ==> Updating trust database...",
      log,
    ),
    "Pinned support installer contract failed: progress record regressed. No image mutation was accepted; update the support bundle and retry.",
  );
});

test("progress-window diagnostics remain in the fixed log toolbar", async () => {
  const [html, css, script] = await Promise.all([
    readFile(new URL("../src/build.html", import.meta.url), "utf8"),
    readFile(new URL("../src/build.css", import.meta.url), "utf8"),
    readFile(new URL("../src/build.js", import.meta.url), "utf8"),
  ]);
  const tools = html.match(/<div class="log-tools">([\s\S]*?)<\/div>/)?.[1] || "";
  assert.match(tools, /id="copy-diagnostic-log"/);
  assert.match(tools, /id="log-follow"/);
  assert.ok(tools.indexOf("copy-diagnostic-log") < tools.indexOf("log-follow"));
  assert.match(css, /\.actions\s*\{[^}]*min-height:\s*41px/s);
  assert.match(css, /\.logs-card\s*\{[^}]*min-height:\s*0/s);
  const resume = script.match(/function resumeLogFollowing\(\) \{([\s\S]*?)\n\}/)?.[1] || "";
  assert.match(resume, /followingLogs\s*=\s*true/);
  assert.match(resume, /flushPendingLogs\(\)/);
  assert.match(resume, /buildLog\.scrollTop\s*=\s*elements\.buildLog\.scrollHeight/);
  assert.match(resume, /logFollow\.textContent\s*=\s*"Following live output"/);
  assert.match(resume, /logFollow\.classList\.remove\("paused"\)/);
});

test("progress-window title starts below the macOS separator", async () => {
  const css = await readFile(new URL("../src/build.css", import.meta.url), "utf8");
  const chromeCss = await readFile(new URL("../src/window-chrome.css", import.meta.url), "utf8");
  const html = await readFile(new URL("../src/build.html", import.meta.url), "utf8");
  assert.match(html, /href="\/window-chrome\.css"/);
  assert.match(chromeCss, /--window-chrome-line:\s*37px/);
  assert.match(css, /\.platform-macos \.progress-shell\s*\{[^}]*padding-top:\s*50px;/);
});

test("credentials and host usernames are redacted", () => {
  const value = redactDiagnosticSecrets(
    "Input: /Users/connor/Downloads/image.img\nAuthorization: Bearer github_pat_abcdefghijklmnopqrstuvwxyz\nhttps://me:secret@example.com/file?token=secret",
  );
  assert.match(value, /\/Users\/<user>\/Downloads\/image\.img/);
  assert.doesNotMatch(value, /connor|github_pat_|me:secret|token=secret/);
});

test("diagnostic copy drops routine noise and retains failure context", () => {
  const raw = [
    "[    0.100] Linux boot noise",
    "[    0.200] Linux boot noise",
    "[  OK  ] Started systemd-journald.service - Journal Service.",
    "         Starting cloud-init-network.service - Cloud-init: Network Stage...",
    "error: ../../grub-core/commands/loadenv.h:read_envblk_file:51:invalid",
    "environment block.",
    "CC [M] module.o",
    "[ nvidia ] CC kernel-open/nvidia/nv.o",
    "[builder] NVIDIA offline validation started",
    "package database: /usr/lib/holo/pacmandb",
    "ERROR: package_dependency_unsatisfied: no package satisfies egl-wayland",
    "QEMU: Terminated",
  ].join("\n");
  const result = buildDiagnosticLog(raw, {
    generatedAt: "2026-08-31T00:00:00.000Z",
    inputName: "/Users/connor/Downloads/recovery.img",
    status: "Failed: Build failed",
  });
  assert.match(result, /Input: recovery\.img/);
  assert.match(result, /package_dependency_unsatisfied/);
  assert.match(result, /\/usr\/lib\/holo\/pacmandb/);
  assert.doesNotMatch(result, /Linux boot noise|systemd-journald|cloud-init-network|grub-core|environment block|CC \[M\]|QEMU: Terminated|\/Users\/connor/);
});

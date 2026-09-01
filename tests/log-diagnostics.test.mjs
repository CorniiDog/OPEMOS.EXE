import test from "node:test";
import assert from "node:assert/strict";

import {
  buildDiagnosticLog,
  inferInstallerValidationProgress,
  inferNvidiaDiagnosticMilestone,
  redactDiagnosticSecrets,
  stripInstallerProgressProtocol,
  stripTerminalFormatting,
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

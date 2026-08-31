import test from "node:test";
import assert from "node:assert/strict";

import {
  buildDiagnosticLog,
  inferNvidiaDiagnosticMilestone,
  redactDiagnosticSecrets,
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
  assert.doesNotMatch(result, /Linux boot noise|CC \[M\]|QEMU: Terminated|\/Users\/connor/);
});

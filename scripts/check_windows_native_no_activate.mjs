#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

function requireText(text, value, label) {
  if (!text.includes(value)) throw new Error(`Native no-activate proof must preserve ${label}.`);
}

export function validateNativeNoActivateProof(app, launcher) {
  requireText(app, 'std::env::var("OPEMOS_NATIVE_NO_ACTIVATE_PROOF").as_deref() == Ok("1")', "the exact process-scoped app gate");
  requireText(app, "if !native_no_activate_proof", "hidden startup under the proof gate");
  requireText(launcher, "$info.Environment['OPEMOS_NATIVE_NO_ACTIVATE_PROOF']='1'", "child-only proof environment");
  requireText(launcher, "SetWinEventHook(3,3", "the foreground activation event hook");
  requireText(launcher, "[OpemosNoActivateNative]::AssertGuard()", "foreground checks around every phase");
  requireText(launcher, "ExpectedForegroundProcessId", "the expected game process identity");
  requireText(launcher, "ExpectedForegroundExecutableSha256", "the expected game executable identity");
  requireText(launcher, "Exactly one existing leftmost portrait monitor is required.", "unambiguous portrait-monitor selection");
  requireText(launcher, "SWP_NOACTIVATE", "no-activate placement");
  requireText(launcher, "The OPEMOS window is not wholly contained by the left portrait monitor.", "post-placement bounds verification");
  requireText(launcher, "Stop-Process -Id $process.Id -Force", "owned candidate cleanup");
  requireText(launcher, "Remove-Item -LiteralPath $PSCommandPath", "transient launcher cleanup");
  if (/Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|ChangeDisplaySettings|DisplaySwitch|reg\.exe|Stop-Process\s+-(?:Name|InputObject)/i.test(launcher)) {
    throw new Error("Native no-activate proof must not change registry, display, system, or unrelated process state.");
  }
  return true;
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    validateNativeNoActivateProof(
      await readFile(path.join(root, "src-tauri", "src", "app.rs"), "utf8"),
      await readFile(path.join(root, "scripts", "windows-native-no-activate-proof.ps1"), "utf8"),
    );
  } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}

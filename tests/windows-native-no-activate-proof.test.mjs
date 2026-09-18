import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateNativeNoActivateProof } from "../scripts/check_windows_native_no_activate.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const app = await readFile(path.join(root, "src-tauri", "src", "app.rs"), "utf8");
const launcher = await readFile(path.join(root, "scripts", "windows-native-no-activate-proof.ps1"), "utf8");

test("native proof is process-scoped, no-activate, foreground-bound, portrait-bound, and self-cleaning", () => {
  assert.equal(validateNativeNoActivateProof(app, launcher), true);
});

for (const [name, mutate, expected] of [
  ["process-scoped app gate", (a, l) => [a.replace('std::env::var("OPEMOS_NATIVE_NO_ACTIVATE_PROOF").as_deref() == Ok("1")', "false"), l], /process-scoped app gate/],
  ["foreground event hook", (a, l) => [a, l.replace("SetWinEventHook(3,3", "SetWinEventHook(4,4")], /foreground activation event hook/],
  ["game executable identity", (a, l) => [a, l.replaceAll("ExpectedForegroundExecutableSha256", "IgnoredForegroundHash")], /game executable identity/],
  ["no-activate placement", (a, l) => [a, l.replaceAll("SWP_NOACTIVATE", "SWP_FRAMECHANGED")], /no-activate placement/],
  ["portrait containment", (a, l) => [a, l.replace("The OPEMOS window is not wholly contained by the left portrait monitor.", "ignored")], /post-placement bounds verification/],
  ["owned cleanup", (a, l) => [a, l.replace("Stop-Process -Id $process.Id -Force", "Write-Output skipped")], /owned candidate cleanup/],
  ["forbidden registry mutation", (a, l) => [a, `${l}\nSet-ItemProperty HKCU:\\Software\\OPEMOS Focus 1`], /must not change registry/],
]) {
  test(`native proof rejects missing ${name}`, () => {
    const [changedApp, changedLauncher] = mutate(app, launcher);
    assert.throws(() => validateNativeNoActivateProof(changedApp, changedLauncher), expected);
  });
}

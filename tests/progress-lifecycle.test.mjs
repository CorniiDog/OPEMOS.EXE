import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const script = await readFile(new URL("../src/build.js", import.meta.url), "utf8");
const appliance = await readFile(new URL("../src-tauri/src/appliance.rs", import.meta.url), "utf8");
const installer = await readFile(new URL("../src-tauri/src/installer.rs", import.meta.url), "utf8");

test("native progress close always confirms both QEMU managers stopped", () => {
  assert.match(script, /onCloseRequested[\s\S]*if \(await cancelBuild\(\)\) await hideProgressWindow\(\);/);
  assert.match(script, /invoke\("stop_appliance"\)/);
  assert.match(script, /invoke\("stop_nvidia_build_appliance"\)/);
  assert.match(script, /native\.state === "stopped" && nvidia\.state === "stopped"/);
  assert.match(script, /Timed out waiting for every managed QEMU worker to stop/);
  assert.doesNotMatch(script, /if \(running\) await cancelBuild\(\)/);
});

test("late x86 startup results are discarded after cancellation", () => {
  for (const source of [appliance, installer]) {
    assert.match(source, /let prepared = prepare_nvidia_build_session/);
    assert.match(source, /if cancel\.load\(Ordering::Relaxed\) \{[\s\S]{0,180}drop\(prepared\);[\s\S]{0,220}manager\.starting = false;/);
  }
});

test("closing during release confirmation resolves the pending modal before cleanup", () => {
  assert.match(script, /let releaseConfirmationCancel = null;/);
  assert.match(script, /function cancelPendingReleaseConfirmation\(\)[\s\S]*releaseConfirmationCancel\(\)/);
  assert.match(script, /async function cancelBuild\(\)[\s\S]*cancelling = true;\s*cancelPendingReleaseConfirmation\(\);/);
  assert.match(script, /if \(settled\) return;[\s\S]*if \(elements\.releaseDialog\.open\) elements\.releaseDialog\.close\(\)/);
});

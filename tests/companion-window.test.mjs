import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const html = await readFile(new URL("../src/index.html", import.meta.url), "utf8");
const css = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
const main = await readFile(new URL("../src/main.js", import.meta.url), "utf8");
const build = await readFile(new URL("../src/build.js", import.meta.url), "utf8");
const maintainer = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
const nativeWindows = await readFile(new URL("../src-tauri/src/windows.rs", import.meta.url), "utf8");

test("companion windows remain native children of the main window", () => {
  assert.equal([...nativeWindows.matchAll(/\.parent\(&main\)/g)].length, 2);
  assert.equal([...nativeWindows.matchAll(/\.set_focus\(\)/g)].length, 4);
  assert.doesNotMatch(nativeWindows, /always_on_top/);
});

test("the rear main window is dimmed and inert while a companion is active", () => {
  assert.match(html, /id="companion-scrim"[^>]*class="companion-scrim hidden"/);
  assert.match(html, /id="app-shell" class="app-shell"/);
  assert.match(css, /\.companion-scrim\s*\{[^}]*z-index:\s*100;[^}]*background:\s*rgba\(2, 6, 10, \.58\);/);
  assert.match(main, /elements\.appShell\.inert = active;/);
  assert.match(main, /mainWindow\.onFocusChanged/);
  assert.match(main, /companion\.setFocus\(\)/);
});

test("both companion close paths release the rear-window interaction lock", () => {
  assert.match(build, /emitTo\("main", "companion-window-hidden", \{ label: "build-progress" \}\)/);
  assert.match(maintainer, /emitTo\("main", "companion-window-hidden", \{ label: "maintainer-workspace" \}\)/);
  assert.match(main, /listen\("companion-window-hidden"/);
});

test("build completion waits for the progress window before changing the main workflow", () => {
  assert.match(main, /if \(activeCompanion === "build-progress"\) \{\s*pendingBuildFinished = event\.payload;\s*return;/);
  assert.match(main, /payload\.label === "build-progress" && pendingBuildFinished/);
  assert.match(build, /export_marker_image", \{ revealInFinder: false \}/);
  assert.match(main, /if \(activeExportMode === "image"\) \{\s*await revealCompletedImage\(output\.path\);/);
});

test("USB builds reselect only the exact pre-build device and defer Finder until verified", () => {
  assert.match(main, /deviceIdentifier: selectedUsb\.value,[\s\S]*identityToken: selectedUsb\.dataset\.identityToken/);
  assert.match(main, /option\.value === preferredTarget\.deviceIdentifier[\s\S]*option\.dataset\.identityToken === preferredTarget\.identityToken/);
  assert.match(main, /if \(restored\) \{\s*setUsbMenuOpen\(true\);/);
  assert.match(main, /if \(activeExportMode === "both"\) \{\s*const revealed = await revealCompletedImage\(completedOutput\.path\);/);
});

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const html = await readFile(new URL("../src/index.html", import.meta.url), "utf8");
const css = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
const main = await readFile(new URL("../src/main.js", import.meta.url), "utf8");
const build = await readFile(new URL("../src/build.js", import.meta.url), "utf8");
const maintainer = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
const nativeWindows = await readFile(new URL("../src-tauri/src/windows.rs", import.meta.url), "utf8");
const nativeApp = await readFile(new URL("../src-tauri/src/app.rs", import.meta.url), "utf8");
const mainCapability = JSON.parse(await readFile(new URL("../src-tauri/capabilities/default.json", import.meta.url), "utf8"));

test("companion windows remain native children of the main window", () => {
  assert.match(nativeWindows, /pub\(crate\) async fn open_progress_window/);
  assert.equal([...nativeWindows.matchAll(/\.parent\(&main\)/g)].length, 2);
  assert.equal([...nativeWindows.matchAll(/\.set_focus\(\)/g)].length, 4);
  assert.match(nativeWindows, /fn center_over_parent[\s\S]*\.outer_position\(\)[\s\S]*\.set_position/);
  assert.equal([...nativeWindows.matchAll(/center_over_parent\(&(?:progress|window), &main\)\?/g)].length, 4);
  assert.doesNotMatch(nativeWindows, /always_on_top/);
});

test("main window leaves companion visibility to native commands instead of denied ACL calls", () => {
  assert.doesNotMatch(main, /progressWindow\.(?:show|isVisible|hide)\(\)/);
  assert.match(main, /invoke\("open_progress_window"\)/);
  assert.match(main, /invoke\("hide_progress_window"\)/);
  assert.match(nativeWindows, /pub\(crate\) fn hide_progress_window[\s\S]*get_webview_window\("build-progress"\)[\s\S]*\.hide\(\)/);
  assert.match(nativeApp, /windows::open_progress_window,[\s\S]*windows::hide_progress_window,/);
  assert.doesNotMatch(mainCapability.permissions.join("\n"), /core:window:allow-(?:show|is-visible|hide)/);
});

test("Windows image commands stay hidden and elevation belongs to the main window", async () => {
  const image = await readFile(new URL("../src-tauri/src/image.rs", import.meta.url), "utf8");
  const appliance = await readFile(new URL("../src-tauri/src/appliance.rs", import.meta.url), "utf8");
  const nvidia = await readFile(new URL("../src-tauri/src/nvidia.rs", import.meta.url), "utf8");
  const library = await readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  assert.match(library, /fn child_command[\s\S]*CREATE_NO_WINDOW[\s\S]*creation_flags/);
  assert.doesNotMatch(appliance, /Command::new\(/);
  assert.doesNotMatch(nvidia, /Command::new\(/);
  assert.match(image, /fn hidden_windows_command[\s\S]*CREATE_NO_WINDOW[\s\S]*creation_flags/);
  assert.equal([...image.matchAll(/hidden_windows_command\("powershell\.exe"\)/g)].length, 3);
  assert.doesNotMatch(image, /Command::new\("powershell\.exe"\)/);
  assert.match(image, /get_webview_window\("main"\)/);
  assert.match(image, /\.and_then\(\|window\| window\.hwnd\(\)\.ok\(\)\)/);
  assert.match(image, /launch_elevated_windows_usb_writer\([\s\S]*owner_window/);
  assert.match(image, /ShellExecuteInfoW \{[\s\S]*hwnd: owner_window as \*mut c_void/);
  assert.match(image, /mask: 0x0000_0040,[\s\S]*show: 1,/);
  assert.match(image, /GetLastError[\s\S]*1223 =>[\s\S]*8235 =>[\s\S]*signed and validated[\s\S]*system error \{error\}/);
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

test("completion commits before the progress window closes into USB review", () => {
  assert.match(main, /applyBuildFinished\(event\.payload, \{\s*openUsbReview: activeCompanion !== "build-progress",\s*\}\)/);
  assert.match(main, /pendingUsbReview = !openUsbReview;/);
  assert.match(main, /payload\.label === "build-progress" && pendingUsbReview/);
  assert.match(build, /export_marker_image", \{ revealInFinder: false \}/);
  assert.match(main, /payload\.label === "build-progress" && pendingUsbReview[\s\S]*revealUsbImaging\(\{ preferredTarget \}\)/);
  assert.doesNotMatch(main, /event\.payload\?\.state === "complete"[\s\S]*progressWindow\?\.hide\(\)/);
});

test("USB builds reselect only the exact pre-build device and defer Finder until verified", () => {
  assert.match(build, /await finish\("complete",/);
  assert.doesNotMatch(build, /if \(usbRequested\) \{\s*await hideProgressWindow\(\)\.catch/);
  assert.match(build, /ready for USB Imaging/);
  assert.match(main, /deviceIdentifier: selectedUsb\.value,[\s\S]*identityToken: selectedUsb\.dataset\.identityToken/);
  assert.match(main, /option\.value === preferredTarget\.deviceIdentifier[\s\S]*option\.dataset\.identityToken === preferredTarget\.identityToken/);
  assert.match(main, /async function revealUsbImaging[\s\S]*usbImagingRefreshPath !== outputPath[\s\S]*refreshUsbTargets\(preferredTarget\)/);
  assert.match(main, /pendingUsbReview = !openUsbReview;[\s\S]*if \(openUsbReview\)[\s\S]*revealUsbImaging\(\{ preferredTarget \}\)/);
  assert.doesNotMatch(main, /if \(openUsbReview\) setUsbMenuOpen\(true\)/);
  assert.doesNotMatch(main, /if \(!finalUsbReady\) setUsbMenuOpen\(false\);/);
  assert.match(main, /preferred\.selected = true;\s*renderUsbTargetSelection\(\);\s*return true;/);
  assert.doesNotMatch(main, /preferred\.selected = true;\s*elements\.usbTarget\.dispatchEvent/);
  assert.match(main, /if \(activeExportMode === "both" && !completedOutputImported\) \{\s*const revealed = await revealCompletedImage\(completedOutput\.path\);/);
});

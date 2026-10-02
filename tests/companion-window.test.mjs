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
  assert.match(main, /invoke\("is_progress_window_visible"\)/);
  assert.match(nativeWindows, /pub\(crate\) fn hide_progress_window[\s\S]*get_webview_window\("build-progress"\)[\s\S]*\.hide\(\)/);
  assert.match(nativeWindows, /pub\(crate\) fn is_progress_window_visible[\s\S]*get_webview_window\("build-progress"\)[\s\S]*\.is_visible\(\)/);
  assert.match(nativeApp, /windows::open_progress_window,[\s\S]*windows::hide_progress_window,[\s\S]*windows::is_progress_window_visible,/);
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
  assert.equal([...image.matchAll(/hidden_windows_command\("powershell\.exe"\)/g)].length, 2);
  assert.match(image, /fn discover_usb_targets[\s\S]*bounded_command_output_with_limits\([\s\S]*Path::new\("powershell\.exe"\)/);
  assert.doesNotMatch(image, /Command::new\("powershell\.exe"\)/);
  assert.match(image, /get_webview_window\("main"\)/);
  assert.match(image, /\.and_then\(\|window\| window\.hwnd\(\)\.ok\(\)\)/);
  assert.match(image, /launch_elevated_windows_usb_writer\([\s\S]*owner_window/);
  assert.match(image, /fn launch_exact_elevated_writer\([\s\S]*verify_windows_elevation_candidate\(executable\)\?;[\s\S]*ShellExecuteExW/);
  assert.match(image, /fn verify_windows_elevation_candidate\([\s\S]*ValidateAdminCodeSignatures[\s\S]*WinVerifyTrust[\s\S]*trusted Authenticode-signed executables[\s\S]*selected USB was not changed/);
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
  assert.match(main, /function completeBuildProgressDismissal\(\)[\s\S]*setCompanionMode\(\)[\s\S]*pendingUsbReview = false;[\s\S]*revealUsbImaging/);
});

test("completion commits before the progress window closes into USB review", () => {
  assert.match(main, /applyBuildFinished\(event\.payload, \{\s*openUsbReview: activeCompanion !== "build-progress",\s*\}\)/);
  assert.match(main, /revealCompletedUsbReview = openUsbReview \|\| !progressVisible;/);
  assert.match(main, /pendingUsbReview = !revealCompletedUsbReview;/);
  assert.match(main, /if \(!pendingUsbReview\) return;/);
  assert.match(build, /export_marker_image", \{ revealInFinder: false \}/);
  assert.match(main, /function completeBuildProgressDismissal\(\)[\s\S]*revealUsbImaging\(\{ preferredTarget \}\)/);
  assert.doesNotMatch(main, /event\.payload\?\.state === "complete"[\s\S]*progressWindow\?\.hide\(\)/);
});

test("USB review survives the progress-close versus completed-image inspection race", () => {
  assert.match(main, /progressVisible = await invoke\("is_progress_window_visible"\)[\s\S]*if \(!progressVisible\) completeBuildProgressDismissal\(\);[\s\S]*revealCompletedUsbReview = openUsbReview \|\| !progressVisible;/);
  assert.match(main, /pendingUsbReview = !revealCompletedUsbReview;/);
  assert.match(main, /activeBuildContext = null;[\s\S]*buildRunning = false;[\s\S]*elements\.refreshUsbTargets\.disabled = false;[\s\S]*if \(revealCompletedUsbReview\) \{[\s\S]*await revealUsbImaging/);
  assert.doesNotMatch(main, /pendingUsbReview = !openUsbReview;/);
});

test("a natively hidden progress window cannot leave the main controls inert", () => {
  assert.match(main, /async function focusActiveCompanion\(\)[\s\S]*invoke\("is_progress_window_visible"\)[\s\S]*if \(!visible && label === activeCompanion\) \{[\s\S]*completeBuildProgressDismissal\(\);[\s\S]*return;/);
  assert.match(main, /function completeBuildProgressDismissal\(\)[\s\S]*activeCompanion === "build-progress"[\s\S]*setCompanionMode\(\)/);
});

test("USB builds reselect only the exact pre-build device and defer Finder until verified", () => {
  assert.match(build, /await finish\("complete",/);
  assert.doesNotMatch(build, /if \(usbRequested\) \{\s*await hideProgressWindow\(\)\.catch/);
  assert.match(build, /ready for USB Imaging/);
  assert.match(main, /deviceIdentifier: selectedUsb\.value,[\s\S]*identityToken: selectedUsb\.dataset\.identityToken/);
  assert.match(main, /option\.value === preferredTarget\.deviceIdentifier[\s\S]*option\.dataset\.identityToken === preferredTarget\.identityToken/);
  assert.match(main, /async function revealUsbImaging[\s\S]*usbInventoryNeedsRefresh\(outputPath, usbImagingRefreshPath,[\s\S]*refreshUsbTargets\(preferredTarget\)[\s\S]*if \(outcome\.completed\) \{\s*usbImagingRefreshPath = acceptedUsbInventoryPath\(outputPath, outcome\)/);
  assert.match(main, /revealCompletedUsbReview = openUsbReview \|\| !progressVisible;[\s\S]*if \(revealCompletedUsbReview\)[\s\S]*revealUsbImaging\(\{ preferredTarget: completedUsbPreferredTarget \}\)/);
  assert.doesNotMatch(main, /if \(openUsbReview\) setUsbMenuOpen\(true\)/);
  assert.doesNotMatch(main, /if \(!finalUsbReady\) setUsbMenuOpen\(false\);/);
  assert.match(main, /preferred\.selected = true;\s*renderUsbTargetSelection\(\);\s*return \{\s*completed: true,[\s\S]*preferredTargetRestored: true,/);
  assert.doesNotMatch(main, /preferred\.selected = true;\s*elements\.usbTarget\.dispatchEvent/);
  assert.match(main, /if \(activeExportMode === "both" && !completedOutputImported\) \{\s*const revealed = await revealCompletedImage\(completedOutput\.path\);/);
});

test("an unusable automatic USB scan releases controls and remains retryable", async () => {
  const image = await readFile(new URL("../src-tauri/src/image.rs", import.meta.url), "utf8");
  assert.match(image, /fn discover_usb_targets[\s\S]*bounded_command_output_with_limits\([\s\S]*Duration::from_secs\(20\)/);
  assert.match(main, /finally \{[\s\S]*elements\.refreshUsbTargets\.disabled = false;[\s\S]*elements\.usbPicker\.classList\.remove\("is-loading"\)/);
  assert.match(main, /acceptedUsbInventoryPath\(outputPath, outcome\)/);
});

test("native close is refused while the exact USB writer remains active", () => {
  assert.match(nativeApp, /CloseRequested \{ api, \.\. \}/);
  assert.match(nativeApp, /manager\.has_active_write\(\)/);
  assert.match(nativeApp, /if usb_write_active \{[\s\S]*api\.prevent_close\(\);[\s\S]*usb-write-close-refused[\s\S]*return;/);
  assert.match(nativeApp, /cleanup_managed_workers\(app_handle\);\s*app_handle\.exit\(0\);/);
});

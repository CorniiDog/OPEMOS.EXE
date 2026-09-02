import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const html = await readFile(new URL("../src/index.html", import.meta.url), "utf8");
const css = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
const chromeCss = await readFile(new URL("../src/window-chrome.css", import.meta.url), "utf8");
const script = await readFile(new URL("../src/main.js", import.meta.url), "utf8");
const tauriConfig = JSON.parse(await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));

test("main workflow keeps readiness compact and balances output and source columns", () => {
  assert.match(html, /id="readiness-grid"[\s\S]*class="environment-card"[\s\S]*id="selection-card"[\s\S]*id="drop-zone"/);
  assert.match(html, /class="build-options-grid"[\s\S]*class="source-choice export-choice"[\s\S]*id="usb-target"[\s\S]*class="build-side-column"[\s\S]*for="nvidia-source"[\s\S]*id="summary-output"[\s\S]*id="build-button"/);
  assert.match(css, /\.readiness-grid\s*\{[\s\S]*grid-template-columns:\s*minmax\(0, 1fr\) minmax\(0, 1fr\)/);
  assert.match(css, /\.build-options-grid\s*\{[^}]*grid-template-columns:\s*minmax\(0, 1\.12fr\) minmax\(0, \.88fr\);/);
  assert.match(css, /\.build-side-column \.build-summary\s*\{[^}]*grid-template-columns:\s*1fr;/);
});

test("USB drives are embedded beside an independent image-output checkbox", () => {
  assert.match(html, /class="source-choice export-choice"[\s\S]*id="export-image"[^>]*checked[\s\S]*id="usb-target" size="3"[\s\S]*id="review-usb-target"/);
  assert.match(html, /id="usb-scrim" class="usb-scrim hidden"/);
  assert.match(html, /id="usb-card"[^>]*role="dialog"[\s\S]*class="usb-heading"[\s\S]*id="close-usb-menu"/);
  assert.match(html, /id="review-usb-target"[^>]*aria-haspopup="dialog"[^>]*aria-controls="usb-card"[^>]*aria-expanded="false"/);
  assert.match(script, /function setUsbMenuOpen\(opened\)/);
  assert.match(script, /function selectedExportMode\(\)[\s\S]*if \(image && usb\) return "both";/);
  assert.match(script, /exportImage\.addEventListener\("change", renderExportMode\)/);
  assert.match(script, /if \(currentImage\) elements\.refreshUsbTargets\.click\(\);/);
  assert.match(html, /id="usb-target" size="3" disabled[^>]*>[\s\S]*Connect a USB drive, then refresh…[\s\S]*<\/select>/);
  assert.match(html, /id="usb-target-detail"[\s\S]*class="usb-picker-actions"[\s\S]*id="clear-usb-target"[\s\S]*id="refresh-usb-targets"/);
  assert.doesNotMatch(script, /Select a removable drive for review/);
  assert.match(script, /placeholder\.value = "";[\s\S]*placeholder\.disabled = true;[\s\S]*placeholder\.selected = true;/);
  assert.match(script, /elements\.clearUsbTarget\.addEventListener\("click"/);
  assert.doesNotMatch(html, /id="export-mode"/);
  assert.match(css, /\.usb-picker select::\-webkit-scrollbar\s*\{[^}]*width:\s*5px;[^}]*background:\s*transparent;/);
  assert.match(css, /\.usb-picker select::\-webkit-scrollbar-track,[\s\S]*\.usb-picker select::\-webkit-scrollbar-corner\s*\{[^}]*background:\s*transparent !important;/);
  assert.match(css, /\.usb-picker-actions\s*\{[^}]*display:\s*flex;[^}]*align-items:\s*center;/);
  assert.match(html, /id="usb-picker" class="usb-picker is-empty"/);
  assert.match(css, /\.usb-picker select\s*\{[^}]*height:\s*68px;[^}]*min-height:\s*68px;/);
  assert.match(css, /\.usb-picker\.is-empty select\s*\{\s*opacity:\s*\.7;/);
  assert.match(script, /elements\.usbPicker\.classList\.add\("is-empty", "is-loading"\)/);
  assert.match(script, /elements\.usbPicker\.classList\.toggle\("is-empty", !preflight\.targets\.length\)/);
  assert.match(script, /placeholder\.textContent = "Select a removable drive…";/);
  assert.match(script, /elements\.reviewUsbTarget\.textContent = finalUsbReady[\s\S]*Select a USB Drive to Continue/);
  assert.match(script, /elements\.refreshUsbTargets\.textContent = "Scanning…";/);
  assert.match(script, /elements\.refreshUsbTargets\.textContent = "Refresh Drives";/);
  assert.match(css, /\.usb-picker\.is-loading #refresh-usb-targets::before\s*\{[^}]*animation:\s*glass-control-spin \.8s linear infinite;/);
  assert.doesNotMatch(html, /Check Preparation Status/);
  assert.match(script, /function renderUsbConfirmationPhase\(prepared = Boolean\(usbPreflightSession\)\)/);
  assert.match(script, /renderUsbConfirmationPhase\(true\)/);
  assert.match(script, /async function dismissUsbMenu\(\)[\s\S]*usbContextGeneration \+= 1;[\s\S]*cancel_usb_write_preflight/);
  assert.match(script, /installKeyboardBindings[\s\S]*keepKeyboardFocusInside[\s\S]*runKeyboardDefaultAction[\s\S]*from "\.\/keyboard\.js";/);
  assert.match(script, /installKeyboardBindings\(\[[\s\S]*key: "Enter"[\s\S]*usbConfirmation\.value === `ERASE \$\{elements\.usbTarget\.value\}`[\s\S]*runKeyboardDefaultAction\(elements\.armUsbPreflight\)[\s\S]*key: "Tab"[\s\S]*keepKeyboardFocusInside[\s\S]*key: "Escape"[\s\S]*dismissUsbMenu\(\)[\s\S]*key: "Escape"[\s\S]*setSettingsOpen\(false\)/);
  assert.match(script, /const wasOpen = !elements\.usbCard\.classList\.contains\("hidden"\);[\s\S]*else if \(wasOpen/);
  assert.match(script, /armUsbPreflight\.setAttribute\("aria-busy", "true"\)[\s\S]*armUsbPreflight\.textContent = "Revalidating…"/);
  assert.match(script, /usbCancelPending \|\| !usbPreflightSession\?\.sessionToken[\s\S]*cancelUsbPreflight\.textContent = "Cancelling…"/);
  assert.match(html, /id="usb-active-warning"[^>]*role="alert"[\s\S]*Do not disconnect the USB drive/);
  assert.match(script, /usbWriting = true;[\s\S]*usbActiveWarning\.classList\.remove\("hidden"\)[\s\S]*usbWriting = false;[\s\S]*usbActiveWarning\.classList\.add\("hidden"\)/);
  assert.match(css, /\.usb-dialog-actions > button\s*\{[^}]*height:\s*42px;[^}]*min-height:\s*42px;[^}]*display:\s*inline-flex;[^}]*align-items:\s*center;[^}]*justify-content:\s*center;/);
  assert.match(css, /\.usb-active-warning\s*\{[^}]*border:[^}]*color:\s*#f4d08b;/);
  assert.match(css, /#usb-card > \.result-message\s*\{[^}]*max-height:\s*5em;[^}]*overflow:\s*auto;/);
  assert.match(css, /\.primary:disabled,[\s\S]*\.secondary:disabled\s*\{[^}]*cursor:\s*not-allowed;/);
});

test("image chooser uses a rounded glass download mark", () => {
  assert.match(html, /class="drop-icon" aria-hidden="true"[\s\S]*<svg viewBox="0 0 32 32"[\s\S]*M16 7v15M10\.5 17\.5 16 23l5\.5-5\.5/);
  assert.match(css, /\.drop-icon\s*\{[^}]*border-radius:\s*999px;[^}]*linear-gradient\(90deg, rgba\(26, 159, 255, \.72\), rgba\(8, 117, 181, \.58\) 48%, rgba\(118, 185, 0, \.64\)\) border-box;/);
  assert.match(css, /\.drop-icon path\s*\{[^}]*stroke-linecap:\s*round;[^}]*stroke-linejoin:\s*round;/);
  assert.doesNotMatch(html, /class="drop-icon"[^>]*>\s*⇩/);
});

test("main macOS chrome stays slim and settings begin below it", () => {
  assert.match(html, /href="\/window-chrome\.css"/);
  assert.match(chromeCss, /--window-chrome-height:\s*38px/);
  assert.match(chromeCss, /--window-chrome-line:\s*37px/);
  assert.match(css, /\.platform-macos \.app-shell\s*\{[^}]*padding:\s*50px 0 8px;/);
  assert.match(css, /\.settings-panel\s*\{[^}]*top:\s*44px;[^}]*max-height:\s*calc\(100vh - 56px\);/);
});

test("manifest-bound NVIDIA outputs skip rebuilding and become USB-ready", () => {
  assert.match(script, /invoke\("inspect_completed_nvidia_image", \{\s*path: info\.path,\s*requestedNvidiaVersion,/);
  assert.match(script, /option\.dataset\.nvidiaVersion = branch\.version/);
  assert.match(script, /NVIDIA \$\{output\.nvidiaVersion\}, SteamOS \$\{output\.steamosVersion\}, kernel \$\{output\.kernelVersion\}, trust \$\{output\.trust\}/);
  assert.match(script, /function applyCompletedOutput\(output, imported = false\)/);
  assert.match(script, /elements\.resultMessage\.title = installedIdentity;/);
  assert.match(script, /Verified existing NVIDIA.*No rebuild needed; select a USB drive/);
  assert.doesNotMatch(script, /Existing NVIDIA output and adjacent manifest match byte-for-byte/);
  assert.match(script, /Boolean\(completedOutput\) \|\| buildRunning/);
  assert.match(css, /\.build-card\.completed-output-selected \.nvidia-choice,[\s\S]*#build-button\s*\{\s*display:\s*none;/);
  assert.doesNotMatch(css, /\.build-card\.completed-output-selected \.build-side-column,[\s\S]{0,100}display:\s*none;/);
  assert.match(script, /elements\.appShell\.classList\.add\("completed-output-selected"\)/);
  assert.match(script, /elements\.appShell\.classList\.remove\("completed-output-selected"\)/);
  assert.match(css, /\.build-card\.completed-output-selected\s*\{[^}]*min-height:\s*188px;/);
  assert.match(css, /\.readiness-grid\.has-selection \.selection-card h2,[\s\S]*text-overflow:\s*ellipsis;[\s\S]*white-space:\s*nowrap;/);
  assert.doesNotMatch(css, /\.app-shell\.completed-output-selected \.drop-zone/);
  assert.match(script, /let completedOutputImported = false;/);
  assert.match(script, /completedOutputImported = imported;/);
  assert.match(script, /activeExportMode === "both" && !completedOutputImported/);
});

test("image selection is transactional across plain and completed outputs", () => {
  assert.match(script, /let imageSelectionGeneration = 0;/);
  assert.match(script, /const selectionGeneration = \+\+imageSelectionGeneration;/);
  assert.match(script, /function hasUsbTargets\(\)[\s\S]*some\(\(option\) => Boolean\(option\.value\)\)/);
  assert.match(script, /completedOutput = null;[\s\S]*currentImage = null;[\s\S]*elements\.buildCard\.classList\.add\("hidden"\);[\s\S]*updateBuildButton\(\);/);
  assert.match(script, /invoke\("validate_image"[\s\S]*if \(selectionGeneration !== imageSelectionGeneration\) return;[\s\S]*invoke\("inspect_completed_nvidia_image"/);
  assert.match(script, /invoke\("inspect_completed_nvidia_image"[\s\S]*if \(selectionGeneration !== imageSelectionGeneration\) return;[\s\S]*invoke\("preview_image_output"/);
  assert.match(script, /if \(buildRunning \|\| usbWriting\)[\s\S]*cannot be changed while a build is running/);
  assert.match(script, /buildRunning = true;[\s\S]*elements\.chooseImage\.disabled = true;/);
  assert.match(script, /usbWriting = true;[\s\S]*elements\.chooseImage\.disabled = true;/);
  assert.match(script, /elements\.nvidiaSource\.disabled = true;[\s\S]*elements\.allowUpstreamBuild\.disabled = true;/);
  assert.match(script, /selectionError = String\(error\);[\s\S]*Choose another SteamOS image[\s\S]*elements\.dropMessage\.title = selectionError \|\| "";/);
  assert.match(script, /elements\.usbTarget\.disabled = !hasUsbTargets\(\);/);
  assert.match(script, /if \(completedOutput\?\.path \|\| !currentImage \|\| !hostReady \|\| !exportMode \|\| buildRunning \|\| usbWriting\) return;/);
  assert.match(script, /const completionSelectionGeneration = imageSelectionGeneration;[\s\S]*invoke\("inspect_completed_nvidia_image"[\s\S]*completionSelectionGeneration !== imageSelectionGeneration \|\| inputPath !== currentImage/);
  assert.doesNotMatch(script, /buildRunning = true;[\s\S]{0,900}refreshUsbTargets\.textContent = "Scanning…";/);
});

test("builder readiness expands while no image has been selected", () => {
  assert.match(css, /\.readiness-grid > \.environment-card\s*\{\s*grid-column:\s*1 \/ -1;/);
  assert.match(css, /\.readiness-grid\.has-selection > \.environment-card\s*\{\s*grid-column:\s*auto;/);
  assert.match(script, /elements\.readinessGrid\.classList\.add\("has-selection"\)/);
});

test("adjacent translucent workflow cards do not cast shadows through each other", () => {
  assert.match(css, /\.environment-card\s*\{[^}]*box-shadow:\s*inset 0 1px 0 var\(--glass-highlight\);/);
  assert.match(css, /\.download-card,[\s\S]*\.build-card\s*\{[^}]*box-shadow:\s*inset 0 1px 0 var\(--glass-highlight\);/);
  assert.doesNotMatch(css, /\.environment-card\s*\{[^}]*box-shadow:\s*var\(--glass-shadow\);/);
});

test("selected-image mode preserves the build action and result region", () => {
  assert.match(script, /elements\.downloadCard\.classList\.toggle\("hidden", Boolean\(currentImage\)\)/);
  assert.match(css, /\.result-message\s*\{\s*min-height:\s*18px;/);
  assert.doesNotMatch(script, /header\.after|dropZone\.after|selectionCard\.after/);
});

test("long selected-image names and paths remain inside the readiness card", () => {
  assert.match(css, /\.readiness-grid > section\s*\{[^}]*overflow:\s*hidden;/);
  assert.match(css, /\.readiness-grid \.path\s*\{[^}]*white-space:\s*normal;[^}]*overflow-wrap:\s*anywhere;/);
  assert.match(css, /\.selection-card h2\s*\{[^}]*white-space:\s*normal;[^}]*overflow-wrap:\s*anywhere;/);
  assert.doesNotMatch(css, /\.selection-card h2\s*\{[^}]*text-overflow:\s*ellipsis;/);
});

test("compact main window height agrees between web content and Tauri", () => {
  const mainWindow = tauriConfig.app.windows.find(({ label }) => label === "main");
  assert.equal(mainWindow.height, 800);
  assert.equal(mainWindow.minHeight, 800);
  assert.match(css, /body\s*\{[\s\S]*min-height:\s*800px;/);
});

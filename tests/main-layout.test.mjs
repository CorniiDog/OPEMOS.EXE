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

test("narrow effective widths and high zoom reflow without horizontal clipping", () => {
  assert.match(css, /@media \(max-width: 760px\), \(max-height: 760px\)/);
  assert.match(css, /body\s*\{\s*min-width:\s*0;\s*min-height:\s*0;/);
  assert.match(css, /\.app-shell\s*\{[^}]*width:\s*calc\(100% - 24px\);[^}]*overflow-x:\s*hidden;[^}]*overflow-y:\s*auto;/s);
  assert.match(css, /\.readiness-grid,[\s\S]*\.build-options-grid,[\s\S]*\.download-card\s*\{\s*grid-template-columns:\s*minmax\(0, 1fr\);/);
  assert.match(css, /\.output-destination-actions\s*\{[^}]*width:\s*100%;[^}]*flex-wrap:\s*wrap;/s);
  assert.match(css, /\.path,[\s\S]*\.output-destination small,[\s\S]*\.build-summary strong\s*\{[^}]*overflow-wrap:\s*anywhere;[^}]*white-space:\s*normal;/s);
});

test("image output folder selection is explicit, reversible, and build-bound", async () => {
  const [html, css, script, progress] = await Promise.all([
    readFile(new URL("../src/index.html", import.meta.url), "utf8"),
    readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
    readFile(new URL("../src/main.js", import.meta.url), "utf8"),
    readFile(new URL("../src/build.js", import.meta.url), "utf8"),
  ]);
  assert.match(html, /id="output-folder-label">Alongside the source image/);
  assert.match(html, /id="reset-output-folder"[^>]*hidden[^>]*>Use Source Folder/);
  assert.match(html, /id="choose-output-folder"[^>]*>Choose…/);
  assert.match(css, /\.output-destination\s*\{[^}]*min-width:\s*0;[^}]*display:\s*flex/s);
  assert.match(script, /open\(\{\s*multiple:\s*false,\s*directory:\s*true\s*\}\)/);
  const selection = script.match(/async function selectOutputDirectory\(directory\) \{([\s\S]*?)\n\}/)?.[1] || "";
  assert.match(selection, /outputDirectory:\s*directory/);
  assert.match(selection, /revision !== outputSelectionGeneration/);
  assert.match(selection, /!admitOutputDirectorySelection\(currentBuildSnapshot\(\)\)\.accepted/);
  assert.doesNotMatch(selection, /!currentImage \|\| completedOutput \|\| buildRunning/);
  assert.match(script, /applyCompletedOutput[\s\S]*chooseOutputFolder\.disabled = true;[\s\S]*resetOutputFolder\.disabled = true;/);
  assert.match(script, /async function selectImage\(path\) \{\s*outputSelectionGeneration \+= 1;/);
  assert.match(script, /chooseImage\.addEventListener\("click", async \(\) => \{[\s\S]*admitImageSelection\(currentBuildSnapshot\(\)\)\.accepted[\s\S]*await open/);
  assert.match(script, /chooseOutputFolder\.addEventListener\("click", async \(\) => \{[\s\S]*admitOutputDirectorySelection\(currentBuildSnapshot\(\)\)\.accepted[\s\S]*await open/);
  assert.doesNotMatch(script, /chooseOutputFolder\.addEventListener\("click", async \(\) => \{\s*const directory = await open/);
  assert.doesNotMatch(script, /chooseImage\.addEventListener\("click", async \(\) => \{\s*const selected = await open/);
  assert.match(script, /onDragDropEvent\(async \(event\) => \{[\s\S]*admitImageSelection\(currentBuildSnapshot\(\)\)[\s\S]*classList\.toggle\("dragging", admission\.accepted\)[\s\S]*type === "drop" && admission\.accepted/);
  assert.doesNotMatch(script, /type === "over"\) \{ elements\.dropZone\.classList\.add\("dragging"\)/);
  assert.match(script, /resetOutputFolder[\s\S]*selectOutputDirectory\(null\)/);
  assert.match(script, /resetOutputFolder\.addEventListener\("click", \(\) => \{[\s\S]*admitOutputDirectorySelection\(currentBuildSnapshot\(\)\)\.accepted[\s\S]*selectOutputDirectory\(null\)/);
  assert.doesNotMatch(script, /resetOutputFolder\.addEventListener\("click", \(\) => \{ void selectOutputDirectory\(null\); \}\)/);
  assert.match(script, /emit\("build-requested",[\s\S]*outputDirectory,/);
  assert.match(progress, /invoke\("start_appliance",\s*\{[\s\S]*outputDirectory:\s*request\.outputDirectory \?\? null/);
});

test("USB drives are embedded beside an independent image-output checkbox", () => {
  assert.match(html, /class="source-choice export-choice"[\s\S]*id="export-image"[^>]*checked[\s\S]*id="usb-target" size="3"[\s\S]*id="review-usb-target"/);
  assert.match(html, /id="usb-scrim" class="usb-scrim hidden"/);
  assert.match(html, /id="usb-card"[^>]*role="dialog"[\s\S]*class="usb-heading"[\s\S]*id="close-usb-menu"/);
  assert.match(html, /id="review-usb-target"[^>]*aria-haspopup="dialog"[^>]*aria-controls="usb-card"[^>]*aria-expanded="false"/);
  assert.match(script, /function setUsbMenuOpen\(opened\)/);
  assert.match(script, /function selectedExportMode\(\)[\s\S]*if \(image && usb\) return "both";/);
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
  assert.match(script, /Drive inspection failed:[\s\S]*renderUsbConfirmationPhase\(false\);[\s\S]*renderExportMode\(\);/);
  assert.match(script, /refreshUsbTargets\.addEventListener\("click", async \(\) => \{[\s\S]*admitUsbTargetRefresh\(currentBuildSnapshot\(\)\)\.accepted[\s\S]*await refreshUsbTargets\(\)/);
  assert.doesNotMatch(script, /refreshUsbTargets\.addEventListener\("click", async \(\) => \{\s*await refreshUsbTargets/);
  assert.match(script, /usbTarget\.addEventListener\("change"[\s\S]*usbPreflightSession = null;\s*renderUsbTargetSelection\(\);[\s\S]*cancel_usb_write_preflight/);
  assert.match(css, /\.usb-picker\.is-loading #refresh-usb-targets::before\s*\{[^}]*animation:\s*glass-control-spin \.8s linear infinite;/);
  assert.doesNotMatch(html, /Check Preparation Status/);
  assert.match(script, /function renderUsbConfirmationPhase\(prepared = Boolean\(usbPreflightSession\)\)/);
  assert.match(script, /usbConfirmation\.addEventListener\("input"[\s\S]*admitUsbConfirmationEdit\(currentBuildSnapshot\(\), \{[\s\S]*hasPreflightSession: Boolean\(usbPreflightSession\?\.sessionToken\)[\s\S]*if \(!admission\.accepted\)[\s\S]*usbConfirmation\.value = "";[\s\S]*armUsbPreflight\.disabled = true;/);
  assert.match(script, /const admission = admitUsbPreflightStart\(currentBuildSnapshot\(\), \{[\s\S]*confirmationMatches:[\s\S]*"ERASE " \+ option\?\.value/);
  assert.match(script, /if \(!admission\.accepted\) return;/);
  assert.doesNotMatch(script, /if \(usbArmPending \|\| !completedOutput\?\.path \|\| !option\?\.value/);
  assert.match(script, /renderUsbConfirmationPhase\(true\)/);
  assert.match(script, /async function dismissUsbMenu\(\)[\s\S]*usbContextGeneration \+= 1;[\s\S]*cancel_usb_write_preflight/);
  assert.match(script, /const admission = admitUsbPreflightCancel\(currentBuildSnapshot\(\), \{[\s\S]*cancelPending: usbCancelPending,[\s\S]*hasPreflightSession: Boolean\(usbPreflightSession\?\.sessionToken\)/);
  assert.match(script, /usbTarget\.addEventListener\("change"[\s\S]*admitUsbTargetSelection\(currentBuildSnapshot\(\)\)\.accepted/);
  assert.doesNotMatch(script, /usbTarget\.addEventListener\("change", async \(\) => \{\s*const generation/);
  assert.match(script, /clearUsbTarget\.addEventListener\("click"[\s\S]*admitUsbTargetClear\(currentBuildSnapshot\(\), \{[\s\S]*hasTarget: Boolean\(elements\.usbTarget\.value\)/);
  assert.doesNotMatch(script, /clearUsbTarget\.addEventListener\("click", \(\) => \{\s*if \(!elements\.usbTarget\.value\) return;/);
  assert.match(script, /reviewUsbTarget\.addEventListener\("click"[\s\S]*admitUsbReviewOpen\(currentBuildSnapshot\(\), \{[\s\S]*hasTarget: Boolean\(elements\.usbTarget\.value\)[\s\S]*if \(admission\.accepted\) setUsbMenuOpen\(true\)/);
  assert.match(script, /exportImage\.addEventListener\("change", \(\) => \{[\s\S]*admitExportModeSelection\(currentBuildSnapshot\(\)\)[\s\S]*if \(!admission\.accepted\)[\s\S]*activeExportMode === "both"[\s\S]*renderExportMode\(\)/);
  assert.doesNotMatch(script, /exportImage\.addEventListener\("change", renderExportMode\)/);
  assert.doesNotMatch(script, /if \(currentImage && completedOutput\?\.path && elements\.usbTarget\.value\)/);
  assert.match(script, /async function dismissUsbMenu\(\) \{[\s\S]*admitUsbReviewDismiss\(currentBuildSnapshot\(\)\)\.accepted/);
  assert.doesNotMatch(script, /async function dismissUsbMenu\(\) \{\s*if \(usbWriting\) return;/);
  assert.match(script, /if \(!admission\.accepted\) return;[\s\S]*const context = \{/);
  assert.doesNotMatch(script, /if \(usbCancelPending \|\| !usbPreflightSession\?\.sessionToken\) return;/);
  assert.match(script, /installKeyboardBindings[\s\S]*keepKeyboardFocusInside[\s\S]*runKeyboardDefaultAction[\s\S]*from "\.\/keyboard\.js";/);
  assert.match(script, /installKeyboardBindings\(\[[\s\S]*key: "Enter"[\s\S]*usbConfirmation\.value === `ERASE \$\{elements\.usbTarget\.value\}`[\s\S]*runKeyboardDefaultAction\(elements\.armUsbPreflight\)[\s\S]*key: "Tab"[\s\S]*keepKeyboardFocusInside[\s\S]*key: "Escape"[\s\S]*dismissUsbMenu\(\)[\s\S]*key: "Escape"[\s\S]*setSettingsOpen\(false\)/);
  assert.match(script, /const wasOpen = !elements\.usbCard\.classList\.contains\("hidden"\);[\s\S]*else if \(wasOpen/);
  assert.match(script, /armUsbPreflight\.setAttribute\("aria-busy", "true"\)[\s\S]*armUsbPreflight\.textContent = "Revalidating…"/);
  assert.match(script, /const context = \{[\s\S]*cancelUsbPreflight\.textContent = "Cancelling…"/);
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
  assert.match(script, /admitBuildStart,[\s\S]*admitImageSelection,[\s\S]*admitExportModeSelection,[\s\S]*admitOutputDirectorySelection,[\s\S]*admitUsbPreflightCancel,[\s\S]*admitUsbConfirmationEdit,[\s\S]*admitUsbPreflightStart,[\s\S]*admitUsbReviewOpen,[\s\S]*admitUsbReviewDismiss,[\s\S]*admitUsbTargetSelection,[\s\S]*admitUsbTargetRefresh,[\s\S]*admitUsbTargetClear,[\s\S]*admitUsbWriteStart,[\s\S]*deriveBuildAdmission,[\s\S]*from "\.\/workflow-state\.js"/);
  assert.match(script, /hasCompletedOutput: Boolean\(completedOutput\?\.path\)/);
  assert.match(script, /elements\.buildButton\.disabled = !deriveBuildAdmission\(currentBuildSnapshot\(\)\)\.canBuild/);
  assert.match(script, /if \(!admitBuildStart\(currentBuildSnapshot\(\)\)\.accepted\) return;/);
  assert.match(script, /const buildContext = \{[\s\S]*sourceSelection: elements\.nvidiaSource\.value,[\s\S]*allowExperimentalUpstream: elements\.nvidiaSource\.value\.startsWith\("upstream:"\)[\s\S]*selectionGeneration:[\s\S]*buildRunning = true;/);
  assert.match(script, /buildRunning = true;[\s\S]*nvidiaSource\.disabled = true;[\s\S]*allowUpstreamBuild\.disabled = true;[\s\S]*emit\("build-requested", \{[\s\S]*sourceSelection: buildContext\.sourceSelection,[\s\S]*allowExperimentalUpstream: buildContext\.allowExperimentalUpstream/);
  assert.doesNotMatch(script, /emit\("build-requested", \{[\s\S]*sourceSelection: elements\.nvidiaSource\.value/);
  assert.match(script, /catch \(error\) \{[\s\S]*buildRunning = false;[\s\S]*nvidiaSource\.disabled = false;[\s\S]*allowUpstreamBuild\.disabled = false;/);
  assert.match(script, /async function applyBuildFinished[\s\S]*buildRunning = false;[\s\S]*nvidiaSource\.disabled = false;[\s\S]*allowUpstreamBuild\.disabled = false;/);
  assert.doesNotMatch(script, /completedOutput\?\.path \|\| !currentImage \|\| !hostReady/);
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
  assert.match(script, /const selection = admitImageSelection\(currentBuildSnapshot\(\)\);[\s\S]*if \(!selection\.accepted\)/);
  assert.match(script, /selection\.phase === "building"[\s\S]*cannot be changed while a build is running/);
  assert.doesNotMatch(script, /if \(buildRunning \|\| usbWriting\)/);
  assert.match(script, /buildRunning = true;[\s\S]*elements\.chooseImage\.disabled = true;/);
  assert.match(script, /const admission = admitUsbWriteStart\(currentBuildSnapshot\(\), \{[\s\S]*hasPreflightSession: Boolean\(usbPreflightSession\?\.sessionToken\)/);
  assert.match(script, /if \(!admission\.accepted\) return;[\s\S]*window\.confirm/);
  assert.doesNotMatch(script, /if \(usbWriting \|\| !usbPreflightSession\?\.sessionToken \|\| !completedOutput\?\.path\) return;/);
  assert.match(script, /usbWriting = true;[\s\S]*elements\.chooseImage\.disabled = true;/);
  assert.match(script, /elements\.nvidiaSource\.disabled = true;[\s\S]*elements\.allowUpstreamBuild\.disabled = true;/);
  assert.match(script, /selectionError = String\(error\);[\s\S]*Choose another SteamOS image[\s\S]*elements\.dropMessage\.title = selectionError \|\| "";/);
  assert.match(script, /elements\.usbTarget\.disabled = !hasUsbTargets\(\);/);
  assert.match(script, /if \(!admitBuildStart\(currentBuildSnapshot\(\)\)\.accepted\) return;/);
  assert.match(script, /const buildContext = activeBuildContext;[\s\S]*invoke\("inspect_completed_nvidia_image"[\s\S]*buildContext\.selectionGeneration !== imageSelectionGeneration[\s\S]*inputPath !== currentImage/);
  assert.doesNotMatch(script, /buildRunning = true;[\s\S]{0,900}refreshUsbTargets\.textContent = "Scanning…";/);
});

test("stale build completions cannot overwrite a newer build context", () => {
  assert.match(script, /import \{ buildCompletionMatches, operationContextMatches \}/);
  assert.match(script, /let buildContextGeneration = 0;/);
  assert.match(script, /requestId: crypto\.randomUUID\(\)/);
  assert.match(script, /activeBuildContext = buildContext;/);
  assert.match(script, /progressWindow\.emit\("build-requested", \{\s*requestId: buildContext\.requestId,/);
  assert.match(script, /if \(!buildCompletionMatches\(event\.payload, activeBuildContext\)\) return;/);
  assert.match(script, /if \(pendingBuildFinished\) return;/);
  assert.match(script, /selectionGeneration: imageSelectionGeneration/);
  assert.match(script, /activeBuildContext = null;[\s\S]*buildRunning = false;/);
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

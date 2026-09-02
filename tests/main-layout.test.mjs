import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const html = await readFile(new URL("../src/index.html", import.meta.url), "utf8");
const css = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
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
  assert.match(script, /function setUsbMenuOpen\(opened\)/);
  assert.match(script, /function selectedExportMode\(\)[\s\S]*if \(image && usb\) return "both";/);
  assert.match(script, /exportImage\.addEventListener\("change", renderExportMode\)/);
  assert.match(script, /if \(currentImage\) elements\.refreshUsbTargets\.click\(\);/);
  assert.doesNotMatch(html, /id="export-mode"/);
  assert.match(css, /\.usb-picker select::\-webkit-scrollbar\s*\{[^}]*width:\s*5px;[^}]*background:\s*transparent;/);
  assert.match(css, /\.usb-picker select::\-webkit-scrollbar-track,[\s\S]*\.usb-picker select::\-webkit-scrollbar-corner\s*\{[^}]*background:\s*transparent !important;/);
});

test("main macOS chrome stays slim and settings begin below it", () => {
  assert.match(css, /\.platform-macos \.window-drag-region\s*\{[^}]*height:\s*32px;/);
  assert.match(css, /\.platform-macos \.app-shell\s*\{[^}]*padding:\s*44px 0 8px;/);
  assert.match(css, /\.settings-panel\s*\{[^}]*top:\s*44px;[^}]*max-height:\s*calc\(100vh - 56px\);/);
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

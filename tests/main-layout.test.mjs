import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const html = await readFile(new URL("../src/index.html", import.meta.url), "utf8");
const css = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
const script = await readFile(new URL("../src/main.js", import.meta.url), "utf8");
const tauriConfig = JSON.parse(await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));

test("main workflow keeps readiness compact and gives output selection full width", () => {
  assert.match(html, /id="readiness-grid"[\s\S]*class="environment-card"[\s\S]*id="selection-card"[\s\S]*id="drop-zone"/);
  assert.match(html, /class="build-options-grid"[\s\S]*for="export-image"[\s\S]*id="usb-target"[\s\S]*for="nvidia-source"/);
  assert.match(css, /\.readiness-grid\s*\{[\s\S]*grid-template-columns:\s*minmax\(0, 1fr\) minmax\(0, 1fr\)/);
  assert.match(css, /\.build-options-grid\s*\{[^}]*grid-template-columns:\s*1fr;/);
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
});

test("main macOS chrome stays slim and settings begin below it", () => {
  assert.match(css, /\.platform-macos \.window-drag-region\s*\{[^}]*height:\s*32px;/);
  assert.match(css, /\.platform-macos \.app-shell\s*\{[^}]*padding:\s*38px 0 8px;/);
  assert.match(css, /\.settings-panel\s*\{[^}]*top:\s*40px;[^}]*max-height:\s*calc\(100vh - 52px\);/);
});

test("builder readiness expands while no image has been selected", () => {
  assert.match(css, /\.readiness-grid > \.environment-card\s*\{\s*grid-column:\s*1 \/ -1;/);
  assert.match(css, /\.readiness-grid\.has-selection > \.environment-card\s*\{\s*grid-column:\s*auto;/);
  assert.match(script, /elements\.readinessGrid\.classList\.add\("has-selection"\)/);
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

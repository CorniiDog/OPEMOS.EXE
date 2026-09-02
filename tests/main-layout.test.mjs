import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const html = await readFile(new URL("../src/index.html", import.meta.url), "utf8");
const css = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
const script = await readFile(new URL("../src/main.js", import.meta.url), "utf8");
const tauriConfig = JSON.parse(await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));

test("main workflow groups related status and build controls into compact columns", () => {
  assert.match(html, /id="readiness-grid"[\s\S]*class="environment-card"[\s\S]*id="selection-card"[\s\S]*id="drop-zone"/);
  assert.match(html, /class="build-options-grid"[\s\S]*for="export-mode"[\s\S]*for="nvidia-source"/);
  assert.match(css, /\.readiness-grid\s*\{[\s\S]*grid-template-columns:\s*minmax\(0, 1fr\) minmax\(0, 1fr\)/);
  assert.match(css, /\.build-options-grid\s*\{[\s\S]*grid-template-columns:\s*minmax\(0, 1fr\) minmax\(0, 1fr\)/);
});

test("USB selection is anchored to its export choice and uses a modal header", () => {
  assert.match(html, /class="source-choice export-choice"[\s\S]*for="export-mode"[\s\S]*id="review-usb-target"/);
  assert.match(html, /id="usb-scrim" class="usb-scrim hidden"/);
  assert.match(html, /id="usb-card"[^>]*role="dialog"[\s\S]*class="usb-heading"[\s\S]*id="close-usb-menu"/);
  assert.match(script, /function setUsbMenuOpen\(opened\)/);
  assert.doesNotMatch(script, /exportMode\.addEventListener\("change", \(\) => \{[\s\S]{0,160}usbCard\.classList\.remove/);
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

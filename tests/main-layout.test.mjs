import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const html = await readFile(new URL("../src/index.html", import.meta.url), "utf8");
const css = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
const tauriConfig = JSON.parse(await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));

test("main workflow groups related status and build controls into compact columns", () => {
  assert.match(html, /class="readiness-grid"[\s\S]*id="selection-card"[\s\S]*class="environment-card"/);
  assert.match(html, /class="build-options-grid"[\s\S]*for="export-mode"[\s\S]*for="nvidia-source"/);
  assert.match(css, /\.readiness-grid\s*\{[\s\S]*grid-template-columns:\s*minmax\(0, 1fr\) minmax\(0, 1fr\)/);
  assert.match(css, /\.build-options-grid\s*\{[\s\S]*grid-template-columns:\s*minmax\(0, 1fr\) minmax\(0, 1fr\)/);
});

test("builder readiness expands while no image has been selected", () => {
  assert.match(css, /\.readiness-grid > \.selection-card\.hidden \+ \.environment-card\s*\{\s*grid-column:\s*1 \/ -1;/);
});

test("compact main window height agrees between web content and Tauri", () => {
  const mainWindow = tauriConfig.app.windows.find(({ label }) => label === "main");
  assert.equal(mainWindow.height, 800);
  assert.equal(mainWindow.minHeight, 800);
  assert.match(css, /body\s*\{[\s\S]*min-height:\s*800px;/);
});

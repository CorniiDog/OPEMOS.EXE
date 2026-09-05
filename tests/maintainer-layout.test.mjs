import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const html = await readFile(new URL("../src/maintainer.html", import.meta.url), "utf8");
const css = await readFile(new URL("../src/maintainer.css", import.meta.url), "utf8");
const chromeCss = await readFile(new URL("../src/window-chrome.css", import.meta.url), "utf8");

test("maintainer scrolling stays inside an inset content viewport", () => {
  assert.match(css, /html, body\s*\{[^}]*height:\s*100%;[^}]*overflow:\s*hidden;/);
  assert.match(css, /\.maintainer-scroll\s*\{[^}]*position:\s*fixed;[^}]*inset:\s*0;[^}]*overflow-y:\s*auto;/);
  assert.match(css, /\.platform-macos \.maintainer-scroll\s*\{[^}]*top:\s*38px;[^}]*height:\s*calc\(100% - 38px\);/);
  assert.doesNotMatch(css, /scrollbar-gutter:\s*stable/);
  assert.match(css, /\.maintainer-scroll::\-webkit-scrollbar\s*\{[^}]*width:\s*5px;[^}]*background:\s*transparent;/);
  assert.match(css, /\.maintainer-scroll::\-webkit-scrollbar-track,[\s\S]*\.maintainer-scroll::\-webkit-scrollbar-corner\s*\{[^}]*background:\s*transparent !important;/);
});

test("macOS keeps a visible drag rail outside the scrolling viewport", () => {
  assert.match(html, /class="window-drag-region" data-tauri-drag-region aria-hidden="true"><\/div>/);
  assert.match(html, /href="\/window-chrome\.css"/);
  assert.match(chromeCss, /\.platform-macos \.window-drag-region\s*\{[^}]*position:\s*fixed;[^}]*height:\s*var\(--window-chrome-height\)/);
  assert.match(chromeCss, /\.platform-macos \.window-drag-region::after\s*\{[^}]*position:\s*fixed;[^}]*right:\s*0;[^}]*left:\s*0;[^}]*height:\s*1px;/);
  assert.match(css, /html\.platform-macos\s*\{\s*--window-chrome-drag-right:\s*0;/);
});

test("maintainer controls and long identities reflow at high zoom", () => {
  const responsive = css.match(/@media \(max-width: 760px\), \(max-height: 760px\) \{([\s\S]*?)\n\}/)?.[1] || "";
  assert.match(responsive, /html,[\s\S]*body\s*\{[^}]*min-width:\s*0;[^}]*min-height:\s*0;/);
  assert.match(responsive, /\.maintainer-shell\s*\{[^}]*width:\s*min\(1040px, calc\(100% - 24px\)\);/);
  assert.match(responsive, /header,[\s\S]*\.section-heading\s*\{[^}]*flex-wrap:\s*wrap;/);
  assert.match(responsive, /\.selector-grid,[\s\S]*\.action-grid\s*\{[^}]*grid-template-columns:\s*1fr;/);
  assert.match(responsive, /\.identity dd,[\s\S]*\.plan-summary strong\s*\{[^}]*white-space:\s*normal;[^}]*overflow-wrap:\s*anywhere;/);
  assert.match(responsive, /\.patch-preview\s*\{[^}]*white-space:\s*pre-wrap;[^}]*overflow-wrap:\s*anywhere;/);
});

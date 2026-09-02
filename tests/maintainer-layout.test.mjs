import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const html = await readFile(new URL("../src/maintainer.html", import.meta.url), "utf8");
const css = await readFile(new URL("../src/maintainer.css", import.meta.url), "utf8");

test("maintainer scrolling stays inside an inset content viewport", () => {
  assert.match(css, /html, body\s*\{[^}]*height:\s*100%;[^}]*overflow:\s*hidden;/);
  assert.match(css, /\.maintainer-shell\s*\{[^}]*height:\s*100%;[^}]*overflow-y:\s*auto;[^}]*scrollbar-gutter:\s*stable;/);
  assert.match(css, /\.maintainer-shell::\-webkit-scrollbar-thumb\s*\{[^}]*border:\s*3px solid transparent;[^}]*background-clip:\s*padding-box;/);
});

test("macOS keeps a visible drag rail outside the scrolling viewport", () => {
  assert.match(html, /class="window-drag-region"[^>]*>[\s\S]*Maintainer Workspace/);
  assert.match(css, /\.platform-macos \.window-drag-region\s*\{[^}]*position:\s*fixed;[^}]*height:\s*38px;/);
  assert.match(css, /\.platform-macos \.maintainer-shell\s*\{[^}]*height:\s*calc\(100% - 38px\);[^}]*margin-top:\s*38px;/);
});

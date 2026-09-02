import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const html = await readFile(new URL("../src/index.html", import.meta.url), "utf8");
const css = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
const main = await readFile(new URL("../src/main.js", import.meta.url), "utf8");
const build = await readFile(new URL("../src/build.js", import.meta.url), "utf8");
const maintainer = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
const nativeWindows = await readFile(new URL("../src-tauri/src/windows.rs", import.meta.url), "utf8");

test("companion windows remain native children of the main window", () => {
  assert.equal([...nativeWindows.matchAll(/\.parent\(&main\)/g)].length, 2);
  assert.equal([...nativeWindows.matchAll(/\.set_focus\(\)/g)].length, 4);
  assert.doesNotMatch(nativeWindows, /always_on_top/);
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

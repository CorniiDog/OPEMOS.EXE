import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const cssFiles = ["styles.css", "build.css", "maintainer.css"];
const htmlFiles = ["index.html", "build.html", "maintainer.html"];
const controlsCss = await readFile(new URL("../src/glass-controls.css", import.meta.url), "utf8");

test("every application surface shares the Steam glass material tokens", async () => {
  const chromeCss = await readFile(new URL("../src/window-chrome.css", import.meta.url), "utf8");
  assert.match(chromeCss, /--window-chrome-height:\s*38px;/);
  assert.match(chromeCss, /--window-chrome-line:\s*37px;/);
  assert.match(chromeCss, /\.platform-macos \.window-drag-region\s*\{[^}]*height:\s*var\(--window-chrome-height\);/);
  assert.match(chromeCss, /\.platform-macos \.window-drag-region::after\s*\{[^}]*position:\s*fixed;[^}]*right:\s*0;[^}]*left:\s*0;[^}]*height:\s*1px;[^}]*background:\s*rgba\(174, 207, 225, \.22\);/);
  for (const name of cssFiles) {
    const css = await readFile(new URL(`../src/${name}`, import.meta.url), "utf8");
    assert.match(css, /--steam-blue:\s*#1a9fff;/, `${name} is missing the Steam accent`);
    assert.match(css, /--nvidia-green:\s*#76b900;/, `${name} is missing the NVIDIA accent`);
    assert.match(css, /--glass-canvas:\s*rgba\(11, 17, 24, \.58\);/, `${name} is missing its translucent dark tint`);
    assert.match(css, /body::after[\s\S]*linear-gradient\(to left, rgba\(118, 185, 0, \.08\), transparent 8%\)/, `${name} is missing the diffuse NVIDIA edge glare`);
    assert.match(css, /body::after[\s\S]*inset 0 0 0 1px rgba\(220, 239, 249, \.12\)/, `${name} is missing the refractive glass rim`);
    assert.match(css, /\.platform-macos body\s*\{[^}]*backdrop-filter:\s*blur\(24px\)/, `${name} is missing macOS frosted blur`);
    assert.match(css, /\.platform-macos body\s*\{[^}]*contain:\s*paint;[^}]*clip-path:\s*inset\(0 round 10px\);/, `${name} can composite beyond the rounded window silhouette`);
    assert.doesNotMatch(css, /body::before[\s\S]{0,160}border:/, `${name} still draws the rejected inset window border`);
    assert.doesNotMatch(css, /--brand-gradient/, `${name} still uses the rejected full-surface gradient`);
  }
});

test("preload and native window backgrounds preserve translucent dark fallback", async () => {
  for (const name of htmlFiles) {
    const html = await readFile(new URL(`../src/${name}`, import.meta.url), "utf8");
    assert.match(html, /html, body \{ background: rgba\(11, 17, 24, \.64\);/, `${name} can flash an un-tinted transparent canvas`);
    assert.match(html, /navigator\.platform\.startsWith\("Mac"\).*navigator\.userAgent\.includes\("Macintosh"\)/, `${name} cannot detect macOS robustly`);
    assert.match(html, /<header[^>]*data-tauri-drag-region/, `${name} cannot drag its overlay title bar`);
    assert.match(html, /class="window-drag-region" data-tauri-drag-region/, `${name} is missing its top-edge drag target`);
    assert.match(html, /href="\/window-chrome\.css"/, `${name} does not load the shared window chrome`);
    assert.match(html, /href="\/glass-controls\.css"/, `${name} does not load the shared glass controls`);
  }

  const config = JSON.parse(await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  const main = config.app.windows[0];
  assert.equal(config.app.macOSPrivateApi, true);
  assert.equal(main.transparent, true);
  assert.equal(main.titleBarStyle, "Overlay");
  assert.equal(main.hiddenTitle, true);
  assert.equal(main.shadow, false);
  assert.deepEqual(main.backgroundColor, [11, 17, 24, 0]);
  assert.deepEqual(main.windowEffects.effects, ["underWindowBackground", "acrylic"]);
  assert.equal(main.windowEffects.radius, 10);
  assert.deepEqual(main.windowEffects.color, [11, 17, 24, 220]);
  assert.deepEqual(config.bundle.icon, [
    "icons/32x32.png",
    "icons/128x128.png",
    "icons/128x128@2x.png",
    "icons/icon.icns",
    "icons/icon.ico",
  ]);

  const buildScript = await readFile(new URL("../src-tauri/build.rs", import.meta.url), "utf8");
  assert.match(buildScript, /cargo:rerun-if-changed=icons\/icon\.png/);
  assert.match(buildScript, /cargo:rerun-if-changed=icons\/icon\.icns/);

  const windows = await readFile(new URL("../src-tauri/src/windows.rs", import.meta.url), "utf8");
  assert.equal([...windows.matchAll(/\.transparent\(true\)/g)].length, 2);
  assert.equal([...windows.matchAll(/\.effects\(glass_window_effects\(\)\)/g)].length, 2);
  assert.equal([...windows.matchAll(/\.shadow\(false\)/g)].length, 2);
  assert.equal([...windows.matchAll(/\.title_bar_style\(tauri::TitleBarStyle::Overlay\)/g)].length, 2);
  assert.match(windows, /\.radius\(10\.0\)/);
  assert.match(windows, /Effect::UnderWindowBackground, Effect::Acrylic/);

  const dragScript = await readFile(new URL("../src/window-drag.js", import.meta.url), "utf8");
  assert.match(dragScript, /pointerdown/);
  assert.match(dragScript, /windowHandle\.startDragging\(\)/);

  const capabilities = JSON.parse(await readFile(new URL("../src-tauri/capabilities/default.json", import.meta.url), "utf8"));
  assert.ok(capabilities.permissions.includes("core:window:allow-start-dragging"));
});

test("interactive controls share one rounded glass component language", async () => {
  assert.match(controlsCss, /input\[type="checkbox"\]\s*\{[^}]*appearance:\s*none;[^}]*border-radius:\s*7px;/);
  assert.match(controlsCss, /input\[type="checkbox"\]:checked\s*\{[^}]*linear-gradient\(135deg, rgba\(26, 159, 255, \.94\)/);
  assert.match(controlsCss, /select:not\(\[size\]\)\s*\{[^}]*appearance:\s*none;[^}]*background-image:/);
  assert.match(controlsCss, /\.danger\s*\{[^}]*linear-gradient\(180deg, rgba\(126, 57, 65, \.88\)/);
  assert.match(controlsCss, /\.status\s*\{[^}]*border:\s*1px solid rgba\(151, 211, 88, \.16\);/);
  assert.match(controlsCss, /button:focus-visible,[\s\S]*input:focus-visible\s*\{[^}]*outline:\s*2px solid rgba\(102, 192, 244, \.78\);/);

  const mainHtml = await readFile(new URL("../src/index.html", import.meta.url), "utf8");
  assert.equal([...mainHtml.matchAll(/class="close-icon"/g)].length, 2);
  assert.doesNotMatch(mainHtml, /aria-label="Close (?:settings|USB menu)">×/);
});

test("build progress uses two rounded glass channels inside one glass pill", async () => {
  const css = await readFile(new URL("../src/build.css", import.meta.url), "utf8");
  assert.match(css, /\.progress-stack\s*\{[^}]*border:\s*1px solid rgba\(184, 220, 241, \.18\);[^}]*border-radius:\s*999px;[^}]*backdrop-filter:\s*blur\(12px\)/);
  assert.match(css, /\.progress-track,[\s\S]*\.step-progress-track\s*\{[^}]*border-radius:\s*999px;/);
  assert.match(css, /\.progress-bar\s*\{[^}]*border-radius:\s*inherit;/);
  assert.match(css, /\.step-progress-bar\s*\{[^}]*border-radius:\s*inherit;/);
});

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const cssFiles = ["styles.css", "build.css", "maintainer.css"];
const htmlFiles = ["index.html", "build.html", "maintainer.html"];

test("every application surface shares the Steam glass material tokens", async () => {
  for (const name of cssFiles) {
    const css = await readFile(new URL(`../src/${name}`, import.meta.url), "utf8");
    assert.match(css, /--steam-blue:\s*#1a9fff;/, `${name} is missing the Steam accent`);
    assert.match(css, /--nvidia-green:\s*#76b900;/, `${name} is missing the NVIDIA accent`);
    assert.match(css, /--glass-canvas:\s*rgba\(11, 17, 24, \.68\);/, `${name} is missing its translucent dark tint`);
    assert.match(css, /body::after[\s\S]*linear-gradient\(to left, rgba\(118, 185, 0, \.08\), transparent 8%\)/, `${name} is missing the diffuse NVIDIA edge glare`);
    assert.doesNotMatch(css, /body::before[\s\S]{0,160}border:/, `${name} still draws the rejected inset window border`);
    assert.doesNotMatch(css, /--brand-gradient/, `${name} still uses the rejected full-surface gradient`);
  }
});

test("preload and native window backgrounds preserve translucent dark fallback", async () => {
  for (const name of htmlFiles) {
    const html = await readFile(new URL(`../src/${name}`, import.meta.url), "utf8");
    assert.match(html, /html, body \{ background: rgba\(11, 17, 24, \.74\);/, `${name} can flash an un-tinted transparent canvas`);
    assert.match(html, /navigator\.platform\.startsWith\("Mac"\)/, `${name} cannot reserve macOS traffic-light space conditionally`);
    assert.match(html, /<header[^>]*data-tauri-drag-region/, `${name} cannot drag its overlay title bar`);
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

  const windows = await readFile(new URL("../src-tauri/src/windows.rs", import.meta.url), "utf8");
  assert.equal([...windows.matchAll(/\.transparent\(true\)/g)].length, 2);
  assert.equal([...windows.matchAll(/\.effects\(glass_window_effects\(\)\)/g)].length, 2);
  assert.equal([...windows.matchAll(/\.shadow\(false\)/g)].length, 2);
  assert.equal([...windows.matchAll(/\.title_bar_style\(tauri::TitleBarStyle::Overlay\)/g)].length, 2);
  assert.match(windows, /\.radius\(10\.0\)/);
  assert.match(windows, /Effect::UnderWindowBackground, Effect::Acrylic/);
});

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
    assert.match(css, /--glass-canvas:\s*rgba\(11, 17, 24, \.82\);/, `${name} is missing its dark fallback tint`);
    assert.match(css, /body::before[\s\S]*border-right-color:\s*rgba\(143, 205, 64, \.62\);/, `${name} is missing the NVIDIA edge glare`);
    assert.doesNotMatch(css, /--brand-gradient/, `${name} still uses the rejected full-surface gradient`);
  }
});

test("preload and native window backgrounds preserve translucent dark fallback", async () => {
  for (const name of htmlFiles) {
    const html = await readFile(new URL(`../src/${name}`, import.meta.url), "utf8");
    assert.match(html, /html, body \{ background: rgba\(11, 17, 24, \.86\);/, `${name} can flash an un-tinted transparent canvas`);
  }

  const config = JSON.parse(await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  const main = config.app.windows[0];
  assert.equal(config.app.macOSPrivateApi, true);
  assert.equal(main.transparent, true);
  assert.deepEqual(main.backgroundColor, [11, 17, 24, 0]);
  assert.deepEqual(main.windowEffects.effects, ["underWindowBackground", "acrylic"]);
  assert.deepEqual(main.windowEffects.color, [11, 17, 24, 220]);

  const windows = await readFile(new URL("../src-tauri/src/windows.rs", import.meta.url), "utf8");
  assert.equal([...windows.matchAll(/\.transparent\(true\)/g)].length, 2);
  assert.equal([...windows.matchAll(/\.effects\(glass_window_effects\(\)\)/g)].length, 2);
  assert.match(windows, /Effect::UnderWindowBackground, Effect::Acrylic/);
});

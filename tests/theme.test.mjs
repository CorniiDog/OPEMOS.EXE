import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const cssFiles = ["styles.css", "build.css", "maintainer.css"];
const htmlFiles = ["index.html", "build.html", "maintainer.html"];

test("every application surface shares the Steam-to-NVIDIA theme tokens", async () => {
  for (const name of cssFiles) {
    const css = await readFile(new URL(`../src/${name}`, import.meta.url), "utf8");
    assert.match(css, /--steam-blue:\s*#1a9fff;/, `${name} is missing the Steam accent`);
    assert.match(css, /--nvidia-green:\s*#76b900;/, `${name} is missing the NVIDIA accent`);
    assert.match(css, /--brand-gradient:\s*linear-gradient\(/, `${name} is missing the shared gradient`);
  }
});

test("preload and native window backgrounds match the themed canvas", async () => {
  for (const name of htmlFiles) {
    const html = await readFile(new URL(`../src/${name}`, import.meta.url), "utf8");
    assert.match(html, /html, body \{ background: #171a21;/, `${name} can flash the old canvas color`);
  }

  const config = JSON.parse(await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  assert.deepEqual(config.app.windows[0].backgroundColor, [23, 26, 33, 255]);

  const windows = await readFile(new URL("../src-tauri/src/windows.rs", import.meta.url), "utf8");
  assert.equal([...windows.matchAll(/background_color\(Color\(23, 26, 33, 255\)\)/g)].length, 2);
});

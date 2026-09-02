import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

const launcher = readFileSync("test_welcome_macos.sh", "utf8");
const html = readFileSync("builder/welcome/preview.html", "utf8");
const css = readFileSync("builder/welcome/preview.css", "utf8");
const javascript = readFileSync("builder/welcome/preview.js", "utf8");

test("macOS welcome preview has a print-only non-GUI test path", () => {
  const result = spawnSync("bash", ["test_welcome_macos.sh"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, OPEMOS_GRAPHICAL_TEST_PRINT_ONLY: "1" },
  });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /builder\/welcome\/preview\.html\s*$/);
  assert.equal(result.stderr, "");
});

test("graphical preview cannot reach disks, privileges, installers, or QEMU", () => {
  const completePreview = `${launcher}\n${html}\n${css}\n${javascript}`;
  assert.doesNotMatch(completePreview, /\bsudo\b/);
  assert.doesNotMatch(completePreview, /diskutil|lsblk|blockdev|\/dev\/rdisk/);
  assert.doesNotMatch(completePreview, /qemu-system|repair_device|opemos-install-helper/);
  assert.doesNotMatch(completePreview, /fetch\s*\(|XMLHttpRequest|WebSocket/);
  assert.match(launcher, /^open "\$PREVIEW"$/m);
  assert.match(launcher, /No disks, privileges, QEMU processes, or installers are used/);
});

test("preview covers the welcome workflow and clearly labels synthetic state", () => {
  assert.match(html, /Safe simulation/);
  assert.match(html, /physical disks and privileged helpers are unreachable/);
  assert.match(javascript, /Install OPEMOS/);
  assert.match(javascript, /Reinstall OPEMOS/);
  assert.match(javascript, /Recovery simulation/);
  assert.match(javascript, /Installation-media diagnostics/);
  assert.match(javascript, /Do not disconnect the target/);
  assert.match(javascript, /ERASE/);
  assert.match(javascript, /REINSTALL/);
  assert.match(javascript, /event\.key === "Enter"/);
  assert.match(css, /backdrop-filter: blur/);
  assert.match(css, /linear-gradient\(90deg, #57c4fb, #78da70\)/);
});

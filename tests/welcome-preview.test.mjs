import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

const launcher = readFileSync("test_welcome_macos.sh", "utf8");
const html = readFileSync("builder/welcome/preview.html", "utf8");
const css = readFileSync("builder/welcome/preview.css", "utf8");
const javascript = readFileSync("builder/welcome/preview.js", "utf8");
const illustrations = ["install", "recovery", "gaming"].map((name) =>
  readFileSync(`builder/welcome/assets/${name}.svg`, "utf8"));

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
  assert.match(html, /SteamOS with NVIDIA drivers/);
  assert.match(html, /MAINTAINED BY OPEMOS/);
  assert.match(javascript, /Install SteamOS with NVIDIA drivers/);
  assert.match(javascript, /Reinstall SteamOS with NVIDIA drivers/);
  assert.doesNotMatch(`${html}\n${javascript}`, /Welcome to OPEMOS|OPEMOS is ready to boot/);
  assert.match(javascript, /Recovery simulation/);
  assert.match(javascript, /Installation-media diagnostics/);
  assert.match(javascript, /Do not disconnect the target/);
  assert.match(javascript, /ERASE/);
  assert.match(javascript, /REINSTALL/);
  assert.match(javascript, /event\.key === "Enter"/);
  assert.match(javascript, /Shut Down is recommended/);
  assert.match(javascript, /simulate-restart/);
  assert.match(javascript, /simulate-shutdown/);
  assert.match(javascript, /assets\/install\.svg/);
  assert.match(javascript, /assets\/recovery\.svg/);
  assert.match(javascript, /assets\/gaming\.svg/);
  assert.match(css, /backdrop-filter: blur/);
  assert.match(css, /linear-gradient\(90deg, #57c4fb, #78da70\)/);
  for (const illustration of illustrations) {
    assert.match(illustration, /^<svg[^>]+viewBox="0 0 520 360"/);
    assert.match(illustration, /<title id="title">[^<]+<\/title>/);
    assert.match(illustration, /<desc id="desc">[^<]+<\/desc>/);
    assert.doesNotMatch(illustration, /<script|<foreignObject|(?:href|src)=["']https?:/);
    assert.doesNotMatch(illustration, /stroke-dasharray|<filter/);
  }
  assert.doesNotMatch(`${illustrations[0]}\n${illustrations[1]}`, /<mask/);
  assert.match(illustrations[2], /<mask id="controller-clearance"[^>]*>/);
  assert.match(illustrations[2], /<use id="controller-knockout" href="#controller-shape"/);
});

function numericAttribute(element, name) {
  const match = element.match(new RegExp(`\\b${name}="([0-9.]+)"`));
  assert.ok(match, `expected ${name} on ${element}`);
  return Number(match[1]);
}

function elementWithId(svg, id) {
  const match = svg.match(new RegExp(`<[^>]+\\bid="${id}"[^>]*>`));
  assert.ok(match, `expected #${id}`);
  return match[0];
}

test("welcome illustrations preserve balanced geometry and intentional layering", () => {
  const [install, recovery, gaming] = illustrations;

  const frame = elementWithId(install, "display-frame");
  const panel = elementWithId(install, "display-panel");
  const disc = elementWithId(install, "download-disc");
  assert.ok(
    install.indexOf('id="display-stand"') < install.indexOf('id="display-frame"'),
    "display stand must remain behind the monitor frame",
  );
  assert.equal(numericAttribute(frame, "x") + numericAttribute(frame, "width") / 2, 260);
  assert.equal(numericAttribute(panel, "x") + numericAttribute(panel, "width") / 2, 260);
  assert.equal(numericAttribute(disc, "cx"), 260);

  const slotA = elementWithId(recovery, "slot-a");
  const slotB = elementWithId(recovery, "slot-b");
  assert.equal(numericAttribute(slotA, "width"), numericAttribute(slotB, "width"));
  assert.equal(numericAttribute(slotA, "height"), numericAttribute(slotB, "height"));
  assert.match(recovery, /<text x="200" y="170" text-anchor="middle" dominant-baseline="middle"/);
  assert.match(recovery, /<text x="320" y="170" text-anchor="middle" dominant-baseline="middle"/);
  assert.equal(
    numericAttribute(slotA, "x") + numericAttribute(slotA, "width") / 2,
    520 - (numericAttribute(slotB, "x") + numericAttribute(slotB, "width") / 2),
  );
  const clearance = elementWithId(recovery, "check-clearance");
  const check = elementWithId(recovery, "readiness-check");
  assert.equal(clearance.match(/\sd="([^"]+)"/)[1], check.match(/\sd="([^"]+)"/)[1]);
  assert.ok(
    numericAttribute(clearance, "stroke-width") >= numericAttribute(check, "stroke-width") + 12,
    "the overlaid check must retain a visible negative-space halo",
  );

  const display = elementWithId(gaming, "gaming-display");
  const controller = elementWithId(gaming, "controller");
  const controllerKnockout = elementWithId(gaming, "controller-knockout");
  const displayBottom = numericAttribute(display, "y") + numericAttribute(display, "height") + numericAttribute(display, "stroke-width") / 2;
  const controllerTop = numericAttribute(controller, "data-top") - numericAttribute(controller, "stroke-width") / 2;
  assert.ok(controllerTop < displayBottom, "controller must intentionally overlay the display");
  assert.equal(numericAttribute(display, "width") / numericAttribute(display, "height"), 16 / 9);
  assert.ok(
    numericAttribute(controllerKnockout, "stroke-width")
      >= numericAttribute(controller, "stroke-width") + 12,
    "controller must retain a visible transparent border over the display",
  );
  const controllerWidth = numericAttribute(controller, "data-right") - numericAttribute(controller, "data-left");
  const controllerHeight = numericAttribute(controller, "data-bottom") - numericAttribute(controller, "data-top");
  assert.equal(
    numericAttribute(controller, "data-left") + numericAttribute(controller, "data-right"),
    520,
    "controller silhouette must remain centered",
  );
  assert.ok(controllerHeight >= 140, "controller must retain full-height grips");
  assert.ok(controllerWidth / controllerHeight < 1.55, "controller must retain Steam Controller proportions");

  const directionPad = elementWithId(gaming, "direction-pad");
  const buttonTop = elementWithId(gaming, "button-top");
  const buttonRight = elementWithId(gaming, "button-right");
  const buttonLeft = elementWithId(gaming, "button-left");
  const buttonBottom = elementWithId(gaming, "button-bottom");
  assert.equal(
    numericAttribute(directionPad, "data-center-x") + numericAttribute(buttonTop, "cx"),
    520,
    "primary control clusters must mirror around the artwork center",
  );
  assert.equal(numericAttribute(buttonTop, "cx"), numericAttribute(buttonBottom, "cx"));
  assert.equal(numericAttribute(buttonLeft, "cx") + numericAttribute(buttonRight, "cx"), 700);
  assert.equal(numericAttribute(buttonLeft, "cy"), numericAttribute(buttonRight, "cy"));
  assert.equal(
    numericAttribute(buttonTop, "cy") + numericAttribute(buttonBottom, "cy"),
    2 * numericAttribute(buttonLeft, "cy"),
  );

  const leftStick = elementWithId(gaming, "left-stick");
  const rightStick = elementWithId(gaming, "right-stick");
  const stickSpacing = numericAttribute(rightStick, "cx") - numericAttribute(leftStick, "cx");
  assert.ok(stickSpacing >= 72, "thumbsticks must retain independent breathing room");
  assert.equal(numericAttribute(leftStick, "cy"), numericAttribute(rightStick, "cy"));
  assert.equal(numericAttribute(leftStick, "r"), numericAttribute(rightStick, "r"));
  assert.equal(numericAttribute(leftStick, "cx"), 520 - numericAttribute(rightStick, "cx"));

  const leftTrackpad = elementWithId(gaming, "left-trackpad");
  const rightTrackpad = elementWithId(gaming, "right-trackpad");
  assert.equal(numericAttribute(leftTrackpad, "width"), numericAttribute(rightTrackpad, "width"));
  assert.equal(numericAttribute(leftTrackpad, "height"), numericAttribute(rightTrackpad, "height"));
  assert.equal(
    numericAttribute(leftTrackpad, "x") + numericAttribute(rightTrackpad, "x")
      + numericAttribute(leftTrackpad, "width"),
    520,
    "twin trackpads must remain mirrored",
  );
});

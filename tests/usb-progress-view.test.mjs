import assert from "node:assert/strict";
import test from "node:test";

import {
  formatUsbProgressBytes,
  renderUsbWriteProgressView,
} from "../src/usb-progress-view.js";

function display() {
  const classes = new Set(["hidden"]);
  const bar = {
    value: 0,
    removeAttribute(name) {
      if (name === "value") delete this.value;
    },
  };
  return {
    container: { classList: { remove: (name) => classes.delete(name) } },
    phase: { textContent: "" },
    percent: { textContent: "" },
    detail: { textContent: "" },
    bar,
    classes,
  };
}

test("USB progress renders honest indeterminate and byte-backed states in both views", () => {
  const inline = display();
  const dialog = display();
  const formatBytes = (bytes) => `${bytes} bytes`;

  renderUsbWriteProgressView([inline, dialog], null, formatBytes);
  for (const view of [inline, dialog]) {
    assert.equal(view.classes.has("hidden"), false);
    assert.equal(view.phase.textContent, "Revalidating");
    assert.equal(view.percent.textContent, "Working…");
    assert.equal("value" in view.bar, false);
    assert.match(view.detail.textContent, /exact image and removable drive/);
  }

  const progress = {
    phase: "writing",
    bytesCompleted: 2_990_538_752,
    bytesTotal: 8_120_172_544,
    message: "Writing the verified image.",
  };
  renderUsbWriteProgressView([inline, dialog], progress, formatBytes);
  for (const view of [inline, dialog]) {
    assert.equal(view.phase.textContent, "Writing");
    assert.equal(view.percent.textContent, "36.8%");
    assert.equal(view.bar.value, progress.bytesCompleted / progress.bytesTotal * 100);
    assert.equal(view.detail.textContent, "2990538752 bytes of 8120172544 bytes processed.");
    assert.doesNotMatch(view.detail.textContent, /Writing/i);
  }
});

test("USB progress byte formatter is available to the main-window runtime", () => {
  assert.equal(formatUsbProgressBytes(0), "0 B");
  assert.equal(formatUsbProgressBytes(1_048_576), "1.00 MiB");
  assert.equal(formatUsbProgressBytes(8_120_172_544), "7.56 GiB");
});

test("the USB dialog does not repeat its detailed progress message below the bar", async () => {
  const script = await import("node:fs/promises").then(({ readFile }) => readFile(new URL("../src/main.js", import.meta.url), "utf8"));
  const handler = script.match(/function applyUsbWriteProgress\(progress\) \{[\s\S]*?\n\}/)?.[0] || "";
  assert.match(handler, /usbMessage\.textContent = ""/);
  assert.match(handler, /usbPickerMessage\.textContent = status/);
  assert.match(handler, /renderUsbWriteProgress\(progress\)/);
  assert.doesNotMatch(handler, /usbMessage\.textContent = status/);
});

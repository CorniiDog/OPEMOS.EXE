import assert from "node:assert/strict";
import test from "node:test";

import { renderUsbWriteProgressView } from "../src/usb-progress-view.js";

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
    assert.equal(view.detail.textContent, "Writing the verified image. 2990538752 bytes of 8120172544 bytes.");
  }
});

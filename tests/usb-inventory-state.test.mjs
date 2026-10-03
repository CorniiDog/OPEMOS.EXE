import assert from "node:assert/strict";
import test from "node:test";

import {
  acceptedUsbInventoryPath,
  usbFirstShowRetryDelay,
  usbInventoryNeedsRefresh,
} from "../src/usb-inventory-state.js";

test("an empty post-build scan remains retryable without restarting the app", () => {
  const outputPath = "C:\\Images\\steamos-nvidia.img";
  const firstScan = { completed: true, targetCount: 0 };
  const refreshedOutputPath = acceptedUsbInventoryPath(outputPath, firstScan);
  assert.equal(refreshedOutputPath, null);
  assert.equal(usbInventoryNeedsRefresh(outputPath, refreshedOutputPath, 0), true);
});

test("a failed or superseded post-build scan remains retryable", () => {
  const outputPath = "C:\\Images\\steamos-nvidia.img";
  assert.equal(acceptedUsbInventoryPath(outputPath, {
    completed: false,
    targetCount: 0,
  }), null);
  assert.equal(usbInventoryNeedsRefresh(outputPath, null, 0), true);
});

test("a usable inventory is retained only for the exact completed output", () => {
  const outputPath = "C:\\Images\\steamos-nvidia.img";
  const refreshedOutputPath = acceptedUsbInventoryPath(outputPath, {
    completed: true,
    targetCount: 1,
  });
  assert.equal(refreshedOutputPath, outputPath);
  assert.equal(usbInventoryNeedsRefresh(outputPath, refreshedOutputPath, 1), false);
  assert.equal(usbInventoryNeedsRefresh("C:\\Images\\new.img", refreshedOutputPath, 1), true);
});

test("USB inventory state rejects malformed inputs", () => {
  assert.throws(() => usbInventoryNeedsRefresh("", null, 0), /outputPath/);
  assert.throws(() => usbInventoryNeedsRefresh("image.img", null, -1), /targetCount/);
  assert.throws(() => acceptedUsbInventoryPath("image.img", null), /outcome/);
  assert.throws(() => acceptedUsbInventoryPath("image.img", {
    completed: "yes",
    targetCount: 1,
  }), /completed/);
});

test("first-show USB inventory retries are bounded and stop on discovery", () => {
  assert.equal(usbFirstShowRetryDelay(1, { completed: true, targetCount: 0 }), 1000);
  assert.equal(usbFirstShowRetryDelay(2, { completed: true, targetCount: 0 }), 2000);
  assert.equal(usbFirstShowRetryDelay(3, { completed: true, targetCount: 0 }), null);
  assert.equal(usbFirstShowRetryDelay(1, { completed: true, targetCount: 1 }), null);
  assert.equal(usbFirstShowRetryDelay(1, { completed: false, targetCount: 0 }), null);
  assert.throws(() => usbFirstShowRetryDelay(0, { completed: true, targetCount: 0 }), /attempt/);
  assert.throws(() => usbFirstShowRetryDelay(1, { completed: true, targetCount: -1 }), /targetCount/);
});

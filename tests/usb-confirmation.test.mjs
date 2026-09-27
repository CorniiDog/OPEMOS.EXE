import assert from "node:assert/strict";
import test from "node:test";
import {
  USB_CONFIRMATION_PHRASE,
  usbConfirmationForBackend,
  usbConfirmationMatches,
} from "../src/usb-confirmation.js";

test("the visible destructive phrase is short and exact", () => {
  assert.equal(USB_CONFIRMATION_PHRASE, "ERASE");
  assert.equal(usbConfirmationMatches("ERASE"), true);
  for (const value of ["", "erase", "ERASE ", " ERASE", "ERASE PhysicalDrive2"]) {
    assert.equal(usbConfirmationMatches(value), false);
  }
});

test("the native preflight still receives a phrase bound to the selected disk", () => {
  assert.equal(usbConfirmationForBackend("PhysicalDrive2", "ERASE"), "ERASE PhysicalDrive2");
  assert.throws(() => usbConfirmationForBackend("", "ERASE"), /identifier is required/);
  assert.throws(() => usbConfirmationForBackend("PhysicalDrive2", "erase"), /Type ERASE exactly/);
});

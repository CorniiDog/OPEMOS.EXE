import test from "node:test";
import assert from "node:assert/strict";

import { validateGuestResult, validateProgressLines } from "./headless-vm/validate-result.mjs";

const validResult = {
  schemaVersion: 1,
  status: "passed",
  reason: "synthetic USB identity, capacity, progress, cancellation cleanup, readback, and recovery A-B rollback succeeded",
  checks: [
    "usb-identity", "usb-capacity", "usb-progress", "usb-cancellation-cleanup",
    "usb-readback", "recovery-ab-rollback",
  ],
};
const block = 4 * 1024 * 1024;
const progressValues = [
  ...Array.from({ length: 8 }, (_, index) => (index + 1) * block),
  ...Array.from({ length: 15 }, (_, index) => (index + 1) * block),
  ...Array.from({ length: 16 }, (_, index) => (index + 1) * block),
];
const progressLines = progressValues.map((bytesCompleted) => JSON.stringify({
  schemaVersion: 1, phase: "writing", bytesCompleted, bytesTotal: 64 * 1024 * 1024,
}));

test("headless VM result accepts only the complete current schema", () => {
  assert.equal(validateGuestResult(validResult), true);
  assert.equal(validateGuestResult({ ...validResult, schemaVersion: 2 }), false);
  assert.equal(validateGuestResult({ ...validResult, status: "failed" }), false);
  assert.equal(validateGuestResult({ ...validResult, checks: validResult.checks.slice(1) }), false);
  assert.equal(validateGuestResult({ ...validResult, reason: "stale success" }), false);
});

test("headless VM progress rejects missing, stale, malformed, and reordered events", () => {
  assert.equal(validateProgressLines(progressLines), true);
  assert.equal(validateProgressLines(progressLines.slice(1)), false);
  assert.equal(validateProgressLines([...progressLines, progressLines.at(-1)]), false);
  const reordered = [...progressLines];
  [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
  assert.equal(validateProgressLines(reordered), false);
  const stale = [...progressLines];
  stale[0] = JSON.stringify({ schemaVersion: 1, phase: "writing", bytesCompleted: block, bytesTotal: 1 });
  assert.equal(validateProgressLines(stale), false);
  assert.throws(() => validateProgressLines(["not JSON", ...progressLines.slice(1)]));
});

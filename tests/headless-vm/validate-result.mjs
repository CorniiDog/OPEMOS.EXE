import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const expectedChecks = [
  "usb-identity",
  "usb-capacity",
  "usb-progress",
  "usb-cancellation-cleanup",
  "usb-readback",
  "recovery-ab-rollback",
];
const expectedReason = "synthetic USB identity, capacity, progress, cancellation cleanup, readback, and recovery A-B rollback succeeded";
const blockBytes = 4 * 1024 * 1024;
const totalBytes = 64 * 1024 * 1024;
const expectedProgress = [
  ...Array.from({ length: 8 }, (_, index) => (index + 1) * blockBytes),
  ...Array.from({ length: 15 }, (_, index) => (index + 1) * blockBytes),
  ...Array.from({ length: 16 }, (_, index) => (index + 1) * blockBytes),
];

export function validateGuestResult(value) {
  return value?.schemaVersion === 1
    && value.status === "passed"
    && value.reason === expectedReason
    && JSON.stringify(value.checks) === JSON.stringify(expectedChecks);
}

export function validateProgressLines(lines) {
  if (lines.length !== expectedProgress.length) return false;
  return lines.every((line, index) => {
    const value = JSON.parse(line);
    return value?.schemaVersion === 1
      && value.phase === "writing"
      && value.bytesTotal === totalBytes
      && value.bytesCompleted === expectedProgress[index];
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [resultPath, progressPath] = process.argv.slice(2);
  try {
    const result = JSON.parse(await readFile(resultPath, "utf8"));
    const progress = (await readFile(progressPath, "utf8")).trim().split(/\n/).filter(Boolean);
    if (!validateGuestResult(result)) {
      console.error("guest result did not match the complete current schema");
      process.exitCode = 1;
    } else if (!validateProgressLines(progress)) {
      console.error(`guest progress sequence was invalid (${progress.length} records)`);
      process.exitCode = 1;
    }
  } catch (error) {
    console.error(`guest result validation failed: ${error.message}`);
    process.exitCode = 1;
  }
}

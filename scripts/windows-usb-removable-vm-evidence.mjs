#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;

function fail(message) {
  throw new Error(message);
}

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object.`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has an unexpected schema.`);
  }
}

export function validateWindowsUsbRemovableVmEvidence(value, expectedCommit) {
  exactObject(value, [
    "schemaVersion", "test", "sourceCommit", "executable", "hypervisor", "target",
    "offlineProbe", "writer", "cleanup",
  ], "evidence");
  if (value.schemaVersion !== 1 || value.test !== "windows-usb-removable-vm") {
    fail("Evidence identity is invalid.");
  }
  if (!COMMIT.test(expectedCommit) || value.sourceCommit !== expectedCommit) {
    fail("Evidence does not bind the exact source commit.");
  }

  exactObject(value.executable, ["size", "sha256"], "executable");
  if (!Number.isSafeInteger(value.executable.size) || value.executable.size < 1
      || !SHA256.test(value.executable.sha256)) {
    fail("Executable identity is invalid.");
  }

  exactObject(value.hypervisor, ["name", "accelerator", "headless", "snapshotSource", "usbDevice"], "hypervisor");
  if (value.hypervisor.name !== "qemu" || value.hypervisor.accelerator !== "whpx"
      || value.hypervisor.headless !== true || value.hypervisor.snapshotSource !== true
      || value.hypervisor.usbDevice !== "usb-storage") {
    fail("Evidence did not use the required headless QEMU USB topology.");
  }

  exactObject(value.target, [
    "busType", "mediaType", "serialNumber", "isBoot", "isSystem", "isReadOnly",
    "initiallyOffline", "deviceBytes", "blockSize",
  ], "target");
  if (value.target.busType !== "USB" || value.target.mediaType !== "Removable Media"
      || typeof value.target.serialNumber !== "string" || !value.target.serialNumber.startsWith("OPEMOS-VM-")
      || value.target.isBoot !== false || value.target.isSystem !== false
      || value.target.isReadOnly !== false || value.target.initiallyOffline !== false
      || !Number.isSafeInteger(value.target.deviceBytes) || value.target.deviceBytes < 64 * 1024 * 1024
      || ![512, 1024, 2048, 4096].includes(value.target.blockSize)) {
    fail("Windows did not report the required disposable USB removable-media target.");
  }

  exactObject(value.offlineProbe, ["attempted", "refused", "remainedOnline", "fullyQualifiedErrorId"], "offlineProbe");
  if (value.offlineProbe.attempted !== true || value.offlineProbe.refused !== true
      || value.offlineProbe.remainedOnline !== true
      || typeof value.offlineProbe.fullyQualifiedErrorId !== "string"
      || !value.offlineProbe.fullyQualifiedErrorId.includes("Set-Disk")) {
    fail("The VM did not reproduce Windows removable-media offline refusal.");
  }

  exactObject(value.writer, [
    "helperExitCode", "receiptSuccess", "sourceSha256", "verifiedSha256",
    "rawReadbackSha256", "sourceUnchanged", "targetAbsentAfter", "ejected",
  ], "writer");
  if (value.writer.helperExitCode !== 0 || value.writer.receiptSuccess !== true
      || !SHA256.test(value.writer.sourceSha256)
      || value.writer.verifiedSha256 !== value.writer.sourceSha256
      || value.writer.rawReadbackSha256 !== value.writer.sourceSha256
      || value.writer.sourceUnchanged !== true || value.writer.targetAbsentAfter !== true
      || value.writer.ejected !== true) {
    fail("The exact Windows writer did not complete write, readback, and verified safe ejection.");
  }

  exactObject(value.cleanup, [
    "qemuStopped", "overlayRemoved", "usbBackingRemoved", "taskRemoved", "sourceDiskUnchanged",
  ], "cleanup");
  if (Object.values(value.cleanup).some((entry) => entry !== true)) {
    fail("The disposable VM cleanup proof is incomplete.");
  }
  return value;
}

async function main() {
  if (process.argv.length !== 4) {
    fail("Usage: windows-usb-removable-vm-evidence.mjs EVIDENCE.json SOURCE_COMMIT");
  }
  const evidencePath = path.resolve(process.argv[2]);
  const bytes = await readFile(evidencePath);
  if (bytes.length > 64 * 1024) fail("Evidence file is oversized.");
  const value = JSON.parse(bytes.toString("utf8"));
  validateWindowsUsbRemovableVmEvidence(value, process.argv[3]);
  process.stdout.write(`Windows removable-USB VM evidence passed for ${process.argv[3]}.\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

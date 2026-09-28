import test from "node:test";
import assert from "node:assert/strict";
import { validateWindowsUsbRemovableVmEvidence } from "../scripts/windows-usb-removable-vm-evidence.mjs";

const commit = "7".repeat(40);
const sha = "a".repeat(64);
const valid = () => ({
  schemaVersion: 1,
  test: "windows-usb-removable-vm",
  sourceCommit: commit,
  executable: { size: 21_000_000, sha256: "b".repeat(64) },
  hypervisor: {
    name: "qemu", accelerator: "whpx", headless: true, snapshotSource: true, usbDevice: "usb-storage",
  },
  target: {
    busType: "USB", mediaType: "Removable Media", serialNumber: "OPEMOS-VM-USB-1",
    isBoot: false, isSystem: false, isReadOnly: false, initiallyOffline: false,
    deviceBytes: 268_435_456, blockSize: 512,
  },
  offlineProbe: {
    attempted: true, refused: true, remainedOnline: true,
    fullyQualifiedErrorId: "StorageWMI 1,Set-Disk",
  },
  writer: {
    helperExitCode: 0, receiptSuccess: true, sourceSha256: sha, verifiedSha256: sha,
    rawReadbackSha256: sha, sourceUnchanged: true, targetAbsentAfter: true, ejected: true,
  },
  cleanup: {
    qemuStopped: true, overlayRemoved: true, usbBackingRemoved: true,
    taskRemoved: true, sourceDiskUnchanged: true,
  },
});

test("accepts exact removable-USB VM write and cleanup evidence", () => {
  assert.equal(validateWindowsUsbRemovableVmEvidence(valid(), commit).sourceCommit, commit);
});

test("refuses fixed disks, missing offline refusal, stale commits, and incomplete cleanup", () => {
  for (const mutate of [
    (value) => { value.target.mediaType = "Fixed hard disk media"; },
    (value) => { value.offlineProbe.refused = false; },
    (value) => { value.writer.rawReadbackSha256 = "c".repeat(64); },
    (value) => { value.writer.targetAbsentAfter = false; },
    (value) => { value.writer.ejected = false; },
    (value) => { value.cleanup.qemuStopped = false; },
    (value) => { value.extra = true; },
  ]) {
    const value = valid();
    mutate(value);
    assert.throws(() => validateWindowsUsbRemovableVmEvidence(value, commit));
  }
  assert.throws(() => validateWindowsUsbRemovableVmEvidence(valid(), "8".repeat(40)));
});

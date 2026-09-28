import test from "node:test";
import assert from "node:assert/strict";
import { validateInstallMediaTargetVmEvidence } from "../scripts/install-media-target-vm-evidence.mjs";

const commit = "7".repeat(40);
const identity = "a".repeat(64);
const valid = () => ({
  schemaVersion: 1,
  test: "install-media-target-vm",
  sourceCommit: commit,
  helper: { size: 20_000, sha256: "b".repeat(64) },
  hypervisor: { name: "hyper-v", headless: true, vm: "OPEMOS-KVM-B", diskKind: "dynamic-vhdx" },
  target: {
    device: "/dev/sdb", model: "Msft Virtual Disk", serial: "",
    bytes: 16 * 1024 * 1024 * 1024, initialPartitionCount: 0,
  },
  unallocated: { status: "eligible", listedExactlyOnce: true, layout: "fresh" },
  mounted: { status: "eligible", listedExactlyOnce: true, layout: "fresh" },
  release: {
    boundedUnmountSucceeded: true, childMountsRemaining: 0,
    identityBefore: identity, identityAfter: identity,
  },
  cleanup: {
    diskDetached: true, vhdxRemoved: true, guestStageRemoved: true,
    vmRemainedRunning: true, systemDiskUnchanged: true,
  },
});

test("accepts exact unallocated and mounted target VM evidence", () => {
  assert.equal(validateInstallMediaTargetVmEvidence(valid(), commit).sourceCommit, commit);
});

test("refuses hidden targets, unstable identities, stale commits, and incomplete cleanup", () => {
  for (const mutate of [
    (value) => { value.unallocated.status = "mounted-or-swap-active"; },
    (value) => { value.mounted.listedExactlyOnce = false; },
    (value) => { value.release.identityAfter = "c".repeat(64); },
    (value) => { value.cleanup.diskDetached = false; },
    (value) => { value.extra = true; },
  ]) {
    const value = valid();
    mutate(value);
    assert.throws(() => validateInstallMediaTargetVmEvidence(value, commit));
  }
  assert.throws(() => validateInstallMediaTargetVmEvidence(valid(), "8".repeat(40)));
});

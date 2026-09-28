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
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object.`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has an unexpected schema.`);
  }
}

export function validateInstallMediaTargetVmEvidence(value, expectedCommit) {
  exactObject(value, [
    "schemaVersion", "test", "sourceCommit", "helper", "hypervisor", "target",
    "unallocated", "mounted", "release", "cleanup",
  ], "evidence");
  if (value.schemaVersion !== 1 || value.test !== "install-media-target-vm") fail("Evidence identity is invalid.");
  if (!COMMIT.test(expectedCommit) || value.sourceCommit !== expectedCommit) {
    fail("Evidence does not bind the exact source commit.");
  }
  exactObject(value.helper, ["size", "sha256"], "helper");
  if (!Number.isSafeInteger(value.helper.size) || value.helper.size < 1 || !SHA256.test(value.helper.sha256)) {
    fail("The production helper identity is invalid.");
  }
  exactObject(value.hypervisor, ["name", "headless", "vm", "diskKind"], "hypervisor");
  if (value.hypervisor.name !== "hyper-v" || value.hypervisor.headless !== true
      || value.hypervisor.vm !== "OPEMOS-KVM-B" || value.hypervisor.diskKind !== "dynamic-vhdx") {
    fail("Evidence did not use the required headless disposable Hyper-V disk topology.");
  }
  exactObject(value.target, ["device", "model", "serial", "bytes", "initialPartitionCount"], "target");
  if (!/^\/dev\/sd[a-z]$/.test(value.target.device) || typeof value.target.model !== "string"
      || typeof value.target.serial !== "string" || !Number.isSafeInteger(value.target.bytes)
      || value.target.bytes < 12 * 1024 * 1024 * 1024 || value.target.initialPartitionCount !== 0) {
    fail("The disposable installation target identity is invalid.");
  }
  for (const label of ["unallocated", "mounted"]) {
    exactObject(value[label], ["status", "listedExactlyOnce", "layout"], label);
    if (value[label].status !== "eligible" || value[label].listedExactlyOnce !== true
        || value[label].layout !== "fresh") {
      fail(`The ${label} installation target was not accepted exactly once.`);
    }
  }
  exactObject(value.release, [
    "boundedUnmountSucceeded", "childMountsRemaining", "identityBefore", "identityAfter",
  ], "release");
  if (value.release.boundedUnmountSucceeded !== true || value.release.childMountsRemaining !== 0
      || !SHA256.test(value.release.identityBefore)
      || value.release.identityAfter !== value.release.identityBefore) {
    fail("The confirmed target was not safely released with stable identity.");
  }
  exactObject(value.cleanup, [
    "diskDetached", "vhdxRemoved", "guestStageRemoved", "vmRemainedRunning", "systemDiskUnchanged",
  ], "cleanup");
  if (Object.values(value.cleanup).some((entry) => entry !== true)) {
    fail("The disposable VM cleanup proof is incomplete.");
  }
  return value;
}

async function main() {
  if (process.argv.length !== 4) fail("Usage: install-media-target-vm-evidence.mjs EVIDENCE.json SOURCE_COMMIT");
  const evidencePath = path.resolve(process.argv[2]);
  const bytes = await readFile(evidencePath);
  if (bytes.length > 64 * 1024) fail("Evidence file is oversized.");
  const value = JSON.parse(bytes.toString("utf8"));
  validateInstallMediaTargetVmEvidence(value, process.argv[3]);
  process.stdout.write(`Installation-target VM evidence passed for ${process.argv[3]}.\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const run = await readFile(new URL("./headless-vm/run.sh", import.meta.url), "utf8");
const guest = await readFile(new URL("./headless-vm/user-data", import.meta.url), "utf8");
const ignore = await readFile(new URL("./headless-vm/.gitignore", import.meta.url), "utf8");

test("headless VM harness exposes no GUI, network, monitor, SSH, or host disks", () => {
  assert.match(run, /-display none/);
  assert.match(run, /-monitor none/);
  assert.match(run, /-nic none/);
  assert.match(run, /if=pflash,format=raw,readonly=on/);
  assert.match(run, /uefi-vars\.fd/);
  assert.doesNotMatch(run, /hostfwd|tap,|bridge,|\/dev\/disk|\/dev\/rdisk|ssh\b/);
  assert.match(run, /synthetic-test-disk\.raw/);
  assert.match(run, /STEAMOS_SYNTH_V1/);
});

test("guest writes only the exact disposable synthetic virtio disk", () => {
  assert.match(guest, /\/dev\/disk\/by-id\/virtio-STEAMOS_SYNTH_V1/);
  assert.match(guest, /synthetic disk resolved to guest root/);
  assert.match(guest, /67108864/);
  assert.match(guest, /name=rootfs-A/);
  assert.match(guest, /name=rootfs-B/);
  assert.match(guest, /synthetic recovery B rollback mismatch/);
  assert.match(guest, /STEAMOS_HEADLESS_RESULT/);
});

test("nested ignores cover VM work and machine results", () => {
  assert.match(ignore, /^work\/$/m);
  assert.match(ignore, /^results\/\*$/m);
  assert.match(ignore, /^!results\/\.gitignore$/m);
});

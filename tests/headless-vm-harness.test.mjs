import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, symlink } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
  assert.match(run, /unexpected-test-disk\.raw/);
  assert.match(run, /STEAMOS_SYNTH_V1/);
  assert.match(run, /STEAMOS_WRONG_V1/);
});

test("guest writes only the exact disposable synthetic virtio disk", () => {
  assert.match(guest, /\/dev\/disk\/by-id\/virtio-STEAMOS_SYNTH_V1/);
  assert.match(guest, /guest root disk passed USB authorization/);
  assert.match(guest, /67108864/);
  assert.match(guest, /unexpected device identity passed USB authorization/);
  assert.match(guest, /undersized capacity boundary passed USB authorization/);
  assert.match(guest, /oversized capacity boundary passed USB authorization/);
  assert.match(guest, /for cancel_point in 0 8 15/);
  assert.match(guest, /STEAMOS_HEADLESS_PROGRESS/);
  assert.match(guest, /cancelled synthetic USB was not sanitized/);
  assert.match(guest, /synthetic USB full readback mismatch/);
  assert.match(guest, /name=rootfs-A/);
  assert.match(guest, /name=rootfs-B/);
  assert.match(guest, /synthetic recovery B rollback mismatch/);
  assert.match(guest, /STEAMOS_HEADLESS_RESULT/);
});

test("host state validation rejects symlinked runtime directories", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "steamos-headless-state-"));
  const redirected = join(fixture, "redirected");
  await mkdir(redirected);
  await symlink(redirected, join(fixture, "work"));
  try {
    const result = spawnSync("bash", [new URL("./headless-vm/run.sh", import.meta.url).pathname], {
      encoding: "utf8",
      env: {
        ...process.env,
        STEAMOS_HEADLESS_VM_STATE_ROOT: fixture,
        STEAMOS_HEADLESS_VM_STATE_CHECK_ONLY: "1",
      },
    });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /refuses unsafe runtime\/result state/);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test("nested ignores cover VM work and machine results", () => {
  assert.match(ignore, /^work\/$/m);
  assert.match(ignore, /^results\/\*$/m);
  assert.match(ignore, /^!results\/\.gitignore$/m);
});

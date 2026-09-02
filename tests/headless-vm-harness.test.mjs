import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
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
  assert.match(run, /welcome-inventory-disk\.raw/);
  assert.match(run, /STEAMOS_SYNTH_V1/);
  assert.match(run, /STEAMOS_WRONG_V1/);
  assert.match(run, /OPEMOS_WELCOME_V1/);
  assert.match(run, /builder\/welcome\/opemos-install-helper/);
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
  assert.match(guest, /welcome helper selected the wrong physical disk/);
  assert.match(guest, /welcome helper identity was not stable/);
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

test("host state validation detects work and result replacement after validation", async () => {
  for (const replacedName of ["work", "results"]) {
    const fixture = await mkdtemp(join(tmpdir(), `steamos-headless-replace-${replacedName}-`));
    const redirected = join(fixture, "redirected");
    await mkdir(redirected);
    try {
      const child = spawn("bash", [new URL("./headless-vm/run.sh", import.meta.url).pathname], {
        env: {
          ...process.env,
          STEAMOS_HEADLESS_VM_STATE_ROOT: fixture,
          STEAMOS_HEADLESS_VM_STATE_CHECK_ONLY: "1",
          STEAMOS_HEADLESS_VM_LIFECYCLE_TEST: "1",
          STEAMOS_HEADLESS_VM_TEST_PHASE: "validated",
        },
        stdio: ["ignore", "ignore", "pipe"],
      });
      let stderr = "";
      child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        try { await readFile(join(fixture, "test-phase")); break; } catch {}
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      await rename(join(fixture, replacedName), join(fixture, `${replacedName}-original`));
      await symlink(redirected, join(fixture, replacedName));
      await writeFile(join(fixture, "test-continue"), "continue\n");
      const status = await new Promise((resolve) => child.once("close", resolve));
      assert.notEqual(status, 0);
      assert.match(stderr, /detected replaced runtime\/result state/);
      assert.deepEqual(await readFile(join(fixture, "test-phase"), "utf8"), "validated\n");
    } finally {
      await rm(fixture, { recursive: true, force: true });
    }
  }
});

test("nested ignores cover VM work and machine results", () => {
  assert.match(ignore, /^work\/$/m);
  assert.match(ignore, /^results\/\*$/m);
  assert.match(ignore, /^!results\/\.gitignore$/m);
});

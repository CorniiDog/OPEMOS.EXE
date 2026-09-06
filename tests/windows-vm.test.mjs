import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  initializeWindowsVmRoot,
  inspectWindowsVmRoot,
  WINDOWS_VM_DIRS,
} from "../scripts/windows-vm.mjs";

async function temporary() {
  return mkdtemp(path.join(os.tmpdir(), "opemos-windows-vm-"));
}

test("Windows VM containment initializes exact private layout idempotently", async () => {
  const parent = await temporary();
  try {
    const root = path.join(parent, "windows-vm");
    const first = await initializeWindowsVmRoot(root);
    const second = await initializeWindowsVmRoot(root);
    assert.equal(first.status, "within-budget");
    assert.deepEqual(second, first);
    assert.deepEqual(Object.keys(first.categories), WINDOWS_VM_DIRS);
    assert.equal(first.files, 1);
    assert.equal(first.logicalBytes, "74");
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("Windows VM containment rejects changed marker and unexpected root entries", async () => {
  const parent = await temporary();
  try {
    const root = path.join(parent, "windows-vm");
    await initializeWindowsVmRoot(root);
    await writeFile(path.join(root, ".opemos-exe-windows-vm.json"), "{}\n");
    await assert.rejects(inspectWindowsVmRoot(root), /marker identity/);
    await writeFile(
      path.join(root, ".opemos-exe-windows-vm.json"),
      '{"creator":"OPEMOS.EXE","kind":"opemos-exe-windows-vm","schemaVersion":1}\n',
    );
    await writeFile(path.join(root, "foreign"), "x");
    await assert.rejects(inspectWindowsVmRoot(root), /unexpected entries: foreign/);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("Windows VM containment rejects directory and nested file symlinks", async () => {
  const parent = await temporary();
  try {
    const root = path.join(parent, "windows-vm");
    await initializeWindowsVmRoot(root);
    await rm(path.join(root, "runtime"), { recursive: true });
    await symlink(parent, path.join(root, "runtime"));
    await assert.rejects(inspectWindowsVmRoot(root), /runtime directory.*not a link/);
    await rm(path.join(root, "runtime"));
    await mkdir(path.join(root, "runtime"), { mode: 0o700 });
    await symlink("/etc/passwd", path.join(root, "runtime", "escape"));
    await assert.rejects(inspectWindowsVmRoot(root), /refuses symlink: runtime\/escape/);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("Windows VM containment rejects permissive directories and oversized sources", async () => {
  const parent = await temporary();
  try {
    const root = path.join(parent, "windows-vm");
    await initializeWindowsVmRoot(root);
    await chmod(path.join(root, "runtime"), 0o755);
    await assert.rejects(inspectWindowsVmRoot(root), /mode 0700/);
    await chmod(path.join(root, "runtime"), 0o700);
    const source = path.join(root, "sources", "oversized.iso");
    const handle = await import("node:fs/promises").then(({ open }) => open(source, "w", 0o600));
    try {
      await handle.truncate(8 * 1024 * 1024 * 1024 + 1);
    } finally {
      await handle.close();
    }
    await assert.rejects(inspectWindowsVmRoot(root), /8 GiB logical-size limit/);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("Windows VM containment counts sparse files by logical and allocated bytes", async () => {
  const parent = await temporary();
  try {
    const root = path.join(parent, "windows-vm");
    await initializeWindowsVmRoot(root);
    const sparse = path.join(root, "base", "windows.qcow2");
    const handle = await import("node:fs/promises").then(({ open }) => open(sparse, "w", 0o600));
    try {
      await handle.truncate(64 * 1024 * 1024);
    } finally {
      await handle.close();
    }
    const result = await inspectWindowsVmRoot(root);
    assert.equal(result.categories.base.logicalBytes, String(64 * 1024 * 1024));
    assert.ok(BigInt(result.categories.base.allocatedBytes) < BigInt(result.categories.base.logicalBytes));
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

#!/usr/bin/env node
import { lstat, mkdir, open, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const WINDOWS_VM_DIRS = [
  "sources", "generated", "base", "overlays", "runtime", "logs", "manifests",
];
export const WINDOWS_VM_LIMITS = Object.freeze({
  softAllocatedBytes: 40n * 1024n ** 3n,
  hardAllocatedBytes: 55n * 1024n ** 3n,
  sourceLogicalBytes: 8n * 1024n ** 3n,
  overlayAllocatedBytes: 12n * 1024n ** 3n,
});
const MARKER_NAME = ".opemos-exe-windows-vm.json";
const MARKER_BYTES = Buffer.from(
  '{"creator":"OPEMOS.EXE","kind":"opemos-exe-windows-vm","schemaVersion":1}\n',
);

function fail(message) {
  throw new Error(message);
}

async function safeDirectory(value, label) {
  const info = await lstat(value, { bigint: true });
  if (info.isSymbolicLink() || !info.isDirectory()) {
    fail(`${label} must be a real directory, not a link or special file.`);
  }
  if (Number(info.mode & 0o777n) !== 0o700 || info.uid !== BigInt(process.getuid())) {
    fail(`${label} must be owned by the current user with mode 0700.`);
  }
  return info;
}

async function writeMarker(root) {
  const marker = path.join(root, MARKER_NAME);
  try {
    const handle = await open(marker, "wx", 0o600);
    try {
      await handle.writeFile(MARKER_BYTES);
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    const info = await lstat(marker, { bigint: true });
    if (info.isSymbolicLink() || !info.isFile()) {
      fail("Windows VM containment marker is not a regular file.");
    }
    const bytes = await readFile(marker);
    if (!bytes.equals(MARKER_BYTES)) {
      fail("Windows VM containment marker identity does not match.");
    }
  }
}

export async function initializeWindowsVmRoot(root) {
  if (!path.isAbsolute(root)) fail("Windows VM root must be absolute.");
  await mkdir(root, { recursive: true, mode: 0o700 });
  await safeDirectory(root, "Windows VM root");
  await writeMarker(root);
  for (const name of WINDOWS_VM_DIRS) {
    const child = path.join(root, name);
    try {
      await mkdir(child, { mode: 0o700 });
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
    }
    await safeDirectory(child, `Windows VM ${name} directory`);
  }
  return inspectWindowsVmRoot(root);
}

async function addTree(root, relative, totals, depth = 0) {
  if (depth > 8) fail("Windows VM containment tree exceeds the depth limit.");
  const current = path.join(root, relative);
  const info = await lstat(current, { bigint: true });
  if (info.isSymbolicLink()) fail(`Windows VM containment refuses symlink: ${relative}`);
  if (info.isFile()) {
    totals.files += 1;
    if (totals.files > 4096) fail("Windows VM containment exceeds 4096 files.");
    totals.logicalBytes += info.size;
    totals.allocatedBytes += info.blocks * 512n;
    return;
  }
  if (!info.isDirectory()) fail(`Windows VM containment refuses special file: ${relative}`);
  const entries = await readdir(current);
  entries.sort();
  for (const name of entries) {
    if (name === "." || name === ".." || name.includes("/") || name.includes("\u0000")) {
      fail("Windows VM containment contains an invalid name.");
    }
    await addTree(root, path.join(relative, name), totals, depth + 1);
  }
}

export async function inspectWindowsVmRoot(root) {
  await safeDirectory(root, "Windows VM root");
  const marker = path.join(root, MARKER_NAME);
  const markerInfo = await lstat(marker, { bigint: true });
  if (markerInfo.isSymbolicLink() || !markerInfo.isFile()
      || Number(markerInfo.mode & 0o777n) !== 0o600
      || markerInfo.uid !== BigInt(process.getuid())
      || !(await readFile(marker)).equals(MARKER_BYTES)) {
    fail("Windows VM containment marker identity does not match.");
  }
  const allowed = new Set([...WINDOWS_VM_DIRS, MARKER_NAME]);
  const top = await readdir(root);
  const unexpected = top.filter((name) => !allowed.has(name));
  if (unexpected.length) fail(`Windows VM root has unexpected entries: ${unexpected.join(", ")}`);

  const categories = {};
  let totalAllocated = markerInfo.blocks * 512n;
  let totalLogical = markerInfo.size;
  let totalFiles = 1;
  for (const name of WINDOWS_VM_DIRS) {
    await safeDirectory(path.join(root, name), `Windows VM ${name} directory`);
    const totals = { logicalBytes: 0n, allocatedBytes: 0n, files: 0 };
    await addTree(root, name, totals);
    categories[name] = totals;
    totalAllocated += totals.allocatedBytes;
    totalLogical += totals.logicalBytes;
    totalFiles += totals.files;
  }
  if (categories.sources.logicalBytes > WINDOWS_VM_LIMITS.sourceLogicalBytes) {
    fail("Windows VM sources exceed the 8 GiB logical-size limit.");
  }
  if (categories.overlays.allocatedBytes > WINDOWS_VM_LIMITS.overlayAllocatedBytes) {
    fail("Windows VM overlays exceed the 12 GiB allocated-size limit.");
  }
  if (totalAllocated > WINDOWS_VM_LIMITS.hardAllocatedBytes) {
    fail("Windows VM containment exceeds the 55 GiB hard allocated-size limit.");
  }
  return {
    schemaVersion: 1,
    status: totalAllocated > WINDOWS_VM_LIMITS.softAllocatedBytes ? "over-soft-target" : "within-budget",
    root,
    logicalBytes: totalLogical.toString(),
    allocatedBytes: totalAllocated.toString(),
    files: totalFiles,
    categories: Object.fromEntries(Object.entries(categories).map(([name, value]) => [
      name,
      {
        logicalBytes: value.logicalBytes.toString(),
        allocatedBytes: value.allocatedBytes.toString(),
        files: value.files,
      },
    ])),
  };
}

function defaultRoot() {
  const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  return path.join(repository, "local-inputs", "windows-vm");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const command = process.argv[2];
  const root = defaultRoot();
  try {
    const result = command === "init"
      ? await initializeWindowsVmRoot(root)
      : command === "status"
        ? await inspectWindowsVmRoot(root)
        : fail("Usage: scripts/windows-vm.mjs init|status");
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  } catch (error) {
    process.stderr.write(String(error?.message || error) + "\n");
    process.exitCode = 1;
  }
}

#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectWindowsVmRoot, WINDOWS_VM_LIMITS } from "./windows-vm.mjs";

const KEYS = ["schemaVersion", "kind", "filename", "sourceUrl", "product", "release", "edition", "architecture", "size", "sha256"];
const HASH = /^[0-9a-f]{64}$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.iso$/;

function fail(message) { throw new Error(message); }
function exactObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("Windows media identity must be an object.");
  const keys = Object.keys(value).sort();
  if (keys.join("\n") !== [...KEYS].sort().join("\n")) fail("Windows media identity fields do not match schema 1.");
}
export function validateWindowsMediaIdentity(value) {
  exactObject(value);
  if (value.schemaVersion !== 1 || value.kind !== "opemos-exe-windows-evaluation-media") fail("Windows media identity kind or schema is unsupported.");
  if (typeof value.filename !== "string" || !NAME.test(value.filename)) fail("Windows media filename is invalid.");
  let source;
  try { source = new URL(value.sourceUrl); } catch { fail("Windows media source URL is invalid."); }
  if (source.protocol !== "https:" || !(source.hostname === "microsoft.com" || source.hostname.endsWith(".microsoft.com"))) fail("Windows media source must be canonical Microsoft HTTPS.");
  for (const field of ["product", "release", "edition"]) {
    if (typeof value[field] !== "string" || value[field].length < 1 || value[field].length > 96 || /[\u0000-\u001f]/.test(value[field])) fail(`Windows media ${field} is invalid.`);
  }
  if (value.product !== "Windows 11 Enterprise Evaluation" || value.edition !== "Enterprise Evaluation" || value.architecture !== "x86_64") fail("Windows media product, edition, or architecture is unsupported.");
  if (!Number.isSafeInteger(value.size) || value.size < 1 || BigInt(value.size) > WINDOWS_VM_LIMITS.sourceLogicalBytes) fail("Windows media size exceeds the 8 GiB source limit.");
  if (typeof value.sha256 !== "string" || !HASH.test(value.sha256)) fail("Windows media SHA-256 is invalid.");
  return Object.freeze({ ...value });
}
async function sha256(file) {
  const hash = createHash("sha256");
  await new Promise((resolve, reject) => createReadStream(file).on("data", (chunk) => hash.update(chunk)).on("error", reject).on("end", resolve));
  return hash.digest("hex");
}
export async function verifyWindowsMedia(root, identity) {
  const expected = validateWindowsMediaIdentity(identity);
  const state = await inspectWindowsVmRoot(root);
  const file = path.join(root, "sources", expected.filename);
  const info = await lstat(file, { bigint: true });
  if (info.isSymbolicLink() || !info.isFile()) fail("Windows media must be a regular source file.");
  if (info.uid !== BigInt(process.getuid()) || Number(info.mode & 0o777n) !== 0o400) fail("Verified Windows media must be current-user-owned and immutable mode 0400.");
  if (info.size !== BigInt(expected.size)) fail("Windows media size does not match its identity.");
  const actual = await sha256(file);
  if (actual !== expected.sha256) fail("Windows media SHA-256 does not match its identity.");
  return { schemaVersion: 1, status: "verified", identity: expected, containmentAllocatedBytes: state.allocatedBytes };
}
function repositoryRoot() { return path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."); }
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== "verify") fail("Usage: scripts/windows-media.mjs verify IDENTITY.json");
    const identity = JSON.parse(await readFile(process.argv[3], "utf8"));
    process.stdout.write(JSON.stringify(await verifyWindowsMedia(path.join(repositoryRoot(), "local-inputs", "windows-vm"), identity), null, 2) + "\n");
  } catch (error) { process.stderr.write(String(error?.message || error) + "\n"); process.exitCode = 1; }
}

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { initializeWindowsVmRoot } from "../scripts/windows-vm.mjs";
import { validateWindowsMediaIdentity, verifyWindowsMedia } from "../scripts/windows-media.mjs";

const bytes = Buffer.from("closed fake ISO bytes\n");
const base = { schemaVersion: 1, kind: "opemos-exe-windows-evaluation-media", filename: "windows-eval.iso", sourceUrl: "https://www.microsoft.com/evalcenter/download-windows-11-enterprise", product: "Windows 11 Enterprise Evaluation", release: "25H2", edition: "Enterprise Evaluation", architecture: "x86_64", locale: "en-US", hashDocumentUrl: "https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/Verify-Download-Win11-Enterprise.pdf", hashDocumentSha256: "0d44bc561af90844c0a0da5ddc420f5fa84459872c02a1def6240fcfe1aac2c7", size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };

test("media identity admits one bounded canonical Microsoft evaluation source", () => {
  assert.deepEqual(validateWindowsMediaIdentity(base), base);
  for (const value of [
    { ...base, sourceUrl: "http://www.microsoft.com/windows.iso" },
    { ...base, sourceUrl: "https://microsoft.com.example/windows.iso" },
    { ...base, architecture: "arm64" },
    { ...base, locale: "en-GB" },
    { ...base, hashDocumentUrl: "https://example.com/hashes.pdf" },
    { ...base, size: 8 * 1024 ** 3 + 1 },
    { ...base, extra: true },
  ]) assert.throws(() => validateWindowsMediaIdentity(value));
});

test("media verification binds exact bytes, size, ownership, and immutable mode", async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "opemos-windows-media-"));
  try {
    const root = path.join(parent, "windows-vm");
    await initializeWindowsVmRoot(root);
    const iso = path.join(root, "sources", base.filename);
    await writeFile(iso, bytes, { mode: 0o400 });
    assert.equal((await verifyWindowsMedia(root, base)).status, "verified");
    await chmod(iso, 0o600);
    await assert.rejects(verifyWindowsMedia(root, base), /immutable mode 0400/);
    await chmod(iso, 0o400);
    await assert.rejects(verifyWindowsMedia(root, { ...base, sha256: "0".repeat(64) }), /SHA-256 does not match/);
    await assert.rejects(verifyWindowsMedia(root, { ...base, size: base.size + 1 }), /size does not match/);
  } finally { await chmod(path.join(parent, "windows-vm", "sources", base.filename), 0o600).catch(() => {}); await rm(parent, { recursive: true, force: true }); }
});

import test from "node:test";
import assert from "node:assert/strict";

import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { classifyCommandFailure, commandTimeoutMs, packagingCommands, runBoundedCommand } from "../scripts/check_macos_packaging.mjs";

test("headless packaging smoke never invokes Finder, AppleScript, mounting, or host disks", () => {
  const commands = packagingCommands("/private/tmp/steamos-package-fixture");
  const rendered = JSON.stringify(commands);
  assert.equal(commands.length, 2);
  assert.match(rendered, /hdiutil.*create/);
  assert.match(rendered, /UDZO/);
  assert.match(rendered, /hdiutil.*verify/);
  assert.doesNotMatch(rendered, /osascript|Finder|attach|mount|detach|\/dev\//i);
  assert.equal(commandTimeoutMs, 30_000);
});

test("packaging diagnostics distinguish timeout, launch, and bounded tool failures", () => {
  assert.match(classifyCommandFailure({ error: { code: "ETIMEDOUT" } }, "create"), /timed out during create/);
  assert.match(classifyCommandFailure({ error: { code: "ENOENT", message: "missing" } }, "create"), /could not start.*missing/);
  assert.match(classifyCommandFailure({ status: 1, stderr: "denied" }, "verify"), /failed during verify.*denied/);
  assert.equal(classifyCommandFailure({ status: 0 }, "verify"), null);
});

test("packaging timeout terminates and reaps the complete descendant process group", async () => {
  const root = await mkdtemp(join(tmpdir(), "steamos-package-timeout-"));
  const descendant = join(root, "descendant.pid");
  try {
    const result = await runBoundedCommand("/bin/sh", ["-c", `sleep 30 & echo $! > '${descendant}'; wait`], 100);
    assert.equal(result.error?.code, "ETIMEDOUT");
    const pid = Number((await readFile(descendant, "utf8")).trim());
    const deadline = Date.now() + 2000;
    while (Date.now() < deadline) {
      try { process.kill(pid, 0); } catch (error) {
        assert.equal(error.code, "ESRCH");
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.fail("timed-out packaging descendant remained alive");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

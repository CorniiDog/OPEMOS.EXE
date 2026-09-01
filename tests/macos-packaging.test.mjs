import test from "node:test";
import assert from "node:assert/strict";

import { classifyCommandFailure, commandTimeoutMs, packagingCommands } from "../scripts/check_macos_packaging.mjs";

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

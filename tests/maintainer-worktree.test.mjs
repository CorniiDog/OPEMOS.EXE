import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("maintainer workspace offers a bounded managed-checkout action", async () => {
  const [html, script] = await Promise.all([
    readFile(new URL("../src/maintainer.html", import.meta.url), "utf8"),
    readFile(new URL("../src/maintainer.js", import.meta.url), "utf8"),
  ]);
  assert.match(html, /id="choose-worktree"[^>]*>Choose Folder</);
  assert.match(html, /id="make-worktree"[^>]*>Make For Me</);
  assert.match(html, /id="recent-worktree"[^>]*aria-label="Recent matching worktrees"/);
  assert.match(script, /invoke\("make_maintainer_worktree", source\)/);
  assert.match(script, /invoke\("list_recent_maintainer_worktrees", \{ repository \}\)/);
  assert.match(script, /Revalidating the recent folder before selecting it/);
  assert.match(script, /Creating or reopening a dedicated checkout at the exact verified commit/);
  assert.match(script, /installKeyboardBindings[\s\S]*key: "Enter"[\s\S]*accelerator: true[\s\S]*document\.activeElement === elements\.commitMessage[\s\S]*runKeyboardDefaultAction\(elements\.reviewStaged\)/);
});

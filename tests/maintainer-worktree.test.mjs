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


test("maintainer source refresh commits only the latest request", async () => {
  const script = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
  const loadSources = script.match(/async function loadSources\(\) \{[\s\S]*?\n\}/)?.[0] || "";
  assert.match(script, /import \{ createLatestRequestGate \} from "\.\/async-generation\.js"/);
  assert.match(loadSources, /const generation = sourceRefreshGate\.begin\(\)/);
  assert.match(loadSources, /const refreshedSources = await invoke\("list_maintainer_workspace_sources"\);\n    if \(!sourceRefreshGate\.isCurrent\(generation\)\) return;\n    sources = refreshedSources/);
  assert.match(loadSources, /catch \(error\) \{\n    if \(!sourceRefreshGate\.isCurrent\(generation\)\) return;/);
  assert.match(loadSources, /finally \{\n    if \(sourceRefreshGate\.isCurrent\(generation\)\) \{[\s\S]*?loading = false;/);
});


test("maintainer plan verification commits only the latest request", async () => {
  const script = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
  const planHandler = script.match(/elements\.planButton\.addEventListener\("click", async \(\) => \{[\s\S]*?\n\}\);/)?.[0] || "";
  assert.match(script, /const planRequestGate = createLatestRequestGate\(\)/);
  assert.match(script, /function resetPlan\(\{ invalidateRequest = true \} = \{\}\) \{\n  if \(invalidateRequest\) planRequestGate\.begin\(\);/);
  assert.match(planHandler, /const generation = planRequestGate\.begin\(\)/);
  assert.match(planHandler, /const plan = await invoke\("plan_maintainer_workspace", \{[\s\S]*?\n    \}\);\n    if \(!planRequestGate\.isCurrent\(generation\)\) return;/);
  assert.match(planHandler, /catch \(error\) \{\n    if \(!planRequestGate\.isCurrent\(generation\)\) return;\n    resetPlan\(\{ invalidateRequest: false \}\);/);
  assert.match(planHandler, /finally \{\n    if \(planRequestGate\.isCurrent\(generation\)\) \{[\s\S]*?loading = false;/);
});


test("maintainer staged review commits only the latest snapshot request", async () => {
  const script = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
  const handler = script.match(/elements\.reviewStaged\.addEventListener\("click", async \(\) => \{[\s\S]*?\n\}\);/)?.[0] || "";
  assert.match(script, /const stagedReviewGate = createLatestRequestGate\(\)/);
  assert.match(script, /function resetPlan[\s\S]*?stagedReviewGate\.begin\(\);[\s\S]*?function disableSourceControls/);
  assert.match(script, /function renderWorktree\(worktree\) \{\n  stagedReviewGate\.begin\(\);/);
  assert.match(script, /elements\.commitMessage\.addEventListener\("input", \(\) => \{\n  stagedReviewGate\.begin\(\);/);
  assert.match(handler, /const requestGeneration = stagedReviewGate\.begin\(\)/);
  assert.match(handler, /const reviewedCommit = await invoke\("review_maintainer_staged_commit"[\s\S]*?if \(!stagedReviewGate\.isCurrent\(requestGeneration\)[\s\S]*?commitReview = reviewedCommit;/);
  assert.match(handler, /catch \(error\) \{\n    if \(!stagedReviewGate\.isCurrent\(requestGeneration\)/);
  assert.match(handler, /finally \{\n    if \(stagedReviewGate\.isCurrent\(requestGeneration\) && generation === workspaceGeneration\) \{/);
});

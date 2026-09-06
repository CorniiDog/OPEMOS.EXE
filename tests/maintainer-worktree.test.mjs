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


test("maintainer local branch loading commits only the latest request", async () => {
  const script = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
  const handler = script.match(/elements\.loadLocalBranches\.addEventListener\("click", async \(\) => \{[\s\S]*?\n\}\);/)?.[0] || "";
  assert.match(script, /const branchListGate = createLatestRequestGate\(\)/);
  assert.match(script, /function resetPlan[\s\S]*?branchListGate\.begin\(\);[\s\S]*?function disableSourceControls/);
  assert.match(script, /function renderWorktree\(worktree\) \{[\s\S]*?branchListGate\.begin\(\);/);
  assert.match(handler, /const requestGeneration = branchListGate\.begin\(\)/);
  assert.match(handler, /const branches = await invoke\("list_maintainer_local_branches"[\s\S]*?if \(!branchListGate\.isCurrent\(requestGeneration\)/);
  assert.match(handler, /catch \(error\) \{\n    if \(!branchListGate\.isCurrent\(requestGeneration\)/);
  assert.match(handler, /finally \{\n    if \(branchListGate\.isCurrent\(requestGeneration\) && generation === workspaceGeneration\) \{/);
});


test("maintainer checkout review commits only the latest branch request", async () => {
  const script = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
  const handler = script.match(/elements\.reviewCheckout\.addEventListener\("click", async \(\) => \{[\s\S]*?\n\}\);/)?.[0] || "";
  assert.match(script, /const checkoutReviewGate = createLatestRequestGate\(\)/);
  assert.match(script, /function resetPlan[\s\S]*?checkoutReviewGate\.begin\(\);[\s\S]*?function disableSourceControls/);
  assert.match(script, /function renderWorktree\(worktree\) \{[\s\S]*?checkoutReviewGate\.begin\(\);/);
  assert.match(script, /const requestGeneration = branchListGate\.begin\(\);\n  checkoutReviewGate\.begin\(\);/);
  assert.match(script, /elements\.localBranch\.addEventListener\("change", \(\) => \{\n  checkoutReviewGate\.begin\(\);/);
  assert.match(handler, /const requestGeneration = checkoutReviewGate\.begin\(\)/);
  assert.match(handler, /const reviewedCheckout = await invoke\("review_maintainer_checkout"[\s\S]*?if \(!checkoutReviewGate\.isCurrent\(requestGeneration\)[\s\S]*?branchReview = reviewedCheckout;/);
  assert.match(handler, /catch \(error\) \{\n    if \(!checkoutReviewGate\.isCurrent\(requestGeneration\)/);
  assert.match(handler, /finally \{\n    if \(checkoutReviewGate\.isCurrent\(requestGeneration\) && generation === workspaceGeneration\) \{/);
});


test("recent worktree refresh commits only the latest repository request", async () => {
  const script = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
  const refresh = script.match(/async function refreshRecentWorktrees\(repository, generation = workspaceGeneration\) \{[\s\S]*?\n\}/)?.[0] || "";
  assert.match(script, /const recentWorktreeGate = createLatestRequestGate\(\)/);
  assert.match(script, /function resetPlan[\s\S]*?recentWorktreeGate\.begin\(\);[\s\S]*?function disableSourceControls/);
  assert.match(script, /function renderWorktree\(worktree\) \{[\s\S]*?recentWorktreeGate\.begin\(\);/);
  assert.match(refresh, /const requestGeneration = recentWorktreeGate\.begin\(\)/);
  assert.match(refresh, /const worktrees = await invoke\("list_recent_maintainer_worktrees"[\s\S]*?if \(!recentWorktreeGate\.isCurrent\(requestGeneration\)[\s\S]*?repository !== plannedRepository\) return;/);
  assert.match(refresh, /catch \(error\) \{\n    if \(!recentWorktreeGate\.isCurrent\(requestGeneration\)[\s\S]*?repository !== plannedRepository\) return;/);
});


test("native worktree chooser commits only the latest dialog and inspection", async () => {
  const script = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
  const handler = script.match(/elements\.chooseWorktree\.addEventListener\("click", async \(\) => \{[\s\S]*?\n\}\);/)?.[0] || "";
  assert.match(script, /const worktreeSelectionGate = createLatestRequestGate\(\)/);
  assert.match(script, /function resetPlan[\s\S]*?worktreeSelectionGate\.begin\(\);[\s\S]*?function disableSourceControls/);
  assert.match(script, /function renderWorktree\(worktree\) \{[\s\S]*?if \(!preserveWorktreeSelectionRequest\) worktreeSelectionGate\.begin\(\);/);
  assert.match(script, /function renderWorktreeForSelection\(worktree\) \{[\s\S]*?renderWorktree\(worktree\);[\s\S]*?preserveWorktreeSelectionRequest = false;/);
  assert.match(handler, /const requestGeneration = worktreeSelectionGate\.begin\(\)[\s\S]*?const path = await openFolder/);
  assert.match(handler, /if \(!worktreeSelectionGate\.isCurrent\(requestGeneration\)[\s\S]*?dialogGeneration !== workspaceGeneration[\s\S]*?repository !== plannedRepository\) return;/);
  assert.match(handler, /const worktree = await invoke\("inspect_maintainer_worktree"[\s\S]*?if \(!worktreeSelectionGate\.isCurrent\(requestGeneration\)[\s\S]*?renderWorktreeForSelection\(worktree\)/);
  assert.match(handler, /catch \(error\) \{\n    if \(!worktreeSelectionGate\.isCurrent\(requestGeneration\)[\s\S]*?repository !== plannedRepository\) return;/);
  assert.match(handler, /finally \{\n    if \(worktreeSelectionGate\.isCurrent\(requestGeneration\)[\s\S]*?setWorkspaceMutationPending\(false\);/);
});


test("recent worktree selection commits only the latest inspection", async () => {
  const script = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
  const handler = script.match(/elements\.recentWorktree\.addEventListener\("change", async \(\) => \{[\s\S]*?\n\}\);/)?.[0] || "";
  assert.match(handler, /const requestGeneration = worktreeSelectionGate\.begin\(\)[\s\S]*?const path = elements\.recentWorktree\.value/);
  assert.match(handler, /const worktree = await invoke\("inspect_maintainer_worktree"[\s\S]*?if \(!worktreeSelectionGate\.isCurrent\(requestGeneration\)[\s\S]*?repository !== plannedRepository\) return;/);
  assert.match(handler, /setWorkspaceMutationPending\(false\);\n    renderWorktreeForSelection\(worktree\);/);
  assert.match(handler, /catch \(error\) \{\n    if \(!worktreeSelectionGate\.isCurrent\(requestGeneration\)[\s\S]*?repository !== plannedRepository\) return;/);
  assert.match(handler, /finally \{\n    if \(worktreeSelectionGate\.isCurrent\(requestGeneration\)[\s\S]*?setWorkspaceMutationPending\(false\);/);
});


test("managed worktree creation commits only the latest exact-source request", async () => {
  const script = await readFile(new URL("../src/maintainer.js", import.meta.url), "utf8");
  const handler = script.match(/elements\.makeWorktree\.addEventListener\("click", async \(\) => \{[\s\S]*?\n\}\);/)?.[0] || "";
  assert.match(handler, /const requestGeneration = worktreeSelectionGate\.begin\(\)[\s\S]*?const sourceIdentity = JSON\.stringify\(source\)/);
  assert.match(handler, /const worktree = await invoke\("make_maintainer_worktree", source\)[\s\S]*?if \(!worktreeSelectionGate\.isCurrent\(requestGeneration\)[\s\S]*?sourceIdentity !== JSON\.stringify\(plannedSource\)\) return;/);
  assert.match(handler, /setWorkspaceMutationPending\(false\);\n    renderWorktreeForSelection\(worktree\);/);
  assert.match(handler, /catch \(error\) \{\n    if \(!worktreeSelectionGate\.isCurrent\(requestGeneration\)[\s\S]*?sourceIdentity !== JSON\.stringify\(plannedSource\)\) return;/);
  assert.match(handler, /finally \{\n    if \(worktreeSelectionGate\.isCurrent\(requestGeneration\)[\s\S]*?sourceIdentity === JSON\.stringify\(plannedSource\)\) \{[\s\S]*?setWorkspaceMutationPending\(false\);/);
});

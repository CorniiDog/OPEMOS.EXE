import test from "node:test";
import assert from "node:assert/strict";

import { operationContextMatches } from "../src/operation-context.js";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test("a delayed USB completion cannot replace a newer session context", async () => {
  const response = deferred();
  const expected = { generation: 4, imagePath: "/image-a.raw", sessionToken: "token-a" };
  let current = { ...expected };
  let applied = null;
  const completion = response.promise.then((value) => {
    if (operationContextMatches(expected, current)) applied = value;
  });

  current = { generation: 5, imagePath: "/image-b.raw", sessionToken: "token-b" };
  response.resolve("stale response");
  await completion;
  assert.equal(applied, null);
  assert.equal(current.sessionToken, "token-b");
});

test("a delayed VS Code completion cannot resurrect an obsolete worktree", async () => {
  const response = deferred();
  const expected = { generation: 8, path: "/worktree-a", repository: "owner/a" };
  let current = { ...expected };
  let rendered = null;
  const completion = response.promise.then((value) => {
    if (operationContextMatches(expected, current)) rendered = value;
  });

  current = { generation: 9, path: null, repository: "owner/b" };
  response.resolve({ path: "/worktree-a" });
  await completion;
  assert.equal(rendered, null);
});

test("an unchanged operation context accepts its completion", async () => {
  const response = deferred();
  const expected = { generation: 2, path: "/worktree", repository: "owner/repository" };
  const current = { ...expected };
  const completion = response.promise.then((value) => (
    operationContextMatches(expected, current) ? value : null
  ));
  response.resolve("accepted");
  assert.equal(await completion, "accepted");
});

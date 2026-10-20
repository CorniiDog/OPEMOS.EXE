import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("the published M1 workflow has one explicit fullstack mode and no ignored manual control", () => {
  const workflow = readFileSync(new URL("../.github/workflows/macos-arm64.yml", import.meta.url), "utf8");
  assert.match(workflow, /^\s+workflow_dispatch:\s*$/m);
  assert.match(workflow, /OPEMOS_MACOS_FULLSTACK:\s*'1'/);
  assert.doesNotMatch(workflow, /^\s+fullstack:\s*$/m);
});

test("visible Settings X has a unique accessible action distinct from its backdrop", () => {
  const html = readFileSync(new URL("../src/index.html", import.meta.url), "utf8");
  const buttons = [...html.matchAll(/<button\b[^>]*>/g)].map(([tag]) => ({
    id: tag.match(/\bid="([^"]+)"/)?.[1],
    label: tag.match(/\baria-label="([^"]+)"/)?.[1],
  }));
  assert.deepEqual(buttons.filter((button) => button.label === "Close settings"), [
    { id: "settings-close", label: "Close settings" },
  ], "screen-reader/OS action lookup must not select the full-window scrim");
  assert.equal(buttons.find((button) => button.id === "settings-scrim")?.label,
    "Dismiss settings background");
});

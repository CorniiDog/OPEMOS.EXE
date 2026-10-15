import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

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

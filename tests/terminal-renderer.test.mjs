import test from "node:test";
import assert from "node:assert/strict";

import {
  ansi256Color,
  freshAnsiState,
  normalizeTerminalText,
} from "../src/terminal-renderer.js";

test("normalizes terminal control data without removing SGR color", () => {
  assert.equal(
    normalizeTerminalText("a\r\nb\r\x00\x1b]0;title\x07\x1b[31mred"),
    "a\nb\n\x1b[31mred",
  );
});

test("creates independent ANSI states", () => {
  const first = freshAnsiState();
  const second = freshAnsiState();
  first.bold = true;
  assert.deepEqual(second, { color: "", background: "", bold: false });
});

test("maps ANSI 256-color boundaries deterministically", () => {
  assert.equal(ansi256Color(0), "#111827");
  assert.equal(ansi256Color(15), "#ffffff");
  assert.equal(ansi256Color(16), "rgb(0,0,0)");
  assert.equal(ansi256Color(231), "rgb(255,255,255)");
  assert.equal(ansi256Color(232), "rgb(8,8,8)");
  assert.equal(ansi256Color(255), "rgb(238,238,238)");
});

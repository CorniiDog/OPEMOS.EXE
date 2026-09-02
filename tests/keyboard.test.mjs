import assert from "node:assert/strict";
import test from "node:test";

import {
  isEditableKeyboardTarget,
  isMacKeyboardPlatform,
  keepKeyboardFocusInside,
  matchesKeyboardBinding,
  normalizeKeyboardKey,
} from "../src/keyboard.js";

function keyboardEvent(overrides = {}) {
  return {
    key: "Escape",
    ctrlKey: false,
    metaKey: false,
    shiftKey: false,
    altKey: false,
    repeat: false,
    isComposing: false,
    defaultPrevented: false,
    target: { nodeType: 1, tagName: "BUTTON", isContentEditable: false },
    ...overrides,
  };
}

test("keyboard keys and Apple platforms are normalized", () => {
  assert.equal(normalizeKeyboardKey("Esc"), "Escape");
  assert.equal(normalizeKeyboardKey("A"), "a");
  assert.equal(normalizeKeyboardKey("Spacebar"), " ");
  assert.equal(isMacKeyboardPlatform("MacIntel"), true);
  assert.equal(isMacKeyboardPlatform("Win32"), false);
});

test("bindings distinguish primary and either-platform accelerators", () => {
  const commandA = keyboardEvent({ key: "A", metaKey: true });
  assert.equal(matchesKeyboardBinding(commandA, { key: "a", accelerator: true }, "MacIntel"), true);
  assert.equal(matchesKeyboardBinding(commandA, { key: "a", accelerator: true }, "Win32"), false);
  assert.equal(matchesKeyboardBinding(commandA, { key: "a", accelerator: "either" }, "Win32"), true);
  assert.equal(matchesKeyboardBinding(keyboardEvent({ key: "a", ctrlKey: true }), { key: "a", accelerator: "either" }, "MacIntel"), true);
});

test("composition, repeats, modifiers, and editable targets fail closed", () => {
  const input = { nodeType: 1, tagName: "INPUT", isContentEditable: false };
  assert.equal(isEditableKeyboardTarget(input), true);
  assert.equal(matchesKeyboardBinding(keyboardEvent({ target: input }), { key: "Escape" }, "MacIntel"), false);
  assert.equal(matchesKeyboardBinding(keyboardEvent({ target: input }), { key: "Escape", allowInEditable: true }, "MacIntel"), true);
  assert.equal(matchesKeyboardBinding(keyboardEvent({ isComposing: true }), { key: "Escape" }, "MacIntel"), false);
  assert.equal(matchesKeyboardBinding(keyboardEvent({ repeat: true }), { key: "Escape" }, "MacIntel"), false);
  assert.equal(matchesKeyboardBinding(keyboardEvent({ shiftKey: true }), { key: "Escape" }, "MacIntel"), false);
  assert.equal(matchesKeyboardBinding(keyboardEvent({ shiftKey: true }), { key: "Escape", shift: "any" }, "MacIntel"), true);
});

test("overlay focus wraps only at visible boundary controls", () => {
  let focused = null;
  const control = (name) => ({
    focus: () => { focused = name; },
    getAttribute: () => null,
    getClientRects: () => [1],
  });
  const first = control("first");
  const middle = control("middle");
  const last = control("last");
  const container = { querySelectorAll: () => [first, middle, last] };
  assert.equal(keepKeyboardFocusInside({ shiftKey: false }, container, { activeElement: last }), true);
  assert.equal(focused, "first");
  assert.equal(keepKeyboardFocusInside({ shiftKey: true }, container, { activeElement: first }), true);
  assert.equal(focused, "last");
  assert.equal(keepKeyboardFocusInside({ shiftKey: false }, container, { activeElement: middle }), false);
});

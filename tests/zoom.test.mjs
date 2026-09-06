import assert from "node:assert/strict";
import test from "node:test";

import { installPageZoom, nextPageZoom, pageZoomCommand } from "../src/zoom.js";

const event = (overrides = {}) => ({
  key: "+", ctrlKey: true, metaKey: false, altKey: false,
  repeat: false, isComposing: false, defaultPrevented: false,
  ...overrides,
});

test("zoom commands accept standard primary shortcuts and reject ambiguous input", () => {
  assert.equal(pageZoomCommand(event()), "increase");
  assert.equal(pageZoomCommand(event({ key: "=", shiftKey: false })), "increase");
  assert.equal(pageZoomCommand(event({ key: "_" })), "decrease");
  assert.equal(pageZoomCommand(event({ key: "0", ctrlKey: false, metaKey: true })), "reset");
  for (const overrides of [
    { ctrlKey: false }, { ctrlKey: true, metaKey: true }, { altKey: true },
    { repeat: true }, { isComposing: true }, { defaultPrevented: true }, { key: "1" },
  ]) assert.equal(pageZoomCommand(event(overrides)), null);
});

test("zoom levels clamp, reset, and recover from an intermediate value", () => {
  assert.equal(nextPageZoom(1, "increase"), 1.1);
  assert.equal(nextPageZoom(1.1, "decrease"), 1);
  assert.equal(nextPageZoom(2, "increase"), 2);
  assert.equal(nextPageZoom(0.8, "decrease"), 0.8);
  assert.equal(nextPageZoom(1.37, "increase"), 1.5);
  assert.equal(nextPageZoom(1.37, "decrease"), 1.1);
  assert.equal(nextPageZoom(1.75, "reset"), 1);
  assert.equal(nextPageZoom(1.25, "unknown"), 1.25);
});

test("installed zoom updates the root and announces changes without duplicate edge announcements", () => {
  const listeners = new Map();
  const status = { id: "", attributes: {}, style: {}, textContent: "", setAttribute(k, v) { this.attributes[k] = v; } };
  const doc = {
    documentElement: { style: {} },
    body: { append(node) { this.child = node; } },
    createElement() { return status; },
    addEventListener(name, handler) { listeners.set(name, handler); },
  };
  const zoom = installPageZoom(doc);
  assert.equal(doc.body.child, status);
  assert.equal(status.attributes.role, "status");
  assert.equal(zoom.apply("increase"), true);
  assert.equal(doc.documentElement.style.zoom, "1.1");
  assert.equal(status.textContent, "Zoom 110%");
  for (let i = 0; i < 20; i += 1) zoom.apply("increase");
  assert.equal(zoom.level, 2);
  assert.equal(zoom.apply("increase"), false);
  let prevented = false;
  listeners.get("keydown")({ ...event({ key: "0" }), preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(zoom.level, 1);
  assert.equal(status.textContent, "Zoom 100%");
});

test("all application webviews install the shared zoom adapter", async () => {
  const { readFile } = await import("node:fs/promises");
  for (const page of ["main.js", "build.js", "maintainer.js"]) {
    const source = await readFile(new URL(`../src/${page}`, import.meta.url), "utf8");
    assert.match(source, /import \{ installPageZoom \} from "\.\/zoom\.js";/);
    assert.equal(source.match(/installPageZoom\(\);/g)?.length, 1, page);
  }
});

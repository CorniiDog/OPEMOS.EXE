import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { presentCompatibilityPreview, createCompatibilityPreviewController, installCompatibilityPreview } from "../src/compatibility-preview.js";

const compatible = JSON.parse(await readFile(new URL("./fixtures/opemos-core/resolver-compatible-v2.json", import.meta.url)));
const absent = JSON.parse(await readFile(new URL("./fixtures/opemos-core/resolver-incompatible-v2.json", import.meta.url)));
const preview = (result = compatible, origin = "development-fixture") => ({ result, origin });
const defer = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };

test("Core statuses and next actions are presented verbatim with unverified origins", () => {
  const accepted = presentCompatibilityPreview(preview());
  assert.match(accepted.origin, /non-production/);
  assert.equal(new Map(accepted.rows).get("Core status"), compatible.status);
  assert.equal(new Map(accepted.rows).get("Artifact trust reported by Core"), "pending-provenance-verification");
  const noArtifact = presentCompatibilityPreview(preview(absent, "unverified-document"));
  assert.equal(noArtifact.origin, "Unverified pasted document");
  assert.equal(new Map(noArtifact.rows).get("Next action reported by Core"), absent.nextAction.kind);
  assert.equal(new Map(noArtifact.rows).get("Message"), absent.message);
  assert.equal(noArtifact.rows.some(([label]) => label === "Artifact name"), false);
  assert.deepEqual(Object.keys(noArtifact).sort(), ["origin", "rows"]);
});

test("Unknown origin, schema, status and non-text fields never produce a preview", () => {
  for (const input of [null, preview(compatible, "production"), preview(compatible, "__proto__"),
    preview({ ...compatible, schemaVersion: 3 }), preview({ ...compatible, status: "trusted" }),
    preview({ ...compatible, target: null }), preview({ ...compatible, message: {} })]) {
    assert.throws(() => presentCompatibilityPreview(input));
  }
  const long = presentCompatibilityPreview(preview({ ...absent, message: "x".repeat(3000) }));
  assert.match(new Map(long.rows).get("Message"), /truncated for display/);
  assert.ok(new Map(long.rows).get("Message").length < 2100);
});

test("Newer requests win and stale errors cannot replace a newer result", async () => {
  const first = defer(), second = defer(), states = [], requests = [];
  const controller = createCompatibilityPreviewController((name, args) => {
    requests.push([name, args]); return requests.length === 1 ? first.promise : second.promise;
  }, (state) => states.push(state));
  const a = controller.inspect({ source: "fixture", name: "compatible" });
  const b = controller.inspect({ source: "fixture", name: "no-artifact" });
  second.resolve(preview(absent)); await b;
  first.reject(new Error("old failure")); await a;
  assert.equal(states.at(-1).phase, "result");
  assert.equal(new Map(states.at(-1).preview.rows).get("Core status"), absent.status);
  assert.ok(requests.every(([name]) => name === "preview_core_compatibility"));
});

test("Clearing or closing invalidates pending successful responses", async () => {
  const pending = defer(), states = [];
  const controller = createCompatibilityPreviewController(() => pending.promise, (state) => states.push(state));
  const work = controller.inspect({ source: "fixture", name: "compatible" });
  controller.clear(); pending.resolve(preview()); await work;
  assert.equal(states.at(-1).phase, "empty");
  assert.equal(states.some((state) => state.phase === "result"), false);
});

test("Document byte limits reject blank, oversized, and Unicode overflow before IPC", async () => {
  const calls = [], states = [];
  const controller = createCompatibilityPreviewController((name, request) => {
    calls.push([name, request]); return Promise.resolve(preview());
  }, (state) => states.push(state));
  for (const document of ["", " \n", null, "x".repeat(1024 * 1024 + 1), "é".repeat(512 * 1024 + 1)]) {
    await controller.inspect({ source: "document", document });
    assert.equal(states.at(-1).phase, "error");
  }
  assert.equal(calls.length, 0);
  const document = "x".repeat(1024 * 1024);
  await controller.inspect({ source: "document", document });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][1].request.document, document);
});

test("Errors and malformed responses clear old data and remain bounded", async () => {
  const states = [];
  let response = preview();
  const controller = createCompatibilityPreviewController(async () => {
    if (response instanceof Error) throw response;
    return response;
  }, (state) => states.push(state));
  await controller.inspect({ source: "fixture", name: "compatible" });
  response = { origin: "production", result: compatible };
  await controller.inspect({ source: "fixture", name: "compatible" });
  assert.equal(states.at(-1).phase, "error");
  assert.equal(states.at(-1).preview, undefined);
  response = new Error("e".repeat(5000));
  await controller.inspect({ source: "fixture", name: "compatible" });
  assert.equal(states.at(-1).message.length, 2048);
});

class Element {
  children = []; handlers = {}; value = ""; textContent = ""; hidden = false; attributes = {};
  set innerHTML(_) { throw new Error("HTML interpretation is forbidden"); }
  setAttribute(key, value) { this.attributes[key] = value; }
  addEventListener(name, callback) { this.handlers[name] = callback; }
  fire(name, event = {}) { this.handlers[name]?.(event); }
  append(...elements) { this.children.push(...elements); }
  replaceChildren(...elements) { this.children = elements; }
  showModal() { this.open = true; }
  close() { this.open = false; this.fire("close"); }
}
function fakeDocument() {
  const elements = new Map();
  return {
    getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
    createElement() { return new Element(); },
  };
}

test("Dialog renders hostile-looking strings as text and isolates keyboard events", async () => {
  const doc = fakeDocument();
  const hostile = '<img src=x onerror="alert(1)">';
  const controller = installCompatibilityPreview(doc, async () => preview({ ...absent, message: hostile }));
  const get = (id) => doc.getElementById(id);
  get("compatibility-open").fire("click");
  assert.equal(get("compatibility-dialog").open, true);
  await controller.inspect({ source: "fixture", name: "no-artifact" });
  assert.equal(get("compatibility-result").hidden, false);
  assert.ok(get("compatibility-fields").children.some((row) => row.children[1].textContent === hostile));
  let stopped = false;
  get("compatibility-dialog").fire("keydown", { stopPropagation() { stopped = true; } });
  assert.equal(stopped, true);
  get("compatibility-document").value = "private pasted content";
  get("compatibility-close").fire("click");
  assert.equal(get("compatibility-document").value, "");
  assert.equal(get("compatibility-result").hidden, true);
  assert.deepEqual(get("compatibility-fields").children, []);
});

test("Editing the input clears a previous result before another submission", async () => {
  const doc = fakeDocument();
  const controller = installCompatibilityPreview(doc, async () => preview());
  await controller.inspect({ source: "fixture", name: "compatible" });
  doc.getElementById("compatibility-document").fire("input");
  assert.equal(doc.getElementById("compatibility-result").hidden, true);
  assert.equal(doc.getElementById("compatibility-status").textContent, "No result loaded.");
});

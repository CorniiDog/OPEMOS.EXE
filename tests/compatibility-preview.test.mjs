import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { presentCompatibilityPreview, createCompatibilityPreviewController, installCompatibilityPreview } from "../src/compatibility-preview.js";

const compatible = JSON.parse(await readFile(new URL("./fixtures/opemos-core/resolver-compatible-v2.json", import.meta.url)));
const absent = JSON.parse(await readFile(new URL("./fixtures/opemos-core/resolver-incompatible-v2.json", import.meta.url)));
const preview = (result = compatible, origin = "development-fixture") => ({ result, origin });
const defer = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const fixtureGeneration = {
  available: [
    { sequence: 41, generationId: "development-fixture-active", manifestSha256: "1".repeat(64) },
    { sequence: 42, generationId: "development-fixture-selected", manifestSha256: "2".repeat(64) },
  ],
  selected: { sequence: 42, generationId: "development-fixture-selected", manifestSha256: "2".repeat(64) },
  active: { sequence: 41, generationId: "development-fixture-active", manifestSha256: "1".repeat(64) },
  lastKnownGood: { sequence: 41, generationId: "development-fixture-active", manifestSha256: "1".repeat(64) },
};

test("Core statuses and next actions are presented verbatim with unverified origins", () => {
  const accepted = presentCompatibilityPreview(preview());
  assert.match(accepted.origin, /non-production/);
  assert.equal(new Map(accepted.rows).get("Core status"), compatible.status);
  assert.equal(new Map(accepted.rows).get("Exact-target support reported by Core"), compatible.compatibility);
  assert.equal(new Map(accepted.rows).get("Artifact trust reported by Core"), "pending-provenance-verification");
  const noArtifact = presentCompatibilityPreview(preview(absent, "unverified-document"));
  assert.equal(noArtifact.origin, "Unverified document");
  assert.equal(new Map(noArtifact.rows).get("Next action reported by Core"), absent.nextAction.kind);
  assert.equal(new Map(noArtifact.rows).get("Message"), absent.message);
  assert.equal(noArtifact.rows.some(([label]) => label === "Artifact name"), false);
  assert.deepEqual(Object.keys(noArtifact).sort(), ["origin", "rows"]);
});

test("Generation status appears only for closed development fixtures", () => {
  const shown = presentCompatibilityPreview({ ...preview(), generationState: fixtureGeneration });
  const rows = new Map(shown.rows);
  assert.match(rows.get("Available generations — development fixture"), /#41.*#42/);
  assert.match(rows.get("Selected generation — development fixture"), /^#42/);
  assert.match(rows.get("Active generation — development fixture"), /^#41/);
  assert.match(rows.get("Last-known-good generation — development fixture"), /^#41/);
  assert.throws(() => presentCompatibilityPreview({
    ...preview(compatible, "unverified-document"), generationState: fixtureGeneration,
  }), /Unsupported generation/);
  for (const generationState of [
    { ...fixtureGeneration, available: [] },
    { ...fixtureGeneration, available: Array(5).fill(fixtureGeneration.active) },
    { ...fixtureGeneration, selected: { ...fixtureGeneration.selected, sequence: 0 } },
    { ...fixtureGeneration, active: { ...fixtureGeneration.active, manifestSha256: "A".repeat(64) } },
    { ...fixtureGeneration, lastKnownGood: { ...fixtureGeneration.active, extra: true } },
    { ...fixtureGeneration, available: [null] },
    { ...fixtureGeneration, available: [fixtureGeneration.active, fixtureGeneration.active] },
    { ...fixtureGeneration, selected: { ...fixtureGeneration.selected, sequence: 43 } },
    { available: fixtureGeneration.available, selected: null, lastKnownGood: null },
    { ...fixtureGeneration, authority: "production" },
  ]) assert.throws(() => presentCompatibilityPreview({ ...preview(), generationState }));
  const absentState = presentCompatibilityPreview({
    ...preview(), generationState: { ...fixtureGeneration, selected: null, active: null, lastKnownGood: null },
  });
  assert.equal(new Map(absentState.rows).get("Active generation — development fixture"), "None");
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
  focus() { this.focusCount = (this.focusCount || 0) + 1; }
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
  assert.equal(get("compatibility-close").focusCount, 1);
  await controller.inspect({ source: "fixture", name: "no-artifact" });
  assert.equal(get("compatibility-result").hidden, false);
  assert.equal(get("compatibility-status").attributes["aria-label"], "Development fixture — non-production");
  const hostileRow = get("compatibility-fields").children.find((row) => row.children[1].textContent === hostile);
  assert.ok(hostileRow);
  assert.equal(hostileRow.children[0].attributes["aria-label"], "Message");
  assert.equal(hostileRow.children[1].attributes["aria-label"], hostile);
  let stopped = false;
  get("compatibility-dialog").fire("keydown", { stopPropagation() { stopped = true; } });
  assert.equal(stopped, true);
  get("compatibility-document").value = "private pasted content";
  get("compatibility-close").fire("click");
  assert.equal(get("compatibility-document").value, "");
  assert.equal(get("compatibility-open").focusCount, 1);
  assert.equal(get("compatibility-result").hidden, true);
  assert.equal(get("compatibility-status").attributes["aria-label"], "No result loaded.");
  assert.deepEqual(get("compatibility-fields").children, []);
});

test("Accessible status label follows loading, result, error, and clear without stale text", async () => {
  const doc = fakeDocument();
  const pending = defer();
  const controller = installCompatibilityPreview(doc, () => pending.promise);
  const status = doc.getElementById("compatibility-status");
  const work = controller.inspect({ source: "fixture", name: "compatible" });
  assert.equal(status.textContent, "Checking document structure…");
  assert.equal(status.attributes["aria-label"], "Checking document structure…");
  pending.resolve(preview());
  await work;
  assert.equal(status.textContent, "Development fixture — non-production");
  assert.equal(status.attributes["aria-label"], "Development fixture — non-production");
  await controller.inspect({ source: "document", document: "" });
  assert.equal(status.textContent, "Choose or paste a Core resolver JSON document no larger than 1 MiB.");
  assert.equal(status.attributes["aria-label"], status.textContent);
  controller.clear();
  assert.equal(status.textContent, "No result loaded.");
  assert.equal(status.attributes["aria-label"], "No result loaded.");
});

test("Editing the input clears a previous result before another submission", async () => {
  const doc = fakeDocument();
  const controller = installCompatibilityPreview(doc, async () => preview());
  await controller.inspect({ source: "fixture", name: "compatible" });
  doc.getElementById("compatibility-document").fire("input");
  assert.equal(doc.getElementById("compatibility-result").hidden, true);
  assert.equal(doc.getElementById("compatibility-status").textContent, "No result loaded.");
  assert.equal(doc.getElementById("compatibility-status").attributes["aria-label"], "No result loaded.");
});


test("Local files use the same unverified document IPC and exact byte limit", async () => {
  const calls = [], states = [];
  const controller = createCompatibilityPreviewController(async (name, args) => {
    calls.push([name, args]); return preview(compatible, "unverified-document");
  }, (state) => states.push(state));
  const json = JSON.stringify(compatible);
  await controller.inspectFile(new Blob([json], { type: "application/octet-stream" }));
  assert.deepEqual(calls[0], ["preview_core_compatibility", { request: { source: "document", document: json } }]);
  assert.equal(states.at(-1).preview.origin, "Unverified document");
  const exact = json.padEnd(1024 * 1024, " ");
  await controller.inspectFile(new Blob([exact]));
  assert.equal(calls[1][1].request.document, exact);
  // Preserve BOM bytes for the same Rust parser decision as pasted input.
  await controller.inspectFile(new Blob(["\uFEFF", json]));
  assert.equal(calls[2][1].request.document, "\uFEFF" + json);
});

test("Invalid file sizes, UTF-8, read failures and changed size stop before IPC", async () => {
  let calls = 0, reads = 0;
  const states = [];
  const controller = createCompatibilityPreviewController(async () => { calls++; return preview(); }, (state) => states.push(state));
  for (const size of [0, -1, 0.5, NaN, Infinity, 1024 * 1024 + 1]) {
    await controller.inspectFile({ size, slice() { reads++; throw new Error(); } });
    assert.equal(states.at(-1).phase, "error");
  }
  assert.equal(reads, 0);
  for (const file of [new Blob([new Uint8Array([0xff])]), new Blob([" "]),
    { size: 1, slice() { throw new Error("private filename"); } },
    { size: 1, slice() { return { arrayBuffer: async () => new ArrayBuffer(2) }; } },
    { size: 1, slice() { return { arrayBuffer: async () => { throw new Error("private filename"); } }; } }]) {
    await controller.inspectFile(file);
    assert.equal(states.at(-1).phase, "error");
    assert.doesNotMatch(states.at(-1).message, /private filename/);
  }
  assert.equal(calls, 0);
});

test("Pending file reads cannot submit after clear, a newer fixture, or a newer file", async () => {
  for (const action of ["clear", "fixture", "file"]) {
    for (const fail of [false, true]) {
      const pending = defer(), states = [], calls = [];
      const controller = createCompatibilityPreviewController(async (_, args) => {
        calls.push(args.request); return preview();
      }, (state) => states.push(state));
      const old = controller.inspectFile({ size: 2, slice(start, end) {
        assert.equal(start, 0); assert.equal(end, 1024 * 1024 + 1);
        return { arrayBuffer: () => pending.promise };
      } });
      if (action === "clear") controller.clear();
      if (action === "fixture") await controller.inspect({ source: "fixture", name: "compatible" });
      if (action === "file") await controller.inspectFile(new Blob(["{}"]));
      const last = states.at(-1);
      if (fail) pending.reject(new Error("stale read error"));
      else pending.resolve(new TextEncoder().encode("{}").buffer);
      await old;
      assert.equal(states.at(-1), last);
      assert.equal(calls.length, action === "clear" ? 0 : 1);
    }
  }
});

test("Native file cancellation preserves preview and close invalidates an ongoing request", async () => {
  const doc = fakeDocument(), calls = [], pending = defer();
  const selections = [null, "/tmp/first.json", "/tmp/repeat.json", "/tmp/pending.json"];
  const controller = installCompatibilityPreview(doc, async (_, args) => {
    calls.push(args.request);
    return args.request.path === "/tmp/pending.json" ? pending.promise : preview();
  }, async () => selections.shift());
  await controller.inspect({ source: "fixture", name: "compatible" });
  const fileOpen = doc.getElementById("compatibility-file-open");
  fileOpen.fire("click");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(doc.getElementById("compatibility-result").hidden, false);
  for (let selection = 0; selection < 2; selection++) {
    fileOpen.fire("click");
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.deepEqual(calls.slice(1), [
    { source: "file", path: "/tmp/first.json" },
    { source: "file", path: "/tmp/repeat.json" },
  ]);
  doc.getElementById("compatibility-document").value = "old text";
  fileOpen.fire("click");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(doc.getElementById("compatibility-document").value, "");
  doc.getElementById("compatibility-close").fire("click");
  pending.resolve(preview());
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(doc.getElementById("compatibility-result").hidden, true);
  assert.equal(doc.getElementById("compatibility-status").textContent, "No result loaded.");
});


test("Main and maintainer inspectors isolate concurrent result revisions", async () => {
  const mainDoc = fakeDocument(), maintainerDoc = fakeDocument();
  const mainPending = defer(), maintainerPending = defer();
  installCompatibilityPreview(mainDoc, () => mainPending.promise);
  installCompatibilityPreview(maintainerDoc, () => maintainerPending.promise);
  mainDoc.getElementById("compatibility-fixture-compatible").fire("click");
  maintainerDoc.getElementById("compatibility-fixture-no-artifact").fire("click");
  maintainerPending.resolve(preview(absent));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(maintainerDoc.getElementById("compatibility-result").hidden, false);
  assert.equal(mainDoc.getElementById("compatibility-result").hidden, true);
  maintainerDoc.getElementById("compatibility-close").fire("click");
  mainPending.resolve(preview(compatible));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(mainDoc.getElementById("compatibility-result").hidden, false);
  assert.equal(maintainerDoc.getElementById("compatibility-result").hidden, true);
});

test("Maintainer workspace wires the shared read-only compatibility inspector", async () => {
  const [html, script] = await Promise.all([
    readFile(new URL("../src/maintainer.html", import.meta.url), "utf8"),
    readFile(new URL("../src/maintainer.js", import.meta.url), "utf8"),
  ]);
  for (const id of ["compatibility-open", "compatibility-dialog", "compatibility-file-open",
    "compatibility-document", "compatibility-result", "compatibility-fields"]) {
    assert.match(html, new RegExp(`id=["']${id}["']`));
  }
  assert.match(html, /compatibility-preview\.css/);
  assert.match(html, /does not authorize a build, download, source choice, or activation/);
  assert.match(script, /import \{ installCompatibilityPreview \} from "\.\/compatibility-preview\.js"/);
  assert.match(script, /installCompatibilityPreview\(document, invoke, \(\) => openFolder/);
  assert.match(script, /Core resolver JSON/);
});

test("Compatibility inspector contains long localized controls at high zoom", async () => {
  const css = await readFile(new URL("../src/compatibility-preview.css", import.meta.url), "utf8");
  assert.match(css, /\.compatibility-dialog h2,[\s\S]*\.compatibility-dialog button,[\s\S]*\.compatibility-dialog dt\s*\{[^}]*min-width:\s*0;[^}]*max-width:\s*100%;[^}]*white-space:\s*normal;[^}]*overflow-wrap:\s*anywhere;/);
  const compact = css.match(/@media \(max-width: 480px\), \(max-height: 480px\) \{([\s\S]*)\n\}/)?.[1] || "";
  assert.match(compact, /\.compatibility-dialog\s*\{[^}]*width:\s*calc\(100vw - 16px\);[^}]*max-height:\s*calc\(100vh - 16px\);[^}]*padding:\s*14px;/);
  assert.match(compact, /\.compatibility-dialog textarea\s*\{\s*min-height:\s*96px;/);
});


test("Main and maintainer inspectors preserve reduced motion and forced colors", async () => {
  const [mainHtml, maintainerHtml, controlsCss, compatibilityCss] = await Promise.all([
    readFile(new URL("../src/index.html", import.meta.url), "utf8"),
    readFile(new URL("../src/maintainer.html", import.meta.url), "utf8"),
    readFile(new URL("../src/glass-controls.css", import.meta.url), "utf8"),
    readFile(new URL("../src/compatibility-preview.css", import.meta.url), "utf8"),
  ]);
  for (const html of [mainHtml, maintainerHtml]) {
    assert.match(html, /glass-controls\.css/);
    assert.match(html, /compatibility-preview\.css/);
  }
  assert.match(controlsCss, /@media \(prefers-reduced-motion: reduce\)[\s\S]*animation-duration:\s*\.01ms !important;[\s\S]*transition-duration:\s*\.01ms !important;/);
  assert.match(controlsCss, /@media \(forced-colors: active\)[\s\S]*forced-color-adjust:\s*auto;[\s\S]*outline:\s*2px solid Highlight;/);
  assert.match(compatibilityCss, /@media \(forced-colors: active\)\s*\{\s*\.compatibility-dialog, \.compatibility-dialog textarea\s*\{\s*border-color:\s*CanvasText;/);
});

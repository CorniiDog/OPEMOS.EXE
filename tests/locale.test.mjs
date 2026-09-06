import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { catalog, installLocale, resolveLocale, SUPPORTED_LOCALES, translate, validateCatalog } from "../src/locale.js";

test("delivered catalogs are complete, plain text, and exercise long Latin and CJK content", () => {
  const expected = Object.keys(catalog("en-US")).sort();
  for (const locale of SUPPORTED_LOCALES) {
    const entries = catalog(locale);
    assert.deepEqual(Object.keys(entries).sort(), expected, locale);
    for (const [key, value] of Object.entries(entries)) {
      assert.equal(typeof value, "string", `${locale}:${key}`);
      assert.ok(value.length > 0 && !/[<>]/.test(value), `${locale}:${key}`);
    }
  }
  assert.ok(catalog("de-DE").notice.length > catalog("en-US").notice.length);
  assert.match(catalog("ja-JP").notice, /[\u3000-\u9fff]/u);
  assert.match(catalog("ar").notice, /[\u0600-\u06ff]/u);
});

test("locale resolution accepts exact and language matches and fails safely", () => {
  assert.equal(resolveLocale("de-DE", ["en-US"]), "de-DE");
  assert.equal(resolveLocale("system", ["ja", "en-US"]), "ja-JP");
  assert.equal(resolveLocale("system", ["ar-EG"]), "ar");
  assert.equal(resolveLocale("unknown", ["xx", "de-AT"]), "de-DE");
  assert.equal(resolveLocale(null, null), "en-US");
});

test("catalog validation rejects missing, extra, malformed, and markup-bearing entries", () => {
  const valid={...catalog("en-US")};
  assert.equal(validateCatalog(valid),true);
  const missing={...valid};delete missing.close;assert.equal(validateCatalog(missing),false);
  assert.equal(validateCatalog({...valid,unexpected:"value"}),false);
  assert.equal(validateCatalog({...valid,close:7}),false);
  assert.equal(validateCatalog({...valid,close:"<b>Close</b>"}),false);
  assert.equal(translate("missing-key","bad-locale"),"missing-key");
});

function fakeDocument() {
  const listeners = new Map();
  const nodes = new Map(["locale-select","locale-label","locale-help","locale-system-option","compatibility-title","compatibility-document"].map(id => [id, { id, value:"system", textContent:"", placeholder:"", listeners:new Map(), addEventListener(n,h){this.listeners.set(n,h);} }]));
  const windowListeners=new Map();
  return { documentElement:{lang:"",dir:""}, defaultView:{CustomEvent:class{constructor(type){this.type=type;}},addEventListener:(n,h)=>windowListeners.set(n,h)}, getElementById:id=>nodes.get(id)||null, addEventListener:(n,h)=>listeners.set(n,h), dispatchEvent:e=>listeners.get(e.type)?.(e), nodes, windowListeners };
}

test("installation follows system locale, persists explicit choice, and applies RTL safely", () => {
  const doc=fakeDocument();const values=new Map();const storage={getItem:()=>null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};
  const installed=installLocale(doc,{languages:["ja-JP"]},storage);
  assert.equal(installed.locale,"ja-JP");assert.equal(doc.documentElement.dir,"ltr");assert.equal(doc.nodes.get("compatibility-title").textContent,catalog("ja-JP").dialogTitle);
  const select=doc.nodes.get("locale-select");select.value="ar";select.listeners.get("change")();
  assert.equal(installed.locale,"ar");assert.equal(doc.documentElement.dir,"rtl");assert.equal(values.get("opemos.locale"),"ar");assert.equal(translate("close"),catalog("ar").close);
  select.value="system";select.listeners.get("change")();assert.equal(values.has("opemos.locale"),false);
  doc.windowListeners.get("storage")({key:"opemos.locale",newValue:"de-DE"});
  assert.equal(installed.locale,"de-DE");assert.equal(doc.documentElement.dir,"ltr");assert.equal(select.value,"de-DE");
});

test("unavailable or throwing storage falls back without blocking localization", () => {
  const doc=fakeDocument();const storage={getItem(){throw new Error("blocked")},setItem(){throw new Error("blocked")},removeItem(){throw new Error("blocked")}};
  assert.doesNotThrow(()=>installLocale(doc,{languages:["de-DE"]},storage));
  assert.equal(doc.documentElement.lang,"de-DE");
});


test("main settings expose a bounded local chooser that remains usable at narrow widths", async () => {
  const [html,css]=await Promise.all([
    readFile(new URL("../src/index.html",import.meta.url),"utf8"),
    readFile(new URL("../src/styles.css",import.meta.url),"utf8"),
  ]);
  assert.match(html,/id="locale-select"[\s\S]*value="system"[\s\S]*value="en-US"[\s\S]*value="de-DE"[\s\S]*value="ja-JP"[\s\S]*value="ar"/);
  assert.match(css,/\.locale-setting select\s*\{[^}]*width:\s*min\(48%, 210px\);[^}]*min-width:\s*0;/);
});

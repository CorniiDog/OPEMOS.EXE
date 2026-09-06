import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RESULT = "OPEMOS_FORCED_COLORS_RESULT:";

export function extractBrowserResult(output) {
  const pattern = new RegExp(`<output id="result">${RESULT}([^<\\n]+)</output>`, "g");
  const matches = [...output.matchAll(pattern)];
  if (matches.length !== 1) throw new Error("Expected exactly one bounded browser result.");
  let parsed;
  try { parsed = JSON.parse(matches[0][1].replaceAll("&quot;", '"').replaceAll("&amp;", "&")); }
  catch { throw new Error("Browser result is not valid JSON."); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Browser result must be an object.");
  }
  return parsed;
}

export function validateForcedColorsResult(result) {
  assert.equal(result.active, true);
  assert.equal(result.before, "none");
  assert.equal(result.after, "none");
  for (const name of ["button", "select", "textarea", "text", "checkbox", "status"]) {
    assert.deepEqual(result[name], { borderWidth: "1px", shadow: "none", adjust: "auto" });
  }
  assert.deepEqual(result.focus, { style: "solid", width: "2px", offset: "3px" });
  assert.equal(result.disabled.opacity, "1");
  assert.equal(result.mainBackdrop, "none");
  assert.equal(result.buildBackdrop, "none");
  assert.equal(result.dialogBorder, result.textareaBorder);
}

function styleSnapshot(element) {
  const style = getComputedStyle(element);
  return { borderWidth: style.borderTopWidth, shadow: style.boxShadow,
    adjust: style.forcedColorAdjust };
}

async function fixtureDocument() {
  const styles = await Promise.all([
    "styles.css", "build.css", "maintainer.css", "glass-controls.css",
    "compatibility-preview.css",
  ].map((name) => readFile(path.join(root, "src", name), "utf8")));
  return `<!doctype html><meta charset="utf-8"><style>${styles.join("\n")}</style>
<body><div class="environment-card">main</div><div class="status-card">build</div>
<div class="card">maintainer</div><div class="compatibility-dialog"><textarea>text</textarea></div>
<button id="button">button</button><select id="select"><option>one</option></select>
<input id="text" type="text"><input id="checkbox" type="checkbox" checked>
<div id="status" class="status">status</div><button id="disabled" disabled>disabled</button>
<output id="result"></output><script>
const snapshot = ${styleSnapshot.toString()};
{
  const button = document.querySelector("#button"); button.focus();
  const focus = getComputedStyle(button);
  const result = {
    active: matchMedia("(forced-colors: active)").matches,
    before: getComputedStyle(document.body, "::before").display,
    after: getComputedStyle(document.body, "::after").display,
    button: snapshot(button),
    select: snapshot(document.querySelector("#select")),
    textarea: snapshot(document.querySelector("textarea")),
    text: snapshot(document.querySelector("#text")),
    checkbox: snapshot(document.querySelector("#checkbox")),
    status: snapshot(document.querySelector("#status")),
    focus: { style: focus.outlineStyle, width: focus.outlineWidth, offset: focus.outlineOffset },
    disabled: { opacity: getComputedStyle(document.querySelector("#disabled")).opacity },
    mainBackdrop: getComputedStyle(document.querySelector(".environment-card")).backdropFilter,
    buildBackdrop: getComputedStyle(document.querySelector(".status-card")).backdropFilter,
    dialogBorder: getComputedStyle(document.querySelector(".compatibility-dialog")).borderTopColor,
    textareaBorder: getComputedStyle(document.querySelector("textarea")).borderTopColor,
  };
  document.querySelector("#result").textContent = "${RESULT}" + JSON.stringify(result);
}
</script>`;
}

function runChrome(chrome, html, profile, forced) {
  const args = ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-background-networking",
    "--host-resolver-rules=MAP * ~NOTFOUND", `--user-data-dir=${profile}`,
    "--virtual-time-budget=1000", "--dump-dom"];
  if (forced) args.push("--force-high-contrast");
  args.push(`file://${html}`);
  const result = spawnSync(chrome, args, { encoding: "utf8", timeout: 15_000,
    maxBuffer: 2 * 1024 * 1024 });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Browser exited ${result.status}: ${result.stderr.slice(0, 500)}`);
  return extractBrowserResult(result.stdout);
}

export async function main() {
  const chrome = process.env.OPEMOS_CHROME || "google-chrome";
  const scratch = await mkdtemp(path.join(os.tmpdir(), "opemos-forced-colors-"));
  try {
    const html = path.join(scratch, "fixture.html");
    await writeFile(html, await fixtureDocument(), { mode: 0o600 });
    const regular = runChrome(chrome, html, path.join(scratch, "regular-profile"), false);
    assert.equal(regular.active, false);
    const forced = runChrome(chrome, html, path.join(scratch, "forced-profile"), true);
    validateForcedColorsResult(forced);
    console.log("PASS: Chromium forced-colors active; application body decoration, cards, controls, focus, disabled state, checkbox/status, and compatibility dialog remain distinguishable.");
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}

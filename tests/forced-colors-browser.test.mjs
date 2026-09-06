import assert from "node:assert/strict";
import test from "node:test";
import { extractBrowserResult, validateForcedColorsResult } from "../scripts/check_forced_colors_browser.mjs";

const valid = {
  active: true, before: "none", after: "none",
  button: { borderWidth: "1px", shadow: "none", adjust: "auto" },
  select: { borderWidth: "1px", shadow: "none", adjust: "auto" },
  textarea: { borderWidth: "1px", shadow: "none", adjust: "auto" },
  text: { borderWidth: "1px", shadow: "none", adjust: "auto" },
  checkbox: { borderWidth: "1px", shadow: "none", adjust: "auto" },
  status: { borderWidth: "1px", shadow: "none", adjust: "auto" },
  focus: { style: "solid", width: "2px", offset: "3px" },
  disabled: { opacity: "1" }, mainBackdrop: "none", buildBackdrop: "none",
  dialogBorder: "rgb(0, 0, 0)", textareaBorder: "rgb(0, 0, 0)",
};

test("browser result parser admits one bounded object", () => {
  assert.deepEqual(extractBrowserResult(`<output id="result">OPEMOS_FORCED_COLORS_RESULT:${JSON.stringify(valid)}</output>`), valid);
  assert.deepEqual(extractBrowserResult('<output id="result">OPEMOS_FORCED_COLORS_RESULT:{&quot;active&quot;:true}</output>'),
    { active: true });
});

test("browser result parser rejects absent, repeated, malformed, and scalar results", () => {
  for (const output of ["", "OPEMOS_FORCED_COLORS_RESULT:{",
    "OPEMOS_FORCED_COLORS_RESULT:true",
    "OPEMOS_FORCED_COLORS_RESULT:{}\nOPEMOS_FORCED_COLORS_RESULT:{}"]) {
    assert.throws(() => extractBrowserResult(output));
  }
});

test("forced-colors validation covers every visual state", () => {
  validateForcedColorsResult(valid);
  for (const mutate of [
    (value) => { value.active = false; },
    (value) => { value.before = "block"; },
    (value) => { value.button.shadow = "rgb(0, 0, 0) 0px 1px 2px"; },
    (value) => { value.checkbox.borderWidth = "0px"; },
    (value) => { value.focus.width = "0px"; },
    (value) => { value.disabled.opacity = "0.5"; },
    (value) => { value.dialogBorder = "rgb(1, 1, 1)"; },
  ]) {
    const changed = structuredClone(valid); mutate(changed);
    assert.throws(() => validateForcedColorsResult(changed));
  }
});

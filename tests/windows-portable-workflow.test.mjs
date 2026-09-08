import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateWindowsPortableWorkflow } from "../scripts/windows-portable-workflow.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflow = await readFile(path.join(repo, ".github", "workflows", "windows-portable.yml"), "utf8");

test("Windows portable workflow preserves immutable inputs and unsigned artifact gates", () => {
  assert.equal(validateWindowsPortableWorkflow(workflow), true);
});

for (const [name, mutate, expected] of [
  ["mutable Core checkout", text => text.replace("ref: 3e49323fce266af8686039fb6487918ef5a64fd9", "ref: main"), /Core checkout pin/],
  ["tagged action", text => text.replace("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020", "actions/setup-node@v4"), /setup-node action/],
  ["missing unsigned gate", text => text.replace("SignatureStatus]::NotSigned", "SignatureStatus]::Valid"), /unsigned-only gate/],
  ["long artifact retention", text => text.replace("retention-days: 1", "retention-days: 90"), /one-day artifact retention/],
  ["unlocked Rust build", text => text.replace("--release --locked", "--release"), /locked release build/],
  ["secret signing input", text => text + "\n# secrets.WINDOWS_CERT signtool", /must not use secrets/],
]) {
  test(`Windows portable workflow rejects ${name}`, () => {
    assert.throws(() => validateWindowsPortableWorkflow(mutate(workflow)), expected);
  });
}

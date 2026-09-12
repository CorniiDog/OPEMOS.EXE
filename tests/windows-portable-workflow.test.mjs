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

test("Windows portable workflow accepts CRLF checkout line endings", () => {
  assert.equal(validateWindowsPortableWorkflow(workflow.replace(/\r\n/g, "\n").replaceAll("\n", "\r\n")), true);
});

for (const [name, mutate, expected] of [
  ["merge-ref source identity", text => text.replace("github.event.pull_request.head.sha || github.sha", "github.sha"), /exact EXE source identity/],
  ["mutable Core checkout", text => text.replace("ref: b02ff79265e20bd7ef4fa4e16835c3c343afdee2", "ref: main"), /Core checkout pin/],
  ["Core CRLF conversion", text => text.replace("git config --global core.autocrlf false", "git config --global core.autocrlf true"), /canonical Core byte preservation/],
  ["tagged action", text => text.replace("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020", "actions/setup-node@v4"), /setup-node action/],
  ["missing unsigned gate", text => text.replace("SignatureStatus]::NotSigned", "SignatureStatus]::Valid"), /unsigned-only gate/],
  ["long artifact retention", text => text.replace("retention-days: 1", "retention-days: 90"), /one-day artifact retention/],
  ["unlocked Rust build", text => text.replace("--release --locked", "--release"), /locked release build/],
  ["missing executable smoke test", text => text.replace("Start-Process -FilePath $source -PassThru", "Write-Host skipped"), /startup smoke test/],
  ["missing UI readiness polling", text => text.replace("} while (($process.MainWindowHandle -eq 0 -or $process.MainWindowTitle -cne \"SteamOS NVIDIA Builder\") -and [DateTime]::UtcNow -lt $deadline)", "} while ($false)"), /native UI readiness polling/],
  ["missing visible-window gate", text => text.replace("if ($process.MainWindowHandle -eq 0) {", "if ($false) {"), /native main-window gate/],
  ["wrong UI title", text => text.replace("if ($process.MainWindowTitle -cne \"SteamOS NVIDIA Builder\") {", "if ($false) {"), /expected Windows UI title/],
  ["missing unconditional cleanup", text => text.replace("finally {", "if ($true) {"), /unconditional smoke-test cleanup/],
  ["secret signing input", text => text + "\n# secrets.WINDOWS_CERT signtool", /must not use secrets/],
]) {
  test(`Windows portable workflow rejects ${name}`, () => {
    assert.throws(() => validateWindowsPortableWorkflow(mutate(workflow)), expected);
  });
}

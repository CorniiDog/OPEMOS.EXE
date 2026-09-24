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
  ["short artifact job budget", text => text.replace("timeout-minutes: 120", "timeout-minutes: 60"), /bounded Windows artifact job budget/],
  ["mutable Core checkout", text => text.replace("ref: 01b85f13bddfa2aa3ba196bc8f35cadc14e11a3b", "ref: main"), /Core checkout pin/],
  ["Core CRLF conversion", text => text.replace("git config --global core.autocrlf false", "git config --global core.autocrlf true"), /canonical Core byte preservation/],
  ["tagged action", text => text.replace("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020", "actions/setup-node@v4"), /setup-node action/],
  ["missing unsigned gate", text => text.replace("SignatureStatus]::NotSigned", "SignatureStatus]::Valid"), /unsigned-only gate/],
  ["long artifact retention", text => text.replace("retention-days: 1", "retention-days: 90"), /one-day artifact retention/],
  ["missing hidden runtime files", text => text.replace("include-hidden-files: true", "include-hidden-files: false"), /declared hidden runtime files/],
  ["missing verified bundle build", text => text.replace("run: .\\bundle_windows.ps1 -CoreRoot opemos-core-contracts", "run: Write-Host skipped"), /verified Windows bundle build/],
  ["all-target Windows Rust test", text => text.replace("--locked --lib windows_", "--locked windows_"), /library-only Windows Rust tests/],
  ["dynamic MSVC runtime", text => text.replace("RUSTFLAGS: -C target-feature=+crt-static", "RUSTFLAGS: dynamic"), /static MSVC runtime linkage/],
  ["missing test activation manifest", text => text.replace(" -C link-arg=/MANIFESTINPUT:${{ github.workspace }}\\scripts\\windows-test-v6.manifest", ""), /test-only Common Controls v6 activation manifest/],
  ["activation manifest applied twice", text => text.replace("      - name: Build unsigned verified runtime bundle", "      - name: Duplicate manifest input\n        env:\n          RUSTFLAGS: -C link-arg=/MANIFESTINPUT:duplicate.manifest\n      - name: Build unsigned verified runtime bundle"), /only to the Rust test step/],
  ["missing static-runtime provenance", text => text.replace(`"crt_static=true"`, `"crt_static=false"`), /static-runtime provenance/],
  ["missing executable smoke test", text => text.replace("Start-Process -FilePath $source -PassThru", "Write-Host skipped"), /startup smoke test/],
  ["missing UI readiness polling", text => text.replace("} while (($process.MainWindowHandle -eq 0 -or $process.MainWindowTitle -cne \"SteamOS NVIDIA Builder\") -and [DateTime]::UtcNow -lt $deadline)", "} while ($false)"), /native UI readiness polling/],
  ["missing visible-window gate", text => text.replace("if ($process.MainWindowHandle -eq 0) {", "if ($false) {"), /native main-window gate/],
  ["wrong UI title", text => text.replace("if ($process.MainWindowTitle -cne \"SteamOS NVIDIA Builder\") {", "if ($false) {"), /expected Windows UI title/],
  ["missing unconditional cleanup", text => text.replace("finally {", "if ($true) {"), /unconditional smoke-test cleanup/],
  ["missing pre-start QEMU inventory", text => text.replace('$qemuBefore = @(Get-Process -Name "qemu-system-*"', '$qemuBefore = @($null #'), /pre-start QEMU identity inventory/],
  ["unbounded post-close QEMU check", text => text.replace('$qemuDeadline = [DateTime]::UtcNow.AddSeconds(5)', '$qemuDeadline = [DateTime]::MaxValue'), /bounded post-close QEMU check/],
  ["missing new-QEMU identity comparison", text => text.replace('Where-Object { $_ -notin $qemuBefore }', 'Where-Object { $false }'), /new-QEMU identity comparison/],
  ["missing no-orphan QEMU gate", text => text.replace('if ($qemuAfter.Count -ne 0) {', 'if ($false) {'), /no-orphan QEMU gate/],
  ["missing bundle-local state selection", text => text.replace('$state = Join-Path $bundleRoot "state"', '$state = "$env:APPDATA\\state"'), /bundle-local smoke-state selection/],
  ["linked smoke-state accepted", text => text.replace('($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint)', '$false'), /linked smoke-state refusal/],
  ["missing smoke-state cleanup", text => text.replace('Remove-Item -LiteralPath $state -Recurse -Force', 'Write-Host skipped'), /owned smoke-state cleanup/],
  ["missing clean-artifact gate", text => text.replace('throw "Portable smoke-test state survived cleanup."', 'Write-Host skipped'), /post-cleanup absence gate/],
  ["secret signing input", text => text + "\n# secrets.WINDOWS_CERT signtool", /must not use secrets/],
]) {
  test(`Windows portable workflow rejects ${name}`, () => {
    assert.throws(() => validateWindowsPortableWorkflow(mutate(workflow)), expected);
  });
}

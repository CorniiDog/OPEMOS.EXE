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
  ["mutable Core checkout", text => text.replace("ref: e1d2046828526c2c23a5e348380f87799fa273e2", "ref: main"), /Core checkout pin/],
  ["Core CRLF conversion", text => text.replace("git config --global core.autocrlf false", "git config --global core.autocrlf true"), /canonical Core byte preservation/],
  ["tagged action", text => text.replace("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020", "actions/setup-node@v4"), /setup-node action/],
  ["missing unsigned gate", text => text.replace("SignatureStatus]::NotSigned", "SignatureStatus]::Valid"), /unsigned-only gate/],
  ["long artifact retention", text => text.replace("retention-days: 1", "retention-days: 90"), /one-day artifact retention/],
  ["missing hidden runtime files", text => text.replace("include-hidden-files: true", "include-hidden-files: false"), /declared hidden runtime files/],
  ["mutable runtime seed action", text => text.replace("actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093", "actions/download-artifact@v4"), /download-artifact action/],
  ["missing exact Git for Windows seed", text => text.replace("python3 scripts/acquire_runtime_windows.py --component git-for-windows --cache build/runtime-cache/windows", "echo skipped"), /locked Git for Windows seed acquisition/],
  ["missing exact GitHub CLI seed", text => text.replace("python3 scripts/acquire_runtime_windows.py --component github-cli --cache build/runtime-cache/windows", "echo skipped"), /locked GitHub CLI seed acquisition/],
  ["missing exact Python seed", text => text.replace("python3 scripts/acquire_runtime_windows.py --component python --cache build/runtime-cache/windows", "echo skipped"), /locked Python seed acquisition/],
  ["missing exact QEMU seed", text => text.replace("python3 scripts/acquire_runtime_windows.py --component qemu --cache build/runtime-cache/windows", "echo skipped"), /locked QEMU seed acquisition/],
  ["missing exact cdrtools binary seed", text => text.replace("python3 scripts/acquire_runtime_windows.py --component cdrtools-binary --cache build/runtime-cache/windows", "echo skipped"), /locked cdrtools binary seed acquisition/],
  ["missing exact cdrtools source seed", text => text.replace("python3 scripts/acquire_runtime_windows.py --component cdrtools-source --cache build/runtime-cache/windows", "echo skipped"), /locked cdrtools source seed acquisition/],
  ["missing runtime seed dependency", text => text.replace("needs: seed-runtime-source", "needs: []"), /runtime-seed dependency/],
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
  ["missing unconditional cleanup", text => text.replace(/finally \{\r?\n            if \(-not \$process\.HasExited\)/, "if ($true) {\n            if (-not $process.HasExited)"), /unconditional smoke-test cleanup/],
  ["missing pre-start QEMU inventory", text => text.replace('$qemuBefore = @(Get-Process -Name "qemu-system-*"', '$qemuBefore = @($null #'), /pre-start QEMU identity inventory/],
  ["unbounded post-close QEMU check", text => text.replace('$qemuDeadline = [DateTime]::UtcNow.AddSeconds(5)', '$qemuDeadline = [DateTime]::MaxValue'), /bounded post-close QEMU check/],
  ["missing new-QEMU identity comparison", text => text.replace('Where-Object { $_ -notin $qemuBefore }', 'Where-Object { $false }'), /new-QEMU identity comparison/],
  ["missing no-orphan QEMU gate", text => text.replace('if ($qemuAfter.Count -ne 0) {', 'if ($false) {'), /no-orphan QEMU gate/],
  ["missing pre-start WebView inventory", text => text.replace('$webviewBefore = @(Get-Process -Name "msedgewebview2"', '$webviewBefore = @($null #'), /pre-start WebView identity inventory/],
  ["racy WebView identity capture", text => text.replaceAll('ForEach-Object { try { "$($_.Id):$($_.StartTime.ToUniversalTime().Ticks)" } catch {} }', 'ForEach-Object { "$($_.Id):$($_.StartTime.ToUniversalTime().Ticks)" }'), /race-safe WebView identity capture/],
  ["unbounded post-close WebView check", text => text.replace('$webviewDeadline = [DateTime]::UtcNow.AddSeconds(15)', '$webviewDeadline = [DateTime]::MaxValue'), /bounded post-close WebView check/],
  ["missing new-WebView identity comparison", text => text.replace('Where-Object { $_ -notin $webviewBefore }', 'Where-Object { $false }'), /new-WebView identity comparison/],
  ["missing no-orphan WebView gate", text => text.replace('if ($webviewAfter.Count -ne 0) {', 'if ($false) {'), /no-orphan WebView gate/],
  ["missing bundle-local state selection", text => text.replace('$state = Join-Path $bundleRoot "state"', '$state = "$env:APPDATA\\state"'), /bundle-local smoke-state selection/],
  ["linked smoke-state accepted", text => text.replace('($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint)', '$false'), /linked smoke-state refusal/],
  ["missing smoke-state cleanup", text => text.replace('Remove-Item -LiteralPath $state -Recurse -Force', 'Write-Host skipped'), /owned smoke-state cleanup/],
  ["unbounded smoke-state cleanup", text => text.replace('$stateCleanupDeadline = [DateTime]::UtcNow.AddSeconds(10)', '$stateCleanupDeadline = [DateTime]::MaxValue'), /bounded smoke-state lock-release retry/],
  ["missing clean-artifact gate", text => text.replace('throw "Portable smoke-test state survived cleanup."', 'Write-Host skipped'), /post-cleanup absence gate/],
  ["secret signing input", text => text + "\n# secrets.WINDOWS_CERT signtool", /must not use secrets/],
]) {
  test(`Windows portable workflow rejects ${name}`, () => {
    assert.throws(() => validateWindowsPortableWorkflow(mutate(workflow)), expected);
  });
}

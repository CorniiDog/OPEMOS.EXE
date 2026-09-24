#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262";
const SETUP_NODE = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020";
const RUST = "dtolnay/rust-toolchain@6bed0761d98439e5a578e2877258200ad565ba87";
const UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02";
const CORE = "342e81025da0551facee2a28e8f2d9ddf1bd2fd6";
const bundle = await readFile(new URL("../bundle_windows.ps1", import.meta.url), "utf8");

function requireText(text, value, label) {
  if (!text.includes(value)) throw new Error(`Windows workflow must preserve ${label}.`);
}

export function validateWindowsPortableWorkflow(text) {
  text = text.replace(/\r\n/g, "\n");
  requireText(text, "runs-on: windows-latest", "the Windows runner");
  requireText(text, "timeout-minutes: 120", "the bounded Windows artifact job budget");
  requireText(text, "permissions:\n  contents: read", "read-only permissions");
  requireText(text, "OPEMOS_EXE_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}", "the exact EXE source identity");
  if ((text.match(new RegExp(CHECKOUT, "g")) || []).length !== 2) throw new Error("Windows workflow must use the exact checkout action twice.");
  requireText(text, SETUP_NODE, "the immutable setup-node action");
  requireText(text, RUST, "the immutable Rust action");
  requireText(text, UPLOAD, "the immutable artifact action");
  requireText(text, `OPEMOS_CORE_COMMIT: ${CORE}`, "the Core environment pin");
  requireText(text, `ref: ${CORE}`, "the Core checkout pin");
  requireText(text, "ref: ${{ env.OPEMOS_EXE_COMMIT }}", "the EXE checkout pin");
  requireText(text, "git rev-parse HEAD", "runtime EXE commit verification");
  requireText(text, "git -C opemos-core-contracts rev-parse HEAD", "runtime Core commit verification");
  requireText(text, "git config --global core.autocrlf false", "canonical Core byte preservation");
  requireText(text, "node-version: 22.23.2", "Node 22.23.2");
  requireText(text, "toolchain: 1.98.1", "Rust 1.98.1");
  requireText(text, "RUSTFLAGS: -C target-feature=+crt-static", "static MSVC runtime linkage");
  if ((text.match(/RUSTFLAGS: -C target-feature=\+crt-static/g) || []).length !== 2) throw new Error("Windows workflow must preserve static MSVC runtime linkage for tests and the bundle build.");
  requireText(text, "run: npm ci", "locked JavaScript installation");
  requireText(text, "run: node --test tests/windows-portable-workflow.test.mjs", "focused cross-platform JavaScript tests");
  requireText(text, "run: node scripts/check_core_maintainer_workflow.mjs", "exact Core maintainer workflow parity check");
  requireText(text, "cargo test --manifest-path src-tauri/Cargo.toml --locked --lib windows_", "locked library-only Windows Rust tests");
  requireText(text, "RUSTFLAGS: -C target-feature=+crt-static -C link-arg=/MANIFEST:EMBED -C link-arg=/MANIFESTINPUT:${{ github.workspace }}\\scripts\\windows-test-v6.manifest", "the test-only Common Controls v6 activation manifest");
  requireText(text, "run: .\\bundle_windows.ps1 -CoreRoot opemos-core-contracts", "verified Windows bundle build");
  requireText(bundle, "scripts/acquire_appliance_windows.py", "exact Fedora appliance acquisition");
  requireText(bundle, "--deadline-seconds 4500", "the bounded Fedora appliance acquisition deadline");
  requireText(bundle, 'dist/windows/appliance', "portable Fedora appliance placement");
  requireText(text, "dist/windows/OPEMOS.EXE-windows-x86_64-unsigned.exe", "bundled executable startup");
  requireText(text, "path: dist/windows", "complete verified bundle upload");
  if ((text.match(/MANIFESTINPUT:/g) || []).length !== 1) throw new Error("Windows workflow must apply the activation manifest only to the Rust test step.");
  requireText(text, "Start-Process -FilePath $source -PassThru", "portable executable startup smoke test");
  requireText(text, "} while (($process.MainWindowHandle -eq 0 -or $process.MainWindowTitle -cne \"SteamOS NVIDIA Builder\") -and [DateTime]::UtcNow -lt $deadline)", "bounded native UI readiness polling");
  requireText(text, "if ($process.MainWindowHandle -eq 0) {", "a visible native main-window gate");
  requireText(text, "if ($process.MainWindowTitle -cne \"SteamOS NVIDIA Builder\") {", "the expected Windows UI title");
  requireText(text, "finally {", "unconditional smoke-test cleanup");
  requireText(text, "Stop-Process -Id $process.Id", "bounded smoke-test process cleanup");
  requireText(text, '$qemuBefore = @(Get-Process -Name "qemu-system-*"', "the pre-start QEMU identity inventory");
  requireText(text, '$qemuDeadline = [DateTime]::UtcNow.AddSeconds(5)', "the bounded post-close QEMU check");
  requireText(text, 'Where-Object { $_ -notin $qemuBefore }', "new-QEMU identity comparison");
  requireText(text, 'if ($qemuAfter.Count -ne 0) {', "the no-orphan QEMU gate");
  requireText(text, '$state = Join-Path $bundleRoot "state"', "exact bundle-local smoke-state selection");
  requireText(text, '($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint)', "linked smoke-state refusal");
  requireText(text, 'Remove-Item -LiteralPath $state -Recurse -Force', "owned smoke-state cleanup");
  requireText(text, 'throw "Portable smoke-test state survived cleanup."', "post-cleanup absence gate");
  requireText(text, "Get-AuthenticodeSignature -LiteralPath $source", "Authenticode inspection");
  requireText(text, "SignatureStatus]::NotSigned", "the unsigned-only gate");
  requireText(text, "Get-FileHash -LiteralPath $destination -Algorithm SHA256", "SHA-256 provenance");
  requireText(text, `"source_commit=$env:OPEMOS_EXE_COMMIT"`, "exact-head provenance");
  requireText(text, `"crt_static=true"`, "static-runtime provenance");
  requireText(text, "unsigned-${{ env.OPEMOS_EXE_COMMIT }}", "exact-head artifact identity");
  requireText(text, "retention-days: 1", "one-day artifact retention");
  requireText(text, "if-no-files-found: error", "missing-artifact failure");
  requireText(text, "include-hidden-files: true", "declared hidden runtime files in the artifact");
  if (/uses:\s*[^\s@]+@(v\d+|main|master|stable)\b/i.test(text)) throw new Error("Windows workflow actions must use immutable commits.");
  if (/secrets\.|signtool|gh\s+release|create-release|pages/i.test(text)) throw new Error("Windows workflow must not use secrets, signing, releases, or Pages.");
  return true;
}

const workflow = path.join(path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."), ".github", "workflows", "windows-portable.yml");
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { validateWindowsPortableWorkflow(await readFile(workflow, "utf8")); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}

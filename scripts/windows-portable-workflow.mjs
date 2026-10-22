#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262";
const SETUP_NODE = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020";
const RUST = "dtolnay/rust-toolchain@6bed0761d98439e5a578e2877258200ad565ba87";
const UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02";
const DOWNLOAD = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093";
const CORE = "f72aff92a5534b676083ccba974f4185f2d4551f";
const bundle = await readFile(new URL("../bundle_windows.ps1", import.meta.url), "utf8");

function requireText(text, value, label) {
  if (!text.includes(value)) throw new Error(`Windows workflow must preserve ${label}.`);
}

export function validateWindowsPortableWorkflow(text) {
  text = text.replace(/\r\n/g, "\n");
  if (text.includes("# OMEN_GUEST_SOURCE_WORKLOAD_V1:")) {
    return validateOmenWindowsProducer(text);
  }
  requireText(text, "runs-on: windows-latest", "the Windows runner");
  requireText(text, "timeout-minutes: 120", "the bounded Windows artifact job budget");
  requireText(text, "permissions:\n  contents: read\n  actions: read", "read-only permissions");
  requireText(text, "OPEMOS_EXE_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}", "the exact EXE source identity");
  if ((text.match(new RegExp(CHECKOUT, "g")) || []).length !== 6) throw new Error("Windows workflow must use six exact checkout actions including the two isolated OMEN gate jobs.");
  requireText(text, "if: github.event_name == 'workflow_dispatch' && inputs.producer-metadata-diagnostic", "manual-only finite diagnostic routing");
  requireText(text, "if: ${{ !inputs.producer-metadata-diagnostic }}", "no expensive source seed during finite diagnostic");
  requireText(text, "run: python scripts/diagnose_windows_producer_metadata.py", "the actual native metadata producer");
  requireText(text, SETUP_NODE, "the immutable setup-node action");
  requireText(text, RUST, "the immutable Rust action");
  requireText(text, UPLOAD, "the immutable artifact action");
  requireText(text, DOWNLOAD, "the immutable download-artifact action");
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
  requireText(text, "runs-on: ubuntu-latest", "the alternate runtime-seed network lane");
  requireText(text, "needs: seed-runtime-source", "the runtime-seed dependency");
  requireText(text, "python3 scripts/acquire_runtime_windows.py --component git-for-windows --cache build/runtime-cache/windows", "exact locked Git for Windows seed acquisition");
  requireText(text, "python3 scripts/acquire_runtime_windows.py --component github-cli --cache build/runtime-cache/windows", "exact locked GitHub CLI seed acquisition");
  requireText(text, "python3 scripts/acquire_runtime_windows.py --component python --cache build/runtime-cache/windows", "exact locked Python seed acquisition");
  requireText(text, "python3 scripts/acquire_runtime_windows.py --component qemu --cache build/runtime-cache/windows", "exact locked QEMU seed acquisition");
  requireText(text, "python3 scripts/acquire_runtime_windows.py --component cdrtools-binary --cache build/runtime-cache/windows", "exact locked cdrtools binary seed acquisition");
  requireText(text, "python3 scripts/acquire_runtime_windows.py --component cdrtools-source --cache build/runtime-cache/windows", "exact locked cdrtools source seed acquisition");
  requireText(text, "name: windows-runtime-source-${{ env.OPEMOS_EXE_COMMIT }}", "exact-head runtime seed identity");
  requireText(text, "build/runtime-cache/windows/PortableGit-2.55.0.5-64-bit.7z.exe", "closed Git for Windows seed upload");
  requireText(text, "build/runtime-cache/windows/gh_2.100.0_windows_amd64.zip", "closed GitHub CLI seed upload");
  requireText(text, "build/runtime-cache/windows/python-3.13.15-embeddable-amd64.zip", "closed Python seed upload");
  requireText(text, "build/runtime-cache/windows/qemu-w64-setup-20260811.exe", "closed QEMU seed upload");
  requireText(text, "build/runtime-cache/windows/schily-cdrtools-3.02a09.7z", "closed cdrtools binary seed upload");
  requireText(text, "build/runtime-cache/windows/cdrtools-3.02a09.tar.gz", "closed cdrtools source seed upload");
  requireText(text, "path: build/runtime-cache/windows", "closed QEMU cache restore");
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
  requireText(text, "finally {\n            if (-not $process.HasExited)", "unconditional smoke-test cleanup");
  requireText(text, "Stop-Process -Id $process.Id", "bounded smoke-test process cleanup");
  requireText(text, '$qemuBefore = @(Get-Process -Name "qemu-system-*"', "the pre-start QEMU identity inventory");
  requireText(text, '$qemuDeadline = [DateTime]::UtcNow.AddSeconds(5)', "the bounded post-close QEMU check");
  requireText(text, 'Where-Object { $_ -notin $qemuBefore }', "new-QEMU identity comparison");
  requireText(text, 'if ($qemuAfter.Count -ne 0) {', "the no-orphan QEMU gate");
  requireText(text, '$webviewBefore = @(Get-Process -Name "msedgewebview2"', "the pre-start WebView identity inventory");
  requireText(text, 'ForEach-Object { try { "$($_.Id):$($_.StartTime.ToUniversalTime().Ticks)" } catch {} }', "race-safe WebView identity capture");
  requireText(text, '$webviewDeadline = [DateTime]::UtcNow.AddSeconds(15)', "the bounded post-close WebView check");
  requireText(text, 'Where-Object { $_ -notin $webviewBefore }', "new-WebView identity comparison");
  requireText(text, 'if ($webviewAfter.Count -ne 0) {', "the no-orphan WebView gate");
  requireText(text, '$state = Join-Path $bundleRoot "state"', "exact bundle-local smoke-state selection");
  requireText(text, '($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint)', "linked smoke-state refusal");
  requireText(text, 'Remove-Item -LiteralPath $state -Recurse -Force', "owned smoke-state cleanup");
  requireText(text, '$stateCleanupDeadline = [DateTime]::UtcNow.AddSeconds(10)', "bounded smoke-state lock-release retry");
  requireText(text, 'throw "Portable smoke-test state survived cleanup."', "post-cleanup absence gate");
  requireText(text, "Get-AuthenticodeSignature -LiteralPath $source", "Authenticode inspection");
  requireText(text, "SignatureStatus]::NotSigned", "the unsigned-only gate");
  requireText(text, "Get-FileHash -LiteralPath $destination -Algorithm SHA256", "SHA-256 provenance");
  requireText(text, `"source_commit=$env:OPEMOS_EXE_COMMIT"`, "exact-head provenance");
  requireText(text, `"crt_static=true"`, "static-runtime provenance");
  requireText(text, "unsigned-${{ env.OPEMOS_EXE_COMMIT }}", "exact-head artifact identity");
  requireText(text, "--platform windows", "the exact Windows producer descriptor");
  requireText(text, "PRODUCER_ARTIFACT_SHA256: ${{ steps.executable.outputs.artifact-digest }}", "uploaded artifact digest binding");
  requireText(text, "path: build/executable-producer/executable-producer.json", "the separate producer descriptor upload");
  const retention = "${{ github.repository == 'CorniiDog/OPEMOS.EXE' && github.ref == 'refs/heads/main' && 90 || 1 }}";
  const retentionValues = [...text.matchAll(/^\s*retention-days:\s*(.*?)\s*$/gm)].map(match => match[1]);
  if (retentionValues.length !== 6 || retentionValues.some(value => value !== retention)) {
    throw new Error("Windows workflow must preserve canonical-main 90-day and other-ref one-day artifact retention for all six uploads.");
  }
  const trustedCondition = "github.repository == 'CorniiDog/OPEMOS.EXE' && github.ref == 'refs/heads/main' && github.ref_protected && (github.event_name == 'push' || github.event_name == 'workflow_dispatch')";
  const main = text.split("\n  omen-required:\n")[1]?.split("\n  omen-required-untrusted:\n")[0] || "";
  const untrusted = text.split("\n  omen-required-untrusted:\n")[1] || "";
  requireText(main, `if: always() && ${trustedCondition}`, "trusted-Main-only OMEN dispatch allocation");
  requireText(main, "ref: ${{ github.sha }}", "immutable Main gate checkout");
  requireText(main, "actions: write", "Main-only dispatch token");
  requireText(main, "dispatch-and-wait --platform windows", "exact Windows required outcome");
  requireText(untrusted, `if: always() && !(${trustedCondition})`, "separate non-Main failure allocation");
  requireText(untrusted, "actions: read", "read-only non-Main diagnostics");
  requireText(untrusted, "ref: ${{ github.event.pull_request.head.sha || github.sha }}", "exact candidate diagnostic checkout");
  requireText(untrusted, "diagnostics --directory required-omen-results", "unavailable outcome reports");
  requireText(untrusted, "exit 1", "red non-Main operational outcome");
  if ((text.match(/actions: write/g) || []).length !== 1 || /actions: write|dispatch-and-wait|self-hosted/.test(untrusted)) {
    throw new Error("Windows workflow must isolate its sole write token/dispatch to Main; non-Main diagnostics stay read-only.");
  }
  requireText(text, "if-no-files-found: error", "missing-artifact failure");
  requireText(text, "include-hidden-files: true", "declared hidden runtime files in the artifact");
  if (/uses:\s*[^\s@]+@(v\d+|main|master|stable)\b/i.test(text)) throw new Error("Windows workflow actions must use immutable commits.");
  if (/secrets\.|signtool|gh\s+release|create-release|pages/i.test(text)) throw new Error("Windows workflow must not use secrets, signing, releases, or Pages.");
  return true;
}

export function validateOmenWindowsProducer(text) {
  text = text.replace(/\r\n/g, "\n");
  requireText(text, "# OMEN_GUEST_SOURCE_WORKLOAD_V1:", "explicit OMEN-only producer schema");
  requireText(text, "permissions:\n  contents: read\n  actions: read", "read-only producer token");
  requireText(text, "cancel-in-progress: false", "preserved running guest/compiler ownership");
  requireText(text, "needs: seed-runtime-source", "same-parent guest seed dependency");
  for (const workload of ["seed-runtime-source", "windows-build"]) {
    requireText(text, `/var/lib/opemos-robot-control-r1/source/scripts/omen_source_ci.py run-required --workload ${workload}`, "fixed A actual guest result consumer");
  }
  requireText(text, "job_guard.py --bind-job-token", "existing source-only token binding");
  requireText(text, "source-route:", "honest offline route diagnostic");
  requireText(text, "ready != 'true'", "failed unavailable context, not skipped acceptance");
  requireText(text, "PRODUCER_ARTIFACT_SHA256: ${{ steps.executable.outputs.artifact-digest }}", "uploaded artifact digest binding");
  requireText(text, "path: dist/windows", "actual reassembled guest bundle upload");
  requireText(text, "path: build/executable-producer/executable-producer.json", "separate producer identity");
  requireText(text, "include-hidden-files: true", "complete runtime bundle");
  requireText(text, UPLOAD, "immutable artifact action");
  const untrusted = text.split("\n  omen-required-untrusted:\n")[1] || "";
  const main = text.split("\n  omen-required:\n")[1]?.split("\n  omen-required-untrusted:\n")[0] || "";
  requireText(main, "github.ref == 'refs/heads/main' && github.ref_protected", "protected Main-only GUI write scope");
  requireText(main, "ref: ${{ github.sha }}", "immutable Main GUI gate checkout");
  if (/actions: write|dispatch-and-wait|self-hosted/.test(untrusted) || (text.match(/actions: write/g) || []).length !== 1) {
    throw new Error("Windows workflow must isolate its sole write token/dispatch to Main.");
  }
  if (/run:\s*(?:npm|cargo|node --test|\.\\bundle_windows|python.*unittest)|runs-on: windows-latest|secrets\.|signtool|gh\s+release/.test(text)) {
    throw new Error("Windows producer must not run hosted project commands or use signing/trust inputs.");
  }
  const sourceJobs = text.split("\n  omen-required:\n")[0];
  if (/actions\/checkout@/.test(sourceJobs)) throw new Error("Source jobs must execute only the fixed installed A client, no candidate checkout.");
  // The original full native recipe and its strict fault suite remain separate
  // guest-only source contracts. This function does not turn those into passes.
  return true;
}

const workflow = path.join(path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."), ".github", "workflows", "windows-portable.yml");
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { validateWindowsPortableWorkflow(await readFile(workflow, "utf8")); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}

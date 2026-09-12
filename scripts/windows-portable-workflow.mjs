#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262";
const SETUP_NODE = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020";
const RUST = "dtolnay/rust-toolchain@6bed0761d98439e5a578e2877258200ad565ba87";
const UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02";
const CORE = "b02ff79265e20bd7ef4fa4e16835c3c343afdee2";

function requireText(text, value, label) {
  if (!text.includes(value)) throw new Error(`Windows workflow must preserve ${label}.`);
}

export function validateWindowsPortableWorkflow(text) {
  text = text.replace(/\r\n/g, "\n");
  requireText(text, "runs-on: windows-latest", "the Windows runner");
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
  requireText(text, "run: npm ci", "locked JavaScript installation");
  requireText(text, "run: node --test tests/windows-portable-workflow.test.mjs", "focused cross-platform JavaScript tests");
  requireText(text, "run: node scripts/check_core_maintainer_workflow.mjs", "exact Core maintainer workflow parity check");
  requireText(text, "cargo test --manifest-path src-tauri/Cargo.toml --locked windows_", "locked Windows Rust tests");
  requireText(text, "cargo build --manifest-path src-tauri/Cargo.toml --release --locked", "locked release build");
  requireText(text, "Start-Process -FilePath $source -PassThru", "portable executable startup smoke test");
  requireText(text, "} while (($process.MainWindowHandle -eq 0 -or $process.MainWindowTitle -cne \"SteamOS NVIDIA Builder\") -and [DateTime]::UtcNow -lt $deadline)", "bounded native UI readiness polling");
  requireText(text, "if ($process.MainWindowHandle -eq 0) {", "a visible native main-window gate");
  requireText(text, "if ($process.MainWindowTitle -cne \"SteamOS NVIDIA Builder\") {", "the expected Windows UI title");
  requireText(text, "finally {", "unconditional smoke-test cleanup");
  requireText(text, "Stop-Process -Id $process.Id", "bounded smoke-test process cleanup");
  requireText(text, "Get-AuthenticodeSignature -LiteralPath $source", "Authenticode inspection");
  requireText(text, "SignatureStatus]::NotSigned", "the unsigned-only gate");
  requireText(text, "Get-FileHash -LiteralPath $destination -Algorithm SHA256", "SHA-256 provenance");
  requireText(text, `"source_commit=$env:OPEMOS_EXE_COMMIT"`, "exact-head provenance");
  requireText(text, "unsigned-${{ env.OPEMOS_EXE_COMMIT }}", "exact-head artifact identity");
  requireText(text, "retention-days: 1", "one-day artifact retention");
  requireText(text, "if-no-files-found: error", "missing-artifact failure");
  if (/uses:\s*[^\s@]+@(v\d+|main|master|stable)\b/i.test(text)) throw new Error("Windows workflow actions must use immutable commits.");
  if (/secrets\.|signtool|gh\s+release|create-release|pages/i.test(text)) throw new Error("Windows workflow must not use secrets, signing, releases, or Pages.");
  return true;
}

const workflow = path.join(path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."), ".github", "workflows", "windows-portable.yml");
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { validateWindowsPortableWorkflow(await readFile(workflow, "utf8")); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}

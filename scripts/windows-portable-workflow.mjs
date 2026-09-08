#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262";
const SETUP_NODE = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020";
const RUST = "dtolnay/rust-toolchain@6bed0761d98439e5a578e2877258200ad565ba87";
const UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02";
const CORE = "3e49323fce266af8686039fb6487918ef5a64fd9";

function requireText(text, value, label) {
  if (!text.includes(value)) throw new Error(`Windows workflow must preserve ${label}.`);
}

export function validateWindowsPortableWorkflow(text) {
  requireText(text, "runs-on: windows-latest", "the Windows runner");
  requireText(text, "permissions:\n  contents: read", "read-only permissions");
  if ((text.match(new RegExp(CHECKOUT, "g")) || []).length !== 2) throw new Error("Windows workflow must use the exact checkout action twice.");
  requireText(text, SETUP_NODE, "the immutable setup-node action");
  requireText(text, RUST, "the immutable Rust action");
  requireText(text, UPLOAD, "the immutable artifact action");
  requireText(text, `OPEMOS_CORE_COMMIT: ${CORE}`, "the Core environment pin");
  requireText(text, `ref: ${CORE}`, "the Core checkout pin");
  requireText(text, "git -C opemos-core-contracts rev-parse HEAD", "runtime Core commit verification");
  requireText(text, "node-version: 22.23.2", "Node 22.23.2");
  requireText(text, "toolchain: 1.98.1", "Rust 1.98.1");
  requireText(text, "run: npm ci", "locked JavaScript installation");
  requireText(text, "cargo test --manifest-path src-tauri/Cargo.toml --locked", "locked Rust tests");
  requireText(text, "cargo build --manifest-path src-tauri/Cargo.toml --release --locked", "locked release build");
  requireText(text, "Get-AuthenticodeSignature -LiteralPath $source", "Authenticode inspection");
  requireText(text, "SignatureStatus]::NotSigned", "the unsigned-only gate");
  requireText(text, "Get-FileHash -LiteralPath $destination -Algorithm SHA256", "SHA-256 provenance");
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
